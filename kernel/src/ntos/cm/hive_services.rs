//! Os serviços de hive: NtLoadKey/NtLoadKey2/NtLoadKeyEx/NtLoadKey3,
//! NtUnloadKey/NtUnloadKey2/NtUnloadKeyEx, NtSaveKey/NtSaveKeyEx,
//! NtRestoreKey, NtFlushKey, NtCompressKey e NtCompactKeys (e os Zw*
//! exportados, com PreviousMode de kernel).
//!
//! Captura dos parâmetros, privilégios e códigos como no ntoskrnl 19041:
//! - NtLoadKeyEx (CmLoadDifferencingKey, rva 0x6e729c): Flags com algum bit
//!   de 0xFFFF000B é STATUS_INVALID_PARAMETER_3, e REG_FLUSH_HIVE_FILE_GROWTH
//!   (0x1000) sem REG_HIVE_SINGLE_LOG | REG_BOOT_HIVE também; sem
//!   REG_APP_HIVE exige SeRestorePrivilege (SeSinglePrivilegeCheck pelo
//!   PreviousMode; sem ele, STATUS_PRIVILEGE_NOT_HELD). Com REG_APP_HIVE ou
//!   REG_LOAD_HIVE_OPEN_HANDLE, RootHandle nulo é
//!   STATUS_INVALID_PARAMETER_7, e REG_APP_HIVE com REG_NO_LAZY_FLUSH,
//!   REG_START_JOURNAL ou REG_BOOT_HIVE (0x444) é
//!   STATUS_INVALID_PARAMETER_3; sem nenhum dos dois, RootHandle não nulo é
//!   STATUS_INVALID_PARAMETER_7 e Event não nulo
//!   STATUS_INVALID_PARAMETER_5. Depois vem o nome do arquivo e o TargetKey:
//!   uma hive de aplicativo com RootDirectory no TargetKey é
//!   STATUS_INVALID_PARAMETER_1 e o *RootHandle zera antes da carga. Então
//!   as referências: o TrustClassKey (handle de chave, qualquer acesso), o
//!   Event (EVENT_MODIFY_STATE) e o token de acesso ao arquivo
//!   (TOKEN_IMPERSONATE; um token primário é STATUS_BAD_TOKEN_TYPE). O
//!   handle da raiz é aberto pelo nome depois da carga, com DesiredAccess e
//!   OBJ_CASE_INSENSITIVE (mais OBJ_KERNEL_HANDLE para um chamador de modo
//!   kernel). O Event é sinalizado quando a hive for descarregada. NtLoadKey
//!   é o Ex com zeros; NtLoadKey2, o Ex com Flags;
//! - NtLoadKey3 (rva 0x5cc3b0): os parâmetros estendidos são um vetor de
//!   CM_EXTENDED_PARAMETER (16 bytes, alinhado a 8 no modo usuário) com o
//!   tipo no byte baixo: 1 o TrustClassKey, 2 o Event e 3 o token de acesso
//!   ao arquivo; um tipo repetido ou desconhecido é
//!   STATUS_INVALID_PARAMETER_4. As Flags ganham
//!   REG_NO_IMPERSONATION_FALLBACK (0x8000) e o resto é o NtLoadKeyEx;
//! - NtUnloadKey(2/Ex) (CmUnloadKey, rva 0x66c6bc): SeRestorePrivilege;
//!   Flags além de REG_FORCE_UNLOAD é STATUS_INVALID_PARAMETER; a chave
//!   ausente também (o STATUS_OBJECT_NAME_NOT_FOUND vira
//!   STATUS_INVALID_PARAMETER); o Event do Ex (EVENT_MODIFY_STATE) é zerado;
//!   o Ex com handles abertos, com ou sem evento, devolve STATUS_PENDING e
//!   descarrega quando o último handle fecha, sinalizando o evento
//!   (`hive_list::unload_key`);
//! - NtSaveKeyEx (rva 0x729730): SeBackupPrivilege; Format 1
//!   (REG_STANDARD_FORMAT), 2 (REG_LATEST_FORMAT) ou 4
//!   (REG_NO_COMPRESSION), senão STATUS_INVALID_PARAMETER; o handle de
//!   arquivo de usuário precisa de FILE_WRITE_DATA. NtSaveKey é o Ex com 1.
//!   O REG_NO_COMPRESSION (cópia da hive como está, o
//!   CmpSaveKeyByFileCopy) ainda grava como o REG_LATEST_FORMAT;
//! - NtRestoreKey (rva 0x869440): SeRestorePrivilege; o arquivo de usuário
//!   precisa de FILE_READ_DATA (o de kernel vai como está ao CmRestoreKey,
//!   e o REG_REFRESH_HIVE não o usa); REG_REFRESH_HIVE com outro bit é
//!   STATUS_INVALID_PARAMETER; REG_WHOLE_HIVE_VOLATILE e REG_REFRESH_HIVE
//!   vão ao CmpLoadHiveVolatile e ao CmpRefreshHive (`hive_list`);
//! - NtFlushKey (rva 0x696c00): qualquer acesso no handle, salvo numa hive
//!   carregada com REG_NO_LAZY_FLUSH (HIVE_NOLAZYFLUSH), em que o modo
//!   usuário precisa de KEY_WRITE (senão STATUS_ACCESS_DENIED);
//! - NtCompressKey (rva 0x868250): SeBackupPrivilege, KEY_WRITE no handle,
//!   o modo nos dois bits baixos do handle e a chave precisa ser a raiz da
//!   hive (STATUS_INVALID_PARAMETER);
//! - NtCompactKeys (rva 0x867f70): SeBackupPrivilege; Count 0 é sucesso,
//!   Count >= 0x1FFFFFFF é STATUS_INVALID_PARAMETER; KEY_WRITE em cada
//!   handle; as chaves precisam estar na mesma hive e nenhuma pode ser raiz
//!   de hive; o NT valida e devolve sucesso sem mudar a hive.
//!
//! Os filtros de registro recebem RegNtPre/PostFlushKey (30/31),
//! LoadKey (32/33), UnLoadKey (34/35), RestoreKey (41/42) e SaveKey
//! (43/44) com as estruturas REG_*_INFORMATION do 19041 (CmpCallCallBacksEx
//! e CmPostCallbackNotificationEx): um pré que falha bloqueia o serviço com
//! o status dele e STATUS_CALLBACK_BYPASS o conclui com sucesso sem a
//! operação.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::callbacks::{self, Operation, Outcome};
use crate::ntos::cm::hive_file::HiveFile;
use crate::ntos::cm::hive_list::{self, LATEST_MINOR, STANDARD_MINOR};
use crate::ntos::cm::key::{objects as key_objects, services as key_services};
use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::inc::types::extra_se_cm::{RegDeleteKeyInformation, RegLoadKeyInformation, RegSaveKeyInformation, RegUnloadKeyInformation};
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, UnicodeString};
use crate::ntos::io::file::request::EventReference;
use crate::ntos::io::file::{request as file_request, zw as zw_files};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user::{registry as user_registry, state as user_state};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::privilege;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_INVALID_PARAMETER_7: u32 = 0xC000_00F5;

/// SeBackupPrivilege e SeRestorePrivilege (LUIDs 17 e 18).
const SE_BACKUP_PRIVILEGE: u64 = 17;
const SE_RESTORE_PRIVILEGE: u64 = 18;

const REG_APP_HIVE: u32 = 0x10;
const REG_LOAD_HIVE_OPEN_HANDLE: u32 = 0x800;
/// REG_NO_LAZY_FLUSH | REG_START_JOURNAL | REG_BOOT_HIVE, recusados numa
/// hive de aplicativo.
const APP_HIVE_REFUSED: u32 = 0x444;
/// REG_FLUSH_HIVE_FILE_GROWTH, que só vale com REG_HIVE_SINGLE_LOG |
/// REG_BOOT_HIVE.
const REG_FLUSH_HIVE_FILE_GROWTH: u32 = 0x1000;
const SINGLE_LOG_BOOT_HIVE: u32 = 0x600;
/// REG_NO_IMPERSONATION_FALLBACK, que o NtLoadKey3 sempre liga.
const REG_NO_IMPERSONATION_FALLBACK: u32 = 0x8000;
/// Os tipos de CM_EXTENDED_PARAMETER: CmExtendedParameterTrustClassKey,
/// CmExtendedParameterEvent e CmExtendedParameterFileAccessToken.
const EXTENDED_TRUST_CLASS_KEY: u8 = 1;
const EXTENDED_EVENT: u8 = 2;
const EXTENDED_FILE_ACCESS_TOKEN: u8 = 3;
/// TOKEN_IMPERSONATE e TokenImpersonation.
const TOKEN_IMPERSONATE: u32 = 4;
const TOKEN_TYPE_IMPERSONATION: u32 = 2;
const REG_WHOLE_HIVE_VOLATILE: u32 = 1;
const REG_REFRESH_HIVE: u32 = 2;
/// KEY_WRITE, FILE_READ_DATA e FILE_WRITE_DATA.
const KEY_WRITE: u32 = 0x2_0006;
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;
/// Os atributos do handle da raiz (o ObOpenObjectByPointer do
/// CmLoadDifferencingKey): OBJ_CASE_INSENSITIVE, mais OBJ_KERNEL_HANDLE
/// para um chamador de modo kernel.
const USER_ROOT_HANDLE_ATTRIBUTES: u32 = 0x40;
const KERNEL_ROOT_HANDLE_ATTRIBUTES: u32 = 0x240;

/// RegNtPreFlushKey, LoadKey, UnLoadKey, RestoreKey e SaveKey (o pós é o
/// seguinte).
const REG_NT_PRE_FLUSH_KEY: u32 = 30;
const REG_NT_PRE_LOAD_KEY: u32 = 32;
const REG_NT_PRE_UNLOAD_KEY: u32 = 34;
const REG_NT_PRE_RESTORE_KEY: u32 = 41;
const REG_NT_PRE_SAVE_KEY: u32 = 43;

fn privileged(privilege_value: u64, previous_mode: bool) -> bool {
    privilege::single_privilege_check(privilege_value, previous_mode as u32)
}

fn is_registry_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "\\registry" || lower.starts_with("\\registry\\")
}

/// O TargetKey capturado: o nome completo e a raiz.
struct KeyTarget {
    path: String,
    root: u64,
}

/// O nome de chave de um OBJECT_ATTRIBUTES (CmpNameFromAttributes): o
/// caminho da raiz (handle de chave) mais o nome, ou o nome absoluto.
fn key_target(attributes: u64, previous_mode: bool) -> Result<KeyTarget, u32> {
    let target = if previous_mode {
        let parsed = user_registry::parse_user_object_attributes(attributes).ok_or(STATUS_ACCESS_VIOLATION)?;
        KeyTarget { path: parsed.path, root: parsed.root_directory }
    } else {
        if attributes == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        // SAFETY: POBJECT_ATTRIBUTES de um chamador de modo kernel.
        let object = unsafe { ObjectAttributes::at(attributes) };
        if object.length.get() != ObjectAttributes::SIZE as u32 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let name_pointer = object.object_name.get();
        let name = if name_pointer != 0 { guest_strings::read_unicode_string(name_pointer) } else { String::new() };
        let root = object.root_directory.get();
        let path = match root {
            0 => name,
            root => {
                let (_, root_path) = key_services::reference_key(root, false, 0)?;
                if name.is_empty() { root_path } else { format!("{root_path}\\{name}") }
            }
        };
        KeyTarget { path, root }
    };
    if is_registry_path(&target.path) { Ok(target) } else { Err(STATUS_OBJECT_PATH_SYNTAX_BAD) }
}

fn key_path(attributes: u64, previous_mode: bool) -> Result<String, u32> {
    key_target(attributes, previous_mode).map(|target| target.path)
}

/// O nome NT de arquivo de um OBJECT_ATTRIBUTES.
fn file_path(attributes: u64, previous_mode: bool) -> Result<String, u32> {
    if previous_mode {
        let parsed = user_registry::parse_user_object_attributes(attributes).ok_or(STATUS_ACCESS_VIOLATION)?;
        if parsed.path.is_empty() { Err(STATUS_OBJECT_NAME_NOT_FOUND) } else { Ok(parsed.path) }
    } else {
        zw_files::file_path_from_object_attributes(attributes)
    }
}

/// O resultado de um serviço de hive para os filtros.
struct HiveOutcome(u32);

impl Outcome for HiveOutcome {
    fn status(&self) -> u32 {
        self.0
    }
    fn object(&self) -> u64 {
        0
    }
    fn set_status(&mut self, status: u32) {
        self.0 = status;
    }
    fn set_object(&mut self, _object: u64) {}
    fn from_status(status: u32) -> Self {
        HiveOutcome(status)
    }
}

/// RegNtPre<serviço> e RegNtPost<serviço> em volta do serviço, com a
/// estrutura `size` preenchida por `fill` e o CallContext em `call_offset`.
fn filtered(pre: u32, size: u64, call_offset: u64, object: u64, fill: impl FnOnce(u64), action: impl FnOnce() -> u32) -> u32 {
    if !callbacks::has() {
        return action();
    }
    let information = guest::alloc_bytes(size);
    if information == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    fill(information);
    let operation = Operation::<HiveOutcome> { pre, post: pre + 1, info: information, call_offset, object, unblockable: false, bypass: None };
    let result = callbacks::perform(&operation, || HiveOutcome(action()));
    guest::free_bytes(information);
    match result {
        Ok(outcome) => outcome.0,
        Err(error) => if error.status != 0 { error.status } else { 0xC000_0001 },
    }
}

/// Um UNICODE_STRING com o texto logo depois, para as notificações.
fn unicode_block(text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let block = guest::alloc_bytes(UnicodeString::SIZE + units.len() as u64 * 2 + 2);
    if block == 0 {
        return 0;
    }
    guest::write_bytes(block + UnicodeString::SIZE, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // SAFETY: bloco próprio recém-alocado.
    let string = unsafe { UnicodeString::at(block) };
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2 + 2);
    string.buffer.set(block + UnicodeString::SIZE);
    block
}

/// Os parâmetros do CmLoadDifferencingKey que o NtLoadKey(2/3/Ex) passa.
struct LoadParameters {
    target: u64,
    source: u64,
    flags: u32,
    trust_class_key: u64,
    event: u64,
    desired_access: u32,
    root_handle: u64,
    file_access_token: u64,
}

/// O token de acesso ao arquivo referenciado (TOKEN_IMPERSONATE): o
/// ponteiro, o nível de impersonação e a referência de kernel a devolver.
struct FileAccessToken {
    token: u64,
    level: u32,
    reference: Option<crate::ntos::se::token::reference::TokenReference>,
}

impl FileAccessToken {
    fn release(&mut self) {
        if let Some(mut reference) = self.reference.take() {
            let _ = reference.release();
        }
    }
}

/// ObReferenceObjectByHandle(Token, TOKEN_IMPERSONATE, SeTokenObjectType)
/// e o TokenType: um token primário é STATUS_BAD_TOKEN_TYPE.
fn file_access_token(handle: u64, previous_mode: bool) -> Result<FileAccessToken, u32> {
    use crate::ntos::se::token::{reference as token_reference, tokens};
    let (token, reference) = if previous_mode {
        (crate::ntos::ps::user::tokens::lookup(handle, TOKEN_IMPERSONATE)?, None)
    } else {
        match token_reference::reference(handle, TOKEN_IMPERSONATE, 0, false) {
            Ok(Ok(reference)) => (reference.token, Some(reference)),
            Ok(Err(status)) => return Err(status),
            Err(error) => return Err(if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }),
        }
    };
    let mut referenced = FileAccessToken { token, level: 0, reference };
    match tokens::with(token, |record| (record.kind, record.impersonation_level)) {
        Some((TOKEN_TYPE_IMPERSONATION, level)) => {
            referenced.level = level;
            Ok(referenced)
        }
        Some(_) => {
            referenced.release();
            Err(STATUS_BAD_TOKEN_TYPE)
        }
        None => {
            referenced.release();
            Err(STATUS_INVALID_HANDLE)
        }
    }
}

/// NtLoadKeyEx(TargetKey, SourceFile, Flags, TrustClassKey, Event,
/// DesiredAccess, RootHandle, Reserved).
#[allow(clippy::too_many_arguments)]
pub fn load_key(target: u64, source: u64, flags: u32, trust_class_key: u64, event: u64, desired_access: u32, root_handle: u64, previous_mode: bool) -> u32 {
    load_differencing_key(&LoadParameters { target, source, flags, trust_class_key, event, desired_access, root_handle, file_access_token: 0 }, previous_mode)
}

/// NtLoadKey3(TargetKey, SourceFile, Flags, ExtendedParameters,
/// ExtendedParameterCount, DesiredAccess, RootHandle, Reserved): os
/// CM_EXTENDED_PARAMETER capturados um a um e o NtLoadKeyEx com
/// REG_NO_IMPERSONATION_FALLBACK.
#[allow(clippy::too_many_arguments)]
pub fn load_key3(target: u64, source: u64, flags: u32, extended: u64, count: u32, desired_access: u32, root_handle: u64, previous_mode: bool) -> u32 {
    let mut parameters = LoadParameters { target, source, flags: flags | REG_NO_IMPERSONATION_FALLBACK, trust_class_key: 0, event: 0, desired_access, root_handle, file_access_token: 0 };
    let mut seen = 0u32;
    for index in 0..count as u64 {
        let entry = extended.wrapping_add(index * 16);
        if previous_mode {
            if entry & 7 != 0 {
                return STATUS_DATATYPE_MISALIGNMENT;
            }
            if !user_state::probe_user_read(entry, 16) {
                return STATUS_ACCESS_VIOLATION;
            }
        }
        let (Ok(kind), Ok(value)) = (guest::try_read::<u64>(entry), guest::try_read::<u64>(entry + 8)) else { return STATUS_ACCESS_VIOLATION };
        let (bit, slot) = match kind as u8 {
            EXTENDED_TRUST_CLASS_KEY => (2, &mut parameters.trust_class_key),
            EXTENDED_EVENT => (4, &mut parameters.event),
            EXTENDED_FILE_ACCESS_TOKEN => (8, &mut parameters.file_access_token),
            _ => return STATUS_INVALID_PARAMETER_4,
        };
        if seen & bit != 0 {
            return STATUS_INVALID_PARAMETER_4;
        }
        seen |= bit;
        *slot = value;
    }
    load_differencing_key(&parameters, previous_mode)
}

/// CmLoadDifferencingKey sem a camada diferencial.
fn load_differencing_key(parameters: &LoadParameters, previous_mode: bool) -> u32 {
    let LoadParameters { target, source, flags, trust_class_key, event, desired_access, root_handle, file_access_token: token_handle } = *parameters;
    if flags & 0xFFFF_000B != 0 {
        return STATUS_INVALID_PARAMETER_3;
    }
    if flags & REG_FLUSH_HIVE_FILE_GROWTH != 0 && flags & SINGLE_LOG_BOOT_HIVE != SINGLE_LOG_BOOT_HIVE {
        return STATUS_INVALID_PARAMETER_3;
    }
    let app = flags & REG_APP_HIVE != 0;
    let open_handle = flags & (REG_APP_HIVE | REG_LOAD_HIVE_OPEN_HANDLE) != 0;
    if !app && !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if open_handle {
        if root_handle == 0 {
            return STATUS_INVALID_PARAMETER_7;
        }
        if app && flags & APP_HIVE_REFUSED != 0 {
            return STATUS_INVALID_PARAMETER_3;
        }
    } else {
        if root_handle != 0 {
            return STATUS_INVALID_PARAMETER_7;
        }
        if event != 0 {
            return STATUS_INVALID_PARAMETER_5;
        }
    }
    let source = match file_path(source, previous_mode) {
        Ok(path) => path,
        Err(status) => return status,
    };
    // *RootHandle = NULL antes da cópia do TargetKey.
    if open_handle && (previous_mode && !user_state::probe_user_write(root_handle, 8) || guest::try_write::<u64>(root_handle, 0).is_err()) {
        return STATUS_ACCESS_VIOLATION;
    }
    let target = match key_target(target, previous_mode) {
        Ok(target) => target,
        Err(status) => return status,
    };
    if app && target.root != 0 {
        return STATUS_INVALID_PARAMETER_1;
    }
    // CmObReferenceObjectByHandle do TrustClassKey, sem acesso pedido.
    let trust = if trust_class_key != 0 {
        match key_services::reference_key(trust_class_key, previous_mode, 0) {
            Ok((node, _)) => Some(node),
            Err(status) => return status,
        }
    } else {
        None
    };
    let mut reference: Option<EventReference> = if event != 0 {
        match file_request::event_reference(event, previous_mode as u8) {
            Ok(reference) => Some(reference),
            Err(status) => return status,
        }
    } else {
        None
    };
    let mut token = if token_handle != 0 {
        match file_access_token(token_handle, previous_mode) {
            Ok(token) => Some(token),
            Err(status) => {
                if let Some(mut reference) = reference.take() {
                    reference.release();
                }
                return status;
            }
        }
    } else {
        None
    };
    let event_pointer = reference.as_ref().map_or(0, |reference| reference.pointer);
    let token_pointer = token.as_ref().map_or(0, |token| token.token);
    let root_body = if target.root != 0 { key_services::key_body(target.root, previous_mode).unwrap_or(0) } else { 0 };
    let trust_body = if trust_class_key != 0 { key_services::key_body(trust_class_key, previous_mode).unwrap_or(0) } else { 0 };
    let names = if callbacks::has() { (unicode_block(&target.path), unicode_block(&source)) } else { (0, 0) };
    let mut mount: Option<String> = None;
    let status = filtered(
        REG_NT_PRE_LOAD_KEY,
        RegLoadKeyInformation::SIZE,
        core::mem::offset_of!(RegLoadKeyInformation, call_context) as u64,
        root_body,
        |information| {
            // SAFETY: a estrutura própria zerada desta notificação.
            let block = unsafe { RegLoadKeyInformation::at(information) };
            block.object.set(root_body);
            block.key_name.set(names.0);
            block.source_file.set(names.1);
            block.flags.set(flags);
            block.trust_class_object.set(trust_body);
            block.user_event.set(event_pointer);
            block.desired_access.set(desired_access);
            block.root_handle.set(root_handle);
            block.version.set(2);
            block.file_access_token.set(token_pointer);
        },
        || {
            let request = hive_list::LoadRequest { flags, unload_event: reference.take(), trust, token: token.as_ref().map(|token| (token.token, token.level)), previous_mode };
            let loaded = if app { hive_list::load_app_hive(&target.path, &source, request) } else { hive_list::load_hive(&target.path, &source, request).map(|identifier| registry::hive_path(identifier).unwrap_or_else(|| target.path.clone())) };
            match loaded {
                Ok(path) => {
                    mount = Some(path);
                    0
                }
                Err(status) => status,
            }
        },
    );
    if let Some(mut reference) = reference {
        reference.release();
    }
    if let Some(token) = token.as_mut() {
        token.release();
    }
    for block in [names.0, names.1].into_iter().filter(|&block| block != 0) {
        guest::free_bytes(block);
    }
    if status != 0 || !open_handle {
        return status;
    }
    // O handle da raiz, aberto pelo nome com DesiredAccess (o
    // ObReferenceObjectByName e o ObOpenObjectByPointer do
    // CmLoadDifferencingKey).
    let Some(mount) = mount else { return status };
    let attributes = if previous_mode { USER_ROOT_HANDLE_ATTRIBUTES } else { KERNEL_ROOT_HANDLE_ATTRIBUTES };
    match key_services::open_hive_root(&mount, desired_access, attributes, root_handle, previous_mode) {
        Ok(opened) => opened,
        Err(error) => if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES },
    }
}

/// NtUnloadKey(TargetKey) = (TargetKey, 0, FALSE, NULL), NtUnloadKey2 =
/// (TargetKey, Flags, FALSE, NULL) e NtUnloadKeyEx = (TargetKey, 0, TRUE,
/// Event): o CmUnloadKey.
pub fn unload_key(target: u64, flags: u32, extended: bool, event: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if flags & !hive_list::REG_FORCE_UNLOAD != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let path = match key_path(target, previous_mode) {
        Ok(path) => path,
        Err(status) => return status,
    };
    let Some(node) = registry::node_by_path(&path) else { return STATUS_INVALID_PARAMETER };
    let mut event = if event != 0 {
        match file_request::event_reference(event, previous_mode as u8) {
            Ok(event) => {
                crate::ntos::ke::dispatcher::reset_event(event.pointer);
                Some(event)
            }
            Err(status) => return status,
        }
    } else {
        None
    };
    let event_pointer = event.as_ref().map_or(0, |event| event.pointer);
    let body = if callbacks::has() { key_objects::temporary(node, &path).unwrap_or(0) } else { 0 };
    let status = filtered(
        REG_NT_PRE_UNLOAD_KEY,
        RegUnloadKeyInformation::SIZE,
        core::mem::offset_of!(RegUnloadKeyInformation, call_context) as u64,
        body,
        |information| {
            // SAFETY: a estrutura própria zerada desta notificação.
            let block = unsafe { RegUnloadKeyInformation::at(information) };
            block.object.set(body);
            block.user_event.set(event_pointer);
        },
        || hive_list::unload_key(node, flags, extended, event.take()),
    );
    if let Some(mut event) = event {
        event.release();
    }
    if body != 0 {
        let _ = key_objects::release(body);
    }
    status
}

/// NtSaveKeyEx(KeyHandle, FileHandle, Format).
pub fn save_key(key: u64, file: u64, format: u32, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if format.wrapping_sub(1) & !3 != 0 || format == 3 {
        return STATUS_INVALID_PARAMETER;
    }
    let hive_file = match HiveFile::from_handle(file, previous_mode, FILE_WRITE_DATA) {
        Ok(file) => file,
        Err(status) => return status,
    };
    let (node, _) = match key_services::reference_key(key, previous_mode, 0) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let body = key_services::key_body(key, previous_mode).unwrap_or(0);
    filtered(
        REG_NT_PRE_SAVE_KEY,
        RegSaveKeyInformation::SIZE,
        core::mem::offset_of!(RegSaveKeyInformation, call_context) as u64,
        body,
        |information| {
            // SAFETY: a estrutura própria zerada desta notificação.
            let block = unsafe { RegSaveKeyInformation::at(information) };
            block.object.set(body);
            block.file_handle.set(file);
            block.format.set(format);
        },
        || hive_list::save(node, &hive_file, if format == 1 { STANDARD_MINOR } else { LATEST_MINOR }),
    )
}

/// NtRestoreKey(KeyHandle, FileHandle, Flags).
pub fn restore_key(key: u64, file: u64, flags: u32, previous_mode: bool) -> u32 {
    if !privileged(SE_RESTORE_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    // O REG_REFRESH_HIVE de modo kernel não usa o arquivo; o de usuário
    // ainda passa pelo IoConvertFileHandleToKernelHandle.
    let refresh_only = flags & REG_REFRESH_HIVE != 0 && !previous_mode;
    let hive_file = if refresh_only {
        None
    } else {
        match HiveFile::from_handle(file, previous_mode, FILE_READ_DATA) {
            Ok(file) => Some(file),
            Err(status) => return status,
        }
    };
    let (node, _) = match key_services::reference_key(key, previous_mode, 0) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    let body = key_services::key_body(key, previous_mode).unwrap_or(0);
    filtered(
        REG_NT_PRE_RESTORE_KEY,
        RegSaveKeyInformation::SIZE,
        core::mem::offset_of!(RegSaveKeyInformation, call_context) as u64,
        body,
        |information| {
            // REG_RESTORE_KEY_INFORMATION: o layout do de gravação, com Flags.
            // SAFETY: a estrutura própria zerada desta notificação.
            let block = unsafe { RegSaveKeyInformation::at(information) };
            block.object.set(body);
            block.file_handle.set(file);
            block.format.set(flags);
        },
        || restore(node, hive_file.as_ref(), flags),
    )
}

/// CmRestoreKey: as flags e o caminho de cada modo.
fn restore(node: NodeId, file: Option<&HiveFile>, flags: u32) -> u32 {
    if flags & REG_REFRESH_HIVE != 0 && flags & !REG_REFRESH_HIVE != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & REG_REFRESH_HIVE != 0 {
        return hive_list::refresh(node);
    }
    let Some(file) = file else { return STATUS_INVALID_PARAMETER };
    if flags & REG_WHOLE_HIVE_VOLATILE != 0 {
        return hive_list::restore_volatile(node, file);
    }
    hive_list::restore(node, file, flags)
}

/// NtFlushKey(KeyHandle).
pub fn flush_key(key: u64, previous_mode: bool) -> u32 {
    let (node, _) = match key_services::reference_key(key, previous_mode, 0) {
        Ok(resolved) => resolved,
        Err(status) => return status,
    };
    if previous_mode && hive_list::no_lazy_flush(node) {
        if let Err(status) = key_services::reference_key(key, previous_mode, KEY_WRITE) {
            return status;
        }
    }
    let body = key_services::key_body(key, previous_mode).unwrap_or(0);
    filtered(
        REG_NT_PRE_FLUSH_KEY,
        RegDeleteKeyInformation::SIZE,
        core::mem::offset_of!(RegDeleteKeyInformation, call_context) as u64,
        body,
        |information| {
            // REG_FLUSH_KEY_INFORMATION: o layout do REG_DELETE_KEY_INFORMATION.
            // SAFETY: a estrutura própria zerada desta notificação.
            unsafe { RegDeleteKeyInformation::at(information) }.object.set(body);
        },
        || hive_list::flush(node),
    )
}

/// NtCompressKey(Key): o modo vem dos dois bits baixos do handle.
pub fn compress_key(key: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let mode = (key & 3) as u32;
    match key_services::reference_key(key & !3, previous_mode, KEY_WRITE) {
        Ok((node, _)) => hive_list::compress(node, mode),
        Err(status) => status,
    }
}

/// NtCompactKeys(Count, KeyArray).
pub fn compact_keys(count: u32, array: u64, previous_mode: bool) -> u32 {
    if !privileged(SE_BACKUP_PRIVILEGE, previous_mode) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    if count == 0 {
        return 0;
    }
    if count >= 0x1FFF_FFFF {
        return STATUS_INVALID_PARAMETER;
    }
    if previous_mode && !user_state::probe_user_read(array, count as u64 * 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let Ok(handles) = guest::try_read_bytes(array, count as usize * 8) else { return STATUS_ACCESS_VIOLATION };
    let mut nodes: Vec<NodeId> = Vec::with_capacity(count as usize);
    for handle in handles.chunks_exact(8) {
        let handle = u64::from_le_bytes([handle[0], handle[1], handle[2], handle[3], handle[4], handle[5], handle[6], handle[7]]);
        match key_services::reference_key(handle, previous_mode, KEY_WRITE) {
            Ok((node, _)) => nodes.push(node),
            Err(status) => return status,
        }
    }
    if hive_list::same_hive(&nodes) { 0 } else { STATUS_INVALID_PARAMETER }
}
