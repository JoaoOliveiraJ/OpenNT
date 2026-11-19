//! Handles de diretórios e links do namespace.
//!
//! NtOpen/NtCreateDirectoryObject(Ex), NtOpen/NtCreateSymbolicLinkObject (e
//! o ZwCreateSymbolicLinkObject de modo kernel), NtQuerySymbolicLinkObject,
//! NtQueryDirectoryObject e NtMakeTemporaryObject.
//! Os handles de usuário do processo corrente entram com a fase 7.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::ntos::ob::open_pointer;
use crate::ntos::ex::callbacks as executive_callbacks;
use crate::ntos::ps::user_probe;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, ObjectDirectoryInformation, UnicodeString};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;

/// Campo de uma estrutura do chamador (de modo usuário ou não): sonda e um
/// acesso da largura do campo, o `__try` do NT. Sem exigir o alinhamento da
/// estrutura inteira, como a captura original.
fn read_field<T: GuestScalar>(base: u64, offset: usize) -> Result<T, u32> {
    guest::try_read(base + offset as u64).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn write_field<T: GuestScalar>(base: u64, offset: usize, value: T) -> Result<(), u32> {
    guest::try_write(base + offset as u64, value).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn write_text(address: u64, bytes: &[u8]) -> Result<(), u32> {
    guest::try_write_bytes(address, bytes).map_err(|_| STATUS_ACCESS_VIOLATION)
}

fn utf16_bytes(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

/// Handle resolvido para um corpo de diretório ou link.
pub struct Opened {
    pub body: u64,
    pub node: NodeId,
    pub directory: bool,
    pub access: u32,
}

/// Exige um corpo Directory ou SymbolicLink registrado no namespace.
pub fn resolve(handle: u64, from_user_mode: bool) -> Result<Opened, u32> {
    let resolved = match open_pointer::resolve(handle, from_user_mode) {
        Some(Err(status)) => return Err(status),
        Some(Ok(resolved)) => resolved,
        None => return Err(STATUS_INVALID_HANDLE),
    };
    let Some((node, directory)) = namespace_objects::get(resolved.item.pointer) else {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    };
    Ok(Opened { body: resolved.item.pointer, node, directory, access: resolved.access })
}

struct Captured {
    name: String,
    start: NodeId,
    flags: u32,
    case_insensitive: bool,
    /// OBJECT_ATTRIBUTES.SecurityDescriptor capturado uma única vez.
    security_descriptor: u64,
}

fn readable(pointer: u64, length: u64, from_user_mode: bool) -> bool {
    !from_user_mode || user_probe::probe_user_read(pointer, length)
}

/// Lê OBJECT_ATTRIBUTES e o UNICODE_STRING com as sondas de usuário;
/// RootDirectory define o início de nomes relativos.
fn capture(attributes: u64, from_user_mode: bool) -> Result<Captured, u32> {
    if attributes == 0 {
        return Err(0xC000_000D);
    }
    if !readable(attributes, ObjectAttributes::SIZE, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    if read_field::<u32>(attributes, offset_of!(ObjectAttributes, length))? != ObjectAttributes::SIZE as u32 {
        return Err(0xC000_000D);
    }
    // O ObpCaptureObjectCreateInformation do ObOpenObjectByNameEx tira o
    // OBJ_KERNEL_HANDLE de quem vem de UserMode, sem recusar (o
    // ScInitServiceConfigRoots do services.exe abre o \DriverStores com
    // 0x240).
    let flags = read_field::<u32>(attributes, offset_of!(ObjectAttributes, attributes))? & if from_user_mode { !0x200 } else { u32::MAX };
    let root = read_field::<u64>(attributes, offset_of!(ObjectAttributes, root_directory))?;
    let unicode = read_field::<u64>(attributes, offset_of!(ObjectAttributes, object_name))?;
    let security_descriptor = read_field::<u64>(attributes, offset_of!(ObjectAttributes, security_descriptor))?;
    if unicode == 0 {
        return Err(0xC000_0033);
    }
    if !readable(unicode, UnicodeString::SIZE, from_user_mode) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let length = read_field::<u16>(unicode, offset_of!(UnicodeString, length))?;
    let buffer = read_field::<u64>(unicode, offset_of!(UnicodeString, buffer))?;
    if length & 1 != 0 || length > read_field::<u16>(unicode, offset_of!(UnicodeString, maximum_length))? {
        return Err(0xC000_0033);
    }
    if length != 0 && (buffer == 0 || !readable(buffer, length as u64, from_user_mode)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = if length != 0 { guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? } else { Vec::new() };
    let units: Vec<u16> = bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    let name = String::from_utf16_lossy(&units);
    let mut start = object_manager::ROOT;
    if root != 0 {
        let opened = resolve(root, from_user_mode)?;
        if !opened.directory {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        if name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        start = opened.node;
    } else if !name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    Ok(Captured { name, start, flags, case_insensitive: flags & 0x40 != 0, security_descriptor })
}

/// Abre ou cria (`create`) o objeto, valida o tipo e publica o handle pelo
/// corpo nativo; uma criação incompleta remove o nó inserido.
pub fn open(output_handle: u64, access: u32, attributes: u64, kind: &str, from_user_mode: bool, create: bool) -> u32 {
    if from_user_mode && !user_probe::probe_user_write(output_handle, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut created: Option<NodeId> = None;
    let status = open_inner(output_handle, access, attributes, kind, from_user_mode, create, None, None, &mut created);
    if let Some(node) = created {
        object_manager::remove_named(node);
    }
    status
}

/// NtCreateSymbolicLinkObject: cria o link com o destino `target` (já
/// capturado) e publica o handle, como a criação de diretório.
pub fn create_link(output_handle: u64, access: u32, attributes: u64, target: &str, from_user_mode: bool) -> u32 {
    if from_user_mode && !user_probe::probe_user_write(output_handle, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut created: Option<NodeId> = None;
    let status = open_inner(output_handle, access, attributes, "SymbolicLink", from_user_mode, true, Some(target), None, &mut created);
    if let Some(node) = created {
        object_manager::remove_named(node);
    }
    status
}

/// O diretório sombra e os OBJECT_DIRECTORY.Flags de um diretório que o
/// NtCreateDirectoryObjectEx cria.
#[derive(Clone, Copy)]
struct DirectorySetup {
    /// O corpo do ShadowDirectory, com a referência que o diretório novo
    /// herda (0 sem sombra).
    shadow: u64,
    flags: u32,
}

/// NtCreateDirectoryObjectEx(DirectoryHandle*, DesiredAccess,
/// ObjectAttributes, ShadowDirectoryHandle, Flags) — o
/// ObpCreateDirectoryObject (ntoskrnl 19041 rva 0x6868e0):
/// - Flags além dos bits 0 e 1, ou o bit 1 vindo de UserMode, é
///   STATUS_INVALID_PARAMETER_5;
/// - o ShadowDirectoryHandle passa pelo ObReferenceObjectByHandle com
///   DIRECTORY_QUERY | DIRECTORY_TRAVERSE no tipo Directory;
/// - o diretório novo guarda a sombra (Flags |= 4, e 0x10 quando quem cria é
///   sandbox pelo RtlIsSandboxedToken), o bit 0 vira Flags 8 (herança
///   automática dos descritores) e o bit 1 Flags 0x20 (o ObQueryNameString
///   para nele). Um nome que já existe (OBJ_OPENIF) abre o diretório antigo e
///   a referência da sombra volta.
pub fn create_directory_ex(output_handle: u64, access: u32, attributes: u64, shadow_handle: u64, flags: u32, from_user_mode: bool) -> u32 {
    if flags & !3 != 0 || (from_user_mode && flags & 2 != 0) {
        return STATUS_INVALID_PARAMETER_5;
    }
    if from_user_mode && !user_probe::probe_user_write(output_handle, 8) {
        return STATUS_ACCESS_VIOLATION;
    }
    let mut setup = DirectorySetup { shadow: 0, flags: 0 };
    if shadow_handle != 0 {
        let shadow = match resolve(shadow_handle, from_user_mode) {
            Ok(shadow) => shadow,
            Err(status) => return status,
        };
        if !shadow.directory {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        if from_user_mode && shadow.access & 3 != 3 {
            return STATUS_ACCESS_DENIED;
        }
        if namespace_objects::reference(shadow.body).is_err() {
            return STATUS_INVALID_HANDLE;
        }
        setup.shadow = shadow.body;
        setup.flags |= namespace_objects::DIRECTORY_SHADOW;
        if crate::ntos::rtl::security::is_sandboxed_token(0, from_user_mode as u8).unwrap_or(false) {
            setup.flags |= namespace_objects::DIRECTORY_SANDBOXED_SHADOW;
        }
    }
    if flags & 1 != 0 {
        setup.flags |= namespace_objects::DIRECTORY_AUTO_INHERIT;
    }
    if flags & 2 != 0 {
        setup.flags |= namespace_objects::DIRECTORY_NAME_ROOT;
    }
    let mut created: Option<NodeId> = None;
    let mut setup_slot = Some(setup);
    let status = open_inner(output_handle, access, attributes, "Directory", from_user_mode, true, None, Some(&mut setup_slot), &mut created);
    // A sombra que nenhum diretório novo herdou volta.
    if let Some(unused) = setup_slot {
        if unused.shadow != 0 {
            let _ = namespace_objects::dereference(unused.shadow);
        }
    }
    if let Some(node) = created {
        object_manager::remove_named(node);
    }
    status
}

/// ZwCreateSymbolicLinkObject(LinkHandle, DesiredAccess, ObjectAttributes,
/// LinkTarget): o NtCreateSymbolicLinkObject (RVA 0x68ef10, cauda 0x808eb0)
/// com PreviousMode KernelMode. O UNICODE_STRING do destino é copiado sem
/// sonda; MaximumLength ímpar perde o bit 0; MaximumLength 0, Length acima
/// de MaximumLength ou Length ímpar -> STATUS_INVALID_PARAMETER, sem criar
/// nada; senão o ObCreateSymbolicLink.
pub fn create_link_from_kernel(output_handle: u64, access: u32, attributes: u64, target: &UnicodeString) -> u32 {
    let length = target.length.get();
    let maximum = target.maximum_length.get() & !1;
    if maximum == 0 || length > maximum || length & 1 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let text = crate::ntos::rtl::guest_strings::read_unicode_string(target.address());
    create_link(output_handle, access, attributes, &text, false)
}

/// O OBJECT_ATTRIBUTES, o UNICODE_STRING e o texto de um nome de modo
/// kernel numa alocação só, com a célula do handle de saída; o bloco sai no
/// drop.
struct KernelName {
    block: u64,
}

impl KernelName {
    fn new(root: u64, name: &str, attributes: u32) -> Option<Self> {
        let units = name.encode_utf16().count() as u64;
        if units * 2 > 0xFFFC {
            return None;
        }
        let size = ObjectAttributes::SIZE + 8 + UnicodeString::SIZE + units * 2 + 2;
        let block = guest::alloc_bytes(size);
        if block == 0 {
            return None;
        }
        guest::write_bytes(block, &vec![0u8; size as usize]);
        let string = block + ObjectAttributes::SIZE + 8;
        let text = string + UnicodeString::SIZE;
        crate::ntos::rtl::guest_strings::write_wide_string(text, name);
        crate::ntos::rtl::guest_strings::write_string_fields(string, (units * 2) as u16, (units * 2 + 2) as u16, text);
        // SAFETY: bloco de kernel zerado com o tamanho do OBJECT_ATTRIBUTES.
        let object_attributes = unsafe { ObjectAttributes::at(block) };
        object_attributes.length.set(ObjectAttributes::SIZE as u32);
        object_attributes.root_directory.set(root);
        object_attributes.object_name.set(string);
        object_attributes.attributes.set(attributes);
        Some(Self { block })
    }

    fn attributes(&self) -> u64 {
        self.block
    }

    fn handle_cell(&self) -> u64 {
        self.block + ObjectAttributes::SIZE
    }

    fn handle(&self) -> u64 {
        guest::read64(self.handle_cell())
    }
}

impl Drop for KernelName {
    fn drop(&mut self) {
        guest::free_bytes(self.block);
    }
}

/// ZwCreateDirectoryObject(&Handle, DesiredAccess, {RootDirectory, Name,
/// Attributes}) de modo kernel: o handle (também com OBJ_OPENIF num nome que
/// já existe) ou o NTSTATUS da falha.
pub fn create_directory_from_kernel(root: u64, name: &str, access: u32, attributes: u32) -> Result<u64, u32> {
    let Some(request) = KernelName::new(root, name, attributes) else { return Err(0xC000_009A) };
    let status = open(request.handle_cell(), access, request.attributes(), "Directory", false, true);
    if status as i32 >= 0 { Ok(request.handle()) } else { Err(status) }
}

/// ZwCreateSymbolicLinkObject de modo kernel com o destino em texto: o
/// handle ou o NTSTATUS da falha.
pub fn create_link_named_from_kernel(root: u64, name: &str, access: u32, attributes: u32, target: &str) -> Result<u64, u32> {
    let Some(request) = KernelName::new(root, name, attributes) else { return Err(0xC000_009A) };
    let status = create_link(request.handle_cell(), access, request.attributes(), target, false);
    if status as i32 >= 0 { Ok(request.handle()) } else { Err(status) }
}

#[allow(clippy::too_many_arguments)]
fn open_inner(output_handle: u64, access: u32, attributes: u64, kind: &str, from_user_mode: bool, create: bool, link_target: Option<&str>, setup: Option<&mut Option<DirectorySetup>>, created: &mut Option<NodeId>) -> u32 {
    let input = match capture(attributes, from_user_mode) {
        Ok(input) => input,
        Err(status) => return status,
    };
    // A abertura procura também nos diretórios sombra; a criação não.
    // OBJ_IGNORE_IMPERSONATED_DEVICEMAP: o `\??` pelo mapa do processo.
    let (found, rest) = if create {
        object_manager::resolve_from(&input.name, 0, input.case_insensitive, kind == "SymbolicLink", input.start)
    } else {
        object_manager::resolve_open_with(&input.name, input.case_insensitive, kind == "SymbolicLink", input.start, from_user_mode, input.flags & 0x800 != 0)
    };
    if rest.is_some_and(|rest| !rest.is_empty()) {
        return 0xC000_003A;
    }
    let mut node = found;
    if create {
        if node.is_some() && input.flags & 0x80 == 0 {
            return 0xC000_0035;
        }
        if node.is_none() {
            let mut parts: Vec<&str> = input.name.split('\\').filter(|part| !part.is_empty()).collect();
            let Some(name) = parts.pop() else { return 0xC000_0033 };
            // O pai de um nome absoluto continua absoluto: `\??\X` tem o
            // pai `\??`, o diretório de devices DOS de quem cria.
            let parent_path = if input.name.starts_with('\\') { alloc::format!("\\{}", parts.join("\\")) } else { parts.join("\\") };
            let (parent, parent_rest) = object_manager::resolve_from(&parent_path, 0, input.case_insensitive, false, input.start);
            let parent = parent.filter(|&parent| object_manager::node(parent).is_some_and(|node| node.type_name == "Directory") && parent_rest.is_none());
            let Some(parent) = parent else { return 0xC000_003A };
            // DIRECTORY_CREATE_SUBDIRECTORY ou DIRECTORY_CREATE_OBJECT no pai
            // (ObCheckCreateObjectAccess), só para quem vem de UserMode.
            if from_user_mode {
                if let Err(status) = crate::ntos::ob::object_security::check_create_in(parent, kind == "Directory") {
                    return status;
                }
            }
            let data = link_target.map(object_manager::ObjectData::symlink);
            let Some(inserted) = object_manager::insert_named(parent, name, kind, data, input.case_insensitive) else {
                return 0xC000_0035;
            };
            *created = Some(inserted);
            object_manager::update_node(inserted, |node| node.permanent = Some(input.flags & 0x10 != 0));
            node = Some(inserted);
        }
    }
    let Some(node) = node else { return 0xC000_0034 };
    if object_manager::node(node).is_none_or(|snapshot| snapshot.type_name != kind) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    let body = match namespace_objects::ensure(node) {
        Ok(Some(body)) => body,
        Ok(None) => return STATUS_OBJECT_TYPE_MISMATCH,
        Err(error) => return if error.status != 0 { error.status } else { 0xC000_0001 },
    };
    // O diretório novo do NtCreateDirectoryObjectEx herda a sombra e os
    // Flags (uma falha depois disto o coleta e a sombra sai com ele).
    if created.is_some() {
        if let Some(DirectorySetup { shadow, flags }) = setup.and_then(Option::take) {
            if shadow != 0 {
                let _ = namespace_objects::set_shadow_directory(body, shadow);
            }
            let _ = namespace_objects::set_directory_flags(body, flags);
        }
    }
    if created.is_some() {
        // O descritor do objeto novo: o explícito, a herança do diretório
        // pai e o token de quem cria (SeAssignSecurity).
        let parent = object_manager::node(node).and_then(|snapshot| snapshot.parent);
        let assigned = crate::ntos::ob::object_security::assign_named(body, parent, input.security_descriptor, from_user_mode);
        if assigned != 0 {
            return assigned;
        }
    }
    let object_type = open_pointer::describe(body).map_or(0, |item| item.object_type.pointer);
    // Quem cria recebe o acesso pedido sem a verificação do descritor novo
    // (o ObInsertObject do objeto novo); só a abertura de um nome existente
    // passa pelo SeAccessCheck.
    let open_mode = if created.is_some() { 0 } else { from_user_mode as u8 };
    let status = match open_pointer::open(body, input.flags, 0, access, object_type, open_mode, output_handle) {
        Ok(status) => status,
        Err(error) => return if error.status != 0 { error.status } else { 0xC000_0001 },
    };
    if status == 0 {
        *created = None;
        // STATUS_OBJECT_NAME_EXISTS: OBJ_OPENIF abriu um nome que já existia.
        return if create && found.is_some() { 0x4000_0000 } else { 0 };
    }
    status
}

/// NtQuerySymbolicLinkObject: copia o destino respeitando a capacidade.
pub fn query_link(handle: u64, output_buffer: u64, output_length: u64, from_user_mode: bool) -> u32 {
    let item = match resolve(handle, from_user_mode) {
        Ok(item) => item,
        Err(status) => return status,
    };
    if item.directory {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if from_user_mode && item.access & 1 == 0 {
        return STATUS_ACCESS_DENIED;
    }
    if from_user_mode && (!user_probe::probe_user_read(output_buffer, 16) || !user_probe::probe_user_write(output_buffer, 2) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4))) {
        return STATUS_ACCESS_VIOLATION;
    }
    match query_link_into(&item, output_buffer, output_length, from_user_mode) {
        Ok(status) | Err(status) => status,
    }
}

/// LinkTarget (UNICODE_STRING do chamador) e ReturnedLength, sondados.
fn query_link_into(item: &Opened, output_buffer: u64, output_length: u64, from_user_mode: bool) -> Result<u32, u32> {
    let maximum = read_field::<u16>(output_buffer, offset_of!(UnicodeString, maximum_length))? as u32;
    let buffer = read_field::<u64>(output_buffer, offset_of!(UnicodeString, buffer))?;
    let units: Vec<u16> = namespace_objects::target(item.body).unwrap_or_default().encode_utf16().collect();
    let length = units.len() as u32 * 2;
    if output_length != 0 {
        write_field::<u32>(output_length, 0, length)?;
    }
    if maximum < length {
        return Ok(0xC000_0023);
    }
    if length != 0 && (buffer == 0 || (from_user_mode && !user_probe::probe_user_write(buffer, length as u64))) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    write_text(buffer, &utf16_bytes(&units))?;
    write_field::<u16>(output_buffer, offset_of!(UnicodeString, length), length as u16)?;
    Ok(0)
}

/// NtMakeTemporaryObject: o nome sai no último fechamento. `None` quando o
/// handle não é de namespace.
pub fn make_temporary(handle: u64) -> Option<u32> {
    match resolve(handle, false) {
        Ok(item) => {
            namespace_objects::set_permanent(item.body, false);
            Some(0)
        }
        Err(STATUS_OBJECT_TYPE_MISMATCH) => None,
        Err(status) => Some(status),
    }
}

/// ZwMakeTemporaryObject: os objetos de callback do Executive primeiro,
/// depois os nós do namespace; outro handle = STATUS_INVALID_HANDLE.
pub fn make_temporary_object(handle: u64) -> Result<u32, KernelError> {
    if let Some(status) = executive_callbacks::make_temporary(handle)? {
        return Ok(status);
    }
    Ok(make_temporary(handle).unwrap_or(STATUS_INVALID_HANDLE))
}

/// NtQueryDirectoryObject: descritores nome/tipo, um terminador vazio e os
/// textos UTF-16 no mesmo buffer, a partir do índice do contexto.
#[allow(clippy::too_many_arguments)]
pub fn query_directory(handle: u64, output_buffer: u64, length: u32, single_entry: bool, restart_scan: bool, context: u64, output_length: u64) -> u32 {
    query_directory_mode(handle, output_buffer, length, single_entry, restart_scan, context, output_length, false)
}

/// NtQueryDirectoryObject(DirectoryHandle, Buffer, Length, ReturnSingleEntry,
/// RestartScan, Context*, ReturnLength*) (ntoskrnl 19041, rva 0x6da0a0). Em
/// UserMode o Buffer passa pelo ProbeForWrite com alinhamento de WCHAR e o
/// Context e o ReturnLength pela sonda de escrita de um ULONG; o Context é
/// lido antes do handle (sem RestartScan). Length + 0x20 que estoura é
/// STATUS_INVALID_PARAMETER; o handle precisa de DIRECTORY_QUERY num
/// diretório.
#[allow(clippy::too_many_arguments)]
pub fn query_directory_mode(handle: u64, output_buffer: u64, length: u32, single_entry: bool, restart_scan: bool, context: u64, output_length: u64, from_user_mode: bool) -> u32 {
    if from_user_mode {
        if length != 0 && (output_buffer & 1 != 0) {
            return 0x8000_0002;
        }
        if (length != 0 && !user_probe::probe_user_write(output_buffer, u64::from(length))) || !user_probe::probe_user_write(context, 4) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return STATUS_ACCESS_VIOLATION;
        }
    } else if context == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    let start = if restart_scan {
        0
    } else {
        match read_field::<u32>(context, 0) {
            Ok(start) => start as usize,
            Err(status) => return status,
        }
    };
    if length.checked_add(ObjectDirectoryInformation::SIZE as u32).is_none() {
        return 0xC000_000D;
    }
    let item = match resolve(handle, from_user_mode) {
        Ok(item) => item,
        Err(status) => return status,
    };
    if !item.directory {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if from_user_mode && item.access & 1 == 0 {
        return STATUS_ACCESS_DENIED;
    }
    match query_directory_into(&item, output_buffer, length, single_entry, start, context, output_length) {
        Ok(status) | Err(status) => status,
    }
}

/// A varredura do NtQueryDirectoryObject: a imagem de saída é montada num
/// buffer zerado (descritores OBJECT_DIRECTORY_INFORMATION, o terminador
/// vazio e os textos, com os ponteiros já no buffer do chamador) e os
/// min(Length, total) primeiros bytes vão para o chamador; o ReturnLength
/// recebe o total e o Context o índice seguinte, salvo nas falhas.
/// - sem entradas a partir do índice: STATUS_NO_MORE_ENTRIES, total 0x20;
/// - uma entrada que não cabe: com ReturnSingleEntry,
///   STATUS_BUFFER_TOO_SMALL e o total que ela pediria; sem, a varredura
///   para ali com STATUS_MORE_ENTRIES (mesmo sem nenhuma entrada copiada);
/// - senão STATUS_SUCCESS.
fn query_directory_into(item: &Opened, output_buffer: u64, length: u32, single_entry: bool, start: usize, context: u64, output_length: u64) -> Result<u32, u32> {
    let entry_size = ObjectDirectoryInformation::SIZE as u32;
    // Ordem de inserção: os ids da arena são alocados na inserção.
    let mut children: Vec<(NodeId, String, String)> = object_manager::node(item.node)
        .and_then(|node| node.children)
        .map(|children| children.values().filter_map(|&child| object_manager::node(child).map(|node| (child, node.name, node.type_name))).collect())
        .unwrap_or_default();
    children.sort_by_key(|(id, _, _)| *id);
    let mut rows = Vec::new();
    let mut total = entry_size;
    let mut status = 0x8000_001A;
    let mut next = start;
    for child in children.iter().skip(start) {
        let entry = entry_size + (child.1.encode_utf16().count() + child.2.encode_utf16().count() + 2) as u32 * 2;
        if total + entry > length {
            if single_entry {
                status = 0xC000_0023;
                total += entry;
            } else {
                status = 0x105;
            }
            break;
        }
        rows.push(child);
        total += entry;
        next += 1;
        status = 0;
        if single_entry {
            break;
        }
    }
    if status == 0 && !single_entry && next < children.len() {
        status = 0x105;
    }
    let mut image = vec![0u8; total as usize];
    if status & 0x8000_0000 == 0 {
        let mut strings = (rows.len() + 1) * entry_size as usize;
        for (index, row) in rows.iter().enumerate() {
            let descriptor = index * entry_size as usize;
            for (offset, text) in [(offset_of!(ObjectDirectoryInformation, name), &row.1), (offset_of!(ObjectDirectoryInformation, type_name), &row.2)] {
                let unicode = descriptor + offset;
                let bytes = utf16_bytes(&text.encode_utf16().collect::<Vec<u16>>());
                let text_length = bytes.len();
                image[unicode + offset_of!(UnicodeString, length)..][..2].copy_from_slice(&(text_length as u16).to_le_bytes());
                image[unicode + offset_of!(UnicodeString, maximum_length)..][..2].copy_from_slice(&(text_length as u16 + 2).to_le_bytes());
                image[unicode + offset_of!(UnicodeString, buffer)..][..8].copy_from_slice(&(output_buffer + strings as u64).to_le_bytes());
                image[strings..][..text_length].copy_from_slice(&bytes);
                strings += text_length + 2;
            }
        }
    }
    write_text(output_buffer, &image[..total.min(length) as usize])?;
    if output_length != 0 {
        write_field::<u32>(output_length, 0, total)?;
    }
    if status & 0x8000_0000 == 0 {
        write_field::<u32>(context, 0, next as u32)?;
    }
    Ok(status)
}

/// ObMakeTemporaryObject(Object) (ntoskrnl 0x6f6210): limpa OBJ_PERMANENT
/// (OBJECT_HEADER.Flags 0x10, sob o lock do objeto) e roda o
/// ObpDeleteNameCheck: sem handles abertos, o nome sai do diretório já.
///
/// No OpenNT a permanência é modelada nos corpos de Directory/SymbolicLink
/// (`objects::namespace`); para eles o nome sai quando não há handles (senão
/// no último fechamento, pelo `namespace_objects::close`). Os corpos
/// publicados por ObInsertObject com nome (`ob::object_create`) não contam
/// handles nem permanência: o nome nunca seria retirado, então sai aqui, que é
/// o momento em que o NT o retira no caso comum (FltCloseCommunicationPort
/// depois de fechar o handle do criador).
pub fn make_temporary_by_pointer(object: u64) {
    if let Some((node, _)) = namespace_objects::get(object) {
        namespace_objects::set_permanent(object, false);
        if namespace_objects::handles(object) == 0 && object_manager::is_attached(node) {
            object_manager::remove_named(node);
        }
        return;
    }
    let named = object_manager::namespace_entries().into_iter().map(|(node, _)| node).find(|&node| {
        object_manager::node(node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == object)
    });
    if let Some(node) = named {
        let type_name = object_manager::node(node).map(|node| node.type_name).unwrap_or_default();
        // Dispositivos e drivers têm donos próprios no OpenNT e não passam por aqui.
        if type_name != "Device" && type_name != "Driver" {
            object_manager::remove_named(node);
        }
    }
}
