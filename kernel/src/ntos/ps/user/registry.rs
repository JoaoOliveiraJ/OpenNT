//! O registro visto do ring 3.
//!
//! Interpretação de OBJECT_ATTRIBUTES de usuário (com raiz de chave, de
//! diretório ou de diretório aberto como arquivo), o seed dos valores reais
//! que o loader lê (NLS, Session Manager, KnownDlls, Segment Heap,
//! ProductOptions, IFEO) e os handlers Nt*Key, que atravessam para o
//! serviço de chaves com PreviousMode de usuário. Também instala a tabela de
//! handles de usuário do serviço de chaves (handles `key` do processo).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::state::{self, NativeBody, UserObject};
use crate::ntos::cm::key::services::{self as key_services, Kind, UserHandles, UserKeyRecord};
use crate::ntos::cm::{computer_name, hive_services, registry};
use crate::ntos::cm::key::objects as key_objects;
use crate::ntos::cm::notify as cm_notify;
use crate::ntos::ob::object_types;
use crate::rtl::KernelError;
use crate::ntos::inc::types::{NtStruct, ObjectAttributes, UnicodeString};

/// OBJECT_ATTRIBUTES interpretado: caminho absoluto (vazio = abertura pela
/// classe) e a raiz original.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub path: String,
    pub root_directory: u64,
}

/// OBJECT_ATTRIBUTES de usuário: estrutura, ObjectName e o texto são
/// sondados; cada campo é lido uma vez.
pub fn parse_user_object_attributes(attributes: u64) -> Option<Parsed> {
    if !state::probe_user_read(attributes, ObjectAttributes::SIZE) {
        return None;
    }
    let object = state::user_struct::<ObjectAttributes>(attributes).ok()?;
    if object.length.probe_get().ok()? < ObjectAttributes::SIZE as u32 {
        return None;
    }
    let root_directory = object.root_directory.probe_get().ok()?;
    let name_pointer = object.object_name.probe_get().ok()?;
    // Sem ObjectName: abertura "pela classe" (o handler decide).
    if name_pointer == 0 {
        return Some(Parsed { path: String::new(), root_directory });
    }
    if !state::probe_user_read(name_pointer, UnicodeString::SIZE) {
        return None;
    }
    let object_name = state::user_struct::<UnicodeString>(name_pointer).ok()?;
    let length = object_name.length.probe_get().ok()? as u64;
    let buffer = object_name.buffer.probe_get().ok()?;
    if length & 1 != 0 || (length != 0 && !state::probe_user_read(buffer, length)) {
        return None;
    }
    let name = state::try_read_user_wide_string(buffer, length / 2).ok()?;
    let mut path = name.clone();
    if root_directory != 0 {
        // Raiz de registro (chave) ou de objetos (diretório, inclusive aberto
        // como arquivo, ou o handle nativo de um diretório do namespace).
        let root_path = match state::get_user_handle(root_directory) {
            // Um arquivo de dispositivo: o nome vai como veio, relativo ao
            // FILE_OBJECT da raiz (o IopParseFile, `files::open_file`).
            Some(root) if root.kind() == "device" => return Some(Parsed { path: name, root_directory }),
            Some(root) => root.object.object_path()?,
            None => {
                // Um namespace privado (diretório sem nome) dá o caminho ancorado.
                let opened = crate::ntos::ob::handles::namespace::resolve(root_directory, true).ok().filter(|opened| opened.directory)?;
                crate::ntos::ob::object_manager::anchored_path_of(opened.node)?
            }
        };
        path = alloc::format!("{}{}{}", root_path, if root_path.ends_with('\\') { "" } else { "\\" }, name);
    }
    Some(Parsed { path, root_directory })
}

/// OBJECT_ATTRIBUTES.Attributes (OBJ_*) de um OA de usuário já aceito por
/// [`parse_user_object_attributes`]; sem OA, nenhum atributo.
pub fn user_object_attributes(attributes: u64) -> Result<u32, KernelError> {
    if attributes == 0 {
        return Ok(0);
    }
    state::user_struct::<ObjectAttributes>(attributes)?.attributes.probe_get()
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().chain([0]).flat_map(|unit| unit.to_le_bytes()).collect()
}

/// Seed dos valores reais que o loader lê. As páginas de código não entram:
/// `Control\Nls\CodePage` é dado da instalação (a hive SYSTEM do boot do
/// smss o traz do xtask), e o kernel segue o que estiver lá
/// (`rtl/nls_configuration`).
pub fn seed_registry_for_user_mode() -> Result<(), KernelError> {
    let set_sz = |handle: u32, name: &str, text: &str| registry::set_value(handle, name, 1, utf16_bytes(text));
    let set_dword = |handle: u32, name: &str, value: u32| registry::set_value(handle, name, 4, value.to_le_bytes().to_vec());
    let set_multi_sz = |handle: u32, name: &str, strings: &[&str]| {
        let mut data: Vec<u8> = strings.iter().flat_map(|text| utf16_bytes(text)).collect();
        data.extend_from_slice(&[0, 0]);
        registry::set_value(handle, name, 7, data)
    };
    let session_manager = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager", None)?;
    set_dword(session_manager, "SafeMode", 0);
    // No boot do processo inicial real, o smss lê a configuração do Session
    // Manager da hive SYSTEM (`cm/session_manager.rs`) e cria ele mesmo o
    // \KnownDlls; o IniFileMapping vem da hive SOFTWARE (`cm/seed.rs`).
    if !crate::ntos::init::boot_config::smss_boot() {
        // KnownDlls: a lista das DLLs conhecidas que o kernel provisiona e o
        // diretório delas.
        let known = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\KnownDlls", None)?;
        set_sz(known, "DllDirectory", "C:\\Windows\\System32");
        set_multi_sz(
            known,
            "KnownDlls",
            &[
                "ntdll.dll", "kernel32.dll", "KERNELBASE.dll", "advapi32.dll", "rpcrt4.dll", "sechost.dll", "msvcrt.dll", "ucrtbase.dll", "bcrypt.dll", "bcryptprimitives.dll", "crypt32.dll", "wintrust.dll", "user32.dll", "win32u.dll", "gdi32.dll", "imm32.dll", "ole32.dll", "combase.dll", "shell32.dll", "shlwapi.dll", "ws2_32.dll", "wldap32.dll", "wtsapi32.dll", "userenv.dll", "profapi.dll", "iphlpapi.dll", "version.dll", "imagehlp.dll", "psapi.dll", "msvcp_win.dll", "cryptbase.dll", "sspicli.dll", "nsi.dll", "dhcpcsvc.dll", "winnsi.dll", "normaliz.dll", "clbcatq.dll",
                "kernel.appcore.dll", "cfgmgr32.dll", "apisetschema.dll",
            ],
        );
    }
    // Segment Heap desligado: o loader toma o caminho do heap NT clássico.
    let segment_heap = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Segment Heap", None)?;
    set_dword(segment_heap, "Enabled", 0);
    let product = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions", None)?;
    set_sz(product, "ProductType", "WinNT");
    computer_name::initialize()?;
    // Image File Execution Options existe, vazia.
    registry::open_or_create("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", None)?;
    debug_print!("[usermode] registry seedada (SessionManager/KnownDlls/SegmentHeap/ProductOptions/IFEO)");
    Ok(())
}

/// Handle `key` do processo: o handle interno da hive e o corpo Key.
pub struct UserKey {
    pub khandle: u32,
    pub body: u64,
}

impl UserObject for UserKey {
    fn kind(&self) -> &'static str {
        "key"
    }
    fn native_body(&self) -> Option<NativeBody> {
        if self.body == 0 {
            return None;
        }
        let body = self.body;
        Some(NativeBody {
            pointer: body,
            type_name: object_types::key_type().name.clone(),
            record: body,
            reference: Arc::new(move || {
                key_objects::hold(body);
            }),
            dereference: Arc::new(move || {
                let _ = key_objects::release(body);
            }),
        })
    }
    /// Liberação no NtClose: fecha o handle interno da hive.
    fn release(&self) {
        registry::close_handle(self.khandle);
    }
    fn object_path(&self) -> Option<String> {
        registry::get_path(self.khandle)
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn user_key(handle: u64) -> Option<UserKeyRecord> {
    let entry = state::get_user_handle(handle).filter(|entry| entry.kind() == "key")?;
    let key = entry.downcast::<UserKey>()?;
    Some(UserKeyRecord { khandle: key.khandle, access: entry.access() })
}

fn allocate_user_key(khandle: u32, access: u32, attributes: u32, body: u64) -> Result<u64, KernelError> {
    Ok(state::alloc_user_handle(Arc::new(UserKey { khandle, body }), access, attributes & 2)? as u64)
}

fn close_user_key(handle: u64) {
    let _ = state::close_user_handle(handle, false, false);
}

fn arguments(pairs: &[(&'static str, u64)]) -> key_services::Fields {
    key_services::fields(pairs)
}

fn nt_open_key(output: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    key_services::open(output, access as u32, attributes, true, 0)
}

fn nt_open_key_ex(output: u64, access: u64, attributes: u64, options: u64, _rsp: u64) -> Result<u32, KernelError> {
    key_services::open(output, access as u32, attributes, true, options as u32)
}

fn nt_create_key(output: u64, access: u64, attributes: u64, title: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::create(output, access as u32, attributes, title as u32, state::stack_arg(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), true)
}

fn nt_query_key(handle: u64, klass: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::QueryKey, handle, &arguments(&[("klass", klass), ("out", out), ("length", length), ("returned", state::stack_arg(rsp, 5))]), true)
}

fn nt_set_information_key(handle: u64, klass: u64, data: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::SetInfo, handle, &arguments(&[("klass", klass), ("data", data), ("length", length)]), true)
}

fn nt_set_value_key(handle: u64, name: u64, title: u64, value_type: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::Set, handle, &arguments(&[("name", name), ("title", title), ("type", value_type), ("data", state::stack_arg(rsp, 5)), ("length", state::stack_arg32(rsp, 6) as u64)]), true)
}

fn nt_delete_value_key(handle: u64, name: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::DeleteValue, handle, &arguments(&[("name", name)]), true)
}

fn nt_delete_key(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::DeleteKey, handle, &arguments(&[]), true)
}

fn nt_query_value_key(handle: u64, name: u64, klass: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::QueryValue, handle, &arguments(&[("name", name), ("klass", klass), ("out", out), ("length", state::stack_arg32(rsp, 5) as u64), ("returned", state::stack_arg(rsp, 6))]), true)
}

/// NtQueryMultipleValueKey(KeyHandle, ValueEntries, EntryCount, ValueBuffer,
/// BufferLength, RequiredBufferLength).
fn nt_query_multiple_value_key(handle: u64, entries: u64, count: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::query_multiple_values(handle, entries, count as u32, buffer, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), true)
}

fn nt_enumerate_key(handle: u64, index: u64, klass: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::EnumerateKey, handle, &arguments(&[("index", index), ("klass", klass), ("out", out), ("length", state::stack_arg32(rsp, 5) as u64), ("returned", state::stack_arg(rsp, 6))]), true)
}

fn nt_enumerate_value_key(handle: u64, index: u64, klass: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::EnumerateValue, handle, &arguments(&[("index", index), ("klass", klass), ("out", out), ("length", state::stack_arg32(rsp, 5) as u64), ("returned", state::stack_arg(rsp, 6))]), true)
}

/// NtNotifyChangeKey(KeyHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
/// CompletionFilter, WatchTree, Buffer, BufferSize, Asynchronous): o
/// NtNotifyChangeMultipleKeys com Count 0 (`cm/notify`).
fn nt_notify_change_key(handle: u64, event: u64, apc_routine: u64, apc_context: u64, rsp: u64) -> Result<u32, KernelError> {
    cm_notify::notify_change_multiple_keys(&cm_notify::Request {
        master_key: handle,
        count: 0,
        subordinate_objects: 0,
        event,
        apc_routine,
        apc_context,
        io_status: state::stack_arg(rsp, 5),
        filter: state::stack_arg32(rsp, 6),
        watch_tree: state::stack_arg32(rsp, 7) as u8 != 0,
        buffer: state::stack_arg(rsp, 8),
        buffer_size: state::stack_arg32(rsp, 9),
        asynchronous: state::stack_arg32(rsp, 10) as u8 != 0,
    })
}

/// NtNotifyChangeMultipleKeys(MasterKeyHandle, Count, SubordinateObjects,
/// Event, ApcRoutine, ApcContext, IoStatusBlock, CompletionFilter,
/// WatchTree, Buffer, BufferSize, Asynchronous).
fn nt_notify_change_multiple_keys(handle: u64, count: u64, subordinate: u64, event: u64, rsp: u64) -> Result<u32, KernelError> {
    cm_notify::notify_change_multiple_keys(&cm_notify::Request {
        master_key: handle,
        count: count as u32,
        subordinate_objects: subordinate,
        event,
        apc_routine: state::stack_arg(rsp, 5),
        apc_context: state::stack_arg(rsp, 6),
        io_status: state::stack_arg(rsp, 7),
        filter: state::stack_arg32(rsp, 8),
        watch_tree: state::stack_arg32(rsp, 9) as u8 != 0,
        buffer: state::stack_arg(rsp, 10),
        buffer_size: state::stack_arg32(rsp, 11),
        asynchronous: state::stack_arg32(rsp, 12) as u8 != 0,
    })
}

// Serviços de hive com PreviousMode de usuário (`cm/hive_services`).

fn nt_load_key(target: u64, source: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::load_key(target, source, 0, 0, 0, 0, 0, true))
}

fn nt_load_key2(target: u64, source: u64, flags: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::load_key(target, source, flags as u32, 0, 0, 0, 0, true))
}

fn nt_load_key_ex(target: u64, source: u64, flags: u64, trust_class_key: u64, rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::load_key(target, source, flags as u32, trust_class_key, state::stack_arg(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), true))
}

fn nt_load_key3(target: u64, source: u64, flags: u64, extended: u64, rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::load_key3(target, source, flags as u32, extended, state::stack_arg32(rsp, 5), state::stack_arg32(rsp, 6), state::stack_arg(rsp, 7), true))
}

fn nt_unload_key(target: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::unload_key(target, 0, false, 0, true))
}

fn nt_unload_key2(target: u64, flags: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::unload_key(target, flags as u32, false, 0, true))
}

fn nt_unload_key_ex(target: u64, event: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::unload_key(target, 0, true, event, true))
}

fn nt_save_key(key: u64, file: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::save_key(key, file, 1, true))
}

fn nt_save_key_ex(key: u64, file: u64, format: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::save_key(key, file, format as u32, true))
}

fn nt_restore_key(key: u64, file: u64, flags: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::restore_key(key, file, flags as u32, true))
}

fn nt_flush_key(key: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::flush_key(key, true))
}

fn nt_compact_keys(count: u64, array: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::compact_keys(count as u32, array, true))
}

fn nt_compress_key(key: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::compress_key(key, true))
}

/// NtQueryOpenSubKeys(TargetKey, HandleCount).
fn nt_query_open_sub_keys(target: u64, handle_count: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::query_open_sub_keys(target, handle_count, true))
}

/// NtQueryOpenSubKeysEx(TargetKey, BufferLength, Buffer, RequiredSize).
fn nt_query_open_sub_keys_ex(target: u64, length: u64, buffer: u64, required: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(hive_services::query_open_sub_keys_ex(target, length as u32, buffer, required, true))
}

/// NtInitializeRegistry(BootCondition), de modo usuário (`cm/hive_init`).
fn nt_initialize_registry(boot_condition: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::cm::hive_init::initialize_registry(boot_condition as u16, 1))
}

/// Registra os handlers Nt*Key e a tabela de handles `key` do processo.
pub fn init() {
    state::register_handler("NtInitializeRegistry", nt_initialize_registry);
    state::register_handler("NtLoadKey", nt_load_key);
    state::register_handler("NtLoadKey2", nt_load_key2);
    state::register_handler("NtLoadKeyEx", nt_load_key_ex);
    state::register_handler("NtLoadKey3", nt_load_key3);
    state::register_handler("NtUnloadKey", nt_unload_key);
    state::register_handler("NtUnloadKey2", nt_unload_key2);
    state::register_handler("NtUnloadKeyEx", nt_unload_key_ex);
    state::register_handler("NtSaveKey", nt_save_key);
    state::register_handler("NtSaveKeyEx", nt_save_key_ex);
    state::register_handler("NtRestoreKey", nt_restore_key);
    state::register_handler("NtFlushKey", nt_flush_key);
    state::register_handler("NtCompactKeys", nt_compact_keys);
    state::register_handler("NtCompressKey", nt_compress_key);
    state::register_handler("NtQueryOpenSubKeys", nt_query_open_sub_keys);
    state::register_handler("NtQueryOpenSubKeysEx", nt_query_open_sub_keys_ex);
    key_services::set_user_handles(Some(UserHandles { get: user_key, allocate: allocate_user_key, close: close_user_key }));
    state::register_handler("NtOpenKey", nt_open_key);
    state::register_handler("NtOpenKeyEx", nt_open_key_ex);
    state::register_handler("NtCreateKey", nt_create_key);
    state::register_handler("NtQueryKey", nt_query_key);
    state::register_handler("NtSetInformationKey", nt_set_information_key);
    state::register_handler("NtSetValueKey", nt_set_value_key);
    state::register_handler("NtDeleteValueKey", nt_delete_value_key);
    state::register_handler("NtDeleteKey", nt_delete_key);
    state::register_handler("NtQueryValueKey", nt_query_value_key);
    state::register_handler("NtQueryMultipleValueKey", nt_query_multiple_value_key);
    state::register_handler("NtEnumerateKey", nt_enumerate_key);
    state::register_handler("NtEnumerateValueKey", nt_enumerate_value_key);
    state::register_handler("NtNotifyChangeKey", nt_notify_change_key);
    state::register_handler("NtNotifyChangeMultipleKeys", nt_notify_change_multiple_keys);
    cm_notify::init();
}
