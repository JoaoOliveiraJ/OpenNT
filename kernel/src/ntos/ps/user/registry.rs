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
use crate::ntos::cm::{computer_name, crypto_defaults, registry};
use crate::ntos::cm::key::objects as key_objects;
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
            Some(root) => root.object.object_path()?,
            None => {
                let opened = crate::ntos::ob::handles::namespace::resolve(root_directory, true).ok().filter(|opened| opened.directory)?;
                crate::ntos::ob::object_manager::path_of(opened.node)?
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

/// Seed dos valores reais que o loader lê; as páginas de código batem com
/// os NLS mapeados (1252/437).
pub fn seed_registry_for_user_mode() -> Result<(), KernelError> {
    let set_sz = |handle: u32, name: &str, text: &str| registry::set_value(handle, name, 1, utf16_bytes(text));
    let set_dword = |handle: u32, name: &str, value: u32| registry::set_value(handle, name, 4, value.to_le_bytes().to_vec());
    let set_multi_sz = |handle: u32, name: &str, strings: &[&str]| {
        let mut data: Vec<u8> = strings.iter().flat_map(|text| utf16_bytes(text)).collect();
        data.extend_from_slice(&[0, 0]);
        registry::set_value(handle, name, 7, data)
    };
    let code_page = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\CodePage", None)?;
    set_sz(code_page, "ACP", "1252");
    set_sz(code_page, "OEMCP", "437");
    set_sz(code_page, "MACCP", "10000");
    set_sz(code_page, "OEMHAL", "vgaoem.fon");
    let session_manager = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager", None)?;
    set_dword(session_manager, "SafeMode", 0);
    if crate::ntos::init::boot_config::SMSS_BOOT {
        // O smss real lê a configuração do Session Manager e cria ele mesmo
        // o \KnownDlls.
        crate::ntos::cm::session_manager::initialize()?;
        crate::ntos::cm::ini_file_mapping::initialize()?;
    } else {
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
    crypto_defaults::initialize()?;
    computer_name::initialize()?;
    // Image File Execution Options existe, vazia.
    registry::open_or_create("\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", None)?;
    debug_print!("[usermode] registry seedada (NLS/SessionManager/KnownDlls/SegmentHeap/ProductOptions/IFEO)");
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

fn nt_enumerate_key(handle: u64, index: u64, klass: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::EnumerateKey, handle, &arguments(&[("index", index), ("klass", klass), ("out", out), ("length", state::stack_arg32(rsp, 5) as u64), ("returned", state::stack_arg(rsp, 6))]), true)
}

fn nt_enumerate_value_key(handle: u64, index: u64, klass: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    key_services::key_operation(Kind::EnumerateValue, handle, &arguments(&[("index", index), ("klass", klass), ("out", out), ("length", state::stack_arg32(rsp, 5) as u64), ("returned", state::stack_arg(rsp, 6))]), true)
}

/// Registra os handlers Nt*Key e a tabela de handles `key` do processo.
pub fn init() {
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
    state::register_handler("NtEnumerateKey", nt_enumerate_key);
    state::register_handler("NtEnumerateValueKey", nt_enumerate_value_key);
}
