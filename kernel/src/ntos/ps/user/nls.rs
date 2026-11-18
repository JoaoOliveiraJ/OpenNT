//! Mapeamentos NLS nativos.
//!
//! As tabelas vêm da mesma instalação do Windows que as DLLs carregadas
//! (o volume); nenhum dado sintético de locale ou collation as substitui.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::sections::{self, CreateOptions, MapRequest, Section, SectionFile};
use super::state::{self, probe_user_write};
use crate::ntos::cm::registry;
use crate::drivers::fs::volume_files;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

static TABLES: SpinLock<BTreeMap<String, Arc<Section>>> = SpinLock::new(BTreeMap::new());
static SORTING_VERSION: SpinLock<Option<u32>> = SpinLock::new(None);

/// Versão de ordenação do SortDefault.nls publicada no registro.
fn initialize_sorting() -> Result<(), KernelError> {
    if SORTING_VERSION.lock().is_some() {
        return Ok(());
    }
    let file = volume_files::lookup_volume_file("C:\\Windows\\Globalization\\Sorting\\SortDefault.nls").filter(|file| file.size() >= 16).ok_or_else(|| KernelError::new("NLS: SortDefault.nls missing"))?;
    let header = file.read_at(0, 16)?;
    let offset = u32::from_le_bytes([header[12], header[13], header[14], header[15]]) as u64;
    if offset < 16 || offset + 8 > file.size() {
        return Err(KernelError::new("NLS: invalid sort header"));
    }
    let bytes = file.read_at(offset, 8)?;
    let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    *SORTING_VERSION.lock() = Some(version);
    let key = registry::open_or_create("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Sorting\\Versions", None)?;
    let set_string = |name: &str, value: &str| {
        let mut data: Vec<u8> = value.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        data.extend_from_slice(&[0, 0]);
        registry::set_value(key, name, 1, data);
    };
    let text = format!("{version:08x}");
    set_string("", &text);
    set_string(&format!("{}xx", &text[..6]), "kernel32.dll");
    registry::close_handle(key);
    Ok(())
}

/// ExInitializeNls (ntoskrnl 19041 rva 0xa73ec4, do
/// Phase1InitializationDiscard): o diretório `\NLS` (ZwCreateDirectoryObject
/// com DIRECTORY_ALL_ACCESS, OBJ_PERMANENT | OBJ_KERNEL_HANDLE |
/// OBJ_CASE_INSENSITIVE e sem descritor). No NT o NtGetNlsSectionPtr cria
/// nele, sob demanda, as seções `NlsSectionCP%d` e `NlsSectionNORM%.8x`; aqui
/// as tabelas são as seções permanentes sem nome de [`map_table`].
pub fn initialize_directory() -> Result<(), KernelError> {
    crate::ntos::ob::object_manager::create_directory("\\NLS").map(|_| ())
}

/// Seção permanente da tabela (uma por nome) e a vista do processo.
pub fn map_table(name: &str) -> Result<Result<(u64, u64), u32>, KernelError> {
    let cached = TABLES.lock().get(name).cloned();
    let section = match cached {
        Some(section) => section,
        None => {
            let Some(file) = volume_files::lookup_volume_file(&format!("C:\\Windows\\System32\\{name}")).filter(|file| !file.directory()) else { return Ok(Err(0xC000_0034)) };
            let size = file.size();
            let backing: Arc<dyn SectionFile> = file;
            let section = match sections::create(CreateOptions { size, file: Some(backing), page_protect: 2, attributes: 0x0800_0000, permanent: true, ..CreateOptions::default() })? {
                Ok(section) => section,
                Err(status) => return Ok(Err(status)),
            };
            TABLES.lock().insert(String::from(name), section.clone());
            section
        }
    };
    let existing = super::memory::Space::current().regions().iter().find(|region| region.section().is_some_and(|candidate| Arc::ptr_eq(&candidate, &section))).map(|region| (region.base(), region.size()));
    if let Some(view) = existing {
        return Ok(Ok(view));
    }
    Ok(match sections::map(&section, &MapRequest { protect: 2, ..MapRequest::default() })? {
        Ok(view) => {
            crate::debug_print!("[nls] {} -> {:#x}", name, view.base);
            Ok((view.base, view.size))
        }
        Err(status) => Err(status),
    })
}

/// NtInitializeNlsFiles(base*, locale*, casingSize*, version*).
fn nt_initialize_nls_files(base: u64, locale: u64, casing_size: u64, version: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(base, 8) || !probe_user_write(locale, 4) || (casing_size != 0 && !probe_user_write(casing_size, 8)) || (version != 0 && !probe_user_write(version, 4)) {
        return Ok(0xC000_0005);
    }
    initialize_sorting()?;
    let (view, _) = match map_table("locale.nls")? {
        Ok(view) => view,
        Err(status) => return Ok(status),
    };
    // PVOID *BaseAddress, LCID *DefaultLocaleId, LARGE_INTEGER
    // *DefaultCasingTableSize e ULONG *CurrentNLSVersion, sondados acima.
    let written = guest::try_write::<u64>(base, view).and_then(|()| guest::try_write::<u32>(locale, crate::ntos::ps::locale::default_system_locale())).and_then(|()| {
        // A ABI x64 atual deixa as saídas legadas zeradas: o casing é a seção
        // independente do tipo 10 (PEB.UnicodeCaseTableData).
        if casing_size != 0 {
            guest::try_write::<u64>(casing_size, 0)?;
        }
        if version != 0 {
            guest::try_write::<u32>(version, 0)?;
        }
        Ok(())
    });
    Ok(if written.is_err() { 0xC000_0005 } else { 0 })
}

/// NtGetNlsSectionPtr(type, data, context, out*, size*).
fn nt_get_nls_section_ptr(section_type: u64, data: u64, context: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    let (section_type, data) = (section_type as u32, data as u32);
    let size = state::stack_arg(rsp, 5);
    // SectionPointer (PVOID*) e SectionSize (ULONG*).
    if !probe_user_write(out, 8) || !probe_user_write(size, 4) {
        return Ok(0xC000_0005);
    }
    if context != 0 {
        return Ok(0xC000_00BB);
    }
    let name = match (section_type, data) {
        (9, 0) => Some(String::from("SortDefault.nls")),
        (10, 0) => Some(String::from("l_intl.nls")),
        (11, 1..=65535) => Some(format!("C_{data}.NLS")),
        (12, 1) => Some(String::from("normnfc.nls")),
        (12, 2) => Some(String::from("normnfd.nls")),
        (12, 5) => Some(String::from("normnfkc.nls")),
        (12, 6) => Some(String::from("normnfkd.nls")),
        (12, 13) => Some(String::from("normidna.nls")),
        _ => None,
    };
    let Some(name) = name else { return Ok(0xC000_000D) };
    let (base, view_size) = match map_table(&name)? {
        Ok(view) => view,
        Err(status) => return Ok(status),
    };
    let written = guest::try_write::<u64>(out, base).and_then(|()| guest::try_write::<u32>(size, view_size as u32));
    Ok(if written.is_err() { 0xC000_0005 } else { 0 })
}

/// NtQueryDefaultLocale(UserProfile, DefaultLocaleId*): o LCID do usuário
/// ou do sistema (`ps/locale`).
fn nt_query_default_locale(user: u64, out: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 4) {
        return Ok(0xC000_0005);
    }
    // LCID de saída (sondado acima).
    Ok(if guest::try_write::<u32>(out, crate::ntos::ps::locale::default_locale(user as u8 != 0)).is_err() { 0xC000_0005 } else { 0 })
}

/// LANGID de saída de um serviço de idioma, sondado.
fn write_language(out: u64, language: u32) -> u32 {
    if !probe_user_write(out, 2) {
        return 0xC000_0005;
    }
    // LANGID de saída (sondado acima).
    if guest::try_write::<u16>(out, language as u16).is_err() { 0xC000_0005 } else { 0 }
}

/// NtQueryDefaultUILanguage: o PsDefaultUILanguageId.
fn nt_query_default_ui_language(out: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(write_language(out, crate::ntos::ps::locale::default_ui_language()))
}

/// NtQueryInstallUILanguage: o PsInstallUILanguageId.
fn nt_query_install_ui_language(out: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(write_language(out, crate::ntos::ps::locale::install_ui_language()))
}

/// NtIsUILanguageComitted() (`ps/locale`).
fn nt_is_ui_language_comitted(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ps::locale::is_ui_language_committed())
}

/// NtFlushInstallUILanguage(InstallUILanguage, SetComittedFlag) de modo
/// usuário: sem SeTcbPrivilege no modo anterior, STATUS_ACCESS_DENIED; o
/// resto em `ps/locale`. (O 19041 recusa o chamador de modo kernel com
/// STATUS_UNSUCCESSFUL: só a entrada de usuário existe.)
fn nt_flush_install_ui_language(language: u64, set_committed: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !crate::ntos::se::privilege::single_privilege_check(SE_TCB_PRIVILEGE, 1) {
        return Ok(0xC000_0022);
    }
    Ok(crate::ntos::ps::locale::flush_install_ui_language(language as u16, set_committed as u32 != 0))
}

/// SeTcbPrivilege.
const SE_TCB_PRIVILEGE: u64 = 7;

pub fn init() {
    state::register_handler("NtIsUILanguageComitted", nt_is_ui_language_comitted);
    state::register_handler("NtFlushInstallUILanguage", nt_flush_install_ui_language);
    state::register_handler("NtInitializeNlsFiles", nt_initialize_nls_files);
    state::register_handler("NtGetNlsSectionPtr", nt_get_nls_section_ptr);
    state::register_handler("NtQueryDefaultLocale", nt_query_default_locale);
    state::register_handler("NtQueryDefaultUILanguage", nt_query_default_ui_language);
    state::register_handler("NtQueryInstallUILanguage", nt_query_install_ui_language);
}
