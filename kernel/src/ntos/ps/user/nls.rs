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
use crate::ntos::rtl::nls_configuration::{DEFAULT_LOCALE, DEFAULT_UI_LANGUAGE};
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
    let existing = state::with(|state| state.user_regions.iter().find(|region| region.section().is_some_and(|candidate| Arc::ptr_eq(&candidate, &section))).map(|region| (region.base(), region.size())));
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
    guest::write64(base, view);
    guest::write32(locale, DEFAULT_LOCALE);
    // A ABI x64 atual deixa as saídas legadas zeradas: o casing é a seção
    // independente do tipo 10 (PEB.UnicodeCaseTableData).
    if casing_size != 0 {
        guest::write64(casing_size, 0);
    }
    if version != 0 {
        guest::write32(version, 0);
    }
    Ok(0)
}

/// NtGetNlsSectionPtr(type, data, context, out*, size*).
fn nt_get_nls_section_ptr(section_type: u64, data: u64, context: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    let (section_type, data) = (section_type as u32, data as u32);
    let size = state::stack_arg(rsp, 5);
    if !probe_user_write(out, 8) || !probe_user_write(size, 8) {
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
    guest::write64(out, base);
    guest::write64(size, view_size);
    Ok(0)
}

fn nt_query_default_locale(_user: u64, out: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 4) {
        return Ok(0xC000_0005);
    }
    guest::write32(out, DEFAULT_LOCALE);
    Ok(0)
}

fn nt_query_default_ui_language(out: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(out, 2) {
        return Ok(0xC000_0005);
    }
    guest::write16(out, DEFAULT_UI_LANGUAGE as u16);
    Ok(0)
}

pub fn init() {
    state::register_handler("NtInitializeNlsFiles", nt_initialize_nls_files);
    state::register_handler("NtGetNlsSectionPtr", nt_get_nls_section_ptr);
    state::register_handler("NtQueryDefaultLocale", nt_query_default_locale);
    state::register_handler("NtQueryDefaultUILanguage", nt_query_default_ui_language);
    state::register_handler("NtQueryInstallUILanguage", nt_query_default_ui_language);
}
