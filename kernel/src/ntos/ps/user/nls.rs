//! Mapeamentos NLS nativos.
//!
//! As tabelas vêm da mesma instalação do Windows que as DLLs carregadas
//! (o volume); nenhum dado sintético de locale ou collation as substitui.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::sections::{self, CreateOptions, MapRequest, Section};
use super::state::{self, probe_user_write};
use crate::ntos::cm::registry;
use crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
/// SEC_COMMIT e PAGE_READONLY das seções das tabelas.
const SEC_COMMIT: u32 = 0x0800_0000;
const PAGE_READONLY: u32 = 2;
const NORMALIZATION_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Nls\\Normalization";
/// Os nomes do RtlStringCchPrintfW de 0x40 caracteres (o da seção e o do
/// arquivo).
const NAME_CAPACITY: usize = 0x40;

/// A seção permanente do locale.nls: o papel do NlsLocaleSectionPointer do
/// ExpGetGlobalLocaleSection, criada na primeira chamada.
static LOCALE_SECTION: SpinLock<Option<Arc<Section>>> = SpinLock::new(None);

/// ExInitializeNls (ntoskrnl 19041 rva 0xa73ec4, do
/// Phase1InitializationDiscard): o diretório `\NLS` (ZwCreateDirectoryObject
/// com DIRECTORY_ALL_ACCESS, OBJ_PERMANENT | OBJ_KERNEL_HANDLE |
/// OBJ_CASE_INSENSITIVE e sem descritor). O NtGetNlsSectionPtr cria nele,
/// sob demanda, as seções permanentes `NlsSectionCP%d` e
/// `NlsSectionNORM%.8x` ([`nls_section`]).
pub fn initialize_directory() -> Result<(), KernelError> {
    crate::ntos::ob::object_manager::create_directory("\\NLS").map(|_| ())
}

/// ExpGetGlobalLocaleSection e o MmMapViewOfSection(ViewShare,
/// PAGE_READONLY) do NtInitializeNlsFiles: uma vista nova da seção global do
/// locale.nls a cada chamada.
fn map_locale_table() -> Result<Result<(u64, u64), u32>, KernelError> {
    let cached = LOCALE_SECTION.lock().clone();
    let section = match cached {
        Some(section) => section,
        None => {
            let backing = match crate::ntos::mm::section::file::system_section_file("\\SystemRoot\\System32\\locale.nls") {
                Ok(Some(file)) => file,
                Ok(None) => return Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND)),
                Err(status) => return Ok(Err(status)),
            };
            let size = backing.size();
            let created = match sections::create(CreateOptions { size, file: Some(backing), page_protect: PAGE_READONLY, attributes: SEC_COMMIT, permanent: true, ..CreateOptions::default() })? {
                Ok(section) => section,
                Err(status) => return Ok(Err(status)),
            };
            // Quem perde a corrida mapeia a seção de quem ganhou.
            LOCALE_SECTION.lock().get_or_insert(created).clone()
        }
    };
    Ok(match sections::map(&section, &MapRequest { protect: PAGE_READONLY, ..MapRequest::default() })? {
        Ok(view) => Ok((view.base, view.size)),
        Err(status) => Err(status),
    })
}

/// NtInitializeNlsFiles(BaseAddress*, DefaultLocaleId*) (ntoskrnl 19041
/// 0x612f00): sonda as duas saídas, toma o PsDefaultSystemLocaleId
/// (ZwQueryDefaultLocale(FALSE)) e mapeia uma vista nova da seção global do
/// locale.nls. O terceiro e o quarto registradores não são argumentos: a
/// ntdll deixa neles o que o chamador tinha, e o 19041 não os lê nem grava
/// (nem toca `Nls\Sorting`, que é dado da instalação na SYSTEM).
fn nt_initialize_nls_files(base: u64, locale: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_write(base, 8) || !probe_user_write(locale, 4) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let default_locale = crate::ntos::ps::locale::default_system_locale();
    let (view, _) = match map_locale_table()? {
        Ok(view) => view,
        Err(status) => return Ok(status),
    };
    // PVOID *BaseAddress e LCID *DefaultLocaleId, sondados acima.
    let written = guest::try_write::<u64>(base, view).and_then(|()| guest::try_write::<u32>(locale, default_locale));
    Ok(if written.is_err() { STATUS_ACCESS_VIOLATION } else { 0 })
}

/// "%.3d" do C: ao menos três dígitos, o sinal antes dos zeros.
fn c_precision3(value: i32) -> String {
    if value < 0 {
        format!("-{:03}", value.unsigned_abs())
    } else {
        format!("{value:03}")
    }
}

/// RtlpInitNlsSectionName (ntoskrnl 19041 0x69d240): só os tipos 11 (página
/// de código) e 12 (forma de normalização).
fn section_name(section_type: u32, data: u32) -> Result<String, u32> {
    match section_type {
        11 => Ok(format!("\\NLS\\NlsSectionCP{}", data as i32)),
        12 => Ok(format!("\\NLS\\NlsSectionNORM{data:08x}")),
        _ => Err(STATUS_INVALID_PARAMETER_1),
    }
}

/// RtlpInitNlsFileName (0x69d2a8): a página de código pelo número
/// (`c_%.3d.nls`); a forma de normalização pelo REG_SZ de
/// `Control\Nls\Normalization` com o nome da forma em hexadecimal
/// (RtlIntegerToUnicodeString base 16), lido num
/// KEY_VALUE_PARTIAL_INFORMATION de 0x120 bytes.
fn file_name(section_type: u32, data: u32) -> Result<String, u32> {
    let path = match section_type {
        11 => format!("\\SystemRoot\\System32\\c_{}.nls", c_precision3(data as i32)),
        12 => {
            let value = registry::read_value_by_path(NORMALIZATION_KEY, &format!("{data:X}")).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            // 12 bytes de cabeçalho (TitleIndex, Type, DataLength) no buffer
            // de 0x120: o que não cabe é STATUS_BUFFER_OVERFLOW.
            if value.data.len() > 0x120 - 12 {
                return Err(STATUS_BUFFER_OVERFLOW);
            }
            if value.value_type != 1 {
                return Err(STATUS_UNSUCCESSFUL);
            }
            let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).take_while(|&unit| unit != 0).collect();
            format!("\\SystemRoot\\System32\\{}", String::from_utf16_lossy(&units))
        }
        _ => return Err(STATUS_INVALID_PARAMETER_1),
    };
    if path.encode_utf16().count() >= NAME_CAPACITY {
        Err(STATUS_BUFFER_OVERFLOW)
    } else {
        Ok(path)
    }
}

/// A seção nomeada em `\NLS`: aberta (ZwOpenSection; qualquer falha segue
/// para o arquivo) ou criada permanente do arquivo da tabela (ZwOpenFile +
/// ZwCreateSection com OBJ_PERMANENT | OBJ_OPENIF: quem perde a corrida
/// abre a do outro).
fn nls_section(section_type: u32, data: u32) -> Result<Result<Arc<Section>, u32>, KernelError> {
    let name = match section_name(section_type, data) {
        Ok(name) => name,
        Err(status) => return Ok(Err(status)),
    };
    if let Ok(section) = sections::open(&name) {
        return Ok(Ok(section));
    }
    let path = match file_name(section_type, data) {
        Ok(path) => path,
        Err(status) => return Ok(Err(status)),
    };
    let backing = match crate::ntos::mm::section::file::system_section_file(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND)),
        Err(status) => return Ok(Err(status)),
    };
    let size = backing.size();
    Ok(match sections::create(CreateOptions { size, file: Some(backing), page_protect: PAGE_READONLY, attributes: SEC_COMMIT, name: Some(name.clone()), permanent: true, ..CreateOptions::default() })? {
        Ok(section) => {
            crate::debug_print!("[nls] {} criada de {}", name, path);
            Ok(section)
        }
        Err(STATUS_OBJECT_NAME_COLLISION) => sections::open(&name),
        Err(status) => Err(status),
    })
}

/// NtGetNlsSectionPtr(SectionType, SectionData, ContextData,
/// SectionPointer*, SectionSize*) (ntoskrnl 19041 0x69cec0).
fn nt_get_nls_section_ptr(section_type: u64, data: u64, context: u64, out: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let size = state::stack_arg(rsp, 5);
    // As duas saídas NULL são recusadas antes do modo anterior.
    if out == 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    if size == 0 {
        return Ok(STATUS_INVALID_PARAMETER_5);
    }
    // PVOID *SectionPointer e SIZE_T *SectionSize: oito bytes cada (o
    // GetCPHashNode do KernelBase passa uma posição de pilha de 8 bytes).
    if !probe_user_write(out, 8) || !probe_user_write(size, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // ContextData: ProbeForRead de 4 bytes alinhado a 4, sem uso depois.
    if context != 0 {
        if context & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if context.checked_add(4).is_none_or(|end| end > USER_ADDRESS_LIMIT) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let section = match nls_section(section_type as u32, data as u32)? {
        Ok(section) => section,
        Err(status) => return Ok(status),
    };
    // MmMapViewOfSection(ViewShare, PAGE_READONLY): uma vista nova por
    // chamada.
    let view = match sections::map(&section, &MapRequest { protect: PAGE_READONLY, ..MapRequest::default() })? {
        Ok(view) => view,
        Err(status) => return Ok(status),
    };
    let written = guest::try_write::<u64>(out, view.base).and_then(|()| guest::try_write::<u64>(size, view.size));
    Ok(if written.is_err() { STATUS_ACCESS_VIOLATION } else { 0 })
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
