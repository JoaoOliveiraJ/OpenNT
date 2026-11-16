//! Localidade e idioma de interface padrão do sistema e do usuário: o
//! PsDefaultSystemLocaleId, o PsDefaultThreadLocaleId e o
//! PsDefaultUILanguageId do NT, que os serviços NtQueryDefaultLocale,
//! NtSetDefaultLocale, NtQueryDefaultUILanguage e NtSetDefaultUILanguage
//! leem e trocam; aqui, as formas Zw (modo kernel, sem sonda).
//!
//! Os valores começam com o padrão de `rtl/nls_configuration` e, carregada a
//! SYSTEM, passam aos da instalação (`Control\Nls\Language`, o
//! PsInstallUILanguageId e o PsDefaultSystemLocaleId do
//! CmGetSystemControlValues). NtSetDefaultLocale com UserProfile troca o
//! LCID do usuário e, sem, o do sistema; LCID 0 é recusado com
//! STATUS_INVALID_PARAMETER. NtSetDefaultUILanguage troca o idioma de
//! interface; 0 é recusado. Em modo kernel não há checagem de privilégio.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::rtl::nls_configuration::{DEFAULT_LOCALE, DEFAULT_UI_LANGUAGE, INSTALL_UI_LANGUAGE};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

static SYSTEM_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static USER_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static UI_LANGUAGE: AtomicU32 = AtomicU32::new(DEFAULT_UI_LANGUAGE);
/// PsInstallUILanguageId.
static INSTALL_LANGUAGE: AtomicU32 = AtomicU32::new(INSTALL_UI_LANGUAGE);

/// A chave de idioma da instalação na SYSTEM.
const LANGUAGE_KEY: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language";

/// Um identificador de idioma como o Registro o guarda: REG_SZ com o número
/// em hexadecimal ("0416"). Zero ou texto inválido não conta.
pub fn parse_language_id(text: &str) -> Option<u32> {
    let value = u32::from_str_radix(text.trim_end_matches('\0').trim(), 16).ok()?;
    (value != 0 && value <= 0xFFFF).then_some(value)
}

fn registry_language(name: &str) -> Option<u32> {
    let value = crate::ntos::cm::registry::read_value_by_path(LANGUAGE_KEY, name)?;
    if value.value_type != 1 && value.value_type != 2 {
        return None;
    }
    let units: alloc::vec::Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    parse_language_id(&alloc::string::String::from_utf16_lossy(&units))
}

/// CmGetSystemControlValues do `Control\Nls\Language` da SYSTEM, logo
/// depois da carga dela: o `Default` dá o PsDefaultSystemLocaleId (e o
/// LCID padrão das threads), o `InstallLanguage` o PsInstallUILanguageId,
/// que também é o idioma de interface padrão (PsDefaultUILanguageId).
/// Valor ausente ou inválido deixa o padrão (`rtl/nls_configuration`).
pub fn initialize_from_registry() {
    if let Some(locale) = registry_language("Default") {
        SYSTEM_LOCALE.store(locale, Ordering::Release);
        USER_LOCALE.store(locale, Ordering::Release);
    }
    if let Some(language) = registry_language("InstallLanguage") {
        INSTALL_LANGUAGE.store(language, Ordering::Release);
        UI_LANGUAGE.store(language, Ordering::Release);
    }
    crate::debug_print!("[nls] localidade {:#x}, idioma de interface {:#x} (instalacao {:#x})", default_system_locale(), default_ui_language(), install_ui_language());
}

/// PsInstallUILanguageId (o NtQueryInstallUILanguage).
pub fn install_ui_language() -> u32 {
    INSTALL_LANGUAGE.load(Ordering::Acquire)
}

/// PsDefaultUILanguageId (o NtQueryDefaultUILanguage).
pub fn default_ui_language() -> u32 {
    UI_LANGUAGE.load(Ordering::Acquire)
}

/// O LCID padrão do usuário (`true`) ou do sistema.
pub fn default_locale(user_profile: bool) -> u32 {
    locale_cell(user_profile).load(Ordering::Acquire)
}

/// PsUILanguageComitted: começa desligado (o valor da imagem do ntoskrnl)
/// e só o NtFlushInstallUILanguage com SetComittedFlag o liga.
static UI_LANGUAGE_COMMITTED: AtomicBool = AtomicBool::new(false);

/// NtIsUILanguageComitted (ntoskrnl 19041, rva 0x771f10): sem sonda nem
/// privilégio, STATUS_SUCCESS com o idioma de interface da instalação já
/// confirmado e STATUS_OBJECT_NAME_NOT_FOUND antes disso.
pub fn is_ui_language_committed() -> u32 {
    if UI_LANGUAGE_COMMITTED.load(Ordering::Acquire) { 0 } else { 0xC000_0034 }
}

fn locale_cell(user_profile: bool) -> &'static AtomicU32 {
    if user_profile { &USER_LOCALE } else { &SYSTEM_LOCALE }
}

/// PsDefaultSystemLocaleId (o LocaleId de uma sessão nova).
pub fn default_system_locale() -> u32 {
    SYSTEM_LOCALE.load(Ordering::Acquire)
}

/// ZwQueryDefaultLocale(UserProfile, DefaultLocaleId*).
pub fn query_default_locale(user_profile: bool, out: u64) -> u32 {
    // SAFETY: o PLCID de saída do chamador de kernel.
    unsafe { Field::<u32>::at(out) }.set(locale_cell(user_profile).load(Ordering::Acquire));
    0
}

/// ZwSetDefaultLocale(UserProfile, DefaultLocaleId).
pub fn set_default_locale(user_profile: bool, locale: u32) -> u32 {
    if locale == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    locale_cell(user_profile).store(locale, Ordering::Release);
    0
}

/// ZwQueryDefaultUILanguage(DefaultUILanguageId*).
pub fn query_default_ui_language(out: u64) -> u32 {
    // SAFETY: o LANGID* de saída do chamador de kernel.
    unsafe { Field::<u16>::at(out) }.set(UI_LANGUAGE.load(Ordering::Acquire) as u16);
    0
}

/// ZwSetDefaultUILanguage(DefaultUILanguageId).
pub fn set_default_ui_language(language: u16) -> u32 {
    if language == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    UI_LANGUAGE.store(language as u32, Ordering::Release);
    0
}
