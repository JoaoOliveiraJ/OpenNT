//! Localidade e idioma de interface padrão do sistema e do usuário: o
//! PsDefaultSystemLocaleId, o PsDefaultThreadLocaleId e o
//! PsDefaultUILanguageId do NT, que os serviços NtQueryDefaultLocale,
//! NtSetDefaultLocale, NtQueryDefaultUILanguage e NtSetDefaultUILanguage
//! leem e trocam; aqui, as formas Zw (modo kernel, sem sonda).
//!
//! Os valores começam com a configuração da instalação
//! (`rtl/nls_configuration`). NtSetDefaultLocale com UserProfile troca o
//! LCID do usuário e, sem, o do sistema; LCID 0 é recusado com
//! STATUS_INVALID_PARAMETER. NtSetDefaultUILanguage troca o idioma de
//! interface; 0 é recusado. Em modo kernel não há checagem de privilégio.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::rtl::nls_configuration::{DEFAULT_LOCALE, DEFAULT_UI_LANGUAGE};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

static SYSTEM_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static USER_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static UI_LANGUAGE: AtomicU32 = AtomicU32::new(DEFAULT_UI_LANGUAGE);

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
