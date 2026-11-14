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

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::rtl::nls_configuration::{DEFAULT_LOCALE, DEFAULT_UI_LANGUAGE};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

static SYSTEM_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static USER_LOCALE: AtomicU32 = AtomicU32::new(DEFAULT_LOCALE);
static UI_LANGUAGE: AtomicU32 = AtomicU32::new(DEFAULT_UI_LANGUAGE);

fn locale_cell(user_profile: bool) -> &'static AtomicU32 {
    if user_profile { &USER_LOCALE } else { &SYSTEM_LOCALE }
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
