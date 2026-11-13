//! EtwEventEnabled.
//!
//! Consulta os campos nativos medidos no kernel 19041; o registro e a
//! publicação desses campos pertencem ao dono ETW (`provider_state`).

use crate::ntos::inc::types::{EtwGuidEntry, EtwRegEntry, EventDescriptor, NtStruct, TraceEnableInfo};

/// EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_0.
const ENABLE_KEYWORD_0: u32 = 0x40;

/// A palavra-chave zero tem regra própria: MatchAll não a restringe quando
/// o controlador publicou a inclusão de keyword zero.
fn keywords_match(information: &TraceEnableInfo, keyword: u64) -> bool {
    if information.enable_property.get() & ENABLE_KEYWORD_0 != 0 && keyword == 0 {
        return true;
    }
    if information.match_any_keyword.get() & keyword == 0 {
        return false;
    }
    let required = information.match_all_keyword.get();
    keyword & required == required
}

fn information_matches(information: &TraceEnableInfo, level: u8, keyword: u64) -> bool {
    if information.is_enabled.get() == 0 {
        return false;
    }
    let maximum = information.level.get();
    if maximum != 0 && level > maximum {
        return false;
    }
    keywords_match(information, keyword)
}

/// TRACE_ENABLE_INFO publicado: habilitado, nível máximo e keywords.
pub fn matches(information: u64, level: u8, keyword: u64) -> bool {
    // SAFETY: um TRACE_ENABLE_INFO de uma ETW_GUID_ENTRY viva.
    information_matches(unsafe { TraceEnableInfo::at(information) }, level, keyword)
}

/// EtwEventEnabled(RegHandle, EventDescriptor). A rotina original lê a
/// Keyword antes de consultar IsEnabled.
pub fn query(registration: u64, descriptor: u64) -> u8 {
    if registration == 0 {
        return 0;
    }
    // SAFETY: REGHANDLE (ETW_REG_ENTRY) e PCEVENT_DESCRIPTOR do driver.
    let (registration, descriptor) = unsafe { (EtwRegEntry::at(registration), EventDescriptor::at(descriptor)) };
    // SAFETY: a ETW_GUID_ENTRY do registro.
    let primary = unsafe { EtwGuidEntry::at(registration.guid_entry.get()) };
    let keyword = descriptor.keyword.get();
    let provider = &primary.provider_enable_info;
    if provider.is_enabled.get() != 0 {
        let maximum = provider.level.get();
        let level = descriptor.level.get();
        if (maximum == 0 || level <= maximum) && keywords_match(provider, keyword) {
            return 1;
        }
    }
    if registration.group_enable_mask.get() == 0 {
        return 0;
    }
    // SAFETY: a entrada do grupo publicada no registro.
    let group = unsafe { EtwGuidEntry::at(registration.group_entry.get()) };
    information_matches(&group.provider_enable_info, descriptor.level.get(), keyword) as u8
}
