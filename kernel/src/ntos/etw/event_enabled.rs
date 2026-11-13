//! EtwEventEnabled — `system32/ntos/etw/event-enabled.js`.
//!
//! Consulta os campos nativos medidos no kernel 19041; o registro e a
//! publicação desses campos pertencem ao dono ETW (`provider_state`).

use crate::ntos::mm::guest_memory as guest;

/// A palavra-chave zero tem regra própria: MatchAll não a restringe quando
/// o controlador publicou a inclusão de keyword zero.
fn keywords_match(information: u64, keyword: u64) -> bool {
    if guest::read32(information + 8) & 0x40 != 0 && keyword == 0 {
        return true;
    }
    if guest::read64(information + 16) & keyword == 0 {
        return false;
    }
    let required = guest::read64(information + 24);
    keyword & required == required
}

/// TRACE_ENABLE_INFO publicado: habilitado, nível máximo e keywords.
pub fn matches(information: u64, level: u8, keyword: u64) -> bool {
    if guest::read32(information) == 0 {
        return false;
    }
    let maximum = guest::read8(information + 4);
    if maximum != 0 && level > maximum {
        return false;
    }
    keywords_match(information, keyword)
}

/// EtwEventEnabled(RegHandle, EventDescriptor). A rotina original lê a
/// Keyword antes de consultar IsEnabled.
pub fn query(registration: u64, descriptor: u64) -> u8 {
    if registration == 0 {
        return 0;
    }
    let primary = guest::read64(registration + 0x20);
    let keyword = guest::read64(descriptor + 8);
    if guest::read32(primary + 0x60) != 0 {
        let maximum = guest::read8(primary + 0x64);
        let level = guest::read8(descriptor + 4);
        if (maximum == 0 || level <= maximum) && keywords_match(primary + 0x60, keyword) {
            return 1;
        }
    }
    if guest::read8(registration + 0x65) == 0 {
        return 0;
    }
    let group = guest::read64(registration + 0x28);
    let level = guest::read8(descriptor + 4);
    matches(group + 0x60, level, keyword) as u8
}
