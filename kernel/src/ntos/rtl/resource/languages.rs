//! Identidade de idiomas do resolvedor de recursos.
//!
//! A configuração corrente da máquina vem do proprietário NLS, sem estado
//! global duplicado nem escolha de idioma pelo processo do host.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::rtl::resource::language_data::LANGUAGES;
use crate::ntos::rtl::resource::tree::{Key, Plan};
use crate::rtl::KernelError;

fn by_identifier(identifier: u32) -> Option<&'static (u32, &'static str, u32)> {
    LANGUAGES.iter().find(|row| row.0 == identifier)
}

/// LANGID de uma chave numérica ou de um nome (sem distinção de caixa).
pub fn resolve(language: &Key) -> Result<u32, u32> {
    let identifier = match language {
        Key::Name(units) => {
            if units.is_empty() {
                return Ok(0);
            }
            // DownLevelLanguageNameToLangID devolve neutro para nome desconhecido:
            // a regra do kernel difere da ntdll. O último nome repetido vence.
            let name: String = char::decode_utf16(units.iter().copied()).map(|character| character.unwrap_or('\u{FFFD}')).collect::<String>().to_lowercase();
            return Ok(LANGUAGES.iter().rev().find(|row| row.1.to_lowercase() == name).map_or(0, |row| row.0));
        }
        Key::Id(identifier) => *identifier,
        Key::Pointer(pointer) => *pointer as u32,
    };
    if identifier == 0 {
        return Ok(0);
    }
    if identifier & 0x3FF == 0 || identifier == 0x7F || by_identifier(identifier).is_none() {
        return Err(0xC000_000D);
    }
    Ok(identifier)
}

/// Plano de idiomas: o pedido, a cadeia de pais ou, sem idioma, os da
/// máquina seguidos de 0x409 e 0x1234.
pub fn fallback(identifier: u32, flags: u32, system_languages: &[u32]) -> Result<Plan, KernelError> {
    let mut candidates: Vec<u32> = alloc::vec![identifier];
    let select_first = flags & 0x20 != 0;
    if flags & 4 != 0 {
        return Ok(Plan { candidates, allow_any: false, select_first });
    }
    if identifier != 0 {
        let mut current = identifier;
        while current != 0 {
            current = by_identifier(current).map_or(0, |row| row.2);
            if candidates.contains(&current) {
                return Err(KernelError::new("cyclic resource language parent"));
            }
            candidates.push(current);
        }
        return Ok(Plan { candidates, allow_any: false, select_first });
    }
    for &language in system_languages.iter().chain([0x409u32, 0x1234].iter()) {
        if language != 0 && language != 0xEEEE && !candidates.contains(&language) {
            candidates.push(language);
        }
    }
    Ok(Plan { candidates, allow_any: true, select_first })
}

/// Nome do idioma (vazio para o neutro); `None` = LANGID desconhecido.
pub fn name_for_identifier(identifier: u32) -> Option<&'static str> {
    if identifier == 0 {
        return Some("");
    }
    by_identifier(identifier).map(|row| row.1)
}
