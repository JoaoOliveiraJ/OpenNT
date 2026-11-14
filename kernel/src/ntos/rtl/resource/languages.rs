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

// ---- RtlGetThreadLangIdByIndex ---------------------------------------------
//
// ntoskrnl 19041 (0x328840). Os idiomas de interface preferidos da thread
// ficam na TEB (TEB.PreferredLanguages, memória de usuário do processo):
// USHORT na posição +4 é a contagem e o ponteiro em +0x18 é o vetor de
// entradas de 6 bytes (ULONG cuja palavra baixa vale 1 numa entrada válida,
// seguido do LANGID). Thread de sistema ou anexada a outro processo
// (ApcStateIndex = 1) não tem TEB a consultar. Cada ponteiro de usuário é
// sondado: desalinhado dá STATUS_DATATYPE_MISALIGNMENT e fora da metade de
// usuário STATUS_ACCESS_VIOLATION, o código da exceção que o __except do
// original devolve.

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INTERNAL_ERROR: u32 = 0xC000_00E5;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// MmUserProbeAddress.
const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// Tamanho sondado do bloco de idiomas da TEB e de uma entrada.
const LANGUAGE_BLOCK_SIZE: u64 = 0x40;
const LANGUAGE_ENTRY_SIZE: u64 = 6;

/// ProbeForRead de [address, address + length) na metade de usuário.
fn probe(address: u64, length: u64) -> Result<(), u32> {
    let end = address.wrapping_add(length);
    if end > USER_PROBE_ADDRESS || end < address { Err(STATUS_ACCESS_VIOLATION) } else { Ok(()) }
}

/// (LANGID, contagem, status) lidos da TEB.
fn preferred_language(teb: u64, index: u32) -> Result<(u16, u32, u32), u32> {
    use crate::ntos::inc::types::{NtStruct, Teb};
    use crate::ntos::mm::guest_memory as guest;
    let read16 = |address: u64| guest::try_read16(address).map_err(|_| STATUS_ACCESS_VIOLATION);
    let read32 = |address: u64| guest::try_read32(address).map_err(|_| STATUS_ACCESS_VIOLATION);
    let read64 = |address: u64| guest::try_read64(address).map_err(|_| STATUS_ACCESS_VIOLATION);
    // SAFETY: só o endereço do campo; a leitura é sondada.
    let field = unsafe { Teb::at(teb) }.preferred_languages.address();
    let languages = read64(field)?;
    if languages == 0 {
        return Ok((0, 0, 0));
    }
    if languages & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    probe(languages, LANGUAGE_BLOCK_SIZE)?;
    let entries = read64(languages + 0x18)?;
    if entries == 0 {
        return Ok((0, 0, 0));
    }
    let count = read16(languages + 4)? as u32;
    if index >= count {
        return Ok((0, count, 0));
    }
    if entries & 1 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    let entry = entries + index as u64 * LANGUAGE_ENTRY_SIZE;
    probe(entry, LANGUAGE_ENTRY_SIZE)?;
    if read32(entry)? as u16 != 1 {
        return Ok((0, count, STATUS_INTERNAL_ERROR));
    }
    Ok((read16(entry + 4)?, count, 0))
}

/// RtlGetThreadLangIdByIndex(Flags, Index, LangId, NumberOfLanguages):
/// Flags não nulo ou LangId NULL = STATUS_INVALID_PARAMETER; LangId (ULONG)
/// e NumberOfLanguages recebem o que a TEB tem; LANGID zero sem outro erro =
/// STATUS_NOT_FOUND.
pub fn thread_lang_id_by_index(flags: u32, index: u32, lang_output: u64, count_output: u64) -> u32 {
    use crate::ntos::inc::field::Field;
    use crate::ntos::inc::types::{Kthread, NtStruct};
    if flags != 0 || lang_output == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: a KTHREAD corrente.
    let thread = unsafe { Kthread::at(crate::ntos::ps::process::get_current_thread()) };
    let teb = if thread.system_thread() != 0 || thread.apc_state_index.get() == 1 { 0 } else { thread.teb.get() };
    let (language, count, status) = if teb == 0 {
        (0, 0, 0)
    } else {
        match preferred_language(teb, index) {
            Ok(found) => found,
            Err(status) => return status,
        }
    };
    // SAFETY: PULONG LangId e PULONG NumberOfLanguages do chamador de kernel.
    unsafe { Field::<u32>::at(lang_output) }.set(language as u32);
    if count_output != 0 {
        unsafe { Field::<u32>::at(count_output) }.set(count);
    }
    if status == 0 && language == 0 { STATUS_NOT_FOUND } else { status }
}
