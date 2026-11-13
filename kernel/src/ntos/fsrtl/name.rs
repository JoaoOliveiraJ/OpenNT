//! Nomes do FsRtl — correspondência com curingas DOS, detecção de curingas,
//! desmontagem de caminhos e o bitmap FsRtlLegalAnsiCharacterArray.
//!
//! `IsNameInExpression`/`DoesNameContainWildCards`/`DissectName` reproduzem
//! o `ntoskrnl` real (desmontagem por RVA). As UNICODE_STRING são endereços
//! do convidado.

use alloc::vec::Vec;

use crate::ntos::inc::types::{NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;
use crate::ntos::mm::kernel_data_layout::FSRTL_LEGAL_ANSI_CHARACTER_ARRAY;
use crate::ntos::rtl::unicode_case;

// Classe FSRTL_WILD_CHARACTER no bitmap de 256 bytes.
const FSRTL_WILD_CHARACTER: u8 = 0x08;

// Os cinco curingas do FsRtl (valores UTF-16 = ASCII).
const WC_STAR: u16 = b'*' as u16; // 0x2A
const WC_QM: u16 = b'?' as u16; // 0x3F
const WC_DOS_STAR: u16 = b'<' as u16; // 0x3C
const WC_DOS_QM: u16 = b'>' as u16; // 0x3E
const WC_DOS_DOT: u16 = b'"' as u16; // 0x22
const WC_DOT: u16 = b'.' as u16; // 0x2E
const WC_BACKSLASH: u16 = 0x5C;

// ---- FsRtlLegalAnsiCharacterArray (data export) -----------------------------

/// Endereço da célula `.kdata` com o bitmap de classes (mesmos bytes que o
/// `ntoskrnl` real referencia em VA 0x140011b20). O armazenamento de 256
/// bytes e os valores iniciais ficam em `mm::kernel_data_layout`
/// (ver REGISTRATION) — aqui só devolvemos o endereço público, como a HAL
/// faz com `HalPrivateDispatchTable`.
pub fn legal_ansi_character_array_address() -> u64 {
    kernel_data::address("FsRtlLegalAnsiCharacterArray")
        .unwrap_or_else(|error| panic!("FsRtlLegalAnsiCharacterArray: {error}"))
}

// ---- Name helpers (§2.1) ----------------------------------------------------

/// FsRtlDoesNameContainWildCards(Name) -> BOOLEAN (RVA 0x24f730).
/// Varre do último caractere para trás; para em `\` (FALSE); para um
/// caractere < 0x40 testa o bit FSRTL_WILD_CHARACTER no bitmap; caracteres
/// >= 0x40 nunca são curingas e são ignorados.
pub fn does_name_contain_wild_cards(name: u64) -> bool {
    let units = read_unicode_string(name);
    let mut index = units.len();
    while index > 0 {
        index -= 1;
        let unit = units[index];
        if unit == WC_BACKSLASH {
            return false;
        }
        if unit < 0x40 && FSRTL_LEGAL_ANSI_CHARACTER_ARRAY[unit as usize] & FSRTL_WILD_CHARACTER != 0 {
            return true;
        }
    }
    false
}

/// FsRtlDissectName(Path, FirstName, RemainingName) (RVA 0x2ede60).
/// Zera as duas UNICODE_STRING de saída; divide `a\b\c` em first=`a`,
/// remaining=`b\c`; pula um `\` inicial. `Path` é passado por ponteiro
/// (struct de 16 bytes na ABI x64).
pub fn dissect_name(path: u64, first: u64, remaining: u64) {
    // SAFETY: as três UNICODE_STRING do chamador.
    let (path_string, first, remaining) = unsafe { (UnicodeString::at(path), UnicodeString::at(first), UnicodeString::at(remaining)) };
    // Saídas zeradas (Length, MaximumLength, Buffer).
    set_string(first, 0, 0);
    set_string(remaining, 0, 0);

    let units = read_unicode_string(path);
    let count = units.len() as u64;
    if count == 0 {
        return;
    }
    let buffer = path_string.buffer.get();
    let leading = if units[0] == WC_BACKSLASH { 1 } else { 0 };

    // Índice do separador `\` (ou `count` se não houver), a partir de `leading`.
    let mut separator = leading;
    while separator < count && units[separator as usize] != WC_BACKSLASH {
        separator += 1;
    }

    set_string(first, ((separator - leading) * 2) as u16, buffer + leading * 2);

    if separator < count {
        set_string(remaining, ((count - separator - 1) * 2) as u16, buffer + (separator + 1) * 2);
    }
}

/// UNICODE_STRING de saída apontando para dentro do buffer de entrada.
fn set_string(string: &UnicodeString, length: u16, buffer: u64) {
    string.length.set(length);
    string.maximum_length.set(length);
    string.buffer.set(buffer);
}

/// FsRtlIsNameInExpression(Expression, Name, IgnoreCase, UpcaseTable)
/// -> BOOLEAN (RVA 0x24f160 -> RtlpIsNameInExpressionPrivate 0x24f290).
/// Matcher de curingas DOS auto-contido (`* ? < > "`), com upcase opcional.
pub fn is_name_in_expression(expression: u64, name: u64, ignore_case: bool) -> bool {
    let expression = read_unicode_string(expression);
    let name = read_unicode_string(name);
    match_expression(&expression, 0, &name, 0, ignore_case)
}

fn read_unicode_string(pointer: u64) -> Vec<u16> {
    // SAFETY: UNICODE_STRING do chamador.
    let string = unsafe { UnicodeString::at(pointer) };
    let count = string.length.get() as usize / 2;
    if count == 0 {
        return Vec::new();
    }
    guest::read_bytes(string.buffer.get(), count * 2).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn upcase(unit: u16) -> u16 {
    unicode_case::upcase_char(unit).unwrap_or(unit)
}

fn unit_eq(a: u16, b: u16, ignore_case: bool) -> bool {
    a == b || (ignore_case && upcase(a) == upcase(b))
}

/// Correspondência recursiva com retrocesso. `expr`/`name` são listas de
/// code units; o retrocesso vive apenas nas ramificações `*` / DOS_STAR.
fn match_expression(expr: &[u16], mut ei: usize, name: &[u16], mut ni: usize, ic: bool) -> bool {
    loop {
        if ei == expr.len() {
            return ni == name.len();
        }
        match expr[ei] {
            WC_STAR => {
                // Zero ou mais de qualquer caractere.
                if ei + 1 == expr.len() {
                    return true; // `*` final casa com o resto.
                }
                for split in ni..=name.len() {
                    if match_expression(expr, ei + 1, name, split, ic) {
                        return true;
                    }
                }
                return false;
            }
            WC_DOS_STAR => {
                // Zero ou mais caracteres até o último `.` do nome restante.
                let mut last_dot = name.len();
                for position in ni..name.len() {
                    if name[position] == WC_DOT {
                        last_dot = position;
                    }
                }
                for split in ni..=last_dot {
                    if match_expression(expr, ei + 1, name, split, ic) {
                        return true;
                    }
                }
                return false;
            }
            WC_QM => {
                // Exatamente um caractere.
                if ni < name.len() {
                    ei += 1;
                    ni += 1;
                    continue;
                }
                return false;
            }
            WC_DOS_QM => {
                // Um caractere qualquer; em `.` ou fim do nome, casa com zero.
                if ni < name.len() && name[ni] != WC_DOT {
                    ni += 1;
                }
                ei += 1;
                continue;
            }
            WC_DOS_DOT => {
                // Um `.` ou zero caracteres (ponto opcional).
                if ni < name.len() && name[ni] == WC_DOT {
                    ni += 1;
                }
                ei += 1;
                continue;
            }
            literal => {
                if ni < name.len() && unit_eq(literal, name[ni], ic) {
                    ei += 1;
                    ni += 1;
                    continue;
                }
                return false;
            }
        }
    }
}
