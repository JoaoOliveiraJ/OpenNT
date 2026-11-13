//! Inteiros em texto e de volta — RtlUnicodeStringToInteger,
//! RtlIntegerToUnicodeString e RtlInt64ToUnicodeString.
//!
//! As formatações aceitam as bases 2, 8, 10 e 16 (0 = 10) e gravam na
//! UNICODE_STRING de destino já alocada; cada rotina devolve o NTSTATUS.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::types::{Field, NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::{guest_strings, unicode};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// RtlUnicodeStringToInteger: base 0 = automática (0x, 0b, 0o, 0 octal).
pub fn unicode_string_to_integer(string: u64, base: u32, value_out: u64) -> u32 {
    let text = guest_strings::read_unicode_string(string);
    let mut text = text.trim();
    let mut base = base;
    let mut negative = false;
    if let Some(rest) = text.strip_prefix('-') {
        negative = true;
        text = rest;
    }
    let lower = text.to_ascii_lowercase();
    if base == 0 {
        if lower.starts_with("0x") {
            base = 16;
            text = &text[2..];
        } else if lower.starts_with("0b") {
            base = 2;
            text = &text[2..];
        } else if lower.starts_with("0o") {
            base = 8;
            text = &text[2..];
        } else if text.len() > 1 && text.starts_with('0') && text.as_bytes()[1].is_ascii_digit() && text.as_bytes()[1] < b'8' {
            base = 8;
            text = &text[1..];
        } else {
            base = 10;
        }
    }
    // O prefixo válido mais longo; nenhum dígito = inválido.
    let digits: String = text.chars().take_while(|character| character.is_digit(base.clamp(2, 36))).collect();
    if digits.is_empty() || !(2..=36).contains(&base) {
        return STATUS_INVALID_PARAMETER;
    }
    let parsed = u64::from_str_radix(&digits, base).unwrap_or(u64::MAX);
    let value = if negative { (parsed as i64).wrapping_neg() as u64 } else { parsed } as u32;
    // SAFETY: PULONG Value do chamador.
    unsafe { Field::<u32>::at(value_out) }.set(value);
    0
}

fn format_radix(mut value: u32, base: u32) -> String {
    if value == 0 {
        return String::from("0");
    }
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(core::char::from_digit(value % base, base).unwrap_or('0'));
        value /= base;
    }
    digits.iter().rev().collect()
}

/// RtlIntegerToUnicodeString (bases 2, 8, 10 e 16).
pub fn integer_to_unicode_string(value: u32, base: u32, string: u64) -> u32 {
    let base = match base {
        0 => 10,
        base => base,
    };
    if ![2, 8, 10, 16].contains(&base) {
        return STATUS_INVALID_PARAMETER;
    }
    let text = format_radix(value, base);
    unicode::append_text(string, &text)
}

fn format_radix64(mut value: u64, base: u32) -> String {
    if value == 0 {
        return String::from("0");
    }
    let mut digits = Vec::new();
    while value > 0 {
        digits.push(core::char::from_digit((value % base as u64) as u32, base).unwrap_or('0'));
        value /= base as u64;
    }
    digits.iter().rev().collect()
}

/// Grava um texto numa UNICODE_STRING de destino (buffer já alocado),
/// terminada em NUL; BUFFER_OVERFLOW se não couber.
fn store_counted_unicode(destination: u64, text: &str) -> u32 {
    // SAFETY: PUNICODE_STRING do chamador.
    let destination = unsafe { UnicodeString::at(destination) };
    let units: Vec<u16> = text.encode_utf16().collect();
    if (units.len() + 1) * 2 > destination.maximum_length.get() as usize {
        return STATUS_BUFFER_OVERFLOW;
    }
    guest::write_bytes(destination.buffer.get(), &guest_strings::wide_bytes_with_nul(text));
    destination.length.set((units.len() * 2) as u16);
    0
}

/// RtlInt64ToUnicodeString(ULONGLONG, Base, PUNICODE_STRING): formata um
/// inteiro de 64 bits (bases 2, 8, 10, 16).
pub fn int64_to_unicode_string(value: u64, base: u32, string: u64) -> u32 {
    let base = match base {
        0 => 10,
        base => base,
    };
    if ![2, 8, 10, 16].contains(&base) {
        return STATUS_INVALID_PARAMETER;
    }
    store_counted_unicode(string, &format_radix64(value, base))
}

// ---- RtlCharToInteger e RtlIntegerToUnicode (rtl-strings) ------------------

/// RtlCharToInteger(String, Base, Value): brancos (byte com sinal <= 0x20),
/// um sinal, prefixo 0x/0o/0b só com Base 0 (um 0 inicial sem prefixo fica
/// decimal); dígitos 0-9/A-F/a-f abaixo da base, acumulados em 32 bits (por
/// deslocamento em 2/8/16). Base fora de {0, 2, 8, 10, 16} =
/// STATUS_INVALID_PARAMETER sem escrever Value.
pub fn char_to_integer(string: u64, base: u32, value: u64) -> u32 {
    let mut cursor = string;
    let mut sign = guest::read8(cursor);
    let mut character;
    if sign as i8 <= 0x20 {
        loop {
            let previous = cursor;
            cursor += 1;
            let next = guest::read8(cursor);
            if next == 0 {
                // Só brancos: o último deles vira o caractere corrente.
                cursor = previous;
                character = sign;
                break;
            }
            sign = next;
            if next as i8 > 0x20 {
                cursor += 1;
                character = sign;
                break;
            }
        }
    } else {
        cursor += 1;
        character = sign;
    }
    if character == b'+' || character == b'-' {
        character = guest::read8(cursor);
        cursor += 1;
    }
    let after = cursor;
    let (shift, radix) = match base {
        0 => {
            let mut chosen = (0, 10);
            if character == b'0' {
                character = guest::read8(cursor);
                cursor += 1;
                chosen = match character {
                    b'x' => (4, 16),
                    b'o' => (3, 8),
                    b'b' => (1, 2),
                    _ => (0, 10),
                };
                if chosen.0 != 0 {
                    character = guest::read8(cursor);
                    cursor += 1;
                } else {
                    cursor = after + 1;
                }
            }
            chosen
        }
        16 => (4, 16),
        10 => (0, 10),
        2 => (1, 2),
        8 => (3, 8),
        _ => return STATUS_INVALID_PARAMETER,
    };
    let mut result = 0u32;
    while character != 0 {
        let digit = match character {
            b'0'..=b'9' => (character - b'0') as u32,
            b'A'..=b'F' => (character - 0x37) as u32,
            b'a'..=b'f' => (character - 0x57) as u32,
            _ => break,
        };
        if digit >= radix {
            break;
        }
        result = if shift != 0 { (result << shift) | digit } else { result.wrapping_mul(radix).wrapping_add(digit) };
        character = guest::read8(cursor);
        cursor += 1;
    }
    // SAFETY: PULONG Value do chamador.
    unsafe { Field::<u32>::at(value) }.set(if sign == b'-' { result.wrapping_neg() } else { result });
    0
}

/// Dígitos de RtlIntegerToUnicode (RtlpIntegerWChars, hex maiúsculo; base 0
/// vale 10).
fn integer_text(value: u32, base: u32) -> Option<String> {
    Some(match base {
        0 | 10 => alloc::format!("{value}"),
        16 => alloc::format!("{value:X}"),
        8 => alloc::format!("{value:o}"),
        2 => alloc::format!("{value:b}"),
        _ => return None,
    })
}

/// RtlIntegerToUnicode(Value, Base, OutputLength, String): OutputLength
/// negativo preenche com '0' à esquerda até |OutputLength| e não termina;
/// positivo termina com NUL quando sobra espaço; dígitos além do limite =
/// STATUS_BUFFER_OVERFLOW.
pub fn integer_to_unicode(value: u32, base: u32, length: i32, output: u64) -> u32 {
    let Some(text) = integer_text(value, base) else {
        return STATUS_INVALID_PARAMETER;
    };
    let count = text.len() as i32;
    let mut output = output;
    let mut limit = length;
    if length < 0 {
        limit = length.wrapping_neg();
        if count < limit {
            let zeros: Vec<u8> = core::iter::repeat_n(b'0' as u16, (limit - count) as usize).flat_map(u16::to_le_bytes).collect();
            guest::write_bytes(output, &zeros);
            output += (limit - count) as u64 * 2;
            limit = count;
        }
    }
    if count > limit {
        return STATUS_BUFFER_OVERFLOW;
    }
    let terminator = (count < limit).then_some(0u16);
    let digits: Vec<u8> = text.bytes().map(u16::from).chain(terminator).flat_map(u16::to_le_bytes).collect();
    guest::write_bytes(output, &digits);
    0
}
