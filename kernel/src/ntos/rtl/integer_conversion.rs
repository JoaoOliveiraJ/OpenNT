//! Inteiros em texto e de volta — RtlUnicodeStringToInteger,
//! RtlIntegerToUnicodeString e RtlInt64ToUnicodeString.
//!
//! As formatações aceitam as bases 2, 8, 10 e 16 (0 = 10) e gravam na
//! UNICODE_STRING de destino já alocada; cada rotina devolve o NTSTATUS.

use alloc::string::String;
use alloc::vec::Vec;

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
    // parseInt: o prefixo válido mais longo; nenhum dígito = inválido.
    let digits: String = text.chars().take_while(|character| character.is_digit(base.clamp(2, 36))).collect();
    if digits.is_empty() || !(2..=36).contains(&base) {
        return STATUS_INVALID_PARAMETER;
    }
    let parsed = u64::from_str_radix(&digits, base).unwrap_or(u64::MAX);
    let value = if negative { (parsed as i64).wrapping_neg() as u64 } else { parsed } as u32;
    guest::write32(value_out, value);
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
    let units: Vec<u16> = text.encode_utf16().collect();
    if (units.len() + 1) * 2 > guest::read16(destination + 2) as usize {
        return STATUS_BUFFER_OVERFLOW;
    }
    let buffer = guest::read64(destination + 8);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
    guest::write16(destination, (units.len() * 2) as u16);
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
