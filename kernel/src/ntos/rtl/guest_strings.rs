//! Strings do convidado.
//!
//! Layout real do NT (WDK): UNICODE_STRING = { u16 Length @0, u16
//! MaximumLength @2, u32 pad @4, u64 Buffer @8 }; ANSI_STRING é igual com
//! bytes de 8 bits. Texto largo vira `String` pelas unidades UTF-16 (pares
//! substitutos são combinados; unidades soltas viram U+FFFD); texto ANSI é
//! Latin-1, um caractere por byte.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::cpu;
use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// Guarda contra leitura descontrolada de um ponteiro errado.
pub const MAX_GUEST_STRING_CHARS: u64 = 65536;

fn runaway(kind: &str, start: u64) -> ! {
    debug_print!("[strings] {} SEM NUL em {:#x} (>64K chars)", kind, start);
    cpu::halt_forever()
}

fn units_to_string(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied()).map(|unit| unit.unwrap_or('\u{FFFD}')).collect()
}

pub fn read_c_string(address: u64) -> String {
    let mut text = String::new();
    let mut at = address;
    loop {
        let byte = guest::read8(at);
        if byte == 0 {
            return text;
        }
        if text.len() as u64 >= MAX_GUEST_STRING_CHARS {
            runaway("C-string", address);
        }
        text.push(byte as char);
        at = at.wrapping_add(1);
    }
}

pub fn read_wide_units(address: u64) -> Vec<u16> {
    let mut units = Vec::new();
    let mut at = address;
    loop {
        let unit = guest::read16(at);
        if unit == 0 {
            return units;
        }
        if units.len() as u64 >= MAX_GUEST_STRING_CHARS {
            runaway("wide-string", address);
        }
        units.push(unit);
        at = at.wrapping_add(2);
    }
}

pub fn read_wide_string(address: u64) -> String {
    units_to_string(&read_wide_units(address))
}

/// Unidades UTF-16 little-endian de um bloco de bytes.
fn units_from_bytes(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

/// Unidades de uma UNICODE_STRING (ponteiro não confiável: descritor e
/// texto sondados).
pub fn try_read_unicode_units(pointer: u64) -> Result<Vec<u16>, KernelError> {
    let string = UnicodeString::try_at(pointer)?;
    let count = string.length.probe_get()? as u64 / 2;
    let buffer = string.buffer.probe_get()?;
    if count > MAX_GUEST_STRING_CHARS {
        runaway(&format!("UNICODE_STRING len={count}"), pointer);
    }
    Ok(units_from_bytes(&guest::try_read_bytes(buffer, count as usize * 2)?))
}

pub fn try_read_unicode_string(pointer: u64) -> Result<String, KernelError> {
    try_read_unicode_units(pointer).map(|units| units_to_string(&units))
}

pub fn read_unicode_string(pointer: u64) -> String {
    try_read_unicode_string(pointer).unwrap_or_else(|error| panic!("{error}"))
}

pub fn try_read_ansi_string(pointer: u64) -> Result<String, KernelError> {
    let string = AnsiString::try_at(pointer)?;
    let length = string.length.probe_get()? as u64;
    let buffer = string.buffer.probe_get()?;
    if length > MAX_GUEST_STRING_CHARS {
        runaway(&format!("ANSI_STRING len={length}"), pointer);
    }
    Ok(guest::try_read_bytes(buffer, length as usize)?.into_iter().map(|byte| byte as char).collect())
}

pub fn read_ansi_string(pointer: u64) -> String {
    try_read_ansi_string(pointer).unwrap_or_else(|error| panic!("{error}"))
}

/// Campos de uma (UNICODE|ANSI)_STRING — as duas têm o mesmo layout
/// (Length, MaximumLength, Buffer); o preenchimento entre eles não é tocado,
/// como no RtlInitUnicodeString.
pub fn write_string_fields(pointer: u64, length_bytes: u16, maximum_bytes: u16, buffer: u64) {
    // SAFETY: descritor do chamador (kernel ou driver), vivo e alinhado.
    let string = unsafe { UnicodeString::at(pointer) };
    string.length.set(length_bytes);
    string.maximum_length.set(maximum_bytes);
    string.buffer.set(buffer);
}

/// Bytes little-endian das unidades UTF-16 de `text` seguidas do NUL.
pub fn wide_bytes_with_nul(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

pub fn write_wide_string(address: u64, text: &str) {
    guest::write_bytes(address, &wide_bytes_with_nul(text));
}

pub fn write_bytes(address: u64, bytes: &[u8]) {
    guest::write_bytes(address, bytes);
}

/// va_list MS x64: slots de 8 bytes lidos sob demanda.
pub fn guest_format_arguments(va_list: u64) -> impl FnMut(usize) -> u64 {
    move |index| guest::read64(va_list + index as u64 * 8)
}

fn read_format_string(pointer: u64, wide: bool, precision: Option<u64>, counted: bool) -> String {
    if pointer == 0 {
        return String::from("(null)");
    }
    let mut limit = precision.unwrap_or(u64::MAX);
    if counted {
        // %Z/%wZ: STRING ou UNICODE_STRING (mesmo layout); o texto contado
        // vem num bloco.
        // SAFETY: argumento de printf do chamador, descritor vivo e alinhado.
        let string = unsafe { UnicodeString::at(pointer) };
        limit = limit.min(string.length.get() as u64 / if wide { 2 } else { 1 });
        let buffer = string.buffer.get();
        if buffer == 0 {
            return String::from("(null)");
        }
        let bytes = guest::read_bytes(buffer, (limit * if wide { 2 } else { 1 }) as usize);
        return if wide { units_to_string(&units_from_bytes(&bytes)) } else { bytes.iter().map(|&byte| byte as char).collect() };
    }
    let mut units = Vec::new();
    let mut index = 0u64;
    while index < limit {
        let unit = if wide { guest::read16(pointer + index * 2) } else { guest::read8(pointer + index) as u16 };
        if unit == 0 {
            break;
        }
        if index >= MAX_GUEST_STRING_CHARS {
            runaway("printf string", pointer);
        }
        units.push(unit);
        index += 1;
    }
    if wide { units_to_string(&units) } else { units.iter().map(|&unit| unit as u8 as char).collect() }
}

fn to_radix(mut number: u128, radix: u32) -> String {
    if number == 0 {
        return String::from("0");
    }
    let mut digits = Vec::new();
    while number > 0 {
        digits.push(core::char::from_digit((number % radix as u128) as u32, radix).unwrap());
        number /= radix as u128;
    }
    digits.iter().rev().collect()
}

fn pad_start(text: &str, width: usize, fill: char) -> String {
    let length = text.chars().count();
    if length >= width {
        return String::from(text);
    }
    let mut padded: String = core::iter::repeat_n(fill, width - length).collect();
    padded.push_str(text);
    padded
}

/// Formatador do CRT do kernel: inteiros, ponteiros e strings, com flags,
/// largura/precisão dinâmicas e tamanhos LLP64. %Z segue o CRT legado do NT
/// (ANSI_STRING); %wZ/%lZ são UNICODE_STRING; %S é string, não estrutura.
pub fn format_guest_text(format_text: &str, arguments: &mut dyn FnMut(usize) -> u64, wide: bool) -> Result<String, KernelError> {
    let characters: Vec<char> = format_text.chars().collect();
    let mut out = String::new();
    let mut output_units = 0u64; // comprimento em unidades UTF-16
    let mut argument_index = 0usize;
    let mut next = |arguments: &mut dyn FnMut(usize) -> u64| {
        let value = arguments(argument_index);
        argument_index += 1;
        value
    };
    let push = |out: &mut String, units: &mut u64, text: &str| {
        out.push_str(text);
        *units += text.encode_utf16().count() as u64;
    };
    let mut i = 0usize;
    while i < characters.len() {
        if characters[i] != '%' {
            let mut buffer = [0u8; 4];
            push(&mut out, &mut output_units, characters[i].encode_utf8(&mut buffer));
            i += 1;
            continue;
        }
        i += 1;
        if characters.get(i) == Some(&'%') {
            push(&mut out, &mut output_units, "%");
            i += 1;
            continue;
        }
        let mut flags = String::new();
        while i < characters.len() && "-+ #0".contains(characters[i]) {
            flags.push(characters[i]);
            i += 1;
        }
        let mut width: i64 = 0;
        let mut precision: Option<i64> = None;
        if characters.get(i) == Some(&'*') {
            width = next(arguments) as i32 as i64;
            i += 1;
        } else {
            while i < characters.len() && characters[i].is_ascii_digit() {
                width = width * 10 + characters[i].to_digit(10).unwrap() as i64;
                i += 1;
            }
        }
        if width < 0 {
            width = -width;
            flags.push('-');
        }
        if characters.get(i) == Some(&'.') {
            i += 1;
            let mut value = 0i64;
            if characters.get(i) == Some(&'*') {
                value = next(arguments) as i32 as i64;
                i += 1;
            } else {
                while i < characters.len() && characters[i].is_ascii_digit() {
                    value = value * 10 + characters[i].to_digit(10).unwrap() as i64;
                    i += 1;
                }
            }
            precision = (value >= 0).then_some(value);
        }
        let mut length = "";
        let rest: String = characters[i..].iter().collect();
        for candidate in ["I64", "I32", "hh", "ll", "h", "l", "j", "z", "t", "I", "w", "L"] {
            if rest.starts_with(candidate) {
                length = candidate;
                i += candidate.len();
                break;
            }
        }
        let spec = characters.get(i).copied();
        let Some(spec) = spec.filter(|spec| "diouxXpcsSCZn".contains(*spec)) else {
            return Err(KernelError::new(format!(
                "Unsupported kernel printf conversion: %{}{}",
                length,
                spec.map(String::from).unwrap_or_default()
            )));
        };
        i += 1;
        let value = next(arguments);
        let bits = match length {
            "ll" | "I64" | "j" | "z" | "t" | "I" => 64,
            "hh" => 8,
            "h" => 16,
            _ => 32,
        };
        let mask = |bits: u32| if bits == 64 { u64::MAX } else { (1u64 << bits) - 1 };
        let mut body;
        let mut prefix = String::new();
        let mut zero_pad = false;
        if "diouxXp".contains(spec) {
            let signed = spec == 'd' || spec == 'i';
            let mut negative = false;
            let number: u128 = if signed {
                let shift = 64 - bits;
                let value = ((value << shift) as i64) >> shift;
                negative = value < 0;
                value.unsigned_abs() as u128
            } else {
                (value & mask(if spec == 'p' { 64 } else { bits })) as u128
            };
            if signed {
                if negative {
                    prefix.push('-');
                } else if flags.contains('+') {
                    prefix.push('+');
                } else if flags.contains(' ') {
                    prefix.push(' ');
                }
            }
            let radix = if spec == 'o' { 8 } else if "xXp".contains(spec) { 16 } else { 10 };
            body = if number == 0 && precision == Some(0) && spec != 'p' { String::new() } else { to_radix(number, radix) };
            if spec == 'X' || spec == 'p' {
                body = body.to_uppercase();
            }
            if spec == 'p' {
                body = pad_start(&body, 16, '0');
            }
            if let Some(precision) = precision {
                body = pad_start(&body, precision as usize, '0');
            }
            if flags.contains('#') {
                if spec == 'o' && !body.starts_with('0') {
                    body.insert(0, '0');
                }
                if (spec == 'x' || spec == 'X') && number != 0 {
                    prefix = String::from(if spec == 'x' { "0x" } else { "0X" });
                }
            }
            zero_pad = precision.is_none() && flags.contains('0');
        } else if spec == 'n' {
            // Ponteiro do argumento: uma escrita sondada da largura do inteiro
            // (`long long` num único store de 64 bits).
            match bits {
                8 => guest::try_write::<u8>(value, output_units as u8)?,
                16 => guest::try_write::<u16>(value, output_units as u16)?,
                64 => guest::try_write::<u64>(value, output_units)?,
                _ => guest::try_write::<u32>(value, output_units as u32)?,
            }
            continue;
        } else {
            let is_wide = match length {
                "l" | "w" => true,
                "h" => false,
                _ if spec == 'Z' => false,
                _ if spec == 'S' || spec == 'C' => !wide,
                _ => wide,
            };
            body = if spec == 'c' || spec == 'C' {
                let unit = (value & if is_wide { 0xFFFF } else { 0xFF }) as u32;
                String::from(char::from_u32(unit).unwrap_or('\u{FFFD}'))
            } else {
                read_format_string(value, is_wide, precision.map(|value| value as u64), spec == 'Z')
            };
        }
        let used = prefix.chars().count() + body.chars().count();
        let padding = (width as usize).saturating_sub(used);
        let spaces: String = core::iter::repeat_n(' ', padding).collect();
        let text = if flags.contains('-') {
            format!("{prefix}{body}{spaces}")
        } else if zero_pad {
            let zeros: String = core::iter::repeat_n('0', padding).collect();
            format!("{prefix}{zeros}{body}")
        } else {
            format!("{spaces}{prefix}{body}")
        };
        push(&mut out, &mut output_units, &text);
    }
    Ok(out)
}

/// _vsn[w]printf legado: `count` inclui todos os caracteres e só escreve NUL
/// se sobra espaço (-1 no truncamento). snprintf C99 reserva o NUL e devolve
/// o comprimento necessário. Nenhuma escrita com `count` zero.
pub fn write_formatted_text(pointer: u64, count: u64, text: &str, wide: bool, legacy: bool) -> i64 {
    let units: Vec<u16> = if wide { text.encode_utf16().collect() } else { text.chars().map(|character| character as u32 as u16).collect() };
    let length = units.len() as u64;
    let writable = length.min(if legacy { count } else { count.saturating_sub(1) });
    let terminator = (writable < count).then_some(0u16);
    let output = units[..writable as usize].iter().copied().chain(terminator);
    let bytes: Vec<u8> = if wide { output.flat_map(u16::to_le_bytes).collect() } else { output.map(|unit| unit as u8).collect() };
    guest::write_bytes(pointer, &bytes);
    if legacy && length > count { -1 } else { length as i64 }
}
