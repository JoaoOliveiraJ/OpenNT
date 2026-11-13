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
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

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

/// Unidades de uma UNICODE_STRING (Buffer é PVOID de 64 bits).
pub fn try_read_unicode_units(pointer: u64) -> Result<Vec<u16>, KernelError> {
    let count = guest::try_read16(pointer)? as u64 / 2;
    let buffer = guest::try_read64(pointer + 8)?;
    if count > MAX_GUEST_STRING_CHARS {
        runaway(&format!("UNICODE_STRING len={count}"), pointer);
    }
    (0..count).map(|index| guest::try_read16(buffer.wrapping_add(index * 2))).collect()
}

pub fn try_read_unicode_string(pointer: u64) -> Result<String, KernelError> {
    try_read_unicode_units(pointer).map(|units| units_to_string(&units))
}

pub fn read_unicode_string(pointer: u64) -> String {
    try_read_unicode_string(pointer).unwrap_or_else(|error| panic!("{error}"))
}

pub fn try_read_ansi_string(pointer: u64) -> Result<String, KernelError> {
    let length = guest::try_read16(pointer)? as u64;
    let buffer = guest::try_read64(pointer + 8)?;
    if length > MAX_GUEST_STRING_CHARS {
        runaway(&format!("ANSI_STRING len={length}"), pointer);
    }
    (0..length).map(|index| guest::try_read8(buffer.wrapping_add(index)).map(|byte| byte as char)).collect()
}

pub fn read_ansi_string(pointer: u64) -> String {
    try_read_ansi_string(pointer).unwrap_or_else(|error| panic!("{error}"))
}

/// Campos de uma (UNICODE|ANSI)_STRING: { u16 len, u16 max, u32 pad, u64 buf }.
pub fn write_string_fields(pointer: u64, length_bytes: u16, maximum_bytes: u16, buffer: u64) {
    guest::write16(pointer, length_bytes);
    guest::write16(pointer + 2, maximum_bytes);
    guest::write32(pointer + 4, 0);
    guest::write64(pointer + 8, buffer);
}

pub fn write_wide_string(address: u64, text: &str) {
    let mut count = 0u64;
    for unit in text.encode_utf16() {
        guest::write16(address + count * 2, unit);
        count += 1;
    }
    guest::write16(address + count * 2, 0);
}

pub fn write_bytes(address: u64, bytes: &[u8]) {
    for (index, &byte) in bytes.iter().enumerate() {
        guest::write8(address + index as u64, byte);
    }
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
    let mut pointer = pointer;
    if counted {
        limit = limit.min(guest::read16(pointer) as u64 / if wide { 2 } else { 1 });
        pointer = guest::read64(pointer + 8);
        if pointer == 0 {
            return String::from("(null)");
        }
    }
    let mut units = Vec::new();
    let mut index = 0u64;
    while index < limit {
        let unit = if wide { guest::read16(pointer + index * 2) } else { guest::read8(pointer + index) as u16 };
        if !counted && unit == 0 {
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
            match bits {
                8 => guest::try_write8(value, output_units as u8)?,
                16 => guest::try_write16(value, output_units as u16)?,
                _ => {
                    guest::try_write32(value, output_units as u32)?;
                    if bits == 64 {
                        guest::try_write32(value + 4, (output_units >> 32) as u32)?;
                    }
                }
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
    let write = |index: u64, unit: u16| {
        if wide {
            guest::write16(pointer + index * 2, unit);
        } else {
            guest::write8(pointer + index, unit as u8);
        }
    };
    for index in 0..writable {
        write(index, units[index as usize]);
    }
    if writable < count {
        write(writable, 0);
    }
    if legacy && length > count { -1 } else { length as i64 }
}
