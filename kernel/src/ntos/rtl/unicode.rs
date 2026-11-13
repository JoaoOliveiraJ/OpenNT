//! WCHARs e UNICODE_STRING do convidado.
//!
//! Length/MaximumLength são contagens de bytes de 16 bits; Buffer fica em +8.
//! Comparações contadas aceitam zeros internos e usam o trie NLS para a
//! equivalência de maiúsculas, sem expansão de caracteres.
//!
//! Também a inicialização, as trocas de caixa com destino, o prefixo, a
//! concatenação, a duplicação e o hash X65599 das UNICODE_STRING.

use alloc::vec::Vec;

use super::unicode_case::upcase_char;
use crate::ntos::mm::kernel_pool;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Diferença assinada de caracteres ou de comprimentos. `ignore_case` usa o
/// byte baixo da flag BOOLEAN.
pub fn compare(left: u64, left_count: u64, right: u64, right_count: u64, ignore_case: u32) -> Result<i32, KernelError> {
    for index in 0..left_count.min(right_count) {
        let mut a = guest::try_read16(left.wrapping_add(index * 2))?;
        let mut b = guest::try_read16(right.wrapping_add(index * 2))?;
        if a == b {
            continue;
        }
        if ignore_case & 255 != 0 {
            a = upcase_char(a)?;
            b = upcase_char(b)?;
        }
        if a != b {
            return Ok(a as i32 - b as i32);
        }
    }
    Ok(left_count.wrapping_sub(right_count) as i32)
}

/// RtlCompareUnicodeString: um Length ímpar é truncado a WCHARs inteiros.
pub fn compare_string(left: u64, right: u64, ignore_case: u32) -> Result<i32, KernelError> {
    compare(
        guest::try_read64(left + 8)?,
        (guest::try_read16(left)? >> 1) as u64,
        guest::try_read64(right + 8)?,
        (guest::try_read16(right)? >> 1) as u64,
        ignore_case,
    )
}

/// RtlEqualUnicodeString: mesmo comprimento em bytes; inclui o último WCHAR
/// completo quando Length é ímpar.
pub fn equal_string(left: u64, right: u64, ignore_case: u32) -> Result<u32, KernelError> {
    let length = guest::try_read16(left)?;
    if length != guest::try_read16(right)? {
        return Ok(0);
    }
    let count = (length as u64 + 1) >> 1;
    let difference = compare(guest::try_read64(left + 8)?, count, guest::try_read64(right + 8)?, count, ignore_case)?;
    Ok((difference == 0) as u32)
}

/// RtlFindUnicodeSubstring: posições alinhadas a WCHAR; o caminho sensível
/// compara bytes, o insensível compara WCHARs.
pub fn find(source: u64, search: u64, ignore_case: u32) -> Result<u64, KernelError> {
    let length = guest::try_read16(source)? as u64;
    let search_length = guest::try_read16(search)? as u64;
    if length < search_length {
        return Ok(0);
    }
    let source_buffer = guest::try_read64(source + 8)?;
    let search_buffer = guest::try_read64(search + 8)?;
    let mut start = 0u64;
    while start <= length - search_length {
        let mut offset = 0u64;
        if ignore_case & 255 != 0 {
            while offset < search_length {
                let a = guest::try_read16(source_buffer + start + offset)?;
                let b = guest::try_read16(search_buffer + offset)?;
                if a != b && upcase_char(a)? != upcase_char(b)? {
                    break;
                }
                offset += 2;
            }
        } else {
            while offset < search_length {
                if guest::try_read8(source_buffer + start + offset)? != guest::try_read8(search_buffer + offset)? {
                    break;
                }
                offset += 1;
            }
        }
        // No caminho insensível, um comprimento ímpar nunca termina exatamente.
        if offset == search_length {
            return Ok(source_buffer + start);
        }
        start += 2;
    }
    Ok(0)
}

/// RtlCreateUnicodeString: limita a alocação a 0xFFFE bytes e publica
/// Buffer antes de conferir a falha (ordem original).
pub fn create(destination: u64, source: u64) -> Result<u32, KernelError> {
    let mut count = 0u64;
    while guest::try_read16(source + count * 2)? != 0 {
        count += 1;
    }
    let bytes = count * 2 + 2;
    if bytes > 0xFFFE {
        return Ok(0);
    }
    let buffer = guest::alloc_bytes(bytes);
    guest::try_write64(destination + 8, buffer)?;
    if buffer == 0 {
        return Ok(0);
    }
    guest::try_write16(destination + 2, bytes as u16)?;
    for offset in (0..bytes).step_by(2) {
        guest::try_write16(buffer + offset, guest::try_read16(source + offset)?)?;
    }
    guest::try_write16(destination, (bytes - 2) as u16)?;
    Ok(1)
}

/// RtlFreeUnicodeString: cada buffer volta ao alocador que o possui (pool
/// paginável da conversão ANSI ou arena).
pub fn free(string: u64) -> Result<u32, KernelError> {
    let buffer = guest::try_read64(string + 8)?;
    if buffer != 0 {
        if kernel_pool::owns(buffer) {
            kernel_pool::free(buffer, None)?;
        } else {
            guest::free_bytes(buffer);
        }
        guest::try_write64(string, 0)?;
        guest::try_write64(string + 8, 0)?;
    }
    Ok(0)
}

/// RtlGUIDFromString: Data1..3 são gravados assim que convertidos; Data4 só
/// depois de validar o formato completo.
pub fn guid_from_string(string: u64, output: u64) -> Result<u32, KernelError> {
    const INVALID_PARAMETER: u32 = 0xC000_000D;
    let count = (guest::try_read16(string)? >> 1) as u64;
    let buffer = guest::try_read64(string + 8)?;
    let index = core::cell::Cell::new(0u64);
    let mut next = || -> Result<i32, KernelError> {
        if index.get() < count {
            let unit = guest::try_read16(buffer + index.get() * 2)?;
            index.set(index.get() + 1);
            Ok(unit as i32)
        } else {
            Ok(-1)
        }
    };
    let hexadecimal = |digits: u32, next: &mut dyn FnMut() -> Result<i32, KernelError>| -> Result<i64, KernelError> {
        let mut value = 0i64;
        for _ in 0..digits {
            let digit = match next()? {
                code @ 48..=57 => code - 48,
                code @ 65..=70 => code - 55,
                code @ 97..=102 => code - 87,
                _ => return Ok(-1),
            };
            value = value * 16 + digit as i64;
        }
        Ok(value)
    };
    if next()? != 123 {
        return Ok(INVALID_PARAMETER);
    }
    for field in 0..3 {
        let value = hexadecimal(if field == 0 { 8 } else { 4 }, &mut next)?;
        if value < 0 {
            return Ok(INVALID_PARAMETER);
        }
        match field {
            0 => guest::try_write32(output, value as u32)?,
            1 => guest::try_write16(output + 4, value as u16)?,
            _ => guest::try_write16(output + 6, value as u16)?,
        }
        if next()? != 45 {
            return Ok(INVALID_PARAMETER);
        }
    }
    let mut tail = [0u8; 8];
    for (position, byte) in tail.iter_mut().enumerate() {
        let value = hexadecimal(2, &mut next)?;
        if value < 0 {
            return Ok(INVALID_PARAMETER);
        }
        *byte = value as u8;
        if position == 1 && next()? != 45 {
            return Ok(INVALID_PARAMETER);
        }
    }
    if next()? != 125 {
        return Ok(INVALID_PARAMETER);
    }
    if index.get() < count && next()? != 0 {
        return Ok(INVALID_PARAMETER);
    }
    guest::try_write_bytes(output + 8, &tail)?;
    Ok(0)
}

// ---- inicialização, caixa, prefixo, concatenação, duplicação e hash ---------

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// RtlInitUnicodeString: só aponta o buffer; origem NULL = campos zerados.
pub fn init(output: u64, source: u64) {
    if source == 0 {
        guest_strings::write_string_fields(output, 0, 0, 0);
        return;
    }
    let count = guest_strings::read_wide_units(source).len() as u16;
    guest_strings::write_string_fields(output, count * 2, count * 2 + 2, source);
}

/// Escreve o texto numa UNICODE_STRING de destino (alocando se pedido ou
/// sem buffer; respeitando MaximumLength). Devolve o NTSTATUS.
fn write_converted_string(destination: u64, text: &str, allocate: bool) -> u32 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let needed = units.len() as u64 * 2 + 2;
    let mut buffer = guest::read64(destination + 8);
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(needed);
        guest::write64(destination + 8, buffer);
        guest::write16(destination + 2, needed as u16);
    } else if (guest::read16(destination + 2) as u64) < needed {
        return STATUS_BUFFER_OVERFLOW;
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
    guest::write16(destination, units.len() as u16 * 2);
    0
}

/// RtlUpcaseUnicodeString.
pub fn upcase_string(destination: u64, source: u64, allocate: bool) -> u32 {
    let text = guest_strings::read_unicode_string(source).to_uppercase();
    write_converted_string(destination, &text, allocate)
}

/// RtlDowncaseUnicodeString.
pub fn downcase_string(destination: u64, source: u64, allocate: bool) -> u32 {
    let text = guest_strings::read_unicode_string(source).to_lowercase();
    write_converted_string(destination, &text, allocate)
}

/// RtlPrefixUnicodeString.
pub fn prefix(prefix: u64, string: u64, case_insensitive: bool) -> bool {
    let mut prefix = guest_strings::read_unicode_string(prefix);
    let mut text = guest_strings::read_unicode_string(string);
    if case_insensitive {
        prefix = prefix.to_lowercase();
        text = text.to_lowercase();
    }
    text.starts_with(&prefix)
}

/// Grava o texto desde o início do buffer do destino, terminado em NUL
/// (respeita MaximumLength). Devolve o NTSTATUS.
pub fn append_text(destination: u64, text: &str) -> u32 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let maximum = guest::read16(destination + 2) as u64 / 2;
    if units.len() as u64 + 1 > maximum {
        return STATUS_BUFFER_OVERFLOW;
    }
    let buffer = guest::read64(destination + 8);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
    guest::write16(destination, units.len() as u16 * 2);
    0
}

/// RtlAppendUnicodeStringToString: concatena no buffer do destino.
pub fn append_string(destination: u64, source: u64) -> u32 {
    let current = guest_strings::read_unicode_string(destination);
    let suffix = guest_strings::read_unicode_string(source);
    append_text(destination, &alloc::format!("{current}{suffix}"))
}

/// RtlDuplicateUnicodeString(flags, source, destination): SEMPRE aloca um
/// buffer novo e copia a origem. `flags` não escolhe alocar — os bits são
/// NULL_TERMINATE (1) e ALLOCATE_NULL_STRING (2); ambos juntos ou outros bits
/// são inválidos. (Antes o OpenNT tratava flags!=0 como "alocar" e, com
/// flags=0, checava a capacidade do destino e devolvia BUFFER_TOO_SMALL.)
pub fn duplicate(flags: u32, source: u64, destination: u64) -> u32 {
    const NULL_TERMINATE: u32 = 1;
    const ALLOCATE_NULL_STRING: u32 = 2;
    if destination == 0 || flags & !3 != 0 || flags & 3 == 3 {
        return STATUS_INVALID_PARAMETER;
    }
    let length = guest::read16(source) as u64;
    let source_buffer = guest::read64(source + 8);
    // Origem vazia sem ALLOCATE_NULL_STRING: destino vazio e sem buffer.
    if length == 0 && flags & ALLOCATE_NULL_STRING == 0 {
        guest::write16(destination, 0);
        guest::write16(destination + 2, 0);
        guest::write64(destination + 8, 0);
        return 0;
    }
    let terminator = if flags & NULL_TERMINATE != 0 { 2 } else { 0 };
    let buffer = guest::alloc_bytes((length + terminator).max(2));
    guest::write_bytes(buffer, &guest::read_bytes(source_buffer, length as usize));
    if terminator != 0 {
        guest::write16(buffer + length, 0);
    }
    guest::write16(destination, length as u16);
    guest::write16(destination + 2, (length + terminator) as u16);
    guest::write64(destination + 8, buffer);
    0
}

/// RtlHashUnicodeString(PCUNICODE_STRING, CaseInsensitive, Alg, PULONG Hash):
/// hash X65599 (Alg 0=default/1). Alg>1 = STATUS_INVALID_PARAMETER.
pub fn hash(string: u64, case_insensitive: bool, algorithm: u32, hash_out: u64) -> u32 {
    if algorithm > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let length_units = guest::read16(string) as u64 / 2;
    let buffer = guest::read64(string + 8);
    let upcase = |unit: u16| upcase_char(unit).unwrap_or(if (0x61..=0x7A).contains(&unit) { unit - 0x20 } else { unit });
    let mut hash = 0u32;
    for index in 0..length_units {
        let mut unit = guest::read16(buffer + index * 2);
        if case_insensitive {
            unit = upcase(unit);
        }
        hash = hash.wrapping_mul(65599).wrapping_add(unit as u32);
    }
    guest::write32(hash_out, hash);
    0
}
