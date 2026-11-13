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
use crate::ntos::inc::types::{Field, Guid, NtStruct, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

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
    let (left, right) = (UnicodeString::try_at(left)?, UnicodeString::try_at(right)?);
    compare(
        left.buffer.probe_get()?,
        (left.length.probe_get()? >> 1) as u64,
        right.buffer.probe_get()?,
        (right.length.probe_get()? >> 1) as u64,
        ignore_case,
    )
}

/// RtlEqualUnicodeString: mesmo comprimento em bytes; inclui o último WCHAR
/// completo quando Length é ímpar.
pub fn equal_string(left: u64, right: u64, ignore_case: u32) -> Result<u32, KernelError> {
    let (left, right) = (UnicodeString::try_at(left)?, UnicodeString::try_at(right)?);
    let length = left.length.probe_get()?;
    if length != right.length.probe_get()? {
        return Ok(0);
    }
    let count = (length as u64 + 1) >> 1;
    let difference = compare(left.buffer.probe_get()?, count, right.buffer.probe_get()?, count, ignore_case)?;
    Ok((difference == 0) as u32)
}

/// RtlFindUnicodeSubstring: posições alinhadas a WCHAR; o caminho sensível
/// compara bytes, o insensível compara WCHARs.
pub fn find(source: u64, search: u64, ignore_case: u32) -> Result<u64, KernelError> {
    let (source, search) = (UnicodeString::try_at(source)?, UnicodeString::try_at(search)?);
    let length = source.length.probe_get()? as u64;
    let search_length = search.length.probe_get()? as u64;
    if length < search_length {
        return Ok(0);
    }
    let source_buffer = source.buffer.probe_get()?;
    let search_buffer = search.buffer.probe_get()?;
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
    let string = UnicodeString::try_at(destination)?;
    let buffer = guest::alloc_bytes(bytes);
    string.buffer.probe_set(buffer)?;
    if buffer == 0 {
        return Ok(0);
    }
    string.maximum_length.probe_set(bytes as u16)?;
    guest::try_write_bytes(buffer, &guest::try_read_bytes(source, bytes as usize)?)?;
    string.length.probe_set((bytes - 2) as u16)?;
    Ok(1)
}

/// RtlFreeUnicodeString: cada buffer volta ao alocador que o possui (pool
/// paginável da conversão ANSI ou arena).
pub fn free(string: u64) -> Result<u32, KernelError> {
    let string = UnicodeString::try_at(string)?;
    let buffer = string.buffer.probe_get()?;
    if buffer != 0 {
        if kernel_pool::owns(buffer) {
            kernel_pool::free(buffer, None)?;
        } else {
            guest::free_bytes(buffer);
        }
        string.length.probe_set(0)?;
        string.maximum_length.probe_set(0)?;
        string.buffer.probe_set(0)?;
    }
    Ok(0)
}

/// RtlGUIDFromString: Data1..3 são gravados assim que convertidos; Data4 só
/// depois de validar o formato completo.
pub fn guid_from_string(string: u64, output: u64) -> Result<u32, KernelError> {
    const INVALID_PARAMETER: u32 = 0xC000_000D;
    let string = UnicodeString::try_at(string)?;
    let count = (string.length.probe_get()? >> 1) as u64;
    let buffer = string.buffer.probe_get()?;
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
    let guid = Guid::try_at(output)?;
    for field in 0..3 {
        let value = hexadecimal(if field == 0 { 8 } else { 4 }, &mut next)?;
        if value < 0 {
            return Ok(INVALID_PARAMETER);
        }
        match field {
            0 => guid.data1.probe_set(value as u32)?,
            1 => guid.data2.probe_set(value as u16)?,
            _ => guid.data3.probe_set(value as u16)?,
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
    guest::try_write_bytes(guid.data4[0].address(), &tail)?;
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
fn write_converted_string(destination: &UnicodeString, text: &str, allocate: bool) -> u32 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let needed = units.len() as u64 * 2 + 2;
    let mut buffer = destination.buffer.get();
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(needed);
        destination.buffer.set(buffer);
        destination.maximum_length.set(needed as u16);
    } else if (destination.maximum_length.get() as u64) < needed {
        return STATUS_BUFFER_OVERFLOW;
    }
    guest::write_bytes(buffer, &guest_strings::wide_bytes_with_nul(text));
    destination.length.set(units.len() as u16 * 2);
    0
}

/// RtlUpcaseUnicodeString.
pub fn upcase_string(destination: u64, source: u64, allocate: bool) -> u32 {
    let text = guest_strings::read_unicode_string(source).to_uppercase();
    // SAFETY: PUNICODE_STRING do chamador.
    write_converted_string(unsafe { UnicodeString::at(destination) }, &text, allocate)
}

/// RtlDowncaseUnicodeString.
pub fn downcase_string(destination: u64, source: u64, allocate: bool) -> u32 {
    let text = guest_strings::read_unicode_string(source).to_lowercase();
    // SAFETY: PUNICODE_STRING do chamador.
    write_converted_string(unsafe { UnicodeString::at(destination) }, &text, allocate)
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
    // SAFETY: PUNICODE_STRING do chamador.
    let destination = unsafe { UnicodeString::at(destination) };
    let count = text.encode_utf16().count() as u64;
    let maximum = destination.maximum_length.get() as u64 / 2;
    if count + 1 > maximum {
        return STATUS_BUFFER_OVERFLOW;
    }
    guest::write_bytes(destination.buffer.get(), &guest_strings::wide_bytes_with_nul(text));
    destination.length.set(count as u16 * 2);
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
    // SAFETY: PCUNICODE_STRING e PUNICODE_STRING do chamador.
    let (source, destination) = unsafe { (UnicodeString::at(source), UnicodeString::at(destination)) };
    let length = source.length.get() as u64;
    let source_buffer = source.buffer.get();
    // Origem vazia sem ALLOCATE_NULL_STRING: destino vazio e sem buffer.
    if length == 0 && flags & ALLOCATE_NULL_STRING == 0 {
        destination.length.set(0);
        destination.maximum_length.set(0);
        destination.buffer.set(0);
        return 0;
    }
    let terminator = if flags & NULL_TERMINATE != 0 { 2 } else { 0 };
    let buffer = guest::alloc_bytes((length + terminator).max(2));
    let mut bytes = guest::read_bytes(source_buffer, length as usize);
    bytes.resize((length + terminator) as usize, 0);
    guest::write_bytes(buffer, &bytes);
    destination.length.set(length as u16);
    destination.maximum_length.set((length + terminator) as u16);
    destination.buffer.set(buffer);
    0
}

/// RtlHashUnicodeString(PCUNICODE_STRING, CaseInsensitive, Alg, PULONG Hash):
/// hash X65599 (Alg 0=default/1). Alg>1 = STATUS_INVALID_PARAMETER.
pub fn hash(string: u64, case_insensitive: bool, algorithm: u32, hash_out: u64) -> u32 {
    if algorithm > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: PCUNICODE_STRING do chamador.
    let string = unsafe { UnicodeString::at(string) };
    let length_units = string.length.get() as u64 / 2;
    let text = guest::read_bytes(string.buffer.get(), length_units as usize * 2);
    let upcase = |unit: u16| upcase_char(unit).unwrap_or(if (0x61..=0x7A).contains(&unit) { unit - 0x20 } else { unit });
    let mut hash = 0u32;
    for pair in text.chunks_exact(2) {
        let mut unit = u16::from_le_bytes([pair[0], pair[1]]);
        if case_insensitive {
            unit = upcase(unit);
        }
        hash = hash.wrapping_mul(65599).wrapping_add(unit as u32);
    }
    // SAFETY: PULONG HashValue do chamador.
    unsafe { Field::<u32>::at(hash_out) }.set(hash);
    0
}

// ---- RtlInitUnicodeStringEx (rtl-strings) ----------------------------------

/// RtlInitUnicodeStringEx(Dest, Source): zera Length/MaximumLength, publica
/// Buffer e mede o texto; mais de 0x7FFE WCHARs devolve
/// STATUS_NAME_TOO_LONG com os comprimentos zerados.
pub fn init_ex(destination: u64, source: u64) -> u32 {
    const STATUS_NAME_TOO_LONG: u32 = 0xC000_0106;
    // SAFETY: PUNICODE_STRING do chamador.
    let destination = unsafe { UnicodeString::at(destination) };
    destination.length.set(0);
    destination.maximum_length.set(0);
    destination.buffer.set(source);
    if source != 0 {
        let mut count = 0u64;
        while guest::read16(source + count * 2) != 0 {
            count += 1;
        }
        if count > 0x7FFE {
            return STATUS_NAME_TOO_LONG;
        }
        destination.length.set((count * 2) as u16);
        destination.maximum_length.set((count * 2 + 2) as u16);
    }
    0
}
