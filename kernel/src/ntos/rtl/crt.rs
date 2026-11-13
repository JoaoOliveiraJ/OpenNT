//! Rotinas de texto e busca da CRT do kernel — `system32/ntos/rtl/crt.js`.
//! Classificação no locale C; ponteiros exatos.

use crate::hal::amd64::native_call;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub fn strlen(source: u64) -> Result<u64, KernelError> {
    let mut length = 0;
    while guest::try_read8(source.wrapping_add(length))? != 0 {
        length += 1;
    }
    Ok(length)
}

/// Diferença dos bytes sem sinal na primeira divergência, terminador ou limite.
pub fn strncmp(left: u64, right: u64, maximum: Option<u64>) -> Result<i32, KernelError> {
    let mut offset = 0u64;
    while maximum.is_none_or(|maximum| offset < maximum) {
        let a = guest::try_read8(left.wrapping_add(offset))?;
        let b = guest::try_read8(right.wrapping_add(offset))?;
        if a != b || a == 0 {
            return Ok(a as i32 - b as i32);
        }
        offset += 1;
    }
    Ok(0)
}

pub fn strcmp(left: u64, right: u64) -> Result<i32, KernelError> {
    strncmp(left, right, None)
}

/// Compara sem distinguir só A..Z ASCII.
pub fn stricmp(left: u64, right: u64) -> Result<i32, KernelError> {
    let mut offset = 0u64;
    loop {
        let a = guest::try_read8(left.wrapping_add(offset))?.to_ascii_lowercase();
        let b = guest::try_read8(right.wrapping_add(offset))?.to_ascii_lowercase();
        if a != b || a == 0 {
            return Ok(a as i32 - b as i32);
        }
        offset += 1;
    }
}

/// Máscara 4 da CRT para dígitos ASCII; EOF (-1) resulta em zero.
pub fn isdigit(character: u32) -> u32 {
    if character as i32 == -1 {
        return 0;
    }
    if (b'0'..=b'9').contains(&(character as u8)) { 4 } else { 0 }
}

/// Busca de WCHAR; procurar o próprio terminador devolve seu endereço.
pub fn wcschr(source: u64, character: u32) -> Result<u64, KernelError> {
    let character = character as u16;
    let mut pointer = source;
    loop {
        let unit = guest::try_read16(pointer)?;
        if unit == character {
            return Ok(pointer);
        }
        if unit == 0 {
            return Ok(0);
        }
        pointer = pointer.wrapping_add(2);
    }
}

/// Espaços, sinal e dígitos; a acumulação transborda em 32 bits.
pub fn atoi(source: u64) -> Result<i32, KernelError> {
    if source == 0 {
        return Ok(0);
    }
    let mut offset = 0u64;
    let mut byte = guest::try_read8(source)?;
    while byte == b' ' || (9..=13).contains(&byte) {
        offset += 1;
        byte = guest::try_read8(source + offset)?;
    }
    let mut negative = false;
    if byte == b'-' || byte == b'+' {
        negative = byte == b'-';
        offset += 1;
        byte = guest::try_read8(source + offset)?;
    }
    let mut value = 0u32;
    while byte.is_ascii_digit() {
        value = value.wrapping_mul(10).wrapping_add((byte - b'0') as u32);
        offset += 1;
        byte = guest::try_read8(source + offset)?;
    }
    Ok(if negative { (value as i32).wrapping_neg() } else { value as i32 })
}

/// _ultow_s: 22 = EINVAL, 34 = ERANGE; publica string vazia antes das
/// validações de base e espaço.
pub fn ultow(value: u32, output: u64, capacity: u64, radix: i32) -> Result<u32, KernelError> {
    if output == 0 || capacity == 0 {
        return Ok(22);
    }
    guest::try_write16(output, 0)?;
    if capacity <= 1 {
        return Ok(34);
    }
    if !(2..=36).contains(&radix) {
        return Ok(22);
    }
    let mut value = value;
    let mut written = 0u64;
    loop {
        let digit = value % radix as u32;
        guest::try_write16(output + written * 2, (digit + if digit <= 9 { 48 } else { 87 }) as u16)?;
        written += 1;
        value /= radix as u32;
        if value == 0 || written >= capacity {
            break;
        }
    }
    if written >= capacity {
        guest::try_write16(output, 0)?;
        return Ok(34);
    }
    guest::try_write16(output + written * 2, 0)?;
    let (mut left, mut right) = (0u64, written - 1);
    while left < right {
        let a = guest::try_read16(output + left * 2)?;
        let b = guest::try_read16(output + right * 2)?;
        guest::try_write16(output + left * 2, b)?;
        guest::try_write16(output + right * 2, a)?;
        left += 1;
        right -= 1;
    }
    Ok(0)
}

/// bsearch/bsearch_s com o comparador nativo (LONG com sinal). Para uma
/// quantidade par, escolhe o elemento central inferior.
pub fn binary_search(
    key: u64,
    base: u64,
    count: u64,
    element_size: u64,
    comparator: u64,
    context: u64,
    pass_context: bool,
) -> Result<u64, KernelError> {
    if (base == 0 && count != 0) || element_size == 0 || comparator == 0 || count == 0 {
        return Ok(0);
    }
    let frame = guest::alloc_bytes(if pass_context { 24 } else { 16 });
    if frame == 0 {
        return Err(KernelError::new("No memory for native comparator argument frame"));
    }
    if pass_context {
        guest::write64(frame, context);
        guest::write64(frame + 8, key);
    } else {
        guest::write64(frame, key);
    }
    let mut first = base;
    let mut remaining = count;
    let mut result = 0;
    while remaining > 0 {
        let middle = (remaining - 1) / 2;
        let element = first.wrapping_add(middle.wrapping_mul(element_size));
        guest::write64(frame + if pass_context { 16 } else { 8 }, element);
        let arguments: alloc::vec::Vec<u64> =
            (0..if pass_context { 3 } else { 2 }).map(|index| guest::read64(frame + index * 8)).collect();
        let comparison = native_call::call(comparator, &arguments) as i32;
        if comparison == 0 {
            result = element;
            break;
        }
        if comparison < 0 {
            remaining = middle;
        } else {
            first = element.wrapping_add(element_size);
            remaining -= middle + 1;
        }
    }
    guest::free_bytes(frame);
    Ok(result)
}
