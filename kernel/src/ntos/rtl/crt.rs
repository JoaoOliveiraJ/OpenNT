//! Rotinas de texto e busca da CRT do kernel — `system32/ntos/rtl/crt.js`.
//! Classificação no locale C; ponteiros exatos.
//!
//! Também as cópias, buscas e concatenações str*/wcs* (as variantes `_s`
//! devolvem errno: 22 = EINVAL, 34 = ERANGE, 80 = STRUNCATE), as trocas de
//! caixa no lugar e a guarda `_purecall`.

use crate::hal::amd64::native_call;
use crate::ntos::rtl::guest_strings;
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

// ---- strings de bytes --------------------------------------------------------

/// Grava o texto e o terminador; com `count`, exatamente `count` bytes
/// (completando com zeros, sem terminador se não couber).
pub fn write_c_text(destination: u64, text: &str, count: Option<u64>) {
    let bytes = text.as_bytes();
    let total = count.unwrap_or(bytes.len() as u64 + 1);
    for index in 0..total {
        guest::write8(destination + index, bytes.get(index as usize).copied().unwrap_or(0));
    }
}

/// strcpy: devolve o destino.
pub fn strcpy(destination: u64, source: u64) -> u64 {
    write_c_text(destination, &guest_strings::read_c_string(source), None);
    destination
}

/// strncpy: exatamente `count` bytes; devolve o destino.
pub fn strncpy(destination: u64, source: u64, count: u64) -> u64 {
    write_c_text(destination, &guest_strings::read_c_string(source), Some(count));
    destination
}

/// strcat: devolve o destino.
pub fn strcat(destination: u64, source: u64) -> u64 {
    let combined = alloc::format!("{}{}", guest_strings::read_c_string(destination), guest_strings::read_c_string(source));
    write_c_text(destination, &combined, None);
    destination
}

/// strchr: primeira ocorrência do byte (o terminador não conta).
pub fn strchr(source: u64, character: u8) -> u64 {
    let text = guest_strings::read_c_string(source);
    text.bytes().position(|byte| byte == character).map_or(0, |index| source + index as u64)
}

/// strstr: primeira ocorrência da agulha.
pub fn strstr(source: u64, needle: u64) -> u64 {
    let text = guest_strings::read_c_string(source);
    let needle = guest_strings::read_c_string(needle);
    text.find(&needle).map_or(0, |index| source + index as u64)
}

/// _strupr: maiúsculas ASCII no lugar; devolve a própria string.
pub fn strupr(source: u64) -> u64 {
    let mut cursor = source;
    loop {
        let byte = guest::read8(cursor);
        if byte == 0 {
            break;
        }
        if byte.is_ascii_lowercase() {
            guest::write8(cursor, byte - 0x20);
        }
        cursor += 1;
    }
    source
}

/// strnlen(const char*, size_t max).
pub fn strnlen(source: u64, maximum: u64) -> u64 {
    let mut count = 0;
    while count < maximum && guest::read8(source + count) != 0 {
        count += 1;
    }
    count
}

/// strcpy_s: ERANGE (destino vazio) quando o texto não cabe.
pub fn strcpy_s(destination: u64, capacity: u64, source: u64) -> u64 {
    let text = guest_strings::read_c_string(source);
    if text.len() as u64 + 1 > capacity {
        guest::write8(destination, 0);
        return 34;
    }
    write_c_text(destination, &text, None);
    0
}

/// strncpy_s: _TRUNCATE (-1) trunca; senão ERANGE quando não cabe.
pub fn strncpy_s(destination: u64, capacity: u64, source: u64, count: i32) -> u64 {
    let text = guest_strings::read_c_string(source);
    let bytes = text.as_bytes();
    let wanted = if count < 0 { bytes.len() as u64 } else { (count as u64).min(bytes.len() as u64) };
    if wanted >= capacity && count >= 0 {
        guest::write8(destination, 0);
        return 34;
    }
    let writable = wanted.min(capacity.saturating_sub(1));
    for index in 0..writable {
        guest::write8(destination + index, bytes[index as usize]);
    }
    guest::write8(destination + writable, 0);
    if wanted > writable || (count < 0 && bytes.len() as u64 > writable) { 80 } else { 0 }
}

// ---- strings largas ----------------------------------------------------------

/// _wcsupr: maiúsculas no lugar, unidade a unidade; devolve a própria string.
pub fn wcsupr(source: u64) -> u64 {
    let mut cursor = source;
    loop {
        let unit = guest::read16(cursor);
        if unit == 0 {
            break;
        }
        let upper = char::from_u32(unit as u32).and_then(|character| character.to_uppercase().next()).map_or(unit, |character| {
            let mut buffer = [0u16; 2];
            character.encode_utf16(&mut buffer)[0]
        });
        guest::write16(cursor, upper);
        cursor += 2;
    }
    source
}

/// _wcslwr(wchar_t*): minúsculas no lugar, unidade a unidade.
pub fn wcslwr(source: u64) -> u64 {
    let mut cursor = source;
    loop {
        let unit = guest::read16(cursor);
        if unit == 0 {
            break;
        }
        let lower = char::from_u32(unit as u32).and_then(|character| character.to_lowercase().next()).map_or(unit, |character| {
            let mut buffer = [0u16; 2];
            character.encode_utf16(&mut buffer)[0]
        });
        guest::write16(cursor, lower);
        cursor += 2;
    }
    source
}

/// wcsstr: agulha vazia devolve o próprio texto.
pub fn wcsstr(haystack: u64, needle: u64) -> u64 {
    let text = guest_strings::read_wide_units(haystack);
    let pattern = guest_strings::read_wide_units(needle);
    if pattern.is_empty() {
        return haystack;
    }
    text.windows(pattern.len()).position(|window| window == pattern.as_slice()).map_or(0, |index| haystack + index as u64 * 2)
}

fn fold(unit: u16) -> u16 {
    char::from_u32(unit as u32).and_then(|character| character.to_uppercase().next()).map_or(unit, |character| {
        let mut buffer = [0u16; 2];
        character.encode_utf16(&mut buffer)[0]
    })
}

/// Comparação WCHAR (com dobra de maiúsculas opcional e limite opcional) de
/// wcscmp/wcsncmp/_wcsicmp/_wcsnicmp: -1, 0 ou 1.
pub fn compare_wide(left: u64, right: u64, limit: Option<u64>, insensitive: bool) -> u64 {
    let mut index = 0u64;
    loop {
        if limit.is_some_and(|limit| index >= limit) {
            return 0;
        }
        let mut a = guest::read16(left + index * 2);
        let mut b = guest::read16(right + index * 2);
        let zero = a == 0;
        if insensitive {
            a = fold(a);
            b = fold(b);
        }
        if a != b {
            return if a < b { (-1i64) as u64 } else { 1 };
        }
        if zero {
            return 0;
        }
        index += 1;
    }
}

/// wcslen.
pub fn wcslen(source: u64) -> u64 {
    let mut count = 0;
    while guest::read16(source + count * 2) != 0 {
        count += 1;
    }
    count
}

/// wcsnlen(const wchar_t*, size_t max).
pub fn wcsnlen(source: u64, maximum: u64) -> u64 {
    let mut count = 0u64;
    while count < maximum && guest::read16(source + count * 2) != 0 {
        count += 1;
    }
    count
}

/// wcsrchr(const wchar_t*, wchar_t): última ocorrência (o terminador conta).
pub fn wcsrchr(source: u64, target: u16) -> u64 {
    let (mut index, mut last) = (0u64, 0u64);
    loop {
        let unit = guest::read16(source + index * 2);
        if unit == target {
            last = source + index * 2;
        }
        if unit == 0 {
            break;
        }
        index += 1;
    }
    last
}

/// wcscat_s: EINVAL sem NUL no destino, ERANGE sem espaço.
pub fn wcscat_s(destination: u64, capacity: u64, source: u64) -> u64 {
    let text = guest_strings::read_wide_string(source);
    let mut length = 0;
    while length < capacity && guest::read16(destination + length * 2) != 0 {
        length += 1;
    }
    if length == capacity {
        return 22;
    }
    if length + text.encode_utf16().count() as u64 + 1 > capacity {
        guest::write16(destination, 0);
        return 34;
    }
    guest_strings::write_wide_string(destination + length * 2, &text);
    0
}

/// wcscpy_s: ERANGE (destino vazio) quando o texto não cabe.
pub fn wcscpy_s(destination: u64, capacity: u64, source: u64) -> u64 {
    let text = guest_strings::read_wide_string(source);
    if text.encode_utf16().count() as u64 + 1 > capacity {
        guest::write16(destination, 0);
        return 34;
    }
    guest_strings::write_wide_string(destination, &text);
    0
}

/// wcsncpy_s(wchar_t* d, size_t n, const wchar_t* s, size_t count): cópia
/// limitada; _TRUNCATE((size_t)-1) trunca com STRUNCATE, senão ERANGE.
pub fn wcsncpy_s(destination: u64, capacity: u64, source: u64, count: u64) -> u64 {
    if capacity == 0 {
        return 22; // EINVAL
    }
    let units = guest_strings::read_wide_units(source);
    let truncate = count == u64::MAX;
    let wanted = if truncate { units.len() as u64 } else { count.min(units.len() as u64) };
    if !truncate && wanted + 1 > capacity {
        guest::write16(destination, 0);
        return 34; // ERANGE
    }
    let writable = wanted.min(capacity - 1);
    for index in 0..writable {
        guest::write16(destination + index * 2, units[index as usize]);
    }
    guest::write16(destination + writable * 2, 0);
    if truncate && units.len() as u64 > writable { 80 } else { 0 } // STRUNCATE/0
}

// ---- guarda ------------------------------------------------------------------

/// _purecall(): guarda de chamada a função virtual pura. Nunca deve ocorrer
/// legitimamente; derruba o sistema (KeBugCheckEx), como no ntoskrnl.
pub fn purecall() -> ! {
    crate::ntos::ke::bugcheck::bug_check_ex(0x0000_0139, 0x0000_0005, 0, 0, 0)
}

/// _strnicmp: compara até `count` bytes sem diferenciar maiúsculas/minúsculas
/// (-1, 0 ou 1).
pub fn strnicmp(first: u64, second: u64, count: u64) -> i32 {
    let (mut first, mut second) = (first, second);
    for _ in 0..count {
        let left = guest::read8(first).to_ascii_lowercase();
        let right = guest::read8(second).to_ascii_lowercase();
        if left != right {
            return if left < right { -1 } else { 1 };
        }
        if left == 0 {
            break;
        }
        first += 1;
        second += 1;
    }
    0
}
