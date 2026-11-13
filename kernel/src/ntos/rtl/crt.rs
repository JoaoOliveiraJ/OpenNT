//! Rotinas de texto e busca da CRT do kernel.
//! Classificação no locale C; ponteiros exatos.
//!
//! Também as cópias, buscas e concatenações str*/wcs* (as variantes `_s`
//! devolvem errno: 22 = EINVAL, 34 = ERANGE, 80 = STRUNCATE), as trocas de
//! caixa no lugar e a guarda `_purecall`.

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// Bytes little-endian de unidades UTF-16.
fn unit_bytes(units: impl IntoIterator<Item = u16>) -> alloc::vec::Vec<u8> {
    units.into_iter().flat_map(u16::to_le_bytes).collect()
}

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
    guest::try_write_bytes(output, &[0, 0])?;
    if capacity <= 1 {
        return Ok(34);
    }
    if !(2..=36).contains(&radix) {
        return Ok(22);
    }
    // Dígitos do menos significativo para o mais, como são gerados.
    let mut value = value;
    let mut digits = alloc::vec::Vec::new();
    loop {
        let digit = value % radix as u32;
        digits.push((digit + if digit <= 9 { 48 } else { 87 }) as u16);
        value /= radix as u32;
        if value == 0 || digits.len() as u64 >= capacity {
            break;
        }
    }
    if digits.len() as u64 >= capacity {
        // Sem espaço: os dígitos gerados ficam e o primeiro vira NUL.
        guest::try_write_bytes(output, &unit_bytes(digits))?;
        guest::try_write_bytes(output, &[0, 0])?;
        return Ok(34);
    }
    guest::try_write_bytes(output, &unit_bytes(digits.into_iter().rev().chain(core::iter::once(0))))?;
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
    let mut bytes = text.as_bytes().to_vec();
    bytes.resize(count.unwrap_or(bytes.len() as u64 + 1) as usize, 0);
    guest::write_bytes(destination, &bytes);
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
    let mut output = bytes[..writable as usize].to_vec();
    output.push(0);
    guest::write_bytes(destination, &output);
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
    guest::write_bytes(destination, &unit_bytes(units[..writable as usize].iter().copied().chain(core::iter::once(0))));
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

// ---- memcpy_s, strrchr, wcsspn, wcscspn, wcstoul, isspace, tolower, toupper,
// ---- iswdigit (crt-strings) ------------------------------------------------
//
// As tabelas de classe são as do próprio ntoskrnl (locale C), lidas da imagem
// com pefile: `pctype` (rva 0xEE00, 257 words com o índice -1 = 0; 128..255
// são zero) e `pwctype` (rva 0xF002, 256 words, Latin-1). toupper passa pela
// página ANSI instalada como o original (RtlAnsiCharToUnicodeChar +
// RtlUpcaseUnicodeToMultiByteN, cujo NLS_UPCASE só consulta a tabela 8:4:4 a
// partir de U+00C0). O errno global (gbl_errno) que wcstoul grava no estouro
// não tem export e não é modelado; o tratador de parâmetro inválido do
// kernel é um `ret`.

const CRT_EINVAL: u32 = 22;
const CRT_ERANGE: u32 = 34;
const CRT_CLASS_UPPER: u16 = 0x001;
const CRT_CLASS_DIGIT: u16 = 0x004;
const CRT_CLASS_SPACE: u16 = 0x008;

/// `pctype` do ntoskrnl, entradas 0..127 (128..255 são zero).
static CRT_NARROW_CLASS: [u16; 128] = [
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x028, 0x028, 0x028, 0x028, 0x028, 0x020, 0x020,
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020,
    0x048, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x081, 0x081, 0x081, 0x081, 0x081, 0x081, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001,
    0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x001, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x082, 0x082, 0x082, 0x082, 0x082, 0x082, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002,
    0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x002, 0x010, 0x010, 0x010, 0x010, 0x020,
];

/// `pwctype` do ntoskrnl (U+0000..U+00FF); acima disso iswctype dá 0.
static CRT_WIDE_CLASS: [u16; 256] = [
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x068, 0x028, 0x028, 0x028, 0x028, 0x020, 0x020,
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020,
    0x048, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x084, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x181, 0x181, 0x181, 0x181, 0x181, 0x181, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x182, 0x182, 0x182, 0x182, 0x182, 0x182, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x010, 0x010, 0x010, 0x010, 0x020,
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020,
    0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020, 0x020,
    0x048, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x010, 0x010, 0x014, 0x014, 0x010, 0x010, 0x010, 0x010, 0x010, 0x014, 0x010, 0x010, 0x010, 0x010, 0x010, 0x010,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101,
    0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x010, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x101, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
    0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x010, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102, 0x102,
];

/// Inícios dos blocos de dez dígitos que `wchartodigit` reconhece.
const CRT_DIGIT_BLOCKS: [u16; 18] = [
    0x0030, 0x0660, 0x06F0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0C66, 0x0CE6, 0x0D66, 0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x17E0, 0x1810, 0xFF10,
];

/// Índice do `pctype`: EOF (-1) lê a entrada -1 (zero); o resto usa o byte baixo.
fn narrow_class(character: u32) -> u16 {
    if character == u32::MAX { 0 } else { CRT_NARROW_CLASS.get((character & 0xFF) as usize).copied().unwrap_or(0) }
}

/// iswctype(_l): só U+0000..U+00FF têm classe.
fn wide_class(unit: u16) -> u16 {
    CRT_WIDE_CLASS.get(unit as usize).copied().unwrap_or(0)
}

/// wchartodigit: valor do dígito Unicode ou None.
fn wide_digit_value(unit: u16) -> Option<u32> {
    CRT_DIGIT_BLOCKS.iter().find(|&&start| unit >= start && unit < start + 10).map(|&start| (unit - start) as u32)
}

fn wide_set_contains(set: u64, unit: u16) -> bool {
    let mut cursor = set;
    loop {
        let candidate = guest::read16(cursor);
        if candidate == 0 {
            return false;
        }
        if candidate == unit {
            return true;
        }
        cursor += 2;
    }
}

/// memcpy_s(Dest, DestSize, Src, Count): Count 0 = sucesso; Dest nulo =
/// EINVAL; Src nulo ou DestSize < Count zeram Dest[0..DestSize] e dão
/// EINVAL/ERANGE.
pub fn memcpy_s(destination: u64, size: u64, source: u64, count: u64) -> u32 {
    if count == 0 {
        return 0;
    }
    if destination == 0 {
        return CRT_EINVAL;
    }
    if source != 0 && size >= count {
        let bytes = guest::read_bytes(source, count as usize);
        guest::write_bytes(destination, &bytes);
        return 0;
    }
    guest::write_bytes(destination, &alloc::vec![0u8; size as usize]);
    if source == 0 {
        return CRT_EINVAL;
    }
    if size < count { CRT_ERANGE } else { CRT_EINVAL }
}

/// strrchr(String, Char): varre de volta a partir do terminador (achar o
/// próprio NUL devolve o seu endereço).
pub fn strrchr(start: u64, wanted: u8) -> u64 {
    let mut cursor = start;
    while guest::read8(cursor) != 0 {
        cursor += 1;
    }
    loop {
        if guest::read8(cursor) == wanted {
            return cursor;
        }
        if cursor == start {
            return 0;
        }
        cursor -= 1;
    }
}

/// wcsspn(String, Set): prefixo formado só por WCHARs de Set.
pub fn wcsspn(text: u64, set: u64) -> u64 {
    let mut index = 0u64;
    loop {
        let unit = guest::read16(text + index * 2);
        if unit == 0 || !wide_set_contains(set, unit) {
            return index;
        }
        index += 1;
    }
}

/// wcscspn(String, Set): prefixo sem nenhum WCHAR de Set.
pub fn wcscspn(text: u64, set: u64) -> u64 {
    let mut index = 0u64;
    loop {
        let unit = guest::read16(text + index * 2);
        if unit == 0 || wide_set_contains(set, unit) {
            return index;
        }
        index += 1;
    }
}

/// wcstoul(String, EndPtr, Base) = wcstoxl(FL_UNSIGNED): brancos de
/// `pwctype`, sinal, prefixo 0x (Base 0/16), octal com 0 inicial em Base 0,
/// dígitos de `wchartodigit` ou letras; estouro satura em ULONG_MAX (negado
/// se houve '-'); sem dígitos, *EndPtr = String e retorno 0.
pub fn wcstoul(text: u64, end: u64, requested: u32) -> u32 {
    // SAFETY: wchar_t** EndPtr do chamador (opcional).
    let end_pointer = (end != 0).then(|| unsafe { Field::<u64>::at(end) });
    if let Some(end_pointer) = end_pointer {
        end_pointer.set(text);
    }
    if text == 0 || (requested != 0 && requested.wrapping_sub(2) > 34) {
        return 0;
    }
    let mut cursor = text + 2;
    let mut unit = guest::read16(text);
    while wide_class(unit) & CRT_CLASS_SPACE != 0 {
        unit = guest::read16(cursor);
        cursor += 2;
    }
    let negative = unit == b'-' as u16;
    if negative || unit == b'+' as u16 {
        unit = guest::read16(cursor);
        cursor += 2;
    }
    let is_x = |candidate: u16| candidate.wrapping_sub(0x58) & 0xFFDF == 0;
    let mut base = requested;
    if base == 0 {
        base = if wide_digit_value(unit) != Some(0) {
            10
        } else if is_x(guest::read16(cursor)) {
            16
        } else {
            8
        };
    }
    if base == 16 && wide_digit_value(unit) == Some(0) && is_x(guest::read16(cursor)) {
        unit = guest::read16(cursor + 2);
        cursor += 4;
    }
    let (limit, remainder) = (u32::MAX / base, u32::MAX % base);
    let (mut number, mut read_digit, mut overflow) = (0u32, false, false);
    loop {
        let digit = match wide_digit_value(unit) {
            Some(digit) => digit,
            None if (0x41..=0x5A).contains(&unit) || (0x61..=0x7A).contains(&unit) => (if unit >= 0x61 { unit - 0x20 } else { unit }) as u32 - 0x37,
            None => break,
        };
        if digit >= base {
            break;
        }
        read_digit = true;
        if number < limit || (number == limit && digit <= remainder) {
            number = number * base + digit;
        } else {
            overflow = true;
            if end == 0 {
                break;
            }
        }
        unit = guest::read16(cursor);
        cursor += 2;
    }
    let mut stop = cursor - 2;
    if !read_digit {
        stop = text;
        number = 0;
    } else if overflow {
        number = u32::MAX;
    }
    if let Some(end_pointer) = end_pointer {
        end_pointer.set(stop);
    }
    if negative { number.wrapping_neg() } else { number }
}

/// isspace(c): bit _SPACE do `pctype`.
pub fn isspace(character: u32) -> u32 {
    (narrow_class(character) & CRT_CLASS_SPACE) as u32
}

/// tolower(c): soma 0x20 quando o byte baixo é _UPPER (só A..Z no locale C).
pub fn tolower(character: u32) -> i32 {
    (if narrow_class(character) & CRT_CLASS_UPPER != 0 { character.wrapping_add(0x20) } else { character }) as i32
}

/// NLS_UPCASE: a..z direto, < U+00C0 inalterado, resto pela tabela 8:4:4.
fn nls_upcase_char(unit: u16) -> Result<u16, KernelError> {
    Ok(match unit {
        0x61..=0x7A => unit - 0x20,
        0..=0xBF => unit,
        _ => crate::ntos::rtl::unicode_case::upcase_char(unit)?,
    })
}

/// toupper(c): RtlAnsiCharToUnicodeChar sobre os bytes do int e
/// RtlUpcaseUnicodeToMultiByteN de um WCHAR (ida e volta pela página,
/// NLS_UPCASE, de volta a MB). Dois bytes de saída viram (alto << 8) | baixo.
pub fn toupper(character: u32) -> Result<i32, KernelError> {
    let code_page = crate::ntos::rtl::ansi_code_page::current()?;
    let wide = if code_page.double_byte {
        // Um inicial DBCS consome o segundo byte do int.
        let scratch = guest::alloc_bytes(4);
        guest::write32(scratch, character);
        let written = code_page.write_unicode(scratch, 2, scratch + 2, 2);
        let unit = guest::read16(scratch + 2);
        guest::free_bytes(scratch);
        written?;
        unit
    } else {
        code_page.multi_byte_to_unicode(character as u8 as u16)?
    };
    let best_fit = code_page.multi_byte_to_unicode(code_page.unicode_to_multi_byte(wide)?)?;
    let upper = code_page.unicode_to_multi_byte(nls_upcase_char(best_fit)?)?;
    Ok(if upper >> 8 != 0 { upper as i32 } else { (upper & 0xFF) as i32 })
}

/// iswdigit(c) = iswctype(c, _DIGIT): U+00B2/B3/B9 contam, acima de U+00FF não.
pub fn iswdigit(unit: u16) -> u32 {
    (wide_class(unit) & CRT_CLASS_DIGIT) as u32
}

// ---- _wtoi, towlower e RtlPrefetchMemoryNonTemporal (ntoskrnl 19041) ---------
//
// _wtoi 0x3d1d30 = _wtol 0x3d1d50 = wcstolX(s, NULL, 10, sem checagem de
// estouro) -> wcstoxlX 0x3d3b7c. towlower 0x3d36a0 = iswctype(c, _UPPER) ?
// c + 0x20 : c. iswctype (0x3d426c) só classifica c < 0x100 pela tabela
// pwctype; as entradas usadas aqui foram lidas da imagem com pefile:
//   _SPACE: 0x09..0x0D, 0x20, 0xA0
//   _UPPER: 0x41..0x5A, 0xC0..0xD6, 0xD8..0xDE
// wchartodigit 0x3d5ac4 aceita os dígitos de '0', 0xFF10 (largos) e os
// blocos com zero em 0x660, 0x6F0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xC66,
// 0xCE6, 0xD66, 0xE50, 0xED0, 0xF20, 0x1040, 0x17E0 e 0x1810.

/// iswctype(c, _SPACE) da tabela pwctype.
fn crt_is_space(c: u16) -> bool {
    (0x09..=0x0D).contains(&c) || c == 0x20 || c == 0xA0
}

/// iswctype(c, _UPPER) da tabela pwctype.
fn crt_is_upper(c: u16) -> bool {
    (0x41..=0x5A).contains(&c) || (0xC0..=0xD6).contains(&c) || (0xD8..=0xDE).contains(&c)
}

/// wchartodigit: valor do dígito Unicode ou None.
fn crt_wide_digit(c: u16) -> Option<u32> {
    const ZEROS: [u16; 17] = [0x660, 0x6F0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xC66, 0xCE6, 0xD66, 0xE50, 0xED0, 0xF20, 0x1040, 0x17E0, 0x1810, 0xFF10];
    if (0x30..0x3A).contains(&c) {
        return Some((c - 0x30) as u32);
    }
    ZEROS.iter().find(|&&zero| c >= zero && c < zero + 10).map(|&zero| (c - zero) as u32)
}

/// _wtoi(s): NULL = 0; espaços (_SPACE), um sinal, dígitos decimais
/// (wchartodigit) acumulados em 32 bits com volta (sem clamp nem errno, o
/// modo de _wtol); '-' nega. A string é lida até o NUL de uma vez (o
/// original para no primeiro caractere que não é dígito, antes do NUL).
pub fn wtoi(source: u64) -> i32 {
    if source == 0 {
        return 0;
    }
    let units = guest_strings::read_wide_units(source);
    let mut chars = units.iter().copied().skip_while(|&c| crt_is_space(c)).peekable();
    let negative = chars.peek() == Some(&0x2D);
    if matches!(chars.peek(), Some(&0x2D) | Some(&0x2B)) {
        chars.next();
    }
    let mut value = 0u32;
    for digit in chars.map_while(crt_wide_digit) {
        value = value.wrapping_mul(10).wrapping_add(digit);
    }
    if negative { (value as i32).wrapping_neg() } else { value as i32 }
}

/// towlower(c): só as maiúsculas da tabela pwctype (c < 0x100) descem.
pub fn towlower(c: u16) -> u16 {
    if crt_is_upper(c) { c + 0x20 } else { c }
}

/// RtlPrefetchMemoryNonTemporal(Source, Length): o original só emite
/// `prefetchnta` a cada 64 bytes — uma dica de cache sem efeito
/// arquitetural nem falta de página; não há estado a reproduzir.
pub fn prefetch_memory_non_temporal(_source: u64, _length: u64) {}

/// isprint(c) (ntoskrnl 19045, 0x3d2030): `_pctype[c] & 0x157` sobre o byte
/// baixo de `c` (EOF = -1 indexa a entrada zero de antes da tabela). Na
/// tabela do locale C do ntoskrnl (lida com pefile): espaço 0x40; pontuação
/// 0x21..0x2F, 0x3A..0x40, 0x5B..0x60, 0x7B..0x7E = 0x10; dígitos = 0x4;
/// maiúsculas = 0x1; minúsculas = 0x2; o resto (controle, 0x7F..0xFF) = 0.
pub fn isprint(character: u32) -> u32 {
    if character == u32::MAX {
        return 0;
    }
    match character as u8 {
        b' ' => 0x40,
        b'0'..=b'9' => 0x4,
        b'A'..=b'Z' => 0x1,
        b'a'..=b'z' => 0x2,
        0x21..=0x7E => 0x10,
        _ => 0,
    }
}
