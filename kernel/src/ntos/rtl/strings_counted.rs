//! Strings contadas do Rtl.
//!
//! Também as STRING/ANSI_STRING de bytes: RtlInitString, RtlEqualString,
//! RtlFreeAnsiString e RtlAppendStringToString.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MAXIMUM_SOURCE_CHARACTERS: u64 = 0x7FFE;
const MAXIMUM_ANSI_LENGTH: u64 = 0xFFFE;

/// memmove byte a byte: a direção inversa preserva a origem sobreposta.
fn move_bytes(destination: u64, source: u64, length: u64) {
    let backwards = destination > source && destination < source + length;
    for index in 0..length {
        let offset = if backwards { length - index - 1 } else { index };
        guest::write8(destination + offset, guest::read8(source + offset));
    }
}

/// RtlAppendUnicodeToString: concatena uma origem WCHAR terminada em NUL.
pub fn append(destination: u64, source: u64) -> u32 {
    // Origem NULL retorna sem consultar o descritor de destino.
    if source == 0 {
        return 0;
    }
    // O NUL é procurado antes de rejeitar o tamanho; só o contador satura.
    let mut cursor = source;
    let mut count = 0u64;
    while guest::read16(cursor) != 0 {
        if count <= MAXIMUM_SOURCE_CHARACTERS {
            count += 1;
        }
        cursor = cursor.wrapping_add(2);
    }
    if count > MAXIMUM_SOURCE_CHARACTERS {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let length = guest::read16(destination) as u64;
    let appended = count * 2;
    if length + appended > guest::read16(destination + 2) as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let at = guest::read64(destination + 8) + (length & !1);
    move_bytes(at, source, appended);
    // Soma ao Length presente depois da cópia (o buffer pode sobrepor o descritor).
    guest::write16(destination, (guest::read16(destination) as u64 + appended) as u16);
    if (guest::read16(destination) as u32) + 1 < guest::read16(destination + 2) as u32 {
        guest::write16(at + appended, 0);
    }
    0
}

/// RtlCopyUnicodeString: copia por bytes (inclusive comprimento ímpar).
pub fn copy(destination: u64, source: u64) {
    if source == 0 {
        guest::write16(destination, 0);
        return;
    }
    let copied = (guest::read16(source)).min(guest::read16(destination + 2)) as u64;
    let source_buffer = guest::read64(source + 8);
    let destination_buffer = guest::read64(destination + 8);
    guest::write16(destination, copied as u16);
    move_bytes(destination_buffer, source_buffer, copied);
    // NUL só com dois bytes extras; o índice WCHAR descarta o bit ímpar.
    if guest::read16(destination) as u32 + 2 <= guest::read16(destination + 2) as u32 {
        guest::write16(destination_buffer + (copied & !1), 0);
    }
}

/// RtlInitAnsiString: descritor escrito antes de procurar o terminador.
pub fn initialize_ansi(destination: u64, source: u64) {
    guest::write64(destination, 0);
    guest::write64(destination + 8, source);
    if source == 0 {
        return;
    }
    let mut cursor = source;
    let mut length = 0u64;
    while guest::read8(cursor) != 0 {
        if length < MAXIMUM_ANSI_LENGTH {
            length += 1;
        }
        cursor = cursor.wrapping_add(1);
    }
    guest::write16(destination, length as u16);
    guest::write16(destination + 2, (length + 1) as u16);
}

/// RtlInitString: o texto não é copiado (MaximumLength = Length + 1).
pub fn init_string(destination: u64, source: u64) {
    let length = if source != 0 { guest_strings::read_c_string(source).len() as u16 } else { 0 };
    guest::write16(destination, length);
    guest::write16(destination + 2, length + 1);
    guest::write64(destination + 8, source);
}

/// RtlEqualString: comparação das ANSI_STRING (minúsculas se pedido).
pub fn equal_ansi(left: u64, right: u64, case_insensitive: bool) -> bool {
    let mut left = guest_strings::read_ansi_string(left);
    let mut right = guest_strings::read_ansi_string(right);
    if case_insensitive {
        left = left.to_lowercase();
        right = right.to_lowercase();
    }
    left == right
}

/// RtlFree*String: libera o buffer e zera os campos.
pub fn free_string(pointer: u64) {
    let buffer = guest::read64(pointer + 8);
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    guest::write16(pointer, 0);
    guest::write16(pointer + 2, 0);
    guest::write64(pointer + 8, 0);
}

/// RtlAppendStringToString(PSTRING Dest, const STRING* Src): concatena uma
/// STRING ANSI contada (sem terminador), respeitando MaximumLength.
pub fn append_string(dest: u64, src: u64) -> u32 {
    let src_len = guest::read16(src) as u64;
    if src_len == 0 {
        return 0;
    }
    let dest_len = guest::read16(dest) as u64;
    if dest_len + src_len > guest::read16(dest + 2) as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let (dest_buffer, src_buffer) = (guest::read64(dest + 8), guest::read64(src + 8));
    for index in 0..src_len {
        guest::write8(dest_buffer + dest_len + index, guest::read8(src_buffer + index));
    }
    guest::write16(dest, (dest_len + src_len) as u16);
    0
}

// ---- RtlFreeOemString, RtlCompareString, RtlPrefixString (rtl-strings) -----

/// RtlFreeOemString: só ExFreePool(Buffer); ao contrário do RtlFreeAnsiString
/// do OpenNT, os campos ficam como estão (o original não os toca).
pub fn free_oem_string(string: u64) -> Result<(), crate::rtl::KernelError> {
    let buffer = guest::read64(string + 8);
    if buffer != 0 {
        crate::ntos::ex::pool_allocation::free(buffer, 0)?;
    }
    Ok(())
}

/// RtlUpperChar desta build: só a..z (o resto, inclusive o intervalo alto,
/// passa igual).
fn upper_ansi_char(character: u8) -> u8 {
    if character.wrapping_sub(b'a') <= 25 { character ^ 0x20 } else { character }
}

/// RtlCompareString(S1, S2, CaseInSensitive): diferença dos bytes sem sinal
/// (depois do RtlUpperChar, se sem caixa) na primeira divergência; senão
/// Length1 - Length2.
pub fn compare_ansi(left: u64, right: u64, case_insensitive: bool) -> i32 {
    let (left_length, right_length) = (guest::read16(left) as i32, guest::read16(right) as i32);
    let (left_buffer, right_buffer) = (guest::read64(left + 8), guest::read64(right + 8));
    for index in 0..left_length.min(right_length) as u64 {
        let (mut a, mut b) = (guest::read8(left_buffer + index), guest::read8(right_buffer + index));
        if a != b {
            if case_insensitive {
                a = upper_ansi_char(a);
                b = upper_ansi_char(b);
                if a == b {
                    continue;
                }
            }
            return a as i32 - b as i32;
        }
    }
    left_length - right_length
}

/// RtlPrefixString(S1, S2, CaseInSensitive): S1 é prefixo de S2.
pub fn prefix_ansi(prefix: u64, text: u64, case_insensitive: bool) -> bool {
    let length = guest::read16(prefix) as u64;
    if (guest::read16(text) as u64) < length {
        return false;
    }
    let (prefix_buffer, text_buffer) = (guest::read64(prefix + 8), guest::read64(text + 8));
    (0..length).all(|index| {
        let (a, b) = (guest::read8(prefix_buffer + index), guest::read8(text_buffer + index));
        a == b || (case_insensitive && upper_ansi_char(a) == upper_ansi_char(b))
    })
}
