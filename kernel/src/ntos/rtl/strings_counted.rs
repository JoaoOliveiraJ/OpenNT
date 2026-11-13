//! Strings contadas do Rtl.
//!
//! Também as STRING/ANSI_STRING de bytes: RtlInitString, RtlEqualString,
//! RtlFreeAnsiString e RtlAppendStringToString.

use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MAXIMUM_SOURCE_CHARACTERS: u64 = 0x7FFE;
const MAXIMUM_ANSI_LENGTH: u64 = 0xFFFE;

/// memmove: a origem inteira é lida antes da escrita (sobreposição preservada).
fn move_bytes(destination: u64, source: u64, length: u64) {
    guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
}

/// PUNICODE_STRING do chamador.
fn unicode(address: u64) -> &'static UnicodeString {
    // SAFETY: descritor vivo e alinhado (kernel ou driver), como o PUNICODE_STRING do NT.
    unsafe { UnicodeString::at(address) }
}

/// PSTRING/PANSI_STRING/POEM_STRING do chamador.
fn ansi(address: u64) -> &'static AnsiString {
    // SAFETY: idem `unicode`.
    unsafe { AnsiString::at(address) }
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
    let destination = unicode(destination);
    let length = destination.length.get() as u64;
    let appended = count * 2;
    if length + appended > destination.maximum_length.get() as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    let at = destination.buffer.get() + (length & !1);
    move_bytes(at, source, appended);
    // Soma ao Length presente depois da cópia (o buffer pode sobrepor o descritor).
    destination.length.set((destination.length.get() as u64 + appended) as u16);
    if (destination.length.get() as u32) + 1 < destination.maximum_length.get() as u32 {
        guest::write_bytes(at + appended, &[0, 0]);
    }
    0
}

/// RtlCopyUnicodeString: copia por bytes (inclusive comprimento ímpar).
pub fn copy(destination: u64, source: u64) {
    let destination = unicode(destination);
    if source == 0 {
        destination.length.set(0);
        return;
    }
    let source = unicode(source);
    let copied = source.length.get().min(destination.maximum_length.get()) as u64;
    let source_buffer = source.buffer.get();
    let destination_buffer = destination.buffer.get();
    destination.length.set(copied as u16);
    move_bytes(destination_buffer, source_buffer, copied);
    // NUL só com dois bytes extras; o índice WCHAR descarta o bit ímpar.
    if destination.length.get() as u32 + 2 <= destination.maximum_length.get() as u32 {
        guest::write_bytes(destination_buffer + (copied & !1), &[0, 0]);
    }
}

/// RtlInitAnsiString: descritor escrito antes de procurar o terminador.
pub fn initialize_ansi(destination: u64, source: u64) {
    let destination = ansi(destination);
    destination.length.set(0);
    destination.maximum_length.set(0);
    destination.buffer.set(source);
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
    destination.length.set(length as u16);
    destination.maximum_length.set((length + 1) as u16);
}

/// RtlInitString: o texto não é copiado (MaximumLength = Length + 1).
pub fn init_string(destination: u64, source: u64) {
    let length = if source != 0 { guest_strings::read_c_string(source).len() as u16 } else { 0 };
    let destination = ansi(destination);
    destination.length.set(length);
    destination.maximum_length.set(length + 1);
    destination.buffer.set(source);
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
    let string = ansi(pointer);
    let buffer = string.buffer.get();
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    string.length.set(0);
    string.maximum_length.set(0);
    string.buffer.set(0);
}

/// RtlAppendStringToString(PSTRING Dest, const STRING* Src): concatena uma
/// STRING ANSI contada (sem terminador), respeitando MaximumLength.
pub fn append_string(dest: u64, src: u64) -> u32 {
    let (dest, src) = (ansi(dest), ansi(src));
    let src_len = src.length.get() as u64;
    if src_len == 0 {
        return 0;
    }
    let dest_len = dest.length.get() as u64;
    if dest_len + src_len > dest.maximum_length.get() as u64 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    guest::write_bytes(dest.buffer.get() + dest_len, &guest::read_bytes(src.buffer.get(), src_len as usize));
    dest.length.set((dest_len + src_len) as u16);
    0
}

// ---- RtlFreeOemString, RtlCompareString, RtlPrefixString (rtl-strings) -----

/// RtlFreeOemString: só ExFreePool(Buffer); ao contrário do RtlFreeAnsiString
/// do OpenNT, os campos ficam como estão (o original não os toca).
pub fn free_oem_string(string: u64) -> Result<(), crate::rtl::KernelError> {
    let buffer = ansi(string).buffer.get();
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
    let (left, right) = (ansi(left), ansi(right));
    let (left_length, right_length) = (left.length.get() as i32, right.length.get() as i32);
    let common = left_length.min(right_length) as usize;
    let left_bytes = guest::read_bytes(left.buffer.get(), common);
    let right_bytes = guest::read_bytes(right.buffer.get(), common);
    for (&a, &b) in left_bytes.iter().zip(&right_bytes) {
        if a != b {
            let (a, b) = if case_insensitive { (upper_ansi_char(a), upper_ansi_char(b)) } else { (a, b) };
            if a == b {
                continue;
            }
            return a as i32 - b as i32;
        }
    }
    left_length - right_length
}

/// RtlPrefixString(S1, S2, CaseInSensitive): S1 é prefixo de S2.
pub fn prefix_ansi(prefix: u64, text: u64, case_insensitive: bool) -> bool {
    let (prefix, text) = (ansi(prefix), ansi(text));
    let length = prefix.length.get() as usize;
    if (text.length.get() as usize) < length {
        return false;
    }
    let prefix_bytes = guest::read_bytes(prefix.buffer.get(), length);
    let text_bytes = guest::read_bytes(text.buffer.get(), length);
    prefix_bytes.iter().zip(&text_bytes).all(|(&a, &b)| a == b || (case_insensitive && upper_ansi_char(a) == upper_ansi_char(b)))
}

/// RtlCopyString(Destination, Source) (ntoskrnl 19045, 0x585370): zera o
/// Length; com Source, copia min(Source.Length, Destination.MaximumLength)
/// bytes e grava esse Length (sem terminador).
pub fn copy_string(destination: &AnsiString, source: u64) {
    destination.length.set(0);
    if source == 0 {
        return;
    }
    let source = ansi(source);
    let length = source.length.get().min(destination.maximum_length.get());
    destination.length.set(length);
    if length != 0 {
        let bytes = guest::read_bytes(source.buffer.get(), length as usize);
        guest::write_bytes(destination.buffer.get(), &bytes);
    }
}
