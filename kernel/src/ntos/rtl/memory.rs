//! Blocos de memória do convidado — a família mem* da CRT e as Rtl*Memory
//! (preencher, copiar, mover e comparar bytes).

use crate::ntos::mm::guest_memory as guest;

/// memset/RtlZeroMemory/RtlFillMemory: grava `value` em `length` bytes.
pub fn fill(destination: u64, length: u64, value: u8) {
    for offset in 0..length {
        guest::write8(destination + offset, value);
    }
}

/// memcpy/memmove/RtlMoveMemory: cópia por um temporário (seguro com
/// sobreposição).
pub fn move_memory(destination: u64, source: u64, length: u64) {
    let bytes = guest::read_bytes(source, length as usize);
    guest::write_bytes(destination, &bytes);
}

/// RtlCopyMemory: cópia byte a byte, do início para o fim.
pub fn copy_memory(destination: u64, source: u64, length: u64) {
    for offset in 0..length {
        guest::write8(destination + offset, guest::read8(source + offset));
    }
}

/// RtlCompareMemory: bytes iguais do início.
pub fn compare(left: u64, right: u64, length: u64) -> u64 {
    let mut equal = 0;
    while equal < length && guest::read8(left + equal) == guest::read8(right + equal) {
        equal += 1;
    }
    equal
}
