//! Blocos de memória do convidado — a família mem* da CRT e as Rtl*Memory
//! (preencher, copiar, mover e comparar bytes).

use crate::ntos::mm::guest_memory as guest;

/// Bloco de preenchimento: blocos de até uma página por cópia.
const FILL_CHUNK: u64 = 4096;

/// memset/RtlZeroMemory/RtlFillMemory: grava `value` em `length` bytes.
pub fn fill(destination: u64, length: u64, value: u8) {
    let pattern = [value; FILL_CHUNK as usize];
    let mut offset = 0;
    while offset < length {
        let chunk = (length - offset).min(FILL_CHUNK);
        guest::write_bytes(destination + offset, &pattern[..chunk as usize]);
        offset += chunk;
    }
}

/// memcpy/memmove/RtlMoveMemory: cópia por um temporário (seguro com
/// sobreposição).
pub fn move_memory(destination: u64, source: u64, length: u64) {
    let bytes = guest::read_bytes(source, length as usize);
    guest::write_bytes(destination, &bytes);
}

/// RtlCopyMemory: cópia do início para o fim. Sem sobreposição à frente
/// da origem é um bloco; com o destino dentro da origem, byte a byte (o
/// padrão se repete, como na cópia crescente).
pub fn copy_memory(destination: u64, source: u64, length: u64) {
    if destination <= source || destination >= source.wrapping_add(length) {
        move_memory(destination, source, length);
        return;
    }
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
