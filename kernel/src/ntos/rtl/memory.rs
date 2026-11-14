//! Blocos de memória do convidado — a família mem* da CRT e as Rtl*Memory
//! (preencher, copiar, mover e comparar bytes).

use crate::hal::volatile;
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

/// RtlCopyMemoryNonTemporal(Destination, Source, Length) (ntoskrnl 19041
/// 0x407930): cópia para a frente com stores não temporais (MOVNTI) e um
/// SFENCE no fim, na mesma ordem de acessos do original. Menos de 8 bytes
/// vão byte a byte, sem fence. De 8 a 0x4E bytes, palavras de 8 bytes e por
/// último a palavra que termina no fim do destino (que pode regravar bytes
/// já copiados). A partir de 0x4F, o destino é alinhado a 16 (uma ou duas
/// palavras), seguem blocos de 64 bytes (lidos e gravados 32 a 32, como os
/// pares MOVDQU/MOVNTDQ do original) em lotes de até 1 KB e o resto como
/// no caso curto. O PREFETCHNTA do original não muda o resultado.
pub fn copy_memory_non_temporal(destination: u64, source: u64, length: u64) {
    if length < 8 {
        for offset in 0..length {
            guest::write8(destination + offset, guest::read8(source + offset));
        }
        return;
    }
    let delta = source.wrapping_sub(destination);
    let copy_word = |at: u64| volatile::write64_non_temporal(at, guest::read64(at.wrapping_add(delta)));
    let mut cursor = destination;
    let mut remaining = length;
    if length >= 0x4F {
        if cursor & 0xF != 0 {
            let end = cursor + remaining;
            copy_word(cursor);
            if cursor & 8 == 0 {
                copy_word(cursor + 8);
            }
            cursor = (cursor + 0x10) & !0xF;
            remaining = end - cursor;
        }
        loop {
            let blocks = if remaining >= 0x400 {
                remaining -= 0x400;
                16
            } else {
                let blocks = remaining >> 6;
                remaining &= 0x3F;
                blocks
            };
            for _ in 0..blocks {
                for half in [0u64, 32] {
                    let base = cursor + half;
                    let words: [u64; 4] = core::array::from_fn(|index| guest::read64((base + index as u64 * 8).wrapping_add(delta)));
                    for (index, &word) in words.iter().enumerate() {
                        volatile::write64_non_temporal(base + index as u64 * 8, word);
                    }
                }
                cursor += 64;
            }
            if remaining < 0x40 {
                break;
            }
        }
    }
    // Palavras de 8 bytes; a última termina exatamente no fim do destino.
    let mut left = remaining as i64 - 8;
    while left > 0 {
        copy_word(cursor);
        cursor += 8;
        left -= 8;
    }
    copy_word(cursor.wrapping_add(left as u64));
    volatile::store_fence();
}

/// RtlCompareMemory: bytes iguais do início.
pub fn compare(left: u64, right: u64, length: u64) -> u64 {
    let mut equal = 0;
    while equal < length && guest::read8(left + equal) == guest::read8(right + equal) {
        equal += 1;
    }
    equal
}
