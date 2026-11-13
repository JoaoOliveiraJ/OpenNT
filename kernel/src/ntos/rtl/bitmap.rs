//! RTL_BITMAP.
//!
//! SizeOfBitMap (32 bits) em +0 e Buffer (64 bits) em +8; índices e
//! comprimentos em bits sobre palavras ULONG. As operações de intervalo
//! pressupõem limites e armazenamento válidos fornecidos pelo chamador.

use crate::ntos::mm::guest_memory as guest;

/// Índice sentinela nativo de busca sem resultado.
pub const NO_MATCH: u32 = 0xFFFF_FFFF;

fn buffer(header: u64) -> u64 {
    guest::read64(header + 8)
}

fn mask(first_bit: u32, count: u32) -> u32 {
    (NO_MATCH >> (32 - count)) << first_bit
}

/// RtlInitializeBitMap: não inicializa o conteúdo do buffer.
pub fn initialize(header: u64, words: u64, bit_count: u32) {
    guest::write32(header, bit_count);
    guest::write64(header + 8, words);
}

fn fill(header: u64, value: u32) {
    let words = (guest::read32(header) as u64).div_ceil(32);
    let pointer = buffer(header);
    for index in 0..words {
        guest::write32(pointer + index * 4, value);
    }
}

pub fn set_all(header: u64) {
    fill(header, NO_MATCH)
}

pub fn clear_all(header: u64) {
    fill(header, 0)
}

/// Ajusta só os bits da máscara; no modo atômico repete o CAS em conflito.
fn change_range(header: u64, first_bit: u32, mut count: u32, set: bool, atomic: bool) {
    let mut pointer = buffer(header) + (first_bit / 32) as u64 * 4;
    let mut offset = first_bit & 31;
    while count != 0 {
        let chunk = count.min(32 - offset);
        let requested = mask(offset, chunk);
        let mut previous = guest::read32(pointer);
        loop {
            let updated = if set { previous | requested } else { previous & !requested };
            if !atomic {
                guest::write32(pointer, updated);
                break;
            }
            let observed = guest::compare_exchange32(pointer, previous, updated).unwrap_or(previous);
            if observed == previous {
                break;
            }
            previous = observed;
        }
        pointer += 4;
        offset = 0;
        count -= chunk;
    }
}

pub fn set_bits(header: u64, first_bit: u32, count: u32) {
    change_range(header, first_bit, count, true, false)
}

pub fn clear_bits(header: u64, first_bit: u32, count: u32) {
    change_range(header, first_bit, count, false, false)
}

pub fn set_bit(header: u64, bit: u32) {
    change_range(header, bit, 1, true, false)
}

pub fn clear_bit(header: u64, bit: u32) {
    change_range(header, bit, 1, false, false)
}

pub fn interlocked_clear(header: u64, first_bit: u32, count: u32) {
    change_range(header, first_bit, count, false, true)
}

pub fn interlocked_set(header: u64, first_bit: u32, count: u32) {
    change_range(header, first_bit, count, true, true)
}

pub fn test_bit(header: u64, bit: u32) -> u32 {
    (guest::read32(buffer(header) + (bit / 32) as u64 * 4) >> (bit & 31)) & 1
}

/// Sequência do estado desejado em [first, end), acumulando entre palavras.
fn find_run_within(words: u64, first_bit: u32, end_bit: u32, count: u32, set: bool) -> u32 {
    let mut current = first_bit;
    let mut run = 0u32;
    while current < end_bit {
        let offset = current & 31;
        let chunk = (32 - offset).min(end_bit - current);
        let mut blocking = guest::read32(words + (current / 32) as u64 * 4);
        if set {
            blocking = !blocking;
        }
        blocking >>= offset;
        let available = if blocking != 0 { chunk.min(blocking.trailing_zeros()) } else { chunk };
        run += available;
        if run >= count {
            return current + available - run;
        }
        current += available;
        if available < chunk {
            current += 1;
            run = 0;
        }
    }
    NO_MATCH
}

/// Procura a partir da dica e volta ao início se preciso; pode inverter os
/// bits encontrados.
fn find_run(header: u64, count: u32, hint: u32, set: bool, update: bool) -> u32 {
    let size = guest::read32(header);
    let hint = if hint >= size { 0 } else { hint };
    // Busca vazia: a dica arredondada para baixo ao limite de um byte.
    if count == 0 {
        return hint & !7;
    }
    if count > size {
        return NO_MATCH;
    }
    let words = buffer(header);
    let mut found = find_run_within(words, hint, size, count, set);
    if found == NO_MATCH && hint != 0 {
        found = find_run_within(words, 0, size.min(hint.saturating_add(count)), count, set);
    }
    if found != NO_MATCH && update {
        change_range(header, found, count, !set, false);
    }
    found
}

pub fn find_clear(header: u64, count: u32, hint: u32) -> u32 {
    find_run(header, count, hint, false, false)
}

pub fn find_set(header: u64, count: u32, hint: u32) -> u32 {
    find_run(header, count, hint, true, false)
}

pub fn find_clear_and_set(header: u64, count: u32, hint: u32) -> u32 {
    find_run(header, count, hint, false, true)
}

pub fn find_set_and_clear(header: u64, count: u32, hint: u32) -> u32 {
    find_run(header, count, hint, true, true)
}

fn contains(header: u64, first_bit: u32, count: u32, set: bool) -> u32 {
    if count == 0 || first_bit as u64 + count as u64 > guest::read32(header) as u64 {
        return 0;
    }
    (find_run_within(buffer(header), first_bit, first_bit + count, count, set) == first_bit) as u32
}

pub fn are_clear(header: u64, first_bit: u32, count: u32) -> u32 {
    contains(header, first_bit, count, false)
}

pub fn are_set(header: u64, first_bit: u32, count: u32) -> u32 {
    contains(header, first_bit, count, true)
}

/// Bits ligados, mascarando a sobra da última palavra.
pub fn number_set(header: u64) -> u32 {
    let mut remaining = guest::read32(header);
    let mut pointer = buffer(header);
    let mut total = 0;
    while remaining != 0 {
        let chunk = remaining.min(32);
        total += (guest::read32(pointer) & (NO_MATCH >> (32 - chunk))).count_ones();
        pointer += 4;
        remaining -= chunk;
    }
    total
}

pub fn number_clear(header: u64) -> u32 {
    guest::read32(header) - number_set(header)
}

/// Reserva cada palavra por CAS só enquanto os bits pedidos estão livres; em
/// conflito, desfaz exatamente o prefixo reservado por esta chamada.
pub fn reserve_clear_run(header: u64, first_bit: u32, count: u32) -> u32 {
    let mut pointer = buffer(header) + (first_bit / 32) as u64 * 4;
    let mut offset = first_bit & 31;
    let mut reserved = 0u32;
    while reserved < count {
        let chunk = (count - reserved).min(32 - offset);
        let requested = mask(offset, chunk);
        let mut previous = guest::read32(pointer);
        loop {
            if previous & requested != 0 {
                if reserved != 0 {
                    change_range(header, first_bit, reserved, false, true);
                }
                return 0;
            }
            let observed = guest::compare_exchange32(pointer, previous, previous | requested).unwrap_or(previous);
            if observed == previous {
                break;
            }
            previous = observed;
        }
        reserved += chunk;
        pointer += 4;
        offset = 0;
    }
    1
}

/// RtlFindLeastSignificantBit: índice do bit 1 mais baixo, -1 se a máscara
/// for zero (CCHAR).
pub fn find_least_significant_bit(set: u64) -> i8 {
    if set == 0 { -1 } else { set.trailing_zeros() as i8 }
}

// ---- RtlFindNextForwardRunClear, RtlNumberOfSetBitsUlongPtr,
// ---- RtlFindMostSignificantBit (rtl-bit-ops) -------------------------------

/// Avança `index` enquanto os bits valem `set`, saltando palavras ULONG
/// inteiras quando alinhado (como os laços de palavra do original).
fn skip_run(words: u64, mut index: u32, limit: u32, set: bool) -> u32 {
    let full = if set { u32::MAX } else { 0 };
    while index < limit {
        let word = guest::read32(words + (index / 32) as u64 * 4);
        if index % 32 == 0 && limit - index >= 32 && word == full {
            index += 32;
            continue;
        }
        if ((word >> (index % 32)) & 1 != 0) != set {
            break;
        }
        index += 1;
    }
    index
}

/// RtlFindNextForwardRunClear(BitMap, FromIndex, StartingRunIndex*): o
/// primeiro bit livre em/após FromIndex vai para *StartingRunIndex e o
/// retorno é o comprimento do run livre, limitado por SizeOfBitMap.
/// FromIndex >= SizeOfBitMap devolve 0 com *StartingRunIndex = FromIndex;
/// sem bit livre, *StartingRunIndex = SizeOfBitMap.
pub fn find_next_forward_run_clear(header: u64, from: u32, start_out: u64) -> u32 {
    let size = guest::read32(header);
    if from >= size {
        guest::write32(start_out, from);
        return 0;
    }
    let start = skip_run(buffer(header), from, size, true);
    let end = skip_run(buffer(header), start, size, false);
    guest::write32(start_out, start);
    end - start
}

/// RtlNumberOfSetBitsUlongPtr(Target): popcount de 64 bits.
pub fn number_of_set_bits_ulong_ptr(target: u64) -> u32 {
    target.count_ones()
}

/// RtlFindMostSignificantBit(Set): índice do bit 1 mais alto, -1 se a
/// máscara for zero (CCHAR; o original devolve EAX = 0xFFFFFFFF).
pub fn find_most_significant_bit(set: u64) -> i8 {
    if set == 0 { -1 } else { (63 - set.leading_zeros()) as i8 }
}
