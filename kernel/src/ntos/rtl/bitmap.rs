//! RTL_BITMAP.
//!
//! SizeOfBitMap (32 bits) em +0 e Buffer (64 bits) em +8; índices e
//! comprimentos em bits sobre palavras ULONG. As operações de intervalo
//! pressupõem limites e armazenamento válidos fornecidos pelo chamador.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{Field, NtStruct, RtlBitmap};

/// Índice sentinela nativo de busca sem resultado.
pub const NO_MATCH: u32 = 0xFFFF_FFFF;

/// PRTL_BITMAP do chamador.
fn bitmap(header: u64) -> &'static RtlBitmap {
    // SAFETY: cabeçalho vivo e alinhado do chamador.
    unsafe { RtlBitmap::at(header) }
}

fn size(header: u64) -> u32 {
    bitmap(header).size_of_bit_map.get()
}

fn buffer(header: u64) -> u64 {
    bitmap(header).buffer.get()
}

/// A palavra ULONG `index` do armazenamento do bitmap.
fn word(words: u64, index: u64) -> &'static Field<u32> {
    // SAFETY: Buffer do chamador cobre SizeOfBitMap bits em ULONGs alinhados.
    unsafe { Field::<u32>::at(words + index * 4) }
}

fn mask(first_bit: u32, count: u32) -> u32 {
    (NO_MATCH >> (32 - count)) << first_bit
}

/// RtlInitializeBitMap: não inicializa o conteúdo do buffer.
pub fn initialize(header: u64, words: u64, bit_count: u32) {
    bitmap(header).size_of_bit_map.set(bit_count);
    bitmap(header).buffer.set(words);
}

fn fill(header: u64, value: u32) {
    let words = (size(header) as u64).div_ceil(32);
    let pointer = buffer(header);
    for index in 0..words {
        word(pointer, index).set(value);
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
    let words = buffer(header);
    let mut index = (first_bit / 32) as u64;
    let mut offset = first_bit & 31;
    while count != 0 {
        let chunk = count.min(32 - offset);
        let requested = mask(offset, chunk);
        let cell = word(words, index);
        let mut previous = cell.get();
        loop {
            let updated = if set { previous | requested } else { previous & !requested };
            if !atomic {
                cell.set(updated);
                break;
            }
            match cell.atomic().compare_exchange(previous, updated, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        index += 1;
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
    (word(buffer(header), (bit / 32) as u64).get() >> (bit & 31)) & 1
}

/// Sequência do estado desejado em [first, end), acumulando entre palavras.
fn find_run_within(words: u64, first_bit: u32, end_bit: u32, count: u32, set: bool) -> u32 {
    let mut current = first_bit;
    let mut run = 0u32;
    while current < end_bit {
        let offset = current & 31;
        let chunk = (32 - offset).min(end_bit - current);
        let mut blocking = word(words, (current / 32) as u64).get();
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
    let size = size(header);
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
    if count == 0 || first_bit as u64 + count as u64 > size(header) as u64 {
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
    let mut remaining = size(header);
    let words = buffer(header);
    let mut index = 0;
    let mut total = 0;
    while remaining != 0 {
        let chunk = remaining.min(32);
        total += (word(words, index).get() & (NO_MATCH >> (32 - chunk))).count_ones();
        index += 1;
        remaining -= chunk;
    }
    total
}

pub fn number_clear(header: u64) -> u32 {
    size(header) - number_set(header)
}

/// Reserva cada palavra por CAS só enquanto os bits pedidos estão livres; em
/// conflito, desfaz exatamente o prefixo reservado por esta chamada.
pub fn reserve_clear_run(header: u64, first_bit: u32, count: u32) -> u32 {
    let words = buffer(header);
    let mut index = (first_bit / 32) as u64;
    let mut offset = first_bit & 31;
    let mut reserved = 0u32;
    while reserved < count {
        let chunk = (count - reserved).min(32 - offset);
        let requested = mask(offset, chunk);
        let cell = word(words, index);
        let mut previous = cell.get();
        loop {
            if previous & requested != 0 {
                if reserved != 0 {
                    change_range(header, first_bit, reserved, false, true);
                }
                return 0;
            }
            match cell.atomic().compare_exchange(previous, previous | requested, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => break,
                Err(observed) => previous = observed,
            }
        }
        reserved += chunk;
        index += 1;
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
        let value = word(words, (index / 32) as u64).get();
        if index % 32 == 0 && limit - index >= 32 && value == full {
            index += 32;
            continue;
        }
        if ((value >> (index % 32)) & 1 != 0) != set {
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
    let size = size(header);
    // SAFETY: PULONG StartingRunIndex do chamador.
    let start_out = unsafe { Field::<u32>::at(start_out) };
    if from >= size {
        start_out.set(from);
        return 0;
    }
    let start = skip_run(buffer(header), from, size, true);
    let end = skip_run(buffer(header), start, size, false);
    start_out.set(start);
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

// ---- RTL_BITMAP_EX ------------------------------------------------------------
//
// `_RTL_BITMAP_EX` (SizeOfBitMap ULONG64, Buffer PULONG64): índices e
// comprimentos de 64 bits sobre palavras ULONG64 (ntoskrnl 19041:
// RtlInitializeBitMapEx 0x32a2d0, RtlSetBitEx 0x30f430, RtlClearBitEx
// 0x313ad0, RtlTestBitEx 0x36d060, RtlFindClearBitsAndSetEx 0x3423e0).

/// Índice sentinela das buscas Ex sem resultado (ULONG64 -1).
pub const NO_MATCH_EX: u64 = u64::MAX;

/// A palavra ULONG64 `index` do armazenamento de um bitmap Ex.
fn word_ex(words: u64, index: u64) -> &'static Field<u64> {
    // SAFETY: Buffer do chamador cobre SizeOfBitMap bits em ULONG64s alinhados.
    unsafe { Field::<u64>::at(words.wrapping_add(index.wrapping_mul(8))) }
}

/// RtlInitializeBitMapEx: grava só o cabeçalho; o buffer não é tocado.
pub fn initialize_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, buffer: u64, size: u64) {
    bitmap.size_of_bit_map.set(size);
    bitmap.buffer.set(buffer);
}

/// Palavra do `bts/btr/bt qword [Buffer], rdx` do original: o índice de bit
/// é com sinal (palavra = Buffer + (bit >> 6) * 8, deslocamento aritmético).
fn bit_word_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, bit: u64) -> &'static Field<u64> {
    word_ex(bitmap.buffer.get(), ((bit as i64) >> 6) as u64)
}

/// RtlSetBitEx: `bts` sem lock (não atômico, como o original).
pub fn set_bit_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, bit: u64) {
    let cell = bit_word_ex(bitmap, bit);
    cell.set(cell.get() | 1 << (bit & 63));
}

/// RtlClearBitEx: `btr` sem lock.
pub fn clear_bit_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, bit: u64) {
    let cell = bit_word_ex(bitmap, bit);
    cell.set(cell.get() & !(1 << (bit & 63)));
}

/// RtlTestBitEx: BOOLEAN do `bt` (setb al).
pub fn test_bit_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, bit: u64) -> bool {
    (bit_word_ex(bitmap, bit).get() >> (bit & 63)) & 1 != 0
}

/// RtlSetBitsEx (interno da busca): liga [first, first + count), sem lock.
fn set_bits_ex(words: u64, first: u64, mut count: u64) {
    let mut index = first >> 6;
    let mut offset = first & 63;
    while count != 0 {
        let chunk = count.min(64 - offset);
        let cell = word_ex(words, index);
        cell.set(cell.get() | (u64::MAX >> (64 - chunk)) << offset);
        index += 1;
        offset = 0;
        count -= chunk;
    }
}

/// Primeiro run de `count` bits livres que começa em [lo, last - count + 1]:
/// o original recusa quando `last - lo + 1 < count` (sem sinal) e, varrendo
/// palavra a palavra, aceita o menor início cujo run cabe até `last`.
fn find_clear_run_ex(words: u64, lo: u64, last: u64, count: u64) -> u64 {
    if last.wrapping_sub(lo).wrapping_add(1) < count {
        return NO_MATCH_EX;
    }
    let mut current = lo;
    let mut run = 0u64;
    while current <= last {
        let offset = current & 63;
        let chunk = (64 - offset).min(last - current + 1);
        let blocking = word_ex(words, current >> 6).get() >> offset;
        let available = if blocking != 0 { chunk.min(blocking.trailing_zeros() as u64) } else { chunk };
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
    NO_MATCH_EX
}

/// RtlFindClearBitsAndSetEx(BitMapHeader, NumberToFind, HintIndex): a dica
/// fora do mapa vira 0; NumberToFind == 0 devolve a dica arredondada para
/// baixo a 8 bits; senão o primeiro run em [dica, Size-1] e, sem resultado
/// com dica != 0, uma segunda passada em [0, min(Number + Hint, Size) - 1].
/// O run encontrado é ligado (RtlSetBitsEx).
pub fn find_clear_bits_and_set_ex(bitmap: &crate::ntos::inc::types::RtlBitmapEx, count: u64, hint: u64) -> u64 {
    let size = bitmap.size_of_bit_map.get();
    let start = if hint < size { hint } else { 0 };
    if count == 0 {
        return start & !7;
    }
    let words = bitmap.buffer.get();
    let mut found = find_clear_run_ex(words, start, size.wrapping_sub(1), count);
    if found == NO_MATCH_EX && start != 0 {
        let last = count.wrapping_add(hint).min(size).wrapping_sub(1);
        found = find_clear_run_ex(words, 0, last, count);
    }
    if found != NO_MATCH_EX {
        set_bits_ex(words, found, count);
    }
    found
}

// ---- Faixas e runs livres (RtlNumberOf{Set,Clear}BitsInRange, RtlExtractBitMap,
// RtlFindClearRuns) ------------------------------------------------------------
//
// Comportamento do ntoskrnl 19045 (RtlNumberOfSetBitsInRange 0x587f90,
// RtlNumberOfClearBitsInRange 0x587dc0, RtlExtractBitMap 0x586ce0,
// RtlFindClearRuns 0x363fe0), conferido contra o mesmo código do ntdll.dll
// em milhares de bitmaps aleatórios. Os originais varrem bytes com tabelas
// (bits livres baixos/altos, maior run livre de um byte); aqui as mesmas
// grandezas são calculadas sobre o armazenamento copiado em bloco.

use crate::ntos::inc::types::extra_fs_ntfs::RtlBitmapRun;

/// Bits livres (0) contíguos a partir do bit 0 de um byte (tabela 0x1e8a0).
fn low_clear_bits(byte: u8) -> u32 {
    (byte as u32 | 0x100).trailing_zeros()
}

/// Bits livres contíguos a partir do bit 7 de um byte (tabela 0x1e7a0).
fn high_clear_bits(byte: u8) -> u32 {
    if byte == 0 { 8 } else { byte.leading_zeros() }
}

/// Maior run livre dentro de um byte (tabela 0x18580).
fn longest_clear_bits(byte: u8) -> u32 {
    let (mut best, mut current) = (0, 0);
    for bit in 0..8 {
        if (byte >> bit) & 1 != 0 {
            current = 0;
        } else {
            current += 1;
            best = best.max(current);
        }
    }
    best
}

/// Bytes do armazenamento do bitmap `[first_byte, first_byte + count)`.
fn storage_bytes(bitmap: &RtlBitmap, first_byte: u64, count: usize) -> alloc::vec::Vec<u8> {
    crate::ntos::mm::guest_memory::read_bytes(bitmap.buffer.get() + first_byte, count)
}

/// RtlNumberOfSetBitsInRange: ULONG -1 para início fora do mapa, faixa que
/// passa do fim ou comprimento zero.
pub fn number_set_in_range(bitmap: &RtlBitmap, start: u32, length: u32) -> u32 {
    let size = bitmap.size_of_bit_map.get();
    if start >= size || size - start < length || length == 0 {
        return NO_MATCH;
    }
    let end = start + length;
    let first = start / 8;
    let bytes = storage_bytes(bitmap, first as u64, ((end - 1) / 8 - first + 1) as usize);
    bytes
        .iter()
        .enumerate()
        .map(|(index, &byte)| {
            let byte_start = (first + index as u32) * 8;
            let low = start.saturating_sub(byte_start).min(8);
            let high = (end - byte_start).min(8);
            let mask = (((1u32 << high) - 1) & !((1u32 << low) - 1)) as u8;
            (byte & mask).count_ones()
        })
        .sum()
}

/// RtlNumberOfClearBitsInRange: Length menos os ligados (ou -1 do erro).
pub fn number_clear_in_range(bitmap: &RtlBitmap, start: u32, length: u32) -> u32 {
    match number_set_in_range(bitmap, start, length) {
        NO_MATCH => NO_MATCH,
        set => length - set,
    }
}

/// RtlExtractBitMap(Source, Destination, TargetBit, NumberOfBits): copia
/// min(NumberOfBits, Source.Size - TargetBit, Destination.Size) bits de
/// `TargetBit` para o bit 0 do destino; os demais bits do destino ficam.
pub fn extract(source: &RtlBitmap, destination: &RtlBitmap, target_bit: u32, bit_count: u32) {
    let available = source.size_of_bit_map.get().wrapping_sub(target_bit);
    let count = bit_count.min(available).min(destination.size_of_bit_map.get());
    if count == 0 {
        return;
    }
    let first = (target_bit / 8) as u64;
    let source_bytes = storage_bytes(source, first, ((target_bit as u64 + count as u64 - 1) / 8 - first + 1) as usize);
    let mut bytes = storage_bytes(destination, 0, count.div_ceil(8) as usize);
    let shift = target_bit % 8;
    for offset in 0..count {
        let from = shift + offset;
        let bit = (source_bytes[(from / 8) as usize] >> (from % 8)) & 1;
        let byte = &mut bytes[(offset / 8) as usize];
        *byte = (*byte & !(1 << (offset % 8))) | (bit << (offset % 8));
    }
    crate::ntos::mm::guest_memory::write_bytes(destination.buffer.get(), &bytes);
}

/// Estado do RtlFindClearRuns: os runs (StartingIndex, NumberOfBits) achados.
struct ClearRuns {
    runs: alloc::vec::Vec<(u32, u32)>,
    capacity: usize,
    longest: bool,
}

impl ClearRuns {
    fn full(&self) -> bool {
        self.runs.len() >= self.capacity
    }

    /// Comprimento do último run guardado (o menor, no modo dos mais longos).
    fn smallest(&self) -> u32 {
        self.runs.last().map_or(0, |run| run.1)
    }

    /// Inserção do original: anexa (ou ordena por comprimento decrescente,
    /// estável, descartando o último quando cheio).
    fn insert(&mut self, start: u32, length: u32) {
        if self.full() {
            self.runs.pop();
        }
        let mut index = self.runs.len();
        if self.longest {
            while index > 0 && self.runs[index - 1].1 < length {
                index -= 1;
            }
        }
        self.runs.insert(index, (start, length));
    }

    /// Fora do modo dos mais longos, o vetor cheio encerra a busca.
    fn stop(&self) -> bool {
        !self.longest && self.full()
    }
}

/// RtlFindClearRuns(BitMap, RunArray, SizeOfRunArray, LocateLongestRuns):
/// varre por bytes; o run que termina num byte entra antes dos runs internos
/// do byte, e esses em ordem de comprimento decrescente (o mais baixo primeiro
/// no empate). Devolve o número de runs escritos em RunArray.
///
/// Com SizeOfRunArray zero o original lê RunArray[-1] (acesso fora do vetor);
/// aqui nada é lido e o resultado é zero.
pub fn find_clear_runs(bitmap: &RtlBitmap, run_array: u64, capacity: u32, locate_longest: bool) -> u32 {
    if capacity == 0 {
        return 0;
    }
    let size = bitmap.size_of_bit_map.get();
    let byte_count = size.div_ceil(8) as usize;
    let bytes = if byte_count == 0 { alloc::vec::Vec::new() } else { storage_bytes(bitmap, 0, byte_count) };
    let mut state = ClearRuns { runs: alloc::vec::Vec::new(), capacity: capacity as usize, longest: locate_longest };
    let (mut run_start, mut run_length) = (0u32, 0u32);
    'scan: for (index, &raw) in bytes.iter().enumerate() {
        let bit = index as u32 * 8;
        let mut byte = raw;
        if index + 1 == byte_count && size % 8 != 0 {
            byte |= 0xFFu8 << (size % 8);
        }
        if byte == 0 {
            run_length += 8;
            continue;
        }
        run_length += low_clear_bits(byte);
        if run_length != 0 && !(state.full() && state.smallest() >= run_length) {
            state.insert(run_start, run_length);
            if state.stop() {
                break 'scan;
            }
        }
        let (high, low) = (high_clear_bits(byte), low_clear_bits(byte));
        run_start = bit + 8 - high;
        run_length = high;
        byte |= ((1u16 << low) - 1) as u8 | (0xFF00u16 >> high) as u8;
        while byte != 0xFF {
            let length = longest_clear_bits(byte);
            if state.full() && state.smallest() >= length {
                break;
            }
            let mut mask = ((1u16 << length) - 1) as u8;
            let mut offset = 0;
            while byte & mask != 0 {
                mask <<= 1;
                offset += 1;
            }
            state.insert(bit + offset, length);
            if state.stop() {
                break 'scan;
            }
            byte |= mask;
        }
    }
    if !state.stop() && run_length != 0 && !(state.full() && state.smallest() >= run_length) {
        state.insert(run_start, run_length);
    }
    // SAFETY: RTL_BITMAP_RUN RunArray[SizeOfRunArray] do chamador (não vazio).
    let output = unsafe { RtlBitmapRun::array_at(run_array, capacity as usize) };
    for (run, &(start, length)) in output.iter().zip(state.runs.iter()) {
        run.starting_index.set(start);
        run.number_of_bits.set(length);
    }
    state.runs.len() as u32
}
