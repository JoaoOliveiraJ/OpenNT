//! Conjuntos de processadores de vários grupos (KAFFINITY_EX) e a
//! enumeração dos processadores de um conjunto, como as rotinas do ntoskrnl
//! 19041 que os drivers de energia do processador (processr.sys,
//! amdppm.sys, intelppm.sys) importam.
//!
//! KAFFINITY_EX = {Count, Size, Reserved, Bitmap[20]}: Count é o número de
//! grupos em uso no Bitmap, Size a capacidade (0x14). Um índice de
//! processador vira (grupo, bit) pela KiProcessorIndexToNumberMappingTable;
//! no OpenNT (um grupo) o número de um processador é o próprio índice.
//! As rotinas confiam no chamador como o binário: nada além de Count é
//! conferido.

use super::{processor_group, smp};
use crate::ntos::inc::types::{Field, GroupAffinity, KaffinityEx, NtStruct};

/// KAFFINITY_EX.Size das inicializadas pelo kernel.
const AFFINITY_EX_SIZE: u16 = 0x14;
/// STATUS_NOT_FOUND.
const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// (grupo, bit) do índice pela KiProcessorIndexToNumberMappingTable.
fn group_and_bit(index: u32) -> (usize, u32) {
    ((index >> 6) as usize, index & 63)
}

/// KiProcessorNumberToIndexMappingTable[grupo * 64 + bit].
fn index_of(group: u16, bit: u32) -> u32 {
    ((group as u32) << 6) + bit
}

fn word(affinity: &KaffinityEx, group: usize) -> &Field<u64> {
    &affinity.bitmap[group.min(affinity.bitmap.len() - 1)]
}

/// KeInitializeAffinityEx: Count 1, Size 0x14 e o Bitmap zerado.
pub fn initialize(affinity: &KaffinityEx) {
    affinity.count.set(1);
    affinity.size.set(AFFINITY_EX_SIZE);
    affinity.reserved.set(0);
    for cell in &affinity.bitmap {
        cell.set(0);
    }
}

/// KeAddProcessorAffinityEx: liga o bit do processador, crescendo Count até
/// o grupo dele.
pub fn add_processor(affinity: &KaffinityEx, index: u32) {
    let (group, bit) = group_and_bit(index);
    if affinity.count.get() as usize <= group {
        affinity.count.set(group as u16 + 1);
    }
    let cell = word(affinity, group);
    cell.set(cell.get() | 1u64 << bit);
}

/// KeRemoveProcessorAffinityEx: desliga o bit, se o grupo está em uso.
pub fn remove_processor(affinity: &KaffinityEx, index: u32) {
    let (group, bit) = group_and_bit(index);
    if (affinity.count.get() as usize) > group {
        let cell = word(affinity, group);
        cell.set(cell.get() & !(1u64 << bit));
    }
}

/// KeCheckProcessorAffinityEx: o bit do processador (sem olhar Count).
pub fn check_processor(affinity: &KaffinityEx, index: u32) -> bool {
    let (group, bit) = group_and_bit(index);
    (word(affinity, group).get() >> bit) & 1 != 0
}

/// Os grupos em uso.
fn used(affinity: &KaffinityEx) -> usize {
    (affinity.count.get() as usize).min(affinity.bitmap.len())
}

/// KeIsEmptyAffinityEx: nenhum bit nos grupos em uso.
pub fn is_empty(affinity: &KaffinityEx) -> bool {
    affinity.bitmap[..used(affinity)].iter().all(|cell| cell.get() == 0)
}

/// KeIsEqualAffinityEx: os grupos comuns iguais e os excedentes do maior
/// conjunto vazios.
pub fn is_equal(first: &KaffinityEx, second: &KaffinityEx) -> bool {
    let (shorter, longer) = if used(first) >= used(second) { (used(second), first) } else { (used(first), second) };
    (0..shorter).all(|group| first.bitmap[group].get() == second.bitmap[group].get()) && longer.bitmap[shorter..used(longer)].iter().all(|cell| cell.get() == 0)
}

/// KeCopyAffinityEx: Count, Size e os grupos em uso da origem; Reserved 0.
pub fn copy(destination: &KaffinityEx, source: &KaffinityEx) {
    destination.count.set(source.count.get());
    destination.size.set(source.size.get());
    destination.reserved.set(0);
    for group in 0..used(source) {
        destination.bitmap[group].set(source.bitmap[group].get());
    }
}

/// O resultado de KeOrAffinityEx/KeAndAffinityEx: grava Count, os grupos e
/// (com destino) Reserved 0, Size 0x14 e os grupos além de Count zerados.
fn combine(result: Option<&KaffinityEx>, count: usize, value: impl Fn(usize) -> u64) -> bool {
    let mut any = false;
    for group in 0..count {
        let bits = value(group);
        any |= bits != 0;
        if let Some(result) = result {
            result.bitmap[group].set(bits);
        }
    }
    if let Some(result) = result {
        result.count.set(count as u16);
        result.reserved.set(0);
        result.size.set(AFFINITY_EX_SIZE);
        for cell in &result.bitmap[count..] {
            cell.set(0);
        }
    }
    any
}

/// KeOrAffinityEx(A, B, Result opcional): a união com Count do maior; devolve
/// se ficou algum bit.
pub fn or(first: &KaffinityEx, second: &KaffinityEx, result: Option<&KaffinityEx>) -> bool {
    let (common, longer) = if used(first) >= used(second) { (used(second), first) } else { (used(first), second) };
    let first_bits: alloc::vec::Vec<u64> = first.bitmap[..used(first)].iter().map(|cell| cell.get()).collect();
    let second_bits: alloc::vec::Vec<u64> = second.bitmap[..used(second)].iter().map(|cell| cell.get()).collect();
    let longer_bits: alloc::vec::Vec<u64> = longer.bitmap[..used(longer)].iter().map(|cell| cell.get()).collect();
    combine(result, used(longer), |group| if group < common { first_bits[group] | second_bits[group] } else { longer_bits[group] })
}

/// KeAndAffinityEx(A, B, Result opcional): a interseção com Count do menor;
/// devolve se ficou algum bit.
pub fn and(first: &KaffinityEx, second: &KaffinityEx, result: Option<&KaffinityEx>) -> bool {
    let count = used(first).min(used(second));
    let bits: alloc::vec::Vec<u64> = (0..count).map(|group| first.bitmap[group].get() & second.bitmap[group].get()).collect();
    combine(result, count, |group| bits[group])
}

/// KeAddGroupAffinityEx(Affinity, Group, Mask).
pub fn add_group(affinity: &KaffinityEx, group: u16, mask: u64) {
    if affinity.count.get() <= group {
        affinity.count.set(group + 1);
    }
    let cell = word(affinity, group as usize);
    cell.set(cell.get() | mask);
}

/// KeCountSetBitsAffinityEx: os processadores dos grupos em uso.
pub fn count_set_bits(affinity: &KaffinityEx) -> u32 {
    affinity.bitmap[..used(affinity)].iter().map(|cell| cell.get().count_ones()).sum()
}

/// KeFindFirstSetLeftGroupAffinity: o índice do processador do bit mais
/// alto, ou 0xFFFFFFFF sem bits.
pub fn find_first_set_left(affinity: &GroupAffinity) -> u32 {
    let mask = affinity.mask.get();
    if mask == 0 {
        return u32::MAX;
    }
    index_of(affinity.group.get(), 63 - mask.leading_zeros())
}

/// KeQueryActiveProcessorAffinity: KeActiveProcessors (um grupo, Size 0x14)
/// copiado pelo KeCopyAffinityEx e KeNumberProcessors devolvido.
pub fn query_active_processor_affinity(affinity: &KaffinityEx) -> u32 {
    affinity.count.set(1);
    affinity.size.set(AFFINITY_EX_SIZE);
    affinity.reserved.set(0);
    affinity.bitmap[0].set(processor_group::active_mask());
    smp::online_cpu_count() as u32
}

/// O contexto de enumeração: o conjunto (opcional), os bits que faltam no
/// grupo corrente e o grupo.
#[repr(C)]
pub struct EnumerationContext {
    pub affinity: Field<u64>,
    pub remaining: Field<u64>,
    pub group: Field<u16>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EnumerationContext {}

const _: () = {
    assert!(core::mem::offset_of!(EnumerationContext, remaining) == 8);
    assert!(core::mem::offset_of!(EnumerationContext, group) == 0x10);
};

/// KeEnumerateNextProcessor(Index, Context): o processador do bit mais baixo
/// que falta no grupo corrente; acabado o grupo, os do seguinte (sem
/// conjunto, só o grupo corrente). Sem mais nenhum, STATUS_NOT_FOUND.
pub fn enumerate_next(index: &Field<u32>, context: &EnumerationContext) -> u32 {
    let set = context.affinity.get();
    // SAFETY: o KAFFINITY_EX do contexto do chamador.
    let affinity = (set != 0).then(|| unsafe { KaffinityEx::at(set) });
    let groups = affinity.map_or(context.group.get() as u32 + 1, |affinity| affinity.count.get() as u32);
    loop {
        let remaining = context.remaining.get();
        if remaining != 0 {
            let bit = remaining.trailing_zeros();
            context.remaining.set(remaining & !(1u64 << bit));
            index.set(index_of(context.group.get(), bit));
            return 0;
        }
        let group = context.group.get().wrapping_add(1);
        context.group.set(group);
        if group as u32 >= groups {
            return STATUS_NOT_FOUND;
        }
        if let Some(affinity) = affinity {
            context.remaining.set(word(affinity, group as usize).get());
        }
    }
}
