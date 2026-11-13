//! Mapping Control Block (MCB) — o mapa VBN -> LBN que os file systems
//! guardam por stream, como no FsRtl do NT. Este assunto implementa o
//! BASE_MCB sobre a memória do convidado; o LARGE_MCB do NT é só
//! `{ PKGUARDED_MUTEX GuardedMutex; BASE_MCB BaseMcb; }` (BaseMcb em +8), e as
//! rotinas *LargeMcb* são estas mesmas sob o mutex.
//!
//! Comportamento do ntoskrnl 10.0.19045, verificado contra o próprio código do
//! ntoskrnl executado num emulador (as mesmas sequências aleatórias de
//! operações dão os mesmos retornos, saídas, pares e alocações):
//!   FsRtlInitializeBaseMcbEx 0x202c10   FsRtlUninitializeBaseMcb 0x2f60c0
//!   FsRtlResetBaseMcb 0x32b890          FsRtlNumberOfRunsInBaseMcb 0x26e9c0
//!   FsRtlAddBaseMcbEntryEx 0x2f5910     FsRtlAddBaseMcbEntry 0x2f58f0
//!   FsRtlRemoveBaseMcbEntry 0x2f5540    FsRtlTruncateBaseMcb 0x2f5430
//!   FsRtlLookupBaseMcbEntry 0x2eedc0    FsRtlLookupLastBaseMcbEntry 0x2ff730
//!   FsRtlLookupLastBaseMcbEntryAndIndex 0x31c1b0
//!   FsRtlGetNextBaseMcbEntry 0x2fa390
//!   internas: FsRtlAddEntry 0x2f5e64, FsRtlFindLargeIndex 0x2f5f9c,
//!   FsRtlRemoveLargeEntry 0x2f6028.
//!
//! Layout: `BASE_MCB` (ntifs.h) é `inc::types::extra_fs_ntfs::BaseMcb`
//! (MaximumPairCount, PairCount, PoolType, Flags com bit 0 =
//! RAISE_ON_ALLOCATION_FAILURE, Mapping); `Mapping` aponta para os pares
//! internos `Mapping` deste arquivo, 8 bytes { ULONG NextVbn; ULONG Lbn; }.
//! O par i cobre os VBNs [NextVbn(i-1), NextVbn(i)) (o par 0 começa em 0) e
//! começa no LBN `Lbn`, ou é um buraco (Lbn = 0xFFFFFFFF). O NT guarda os
//! pares em 32 bits: as APIs LONGLONG truncam VBN/LBN/contagem para 32 bits
//! e devolvem os valores estendidos com zero (ou com sinal, só para -1, onde
//! o NT o faz) — reproduzido aqui.
//!
//! Alocação: o NT tira o vetor inicial de 15 pares (0x78 bytes, tag 'FSim')
//! das listas lookaside FsRtlFirst{Paged,NonPaged}MappingLookasideList
//! (PoolType == PagedPool escolhe a paginada) e os vetores maiores do pool
//! (`ExAllocatePoolWithTag(PoolType, n*8, 'FSim')`). O OpenNT não tem essas
//! duas listas globais: o vetor de 15 pares vem do pool com o mesmo tamanho,
//! tag e tipo (PagedPool / NonPagedPool) — o cache da lookaside não é
//! observável pelo driver.

use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_fs_ntfs::BaseMcb;
use crate::ntos::inc::types::LargeInteger;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool;
use crate::ntos::rtl::exceptions;
use crate::rtl::KernelError;

/// MCB_FLAG_RAISE_ON_ALLOCATION_FAILURE.
pub const FLAG_RAISE_ON_ALLOCATION_FAILURE: u16 = 1;
/// Lbn de um buraco.
pub const UNUSED_LBN: u32 = 0xFFFF_FFFF;
/// Pares do vetor inicial (entrada da lookaside, 0x78 bytes).
const FIRST_PAIR_COUNT: u32 = 15;
const POOL_TAG: u32 = 0x6D69_5346; // 'FSim'
const PAGED_POOL: u32 = 1;
const NON_PAGED_POOL: u32 = 0;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Um par do vetor `Mapping` — o `MAPPING` interno do FsRtl do NT (não é
/// público no WDK; layout lido dos acessos `[Mapping + i*8]` / `+4` do
/// ntoskrnl): o fim exclusivo do trecho e o seu LBN inicial (ou UNUSED_LBN).
#[repr(C)]
struct Mapping {
    next_vbn: Field<u32>,
    lbn: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for Mapping {}

const _: () = {
    assert!(core::mem::size_of::<Mapping>() == 8);
    assert!(core::mem::offset_of!(Mapping, lbn) == 4);
};

// ---- acesso ao BASE_MCB ------------------------------------------------------

fn count(mcb: &BaseMcb) -> u32 {
    mcb.pair_count.get()
}

fn set_count(mcb: &BaseMcb, value: u32) {
    mcb.pair_count.set(value);
}

/// O par `index` do vetor `Mapping`.
fn pair(mcb: &BaseMcb, index: u32) -> &'static Mapping {
    // SAFETY: `Mapping` aponta para MaximumPairCount pares alocados por este
    // assunto e todo índice usado é < MaximumPairCount (como no NT).
    unsafe { Mapping::at(mcb.mapping.get() + index as u64 * Mapping::SIZE) }
}

/// NextVbn do par `index`.
fn pair_next(mcb: &BaseMcb, index: u32) -> u32 {
    pair(mcb, index).next_vbn.get()
}

/// Lbn do par `index`.
fn pair_lbn(mcb: &BaseMcb, index: u32) -> u32 {
    pair(mcb, index).lbn.get()
}

fn set_pair_next(mcb: &BaseMcb, index: u32, value: u32) {
    pair(mcb, index).next_vbn.set(value);
}

fn set_pair_lbn(mcb: &BaseMcb, index: u32, value: u32) {
    pair(mcb, index).lbn.set(value);
}

/// Primeiro VBN do par `index` (NextVbn do anterior; 0 no par 0).
fn start_vbn(mcb: &BaseMcb, index: u32) -> u32 {
    if index == 0 { 0 } else { pair_next(mcb, index - 1) }
}

/// LBN logo após o par `index` mapeado: Lbn - início + NextVbn (32 bits),
/// ou 0 se o par for um buraco — a mesma conta inline do NT.
fn end_lbn(mcb: &BaseMcb, index: u32) -> u32 {
    let lbn = pair_lbn(mcb, index);
    if lbn == UNUSED_LBN {
        return 0;
    }
    lbn.wrapping_sub(start_vbn(mcb, index)).wrapping_add(pair_next(mcb, index))
}

/// memmove de `pairs` pares (cópia em bloco; origem e destino podem se sobrepor).
fn move_pairs(destination: u64, source: u64, pairs: u32) {
    if pairs != 0 {
        let bytes = guest::read_bytes(source, pairs as usize * Mapping::SIZE as usize);
        guest::write_bytes(destination, &bytes);
    }
}

/// Vetor de 15 pares (a entrada da lookaside do NT): PagedPool para
/// PoolType == PagedPool, senão NonPagedPool.
fn allocate_first_mapping(pool: u16) -> Result<u64, KernelError> {
    let kind = if pool as u32 == PAGED_POOL { PAGED_POOL } else { NON_PAGED_POOL };
    pool_allocation::allocate_tagged(kind, FIRST_PAIR_COUNT as u64 * 8, POOL_TAG)
}

fn free_mapping(pointer: u64) -> Result<(), KernelError> {
    kernel_pool::free(pointer, Some(POOL_TAG))
}

/// RtlRaiseStatus(STATUS_INSUFFICIENT_RESOURCES): não retorna.
fn raise_insufficient_resources() -> Result<bool, KernelError> {
    exceptions::raise_status(STATUS_INSUFFICIENT_RESOURCES, 0, 0, 2)?;
    Err(KernelError::new("RtlRaiseStatus retornou"))
}

// ---- internas do MCB do FsRtl ------------------------------------------------

/// FsRtlFindLargeIndex: busca binária do par que contém `vbn`. Não
/// encontrado devolve (false, PairCount).
fn find_index(mcb: &BaseMcb, vbn: u32) -> (bool, u32) {
    let total = count(mcb);
    let (mut low, mut high) = (0i32, total as i32 - 1);
    while low <= high {
        let middle = (low + high) / 2;
        if middle != 0 && vbn < pair_next(mcb, middle as u32 - 1) {
            high = middle - 1;
        } else if vbn <= pair_next(mcb, middle as u32).wrapping_sub(1) {
            return (true, middle as u32);
        } else {
            low = middle + 1;
        }
    }
    (false, total)
}

/// FsRtlAddEntry: abre `amount` pares em `index`, ampliando o vetor (dobra
/// até 0x800 pares, depois +0x800). Falta de memória: exceção se o MCB tem
/// RAISE_ON_ALLOCATION_FAILURE, senão FALSE.
fn add_entry(mcb: &BaseMcb, index: u32, amount: u32) -> Result<bool, KernelError> {
    let total = count(mcb);
    let limit = mcb.maximum_pair_count.get();
    if total.wrapping_add(amount) > limit {
        let grown = if limit >= 0x800 { limit.wrapping_add(0x800) } else { limit.wrapping_mul(2) };
        let bytes = (grown as u64) << 3;
        let fresh = if bytes > 0xFFFF_FFFF { 0 } else { pool_allocation::allocate_tagged(mcb.pool_type.get() as u32, bytes & 0xFFFF_FFFF, POOL_TAG)? };
        if fresh == 0 {
            if mcb.flags.get() & FLAG_RAISE_ON_ALLOCATION_FAILURE != 0 {
                return raise_insufficient_resources();
            }
            return Ok(false);
        }
        move_pairs(fresh, mcb.mapping.get(), total);
        free_mapping(mcb.mapping.get())?;
        mcb.mapping.set(fresh);
        mcb.maximum_pair_count.set(grown);
    }
    let total = count(mcb);
    if index < total {
        let base = mcb.mapping.get();
        move_pairs(base + (index + amount) as u64 * Mapping::SIZE, base + index as u64 * Mapping::SIZE, total - index);
    }
    set_count(mcb, total.wrapping_add(amount));
    Ok(true)
}

/// FsRtlRemoveLargeEntry: fecha `amount` pares em `index`.
fn remove_entry(mcb: &BaseMcb, index: u32, amount: u32) {
    let total = count(mcb);
    let end = index.wrapping_add(amount);
    if end < total {
        let base = mcb.mapping.get();
        move_pairs(base + index as u64 * Mapping::SIZE, base + end as u64 * Mapping::SIZE, total - index - amount);
    }
    set_count(mcb, total.wrapping_sub(amount));
}

// ---- rotinas exportadas ------------------------------------------------------

/// FsRtlInitializeBaseMcbEx(Mcb, PoolType, Flags) -> BOOLEAN.
pub fn initialize(mcb: &BaseMcb, pool: u32, flags: u16) -> Result<bool, KernelError> {
    set_count(mcb, 0);
    mcb.pool_type.set(pool as u16);
    mcb.flags.set(flags);
    let first = allocate_first_mapping(pool as u16)?;
    mcb.mapping.set(first);
    if first == 0 {
        if flags & FLAG_RAISE_ON_ALLOCATION_FAILURE != 0 {
            return raise_insufficient_resources();
        }
        return Ok(false);
    }
    mcb.maximum_pair_count.set(FIRST_PAIR_COUNT);
    Ok(true)
}

/// FsRtlUninitializeBaseMcb: devolve o vetor de pares.
pub fn uninitialize(mcb: &BaseMcb) -> Result<(), KernelError> {
    free_mapping(mcb.mapping.get())
}

/// FsRtlResetBaseMcb: PairCount = 0 (o vetor fica).
pub fn reset(mcb: &BaseMcb) {
    set_count(mcb, 0);
}

/// FsRtlNumberOfRunsInBaseMcb: pares, buracos incluídos.
pub fn number_of_runs(mcb: &BaseMcb) -> u32 {
    count(mcb)
}

/// FsRtlAddBaseMcbEntryEx(Mcb, Vbn, Lbn, SectorCount) -> NTSTATUS. Um trecho
/// que já mapeia igual é aceito (aparado); conflito -> STATUS_UNSUCCESSFUL;
/// falta de memória -> STATUS_INSUFFICIENT_RESOURCES (ou exceção).
pub fn add_entry_ex(mcb: &BaseMcb, vbn: u64, lbn: u64, sector_count: u64) -> Result<u32, KernelError> {
    let (mut vbn, mut lbn, mut sectors) = (vbn as u32, lbn as u32, sector_count as u32);
    let pairs = count(mcb);
    let added = |ok: bool| if ok { STATUS_SUCCESS } else { STATUS_INSUFFICIENT_RESOURCES };

    // Pré-verificação: o início já está mapeado?
    let (found, index) = find_index(mcb, vbn);
    if found {
        let last_vbn = sectors.wrapping_sub(1).wrapping_add(vbn);
        let run_lbn = pair_lbn(mcb, index);
        if run_lbn != UNUSED_LBN {
            let start = start_vbn(mcb, index);
            if lbn != run_lbn.wrapping_sub(start).wrapping_add(vbn) {
                return Ok(STATUS_UNSUCCESSFUL);
            }
            let next = pair_next(mcb, index);
            if last_vbn <= next.wrapping_sub(1) {
                return Ok(STATUS_SUCCESS);
            }
            // Apara o prefixo idêntico e segue com o resto.
            let length = next.wrapping_sub(start);
            vbn = next;
            lbn = run_lbn.wrapping_add(length);
            sectors = last_vbn.wrapping_sub(vbn).wrapping_add(1);
        } else {
            // Começa num buraco e termina no par seguinte: aceito se o par
            // seguinte continua exatamente o mapeamento (sufixo aparado).
            let (end_found, end_index) = find_index(mcb, last_vbn);
            if end_found && index == end_index.wrapping_sub(1) {
                let boundary = if end_index == 0 { 0 } else { pair_next(mcb, end_index - 1) };
                if pair_lbn(mcb, end_index) != boundary.wrapping_sub(vbn).wrapping_add(lbn) {
                    return Ok(STATUS_UNSUCCESSFUL);
                }
                sectors = boundary.wrapping_sub(vbn);
            }
        }
    }

    // Inserção geral, com o PairCount lido na entrada.
    let mut at = pairs;
    if pairs != 0 && pair_next(mcb, pairs - 1) > vbn {
        let (inside, hole) = find_index(mcb, vbn);
        if !inside {
            at = hole;
        } else {
            return add_inside_hole(mcb, hole, pairs, vbn, lbn, sectors);
        }
    }

    // Depois do fim do mapa.
    if at != 0 && pair_next(mcb, at - 1) == vbn {
        let tail = at - 1;
        let continues = if pair_lbn(mcb, tail) == UNUSED_LBN { 0 } else { end_lbn(mcb, tail) };
        if continues == lbn {
            set_pair_next(mcb, pairs - 1, pair_next(mcb, pairs - 1).wrapping_add(sectors));
            return Ok(STATUS_SUCCESS);
        }
    }
    let previous_end = if at == 0 { 0 } else { pair_next(mcb, at - 1) };
    if vbn == 0 || previous_end == vbn {
        if !add_entry(mcb, at, 1)? {
            return Ok(added(false));
        }
        set_pair_lbn(mcb, at, lbn);
        set_pair_next(mcb, at, sectors.wrapping_add(vbn));
        return Ok(STATUS_SUCCESS);
    }
    // Lacuna até o fim atual: um buraco e o trecho novo.
    if !add_entry(mcb, at, 2)? {
        return Ok(added(false));
    }
    set_pair_lbn(mcb, at, UNUSED_LBN);
    set_pair_next(mcb, at, vbn);
    set_pair_lbn(mcb, at + 1, lbn);
    set_pair_next(mcb, at + 1, sectors.wrapping_add(vbn));
    Ok(STATUS_SUCCESS)
}

/// O trecho novo cai dentro do mapa: só pode ocupar (parte de) um buraco.
fn add_inside_hole(mcb: &BaseMcb, index: u32, pairs: u32, vbn: u32, lbn: u32, sectors: u32) -> Result<u32, KernelError> {
    let end = sectors.wrapping_add(vbn);
    let last_vbn = end.wrapping_sub(1);
    let added = |ok: bool| if ok { STATUS_SUCCESS } else { STATUS_INSUFFICIENT_RESOURCES };
    if pair_lbn(mcb, index) != UNUSED_LBN {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    if index != 0 && pair_next(mcb, index - 1) > vbn {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let hole_end = pair_next(mcb, index);
    if last_vbn > hole_end.wrapping_sub(1) {
        return Ok(STATUS_UNSUCCESSFUL);
    }
    let hole_start = start_vbn(mcb, index);
    let reaches_end = last_vbn >= hole_end.wrapping_sub(1);
    let next_lbn = |at: u32| if at >= pairs.wrapping_sub(1) { UNUSED_LBN } else { pair_lbn(mcb, at + 1) };

    if hole_start < vbn && !reaches_end {
        // No meio do buraco: buraco / trecho / buraco.
        if !add_entry(mcb, index, 2)? {
            return Ok(added(false));
        }
        set_pair_lbn(mcb, index, UNUSED_LBN);
        set_pair_next(mcb, index, vbn);
        set_pair_lbn(mcb, index + 1, lbn);
        set_pair_next(mcb, index + 1, end);
        return Ok(STATUS_SUCCESS);
    }
    if hole_start == vbn && !reaches_end {
        // No começo do buraco: estende o par anterior ou insere antes.
        let previous = if index == 0 { 0 } else { end_lbn(mcb, index - 1) };
        if previous != lbn {
            if !add_entry(mcb, index, 1)? {
                return Ok(added(false));
            }
            set_pair_lbn(mcb, index, lbn);
            set_pair_next(mcb, index, end);
            return Ok(STATUS_SUCCESS);
        }
        if index == 0 {
            if !add_entry(mcb, 0, 1)? {
                return Ok(added(false));
            }
            set_pair_lbn(mcb, 0, lbn);
            set_pair_next(mcb, 0, sectors);
            return Ok(STATUS_SUCCESS);
        }
        set_pair_next(mcb, index - 1, pair_next(mcb, index - 1).wrapping_add(sectors));
        return Ok(STATUS_SUCCESS);
    }
    if hole_start < vbn {
        // No fim do buraco: estende o par seguinte para trás ou insere.
        if next_lbn(index) != sectors.wrapping_add(lbn) {
            if !add_entry(mcb, index, 1)? {
                return Ok(added(false));
            }
            set_pair_lbn(mcb, index, UNUSED_LBN);
            set_pair_next(mcb, index, vbn);
            set_pair_lbn(mcb, index + 1, lbn);
            return Ok(STATUS_SUCCESS);
        }
        set_pair_next(mcb, index, vbn);
        set_pair_lbn(mcb, index + 1, lbn);
        return Ok(STATUS_SUCCESS);
    }

    // Preenche o buraco inteiro: funde com os vizinhos contíguos.
    let previous = if index == 0 { 0 } else { end_lbn(mcb, index - 1) };
    let next_continues = next_lbn(index) == sectors.wrapping_add(lbn);
    if previous == lbn && next_continues {
        if index == 0 {
            set_pair_lbn(mcb, 1, lbn);
            remove_entry(mcb, 0, 1);
        } else {
            set_pair_next(mcb, index - 1, pair_next(mcb, index + 1));
            remove_entry(mcb, index, 2);
        }
        return Ok(STATUS_SUCCESS);
    }
    if next_continues {
        set_pair_lbn(mcb, index + 1, lbn);
        remove_entry(mcb, index, 1);
        return Ok(STATUS_SUCCESS);
    }
    if index != 0 && end_lbn(mcb, index - 1) == lbn {
        set_pair_next(mcb, index - 1, hole_end);
        remove_entry(mcb, index, 1);
        return Ok(STATUS_SUCCESS);
    }
    set_pair_lbn(mcb, index, lbn);
    Ok(STATUS_SUCCESS)
}

/// FsRtlAddBaseMcbEntry: NT_SUCCESS(FsRtlAddBaseMcbEntryEx(...)).
pub fn add_entry_boolean(mcb: &BaseMcb, vbn: u64, lbn: u64, sector_count: u64) -> Result<bool, KernelError> {
    Ok(add_entry_ex(mcb, vbn, lbn, sector_count)? as i32 >= 0)
}

/// FsRtlRemoveBaseMcbEntry(Mcb, Vbn, SectorCount) -> BOOLEAN: transforma o
/// trecho em buraco (aparando o fim do mapa). FALSE só por falta de memória.
pub fn remove(mcb: &BaseMcb, vbn: u64, sector_count: u64) -> Result<bool, KernelError> {
    let (mut vbn, mut remaining) = (vbn, sector_count as i64);
    if vbn == 0 {
        let pairs = count(mcb);
        if pairs != 0 && remaining >= pair_next(mcb, pairs - 1) as i64 {
            set_count(mcb, 0);
            return Ok(true);
        }
    }
    // O "fim LBN" calculado inline (0 também conta como buraco, como no NT).
    let is_hole_like = |at: u32| pair_lbn(mcb, at) == UNUSED_LBN || end_lbn(mcb, at) == 0;
    while remaining > 0 {
        let (found, index) = find_index(mcb, vbn as u32);
        if !found {
            break;
        }
        let pairs = count(mcb);
        let start = start_vbn(mcb, index) as u64;
        let next = pair_next(mcb, index);
        let end = vbn.wrapping_add(remaining as u64);
        let last = next.wrapping_sub(1) as u64 as i64;
        if start == vbn && last < end as i64 {
            // O trecho cobre o par inteiro.
            let length = next.wrapping_sub(start as u32) as u64;
            vbn = vbn.wrapping_add(length);
            remaining = remaining.wrapping_sub(length as i64);
            if pair_lbn(mcb, index) == UNUSED_LBN {
                continue;
            }
            if index == pairs - 1 {
                // Último par: some; um buraco antes dele também.
                if index != 0 && is_hole_like(index - 1) {
                    remove_entry(mcb, index - 1, 2);
                } else {
                    remove_entry(mcb, index, 1);
                }
                continue;
            }
            let previous_hole = index != 0 && is_hole_like(index - 1);
            let next_mapped = pair_lbn(mcb, index + 1) != UNUSED_LBN;
            match (previous_hole, next_mapped) {
                (false, true) => set_pair_lbn(mcb, index, UNUSED_LBN),
                (false, false) => remove_entry(mcb, index, 1),
                (true, true) => {
                    set_pair_lbn(mcb, index, UNUSED_LBN);
                    remove_entry(mcb, index - 1, 1);
                }
                (true, false) => remove_entry(mcb, index - 1, 2),
            }
            continue;
        }
        if start == vbn {
            // Começa no início do par e termina dentro dele.
            if pair_lbn(mcb, index) == UNUSED_LBN {
                return Ok(true);
            }
            let part = remaining as u32;
            if index != 0 && is_hole_like(index - 1) {
                set_pair_next(mcb, index - 1, pair_next(mcb, index - 1).wrapping_add(part));
                set_pair_lbn(mcb, index, pair_lbn(mcb, index).wrapping_add(part));
                return Ok(true);
            }
            if !add_entry(mcb, index, 1)? {
                return Ok(false);
            }
            set_pair_lbn(mcb, index, UNUSED_LBN);
            set_pair_next(mcb, index, (vbn as u32).wrapping_add(part));
            set_pair_lbn(mcb, index + 1, pair_lbn(mcb, index + 1).wrapping_add(part));
            return Ok(true);
        }
        // Começa dentro do par.
        let run_lbn = pair_lbn(mcb, index);
        if last >= end as i64 {
            // Termina antes do fim do par: abre um buraco no meio.
            if run_lbn == UNUSED_LBN {
                return Ok(true);
            }
            if !add_entry(mcb, index, 2)? {
                return Ok(false);
            }
            set_pair_lbn(mcb, index, pair_lbn(mcb, index + 2));
            set_pair_next(mcb, index, vbn as u32);
            set_pair_lbn(mcb, index + 1, UNUSED_LBN);
            set_pair_next(mcb, index + 1, end as u32);
            let skipped = pair_next(mcb, index + 1).wrapping_sub(start_vbn(mcb, index));
            set_pair_lbn(mcb, index + 2, pair_lbn(mcb, index + 2).wrapping_add(skipped));
            return Ok(true);
        }
        // Vai até o fim do par (ou além): apara a cauda do par.
        let cut = next.wrapping_sub(vbn as u32);
        if run_lbn != UNUSED_LBN {
            if index == pairs - 1 || pair_lbn(mcb, index + 1) == UNUSED_LBN {
                set_pair_next(mcb, index, next.wrapping_sub(cut));
            } else {
                if !add_entry(mcb, index + 1, 1)? {
                    return Ok(false);
                }
                set_pair_lbn(mcb, index + 1, UNUSED_LBN);
                set_pair_next(mcb, index + 1, pair_next(mcb, index));
                set_pair_next(mcb, index, pair_next(mcb, index).wrapping_sub(cut));
            }
        }
        vbn = vbn.wrapping_add(cut as u64);
        remaining = remaining.wrapping_sub(cut as i64);
    }
    Ok(true)
}

/// FsRtlTruncateBaseMcb(Mcb, Vbn): descarta tudo a partir de `Vbn` e
/// encolhe o vetor quando sobra menos de 1/4 (nunca abaixo de 15 pares;
/// falta de memória ao encolher só mantém o vetor).
pub fn truncate(mcb: &BaseMcb, vbn: u64) -> Result<(), KernelError> {
    let vbn = vbn as u32;
    if vbn == 0 {
        set_count(mcb, 0);
    } else if count(mcb) != 0 {
        let (found, index) = find_index(mcb, vbn - 1);
        if found {
            if pair_lbn(mcb, index) == UNUSED_LBN {
                set_count(mcb, index);
            } else {
                set_count(mcb, index + 1);
                if pair_next(mcb, index) > vbn {
                    set_pair_next(mcb, index, vbn);
                }
            }
        }
    }
    let limit = mcb.maximum_pair_count.get();
    let pairs = count(mcb);
    if pairs < limit >> 2 && limit > FIRST_PAIR_COUNT {
        let target = pairs.wrapping_mul(2).max(FIRST_PAIR_COUNT);
        let fresh = if target == FIRST_PAIR_COUNT {
            allocate_first_mapping(mcb.pool_type.get())?
        } else {
            pool_allocation::allocate_tagged(mcb.pool_type.get() as u32, (target as u64) << 3, POOL_TAG)?
        };
        if fresh != 0 {
            move_pairs(fresh, mcb.mapping.get(), pairs);
            free_mapping(mcb.mapping.get())?;
            mcb.mapping.set(fresh);
            mcb.maximum_pair_count.set(target);
        }
    }
    Ok(())
}

/// Saídas opcionais de FsRtlLookupBaseMcbEntry: endereços dos PLONGLONG /
/// PULONG do chamador (0 = não pedida).
pub struct LookupOutputs {
    pub lbn: u64,
    pub sector_count_from_lbn: u64,
    pub starting_lbn: u64,
    pub sector_count_from_starting_lbn: u64,
    pub index: u64,
}

/// Parâmetro de saída escalar do chamador (PLONGLONG/PULONG).
fn output<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: os exports do MCB recebem ponteiros de saída do driver
    // (memória do kernel), como o NT, que os escreve sem sondar.
    unsafe { Field::<T>::at(address) }
}

/// Parâmetro de saída LONGLONG gravado em metades, como o NT o grava.
fn large_output(address: u64) -> &'static LargeInteger {
    // SAFETY: idem `output`.
    unsafe { LargeInteger::at(address) }
}

fn lbn_as_large(value: u32) -> u64 {
    if value == UNUSED_LBN { u64::MAX } else { value as u64 }
}

/// Parte alta que o NT põe sob uma parte baixa de 32 bits: -1 só sob -1.
fn high_part(low: u32) -> i32 {
    if low != UNUSED_LBN { 0 } else { -1 }
}

/// FsRtlLookupBaseMcbEntry: TRUE se `vbn` está dentro do mapa (num buraco o
/// LBN é -1); FALSE além do fim, sem escrever nada.
pub fn lookup(mcb: &BaseMcb, vbn: u64, outputs: &LookupOutputs) -> bool {
    let vbn = vbn as u32;
    let (found, index) = find_index(mcb, vbn);
    if !found {
        return false;
    }
    let start = start_vbn(mcb, index);
    let next = pair_next(mcb, index);
    let run_lbn = pair_lbn(mcb, index);
    if outputs.lbn != 0 {
        let value = if run_lbn == UNUSED_LBN { u64::MAX } else { run_lbn.wrapping_sub(start).wrapping_add(vbn) as u64 };
        output::<u64>(outputs.lbn).set(value);
    }
    if outputs.sector_count_from_lbn != 0 {
        output::<u64>(outputs.sector_count_from_lbn).set(next.wrapping_sub(vbn) as u64);
    }
    if outputs.starting_lbn != 0 {
        output::<u64>(outputs.starting_lbn).set(lbn_as_large(run_lbn));
    }
    if outputs.sector_count_from_starting_lbn != 0 {
        output::<u64>(outputs.sector_count_from_starting_lbn).set(next.wrapping_sub(start) as u64);
    }
    if outputs.index != 0 {
        output::<u32>(outputs.index).set(index);
    }
    true
}

/// FsRtlLookupLastBaseMcbEntry(Mcb, *Vbn, *Lbn): último VBN mapeado e o seu
/// LBN. Num buraco final o NT grava 0x00000000FFFFFFFF (estendido com zero).
pub fn lookup_last(mcb: &BaseMcb, vbn_out: u64, lbn_out: u64) -> bool {
    let pairs = count(mcb);
    if pairs == 0 {
        return false;
    }
    let last = pairs - 1;
    let run_lbn = pair_lbn(mcb, last);
    let value = if run_lbn == UNUSED_LBN { UNUSED_LBN } else { run_lbn.wrapping_sub(start_vbn(mcb, last)).wrapping_add(pair_next(mcb, last).wrapping_sub(1)) };
    output::<u64>(lbn_out).set(value as u64);
    output::<u64>(vbn_out).set(pair_next(mcb, last).wrapping_sub(1) as u64);
    true
}

/// FsRtlLookupLastBaseMcbEntryAndIndex(Mcb, *Vbn, *Lbn, *Index). As partes
/// baixas são gravadas em 32 bits e, sempre (mesmo com o MCB vazio, sobre o
/// que já estava lá), a parte alta vira -1 se a baixa for -1, senão 0.
pub fn lookup_last_and_index(mcb: &BaseMcb, vbn_out: u64, lbn_out: u64, index_out: u64) -> bool {
    let (vbn, lbn) = (large_output(vbn_out), large_output(lbn_out));
    let pairs = count(mcb);
    let mut found = false;
    if pairs != 0 {
        let last = pairs - 1;
        let run_lbn = pair_lbn(mcb, last);
        let low = if run_lbn == UNUSED_LBN { UNUSED_LBN } else { pair_next(mcb, last).wrapping_sub(1).wrapping_add(run_lbn.wrapping_sub(start_vbn(mcb, last))) };
        lbn.low_part.set(low);
        vbn.low_part.set(pair_next(mcb, last).wrapping_sub(1));
        output::<u32>(index_out).set(last);
        found = true;
    }
    vbn.high_part.set(high_part(vbn.low_part.get()));
    lbn.high_part.set(high_part(lbn.low_part.get()));
    found
}

/// FsRtlGetNextBaseMcbEntry(Mcb, RunIndex, *Vbn, *Lbn, *SectorCount): o par
/// `RunIndex` (buracos têm Lbn = -1).
pub fn get_next_entry(mcb: &BaseMcb, run_index: u32, vbn_out: u64, lbn_out: u64, sector_count_out: u64) -> bool {
    if run_index >= count(mcb) {
        return false;
    }
    let (vbn, lbn) = (large_output(vbn_out), large_output(lbn_out));
    let start = start_vbn(mcb, run_index);
    vbn.low_part.set(start);
    vbn.high_part.set(high_part(start));
    let run_lbn = pair_lbn(mcb, run_index);
    lbn.low_part.set(run_lbn);
    lbn.high_part.set(high_part(run_lbn));
    output::<u64>(sector_count_out).set(pair_next(mcb, run_index).wrapping_sub(start) as u64);
    true
}

/// Pares atuais (NextVbn, Lbn), para diagnóstico e autoteste.
pub fn pairs(mcb: &BaseMcb) -> Vec<(u32, u32)> {
    (0..count(mcb)).map(|index| (pair_next(mcb, index), pair_lbn(mcb, index))).collect()
}
