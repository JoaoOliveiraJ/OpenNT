//! GENERAL_LOOKASIDE x64.
//!
//! Armazenamento e vínculos nativos; o descritor pertence ao cliente. As
//! macros inline dos drivers chamam `Allocate`/`Free` diretamente, então os
//! callbacks padrão são os endereços dos exports ExAllocatePoolWithTag e
//! ExFreePool, entregues pelo provedor de exports (fase 6).

use alloc::collections::BTreeMap;

use super::{pool_allocation, slist};
use crate::hal::amd64::native_call;
use crate::ntos::ke::{clock, irql};
use crate::ntos::mm::page_residency::{self, FaultResult, Provider};
use crate::ntos::mm::{kernel_pool, pfn};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::lookaside_list as layout;

const MINIMUM_DEPTH: u16 = 4;
const MAXIMUM_DEPTH: u16 = 256;

struct State {
    lists: BTreeMap<u64, bool>,
    registry_heads: [u64; 2],
    kernel_provider: Option<fn(&str) -> Option<u64>>,
    pressure_registered: bool,
    last_adjustment_ms: u64,
}

static STATE: SpinLock<State> = SpinLock::new(State { lists: BTreeMap::new(), registry_heads: [0; 2], kernel_provider: None, pressure_registered: false, last_adjustment_ms: 0 });

/// Endereços públicos dos exports, instalados depois da montagem do PE.
pub fn register_kernel_provider(provider: fn(&str) -> Option<u64>) -> Result<(), KernelError> {
    let mut state = STATE.lock();
    if state.kernel_provider.is_some_and(|current| current as usize != provider as usize) {
        return Err(KernelError::new("lookaside kernel provider already registered"));
    }
    state.kernel_provider = Some(provider);
    Ok(())
}

fn exported_callback(name: &str) -> Result<u64, KernelError> {
    let provider = STATE.lock().kernel_provider.ok_or_else(|| KernelError::new("lookaside callbacks unavailable"))?;
    provider(name).filter(|&address| address != 0).ok_or_else(|| KernelError::new(alloc::format!("lookaside callback export missing: {name}")))
}

/// CAS32 conserva incrementos concorrentes das macros nativas.
fn increment(address: u64) {
    let mut expected = guest::read32(address);
    loop {
        let observed = guest::compare_exchange32(address, expected, expected.wrapping_add(1)).unwrap_or(expected.wrapping_add(1));
        if observed == expected {
            return;
        }
        expected = observed;
    }
}

fn check_irql(address: u64) -> Result<(), KernelError> {
    let paged = guest::read32(address + layout::POOL_TYPE) & 1 != 0;
    if irql::get_irql() > if paged { 1 } else { 2 } {
        return Err(KernelError::new("lookaside operation at invalid IRQL"));
    }
    Ok(())
}

/// Cabeçalho permanente da cadeia de cada categoria.
fn registry_for(paged: bool) -> Result<u64, KernelError> {
    let index = paged as usize;
    let existing = STATE.lock().registry_heads[index];
    if existing != 0 {
        return Ok(existing);
    }
    let head = guest::alloc_bytes(16);
    if head == 0 {
        return Err(KernelError::new("lookaside registry allocation failed"));
    }
    guest::write64(head, head);
    guest::write64(head + 8, head);
    STATE.lock().registry_heads[index] = head;
    Ok(head)
}

fn reclaim_provider(frames: u64) -> Result<u64, KernelError> {
    Ok(reclaim(frames))
}

/// ExInitialize(N)PagedLookasideList.
#[allow(clippy::too_many_arguments)]
pub fn initialize(list: u64, allocate_routine: u64, free_routine: u64, flags: u32, block_size: u64, tag: u32, paged: bool) -> Result<(), KernelError> {
    let head = registry_for(paged)?;
    let entry = list + layout::REGISTRY_ENTRY;
    let allocate_callback = if allocate_routine != 0 { allocate_routine } else { exported_callback("ExAllocatePoolWithTag")? };
    // PFREE_FUNCTION tem um argumento: ExFreePool libera sem exigir tag.
    let free_callback = if free_routine != 0 { free_routine } else { exported_callback("ExFreePool")? };
    if irql::get_irql() > 2 {
        return Err(KernelError::new("lookaside initialization at invalid IRQL"));
    }
    if STATE.lock().lists.contains_key(&list) {
        return Err(KernelError::new("lookaside initialized twice"));
    }
    slist::initialize(list)?;
    guest::write16(list + layout::DEPTH, MINIMUM_DEPTH);
    guest::write16(list + layout::MAXIMUM_DEPTH, MAXIMUM_DEPTH);
    guest::write64(list + layout::ALLOC_COUNT, 0);
    guest::write64(list + layout::FREE_COUNT, 0);
    guest::write32(list + layout::POOL_TYPE, flags | paged as u32);
    guest::write32(list + layout::TAG, tag);
    // O parâmetro é SIZE_T, mas o campo persistente Size é ULONG.
    guest::write32(list + layout::BLOCK_SIZE, block_size as u32);
    guest::write64(list + layout::ALLOCATE_CALLBACK, allocate_callback);
    guest::write64(list + layout::FREE_CALLBACK, free_callback);
    guest::write64(list + layout::LAST_ALLOC_COUNT, 0);
    let tail = guest::read64(head + 8);
    if guest::read64(tail) != head {
        return Err(KernelError::new("corrupt lookaside registry"));
    }
    guest::write64(entry, head);
    guest::write64(entry + 8, tail);
    guest::write64(tail, entry);
    guest::write64(head + 8, entry);
    let register = {
        let mut state = STATE.lock();
        state.lists.insert(list, paged);
        let first = !state.pressure_registered;
        if first {
            state.pressure_registered = true;
            state.last_adjustment_ms = clock::uptime_ms();
        }
        first
    };
    if register {
        // O pool já cuida das traduções; o cache só devolve blocos livres.
        page_residency::register(
            "lookaside caches",
            Provider { fault: |_, _| FaultResult::NotMine, resolve: |_| Ok(None), reclaim: reclaim_provider, prepare: || Ok(()), resolve_range: None },
        )?;
    }
    Ok(())
}

/// ExInitializeLookasideListEx(List, AllocateEx, FreeEx, PoolType, Flags,
/// Size, Tag, Depth). O PoolType vira o campo Type (+0x24) e escolhe o
/// registro paginado/não paginado pelo bit 0; AllocateEx/FreeEx nulos
/// recebem ExAllocatePoolWithTag/ExFreePool (feito dentro de `initialize`,
/// como nas listas não-Ex). Flags e Depth não têm efeito persistente aqui.
pub fn initialize_ex(list: u64, allocate_routine: u64, free_routine: u64, pool_type: u32, block_size: u64, tag: u32) -> Result<(), KernelError> {
    initialize(list, allocate_routine, free_routine, pool_type, block_size, tag, pool_type & 1 != 0)
}

/// A primeira falta chama o alocador verdadeiro; uma entrada do cache
/// conserva o endereço.
pub fn allocate(list: u64) -> Result<u64, KernelError> {
    check_irql(list)?;
    increment(list + layout::ALLOC_COUNT);
    let entry = slist::pop(list)?;
    if entry != 0 {
        return Ok(entry);
    }
    increment(list + layout::ALLOC_MISSES);
    let callback = guest::read64(list + layout::ALLOCATE_CALLBACK);
    let pool_type = guest::read32(list + layout::POOL_TYPE);
    let size = guest::read32(list + layout::BLOCK_SIZE);
    let tag = guest::read32(list + layout::TAG);
    if exported_callback("ExAllocatePoolWithTag").ok() == Some(callback) {
        return pool_allocation::allocate_tagged(pool_type, size as u64, tag);
    }
    Ok(native_call::call(callback, &[pool_type as u64, size as u64, tag as u64]))
}

/// A entrada já saiu do cache antes do callback (reentrância sem dupla
/// liberação).
fn release_entry(list: u64, block: u64) -> Result<(), KernelError> {
    let callback = guest::read64(list + layout::FREE_CALLBACK);
    if exported_callback("ExFreePool").ok() == Some(callback) {
        kernel_pool::free(block, None)
    } else {
        native_call::call(callback, &[block]);
        Ok(())
    }
}

pub fn free(list: u64, block: u64) -> Result<(), KernelError> {
    check_irql(list)?;
    increment(list + layout::FREE_COUNT);
    if slist::depth(list) >= guest::read16(list + layout::DEPTH) {
        increment(list + layout::FREE_MISSES);
        release_entry(list, block)
    } else {
        slist::push(list, block).map(|_| ())
    }
}

/// Excluir libera só o cache; um bloco emprestado vive até ser devolvido, e
/// com Depth zero a devolução vai direto ao liberador.
pub fn delete(list: u64) -> Result<(), KernelError> {
    check_irql(list)?;
    if !STATE.lock().lists.contains_key(&list) {
        return Err(KernelError::new("lookaside is not registered"));
    }
    let entry = list + layout::REGISTRY_ENTRY;
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("corrupt lookaside registry links"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    STATE.lock().lists.remove(&list);
    guest::write16(list + layout::DEPTH, 0);
    guest::write64(entry, 0);
    let mut block = slist::flush(list)?;
    while block != 0 {
        let following = guest::read64(block);
        release_entry(list, block)?;
        block = following;
    }
    Ok(())
}

/// ExpComputeLookasideDepth: ajusta o cache pelas alocações e faltas desde
/// a última amostra.
fn adjust_depth(list: u64, intervals: u64) {
    let total = guest::read32(list + layout::ALLOC_COUNT);
    let misses = guest::read32(list + layout::ALLOC_MISSES);
    let allocations = total.wrapping_sub(guest::read32(list + layout::LAST_ALLOC_COUNT));
    let allocation_misses = misses.wrapping_sub(guest::read32(list + layout::LAST_ALLOC_MISSES));
    let maximum = guest::read16(list + layout::MAXIMUM_DEPTH) as i64;
    let mut depth = guest::read16(list + layout::DEPTH) as i64;
    guest::write32(list + layout::LAST_ALLOC_COUNT, total);
    guest::write32(list + layout::LAST_ALLOC_MISSES, misses);
    if maximum == 65535 {
        return;
    }
    if (allocations as u64) < intervals * 25 {
        depth -= 10;
    } else {
        let miss_rate = (allocation_misses as i64 * 1000) / allocations as i64;
        if miss_rate < 5 {
            depth -= 1;
        } else {
            depth = maximum.min(depth + 30.min(5 + ((maximum - depth) * miss_rate) / 1000));
        }
    }
    guest::write16(list + layout::DEPTH, depth.max(MINIMUM_DEPTH as i64) as u16);
}

/// Manutenção periódica (uma amostra por segundo, até APC_LEVEL).
pub fn maintain() {
    if irql::get_irql() > 1 {
        return;
    }
    let (lists, intervals) = {
        let mut state = STATE.lock();
        if state.lists.is_empty() {
            return;
        }
        let now = clock::uptime_ms();
        let intervals = (now - state.last_adjustment_ms) / 1000;
        if intervals < 1 {
            return;
        }
        state.last_adjustment_ms = now;
        (state.lists.keys().copied().collect::<alloc::vec::Vec<_>>(), intervals)
    };
    for list in lists {
        adjust_depth(list, intervals);
    }
}

/// Devolve só entradas livres e mede os PFNs efetivamente liberados.
pub fn reclaim(requested: u64) -> u64 {
    let initial = pfn::free_count();
    let gained = || pfn::free_count().saturating_sub(initial);
    let lists: alloc::vec::Vec<u64> = STATE.lock().lists.keys().copied().collect();
    for list in lists {
        while gained() < requested {
            let Ok(entry) = slist::pop(list) else { break };
            if entry == 0 || release_entry(list, entry).is_err() {
                break;
            }
        }
        if gained() >= requested {
            break;
        }
    }
    gained()
}

pub fn registered_count() -> usize {
    STATE.lock().lists.len()
}
