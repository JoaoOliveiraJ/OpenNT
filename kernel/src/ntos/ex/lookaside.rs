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
use core::sync::atomic::Ordering;

use super::list_entry;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{GeneralLookaside, ListEntry, PoolType, SlistEntry};
use crate::ntos::mm::guest_memory as guest;

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

/// O descritor do chamador: NPAGED/PAGED_LOOKASIDE_LIST.L ou
/// LOOKASIDE_LIST_EX.L (GENERAL_LOOKASIDE_POOL, mesmos offsets até 0x60).
fn lookaside(list: u64) -> &'static GeneralLookaside {
    // SAFETY: os exports recebem o descritor do chamador.
    unsafe { GeneralLookaside::at(list) }
}

/// LOCK XADD: conserva incrementos concorrentes das macros nativas.
fn increment(counter: &Field<u32>) {
    counter.atomic().fetch_add(1, Ordering::SeqCst);
}

fn check_irql(list: &GeneralLookaside) -> Result<(), KernelError> {
    let paged = list.type_.get().0 & 1 != 0;
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
    let head = guest::alloc_bytes(ListEntry::SIZE);
    if head == 0 {
        return Err(KernelError::new("lookaside registry allocation failed"));
    }
    list_entry::initialize(list_entry::at(head));
    STATE.lock().registry_heads[index] = head;
    Ok(head)
}

fn reclaim_provider(frames: u64) -> Result<u64, KernelError> {
    Ok(reclaim(frames))
}

/// ExInitialize(N)PagedLookasideList.
#[allow(clippy::too_many_arguments)]
pub fn initialize(list: u64, allocate_routine: u64, free_routine: u64, flags: u32, block_size: u64, tag: u32, paged: bool) -> Result<(), KernelError> {
    let head = list_entry::at(registry_for(paged)?);
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
    let descriptor = lookaside(list);
    descriptor.depth.set(MINIMUM_DEPTH);
    descriptor.maximum_depth.set(MAXIMUM_DEPTH);
    descriptor.total_allocates.set(0);
    descriptor.allocate_misses.set(0);
    descriptor.total_frees.set(0);
    descriptor.free_misses.set(0);
    descriptor.type_.set(PoolType((flags | paged as u32) as i32));
    descriptor.tag.set(tag);
    // O parâmetro é SIZE_T, mas o campo persistente Size é ULONG.
    descriptor.size.set(block_size as u32);
    descriptor.allocate_ex.set(allocate_callback);
    descriptor.free_ex.set(free_callback);
    descriptor.last_total_allocates.set(0);
    descriptor.last_allocate_misses.set(0);
    if !list_entry::tail_consistent(head) {
        return Err(KernelError::new("corrupt lookaside registry"));
    }
    list_entry::insert_tail(head, &descriptor.list_entry);
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
    let descriptor = lookaside(list);
    check_irql(descriptor)?;
    increment(&descriptor.total_allocates);
    let entry = slist::pop(list)?;
    if entry != 0 {
        return Ok(entry);
    }
    increment(&descriptor.allocate_misses);
    let callback = descriptor.allocate_ex.get();
    let pool_type = descriptor.type_.get().0 as u32;
    let size = descriptor.size.get();
    let tag = descriptor.tag.get();
    if exported_callback("ExAllocatePoolWithTag").ok() == Some(callback) {
        return pool_allocation::allocate_tagged(pool_type, size as u64, tag);
    }
    Ok(native_call::call(callback, &[pool_type as u64, size as u64, tag as u64]))
}

/// A entrada já saiu do cache antes do callback (reentrância sem dupla
/// liberação).
fn release_entry(list: u64, block: u64) -> Result<(), KernelError> {
    let callback = lookaside(list).free_ex.get();
    if exported_callback("ExFreePool").ok() == Some(callback) {
        kernel_pool::free(block, None)
    } else {
        native_call::call(callback, &[block]);
        Ok(())
    }
}

pub fn free(list: u64, block: u64) -> Result<(), KernelError> {
    let descriptor = lookaside(list);
    check_irql(descriptor)?;
    increment(&descriptor.total_frees);
    if slist::depth(list) >= descriptor.depth.get() {
        increment(&descriptor.free_misses);
        release_entry(list, block)
    } else {
        slist::push(list, block).map(|_| ())
    }
}

/// Excluir libera só o cache; um bloco emprestado vive até ser devolvido, e
/// com Depth zero a devolução vai direto ao liberador.
pub fn delete(list: u64) -> Result<(), KernelError> {
    let descriptor = lookaside(list);
    check_irql(descriptor)?;
    if !STATE.lock().lists.contains_key(&list) {
        return Err(KernelError::new("lookaside is not registered"));
    }
    if list_entry::remove(&descriptor.list_entry).is_none() {
        return Err(KernelError::new("corrupt lookaside registry links"));
    }
    STATE.lock().lists.remove(&list);
    descriptor.depth.set(0);
    descriptor.list_entry.flink.set(0);
    let mut block = slist::flush(list)?;
    while block != 0 {
        // SAFETY: os blocos livres do cache começam pela SLIST_ENTRY.
        let following = unsafe { SlistEntry::at(block) }.next.get();
        release_entry(list, block)?;
        block = following;
    }
    Ok(())
}

/// ExpComputeLookasideDepth: ajusta o cache pelas alocações e faltas desde
/// a última amostra.
fn adjust_depth(list: u64, intervals: u64) {
    let descriptor = lookaside(list);
    let total = descriptor.total_allocates.get();
    let misses = descriptor.allocate_misses.get();
    let allocations = total.wrapping_sub(descriptor.last_total_allocates.get());
    let allocation_misses = misses.wrapping_sub(descriptor.last_allocate_misses.get());
    let maximum = descriptor.maximum_depth.get() as i64;
    let mut depth = descriptor.depth.get() as i64;
    descriptor.last_total_allocates.set(total);
    descriptor.last_allocate_misses.set(misses);
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
    descriptor.depth.set(depth.max(MINIMUM_DEPTH as i64) as u16);
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
