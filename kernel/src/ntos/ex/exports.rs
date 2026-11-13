//! Exports Ex* (pool, mutexes, ERESOURCE, rundown, lookaside, SLIST, timers,
//! push locks, spin locks) — `system32/win32/ntoskrnl/ex.js`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::hal::cpu;
use crate::hal::amd64::native_call;
use crate::ntos::ex::{lookaside, pool_allocation, push_lock, resource, rundown, slist, spin_lock};
use crate::ntos::io::work_items;
use crate::ntos::ke::{dpc, fast_mutex, irql, timer};
use crate::ntos::mm::{data_pool, kernel_pool};
use crate::ntos::ps::previous_mode;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// EX_TIMER (0x100 bytes): KTIMER, KDPC interno, callback e contexto. O DPC
/// repassa (exTimer, context) ao PEXT_CALLBACK do driver.
mod ex_timer {
    pub const KTIMER: u64 = 0x00;
    pub const KDPC: u64 = 0x40;
    pub const CALLBACK: u64 = 0x80;
    pub const CONTEXT: u64 = 0x88;
    pub const STRUCT_SIZE: u64 = 0x100;
}

/// Tabela de extensões (ExRegisterExtension): o limite real é 512.
static EXTENSIONS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
/// Célula de ExEventObjectType: a IAT recebe o endereço da célula, que
/// aponta para o OBJECT_TYPE do evento.
static EVENT_OBJECT_TYPE: AtomicU64 = AtomicU64::new(0);
/// Gerador xorshift32 semeado no TSC (ExUuidCreate).
static IDENTIFIER_STATE: SpinLock<u32> = SpinLock::new(0);

fn event_object_type() -> u64 {
    let current = EVENT_OBJECT_TYPE.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let type_structure = guest::alloc_bytes(0x40);
    let cell = guest::alloc_bytes(8);
    guest::write64(cell, type_structure);
    match EVENT_OBJECT_TYPE.compare_exchange(0, cell, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => cell,
        Err(existing) => {
            guest::free_bytes(cell);
            guest::free_bytes(type_structure);
            existing
        }
    }
}

fn next_random32() -> u32 {
    let mut state = IDENTIFIER_STATE.lock();
    if *state == 0 {
        *state = match (cpu::rdtsc() as u32) ^ 0x9E37_79B9 {
            0 => 0x2545_F491,
            seed => seed,
        };
    }
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    *state
}

/// Duas saídas do gerador; os 64 bits saem exatos (o original passava por
/// Number e podia arredondar os bits baixos).
fn next_random64() -> u64 {
    let low = next_random32() as u64;
    low | (next_random32() as u64) << 32
}

/// Encaminha ao alocador dono: endereços baixos são da arena; a tag opcional
/// só é conferida pelo pool que guarda o metadado.
fn free_pool(pointer: u64, tag: u64) -> Result<u64, KernelError> {
    if pointer < 0xFFFF_0000_0000_0000 {
        guest::free_bytes(pointer);
    } else if data_pool::owns(pointer) {
        data_pool::free(pointer)?;
    } else if kernel_pool::owns(pointer) {
        kernel_pool::free(pointer, if tag == 0 { None } else { Some(tag as u32) })?;
    } else {
        guest::free_bytes(pointer);
    }
    Ok(0)
}

/// Spin lock legado com subida a DISPATCH_LEVEL.
fn lock_with_raise(lock: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(2);
    loop {
        if guest::read32(lock) == 0 {
            guest::write32(lock, 1);
            return previous;
        }
        core::hint::spin_loop();
    }
}

fn unlock_with_lower(lock: u64, previous: u8) {
    guest::write32(lock, 0);
    irql::lower_irql(previous as u64);
}

/// SINGLE_LIST com Depth em +8 e Sequence em +0xA (como o original).
fn push_entry(head: u64, entry: u64) -> u64 {
    let previous = guest::read64(head);
    guest::write64(entry, previous);
    guest::write64(head, entry);
    guest::write16(head + 8, guest::read16(head + 8).wrapping_add(1));
    guest::write16(head + 0xA, guest::read16(head + 0xA).wrapping_add(1));
    previous
}

fn pop_entry(head: u64) -> u64 {
    let first = guest::read64(head);
    if first == 0 {
        return 0;
    }
    guest::write64(head, guest::read64(first));
    guest::write16(head + 8, guest::read16(head + 8).wrapping_sub(1));
    first
}

/// DPC interno do EX_TIMER: o ponteiro recebido é o KDPC embutido.
fn ex_timer_dpc(dpc_pointer: u64, _context: u64, _first: u64, _second: u64) {
    let timer_pointer = dpc_pointer - ex_timer::KDPC;
    let callback = guest::read64(timer_pointer + ex_timer::CALLBACK);
    let context = guest::read64(timer_pointer + ex_timer::CONTEXT);
    native_call::call(callback, &[timer_pointer, context]);
}

fn ok<T>(result: Result<T, KernelError>) -> Result<u64, KernelError> {
    result.map(|_| 0)
}

// ---- pool ----------------------------------------------------------------

fn allocate_pool_with_tag(call: &Call) -> Result<u64, KernelError> {
    pool_allocation::allocate_tagged(call.arg(1) as u32, call.arg(2), call.arg(3) as u32)
}
fn free_pool_export(call: &Call) -> Result<u64, KernelError> {
    free_pool(call.arg(1), 0)
}
/// A tag fornecida não muda o caminho do kernel original.
fn free_pool_with_tag(call: &Call) -> Result<u64, KernelError> {
    free_pool(call.arg(1), 0)
}
/// POOL_FLAGS só escolhe paginado/não paginado; o pool do convidado é único.
fn allocate_pool2(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_bytes(call.arg(2)))
}
fn allocate_pool_zero(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_bytes(call.arg(2)))
}
fn allocate_pool_uninitialized(call: &Call) -> Result<u64, KernelError> {
    Ok(guest::alloc_raw(call.arg(2)))
}
fn free_pool2(call: &Call) -> Result<u64, KernelError> {
    free_pool(call.arg(1), call.arg(2))
}

// ---- fast mutex ----------------------------------------------------------

fn initialize_fast_mutex(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::initialize(call.arg(1));
    Ok(0)
}
fn acquire_fast_mutex(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::acquire(call.arg(1)))
}
fn try_to_acquire_fast_mutex(call: &Call) -> Result<u64, KernelError> {
    Ok(fast_mutex::try_acquire(call.arg(1))? as u64)
}
fn release_fast_mutex(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::release(call.arg(1)))
}
fn acquire_fast_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::acquire_unsafe(call.arg(1)))
}
fn release_fast_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::release_unsafe(call.arg(1)))
}

// ---- ERESOURCE -----------------------------------------------------------

fn initialize_resource(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::initialize(call.arg(1))? as u64)
}
fn acquire_resource_exclusive(call: &Call) -> Result<u64, KernelError> {
    resource::acquire_exclusive(call.arg(1), call.arg(2) & 0xFF != 0)
}
fn acquire_resource_shared(call: &Call) -> Result<u64, KernelError> {
    resource::acquire_shared(call.arg(1), call.arg(2) & 0xFF != 0)
}
fn release_resource(call: &Call) -> Result<u64, KernelError> {
    ok(resource::release(call.arg(1)))
}
fn is_resource_acquired_exclusive(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::is_acquired_exclusive(call.arg(1))? as u64)
}
fn is_resource_acquired_shared(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::is_acquired_shared(call.arg(1))? as u64)
}
fn convert_exclusive_to_shared(call: &Call) -> Result<u64, KernelError> {
    ok(resource::convert_exclusive_to_shared(call.arg(1)))
}
fn delete_resource(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::delete(call.arg(1))? as u64)
}
fn acquire_shared_starve_exclusive(call: &Call) -> Result<u64, KernelError> {
    resource::acquire_shared_starve_exclusive(call.arg(1), call.arg(2) & 0xFF != 0)
}
fn acquire_shared_wait_for_exclusive(call: &Call) -> Result<u64, KernelError> {
    resource::acquire_shared_wait_for_exclusive(call.arg(1), call.arg(2) & 0xFF != 0)
}
fn reinitialize_resource(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::reinitialize(call.arg(1))? as u64)
}
fn release_resource_for_thread(call: &Call) -> Result<u64, KernelError> {
    ok(resource::release_for_thread(call.arg(1), call.arg(2)))
}
fn shared_waiter_count(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::shared_waiters(call.arg(1)) as u64)
}
fn exclusive_waiter_count(call: &Call) -> Result<u64, KernelError> {
    Ok(resource::exclusive_waiters(call.arg(1)) as u64)
}
fn enter_critical_region_and_acquire_exclusive(call: &Call) -> Result<u64, KernelError> {
    resource::enter_exclusive(call.arg(1))
}
fn enter_critical_region_and_acquire_shared(call: &Call) -> Result<u64, KernelError> {
    resource::enter_shared(call.arg(1))
}
fn release_resource_and_leave_critical_region(call: &Call) -> Result<u64, KernelError> {
    ok(resource::release_and_leave(call.arg(1)))
}

// ---- rundown -------------------------------------------------------------

fn initialize_rundown(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::initialize(call.arg(1)))
}
fn acquire_rundown(call: &Call) -> Result<u64, KernelError> {
    Ok(rundown::acquire(call.arg(1))? as u64)
}
fn release_rundown(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::release(call.arg(1)))
}
fn rundown_completed(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::completed(call.arg(1)))
}
fn size_of_rundown_cache_aware(_: &Call) -> Result<u64, KernelError> {
    Ok(rundown::size_cache())
}
fn allocate_cache_aware_rundown(call: &Call) -> Result<u64, KernelError> {
    rundown::allocate_cache(call.arg(1) as u32, call.arg(2) as u32)
}
fn initialize_rundown_cache_aware(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::initialize_cache(call.arg(1), call.arg(2) as u32))
}
fn acquire_rundown_cache_aware(call: &Call) -> Result<u64, KernelError> {
    Ok(rundown::acquire_cache(call.arg(1), 1)? as u64)
}
fn release_rundown_cache_aware(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::release_cache(call.arg(1), 1))
}
fn wait_rundown_cache_aware(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::wait_cache(call.arg(1)))
}
fn reinitialize_rundown_cache_aware(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::reinitialize_cache(call.arg(1)))
}
fn free_cache_aware_rundown(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::free_cache(call.arg(1)))
}
fn acquire_rundown_cache_aware_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(rundown::acquire_cache(call.arg(1), call.arg(2) as u32)? as u64)
}
fn release_rundown_cache_aware_ex(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::release_cache(call.arg(1), call.arg(2) as u32))
}
fn wait_rundown_release(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::wait(call.arg(1)))
}
fn acquire_rundown_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(rundown::acquire_ex(call.arg(1), call.arg(2) as u32)? as u64)
}
fn release_rundown_ex(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::release_ex(call.arg(1), call.arg(2) as u32))
}
fn reinitialize_rundown(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::reinitialize(call.arg(1)))
}
fn rundown_completed_cache_aware(call: &Call) -> Result<u64, KernelError> {
    ok(rundown::completed_cache(call.arg(1)))
}

// ---- lookaside -----------------------------------------------------------

fn initialize_paged_lookaside(call: &Call) -> Result<u64, KernelError> {
    ok(lookaside::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, true))
}
fn allocate_from_lookaside(call: &Call) -> Result<u64, KernelError> {
    lookaside::allocate(call.arg(1))
}
fn free_to_lookaside(call: &Call) -> Result<u64, KernelError> {
    ok(lookaside::free(call.arg(1), call.arg(2)))
}
fn delete_lookaside(call: &Call) -> Result<u64, KernelError> {
    ok(lookaside::delete(call.arg(1)))
}
fn initialize_nonpaged_lookaside(call: &Call) -> Result<u64, KernelError> {
    ok(lookaside::initialize(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, false))
}

// ---- diversos ------------------------------------------------------------

fn get_previous_mode(_: &Call) -> Result<u64, KernelError> {
    Ok(previous_mode::get()? as u64)
}
/// WORK_QUEUE_ITEM: a rotina recebe só o contexto (modelo Ex).
fn initialize_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::initialize_ex_work_item(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
fn queue_work_item(call: &Call) -> Result<u64, KernelError> {
    work_items::queue_ex_work_item(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
/// API legada: sobe a DISPATCH_LEVEL e adquire por test-and-set.
fn acquire_spin_lock(call: &Call) -> Result<u64, KernelError> {
    let previous = lock_with_raise(call.arg(1));
    guest::write32(call.arg(2), previous as u32);
    Ok(0)
}
fn release_spin_lock(call: &Call) -> Result<u64, KernelError> {
    unlock_with_lower(call.arg(1), call.arg(2) as u8);
    Ok(0)
}

// ---- SLIST ---------------------------------------------------------------

fn initialize_slist_head(call: &Call) -> Result<u64, KernelError> {
    ok(slist::initialize(call.arg(1)))
}
fn interlocked_push_entry_slist(call: &Call) -> Result<u64, KernelError> {
    slist::push(call.arg(1), call.arg(2))
}
fn interlocked_pop_entry_slist(call: &Call) -> Result<u64, KernelError> {
    slist::pop(call.arg(1))
}
fn interlocked_flush_slist(call: &Call) -> Result<u64, KernelError> {
    slist::flush(call.arg(1))
}
fn query_depth_slist(call: &Call) -> Result<u64, KernelError> {
    Ok(slist::depth(call.arg(1)) as u64)
}
fn interlocked_push_entry_list(call: &Call) -> Result<u64, KernelError> {
    let previous_irql = lock_with_raise(call.arg(3));
    let previous = push_entry(call.arg(1), call.arg(2));
    unlock_with_lower(call.arg(3), previous_irql);
    Ok(previous)
}
fn interlocked_pop_entry_list(call: &Call) -> Result<u64, KernelError> {
    let previous_irql = lock_with_raise(call.arg(2));
    let removed = pop_entry(call.arg(1));
    unlock_with_lower(call.arg(2), previous_irql);
    Ok(removed)
}

// ---- EX_TIMER ------------------------------------------------------------

fn allocate_timer(call: &Call) -> Result<u64, KernelError> {
    let timer_pointer = guest::alloc_bytes(ex_timer::STRUCT_SIZE);
    if timer_pointer == 0 {
        return Ok(0);
    }
    timer::initialize_timer(timer_pointer + ex_timer::KTIMER, 0);
    guest::write64(timer_pointer + ex_timer::CALLBACK, call.arg(1));
    guest::write64(timer_pointer + ex_timer::CONTEXT, call.arg(2));
    // O KDPC embutido identifica o EX_TIMER que guarda rotina e contexto.
    dpc::initialize_kernel_dpc(timer_pointer + ex_timer::KDPC, ex_timer_dpc, 0);
    Ok(timer_pointer)
}
/// ExSetTimer(timer, dueTime, periodMs, parameters): o período dos
/// parâmetros, quando não nulo, prevalece.
fn set_timer(call: &Call) -> Result<u64, KernelError> {
    let timer_pointer = call.arg(1);
    let mut period = call.arg(3) as u32;
    if call.arg(4) != 0 {
        let parameter_period = guest::read32(call.arg(4));
        if parameter_period != 0 {
            period = parameter_period;
        }
    }
    Ok(timer::set_timer(timer_pointer + ex_timer::KTIMER, call.arg(2) as i64, timer_pointer + ex_timer::KDPC, period) as u64)
}
fn cancel_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::cancel_timer(call.arg(1) + ex_timer::KTIMER) as u64)
}
fn delete_timer(call: &Call) -> Result<u64, KernelError> {
    let was_queued = call.arg(2) != 0 && timer::cancel_timer(call.arg(1) + ex_timer::KTIMER);
    guest::free_bytes(call.arg(1));
    Ok(was_queued as u64)
}

/// UUID versão 4 com variante DCE.
fn uuid_create(call: &Call) -> Result<u64, KernelError> {
    let pointer = call.arg(1);
    let low = next_random64();
    let high = next_random64();
    guest::write64(pointer, low);
    guest::write64(pointer + 8, high);
    guest::write8(pointer + 6, (guest::read8(pointer + 6) & 0x0F) | 0x40);
    guest::write8(pointer + 8, (guest::read8(pointer + 8) & 0x3F) | 0x80);
    Ok(0)
}
/// O banco de regras do Error Management está vazio: STATUS_NOT_FOUND.
fn em_client_query_rule_state(_: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(0xC000_0225))
}

// ---- push locks ----------------------------------------------------------

fn initialize_push_lock(call: &Call) -> Result<u64, KernelError> {
    push_lock::initialize(call.arg(1));
    Ok(0)
}
fn acquire_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    ok(push_lock::acquire_exclusive(call.arg(1), call.arg(2) as u32))
}
fn release_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    ok(push_lock::release_exclusive(call.arg(1), call.arg(2) as u32))
}
fn acquire_push_lock_shared(call: &Call) -> Result<u64, KernelError> {
    ok(push_lock::acquire_shared(call.arg(1), call.arg(2) as u32))
}
fn release_push_lock_shared(call: &Call) -> Result<u64, KernelError> {
    ok(push_lock::release_shared(call.arg(1), call.arg(2) as u32))
}
fn release_push_lock(call: &Call) -> Result<u64, KernelError> {
    ok(push_lock::release_any(call.arg(1), call.arg(2) as u32))
}
fn try_acquire_push_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    Ok(push_lock::try_exclusive(call.arg(1), call.arg(2) as u32)? as u64)
}
fn try_acquire_push_lock_shared(call: &Call) -> Result<u64, KernelError> {
    Ok(push_lock::try_shared(call.arg(1), call.arg(2) as u32)? as u64)
}
fn convert_push_lock_exclusive_to_shared(call: &Call) -> Result<u64, KernelError> {
    push_lock::convert_exclusive_to_shared(call.arg(1));
    Ok(0)
}

/// EX_EXTENSION_REGISTRATION (InfoVersion @0, ExtensionVersion @2,
/// FunctionTable @8) numa tabela de até 512 extensões.
fn register_extension(call: &Call) -> Result<u64, KernelError> {
    let mut table = EXTENSIONS.lock();
    if table.len() >= 512 {
        return Ok(signed_status(0xC000_009A));
    }
    let record = guest::alloc_bytes(0x10);
    if record == 0 {
        return Ok(signed_status(0xC000_009A));
    }
    guest::write16(record, call.arg(2) as u16);
    guest::write16(record + 2, 0);
    guest::write64(record + 8, call.arg(3));
    table.push(record);
    drop(table);
    guest::write64(call.arg(1), record);
    Ok(0)
}

/// UTC para a hora local do runtime: sem fuso configurado o deslocamento é
/// zero (o `getTimezoneOffset` do runtime original também devolvia 0).
fn system_time_to_local_time(call: &Call) -> Result<u64, KernelError> {
    const TIMEZONE_OFFSET_MINUTES: i64 = 0;
    let universal = guest::read64(call.arg(1)) as i64;
    let local = universal - TIMEZONE_OFFSET_MINUTES * 60 * 10_000_000;
    guest::write64(call.arg(2), local as u64);
    Ok(0)
}

// ---- spin locks executivos -----------------------------------------------

fn try_acquire_spin_lock_exclusive_at_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_acquire_exclusive_at_dpc(call.arg(1))? as u64)
}
fn try_acquire_spin_lock_shared_at_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_acquire_shared_at_dpc(call.arg(1))? as u64)
}

pub static TRY_SPIN_LOCKS_GROUP: Group = Group {
    name: "ex-try-spin-locks",
    names: &["ExTryAcquireSpinLockExclusiveAtDpcLevel", "ExTryAcquireSpinLockSharedAtDpcLevel"],
    handlers: &[try_acquire_spin_lock_exclusive_at_dpc, try_acquire_spin_lock_shared_at_dpc],
    data_exports: &[],
};

fn acquire_spin_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_exclusive(call.arg(1)) as u64)
}
fn acquire_spin_lock_shared(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_shared(call.arg(1)) as u64)
}
fn acquire_spin_lock_exclusive_at_dpc(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::acquire_exclusive_at_dpc(call.arg(1)))
}
fn acquire_spin_lock_shared_at_dpc(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::acquire_shared_at_dpc(call.arg(1)))
}
fn release_spin_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::release_exclusive(call.arg(1), call.arg(2) as u8))
}
fn release_spin_lock_shared(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::release_shared(call.arg(1), call.arg(2) as u8))
}
fn release_spin_lock_exclusive_from_dpc(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::release_exclusive_from_dpc(call.arg(1)))
}
fn release_spin_lock_shared_from_dpc(call: &Call) -> Result<u64, KernelError> {
    ok(spin_lock::release_shared_from_dpc(call.arg(1)))
}
fn try_convert_shared_spin_lock_exclusive(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_convert(call.arg(1))? as u64)
}

fn event_object_type_address() -> u64 {
    event_object_type()
}

pub static GROUP: Group = Group {
    name: "ex",
    names: &[
        "ExAllocatePoolWithTag", "ExFreePool", "ExFreePoolWithTag", "ExAllocatePool2", "ExAllocatePoolZero", "ExAllocatePoolUninitialized", "ExFreePool2",
        "ExInitializeFastMutex", "ExAcquireFastMutex", "ExTryToAcquireFastMutex", "ExReleaseFastMutex",
        "ExInitializeResourceLite", "ExAcquireResourceExclusiveLite", "ExAcquireResourceSharedLite", "ExReleaseResourceLite", "ExIsResourceAcquiredExclusiveLite", "ExIsResourceAcquiredSharedLite", "ExConvertExclusiveToSharedLite", "ExDeleteResourceLite", "ExAcquireSharedStarveExclusive", "ExAcquireSharedWaitForExclusive",
        "ExInitializeRundownProtection", "ExAcquireRundownProtection", "ExReleaseRundownProtection", "ExRundownCompleted",
        "ExInitializePagedLookasideList", "ExAllocateFromPagedLookasideList", "ExFreeToPagedLookasideList", "ExDeletePagedLookasideList",
        "ExGetPreviousMode", "ExInitializeWorkItem", "ExQueueWorkItem", "ExAcquireSpinLock", "ExReleaseSpinLock", "ExAcquireFastMutexUnsafe", "ExReleaseFastMutexUnsafe",
        "InitializeSListHead", "ExpInterlockedPushEntrySList", "ExpInterlockedPopEntrySList", "ExpInterlockedFlushSList", "ExQueryDepthSList", "ExInterlockedPushEntryList", "ExInterlockedPopEntryList",
        "ExInitializeNPagedLookasideList", "ExDeleteNPagedLookasideList",
        "ExSizeOfRundownProtectionCacheAware", "ExAllocateCacheAwareRundownProtection", "ExInitializeRundownProtectionCacheAware", "ExAcquireRundownProtectionCacheAware", "ExReleaseRundownProtectionCacheAware", "ExWaitForRundownProtectionReleaseCacheAware", "ExReInitializeRundownProtectionCacheAware", "ExFreeCacheAwareRundownProtection",
        "ExAllocateTimer", "ExSetTimer", "ExCancelTimer", "ExDeleteTimer", "ExUuidCreate", "EmClientQueryRuleState",
        "ExInitializePushLock", "ExAcquirePushLockExclusiveEx", "ExReleasePushLockExclusiveEx", "ExAcquireRundownProtectionCacheAwareEx", "ExReleaseRundownProtectionCacheAwareEx", "ExWaitForRundownProtectionRelease", "ExRegisterExtension", "ExSystemTimeToLocalTime",
        "ExAcquireSpinLockExclusive", "ExAcquireSpinLockShared", "ExAcquireSpinLockExclusiveAtDpcLevel", "ExAcquireSpinLockSharedAtDpcLevel", "ExReleaseSpinLockExclusive", "ExReleaseSpinLockShared", "ExReleaseSpinLockExclusiveFromDpcLevel", "ExReleaseSpinLockSharedFromDpcLevel", "ExTryConvertSharedSpinLockExclusive",
        "ExAcquirePushLockSharedEx", "ExReleasePushLockSharedEx", "ExReleasePushLockEx", "ExTryAcquirePushLockExclusiveEx", "ExTryAcquirePushLockSharedEx", "ExConvertPushLockExclusiveToShared",
        "ExReinitializeResourceLite", "ExReleaseResourceForThreadLite", "ExGetSharedWaiterCount", "ExGetExclusiveWaiterCount", "ExEnterCriticalRegionAndAcquireResourceExclusive", "ExEnterCriticalRegionAndAcquireResourceShared", "ExReleaseResourceAndLeaveCriticalRegion",
        "ExAcquireRundownProtectionEx", "ExReleaseRundownProtectionEx", "ExReInitializeRundownProtection", "ExRundownCompletedCacheAware",
    ],
    handlers: &[
        allocate_pool_with_tag, free_pool_export, free_pool_with_tag, allocate_pool2, allocate_pool_zero, allocate_pool_uninitialized, free_pool2,
        initialize_fast_mutex, acquire_fast_mutex, try_to_acquire_fast_mutex, release_fast_mutex,
        initialize_resource, acquire_resource_exclusive, acquire_resource_shared, release_resource, is_resource_acquired_exclusive, is_resource_acquired_shared, convert_exclusive_to_shared, delete_resource, acquire_shared_starve_exclusive, acquire_shared_wait_for_exclusive,
        initialize_rundown, acquire_rundown, release_rundown, rundown_completed,
        initialize_paged_lookaside, allocate_from_lookaside, free_to_lookaside, delete_lookaside,
        get_previous_mode, initialize_work_item, queue_work_item, acquire_spin_lock, release_spin_lock, acquire_fast_mutex_unsafe, release_fast_mutex_unsafe,
        initialize_slist_head, interlocked_push_entry_slist, interlocked_pop_entry_slist, interlocked_flush_slist, query_depth_slist, interlocked_push_entry_list, interlocked_pop_entry_list,
        initialize_nonpaged_lookaside, delete_lookaside,
        size_of_rundown_cache_aware, allocate_cache_aware_rundown, initialize_rundown_cache_aware, acquire_rundown_cache_aware, release_rundown_cache_aware, wait_rundown_cache_aware, reinitialize_rundown_cache_aware, free_cache_aware_rundown,
        allocate_timer, set_timer, cancel_timer, delete_timer, uuid_create, em_client_query_rule_state,
        initialize_push_lock, acquire_push_lock_exclusive, release_push_lock_exclusive, acquire_rundown_cache_aware_ex, release_rundown_cache_aware_ex, wait_rundown_release, register_extension, system_time_to_local_time,
        acquire_spin_lock_exclusive, acquire_spin_lock_shared, acquire_spin_lock_exclusive_at_dpc, acquire_spin_lock_shared_at_dpc, release_spin_lock_exclusive, release_spin_lock_shared, release_spin_lock_exclusive_from_dpc, release_spin_lock_shared_from_dpc, try_convert_shared_spin_lock_exclusive,
        acquire_push_lock_shared, release_push_lock_shared, release_push_lock, try_acquire_push_lock_exclusive, try_acquire_push_lock_shared, convert_push_lock_exclusive_to_shared,
        reinitialize_resource, release_resource_for_thread, shared_waiter_count, exclusive_waiter_count, enter_critical_region_and_acquire_exclusive, enter_critical_region_and_acquire_shared, release_resource_and_leave_critical_region,
        acquire_rundown_ex, release_rundown_ex, reinitialize_rundown, rundown_completed_cache_aware,
    ],
    data_exports: &[("ExEventObjectType", event_object_type_address)],
};

pub mod callbacks {
    //! Objetos de callback do Executive — `system32/win32/ntoskrnl/callbacks.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::callbacks;

    /// Os dois BOOLEANs valem pelo byte baixo.
    fn create_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::create(call.arg(1), call.arg(2), call.arg(3) & 0xFF != 0, call.arg(4) & 0xFF != 0)? as u64)
    }

    fn register_callback(call: &Call) -> Result<u64, KernelError> {
        callbacks::register(call.arg(1), call.arg(2), call.arg(3))
    }

    fn unregister_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(callbacks::unregister(call.arg(1))? as u64)
    }

    fn notify_callback(call: &Call) -> Result<u64, KernelError> {
        callbacks::notify(call.arg(1), call.arg(2), call.arg(3))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "callbacks",
        names: &["ExCreateCallback", "ExRegisterCallback", "ExUnregisterCallback", "ExNotifyCallback"],
        handlers: &[create_callback, register_callback, unregister_callback, notify_callback],
        data_exports: &[],
    };
}

pub mod datatype_misalignment {
    //! ExRaiseDatatypeMisalignment — STATUS_DATATYPE_MISALIGNMENT por `ntos/rtl/exceptions`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::exceptions;
    use crate::rtl::KernelError;

    fn raise_datatype_misalignment(_: &Call) -> Result<u64, KernelError> {
        exceptions::raise_status(0x8000_0002, 0, 0, 0)
    }

    pub static GROUP: Group = Group { name: "datatype-misalignment", names: &["ExRaiseDatatypeMisalignment"], handlers: &[raise_datatype_misalignment], data_exports: &[] };
}

pub mod enum_handles {
    //! ExEnumHandleTable — `system32/win32/ntoskrnl/enum-handles.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::enum_handles;

    fn enum_handle_table(call: &Call) -> Result<u64, KernelError> {
        Ok(enum_handles::enumerate(call.arg(1), call.arg(2), call.arg(3), call.arg(4))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "enum-handles",
        names: &["ExEnumHandleTable"],
        handlers: &[enum_handle_table],
        data_exports: &[],
    };
}

pub mod pool_allocation_exports {
    //! ExAllocatePoolWithTagPriority — `system32/win32/ntoskrnl/pool-allocation.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::pool_allocation;

    fn allocate_pool_with_tag_priority(call: &Call) -> Result<u64, KernelError> {
        pool_allocation::allocate_priority(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4) as u32)
    }

    pub static GROUP: Group = Group {
        name: "pool-allocation",
        names: &["ExAllocatePoolWithTagPriority"],
        handlers: &[allocate_pool_with_tag_priority],
        data_exports: &[],
    };
}

pub mod pool_quota {
    //! ExAllocatePoolWithQuotaTag — `system32/win32/ntoskrnl/pool-quota.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::pool_quota;

    fn allocate_pool_with_quota_tag(call: &Call) -> Result<u64, KernelError> {
        fatal_unless_transfer("pool-quota", pool_quota::allocate(call.arg(1) as u32, call.arg(2), call.arg(3) as u32))
    }

    pub static GROUP: Group = Group {
        name: "pool-quota",
        names: &["ExAllocatePoolWithQuotaTag"],
        handlers: &[allocate_pool_with_quota_tag],
        data_exports: &[],
    };
}

pub mod system_exception_filter {
    //! ExSystemExceptionFilter — `system32/win32/ntoskrnl/system-exception-filter.js`.
    //!
    //! EXCEPTION_EXECUTE_HANDLER quando o modo anterior não é KernelMode.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::previous_mode;

    fn system_exception_filter(_: &Call) -> Result<u64, KernelError> {
        Ok((previous_mode::get()? != 0) as u64)
    }

    pub static GROUP: Group = Group {
        name: "system-exception-filter",
        names: &["ExSystemExceptionFilter"],
        handlers: &[system_exception_filter],
        data_exports: &[],
    };
}

pub mod unblock_push_lock {
    //! ExfUnblockPushLock — `system32/win32/ntoskrnl/unblock-push-lock.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::unblock_push_lock;

    fn unblock_push_lock(call: &Call) -> Result<u64, KernelError> {
        unblock_push_lock::unblock(call.arg(1), call.arg(2))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "unblock-push-lock",
        names: &["ExfUnblockPushLock"],
        handlers: &[unblock_push_lock],
        data_exports: &[],
    };
}

pub mod license_values {
    //! ZwQueryLicenseValue — `system32/win32/ntoskrnl/license-values.js`.
    //!
    //! Consulta em KernelMode (o despachante aplica o modo aos exports `Zw*`);
    //! falha interna interrompe o sistema e o sinal de transferência propaga.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::license::values as license_values;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("license-values", license_values::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "license-values",
        names: &["ZwQueryLicenseValue"],
        handlers: &[query],
        data_exports: &[],
    };
}

pub mod wnf_query {
    //! ZwQueryWnfStateData — `system32/win32/ntoskrnl/wnf-query.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::wnf::service as wnf_service;

    fn query_state_data(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("wnf-query", wnf_service::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "wnf-query",
        names: &["ZwQueryWnfStateData"],
        handlers: &[query_state_data],
        data_exports: &[],
    };
}

pub mod wnf_update {
    //! ZwUpdateWnfStateData — `system32/win32/ntoskrnl/wnf-update.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ex::wnf::update as wnf_update;

    fn update_state_data(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("wnf-update", wnf_update::update(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6) as u32, call.arg(7) as u32 != 0))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "wnf-update",
        names: &["ZwUpdateWnfStateData"],
        handlers: &[update_state_data],
        data_exports: &[],
    };
}

pub mod firmware_environment {
    //! Variáveis de firmware — `system32/win32/ntoskrnl/firmware-environment.js`.
    //!
    //! Os cinco argumentos são ponteiros: nome UNICODE_STRING, GUID do
    //! fabricante, buffer, tamanho e atributos; o provedor consulta o firmware
    //! do loader antes de tocar neles. Só o serviço Zw assume KernelMode (o
    //! despachante já faz isso para os exports `Zw*`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::hal::firmware_environment;
    use crate::rtl::KernelError;

    fn query_firmware_environment(call: &Call) -> Result<u64, KernelError> {
        Ok(firmware_environment::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "firmware-environment",
        names: &["ZwQuerySystemEnvironmentValueEx", "ExGetFirmwareEnvironmentVariable"],
        handlers: &[query_firmware_environment, query_firmware_environment],
        data_exports: &[],
    };
}

pub mod zw {
    //! Rotinas Zw* do ntoskrnl — `system32/win32/ntoskrnl/zw.js` (handlers).
    //!
    //! Chaves pelo serviço de chaves (com callbacks do Cm), arquivos pelo
    //! núcleo `zw_files` e pelos serviços de I/O, objetos do namespace pelos
    //! handles de namespace, drivers pelo registro de serviços e as consultas de
    //! sistema pelas folhas de cada classe.

    use alloc::vec::Vec;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::cm::service::driver as driver_services;
    use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
    use crate::ntos::cm::key::native as native_keys;
    use crate::ntos::ex::{boot_environment_information, callbacks as executive_callbacks};
    use crate::ntos::io::file::{query as query_file, read as read_file, write as write_file};
    use crate::ntos::ke::{dispatcher, processor_information};
    use crate::ntos::mm::module_queries;
    use crate::ntos::ob::{close, object_manager, open_pointer};
    use crate::ntos::ob::handles::namespace as namespace_handles;
    use crate::ntos::po::black_box;
    use crate::ntos::ps::{image_information, kernel_threads, previous_mode, process, scheduler, system_process_information};
    use crate::ntos::se::{code_integrity_information, secure_boot_information};
    use crate::rtl::{KernelError, SpinLock};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::rtl::guest_strings;
    use crate::ntos::inc::nt_abi::{eprocess, kthread, object_attributes};

    const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    const FILE_OPEN: u32 = 1;

    /// Rotinas de entropia registradas por ZwSetSystemInformation(131): o RNG
    /// do kernel as chama ao coletar/resemear entropia.
    #[derive(Clone, Copy, Debug)]
    pub struct EntropyRegistration {
        pub entropy_routine: u64,
        pub initialization_routine: u64,
        pub initialization_context: u64,
    }

    static ENTROPY_TIMING_REGISTRATIONS: SpinLock<Vec<EntropyRegistration>> = SpinLock::new(Vec::new());

    pub fn entropy_registrations() -> Vec<EntropyRegistration> {
        ENTROPY_TIMING_REGISTRATIONS.lock().clone()
    }

    fn kernel_previous_mode() -> Result<bool, KernelError> {
        Ok(previous_mode::get()? != 0)
    }

    fn key(kind: Kind, handle: u64, arguments: &[(&'static str, u64)]) -> Result<u64, KernelError> {
        Ok(key_services::key_operation(kind, handle, &fields(arguments), kernel_previous_mode()?)? as u64)
    }

    fn object_name(attributes: u64) -> alloc::string::String {
        guest_strings::read_unicode_string(guest::read64(attributes + object_attributes::OBJECT_NAME))
    }

    /// "Handle de processo": -1/0 = corrente (CID da thread); senão o pid.
    fn process_id_from_handle(handle: u64) -> u64 {
        let value = handle as u32 as i32;
        if value == -1 || value == 0 {
            let thread = process::get_current_thread();
            if thread == 0 {
                return 4;
            }
            return guest::read64(thread + kthread::CID_UNIQUE_PROCESS);
        }
        value as u32 as u64
    }

    /// ZwQuerySystemInformation/NtQuerySystemInformation (o mesmo corpo).
    pub fn query_system_information(class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
        debug_print!("[zw] QuerySystemInformation classe {} buf={}", class, length);
        match class {
            90 => return boot_environment_information::query(output, length as u64, returned, false),
            103 => return code_integrity_information::query(output, length as u64, returned, false),
            143 => return secure_boot_information::query(output, length as u64, returned, false),
            11 | 77 => return module_queries::query_system_modules(class, output, length as u64, returned),
            1 | 63 => return Ok(processor_information::query(output, length, returned, false, class == 63)),
            // SystemCodeIntegrityCertificateManagementInformation: nenhuma
            // operação de certificados pendente (o cng percorre e segue).
            117 => {
                for offset in (0..length as u64).step_by(4) {
                    guest::write32(output + offset, 0);
                }
                if returned != 0 {
                    guest::write32(returned, length);
                }
                return Ok(0);
            }
            5 => {}
            _ => return Ok(0xC000_000D),
        }
        system_process_information::query(output, length as u64, returned, false)
    }

    fn create_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7))? as u64)
    }
    fn open_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::open(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
    }
    fn set_value_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::Set, call.arg(1), &[("name", call.arg(2)), ("title", call.arg(3)), ("type", call.arg(4)), ("data", call.arg(5)), ("length", call.arg(6))])
    }
    fn query_value_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::QueryValue, call.arg(1), &[("name", call.arg(2)), ("klass", call.arg(3)), ("out", call.arg(4)), ("length", call.arg(5)), ("returned", call.arg(6))])
    }
    /// ZwClose: arquivo, chave, dispositivo (CLEANUP+CLOSE) ou objeto.
    fn close_handle(call: &Call) -> Result<u64, KernelError> {
        Ok(close::close(call.arg(1), Some(0))? as u64)
    }
    fn create_file(call: &Call) -> Result<u64, KernelError> {
        Ok(zw_files::create_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(7) as u32, call.arg(8) as u32, call.arg(9) as u32)? as u64)
    }
    fn read(call: &Call) -> Result<u64, KernelError> {
        Ok(read_file::read(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }
    fn write(call: &Call) -> Result<u64, KernelError> {
        Ok(write_file::write(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8), call.arg(9))? as u64)
    }
    fn enumerate_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::EnumerateKey, call.arg(1), &[("index", call.arg(2)), ("klass", call.arg(3)), ("out", call.arg(4)), ("length", call.arg(5)), ("returned", call.arg(6))])
    }
    fn enumerate_value_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::EnumerateValue, call.arg(1), &[("index", call.arg(2)), ("klass", call.arg(3)), ("out", call.arg(4)), ("length", call.arg(5)), ("returned", call.arg(6))])
    }
    fn delete_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::DeleteKey, call.arg(1), &[])
    }
    fn query_full_attributes_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::query_full_attributes_file(call.arg(1), call.arg(2))))
    }
    /// ZwOpenFile = ZwCreateFile com FILE_OPEN (compartilhamento e opções não
    /// são repassados, como no original).
    fn open_file(call: &Call) -> Result<u64, KernelError> {
        Ok(zw_files::create_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), 0, FILE_OPEN, 0)? as u64)
    }
    fn query_information_file(call: &Call) -> Result<u64, KernelError> {
        Ok(query_file::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }
    fn set_information_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::set_information_file(call.arg(1), call.arg(2), call.arg(3), call.arg(5) as u32)?))
    }
    /// ZwLoadDriver/ZwUnloadDriver: o mesmo registro de serviços do SCM.
    fn load_driver(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(driver_services::nt_request(&guest_strings::read_unicode_string(call.arg(1)), false)))
    }
    fn unload_driver(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(driver_services::nt_request(&guest_strings::read_unicode_string(call.arg(1)), true)))
    }
    fn query_system_information_handler(call: &Call) -> Result<u64, KernelError> {
        Ok(query_system_information(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4))? as u64)
    }
    /// ZwPowerInformation: 94 = black box do kernel; 4 = SystemPowerCapabilities
    /// de desktop (sem bateria, AC ligado).
    fn power_information(call: &Call) -> Result<u64, KernelError> {
        let level = call.arg(1) as u32;
        if level == 94 {
            return Ok(signed_status(black_box::update_from_kernel(call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32)?));
        }
        if level != 4 {
            return Ok(signed_status(0xC000_000D));
        }
        if (call.arg(5) as u32) < 0x40 {
            return Ok(signed_status(STATUS_BUFFER_TOO_SMALL));
        }
        let destination = call.arg(4);
        guest::write8(destination, 1);
        guest::write8(destination + 1, 1);
        guest::write8(destination + 2, 0);
        guest::write8(destination + 3, 1);
        guest::write8(destination + 7, 1);
        guest::write8(destination + 0x0C, 1);
        Ok(0)
    }
    /// ZwWaitForSingleObject: eventos da tabela nativa (abertos por ponteiro),
    /// threads de sistema e os eventos abertos pelo zw.
    fn wait_for_single_object(call: &Call) -> Result<u64, KernelError> {
        let (handle, alertable, timeout) = (call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3));
        match open_pointer::resolve(handle, false) {
            Some(Err(status)) => return Ok(status as u64),
            Some(Ok(opened)) if opened.item.object_type.name == "Event" => {
                // O último fechamento durante a espera não libera o KEVENT em uso.
                opened.item.reference();
                let status = dispatcher::wait_for_single_object(opened.item.pointer, timeout, 0, alertable);
                opened.item.dereference();
                return Ok(signed_status(status));
            }
            _ => {}
        }
        if let Some(thread) = kernel_threads::of_handle(handle) {
            return Ok(dispatcher::wait_for_single_object(thread, timeout, 0, alertable) as u64);
        }
        let pointer = zw_files::wait_object_of_handle(handle);
        if pointer == 0 {
            return Ok(signed_status(STATUS_INVALID_HANDLE));
        }
        Ok(signed_status(dispatcher::wait_for_single_object(pointer, timeout, 0, alertable)))
    }
    /// ZwOpenEvent: evento nomeado do namespace.
    fn open_event(call: &Call) -> Result<u64, KernelError> {
        let node = object_manager::lookup(&object_name(call.arg(3))).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Event"));
        let Some(node) = node else { return Ok(signed_status(STATUS_OBJECT_NAME_NOT_FOUND)) };
        Ok(zw_files::open_kernel_object(call.arg(1), node, call.arg(2) as u32, call.arg(3))? as u64)
    }
    fn create_directory_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::open(call.arg(1), call.arg(2) as u32, call.arg(3), "Directory", false, true) as u64)
    }
    fn make_temporary_object(call: &Call) -> Result<u64, KernelError> {
        if let Some(status) = executive_callbacks::make_temporary(call.arg(1))? {
            return Ok(status as u64);
        }
        Ok(namespace_handles::make_temporary(call.arg(1)).unwrap_or(STATUS_INVALID_HANDLE) as u64)
    }
    fn open_symbolic_link_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::open(call.arg(1), call.arg(2) as u32, call.arg(3), "SymbolicLink", false, false) as u64)
    }
    fn query_symbolic_link_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::query_link(call.arg(1), call.arg(2), call.arg(3), false) as u64)
    }
    fn fs_control_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::fs_control_file(call.arg(1), call.arg(5), call.arg(6) as u32, call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10) as u32)?))
    }
    fn query_volume_information_file(call: &Call) -> Result<u64, KernelError> {
        Ok(zw_files::query_volume_information_file(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
    }
    fn query_directory_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::query_directory_file(call.arg(1), call.arg(5), call.arg(6), call.arg(7) as u32, call.arg(8) as u32, call.arg(9) & 0xFF != 0, call.arg(10), call.arg(11) & 0xFF != 0)))
    }
    fn delete_value_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::DeleteValue, call.arg(1), &[("name", call.arg(2))])
    }
    fn query_key(call: &Call) -> Result<u64, KernelError> {
        key(Kind::QueryKey, call.arg(1), &[("klass", call.arg(2)), ("out", call.arg(3)), ("length", call.arg(4)), ("returned", call.arg(5))])
    }
    /// ZwSetSystemInformation: 131 registra as rotinas de entropia do chamador;
    /// classes desconhecidas = STATUS_INVALID_INFO_CLASS.
    fn set_system_information(call: &Call) -> Result<u64, KernelError> {
        let class = call.arg(1) as u32;
        if class == 131 {
            if (call.arg(3) as u32) < 24 {
                return Ok(signed_status(0xC000_0004));
            }
            let buffer = call.arg(2);
            let count = {
                let mut registrations = ENTROPY_TIMING_REGISTRATIONS.lock();
                registrations.push(EntropyRegistration { entropy_routine: guest::read64(buffer), initialization_routine: guest::read64(buffer + 8), initialization_context: guest::read64(buffer + 16) });
                registrations.len()
            };
            debug_print!("[zw] entropia: rotinas registradas ({} provedor(es))", count);
            return Ok(0);
        }
        debug_print!("[zw] ZwSetSystemInformation classe {} (sem suporte)", class);
        Ok(signed_status(0xC000_0003))
    }
    /// ZwQueryInformationProcess: ProcessImageInformation (37) e
    /// ProcessBasicInformation (0).
    fn query_information_process(call: &Call) -> Result<u64, KernelError> {
        let (handle, class, output, length, returned) = (call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5));
        if class == 37 {
            return Ok(signed_status(image_information::query(handle, output, length, returned, 0, None)?));
        }
        if class != 0 {
            return Ok(signed_status(0xC000_000D));
        }
        if length < 0x30 {
            if returned != 0 {
                guest::write32(returned, 0x30);
            }
            return Ok(signed_status(STATUS_BUFFER_TOO_SMALL));
        }
        let pid = process_id_from_handle(handle);
        let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == pid) else { return Ok(signed_status(STATUS_INVALID_HANDLE)) };
        guest::write32(output, 0x103);
        guest::write32(output + 4, 0);
        guest::write64(output + 8, guest::read64(target.address + eprocess::PEB));
        guest::write64(output + 0x10, 1);
        guest::write32(output + 0x18, 8);
        guest::write32(output + 0x1C, 0);
        guest::write64(output + 0x20, pid);
        guest::write64(output + 0x28, 4);
        if returned != 0 {
            guest::write32(returned, 0x30);
        }
        Ok(0)
    }
    /// ZwTerminateProcess: marca no escalonador preservando o status.
    fn terminate_process(call: &Call) -> Result<u64, KernelError> {
        let pid = process_id_from_handle(call.arg(1));
        Ok(if scheduler::kill(pid as u32, call.arg(2) as u32) { 0 } else { signed_status(STATUS_INVALID_HANDLE) })
    }
    fn flush_buffers_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::flush_buffers_file(call.arg(1), call.arg(2))))
    }
    fn open_directory_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::open(call.arg(1), call.arg(2) as u32, call.arg(3), "Directory", false, false) as u64)
    }
    fn query_directory_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::query_directory(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) & 0xFF != 0, call.arg(5) & 0xFF != 0, call.arg(6), call.arg(7)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "zw",
        names: &[
            "ZwCreateKey", "ZwOpenKey", "ZwSetValueKey", "ZwQueryValueKey", "ZwClose", "ZwCreateFile", "ZwReadFile", "ZwWriteFile", "ZwEnumerateKey", "ZwEnumerateValueKey", "ZwDeleteKey", "ZwQueryFullAttributesFile", "ZwOpenFile", "ZwQueryInformationFile", "ZwSetInformationFile", "ZwLoadDriver", "ZwUnloadDriver", "ZwQuerySystemInformation", "ZwPowerInformation", "ZwWaitForSingleObject", "ZwOpenEvent", "ZwCreateDirectoryObject", "ZwMakeTemporaryObject", "ZwOpenSymbolicLinkObject", "ZwQuerySymbolicLinkObject", "ZwFsControlFile", "ZwQueryVolumeInformationFile", "ZwQueryDirectoryFile", "ZwDeleteValueKey", "ZwQueryKey", "ZwSetSystemInformation", "ZwQueryInformationProcess", "ZwTerminateProcess", "ZwFlushBuffersFile", "ZwOpenDirectoryObject", "ZwQueryDirectoryObject", "NtQuerySystemInformation",
        ],
        handlers: &[
            create_key, open_key, set_value_key, query_value_key, close_handle, create_file, read, write, enumerate_key, enumerate_value_key, delete_key, query_full_attributes_file, open_file, query_information_file, set_information_file, load_driver, unload_driver, query_system_information_handler, power_information, wait_for_single_object, open_event, create_directory_object, make_temporary_object, open_symbolic_link_object, query_symbolic_link_object, fs_control_file, query_volume_information_file, query_directory_file, delete_value_key, query_key, set_system_information, query_information_process, terminate_process, flush_buffers_file, open_directory_object, query_directory_object, query_system_information_handler,
        ],
        data_exports: &[],
    };

    // ---- ZwDisplayString (grupo "display-string", no fim da ABI) ---------------

    /// NtDisplayString: modo usuário precisa do SeTcbPrivilege; a string vira
    /// ANSI (fora do Latin-1 vira `?`) e vai para o vídeo de texto de boot, que
    /// no OpenNT é o console.
    fn display_string(call: &Call) -> Result<u64, KernelError> {
        let string = call.arg(1);
        if crate::ntos::ps::previous_mode::get()? != 0 {
            return Ok(0xC000_0061);
        }
        if string == 0 {
            return Ok(0xC000_0005);
        }
        let length = crate::ntos::mm::guest_memory::read16(string);
        if length & 1 != 0 || (length != 0 && crate::ntos::mm::guest_memory::read64(string + 8) == 0) {
            return Ok(0xC000_000D);
        }
        let text: alloc::string::String = crate::ntos::rtl::guest_strings::read_unicode_string(string).chars().map(|character| if (character as u32) < 0x100 { character } else { '?' }).collect();
        crate::drivers::console::write(&text);
        Ok(0)
    }

    pub static DISPLAY_STRING_GROUP: Group = Group {
        name: "display-string",
        names: &["ZwDisplayString"],
        handlers: &[display_string],
        data_exports: &[],
    };
}

pub mod ex_lookaside_wnf {
    //! ExInitializeLookasideListEx / ExDeleteLookasideListEx e
    //! ExQueryWnfStateData. O lookaside reusa `ex/lookaside.rs`; a consulta WNF
    //! reusa `ex/wnf/service::query`. A inscrição/desinscrição de kernel
    //! (ExSubscribe/ExUnsubscribeWnfStateChange) entra num grupo próprio quando
    //! o motor WNF tiver remoção de assinatura.

    use crate::ntos::ex::lookaside;
    use crate::ntos::ex::wnf::service as wnf_service;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// ExInitializeLookasideListEx(List, AllocateEx, FreeEx, PoolType, Flags,
    /// Size, Tag, Depth). O PoolType vira o campo Type (+0x24) e escolhe o
    /// registro paginado/não paginado pelo bit 0; AllocateEx/FreeEx nulos
    /// recebem ExAllocatePoolWithTag/ExFreePool (feito dentro de `initialize`,
    /// como nas listas não-Ex). Flags e Depth não têm efeito persistente aqui.
    fn initialize_lookaside_list_ex(call: &Call) -> Result<u64, KernelError> {
        let pool_type = call.arg(4) as u32;
        lookaside::initialize(call.arg(1), call.arg(2), call.arg(3), pool_type, call.arg(6), call.arg(7) as u32, pool_type & 1 != 0)?;
        Ok(0)
    }

    /// ExDeleteLookasideListEx(List): tira do registro e esvazia a SLIST pelo
    /// FreeEx (reusa `lookaside::delete`).
    fn delete_lookaside_list_ex(call: &Call) -> Result<u64, KernelError> {
        lookaside::delete(call.arg(1))?;
        Ok(0)
    }

    /// ExQueryWnfStateData(StateName, TypeId, ExplicitScope, ChangeStamp,
    /// Buffer, BufferSize): a mesma entrada do motor que o ZwQueryWnfStateData,
    /// chamada em modo kernel. Nome indefinido devolve STATUS_OBJECT_NAME_NOT_FOUND.
    fn query_wnf_state_data(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wnf_service::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))?))
    }

    pub static GROUP: Group = Group {
        name: "ex-lookaside-wnf",
        names: &["ExInitializeLookasideListEx", "ExDeleteLookasideListEx", "ExQueryWnfStateData"],
        handlers: &[initialize_lookaside_list_ex, delete_lookaside_list_ex, query_wnf_state_data],
        data_exports: &[],
    };
}
