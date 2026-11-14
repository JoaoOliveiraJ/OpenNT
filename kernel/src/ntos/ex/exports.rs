//! Exports Ex* (pool, mutexes, ERESOURCE, rundown, lookaside, SLIST, timers,
//! push locks, spin locks).

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::ex::{event, extension_host, interlocked_list, lookaside, pool_allocation, push_lock, resource, rundown, slist, spin_lock, system_time, timer, uuid};
use crate::ntos::io::work_items;
use crate::ntos::ke::fast_mutex;
use crate::ntos::ps::previous_mode;
use crate::rtl::KernelError;

fn ok<T>(result: Result<T, KernelError>) -> Result<u64, KernelError> {
    result.map(|_| 0)
}

// ---- pool ----------------------------------------------------------------

fn allocate_pool_with_tag(call: &Call) -> Result<u64, KernelError> {
    pool_allocation::allocate_tagged(call.arg(1) as u32, call.arg(2), call.arg(3) as u32)
}
fn free_pool_export(call: &Call) -> Result<u64, KernelError> {
    ok(pool_allocation::free(call.arg(1), 0))
}
/// A tag fornecida não muda o caminho do kernel original.
fn free_pool_with_tag(call: &Call) -> Result<u64, KernelError> {
    ok(pool_allocation::free(call.arg(1), 0))
}
/// ExAllocatePool2(Flags, NumberOfBytes, Tag).
fn allocate_pool2(call: &Call) -> Result<u64, KernelError> {
    pool_allocation::allocate_pool2(call.arg(1), call.arg(2), call.arg(3) as u32)
}
/// ExAllocatePoolZero(PoolType, NumberOfBytes, Tag).
fn allocate_pool_zero(call: &Call) -> Result<u64, KernelError> {
    pool_allocation::allocate_typed(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, true)
}
/// ExAllocatePoolUninitialized(PoolType, NumberOfBytes, Tag).
fn allocate_pool_uninitialized(call: &Call) -> Result<u64, KernelError> {
    pool_allocation::allocate_typed(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, false)
}
fn free_pool2(call: &Call) -> Result<u64, KernelError> {
    ok(pool_allocation::free(call.arg(1), call.arg(2)))
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
fn acquire_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_legacy(call.arg(1), call.arg(2));
    Ok(0)
}
fn release_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::unlock_with_lower(call.arg(1), call.arg(2) as u8);
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
    Ok(interlocked_list::push(call.arg(1), call.arg(2), call.arg(3)))
}
fn interlocked_pop_entry_list(call: &Call) -> Result<u64, KernelError> {
    Ok(interlocked_list::pop(call.arg(1), call.arg(2)))
}

// ---- EX_TIMER ------------------------------------------------------------

fn allocate_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::allocate(call.arg(1), call.arg(2)))
}
fn set_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::set(call.arg(1), call.arg(2) as i64, call.arg(3) as u32, call.arg(4)) as u64)
}
fn cancel_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::cancel(call.arg(1)) as u64)
}
fn delete_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::delete(call.arg(1), call.arg(2) != 0) as u64)
}

fn uuid_create(call: &Call) -> Result<u64, KernelError> {
    uuid::create(call.arg(1));
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

/// ExRegisterExtension(Extension*, RegistrationVersion, RegistrationInfo).
fn register_extension(call: &Call) -> Result<u64, KernelError> {
    use crate::ntos::inc::field::{Field, NtStruct};
    // SAFETY: o PEX_EXTENSION de saída e o EX_EXTENSION_REGISTRATION_1 de um
    // chamador de modo kernel.
    let (extension, info) = unsafe { (Field::<u64>::at(call.arg(1)), extension_host::ExExtensionRegistration1::at(call.arg(3))) };
    Ok(signed_status(extension_host::register_extension(extension, call.arg(2) as u32, info)?))
}

fn system_time_to_local_time(call: &Call) -> Result<u64, KernelError> {
    system_time::system_time_to_local_time(call.arg(1), call.arg(2));
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
    event::event_object_type()
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
    //! Objetos de callback do Executive.

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
    //! ExEnumHandleTable.

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
    //! ExAllocatePoolWithTagPriority.

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
    //! ExAllocatePoolWithQuotaTag.
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
    //! ExSystemExceptionFilter.
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
    //! ExfUnblockPushLock.

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
    //! ZwQueryLicenseValue.
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
    //! ZwQueryWnfStateData.
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
    //! ZwUpdateWnfStateData.
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
    //! Variáveis de firmware.
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
    //! Rotinas Zw* do ntoskrnl (handlers).
    //!
    //! Chaves pelo serviço de chaves (com callbacks do Cm), arquivos pelo
    //! núcleo `zw_files` e pelos serviços de I/O, objetos do namespace pelos
    //! handles de namespace, drivers pelo registro de serviços e as consultas de
    //! sistema pelas folhas de cada classe.
    //!
    //! Cada serviço mora no seu componente: chaves em `cm/key/native`,
    //! arquivos em `io/file`, ZwClose/ZwWaitForSingleObject e objetos do
    //! namespace em `ob`, drivers em `cm/service/driver`, informações do
    //! sistema em `ex/system_information`, ZwOpenEvent em `ex/event`,
    //! ZwPowerInformation em `po/power_information`, processos em
    //! `ps/query_process` e `ps/scheduler`, ZwDisplayString em
    //! `ex/boot_display`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::io::file::zw as zw_files;
    use crate::ntos::cm::service::driver as driver_services;
    use crate::ntos::cm::key::native as native_keys;
    use crate::ntos::ex::{boot_display, event, system_information};
    use crate::ntos::io::file::{query as query_file, read as read_file, write as write_file};
    use crate::ntos::ob::{close, wait};
    use crate::ntos::ob::handles::namespace as namespace_handles;
    use crate::ntos::po::power_information;
    use crate::ntos::ps::{query_process, scheduler};
    use crate::rtl::KernelError;
    use crate::ntos::rtl::guest_strings;

    fn create_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6) as u32, call.arg(7))? as u64)
    }
    fn open_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::open(call.arg(1), call.arg(2) as u32, call.arg(3))? as u64)
    }
    fn set_value_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::set_value(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }
    fn query_value_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::query_value(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
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
        Ok(native_keys::enumerate_key(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }
    fn enumerate_value_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::enumerate_value(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }
    fn delete_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::delete_key(call.arg(1))? as u64)
    }
    fn query_full_attributes_file(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(zw_files::query_full_attributes_file(call.arg(1), call.arg(2))))
    }
    fn open_file(call: &Call) -> Result<u64, KernelError> {
        Ok(zw_files::open_kernel_file(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))? as u64)
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
        Ok(system_information::query(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4))? as u64)
    }
    fn power_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(power_information::query(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32)?))
    }
    fn wait_for_single_object(call: &Call) -> Result<u64, KernelError> {
        Ok(wait::wait_for_single_object(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3)))
    }
    fn open_event(call: &Call) -> Result<u64, KernelError> {
        event::open(call.arg(1), call.arg(2) as u32, call.arg(3))
    }
    fn create_directory_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::open(call.arg(1), call.arg(2) as u32, call.arg(3), "Directory", false, true) as u64)
    }
    fn make_temporary_object(call: &Call) -> Result<u64, KernelError> {
        Ok(namespace_handles::make_temporary_object(call.arg(1))? as u64)
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
        Ok(native_keys::delete_value(call.arg(1), call.arg(2))? as u64)
    }
    fn query_key(call: &Call) -> Result<u64, KernelError> {
        Ok(native_keys::query_key(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5))? as u64)
    }
    fn set_system_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(system_information::set(call.arg(1) as u32, call.arg(2), call.arg(3) as u32)))
    }
    fn query_information_process(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(query_process::query_information(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5))?))
    }
    fn terminate_process(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(scheduler::terminate_by_handle(call.arg(1), call.arg(2) as u32)))
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

    fn display_string(call: &Call) -> Result<u64, KernelError> {
        Ok(boot_display::display_string(call.arg(1))? as u64)
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
    //! (ExSubscribe/ExUnsubscribeWnfStateChange) fica no grupo
    //! `ex-wnf-subscription`, depois que
    //! o motor WNF tiver remoção de assinatura.

    use crate::ntos::ex::lookaside;
    use crate::ntos::ex::wnf::service as wnf_service;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    fn initialize_lookaside_list_ex(call: &Call) -> Result<u64, KernelError> {
        lookaside::initialize_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(6), call.arg(7) as u32)?;
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

pub mod ex_interlocked {
    //! Adaptadores de ExInterlockedAddLargeInteger/Ulong (lógica em
    //! `ex/interlocked.rs`).

    use crate::ntos::ex::interlocked;
    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// (PLARGE_INTEGER Addend, LARGE_INTEGER Increment por valor, PKSPIN_LOCK).
    fn add_large_integer(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: Addend vivo e alinhado do chamador, como no NT.
        let addend = unsafe { Field::<i64>::at(call.arg(1)) };
        Ok(interlocked::add_large_integer(addend, call.arg(2) as i64, call.arg(3)) as u64)
    }

    /// (PULONG Addend, ULONG Increment, PKSPIN_LOCK).
    fn add_ulong(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: idem.
        let addend = unsafe { Field::<u32>::at(call.arg(1)) };
        Ok(interlocked::add_ulong(addend, call.arg(2) as u32, call.arg(3)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "ex-interlocked",
        names: &["ExInterlockedAddLargeInteger", "ExInterlockedAddUlong"],
        handlers: &[add_large_integer, add_ulong],
        data_exports: &[],
    };
}

pub mod ex_processor_usage {
    //! Adaptadores de ExGetCurrentProcessorCounts/CpuUsage (lógica em
    //! `ex/processor_usage.rs`).

    use crate::ntos::ex::processor_usage;
    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// PULONG de saída do chamador.
    fn ulong(address: u64) -> &'static Field<u32> {
        // SAFETY: os exports recebem PULONGs vivos e alinhados, sem validação no NT.
        unsafe { Field::<u32>::at(address) }
    }

    fn get_current_processor_counts(call: &Call) -> Result<u64, KernelError> {
        processor_usage::counts(ulong(call.arg(1)), ulong(call.arg(2)), ulong(call.arg(3)));
        Ok(0)
    }

    fn get_current_processor_cpu_usage(call: &Call) -> Result<u64, KernelError> {
        processor_usage::cpu_usage(ulong(call.arg(1)));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-processor-usage",
        names: &["ExGetCurrentProcessorCounts", "ExGetCurrentProcessorCpuUsage"],
        handlers: &[get_current_processor_counts, get_current_processor_cpu_usage],
        data_exports: &[],
    };
}

pub mod pcw_counters {
    //! Adaptadores de PcwRegister/PcwUnregister/PcwAddInstance (lógica em
    //! `ex/pcw.rs`: o ramo do ntoskrnl sem a extensão do pcw.sys).

    use crate::ntos::ex::pcw;
    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// (PPCW_REGISTRATION *Registration, PPCW_REGISTRATION_INFORMATION Info).
    fn register(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: ponteiro de saída vivo do driver, como no NT.
        let registration = unsafe { Field::<u64>::at(call.arg(1)) };
        Ok(signed_status(pcw::register(registration, call.arg(2))))
    }

    fn unregister(call: &Call) -> Result<u64, KernelError> {
        pcw::unregister(call.arg(1));
        Ok(0)
    }

    fn add_instance(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(pcw::add_instance(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5))))
    }

    pub static GROUP: Group = Group {
        name: "pcw-counters",
        names: &["PcwRegister", "PcwUnregister", "PcwAddInstance"],
        handlers: &[register, unregister, add_instance],
        data_exports: &[],
    };
}

pub mod ex_access_violation {
    //! ExRaiseAccessViolation — STATUS_ACCESS_VIOLATION por `ntos/rtl/exceptions`
    //! (o RtlRaiseStatus do original; não retorna).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::rtl::exceptions;
    use crate::rtl::KernelError;

    /// Mesmo limite de IRQL do adaptador de RtlRaiseStatus.
    fn raise_access_violation(_: &Call) -> Result<u64, KernelError> {
        exceptions::raise_status(0xC000_0005, 0, 0, 1)
    }

    pub static GROUP: Group = Group { name: "ex-access-violation", names: &["ExRaiseAccessViolation"], handlers: &[raise_access_violation], data_exports: &[] };
}

pub mod ex_auto_expand_push_lock {
    //! EX_PUSH_LOCK_AUTO_EXPAND: adaptadores finos sobre `ex::auto_expand_push_lock`.
    //! O PEX_PUSH_LOCK_AUTO_EXPAND do driver vira `&ExPushLockAutoExpand` aqui.

    use crate::ntos::ex::auto_expand_push_lock;
    use crate::ntos::inc::types::extra_fs_ntfs::ExPushLockAutoExpand;
    use crate::ntos::inc::NtStruct;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn initialize(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::initialize(unsafe { ExPushLockAutoExpand::at(call.arg(1)) }, call.arg(2) as u32);
        Ok(0)
    }

    fn cleanup(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::cleanup(unsafe { ExPushLockAutoExpand::at(call.arg(1)) })?;
        Ok(0)
    }

    fn acquire_exclusive(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::acquire_exclusive(unsafe { ExPushLockAutoExpand::at(call.arg(1)) }, call.arg(2) as u32)?;
        Ok(0)
    }

    fn release_exclusive(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::release_exclusive(unsafe { ExPushLockAutoExpand::at(call.arg(1)) }, call.arg(2) as u32)?;
        Ok(0)
    }

    /// ExAcquireAutoExpandPushLockShared(PushLock, Flags) -> PVOID token.
    fn acquire_shared(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::acquire_shared(unsafe { ExPushLockAutoExpand::at(call.arg(1)) }, call.arg(2) as u32)
    }

    /// ExReleaseAutoExpandPushLockShared(Token, Flags).
    fn release_shared(call: &Call) -> Result<u64, KernelError> {
        auto_expand_push_lock::release_shared(call.arg(1), call.arg(2) as u32)?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-auto-expand-push-lock",
        names: &[
            "ExInitializeAutoExpandPushLock",
            "ExCleanupAutoExpandPushLock",
            "ExAcquireAutoExpandPushLockExclusive",
            "ExReleaseAutoExpandPushLockExclusive",
            "ExAcquireAutoExpandPushLockShared",
            "ExReleaseAutoExpandPushLockShared",
        ],
        handlers: &[initialize, cleanup, acquire_exclusive, release_exclusive, acquire_shared, release_shared],
        data_exports: &[],
    };
}

pub mod ex_resource_owner {
    //! ExSetResourceOwnerPointerEx: adaptador fino sobre `ex::resource::set_owner_pointer`.

    use crate::ntos::ex::resource;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// ExSetResourceOwnerPointerEx(Resource, OwnerPointer, Flags).
    fn set_owner_pointer_ex(call: &Call) -> Result<u64, KernelError> {
        resource::set_owner_pointer(call.arg(1), call.arg(2), call.arg(3) as u32)?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-resource-owner",
        names: &["ExSetResourceOwnerPointerEx"],
        handlers: &[set_owner_pointer_ex],
        data_exports: &[],
    };
}

pub mod ex_resource_owner_and_local_time {
    //! ExSetResourceOwnerPointer (= ExSetResourceOwnerPointerEx com Flags 0) e
    //! ExLocalTimeToSystemTime: a lógica mora em `ex/resource.rs` e `ex/system_time.rs`.

    use crate::ntos::ex::{resource, system_time};
    use crate::ntos::inc::types::{LargeInteger, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn set_owner_pointer(call: &Call) -> Result<u64, KernelError> {
        resource::set_owner_pointer(call.arg(1), call.arg(2), 0).map(|_| 0)
    }
    fn local_time_to_system_time(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: os PLARGE_INTEGER do chamador (modo kernel).
        system_time::local_time_to_system_time(unsafe { LargeInteger::at(call.arg(1)) }, unsafe { LargeInteger::at(call.arg(2)) });
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-resource-owner-and-local-time",
        names: &["ExSetResourceOwnerPointer", "ExLocalTimeToSystemTime"],
        handlers: &[set_owner_pointer, local_time_to_system_time],
        data_exports: &[],
    };
}

pub mod ex_cache_aware_push_locks {
    //! EX_PUSH_LOCK_CACHE_AWARE: a lógica mora em `ex/push_lock.rs`.

    use crate::ntos::ex::push_lock;
    use crate::ntos::inc::types::extra_fs_fat::ExPushLockCacheAware;
    use crate::ntos::inc::types::NtStruct;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// PEX_PUSH_LOCK_CACHE_AWARE devolvido por ExAllocateCacheAwarePushLock.
    fn table(call: &Call) -> &'static ExPushLockCacheAware {
        // SAFETY: o driver passa a tabela que o Allocate lhe entregou.
        unsafe { ExPushLockCacheAware::at(call.arg(1)) }
    }

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        push_lock::allocate_cache_aware(call.arg(1) as u32)
    }
    fn acquire_exclusive(call: &Call) -> Result<u64, KernelError> {
        push_lock::acquire_cache_aware_exclusive(table(call)).map(|_| 0)
    }
    fn release_exclusive(call: &Call) -> Result<u64, KernelError> {
        push_lock::release_cache_aware_exclusive(table(call)).map(|_| 0)
    }
    fn acquire_shared(call: &Call) -> Result<u64, KernelError> {
        push_lock::acquire_cache_aware_shared(table(call), call.arg(2) as u32)
    }
    fn release_shared(call: &Call) -> Result<u64, KernelError> {
        push_lock::release_cache_aware_shared(call.arg(1), call.arg(2) as u32).map(|_| 0)
    }

    pub static GROUP: Group = Group {
        name: "ex-cache-aware-push-locks",
        names: &[
            "ExAllocateCacheAwarePushLock",
            "ExAcquireCacheAwarePushLockExclusive",
            "ExReleaseCacheAwarePushLockExclusive",
            "ExAcquireCacheAwarePushLockSharedEx",
            "ExReleaseCacheAwarePushLockSharedEx",
        ],
        handlers: &[allocate, acquire_exclusive, release_exclusive, acquire_shared, release_shared],
        data_exports: &[],
    };
}

pub mod ex_resource_priority {
    //! ERESOURCE com região de prioridade: só adaptadores.

    use crate::ntos::ex::resource;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn enter_priority_region_and_acquire_shared(call: &Call) -> Result<u64, KernelError> {
        resource::enter_priority_region_shared(call.arg(1))
    }
    fn enter_priority_region_and_acquire_exclusive(call: &Call) -> Result<u64, KernelError> {
        resource::enter_priority_region_exclusive(call.arg(1))
    }
    fn release_resource_and_leave_priority_region(call: &Call) -> Result<u64, KernelError> {
        resource::release_and_leave_priority_region(call.arg(1)).map(|()| 0)
    }

    pub static GROUP: Group = Group {
        name: "ex-resource-priority",
        names: &[
            "ExEnterPriorityRegionAndAcquireResourceShared",
            "ExEnterPriorityRegionAndAcquireResourceExclusive",
            "ExReleaseResourceAndLeavePriorityRegion",
        ],
        handlers: &[
            enter_priority_region_and_acquire_shared,
            enter_priority_region_and_acquire_exclusive,
            release_resource_and_leave_priority_region,
        ],
        data_exports: &[],
    };
}

pub mod ex_pool_block_size {
    //! ExQueryPoolBlockSize: só o adaptador.

    use crate::ntos::ex::pool_allocation;
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::rtl::KernelError;

    fn query_pool_block_size(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PBOOLEAN QuotaCharged do driver (NULL tolerado).
        let quota_charged = (call.arg(2) != 0).then(|| unsafe { Field::<u8>::at(call.arg(2)) });
        Ok(pool_allocation::query_block_size_with_quota(call.arg(1), quota_charged))
    }

    pub static GROUP: Group = Group {
        name: "ex-pool-block-size",
        names: &["ExQueryPoolBlockSize"],
        handlers: &[query_pool_block_size],
        data_exports: &[],
    };
}

pub mod ex_legacy_support {
    use crate::ntos::ex::{interlocked, pool_allocation};
    use crate::ntos::inc::types::{Field, ListEntry, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::clock;
    use crate::rtl::KernelError;

    fn allocate_pool(call: &Call) -> Result<u64, KernelError> {
        pool_allocation::allocate_untagged(call.arg(1) as u32, call.arg(2))
    }

    fn interlocked_insert_head_list(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: LIST_ENTRYs de um chamador de modo kernel (o lock protege a lista).
        let (head, entry) = unsafe { (ListEntry::at(call.arg(1)), ListEntry::at(call.arg(2))) };
        Ok(interlocked::insert_head_list(head, entry, call.arg(3)))
    }

    fn query_timer_resolution(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG de saída de um chamador de modo kernel.
        let (maximum, minimum, current) = unsafe { (Field::<u32>::at(call.arg(1)), Field::<u32>::at(call.arg(2)), Field::<u32>::at(call.arg(3))) };
        clock::query_timer_resolution(maximum, minimum, current);
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-legacy-support",
        names: &["ExAllocatePool", "ExInterlockedInsertHeadList", "ExQueryTimerResolution"],
        handlers: &[allocate_pool, interlocked_insert_head_list, query_timer_resolution],
        data_exports: &[],
    };
}

pub mod ex_hard_error {
    //! ExRaiseHardError (`ex/hard_error`) e as células dos tipos que o
    //! executive cria no boot: os do subsistema Win32 (`ex/win32`) e o Timer
    //! (`ex/timer`).

    use crate::ntos::ex::{hard_error, win32};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// ExRaiseHardError(ErrorStatus, NumberOfParameters,
    /// UnicodeStringParameterMask, Parameters, ValidResponseOptions,
    /// Response*).
    fn raise_hard_error(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(hard_error::raise_hard_error(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6))))
    }

    fn window_station_type() -> u64 {
        win32::cell("ExWindowStationObjectType")
    }
    fn desktop_type() -> u64 {
        win32::cell("ExDesktopObjectType")
    }
    fn composition_type() -> u64 {
        win32::cell("ExCompositionObjectType")
    }
    fn raw_input_manager_type() -> u64 {
        win32::cell("ExRawInputManagerObjectType")
    }
    fn core_messaging_type() -> u64 {
        win32::cell("ExCoreMessagingObjectType")
    }
    fn activation_type() -> u64 {
        win32::cell("ExActivationObjectType")
    }
    fn timer_type() -> u64 {
        win32::cell("ExTimerObjectType")
    }

    pub static GROUP: Group = Group {
        name: "ex-hard-error",
        names: &["ExRaiseHardError"],
        handlers: &[raise_hard_error],
        data_exports: &[
            ("ExWindowStationObjectType", window_station_type),
            ("ExDesktopObjectType", desktop_type),
            ("ExCompositionObjectType", composition_type),
            ("ExRawInputManagerObjectType", raw_input_manager_type),
            ("ExCoreMessagingObjectType", core_messaging_type),
            ("ExActivationObjectType", activation_type),
            ("ExTimerObjectType", timer_type),
        ],
    };
}

pub mod ex_push_lock_convert {
    //! ExTryConvertPushLockSharedToExclusiveEx; a lógica mora em `ex/push_lock`.

    use crate::ntos::ex::push_lock;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// ExTryConvertPushLockSharedToExclusiveEx(PushLock, Flags) -> BOOLEAN.
    fn try_convert_shared_to_exclusive(call: &Call) -> Result<u64, KernelError> {
        Ok(push_lock::try_convert_shared_to_exclusive(call.arg(1), call.arg(2) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "ex-push-lock-convert",
        names: &["ExTryConvertPushLockSharedToExclusiveEx"],
        handlers: &[try_convert_shared_to_exclusive],
        data_exports: &[],
    };
}

pub mod ex_extension_unregister {
    //! ExUnregisterExtension; a lógica mora em `ex/extension_host`.

    use crate::ntos::ex::extension_host;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    /// ExUnregisterExtension(Extension).
    fn unregister_extension(call: &Call) -> Result<u64, KernelError> {
        extension_host::unregister_extension(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-extension-unregister",
        names: &["ExUnregisterExtension"],
        handlers: &[unregister_extension],
        data_exports: &[],
    };
}

pub mod ex_timer_resolution {
    //! ExSetTimerResolution; a lógica mora em `ke/clock`, junto do
    //! ExQueryTimerResolution.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::clock;
    use crate::rtl::KernelError;

    /// ExSetTimerResolution(DesiredTime, SetResolution) -> ULONG.
    fn set_timer_resolution(call: &Call) -> Result<u64, KernelError> {
        Ok(clock::set_timer_resolution(call.arg(1) as u32, call.arg(2) as u8 != 0) as u64)
    }

    pub static GROUP: Group = Group {
        name: "ex-timer-resolution",
        names: &["ExSetTimerResolution"],
        handlers: &[set_timer_resolution],
        data_exports: &[],
    };
}

pub mod zw_event {
    //! ZwCreateEvent, ZwSetEvent, ZwResetEvent e ZwClearEvent em KernelMode;
    //! a lógica mora em `ex/event`.

    use crate::ntos::ex::event;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// ZwCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState).
    fn create_event(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(event::create(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5) & 0xFF != 0)?))
    }
    fn set_event(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(event::set(call.arg(1), call.arg(2))?))
    }
    fn reset_event(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(event::reset(call.arg(1), call.arg(2))?))
    }
    fn clear_event(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(event::clear(call.arg(1))?))
    }

    pub static GROUP: Group = Group {
        name: "zw-event",
        names: &["ZwCreateEvent", "ZwSetEvent", "ZwResetEvent", "ZwClearEvent"],
        handlers: &[create_event, set_event, reset_event, clear_event],
        data_exports: &[],
    };
}

pub mod ex_wnf_subscription {
    //! ExSubscribeWnfStateChange e ExUnsubscribeWnfStateChange: as inscrições
    //! de kernel do motor WNF (`ex/wnf/service`).

    use crate::ntos::ex::wnf::service as wnf_service;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// ExSubscribeWnfStateChange(Subscription, StateName, DeliveryOption,
    /// CurrentChangeStamp, Callback, CallbackContext).
    fn subscribe(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(wnf_service::subscribe_kernel(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4) as u32, call.arg(5), call.arg(6))?))
    }
    fn unsubscribe(call: &Call) -> Result<u64, KernelError> {
        wnf_service::unsubscribe_kernel(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ex-wnf-subscription",
        names: &["ExSubscribeWnfStateChange", "ExUnsubscribeWnfStateChange"],
        handlers: &[subscribe, unsubscribe],
        data_exports: &[],
    };
}

pub mod ex_processor_feature {
    //! ExIsProcessorFeaturePresent; a lógica mora em `ex/processor_feature.rs`.

    use crate::ntos::ex::processor_feature;
    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;

    fn is_processor_feature_present(call: &Call) -> Result<u64, KernelError> {
        Ok(processor_feature::is_present(call.arg(1) as u32) as u64)
    }

    pub static GROUP: Group = Group { name: "ex-processor-feature", names: &["ExIsProcessorFeaturePresent"], handlers: &[is_processor_feature_present], data_exports: &[] };
}

pub mod pcw_instances {
    //! PcwCreateInstance/PcwCloseInstance (lógica em `ex/pcw.rs`: o ramo do
    //! ntoskrnl sem a extensão do pcw.sys).

    use crate::ntos::ex::pcw;
    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::rtl::KernelError;

    /// (PPCW_INSTANCE *Instance, Registration, Name, Count, Data).
    fn create_instance(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: ponteiro de saída vivo do driver, como no NT.
        let instance = unsafe { Field::<u64>::at(call.arg(1)) };
        Ok(signed_status(pcw::create_instance(instance, call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5))))
    }

    fn close_instance(call: &Call) -> Result<u64, KernelError> {
        pcw::close_instance(call.arg(1));
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "pcw-instances", names: &["PcwCreateInstance", "PcwCloseInstance"], handlers: &[create_instance, close_instance], data_exports: &[] };
}

pub mod ex_try_queue_work_item {
    //! ExTryQueueWorkItem; a lógica mora em `io/work_items.rs`, com a fila
    //! do ExQueueWorkItem.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::io::work_items;
    use crate::rtl::KernelError;

    fn try_queue_work_item(call: &Call) -> Result<u64, KernelError> {
        Ok(work_items::try_queue_ex_work_item(call.arg(1), call.arg(2) as u32) as u64)
    }

    pub static GROUP: Group = Group { name: "ex-try-queue-work-item", names: &["ExTryQueueWorkItem"], handlers: &[try_queue_work_item], data_exports: &[] };
}
