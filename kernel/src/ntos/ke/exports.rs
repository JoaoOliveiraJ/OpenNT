//! Exports Ke* (IRQL, spin locks, DPC, timers, eventos, waits, bugcheck,
//! APC, regiões críticas, processadores).
//!
//! Só adaptadores: a lógica mora nos arquivos de assunto do `ke`.

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::ke::{affinity, apc, bugcheck, bugcheck_reason, callout, clock, critical_region, debug_print, dispatcher, dpc, fast_mutex, interrupt_object, irql, pcr, process_attachment, processor_group, spin_lock, thread_dispatch, timer, version, xstate};
use crate::rtl::KernelError;

fn dbg_print(call: &Call) -> Result<u64, KernelError> {
    debug_print::dbg_print(call.arg(1), &call.args[1..7]).map(|()| 0)
}
fn dbg_print_ex(call: &Call) -> Result<u64, KernelError> {
    debug_print::dbg_print_ex(call.arg(1) as u32, call.arg(3), &call.args[3..8]).map(|()| 0)
}
fn query_system_time(call: &Call) -> Result<u64, KernelError> {
    clock::query_system_time(call.arg(1));
    Ok(0)
}
fn query_tick_count(call: &Call) -> Result<u64, KernelError> {
    clock::query_tick_count(call.arg(1));
    Ok(0)
}
fn get_current_irql(_: &Call) -> Result<u64, KernelError> {
    Ok(irql::get_irql() as u64)
}
fn raise_irql(call: &Call) -> Result<u64, KernelError> {
    irql::raise_irql_saving(call.arg(1) as u8, call.arg(2));
    Ok(0)
}
fn lower_irql(call: &Call) -> Result<u64, KernelError> {
    irql::lower_irql(call.arg(1) & 0xFF);
    Ok(0)
}
fn initialize_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::initialize(call.arg(1));
    Ok(0)
}
fn acquire_spin_lock_raise_to_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire(call.arg(1)) as u64)
}
fn release_spin_lock_export(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release(call.arg(1), call.arg(2));
    Ok(0)
}
fn acquire_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_at_dpc_level(call.arg(1));
    Ok(0)
}
fn release_spin_lock_from_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release_from_dpc_level(call.arg(1));
    Ok(0)
}
fn initialize_dpc(call: &Call) -> Result<u64, KernelError> {
    dpc::initialize_dpc(call.arg(1), call.arg(2), call.arg(3));
    Ok(0)
}
fn insert_queue_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(dpc::insert_queue_dpc(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn remove_queue_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(dpc::remove_queue_dpc(call.arg(1)) as u64)
}
fn get_current_processor_number(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::current_processor_number() as u64)
}
fn query_active_processor_count(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::active_processor_count())
}
fn query_active_processors(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::active_processors())
}
fn get_processor_number_from_index(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(processor_group::processor_number_from_index(call.arg(1), call.arg(2))))
}
fn initialize_timer(call: &Call) -> Result<u64, KernelError> {
    timer::initialize_notification_timer(call.arg(1));
    Ok(0)
}
fn initialize_timer_ex(call: &Call) -> Result<u64, KernelError> {
    timer::initialize_timer_of_type(call.arg(1), call.arg(2));
    Ok(0)
}
fn set_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::set_timer(call.arg(1), call.arg(2) as i64, call.arg(3), 0) as u64)
}
fn set_timer_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::set_timer(call.arg(1), call.arg(2) as i64, call.arg(4), call.arg(3) as u32) as u64)
}
fn cancel_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::cancel_timer(call.arg(1)) as u64)
}
fn read_state_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::read_state(call.arg(1)) as u64)
}
fn delay_execution_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::delay_execution_thread(call.arg(3), call.arg(1) as u8, call.arg(2) & 0xFF != 0)? as u64)
}
fn initialize_event(call: &Call) -> Result<u64, KernelError> {
    dispatcher::initialize_event(call.arg(1), call.arg(2) as u8, call.arg(3) & 0xFF != 0);
    Ok(0)
}
fn set_event(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::set_event(call.arg(1)) as u64)
}
fn clear_event(call: &Call) -> Result<u64, KernelError> {
    dispatcher::clear_event(call.arg(1));
    Ok(0)
}
fn reset_event(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::reset_event(call.arg(1)) as u64)
}
fn read_state_event(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::read_state(call.arg(1)) as u64)
}
fn initialize_mutex(call: &Call) -> Result<u64, KernelError> {
    dispatcher::initialize_mutex(call.arg(1), call.arg(2) as u32);
    Ok(0)
}
fn release_mutex(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::release_mutex(call.arg(1)) as u64)
}
fn wait_for_single_object(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::wait_for_single_object(call.arg(1), call.arg(5), call.arg(3) as u8, call.arg(4) & 0xFF != 0) as u64)
}
fn wait_for_multiple_objects(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::wait_for_multiple_objects(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(7), call.arg(5) as u8, call.arg(6) & 0xFF != 0) as u64)
}
fn query_performance_counter(call: &Call) -> Result<u64, KernelError> {
    Ok(clock::query_performance_counter(call.arg(1)))
}
fn stall_execution_processor(call: &Call) -> Result<u64, KernelError> {
    clock::stall_execution_processor(call.arg(1) as u32);
    Ok(0)
}
fn bug_check_ex(call: &Call) -> Result<u64, KernelError> {
    bugcheck::raise_bug_check(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5))
}
fn set_importance_dpc(call: &Call) -> Result<u64, KernelError> {
    dpc::set_importance(call.arg(1), call.arg(2) as u8);
    Ok(0)
}
fn set_target_processor_dpc(call: &Call) -> Result<u64, KernelError> {
    dpc::set_target_processor(call.arg(1), call.arg(2));
    Ok(0)
}
/// Drena a fila de DPCs na hora, como o NT.
fn flush_queued_dpcs(_: &Call) -> Result<u64, KernelError> {
    dpc::run_queue().map(|()| 1)
}
fn enter_critical_region(_: &Call) -> Result<u64, KernelError> {
    critical_region::enter_critical().map(|()| 0)
}
fn leave_critical_region(_: &Call) -> Result<u64, KernelError> {
    critical_region::leave_critical().map(|()| 0)
}
fn are_apcs_disabled(_: &Call) -> Result<u64, KernelError> {
    Ok(critical_region::disabled() as u64)
}
fn register_bug_check_callback(call: &Call) -> Result<u64, KernelError> {
    Ok(bugcheck::register_callback(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5)) as u64)
}
fn deregister_bug_check_callback(call: &Call) -> Result<u64, KernelError> {
    Ok(bugcheck::deregister_callback(call.arg(1)) as u64)
}
fn ps_get_version(call: &Call) -> Result<u64, KernelError> {
    Ok(version::get_version(call.arg(1), call.arg(2), call.arg(3), call.arg(4)) as u64)
}
fn kf_raise_irql(call: &Call) -> Result<u64, KernelError> {
    Ok(irql::kf_raise_irql(call.arg(1) as u8) as u64)
}
fn query_time_increment(_: &Call) -> Result<u64, KernelError> {
    Ok(clock::TIME_INCREMENT)
}
fn query_dpc_watchdog_information(call: &Call) -> Result<u64, KernelError> {
    dpc::query_watchdog_information(call.arg(1));
    Ok(0)
}
fn synchronize_execution(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_object::ke_synchronize_execution(call.arg(1), call.arg(2), call.arg(3)))
}
fn init_safe_boot_mode(_: &Call) -> Result<u64, KernelError> {
    Ok(version::safe_boot_mode())
}
fn initialize_semaphore(call: &Call) -> Result<u64, KernelError> {
    dispatcher::initialize_driver_semaphore(call.arg(1), call.arg(2) as u32, call.arg(3) as u32);
    Ok(0)
}
fn release_semaphore(call: &Call) -> Result<u64, KernelError> {
    Ok(dispatcher::release_driver_semaphore(call.arg(1), call.arg(3) as i32) as i64 as u64)
}
fn initialize_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::initialize(call.arg(1));
    Ok(0)
}
fn acquire_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::acquire(call.arg(1)).map(|_| 0)
}
fn release_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::release(call.arg(1)).map(|_| 0)
}
fn acquire_in_stack_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_in_stack_queued(call.arg(1), call.arg(2));
    Ok(0)
}
fn release_in_stack_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release_in_stack_queued(call.arg(1));
    Ok(0)
}
fn acquire_in_stack_queued_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_in_stack_queued_at_dpc_level(call.arg(1), call.arg(2));
    Ok(0)
}
fn release_in_stack_queued_spin_lock_from_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release_in_stack_queued_from_dpc_level(call.arg(1));
    Ok(0)
}
fn acquire_interrupt_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_object::acquire_interrupt_spin_lock(call.arg(1)) as u64)
}
fn release_interrupt_spin_lock(call: &Call) -> Result<u64, KernelError> {
    interrupt_object::release_interrupt_spin_lock(call.arg(1), call.arg(2));
    Ok(0)
}
fn register_bug_check_reason_callback(call: &Call) -> Result<u64, KernelError> {
    Ok(bugcheck_reason::register(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))? as u64)
}
/// A remoção não libera a memória do driver.
fn deregister_bug_check_reason_callback(call: &Call) -> Result<u64, KernelError> {
    Ok(bugcheck_reason::remove(call.arg(1))? as u64)
}
fn bug_check(call: &Call) -> Result<u64, KernelError> {
    bugcheck::raise_bug_check(call.arg(1) as u32, 0, 0, 0, 0)
}
fn expand_kernel_stack_and_callout_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(callout::expand_kernel_stack_and_callout(call.arg(1), call.arg(2), call.arg(5)) as i64 as u64)
}
/// Em x86-64 a coerência de DMA é do hardware.
fn flush_io_buffers(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn get_current_node_number(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::node_number())
}
fn query_highest_node_number(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::node_number())
}
fn query_maximum_processor_count_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::maximum_processor_count_ex(call.arg(1) as u32))
}
fn query_unbiased_interrupt_time(_: &Call) -> Result<u64, KernelError> {
    Ok(clock::unbiased_interrupt_time())
}
fn query_unbiased_interrupt_time_precise(call: &Call) -> Result<u64, KernelError> {
    clock::query_unbiased_interrupt_time_precise(call.arg(1));
    Ok(0)
}
/// A tolerância é otimização de energia: agenda como um timer normal.
fn set_coalescable_timer(call: &Call) -> Result<u64, KernelError> {
    Ok(timer::set_timer(call.arg(1), call.arg(2) as i64, call.arg(5), call.arg(3) as u32) as u64)
}
fn stack_attach_process(call: &Call) -> Result<u64, KernelError> {
    Ok(process_attachment::attach(call.arg(1), call.arg(2))? as u64)
}
fn unstack_detach_process(call: &Call) -> Result<u64, KernelError> {
    Ok(process_attachment::detach(call.arg(1))? as u64)
}
fn enter_guarded_region(_: &Call) -> Result<u64, KernelError> {
    critical_region::enter_guarded().map(|()| 0)
}
fn leave_guarded_region(_: &Call) -> Result<u64, KernelError> {
    critical_region::leave_guarded().map(|()| 0)
}
/// Uma região crítica isolada ainda permite APCs especiais de kernel.
fn are_all_apcs_disabled(_: &Call) -> Result<u64, KernelError> {
    Ok(critical_region::all_disabled() as u64)
}
fn get_current_processor_number_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::current_processor_number_ex(call.arg(1)) as u64)
}
fn query_active_processor_count_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::active_processor_count_ex(call.arg(1) as u32))
}
fn query_system_time_precise(call: &Call) -> Result<u64, KernelError> {
    clock::query_system_time(call.arg(1));
    Ok(0)
}
fn initialize_mutant(call: &Call) -> Result<u64, KernelError> {
    dispatcher::initialize_mutant(call.arg(1), call.arg(2) & 0xFF != 0);
    Ok(0)
}
fn initialize_apc(call: &Call) -> Result<u64, KernelError> {
    apc::initialize(call.arg(1), call.arg(2), call.arg(3) as u8, call.arg(4), call.arg(5), call.arg(6), call.arg(7) as u8, call.arg(8));
    Ok(0)
}
fn insert_queue_apc(call: &Call) -> Result<u64, KernelError> {
    Ok(apc::insert(call.arg(1), call.arg(2), call.arg(3)) as u64)
}
fn ipi_generic_call(call: &Call) -> Result<u64, KernelError> {
    Ok(callout::ipi_generic_call(call.arg(1), call.arg(2)))
}
fn save_extended_processor_state(call: &Call) -> Result<u64, KernelError> {
    xstate::save(call.arg(1), call.arg(2));
    Ok(0)
}
fn restore_extended_processor_state(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(xstate::restore(call.arg(1))))
}
/// Aceita e segue (o ajuste de prioridade real é o KeSetBasePriorityThread).
fn set_actual_base_priority_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn try_to_acquire_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    Ok(fast_mutex::try_acquire(call.arg(1))? as u64)
}
fn acquire_guarded_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::acquire_guarded_unsafe(call.arg(1)).map(|_| 0)
}
fn release_guarded_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::release_guarded_unsafe(call.arg(1)).map(|_| 0)
}

pub static GROUP: Group = Group {
    name: "ke",
    names: &[
        "DbgPrint", "DbgPrintEx", "KeQuerySystemTime", "KeQueryTickCount", "KeGetCurrentIrql", "KeRaiseIrql", "KeLowerIrql", "KeInitializeSpinLock",
        "KeAcquireSpinLockRaiseToDpc", "KfAcquireSpinLock", "KfReleaseSpinLock", "KefAcquireSpinLockAtDpcLevel", "KefReleaseSpinLockFromDpcLevel",
        "KeInitializeDpc", "KeInsertQueueDpc", "KeRemoveQueueDpc", "KeReleaseSpinLock", "KeGetCurrentProcessorNumber", "KeQueryActiveProcessorCount", "KeQueryActiveProcessors", "KeGetProcessorNumberFromIndex",
        "KeInitializeTimer", "KeInitializeTimerEx", "KeSetTimer", "KeSetTimerEx", "KeCancelTimer", "KeReadStateTimer", "KeDelayExecutionThread",
        "KeInitializeEvent", "KeSetEvent", "KeClearEvent", "KeResetEvent", "KeReadStateEvent", "KeInitializeMutex", "KeReleaseMutex", "KeWaitForSingleObject", "KeWaitForMultipleObjects",
        "KeQueryPerformanceCounter", "KeStallExecutionProcessor", "KeBugCheckEx", "KeSetImportanceDpc", "KeSetTargetProcessorDpc", "KeFlushQueuedDpcs",
        "KeEnterCriticalRegion", "KeLeaveCriticalRegion", "KeAreApcsDisabled", "KeRegisterBugCheckCallback", "KeDeregisterBugCheckCallback", "KeAcquireSpinLockAtDpcLevel", "KeReleaseSpinLockFromDpcLevel",
        "PsGetVersion", "KfRaiseIrql", "KeQueryTimeIncrement", "KeQueryDpcWatchdogInformation", "KeSynchronizeExecution", "InitSafeBootMode", "KeInitializeSemaphore", "KeReleaseSemaphore",
        "KeInitializeGuardedMutex", "KeAcquireGuardedMutex", "KeReleaseGuardedMutex", "KeAcquireInStackQueuedSpinLock", "KeReleaseInStackQueuedSpinLock", "KeAcquireInStackQueuedSpinLockAtDpcLevel", "KeReleaseInStackQueuedSpinLockFromDpcLevel",
        "KeAcquireInterruptSpinLock", "KeReleaseInterruptSpinLock", "KeRegisterBugCheckReasonCallback", "KeDeregisterBugCheckReasonCallback", "KeBugCheck", "KeExpandKernelStackAndCalloutEx", "KeFlushIoBuffers",
        "KeGetCurrentNodeNumber", "KeQueryHighestNodeNumber", "KeQueryMaximumProcessorCountEx", "KeQueryUnbiasedInterruptTime", "KeQueryUnbiasedInterruptTimePrecise", "KeSetCoalescableTimer",
        "KeStackAttachProcess", "KeUnstackDetachProcess", "KeEnterGuardedRegion", "KeLeaveGuardedRegion", "KeAreAllApcsDisabled", "KeGetCurrentProcessorNumberEx", "KeQueryActiveProcessorCountEx", "KeQuerySystemTimePrecise",
        "KeInitializeMutant", "KeInitializeApc", "KeInsertQueueApc", "KeIpiGenericCall", "KeSaveExtendedProcessorState", "KeRestoreExtendedProcessorState", "KeSetActualBasePriorityThread",
        "KeTryToAcquireGuardedMutex", "KeAcquireGuardedMutexUnsafe", "KeReleaseGuardedMutexUnsafe",
    ],
    handlers: &[
        dbg_print, dbg_print_ex, query_system_time, query_tick_count, get_current_irql, raise_irql, lower_irql, initialize_spin_lock,
        acquire_spin_lock_raise_to_dpc, acquire_spin_lock_raise_to_dpc, release_spin_lock_export, acquire_spin_lock_at_dpc, release_spin_lock_from_dpc,
        initialize_dpc, insert_queue_dpc, remove_queue_dpc, release_spin_lock_export, get_current_processor_number, query_active_processor_count, query_active_processors, get_processor_number_from_index,
        initialize_timer, initialize_timer_ex, set_timer, set_timer_ex, cancel_timer, read_state_timer, delay_execution_thread,
        initialize_event, set_event, clear_event, reset_event, read_state_event, initialize_mutex, release_mutex, wait_for_single_object, wait_for_multiple_objects,
        query_performance_counter, stall_execution_processor, bug_check_ex, set_importance_dpc, set_target_processor_dpc, flush_queued_dpcs,
        enter_critical_region, leave_critical_region, are_apcs_disabled, register_bug_check_callback, deregister_bug_check_callback, acquire_spin_lock_at_dpc, release_spin_lock_from_dpc,
        ps_get_version, kf_raise_irql, query_time_increment, query_dpc_watchdog_information, synchronize_execution, init_safe_boot_mode, initialize_semaphore, release_semaphore,
        initialize_guarded_mutex, acquire_guarded_mutex, release_guarded_mutex, acquire_in_stack_queued_spin_lock, release_in_stack_queued_spin_lock, acquire_in_stack_queued_spin_lock_at_dpc, release_in_stack_queued_spin_lock_from_dpc,
        acquire_interrupt_spin_lock, release_interrupt_spin_lock, register_bug_check_reason_callback, deregister_bug_check_reason_callback, bug_check, expand_kernel_stack_and_callout_ex, flush_io_buffers,
        get_current_node_number, query_highest_node_number, query_maximum_processor_count_ex, query_unbiased_interrupt_time, query_unbiased_interrupt_time_precise, set_coalescable_timer,
        stack_attach_process, unstack_detach_process, enter_guarded_region, leave_guarded_region, are_all_apcs_disabled, get_current_processor_number_ex, query_active_processor_count_ex, query_system_time_precise,
        initialize_mutant, initialize_apc, insert_queue_apc, ipi_generic_call, save_extended_processor_state, restore_extended_processor_state, set_actual_base_priority_thread,
        try_to_acquire_guarded_mutex, acquire_guarded_mutex_unsafe, release_guarded_mutex_unsafe,
    ],
    data_exports: &[("KiBugCheckData", bugcheck::bug_check_data), ("KeNumberProcessors", processor_group::number_processors_cell)],
};

// ---- KeQueryPrcbAddress, KeQueryPriorityThread e KeQueryRuntimeThread -------
// (grupo "processor-queries", no fim da ABI)

fn query_prcb_address(call: &Call) -> Result<u64, KernelError> {
    Ok(pcr::query_prcb_address(call.arg(1) as u32))
}

fn query_priority_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::ke::thread_priority::query_priority(call.arg(1)) as i64 as u64)
}

fn query_runtime_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(thread_dispatch::query_runtime_thread(call.arg(1), call.arg(2)))
}

// ---- spin locks numerados, ForDpc, RaiseToSynch, Test/TryTo -------------

fn acquire_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_queued(call.arg(1))? as u64)
}
fn acquire_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_queued_raise_to_synch(call.arg(1))? as u64)
}
fn release_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release_queued(call.arg(1), call.arg(2)).map(|()| 0)
}
fn try_to_acquire_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_to_acquire_queued(call.arg(1), call.arg(2))? as u64)
}
fn try_to_acquire_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_to_acquire_queued_raise_to_synch(call.arg(1), call.arg(2))? as u64)
}
fn acquire_in_stack_queued_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_in_stack_queued_for_dpc(call.arg(1), call.arg(2));
    Ok(0)
}
fn acquire_in_stack_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    spin_lock::acquire_in_stack_queued_raise_to_synch(call.arg(1), call.arg(2));
    Ok(0)
}
fn release_in_stack_queued_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release_in_stack_queued(call.arg(1));
    Ok(0)
}
fn acquire_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_for_dpc(call.arg(1)) as u64)
}
fn release_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_lock::release(call.arg(1), call.arg(2));
    Ok(0)
}
fn acquire_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::acquire_raise_to_synch(call.arg(1)) as u64)
}
fn test_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::test(call.arg(1)) as u64)
}
fn try_to_acquire_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(spin_lock::try_to_acquire_at_dpc_level(call.arg(1)) as u64)
}

pub static QUEUED_SPIN_LOCKS_GROUP: Group = Group {
    name: "queued-spin-locks",
    names: &[
        "KeAcquireQueuedSpinLock", "KeAcquireQueuedSpinLockRaiseToSynch", "KeReleaseQueuedSpinLock", "KeTryToAcquireQueuedSpinLock",
        "KeTryToAcquireQueuedSpinLockRaiseToSynch", "KeAcquireInStackQueuedSpinLockForDpc", "KeAcquireInStackQueuedSpinLockRaiseToSynch",
        "KeReleaseInStackQueuedSpinLockForDpc", "KeAcquireSpinLockForDpc", "KeReleaseSpinLockForDpc", "KeAcquireSpinLockRaiseToSynch",
        "KeTestSpinLock", "KeTryToAcquireSpinLockAtDpcLevel",
    ],
    handlers: &[
        acquire_queued_spin_lock, acquire_queued_spin_lock_raise_to_synch, release_queued_spin_lock, try_to_acquire_queued_spin_lock,
        try_to_acquire_queued_spin_lock_raise_to_synch, acquire_in_stack_queued_spin_lock_for_dpc, acquire_in_stack_queued_spin_lock_raise_to_synch,
        release_in_stack_queued_spin_lock_for_dpc, acquire_spin_lock_for_dpc, release_spin_lock_for_dpc, acquire_spin_lock_raise_to_synch,
        test_spin_lock, try_to_acquire_spin_lock_at_dpc,
    ],
    data_exports: &[],
};

// ---- afinidade e grupos de processadores ----------------------------------

fn set_system_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    affinity::set_system_affinity_thread(call.arg(1));
    Ok(0)
}
fn set_system_affinity_thread_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(affinity::set_system_affinity_thread_ex(call.arg(1)))
}
fn revert_to_user_affinity_thread(_: &Call) -> Result<u64, KernelError> {
    affinity::revert_to_user_affinity_thread();
    Ok(0)
}
fn revert_to_user_affinity_thread_ex(call: &Call) -> Result<u64, KernelError> {
    affinity::revert_to_user_affinity_thread_ex(call.arg(1));
    Ok(0)
}
fn set_system_group_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    affinity::set_system_group_affinity_thread(call.arg(1), call.arg(2));
    Ok(0)
}
fn revert_to_user_group_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    affinity::revert_to_user_group_affinity_thread(call.arg(1));
    Ok(0)
}
fn set_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(affinity::set_affinity_thread(call.arg(1), call.arg(2)))
}
fn set_ideal_processor_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(affinity::set_ideal_processor_thread(call.arg(1), call.arg(2) as u8) as u64)
}
fn query_active_group_count(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::group_count())
}
fn query_maximum_group_count(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::group_count())
}
fn query_maximum_processor_count(_: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::maximum_processor_count())
}
fn query_group_affinity(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::group_affinity(call.arg(1) as u16))
}
fn query_node_active_affinity(call: &Call) -> Result<u64, KernelError> {
    processor_group::query_node_active_affinity(call.arg(1) as u16, call.arg(2), call.arg(3));
    Ok(0)
}
fn query_node_maximum_processor_count(call: &Call) -> Result<u64, KernelError> {
    Ok(processor_group::node_maximum_processor_count(call.arg(1) as u16))
}
fn set_target_processor_dpc_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(dpc::set_target_processor_ex(call.arg(1), call.arg(2))))
}

pub static AFFINITY_GROUP: Group = Group {
    name: "affinity",
    names: &[
        "KeSetSystemAffinityThread", "KeSetSystemAffinityThreadEx", "KeRevertToUserAffinityThread", "KeRevertToUserAffinityThreadEx",
        "KeSetSystemGroupAffinityThread", "KeRevertToUserGroupAffinityThread", "KeSetAffinityThread", "KeSetIdealProcessorThread",
        "KeQueryActiveGroupCount", "KeQueryMaximumGroupCount", "KeQueryMaximumProcessorCount", "KeQueryGroupAffinity",
        "KeQueryNodeActiveAffinity", "KeQueryNodeMaximumProcessorCount", "KeSetTargetProcessorDpcEx",
    ],
    handlers: &[
        set_system_affinity_thread, set_system_affinity_thread_ex, revert_to_user_affinity_thread, revert_to_user_affinity_thread_ex,
        set_system_group_affinity_thread, revert_to_user_group_affinity_thread, set_affinity_thread, set_ideal_processor_thread,
        query_active_group_count, query_maximum_group_count, query_maximum_processor_count, query_group_affinity,
        query_node_active_affinity, query_node_maximum_processor_count, set_target_processor_dpc_ex,
    ],
    data_exports: &[],
};

// ---- KeGenericCallDpc ---------------------------------------------------

fn generic_call_dpc(call: &Call) -> Result<u64, KernelError> {
    callout::generic_call_dpc(call.arg(1), call.arg(2)).map(|()| 0)
}
fn signal_call_dpc_done(call: &Call) -> Result<u64, KernelError> {
    callout::signal_call_dpc_done(call.arg(1));
    Ok(0)
}
fn signal_call_dpc_synchronize(call: &Call) -> Result<u64, KernelError> {
    Ok(callout::signal_call_dpc_synchronize(call.arg(1)) as u64)
}

pub static GENERIC_CALL_DPC_GROUP: Group = Group {
    name: "generic-call-dpc",
    names: &["KeGenericCallDpc", "KeSignalCallDpcDone", "KeSignalCallDpcSynchronize"],
    handlers: &[generic_call_dpc, signal_call_dpc_done, signal_call_dpc_synchronize],
    data_exports: &[],
};

pub static PROCESSOR_QUERIES_GROUP: Group = Group {
    name: "processor-queries",
    names: &["KeQueryPrcbAddress", "KeQueryPriorityThread", "KeQueryRuntimeThread"],
    handlers: &[query_prcb_address, query_priority_thread, query_runtime_thread],
    data_exports: &[],
};

pub mod test_alert {
    //! KeTestAlertThread.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ke::test_alert;

    fn test_alert_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(test_alert::test(call.arg(1))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "test-alert",
        names: &["KeTestAlertThread"],
        handlers: &[test_alert_thread],
        data_exports: &[],
    };
}

pub mod thread_base_priority {
    //! KeSetBasePriorityThread.
    //!
    //! Qualquer falha interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ke::thread_priority;

    fn set_thread_base_priority(call: &Call) -> Result<u64, KernelError> {
        match thread_priority::set_base_priority(call.arg(1), call.arg(2)) {
            Ok(previous) => Ok(previous as i64 as u64),
            Err(error) => {
                debug_print!("[thread-base-priority] falha de kernel: {}", error);
                crate::hal::cpu::halt_forever()
            }
        }
    }

    pub static GROUP: Group = Group {
        name: "thread-base-priority",
        names: &["KeSetBasePriorityThread"],
        handlers: &[set_thread_base_priority],
        data_exports: &[],
    };
}

pub mod thread_priority {
    //! KeSetPriorityThread.
    //!
    //! Qualquer falha interna interrompe o sistema.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ke::thread_priority;

    fn set_thread_priority(call: &Call) -> Result<u64, KernelError> {
        match thread_priority::set_priority(call.arg(1), call.arg(2)) {
            Ok(previous) => Ok(previous as i64 as u64),
            Err(error) => {
                debug_print!("[thread-priority] fatal kernel failure: {}", error);
                crate::hal::cpu::halt_forever()
            }
        }
    }

    pub static GROUP: Group = Group {
        name: "thread-priority",
        names: &["KeSetPriorityThread"],
        handlers: &[set_thread_priority],
        data_exports: &[],
    };
}

pub mod persistent_thread_state {
    //! KeCapturePersistentThreadState — `ntos/ke/persistent_thread_state`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::persistent_thread_state;
    use crate::rtl::KernelError;

    fn capture(call: &Call) -> Result<u64, KernelError> {
        persistent_thread_state::capture(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))
    }

    pub static GROUP: Group = Group { name: "persistent-thread-state", names: &["KeCapturePersistentThreadState"], handlers: &[capture], data_exports: &[] };
}

pub mod alert_thread {
    //! ZwAlertThread.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::ps::alert_thread;

    fn alert(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("alert-thread", alert_thread::alert(call.arg(1), 0))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "alert-thread",
        names: &["ZwAlertThread"],
        handlers: &[alert],
        data_exports: &[],
    };
}

pub mod ke_ex_sync {
    //! Sincronização e miscelânea Ke/Ex que o dxgkrnl.sys real importa e que
    //! faltavam: anexação legada de processo, KePulseEvent, leitura de mutante,
    //! tempo de interrupção preciso, o par região-crítica + fast-mutex-unsafe, e
    //! as constantes/stubs de firmware e licença. Tudo é um invólucro fiel sobre
    //! o que o OpenNT já tem (eventos/mutantes no `dispatcher`, anexação no
    //! `process_attachment`, relógio no `clock`, mutex rápido e região crítica no
    //! `fast_mutex`, tipo de firmware no `ex::boot_environment`); onde o
    //! subsistema não existe (IOMMU sharing, licença fast-cache) devolve o
    //! NTSTATUS que o Windows devolve quando o recurso está inerte. Também
    //! atende storport/ndis nos nomes genéricos (mutex rápido + região crítica,
    //! ExGetFirmwareType, etc.).

    use crate::ntos::ex::boot_environment;
    use crate::ntos::inc::status::STATUS_NOT_SUPPORTED;
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ke::{clock, dispatcher, fast_mutex, process_attachment};
    use crate::rtl::KernelError;

    fn attach_process(call: &Call) -> Result<u64, KernelError> {
        process_attachment::attach_legacy(call.arg(1)).map(|()| 0)
    }

    fn detach_process(_: &Call) -> Result<u64, KernelError> {
        process_attachment::detach_legacy().map(|()| 0)
    }

    fn is_attached_process(_: &Call) -> Result<u64, KernelError> {
        Ok(process_attachment::is_attached() as u64)
    }

    fn pulse_event(call: &Call) -> Result<u64, KernelError> {
        Ok(dispatcher::pulse_event(call.arg(1)) as u64)
    }

    fn query_interrupt_time_precise(call: &Call) -> Result<u64, KernelError> {
        Ok(clock::query_interrupt_time_precise(call.arg(1)))
    }

    /// KeReadStateMutant / KeReadStateMutex (mesmo RVA 0x26e9c0): devolve o
    /// SignalState do mutante (LONG). Um único handler, dois nomes.
    fn read_state_mutant(call: &Call) -> Result<u64, KernelError> {
        Ok(dispatcher::read_state(call.arg(1)) as u64)
    }

    fn enter_critical_region_and_acquire_fast_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
        fast_mutex::enter_critical_region_and_acquire_unsafe(call.arg(1))
    }

    fn release_fast_mutex_unsafe_and_leave_critical_region(call: &Call) -> Result<u64, KernelError> {
        fast_mutex::release_unsafe_and_leave_critical_region(call.arg(1)).map(|()| 0)
    }

    fn get_firmware_type(_: &Call) -> Result<u64, KernelError> {
        Ok(boot_environment::get_firmware_type())
    }

    /// ExIsManufacturingModeEnabled(void): modo de fábrica desligado (FALSE).
    fn is_manufacturing_mode_enabled(_: &Call) -> Result<u64, KernelError> {
        Ok(0)
    }

    /// ExShareAddressSpaceWithDevice(...): sem motor de compartilhamento
    /// IOMMU/ATS — STATUS_NOT_SUPPORTED, como o Windows quando o recurso falta.
    fn share_address_space_with_device(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_SUPPORTED))
    }

    /// ExQueryFastCacheDevLicense(...): sem blob de licença "fast cache"
    /// (DRM) — STATUS_NOT_SUPPORTED.
    fn query_fast_cache_dev_license(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_SUPPORTED))
    }

    pub static GROUP: Group = Group {
        name: "ke-ex-sync",
        names: &[
            "KeAttachProcess", "KeDetachProcess", "KeIsAttachedProcess", "KePulseEvent",
            "KeQueryInterruptTimePrecise", "KeReadStateMutant", "KeReadStateMutex",
            "ExEnterCriticalRegionAndAcquireFastMutexUnsafe", "ExReleaseFastMutexUnsafeAndLeaveCriticalRegion",
            "ExGetFirmwareType", "ExIsManufacturingModeEnabled", "ExShareAddressSpaceWithDevice",
            "ExQueryFastCacheDevLicense",
        ],
        handlers: &[
            attach_process, detach_process, is_attached_process, pulse_event,
            query_interrupt_time_precise, read_state_mutant, read_state_mutant, // KeReadStateMutex é alias
            enter_critical_region_and_acquire_fast_mutex_unsafe, release_fast_mutex_unsafe_and_leave_critical_region,
            get_firmware_type, is_manufacturing_mode_enabled, share_address_space_with_device,
            query_fast_cache_dev_license,
        ],
        data_exports: &[],
    };
}

// =============================================================================

pub mod ke_processors {
    //! Processadores, topologia, ciclos e DPCs encadeadas: só adaptadores.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::{Field, Kdpc, NtStruct, ProcessorNumber};
    use crate::ntos::ke::{dpc, processor_group, processor_topology, thread_dispatch};
    use crate::rtl::KernelError;

    fn get_recommended_shared_data_alignment(_: &Call) -> Result<u64, KernelError> {
        Ok(processor_topology::recommended_shared_data_alignment()? as u64)
    }
    fn get_processor_index_from_number(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PPROCESSOR_NUMBER do driver.
        Ok(processor_group::processor_index_from_number(unsafe { ProcessorNumber::at(call.arg(1)) }))
    }
    fn query_logical_processor_relationship(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PPROCESSOR_NUMBER opcional do driver.
        let number = (call.arg(1) != 0).then(|| unsafe { ProcessorNumber::at(call.arg(1)) });
        Ok(signed_status(processor_topology::query_logical_processor_relationship(number, call.arg(2) as u32, call.arg(3), call.arg(4))?))
    }
    fn query_total_cycle_time_thread(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PULONG64 CycleTimeStamp opcional do driver.
        let stamp = (call.arg(2) != 0).then(|| unsafe { Field::<u64>::at(call.arg(2)) });
        Ok(thread_dispatch::query_total_cycle_time(call.arg(1), stamp))
    }
    fn should_yield_processor(_: &Call) -> Result<u64, KernelError> {
        Ok(thread_dispatch::should_yield_processor() as u64)
    }
    fn register_processor_change_callback(call: &Call) -> Result<u64, KernelError> {
        processor_group::register_processor_change_callback(call.arg(1), call.arg(2), call.arg(3) as u32)
    }
    fn deregister_processor_change_callback(call: &Call) -> Result<u64, KernelError> {
        processor_group::deregister_processor_change_callback(call.arg(1)).map(|()| 0)
    }
    fn initialize_threaded_dpc(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PRKDPC do driver.
        dpc::initialize_threaded_dpc(unsafe { Kdpc::at(call.arg(1)) }, call.arg(2), call.arg(3));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "ke-processors",
        names: &[
            "KeGetRecommendedSharedDataAlignment",
            "KeGetProcessorIndexFromNumber",
            "KeQueryLogicalProcessorRelationship",
            "KeQueryTotalCycleTimeThread",
            "KeShouldYieldProcessor",
            "KeRegisterProcessorChangeCallback",
            "KeDeregisterProcessorChangeCallback",
            "KeInitializeThreadedDpc",
        ],
        handlers: &[
            get_recommended_shared_data_alignment,
            get_processor_index_from_number,
            query_logical_processor_relationship,
            query_total_cycle_time_thread,
            should_yield_processor,
            register_processor_change_callback,
            deregister_processor_change_callback,
            initialize_threaded_dpc,
        ],
        data_exports: &[],
    };
}

pub mod ke_kernel_stacks {
    //! Callouts com pilha expandida e contextos de pilha de callout: só adaptadores.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::inc::types::{Field, Kthread, NtStruct};
    use crate::ntos::ke::callout::{self, CalloutStackContext};
    use crate::ntos::ps::process;
    use crate::rtl::KernelError;

    fn expand_kernel_stack_and_callout(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(callout::expand_kernel_stack_and_callout_internal(call.arg(1), call.arg(2), call.arg(3))))
    }
    fn set_kernel_stack_swap_enable(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: a KTHREAD corrente (o export só existe com uma thread corrente).
        let thread = unsafe { Kthread::at(process::get_current_thread()) };
        Ok(callout::set_kernel_stack_swap_enable(thread, call.arg(1) & 0xFF != 0) as u64)
    }
    fn allocate_callout_stack(call: &Call) -> Result<u64, KernelError> {
        callout::allocate_callout_stack(call.arg(1) & 0xFF != 0)
    }
    fn allocate_callout_stack_ex(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PVOID* Context de saída do driver.
        let output = unsafe { Field::<u64>::at(call.arg(4)) };
        Ok(signed_status(callout::allocate_callout_stack_ex(call.arg(1) as u32, call.arg(2) as u8, call.arg(3), output)?))
    }
    fn free_callout_stack(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o contexto devolvido por KeAllocateCalloutStack(Ex).
        callout::free_callout_stack(unsafe { CalloutStackContext::at(call.arg(1)) }).map(|()| 0)
    }

    pub static GROUP: Group = Group {
        name: "ke-kernel-stacks",
        names: &[
            "KeExpandKernelStackAndCallout",
            "KeSetKernelStackSwapEnable",
            "KeAllocateCalloutStack",
            "KeAllocateCalloutStackEx",
            "KeFreeCalloutStack",
        ],
        handlers: &[
            expand_kernel_stack_and_callout,
            set_kernel_stack_swap_enable,
            allocate_callout_stack,
            allocate_callout_stack_ex,
            free_callout_stack,
        ],
        data_exports: &[],
    };
}

pub mod ke_service_tables {
    //! Tabelas de serviço adicionais (win32k e filtro): só adaptadores.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::service_tables;
    use crate::rtl::KernelError;

    /// KeAddSystemServiceTable(Base, Count, Limit, Number, Index).
    fn add_system_service_table(call: &Call) -> Result<u64, KernelError> {
        Ok(service_tables::add(call.arg(1), call.arg(3) as u32, call.arg(4), call.arg(5) as u32)? as u64)
    }
    fn remove_system_service_table(call: &Call) -> Result<u64, KernelError> {
        Ok(service_tables::remove(call.arg(1) as u32)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "ke-service-tables",
        names: &["KeAddSystemServiceTable", "KeRemoveSystemServiceTable"],
        handlers: &[add_system_service_table, remove_system_service_table],
        data_exports: &[],
    };
}

pub mod ke_queues {
    //! Objetos KQUEUE: só adaptadores.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::inc::types::{Kqueue, ListEntry, NtStruct};
    use crate::ntos::ke::queue;
    use crate::rtl::KernelError;

    /// O PRKQUEUE do driver.
    fn kqueue(address: u64) -> &'static Kqueue {
        // SAFETY: KQUEUE do chamador (memória de driver ou do kernel).
        unsafe { Kqueue::at(address) }
    }

    fn initialize_queue(call: &Call) -> Result<u64, KernelError> {
        queue::initialize(kqueue(call.arg(1)), call.arg(2) as u32);
        Ok(0)
    }
    fn read_state_queue(call: &Call) -> Result<u64, KernelError> {
        Ok(queue::read_state(kqueue(call.arg(1))) as i64 as u64)
    }
    fn insert_queue(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PLIST_ENTRY do chamador.
        Ok(queue::insert_entry(kqueue(call.arg(1)), unsafe { ListEntry::at(call.arg(2)) }, false) as i64 as u64)
    }
    fn insert_head_queue(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PLIST_ENTRY do chamador.
        Ok(queue::insert_entry(kqueue(call.arg(1)), unsafe { ListEntry::at(call.arg(2)) }, true) as i64 as u64)
    }
    /// KeRemoveQueue(Queue, WaitMode, Timeout).
    fn remove_queue(call: &Call) -> Result<u64, KernelError> {
        queue::remove(kqueue(call.arg(1)), call.arg(3))
    }
    /// KeRemoveQueueEx(Queue, WaitMode, Alertable, Timeout, Array, Count).
    fn remove_queue_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(queue::remove_ex(kqueue(call.arg(1)), call.arg(4), call.arg(5), call.arg(6) as u32)? as u64)
    }
    fn rundown_queue(call: &Call) -> Result<u64, KernelError> {
        Ok(queue::rundown(kqueue(call.arg(1))))
    }

    pub static GROUP: Group = Group {
        name: "ke-queues",
        names: &[
            "KeInitializeQueue",
            "KeReadStateQueue",
            "KeInsertQueue",
            "KeInsertHeadQueue",
            "KeRemoveQueue",
            "KeRemoveQueueEx",
            "KeRundownQueue",
        ],
        handlers: &[initialize_queue, read_state_queue, insert_queue, insert_head_queue, remove_queue, remove_queue_ex, rundown_queue],
        data_exports: &[],
    };
}

pub mod ke_user_callback {
    //! KeUserModeCallback; a lógica mora em `ke/user_callback`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ke::user_callback;
    use crate::rtl::KernelError;

    /// KeUserModeCallback(ApiNumber, InputBuffer, InputLength, OutputBuffer*,
    /// OutputLength*).
    fn user_mode_callback(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(user_callback::user_mode_callback(call.arg(1) as u32, call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5))?))
    }

    pub static GROUP: Group = Group { name: "ke-user-callback", names: &["KeUserModeCallback"], handlers: &[user_mode_callback], data_exports: &[] };
}

pub mod zw_yield_execution {
    //! ZwYieldExecution; a lógica mora em `ke/thread_dispatch` (as threads de
    //! sistema nativas cedem pela interceptação de `ps/kernel_threads`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ke::thread_dispatch;
    use crate::rtl::KernelError;

    fn yield_execution(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(thread_dispatch::yield_execution()?))
    }

    pub static GROUP: Group = Group { name: "zw-yield-execution", names: &["ZwYieldExecution"], handlers: &[yield_execution], data_exports: &[] };
}
