//! Exports Ke* (IRQL, spin locks, DPC, timers, eventos, waits, bugcheck,
//! APC, regiões críticas, processadores) — `system32/win32/ntoskrnl/ke.js`.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::hal::cpu;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{apc, bugcheck, bugcheck_reason, clock, critical_region, dispatcher, dpc, fast_mutex, interrupt_object, irql, process_attachment, smp, timer};
use crate::ntos::po::black_box;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::nt_abi::{dispatcher_header, kdpc, kinterrupt, ktimer};

/// Registros de KeRegisterBugCheckCallback (rotina, componente, contexto).
static BUG_CHECK_CALLBACKS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
/// KiBugCheckData: código e quatro parâmetros do último bugcheck.
static BUG_CHECK_DATA: AtomicU64 = AtomicU64::new(0);
/// KeNumberProcessors: célula u32 gravada no primeiro acesso (depois do SMP).
static NUMBER_PROCESSORS: AtomicU64 = AtomicU64::new(0);

fn lazy_cell(cell: &AtomicU64, size: u64, initialize: impl FnOnce(u64)) -> u64 {
    let current = cell.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let pointer = guest::alloc_bytes(size);
    initialize(pointer);
    match cell.compare_exchange(0, pointer, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => pointer,
        Err(existing) => {
            guest::free_bytes(pointer);
            existing
        }
    }
}

fn bug_check_data() -> u64 {
    lazy_cell(&BUG_CHECK_DATA, 5 * 8, |_| {})
}

fn number_processors_cell() -> u64 {
    lazy_cell(&NUMBER_PROCESSORS, 4, |pointer| guest::write32(pointer, smp::online_cpu_count() as u32))
}

/// Parada fatal comum: grava KiBugCheckData, roda os callbacks registrados,
/// publica os dados secundários e o black box e para a máquina.
/// KeBugCheckEx para os demais grupos.
pub fn raise_bug_check(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    do_bug_check(code, first, second, third, fourth)
}

fn do_bug_check(code: u32, first: u64, second: u64, third: u64, fourth: u64) -> ! {
    let data = bug_check_data();
    guest::write64(data, code as u64);
    guest::write64(data + 8, first);
    guest::write64(data + 16, second);
    guest::write64(data + 24, third);
    guest::write64(data + 32, fourth);
    debug_print!("");
    debug_print!("*** STOP (KeBugCheckEx): {:#010x} ({:#x}, {:#x}, {:#x}, {:#x})", code, first, second, third, fourth);
    let callbacks = BUG_CHECK_CALLBACKS.lock().clone();
    for record in callbacks {
        let routine = guest::read64(record);
        if routine != 0 {
            native_call::call(routine, &[record, 0]);
        }
    }
    if let Err(error) = bugcheck_reason::publish_secondary_data(0) {
        debug_print!("[bugcheck] dados secundarios: {}", error);
    }
    black_box::publish_crash_records();
    cpu::halt_forever()
}

/// Spin lock com test-and-set; devolve o IRQL antigo.
fn acquire_spin_lock(pointer: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(2);
    spin_at_dpc(pointer);
    previous
}

/// Uma tentativa de posse: o bit 0 do KSPIN_LOCK, trocado atomicamente
/// (o InterlockedBitTestAndSet64 do NT), para que dois processadores nunca
/// saiam com o mesmo lock.
fn try_spin(pointer: u64) -> bool {
    let value = guest::read64(pointer);
    value & 1 == 0 && guest::compare_exchange64(pointer, value, value | 1).unwrap_or_else(|error| panic!("{error}")) == value
}

fn spin_at_dpc(pointer: u64) {
    while !try_spin(pointer) {
        core::hint::spin_loop();
    }
}

/// KIRQL é UCHAR: só o byte baixo do registrador vale.
fn release_spin_lock(pointer: u64, new_irql: u64) {
    guest::write64(pointer, 0);
    irql::lower_irql(new_irql & 0xFF);
}

fn system_time() -> u64 {
    clock::now_ms() * 10_000 + 116_444_736_000_000_000
}

fn print_formatted(prefix: &str, format_pointer: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let format_text = guest_strings::read_c_string(format_pointer);
    let text = guest_strings::format_guest_text(&format_text, &mut |index| arguments.get(index).copied().unwrap_or(0), false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("{}{}", prefix, text);
    Ok(0)
}

fn ok<T>(result: Result<T, KernelError>) -> Result<u64, KernelError> {
    result.map(|_| 0)
}

fn dbg_print(call: &Call) -> Result<u64, KernelError> {
    print_formatted("[driver] ", call.arg(1), &call.args[1..7])
}
/// O nível chega pela ABI, mas ainda não filtra.
fn dbg_print_ex(call: &Call) -> Result<u64, KernelError> {
    print_formatted(&alloc::format!("[driver:{}] ", call.arg(1) as u32), call.arg(3), &call.args[3..8])
}
fn query_system_time(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), system_time());
    Ok(0)
}
fn query_tick_count(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), clock::uptime_ms());
    Ok(0)
}
fn get_current_irql(_: &Call) -> Result<u64, KernelError> {
    Ok(irql::get_irql() as u64)
}
fn raise_irql(call: &Call) -> Result<u64, KernelError> {
    let previous = irql::raise_irql(call.arg(1) as u8);
    if call.arg(2) != 0 {
        guest::write8(call.arg(2), previous);
    }
    Ok(0)
}
fn lower_irql(call: &Call) -> Result<u64, KernelError> {
    irql::lower_irql(call.arg(1) & 0xFF);
    Ok(0)
}
fn initialize_spin_lock(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), 0);
    Ok(0)
}
fn acquire_spin_lock_raise_to_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(acquire_spin_lock(call.arg(1)) as u64)
}
fn release_spin_lock_export(call: &Call) -> Result<u64, KernelError> {
    release_spin_lock(call.arg(1), call.arg(2));
    Ok(0)
}
fn acquire_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    spin_at_dpc(call.arg(1));
    Ok(0)
}
fn release_spin_lock_from_dpc(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), 0);
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
/// Todo código de driver roda no BSP.
fn get_current_processor_number(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn query_active_processor_count(_: &Call) -> Result<u64, KernelError> {
    Ok(smp::online_cpu_count() as u64)
}
/// Bit N = CPU N online (o BSP sempre).
fn query_active_processors(_: &Call) -> Result<u64, KernelError> {
    let mut mask = 1u32;
    for slot in 0..smp::ap_slot_count() as u32 {
        mask |= 1u32.wrapping_shl(slot + 1);
    }
    Ok(mask as i32 as i64 as u64)
}
fn get_processor_number_from_index(call: &Call) -> Result<u64, KernelError> {
    let index = call.arg(1);
    if index >= smp::online_cpu_count() as u64 {
        return Ok(signed_status(0xC000_000D));
    }
    if call.arg(2) != 0 {
        guest::write16(call.arg(2), 0);
        guest::write8(call.arg(2) + 2, index as u8);
        guest::write8(call.arg(2) + 3, 0);
    }
    Ok(0)
}
fn initialize_timer(call: &Call) -> Result<u64, KernelError> {
    timer::initialize_timer(call.arg(1), ktimer::TIMER_NOTIFICATION as u32);
    Ok(0)
}
fn initialize_timer_ex(call: &Call) -> Result<u64, KernelError> {
    timer::initialize_timer(call.arg(1), if call.arg(2) != 0 { ktimer::TIMER_SYNCHRONIZATION } else { ktimer::TIMER_NOTIFICATION } as u32);
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
    Ok(guest::read32(call.arg(1) + ktimer::SIGNAL_STATE) as u64)
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
/// Contador TSC; a frequência sai no ponteiro opcional.
fn query_performance_counter(call: &Call) -> Result<u64, KernelError> {
    if call.arg(1) != 0 {
        guest::write64(call.arg(1), clock::tsc_frequency_hz());
    }
    Ok(cpu::rdtsc())
}
/// Espera ocupada medida pelo TSC.
fn stall_execution_processor(call: &Call) -> Result<u64, KernelError> {
    let ticks = clock::tsc_frequency_hz() / 1_000_000 * (call.arg(1) as u32 as u64);
    let start = cpu::rdtsc();
    while cpu::rdtsc().wrapping_sub(start) < ticks {
        core::hint::spin_loop();
    }
    Ok(0)
}
fn bug_check_ex(call: &Call) -> Result<u64, KernelError> {
    do_bug_check(call.arg(1) as u32, call.arg(2), call.arg(3), call.arg(4), call.arg(5))
}
fn set_importance_dpc(call: &Call) -> Result<u64, KernelError> {
    guest::write8(call.arg(1) + kdpc::IMPORTANCE, call.arg(2) as u8);
    Ok(0)
}
fn set_target_processor_dpc(call: &Call) -> Result<u64, KernelError> {
    guest::write16(call.arg(1) + kdpc::NUMBER, (call.arg(2) & 255) as u16);
    Ok(0)
}
/// Drena a fila de DPCs na hora, como o NT.
fn flush_queued_dpcs(_: &Call) -> Result<u64, KernelError> {
    dpc::run_queue()?;
    Ok(1)
}
fn enter_critical_region(_: &Call) -> Result<u64, KernelError> {
    ok(critical_region::enter_critical())
}
fn leave_critical_region(_: &Call) -> Result<u64, KernelError> {
    ok(critical_region::leave_critical())
}
fn are_apcs_disabled(_: &Call) -> Result<u64, KernelError> {
    Ok(critical_region::disabled() as u64)
}
/// Registro real: os callbacks rodam no KeBugCheckEx.
fn register_bug_check_callback(call: &Call) -> Result<u64, KernelError> {
    let record = guest::alloc_bytes(0x20);
    guest::write64(record, call.arg(1));
    guest::write64(record + 8, call.arg(3));
    guest::write64(record + 16, call.arg(2));
    BUG_CHECK_CALLBACKS.lock().push(record);
    if call.arg(5) != 0 {
        guest::write32(call.arg(5), 1);
    }
    Ok(1)
}
fn deregister_bug_check_callback(call: &Call) -> Result<u64, KernelError> {
    let mut callbacks = BUG_CHECK_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|&record| record == call.arg(1)) else { return Ok(0) };
    callbacks.remove(index);
    drop(callbacks);
    guest::free_bytes(call.arg(1));
    Ok(1)
}
/// Versão anunciada pelo adaptador: 10.0.26100 (saídas opcionais).
fn ps_get_version(call: &Call) -> Result<u64, KernelError> {
    for (pointer, value) in [(call.arg(1), 10), (call.arg(2), 0), (call.arg(3), 26100), (call.arg(4), 0)] {
        if pointer != 0 {
            guest::write32(pointer, value);
        }
    }
    Ok(1)
}
fn kf_raise_irql(call: &Call) -> Result<u64, KernelError> {
    let previous = irql::get_irql();
    irql::raise_irql(call.arg(1) as u8);
    Ok(previous as u64)
}
/// Quantum do timer do LAPIC: 100 Hz = 10 ms = 100000 × 100 ns.
fn query_time_increment(_: &Call) -> Result<u64, KernelError> {
    Ok(100_000)
}
/// Sem watchdog de DPC: a estrutura sai zerada.
fn query_dpc_watchdog_information(call: &Call) -> Result<u64, KernelError> {
    for offset in (0..0x50).step_by(4) {
        guest::write32(call.arg(1) + offset, 0);
    }
    Ok(0)
}
fn synchronize_execution(call: &Call) -> Result<u64, KernelError> {
    Ok(interrupt_object::ke_synchronize_execution(call.arg(1), call.arg(2), call.arg(3)))
}
/// Boot normal (sem safe boot).
fn init_safe_boot_mode(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
/// KSEMAPHORE: Type 5, SignalState = count, Limit em +0x18.
fn initialize_semaphore(call: &Call) -> Result<u64, KernelError> {
    guest::write8(call.arg(1) + dispatcher_header::TYPE, 5);
    guest::write32(call.arg(1) + dispatcher_header::SIGNAL_STATE, call.arg(2) as u32);
    guest::write32(call.arg(1) + 0x18, call.arg(3) as u32);
    Ok(0)
}
/// Devolve o SignalState anterior; o novo é anterior + ajuste, limitado.
fn release_semaphore(call: &Call) -> Result<u64, KernelError> {
    let state = call.arg(1) + dispatcher_header::SIGNAL_STATE;
    let previous = guest::read32(state) as i32;
    let limit = guest::read32(call.arg(1) + 0x18) as i32;
    let released = previous.wrapping_add(call.arg(3) as i32).min(limit);
    guest::write32(state, released as u32);
    Ok(previous as i64 as u64)
}
fn initialize_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    fast_mutex::initialize(call.arg(1));
    Ok(0)
}
fn acquire_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::acquire(call.arg(1)))
}
fn release_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::release(call.arg(1)))
}
/// KLOCK_QUEUE_HANDLE { Next, Lock, OldIrql }.
fn acquire_in_stack_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    let handle = call.arg(2);
    guest::write64(handle, 0);
    guest::write64(handle + 8, call.arg(1));
    let previous = acquire_spin_lock(call.arg(1));
    guest::write8(handle + 0x10, previous);
    Ok(0)
}
fn release_in_stack_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    let handle = call.arg(1);
    release_spin_lock(guest::read64(handle + 8), guest::read8(handle + 0x10) as u64);
    Ok(0)
}
fn acquire_in_stack_queued_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    let handle = call.arg(2);
    guest::write64(handle, 0);
    guest::write64(handle + 8, call.arg(1));
    spin_at_dpc(call.arg(1));
    Ok(0)
}
fn release_in_stack_queued_spin_lock_from_dpc(call: &Call) -> Result<u64, KernelError> {
    guest::write64(guest::read64(call.arg(1) + 8), 0);
    Ok(0)
}
/// KeAcquireInterruptSpinLock: sobe ao SynchronizeIrql do objeto, pega o
/// lock apontado por ActualLock e devolve o IRQL anterior.
fn acquire_interrupt_spin_lock(call: &Call) -> Result<u64, KernelError> {
    let lock = guest::read64(call.arg(1) + kinterrupt::ACTUAL_LOCK);
    let previous = raise_at_least(guest::read8(call.arg(1) + kinterrupt::SYNCHRONIZE_IRQL));
    spin_at_dpc(lock);
    Ok(previous as u64)
}
/// KeReleaseInterruptSpinLock: solta o ActualLock e volta ao IRQL dado.
fn release_interrupt_spin_lock(call: &Call) -> Result<u64, KernelError> {
    release_spin_lock(guest::read64(call.arg(1) + kinterrupt::ACTUAL_LOCK), call.arg(2));
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
    do_bug_check(call.arg(1) as u32, 0, 0, 0, 0)
}
/// A pilha do kernel já garante os bytes pedidos: chama de verdade.
fn expand_kernel_stack_and_callout_ex(call: &Call) -> Result<u64, KernelError> {
    Ok(native_call::call(call.arg(1), &[call.arg(2), call.arg(5)]) as i32 as i64 as u64)
}
/// Em x86-64 a coerência de DMA é do hardware.
fn flush_io_buffers(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
/// Sem SRAT: tudo no nó NUMA 0.
fn get_current_node_number(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn query_highest_node_number(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
/// CPUs da MADT no grupo 0 (ou ALL_GROUPS).
fn query_maximum_processor_count_ex(call: &Call) -> Result<u64, KernelError> {
    let group = call.arg(1) as u32;
    if group != 0 && group != 0xFFFF {
        return Ok(0);
    }
    Ok(smp::discovered_cpu_count() as u64)
}
/// Sem suspensão: unbiased == interrupt time.
fn query_unbiased_interrupt_time(_: &Call) -> Result<u64, KernelError> {
    Ok(clock::uptime_ms() * 10_000)
}
fn query_unbiased_interrupt_time_precise(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), clock::uptime_ms() * 10_000);
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
    ok(critical_region::enter_guarded())
}
fn leave_guarded_region(_: &Call) -> Result<u64, KernelError> {
    ok(critical_region::leave_guarded())
}
/// Uma região crítica isolada ainda permite APCs especiais de kernel.
fn are_all_apcs_disabled(_: &Call) -> Result<u64, KernelError> {
    Ok(critical_region::all_disabled() as u64)
}
/// PROCESSOR_NUMBER do BSP (grupo 0, número 0); saída opcional.
fn get_current_processor_number_ex(call: &Call) -> Result<u64, KernelError> {
    if call.arg(1) != 0 {
        guest::write32(call.arg(1), 0);
    }
    Ok(0)
}
/// CPUs online; grupo inexistente devolve 0.
fn query_active_processor_count_ex(call: &Call) -> Result<u64, KernelError> {
    let group = call.arg(1) as u32;
    if group != 0 && group != 0xFFFF {
        return Ok(0);
    }
    Ok(smp::online_cpu_count() as u64)
}
fn query_system_time_precise(call: &Call) -> Result<u64, KernelError> {
    guest::write64(call.arg(1), system_time());
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
/// Drivers rodam no BSP: o broadcast é local.
fn ipi_generic_call(call: &Call) -> Result<u64, KernelError> {
    Ok(native_call::call(call.arg(1), &[call.arg(2), 0]))
}
/// XSTATE_SAVE próprio: assinatura 'XS' e área FXSAVE alinhada; a máscara
/// de recursos estendidos ainda não seleciona nada além do FXSAVE.
fn save_extended_processor_state(call: &Call) -> Result<u64, KernelError> {
    let state = guest::alloc_bytes(0x20);
    let area = guest::alloc_aligned(0x200, 16, true);
    guest::write32(state, 0x5358);
    guest::write64(state + 8, area);
    cpu::fxsave(area);
    guest::write64(call.arg(2), state);
    Ok(0)
}
fn restore_extended_processor_state(call: &Call) -> Result<u64, KernelError> {
    let state = call.arg(1);
    if state == 0 {
        return Ok(signed_status(0xC000_000D));
    }
    let area = guest::read64(state + 8);
    cpu::fxrstor(area);
    guest::free_bytes(area);
    guest::free_bytes(state);
    Ok(0)
}
/// Aceita e segue (o ajuste de prioridade real é o KeSetBasePriorityThread).
fn set_actual_base_priority_thread(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}
fn try_to_acquire_guarded_mutex(call: &Call) -> Result<u64, KernelError> {
    Ok(fast_mutex::try_acquire(call.arg(1))? as u64)
}
fn acquire_guarded_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::acquire_guarded_unsafe(call.arg(1)))
}
fn release_guarded_mutex_unsafe(call: &Call) -> Result<u64, KernelError> {
    ok(fast_mutex::release_guarded_unsafe(call.arg(1)))
}

fn bug_check_data_address() -> u64 {
    bug_check_data()
}

fn number_processors_address() -> u64 {
    number_processors_cell()
}

/// Liga o bugcheck interno do kernel ao handler do grupo.
pub fn init() {
    bug_check_data();
    bugcheck::set_handler(do_bug_check);
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
    data_exports: &[("KiBugCheckData", bug_check_data_address), ("KeNumberProcessors", number_processors_address)],
};

// ---- KeQueryPrcbAddress, KeQueryPriorityThread e KeQueryRuntimeThread -------
// (grupo "processor-queries", no fim da ABI)

/// Entrada de KiProcessorBlock: a KPRCB embutida na KPCR de cada processador
/// que tem uma (o OpenNT publica a do processador de boot); sem KPRCB, NULL.
fn query_prcb_address(call: &Call) -> Result<u64, KernelError> {
    let base = crate::ntos::ke::pcr::get_pcr_address();
    Ok(if call.arg(1) as u32 == 0 && base != 0 { base + crate::ntos::ke::pcr::layout::PRCB } else { 0 })
}

fn query_priority_thread(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::ntos::ke::thread_priority::query_priority(call.arg(1)) as i64 as u64)
}

/// Tempo de kernel devolvido e de usuário gravado, em ticks do relógio
/// (KeQueryTimeIncrement: 100000 unidades de 100 ns).
fn query_runtime_thread(call: &Call) -> Result<u64, KernelError> {
    let (kernel, user) = crate::ntos::ps::process::thread_record(call.arg(1)).map_or((0, 0), |record| (record.kernel_time, record.user_time));
    if call.arg(2) != 0 {
        guest::write32(call.arg(2), (user / 100_000) as u32);
    }
    Ok(kernel / 100_000 & 0xFFFF_FFFF)
}

// ---- spin locks numerados, ForDpc, RaiseToSynch, Test/TryTo -------------

/// SYNCH_LEVEL do x64 multiprocessado.
const SYNCH_LEVEL: u8 = 12;
/// LockQueueMaximumLock: as entradas da LockQueue da PRCB.
const LOCK_QUEUE_MAXIMUM: u64 = 17;
/// LockQueueIoVpbLock.
const LOCK_QUEUE_IO_VPB_LOCK: u64 = 9;

/// O KSPIN_LOCK da entrada `number` da LockQueue da PRCB corrente.
fn queued_lock(number: u64) -> Result<u64, KernelError> {
    let number = number as u32 as u64;
    if number >= LOCK_QUEUE_MAXIMUM {
        return Err(KernelError::new(alloc::format!("KSPIN_LOCK_QUEUE_NUMBER invalido: {number}")));
    }
    crate::ntos::ke::pcr::queued_spin_lock(number).ok_or_else(|| KernelError::new("LockQueue da PRCB sem lock"))
}

/// Sobe a `level` (nunca desce) e devolve o IRQL anterior.
fn raise_at_least(level: u8) -> u8 {
    let previous = irql::get_irql();
    if level > previous {
        irql::raise_irql(level);
    }
    previous
}

/// Uma tentativa em `level`; sem sucesso o IRQL volta e a saída fica intacta.
fn try_acquire_raised(lock: u64, level: u8, old_irql: u64) -> u64 {
    let previous = raise_at_least(level);
    if try_spin(lock) {
        guest::write8(old_irql, previous);
        1
    } else {
        irql::lower_irql(previous as u64);
        0
    }
}

fn acquire_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    let lock = queued_lock(call.arg(1))?;
    Ok(acquire_spin_lock(lock) as u64)
}
fn acquire_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    let lock = queued_lock(call.arg(1))?;
    let previous = raise_at_least(SYNCH_LEVEL);
    spin_at_dpc(lock);
    Ok(previous as u64)
}
fn release_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    release_spin_lock(queued_lock(call.arg(1))?, call.arg(2));
    Ok(0)
}
fn try_to_acquire_queued_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok(try_acquire_raised(queued_lock(call.arg(1))?, irql::DISPATCH_LEVEL, call.arg(2)))
}
fn try_to_acquire_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    Ok(try_acquire_raised(queued_lock(call.arg(1))?, SYNCH_LEVEL, call.arg(2)))
}
/// KLOCK_QUEUE_HANDLE { Next, Lock, OldIrql } no nível pedido (nunca desce).
fn acquire_in_stack_at(lock: u64, handle: u64, level: u8) {
    guest::write64(handle, 0);
    guest::write64(handle + 8, lock);
    let previous = raise_at_least(level);
    spin_at_dpc(lock);
    guest::write8(handle + 0x10, previous);
}
/// Numa DPC comum (DISPATCH_LEVEL) só pega o lock; numa DPC encadeada sobe antes.
fn acquire_in_stack_queued_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    acquire_in_stack_at(call.arg(1), call.arg(2), irql::DISPATCH_LEVEL);
    Ok(0)
}
fn acquire_in_stack_queued_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    acquire_in_stack_at(call.arg(1), call.arg(2), SYNCH_LEVEL);
    Ok(0)
}
fn release_in_stack_queued_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    let handle = call.arg(1);
    release_spin_lock(guest::read64(handle + 8), guest::read8(handle + 0x10) as u64);
    Ok(0)
}
fn acquire_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    let previous = raise_at_least(irql::DISPATCH_LEVEL);
    spin_at_dpc(call.arg(1));
    Ok(previous as u64)
}
fn release_spin_lock_for_dpc(call: &Call) -> Result<u64, KernelError> {
    release_spin_lock(call.arg(1), call.arg(2));
    Ok(0)
}
fn acquire_spin_lock_raise_to_synch(call: &Call) -> Result<u64, KernelError> {
    let previous = raise_at_least(SYNCH_LEVEL);
    spin_at_dpc(call.arg(1));
    Ok(previous as u64)
}
/// TRUE quando o lock está livre.
fn test_spin_lock(call: &Call) -> Result<u64, KernelError> {
    Ok((guest::read64(call.arg(1)) & 1 == 0) as u64)
}
fn try_to_acquire_spin_lock_at_dpc(call: &Call) -> Result<u64, KernelError> {
    Ok(try_spin(call.arg(1)) as u64)
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

/// IoAcquireVpbSpinLock: o lock numerado LockQueueIoVpbLock; o IRQL
/// anterior vai para a saída.
pub fn acquire_vpb_spin_lock(old_irql: u64) -> Result<u64, KernelError> {
    let previous = acquire_spin_lock(queued_lock(LOCK_QUEUE_IO_VPB_LOCK)?);
    guest::write8(old_irql, previous);
    Ok(0)
}
/// IoReleaseVpbSpinLock.
pub fn release_vpb_spin_lock(new_irql: u64) -> Result<u64, KernelError> {
    release_spin_lock(queued_lock(LOCK_QUEUE_IO_VPB_LOCK)?, new_irql);
    Ok(0)
}

// ---- afinidade e grupos de processadores ----------------------------------
//
// O código dos drivers roda no processador de boot (KeGetCurrentProcessorNumber
// é 0); a afinidade pedida é validada contra os processadores ativos da MADT e
// guardada por thread, e as consultas de grupo e nó descrevem o grupo 0 e o
// nó 0 com todos os processadores ativos.

/// GROUP_AFFINITY { KAFFINITY Mask; USHORT Group; USHORT Reserved[3]; }.
const GROUP_AFFINITY_SIZE: usize = 16;
/// INVALID_AFFINITY_SET.
const INVALID_AFFINITY_SET: u64 = 0x3;

#[derive(Clone, Copy)]
struct ThreadAffinity {
    user: u64,
    system: Option<u64>,
    ideal: u8,
}

static AFFINITIES: SpinLock<alloc::collections::BTreeMap<u64, ThreadAffinity>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Bit N = processador N ativo (o BSP sempre).
fn active_mask() -> u64 {
    let mut mask = 1u64;
    for slot in 0..smp::ap_slot_count().min(63) as u32 {
        mask |= 1u64 << (slot + 1);
    }
    mask
}

fn thread_affinity(thread: u64) -> ThreadAffinity {
    AFFINITIES.lock().get(&thread).copied().unwrap_or(ThreadAffinity { user: active_mask(), system: None, ideal: 0 })
}

fn update_affinity<T>(thread: u64, change: impl FnOnce(&mut ThreadAffinity) -> T) -> T {
    let mut affinity = thread_affinity(thread);
    let result = change(&mut affinity);
    AFFINITIES.lock().insert(thread, affinity);
    result
}

/// Só processadores ativos; um conjunto sem nenhum é INVALID_AFFINITY_SET.
fn validated_affinity(affinity: u64) -> u64 {
    let mask = affinity & active_mask();
    if mask == 0 {
        bugcheck::bug_check_ex(INVALID_AFFINITY_SET as u32, affinity, active_mask(), 0, 0);
    }
    mask
}

fn current_thread() -> u64 {
    crate::ntos::ps::process::get_current_thread()
}

fn set_system_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    let mask = validated_affinity(call.arg(1));
    update_affinity(current_thread(), |affinity| affinity.system = Some(mask));
    Ok(0)
}
/// Devolve a afinidade de sistema anterior (0 sem afinidade de sistema).
fn set_system_affinity_thread_ex(call: &Call) -> Result<u64, KernelError> {
    let mask = validated_affinity(call.arg(1));
    Ok(update_affinity(current_thread(), |affinity| affinity.system.replace(mask).unwrap_or(0)))
}
fn revert_to_user_affinity_thread(_: &Call) -> Result<u64, KernelError> {
    update_affinity(current_thread(), |affinity| affinity.system = None);
    Ok(0)
}
/// Afinidade 0 volta à de usuário; outra vira a afinidade de sistema.
fn revert_to_user_affinity_thread_ex(call: &Call) -> Result<u64, KernelError> {
    let system = if call.arg(1) == 0 { None } else { Some(validated_affinity(call.arg(1))) };
    update_affinity(current_thread(), |affinity| affinity.system = system);
    Ok(0)
}
fn write_group_affinity(pointer: u64, mask: u64) {
    guest::write_bytes(pointer, &[0; GROUP_AFFINITY_SIZE]);
    guest::write64(pointer, mask);
}
/// A anterior vai para PreviousAffinity com Mask 0 quando a thread não
/// estava em afinidade de sistema; só o grupo 0 existe.
fn set_system_group_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    let (requested, previous) = (call.arg(1), call.arg(2));
    let (mask, group) = (guest::read64(requested), guest::read16(requested + 8));
    if group != 0 {
        bugcheck::bug_check_ex(INVALID_AFFINITY_SET as u32, mask, group as u64, 0, 0);
    }
    let mask = validated_affinity(mask);
    let before = update_affinity(current_thread(), |affinity| affinity.system.replace(mask));
    if previous != 0 {
        write_group_affinity(previous, before.unwrap_or(0));
    }
    Ok(0)
}
fn revert_to_user_group_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    let mask = guest::read64(call.arg(1));
    let system = if mask == 0 { None } else { Some(validated_affinity(mask)) };
    update_affinity(current_thread(), |affinity| affinity.system = system);
    Ok(0)
}
/// KeSetAffinityThread: troca a afinidade de usuário e devolve a anterior.
fn set_affinity_thread(call: &Call) -> Result<u64, KernelError> {
    let mask = validated_affinity(call.arg(2));
    Ok(update_affinity(call.arg(1), |affinity| core::mem::replace(&mut affinity.user, mask)))
}
/// Devolve o processador ideal anterior; um processador inexistente é ignorado.
fn set_ideal_processor_thread(call: &Call) -> Result<u64, KernelError> {
    let processor = call.arg(2) as u8;
    let valid = (processor as usize) < smp::online_cpu_count();
    Ok(update_affinity(call.arg(1), |affinity| {
        let previous = affinity.ideal;
        if valid {
            affinity.ideal = processor;
        }
        previous
    }) as u64)
}
fn query_active_group_count(_: &Call) -> Result<u64, KernelError> {
    Ok(1)
}
fn query_maximum_group_count(_: &Call) -> Result<u64, KernelError> {
    Ok(1)
}
fn query_maximum_processor_count(_: &Call) -> Result<u64, KernelError> {
    Ok(smp::discovered_cpu_count() as u64)
}
fn query_group_affinity(call: &Call) -> Result<u64, KernelError> {
    Ok(if call.arg(1) as u16 == 0 { active_mask() } else { 0 })
}
/// Nó 0 com todos os processadores ativos; outro nó volta vazio.
fn query_node_active_affinity(call: &Call) -> Result<u64, KernelError> {
    let (node, affinity, count) = (call.arg(1) as u16, call.arg(2), call.arg(3));
    let (mask, processors) = if node == 0 { (active_mask(), smp::online_cpu_count() as u16) } else { (0, 0) };
    if affinity != 0 {
        write_group_affinity(affinity, mask);
    }
    if count != 0 {
        guest::write16(count, processors);
    }
    Ok(0)
}
fn query_node_maximum_processor_count(call: &Call) -> Result<u64, KernelError> {
    Ok(if call.arg(1) as u16 == 0 { smp::discovered_cpu_count() as u64 } else { 0 })
}
/// PROCESSOR_NUMBER { USHORT Group; UCHAR Number; UCHAR Reserved; }.
fn set_target_processor_dpc_ex(call: &Call) -> Result<u64, KernelError> {
    let number = call.arg(2);
    let (group, processor) = (guest::read16(number), guest::read8(number + 2));
    if group != 0 || processor as usize >= smp::discovered_cpu_count() {
        return Ok(signed_status(0xC000_000D));
    }
    guest::write16(call.arg(1) + kdpc::NUMBER, processor as u16);
    Ok(0)
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
//
// A rotina roda como DPC (DISPATCH_LEVEL) em cada processador que executa
// código de driver — o de boot, como no KeIpiGenericCall — com
// SystemArgument1 apontando a contagem de pendentes (KeSignalCallDpcDone) e
// SystemArgument2 a barreira (KeSignalCallDpcSynchronize). As duas contam os
// participantes reais, então a espera sempre termina.

/// Bloco da chamada: +0 pendentes, +8 barreira { restantes, participantes, sentido }.
const CALL_DPC_BLOCK: u64 = 0x20;
const CALL_DPC_BARRIER: u64 = 8;

fn atomic_add32(pointer: u64, delta: i32) -> i32 {
    loop {
        let value = guest::read32(pointer);
        let next = (value as i32).wrapping_add(delta);
        if guest::compare_exchange32(pointer, value, next as u32).unwrap_or_else(|error| panic!("{error}")) == value {
            return next;
        }
    }
}

fn generic_call_dpc(call: &Call) -> Result<u64, KernelError> {
    let (routine, context) = (call.arg(1), call.arg(2));
    let participants = 1u32;
    let block = guest::alloc_bytes(CALL_DPC_BLOCK);
    let dpc = guest::alloc_bytes(kdpc::SIZE);
    if block == 0 || dpc == 0 {
        return Err(KernelError::new("KeGenericCallDpc: sem memoria para a DPC"));
    }
    guest::write_bytes(block, &[0; CALL_DPC_BLOCK as usize]);
    guest::write32(block, participants);
    guest::write32(block + CALL_DPC_BARRIER, participants);
    guest::write32(block + CALL_DPC_BARRIER + 4, participants);
    dpc::initialize_dpc(dpc, routine, context);
    guest::write64(dpc + kdpc::SYSARG1, block);
    guest::write64(dpc + kdpc::SYSARG2, block + CALL_DPC_BARRIER);
    let previous = raise_at_least(irql::DISPATCH_LEVEL);
    native_call::call(routine, &[dpc, context, block, block + CALL_DPC_BARRIER]);
    irql::lower_irql(previous as u64);
    // Todos os participantes avisam o fim antes de a chamada voltar.
    while guest::read32(block) as i32 > 0 {
        core::hint::spin_loop();
    }
    guest::free_bytes(dpc);
    guest::free_bytes(block);
    Ok(0)
}
/// KeSignalCallDpcDone: um participante a menos.
fn signal_call_dpc_done(call: &Call) -> Result<u64, KernelError> {
    atomic_add32(call.arg(1), -1);
    Ok(0)
}
/// KeSignalCallDpcSynchronize: barreira entre os participantes; TRUE para
/// exatamente um (o último a chegar), que rearma a barreira.
fn signal_call_dpc_synchronize(call: &Call) -> Result<u64, KernelError> {
    let barrier = call.arg(1);
    let sense = guest::read32(barrier + 8);
    if atomic_add32(barrier, -1) == 0 {
        guest::write32(barrier, guest::read32(barrier + 4));
        guest::write32(barrier + 8, sense ^ 1);
        return Ok(1);
    }
    while guest::read32(barrier + 8) == sense {
        core::hint::spin_loop();
    }
    Ok(0)
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
    //! KeTestAlertThread — `system32/win32/ntoskrnl/test-alert.js`.

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
    //! KeSetBasePriorityThread — `system32/win32/ntoskrnl/thread-base-priority.js`.
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
    //! KeSetPriorityThread — `system32/win32/ntoskrnl/thread-priority.js`.
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
    //! KeCapturePersistentThreadState — `ntos/ke/persistent-thread-state`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::persistent_thread_state;
    use crate::rtl::KernelError;

    fn capture(call: &Call) -> Result<u64, KernelError> {
        persistent_thread_state::capture(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5), call.arg(6), call.arg(7), call.arg(8))
    }

    pub static GROUP: Group = Group { name: "persistent-thread-state", names: &["KeCapturePersistentThreadState"], handlers: &[capture], data_exports: &[] };
}

pub mod alert_thread {
    //! ZwAlertThread — `system32/win32/ntoskrnl/alert-thread.js`.
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
