//! Autotestes (fase 6) dos exports de suporte de plataforma que os drivers
//! de barramento importam: KTIMER2, afinidade de grupo e processadores
//! dinâmicos, a trava e a energia do KD, o Errata Manager e o
//! ExTryQueueWorkItem, cada um chamado pelo nome.
//!
//! Os valores esperados vêm das instruções de cada rotina no ntoskrnl
//! 19041 (tabela KiTimer2Combinations, status e campos gravados).

use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ke_misc::Ktimer2;
use crate::ntos::io::{io_manager, work_items};
use crate::ntos::ke::{clock, irql, smp, timer, timer2};
use crate::ntos::kd::power;
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_NOT_FOUND: u64 = 0xC000_0225;
const STATUS_DEBUGGER_INACTIVE: u64 = 0xC000_0354;
const STATUS_TIMEOUT: u64 = 0x102;

static TIMER_CALLS: AtomicU64 = AtomicU64::new(0);
static TIMER_ARGUMENTS: AtomicU64 = AtomicU64::new(0);
static WORK_PARAMETER: AtomicU64 = AtomicU64::new(0);

/// PTIMER2_CALLBACK(Timer, Context): conta e guarda Timer ^ Context.
extern "win64" fn timer2_fired(timer: u64, context: u64) {
    TIMER_CALLS.fetch_add(1, Ordering::SeqCst);
    TIMER_ARGUMENTS.store(timer ^ context, Ordering::SeqCst);
}

/// WORKER_THREAD_ROUTINE(Parameter).
extern "win64" fn work_routine(parameter: u64) {
    WORK_PARAMETER.store(parameter, Ordering::SeqCst);
}

fn status(name: &str, arguments: &[u64]) -> u64 {
    call_export(name, arguments).map_or(u64::MAX, |value| value as u32 as u64)
}

fn timer_flags(timer: u64) -> u8 {
    guest::read8(timer + 1)
}

/// Gira o pump dos timers até `done` ou ~2 s.
fn pump_until(done: impl Fn() -> bool) -> bool {
    let deadline = clock::uptime_100ns() + 20_000_000;
    while !done() {
        if clock::uptime_100ns() > deadline {
            return false;
        }
        timer::check_timers();
        crate::hal::cpu::pause();
    }
    true
}

fn timer2_exports(assert: Assert) {
    let block = guest::alloc_bytes(0x200);
    let (timer, parameters, timeout) = (block, block + 0x100, block + 0x140);
    let callback = timer2_fired as extern "win64" fn(u64, u64) as usize as u64;
    let context = 0x1234_5678_9ABC_DEF0u64;
    guest::write_bytes(timer, &[0xCC; 0x88]);
    let _ = call_export("KeInitializeTimer2", &[timer, callback, context, 0]);
    // SAFETY: o KTIMER2 recém-inicializado.
    let object = unsafe { Ktimer2::at(timer) };
    let decoded = timer2::decoded_callback(object);
    assert(guest::read8(timer) == 0x19 && guest::read32(timer + 4) == 0 && guest::read64(timer + 8) == timer + 8 && guest::read64(timer + 0x10) == timer + 8 && guest::read8(timer + 0x81) == 0 && guest::read8(timer + 0x82) == 21 && guest::read8(timer + 0x83) == 3 && decoded == (callback, context) && object.callback.get() != callback, "timer2: KeInitializeTimer2 sincronizacao, lista de espera, combinacao 0 e callback codificado");
    let _ = call_export("KeInitializeTimer2", &[timer, callback, context, 0x8000_0004]);
    let notification = (guest::read8(timer), guest::read8(timer + 0x81), guest::read8(timer + 0x82), guest::read8(timer + 0x83));
    let _ = call_export("KeInitializeTimer2", &[timer, callback, context, 2]);
    let idle = (guest::read8(timer + 0x81), guest::read8(timer + 0x82), guest::read8(timer + 0x83));
    assert(notification == (0x18, 4, 1, 35) && idle == (2, 32, 36), "timer2: notificacao pelo bit 31 e as combinacoes de KiTimer2Combinations");

    // Set/Cancel: prazo relativo, período mínimo e tolerância.
    let _ = call_export("KeInitializeTimer2", &[timer, callback, context, 0]);
    let before = clock::uptime_100ns();
    let first = call_export("KeSetTimer2", &[timer, (-100_000_000i64) as u64, 0, 0]);
    let due = guest::read64(timer + 0x48);
    let after = clock::uptime_100ns();
    let latest = guest::read64(timer + 0x50);
    let again = call_export("KeSetTimer2", &[timer, (-100_000_000i64) as u64, 5, 0]);
    let period = guest::read64(timer + 0x58);
    assert(first == Some(0) && again == Some(1) && timer_flags(timer) & 1 != 0 && due >= before + 100_000_000 && due <= after + 100_000_000 && latest == due && period == clock::CLOCK_TIME_INCREMENT as u64 && guest::read32(timer + 4) == 0, "timer2: KeSetTimer2 insere, devolve se ja estava e sobe o periodo ao minimo");
    // A combinação 0 (CollectionIndex 0x15) ignora a tolerância; a NoWake a soma.
    guest::write64(parameters + 8, 50_000);
    let _ = call_export("KeSetTimer2", &[timer, (-100_000_000i64) as u64, 0, parameters]);
    let ignored = guest::read64(timer + 0x50) == guest::read64(timer + 0x48);
    let first_cancel = call_export("KeCancelTimer2", &[timer, 0]);
    let _ = call_export("KeInitializeTimer2", &[timer, callback, context, 8]);
    let _ = call_export("KeSetTimer2", &[timer, (-100_000_000i64) as u64, 0, parameters]);
    let tolerance = guest::read64(timer + 0x50).wrapping_sub(guest::read64(timer + 0x48));
    guest::write64(parameters + 8, u64::MAX);
    let _ = call_export("KeSetTimer2", &[timer, (-100_000_000i64) as u64, 0, parameters]);
    let unlimited = guest::read64(timer + 0x50);
    let cancelled = call_export("KeCancelTimer2", &[timer, 0]);
    let cancelled_again = call_export("KeCancelTimer2", &[timer, 0]);
    assert(ignored && first_cancel == Some(1) && tolerance == 50_000 && unlimited == u64::MAX && cancelled == Some(1) && cancelled_again == Some(0) && timer_flags(timer) & 1 == 0, "timer2: tolerancia do EXT_SET_PARAMETERS (ignorada na combinacao 0x15) e KeCancelTimer2");
    // Disabled: Set e Cancel não mexem.
    guest::write8(timer + 1, 0x20);
    let disabled = (call_export("KeSetTimer2", &[timer, (-1i64) as u64, 0, 0]), call_export("KeCancelTimer2", &[timer, 0]), timer_flags(timer));
    guest::write8(timer + 1, 0);
    assert(disabled == (Some(0), Some(0), 0x20), "timer2: timer desabilitado ignora Set e Cancel");

    // Expiração: o callback recebe (Timer, Context), o objeto fica
    // sinalizado e a espera de sincronização consome o sinal.
    TIMER_CALLS.store(0, Ordering::SeqCst);
    let _ = call_export("KeSetTimer2", &[timer, (-1i64) as u64, 0, 0]);
    let fired = pump_until(|| TIMER_CALLS.load(Ordering::SeqCst) == 1);
    guest::write64(timeout, 0);
    let wait = call_export("KeWaitForSingleObject", &[timer, 0, 0, 0, timeout]);
    let wait_again = call_export("KeWaitForSingleObject", &[timer, 0, 0, 0, timeout]);
    assert(fired && TIMER_ARGUMENTS.load(Ordering::SeqCst) == timer ^ context && timer_flags(timer) & 0x11 == 0 && wait == Some(0) && wait_again == Some(STATUS_TIMEOUT), "timer2: expiracao chama o callback, sinaliza e a espera consome o sinal");
    // Periódico: volta inserido para agora + período.
    TIMER_CALLS.store(0, Ordering::SeqCst);
    let _ = call_export("KeSetTimer2", &[timer, (-1i64) as u64, 200_000, 0]);
    let periodic = pump_until(|| TIMER_CALLS.load(Ordering::SeqCst) >= 2);
    let still_inserted = timer_flags(timer) & 1 != 0;
    let _ = call_export("KeCancelTimer2", &[timer, 0]);
    assert(periodic && still_inserted && timer2::inserted_count() == 0, "timer2: periodico rearma depois de cada expiracao");
    guest::free_bytes(block);
}

fn processor_exports(assert: Assert) {
    let block = guest::alloc_bytes(0x40);
    guest::write_bytes(block, &[0xFF; 0x10]);
    let _ = call_export("KeProcessorGroupAffinity", &[block, 0]);
    let first = (guest::read64(block), guest::read16(block + 8), guest::read16(block + 0xA), guest::read16(block + 0xC), guest::read16(block + 0xE));
    let online = smp::online_cpu_count() as u64;
    let _ = call_export("KeProcessorGroupAffinity", &[block, online - 1]);
    let last = guest::read64(block);
    let _ = call_export("KeProcessorGroupAffinity", &[block, online + 5]);
    let absent = guest::read64(block);
    assert(first == (1, 0, 0, 0, 0) && last == 1u64 << (online - 1) && absent == 1, "ke: KeProcessorGroupAffinity pelo indice do processador");
    let coherent_before = smp::system_fully_coherent();
    let _ = call_export("KeReportCacheIncoherentDevice", &[]);
    assert(coherent_before && !smp::system_fully_coherent(), "ke: KeReportCacheIncoherentDevice zera KiSystemFullyCoherent");
    guest::write32(block + 0x20, 0x5555);
    assert(status("KeStartDynamicProcessor", &[0, 0, 0, block + 0x20]) == STATUS_UNSUCCESSFUL && guest::read32(block + 0x20) == 0x5555, "ke: KeStartDynamicProcessor sem particao dinamica");
    guest::free_bytes(block);
}

fn kd_exports(assert: Assert) {
    let block = guest::alloc_bytes(0x40);
    guest::write8(block, 0xEE);
    let entry_irql = irql::get_irql();
    let _ = call_export("KdAcquireDebuggerLock", &[block]);
    let (held_irql, held) = (irql::get_irql(), power::debugger_lock_held());
    let saved = guest::read8(block);
    let _ = call_export("KdReleaseDebuggerLock", &[saved as u64]);
    assert(saved == entry_irql && held_irql == irql::DISPATCH_LEVEL && held && !power::debugger_lock_held() && irql::get_irql() == entry_irql, "kd: KdAcquireDebuggerLock/KdReleaseDebuggerLock em DISPATCH_LEVEL");
    let handle = block + 0x10;
    let registered = status("KdRegisterPowerHandler", &[0x1111, 0x2222, handle]);
    let record = guest::read64(handle);
    let listed = power::registered_power_handlers().contains(&record);
    let fields = (guest::read64(record + 0x10), guest::read64(record + 0x18));
    let removed = status("KdDeregisterPowerHandler", &[record]);
    let removed_again = status("KdDeregisterPowerHandler", &[record]);
    assert(registered == 0 && record != 0 && listed && fields == (0x1111, 0x2222) && removed == 0 && removed_again == STATUS_NOT_FOUND, "kd: KdRegisterPowerHandler/KdDeregisterPowerHandler");
    assert(status("KdPowerTransitionEx", &[1, 1]) == 0 && status("KdDisableDebugger", &[]) == STATUS_DEBUGGER_INACTIVE, "kd: KdPowerTransitionEx e KdDisableDebugger sem /DEBUG");
    guest::write_bytes(block + 0x20, b"opennt\0");
    guest::write_bytes(block + 0x30, b".reload\0");
    assert(call_export("DbgCommandString", &[block + 0x20, block + 0x30]).is_some(), "kd: DbgCommandString pelo int 0x2D sem depurador");
    guest::free_bytes(block);
}

fn errata_exports(assert: Assert) {
    let Some(driver) = io_manager::devices().into_iter().filter(|(_, entry)| entry.native_device != 0).map(|(_, entry)| guest::read64(entry.native_device + 8)).find(|&driver| driver != 0) else {
        assert(false, "em: nenhum DRIVER_OBJECT de dispositivo");
        return;
    };
    let block = guest::alloc_bytes(0x100);
    let (guid, entries, callbacks, handle, state) = (block, block + 0x10, block + 0x40, block + 0x70, block + 0x78);
    guest::write_bytes(guid, &[0x11; 16]);
    guest::write32(state, 7);
    let invalid = [status("EmClientRuleEvaluate", &[0, entries, 1, state]), status("EmClientRuleEvaluate", &[guid, entries, 0, state]), status("EmClientRuleEvaluate", &[guid, entries, 1, 0])];
    let state_untouched = guest::read32(state) == 7;
    let missing = status("EmClientRuleEvaluate", &[guid, entries, 1, state]);
    assert(invalid == [STATUS_INVALID_PARAMETER; 3] && state_untouched && missing == STATUS_NOT_FOUND && guest::read32(state) == 1, "em: EmClientRuleEvaluate sem regras no banco: STATE_UNKNOWN e STATUS_NOT_FOUND");
    guest::write64(entries, guid);
    guest::write64(entries + 8, 0);
    guest::write64(callbacks, guid);
    guest::write64(callbacks + 8, 0);
    let rejected = [
        status("EmProviderRegister", &[0, 0, 0, 0, 0, handle]),
        status("EmProviderRegister", &[driver, 0, 0, 0, 0, 0]),
        status("EmProviderRegister", &[driver, 0, 1, 0, 0, handle]),
        status("EmProviderRegister", &[driver, 0, 0, callbacks, 1, handle]),
    ];
    let unknown_entry = status("EmProviderRegister", &[driver, entries, 1, 0, 0, handle]);
    guest::write64(callbacks + 8, 0x1000);
    let unknown_callback = status("EmProviderRegister", &[driver, 0, 0, callbacks, 1, handle]);
    guest::write64(handle, 0);
    let registered = status("EmProviderRegister", &[driver, 0, 0, 0, 0, handle]);
    let provider = guest::read64(handle);
    let owner = if provider != 0 { guest::read64(provider) } else { 0 };
    let _ = call_export("EmProviderDeregister", &[provider]);
    let _ = call_export("EmProviderDeregister", &[0]);
    assert(rejected == [STATUS_INVALID_PARAMETER; 4] && unknown_entry == STATUS_NOT_FOUND && unknown_callback == STATUS_NOT_FOUND && registered == 0 && provider != 0 && owner == driver, "em: EmProviderRegister valida, recusa entradas e callbacks fora do banco e registra o provedor vazio");
    guest::free_bytes(block);
}

fn work_item_exports(assert: Assert) {
    let item = guest::alloc_bytes(0x20);
    let routine = work_routine as extern "win64" fn(u64) as usize as u64;
    let _ = call_export("ExInitializeWorkItem", &[item, routine, 0xABCD]);
    WORK_PARAMETER.store(0, Ordering::SeqCst);
    let queued = call_export("ExTryQueueWorkItem", &[item, 1]);
    work_items::run_queue();
    assert(queued == Some(1) && WORK_PARAMETER.load(Ordering::SeqCst) == 0xABCD, "ex: ExTryQueueWorkItem enfileira e o worker roda com o Parameter");
    guest::free_bytes(item);
}

pub fn run(assert: Assert) {
    timer2_exports(assert);
    processor_exports(assert);
    kd_exports(assert);
    errata_exports(assert);
    work_item_exports(assert);
}
