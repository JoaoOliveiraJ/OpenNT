//! Os watchdogs de energia do Po (ntoskrnl 19041).
//!
//! Um watchdog é o bloco 'POWD' de 0x138 bytes (`PopPowerWatchdog`) que o
//! PopSetWatchdog (0x349578) cria e devolve como PVOID. Armado com um prazo
//! em ms, o timer dele vence pela DPC (PopWatchdogDpc 0x578cd0), que põe o
//! item de trabalho na DelayedWorkQueue; o worker (PopWatchdogWorker
//! 0x578db0), ainda armado e com o prazo vencido, anexa a sessão dos
//! parâmetros, resolve os quatro parâmetros e chama o callback deles ou, sem
//! callback, o KeBugCheckEx com o código dos parâmetros (o win32kbase usa
//! WIN32K_POWER_WATCHDOG_TIMEOUT, 0x19C, no ArmPowerWatchdog).
//!
//! O PowerInternalSetWatchdog (NtPowerInformation 87, tipo interno 0x15,
//! PopPowerInformationInternal 0x6f1c02) é a porta: só de modo kernel (o tipo
//! está na lista que o modo usuário recebe com STATUS_ACCESS_DENIED).
//!
//! O 19041 também grava a duração da fase de tela ligada
//! (PopCacheDisplayOnPhaseDuration) ao desarmar um watchdog 0x19C de estágio
//! acima de 0x20; é só diagnóstico do boot status data e o OpenNT não a
//! guarda.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::extra_ps_user::{PopPowerWatchdog, PowerInternalSetWatchdogInput, PowerWatchdogParameters};
use crate::ntos::inc::types::{KapcState, NtStruct};
use crate::ntos::io::work_items;
use crate::ntos::ke::{bugcheck, clock, dispatcher, dpc, timer, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// 'POWD', a tag do pool e a assinatura de um watchdog vivo.
const WATCHDOG_SIGNATURE: u32 = 0x4457_4F50;
/// 'NONO', a assinatura gravada antes de soltar o bloco.
const FREED_SIGNATURE: u32 = 0x4F4E_4F4E;
/// WIN32K_POWER_WATCHDOG_TIMEOUT: o código dos watchdogs do win32kbase, que
/// o boot status data acompanha.
pub const WIN32K_POWER_WATCHDOG_TIMEOUT: u32 = 0x19C;
/// KERNEL_SECURITY_CHECK_FAILURE com FAST_FAIL_INVALID_ARG (o `int 0x29`
/// código 5 de um watchdog sem a assinatura).
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_INVALID_ARG: u64 = 5;
/// NotificationEvent.
const NOTIFICATION_EVENT: u8 = 0;
/// KernelMode.
const KERNEL_MODE: u8 = 0;
/// O comprimento mínimo da entrada do PowerInternalSetWatchdog.
pub const SET_WATCHDOG_INPUT: usize = 0x60;

/// PopWatchdogLock com a PopWatchdogList (os watchdogs vivos).
static WATCHDOGS: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// PopBsdPowerWatchdogArmed e PopBsdLastPowerWatchdogStage: o último
/// watchdog 0x19C armado (o estágio é o primeiro parâmetro), para o boot
/// status data.
static BSD_POWER_WATCHDOG_ARMED: AtomicU32 = AtomicU32::new(0);
static BSD_LAST_POWER_WATCHDOG_STAGE: AtomicU32 = AtomicU32::new(0);

fn watchdog(object: u64) -> &'static PopPowerWatchdog {
    // SAFETY: um bloco 'POWD' vivo (a assinatura é conferida antes de usar).
    unsafe { PopPowerWatchdog::at(object) }
}

/// O `int 0x29` com FAST_FAIL_INVALID_ARG de um ponteiro que não é watchdog.
fn check_signature(object: &PopPowerWatchdog) {
    if object.signature.get() != WATCHDOG_SIGNATURE {
        bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_INVALID_ARG, 0, 0, 0);
    }
}

/// PopUpdateWatchdogNoWorkersEvent (0x349850): o evento sinalizado sem timer
/// nem worker pendentes.
fn update_no_workers_event(object: &PopPowerWatchdog) {
    let event = object.no_workers.address();
    if object.timer_active.get() == 0 && object.worker_queued.get() == 0 {
        dispatcher::set_event(event);
    } else {
        dispatcher::reset_event(event);
    }
}

/// A criação do PopSetWatchdog (0x349725..0x349807): o bloco zerado de pool
/// NonPagedPoolNx, o evento sinalizado, o timer de notificação, a DPC e o
/// item de trabalho com o próprio bloco de contexto, na lista. 0 sem memória.
fn create() -> u64 {
    let object = guest::alloc_bytes(PopPowerWatchdog::SIZE);
    if object == 0 {
        return 0;
    }
    let body = watchdog(object);
    body.signature.set(WATCHDOG_SIGNATURE);
    dispatcher::initialize_event(body.no_workers.address(), NOTIFICATION_EVENT, true);
    timer::initialize_timer_of_type(body.timer.address(), 0);
    dpc::initialize_kernel_dpc(body.dpc.address(), watchdog_dpc, object);
    body.work_item.list.flink.set(0);
    body.work_item.list.blink.set(0);
    body.work_item.parameter.set(object);
    WATCHDOGS.lock().push(object);
    object
}

/// PopSetWatchdog(Watchdog, Parameters, Delete): cria o watchdog quando
/// `object` é 0; com prazo e sem Delete, arma (os parâmetros copiados, o
/// timer no prazo relativo); senão desarma (cancela o timer e espera o worker
/// em curso) e, com Delete, tira da lista e solta o bloco. Devolve o
/// watchdog, 0 depois de apagado ou sem memória para criar.
pub fn set_watchdog(object: u64, parameters: &PowerWatchdogParameters, delete: bool) -> u64 {
    let object = if object == 0 { create() } else { object };
    if object == 0 {
        return 0;
    }
    let body = watchdog(object);
    let mut list = WATCHDOGS.lock();
    check_signature(body);
    let timeout = parameters.timeout.get();
    if timeout != 0 && !delete {
        copy_parameters(&body.parameters, parameters);
        let now = clock::uptime_100ns();
        let interval = timeout as u64 * 10_000;
        body.arm_time.set(now);
        body.due_time.set(now + interval);
        body.arming_thread.set(crate::ntos::ps::process::get_current_thread());
        body.armed.set(1);
        if !timer::set_timer(body.timer.address(), -(interval as i64), body.dpc.address(), 0) {
            body.timer_active.set(1);
            update_no_workers_event(body);
        }
        return object;
    }
    body.armed.set(0);
    if timer::cancel_timer(body.timer.address()) {
        body.timer_active.set(0);
        update_no_workers_event(body);
    }
    // Um worker já na fila (ou rodando): o 19041 solta o lock e espera o
    // evento antes de seguir (0x48435d).
    if dispatcher::read_state(body.no_workers.address()) == 0 {
        drop(list);
        wait::wait_for_objects(&[body.no_workers.address()], false, wait::Deadline::Infinite, KERNEL_MODE, false, wait::reason::EXECUTIVE);
        list = WATCHDOGS.lock();
    }
    if !delete {
        return object;
    }
    list.retain(|&live| live != object);
    drop(list);
    body.signature.set(FREED_SIGNATURE);
    // A rotina interna da DPC sai com ela.
    dpc::initialize_dpc(body.dpc.address(), 0, 0);
    guest::free_bytes(object);
    0
}

fn copy_parameters(target: &PowerWatchdogParameters, source: &PowerWatchdogParameters) {
    target.timeout.set(source.timeout.get());
    target.session_id.set(source.session_id.get());
    target.bug_check_code.set(source.bug_check_code.get());
    target.reserved.set(source.reserved.get());
    for index in 0..4 {
        target.parameters[index].set(source.parameters[index].get());
        target.indirect[index].set(source.indirect[index].get());
    }
    target.callback.set(source.callback.get());
    target.callback_context.set(source.callback_context.get());
}

/// PopWatchdogDpc(Dpc, Watchdog, ...): armado e sem worker na fila, o item
/// de trabalho vai à DelayedWorkQueue; o timer deixa de estar ativo.
fn watchdog_dpc(_dpc: u64, context: u64, _first: u64, _second: u64) {
    let body = watchdog(context);
    check_signature(body);
    let _list = WATCHDOGS.lock();
    if body.armed.get() != 0 && body.worker_queued.get() == 0 {
        body.worker_queued.set(1);
        work_items::queue_kernel_ex_work_item(body.work_item.address(), watchdog_worker, context);
    }
    body.timer_active.set(0);
    update_no_workers_event(body);
}

/// PopResolveWatchdogParam (0x578cac): o valor, ou o QWORD para onde ele
/// aponta quando o parâmetro é indireto (-1 se a leitura falhar).
fn resolve_parameter(value: u64, indirect: bool) -> u64 {
    if !indirect {
        return value;
    }
    guest::try_read::<u64>(value).unwrap_or(u64::MAX)
}

/// PopWatchdogWorker(Watchdog): desarmado ou antes do prazo, só sai da fila;
/// vencido, anexa a sessão dos parâmetros (MmGetSessionById /
/// MmAttachSession), resolve os parâmetros e chama o callback(Context, Code,
/// P1, P2, P3, P4) ou o KeBugCheckEx(Code, P1, P2, P3, P4).
fn watchdog_worker(_device: u64, context: u64) {
    let body = watchdog(context);
    let snapshot = {
        let _list = WATCHDOGS.lock();
        if body.armed.get() == 0 || clock::uptime_100ns() < body.due_time.get() {
            body.worker_queued.set(0);
            update_no_workers_event(body);
            return;
        }
        let parameters = &body.parameters;
        (
            parameters.session_id.get(),
            parameters.bug_check_code.get(),
            [0, 1, 2, 3].map(|index| (parameters.parameters[index].get(), parameters.indirect[index].get() != 0)),
            parameters.callback.get(),
            parameters.callback_context.get(),
        )
    };
    let (session_id, code, raw, callback, callback_context) = snapshot;
    let session_process = if session_id != u32::MAX { crate::ntos::mm::session::by_id(session_id) } else { 0 };
    let apc_state = if session_process != 0 { guest::alloc_bytes(KapcState::SIZE) } else { 0 };
    let attached = apc_state != 0 && matches!(crate::ntos::mm::session::attach(session_process, apc_state), Ok(0));
    let [p1, p2, p3, p4] = raw.map(|(value, indirect)| resolve_parameter(value, indirect));
    if callback == 0 {
        bugcheck::bug_check_ex(code, p1, p2, p3, p4);
    }
    native_call::call(callback, &[callback_context, code as u64, p1, p2, p3, p4]);
    {
        let _list = WATCHDOGS.lock();
        body.worker_queued.set(0);
        update_no_workers_event(body);
    }
    if attached {
        let _ = crate::ntos::mm::session::detach(session_process, apc_state);
    }
    if apc_state != 0 {
        guest::free_bytes(apc_state);
    }
    if session_process != 0 {
        // MmQuitNextSession: a referência do MmGetSessionById.
        let _ = crate::ntos::ps::process::dereference(session_process);
    }
}

/// PowerInternalSetWatchdog (PopPowerInformationInternal 0x6f1c02) sobre a
/// entrada (de modo kernel, sem captura) de `input_length` bytes: menos de
/// 0x60 ou um watchdog NULL sem saída dão STATUS_BUFFER_TOO_SMALL. Um
/// watchdog 0x19C atualiza o PopBsdPowerWatchdogArmed (armado com prazo e
/// sem Delete, com o estágio no primeiro parâmetro). Com saída, o resultado
/// são os 8 bytes do PVOID do watchdog (0 depois de apagado), que o fim comum
/// copia (o 19041 os põe num bloco de pool de 8 bytes alocado antes do
/// PopSetWatchdog).
pub fn set_watchdog_request(input: u64, input_length: usize, has_output: bool) -> Result<Vec<u8>, u32> {
    if input_length < SET_WATCHDOG_INPUT {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    // SAFETY: a entrada de modo kernel do chamador, com os 0x60 bytes
    // conferidos acima.
    let request = unsafe { PowerInternalSetWatchdogInput::at(input) };
    if request.watchdog.get() == 0 && !has_output {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let parameters = &request.parameters;
    let delete = request.delete.get() != 0;
    if parameters.bug_check_code.get() == WIN32K_POWER_WATCHDOG_TIMEOUT {
        if !delete && parameters.timeout.get() != 0 {
            BSD_LAST_POWER_WATCHDOG_STAGE.store(parameters.parameters[0].get() as u32, Ordering::Relaxed);
            BSD_POWER_WATCHDOG_ARMED.store(1, Ordering::Relaxed);
        } else {
            BSD_POWER_WATCHDOG_ARMED.store(0, Ordering::Relaxed);
        }
    }
    let object = set_watchdog(request.watchdog.get(), parameters, delete);
    Ok(if has_output { object.to_le_bytes().to_vec() } else { Vec::new() })
}

/// PopBsdPowerWatchdogArmed e PopBsdLastPowerWatchdogStage.
pub fn bsd_power_watchdog() -> (bool, u32) {
    (BSD_POWER_WATCHDOG_ARMED.load(Ordering::Relaxed) != 0, BSD_LAST_POWER_WATCHDOG_STAGE.load(Ordering::Relaxed))
}

/// Se o watchdog está armado e com o timer na fila (para os autotestes).
pub fn is_armed(object: u64) -> bool {
    WATCHDOGS.lock().contains(&object) && watchdog(object).armed.get() != 0 && timer::query_due_time(watchdog(object).timer.address()) != 0
}

/// Se o watchdog ainda está na PopWatchdogList.
pub fn is_live(object: u64) -> bool {
    WATCHDOGS.lock().contains(&object)
}
