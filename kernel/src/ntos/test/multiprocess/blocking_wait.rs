//! Esperas que bloqueiam (`ke/context_switch.rs`,
//! `hal/amd64/context_switch.rs`, o laço de `ps/user/threads.rs`):
//!
//! - duas threads de usuário de um processo real, no despachante de verdade
//!   (`threads::run`). A 1 faz uma syscall de teste (tabela 1 do Shadow,
//!   threads GUI) cujo serviço espera um KEVENT por
//!   `dispatcher::wait_for_single_object`, sem prazo; a 2 só fica pronta
//!   quando a 1 já está nesse serviço e faz a syscall que sinaliza o evento.
//!   O serviço da 2 vê a 1 bloqueada no kernel (KTHREAD em Waiting, quadro
//!   salvo em KernelStack dentro da pilha dela); a 1 é retomada na própria
//!   pilha, a espera devolve STATUS_SUCCESS, a syscall devolve 0 ao anel 3,
//!   e as duas terminam. No código sem a troca a espera gira o pump dentro
//!   do serviço da 1, a 2 nunca roda, e o prazo do test-boot derruba a
//!   suíte;
//! - uma thread terminada (NtTerminateThread de outra) enquanto bloqueada:
//!   a espera conclui com STATUS_THREAD_IS_TERMINATING, o serviço é desfeito
//!   na pilha dela, que segue viva até isso, e as duas terminam;
//! - uma thread com estado do win32k (KTHREAD.Win32Thread, aqui um bloco do
//!   teste) terminada enquanto bloqueada numa espera não alertável de
//!   UserMode, como a do xxxRealSleepThread: o NtTerminateThread só pede o
//!   término (a thread segue viva, com CrossThreadFlags.Terminated e
//!   TerminationApcRequest), a espera sai com STATUS_USER_APC na pilha dela,
//!   o serviço volta e, no fim dele, a thread roda o próprio PspExitThread:
//!   as rotinas de saída de thread a veem como a thread corrente, na própria
//!   pilha de kernel, num intervalo de serviço e com o Win32Thread ainda
//!   publicado; ela não volta ao anel 3.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Ethread, Kevent, Kthread, NtStruct};
use crate::ntos::ke::context_switch::STATUS_THREAD_IS_TERMINATING;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::user::threads::{self, KernelState, UserThread};
use crate::ntos::ps::user::{memory, state};
use crate::ntos::ps::{cid, process};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

/// Os serviços de teste: índices 0-4 da tabela 1.
const WAIT_SERVICE: u32 = 0x1000;
const SIGNAL_SERVICE: u32 = 0x1001;
pub(super) const EXIT_SERVICE: u32 = 0x1002;
const TERMINATE_SERVICE: u32 = 0x1003;
const RELEASE_SERVICE: u32 = 0x1004;
const SERVICES: usize = 5;
/// O resultado da espera antes de o serviço publicá-lo.
const UNSET: u32 = 0xFFFF_FFFF;
/// Onde a thread 1 guarda, no anel 3, o RAX devolvido pela syscall de espera.
const RESULT_OFFSET: u64 = 0x800;
pub(super) const KTHREAD_WAITING: u8 = 5;

/// A tabela compactada dos serviços, na imagem do kernel (a entrada é
/// relativa à tabela e só alcança ±128 MB).
static SERVICE_TABLE: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICES] = [const { AtomicU8::new(0) }; SERVICES];

/// O KEVENT esperado, a KTHREAD que espera e a parceira que ela libera.
static EVENT: AtomicU64 = AtomicU64::new(0);
static WAITER: AtomicU64 = AtomicU64::new(0);
static PARTNER: SpinLock<Option<Arc<UserThread>>> = SpinLock::new(None);
/// Handle (no processo de teste) da thread que o serviço de término encerra.
static TARGET: AtomicU64 = AtomicU64::new(0);
/// O que os serviços observaram.
static WAIT_RESULT: AtomicU32 = AtomicU32::new(UNSET);
static RESUMED_ON_OWN_STACK: AtomicBool = AtomicBool::new(false);
static SAW_WAITER_BLOCKED: AtomicBool = AtomicBool::new(false);
static TERMINATE_STATUS: AtomicU32 = AtomicU32::new(UNSET);
/// O WaitMode da espera do serviço (KernelMode 0, UserMode 1).
static WAIT_MODE: AtomicU8 = AtomicU8::new(0);
/// Logo depois do NtTerminateThread, a terminada segue viva com o término
/// pedido (CrossThreadFlags.Terminated, TerminationApcRequest).
static REQUESTED_ALIVE: AtomicBool = AtomicBool::new(false);
/// A thread que a rotina de saída de teste observa e o que ela viu.
static PROBED: AtomicU64 = AtomicU64::new(0);
static PROBE_SEEN: AtomicU32 = AtomicU32::new(0);
/// O Win32Thread que o teste publicou na thread GUI.
static WIN32_THREAD: AtomicU64 = AtomicU64::new(0);
static PROBE_REGISTERED: AtomicBool = AtomicBool::new(false);
/// Bits de `PROBE_SEEN`: a rotina rodou para a thread observada, ela era a
/// corrente, o RSP estava na pilha de kernel dela, num intervalo de serviço,
/// e o Win32Thread ainda era o publicado.
const SEEN_RAN: u32 = 1;
const SEEN_CURRENT: u32 = 2;
const SEEN_OWN_STACK: u32 = 4;
const SEEN_SERVICE: u32 = 8;
const SEEN_WIN32_THREAD: u32 = 16;
const SEEN_ALL: u32 = SEEN_RAN | SEEN_CURRENT | SEEN_OWN_STACK | SEEN_SERVICE | SEEN_WIN32_THREAD;
const STATUS_USER_APC: u32 = 0xC0;

fn kthread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva, criada e retida pelo teste.
    unsafe { Kthread::at(pointer) }
}

fn current_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: só lê o registrador.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

/// A thread esperando está bloqueada no kernel: espera pendente, KTHREAD em
/// Waiting e o quadro de troca salvo em KernelStack, dentro da pilha dela.
fn waiter_blocked() -> bool {
    let waiter = WAITER.load(Ordering::SeqCst);
    let blocked = threads::find_by_pointer(waiter).is_some_and(|thread| thread.kernel_state() == KernelState::Blocked { status: None });
    let tcb = kthread(waiter);
    let saved = tcb.kernel_stack.get();
    blocked && tcb.state.get() == KTHREAD_WAITING && saved > tcb.stack_limit.get() && saved < tcb.initial_stack.get() && WAIT_RESULT.load(Ordering::SeqCst) == UNSET
}

/// Espera o KEVENT sem prazo. Só depois de entrar aqui a parceira fica
/// pronta: ela nunca roda antes de esta thread estar no serviço.
extern "win64" fn wait_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let partner = PARTNER.lock().take();
    if let Some(partner) = partner {
        partner.with(|thread| thread.suspend_count = 0);
    }
    let before = current_rsp();
    let status = dispatcher::wait_for_single_object(EVENT.load(Ordering::SeqCst), 0, WAIT_MODE.load(Ordering::SeqCst), false);
    let after = current_rsp();
    let thread = process::get_current_thread();
    let tcb = kthread(thread);
    let own_stack = thread == WAITER.load(Ordering::SeqCst)
        && before == after
        && after > tcb.stack_limit.get()
        && after < tcb.initial_stack.get()
        && tcb.kernel_stack.get() == tcb.initial_stack.get()
        && kernel_stack::find(tcb.stack_base.get()).is_some();
    RESUMED_ON_OWN_STACK.store(own_stack, Ordering::SeqCst);
    WAIT_RESULT.store(status, Ordering::SeqCst);
    status as u64
}

/// Só libera a parceira e volta (a thread 1 segue girando no anel 3).
extern "win64" fn release_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let partner = PARTNER.lock().take();
    if let Some(partner) = partner {
        partner.with(|thread| thread.suspend_count = 0);
    }
    0
}

/// Confere que a thread 1 está bloqueada no kernel e sinaliza o evento.
extern "win64" fn signal_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    SAW_WAITER_BLOCKED.store(waiter_blocked(), Ordering::SeqCst);
    dispatcher::set_event(EVENT.load(Ordering::SeqCst));
    0
}

/// NtTerminateThread da thread corrente.
pub(super) extern "win64" fn exit_service(code: u64, _: u64, _: u64, _: u64) -> u64 {
    state::handler("NtTerminateThread").map_or(0xC000_0001, |handler| handler(0, code, 0, 0, 0).unwrap_or(0xC000_0001)) as u64
}

/// NtTerminateThread da thread 1, bloqueada no kernel.
extern "win64" fn terminate_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    SAW_WAITER_BLOCKED.store(waiter_blocked(), Ordering::SeqCst);
    let status = state::handler("NtTerminateThread").map_or(0xC000_0001, |handler| handler(TARGET.load(Ordering::SeqCst), 0x77, 0, 0, 0).unwrap_or(0xC000_0001));
    TERMINATE_STATUS.store(status, Ordering::SeqCst);
    let waiter = WAITER.load(Ordering::SeqCst);
    let alive = threads::find_by_pointer(waiter).is_some_and(|thread| !thread.dead() && thread.termination_pending());
    // SAFETY: a ETHREAD da thread 1, retida pela thread de usuário dela.
    let flagged = unsafe { Ethread::at(waiter) }.terminated() != 0 && kthread(waiter).termination_apc_request() != 0;
    REQUESTED_ALIVE.store(alive && flagged, Ordering::SeqCst);
    status as u64
}

/// A rotina de saída de thread do teste: para a thread observada, o contexto
/// em que o PspExitThread roda as rotinas de saída.
fn exit_probe(thread: u64) {
    if thread == 0 || thread != PROBED.load(Ordering::SeqCst) {
        return;
    }
    let tcb = kthread(thread);
    let rsp = current_rsp();
    let mut seen = SEEN_RAN;
    if process::get_current_thread() == thread {
        seen |= SEEN_CURRENT;
    }
    if rsp > tcb.stack_limit.get() && rsp < tcb.initial_stack.get() {
        seen |= SEEN_OWN_STACK;
    }
    if usermode::in_service() {
        seen |= SEEN_SERVICE;
    }
    let win32_thread = tcb.win32_thread.get();
    if win32_thread != 0 && win32_thread == WIN32_THREAD.load(Ordering::SeqCst) {
        seen |= SEEN_WIN32_THREAD;
    }
    PROBE_SEEN.fetch_or(seen, Ordering::SeqCst);
}

/// `mov eax, serviço; mov r10, rcx; syscall`.
fn syscall(program: &mut Vec<u8>, service: u32) {
    program.push(0xB8);
    program.extend_from_slice(&service.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05]);
}

/// Uma syscall, opcionalmente `mov [rip+..], eax` para a célula de resultado
/// (o programa começa em `code + start`), a syscall de saída e `jmp $`.
pub(super) fn program(service: u32, start: u64, store_result: bool) -> Vec<u8> {
    let mut program = Vec::new();
    syscall(&mut program, service);
    if store_result {
        let next = start + program.len() as u64 + 6;
        program.extend_from_slice(&[0x89, 0x05]);
        program.extend_from_slice(&((RESULT_OFFSET as i64 - next as i64) as i32).to_le_bytes());
    }
    syscall(&mut program, EXIT_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    program
}

/// Uma thread de usuário GUI do processo corrente, com pilha de kernel
/// própria, contada no EPROCESS (o término a desconta).
pub(super) fn user_thread(process_pointer: u64, start: u64) -> Option<Arc<UserThread>> {
    let stack = kernel_stack::create(false).ok()?;
    let pointer = process::create_kernel_thread(process_pointer, cid::ALLOCATE, true, 1, Some(stack)).ok()?;
    // SAFETY: ETHREAD recém-criada, retida pela thread de usuário.
    let ethread = unsafe { Ethread::at(pointer) };
    ethread.tcb.set_gui_thread(1);
    let thread = UserThread::new(ethread.cid.unique_thread.get(), pointer, 0, start);
    thread.with(|thread| thread.process_pointer = process_pointer);
    process::add_thread(process_pointer);
    threads::push(thread.clone());
    Some(thread)
}

/// A parceira: CONTEXT próprio, registrada no despacho e suspensa até a
/// thread 1 entrar no serviço de espera.
pub(super) fn prepare_partner(thread: &Arc<UserThread>, start: u64, stack_top: u64) -> bool {
    let context = guest::alloc_bytes(threads::CONTEXT_SIZE);
    if context == 0 {
        return false;
    }
    threads::initialize_context(context, start, stack_top, 0, 0);
    let pointer = thread.pointer();
    thread.with(|thread| {
        thread.context = context;
        thread.suspend_count = 1;
    });
    process::describe_thread(pointer, None, false);
    process::set_thread_start(pointer, start);
    // O cabeçalho da KTHREAD é um objeto de notificação do tipo Thread.
    dispatcher::initialize_event(pointer, 6, false);
    threads::attach_scheduling(thread).is_ok()
}

/// Os cenários: a 2 sinaliza o evento, termina a 1 sem estado do win32k
/// (espera de KernelMode), termina a 1 com Win32Thread (espera de UserMode)
/// ou termina a 1 com Win32Thread girando no anel 3.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Signal,
    Terminate,
    TerminateGui,
    TerminateGuiRing3,
}

/// O que um cenário observou.
struct Outcome {
    ran: bool,
    user_result: u32,
    wait_result: u32,
    own_stack: bool,
    saw_blocked: bool,
    terminate_status: u32,
    requested_alive: bool,
    probe: u32,
    dead: bool,
    stacks_released: bool,
}

/// Memória de usuário do processo corrente (`protect`: 0x40 RWX, 4 RW).
pub(super) fn allocate(size: u64, protect: u32) -> u64 {
    let scratch = guest::alloc_bytes(16);
    if scratch == 0 {
        return 0;
    }
    guest::write64(scratch, 0);
    guest::write64(scratch + 8, size);
    let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
    let base = if status == 0 { guest::read64(scratch) } else { 0 };
    guest::free_bytes(scratch);
    base
}

/// Roda as duas threads no despachante: a 1 (principal) espera, a 2
/// sinaliza o evento ou encerra a 1.
fn scenario(kind: Scenario) -> Option<Outcome> {
    let name = match kind {
        Scenario::Signal => "bloqueio.exe",
        Scenario::Terminate => "bloqueio-termino.exe",
        Scenario::TerminateGui => "bloqueio-termino-gui.exe",
        Scenario::TerminateGuiRing3 => "anel3-termino-gui.exe",
    };
    let terminate = kind != Scenario::Signal;
    let gui = matches!(kind, Scenario::TerminateGui | Scenario::TerminateGuiRing3);
    with_test_process(name, None, |test| {
        let (code, stacks) = (allocate(0x1000, 0x40), allocate(0x8000, 4));
        let event = guest::alloc_bytes(Kevent::SIZE);
        // O W32THREAD de teste: um bloco do kernel que só o teste lê.
        let win32_thread = if gui { guest::alloc_bytes(0x100) } else { 0 };
        let waiter = user_thread(test.process, code);
        let partner = user_thread(test.process, code + 0x100);
        let mut outcome = Outcome { ran: false, user_result: UNSET, wait_result: UNSET, own_stack: false, saw_blocked: false, terminate_status: UNSET, requested_alive: false, probe: 0, dead: false, stacks_released: false };
        let mut handle = 0;
        if let (Some(waiter), Some(partner), true) = (waiter.as_ref(), partner.as_ref(), event != 0 && code != 0 && stacks != 0 && (win32_thread != 0 || !gui)) {
            if kind == Scenario::TerminateGuiRing3 {
                // Libera a parceira e gira no anel 3 (`jmp $`): só o timer a
                // tira da CPU.
                let mut spin = Vec::new();
                syscall(&mut spin, RELEASE_SERVICE);
                spin.extend_from_slice(&[0xEB, 0xFE]);
                guest::write_bytes(code, &spin);
            } else {
                guest::write_bytes(code, &program(WAIT_SERVICE, 0, true));
            }
            guest::write_bytes(code + 0x100, &program(if terminate { TERMINATE_SERVICE } else { SIGNAL_SERVICE }, 0x100, false));
            guest::write32(code + RESULT_OFFSET, UNSET);
            dispatcher::initialize_event(event, 0, false);
            EVENT.store(event, Ordering::SeqCst);
            WAITER.store(waiter.pointer(), Ordering::SeqCst);
            WAIT_RESULT.store(UNSET, Ordering::SeqCst);
            TERMINATE_STATUS.store(UNSET, Ordering::SeqCst);
            RESUMED_ON_OWN_STACK.store(false, Ordering::SeqCst);
            SAW_WAITER_BLOCKED.store(false, Ordering::SeqCst);
            REQUESTED_ALIVE.store(false, Ordering::SeqCst);
            PROBE_SEEN.store(0, Ordering::SeqCst);
            // A espera do xxxRealSleepThread é de UserMode, não alertável.
            WAIT_MODE.store(gui as u8, Ordering::SeqCst);
            if gui {
                WIN32_THREAD.store(win32_thread, Ordering::SeqCst);
                kthread(waiter.pointer()).win32_thread.set(win32_thread);
                PROBED.store(waiter.pointer(), Ordering::SeqCst);
            }
            if terminate {
                handle = threads::thread_handle(waiter, 1, 0).unwrap_or(0);
                TARGET.store(handle, Ordering::SeqCst);
            }
            let bases = [kthread(waiter.pointer()).stack_base.get(), kthread(partner.pointer()).stack_base.get()];
            if prepare_partner(partner, code + 0x100, stacks + 0x8000 - 0x28) && (handle != 0 || !terminate) {
                *PARTNER.lock() = Some(partner.clone());
                outcome.ran = threads::run(waiter, code, stacks + 0x4000 - 0x28, 0, 0).is_ok();
            }
            PROBED.store(0, Ordering::SeqCst);
            WAIT_MODE.store(0, Ordering::SeqCst);
            if gui && waiter.pointer() != 0 {
                kthread(waiter.pointer()).win32_thread.set(0);
            }
            outcome.user_result = guest::read32(code + RESULT_OFFSET);
            outcome.wait_result = WAIT_RESULT.load(Ordering::SeqCst);
            outcome.own_stack = RESUMED_ON_OWN_STACK.load(Ordering::SeqCst);
            outcome.saw_blocked = SAW_WAITER_BLOCKED.load(Ordering::SeqCst);
            outcome.terminate_status = TERMINATE_STATUS.load(Ordering::SeqCst);
            outcome.requested_alive = REQUESTED_ALIVE.load(Ordering::SeqCst);
            outcome.probe = PROBE_SEEN.load(Ordering::SeqCst);
            outcome.dead = waiter.dead() && partner.dead() && !waiter.blocked_in_kernel() && !partner.blocked_in_kernel();
            if handle != 0 {
                let _ = state::close_user_handle(handle, true, false);
            }
            *PARTNER.lock() = None;
            threads::release_process(test.process);
            kernel_stack::reap();
            let listed = threads::all().iter().any(|thread| thread.with(|thread| thread.process_pointer) == test.process);
            outcome.stacks_released = bases.iter().all(|&base| kernel_stack::find(base).is_none()) && !listed;
        }
        // Conclui o que uma montagem incompleta deixou.
        threads::release_process(test.process);
        WIN32_THREAD.store(0, Ordering::SeqCst);
        for block in [event, win32_thread] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        for base in [code, stacks] {
            if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
                memory::release_private_region(&region);
            }
        }
        outcome
    })
}

pub fn run(assert: Assert) {
    if !usermode::ready() {
        assert(false, "bloqueio: anel 3 armado");
        return;
    }
    // A fila de prontas do despacho é a de todas as threads de usuário.
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "bloqueio: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "bloqueio: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICES] = [wait_service, signal_service, exit_service, terminate_service, release_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || service_table::publish_shadow_second_table(table, SERVICES as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "bloqueio: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }

    // A rotina de saída de teste fica registrada (só observa a thread em
    // PROBED, zero fora do cenário GUI).
    if !PROBE_REGISTERED.swap(true, Ordering::SeqCst) {
        process::register_thread_exit_routine(exit_probe);
    }

    let signalled = scenario(Scenario::Signal);
    let ok = signalled.as_ref().is_some_and(|outcome| outcome.ran);
    assert(ok, "bloqueio: duas threads de usuario no despachante");
    if let Some(outcome) = signalled.filter(|_| ok) {
        assert(outcome.saw_blocked, "bloqueio: a thread 2 roda com a 1 bloqueada no kernel (KTHREAD em Waiting, quadro salvo em KernelStack)");
        assert(outcome.own_stack, "bloqueio: a thread 1 e retomada na propria pilha de kernel, viva durante o bloqueio");
        assert(outcome.wait_result == 0 && outcome.user_result == 0, "bloqueio: a espera devolve STATUS_SUCCESS e a syscall devolve 0 ao anel 3");
        assert(outcome.dead && outcome.stacks_released, "bloqueio: as duas threads terminam, as pilhas voltam ao Mm e nenhuma fica no indice");
    }

    let terminated = scenario(Scenario::Terminate);
    let ok = terminated.as_ref().is_some_and(|outcome| outcome.ran);
    assert(ok, "bloqueio: thread terminada enquanto bloqueada");
    if let Some(outcome) = terminated.filter(|_| ok) {
        assert(outcome.saw_blocked && outcome.terminate_status == 0, "bloqueio: NtTerminateThread de uma thread bloqueada no kernel");
        assert(outcome.wait_result == STATUS_THREAD_IS_TERMINATING && outcome.own_stack, "bloqueio: a espera da terminada conclui com THREAD_IS_TERMINATING, na pilha dela, ainda viva");
        assert(outcome.dead && outcome.stacks_released && outcome.user_result == UNSET, "bloqueio: a terminada desfaz o servico sem voltar ao anel 3, as pilhas voltam ao Mm e nenhuma fica no indice");
    }

    let gui = scenario(Scenario::TerminateGui);
    let ok = gui.as_ref().is_some_and(|outcome| outcome.ran);
    assert(ok, "bloqueio: thread GUI terminada enquanto bloqueada numa espera de UserMode");
    if let Some(outcome) = gui.filter(|_| ok) {
        crate::debug_print!("[bloqueio] GUI: espera={:#x} anel3={:#x} vista={:#x} pedido={}", outcome.wait_result, outcome.user_result, outcome.probe, outcome.requested_alive);
        assert(outcome.saw_blocked && outcome.terminate_status == 0 && outcome.requested_alive, "bloqueio: o NtTerminateThread de uma thread GUI bloqueada so pede o termino (ela segue viva, com Terminated e TerminationApcRequest)");
        assert(outcome.wait_result == STATUS_USER_APC && outcome.own_stack, "bloqueio: a APC de termino tira a thread GUI da espera de UserMode com STATUS_USER_APC, na pilha dela");
        assert(outcome.probe == SEEN_ALL, "bloqueio: o PspExitThread da thread GUI roda nela mesma: rotinas de saida com ela corrente, na propria pilha de kernel, num servico e com o Win32Thread ainda publicado");
        assert(outcome.dead && outcome.stacks_released && outcome.user_result == UNSET, "bloqueio: a thread GUI sai no fim do servico sem voltar ao anel 3, as pilhas voltam ao Mm e nenhuma fica no indice");
    }

    let ring3 = scenario(Scenario::TerminateGuiRing3);
    let ok = ring3.as_ref().is_some_and(|outcome| outcome.ran);
    assert(ok, "bloqueio: thread GUI terminada enquanto gira no anel 3");
    if let Some(outcome) = ring3.filter(|_| ok) {
        crate::debug_print!("[bloqueio] GUI no anel 3: vista={:#x} pedido={}", outcome.probe, outcome.requested_alive);
        assert(outcome.terminate_status == 0 && outcome.requested_alive, "bloqueio: o NtTerminateThread de uma thread GUI no anel 3 so pede o termino");
        assert(outcome.probe == SEEN_ALL, "bloqueio: a APC de termino da thread GUI que estava no anel 3 roda o PspExitThread na pilha de kernel dela, num intervalo de servico, com ela corrente e o Win32Thread publicado");
        assert(outcome.dead && outcome.stacks_released, "bloqueio: a thread GUI sai sem voltar ao anel 3, as pilhas voltam ao Mm e nenhuma fica no indice");
    }

    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
