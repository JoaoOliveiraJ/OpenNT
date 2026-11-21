//! As threads de usuário despachadas nos APs (`threads::dispatch_on_processor`,
//! a posse entre CPUs do `ke/thread_dispatch` e o shootdown de TLB das raízes
//! de usuário). Só com dois processadores ou mais.
//!
//! Os APs são armados e passam a despachar usuário; o BSP, que roda o teste,
//! não dá intervalo nenhum nas fases em que só gira esperando, então o que
//! anda no anel 3 nessas fases anda num AP.
//!
//! - Execução nos APs: uma thread repete um serviço que anota a CPU em que
//!   roda; com o BSP só girando, as chamadas vêm dos APs.
//! - A espera adiada entre CPUs: uma thread num AP repete uma espera adiada
//!   (a do NtWaitFor*, STATUS_PENDING com a espera instalada) num evento de
//!   sincronização que o BSP sinaliza uma vez a cada volta dela. Cada sinal
//!   conclui exatamente uma espera (a que ainda não ligou os blocos o acha
//!   na ligação; a ligada e ainda na CPU sai abortada e volta direto à
//!   fila), nenhuma se perde, e o anel 3 nunca vê o STATUS_PENDING (a
//!   conclusão por outra CPU antes de a thread deixar a dela não grava o
//!   CONTEXT por cima do resultado).
//! - A retomada entre CPUs: uma thread num AP se suspende a cada serviço e o
//!   BSP a retoma assim que vê a suspensão; uma retomada que chegue antes de
//!   ela deixar a CPU não se perde (a decisão do fim do intervalo sob o
//!   PrcbLock), e as voltas não param.
//! - O fim de um processo com threads girando no anel 3 dos APs: o pedido do
//!   BSP as encerra, e o processo acaba no prazo com o status pedido.
//! - O shootdown: uma thread num AP lê uma página em laço; o BSP a libera, e
//!   a leitura seguinte falta (a tradução velha não sobrevive na TLB do AP),
//!   e a exceção sem tratador encerra o processo.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::blocking_wait::{self, EXIT_SERVICE};
use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::ntos::ke::{clock, context_switch, dispatcher, smp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ps::user::memory;
use crate::ntos::ps::user::threads;

type Assert = fn(bool, &str);

/// Os serviços de teste: 0 anota a CPU, 1 espera adiada, 2 é a saída, 3
/// suspende a própria thread, 4 registra o STATUS_PENDING visto no anel 3.
const CPU_SERVICE: u32 = 0x1000;
const DEFERRED_SERVICE: u32 = 0x1001;
const SUSPEND_SERVICE: u32 = 0x1003;
const PENDING_SEEN_SERVICE: u32 = 0x1004;
const SERVICES: usize = 5;
/// Os pares sinaliza-limpa da fase da espera adiada.
const PAIRS: u64 = 500;
/// As voltas de suspensão e retomada.
const RESUMES: u64 = 500;
/// O prazo de cada fase.
const PHASE_MS: u64 = 30_000;

static SERVICE_TABLE: [AtomicU32; SERVICES] = [const { AtomicU32::new(0) }; SERVICES];
static SERVICE_ARGUMENTS: [AtomicU8; SERVICES] = [const { AtomicU8::new(0) }; SERVICES];

static STOP: AtomicBool = AtomicBool::new(false);
static BLOCK: AtomicU64 = AtomicU64::new(0);
/// As CPUs (bits pelo número) em que o serviço de CPU rodou.
static CPU_MASK: AtomicU64 = AtomicU64::new(0);
static AP_CALLS: AtomicU64 = AtomicU64::new(0);
static DEFERRED_CALLS: AtomicU64 = AtomicU64::new(0);
static DEFERRED_ON_AP: AtomicU64 = AtomicU64::new(0);
static SUSPENDS: AtomicU64 = AtomicU64::new(0);
static PENDING_SEEN: AtomicBool = AtomicBool::new(false);

fn stop() -> u64 {
    STOP.load(Ordering::SeqCst) as u64
}

/// Anota a CPU que atende e devolve: 0 segue o laço, 1 o encerra.
extern "win64" fn cpu_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let cpu = context_switch::processor();
    CPU_MASK.fetch_or(1 << cpu, Ordering::SeqCst);
    if cpu != 0 {
        AP_CALLS.fetch_add(1, Ordering::SeqCst);
    }
    stop()
}

/// A espera adiada no evento de sincronização, sem prazo; cada chamada depois
/// da primeira quer dizer que a anterior concluiu com 0.
extern "win64" fn deferred_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    DEFERRED_CALLS.fetch_add(1, Ordering::SeqCst);
    if context_switch::processor() != 0 {
        DEFERRED_ON_AP.fetch_add(1, Ordering::SeqCst);
    }
    if stop() != 0 {
        return 1;
    }
    threads::wait_objects(Vec::new(), alloc::vec![BLOCK.load(Ordering::SeqCst)], 1, 0, false) as u64
}

/// A thread corrente se suspende (o NtSuspendThread nela mesma) e devolve 0:
/// a suspensão vale quando ela deixa a CPU, na saída do serviço.
extern "win64" fn suspend_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    if stop() != 0 {
        return 1;
    }
    SUSPENDS.fetch_add(1, Ordering::SeqCst);
    threads::suspend_thread(crate::ntos::ps::process::get_current_thread());
    0
}

/// O anel 3 viu STATUS_PENDING na volta de um serviço.
extern "win64" fn pending_seen_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    PENDING_SEEN.store(true, Ordering::SeqCst);
    1
}

/// `mov eax, número; mov r10, rcx; syscall`.
fn syscall(program: &mut Vec<u8>, number: u32) {
    program.push(0xB8);
    program.extend_from_slice(&number.to_le_bytes());
    program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05]);
}

/// `laço: serviço; cmp eax, 0x103; je visto; test eax, eax; jz laço`, a
/// saída e `jmp $`; em `visto`, o serviço que registra o STATUS_PENDING.
fn looping_program(service: u32) -> Vec<u8> {
    let mut program = Vec::new();
    syscall(&mut program, service);
    program.extend_from_slice(&[0x3D, 0x03, 0x01, 0x00, 0x00, 0x74, 16, 0x85, 0xC0, 0x74]);
    program.push((-(program.len() as i8) - 1) as u8);
    syscall(&mut program, EXIT_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    syscall(&mut program, PENDING_SEEN_SERVICE);
    program.extend_from_slice(&[0xEB, 0xFE]);
    program
}

/// `mov rbx, página; mov rcx, contador; laço: mov eax, [rbx]; inc dword
/// [rcx]; jmp laço`: lê a página para sempre e conta as voltas.
fn reader_program(page: u64, counter: u64) -> Vec<u8> {
    let mut program = alloc::vec![0x48, 0xBB];
    program.extend_from_slice(&page.to_le_bytes());
    program.extend_from_slice(&[0x48, 0xB9]);
    program.extend_from_slice(&counter.to_le_bytes());
    program.extend_from_slice(&[0x8B, 0x03, 0xFF, 0x01, 0xEB, 0xFA]);
    program
}

/// Gira no BSP, sem dar intervalo nenhum, até `done` valer ou o prazo.
fn spin_until(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = clock::uptime_ms() + timeout_ms;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    done()
}

/// Despacha no BSP também até `done` valer ou o prazo.
fn dispatch_until(timeout_ms: u64, mut done: impl FnMut() -> bool) -> bool {
    let deadline = clock::uptime_ms() + timeout_ms;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        let _ = threads::dispatch_round();
    }
    done()
}

/// Pede o fim, solta a espera e espera o processo sair, com prazo.
fn finish(process: u64) -> bool {
    STOP.store(true, Ordering::SeqCst);
    let block = BLOCK.load(Ordering::SeqCst);
    if block != 0 {
        dispatcher::set_event(block);
    }
    for thread in threads::of_process(process) {
        while thread.with(|thread| thread.suspend_count) != 0 {
            threads::resume_thread(thread.pointer());
        }
    }
    let ended = dispatch_until(PHASE_MS, || threads::of_process(process).iter().all(|thread| thread.dead()));
    ended && threads::wait_for_process(process).is_ok()
}

fn release(regions: &[u64]) {
    for &base in regions {
        if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
            memory::release_private_region(&region);
        }
    }
}

/// O que as fases observaram.
#[derive(Debug, Default)]
struct Outcome {
    ran_on_aps: bool,
    ap_calls: u64,
    cpu_mask: u64,
    pairs: u64,
    completed: u64,
    deferred_on_ap: u64,
    deferred_finished: bool,
    resumes: u64,
    suspends: u64,
    resumed_finished: bool,
    exit_spinning: bool,
    exit_status: u32,
    faulted: bool,
    reader_counted: bool,
}

/// Execução nos APs: o BSP só gira, e o serviço é atendido num AP.
fn phase_execution(outcome: &mut Outcome) {
    let _ = with_test_process("smp-execucao.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4));
        let first = blocking_wait::user_thread(test.process, code);
        let second = blocking_wait::user_thread(test.process, code);
        if let (Some(first), Some(second), true) = (first.as_ref(), second.as_ref(), code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(CPU_SERVICE));
            STOP.store(false, Ordering::SeqCst);
            CPU_MASK.store(0, Ordering::SeqCst);
            AP_CALLS.store(0, Ordering::SeqCst);
            if blocking_wait::prepare_partner(second, code, stacks + 0x8000 - 0x28) && threads::start(first, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                threads::resume_thread(second.pointer());
                outcome.ran_on_aps = spin_until(PHASE_MS, || AP_CALLS.load(Ordering::SeqCst) >= 1000);
                outcome.ap_calls = AP_CALLS.load(Ordering::SeqCst);
                outcome.cpu_mask = CPU_MASK.load(Ordering::SeqCst);
                finish(test.process);
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        release(&[code, stacks]);
    });
}

/// A espera adiada concluída pelo BSP com a thread num AP.
fn phase_deferred(outcome: &mut Outcome) {
    let _ = with_test_process("smp-espera.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x4000, 4));
        let block = guest::alloc_bytes(0x40);
        let waiter = blocking_wait::user_thread(test.process, code);
        if let (Some(waiter), true) = (waiter.as_ref(), block != 0 && code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(DEFERRED_SERVICE));
            guest::write_bytes(block, &[0; 0x40]);
            dispatcher::initialize_event(block, 1, false);
            BLOCK.store(block, Ordering::SeqCst);
            STOP.store(false, Ordering::SeqCst);
            DEFERRED_CALLS.store(0, Ordering::SeqCst);
            DEFERRED_ON_AP.store(0, Ordering::SeqCst);
            PENDING_SEEN.store(false, Ordering::SeqCst);
            if threads::start(waiter, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                let deadline = clock::uptime_ms() + PHASE_MS;
                while outcome.pairs < PAIRS && clock::uptime_ms() < deadline && !PENDING_SEEN.load(Ordering::SeqCst) {
                    // Um sinal por volta, assim que ela entra no serviço de
                    // novo (todas as anteriores concluídas); o BSP não
                    // despacha: a thread roda num AP, e o sinal cai em
                    // qualquer ponto da volta dela.
                    if DEFERRED_CALLS.load(Ordering::SeqCst) == outcome.pairs + 1 {
                        dispatcher::set_event(block);
                        outcome.pairs += 1;
                    }
                    core::hint::spin_loop();
                }
                spin_until(5_000, || DEFERRED_CALLS.load(Ordering::SeqCst) > outcome.pairs);
                outcome.completed = DEFERRED_CALLS.load(Ordering::SeqCst).saturating_sub(1);
                outcome.deferred_on_ap = DEFERRED_ON_AP.load(Ordering::SeqCst);
                outcome.deferred_finished = finish(test.process);
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        BLOCK.store(0, Ordering::SeqCst);
        if block != 0 {
            guest::free_bytes(block);
        }
        release(&[code, stacks]);
    });
}

/// A thread num AP se suspende a cada serviço; o BSP a retoma.
fn phase_resume(outcome: &mut Outcome) {
    let _ = with_test_process("smp-retomada.exe", None, |test| {
        let (code, stacks) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x4000, 4));
        let thread = blocking_wait::user_thread(test.process, code);
        if let (Some(thread), true) = (thread.as_ref(), code != 0 && stacks != 0) {
            guest::write_bytes(code, &looping_program(SUSPEND_SERVICE));
            STOP.store(false, Ordering::SeqCst);
            SUSPENDS.store(0, Ordering::SeqCst);
            if threads::start(thread, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                let deadline = clock::uptime_ms() + PHASE_MS;
                while outcome.resumes < RESUMES && clock::uptime_ms() < deadline {
                    if thread.with(|thread| thread.suspend_count) != 0 {
                        threads::resume_thread(thread.pointer());
                        outcome.resumes += 1;
                    }
                    core::hint::spin_loop();
                }
                outcome.suspends = SUSPENDS.load(Ordering::SeqCst);
                outcome.resumed_finished = finish(test.process);
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        release(&[code, stacks]);
    });
}

/// O fim do processo pedido pelo BSP com as threads girando no anel 3 dos
/// APs.
fn phase_exit(outcome: &mut Outcome) {
    let _ = with_test_process("smp-fim.exe", None, |test| {
        let (code, stacks, counters) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x8000, 4), blocking_wait::allocate(0x1000, 4));
        let first = blocking_wait::user_thread(test.process, code);
        let second = blocking_wait::user_thread(test.process, code);
        if let (Some(first), Some(second), true) = (first.as_ref(), second.as_ref(), code != 0 && stacks != 0 && counters != 0) {
            guest::write_bytes(code, &reader_program(counters + 0x800, counters));
            guest::write32(counters, 0);
            if blocking_wait::prepare_partner(second, code, stacks + 0x8000 - 0x28) && threads::start(first, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                threads::resume_thread(second.pointer());
                // As duas no anel 3 (uma a cada AP, ou em vez nele): o contador anda.
                let spinning = spin_until(PHASE_MS, || guest::read32(counters) > 100_000);
                crate::ntos::ps::create::exit_process(test.process, 0x77);
                let ended = dispatch_until(PHASE_MS, || first.dead() && second.dead());
                outcome.exit_spinning = spinning && ended && threads::wait_for_process(test.process).is_ok();
                // SAFETY: o EPROCESS do processo de teste, retido até o fim.
                outcome.exit_status = unsafe { Eprocess::at(test.process) }.exit_status.get() as u32;
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        release(&[code, stacks, counters]);
    });
}

/// O shootdown: a página que a thread do AP lê em laço é liberada pelo BSP.
fn phase_shootdown(outcome: &mut Outcome) {
    let _ = with_test_process("smp-tlb.exe", None, |test| {
        let (code, stacks, page, counters) = (blocking_wait::allocate(0x1000, 0x40), blocking_wait::allocate(0x4000, 4), blocking_wait::allocate(0x1000, 4), blocking_wait::allocate(0x1000, 4));
        let reader = blocking_wait::user_thread(test.process, code);
        if let (Some(reader), true) = (reader.as_ref(), code != 0 && stacks != 0 && page != 0 && counters != 0) {
            guest::write_bytes(code, &reader_program(page, counters));
            guest::write32(counters, 0);
            guest::write32(page, 0x5A5A_5A5A);
            if threads::start(reader, code, stacks + 0x4000 - 0x28, 0, 0).is_ok() {
                // A leitura anda num AP (o BSP só gira).
                outcome.reader_counted = spin_until(PHASE_MS, || guest::read32(counters) > 100_000);
                release(&[page]);
                // A próxima leitura falta: a exceção sem tratador encerra o
                // processo. Com a tradução velha viva na TLB do AP, ela
                // seguiria lendo o frame liberado para sempre.
                let ended = dispatch_until(PHASE_MS, || reader.dead());
                // SAFETY: o EPROCESS do processo de teste, retido até o fim.
                let status = unsafe { Eprocess::at(test.process) }.exit_status.get() as u32;
                // O processo de teste não tem ntdll: a falta de acesso não
                // tem KiUserExceptionDispatcher e encerra o processo com
                // STATUS_ENTRYPOINT_NOT_FOUND (a entrega recusada).
                outcome.faulted = ended && threads::wait_for_process(test.process).is_ok() && status == 0xC000_0139;
                if !outcome.faulted {
                    crate::debug_print!("[smp-usuario] shootdown: fim={} status={:#x}", ended, status);
                }
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        release(&[code, stacks, counters]);
    });
}

pub fn run(assert: Assert) {
    if smp::online_cpu_count() < 2 {
        return;
    }
    if !usermode::ready() {
        assert(false, "smp-usuario: anel 3 armado");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "smp-usuario: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "smp-usuario: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; SERVICES] = [cpu_service, deferred_service, blocking_wait::exit_service, suspend_service, pending_seen_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || EXIT_SERVICE != 0x1002 || service_table::publish_shadow_second_table(table, SERVICES as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "smp-usuario: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }
    // Os APs armados despacham usuário durante o teste; sem a opção de boot,
    // voltam a só atender trabalhos no fim.
    smp::start_scheduling_all();
    let enabled_at_boot = smp::user_dispatch_enabled();
    smp::enable_user_dispatch();
    threads::force_fast_exit(true);
    let mut outcome = Outcome::default();
    phase_execution(&mut outcome);
    phase_deferred(&mut outcome);
    phase_resume(&mut outcome);
    phase_exit(&mut outcome);
    phase_shootdown(&mut outcome);
    threads::force_fast_exit(false);
    if !enabled_at_boot {
        smp::disable_user_dispatch();
    }
    crate::debug_print!("[smp-usuario] {:?}", outcome);
    assert(outcome.ran_on_aps && outcome.cpu_mask & !1 != 0, "smp-usuario: com o BSP so girando, as threads de usuario rodam nos APs (o servico atendido num AP)");
    assert(outcome.deferred_finished && outcome.pairs == PAIRS && outcome.completed == PAIRS && outcome.deferred_on_ap != 0 && !PENDING_SEEN.load(Ordering::SeqCst), "smp-usuario: cada sinal do BSP conclui exatamente uma espera adiada da thread num AP, sem perder nenhum, e o anel 3 nunca ve STATUS_PENDING");
    assert(outcome.resumed_finished && outcome.resumes == RESUMES && outcome.suspends >= RESUMES, "smp-usuario: a thread num AP que se suspende a cada servico e retomada pelo BSP sem perder nenhuma retomada");
    assert(outcome.exit_spinning && outcome.exit_status == 0x77, "smp-usuario: o fim do processo pedido pelo BSP encerra as threads que giram no anel 3 dos APs, com o status pedido");
    assert(outcome.reader_counted && outcome.faulted, "smp-usuario: a pagina liberada pelo BSP falta na leitura seguinte da thread do AP (shootdown da raiz de usuario)");
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
