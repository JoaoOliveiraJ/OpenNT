//! A hora vista do modo usuário pela ntdll real do volume e os serviços de
//! hora de um processo de teste.
//!
//! - Os serviços pelo handler de usuário do processo de teste (buffers na
//!   memória de usuário dele): NtQueryTimerResolution, NtSetTimerResolution
//!   de 1 ms (o pedido fica com o processo) e NtSetSystemTime com o
//!   SeSystemtimePrivilege desabilitado no token (STATUS_PRIVILEGE_NOT_HELD).
//! - Um programa no anel 3 chama a ntdll real mapeada no processo. Primeiro
//!   grava no RtlpHypervisorSharedUserVa da ntdll a VA que a classe 197 do
//!   NtQuerySystemInformation devolve (o que o LdrpInitializeProcess faz com
//!   a mesma consulta; a tabela de serviços dos autotestes é a da ntdll de
//!   bring-up, sem esse serviço); depois RtlQueryPerformanceCounter,
//!   RtlQueryPerformanceFrequency, NtQuerySystemTime (a ntdll lê a
//!   KUSER_SHARED_DATA), RtlGetSystemTimePrecise e RtlQueryPerformanceCounter
//!   de novo, e sai pelo NtTerminateProcess. Uma rotina de saída de processo
//!   copia a área de resultados antes de o espaço de endereçamento sair
//!   (pelas tabelas de páginas). O teste confere os valores contra o kernel,
//!   que nenhuma leitura do QPC entrou no kernel (o atalho do TSC pela página
//!   de referência) e que a saída do processo cancelou o pedido de resolução
//!   (ExCleanTimerResolutionRequest, a rotina de saída registrada antes).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::inc::types::{Eprocess, Ethread, NtStruct};
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::{self, LoadOptions};
use crate::ntos::mm::{kernel_stack, peb_teb};
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{loader, memory, state, time_services};
use crate::ntos::ps::{cid, process};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

/// SeSystemtimePrivilege e SE_PRIVILEGE_ENABLED.
const SE_SYSTEMTIME_PRIVILEGE: u64 = 12;
const SE_PRIVILEGE_ENABLED: u32 = 2;
/// Código de saída do programa.
const EXIT_CODE: u32 = 0x7154;
/// A área de resultados do programa.
const DATA_SIZE: usize = 0x200;

/// O processo de teste e a área de resultados dele; a cópia feita na saída.
static CAPTURE_PROCESS: AtomicU64 = AtomicU64::new(0);
static CAPTURE_DATA: AtomicU64 = AtomicU64::new(0);
static CAPTURED: SpinLock<Vec<u8>> = SpinLock::new(Vec::new());
/// KeTimeIncrement visto na saída, depois do ExCleanTimerResolutionRequest.
static INCREMENT_AT_EXIT: AtomicU64 = AtomicU64::new(0);

core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_time_services_program, "a"
.balign 16
.global opennt_tks_start
opennt_tks_start:
    sub rsp, 0x28
    lea rbx, [rip + opennt_tks_data]
    mov rax, qword ptr [rbx + 0x30]
    mov rcx, qword ptr [rbx + 0x28]
    mov qword ptr [rcx], rax
    lea rcx, [rbx + 0x100]
    call qword ptr [rbx + 0x00]
    lea rcx, [rbx + 0x108]
    call qword ptr [rbx + 0x08]
    lea rcx, [rbx + 0x110]
    call qword ptr [rbx + 0x10]
    call qword ptr [rbx + 0x18]
    mov qword ptr [rbx + 0x118], rax
    lea rcx, [rbx + 0x120]
    call qword ptr [rbx + 0x00]
    mov dword ptr [rbx + 0x178], 1
    mov rcx, -1
    mov edx, 0x7154
    call qword ptr [rbx + 0x20]
opennt_tks_hang:
    jmp opennt_tks_hang
.balign 16
.global opennt_tks_data
opennt_tks_data:
    .space 0x200
.global opennt_tks_end
opennt_tks_end:
.popsection
"#
);

extern "C" {
    static opennt_tks_start: u8;
    static opennt_tks_data: u8;
    static opennt_tks_end: u8;
}

/// O programa (código e a área de dados zerada).
fn program() -> &'static [u8] {
    // SAFETY: os rótulos delimitam o bloco somente leitura acima.
    unsafe {
        let start = &opennt_tks_start as *const u8;
        core::slice::from_raw_parts(start, (&opennt_tks_end as *const u8 as usize) - start as usize)
    }
}

fn data_offset() -> u64 {
    // SAFETY: rótulos do mesmo bloco.
    unsafe { &opennt_tks_data as *const u8 as u64 - &opennt_tks_start as *const u8 as u64 }
}

/// Os exports que o programa chama, na ordem da tabela de dados.
const IMPORTS: [&str; 5] = ["RtlQueryPerformanceCounter", "RtlQueryPerformanceFrequency", "NtQuerySystemTime", "RtlGetSystemTimePrecise", "NtTerminateProcess"];

/// Um byte de usuário pelas tabelas de páginas da raiz `root` (a imagem do
/// teste não tem região no VAD: a leitura não passa pela sonda de posse).
fn user_byte(root: u64, address: u64) -> Option<u8> {
    match crate::ntos::mm::paging::translate_in(root, address) {
        0 => None,
        physical => Some(crate::hal::physical::read8(physical)),
    }
}

/// A raiz própria do processo ou, sem ela, a corrente (a do System, que ele
/// divide).
fn root_of(process: u64) -> u64 {
    crate::ntos::mm::process_address_space::root_of(process).unwrap_or_else(crate::ntos::mm::paging::current_root)
}

/// O RtlpHypervisorSharedUserVa: o alvo do `mov r9, [rip+disp32]`
/// (4C 8B 0D) do começo do RtlQueryPerformanceCounter.
fn hypervisor_page_global(root: u64, function: u64) -> Option<u64> {
    let bytes: Vec<u8> = (0..0x60).map(|offset| user_byte(root, function + offset)).collect::<Option<_>>()?;
    let at = bytes.windows(3).position(|window| window == [0x4C, 0x8B, 0x0D])?;
    let displacement = i32::from_le_bytes(bytes.get(at + 3..at + 7)?.try_into().ok()?);
    Some((function + at as u64 + 7).wrapping_add(displacement as i64 as u64))
}

/// A rotina de saída de processo: a área de resultados do processo de teste.
fn capture_on_exit(process: u64) {
    if process == 0 || process != CAPTURE_PROCESS.load(Ordering::SeqCst) {
        return;
    }
    INCREMENT_AT_EXIT.store(clock::time_increment() as u64, Ordering::SeqCst);
    let root = root_of(process);
    let data = CAPTURE_DATA.load(Ordering::SeqCst);
    if let Some(bytes) = (0..DATA_SIZE as u64).map(|offset| user_byte(root, data + offset)).collect::<Option<Vec<u8>>>() {
        *CAPTURED.lock() = bytes;
    }
}

/// Memória de usuário do processo corrente (`protect`: 0x40 RWX, 4 RW).
fn allocate(size: u64, protect: u32) -> u64 {
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

/// O que os serviços, o programa e o kernel viram.
struct Outcome {
    /// NtQueryTimerResolution: (status, máximo, mínimo, corrente).
    query: (u32, u32, u32, u32),
    /// NtSetTimerResolution(1 ms): (status, ActualTime, KeTimeIncrement,
    /// EPROCESS.Flags.SetTimerResolution, RequestedTimerResolution).
    set: (u32, u32, u32, bool, u32),
    /// NtSetSystemTime sem o privilégio habilitado.
    set_time: u32,
    exit: Option<u32>,
    increment_at_exit: u64,
    data: Vec<u8>,
    calls: u64,
    before: (u64, i64, u64),
    after: (u64, i64, u64),
    hypervisor_page: u64,
}

fn read64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn read32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

/// Os instantes do kernel: (QPC, SystemTime do tick, hora precisa).
fn instants() -> (u64, i64, u64) {
    crate::ntos::mm::shared_user_data::update_system_times();
    (clock::query_performance_counter_value(), clock::shared_system_time(), clock::system_time_precise())
}

/// Um serviço de usuário pelo handler (o modo anterior é o de usuário).
fn service(name: &str, arguments: [u64; 4], rsp: u64) -> u32 {
    state::handler(name).map_or(1, |handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], rsp).unwrap_or(1))
}

fn scenario() -> Option<Outcome> {
    with_test_process("hora.exe", None, |test| {
        let (code, stacks) = (allocate(0x1000, 0x40), allocate(0x8000, 4));
        let stack = kernel_stack::create(false).ok();
        let pointer = stack.and_then(|stack| process::create_kernel_thread(test.process, cid::ALLOCATE, true, 1, Some(stack)).ok());
        let mut outcome = Outcome { query: (1, 0, 0, 0), set: (1, 0, 0, false, 0), set_time: 1, exit: None, increment_at_exit: 0, data: Vec::new(), calls: 0, before: (0, 0, 0), after: (0, 0, 0), hypervisor_page: 0 };
        let ntdll = loader::ntfs_volume().and_then(|volume| volume.read_bytes("/Windows/System32/ntdll.dll").ok().flatten()).and_then(|bytes| pe_loader::load_user(bytes, &LoadOptions { notify_image: false, ..LoadOptions::default() }).ok());
        let token = process::get_primary_token(test.process);
        if let (Some(pointer), Some(image), Some(token), true) = (pointer, ntdll.as_ref(), token, code != 0 && stacks != 0) {
            // SAFETY: ETHREAD recém-criada, retida pela thread de usuário.
            let ethread = unsafe { Ethread::at(pointer) };
            let teb = peb_teb::create_teb(&peb_teb::TebDescription { process_id: test.process_id, thread_id: ethread.cid.unique_thread.get(), peb: test.peb, stack_base: stacks + 0x8000, stack_limit: stacks, deallocation_stack: stacks, current_locale: 0 }).unwrap_or(0);
            let thread: Arc<UserThread> = UserThread::new(ethread.cid.unique_thread.get(), pointer, teb, code);
            thread.with(|thread| thread.process_pointer = test.process);
            process::add_thread(test.process);
            threads::push(thread.clone());
            guest::write_bytes(code, program());
            let data = code + data_offset();
            // O privilégio de mudar a hora desabilitado no token do processo.
            let saved = crate::ntos::se::token::tokens::update(token, |token| {
                let saved: Vec<(u64, u32)> = token.privileges.iter().map(|privilege| (privilege.id, privilege.attributes)).collect();
                for privilege in token.privileges.iter_mut().filter(|privilege| privilege.id == SE_SYSTEMTIME_PRIVILEGE) {
                    privilege.attributes &= !SE_PRIVILEGE_ENABLED;
                }
                saved
            });
            // Os serviços do processo, com as saídas na área do programa
            // (depois do que ele usa; a rotina de saída só copia os 0x200).
            let (scratch, rsp) = (data + 0x1C0, stacks + 0x8000 - 0x100);
            outcome.query = (service("NtQueryTimerResolution", [scratch, scratch + 4, scratch + 8, 0], rsp), guest::read32(scratch), guest::read32(scratch + 4), guest::read32(scratch + 8));
            let status = service("NtSetTimerResolution", [10_000, 1, scratch + 0xC, 0], rsp);
            // SAFETY: o EPROCESS do processo de teste.
            let object = unsafe { Eprocess::at(test.process) };
            outcome.set = (status, guest::read32(scratch + 0xC), clock::time_increment(), object.flags.get() & Eprocess::SET_TIMER_RESOLUTION_MASK != 0, object.requested_timer_resolution.get());
            guest::write64(scratch + 0x10, clock::system_time_precise());
            outcome.set_time = service("NtSetSystemTime", [scratch + 0x10, 0, 0, 0], rsp);
            guest::write_bytes(scratch, &[0; 0x20]);
            let exports = &image.exports.exports;
            let addresses: Vec<u64> = IMPORTS.iter().map(|name| exports.get(*name).copied().unwrap_or(0)).collect();
            let global = hypervisor_page_global(root_of(test.process), addresses[0]).unwrap_or(0);
            outcome.hypervisor_page = global;
            for (index, &address) in addresses.iter().enumerate() {
                guest::write64(data + index as u64 * 8, address);
            }
            guest::write64(data + 0x28, global);
            guest::write64(data + 0x30, crate::ntos::mm::shared_user_data::hypervisor_shared_user_va());
            if addresses.iter().all(|&address| address != 0) && global != 0 && teb != 0 {
                outcome.before = instants();
                let calls = time_services::performance_counter_calls();
                CAPTURED.lock().clear();
                CAPTURE_DATA.store(data, Ordering::SeqCst);
                CAPTURE_PROCESS.store(test.process, Ordering::SeqCst);
                process::register_process_exit_routine(capture_on_exit);
                outcome.exit = threads::run(&thread, code, stacks + 0x8000 - 0x28, 0, 0).ok();
                process::unregister_process_exit_routine(capture_on_exit);
                CAPTURE_PROCESS.store(0, Ordering::SeqCst);
                outcome.calls = time_services::performance_counter_calls() - calls;
                outcome.after = instants();
                outcome.data = core::mem::take(&mut *CAPTURED.lock());
                outcome.increment_at_exit = INCREMENT_AT_EXIT.load(Ordering::SeqCst);
            }
            if let Some(saved) = saved {
                crate::ntos::se::token::tokens::update(token, |token| {
                    for privilege in token.privileges.iter_mut() {
                        if let Some(&(_, attributes)) = saved.iter().find(|(id, _)| *id == privilege.id) {
                            privilege.attributes = attributes;
                        }
                    }
                });
            }
            threads::release_process(test.process);
            kernel_stack::reap();
        }
        threads::release_process(test.process);
        if let Some(mut image) = ntdll {
            let _ = image.release();
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
    if !usermode::ready() || loader::ntfs_volume().is_none() {
        assert(false, "hora: anel 3 armado e volume com a ntdll real");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "hora: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Some(outcome) = scenario() else {
        assert(false, "hora: processo de teste");
        return;
    };
    assert(outcome.query == (0, 156_250, 5000, 156_250), "hora: NtQueryTimerResolution do processo (15,625 ms, 0,5 ms e o corrente)");
    assert(outcome.set == (0, 10_000, 10_000, true, 10_000), "hora: NtSetTimerResolution(1 ms) do processo liga SetTimerResolution e afina o relogio");
    assert(outcome.set_time == 0xC000_0061, "hora: NtSetSystemTime sem SeSystemtimePrivilege habilitado e STATUS_PRIVILEGE_NOT_HELD");
    assert(outcome.exit == Some(EXIT_CODE) && outcome.data.len() == DATA_SIZE && read32(&outcome.data, 0x178) == 1 && outcome.hypervisor_page != 0, "hora: o programa chama a ntdll real e sai pelo NtTerminateProcess");
    if outcome.data.len() != DATA_SIZE {
        return;
    }
    let data = &outcome.data;
    let (qpc_before, shared_before, precise_before) = outcome.before;
    let (qpc_after, shared_after, precise_after) = outcome.after;
    let counters = [read64(data, 0x100), read64(data, 0x120)];
    let system_time = read64(data, 0x110) as i64;
    let precise = read64(data, 0x118);
    let ok = counters[0] >= qpc_before && counters[0] <= counters[1] && counters[1] <= qpc_after && read64(data, 0x108) == clock::QPC_FREQUENCY && outcome.calls == 0;
    if !ok {
        crate::debug_print!("[hora] QPC do kernel {}..{}, da ntdll {:?}, frequencia {}, chamadas ao kernel {}", qpc_before, qpc_after, counters, read64(data, 0x108), outcome.calls);
    }
    assert(ok, "hora: RtlQueryPerformanceCounter le o TSC pela pagina de referencia sem entrar no kernel, cresce e fica entre as leituras do kernel; RtlQueryPerformanceFrequency = 10 MHz");
    assert(system_time >= shared_before && system_time <= shared_after && precise >= precise_before && precise <= precise_after, "hora: NtQuerySystemTime le a KUSER_SHARED_DATA e RtlGetSystemTimePrecise fica entre as leituras precisas do kernel");
    assert(outcome.increment_at_exit == 156_250 && clock::time_increment() == 156_250 && crate::ntos::ex::timer_resolution::process_request_count() == 0, "hora: a saida do processo cancela o pedido de resolucao");
    crate::debug_print!("TIME_USER_OK");
}
