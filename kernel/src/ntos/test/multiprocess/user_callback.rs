//! Callbacks de modo usuário (`ke/user_callback.rs`): o KeUserModeCallback
//! de um serviço chama de verdade a rotina de usuário da
//! `PEB->KernelCallbackTable`, pela ntdll!KiUserCallbackDispatcher real, e
//! volta pelo NtCallbackReturn.
//!
//! Uma thread de usuário GUI de um processo de teste (TEB com a PEB, a
//! tabela de callbacks na PEB, a ntdll real do volume mapeada no processo e
//! o KiUserCallbackDispatcher dela publicado como despachante) faz syscalls
//! de teste (tabela 1 do Shadow) cujo serviço chama o export
//! KeUserModeCallback pelo nome:
//!
//! - a API 1 transforma a entrada (cada byte XOR 0x5A) num buffer de
//!   usuário, faz no meio uma syscall que sonda a pilha de kernel e devolve
//!   pelo NtCallbackReturn(saída, tamanho, 0x1234): o serviço recebe o
//!   status, o ponteiro e o tamanho, e confere o UCALLOUT_FRAME montado
//!   abaixo do RSP da syscall (Buffer, Length, ApiNumber, o RIP e o RSP da
//!   syscall, a cópia da entrada alinhada a 16); a sonda vê a pilha do
//!   callback (InitialStack, StackBase e StackLimit novos, KPRCB.RspBase na
//!   InitialStack, o RSP dentro dela, o KERNEL_STACK_CONTROL com a pilha
//!   anterior e o quadro do callout) e CallbackNestingLevel 1;
//! - a API 2 faz, de dentro do callback, a mesma syscall com a API 1 (um
//!   callback aninhado, nível 2, sobre a pilha do nível 1) e devolve 0x4321;
//! - a API 3 só retorna 0x777: o KiUserCallbackDispatcher chama
//!   NtCallbackReturn(NULL, 0, 0x777);
//! - uma entrada maior que o espaço do usuário falha na sonda com
//!   STATUS_ACCESS_VIOLATION sem rodar callback;
//! - o NtCallbackReturn fora de um callback dá STATUS_NO_CALLBACK_ACTIVE.
//!
//! Depois de cada callback a KTHREAD volta à pilha anterior, o aninhamento
//! cai e a pilha do callback volta ao Mm. Sem o KeUserModeCallback (ou sem
//! o NtCallbackReturn) nada disso roda: o export não existe e a syscall 5
//! não tem provedor.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use super::identity::with_test_process;
use crate::hal::amd64::usermode;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::extra_fs_fat::KernelStackControl;
use crate::ntos::inc::types::{Context, Ethread, Kthread, NtStruct};
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ke::user_callback;
use crate::ntos::mm::pe_loader::{self, LoadOptions};
use crate::ntos::mm::{kernel_stack, memory_map, peb_teb};
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{loader, memory, state};
use crate::ntos::ps::{cid, process};
use crate::ntos::test::phase6::call_export;
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const CALLBACK_SERVICE: u32 = 0x1000;
const PROBE_SERVICE: u32 = 0x1001;
const EXIT_SERVICE: u32 = 0x1002;
/// A entrada da API 1: 37 bytes (não múltiplo de 16).
const INPUT_LENGTH: u32 = 37;
/// Uma entrada que não cabe no espaço do usuário.
const HUGE_LENGTH: u32 = 0xFFFF_0000;
const UCALLOUT_FRAME: u64 = 0x58;
const SENTINEL: u64 = 0xA5A5_A5A5_A5A5_A5A5;

core::arch::global_asm!(
    r#"
.pushsection .rodata.opennt_user_callback_program, "a"
.balign 16
.global opennt_ucb_start
opennt_ucb_start:
    mov ecx, 1
    xor edx, edx
    mov eax, {callback}
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_main1], eax
    mov ecx, 2
    xor edx, edx
    mov eax, {callback}
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_main2], eax
    mov ecx, 3
    xor edx, edx
    mov eax, {callback}
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_main3], eax
    mov ecx, 1
    mov edx, 1
    mov eax, {callback}
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_main4], eax
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    mov eax, 5
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_main5], eax
    xor ecx, ecx
    mov eax, {exit}
    mov r10, rcx
    syscall
opennt_ucb_main_hang:
    jmp opennt_ucb_main_hang

.global opennt_ucb_routine1
opennt_ucb_routine1:
    mov qword ptr [rip + opennt_ucb_r1_buffer], rcx
    mov dword ptr [rip + opennt_ucb_r1_length], edx
    mov qword ptr [rip + opennt_ucb_r1_rsp], rsp
    mov eax, {probe}
    mov r10, rcx
    syscall
    mov rsi, qword ptr [rip + opennt_ucb_r1_buffer]
    lea rdi, [rip + opennt_ucb_output]
    mov ecx, dword ptr [rip + opennt_ucb_r1_length]
opennt_ucb_r1_loop:
    test ecx, ecx
    jz opennt_ucb_r1_done
    mov al, byte ptr [rsi]
    xor al, 0x5A
    mov byte ptr [rdi], al
    inc rsi
    inc rdi
    dec ecx
    jmp opennt_ucb_r1_loop
opennt_ucb_r1_done:
    lea rcx, [rip + opennt_ucb_output]
    mov edx, dword ptr [rip + opennt_ucb_r1_length]
    mov r8d, 0x1234
    mov eax, 5
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_r1_after], eax
opennt_ucb_r1_hang:
    jmp opennt_ucb_r1_hang

.global opennt_ucb_routine2
opennt_ucb_routine2:
    mov ecx, 1
    xor edx, edx
    mov eax, {callback}
    mov r10, rcx
    syscall
    mov dword ptr [rip + opennt_ucb_r2_nested], eax
    xor ecx, ecx
    xor edx, edx
    mov r8d, 0x4321
    mov eax, 5
    mov r10, rcx
    syscall
opennt_ucb_r2_hang:
    jmp opennt_ucb_r2_hang

.global opennt_ucb_routine3
opennt_ucb_routine3:
    mov eax, 0x777
    ret

.balign 16
.global opennt_ucb_data
opennt_ucb_data:
opennt_ucb_main1: .long 0xFFFFFFFF
opennt_ucb_main2: .long 0xFFFFFFFF
opennt_ucb_main3: .long 0xFFFFFFFF
opennt_ucb_main4: .long 0xFFFFFFFF
opennt_ucb_main5: .long 0xFFFFFFFF
opennt_ucb_r2_nested: .long 0xFFFFFFFF
opennt_ucb_r1_after: .long 0xFFFFFFFF
opennt_ucb_r1_length: .long 0
opennt_ucb_r1_buffer: .quad 0
opennt_ucb_r1_rsp: .quad 0
.global opennt_ucb_table
opennt_ucb_table: .quad 0, 0, 0, 0
.global opennt_ucb_output
opennt_ucb_output: .zero 64
.global opennt_ucb_end
opennt_ucb_end:
.popsection
"#,
    callback = const CALLBACK_SERVICE,
    probe = const PROBE_SERVICE,
    exit = const EXIT_SERVICE,
);

extern "C" {
    static opennt_ucb_start: u8;
    static opennt_ucb_routine1: u8;
    static opennt_ucb_routine2: u8;
    static opennt_ucb_routine3: u8;
    static opennt_ucb_data: u8;
    static opennt_ucb_table: u8;
    static opennt_ucb_output: u8;
    static opennt_ucb_end: u8;
}

/// Deslocamento de um rótulo do programa a partir do começo dele.
fn offset(label: &u8) -> u64 {
    // SAFETY: só o endereço do rótulo é usado.
    label as *const u8 as u64 - unsafe { &opennt_ucb_start as *const u8 as u64 }
}

/// Os bytes do programa (código e dados, independentes de posição).
fn program() -> &'static [u8] {
    // SAFETY: os rótulos delimitam o blob em `.rodata`.
    unsafe {
        let start = &opennt_ucb_start as *const u8;
        core::slice::from_raw_parts(start, (&opennt_ucb_end as *const u8 as usize) - start as usize)
    }
}

/// As células de resultado no começo dos dados: os cinco da principal, o
/// do callback aninhado e o depois do NtCallbackReturn, e o último tamanho,
/// buffer e RSP que a rotina 1 viu.
mod cell {
    pub const MAIN: [u64; 5] = [0, 4, 8, 12, 16];
    pub const NESTED: u64 = 20;
    pub const AFTER: u64 = 24;
    pub const LENGTH: u64 = 28;
    pub const BUFFER: u64 = 32;
    pub const RSP: u64 = 40;
}

/// O que um KeUserModeCallback devolveu, visto pelo serviço.
#[derive(Clone, Copy, Default)]
struct Record {
    api: u64,
    status: u32,
    output: u64,
    output_length: u32,
    output_matches: bool,
    frame_ok: bool,
    nesting: (u8, u8),
    restored: bool,
}

/// O que a syscall de sonda viu dentro de um callback.
#[derive(Clone, Copy, Default)]
struct Probe {
    nesting: u8,
    on_callback_stack: bool,
    previous_initial: u64,
    frame: u64,
}

static SERVICE_TABLE: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
static SERVICE_ARGUMENTS: [AtomicU8; 3] = [const { AtomicU8::new(0) }; 3];
static RECORDS: SpinLock<Vec<Record>> = SpinLock::new(Vec::new());
static PROBES: SpinLock<Vec<Probe>> = SpinLock::new(Vec::new());
/// A entrada (memória do kernel) e o programa copiado no processo.
static INPUT: AtomicU64 = AtomicU64::new(0);
static CODE: AtomicU64 = AtomicU64::new(0);

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

/// O byte `index` da entrada.
fn input_byte(index: u64) -> u8 {
    (index * 7 + 3) as u8
}

/// O UCALLOUT_FRAME e a cópia da entrada abaixo do RSP da syscall.
fn frame_matches(api: u64, length: u32, syscall: &Context) -> bool {
    let user_rsp = syscall.rsp.get();
    let frame = (user_rsp - (((length as u64 + 15) & !15) + UCALLOUT_FRAME)) & !15;
    let copy = guest::read_bytes(frame + UCALLOUT_FRAME, length as usize);
    guest::read64(frame + 0x20) == frame + UCALLOUT_FRAME
        && guest::read32(frame + 0x28) == length
        && guest::read32(frame + 0x2C) == api as u32
        && guest::read64(frame + 0x30) == syscall.rip.get()
        && guest::read64(frame + 0x48) == user_rsp
        && copy.iter().enumerate().all(|(index, &byte)| byte == input_byte(index as u64))
}

/// KeUserModeCallback(api) pelo export, com a entrada de 37 bytes ou (modo
/// 1) com um tamanho que não cabe na pilha do usuário.
extern "win64" fn callback_service(api: u64, mode: u64, _: u64, _: u64) -> u64 {
    let length = if mode == 1 { HUGE_LENGTH } else { INPUT_LENGTH };
    let out = guest::alloc_bytes(16);
    guest::write64(out, SENTINEL);
    guest::write64(out + 8, SENTINEL);
    let pointer = process::get_current_thread();
    let tcb = kthread(pointer);
    let before = (tcb.initial_stack.get(), tcb.stack_base.get(), tcb.stack_limit.get(), kernel_stack::live_count());
    let nesting = tcb.callback_nesting_level.get();
    // SAFETY: o CONTEXT do intervalo em curso (memória do kernel).
    let syscall = unsafe { Context::at(usermode::block().context.get()) };
    let status = call_export("KeUserModeCallback", &[api, INPUT.load(Ordering::SeqCst), length as u64, out, out + 8]).unwrap_or(0xDEAD_0000) as u32;
    let after = (tcb.initial_stack.get(), tcb.stack_base.get(), tcb.stack_limit.get(), kernel_stack::live_count());
    let output = guest::read64(out);
    let output_length = guest::read32(out + 8);
    let expected_output = CODE.load(Ordering::SeqCst) + offset(unsafe { &opennt_ucb_output });
    let output_matches = output == expected_output && (0..INPUT_LENGTH as u64).all(|index| guest::read8(output + index) == input_byte(index) ^ 0x5A);
    let frame_ok = mode == 1 || frame_matches(api, length, syscall);
    RECORDS.lock().push(Record { api, status, output, output_length, output_matches, frame_ok, nesting: (nesting, tcb.callback_nesting_level.get()), restored: before == after });
    guest::free_bytes(out);
    status as u64
}

/// A pilha de kernel e o aninhamento vistos de uma syscall do callback.
extern "win64" fn probe_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let tcb = kthread(process::get_current_thread());
    let (initial, base, limit, rsp) = (tcb.initial_stack.get(), tcb.stack_base.get(), tcb.stack_limit.get(), current_rsp());
    // SAFETY: o KERNEL_STACK_CONTROL da pilha corrente da thread.
    let control = unsafe { KernelStackControl::at(initial) };
    let on_callback_stack = memory_map::is_kernel_stack(initial)
        && rsp > limit
        && rsp < initial
        && pcr::current().prcb.rsp_base.get() == initial
        && control.current_stack_base.get() == base
        && kernel_stack::find(base).is_some_and(|stack| stack.initial == initial && stack.limit == limit);
    PROBES.lock().push(Probe { nesting: tcb.callback_nesting_level.get(), on_callback_stack, previous_initial: control.previous.initial_stack.get(), frame: control.previous.kernel_stack.get() });
    0
}

/// NtTerminateThread da thread corrente.
extern "win64" fn exit_service(code: u64, _: u64, _: u64, _: u64) -> u64 {
    state::handler("NtTerminateThread").map_or(0xC000_0001, |handler| handler(0, code, 0, 0, 0).unwrap_or(0xC000_0001)) as u64
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

/// O que o cenário observou.
struct Outcome {
    ran: bool,
    main: [u32; 5],
    nested: u32,
    after: u32,
    length: u32,
    buffer: u64,
    routine_rsp: u64,
    original_initial: u64,
    restored: bool,
    stacks_released: bool,
}

fn scenario() -> Option<Outcome> {
    with_test_process("callback.exe", None, |test| {
        let (code, stacks) = (allocate(0x1000, 0x40), allocate(0x8000, 4));
        let input = guest::alloc_bytes(INPUT_LENGTH as u64);
        let stack = kernel_stack::create(false).ok();
        let stack_base = stack.map_or(0, |stack| stack.base);
        let pointer = stack.and_then(|stack| process::create_kernel_thread(test.process, cid::ALLOCATE, true, 1, Some(stack)).ok());
        let mut outcome = Outcome { ran: false, main: [0; 5], nested: 0, after: 0, length: 0, buffer: 0, routine_rsp: 0, original_initial: 0, restored: false, stacks_released: false };
        if let (Some(pointer), true) = (pointer, code != 0 && stacks != 0 && input != 0) {
            // SAFETY: ETHREAD recém-criada, retida pela thread de usuário.
            let ethread = unsafe { Ethread::at(pointer) };
            ethread.tcb.set_gui_thread(1);
            let teb = peb_teb::create_teb(&peb_teb::TebDescription { process_id: test.process_id, thread_id: ethread.cid.unique_thread.get(), peb: test.peb, stack_base: stacks + 0x8000, stack_limit: stacks }).unwrap_or(0);
            let thread: Arc<UserThread> = UserThread::new(ethread.cid.unique_thread.get(), pointer, teb, code);
            thread.with(|thread| thread.process_pointer = test.process);
            process::add_thread(test.process);
            threads::push(thread.clone());
            for index in 0..INPUT_LENGTH as u64 {
                guest::write8(input + index, input_byte(index));
            }
            INPUT.store(input, Ordering::SeqCst);
            CODE.store(code, Ordering::SeqCst);
            guest::write_bytes(code, program());
            // SAFETY: os rótulos do programa.
            let (table, routines) = unsafe { (code + offset(&opennt_ucb_table), [offset(&opennt_ucb_routine1), offset(&opennt_ucb_routine2), offset(&opennt_ucb_routine3)]) };
            for (index, routine) in routines.iter().enumerate() {
                guest::write64(table + (index as u64 + 1) * 8, code + routine);
            }
            // PEB->KernelCallbackTable.
            guest::write64(test.peb + 0x58, table);
            outcome.original_initial = kthread(pointer).initial_stack.get();
            RECORDS.lock().clear();
            PROBES.lock().clear();
            // A ntdll real do volume, mapeada no processo, publica o
            // despachante de callbacks durante o cenário.
            let ntdll = loader::ntfs_volume().and_then(|volume| volume.read_bytes("/Windows/System32/ntdll.dll").ok().flatten()).and_then(|bytes| pe_loader::load_user(bytes, &LoadOptions { notify_image: false, ..LoadOptions::default() }).ok());
            let dispatcher = ntdll.as_ref().and_then(|image| image.exports.exports.get("KiUserCallbackDispatcher").copied()).unwrap_or(0);
            if teb != 0 && dispatcher != 0 {
                let previous = user_callback::set_dispatcher(dispatcher);
                outcome.ran = threads::run(&thread, code, stacks + 0x8000 - 0x28, 0, 0).is_ok();
                user_callback::set_dispatcher(previous);
            }
            if let Some(mut image) = ntdll {
                let _ = image.release();
            }
            // SAFETY: os dados do programa.
            let data = code + unsafe { offset(&opennt_ucb_data) };
            outcome.main = cell::MAIN.map(|offset| guest::read32(data + offset));
            outcome.nested = guest::read32(data + cell::NESTED);
            outcome.after = guest::read32(data + cell::AFTER);
            outcome.length = guest::read32(data + cell::LENGTH);
            outcome.buffer = guest::read64(data + cell::BUFFER);
            outcome.routine_rsp = guest::read64(data + cell::RSP);
            // A thread já saiu: o ceifador zerou os campos de pilha da KTHREAD.
            outcome.restored = kthread(pointer).callback_nesting_level.get() == 0;
            threads::release_process(test.process);
            kernel_stack::reap();
            outcome.stacks_released = kernel_stack::find(stack_base).is_none();
        }
        threads::release_process(test.process);
        if input != 0 {
            guest::free_bytes(input);
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
        assert(false, "callback: anel 3 armado e volume com a ntdll real");
        return;
    }
    if threads::all().iter().any(|thread| !thread.dead()) {
        assert(false, "callback: nenhuma thread de usuario de outro teste viva");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "callback: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let routines: [extern "win64" fn(u64, u64, u64, u64) -> u64; 3] = [callback_service, probe_service, exit_service];
    let mut encoded = true;
    for (slot, routine) in SERVICE_TABLE.iter().zip(routines) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => encoded = false,
        }
    }
    if !encoded || service_table::publish_shadow_second_table(table, 3, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        assert(false, "callback: tabela 1 de teste");
        let _ = service_table::restore_shadow_second_table(saved_shadow);
        return;
    }

    let outcome = scenario();
    let records = core::mem::take(&mut *RECORDS.lock());
    let probes = core::mem::take(&mut *PROBES.lock());
    let ok = outcome.as_ref().is_some_and(|outcome| outcome.ran);
    assert(ok, "callback: thread de usuario com TEB, PEB e KernelCallbackTable no despachante");
    if let Some(outcome) = outcome.filter(|_| ok) {
        assert(outcome.main == [0x1234, 0x4321, 0x777, 0xC000_0005, 0xC000_0258], "callback: as syscalls da principal devolvem o status de cada NtCallbackReturn, ACCESS_VIOLATION na entrada grande e NO_CALLBACK_ACTIVE fora de um callback");
        assert(records.len() == 5, "callback: cinco KeUserModeCallback (API 1, a 1 aninhada, a 2, a 3 e a entrada grande)");
        if let [first, inner, second, third, huge] = records[..] {
            assert(first.api == 1 && first.status == 0x1234 && first.output_length == INPUT_LENGTH && first.output_matches, "callback: a API 1 devolve pelo NtCallbackReturn o status, o buffer de saida transformado e o tamanho");
            assert(first.frame_ok && inner.frame_ok && second.frame_ok && third.frame_ok, "callback: UCALLOUT_FRAME abaixo do RSP da syscall (Buffer, Length, ApiNumber, RIP e RSP) com a entrada alinhada a 16");
            assert(inner.api == 1 && inner.status == 0x1234 && inner.output_matches && inner.nesting == (1, 1) && second.api == 2 && second.status == 0x4321 && second.output == 0 && second.output_length == 0 && outcome.nested == 0x1234, "callback: um callback aninhado dentro do callback da API 2");
            assert(third.api == 3 && third.status == 0x777 && third.output == 0 && third.output_length == 0, "callback: a rotina que retorna volta pelo NtCallbackReturn(NULL, 0, retorno) do KiUserCallbackDispatcher");
            assert(huge.status == 0xC000_0005 && huge.output == SENTINEL, "callback: entrada maior que a pilha do usuario falha na sonda com ACCESS_VIOLATION, sem saida");
            assert([first, inner, second, third, huge].iter().all(|record| record.restored && record.nesting.0 == record.nesting.1), "callback: depois de cada callback a KTHREAD volta a pilha anterior, o aninhamento cai e a pilha do callback volta ao Mm");
        }
        assert(probes.len() == 2, "callback: duas sondas (API 1 e a 1 aninhada)");
        if let [outer, nested] = probes[..] {
            assert(outer.nesting == 1 && outer.on_callback_stack && outer.previous_initial == outcome.original_initial && (outer.frame as i64) < 0, "callback: a syscall do callback roda na pilha nova (InitialStack, StackBase, StackLimit e RspBase), com a pilha anterior e o quadro do callout no KERNEL_STACK_CONTROL");
            assert(nested.nesting == 2 && nested.on_callback_stack && nested.previous_initial != outcome.original_initial && memory_map::is_kernel_stack(nested.previous_initial), "callback: o aninhado roda numa terceira pilha, sobre a do nivel 1");
        }
        assert(outcome.length == INPUT_LENGTH && outcome.routine_rsp == outcome.buffer - UCALLOUT_FRAME - 8 && outcome.after == 0xFFFF_FFFF, "callback: a rotina recebe Buffer e Length do frame, roda com o RSP do KiUserCallbackDispatcher e o NtCallbackReturn nao volta");
        assert(outcome.restored && outcome.stacks_released, "callback: a thread termina sem aninhamento e as pilhas voltam ao Mm");
    }
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}
