//! Pilhas de kernel por thread (`mm/kernel_stack.rs`, `ps/process.rs`,
//! `hal/amd64/usermode.rs`):
//!
//! - uma KTHREAD com pilha própria publica StackBase, StackLimit,
//!   InitialStack (o KERNEL_STACK_CONTROL) e KernelStack, com a pilha na
//!   janela de sistema, em PTEs de supervisor NX, e a guarda sem PTE;
//! - uma syscall de teste (tabela 1 do Shadow, thread GUI, o caminho inteiro
//!   do KiSystemCall64) devolve o próprio RSP: ele fica entre o StackLimit e o
//!   InitialStack da thread que a fez, difere entre duas threads, e durante a
//!   syscall KPRCB.RspBase e TSS.RSP0 são a InitialStack dela;
//! - um tick do timer que chega no anel 3 entra pela TSS.RSP0, com o quadro
//!   de interrupção no topo da pilha de kernel da thread, e encerra o
//!   intervalo (tipo 2); a thread segue do CONTEXT salvo, como no despacho.
//!   O teste espera, com as interrupções desligadas, o tick ficar pendente
//!   no IRR do LAPIC antes da entrada, para que ele chegue sempre antes da
//!   primeira instrução de usuário;
//! - IoGetStackLimits chamado por uma thread de sistema nativa devolve a
//!   faixa real da pilha dela, que contém o RSP do código nativo, e o
//!   ceifador devolve a pilha;
//! - criar e destruir 8 threads deixa o PFN como estava (as pilhas vêm dele);
//! - a falta dupla usa a IST1, numa pilha de kernel própria;
//! - os contextos de KeAllocateCalloutStackEx têm pilhas reais.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

use crate::hal::amd64::usermode;
use crate::hal::{cpu, lapic};
use crate::nano::interrupts;
use crate::ntos::ex::service_table;
use crate::ntos::inc::types::extra_fs_fat::KernelStackControl;
use crate::ntos::inc::types::{Context, Ethread, Kthread, NtStruct};
use crate::ntos::init::exports;
use crate::ntos::ke::{callout, clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack::{self, KERNEL_LARGE_STACK_SIZE, KERNEL_STACK_GUARD, KERNEL_STACK_SIZE};
use crate::ntos::mm::pe_loader::ResolvedImport;
use crate::ntos::mm::{memory_map as map, paging, pfn};
use crate::ntos::ob::object_manager;
use crate::ntos::ps::user::{memory, threads};
use crate::ntos::ps::{kernel_threads, process, scheduler};

type Assert = fn(bool, &str);

const FIRST_THREAD_ID: u64 = 0x7E70;
const SECOND_THREAD_ID: u64 = 0x7E74;
/// As 8 threads do teste do PFN: 0x7F80, 0x7F84, ...
const CYCLE_THREAD_ID: u64 = 0x7F80;
/// Primeiro serviço da tabela 1 (o índice 0 da tabela gráfica).
const TEST_SERVICE: u32 = 0x1000;

/// A tabela compactada do serviço de teste, na imagem do kernel (a entrada
/// é relativa à tabela e só alcança ±128 MB).
static SERVICE_TABLE: [AtomicU32; 1] = [AtomicU32::new(0)];
static SERVICE_ARGUMENTS: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];
/// KPRCB.RspBase e TSS.RSP0 vistos pelo serviço de teste.
static SEEN_RSP_BASE: AtomicU64 = AtomicU64::new(0);
static SEEN_RSP0: AtomicU64 = AtomicU64::new(0);

/// O serviço de teste: devolve o próprio RSP (na pilha de kernel em que a
/// syscall roda) e anota a KPRCB.RspBase e a TSS.RSP0 da CPU.
extern "win64" fn rsp_service(_: u64, _: u64, _: u64, _: u64) -> u64 {
    let rsp: u64;
    // SAFETY: só lê o registrador.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    SEEN_RSP_BASE.store(pcr::current().prcb.rsp_base.get(), Ordering::SeqCst);
    SEEN_RSP0.store(usermode::tss_stacks().0, Ordering::SeqCst);
    rsp
}

fn kthread(pointer: u64) -> &'static Kthread {
    // SAFETY: KTHREAD vivo, criado e retido pelo teste.
    unsafe { Kthread::at(pointer) }
}

/// (StackBase, InitialStack, StackLimit, KernelStack) da KTHREAD.
fn stack_fields(pointer: u64) -> (u64, u64, u64, u64) {
    let thread = kthread(pointer);
    (thread.stack_base.get(), thread.initial_stack.get(), thread.stack_limit.get(), thread.kernel_stack.get())
}

/// O tick do LAPIC (vetor 0x40) pendente no IRR desta CPU (registradores de
/// 32 bits a cada 16 bytes a partir de 0x200, um bit por vetor).
fn timer_tick_pending() -> bool {
    let vector = interrupts::VECTOR_LAPIC_TIMER as u32;
    lapic::read(0x200 + (vector / 32) * 0x10) & (1 << (vector % 32)) != 0
}

/// Uma KTHREAD do processo corrente com pilha de kernel própria.
fn thread_with_stack(id: u64) -> Option<u64> {
    let stack = kernel_stack::create(false).ok()?;
    process::create_kernel_thread(process::get_current_process(), id, true, 1, Some(stack)).ok()
}

pub fn run(assert: Assert) {
    thread_fields(assert);
    syscall_rsp(assert);
    native_thread_limits(assert);
    pfn_stable(assert);
    double_fault_stack(assert);
    callout_stacks(assert);
}

/// Os campos de pilha da KTHREAD e a geometria da pilha.
fn thread_fields(assert: Assert) {
    let Some(thread) = thread_with_stack(FIRST_THREAD_ID) else {
        assert(false, "pilhas: thread com pilha de kernel propria");
        return;
    };
    let (base, initial, limit, saved) = stack_fields(thread);
    assert(map::is_kernel_stack(limit) && map::is_kernel_stack(base - 1) && base - limit == KERNEL_STACK_SIZE && initial == base - KernelStackControl::SIZE && saved == initial, "pilhas: StackBase, StackLimit, InitialStack e KernelStack publicados na janela de sistema");
    // SAFETY: o InitialStack de uma pilha viva aponta o controle.
    let control = unsafe { KernelStackControl::at(initial) };
    assert(control.current_stack_base.get() == base && control.actual_limit.get() == limit && control.previous.stack_base.get() == 0, "pilhas: KERNEL_STACK_CONTROL no InitialStack");
    let pages_ok = (limit..base).step_by(0x1000).all(|page| paging::query_page(page, false).is_some_and(|mapping| mapping.nx && mapping.access & paging::PAGE_RW != 0 && mapping.access & paging::PAGE_USER == 0));
    assert(pages_ok && paging::translate(limit - KERNEL_STACK_GUARD) == 0 && kernel_stack::find(base).is_some(), "pilhas: paginas de supervisor NX e a guarda sem PTE");
    let _ = process::release_thread(thread);
    assert(kernel_stack::find(base).is_none() && paging::translate(limit) == 0, "pilhas: a pilha volta ao Mm com a KTHREAD");
}

/// A syscall roda na pilha de kernel da thread que a fez.
fn syscall_rsp(assert: Assert) {
    if !usermode::ready() {
        assert(false, "pilhas: anel 3 armado");
        return;
    }
    let Ok(saved_shadow) = service_table::shadow_second_table() else {
        assert(false, "pilhas: descritores de servico publicados");
        return;
    };
    let table = SERVICE_TABLE.as_ptr() as u64;
    let Ok(entry) = service_table::encode_entry(table, rsp_service as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64, 0) else {
        assert(false, "pilhas: entrada do servico de teste");
        return;
    };
    SERVICE_TABLE[0].store(entry, Ordering::Release);
    let scratch = guest::alloc_bytes(16);
    let allocate = |size: u64, protect: u32| {
        guest::write64(scratch, 0);
        guest::write64(scratch + 8, size);
        let status = memory::do_user_allocate(scratch, scratch + 8, 0x3000, protect, 0x10000, 0x7FFF_FFFF_0000, 0x10000).unwrap_or(1);
        if status == 0 { guest::read64(scratch) } else { 0 }
    };
    let (code, stack) = (allocate(0x1000, 0x40), allocate(0x4000, 4));
    let context = guest::alloc_bytes(threads::CONTEXT_SIZE);
    let previous = process::get_current_thread();
    let created = [thread_with_stack(FIRST_THREAD_ID), thread_with_stack(SECOND_THREAD_ID)];
    let mut seen = [0u64; 2];
    if let ([Some(_), Some(_)], true, true) = (created, code != 0 && stack != 0 && context != 0, service_table::publish_shadow_second_table(table, 1, SERVICE_ARGUMENTS.as_ptr() as u64).is_ok()) {
        // syscall TEST_SERVICE; jmp $ (o intervalo termina na syscall).
        let mut program = alloc::vec![0xB8];
        program.extend_from_slice(&TEST_SERVICE.to_le_bytes());
        program.extend_from_slice(&[0x49, 0x89, 0xCA, 0x0F, 0x05, 0xEB, 0xFE]);
        guest::write_bytes(code, &program);
        let user_rsp = stack + 0x4000 - 0x28;
        for (index, thread) in created.iter().flatten().enumerate() {
            let (_, initial, limit, _) = stack_fields(*thread);
            // A thread GUI busca no Shadow, cuja tabela 1 é a de teste.
            // SAFETY: a ETHREAD acabou de ser criada e é retida até o fim.
            let tcb = &unsafe { Ethread::at(*thread) }.tcb;
            tcb.set_gui_thread(1);
            threads::initialize_context(context, code, user_rsp, 0, 0);
            SEEN_RSP_BASE.store(0, Ordering::SeqCst);
            SEEN_RSP0.store(0, Ordering::SeqCst);
            process::set_current_thread(*thread);
            if index == 0 {
                // Com as interrupções desligadas, espera o tick do LAPIC
                // ficar pendente no IRR: o IRETQ religa o IF e ele chega
                // antes da primeira instrução de usuário. (Um prazo fixo não
                // basta: num host carregado o tick do QEMU pode atrasar.)
                let flags = cpu::save_and_disable_interrupts();
                let deadline = clock::uptime_ms() + 2_000;
                while !timer_tick_pending() && clock::uptime_ms() < deadline {
                    cpu::pause();
                }
                let pending = timer_tick_pending();
                let _ = usermode::exec_user_context(context, 0);
                cpu::restore_interrupts(flags);
                let kind = usermode::block().exit_kind.get();
                // SAFETY: o CONTEXT do intervalo, memória do kernel.
                let rip = unsafe { Context::at(context) }.rip.get();
                // O quadro da IRQ no topo da pilha da thread (InitialStack,
                // alinhada a 16): RIP, CS, RFLAGS, RSP e SS do anel 3.
                let frame = [guest::read64(initial - 40), guest::read64(initial - 32), guest::read64(initial - 16), guest::read64(initial - 8)];
                let preempted = pending && kind == 2 && rip == code && frame == [code, 0x33, user_rsp, 0x2B];
                if !preempted {
                    crate::debug_print!("[pilhas] tick pendente={} tipo={} rip={:#x} quadro={:x?}", pending, kind, rip, frame);
                }
                assert(preempted, "pilhas: o tick do timer no anel 3 entra pela TSS.RSP0, na pilha de kernel da thread, e encerra o intervalo");
            }
            // Um tick no anel 3 encerra o intervalo (tipo 2) e a thread segue
            // do CONTEXT salvo até a syscall.
            let mut kind = 2;
            let mut rounds = 0;
            while kind == 2 && rounds < 64 {
                let _ = usermode::exec_user_context(context, 0);
                kind = usermode::block().exit_kind.get();
                rounds += 1;
            }
            process::set_current_thread(previous);
            tcb.set_gui_thread(0);
            // SAFETY: o CONTEXT do intervalo, memória do kernel.
            let rsp = unsafe { Context::at(context) }.rax.get();
            seen[index] = rsp;
            assert(kind == 1 && rsp > limit && rsp < initial, "pilhas: o RSP da syscall fica entre o StackLimit e o InitialStack da thread");
            assert(SEEN_RSP_BASE.load(Ordering::SeqCst) == initial && SEEN_RSP0.load(Ordering::SeqCst) == initial, "pilhas: durante a syscall KPRCB.RspBase e TSS.RSP0 sao a InitialStack da thread");
        }
        let (rsp_base, rsp0) = (pcr::current().prcb.rsp_base.get(), usermode::tss_stacks().0);
        assert(seen[0] != seen[1] && created[1].is_some_and(|second| { let (base, _, limit, _) = stack_fields(second); !(limit..base).contains(&seen[0]) }), "pilhas: duas threads fazem a syscall em pilhas distintas");
        assert(rsp_base == rsp0 && created.iter().flatten().all(|&thread| { let (base, _, limit, _) = stack_fields(thread); !(limit..=base).contains(&rsp_base) }), "pilhas: fora do intervalo RspBase e RSP0 voltam a pilha reserva da CPU");
    } else {
        assert(false, "pilhas: threads, memoria de usuario e tabela 1 de teste");
    }
    let _ = service_table::restore_shadow_second_table(saved_shadow);
    SERVICE_TABLE[0].store(0, Ordering::Release);
    for thread in created.into_iter().flatten() {
        let _ = process::release_thread(thread);
    }
    guest::free_bytes(scratch);
    if context != 0 {
        guest::free_bytes(context);
    }
    for base in [code, stack] {
        if let Some(region) = memory::find_region(base).filter(|_| base != 0) {
            memory::release_private_region(&region);
        }
    }
}

/// O trampolim de um export, como um driver o recebe na IAT.
fn export_thunk(name: &str) -> u64 {
    let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", name) else { return 0 };
    exports::thunk_address(id as u64).unwrap_or(0)
}

/// Roda o escalonador até `done` (com limite).
fn pump(done: &dyn Fn() -> bool) -> bool {
    for _ in 0..256 {
        if done() {
            return true;
        }
        scheduler::tick(-1);
    }
    done()
}

/// IoGetStackLimits de uma thread de sistema nativa.
fn native_thread_limits(assert: Assert) {
    let thunk = export_thunk("IoGetStackLimits");
    // [0] LowLimit, [8] HighLimit, [0x10] RSP do código nativo, [0x18] marcador.
    let block = guest::alloc_bytes(0x20);
    // O corpo nativo numa alocação executável (o heap não executa).
    let code = crate::ntos::test::executable_code::reserve(0x40);
    if thunk == 0 || block == 0 || code == 0 {
        assert(false, "pilhas: trampolim de IoGetStackLimits e memoria do teste");
        return;
    }
    guest::write_bytes(block, &[0; 0x20]);
    // push rbx; sub rsp, 20h; mov rbx, rcx; mov [rbx+10h], rsp;
    // lea rdx, [rbx+8]; mov rcx, rbx; mov rax, IoGetStackLimits; call rax;
    // mov dword [rbx+18h], 77h; add rsp, 20h; pop rbx; xor eax, eax; ret.
    let mut routine = alloc::vec![0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x89, 0xCB, 0x48, 0x89, 0x63, 0x10, 0x48, 0x8D, 0x53, 0x08, 0x48, 0x89, 0xD9, 0x48, 0xB8];
    routine.extend_from_slice(&thunk.to_le_bytes());
    routine.extend_from_slice(&[0xFF, 0xD0, 0xC7, 0x43, 0x18, 0x77, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x20, 0x5B, 0x31, 0xC0, 0xC3]);
    guest::write_bytes(code, &routine);
    let created = kernel_threads::create_system_thread(0, code, block, 0x1F_FFFF, 0, None);
    let handle = *created.as_ref().unwrap_or(&0);
    let pointer = kernel_threads::of_handle(handle).unwrap_or(0);
    if pointer == 0 {
        assert(false, "pilhas: thread de sistema nativa criada");
        guest::free_bytes(block);
        crate::ntos::test::executable_code::release(code);
        return;
    }
    let (base, initial, limit, _) = stack_fields(pointer);
    let _ = object_manager::close(handle as u32);
    let finished = pump(&|| guest::read32(block + 0x18) == 0x77 && kernel_stack::find(base).is_none());
    let (low, high, rsp) = (guest::read64(block), guest::read64(block + 8), guest::read64(block + 0x10));
    assert(map::is_kernel_stack(limit) && base - limit == KERNEL_STACK_SIZE && initial == base - KernelStackControl::SIZE, "pilhas: a thread nativa tem pilha de kernel propria na janela de sistema");
    assert(guest::read32(block + 0x18) == 0x77 && low == limit && high == base && rsp > low && rsp < initial, "pilhas: IoGetStackLimits de uma thread nativa devolve a faixa real, que contem o RSP do codigo nativo");
    assert(finished, "pilhas: o ceifador da thread nativa devolve a pilha");
    guest::free_bytes(block);
    crate::ntos::test::executable_code::release(code);
}

/// Criar e destruir 8 threads com pilha própria deixa o PFN como estava.
fn pfn_stable(assert: Assert) {
    // Uma volta antes da medida assenta as tabelas da janela.
    if let Some(thread) = thread_with_stack(CYCLE_THREAD_ID) {
        let _ = process::release_thread(thread);
    }
    let before = pfn::free_count();
    let threads: alloc::vec::Vec<u64> = (0..8).filter_map(|index| thread_with_stack(CYCLE_THREAD_ID + index * 4)).collect();
    let during = pfn::free_count();
    let bases: alloc::vec::Vec<u64> = threads.iter().map(|&thread| stack_fields(thread).0).collect();
    let distinct = bases.iter().enumerate().all(|(index, base)| !bases[..index].contains(base));
    for &thread in &threads {
        let _ = process::release_thread(thread);
    }
    let after = pfn::free_count();
    assert(threads.len() == 8 && distinct && before - during >= 8 * KERNEL_STACK_SIZE / 0x1000, "pilhas: 8 threads com pilhas distintas, tiradas do PFN");
    assert(after == before && bases.iter().all(|&base| kernel_stack::find(base).is_none()), "pilhas: o PFN fica estavel depois de criar e destruir 8 threads");
}

/// A falta dupla entra pela IST1, numa pilha de kernel própria.
fn double_fault_stack(assert: Assert) {
    let (rsp0, ist1) = usermode::tss_stacks();
    let ist_ok = map::is_kernel_stack(ist1) && paging::translate(ist1 - 8) != 0 && paging::translate(ist1 - KERNEL_STACK_SIZE - 8) == 0;
    assert(interrupts::interrupt_stack(8) == 1 && ist_ok && ist1 != rsp0, "pilhas: o portao da falta dupla usa a IST1, numa pilha de kernel com guarda");
}

/// KeAllocateCalloutStackEx cria uma pilha real por nível.
fn callout_stacks(assert: Assert) {
    let Ok(Ok(context)) = callout::allocate_callout_stack_context(1, 2, 0) else {
        assert(false, "pilhas: contexto de pilhas de callout");
        return;
    };
    let bases: alloc::vec::Vec<u64> = context.stacks().iter().map(|slot| slot.get()).collect();
    let real = bases.len() == 2 && bases.iter().all(|&base| kernel_stack::find(base).is_some_and(|stack| stack.size() == KERNEL_LARGE_STACK_SIZE));
    let _ = callout::free_callout_stack(context);
    assert(real && bases.iter().all(|&base| kernel_stack::find(base).is_none()), "pilhas: KeAllocateCalloutStackEx cria pilhas grandes reais e KeFreeCalloutStack as devolve");
}
