//! As chamadas nativas em curso são da thread e da CPU
//! (`hal::amd64::native_call`): o contexto nativo agendado em execução e a
//! posse de execução nativa síncrona ficam em células da CPU que a troca de
//! thread leva, e o RSP do hospedeiro para onde a saída de um contexto
//! agendado volta fica no próprio quadro dele.
//!
//! - duas CPUs ao mesmo tempo: o BSP está dentro de um contexto nativo
//!   agendado (`native_context::call`) cujo código espera um sinal, e um AP
//!   chama um export pelo trampolim, pelo caminho síncrono, nesse meio-tempo:
//!   o AP não vê o contexto do BSP (com uma célula única do sistema, o
//!   trampolim do AP desviaria para a saída do contexto do BSP e voltaria
//!   pela pilha do hospedeiro dele), é servido com o valor do export, e o
//!   contexto do BSP segue até a própria saída;
//! - duas threads de sistema numa CPU, cada uma dentro do próprio contexto
//!   nativo agendado, se intercalam por dois eventos esperados de dentro dos
//!   contextos: cada KeWaitForSingleObject sai do contexto, a thread deixa a
//!   CPU e a outra entra no dela; cada saída volta ao hospedeiro da própria
//!   thread, e as duas terminam as rodadas com as próprias contagens.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::hal::cpu;
use crate::ntos::init::exports;
use crate::ntos::inc::types::{self as nt, NtStruct};
use crate::ntos::ke::{clock, dispatcher, smp};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::ResolvedImport;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, scheduler};
use crate::ntos::rtl::native_context;
use crate::ntos::test::executable_code;

type Assert = fn(bool, &str);

/// O trampolim de um export, como um driver o recebe na IAT.
fn export_thunk(name: &str) -> u64 {
    let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", name) else { return 0 };
    exports::thunk_address(id as u64).unwrap_or(0)
}

/// O TID sintético que o PsGetThreadId do AP devolve.
const THREAD_ID: u64 = 0x8765_4321_0FED_CBA9;

/// Código do contexto agendado do BSP (rcx = bloco): [0] = 1 (dentro do
/// contexto), espera [0x10] != 0 até o TSC passar de [0x18] e devolve [8]
/// (0 no prazo vencido).
const WINDOW_WAITS_FOR_AP: [u8; 39] = [
    0x48, 0xC7, 0x01, 0x01, 0x00, 0x00, 0x00, // mov qword ptr [rcx], 1
    0xF3, 0x90, // spin: pause
    0x48, 0x83, 0x79, 0x10, 0x00, // cmp qword ptr [rcx+10h], 0
    0x75, 0x12, // jne done
    0x0F, 0x31, // rdtsc
    0x48, 0xC1, 0xE2, 0x20, // shl rdx, 20h
    0x48, 0x09, 0xD0, // or rax, rdx
    0x48, 0x3B, 0x41, 0x18, // cmp rax, [rcx+18h]
    0x72, 0xE8, // jb spin
    0x31, 0xC0, // xor eax, eax
    0xC3, // ret
    0x48, 0x8B, 0x41, 0x08, // done: mov rax, [rcx+8]
    0xC3, // ret
];

/// Bloco do par BSP/AP: [0] o BSP está no contexto, [8] o valor que o AP
/// obteve, [0x10] o AP terminou, [0x18] prazo (TSC), [0x20] a célula do
/// contexto agendado que o AP viu, [0x28] o PsGetThreadId, [0x30] a ETHREAD.
static AP_DONE: AtomicU64 = AtomicU64::new(0);

/// Job do AP: espera o BSP entrar no contexto agendado e chama o export pelo
/// trampolim (caminho síncrono) nesse meio-tempo.
extern "win64" fn ap_export_during_window(block: u64, _: u64, _: u64, _: u64) -> u64 {
    let deadline = guest::read64(block + 0x18);
    while guest::read64(block) == 0 && cpu::rdtsc() < deadline {
        core::hint::spin_loop();
    }
    let inside = guest::read64(block) == 1;
    guest::write64(block + 0x20, native_call::scheduled_frame());
    let value = native_call::call(guest::read64(block + 0x28), &[guest::read64(block + 0x30)]);
    guest::write64(block + 8, value);
    guest::write64(block + 0x10, 1);
    AP_DONE.store(1, Ordering::SeqCst);
    inside as u64
}

fn ap_call_while_bsp_in_window(assert: Assert) {
    let Some(slot) = smp::ap_slot(0) else { return };
    let code = executable_code::place(&WINDOW_WAITS_FOR_AP);
    let block = guest::alloc_bytes(0x40);
    let thread = guest::alloc_bytes(nt::Ethread::SIZE);
    let thunk = export_thunk("PsGetThreadId");
    if code == 0 || block == 0 || thread == 0 || thunk == 0 {
        assert(false, "nativo intercalado: codigo, bloco e trampolim do teste entre CPUs");
        return;
    }
    guest::write_bytes(block, &[0; 0x40]);
    // SAFETY: ETHREAD sintética do teste.
    unsafe { nt::Ethread::at(thread) }.cid.unique_thread.set(THREAD_ID);
    let frequency = clock::tsc_frequency_hz();
    guest::write64(block + 0x18, cpu::rdtsc() + frequency * 10);
    guest::write64(block + 0x28, thunk);
    guest::write64(block + 0x30, thread);
    AP_DONE.store(0, Ordering::SeqCst);
    let routine = ap_export_during_window as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let started = smp::start_job(slot, routine, [block, 0, 0, 0]).is_ok_and(|started| started);
    let window = if started { native_context::call(code, &[block], 0).ok() } else { None };
    let after = native_call::state();
    let inside = started && smp::wait_job(slot, 15_000).is_ok_and(|result| result == 1);
    debug_print!(
        "[nativo] AP durante o contexto do BSP: dentro={} AP viu contexto={:#x} AP obteve={:#x} BSP devolveu={:x?} estado do BSP depois={:?}",
        inside,
        guest::read64(block + 0x20),
        guest::read64(block + 8),
        window,
        after
    );
    assert(
        inside && guest::read64(block + 0x20) == 0 && guest::read64(block + 8) == THREAD_ID,
        "nativo intercalado: um AP que chama um export enquanto o BSP esta num contexto nativo agendado ve as proprias celulas e e servido pelo caminho sincrono",
    );
    assert(window == Some(THREAD_ID) && after == native_call::NativeState::default(), "nativo intercalado: o contexto agendado do BSP segue ate a propria saida, sem celula restante");
    executable_code::release(code);
    guest::free_bytes(thread);
    guest::free_bytes(block);
}

/// Código de cada thread (rcx = bloco): [0] KeWaitForSingleObject, [8]
/// KeSetEvent, [0x10] o evento dela, [0x18] o da outra, [0x20] rodadas,
/// [0x28] contagem, [0x30] o primeiro status diferente de zero. Cada rodada
/// espera o próprio evento e sinaliza o da outra; devolve a contagem.
const PING_PONG_IN_WINDOW: [u8; 78] = [
    0x53, // push rbx
    0x56, // push rsi
    0x48, 0x83, 0xEC, 0x38, // sub rsp, 38h
    0x48, 0x89, 0xCB, // mov rbx, rcx
    0x48, 0x8B, 0x73, 0x20, // mov rsi, [rbx+20h]
    0x48, 0x8B, 0x4B, 0x10, // round: mov rcx, [rbx+10h]
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x48, 0xC7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00, // mov qword ptr [rsp+20h], 0
    0xFF, 0x13, // call qword ptr [rbx]
    0x85, 0xC0, // test eax, eax
    0x75, 0x17, // jnz fail
    0x48, 0xFF, 0x43, 0x28, // inc qword ptr [rbx+28h]
    0x48, 0x8B, 0x4B, 0x18, // mov rcx, [rbx+18h]
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0xFF, 0x53, 0x08, // call qword ptr [rbx+8]
    0x48, 0xFF, 0xCE, // dec rsi
    0x75, 0xD0, // jnz round
    0xEB, 0x04, // jmp out
    0x48, 0x89, 0x43, 0x30, // fail: mov [rbx+30h], rax
    0x48, 0x8B, 0x43, 0x28, // out: mov rax, [rbx+28h]
    0x48, 0x83, 0xC4, 0x38, // add rsp, 38h
    0x5E, // pop rsi
    0x5B, // pop rbx
    0xC3, // ret
];

const ROUNDS: u64 = 32;

/// Threads de `threads_interleave_in_windows` que terminaram, e cada valor
/// devolvido pelo contexto ([0x38] do bloco).
static FINISHED: AtomicU64 = AtomicU64::new(0);

/// Corpo de cada thread de sistema: o contexto nativo agendado com o código
/// do pingue-pongue; [0x38] recebe o valor devolvido (u64::MAX numa falha) e
/// [0x40], a célula do contexto agendado depois da saída.
extern "win64" fn window_thread(block: u64) {
    let code = guest::read64(block + 0x48);
    let value = native_context::call(code, &[block], 0).unwrap_or(u64::MAX);
    guest::write64(block + 0x38, value);
    guest::write64(block + 0x40, native_call::scheduled_frame());
    FINISHED.fetch_add(1, Ordering::SeqCst);
}

fn threads_interleave_in_windows(assert: Assert) {
    let code = executable_code::place(&PING_PONG_IN_WINDOW);
    let (wait, set) = (export_thunk("KeWaitForSingleObject"), export_thunk("KeSetEvent"));
    let events = guest::alloc_bytes(0x40);
    let blocks = [guest::alloc_bytes(0x60), guest::alloc_bytes(0x60)];
    if code == 0 || wait == 0 || set == 0 || events == 0 || blocks.contains(&0) {
        assert(false, "nativo intercalado: codigo, eventos e blocos das threads");
        return;
    }
    // Eventos de sincronização; o da primeira começa sinalizado.
    dispatcher::initialize_event(events, 1, true);
    dispatcher::initialize_event(events + 0x20, 1, false);
    for (index, &block) in blocks.iter().enumerate() {
        guest::write_bytes(block, &[0; 0x60]);
        guest::write64(block, wait);
        guest::write64(block + 8, set);
        guest::write64(block + 0x10, events + index as u64 * 0x20);
        guest::write64(block + 0x18, events + (1 - index as u64) * 0x20);
        guest::write64(block + 0x20, ROUNDS);
        guest::write64(block + 0x48, code);
    }
    FINISHED.store(0, Ordering::SeqCst);
    let routine: extern "win64" fn(u64) = window_thread;
    let handles: [u64; 2] = core::array::from_fn(|index| kernel_threads::create_system_thread(0, routine as usize as u64, blocks[index], 0x1F_FFFF, 0, None).unwrap_or(0));
    let deadline = clock::uptime_ms() + 20_000;
    while clock::uptime_ms() < deadline && FINISHED.load(Ordering::SeqCst) < 2 {
        scheduler::tick(-1);
    }
    let finished = FINISHED.load(Ordering::SeqCst) == 2;
    let results: [(u64, u64, u64, u64); 2] = core::array::from_fn(|index| (guest::read64(blocks[index] + 0x28), guest::read64(blocks[index] + 0x30), guest::read64(blocks[index] + 0x38), guest::read64(blocks[index] + 0x40)));
    debug_print!("[nativo] duas threads em contextos agendados: fim={} (contagem, status, devolvido, celula) = {:x?}", finished, results);
    assert(
        finished && results.iter().all(|&(count, status, value, frame)| count == ROUNDS && status == 0 && value == ROUNDS && frame == 0),
        "nativo intercalado: duas threads de sistema dentro de contextos nativos agendados se intercalam por eventos, cada saida volta ao hospedeiro da propria thread",
    );
    for handle in handles.into_iter().filter(|&handle| handle != 0) {
        let _ = object_manager::close(handle as u32);
    }
    executable_code::release(code);
    for block in blocks {
        guest::free_bytes(block);
    }
    guest::free_bytes(events);
}

pub fn run(assert: Assert) {
    threads_interleave_in_windows(assert);
    if smp::ap_slot_count() > 0 {
        ap_call_while_bsp_in_window(assert);
    }
}
