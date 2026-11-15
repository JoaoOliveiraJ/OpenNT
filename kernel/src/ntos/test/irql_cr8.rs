//! O IRQL é o CR8 (`ke/irql.rs`), como no x64 do NT 19041.
//!
//! - código nativo que sobe pelo KfRaiseIrql e desce inline (`mov cr8, 0`,
//!   o KzLowerIrql do wdm.h, como o tcpip.sys) deixa o kernel em
//!   PASSIVE_LEVEL: o KeGetCurrentIrql seguinte devolve 0, e uma subida
//!   inline (`mov cr8, 1`) é vista pelo export; o nível que o export grava é
//!   o que o `mov rax, cr8` inline lê;
//! - uma thread de sistema que sobe inline a APC_LEVEL e espera um evento
//!   leva o nível consigo: enquanto ela está parada, o contexto de boot roda
//!   com o CR8 dele (PASSIVE_LEVEL), e ela volta da espera com o CR8 em
//!   APC_LEVEL.

use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::hal::cpu;
use crate::ntos::init::exports;
use crate::ntos::ke::{clock, dispatcher, irql, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::ResolvedImport;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::{kernel_threads, scheduler};

type Assert = fn(bool, &str);

/// O trampolim de um export, como um driver o recebe na IAT.
fn export_thunk(name: &str) -> u64 {
    let Some(ResolvedImport::Thunk(id)) = exports::lookup("ntoskrnl.exe", name) else { return 0 };
    exports::thunk_address(id as u64).unwrap_or(0)
}

/// (KfRaiseIrql, KeGetCurrentIrql, saída): [0] o IRQL anterior do
/// KfRaiseIrql(DISPATCH_LEVEL), [1] o CR8 lido inline depois dele, [2] o
/// KeGetCurrentIrql depois dele, [3] o KeGetCurrentIrql depois de
/// `mov cr8, 0`, [4] o KeGetCurrentIrql depois de `mov cr8, 1`; sai em
/// PASSIVE_LEVEL (inline).
const RAISE_EXPORT_LOWER_INLINE: [u8; 81] = [
    0x53, // push rbx
    0x56, // push rsi
    0x57, // push rdi
    0x48, 0x83, 0xEC, 0x20, // sub rsp, 20h
    0x48, 0x89, 0xCE, // mov rsi, rcx
    0x48, 0x89, 0xD7, // mov rdi, rdx
    0x4C, 0x89, 0xC3, // mov rbx, r8
    0xB9, 0x02, 0x00, 0x00, 0x00, // mov ecx, 2
    0xFF, 0xD6, // call rsi (KfRaiseIrql)
    0x48, 0x89, 0x03, // mov [rbx], rax
    0x44, 0x0F, 0x20, 0xC0, // mov rax, cr8
    0x48, 0x89, 0x43, 0x08, // mov [rbx+8], rax
    0xFF, 0xD7, // call rdi (KeGetCurrentIrql)
    0x48, 0x89, 0x43, 0x10, // mov [rbx+10h], rax
    0x31, 0xC0, // xor eax, eax
    0x44, 0x0F, 0x22, 0xC0, // mov cr8, rax
    0xFF, 0xD7, // call rdi
    0x48, 0x89, 0x43, 0x18, // mov [rbx+18h], rax
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0x44, 0x0F, 0x22, 0xC0, // mov cr8, rax
    0xFF, 0xD7, // call rdi
    0x48, 0x89, 0x43, 0x20, // mov [rbx+20h], rax
    0x31, 0xC0, // xor eax, eax
    0x44, 0x0F, 0x22, 0xC0, // mov cr8, rax
    0x48, 0x83, 0xC4, 0x20, // add rsp, 20h
    0x5F, // pop rdi
    0x5E, // pop rsi
    0x5B, // pop rbx
    0xC3, // ret
];

fn export_raise_inline_lower(assert: Assert) {
    let entry = irql::get_irql();
    let (raise, current) = (export_thunk("KfRaiseIrql"), export_thunk("KeGetCurrentIrql"));
    let code = super::executable_code::place(&RAISE_EXPORT_LOWER_INLINE);
    let block = guest::alloc_bytes(0x40);
    if code == 0 || block == 0 || raise == 0 || current == 0 {
        assert(false, "irql: codigo nativo e trampolins do teste do CR8");
        return;
    }
    guest::write_bytes(block, &[0xEE; 0x40]);
    crate::hal::amd64::native_call::call(code, &[raise, current, block]);
    let seen: [u64; 5] = core::array::from_fn(|index| guest::read64(block + index as u64 * 8) & 0xFF);
    // O código saiu em PASSIVE_LEVEL; volta ao nível de entrada.
    irql::swap_irql(entry);
    debug_print!("[irql] KfRaiseIrql/inline: anterior={} cr8={} export={} apos mov cr8,0: {} apos mov cr8,1: {}", seen[0], seen[1], seen[2], seen[3], seen[4]);
    assert(seen[0] == 0 && seen[1] == 2 && seen[2] == 2, "irql: o KfRaiseIrql grava o CR8 que o codigo nativo le inline");
    assert(seen[3] == 0 && seen[4] == 1, "irql: o nivel gravado inline (mov cr8) e o que o KeGetCurrentIrql devolve, subindo ou descendo");
    super::executable_code::release(code);
    guest::free_bytes(block);
}

/// A thread de `carried_across_switch` terminou.
static CARRIED: AtomicU64 = AtomicU64::new(0);

/// Bloco: [0] evento, [0x20] CR8 antes da espera, [0x28] status, [0x30] CR8
/// depois, [0x38] KeGetCurrentIrql depois, [0x40] pronto.
extern "win64" fn raised_waiter(block: u64) {
    // Sobe inline, como um driver (KzRaiseIrql), e espera em APC_LEVEL.
    cpu::write_cr8(irql::APC_LEVEL as u64);
    guest::write64(block + 0x20, cpu::read_cr8());
    let status = call_export("KeWaitForSingleObject", &[block, 0, 0, 0, 0]).unwrap_or(u64::MAX);
    guest::write64(block + 0x28, status);
    guest::write64(block + 0x30, cpu::read_cr8());
    guest::write64(block + 0x38, call_export("KeGetCurrentIrql", &[]).unwrap_or(u64::MAX) & 0xFF);
    cpu::write_cr8(irql::PASSIVE_LEVEL as u64);
    guest::write64(block + 0x40, 1);
    CARRIED.store(1, Ordering::SeqCst);
}

fn carried_across_switch(assert: Assert) {
    let block = guest::alloc_bytes(0x80);
    guest::write_bytes(block, &[0; 0x80]);
    dispatcher::initialize_event(block, 1, false);
    CARRIED.store(0, Ordering::SeqCst);
    let routine: extern "win64" fn(u64) = raised_waiter;
    let handle = kernel_threads::create_system_thread(0, routine as usize as u64, block, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    let pump = |milliseconds: u64, done: &dyn Fn() -> bool| {
        let deadline = clock::uptime_ms() + milliseconds;
        while clock::uptime_ms() < deadline && !done() {
            scheduler::tick(-1);
        }
        done()
    };
    let parked = thread != 0 && pump(5000, &|| wait::is_waiting(thread));
    // A thread parada levou o APC_LEVEL; o contexto de boot roda no dele.
    let boot_level = cpu::read_cr8();
    let boot_export = call_export("KeGetCurrentIrql", &[]).unwrap_or(u64::MAX) & 0xFF;
    call_export("KeSetEvent", &[block, 0, 0]);
    let finished = pump(5000, &|| CARRIED.load(Ordering::SeqCst) == 1);
    debug_print!(
        "[irql] espera em APC_LEVEL: parada={} cr8 antes={} contexto de boot cr8={} export={} status={:#x} cr8 depois={} export depois={}",
        parked,
        guest::read64(block + 0x20),
        boot_level,
        boot_export,
        guest::read64(block + 0x28),
        guest::read64(block + 0x30),
        guest::read64(block + 0x38)
    );
    assert(parked && boot_level == irql::PASSIVE_LEVEL as u64 && boot_export == 0, "irql: a thread que espera em APC_LEVEL leva o CR8 dela; o despachante roda no proprio nivel");
    assert(finished && guest::read64(block + 0x20) == 1 && guest::read64(block + 0x28) == 0 && guest::read64(block + 0x30) == 1 && guest::read64(block + 0x38) == 1, "irql: a thread volta da espera com o CR8 em APC_LEVEL");
    if handle != 0 {
        let _ = object_manager::close(handle as u32);
    }
    guest::free_bytes(block);
}

pub fn run(assert: Assert) {
    export_raise_inline_lower(assert);
    carried_across_switch(assert);
}
