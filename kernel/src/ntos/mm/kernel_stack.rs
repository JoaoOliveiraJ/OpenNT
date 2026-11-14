//! Pilhas de kernel das threads: o MmCreateKernelStack e o
//! MmDeleteKernelStack do NT.
//!
//! Cada pilha ocupa uma reserva fixa de [`SLOT_SIZE`] bytes de VA na janela
//! `KERNEL_STACK_BASE..TOP` da metade de sistema (`memory_map`). As páginas
//! da pilha ficam no topo da reserva, em frames do PFN não contíguos,
//! mapeados em PTEs de 4 KB de supervisor, RW e NX; o resto da reserva fica
//! sem PTE, e a página logo abaixo do StackLimit é a guarda: um estouro falta
//! nela em vez de escrever na memória vizinha. A geometria das reservas é
//! aritmética e não depende de trava, para que o diagnóstico de falta do
//! kernel (`hal::amd64::irqstubs`, que roda na pilha da IST) reconheça uma
//! guarda atingida.
//!
//! Layout de uma pilha, do topo para baixo, como no x64 do NT:
//!
//! ```text
//!   StackBase      topo exclusivo da pilha
//!   InitialStack   StackBase - sizeof(KERNEL_STACK_CONTROL): o controle da
//!                  pilha (CurrentStackBase, ActualLimit, Previous zerado) e
//!                  o valor que o despacho grava em KPRCB.RspBase e TSS.RSP0
//!   StackLimit     a página mais baixa da pilha
//!   guarda         StackLimit - 0x1000, sem PTE
//! ```
//!
//! O ceifador da thread devolve a pilha ([`delete`]); se a CPU ainda está
//! nela (a liberação partiu da própria pilha), ela fica para o próximo
//! [`reap`], que roda fora dela.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::paging::{self, MapOptions};
use super::{memory_map as map, pfn};
use crate::hal::{cpu, physical};
use crate::ntos::inc::types::extra_fs_fat::KernelStackControl;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::ke::smp;
use crate::rtl::{KernelError, SpinLock};

/// Pilha de kernel comum: 64 KiB (os quadros do kernel Rust passam dos 24
/// KiB do KERNEL_STACK_SIZE do NT).
pub const KERNEL_STACK_SIZE: u64 = 0x1_0000;
/// Pilha grande (o KERNEL_LARGE_STACK_SIZE das threads GUI e das pilhas de
/// callout grandes).
pub const KERNEL_LARGE_STACK_SIZE: u64 = 0x2_0000;
/// A página sem PTE logo abaixo do StackLimit.
pub const KERNEL_STACK_GUARD: u64 = 0x1000;
/// Reserva de VA de cada pilha (a maior pilha, a guarda e folga sem PTE),
/// alinhada ao próprio tamanho.
pub const SLOT_SIZE: u64 = 0x4_0000;
const SLOT_COUNT: u64 = (map::KERNEL_STACK_TOP - map::KERNEL_STACK_BASE) / SLOT_SIZE;
const PAGE: u64 = 0x1000;

const _: () = assert!(KERNEL_LARGE_STACK_SIZE + KERNEL_STACK_GUARD <= SLOT_SIZE && SLOT_SIZE.is_power_of_two() && map::KERNEL_STACK_BASE % SLOT_SIZE == 0);
// Uma pilha nunca atravessa uma PT: as páginas de uma reserva têm uma PT só.
const _: () = assert!(map::LARGE_PAGE_SIZE % SLOT_SIZE == 0);
const _: () = assert!(KernelStackControl::SIZE % 16 == 0);

/// Uma pilha de kernel viva.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelStack {
    /// StackBase: o topo exclusivo.
    pub base: u64,
    /// InitialStack: o KERNEL_STACK_CONTROL fica aqui.
    pub initial: u64,
    /// StackLimit: a página mais baixa.
    pub limit: u64,
}

impl KernelStack {
    /// Bytes de pilha utilizável (StackBase - StackLimit).
    pub fn size(&self) -> u64 {
        self.base - self.limit
    }

    /// `address` é uma VA da pilha.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.limit && address < self.base
    }
}

struct Allocation {
    stack: KernelStack,
    frames: Vec<u64>,
}

struct State {
    /// StackBase -> pilha viva e os frames dela.
    live: BTreeMap<u64, Allocation>,
    /// Reservas devolvidas, reusadas antes de abrir uma nova.
    free_slots: Vec<u64>,
    next_slot: u64,
    /// Pilhas liberadas enquanto a CPU ainda estava nelas.
    deferred: Vec<KernelStack>,
}

static STATE: SpinLock<State> = SpinLock::new(State { live: BTreeMap::new(), free_slots: Vec::new(), next_slot: 0, deferred: Vec::new() });

/// O RSP de quem chama.
fn current_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: só lê o registrador.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

/// StackBase da reserva `slot` (o topo dela).
fn slot_top(slot: u64) -> u64 {
    map::KERNEL_STACK_BASE + (slot + 1) * SLOT_SIZE
}

/// A reserva cujo topo é `base`.
fn slot_of(base: u64) -> u64 {
    (base - map::KERNEL_STACK_BASE) / SLOT_SIZE - 1
}

/// A CPU está executando na pilha (ou na guarda dela).
fn in_use(stack: &KernelStack) -> bool {
    let rsp = current_rsp();
    rsp >= stack.limit - KERNEL_STACK_GUARD && rsp <= stack.base
}

/// MmCreateKernelStack: uma pilha nova, zerada, com a guarda e o
/// KERNEL_STACK_CONTROL no InitialStack.
pub fn create(large: bool) -> Result<KernelStack, KernelError> {
    reap();
    let size = if large { KERNEL_LARGE_STACK_SIZE } else { KERNEL_STACK_SIZE };
    let slot = {
        let mut state = STATE.lock();
        match state.free_slots.pop() {
            Some(slot) => slot,
            None if state.next_slot < SLOT_COUNT => {
                state.next_slot += 1;
                state.next_slot - 1
            }
            None => return Err(KernelError::new("janela das pilhas de kernel esgotada")),
        }
    };
    let base = slot_top(slot);
    let limit = base - size;
    let mut frames: Vec<u64> = Vec::with_capacity((size / PAGE) as usize);
    for page in (limit..base).step_by(PAGE as usize) {
        let frame = pfn::alloc_page();
        if frame == 0 {
            unmap_and_free(limit, frames);
            STATE.lock().free_slots.push(slot);
            return Err(KernelError::with_status("PFN esgotado na pilha de kernel", 0xC000_009A));
        }
        physical::zero(frame, PAGE as usize);
        if !paging::map_page(page, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions { nx: true, ..MapOptions::default() }) {
            pfn::free_page(frame);
            unmap_and_free(limit, frames);
            STATE.lock().free_slots.push(slot);
            return Err(KernelError::new("mapeamento da pilha de kernel falhou"));
        }
        frames.push(frame);
    }
    let initial = base - KernelStackControl::SIZE;
    // SAFETY: as páginas do topo acabaram de ser mapeadas e zeradas.
    let control = unsafe { KernelStackControl::at(initial) };
    control.current_stack_base.set(base);
    control.actual_limit.set(limit);
    let stack = KernelStack { base, initial, limit };
    STATE.lock().live.insert(base, Allocation { stack, frames });
    Ok(stack)
}

/// Desmapeia as `frames.len()` primeiras páginas a partir de `limit` e
/// devolve frames e tabelas ao PFN depois que toda CPU descartou as
/// traduções. Se a invalidação remota falhar, os frames ficam retidos (um
/// vazamento é melhor que um frame reusado com tradução viva).
fn unmap_and_free(limit: u64, frames: Vec<u64>) {
    let mut tables = Vec::new();
    for index in 0..frames.len() as u64 {
        paging::unmap_page(limit + index * PAGE, MapOptions { deferred_tables: Some(&mut tables), ..MapOptions::default() });
    }
    cpu::reload_cr3();
    if let Err(error) = smp::flush_remote_tlb(false) {
        crate::debug_print!("[kernel-stack] invalidacao remota falhou, {} frames retidos: {}", frames.len() + tables.len(), error);
        return;
    }
    for frame in tables.into_iter().chain(frames) {
        pfn::free_page(frame);
    }
}

fn release(stack: KernelStack) {
    let Some(allocation) = STATE.lock().live.remove(&stack.base) else {
        crate::debug_print!("[kernel-stack] liberacao de pilha desconhecida (StackBase {:#x})", stack.base);
        return;
    };
    unmap_and_free(allocation.stack.limit, allocation.frames);
    STATE.lock().free_slots.push(slot_of(stack.base));
}

/// MmDeleteKernelStack: devolve a pilha; adiada se a CPU ainda está nela.
pub fn delete(stack: KernelStack) {
    if in_use(&stack) {
        STATE.lock().deferred.push(stack);
        return;
    }
    release(stack);
}

/// Libera as pilhas adiadas que a CPU já deixou.
pub fn reap() {
    let ready: Vec<KernelStack> = {
        let mut state = STATE.lock();
        if state.deferred.is_empty() {
            return;
        }
        let (ready, kept) = state.deferred.drain(..).partition(|stack| !in_use(stack));
        state.deferred = kept;
        ready
    };
    for stack in ready {
        release(stack);
    }
}

/// A pilha viva de topo `base`.
pub fn find(base: u64) -> Option<KernelStack> {
    STATE.lock().live.get(&base).map(|allocation| allocation.stack)
}

/// Quantas pilhas estão vivas (as adiadas contam até o `reap`).
pub fn live_count() -> usize {
    STATE.lock().live.len()
}

/// Uma falta na janela das pilhas, para o diagnóstico do kernel.
pub struct StackFault {
    /// O topo (StackBase) da reserva atingida.
    pub base: u64,
    /// O acesso caiu abaixo do StackLimit: estouro. Senão, a pilha já tinha
    /// sido liberada.
    pub overflow: bool,
}

/// Classifica, sem trava, uma falta em `address`: as páginas de uma pilha
/// viva estão sempre mapeadas, então um acesso que falta numa reserva é um
/// estouro (abaixo do StackLimit, na guarda ou na folga) ou o uso de uma
/// pilha liberada.
pub fn classify_fault(address: u64) -> Option<StackFault> {
    if !map::is_kernel_stack(address) {
        return None;
    }
    let base = map::KERNEL_STACK_BASE + ((address - map::KERNEL_STACK_BASE) / SLOT_SIZE + 1) * SLOT_SIZE;
    // Abaixo da faixa de uma pilha comum a falta é estouro: numa pilha
    // grande essas páginas estão mapeadas e não faltam.
    Some(StackFault { base, overflow: address < base - KERNEL_STACK_SIZE })
}
