//! Breakpoints de hardware do modo usuário, por processo.
//!
//! No anel 3 a CPU usa o banco de depuração da thread: na entrada do modo
//! usuário a HAL carrega DR0-DR3, DR6 e DR7 do CONTEXT da thread
//! (`hal::amd64::usermode`) e, na saída, devolve o banco ao CONTEXT. Os
//! comparadores do kernel (`kd::breakpoints`) não valem ali. Um
//! `Z1`/`Z2`/`Z4` num endereço de usuário, com um processo escolhido pelo
//! `monitor .process`, arma o comparador no CONTEXT de cada thread do
//! processo (o mesmo índice DRn para todas, habilitação local), e a
//! máquina para quando o #DB do anel 3 cita esse comparador na thread de um
//! processo com a mesma raiz.
//!
//! - As threads ganham o comparador na hora e a cada continuação (as
//!   criadas depois o recebem na parada seguinte).
//! - Um comparador que a própria thread usava no mesmo índice é trocado
//!   enquanto o breakpoint existe.
//! - Continuar de um comparador de execução desliga o comparador por um
//!   passo da thread (o TF) e o religa depois (`user_debug`).

use core::fmt::Write;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use super::breakpoints::Watch;
use super::packet::Payload;
use super::stop;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Context;
use crate::ntos::ps::user::process_state;

const SLOTS: usize = 4;

struct Slot {
    /// 0 = livre; senão o código do tipo (1 execução, 2 escrita, 3 acesso).
    kind: AtomicU8,
    address: AtomicU64,
    length: AtomicU8,
    eprocess: AtomicU64,
    root: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Slot { kind: AtomicU8::new(0), address: AtomicU64::new(0), length: AtomicU8::new(0), eprocess: AtomicU64::new(0), root: AtomicU64::new(0) }
    }
}

static TABLE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];

fn code(kind: Watch) -> u8 {
    match kind {
        Watch::Execute => 1,
        Watch::Write => 2,
        Watch::Access => 3,
    }
}

fn watch(code: u8) -> Option<Watch> {
    match code {
        1 => Some(Watch::Execute),
        2 => Some(Watch::Write),
        3 => Some(Watch::Access),
        _ => None,
    }
}

/// Os bits do DR7 do comparador `index`: habilitação local, tipo e tamanho.
fn control_bits(index: usize, kind: Watch, length: u64) -> (u64, u64) {
    let read_write = match kind {
        Watch::Execute => 0,
        Watch::Write => 1,
        Watch::Access => 3,
    };
    let size = match length {
        2 => 1,
        8 => 2,
        4 => 3,
        _ => 0,
    };
    let field_mask = 0xFu64 << (16 + index * 4) | 3 << (index * 2);
    let bits = 1u64 << (index * 2) | (read_write | size << 2) << (16 + index * 4);
    (field_mask, bits)
}

/// O comparador `index` armado: tipo, endereço, tamanho, EPROCESS e raiz.
pub fn slot(index: usize) -> Option<(Watch, u64, u64, u64, u64)> {
    let entry = TABLE.get(index)?;
    let kind = watch(entry.kind.load(Ordering::Acquire))?;
    Some((kind, entry.address.load(Ordering::Relaxed), entry.length.load(Ordering::Relaxed) as u64, entry.eprocess.load(Ordering::Relaxed), entry.root.load(Ordering::Relaxed)))
}

/// Arma um comparador de usuário para o processo; `false` sem índice livre
/// ou com tamanho e alinhamento que o x86 não aceita.
pub fn insert(kind: Watch, address: u64, length: u64, eprocess: u64, root: u64) -> bool {
    let length = if kind == Watch::Execute { 1 } else { length };
    if !matches!(length, 1 | 2 | 4 | 8) || address % length != 0 {
        return false;
    }
    if (0..SLOTS).any(|index| matches!(slot(index), Some((existing, at, _, process, _)) if existing == kind && at == address && process == eprocess)) {
        return true;
    }
    let Some(index) = (0..SLOTS).find(|&index| TABLE[index].kind.load(Ordering::Acquire) == 0) else { return false };
    let entry = &TABLE[index];
    entry.address.store(address, Ordering::Relaxed);
    entry.length.store(length as u8, Ordering::Relaxed);
    entry.eprocess.store(eprocess, Ordering::Relaxed);
    entry.root.store(root, Ordering::Relaxed);
    entry.kind.store(code(kind), Ordering::Release);
    apply_to_process(eprocess);
    true
}

/// Tira o comparador do processo (e das threads dele).
pub fn remove(kind: Watch, address: u64, eprocess: u64) -> bool {
    let Some(index) = (0..SLOTS).find(|&index| matches!(slot(index), Some((existing, at, _, process, _)) if existing == kind && at == address && (eprocess == 0 || process == eprocess))) else { return false };
    let process = TABLE[index].eprocess.load(Ordering::Relaxed);
    TABLE[index].kind.store(0, Ordering::Release);
    clear_in_process(process, index);
    true
}

/// O host se desligou: os comparadores saem das threads.
pub fn remove_all() {
    for index in 0..SLOTS {
        if let Some((_, _, _, process, _)) = slot(index) {
            TABLE[index].kind.store(0, Ordering::Release);
            clear_in_process(process, index);
        }
    }
}

/// Algum comparador de usuário armado.
pub fn any() -> bool {
    (0..SLOTS).any(|index| slot(index).is_some())
}

/// Grava no CONTEXT os comparadores do processo (endereços e DR7).
pub fn apply_to_context(context: &Context, eprocess: u64) {
    let registers = [&context.dr0, &context.dr1, &context.dr2, &context.dr3];
    let mut control = context.dr7.get();
    for index in 0..SLOTS {
        let Some((kind, address, length, process, _)) = slot(index) else { continue };
        if process != eprocess {
            continue;
        }
        registers[index].set(address);
        let (mask, bits) = control_bits(index, kind, length);
        control = (control & !mask) | bits;
    }
    context.dr7.set(control);
}

/// Desliga o comparador `index` no CONTEXT (o passo de saída de um
/// comparador de execução) ou o religa.
pub fn set_enabled_in_context(context: &Context, index: usize, enabled: bool) {
    let mut control = context.dr7.get();
    if enabled {
        if let Some((kind, address, length, _, _)) = slot(index) {
            [&context.dr0, &context.dr1, &context.dr2, &context.dr3][index].set(address);
            let (mask, bits) = control_bits(index, kind, length);
            control = (control & !mask) | bits;
        }
    } else {
        control &= !(3u64 << (index * 2));
    }
    context.dr7.set(control);
}

/// As threads vivas de um processo: o endereço do CONTEXT de cada uma. Só
/// quando nenhum processador parado tinha trava (as listas têm travas).
fn for_each_context(eprocess: u64, mut each: impl FnMut(&Context)) {
    if stop::locks_held() {
        return;
    }
    let Some(state) = process_state::get(eprocess) else { return };
    let threads = state.threads.lock();
    for thread in threads.iter() {
        let (context, dead) = thread.with(|thread| (thread.context, thread.dead));
        if context != 0 && !dead {
            // SAFETY: o CONTEXT salvo da thread, memória do kernel viva
            // enquanto a thread está na lista do processo.
            each(unsafe { Context::at(context) });
        }
    }
}

fn apply_to_process(eprocess: u64) {
    for_each_context(eprocess, |context| apply_to_context(context, eprocess));
}

fn clear_in_process(eprocess: u64, index: usize) {
    for_each_context(eprocess, |context| {
        let control = context.dr7.get() & !(3u64 << (index * 2));
        context.dr7.set(control);
    });
}

/// Reaplica todos os comparadores (a máquina vai seguir).
pub fn refresh() {
    let mut done = [0u64; SLOTS];
    for index in 0..SLOTS {
        let Some((_, _, _, process, _)) = slot(index) else { continue };
        if !done.contains(&process) {
            done[index] = process;
            apply_to_process(process);
        }
    }
}

/// O #DB do anel 3 de uma thread com a raiz `root`: o comparador do
/// depurador que o DR6 do CONTEXT cita (índice, tipo e endereço). Os bits
/// citados saem do DR6.
pub fn hit(context: &Context, root: u64) -> Option<(usize, Watch, u64)> {
    let status = context.dr6.get();
    let index = (0..SLOTS).find(|&index| status & (1 << index) != 0 && matches!(slot(index), Some((_, _, _, _, slot_root)) if slot_root == root))?;
    let (kind, address, _, _, _) = slot(index)?;
    context.dr6.set(status & !0xF);
    Some((index, kind, address))
}

/// `uhw`: os comparadores de usuário armados.
pub fn command(out: &mut Payload) {
    let mut any = false;
    for index in 0..SLOTS {
        if let Some((kind, address, length, process, root)) = slot(index) {
            any = true;
            let kind = match kind {
                Watch::Execute => "execucao",
                Watch::Write => "escrita",
                Watch::Access => "acesso",
            };
            let _ = writeln!(out, "DR{} {:<8} {:#018x} tamanho {} EPROCESS {:#x} CR3 {:#x}", index, kind, address, length, process, root);
        }
    }
    if !any {
        out.push_str("nenhum breakpoint de hardware de usuario\n");
    }
    if stop::locks_held() {
        out.push_str("(um processador parado tinha trava: as threads recebem os comparadores na proxima parada)\n");
    }
}
