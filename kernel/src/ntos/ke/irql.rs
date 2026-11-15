//! Nível de interrupção de cada processador.
//!
//! Como no x64 do NT 19041, o IRQL é o CR8 da CPU: o KeGetCurrentIrql é um
//! `mov rax, cr8` e o KfRaiseIrql, o KeRaiseIrqlToDpcLevel e o KeLowerIrql
//! gravam o CR8, o mesmo registrador que os drivers leem e gravam inline
//! (`mov rax, cr8`/`mov cr8, rcx`, o KeGetCurrentIrql e o KzLowerIrql do
//! wdm.h). Nada mais guarda o nível (o ntoskrnl não usa KPCR.Irql): um
//! driver que sobe pelo export e desce inline, ou o contrário, deixa o
//! kernel vendo o nível verdadeiro. O CR8 é a classe de prioridade do TPR
//! do LAPIC (TPR[7:4]): um IRQL `n` retém no LAPIC os vetores de classe até
//! `n` (vetor < 16 * (n + 1)), como no NT; o ExtINT do PIC e as NMIs não
//! passam pelo TPR. Cada CPU tem o seu desde a partida (o INIT o zera), e
//! uma thread que deixa a CPU leva o seu (KTHREAD.WaitIrql) e o recoloca ao
//! voltar (`context_switch`).

use crate::hal::cpu;
use crate::ntos::inc::types::{Field, NtStruct};

pub const PASSIVE_LEVEL: u8 = 0;
pub const APC_LEVEL: u8 = 1;
pub const DISPATCH_LEVEL: u8 = 2;
/// SYNCH_LEVEL do x64 multiprocessado.
pub const SYNCH_LEVEL: u8 = 12;
pub const HIGH_LEVEL: u8 = 15;

/// O nível da CPU corrente: KeGetCurrentIrql (ntoskrnl 19041 rva 0x21fa90,
/// `mov rax, cr8`).
pub fn get_irql() -> u8 {
    cpu::read_cr8() as u8
}

/// Publica `level` como o nível da CPU corrente (`mov cr8`).
fn publish(level: u8) {
    cpu::write_cr8(level as u64 & 0xF);
}

/// KeGetEffectiveIrql (ntoskrnl 19041 rva 0x25edf0): com as interrupções
/// ligadas, o IRQL corrente; desligadas, HIGH_LEVEL (nada interrompe a CPU).
pub fn effective_irql() -> u8 {
    if crate::hal::cpu::interrupts_enabled() { get_irql() } else { HIGH_LEVEL }
}

/// Exige um nível não inferior ao atual; devolve o anterior. Direção
/// inválida imprime o diagnóstico e para a CPU (bugcheck).
pub fn raise_irql(level: u8) -> u8 {
    let previous = get_irql();
    if level < previous {
        debug_print!("[ke] BUGCHECK: KeRaiseIrql p/ nivel menor ({} < {})", level, previous);
        cpu::halt_forever();
    }
    publish(level);
    previous
}

pub fn lower_irql(level: u64) {
    let current = get_irql();
    if level > current as u64 {
        debug_print!(
            "[ke] BUGCHECK: KeLowerIrql para nivel maior ({:#x} | hi={:#x} > {})",
            level as u32,
            level >> 32,
            current
        );
        cpu::halt_forever();
    }
    publish(level as u8);
}

/// Troca o nível da CPU corrente sem conferir a direção: só a troca de
/// thread (`context_switch`), que recoloca o IRQL de quem volta a executar.
pub fn swap_irql(level: u8) -> u8 {
    let previous = get_irql();
    publish(level);
    previous
}

/// KeRaiseIrql: o IRQL anterior vai para a saída opcional.
pub fn raise_irql_saving(level: u8, old_irql: u64) {
    let previous = raise_irql(level);
    if old_irql != 0 {
        // SAFETY: PKIRQL OldIrql do chamador.
        unsafe { Field::<u8>::at(old_irql) }.set(previous);
    }
}

/// KfRaiseIrql (rva 0x21fa60: `mov rax, cr8; mov cr8, r11`): devolve o
/// IRQL anterior.
pub fn kf_raise_irql(level: u8) -> u8 {
    raise_irql(level)
}

/// Sobe a `level` (nunca desce) e devolve o IRQL anterior.
pub fn raise_at_least(level: u8) -> u8 {
    let previous = get_irql();
    if level > previous {
        raise_irql(level);
    }
    previous
}
