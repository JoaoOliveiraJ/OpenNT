//! Nível de interrupção de cada processador.
//!
//! Como no NT, o IRQL é da CPU, não do sistema: cada uma guarda o seu na
//! própria KPCR (KPCR.Irql, lido e gravado pelo GS), e elevar ou baixar o
//! nível numa CPU não muda o que outra vê. Antes da KPCR do BSP (o começo da
//! fase 0) só existe o processador de boot, e o nível fica numa célula de
//! partida que a KPCR herda ao ser publicada (`pcr::init`). Uma thread que
//! deixa a CPU leva o seu IRQL (KTHREAD.WaitIrql) e o recoloca ao voltar
//! (`context_switch`).

use core::sync::atomic::{AtomicU8, Ordering};

use super::pcr;
use crate::hal::cpu;
use crate::ntos::inc::types::{Field, NtStruct};

pub const PASSIVE_LEVEL: u8 = 0;
pub const APC_LEVEL: u8 = 1;
pub const DISPATCH_LEVEL: u8 = 2;
/// SYNCH_LEVEL do x64 multiprocessado.
pub const SYNCH_LEVEL: u8 = 12;
pub const HIGH_LEVEL: u8 = 15;

/// O nível do processador de boot antes da KPCR dele.
static BOOT: AtomicU8 = AtomicU8::new(PASSIVE_LEVEL);

/// O nível da CPU corrente.
pub fn get_irql() -> u8 {
    if pcr::get_pcr_address() == 0 {
        return BOOT.load(Ordering::Relaxed);
    }
    pcr::current_irql()
}

/// Publica `level` como o nível da CPU corrente.
fn publish(level: u8) {
    if pcr::get_pcr_address() == 0 {
        BOOT.store(level, Ordering::Relaxed);
    } else {
        pcr::set_current_irql(level);
    }
}

/// KeGetEffectiveIrql (ntoskrnl 19041 rva 0x25edf0): com as interrupções
/// ligadas, o IRQL corrente; desligadas, HIGH_LEVEL (nada interrompe a CPU).
pub fn effective_irql() -> u8 {
    if crate::hal::cpu::interrupts_enabled() { get_irql() } else { HIGH_LEVEL }
}

/// O nível de partida, que a KPCR do BSP herda (`pcr::init`).
pub fn boot_level() -> u8 {
    BOOT.load(Ordering::Relaxed)
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

/// KfRaiseIrql: devolve o IRQL anterior.
pub fn kf_raise_irql(level: u8) -> u8 {
    let previous = get_irql();
    raise_irql(level);
    previous
}

/// Sobe a `level` (nunca desce) e devolve o IRQL anterior.
pub fn raise_at_least(level: u8) -> u8 {
    let previous = get_irql();
    if level > previous {
        raise_irql(level);
    }
    previous
}
