//! Nível de interrupção do runtime — `system32/ntos/ke/irql.js`.
//!
//! A variável acompanha elevações e reduções; a publicação mantém a célula
//! física (lida pelo stub de interrupções) e a PCR coerentes.

use core::sync::atomic::{AtomicU8, Ordering};

use super::pcr;
use crate::hal::{cpu, physical};

pub const PASSIVE_LEVEL: u8 = 0;
pub const APC_LEVEL: u8 = 1;
pub const DISPATCH_LEVEL: u8 = 2;
pub const HIGH_LEVEL: u8 = 15;

/// O stub consulta esta célula para decidir se a IRQ pode preemptar.
const CURRENT_INTERRUPT_LEVEL_ADDRESS: u64 = 0x81528;

static CURRENT: AtomicU8 = AtomicU8::new(PASSIVE_LEVEL);

fn publish(level: u8) {
    physical::write32(CURRENT_INTERRUPT_LEVEL_ADDRESS, level as u32);
    pcr::set_irql(level);
}

pub fn get_irql() -> u8 {
    CURRENT.load(Ordering::Relaxed)
}

/// Exige um nível não inferior ao atual; devolve o anterior. Direção
/// inválida imprime o diagnóstico e para a CPU (bugcheck).
pub fn raise_irql(level: u8) -> u8 {
    let previous = get_irql();
    if level < previous {
        debug_print!("[ke] BUGCHECK: KeRaiseIrql p/ nivel menor ({} < {})", level, previous);
        cpu::halt_forever();
    }
    CURRENT.store(level, Ordering::Relaxed);
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
    CURRENT.store(level as u8, Ordering::Relaxed);
    publish(level as u8);
}
