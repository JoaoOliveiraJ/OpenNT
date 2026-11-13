//! EX_SPIN_LOCK.
//!
//! A palavra nativa de 32 bits do chamador: o bit 31 reserva o escritor, o
//! bit 30 marca espera por leitores e os bits 0 a 29 contam leitores. Não há
//! fila paralela de donos. No fim, o spin lock legado (test-and-set com
//! subida a DISPATCH_LEVEL) de ExAcquireSpinLock/ExReleaseSpinLock.

use crate::hal::cpu;
use crate::ntos::ke::irql;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const WRITER_RESERVED: u32 = 0x8000_0000;
const WRITER_WAITING: u32 = 0x4000_0000;
const READER_COUNT_MASK: u32 = 0x3FFF_FFFF;

fn cas(pointer: u64, expected: u32, replacement: u32) -> u32 {
    guest::compare_exchange32(pointer, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

fn update(pointer: u64, transform: impl Fn(u32) -> u32) -> u32 {
    let mut expected = guest::read32(pointer);
    loop {
        let observed = cas(pointer, expected, transform(expected));
        if observed == expected {
            return expected;
        }
        expected = observed;
    }
}

fn require_dispatch_level() -> Result<(), KernelError> {
    if irql::get_irql() < irql::DISPATCH_LEVEL {
        return Err(KernelError::new("EX_SPIN_LOCK requires DISPATCH_LEVEL or higher"));
    }
    Ok(())
}

/// Nas aquisições comuns o IRQL anterior volta durante a espera.
fn pause_contention(previous: Option<u8>) {
    if let Some(level) = previous {
        irql::lower_irql(level as u64);
    }
    cpu::pause();
    if previous.is_some() {
        irql::raise_irql(irql::DISPATCH_LEVEL);
    }
}

/// Publica a espera do escritor sem sobrescrever mudanças concorrentes.
fn mark_waiting(pointer: u64, value: u32) {
    if value & WRITER_WAITING == 0 {
        cas(pointer, value, value | WRITER_WAITING);
    }
}

fn reserve_writer(pointer: u64, try_only: bool, previous: Option<u8>) -> bool {
    loop {
        let value = guest::read32(pointer);
        if value & WRITER_RESERVED != 0 {
            if try_only {
                return false;
            }
            mark_waiting(pointer, value);
            pause_contention(previous);
            continue;
        }
        if cas(pointer, value, value | WRITER_RESERVED) == value {
            return true;
        }
    }
}

/// Espera a contagem chegar a `remaining` mantendo a reserva e o IRQL.
fn drain_readers(pointer: u64, remaining: u32) {
    loop {
        let value = guest::read32(pointer);
        if value & READER_COUNT_MASK == remaining {
            return;
        }
        mark_waiting(pointer, value);
        pause_contention(None);
    }
}

pub fn acquire_exclusive_at_dpc(pointer: u64) -> Result<(), KernelError> {
    require_dispatch_level()?;
    reserve_writer(pointer, false, None);
    drain_readers(pointer, 0);
    Ok(())
}

fn acquire_shared_core(pointer: u64, previous: Option<u8>) {
    // O primeiro CAS só vence sem o bit exclusivo.
    let expected = guest::read32(pointer) & !WRITER_RESERVED;
    if cas(pointer, expected, expected.wrapping_add(1)) == expected {
        return;
    }
    loop {
        let value = guest::read32(pointer);
        if value & WRITER_RESERVED != 0 {
            mark_waiting(pointer, value);
            pause_contention(previous);
            continue;
        }
        if cas(pointer, value, value.wrapping_add(1) & !WRITER_WAITING) == value {
            return;
        }
    }
}

pub fn acquire_shared_at_dpc(pointer: u64) -> Result<(), KernelError> {
    require_dispatch_level()?;
    acquire_shared_core(pointer, None);
    Ok(())
}

/// ExTryAcquireSpinLockExclusiveAtDpcLevel: só com a palavra livre (sem
/// leitores nem escritor reservado); nunca espera.
pub fn try_acquire_exclusive_at_dpc(pointer: u64) -> Result<bool, KernelError> {
    require_dispatch_level()?;
    let value = guest::read32(pointer);
    if value & (WRITER_RESERVED | READER_COUNT_MASK) != 0 {
        return Ok(false);
    }
    Ok(cas(pointer, value, WRITER_RESERVED) == value)
}

/// ExTryAcquireSpinLockSharedAtDpcLevel: falha só com o escritor reservado.
pub fn try_acquire_shared_at_dpc(pointer: u64) -> Result<bool, KernelError> {
    require_dispatch_level()?;
    loop {
        let value = guest::read32(pointer);
        if value & WRITER_RESERVED != 0 {
            return Ok(false);
        }
        if cas(pointer, value, value.wrapping_add(1) & !WRITER_WAITING) == value {
            return Ok(true);
        }
    }
}

/// ExAcquireSpinLockExclusive: devolve o IRQL anterior.
pub fn acquire_exclusive(pointer: u64) -> u8 {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    reserve_writer(pointer, false, Some(previous));
    drain_readers(pointer, 0);
    previous
}

/// ExAcquireSpinLockShared: devolve o IRQL anterior.
pub fn acquire_shared(pointer: u64) -> u8 {
    let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
    acquire_shared_core(pointer, Some(previous));
    previous
}

pub fn release_exclusive_from_dpc(pointer: u64) -> Result<(), KernelError> {
    require_dispatch_level()?;
    update(pointer, |_| 0);
    Ok(())
}

/// Duas operações atômicas distintas, como no protocolo nativo: outro
/// escritor pode republicar a espera entre elas.
pub fn release_shared_from_dpc(pointer: u64) -> Result<(), KernelError> {
    require_dispatch_level()?;
    update(pointer, |value| value & !WRITER_WAITING);
    update(pointer, |value| value.wrapping_sub(1));
    Ok(())
}

pub fn release_exclusive(pointer: u64, previous: u8) -> Result<(), KernelError> {
    release_exclusive_from_dpc(pointer)?;
    irql::lower_irql(previous as u64);
    Ok(())
}

pub fn release_shared(pointer: u64, previous: u8) -> Result<(), KernelError> {
    release_shared_from_dpc(pointer)?;
    irql::lower_irql(previous as u64);
    Ok(())
}

/// ExTryConvertSharedSpinLockExclusive: a referência do próprio chamador
/// permanece até a liberação exclusiva.
pub fn try_convert(pointer: u64) -> Result<bool, KernelError> {
    require_dispatch_level()?;
    if !reserve_writer(pointer, true, None) {
        return Ok(false);
    }
    drain_readers(pointer, 1);
    Ok(true)
}

// ---- spin lock legado (ExAcquireSpinLock/ExReleaseSpinLock) -----------------

/// Spin lock legado com subida a DISPATCH_LEVEL.
pub fn lock_with_raise(lock: u64) -> u8 {
    let previous = irql::get_irql();
    irql::raise_irql(2);
    loop {
        if guest::read32(lock) == 0 {
            guest::write32(lock, 1);
            return previous;
        }
        core::hint::spin_loop();
    }
}

pub fn unlock_with_lower(lock: u64, previous: u8) {
    guest::write32(lock, 0);
    irql::lower_irql(previous as u64);
}

/// API legada: sobe a DISPATCH_LEVEL e adquire por test-and-set; o IRQL
/// anterior vai para `old_irql`.
pub fn acquire_legacy(lock: u64, old_irql: u64) {
    let previous = lock_with_raise(lock);
    guest::write32(old_irql, previous as u32);
}
