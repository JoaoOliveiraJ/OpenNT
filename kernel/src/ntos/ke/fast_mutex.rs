//! FAST_MUTEX e KGUARDED_MUTEX — `system32/ntos/ke/fast-mutex.js`.
//!
//! Layout de 0x38 bytes e o protocolo de Count do kernel de referência:
//! bit 0 disponível, bit 1 despertar em trânsito e aguardantes nos bits
//! superiores (ExpAcquireFastMutexContended / ExpReleaseFastMutexContended).

use super::{critical_region, dispatcher, irql};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

fn current_thread() -> u64 {
    process::get_current_thread()
}

/// Lê Count atomicamente sem alterar seus bits.
fn read_atomic(pointer: u64) -> Result<u32, KernelError> {
    guest::compare_exchange32(pointer, 0, 0)
}

/// Exige IRQL até APC_LEVEL; as variantes inseguras em PASSIVE_LEVEL exigem
/// as APCs desligadas pela região correspondente.
fn validate_caller(caller_controls_irql: bool, requires_guarded_region: bool) -> Result<u8, KernelError> {
    let level = irql::get_irql();
    if level > 1 {
        return Err(KernelError::new("fast/guarded mutex IRQL exceeds APC_LEVEL"));
    }
    if caller_controls_irql && level == 0 && !(if requires_guarded_region { critical_region::all_disabled() } else { critical_region::disabled() }) {
        return Err(KernelError::new("unsafe mutex requires APCs disabled by its caller"));
    }
    Ok(level)
}

/// Count disponível, dono nulo, contador de contenções e evento de
/// sincronização embutido.
pub fn initialize(pointer: u64) {
    guest::write32(pointer, 1);
    guest::write64(pointer + 8, 0);
    guest::write32(pointer + 0x10, 0);
    dispatcher::initialize_event(pointer + 0x18, 1, false);
}

/// Aquisição suspensível: acompanha contenção e reserva de despertar.
pub struct Request {
    pointer: u64,
    thread: u64,
    /// O chamador controla o IRQL.
    unsafe_variant: bool,
    old_irql: u8,
    contended: bool,
    parked: bool,
    mask: u32,
    increment: u32,
    done: bool,
}

/// Captura a thread e o IRQL de entrada; as variantes seguras elevam a
/// APC_LEVEL.
pub fn begin(pointer: u64, caller_controls_irql: bool, requires_guarded_region: bool) -> Result<Request, KernelError> {
    let old_irql = validate_caller(caller_controls_irql, requires_guarded_region)?;
    let thread = current_thread();
    if thread == 0 {
        return Err(KernelError::new("mutex requires a current KTHREAD"));
    }
    if !caller_controls_irql && old_irql < 1 {
        irql::raise_irql(1);
    }
    Ok(Request { pointer, thread, unsafe_variant: caller_controls_irql, old_irql, contended: false, parked: false, mask: 1, increment: 4, done: false })
}

/// Grava o dono e, na variante segura, o IRQL de entrada.
fn publish_ownership(pointer: u64, thread: u64, old_irql: u8, unsafe_variant: bool) {
    guest::write64(pointer + 8, thread);
    if !unsafe_variant {
        guest::write32(pointer + 0x30, old_irql as u32);
    }
}

impl Request {
    /// Tenta adquirir ou publicar a espera; depois de consumir um despertar
    /// usa a máscara e o incremento da reserva transferida. `None` = espera.
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if self.done {
            return Ok(Some(0));
        }
        let pointer = self.pointer;
        // O evento é consumido por compare-exchange: leitura e escrita
        // separadas entregariam a mesma reserva a duas CPUs.
        if self.parked {
            if guest::compare_exchange32(pointer + 0x1C, 1, 0)? != 1 {
                return Ok(None);
            }
            self.parked = false;
            self.mask = 3;
            self.increment = 2;
        }
        let mut value = read_atomic(pointer)?;
        loop {
            if value & 1 != 0 {
                let observed = guest::compare_exchange32(pointer, value, value ^ self.mask)?;
                if observed == value {
                    publish_ownership(pointer, self.thread, self.old_irql, self.unsafe_variant);
                    self.done = true;
                    return Ok(Some(0));
                }
                value = observed;
                continue;
            }
            // Uma contenção por aquisição, mesmo com várias consultas.
            if !self.contended {
                let mut expected = read_atomic(pointer + 0x10)?;
                loop {
                    let observed = guest::compare_exchange32(pointer + 0x10, expected, expected.wrapping_add(1))?;
                    if observed == expected {
                        break;
                    }
                    expected = observed;
                }
                self.contended = true;
            }
            let observed = guest::compare_exchange32(pointer, value, value.wrapping_add(self.increment))?;
            if observed != value {
                value = observed;
                continue;
            }
            self.parked = true;
            return Ok(None);
        }
    }
}

/// Avança o dispatcher enquanto o evento não permite retomar.
fn acquire_with(pointer: u64, caller_controls_irql: bool, requires_guarded_region: bool) -> Result<u32, KernelError> {
    let mut request = begin(pointer, caller_controls_irql, requires_guarded_region)?;
    while request.poll()?.is_none() {
        dispatcher::pump_kernel();
    }
    Ok(0)
}

/// Tenta sem publicar espera; a falha restaura o IRQL elevado.
pub fn try_acquire(pointer: u64) -> Result<u32, KernelError> {
    let old_irql = validate_caller(false, false)?;
    let thread = current_thread();
    if thread == 0 {
        return Err(KernelError::new("mutex requires a current KTHREAD"));
    }
    if old_irql < 1 {
        irql::raise_irql(1);
    }
    let mut value = read_atomic(pointer)?;
    while value & 1 != 0 {
        let observed = guest::compare_exchange32(pointer, value, value & !1)?;
        if observed == value {
            publish_ownership(pointer, thread, old_irql, false);
            return Ok(1);
        }
        value = observed;
    }
    if old_irql < 1 {
        irql::lower_irql(old_irql as u64);
    }
    Ok(0)
}

/// Exige o dono, captura seu IRQL antes de liberar e transfere um despertar
/// quando há aguardantes.
fn release_with(pointer: u64, caller_controls_irql: bool, requires_guarded_region: bool) -> Result<u32, KernelError> {
    validate_caller(caller_controls_irql, requires_guarded_region)?;
    if guest::read64(pointer + 8) != current_thread() {
        return Err(KernelError::new("mutex released by non-owner"));
    }
    if !caller_controls_irql && irql::get_irql() != 1 {
        return Err(KernelError::new("safe mutex released outside APC_LEVEL"));
    }
    // Owner e OldIrql podem ser sobrescritos pelo próximo dono assim que a
    // palavra fica disponível.
    let old_irql = if caller_controls_irql { irql::get_irql() } else { guest::read8(pointer + 0x30) };
    guest::write64(pointer + 8, 0);
    let mut value = guest::compare_exchange32(pointer, 0, 1)?;
    if value != 0 {
        loop {
            let next = if value & 2 != 0 { value.wrapping_add(1) } else { value.wrapping_sub(1) };
            let observed = guest::compare_exchange32(pointer, value, next)?;
            if observed == value {
                break;
            }
            value = observed;
        }
        if value & 2 == 0 {
            dispatcher::set_event(pointer + 0x18);
        }
    }
    if !caller_controls_irql && old_irql < 1 {
        irql::lower_irql(old_irql as u64);
    }
    Ok(0)
}

pub fn acquire(pointer: u64) -> Result<u32, KernelError> {
    acquire_with(pointer, false, false)
}

pub fn release(pointer: u64) -> Result<u32, KernelError> {
    release_with(pointer, false, false)
}

pub fn acquire_unsafe(pointer: u64) -> Result<u32, KernelError> {
    acquire_with(pointer, true, false)
}

pub fn release_unsafe(pointer: u64) -> Result<u32, KernelError> {
    release_with(pointer, true, false)
}

pub fn acquire_guarded_unsafe(pointer: u64) -> Result<u32, KernelError> {
    acquire_with(pointer, true, true)
}

pub fn release_guarded_unsafe(pointer: u64) -> Result<u32, KernelError> {
    release_with(pointer, true, true)
}
