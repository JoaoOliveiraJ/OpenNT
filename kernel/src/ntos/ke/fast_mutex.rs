//! FAST_MUTEX e KGUARDED_MUTEX.
//!
//! Layout de 0x38 bytes e o protocolo de Count do kernel de referência:
//! bit 0 disponível, bit 1 despertar em trânsito e aguardantes nos bits
//! superiores (ExpAcquireFastMutexContended / ExpReleaseFastMutexContended).

use core::sync::atomic::Ordering;

use super::{critical_region, dispatcher, irql};
use crate::ntos::inc::types::{FastMutex, NtStruct};
use crate::ntos::ps::process;
use crate::rtl::KernelError;

fn current_thread() -> u64 {
    process::get_current_thread()
}

/// FAST_MUTEX/KGUARDED_MUTEX do chamador (o mesmo layout de 0x38 bytes).
fn mutex_at(pointer: u64) -> &'static FastMutex {
    // SAFETY: os exports recebem um FAST_MUTEX vivo do driver.
    unsafe { FastMutex::at(pointer) }
}

/// Compare-exchange do NT: devolve o valor observado.
fn compare_exchange(cell: &core::sync::atomic::AtomicI32, expected: u32, replacement: u32) -> u32 {
    match cell.compare_exchange(expected as i32, replacement as i32, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(value) | Err(value) => value as u32,
    }
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
    let mutex = mutex_at(pointer);
    mutex.count.set(1);
    mutex.owner.set(0);
    mutex.contention.set(0);
    dispatcher::initialize_event(mutex.event.address(), 1, false);
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
fn publish_ownership(mutex: &FastMutex, thread: u64, old_irql: u8, unsafe_variant: bool) {
    mutex.owner.set(thread);
    if !unsafe_variant {
        mutex.old_irql.set(old_irql as u32);
    }
}

impl Request {
    /// Tenta adquirir ou publicar a espera; depois de consumir um despertar
    /// usa a máscara e o incremento da reserva transferida. `None` = espera.
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if self.done {
            return Ok(Some(0));
        }
        let mutex = mutex_at(self.pointer);
        let count = mutex.count.atomic();
        // O evento é consumido por compare-exchange: leitura e escrita
        // separadas entregariam a mesma reserva a duas CPUs.
        if self.parked {
            if compare_exchange(mutex.event.header.signal_state.atomic(), 1, 0) != 1 {
                return Ok(None);
            }
            self.parked = false;
            self.mask = 3;
            self.increment = 2;
        }
        let mut value = count.load(Ordering::SeqCst) as u32;
        loop {
            if value & 1 != 0 {
                let observed = compare_exchange(count, value, value ^ self.mask);
                if observed == value {
                    publish_ownership(mutex, self.thread, self.old_irql, self.unsafe_variant);
                    self.done = true;
                    return Ok(Some(0));
                }
                value = observed;
                continue;
            }
            // Uma contenção por aquisição, mesmo com várias consultas.
            if !self.contended {
                mutex.contention.atomic().fetch_add(1, Ordering::SeqCst);
                self.contended = true;
            }
            let observed = compare_exchange(count, value, value.wrapping_add(self.increment));
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
    let mutex = mutex_at(pointer);
    let count = mutex.count.atomic();
    let mut value = count.load(Ordering::SeqCst) as u32;
    while value & 1 != 0 {
        let observed = compare_exchange(count, value, value & !1);
        if observed == value {
            publish_ownership(mutex, thread, old_irql, false);
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
    let mutex = mutex_at(pointer);
    if mutex.owner.get() != current_thread() {
        return Err(KernelError::new("mutex released by non-owner"));
    }
    if !caller_controls_irql && irql::get_irql() != 1 {
        return Err(KernelError::new("safe mutex released outside APC_LEVEL"));
    }
    // Owner e OldIrql podem ser sobrescritos pelo próximo dono assim que a
    // palavra fica disponível.
    let old_irql = if caller_controls_irql { irql::get_irql() } else { mutex.old_irql.get() as u8 };
    mutex.owner.set(0);
    let count = mutex.count.atomic();
    let mut value = compare_exchange(count, 0, 1);
    if value != 0 {
        loop {
            let next = if value & 2 != 0 { value.wrapping_add(1) } else { value.wrapping_sub(1) };
            let observed = compare_exchange(count, value, next);
            if observed == value {
                break;
            }
            value = observed;
        }
        if value & 2 == 0 {
            dispatcher::set_event(mutex.event.address());
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

/// ExEnterCriticalRegionAndAcquireFastMutexUnsafe(PFAST_MUTEX):
/// KeEnterCriticalRegion + ExAcquireFastMutexUnsafe; devolve a thread atual
/// (o chamador a repassa à função inversa).
pub fn enter_critical_region_and_acquire_unsafe(pointer: u64) -> Result<u64, KernelError> {
    critical_region::enter_critical()?;
    acquire_unsafe(pointer)?;
    Ok(process::get_current_thread())
}

/// ExReleaseFastMutexUnsafeAndLeaveCriticalRegion(PFAST_MUTEX): inverso
/// exato — ExReleaseFastMutexUnsafe + KeLeaveCriticalRegion.
pub fn release_unsafe_and_leave_critical_region(pointer: u64) -> Result<(), KernelError> {
    release_unsafe(pointer)?;
    critical_region::leave_critical()
}
