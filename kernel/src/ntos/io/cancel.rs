//! Spin lock de cancelamento compartilhado e IoCancelIrp.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::ke::irql;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{io_stack_location as stack, irp};

static HELD: AtomicBool = AtomicBool::new(false);

/// IoAcquireCancelSpinLock: eleva a DISPATCH_LEVEL e devolve o IRQL anterior.
/// A posse é tomada numa troca atômica; com o lock já tomado (o código de
/// driver roda no BSP, então é reentrância) a aquisição falha.
pub fn acquire() -> Result<u8, KernelError> {
    if HELD.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        return Err(KernelError::new("Recursive acquisition of the cancel spin lock"));
    }
    Ok(irql::raise_irql(irql::DISPATCH_LEVEL))
}

/// IoAcquireCancelSpinLock(Irql): o IRQL anterior vai para *Irql.
pub fn acquire_into(irql_output: u64) -> Result<(), KernelError> {
    guest::write8(irql_output, acquire()?);
    Ok(())
}

/// IoReleaseCancelSpinLock.
pub fn release(previous: u8) -> Result<(), KernelError> {
    if HELD.compare_exchange(true, false, Ordering::Release, Ordering::Relaxed).is_err() {
        return Err(KernelError::new("Cancel spin lock is not held"));
    }
    irql::lower_irql(previous as u64);
    Ok(())
}

pub fn is_held() -> bool {
    HELD.load(Ordering::Acquire)
}

/// IoCancelIrp: marca Cancel e toma a rotina com InterlockedExchangePointer
/// (o IoSetCancelRoutine inline dos drivers disputa a mesma célula); havendo
/// rotina, a entrega com o lock retido — a rotina do driver chama
/// IoReleaseCancelSpinLock(Irp->CancelIrql) antes de completar o IRP.
/// Devolve 1 quando uma rotina foi chamada.
pub fn irp(pointer: u64) -> Result<u8, KernelError> {
    let previous = acquire()?;
    guest::write8(pointer + irp::CANCEL, 1);
    let routine = guest::atomic_u64(pointer + irp::CANCEL_ROUTINE).swap(0, Ordering::SeqCst);
    if routine == 0 {
        release(previous)?;
        return Ok(0);
    }
    let location = guest::read64(pointer + irp::CURRENT_STACK_LOCATION);
    let device = guest::read64(location + stack::DEVICE_OBJECT);
    guest::write8(pointer + irp::CANCEL_IRQL, previous);
    native_call::call(routine, &[device, pointer]);
    Ok(1)
}

/// IoSetCancelRoutine (InterlockedExchangePointer): devolve a rotina anterior.
pub fn set_cancel_routine(pointer: u64, routine: u64) -> u64 {
    guest::atomic_u64(pointer + irp::CANCEL_ROUTINE).swap(routine, Ordering::SeqCst)
}
