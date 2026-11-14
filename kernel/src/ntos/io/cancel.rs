//! Spin lock de cancelamento compartilhado e IoCancelIrp.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{IoStackLocation, Irp, NtStruct};
use crate::ntos::ke::irql;
use crate::rtl::KernelError;

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
    let previous = acquire()?;
    // SAFETY: PKIRQL do chamador de modo kernel.
    unsafe { Field::<u8>::at(irql_output) }.set(previous);
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
    // SAFETY: IRP vivo do chamador.
    let irp = unsafe { Irp::at(pointer) };
    let previous = acquire()?;
    irp.cancel.set(1);
    let routine = irp.cancel_routine.atomic().swap(0, Ordering::SeqCst);
    if routine == 0 {
        release(previous)?;
        return Ok(0);
    }
    // SAFETY: CurrentStackLocation de um IRP vivo.
    let device = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }.device_object.get();
    irp.cancel_irql.set(previous);
    native_call::call(routine, &[device, pointer]);
    Ok(1)
}

/// IoSetCancelRoutine (InterlockedExchangePointer): devolve a rotina anterior.
pub fn set_cancel_routine(pointer: u64, routine: u64) -> u64 {
    // SAFETY: IRP vivo do chamador.
    unsafe { Irp::at(pointer) }.cancel_routine.atomic().swap(routine, Ordering::SeqCst)
}

/// ZwCancelIoFile(FileHandle, IoStatusBlock): cancela os pedidos de E/S da
/// thread corrente para o arquivo do handle — as IRPs da IrpList dela cujo
/// OriginalFileObject é o FILE_OBJECT do handle, pelo IoCancelIrp — e grava
/// STATUS_SUCCESS no IOSB, como o NtCancelIoFile. Handle de arquivo
/// desconhecido dá STATUS_INVALID_HANDLE. Devolve o NTSTATUS e quantas IRPs
/// foram canceladas.
pub fn cancel_io_file(handle: u64, io_status: u64) -> Result<(u32, usize), KernelError> {
    use crate::ntos::inc::types::{Irp, NtStruct};
    let file = crate::ntos::io::file::zw::file_object_of_handle(handle);
    if file == 0 {
        return Ok((0xC000_0008, 0));
    }
    let thread = crate::ntos::ps::process::get_current_thread();
    let mut cancelled = 0;
    for request in crate::ntos::io::threads::thread_requests::of_thread(thread)? {
        // SAFETY: IRP viva da lista da thread corrente.
        if unsafe { Irp::at(request) }.tail.overlay.original_file_object.get() == file {
            irp(request)?;
            cancelled += 1;
        }
    }
    crate::ntos::io::file::zw::write_io_status(io_status, 0, 0);
    Ok((0, cancelled))
}
