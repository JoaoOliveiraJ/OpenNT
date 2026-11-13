//! Esperas canceláveis do FsRtl — FsRtlCancellableWaitForSingleObject
//! (RVA 0x695d10) e FsRtlCancellableWaitForMultipleObjects (RVA 0x5fcb60)
//! do ntoskrnl 10.0.19045.
//!
//! Espera alertável em KernelMode (Executive). A cada STATUS_ALERTED o NT
//! confere, nesta ordem: thread terminando (ETHREAD.CrossThreadFlags bit 0
//! -> STATUS_THREAD_IS_TERMINATING), Irp->Cancel (-> STATUS_CANCELLED) e o
//! prazo — um timeout relativo é reescrito com o restante no LARGE_INTEGER
//! do chamador, um absoluto vencido vira STATUS_TIMEOUT — e volta a esperar.
//! O WaitBlockArray do chamador não é necessário: o dispatcher do OpenNT
//! mantém os próprios blocos.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Ethread, Irp, LargeInteger};
use crate::ntos::ke::{clock, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;

pub const STATUS_ALERTED: u32 = 0x0000_0101;
pub const STATUS_TIMEOUT: u32 = 0x0000_0102;
pub const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;
pub const STATUS_CANCELLED: u32 = 0xC000_0120;

const KERNEL_MODE: u8 = 0;
const WAIT_ALL: u32 = 0;

/// FsRtlCancellableWaitForMultipleObjects(Count, ObjectArray, WaitType,
/// Timeout, WaitBlockArray, Irp). `objects` é o vetor de PVOID (o
/// dispatcher recebe o endereço); `timeout` é o LARGE_INTEGER do chamador.
pub fn wait_for_multiple_objects(count: u32, objects: &Field<u64>, wait_type: u32, timeout: Option<&LargeInteger>, _wait_block_array: u64, irp: Option<&Irp>) -> u32 {
    let initial = timeout.map_or(0, |timeout| timeout.quad_part.get());
    let deadline = (initial < 0).then(|| clock::uptime_100ns().saturating_add(initial.unsigned_abs()));
    let absolute = (initial > 0).then_some(initial as u64);
    let timeout_pointer = timeout.map_or(0, |timeout| timeout.address());
    loop {
        let status = if count == 1 {
            dispatcher::wait_for_single_object(objects.get(), timeout_pointer, KERNEL_MODE, true)
        } else {
            dispatcher::wait_for_multiple_objects(count, objects.address(), wait_type, timeout_pointer, KERNEL_MODE, true)
        };
        if status != STATUS_ALERTED {
            return status;
        }
        // SAFETY: a thread corrente é um ETHREAD vivo.
        if unsafe { Ethread::at(process::get_current_thread()) }.terminated() != 0 {
            return STATUS_THREAD_IS_TERMINATING;
        }
        if irp.is_some_and(|irp| irp.cancel.get() != 0) {
            return STATUS_CANCELLED;
        }
        if let (Some(deadline), Some(timeout)) = (deadline, timeout) {
            let now = clock::uptime_100ns();
            if now >= deadline {
                return STATUS_TIMEOUT;
            }
            timeout.quad_part.set(-((deadline - now) as i64));
        } else if let Some(absolute) = absolute {
            if clock::system_time_100ns() >= absolute {
                return STATUS_TIMEOUT;
            }
        }
    }
}

/// FsRtlCancellableWaitForSingleObject(Object, Timeout, Irp) =
/// Multiple(1, &Object, WaitAll, Timeout, NULL, Irp).
pub fn wait_for_single_object(object: u64, timeout: Option<&LargeInteger>, irp: Option<&Irp>) -> u32 {
    let address = guest::alloc_bytes(Field::<u64>::SIZE);
    // SAFETY: célula recém-alocada (o `&Object` local do NT).
    let cell = unsafe { Field::<u64>::at(address) };
    cell.set(object);
    let status = wait_for_multiple_objects(1, cell, WAIT_ALL, timeout, 0, irp);
    guest::free_bytes(address);
    status
}
