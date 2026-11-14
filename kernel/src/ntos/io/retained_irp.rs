//! Pedidos síncronos do FsRtl com posse retida.
//!
//! A rotina de conclusão sinaliza o evento privado e devolve
//! STATUS_MORE_PROCESSING_REQUIRED: só o chamador solta o IRP, depois da
//! conclusão ou do cancelamento.

use core::sync::atomic::{AtomicU64, Ordering};

use super::{cancel, io_manager};
use crate::ntos::ke::{context_switch, dispatcher};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Ethread, IoStackLocation, NtStruct};

/// SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL.
const INVOKE_ALWAYS: u8 = 0xE0;

static COMPLETION: AtomicU64 = AtomicU64::new(0);

/// KeSetEvent(context, 0, FALSE) e STATUS_MORE_PROCESSING_REQUIRED.
pub fn completion_routine() -> Result<u64, KernelError> {
    let current = COMPLETION.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let code = guest::alloc_bytes(48);
    if code == 0 {
        return Ok(0);
    }
    let set_event = crate::ntos::init::exports::export_module()?.exports.exports.get("KeSetEvent").copied().ok_or_else(|| KernelError::new("KeSetEvent unavailable"))?;
    let mut bytes = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0x4C, 0x89, 0xC1, 0x31, 0xD2, 0x45, 0x31, 0xC0, 0x48, 0xB8];
    bytes.extend_from_slice(&set_event.to_le_bytes());
    bytes.extend_from_slice(&[0xFF, 0xD0, 0xB8, 0x16, 0, 0, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
    guest::write_bytes(code, &bytes);
    match COMPLETION.compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(code),
        Err(existing) => {
            guest::free_bytes(code);
            Ok(existing)
        }
    }
}

/// Envia o IRP com a rotina de conclusão no evento (que leva 16 bytes de
/// argumentos de cancelamento pré-alocados). `None` = concluído; senão o
/// status da recusa síncrona.
pub fn dispatch(device: u64, irp: u64, stack: u64, event: u64, routine: u64) -> Result<Option<u32>, KernelError> {
    // SAFETY: a próxima stack location do IRP recém-construído pelo chamador.
    let location = unsafe { IoStackLocation::at(stack) };
    location.completion_routine.set(routine);
    location.context.set(event);
    location.control.set(INVOKE_ALWAYS);
    let status = io_manager::iof_call_driver(device, irp) as u32;
    if status != 0x103 && dispatcher::read_state(event) == 0 {
        return Ok(Some(if status & 0x8000_0000 != 0 { status } else { 0xC000_0010 }));
    }
    if status == 0x103 {
        // A espera do evento da conclusão: bloqueia numa syscall, gira o pump
        // fora dela. A thread terminada no meio cancela o IRP e espera a
        // conclusão do cancelamento.
        let thread = process::get_current_thread();
        // SAFETY: a thread corrente.
        let terminated = || unsafe { Ethread::at(thread) }.terminated() != 0;
        let mut poll = || dispatcher::try_wait_objects(&[event], 1).or_else(|| terminated().then_some(context_switch::STATUS_THREAD_IS_TERMINATING));
        if context_switch::wait_until(&mut poll, dispatcher::pump_kernel) == context_switch::STATUS_THREAD_IS_TERMINATING {
            cancel::irp(irp)?;
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
    }
    Ok(None)
}
