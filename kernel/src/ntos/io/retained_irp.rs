//! Pedidos síncronos do FsRtl com posse retida.
//!
//! A rotina de conclusão sinaliza o evento privado e devolve
//! STATUS_MORE_PROCESSING_REQUIRED: só o chamador solta o IRP, depois da
//! conclusão ou do cancelamento.

use super::{cancel, io_manager};
use crate::ntos::ke::{context_switch, dispatcher};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::inc::types::{Ethread, IoStackLocation, NtStruct};

/// SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL.
const INVOKE_ALWAYS: u8 = 0xE0;

/// A rotina de conclusão dos IRPs retidos (IO_COMPLETION_ROUTINE): KeSetEvent
/// (Context, 0, FALSE) e STATUS_MORE_PROCESSING_REQUIRED. Uma função da
/// imagem do kernel, chamada pela ABI MS x64 como as dos drivers.
extern "win64" fn signal_completion(_device: u64, _irp: u64, context: u64) -> u32 {
    dispatcher::set_event(context);
    0xC000_0016
}

/// O endereço de [`signal_completion`].
pub fn completion_routine() -> Result<u64, KernelError> {
    Ok(signal_completion as extern "win64" fn(u64, u64, u64) -> u32 as usize as u64)
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
