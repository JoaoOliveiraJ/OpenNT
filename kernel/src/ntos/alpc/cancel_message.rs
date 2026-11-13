//! Captura de Nt/ZwAlpcCancelMessage.
//!
//! A operação do transporte recebe só valores capturados e uma porta já
//! referenciada, na ordem do kernel original.

use alloc::sync::Arc;

use crate::ntos::alpc::message::buffer as message_buffer;
use super::port_reference;
use crate::ntos::ke::critical_region;
use crate::ntos::ob::objects::port::Port;
use crate::rtl::KernelError;
use core::mem::offset_of;

use crate::ntos::inc::types::extra_ob_alpc::AlpcContextAttr32;
use crate::ntos::inc::types::AlpcContextAttr;

/// ALPC_CONTEXT_ATTR capturado.
#[derive(Clone, Copy, Debug)]
pub struct Selection {
    pub identifier: u32,
    pub callback: u32,
    pub message_context: u64,
}

pub fn cancel(port_handle: u64, flags: u32, context: u64, mode: u8, perform: impl FnOnce(&Arc<Port>, Selection, u32) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<u32, KernelError> {
        if flags & 0xFFFF_FFF0 != 0 {
            return Ok(0xC000_000D);
        }
        if mode != 0 && context & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if mode != 0 && !message_buffer::accessible(context, 1, mode, false) {
            return Ok(0xC000_0005);
        }
        // O bit 4 seleciona o layout compacto só em Nt/UserMode; Zw sempre
        // lê o layout x64, mesmo com PreviousMode=UserMode.
        let compact = mode != 0 && flags & 4 != 0;
        let (identifier_offset, callback_offset, context_offset) = if compact {
            (offset_of!(AlpcContextAttr32, message_id), offset_of!(AlpcContextAttr32, callback_id), offset_of!(AlpcContextAttr32, message_context))
        } else {
            (offset_of!(AlpcContextAttr, message_id), offset_of!(AlpcContextAttr, callback_id), offset_of!(AlpcContextAttr, message_context))
        };
        if !message_buffer::accessible(context + identifier_offset as u64, 4, mode, false) {
            return Ok(0xC000_0005);
        }
        let identifier = match message_buffer::read_field::<u32>(context, identifier_offset) {
            Ok(value) => value,
            Err(status) => return Ok(status),
        };
        if !message_buffer::accessible(context + callback_offset as u64, 4, mode, false) {
            return Ok(0xC000_0005);
        }
        let callback = match message_buffer::read_field::<u32>(context, callback_offset) {
            Ok(value) => value,
            Err(status) => return Ok(status),
        };
        if !message_buffer::accessible(context + context_offset as u64, if compact { 4 } else { 8 }, mode, false) {
            return Ok(0xC000_0005);
        }
        let message_context = if compact { message_buffer::read_field::<u32>(context, context_offset).map(|value| value as u64) } else { message_buffer::read_field::<u64>(context, context_offset) };
        let message_context = match message_context {
            Ok(value) => value,
            Err(status) => return Ok(status),
        };
        if identifier == 0 {
            return Ok(0xC000_0109);
        }
        let mut reference = match port_reference::reference(port_handle, 1, mode)? {
            Ok(reference) => reference,
            Err(status) => return Ok(status),
        };
        let port = reference.port.clone();
        let result = port.run(|| perform(&port, Selection { identifier, callback, message_context }, flags));
        let _ = reference.release();
        result
    })();
    let _ = critical_region::leave_critical();
    result
}
