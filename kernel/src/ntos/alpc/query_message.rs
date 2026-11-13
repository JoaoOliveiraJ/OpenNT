//! Nt/ZwAlpcQueryInformationMessage.
//!
//! Captura, resolução e consulta compartilham os objetos do transporte;
//! cada classe conserva sua ordem de escrita.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::message::identity::{self as message_identity, Identity};
use super::port_reference::{self, PortReference};
use crate::ntos::alpc::message::{buffer as message_buffer, handles as message_handles, security as message_security};
use crate::ntos::ke::critical_region;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::se::token::{statistics as token_statistics, tokens};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const ACCESS_VIOLATION: u32 = 0xC000_0005;
const INVALID_PARAMETER: u32 = 0xC000_000D;
const BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// WOW64 usa os campos de 32 bits em +16/+20; o restante do PORT_MESSAGE
/// não é lido (pode terminar numa página inacessível).
fn capture_selection(message: u64, mode: u8) -> Result<(u32, u32), u32> {
    if mode != 0 && message & 3 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(message, 1, mode, false) || !message_buffer::accessible(message + 4, 2, mode, false) {
        return Err(ACCESS_VIOLATION);
    }
    let compact = guest::read16(message + 4) & 0x1000 != 0;
    let identifier = message + if compact { 16 } else { 24 };
    let callback = message + if compact { 20 } else { 32 };
    if !message_buffer::accessible(identifier, 4, mode, false) || !message_buffer::accessible(callback, 4, mode, false) {
        return Err(ACCESS_VIOLATION);
    }
    Ok((guest::read32(identifier), guest::read32(callback)))
}

fn write_length(address: u64, length: u32, mode: u8) -> u32 {
    if address == 0 {
        return 0;
    }
    if !message_buffer::writable(address, 4, mode) {
        return ACCESS_VIOLATION;
    }
    guest::write32(address, length);
    0
}

fn write_bytes(address: u64, bytes: &[u8], mode: u8) -> u32 {
    if !message_buffer::writable(address, bytes.len() as u64, mode) {
        return ACCESS_VIOLATION;
    }
    for (index, &byte) in bytes.iter().enumerate() {
        guest::write8(address + index as u64, byte);
    }
    0
}

fn query_token(port: &Arc<Port>, identity: &Identity, class: u32, output: u64, length: u32, returned: u64, mode: u8) -> Result<u32, KernelError> {
    // ModifiedId informa oito bytes antes mesmo de tentar selecionar o token.
    if class == 1 && length < 8 {
        let status = write_length(returned, 8, mode);
        return Ok(if status != 0 { status } else { BUFFER_TOO_SMALL });
    }
    let selected = match message_security::select(port, identity)? {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    let bytes: Result<Vec<u8>, KernelError> = if class == 0 { Ok(tokens::with(selected.token, |token| token.user.clone()).unwrap_or_default()) } else { token_statistics::encode(selected.token).map(|statistics| statistics[48..56].to_vec()) };
    selected.release();
    let bytes = bytes?;
    let status = write_length(returned, bytes.len() as u32, mode);
    if status != 0 {
        return Ok(status);
    }
    if (length as usize) < bytes.len() {
        return Ok(BUFFER_TOO_SMALL);
    }
    // ReturnLength precede a carga, mesmo quando as saídas se sobrepõem.
    Ok(write_bytes(output, &bytes, mode))
}

fn query_handle(port: &Arc<Port>, identity: &Identity, output: u64, length: u32, returned: u64, mode: u8) -> Result<u32, KernelError> {
    if length != 20 {
        return Ok(0xC000_0004);
    }
    if !message_buffer::accessible(output, 4, mode, false) {
        return Ok(ACCESS_VIOLATION);
    }
    let index = guest::read32(output);
    let Some(handles) = identity.with(|state| state.handles.clone()) else { return Ok(0xC000_0008) };
    let duplicated = {
        let entries = handles.entries.lock();
        let Some(entry) = entries.get(index as usize) else { return Ok(0xC000_0008) };
        message_handles::duplicate(entry, port, mode)?
    };
    let duplicated = match duplicated {
        Ok(duplicated) => duplicated,
        Err(status) => return Ok(status),
    };
    let mut bytes = [0u8; 20];
    bytes[0..4].copy_from_slice(&index.to_le_bytes());
    bytes[8..12].copy_from_slice(&duplicated.handle.to_le_bytes());
    bytes[12..16].copy_from_slice(&duplicated.object_type.to_le_bytes());
    bytes[16..20].copy_from_slice(&duplicated.granted.to_le_bytes());
    // O handle já foi criado: o resultado é conservado mesmo se a
    // cópia final falha, sem fechar um objeto já publicado.
    if write_bytes(output, &bytes, mode) == 0 {
        write_length(returned, 20, mode);
    }
    Ok(0)
}

#[allow(clippy::too_many_arguments)]
pub fn query(handle: u64, message: u64, class: u32, output: u64, length: u32, returned: u64, mode: u8, before_lookup: Option<&dyn Fn()>) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let mut reference: Option<PortReference> = None;
    let mut held: Option<Arc<Identity>> = None;
    let result = (|| -> Result<u32, KernelError> {
        let (identifier, callback) = match capture_selection(message, mode) {
            Ok(selection) => selection,
            Err(status) => return Ok(status),
        };
        if mode != 0 {
            if length != 0 && output & 3 != 0 {
                return Ok(0x8000_0002);
            }
            if length != 0 && !message_buffer::writable(output, length as u64, mode) {
                return Ok(ACCESS_VIOLATION);
            }
            if returned != 0 && !message_buffer::writable(returned, 4, mode) {
                return Ok(ACCESS_VIOLATION);
            }
        }
        if identifier == 0 {
            return Ok(INVALID_PARAMETER);
        }
        let port = match port_reference::reference(handle, 0x2_0000, mode)? {
            Ok(port) => {
                let shared = port.port.clone();
                reference = Some(port);
                shared
            }
            Err(status) => return Ok(status),
        };
        port.run(|| {
            if let Some(before_lookup) = before_lookup {
                before_lookup();
            }
            let resolved = match message_identity::resolve(&port, identifier, callback) {
                Ok(resolved) => resolved,
                Err(status) => return Ok(status),
            };
            let identity = message_identity::reference(&resolved)?;
            held = Some(identity.clone());
            let (canceled, disconnected, queued, direct) = identity.with(|state| (state.canceled, state.disconnected, state.queued, state.direct));
            if canceled || disconnected || identity.port.closed() {
                return Ok(0xC000_0703);
            }
            match class {
                0 | 1 => query_token(&port, &identity, class, output, length, returned, mode),
                2 => {
                    if output != 0 || length != 0 || returned != 0 {
                        return Ok(INVALID_PARAMETER);
                    }
                    Ok(if queued && direct { 0 } else { 0x103 })
                }
                3 => query_handle(&port, &identity, output, length, returned, mode),
                _ => Ok(INVALID_PARAMETER),
            }
        })
    })();
    if let Some(identity) = held {
        let _ = message_identity::dereference(&identity, true);
    }
    if let Some(mut reference) = reference {
        let _ = reference.release();
    }
    let _ = critical_region::leave_critical();
    result
}
