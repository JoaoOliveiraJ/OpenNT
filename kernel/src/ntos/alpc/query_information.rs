//! Consultas da porta usadas pelo MSRPC.
//!
//! Estado básico da porta e SID do processo conectado; Nt e Zw
//! compartilham objetos e serialização, com a sondagem de cada modo.

use alloc::sync::Arc;

use crate::ntos::alpc::message::buffer as message_buffer;
use super::port_reference::{self, PortReference};
use crate::ntos::ke::critical_region;
use crate::ntos::ob::objects::port::{self as port_objects, Port};
use crate::ntos::ps::process;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;
use crate::ntos::alpc::message::buffer::{read_block, read_field, write_field};
use crate::ntos::inc::types::{AlpcBasicInformation, NtStruct, Sid};
use crate::ntos::mm::guest_memory as guest;
use core::mem::offset_of;

const ACCESS_VIOLATION: u32 = 0xC000_0005;
const INVALID_PARAMETER: u32 = 0xC000_000D;
const USER_LIMIT: u64 = 0x7FFF_FFFF_0000;

/// ReturnLength não exige alinhamento. Na classe 0 vem depois dos campos;
/// na classe 3 recebe zero antes da captura do SID.
fn write_length(address: u64, value: u32, mode: u8) -> u32 {
    if address == 0 {
        return 0;
    }
    if !message_buffer::writable(address, 4, mode) {
        return ACCESS_VIOLATION;
    }
    match write_field::<u32>(address, 0, value) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

fn query_basic(port: Option<&Arc<Port>>, output: u64, length: u32, returned: u64, mode: u8) -> u32 {
    let Some(port) = port else { return INVALID_PARAMETER };
    let size = AlpcBasicInformation::SIZE as u32;
    if length < size {
        let status = write_length(returned, size, mode);
        return if status != 0 { status } else { 0xC000_0004 };
    }
    let (flags, context) = port.with(|state| (state.port_flags, state.port_context));
    // Escritas separadas mantêm os campos anteriores quando uma página
    // seguinte falha.
    for (offset, width, value) in [
        (offset_of!(AlpcBasicInformation, flags), 4u64, (flags & 0x3FF_0000) as u64),
        (offset_of!(AlpcBasicInformation, sequence_no), 4, port.sequence() as u64),
        (offset_of!(AlpcBasicInformation, port_context), 8, context),
    ] {
        if !message_buffer::writable(output + offset as u64, width, mode) {
            return ACCESS_VIOLATION;
        }
        let written = if width == 8 { write_field::<u64>(output, offset, value) } else { write_field::<u32>(output, offset, value as u32) };
        if let Err(status) = written {
            return status;
        }
    }
    write_length(returned, size, mode)
}

fn query_connected_sid(port: Option<&Arc<Port>>, input: u64, returned: u64, mode: u8) -> Result<u32, KernelError> {
    let Some(port) = port else { return Ok(INVALID_PARAMETER) };
    let status = write_length(returned, 0, mode);
    if status != 0 {
        return Ok(status);
    }
    let mut captured = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        let mut input = input;
        if mode != 0 {
            // SeCaptureSid lê a contagem antes do alinhamento, aloca a cópia
            // e só então valida revisão e contagem; Length é ignorado.
            let count_offset = offset_of!(Sid, sub_authority_count);
            if !message_buffer::accessible(input + count_offset as u64, 1, mode, false) {
                return Ok(ACCESS_VIOLATION);
            }
            let count = match read_field::<u8>(input, count_offset) {
                Ok(count) => count,
                Err(status) => return Ok(status),
            };
            // Cabeçalho mais SubAuthority[count].
            let length = offset_of!(Sid, sub_authority) as u64 + count as u64 * 4;
            if input & 3 != 0 {
                return Ok(0x8000_0002);
            }
            if input + length > USER_LIMIT {
                return Ok(ACCESS_VIOLATION);
            }
            captured = guest::alloc_bytes(length);
            if captured == 0 {
                return Ok(0xC000_009A);
            }
            if !message_buffer::accessible(input, length, mode, false) {
                return Ok(ACCESS_VIOLATION);
            }
            match read_block(input, length) {
                Ok(bytes) => guest::write_bytes(captured, &bytes),
                Err(status) => return Ok(status),
            }
            // A cópia conserva a contagem lida primeiro (sem dupla leitura).
            // SAFETY: cópia alocada acima com `length` bytes.
            let copy = unsafe { Sid::at(captured) };
            copy.sub_authority_count.set(count);
            if copy.revision.get() & 15 != 1 || count > 15 {
                return Ok(0xC000_0078);
            }
            input = captured;
        }
        let Some(connected) = port_objects::reference_connected_process(port)? else { return Ok(0xC000_0037) };
        let outcome = (|| -> Result<u32, KernelError> {
            let Some(token) = process::get_primary_token(connected.process) else { return Err(KernelError::new("Connected ALPC process has no primary token")) };
            tokens::retain(token)?;
            let user = tokens::with(token, |token| token.user.clone()).unwrap_or_default();
            let compared = (|| {
                // KernelMode usa o SID original; a comparação lê revisão e
                // contagem antes da cauda.
                if captured == 0 && !message_buffer::accessible(input, 2, mode, false) {
                    return ACCESS_VIOLATION;
                }
                if user.len() < 2 {
                    return 0xC000_02A0;
                }
                let header = (read_field::<u8>(input, offset_of!(Sid, revision)), read_field::<u8>(input, offset_of!(Sid, sub_authority_count)));
                let (revision, count) = match header {
                    (Ok(revision), Ok(count)) => (revision, count),
                    _ => return ACCESS_VIOLATION,
                };
                if revision != user[0] || count != user[1] {
                    return 0xC000_02A0;
                }
                // Byte a byte: em KernelMode a primeira diferença encerra a
                // comparação antes de tocar o resto do SID original.
                for (index, &byte) in user.iter().enumerate().skip(2) {
                    let address = input + index as u64;
                    if captured == 0 && !message_buffer::accessible(address, 1, mode, false) {
                        return ACCESS_VIOLATION;
                    }
                    match read_field::<u8>(address, 0) {
                        Ok(value) if value == byte => {}
                        Ok(_) => return 0xC000_02A0,
                        Err(status) => return status,
                    }
                }
                0
            })();
            let _ = tokens::release(token);
            Ok(compared)
        })();
        connected.release()?;
        outcome
    })();
    if captured != 0 {
        guest::free_bytes(captured);
    }
    result
}

pub fn query(handle: u64, class: u32, output: u64, length: u32, returned: u64, mode: u8) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let mut reference: Option<PortReference> = None;
    let result = (|| -> Result<u32, KernelError> {
        if output == 0 {
            return Ok(INVALID_PARAMETER);
        }
        if mode != 0 {
            if class != 3 && class != 11 && length != 0 {
                if output & 3 != 0 {
                    return Ok(0x8000_0002);
                }
                if output + length as u64 > USER_LIMIT || !message_buffer::writable(output, length as u64, mode) {
                    return Ok(ACCESS_VIOLATION);
                }
            }
            if returned != 0 && !message_buffer::writable(returned, 4, mode) {
                return Ok(ACCESS_VIOLATION);
            }
        }
        if handle != 0 {
            match port_reference::reference(handle, 0x2_0000, mode)? {
                Ok(held) => reference = Some(held),
                Err(status) => return Ok(status),
            }
        }
        let port = reference.as_ref().map(|reference| reference.port.clone());
        match class {
            0 => Ok(query_basic(port.as_ref(), output, length, returned, mode)),
            3 => query_connected_sid(port.as_ref(), output, returned, mode),
            // Servidor, espera de referências e sessão exigem operações próprias.
            4 | 11 | 12 => Ok(0xC000_00BB),
            _ => Ok(INVALID_PARAMETER),
        }
    })();
    if let Some(mut reference) = reference {
        let _ = reference.release();
    }
    let _ = critical_region::leave_critical();
    result
}
