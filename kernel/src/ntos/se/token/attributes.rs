//! ZwQuerySecurityAttributesToken: NtQuerySecurityAttributesToken com o modo
//! anterior KernelMode (o serviço 0x15b pelo KiServiceInternal).
//!
//! ntoskrnl 10.0.19041: NtQuerySecurityAttributesToken 0x6011c0,
//! SepCaptureUnicodeStringArray 0x601510. Em KernelMode nada é sondado nem
//! copiado: Length zero exige Buffer nulo (a consulta de tamanho) e Length
//! não nulo exige Buffer; Attributes e NumberOfAttributes são nulos juntos.
//! O token é referenciado com TOKEN_QUERY (handles de kernel e os
//! pseudo-handles de token valem) e a seleção e a codificação são as do
//! serviço de usuário (`se::security_attributes`): um nome ausente devolve
//! STATUS_NOT_FOUND, buffer curto STATUS_BUFFER_TOO_SMALL, e ReturnLength
//! recebe o tamanho necessário.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::security_attributes;
use crate::ntos::se::token::{reference as token_reference, tokens};
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const TOKEN_QUERY: u32 = 0x8;
const KERNEL_MODE: u8 = 0;

/// ZwQuerySecurityAttributesToken(TokenHandle, Attributes, NumberOfAttributes,
/// Buffer, Length, ReturnLength) -> NTSTATUS.
pub fn query(handle: u64, attributes: u64, count: u32, buffer: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if (length == 0 && buffer != 0) || (length != 0 && buffer == 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if (attributes == 0) != (count == 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut reference = match token_reference::reference(handle, TOKEN_QUERY, KERNEL_MODE, true)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let token = reference.token;
    let result = (|| -> Result<u32, KernelError> {
        let report = |value: u32| {
            if returned != 0 {
                guest::write32(returned, value);
            }
        };
        let mut names: Vec<String> = Vec::new();
        for index in 0..count as u64 {
            // SAFETY: UNICODE_STRING Attributes[NumberOfAttributes] do chamador de modo kernel.
            let name = unsafe { UnicodeString::at(attributes + index * UnicodeString::SIZE) };
            let size = name.length.get() as usize;
            if size == 0 {
                report(0);
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let units: Vec<u16> = guest::read_bytes(name.buffer.get(), size & !1).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            names.push(String::from_utf16_lossy(&units));
        }
        let all = tokens::with(token, |record| record.security_attributes.clone()).unwrap_or_default();
        let Some(selected) = security_attributes::select(&all, if count != 0 { Some(&names) } else { None })? else {
            report(0);
            return Ok(STATUS_NOT_FOUND);
        };
        let bytes = match security_attributes::encode(&selected, buffer) {
            Ok(bytes) => bytes,
            Err(status) => return Ok(status),
        };
        report(bytes.len() as u32);
        if (length as usize) < bytes.len() {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        guest::write_bytes(buffer, &bytes);
        Ok(0)
    })();
    reference.release()?;
    result
}
