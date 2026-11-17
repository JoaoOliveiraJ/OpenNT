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

// ---- SeSetSecurityAttributesToken / SeSetSecurityAttributesTokenEx ---------

/// TOKEN_ADJUST_DEFAULT.
const TOKEN_ADJUST_DEFAULT: u32 = 0x80;
/// TokenFlags: TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY (o bit 17 que o
/// SepInternalSetSecurityAttributesToken liga com o delink).
const TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY: u32 = 0x2_0000;

/// SepInternalSetSecurityAttributesToken(TokenHandle, AccessMode,
/// ForceDelink, Operations, Attributes) (ntoskrnl 19041 rva 0x595b2c):
/// referencia o token pelo handle com TOKEN_ADJUST_DEFAULT no AccessMode;
/// Operations NULL é STATUS_INVALID_PARAMETER. Attributes NULL só vale com
/// REPLACE_ALL (tira todos). Aplica as operações sob o lock do token
/// (`security_attributes::apply_operations`) e, no sucesso, liga
/// TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY se pedido (ForceDelink) ou se o
/// SepShouldSetDelinkFlags pede, e dá ao token um ModifiedId novo. Devolve
/// o NTSTATUS. As operações (ULONG) são uma por atributo.
pub fn set_security_attributes(handle: u64, access_mode: u8, force_delink: bool, operations: u64, attributes: u64) -> Result<u32, KernelError> {
    let mut reference = match token_reference::reference(handle, TOKEN_ADJUST_DEFAULT, access_mode, false)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let token = reference.token;
    let result = (|| -> u32 {
        if operations == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let Ok(first) = guest::try_read::<u32>(operations) else { return 0xC000_0005 };
        let replace_all = first == 1;
        let captured = if attributes == 0 {
            if !replace_all {
                return STATUS_INVALID_PARAMETER;
            }
            Vec::new()
        } else {
            match security_attributes::capture_for_set(attributes, replace_all) {
                Ok(captured) => captured,
                Err(status) => return status,
            }
        };
        let codes = match (0..captured.len().max(1) as u64).map(|index| guest::try_read::<u32>(operations + index * 4)).collect::<Result<Vec<u32>, _>>() {
            Ok(codes) => codes,
            Err(_) => return 0xC000_0005,
        };
        let delink = force_delink || security_attributes::should_set_delink_flags(&codes, &captured);
        let status = tokens::update(token, |record| match security_attributes::apply_operations(&record.security_attributes, captured, &codes) {
            Ok(updated) => {
                record.security_attributes = updated;
                0
            }
            Err(status) => status,
        })
        .unwrap_or(STATUS_INVALID_PARAMETER);
        if status == 0 {
            if delink {
                tokens::body(token).token_flags.atomic().fetch_or(TOKEN_DO_NOT_USE_GLOBAL_ATTRIBS_FOR_QUERY, core::sync::atomic::Ordering::SeqCst);
            }
            tokens::new_modified_id(token);
        }
        status
    })();
    reference.release()?;
    Ok(result)
}

/// SeSetSecurityAttributesTokenEx(TokenHandle, AccessMode, Reserved,
/// Singleton, Operations, Attributes, SingletonSet*) (rva 0x5974c0):
/// Reserved não nulo é STATUS_INVALID_PARAMETER. O caminho de atributo
/// único (Singleton com SepTokenSingletonAttributesConfig & 3 == 3) não
/// existe no OpenNT, que não liga essa configuração: *SingletonSet = FALSE
/// e o SepInternalSetSecurityAttributesToken com ForceDelink.
pub fn set_security_attributes_ex(handle: u64, access_mode: u8, reserved: u64, _singleton: bool, operations: u64, attributes: u64, singleton_set: &crate::ntos::inc::types::Field<u8>) -> Result<u32, KernelError> {
    if reserved != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    singleton_set.set(0);
    set_security_attributes(handle, access_mode, true, operations, attributes)
}
