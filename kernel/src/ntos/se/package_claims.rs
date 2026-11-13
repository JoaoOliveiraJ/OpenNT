//! RtlQueryPackageClaims do kernel.
//!
//! Recebe o corpo de um token, não um handle; nomes, claims e bits de
//! presença vêm só dos atributos de segurança dele.

use crate::ntos::inc::types::{Guid, NtStruct, TokenSecurityAttributeV1, TokenSecurityAttributesInformation, UnicodeString};
use crate::ntos::rtl::unicode;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::security;
use super::out;

/// Área privada desta chamada (substitui os locais da pilha nativa):
/// TOKEN_SECURITY_ATTRIBUTES_INFORMATION em +0, ReturnLength em +0x330, os
/// quatro UNICODE_STRING de filtro em +0x340 e os textos em +0x380.
const ATTRIBUTE_BUFFER_BYTES: u32 = 0x330;
const RETURNED_OFFSET: u64 = 0x330;
const FILTERS_OFFSET: u64 = 0x340;
const FILTER_TEXT_OFFSET: u64 = 0x380;
const SCRATCH_BYTES: u64 = 0x400;
const ATTRIBUTE_NAMES: [&str; 4] = ["WIN://SYSAPPID", "WIN://PKG", "WP://SKUID", "XBOX://LI"];
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// UNICODE_STRING dos filtros numa região privada desta chamada.
fn initialize_filters(scratch: u64) {
    let mut text_pointer = scratch + FILTER_TEXT_OFFSET;
    // SAFETY: os quatro descritores ficam na área privada desta chamada.
    let filters = unsafe { UnicodeString::array_at(scratch + FILTERS_OFFSET, ATTRIBUTE_NAMES.len()) };
    for (descriptor, text) in filters.iter().zip(ATTRIBUTE_NAMES) {
        descriptor.length.set(text.len() as u16 * 2);
        descriptor.maximum_length.set(text.len() as u16 * 2 + 2);
        descriptor.buffer.set(text_pointer);
        let bytes: alloc::vec::Vec<u8> = text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect();
        guest::write_bytes(text_pointer, &bytes);
        text_pointer += bytes.len() as u64;
    }
}

/// Parte usada de RtlStringCbPrintfExW (%wZ, STRSAFE_NO_TRUNCATION): no erro
/// o formato pode deixar caracteres copiados, NUL no fim disponível e NUL no
/// início; o tamanho só muda no sucesso. Devolve (status, bytes).
fn copy_counted_name(descriptor: u64, destination: u64, capacity_bytes: u64) -> (u32, u64) {
    let character_capacity = capacity_bytes >> 1;
    if character_capacity == 0 || character_capacity > 0x7FFF_FFFF {
        if character_capacity != 0 {
            guest::write16(destination, 0);
        }
        return (STATUS_INVALID_PARAMETER, 0);
    }
    // SAFETY: valor UNICODE_STRING do atributo devolvido pela consulta.
    let descriptor = unsafe { UnicodeString::at(descriptor) };
    let source = descriptor.buffer.get();
    let (count, invalid) = if source == 0 {
        // %wZ imprime "(null)" para Buffer NULL.
        (6u64, false)
    } else {
        let length = descriptor.length.get();
        let maximum = descriptor.maximum_length.get();
        ((length >> 1) as u64, maximum < length || length & 1 != 0 || source & 1 != 0)
    };
    let limit = character_capacity - 1;
    let copied = if invalid { 0 } else { count.min(limit) };
    if copied != 0 {
        let text = if source != 0 { guest::read_bytes(source, copied as usize * 2) } else { b"(\0n\0u\0l\0l\0)\0"[..copied as usize * 2].to_vec() };
        guest::write_bytes(destination, &text);
    }
    if invalid || count > limit {
        guest::write16(destination + limit * 2, 0);
        guest::write16(destination, 0);
        return (STATUS_BUFFER_OVERFLOW, 0);
    }
    guest::write16(destination + count * 2, 0);
    (0, (count + 1) * 2)
}

/// PKG é opcional: na ausência a consulta repete só SYSAPPID. As sondagens
/// SKUID/LI pedem tamanho zero e não substituem o status principal.
fn query_identity(token: u64, scratch: u64, claim: u64, presence: u64) -> Result<u32, KernelError> {
    let filters = scratch + FILTERS_OFFSET;
    let returned = scratch + RETURNED_OFFSET;
    let requested = if claim != 0 || presence != 0 { 2 } else { 1 };
    let mut has_package_claim = true;
    if presence != 0 {
        out::<u64>(presence).set(0);
    }
    let mut status = security::query_attributes(token, filters, requested, scratch, ATTRIBUTE_BUFFER_BYTES, returned)?;
    if status == STATUS_NOT_FOUND && requested == 2 {
        has_package_claim = false;
        status = security::query_attributes(token, filters, 1, scratch, ATTRIBUTE_BUFFER_BYTES, returned)?;
    }
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    if information(scratch).attribute_count.get() == 0 {
        return Ok(STATUS_NOT_FOUND);
    }
    if claim != 0 {
        let mut value = 0;
        if has_package_claim {
            // WIN://PKG é o segundo atributo devolvido; o valor é um ULONG64.
            let values = attributes(scratch, 2)[1].values.get();
            value = out::<u64>(values).get();
        }
        out::<u64>(claim).set(value);
    }
    if presence != 0 {
        let presence = out::<u64>(presence);
        presence.set(presence.get() | if has_package_claim { 3 } else { 1 });
        for index in 2..ATTRIBUTE_NAMES.len() as u64 {
            let probe = security::query_attributes(token, filters + index * UnicodeString::SIZE, 1, 0, 0, returned)?;
            if probe == STATUS_BUFFER_TOO_SMALL {
                presence.set(presence.get() | 1 << index);
            }
        }
    }
    Ok(0)
}

/// TOKEN_SECURITY_ATTRIBUTES_INFORMATION devolvido na área privada.
fn information(scratch: u64) -> &'static TokenSecurityAttributesInformation {
    // SAFETY: a consulta escreveu o cabeçalho no início da área privada.
    unsafe { TokenSecurityAttributesInformation::at(scratch) }
}

/// Os primeiros `count` TOKEN_SECURITY_ATTRIBUTE_V1 da resposta.
fn attributes(scratch: u64, count: usize) -> &'static [TokenSecurityAttributeV1] {
    // SAFETY: pAttributeV1 aponta para o vetor dentro da mesma área.
    unsafe { TokenSecurityAttributeV1::array_at(information(scratch).p_attribute_v1.get(), count) }
}

/// UNICODE_STRING de índice `index` nos valores do atributo SYSAPPID.
fn application_string(scratch: u64, index: u64) -> u64 {
    attributes(scratch, 1)[0].values.get() + index * UnicodeString::SIZE
}

#[allow(clippy::too_many_arguments)]
pub fn query(token: u64, package: u64, package_size: u64, application: u64, application_size: u64, dynamic_id: u64, claim: u64, presence: u64) -> Result<u32, KernelError> {
    // Substitui o armazenamento temporário da pilha nativa; pertence só a
    // esta chamada, inclusive nas consultas reentrantes e nos erros.
    let scratch = guest::alloc_bytes(SCRATCH_BYTES);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    let result = (|| -> Result<u32, KernelError> {
        initialize_filters(scratch);
        let status = query_identity(token, scratch, claim, presence)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if package != 0 {
            if package_size == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let package_size = out::<u64>(package_size);
            let (status, bytes) = copy_counted_name(application_string(scratch, 0), package, package_size.get());
            if status != 0 {
                return Ok(status);
            }
            package_size.set(bytes);
        } else if package_size != 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // O contrato original só verifica ApplicationPointer.
        if application != 0 {
            let application_size = out::<u64>(application_size);
            let (status, bytes) = copy_counted_name(application_string(scratch, 1), application, application_size.get());
            if status != 0 {
                return Ok(status);
            }
            application_size.set(bytes);
        }
        if dynamic_id != 0 {
            guest::write_bytes(dynamic_id, &[0u8; Guid::SIZE as usize]);
            if attributes(scratch, 1)[0].value_count.get() > 3 {
                let descriptor = application_string(scratch, 3);
                // O status anterior é conservado mesmo com GUID inválido.
                let _ = unicode::guid_from_string(descriptor, dynamic_id)?;
            }
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    result
}
