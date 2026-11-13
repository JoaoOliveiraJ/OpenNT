//! RtlQueryPackageClaims do kernel — `system32/ntos/se/package-claims.js`.
//!
//! Recebe o corpo de um token, não um handle; nomes, claims e bits de
//! presença vêm só dos atributos de segurança dele.

use crate::ntos::rtl::unicode;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::security;

const ATTRIBUTE_BUFFER_BYTES: u32 = 0x330;
const SCRATCH_BYTES: u64 = 0x400;
const ATTRIBUTE_NAMES: [&str; 4] = ["WIN://SYSAPPID", "WIN://PKG", "WP://SKUID", "XBOX://LI"];
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// UNICODE_STRING dos filtros numa região privada desta chamada.
fn initialize_filters(scratch: u64) {
    let mut text_pointer = scratch + 0x380;
    for (index, text) in ATTRIBUTE_NAMES.iter().enumerate() {
        let descriptor = scratch + 0x340 + index as u64 * 16;
        guest::write16(descriptor, text.len() as u16 * 2);
        guest::write16(descriptor + 2, text.len() as u16 * 2 + 2);
        guest::write64(descriptor + 8, text_pointer);
        for (character, unit) in text.encode_utf16().enumerate() {
            guest::write16(text_pointer + character as u64 * 2, unit);
        }
        guest::write16(text_pointer + text.len() as u64 * 2, 0);
        text_pointer += text.len() as u64 * 2 + 2;
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
    let source = guest::read64(descriptor + 8);
    let (count, invalid) = if source == 0 {
        // %wZ imprime "(null)" para Buffer NULL.
        (6u64, false)
    } else {
        let length = guest::read16(descriptor);
        let maximum = guest::read16(descriptor + 2);
        ((length >> 1) as u64, maximum < length || length & 1 != 0 || source & 1 != 0)
    };
    let limit = character_capacity - 1;
    let copied = if invalid { 0 } else { count.min(limit) };
    let null_text: [u16; 6] = [b'(' as u16, b'n' as u16, b'u' as u16, b'l' as u16, b'l' as u16, b')' as u16];
    for index in 0..copied {
        let character = if source != 0 { guest::read16(source + index * 2) } else { null_text[index as usize] };
        guest::write16(destination + index * 2, character);
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
    let filters = scratch + 0x340;
    let returned = scratch + 0x330;
    let requested = if claim != 0 || presence != 0 { 2 } else { 1 };
    let mut has_package_claim = true;
    if presence != 0 {
        guest::write64(presence, 0);
    }
    let mut status = security::query_attributes(token, filters, requested, scratch, ATTRIBUTE_BUFFER_BYTES, returned)?;
    if status == STATUS_NOT_FOUND && requested == 2 {
        has_package_claim = false;
        status = security::query_attributes(token, filters, 1, scratch, ATTRIBUTE_BUFFER_BYTES, returned)?;
    }
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    if guest::read32(scratch + 4) == 0 {
        return Ok(STATUS_NOT_FOUND);
    }
    if claim != 0 {
        let mut value = 0;
        if has_package_claim {
            let attributes = guest::read64(scratch + 8);
            let values = guest::read64(attributes + 0x48);
            value = guest::read64(values);
        }
        guest::write64(claim, value);
    }
    if presence != 0 {
        guest::write64(presence, guest::read64(presence) | if has_package_claim { 3 } else { 1 });
        for index in 2..ATTRIBUTE_NAMES.len() as u64 {
            let probe = security::query_attributes(token, filters + index * 16, 1, 0, 0, returned)?;
            if probe == STATUS_BUFFER_TOO_SMALL {
                guest::write64(presence, guest::read64(presence) | 1 << index);
            }
        }
    }
    Ok(0)
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
            let capacity = guest::read64(package_size);
            let attributes = guest::read64(scratch + 8);
            let descriptor = guest::read64(attributes + 0x20);
            let (status, bytes) = copy_counted_name(descriptor, package, capacity);
            if status != 0 {
                return Ok(status);
            }
            guest::write64(package_size, bytes);
        } else if package_size != 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // O contrato original só verifica ApplicationPointer.
        if application != 0 {
            let capacity = guest::read64(application_size);
            let attributes = guest::read64(scratch + 8);
            let descriptor = guest::read64(attributes + 0x20) + 16;
            let (status, bytes) = copy_counted_name(descriptor, application, capacity);
            if status != 0 {
                return Ok(status);
            }
            guest::write64(application_size, bytes);
        }
        if dynamic_id != 0 {
            for offset in 0..16 {
                guest::write8(dynamic_id + offset, 0);
            }
            let attributes = guest::read64(scratch + 8);
            if guest::read32(attributes + 0x18) > 3 {
                let descriptor = guest::read64(attributes + 0x20) + 48;
                // O status anterior é conservado mesmo com GUID inválido.
                let _ = unicode::guid_from_string(descriptor, dynamic_id)?;
            }
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    result
}
