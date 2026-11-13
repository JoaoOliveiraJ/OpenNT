//! RC_CONFIG.
//!
//! O recurso MUI que declara quais tipos pertencem ao módulo principal e ao
//! arquivo de idioma; a existência de bytes locais não substitui essa
//! declaração. Os arquivos satélites são do loader.

use alloc::vec::Vec;

use crate::ntos::rtl::resource::memory as resource_memory;
use crate::ntos::rtl::resource::tree::{self as resource_tree, Image, Key, LookupOptions, Plan, STATUS_INVALID_IMAGE_FORMAT, STATUS_RESOURCE_TYPE_NOT_FOUND};
use crate::ntos::rtl::unicode_case;
use crate::rtl::KernelError;

const STATUS_MUI_INVALID_RC_CONFIG: u32 = 0xC00B_0003;

/// O payload RC_CONFIG na vista.
#[derive(Clone, Copy, Debug)]
pub struct Configuration {
    pub address: u64,
    pub size: u32,
}

fn read_dword(configuration: &Configuration, offset: u64) -> Result<u32, KernelError> {
    resource_memory::read32(configuration.address.wrapping_add(offset))
}

fn has_one_allowed_bit(value: u32, allowed: u32) -> bool {
    value & !allowed == 0 && value != 0 && value & value.wrapping_sub(1) == 0
}

/// Limites contra a vista e contra o tamanho declarado; os oito pares
/// offset/tamanho são em bytes, inclusive nas listas UTF-16.
fn validate(configuration: &Configuration, image: &Image) -> Result<u32, KernelError> {
    let size = read_dword(configuration, 4)?;
    if configuration.address as u128 + size as u128 > image.base as u128 + image.size {
        return Ok(STATUS_INVALID_IMAGE_FORMAT);
    }
    for field in (0x44..=0x7C).step_by(8) {
        let offset = read_dword(configuration, field)? as u64;
        let length = read_dword(configuration, field + 4)? as u64;
        if offset + length > 0xFFFF_FFFF || offset + length > size as u64 {
            return Ok(STATUS_MUI_INVALID_RC_CONFIG);
        }
    }
    if read_dword(configuration, 0)? != 0xFECD_FECD || size != configuration.size || read_dword(configuration, 8)? != 0x10000 {
        return Ok(STATUS_MUI_INVALID_RC_CONFIG);
    }
    let path_type = read_dword(configuration, 0x0C)?;
    let file_type = read_dword(configuration, 0x10)?;
    if (path_type != 0 && !has_one_allowed_bit(path_type, 7)) || !has_one_allowed_bit(file_type & !0x30, 3) || !has_one_allowed_bit(file_type & !3, 0x30) {
        return Ok(STATUS_MUI_INVALID_RC_CONFIG);
    }
    if file_type & 1 != 0 {
        let fallback_location = read_dword(configuration, 0x18)?;
        let attributes = read_dword(configuration, 0x14)?;
        if !has_one_allowed_bit(fallback_location, 3) || (attributes != 0 && !has_one_allowed_bit(attributes, 0x100)) {
            return Ok(STATUS_MUI_INVALID_RC_CONFIG);
        }
    }
    Ok(0)
}

pub fn inspect(image: &Image) -> Result<Result<Configuration, u32>, KernelError> {
    let resource = resource_tree::lookup(image, &Key::Name("MUI".encode_utf16().collect()), &Key::Id(1), &Plan { candidates: alloc::vec![0], select_first: true, allow_any: false }, [0, 1], LookupOptions::default())?;
    if resource.status != 0 {
        return Ok(Err(if resource.status == STATUS_INVALID_IMAGE_FORMAT { resource.status } else { STATUS_RESOURCE_TYPE_NOT_FOUND }));
    }
    let configuration = Configuration { address: resource.address, size: resource.size };
    let status = if image.validate { validate(&configuration, image)? } else { 0 };
    Ok(if status != 0 { Err(status) } else { Ok(configuration) })
}

fn contains_identifier(configuration: &Configuration, field: u64, identifier: u32) -> Result<bool, KernelError> {
    let offset = read_dword(configuration, field)? as u64;
    let count = read_dword(configuration, field + 4)? >> 2;
    for index in 0..count as u64 {
        if read_dword(configuration, offset + index * 4)? == identifier {
            return Ok(true);
        }
    }
    Ok(false)
}

/// As listas de tipos são MULTI_SZ comparadas sem distinção de caixa (a
/// árvore PE continua sensível à caixa).
fn contains_name(configuration: &Configuration, field: u64, name: &[u16]) -> Result<bool, KernelError> {
    let offset = read_dword(configuration, field)? as u64;
    let mut remaining = (read_dword(configuration, field + 4)? >> 1) as i64;
    let mut pointer = configuration.address.wrapping_add(offset);
    let wanted = unicode_case::upcase_units(name)?;
    while remaining > 0 {
        let mut available = Vec::new();
        let mut count = 0u64;
        loop {
            let character = resource_memory::read16(pointer.wrapping_add(count * 2))?;
            count += 1;
            if character == 0 {
                break;
            }
            available.push(character);
        }
        if available.is_empty() {
            return Ok(false);
        }
        if unicode_case::upcase_units(&available)? == wanted {
            return Ok(true);
        }
        remaining -= count as i64;
        pointer = pointer.wrapping_add(count * 2);
    }
    Ok(false)
}

/// Os bits 17 e 18 indicam ausência no satélite e no principal; os dois
/// juntos impedem aceitar um payload do tipo.
pub fn type_membership(configuration: &Configuration, resource_type: &Key) -> Result<u32, KernelError> {
    let (in_main, in_satellite) = match resource_type {
        Key::Id(identifier) => (contains_identifier(configuration, 0x5C, *identifier)?, contains_identifier(configuration, 0x6C, *identifier)?),
        Key::Name(units) => (contains_name(configuration, 0x54, units)?, contains_name(configuration, 0x64, units)?),
        Key::Pointer(pointer) => (contains_identifier(configuration, 0x5C, *pointer as u32)?, contains_identifier(configuration, 0x6C, *pointer as u32)?),
    };
    let mut flags = if in_main { 0 } else { 0x40000 } | if in_satellite { 0 } else { 0x20000 };
    if read_dword(configuration, 0x14)? & 0x100 != 0 {
        flags |= 0x10_0000;
    }
    if read_dword(configuration, 0x10)? & 0x10 != 0 {
        flags |= 0x20_0000;
    }
    Ok(flags)
}

/// O checksum de serviço (16 bytes) impede aceitar um satélite de outra
/// versão com o mesmo nome de arquivo.
pub fn service_checksum_matches(primary: &Configuration, satellite: &Configuration) -> Result<bool, KernelError> {
    for offset in (0x2C..0x3C).step_by(4) {
        if read_dword(primary, offset)? != read_dword(satellite, offset)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// LanguageName: WCHAR* relativo à configuração.
pub fn language_name(configuration: &Configuration) -> Result<Vec<u16>, KernelError> {
    let mut pointer = configuration.address.wrapping_add(read_dword(configuration, 0x74)? as u64);
    let mut name = Vec::new();
    loop {
        let character = resource_memory::read16(pointer)?;
        if character == 0 {
            return Ok(name);
        }
        name.push(character);
        pointer = pointer.wrapping_add(2);
    }
}

/// Consulta legada do fallback MUN: só a assinatura, sem as checagens
/// estritas; assinatura inválida equivale a ausência.
pub fn inspect_legacy(image: &Image) -> Result<Result<Configuration, u32>, KernelError> {
    let relaxed = Image { validate: false, ..image.clone() };
    match inspect(&relaxed)? {
        Ok(configuration) if read_dword(&configuration, 0)? == 0xFECD_FECD => Ok(Ok(configuration)),
        _ => Ok(Err(STATUS_RESOURCE_TYPE_NOT_FOUND)),
    }
}
