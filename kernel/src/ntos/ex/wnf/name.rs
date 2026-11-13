//! WNF_STATE_NAME.
//!
//! Formato do nome e pré-condições medidas no kernel original; a resolução
//! do namespace e a captura dos ponteiros pertencem ao serviço.

use alloc::string::String;

use crate::ntos::mm::guest_memory as guest;

pub const NAME_MASK: u64 = 0x41C6_4E6D_A3BC_0074;
const INVALID_PARAMETER: u32 = 0xC000_000D;

/// Nome decodificado: versão, tempo de vida, escopo e dados permanentes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedName {
    pub decoded_name: u64,
    pub version: u32,
    pub lifetime: u32,
    pub scope: u32,
    pub permanent_data: bool,
    pub status: u32,
}

pub fn decode(encoded: u64) -> DecodedName {
    let decoded_name = encoded ^ NAME_MASK;
    let version = (decoded_name & 15) as u32;
    let lifetime = ((decoded_name >> 4) & 3) as u32;
    let scope = ((decoded_name >> 6) & 15) as u32;
    let permanent_data = decoded_name & 1024 != 0;
    let status = if version != 1 || scope > 5 || (permanent_data && scope & !6 != 0) { INVALID_PARAMETER } else { 0 };
    DecodedName { decoded_name, version, lifetime, scope, permanent_data, status }
}

/// Valor da hive: os 64 bits do nome público em hexadecimal.
pub fn value_name(decoded_name: u64) -> String {
    alloc::format!("{:016X}", decoded_name ^ NAME_MASK)
}

/// Descrição validada: estado do namespace ou definição da hive (o GUID de
/// TypeId fica no pool do convidado; zero = sem GUID).
#[derive(Clone, Copy, Debug)]
pub struct Description {
    pub security_descriptor: u64,
    pub type_identifier: u64,
    pub maximum_size: u32,
}

/// TypeId fornecido: ponteiro (Zw conserva o ponteiro) ou cópia capturada
/// (Nt captura antes de tocar as saídas).
#[derive(Clone, Copy, Debug)]
pub enum SuppliedType {
    None,
    Pointer(u64),
    Captured([u8; 16]),
}

/// A permissão é avaliada antes do GUID e do limite. Estado sem GUID aceita
/// TypeId opcional sem ler o ponteiro; GUID armazenado exige igualdade.
pub fn validate(description: &Description, length: u32, supplied: SuppliedType, skip_access: bool, check_access: Option<&dyn Fn(u64, u32) -> u32>, desired_access: u32) -> u32 {
    if !skip_access {
        let status = check_access.map_or(0xC000_0022, |check| check(description.security_descriptor, desired_access));
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    if description.type_identifier != 0 {
        for offset in [0u64, 8] {
            let expected = guest::read64(description.type_identifier + offset);
            let provided = match supplied {
                SuppliedType::None | SuppliedType::Pointer(0) => return INVALID_PARAMETER,
                SuppliedType::Pointer(pointer) => guest::read64(pointer + offset),
                SuppliedType::Captured(bytes) => u64::from_le_bytes(bytes[offset as usize..offset as usize + 8].try_into().unwrap_or([0; 8])),
            };
            if provided != expected {
                return INVALID_PARAMETER;
            }
        }
    }
    if length > description.maximum_size { INVALID_PARAMETER } else { 0 }
}
