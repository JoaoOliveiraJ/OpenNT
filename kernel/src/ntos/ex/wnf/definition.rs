//! Definição WNF lida do name store — `system32/ntos/ex/wnf-definition.js`.
//!
//! O resolvedor de namespace escolhe o store e o mantém vivo; este módulo só
//! possui a cópia capturada da definição.

use crate::ntos::ex::pool_allocation;
use crate::ntos::ex::wnf::name as wnf_name;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::previous_mode;
use crate::ntos::se::descriptor;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub const DEFINITION_TAG: u32 = 0x2066_6E57;
const FRAME_TAG: u32 = 0x6466_6E57;
const GENERIC_MAPPING: [u32; 4] = [0x12_0001, 0x2, 0x1F_0000, 0x1F_0013];

/// Expande os bits genéricos e limita aos direitos WNF; entradas de
/// auditoria preservam ACCESS_SYSTEM_SECURITY, como o original.
fn map_entry_permissions(mask: u32, entry_type: u8) -> u32 {
    let mut mapped = mask;
    for (index, &mapping) in GENERIC_MAPPING.iter().enumerate() {
        if mapped & (0x8000_0000 >> index) != 0 {
            mapped |= mapping;
        }
    }
    let valid = GENERIC_MAPPING[3] | if entry_type <= 10 && 0x673 & (1 << entry_type) != 0 { 0 } else { 0x100_0000 };
    mapped & 0x0FFF_FFFF & valid
}

/// Tipos que o original não mapeia e ACEs INHERIT_ONLY conservam os bytes.
fn specialize_access_control_list(pointer: u64) {
    let count = guest::read16(pointer + 4);
    let mut entry = pointer + 8;
    for _ in 0..count {
        let entry_type = guest::read8(entry);
        if (entry_type < 11 || entry_type == 13 || entry_type == 14) && guest::read8(entry + 1) & 8 == 0 {
            guest::write32(entry + 4, map_entry_permissions(guest::read32(entry + 4), entry_type));
        }
        entry += guest::read16(entry + 2) as u64;
    }
}

/// DACL antes da SACL; aceita também a forma absoluta.
pub fn specialize(descriptor: u64) {
    if guest::read8(descriptor) != 1 {
        return;
    }
    let control = guest::read16(descriptor + 2);
    for (index, present) in [(3u64, 4u16), (2, 16)] {
        if control & present == 0 {
            continue;
        }
        let pointer = if control & 0x8000 != 0 {
            let offset = guest::read32(descriptor + 4 + index * 4);
            if offset != 0 { descriptor + offset as u64 } else { 0 }
        } else {
            guest::read64(descriptor + 8 + index * 8)
        };
        if pointer != 0 {
            specialize_access_control_list(pointer);
        }
    }
}

/// Cópia capturada: cabeçalho (tamanho máximo, TypeId, descritor) seguido
/// da KEY_VALUE_PARTIAL_INFORMATION; liberada ao ser descartada.
#[derive(Debug)]
pub struct Definition {
    pub pointer: u64,
    pub maximum_size: u32,
    pub type_identifier: u64,
    pub security_descriptor: u64,
}

impl Definition {
    pub fn release(self) {
        drop(self);
    }

    pub fn description(&self) -> wnf_name::Description {
        wnf_name::Description { security_descriptor: self.security_descriptor, type_identifier: self.type_identifier, maximum_size: self.maximum_size }
    }
}

impl Drop for Definition {
    fn drop(&mut self) {
        let _ = kernel_pool::free(self.pointer, Some(DEFINITION_TAG));
    }
}

/// Lê a definição pelo handle do store (do chamador). BUFFER_TOO_SMALL
/// realoca e consulta de novo; outros erros não publicam nada. Os filtros
/// CM participam das duas consultas pelo provedor real.
pub fn read(decoded_name: u64, key_handle: u64) -> Result<Result<Definition, u32>, KernelError> {
    let Ok(frame) = kernel_pool::allocate(64, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    let mut allocation = 0u64;
    let mut capacity = 0u32;
    let result = (|| -> Result<Result<Definition, u32>, KernelError> {
        let name = wnf_name::value_name(decoded_name);
        guest::write16(frame, 32);
        guest::write16(frame + 2, 34);
        guest::write64(frame + 8, frame + 16);
        for (index, unit) in name.encode_utf16().enumerate() {
            guest::write16(frame + 16 + index as u64 * 2, unit);
        }
        loop {
            let information = if allocation != 0 { allocation + 24 } else { 0 };
            let arguments = fields(&[("name", frame), ("klass", 2), ("out", information), ("length", capacity as u64), ("returned", frame + 56)]);
            let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, key_handle, &arguments, false))??;
            if status == 0xC000_0023 {
                if allocation != 0 {
                    let _ = kernel_pool::free(allocation, Some(DEFINITION_TAG));
                }
                capacity = guest::read32(frame + 56);
                allocation = pool_allocation::allocate_tagged(1, capacity.wrapping_add(24) as u64, DEFINITION_TAG).unwrap_or(0);
                if allocation == 0 {
                    return Ok(Err(0xC000_009A));
                }
                continue;
            }
            if status & 0x8000_0000 != 0 {
                return Ok(Err(status));
            }
            // REG_BINARY: SECURITY_DESCRIPTOR relativo, ULONG do tamanho
            // máximo e, havendo 16 bytes, o GUID de TypeId.
            if guest::read32(information + 4) != 3 {
                return Ok(Err(0xC000_0001));
            }
            let security = information + 12;
            let data_length = guest::read32(information + 8);
            if !descriptor::valid_relative(security, data_length, 0) {
                return Ok(Err(0xC000_0001));
            }
            specialize(security);
            let security_length = descriptor::length(security);
            let remaining = data_length.wrapping_sub(security_length);
            if remaining < 4 {
                return Ok(Err(0xC000_0001));
            }
            let maximum_size = guest::read32(security + security_length as u64);
            let type_identifier = if remaining - 4 >= 16 { security + security_length as u64 + 4 } else { 0 };
            guest::write64(allocation, 0);
            guest::write32(allocation, maximum_size);
            guest::write64(allocation + 8, type_identifier);
            guest::write64(allocation + 16, security);
            let definition = Definition { pointer: allocation, maximum_size, type_identifier, security_descriptor: security };
            allocation = 0; // publicada: a definição passa a ser a dona
            return Ok(Ok(definition));
        }
    })();
    if allocation != 0 {
        let _ = kernel_pool::free(allocation, Some(DEFINITION_TAG));
    }
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}
