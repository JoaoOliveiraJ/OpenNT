//! Definição WNF lida do name store.
//!
//! O resolvedor de namespace escolhe o store e o mantém vivo; este módulo só
//! possui a cópia capturada da definição.

use crate::ntos::ex::pool_allocation;
use crate::ntos::ex::wnf::name as wnf_name;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::previous_mode;
use crate::ntos::se::descriptor;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{
    AccessAllowedAce, Acl, KeyValuePartialInformation, SecurityDescriptor, SecurityDescriptorRelative, UnicodeString, WnfStateNameRegistration, Guid,
};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Moldura de pool do valor da definição: o UNICODE_STRING com os 16 WCHARs
/// logo depois e o ResultLength da consulta.
#[repr(C)]
struct ValueFrame {
    name: UnicodeString,
    _text: Reserved<0x28>,
    result_length: Field<u32>,
    _pad_3c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ValueFrame {}

const _: () = assert!(core::mem::offset_of!(ValueFrame, result_length) == 56 && core::mem::size_of::<ValueFrame>() == 64);

pub const DEFINITION_TAG: u32 = 0x2066_6E57;
const FRAME_TAG: u32 = 0x6466_6E57;
const GENERIC_MAPPING: [u32; 4] = [0x12_0001, 0x2, 0x1F_0000, 0x1F_0013];

/// Expande os bits genéricos e limita aos direitos WNF; entradas de
/// auditoria preservam ACCESS_SYSTEM_SECURITY.
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

/// Tipos de ACE não mapeados e ACEs INHERIT_ONLY conservam os bytes.
fn specialize_access_control_list(pointer: u64) {
    // SAFETY: ACL da cópia própria do descritor da definição.
    let acl = unsafe { Acl::at(pointer) };
    let mut entry = pointer + Acl::SIZE;
    for _ in 0..acl.ace_count.get() {
        // SAFETY: as ACEs seguem o cabeçalho, cada uma com AceSize.
        let ace = unsafe { AccessAllowedAce::at(entry) };
        let entry_type = ace.header.ace_type.get();
        if (entry_type < 11 || entry_type == 13 || entry_type == 14) && ace.header.ace_flags.get() & 8 == 0 {
            ace.mask.set(map_entry_permissions(ace.mask.get(), entry_type));
        }
        entry += ace.header.ace_size.get() as u64;
    }
}

/// DACL antes da SACL; aceita também a forma absoluta.
pub fn specialize(descriptor: u64) {
    // SAFETY: descritor da cópia própria (relativo; a forma absoluta também vale).
    let relative = unsafe { SecurityDescriptorRelative::at(descriptor) };
    if relative.revision.get() != 1 {
        return;
    }
    let control = relative.control.get();
    // DACL (SE_DACL_PRESENT) antes da SACL (SE_SACL_PRESENT).
    for (dacl, present) in [(true, 4u16), (false, 16)] {
        if control & present == 0 {
            continue;
        }
        let pointer = if control & 0x8000 != 0 {
            let offset = if dacl { relative.dacl.get() } else { relative.sacl.get() };
            if offset != 0 { descriptor + offset as u64 } else { 0 }
        } else {
            // SAFETY: forma absoluta (alinhada a ponteiro) indicada pelo Control.
            let absolute = unsafe { SecurityDescriptor::at(descriptor) };
            if dacl { absolute.dacl.get() } else { absolute.sacl.get() }
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
    let Ok(frame) = kernel_pool::allocate(ValueFrame::SIZE, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(Err(0xC000_0017)) };
    // SAFETY: alocação nova do tamanho da moldura.
    let value = unsafe { ValueFrame::at(frame) };
    let header = WnfStateNameRegistration::SIZE;
    let mut allocation = 0u64;
    let mut capacity = 0u32;
    let result = (|| -> Result<Result<Definition, u32>, KernelError> {
        let name = wnf_name::value_name(decoded_name);
        let text = value.name.address() + UnicodeString::SIZE;
        value.name.length.set(32);
        value.name.maximum_length.set(34);
        value.name.buffer.set(text);
        let bytes: alloc::vec::Vec<u8> = name.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(text, &bytes);
        loop {
            // A KEY_VALUE_PARTIAL_INFORMATION segue o cabeçalho da definição.
            let information = if allocation != 0 { allocation + header } else { 0 };
            let arguments = fields(&[("name", frame), ("klass", 2), ("out", information), ("length", capacity as u64), ("returned", value.result_length.address())]);
            let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, key_handle, &arguments, false))??;
            if status == 0xC000_0023 {
                if allocation != 0 {
                    let _ = kernel_pool::free(allocation, Some(DEFINITION_TAG));
                }
                capacity = value.result_length.get();
                allocation = pool_allocation::allocate_tagged(1, capacity.wrapping_add(header as u32) as u64, DEFINITION_TAG).unwrap_or(0);
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
            // SAFETY: a resposta do ZwQueryValueKey na alocação própria.
            let partial = unsafe { KeyValuePartialInformation::at(information) };
            if partial.type_.get() != 3 {
                return Ok(Err(0xC000_0001));
            }
            let security = partial.data.as_ptr() as u64;
            let data_length = partial.data_length.get();
            if !descriptor::valid_relative(security, data_length, 0) {
                return Ok(Err(0xC000_0001));
            }
            specialize(security);
            let security_length = descriptor::length(security);
            let remaining = data_length.wrapping_sub(security_length);
            if remaining < 4 {
                return Ok(Err(0xC000_0001));
            }
            // Depois do descritor: o ULONG do tamanho máximo e o TypeId opcional.
            let maximum_size = guest::read::<u32>(security + security_length as u64);
            let type_identifier = if (remaining - 4) as u64 >= Guid::SIZE { security + security_length as u64 + 4 } else { 0 };
            // SAFETY: cabeçalho da alocação própria.
            let registration = unsafe { WnfStateNameRegistration::at(allocation) };
            registration.max_state_size.set(maximum_size);
            registration.type_id.set(type_identifier);
            registration.security_descriptor.set(security);
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
