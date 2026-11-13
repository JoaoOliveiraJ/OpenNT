//! ALPC_PORT_ATTRIBUTES da conexão.
//!
//! Captura a estrutura x64 antes da busca da porta e valida a cópia ao
//! criar o cliente; a separação preserva a ordem de falhas do serviço NT.

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::alpc::security_contexts::Quality;
use crate::ntos::inc::types::{AlpcPortAttributes, NtStruct};
use crate::rtl::KernelError;

pub const ATTRIBUTES_BYTE_LENGTH: u64 = AlpcPortAttributes::SIZE;

/// Cópia sem ponteiros do chamador, mesmo quando a conexão aguarda o servidor.
pub struct Captured {
    pub bytes: Option<Vec<u8>>,
    pub access_mode: u8,
}

/// A estrutura aceita endereços sem alinhamento.
pub fn capture(pointer: u64, access_mode: u8) -> Result<Captured, u32> {
    if pointer == 0 {
        return Ok(Captured { bytes: None, access_mode });
    }
    if !message_buffer::accessible(pointer, ATTRIBUTES_BYTE_LENGTH, access_mode, false) {
        return Err(0xC000_0005);
    }
    Ok(Captured { bytes: Some(message_buffer::read_block(pointer, ATTRIBUTES_BYTE_LENGTH)?), access_mode })
}

#[derive(Clone, Copy, Debug)]
pub struct ClientParameters {
    pub port_flags: u32,
    pub maximum: u32,
    pub security_quality: Quality,
    pub memory_bandwidth: u64,
    pub maximum_pool_usage: u64,
    pub maximum_section_size: u64,
    pub maximum_view_size: u64,
    pub maximum_total_section_size: u64,
    pub duplicate_object_types: u32,
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap_or([0; 8]))
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap_or([0; 4]))
}

/// AlpcpValidateAndSetPortAttributes, caminho de cliente ALPC. O limite de
/// mensagem é compartilhado com o servidor; as quotas continuam SIZE_T.
pub fn for_client(captured: &Captured, listener_maximum: u32) -> Result<Result<ClientParameters, u32>, KernelError> {
    if !(40..=65535).contains(&listener_maximum) {
        return Err(KernelError::new("ALPC listener has an invalid maximum message length"));
    }
    let Some(bytes) = &captured.bytes else {
        return Ok(Ok(ClientParameters {
            port_flags: 0x1_0000,
            maximum: listener_maximum.min(512),
            security_quality: Quality { level: 0, tracking: 1, effective_only: true },
            memory_bandwidth: 0,
            maximum_pool_usage: 0x4000,
            maximum_section_size: 0x4000,
            maximum_view_size: 0,
            maximum_total_section_size: 0x2_0000,
            duplicate_object_types: 0,
        }));
    };
    let maximum = u64_at(bytes, offset_of!(AlpcPortAttributes, max_message_length));
    let flags = u32_at(bytes, offset_of!(AlpcPortAttributes, flags));
    let level = u32_at(bytes, offset_of!(AlpcPortAttributes, security_qos.impersonation_level));
    let tracking = bytes[offset_of!(AlpcPortAttributes, security_qos.context_tracking_mode)];
    // A ordem é significativa: comprimento, porta de sistema, tracking e
    // nível. SecurityQos.Length não é validado neste serviço.
    if !(40..=65535).contains(&maximum) {
        return Ok(Err(0xC000_000D));
    }
    if captured.access_mode != 0 && flags & 0x10_0000 != 0 {
        return Ok(Err(0xC000_000D));
    }
    if tracking > 1 {
        return Ok(Err(0xC000_000D));
    }
    if level > 3 {
        return Ok(Err(0xC000_00A5));
    }
    Ok(Ok(ClientParameters {
        port_flags: flags & 0x03FF_0000,
        maximum: (maximum as u32).min(listener_maximum),
        security_quality: Quality { level, tracking, effective_only: bytes[offset_of!(AlpcPortAttributes, security_qos.effective_only)] != 0 },
        memory_bandwidth: u64_at(bytes, offset_of!(AlpcPortAttributes, memory_bandwidth)),
        maximum_pool_usage: u64_at(bytes, offset_of!(AlpcPortAttributes, max_pool_usage)),
        maximum_section_size: u64_at(bytes, offset_of!(AlpcPortAttributes, max_section_size)),
        maximum_view_size: u64_at(bytes, offset_of!(AlpcPortAttributes, max_view_size)),
        maximum_total_section_size: u64_at(bytes, offset_of!(AlpcPortAttributes, max_total_section_size)),
        duplicate_object_types: u32_at(bytes, offset_of!(AlpcPortAttributes, dup_object_types)) & 0xFFD,
    }))
}
