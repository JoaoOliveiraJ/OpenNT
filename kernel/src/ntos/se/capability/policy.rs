//! Políticas de RtlCapabilityCheck.
//!
//! A configuração vem do SKU corrente e do cache ProductPolicy.

use crate::ntos::ex::license::values as license_values;
use crate::ntos::ex::{pool_allocation, pool_quota};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Ejob, EserversiloGlobals, KuserSharedData, NtStruct, SiloUserSharedData, UnicodeString};
use crate::ntos::mm::shared_user_data::SHARED_USER_DATA_VA;

const PREFIX: &str = "Security-System-Capability-";
const STRING_TAG: u32 = 0x6772_7453;
const POLICY_TAG: u32 = 0x6250_7452;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// RtlIsMultiSessionSku: o bit global só vale fora de server silos; o ramo
/// do silo devolve o byte próprio sem normalizar.
pub fn is_multi_session() -> u32 {
    let silo = silo_query::current_server_silo();
    if silo == 0 {
        // SAFETY: KUSER_SHARED_DATA mapeada pelo kernel no endereço fixo.
        return unsafe { KuserSharedData::at(SHARED_USER_DATA_VA) }.dbg_multi_session_sku();
    }
    // SAFETY: server silo vivo (EJOB) com os globais e o SILO_USER_SHARED_DATA publicados.
    unsafe {
        let globals = Ejob::at(silo).server_silo_globals.get();
        let shared = EserversiloGlobals::at(globals).user_shared_data.get();
        SiloUserSharedData::at(shared).is_multi_session_sku.get() as u32
    }
}

fn string_at(descriptor: u64) -> &'static UnicodeString {
    // SAFETY: PUNICODE_STRING vivo do chamador (ou do frame privado).
    unsafe { UnicodeString::at(descriptor) }
}

fn clear_descriptor(pointer: u64) {
    guest::write_bytes(pointer, &[0u8; UnicodeString::SIZE as usize]);
}

/// RtlFreeUnicodeString: só zera o descritor quando havia buffer.
pub fn release_string(descriptor: u64) {
    let buffer = string_at(descriptor).buffer.get();
    if buffer != 0 {
        let _ = kernel_pool::free(buffer, None);
        clear_descriptor(descriptor);
    }
}

/// `Security-System-Capability-<nome>`: descoberta do tamanho e cópia; o
/// buffer é entregue ao descritor do chamador no sucesso.
pub fn query_system_policy(name: u64, output: u64) -> Result<u32, KernelError> {
    let mut prefix_buffer = 0u64;
    let mut value_buffer = 0u64;
    let mut result_buffer = 0u64;
    let mut frame = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        if name == 0 || output == 0 {
            return Ok(0xC000_000D);
        }
        let name_string = string_at(name);
        let name_bytes = name_string.length.get() as u32;
        let capacity = (name_bytes + 56) & 0xFFFF;
        prefix_buffer = pool_allocation::allocate_tagged(1, capacity as u64, STRING_TAG).unwrap_or(0);
        if prefix_buffer == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        guest::write_bytes(prefix_buffer, &alloc::vec![0u8; capacity as usize]);
        // A capacidade USHORT pode dar a volta antes das concatenações.
        let prefix_bytes = PREFIX.len() as u32 * 2;
        if prefix_bytes > capacity || prefix_bytes + name_bytes > capacity {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        guest::write_bytes(prefix_buffer, &PREFIX.encode_utf16().flat_map(u16::to_le_bytes).collect::<alloc::vec::Vec<u8>>());
        let source = name_string.buffer.get();
        guest::write_bytes(prefix_buffer + prefix_bytes as u64, &guest::read_bytes(source, name_bytes as usize));
        guest::write16(prefix_buffer + ((prefix_bytes + name_bytes) >> 1) as u64 * 2, 0);
        // Armazenamento privado dos escalares e da UNICODE_STRING da pilha.
        frame = kernel_pool::allocate(32, AllocateOptions { tag: POLICY_TAG, zero: true, ..Default::default() }).unwrap_or(0);
        if frame == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        let value_name = string_at(frame);
        value_name.length.set((prefix_bytes + name_bytes) as u16);
        value_name.maximum_length.set(capacity as u16);
        value_name.buffer.set(prefix_buffer);
        let status = license_values::query(frame, frame + 16, 0, 0, frame + 20)?;
        if status != STATUS_BUFFER_TOO_SMALL {
            return Ok(status);
        }
        let value_bytes = guest::read32(frame + 20);
        value_buffer = pool_quota::allocate(0x208, value_bytes as u64, POLICY_TAG).unwrap_or(0);
        let status = license_values::query(frame, frame + 16, value_buffer, value_bytes, frame + 20)?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if guest::read32(frame + 16) != 1 || value_bytes < 1 || value_bytes & 1 != 0 {
            return Ok(0xC000_0001);
        }
        result_buffer = pool_allocation::allocate_tagged(1, value_bytes as u64, STRING_TAG).unwrap_or(0);
        if result_buffer == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        guest::write_bytes(result_buffer, &guest::read_bytes(value_buffer, value_bytes as usize));
        clear_descriptor(output);
        let mut characters = 0u64;
        while characters < 0x7FFF && guest::read16(result_buffer + characters * 2) != 0 {
            characters += 1;
        }
        if characters == 0x7FFF {
            return Ok(0xC000_000D);
        }
        let result = string_at(output);
        result.buffer.set(result_buffer);
        result.length.set(characters as u16 * 2);
        result.maximum_length.set(characters as u16 * 2 + 2);
        result_buffer = 0; // propriedade transferida ao descritor do chamador
        Ok(0)
    })();
    let failed = !matches!(result, Ok(status) if status & 0x8000_0000 == 0);
    if failed && output != 0 {
        release_string(output);
    }
    for buffer in [result_buffer, value_buffer, prefix_buffer, frame] {
        if buffer != 0 {
            let _ = kernel_pool::free(buffer, None);
        }
    }
    result
}
