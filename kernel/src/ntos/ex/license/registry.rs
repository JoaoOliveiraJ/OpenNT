//! Consultas de licenciamento em ProductOptions.
//!
//! Os dados pertencem à hive e ao provedor de informações do sistema; este
//! módulo conserva a ordem das consultas e não cria políticas nem estados de
//! ativação. ZwQuerySystemInformation (classe 0xBE, Cloudbook) entra por
//! [`set_system_information`] com o Zw da fase 6.

use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const PRODUCT_OPTIONS: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\ProductOptions";
const FRAME_TAG: u32 = 0x724C_7354;
const VALUE_TAG: u32 = 0x2053_4C53;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// ZwQuerySystemInformation(classe, buffer, tamanho, &retornado).
pub type SystemInformation = fn(u32, u64, u32, u64) -> u32;

static SYSTEM_INFORMATION: SpinLock<Option<SystemInformation>> = SpinLock::new(None);

pub fn set_system_information(provider: Option<SystemInformation>) {
    *SYSTEM_INFORMATION.lock() = provider;
}

/// Nome do valor: constante interna ou UNICODE_STRING do chamador (não lida
/// antes de o CM consultá-la).
#[derive(Clone, Copy)]
pub enum ValueName<'a> {
    Text(&'a str),
    Pointer(u64),
}

/// UNICODE_STRING contada com o terminador reservado à parte.
fn write_name(descriptor: u64, buffer: u64, text: &str) {
    let units: Vec<u16> = text.encode_utf16().collect();
    guest::write16(descriptor, units.len() as u16 * 2);
    guest::write16(descriptor + 2, (units.len() as u16 + 1) * 2);
    guest::write64(descriptor + 8, buffer);
    for (index, unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    guest::write16(buffer + units.len() as u64 * 2, 0);
}

fn move_bytes(destination: u64, source: u64, length: u32) {
    let backwards = destination > source && destination < source + length as u64;
    for position in 0..length as u64 {
        let offset = if backwards { length as u64 - position - 1 } else { position };
        guest::write8(destination + offset, guest::read8(source + offset));
    }
}

/// Helper 0x7D13E4: abre ProductOptions, consulta o tamanho e depois o
/// valor; BUFFER_OVERFLOW não autoriza a segunda consulta.
pub fn query(name: ValueName, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64, handled: u64) -> Result<u32, KernelError> {
    guest::write8(handled, 1);
    let path_bytes = (PRODUCT_OPTIONS.len() as u64 + 1) * 2;
    let name_bytes = match name {
        ValueName::Text(text) => (text.encode_utf16().count() as u64 + 1) * 2,
        ValueName::Pointer(_) => 0,
    };
    let Ok(frame) = kernel_pool::allocate(96 + path_bytes + name_bytes, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    let mut opened = None;
    let mut value = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        guest::write32(frame, 48);
        guest::write64(frame + 16, frame + 48);
        guest::write32(frame + 24, 0x240);
        write_name(frame + 48, frame + 96, PRODUCT_OPTIONS);
        let name_pointer = match name {
            ValueName::Text(text) => {
                write_name(frame + 80, frame + 96 + path_bytes, text);
                frame + 80
            }
            ValueName::Pointer(pointer) => pointer,
        };
        let status = previous_mode::with_kernel(|| key_services::open(frame + 64, 0x20019, frame, false, 0))??;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let handle = guest::read64(frame + 64);
        opened = Some(handle);
        let request = |out: u64, length: u32| fields(&[("name", name_pointer), ("klass", 2), ("out", out), ("length", length as u64), ("returned", frame + 72)]);
        let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, handle, &request(0, 0), false))??;
        if status & 0x8000_0000 != 0 && status != STATUS_BUFFER_TOO_SMALL {
            return Ok(status);
        }
        let size = guest::read32(frame + 72);
        value = pool_allocation::allocate_tagged(1, size as u64, VALUE_TAG).unwrap_or(0);
        if value == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, handle, &request(value, size), false))??;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        guest::write32(length_pointer, guest::read32(value + 8));
        if type_pointer != 0 {
            guest::write32(type_pointer, guest::read32(value + 4));
        }
        // Uma saída pode apontar para os metadados: o comprimento é relido.
        let length = guest::read32(value + 8);
        if capacity < length {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        if buffer != 0 {
            move_bytes(buffer, value + 12, length);
        }
        Ok(status)
    })();
    // A resposta é liberada antes de fechar a chave.
    if value != 0 {
        let _ = kernel_pool::free(value, None);
    }
    if let Some(handle) = opened {
        let _ = previous_mode::with_kernel(|| close::close(handle, Some(0)));
    }
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

/// Callbacks Cloudbook: leitura da classe 0xBE quando o valor não está em
/// ProductOptions, com tratamentos de falha e capacidade distintos.
fn query_device(identifier: bool, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64, handled: u64) -> Result<u32, KernelError> {
    let result = query(ValueName::Text(if identifier { "CloudbookDeviceID" } else { "CloudbookDeviceLocked" }), type_pointer, buffer, capacity, length_pointer, handled)?;
    if result & 0x8000_0000 == 0 || result == STATUS_BUFFER_TOO_SMALL {
        return Ok(result);
    }
    guest::write32(length_pointer, if identifier { 32 } else { 4 });
    let Ok(frame) = kernel_pool::allocate(40, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    let result = (|| -> Result<u32, KernelError> {
        let handler = (*SYSTEM_INFORMATION.lock()).ok_or_else(|| KernelError::new("ZwQuerySystemInformation is not available yet"))?;
        let status = previous_mode::with_kernel(|| handler(0xBE, frame, 36, 0))?;
        let final_status = if status & 0x8000_0000 != 0 {
            if identifier { status } else { STATUS_NAME_NOT_FOUND }
        } else if identifier && guest::read8(frame) & 4 == 0 {
            STATUS_NAME_NOT_FOUND
        } else if capacity < if identifier { 32 } else { guest::read32(length_pointer) } {
            STATUS_BUFFER_TOO_SMALL
        } else {
            let flags = if identifier { 0 } else { guest::read32(frame) };
            // Este caminho exige Type e Buffer, sem os testes opcionais.
            guest::write32(type_pointer, if identifier { 3 } else { 4 });
            let length = guest::read32(length_pointer);
            if !identifier {
                guest::write32(frame + 36, (flags & 5 == 5) as u32);
            }
            move_bytes(buffer, frame + if identifier { 4 } else { 36 }, length);
            0
        };
        guest::write8(handled, 1);
        Ok(final_status)
    })();
    let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    result
}

pub fn query_product_pfn(type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query(ValueName::Text("OSProductPfn"), type_pointer, buffer, capacity, length, handled)
}

pub fn query_product_content_id(type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query(ValueName::Text("OSProductContentId"), type_pointer, buffer, capacity, length, handled)
}

pub fn query_device_locked(type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query_device(false, type_pointer, buffer, capacity, length, handled)
}

pub fn query_device_identifier(type_pointer: u64, buffer: u64, capacity: u32, length: u64, handled: u64) -> Result<u32, KernelError> {
    query_device(true, type_pointer, buffer, capacity, length, handled)
}
