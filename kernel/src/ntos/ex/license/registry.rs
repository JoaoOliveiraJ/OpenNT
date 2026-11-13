//! Consultas de licenciamento em ProductOptions.
//!
//! Os dados pertencem à hive e ao provedor de informações do sistema; este
//! módulo conserva a ordem das consultas e não cria políticas nem estados de
//! ativação. ZwQuerySystemInformation (classe 0xBE, Cloudbook) entra por
//! [`set_system_information`] com o Zw da fase 6.

use crate::ntos::ex::pool_allocation;
use crate::ntos::cm::key::services::{self as key_services, fields, Kind};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::previous_mode;
use super::layout::{self, byte_at, ulong_at};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{KeyValuePartialInformation, ObjectAttributes, UnicodeString};
use crate::rtl::{KernelError, SpinLock};

/// Moldura de pool da consulta: atributos da chave ProductOptions, o
/// caminho e o nome do valor (caracteres logo depois da moldura), o handle
/// aberto e o ResultLength.
#[repr(C)]
struct KeyFrame {
    attributes: ObjectAttributes,
    path: UnicodeString,
    handle: Field<u64>,
    result_length: Field<u32>,
    _pad_4c: Reserved<0x4>,
    name: UnicodeString,
}

/// Saída da classe 0xBE (36 bytes: flags e o identificador) e o DWORD
/// devolvido como valor "travado".
#[repr(C)]
struct DeviceFrame {
    flags: Field<u32>,
    identifier: [Field<u8>; 32],
    locked: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for KeyFrame {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DeviceFrame {}

const _: () = {
    assert!(core::mem::size_of::<KeyFrame>() == 96);
    assert!(core::mem::offset_of!(KeyFrame, path) == 0x30);
    assert!(core::mem::offset_of!(KeyFrame, handle) == 0x40);
    assert!(core::mem::offset_of!(KeyFrame, name) == 0x50);
    assert!(core::mem::size_of::<DeviceFrame>() == 40);
    assert!(core::mem::offset_of!(DeviceFrame, locked) == 36);
};

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


/// Helper 0x7D13E4: abre ProductOptions, consulta o tamanho e depois o
/// valor; BUFFER_OVERFLOW não autoriza a segunda consulta.
pub fn query(name: ValueName, type_pointer: u64, buffer: u64, capacity: u32, length_pointer: u64, handled: u64) -> Result<u32, KernelError> {
    byte_at(handled).set(1);
    let path_bytes = (PRODUCT_OPTIONS.len() as u64 + 1) * 2;
    let name_bytes = match name {
        ValueName::Text(text) => (text.encode_utf16().count() as u64 + 1) * 2,
        ValueName::Pointer(_) => 0,
    };
    let Ok(frame) = kernel_pool::allocate(KeyFrame::SIZE + path_bytes + name_bytes, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    // SAFETY: alocação nova da moldura seguida dos caracteres.
    let key = unsafe { KeyFrame::at(frame) };
    let text_area = frame + KeyFrame::SIZE;
    let mut opened = None;
    let mut value = 0u64;
    let result = (|| -> Result<u32, KernelError> {
        key.attributes.length.set(ObjectAttributes::SIZE as u32);
        key.attributes.object_name.set(key.path.address());
        key.attributes.attributes.set(0x240);
        layout::write_name(key.path.address(), text_area, PRODUCT_OPTIONS);
        let name_pointer = match name {
            ValueName::Text(text) => {
                layout::write_name(key.name.address(), text_area + path_bytes, text);
                key.name.address()
            }
            ValueName::Pointer(pointer) => pointer,
        };
        let status = previous_mode::with_kernel(|| key_services::open(key.handle.address(), 0x20019, key.attributes.address(), false, 0))??;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let handle = key.handle.get();
        opened = Some(handle);
        let request = |out: u64, length: u32| fields(&[("name", name_pointer), ("klass", 2), ("out", out), ("length", length as u64), ("returned", key.result_length.address())]);
        let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, handle, &request(0, 0), false))??;
        if status & 0x8000_0000 != 0 && status != STATUS_BUFFER_TOO_SMALL {
            return Ok(status);
        }
        let size = key.result_length.get();
        value = pool_allocation::allocate_tagged(1, size as u64, VALUE_TAG).unwrap_or(0);
        if value == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
        let status = previous_mode::with_kernel(|| key_services::key_operation(Kind::QueryValue, handle, &request(value, size), false))??;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // SAFETY: KEY_VALUE_PARTIAL_INFORMATION devolvida em `value`.
        let information = unsafe { KeyValuePartialInformation::at(value) };
        ulong_at(length_pointer).set(information.data_length.get());
        if type_pointer != 0 {
            ulong_at(type_pointer).set(information.type_.get());
        }
        // Uma saída pode apontar para os metadados: o comprimento é relido.
        let length = information.data_length.get();
        if capacity < length {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        if buffer != 0 {
            layout::move_bytes(buffer, information.data.as_ptr() as u64, length);
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
    ulong_at(length_pointer).set(if identifier { 32 } else { 4 });
    let Ok(frame) = kernel_pool::allocate(DeviceFrame::SIZE, AllocateOptions { zero: true, paged: true, tag: FRAME_TAG, ..Default::default() }) else { return Ok(STATUS_NO_MEMORY) };
    // SAFETY: alocação nova do tamanho da moldura.
    let device = unsafe { DeviceFrame::at(frame) };
    let result = (|| -> Result<u32, KernelError> {
        let handler = (*SYSTEM_INFORMATION.lock()).ok_or_else(|| KernelError::new("ZwQuerySystemInformation is not available yet"))?;
        let status = previous_mode::with_kernel(|| handler(0xBE, frame, core::mem::offset_of!(DeviceFrame, locked) as u32, 0))?;
        let final_status = if status & 0x8000_0000 != 0 {
            if identifier { status } else { STATUS_NAME_NOT_FOUND }
        } else if identifier && device.flags.get() & 4 == 0 {
            STATUS_NAME_NOT_FOUND
        } else if capacity < if identifier { 32 } else { ulong_at(length_pointer).get() } {
            STATUS_BUFFER_TOO_SMALL
        } else {
            let flags = if identifier { 0 } else { device.flags.get() };
            // Este caminho exige Type e Buffer, sem os testes opcionais.
            ulong_at(type_pointer).set(if identifier { 3 } else { 4 });
            let length = ulong_at(length_pointer).get();
            if !identifier {
                device.locked.set((flags & 5 == 5) as u32);
            }
            layout::move_bytes(buffer, if identifier { device.identifier.as_ptr() as u64 } else { device.locked.address() }, length);
            0
        };
        byte_at(handled).set(1);
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
