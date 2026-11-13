//! Pontos de entrada de kernel do registro — `system32/ntos/cm/native-keys.js`.
//!
//! PreviousMode zero; os ponteiros de saída continuam do chamador e o corpo
//! das operações fica em `key_services`. As operações sobre um handle aberto
//! (ZwSetValueKey, ZwQueryValueKey, enumeração, exclusão, ZwQueryKey) passam
//! o PreviousMode corrente, que o despachante já fixa em KernelMode para os
//! exports `Zw*`.

use crate::ntos::cm::key::services::{self as key_services, fields, Kind, NativeHandleInfo};
use crate::ntos::ps::previous_mode;
use crate::rtl::KernelError;

/// ZwOpenKey (ordem dos argumentos da ABI).
pub fn open(output: u64, desired: u32, attributes: u64) -> Result<u32, KernelError> {
    key_services::open(output, desired, attributes, false, 0)
}

/// ZwCreateKey: ClassName é uma UNICODE_STRING e Disposition recebe se a
/// chave foi criada ou aberta.
#[allow(clippy::too_many_arguments)]
pub fn create(output: u64, desired: u32, attributes: u64, title_index: u32, class_name: u64, options: u32, disposition: u64) -> Result<u32, KernelError> {
    key_services::create(output, desired, attributes, title_index, class_name, options, disposition, false)
}

pub fn close_record(handle: u32) -> Option<NativeHandleInfo> {
    key_services::close_record(handle)
}

fn kernel_previous_mode() -> Result<bool, KernelError> {
    Ok(previous_mode::get()? != 0)
}

fn key(kind: Kind, handle: u64, arguments: &[(&'static str, u64)]) -> Result<u32, KernelError> {
    key_services::key_operation(kind, handle, &fields(arguments), kernel_previous_mode()?)
}

/// ZwSetValueKey(handle, name, titleIndex, type, data, length).
pub fn set_value(handle: u64, name: u64, title_index: u64, value_type: u64, data: u64, length: u64) -> Result<u32, KernelError> {
    key(Kind::Set, handle, &[("name", name), ("title", title_index), ("type", value_type), ("data", data), ("length", length)])
}

/// ZwQueryValueKey(handle, name, class, out, length, returned).
pub fn query_value(handle: u64, name: u64, class: u64, output: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    key(Kind::QueryValue, handle, &[("name", name), ("klass", class), ("out", output), ("length", length), ("returned", returned)])
}

/// ZwEnumerateKey(handle, index, class, out, length, returned).
pub fn enumerate_key(handle: u64, index: u64, class: u64, output: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    key(Kind::EnumerateKey, handle, &[("index", index), ("klass", class), ("out", output), ("length", length), ("returned", returned)])
}

/// ZwEnumerateValueKey(handle, index, class, out, length, returned).
pub fn enumerate_value(handle: u64, index: u64, class: u64, output: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    key(Kind::EnumerateValue, handle, &[("index", index), ("klass", class), ("out", output), ("length", length), ("returned", returned)])
}

/// ZwDeleteKey(handle).
pub fn delete_key(handle: u64) -> Result<u32, KernelError> {
    key(Kind::DeleteKey, handle, &[])
}

/// ZwDeleteValueKey(handle, name).
pub fn delete_value(handle: u64, name: u64) -> Result<u32, KernelError> {
    key(Kind::DeleteValue, handle, &[("name", name)])
}

/// ZwQueryKey(handle, class, out, length, returned).
pub fn query_key(handle: u64, class: u64, output: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    key(Kind::QueryKey, handle, &[("klass", class), ("out", output), ("length", length), ("returned", returned)])
}
