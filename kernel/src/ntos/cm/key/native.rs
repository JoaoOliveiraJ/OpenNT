//! Pontos de entrada de kernel do registro — `system32/ntos/cm/native-keys.js`.
//!
//! PreviousMode zero; os ponteiros de saída continuam do chamador e o corpo
//! das operações fica em `key_services`.

use crate::ntos::cm::key::services::{self as key_services, NativeHandleInfo};
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
