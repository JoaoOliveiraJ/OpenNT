//! KeAllocateProcessorProfileStructures.
//!
//! As estruturas de perfil de um processador são as
//! PROCESSOR_PROFILE_CONTROL_AREA (0xA0 bytes, a PEBS_DS_SAVE_AREA) que a
//! PRCB publica em ProcessorProfileControlArea e ProfileEventIndexAddress.
//! O export é o corpo nativo de `hal/amd64/private_entries.rs`, a sequência
//! do ntoskrnl 19041 (rva 0x3b5e70) até o CALL do MmAllocateIndependentPages
//! em +0xc6, que drivers seguem para achar essa rotina. A chamada pela
//! tabela de exports entra no mesmo corpo.

use crate::hal::amd64::{native_call, private_entries};
use crate::ntos::mm::kernel_address;
use crate::rtl::KernelError;

/// KeAllocateProcessorProfileStructures(ProcessorCount, BufferSize,
/// ProfileStructures, Allocate): devolve o NTSTATUS.
pub fn allocate_structures(processor_count: u32, buffer_size: u64, profile_structures: u64, allocate: u8) -> Result<u32, KernelError> {
    let entry = private_entries::entry("ke_allocate_processor_profile_structures").ok_or_else(|| KernelError::new("KeAllocateProcessorProfileStructures native body is missing"))?;
    let address = kernel_address::image_address(entry)?;
    Ok(native_call::call(address, &[processor_count as u64, buffer_size, profile_structures, allocate as u64]) as u32)
}
