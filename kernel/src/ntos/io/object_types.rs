//! Tipos de objeto do I/O Manager — as células IoDriverObjectType e
//! IoFileObjectType e o mapeamento genérico do FILE_OBJECT (IopFileMapping,
//! devolvido por IoGetFileObjectGenericMapping).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{GenericMapping, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_data;

/// IoGetFileObjectGenericMapping: &IopFileMapping (os quatro valores reais).
static FILE_MAPPING: AtomicU64 = AtomicU64::new(0);

/// Endereço da célula IoDriverObjectType.
pub fn driver_object_type() -> u64 {
    kernel_data::address("IoDriverObjectType").unwrap_or_else(|error| panic!("IoDriverObjectType: {error}"))
}

/// Endereço da célula IoFileObjectType.
pub fn file_object_type() -> u64 {
    kernel_data::address("IoFileObjectType").unwrap_or_else(|error| panic!("IoFileObjectType: {error}"))
}

/// GENERIC_MAPPING do FILE_OBJECT, criado na primeira consulta.
pub fn file_object_generic_mapping() -> u64 {
    let mut pointer = FILE_MAPPING.load(Ordering::Acquire);
    if pointer == 0 {
        pointer = guest::alloc_bytes(GenericMapping::SIZE);
        // SAFETY: GENERIC_MAPPING recém-alocado.
        let mapping = unsafe { GenericMapping::at(pointer) };
        mapping.generic_read.set(0x0012_0089);
        mapping.generic_write.set(0x0012_0116);
        mapping.generic_execute.set(0x0012_00A0);
        mapping.generic_all.set(0x001F_01FF);
        FILE_MAPPING.store(pointer, Ordering::Release);
    }
    pointer
}
