//! Classes de informação do NT usadas pelos self-tests de modo usuário que
//! não constam dos símbolos do ntoskrnl nem de `wdk.rs`.
//!
//! Mesmo estilo das geradas: `#[repr(C)]` só de células, com tamanho e
//! offsets conferidos em compilação.

use super::{Field, NtStruct};

/// `SYSTEM_MEMORY_LIST_INFORMATION` (classe `SystemMemoryListInformation`,
/// 80) como o Windows 10 x64 a devolve: contagens de páginas por lista.
#[repr(C)]
pub struct SystemMemoryListInformation {
    pub zero_page_count: Field<u64>,
    pub free_page_count: Field<u64>,
    pub modified_page_count: Field<u64>,
    pub modified_no_write_page_count: Field<u64>,
    pub bad_page_count: Field<u64>,
    pub page_count_by_priority: [Field<u64>; 8],
    pub repurposed_pages_by_priority: [Field<u64>; 8],
    pub modified_page_count_page_file: Field<u64>,
}

unsafe impl NtStruct for SystemMemoryListInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemMemoryListInformation>() == 0xb0);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, free_page_count) == 0x8);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, page_count_by_priority) == 0x28);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, repurposed_pages_by_priority) == 0x68);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, modified_page_count_page_file) == 0xa8);
};
