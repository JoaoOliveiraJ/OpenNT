//! Buffers de serviços Nt* do modo usuário que não constam dos símbolos do
//! ntoskrnl nem de `wdk.rs`.
//!
//! Mesmo estilo de `wdk.rs`: `#[repr(C)]`, folhas `Field<T>`, layout x64 e
//! asserções de tamanho e de todos os offsets. Cada estrutura cita o serviço
//! que define o buffer.

use super::*;

/// `_SYSTEM_TIMEOFDAY_INFORMATION` (NtQuerySystemInformation
/// (SystemTimeOfDayInformation, classe 3); 0x30 bytes).
#[repr(C)]
pub struct SystemTimeofdayInformation {
    pub boot_time: Field<i64>,
    pub current_time: Field<i64>,
    pub time_zone_bias: Field<i64>,
    pub time_zone_id: Field<u32>,
    pub reserved: Field<u32>,
    pub boot_time_bias: Field<u64>,
    pub sleep_time_bias: Field<u64>,
}

unsafe impl NtStruct for SystemTimeofdayInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemTimeofdayInformation>() == 0x30);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, boot_time) == 0x0);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, current_time) == 0x8);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, time_zone_bias) == 0x10);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, time_zone_id) == 0x18);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, reserved) == 0x1C);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, boot_time_bias) == 0x20);
    assert!(core::mem::offset_of!(SystemTimeofdayInformation, sleep_time_bias) == 0x28);
};

/// `_SYSTEM_MANUFACTURING_INFORMATION` (NtQuerySystemInformation
/// (SystemManufacturingInformation, classe 157); 0x18 bytes): Options e o
/// nome do perfil, cujo texto vem logo depois da estrutura.
#[repr(C)]
pub struct SystemManufacturingInformation {
    pub options: Field<u32>,
    pub _padding: Field<u32>,
    pub profile_name: UnicodeString,
}

unsafe impl NtStruct for SystemManufacturingInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemManufacturingInformation>() == 0x18);
    assert!(core::mem::offset_of!(SystemManufacturingInformation, options) == 0x0);
    assert!(core::mem::offset_of!(SystemManufacturingInformation, profile_name) == 0x8);
};

/// `_SYSTEM_MEMORY_LIST_INFORMATION` (NtQuerySystemInformation
/// (SystemMemoryListInformation, classe 80); 0xB0 bytes).
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
    assert!(core::mem::size_of::<SystemMemoryListInformation>() == 0xB0);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, zero_page_count) == 0x0);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, free_page_count) == 0x8);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, modified_page_count) == 0x10);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, modified_no_write_page_count) == 0x18);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, bad_page_count) == 0x20);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, page_count_by_priority) == 0x28);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, repurposed_pages_by_priority) == 0x68);
    assert!(core::mem::offset_of!(SystemMemoryListInformation, modified_page_count_page_file) == 0xA8);
};

/// `_API_SET_NAMESPACE` (cabeçalho do schema v6 apontado por
/// `PEB.ApiSetMap`; 0x1C bytes).
#[repr(C)]
pub struct ApiSetNamespace {
    pub version: Field<u32>,
    pub size: Field<u32>,
    pub flags: Field<u32>,
    pub count: Field<u32>,
    pub entry_offset: Field<u32>,
    pub hash_offset: Field<u32>,
    pub hash_factor: Field<u32>,
}

unsafe impl NtStruct for ApiSetNamespace {}

const _: () = {
    assert!(core::mem::size_of::<ApiSetNamespace>() == 0x1C);
    assert!(core::mem::offset_of!(ApiSetNamespace, version) == 0x0);
    assert!(core::mem::offset_of!(ApiSetNamespace, size) == 0x4);
    assert!(core::mem::offset_of!(ApiSetNamespace, flags) == 0x8);
    assert!(core::mem::offset_of!(ApiSetNamespace, count) == 0xC);
    assert!(core::mem::offset_of!(ApiSetNamespace, entry_offset) == 0x10);
    assert!(core::mem::offset_of!(ApiSetNamespace, hash_offset) == 0x14);
    assert!(core::mem::offset_of!(ApiSetNamespace, hash_factor) == 0x18);
};

/// `_WORKER_FACTORY_DEFERRED_WORK` (NtWaitForWorkViaWorkerFactory,
/// DeferredWork; 0x18 bytes).
#[repr(C)]
pub struct WorkerFactoryDeferredWork {
    /// -> `_PORT_MESSAGE`
    pub alpc_send_message: Field<u64>,
    /// -> `void`
    pub alpc_send_message_port: Field<u64>,
    pub alpc_send_message_flags: Field<u32>,
    pub flags: Field<u32>,
}

unsafe impl NtStruct for WorkerFactoryDeferredWork {}

const _: () = {
    assert!(core::mem::size_of::<WorkerFactoryDeferredWork>() == 0x18);
    assert!(core::mem::offset_of!(WorkerFactoryDeferredWork, alpc_send_message) == 0x0);
    assert!(core::mem::offset_of!(WorkerFactoryDeferredWork, alpc_send_message_port) == 0x8);
    assert!(core::mem::offset_of!(WorkerFactoryDeferredWork, alpc_send_message_flags) == 0x10);
    assert!(core::mem::offset_of!(WorkerFactoryDeferredWork, flags) == 0x14);
};
