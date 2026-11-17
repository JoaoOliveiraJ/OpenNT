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

/// `_SYSTEM_GDI_DRIVER_INFORMATION` (ZwSetSystemInformation
/// (SystemLoadGdiDriverInformation, classe 26, e
/// SystemLoadGdiDriverInSystemSpace, classe 54); 0x38 bytes): o nome da
/// imagem e o que a carga devolve.
#[repr(C)]
pub struct SystemGdiDriverInformation {
    pub driver_name: UnicodeString,
    pub image_address: Field<u64>,
    /// O ImageHandle do MmLoadSystemImage (a entrada do loader).
    pub section_pointer: Field<u64>,
    pub entry_point: Field<u64>,
    pub export_section_pointer: Field<u64>,
    pub image_length: Field<u32>,
    pub _padding: Field<u32>,
}

unsafe impl NtStruct for SystemGdiDriverInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemGdiDriverInformation>() == 0x38);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, driver_name) == 0x0);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, image_address) == 0x10);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, section_pointer) == 0x18);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, entry_point) == 0x20);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, export_section_pointer) == 0x28);
    assert!(core::mem::offset_of!(SystemGdiDriverInformation, image_length) == 0x30);
};

/// A saída de 0x40 bytes do ZwPowerInformation(SessionPowerInit, nível 41),
/// como o NtPowerInformation 19041 a monta (0x6f123a): dois ponteiros para
/// BOOLEANs do Po que o win32k lê e grava, os valores de configuração de
/// energia da sessão (de PopPowerSettingValues), o estado do economizador
/// de energia, a tampa aberta e o TTM ligado. Os nomes seguem a origem de
/// cada campo.
#[repr(C)]
pub struct PowerSessionInit {
    /// -> PopNoMoreInput (BOOLEAN).
    pub no_more_input: Field<u64>,
    /// -> PopHiberBootForceMonitorOff (BOOLEAN).
    pub hiber_boot_force_monitor_off: Field<u64>,
    pub reserved: Field<u32>,
    /// PopPowerSettingValues + 0x10C.
    pub setting_10c: Field<u32>,
    /// PopPowerSettingValues + 0xF1 != 0.
    pub setting_f1_present: Field<u32>,
    /// PopPowerSettingValues + 0xEC.
    pub setting_ec: Field<u32>,
    /// PopPowerSettingValues + 0x110, 0x114 e 0x118.
    pub setting_110: Field<u32>,
    pub setting_114: Field<u32>,
    pub setting_118: Field<u32>,
    /// PopPowerSettingValues + 0x120.
    pub setting_120: Field<u32>,
    /// PopEsState == 1 (economizador de energia ligado).
    pub energy_saver_on: Field<u8>,
    /// PopLidOpened.
    pub lid_opened: Field<u8>,
    pub _padding: [Field<u8>; 2],
    /// PopPowerSettingValues + 0x11C.
    pub setting_11c: Field<u32>,
    /// TtmpEnabled == 1.
    pub ttm_enabled: Field<u8>,
    pub _tail: [Field<u8>; 7],
}

unsafe impl NtStruct for PowerSessionInit {}

const _: () = {
    assert!(core::mem::size_of::<PowerSessionInit>() == 0x40);
    assert!(core::mem::offset_of!(PowerSessionInit, no_more_input) == 0x0);
    assert!(core::mem::offset_of!(PowerSessionInit, hiber_boot_force_monitor_off) == 0x8);
    assert!(core::mem::offset_of!(PowerSessionInit, reserved) == 0x10);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_10c) == 0x14);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_f1_present) == 0x18);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_ec) == 0x1C);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_110) == 0x20);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_120) == 0x2C);
    assert!(core::mem::offset_of!(PowerSessionInit, energy_saver_on) == 0x30);
    assert!(core::mem::offset_of!(PowerSessionInit, lid_opened) == 0x31);
    assert!(core::mem::offset_of!(PowerSessionInit, setting_11c) == 0x34);
    assert!(core::mem::offset_of!(PowerSessionInit, ttm_enabled) == 0x38);
};

/// `SYSTEM_BATTERY_STATE` (NtPowerInformation(SystemBatteryState, nível
/// 5); 0x20 bytes).
#[repr(C)]
pub struct SystemBatteryState {
    pub ac_on_line: Field<u8>,
    pub battery_present: Field<u8>,
    pub charging: Field<u8>,
    pub discharging: Field<u8>,
    pub spare1: [Field<u8>; 3],
    pub tag: Field<u8>,
    pub max_capacity: Field<u32>,
    pub remaining_capacity: Field<u32>,
    pub rate: Field<u32>,
    pub estimated_time: Field<u32>,
    pub default_alert1: Field<u32>,
    pub default_alert2: Field<u32>,
}

unsafe impl NtStruct for SystemBatteryState {}

const _: () = {
    assert!(core::mem::size_of::<SystemBatteryState>() == 0x20);
    assert!(core::mem::offset_of!(SystemBatteryState, ac_on_line) == 0x0);
    assert!(core::mem::offset_of!(SystemBatteryState, battery_present) == 0x1);
    assert!(core::mem::offset_of!(SystemBatteryState, charging) == 0x2);
    assert!(core::mem::offset_of!(SystemBatteryState, discharging) == 0x3);
    assert!(core::mem::offset_of!(SystemBatteryState, spare1) == 0x4);
    assert!(core::mem::offset_of!(SystemBatteryState, tag) == 0x7);
    assert!(core::mem::offset_of!(SystemBatteryState, max_capacity) == 0x8);
    assert!(core::mem::offset_of!(SystemBatteryState, remaining_capacity) == 0xC);
    assert!(core::mem::offset_of!(SystemBatteryState, rate) == 0x10);
    assert!(core::mem::offset_of!(SystemBatteryState, estimated_time) == 0x14);
    assert!(core::mem::offset_of!(SystemBatteryState, default_alert1) == 0x18);
    assert!(core::mem::offset_of!(SystemBatteryState, default_alert2) == 0x1C);
};

/// `_QUOTA_LIMITS_EX` (NtQueryInformationProcess (ProcessQuotaLimits, classe
/// 1); 0x58 bytes; o `_QUOTA_LIMITS` são os primeiros 0x30).
#[repr(C)]
pub struct QuotaLimitsEx {
    pub paged_pool_limit: Field<u64>,
    pub non_paged_pool_limit: Field<u64>,
    pub minimum_working_set_size: Field<u64>,
    pub maximum_working_set_size: Field<u64>,
    pub pagefile_limit: Field<u64>,
    pub time_limit: Field<i64>,
    pub working_set_limit: Field<u64>,
    pub reserved2: Field<u64>,
    pub reserved3: Field<u64>,
    pub reserved4: Field<u64>,
    pub flags: Field<u32>,
    pub cpu_rate_limit: Field<u32>,
}

unsafe impl NtStruct for QuotaLimitsEx {}

const _: () = {
    assert!(core::mem::size_of::<QuotaLimitsEx>() == 0x58);
    assert!(core::mem::offset_of!(QuotaLimitsEx, paged_pool_limit) == 0x0);
    assert!(core::mem::offset_of!(QuotaLimitsEx, non_paged_pool_limit) == 0x8);
    assert!(core::mem::offset_of!(QuotaLimitsEx, minimum_working_set_size) == 0x10);
    assert!(core::mem::offset_of!(QuotaLimitsEx, maximum_working_set_size) == 0x18);
    assert!(core::mem::offset_of!(QuotaLimitsEx, pagefile_limit) == 0x20);
    assert!(core::mem::offset_of!(QuotaLimitsEx, time_limit) == 0x28);
    assert!(core::mem::offset_of!(QuotaLimitsEx, working_set_limit) == 0x30);
    assert!(core::mem::offset_of!(QuotaLimitsEx, reserved2) == 0x38);
    assert!(core::mem::offset_of!(QuotaLimitsEx, reserved3) == 0x40);
    assert!(core::mem::offset_of!(QuotaLimitsEx, reserved4) == 0x48);
    assert!(core::mem::offset_of!(QuotaLimitsEx, flags) == 0x50);
    assert!(core::mem::offset_of!(QuotaLimitsEx, cpu_rate_limit) == 0x54);
};

/// `_VM_COUNTERS_EX2` (NtQueryInformationProcess (ProcessVmCounters, classe
/// 3); 0x70 bytes; o `_VM_COUNTERS` são os primeiros 0x58 e o
/// `_VM_COUNTERS_EX` os primeiros 0x60).
#[repr(C)]
pub struct VmCountersEx2 {
    pub peak_virtual_size: Field<u64>,
    pub virtual_size: Field<u64>,
    pub page_fault_count: Field<u32>,
    pub _pad_14: Field<u32>,
    pub peak_working_set_size: Field<u64>,
    pub working_set_size: Field<u64>,
    pub quota_peak_paged_pool_usage: Field<u64>,
    pub quota_paged_pool_usage: Field<u64>,
    pub quota_peak_non_paged_pool_usage: Field<u64>,
    pub quota_non_paged_pool_usage: Field<u64>,
    pub pagefile_usage: Field<u64>,
    pub peak_pagefile_usage: Field<u64>,
    pub private_usage: Field<u64>,
    pub private_working_set_size: Field<u64>,
    pub shared_commit_usage: Field<u64>,
}

unsafe impl NtStruct for VmCountersEx2 {}

const _: () = {
    assert!(core::mem::size_of::<VmCountersEx2>() == 0x70);
    assert!(core::mem::offset_of!(VmCountersEx2, peak_virtual_size) == 0x0);
    assert!(core::mem::offset_of!(VmCountersEx2, virtual_size) == 0x8);
    assert!(core::mem::offset_of!(VmCountersEx2, page_fault_count) == 0x10);
    assert!(core::mem::offset_of!(VmCountersEx2, peak_working_set_size) == 0x18);
    assert!(core::mem::offset_of!(VmCountersEx2, working_set_size) == 0x20);
    assert!(core::mem::offset_of!(VmCountersEx2, quota_peak_paged_pool_usage) == 0x28);
    assert!(core::mem::offset_of!(VmCountersEx2, quota_paged_pool_usage) == 0x30);
    assert!(core::mem::offset_of!(VmCountersEx2, quota_peak_non_paged_pool_usage) == 0x38);
    assert!(core::mem::offset_of!(VmCountersEx2, quota_non_paged_pool_usage) == 0x40);
    assert!(core::mem::offset_of!(VmCountersEx2, pagefile_usage) == 0x48);
    assert!(core::mem::offset_of!(VmCountersEx2, peak_pagefile_usage) == 0x50);
    assert!(core::mem::offset_of!(VmCountersEx2, private_usage) == 0x58);
    assert!(core::mem::offset_of!(VmCountersEx2, private_working_set_size) == 0x60);
    assert!(core::mem::offset_of!(VmCountersEx2, shared_commit_usage) == 0x68);
};

/// `_SYSTEM_MEMORY_USAGE_INFORMATION` (NtQuerySystemInformation
/// (SystemMemoryUsageInformation, classe 182); 0x38 bytes).
#[repr(C)]
pub struct SystemMemoryUsageInformation {
    pub total_physical_bytes: Field<u64>,
    pub available_bytes: Field<u64>,
    pub resident_available_bytes: Field<u64>,
    pub committed_bytes: Field<u64>,
    pub shared_committed_bytes: Field<u64>,
    pub commit_limit_bytes: Field<u64>,
    pub peak_commitment_bytes: Field<u64>,
}

unsafe impl NtStruct for SystemMemoryUsageInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemMemoryUsageInformation>() == 0x38);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, total_physical_bytes) == 0x0);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, available_bytes) == 0x8);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, resident_available_bytes) == 0x10);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, committed_bytes) == 0x18);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, shared_committed_bytes) == 0x20);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, commit_limit_bytes) == 0x28);
    assert!(core::mem::offset_of!(SystemMemoryUsageInformation, peak_commitment_bytes) == 0x30);
};
