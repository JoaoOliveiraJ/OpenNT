//! Estruturas públicas das classes de informação de job (winnt.h) que não
//! constam dos símbolos do ntoskrnl 19041: as que o
//! NtQueryInformationJobObject e o NtSetInformationJobObject trocam com o
//! chamador. Layout x64, conferido em compilação contra os tamanhos da
//! PspJobInfoLengths.

use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::LargeInteger;

/// `_JOBOBJECT_BASIC_ACCOUNTING_INFORMATION` (JobObjectBasicAccountingInformation,
/// 0x30 bytes).
#[repr(C)]
pub struct JobobjectBasicAccountingInformation {
    pub total_user_time: LargeInteger,
    pub total_kernel_time: LargeInteger,
    pub this_period_total_user_time: LargeInteger,
    pub this_period_total_kernel_time: LargeInteger,
    pub total_page_fault_count: Field<u32>,
    pub total_processes: Field<u32>,
    pub active_processes: Field<u32>,
    pub total_terminated_processes: Field<u32>,
}

unsafe impl NtStruct for JobobjectBasicAccountingInformation {}

/// `_IO_COUNTERS` (0x30 bytes).
#[repr(C)]
pub struct IoCounters {
    pub read_operation_count: Field<u64>,
    pub write_operation_count: Field<u64>,
    pub other_operation_count: Field<u64>,
    pub read_transfer_count: Field<u64>,
    pub write_transfer_count: Field<u64>,
    pub other_transfer_count: Field<u64>,
}

unsafe impl NtStruct for IoCounters {}

/// `_JOBOBJECT_BASIC_AND_IO_ACCOUNTING_INFORMATION`
/// (JobObjectBasicAndIoAccountingInformation, 0x60 bytes).
#[repr(C)]
pub struct JobobjectBasicAndIoAccountingInformation {
    pub basic_info: JobobjectBasicAccountingInformation,
    pub io_info: IoCounters,
}

unsafe impl NtStruct for JobobjectBasicAndIoAccountingInformation {}

/// `_JOBOBJECT_BASIC_LIMIT_INFORMATION` (JobObjectBasicLimitInformation,
/// 0x40 bytes).
#[repr(C)]
pub struct JobobjectBasicLimitInformation {
    pub per_process_user_time_limit: LargeInteger,
    pub per_job_user_time_limit: LargeInteger,
    pub limit_flags: Field<u32>,
    _pad_14: Reserved<4>,
    pub minimum_working_set_size: Field<u64>,
    pub maximum_working_set_size: Field<u64>,
    pub active_process_limit: Field<u32>,
    _pad_2c: Reserved<4>,
    pub affinity: Field<u64>,
    pub priority_class: Field<u32>,
    pub scheduling_class: Field<u32>,
}

unsafe impl NtStruct for JobobjectBasicLimitInformation {}

/// `_JOBOBJECT_EXTENDED_LIMIT_INFORMATION` (JobObjectExtendedLimitInformation,
/// 0x90 bytes) com o JobTotalMemoryLimit da forma de 0x98 bytes que o
/// kernel também aceita.
#[repr(C)]
pub struct JobobjectExtendedLimitInformation {
    pub basic_limit_information: JobobjectBasicLimitInformation,
    pub io_info: IoCounters,
    pub process_memory_limit: Field<u64>,
    pub job_memory_limit: Field<u64>,
    pub peak_process_memory_used: Field<u64>,
    pub peak_job_memory_used: Field<u64>,
    pub job_total_memory_limit: Field<u64>,
}

unsafe impl NtStruct for JobobjectExtendedLimitInformation {}

/// `_JOBOBJECT_BASIC_PROCESS_ID_LIST` (JobObjectBasicProcessIdList): o
/// cabeçalho; os ULONG_PTR dos PIDs seguem em 8.
#[repr(C)]
pub struct JobobjectBasicProcessIdList {
    pub number_of_assigned_processes: Field<u32>,
    pub number_of_process_ids_in_list: Field<u32>,
    pub process_id_list: [Field<u64>; 1],
}

unsafe impl NtStruct for JobobjectBasicProcessIdList {}

/// `_JOBOBJECT_ASSOCIATE_COMPLETION_PORT`
/// (JobObjectAssociateCompletionPortInformation, 0x10 bytes).
#[repr(C)]
pub struct JobobjectAssociateCompletionPort {
    pub completion_key: Field<u64>,
    pub completion_port: Field<u64>,
}

unsafe impl NtStruct for JobobjectAssociateCompletionPort {}

/// `_JOBOBJECT_SECURITY_LIMIT_INFORMATION` (JobObjectSecurityLimitInformation,
/// 0x28 bytes).
#[repr(C)]
pub struct JobobjectSecurityLimitInformation {
    pub security_limit_flags: Field<u32>,
    _pad_4: Reserved<4>,
    pub job_token: Field<u64>,
    pub sids_to_disable: Field<u64>,
    pub privileges_to_delete: Field<u64>,
    pub restricted_sids: Field<u64>,
}

unsafe impl NtStruct for JobobjectSecurityLimitInformation {}

/// `_JOBOBJECT_FREEZE_INFORMATION` (JobObjectFreezeInformation, 0x10 bytes).
#[repr(C)]
pub struct JobobjectFreezeInformation {
    pub flags: Field<u32>,
    pub freeze: Field<u8>,
    pub swap: Field<u8>,
    _reserved0: Reserved<2>,
    pub wake_filter: Field<u64>,
}

unsafe impl NtStruct for JobobjectFreezeInformation {}

/// `_JOBOBJECT_MEMORY_USAGE_INFORMATION_V2` (JobObjectMemoryUsageInformation:
/// os 0x10 primeiros bytes são a forma V1).
#[repr(C)]
pub struct JobobjectMemoryUsageInformation {
    pub job_memory: Field<u64>,
    pub peak_job_memory_used: Field<u64>,
    pub job_shared_memory: Field<u64>,
    _reserved: Reserved<0x10>,
}

unsafe impl NtStruct for JobobjectMemoryUsageInformation {}

const _: () = {
    assert!(core::mem::size_of::<JobobjectBasicAccountingInformation>() == 0x30);
    assert!(core::mem::offset_of!(JobobjectBasicAccountingInformation, total_page_fault_count) == 0x20);
    assert!(core::mem::offset_of!(JobobjectBasicAccountingInformation, total_terminated_processes) == 0x2C);
    assert!(core::mem::size_of::<IoCounters>() == 0x30);
    assert!(core::mem::size_of::<JobobjectBasicAndIoAccountingInformation>() == 0x60);
    assert!(core::mem::size_of::<JobobjectBasicLimitInformation>() == 0x40);
    assert!(core::mem::offset_of!(JobobjectBasicLimitInformation, limit_flags) == 0x10);
    assert!(core::mem::offset_of!(JobobjectBasicLimitInformation, active_process_limit) == 0x28);
    assert!(core::mem::offset_of!(JobobjectBasicLimitInformation, affinity) == 0x30);
    assert!(core::mem::offset_of!(JobobjectBasicLimitInformation, scheduling_class) == 0x3C);
    assert!(core::mem::size_of::<JobobjectExtendedLimitInformation>() == 0x98);
    assert!(core::mem::offset_of!(JobobjectExtendedLimitInformation, process_memory_limit) == 0x70);
    assert!(core::mem::offset_of!(JobobjectExtendedLimitInformation, peak_job_memory_used) == 0x88);
    assert!(core::mem::size_of::<JobobjectBasicProcessIdList>() == 0x10);
    assert!(core::mem::size_of::<JobobjectAssociateCompletionPort>() == 0x10);
    assert!(core::mem::size_of::<JobobjectSecurityLimitInformation>() == 0x28);
    assert!(core::mem::size_of::<JobobjectFreezeInformation>() == 0x10);
    assert!(core::mem::size_of::<JobobjectMemoryUsageInformation>() == 0x28);
};
