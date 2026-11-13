//! Layouts reais das structs do kernel NT x64 — `system32/win32/nt-abi.js`.
//!
//! Extraídos do WDK 10.0.26100 (km/wdm.h) e conferidos por disassembly do
//! ntoskrnl.exe do Windows 10 22H2. Fonte única da ABI convidado<->kernel:
//! drivers compilados com o ntddk.h real dependem destes offsets.
#![allow(dead_code)]

/// DRIVER_OBJECT (wdm.h): MajorFunction deve ser o último campo.
pub mod driver_object {
    pub const TYPE: u64 = 0; // IO_TYPE_DRIVER = 4
    pub const SIZE: u64 = 2;
    pub const DEVICE_OBJECT: u64 = 0x08;
    pub const FLAGS: u64 = 0x10;
    pub const DRIVER_START: u64 = 0x18;
    pub const DRIVER_SIZE: u64 = 0x20;
    pub const DRIVER_SECTION: u64 = 0x28;
    pub const DRIVER_EXTENSION: u64 = 0x30;
    pub const DRIVER_NAME: u64 = 0x38; // UNICODE_STRING (16B)
    pub const HARDWARE_DATABASE: u64 = 0x48;
    pub const FAST_IO_DISPATCH: u64 = 0x50;
    pub const DRIVER_INIT: u64 = 0x58;
    pub const DRIVER_START_IO: u64 = 0x60;
    pub const DRIVER_UNLOAD: u64 = 0x68;
    pub const MAJOR_FUNCTION: u64 = 0x70; // [29]
    pub const STRUCT_SIZE: u64 = 0x70 + 29 * 8;
    pub const IO_TYPE: u16 = 4;
}

/// DRIVER_EXTENSION (wdm.h).
pub mod driver_extension {
    pub const DRIVER_OBJECT: u64 = 0x00;
    pub const ADD_DEVICE: u64 = 0x08;
    pub const COUNT: u64 = 0x10;
    pub const SERVICE_KEY_NAME: u64 = 0x18; // UNICODE_STRING
    pub const SIZE: u64 = 0x40;
}

/// DEVICE_OBJECT (wdm.h x64, sizeof = 0x150).
pub mod device_object {
    pub const TYPE: u64 = 0; // IO_TYPE_DEVICE = 3
    pub const SIZE: u64 = 2;
    pub const REFERENCE_COUNT: u64 = 4;
    pub const DRIVER_OBJECT: u64 = 0x08;
    pub const NEXT_DEVICE: u64 = 0x10;
    pub const ATTACHED_DEVICE: u64 = 0x18;
    pub const CURRENT_IRP: u64 = 0x20;
    pub const TIMER: u64 = 0x28;
    pub const FLAGS: u64 = 0x30;
    pub const CHARACTERISTICS: u64 = 0x34;
    pub const VPB: u64 = 0x38;
    pub const DEVICE_EXTENSION: u64 = 0x40;
    pub const DEVICE_TYPE: u64 = 0x48;
    pub const STACK_SIZE: u64 = 0x4C;
    pub const QUEUE_LIST: u64 = 0x50;
    pub const DEVICE_QUEUE: u64 = 0x60; // KDEVICE_QUEUE embutido (0x28 bytes)
    pub const DPC: u64 = 0x88; // KDPC embutido (0x40 bytes)
    pub const DEVICE_OBJECT_EXTENSION: u64 = 0x138;
    pub const STRUCT_SIZE: u64 = 0x150;
    pub const IO_TYPE: u16 = 3;
}

/// _DEVOBJ_EXTENSION (kernel 19041).
pub mod devobj_extension {
    pub const STRUCT_SIZE: u64 = 0x70;
    pub const DEVICE_OBJECT: u64 = 8;
    pub const VPB: u64 = 0x48;
}

/// VPB (wdm.h).
pub mod vpb {
    pub const TYPE: u64 = 0;
    pub const SIZE: u64 = 2;
    pub const FLAGS: u64 = 4;
    pub const VOLUME_LABEL_LENGTH: u64 = 6;
    pub const DEVICE_OBJECT: u64 = 8;
    pub const REAL_DEVICE: u64 = 0x10;
    pub const SERIAL_NUMBER: u64 = 0x18;
    pub const REFERENCE_COUNT: u64 = 0x1C;
    pub const VOLUME_LABEL: u64 = 0x20;
    pub const STRUCT_SIZE: u64 = 0x60;
    pub const MOUNTED: u32 = 1;
}

/// IRP (wdm.h).
pub mod irp {
    pub const TYPE: u64 = 0; // IO_TYPE_IRP = 6
    pub const SIZE_FIELD: u64 = 2;
    pub const MDL_ADDRESS: u64 = 0x08;
    pub const FLAGS: u64 = 0x10;
    pub const SYSTEM_BUFFER: u64 = 0x18;
    pub const IO_STATUS: u64 = 0x30;
    pub const IO_STATUS_INFORMATION: u64 = 0x38;
    pub const REQUESTOR_MODE: u64 = 0x40;
    pub const STACK_COUNT: u64 = 0x42;
    pub const CURRENT_LOCATION: u64 = 0x43;
    pub const CANCEL: u64 = 0x44;
    pub const CANCEL_IRQL: u64 = 0x45;
    pub const CANCEL_ROUTINE: u64 = 0x68;
    pub const USER_IOSB: u64 = 0x48;
    pub const USER_EVENT: u64 = 0x50;
    pub const USER_BUFFER: u64 = 0x70;
    pub const THREAD: u64 = 0x98;
    pub const ORIGINAL_FILE_OBJECT: u64 = 0xC0;
    pub const CURRENT_STACK_LOCATION: u64 = 0xB8;
    pub const STRUCT_SIZE: u64 = 0xD0;
    pub const STACK_LOCATION_SIZE: u64 = 0x48;
    pub const IO_TYPE: u16 = 6;
}

/// IO_STACK_LOCATION (wdm.h x64).
pub mod io_stack_location {
    pub const MAJOR: u64 = 0;
    pub const MINOR: u64 = 1;
    pub const FLAGS: u64 = 2;
    pub const CONTROL: u64 = 3; // SL_INVOKE_*
    pub const READ_LENGTH: u64 = 0x08;
    pub const READ_KEY: u64 = 0x10;
    pub const READ_OFFSET: u64 = 0x18;
    pub const IOCTL_OUT_LENGTH: u64 = 0x08;
    pub const IOCTL_IN_LENGTH: u64 = 0x10;
    pub const IOCTL_CODE: u64 = 0x18;
    pub const IOCTL_TYPE3_BUFFER: u64 = 0x20;
    pub const POWER_SYSTEM_CONTEXT: u64 = 0x08;
    pub const POWER_TYPE: u64 = 0x10;
    pub const POWER_STATE: u64 = 0x18;
    pub const POWER_SHUTDOWN_TYPE: u64 = 0x20;
    pub const PNP_ALLOCATED_RESOURCES: u64 = 0x08;
    pub const PNP_ALLOCATED_RESOURCES_TRANSLATED: u64 = 0x10;
    pub const DEVICE_OBJECT: u64 = 0x28;
    pub const FILE_OBJECT: u64 = 0x30;
    pub const COMPLETION_ROUTINE: u64 = 0x38;
    pub const CONTEXT: u64 = 0x40;
    pub const SIZE: u64 = 0x48;
}

pub const SL_INVOKE_ON_CANCEL: u8 = 0x20;
pub const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
pub const SL_INVOKE_ON_ERROR: u8 = 0x80;

/// NTSTATUS do modelo de conclusão (bits do i32).
pub mod status {
    pub const SUCCESS: u32 = 0;
    pub const PENDING: u32 = 0x103;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const INVALID_PARAMETER: u32 = 0xC000_000D;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
}

/// FILE_OBJECT (wdm.h x64).
pub mod file_object {
    pub const TYPE: u64 = 0; // IO_TYPE_FILE = 5
    pub const SIZE: u64 = 2;
    pub const DEVICE_OBJECT: u64 = 0x08;
    pub const FLAGS: u64 = 0x50;
    pub const FILE_NAME: u64 = 0x58;
    pub const CURRENT_BYTE_OFFSET: u64 = 0x68;
    pub const LOCK: u64 = 0x80;
    pub const EVENT: u64 = 0x98;
    pub const IRP_LIST: u64 = 0xC0;
    pub const STRUCT_SIZE: u64 = 0xD8;
}

pub mod io_status_block {
    pub const STATUS: u64 = 0;
    pub const INFORMATION: u64 = 8;
    pub const SIZE: u64 = 0x10;
}

pub mod power_state_type {
    pub const SYSTEM_POWER_STATE: u32 = 0;
    pub const DEVICE_POWER_STATE: u32 = 1;
}

pub mod device_power_state {
    pub const UNSPECIFIED: u32 = 0;
    pub const D0: u32 = 1;
    pub const D1: u32 = 2;
    pub const D2: u32 = 3;
    pub const D3: u32 = 4;
}

pub mod object_attributes {
    pub const LENGTH: u64 = 0;
    pub const ROOT_DIRECTORY: u64 = 0x08;
    pub const OBJECT_NAME: u64 = 0x10;
    pub const ATTRIBUTES: u64 = 0x18;
    pub const SIZE: u64 = 0x30;
}

/// UNICODE_STRING / ANSI_STRING.
pub mod unicode_string {
    pub const LENGTH: u64 = 0;
    pub const MAXIMUM_LENGTH: u64 = 2;
    pub const BUFFER: u64 = 8;
    pub const SIZE: u64 = 0x10;
}

/// DISPATCHER_HEADER (base de KEVENT/KMUTEX/KTIMER).
pub mod dispatcher_header {
    pub const TYPE: u64 = 0;
    pub const SIGNAL_STATE: u64 = 4; // i32
    pub const WAIT_LIST_HEAD: u64 = 8;
    pub const SIZE: u64 = 0x18;
    pub const TYPE_EVENT_NOTIFICATION: u8 = 0;
    pub const TYPE_EVENT_SYNCHRONIZATION: u8 = 1;
    pub const TYPE_MUTANT: u8 = 2;
    pub const MUTEX_OWNER: u64 = 0x28; // KMUTANT x64, após MutantListEntry
}

pub mod kevent {
    pub const SIZE: u64 = 0x18;
}

pub mod kmutex {
    pub const SIZE: u64 = 0x38;
}

/// FAST_MUTEX (wdm.h x64, sizeof 0x38).
pub mod fast_mutex {
    pub const COUNT: u64 = 0x00;
    pub const OWNER: u64 = 0x08;
    pub const CONTENTION: u64 = 0x10;
    pub const EVENT: u64 = 0x18;
    pub const OLD_IRQL: u64 = 0x30;
    pub const SIZE: u64 = 0x38;
}

/// KDPC (wdm.h x64, sizeof 0x40).
pub mod kdpc {
    pub const TYPE: u64 = 0x00; // DpcObject = 0x13
    pub const IMPORTANCE: u64 = 0x01;
    pub const NUMBER: u64 = 0x02;
    pub const DPC_LIST_ENTRY: u64 = 0x08;
    pub const PROCESSOR_HISTORY: u64 = 0x10;
    pub const ROUTINE: u64 = 0x18;
    pub const CONTEXT: u64 = 0x20;
    pub const SYSARG1: u64 = 0x28;
    pub const SYSARG2: u64 = 0x30;
    pub const DPC_DATA: u64 = 0x38; // não nulo enquanto enfileirado
    pub const SIZE: u64 = 0x40;
    pub const TYPE_DPC: u8 = 0x13;
    pub const IMPORTANCE_MEDIUM: u8 = 1;
}

/// KTIMER (wdm.h x64).
pub mod ktimer {
    pub const TYPE: u64 = 0; // TimerNotificationObject=8 / Sync=9
    pub const SIGNAL_STATE: u64 = 4;
    pub const DUE_TIME: u64 = 0x18;
    pub const TIMER_LIST_ENTRY: u64 = 0x20;
    pub const DPC: u64 = 0x30;
    pub const PERIOD: u64 = 0x38;
    pub const SIZE: u64 = 0x40;
    pub const TIMER_NOTIFICATION: u8 = 8;
    pub const TIMER_SYNCHRONIZATION: u8 = 9;
}

/// IO_WORKITEM (WORK_QUEUE_ITEM + contexto).
pub mod io_workitem {
    pub const LIST_FLINK: u64 = 0x00;
    pub const LIST_BLINK: u64 = 0x08;
    pub const FUNCTION: u64 = 0x10;
    pub const CONTEXT: u64 = 0x18;
    pub const DEVICE_OBJECT: u64 = 0x20;
    pub const TYPE: u64 = 0x28;
    pub const QUEUED: u64 = 0x2C;
    pub const SIZE: u64 = 0x30;
}

pub mod key_value_partial {
    pub const TITLE_INDEX: u64 = 0;
    pub const TYPE: u64 = 4;
    pub const DATA_LENGTH: u64 = 8;
    pub const DATA: u64 = 12;
}

/// MDL (wdm.h x64; o array de PFNs começa em 0x30).
pub mod mdl {
    pub const NEXT: u64 = 0x00;
    pub const SIZE: u64 = 0x08;
    pub const MDL_FLAGS: u64 = 0x0A;
    pub const PROCESS: u64 = 0x10;
    pub const MAPPED_SYSTEM_VA: u64 = 0x18;
    pub const START_VA: u64 = 0x20;
    pub const BYTE_COUNT: u64 = 0x28;
    pub const BYTE_OFFSET: u64 = 0x2C;
    pub const PFN_ARRAY: u64 = 0x30;
    pub const FLAG_MAPPED_TO_SYSTEM_VA: u16 = 0x0001;
    pub const FLAG_PAGES_LOCKED: u16 = 0x0002;
    pub const FLAG_SOURCE_NONPAGED: u16 = 0x0004;
}

/// GENERAL_LOOKASIDE x64.
pub mod lookaside_list {
    pub const DEPTH: u64 = 0x10;
    pub const MAXIMUM_DEPTH: u64 = 0x12;
    pub const ALLOC_COUNT: u64 = 0x14;
    pub const ALLOC_MISSES: u64 = 0x18;
    pub const FREE_COUNT: u64 = 0x1C;
    pub const FREE_MISSES: u64 = 0x20;
    pub const POOL_TYPE: u64 = 0x24;
    pub const TAG: u64 = 0x28;
    pub const BLOCK_SIZE: u64 = 0x2C;
    pub const ALLOCATE_CALLBACK: u64 = 0x30;
    pub const FREE_CALLBACK: u64 = 0x38;
    pub const REGISTRY_ENTRY: u64 = 0x40;
    pub const LAST_ALLOC_COUNT: u64 = 0x50;
    pub const LAST_ALLOC_MISSES: u64 = 0x54;
    pub const SIZE: u64 = 0x80;
}

/// KTHREAD/ETHREAD (Windows 10 22H2, offsets conferidos por RE).
pub mod kthread {
    pub const QUANTUM_TARGET: u64 = 0x20;
    pub const INITIAL_STACK: u64 = 0x28;
    pub const STACK_LIMIT: u64 = 0x30;
    pub const STACK_BASE: u64 = 0x38;
    pub const TEB: u64 = 0xF0;
    pub const WIN32_THREAD: u64 = 0x1C8;
    /// ETHREAD.CreateTime.
    pub const CREATE_TIME: u64 = 0x430;
    pub const THREAD_LOCK: u64 = 0x40;
    pub const CYCLE_TIME: u64 = 0x48;
    pub const WAIT_REGISTER: u64 = 0x70;
    pub const RUNNING: u64 = 0x71;
    pub const ALERTED: u64 = 0x72;
    pub const MISC_FLAGS: u64 = 0x74; // SystemThread é o bit 10
    pub const THREAD_FLAGS: u64 = 0x78;
    pub const READY_TIME: u64 = 0x84;
    pub const TRAP_FRAME: u64 = 0x90;
    pub const APC_STATE: u64 = 0x98;
    pub const APC_STATE_PROCESS: u64 = 0xB8;
    pub const PRIORITY: u64 = 0xC3;
    pub const WAIT_STATUS: u64 = 0xC8;
    pub const WAIT_LIST_ENTRY: u64 = 0xD8;
    pub const STATE: u64 = 0x184;
    pub const WAIT_MODE: u64 = 0x187;
    pub const WAIT_TIME: u64 = 0x1B4;
    pub const KERNEL_APC_DISABLE: u64 = 0x1E4;
    pub const SPECIAL_APC_DISABLE: u64 = 0x1E6;
    pub const PROCESS: u64 = 0x220;
    pub const PREVIOUS_MODE: u64 = 0x232;
    pub const BASE_PRIORITY: u64 = 0x233;
    pub const PRIORITY_DECREMENT: u64 = 0x234;
    pub const SATURATION: u64 = 0x285;
    pub const QUANTUM_RESET: u64 = 0x28B;
    pub const PRIORITY_FLOOR_SUMMARY: u64 = 0x358;
    pub const FOREGROUND_LOSS_TIME: u64 = 0x368;
    pub const OTHER_OPERATION_COUNT: u64 = 0x390;
    pub const CID: u64 = 0x478;
    pub const CID_UNIQUE_PROCESS: u64 = 0x478;
    pub const CID_UNIQUE_THREAD: u64 = 0x480;
    pub const IRP_LIST_HEAD: u64 = 0x4B0;
    pub const THREAD_LIST_ENTRY: u64 = 0x4E8;
    pub const RUNDOWN_PROTECT: u64 = 0x4F8;
    pub const INSERTION_LOCK: u64 = 0x500;
    pub const CROSS_THREAD_FLAGS: u64 = 0x510;
    pub const SAME_THREAD_APC_FLAGS: u64 = 0x518;
    pub const EXIT_STATUS: u64 = 0x548;
    pub const IRP_LIST_LOCK: u64 = 0x588;
    pub const ACTIVITY_ID: u64 = 0x5A0;
    pub const SILO: u64 = 0x608;
    pub const EXPECTED_RUN_TIME: u64 = 0x620;
    pub const PAGE_PRIORITY_SHIFT: u32 = 12;
    pub const SIZE: u64 = 0x898;
}

/// EPROCESS/KPROCESS (Windows 10 19041/22H2).
pub mod eprocess {
    pub const DIRECTORY_TABLE_BASE: u64 = 0x28;
    pub const BASE_PRIORITY: u64 = 0x280;
    pub const PROCESS_LOCK: u64 = 0x438;
    pub const UNIQUE_PROCESS_ID: u64 = 0x440;
    pub const ACTIVE_PROCESS_LINKS: u64 = 0x448;
    pub const RUNDOWN_PROTECT: u64 = 0x458;
    pub const FLAGS: u64 = 0x464;
    pub const PROCESS_EXITING_FLAG: u32 = 4;
    pub const CREATE_TIME: u64 = 0x468;
    pub const WIN32_WINDOW_STATION: u64 = 0x538;
    pub const INHERITED_FROM_UNIQUE_PROCESS_ID: u64 = 0x540;
    pub const PRIORITY_CLASS: u64 = 0x5B7;
    pub const SECURITY_PORT: u64 = 0x5B8;
    pub const SEQUENCE_NUMBER: u64 = 0x8F8;
    pub const DXG_PROCESS: u64 = 0x960;
    pub const POOL_QUOTA_USAGE: u64 = 0x470;
    pub const POOL_QUOTA_PEAK: u64 = 0x480;
    pub const TOKEN: u64 = 0x4B8;
    pub const WIN32_PROCESS: u64 = 0x508;
    pub const JOB: u64 = 0x510;
    pub const SECTION_OBJECT: u64 = 0x518;
    pub const SECTION_BASE_ADDRESS: u64 = 0x520;
    pub const PEB: u64 = 0x550;
    pub const SESSION: u64 = 0x558;
    pub const OBJECT_TABLE: u64 = 0x570;
    pub const DEBUG_PORT: u64 = 0x578;
    pub const WOW64_PROCESS: u64 = 0x580;
    pub const IMAGE_FILE_POINTER: u64 = 0x5A0;
    pub const IMAGE_FILE_NAME: u64 = 0x5A8;
    pub const AUDIT_IMAGE_NAME: u64 = 0x5C0;
    pub const THREAD_LIST_HEAD: u64 = 0x5E0;
    pub const ACTIVE_THREADS: u64 = 0x5F0;
    pub const EXIT_STATUS: u64 = 0x7D4;
    pub const EXIT_TIME: u64 = 0x840;
    pub const SERVER_SILO: u64 = 0x870;
    pub const SIGNATURE_LEVEL: u64 = 0x878;
    pub const SECTION_SIGNATURE_LEVEL: u64 = 0x879;
    pub const PROTECTION: u64 = 0x87A;
    pub const FLAGS3: u64 = 0x87C;
    pub const SYSTEM_PROCESS_FLAG: u32 = 0x1000;
    pub const SIZE: u64 = 0xA40;
    pub const TYPE_PROCESS: u8 = 3;
}

pub mod ejob {
    pub const PARENT: u64 = 0x430;
    pub const SERVER_SILO_GLOBALS: u64 = 0x4F8;
    pub const SILO_CONTEXT: u64 = 0x518;
    pub const FLAGS: u64 = 0x528;
    pub const SIZE: u64 = 0x640;
}

/// KINTERRUPT (objeto opaco para drivers).
pub mod kinterrupt {
    pub const TYPE: u64 = 0x00; // InterruptObject = 0x16
    pub const SIZE_FIELD: u64 = 0x02;
    pub const LIST_ENTRY: u64 = 0x08;
    pub const SERVICE_ROUTINE: u64 = 0x18;
    pub const SERVICE_CONTEXT: u64 = 0x20;
    pub const SPIN_LOCK: u64 = 0x28;
    pub const TICK_COUNT: u64 = 0x30;
    pub const ACTUAL_LOCK: u64 = 0x38;
    pub const VECTOR: u64 = 0x40;
    pub const IRQL: u64 = 0x44;
    pub const SYNCHRONIZE_IRQL: u64 = 0x45;
    pub const FLOATING_SAVE: u64 = 0x46;
    pub const CONNECTED: u64 = 0x47;
    pub const NUMBER: u64 = 0x48;
    pub const SHARE_VECTOR: u64 = 0x4A;
    pub const MODE: u64 = 0x4C;
    pub const SHARE_DISPOSITION: u64 = 0x50;
    pub const DISPATCH_ADDRESS: u64 = 0x58;
    pub const SIZE: u64 = 0x100;
    pub const TYPE_INTERRUPT: u8 = 0x16;
}

/// KDEVICE_QUEUE (wdm.h x64, sizeof 0x28).
pub mod kdevice_queue {
    pub const TYPE: u64 = 0x00;
    pub const SIZE_FIELD: u64 = 0x02;
    pub const LOCK: u64 = 0x08;
    pub const BUSY: u64 = 0x10;
    pub const ENTRY: u64 = 0x18;
    pub const SIZE: u64 = 0x28;
    pub const TYPE_DEVICE_QUEUE: u8 = 0x14;
}

/// CONTROLLER_OBJECT (wdm.h x64) + estado interno do kernel.
pub mod controller_object {
    pub const TYPE: u64 = 0x00;
    pub const SIZE_FIELD: u64 = 0x02;
    pub const REFERENCE_COUNT: u64 = 0x04;
    pub const CONTROLLER_EXTENSION: u64 = 0x08;
    pub const DEVICE_OBJECT: u64 = 0x10;
    pub const BUSY: u64 = 0x18;
    pub const QUEUED: u64 = 0x1C;
    pub const SIZE: u64 = 0x40;
    pub const TYPE_CONTROLLER: u8 = 7;
}

/// CM_RESOURCE_LIST — alinhamento real de 4 bytes (medido no i8042prt.sys).
pub mod cm_resource_list {
    pub const COUNT: u64 = 0x00;
    pub const FULL_DESCRIPTOR: u64 = 0x04;
}

pub mod cm_full_resource_descriptor {
    pub const INTERFACE_TYPE: u64 = 0x00;
    pub const BUS_NUMBER: u64 = 0x04;
    pub const PARTIAL_LIST: u64 = 0x08;
}

pub mod cm_partial_resource_list {
    pub const VERSION: u64 = 0x00;
    pub const REVISION: u64 = 0x02;
    pub const COUNT: u64 = 0x04;
    pub const DESCRIPTORS: u64 = 0x08;
}

pub mod cm_partial_resource_descriptor {
    pub const TYPE: u64 = 0x00;
    pub const SHARE_DISPOSITION: u64 = 0x01;
    pub const FLAGS: u64 = 0x02;
    pub const PORT_START: u64 = 0x04;
    pub const PORT_LENGTH: u64 = 0x0C;
    pub const INTERRUPT_LEVEL: u64 = 0x04;
    pub const INTERRUPT_VECTOR: u64 = 0x08;
    pub const INTERRUPT_AFFINITY: u64 = 0x0C;
    pub const SIZE: u64 = 0x14;
    pub const TYPE_PORT: u8 = 1;
    pub const TYPE_INTERRUPT: u8 = 2;
    pub const TYPE_MEMORY: u8 = 3;
}
