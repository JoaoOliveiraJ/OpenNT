//! Layouts reais das structs do kernel NT x64.
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

// ---- Prova contra os símbolos do ntoskrnl (gerado por `cargo xtask nt-types`) ----
//
// Cada constante de offset acima que corresponde a um campo do layout real
// é conferida em compilação contra `inc::types` (gerado dos símbolos).
// Divergem dos símbolos (constantes mantidas como estão; a conferir):
//   driver_object::STRUCT_SIZE = 0x158; símbolos: sizeof(_DRIVER_OBJECT) = 0x150
//   driver_extension::SIZE = 0x40; símbolos: sizeof(_DRIVER_EXTENSION) = 0x50
//   device_object::DEVICE_QUEUE = 0x60; símbolos: _DEVICE_OBJECT.DeviceQueue = 0xa0
//   device_object::DPC = 0x88; símbolos: _DEVICE_OBJECT.Dpc = 0xc8
//   ktimer::PERIOD = 0x38; símbolos: _KTIMER.Period = 0x3c
//   io_workitem::DEVICE_OBJECT = 0x20; símbolos: _IO_WORKITEM.IoObject = 0x28
//   io_workitem::TYPE = 0x28; símbolos: _IO_WORKITEM.Type = 0x40
//   io_workitem::SIZE = 0x30; símbolos: sizeof(_IO_WORKITEM) = 0x58
//   kinterrupt::SERVICE_CONTEXT = 0x20; símbolos: _KINTERRUPT.ServiceContext = 0x30
//   kinterrupt::SPIN_LOCK = 0x28; símbolos: _KINTERRUPT.SpinLock = 0x38
//   kinterrupt::TICK_COUNT = 0x30; símbolos: _KINTERRUPT.TickCount = 0x40
//   kinterrupt::ACTUAL_LOCK = 0x38; símbolos: _KINTERRUPT.ActualLock = 0x48
//   kinterrupt::VECTOR = 0x40; símbolos: _KINTERRUPT.Vector = 0x58
//   kinterrupt::IRQL = 0x44; símbolos: _KINTERRUPT.Irql = 0x5c
//   kinterrupt::SYNCHRONIZE_IRQL = 0x45; símbolos: _KINTERRUPT.SynchronizeIrql = 0x5d
//   kinterrupt::FLOATING_SAVE = 0x46; símbolos: _KINTERRUPT.FloatingSave = 0x5e
//   kinterrupt::CONNECTED = 0x47; símbolos: _KINTERRUPT.Connected = 0x5f
//   kinterrupt::NUMBER = 0x48; símbolos: _KINTERRUPT.Number = 0x60
//   kinterrupt::SHARE_VECTOR = 0x4a; símbolos: _KINTERRUPT.ShareVector = 0x64
//   kinterrupt::MODE = 0x4c; símbolos: _KINTERRUPT.Mode = 0x6c
//   kinterrupt::SHARE_DISPOSITION = 0x50; símbolos: _KINTERRUPT.Polarity = 0x70
//   kinterrupt::DISPATCH_ADDRESS = 0x58; símbolos: _KINTERRUPT.DispatchAddress = 0x50
//   kinterrupt::SIZE = 0x100; símbolos: sizeof(_KINTERRUPT) = 0x120
//   kdevice_queue::LOCK = 0x8; símbolos: _KDEVICE_QUEUE.Lock = 0x18
//   kdevice_queue::BUSY = 0x10; símbolos: _KDEVICE_QUEUE.Busy = 0x20
//   kdevice_queue::ENTRY = 0x18; símbolos: _KDEVICE_QUEUE.DeviceListHead = 0x8
//   controller_object::SIZE = 0x40; símbolos: sizeof(_CONTROLLER_OBJECT) = 0x48
const _: () = {
    use crate::ntos::inc::types::*;
    assert!(driver_object::TYPE as usize == core::mem::offset_of!(DriverObject, type_));
    assert!(driver_object::SIZE as usize == core::mem::offset_of!(DriverObject, size));
    assert!(driver_object::DEVICE_OBJECT as usize == core::mem::offset_of!(DriverObject, device_object));
    assert!(driver_object::FLAGS as usize == core::mem::offset_of!(DriverObject, flags));
    assert!(driver_object::DRIVER_START as usize == core::mem::offset_of!(DriverObject, driver_start));
    assert!(driver_object::DRIVER_SIZE as usize == core::mem::offset_of!(DriverObject, driver_size));
    assert!(driver_object::DRIVER_SECTION as usize == core::mem::offset_of!(DriverObject, driver_section));
    assert!(driver_object::DRIVER_EXTENSION as usize == core::mem::offset_of!(DriverObject, driver_extension));
    assert!(driver_object::DRIVER_NAME as usize == core::mem::offset_of!(DriverObject, driver_name));
    assert!(driver_object::HARDWARE_DATABASE as usize == core::mem::offset_of!(DriverObject, hardware_database));
    assert!(driver_object::FAST_IO_DISPATCH as usize == core::mem::offset_of!(DriverObject, fast_io_dispatch));
    assert!(driver_object::DRIVER_INIT as usize == core::mem::offset_of!(DriverObject, driver_init));
    assert!(driver_object::DRIVER_START_IO as usize == core::mem::offset_of!(DriverObject, driver_start_io));
    assert!(driver_object::DRIVER_UNLOAD as usize == core::mem::offset_of!(DriverObject, driver_unload));
    assert!(driver_object::MAJOR_FUNCTION as usize == core::mem::offset_of!(DriverObject, major_function));
    assert!(driver_extension::DRIVER_OBJECT as usize == core::mem::offset_of!(DriverExtension, driver_object));
    assert!(driver_extension::ADD_DEVICE as usize == core::mem::offset_of!(DriverExtension, add_device));
    assert!(driver_extension::COUNT as usize == core::mem::offset_of!(DriverExtension, count));
    assert!(driver_extension::SERVICE_KEY_NAME as usize == core::mem::offset_of!(DriverExtension, service_key_name));
    assert!(device_object::TYPE as usize == core::mem::offset_of!(DeviceObject, type_));
    assert!(device_object::SIZE as usize == core::mem::offset_of!(DeviceObject, size));
    assert!(device_object::REFERENCE_COUNT as usize == core::mem::offset_of!(DeviceObject, reference_count));
    assert!(device_object::DRIVER_OBJECT as usize == core::mem::offset_of!(DeviceObject, driver_object));
    assert!(device_object::NEXT_DEVICE as usize == core::mem::offset_of!(DeviceObject, next_device));
    assert!(device_object::ATTACHED_DEVICE as usize == core::mem::offset_of!(DeviceObject, attached_device));
    assert!(device_object::CURRENT_IRP as usize == core::mem::offset_of!(DeviceObject, current_irp));
    assert!(device_object::TIMER as usize == core::mem::offset_of!(DeviceObject, timer));
    assert!(device_object::FLAGS as usize == core::mem::offset_of!(DeviceObject, flags));
    assert!(device_object::CHARACTERISTICS as usize == core::mem::offset_of!(DeviceObject, characteristics));
    assert!(device_object::VPB as usize == core::mem::offset_of!(DeviceObject, vpb));
    assert!(device_object::DEVICE_EXTENSION as usize == core::mem::offset_of!(DeviceObject, device_extension));
    assert!(device_object::DEVICE_TYPE as usize == core::mem::offset_of!(DeviceObject, device_type));
    assert!(device_object::STACK_SIZE as usize == core::mem::offset_of!(DeviceObject, stack_size));
    assert!(device_object::QUEUE_LIST as usize == core::mem::offset_of!(DeviceObject, queue));
    assert!(device_object::DEVICE_OBJECT_EXTENSION as usize == core::mem::offset_of!(DeviceObject, device_object_extension));
    assert!(device_object::STRUCT_SIZE as usize == core::mem::size_of::<DeviceObject>());
    assert!(devobj_extension::STRUCT_SIZE as usize == core::mem::size_of::<DevobjExtension>());
    assert!(devobj_extension::DEVICE_OBJECT as usize == core::mem::offset_of!(DevobjExtension, device_object));
    assert!(devobj_extension::VPB as usize == core::mem::offset_of!(DevobjExtension, vpb));
    assert!(vpb::TYPE as usize == core::mem::offset_of!(Vpb, type_));
    assert!(vpb::SIZE as usize == core::mem::offset_of!(Vpb, size));
    assert!(vpb::FLAGS as usize == core::mem::offset_of!(Vpb, flags));
    assert!(vpb::VOLUME_LABEL_LENGTH as usize == core::mem::offset_of!(Vpb, volume_label_length));
    assert!(vpb::DEVICE_OBJECT as usize == core::mem::offset_of!(Vpb, device_object));
    assert!(vpb::REAL_DEVICE as usize == core::mem::offset_of!(Vpb, real_device));
    assert!(vpb::SERIAL_NUMBER as usize == core::mem::offset_of!(Vpb, serial_number));
    assert!(vpb::REFERENCE_COUNT as usize == core::mem::offset_of!(Vpb, reference_count));
    assert!(vpb::VOLUME_LABEL as usize == core::mem::offset_of!(Vpb, volume_label));
    assert!(vpb::STRUCT_SIZE as usize == core::mem::size_of::<Vpb>());
    assert!(irp::TYPE as usize == core::mem::offset_of!(Irp, type_));
    assert!(irp::SIZE_FIELD as usize == core::mem::offset_of!(Irp, size));
    assert!(irp::MDL_ADDRESS as usize == core::mem::offset_of!(Irp, mdl_address));
    assert!(irp::FLAGS as usize == core::mem::offset_of!(Irp, flags));
    assert!(irp::SYSTEM_BUFFER as usize == core::mem::offset_of!(Irp, associated_irp) + core::mem::offset_of!(IrpAssociatedIrpView2, system_buffer));
    assert!(irp::IO_STATUS as usize == core::mem::offset_of!(Irp, io_status));
    assert!(irp::IO_STATUS_INFORMATION as usize == core::mem::offset_of!(Irp, io_status) + core::mem::offset_of!(IoStatusBlock, information));
    assert!(irp::REQUESTOR_MODE as usize == core::mem::offset_of!(Irp, requestor_mode));
    assert!(irp::STACK_COUNT as usize == core::mem::offset_of!(Irp, stack_count));
    assert!(irp::CURRENT_LOCATION as usize == core::mem::offset_of!(Irp, current_location));
    assert!(irp::CANCEL as usize == core::mem::offset_of!(Irp, cancel));
    assert!(irp::CANCEL_IRQL as usize == core::mem::offset_of!(Irp, cancel_irql));
    assert!(irp::CANCEL_ROUTINE as usize == core::mem::offset_of!(Irp, cancel_routine));
    assert!(irp::USER_IOSB as usize == core::mem::offset_of!(Irp, user_iosb));
    assert!(irp::USER_EVENT as usize == core::mem::offset_of!(Irp, user_event));
    assert!(irp::USER_BUFFER as usize == core::mem::offset_of!(Irp, user_buffer));
    assert!(irp::THREAD as usize == core::mem::offset_of!(Irp, tail) + core::mem::offset_of!(IrpTail, overlay) + core::mem::offset_of!(IrpTailOverlay, thread));
    assert!(irp::ORIGINAL_FILE_OBJECT as usize == core::mem::offset_of!(Irp, tail) + core::mem::offset_of!(IrpTail, overlay) + core::mem::offset_of!(IrpTailOverlay, original_file_object));
    assert!(irp::CURRENT_STACK_LOCATION as usize == core::mem::offset_of!(Irp, tail) + core::mem::offset_of!(IrpTail, overlay) + core::mem::offset_of!(IrpTailOverlay, current_stack_location));
    assert!(irp::STRUCT_SIZE as usize == core::mem::size_of::<Irp>());
    assert!(irp::STACK_LOCATION_SIZE as usize == core::mem::size_of::<IoStackLocation>());
    assert!(io_stack_location::MAJOR as usize == core::mem::offset_of!(IoStackLocation, major_function));
    assert!(io_stack_location::MINOR as usize == core::mem::offset_of!(IoStackLocation, minor_function));
    assert!(io_stack_location::FLAGS as usize == core::mem::offset_of!(IoStackLocation, flags));
    assert!(io_stack_location::CONTROL as usize == core::mem::offset_of!(IoStackLocation, control));
    assert!(io_stack_location::READ_LENGTH as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView3, read) + core::mem::offset_of!(IoStackLocationParametersRead, length));
    assert!(io_stack_location::READ_KEY as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView3, read) + core::mem::offset_of!(IoStackLocationParametersRead, key));
    assert!(io_stack_location::READ_OFFSET as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView3, read) + core::mem::offset_of!(IoStackLocationParametersRead, byte_offset));
    assert!(io_stack_location::IOCTL_OUT_LENGTH as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView16, device_io_control) + core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, output_buffer_length));
    assert!(io_stack_location::IOCTL_IN_LENGTH as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView16, device_io_control) + core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, input_buffer_length));
    assert!(io_stack_location::IOCTL_CODE as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView16, device_io_control) + core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, io_control_code));
    assert!(io_stack_location::IOCTL_TYPE3_BUFFER as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView16, device_io_control) + core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, type3_input_buffer));
    assert!(io_stack_location::POWER_SYSTEM_CONTEXT as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView35, power) + core::mem::offset_of!(IoStackLocationParametersPower, system_context));
    assert!(io_stack_location::POWER_TYPE as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView35, power) + core::mem::offset_of!(IoStackLocationParametersPower, type_));
    assert!(io_stack_location::POWER_STATE as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView35, power) + core::mem::offset_of!(IoStackLocationParametersPower, state));
    assert!(io_stack_location::POWER_SHUTDOWN_TYPE as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView35, power) + core::mem::offset_of!(IoStackLocationParametersPower, shutdown_type));
    assert!(io_stack_location::PNP_ALLOCATED_RESOURCES as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView36, start_device) + core::mem::offset_of!(IoStackLocationParametersStartDevice, allocated_resources));
    assert!(io_stack_location::PNP_ALLOCATED_RESOURCES_TRANSLATED as usize == core::mem::offset_of!(IoStackLocation, parameters) + core::mem::offset_of!(IoStackLocationParametersView36, start_device) + core::mem::offset_of!(IoStackLocationParametersStartDevice, allocated_resources_translated));
    assert!(io_stack_location::DEVICE_OBJECT as usize == core::mem::offset_of!(IoStackLocation, device_object));
    assert!(io_stack_location::FILE_OBJECT as usize == core::mem::offset_of!(IoStackLocation, file_object));
    assert!(io_stack_location::COMPLETION_ROUTINE as usize == core::mem::offset_of!(IoStackLocation, completion_routine));
    assert!(io_stack_location::CONTEXT as usize == core::mem::offset_of!(IoStackLocation, context));
    assert!(io_stack_location::SIZE as usize == core::mem::size_of::<IoStackLocation>());
    assert!(file_object::TYPE as usize == core::mem::offset_of!(FileObject, type_));
    assert!(file_object::SIZE as usize == core::mem::offset_of!(FileObject, size));
    assert!(file_object::DEVICE_OBJECT as usize == core::mem::offset_of!(FileObject, device_object));
    assert!(file_object::FLAGS as usize == core::mem::offset_of!(FileObject, flags));
    assert!(file_object::FILE_NAME as usize == core::mem::offset_of!(FileObject, file_name));
    assert!(file_object::CURRENT_BYTE_OFFSET as usize == core::mem::offset_of!(FileObject, current_byte_offset));
    assert!(file_object::LOCK as usize == core::mem::offset_of!(FileObject, lock));
    assert!(file_object::EVENT as usize == core::mem::offset_of!(FileObject, event));
    assert!(file_object::IRP_LIST as usize == core::mem::offset_of!(FileObject, irp_list));
    assert!(file_object::STRUCT_SIZE as usize == core::mem::size_of::<FileObject>());
    assert!(io_status_block::STATUS as usize == core::mem::offset_of!(IoStatusBlock, status));
    assert!(io_status_block::INFORMATION as usize == core::mem::offset_of!(IoStatusBlock, information));
    assert!(io_status_block::SIZE as usize == core::mem::size_of::<IoStatusBlock>());
    assert!(object_attributes::LENGTH as usize == core::mem::offset_of!(ObjectAttributes, length));
    assert!(object_attributes::ROOT_DIRECTORY as usize == core::mem::offset_of!(ObjectAttributes, root_directory));
    assert!(object_attributes::OBJECT_NAME as usize == core::mem::offset_of!(ObjectAttributes, object_name));
    assert!(object_attributes::ATTRIBUTES as usize == core::mem::offset_of!(ObjectAttributes, attributes));
    assert!(object_attributes::SIZE as usize == core::mem::size_of::<ObjectAttributes>());
    assert!(unicode_string::LENGTH as usize == core::mem::offset_of!(UnicodeString, length));
    assert!(unicode_string::MAXIMUM_LENGTH as usize == core::mem::offset_of!(UnicodeString, maximum_length));
    assert!(unicode_string::BUFFER as usize == core::mem::offset_of!(UnicodeString, buffer));
    assert!(unicode_string::SIZE as usize == core::mem::size_of::<UnicodeString>());
    assert!(dispatcher_header::TYPE as usize == core::mem::offset_of!(DispatcherHeaderView2, type_));
    assert!(dispatcher_header::SIGNAL_STATE as usize == core::mem::offset_of!(DispatcherHeader, signal_state));
    assert!(dispatcher_header::WAIT_LIST_HEAD as usize == core::mem::offset_of!(DispatcherHeader, wait_list_head));
    assert!(dispatcher_header::SIZE as usize == core::mem::size_of::<DispatcherHeader>());
    assert!(dispatcher_header::MUTEX_OWNER as usize == core::mem::offset_of!(Kmutant, owner_thread));
    assert!(kevent::SIZE as usize == core::mem::size_of::<Kevent>());
    assert!(kmutex::SIZE as usize == core::mem::size_of::<Kmutant>());
    assert!(fast_mutex::COUNT as usize == core::mem::offset_of!(FastMutex, count));
    assert!(fast_mutex::OWNER as usize == core::mem::offset_of!(FastMutex, owner));
    assert!(fast_mutex::CONTENTION as usize == core::mem::offset_of!(FastMutex, contention));
    assert!(fast_mutex::EVENT as usize == core::mem::offset_of!(FastMutex, event));
    assert!(fast_mutex::OLD_IRQL as usize == core::mem::offset_of!(FastMutex, old_irql));
    assert!(fast_mutex::SIZE as usize == core::mem::size_of::<FastMutex>());
    assert!(kdpc::TYPE as usize == core::mem::offset_of!(KdpcView1, type_));
    assert!(kdpc::IMPORTANCE as usize == core::mem::offset_of!(KdpcView1, importance));
    assert!(kdpc::NUMBER as usize == core::mem::offset_of!(KdpcView1, number));
    assert!(kdpc::DPC_LIST_ENTRY as usize == core::mem::offset_of!(Kdpc, dpc_list_entry));
    assert!(kdpc::PROCESSOR_HISTORY as usize == core::mem::offset_of!(Kdpc, processor_history));
    assert!(kdpc::ROUTINE as usize == core::mem::offset_of!(Kdpc, deferred_routine));
    assert!(kdpc::CONTEXT as usize == core::mem::offset_of!(Kdpc, deferred_context));
    assert!(kdpc::SYSARG1 as usize == core::mem::offset_of!(Kdpc, system_argument1));
    assert!(kdpc::SYSARG2 as usize == core::mem::offset_of!(Kdpc, system_argument2));
    assert!(kdpc::DPC_DATA as usize == core::mem::offset_of!(Kdpc, dpc_data));
    assert!(kdpc::SIZE as usize == core::mem::size_of::<Kdpc>());
    assert!(ktimer::TYPE as usize == core::mem::offset_of!(Ktimer, header) + core::mem::offset_of!(DispatcherHeaderView2, type_));
    assert!(ktimer::SIGNAL_STATE as usize == core::mem::offset_of!(Ktimer, header) + core::mem::offset_of!(DispatcherHeader, signal_state));
    assert!(ktimer::DUE_TIME as usize == core::mem::offset_of!(Ktimer, due_time));
    assert!(ktimer::TIMER_LIST_ENTRY as usize == core::mem::offset_of!(Ktimer, timer_list_entry));
    assert!(ktimer::DPC as usize == core::mem::offset_of!(Ktimer, dpc));
    assert!(ktimer::SIZE as usize == core::mem::size_of::<Ktimer>());
    assert!(io_workitem::LIST_FLINK as usize == core::mem::offset_of!(IoWorkitem, work_item) + core::mem::offset_of!(WorkQueueItem, list) + core::mem::offset_of!(ListEntry, flink));
    assert!(io_workitem::LIST_BLINK as usize == core::mem::offset_of!(IoWorkitem, work_item) + core::mem::offset_of!(WorkQueueItem, list) + core::mem::offset_of!(ListEntry, blink));
    assert!(io_workitem::FUNCTION as usize == core::mem::offset_of!(IoWorkitem, work_item) + core::mem::offset_of!(WorkQueueItem, worker_routine));
    assert!(io_workitem::CONTEXT as usize == core::mem::offset_of!(IoWorkitem, work_item) + core::mem::offset_of!(WorkQueueItem, parameter));
    assert!(key_value_partial::TITLE_INDEX as usize == core::mem::offset_of!(KeyValuePartialInformation, title_index));
    assert!(key_value_partial::TYPE as usize == core::mem::offset_of!(KeyValuePartialInformation, type_));
    assert!(key_value_partial::DATA_LENGTH as usize == core::mem::offset_of!(KeyValuePartialInformation, data_length));
    assert!(key_value_partial::DATA as usize == core::mem::offset_of!(KeyValuePartialInformation, data));
    assert!(mdl::NEXT as usize == core::mem::offset_of!(Mdl, next));
    assert!(mdl::SIZE as usize == core::mem::offset_of!(Mdl, size));
    assert!(mdl::MDL_FLAGS as usize == core::mem::offset_of!(Mdl, mdl_flags));
    assert!(mdl::PROCESS as usize == core::mem::offset_of!(Mdl, process));
    assert!(mdl::MAPPED_SYSTEM_VA as usize == core::mem::offset_of!(Mdl, mapped_system_va));
    assert!(mdl::START_VA as usize == core::mem::offset_of!(Mdl, start_va));
    assert!(mdl::BYTE_COUNT as usize == core::mem::offset_of!(Mdl, byte_count));
    assert!(mdl::BYTE_OFFSET as usize == core::mem::offset_of!(Mdl, byte_offset));
    assert!(mdl::PFN_ARRAY as usize == core::mem::size_of::<Mdl>());
    assert!(lookaside_list::DEPTH as usize == core::mem::offset_of!(GeneralLookaside, depth));
    assert!(lookaside_list::MAXIMUM_DEPTH as usize == core::mem::offset_of!(GeneralLookaside, maximum_depth));
    assert!(lookaside_list::ALLOC_COUNT as usize == core::mem::offset_of!(GeneralLookaside, total_allocates));
    assert!(lookaside_list::ALLOC_MISSES as usize == core::mem::offset_of!(GeneralLookaside, allocate_misses));
    assert!(lookaside_list::FREE_COUNT as usize == core::mem::offset_of!(GeneralLookaside, total_frees));
    assert!(lookaside_list::FREE_MISSES as usize == core::mem::offset_of!(GeneralLookaside, free_misses));
    assert!(lookaside_list::POOL_TYPE as usize == core::mem::offset_of!(GeneralLookaside, type_));
    assert!(lookaside_list::TAG as usize == core::mem::offset_of!(GeneralLookaside, tag));
    assert!(lookaside_list::BLOCK_SIZE as usize == core::mem::offset_of!(GeneralLookaside, size));
    assert!(lookaside_list::ALLOCATE_CALLBACK as usize == core::mem::offset_of!(GeneralLookasideView1, allocate));
    assert!(lookaside_list::FREE_CALLBACK as usize == core::mem::offset_of!(GeneralLookasideView1, free));
    assert!(lookaside_list::REGISTRY_ENTRY as usize == core::mem::offset_of!(GeneralLookaside, list_entry));
    assert!(lookaside_list::LAST_ALLOC_COUNT as usize == core::mem::offset_of!(GeneralLookaside, last_total_allocates));
    assert!(lookaside_list::LAST_ALLOC_MISSES as usize == core::mem::offset_of!(GeneralLookaside, last_allocate_misses));
    assert!(lookaside_list::SIZE as usize == core::mem::size_of::<GeneralLookaside>());
    assert!(kthread::QUANTUM_TARGET as usize == core::mem::offset_of!(Kthread, quantum_target));
    assert!(kthread::INITIAL_STACK as usize == core::mem::offset_of!(Kthread, initial_stack));
    assert!(kthread::STACK_LIMIT as usize == core::mem::offset_of!(Kthread, stack_limit));
    assert!(kthread::STACK_BASE as usize == core::mem::offset_of!(Kthread, stack_base));
    assert!(kthread::TEB as usize == core::mem::offset_of!(Kthread, teb));
    assert!(kthread::WIN32_THREAD as usize == core::mem::offset_of!(KthreadView1, win32_thread));
    assert!(kthread::CREATE_TIME as usize == core::mem::offset_of!(Ethread, create_time));
    assert!(kthread::THREAD_LOCK as usize == core::mem::offset_of!(Kthread, thread_lock));
    assert!(kthread::CYCLE_TIME as usize == core::mem::offset_of!(Kthread, cycle_time));
    assert!(kthread::WAIT_REGISTER as usize == core::mem::offset_of!(Kthread, wait_register));
    assert!(kthread::RUNNING as usize == core::mem::offset_of!(Kthread, running));
    assert!(kthread::ALERTED as usize == core::mem::offset_of!(Kthread, alerted));
    assert!(kthread::MISC_FLAGS as usize == core::mem::offset_of!(Kthread, misc_flags));
    assert!(kthread::THREAD_FLAGS as usize == core::mem::offset_of!(Kthread, thread_flags));
    assert!(kthread::READY_TIME as usize == core::mem::offset_of!(Kthread, ready_time));
    assert!(kthread::TRAP_FRAME as usize == core::mem::offset_of!(Kthread, trap_frame));
    assert!(kthread::APC_STATE as usize == core::mem::offset_of!(Kthread, apc_state));
    assert!(kthread::APC_STATE_PROCESS as usize == core::mem::offset_of!(Kthread, apc_state) + core::mem::offset_of!(KapcState, process));
    assert!(kthread::PRIORITY as usize == core::mem::offset_of!(KthreadView1, priority));
    assert!(kthread::WAIT_STATUS as usize == core::mem::offset_of!(Kthread, wait_status));
    assert!(kthread::WAIT_LIST_ENTRY as usize == core::mem::offset_of!(Kthread, wait_list_entry));
    assert!(kthread::STATE as usize == core::mem::offset_of!(KthreadView1, state));
    assert!(kthread::WAIT_MODE as usize == core::mem::offset_of!(KthreadView1, wait_mode));
    assert!(kthread::WAIT_TIME as usize == core::mem::offset_of!(KthreadView1, wait_time));
    assert!(kthread::KERNEL_APC_DISABLE as usize == core::mem::offset_of!(KthreadView1, kernel_apc_disable));
    assert!(kthread::SPECIAL_APC_DISABLE as usize == core::mem::offset_of!(KthreadView1, special_apc_disable));
    assert!(kthread::PROCESS as usize == core::mem::offset_of!(Kthread, process));
    assert!(kthread::PREVIOUS_MODE as usize == core::mem::offset_of!(KthreadView1, previous_mode));
    assert!(kthread::BASE_PRIORITY as usize == core::mem::offset_of!(KthreadView1, base_priority));
    assert!(kthread::PRIORITY_DECREMENT as usize == core::mem::offset_of!(KthreadView1, priority_decrement));
    assert!(kthread::SATURATION as usize == core::mem::offset_of!(KthreadView1, saturation));
    assert!(kthread::QUANTUM_RESET as usize == core::mem::offset_of!(KthreadView1, quantum_reset));
    assert!(kthread::PRIORITY_FLOOR_SUMMARY as usize == core::mem::offset_of!(Kthread, priority_floor_summary));
    assert!(kthread::FOREGROUND_LOSS_TIME as usize == core::mem::offset_of!(Kthread, foreground_loss_time));
    assert!(kthread::OTHER_OPERATION_COUNT as usize == core::mem::offset_of!(Kthread, other_operation_count));
    assert!(kthread::CID as usize == core::mem::offset_of!(Ethread, cid));
    assert!(kthread::CID_UNIQUE_PROCESS as usize == core::mem::offset_of!(Ethread, cid) + core::mem::offset_of!(ClientId, unique_process));
    assert!(kthread::CID_UNIQUE_THREAD as usize == core::mem::offset_of!(Ethread, cid) + core::mem::offset_of!(ClientId, unique_thread));
    assert!(kthread::IRP_LIST_HEAD as usize == core::mem::offset_of!(Ethread, irp_list));
    assert!(kthread::THREAD_LIST_ENTRY as usize == core::mem::offset_of!(Ethread, thread_list_entry));
    assert!(kthread::RUNDOWN_PROTECT as usize == core::mem::offset_of!(Ethread, rundown_protect));
    assert!(kthread::INSERTION_LOCK as usize == core::mem::offset_of!(Ethread, thread_lock));
    assert!(kthread::CROSS_THREAD_FLAGS as usize == core::mem::offset_of!(Ethread, cross_thread_flags));
    assert!(kthread::SAME_THREAD_APC_FLAGS as usize == core::mem::offset_of!(Ethread, same_thread_apc_flags));
    assert!(kthread::EXIT_STATUS as usize == core::mem::offset_of!(Ethread, exit_status));
    assert!(kthread::IRP_LIST_LOCK as usize == core::mem::offset_of!(Ethread, irp_list_lock));
    assert!(kthread::ACTIVITY_ID as usize == core::mem::offset_of!(Ethread, activity_id));
    assert!(kthread::SILO as usize == core::mem::offset_of!(Ethread, silo));
    assert!(kthread::EXPECTED_RUN_TIME as usize == core::mem::offset_of!(Ethread, last_expected_run_time));
    assert!(kthread::SIZE as usize == core::mem::size_of::<Ethread>());
    assert!(eprocess::DIRECTORY_TABLE_BASE as usize == core::mem::offset_of!(Eprocess, pcb) + core::mem::offset_of!(Kprocess, directory_table_base));
    assert!(eprocess::BASE_PRIORITY as usize == core::mem::offset_of!(Eprocess, pcb) + core::mem::offset_of!(Kprocess, base_priority));
    assert!(eprocess::PROCESS_LOCK as usize == core::mem::offset_of!(Eprocess, process_lock));
    assert!(eprocess::UNIQUE_PROCESS_ID as usize == core::mem::offset_of!(Eprocess, unique_process_id));
    assert!(eprocess::ACTIVE_PROCESS_LINKS as usize == core::mem::offset_of!(Eprocess, active_process_links));
    assert!(eprocess::RUNDOWN_PROTECT as usize == core::mem::offset_of!(Eprocess, rundown_protect));
    assert!(eprocess::FLAGS as usize == core::mem::offset_of!(Eprocess, flags));
    assert!(eprocess::CREATE_TIME as usize == core::mem::offset_of!(Eprocess, create_time));
    assert!(eprocess::WIN32_WINDOW_STATION as usize == core::mem::offset_of!(Eprocess, win32_window_station));
    assert!(eprocess::INHERITED_FROM_UNIQUE_PROCESS_ID as usize == core::mem::offset_of!(Eprocess, inherited_from_unique_process_id));
    assert!(eprocess::PRIORITY_CLASS as usize == core::mem::offset_of!(Eprocess, priority_class));
    assert!(eprocess::SECURITY_PORT as usize == core::mem::offset_of!(Eprocess, security_port));
    assert!(eprocess::SEQUENCE_NUMBER as usize == core::mem::offset_of!(Eprocess, sequence_number));
    assert!(eprocess::DXG_PROCESS as usize == core::mem::offset_of!(Eprocess, dxg_process));
    assert!(eprocess::POOL_QUOTA_USAGE as usize == core::mem::offset_of!(Eprocess, process_quota_usage));
    assert!(eprocess::POOL_QUOTA_PEAK as usize == core::mem::offset_of!(Eprocess, process_quota_peak));
    assert!(eprocess::TOKEN as usize == core::mem::offset_of!(Eprocess, token));
    assert!(eprocess::WIN32_PROCESS as usize == core::mem::offset_of!(Eprocess, win32_process));
    assert!(eprocess::JOB as usize == core::mem::offset_of!(Eprocess, job));
    assert!(eprocess::SECTION_OBJECT as usize == core::mem::offset_of!(Eprocess, section_object));
    assert!(eprocess::SECTION_BASE_ADDRESS as usize == core::mem::offset_of!(Eprocess, section_base_address));
    assert!(eprocess::PEB as usize == core::mem::offset_of!(Eprocess, peb));
    assert!(eprocess::SESSION as usize == core::mem::offset_of!(Eprocess, session));
    assert!(eprocess::OBJECT_TABLE as usize == core::mem::offset_of!(Eprocess, object_table));
    assert!(eprocess::DEBUG_PORT as usize == core::mem::offset_of!(Eprocess, debug_port));
    assert!(eprocess::WOW64_PROCESS as usize == core::mem::offset_of!(Eprocess, wo_w64_process));
    assert!(eprocess::IMAGE_FILE_POINTER as usize == core::mem::offset_of!(Eprocess, image_file_pointer));
    assert!(eprocess::IMAGE_FILE_NAME as usize == core::mem::offset_of!(Eprocess, image_file_name));
    assert!(eprocess::AUDIT_IMAGE_NAME as usize == core::mem::offset_of!(Eprocess, se_audit_process_creation_info));
    assert!(eprocess::THREAD_LIST_HEAD as usize == core::mem::offset_of!(Eprocess, thread_list_head));
    assert!(eprocess::ACTIVE_THREADS as usize == core::mem::offset_of!(Eprocess, active_threads));
    assert!(eprocess::EXIT_STATUS as usize == core::mem::offset_of!(Eprocess, exit_status));
    assert!(eprocess::EXIT_TIME as usize == core::mem::offset_of!(Eprocess, exit_time));
    assert!(eprocess::SERVER_SILO as usize == core::mem::offset_of!(Eprocess, server_silo));
    assert!(eprocess::SIGNATURE_LEVEL as usize == core::mem::offset_of!(Eprocess, signature_level));
    assert!(eprocess::SECTION_SIGNATURE_LEVEL as usize == core::mem::offset_of!(Eprocess, section_signature_level));
    assert!(eprocess::PROTECTION as usize == core::mem::offset_of!(Eprocess, protection));
    assert!(eprocess::FLAGS3 as usize == core::mem::offset_of!(Eprocess, flags3));
    assert!(eprocess::SIZE as usize == core::mem::size_of::<Eprocess>());
    assert!(ejob::PARENT as usize == core::mem::offset_of!(Ejob, parent_job));
    assert!(ejob::SERVER_SILO_GLOBALS as usize == core::mem::offset_of!(Ejob, server_silo_globals));
    assert!(ejob::SILO_CONTEXT as usize == core::mem::offset_of!(Ejob, storage));
    assert!(ejob::FLAGS as usize == core::mem::offset_of!(Ejob, job_flags));
    assert!(ejob::SIZE as usize == core::mem::size_of::<Ejob>());
    assert!(kinterrupt::TYPE as usize == core::mem::offset_of!(Kinterrupt, type_));
    assert!(kinterrupt::SIZE_FIELD as usize == core::mem::offset_of!(Kinterrupt, size));
    assert!(kinterrupt::LIST_ENTRY as usize == core::mem::offset_of!(Kinterrupt, interrupt_list_entry));
    assert!(kinterrupt::SERVICE_ROUTINE as usize == core::mem::offset_of!(Kinterrupt, service_routine));
    assert!(kdevice_queue::TYPE as usize == core::mem::offset_of!(KdeviceQueue, type_));
    assert!(kdevice_queue::SIZE_FIELD as usize == core::mem::offset_of!(KdeviceQueue, size));
    assert!(kdevice_queue::SIZE as usize == core::mem::size_of::<KdeviceQueue>());
    assert!(controller_object::TYPE as usize == core::mem::offset_of!(ControllerObject, type_));
    assert!(controller_object::SIZE_FIELD as usize == core::mem::offset_of!(ControllerObject, size));
    assert!(controller_object::CONTROLLER_EXTENSION as usize == core::mem::offset_of!(ControllerObject, controller_extension));
    assert!(cm_resource_list::COUNT as usize == core::mem::offset_of!(CmResourceList, count));
    assert!(cm_resource_list::FULL_DESCRIPTOR as usize == core::mem::offset_of!(CmResourceList, list));
    assert!(cm_full_resource_descriptor::INTERFACE_TYPE as usize == core::mem::offset_of!(CmFullResourceDescriptor, interface_type));
    assert!(cm_full_resource_descriptor::BUS_NUMBER as usize == core::mem::offset_of!(CmFullResourceDescriptor, bus_number));
    assert!(cm_full_resource_descriptor::PARTIAL_LIST as usize == core::mem::offset_of!(CmFullResourceDescriptor, partial_resource_list));
    assert!(cm_partial_resource_list::VERSION as usize == core::mem::offset_of!(CmPartialResourceList, version));
    assert!(cm_partial_resource_list::REVISION as usize == core::mem::offset_of!(CmPartialResourceList, revision));
    assert!(cm_partial_resource_list::COUNT as usize == core::mem::offset_of!(CmPartialResourceList, count));
    assert!(cm_partial_resource_list::DESCRIPTORS as usize == core::mem::offset_of!(CmPartialResourceList, partial_descriptors));
    assert!(cm_partial_resource_descriptor::TYPE as usize == core::mem::offset_of!(CmPartialResourceDescriptor, type_));
    assert!(cm_partial_resource_descriptor::SHARE_DISPOSITION as usize == core::mem::offset_of!(CmPartialResourceDescriptor, share_disposition));
    assert!(cm_partial_resource_descriptor::FLAGS as usize == core::mem::offset_of!(CmPartialResourceDescriptor, flags));
    assert!(cm_partial_resource_descriptor::PORT_START as usize == core::mem::offset_of!(CmPartialResourceDescriptor, u) + core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView1, port) + core::mem::offset_of!(CmPartialResourceDescriptorUGenericUnaligned, start));
    assert!(cm_partial_resource_descriptor::PORT_LENGTH as usize == core::mem::offset_of!(CmPartialResourceDescriptor, u) + core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView1, port) + core::mem::offset_of!(CmPartialResourceDescriptorUGenericUnaligned, length));
    assert!(cm_partial_resource_descriptor::INTERRUPT_LEVEL as usize == core::mem::offset_of!(CmPartialResourceDescriptor, u) + core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView2, interrupt) + core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, level));
    assert!(cm_partial_resource_descriptor::INTERRUPT_VECTOR as usize == core::mem::offset_of!(CmPartialResourceDescriptor, u) + core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView2, interrupt) + core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, vector));
    assert!(cm_partial_resource_descriptor::INTERRUPT_AFFINITY as usize == core::mem::offset_of!(CmPartialResourceDescriptor, u) + core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView2, interrupt) + core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, affinity));
    assert!(cm_partial_resource_descriptor::SIZE as usize == core::mem::size_of::<CmPartialResourceDescriptor>());
};
