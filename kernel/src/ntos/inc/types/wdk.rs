//! Estruturas públicas do WDK/SDK que não constam dos símbolos do ntoskrnl.
//!
//! Mantido à mão (o gerador de `types` não toca neste arquivo), no mesmo
//! estilo do resto de `types`: `#[repr(C)]`, folhas `Field<T>`, membros
//! sobrepostos em vistas por `Deref`, `size_of`/`offset_of!` conferidos em
//! compilação. Cada estrutura cita o cabeçalho de origem (wdm.h, ntddk.h,
//! ntifs.h, winnt.h, winternl.h) ou, quando não há cabeçalho do WDK, o
//! serviço Nt* que define o buffer. Ao acrescentar uma, copie o layout x64 do
//! cabeçalho e escreva as asserções de todos os campos.

use super::*;

/// `_IO_CSQ` (wdm.h; 0x40 bytes).
#[repr(C)]
pub struct IoCsq {
    pub type_: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub csq_insert_irp: Field<u64>,
    /// -> `void`
    pub csq_remove_irp: Field<u64>,
    /// -> `void`
    pub csq_peek_next_irp: Field<u64>,
    /// -> `void`
    pub csq_acquire_lock: Field<u64>,
    /// -> `void`
    pub csq_release_lock: Field<u64>,
    /// -> `void`
    pub csq_complete_canceled_irp: Field<u64>,
    /// -> `void`
    pub reserve_pointer: Field<u64>,
}

unsafe impl NtStruct for IoCsq {}

const _: () = {
    assert!(core::mem::size_of::<IoCsq>() == 0x40);
    assert!(core::mem::offset_of!(IoCsq, type_) == 0x0);
    assert!(core::mem::offset_of!(IoCsq, csq_insert_irp) == 0x8);
    assert!(core::mem::offset_of!(IoCsq, csq_remove_irp) == 0x10);
    assert!(core::mem::offset_of!(IoCsq, csq_peek_next_irp) == 0x18);
    assert!(core::mem::offset_of!(IoCsq, csq_acquire_lock) == 0x20);
    assert!(core::mem::offset_of!(IoCsq, csq_release_lock) == 0x28);
    assert!(core::mem::offset_of!(IoCsq, csq_complete_canceled_irp) == 0x30);
    assert!(core::mem::offset_of!(IoCsq, reserve_pointer) == 0x38);
};

/// `_IO_CSQ_IRP_CONTEXT` (wdm.h; 0x18 bytes).
#[repr(C)]
pub struct IoCsqIrpContext {
    pub type_: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_IRP`
    pub irp: Field<u64>,
    /// -> `_IO_CSQ`
    pub csq: Field<u64>,
}

unsafe impl NtStruct for IoCsqIrpContext {}

const _: () = {
    assert!(core::mem::size_of::<IoCsqIrpContext>() == 0x18);
    assert!(core::mem::offset_of!(IoCsqIrpContext, type_) == 0x0);
    assert!(core::mem::offset_of!(IoCsqIrpContext, irp) == 0x8);
    assert!(core::mem::offset_of!(IoCsqIrpContext, csq) == 0x10);
};

/// `_KBUGCHECK_REASON_CALLBACK_RECORD` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct KbugcheckReasonCallbackRecord {
    pub entry: ListEntry,
    /// -> `void`
    pub callback_routine: Field<u64>,
    /// -> `void`
    pub component: Field<u64>,
    pub checksum: Field<u64>,
    pub reason: Field<i32>,
    pub state: Field<u8>,
    _pad_2d: Reserved<0x3>,
}

unsafe impl NtStruct for KbugcheckReasonCallbackRecord {}

const _: () = {
    assert!(core::mem::size_of::<KbugcheckReasonCallbackRecord>() == 0x30);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, entry) == 0x0);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, callback_routine) == 0x10);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, component) == 0x18);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, checksum) == 0x20);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, reason) == 0x28);
    assert!(core::mem::offset_of!(KbugcheckReasonCallbackRecord, state) == 0x2c);
};

/// `_KBUGCHECK_SECONDARY_DUMP_DATA` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct KbugcheckSecondaryDumpData {
    /// -> `void`
    pub in_buffer: Field<u64>,
    pub in_buffer_length: Field<u32>,
    pub maximum_allowed: Field<u32>,
    pub guid: Guid,
    /// -> `void`
    pub out_buffer: Field<u64>,
    pub out_buffer_length: Field<u32>,
    _pad_2c: Reserved<0x4>,
}

unsafe impl NtStruct for KbugcheckSecondaryDumpData {}

const _: () = {
    assert!(core::mem::size_of::<KbugcheckSecondaryDumpData>() == 0x30);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, in_buffer) == 0x0);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, in_buffer_length) == 0x8);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, maximum_allowed) == 0xc);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, guid) == 0x10);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, out_buffer) == 0x20);
    assert!(core::mem::offset_of!(KbugcheckSecondaryDumpData, out_buffer_length) == 0x28);
};

/// `_OB_OPERATION_REGISTRATION` (wdm.h; 0x20 bytes).
#[repr(C)]
pub struct ObOperationRegistration {
    /// -> `POBJECT_TYPE`
    pub object_type: Field<u64>,
    pub operations: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub pre_operation: Field<u64>,
    /// -> `void`
    pub post_operation: Field<u64>,
}

unsafe impl NtStruct for ObOperationRegistration {}

const _: () = {
    assert!(core::mem::size_of::<ObOperationRegistration>() == 0x20);
    assert!(core::mem::offset_of!(ObOperationRegistration, object_type) == 0x0);
    assert!(core::mem::offset_of!(ObOperationRegistration, operations) == 0x8);
    assert!(core::mem::offset_of!(ObOperationRegistration, pre_operation) == 0x10);
    assert!(core::mem::offset_of!(ObOperationRegistration, post_operation) == 0x18);
};

/// `_OB_CALLBACK_REGISTRATION` (wdm.h; 0x28 bytes).
#[repr(C)]
pub struct ObCallbackRegistration {
    pub version: Field<u16>,
    pub operation_registration_count: Field<u16>,
    _pad_4: Reserved<0x4>,
    pub altitude: UnicodeString,
    /// -> `void`
    pub registration_context: Field<u64>,
    /// -> `_OB_OPERATION_REGISTRATION`
    pub operation_registration: Field<u64>,
}

unsafe impl NtStruct for ObCallbackRegistration {}

const _: () = {
    assert!(core::mem::size_of::<ObCallbackRegistration>() == 0x28);
    assert!(core::mem::offset_of!(ObCallbackRegistration, version) == 0x0);
    assert!(core::mem::offset_of!(ObCallbackRegistration, operation_registration_count) == 0x2);
    assert!(core::mem::offset_of!(ObCallbackRegistration, altitude) == 0x8);
    assert!(core::mem::offset_of!(ObCallbackRegistration, registration_context) == 0x18);
    assert!(core::mem::offset_of!(ObCallbackRegistration, operation_registration) == 0x20);
};

/// `_OB_PRE_CREATE_HANDLE_INFORMATION` (wdm.h; 0x8 bytes).
#[repr(C)]
pub struct ObPreCreateHandleInformation {
    pub desired_access: Field<u32>,
    pub original_desired_access: Field<u32>,
}

unsafe impl NtStruct for ObPreCreateHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObPreCreateHandleInformation>() == 0x8);
    assert!(core::mem::offset_of!(ObPreCreateHandleInformation, desired_access) == 0x0);
    assert!(core::mem::offset_of!(ObPreCreateHandleInformation, original_desired_access) == 0x4);
};

/// `_OB_PRE_DUPLICATE_HANDLE_INFORMATION` (wdm.h; 0x18 bytes).
#[repr(C)]
pub struct ObPreDuplicateHandleInformation {
    pub desired_access: Field<u32>,
    pub original_desired_access: Field<u32>,
    /// -> `_EPROCESS`
    pub source_process: Field<u64>,
    /// -> `_EPROCESS`
    pub target_process: Field<u64>,
}

unsafe impl NtStruct for ObPreDuplicateHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObPreDuplicateHandleInformation>() == 0x18);
    assert!(core::mem::offset_of!(ObPreDuplicateHandleInformation, desired_access) == 0x0);
    assert!(core::mem::offset_of!(ObPreDuplicateHandleInformation, original_desired_access) == 0x4);
    assert!(core::mem::offset_of!(ObPreDuplicateHandleInformation, source_process) == 0x8);
    assert!(core::mem::offset_of!(ObPreDuplicateHandleInformation, target_process) == 0x10);
};

/// `_OB_PRE_OPERATION_PARAMETERS` (wdm.h; 0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ObPreOperationParametersView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ObPreOperationParameters {
    _align: [u64; 0],
    pub create_handle_information: ObPreCreateHandleInformation,
    _pad_8: Reserved<0x10>,
}

/// Vista 1 de `_OB_PRE_OPERATION_PARAMETERS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ObPreOperationParametersView1 {
    pub duplicate_handle_information: ObPreDuplicateHandleInformation,
}

impl core::ops::Deref for ObPreOperationParameters {
    type Target = ObPreOperationParametersView1;
    #[inline(always)]
    fn deref(&self) -> &ObPreOperationParametersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ObPreOperationParametersView1>() }
    }
}

unsafe impl NtStruct for ObPreOperationParameters {}

const _: () = {
    assert!(core::mem::size_of::<ObPreOperationParameters>() == 0x18);
    assert!(core::mem::offset_of!(ObPreOperationParameters, create_handle_information) == 0x0);
    assert!(core::mem::size_of::<ObPreOperationParametersView1>() == 0x18);
    assert!(core::mem::align_of::<ObPreOperationParametersView1>() == core::mem::align_of::<ObPreOperationParameters>());
    assert!(core::mem::offset_of!(ObPreOperationParametersView1, duplicate_handle_information) == 0x0);
};

/// `_OB_PRE_OPERATION_INFORMATION` (wdm.h; 0x28 bytes).
#[repr(C)]
pub struct ObPreOperationInformation {
    pub operation: Field<u32>,
    pub flags: Field<u32>,
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_OBJECT_TYPE`
    pub object_type: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `_OB_PRE_OPERATION_PARAMETERS`
    pub parameters: Field<u64>,
}

unsafe impl NtStruct for ObPreOperationInformation {}

impl ObPreOperationInformation {
    /// `KernelHandle`: bits 0..=0 de `flags`.
    pub const KERNEL_HANDLE_SHIFT: u32 = 0;
    pub const KERNEL_HANDLE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn kernel_handle(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_kernel_handle(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=31 de `flags`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u32 = 0xfffffffe;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.flags.bits(1, 31) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.flags.set_bits(1, 31, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ObPreOperationInformation>() == 0x28);
    assert!(core::mem::offset_of!(ObPreOperationInformation, operation) == 0x0);
    assert!(core::mem::offset_of!(ObPreOperationInformation, flags) == 0x4);
    assert!(core::mem::offset_of!(ObPreOperationInformation, object) == 0x8);
    assert!(core::mem::offset_of!(ObPreOperationInformation, object_type) == 0x10);
    assert!(core::mem::offset_of!(ObPreOperationInformation, call_context) == 0x18);
    assert!(core::mem::offset_of!(ObPreOperationInformation, parameters) == 0x20);
};

/// `_OB_POST_CREATE_HANDLE_INFORMATION` (wdm.h; 0x4 bytes).
#[repr(C)]
pub struct ObPostCreateHandleInformation {
    pub granted_access: Field<u32>,
}

unsafe impl NtStruct for ObPostCreateHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObPostCreateHandleInformation>() == 0x4);
    assert!(core::mem::offset_of!(ObPostCreateHandleInformation, granted_access) == 0x0);
};

/// `_OB_POST_DUPLICATE_HANDLE_INFORMATION` (wdm.h; 0x4 bytes).
#[repr(C)]
pub struct ObPostDuplicateHandleInformation {
    pub granted_access: Field<u32>,
}

unsafe impl NtStruct for ObPostDuplicateHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObPostDuplicateHandleInformation>() == 0x4);
    assert!(core::mem::offset_of!(ObPostDuplicateHandleInformation, granted_access) == 0x0);
};

/// `_OB_POST_OPERATION_PARAMETERS` (wdm.h; 0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ObPostOperationParametersView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ObPostOperationParameters {
    pub create_handle_information: ObPostCreateHandleInformation,
}

/// Vista 1 de `_OB_POST_OPERATION_PARAMETERS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ObPostOperationParametersView1 {
    pub duplicate_handle_information: ObPostDuplicateHandleInformation,
}

impl core::ops::Deref for ObPostOperationParameters {
    type Target = ObPostOperationParametersView1;
    #[inline(always)]
    fn deref(&self) -> &ObPostOperationParametersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ObPostOperationParametersView1>() }
    }
}

unsafe impl NtStruct for ObPostOperationParameters {}

const _: () = {
    assert!(core::mem::size_of::<ObPostOperationParameters>() == 0x4);
    assert!(core::mem::offset_of!(ObPostOperationParameters, create_handle_information) == 0x0);
    assert!(core::mem::size_of::<ObPostOperationParametersView1>() == 0x4);
    assert!(core::mem::align_of::<ObPostOperationParametersView1>() == core::mem::align_of::<ObPostOperationParameters>());
    assert!(core::mem::offset_of!(ObPostOperationParametersView1, duplicate_handle_information) == 0x0);
};

/// `_OB_POST_OPERATION_INFORMATION` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct ObPostOperationInformation {
    pub operation: Field<u32>,
    pub flags: Field<u32>,
    /// -> `void`
    pub object: Field<u64>,
    /// -> `_OBJECT_TYPE`
    pub object_type: Field<u64>,
    /// -> `void`
    pub call_context: Field<u64>,
    pub return_status: Field<i32>,
    _pad_24: Reserved<0x4>,
    /// -> `_OB_POST_OPERATION_PARAMETERS`
    pub parameters: Field<u64>,
}

unsafe impl NtStruct for ObPostOperationInformation {}

impl ObPostOperationInformation {
    /// `KernelHandle`: bits 0..=0 de `flags`.
    pub const KERNEL_HANDLE_SHIFT: u32 = 0;
    pub const KERNEL_HANDLE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn kernel_handle(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_kernel_handle(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=31 de `flags`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u32 = 0xfffffffe;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.flags.bits(1, 31) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.flags.set_bits(1, 31, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ObPostOperationInformation>() == 0x30);
    assert!(core::mem::offset_of!(ObPostOperationInformation, operation) == 0x0);
    assert!(core::mem::offset_of!(ObPostOperationInformation, flags) == 0x4);
    assert!(core::mem::offset_of!(ObPostOperationInformation, object) == 0x8);
    assert!(core::mem::offset_of!(ObPostOperationInformation, object_type) == 0x10);
    assert!(core::mem::offset_of!(ObPostOperationInformation, call_context) == 0x18);
    assert!(core::mem::offset_of!(ObPostOperationInformation, return_status) == 0x20);
    assert!(core::mem::offset_of!(ObPostOperationInformation, parameters) == 0x28);
};

/// `_IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS` (wdm.h; 0x48 bytes).
#[repr(C)]
pub struct IoConnectInterruptFullySpecifiedParameters {
    /// -> `_DEVICE_OBJECT`
    pub physical_device_object: Field<u64>,
    /// -> `PKINTERRUPT`
    pub interrupt_object: Field<u64>,
    /// -> `void`
    pub service_routine: Field<u64>,
    /// -> `void`
    pub service_context: Field<u64>,
    /// -> `void`
    pub spin_lock: Field<u64>,
    pub synchronize_irql: Field<u8>,
    pub floating_save: Field<u8>,
    pub share_vector: Field<u8>,
    _pad_2b: Reserved<0x1>,
    pub vector: Field<u32>,
    pub irql: Field<u8>,
    _pad_31: Reserved<0x3>,
    pub interrupt_mode: Field<i32>,
    pub processor_enable_mask: Field<u64>,
    pub group: Field<u16>,
    _pad_42: Reserved<0x6>,
}

unsafe impl NtStruct for IoConnectInterruptFullySpecifiedParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoConnectInterruptFullySpecifiedParameters>() == 0x48);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, physical_device_object) == 0x0);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, interrupt_object) == 0x8);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, service_routine) == 0x10);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, service_context) == 0x18);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, spin_lock) == 0x20);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, synchronize_irql) == 0x28);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, floating_save) == 0x29);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, share_vector) == 0x2a);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, vector) == 0x2c);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, irql) == 0x30);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, interrupt_mode) == 0x34);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, processor_enable_mask) == 0x38);
    assert!(core::mem::offset_of!(IoConnectInterruptFullySpecifiedParameters, group) == 0x40);
};

/// `_IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct IoConnectInterruptLineBasedParameters {
    /// -> `_DEVICE_OBJECT`
    pub physical_device_object: Field<u64>,
    /// -> `PKINTERRUPT`
    pub interrupt_object: Field<u64>,
    /// -> `void`
    pub service_routine: Field<u64>,
    /// -> `void`
    pub service_context: Field<u64>,
    /// -> `void`
    pub spin_lock: Field<u64>,
    pub synchronize_irql: Field<u8>,
    pub floating_save: Field<u8>,
    _pad_2a: Reserved<0x6>,
}

unsafe impl NtStruct for IoConnectInterruptLineBasedParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoConnectInterruptLineBasedParameters>() == 0x30);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, physical_device_object) == 0x0);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, interrupt_object) == 0x8);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, service_routine) == 0x10);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, service_context) == 0x18);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, spin_lock) == 0x20);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, synchronize_irql) == 0x28);
    assert!(core::mem::offset_of!(IoConnectInterruptLineBasedParameters, floating_save) == 0x29);
};

/// `_IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS` (wdm.h; 0x38 bytes).
#[repr(C)]
pub struct IoConnectInterruptMessageBasedParameters {
    /// -> `_DEVICE_OBJECT`
    pub physical_device_object: Field<u64>,
    /// -> `união Generic/InterruptMessageTable/InterruptObject`
    pub connection_context: Field<u64>,
    /// -> `void`
    pub message_service_routine: Field<u64>,
    /// -> `void`
    pub service_context: Field<u64>,
    /// -> `void`
    pub spin_lock: Field<u64>,
    pub synchronize_irql: Field<u8>,
    pub floating_save: Field<u8>,
    _pad_2a: Reserved<0x6>,
    /// -> `void`
    pub fall_back_service_routine: Field<u64>,
}

unsafe impl NtStruct for IoConnectInterruptMessageBasedParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoConnectInterruptMessageBasedParameters>() == 0x38);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, physical_device_object) == 0x0);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, connection_context) == 0x8);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, message_service_routine) == 0x10);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, service_context) == 0x18);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, spin_lock) == 0x20);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, synchronize_irql) == 0x28);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, floating_save) == 0x29);
    assert!(core::mem::offset_of!(IoConnectInterruptMessageBasedParameters, fall_back_service_routine) == 0x30);
};

/// `_IO_CONNECT_INTERRUPT_PARAMETERS` (wdm.h; 0x50 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoConnectInterruptParametersView1`..`IoConnectInterruptParametersView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct IoConnectInterruptParameters {
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub fully_specified: IoConnectInterruptFullySpecifiedParameters,
}

/// Vista 1 de `_IO_CONNECT_INTERRUPT_PARAMETERS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoConnectInterruptParametersView1 {
    _pad_0: Reserved<0x8>,
    pub line_based: IoConnectInterruptLineBasedParameters,
    _pad_38: Reserved<0x18>,
}

/// Vista 2 de `_IO_CONNECT_INTERRUPT_PARAMETERS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoConnectInterruptParametersView2 {
    _pad_0: Reserved<0x8>,
    pub message_based: IoConnectInterruptMessageBasedParameters,
    _pad_40: Reserved<0x10>,
}

impl core::ops::Deref for IoConnectInterruptParameters {
    type Target = IoConnectInterruptParametersView1;
    #[inline(always)]
    fn deref(&self) -> &IoConnectInterruptParametersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoConnectInterruptParametersView1>() }
    }
}

impl core::ops::Deref for IoConnectInterruptParametersView1 {
    type Target = IoConnectInterruptParametersView2;
    #[inline(always)]
    fn deref(&self) -> &IoConnectInterruptParametersView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoConnectInterruptParametersView2>() }
    }
}

unsafe impl NtStruct for IoConnectInterruptParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoConnectInterruptParameters>() == 0x50);
    assert!(core::mem::offset_of!(IoConnectInterruptParameters, version) == 0x0);
    assert!(core::mem::offset_of!(IoConnectInterruptParameters, fully_specified) == 0x8);
    assert!(core::mem::size_of::<IoConnectInterruptParametersView1>() == 0x50);
    assert!(core::mem::align_of::<IoConnectInterruptParametersView1>() == core::mem::align_of::<IoConnectInterruptParameters>());
    assert!(core::mem::offset_of!(IoConnectInterruptParametersView1, line_based) == 0x8);
    assert!(core::mem::size_of::<IoConnectInterruptParametersView2>() == 0x50);
    assert!(core::mem::align_of::<IoConnectInterruptParametersView2>() == core::mem::align_of::<IoConnectInterruptParameters>());
    assert!(core::mem::offset_of!(IoConnectInterruptParametersView2, message_based) == 0x8);
};

/// `_IO_DISCONNECT_INTERRUPT_PARAMETERS` (wdm.h; 0x10 bytes).
#[repr(C)]
pub struct IoDisconnectInterruptParameters {
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub connection_context: Field<u64>,
}

unsafe impl NtStruct for IoDisconnectInterruptParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoDisconnectInterruptParameters>() == 0x10);
    assert!(core::mem::offset_of!(IoDisconnectInterruptParameters, version) == 0x0);
    assert!(core::mem::offset_of!(IoDisconnectInterruptParameters, connection_context) == 0x8);
};

/// `_REG_POST_OPERATION_INFORMATION` (wdm.h; 0x38 bytes).
#[repr(C)]
pub struct RegPostOperationInformation {
    /// -> `void`
    pub object: Field<u64>,
    pub status: Field<i32>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub pre_information: Field<u64>,
    pub return_status: Field<i32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub call_context: Field<u64>,
    /// -> `void`
    pub object_context: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
}

unsafe impl NtStruct for RegPostOperationInformation {}

const _: () = {
    assert!(core::mem::size_of::<RegPostOperationInformation>() == 0x38);
    assert!(core::mem::offset_of!(RegPostOperationInformation, object) == 0x0);
    assert!(core::mem::offset_of!(RegPostOperationInformation, status) == 0x8);
    assert!(core::mem::offset_of!(RegPostOperationInformation, pre_information) == 0x10);
    assert!(core::mem::offset_of!(RegPostOperationInformation, return_status) == 0x18);
    assert!(core::mem::offset_of!(RegPostOperationInformation, call_context) == 0x20);
    assert!(core::mem::offset_of!(RegPostOperationInformation, object_context) == 0x28);
    assert!(core::mem::offset_of!(RegPostOperationInformation, reserved) == 0x30);
};

/// `_DEVICE_INTERFACE_CHANGE_NOTIFICATION` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct DeviceInterfaceChangeNotification {
    pub version: Field<u16>,
    pub size: Field<u16>,
    pub event: Guid,
    pub interface_class_guid: Guid,
    _pad_24: Reserved<0x4>,
    /// -> `_UNICODE_STRING`
    pub symbolic_link_name: Field<u64>,
}

unsafe impl NtStruct for DeviceInterfaceChangeNotification {}

const _: () = {
    assert!(core::mem::size_of::<DeviceInterfaceChangeNotification>() == 0x30);
    assert!(core::mem::offset_of!(DeviceInterfaceChangeNotification, version) == 0x0);
    assert!(core::mem::offset_of!(DeviceInterfaceChangeNotification, size) == 0x2);
    assert!(core::mem::offset_of!(DeviceInterfaceChangeNotification, event) == 0x4);
    assert!(core::mem::offset_of!(DeviceInterfaceChangeNotification, interface_class_guid) == 0x14);
    assert!(core::mem::offset_of!(DeviceInterfaceChangeNotification, symbolic_link_name) == 0x28);
};

/// `_KEY_VALUE_PARTIAL_INFORMATION` (wdm.h; 0x10 bytes).
#[repr(C)]
pub struct KeyValuePartialInformation {
    pub title_index: Field<u32>,
    pub type_: Field<u32>,
    pub data_length: Field<u32>,
    pub data: [Field<u8>; 1],
    _pad_d: Reserved<0x3>,
}

unsafe impl NtStruct for KeyValuePartialInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyValuePartialInformation>() == 0x10);
    assert!(core::mem::offset_of!(KeyValuePartialInformation, title_index) == 0x0);
    assert!(core::mem::offset_of!(KeyValuePartialInformation, type_) == 0x4);
    assert!(core::mem::offset_of!(KeyValuePartialInformation, data_length) == 0x8);
    assert!(core::mem::offset_of!(KeyValuePartialInformation, data) == 0xc);
};

/// `_KEY_VALUE_PARTIAL_INFORMATION_ALIGN64` (wdm.h; 0xc bytes).
#[repr(C)]
pub struct KeyValuePartialInformationAlign64 {
    pub type_: Field<u32>,
    pub data_length: Field<u32>,
    pub data: [Field<u8>; 1],
    _pad_9: Reserved<0x3>,
}

unsafe impl NtStruct for KeyValuePartialInformationAlign64 {}

const _: () = {
    assert!(core::mem::size_of::<KeyValuePartialInformationAlign64>() == 0xc);
    assert!(core::mem::offset_of!(KeyValuePartialInformationAlign64, type_) == 0x0);
    assert!(core::mem::offset_of!(KeyValuePartialInformationAlign64, data_length) == 0x4);
    assert!(core::mem::offset_of!(KeyValuePartialInformationAlign64, data) == 0x8);
};

/// `_KEY_VALUE_FULL_INFORMATION` (wdm.h; 0x18 bytes).
#[repr(C)]
pub struct KeyValueFullInformation {
    pub title_index: Field<u32>,
    pub type_: Field<u32>,
    pub data_offset: Field<u32>,
    pub data_length: Field<u32>,
    pub name_length: Field<u32>,
    pub name: [Field<u16>; 1],
    _pad_16: Reserved<0x2>,
}

unsafe impl NtStruct for KeyValueFullInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyValueFullInformation>() == 0x18);
    assert!(core::mem::offset_of!(KeyValueFullInformation, title_index) == 0x0);
    assert!(core::mem::offset_of!(KeyValueFullInformation, type_) == 0x4);
    assert!(core::mem::offset_of!(KeyValueFullInformation, data_offset) == 0x8);
    assert!(core::mem::offset_of!(KeyValueFullInformation, data_length) == 0xc);
    assert!(core::mem::offset_of!(KeyValueFullInformation, name_length) == 0x10);
    assert!(core::mem::offset_of!(KeyValueFullInformation, name) == 0x14);
};

/// `_KEY_VALUE_BASIC_INFORMATION` (wdm.h; 0x10 bytes).
#[repr(C)]
pub struct KeyValueBasicInformation {
    pub title_index: Field<u32>,
    pub type_: Field<u32>,
    pub name_length: Field<u32>,
    pub name: [Field<u16>; 1],
    _pad_e: Reserved<0x2>,
}

unsafe impl NtStruct for KeyValueBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyValueBasicInformation>() == 0x10);
    assert!(core::mem::offset_of!(KeyValueBasicInformation, title_index) == 0x0);
    assert!(core::mem::offset_of!(KeyValueBasicInformation, type_) == 0x4);
    assert!(core::mem::offset_of!(KeyValueBasicInformation, name_length) == 0x8);
    assert!(core::mem::offset_of!(KeyValueBasicInformation, name) == 0xc);
};

/// `_KEY_BASIC_INFORMATION` (wdm.h; 0x18 bytes).
#[repr(C)]
pub struct KeyBasicInformation {
    pub last_write_time: LargeInteger,
    pub title_index: Field<u32>,
    pub name_length: Field<u32>,
    pub name: [Field<u16>; 1],
    _pad_12: Reserved<0x6>,
}

unsafe impl NtStruct for KeyBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyBasicInformation>() == 0x18);
    assert!(core::mem::offset_of!(KeyBasicInformation, last_write_time) == 0x0);
    assert!(core::mem::offset_of!(KeyBasicInformation, title_index) == 0x8);
    assert!(core::mem::offset_of!(KeyBasicInformation, name_length) == 0xc);
    assert!(core::mem::offset_of!(KeyBasicInformation, name) == 0x10);
};

/// `_KEY_NODE_INFORMATION` (wdm.h; 0x20 bytes).
#[repr(C)]
pub struct KeyNodeInformation {
    pub last_write_time: LargeInteger,
    pub title_index: Field<u32>,
    pub class_offset: Field<u32>,
    pub class_length: Field<u32>,
    pub name_length: Field<u32>,
    pub name: [Field<u16>; 1],
    _pad_1a: Reserved<0x6>,
}

unsafe impl NtStruct for KeyNodeInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyNodeInformation>() == 0x20);
    assert!(core::mem::offset_of!(KeyNodeInformation, last_write_time) == 0x0);
    assert!(core::mem::offset_of!(KeyNodeInformation, title_index) == 0x8);
    assert!(core::mem::offset_of!(KeyNodeInformation, class_offset) == 0xc);
    assert!(core::mem::offset_of!(KeyNodeInformation, class_length) == 0x10);
    assert!(core::mem::offset_of!(KeyNodeInformation, name_length) == 0x14);
    assert!(core::mem::offset_of!(KeyNodeInformation, name) == 0x18);
};

/// `_KEY_FULL_INFORMATION` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct KeyFullInformation {
    pub last_write_time: LargeInteger,
    pub title_index: Field<u32>,
    pub class_offset: Field<u32>,
    pub class_length: Field<u32>,
    pub sub_keys: Field<u32>,
    pub max_name_len: Field<u32>,
    pub max_class_len: Field<u32>,
    pub values: Field<u32>,
    pub max_value_name_len: Field<u32>,
    pub max_value_data_len: Field<u32>,
    pub class: [Field<u16>; 1],
    _pad_2e: Reserved<0x2>,
}

unsafe impl NtStruct for KeyFullInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyFullInformation>() == 0x30);
    assert!(core::mem::offset_of!(KeyFullInformation, last_write_time) == 0x0);
    assert!(core::mem::offset_of!(KeyFullInformation, title_index) == 0x8);
    assert!(core::mem::offset_of!(KeyFullInformation, class_offset) == 0xc);
    assert!(core::mem::offset_of!(KeyFullInformation, class_length) == 0x10);
    assert!(core::mem::offset_of!(KeyFullInformation, sub_keys) == 0x14);
    assert!(core::mem::offset_of!(KeyFullInformation, max_name_len) == 0x18);
    assert!(core::mem::offset_of!(KeyFullInformation, max_class_len) == 0x1c);
    assert!(core::mem::offset_of!(KeyFullInformation, values) == 0x20);
    assert!(core::mem::offset_of!(KeyFullInformation, max_value_name_len) == 0x24);
    assert!(core::mem::offset_of!(KeyFullInformation, max_value_data_len) == 0x28);
    assert!(core::mem::offset_of!(KeyFullInformation, class) == 0x2c);
};

/// `_OSVERSIONINFOEXW` (wdm.h (RTL_OSVERSIONINFOEXW); 0x11c bytes).
#[repr(C)]
pub struct OsVersionInfoExW {
    pub dw_os_version_info_size: Field<u32>,
    pub dw_major_version: Field<u32>,
    pub dw_minor_version: Field<u32>,
    pub dw_build_number: Field<u32>,
    pub dw_platform_id: Field<u32>,
    pub sz_csd_version: [Field<u16>; 128],
    pub w_service_pack_major: Field<u16>,
    pub w_service_pack_minor: Field<u16>,
    pub w_suite_mask: Field<u16>,
    pub w_product_type: Field<u8>,
    pub w_reserved: Field<u8>,
}

unsafe impl NtStruct for OsVersionInfoExW {}

const _: () = {
    assert!(core::mem::size_of::<OsVersionInfoExW>() == 0x11c);
    assert!(core::mem::offset_of!(OsVersionInfoExW, dw_os_version_info_size) == 0x0);
    assert!(core::mem::offset_of!(OsVersionInfoExW, dw_major_version) == 0x4);
    assert!(core::mem::offset_of!(OsVersionInfoExW, dw_minor_version) == 0x8);
    assert!(core::mem::offset_of!(OsVersionInfoExW, dw_build_number) == 0xc);
    assert!(core::mem::offset_of!(OsVersionInfoExW, dw_platform_id) == 0x10);
    assert!(core::mem::offset_of!(OsVersionInfoExW, sz_csd_version) == 0x14);
    assert!(core::mem::offset_of!(OsVersionInfoExW, w_service_pack_major) == 0x114);
    assert!(core::mem::offset_of!(OsVersionInfoExW, w_service_pack_minor) == 0x116);
    assert!(core::mem::offset_of!(OsVersionInfoExW, w_suite_mask) == 0x118);
    assert!(core::mem::offset_of!(OsVersionInfoExW, w_product_type) == 0x11a);
    assert!(core::mem::offset_of!(OsVersionInfoExW, w_reserved) == 0x11b);
};

/// `_FILE_NAME_INFORMATION` (wdm.h; 0x8 bytes).
#[repr(C)]
pub struct FileNameInformation {
    pub file_name_length: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_6: Reserved<0x2>,
}

unsafe impl NtStruct for FileNameInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileNameInformation>() == 0x8);
    assert!(core::mem::offset_of!(FileNameInformation, file_name_length) == 0x0);
    assert!(core::mem::offset_of!(FileNameInformation, file_name) == 0x4);
};

/// `_FILE_POSITION_INFORMATION` (wdm.h; 0x8 bytes).
#[repr(C)]
pub struct FilePositionInformation {
    pub current_byte_offset: LargeInteger,
}

unsafe impl NtStruct for FilePositionInformation {}

const _: () = {
    assert!(core::mem::size_of::<FilePositionInformation>() == 0x8);
    assert!(core::mem::offset_of!(FilePositionInformation, current_byte_offset) == 0x0);
};

/// `_FILE_IO_COMPLETION_INFORMATION` (wdm.h; 0x20 bytes).
#[repr(C)]
pub struct FileIoCompletionInformation {
    /// -> `void`
    pub key_context: Field<u64>,
    /// -> `void`
    pub apc_context: Field<u64>,
    pub io_status_block: IoStatusBlock,
}

unsafe impl NtStruct for FileIoCompletionInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileIoCompletionInformation>() == 0x20);
    assert!(core::mem::offset_of!(FileIoCompletionInformation, key_context) == 0x0);
    assert!(core::mem::offset_of!(FileIoCompletionInformation, apc_context) == 0x8);
    assert!(core::mem::offset_of!(FileIoCompletionInformation, io_status_block) == 0x10);
};

/// `_SILO_MONITOR_REGISTRATION` (ntddk.h; 0x20 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SiloMonitorRegistrationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct SiloMonitorRegistration {
    pub version: Field<u8>,
    pub monitor_host: Field<u8>,
    pub monitor_existing_silos: Field<u8>,
    pub reserved: [Field<u8>; 5],
    /// -> `_UNICODE_STRING`
    pub driver_object_name: Field<u64>,
    /// -> `void`
    pub create_callback: Field<u64>,
    /// -> `void`
    pub terminate_callback: Field<u64>,
}

/// Vista 1 de `_SILO_MONITOR_REGISTRATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SiloMonitorRegistrationView1 {
    _pad_0: Reserved<0x8>,
    /// -> `_UNICODE_STRING`
    pub component_name: Field<u64>,
    _pad_10: Reserved<0x10>,
}

impl core::ops::Deref for SiloMonitorRegistration {
    type Target = SiloMonitorRegistrationView1;
    #[inline(always)]
    fn deref(&self) -> &SiloMonitorRegistrationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SiloMonitorRegistrationView1>() }
    }
}

unsafe impl NtStruct for SiloMonitorRegistration {}

const _: () = {
    assert!(core::mem::size_of::<SiloMonitorRegistration>() == 0x20);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, version) == 0x0);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, monitor_host) == 0x1);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, monitor_existing_silos) == 0x2);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, reserved) == 0x3);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, driver_object_name) == 0x8);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, create_callback) == 0x10);
    assert!(core::mem::offset_of!(SiloMonitorRegistration, terminate_callback) == 0x18);
    assert!(core::mem::size_of::<SiloMonitorRegistrationView1>() == 0x20);
    assert!(core::mem::align_of::<SiloMonitorRegistrationView1>() == core::mem::align_of::<SiloMonitorRegistration>());
    assert!(core::mem::offset_of!(SiloMonitorRegistrationView1, component_name) == 0x8);
};

/// `_PS_CREATE_NOTIFY_INFO` (ntddk.h; 0x48 bytes).
#[repr(C)]
pub struct PsCreateNotifyInfo {
    pub size: Field<u64>,
    pub flags: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub parent_process_id: Field<u64>,
    pub creating_thread_id: ClientId,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub image_file_name: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub command_line: Field<u64>,
    pub creation_status: Field<i32>,
    _pad_44: Reserved<0x4>,
}

unsafe impl NtStruct for PsCreateNotifyInfo {}

impl PsCreateNotifyInfo {
    /// `FileOpenNameAvailable`: bits 0..=0 de `flags`.
    pub const FILE_OPEN_NAME_AVAILABLE_SHIFT: u32 = 0;
    pub const FILE_OPEN_NAME_AVAILABLE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn file_open_name_available(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_file_open_name_available(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `IsSubsystemProcess`: bits 1..=1 de `flags`.
    pub const IS_SUBSYSTEM_PROCESS_SHIFT: u32 = 1;
    pub const IS_SUBSYSTEM_PROCESS_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn is_subsystem_process(&self) -> u32 {
        self.flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_subsystem_process(&self, value: u32) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=31 de `flags`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u32 = 0xfffffffc;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.flags.bits(2, 30) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.flags.set_bits(2, 30, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PsCreateNotifyInfo>() == 0x48);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, size) == 0x0);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, flags) == 0x8);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, parent_process_id) == 0x10);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, creating_thread_id) == 0x18);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, file_object) == 0x28);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, image_file_name) == 0x30);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, command_line) == 0x38);
    assert!(core::mem::offset_of!(PsCreateNotifyInfo, creation_status) == 0x40);
};

/// `_IMAGE_INFO` (ntddk.h; 0x28 bytes).
#[repr(C)]
pub struct ImageInfo {
    pub properties: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub image_base: Field<u64>,
    pub image_selector: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub image_size: Field<u64>,
    pub image_section_number: Field<u32>,
    _pad_24: Reserved<0x4>,
}

unsafe impl NtStruct for ImageInfo {}

impl ImageInfo {
    /// `ImageAddressingMode`: bits 0..=7 de `properties`.
    pub const IMAGE_ADDRESSING_MODE_SHIFT: u32 = 0;
    pub const IMAGE_ADDRESSING_MODE_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn image_addressing_mode(&self) -> u32 {
        self.properties.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_image_addressing_mode(&self, value: u32) {
        self.properties.set_bits(0, 8, value as u64)
    }
    /// `SystemModeImage`: bits 8..=8 de `properties`.
    pub const SYSTEM_MODE_IMAGE_SHIFT: u32 = 8;
    pub const SYSTEM_MODE_IMAGE_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn system_mode_image(&self) -> u32 {
        self.properties.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_mode_image(&self, value: u32) {
        self.properties.set_bits(8, 1, value as u64)
    }
    /// `ImageMappedToAllPids`: bits 9..=9 de `properties`.
    pub const IMAGE_MAPPED_TO_ALL_PIDS_SHIFT: u32 = 9;
    pub const IMAGE_MAPPED_TO_ALL_PIDS_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn image_mapped_to_all_pids(&self) -> u32 {
        self.properties.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_mapped_to_all_pids(&self, value: u32) {
        self.properties.set_bits(9, 1, value as u64)
    }
    /// `ExtendedInfoPresent`: bits 10..=10 de `properties`.
    pub const EXTENDED_INFO_PRESENT_SHIFT: u32 = 10;
    pub const EXTENDED_INFO_PRESENT_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn extended_info_present(&self) -> u32 {
        self.properties.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_extended_info_present(&self, value: u32) {
        self.properties.set_bits(10, 1, value as u64)
    }
    /// `MachineTypeMismatch`: bits 11..=11 de `properties`.
    pub const MACHINE_TYPE_MISMATCH_SHIFT: u32 = 11;
    pub const MACHINE_TYPE_MISMATCH_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn machine_type_mismatch(&self) -> u32 {
        self.properties.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_machine_type_mismatch(&self, value: u32) {
        self.properties.set_bits(11, 1, value as u64)
    }
    /// `ImageSignatureLevel`: bits 12..=15 de `properties`.
    pub const IMAGE_SIGNATURE_LEVEL_SHIFT: u32 = 12;
    pub const IMAGE_SIGNATURE_LEVEL_MASK: u32 = 0xf000;
    #[inline(always)]
    pub fn image_signature_level(&self) -> u32 {
        self.properties.bits(12, 4) as u32
    }
    #[inline(always)]
    pub fn set_image_signature_level(&self, value: u32) {
        self.properties.set_bits(12, 4, value as u64)
    }
    /// `ImageSignatureType`: bits 16..=18 de `properties`.
    pub const IMAGE_SIGNATURE_TYPE_SHIFT: u32 = 16;
    pub const IMAGE_SIGNATURE_TYPE_MASK: u32 = 0x70000;
    #[inline(always)]
    pub fn image_signature_type(&self) -> u32 {
        self.properties.bits(16, 3) as u32
    }
    #[inline(always)]
    pub fn set_image_signature_type(&self, value: u32) {
        self.properties.set_bits(16, 3, value as u64)
    }
    /// `ImagePartialMap`: bits 19..=19 de `properties`.
    pub const IMAGE_PARTIAL_MAP_SHIFT: u32 = 19;
    pub const IMAGE_PARTIAL_MAP_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn image_partial_map(&self) -> u32 {
        self.properties.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_partial_map(&self, value: u32) {
        self.properties.set_bits(19, 1, value as u64)
    }
    /// `Reserved`: bits 20..=31 de `properties`.
    pub const RESERVED_SHIFT: u32 = 20;
    pub const RESERVED_MASK: u32 = 0xfff00000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.properties.bits(20, 12) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.properties.set_bits(20, 12, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ImageInfo>() == 0x28);
    assert!(core::mem::offset_of!(ImageInfo, properties) == 0x0);
    assert!(core::mem::offset_of!(ImageInfo, image_base) == 0x8);
    assert!(core::mem::offset_of!(ImageInfo, image_selector) == 0x10);
    assert!(core::mem::offset_of!(ImageInfo, image_size) == 0x18);
    assert!(core::mem::offset_of!(ImageInfo, image_section_number) == 0x20);
};

/// `_IMAGE_INFO_EX` (ntddk.h; 0x38 bytes).
#[repr(C)]
pub struct ImageInfoEx {
    pub size: Field<u64>,
    pub image_info: ImageInfo,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
}

unsafe impl NtStruct for ImageInfoEx {}

const _: () = {
    assert!(core::mem::size_of::<ImageInfoEx>() == 0x38);
    assert!(core::mem::offset_of!(ImageInfoEx, size) == 0x0);
    assert!(core::mem::offset_of!(ImageInfoEx, image_info) == 0x8);
    assert!(core::mem::offset_of!(ImageInfoEx, file_object) == 0x30);
};

/// `_BDCB_IMAGE_INFORMATION` (ntddk.h; 0x68 bytes).
#[repr(C)]
pub struct BdcbImageInformation {
    pub classification: Field<i32>,
    pub image_flags: Field<u32>,
    pub image_name: UnicodeString,
    pub registry_path: UnicodeString,
    pub certificate_publisher: UnicodeString,
    pub certificate_issuer: UnicodeString,
    /// -> `void`
    pub image_hash: Field<u64>,
    /// -> `void`
    pub certificate_thumbprint: Field<u64>,
    pub image_hash_algorithm: Field<u32>,
    pub thumbprint_hash_algorithm: Field<u32>,
    pub image_hash_length: Field<u32>,
    pub certificate_thumbprint_length: Field<u32>,
}

unsafe impl NtStruct for BdcbImageInformation {}

const _: () = {
    assert!(core::mem::size_of::<BdcbImageInformation>() == 0x68);
    assert!(core::mem::offset_of!(BdcbImageInformation, classification) == 0x0);
    assert!(core::mem::offset_of!(BdcbImageInformation, image_flags) == 0x4);
    assert!(core::mem::offset_of!(BdcbImageInformation, image_name) == 0x8);
    assert!(core::mem::offset_of!(BdcbImageInformation, registry_path) == 0x18);
    assert!(core::mem::offset_of!(BdcbImageInformation, certificate_publisher) == 0x28);
    assert!(core::mem::offset_of!(BdcbImageInformation, certificate_issuer) == 0x38);
    assert!(core::mem::offset_of!(BdcbImageInformation, image_hash) == 0x48);
    assert!(core::mem::offset_of!(BdcbImageInformation, certificate_thumbprint) == 0x50);
    assert!(core::mem::offset_of!(BdcbImageInformation, image_hash_algorithm) == 0x58);
    assert!(core::mem::offset_of!(BdcbImageInformation, thumbprint_hash_algorithm) == 0x5c);
    assert!(core::mem::offset_of!(BdcbImageInformation, image_hash_length) == 0x60);
    assert!(core::mem::offset_of!(BdcbImageInformation, certificate_thumbprint_length) == 0x64);
};

/// `_RTL_GENERIC_TABLE` (ntddk.h; 0x48 bytes).
#[repr(C)]
pub struct RtlGenericTable {
    /// -> `_RTL_SPLAY_LINKS`
    pub table_root: Field<u64>,
    pub insert_order_list: ListEntry,
    /// -> `_LIST_ENTRY`
    pub ordered_pointer: Field<u64>,
    pub which_ordered_element: Field<u32>,
    pub number_generic_table_elements: Field<u32>,
    /// -> `void`
    pub compare_routine: Field<u64>,
    /// -> `void`
    pub allocate_routine: Field<u64>,
    /// -> `void`
    pub free_routine: Field<u64>,
    /// -> `void`
    pub table_context: Field<u64>,
}

unsafe impl NtStruct for RtlGenericTable {}

const _: () = {
    assert!(core::mem::size_of::<RtlGenericTable>() == 0x48);
    assert!(core::mem::offset_of!(RtlGenericTable, table_root) == 0x0);
    assert!(core::mem::offset_of!(RtlGenericTable, insert_order_list) == 0x8);
    assert!(core::mem::offset_of!(RtlGenericTable, ordered_pointer) == 0x18);
    assert!(core::mem::offset_of!(RtlGenericTable, which_ordered_element) == 0x20);
    assert!(core::mem::offset_of!(RtlGenericTable, number_generic_table_elements) == 0x24);
    assert!(core::mem::offset_of!(RtlGenericTable, compare_routine) == 0x28);
    assert!(core::mem::offset_of!(RtlGenericTable, allocate_routine) == 0x30);
    assert!(core::mem::offset_of!(RtlGenericTable, free_routine) == 0x38);
    assert!(core::mem::offset_of!(RtlGenericTable, table_context) == 0x40);
};

/// `_PHYSICAL_MEMORY_RANGE` (ntddk.h; 0x10 bytes).
#[repr(C)]
pub struct PhysicalMemoryRange {
    pub base_address: LargeInteger,
    pub number_of_bytes: LargeInteger,
}

unsafe impl NtStruct for PhysicalMemoryRange {}

const _: () = {
    assert!(core::mem::size_of::<PhysicalMemoryRange>() == 0x10);
    assert!(core::mem::offset_of!(PhysicalMemoryRange, base_address) == 0x0);
    assert!(core::mem::offset_of!(PhysicalMemoryRange, number_of_bytes) == 0x8);
};

/// `_KEY_NAME_INFORMATION` (ntddk.h; 0x8 bytes).
#[repr(C)]
pub struct KeyNameInformation {
    pub name_length: Field<u32>,
    pub name: [Field<u16>; 1],
    _pad_6: Reserved<0x2>,
}

unsafe impl NtStruct for KeyNameInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyNameInformation>() == 0x8);
    assert!(core::mem::offset_of!(KeyNameInformation, name_length) == 0x0);
    assert!(core::mem::offset_of!(KeyNameInformation, name) == 0x4);
};

/// `_KEY_CACHED_INFORMATION` (ntddk.h; 0x28 bytes).
#[repr(C)]
pub struct KeyCachedInformation {
    pub last_write_time: LargeInteger,
    pub title_index: Field<u32>,
    pub sub_keys: Field<u32>,
    pub max_name_len: Field<u32>,
    pub values: Field<u32>,
    pub max_value_name_len: Field<u32>,
    pub max_value_data_len: Field<u32>,
    pub name_length: Field<u32>,
    _pad_24: Reserved<0x4>,
}

unsafe impl NtStruct for KeyCachedInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyCachedInformation>() == 0x28);
    assert!(core::mem::offset_of!(KeyCachedInformation, last_write_time) == 0x0);
    assert!(core::mem::offset_of!(KeyCachedInformation, title_index) == 0x8);
    assert!(core::mem::offset_of!(KeyCachedInformation, sub_keys) == 0xc);
    assert!(core::mem::offset_of!(KeyCachedInformation, max_name_len) == 0x10);
    assert!(core::mem::offset_of!(KeyCachedInformation, values) == 0x14);
    assert!(core::mem::offset_of!(KeyCachedInformation, max_value_name_len) == 0x18);
    assert!(core::mem::offset_of!(KeyCachedInformation, max_value_data_len) == 0x1c);
    assert!(core::mem::offset_of!(KeyCachedInformation, name_length) == 0x20);
};

/// `_KEY_HANDLE_TAGS_INFORMATION` (ntddk.h; 0x4 bytes).
#[repr(C)]
pub struct KeyHandleTagsInformation {
    pub handle_tags: Field<u32>,
}

unsafe impl NtStruct for KeyHandleTagsInformation {}

const _: () = {
    assert!(core::mem::size_of::<KeyHandleTagsInformation>() == 0x4);
    assert!(core::mem::offset_of!(KeyHandleTagsInformation, handle_tags) == 0x0);
};

/// `_FILE_INTERNAL_INFORMATION` (ntddk.h; 0x8 bytes).
#[repr(C)]
pub struct FileInternalInformation {
    pub index_number: LargeInteger,
}

unsafe impl NtStruct for FileInternalInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileInternalInformation>() == 0x8);
    assert!(core::mem::offset_of!(FileInternalInformation, index_number) == 0x0);
};

/// `_FILE_EA_INFORMATION` (ntddk.h; 0x4 bytes).
#[repr(C)]
pub struct FileEaInformation {
    pub ea_size: Field<u32>,
}

unsafe impl NtStruct for FileEaInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileEaInformation>() == 0x4);
    assert!(core::mem::offset_of!(FileEaInformation, ea_size) == 0x0);
};

/// `_FILE_ALIGNMENT_INFORMATION` (ntddk.h; 0x4 bytes).
#[repr(C)]
pub struct FileAlignmentInformation {
    pub alignment_requirement: Field<u32>,
}

unsafe impl NtStruct for FileAlignmentInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileAlignmentInformation>() == 0x4);
    assert!(core::mem::offset_of!(FileAlignmentInformation, alignment_requirement) == 0x0);
};

/// `_FILE_ATTRIBUTE_TAG_INFORMATION` (ntddk.h; 0x8 bytes).
#[repr(C)]
pub struct FileAttributeTagInformation {
    pub file_attributes: Field<u32>,
    pub reparse_tag: Field<u32>,
}

unsafe impl NtStruct for FileAttributeTagInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileAttributeTagInformation>() == 0x8);
    assert!(core::mem::offset_of!(FileAttributeTagInformation, file_attributes) == 0x0);
    assert!(core::mem::offset_of!(FileAttributeTagInformation, reparse_tag) == 0x4);
};

/// `_FILE_DISPOSITION_INFORMATION` (ntddk.h; 0x1 bytes).
#[repr(C)]
pub struct FileDispositionInformation {
    pub delete_file: Field<u8>,
}

unsafe impl NtStruct for FileDispositionInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileDispositionInformation>() == 0x1);
    assert!(core::mem::offset_of!(FileDispositionInformation, delete_file) == 0x0);
};

/// `_FILE_DISPOSITION_INFORMATION_EX` (ntddk.h; 0x4 bytes).
#[repr(C)]
pub struct FileDispositionInformationEx {
    pub flags: Field<u32>,
}

unsafe impl NtStruct for FileDispositionInformationEx {}

const _: () = {
    assert!(core::mem::size_of::<FileDispositionInformationEx>() == 0x4);
    assert!(core::mem::offset_of!(FileDispositionInformationEx, flags) == 0x0);
};

/// `_FILE_FS_VOLUME_INFORMATION` (ntddk.h; 0x18 bytes).
#[repr(C)]
pub struct FileFsVolumeInformation {
    pub volume_creation_time: LargeInteger,
    pub volume_serial_number: Field<u32>,
    pub volume_label_length: Field<u32>,
    pub supports_objects: Field<u8>,
    _pad_11: Reserved<0x1>,
    pub volume_label: [Field<u16>; 1],
    _pad_14: Reserved<0x4>,
}

unsafe impl NtStruct for FileFsVolumeInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileFsVolumeInformation>() == 0x18);
    assert!(core::mem::offset_of!(FileFsVolumeInformation, volume_creation_time) == 0x0);
    assert!(core::mem::offset_of!(FileFsVolumeInformation, volume_serial_number) == 0x8);
    assert!(core::mem::offset_of!(FileFsVolumeInformation, volume_label_length) == 0xc);
    assert!(core::mem::offset_of!(FileFsVolumeInformation, supports_objects) == 0x10);
    assert!(core::mem::offset_of!(FileFsVolumeInformation, volume_label) == 0x12);
};

/// `_FILE_FS_SIZE_INFORMATION` (ntddk.h; 0x18 bytes).
#[repr(C)]
pub struct FileFsSizeInformation {
    pub total_allocation_units: LargeInteger,
    pub available_allocation_units: LargeInteger,
    pub sectors_per_allocation_unit: Field<u32>,
    pub bytes_per_sector: Field<u32>,
}

unsafe impl NtStruct for FileFsSizeInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileFsSizeInformation>() == 0x18);
    assert!(core::mem::offset_of!(FileFsSizeInformation, total_allocation_units) == 0x0);
    assert!(core::mem::offset_of!(FileFsSizeInformation, available_allocation_units) == 0x8);
    assert!(core::mem::offset_of!(FileFsSizeInformation, sectors_per_allocation_unit) == 0x10);
    assert!(core::mem::offset_of!(FileFsSizeInformation, bytes_per_sector) == 0x14);
};

/// `_FILE_DIRECTORY_INFORMATION` (ntifs.h; 0x48 bytes).
#[repr(C)]
pub struct FileDirectoryInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: Field<u32>,
    pub file_name_length: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_42: Reserved<0x6>,
}

unsafe impl NtStruct for FileDirectoryInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileDirectoryInformation>() == 0x48);
    assert!(core::mem::offset_of!(FileDirectoryInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileDirectoryInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileDirectoryInformation, creation_time) == 0x8);
    assert!(core::mem::offset_of!(FileDirectoryInformation, last_access_time) == 0x10);
    assert!(core::mem::offset_of!(FileDirectoryInformation, last_write_time) == 0x18);
    assert!(core::mem::offset_of!(FileDirectoryInformation, change_time) == 0x20);
    assert!(core::mem::offset_of!(FileDirectoryInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileDirectoryInformation, allocation_size) == 0x30);
    assert!(core::mem::offset_of!(FileDirectoryInformation, file_attributes) == 0x38);
    assert!(core::mem::offset_of!(FileDirectoryInformation, file_name_length) == 0x3c);
    assert!(core::mem::offset_of!(FileDirectoryInformation, file_name) == 0x40);
};

/// `_FILE_FULL_DIR_INFORMATION` (ntifs.h; 0x48 bytes).
#[repr(C)]
pub struct FileFullDirInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: Field<u32>,
    pub file_name_length: Field<u32>,
    pub ea_size: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_46: Reserved<0x2>,
}

unsafe impl NtStruct for FileFullDirInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileFullDirInformation>() == 0x48);
    assert!(core::mem::offset_of!(FileFullDirInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileFullDirInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileFullDirInformation, creation_time) == 0x8);
    assert!(core::mem::offset_of!(FileFullDirInformation, last_access_time) == 0x10);
    assert!(core::mem::offset_of!(FileFullDirInformation, last_write_time) == 0x18);
    assert!(core::mem::offset_of!(FileFullDirInformation, change_time) == 0x20);
    assert!(core::mem::offset_of!(FileFullDirInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileFullDirInformation, allocation_size) == 0x30);
    assert!(core::mem::offset_of!(FileFullDirInformation, file_attributes) == 0x38);
    assert!(core::mem::offset_of!(FileFullDirInformation, file_name_length) == 0x3c);
    assert!(core::mem::offset_of!(FileFullDirInformation, ea_size) == 0x40);
    assert!(core::mem::offset_of!(FileFullDirInformation, file_name) == 0x44);
};

/// `_FILE_ID_FULL_DIR_INFORMATION` (ntifs.h; 0x58 bytes).
#[repr(C)]
pub struct FileIdFullDirInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: Field<u32>,
    pub file_name_length: Field<u32>,
    pub ea_size: Field<u32>,
    _pad_44: Reserved<0x4>,
    pub file_id: LargeInteger,
    pub file_name: [Field<u16>; 1],
    _pad_52: Reserved<0x6>,
}

unsafe impl NtStruct for FileIdFullDirInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileIdFullDirInformation>() == 0x58);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, creation_time) == 0x8);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, last_access_time) == 0x10);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, last_write_time) == 0x18);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, change_time) == 0x20);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, allocation_size) == 0x30);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, file_attributes) == 0x38);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, file_name_length) == 0x3c);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, ea_size) == 0x40);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, file_id) == 0x48);
    assert!(core::mem::offset_of!(FileIdFullDirInformation, file_name) == 0x50);
};

/// `_FILE_BOTH_DIR_INFORMATION` (ntifs.h; 0x60 bytes).
#[repr(C)]
pub struct FileBothDirInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: Field<u32>,
    pub file_name_length: Field<u32>,
    pub ea_size: Field<u32>,
    pub short_name_length: Field<i8>,
    _pad_45: Reserved<0x1>,
    pub short_name: [Field<u16>; 12],
    pub file_name: [Field<u16>; 1],
}

unsafe impl NtStruct for FileBothDirInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileBothDirInformation>() == 0x60);
    assert!(core::mem::offset_of!(FileBothDirInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileBothDirInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileBothDirInformation, creation_time) == 0x8);
    assert!(core::mem::offset_of!(FileBothDirInformation, last_access_time) == 0x10);
    assert!(core::mem::offset_of!(FileBothDirInformation, last_write_time) == 0x18);
    assert!(core::mem::offset_of!(FileBothDirInformation, change_time) == 0x20);
    assert!(core::mem::offset_of!(FileBothDirInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileBothDirInformation, allocation_size) == 0x30);
    assert!(core::mem::offset_of!(FileBothDirInformation, file_attributes) == 0x38);
    assert!(core::mem::offset_of!(FileBothDirInformation, file_name_length) == 0x3c);
    assert!(core::mem::offset_of!(FileBothDirInformation, ea_size) == 0x40);
    assert!(core::mem::offset_of!(FileBothDirInformation, short_name_length) == 0x44);
    assert!(core::mem::offset_of!(FileBothDirInformation, short_name) == 0x46);
    assert!(core::mem::offset_of!(FileBothDirInformation, file_name) == 0x5e);
};

/// `_FILE_ID_BOTH_DIR_INFORMATION` (ntifs.h; 0x70 bytes).
#[repr(C)]
pub struct FileIdBothDirInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub end_of_file: LargeInteger,
    pub allocation_size: LargeInteger,
    pub file_attributes: Field<u32>,
    pub file_name_length: Field<u32>,
    pub ea_size: Field<u32>,
    pub short_name_length: Field<i8>,
    _pad_45: Reserved<0x1>,
    pub short_name: [Field<u16>; 12],
    _pad_5e: Reserved<0x2>,
    pub file_id: LargeInteger,
    pub file_name: [Field<u16>; 1],
    _pad_6a: Reserved<0x6>,
}

unsafe impl NtStruct for FileIdBothDirInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileIdBothDirInformation>() == 0x70);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, creation_time) == 0x8);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, last_access_time) == 0x10);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, last_write_time) == 0x18);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, change_time) == 0x20);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, allocation_size) == 0x30);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, file_attributes) == 0x38);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, file_name_length) == 0x3c);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, ea_size) == 0x40);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, short_name_length) == 0x44);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, short_name) == 0x46);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, file_id) == 0x60);
    assert!(core::mem::offset_of!(FileIdBothDirInformation, file_name) == 0x68);
};

/// `_FILE_NAMES_INFORMATION` (ntifs.h; 0x10 bytes).
#[repr(C)]
pub struct FileNamesInformation {
    pub next_entry_offset: Field<u32>,
    pub file_index: Field<u32>,
    pub file_name_length: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_e: Reserved<0x2>,
}

unsafe impl NtStruct for FileNamesInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileNamesInformation>() == 0x10);
    assert!(core::mem::offset_of!(FileNamesInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(FileNamesInformation, file_index) == 0x4);
    assert!(core::mem::offset_of!(FileNamesInformation, file_name_length) == 0x8);
    assert!(core::mem::offset_of!(FileNamesInformation, file_name) == 0xc);
};

/// `_FILE_ACCESS_INFORMATION` (ntifs.h; 0x4 bytes).
#[repr(C)]
pub struct FileAccessInformation {
    pub access_flags: Field<u32>,
}

unsafe impl NtStruct for FileAccessInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileAccessInformation>() == 0x4);
    assert!(core::mem::offset_of!(FileAccessInformation, access_flags) == 0x0);
};

/// `_FILE_MODE_INFORMATION` (ntifs.h; 0x4 bytes).
#[repr(C)]
pub struct FileModeInformation {
    pub mode: Field<u32>,
}

unsafe impl NtStruct for FileModeInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileModeInformation>() == 0x4);
    assert!(core::mem::offset_of!(FileModeInformation, mode) == 0x0);
};

/// `_FILE_ALL_INFORMATION` (ntifs.h; 0x68 bytes).
#[repr(C)]
pub struct FileAllInformation {
    pub basic_information: FileBasicInformation,
    pub standard_information: FileStandardInformation,
    pub internal_information: FileInternalInformation,
    pub ea_information: FileEaInformation,
    pub access_information: FileAccessInformation,
    pub position_information: FilePositionInformation,
    pub mode_information: FileModeInformation,
    pub alignment_information: FileAlignmentInformation,
    pub name_information: FileNameInformation,
}

unsafe impl NtStruct for FileAllInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileAllInformation>() == 0x68);
    assert!(core::mem::offset_of!(FileAllInformation, basic_information) == 0x0);
    assert!(core::mem::offset_of!(FileAllInformation, standard_information) == 0x28);
    assert!(core::mem::offset_of!(FileAllInformation, internal_information) == 0x40);
    assert!(core::mem::offset_of!(FileAllInformation, ea_information) == 0x48);
    assert!(core::mem::offset_of!(FileAllInformation, access_information) == 0x4c);
    assert!(core::mem::offset_of!(FileAllInformation, position_information) == 0x50);
    assert!(core::mem::offset_of!(FileAllInformation, mode_information) == 0x58);
    assert!(core::mem::offset_of!(FileAllInformation, alignment_information) == 0x5c);
    assert!(core::mem::offset_of!(FileAllInformation, name_information) == 0x60);
};

/// `_FILE_ID_128` (ntifs.h; 0x10 bytes).
#[repr(C)]
pub struct FileId128 {
    pub identifier: [Field<u8>; 16],
}

unsafe impl NtStruct for FileId128 {}

const _: () = {
    assert!(core::mem::size_of::<FileId128>() == 0x10);
    assert!(core::mem::offset_of!(FileId128, identifier) == 0x0);
};

/// `_FILE_ID_INFORMATION` (ntifs.h; 0x18 bytes).
#[repr(C)]
pub struct FileIdInformation {
    pub volume_serial_number: Field<u64>,
    pub file_id: FileId128,
}

unsafe impl NtStruct for FileIdInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileIdInformation>() == 0x18);
    assert!(core::mem::offset_of!(FileIdInformation, volume_serial_number) == 0x0);
    assert!(core::mem::offset_of!(FileIdInformation, file_id) == 0x8);
};

/// `_FILE_RENAME_INFORMATION` (ntifs.h; 0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `FileRenameInformationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct FileRenameInformation {
    pub replace_if_exists: Field<u8>,
    _pad_1: Reserved<0x7>,
    /// -> `void`
    pub root_directory: Field<u64>,
    pub file_name_length: Field<u32>,
    pub file_name: [Field<u16>; 1],
    _pad_16: Reserved<0x2>,
}

/// Vista 1 de `_FILE_RENAME_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct FileRenameInformationView1 {
    _align: [u64; 0],
    pub flags: Field<u32>,
    _pad_4: Reserved<0x14>,
}

impl core::ops::Deref for FileRenameInformation {
    type Target = FileRenameInformationView1;
    #[inline(always)]
    fn deref(&self) -> &FileRenameInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<FileRenameInformationView1>() }
    }
}

unsafe impl NtStruct for FileRenameInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileRenameInformation>() == 0x18);
    assert!(core::mem::offset_of!(FileRenameInformation, replace_if_exists) == 0x0);
    assert!(core::mem::offset_of!(FileRenameInformation, root_directory) == 0x8);
    assert!(core::mem::offset_of!(FileRenameInformation, file_name_length) == 0x10);
    assert!(core::mem::offset_of!(FileRenameInformation, file_name) == 0x14);
    assert!(core::mem::size_of::<FileRenameInformationView1>() == 0x18);
    assert!(core::mem::align_of::<FileRenameInformationView1>() == core::mem::align_of::<FileRenameInformation>());
    assert!(core::mem::offset_of!(FileRenameInformationView1, flags) == 0x0);
};

/// `_MEMORY_BASIC_INFORMATION` (winnt.h; 0x30 bytes).
#[repr(C)]
pub struct MemoryBasicInformation {
    /// -> `void`
    pub base_address: Field<u64>,
    /// -> `void`
    pub allocation_base: Field<u64>,
    pub allocation_protect: Field<u32>,
    pub partition_id: Field<u16>,
    _pad_16: Reserved<0x2>,
    pub region_size: Field<u64>,
    pub state: Field<u32>,
    pub protect: Field<u32>,
    pub type_: Field<u32>,
    _pad_2c: Reserved<0x4>,
}

unsafe impl NtStruct for MemoryBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<MemoryBasicInformation>() == 0x30);
    assert!(core::mem::offset_of!(MemoryBasicInformation, base_address) == 0x0);
    assert!(core::mem::offset_of!(MemoryBasicInformation, allocation_base) == 0x8);
    assert!(core::mem::offset_of!(MemoryBasicInformation, allocation_protect) == 0x10);
    assert!(core::mem::offset_of!(MemoryBasicInformation, partition_id) == 0x14);
    assert!(core::mem::offset_of!(MemoryBasicInformation, region_size) == 0x18);
    assert!(core::mem::offset_of!(MemoryBasicInformation, state) == 0x20);
    assert!(core::mem::offset_of!(MemoryBasicInformation, protect) == 0x24);
    assert!(core::mem::offset_of!(MemoryBasicInformation, type_) == 0x28);
};

/// `_ACE_HEADER` (winnt.h; 0x4 bytes).
#[repr(C)]
pub struct AceHeader {
    pub ace_type: Field<u8>,
    pub ace_flags: Field<u8>,
    pub ace_size: Field<u16>,
}

unsafe impl NtStruct for AceHeader {}

const _: () = {
    assert!(core::mem::size_of::<AceHeader>() == 0x4);
    assert!(core::mem::offset_of!(AceHeader, ace_type) == 0x0);
    assert!(core::mem::offset_of!(AceHeader, ace_flags) == 0x1);
    assert!(core::mem::offset_of!(AceHeader, ace_size) == 0x2);
};

/// `_ACCESS_ALLOWED_ACE` (winnt.h; 0xc bytes).
#[repr(C)]
pub struct AccessAllowedAce {
    pub header: AceHeader,
    pub mask: Field<u32>,
    pub sid_start: Field<u32>,
}

unsafe impl NtStruct for AccessAllowedAce {}

const _: () = {
    assert!(core::mem::size_of::<AccessAllowedAce>() == 0xc);
    assert!(core::mem::offset_of!(AccessAllowedAce, header) == 0x0);
    assert!(core::mem::offset_of!(AccessAllowedAce, mask) == 0x4);
    assert!(core::mem::offset_of!(AccessAllowedAce, sid_start) == 0x8);
};

/// `_TOKEN_STATISTICS` (winnt.h; 0x38 bytes).
#[repr(C)]
pub struct TokenStatistics {
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub expiration_time: LargeInteger,
    pub token_type: Field<i32>,
    pub impersonation_level: Field<i32>,
    pub dynamic_charged: Field<u32>,
    pub dynamic_available: Field<u32>,
    pub group_count: Field<u32>,
    pub privilege_count: Field<u32>,
    pub modified_id: Luid,
}

unsafe impl NtStruct for TokenStatistics {}

const _: () = {
    assert!(core::mem::size_of::<TokenStatistics>() == 0x38);
    assert!(core::mem::offset_of!(TokenStatistics, token_id) == 0x0);
    assert!(core::mem::offset_of!(TokenStatistics, authentication_id) == 0x8);
    assert!(core::mem::offset_of!(TokenStatistics, expiration_time) == 0x10);
    assert!(core::mem::offset_of!(TokenStatistics, token_type) == 0x18);
    assert!(core::mem::offset_of!(TokenStatistics, impersonation_level) == 0x1c);
    assert!(core::mem::offset_of!(TokenStatistics, dynamic_charged) == 0x20);
    assert!(core::mem::offset_of!(TokenStatistics, dynamic_available) == 0x24);
    assert!(core::mem::offset_of!(TokenStatistics, group_count) == 0x28);
    assert!(core::mem::offset_of!(TokenStatistics, privilege_count) == 0x2c);
    assert!(core::mem::offset_of!(TokenStatistics, modified_id) == 0x30);
};

/// `_TOKEN_USER` (winnt.h; 0x10 bytes).
#[repr(C)]
pub struct TokenUser {
    pub user: SidAndAttributes,
}

unsafe impl NtStruct for TokenUser {}

const _: () = {
    assert!(core::mem::size_of::<TokenUser>() == 0x10);
    assert!(core::mem::offset_of!(TokenUser, user) == 0x0);
};

/// `_TOKEN_GROUPS` (winnt.h; 0x18 bytes).
#[repr(C)]
pub struct TokenGroups {
    pub group_count: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub groups: [SidAndAttributes; 1],
}

unsafe impl NtStruct for TokenGroups {}

const _: () = {
    assert!(core::mem::size_of::<TokenGroups>() == 0x18);
    assert!(core::mem::offset_of!(TokenGroups, group_count) == 0x0);
    assert!(core::mem::offset_of!(TokenGroups, groups) == 0x8);
};

/// `_IMAGE_EXPORT_DIRECTORY` (winnt.h; 0x28 bytes).
#[repr(C)]
pub struct ImageExportDirectory {
    pub characteristics: Field<u32>,
    pub time_date_stamp: Field<u32>,
    pub major_version: Field<u16>,
    pub minor_version: Field<u16>,
    pub name: Field<u32>,
    pub base: Field<u32>,
    pub number_of_functions: Field<u32>,
    pub number_of_names: Field<u32>,
    pub address_of_functions: Field<u32>,
    pub address_of_names: Field<u32>,
    pub address_of_name_ordinals: Field<u32>,
}

unsafe impl NtStruct for ImageExportDirectory {}

const _: () = {
    assert!(core::mem::size_of::<ImageExportDirectory>() == 0x28);
    assert!(core::mem::offset_of!(ImageExportDirectory, characteristics) == 0x0);
    assert!(core::mem::offset_of!(ImageExportDirectory, time_date_stamp) == 0x4);
    assert!(core::mem::offset_of!(ImageExportDirectory, major_version) == 0x8);
    assert!(core::mem::offset_of!(ImageExportDirectory, minor_version) == 0xa);
    assert!(core::mem::offset_of!(ImageExportDirectory, name) == 0xc);
    assert!(core::mem::offset_of!(ImageExportDirectory, base) == 0x10);
    assert!(core::mem::offset_of!(ImageExportDirectory, number_of_functions) == 0x14);
    assert!(core::mem::offset_of!(ImageExportDirectory, number_of_names) == 0x18);
    assert!(core::mem::offset_of!(ImageExportDirectory, address_of_functions) == 0x1c);
    assert!(core::mem::offset_of!(ImageExportDirectory, address_of_names) == 0x20);
    assert!(core::mem::offset_of!(ImageExportDirectory, address_of_name_ordinals) == 0x24);
};

/// `_IMAGE_IMPORT_DESCRIPTOR` (winnt.h; 0x14 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ImageImportDescriptorView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ImageImportDescriptor {
    pub characteristics: Field<u32>,
    pub time_date_stamp: Field<u32>,
    pub forwarder_chain: Field<u32>,
    pub name: Field<u32>,
    pub first_thunk: Field<u32>,
}

/// Vista 1 de `_IMAGE_IMPORT_DESCRIPTOR` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageImportDescriptorView1 {
    pub original_first_thunk: Field<u32>,
    _pad_4: Reserved<0x10>,
}

impl core::ops::Deref for ImageImportDescriptor {
    type Target = ImageImportDescriptorView1;
    #[inline(always)]
    fn deref(&self) -> &ImageImportDescriptorView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageImportDescriptorView1>() }
    }
}

unsafe impl NtStruct for ImageImportDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<ImageImportDescriptor>() == 0x14);
    assert!(core::mem::offset_of!(ImageImportDescriptor, characteristics) == 0x0);
    assert!(core::mem::offset_of!(ImageImportDescriptor, time_date_stamp) == 0x4);
    assert!(core::mem::offset_of!(ImageImportDescriptor, forwarder_chain) == 0x8);
    assert!(core::mem::offset_of!(ImageImportDescriptor, name) == 0xc);
    assert!(core::mem::offset_of!(ImageImportDescriptor, first_thunk) == 0x10);
    assert!(core::mem::size_of::<ImageImportDescriptorView1>() == 0x14);
    assert!(core::mem::align_of::<ImageImportDescriptorView1>() == core::mem::align_of::<ImageImportDescriptor>());
    assert!(core::mem::offset_of!(ImageImportDescriptorView1, original_first_thunk) == 0x0);
};

/// `_IMAGE_THUNK_DATA64::u1` (winnt.h; 0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ImageThunkData64U1View1`..`ImageThunkData64U1View3`, alcançadas por `Deref`.
#[repr(C)]
pub struct ImageThunkData64U1 {
    pub forwarder_string: Field<u64>,
}

/// Vista 1 de `_IMAGE_THUNK_DATA64::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageThunkData64U1View1 {
    pub function: Field<u64>,
}

/// Vista 2 de `_IMAGE_THUNK_DATA64::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageThunkData64U1View2 {
    pub ordinal: Field<u64>,
}

/// Vista 3 de `_IMAGE_THUNK_DATA64::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageThunkData64U1View3 {
    pub address_of_data: Field<u64>,
}

impl core::ops::Deref for ImageThunkData64U1 {
    type Target = ImageThunkData64U1View1;
    #[inline(always)]
    fn deref(&self) -> &ImageThunkData64U1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageThunkData64U1View1>() }
    }
}

impl core::ops::Deref for ImageThunkData64U1View1 {
    type Target = ImageThunkData64U1View2;
    #[inline(always)]
    fn deref(&self) -> &ImageThunkData64U1View2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageThunkData64U1View2>() }
    }
}

impl core::ops::Deref for ImageThunkData64U1View2 {
    type Target = ImageThunkData64U1View3;
    #[inline(always)]
    fn deref(&self) -> &ImageThunkData64U1View3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageThunkData64U1View3>() }
    }
}

unsafe impl NtStruct for ImageThunkData64U1 {}

const _: () = {
    assert!(core::mem::size_of::<ImageThunkData64U1>() == 0x8);
    assert!(core::mem::offset_of!(ImageThunkData64U1, forwarder_string) == 0x0);
    assert!(core::mem::size_of::<ImageThunkData64U1View1>() == 0x8);
    assert!(core::mem::align_of::<ImageThunkData64U1View1>() == core::mem::align_of::<ImageThunkData64U1>());
    assert!(core::mem::offset_of!(ImageThunkData64U1View1, function) == 0x0);
    assert!(core::mem::size_of::<ImageThunkData64U1View2>() == 0x8);
    assert!(core::mem::align_of::<ImageThunkData64U1View2>() == core::mem::align_of::<ImageThunkData64U1>());
    assert!(core::mem::offset_of!(ImageThunkData64U1View2, ordinal) == 0x0);
    assert!(core::mem::size_of::<ImageThunkData64U1View3>() == 0x8);
    assert!(core::mem::align_of::<ImageThunkData64U1View3>() == core::mem::align_of::<ImageThunkData64U1>());
    assert!(core::mem::offset_of!(ImageThunkData64U1View3, address_of_data) == 0x0);
};

/// `_IMAGE_THUNK_DATA64` (winnt.h; 0x8 bytes).
#[repr(C)]
pub struct ImageThunkData64 {
    pub u1: ImageThunkData64U1,
}

unsafe impl NtStruct for ImageThunkData64 {}

const _: () = {
    assert!(core::mem::size_of::<ImageThunkData64>() == 0x8);
    assert!(core::mem::offset_of!(ImageThunkData64, u1) == 0x0);
};

/// `_IMAGE_RESOURCE_DIRECTORY` (winnt.h; 0x10 bytes).
#[repr(C)]
pub struct ImageResourceDirectory {
    pub characteristics: Field<u32>,
    pub time_date_stamp: Field<u32>,
    pub major_version: Field<u16>,
    pub minor_version: Field<u16>,
    pub number_of_named_entries: Field<u16>,
    pub number_of_id_entries: Field<u16>,
}

unsafe impl NtStruct for ImageResourceDirectory {}

const _: () = {
    assert!(core::mem::size_of::<ImageResourceDirectory>() == 0x10);
    assert!(core::mem::offset_of!(ImageResourceDirectory, characteristics) == 0x0);
    assert!(core::mem::offset_of!(ImageResourceDirectory, time_date_stamp) == 0x4);
    assert!(core::mem::offset_of!(ImageResourceDirectory, major_version) == 0x8);
    assert!(core::mem::offset_of!(ImageResourceDirectory, minor_version) == 0xa);
    assert!(core::mem::offset_of!(ImageResourceDirectory, number_of_named_entries) == 0xc);
    assert!(core::mem::offset_of!(ImageResourceDirectory, number_of_id_entries) == 0xe);
};

/// `_IMAGE_RESOURCE_DIRECTORY_ENTRY` (winnt.h; 0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ImageResourceDirectoryEntryView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ImageResourceDirectoryEntry {
    pub name: Field<u32>,
    pub offset_to_data: Field<u32>,
}

/// Vista 1 de `_IMAGE_RESOURCE_DIRECTORY_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageResourceDirectoryEntryView1 {
    _align: [u32; 0],
    pub id: Field<u16>,
    _pad_2: Reserved<0x6>,
}

impl core::ops::Deref for ImageResourceDirectoryEntry {
    type Target = ImageResourceDirectoryEntryView1;
    #[inline(always)]
    fn deref(&self) -> &ImageResourceDirectoryEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageResourceDirectoryEntryView1>() }
    }
}

unsafe impl NtStruct for ImageResourceDirectoryEntry {}

impl ImageResourceDirectoryEntry {
    /// `NameOffset`: bits 0..=30 de `name`.
    pub const NAME_OFFSET_SHIFT: u32 = 0;
    pub const NAME_OFFSET_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn name_offset(&self) -> u32 {
        self.name.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_name_offset(&self, value: u32) {
        self.name.set_bits(0, 31, value as u64)
    }
    /// `NameIsString`: bits 31..=31 de `name`.
    pub const NAME_IS_STRING_SHIFT: u32 = 31;
    pub const NAME_IS_STRING_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn name_is_string(&self) -> u32 {
        self.name.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_name_is_string(&self, value: u32) {
        self.name.set_bits(31, 1, value as u64)
    }
    /// `OffsetToDirectory`: bits 0..=30 de `offset_to_data`.
    pub const OFFSET_TO_DIRECTORY_SHIFT: u32 = 0;
    pub const OFFSET_TO_DIRECTORY_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn offset_to_directory(&self) -> u32 {
        self.offset_to_data.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_offset_to_directory(&self, value: u32) {
        self.offset_to_data.set_bits(0, 31, value as u64)
    }
    /// `DataIsDirectory`: bits 31..=31 de `offset_to_data`.
    pub const DATA_IS_DIRECTORY_SHIFT: u32 = 31;
    pub const DATA_IS_DIRECTORY_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn data_is_directory(&self) -> u32 {
        self.offset_to_data.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_data_is_directory(&self, value: u32) {
        self.offset_to_data.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ImageResourceDirectoryEntry>() == 0x8);
    assert!(core::mem::offset_of!(ImageResourceDirectoryEntry, name) == 0x0);
    assert!(core::mem::offset_of!(ImageResourceDirectoryEntry, offset_to_data) == 0x4);
    assert!(core::mem::size_of::<ImageResourceDirectoryEntryView1>() == 0x8);
    assert!(core::mem::align_of::<ImageResourceDirectoryEntryView1>() == core::mem::align_of::<ImageResourceDirectoryEntry>());
    assert!(core::mem::offset_of!(ImageResourceDirectoryEntryView1, id) == 0x0);
};

/// `_IMAGE_RESOURCE_DATA_ENTRY` (winnt.h; 0x10 bytes).
#[repr(C)]
pub struct ImageResourceDataEntry {
    pub offset_to_data: Field<u32>,
    pub size: Field<u32>,
    pub code_page: Field<u32>,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for ImageResourceDataEntry {}

const _: () = {
    assert!(core::mem::size_of::<ImageResourceDataEntry>() == 0x10);
    assert!(core::mem::offset_of!(ImageResourceDataEntry, offset_to_data) == 0x0);
    assert!(core::mem::offset_of!(ImageResourceDataEntry, size) == 0x4);
    assert!(core::mem::offset_of!(ImageResourceDataEntry, code_page) == 0x8);
    assert!(core::mem::offset_of!(ImageResourceDataEntry, reserved) == 0xc);
};

/// `_DISPATCHER_CONTEXT` (winnt.h (x64); 0x50 bytes).
#[repr(C)]
pub struct DispatcherContext {
    pub control_pc: Field<u64>,
    pub image_base: Field<u64>,
    /// -> `_IMAGE_RUNTIME_FUNCTION_ENTRY`
    pub function_entry: Field<u64>,
    pub establisher_frame: Field<u64>,
    pub target_ip: Field<u64>,
    /// -> `_CONTEXT`
    pub context_record: Field<u64>,
    /// -> `void`
    pub language_handler: Field<u64>,
    /// -> `void`
    pub handler_data: Field<u64>,
    /// -> `void`
    pub history_table: Field<u64>,
    pub scope_index: Field<u32>,
    pub fill0: Field<u32>,
}

unsafe impl NtStruct for DispatcherContext {}

const _: () = {
    assert!(core::mem::size_of::<DispatcherContext>() == 0x50);
    assert!(core::mem::offset_of!(DispatcherContext, control_pc) == 0x0);
    assert!(core::mem::offset_of!(DispatcherContext, image_base) == 0x8);
    assert!(core::mem::offset_of!(DispatcherContext, function_entry) == 0x10);
    assert!(core::mem::offset_of!(DispatcherContext, establisher_frame) == 0x18);
    assert!(core::mem::offset_of!(DispatcherContext, target_ip) == 0x20);
    assert!(core::mem::offset_of!(DispatcherContext, context_record) == 0x28);
    assert!(core::mem::offset_of!(DispatcherContext, language_handler) == 0x30);
    assert!(core::mem::offset_of!(DispatcherContext, handler_data) == 0x38);
    assert!(core::mem::offset_of!(DispatcherContext, history_table) == 0x40);
    assert!(core::mem::offset_of!(DispatcherContext, scope_index) == 0x48);
    assert!(core::mem::offset_of!(DispatcherContext, fill0) == 0x4c);
};

/// `_KNONVOLATILE_CONTEXT_POINTERS` (winnt.h (x64); 0x100 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KnonvolatileContextPointersView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KnonvolatileContextPointers {
    /// -> `_M128A`
    pub floating_context: [Field<u64>; 16],
    /// -> `ULONG64`
    pub integer_context: [Field<u64>; 16],
}

/// Vista 1 de `_KNONVOLATILE_CONTEXT_POINTERS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KnonvolatileContextPointersView1 {
    /// -> `_M128A`
    pub xmm0: Field<u64>,
    /// -> `_M128A`
    pub xmm1: Field<u64>,
    /// -> `_M128A`
    pub xmm2: Field<u64>,
    /// -> `_M128A`
    pub xmm3: Field<u64>,
    /// -> `_M128A`
    pub xmm4: Field<u64>,
    /// -> `_M128A`
    pub xmm5: Field<u64>,
    /// -> `_M128A`
    pub xmm6: Field<u64>,
    /// -> `_M128A`
    pub xmm7: Field<u64>,
    /// -> `_M128A`
    pub xmm8: Field<u64>,
    /// -> `_M128A`
    pub xmm9: Field<u64>,
    /// -> `_M128A`
    pub xmm10: Field<u64>,
    /// -> `_M128A`
    pub xmm11: Field<u64>,
    /// -> `_M128A`
    pub xmm12: Field<u64>,
    /// -> `_M128A`
    pub xmm13: Field<u64>,
    /// -> `_M128A`
    pub xmm14: Field<u64>,
    /// -> `_M128A`
    pub xmm15: Field<u64>,
    /// -> `ULONG64`
    pub rax: Field<u64>,
    /// -> `ULONG64`
    pub rcx: Field<u64>,
    /// -> `ULONG64`
    pub rdx: Field<u64>,
    /// -> `ULONG64`
    pub rbx: Field<u64>,
    /// -> `ULONG64`
    pub rsp: Field<u64>,
    /// -> `ULONG64`
    pub rbp: Field<u64>,
    /// -> `ULONG64`
    pub rsi: Field<u64>,
    /// -> `ULONG64`
    pub rdi: Field<u64>,
    /// -> `ULONG64`
    pub r8: Field<u64>,
    /// -> `ULONG64`
    pub r9: Field<u64>,
    /// -> `ULONG64`
    pub r10: Field<u64>,
    /// -> `ULONG64`
    pub r11: Field<u64>,
    /// -> `ULONG64`
    pub r12: Field<u64>,
    /// -> `ULONG64`
    pub r13: Field<u64>,
    /// -> `ULONG64`
    pub r14: Field<u64>,
    /// -> `ULONG64`
    pub r15: Field<u64>,
}

impl core::ops::Deref for KnonvolatileContextPointers {
    type Target = KnonvolatileContextPointersView1;
    #[inline(always)]
    fn deref(&self) -> &KnonvolatileContextPointersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KnonvolatileContextPointersView1>() }
    }
}

unsafe impl NtStruct for KnonvolatileContextPointers {}

const _: () = {
    assert!(core::mem::size_of::<KnonvolatileContextPointers>() == 0x100);
    assert!(core::mem::offset_of!(KnonvolatileContextPointers, floating_context) == 0x0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointers, integer_context) == 0x80);
    assert!(core::mem::size_of::<KnonvolatileContextPointersView1>() == 0x100);
    assert!(core::mem::align_of::<KnonvolatileContextPointersView1>() == core::mem::align_of::<KnonvolatileContextPointers>());
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm0) == 0x0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm1) == 0x8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm2) == 0x10);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm3) == 0x18);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm4) == 0x20);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm5) == 0x28);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm6) == 0x30);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm7) == 0x38);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm8) == 0x40);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm9) == 0x48);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm10) == 0x50);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm11) == 0x58);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm12) == 0x60);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm13) == 0x68);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm14) == 0x70);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, xmm15) == 0x78);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rax) == 0x80);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rcx) == 0x88);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rdx) == 0x90);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rbx) == 0x98);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rsp) == 0xa0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rbp) == 0xa8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rsi) == 0xb0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, rdi) == 0xb8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r8) == 0xc0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r9) == 0xc8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r10) == 0xd0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r11) == 0xd8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r12) == 0xe0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r13) == 0xe8);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r14) == 0xf0);
    assert!(core::mem::offset_of!(KnonvolatileContextPointersView1, r15) == 0xf8);
};

/// `_SCOPE_TABLE_AMD64::ScopeRecord` (winnt.h (x64); 0x10 bytes).
#[repr(C)]
pub struct ScopeTableAmd64ScopeRecord {
    pub begin_address: Field<u32>,
    pub end_address: Field<u32>,
    pub handler_address: Field<u32>,
    pub jump_target: Field<u32>,
}

unsafe impl NtStruct for ScopeTableAmd64ScopeRecord {}

const _: () = {
    assert!(core::mem::size_of::<ScopeTableAmd64ScopeRecord>() == 0x10);
    assert!(core::mem::offset_of!(ScopeTableAmd64ScopeRecord, begin_address) == 0x0);
    assert!(core::mem::offset_of!(ScopeTableAmd64ScopeRecord, end_address) == 0x4);
    assert!(core::mem::offset_of!(ScopeTableAmd64ScopeRecord, handler_address) == 0x8);
    assert!(core::mem::offset_of!(ScopeTableAmd64ScopeRecord, jump_target) == 0xc);
};

/// `_SCOPE_TABLE_AMD64` (winnt.h (x64); 0x14 bytes).
#[repr(C)]
pub struct ScopeTableAmd64 {
    pub count: Field<u32>,
    pub scope_record: [ScopeTableAmd64ScopeRecord; 1],
}

unsafe impl NtStruct for ScopeTableAmd64 {}

const _: () = {
    assert!(core::mem::size_of::<ScopeTableAmd64>() == 0x14);
    assert!(core::mem::offset_of!(ScopeTableAmd64, count) == 0x0);
    assert!(core::mem::offset_of!(ScopeTableAmd64, scope_record) == 0x4);
};

/// `_PROCESS_BASIC_INFORMATION` (winternl.h / NtQueryInformationProcess; 0x30 bytes).
#[repr(C)]
pub struct ProcessBasicInformation {
    pub exit_status: Field<i32>,
    _pad_4: Reserved<0x4>,
    /// -> `_PEB`
    pub peb_base_address: Field<u64>,
    pub affinity_mask: Field<u64>,
    pub base_priority: Field<i32>,
    _pad_1c: Reserved<0x4>,
    pub unique_process_id: Field<u64>,
    pub inherited_from_unique_process_id: Field<u64>,
}

unsafe impl NtStruct for ProcessBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<ProcessBasicInformation>() == 0x30);
    assert!(core::mem::offset_of!(ProcessBasicInformation, exit_status) == 0x0);
    assert!(core::mem::offset_of!(ProcessBasicInformation, peb_base_address) == 0x8);
    assert!(core::mem::offset_of!(ProcessBasicInformation, affinity_mask) == 0x10);
    assert!(core::mem::offset_of!(ProcessBasicInformation, base_priority) == 0x18);
    assert!(core::mem::offset_of!(ProcessBasicInformation, unique_process_id) == 0x20);
    assert!(core::mem::offset_of!(ProcessBasicInformation, inherited_from_unique_process_id) == 0x28);
};

/// `_THREAD_BASIC_INFORMATION` (NtQueryInformationThread (ThreadBasicInformation); 0x30 bytes).
#[repr(C)]
pub struct ThreadBasicInformation {
    pub exit_status: Field<i32>,
    _pad_4: Reserved<0x4>,
    /// -> `_TEB`
    pub teb_base_address: Field<u64>,
    pub client_id: ClientId,
    pub affinity_mask: Field<u64>,
    pub priority: Field<i32>,
    pub base_priority: Field<i32>,
}

unsafe impl NtStruct for ThreadBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<ThreadBasicInformation>() == 0x30);
    assert!(core::mem::offset_of!(ThreadBasicInformation, exit_status) == 0x0);
    assert!(core::mem::offset_of!(ThreadBasicInformation, teb_base_address) == 0x8);
    assert!(core::mem::offset_of!(ThreadBasicInformation, client_id) == 0x10);
    assert!(core::mem::offset_of!(ThreadBasicInformation, affinity_mask) == 0x20);
    assert!(core::mem::offset_of!(ThreadBasicInformation, priority) == 0x28);
    assert!(core::mem::offset_of!(ThreadBasicInformation, base_priority) == 0x2c);
};

/// `_SYSTEM_BASIC_INFORMATION` (winternl.h / NtQuerySystemInformation; 0x40 bytes).
#[repr(C)]
pub struct SystemBasicInformation {
    pub reserved: Field<u32>,
    pub timer_resolution: Field<u32>,
    pub page_size: Field<u32>,
    pub number_of_physical_pages: Field<u32>,
    pub lowest_physical_page_number: Field<u32>,
    pub highest_physical_page_number: Field<u32>,
    pub allocation_granularity: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub minimum_user_mode_address: Field<u64>,
    pub maximum_user_mode_address: Field<u64>,
    pub active_processors_affinity_mask: Field<u64>,
    pub number_of_processors: Field<i8>,
    _pad_39: Reserved<0x7>,
}

unsafe impl NtStruct for SystemBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemBasicInformation>() == 0x40);
    assert!(core::mem::offset_of!(SystemBasicInformation, reserved) == 0x0);
    assert!(core::mem::offset_of!(SystemBasicInformation, timer_resolution) == 0x4);
    assert!(core::mem::offset_of!(SystemBasicInformation, page_size) == 0x8);
    assert!(core::mem::offset_of!(SystemBasicInformation, number_of_physical_pages) == 0xc);
    assert!(core::mem::offset_of!(SystemBasicInformation, lowest_physical_page_number) == 0x10);
    assert!(core::mem::offset_of!(SystemBasicInformation, highest_physical_page_number) == 0x14);
    assert!(core::mem::offset_of!(SystemBasicInformation, allocation_granularity) == 0x18);
    assert!(core::mem::offset_of!(SystemBasicInformation, minimum_user_mode_address) == 0x20);
    assert!(core::mem::offset_of!(SystemBasicInformation, maximum_user_mode_address) == 0x28);
    assert!(core::mem::offset_of!(SystemBasicInformation, active_processors_affinity_mask) == 0x30);
    assert!(core::mem::offset_of!(SystemBasicInformation, number_of_processors) == 0x38);
};

/// `_OBJECT_BASIC_INFORMATION` (winternl.h (PUBLIC_OBJECT_BASIC_INFORMATION) / NtQueryObject; 0x38 bytes).
#[repr(C)]
pub struct ObjectBasicInformation {
    pub attributes: Field<u32>,
    pub granted_access: Field<u32>,
    pub handle_count: Field<u32>,
    pub pointer_count: Field<u32>,
    pub paged_pool_charge: Field<u32>,
    pub non_paged_pool_charge: Field<u32>,
    pub reserved: [Field<u32>; 3],
    pub name_info_size: Field<u32>,
    pub type_info_size: Field<u32>,
    pub security_descriptor_size: Field<u32>,
    pub creation_time: LargeInteger,
}

unsafe impl NtStruct for ObjectBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectBasicInformation>() == 0x38);
    assert!(core::mem::offset_of!(ObjectBasicInformation, attributes) == 0x0);
    assert!(core::mem::offset_of!(ObjectBasicInformation, granted_access) == 0x4);
    assert!(core::mem::offset_of!(ObjectBasicInformation, handle_count) == 0x8);
    assert!(core::mem::offset_of!(ObjectBasicInformation, pointer_count) == 0xc);
    assert!(core::mem::offset_of!(ObjectBasicInformation, paged_pool_charge) == 0x10);
    assert!(core::mem::offset_of!(ObjectBasicInformation, non_paged_pool_charge) == 0x14);
    assert!(core::mem::offset_of!(ObjectBasicInformation, reserved) == 0x18);
    assert!(core::mem::offset_of!(ObjectBasicInformation, name_info_size) == 0x24);
    assert!(core::mem::offset_of!(ObjectBasicInformation, type_info_size) == 0x28);
    assert!(core::mem::offset_of!(ObjectBasicInformation, security_descriptor_size) == 0x2c);
    assert!(core::mem::offset_of!(ObjectBasicInformation, creation_time) == 0x30);
};

/// `_OBJECT_TYPE_INFORMATION` (winternl.h (PUBLIC_OBJECT_TYPE_INFORMATION) / NtQueryObject; 0x68 bytes).
#[repr(C)]
pub struct ObjectTypeInformation {
    pub type_name: UnicodeString,
    pub total_number_of_objects: Field<u32>,
    pub total_number_of_handles: Field<u32>,
    pub total_paged_pool_usage: Field<u32>,
    pub total_non_paged_pool_usage: Field<u32>,
    pub total_name_pool_usage: Field<u32>,
    pub total_handle_table_usage: Field<u32>,
    pub high_water_number_of_objects: Field<u32>,
    pub high_water_number_of_handles: Field<u32>,
    pub high_water_paged_pool_usage: Field<u32>,
    pub high_water_non_paged_pool_usage: Field<u32>,
    pub high_water_name_pool_usage: Field<u32>,
    pub high_water_handle_table_usage: Field<u32>,
    pub invalid_attributes: Field<u32>,
    pub generic_mapping: GenericMapping,
    pub valid_access_mask: Field<u32>,
    pub security_required: Field<u8>,
    pub maintain_handle_count: Field<u8>,
    pub type_index: Field<u8>,
    pub reserved_byte: Field<u8>,
    pub pool_type: Field<u32>,
    pub default_paged_pool_charge: Field<u32>,
    pub default_non_paged_pool_charge: Field<u32>,
}

unsafe impl NtStruct for ObjectTypeInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectTypeInformation>() == 0x68);
    assert!(core::mem::offset_of!(ObjectTypeInformation, type_name) == 0x0);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_number_of_objects) == 0x10);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_number_of_handles) == 0x14);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_paged_pool_usage) == 0x18);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_non_paged_pool_usage) == 0x1c);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_name_pool_usage) == 0x20);
    assert!(core::mem::offset_of!(ObjectTypeInformation, total_handle_table_usage) == 0x24);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_number_of_objects) == 0x28);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_number_of_handles) == 0x2c);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_paged_pool_usage) == 0x30);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_non_paged_pool_usage) == 0x34);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_name_pool_usage) == 0x38);
    assert!(core::mem::offset_of!(ObjectTypeInformation, high_water_handle_table_usage) == 0x3c);
    assert!(core::mem::offset_of!(ObjectTypeInformation, invalid_attributes) == 0x40);
    assert!(core::mem::offset_of!(ObjectTypeInformation, generic_mapping) == 0x44);
    assert!(core::mem::offset_of!(ObjectTypeInformation, valid_access_mask) == 0x54);
    assert!(core::mem::offset_of!(ObjectTypeInformation, security_required) == 0x58);
    assert!(core::mem::offset_of!(ObjectTypeInformation, maintain_handle_count) == 0x59);
    assert!(core::mem::offset_of!(ObjectTypeInformation, type_index) == 0x5a);
    assert!(core::mem::offset_of!(ObjectTypeInformation, reserved_byte) == 0x5b);
    assert!(core::mem::offset_of!(ObjectTypeInformation, pool_type) == 0x5c);
    assert!(core::mem::offset_of!(ObjectTypeInformation, default_paged_pool_charge) == 0x60);
    assert!(core::mem::offset_of!(ObjectTypeInformation, default_non_paged_pool_charge) == 0x64);
};

/// `_OBJECT_HANDLE_FLAG_INFORMATION` (NtQueryObject (ObjectHandleFlagInformation); 0x2 bytes).
#[repr(C)]
pub struct ObjectHandleFlagInformation {
    pub inherit: Field<u8>,
    pub protect_from_close: Field<u8>,
}

unsafe impl NtStruct for ObjectHandleFlagInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectHandleFlagInformation>() == 0x2);
    assert!(core::mem::offset_of!(ObjectHandleFlagInformation, inherit) == 0x0);
    assert!(core::mem::offset_of!(ObjectHandleFlagInformation, protect_from_close) == 0x1);
};

/// `_EVENT_BASIC_INFORMATION` (NtQueryEvent; 0x8 bytes).
#[repr(C)]
pub struct EventBasicInformation {
    pub event_type: Field<i32>,
    pub event_state: Field<i32>,
}

unsafe impl NtStruct for EventBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<EventBasicInformation>() == 0x8);
    assert!(core::mem::offset_of!(EventBasicInformation, event_type) == 0x0);
    assert!(core::mem::offset_of!(EventBasicInformation, event_state) == 0x4);
};

/// `_MUTANT_BASIC_INFORMATION` (NtQueryMutant; 0x8 bytes).
#[repr(C)]
pub struct MutantBasicInformation {
    pub current_count: Field<i32>,
    pub owned_by_caller: Field<u8>,
    pub abandoned_state: Field<u8>,
    _pad_6: Reserved<0x2>,
}

unsafe impl NtStruct for MutantBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<MutantBasicInformation>() == 0x8);
    assert!(core::mem::offset_of!(MutantBasicInformation, current_count) == 0x0);
    assert!(core::mem::offset_of!(MutantBasicInformation, owned_by_caller) == 0x4);
    assert!(core::mem::offset_of!(MutantBasicInformation, abandoned_state) == 0x5);
};

/// `_SEMAPHORE_BASIC_INFORMATION` (NtQuerySemaphore; 0x8 bytes).
#[repr(C)]
pub struct SemaphoreBasicInformation {
    pub current_count: Field<i32>,
    pub maximum_count: Field<i32>,
}

unsafe impl NtStruct for SemaphoreBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<SemaphoreBasicInformation>() == 0x8);
    assert!(core::mem::offset_of!(SemaphoreBasicInformation, current_count) == 0x0);
    assert!(core::mem::offset_of!(SemaphoreBasicInformation, maximum_count) == 0x4);
};

/// `_TIMER_BASIC_INFORMATION` (NtQueryTimer; 0x10 bytes).
#[repr(C)]
pub struct TimerBasicInformation {
    pub remaining_time: LargeInteger,
    pub timer_state: Field<u8>,
    _pad_9: Reserved<0x7>,
}

unsafe impl NtStruct for TimerBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<TimerBasicInformation>() == 0x10);
    assert!(core::mem::offset_of!(TimerBasicInformation, remaining_time) == 0x0);
    assert!(core::mem::offset_of!(TimerBasicInformation, timer_state) == 0x8);
};

/// `_SECTION_BASIC_INFORMATION` (NtQuerySection; 0x18 bytes).
#[repr(C)]
pub struct SectionBasicInformation {
    /// -> `void`
    pub base_address: Field<u64>,
    pub allocation_attributes: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub maximum_size: LargeInteger,
}

unsafe impl NtStruct for SectionBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<SectionBasicInformation>() == 0x18);
    assert!(core::mem::offset_of!(SectionBasicInformation, base_address) == 0x0);
    assert!(core::mem::offset_of!(SectionBasicInformation, allocation_attributes) == 0x8);
    assert!(core::mem::offset_of!(SectionBasicInformation, maximum_size) == 0x10);
};

/// `_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION` (NtSetInformationProcess (ProcessInstrumentationCallback); 0x10 bytes).
#[repr(C)]
pub struct ProcessInstrumentationCallbackInformation {
    pub version: Field<u32>,
    pub reserved: Field<u32>,
    /// -> `void`
    pub callback: Field<u64>,
}

unsafe impl NtStruct for ProcessInstrumentationCallbackInformation {}

const _: () = {
    assert!(core::mem::size_of::<ProcessInstrumentationCallbackInformation>() == 0x10);
    assert!(core::mem::offset_of!(ProcessInstrumentationCallbackInformation, version) == 0x0);
    assert!(core::mem::offset_of!(ProcessInstrumentationCallbackInformation, reserved) == 0x4);
    assert!(core::mem::offset_of!(ProcessInstrumentationCallbackInformation, callback) == 0x8);
};

/// `_MEMORY_REGION_INFORMATION` (NtQueryVirtualMemory (MemoryRegionInformation); 0x30 bytes).
#[repr(C)]
pub struct MemoryRegionInformation {
    /// -> `void`
    pub allocation_base: Field<u64>,
    pub allocation_protect: Field<u32>,
    pub region_type: Field<u32>,
    pub region_size: Field<u64>,
    pub commit_size: Field<u64>,
    pub partition_id: Field<u64>,
    pub node_preference: Field<u64>,
}

unsafe impl NtStruct for MemoryRegionInformation {}

const _: () = {
    assert!(core::mem::size_of::<MemoryRegionInformation>() == 0x30);
    assert!(core::mem::offset_of!(MemoryRegionInformation, allocation_base) == 0x0);
    assert!(core::mem::offset_of!(MemoryRegionInformation, allocation_protect) == 0x8);
    assert!(core::mem::offset_of!(MemoryRegionInformation, region_type) == 0xc);
    assert!(core::mem::offset_of!(MemoryRegionInformation, region_size) == 0x10);
    assert!(core::mem::offset_of!(MemoryRegionInformation, commit_size) == 0x18);
    assert!(core::mem::offset_of!(MemoryRegionInformation, partition_id) == 0x20);
    assert!(core::mem::offset_of!(MemoryRegionInformation, node_preference) == 0x28);
};

/// `_PS_ATTRIBUTE` (NtCreateUserProcess (lista de atributos); 0x20 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PsAttributeView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PsAttribute {
    pub attribute: Field<u64>,
    pub size: Field<u64>,
    pub value: Field<u64>,
    /// -> `SIZE_T`
    pub return_length: Field<u64>,
}

/// Vista 1 de `_PS_ATTRIBUTE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PsAttributeView1 {
    _pad_0: Reserved<0x10>,
    /// -> `void`
    pub value_ptr: Field<u64>,
    _pad_18: Reserved<0x8>,
}

impl core::ops::Deref for PsAttribute {
    type Target = PsAttributeView1;
    #[inline(always)]
    fn deref(&self) -> &PsAttributeView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PsAttributeView1>() }
    }
}

unsafe impl NtStruct for PsAttribute {}

const _: () = {
    assert!(core::mem::size_of::<PsAttribute>() == 0x20);
    assert!(core::mem::offset_of!(PsAttribute, attribute) == 0x0);
    assert!(core::mem::offset_of!(PsAttribute, size) == 0x8);
    assert!(core::mem::offset_of!(PsAttribute, value) == 0x10);
    assert!(core::mem::offset_of!(PsAttribute, return_length) == 0x18);
    assert!(core::mem::size_of::<PsAttributeView1>() == 0x20);
    assert!(core::mem::align_of::<PsAttributeView1>() == core::mem::align_of::<PsAttribute>());
    assert!(core::mem::offset_of!(PsAttributeView1, value_ptr) == 0x10);
};

/// `_PS_ATTRIBUTE_LIST` (NtCreateUserProcess (lista de atributos); 0x28 bytes).
#[repr(C)]
pub struct PsAttributeList {
    pub total_length: Field<u64>,
    pub attributes: [PsAttribute; 1],
}

unsafe impl NtStruct for PsAttributeList {}

const _: () = {
    assert!(core::mem::size_of::<PsAttributeList>() == 0x28);
    assert!(core::mem::offset_of!(PsAttributeList, total_length) == 0x0);
    assert!(core::mem::offset_of!(PsAttributeList, attributes) == 0x8);
};

/// `_PORT_VIEW` (NtConnectPort/NtAcceptConnectPort (LPC); 0x30 bytes).
#[repr(C)]
pub struct PortView {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub section_handle: Field<u64>,
    pub section_offset: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub view_size: Field<u64>,
    /// -> `void`
    pub view_base: Field<u64>,
    /// -> `void`
    pub view_remote_base: Field<u64>,
}

unsafe impl NtStruct for PortView {}

const _: () = {
    assert!(core::mem::size_of::<PortView>() == 0x30);
    assert!(core::mem::offset_of!(PortView, length) == 0x0);
    assert!(core::mem::offset_of!(PortView, section_handle) == 0x8);
    assert!(core::mem::offset_of!(PortView, section_offset) == 0x10);
    assert!(core::mem::offset_of!(PortView, view_size) == 0x18);
    assert!(core::mem::offset_of!(PortView, view_base) == 0x20);
    assert!(core::mem::offset_of!(PortView, view_remote_base) == 0x28);
};

/// `_ALPC_CONTEXT_ATTR` (NtAlpc* (atributo de contexto); 0x20 bytes).
#[repr(C)]
pub struct AlpcContextAttr {
    /// -> `void`
    pub port_context: Field<u64>,
    /// -> `void`
    pub message_context: Field<u64>,
    pub sequence: Field<u32>,
    pub message_id: Field<u32>,
    pub callback_id: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for AlpcContextAttr {}

const _: () = {
    assert!(core::mem::size_of::<AlpcContextAttr>() == 0x20);
    assert!(core::mem::offset_of!(AlpcContextAttr, port_context) == 0x0);
    assert!(core::mem::offset_of!(AlpcContextAttr, message_context) == 0x8);
    assert!(core::mem::offset_of!(AlpcContextAttr, sequence) == 0x10);
    assert!(core::mem::offset_of!(AlpcContextAttr, message_id) == 0x14);
    assert!(core::mem::offset_of!(AlpcContextAttr, callback_id) == 0x18);
};

/// `_ALPC_SECURITY_ATTR` (NtAlpc* (atributo de segurança); 0x18 bytes).
#[repr(C)]
pub struct AlpcSecurityAttr {
    pub flags: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_SECURITY_QUALITY_OF_SERVICE`
    pub p_qos: Field<u64>,
    /// -> `void`
    pub context_handle: Field<u64>,
}

unsafe impl NtStruct for AlpcSecurityAttr {}

const _: () = {
    assert!(core::mem::size_of::<AlpcSecurityAttr>() == 0x18);
    assert!(core::mem::offset_of!(AlpcSecurityAttr, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcSecurityAttr, p_qos) == 0x8);
    assert!(core::mem::offset_of!(AlpcSecurityAttr, context_handle) == 0x10);
};

/// `_ALPC_DATA_VIEW_ATTR` (NtAlpc* (atributo de visão); 0x20 bytes).
#[repr(C)]
pub struct AlpcDataViewAttr {
    pub flags: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub section_handle: Field<u64>,
    /// -> `void`
    pub view_base: Field<u64>,
    pub view_size: Field<u64>,
}

unsafe impl NtStruct for AlpcDataViewAttr {}

const _: () = {
    assert!(core::mem::size_of::<AlpcDataViewAttr>() == 0x20);
    assert!(core::mem::offset_of!(AlpcDataViewAttr, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcDataViewAttr, section_handle) == 0x8);
    assert!(core::mem::offset_of!(AlpcDataViewAttr, view_base) == 0x10);
    assert!(core::mem::offset_of!(AlpcDataViewAttr, view_size) == 0x18);
};

/// `_ALPC_HANDLE_ATTR` (NtAlpc* (atributo de handle); 0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `AlpcHandleAttrView1`, alcançada por `Deref`.
#[repr(C)]
pub struct AlpcHandleAttr {
    pub flags: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub handle: Field<u64>,
    pub object_type: Field<u32>,
    pub desired_access: Field<u32>,
}

/// Vista 1 de `_ALPC_HANDLE_ATTR` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct AlpcHandleAttrView1 {
    _pad_0: Reserved<0x8>,
    /// -> `_ALPC_HANDLE_ATTR32`
    pub handle_attr_array: Field<u64>,
    pub handle_count: Field<u32>,
    pub granted_access: Field<u32>,
}

impl core::ops::Deref for AlpcHandleAttr {
    type Target = AlpcHandleAttrView1;
    #[inline(always)]
    fn deref(&self) -> &AlpcHandleAttrView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<AlpcHandleAttrView1>() }
    }
}

unsafe impl NtStruct for AlpcHandleAttr {}

const _: () = {
    assert!(core::mem::size_of::<AlpcHandleAttr>() == 0x18);
    assert!(core::mem::offset_of!(AlpcHandleAttr, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcHandleAttr, handle) == 0x8);
    assert!(core::mem::offset_of!(AlpcHandleAttr, object_type) == 0x10);
    assert!(core::mem::offset_of!(AlpcHandleAttr, desired_access) == 0x14);
    assert!(core::mem::size_of::<AlpcHandleAttrView1>() == 0x18);
    assert!(core::mem::align_of::<AlpcHandleAttrView1>() == core::mem::align_of::<AlpcHandleAttr>());
    assert!(core::mem::offset_of!(AlpcHandleAttrView1, handle_attr_array) == 0x8);
    assert!(core::mem::offset_of!(AlpcHandleAttrView1, handle_count) == 0x10);
    assert!(core::mem::offset_of!(AlpcHandleAttrView1, granted_access) == 0x14);
};

/// `_ALPC_HANDLE_ATTR32` (NtAlpc* (atributo de handle, vetor); 0x10 bytes).
#[repr(C)]
pub struct AlpcHandleAttr32 {
    pub flags: Field<u32>,
    pub handle: Field<u32>,
    pub object_type: Field<u32>,
    pub desired_access: Field<u32>,
}

unsafe impl NtStruct for AlpcHandleAttr32 {}

const _: () = {
    assert!(core::mem::size_of::<AlpcHandleAttr32>() == 0x10);
    assert!(core::mem::offset_of!(AlpcHandleAttr32, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcHandleAttr32, handle) == 0x4);
    assert!(core::mem::offset_of!(AlpcHandleAttr32, object_type) == 0x8);
    assert!(core::mem::offset_of!(AlpcHandleAttr32, desired_access) == 0xc);
};

/// `_ALPC_DIRECT_ATTR` (NtAlpc* (atributo direto); 0x8 bytes).
#[repr(C)]
pub struct AlpcDirectAttr {
    /// -> `void`
    pub event: Field<u64>,
}

unsafe impl NtStruct for AlpcDirectAttr {}

const _: () = {
    assert!(core::mem::size_of::<AlpcDirectAttr>() == 0x8);
    assert!(core::mem::offset_of!(AlpcDirectAttr, event) == 0x0);
};

/// `_ALPC_BASIC_INFORMATION` (NtAlpcQueryInformation (AlpcBasicInformation); 0x10 bytes).
#[repr(C)]
pub struct AlpcBasicInformation {
    pub flags: Field<u32>,
    pub sequence_no: Field<u32>,
    /// -> `void`
    pub port_context: Field<u64>,
}

unsafe impl NtStruct for AlpcBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<AlpcBasicInformation>() == 0x10);
    assert!(core::mem::offset_of!(AlpcBasicInformation, flags) == 0x0);
    assert!(core::mem::offset_of!(AlpcBasicInformation, sequence_no) == 0x4);
    assert!(core::mem::offset_of!(AlpcBasicInformation, port_context) == 0x8);
};

/// `_ALPC_PORT_ASSOCIATE_COMPLETION_PORT` (NtAlpcSetInformation (AlpcAssociateCompletionPortInformation); 0x10 bytes).
#[repr(C)]
pub struct AlpcPortAssociateCompletionPort {
    /// -> `void`
    pub completion_key: Field<u64>,
    /// -> `void`
    pub completion_port: Field<u64>,
}

unsafe impl NtStruct for AlpcPortAssociateCompletionPort {}

const _: () = {
    assert!(core::mem::size_of::<AlpcPortAssociateCompletionPort>() == 0x10);
    assert!(core::mem::offset_of!(AlpcPortAssociateCompletionPort, completion_key) == 0x0);
    assert!(core::mem::offset_of!(AlpcPortAssociateCompletionPort, completion_port) == 0x8);
};

/// `_ALPC_MESSAGE_HANDLE_INFORMATION` (NtAlpcQueryInformationMessage (AlpcMessageHandleInformation); 0x14 bytes).
#[repr(C)]
pub struct AlpcMessageHandleInformation {
    pub index: Field<u32>,
    pub flags: Field<u32>,
    pub handle: Field<u32>,
    pub object_type: Field<u32>,
    pub granted_access: Field<u32>,
}

unsafe impl NtStruct for AlpcMessageHandleInformation {}

const _: () = {
    assert!(core::mem::size_of::<AlpcMessageHandleInformation>() == 0x14);
    assert!(core::mem::offset_of!(AlpcMessageHandleInformation, index) == 0x0);
    assert!(core::mem::offset_of!(AlpcMessageHandleInformation, flags) == 0x4);
    assert!(core::mem::offset_of!(AlpcMessageHandleInformation, handle) == 0x8);
    assert!(core::mem::offset_of!(AlpcMessageHandleInformation, object_type) == 0xc);
    assert!(core::mem::offset_of!(AlpcMessageHandleInformation, granted_access) == 0x10);
};

/// `_PO_FX_COMPONENT_V1` (wdm.h; 0x20 bytes).
#[repr(C)]
pub struct PoFxComponentV1 {
    pub id: Guid,
    pub idle_state_count: Field<u32>,
    pub deepest_wakeable_idle_state: Field<u32>,
    /// -> `_PO_FX_COMPONENT_IDLE_STATE`
    pub idle_states: Field<u64>,
}

unsafe impl NtStruct for PoFxComponentV1 {}

const _: () = {
    assert!(core::mem::size_of::<PoFxComponentV1>() == 0x20);
    assert!(core::mem::offset_of!(PoFxComponentV1, id) == 0x0);
    assert!(core::mem::offset_of!(PoFxComponentV1, idle_state_count) == 0x10);
    assert!(core::mem::offset_of!(PoFxComponentV1, deepest_wakeable_idle_state) == 0x14);
    assert!(core::mem::offset_of!(PoFxComponentV1, idle_states) == 0x18);
};

/// `_PO_FX_DEVICE_V1` (wdm.h; 0x60 bytes).
#[repr(C)]
pub struct PoFxDeviceV1 {
    pub version: Field<u32>,
    pub component_count: Field<u32>,
    /// -> `void`
    pub component_active_condition_callback: Field<u64>,
    /// -> `void`
    pub component_idle_condition_callback: Field<u64>,
    /// -> `void`
    pub component_idle_state_callback: Field<u64>,
    /// -> `void`
    pub device_power_required_callback: Field<u64>,
    /// -> `void`
    pub device_power_not_required_callback: Field<u64>,
    /// -> `void`
    pub power_control_callback: Field<u64>,
    /// -> `void`
    pub device_context: Field<u64>,
    pub components: [PoFxComponentV1; 1],
}

unsafe impl NtStruct for PoFxDeviceV1 {}

const _: () = {
    assert!(core::mem::size_of::<PoFxDeviceV1>() == 0x60);
    assert!(core::mem::offset_of!(PoFxDeviceV1, version) == 0x0);
    assert!(core::mem::offset_of!(PoFxDeviceV1, component_count) == 0x4);
    assert!(core::mem::offset_of!(PoFxDeviceV1, component_active_condition_callback) == 0x8);
    assert!(core::mem::offset_of!(PoFxDeviceV1, component_idle_condition_callback) == 0x10);
    assert!(core::mem::offset_of!(PoFxDeviceV1, component_idle_state_callback) == 0x18);
    assert!(core::mem::offset_of!(PoFxDeviceV1, device_power_required_callback) == 0x20);
    assert!(core::mem::offset_of!(PoFxDeviceV1, device_power_not_required_callback) == 0x28);
    assert!(core::mem::offset_of!(PoFxDeviceV1, power_control_callback) == 0x30);
    assert!(core::mem::offset_of!(PoFxDeviceV1, device_context) == 0x38);
    assert!(core::mem::offset_of!(PoFxDeviceV1, components) == 0x40);
};

/// `_IO_ERROR_LOG_PACKET` (wdm.h; 0x30 bytes).
#[repr(C)]
pub struct IoErrorLogPacket {
    pub major_function_code: Field<u8>,
    pub retry_count: Field<u8>,
    pub dump_data_size: Field<u16>,
    pub number_of_strings: Field<u16>,
    pub string_offset: Field<u16>,
    pub event_category: Field<u16>,
    _pad_a: Reserved<0x2>,
    pub error_code: Field<i32>,
    pub unique_error_value: Field<u32>,
    pub final_status: Field<i32>,
    pub sequence_number: Field<u32>,
    pub io_control_code: Field<u32>,
    pub device_offset: LargeInteger,
    pub dump_data: [Field<u32>; 1],
    _pad_2c: Reserved<0x4>,
}

unsafe impl NtStruct for IoErrorLogPacket {}

const _: () = {
    assert!(core::mem::size_of::<IoErrorLogPacket>() == 0x30);
    assert!(core::mem::offset_of!(IoErrorLogPacket, major_function_code) == 0x0);
    assert!(core::mem::offset_of!(IoErrorLogPacket, retry_count) == 0x1);
    assert!(core::mem::offset_of!(IoErrorLogPacket, dump_data_size) == 0x2);
    assert!(core::mem::offset_of!(IoErrorLogPacket, number_of_strings) == 0x4);
    assert!(core::mem::offset_of!(IoErrorLogPacket, string_offset) == 0x6);
    assert!(core::mem::offset_of!(IoErrorLogPacket, event_category) == 0x8);
    assert!(core::mem::offset_of!(IoErrorLogPacket, error_code) == 0xc);
    assert!(core::mem::offset_of!(IoErrorLogPacket, unique_error_value) == 0x10);
    assert!(core::mem::offset_of!(IoErrorLogPacket, final_status) == 0x14);
    assert!(core::mem::offset_of!(IoErrorLogPacket, sequence_number) == 0x18);
    assert!(core::mem::offset_of!(IoErrorLogPacket, io_control_code) == 0x1c);
    assert!(core::mem::offset_of!(IoErrorLogPacket, device_offset) == 0x20);
    assert!(core::mem::offset_of!(IoErrorLogPacket, dump_data) == 0x28);
};

/// `_KDPC_WATCHDOG_INFORMATION` (wdm.h; 0x14 bytes).
#[repr(C)]
pub struct KdpcWatchdogInformation {
    pub dpc_time_limit: Field<u32>,
    pub dpc_time_count: Field<u32>,
    pub dpc_watchdog_limit: Field<u32>,
    pub dpc_watchdog_count: Field<u32>,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for KdpcWatchdogInformation {}

const _: () = {
    assert!(core::mem::size_of::<KdpcWatchdogInformation>() == 0x14);
    assert!(core::mem::offset_of!(KdpcWatchdogInformation, dpc_time_limit) == 0x0);
    assert!(core::mem::offset_of!(KdpcWatchdogInformation, dpc_time_count) == 0x4);
    assert!(core::mem::offset_of!(KdpcWatchdogInformation, dpc_watchdog_limit) == 0x8);
    assert!(core::mem::offset_of!(KdpcWatchdogInformation, dpc_watchdog_count) == 0xc);
    assert!(core::mem::offset_of!(KdpcWatchdogInformation, reserved) == 0x10);
};

/// `_T2_SET_PARAMETERS_V0` (wdm.h (T2_SET_PARAMETERS); 0x10 bytes).
#[repr(C)]
pub struct T2SetParameters {
    pub version: Field<u32>,
    pub reserved: Field<u32>,
    pub no_wake_tolerance: Field<i64>,
}

unsafe impl NtStruct for T2SetParameters {}

const _: () = {
    assert!(core::mem::size_of::<T2SetParameters>() == 0x10);
    assert!(core::mem::offset_of!(T2SetParameters, version) == 0x0);
    assert!(core::mem::offset_of!(T2SetParameters, reserved) == 0x4);
    assert!(core::mem::offset_of!(T2SetParameters, no_wake_tolerance) == 0x8);
};

/// `_KEYBOARD_INPUT_DATA` (ntddkbd.h; 0xc bytes).
#[repr(C)]
pub struct KeyboardInputData {
    pub unit_id: Field<u16>,
    pub make_code: Field<u16>,
    pub flags: Field<u16>,
    pub reserved: Field<u16>,
    pub extra_information: Field<u32>,
}

unsafe impl NtStruct for KeyboardInputData {}

const _: () = {
    assert!(core::mem::size_of::<KeyboardInputData>() == 0xc);
    assert!(core::mem::offset_of!(KeyboardInputData, unit_id) == 0x0);
    assert!(core::mem::offset_of!(KeyboardInputData, make_code) == 0x2);
    assert!(core::mem::offset_of!(KeyboardInputData, flags) == 0x4);
    assert!(core::mem::offset_of!(KeyboardInputData, reserved) == 0x6);
    assert!(core::mem::offset_of!(KeyboardInputData, extra_information) == 0x8);
};

/// `_MOUNTMGR_VOLUME_PATHS` (mountmgr.h; 0x8 bytes).
#[repr(C)]
pub struct MountmgrVolumePaths {
    pub multi_sz_length: Field<u32>,
    pub multi_sz: [Field<u16>; 1],
    _pad_6: Reserved<0x2>,
}

unsafe impl NtStruct for MountmgrVolumePaths {}

const _: () = {
    assert!(core::mem::size_of::<MountmgrVolumePaths>() == 0x8);
    assert!(core::mem::offset_of!(MountmgrVolumePaths, multi_sz_length) == 0x0);
    assert!(core::mem::offset_of!(MountmgrVolumePaths, multi_sz) == 0x4);
};

/// `NTFS_VOLUME_DATA_BUFFER` (winioctl.h; 0x60 bytes).
#[repr(C)]
pub struct NtfsVolumeDataBuffer {
    pub volume_serial_number: LargeInteger,
    pub number_sectors: LargeInteger,
    pub total_clusters: LargeInteger,
    pub free_clusters: LargeInteger,
    pub total_reserved: LargeInteger,
    pub bytes_per_sector: Field<u32>,
    pub bytes_per_cluster: Field<u32>,
    pub bytes_per_file_record_segment: Field<u32>,
    pub clusters_per_file_record_segment: Field<u32>,
    pub mft_valid_data_length: LargeInteger,
    pub mft_start_lcn: LargeInteger,
    pub mft2_start_lcn: LargeInteger,
    pub mft_zone_start: LargeInteger,
    pub mft_zone_end: LargeInteger,
}

unsafe impl NtStruct for NtfsVolumeDataBuffer {}

const _: () = {
    assert!(core::mem::size_of::<NtfsVolumeDataBuffer>() == 0x60);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, volume_serial_number) == 0x0);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, number_sectors) == 0x8);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, total_clusters) == 0x10);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, free_clusters) == 0x18);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, total_reserved) == 0x20);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, bytes_per_sector) == 0x28);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, bytes_per_cluster) == 0x2c);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, bytes_per_file_record_segment) == 0x30);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, clusters_per_file_record_segment) == 0x34);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, mft_valid_data_length) == 0x38);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, mft_start_lcn) == 0x40);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, mft2_start_lcn) == 0x48);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, mft_zone_start) == 0x50);
    assert!(core::mem::offset_of!(NtfsVolumeDataBuffer, mft_zone_end) == 0x58);
};

/// `_PROCESSOR_RELATIONSHIP` (winnt.h; 0x28 bytes).
#[repr(C)]
pub struct ProcessorRelationship {
    pub flags: Field<u8>,
    pub efficiency_class: Field<u8>,
    pub reserved: [Field<u8>; 20],
    pub group_count: Field<u16>,
    pub group_mask: [GroupAffinity; 1],
}

unsafe impl NtStruct for ProcessorRelationship {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorRelationship>() == 0x28);
    assert!(core::mem::offset_of!(ProcessorRelationship, flags) == 0x0);
    assert!(core::mem::offset_of!(ProcessorRelationship, efficiency_class) == 0x1);
    assert!(core::mem::offset_of!(ProcessorRelationship, reserved) == 0x2);
    assert!(core::mem::offset_of!(ProcessorRelationship, group_count) == 0x16);
    assert!(core::mem::offset_of!(ProcessorRelationship, group_mask) == 0x18);
};

/// `_NUMA_NODE_RELATIONSHIP` (winnt.h; 0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `NumaNodeRelationshipView1`, alcançada por `Deref`.
#[repr(C)]
pub struct NumaNodeRelationship {
    pub node_number: Field<u32>,
    pub reserved: [Field<u8>; 18],
    pub group_count: Field<u16>,
    pub group_mask: GroupAffinity,
}

/// Vista 1 de `_NUMA_NODE_RELATIONSHIP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct NumaNodeRelationshipView1 {
    _pad_0: Reserved<0x18>,
    pub group_masks: [GroupAffinity; 1],
}

impl core::ops::Deref for NumaNodeRelationship {
    type Target = NumaNodeRelationshipView1;
    #[inline(always)]
    fn deref(&self) -> &NumaNodeRelationshipView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<NumaNodeRelationshipView1>() }
    }
}

unsafe impl NtStruct for NumaNodeRelationship {}

const _: () = {
    assert!(core::mem::size_of::<NumaNodeRelationship>() == 0x28);
    assert!(core::mem::offset_of!(NumaNodeRelationship, node_number) == 0x0);
    assert!(core::mem::offset_of!(NumaNodeRelationship, reserved) == 0x4);
    assert!(core::mem::offset_of!(NumaNodeRelationship, group_count) == 0x16);
    assert!(core::mem::offset_of!(NumaNodeRelationship, group_mask) == 0x18);
    assert!(core::mem::size_of::<NumaNodeRelationshipView1>() == 0x28);
    assert!(core::mem::align_of::<NumaNodeRelationshipView1>() == core::mem::align_of::<NumaNodeRelationship>());
    assert!(core::mem::offset_of!(NumaNodeRelationshipView1, group_masks) == 0x18);
};

/// `_CACHE_RELATIONSHIP` (winnt.h; 0x30 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CacheRelationshipView1`, alcançada por `Deref`.
#[repr(C)]
pub struct CacheRelationship {
    pub level: Field<u8>,
    pub associativity: Field<u8>,
    pub line_size: Field<u16>,
    pub cache_size: Field<u32>,
    pub type_: Field<i32>,
    pub reserved: [Field<u8>; 18],
    pub group_count: Field<u16>,
    pub group_mask: GroupAffinity,
}

/// Vista 1 de `_CACHE_RELATIONSHIP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CacheRelationshipView1 {
    _pad_0: Reserved<0x20>,
    pub group_masks: [GroupAffinity; 1],
}

impl core::ops::Deref for CacheRelationship {
    type Target = CacheRelationshipView1;
    #[inline(always)]
    fn deref(&self) -> &CacheRelationshipView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CacheRelationshipView1>() }
    }
}

unsafe impl NtStruct for CacheRelationship {}

const _: () = {
    assert!(core::mem::size_of::<CacheRelationship>() == 0x30);
    assert!(core::mem::offset_of!(CacheRelationship, level) == 0x0);
    assert!(core::mem::offset_of!(CacheRelationship, associativity) == 0x1);
    assert!(core::mem::offset_of!(CacheRelationship, line_size) == 0x2);
    assert!(core::mem::offset_of!(CacheRelationship, cache_size) == 0x4);
    assert!(core::mem::offset_of!(CacheRelationship, type_) == 0x8);
    assert!(core::mem::offset_of!(CacheRelationship, reserved) == 0xc);
    assert!(core::mem::offset_of!(CacheRelationship, group_count) == 0x1e);
    assert!(core::mem::offset_of!(CacheRelationship, group_mask) == 0x20);
    assert!(core::mem::size_of::<CacheRelationshipView1>() == 0x30);
    assert!(core::mem::align_of::<CacheRelationshipView1>() == core::mem::align_of::<CacheRelationship>());
    assert!(core::mem::offset_of!(CacheRelationshipView1, group_masks) == 0x20);
};

/// `_PROCESSOR_GROUP_INFO` (winnt.h; 0x30 bytes).
#[repr(C)]
pub struct ProcessorGroupInfo {
    pub maximum_processor_count: Field<u8>,
    pub active_processor_count: Field<u8>,
    pub reserved: [Field<u8>; 38],
    pub active_processor_mask: Field<u64>,
}

unsafe impl NtStruct for ProcessorGroupInfo {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorGroupInfo>() == 0x30);
    assert!(core::mem::offset_of!(ProcessorGroupInfo, maximum_processor_count) == 0x0);
    assert!(core::mem::offset_of!(ProcessorGroupInfo, active_processor_count) == 0x1);
    assert!(core::mem::offset_of!(ProcessorGroupInfo, reserved) == 0x2);
    assert!(core::mem::offset_of!(ProcessorGroupInfo, active_processor_mask) == 0x28);
};

/// `_GROUP_RELATIONSHIP` (winnt.h; 0x48 bytes).
#[repr(C)]
pub struct GroupRelationship {
    pub maximum_group_count: Field<u16>,
    pub active_group_count: Field<u16>,
    pub reserved: [Field<u8>; 20],
    pub group_info: [ProcessorGroupInfo; 1],
}

unsafe impl NtStruct for GroupRelationship {}

const _: () = {
    assert!(core::mem::size_of::<GroupRelationship>() == 0x48);
    assert!(core::mem::offset_of!(GroupRelationship, maximum_group_count) == 0x0);
    assert!(core::mem::offset_of!(GroupRelationship, active_group_count) == 0x2);
    assert!(core::mem::offset_of!(GroupRelationship, reserved) == 0x4);
    assert!(core::mem::offset_of!(GroupRelationship, group_info) == 0x18);
};

/// `_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` (winnt.h; 0x50 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SystemLogicalProcessorInformationExView1`..`SystemLogicalProcessorInformationExView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct SystemLogicalProcessorInformationEx {
    pub relationship: Field<i32>,
    pub size: Field<u32>,
    pub processor: ProcessorRelationship,
    _pad_30: Reserved<0x20>,
}

/// Vista 1 de `_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SystemLogicalProcessorInformationExView1 {
    _pad_0: Reserved<0x8>,
    pub numa_node: NumaNodeRelationship,
    _pad_30: Reserved<0x20>,
}

/// Vista 2 de `_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SystemLogicalProcessorInformationExView2 {
    _pad_0: Reserved<0x8>,
    pub cache: CacheRelationship,
    _pad_38: Reserved<0x18>,
}

/// Vista 3 de `_SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SystemLogicalProcessorInformationExView3 {
    _pad_0: Reserved<0x8>,
    pub group: GroupRelationship,
}

impl core::ops::Deref for SystemLogicalProcessorInformationEx {
    type Target = SystemLogicalProcessorInformationExView1;
    #[inline(always)]
    fn deref(&self) -> &SystemLogicalProcessorInformationExView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SystemLogicalProcessorInformationExView1>() }
    }
}

impl core::ops::Deref for SystemLogicalProcessorInformationExView1 {
    type Target = SystemLogicalProcessorInformationExView2;
    #[inline(always)]
    fn deref(&self) -> &SystemLogicalProcessorInformationExView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SystemLogicalProcessorInformationExView2>() }
    }
}

impl core::ops::Deref for SystemLogicalProcessorInformationExView2 {
    type Target = SystemLogicalProcessorInformationExView3;
    #[inline(always)]
    fn deref(&self) -> &SystemLogicalProcessorInformationExView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SystemLogicalProcessorInformationExView3>() }
    }
}

unsafe impl NtStruct for SystemLogicalProcessorInformationEx {}

const _: () = {
    assert!(core::mem::size_of::<SystemLogicalProcessorInformationEx>() == 0x50);
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationEx, relationship) == 0x0);
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationEx, size) == 0x4);
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationEx, processor) == 0x8);
    assert!(core::mem::size_of::<SystemLogicalProcessorInformationExView1>() == 0x50);
    assert!(core::mem::align_of::<SystemLogicalProcessorInformationExView1>() == core::mem::align_of::<SystemLogicalProcessorInformationEx>());
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationExView1, numa_node) == 0x8);
    assert!(core::mem::size_of::<SystemLogicalProcessorInformationExView2>() == 0x50);
    assert!(core::mem::align_of::<SystemLogicalProcessorInformationExView2>() == core::mem::align_of::<SystemLogicalProcessorInformationEx>());
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationExView2, cache) == 0x8);
    assert!(core::mem::size_of::<SystemLogicalProcessorInformationExView3>() == 0x50);
    assert!(core::mem::align_of::<SystemLogicalProcessorInformationExView3>() == core::mem::align_of::<SystemLogicalProcessorInformationEx>());
    assert!(core::mem::offset_of!(SystemLogicalProcessorInformationExView3, group) == 0x8);
};

/// `BATTERY_REPORTING_SCALE` (winnt.h; 0x8 bytes).
#[repr(C)]
pub struct BatteryReportingScale {
    pub granularity: Field<u32>,
    pub capacity: Field<u32>,
}

unsafe impl NtStruct for BatteryReportingScale {}

const _: () = {
    assert!(core::mem::size_of::<BatteryReportingScale>() == 0x8);
    assert!(core::mem::offset_of!(BatteryReportingScale, granularity) == 0x0);
    assert!(core::mem::offset_of!(BatteryReportingScale, capacity) == 0x4);
};

/// `SYSTEM_POWER_CAPABILITIES` (winnt.h; 0x4c bytes).
#[repr(C)]
pub struct SystemPowerCapabilities {
    pub power_button_present: Field<u8>,
    pub sleep_button_present: Field<u8>,
    pub lid_present: Field<u8>,
    pub system_s1: Field<u8>,
    pub system_s2: Field<u8>,
    pub system_s3: Field<u8>,
    pub system_s4: Field<u8>,
    pub system_s5: Field<u8>,
    pub hiber_file_present: Field<u8>,
    pub full_wake: Field<u8>,
    pub video_dim_present: Field<u8>,
    pub apm_present: Field<u8>,
    pub ups_present: Field<u8>,
    pub thermal_control: Field<u8>,
    pub processor_throttle: Field<u8>,
    pub processor_min_throttle: Field<u8>,
    pub processor_max_throttle: Field<u8>,
    pub fast_system_s4: Field<u8>,
    pub hiberboot: Field<u8>,
    pub wake_alarm_present: Field<u8>,
    pub ao_ac: Field<u8>,
    pub disk_spin_down: Field<u8>,
    pub hiber_file_type: Field<u8>,
    pub ao_ac_connectivity_supported: Field<u8>,
    pub spare3: [Field<u8>; 6],
    pub system_batteries_present: Field<u8>,
    pub batteries_are_short_term: Field<u8>,
    pub battery_scale: [BatteryReportingScale; 3],
    pub ac_on_line_wake: Field<i32>,
    pub soft_lid_wake: Field<i32>,
    pub rtc_wake: Field<i32>,
    pub min_device_wake_state: Field<i32>,
    pub default_low_latency_wake: Field<i32>,
}

unsafe impl NtStruct for SystemPowerCapabilities {}

const _: () = {
    assert!(core::mem::size_of::<SystemPowerCapabilities>() == 0x4c);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, power_button_present) == 0x0);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, sleep_button_present) == 0x1);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, lid_present) == 0x2);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_s1) == 0x3);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_s2) == 0x4);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_s3) == 0x5);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_s4) == 0x6);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_s5) == 0x7);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, hiber_file_present) == 0x8);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, full_wake) == 0x9);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, video_dim_present) == 0xa);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, apm_present) == 0xb);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, ups_present) == 0xc);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, thermal_control) == 0xd);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, processor_throttle) == 0xe);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, processor_min_throttle) == 0xf);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, processor_max_throttle) == 0x10);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, fast_system_s4) == 0x11);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, hiberboot) == 0x12);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, wake_alarm_present) == 0x13);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, ao_ac) == 0x14);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, disk_spin_down) == 0x15);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, hiber_file_type) == 0x16);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, ao_ac_connectivity_supported) == 0x17);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, spare3) == 0x18);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, system_batteries_present) == 0x1e);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, batteries_are_short_term) == 0x1f);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, battery_scale) == 0x20);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, ac_on_line_wake) == 0x38);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, soft_lid_wake) == 0x3c);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, rtc_wake) == 0x40);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, min_device_wake_state) == 0x44);
    assert!(core::mem::offset_of!(SystemPowerCapabilities, default_low_latency_wake) == 0x48);
};

/// `_CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1` (winnt.h; 0x14 bytes).
#[repr(C)]
pub struct ClaimSecurityAttributeRelativeV1 {
    pub name: Field<u32>,
    pub value_type: Field<u16>,
    pub reserved: Field<u16>,
    pub flags: Field<u32>,
    pub value_count: Field<u32>,
    pub values: [Field<u32>; 1],
}

unsafe impl NtStruct for ClaimSecurityAttributeRelativeV1 {}

const _: () = {
    assert!(core::mem::size_of::<ClaimSecurityAttributeRelativeV1>() == 0x14);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, name) == 0x0);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, value_type) == 0x4);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, reserved) == 0x6);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, flags) == 0x8);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, value_count) == 0xc);
    assert!(core::mem::offset_of!(ClaimSecurityAttributeRelativeV1, values) == 0x10);
};

/// `_ACCESS_ALLOWED_OBJECT_ACE` (winnt.h; 0x30 bytes).
#[repr(C)]
pub struct AccessAllowedObjectAce {
    pub header: AceHeader,
    pub mask: Field<u32>,
    pub flags: Field<u32>,
    pub object_type: Guid,
    pub inherited_object_type: Guid,
    pub sid_start: Field<u32>,
}

unsafe impl NtStruct for AccessAllowedObjectAce {}

const _: () = {
    assert!(core::mem::size_of::<AccessAllowedObjectAce>() == 0x30);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, header) == 0x0);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, mask) == 0x4);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, flags) == 0x8);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, object_type) == 0xc);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, inherited_object_type) == 0x1c);
    assert!(core::mem::offset_of!(AccessAllowedObjectAce, sid_start) == 0x2c);
};

/// `_COMPOUND_ACCESS_ALLOWED_ACE` (winnt.h; 0x10 bytes).
#[repr(C)]
pub struct CompoundAccessAllowedAce {
    pub header: AceHeader,
    pub mask: Field<u32>,
    pub compound_ace_type: Field<u16>,
    pub reserved: Field<u16>,
    pub sid_start: Field<u32>,
}

unsafe impl NtStruct for CompoundAccessAllowedAce {}

const _: () = {
    assert!(core::mem::size_of::<CompoundAccessAllowedAce>() == 0x10);
    assert!(core::mem::offset_of!(CompoundAccessAllowedAce, header) == 0x0);
    assert!(core::mem::offset_of!(CompoundAccessAllowedAce, mask) == 0x4);
    assert!(core::mem::offset_of!(CompoundAccessAllowedAce, compound_ace_type) == 0x8);
    assert!(core::mem::offset_of!(CompoundAccessAllowedAce, reserved) == 0xa);
    assert!(core::mem::offset_of!(CompoundAccessAllowedAce, sid_start) == 0xc);
};

/// `_SYSTEM_ACCESS_FILTER_ACE` (winnt.h; 0xc bytes).
#[repr(C)]
pub struct SystemAccessFilterAce {
    pub header: AceHeader,
    pub mask: Field<u32>,
    pub sid_start: Field<u32>,
}

unsafe impl NtStruct for SystemAccessFilterAce {}

const _: () = {
    assert!(core::mem::size_of::<SystemAccessFilterAce>() == 0xc);
    assert!(core::mem::offset_of!(SystemAccessFilterAce, header) == 0x0);
    assert!(core::mem::offset_of!(SystemAccessFilterAce, mask) == 0x4);
    assert!(core::mem::offset_of!(SystemAccessFilterAce, sid_start) == 0x8);
};

/// `_MEM_ADDRESS_REQUIREMENTS` (winnt.h; 0x18 bytes).
#[repr(C)]
pub struct MemAddressRequirements {
    /// -> `void`
    pub lowest_starting_address: Field<u64>,
    /// -> `void`
    pub highest_ending_address: Field<u64>,
    pub alignment: Field<u64>,
}

unsafe impl NtStruct for MemAddressRequirements {}

const _: () = {
    assert!(core::mem::size_of::<MemAddressRequirements>() == 0x18);
    assert!(core::mem::offset_of!(MemAddressRequirements, lowest_starting_address) == 0x0);
    assert!(core::mem::offset_of!(MemAddressRequirements, highest_ending_address) == 0x8);
    assert!(core::mem::offset_of!(MemAddressRequirements, alignment) == 0x10);
};

/// `_MEM_EXTENDED_PARAMETER` (winnt.h; 0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MemExtendedParameterView1`..`MemExtendedParameterView4`, alcançadas por `Deref`.
#[repr(C)]
pub struct MemExtendedParameter {
    pub header: Field<u64>,
    pub u_long64: Field<u64>,
}

/// Vista 1 de `_MEM_EXTENDED_PARAMETER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MemExtendedParameterView1 {
    _pad_0: Reserved<0x8>,
    /// -> `void`
    pub pointer: Field<u64>,
}

/// Vista 2 de `_MEM_EXTENDED_PARAMETER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MemExtendedParameterView2 {
    _pad_0: Reserved<0x8>,
    pub size: Field<u64>,
}

/// Vista 3 de `_MEM_EXTENDED_PARAMETER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MemExtendedParameterView3 {
    _pad_0: Reserved<0x8>,
    /// -> `void`
    pub handle: Field<u64>,
}

/// Vista 4 de `_MEM_EXTENDED_PARAMETER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MemExtendedParameterView4 {
    _align: [u64; 0],
    _pad_0: Reserved<0x8>,
    pub u_long: Field<u32>,
    _pad_c: Reserved<0x4>,
}

impl core::ops::Deref for MemExtendedParameter {
    type Target = MemExtendedParameterView1;
    #[inline(always)]
    fn deref(&self) -> &MemExtendedParameterView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MemExtendedParameterView1>() }
    }
}

impl core::ops::Deref for MemExtendedParameterView1 {
    type Target = MemExtendedParameterView2;
    #[inline(always)]
    fn deref(&self) -> &MemExtendedParameterView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MemExtendedParameterView2>() }
    }
}

impl core::ops::Deref for MemExtendedParameterView2 {
    type Target = MemExtendedParameterView3;
    #[inline(always)]
    fn deref(&self) -> &MemExtendedParameterView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MemExtendedParameterView3>() }
    }
}

impl core::ops::Deref for MemExtendedParameterView3 {
    type Target = MemExtendedParameterView4;
    #[inline(always)]
    fn deref(&self) -> &MemExtendedParameterView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MemExtendedParameterView4>() }
    }
}

unsafe impl NtStruct for MemExtendedParameter {}

impl MemExtendedParameter {
    /// `Type`: bits 0..=7 de `header`.
    pub const TYPE_SHIFT: u32 = 0;
    pub const TYPE_MASK: u64 = 0xff;
    #[inline(always)]
    pub fn type_(&self) -> u64 {
        self.header.bits(0, 8) as u64
    }
    #[inline(always)]
    pub fn set_type(&self, value: u64) {
        self.header.set_bits(0, 8, value as u64)
    }
    /// `Reserved`: bits 8..=63 de `header`.
    pub const RESERVED_SHIFT: u32 = 8;
    pub const RESERVED_MASK: u64 = 0xffffffffffffff00;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.header.bits(8, 56) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.header.set_bits(8, 56, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MemExtendedParameter>() == 0x10);
    assert!(core::mem::offset_of!(MemExtendedParameter, header) == 0x0);
    assert!(core::mem::offset_of!(MemExtendedParameter, u_long64) == 0x8);
    assert!(core::mem::size_of::<MemExtendedParameterView1>() == 0x10);
    assert!(core::mem::align_of::<MemExtendedParameterView1>() == core::mem::align_of::<MemExtendedParameter>());
    assert!(core::mem::offset_of!(MemExtendedParameterView1, pointer) == 0x8);
    assert!(core::mem::size_of::<MemExtendedParameterView2>() == 0x10);
    assert!(core::mem::align_of::<MemExtendedParameterView2>() == core::mem::align_of::<MemExtendedParameter>());
    assert!(core::mem::offset_of!(MemExtendedParameterView2, size) == 0x8);
    assert!(core::mem::size_of::<MemExtendedParameterView3>() == 0x10);
    assert!(core::mem::align_of::<MemExtendedParameterView3>() == core::mem::align_of::<MemExtendedParameter>());
    assert!(core::mem::offset_of!(MemExtendedParameterView3, handle) == 0x8);
    assert!(core::mem::size_of::<MemExtendedParameterView4>() == 0x10);
    assert!(core::mem::align_of::<MemExtendedParameterView4>() == core::mem::align_of::<MemExtendedParameter>());
    assert!(core::mem::offset_of!(MemExtendedParameterView4, u_long) == 0x8);
};

/// `_IMAGE_RESOURCE_DIR_STRING_U` (winnt.h; 0x4 bytes).
#[repr(C)]
pub struct ImageResourceDirStringU {
    pub length: Field<u16>,
    pub name_string: [Field<u16>; 1],
}

unsafe impl NtStruct for ImageResourceDirStringU {}

const _: () = {
    assert!(core::mem::size_of::<ImageResourceDirStringU>() == 0x4);
    assert!(core::mem::offset_of!(ImageResourceDirStringU, length) == 0x0);
    assert!(core::mem::offset_of!(ImageResourceDirStringU, name_string) == 0x2);
};

/// `_IMAGE_IMPORT_BY_NAME` (winnt.h; 0x4 bytes).
#[repr(C)]
pub struct ImageImportByName {
    pub hint: Field<u16>,
    pub name: [Field<u8>; 1],
    _pad_3: Reserved<0x1>,
}

unsafe impl NtStruct for ImageImportByName {}

const _: () = {
    assert!(core::mem::size_of::<ImageImportByName>() == 0x4);
    assert!(core::mem::offset_of!(ImageImportByName, hint) == 0x0);
    assert!(core::mem::offset_of!(ImageImportByName, name) == 0x2);
};

/// `_MEMORY_WORKING_SET_EX_INFORMATION` (psapi.h (PSAPI_WORKING_SET_EX_INFORMATION); 0x10 bytes).
#[repr(C)]
pub struct MemoryWorkingSetExInformation {
    /// -> `void`
    pub virtual_address: Field<u64>,
    pub virtual_attributes: Field<u64>,
}

unsafe impl NtStruct for MemoryWorkingSetExInformation {}

const _: () = {
    assert!(core::mem::size_of::<MemoryWorkingSetExInformation>() == 0x10);
    assert!(core::mem::offset_of!(MemoryWorkingSetExInformation, virtual_address) == 0x0);
    assert!(core::mem::offset_of!(MemoryWorkingSetExInformation, virtual_attributes) == 0x8);
};

/// `_MEMORY_IMAGE_INFORMATION` (NtQueryVirtualMemory (MemoryImageInformation); 0x18 bytes).
#[repr(C)]
pub struct MemoryImageInformation {
    /// -> `void`
    pub image_base: Field<u64>,
    pub size_of_image: Field<u64>,
    pub image_flags: Field<u32>,
    _pad_14: Reserved<0x4>,
}

unsafe impl NtStruct for MemoryImageInformation {}

const _: () = {
    assert!(core::mem::size_of::<MemoryImageInformation>() == 0x18);
    assert!(core::mem::offset_of!(MemoryImageInformation, image_base) == 0x0);
    assert!(core::mem::offset_of!(MemoryImageInformation, size_of_image) == 0x8);
    assert!(core::mem::offset_of!(MemoryImageInformation, image_flags) == 0x10);
};

/// `_UNWIND_INFO` (x64 exception handling (UNWIND_INFO); 0x6 bytes).
#[repr(C)]
pub struct UnwindInfo {
    pub bitfield_0: Field<u8>,
    pub size_of_prolog: Field<u8>,
    pub count_of_codes: Field<u8>,
    pub bitfield_3: Field<u8>,
    pub unwind_code: [Field<u16>; 1],
}

unsafe impl NtStruct for UnwindInfo {}

impl UnwindInfo {
    /// `Version`: bits 0..=2 de `bitfield_0`.
    pub const VERSION_SHIFT: u32 = 0;
    pub const VERSION_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.bitfield_0.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_version(&self, value: u8) {
        self.bitfield_0.set_bits(0, 3, value as u64)
    }
    /// `Flags`: bits 3..=7 de `bitfield_0`.
    pub const FLAGS_SHIFT: u32 = 3;
    pub const FLAGS_MASK: u8 = 0xf8;
    #[inline(always)]
    pub fn flags(&self) -> u8 {
        self.bitfield_0.bits(3, 5) as u8
    }
    #[inline(always)]
    pub fn set_flags(&self, value: u8) {
        self.bitfield_0.set_bits(3, 5, value as u64)
    }
    /// `FrameRegister`: bits 0..=3 de `bitfield_3`.
    pub const FRAME_REGISTER_SHIFT: u32 = 0;
    pub const FRAME_REGISTER_MASK: u8 = 0xf;
    #[inline(always)]
    pub fn frame_register(&self) -> u8 {
        self.bitfield_3.bits(0, 4) as u8
    }
    #[inline(always)]
    pub fn set_frame_register(&self, value: u8) {
        self.bitfield_3.set_bits(0, 4, value as u64)
    }
    /// `FrameOffset`: bits 4..=7 de `bitfield_3`.
    pub const FRAME_OFFSET_SHIFT: u32 = 4;
    pub const FRAME_OFFSET_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn frame_offset(&self) -> u8 {
        self.bitfield_3.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_frame_offset(&self, value: u8) {
        self.bitfield_3.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<UnwindInfo>() == 0x6);
    assert!(core::mem::offset_of!(UnwindInfo, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(UnwindInfo, size_of_prolog) == 0x1);
    assert!(core::mem::offset_of!(UnwindInfo, count_of_codes) == 0x2);
    assert!(core::mem::offset_of!(UnwindInfo, bitfield_3) == 0x3);
    assert!(core::mem::offset_of!(UnwindInfo, unwind_code) == 0x4);
};

/// `_TOKEN_SECURITY_ATTRIBUTE_V1` (ntifs.h; 0x28 bytes).
#[repr(C)]
pub struct TokenSecurityAttributeV1 {
    pub name: UnicodeString,
    pub value_type: Field<u16>,
    pub reserved: Field<u16>,
    pub flags: Field<u32>,
    pub value_count: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `união pInt64/pUint64/pString/pFqbn/pOctetString`
    pub values: Field<u64>,
}

unsafe impl NtStruct for TokenSecurityAttributeV1 {}

const _: () = {
    assert!(core::mem::size_of::<TokenSecurityAttributeV1>() == 0x28);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, name) == 0x0);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, value_type) == 0x10);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, reserved) == 0x12);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, flags) == 0x14);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, value_count) == 0x18);
    assert!(core::mem::offset_of!(TokenSecurityAttributeV1, values) == 0x20);
};

/// `_TOKEN_SECURITY_ATTRIBUTES_INFORMATION` (ntifs.h; 0x10 bytes).
#[repr(C)]
pub struct TokenSecurityAttributesInformation {
    pub version: Field<u16>,
    pub reserved: Field<u16>,
    pub attribute_count: Field<u32>,
    /// -> `_TOKEN_SECURITY_ATTRIBUTE_V1`
    pub p_attribute_v1: Field<u64>,
}

unsafe impl NtStruct for TokenSecurityAttributesInformation {}

const _: () = {
    assert!(core::mem::size_of::<TokenSecurityAttributesInformation>() == 0x10);
    assert!(core::mem::offset_of!(TokenSecurityAttributesInformation, version) == 0x0);
    assert!(core::mem::offset_of!(TokenSecurityAttributesInformation, reserved) == 0x2);
    assert!(core::mem::offset_of!(TokenSecurityAttributesInformation, attribute_count) == 0x4);
    assert!(core::mem::offset_of!(TokenSecurityAttributesInformation, p_attribute_v1) == 0x8);
};

/// `_CONTEXT_CHUNK` (RtlInitializeExtendedContext (CONTEXT_EX); 0x8 bytes).
#[repr(C)]
pub struct ContextChunk {
    pub offset: Field<i32>,
    pub length: Field<u32>,
}

unsafe impl NtStruct for ContextChunk {}

const _: () = {
    assert!(core::mem::size_of::<ContextChunk>() == 0x8);
    assert!(core::mem::offset_of!(ContextChunk, offset) == 0x0);
    assert!(core::mem::offset_of!(ContextChunk, length) == 0x4);
};

/// `_CONTEXT_EX` (RtlInitializeExtendedContext (CONTEXT_EX); 0x18 bytes).
#[repr(C)]
pub struct ContextEx {
    pub all: ContextChunk,
    pub legacy: ContextChunk,
    pub x_state: ContextChunk,
}

unsafe impl NtStruct for ContextEx {}

const _: () = {
    assert!(core::mem::size_of::<ContextEx>() == 0x18);
    assert!(core::mem::offset_of!(ContextEx, all) == 0x0);
    assert!(core::mem::offset_of!(ContextEx, legacy) == 0x8);
    assert!(core::mem::offset_of!(ContextEx, x_state) == 0x10);
};

/// `_PROCESS_EXTENDED_BASIC_INFORMATION` (NtQueryInformationProcess (ProcessBasicInformation, forma estendida); 0x40 bytes).
#[repr(C)]
pub struct ProcessExtendedBasicInformation {
    pub size: Field<u64>,
    pub basic_info: ProcessBasicInformation,
    pub flags: Field<u32>,
    _pad_3c: Reserved<0x4>,
}

unsafe impl NtStruct for ProcessExtendedBasicInformation {}

impl ProcessExtendedBasicInformation {
    /// `IsProtectedProcess`: bits 0..=0 de `flags`.
    pub const IS_PROTECTED_PROCESS_SHIFT: u32 = 0;
    pub const IS_PROTECTED_PROCESS_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn is_protected_process(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_protected_process(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `IsWow64Process`: bits 1..=1 de `flags`.
    pub const IS_WOW64_PROCESS_SHIFT: u32 = 1;
    pub const IS_WOW64_PROCESS_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn is_wow64_process(&self) -> u32 {
        self.flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_wow64_process(&self, value: u32) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `IsProcessDeleting`: bits 2..=2 de `flags`.
    pub const IS_PROCESS_DELETING_SHIFT: u32 = 2;
    pub const IS_PROCESS_DELETING_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn is_process_deleting(&self) -> u32 {
        self.flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_process_deleting(&self, value: u32) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `IsCrossSessionCreate`: bits 3..=3 de `flags`.
    pub const IS_CROSS_SESSION_CREATE_SHIFT: u32 = 3;
    pub const IS_CROSS_SESSION_CREATE_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn is_cross_session_create(&self) -> u32 {
        self.flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_cross_session_create(&self, value: u32) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `IsFrozen`: bits 4..=4 de `flags`.
    pub const IS_FROZEN_SHIFT: u32 = 4;
    pub const IS_FROZEN_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn is_frozen(&self) -> u32 {
        self.flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_frozen(&self, value: u32) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `IsBackground`: bits 5..=5 de `flags`.
    pub const IS_BACKGROUND_SHIFT: u32 = 5;
    pub const IS_BACKGROUND_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn is_background(&self) -> u32 {
        self.flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_background(&self, value: u32) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `IsStronglyNamed`: bits 6..=6 de `flags`.
    pub const IS_STRONGLY_NAMED_SHIFT: u32 = 6;
    pub const IS_STRONGLY_NAMED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn is_strongly_named(&self) -> u32 {
        self.flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_strongly_named(&self, value: u32) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `IsSecureProcess`: bits 7..=7 de `flags`.
    pub const IS_SECURE_PROCESS_SHIFT: u32 = 7;
    pub const IS_SECURE_PROCESS_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn is_secure_process(&self) -> u32 {
        self.flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_secure_process(&self, value: u32) {
        self.flags.set_bits(7, 1, value as u64)
    }
    /// `IsSubsystemProcess`: bits 8..=8 de `flags`.
    pub const IS_SUBSYSTEM_PROCESS_SHIFT: u32 = 8;
    pub const IS_SUBSYSTEM_PROCESS_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn is_subsystem_process(&self) -> u32 {
        self.flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_subsystem_process(&self, value: u32) {
        self.flags.set_bits(8, 1, value as u64)
    }
    /// `SpareBits`: bits 9..=31 de `flags`.
    pub const SPARE_BITS_SHIFT: u32 = 9;
    pub const SPARE_BITS_MASK: u32 = 0xfffffe00;
    #[inline(always)]
    pub fn spare_bits(&self) -> u32 {
        self.flags.bits(9, 23) as u32
    }
    #[inline(always)]
    pub fn set_spare_bits(&self, value: u32) {
        self.flags.set_bits(9, 23, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ProcessExtendedBasicInformation>() == 0x40);
    assert!(core::mem::offset_of!(ProcessExtendedBasicInformation, size) == 0x0);
    assert!(core::mem::offset_of!(ProcessExtendedBasicInformation, basic_info) == 0x8);
    assert!(core::mem::offset_of!(ProcessExtendedBasicInformation, flags) == 0x38);
};

/// `_SYSTEM_PROCESSOR_INFORMATION` (NtQuerySystemInformation (SystemProcessorInformation); 0xc bytes).
#[repr(C)]
pub struct SystemProcessorInformation {
    pub processor_architecture: Field<u16>,
    pub processor_level: Field<u16>,
    pub processor_revision: Field<u16>,
    pub maximum_processors: Field<u16>,
    pub processor_feature_bits: Field<u32>,
}

unsafe impl NtStruct for SystemProcessorInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemProcessorInformation>() == 0xc);
    assert!(core::mem::offset_of!(SystemProcessorInformation, processor_architecture) == 0x0);
    assert!(core::mem::offset_of!(SystemProcessorInformation, processor_level) == 0x2);
    assert!(core::mem::offset_of!(SystemProcessorInformation, processor_revision) == 0x4);
    assert!(core::mem::offset_of!(SystemProcessorInformation, maximum_processors) == 0x6);
    assert!(core::mem::offset_of!(SystemProcessorInformation, processor_feature_bits) == 0x8);
};

/// `_SYSTEM_PROCESS_INFORMATION` (winternl.h / NtQuerySystemInformation; 0x100 bytes).
#[repr(C)]
pub struct SystemProcessInformation {
    pub next_entry_offset: Field<u32>,
    pub number_of_threads: Field<u32>,
    pub working_set_private_size: LargeInteger,
    pub hard_fault_count: Field<u32>,
    pub number_of_threads_high_watermark: Field<u32>,
    pub cycle_time: Field<u64>,
    pub create_time: LargeInteger,
    pub user_time: LargeInteger,
    pub kernel_time: LargeInteger,
    pub image_name: UnicodeString,
    pub base_priority: Field<i32>,
    _pad_4c: Reserved<0x4>,
    pub unique_process_id: Field<u64>,
    pub inherited_from_unique_process_id: Field<u64>,
    pub handle_count: Field<u32>,
    pub session_id: Field<u32>,
    pub unique_process_key: Field<u64>,
    pub peak_virtual_size: Field<u64>,
    pub virtual_size: Field<u64>,
    pub page_fault_count: Field<u32>,
    _pad_84: Reserved<0x4>,
    pub peak_working_set_size: Field<u64>,
    pub working_set_size: Field<u64>,
    pub quota_peak_paged_pool_usage: Field<u64>,
    pub quota_paged_pool_usage: Field<u64>,
    pub quota_peak_non_paged_pool_usage: Field<u64>,
    pub quota_non_paged_pool_usage: Field<u64>,
    pub pagefile_usage: Field<u64>,
    pub peak_pagefile_usage: Field<u64>,
    pub private_page_count: Field<u64>,
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
}

unsafe impl NtStruct for SystemProcessInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemProcessInformation>() == 0x100);
    assert!(core::mem::offset_of!(SystemProcessInformation, next_entry_offset) == 0x0);
    assert!(core::mem::offset_of!(SystemProcessInformation, number_of_threads) == 0x4);
    assert!(core::mem::offset_of!(SystemProcessInformation, working_set_private_size) == 0x8);
    assert!(core::mem::offset_of!(SystemProcessInformation, hard_fault_count) == 0x10);
    assert!(core::mem::offset_of!(SystemProcessInformation, number_of_threads_high_watermark) == 0x14);
    assert!(core::mem::offset_of!(SystemProcessInformation, cycle_time) == 0x18);
    assert!(core::mem::offset_of!(SystemProcessInformation, create_time) == 0x20);
    assert!(core::mem::offset_of!(SystemProcessInformation, user_time) == 0x28);
    assert!(core::mem::offset_of!(SystemProcessInformation, kernel_time) == 0x30);
    assert!(core::mem::offset_of!(SystemProcessInformation, image_name) == 0x38);
    assert!(core::mem::offset_of!(SystemProcessInformation, base_priority) == 0x48);
    assert!(core::mem::offset_of!(SystemProcessInformation, unique_process_id) == 0x50);
    assert!(core::mem::offset_of!(SystemProcessInformation, inherited_from_unique_process_id) == 0x58);
    assert!(core::mem::offset_of!(SystemProcessInformation, handle_count) == 0x60);
    assert!(core::mem::offset_of!(SystemProcessInformation, session_id) == 0x64);
    assert!(core::mem::offset_of!(SystemProcessInformation, unique_process_key) == 0x68);
    assert!(core::mem::offset_of!(SystemProcessInformation, peak_virtual_size) == 0x70);
    assert!(core::mem::offset_of!(SystemProcessInformation, virtual_size) == 0x78);
    assert!(core::mem::offset_of!(SystemProcessInformation, page_fault_count) == 0x80);
    assert!(core::mem::offset_of!(SystemProcessInformation, peak_working_set_size) == 0x88);
    assert!(core::mem::offset_of!(SystemProcessInformation, working_set_size) == 0x90);
    assert!(core::mem::offset_of!(SystemProcessInformation, quota_peak_paged_pool_usage) == 0x98);
    assert!(core::mem::offset_of!(SystemProcessInformation, quota_paged_pool_usage) == 0xa0);
    assert!(core::mem::offset_of!(SystemProcessInformation, quota_peak_non_paged_pool_usage) == 0xa8);
    assert!(core::mem::offset_of!(SystemProcessInformation, quota_non_paged_pool_usage) == 0xb0);
    assert!(core::mem::offset_of!(SystemProcessInformation, pagefile_usage) == 0xb8);
    assert!(core::mem::offset_of!(SystemProcessInformation, peak_pagefile_usage) == 0xc0);
    assert!(core::mem::offset_of!(SystemProcessInformation, private_page_count) == 0xc8);
    assert!(core::mem::offset_of!(SystemProcessInformation, read_operation_count) == 0xd0);
    assert!(core::mem::offset_of!(SystemProcessInformation, write_operation_count) == 0xd8);
    assert!(core::mem::offset_of!(SystemProcessInformation, other_operation_count) == 0xe0);
    assert!(core::mem::offset_of!(SystemProcessInformation, read_transfer_count) == 0xe8);
    assert!(core::mem::offset_of!(SystemProcessInformation, write_transfer_count) == 0xf0);
    assert!(core::mem::offset_of!(SystemProcessInformation, other_transfer_count) == 0xf8);
};

/// `_SYSTEM_CODEINTEGRITY_INFORMATION` (winternl.h; 0x8 bytes).
#[repr(C)]
pub struct SystemCodeintegrityInformation {
    pub length: Field<u32>,
    pub code_integrity_options: Field<u32>,
}

unsafe impl NtStruct for SystemCodeintegrityInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemCodeintegrityInformation>() == 0x8);
    assert!(core::mem::offset_of!(SystemCodeintegrityInformation, length) == 0x0);
    assert!(core::mem::offset_of!(SystemCodeintegrityInformation, code_integrity_options) == 0x4);
};

/// `_SYSTEM_BOOT_ENVIRONMENT_INFORMATION` (NtQuerySystemInformation (SystemBootEnvironmentInformation); 0x20 bytes).
#[repr(C)]
pub struct SystemBootEnvironmentInformation {
    pub boot_identifier: Guid,
    pub firmware_type: Field<i32>,
    _pad_14: Reserved<0x4>,
    pub boot_flags: Field<u64>,
}

unsafe impl NtStruct for SystemBootEnvironmentInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemBootEnvironmentInformation>() == 0x20);
    assert!(core::mem::offset_of!(SystemBootEnvironmentInformation, boot_identifier) == 0x0);
    assert!(core::mem::offset_of!(SystemBootEnvironmentInformation, firmware_type) == 0x10);
    assert!(core::mem::offset_of!(SystemBootEnvironmentInformation, boot_flags) == 0x18);
};

/// `_SYSTEM_NUMA_INFORMATION` (NtQuerySystemInformation (SystemNumaProcessorMap/AvailableMemory); 0x408 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SystemNumaInformationView1`..`SystemNumaInformationView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct SystemNumaInformation {
    pub highest_node_number: Field<u32>,
    pub reserved: Field<u32>,
    pub active_processors_group_affinity: [GroupAffinity; 64],
}

/// Vista 1 de `_SYSTEM_NUMA_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SystemNumaInformationView1 {
    _pad_0: Reserved<0x8>,
    pub available_memory: [Field<u64>; 64],
    _pad_208: Reserved<0x200>,
}

/// Vista 2 de `_SYSTEM_NUMA_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SystemNumaInformationView2 {
    _pad_0: Reserved<0x8>,
    pub pad: [Field<u64>; 128],
}

impl core::ops::Deref for SystemNumaInformation {
    type Target = SystemNumaInformationView1;
    #[inline(always)]
    fn deref(&self) -> &SystemNumaInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SystemNumaInformationView1>() }
    }
}

impl core::ops::Deref for SystemNumaInformationView1 {
    type Target = SystemNumaInformationView2;
    #[inline(always)]
    fn deref(&self) -> &SystemNumaInformationView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SystemNumaInformationView2>() }
    }
}

unsafe impl NtStruct for SystemNumaInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemNumaInformation>() == 0x408);
    assert!(core::mem::offset_of!(SystemNumaInformation, highest_node_number) == 0x0);
    assert!(core::mem::offset_of!(SystemNumaInformation, reserved) == 0x4);
    assert!(core::mem::offset_of!(SystemNumaInformation, active_processors_group_affinity) == 0x8);
    assert!(core::mem::size_of::<SystemNumaInformationView1>() == 0x408);
    assert!(core::mem::align_of::<SystemNumaInformationView1>() == core::mem::align_of::<SystemNumaInformation>());
    assert!(core::mem::offset_of!(SystemNumaInformationView1, available_memory) == 0x8);
    assert!(core::mem::size_of::<SystemNumaInformationView2>() == 0x408);
    assert!(core::mem::align_of::<SystemNumaInformationView2>() == core::mem::align_of::<SystemNumaInformation>());
    assert!(core::mem::offset_of!(SystemNumaInformationView2, pad) == 0x8);
};

/// `_RTL_PROCESS_MODULE_INFORMATION` (NtQuerySystemInformation (SystemModuleInformation); 0x128 bytes).
#[repr(C)]
pub struct RtlProcessModuleInformation {
    /// -> `void`
    pub section: Field<u64>,
    /// -> `void`
    pub mapped_base: Field<u64>,
    /// -> `void`
    pub image_base: Field<u64>,
    pub image_size: Field<u32>,
    pub flags: Field<u32>,
    pub load_order_index: Field<u16>,
    pub init_order_index: Field<u16>,
    pub load_count: Field<u16>,
    pub offset_to_file_name: Field<u16>,
    pub full_path_name: [Field<u8>; 256],
}

unsafe impl NtStruct for RtlProcessModuleInformation {}

const _: () = {
    assert!(core::mem::size_of::<RtlProcessModuleInformation>() == 0x128);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, section) == 0x0);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, mapped_base) == 0x8);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, image_base) == 0x10);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, image_size) == 0x18);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, flags) == 0x1c);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, load_order_index) == 0x20);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, init_order_index) == 0x22);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, load_count) == 0x24);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, offset_to_file_name) == 0x26);
    assert!(core::mem::offset_of!(RtlProcessModuleInformation, full_path_name) == 0x28);
};

/// `_RTL_PROCESS_MODULES` (NtQuerySystemInformation (SystemModuleInformation); 0x130 bytes).
#[repr(C)]
pub struct RtlProcessModules {
    pub number_of_modules: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub modules: [RtlProcessModuleInformation; 1],
}

unsafe impl NtStruct for RtlProcessModules {}

const _: () = {
    assert!(core::mem::size_of::<RtlProcessModules>() == 0x130);
    assert!(core::mem::offset_of!(RtlProcessModules, number_of_modules) == 0x0);
    assert!(core::mem::offset_of!(RtlProcessModules, modules) == 0x8);
};

/// `_RTL_PROCESS_MODULE_INFORMATION_EX` (NtQuerySystemInformation (SystemModuleInformationEx); 0x140 bytes).
#[repr(C)]
pub struct RtlProcessModuleInformationEx {
    pub next_offset: Field<u16>,
    _pad_2: Reserved<0x6>,
    pub base_info: RtlProcessModuleInformation,
    pub image_checksum: Field<u32>,
    pub time_date_stamp: Field<u32>,
    /// -> `void`
    pub default_base: Field<u64>,
}

unsafe impl NtStruct for RtlProcessModuleInformationEx {}

const _: () = {
    assert!(core::mem::size_of::<RtlProcessModuleInformationEx>() == 0x140);
    assert!(core::mem::offset_of!(RtlProcessModuleInformationEx, next_offset) == 0x0);
    assert!(core::mem::offset_of!(RtlProcessModuleInformationEx, base_info) == 0x8);
    assert!(core::mem::offset_of!(RtlProcessModuleInformationEx, image_checksum) == 0x130);
    assert!(core::mem::offset_of!(RtlProcessModuleInformationEx, time_date_stamp) == 0x134);
    assert!(core::mem::offset_of!(RtlProcessModuleInformationEx, default_base) == 0x138);
};

/// `_OBJECT_DIRECTORY_INFORMATION` (NtQueryDirectoryObject; 0x20 bytes).
#[repr(C)]
pub struct ObjectDirectoryInformation {
    pub name: UnicodeString,
    pub type_name: UnicodeString,
}

unsafe impl NtStruct for ObjectDirectoryInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectDirectoryInformation>() == 0x20);
    assert!(core::mem::offset_of!(ObjectDirectoryInformation, name) == 0x0);
    assert!(core::mem::offset_of!(ObjectDirectoryInformation, type_name) == 0x10);
};

/// `_IO_COMPLETION_BASIC_INFORMATION` (NtQueryIoCompletion; 0x4 bytes).
#[repr(C)]
pub struct IoCompletionBasicInformation {
    pub depth: Field<i32>,
}

unsafe impl NtStruct for IoCompletionBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<IoCompletionBasicInformation>() == 0x4);
    assert!(core::mem::offset_of!(IoCompletionBasicInformation, depth) == 0x0);
};

/// `_WORKER_FACTORY_BASIC_INFORMATION` (NtQueryInformationWorkerFactory (WorkerFactoryBasicInformation); 0x78 bytes).
#[repr(C)]
pub struct WorkerFactoryBasicInformation {
    pub timeout: LargeInteger,
    pub retry_timeout: LargeInteger,
    pub idle_timeout: LargeInteger,
    pub paused: Field<u8>,
    pub timer_set: Field<u8>,
    pub queued_to_ex_worker: Field<u8>,
    pub may_create: Field<u8>,
    pub create_in_progress: Field<u8>,
    pub inserted_into_queue: Field<u8>,
    pub shutdown: Field<u8>,
    _pad_1f: Reserved<0x1>,
    pub binding_count: Field<u32>,
    pub thread_minimum: Field<u32>,
    pub thread_maximum: Field<u32>,
    pub pending_worker_count: Field<u32>,
    pub waiting_worker_count: Field<u32>,
    pub total_worker_count: Field<u32>,
    pub release_count: Field<u32>,
    _pad_3c: Reserved<0x4>,
    pub infinite_wait_goal: Field<i64>,
    /// -> `void`
    pub start_routine: Field<u64>,
    /// -> `void`
    pub start_parameter: Field<u64>,
    /// -> `void`
    pub process_id: Field<u64>,
    pub stack_reserve: Field<u64>,
    pub stack_commit: Field<u64>,
    pub last_thread_creation_status: Field<i32>,
    _pad_74: Reserved<0x4>,
}

unsafe impl NtStruct for WorkerFactoryBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<WorkerFactoryBasicInformation>() == 0x78);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, timeout) == 0x0);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, retry_timeout) == 0x8);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, idle_timeout) == 0x10);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, paused) == 0x18);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, timer_set) == 0x19);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, queued_to_ex_worker) == 0x1a);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, may_create) == 0x1b);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, create_in_progress) == 0x1c);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, inserted_into_queue) == 0x1d);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, shutdown) == 0x1e);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, binding_count) == 0x20);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, thread_minimum) == 0x24);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, thread_maximum) == 0x28);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, pending_worker_count) == 0x2c);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, waiting_worker_count) == 0x30);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, total_worker_count) == 0x34);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, release_count) == 0x38);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, infinite_wait_goal) == 0x40);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, start_routine) == 0x48);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, start_parameter) == 0x50);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, process_id) == 0x58);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, stack_reserve) == 0x60);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, stack_commit) == 0x68);
    assert!(core::mem::offset_of!(WorkerFactoryBasicInformation, last_thread_creation_status) == 0x70);
};

/// `_THREAD_TLS_INFORMATION` (NtSetInformationProcess (ProcessTlsInformation); 0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ThreadTlsInformationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ThreadTlsInformation {
    pub flags: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub new_tls_data: Field<u64>,
    /// -> `void`
    pub thread_id: Field<u64>,
}

/// Vista 1 de `_THREAD_TLS_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ThreadTlsInformationView1 {
    _pad_0: Reserved<0x8>,
    /// -> `void`
    pub old_tls_data: Field<u64>,
    _pad_10: Reserved<0x8>,
}

impl core::ops::Deref for ThreadTlsInformation {
    type Target = ThreadTlsInformationView1;
    #[inline(always)]
    fn deref(&self) -> &ThreadTlsInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ThreadTlsInformationView1>() }
    }
}

unsafe impl NtStruct for ThreadTlsInformation {}

const _: () = {
    assert!(core::mem::size_of::<ThreadTlsInformation>() == 0x18);
    assert!(core::mem::offset_of!(ThreadTlsInformation, flags) == 0x0);
    assert!(core::mem::offset_of!(ThreadTlsInformation, new_tls_data) == 0x8);
    assert!(core::mem::offset_of!(ThreadTlsInformation, thread_id) == 0x10);
    assert!(core::mem::size_of::<ThreadTlsInformationView1>() == 0x18);
    assert!(core::mem::align_of::<ThreadTlsInformationView1>() == core::mem::align_of::<ThreadTlsInformation>());
    assert!(core::mem::offset_of!(ThreadTlsInformationView1, old_tls_data) == 0x8);
};

/// `_PROCESS_TLS_INFORMATION` (NtSetInformationProcess (ProcessTlsInformation); 0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ProcessTlsInformationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ProcessTlsInformation {
    pub flags: Field<u32>,
    pub operation_type: Field<u32>,
    pub thread_data_count: Field<u32>,
    pub tls_index: Field<u32>,
    pub thread_data: [ThreadTlsInformation; 1],
}

/// Vista 1 de `_PROCESS_TLS_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ProcessTlsInformationView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0xc>,
    pub tls_vector_length: Field<u32>,
    _pad_10: Reserved<0x18>,
}

impl core::ops::Deref for ProcessTlsInformation {
    type Target = ProcessTlsInformationView1;
    #[inline(always)]
    fn deref(&self) -> &ProcessTlsInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ProcessTlsInformationView1>() }
    }
}

unsafe impl NtStruct for ProcessTlsInformation {}

const _: () = {
    assert!(core::mem::size_of::<ProcessTlsInformation>() == 0x28);
    assert!(core::mem::offset_of!(ProcessTlsInformation, flags) == 0x0);
    assert!(core::mem::offset_of!(ProcessTlsInformation, operation_type) == 0x4);
    assert!(core::mem::offset_of!(ProcessTlsInformation, thread_data_count) == 0x8);
    assert!(core::mem::offset_of!(ProcessTlsInformation, tls_index) == 0xc);
    assert!(core::mem::offset_of!(ProcessTlsInformation, thread_data) == 0x10);
    assert!(core::mem::size_of::<ProcessTlsInformationView1>() == 0x28);
    assert!(core::mem::align_of::<ProcessTlsInformationView1>() == core::mem::align_of::<ProcessTlsInformation>());
    assert!(core::mem::offset_of!(ProcessTlsInformationView1, tls_vector_length) == 0xc);
};

/// `HAL_DISPATCH` (ntddk.h; sem os campos de IA64; 0xb8 bytes).
#[repr(C)]
pub struct HalDispatch {
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub hal_query_system_information: Field<u64>,
    /// -> `void`
    pub hal_set_system_information: Field<u64>,
    /// -> `void`
    pub hal_query_bus_slots: Field<u64>,
    pub spare1: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub hal_examine_mbr: Field<u64>,
    /// -> `void`
    pub hal_io_read_partition_table: Field<u64>,
    /// -> `void`
    pub hal_io_set_partition_information: Field<u64>,
    /// -> `void`
    pub hal_io_write_partition_table: Field<u64>,
    /// -> `void`
    pub hal_reference_handler_for_bus: Field<u64>,
    /// -> `void`
    pub hal_reference_bus_handler: Field<u64>,
    /// -> `void`
    pub hal_dereference_bus_handler: Field<u64>,
    /// -> `void`
    pub hal_init_pnp_driver: Field<u64>,
    /// -> `void`
    pub hal_init_power_management: Field<u64>,
    /// -> `void`
    pub hal_get_dma_adapter: Field<u64>,
    /// -> `void`
    pub hal_get_interrupt_translator: Field<u64>,
    /// -> `void`
    pub hal_start_mirroring: Field<u64>,
    /// -> `void`
    pub hal_end_mirroring: Field<u64>,
    /// -> `void`
    pub hal_mirror_physical_memory: Field<u64>,
    /// -> `void`
    pub hal_end_of_boot: Field<u64>,
    /// -> `void`
    pub hal_mirror_verify: Field<u64>,
    /// -> `void`
    pub hal_get_cached_acpi_table: Field<u64>,
    /// -> `void`
    pub hal_set_pci_error_handler_callback: Field<u64>,
}

unsafe impl NtStruct for HalDispatch {}

const _: () = {
    assert!(core::mem::size_of::<HalDispatch>() == 0xb8);
    assert!(core::mem::offset_of!(HalDispatch, version) == 0x0);
    assert!(core::mem::offset_of!(HalDispatch, hal_query_system_information) == 0x8);
    assert!(core::mem::offset_of!(HalDispatch, hal_set_system_information) == 0x10);
    assert!(core::mem::offset_of!(HalDispatch, hal_query_bus_slots) == 0x18);
    assert!(core::mem::offset_of!(HalDispatch, spare1) == 0x20);
    assert!(core::mem::offset_of!(HalDispatch, hal_examine_mbr) == 0x28);
    assert!(core::mem::offset_of!(HalDispatch, hal_io_read_partition_table) == 0x30);
    assert!(core::mem::offset_of!(HalDispatch, hal_io_set_partition_information) == 0x38);
    assert!(core::mem::offset_of!(HalDispatch, hal_io_write_partition_table) == 0x40);
    assert!(core::mem::offset_of!(HalDispatch, hal_reference_handler_for_bus) == 0x48);
    assert!(core::mem::offset_of!(HalDispatch, hal_reference_bus_handler) == 0x50);
    assert!(core::mem::offset_of!(HalDispatch, hal_dereference_bus_handler) == 0x58);
    assert!(core::mem::offset_of!(HalDispatch, hal_init_pnp_driver) == 0x60);
    assert!(core::mem::offset_of!(HalDispatch, hal_init_power_management) == 0x68);
    assert!(core::mem::offset_of!(HalDispatch, hal_get_dma_adapter) == 0x70);
    assert!(core::mem::offset_of!(HalDispatch, hal_get_interrupt_translator) == 0x78);
    assert!(core::mem::offset_of!(HalDispatch, hal_start_mirroring) == 0x80);
    assert!(core::mem::offset_of!(HalDispatch, hal_end_mirroring) == 0x88);
    assert!(core::mem::offset_of!(HalDispatch, hal_mirror_physical_memory) == 0x90);
    assert!(core::mem::offset_of!(HalDispatch, hal_end_of_boot) == 0x98);
    assert!(core::mem::offset_of!(HalDispatch, hal_mirror_verify) == 0xa0);
    assert!(core::mem::offset_of!(HalDispatch, hal_get_cached_acpi_table) == 0xa8);
    assert!(core::mem::offset_of!(HalDispatch, hal_set_pci_error_handler_callback) == 0xb0);
};

/// `_OBJECT_TYPES_INFORMATION` (NtQueryObject (ObjectTypesInformation); 0x70 bytes).
#[repr(C)]
pub struct ObjectTypesInformation {
    pub number_of_types: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub type_information: [ObjectTypeInformation; 1],
}

unsafe impl NtStruct for ObjectTypesInformation {}

const _: () = {
    assert!(core::mem::size_of::<ObjectTypesInformation>() == 0x70);
    assert!(core::mem::offset_of!(ObjectTypesInformation, number_of_types) == 0x0);
    assert!(core::mem::offset_of!(ObjectTypesInformation, type_information) == 0x8);
};

/// `KGUARDED_MUTEX` (wdm.h): desde o Windows 8 é o próprio `FAST_MUTEX`.
pub type KguardedMutex = FastMutex;

/// `KSPIN_LOCK` (wdm.h): um `ULONG_PTR`; use `KspinLock::at(endereço)` e `atomic()`.
pub type KspinLock = Field<u64>;
