//! Io: IRPs, pilhas de I/O, objetos de driver/dispositivo/arquivo.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_DRIVER_OBJECT` (0x150 bytes).
#[repr(C)]
pub struct DriverObject {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_4: Reserved<0x4>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    pub flags: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub driver_start: Field<u64>,
    pub driver_size: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub driver_section: Field<u64>,
    /// -> `_DRIVER_EXTENSION`
    pub driver_extension: Field<u64>,
    pub driver_name: UnicodeString,
    /// -> `_UNICODE_STRING`
    pub hardware_database: Field<u64>,
    /// -> `_FAST_IO_DISPATCH`
    pub fast_io_dispatch: Field<u64>,
    /// -> `fn`
    pub driver_init: Field<u64>,
    /// -> `fn`
    pub driver_start_io: Field<u64>,
    /// -> `fn`
    pub driver_unload: Field<u64>,
    /// -> `fn`
    pub major_function: [Field<u64>; 28],
}

unsafe impl NtStruct for DriverObject {}

const _: () = {
    assert!(core::mem::size_of::<DriverObject>() == 0x150);
    assert!(core::mem::offset_of!(DriverObject, type_) == 0x0);
    assert!(core::mem::offset_of!(DriverObject, size) == 0x2);
    assert!(core::mem::offset_of!(DriverObject, device_object) == 0x8);
    assert!(core::mem::offset_of!(DriverObject, flags) == 0x10);
    assert!(core::mem::offset_of!(DriverObject, driver_start) == 0x18);
    assert!(core::mem::offset_of!(DriverObject, driver_size) == 0x20);
    assert!(core::mem::offset_of!(DriverObject, driver_section) == 0x28);
    assert!(core::mem::offset_of!(DriverObject, driver_extension) == 0x30);
    assert!(core::mem::offset_of!(DriverObject, driver_name) == 0x38);
    assert!(core::mem::offset_of!(DriverObject, hardware_database) == 0x48);
    assert!(core::mem::offset_of!(DriverObject, fast_io_dispatch) == 0x50);
    assert!(core::mem::offset_of!(DriverObject, driver_init) == 0x58);
    assert!(core::mem::offset_of!(DriverObject, driver_start_io) == 0x60);
    assert!(core::mem::offset_of!(DriverObject, driver_unload) == 0x68);
    assert!(core::mem::offset_of!(DriverObject, major_function) == 0x70);
};

/// `_DRIVER_EXTENSION` (0x50 bytes).
#[repr(C)]
pub struct DriverExtension {
    /// -> `_DRIVER_OBJECT`
    pub driver_object: Field<u64>,
    /// -> `fn`
    pub add_device: Field<u64>,
    pub count: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub service_key_name: UnicodeString,
    /// -> `_IO_CLIENT_EXTENSION`
    pub client_driver_extension: Field<u64>,
    /// -> `_FS_FILTER_CALLBACKS`
    pub fs_filter_callbacks: Field<u64>,
    /// -> `void`
    pub kse_callbacks: Field<u64>,
    /// -> `void`
    pub dv_callbacks: Field<u64>,
    /// -> `void`
    pub verifier_context: Field<u64>,
}

unsafe impl NtStruct for DriverExtension {}

const _: () = {
    assert!(core::mem::size_of::<DriverExtension>() == 0x50);
    assert!(core::mem::offset_of!(DriverExtension, driver_object) == 0x0);
    assert!(core::mem::offset_of!(DriverExtension, add_device) == 0x8);
    assert!(core::mem::offset_of!(DriverExtension, count) == 0x10);
    assert!(core::mem::offset_of!(DriverExtension, service_key_name) == 0x18);
    assert!(core::mem::offset_of!(DriverExtension, client_driver_extension) == 0x28);
    assert!(core::mem::offset_of!(DriverExtension, fs_filter_callbacks) == 0x30);
    assert!(core::mem::offset_of!(DriverExtension, kse_callbacks) == 0x38);
    assert!(core::mem::offset_of!(DriverExtension, dv_callbacks) == 0x40);
    assert!(core::mem::offset_of!(DriverExtension, verifier_context) == 0x48);
};

/// `_DEVICE_OBJECT` (0x150 bytes).
#[repr(C)]
pub struct DeviceObject {
    pub type_: Field<i16>,
    pub size: Field<u16>,
    pub reference_count: Field<i32>,
    /// -> `_DRIVER_OBJECT`
    pub driver_object: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub next_device: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub attached_device: Field<u64>,
    /// -> `_IRP`
    pub current_irp: Field<u64>,
    /// -> `_IO_TIMER`
    pub timer: Field<u64>,
    pub flags: Field<u32>,
    pub characteristics: Field<u32>,
    /// -> `_VPB`
    pub vpb: Field<u64>,
    /// -> `void`
    pub device_extension: Field<u64>,
    pub device_type: Field<u32>,
    pub stack_size: Field<i8>,
    _pad_4d: Reserved<0x3>,
    pub queue: DeviceObjectQueue,
    pub alignment_requirement: Field<u32>,
    _pad_9c: Reserved<0x4>,
    pub device_queue: KdeviceQueue,
    pub dpc: Kdpc,
    pub active_thread_count: Field<u32>,
    _pad_10c: Reserved<0x4>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    pub device_lock: Kevent,
    pub sector_size: Field<u16>,
    pub spare1: Field<u16>,
    _pad_134: Reserved<0x4>,
    /// -> `_DEVOBJ_EXTENSION`
    pub device_object_extension: Field<u64>,
    /// -> `void`
    pub reserved: Field<u64>,
    _pad_148: Reserved<0x8>,
}

unsafe impl NtStruct for DeviceObject {}

const _: () = {
    assert!(core::mem::size_of::<DeviceObject>() == 0x150);
    assert!(core::mem::offset_of!(DeviceObject, type_) == 0x0);
    assert!(core::mem::offset_of!(DeviceObject, size) == 0x2);
    assert!(core::mem::offset_of!(DeviceObject, reference_count) == 0x4);
    assert!(core::mem::offset_of!(DeviceObject, driver_object) == 0x8);
    assert!(core::mem::offset_of!(DeviceObject, next_device) == 0x10);
    assert!(core::mem::offset_of!(DeviceObject, attached_device) == 0x18);
    assert!(core::mem::offset_of!(DeviceObject, current_irp) == 0x20);
    assert!(core::mem::offset_of!(DeviceObject, timer) == 0x28);
    assert!(core::mem::offset_of!(DeviceObject, flags) == 0x30);
    assert!(core::mem::offset_of!(DeviceObject, characteristics) == 0x34);
    assert!(core::mem::offset_of!(DeviceObject, vpb) == 0x38);
    assert!(core::mem::offset_of!(DeviceObject, device_extension) == 0x40);
    assert!(core::mem::offset_of!(DeviceObject, device_type) == 0x48);
    assert!(core::mem::offset_of!(DeviceObject, stack_size) == 0x4c);
    assert!(core::mem::offset_of!(DeviceObject, queue) == 0x50);
    assert!(core::mem::offset_of!(DeviceObject, alignment_requirement) == 0x98);
    assert!(core::mem::offset_of!(DeviceObject, device_queue) == 0xa0);
    assert!(core::mem::offset_of!(DeviceObject, dpc) == 0xc8);
    assert!(core::mem::offset_of!(DeviceObject, active_thread_count) == 0x108);
    assert!(core::mem::offset_of!(DeviceObject, security_descriptor) == 0x110);
    assert!(core::mem::offset_of!(DeviceObject, device_lock) == 0x118);
    assert!(core::mem::offset_of!(DeviceObject, sector_size) == 0x130);
    assert!(core::mem::offset_of!(DeviceObject, spare1) == 0x132);
    assert!(core::mem::offset_of!(DeviceObject, device_object_extension) == 0x138);
    assert!(core::mem::offset_of!(DeviceObject, reserved) == 0x140);
};

/// `_DEVICE_OBJECT::Queue` (0x48 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `DeviceObjectQueueView1`, alcançada por `Deref`.
#[repr(C)]
pub struct DeviceObjectQueue {
    pub list_entry: ListEntry,
    _pad_10: Reserved<0x38>,
}

/// Vista 1 de `_DEVICE_OBJECT::Queue` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DeviceObjectQueueView1 {
    pub wcb: WaitContextBlock,
}

impl core::ops::Deref for DeviceObjectQueue {
    type Target = DeviceObjectQueueView1;
    #[inline(always)]
    fn deref(&self) -> &DeviceObjectQueueView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DeviceObjectQueueView1>() }
    }
}

unsafe impl NtStruct for DeviceObjectQueue {}

const _: () = {
    assert!(core::mem::size_of::<DeviceObjectQueue>() == 0x48);
    assert!(core::mem::offset_of!(DeviceObjectQueue, list_entry) == 0x0);
    assert!(core::mem::size_of::<DeviceObjectQueueView1>() == 0x48);
    assert!(core::mem::align_of::<DeviceObjectQueueView1>() == core::mem::align_of::<DeviceObjectQueue>());
    assert!(core::mem::offset_of!(DeviceObjectQueueView1, wcb) == 0x0);
};

/// `_WAIT_CONTEXT_BLOCK` (0x48 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WaitContextBlockView1`, alcançada por `Deref`.
#[repr(C)]
pub struct WaitContextBlock {
    pub wait_queue_entry: KdeviceQueueEntry,
    /// -> `fn`
    pub device_routine: Field<u64>,
    /// -> `void`
    pub device_context: Field<u64>,
    pub number_of_map_registers: Field<u32>,
    _pad_2c: Reserved<0x4>,
    /// -> `void`
    pub device_object: Field<u64>,
    /// -> `void`
    pub current_irp: Field<u64>,
    /// -> `_KDPC`
    pub buffer_chaining_dpc: Field<u64>,
}

/// Vista 1 de `_WAIT_CONTEXT_BLOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WaitContextBlockView1 {
    pub dma_wait_entry: ListEntry,
    pub number_of_channels: Field<u32>,
    pub bitfield_14: Field<u32>,
    _pad_18: Reserved<0x30>,
}

impl core::ops::Deref for WaitContextBlock {
    type Target = WaitContextBlockView1;
    #[inline(always)]
    fn deref(&self) -> &WaitContextBlockView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WaitContextBlockView1>() }
    }
}

unsafe impl NtStruct for WaitContextBlock {}

impl WaitContextBlock {
    /// `SyncCallback`: bits 0..=0 de `bitfield_14`.
    pub const SYNC_CALLBACK_SHIFT: u32 = 0;
    pub const SYNC_CALLBACK_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn sync_callback(&self) -> u32 {
        self.bitfield_14.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_sync_callback(&self, value: u32) {
        self.bitfield_14.set_bits(0, 1, value as u64)
    }
    /// `DmaContext`: bits 1..=1 de `bitfield_14`.
    pub const DMA_CONTEXT_SHIFT: u32 = 1;
    pub const DMA_CONTEXT_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn dma_context(&self) -> u32 {
        self.bitfield_14.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_dma_context(&self, value: u32) {
        self.bitfield_14.set_bits(1, 1, value as u64)
    }
    /// `ZeroMapRegisters`: bits 2..=2 de `bitfield_14`.
    pub const ZERO_MAP_REGISTERS_SHIFT: u32 = 2;
    pub const ZERO_MAP_REGISTERS_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn zero_map_registers(&self) -> u32 {
        self.bitfield_14.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_zero_map_registers(&self, value: u32) {
        self.bitfield_14.set_bits(2, 1, value as u64)
    }
    /// `Reserved`: bits 3..=11 de `bitfield_14`.
    pub const RESERVED_SHIFT: u32 = 3;
    pub const RESERVED_MASK: u32 = 0xff8;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.bitfield_14.bits(3, 9) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.bitfield_14.set_bits(3, 9, value as u64)
    }
    /// `NumberOfRemapPages`: bits 12..=31 de `bitfield_14`.
    pub const NUMBER_OF_REMAP_PAGES_SHIFT: u32 = 12;
    pub const NUMBER_OF_REMAP_PAGES_MASK: u32 = 0xfffff000;
    #[inline(always)]
    pub fn number_of_remap_pages(&self) -> u32 {
        self.bitfield_14.bits(12, 20) as u32
    }
    #[inline(always)]
    pub fn set_number_of_remap_pages(&self, value: u32) {
        self.bitfield_14.set_bits(12, 20, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WaitContextBlock>() == 0x48);
    assert!(core::mem::offset_of!(WaitContextBlock, wait_queue_entry) == 0x0);
    assert!(core::mem::offset_of!(WaitContextBlock, device_routine) == 0x18);
    assert!(core::mem::offset_of!(WaitContextBlock, device_context) == 0x20);
    assert!(core::mem::offset_of!(WaitContextBlock, number_of_map_registers) == 0x28);
    assert!(core::mem::offset_of!(WaitContextBlock, device_object) == 0x30);
    assert!(core::mem::offset_of!(WaitContextBlock, current_irp) == 0x38);
    assert!(core::mem::offset_of!(WaitContextBlock, buffer_chaining_dpc) == 0x40);
    assert!(core::mem::size_of::<WaitContextBlockView1>() == 0x48);
    assert!(core::mem::align_of::<WaitContextBlockView1>() == core::mem::align_of::<WaitContextBlock>());
    assert!(core::mem::offset_of!(WaitContextBlockView1, dma_wait_entry) == 0x0);
    assert!(core::mem::offset_of!(WaitContextBlockView1, number_of_channels) == 0x10);
    assert!(core::mem::offset_of!(WaitContextBlockView1, bitfield_14) == 0x14);
};

/// `_DEVOBJ_EXTENSION` (0x70 bytes).
#[repr(C)]
pub struct DevobjExtension {
    pub type_: Field<i16>,
    pub size: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    pub power_flags: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `_DEVICE_OBJECT_POWER_EXTENSION`
    pub dope: Field<u64>,
    pub extension_flags: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub device_node: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub attached_to: Field<u64>,
    pub start_io_count: Field<i32>,
    pub start_io_key: Field<i32>,
    pub start_io_flags: Field<u32>,
    _pad_44: Reserved<0x4>,
    /// -> `_VPB`
    pub vpb: Field<u64>,
    /// -> `void`
    pub dependency_node: Field<u64>,
    /// -> `void`
    pub interrupt_context: Field<u64>,
    pub interrupt_count: Field<i32>,
    _pad_64: Reserved<0x4>,
    /// -> `void`
    pub verifier_context: Field<u64>,
}

unsafe impl NtStruct for DevobjExtension {}

const _: () = {
    assert!(core::mem::size_of::<DevobjExtension>() == 0x70);
    assert!(core::mem::offset_of!(DevobjExtension, type_) == 0x0);
    assert!(core::mem::offset_of!(DevobjExtension, size) == 0x2);
    assert!(core::mem::offset_of!(DevobjExtension, device_object) == 0x8);
    assert!(core::mem::offset_of!(DevobjExtension, power_flags) == 0x10);
    assert!(core::mem::offset_of!(DevobjExtension, dope) == 0x18);
    assert!(core::mem::offset_of!(DevobjExtension, extension_flags) == 0x20);
    assert!(core::mem::offset_of!(DevobjExtension, device_node) == 0x28);
    assert!(core::mem::offset_of!(DevobjExtension, attached_to) == 0x30);
    assert!(core::mem::offset_of!(DevobjExtension, start_io_count) == 0x38);
    assert!(core::mem::offset_of!(DevobjExtension, start_io_key) == 0x3c);
    assert!(core::mem::offset_of!(DevobjExtension, start_io_flags) == 0x40);
    assert!(core::mem::offset_of!(DevobjExtension, vpb) == 0x48);
    assert!(core::mem::offset_of!(DevobjExtension, dependency_node) == 0x50);
    assert!(core::mem::offset_of!(DevobjExtension, interrupt_context) == 0x58);
    assert!(core::mem::offset_of!(DevobjExtension, interrupt_count) == 0x60);
    assert!(core::mem::offset_of!(DevobjExtension, verifier_context) == 0x68);
};

/// `_VPB` (0x60 bytes).
#[repr(C)]
pub struct Vpb {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    pub flags: Field<u16>,
    pub volume_label_length: Field<u16>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub real_device: Field<u64>,
    pub serial_number: Field<u32>,
    pub reference_count: Field<u32>,
    pub volume_label: [Field<u16>; 32],
}

unsafe impl NtStruct for Vpb {}

const _: () = {
    assert!(core::mem::size_of::<Vpb>() == 0x60);
    assert!(core::mem::offset_of!(Vpb, type_) == 0x0);
    assert!(core::mem::offset_of!(Vpb, size) == 0x2);
    assert!(core::mem::offset_of!(Vpb, flags) == 0x4);
    assert!(core::mem::offset_of!(Vpb, volume_label_length) == 0x6);
    assert!(core::mem::offset_of!(Vpb, device_object) == 0x8);
    assert!(core::mem::offset_of!(Vpb, real_device) == 0x10);
    assert!(core::mem::offset_of!(Vpb, serial_number) == 0x18);
    assert!(core::mem::offset_of!(Vpb, reference_count) == 0x1c);
    assert!(core::mem::offset_of!(Vpb, volume_label) == 0x20);
};

/// `_IRP` (0xd0 bytes).
#[repr(C)]
pub struct Irp {
    pub type_: Field<i16>,
    pub size: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `_MDL`
    pub mdl_address: Field<u64>,
    pub flags: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub associated_irp: IrpAssociatedIrp,
    pub thread_list_entry: ListEntry,
    pub io_status: IoStatusBlock,
    pub requestor_mode: Field<i8>,
    pub pending_returned: Field<u8>,
    pub stack_count: Field<i8>,
    pub current_location: Field<i8>,
    pub cancel: Field<u8>,
    pub cancel_irql: Field<u8>,
    pub apc_environment: Field<i8>,
    pub allocation_flags: Field<u8>,
    /// -> `_IO_STATUS_BLOCK`
    pub user_iosb: Field<u64>,
    /// -> `_KEVENT`
    pub user_event: Field<u64>,
    pub overlay: IrpOverlay,
    /// -> `fn`
    pub cancel_routine: Field<u64>,
    /// -> `void`
    pub user_buffer: Field<u64>,
    pub tail: IrpTail,
}

unsafe impl NtStruct for Irp {}

const _: () = {
    assert!(core::mem::size_of::<Irp>() == 0xd0);
    assert!(core::mem::offset_of!(Irp, type_) == 0x0);
    assert!(core::mem::offset_of!(Irp, size) == 0x2);
    assert!(core::mem::offset_of!(Irp, mdl_address) == 0x8);
    assert!(core::mem::offset_of!(Irp, flags) == 0x10);
    assert!(core::mem::offset_of!(Irp, associated_irp) == 0x18);
    assert!(core::mem::offset_of!(Irp, thread_list_entry) == 0x20);
    assert!(core::mem::offset_of!(Irp, io_status) == 0x30);
    assert!(core::mem::offset_of!(Irp, requestor_mode) == 0x40);
    assert!(core::mem::offset_of!(Irp, pending_returned) == 0x41);
    assert!(core::mem::offset_of!(Irp, stack_count) == 0x42);
    assert!(core::mem::offset_of!(Irp, current_location) == 0x43);
    assert!(core::mem::offset_of!(Irp, cancel) == 0x44);
    assert!(core::mem::offset_of!(Irp, cancel_irql) == 0x45);
    assert!(core::mem::offset_of!(Irp, apc_environment) == 0x46);
    assert!(core::mem::offset_of!(Irp, allocation_flags) == 0x47);
    assert!(core::mem::offset_of!(Irp, user_iosb) == 0x48);
    assert!(core::mem::offset_of!(Irp, user_event) == 0x50);
    assert!(core::mem::offset_of!(Irp, overlay) == 0x58);
    assert!(core::mem::offset_of!(Irp, cancel_routine) == 0x68);
    assert!(core::mem::offset_of!(Irp, user_buffer) == 0x70);
    assert!(core::mem::offset_of!(Irp, tail) == 0x78);
};

/// `_IRP::AssociatedIrp` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IrpAssociatedIrpView1`..`IrpAssociatedIrpView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct IrpAssociatedIrp {
    /// -> `_IRP`
    pub master_irp: Field<u64>,
}

/// Vista 1 de `_IRP::AssociatedIrp` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpAssociatedIrpView1 {
    _align: [u64; 0],
    pub irp_count: Field<i32>,
    _pad_4: Reserved<0x4>,
}

/// Vista 2 de `_IRP::AssociatedIrp` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpAssociatedIrpView2 {
    /// -> `void`
    pub system_buffer: Field<u64>,
}

impl core::ops::Deref for IrpAssociatedIrp {
    type Target = IrpAssociatedIrpView1;
    #[inline(always)]
    fn deref(&self) -> &IrpAssociatedIrpView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpAssociatedIrpView1>() }
    }
}

impl core::ops::Deref for IrpAssociatedIrpView1 {
    type Target = IrpAssociatedIrpView2;
    #[inline(always)]
    fn deref(&self) -> &IrpAssociatedIrpView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpAssociatedIrpView2>() }
    }
}

unsafe impl NtStruct for IrpAssociatedIrp {}

const _: () = {
    assert!(core::mem::size_of::<IrpAssociatedIrp>() == 0x8);
    assert!(core::mem::offset_of!(IrpAssociatedIrp, master_irp) == 0x0);
    assert!(core::mem::size_of::<IrpAssociatedIrpView1>() == 0x8);
    assert!(core::mem::align_of::<IrpAssociatedIrpView1>() == core::mem::align_of::<IrpAssociatedIrp>());
    assert!(core::mem::offset_of!(IrpAssociatedIrpView1, irp_count) == 0x0);
    assert!(core::mem::size_of::<IrpAssociatedIrpView2>() == 0x8);
    assert!(core::mem::align_of::<IrpAssociatedIrpView2>() == core::mem::align_of::<IrpAssociatedIrp>());
    assert!(core::mem::offset_of!(IrpAssociatedIrpView2, system_buffer) == 0x0);
};

/// `_IO_STATUS_BLOCK` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoStatusBlockView1`, alcançada por `Deref`.
#[repr(C)]
pub struct IoStatusBlock {
    pub status: Field<i32>,
    _pad_4: Reserved<0x4>,
    pub information: Field<u64>,
}

/// Vista 1 de `_IO_STATUS_BLOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStatusBlockView1 {
    /// -> `void`
    pub pointer: Field<u64>,
    _pad_8: Reserved<0x8>,
}

impl core::ops::Deref for IoStatusBlock {
    type Target = IoStatusBlockView1;
    #[inline(always)]
    fn deref(&self) -> &IoStatusBlockView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStatusBlockView1>() }
    }
}

unsafe impl NtStruct for IoStatusBlock {}

const _: () = {
    assert!(core::mem::size_of::<IoStatusBlock>() == 0x10);
    assert!(core::mem::offset_of!(IoStatusBlock, status) == 0x0);
    assert!(core::mem::offset_of!(IoStatusBlock, information) == 0x8);
    assert!(core::mem::size_of::<IoStatusBlockView1>() == 0x10);
    assert!(core::mem::align_of::<IoStatusBlockView1>() == core::mem::align_of::<IoStatusBlock>());
    assert!(core::mem::offset_of!(IoStatusBlockView1, pointer) == 0x0);
};

/// `_IRP::Overlay` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IrpOverlayView1`, alcançada por `Deref`.
#[repr(C)]
pub struct IrpOverlay {
    pub asynchronous_parameters: IrpOverlayAsynchronousParameters,
}

/// Vista 1 de `_IRP::Overlay` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpOverlayView1 {
    pub allocation_size: LargeInteger,
    _pad_8: Reserved<0x8>,
}

impl core::ops::Deref for IrpOverlay {
    type Target = IrpOverlayView1;
    #[inline(always)]
    fn deref(&self) -> &IrpOverlayView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpOverlayView1>() }
    }
}

unsafe impl NtStruct for IrpOverlay {}

const _: () = {
    assert!(core::mem::size_of::<IrpOverlay>() == 0x10);
    assert!(core::mem::offset_of!(IrpOverlay, asynchronous_parameters) == 0x0);
    assert!(core::mem::size_of::<IrpOverlayView1>() == 0x10);
    assert!(core::mem::align_of::<IrpOverlayView1>() == core::mem::align_of::<IrpOverlay>());
    assert!(core::mem::offset_of!(IrpOverlayView1, allocation_size) == 0x0);
};

/// `_IRP::Overlay::AsynchronousParameters` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IrpOverlayAsynchronousParametersView1`, alcançada por `Deref`.
#[repr(C)]
pub struct IrpOverlayAsynchronousParameters {
    /// -> `fn`
    pub user_apc_routine: Field<u64>,
    /// -> `void`
    pub user_apc_context: Field<u64>,
}

/// Vista 1 de `_IRP::Overlay::AsynchronousParameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpOverlayAsynchronousParametersView1 {
    /// -> `void`
    pub issuing_process: Field<u64>,
    _pad_8: Reserved<0x8>,
}

impl core::ops::Deref for IrpOverlayAsynchronousParameters {
    type Target = IrpOverlayAsynchronousParametersView1;
    #[inline(always)]
    fn deref(&self) -> &IrpOverlayAsynchronousParametersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpOverlayAsynchronousParametersView1>() }
    }
}

unsafe impl NtStruct for IrpOverlayAsynchronousParameters {}

const _: () = {
    assert!(core::mem::size_of::<IrpOverlayAsynchronousParameters>() == 0x10);
    assert!(core::mem::offset_of!(IrpOverlayAsynchronousParameters, user_apc_routine) == 0x0);
    assert!(core::mem::offset_of!(IrpOverlayAsynchronousParameters, user_apc_context) == 0x8);
    assert!(core::mem::size_of::<IrpOverlayAsynchronousParametersView1>() == 0x10);
    assert!(core::mem::align_of::<IrpOverlayAsynchronousParametersView1>() == core::mem::align_of::<IrpOverlayAsynchronousParameters>());
    assert!(core::mem::offset_of!(IrpOverlayAsynchronousParametersView1, issuing_process) == 0x0);
};

/// `_IRP::Tail` (0x58 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IrpTailView1`..`IrpTailView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct IrpTail {
    pub overlay: IrpTailOverlay,
    _pad_50: Reserved<0x8>,
}

/// Vista 1 de `_IRP::Tail` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpTailView1 {
    pub apc: Kapc,
}

/// Vista 2 de `_IRP::Tail` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpTailView2 {
    /// -> `void`
    pub completion_key: Field<u64>,
    _pad_8: Reserved<0x50>,
}

impl core::ops::Deref for IrpTail {
    type Target = IrpTailView1;
    #[inline(always)]
    fn deref(&self) -> &IrpTailView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpTailView1>() }
    }
}

impl core::ops::Deref for IrpTailView1 {
    type Target = IrpTailView2;
    #[inline(always)]
    fn deref(&self) -> &IrpTailView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpTailView2>() }
    }
}

unsafe impl NtStruct for IrpTail {}

const _: () = {
    assert!(core::mem::size_of::<IrpTail>() == 0x58);
    assert!(core::mem::offset_of!(IrpTail, overlay) == 0x0);
    assert!(core::mem::size_of::<IrpTailView1>() == 0x58);
    assert!(core::mem::align_of::<IrpTailView1>() == core::mem::align_of::<IrpTail>());
    assert!(core::mem::offset_of!(IrpTailView1, apc) == 0x0);
    assert!(core::mem::size_of::<IrpTailView2>() == 0x58);
    assert!(core::mem::align_of::<IrpTailView2>() == core::mem::align_of::<IrpTail>());
    assert!(core::mem::offset_of!(IrpTailView2, completion_key) == 0x0);
};

/// `_IRP::Tail::Overlay` (0x50 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IrpTailOverlayView1`, alcançada por `Deref`.
#[repr(C)]
pub struct IrpTailOverlay {
    pub device_queue_entry: KdeviceQueueEntry,
    _pad_18: Reserved<0x8>,
    /// -> `_ETHREAD`
    pub thread: Field<u64>,
    /// -> `i8`
    pub auxiliary_buffer: Field<u64>,
    pub list_entry: ListEntry,
    /// -> `_IO_STACK_LOCATION`
    pub current_stack_location: Field<u64>,
    /// -> `_FILE_OBJECT`
    pub original_file_object: Field<u64>,
}

/// Vista 1 de `_IRP::Tail::Overlay` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IrpTailOverlayView1 {
    /// -> `void`
    pub driver_context: [Field<u64>; 4],
    _pad_20: Reserved<0x20>,
    pub packet_type: Field<u32>,
    _pad_44: Reserved<0xc>,
}

impl core::ops::Deref for IrpTailOverlay {
    type Target = IrpTailOverlayView1;
    #[inline(always)]
    fn deref(&self) -> &IrpTailOverlayView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IrpTailOverlayView1>() }
    }
}

unsafe impl NtStruct for IrpTailOverlay {}

const _: () = {
    assert!(core::mem::size_of::<IrpTailOverlay>() == 0x50);
    assert!(core::mem::offset_of!(IrpTailOverlay, device_queue_entry) == 0x0);
    assert!(core::mem::offset_of!(IrpTailOverlay, thread) == 0x20);
    assert!(core::mem::offset_of!(IrpTailOverlay, auxiliary_buffer) == 0x28);
    assert!(core::mem::offset_of!(IrpTailOverlay, list_entry) == 0x30);
    assert!(core::mem::offset_of!(IrpTailOverlay, current_stack_location) == 0x40);
    assert!(core::mem::offset_of!(IrpTailOverlay, original_file_object) == 0x48);
    assert!(core::mem::size_of::<IrpTailOverlayView1>() == 0x50);
    assert!(core::mem::align_of::<IrpTailOverlayView1>() == core::mem::align_of::<IrpTailOverlay>());
    assert!(core::mem::offset_of!(IrpTailOverlayView1, driver_context) == 0x0);
    assert!(core::mem::offset_of!(IrpTailOverlayView1, packet_type) == 0x40);
};

/// `_IO_STACK_LOCATION` (0x48 bytes).
#[repr(C)]
pub struct IoStackLocation {
    pub major_function: Field<u8>,
    pub minor_function: Field<u8>,
    pub flags: Field<u8>,
    pub control: Field<u8>,
    _pad_4: Reserved<0x4>,
    pub parameters: IoStackLocationParameters,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
    /// -> `fn`
    pub completion_routine: Field<u64>,
    /// -> `void`
    pub context: Field<u64>,
}

unsafe impl NtStruct for IoStackLocation {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocation>() == 0x48);
    assert!(core::mem::offset_of!(IoStackLocation, major_function) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocation, minor_function) == 0x1);
    assert!(core::mem::offset_of!(IoStackLocation, flags) == 0x2);
    assert!(core::mem::offset_of!(IoStackLocation, control) == 0x3);
    assert!(core::mem::offset_of!(IoStackLocation, parameters) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocation, device_object) == 0x28);
    assert!(core::mem::offset_of!(IoStackLocation, file_object) == 0x30);
    assert!(core::mem::offset_of!(IoStackLocation, completion_routine) == 0x38);
    assert!(core::mem::offset_of!(IoStackLocation, context) == 0x40);
};

/// `_IO_STACK_LOCATION::Parameters` (0x20 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoStackLocationParametersView1`..`IoStackLocationParametersView38`, alcançadas por `Deref`.
#[repr(C)]
pub struct IoStackLocationParameters {
    pub create: IoStackLocationParametersCreate,
}

/// Vista 1 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView1 {
    pub create_pipe: IoStackLocationParametersCreatePipe,
}

/// Vista 2 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView2 {
    pub create_mailslot: IoStackLocationParametersCreateMailslot,
}

/// Vista 3 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView3 {
    pub read: IoStackLocationParametersRead,
    _pad_18: Reserved<0x8>,
}

/// Vista 4 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView4 {
    pub write: IoStackLocationParametersRead,
    _pad_18: Reserved<0x8>,
}

/// Vista 5 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView5 {
    pub query_directory: IoStackLocationParametersQueryDirectory,
}

/// Vista 6 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView6 {
    _align: [u64; 0],
    pub notify_directory: IoStackLocationParametersNotifyDirectory,
    _pad_10: Reserved<0x10>,
}

/// Vista 7 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView7 {
    _align: [u64; 0],
    pub notify_directory_ex: IoStackLocationParametersNotifyDirectoryEx,
    _pad_18: Reserved<0x8>,
}

/// Vista 8 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView8 {
    _align: [u64; 0],
    pub query_file: IoStackLocationParametersQueryFile,
    _pad_10: Reserved<0x10>,
}

/// Vista 9 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView9 {
    pub set_file: IoStackLocationParametersSetFile,
}

/// Vista 10 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView10 {
    pub query_ea: IoStackLocationParametersQueryEa,
}

/// Vista 11 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView11 {
    _align: [u64; 0],
    pub set_ea: IoStackLocationParametersSetEa,
    _pad_4: Reserved<0x1c>,
}

/// Vista 12 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView12 {
    _align: [u64; 0],
    pub query_volume: IoStackLocationParametersQueryVolume,
    _pad_10: Reserved<0x10>,
}

/// Vista 13 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView13 {
    _align: [u64; 0],
    pub set_volume: IoStackLocationParametersQueryVolume,
    _pad_10: Reserved<0x10>,
}

/// Vista 14 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView14 {
    pub file_system_control: IoStackLocationParametersFileSystemControl,
}

/// Vista 15 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView15 {
    pub lock_control: IoStackLocationParametersLockControl,
    _pad_18: Reserved<0x8>,
}

/// Vista 16 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView16 {
    pub device_io_control: IoStackLocationParametersDeviceIoControl,
}

/// Vista 17 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView17 {
    _align: [u64; 0],
    pub query_security: IoStackLocationParametersQuerySecurity,
    _pad_10: Reserved<0x10>,
}

/// Vista 18 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView18 {
    pub set_security: IoStackLocationParametersSetSecurity,
    _pad_10: Reserved<0x10>,
}

/// Vista 19 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView19 {
    pub mount_volume: IoStackLocationParametersMountVolume,
    _pad_10: Reserved<0x10>,
}

/// Vista 20 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView20 {
    pub verify_volume: IoStackLocationParametersMountVolume,
    _pad_10: Reserved<0x10>,
}

/// Vista 21 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView21 {
    pub scsi: IoStackLocationParametersScsi,
    _pad_8: Reserved<0x18>,
}

/// Vista 22 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView22 {
    pub query_quota: IoStackLocationParametersQueryQuota,
}

/// Vista 23 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView23 {
    _align: [u64; 0],
    pub set_quota: IoStackLocationParametersSetEa,
    _pad_4: Reserved<0x1c>,
}

/// Vista 24 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView24 {
    _align: [u64; 0],
    pub query_device_relations: IoStackLocationParametersQueryDeviceRelations,
    _pad_4: Reserved<0x1c>,
}

/// Vista 25 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView25 {
    pub query_interface: IoStackLocationParametersQueryInterface,
}

/// Vista 26 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView26 {
    pub device_capabilities: IoStackLocationParametersDeviceCapabilities,
    _pad_8: Reserved<0x18>,
}

/// Vista 27 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView27 {
    pub filter_resource_requirements: IoStackLocationParametersFilterResourceRequirements,
    _pad_8: Reserved<0x18>,
}

/// Vista 28 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView28 {
    pub read_write_config: IoStackLocationParametersReadWriteConfig,
}

/// Vista 29 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView29 {
    _align: [u64; 0],
    pub set_lock: IoStackLocationParametersSetLock,
    _pad_1: Reserved<0x1f>,
}

/// Vista 30 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView30 {
    _align: [u64; 0],
    pub query_id: IoStackLocationParametersQueryId,
    _pad_4: Reserved<0x1c>,
}

/// Vista 31 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView31 {
    _align: [u64; 0],
    pub query_device_text: IoStackLocationParametersQueryDeviceText,
    _pad_10: Reserved<0x10>,
}

/// Vista 32 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView32 {
    _align: [u64; 0],
    pub usage_notification: IoStackLocationParametersUsageNotification,
    _pad_10: Reserved<0x10>,
}

/// Vista 33 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView33 {
    _align: [u64; 0],
    pub wait_wake: IoStackLocationParametersWaitWake,
    _pad_4: Reserved<0x1c>,
}

/// Vista 34 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView34 {
    pub power_sequence: IoStackLocationParametersPowerSequence,
    _pad_8: Reserved<0x18>,
}

/// Vista 35 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView35 {
    _align: [u64; 0],
    pub power: IoStackLocationParametersPower,
}

/// Vista 36 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView36 {
    pub start_device: IoStackLocationParametersStartDevice,
    _pad_10: Reserved<0x10>,
}

/// Vista 37 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView37 {
    pub wmi: IoStackLocationParametersWmi,
}

/// Vista 38 de `_IO_STACK_LOCATION::Parameters` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersView38 {
    pub others: IoStackLocationParametersOthers,
}

impl core::ops::Deref for IoStackLocationParameters {
    type Target = IoStackLocationParametersView1;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView1>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView1 {
    type Target = IoStackLocationParametersView2;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView2>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView2 {
    type Target = IoStackLocationParametersView3;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView3>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView3 {
    type Target = IoStackLocationParametersView4;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView4>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView4 {
    type Target = IoStackLocationParametersView5;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView5>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView5 {
    type Target = IoStackLocationParametersView6;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView6>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView6 {
    type Target = IoStackLocationParametersView7;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView7>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView7 {
    type Target = IoStackLocationParametersView8;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView8 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView8>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView8 {
    type Target = IoStackLocationParametersView9;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView9 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView9>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView9 {
    type Target = IoStackLocationParametersView10;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView10 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView10>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView10 {
    type Target = IoStackLocationParametersView11;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView11 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView11>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView11 {
    type Target = IoStackLocationParametersView12;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView12 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView12>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView12 {
    type Target = IoStackLocationParametersView13;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView13 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView13>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView13 {
    type Target = IoStackLocationParametersView14;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView14 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView14>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView14 {
    type Target = IoStackLocationParametersView15;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView15 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView15>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView15 {
    type Target = IoStackLocationParametersView16;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView16 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView16>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView16 {
    type Target = IoStackLocationParametersView17;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView17 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView17>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView17 {
    type Target = IoStackLocationParametersView18;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView18 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView18>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView18 {
    type Target = IoStackLocationParametersView19;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView19 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView19>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView19 {
    type Target = IoStackLocationParametersView20;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView20 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView20>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView20 {
    type Target = IoStackLocationParametersView21;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView21 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView21>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView21 {
    type Target = IoStackLocationParametersView22;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView22 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView22>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView22 {
    type Target = IoStackLocationParametersView23;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView23 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView23>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView23 {
    type Target = IoStackLocationParametersView24;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView24 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView24>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView24 {
    type Target = IoStackLocationParametersView25;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView25 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView25>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView25 {
    type Target = IoStackLocationParametersView26;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView26 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView26>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView26 {
    type Target = IoStackLocationParametersView27;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView27 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView27>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView27 {
    type Target = IoStackLocationParametersView28;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView28 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView28>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView28 {
    type Target = IoStackLocationParametersView29;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView29 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView29>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView29 {
    type Target = IoStackLocationParametersView30;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView30 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView30>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView30 {
    type Target = IoStackLocationParametersView31;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView31 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView31>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView31 {
    type Target = IoStackLocationParametersView32;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView32 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView32>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView32 {
    type Target = IoStackLocationParametersView33;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView33 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView33>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView33 {
    type Target = IoStackLocationParametersView34;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView34 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView34>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView34 {
    type Target = IoStackLocationParametersView35;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView35 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView35>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView35 {
    type Target = IoStackLocationParametersView36;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView36 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView36>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView36 {
    type Target = IoStackLocationParametersView37;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView37 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView37>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersView37 {
    type Target = IoStackLocationParametersView38;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersView38 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersView38>() }
    }
}

unsafe impl NtStruct for IoStackLocationParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParameters>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParameters, create) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView1>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView1>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView1, create_pipe) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView2>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView2>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView2, create_mailslot) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView3>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView3>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView3, read) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView4>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView4>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView4, write) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView5>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView5>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView5, query_directory) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView6>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView6>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView6, notify_directory) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView7>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView7>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView7, notify_directory_ex) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView8>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView8>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView8, query_file) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView9>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView9>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView9, set_file) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView10>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView10>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView10, query_ea) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView11>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView11>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView11, set_ea) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView12>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView12>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView12, query_volume) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView13>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView13>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView13, set_volume) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView14>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView14>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView14, file_system_control) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView15>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView15>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView15, lock_control) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView16>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView16>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView16, device_io_control) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView17>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView17>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView17, query_security) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView18>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView18>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView18, set_security) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView19>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView19>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView19, mount_volume) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView20>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView20>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView20, verify_volume) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView21>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView21>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView21, scsi) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView22>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView22>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView22, query_quota) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView23>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView23>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView23, set_quota) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView24>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView24>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView24, query_device_relations) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView25>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView25>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView25, query_interface) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView26>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView26>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView26, device_capabilities) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView27>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView27>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView27, filter_resource_requirements) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView28>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView28>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView28, read_write_config) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView29>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView29>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView29, set_lock) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView30>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView30>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView30, query_id) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView31>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView31>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView31, query_device_text) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView32>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView32>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView32, usage_notification) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView33>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView33>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView33, wait_wake) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView34>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView34>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView34, power_sequence) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView35>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView35>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView35, power) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView36>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView36>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView36, start_device) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView37>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView37>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView37, wmi) == 0x0);
    assert!(core::mem::size_of::<IoStackLocationParametersView38>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersView38>() == core::mem::align_of::<IoStackLocationParameters>());
    assert!(core::mem::offset_of!(IoStackLocationParametersView38, others) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::Create` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersCreate {
    /// -> `_IO_SECURITY_CONTEXT`
    pub security_context: Field<u64>,
    pub options: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub file_attributes: Field<u16>,
    pub share_access: Field<u16>,
    _pad_14: Reserved<0x4>,
    pub ea_length: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersCreate {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersCreate>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreate, security_context) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreate, options) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreate, file_attributes) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreate, share_access) == 0x12);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreate, ea_length) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::CreatePipe` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersCreatePipe {
    /// -> `_IO_SECURITY_CONTEXT`
    pub security_context: Field<u64>,
    pub options: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub reserved: Field<u16>,
    pub share_access: Field<u16>,
    _pad_14: Reserved<0x4>,
    /// -> `_NAMED_PIPE_CREATE_PARAMETERS`
    pub parameters: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersCreatePipe {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersCreatePipe>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreatePipe, security_context) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreatePipe, options) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreatePipe, reserved) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreatePipe, share_access) == 0x12);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreatePipe, parameters) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::CreateMailslot` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersCreateMailslot {
    /// -> `_IO_SECURITY_CONTEXT`
    pub security_context: Field<u64>,
    pub options: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub reserved: Field<u16>,
    pub share_access: Field<u16>,
    _pad_14: Reserved<0x4>,
    /// -> `_MAILSLOT_CREATE_PARAMETERS`
    pub parameters: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersCreateMailslot {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersCreateMailslot>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreateMailslot, security_context) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreateMailslot, options) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreateMailslot, reserved) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreateMailslot, share_access) == 0x12);
    assert!(core::mem::offset_of!(IoStackLocationParametersCreateMailslot, parameters) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::Read` (0x18 bytes).
#[repr(C)]
pub struct IoStackLocationParametersRead {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub key: Field<u32>,
    pub flags: Field<u32>,
    pub byte_offset: LargeInteger,
}

unsafe impl NtStruct for IoStackLocationParametersRead {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersRead>() == 0x18);
    assert!(core::mem::offset_of!(IoStackLocationParametersRead, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersRead, key) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersRead, flags) == 0xc);
    assert!(core::mem::offset_of!(IoStackLocationParametersRead, byte_offset) == 0x10);
};

/// `_IO_STACK_LOCATION::Parameters::QueryDirectory` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryDirectory {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_UNICODE_STRING`
    pub file_name: Field<u64>,
    pub file_information_class: Field<FileInformationClass>,
    _pad_14: Reserved<0x4>,
    pub file_index: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryDirectory {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryDirectory>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDirectory, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDirectory, file_name) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDirectory, file_information_class) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDirectory, file_index) == 0x18);
};

/// `_FILE_INFORMATION_CLASS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct FileInformationClass(pub i32);

impl FileInformationClass {
    pub const FILE_DIRECTORY_INFORMATION: Self = Self(1);
    pub const FILE_FULL_DIRECTORY_INFORMATION: Self = Self(2);
    pub const FILE_BOTH_DIRECTORY_INFORMATION: Self = Self(3);
    pub const FILE_BASIC_INFORMATION: Self = Self(4);
    pub const FILE_STANDARD_INFORMATION: Self = Self(5);
    pub const FILE_INTERNAL_INFORMATION: Self = Self(6);
    pub const FILE_EA_INFORMATION: Self = Self(7);
    pub const FILE_ACCESS_INFORMATION: Self = Self(8);
    pub const FILE_NAME_INFORMATION: Self = Self(9);
    pub const FILE_RENAME_INFORMATION: Self = Self(10);
    pub const FILE_LINK_INFORMATION: Self = Self(11);
    pub const FILE_NAMES_INFORMATION: Self = Self(12);
    pub const FILE_DISPOSITION_INFORMATION: Self = Self(13);
    pub const FILE_POSITION_INFORMATION: Self = Self(14);
    pub const FILE_FULL_EA_INFORMATION: Self = Self(15);
    pub const FILE_MODE_INFORMATION: Self = Self(16);
    pub const FILE_ALIGNMENT_INFORMATION: Self = Self(17);
    pub const FILE_ALL_INFORMATION: Self = Self(18);
    pub const FILE_ALLOCATION_INFORMATION: Self = Self(19);
    pub const FILE_END_OF_FILE_INFORMATION: Self = Self(20);
    pub const FILE_ALTERNATE_NAME_INFORMATION: Self = Self(21);
    pub const FILE_STREAM_INFORMATION: Self = Self(22);
    pub const FILE_PIPE_INFORMATION: Self = Self(23);
    pub const FILE_PIPE_LOCAL_INFORMATION: Self = Self(24);
    pub const FILE_PIPE_REMOTE_INFORMATION: Self = Self(25);
    pub const FILE_MAILSLOT_QUERY_INFORMATION: Self = Self(26);
    pub const FILE_MAILSLOT_SET_INFORMATION: Self = Self(27);
    pub const FILE_COMPRESSION_INFORMATION: Self = Self(28);
    pub const FILE_OBJECT_ID_INFORMATION: Self = Self(29);
    pub const FILE_COMPLETION_INFORMATION: Self = Self(30);
    pub const FILE_MOVE_CLUSTER_INFORMATION: Self = Self(31);
    pub const FILE_QUOTA_INFORMATION: Self = Self(32);
    pub const FILE_REPARSE_POINT_INFORMATION: Self = Self(33);
    pub const FILE_NETWORK_OPEN_INFORMATION: Self = Self(34);
    pub const FILE_ATTRIBUTE_TAG_INFORMATION: Self = Self(35);
    pub const FILE_TRACKING_INFORMATION: Self = Self(36);
    pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: Self = Self(37);
    pub const FILE_ID_FULL_DIRECTORY_INFORMATION: Self = Self(38);
    pub const FILE_VALID_DATA_LENGTH_INFORMATION: Self = Self(39);
    pub const FILE_SHORT_NAME_INFORMATION: Self = Self(40);
    pub const FILE_IO_COMPLETION_NOTIFICATION_INFORMATION: Self = Self(41);
    pub const FILE_IO_STATUS_BLOCK_RANGE_INFORMATION: Self = Self(42);
    pub const FILE_IO_PRIORITY_HINT_INFORMATION: Self = Self(43);
    pub const FILE_SFIO_RESERVE_INFORMATION: Self = Self(44);
    pub const FILE_SFIO_VOLUME_INFORMATION: Self = Self(45);
    pub const FILE_HARD_LINK_INFORMATION: Self = Self(46);
    pub const FILE_PROCESS_IDS_USING_FILE_INFORMATION: Self = Self(47);
    pub const FILE_NORMALIZED_NAME_INFORMATION: Self = Self(48);
    pub const FILE_NETWORK_PHYSICAL_NAME_INFORMATION: Self = Self(49);
    pub const FILE_ID_GLOBAL_TX_DIRECTORY_INFORMATION: Self = Self(50);
    pub const FILE_IS_REMOTE_DEVICE_INFORMATION: Self = Self(51);
    pub const FILE_UNUSED_INFORMATION: Self = Self(52);
    pub const FILE_NUMA_NODE_INFORMATION: Self = Self(53);
    pub const FILE_STANDARD_LINK_INFORMATION: Self = Self(54);
    pub const FILE_REMOTE_PROTOCOL_INFORMATION: Self = Self(55);
    pub const FILE_RENAME_INFORMATION_BYPASS_ACCESS_CHECK: Self = Self(56);
    pub const FILE_LINK_INFORMATION_BYPASS_ACCESS_CHECK: Self = Self(57);
    pub const FILE_VOLUME_NAME_INFORMATION: Self = Self(58);
    pub const FILE_ID_INFORMATION: Self = Self(59);
    pub const FILE_ID_EXTD_DIRECTORY_INFORMATION: Self = Self(60);
    pub const FILE_REPLACE_COMPLETION_INFORMATION: Self = Self(61);
    pub const FILE_HARD_LINK_FULL_ID_INFORMATION: Self = Self(62);
    pub const FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION: Self = Self(63);
    pub const FILE_DISPOSITION_INFORMATION_EX: Self = Self(64);
    pub const FILE_RENAME_INFORMATION_EX: Self = Self(65);
    pub const FILE_RENAME_INFORMATION_EX_BYPASS_ACCESS_CHECK: Self = Self(66);
    pub const FILE_DESIRED_STORAGE_CLASS_INFORMATION: Self = Self(67);
    pub const FILE_STAT_INFORMATION: Self = Self(68);
    pub const FILE_MEMORY_PARTITION_INFORMATION: Self = Self(69);
    pub const FILE_STAT_LX_INFORMATION: Self = Self(70);
    pub const FILE_CASE_SENSITIVE_INFORMATION: Self = Self(71);
    pub const FILE_LINK_INFORMATION_EX: Self = Self(72);
    pub const FILE_LINK_INFORMATION_EX_BYPASS_ACCESS_CHECK: Self = Self(73);
    pub const FILE_STORAGE_RESERVE_ID_INFORMATION: Self = Self(74);
    pub const FILE_CASE_SENSITIVE_INFORMATION_FORCE_ACCESS_CHECK: Self = Self(75);
    pub const FILE_MAXIMUM_INFORMATION: Self = Self(76);
}

impl GuestScalar for FileInformationClass {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::NotifyDirectory` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersNotifyDirectory {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub completion_filter: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersNotifyDirectory {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersNotifyDirectory>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersNotifyDirectory, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersNotifyDirectory, completion_filter) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::NotifyDirectoryEx` (0x18 bytes).
#[repr(C)]
pub struct IoStackLocationParametersNotifyDirectoryEx {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub completion_filter: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub directory_notify_information_class: Field<DirectoryNotifyInformationClass>,
    _pad_14: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersNotifyDirectoryEx {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersNotifyDirectoryEx>() == 0x18);
    assert!(core::mem::offset_of!(IoStackLocationParametersNotifyDirectoryEx, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersNotifyDirectoryEx, completion_filter) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersNotifyDirectoryEx, directory_notify_information_class) == 0x10);
};

/// `_DIRECTORY_NOTIFY_INFORMATION_CLASS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DirectoryNotifyInformationClass(pub i32);

impl DirectoryNotifyInformationClass {
    pub const DIRECTORY_NOTIFY_INFORMATION: Self = Self(1);
    pub const DIRECTORY_NOTIFY_EXTENDED_INFORMATION: Self = Self(2);
}

impl GuestScalar for DirectoryNotifyInformationClass {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::QueryFile` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryFile {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub file_information_class: Field<FileInformationClass>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryFile {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryFile>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryFile, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryFile, file_information_class) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::SetFile` (0x20 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoStackLocationParametersSetFileView1`..`IoStackLocationParametersSetFileView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct IoStackLocationParametersSetFile {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub file_information_class: Field<FileInformationClass>,
    _pad_c: Reserved<0x4>,
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
    pub replace_if_exists: Field<u8>,
    pub advance_only: Field<u8>,
    _pad_1a: Reserved<0x6>,
}

/// Vista 1 de `_IO_STACK_LOCATION::Parameters::SetFile` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersSetFileView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x18>,
    pub cluster_count: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

/// Vista 2 de `_IO_STACK_LOCATION::Parameters::SetFile` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersSetFileView2 {
    _pad_0: Reserved<0x18>,
    /// -> `void`
    pub delete_handle: Field<u64>,
}

impl core::ops::Deref for IoStackLocationParametersSetFile {
    type Target = IoStackLocationParametersSetFileView1;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersSetFileView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersSetFileView1>() }
    }
}

impl core::ops::Deref for IoStackLocationParametersSetFileView1 {
    type Target = IoStackLocationParametersSetFileView2;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersSetFileView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersSetFileView2>() }
    }
}

unsafe impl NtStruct for IoStackLocationParametersSetFile {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersSetFile>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFile, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFile, file_information_class) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFile, file_object) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFile, replace_if_exists) == 0x18);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFile, advance_only) == 0x19);
    assert!(core::mem::size_of::<IoStackLocationParametersSetFileView1>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersSetFileView1>() == core::mem::align_of::<IoStackLocationParametersSetFile>());
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFileView1, cluster_count) == 0x18);
    assert!(core::mem::size_of::<IoStackLocationParametersSetFileView2>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersSetFileView2>() == core::mem::align_of::<IoStackLocationParametersSetFile>());
    assert!(core::mem::offset_of!(IoStackLocationParametersSetFileView2, delete_handle) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::QueryEa` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryEa {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub ea_list: Field<u64>,
    pub ea_list_length: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub ea_index: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryEa {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryEa>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryEa, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryEa, ea_list) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryEa, ea_list_length) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryEa, ea_index) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::SetEa` (0x4 bytes).
#[repr(C)]
pub struct IoStackLocationParametersSetEa {
    pub length: Field<u32>,
}

unsafe impl NtStruct for IoStackLocationParametersSetEa {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersSetEa>() == 0x4);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetEa, length) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::QueryVolume` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryVolume {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub fs_information_class: Field<Fsinfoclass>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryVolume {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryVolume>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryVolume, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryVolume, fs_information_class) == 0x8);
};

/// `_FSINFOCLASS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Fsinfoclass(pub i32);

impl Fsinfoclass {
    pub const FILE_FS_VOLUME_INFORMATION: Self = Self(1);
    pub const FILE_FS_LABEL_INFORMATION: Self = Self(2);
    pub const FILE_FS_SIZE_INFORMATION: Self = Self(3);
    pub const FILE_FS_DEVICE_INFORMATION: Self = Self(4);
    pub const FILE_FS_ATTRIBUTE_INFORMATION: Self = Self(5);
    pub const FILE_FS_CONTROL_INFORMATION: Self = Self(6);
    pub const FILE_FS_FULL_SIZE_INFORMATION: Self = Self(7);
    pub const FILE_FS_OBJECT_ID_INFORMATION: Self = Self(8);
    pub const FILE_FS_DRIVER_PATH_INFORMATION: Self = Self(9);
    pub const FILE_FS_VOLUME_FLAGS_INFORMATION: Self = Self(10);
    pub const FILE_FS_SECTOR_SIZE_INFORMATION: Self = Self(11);
    pub const FILE_FS_DATA_COPY_INFORMATION: Self = Self(12);
    pub const FILE_FS_METADATA_SIZE_INFORMATION: Self = Self(13);
    pub const FILE_FS_FULL_SIZE_INFORMATION_EX: Self = Self(14);
    pub const FILE_FS_MAXIMUM_INFORMATION: Self = Self(15);
}

impl GuestScalar for Fsinfoclass {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::FileSystemControl` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersFileSystemControl {
    pub output_buffer_length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub input_buffer_length: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub fs_control_code: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub type3_input_buffer: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersFileSystemControl {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersFileSystemControl>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersFileSystemControl, output_buffer_length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersFileSystemControl, input_buffer_length) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersFileSystemControl, fs_control_code) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersFileSystemControl, type3_input_buffer) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::LockControl` (0x18 bytes).
#[repr(C)]
pub struct IoStackLocationParametersLockControl {
    /// -> `_LARGE_INTEGER`
    pub length: Field<u64>,
    pub key: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub byte_offset: LargeInteger,
}

unsafe impl NtStruct for IoStackLocationParametersLockControl {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersLockControl>() == 0x18);
    assert!(core::mem::offset_of!(IoStackLocationParametersLockControl, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersLockControl, key) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersLockControl, byte_offset) == 0x10);
};

/// `_IO_STACK_LOCATION::Parameters::DeviceIoControl` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersDeviceIoControl {
    pub output_buffer_length: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub input_buffer_length: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub io_control_code: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub type3_input_buffer: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersDeviceIoControl {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersDeviceIoControl>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, output_buffer_length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, input_buffer_length) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, io_control_code) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersDeviceIoControl, type3_input_buffer) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::QuerySecurity` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQuerySecurity {
    pub security_information: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub length: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQuerySecurity {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQuerySecurity>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQuerySecurity, security_information) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQuerySecurity, length) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::SetSecurity` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersSetSecurity {
    pub security_information: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub security_descriptor: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersSetSecurity {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersSetSecurity>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetSecurity, security_information) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetSecurity, security_descriptor) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::MountVolume` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersMountVolume {
    /// -> `_VPB`
    pub vpb: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersMountVolume {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersMountVolume>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersMountVolume, vpb) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersMountVolume, device_object) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::Scsi` (0x8 bytes).
#[repr(C)]
pub struct IoStackLocationParametersScsi {
    /// -> `_SCSI_REQUEST_BLOCK`
    pub srb: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersScsi {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersScsi>() == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersScsi, srb) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::QueryQuota` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryQuota {
    pub length: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub start_sid: Field<u64>,
    /// -> `_FILE_GET_QUOTA_INFORMATION`
    pub sid_list: Field<u64>,
    pub sid_list_length: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryQuota {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryQuota>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryQuota, length) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryQuota, start_sid) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryQuota, sid_list) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryQuota, sid_list_length) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::QueryDeviceRelations` (0x4 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryDeviceRelations {
    pub type_: Field<DeviceRelationType>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryDeviceRelations {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryDeviceRelations>() == 0x4);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDeviceRelations, type_) == 0x0);
};

/// `_DEVICE_RELATION_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DeviceRelationType(pub i32);

impl DeviceRelationType {
    pub const BUS_RELATIONS: Self = Self(0);
    pub const EJECTION_RELATIONS: Self = Self(1);
    pub const POWER_RELATIONS: Self = Self(2);
    pub const REMOVAL_RELATIONS: Self = Self(3);
    pub const TARGET_DEVICE_RELATION: Self = Self(4);
    pub const SINGLE_BUS_RELATIONS: Self = Self(5);
    pub const TRANSPORT_RELATIONS: Self = Self(6);
}

impl GuestScalar for DeviceRelationType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::QueryInterface` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryInterface {
    /// -> `_GUID`
    pub interface_type: Field<u64>,
    pub size: Field<u16>,
    pub version: Field<u16>,
    _pad_c: Reserved<0x4>,
    /// -> `_INTERFACE`
    pub interface: Field<u64>,
    /// -> `void`
    pub interface_specific_data: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryInterface {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryInterface>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryInterface, interface_type) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryInterface, size) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryInterface, version) == 0xa);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryInterface, interface) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryInterface, interface_specific_data) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::DeviceCapabilities` (0x8 bytes).
#[repr(C)]
pub struct IoStackLocationParametersDeviceCapabilities {
    /// -> `_DEVICE_CAPABILITIES`
    pub capabilities: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersDeviceCapabilities {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersDeviceCapabilities>() == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersDeviceCapabilities, capabilities) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::FilterResourceRequirements` (0x8 bytes).
#[repr(C)]
pub struct IoStackLocationParametersFilterResourceRequirements {
    /// -> `_IO_RESOURCE_REQUIREMENTS_LIST`
    pub io_resource_requirement_list: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersFilterResourceRequirements {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersFilterResourceRequirements>() == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersFilterResourceRequirements, io_resource_requirement_list) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::ReadWriteConfig` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersReadWriteConfig {
    pub which_space: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub buffer: Field<u64>,
    pub offset: Field<u32>,
    _pad_14: Reserved<0x4>,
    pub length: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersReadWriteConfig {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersReadWriteConfig>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersReadWriteConfig, which_space) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersReadWriteConfig, buffer) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersReadWriteConfig, offset) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersReadWriteConfig, length) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::SetLock` (0x1 bytes).
#[repr(C)]
pub struct IoStackLocationParametersSetLock {
    pub lock: Field<u8>,
}

unsafe impl NtStruct for IoStackLocationParametersSetLock {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersSetLock>() == 0x1);
    assert!(core::mem::offset_of!(IoStackLocationParametersSetLock, lock) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::QueryId` (0x4 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryId {
    pub id_type: Field<BusQueryIdType>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryId {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryId>() == 0x4);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryId, id_type) == 0x0);
};

/// `BUS_QUERY_ID_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct BusQueryIdType(pub i32);

impl BusQueryIdType {
    pub const BUS_QUERY_DEVICE_ID: Self = Self(0);
    pub const BUS_QUERY_HARDWARE_I_DS: Self = Self(1);
    pub const BUS_QUERY_COMPATIBLE_I_DS: Self = Self(2);
    pub const BUS_QUERY_INSTANCE_ID: Self = Self(3);
    pub const BUS_QUERY_DEVICE_SERIAL_NUMBER: Self = Self(4);
    pub const BUS_QUERY_CONTAINER_ID: Self = Self(5);
}

impl GuestScalar for BusQueryIdType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::QueryDeviceText` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersQueryDeviceText {
    pub device_text_type: Field<DeviceTextType>,
    _pad_4: Reserved<0x4>,
    pub locale_id: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersQueryDeviceText {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersQueryDeviceText>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDeviceText, device_text_type) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersQueryDeviceText, locale_id) == 0x8);
};

/// `DEVICE_TEXT_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DeviceTextType(pub i32);

impl DeviceTextType {
    pub const DEVICE_TEXT_DESCRIPTION: Self = Self(0);
    pub const DEVICE_TEXT_LOCATION_INFORMATION: Self = Self(1);
}

impl GuestScalar for DeviceTextType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::UsageNotification` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersUsageNotification {
    pub in_path: Field<u8>,
    pub reserved: [Field<u8>; 3],
    _pad_4: Reserved<0x4>,
    pub type_: Field<DeviceUsageNotificationType>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for IoStackLocationParametersUsageNotification {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersUsageNotification>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersUsageNotification, in_path) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersUsageNotification, reserved) == 0x1);
    assert!(core::mem::offset_of!(IoStackLocationParametersUsageNotification, type_) == 0x8);
};

/// `_DEVICE_USAGE_NOTIFICATION_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DeviceUsageNotificationType(pub i32);

impl DeviceUsageNotificationType {
    pub const DEVICE_USAGE_TYPE_UNDEFINED: Self = Self(0);
    pub const DEVICE_USAGE_TYPE_PAGING: Self = Self(1);
    pub const DEVICE_USAGE_TYPE_HIBERNATION: Self = Self(2);
    pub const DEVICE_USAGE_TYPE_DUMP_FILE: Self = Self(3);
    pub const DEVICE_USAGE_TYPE_BOOT: Self = Self(4);
    pub const DEVICE_USAGE_TYPE_POST_DISPLAY: Self = Self(5);
    pub const DEVICE_USAGE_TYPE_GUEST_ASSIGNED: Self = Self(6);
}

impl GuestScalar for DeviceUsageNotificationType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::WaitWake` (0x4 bytes).
#[repr(C)]
pub struct IoStackLocationParametersWaitWake {
    pub power_state: Field<SystemPowerState>,
}

unsafe impl NtStruct for IoStackLocationParametersWaitWake {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersWaitWake>() == 0x4);
    assert!(core::mem::offset_of!(IoStackLocationParametersWaitWake, power_state) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::PowerSequence` (0x8 bytes).
#[repr(C)]
pub struct IoStackLocationParametersPowerSequence {
    /// -> `_POWER_SEQUENCE`
    pub power_sequence: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersPowerSequence {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersPowerSequence>() == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersPowerSequence, power_sequence) == 0x0);
};

/// `_IO_STACK_LOCATION::Parameters::Power` (0x20 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoStackLocationParametersPowerView1`, alcançada por `Deref`.
#[repr(C)]
pub struct IoStackLocationParametersPower {
    pub system_context: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub type_: Field<PowerStateType>,
    _pad_c: Reserved<0x4>,
    pub state: PowerState,
    _pad_14: Reserved<0x4>,
    pub shutdown_type: Field<PowerAction>,
    _pad_1c: Reserved<0x4>,
}

/// Vista 1 de `_IO_STACK_LOCATION::Parameters::Power` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoStackLocationParametersPowerView1 {
    pub system_power_state_context: SystemPowerStateContext,
    _pad_4: Reserved<0x1c>,
}

impl core::ops::Deref for IoStackLocationParametersPower {
    type Target = IoStackLocationParametersPowerView1;
    #[inline(always)]
    fn deref(&self) -> &IoStackLocationParametersPowerView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoStackLocationParametersPowerView1>() }
    }
}

unsafe impl NtStruct for IoStackLocationParametersPower {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersPower>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersPower, system_context) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersPower, type_) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersPower, state) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersPower, shutdown_type) == 0x18);
    assert!(core::mem::size_of::<IoStackLocationParametersPowerView1>() == 0x20);
    assert!(core::mem::align_of::<IoStackLocationParametersPowerView1>() == core::mem::align_of::<IoStackLocationParametersPower>());
    assert!(core::mem::offset_of!(IoStackLocationParametersPowerView1, system_power_state_context) == 0x0);
};

/// `_SYSTEM_POWER_STATE_CONTEXT` (0x4 bytes).
#[repr(C)]
pub struct SystemPowerStateContext {
    pub context_as_ulong: Field<u32>,
}

unsafe impl NtStruct for SystemPowerStateContext {}

impl SystemPowerStateContext {
    /// `Reserved1`: bits 0..=7 de `context_as_ulong`.
    pub const RESERVED1_SHIFT: u32 = 0;
    pub const RESERVED1_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn reserved1(&self) -> u32 {
        self.context_as_ulong.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_reserved1(&self, value: u32) {
        self.context_as_ulong.set_bits(0, 8, value as u64)
    }
    /// `TargetSystemState`: bits 8..=11 de `context_as_ulong`.
    pub const TARGET_SYSTEM_STATE_SHIFT: u32 = 8;
    pub const TARGET_SYSTEM_STATE_MASK: u32 = 0xf00;
    #[inline(always)]
    pub fn target_system_state(&self) -> u32 {
        self.context_as_ulong.bits(8, 4) as u32
    }
    #[inline(always)]
    pub fn set_target_system_state(&self, value: u32) {
        self.context_as_ulong.set_bits(8, 4, value as u64)
    }
    /// `EffectiveSystemState`: bits 12..=15 de `context_as_ulong`.
    pub const EFFECTIVE_SYSTEM_STATE_SHIFT: u32 = 12;
    pub const EFFECTIVE_SYSTEM_STATE_MASK: u32 = 0xf000;
    #[inline(always)]
    pub fn effective_system_state(&self) -> u32 {
        self.context_as_ulong.bits(12, 4) as u32
    }
    #[inline(always)]
    pub fn set_effective_system_state(&self, value: u32) {
        self.context_as_ulong.set_bits(12, 4, value as u64)
    }
    /// `CurrentSystemState`: bits 16..=19 de `context_as_ulong`.
    pub const CURRENT_SYSTEM_STATE_SHIFT: u32 = 16;
    pub const CURRENT_SYSTEM_STATE_MASK: u32 = 0xf0000;
    #[inline(always)]
    pub fn current_system_state(&self) -> u32 {
        self.context_as_ulong.bits(16, 4) as u32
    }
    #[inline(always)]
    pub fn set_current_system_state(&self, value: u32) {
        self.context_as_ulong.set_bits(16, 4, value as u64)
    }
    /// `IgnoreHibernationPath`: bits 20..=20 de `context_as_ulong`.
    pub const IGNORE_HIBERNATION_PATH_SHIFT: u32 = 20;
    pub const IGNORE_HIBERNATION_PATH_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn ignore_hibernation_path(&self) -> u32 {
        self.context_as_ulong.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_ignore_hibernation_path(&self, value: u32) {
        self.context_as_ulong.set_bits(20, 1, value as u64)
    }
    /// `PseudoTransition`: bits 21..=21 de `context_as_ulong`.
    pub const PSEUDO_TRANSITION_SHIFT: u32 = 21;
    pub const PSEUDO_TRANSITION_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn pseudo_transition(&self) -> u32 {
        self.context_as_ulong.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_pseudo_transition(&self, value: u32) {
        self.context_as_ulong.set_bits(21, 1, value as u64)
    }
    /// `KernelSoftReboot`: bits 22..=22 de `context_as_ulong`.
    pub const KERNEL_SOFT_REBOOT_SHIFT: u32 = 22;
    pub const KERNEL_SOFT_REBOOT_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn kernel_soft_reboot(&self) -> u32 {
        self.context_as_ulong.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_kernel_soft_reboot(&self, value: u32) {
        self.context_as_ulong.set_bits(22, 1, value as u64)
    }
    /// `DirectedDripsTransition`: bits 23..=23 de `context_as_ulong`.
    pub const DIRECTED_DRIPS_TRANSITION_SHIFT: u32 = 23;
    pub const DIRECTED_DRIPS_TRANSITION_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn directed_drips_transition(&self) -> u32 {
        self.context_as_ulong.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_directed_drips_transition(&self, value: u32) {
        self.context_as_ulong.set_bits(23, 1, value as u64)
    }
    /// `Reserved2`: bits 24..=31 de `context_as_ulong`.
    pub const RESERVED2_SHIFT: u32 = 24;
    pub const RESERVED2_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn reserved2(&self) -> u32 {
        self.context_as_ulong.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_reserved2(&self, value: u32) {
        self.context_as_ulong.set_bits(24, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SystemPowerStateContext>() == 0x4);
    assert!(core::mem::offset_of!(SystemPowerStateContext, context_as_ulong) == 0x0);
};

/// `_DEVICE_POWER_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DevicePowerState(pub i32);

impl DevicePowerState {
    pub const POWER_DEVICE_UNSPECIFIED: Self = Self(0);
    pub const POWER_DEVICE_D0: Self = Self(1);
    pub const POWER_DEVICE_D1: Self = Self(2);
    pub const POWER_DEVICE_D2: Self = Self(3);
    pub const POWER_DEVICE_D3: Self = Self(4);
    pub const POWER_DEVICE_MAXIMUM: Self = Self(5);
}

impl GuestScalar for DevicePowerState {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_STACK_LOCATION::Parameters::StartDevice` (0x10 bytes).
#[repr(C)]
pub struct IoStackLocationParametersStartDevice {
    /// -> `_CM_RESOURCE_LIST`
    pub allocated_resources: Field<u64>,
    /// -> `_CM_RESOURCE_LIST`
    pub allocated_resources_translated: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersStartDevice {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersStartDevice>() == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersStartDevice, allocated_resources) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersStartDevice, allocated_resources_translated) == 0x8);
};

/// `_IO_STACK_LOCATION::Parameters::WMI` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersWmi {
    pub provider_id: Field<u64>,
    /// -> `void`
    pub data_path: Field<u64>,
    pub buffer_size: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersWmi {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersWmi>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersWmi, provider_id) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersWmi, data_path) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersWmi, buffer_size) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersWmi, buffer) == 0x18);
};

/// `_IO_STACK_LOCATION::Parameters::Others` (0x20 bytes).
#[repr(C)]
pub struct IoStackLocationParametersOthers {
    /// -> `void`
    pub argument1: Field<u64>,
    /// -> `void`
    pub argument2: Field<u64>,
    /// -> `void`
    pub argument3: Field<u64>,
    /// -> `void`
    pub argument4: Field<u64>,
}

unsafe impl NtStruct for IoStackLocationParametersOthers {}

const _: () = {
    assert!(core::mem::size_of::<IoStackLocationParametersOthers>() == 0x20);
    assert!(core::mem::offset_of!(IoStackLocationParametersOthers, argument1) == 0x0);
    assert!(core::mem::offset_of!(IoStackLocationParametersOthers, argument2) == 0x8);
    assert!(core::mem::offset_of!(IoStackLocationParametersOthers, argument3) == 0x10);
    assert!(core::mem::offset_of!(IoStackLocationParametersOthers, argument4) == 0x18);
};

/// `_FILE_OBJECT` (0xd8 bytes).
#[repr(C)]
pub struct FileObject {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_4: Reserved<0x4>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    /// -> `_VPB`
    pub vpb: Field<u64>,
    /// -> `void`
    pub fs_context: Field<u64>,
    /// -> `void`
    pub fs_context2: Field<u64>,
    /// -> `_SECTION_OBJECT_POINTERS`
    pub section_object_pointer: Field<u64>,
    /// -> `void`
    pub private_cache_map: Field<u64>,
    pub final_status: Field<i32>,
    _pad_3c: Reserved<0x4>,
    /// -> `_FILE_OBJECT`
    pub related_file_object: Field<u64>,
    pub lock_operation: Field<u8>,
    pub delete_pending: Field<u8>,
    pub read_access: Field<u8>,
    pub write_access: Field<u8>,
    pub delete_access: Field<u8>,
    pub shared_read: Field<u8>,
    pub shared_write: Field<u8>,
    pub shared_delete: Field<u8>,
    pub flags: Field<u32>,
    _pad_54: Reserved<0x4>,
    pub file_name: UnicodeString,
    pub current_byte_offset: LargeInteger,
    pub waiters: Field<u32>,
    pub busy: Field<u32>,
    /// -> `void`
    pub last_lock: Field<u64>,
    pub lock: Kevent,
    pub event: Kevent,
    /// -> `_IO_COMPLETION_CONTEXT`
    pub completion_context: Field<u64>,
    pub irp_list_lock: Field<u64>,
    pub irp_list: ListEntry,
    /// -> `void`
    pub file_object_extension: Field<u64>,
}

unsafe impl NtStruct for FileObject {}

const _: () = {
    assert!(core::mem::size_of::<FileObject>() == 0xd8);
    assert!(core::mem::offset_of!(FileObject, type_) == 0x0);
    assert!(core::mem::offset_of!(FileObject, size) == 0x2);
    assert!(core::mem::offset_of!(FileObject, device_object) == 0x8);
    assert!(core::mem::offset_of!(FileObject, vpb) == 0x10);
    assert!(core::mem::offset_of!(FileObject, fs_context) == 0x18);
    assert!(core::mem::offset_of!(FileObject, fs_context2) == 0x20);
    assert!(core::mem::offset_of!(FileObject, section_object_pointer) == 0x28);
    assert!(core::mem::offset_of!(FileObject, private_cache_map) == 0x30);
    assert!(core::mem::offset_of!(FileObject, final_status) == 0x38);
    assert!(core::mem::offset_of!(FileObject, related_file_object) == 0x40);
    assert!(core::mem::offset_of!(FileObject, lock_operation) == 0x48);
    assert!(core::mem::offset_of!(FileObject, delete_pending) == 0x49);
    assert!(core::mem::offset_of!(FileObject, read_access) == 0x4a);
    assert!(core::mem::offset_of!(FileObject, write_access) == 0x4b);
    assert!(core::mem::offset_of!(FileObject, delete_access) == 0x4c);
    assert!(core::mem::offset_of!(FileObject, shared_read) == 0x4d);
    assert!(core::mem::offset_of!(FileObject, shared_write) == 0x4e);
    assert!(core::mem::offset_of!(FileObject, shared_delete) == 0x4f);
    assert!(core::mem::offset_of!(FileObject, flags) == 0x50);
    assert!(core::mem::offset_of!(FileObject, file_name) == 0x58);
    assert!(core::mem::offset_of!(FileObject, current_byte_offset) == 0x68);
    assert!(core::mem::offset_of!(FileObject, waiters) == 0x70);
    assert!(core::mem::offset_of!(FileObject, busy) == 0x74);
    assert!(core::mem::offset_of!(FileObject, last_lock) == 0x78);
    assert!(core::mem::offset_of!(FileObject, lock) == 0x80);
    assert!(core::mem::offset_of!(FileObject, event) == 0x98);
    assert!(core::mem::offset_of!(FileObject, completion_context) == 0xb0);
    assert!(core::mem::offset_of!(FileObject, irp_list_lock) == 0xb8);
    assert!(core::mem::offset_of!(FileObject, irp_list) == 0xc0);
    assert!(core::mem::offset_of!(FileObject, file_object_extension) == 0xd0);
};

/// `_IO_WORKITEM` (0x58 bytes).
#[repr(C)]
pub struct IoWorkitem {
    pub work_item: WorkQueueItem,
    /// -> `fn`
    pub routine: Field<u64>,
    /// -> `void`
    pub io_object: Field<u64>,
    /// -> `void`
    pub context: Field<u64>,
    /// -> `_ETHREAD`
    pub work_on_behalf_thread: Field<u64>,
    pub type_: Field<u32>,
    pub activity_id: Guid,
    _pad_54: Reserved<0x4>,
}

unsafe impl NtStruct for IoWorkitem {}

const _: () = {
    assert!(core::mem::size_of::<IoWorkitem>() == 0x58);
    assert!(core::mem::offset_of!(IoWorkitem, work_item) == 0x0);
    assert!(core::mem::offset_of!(IoWorkitem, routine) == 0x20);
    assert!(core::mem::offset_of!(IoWorkitem, io_object) == 0x28);
    assert!(core::mem::offset_of!(IoWorkitem, context) == 0x30);
    assert!(core::mem::offset_of!(IoWorkitem, work_on_behalf_thread) == 0x38);
    assert!(core::mem::offset_of!(IoWorkitem, type_) == 0x40);
    assert!(core::mem::offset_of!(IoWorkitem, activity_id) == 0x44);
};

/// `_CONTROLLER_OBJECT` (0x48 bytes).
#[repr(C)]
pub struct ControllerObject {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub controller_extension: Field<u64>,
    pub device_wait_queue: KdeviceQueue,
    pub spare1: Field<u32>,
    _pad_3c: Reserved<0x4>,
    pub spare2: LargeInteger,
}

unsafe impl NtStruct for ControllerObject {}

const _: () = {
    assert!(core::mem::size_of::<ControllerObject>() == 0x48);
    assert!(core::mem::offset_of!(ControllerObject, type_) == 0x0);
    assert!(core::mem::offset_of!(ControllerObject, size) == 0x2);
    assert!(core::mem::offset_of!(ControllerObject, controller_extension) == 0x8);
    assert!(core::mem::offset_of!(ControllerObject, device_wait_queue) == 0x10);
    assert!(core::mem::offset_of!(ControllerObject, spare1) == 0x38);
    assert!(core::mem::offset_of!(ControllerObject, spare2) == 0x40);
};

/// `_INTERFACE_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct InterfaceType(pub i32);

impl InterfaceType {
    pub const INTERFACE_TYPE_UNDEFINED: Self = Self(-1);
    pub const INTERNAL: Self = Self(0);
    pub const ISA: Self = Self(1);
    pub const EISA: Self = Self(2);
    pub const MICRO_CHANNEL: Self = Self(3);
    pub const TURBO_CHANNEL: Self = Self(4);
    pub const PCI_BUS: Self = Self(5);
    pub const VME_BUS: Self = Self(6);
    pub const NU_BUS: Self = Self(7);
    pub const PCMCIA_BUS: Self = Self(8);
    pub const C_BUS: Self = Self(9);
    pub const MPI_BUS: Self = Self(10);
    pub const MPSA_BUS: Self = Self(11);
    pub const PROCESSOR_INTERNAL: Self = Self(12);
    pub const INTERNAL_POWER_BUS: Self = Self(13);
    pub const PNPISA_BUS: Self = Self(14);
    pub const PNP_BUS: Self = Self(15);
    pub const VMCS: Self = Self(16);
    pub const ACPI_BUS: Self = Self(17);
    pub const MAXIMUM_INTERFACE_TYPE: Self = Self(18);
}

impl GuestScalar for InterfaceType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IOP_IRP_STACK_PROFILER` (0x54 bytes).
#[repr(C)]
pub struct IopIrpStackProfiler {
    pub profile: [Field<u32>; 20],
    pub total_irps: Field<u32>,
}

unsafe impl NtStruct for IopIrpStackProfiler {}

const _: () = {
    assert!(core::mem::size_of::<IopIrpStackProfiler>() == 0x54);
    assert!(core::mem::offset_of!(IopIrpStackProfiler, profile) == 0x0);
    assert!(core::mem::offset_of!(IopIrpStackProfiler, total_irps) == 0x50);
};

/// `_SECTION_OBJECT_POINTERS` (0x18 bytes).
#[repr(C)]
pub struct SectionObjectPointers {
    /// -> `void`
    pub data_section_object: Field<u64>,
    /// -> `void`
    pub shared_cache_map: Field<u64>,
    /// -> `void`
    pub image_section_object: Field<u64>,
}

unsafe impl NtStruct for SectionObjectPointers {}

const _: () = {
    assert!(core::mem::size_of::<SectionObjectPointers>() == 0x18);
    assert!(core::mem::offset_of!(SectionObjectPointers, data_section_object) == 0x0);
    assert!(core::mem::offset_of!(SectionObjectPointers, shared_cache_map) == 0x8);
    assert!(core::mem::offset_of!(SectionObjectPointers, image_section_object) == 0x10);
};

/// `_IO_COMPLETION_CONTEXT` (0x18 bytes).
#[repr(C)]
pub struct IoCompletionContext {
    /// -> `void`
    pub port: Field<u64>,
    /// -> `void`
    pub key: Field<u64>,
    pub usage_count: Field<i64>,
}

unsafe impl NtStruct for IoCompletionContext {}

const _: () = {
    assert!(core::mem::size_of::<IoCompletionContext>() == 0x18);
    assert!(core::mem::offset_of!(IoCompletionContext, port) == 0x0);
    assert!(core::mem::offset_of!(IoCompletionContext, key) == 0x8);
    assert!(core::mem::offset_of!(IoCompletionContext, usage_count) == 0x10);
};

/// `_IO_TIMER` (0x30 bytes).
#[repr(C)]
pub struct IoTimer {
    pub type_: Field<i16>,
    pub timer_flag: Field<i16>,
    _pad_4: Reserved<0x4>,
    pub timer_list: ListEntry,
    /// -> `fn`
    pub timer_routine: Field<u64>,
    /// -> `void`
    pub context: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
}

unsafe impl NtStruct for IoTimer {}

const _: () = {
    assert!(core::mem::size_of::<IoTimer>() == 0x30);
    assert!(core::mem::offset_of!(IoTimer, type_) == 0x0);
    assert!(core::mem::offset_of!(IoTimer, timer_flag) == 0x2);
    assert!(core::mem::offset_of!(IoTimer, timer_list) == 0x8);
    assert!(core::mem::offset_of!(IoTimer, timer_routine) == 0x18);
    assert!(core::mem::offset_of!(IoTimer, context) == 0x20);
    assert!(core::mem::offset_of!(IoTimer, device_object) == 0x28);
};

/// `_FILE_BASIC_INFORMATION` (0x28 bytes).
#[repr(C)]
pub struct FileBasicInformation {
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub file_attributes: Field<u32>,
    _pad_24: Reserved<0x4>,
}

unsafe impl NtStruct for FileBasicInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileBasicInformation>() == 0x28);
    assert!(core::mem::offset_of!(FileBasicInformation, creation_time) == 0x0);
    assert!(core::mem::offset_of!(FileBasicInformation, last_access_time) == 0x8);
    assert!(core::mem::offset_of!(FileBasicInformation, last_write_time) == 0x10);
    assert!(core::mem::offset_of!(FileBasicInformation, change_time) == 0x18);
    assert!(core::mem::offset_of!(FileBasicInformation, file_attributes) == 0x20);
};

/// `_FILE_STANDARD_INFORMATION` (0x18 bytes).
#[repr(C)]
pub struct FileStandardInformation {
    pub allocation_size: LargeInteger,
    pub end_of_file: LargeInteger,
    pub number_of_links: Field<u32>,
    pub delete_pending: Field<u8>,
    pub directory: Field<u8>,
    _pad_16: Reserved<0x2>,
}

unsafe impl NtStruct for FileStandardInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileStandardInformation>() == 0x18);
    assert!(core::mem::offset_of!(FileStandardInformation, allocation_size) == 0x0);
    assert!(core::mem::offset_of!(FileStandardInformation, end_of_file) == 0x8);
    assert!(core::mem::offset_of!(FileStandardInformation, number_of_links) == 0x10);
    assert!(core::mem::offset_of!(FileStandardInformation, delete_pending) == 0x14);
    assert!(core::mem::offset_of!(FileStandardInformation, directory) == 0x15);
};

/// `_DEVICE_CAPABILITIES` (0x40 bytes).
#[repr(C)]
pub struct DeviceCapabilities {
    pub size: Field<u16>,
    pub version: Field<u16>,
    pub bitfield_4: Field<u32>,
    pub address: Field<u32>,
    pub ui_number: Field<u32>,
    pub device_state: [Field<DevicePowerState>; 7],
    pub system_wake: Field<SystemPowerState>,
    pub device_wake: Field<DevicePowerState>,
    pub d1_latency: Field<u32>,
    pub d2_latency: Field<u32>,
    pub d3_latency: Field<u32>,
}

unsafe impl NtStruct for DeviceCapabilities {}

impl DeviceCapabilities {
    /// `DeviceD1`: bits 0..=0 de `bitfield_4`.
    pub const DEVICE_D1_SHIFT: u32 = 0;
    pub const DEVICE_D1_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn device_d1(&self) -> u32 {
        self.bitfield_4.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_device_d1(&self, value: u32) {
        self.bitfield_4.set_bits(0, 1, value as u64)
    }
    /// `DeviceD2`: bits 1..=1 de `bitfield_4`.
    pub const DEVICE_D2_SHIFT: u32 = 1;
    pub const DEVICE_D2_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn device_d2(&self) -> u32 {
        self.bitfield_4.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_device_d2(&self, value: u32) {
        self.bitfield_4.set_bits(1, 1, value as u64)
    }
    /// `LockSupported`: bits 2..=2 de `bitfield_4`.
    pub const LOCK_SUPPORTED_SHIFT: u32 = 2;
    pub const LOCK_SUPPORTED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn lock_supported(&self) -> u32 {
        self.bitfield_4.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_lock_supported(&self, value: u32) {
        self.bitfield_4.set_bits(2, 1, value as u64)
    }
    /// `EjectSupported`: bits 3..=3 de `bitfield_4`.
    pub const EJECT_SUPPORTED_SHIFT: u32 = 3;
    pub const EJECT_SUPPORTED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn eject_supported(&self) -> u32 {
        self.bitfield_4.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_eject_supported(&self, value: u32) {
        self.bitfield_4.set_bits(3, 1, value as u64)
    }
    /// `Removable`: bits 4..=4 de `bitfield_4`.
    pub const REMOVABLE_SHIFT: u32 = 4;
    pub const REMOVABLE_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn removable(&self) -> u32 {
        self.bitfield_4.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_removable(&self, value: u32) {
        self.bitfield_4.set_bits(4, 1, value as u64)
    }
    /// `DockDevice`: bits 5..=5 de `bitfield_4`.
    pub const DOCK_DEVICE_SHIFT: u32 = 5;
    pub const DOCK_DEVICE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn dock_device(&self) -> u32 {
        self.bitfield_4.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_dock_device(&self, value: u32) {
        self.bitfield_4.set_bits(5, 1, value as u64)
    }
    /// `UniqueID`: bits 6..=6 de `bitfield_4`.
    pub const UNIQUE_ID_SHIFT: u32 = 6;
    pub const UNIQUE_ID_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn unique_id(&self) -> u32 {
        self.bitfield_4.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_unique_id(&self, value: u32) {
        self.bitfield_4.set_bits(6, 1, value as u64)
    }
    /// `SilentInstall`: bits 7..=7 de `bitfield_4`.
    pub const SILENT_INSTALL_SHIFT: u32 = 7;
    pub const SILENT_INSTALL_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn silent_install(&self) -> u32 {
        self.bitfield_4.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_silent_install(&self, value: u32) {
        self.bitfield_4.set_bits(7, 1, value as u64)
    }
    /// `RawDeviceOK`: bits 8..=8 de `bitfield_4`.
    pub const RAW_DEVICE_OK_SHIFT: u32 = 8;
    pub const RAW_DEVICE_OK_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn raw_device_ok(&self) -> u32 {
        self.bitfield_4.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_raw_device_ok(&self, value: u32) {
        self.bitfield_4.set_bits(8, 1, value as u64)
    }
    /// `SurpriseRemovalOK`: bits 9..=9 de `bitfield_4`.
    pub const SURPRISE_REMOVAL_OK_SHIFT: u32 = 9;
    pub const SURPRISE_REMOVAL_OK_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn surprise_removal_ok(&self) -> u32 {
        self.bitfield_4.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_surprise_removal_ok(&self, value: u32) {
        self.bitfield_4.set_bits(9, 1, value as u64)
    }
    /// `WakeFromD0`: bits 10..=10 de `bitfield_4`.
    pub const WAKE_FROM_D0_SHIFT: u32 = 10;
    pub const WAKE_FROM_D0_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn wake_from_d0(&self) -> u32 {
        self.bitfield_4.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_from_d0(&self, value: u32) {
        self.bitfield_4.set_bits(10, 1, value as u64)
    }
    /// `WakeFromD1`: bits 11..=11 de `bitfield_4`.
    pub const WAKE_FROM_D1_SHIFT: u32 = 11;
    pub const WAKE_FROM_D1_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn wake_from_d1(&self) -> u32 {
        self.bitfield_4.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_from_d1(&self, value: u32) {
        self.bitfield_4.set_bits(11, 1, value as u64)
    }
    /// `WakeFromD2`: bits 12..=12 de `bitfield_4`.
    pub const WAKE_FROM_D2_SHIFT: u32 = 12;
    pub const WAKE_FROM_D2_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn wake_from_d2(&self) -> u32 {
        self.bitfield_4.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_from_d2(&self, value: u32) {
        self.bitfield_4.set_bits(12, 1, value as u64)
    }
    /// `WakeFromD3`: bits 13..=13 de `bitfield_4`.
    pub const WAKE_FROM_D3_SHIFT: u32 = 13;
    pub const WAKE_FROM_D3_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn wake_from_d3(&self) -> u32 {
        self.bitfield_4.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_from_d3(&self, value: u32) {
        self.bitfield_4.set_bits(13, 1, value as u64)
    }
    /// `HardwareDisabled`: bits 14..=14 de `bitfield_4`.
    pub const HARDWARE_DISABLED_SHIFT: u32 = 14;
    pub const HARDWARE_DISABLED_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn hardware_disabled(&self) -> u32 {
        self.bitfield_4.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_hardware_disabled(&self, value: u32) {
        self.bitfield_4.set_bits(14, 1, value as u64)
    }
    /// `NonDynamic`: bits 15..=15 de `bitfield_4`.
    pub const NON_DYNAMIC_SHIFT: u32 = 15;
    pub const NON_DYNAMIC_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn non_dynamic(&self) -> u32 {
        self.bitfield_4.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_non_dynamic(&self, value: u32) {
        self.bitfield_4.set_bits(15, 1, value as u64)
    }
    /// `WarmEjectSupported`: bits 16..=16 de `bitfield_4`.
    pub const WARM_EJECT_SUPPORTED_SHIFT: u32 = 16;
    pub const WARM_EJECT_SUPPORTED_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn warm_eject_supported(&self) -> u32 {
        self.bitfield_4.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_warm_eject_supported(&self, value: u32) {
        self.bitfield_4.set_bits(16, 1, value as u64)
    }
    /// `NoDisplayInUI`: bits 17..=17 de `bitfield_4`.
    pub const NO_DISPLAY_IN_UI_SHIFT: u32 = 17;
    pub const NO_DISPLAY_IN_UI_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn no_display_in_ui(&self) -> u32 {
        self.bitfield_4.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_display_in_ui(&self, value: u32) {
        self.bitfield_4.set_bits(17, 1, value as u64)
    }
    /// `Reserved1`: bits 18..=18 de `bitfield_4`.
    pub const RESERVED1_SHIFT: u32 = 18;
    pub const RESERVED1_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn reserved1(&self) -> u32 {
        self.bitfield_4.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved1(&self, value: u32) {
        self.bitfield_4.set_bits(18, 1, value as u64)
    }
    /// `WakeFromInterrupt`: bits 19..=19 de `bitfield_4`.
    pub const WAKE_FROM_INTERRUPT_SHIFT: u32 = 19;
    pub const WAKE_FROM_INTERRUPT_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn wake_from_interrupt(&self) -> u32 {
        self.bitfield_4.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_from_interrupt(&self, value: u32) {
        self.bitfield_4.set_bits(19, 1, value as u64)
    }
    /// `SecureDevice`: bits 20..=20 de `bitfield_4`.
    pub const SECURE_DEVICE_SHIFT: u32 = 20;
    pub const SECURE_DEVICE_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn secure_device(&self) -> u32 {
        self.bitfield_4.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_secure_device(&self, value: u32) {
        self.bitfield_4.set_bits(20, 1, value as u64)
    }
    /// `ChildOfVgaEnabledBridge`: bits 21..=21 de `bitfield_4`.
    pub const CHILD_OF_VGA_ENABLED_BRIDGE_SHIFT: u32 = 21;
    pub const CHILD_OF_VGA_ENABLED_BRIDGE_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn child_of_vga_enabled_bridge(&self) -> u32 {
        self.bitfield_4.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_child_of_vga_enabled_bridge(&self, value: u32) {
        self.bitfield_4.set_bits(21, 1, value as u64)
    }
    /// `DecodeIoOnBoot`: bits 22..=22 de `bitfield_4`.
    pub const DECODE_IO_ON_BOOT_SHIFT: u32 = 22;
    pub const DECODE_IO_ON_BOOT_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn decode_io_on_boot(&self) -> u32 {
        self.bitfield_4.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_decode_io_on_boot(&self, value: u32) {
        self.bitfield_4.set_bits(22, 1, value as u64)
    }
    /// `Reserved`: bits 23..=31 de `bitfield_4`.
    pub const RESERVED_SHIFT: u32 = 23;
    pub const RESERVED_MASK: u32 = 0xff800000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.bitfield_4.bits(23, 9) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.bitfield_4.set_bits(23, 9, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<DeviceCapabilities>() == 0x40);
    assert!(core::mem::offset_of!(DeviceCapabilities, size) == 0x0);
    assert!(core::mem::offset_of!(DeviceCapabilities, version) == 0x2);
    assert!(core::mem::offset_of!(DeviceCapabilities, bitfield_4) == 0x4);
    assert!(core::mem::offset_of!(DeviceCapabilities, address) == 0x8);
    assert!(core::mem::offset_of!(DeviceCapabilities, ui_number) == 0xc);
    assert!(core::mem::offset_of!(DeviceCapabilities, device_state) == 0x10);
    assert!(core::mem::offset_of!(DeviceCapabilities, system_wake) == 0x2c);
    assert!(core::mem::offset_of!(DeviceCapabilities, device_wake) == 0x30);
    assert!(core::mem::offset_of!(DeviceCapabilities, d1_latency) == 0x34);
    assert!(core::mem::offset_of!(DeviceCapabilities, d2_latency) == 0x38);
    assert!(core::mem::offset_of!(DeviceCapabilities, d3_latency) == 0x3c);
};

/// `_IO_MINI_COMPLETION_PACKET_USER` (0x50 bytes).
#[repr(C)]
pub struct IoMiniCompletionPacketUser {
    pub list_entry: ListEntry,
    pub packet_type: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `void`
    pub key_context: Field<u64>,
    /// -> `void`
    pub apc_context: Field<u64>,
    pub io_status: Field<i32>,
    _pad_2c: Reserved<0x4>,
    pub io_status_information: Field<u64>,
    /// -> `fn`
    pub mini_packet_callback: Field<u64>,
    /// -> `void`
    pub context: Field<u64>,
    pub allocated: Field<u8>,
    _pad_49: Reserved<0x7>,
}

unsafe impl NtStruct for IoMiniCompletionPacketUser {}

const _: () = {
    assert!(core::mem::size_of::<IoMiniCompletionPacketUser>() == 0x50);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, list_entry) == 0x0);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, packet_type) == 0x10);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, key_context) == 0x18);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, apc_context) == 0x20);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, io_status) == 0x28);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, io_status_information) == 0x30);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, mini_packet_callback) == 0x38);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, context) == 0x40);
    assert!(core::mem::offset_of!(IoMiniCompletionPacketUser, allocated) == 0x48);
};

/// `_IO_RESOURCE_DESCRIPTOR` (0x20 bytes).
#[repr(C)]
pub struct IoResourceDescriptor {
    pub option: Field<u8>,
    pub type_: Field<u8>,
    pub share_disposition: Field<u8>,
    pub spare1: Field<u8>,
    pub flags: Field<u16>,
    pub spare2: Field<u16>,
    pub u: IoResourceDescriptorU,
}

unsafe impl NtStruct for IoResourceDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptor>() == 0x20);
    assert!(core::mem::offset_of!(IoResourceDescriptor, option) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptor, type_) == 0x1);
    assert!(core::mem::offset_of!(IoResourceDescriptor, share_disposition) == 0x2);
    assert!(core::mem::offset_of!(IoResourceDescriptor, spare1) == 0x3);
    assert!(core::mem::offset_of!(IoResourceDescriptor, flags) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptor, spare2) == 0x6);
    assert!(core::mem::offset_of!(IoResourceDescriptor, u) == 0x8);
};

/// `_IO_RESOURCE_DESCRIPTOR::u` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IoResourceDescriptorUView1`..`IoResourceDescriptorUView12`, alcançadas por `Deref`.
#[repr(C)]
pub struct IoResourceDescriptorU {
    pub port: IoResourceDescriptorUPort,
}

/// Vista 1 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView1 {
    pub memory: IoResourceDescriptorUPort,
}

/// Vista 2 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView2 {
    pub interrupt: IoResourceDescriptorUInterrupt,
}

/// Vista 3 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView3 {
    _align: [u64; 0],
    pub dma: IoResourceDescriptorUDma,
    _pad_8: Reserved<0x10>,
}

/// Vista 4 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView4 {
    _align: [u64; 0],
    pub dma_v3: IoResourceDescriptorUDmaV3,
    _pad_10: Reserved<0x8>,
}

/// Vista 5 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView5 {
    pub generic: IoResourceDescriptorUPort,
}

/// Vista 6 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView6 {
    _align: [u64; 0],
    pub device_private: CmPartialResourceDescriptorUDevicePrivate,
    _pad_c: Reserved<0xc>,
}

/// Vista 7 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView7 {
    _align: [u64; 0],
    pub bus_number: IoResourceDescriptorUBusNumber,
    _pad_10: Reserved<0x8>,
}

/// Vista 8 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView8 {
    _align: [u64; 0],
    pub config_data: IoResourceDescriptorUConfigData,
    _pad_c: Reserved<0xc>,
}

/// Vista 9 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView9 {
    pub memory40: IoResourceDescriptorUMemory40,
}

/// Vista 10 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView10 {
    pub memory48: IoResourceDescriptorUMemory48,
}

/// Vista 11 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView11 {
    pub memory64: IoResourceDescriptorUMemory64,
}

/// Vista 12 de `_IO_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IoResourceDescriptorUView12 {
    _align: [u64; 0],
    pub connection: CmPartialResourceDescriptorUConnection,
    _pad_c: Reserved<0xc>,
}

impl core::ops::Deref for IoResourceDescriptorU {
    type Target = IoResourceDescriptorUView1;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView1>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView1 {
    type Target = IoResourceDescriptorUView2;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView2>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView2 {
    type Target = IoResourceDescriptorUView3;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView3>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView3 {
    type Target = IoResourceDescriptorUView4;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView4>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView4 {
    type Target = IoResourceDescriptorUView5;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView5>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView5 {
    type Target = IoResourceDescriptorUView6;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView6>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView6 {
    type Target = IoResourceDescriptorUView7;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView7>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView7 {
    type Target = IoResourceDescriptorUView8;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView8 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView8>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView8 {
    type Target = IoResourceDescriptorUView9;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView9 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView9>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView9 {
    type Target = IoResourceDescriptorUView10;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView10 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView10>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView10 {
    type Target = IoResourceDescriptorUView11;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView11 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView11>() }
    }
}

impl core::ops::Deref for IoResourceDescriptorUView11 {
    type Target = IoResourceDescriptorUView12;
    #[inline(always)]
    fn deref(&self) -> &IoResourceDescriptorUView12 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IoResourceDescriptorUView12>() }
    }
}

unsafe impl NtStruct for IoResourceDescriptorU {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorU>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorU, port) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView1>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView1>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView1, memory) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView2>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView2>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView2, interrupt) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView3>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView3>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView3, dma) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView4>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView4>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView4, dma_v3) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView5>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView5>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView5, generic) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView6>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView6>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView6, device_private) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView7>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView7>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView7, bus_number) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView8>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView8>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView8, config_data) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView9>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView9>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView9, memory40) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView10>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView10>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView10, memory48) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView11>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView11>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView11, memory64) == 0x0);
    assert!(core::mem::size_of::<IoResourceDescriptorUView12>() == 0x18);
    assert!(core::mem::align_of::<IoResourceDescriptorUView12>() == core::mem::align_of::<IoResourceDescriptorU>());
    assert!(core::mem::offset_of!(IoResourceDescriptorUView12, connection) == 0x0);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::Port` (0x18 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUPort {
    pub length: Field<u32>,
    pub alignment: Field<u32>,
    pub minimum_address: LargeInteger,
    pub maximum_address: LargeInteger,
}

unsafe impl NtStruct for IoResourceDescriptorUPort {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUPort>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorUPort, length) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUPort, alignment) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUPort, minimum_address) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUPort, maximum_address) == 0x10);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::Interrupt` (0x18 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUInterrupt {
    pub minimum_vector: Field<u32>,
    pub maximum_vector: Field<u32>,
    pub affinity_policy: Field<u16>,
    pub group: Field<u16>,
    pub priority_policy: Field<IrqPriority>,
    pub targeted_processors: Field<u64>,
}

unsafe impl NtStruct for IoResourceDescriptorUInterrupt {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUInterrupt>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, minimum_vector) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, maximum_vector) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, affinity_policy) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, group) == 0xa);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, priority_policy) == 0xc);
    assert!(core::mem::offset_of!(IoResourceDescriptorUInterrupt, targeted_processors) == 0x10);
};

/// `_IRQ_PRIORITY`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct IrqPriority(pub i32);

impl IrqPriority {
    pub const IRQ_PRIORITY_UNDEFINED: Self = Self(0);
    pub const IRQ_PRIORITY_LOW: Self = Self(1);
    pub const IRQ_PRIORITY_NORMAL: Self = Self(2);
    pub const IRQ_PRIORITY_HIGH: Self = Self(3);
}

impl GuestScalar for IrqPriority {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_RESOURCE_DESCRIPTOR::u::Dma` (0x8 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUDma {
    pub minimum_channel: Field<u32>,
    pub maximum_channel: Field<u32>,
}

unsafe impl NtStruct for IoResourceDescriptorUDma {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUDma>() == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDma, minimum_channel) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDma, maximum_channel) == 0x4);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::DmaV3` (0x10 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUDmaV3 {
    pub request_line: Field<u32>,
    pub reserved: Field<u32>,
    pub channel: Field<u32>,
    pub transfer_width: Field<u32>,
}

unsafe impl NtStruct for IoResourceDescriptorUDmaV3 {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUDmaV3>() == 0x10);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDmaV3, request_line) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDmaV3, reserved) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDmaV3, channel) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUDmaV3, transfer_width) == 0xc);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::BusNumber` (0x10 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUBusNumber {
    pub length: Field<u32>,
    pub min_bus_number: Field<u32>,
    pub max_bus_number: Field<u32>,
    pub reserved: Field<u32>,
}

unsafe impl NtStruct for IoResourceDescriptorUBusNumber {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUBusNumber>() == 0x10);
    assert!(core::mem::offset_of!(IoResourceDescriptorUBusNumber, length) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUBusNumber, min_bus_number) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUBusNumber, max_bus_number) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUBusNumber, reserved) == 0xc);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::ConfigData` (0xc bytes).
#[repr(C)]
pub struct IoResourceDescriptorUConfigData {
    pub priority: Field<u32>,
    pub reserved1: Field<u32>,
    pub reserved2: Field<u32>,
}

unsafe impl NtStruct for IoResourceDescriptorUConfigData {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUConfigData>() == 0xc);
    assert!(core::mem::offset_of!(IoResourceDescriptorUConfigData, priority) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUConfigData, reserved1) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUConfigData, reserved2) == 0x8);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::Memory40` (0x18 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUMemory40 {
    pub length40: Field<u32>,
    pub alignment40: Field<u32>,
    pub minimum_address: LargeInteger,
    pub maximum_address: LargeInteger,
}

unsafe impl NtStruct for IoResourceDescriptorUMemory40 {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUMemory40>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory40, length40) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory40, alignment40) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory40, minimum_address) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory40, maximum_address) == 0x10);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::Memory48` (0x18 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUMemory48 {
    pub length48: Field<u32>,
    pub alignment48: Field<u32>,
    pub minimum_address: LargeInteger,
    pub maximum_address: LargeInteger,
}

unsafe impl NtStruct for IoResourceDescriptorUMemory48 {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUMemory48>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory48, length48) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory48, alignment48) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory48, minimum_address) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory48, maximum_address) == 0x10);
};

/// `_IO_RESOURCE_DESCRIPTOR::u::Memory64` (0x18 bytes).
#[repr(C)]
pub struct IoResourceDescriptorUMemory64 {
    pub length64: Field<u32>,
    pub alignment64: Field<u32>,
    pub minimum_address: LargeInteger,
    pub maximum_address: LargeInteger,
}

unsafe impl NtStruct for IoResourceDescriptorUMemory64 {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceDescriptorUMemory64>() == 0x18);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory64, length64) == 0x0);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory64, alignment64) == 0x4);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory64, minimum_address) == 0x8);
    assert!(core::mem::offset_of!(IoResourceDescriptorUMemory64, maximum_address) == 0x10);
};

/// `_FILE_NETWORK_OPEN_INFORMATION` (0x38 bytes).
#[repr(C)]
pub struct FileNetworkOpenInformation {
    pub creation_time: LargeInteger,
    pub last_access_time: LargeInteger,
    pub last_write_time: LargeInteger,
    pub change_time: LargeInteger,
    pub allocation_size: LargeInteger,
    pub end_of_file: LargeInteger,
    pub file_attributes: Field<u32>,
    _pad_34: Reserved<0x4>,
}

unsafe impl NtStruct for FileNetworkOpenInformation {}

const _: () = {
    assert!(core::mem::size_of::<FileNetworkOpenInformation>() == 0x38);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, creation_time) == 0x0);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, last_access_time) == 0x8);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, last_write_time) == 0x10);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, change_time) == 0x18);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, allocation_size) == 0x20);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, end_of_file) == 0x28);
    assert!(core::mem::offset_of!(FileNetworkOpenInformation, file_attributes) == 0x30);
};

/// `_IO_RESOURCE_REQUIREMENTS_LIST` (0x48 bytes).
#[repr(C)]
pub struct IoResourceRequirementsList {
    pub list_size: Field<u32>,
    pub interface_type: Field<InterfaceType>,
    pub bus_number: Field<u32>,
    pub slot_number: Field<u32>,
    pub reserved: [Field<u32>; 3],
    pub alternative_lists: Field<u32>,
    pub list: [IoResourceList; 1],
}

unsafe impl NtStruct for IoResourceRequirementsList {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceRequirementsList>() == 0x48);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, list_size) == 0x0);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, interface_type) == 0x4);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, bus_number) == 0x8);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, slot_number) == 0xc);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, reserved) == 0x10);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, alternative_lists) == 0x1c);
    assert!(core::mem::offset_of!(IoResourceRequirementsList, list) == 0x20);
};

/// `_IO_RESOURCE_LIST` (0x28 bytes).
#[repr(C)]
pub struct IoResourceList {
    pub version: Field<u16>,
    pub revision: Field<u16>,
    pub count: Field<u32>,
    pub descriptors: [IoResourceDescriptor; 1],
}

unsafe impl NtStruct for IoResourceList {}

const _: () = {
    assert!(core::mem::size_of::<IoResourceList>() == 0x28);
    assert!(core::mem::offset_of!(IoResourceList, version) == 0x0);
    assert!(core::mem::offset_of!(IoResourceList, revision) == 0x2);
    assert!(core::mem::offset_of!(IoResourceList, count) == 0x4);
    assert!(core::mem::offset_of!(IoResourceList, descriptors) == 0x8);
};

/// `_IO_REMOVE_LOCK` (0x20 bytes).
#[repr(C)]
pub struct IoRemoveLock {
    pub common: IoRemoveLockCommonBlock,
}

unsafe impl NtStruct for IoRemoveLock {}

const _: () = {
    assert!(core::mem::size_of::<IoRemoveLock>() == 0x20);
    assert!(core::mem::offset_of!(IoRemoveLock, common) == 0x0);
};

/// `_IO_REMOVE_LOCK_COMMON_BLOCK` (0x20 bytes).
#[repr(C)]
pub struct IoRemoveLockCommonBlock {
    pub removed: Field<u8>,
    pub reserved: [Field<u8>; 3],
    pub io_count: Field<i32>,
    pub remove_event: Kevent,
}

unsafe impl NtStruct for IoRemoveLockCommonBlock {}

const _: () = {
    assert!(core::mem::size_of::<IoRemoveLockCommonBlock>() == 0x20);
    assert!(core::mem::offset_of!(IoRemoveLockCommonBlock, removed) == 0x0);
    assert!(core::mem::offset_of!(IoRemoveLockCommonBlock, reserved) == 0x1);
    assert!(core::mem::offset_of!(IoRemoveLockCommonBlock, io_count) == 0x4);
    assert!(core::mem::offset_of!(IoRemoveLockCommonBlock, remove_event) == 0x8);
};

/// `_FAST_IO_DISPATCH` (0xe0 bytes).
#[repr(C)]
pub struct FastIoDispatch {
    pub size_of_fast_io_dispatch: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `fn`
    pub fast_io_check_if_possible: Field<u64>,
    /// -> `fn`
    pub fast_io_read: Field<u64>,
    /// -> `fn`
    pub fast_io_write: Field<u64>,
    /// -> `fn`
    pub fast_io_query_basic_info: Field<u64>,
    /// -> `fn`
    pub fast_io_query_standard_info: Field<u64>,
    /// -> `fn`
    pub fast_io_lock: Field<u64>,
    /// -> `fn`
    pub fast_io_unlock_single: Field<u64>,
    /// -> `fn`
    pub fast_io_unlock_all: Field<u64>,
    /// -> `fn`
    pub fast_io_unlock_all_by_key: Field<u64>,
    /// -> `fn`
    pub fast_io_device_control: Field<u64>,
    /// -> `fn`
    pub acquire_file_for_nt_create_section: Field<u64>,
    /// -> `fn`
    pub release_file_for_nt_create_section: Field<u64>,
    /// -> `fn`
    pub fast_io_detach_device: Field<u64>,
    /// -> `fn`
    pub fast_io_query_network_open_info: Field<u64>,
    /// -> `fn`
    pub acquire_for_mod_write: Field<u64>,
    /// -> `fn`
    pub mdl_read: Field<u64>,
    /// -> `fn`
    pub mdl_read_complete: Field<u64>,
    /// -> `fn`
    pub prepare_mdl_write: Field<u64>,
    /// -> `fn`
    pub mdl_write_complete: Field<u64>,
    /// -> `fn`
    pub fast_io_read_compressed: Field<u64>,
    /// -> `fn`
    pub fast_io_write_compressed: Field<u64>,
    /// -> `fn`
    pub mdl_read_complete_compressed: Field<u64>,
    /// -> `fn`
    pub mdl_write_complete_compressed: Field<u64>,
    /// -> `fn`
    pub fast_io_query_open: Field<u64>,
    /// -> `fn`
    pub release_for_mod_write: Field<u64>,
    /// -> `fn`
    pub acquire_for_cc_flush: Field<u64>,
    /// -> `fn`
    pub release_for_cc_flush: Field<u64>,
}

unsafe impl NtStruct for FastIoDispatch {}

const _: () = {
    assert!(core::mem::size_of::<FastIoDispatch>() == 0xe0);
    assert!(core::mem::offset_of!(FastIoDispatch, size_of_fast_io_dispatch) == 0x0);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_check_if_possible) == 0x8);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_read) == 0x10);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_write) == 0x18);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_query_basic_info) == 0x20);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_query_standard_info) == 0x28);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_lock) == 0x30);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_unlock_single) == 0x38);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_unlock_all) == 0x40);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_unlock_all_by_key) == 0x48);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_device_control) == 0x50);
    assert!(core::mem::offset_of!(FastIoDispatch, acquire_file_for_nt_create_section) == 0x58);
    assert!(core::mem::offset_of!(FastIoDispatch, release_file_for_nt_create_section) == 0x60);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_detach_device) == 0x68);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_query_network_open_info) == 0x70);
    assert!(core::mem::offset_of!(FastIoDispatch, acquire_for_mod_write) == 0x78);
    assert!(core::mem::offset_of!(FastIoDispatch, mdl_read) == 0x80);
    assert!(core::mem::offset_of!(FastIoDispatch, mdl_read_complete) == 0x88);
    assert!(core::mem::offset_of!(FastIoDispatch, prepare_mdl_write) == 0x90);
    assert!(core::mem::offset_of!(FastIoDispatch, mdl_write_complete) == 0x98);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_read_compressed) == 0xa0);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_write_compressed) == 0xa8);
    assert!(core::mem::offset_of!(FastIoDispatch, mdl_read_complete_compressed) == 0xb0);
    assert!(core::mem::offset_of!(FastIoDispatch, mdl_write_complete_compressed) == 0xb8);
    assert!(core::mem::offset_of!(FastIoDispatch, fast_io_query_open) == 0xc0);
    assert!(core::mem::offset_of!(FastIoDispatch, release_for_mod_write) == 0xc8);
    assert!(core::mem::offset_of!(FastIoDispatch, acquire_for_cc_flush) == 0xd0);
    assert!(core::mem::offset_of!(FastIoDispatch, release_for_cc_flush) == 0xd8);
};

/// `_IOP_FILE_OBJECT_EXTENSION` (0x58 bytes).
#[repr(C)]
pub struct IopFileObjectExtension {
    pub fo_ext_flags: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub fo_ext_per_type_extension: [Field<u64>; 9],
    pub fo_io_priority_hint: Field<IopPriorityHint>,
    _pad_54: Reserved<0x4>,
}

unsafe impl NtStruct for IopFileObjectExtension {}

const _: () = {
    assert!(core::mem::size_of::<IopFileObjectExtension>() == 0x58);
    assert!(core::mem::offset_of!(IopFileObjectExtension, fo_ext_flags) == 0x0);
    assert!(core::mem::offset_of!(IopFileObjectExtension, fo_ext_per_type_extension) == 0x8);
    assert!(core::mem::offset_of!(IopFileObjectExtension, fo_io_priority_hint) == 0x50);
};

/// `_IOP_PRIORITY_HINT`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct IopPriorityHint(pub i32);

impl IopPriorityHint {
    pub const IOP_IO_PRIORITY_NOT_SET: Self = Self(0);
    pub const IOP_IO_PRIORITY_VERY_LOW: Self = Self(1);
    pub const IOP_IO_PRIORITY_LOW: Self = Self(2);
    pub const IOP_IO_PRIORITY_NORMAL: Self = Self(3);
    pub const IOP_IO_PRIORITY_HIGH: Self = Self(4);
    pub const IOP_IO_PRIORITY_CRITICAL: Self = Self(5);
    pub const MAX_IOP_IO_PRIORITY_TYPES: Self = Self(6);
}

impl GuestScalar for IopPriorityHint {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_SESSION_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct IoSessionState(pub i32);

impl IoSessionState {
    pub const IO_SESSION_STATE_CREATED: Self = Self(1);
    pub const IO_SESSION_STATE_INITIALIZED: Self = Self(2);
    pub const IO_SESSION_STATE_CONNECTED: Self = Self(3);
    pub const IO_SESSION_STATE_DISCONNECTED: Self = Self(4);
    pub const IO_SESSION_STATE_DISCONNECTED_LOGGED_ON: Self = Self(5);
    pub const IO_SESSION_STATE_LOGGED_ON: Self = Self(6);
    pub const IO_SESSION_STATE_LOGGED_OFF: Self = Self(7);
    pub const IO_SESSION_STATE_TERMINATED: Self = Self(8);
    pub const IO_SESSION_STATE_MAX: Self = Self(9);
}

impl GuestScalar for IoSessionState {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_DEVPROPKEY` (0x14 bytes).
#[repr(C)]
pub struct Devpropkey {
    pub fmtid: Guid,
    pub pid: Field<u32>,
}

unsafe impl NtStruct for Devpropkey {}

const _: () = {
    assert!(core::mem::size_of::<Devpropkey>() == 0x14);
    assert!(core::mem::offset_of!(Devpropkey, fmtid) == 0x0);
    assert!(core::mem::offset_of!(Devpropkey, pid) == 0x10);
};

/// `_FS_FILTER_CALLBACKS` (0x78 bytes).
#[repr(C)]
pub struct FsFilterCallbacks {
    pub size_of_fs_filter_callbacks: Field<u32>,
    pub reserved: Field<u32>,
    /// -> `fn`
    pub pre_acquire_for_section_synchronization: Field<u64>,
    /// -> `fn`
    pub post_acquire_for_section_synchronization: Field<u64>,
    /// -> `fn`
    pub pre_release_for_section_synchronization: Field<u64>,
    /// -> `fn`
    pub post_release_for_section_synchronization: Field<u64>,
    /// -> `fn`
    pub pre_acquire_for_cc_flush: Field<u64>,
    /// -> `fn`
    pub post_acquire_for_cc_flush: Field<u64>,
    /// -> `fn`
    pub pre_release_for_cc_flush: Field<u64>,
    /// -> `fn`
    pub post_release_for_cc_flush: Field<u64>,
    /// -> `fn`
    pub pre_acquire_for_modified_page_writer: Field<u64>,
    /// -> `fn`
    pub post_acquire_for_modified_page_writer: Field<u64>,
    /// -> `fn`
    pub pre_release_for_modified_page_writer: Field<u64>,
    /// -> `fn`
    pub post_release_for_modified_page_writer: Field<u64>,
    /// -> `fn`
    pub pre_query_open: Field<u64>,
    /// -> `fn`
    pub post_query_open: Field<u64>,
}

unsafe impl NtStruct for FsFilterCallbacks {}

const _: () = {
    assert!(core::mem::size_of::<FsFilterCallbacks>() == 0x78);
    assert!(core::mem::offset_of!(FsFilterCallbacks, size_of_fs_filter_callbacks) == 0x0);
    assert!(core::mem::offset_of!(FsFilterCallbacks, reserved) == 0x4);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_acquire_for_section_synchronization) == 0x8);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_acquire_for_section_synchronization) == 0x10);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_release_for_section_synchronization) == 0x18);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_release_for_section_synchronization) == 0x20);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_acquire_for_cc_flush) == 0x28);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_acquire_for_cc_flush) == 0x30);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_release_for_cc_flush) == 0x38);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_release_for_cc_flush) == 0x40);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_acquire_for_modified_page_writer) == 0x48);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_acquire_for_modified_page_writer) == 0x50);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_release_for_modified_page_writer) == 0x58);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_release_for_modified_page_writer) == 0x60);
    assert!(core::mem::offset_of!(FsFilterCallbacks, pre_query_open) == 0x68);
    assert!(core::mem::offset_of!(FsFilterCallbacks, post_query_open) == 0x70);
};

/// `_DEVICE_RELATIONS` (0x10 bytes).
#[repr(C)]
pub struct DeviceRelations {
    pub count: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_DEVICE_OBJECT`
    pub objects: [Field<u64>; 1],
}

unsafe impl NtStruct for DeviceRelations {}

const _: () = {
    assert!(core::mem::size_of::<DeviceRelations>() == 0x10);
    assert!(core::mem::offset_of!(DeviceRelations, count) == 0x0);
    assert!(core::mem::offset_of!(DeviceRelations, objects) == 0x8);
};

/// `_FSRTL_ADVANCED_FCB_HEADER` (0x68 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `FsrtlAdvancedFcbHeaderView1`, alcançada por `Deref`.
#[repr(C)]
pub struct FsrtlAdvancedFcbHeader {
    pub node_type_code: Field<i16>,
    pub node_byte_size: Field<i16>,
    pub flags: Field<u8>,
    pub is_fast_io_possible: Field<u8>,
    pub flags2: Field<u8>,
    pub bitfield_7: Field<u8>,
    /// -> `_ERESOURCE`
    pub resource: Field<u64>,
    /// -> `_ERESOURCE`
    pub paging_io_resource: Field<u64>,
    pub allocation_size: LargeInteger,
    pub file_size: LargeInteger,
    pub valid_data_length: LargeInteger,
    /// -> `_FAST_MUTEX`
    pub fast_mutex: Field<u64>,
    pub filter_contexts: ListEntry,
    pub push_lock: ExPushLock,
    /// -> `void*`
    pub file_context_support_pointer: Field<u64>,
    /// -> `void`
    pub oplock: Field<u64>,
    /// -> `void`
    pub reserved_context: Field<u64>,
}

/// Vista 1 de `_FSRTL_ADVANCED_FCB_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct FsrtlAdvancedFcbHeaderView1 {
    _pad_0: Reserved<0x58>,
    /// -> `void`
    pub reserved_for_remote: Field<u64>,
    _pad_60: Reserved<0x8>,
}

impl core::ops::Deref for FsrtlAdvancedFcbHeader {
    type Target = FsrtlAdvancedFcbHeaderView1;
    #[inline(always)]
    fn deref(&self) -> &FsrtlAdvancedFcbHeaderView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<FsrtlAdvancedFcbHeaderView1>() }
    }
}

unsafe impl NtStruct for FsrtlAdvancedFcbHeader {}

impl FsrtlAdvancedFcbHeader {
    /// `Reserved`: bits 0..=3 de `bitfield_7`.
    pub const RESERVED_SHIFT: u32 = 0;
    pub const RESERVED_MASK: u8 = 0xf;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.bitfield_7.bits(0, 4) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.bitfield_7.set_bits(0, 4, value as u64)
    }
    /// `Version`: bits 4..=7 de `bitfield_7`.
    pub const VERSION_SHIFT: u32 = 4;
    pub const VERSION_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn version(&self) -> u8 {
        self.bitfield_7.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_version(&self, value: u8) {
        self.bitfield_7.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<FsrtlAdvancedFcbHeader>() == 0x68);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, node_type_code) == 0x0);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, node_byte_size) == 0x2);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, flags) == 0x4);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, is_fast_io_possible) == 0x5);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, flags2) == 0x6);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, bitfield_7) == 0x7);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, resource) == 0x8);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, paging_io_resource) == 0x10);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, allocation_size) == 0x18);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, file_size) == 0x20);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, valid_data_length) == 0x28);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, fast_mutex) == 0x30);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, filter_contexts) == 0x38);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, push_lock) == 0x48);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, file_context_support_pointer) == 0x50);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, oplock) == 0x58);
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeader, reserved_context) == 0x60);
    assert!(core::mem::size_of::<FsrtlAdvancedFcbHeaderView1>() == 0x68);
    assert!(core::mem::align_of::<FsrtlAdvancedFcbHeaderView1>() == core::mem::align_of::<FsrtlAdvancedFcbHeader>());
    assert!(core::mem::offset_of!(FsrtlAdvancedFcbHeaderView1, reserved_for_remote) == 0x58);
};

/// `_ECP_LIST` (0x18 bytes).
#[repr(C)]
pub struct EcpList {
    pub signature: Field<u32>,
    pub flags: Field<u32>,
    pub ecp_list: ListEntry,
}

unsafe impl NtStruct for EcpList {}

const _: () = {
    assert!(core::mem::size_of::<EcpList>() == 0x18);
    assert!(core::mem::offset_of!(EcpList, signature) == 0x0);
    assert!(core::mem::offset_of!(EcpList, flags) == 0x4);
    assert!(core::mem::offset_of!(EcpList, ecp_list) == 0x8);
};

/// `_IO_PRIORITY_INFO` (0x10 bytes).
#[repr(C)]
pub struct IoPriorityInfo {
    pub size: Field<u32>,
    pub thread_priority: Field<u32>,
    pub page_priority: Field<u32>,
    pub io_priority: Field<IoPriorityHint>,
}

unsafe impl NtStruct for IoPriorityInfo {}

const _: () = {
    assert!(core::mem::size_of::<IoPriorityInfo>() == 0x10);
    assert!(core::mem::offset_of!(IoPriorityInfo, size) == 0x0);
    assert!(core::mem::offset_of!(IoPriorityInfo, thread_priority) == 0x4);
    assert!(core::mem::offset_of!(IoPriorityInfo, page_priority) == 0x8);
    assert!(core::mem::offset_of!(IoPriorityInfo, io_priority) == 0xc);
};

/// `_IO_PRIORITY_HINT`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct IoPriorityHint(pub i32);

impl IoPriorityHint {
    pub const IO_PRIORITY_VERY_LOW: Self = Self(0);
    pub const IO_PRIORITY_LOW: Self = Self(1);
    pub const IO_PRIORITY_NORMAL: Self = Self(2);
    pub const IO_PRIORITY_HIGH: Self = Self(3);
    pub const IO_PRIORITY_CRITICAL: Self = Self(4);
    pub const MAX_IO_PRIORITY_TYPES: Self = Self(5);
}

impl GuestScalar for IoPriorityHint {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IOP_IRP_EXTENSION` (0x50 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `IopIrpExtensionView1`..`IopIrpExtensionView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct IopIrpExtension {
    pub extension_flags: Field<u16>,
    pub types_allocated: Field<u16>,
    pub generic_extension: [Field<u8>; 4],
    /// -> `void`
    pub verifier_context: Field<u64>,
    pub disk_io_attribution_handle: Field<u64>,
    pub activity_id: Guid,
    pub timestamp: LargeInteger,
    pub fs_tracked_offset: Field<i64>,
    pub driver_flags: IopIrpExtensionDriverFlags,
    pub copy_information: CopyInformation,
}

/// Vista 1 de `_IOP_IRP_EXTENSION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IopIrpExtensionView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x28>,
    pub zeroing_offset: Field<u32>,
    _pad_2c: Reserved<0x24>,
}

/// Vista 2 de `_IOP_IRP_EXTENSION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IopIrpExtensionView2 {
    _pad_0: Reserved<0x28>,
    /// -> `_IO_IRP_EXT_TRACK_OFFSET_HEADER`
    pub fs_track_offset_blob: Field<u64>,
    _pad_30: Reserved<0x20>,
}

/// Vista 3 de `_IOP_IRP_EXTENSION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct IopIrpExtensionView3 {
    _pad_0: Reserved<0x28>,
    pub adapter_crypto_parameters: IoAdapterCryptoParameters,
    _pad_38: Reserved<0x18>,
}

impl core::ops::Deref for IopIrpExtension {
    type Target = IopIrpExtensionView1;
    #[inline(always)]
    fn deref(&self) -> &IopIrpExtensionView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IopIrpExtensionView1>() }
    }
}

impl core::ops::Deref for IopIrpExtensionView1 {
    type Target = IopIrpExtensionView2;
    #[inline(always)]
    fn deref(&self) -> &IopIrpExtensionView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IopIrpExtensionView2>() }
    }
}

impl core::ops::Deref for IopIrpExtensionView2 {
    type Target = IopIrpExtensionView3;
    #[inline(always)]
    fn deref(&self) -> &IopIrpExtensionView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<IopIrpExtensionView3>() }
    }
}

unsafe impl NtStruct for IopIrpExtension {}

impl IopIrpExtension {
    /// `Allocated`: bits 0..=0 de `extension_flags`.
    pub const ALLOCATED_SHIFT: u32 = 0;
    pub const ALLOCATED_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn allocated(&self) -> u16 {
        self.extension_flags.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_allocated(&self, value: u16) {
        self.extension_flags.set_bits(0, 1, value as u64)
    }
    /// `PropagateId`: bits 1..=1 de `extension_flags`.
    pub const PROPAGATE_ID_SHIFT: u32 = 1;
    pub const PROPAGATE_ID_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn propagate_id(&self) -> u16 {
        self.extension_flags.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_propagate_id(&self, value: u16) {
        self.extension_flags.set_bits(1, 1, value as u64)
    }
    /// `SpareBits`: bits 2..=15 de `extension_flags`.
    pub const SPARE_BITS_SHIFT: u32 = 2;
    pub const SPARE_BITS_MASK: u16 = 0xfffc;
    #[inline(always)]
    pub fn spare_bits(&self) -> u16 {
        self.extension_flags.bits(2, 14) as u16
    }
    #[inline(always)]
    pub fn set_spare_bits(&self, value: u16) {
        self.extension_flags.set_bits(2, 14, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<IopIrpExtension>() == 0x50);
    assert!(core::mem::offset_of!(IopIrpExtension, extension_flags) == 0x0);
    assert!(core::mem::offset_of!(IopIrpExtension, types_allocated) == 0x2);
    assert!(core::mem::offset_of!(IopIrpExtension, generic_extension) == 0x4);
    assert!(core::mem::offset_of!(IopIrpExtension, verifier_context) == 0x8);
    assert!(core::mem::offset_of!(IopIrpExtension, disk_io_attribution_handle) == 0x10);
    assert!(core::mem::offset_of!(IopIrpExtension, activity_id) == 0x18);
    assert!(core::mem::offset_of!(IopIrpExtension, timestamp) == 0x28);
    assert!(core::mem::offset_of!(IopIrpExtension, fs_tracked_offset) == 0x30);
    assert!(core::mem::offset_of!(IopIrpExtension, driver_flags) == 0x38);
    assert!(core::mem::offset_of!(IopIrpExtension, copy_information) == 0x40);
    assert!(core::mem::size_of::<IopIrpExtensionView1>() == 0x50);
    assert!(core::mem::align_of::<IopIrpExtensionView1>() == core::mem::align_of::<IopIrpExtension>());
    assert!(core::mem::offset_of!(IopIrpExtensionView1, zeroing_offset) == 0x28);
    assert!(core::mem::size_of::<IopIrpExtensionView2>() == 0x50);
    assert!(core::mem::align_of::<IopIrpExtensionView2>() == core::mem::align_of::<IopIrpExtension>());
    assert!(core::mem::offset_of!(IopIrpExtensionView2, fs_track_offset_blob) == 0x28);
    assert!(core::mem::size_of::<IopIrpExtensionView3>() == 0x50);
    assert!(core::mem::align_of::<IopIrpExtensionView3>() == core::mem::align_of::<IopIrpExtension>());
    assert!(core::mem::offset_of!(IopIrpExtensionView3, adapter_crypto_parameters) == 0x28);
};

/// `_IO_ADAPTER_CRYPTO_PARAMETERS` (0x10 bytes).
#[repr(C)]
pub struct IoAdapterCryptoParameters {
    pub tweak: Field<u64>,
    /// -> `_IO_ADAPTER_CRYPTO_KEY_DESCRIPTOR`
    pub key_descriptor: Field<u64>,
}

unsafe impl NtStruct for IoAdapterCryptoParameters {}

const _: () = {
    assert!(core::mem::size_of::<IoAdapterCryptoParameters>() == 0x10);
    assert!(core::mem::offset_of!(IoAdapterCryptoParameters, tweak) == 0x0);
    assert!(core::mem::offset_of!(IoAdapterCryptoParameters, key_descriptor) == 0x8);
};

/// `_IOP_IRP_EXTENSION::DriverFlags` (0x8 bytes).
#[repr(C)]
pub struct IopIrpExtensionDriverFlags {
    pub value: Field<u64>,
}

unsafe impl NtStruct for IopIrpExtensionDriverFlags {}

impl IopIrpExtensionDriverFlags {
    /// `UserFlags`: bits 0..=31 de `value`.
    pub const USER_FLAGS_SHIFT: u32 = 0;
    pub const USER_FLAGS_MASK: u64 = 0xffffffff;
    #[inline(always)]
    pub fn user_flags(&self) -> u64 {
        self.value.bits(0, 32) as u64
    }
    #[inline(always)]
    pub fn set_user_flags(&self, value: u64) {
        self.value.set_bits(0, 32, value as u64)
    }
    /// `SystemFlags`: bits 32..=47 de `value`.
    pub const SYSTEM_FLAGS_SHIFT: u32 = 32;
    pub const SYSTEM_FLAGS_MASK: u64 = 0xffff00000000;
    #[inline(always)]
    pub fn system_flags(&self) -> u64 {
        self.value.bits(32, 16) as u64
    }
    #[inline(always)]
    pub fn set_system_flags(&self, value: u64) {
        self.value.set_bits(32, 16, value as u64)
    }
    /// `UserFlagsId`: bits 48..=63 de `value`.
    pub const USER_FLAGS_ID_SHIFT: u32 = 48;
    pub const USER_FLAGS_ID_MASK: u64 = 0xffff000000000000;
    #[inline(always)]
    pub fn user_flags_id(&self) -> u64 {
        self.value.bits(48, 16) as u64
    }
    #[inline(always)]
    pub fn set_user_flags_id(&self, value: u64) {
        self.value.set_bits(48, 16, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<IopIrpExtensionDriverFlags>() == 0x8);
    assert!(core::mem::offset_of!(IopIrpExtensionDriverFlags, value) == 0x0);
};

/// `_COPY_INFORMATION` (0x10 bytes).
#[repr(C)]
pub struct CopyInformation {
    /// -> `_FILE_OBJECT`
    pub source_file_object: Field<u64>,
    pub source_file_offset: Field<i64>,
}

unsafe impl NtStruct for CopyInformation {}

const _: () = {
    assert!(core::mem::size_of::<CopyInformation>() == 0x10);
    assert!(core::mem::offset_of!(CopyInformation, source_file_object) == 0x0);
    assert!(core::mem::offset_of!(CopyInformation, source_file_offset) == 0x8);
};

/// `_INTERFACE` (0x20 bytes).
#[repr(C)]
pub struct Interface {
    pub size: Field<u16>,
    pub version: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub context: Field<u64>,
    /// -> `fn`
    pub interface_reference: Field<u64>,
    /// -> `fn`
    pub interface_dereference: Field<u64>,
}

unsafe impl NtStruct for Interface {}

const _: () = {
    assert!(core::mem::size_of::<Interface>() == 0x20);
    assert!(core::mem::offset_of!(Interface, size) == 0x0);
    assert!(core::mem::offset_of!(Interface, version) == 0x2);
    assert!(core::mem::offset_of!(Interface, context) == 0x8);
    assert!(core::mem::offset_of!(Interface, interface_reference) == 0x10);
    assert!(core::mem::offset_of!(Interface, interface_dereference) == 0x18);
};

/// `_DEVICE_DESCRIPTION` (0x40 bytes).
#[repr(C)]
pub struct DeviceDescription {
    pub version: Field<u32>,
    pub master: Field<u8>,
    pub scatter_gather: Field<u8>,
    pub demand_mode: Field<u8>,
    pub auto_initialize: Field<u8>,
    pub dma32_bit_addresses: Field<u8>,
    pub ignore_count: Field<u8>,
    pub reserved1: Field<u8>,
    pub dma64_bit_addresses: Field<u8>,
    pub bus_number: Field<u32>,
    pub dma_channel: Field<u32>,
    pub interface_type: Field<InterfaceType>,
    pub dma_width: Field<DmaWidth>,
    pub dma_speed: Field<DmaSpeed>,
    pub maximum_length: Field<u32>,
    pub dma_port: Field<u32>,
    pub dma_address_width: Field<u32>,
    pub dma_controller_instance: Field<u32>,
    pub dma_request_line: Field<u32>,
    _pad_34: Reserved<0x4>,
    pub device_address: LargeInteger,
}

unsafe impl NtStruct for DeviceDescription {}

const _: () = {
    assert!(core::mem::size_of::<DeviceDescription>() == 0x40);
    assert!(core::mem::offset_of!(DeviceDescription, version) == 0x0);
    assert!(core::mem::offset_of!(DeviceDescription, master) == 0x4);
    assert!(core::mem::offset_of!(DeviceDescription, scatter_gather) == 0x5);
    assert!(core::mem::offset_of!(DeviceDescription, demand_mode) == 0x6);
    assert!(core::mem::offset_of!(DeviceDescription, auto_initialize) == 0x7);
    assert!(core::mem::offset_of!(DeviceDescription, dma32_bit_addresses) == 0x8);
    assert!(core::mem::offset_of!(DeviceDescription, ignore_count) == 0x9);
    assert!(core::mem::offset_of!(DeviceDescription, reserved1) == 0xa);
    assert!(core::mem::offset_of!(DeviceDescription, dma64_bit_addresses) == 0xb);
    assert!(core::mem::offset_of!(DeviceDescription, bus_number) == 0xc);
    assert!(core::mem::offset_of!(DeviceDescription, dma_channel) == 0x10);
    assert!(core::mem::offset_of!(DeviceDescription, interface_type) == 0x14);
    assert!(core::mem::offset_of!(DeviceDescription, dma_width) == 0x18);
    assert!(core::mem::offset_of!(DeviceDescription, dma_speed) == 0x1c);
    assert!(core::mem::offset_of!(DeviceDescription, maximum_length) == 0x20);
    assert!(core::mem::offset_of!(DeviceDescription, dma_port) == 0x24);
    assert!(core::mem::offset_of!(DeviceDescription, dma_address_width) == 0x28);
    assert!(core::mem::offset_of!(DeviceDescription, dma_controller_instance) == 0x2c);
    assert!(core::mem::offset_of!(DeviceDescription, dma_request_line) == 0x30);
    assert!(core::mem::offset_of!(DeviceDescription, device_address) == 0x38);
};

/// `_DMA_WIDTH`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DmaWidth(pub i32);

impl DmaWidth {
    pub const WIDTH8_BITS: Self = Self(0);
    pub const WIDTH16_BITS: Self = Self(1);
    pub const WIDTH32_BITS: Self = Self(2);
    pub const WIDTH64_BITS: Self = Self(3);
    pub const WIDTH_NO_WRAP: Self = Self(4);
    pub const MAXIMUM_DMA_WIDTH: Self = Self(5);
}

impl GuestScalar for DmaWidth {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_DMA_SPEED`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct DmaSpeed(pub i32);

impl DmaSpeed {
    pub const COMPATIBLE: Self = Self(0);
    pub const TYPE_A: Self = Self(1);
    pub const TYPE_B: Self = Self(2);
    pub const TYPE_C: Self = Self(3);
    pub const TYPE_F: Self = Self(4);
    pub const MAXIMUM_DMA_SPEED: Self = Self(5);
}

impl GuestScalar for DmaSpeed {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_IO_SECURITY_CONTEXT` (0x18 bytes).
#[repr(C)]
pub struct IoSecurityContext {
    /// -> `_SECURITY_QUALITY_OF_SERVICE`
    pub security_qos: Field<u64>,
    /// -> `_ACCESS_STATE`
    pub access_state: Field<u64>,
    pub desired_access: Field<u32>,
    pub full_create_options: Field<u32>,
}

unsafe impl NtStruct for IoSecurityContext {}

const _: () = {
    assert!(core::mem::size_of::<IoSecurityContext>() == 0x18);
    assert!(core::mem::offset_of!(IoSecurityContext, security_qos) == 0x0);
    assert!(core::mem::offset_of!(IoSecurityContext, access_state) == 0x8);
    assert!(core::mem::offset_of!(IoSecurityContext, desired_access) == 0x10);
    assert!(core::mem::offset_of!(IoSecurityContext, full_create_options) == 0x14);
};
