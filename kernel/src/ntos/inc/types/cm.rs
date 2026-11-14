//! Cm: listas de recursos e estruturas do registro.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_CM_RESOURCE_LIST` (0x28 bytes).
#[repr(C)]
pub struct CmResourceList {
    pub count: Field<u32>,
    pub list: [CmFullResourceDescriptor; 1],
}

unsafe impl NtStruct for CmResourceList {}

const _: () = {
    assert!(core::mem::size_of::<CmResourceList>() == 0x28);
    assert!(core::mem::offset_of!(CmResourceList, count) == 0x0);
    assert!(core::mem::offset_of!(CmResourceList, list) == 0x4);
};

/// `_CM_FULL_RESOURCE_DESCRIPTOR` (0x24 bytes).
#[repr(C)]
pub struct CmFullResourceDescriptor {
    pub interface_type: Field<InterfaceType>,
    pub bus_number: Field<u32>,
    pub partial_resource_list: CmPartialResourceList,
}

unsafe impl NtStruct for CmFullResourceDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<CmFullResourceDescriptor>() == 0x24);
    assert!(core::mem::offset_of!(CmFullResourceDescriptor, interface_type) == 0x0);
    assert!(core::mem::offset_of!(CmFullResourceDescriptor, bus_number) == 0x4);
    assert!(core::mem::offset_of!(CmFullResourceDescriptor, partial_resource_list) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_LIST` (0x1c bytes).
#[repr(C)]
pub struct CmPartialResourceList {
    pub version: Field<u16>,
    pub revision: Field<u16>,
    pub count: Field<u32>,
    pub partial_descriptors: [CmPartialResourceDescriptor; 1],
}

unsafe impl NtStruct for CmPartialResourceList {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceList>() == 0x1c);
    assert!(core::mem::offset_of!(CmPartialResourceList, version) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceList, revision) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceList, count) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceList, partial_descriptors) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR` (0x14 bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptor {
    pub type_: Field<u8>,
    pub share_disposition: Field<u8>,
    pub flags: Field<u16>,
    pub u: CmPartialResourceDescriptorUUnaligned,
}

unsafe impl NtStruct for CmPartialResourceDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptor>() == 0x14);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptor, share_disposition) == 0x1);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptor, flags) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptor, u) == 0x4);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::DevicePrivate` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUDevicePrivate {
    pub data: [Field<u32>; 3],
}

unsafe impl NtStruct for CmPartialResourceDescriptorUDevicePrivate {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUDevicePrivate>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDevicePrivate, data) == 0x0);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Connection` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUConnection {
    pub class: Field<u8>,
    pub type_: Field<u8>,
    pub reserved1: Field<u8>,
    pub reserved2: Field<u8>,
    pub id_low_part: Field<u32>,
    pub id_high_part: Field<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUConnection {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUConnection>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, class) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, type_) == 0x1);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, reserved1) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, reserved2) == 0x3);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, id_low_part) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnection, id_high_part) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CmPartialResourceDescriptorUUnalignedView1`..`CmPartialResourceDescriptorUUnalignedView13`, alcançadas por `Deref`.
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnaligned {
    pub generic: CmPartialResourceDescriptorUGenericUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 1 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView1 {
    pub port: CmPartialResourceDescriptorUGenericUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 2 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView2 {
    pub interrupt: CmPartialResourceDescriptorUInterruptUnaligned,
}

/// Vista 3 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView3 {
    pub message_interrupt: CmPartialResourceDescriptorUMessageInterruptUnaligned,
}

/// Vista 4 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView4 {
    pub memory: CmPartialResourceDescriptorUGenericUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 5 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView5 {
    pub dma: CmPartialResourceDescriptorUDmaUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 6 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView6 {
    pub dma_v3: CmPartialResourceDescriptorUDmaV3Unaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 7 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView7 {
    pub device_private: CmPartialResourceDescriptorUDevicePrivateUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 8 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView8 {
    pub bus_number: CmPartialResourceDescriptorUBusNumberUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 9 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView9 {
    pub device_specific_data: CmPartialResourceDescriptorUDeviceSpecificDataUnaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 10 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView10 {
    pub memory40: CmPartialResourceDescriptorUMemory40Unaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 11 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView11 {
    pub memory48: CmPartialResourceDescriptorUMemory48Unaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 12 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView12 {
    pub memory64: CmPartialResourceDescriptorUMemory64Unaligned,
    _pad_c: Reserved<0x4>,
}

/// Vista 13 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUUnalignedView13 {
    pub connection: CmPartialResourceDescriptorUConnectionUnaligned,
    _pad_c: Reserved<0x4>,
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnaligned {
    type Target = CmPartialResourceDescriptorUUnalignedView1;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView1>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView1 {
    type Target = CmPartialResourceDescriptorUUnalignedView2;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView2>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView2 {
    type Target = CmPartialResourceDescriptorUUnalignedView3;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView3>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView3 {
    type Target = CmPartialResourceDescriptorUUnalignedView4;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView4>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView4 {
    type Target = CmPartialResourceDescriptorUUnalignedView5;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView5>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView5 {
    type Target = CmPartialResourceDescriptorUUnalignedView6;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView6>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView6 {
    type Target = CmPartialResourceDescriptorUUnalignedView7;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView7>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView7 {
    type Target = CmPartialResourceDescriptorUUnalignedView8;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView8 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView8>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView8 {
    type Target = CmPartialResourceDescriptorUUnalignedView9;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView9 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView9>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView9 {
    type Target = CmPartialResourceDescriptorUUnalignedView10;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView10 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView10>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView10 {
    type Target = CmPartialResourceDescriptorUUnalignedView11;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView11 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView11>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView11 {
    type Target = CmPartialResourceDescriptorUUnalignedView12;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView12 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView12>() }
    }
}

impl core::ops::Deref for CmPartialResourceDescriptorUUnalignedView12 {
    type Target = CmPartialResourceDescriptorUUnalignedView13;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUUnalignedView13 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUUnalignedView13>() }
    }
}

unsafe impl NtStruct for CmPartialResourceDescriptorUUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnaligned>() == 0x10);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnaligned, generic) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView1>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView1>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView1, port) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView2>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView2>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView2, interrupt) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView3>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView3>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView3, message_interrupt) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView4>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView4>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView4, memory) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView5>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView5>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView5, dma) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView6>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView6>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView6, dma_v3) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView7>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView7>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView7, device_private) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView8>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView8>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView8, bus_number) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView9>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView9>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView9, device_specific_data) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView10>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView10>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView10, memory40) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView11>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView11>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView11, memory48) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView12>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView12>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView12, memory64) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUUnalignedView13>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUUnalignedView13>() == core::mem::align_of::<CmPartialResourceDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUUnalignedView13, connection) == 0x0);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Generic` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUGenericUnaligned {
    pub start: LargeIntegerUnaligned,
    pub length: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUGenericUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUGenericUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUGenericUnaligned, start) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUGenericUnaligned, length) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Interrupt` (0x10 bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUInterruptUnaligned {
    pub level: UnalignedField<u16>,
    pub group: UnalignedField<u16>,
    pub vector: UnalignedField<u32>,
    pub affinity: UnalignedField<u64>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUInterruptUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUInterruptUnaligned>() == 0x10);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, level) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, group) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, vector) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUInterruptUnaligned, affinity) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::MessageInterrupt` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CmPartialResourceDescriptorUMessageInterruptUnalignedView1`, alcançada por `Deref`.
#[repr(C)]
pub struct CmPartialResourceDescriptorUMessageInterruptUnaligned {
    pub raw: CmPartialResourceDescriptorUMessageInterruptRawUnaligned,
}

/// Vista 1 de `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::MessageInterrupt` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmPartialResourceDescriptorUMessageInterruptUnalignedView1 {
    pub translated: CmPartialResourceDescriptorUInterruptUnaligned,
}

impl core::ops::Deref for CmPartialResourceDescriptorUMessageInterruptUnaligned {
    type Target = CmPartialResourceDescriptorUMessageInterruptUnalignedView1;
    #[inline(always)]
    fn deref(&self) -> &CmPartialResourceDescriptorUMessageInterruptUnalignedView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmPartialResourceDescriptorUMessageInterruptUnalignedView1>() }
    }
}

unsafe impl NtStruct for CmPartialResourceDescriptorUMessageInterruptUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMessageInterruptUnaligned>() == 0x10);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptUnaligned, raw) == 0x0);
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMessageInterruptUnalignedView1>() == 0x10);
    assert!(core::mem::align_of::<CmPartialResourceDescriptorUMessageInterruptUnalignedView1>() == core::mem::align_of::<CmPartialResourceDescriptorUMessageInterruptUnaligned>());
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptUnalignedView1, translated) == 0x0);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::MessageInterrupt::Raw` (0x10 bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUMessageInterruptRawUnaligned {
    pub group: UnalignedField<u16>,
    pub message_count: UnalignedField<u16>,
    pub vector: UnalignedField<u32>,
    pub affinity: UnalignedField<u64>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUMessageInterruptRawUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMessageInterruptRawUnaligned>() == 0x10);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptRawUnaligned, group) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptRawUnaligned, message_count) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptRawUnaligned, vector) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMessageInterruptRawUnaligned, affinity) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Dma` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUDmaUnaligned {
    pub channel: UnalignedField<u32>,
    pub port: UnalignedField<u32>,
    pub reserved1: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUDmaUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUDmaUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaUnaligned, channel) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaUnaligned, port) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaUnaligned, reserved1) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::DmaV3` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUDmaV3Unaligned {
    pub channel: UnalignedField<u32>,
    pub request_line: UnalignedField<u32>,
    pub transfer_width: UnalignedField<u8>,
    pub reserved1: UnalignedField<u8>,
    pub reserved2: UnalignedField<u8>,
    pub reserved3: UnalignedField<u8>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUDmaV3Unaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUDmaV3Unaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, channel) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, request_line) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, transfer_width) == 0x8);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, reserved1) == 0x9);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, reserved2) == 0xa);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDmaV3Unaligned, reserved3) == 0xb);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::DevicePrivate` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUDevicePrivateUnaligned {
    pub data: [UnalignedField<u32>; 3],
}

unsafe impl NtStruct for CmPartialResourceDescriptorUDevicePrivateUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUDevicePrivateUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDevicePrivateUnaligned, data) == 0x0);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::BusNumber` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUBusNumberUnaligned {
    pub start: UnalignedField<u32>,
    pub length: UnalignedField<u32>,
    pub reserved: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUBusNumberUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUBusNumberUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUBusNumberUnaligned, start) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUBusNumberUnaligned, length) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUBusNumberUnaligned, reserved) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::DeviceSpecificData` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUDeviceSpecificDataUnaligned {
    pub data_size: UnalignedField<u32>,
    pub reserved1: UnalignedField<u32>,
    pub reserved2: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUDeviceSpecificDataUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUDeviceSpecificDataUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDeviceSpecificDataUnaligned, data_size) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDeviceSpecificDataUnaligned, reserved1) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUDeviceSpecificDataUnaligned, reserved2) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Memory40` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUMemory40Unaligned {
    pub start: LargeIntegerUnaligned,
    pub length40: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUMemory40Unaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMemory40Unaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory40Unaligned, start) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory40Unaligned, length40) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Memory48` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUMemory48Unaligned {
    pub start: LargeIntegerUnaligned,
    pub length48: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUMemory48Unaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMemory48Unaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory48Unaligned, start) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory48Unaligned, length48) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Memory64` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUMemory64Unaligned {
    pub start: LargeIntegerUnaligned,
    pub length64: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUMemory64Unaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUMemory64Unaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory64Unaligned, start) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUMemory64Unaligned, length64) == 0x8);
};

/// `_CM_PARTIAL_RESOURCE_DESCRIPTOR::u::Connection` (0xc bytes).
#[repr(C)]
pub struct CmPartialResourceDescriptorUConnectionUnaligned {
    pub class: UnalignedField<u8>,
    pub type_: UnalignedField<u8>,
    pub reserved1: UnalignedField<u8>,
    pub reserved2: UnalignedField<u8>,
    pub id_low_part: UnalignedField<u32>,
    pub id_high_part: UnalignedField<u32>,
}

unsafe impl NtStruct for CmPartialResourceDescriptorUConnectionUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmPartialResourceDescriptorUConnectionUnaligned>() == 0xc);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, class) == 0x0);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, type_) == 0x1);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, reserved1) == 0x2);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, reserved2) == 0x3);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, id_low_part) == 0x4);
    assert!(core::mem::offset_of!(CmPartialResourceDescriptorUConnectionUnaligned, id_high_part) == 0x8);
};

/// `_CM_KEY_BODY` (0x68 bytes).
#[repr(C)]
pub struct CmKeyBody {
    pub type_: Field<u32>,
    pub access_checked_layer_height: Field<u16>,
    _pad_6: Reserved<0x2>,
    /// -> `_CM_KEY_CONTROL_BLOCK`
    pub key_control_block: Field<u64>,
    /// -> `_CM_NOTIFY_BLOCK`
    pub notify_block: Field<u64>,
    /// -> `void`
    pub process_id: Field<u64>,
    pub key_body_list: ListEntry,
    pub bitfield_30: Field<u32>,
    _pad_34: Reserved<0x4>,
    pub trans: CmTransPtr,
    /// -> `_GUID`
    pub ktm_uow: Field<u64>,
    pub context_list_head: ListEntry,
    /// -> `void`
    pub enumeration_resume_context: Field<u64>,
    pub restricted_access_mask: Field<u32>,
    _pad_64: Reserved<0x4>,
}

unsafe impl NtStruct for CmKeyBody {}

impl CmKeyBody {
    /// `Flags`: bits 0..=15 de `bitfield_30`.
    pub const FLAGS_SHIFT: u32 = 0;
    pub const FLAGS_MASK: u32 = 0xffff;
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.bitfield_30.bits(0, 16) as u32
    }
    #[inline(always)]
    pub fn set_flags(&self, value: u32) {
        self.bitfield_30.set_bits(0, 16, value as u64)
    }
    /// `HandleTags`: bits 16..=31 de `bitfield_30`.
    pub const HANDLE_TAGS_SHIFT: u32 = 16;
    pub const HANDLE_TAGS_MASK: u32 = 0xffff0000;
    #[inline(always)]
    pub fn handle_tags(&self) -> u32 {
        self.bitfield_30.bits(16, 16) as u32
    }
    #[inline(always)]
    pub fn set_handle_tags(&self, value: u32) {
        self.bitfield_30.set_bits(16, 16, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<CmKeyBody>() == 0x68);
    assert!(core::mem::offset_of!(CmKeyBody, type_) == 0x0);
    assert!(core::mem::offset_of!(CmKeyBody, access_checked_layer_height) == 0x4);
    assert!(core::mem::offset_of!(CmKeyBody, key_control_block) == 0x8);
    assert!(core::mem::offset_of!(CmKeyBody, notify_block) == 0x10);
    assert!(core::mem::offset_of!(CmKeyBody, process_id) == 0x18);
    assert!(core::mem::offset_of!(CmKeyBody, key_body_list) == 0x20);
    assert!(core::mem::offset_of!(CmKeyBody, bitfield_30) == 0x30);
    assert!(core::mem::offset_of!(CmKeyBody, trans) == 0x38);
    assert!(core::mem::offset_of!(CmKeyBody, ktm_uow) == 0x40);
    assert!(core::mem::offset_of!(CmKeyBody, context_list_head) == 0x48);
    assert!(core::mem::offset_of!(CmKeyBody, enumeration_resume_context) == 0x58);
    assert!(core::mem::offset_of!(CmKeyBody, restricted_access_mask) == 0x60);
};

/// `_CM_TRANS_PTR` (0x8 bytes).
#[repr(C)]
pub struct CmTransPtr {
    /// -> `void`
    pub trans_ptr: Field<u64>,
}

unsafe impl NtStruct for CmTransPtr {}

impl CmTransPtr {
    /// `LightWeight`: bits 0..=0 de `trans_ptr`.
    pub const LIGHT_WEIGHT_SHIFT: u32 = 0;
    pub const LIGHT_WEIGHT_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn light_weight(&self) -> u64 {
        self.trans_ptr.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_light_weight(&self, value: u64) {
        self.trans_ptr.set_bits(0, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<CmTransPtr>() == 0x8);
    assert!(core::mem::offset_of!(CmTransPtr, trans_ptr) == 0x0);
};

/// `_HBASE_BLOCK` (0x1000 bytes).
#[repr(C)]
pub struct HbaseBlock {
    pub signature: Field<u32>,
    pub sequence1: Field<u32>,
    pub sequence2: Field<u32>,
    pub time_stamp: LargeIntegerUnaligned,
    pub major: Field<u32>,
    pub minor: Field<u32>,
    pub type_: Field<u32>,
    pub format: Field<u32>,
    pub root_cell: Field<u32>,
    pub length: Field<u32>,
    pub cluster: Field<u32>,
    pub file_name: [Field<u8>; 64],
    pub rm_id: Guid,
    pub log_id: Guid,
    pub flags: Field<u32>,
    pub tm_id: Guid,
    pub guid_signature: Field<u32>,
    pub last_reorganize_time: Field<u64>,
    pub reserved1: [Field<u32>; 83],
    pub check_sum: Field<u32>,
    pub reserved2: [Field<u32>; 882],
    pub thaw_tm_id: Guid,
    pub thaw_rm_id: Guid,
    pub thaw_log_id: Guid,
    pub boot_type: Field<u32>,
    pub boot_recover: Field<u32>,
}

unsafe impl NtStruct for HbaseBlock {}

const _: () = {
    assert!(core::mem::size_of::<HbaseBlock>() == 0x1000);
    assert!(core::mem::offset_of!(HbaseBlock, signature) == 0x0);
    assert!(core::mem::offset_of!(HbaseBlock, sequence1) == 0x4);
    assert!(core::mem::offset_of!(HbaseBlock, sequence2) == 0x8);
    assert!(core::mem::offset_of!(HbaseBlock, time_stamp) == 0xc);
    assert!(core::mem::offset_of!(HbaseBlock, major) == 0x14);
    assert!(core::mem::offset_of!(HbaseBlock, minor) == 0x18);
    assert!(core::mem::offset_of!(HbaseBlock, type_) == 0x1c);
    assert!(core::mem::offset_of!(HbaseBlock, format) == 0x20);
    assert!(core::mem::offset_of!(HbaseBlock, root_cell) == 0x24);
    assert!(core::mem::offset_of!(HbaseBlock, length) == 0x28);
    assert!(core::mem::offset_of!(HbaseBlock, cluster) == 0x2c);
    assert!(core::mem::offset_of!(HbaseBlock, file_name) == 0x30);
    assert!(core::mem::offset_of!(HbaseBlock, rm_id) == 0x70);
    assert!(core::mem::offset_of!(HbaseBlock, log_id) == 0x80);
    assert!(core::mem::offset_of!(HbaseBlock, flags) == 0x90);
    assert!(core::mem::offset_of!(HbaseBlock, tm_id) == 0x94);
    assert!(core::mem::offset_of!(HbaseBlock, guid_signature) == 0xa4);
    assert!(core::mem::offset_of!(HbaseBlock, last_reorganize_time) == 0xa8);
    assert!(core::mem::offset_of!(HbaseBlock, reserved1) == 0xb0);
    assert!(core::mem::offset_of!(HbaseBlock, check_sum) == 0x1fc);
    assert!(core::mem::offset_of!(HbaseBlock, reserved2) == 0x200);
    assert!(core::mem::offset_of!(HbaseBlock, thaw_tm_id) == 0xfc8);
    assert!(core::mem::offset_of!(HbaseBlock, thaw_rm_id) == 0xfd8);
    assert!(core::mem::offset_of!(HbaseBlock, thaw_log_id) == 0xfe8);
    assert!(core::mem::offset_of!(HbaseBlock, boot_type) == 0xff8);
    assert!(core::mem::offset_of!(HbaseBlock, boot_recover) == 0xffc);
};

/// `_HBIN` (0x20 bytes).
#[repr(C)]
pub struct Hbin {
    pub signature: Field<u32>,
    pub file_offset: Field<u32>,
    pub size: Field<u32>,
    pub reserved1: [Field<u32>; 2],
    pub time_stamp: LargeIntegerUnaligned,
    pub spare: Field<u32>,
}

unsafe impl NtStruct for Hbin {}

const _: () = {
    assert!(core::mem::size_of::<Hbin>() == 0x20);
    assert!(core::mem::offset_of!(Hbin, signature) == 0x0);
    assert!(core::mem::offset_of!(Hbin, file_offset) == 0x4);
    assert!(core::mem::offset_of!(Hbin, size) == 0x8);
    assert!(core::mem::offset_of!(Hbin, reserved1) == 0xc);
    assert!(core::mem::offset_of!(Hbin, time_stamp) == 0x14);
    assert!(core::mem::offset_of!(Hbin, spare) == 0x1c);
};

/// `_CM_KEY_NODE` (0x50 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CmKeyNodeView1`, alcançada por `Deref`.
#[repr(C)]
pub struct CmKeyNode {
    pub signature: Field<u16>,
    pub flags: Field<u16>,
    pub last_write_time: LargeIntegerUnaligned,
    pub access_bits: Field<u8>,
    pub bitfield_d: Field<u8>,
    pub spare2: Field<u16>,
    pub parent: Field<u32>,
    pub sub_key_counts: [Field<u32>; 2],
    pub sub_key_lists: [Field<u32>; 2],
    pub value_list: ChildList,
    pub security: Field<u32>,
    pub class: Field<u32>,
    pub bitfield_34: Field<u32>,
    pub max_class_len: Field<u32>,
    pub max_value_name_len: Field<u32>,
    pub max_value_data_len: Field<u32>,
    pub work_var: Field<u32>,
    pub name_length: Field<u16>,
    pub class_length: Field<u16>,
    pub name: [Field<u16>; 1],
    _pad_4e: Reserved<0x2>,
}

/// Vista 1 de `_CM_KEY_NODE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmKeyNodeView1 {
    _align: [u32; 0],
    _pad_0: Reserved<0x1c>,
    pub child_hive_reference: CmKeyReferenceUnaligned,
    _pad_2c: Reserved<0x24>,
}

impl core::ops::Deref for CmKeyNode {
    type Target = CmKeyNodeView1;
    #[inline(always)]
    fn deref(&self) -> &CmKeyNodeView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmKeyNodeView1>() }
    }
}

unsafe impl NtStruct for CmKeyNode {}

impl CmKeyNode {
    /// `LayerSemantics`: bits 0..=1 de `bitfield_d`.
    pub const LAYER_SEMANTICS_SHIFT: u32 = 0;
    pub const LAYER_SEMANTICS_MASK: u8 = 0x3;
    #[inline(always)]
    pub fn layer_semantics(&self) -> u8 {
        self.bitfield_d.bits(0, 2) as u8
    }
    #[inline(always)]
    pub fn set_layer_semantics(&self, value: u8) {
        self.bitfield_d.set_bits(0, 2, value as u64)
    }
    /// `Spare1`: bits 2..=6 de `bitfield_d`.
    pub const SPARE1_SHIFT: u32 = 2;
    pub const SPARE1_MASK: u8 = 0x7c;
    #[inline(always)]
    pub fn spare1(&self) -> u8 {
        self.bitfield_d.bits(2, 5) as u8
    }
    #[inline(always)]
    pub fn set_spare1(&self, value: u8) {
        self.bitfield_d.set_bits(2, 5, value as u64)
    }
    /// `InheritClass`: bits 7..=7 de `bitfield_d`.
    pub const INHERIT_CLASS_SHIFT: u32 = 7;
    pub const INHERIT_CLASS_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn inherit_class(&self) -> u8 {
        self.bitfield_d.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_inherit_class(&self, value: u8) {
        self.bitfield_d.set_bits(7, 1, value as u64)
    }
    /// `MaxNameLen`: bits 0..=15 de `bitfield_34`.
    pub const MAX_NAME_LEN_SHIFT: u32 = 0;
    pub const MAX_NAME_LEN_MASK: u32 = 0xffff;
    #[inline(always)]
    pub fn max_name_len(&self) -> u32 {
        self.bitfield_34.bits(0, 16) as u32
    }
    #[inline(always)]
    pub fn set_max_name_len(&self, value: u32) {
        self.bitfield_34.set_bits(0, 16, value as u64)
    }
    /// `UserFlags`: bits 16..=19 de `bitfield_34`.
    pub const USER_FLAGS_SHIFT: u32 = 16;
    pub const USER_FLAGS_MASK: u32 = 0xf0000;
    #[inline(always)]
    pub fn user_flags(&self) -> u32 {
        self.bitfield_34.bits(16, 4) as u32
    }
    #[inline(always)]
    pub fn set_user_flags(&self, value: u32) {
        self.bitfield_34.set_bits(16, 4, value as u64)
    }
    /// `VirtControlFlags`: bits 20..=23 de `bitfield_34`.
    pub const VIRT_CONTROL_FLAGS_SHIFT: u32 = 20;
    pub const VIRT_CONTROL_FLAGS_MASK: u32 = 0xf00000;
    #[inline(always)]
    pub fn virt_control_flags(&self) -> u32 {
        self.bitfield_34.bits(20, 4) as u32
    }
    #[inline(always)]
    pub fn set_virt_control_flags(&self, value: u32) {
        self.bitfield_34.set_bits(20, 4, value as u64)
    }
    /// `Debug`: bits 24..=31 de `bitfield_34`.
    pub const DEBUG_SHIFT: u32 = 24;
    pub const DEBUG_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn debug(&self) -> u32 {
        self.bitfield_34.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_debug(&self, value: u32) {
        self.bitfield_34.set_bits(24, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<CmKeyNode>() == 0x50);
    assert!(core::mem::offset_of!(CmKeyNode, signature) == 0x0);
    assert!(core::mem::offset_of!(CmKeyNode, flags) == 0x2);
    assert!(core::mem::offset_of!(CmKeyNode, last_write_time) == 0x4);
    assert!(core::mem::offset_of!(CmKeyNode, access_bits) == 0xc);
    assert!(core::mem::offset_of!(CmKeyNode, bitfield_d) == 0xd);
    assert!(core::mem::offset_of!(CmKeyNode, spare2) == 0xe);
    assert!(core::mem::offset_of!(CmKeyNode, parent) == 0x10);
    assert!(core::mem::offset_of!(CmKeyNode, sub_key_counts) == 0x14);
    assert!(core::mem::offset_of!(CmKeyNode, sub_key_lists) == 0x1c);
    assert!(core::mem::offset_of!(CmKeyNode, value_list) == 0x24);
    assert!(core::mem::offset_of!(CmKeyNode, security) == 0x2c);
    assert!(core::mem::offset_of!(CmKeyNode, class) == 0x30);
    assert!(core::mem::offset_of!(CmKeyNode, bitfield_34) == 0x34);
    assert!(core::mem::offset_of!(CmKeyNode, max_class_len) == 0x38);
    assert!(core::mem::offset_of!(CmKeyNode, max_value_name_len) == 0x3c);
    assert!(core::mem::offset_of!(CmKeyNode, max_value_data_len) == 0x40);
    assert!(core::mem::offset_of!(CmKeyNode, work_var) == 0x44);
    assert!(core::mem::offset_of!(CmKeyNode, name_length) == 0x48);
    assert!(core::mem::offset_of!(CmKeyNode, class_length) == 0x4a);
    assert!(core::mem::offset_of!(CmKeyNode, name) == 0x4c);
    assert!(core::mem::size_of::<CmKeyNodeView1>() == 0x50);
    assert!(core::mem::align_of::<CmKeyNodeView1>() == core::mem::align_of::<CmKeyNode>());
    assert!(core::mem::offset_of!(CmKeyNodeView1, child_hive_reference) == 0x1c);
};

/// `_CHILD_LIST` (0x8 bytes).
#[repr(C)]
pub struct ChildList {
    pub count: Field<u32>,
    pub list: Field<u32>,
}

unsafe impl NtStruct for ChildList {}

const _: () = {
    assert!(core::mem::size_of::<ChildList>() == 0x8);
    assert!(core::mem::offset_of!(ChildList, count) == 0x0);
    assert!(core::mem::offset_of!(ChildList, list) == 0x4);
};

/// `_CM_KEY_REFERENCE` (0x10 bytes).
#[repr(C)]
pub struct CmKeyReferenceUnaligned {
    pub key_cell: UnalignedField<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_HHIVE`
    pub key_hive: UnalignedField<u64>,
}

unsafe impl NtStruct for CmKeyReferenceUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyReferenceUnaligned>() == 0x10);
    assert!(core::mem::offset_of!(CmKeyReferenceUnaligned, key_cell) == 0x0);
    assert!(core::mem::offset_of!(CmKeyReferenceUnaligned, key_hive) == 0x8);
};

/// `_CM_KEY_VALUE` (0x18 bytes).
#[repr(C)]
pub struct CmKeyValue {
    pub signature: Field<u16>,
    pub name_length: Field<u16>,
    pub data_length: Field<u32>,
    pub data: Field<u32>,
    pub type_: Field<u32>,
    pub flags: Field<u16>,
    pub spare: Field<u16>,
    pub name: [Field<u16>; 1],
    _pad_16: Reserved<0x2>,
}

unsafe impl NtStruct for CmKeyValue {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyValue>() == 0x18);
    assert!(core::mem::offset_of!(CmKeyValue, signature) == 0x0);
    assert!(core::mem::offset_of!(CmKeyValue, name_length) == 0x2);
    assert!(core::mem::offset_of!(CmKeyValue, data_length) == 0x4);
    assert!(core::mem::offset_of!(CmKeyValue, data) == 0x8);
    assert!(core::mem::offset_of!(CmKeyValue, type_) == 0xc);
    assert!(core::mem::offset_of!(CmKeyValue, flags) == 0x10);
    assert!(core::mem::offset_of!(CmKeyValue, spare) == 0x12);
    assert!(core::mem::offset_of!(CmKeyValue, name) == 0x14);
};

/// `_CM_KEY_SECURITY` (0x28 bytes).
#[repr(C)]
pub struct CmKeySecurity {
    pub signature: Field<u16>,
    pub reserved: Field<u16>,
    pub flink: Field<u32>,
    pub blink: Field<u32>,
    pub reference_count: Field<u32>,
    pub descriptor_length: Field<u32>,
    pub descriptor: SecurityDescriptorRelative,
}

unsafe impl NtStruct for CmKeySecurity {}

const _: () = {
    assert!(core::mem::size_of::<CmKeySecurity>() == 0x28);
    assert!(core::mem::offset_of!(CmKeySecurity, signature) == 0x0);
    assert!(core::mem::offset_of!(CmKeySecurity, reserved) == 0x2);
    assert!(core::mem::offset_of!(CmKeySecurity, flink) == 0x4);
    assert!(core::mem::offset_of!(CmKeySecurity, blink) == 0x8);
    assert!(core::mem::offset_of!(CmKeySecurity, reference_count) == 0xc);
    assert!(core::mem::offset_of!(CmKeySecurity, descriptor_length) == 0x10);
    assert!(core::mem::offset_of!(CmKeySecurity, descriptor) == 0x14);
};

/// `_CM_KEY_INDEX` (0x8 bytes).
#[repr(C)]
pub struct CmKeyIndex {
    pub signature: Field<u16>,
    pub count: Field<u16>,
    pub list: [Field<u32>; 1],
}

unsafe impl NtStruct for CmKeyIndex {}

const _: () = {
    assert!(core::mem::size_of::<CmKeyIndex>() == 0x8);
    assert!(core::mem::offset_of!(CmKeyIndex, signature) == 0x0);
    assert!(core::mem::offset_of!(CmKeyIndex, count) == 0x2);
    assert!(core::mem::offset_of!(CmKeyIndex, list) == 0x4);
};

/// `_CM_INDEX` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CmIndexView1`, alcançada por `Deref`.
#[repr(C)]
pub struct CmIndex {
    pub cell: Field<u32>,
    pub name_hint: CmFastLeafHint,
}

/// Vista 1 de `_CM_INDEX` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmIndexView1 {
    _pad_0: Reserved<0x4>,
    pub hash_key: CmComponentHash,
}

impl core::ops::Deref for CmIndex {
    type Target = CmIndexView1;
    #[inline(always)]
    fn deref(&self) -> &CmIndexView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmIndexView1>() }
    }
}

unsafe impl NtStruct for CmIndex {}

const _: () = {
    assert!(core::mem::size_of::<CmIndex>() == 0x8);
    assert!(core::mem::offset_of!(CmIndex, cell) == 0x0);
    assert!(core::mem::offset_of!(CmIndex, name_hint) == 0x4);
    assert!(core::mem::size_of::<CmIndexView1>() == 0x8);
    assert!(core::mem::align_of::<CmIndexView1>() == core::mem::align_of::<CmIndex>());
    assert!(core::mem::offset_of!(CmIndexView1, hash_key) == 0x4);
};

/// `_CM_FAST_LEAF_HINT` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `CmFastLeafHintView1`, alcançada por `Deref`.
#[repr(C)]
pub struct CmFastLeafHint {
    _align: [u32; 0],
    pub characters: [Field<u8>; 4],
}

/// Vista 1 de `_CM_FAST_LEAF_HINT` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct CmFastLeafHintView1 {
    pub full_hint: Field<u32>,
}

impl core::ops::Deref for CmFastLeafHint {
    type Target = CmFastLeafHintView1;
    #[inline(always)]
    fn deref(&self) -> &CmFastLeafHintView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<CmFastLeafHintView1>() }
    }
}

unsafe impl NtStruct for CmFastLeafHint {}

const _: () = {
    assert!(core::mem::size_of::<CmFastLeafHint>() == 0x4);
    assert!(core::mem::offset_of!(CmFastLeafHint, characters) == 0x0);
    assert!(core::mem::size_of::<CmFastLeafHintView1>() == 0x4);
    assert!(core::mem::align_of::<CmFastLeafHintView1>() == core::mem::align_of::<CmFastLeafHint>());
    assert!(core::mem::offset_of!(CmFastLeafHintView1, full_hint) == 0x0);
};

/// `_CM_COMPONENT_HASH` (0x4 bytes).
#[repr(C)]
pub struct CmComponentHash {
    pub hash: Field<u32>,
}

unsafe impl NtStruct for CmComponentHash {}

const _: () = {
    assert!(core::mem::size_of::<CmComponentHash>() == 0x4);
    assert!(core::mem::offset_of!(CmComponentHash, hash) == 0x0);
};

/// `_CM_BIG_DATA` (0x8 bytes).
#[repr(C)]
pub struct CmBigData {
    pub signature: Field<u16>,
    pub count: Field<u16>,
    pub list: Field<u32>,
}

unsafe impl NtStruct for CmBigData {}

const _: () = {
    assert!(core::mem::size_of::<CmBigData>() == 0x8);
    assert!(core::mem::offset_of!(CmBigData, signature) == 0x0);
    assert!(core::mem::offset_of!(CmBigData, count) == 0x2);
    assert!(core::mem::offset_of!(CmBigData, list) == 0x4);
};
