//! Demais estruturas alcançadas pelo fecho transitivo.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_ENERGY_STATE_DURATION` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EnergyStateDurationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct EnergyStateDuration {
    pub value: Field<u64>,
}

/// Vista 1 de `_ENERGY_STATE_DURATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EnergyStateDurationView1 {
    _align: [u64; 0],
    pub last_change_time: Field<u32>,
    pub bitfield_4: Field<u32>,
}

impl core::ops::Deref for EnergyStateDuration {
    type Target = EnergyStateDurationView1;
    #[inline(always)]
    fn deref(&self) -> &EnergyStateDurationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EnergyStateDurationView1>() }
    }
}

unsafe impl NtStruct for EnergyStateDuration {}

impl EnergyStateDuration {
    /// `Duration`: bits 0..=30 de `bitfield_4`.
    pub const DURATION_SHIFT: u32 = 0;
    pub const DURATION_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn duration(&self) -> u32 {
        self.bitfield_4.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_duration(&self, value: u32) {
        self.bitfield_4.set_bits(0, 31, value as u64)
    }
    /// `IsInState`: bits 31..=31 de `bitfield_4`.
    pub const IS_IN_STATE_SHIFT: u32 = 31;
    pub const IS_IN_STATE_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn is_in_state(&self) -> u32 {
        self.bitfield_4.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_is_in_state(&self, value: u32) {
        self.bitfield_4.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EnergyStateDuration>() == 0x8);
    assert!(core::mem::offset_of!(EnergyStateDuration, value) == 0x0);
    assert!(core::mem::size_of::<EnergyStateDurationView1>() == 0x8);
    assert!(core::mem::align_of::<EnergyStateDurationView1>() == core::mem::align_of::<EnergyStateDuration>());
    assert!(core::mem::offset_of!(EnergyStateDurationView1, last_change_time) == 0x0);
    assert!(core::mem::offset_of!(EnergyStateDurationView1, bitfield_4) == 0x4);
};

/// `_PCW_REGISTRATION_INFORMATION` (0x30 bytes).
#[repr(C)]
pub struct PcwRegistrationInformation {
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_UNICODE_STRING`
    pub name: Field<u64>,
    pub counter_count: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `_PCW_COUNTER_DESCRIPTOR`
    pub counters: Field<u64>,
    /// -> `fn`
    pub callback: Field<u64>,
    /// -> `void`
    pub callback_context: Field<u64>,
}

unsafe impl NtStruct for PcwRegistrationInformation {}

const _: () = {
    assert!(core::mem::size_of::<PcwRegistrationInformation>() == 0x30);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, version) == 0x0);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, name) == 0x8);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, counter_count) == 0x10);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, counters) == 0x18);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, callback) == 0x20);
    assert!(core::mem::offset_of!(PcwRegistrationInformation, callback_context) == 0x28);
};

/// `_PCW_COUNTER_DESCRIPTOR` (0x8 bytes).
#[repr(C)]
pub struct PcwCounterDescriptor {
    pub id: Field<u16>,
    pub struct_index: Field<u16>,
    pub offset: Field<u16>,
    pub size: Field<u16>,
}

unsafe impl NtStruct for PcwCounterDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<PcwCounterDescriptor>() == 0x8);
    assert!(core::mem::offset_of!(PcwCounterDescriptor, id) == 0x0);
    assert!(core::mem::offset_of!(PcwCounterDescriptor, struct_index) == 0x2);
    assert!(core::mem::offset_of!(PcwCounterDescriptor, offset) == 0x4);
    assert!(core::mem::offset_of!(PcwCounterDescriptor, size) == 0x6);
};

/// `_PCW_CALLBACK_INFORMATION` (0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PcwCallbackInformationView1`..`PcwCallbackInformationView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct PcwCallbackInformation {
    pub add_counter: PcwCounterInformation,
    _pad_10: Reserved<0x18>,
}

/// Vista 1 de `_PCW_CALLBACK_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PcwCallbackInformationView1 {
    pub remove_counter: PcwCounterInformation,
    _pad_10: Reserved<0x18>,
}

/// Vista 2 de `_PCW_CALLBACK_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PcwCallbackInformationView2 {
    pub enumerate_instances: PcwMaskInformation,
}

/// Vista 3 de `_PCW_CALLBACK_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PcwCallbackInformationView3 {
    pub collect_data: PcwMaskInformation,
}

impl core::ops::Deref for PcwCallbackInformation {
    type Target = PcwCallbackInformationView1;
    #[inline(always)]
    fn deref(&self) -> &PcwCallbackInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PcwCallbackInformationView1>() }
    }
}

impl core::ops::Deref for PcwCallbackInformationView1 {
    type Target = PcwCallbackInformationView2;
    #[inline(always)]
    fn deref(&self) -> &PcwCallbackInformationView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PcwCallbackInformationView2>() }
    }
}

impl core::ops::Deref for PcwCallbackInformationView2 {
    type Target = PcwCallbackInformationView3;
    #[inline(always)]
    fn deref(&self) -> &PcwCallbackInformationView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PcwCallbackInformationView3>() }
    }
}

unsafe impl NtStruct for PcwCallbackInformation {}

const _: () = {
    assert!(core::mem::size_of::<PcwCallbackInformation>() == 0x28);
    assert!(core::mem::offset_of!(PcwCallbackInformation, add_counter) == 0x0);
    assert!(core::mem::size_of::<PcwCallbackInformationView1>() == 0x28);
    assert!(core::mem::align_of::<PcwCallbackInformationView1>() == core::mem::align_of::<PcwCallbackInformation>());
    assert!(core::mem::offset_of!(PcwCallbackInformationView1, remove_counter) == 0x0);
    assert!(core::mem::size_of::<PcwCallbackInformationView2>() == 0x28);
    assert!(core::mem::align_of::<PcwCallbackInformationView2>() == core::mem::align_of::<PcwCallbackInformation>());
    assert!(core::mem::offset_of!(PcwCallbackInformationView2, enumerate_instances) == 0x0);
    assert!(core::mem::size_of::<PcwCallbackInformationView3>() == 0x28);
    assert!(core::mem::align_of::<PcwCallbackInformationView3>() == core::mem::align_of::<PcwCallbackInformation>());
    assert!(core::mem::offset_of!(PcwCallbackInformationView3, collect_data) == 0x0);
};

/// `_PCW_COUNTER_INFORMATION` (0x10 bytes).
#[repr(C)]
pub struct PcwCounterInformation {
    pub counter_mask: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub instance_mask: Field<u64>,
}

unsafe impl NtStruct for PcwCounterInformation {}

const _: () = {
    assert!(core::mem::size_of::<PcwCounterInformation>() == 0x10);
    assert!(core::mem::offset_of!(PcwCounterInformation, counter_mask) == 0x0);
    assert!(core::mem::offset_of!(PcwCounterInformation, instance_mask) == 0x8);
};

/// `_PCW_MASK_INFORMATION` (0x28 bytes).
#[repr(C)]
pub struct PcwMaskInformation {
    pub counter_mask: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub instance_mask: Field<u64>,
    pub instance_id: Field<u32>,
    pub collect_multiple: Field<u8>,
    _pad_15: Reserved<0x3>,
    /// -> `_PCW_BUFFER`
    pub buffer: Field<u64>,
    /// -> `_KEVENT`
    pub cancel_event: Field<u64>,
}

unsafe impl NtStruct for PcwMaskInformation {}

const _: () = {
    assert!(core::mem::size_of::<PcwMaskInformation>() == 0x28);
    assert!(core::mem::offset_of!(PcwMaskInformation, counter_mask) == 0x0);
    assert!(core::mem::offset_of!(PcwMaskInformation, instance_mask) == 0x8);
    assert!(core::mem::offset_of!(PcwMaskInformation, instance_id) == 0x10);
    assert!(core::mem::offset_of!(PcwMaskInformation, collect_multiple) == 0x14);
    assert!(core::mem::offset_of!(PcwMaskInformation, buffer) == 0x18);
    assert!(core::mem::offset_of!(PcwMaskInformation, cancel_event) == 0x20);
};

/// `_PCW_DATA` (0x10 bytes).
#[repr(C)]
pub struct PcwData {
    /// -> `void`
    pub data: Field<u64>,
    pub size: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for PcwData {}

const _: () = {
    assert!(core::mem::size_of::<PcwData>() == 0x10);
    assert!(core::mem::offset_of!(PcwData, data) == 0x0);
    assert!(core::mem::offset_of!(PcwData, size) == 0x8);
};
