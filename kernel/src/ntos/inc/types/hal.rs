//! Hal: estruturas do HAL e do WHEA.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_HAL_UNMASKED_INTERRUPT_INFORMATION` (0x20 bytes).
#[repr(C)]
pub struct HalUnmaskedInterruptInformation {
    pub version: Field<u16>,
    pub size: Field<u16>,
    pub flags: HalUnmaskedInterruptFlags,
    _pad_6: Reserved<0x2>,
    pub mode: Field<KinterruptMode>,
    pub polarity: Field<KinterruptPolarity>,
    pub gsiv: Field<u32>,
    pub pin_number: Field<u16>,
    _pad_16: Reserved<0x2>,
    /// -> `void`
    pub device_handle: Field<u64>,
}

unsafe impl NtStruct for HalUnmaskedInterruptInformation {}

const _: () = {
    assert!(core::mem::size_of::<HalUnmaskedInterruptInformation>() == 0x20);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, version) == 0x0);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, size) == 0x2);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, flags) == 0x4);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, mode) == 0x8);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, polarity) == 0xc);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, gsiv) == 0x10);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, pin_number) == 0x14);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptInformation, device_handle) == 0x18);
};

/// `_HAL_UNMASKED_INTERRUPT_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct HalUnmaskedInterruptFlags {
    pub as_ushort: Field<u16>,
}

unsafe impl NtStruct for HalUnmaskedInterruptFlags {}

impl HalUnmaskedInterruptFlags {
    /// `SecondaryInterrupt`: bits 0..=0 de `as_ushort`.
    pub const SECONDARY_INTERRUPT_SHIFT: u32 = 0;
    pub const SECONDARY_INTERRUPT_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn secondary_interrupt(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_secondary_interrupt(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u16 = 0xfffe;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(1, 15) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(1, 15, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HalUnmaskedInterruptFlags>() == 0x2);
    assert!(core::mem::offset_of!(HalUnmaskedInterruptFlags, as_ushort) == 0x0);
};

/// `_HAL_CLOCK_TIMER_CONFIGURATION` (0x20 bytes).
#[repr(C)]
pub struct HalClockTimerConfiguration {
    pub flags: Field<u8>,
    _pad_1: Reserved<0x3>,
    pub known_type: Field<u32>,
    pub capabilities: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub max_increment: Field<u64>,
    pub min_increment: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for HalClockTimerConfiguration {}

impl HalClockTimerConfiguration {
    /// `AlwaysOnTimer`: bits 0..=0 de `flags`.
    pub const ALWAYS_ON_TIMER_SHIFT: u32 = 0;
    pub const ALWAYS_ON_TIMER_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn always_on_timer(&self) -> u8 {
        self.flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_always_on_timer(&self, value: u8) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `HighLatency`: bits 1..=1 de `flags`.
    pub const HIGH_LATENCY_SHIFT: u32 = 1;
    pub const HIGH_LATENCY_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn high_latency(&self) -> u8 {
        self.flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_high_latency(&self, value: u8) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `PerCpuTimer`: bits 2..=2 de `flags`.
    pub const PER_CPU_TIMER_SHIFT: u32 = 2;
    pub const PER_CPU_TIMER_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn per_cpu_timer(&self) -> u8 {
        self.flags.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_per_cpu_timer(&self, value: u8) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `DynamicTickSupported`: bits 3..=3 de `flags`.
    pub const DYNAMIC_TICK_SUPPORTED_SHIFT: u32 = 3;
    pub const DYNAMIC_TICK_SUPPORTED_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn dynamic_tick_supported(&self) -> u8 {
        self.flags.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_dynamic_tick_supported(&self, value: u8) {
        self.flags.set_bits(3, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HalClockTimerConfiguration>() == 0x20);
    assert!(core::mem::offset_of!(HalClockTimerConfiguration, flags) == 0x0);
    assert!(core::mem::offset_of!(HalClockTimerConfiguration, known_type) == 0x4);
    assert!(core::mem::offset_of!(HalClockTimerConfiguration, capabilities) == 0x8);
    assert!(core::mem::offset_of!(HalClockTimerConfiguration, max_increment) == 0x10);
    assert!(core::mem::offset_of!(HalClockTimerConfiguration, min_increment) == 0x18);
};

/// `_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR` (0x48 bytes).
#[repr(C)]
pub struct WheaErrorRecordSectionDescriptor {
    pub section_offset: Field<u32>,
    pub section_length: Field<u32>,
    pub revision: WheaRevision,
    pub valid_bits: WheaErrorRecordSectionDescriptorValidbits,
    pub reserved: Field<u8>,
    pub flags: WheaErrorRecordSectionDescriptorFlags,
    pub section_type: Guid,
    pub fru_id: Guid,
    pub section_severity: Field<WheaErrorSeverity>,
    pub fru_text: [Field<i8>; 20],
}

unsafe impl NtStruct for WheaErrorRecordSectionDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordSectionDescriptor>() == 0x48);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, section_offset) == 0x0);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, section_length) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, revision) == 0x8);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, valid_bits) == 0xa);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, reserved) == 0xb);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, flags) == 0xc);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, section_type) == 0x10);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, fru_id) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, section_severity) == 0x30);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptor, fru_text) == 0x34);
};

/// `_WHEA_REVISION` (0x2 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaRevisionView1`, alcançada por `Deref`.
#[repr(C)]
pub struct WheaRevision {
    _align: [u16; 0],
    pub minor_revision: Field<u8>,
    pub major_revision: Field<u8>,
}

/// Vista 1 de `_WHEA_REVISION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaRevisionView1 {
    pub as_ushort: Field<u16>,
}

impl core::ops::Deref for WheaRevision {
    type Target = WheaRevisionView1;
    #[inline(always)]
    fn deref(&self) -> &WheaRevisionView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaRevisionView1>() }
    }
}

unsafe impl NtStruct for WheaRevision {}

const _: () = {
    assert!(core::mem::size_of::<WheaRevision>() == 0x2);
    assert!(core::mem::offset_of!(WheaRevision, minor_revision) == 0x0);
    assert!(core::mem::offset_of!(WheaRevision, major_revision) == 0x1);
    assert!(core::mem::size_of::<WheaRevisionView1>() == 0x2);
    assert!(core::mem::align_of::<WheaRevisionView1>() == core::mem::align_of::<WheaRevision>());
    assert!(core::mem::offset_of!(WheaRevisionView1, as_ushort) == 0x0);
};

/// `_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_VALIDBITS` (0x1 bytes).
#[repr(C)]
pub struct WheaErrorRecordSectionDescriptorValidbits {
    pub as_uchar: Field<u8>,
}

unsafe impl NtStruct for WheaErrorRecordSectionDescriptorValidbits {}

impl WheaErrorRecordSectionDescriptorValidbits {
    /// `FRUId`: bits 0..=0 de `as_uchar`.
    pub const FRU_ID_SHIFT: u32 = 0;
    pub const FRU_ID_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn fru_id(&self) -> u8 {
        self.as_uchar.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_fru_id(&self, value: u8) {
        self.as_uchar.set_bits(0, 1, value as u64)
    }
    /// `FRUText`: bits 1..=1 de `as_uchar`.
    pub const FRU_TEXT_SHIFT: u32 = 1;
    pub const FRU_TEXT_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn fru_text(&self) -> u8 {
        self.as_uchar.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_fru_text(&self, value: u8) {
        self.as_uchar.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=7 de `as_uchar`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.as_uchar.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.as_uchar.set_bits(2, 6, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordSectionDescriptorValidbits>() == 0x1);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptorValidbits, as_uchar) == 0x0);
};

/// `_WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct WheaErrorRecordSectionDescriptorFlags {
    pub as_ulong: Field<u32>,
}

unsafe impl NtStruct for WheaErrorRecordSectionDescriptorFlags {}

impl WheaErrorRecordSectionDescriptorFlags {
    /// `Primary`: bits 0..=0 de `as_ulong`.
    pub const PRIMARY_SHIFT: u32 = 0;
    pub const PRIMARY_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn primary(&self) -> u32 {
        self.as_ulong.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_primary(&self, value: u32) {
        self.as_ulong.set_bits(0, 1, value as u64)
    }
    /// `ContainmentWarning`: bits 1..=1 de `as_ulong`.
    pub const CONTAINMENT_WARNING_SHIFT: u32 = 1;
    pub const CONTAINMENT_WARNING_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn containment_warning(&self) -> u32 {
        self.as_ulong.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_containment_warning(&self, value: u32) {
        self.as_ulong.set_bits(1, 1, value as u64)
    }
    /// `Reset`: bits 2..=2 de `as_ulong`.
    pub const RESET_SHIFT: u32 = 2;
    pub const RESET_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn reset(&self) -> u32 {
        self.as_ulong.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_reset(&self, value: u32) {
        self.as_ulong.set_bits(2, 1, value as u64)
    }
    /// `ThresholdExceeded`: bits 3..=3 de `as_ulong`.
    pub const THRESHOLD_EXCEEDED_SHIFT: u32 = 3;
    pub const THRESHOLD_EXCEEDED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn threshold_exceeded(&self) -> u32 {
        self.as_ulong.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_threshold_exceeded(&self, value: u32) {
        self.as_ulong.set_bits(3, 1, value as u64)
    }
    /// `ResourceNotAvailable`: bits 4..=4 de `as_ulong`.
    pub const RESOURCE_NOT_AVAILABLE_SHIFT: u32 = 4;
    pub const RESOURCE_NOT_AVAILABLE_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn resource_not_available(&self) -> u32 {
        self.as_ulong.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_resource_not_available(&self, value: u32) {
        self.as_ulong.set_bits(4, 1, value as u64)
    }
    /// `LatentError`: bits 5..=5 de `as_ulong`.
    pub const LATENT_ERROR_SHIFT: u32 = 5;
    pub const LATENT_ERROR_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn latent_error(&self) -> u32 {
        self.as_ulong.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_latent_error(&self, value: u32) {
        self.as_ulong.set_bits(5, 1, value as u64)
    }
    /// `Propagated`: bits 6..=6 de `as_ulong`.
    pub const PROPAGATED_SHIFT: u32 = 6;
    pub const PROPAGATED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn propagated(&self) -> u32 {
        self.as_ulong.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_propagated(&self, value: u32) {
        self.as_ulong.set_bits(6, 1, value as u64)
    }
    /// `Reserved`: bits 7..=31 de `as_ulong`.
    pub const RESERVED_SHIFT: u32 = 7;
    pub const RESERVED_MASK: u32 = 0xffffff80;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.as_ulong.bits(7, 25) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.as_ulong.set_bits(7, 25, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordSectionDescriptorFlags>() == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordSectionDescriptorFlags, as_ulong) == 0x0);
};

/// `_WHEA_ERROR_SEVERITY`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WheaErrorSeverity(pub i32);

impl WheaErrorSeverity {
    pub const WHEA_ERR_SEV_RECOVERABLE: Self = Self(0);
    pub const WHEA_ERR_SEV_FATAL: Self = Self(1);
    pub const WHEA_ERR_SEV_CORRECTED: Self = Self(2);
    pub const WHEA_ERR_SEV_INFORMATIONAL: Self = Self(3);
}

impl GuestScalar for WheaErrorSeverity {
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

/// `_WHEA_PROCESSOR_GENERIC_ERROR_SECTION` (0xc0 bytes).
#[repr(C)]
pub struct WheaProcessorGenericErrorSection {
    pub valid_bits: WheaProcessorGenericErrorSectionValidbits,
    pub processor_type: Field<u8>,
    pub instruction_set: Field<u8>,
    pub error_type: Field<u8>,
    pub operation: Field<u8>,
    pub flags: Field<u8>,
    pub level: Field<u8>,
    pub reserved: Field<u16>,
    pub cpu_version: Field<u64>,
    pub cpu_brand_string: [Field<u8>; 128],
    pub processor_id: Field<u64>,
    pub target_address: Field<u64>,
    pub requester_id: Field<u64>,
    pub responder_id: Field<u64>,
    pub instruction_pointer: Field<u64>,
}

unsafe impl NtStruct for WheaProcessorGenericErrorSection {}

const _: () = {
    assert!(core::mem::size_of::<WheaProcessorGenericErrorSection>() == 0xc0);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, valid_bits) == 0x0);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, processor_type) == 0x8);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, instruction_set) == 0x9);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, error_type) == 0xa);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, operation) == 0xb);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, flags) == 0xc);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, level) == 0xd);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, reserved) == 0xe);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, cpu_version) == 0x10);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, cpu_brand_string) == 0x18);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, processor_id) == 0x98);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, target_address) == 0xa0);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, requester_id) == 0xa8);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, responder_id) == 0xb0);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSection, instruction_pointer) == 0xb8);
};

/// `_WHEA_PROCESSOR_GENERIC_ERROR_SECTION_VALIDBITS` (0x8 bytes).
#[repr(C)]
pub struct WheaProcessorGenericErrorSectionValidbits {
    pub valid_bits: Field<u64>,
}

unsafe impl NtStruct for WheaProcessorGenericErrorSectionValidbits {}

impl WheaProcessorGenericErrorSectionValidbits {
    /// `ProcessorType`: bits 0..=0 de `valid_bits`.
    pub const PROCESSOR_TYPE_SHIFT: u32 = 0;
    pub const PROCESSOR_TYPE_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn processor_type(&self) -> u64 {
        self.valid_bits.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_processor_type(&self, value: u64) {
        self.valid_bits.set_bits(0, 1, value as u64)
    }
    /// `InstructionSet`: bits 1..=1 de `valid_bits`.
    pub const INSTRUCTION_SET_SHIFT: u32 = 1;
    pub const INSTRUCTION_SET_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn instruction_set(&self) -> u64 {
        self.valid_bits.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_instruction_set(&self, value: u64) {
        self.valid_bits.set_bits(1, 1, value as u64)
    }
    /// `ErrorType`: bits 2..=2 de `valid_bits`.
    pub const ERROR_TYPE_SHIFT: u32 = 2;
    pub const ERROR_TYPE_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn error_type(&self) -> u64 {
        self.valid_bits.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_error_type(&self, value: u64) {
        self.valid_bits.set_bits(2, 1, value as u64)
    }
    /// `Operation`: bits 3..=3 de `valid_bits`.
    pub const OPERATION_SHIFT: u32 = 3;
    pub const OPERATION_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn operation(&self) -> u64 {
        self.valid_bits.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_operation(&self, value: u64) {
        self.valid_bits.set_bits(3, 1, value as u64)
    }
    /// `Flags`: bits 4..=4 de `valid_bits`.
    pub const FLAGS_SHIFT: u32 = 4;
    pub const FLAGS_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn flags(&self) -> u64 {
        self.valid_bits.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_flags(&self, value: u64) {
        self.valid_bits.set_bits(4, 1, value as u64)
    }
    /// `Level`: bits 5..=5 de `valid_bits`.
    pub const LEVEL_SHIFT: u32 = 5;
    pub const LEVEL_MASK: u64 = 0x20;
    #[inline(always)]
    pub fn level(&self) -> u64 {
        self.valid_bits.bits(5, 1) as u64
    }
    #[inline(always)]
    pub fn set_level(&self, value: u64) {
        self.valid_bits.set_bits(5, 1, value as u64)
    }
    /// `CPUVersion`: bits 6..=6 de `valid_bits`.
    pub const CPU_VERSION_SHIFT: u32 = 6;
    pub const CPU_VERSION_MASK: u64 = 0x40;
    #[inline(always)]
    pub fn cpu_version(&self) -> u64 {
        self.valid_bits.bits(6, 1) as u64
    }
    #[inline(always)]
    pub fn set_cpu_version(&self, value: u64) {
        self.valid_bits.set_bits(6, 1, value as u64)
    }
    /// `CPUBrandString`: bits 7..=7 de `valid_bits`.
    pub const CPU_BRAND_STRING_SHIFT: u32 = 7;
    pub const CPU_BRAND_STRING_MASK: u64 = 0x80;
    #[inline(always)]
    pub fn cpu_brand_string(&self) -> u64 {
        self.valid_bits.bits(7, 1) as u64
    }
    #[inline(always)]
    pub fn set_cpu_brand_string(&self, value: u64) {
        self.valid_bits.set_bits(7, 1, value as u64)
    }
    /// `ProcessorId`: bits 8..=8 de `valid_bits`.
    pub const PROCESSOR_ID_SHIFT: u32 = 8;
    pub const PROCESSOR_ID_MASK: u64 = 0x100;
    #[inline(always)]
    pub fn processor_id(&self) -> u64 {
        self.valid_bits.bits(8, 1) as u64
    }
    #[inline(always)]
    pub fn set_processor_id(&self, value: u64) {
        self.valid_bits.set_bits(8, 1, value as u64)
    }
    /// `TargetAddress`: bits 9..=9 de `valid_bits`.
    pub const TARGET_ADDRESS_SHIFT: u32 = 9;
    pub const TARGET_ADDRESS_MASK: u64 = 0x200;
    #[inline(always)]
    pub fn target_address(&self) -> u64 {
        self.valid_bits.bits(9, 1) as u64
    }
    #[inline(always)]
    pub fn set_target_address(&self, value: u64) {
        self.valid_bits.set_bits(9, 1, value as u64)
    }
    /// `RequesterId`: bits 10..=10 de `valid_bits`.
    pub const REQUESTER_ID_SHIFT: u32 = 10;
    pub const REQUESTER_ID_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn requester_id(&self) -> u64 {
        self.valid_bits.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_requester_id(&self, value: u64) {
        self.valid_bits.set_bits(10, 1, value as u64)
    }
    /// `ResponderId`: bits 11..=11 de `valid_bits`.
    pub const RESPONDER_ID_SHIFT: u32 = 11;
    pub const RESPONDER_ID_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn responder_id(&self) -> u64 {
        self.valid_bits.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_responder_id(&self, value: u64) {
        self.valid_bits.set_bits(11, 1, value as u64)
    }
    /// `InstructionPointer`: bits 12..=12 de `valid_bits`.
    pub const INSTRUCTION_POINTER_SHIFT: u32 = 12;
    pub const INSTRUCTION_POINTER_MASK: u64 = 0x1000;
    #[inline(always)]
    pub fn instruction_pointer(&self) -> u64 {
        self.valid_bits.bits(12, 1) as u64
    }
    #[inline(always)]
    pub fn set_instruction_pointer(&self, value: u64) {
        self.valid_bits.set_bits(12, 1, value as u64)
    }
    /// `Reserved`: bits 13..=63 de `valid_bits`.
    pub const RESERVED_SHIFT: u32 = 13;
    pub const RESERVED_MASK: u64 = 0xffffffffffffe000;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.valid_bits.bits(13, 51) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.valid_bits.set_bits(13, 51, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaProcessorGenericErrorSectionValidbits>() == 0x8);
    assert!(core::mem::offset_of!(WheaProcessorGenericErrorSectionValidbits, valid_bits) == 0x0);
};

/// `_INTERRUPT_VECTOR_DATA` (0x58 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `InterruptVectorDataView1`..`InterruptVectorDataView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct InterruptVectorData {
    pub type_: Field<InterruptConnectionType>,
    pub vector: Field<u32>,
    pub irql: Field<u8>,
    _pad_9: Reserved<0x3>,
    pub polarity: Field<KinterruptPolarity>,
    pub mode: Field<KinterruptMode>,
    _pad_14: Reserved<0x4>,
    pub target_processors: GroupAffinity,
    pub int_remap_info: InterruptRemappingInfo,
    pub controller_input: InterruptVectorDataControllerInput,
    pub hv_device_id: Field<u64>,
    pub xapic_message: InterruptVectorDataXapicMessage,
}

/// Vista 1 de `_INTERRUPT_VECTOR_DATA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct InterruptVectorDataView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x48>,
    pub hypertransport: InterruptVectorDataHypertransport,
    _pad_50: Reserved<0x8>,
}

/// Vista 2 de `_INTERRUPT_VECTOR_DATA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct InterruptVectorDataView2 {
    _pad_0: Reserved<0x48>,
    pub generic_message: InterruptVectorDataXapicMessage,
}

/// Vista 3 de `_INTERRUPT_VECTOR_DATA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct InterruptVectorDataView3 {
    _align: [u64; 0],
    _pad_0: Reserved<0x48>,
    pub message_request: InterruptVectorDataMessageRequest,
    _pad_4c: Reserved<0xc>,
}

impl core::ops::Deref for InterruptVectorData {
    type Target = InterruptVectorDataView1;
    #[inline(always)]
    fn deref(&self) -> &InterruptVectorDataView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<InterruptVectorDataView1>() }
    }
}

impl core::ops::Deref for InterruptVectorDataView1 {
    type Target = InterruptVectorDataView2;
    #[inline(always)]
    fn deref(&self) -> &InterruptVectorDataView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<InterruptVectorDataView2>() }
    }
}

impl core::ops::Deref for InterruptVectorDataView2 {
    type Target = InterruptVectorDataView3;
    #[inline(always)]
    fn deref(&self) -> &InterruptVectorDataView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<InterruptVectorDataView3>() }
    }
}

unsafe impl NtStruct for InterruptVectorData {}

const _: () = {
    assert!(core::mem::size_of::<InterruptVectorData>() == 0x58);
    assert!(core::mem::offset_of!(InterruptVectorData, type_) == 0x0);
    assert!(core::mem::offset_of!(InterruptVectorData, vector) == 0x4);
    assert!(core::mem::offset_of!(InterruptVectorData, irql) == 0x8);
    assert!(core::mem::offset_of!(InterruptVectorData, polarity) == 0xc);
    assert!(core::mem::offset_of!(InterruptVectorData, mode) == 0x10);
    assert!(core::mem::offset_of!(InterruptVectorData, target_processors) == 0x18);
    assert!(core::mem::offset_of!(InterruptVectorData, int_remap_info) == 0x28);
    assert!(core::mem::offset_of!(InterruptVectorData, controller_input) == 0x38);
    assert!(core::mem::offset_of!(InterruptVectorData, hv_device_id) == 0x40);
    assert!(core::mem::offset_of!(InterruptVectorData, xapic_message) == 0x48);
    assert!(core::mem::size_of::<InterruptVectorDataView1>() == 0x58);
    assert!(core::mem::align_of::<InterruptVectorDataView1>() == core::mem::align_of::<InterruptVectorData>());
    assert!(core::mem::offset_of!(InterruptVectorDataView1, hypertransport) == 0x48);
    assert!(core::mem::size_of::<InterruptVectorDataView2>() == 0x58);
    assert!(core::mem::align_of::<InterruptVectorDataView2>() == core::mem::align_of::<InterruptVectorData>());
    assert!(core::mem::offset_of!(InterruptVectorDataView2, generic_message) == 0x48);
    assert!(core::mem::size_of::<InterruptVectorDataView3>() == 0x58);
    assert!(core::mem::align_of::<InterruptVectorDataView3>() == core::mem::align_of::<InterruptVectorData>());
    assert!(core::mem::offset_of!(InterruptVectorDataView3, message_request) == 0x48);
};

/// `INTERRUPT_CONNECTION_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct InterruptConnectionType(pub i32);

impl InterruptConnectionType {
    pub const INTERRUPT_TYPE_CONTROLLER_INPUT: Self = Self(0);
    pub const INTERRUPT_TYPE_XAPIC_MESSAGE: Self = Self(1);
    pub const INTERRUPT_TYPE_HYPERTRANSPORT: Self = Self(2);
    pub const INTERRUPT_TYPE_MESSAGE_REQUEST: Self = Self(3);
}

impl GuestScalar for InterruptConnectionType {
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

/// `_INTERRUPT_REMAPPING_INFO` (0x10 bytes).
#[repr(C)]
pub struct InterruptRemappingInfo {
    pub bitfield_0: Field<u32>,
    pub u: InterruptRemappingInfoU,
}

unsafe impl NtStruct for InterruptRemappingInfo {}

impl InterruptRemappingInfo {
    /// `IrtIndex`: bits 0..=29 de `bitfield_0`.
    pub const IRT_INDEX_SHIFT: u32 = 0;
    pub const IRT_INDEX_MASK: u32 = 0x3fffffff;
    #[inline(always)]
    pub fn irt_index(&self) -> u32 {
        self.bitfield_0.bits(0, 30) as u32
    }
    #[inline(always)]
    pub fn set_irt_index(&self, value: u32) {
        self.bitfield_0.set_bits(0, 30, value as u64)
    }
    /// `FlagHalInternal`: bits 30..=30 de `bitfield_0`.
    pub const FLAG_HAL_INTERNAL_SHIFT: u32 = 30;
    pub const FLAG_HAL_INTERNAL_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn flag_hal_internal(&self) -> u32 {
        self.bitfield_0.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_flag_hal_internal(&self, value: u32) {
        self.bitfield_0.set_bits(30, 1, value as u64)
    }
    /// `FlagTranslated`: bits 31..=31 de `bitfield_0`.
    pub const FLAG_TRANSLATED_SHIFT: u32 = 31;
    pub const FLAG_TRANSLATED_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn flag_translated(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_flag_translated(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<InterruptRemappingInfo>() == 0x10);
    assert!(core::mem::offset_of!(InterruptRemappingInfo, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(InterruptRemappingInfo, u) == 0x4);
};

/// `_INTERRUPT_REMAPPING_INFO::u` (0xc bytes).
#[repr(C)]
pub struct InterruptRemappingInfoU {
    pub msi: InterruptRemappingInfoUMsi,
}

unsafe impl NtStruct for InterruptRemappingInfoU {}

const _: () = {
    assert!(core::mem::size_of::<InterruptRemappingInfoU>() == 0xc);
    assert!(core::mem::offset_of!(InterruptRemappingInfoU, msi) == 0x0);
};

/// `_INTERRUPT_REMAPPING_INFO::u::Msi` (0xc bytes).
#[repr(C)]
pub struct InterruptRemappingInfoUMsi {
    pub message_address_high: Field<u32>,
    pub message_address_low: Field<u32>,
    pub message_data: Field<u16>,
    pub reserved: Field<u16>,
}

unsafe impl NtStruct for InterruptRemappingInfoUMsi {}

const _: () = {
    assert!(core::mem::size_of::<InterruptRemappingInfoUMsi>() == 0xc);
    assert!(core::mem::offset_of!(InterruptRemappingInfoUMsi, message_address_high) == 0x0);
    assert!(core::mem::offset_of!(InterruptRemappingInfoUMsi, message_address_low) == 0x4);
    assert!(core::mem::offset_of!(InterruptRemappingInfoUMsi, message_data) == 0x8);
    assert!(core::mem::offset_of!(InterruptRemappingInfoUMsi, reserved) == 0xa);
};

/// `_INTERRUPT_VECTOR_DATA::ControllerInput` (0x8 bytes).
#[repr(C)]
pub struct InterruptVectorDataControllerInput {
    pub gsiv: Field<u32>,
    pub bitfield_4: Field<u32>,
}

unsafe impl NtStruct for InterruptVectorDataControllerInput {}

impl InterruptVectorDataControllerInput {
    /// `WakeInterrupt`: bits 0..=0 de `bitfield_4`.
    pub const WAKE_INTERRUPT_SHIFT: u32 = 0;
    pub const WAKE_INTERRUPT_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn wake_interrupt(&self) -> u32 {
        self.bitfield_4.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_interrupt(&self, value: u32) {
        self.bitfield_4.set_bits(0, 1, value as u64)
    }
    /// `ReservedFlags`: bits 1..=31 de `bitfield_4`.
    pub const RESERVED_FLAGS_SHIFT: u32 = 1;
    pub const RESERVED_FLAGS_MASK: u32 = 0xfffffffe;
    #[inline(always)]
    pub fn reserved_flags(&self) -> u32 {
        self.bitfield_4.bits(1, 31) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags(&self, value: u32) {
        self.bitfield_4.set_bits(1, 31, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<InterruptVectorDataControllerInput>() == 0x8);
    assert!(core::mem::offset_of!(InterruptVectorDataControllerInput, gsiv) == 0x0);
    assert!(core::mem::offset_of!(InterruptVectorDataControllerInput, bitfield_4) == 0x4);
};

/// `_INTERRUPT_VECTOR_DATA::XapicMessage` (0x10 bytes).
#[repr(C)]
pub struct InterruptVectorDataXapicMessage {
    pub address: LargeInteger,
    pub data_payload: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for InterruptVectorDataXapicMessage {}

const _: () = {
    assert!(core::mem::size_of::<InterruptVectorDataXapicMessage>() == 0x10);
    assert!(core::mem::offset_of!(InterruptVectorDataXapicMessage, address) == 0x0);
    assert!(core::mem::offset_of!(InterruptVectorDataXapicMessage, data_payload) == 0x8);
};

/// `_INTERRUPT_VECTOR_DATA::Hypertransport` (0x8 bytes).
#[repr(C)]
pub struct InterruptVectorDataHypertransport {
    pub intr_info: InterruptHtIntrInfo,
}

unsafe impl NtStruct for InterruptVectorDataHypertransport {}

const _: () = {
    assert!(core::mem::size_of::<InterruptVectorDataHypertransport>() == 0x8);
    assert!(core::mem::offset_of!(InterruptVectorDataHypertransport, intr_info) == 0x0);
};

/// `_INTERRUPT_HT_INTR_INFO` (0x8 bytes).
#[repr(C)]
pub struct InterruptHtIntrInfo {
    pub low_part: InterruptHtIntrInfoLowPart,
    pub high_part: InterruptHtIntrInfoHighPart,
}

unsafe impl NtStruct for InterruptHtIntrInfo {}

const _: () = {
    assert!(core::mem::size_of::<InterruptHtIntrInfo>() == 0x8);
    assert!(core::mem::offset_of!(InterruptHtIntrInfo, low_part) == 0x0);
    assert!(core::mem::offset_of!(InterruptHtIntrInfo, high_part) == 0x4);
};

/// `_INTERRUPT_HT_INTR_INFO::LowPart` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `InterruptHtIntrInfoLowPartView1`, alcançada por `Deref`.
#[repr(C)]
pub struct InterruptHtIntrInfoLowPart {
    pub bits: InterruptHtIntrInfoLowPartBits,
}

/// Vista 1 de `_INTERRUPT_HT_INTR_INFO::LowPart` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct InterruptHtIntrInfoLowPartView1 {
    pub as_ulong: Field<u32>,
}

impl core::ops::Deref for InterruptHtIntrInfoLowPart {
    type Target = InterruptHtIntrInfoLowPartView1;
    #[inline(always)]
    fn deref(&self) -> &InterruptHtIntrInfoLowPartView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<InterruptHtIntrInfoLowPartView1>() }
    }
}

unsafe impl NtStruct for InterruptHtIntrInfoLowPart {}

const _: () = {
    assert!(core::mem::size_of::<InterruptHtIntrInfoLowPart>() == 0x4);
    assert!(core::mem::offset_of!(InterruptHtIntrInfoLowPart, bits) == 0x0);
    assert!(core::mem::size_of::<InterruptHtIntrInfoLowPartView1>() == 0x4);
    assert!(core::mem::align_of::<InterruptHtIntrInfoLowPartView1>() == core::mem::align_of::<InterruptHtIntrInfoLowPart>());
    assert!(core::mem::offset_of!(InterruptHtIntrInfoLowPartView1, as_ulong) == 0x0);
};

/// `_INTERRUPT_HT_INTR_INFO::LowPart::bits` (0x4 bytes).
#[repr(C)]
pub struct InterruptHtIntrInfoLowPartBits {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for InterruptHtIntrInfoLowPartBits {}

impl InterruptHtIntrInfoLowPartBits {
    /// `Mask`: bits 0..=0 de `bitfield_0`.
    pub const MASK_SHIFT: u32 = 0;
    pub const MASK_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn mask(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_mask(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Polarity`: bits 1..=1 de `bitfield_0`.
    pub const POLARITY_SHIFT: u32 = 1;
    pub const POLARITY_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn polarity(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_polarity(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `MessageType`: bits 2..=4 de `bitfield_0`.
    pub const MESSAGE_TYPE_SHIFT: u32 = 2;
    pub const MESSAGE_TYPE_MASK: u32 = 0x1c;
    #[inline(always)]
    pub fn message_type(&self) -> u32 {
        self.bitfield_0.bits(2, 3) as u32
    }
    #[inline(always)]
    pub fn set_message_type(&self, value: u32) {
        self.bitfield_0.set_bits(2, 3, value as u64)
    }
    /// `RequestEOI`: bits 5..=5 de `bitfield_0`.
    pub const REQUEST_EOI_SHIFT: u32 = 5;
    pub const REQUEST_EOI_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn request_eoi(&self) -> u32 {
        self.bitfield_0.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_request_eoi(&self, value: u32) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `DestinationMode`: bits 6..=6 de `bitfield_0`.
    pub const DESTINATION_MODE_SHIFT: u32 = 6;
    pub const DESTINATION_MODE_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn destination_mode(&self) -> u32 {
        self.bitfield_0.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_destination_mode(&self, value: u32) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `MessageType3`: bits 7..=7 de `bitfield_0`.
    pub const MESSAGE_TYPE3_SHIFT: u32 = 7;
    pub const MESSAGE_TYPE3_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn message_type3(&self) -> u32 {
        self.bitfield_0.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_message_type3(&self, value: u32) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `Destination`: bits 8..=15 de `bitfield_0`.
    pub const DESTINATION_SHIFT: u32 = 8;
    pub const DESTINATION_MASK: u32 = 0xff00;
    #[inline(always)]
    pub fn destination(&self) -> u32 {
        self.bitfield_0.bits(8, 8) as u32
    }
    #[inline(always)]
    pub fn set_destination(&self, value: u32) {
        self.bitfield_0.set_bits(8, 8, value as u64)
    }
    /// `Vector`: bits 16..=23 de `bitfield_0`.
    pub const VECTOR_SHIFT: u32 = 16;
    pub const VECTOR_MASK: u32 = 0xff0000;
    #[inline(always)]
    pub fn vector(&self) -> u32 {
        self.bitfield_0.bits(16, 8) as u32
    }
    #[inline(always)]
    pub fn set_vector(&self, value: u32) {
        self.bitfield_0.set_bits(16, 8, value as u64)
    }
    /// `ExtendedAddress`: bits 24..=31 de `bitfield_0`.
    pub const EXTENDED_ADDRESS_SHIFT: u32 = 24;
    pub const EXTENDED_ADDRESS_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn extended_address(&self) -> u32 {
        self.bitfield_0.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_extended_address(&self, value: u32) {
        self.bitfield_0.set_bits(24, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<InterruptHtIntrInfoLowPartBits>() == 0x4);
    assert!(core::mem::offset_of!(InterruptHtIntrInfoLowPartBits, bitfield_0) == 0x0);
};

/// `_INTERRUPT_HT_INTR_INFO::HighPart` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `InterruptHtIntrInfoHighPartView1`, alcançada por `Deref`.
#[repr(C)]
pub struct InterruptHtIntrInfoHighPart {
    pub bits: InterruptHtIntrInfoHighPartBits,
}

/// Vista 1 de `_INTERRUPT_HT_INTR_INFO::HighPart` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct InterruptHtIntrInfoHighPartView1 {
    pub as_ulong: Field<u32>,
}

impl core::ops::Deref for InterruptHtIntrInfoHighPart {
    type Target = InterruptHtIntrInfoHighPartView1;
    #[inline(always)]
    fn deref(&self) -> &InterruptHtIntrInfoHighPartView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<InterruptHtIntrInfoHighPartView1>() }
    }
}

unsafe impl NtStruct for InterruptHtIntrInfoHighPart {}

const _: () = {
    assert!(core::mem::size_of::<InterruptHtIntrInfoHighPart>() == 0x4);
    assert!(core::mem::offset_of!(InterruptHtIntrInfoHighPart, bits) == 0x0);
    assert!(core::mem::size_of::<InterruptHtIntrInfoHighPartView1>() == 0x4);
    assert!(core::mem::align_of::<InterruptHtIntrInfoHighPartView1>() == core::mem::align_of::<InterruptHtIntrInfoHighPart>());
    assert!(core::mem::offset_of!(InterruptHtIntrInfoHighPartView1, as_ulong) == 0x0);
};

/// `_INTERRUPT_HT_INTR_INFO::HighPart::bits` (0x4 bytes).
#[repr(C)]
pub struct InterruptHtIntrInfoHighPartBits {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for InterruptHtIntrInfoHighPartBits {}

impl InterruptHtIntrInfoHighPartBits {
    /// `ExtendedDestination`: bits 0..=23 de `bitfield_0`.
    pub const EXTENDED_DESTINATION_SHIFT: u32 = 0;
    pub const EXTENDED_DESTINATION_MASK: u32 = 0xffffff;
    #[inline(always)]
    pub fn extended_destination(&self) -> u32 {
        self.bitfield_0.bits(0, 24) as u32
    }
    #[inline(always)]
    pub fn set_extended_destination(&self, value: u32) {
        self.bitfield_0.set_bits(0, 24, value as u64)
    }
    /// `Reserved`: bits 24..=29 de `bitfield_0`.
    pub const RESERVED_SHIFT: u32 = 24;
    pub const RESERVED_MASK: u32 = 0x3f000000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.bitfield_0.bits(24, 6) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.bitfield_0.set_bits(24, 6, value as u64)
    }
    /// `PassPW`: bits 30..=30 de `bitfield_0`.
    pub const PASS_PW_SHIFT: u32 = 30;
    pub const PASS_PW_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn pass_pw(&self) -> u32 {
        self.bitfield_0.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_pass_pw(&self, value: u32) {
        self.bitfield_0.set_bits(30, 1, value as u64)
    }
    /// `WaitingForEOI`: bits 31..=31 de `bitfield_0`.
    pub const WAITING_FOR_EOI_SHIFT: u32 = 31;
    pub const WAITING_FOR_EOI_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn waiting_for_eoi(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_waiting_for_eoi(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<InterruptHtIntrInfoHighPartBits>() == 0x4);
    assert!(core::mem::offset_of!(InterruptHtIntrInfoHighPartBits, bitfield_0) == 0x0);
};

/// `_INTERRUPT_VECTOR_DATA::MessageRequest` (0x4 bytes).
#[repr(C)]
pub struct InterruptVectorDataMessageRequest {
    pub destination_mode: Field<HalApicDestinationMode>,
}

unsafe impl NtStruct for InterruptVectorDataMessageRequest {}

const _: () = {
    assert!(core::mem::size_of::<InterruptVectorDataMessageRequest>() == 0x4);
    assert!(core::mem::offset_of!(InterruptVectorDataMessageRequest, destination_mode) == 0x0);
};

/// `HAL_APIC_DESTINATION_MODE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct HalApicDestinationMode(pub i32);

impl HalApicDestinationMode {
    pub const APIC_DESTINATION_MODE_PHYSICAL: Self = Self(1);
    pub const APIC_DESTINATION_MODE_LOGICAL_FLAT: Self = Self(2);
    pub const APIC_DESTINATION_MODE_LOGICAL_CLUSTERED: Self = Self(3);
    pub const APIC_DESTINATION_MODE_UNKNOWN: Self = Self(4);
}

impl GuestScalar for HalApicDestinationMode {
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

/// `_HAL_INTEL_ENLIGHTENMENT_INFORMATION` (0x1f8 bytes).
#[repr(C)]
pub struct HalIntelEnlightenmentInformation {
    pub enlightenments: Field<u32>,
    pub hypervisor_connected: Field<u32>,
    /// -> `fn`
    pub end_of_interrupt: Field<u64>,
    /// -> `fn`
    pub apic_write_icr: Field<u64>,
    pub reserved0: Field<u32>,
    pub spin_count_mask: Field<u32>,
    /// -> `fn`
    pub long_spin_wait: Field<u64>,
    /// -> `fn`
    pub get_reference_time: Field<u64>,
    /// -> `fn`
    pub set_system_sleep_property: Field<u64>,
    /// -> `fn`
    pub enter_sleep_state: Field<u64>,
    /// -> `fn`
    pub notify_debug_device_available: Field<u64>,
    /// -> `fn`
    pub map_device_interrupt: Field<u64>,
    /// -> `fn`
    pub unmap_device_interrupt: Field<u64>,
    /// -> `fn`
    pub retarget_device_interrupt: Field<u64>,
    /// -> `fn`
    pub set_hpet_config: Field<u64>,
    /// -> `fn`
    pub notify_hpet_enabled: Field<u64>,
    /// -> `fn`
    pub query_associated_processors: Field<u64>,
    /// -> `fn`
    pub read_multiple_msr: Field<u64>,
    /// -> `fn`
    pub write_multiple_msr: Field<u64>,
    /// -> `fn`
    pub read_cpuid: Field<u64>,
    /// -> `fn`
    pub lp_writeback_invalidate: Field<u64>,
    /// -> `fn`
    pub get_machine_check_context: Field<u64>,
    /// -> `fn`
    pub suspend_partition: Field<u64>,
    /// -> `fn`
    pub resume_partition: Field<u64>,
    /// -> `fn`
    pub set_system_machine_check_property: Field<u64>,
    /// -> `fn`
    pub whea_error_notification: Field<u64>,
    /// -> `fn`
    pub get_processor_index_from_vp_index: Field<u64>,
    /// -> `fn`
    pub synthetic_cluster_ipi: Field<u64>,
    /// -> `fn`
    pub vp_start_enabled: Field<u64>,
    /// -> `fn`
    pub start_virtual_processor: Field<u64>,
    /// -> `fn`
    pub get_vp_index_from_apic_id: Field<u64>,
    /// -> `fn`
    pub ium_access_pci_device: Field<u64>,
    /// -> `fn`
    pub ium_efi_runtime_service: Field<u64>,
    /// -> `fn`
    pub svm_get_system_capabilities: Field<u64>,
    /// -> `fn`
    pub svm_get_device_capabilities: Field<u64>,
    /// -> `fn`
    pub svm_create_pasid_space: Field<u64>,
    /// -> `fn`
    pub svm_set_pasid_address_space: Field<u64>,
    /// -> `fn`
    pub svm_flush_pasid: Field<u64>,
    /// -> `fn`
    pub svm_attach_pasid_space: Field<u64>,
    /// -> `fn`
    pub svm_detach_pasid_space: Field<u64>,
    /// -> `fn`
    pub svm_enable_pasid: Field<u64>,
    /// -> `fn`
    pub svm_disable_pasid: Field<u64>,
    /// -> `fn`
    pub svm_acknowledge_page_request: Field<u64>,
    /// -> `fn`
    pub svm_create_pr_queue: Field<u64>,
    /// -> `fn`
    pub svm_delete_pr_queue: Field<u64>,
    /// -> `fn`
    pub svm_clear_prq_stalled: Field<u64>,
    /// -> `fn`
    pub svm_set_device_enabled: Field<u64>,
    /// -> `fn`
    pub hv_debugger_power_handler: Field<u64>,
    /// -> `fn`
    pub set_qpc_bias: Field<u64>,
    /// -> `fn`
    pub get_qpc_bias: Field<u64>,
    /// -> `fn`
    pub register_device_id: Field<u64>,
    /// -> `fn`
    pub unregister_device_id: Field<u64>,
    /// -> `fn`
    pub allocate_device_domain: Field<u64>,
    /// -> `fn`
    pub attach_device_domain: Field<u64>,
    /// -> `fn`
    pub detach_device_domain: Field<u64>,
    /// -> `fn`
    pub delete_device_domain: Field<u64>,
    /// -> `fn`
    pub map_device_logical_range: Field<u64>,
    /// -> `fn`
    pub unmap_device_logical_range: Field<u64>,
    /// -> `fn`
    pub map_device_sparse_pages: Field<u64>,
    /// -> `fn`
    pub unmap_device_sparse_pages: Field<u64>,
    /// -> `fn`
    pub get_dma_guard_enabled: Field<u64>,
    /// -> `fn`
    pub update_microcode: Field<u64>,
    /// -> `fn`
    pub get_sint_message: Field<u64>,
    /// -> `fn`
    pub restore_time: Field<u64>,
    /// -> `fn`
    pub set_root_fault_reporting_ready: Field<u64>,
}

unsafe impl NtStruct for HalIntelEnlightenmentInformation {}

const _: () = {
    assert!(core::mem::size_of::<HalIntelEnlightenmentInformation>() == 0x1f8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, enlightenments) == 0x0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, hypervisor_connected) == 0x4);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, end_of_interrupt) == 0x8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, apic_write_icr) == 0x10);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, reserved0) == 0x18);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, spin_count_mask) == 0x1c);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, long_spin_wait) == 0x20);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_reference_time) == 0x28);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, set_system_sleep_property) == 0x30);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, enter_sleep_state) == 0x38);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, notify_debug_device_available) == 0x40);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, map_device_interrupt) == 0x48);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, unmap_device_interrupt) == 0x50);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, retarget_device_interrupt) == 0x58);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, set_hpet_config) == 0x60);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, notify_hpet_enabled) == 0x68);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, query_associated_processors) == 0x70);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, read_multiple_msr) == 0x78);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, write_multiple_msr) == 0x80);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, read_cpuid) == 0x88);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, lp_writeback_invalidate) == 0x90);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_machine_check_context) == 0x98);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, suspend_partition) == 0xa0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, resume_partition) == 0xa8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, set_system_machine_check_property) == 0xb0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, whea_error_notification) == 0xb8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_processor_index_from_vp_index) == 0xc0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, synthetic_cluster_ipi) == 0xc8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, vp_start_enabled) == 0xd0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, start_virtual_processor) == 0xd8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_vp_index_from_apic_id) == 0xe0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, ium_access_pci_device) == 0xe8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, ium_efi_runtime_service) == 0xf0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_get_system_capabilities) == 0xf8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_get_device_capabilities) == 0x100);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_create_pasid_space) == 0x108);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_set_pasid_address_space) == 0x110);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_flush_pasid) == 0x118);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_attach_pasid_space) == 0x120);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_detach_pasid_space) == 0x128);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_enable_pasid) == 0x130);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_disable_pasid) == 0x138);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_acknowledge_page_request) == 0x140);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_create_pr_queue) == 0x148);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_delete_pr_queue) == 0x150);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_clear_prq_stalled) == 0x158);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, svm_set_device_enabled) == 0x160);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, hv_debugger_power_handler) == 0x168);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, set_qpc_bias) == 0x170);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_qpc_bias) == 0x178);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, register_device_id) == 0x180);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, unregister_device_id) == 0x188);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, allocate_device_domain) == 0x190);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, attach_device_domain) == 0x198);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, detach_device_domain) == 0x1a0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, delete_device_domain) == 0x1a8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, map_device_logical_range) == 0x1b0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, unmap_device_logical_range) == 0x1b8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, map_device_sparse_pages) == 0x1c0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, unmap_device_sparse_pages) == 0x1c8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_dma_guard_enabled) == 0x1d0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, update_microcode) == 0x1d8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, get_sint_message) == 0x1e0);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, restore_time) == 0x1e8);
    assert!(core::mem::offset_of!(HalIntelEnlightenmentInformation, set_root_fault_reporting_ready) == 0x1f0);
};

/// `_HAL_IOMMU_DISPATCH` (0x98 bytes).
#[repr(C)]
pub struct HalIommuDispatch {
    /// -> `fn`
    pub hal_iommu_support_enabled: Field<u64>,
    /// -> `fn`
    pub hal_iommu_get_configuration: Field<u64>,
    /// -> `fn`
    pub hal_iommu_get_library_context: Field<u64>,
    /// -> `fn`
    pub hal_iommu_map_device: Field<u64>,
    /// -> `fn`
    pub hal_iommu_enable_device_pasid: Field<u64>,
    /// -> `fn`
    pub hal_iommu_set_address_space: Field<u64>,
    /// -> `fn`
    pub hal_iommu_disable_device_pasid: Field<u64>,
    /// -> `fn`
    pub hal_iommu_unmap_device: Field<u64>,
    /// -> `fn`
    pub hal_iommu_free_library_context: Field<u64>,
    /// -> `fn`
    pub hal_iommu_flush_tb: Field<u64>,
    /// -> `fn`
    pub hal_iommu_flush_all_pasid: Field<u64>,
    /// -> `fn`
    pub hal_iommu_process_page_request_queue: Field<u64>,
    /// -> `fn`
    pub hal_iommu_fault_routine: Field<u64>,
    /// -> `fn`
    pub hal_iommu_reference_asid: Field<u64>,
    /// -> `fn`
    pub hal_iommu_dereference_asid: Field<u64>,
    /// -> `fn`
    pub hal_iommu_service_page_fault: Field<u64>,
    /// -> `fn`
    pub hal_iommu_device_power_change: Field<u64>,
    /// -> `fn`
    pub hal_iommu_begin_device_reset: Field<u64>,
    /// -> `fn`
    pub hal_iommu_finalize_device_reset: Field<u64>,
}

unsafe impl NtStruct for HalIommuDispatch {}

const _: () = {
    assert!(core::mem::size_of::<HalIommuDispatch>() == 0x98);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_support_enabled) == 0x0);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_get_configuration) == 0x8);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_get_library_context) == 0x10);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_map_device) == 0x18);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_enable_device_pasid) == 0x20);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_set_address_space) == 0x28);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_disable_device_pasid) == 0x30);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_unmap_device) == 0x38);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_free_library_context) == 0x40);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_flush_tb) == 0x48);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_flush_all_pasid) == 0x50);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_process_page_request_queue) == 0x58);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_fault_routine) == 0x60);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_reference_asid) == 0x68);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_dereference_asid) == 0x70);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_service_page_fault) == 0x78);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_device_power_change) == 0x80);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_begin_device_reset) == 0x88);
    assert!(core::mem::offset_of!(HalIommuDispatch, hal_iommu_finalize_device_reset) == 0x90);
};

/// `HAL_PRIVATE_DISPATCH` (0x4b0 bytes).
#[repr(C)]
pub struct HalPrivateDispatch {
    pub version: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `fn`
    pub hal_handler_for_bus: Field<u64>,
    /// -> `fn`
    pub hal_handler_for_config_space: Field<u64>,
    /// -> `fn`
    pub hal_locate_hiber_ranges: Field<u64>,
    /// -> `fn`
    pub hal_register_bus_handler: Field<u64>,
    /// -> `fn`
    pub hal_set_wake_enable: Field<u64>,
    /// -> `fn`
    pub hal_set_wake_alarm: Field<u64>,
    /// -> `fn`
    pub hal_pci_translate_bus_address: Field<u64>,
    /// -> `fn`
    pub hal_pci_assign_slot_resources: Field<u64>,
    /// -> `fn`
    pub hal_halt_system: Field<u64>,
    /// -> `fn`
    pub hal_find_bus_address_translation: Field<u64>,
    /// -> `fn`
    pub hal_reset_display: Field<u64>,
    /// -> `fn`
    pub hal_allocate_map_registers: Field<u64>,
    /// -> `fn`
    pub kd_setup_pci_device_for_debugging: Field<u64>,
    /// -> `fn`
    pub kd_release_pci_device_for_debugging: Field<u64>,
    /// -> `fn`
    pub kd_get_acpi_table_phase0: Field<u64>,
    /// -> `fn`
    pub kd_check_power_button: Field<u64>,
    /// -> `fn`
    pub hal_vector_to_idt_entry: Field<u64>,
    /// -> `fn`
    pub kd_map_physical_memory64: Field<u64>,
    /// -> `fn`
    pub kd_unmap_virtual_address: Field<u64>,
    /// -> `fn`
    pub kd_get_pci_data_by_offset: Field<u64>,
    /// -> `fn`
    pub kd_set_pci_data_by_offset: Field<u64>,
    /// -> `fn`
    pub hal_get_interrupt_vector_override: Field<u64>,
    /// -> `fn`
    pub hal_get_vector_input_override: Field<u64>,
    /// -> `fn`
    pub hal_load_microcode: Field<u64>,
    /// -> `fn`
    pub hal_unload_microcode: Field<u64>,
    /// -> `fn`
    pub hal_post_microcode_update: Field<u64>,
    /// -> `fn`
    pub hal_allocate_message_target_override: Field<u64>,
    /// -> `fn`
    pub hal_free_message_target_override: Field<u64>,
    /// -> `fn`
    pub hal_dp_replace_begin: Field<u64>,
    /// -> `fn`
    pub hal_dp_replace_target: Field<u64>,
    /// -> `fn`
    pub hal_dp_replace_control: Field<u64>,
    /// -> `fn`
    pub hal_dp_replace_end: Field<u64>,
    /// -> `fn`
    pub hal_prepare_for_bugcheck: Field<u64>,
    /// -> `fn`
    pub hal_query_wake_time: Field<u64>,
    /// -> `fn`
    pub hal_report_idle_state_usage: Field<u64>,
    /// -> `fn`
    pub hal_tsc_synchronization: Field<u64>,
    /// -> `fn`
    pub hal_whea_init_processor_generic_section: Field<u64>,
    /// -> `fn`
    pub hal_stop_legacy_usb_interrupts: Field<u64>,
    /// -> `fn`
    pub hal_read_whea_physical_memory: Field<u64>,
    /// -> `fn`
    pub hal_write_whea_physical_memory: Field<u64>,
    /// -> `fn`
    pub hal_dp_mask_level_triggered_interrupts: Field<u64>,
    /// -> `fn`
    pub hal_dp_unmask_level_triggered_interrupts: Field<u64>,
    /// -> `fn`
    pub hal_dp_get_interrupt_replay_state: Field<u64>,
    /// -> `fn`
    pub hal_dp_replay_interrupts: Field<u64>,
    /// -> `fn`
    pub hal_query_io_port_access_supported: Field<u64>,
    /// -> `fn`
    pub kd_setup_integrated_device_for_debugging: Field<u64>,
    /// -> `fn`
    pub kd_release_integrated_device_for_debugging: Field<u64>,
    /// -> `fn`
    pub hal_get_enlightenment_information: Field<u64>,
    /// -> `fn`
    pub hal_allocate_early_pages: Field<u64>,
    /// -> `fn`
    pub hal_map_early_pages: Field<u64>,
    /// -> `void`
    pub dummy1: Field<u64>,
    /// -> `void`
    pub dummy2: Field<u64>,
    /// -> `fn`
    pub hal_notify_processor_freeze: Field<u64>,
    /// -> `fn`
    pub hal_prepare_processor_for_idle: Field<u64>,
    /// -> `fn`
    pub hal_register_log_routine: Field<u64>,
    /// -> `fn`
    pub hal_resume_processor_from_idle: Field<u64>,
    /// -> `void`
    pub dummy: Field<u64>,
    /// -> `fn`
    pub hal_vector_to_idt_entry_ex: Field<u64>,
    /// -> `fn`
    pub hal_secondary_interrupt_query_primary_information: Field<u64>,
    /// -> `fn`
    pub hal_mask_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_unmask_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_is_interrupt_type_secondary: Field<u64>,
    /// -> `fn`
    pub hal_allocate_gsiv_for_secondary_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_add_interrupt_remapping: Field<u64>,
    /// -> `fn`
    pub hal_remove_interrupt_remapping: Field<u64>,
    /// -> `fn`
    pub hal_save_and_disable_hv_enlightenment: Field<u64>,
    /// -> `fn`
    pub hal_restore_hv_enlightenment: Field<u64>,
    /// -> `fn`
    pub hal_flush_io_buffers_external_cache: Field<u64>,
    /// -> `fn`
    pub hal_flush_external_cache: Field<u64>,
    /// -> `fn`
    pub hal_pci_early_restore: Field<u64>,
    /// -> `fn`
    pub hal_get_processor_id: Field<u64>,
    /// -> `fn`
    pub hal_allocate_pmc_counter_set: Field<u64>,
    /// -> `fn`
    pub hal_collect_pmc_counters: Field<u64>,
    /// -> `fn`
    pub hal_free_pmc_counter_set: Field<u64>,
    /// -> `fn`
    pub hal_processor_halt: Field<u64>,
    /// -> `fn`
    pub hal_timer_query_cycle_counter: Field<u64>,
    /// -> `void`
    pub dummy3: Field<u64>,
    /// -> `fn`
    pub hal_pci_mark_hiber_phase: Field<u64>,
    /// -> `fn`
    pub hal_query_processor_restart_entry_point: Field<u64>,
    /// -> `fn`
    pub hal_request_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_enumerate_unmasked_interrupts: Field<u64>,
    /// -> `fn`
    pub hal_flush_and_invalidate_page_external_cache: Field<u64>,
    /// -> `fn`
    pub kd_enumerate_debugging_devices: Field<u64>,
    /// -> `fn`
    pub hal_flush_io_rectangle_external_cache: Field<u64>,
    /// -> `fn`
    pub hal_power_early_restore: Field<u64>,
    /// -> `fn`
    pub hal_query_capsule_capabilities: Field<u64>,
    /// -> `fn`
    pub hal_update_capsule: Field<u64>,
    /// -> `fn`
    pub hal_pci_multi_stage_resume_capable: Field<u64>,
    /// -> `fn`
    pub hal_dma_free_crash_dump_registers: Field<u64>,
    /// -> `fn`
    pub hal_acpi_aoac_capable: Field<u64>,
    /// -> `fn`
    pub hal_interrupt_set_destination: Field<u64>,
    /// -> `fn`
    pub hal_get_clock_configuration: Field<u64>,
    /// -> `fn`
    pub hal_clock_timer_activate: Field<u64>,
    /// -> `fn`
    pub hal_clock_timer_initialize: Field<u64>,
    /// -> `fn`
    pub hal_clock_timer_stop: Field<u64>,
    /// -> `fn`
    pub hal_clock_timer_arm: Field<u64>,
    /// -> `fn`
    pub hal_timer_only_clock_interrupt_pending: Field<u64>,
    /// -> `fn`
    pub hal_acpi_get_multi_node: Field<u64>,
    /// -> `fn`
    pub hal_power_set_reboot_handler: Field<u64>,
    /// -> `fn`
    pub hal_iommu_register_dispatch_table: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_start: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_reset_countdown: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_stop: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_generated_last_reset: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_trigger_system_reset: Field<u64>,
    /// -> `fn`
    pub hal_interrupt_vector_data_to_gsiv: Field<u64>,
    /// -> `fn`
    pub hal_interrupt_get_highest_priority_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_processor_on: Field<u64>,
    /// -> `fn`
    pub hal_processor_off: Field<u64>,
    /// -> `fn`
    pub hal_processor_freeze: Field<u64>,
    /// -> `fn`
    pub hal_dma_link_device_object_by_token: Field<u64>,
    /// -> `fn`
    pub hal_dma_check_adapter_token: Field<u64>,
    /// -> `void`
    pub dummy4: Field<u64>,
    /// -> `fn`
    pub hal_timer_convert_performance_counter_to_auxiliary_counter: Field<u64>,
    /// -> `fn`
    pub hal_timer_convert_auxiliary_counter_to_performance_counter: Field<u64>,
    /// -> `fn`
    pub hal_timer_query_auxiliary_counter_frequency: Field<u64>,
    /// -> `fn`
    pub hal_connect_thermal_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_is_efi_runtime_active: Field<u64>,
    /// -> `fn`
    pub hal_timer_query_and_reset_rtc_errors: Field<u64>,
    /// -> `fn`
    pub hal_acpi_late_restore: Field<u64>,
    /// -> `fn`
    pub kd_watchdog_delay_expiration: Field<u64>,
    /// -> `fn`
    pub hal_get_processor_stats: Field<u64>,
    /// -> `fn`
    pub hal_timer_watchdog_query_due_time: Field<u64>,
    /// -> `fn`
    pub hal_connect_synthetic_interrupt: Field<u64>,
    /// -> `fn`
    pub hal_preprocess_nmi: Field<u64>,
    /// -> `fn`
    pub hal_enumerate_environment_variables_with_filter: Field<u64>,
    /// -> `fn`
    pub hal_capture_last_branch_record_stack: Field<u64>,
    /// -> `fn`
    pub hal_clear_last_branch_record_stack: Field<u64>,
    /// -> `fn`
    pub hal_configure_last_branch_record: Field<u64>,
    /// -> `fn`
    pub hal_get_last_branch_information: Field<u64>,
    /// -> `fn`
    pub hal_resume_last_branch_record: Field<u64>,
    /// -> `fn`
    pub hal_start_last_branch_record: Field<u64>,
    /// -> `fn`
    pub hal_stop_last_branch_record: Field<u64>,
    /// -> `fn`
    pub hal_iommu_block_device: Field<u64>,
    /// -> `fn`
    pub hal_iommu_unblock_device: Field<u64>,
    /// -> `fn`
    pub hal_get_iommu_interface: Field<u64>,
    /// -> `fn`
    pub hal_request_generic_error_recovery: Field<u64>,
    /// -> `fn`
    pub hal_timer_query_host_performance_counter: Field<u64>,
    /// -> `fn`
    pub hal_topology_query_processor_relationships: Field<u64>,
    /// -> `fn`
    pub hal_init_platform_debug_triggers: Field<u64>,
    /// -> `fn`
    pub hal_run_platform_debug_triggers: Field<u64>,
    /// -> `fn`
    pub hal_timer_get_reference_page: Field<u64>,
    /// -> `fn`
    pub hal_get_hidden_processor_power_interface: Field<u64>,
    /// -> `fn`
    pub hal_get_hidden_processor_package_id: Field<u64>,
    /// -> `fn`
    pub hal_get_hidden_package_processor_count: Field<u64>,
    /// -> `fn`
    pub hal_get_hidden_processor_apic_id_by_index: Field<u64>,
    /// -> `fn`
    pub hal_register_hidden_processor_idle_state: Field<u64>,
    /// -> `fn`
    pub hal_iommu_report_iommu_fault: Field<u64>,
    /// -> `fn`
    pub hal_iommu_dma_remapping_capable: Field<u64>,
}

unsafe impl NtStruct for HalPrivateDispatch {}

const _: () = {
    assert!(core::mem::size_of::<HalPrivateDispatch>() == 0x4b0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, version) == 0x0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_handler_for_bus) == 0x8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_handler_for_config_space) == 0x10);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_locate_hiber_ranges) == 0x18);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_register_bus_handler) == 0x20);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_set_wake_enable) == 0x28);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_set_wake_alarm) == 0x30);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_pci_translate_bus_address) == 0x38);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_pci_assign_slot_resources) == 0x40);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_halt_system) == 0x48);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_find_bus_address_translation) == 0x50);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_reset_display) == 0x58);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_allocate_map_registers) == 0x60);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_setup_pci_device_for_debugging) == 0x68);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_release_pci_device_for_debugging) == 0x70);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_get_acpi_table_phase0) == 0x78);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_check_power_button) == 0x80);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_vector_to_idt_entry) == 0x88);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_map_physical_memory64) == 0x90);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_unmap_virtual_address) == 0x98);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_get_pci_data_by_offset) == 0xa0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_set_pci_data_by_offset) == 0xa8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_interrupt_vector_override) == 0xb0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_vector_input_override) == 0xb8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_load_microcode) == 0xc0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_unload_microcode) == 0xc8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_post_microcode_update) == 0xd0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_allocate_message_target_override) == 0xd8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_free_message_target_override) == 0xe0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_replace_begin) == 0xe8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_replace_target) == 0xf0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_replace_control) == 0xf8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_replace_end) == 0x100);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_prepare_for_bugcheck) == 0x108);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_query_wake_time) == 0x110);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_report_idle_state_usage) == 0x118);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_tsc_synchronization) == 0x120);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_whea_init_processor_generic_section) == 0x128);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_stop_legacy_usb_interrupts) == 0x130);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_read_whea_physical_memory) == 0x138);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_write_whea_physical_memory) == 0x140);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_mask_level_triggered_interrupts) == 0x148);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_unmask_level_triggered_interrupts) == 0x150);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_get_interrupt_replay_state) == 0x158);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dp_replay_interrupts) == 0x160);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_query_io_port_access_supported) == 0x168);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_setup_integrated_device_for_debugging) == 0x170);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_release_integrated_device_for_debugging) == 0x178);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_enlightenment_information) == 0x180);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_allocate_early_pages) == 0x188);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_map_early_pages) == 0x190);
    assert!(core::mem::offset_of!(HalPrivateDispatch, dummy1) == 0x198);
    assert!(core::mem::offset_of!(HalPrivateDispatch, dummy2) == 0x1a0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_notify_processor_freeze) == 0x1a8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_prepare_processor_for_idle) == 0x1b0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_register_log_routine) == 0x1b8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_resume_processor_from_idle) == 0x1c0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, dummy) == 0x1c8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_vector_to_idt_entry_ex) == 0x1d0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_secondary_interrupt_query_primary_information) == 0x1d8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_mask_interrupt) == 0x1e0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_unmask_interrupt) == 0x1e8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_is_interrupt_type_secondary) == 0x1f0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_allocate_gsiv_for_secondary_interrupt) == 0x1f8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_add_interrupt_remapping) == 0x200);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_remove_interrupt_remapping) == 0x208);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_save_and_disable_hv_enlightenment) == 0x210);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_restore_hv_enlightenment) == 0x218);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_flush_io_buffers_external_cache) == 0x220);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_flush_external_cache) == 0x228);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_pci_early_restore) == 0x230);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_processor_id) == 0x238);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_allocate_pmc_counter_set) == 0x240);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_collect_pmc_counters) == 0x248);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_free_pmc_counter_set) == 0x250);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_processor_halt) == 0x258);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_query_cycle_counter) == 0x260);
    assert!(core::mem::offset_of!(HalPrivateDispatch, dummy3) == 0x268);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_pci_mark_hiber_phase) == 0x270);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_query_processor_restart_entry_point) == 0x278);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_request_interrupt) == 0x280);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_enumerate_unmasked_interrupts) == 0x288);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_flush_and_invalidate_page_external_cache) == 0x290);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_enumerate_debugging_devices) == 0x298);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_flush_io_rectangle_external_cache) == 0x2a0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_power_early_restore) == 0x2a8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_query_capsule_capabilities) == 0x2b0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_update_capsule) == 0x2b8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_pci_multi_stage_resume_capable) == 0x2c0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dma_free_crash_dump_registers) == 0x2c8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_acpi_aoac_capable) == 0x2d0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_interrupt_set_destination) == 0x2d8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_clock_configuration) == 0x2e0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_clock_timer_activate) == 0x2e8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_clock_timer_initialize) == 0x2f0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_clock_timer_stop) == 0x2f8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_clock_timer_arm) == 0x300);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_only_clock_interrupt_pending) == 0x308);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_acpi_get_multi_node) == 0x310);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_power_set_reboot_handler) == 0x318);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_iommu_register_dispatch_table) == 0x320);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_start) == 0x328);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_reset_countdown) == 0x330);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_stop) == 0x338);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_generated_last_reset) == 0x340);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_trigger_system_reset) == 0x348);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_interrupt_vector_data_to_gsiv) == 0x350);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_interrupt_get_highest_priority_interrupt) == 0x358);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_processor_on) == 0x360);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_processor_off) == 0x368);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_processor_freeze) == 0x370);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dma_link_device_object_by_token) == 0x378);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_dma_check_adapter_token) == 0x380);
    assert!(core::mem::offset_of!(HalPrivateDispatch, dummy4) == 0x388);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_convert_performance_counter_to_auxiliary_counter) == 0x390);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_convert_auxiliary_counter_to_performance_counter) == 0x398);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_query_auxiliary_counter_frequency) == 0x3a0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_connect_thermal_interrupt) == 0x3a8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_is_efi_runtime_active) == 0x3b0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_query_and_reset_rtc_errors) == 0x3b8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_acpi_late_restore) == 0x3c0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, kd_watchdog_delay_expiration) == 0x3c8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_processor_stats) == 0x3d0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_watchdog_query_due_time) == 0x3d8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_connect_synthetic_interrupt) == 0x3e0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_preprocess_nmi) == 0x3e8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_enumerate_environment_variables_with_filter) == 0x3f0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_capture_last_branch_record_stack) == 0x3f8);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_clear_last_branch_record_stack) == 0x400);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_configure_last_branch_record) == 0x408);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_last_branch_information) == 0x410);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_resume_last_branch_record) == 0x418);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_start_last_branch_record) == 0x420);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_stop_last_branch_record) == 0x428);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_iommu_block_device) == 0x430);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_iommu_unblock_device) == 0x438);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_iommu_interface) == 0x440);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_request_generic_error_recovery) == 0x448);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_query_host_performance_counter) == 0x450);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_topology_query_processor_relationships) == 0x458);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_init_platform_debug_triggers) == 0x460);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_run_platform_debug_triggers) == 0x468);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_timer_get_reference_page) == 0x470);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_hidden_processor_power_interface) == 0x478);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_hidden_processor_package_id) == 0x480);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_hidden_package_processor_count) == 0x488);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_get_hidden_processor_apic_id_by_index) == 0x490);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_register_hidden_processor_idle_state) == 0x498);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_iommu_report_iommu_fault) == 0x4a0);
    assert!(core::mem::offset_of!(HalPrivateDispatch, hal_iommu_dma_remapping_capable) == 0x4a8);
};

/// `_WHEA_TIMESTAMP` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaTimestampView1`, alcançada por `Deref`.
#[repr(C)]
pub struct WheaTimestamp {
    pub bitfield_0: Field<u64>,
}

/// Vista 1 de `_WHEA_TIMESTAMP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaTimestampView1 {
    pub as_large_integer: LargeInteger,
}

impl core::ops::Deref for WheaTimestamp {
    type Target = WheaTimestampView1;
    #[inline(always)]
    fn deref(&self) -> &WheaTimestampView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaTimestampView1>() }
    }
}

unsafe impl NtStruct for WheaTimestamp {}

impl WheaTimestamp {
    /// `Seconds`: bits 0..=7 de `bitfield_0`.
    pub const SECONDS_SHIFT: u32 = 0;
    pub const SECONDS_MASK: u64 = 0xff;
    #[inline(always)]
    pub fn seconds(&self) -> u64 {
        self.bitfield_0.bits(0, 8) as u64
    }
    #[inline(always)]
    pub fn set_seconds(&self, value: u64) {
        self.bitfield_0.set_bits(0, 8, value as u64)
    }
    /// `Minutes`: bits 8..=15 de `bitfield_0`.
    pub const MINUTES_SHIFT: u32 = 8;
    pub const MINUTES_MASK: u64 = 0xff00;
    #[inline(always)]
    pub fn minutes(&self) -> u64 {
        self.bitfield_0.bits(8, 8) as u64
    }
    #[inline(always)]
    pub fn set_minutes(&self, value: u64) {
        self.bitfield_0.set_bits(8, 8, value as u64)
    }
    /// `Hours`: bits 16..=23 de `bitfield_0`.
    pub const HOURS_SHIFT: u32 = 16;
    pub const HOURS_MASK: u64 = 0xff0000;
    #[inline(always)]
    pub fn hours(&self) -> u64 {
        self.bitfield_0.bits(16, 8) as u64
    }
    #[inline(always)]
    pub fn set_hours(&self, value: u64) {
        self.bitfield_0.set_bits(16, 8, value as u64)
    }
    /// `Precise`: bits 24..=24 de `bitfield_0`.
    pub const PRECISE_SHIFT: u32 = 24;
    pub const PRECISE_MASK: u64 = 0x1000000;
    #[inline(always)]
    pub fn precise(&self) -> u64 {
        self.bitfield_0.bits(24, 1) as u64
    }
    #[inline(always)]
    pub fn set_precise(&self, value: u64) {
        self.bitfield_0.set_bits(24, 1, value as u64)
    }
    /// `Reserved`: bits 25..=31 de `bitfield_0`.
    pub const RESERVED_SHIFT: u32 = 25;
    pub const RESERVED_MASK: u64 = 0xfe000000;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.bitfield_0.bits(25, 7) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.bitfield_0.set_bits(25, 7, value as u64)
    }
    /// `Day`: bits 32..=39 de `bitfield_0`.
    pub const DAY_SHIFT: u32 = 32;
    pub const DAY_MASK: u64 = 0xff00000000;
    #[inline(always)]
    pub fn day(&self) -> u64 {
        self.bitfield_0.bits(32, 8) as u64
    }
    #[inline(always)]
    pub fn set_day(&self, value: u64) {
        self.bitfield_0.set_bits(32, 8, value as u64)
    }
    /// `Month`: bits 40..=47 de `bitfield_0`.
    pub const MONTH_SHIFT: u32 = 40;
    pub const MONTH_MASK: u64 = 0xff0000000000;
    #[inline(always)]
    pub fn month(&self) -> u64 {
        self.bitfield_0.bits(40, 8) as u64
    }
    #[inline(always)]
    pub fn set_month(&self, value: u64) {
        self.bitfield_0.set_bits(40, 8, value as u64)
    }
    /// `Year`: bits 48..=55 de `bitfield_0`.
    pub const YEAR_SHIFT: u32 = 48;
    pub const YEAR_MASK: u64 = 0xff000000000000;
    #[inline(always)]
    pub fn year(&self) -> u64 {
        self.bitfield_0.bits(48, 8) as u64
    }
    #[inline(always)]
    pub fn set_year(&self, value: u64) {
        self.bitfield_0.set_bits(48, 8, value as u64)
    }
    /// `Century`: bits 56..=63 de `bitfield_0`.
    pub const CENTURY_SHIFT: u32 = 56;
    pub const CENTURY_MASK: u64 = 0xff00000000000000;
    #[inline(always)]
    pub fn century(&self) -> u64 {
        self.bitfield_0.bits(56, 8) as u64
    }
    #[inline(always)]
    pub fn set_century(&self, value: u64) {
        self.bitfield_0.set_bits(56, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaTimestamp>() == 0x8);
    assert!(core::mem::offset_of!(WheaTimestamp, bitfield_0) == 0x0);
    assert!(core::mem::size_of::<WheaTimestampView1>() == 0x8);
    assert!(core::mem::align_of::<WheaTimestampView1>() == core::mem::align_of::<WheaTimestamp>());
    assert!(core::mem::offset_of!(WheaTimestampView1, as_large_integer) == 0x0);
};

/// `_WHEA_ERROR_RECORD_HEADER` (0x80 bytes).
#[repr(C)]
pub struct WheaErrorRecordHeader {
    pub signature: Field<u32>,
    pub revision: WheaRevision,
    pub signature_end: UnalignedField<u32>,
    pub section_count: Field<u16>,
    pub severity: Field<WheaErrorSeverity>,
    pub valid_bits: WheaErrorRecordHeaderValidbits,
    pub length: Field<u32>,
    pub timestamp: WheaTimestamp,
    pub platform_id: Guid,
    pub partition_id: Guid,
    pub creator_id: Guid,
    pub notify_type: Guid,
    pub record_id: Field<u64>,
    pub flags: WheaErrorRecordHeaderFlags,
    pub persistence_info: WheaPersistenceInfoUnaligned,
    pub reserved: [Field<u8>; 12],
}

unsafe impl NtStruct for WheaErrorRecordHeader {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordHeader>() == 0x80);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, signature) == 0x0);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, revision) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, signature_end) == 0x6);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, section_count) == 0xa);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, severity) == 0xc);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, valid_bits) == 0x10);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, length) == 0x14);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, timestamp) == 0x18);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, platform_id) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, partition_id) == 0x30);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, creator_id) == 0x40);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, notify_type) == 0x50);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, record_id) == 0x60);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, flags) == 0x68);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, persistence_info) == 0x6c);
    assert!(core::mem::offset_of!(WheaErrorRecordHeader, reserved) == 0x74);
};

/// `_WHEA_ERROR_RECORD_HEADER_VALIDBITS` (0x4 bytes).
#[repr(C)]
pub struct WheaErrorRecordHeaderValidbits {
    pub as_ulong: Field<u32>,
}

unsafe impl NtStruct for WheaErrorRecordHeaderValidbits {}

impl WheaErrorRecordHeaderValidbits {
    /// `PlatformId`: bits 0..=0 de `as_ulong`.
    pub const PLATFORM_ID_SHIFT: u32 = 0;
    pub const PLATFORM_ID_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn platform_id(&self) -> u32 {
        self.as_ulong.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_platform_id(&self, value: u32) {
        self.as_ulong.set_bits(0, 1, value as u64)
    }
    /// `Timestamp`: bits 1..=1 de `as_ulong`.
    pub const TIMESTAMP_SHIFT: u32 = 1;
    pub const TIMESTAMP_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn timestamp(&self) -> u32 {
        self.as_ulong.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_timestamp(&self, value: u32) {
        self.as_ulong.set_bits(1, 1, value as u64)
    }
    /// `PartitionId`: bits 2..=2 de `as_ulong`.
    pub const PARTITION_ID_SHIFT: u32 = 2;
    pub const PARTITION_ID_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn partition_id(&self) -> u32 {
        self.as_ulong.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_partition_id(&self, value: u32) {
        self.as_ulong.set_bits(2, 1, value as u64)
    }
    /// `Reserved`: bits 3..=31 de `as_ulong`.
    pub const RESERVED_SHIFT: u32 = 3;
    pub const RESERVED_MASK: u32 = 0xfffffff8;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.as_ulong.bits(3, 29) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.as_ulong.set_bits(3, 29, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordHeaderValidbits>() == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordHeaderValidbits, as_ulong) == 0x0);
};

/// `_WHEA_ERROR_RECORD_HEADER_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct WheaErrorRecordHeaderFlags {
    pub as_ulong: Field<u32>,
}

unsafe impl NtStruct for WheaErrorRecordHeaderFlags {}

impl WheaErrorRecordHeaderFlags {
    /// `Recovered`: bits 0..=0 de `as_ulong`.
    pub const RECOVERED_SHIFT: u32 = 0;
    pub const RECOVERED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn recovered(&self) -> u32 {
        self.as_ulong.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_recovered(&self, value: u32) {
        self.as_ulong.set_bits(0, 1, value as u64)
    }
    /// `PreviousError`: bits 1..=1 de `as_ulong`.
    pub const PREVIOUS_ERROR_SHIFT: u32 = 1;
    pub const PREVIOUS_ERROR_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn previous_error(&self) -> u32 {
        self.as_ulong.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_previous_error(&self, value: u32) {
        self.as_ulong.set_bits(1, 1, value as u64)
    }
    /// `Simulated`: bits 2..=2 de `as_ulong`.
    pub const SIMULATED_SHIFT: u32 = 2;
    pub const SIMULATED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn simulated(&self) -> u32 {
        self.as_ulong.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_simulated(&self, value: u32) {
        self.as_ulong.set_bits(2, 1, value as u64)
    }
    /// `DeviceDriver`: bits 3..=3 de `as_ulong`.
    pub const DEVICE_DRIVER_SHIFT: u32 = 3;
    pub const DEVICE_DRIVER_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn device_driver(&self) -> u32 {
        self.as_ulong.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_device_driver(&self, value: u32) {
        self.as_ulong.set_bits(3, 1, value as u64)
    }
    /// `CriticalEvent`: bits 4..=4 de `as_ulong`.
    pub const CRITICAL_EVENT_SHIFT: u32 = 4;
    pub const CRITICAL_EVENT_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn critical_event(&self) -> u32 {
        self.as_ulong.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_critical_event(&self, value: u32) {
        self.as_ulong.set_bits(4, 1, value as u64)
    }
    /// `PersistPfn`: bits 5..=5 de `as_ulong`.
    pub const PERSIST_PFN_SHIFT: u32 = 5;
    pub const PERSIST_PFN_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn persist_pfn(&self) -> u32 {
        self.as_ulong.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_persist_pfn(&self, value: u32) {
        self.as_ulong.set_bits(5, 1, value as u64)
    }
    /// `Reserved`: bits 6..=31 de `as_ulong`.
    pub const RESERVED_SHIFT: u32 = 6;
    pub const RESERVED_MASK: u32 = 0xffffffc0;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.as_ulong.bits(6, 26) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.as_ulong.set_bits(6, 26, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorRecordHeaderFlags>() == 0x4);
    assert!(core::mem::offset_of!(WheaErrorRecordHeaderFlags, as_ulong) == 0x0);
};

/// `_WHEA_PERSISTENCE_INFO` (0x8 bytes).
#[repr(C)]
pub struct WheaPersistenceInfoUnaligned {
    pub as_ulonglong: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaPersistenceInfoUnaligned {}

impl WheaPersistenceInfoUnaligned {
    /// `Signature`: bits 0..=15 de `as_ulonglong`.
    pub const SIGNATURE_SHIFT: u32 = 0;
    pub const SIGNATURE_MASK: u64 = 0xffff;
    #[inline(always)]
    pub fn signature(&self) -> u64 {
        self.as_ulonglong.bits(0, 16) as u64
    }
    #[inline(always)]
    pub fn set_signature(&self, value: u64) {
        self.as_ulonglong.set_bits(0, 16, value as u64)
    }
    /// `Length`: bits 16..=39 de `as_ulonglong`.
    pub const LENGTH_SHIFT: u32 = 16;
    pub const LENGTH_MASK: u64 = 0xffffff0000;
    #[inline(always)]
    pub fn length(&self) -> u64 {
        self.as_ulonglong.bits(16, 24) as u64
    }
    #[inline(always)]
    pub fn set_length(&self, value: u64) {
        self.as_ulonglong.set_bits(16, 24, value as u64)
    }
    /// `Identifier`: bits 40..=55 de `as_ulonglong`.
    pub const IDENTIFIER_SHIFT: u32 = 40;
    pub const IDENTIFIER_MASK: u64 = 0xffff0000000000;
    #[inline(always)]
    pub fn identifier(&self) -> u64 {
        self.as_ulonglong.bits(40, 16) as u64
    }
    #[inline(always)]
    pub fn set_identifier(&self, value: u64) {
        self.as_ulonglong.set_bits(40, 16, value as u64)
    }
    /// `Attributes`: bits 56..=57 de `as_ulonglong`.
    pub const ATTRIBUTES_SHIFT: u32 = 56;
    pub const ATTRIBUTES_MASK: u64 = 0x300000000000000;
    #[inline(always)]
    pub fn attributes(&self) -> u64 {
        self.as_ulonglong.bits(56, 2) as u64
    }
    #[inline(always)]
    pub fn set_attributes(&self, value: u64) {
        self.as_ulonglong.set_bits(56, 2, value as u64)
    }
    /// `DoNotLog`: bits 58..=58 de `as_ulonglong`.
    pub const DO_NOT_LOG_SHIFT: u32 = 58;
    pub const DO_NOT_LOG_MASK: u64 = 0x400000000000000;
    #[inline(always)]
    pub fn do_not_log(&self) -> u64 {
        self.as_ulonglong.bits(58, 1) as u64
    }
    #[inline(always)]
    pub fn set_do_not_log(&self, value: u64) {
        self.as_ulonglong.set_bits(58, 1, value as u64)
    }
    /// `Reserved`: bits 59..=63 de `as_ulonglong`.
    pub const RESERVED_SHIFT: u32 = 59;
    pub const RESERVED_MASK: u64 = 0xf800000000000000;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.as_ulonglong.bits(59, 5) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.as_ulonglong.set_bits(59, 5, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaPersistenceInfoUnaligned>() == 0x8);
    assert!(core::mem::offset_of!(WheaPersistenceInfoUnaligned, as_ulonglong) == 0x0);
};

/// `_WHEA_ERROR_PACKET_V2` (0x50 bytes).
#[repr(C)]
pub struct WheaErrorPacketV2 {
    pub signature: Field<u32>,
    pub version: Field<u32>,
    pub length: Field<u32>,
    pub flags: WheaErrorPacketFlags,
    pub error_type: Field<WheaErrorType>,
    pub error_severity: Field<WheaErrorSeverity>,
    pub error_source_id: Field<u32>,
    pub error_source_type: Field<WheaErrorSourceType>,
    pub notify_type: Guid,
    pub context: Field<u64>,
    pub data_format: Field<WheaErrorPacketDataFormat>,
    pub reserved1: Field<u32>,
    pub data_offset: Field<u32>,
    pub data_length: Field<u32>,
    pub pshed_data_offset: Field<u32>,
    pub pshed_data_length: Field<u32>,
}

unsafe impl NtStruct for WheaErrorPacketV2 {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorPacketV2>() == 0x50);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, signature) == 0x0);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, version) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, length) == 0x8);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, flags) == 0xc);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_type) == 0x10);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_severity) == 0x14);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_source_id) == 0x18);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, error_source_type) == 0x1c);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, notify_type) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, context) == 0x30);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, data_format) == 0x38);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, reserved1) == 0x3c);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, data_offset) == 0x40);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, data_length) == 0x44);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, pshed_data_offset) == 0x48);
    assert!(core::mem::offset_of!(WheaErrorPacketV2, pshed_data_length) == 0x4c);
};

/// `_WHEA_ERROR_PACKET_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct WheaErrorPacketFlags {
    pub as_ulong: Field<u32>,
}

unsafe impl NtStruct for WheaErrorPacketFlags {}

impl WheaErrorPacketFlags {
    /// `PreviousError`: bits 0..=0 de `as_ulong`.
    pub const PREVIOUS_ERROR_SHIFT: u32 = 0;
    pub const PREVIOUS_ERROR_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn previous_error(&self) -> u32 {
        self.as_ulong.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_previous_error(&self, value: u32) {
        self.as_ulong.set_bits(0, 1, value as u64)
    }
    /// `CriticalEvent`: bits 1..=1 de `as_ulong`.
    pub const CRITICAL_EVENT_SHIFT: u32 = 1;
    pub const CRITICAL_EVENT_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn critical_event(&self) -> u32 {
        self.as_ulong.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_critical_event(&self, value: u32) {
        self.as_ulong.set_bits(1, 1, value as u64)
    }
    /// `HypervisorError`: bits 2..=2 de `as_ulong`.
    pub const HYPERVISOR_ERROR_SHIFT: u32 = 2;
    pub const HYPERVISOR_ERROR_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn hypervisor_error(&self) -> u32 {
        self.as_ulong.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_hypervisor_error(&self, value: u32) {
        self.as_ulong.set_bits(2, 1, value as u64)
    }
    /// `Simulated`: bits 3..=3 de `as_ulong`.
    pub const SIMULATED_SHIFT: u32 = 3;
    pub const SIMULATED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn simulated(&self) -> u32 {
        self.as_ulong.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_simulated(&self, value: u32) {
        self.as_ulong.set_bits(3, 1, value as u64)
    }
    /// `PlatformPfaControl`: bits 4..=4 de `as_ulong`.
    pub const PLATFORM_PFA_CONTROL_SHIFT: u32 = 4;
    pub const PLATFORM_PFA_CONTROL_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn platform_pfa_control(&self) -> u32 {
        self.as_ulong.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_platform_pfa_control(&self, value: u32) {
        self.as_ulong.set_bits(4, 1, value as u64)
    }
    /// `PlatformDirectedOffline`: bits 5..=5 de `as_ulong`.
    pub const PLATFORM_DIRECTED_OFFLINE_SHIFT: u32 = 5;
    pub const PLATFORM_DIRECTED_OFFLINE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn platform_directed_offline(&self) -> u32 {
        self.as_ulong.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_platform_directed_offline(&self, value: u32) {
        self.as_ulong.set_bits(5, 1, value as u64)
    }
    /// `AddressTranslationRequired`: bits 6..=6 de `as_ulong`.
    pub const ADDRESS_TRANSLATION_REQUIRED_SHIFT: u32 = 6;
    pub const ADDRESS_TRANSLATION_REQUIRED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn address_translation_required(&self) -> u32 {
        self.as_ulong.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_address_translation_required(&self, value: u32) {
        self.as_ulong.set_bits(6, 1, value as u64)
    }
    /// `AddressTranslationCompleted`: bits 7..=7 de `as_ulong`.
    pub const ADDRESS_TRANSLATION_COMPLETED_SHIFT: u32 = 7;
    pub const ADDRESS_TRANSLATION_COMPLETED_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn address_translation_completed(&self) -> u32 {
        self.as_ulong.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_address_translation_completed(&self, value: u32) {
        self.as_ulong.set_bits(7, 1, value as u64)
    }
    /// `Reserved2`: bits 8..=31 de `as_ulong`.
    pub const RESERVED2_SHIFT: u32 = 8;
    pub const RESERVED2_MASK: u32 = 0xffffff00;
    #[inline(always)]
    pub fn reserved2(&self) -> u32 {
        self.as_ulong.bits(8, 24) as u32
    }
    #[inline(always)]
    pub fn set_reserved2(&self, value: u32) {
        self.as_ulong.set_bits(8, 24, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorPacketFlags>() == 0x4);
    assert!(core::mem::offset_of!(WheaErrorPacketFlags, as_ulong) == 0x0);
};

/// `_WHEA_ERROR_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WheaErrorType(pub i32);

impl WheaErrorType {
    pub const WHEA_ERR_TYPE_PROCESSOR: Self = Self(0);
    pub const WHEA_ERR_TYPE_MEMORY: Self = Self(1);
    pub const WHEA_ERR_TYPE_PCI_EXPRESS: Self = Self(2);
    pub const WHEA_ERR_TYPE_NMI: Self = Self(3);
    pub const WHEA_ERR_TYPE_PCIX_BUS: Self = Self(4);
    pub const WHEA_ERR_TYPE_PCIX_DEVICE: Self = Self(5);
    pub const WHEA_ERR_TYPE_GENERIC: Self = Self(6);
    pub const WHEA_ERR_TYPE_PMEM: Self = Self(7);
}

impl GuestScalar for WheaErrorType {
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

/// `_WHEA_ERROR_SOURCE_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WheaErrorSourceType(pub i32);

impl WheaErrorSourceType {
    pub const WHEA_ERR_SRC_TYPE_MCE: Self = Self(0);
    pub const WHEA_ERR_SRC_TYPE_CMC: Self = Self(1);
    pub const WHEA_ERR_SRC_TYPE_CPE: Self = Self(2);
    pub const WHEA_ERR_SRC_TYPE_NMI: Self = Self(3);
    pub const WHEA_ERR_SRC_TYPE_PC_IE: Self = Self(4);
    pub const WHEA_ERR_SRC_TYPE_GENERIC: Self = Self(5);
    pub const WHEA_ERR_SRC_TYPE_INIT: Self = Self(6);
    pub const WHEA_ERR_SRC_TYPE_BOOT: Self = Self(7);
    pub const WHEA_ERR_SRC_TYPE_SCI_GENERIC: Self = Self(8);
    pub const WHEA_ERR_SRC_TYPE_IPFMCA: Self = Self(9);
    pub const WHEA_ERR_SRC_TYPE_IPFCMC: Self = Self(10);
    pub const WHEA_ERR_SRC_TYPE_IPFCPE: Self = Self(11);
    pub const WHEA_ERR_SRC_TYPE_GENERIC_V2: Self = Self(12);
    pub const WHEA_ERR_SRC_TYPE_SCI_GENERIC_V2: Self = Self(13);
    pub const WHEA_ERR_SRC_TYPE_BMC: Self = Self(14);
    pub const WHEA_ERR_SRC_TYPE_PMEM: Self = Self(15);
    pub const WHEA_ERR_SRC_TYPE_DEVICE_DRIVER: Self = Self(16);
    pub const WHEA_ERR_SRC_TYPE_MAX: Self = Self(17);
}

impl GuestScalar for WheaErrorSourceType {
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

/// `_WHEA_ERROR_PACKET_DATA_FORMAT`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WheaErrorPacketDataFormat(pub i32);

impl WheaErrorPacketDataFormat {
    pub const WHEA_DATA_FORMAT_IPF_SAL_RECORD: Self = Self(0);
    pub const WHEA_DATA_FORMAT_XPFMCA: Self = Self(1);
    pub const WHEA_DATA_FORMAT_MEMORY: Self = Self(2);
    pub const WHEA_DATA_FORMAT_PCI_EXPRESS: Self = Self(3);
    pub const WHEA_DATA_FORMAT_NMI_PORT: Self = Self(4);
    pub const WHEA_DATA_FORMAT_PCIX_BUS: Self = Self(5);
    pub const WHEA_DATA_FORMAT_PCIX_DEVICE: Self = Self(6);
    pub const WHEA_DATA_FORMAT_GENERIC: Self = Self(7);
    pub const WHEA_DATA_FORMAT_MAX: Self = Self(8);
}

impl GuestScalar for WheaErrorPacketDataFormat {
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

/// `_WHEA_DEVICE_DRIVER_DESCRIPTOR` (0x74 bytes).
#[repr(C)]
pub struct WheaDeviceDriverDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
    pub source_guid: Guid,
    pub log_tag: Field<u16>,
    pub reserved2: Field<u16>,
    pub packet_length: Field<u32>,
    pub packet_count: Field<u32>,
    /// -> `u8`
    pub packet_buffer: UnalignedField<u64>,
    pub config: WheaErrorSourceConfigurationDdUnaligned,
    pub creator_id: Guid,
    pub partition_id: Guid,
    pub max_section_data_length: Field<u32>,
    pub max_sections_per_record: Field<u32>,
    /// -> `u8`
    pub packet_state_buffer: UnalignedField<u64>,
    pub open_handles: Field<i32>,
}

unsafe impl NtStruct for WheaDeviceDriverDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaDeviceDriverDescriptor>() == 0x74);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, reserved) == 0x3);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, source_guid) == 0x4);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, log_tag) == 0x14);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, reserved2) == 0x16);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_length) == 0x18);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_count) == 0x1c);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_buffer) == 0x20);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, config) == 0x28);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, creator_id) == 0x40);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, partition_id) == 0x50);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, max_section_data_length) == 0x60);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, max_sections_per_record) == 0x64);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, packet_state_buffer) == 0x68);
    assert!(core::mem::offset_of!(WheaDeviceDriverDescriptor, open_handles) == 0x70);
};

/// `_WHEA_ERROR_SOURCE_CONFIGURATION_DD` (0x18 bytes).
#[repr(C)]
pub struct WheaErrorSourceConfigurationDdUnaligned {
    /// -> `fn`
    pub initialize: UnalignedField<u64>,
    /// -> `fn`
    pub uninitialize: UnalignedField<u64>,
    /// -> `fn`
    pub correct: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaErrorSourceConfigurationDdUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceConfigurationDdUnaligned>() == 0x18);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDdUnaligned, initialize) == 0x0);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDdUnaligned, uninitialize) == 0x8);
    assert!(core::mem::offset_of!(WheaErrorSourceConfigurationDdUnaligned, correct) == 0x10);
};

/// `_WHEA_ERROR_SOURCE_DESCRIPTOR` (0x3cc bytes).
#[repr(C)]
pub struct WheaErrorSourceDescriptor {
    pub length: Field<u32>,
    pub version: Field<u32>,
    pub type_: Field<WheaErrorSourceType>,
    pub state: Field<WheaErrorSourceState>,
    pub max_raw_data_length: Field<u32>,
    pub num_records_to_preallocate: Field<u32>,
    pub max_sections_per_record: Field<u32>,
    pub error_source_id: Field<u32>,
    pub platform_error_source_id: Field<u32>,
    pub flags: Field<u32>,
    pub info: WheaErrorSourceDescriptorInfo,
}

unsafe impl NtStruct for WheaErrorSourceDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceDescriptor>() == 0x3cc);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, length) == 0x0);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, version) == 0x4);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, type_) == 0x8);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, state) == 0xc);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, max_raw_data_length) == 0x10);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, num_records_to_preallocate) == 0x14);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, max_sections_per_record) == 0x18);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, error_source_id) == 0x1c);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, platform_error_source_id) == 0x20);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, flags) == 0x24);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptor, info) == 0x28);
};

/// `_WHEA_ERROR_SOURCE_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct WheaErrorSourceState(pub i32);

impl WheaErrorSourceState {
    pub const WHEA_ERR_SRC_STATE_STOPPED: Self = Self(1);
    pub const WHEA_ERR_SRC_STATE_STARTED: Self = Self(2);
    pub const WHEA_ERR_SRC_STATE_REMOVED: Self = Self(3);
    pub const WHEA_ERR_SRC_STATE_REMOVE_PENDING: Self = Self(4);
}

impl GuestScalar for WheaErrorSourceState {
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

/// `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (0x3a4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaErrorSourceDescriptorInfoView1`..`WheaErrorSourceDescriptorInfoView11`, alcançadas por `Deref`.
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfo {
    _align: [u32; 0],
    pub xpf_mce_descriptor: WheaXpfMceDescriptorUnaligned,
    _pad_398: Reserved<0xc>,
}

/// Vista 1 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView1 {
    pub xpf_cmc_descriptor: WheaXpfCmcDescriptor,
}

/// Vista 2 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView2 {
    _align: [u32; 0],
    pub xpf_nmi_descriptor: WheaXpfNmiDescriptor,
    _pad_3: Reserved<0x3a1>,
}

/// Vista 3 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView3 {
    _align: [u32; 0],
    pub ipf_mca_descriptor: WheaIpfMcaDescriptor,
    _pad_4: Reserved<0x3a0>,
}

/// Vista 4 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView4 {
    _align: [u32; 0],
    pub ipf_cmc_descriptor: WheaIpfCmcDescriptor,
    _pad_4: Reserved<0x3a0>,
}

/// Vista 5 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView5 {
    _align: [u32; 0],
    pub ipf_cpe_descriptor: WheaIpfCpeDescriptor,
    _pad_4: Reserved<0x3a0>,
}

/// Vista 6 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView6 {
    pub aer_rootport_descriptor: WheaAerRootportDescriptor,
    _pad_24: Reserved<0x380>,
}

/// Vista 7 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView7 {
    pub aer_endpoint_descriptor: WheaAerEndpointDescriptor,
    _pad_20: Reserved<0x384>,
}

/// Vista 8 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView8 {
    pub aer_bridge_descriptor: WheaAerBridgeDescriptor,
    _pad_2c: Reserved<0x378>,
}

/// Vista 9 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView9 {
    pub gen_err_descriptor: WheaGenericErrorDescriptor,
    _pad_34: Reserved<0x370>,
}

/// Vista 10 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView10 {
    _align: [u32; 0],
    pub gen_err_descriptor_v2: WheaGenericErrorDescriptorV2Unaligned,
    _pad_50: Reserved<0x354>,
}

/// Vista 11 de `_WHEA_ERROR_SOURCE_DESCRIPTOR::Info` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaErrorSourceDescriptorInfoView11 {
    pub device_driver_descriptor: WheaDeviceDriverDescriptor,
    _pad_74: Reserved<0x330>,
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfo {
    type Target = WheaErrorSourceDescriptorInfoView1;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView1>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView1 {
    type Target = WheaErrorSourceDescriptorInfoView2;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView2>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView2 {
    type Target = WheaErrorSourceDescriptorInfoView3;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView3>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView3 {
    type Target = WheaErrorSourceDescriptorInfoView4;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView4>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView4 {
    type Target = WheaErrorSourceDescriptorInfoView5;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView5>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView5 {
    type Target = WheaErrorSourceDescriptorInfoView6;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView6>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView6 {
    type Target = WheaErrorSourceDescriptorInfoView7;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView7>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView7 {
    type Target = WheaErrorSourceDescriptorInfoView8;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView8 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView8>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView8 {
    type Target = WheaErrorSourceDescriptorInfoView9;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView9 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView9>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView9 {
    type Target = WheaErrorSourceDescriptorInfoView10;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView10 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView10>() }
    }
}

impl core::ops::Deref for WheaErrorSourceDescriptorInfoView10 {
    type Target = WheaErrorSourceDescriptorInfoView11;
    #[inline(always)]
    fn deref(&self) -> &WheaErrorSourceDescriptorInfoView11 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaErrorSourceDescriptorInfoView11>() }
    }
}

unsafe impl NtStruct for WheaErrorSourceDescriptorInfo {}

const _: () = {
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfo>() == 0x3a4);
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfo, xpf_mce_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView1>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView1>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView1, xpf_cmc_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView2>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView2>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView2, xpf_nmi_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView3>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView3>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView3, ipf_mca_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView4>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView4>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView4, ipf_cmc_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView5>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView5>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView5, ipf_cpe_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView6>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView6>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView6, aer_rootport_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView7>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView7>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView7, aer_endpoint_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView8>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView8>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView8, aer_bridge_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView9>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView9>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView9, gen_err_descriptor) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView10>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView10>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView10, gen_err_descriptor_v2) == 0x0);
    assert!(core::mem::size_of::<WheaErrorSourceDescriptorInfoView11>() == 0x3a4);
    assert!(core::mem::align_of::<WheaErrorSourceDescriptorInfoView11>() == core::mem::align_of::<WheaErrorSourceDescriptorInfo>());
    assert!(core::mem::offset_of!(WheaErrorSourceDescriptorInfoView11, device_driver_descriptor) == 0x0);
};

/// `_WHEA_XPF_MC_BANK_DESCRIPTOR` (0x1c bytes).
#[repr(C)]
pub struct WheaXpfMcBankDescriptor {
    pub bank_number: Field<u8>,
    pub clear_on_initialization: Field<u8>,
    pub status_data_format: Field<u8>,
    pub flags: XpfMcBankFlags,
    pub control_msr: Field<u32>,
    pub status_msr: Field<u32>,
    pub address_msr: Field<u32>,
    pub misc_msr: Field<u32>,
    pub control_data: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaXpfMcBankDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaXpfMcBankDescriptor>() == 0x1c);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, bank_number) == 0x0);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, clear_on_initialization) == 0x1);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, status_data_format) == 0x2);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, flags) == 0x3);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, control_msr) == 0x4);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, status_msr) == 0x8);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, address_msr) == 0xc);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, misc_msr) == 0x10);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptor, control_data) == 0x14);
};

/// `_XPF_MC_BANK_FLAGS` (0x1 bytes).
#[repr(C)]
pub struct XpfMcBankFlags {
    pub as_uchar: Field<u8>,
}

unsafe impl NtStruct for XpfMcBankFlags {}

impl XpfMcBankFlags {
    /// `ClearOnInitializationRW`: bits 0..=0 de `as_uchar`.
    pub const CLEAR_ON_INITIALIZATION_RW_SHIFT: u32 = 0;
    pub const CLEAR_ON_INITIALIZATION_RW_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn clear_on_initialization_rw(&self) -> u8 {
        self.as_uchar.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_clear_on_initialization_rw(&self, value: u8) {
        self.as_uchar.set_bits(0, 1, value as u64)
    }
    /// `ControlDataRW`: bits 1..=1 de `as_uchar`.
    pub const CONTROL_DATA_RW_SHIFT: u32 = 1;
    pub const CONTROL_DATA_RW_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn control_data_rw(&self) -> u8 {
        self.as_uchar.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_control_data_rw(&self, value: u8) {
        self.as_uchar.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=7 de `as_uchar`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.as_uchar.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.as_uchar.set_bits(2, 6, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<XpfMcBankFlags>() == 0x1);
    assert!(core::mem::offset_of!(XpfMcBankFlags, as_uchar) == 0x0);
};

/// `_WHEA_XPF_CMC_DESCRIPTOR` (0x3a4 bytes).
#[repr(C)]
pub struct WheaXpfCmcDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub number_of_banks: Field<u8>,
    pub reserved: Field<u32>,
    pub notify: WheaNotificationDescriptor,
    pub banks: [WheaXpfMcBankDescriptor; 32],
}

unsafe impl NtStruct for WheaXpfCmcDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaXpfCmcDescriptor>() == 0x3a4);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, number_of_banks) == 0x3);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, reserved) == 0x4);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, notify) == 0x8);
    assert!(core::mem::offset_of!(WheaXpfCmcDescriptor, banks) == 0x24);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR` (0x1c bytes).
#[repr(C)]
pub struct WheaNotificationDescriptor {
    pub type_: Field<u8>,
    pub length: Field<u8>,
    pub flags: WheaNotificationFlags,
    pub u: WheaNotificationDescriptorU,
}

unsafe impl NtStruct for WheaNotificationDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptor>() == 0x1c);
    assert!(core::mem::offset_of!(WheaNotificationDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaNotificationDescriptor, length) == 0x1);
    assert!(core::mem::offset_of!(WheaNotificationDescriptor, flags) == 0x2);
    assert!(core::mem::offset_of!(WheaNotificationDescriptor, u) == 0x4);
};

/// `_WHEA_NOTIFICATION_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct WheaNotificationFlags {
    pub as_ushort: Field<u16>,
}

unsafe impl NtStruct for WheaNotificationFlags {}

impl WheaNotificationFlags {
    /// `PollIntervalRW`: bits 0..=0 de `as_ushort`.
    pub const POLL_INTERVAL_RW_SHIFT: u32 = 0;
    pub const POLL_INTERVAL_RW_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn poll_interval_rw(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_poll_interval_rw(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `SwitchToPollingThresholdRW`: bits 1..=1 de `as_ushort`.
    pub const SWITCH_TO_POLLING_THRESHOLD_RW_SHIFT: u32 = 1;
    pub const SWITCH_TO_POLLING_THRESHOLD_RW_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn switch_to_polling_threshold_rw(&self) -> u16 {
        self.as_ushort.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_switch_to_polling_threshold_rw(&self, value: u16) {
        self.as_ushort.set_bits(1, 1, value as u64)
    }
    /// `SwitchToPollingWindowRW`: bits 2..=2 de `as_ushort`.
    pub const SWITCH_TO_POLLING_WINDOW_RW_SHIFT: u32 = 2;
    pub const SWITCH_TO_POLLING_WINDOW_RW_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn switch_to_polling_window_rw(&self) -> u16 {
        self.as_ushort.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_switch_to_polling_window_rw(&self, value: u16) {
        self.as_ushort.set_bits(2, 1, value as u64)
    }
    /// `ErrorThresholdRW`: bits 3..=3 de `as_ushort`.
    pub const ERROR_THRESHOLD_RW_SHIFT: u32 = 3;
    pub const ERROR_THRESHOLD_RW_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn error_threshold_rw(&self) -> u16 {
        self.as_ushort.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_error_threshold_rw(&self, value: u16) {
        self.as_ushort.set_bits(3, 1, value as u64)
    }
    /// `ErrorThresholdWindowRW`: bits 4..=4 de `as_ushort`.
    pub const ERROR_THRESHOLD_WINDOW_RW_SHIFT: u32 = 4;
    pub const ERROR_THRESHOLD_WINDOW_RW_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn error_threshold_window_rw(&self) -> u16 {
        self.as_ushort.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_error_threshold_window_rw(&self, value: u16) {
        self.as_ushort.set_bits(4, 1, value as u64)
    }
    /// `Reserved`: bits 5..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 5;
    pub const RESERVED_MASK: u16 = 0xffe0;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(5, 11) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(5, 11, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationFlags>() == 0x2);
    assert!(core::mem::offset_of!(WheaNotificationFlags, as_ushort) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaNotificationDescriptorUView1`..`WheaNotificationDescriptorUView7`, alcançadas por `Deref`.
#[repr(C)]
pub struct WheaNotificationDescriptorU {
    pub polled: WheaNotificationDescriptorUPolled,
    _pad_4: Reserved<0x14>,
}

/// Vista 1 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView1 {
    pub interrupt: WheaNotificationDescriptorUInterrupt,
}

/// Vista 2 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView2 {
    pub local_interrupt: WheaNotificationDescriptorUInterrupt,
}

/// Vista 3 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView3 {
    pub sci: WheaNotificationDescriptorUInterrupt,
}

/// Vista 4 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView4 {
    pub nmi: WheaNotificationDescriptorUInterrupt,
}

/// Vista 5 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView5 {
    pub sea: WheaNotificationDescriptorUInterrupt,
}

/// Vista 6 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView6 {
    pub sei: WheaNotificationDescriptorUInterrupt,
}

/// Vista 7 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUView7 {
    pub gsiv: WheaNotificationDescriptorUInterrupt,
}

impl core::ops::Deref for WheaNotificationDescriptorU {
    type Target = WheaNotificationDescriptorUView1;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView1>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView1 {
    type Target = WheaNotificationDescriptorUView2;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView2>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView2 {
    type Target = WheaNotificationDescriptorUView3;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView3>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView3 {
    type Target = WheaNotificationDescriptorUView4;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView4>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView4 {
    type Target = WheaNotificationDescriptorUView5;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView5>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView5 {
    type Target = WheaNotificationDescriptorUView6;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView6>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUView6 {
    type Target = WheaNotificationDescriptorUView7;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUView7>() }
    }
}

unsafe impl NtStruct for WheaNotificationDescriptorU {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorU>() == 0x18);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorU, polled) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView1>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView1>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView1, interrupt) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView2>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView2>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView2, local_interrupt) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView3>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView3>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView3, sci) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView4>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView4>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView4, nmi) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView5>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView5>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView5, sea) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView6>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView6>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView6, sei) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUView7>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUView7>() == core::mem::align_of::<WheaNotificationDescriptorU>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUView7, gsiv) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u::Polled` (0x4 bytes).
#[repr(C)]
pub struct WheaNotificationDescriptorUPolled {
    pub poll_interval: Field<u32>,
}

unsafe impl NtStruct for WheaNotificationDescriptorUPolled {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUPolled>() == 0x4);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUPolled, poll_interval) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u::Interrupt` (0x18 bytes).
#[repr(C)]
pub struct WheaNotificationDescriptorUInterrupt {
    pub poll_interval: Field<u32>,
    pub vector: Field<u32>,
    pub switch_to_polling_threshold: Field<u32>,
    pub switch_to_polling_window: Field<u32>,
    pub error_threshold: Field<u32>,
    pub error_threshold_window: Field<u32>,
}

unsafe impl NtStruct for WheaNotificationDescriptorUInterrupt {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUInterrupt>() == 0x18);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, poll_interval) == 0x0);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, vector) == 0x4);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, switch_to_polling_threshold) == 0x8);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, switch_to_polling_window) == 0xc);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, error_threshold) == 0x10);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterrupt, error_threshold_window) == 0x14);
};

/// `_WHEA_XPF_NMI_DESCRIPTOR` (0x3 bytes).
#[repr(C)]
pub struct WheaXpfNmiDescriptor {
    pub type_: UnalignedField<u16>,
    pub enabled: Field<u8>,
}

unsafe impl NtStruct for WheaXpfNmiDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaXpfNmiDescriptor>() == 0x3);
    assert!(core::mem::offset_of!(WheaXpfNmiDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaXpfNmiDescriptor, enabled) == 0x2);
};

/// `_WHEA_IPF_MCA_DESCRIPTOR` (0x4 bytes).
#[repr(C)]
pub struct WheaIpfMcaDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
}

unsafe impl NtStruct for WheaIpfMcaDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaIpfMcaDescriptor>() == 0x4);
    assert!(core::mem::offset_of!(WheaIpfMcaDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaIpfMcaDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaIpfMcaDescriptor, reserved) == 0x3);
};

/// `_WHEA_IPF_CMC_DESCRIPTOR` (0x4 bytes).
#[repr(C)]
pub struct WheaIpfCmcDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
}

unsafe impl NtStruct for WheaIpfCmcDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaIpfCmcDescriptor>() == 0x4);
    assert!(core::mem::offset_of!(WheaIpfCmcDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaIpfCmcDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaIpfCmcDescriptor, reserved) == 0x3);
};

/// `_WHEA_IPF_CPE_DESCRIPTOR` (0x4 bytes).
#[repr(C)]
pub struct WheaIpfCpeDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
}

unsafe impl NtStruct for WheaIpfCpeDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaIpfCpeDescriptor>() == 0x4);
    assert!(core::mem::offset_of!(WheaIpfCpeDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaIpfCpeDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaIpfCpeDescriptor, reserved) == 0x3);
};

/// `_WHEA_AER_ROOTPORT_DESCRIPTOR` (0x24 bytes).
#[repr(C)]
pub struct WheaAerRootportDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
    pub bus_number: Field<u32>,
    pub slot: WheaPciSlotNumber,
    pub device_control: Field<u16>,
    pub flags: AerRootportDescriptorFlags,
    pub uncorrectable_error_mask: Field<u32>,
    pub uncorrectable_error_severity: Field<u32>,
    pub correctable_error_mask: Field<u32>,
    pub advanced_caps_and_control: Field<u32>,
    pub root_error_command: Field<u32>,
}

unsafe impl NtStruct for WheaAerRootportDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaAerRootportDescriptor>() == 0x24);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, reserved) == 0x3);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, bus_number) == 0x4);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, slot) == 0x8);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, device_control) == 0xc);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, flags) == 0xe);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, uncorrectable_error_mask) == 0x10);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, uncorrectable_error_severity) == 0x14);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, correctable_error_mask) == 0x18);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, advanced_caps_and_control) == 0x1c);
    assert!(core::mem::offset_of!(WheaAerRootportDescriptor, root_error_command) == 0x20);
};

/// `_WHEA_PCI_SLOT_NUMBER` (0x4 bytes).
#[repr(C)]
pub struct WheaPciSlotNumber {
    pub u: WheaPciSlotNumberU,
}

unsafe impl NtStruct for WheaPciSlotNumber {}

const _: () = {
    assert!(core::mem::size_of::<WheaPciSlotNumber>() == 0x4);
    assert!(core::mem::offset_of!(WheaPciSlotNumber, u) == 0x0);
};

/// `_WHEA_PCI_SLOT_NUMBER::u` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaPciSlotNumberUView1`, alcançada por `Deref`.
#[repr(C)]
pub struct WheaPciSlotNumberU {
    pub bits: WheaPciSlotNumberUBits,
}

/// Vista 1 de `_WHEA_PCI_SLOT_NUMBER::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaPciSlotNumberUView1 {
    pub as_ulong: Field<u32>,
}

impl core::ops::Deref for WheaPciSlotNumberU {
    type Target = WheaPciSlotNumberUView1;
    #[inline(always)]
    fn deref(&self) -> &WheaPciSlotNumberUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaPciSlotNumberUView1>() }
    }
}

unsafe impl NtStruct for WheaPciSlotNumberU {}

const _: () = {
    assert!(core::mem::size_of::<WheaPciSlotNumberU>() == 0x4);
    assert!(core::mem::offset_of!(WheaPciSlotNumberU, bits) == 0x0);
    assert!(core::mem::size_of::<WheaPciSlotNumberUView1>() == 0x4);
    assert!(core::mem::align_of::<WheaPciSlotNumberUView1>() == core::mem::align_of::<WheaPciSlotNumberU>());
    assert!(core::mem::offset_of!(WheaPciSlotNumberUView1, as_ulong) == 0x0);
};

/// `_WHEA_PCI_SLOT_NUMBER::u::bits` (0x4 bytes).
#[repr(C)]
pub struct WheaPciSlotNumberUBits {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for WheaPciSlotNumberUBits {}

impl WheaPciSlotNumberUBits {
    /// `DeviceNumber`: bits 0..=4 de `bitfield_0`.
    pub const DEVICE_NUMBER_SHIFT: u32 = 0;
    pub const DEVICE_NUMBER_MASK: u32 = 0x1f;
    #[inline(always)]
    pub fn device_number(&self) -> u32 {
        self.bitfield_0.bits(0, 5) as u32
    }
    #[inline(always)]
    pub fn set_device_number(&self, value: u32) {
        self.bitfield_0.set_bits(0, 5, value as u64)
    }
    /// `FunctionNumber`: bits 5..=7 de `bitfield_0`.
    pub const FUNCTION_NUMBER_SHIFT: u32 = 5;
    pub const FUNCTION_NUMBER_MASK: u32 = 0xe0;
    #[inline(always)]
    pub fn function_number(&self) -> u32 {
        self.bitfield_0.bits(5, 3) as u32
    }
    #[inline(always)]
    pub fn set_function_number(&self, value: u32) {
        self.bitfield_0.set_bits(5, 3, value as u64)
    }
    /// `Reserved`: bits 8..=31 de `bitfield_0`.
    pub const RESERVED_SHIFT: u32 = 8;
    pub const RESERVED_MASK: u32 = 0xffffff00;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.bitfield_0.bits(8, 24) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.bitfield_0.set_bits(8, 24, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaPciSlotNumberUBits>() == 0x4);
    assert!(core::mem::offset_of!(WheaPciSlotNumberUBits, bitfield_0) == 0x0);
};

/// `_AER_ROOTPORT_DESCRIPTOR_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct AerRootportDescriptorFlags {
    pub as_ushort: Field<u16>,
}

unsafe impl NtStruct for AerRootportDescriptorFlags {}

impl AerRootportDescriptorFlags {
    /// `UncorrectableErrorMaskRW`: bits 0..=0 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 0;
    pub const UNCORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn uncorrectable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `UncorrectableErrorSeverityRW`: bits 1..=1 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_SHIFT: u32 = 1;
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn uncorrectable_error_severity_rw(&self) -> u16 {
        self.as_ushort.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_severity_rw(&self, value: u16) {
        self.as_ushort.set_bits(1, 1, value as u64)
    }
    /// `CorrectableErrorMaskRW`: bits 2..=2 de `as_ushort`.
    pub const CORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 2;
    pub const CORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn correctable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_correctable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(2, 1, value as u64)
    }
    /// `AdvancedCapsAndControlRW`: bits 3..=3 de `as_ushort`.
    pub const ADVANCED_CAPS_AND_CONTROL_RW_SHIFT: u32 = 3;
    pub const ADVANCED_CAPS_AND_CONTROL_RW_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn advanced_caps_and_control_rw(&self) -> u16 {
        self.as_ushort.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_advanced_caps_and_control_rw(&self, value: u16) {
        self.as_ushort.set_bits(3, 1, value as u64)
    }
    /// `RootErrorCommandRW`: bits 4..=4 de `as_ushort`.
    pub const ROOT_ERROR_COMMAND_RW_SHIFT: u32 = 4;
    pub const ROOT_ERROR_COMMAND_RW_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn root_error_command_rw(&self) -> u16 {
        self.as_ushort.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_root_error_command_rw(&self, value: u16) {
        self.as_ushort.set_bits(4, 1, value as u64)
    }
    /// `Reserved`: bits 5..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 5;
    pub const RESERVED_MASK: u16 = 0xffe0;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(5, 11) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(5, 11, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<AerRootportDescriptorFlags>() == 0x2);
    assert!(core::mem::offset_of!(AerRootportDescriptorFlags, as_ushort) == 0x0);
};

/// `_WHEA_AER_ENDPOINT_DESCRIPTOR` (0x20 bytes).
#[repr(C)]
pub struct WheaAerEndpointDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
    pub bus_number: Field<u32>,
    pub slot: WheaPciSlotNumber,
    pub device_control: Field<u16>,
    pub flags: AerEndpointDescriptorFlags,
    pub uncorrectable_error_mask: Field<u32>,
    pub uncorrectable_error_severity: Field<u32>,
    pub correctable_error_mask: Field<u32>,
    pub advanced_caps_and_control: Field<u32>,
}

unsafe impl NtStruct for WheaAerEndpointDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaAerEndpointDescriptor>() == 0x20);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, reserved) == 0x3);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, bus_number) == 0x4);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, slot) == 0x8);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, device_control) == 0xc);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, flags) == 0xe);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, uncorrectable_error_mask) == 0x10);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, uncorrectable_error_severity) == 0x14);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, correctable_error_mask) == 0x18);
    assert!(core::mem::offset_of!(WheaAerEndpointDescriptor, advanced_caps_and_control) == 0x1c);
};

/// `_AER_ENDPOINT_DESCRIPTOR_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct AerEndpointDescriptorFlags {
    pub as_ushort: Field<u16>,
}

unsafe impl NtStruct for AerEndpointDescriptorFlags {}

impl AerEndpointDescriptorFlags {
    /// `UncorrectableErrorMaskRW`: bits 0..=0 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 0;
    pub const UNCORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn uncorrectable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `UncorrectableErrorSeverityRW`: bits 1..=1 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_SHIFT: u32 = 1;
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn uncorrectable_error_severity_rw(&self) -> u16 {
        self.as_ushort.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_severity_rw(&self, value: u16) {
        self.as_ushort.set_bits(1, 1, value as u64)
    }
    /// `CorrectableErrorMaskRW`: bits 2..=2 de `as_ushort`.
    pub const CORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 2;
    pub const CORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn correctable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_correctable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(2, 1, value as u64)
    }
    /// `AdvancedCapsAndControlRW`: bits 3..=3 de `as_ushort`.
    pub const ADVANCED_CAPS_AND_CONTROL_RW_SHIFT: u32 = 3;
    pub const ADVANCED_CAPS_AND_CONTROL_RW_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn advanced_caps_and_control_rw(&self) -> u16 {
        self.as_ushort.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_advanced_caps_and_control_rw(&self, value: u16) {
        self.as_ushort.set_bits(3, 1, value as u64)
    }
    /// `Reserved`: bits 4..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 4;
    pub const RESERVED_MASK: u16 = 0xfff0;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(4, 12) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(4, 12, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<AerEndpointDescriptorFlags>() == 0x2);
    assert!(core::mem::offset_of!(AerEndpointDescriptorFlags, as_ushort) == 0x0);
};

/// `_WHEA_AER_BRIDGE_DESCRIPTOR` (0x2c bytes).
#[repr(C)]
pub struct WheaAerBridgeDescriptor {
    pub type_: Field<u16>,
    pub enabled: Field<u8>,
    pub reserved: Field<u8>,
    pub bus_number: Field<u32>,
    pub slot: WheaPciSlotNumber,
    pub device_control: Field<u16>,
    pub flags: AerBridgeDescriptorFlags,
    pub uncorrectable_error_mask: Field<u32>,
    pub uncorrectable_error_severity: Field<u32>,
    pub correctable_error_mask: Field<u32>,
    pub advanced_caps_and_control: Field<u32>,
    pub secondary_uncorrectable_error_mask: Field<u32>,
    pub secondary_uncorrectable_error_sev: Field<u32>,
    pub secondary_caps_and_control: Field<u32>,
}

unsafe impl NtStruct for WheaAerBridgeDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaAerBridgeDescriptor>() == 0x2c);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, reserved) == 0x3);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, bus_number) == 0x4);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, slot) == 0x8);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, device_control) == 0xc);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, flags) == 0xe);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, uncorrectable_error_mask) == 0x10);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, uncorrectable_error_severity) == 0x14);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, correctable_error_mask) == 0x18);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, advanced_caps_and_control) == 0x1c);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, secondary_uncorrectable_error_mask) == 0x20);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, secondary_uncorrectable_error_sev) == 0x24);
    assert!(core::mem::offset_of!(WheaAerBridgeDescriptor, secondary_caps_and_control) == 0x28);
};

/// `_AER_BRIDGE_DESCRIPTOR_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct AerBridgeDescriptorFlags {
    pub as_ushort: Field<u16>,
}

unsafe impl NtStruct for AerBridgeDescriptorFlags {}

impl AerBridgeDescriptorFlags {
    /// `UncorrectableErrorMaskRW`: bits 0..=0 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 0;
    pub const UNCORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn uncorrectable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `UncorrectableErrorSeverityRW`: bits 1..=1 de `as_ushort`.
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_SHIFT: u32 = 1;
    pub const UNCORRECTABLE_ERROR_SEVERITY_RW_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn uncorrectable_error_severity_rw(&self) -> u16 {
        self.as_ushort.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_uncorrectable_error_severity_rw(&self, value: u16) {
        self.as_ushort.set_bits(1, 1, value as u64)
    }
    /// `CorrectableErrorMaskRW`: bits 2..=2 de `as_ushort`.
    pub const CORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 2;
    pub const CORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn correctable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_correctable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(2, 1, value as u64)
    }
    /// `AdvancedCapsAndControlRW`: bits 3..=3 de `as_ushort`.
    pub const ADVANCED_CAPS_AND_CONTROL_RW_SHIFT: u32 = 3;
    pub const ADVANCED_CAPS_AND_CONTROL_RW_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn advanced_caps_and_control_rw(&self) -> u16 {
        self.as_ushort.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_advanced_caps_and_control_rw(&self, value: u16) {
        self.as_ushort.set_bits(3, 1, value as u64)
    }
    /// `SecondaryUncorrectableErrorMaskRW`: bits 4..=4 de `as_ushort`.
    pub const SECONDARY_UNCORRECTABLE_ERROR_MASK_RW_SHIFT: u32 = 4;
    pub const SECONDARY_UNCORRECTABLE_ERROR_MASK_RW_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn secondary_uncorrectable_error_mask_rw(&self) -> u16 {
        self.as_ushort.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_secondary_uncorrectable_error_mask_rw(&self, value: u16) {
        self.as_ushort.set_bits(4, 1, value as u64)
    }
    /// `SecondaryUncorrectableErrorSevRW`: bits 5..=5 de `as_ushort`.
    pub const SECONDARY_UNCORRECTABLE_ERROR_SEV_RW_SHIFT: u32 = 5;
    pub const SECONDARY_UNCORRECTABLE_ERROR_SEV_RW_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn secondary_uncorrectable_error_sev_rw(&self) -> u16 {
        self.as_ushort.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_secondary_uncorrectable_error_sev_rw(&self, value: u16) {
        self.as_ushort.set_bits(5, 1, value as u64)
    }
    /// `SecondaryCapsAndControlRW`: bits 6..=6 de `as_ushort`.
    pub const SECONDARY_CAPS_AND_CONTROL_RW_SHIFT: u32 = 6;
    pub const SECONDARY_CAPS_AND_CONTROL_RW_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn secondary_caps_and_control_rw(&self) -> u16 {
        self.as_ushort.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_secondary_caps_and_control_rw(&self, value: u16) {
        self.as_ushort.set_bits(6, 1, value as u64)
    }
    /// `Reserved`: bits 7..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 7;
    pub const RESERVED_MASK: u16 = 0xff80;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(7, 9) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(7, 9, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<AerBridgeDescriptorFlags>() == 0x2);
    assert!(core::mem::offset_of!(AerBridgeDescriptorFlags, as_ushort) == 0x0);
};

/// `_WHEA_GENERIC_ERROR_DESCRIPTOR` (0x34 bytes).
#[repr(C)]
pub struct WheaGenericErrorDescriptor {
    pub type_: Field<u16>,
    pub reserved: Field<u8>,
    pub enabled: Field<u8>,
    pub err_status_block_length: Field<u32>,
    pub related_error_source_id: Field<u32>,
    pub err_status_address_space_id: Field<u8>,
    pub err_status_address_bit_width: Field<u8>,
    pub err_status_address_bit_offset: Field<u8>,
    pub err_status_address_access_size: Field<u8>,
    pub err_status_address: LargeIntegerUnaligned,
    pub notify: WheaNotificationDescriptor,
}

unsafe impl NtStruct for WheaGenericErrorDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<WheaGenericErrorDescriptor>() == 0x34);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, reserved) == 0x2);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, enabled) == 0x3);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_block_length) == 0x4);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, related_error_source_id) == 0x8);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_address_space_id) == 0xc);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_address_bit_width) == 0xd);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_address_bit_offset) == 0xe);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_address_access_size) == 0xf);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, err_status_address) == 0x10);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptor, notify) == 0x18);
};

/// `_WHEA_XPF_MCE_DESCRIPTOR` (0x398 bytes).
#[repr(C)]
pub struct WheaXpfMceDescriptorUnaligned {
    pub type_: UnalignedField<u16>,
    pub enabled: UnalignedField<u8>,
    pub number_of_banks: UnalignedField<u8>,
    pub flags: XpfMceFlagsUnaligned,
    pub mcg_capability: UnalignedField<u64>,
    pub mcg_global_control: UnalignedField<u64>,
    pub banks: [WheaXpfMcBankDescriptorUnaligned; 32],
}

unsafe impl NtStruct for WheaXpfMceDescriptorUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaXpfMceDescriptorUnaligned>() == 0x398);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, enabled) == 0x2);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, number_of_banks) == 0x3);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, flags) == 0x4);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, mcg_capability) == 0x8);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, mcg_global_control) == 0x10);
    assert!(core::mem::offset_of!(WheaXpfMceDescriptorUnaligned, banks) == 0x18);
};

/// `_XPF_MCE_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct XpfMceFlagsUnaligned {
    pub as_ulong: UnalignedField<u32>,
}

unsafe impl NtStruct for XpfMceFlagsUnaligned {}

impl XpfMceFlagsUnaligned {
    /// `MCG_CapabilityRW`: bits 0..=0 de `as_ulong`.
    pub const MCG_CAPABILITY_RW_SHIFT: u32 = 0;
    pub const MCG_CAPABILITY_RW_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn mcg_capability_rw(&self) -> u32 {
        self.as_ulong.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_mcg_capability_rw(&self, value: u32) {
        self.as_ulong.set_bits(0, 1, value as u64)
    }
    /// `MCG_GlobalControlRW`: bits 1..=1 de `as_ulong`.
    pub const MCG_GLOBAL_CONTROL_RW_SHIFT: u32 = 1;
    pub const MCG_GLOBAL_CONTROL_RW_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn mcg_global_control_rw(&self) -> u32 {
        self.as_ulong.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_mcg_global_control_rw(&self, value: u32) {
        self.as_ulong.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=31 de `as_ulong`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u32 = 0xfffffffc;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.as_ulong.bits(2, 30) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.as_ulong.set_bits(2, 30, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<XpfMceFlagsUnaligned>() == 0x4);
    assert!(core::mem::offset_of!(XpfMceFlagsUnaligned, as_ulong) == 0x0);
};

/// `_WHEA_XPF_MC_BANK_DESCRIPTOR` (0x1c bytes).
#[repr(C)]
pub struct WheaXpfMcBankDescriptorUnaligned {
    pub bank_number: UnalignedField<u8>,
    pub clear_on_initialization: UnalignedField<u8>,
    pub status_data_format: UnalignedField<u8>,
    pub flags: XpfMcBankFlagsUnaligned,
    pub control_msr: UnalignedField<u32>,
    pub status_msr: UnalignedField<u32>,
    pub address_msr: UnalignedField<u32>,
    pub misc_msr: UnalignedField<u32>,
    pub control_data: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaXpfMcBankDescriptorUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaXpfMcBankDescriptorUnaligned>() == 0x1c);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, bank_number) == 0x0);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, clear_on_initialization) == 0x1);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, status_data_format) == 0x2);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, flags) == 0x3);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, control_msr) == 0x4);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, status_msr) == 0x8);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, address_msr) == 0xc);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, misc_msr) == 0x10);
    assert!(core::mem::offset_of!(WheaXpfMcBankDescriptorUnaligned, control_data) == 0x14);
};

/// `_XPF_MC_BANK_FLAGS` (0x1 bytes).
#[repr(C)]
pub struct XpfMcBankFlagsUnaligned {
    pub as_uchar: UnalignedField<u8>,
}

unsafe impl NtStruct for XpfMcBankFlagsUnaligned {}

impl XpfMcBankFlagsUnaligned {
    /// `ClearOnInitializationRW`: bits 0..=0 de `as_uchar`.
    pub const CLEAR_ON_INITIALIZATION_RW_SHIFT: u32 = 0;
    pub const CLEAR_ON_INITIALIZATION_RW_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn clear_on_initialization_rw(&self) -> u8 {
        self.as_uchar.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_clear_on_initialization_rw(&self, value: u8) {
        self.as_uchar.set_bits(0, 1, value as u64)
    }
    /// `ControlDataRW`: bits 1..=1 de `as_uchar`.
    pub const CONTROL_DATA_RW_SHIFT: u32 = 1;
    pub const CONTROL_DATA_RW_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn control_data_rw(&self) -> u8 {
        self.as_uchar.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_control_data_rw(&self, value: u8) {
        self.as_uchar.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=7 de `as_uchar`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.as_uchar.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.as_uchar.set_bits(2, 6, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<XpfMcBankFlagsUnaligned>() == 0x1);
    assert!(core::mem::offset_of!(XpfMcBankFlagsUnaligned, as_uchar) == 0x0);
};

/// `_WHEA_GENERIC_ERROR_DESCRIPTOR_V2` (0x50 bytes).
#[repr(C)]
pub struct WheaGenericErrorDescriptorV2Unaligned {
    pub type_: UnalignedField<u16>,
    pub reserved: UnalignedField<u8>,
    pub enabled: UnalignedField<u8>,
    pub err_status_block_length: UnalignedField<u32>,
    pub related_error_source_id: UnalignedField<u32>,
    pub err_status_address_space_id: UnalignedField<u8>,
    pub err_status_address_bit_width: UnalignedField<u8>,
    pub err_status_address_bit_offset: UnalignedField<u8>,
    pub err_status_address_access_size: UnalignedField<u8>,
    pub err_status_address: LargeIntegerUnaligned,
    pub notify: WheaNotificationDescriptorUnaligned,
    pub read_ack_address_space_id: UnalignedField<u8>,
    pub read_ack_address_bit_width: UnalignedField<u8>,
    pub read_ack_address_bit_offset: UnalignedField<u8>,
    pub read_ack_address_access_size: UnalignedField<u8>,
    pub read_ack_address: LargeIntegerUnaligned,
    pub read_ack_preserve_mask: UnalignedField<u64>,
    pub read_ack_write_mask: UnalignedField<u64>,
}

unsafe impl NtStruct for WheaGenericErrorDescriptorV2Unaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaGenericErrorDescriptorV2Unaligned>() == 0x50);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, reserved) == 0x2);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, enabled) == 0x3);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_block_length) == 0x4);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, related_error_source_id) == 0x8);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_address_space_id) == 0xc);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_address_bit_width) == 0xd);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_address_bit_offset) == 0xe);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_address_access_size) == 0xf);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, err_status_address) == 0x10);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, notify) == 0x18);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_address_space_id) == 0x34);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_address_bit_width) == 0x35);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_address_bit_offset) == 0x36);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_address_access_size) == 0x37);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_address) == 0x38);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_preserve_mask) == 0x40);
    assert!(core::mem::offset_of!(WheaGenericErrorDescriptorV2Unaligned, read_ack_write_mask) == 0x48);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR` (0x1c bytes).
#[repr(C)]
pub struct WheaNotificationDescriptorUnaligned {
    pub type_: UnalignedField<u8>,
    pub length: UnalignedField<u8>,
    pub flags: WheaNotificationFlagsUnaligned,
    pub u: WheaNotificationDescriptorUUnaligned,
}

unsafe impl NtStruct for WheaNotificationDescriptorUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUnaligned>() == 0x1c);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUnaligned, type_) == 0x0);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUnaligned, length) == 0x1);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUnaligned, flags) == 0x2);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUnaligned, u) == 0x4);
};

/// `_WHEA_NOTIFICATION_FLAGS` (0x2 bytes).
#[repr(C)]
pub struct WheaNotificationFlagsUnaligned {
    pub as_ushort: UnalignedField<u16>,
}

unsafe impl NtStruct for WheaNotificationFlagsUnaligned {}

impl WheaNotificationFlagsUnaligned {
    /// `PollIntervalRW`: bits 0..=0 de `as_ushort`.
    pub const POLL_INTERVAL_RW_SHIFT: u32 = 0;
    pub const POLL_INTERVAL_RW_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn poll_interval_rw(&self) -> u16 {
        self.as_ushort.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_poll_interval_rw(&self, value: u16) {
        self.as_ushort.set_bits(0, 1, value as u64)
    }
    /// `SwitchToPollingThresholdRW`: bits 1..=1 de `as_ushort`.
    pub const SWITCH_TO_POLLING_THRESHOLD_RW_SHIFT: u32 = 1;
    pub const SWITCH_TO_POLLING_THRESHOLD_RW_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn switch_to_polling_threshold_rw(&self) -> u16 {
        self.as_ushort.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_switch_to_polling_threshold_rw(&self, value: u16) {
        self.as_ushort.set_bits(1, 1, value as u64)
    }
    /// `SwitchToPollingWindowRW`: bits 2..=2 de `as_ushort`.
    pub const SWITCH_TO_POLLING_WINDOW_RW_SHIFT: u32 = 2;
    pub const SWITCH_TO_POLLING_WINDOW_RW_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn switch_to_polling_window_rw(&self) -> u16 {
        self.as_ushort.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_switch_to_polling_window_rw(&self, value: u16) {
        self.as_ushort.set_bits(2, 1, value as u64)
    }
    /// `ErrorThresholdRW`: bits 3..=3 de `as_ushort`.
    pub const ERROR_THRESHOLD_RW_SHIFT: u32 = 3;
    pub const ERROR_THRESHOLD_RW_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn error_threshold_rw(&self) -> u16 {
        self.as_ushort.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_error_threshold_rw(&self, value: u16) {
        self.as_ushort.set_bits(3, 1, value as u64)
    }
    /// `ErrorThresholdWindowRW`: bits 4..=4 de `as_ushort`.
    pub const ERROR_THRESHOLD_WINDOW_RW_SHIFT: u32 = 4;
    pub const ERROR_THRESHOLD_WINDOW_RW_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn error_threshold_window_rw(&self) -> u16 {
        self.as_ushort.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_error_threshold_window_rw(&self, value: u16) {
        self.as_ushort.set_bits(4, 1, value as u64)
    }
    /// `Reserved`: bits 5..=15 de `as_ushort`.
    pub const RESERVED_SHIFT: u32 = 5;
    pub const RESERVED_MASK: u16 = 0xffe0;
    #[inline(always)]
    pub fn reserved(&self) -> u16 {
        self.as_ushort.bits(5, 11) as u16
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u16) {
        self.as_ushort.set_bits(5, 11, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationFlagsUnaligned>() == 0x2);
    assert!(core::mem::offset_of!(WheaNotificationFlagsUnaligned, as_ushort) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `WheaNotificationDescriptorUUnalignedView1`..`WheaNotificationDescriptorUUnalignedView7`, alcançadas por `Deref`.
#[repr(C)]
pub struct WheaNotificationDescriptorUUnaligned {
    pub polled: WheaNotificationDescriptorUPolledUnaligned,
    _pad_4: Reserved<0x14>,
}

/// Vista 1 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView1 {
    pub interrupt: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 2 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView2 {
    pub local_interrupt: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 3 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView3 {
    pub sci: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 4 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView4 {
    pub nmi: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 5 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView5 {
    pub sea: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 6 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView6 {
    pub sei: WheaNotificationDescriptorUInterruptUnaligned,
}

/// Vista 7 de `_WHEA_NOTIFICATION_DESCRIPTOR::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct WheaNotificationDescriptorUUnalignedView7 {
    pub gsiv: WheaNotificationDescriptorUInterruptUnaligned,
}

impl core::ops::Deref for WheaNotificationDescriptorUUnaligned {
    type Target = WheaNotificationDescriptorUUnalignedView1;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView1>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView1 {
    type Target = WheaNotificationDescriptorUUnalignedView2;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView2>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView2 {
    type Target = WheaNotificationDescriptorUUnalignedView3;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView3>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView3 {
    type Target = WheaNotificationDescriptorUUnalignedView4;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView4>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView4 {
    type Target = WheaNotificationDescriptorUUnalignedView5;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView5>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView5 {
    type Target = WheaNotificationDescriptorUUnalignedView6;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView6>() }
    }
}

impl core::ops::Deref for WheaNotificationDescriptorUUnalignedView6 {
    type Target = WheaNotificationDescriptorUUnalignedView7;
    #[inline(always)]
    fn deref(&self) -> &WheaNotificationDescriptorUUnalignedView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<WheaNotificationDescriptorUUnalignedView7>() }
    }
}

unsafe impl NtStruct for WheaNotificationDescriptorUUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnaligned>() == 0x18);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnaligned, polled) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView1>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView1>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView1, interrupt) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView2>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView2>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView2, local_interrupt) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView3>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView3>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView3, sci) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView4>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView4>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView4, nmi) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView5>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView5>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView5, sea) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView6>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView6>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView6, sei) == 0x0);
    assert!(core::mem::size_of::<WheaNotificationDescriptorUUnalignedView7>() == 0x18);
    assert!(core::mem::align_of::<WheaNotificationDescriptorUUnalignedView7>() == core::mem::align_of::<WheaNotificationDescriptorUUnaligned>());
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUUnalignedView7, gsiv) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u::Polled` (0x4 bytes).
#[repr(C)]
pub struct WheaNotificationDescriptorUPolledUnaligned {
    pub poll_interval: UnalignedField<u32>,
}

unsafe impl NtStruct for WheaNotificationDescriptorUPolledUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUPolledUnaligned>() == 0x4);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUPolledUnaligned, poll_interval) == 0x0);
};

/// `_WHEA_NOTIFICATION_DESCRIPTOR::u::Interrupt` (0x18 bytes).
#[repr(C)]
pub struct WheaNotificationDescriptorUInterruptUnaligned {
    pub poll_interval: UnalignedField<u32>,
    pub vector: UnalignedField<u32>,
    pub switch_to_polling_threshold: UnalignedField<u32>,
    pub switch_to_polling_window: UnalignedField<u32>,
    pub error_threshold: UnalignedField<u32>,
    pub error_threshold_window: UnalignedField<u32>,
}

unsafe impl NtStruct for WheaNotificationDescriptorUInterruptUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<WheaNotificationDescriptorUInterruptUnaligned>() == 0x18);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, poll_interval) == 0x0);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, vector) == 0x4);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, switch_to_polling_threshold) == 0x8);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, switch_to_polling_window) == 0xc);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, error_threshold) == 0x10);
    assert!(core::mem::offset_of!(WheaNotificationDescriptorUInterruptUnaligned, error_threshold_window) == 0x14);
};
