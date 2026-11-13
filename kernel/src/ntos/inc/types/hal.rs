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
