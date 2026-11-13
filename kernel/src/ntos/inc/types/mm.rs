//! Mm: MDLs, seções, entradas do loader e cabeçalhos PE.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_MDL` (0x30 bytes).
#[repr(C)]
pub struct Mdl {
    /// -> `_MDL`
    pub next: Field<u64>,
    pub size: Field<i16>,
    pub mdl_flags: Field<i16>,
    _pad_c: Reserved<0x4>,
    /// -> `_EPROCESS`
    pub process: Field<u64>,
    /// -> `void`
    pub mapped_system_va: Field<u64>,
    /// -> `void`
    pub start_va: Field<u64>,
    pub byte_count: Field<u32>,
    pub byte_offset: Field<u32>,
}

unsafe impl NtStruct for Mdl {}

const _: () = {
    assert!(core::mem::size_of::<Mdl>() == 0x30);
    assert!(core::mem::offset_of!(Mdl, next) == 0x0);
    assert!(core::mem::offset_of!(Mdl, size) == 0x8);
    assert!(core::mem::offset_of!(Mdl, mdl_flags) == 0xa);
    assert!(core::mem::offset_of!(Mdl, process) == 0x10);
    assert!(core::mem::offset_of!(Mdl, mapped_system_va) == 0x18);
    assert!(core::mem::offset_of!(Mdl, start_va) == 0x20);
    assert!(core::mem::offset_of!(Mdl, byte_count) == 0x28);
    assert!(core::mem::offset_of!(Mdl, byte_offset) == 0x2c);
};

/// `_MMSUPPORT_FULL` (0x140 bytes).
#[repr(C)]
pub struct MmsupportFull {
    pub instance: MmsupportInstance,
    pub shared: MmsupportShared,
}

unsafe impl NtStruct for MmsupportFull {}

const _: () = {
    assert!(core::mem::size_of::<MmsupportFull>() == 0x140);
    assert!(core::mem::offset_of!(MmsupportFull, instance) == 0x0);
    assert!(core::mem::offset_of!(MmsupportFull, shared) == 0xc0);
};

/// `_MMSUPPORT_INSTANCE` (0xc0 bytes).
#[repr(C)]
pub struct MmsupportInstance {
    pub next_page_color: Field<u32>,
    pub page_fault_count: Field<u32>,
    pub trimmed_page_count: Field<u64>,
    /// -> `_MMWSL_INSTANCE`
    pub vm_working_set_list: Field<u64>,
    pub working_set_expansion_links: ListEntry,
    pub age_distribution: [Field<u64>; 8],
    /// -> `_KGATE`
    pub exit_outswap_gate: Field<u64>,
    pub minimum_working_set_size: Field<u64>,
    pub working_set_leaf_size: Field<u64>,
    pub working_set_leaf_private_size: Field<u64>,
    pub working_set_size: Field<u64>,
    pub working_set_private_size: Field<u64>,
    pub maximum_working_set_size: Field<u64>,
    pub peak_working_set_size: Field<u64>,
    pub hard_fault_count: Field<u32>,
    pub last_trim_stamp: Field<u16>,
    pub partition_id: Field<u16>,
    pub selfmap_lock: Field<u64>,
    pub flags: MmsupportFlags,
    _pad_bc: Reserved<0x4>,
}

unsafe impl NtStruct for MmsupportInstance {}

const _: () = {
    assert!(core::mem::size_of::<MmsupportInstance>() == 0xc0);
    assert!(core::mem::offset_of!(MmsupportInstance, next_page_color) == 0x0);
    assert!(core::mem::offset_of!(MmsupportInstance, page_fault_count) == 0x4);
    assert!(core::mem::offset_of!(MmsupportInstance, trimmed_page_count) == 0x8);
    assert!(core::mem::offset_of!(MmsupportInstance, vm_working_set_list) == 0x10);
    assert!(core::mem::offset_of!(MmsupportInstance, working_set_expansion_links) == 0x18);
    assert!(core::mem::offset_of!(MmsupportInstance, age_distribution) == 0x28);
    assert!(core::mem::offset_of!(MmsupportInstance, exit_outswap_gate) == 0x68);
    assert!(core::mem::offset_of!(MmsupportInstance, minimum_working_set_size) == 0x70);
    assert!(core::mem::offset_of!(MmsupportInstance, working_set_leaf_size) == 0x78);
    assert!(core::mem::offset_of!(MmsupportInstance, working_set_leaf_private_size) == 0x80);
    assert!(core::mem::offset_of!(MmsupportInstance, working_set_size) == 0x88);
    assert!(core::mem::offset_of!(MmsupportInstance, working_set_private_size) == 0x90);
    assert!(core::mem::offset_of!(MmsupportInstance, maximum_working_set_size) == 0x98);
    assert!(core::mem::offset_of!(MmsupportInstance, peak_working_set_size) == 0xa0);
    assert!(core::mem::offset_of!(MmsupportInstance, hard_fault_count) == 0xa8);
    assert!(core::mem::offset_of!(MmsupportInstance, last_trim_stamp) == 0xac);
    assert!(core::mem::offset_of!(MmsupportInstance, partition_id) == 0xae);
    assert!(core::mem::offset_of!(MmsupportInstance, selfmap_lock) == 0xb0);
    assert!(core::mem::offset_of!(MmsupportInstance, flags) == 0xb8);
};

/// `_MMSUPPORT_FLAGS` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmsupportFlagsView1`, alcançada por `Deref`.
#[repr(C)]
pub struct MmsupportFlags {
    _align: [u16; 0],
    pub bitfield_0: Field<u8>,
    pub bitfield_1: Field<u8>,
    pub memory_priority: Field<u8>,
    pub u2: Field<u8>,
}

/// Vista 1 de `_MMSUPPORT_FLAGS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmsupportFlagsView1 {
    pub u1: Field<u16>,
    _pad_2: Reserved<0x2>,
}

impl core::ops::Deref for MmsupportFlags {
    type Target = MmsupportFlagsView1;
    #[inline(always)]
    fn deref(&self) -> &MmsupportFlagsView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmsupportFlagsView1>() }
    }
}

unsafe impl NtStruct for MmsupportFlags {}

impl MmsupportFlags {
    /// `WorkingSetType`: bits 0..=2 de `bitfield_0`.
    pub const WORKING_SET_TYPE_SHIFT: u32 = 0;
    pub const WORKING_SET_TYPE_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn working_set_type(&self) -> u8 {
        self.bitfield_0.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_working_set_type(&self, value: u8) {
        self.bitfield_0.set_bits(0, 3, value as u64)
    }
    /// `Reserved0`: bits 3..=5 de `bitfield_0`.
    pub const RESERVED0_SHIFT: u32 = 3;
    pub const RESERVED0_MASK: u8 = 0x38;
    #[inline(always)]
    pub fn reserved0(&self) -> u8 {
        self.bitfield_0.bits(3, 3) as u8
    }
    #[inline(always)]
    pub fn set_reserved0(&self, value: u8) {
        self.bitfield_0.set_bits(3, 3, value as u64)
    }
    /// `MaximumWorkingSetHard`: bits 6..=6 de `bitfield_0`.
    pub const MAXIMUM_WORKING_SET_HARD_SHIFT: u32 = 6;
    pub const MAXIMUM_WORKING_SET_HARD_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn maximum_working_set_hard(&self) -> u8 {
        self.bitfield_0.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_maximum_working_set_hard(&self, value: u8) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `MinimumWorkingSetHard`: bits 7..=7 de `bitfield_0`.
    pub const MINIMUM_WORKING_SET_HARD_SHIFT: u32 = 7;
    pub const MINIMUM_WORKING_SET_HARD_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn minimum_working_set_hard(&self) -> u8 {
        self.bitfield_0.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_minimum_working_set_hard(&self, value: u8) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `SessionMaster`: bits 0..=0 de `bitfield_1`.
    pub const SESSION_MASTER_SHIFT: u32 = 0;
    pub const SESSION_MASTER_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn session_master(&self) -> u8 {
        self.bitfield_1.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_session_master(&self, value: u8) {
        self.bitfield_1.set_bits(0, 1, value as u64)
    }
    /// `TrimmerState`: bits 1..=2 de `bitfield_1`.
    pub const TRIMMER_STATE_SHIFT: u32 = 1;
    pub const TRIMMER_STATE_MASK: u8 = 0x6;
    #[inline(always)]
    pub fn trimmer_state(&self) -> u8 {
        self.bitfield_1.bits(1, 2) as u8
    }
    #[inline(always)]
    pub fn set_trimmer_state(&self, value: u8) {
        self.bitfield_1.set_bits(1, 2, value as u64)
    }
    /// `Reserved`: bits 3..=3 de `bitfield_1`.
    pub const RESERVED_SHIFT: u32 = 3;
    pub const RESERVED_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.bitfield_1.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.bitfield_1.set_bits(3, 1, value as u64)
    }
    /// `PageStealers`: bits 4..=7 de `bitfield_1`.
    pub const PAGE_STEALERS_SHIFT: u32 = 4;
    pub const PAGE_STEALERS_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn page_stealers(&self) -> u8 {
        self.bitfield_1.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_page_stealers(&self, value: u8) {
        self.bitfield_1.set_bits(4, 4, value as u64)
    }
    /// `WsleDeleted`: bits 0..=0 de `u2`.
    pub const WSLE_DELETED_SHIFT: u32 = 0;
    pub const WSLE_DELETED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn wsle_deleted(&self) -> u8 {
        self.u2.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_wsle_deleted(&self, value: u8) {
        self.u2.set_bits(0, 1, value as u64)
    }
    /// `SvmEnabled`: bits 1..=1 de `u2`.
    pub const SVM_ENABLED_SHIFT: u32 = 1;
    pub const SVM_ENABLED_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn svm_enabled(&self) -> u8 {
        self.u2.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_svm_enabled(&self, value: u8) {
        self.u2.set_bits(1, 1, value as u64)
    }
    /// `ForceAge`: bits 2..=2 de `u2`.
    pub const FORCE_AGE_SHIFT: u32 = 2;
    pub const FORCE_AGE_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn force_age(&self) -> u8 {
        self.u2.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_force_age(&self, value: u8) {
        self.u2.set_bits(2, 1, value as u64)
    }
    /// `ForceTrim`: bits 3..=3 de `u2`.
    pub const FORCE_TRIM_SHIFT: u32 = 3;
    pub const FORCE_TRIM_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn force_trim(&self) -> u8 {
        self.u2.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_force_trim(&self, value: u8) {
        self.u2.set_bits(3, 1, value as u64)
    }
    /// `NewMaximum`: bits 4..=4 de `u2`.
    pub const NEW_MAXIMUM_SHIFT: u32 = 4;
    pub const NEW_MAXIMUM_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn new_maximum(&self) -> u8 {
        self.u2.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_new_maximum(&self, value: u8) {
        self.u2.set_bits(4, 1, value as u64)
    }
    /// `CommitReleaseState`: bits 5..=6 de `u2`.
    pub const COMMIT_RELEASE_STATE_SHIFT: u32 = 5;
    pub const COMMIT_RELEASE_STATE_MASK: u8 = 0x60;
    #[inline(always)]
    pub fn commit_release_state(&self) -> u8 {
        self.u2.bits(5, 2) as u8
    }
    #[inline(always)]
    pub fn set_commit_release_state(&self, value: u8) {
        self.u2.set_bits(5, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmsupportFlags>() == 0x4);
    assert!(core::mem::offset_of!(MmsupportFlags, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(MmsupportFlags, bitfield_1) == 0x1);
    assert!(core::mem::offset_of!(MmsupportFlags, memory_priority) == 0x2);
    assert!(core::mem::offset_of!(MmsupportFlags, u2) == 0x3);
    assert!(core::mem::size_of::<MmsupportFlagsView1>() == 0x4);
    assert!(core::mem::align_of::<MmsupportFlagsView1>() == core::mem::align_of::<MmsupportFlags>());
    assert!(core::mem::offset_of!(MmsupportFlagsView1, u1) == 0x0);
};

/// `_KLDR_DATA_TABLE_ENTRY` (0xa0 bytes).
#[repr(C)]
pub struct KldrDataTableEntry {
    pub in_load_order_links: ListEntry,
    /// -> `void`
    pub exception_table: Field<u64>,
    pub exception_table_size: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub gp_value: Field<u64>,
    /// -> `_NON_PAGED_DEBUG_INFO`
    pub non_paged_debug_info: Field<u64>,
    /// -> `void`
    pub dll_base: Field<u64>,
    /// -> `void`
    pub entry_point: Field<u64>,
    pub size_of_image: Field<u32>,
    _pad_44: Reserved<0x4>,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flags: Field<u32>,
    pub load_count: Field<u16>,
    pub u1: KldrDataTableEntryU1,
    /// -> `void`
    pub section_pointer: Field<u64>,
    pub check_sum: Field<u32>,
    pub coverage_section_size: Field<u32>,
    /// -> `void`
    pub coverage_section: Field<u64>,
    /// -> `void`
    pub loaded_imports: Field<u64>,
    /// -> `void`
    pub spare: Field<u64>,
    pub size_of_image_not_rounded: Field<u32>,
    pub time_date_stamp: Field<u32>,
}

unsafe impl NtStruct for KldrDataTableEntry {}

const _: () = {
    assert!(core::mem::size_of::<KldrDataTableEntry>() == 0xa0);
    assert!(core::mem::offset_of!(KldrDataTableEntry, in_load_order_links) == 0x0);
    assert!(core::mem::offset_of!(KldrDataTableEntry, exception_table) == 0x10);
    assert!(core::mem::offset_of!(KldrDataTableEntry, exception_table_size) == 0x18);
    assert!(core::mem::offset_of!(KldrDataTableEntry, gp_value) == 0x20);
    assert!(core::mem::offset_of!(KldrDataTableEntry, non_paged_debug_info) == 0x28);
    assert!(core::mem::offset_of!(KldrDataTableEntry, dll_base) == 0x30);
    assert!(core::mem::offset_of!(KldrDataTableEntry, entry_point) == 0x38);
    assert!(core::mem::offset_of!(KldrDataTableEntry, size_of_image) == 0x40);
    assert!(core::mem::offset_of!(KldrDataTableEntry, full_dll_name) == 0x48);
    assert!(core::mem::offset_of!(KldrDataTableEntry, base_dll_name) == 0x58);
    assert!(core::mem::offset_of!(KldrDataTableEntry, flags) == 0x68);
    assert!(core::mem::offset_of!(KldrDataTableEntry, load_count) == 0x6c);
    assert!(core::mem::offset_of!(KldrDataTableEntry, u1) == 0x6e);
    assert!(core::mem::offset_of!(KldrDataTableEntry, section_pointer) == 0x70);
    assert!(core::mem::offset_of!(KldrDataTableEntry, check_sum) == 0x78);
    assert!(core::mem::offset_of!(KldrDataTableEntry, coverage_section_size) == 0x7c);
    assert!(core::mem::offset_of!(KldrDataTableEntry, coverage_section) == 0x80);
    assert!(core::mem::offset_of!(KldrDataTableEntry, loaded_imports) == 0x88);
    assert!(core::mem::offset_of!(KldrDataTableEntry, spare) == 0x90);
    assert!(core::mem::offset_of!(KldrDataTableEntry, size_of_image_not_rounded) == 0x98);
    assert!(core::mem::offset_of!(KldrDataTableEntry, time_date_stamp) == 0x9c);
};

/// `_KLDR_DATA_TABLE_ENTRY::u1` (0x2 bytes).
#[repr(C)]
pub struct KldrDataTableEntryU1 {
    pub entire_field: Field<u16>,
}

unsafe impl NtStruct for KldrDataTableEntryU1 {}

impl KldrDataTableEntryU1 {
    /// `SignatureLevel`: bits 0..=3 de `entire_field`.
    pub const SIGNATURE_LEVEL_SHIFT: u32 = 0;
    pub const SIGNATURE_LEVEL_MASK: u16 = 0xf;
    #[inline(always)]
    pub fn signature_level(&self) -> u16 {
        self.entire_field.bits(0, 4) as u16
    }
    #[inline(always)]
    pub fn set_signature_level(&self, value: u16) {
        self.entire_field.set_bits(0, 4, value as u64)
    }
    /// `SignatureType`: bits 4..=6 de `entire_field`.
    pub const SIGNATURE_TYPE_SHIFT: u32 = 4;
    pub const SIGNATURE_TYPE_MASK: u16 = 0x70;
    #[inline(always)]
    pub fn signature_type(&self) -> u16 {
        self.entire_field.bits(4, 3) as u16
    }
    #[inline(always)]
    pub fn set_signature_type(&self, value: u16) {
        self.entire_field.set_bits(4, 3, value as u64)
    }
    /// `Unused`: bits 7..=15 de `entire_field`.
    pub const UNUSED_SHIFT: u32 = 7;
    pub const UNUSED_MASK: u16 = 0xff80;
    #[inline(always)]
    pub fn unused(&self) -> u16 {
        self.entire_field.bits(7, 9) as u16
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u16) {
        self.entire_field.set_bits(7, 9, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KldrDataTableEntryU1>() == 0x2);
    assert!(core::mem::offset_of!(KldrDataTableEntryU1, entire_field) == 0x0);
};

/// `_LDR_DATA_TABLE_ENTRY` (0x120 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `LdrDataTableEntryView1`, alcançada por `Deref`.
#[repr(C)]
pub struct LdrDataTableEntry {
    pub in_load_order_links: ListEntry,
    pub in_memory_order_links: ListEntry,
    pub in_initialization_order_links: ListEntry,
    /// -> `void`
    pub dll_base: Field<u64>,
    /// -> `void`
    pub entry_point: Field<u64>,
    pub size_of_image: Field<u32>,
    _pad_44: Reserved<0x4>,
    pub full_dll_name: UnicodeString,
    pub base_dll_name: UnicodeString,
    pub flag_group: [Field<u8>; 4],
    pub obsolete_load_count: Field<u16>,
    pub tls_index: Field<u16>,
    pub hash_links: ListEntry,
    pub time_date_stamp: Field<u32>,
    _pad_84: Reserved<0x4>,
    /// -> `_ACTIVATION_CONTEXT`
    pub entry_point_activation_context: Field<u64>,
    /// -> `void`
    pub lock: Field<u64>,
    /// -> `_LDR_DDAG_NODE`
    pub ddag_node: Field<u64>,
    pub node_module_link: ListEntry,
    /// -> `_LDRP_LOAD_CONTEXT`
    pub load_context: Field<u64>,
    /// -> `void`
    pub parent_dll_base: Field<u64>,
    /// -> `void`
    pub switch_back_context: Field<u64>,
    pub base_address_index_node: RtlBalancedNode,
    pub mapping_info_index_node: RtlBalancedNode,
    pub original_base: Field<u64>,
    pub load_time: LargeInteger,
    pub base_name_hash_value: Field<u32>,
    pub load_reason: Field<LdrDllLoadReason>,
    pub implicit_path_options: Field<u32>,
    pub reference_count: Field<u32>,
    pub dependent_load_flags: Field<u32>,
    pub signing_level: Field<u8>,
    _pad_11d: Reserved<0x3>,
}

/// Vista 1 de `_LDR_DATA_TABLE_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct LdrDataTableEntryView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x68>,
    pub flags: Field<u32>,
    _pad_6c: Reserved<0xb4>,
}

impl core::ops::Deref for LdrDataTableEntry {
    type Target = LdrDataTableEntryView1;
    #[inline(always)]
    fn deref(&self) -> &LdrDataTableEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<LdrDataTableEntryView1>() }
    }
}

unsafe impl NtStruct for LdrDataTableEntry {}

impl LdrDataTableEntry {
    /// `PackagedBinary`: bits 0..=0 de `flags`.
    pub const PACKAGED_BINARY_SHIFT: u32 = 0;
    pub const PACKAGED_BINARY_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn packaged_binary(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_packaged_binary(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `MarkedForRemoval`: bits 1..=1 de `flags`.
    pub const MARKED_FOR_REMOVAL_SHIFT: u32 = 1;
    pub const MARKED_FOR_REMOVAL_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn marked_for_removal(&self) -> u32 {
        self.flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_marked_for_removal(&self, value: u32) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `ImageDll`: bits 2..=2 de `flags`.
    pub const IMAGE_DLL_SHIFT: u32 = 2;
    pub const IMAGE_DLL_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn image_dll(&self) -> u32 {
        self.flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_dll(&self, value: u32) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `LoadNotificationsSent`: bits 3..=3 de `flags`.
    pub const LOAD_NOTIFICATIONS_SENT_SHIFT: u32 = 3;
    pub const LOAD_NOTIFICATIONS_SENT_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn load_notifications_sent(&self) -> u32 {
        self.flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_load_notifications_sent(&self, value: u32) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `TelemetryEntryProcessed`: bits 4..=4 de `flags`.
    pub const TELEMETRY_ENTRY_PROCESSED_SHIFT: u32 = 4;
    pub const TELEMETRY_ENTRY_PROCESSED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn telemetry_entry_processed(&self) -> u32 {
        self.flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_telemetry_entry_processed(&self, value: u32) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `ProcessStaticImport`: bits 5..=5 de `flags`.
    pub const PROCESS_STATIC_IMPORT_SHIFT: u32 = 5;
    pub const PROCESS_STATIC_IMPORT_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn process_static_import(&self) -> u32 {
        self.flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_static_import(&self, value: u32) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `InLegacyLists`: bits 6..=6 de `flags`.
    pub const IN_LEGACY_LISTS_SHIFT: u32 = 6;
    pub const IN_LEGACY_LISTS_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn in_legacy_lists(&self) -> u32 {
        self.flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_in_legacy_lists(&self, value: u32) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `InIndexes`: bits 7..=7 de `flags`.
    pub const IN_INDEXES_SHIFT: u32 = 7;
    pub const IN_INDEXES_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn in_indexes(&self) -> u32 {
        self.flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_in_indexes(&self, value: u32) {
        self.flags.set_bits(7, 1, value as u64)
    }
    /// `ShimDll`: bits 8..=8 de `flags`.
    pub const SHIM_DLL_SHIFT: u32 = 8;
    pub const SHIM_DLL_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn shim_dll(&self) -> u32 {
        self.flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_shim_dll(&self, value: u32) {
        self.flags.set_bits(8, 1, value as u64)
    }
    /// `InExceptionTable`: bits 9..=9 de `flags`.
    pub const IN_EXCEPTION_TABLE_SHIFT: u32 = 9;
    pub const IN_EXCEPTION_TABLE_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn in_exception_table(&self) -> u32 {
        self.flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_in_exception_table(&self, value: u32) {
        self.flags.set_bits(9, 1, value as u64)
    }
    /// `ReservedFlags1`: bits 10..=11 de `flags`.
    pub const RESERVED_FLAGS1_SHIFT: u32 = 10;
    pub const RESERVED_FLAGS1_MASK: u32 = 0xc00;
    #[inline(always)]
    pub fn reserved_flags1(&self) -> u32 {
        self.flags.bits(10, 2) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags1(&self, value: u32) {
        self.flags.set_bits(10, 2, value as u64)
    }
    /// `LoadInProgress`: bits 12..=12 de `flags`.
    pub const LOAD_IN_PROGRESS_SHIFT: u32 = 12;
    pub const LOAD_IN_PROGRESS_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn load_in_progress(&self) -> u32 {
        self.flags.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_load_in_progress(&self, value: u32) {
        self.flags.set_bits(12, 1, value as u64)
    }
    /// `LoadConfigProcessed`: bits 13..=13 de `flags`.
    pub const LOAD_CONFIG_PROCESSED_SHIFT: u32 = 13;
    pub const LOAD_CONFIG_PROCESSED_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn load_config_processed(&self) -> u32 {
        self.flags.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_load_config_processed(&self, value: u32) {
        self.flags.set_bits(13, 1, value as u64)
    }
    /// `EntryProcessed`: bits 14..=14 de `flags`.
    pub const ENTRY_PROCESSED_SHIFT: u32 = 14;
    pub const ENTRY_PROCESSED_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn entry_processed(&self) -> u32 {
        self.flags.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_entry_processed(&self, value: u32) {
        self.flags.set_bits(14, 1, value as u64)
    }
    /// `ProtectDelayLoad`: bits 15..=15 de `flags`.
    pub const PROTECT_DELAY_LOAD_SHIFT: u32 = 15;
    pub const PROTECT_DELAY_LOAD_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn protect_delay_load(&self) -> u32 {
        self.flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_protect_delay_load(&self, value: u32) {
        self.flags.set_bits(15, 1, value as u64)
    }
    /// `ReservedFlags3`: bits 16..=17 de `flags`.
    pub const RESERVED_FLAGS3_SHIFT: u32 = 16;
    pub const RESERVED_FLAGS3_MASK: u32 = 0x30000;
    #[inline(always)]
    pub fn reserved_flags3(&self) -> u32 {
        self.flags.bits(16, 2) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags3(&self, value: u32) {
        self.flags.set_bits(16, 2, value as u64)
    }
    /// `DontCallForThreads`: bits 18..=18 de `flags`.
    pub const DONT_CALL_FOR_THREADS_SHIFT: u32 = 18;
    pub const DONT_CALL_FOR_THREADS_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn dont_call_for_threads(&self) -> u32 {
        self.flags.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_dont_call_for_threads(&self, value: u32) {
        self.flags.set_bits(18, 1, value as u64)
    }
    /// `ProcessAttachCalled`: bits 19..=19 de `flags`.
    pub const PROCESS_ATTACH_CALLED_SHIFT: u32 = 19;
    pub const PROCESS_ATTACH_CALLED_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn process_attach_called(&self) -> u32 {
        self.flags.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_attach_called(&self, value: u32) {
        self.flags.set_bits(19, 1, value as u64)
    }
    /// `ProcessAttachFailed`: bits 20..=20 de `flags`.
    pub const PROCESS_ATTACH_FAILED_SHIFT: u32 = 20;
    pub const PROCESS_ATTACH_FAILED_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn process_attach_failed(&self) -> u32 {
        self.flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_attach_failed(&self, value: u32) {
        self.flags.set_bits(20, 1, value as u64)
    }
    /// `CorDeferredValidate`: bits 21..=21 de `flags`.
    pub const COR_DEFERRED_VALIDATE_SHIFT: u32 = 21;
    pub const COR_DEFERRED_VALIDATE_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn cor_deferred_validate(&self) -> u32 {
        self.flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_cor_deferred_validate(&self, value: u32) {
        self.flags.set_bits(21, 1, value as u64)
    }
    /// `CorImage`: bits 22..=22 de `flags`.
    pub const COR_IMAGE_SHIFT: u32 = 22;
    pub const COR_IMAGE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn cor_image(&self) -> u32 {
        self.flags.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_cor_image(&self, value: u32) {
        self.flags.set_bits(22, 1, value as u64)
    }
    /// `DontRelocate`: bits 23..=23 de `flags`.
    pub const DONT_RELOCATE_SHIFT: u32 = 23;
    pub const DONT_RELOCATE_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn dont_relocate(&self) -> u32 {
        self.flags.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_dont_relocate(&self, value: u32) {
        self.flags.set_bits(23, 1, value as u64)
    }
    /// `CorILOnly`: bits 24..=24 de `flags`.
    pub const COR_IL_ONLY_SHIFT: u32 = 24;
    pub const COR_IL_ONLY_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn cor_il_only(&self) -> u32 {
        self.flags.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_cor_il_only(&self, value: u32) {
        self.flags.set_bits(24, 1, value as u64)
    }
    /// `ChpeImage`: bits 25..=25 de `flags`.
    pub const CHPE_IMAGE_SHIFT: u32 = 25;
    pub const CHPE_IMAGE_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn chpe_image(&self) -> u32 {
        self.flags.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_chpe_image(&self, value: u32) {
        self.flags.set_bits(25, 1, value as u64)
    }
    /// `ReservedFlags5`: bits 26..=27 de `flags`.
    pub const RESERVED_FLAGS5_SHIFT: u32 = 26;
    pub const RESERVED_FLAGS5_MASK: u32 = 0xc000000;
    #[inline(always)]
    pub fn reserved_flags5(&self) -> u32 {
        self.flags.bits(26, 2) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags5(&self, value: u32) {
        self.flags.set_bits(26, 2, value as u64)
    }
    /// `Redirected`: bits 28..=28 de `flags`.
    pub const REDIRECTED_SHIFT: u32 = 28;
    pub const REDIRECTED_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn redirected(&self) -> u32 {
        self.flags.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_redirected(&self, value: u32) {
        self.flags.set_bits(28, 1, value as u64)
    }
    /// `ReservedFlags6`: bits 29..=30 de `flags`.
    pub const RESERVED_FLAGS6_SHIFT: u32 = 29;
    pub const RESERVED_FLAGS6_MASK: u32 = 0x60000000;
    #[inline(always)]
    pub fn reserved_flags6(&self) -> u32 {
        self.flags.bits(29, 2) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags6(&self, value: u32) {
        self.flags.set_bits(29, 2, value as u64)
    }
    /// `CompatDatabaseProcessed`: bits 31..=31 de `flags`.
    pub const COMPAT_DATABASE_PROCESSED_SHIFT: u32 = 31;
    pub const COMPAT_DATABASE_PROCESSED_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn compat_database_processed(&self) -> u32 {
        self.flags.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_compat_database_processed(&self, value: u32) {
        self.flags.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<LdrDataTableEntry>() == 0x120);
    assert!(core::mem::offset_of!(LdrDataTableEntry, in_load_order_links) == 0x0);
    assert!(core::mem::offset_of!(LdrDataTableEntry, in_memory_order_links) == 0x10);
    assert!(core::mem::offset_of!(LdrDataTableEntry, in_initialization_order_links) == 0x20);
    assert!(core::mem::offset_of!(LdrDataTableEntry, dll_base) == 0x30);
    assert!(core::mem::offset_of!(LdrDataTableEntry, entry_point) == 0x38);
    assert!(core::mem::offset_of!(LdrDataTableEntry, size_of_image) == 0x40);
    assert!(core::mem::offset_of!(LdrDataTableEntry, full_dll_name) == 0x48);
    assert!(core::mem::offset_of!(LdrDataTableEntry, base_dll_name) == 0x58);
    assert!(core::mem::offset_of!(LdrDataTableEntry, flag_group) == 0x68);
    assert!(core::mem::offset_of!(LdrDataTableEntry, obsolete_load_count) == 0x6c);
    assert!(core::mem::offset_of!(LdrDataTableEntry, tls_index) == 0x6e);
    assert!(core::mem::offset_of!(LdrDataTableEntry, hash_links) == 0x70);
    assert!(core::mem::offset_of!(LdrDataTableEntry, time_date_stamp) == 0x80);
    assert!(core::mem::offset_of!(LdrDataTableEntry, entry_point_activation_context) == 0x88);
    assert!(core::mem::offset_of!(LdrDataTableEntry, lock) == 0x90);
    assert!(core::mem::offset_of!(LdrDataTableEntry, ddag_node) == 0x98);
    assert!(core::mem::offset_of!(LdrDataTableEntry, node_module_link) == 0xa0);
    assert!(core::mem::offset_of!(LdrDataTableEntry, load_context) == 0xb0);
    assert!(core::mem::offset_of!(LdrDataTableEntry, parent_dll_base) == 0xb8);
    assert!(core::mem::offset_of!(LdrDataTableEntry, switch_back_context) == 0xc0);
    assert!(core::mem::offset_of!(LdrDataTableEntry, base_address_index_node) == 0xc8);
    assert!(core::mem::offset_of!(LdrDataTableEntry, mapping_info_index_node) == 0xe0);
    assert!(core::mem::offset_of!(LdrDataTableEntry, original_base) == 0xf8);
    assert!(core::mem::offset_of!(LdrDataTableEntry, load_time) == 0x100);
    assert!(core::mem::offset_of!(LdrDataTableEntry, base_name_hash_value) == 0x108);
    assert!(core::mem::offset_of!(LdrDataTableEntry, load_reason) == 0x10c);
    assert!(core::mem::offset_of!(LdrDataTableEntry, implicit_path_options) == 0x110);
    assert!(core::mem::offset_of!(LdrDataTableEntry, reference_count) == 0x114);
    assert!(core::mem::offset_of!(LdrDataTableEntry, dependent_load_flags) == 0x118);
    assert!(core::mem::offset_of!(LdrDataTableEntry, signing_level) == 0x11c);
    assert!(core::mem::size_of::<LdrDataTableEntryView1>() == 0x120);
    assert!(core::mem::align_of::<LdrDataTableEntryView1>() == core::mem::align_of::<LdrDataTableEntry>());
    assert!(core::mem::offset_of!(LdrDataTableEntryView1, flags) == 0x68);
};

/// `_LDR_DLL_LOAD_REASON`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct LdrDllLoadReason(pub i32);

impl LdrDllLoadReason {
    pub const LOAD_REASON_STATIC_DEPENDENCY: Self = Self(0);
    pub const LOAD_REASON_STATIC_FORWARDER_DEPENDENCY: Self = Self(1);
    pub const LOAD_REASON_DYNAMIC_FORWARDER_DEPENDENCY: Self = Self(2);
    pub const LOAD_REASON_DELAYLOAD_DEPENDENCY: Self = Self(3);
    pub const LOAD_REASON_DYNAMIC_LOAD: Self = Self(4);
    pub const LOAD_REASON_AS_IMAGE_LOAD: Self = Self(5);
    pub const LOAD_REASON_AS_DATA_LOAD: Self = Self(6);
    pub const LOAD_REASON_ENCLAVE_PRIMARY: Self = Self(7);
    pub const LOAD_REASON_ENCLAVE_DEPENDENCY: Self = Self(8);
    pub const LOAD_REASON_UNKNOWN: Self = Self(-1);
}

impl GuestScalar for LdrDllLoadReason {
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

/// `_IMAGE_DOS_HEADER` (0x40 bytes).
#[repr(C)]
pub struct ImageDosHeader {
    pub e_magic: Field<u16>,
    pub e_cblp: Field<u16>,
    pub e_cp: Field<u16>,
    pub e_crlc: Field<u16>,
    pub e_cparhdr: Field<u16>,
    pub e_minalloc: Field<u16>,
    pub e_maxalloc: Field<u16>,
    pub e_ss: Field<u16>,
    pub e_sp: Field<u16>,
    pub e_csum: Field<u16>,
    pub e_ip: Field<u16>,
    pub e_cs: Field<u16>,
    pub e_lfarlc: Field<u16>,
    pub e_ovno: Field<u16>,
    pub e_res: [Field<u16>; 4],
    pub e_oemid: Field<u16>,
    pub e_oeminfo: Field<u16>,
    pub e_res2: [Field<u16>; 10],
    pub e_lfanew: Field<i32>,
}

unsafe impl NtStruct for ImageDosHeader {}

const _: () = {
    assert!(core::mem::size_of::<ImageDosHeader>() == 0x40);
    assert!(core::mem::offset_of!(ImageDosHeader, e_magic) == 0x0);
    assert!(core::mem::offset_of!(ImageDosHeader, e_cblp) == 0x2);
    assert!(core::mem::offset_of!(ImageDosHeader, e_cp) == 0x4);
    assert!(core::mem::offset_of!(ImageDosHeader, e_crlc) == 0x6);
    assert!(core::mem::offset_of!(ImageDosHeader, e_cparhdr) == 0x8);
    assert!(core::mem::offset_of!(ImageDosHeader, e_minalloc) == 0xa);
    assert!(core::mem::offset_of!(ImageDosHeader, e_maxalloc) == 0xc);
    assert!(core::mem::offset_of!(ImageDosHeader, e_ss) == 0xe);
    assert!(core::mem::offset_of!(ImageDosHeader, e_sp) == 0x10);
    assert!(core::mem::offset_of!(ImageDosHeader, e_csum) == 0x12);
    assert!(core::mem::offset_of!(ImageDosHeader, e_ip) == 0x14);
    assert!(core::mem::offset_of!(ImageDosHeader, e_cs) == 0x16);
    assert!(core::mem::offset_of!(ImageDosHeader, e_lfarlc) == 0x18);
    assert!(core::mem::offset_of!(ImageDosHeader, e_ovno) == 0x1a);
    assert!(core::mem::offset_of!(ImageDosHeader, e_res) == 0x1c);
    assert!(core::mem::offset_of!(ImageDosHeader, e_oemid) == 0x24);
    assert!(core::mem::offset_of!(ImageDosHeader, e_oeminfo) == 0x26);
    assert!(core::mem::offset_of!(ImageDosHeader, e_res2) == 0x28);
    assert!(core::mem::offset_of!(ImageDosHeader, e_lfanew) == 0x3c);
};

/// `_IMAGE_NT_HEADERS64` (0x108 bytes).
#[repr(C)]
pub struct ImageNtHeaders64 {
    pub signature: Field<u32>,
    pub file_header: ImageFileHeader,
    pub optional_header: ImageOptionalHeader64,
}

unsafe impl NtStruct for ImageNtHeaders64 {}

const _: () = {
    assert!(core::mem::size_of::<ImageNtHeaders64>() == 0x108);
    assert!(core::mem::offset_of!(ImageNtHeaders64, signature) == 0x0);
    assert!(core::mem::offset_of!(ImageNtHeaders64, file_header) == 0x4);
    assert!(core::mem::offset_of!(ImageNtHeaders64, optional_header) == 0x18);
};

/// `_IMAGE_FILE_HEADER` (0x14 bytes).
#[repr(C)]
pub struct ImageFileHeader {
    pub machine: Field<u16>,
    pub number_of_sections: Field<u16>,
    pub time_date_stamp: Field<u32>,
    pub pointer_to_symbol_table: Field<u32>,
    pub number_of_symbols: Field<u32>,
    pub size_of_optional_header: Field<u16>,
    pub characteristics: Field<u16>,
}

unsafe impl NtStruct for ImageFileHeader {}

const _: () = {
    assert!(core::mem::size_of::<ImageFileHeader>() == 0x14);
    assert!(core::mem::offset_of!(ImageFileHeader, machine) == 0x0);
    assert!(core::mem::offset_of!(ImageFileHeader, number_of_sections) == 0x2);
    assert!(core::mem::offset_of!(ImageFileHeader, time_date_stamp) == 0x4);
    assert!(core::mem::offset_of!(ImageFileHeader, pointer_to_symbol_table) == 0x8);
    assert!(core::mem::offset_of!(ImageFileHeader, number_of_symbols) == 0xc);
    assert!(core::mem::offset_of!(ImageFileHeader, size_of_optional_header) == 0x10);
    assert!(core::mem::offset_of!(ImageFileHeader, characteristics) == 0x12);
};

/// `_IMAGE_OPTIONAL_HEADER64` (0xf0 bytes).
#[repr(C)]
pub struct ImageOptionalHeader64 {
    pub magic: Field<u16>,
    pub major_linker_version: Field<u8>,
    pub minor_linker_version: Field<u8>,
    pub size_of_code: Field<u32>,
    pub size_of_initialized_data: Field<u32>,
    pub size_of_uninitialized_data: Field<u32>,
    pub address_of_entry_point: Field<u32>,
    pub base_of_code: Field<u32>,
    pub image_base: Field<u64>,
    pub section_alignment: Field<u32>,
    pub file_alignment: Field<u32>,
    pub major_operating_system_version: Field<u16>,
    pub minor_operating_system_version: Field<u16>,
    pub major_image_version: Field<u16>,
    pub minor_image_version: Field<u16>,
    pub major_subsystem_version: Field<u16>,
    pub minor_subsystem_version: Field<u16>,
    pub win32_version_value: Field<u32>,
    pub size_of_image: Field<u32>,
    pub size_of_headers: Field<u32>,
    pub check_sum: Field<u32>,
    pub subsystem: Field<u16>,
    pub dll_characteristics: Field<u16>,
    pub size_of_stack_reserve: Field<u64>,
    pub size_of_stack_commit: Field<u64>,
    pub size_of_heap_reserve: Field<u64>,
    pub size_of_heap_commit: Field<u64>,
    pub loader_flags: Field<u32>,
    pub number_of_rva_and_sizes: Field<u32>,
    pub data_directory: [ImageDataDirectory; 16],
}

unsafe impl NtStruct for ImageOptionalHeader64 {}

const _: () = {
    assert!(core::mem::size_of::<ImageOptionalHeader64>() == 0xf0);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, magic) == 0x0);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, major_linker_version) == 0x2);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, minor_linker_version) == 0x3);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_code) == 0x4);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_initialized_data) == 0x8);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_uninitialized_data) == 0xc);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, address_of_entry_point) == 0x10);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, base_of_code) == 0x14);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, image_base) == 0x18);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, section_alignment) == 0x20);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, file_alignment) == 0x24);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, major_operating_system_version) == 0x28);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, minor_operating_system_version) == 0x2a);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, major_image_version) == 0x2c);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, minor_image_version) == 0x2e);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, major_subsystem_version) == 0x30);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, minor_subsystem_version) == 0x32);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, win32_version_value) == 0x34);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_image) == 0x38);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_headers) == 0x3c);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, check_sum) == 0x40);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, subsystem) == 0x44);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, dll_characteristics) == 0x46);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_stack_reserve) == 0x48);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_stack_commit) == 0x50);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_heap_reserve) == 0x58);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, size_of_heap_commit) == 0x60);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, loader_flags) == 0x68);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, number_of_rva_and_sizes) == 0x6c);
    assert!(core::mem::offset_of!(ImageOptionalHeader64, data_directory) == 0x70);
};

/// `_IMAGE_DATA_DIRECTORY` (0x8 bytes).
#[repr(C)]
pub struct ImageDataDirectory {
    pub virtual_address: Field<u32>,
    pub size: Field<u32>,
}

unsafe impl NtStruct for ImageDataDirectory {}

const _: () = {
    assert!(core::mem::size_of::<ImageDataDirectory>() == 0x8);
    assert!(core::mem::offset_of!(ImageDataDirectory, virtual_address) == 0x0);
    assert!(core::mem::offset_of!(ImageDataDirectory, size) == 0x4);
};

/// `_IMAGE_SECTION_HEADER` (0x28 bytes).
#[repr(C)]
pub struct ImageSectionHeader {
    pub name: [Field<u8>; 8],
    pub misc: ImageSectionHeaderMisc,
    pub virtual_address: Field<u32>,
    pub size_of_raw_data: Field<u32>,
    pub pointer_to_raw_data: Field<u32>,
    pub pointer_to_relocations: Field<u32>,
    pub pointer_to_linenumbers: Field<u32>,
    pub number_of_relocations: Field<u16>,
    pub number_of_linenumbers: Field<u16>,
    pub characteristics: Field<u32>,
}

unsafe impl NtStruct for ImageSectionHeader {}

const _: () = {
    assert!(core::mem::size_of::<ImageSectionHeader>() == 0x28);
    assert!(core::mem::offset_of!(ImageSectionHeader, name) == 0x0);
    assert!(core::mem::offset_of!(ImageSectionHeader, misc) == 0x8);
    assert!(core::mem::offset_of!(ImageSectionHeader, virtual_address) == 0xc);
    assert!(core::mem::offset_of!(ImageSectionHeader, size_of_raw_data) == 0x10);
    assert!(core::mem::offset_of!(ImageSectionHeader, pointer_to_raw_data) == 0x14);
    assert!(core::mem::offset_of!(ImageSectionHeader, pointer_to_relocations) == 0x18);
    assert!(core::mem::offset_of!(ImageSectionHeader, pointer_to_linenumbers) == 0x1c);
    assert!(core::mem::offset_of!(ImageSectionHeader, number_of_relocations) == 0x20);
    assert!(core::mem::offset_of!(ImageSectionHeader, number_of_linenumbers) == 0x22);
    assert!(core::mem::offset_of!(ImageSectionHeader, characteristics) == 0x24);
};

/// `_IMAGE_SECTION_HEADER::Misc` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ImageSectionHeaderMiscView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ImageSectionHeaderMisc {
    pub physical_address: Field<u32>,
}

/// Vista 1 de `_IMAGE_SECTION_HEADER::Misc` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageSectionHeaderMiscView1 {
    pub virtual_size: Field<u32>,
}

impl core::ops::Deref for ImageSectionHeaderMisc {
    type Target = ImageSectionHeaderMiscView1;
    #[inline(always)]
    fn deref(&self) -> &ImageSectionHeaderMiscView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageSectionHeaderMiscView1>() }
    }
}

unsafe impl NtStruct for ImageSectionHeaderMisc {}

const _: () = {
    assert!(core::mem::size_of::<ImageSectionHeaderMisc>() == 0x4);
    assert!(core::mem::offset_of!(ImageSectionHeaderMisc, physical_address) == 0x0);
    assert!(core::mem::size_of::<ImageSectionHeaderMiscView1>() == 0x4);
    assert!(core::mem::align_of::<ImageSectionHeaderMiscView1>() == core::mem::align_of::<ImageSectionHeaderMisc>());
    assert!(core::mem::offset_of!(ImageSectionHeaderMiscView1, virtual_size) == 0x0);
};

/// `_SECTION` (0x40 bytes).
#[repr(C)]
pub struct Section {
    pub section_node: RtlBalancedNode,
    pub starting_vpn: Field<u64>,
    pub ending_vpn: Field<u64>,
    pub u1: SectionU1,
    pub size_of_section: Field<u64>,
    pub u: SectionU,
    pub bitfield_3c: Field<u32>,
}

unsafe impl NtStruct for Section {}

impl Section {
    /// `InitialPageProtection`: bits 0..=11 de `bitfield_3c`.
    pub const INITIAL_PAGE_PROTECTION_SHIFT: u32 = 0;
    pub const INITIAL_PAGE_PROTECTION_MASK: u32 = 0xfff;
    #[inline(always)]
    pub fn initial_page_protection(&self) -> u32 {
        self.bitfield_3c.bits(0, 12) as u32
    }
    #[inline(always)]
    pub fn set_initial_page_protection(&self, value: u32) {
        self.bitfield_3c.set_bits(0, 12, value as u64)
    }
    /// `SessionId`: bits 12..=30 de `bitfield_3c`.
    pub const SESSION_ID_SHIFT: u32 = 12;
    pub const SESSION_ID_MASK: u32 = 0x7ffff000;
    #[inline(always)]
    pub fn session_id(&self) -> u32 {
        self.bitfield_3c.bits(12, 19) as u32
    }
    #[inline(always)]
    pub fn set_session_id(&self, value: u32) {
        self.bitfield_3c.set_bits(12, 19, value as u64)
    }
    /// `NoValidationNeeded`: bits 31..=31 de `bitfield_3c`.
    pub const NO_VALIDATION_NEEDED_SHIFT: u32 = 31;
    pub const NO_VALIDATION_NEEDED_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn no_validation_needed(&self) -> u32 {
        self.bitfield_3c.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_validation_needed(&self, value: u32) {
        self.bitfield_3c.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Section>() == 0x40);
    assert!(core::mem::offset_of!(Section, section_node) == 0x0);
    assert!(core::mem::offset_of!(Section, starting_vpn) == 0x18);
    assert!(core::mem::offset_of!(Section, ending_vpn) == 0x20);
    assert!(core::mem::offset_of!(Section, u1) == 0x28);
    assert!(core::mem::offset_of!(Section, size_of_section) == 0x30);
    assert!(core::mem::offset_of!(Section, u) == 0x38);
    assert!(core::mem::offset_of!(Section, bitfield_3c) == 0x3c);
};

/// `_SECTION::u1` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SectionU1View1`, alcançada por `Deref`.
#[repr(C)]
pub struct SectionU1 {
    /// -> `_CONTROL_AREA`
    pub control_area: Field<u64>,
}

/// Vista 1 de `_SECTION::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SectionU1View1 {
    /// -> `_FILE_OBJECT`
    pub file_object: Field<u64>,
}

impl core::ops::Deref for SectionU1 {
    type Target = SectionU1View1;
    #[inline(always)]
    fn deref(&self) -> &SectionU1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SectionU1View1>() }
    }
}

unsafe impl NtStruct for SectionU1 {}

impl SectionU1 {
    /// `RemoteImageFileObject`: bits 0..=0 de `file_object`.
    pub const REMOTE_IMAGE_FILE_OBJECT_SHIFT: u32 = 0;
    pub const REMOTE_IMAGE_FILE_OBJECT_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn remote_image_file_object(&self) -> u64 {
        self.file_object.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_remote_image_file_object(&self, value: u64) {
        self.file_object.set_bits(0, 1, value as u64)
    }
    /// `RemoteDataFileObject`: bits 1..=1 de `file_object`.
    pub const REMOTE_DATA_FILE_OBJECT_SHIFT: u32 = 1;
    pub const REMOTE_DATA_FILE_OBJECT_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn remote_data_file_object(&self) -> u64 {
        self.file_object.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_remote_data_file_object(&self, value: u64) {
        self.file_object.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SectionU1>() == 0x8);
    assert!(core::mem::offset_of!(SectionU1, control_area) == 0x0);
    assert!(core::mem::size_of::<SectionU1View1>() == 0x8);
    assert!(core::mem::align_of::<SectionU1View1>() == core::mem::align_of::<SectionU1>());
    assert!(core::mem::offset_of!(SectionU1View1, file_object) == 0x0);
};

/// `_SECTION::u` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SectionUView1`, alcançada por `Deref`.
#[repr(C)]
pub struct SectionU {
    pub long_flags: Field<u32>,
}

/// Vista 1 de `_SECTION::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SectionUView1 {
    pub flags: MmsectionFlags,
}

impl core::ops::Deref for SectionU {
    type Target = SectionUView1;
    #[inline(always)]
    fn deref(&self) -> &SectionUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SectionUView1>() }
    }
}

unsafe impl NtStruct for SectionU {}

const _: () = {
    assert!(core::mem::size_of::<SectionU>() == 0x4);
    assert!(core::mem::offset_of!(SectionU, long_flags) == 0x0);
    assert!(core::mem::size_of::<SectionUView1>() == 0x4);
    assert!(core::mem::align_of::<SectionUView1>() == core::mem::align_of::<SectionU>());
    assert!(core::mem::offset_of!(SectionUView1, flags) == 0x0);
};

/// `_MMSECTION_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct MmsectionFlags {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for MmsectionFlags {}

impl MmsectionFlags {
    /// `BeingDeleted`: bits 0..=0 de `bitfield_0`.
    pub const BEING_DELETED_SHIFT: u32 = 0;
    pub const BEING_DELETED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn being_deleted(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_being_deleted(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `BeingCreated`: bits 1..=1 de `bitfield_0`.
    pub const BEING_CREATED_SHIFT: u32 = 1;
    pub const BEING_CREATED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn being_created(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_being_created(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `BeingPurged`: bits 2..=2 de `bitfield_0`.
    pub const BEING_PURGED_SHIFT: u32 = 2;
    pub const BEING_PURGED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn being_purged(&self) -> u32 {
        self.bitfield_0.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_being_purged(&self, value: u32) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `NoModifiedWriting`: bits 3..=3 de `bitfield_0`.
    pub const NO_MODIFIED_WRITING_SHIFT: u32 = 3;
    pub const NO_MODIFIED_WRITING_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn no_modified_writing(&self) -> u32 {
        self.bitfield_0.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_modified_writing(&self, value: u32) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `FailAllIo`: bits 4..=4 de `bitfield_0`.
    pub const FAIL_ALL_IO_SHIFT: u32 = 4;
    pub const FAIL_ALL_IO_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn fail_all_io(&self) -> u32 {
        self.bitfield_0.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_fail_all_io(&self, value: u32) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Image`: bits 5..=5 de `bitfield_0`.
    pub const IMAGE_SHIFT: u32 = 5;
    pub const IMAGE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn image(&self) -> u32 {
        self.bitfield_0.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_image(&self, value: u32) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `Based`: bits 6..=6 de `bitfield_0`.
    pub const BASED_SHIFT: u32 = 6;
    pub const BASED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn based(&self) -> u32 {
        self.bitfield_0.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_based(&self, value: u32) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `File`: bits 7..=7 de `bitfield_0`.
    pub const FILE_SHIFT: u32 = 7;
    pub const FILE_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn file(&self) -> u32 {
        self.bitfield_0.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_file(&self, value: u32) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `AttemptingDelete`: bits 8..=8 de `bitfield_0`.
    pub const ATTEMPTING_DELETE_SHIFT: u32 = 8;
    pub const ATTEMPTING_DELETE_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn attempting_delete(&self) -> u32 {
        self.bitfield_0.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_attempting_delete(&self, value: u32) {
        self.bitfield_0.set_bits(8, 1, value as u64)
    }
    /// `PrefetchCreated`: bits 9..=9 de `bitfield_0`.
    pub const PREFETCH_CREATED_SHIFT: u32 = 9;
    pub const PREFETCH_CREATED_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn prefetch_created(&self) -> u32 {
        self.bitfield_0.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_prefetch_created(&self, value: u32) {
        self.bitfield_0.set_bits(9, 1, value as u64)
    }
    /// `PhysicalMemory`: bits 10..=10 de `bitfield_0`.
    pub const PHYSICAL_MEMORY_SHIFT: u32 = 10;
    pub const PHYSICAL_MEMORY_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn physical_memory(&self) -> u32 {
        self.bitfield_0.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_physical_memory(&self, value: u32) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `ImageControlAreaOnRemovableMedia`: bits 11..=11 de `bitfield_0`.
    pub const IMAGE_CONTROL_AREA_ON_REMOVABLE_MEDIA_SHIFT: u32 = 11;
    pub const IMAGE_CONTROL_AREA_ON_REMOVABLE_MEDIA_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn image_control_area_on_removable_media(&self) -> u32 {
        self.bitfield_0.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_control_area_on_removable_media(&self, value: u32) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `Reserve`: bits 12..=12 de `bitfield_0`.
    pub const RESERVE_SHIFT: u32 = 12;
    pub const RESERVE_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn reserve(&self) -> u32 {
        self.bitfield_0.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserve(&self, value: u32) {
        self.bitfield_0.set_bits(12, 1, value as u64)
    }
    /// `Commit`: bits 13..=13 de `bitfield_0`.
    pub const COMMIT_SHIFT: u32 = 13;
    pub const COMMIT_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn commit(&self) -> u32 {
        self.bitfield_0.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_commit(&self, value: u32) {
        self.bitfield_0.set_bits(13, 1, value as u64)
    }
    /// `NoChange`: bits 14..=14 de `bitfield_0`.
    pub const NO_CHANGE_SHIFT: u32 = 14;
    pub const NO_CHANGE_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn no_change(&self) -> u32 {
        self.bitfield_0.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_change(&self, value: u32) {
        self.bitfield_0.set_bits(14, 1, value as u64)
    }
    /// `WasPurged`: bits 15..=15 de `bitfield_0`.
    pub const WAS_PURGED_SHIFT: u32 = 15;
    pub const WAS_PURGED_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn was_purged(&self) -> u32 {
        self.bitfield_0.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_was_purged(&self, value: u32) {
        self.bitfield_0.set_bits(15, 1, value as u64)
    }
    /// `UserReference`: bits 16..=16 de `bitfield_0`.
    pub const USER_REFERENCE_SHIFT: u32 = 16;
    pub const USER_REFERENCE_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn user_reference(&self) -> u32 {
        self.bitfield_0.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_user_reference(&self, value: u32) {
        self.bitfield_0.set_bits(16, 1, value as u64)
    }
    /// `GlobalMemory`: bits 17..=17 de `bitfield_0`.
    pub const GLOBAL_MEMORY_SHIFT: u32 = 17;
    pub const GLOBAL_MEMORY_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn global_memory(&self) -> u32 {
        self.bitfield_0.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_global_memory(&self, value: u32) {
        self.bitfield_0.set_bits(17, 1, value as u64)
    }
    /// `DeleteOnClose`: bits 18..=18 de `bitfield_0`.
    pub const DELETE_ON_CLOSE_SHIFT: u32 = 18;
    pub const DELETE_ON_CLOSE_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn delete_on_close(&self) -> u32 {
        self.bitfield_0.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_delete_on_close(&self, value: u32) {
        self.bitfield_0.set_bits(18, 1, value as u64)
    }
    /// `FilePointerNull`: bits 19..=19 de `bitfield_0`.
    pub const FILE_POINTER_NULL_SHIFT: u32 = 19;
    pub const FILE_POINTER_NULL_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn file_pointer_null(&self) -> u32 {
        self.bitfield_0.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_file_pointer_null(&self, value: u32) {
        self.bitfield_0.set_bits(19, 1, value as u64)
    }
    /// `PreferredNode`: bits 20..=25 de `bitfield_0`.
    pub const PREFERRED_NODE_SHIFT: u32 = 20;
    pub const PREFERRED_NODE_MASK: u32 = 0x3f00000;
    #[inline(always)]
    pub fn preferred_node(&self) -> u32 {
        self.bitfield_0.bits(20, 6) as u32
    }
    #[inline(always)]
    pub fn set_preferred_node(&self, value: u32) {
        self.bitfield_0.set_bits(20, 6, value as u64)
    }
    /// `GlobalOnlyPerSession`: bits 26..=26 de `bitfield_0`.
    pub const GLOBAL_ONLY_PER_SESSION_SHIFT: u32 = 26;
    pub const GLOBAL_ONLY_PER_SESSION_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn global_only_per_session(&self) -> u32 {
        self.bitfield_0.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_global_only_per_session(&self, value: u32) {
        self.bitfield_0.set_bits(26, 1, value as u64)
    }
    /// `UserWritable`: bits 27..=27 de `bitfield_0`.
    pub const USER_WRITABLE_SHIFT: u32 = 27;
    pub const USER_WRITABLE_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn user_writable(&self) -> u32 {
        self.bitfield_0.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_user_writable(&self, value: u32) {
        self.bitfield_0.set_bits(27, 1, value as u64)
    }
    /// `SystemVaAllocated`: bits 28..=28 de `bitfield_0`.
    pub const SYSTEM_VA_ALLOCATED_SHIFT: u32 = 28;
    pub const SYSTEM_VA_ALLOCATED_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn system_va_allocated(&self) -> u32 {
        self.bitfield_0.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_va_allocated(&self, value: u32) {
        self.bitfield_0.set_bits(28, 1, value as u64)
    }
    /// `PreferredFsCompressionBoundary`: bits 29..=29 de `bitfield_0`.
    pub const PREFERRED_FS_COMPRESSION_BOUNDARY_SHIFT: u32 = 29;
    pub const PREFERRED_FS_COMPRESSION_BOUNDARY_MASK: u32 = 0x20000000;
    #[inline(always)]
    pub fn preferred_fs_compression_boundary(&self) -> u32 {
        self.bitfield_0.bits(29, 1) as u32
    }
    #[inline(always)]
    pub fn set_preferred_fs_compression_boundary(&self, value: u32) {
        self.bitfield_0.set_bits(29, 1, value as u64)
    }
    /// `UsingFileExtents`: bits 30..=30 de `bitfield_0`.
    pub const USING_FILE_EXTENTS_SHIFT: u32 = 30;
    pub const USING_FILE_EXTENTS_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn using_file_extents(&self) -> u32 {
        self.bitfield_0.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_using_file_extents(&self, value: u32) {
        self.bitfield_0.set_bits(30, 1, value as u64)
    }
    /// `PageSize64K`: bits 31..=31 de `bitfield_0`.
    pub const PAGE_SIZE64_K_SHIFT: u32 = 31;
    pub const PAGE_SIZE64_K_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn page_size64_k(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_page_size64_k(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmsectionFlags>() == 0x4);
    assert!(core::mem::offset_of!(MmsectionFlags, bitfield_0) == 0x0);
};

/// `_CONTROL_AREA` (0x80 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ControlAreaView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ControlArea {
    /// -> `_SEGMENT`
    pub segment: Field<u64>,
    pub list_head: ListEntry,
    pub number_of_section_references: Field<u64>,
    pub number_of_pfn_references: Field<u64>,
    pub number_of_mapped_views: Field<u64>,
    pub number_of_user_references: Field<u64>,
    pub u: SectionU,
    pub u1: ControlAreaU1,
    pub file_pointer: ExFastRef,
    pub control_area_lock: Field<i32>,
    pub modified_write_count: Field<u32>,
    /// -> `_MI_CONTROL_AREA_WAIT_BLOCK`
    pub wait_list: Field<u64>,
    pub u2: ControlAreaU2,
    pub file_object_lock: ExPushLock,
    pub locked_pages: Field<u64>,
    pub u3: ControlAreaU3,
}

/// Vista 1 de `_CONTROL_AREA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ControlAreaView1 {
    _pad_0: Reserved<0x8>,
    /// -> `void`
    pub awe_context: Field<u64>,
    _pad_10: Reserved<0x70>,
}

impl core::ops::Deref for ControlArea {
    type Target = ControlAreaView1;
    #[inline(always)]
    fn deref(&self) -> &ControlAreaView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ControlAreaView1>() }
    }
}

unsafe impl NtStruct for ControlArea {}

const _: () = {
    assert!(core::mem::size_of::<ControlArea>() == 0x80);
    assert!(core::mem::offset_of!(ControlArea, segment) == 0x0);
    assert!(core::mem::offset_of!(ControlArea, list_head) == 0x8);
    assert!(core::mem::offset_of!(ControlArea, number_of_section_references) == 0x18);
    assert!(core::mem::offset_of!(ControlArea, number_of_pfn_references) == 0x20);
    assert!(core::mem::offset_of!(ControlArea, number_of_mapped_views) == 0x28);
    assert!(core::mem::offset_of!(ControlArea, number_of_user_references) == 0x30);
    assert!(core::mem::offset_of!(ControlArea, u) == 0x38);
    assert!(core::mem::offset_of!(ControlArea, u1) == 0x3c);
    assert!(core::mem::offset_of!(ControlArea, file_pointer) == 0x40);
    assert!(core::mem::offset_of!(ControlArea, control_area_lock) == 0x48);
    assert!(core::mem::offset_of!(ControlArea, modified_write_count) == 0x4c);
    assert!(core::mem::offset_of!(ControlArea, wait_list) == 0x50);
    assert!(core::mem::offset_of!(ControlArea, u2) == 0x58);
    assert!(core::mem::offset_of!(ControlArea, file_object_lock) == 0x68);
    assert!(core::mem::offset_of!(ControlArea, locked_pages) == 0x70);
    assert!(core::mem::offset_of!(ControlArea, u3) == 0x78);
    assert!(core::mem::size_of::<ControlAreaView1>() == 0x80);
    assert!(core::mem::align_of::<ControlAreaView1>() == core::mem::align_of::<ControlArea>());
    assert!(core::mem::offset_of!(ControlAreaView1, awe_context) == 0x8);
};

/// `_CONTROL_AREA::u1` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ControlAreaU1View1`, alcançada por `Deref`.
#[repr(C)]
pub struct ControlAreaU1 {
    pub long_flags: Field<u32>,
}

/// Vista 1 de `_CONTROL_AREA::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ControlAreaU1View1 {
    _align: [u32; 0],
    pub flags: MmsectionFlags2,
}

impl core::ops::Deref for ControlAreaU1 {
    type Target = ControlAreaU1View1;
    #[inline(always)]
    fn deref(&self) -> &ControlAreaU1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ControlAreaU1View1>() }
    }
}

unsafe impl NtStruct for ControlAreaU1 {}

const _: () = {
    assert!(core::mem::size_of::<ControlAreaU1>() == 0x4);
    assert!(core::mem::offset_of!(ControlAreaU1, long_flags) == 0x0);
    assert!(core::mem::size_of::<ControlAreaU1View1>() == 0x4);
    assert!(core::mem::align_of::<ControlAreaU1View1>() == core::mem::align_of::<ControlAreaU1>());
    assert!(core::mem::offset_of!(ControlAreaU1View1, flags) == 0x0);
};

/// `_MMSECTION_FLAGS2` (0x4 bytes).
#[repr(C)]
pub struct MmsectionFlags2 {
    pub bitfield_0: Field<u16>,
    pub bitfield_2: Field<u8>,
    _pad_3: Reserved<0x1>,
}

unsafe impl NtStruct for MmsectionFlags2 {}

impl MmsectionFlags2 {
    /// `PartitionId`: bits 0..=9 de `bitfield_0`.
    pub const PARTITION_ID_SHIFT: u32 = 0;
    pub const PARTITION_ID_MASK: u16 = 0x3ff;
    #[inline(always)]
    pub fn partition_id(&self) -> u16 {
        self.bitfield_0.bits(0, 10) as u16
    }
    #[inline(always)]
    pub fn set_partition_id(&self, value: u16) {
        self.bitfield_0.set_bits(0, 10, value as u64)
    }
    /// `NoCrossPartitionAccess`: bits 0..=0 de `bitfield_2`.
    pub const NO_CROSS_PARTITION_ACCESS_SHIFT: u32 = 0;
    pub const NO_CROSS_PARTITION_ACCESS_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn no_cross_partition_access(&self) -> u8 {
        self.bitfield_2.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_no_cross_partition_access(&self, value: u8) {
        self.bitfield_2.set_bits(0, 1, value as u64)
    }
    /// `SubsectionCrossPartitionReferenceOverflow`: bits 1..=1 de `bitfield_2`.
    pub const SUBSECTION_CROSS_PARTITION_REFERENCE_OVERFLOW_SHIFT: u32 = 1;
    pub const SUBSECTION_CROSS_PARTITION_REFERENCE_OVERFLOW_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn subsection_cross_partition_reference_overflow(&self) -> u8 {
        self.bitfield_2.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_subsection_cross_partition_reference_overflow(&self, value: u8) {
        self.bitfield_2.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmsectionFlags2>() == 0x4);
    assert!(core::mem::offset_of!(MmsectionFlags2, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(MmsectionFlags2, bitfield_2) == 0x2);
};

/// `_CONTROL_AREA::u2` (0x10 bytes).
#[repr(C)]
pub struct ControlAreaU2 {
    pub e2: ControlAreaU2E2,
}

unsafe impl NtStruct for ControlAreaU2 {}

const _: () = {
    assert!(core::mem::size_of::<ControlAreaU2>() == 0x10);
    assert!(core::mem::offset_of!(ControlAreaU2, e2) == 0x0);
};

/// `_CONTROL_AREA::u2::e2` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ControlAreaU2E2View1`..`ControlAreaU2E2View2`, alcançadas por `Deref`.
#[repr(C)]
pub struct ControlAreaU2E2 {
    _align: [u64; 0],
    pub number_of_system_cache_views: Field<u32>,
    pub writable_user_references: Field<i32>,
    pub flush_in_progress_count: Field<u32>,
    _pad_c: Reserved<0x4>,
}

/// Vista 1 de `_CONTROL_AREA::u2::e2` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ControlAreaU2E2View1 {
    _align: [u64; 0],
    pub image_relocation_start_bit: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub number_of_subsections: Field<u32>,
    _pad_c: Reserved<0x4>,
}

/// Vista 2 de `_CONTROL_AREA::u2::e2` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ControlAreaU2E2View2 {
    _pad_0: Reserved<0x8>,
    /// -> `_MI_IMAGE_SECURITY_REFERENCE`
    pub se_image_stub: Field<u64>,
}

impl core::ops::Deref for ControlAreaU2E2 {
    type Target = ControlAreaU2E2View1;
    #[inline(always)]
    fn deref(&self) -> &ControlAreaU2E2View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ControlAreaU2E2View1>() }
    }
}

impl core::ops::Deref for ControlAreaU2E2View1 {
    type Target = ControlAreaU2E2View2;
    #[inline(always)]
    fn deref(&self) -> &ControlAreaU2E2View2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ControlAreaU2E2View2>() }
    }
}

unsafe impl NtStruct for ControlAreaU2E2 {}

impl ControlAreaU2E2 {
    /// `ImageRelocationSizeIn64k`: bits 0..=15 de `writable_user_references`.
    pub const IMAGE_RELOCATION_SIZE_IN64K_SHIFT: u32 = 0;
    pub const IMAGE_RELOCATION_SIZE_IN64K_MASK: u32 = 0xffff;
    #[inline(always)]
    pub fn image_relocation_size_in64k(&self) -> u32 {
        self.writable_user_references.bits(0, 16) as u32
    }
    #[inline(always)]
    pub fn set_image_relocation_size_in64k(&self, value: u32) {
        self.writable_user_references.set_bits(0, 16, value as u64)
    }
    /// `SystemImage`: bits 16..=16 de `writable_user_references`.
    pub const SYSTEM_IMAGE_SHIFT: u32 = 16;
    pub const SYSTEM_IMAGE_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn system_image(&self) -> u32 {
        self.writable_user_references.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_image(&self, value: u32) {
        self.writable_user_references.set_bits(16, 1, value as u64)
    }
    /// `CantMove`: bits 17..=17 de `writable_user_references`.
    pub const CANT_MOVE_SHIFT: u32 = 17;
    pub const CANT_MOVE_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn cant_move(&self) -> u32 {
        self.writable_user_references.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_cant_move(&self, value: u32) {
        self.writable_user_references.set_bits(17, 1, value as u64)
    }
    /// `StrongCode`: bits 18..=19 de `writable_user_references`.
    pub const STRONG_CODE_SHIFT: u32 = 18;
    pub const STRONG_CODE_MASK: u32 = 0xc0000;
    #[inline(always)]
    pub fn strong_code(&self) -> u32 {
        self.writable_user_references.bits(18, 2) as u32
    }
    #[inline(always)]
    pub fn set_strong_code(&self, value: u32) {
        self.writable_user_references.set_bits(18, 2, value as u64)
    }
    /// `BitMap`: bits 20..=21 de `writable_user_references`.
    pub const BIT_MAP_SHIFT: u32 = 20;
    pub const BIT_MAP_MASK: u32 = 0x300000;
    #[inline(always)]
    pub fn bit_map(&self) -> u32 {
        self.writable_user_references.bits(20, 2) as u32
    }
    #[inline(always)]
    pub fn set_bit_map(&self, value: u32) {
        self.writable_user_references.set_bits(20, 2, value as u64)
    }
    /// `ImageActive`: bits 22..=22 de `writable_user_references`.
    pub const IMAGE_ACTIVE_SHIFT: u32 = 22;
    pub const IMAGE_ACTIVE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn image_active(&self) -> u32 {
        self.writable_user_references.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_active(&self, value: u32) {
        self.writable_user_references.set_bits(22, 1, value as u64)
    }
    /// `ImageBaseOkToReuse`: bits 23..=23 de `writable_user_references`.
    pub const IMAGE_BASE_OK_TO_REUSE_SHIFT: u32 = 23;
    pub const IMAGE_BASE_OK_TO_REUSE_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn image_base_ok_to_reuse(&self) -> u32 {
        self.writable_user_references.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_base_ok_to_reuse(&self, value: u32) {
        self.writable_user_references.set_bits(23, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ControlAreaU2E2>() == 0x10);
    assert!(core::mem::offset_of!(ControlAreaU2E2, number_of_system_cache_views) == 0x0);
    assert!(core::mem::offset_of!(ControlAreaU2E2, writable_user_references) == 0x4);
    assert!(core::mem::offset_of!(ControlAreaU2E2, flush_in_progress_count) == 0x8);
    assert!(core::mem::size_of::<ControlAreaU2E2View1>() == 0x10);
    assert!(core::mem::align_of::<ControlAreaU2E2View1>() == core::mem::align_of::<ControlAreaU2E2>());
    assert!(core::mem::offset_of!(ControlAreaU2E2View1, image_relocation_start_bit) == 0x0);
    assert!(core::mem::offset_of!(ControlAreaU2E2View1, number_of_subsections) == 0x8);
    assert!(core::mem::size_of::<ControlAreaU2E2View2>() == 0x10);
    assert!(core::mem::align_of::<ControlAreaU2E2View2>() == core::mem::align_of::<ControlAreaU2E2>());
    assert!(core::mem::offset_of!(ControlAreaU2E2View2, se_image_stub) == 0x8);
};

/// `_CONTROL_AREA::u3` (0x8 bytes).
#[repr(C)]
pub struct ControlAreaU3 {
    pub image_cross_partition_charge: Field<u64>,
}

unsafe impl NtStruct for ControlAreaU3 {}

impl ControlAreaU3 {
    /// `IoAttributionContext`: bits 0..=60 de `image_cross_partition_charge`.
    pub const IO_ATTRIBUTION_CONTEXT_SHIFT: u32 = 0;
    pub const IO_ATTRIBUTION_CONTEXT_MASK: u64 = 0x1fffffffffffffff;
    #[inline(always)]
    pub fn io_attribution_context(&self) -> u64 {
        self.image_cross_partition_charge.bits(0, 61) as u64
    }
    #[inline(always)]
    pub fn set_io_attribution_context(&self, value: u64) {
        self.image_cross_partition_charge.set_bits(0, 61, value as u64)
    }
    /// `Spare`: bits 61..=63 de `image_cross_partition_charge`.
    pub const SPARE_SHIFT: u32 = 61;
    pub const SPARE_MASK: u64 = 0xe000000000000000;
    #[inline(always)]
    pub fn spare(&self) -> u64 {
        self.image_cross_partition_charge.bits(61, 3) as u64
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u64) {
        self.image_cross_partition_charge.set_bits(61, 3, value as u64)
    }
    /// `CommittedPageCount`: bits 0..=35 de `image_cross_partition_charge`.
    pub const COMMITTED_PAGE_COUNT_SHIFT: u32 = 0;
    pub const COMMITTED_PAGE_COUNT_MASK: u64 = 0xfffffffff;
    #[inline(always)]
    pub fn committed_page_count(&self) -> u64 {
        self.image_cross_partition_charge.bits(0, 36) as u64
    }
    #[inline(always)]
    pub fn set_committed_page_count(&self, value: u64) {
        self.image_cross_partition_charge.set_bits(0, 36, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<ControlAreaU3>() == 0x8);
    assert!(core::mem::offset_of!(ControlAreaU3, image_cross_partition_charge) == 0x0);
};

/// `_SEGMENT` (0x48 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SegmentView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Segment {
    /// -> `_CONTROL_AREA`
    pub control_area: Field<u64>,
    pub total_number_of_ptes: Field<u32>,
    pub segment_flags: SegmentFlags,
    pub number_of_committed_pages: Field<u64>,
    pub size_of_segment: Field<u64>,
    /// -> `_MMEXTEND_INFO`
    pub extend_info: Field<u64>,
    pub segment_lock: ExPushLock,
    pub u1: SegmentU1,
    pub u2: SegmentU2,
    /// -> `_MMPTE`
    pub prototype_pte: Field<u64>,
}

/// Vista 1 de `_SEGMENT` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SegmentView1 {
    _pad_0: Reserved<0x20>,
    /// -> `void`
    pub based_address: Field<u64>,
    _pad_28: Reserved<0x20>,
}

impl core::ops::Deref for Segment {
    type Target = SegmentView1;
    #[inline(always)]
    fn deref(&self) -> &SegmentView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SegmentView1>() }
    }
}

unsafe impl NtStruct for Segment {}

const _: () = {
    assert!(core::mem::size_of::<Segment>() == 0x48);
    assert!(core::mem::offset_of!(Segment, control_area) == 0x0);
    assert!(core::mem::offset_of!(Segment, total_number_of_ptes) == 0x8);
    assert!(core::mem::offset_of!(Segment, segment_flags) == 0xc);
    assert!(core::mem::offset_of!(Segment, number_of_committed_pages) == 0x10);
    assert!(core::mem::offset_of!(Segment, size_of_segment) == 0x18);
    assert!(core::mem::offset_of!(Segment, extend_info) == 0x20);
    assert!(core::mem::offset_of!(Segment, segment_lock) == 0x28);
    assert!(core::mem::offset_of!(Segment, u1) == 0x30);
    assert!(core::mem::offset_of!(Segment, u2) == 0x38);
    assert!(core::mem::offset_of!(Segment, prototype_pte) == 0x40);
    assert!(core::mem::size_of::<SegmentView1>() == 0x48);
    assert!(core::mem::align_of::<SegmentView1>() == core::mem::align_of::<Segment>());
    assert!(core::mem::offset_of!(SegmentView1, based_address) == 0x20);
};

/// `_SEGMENT_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct SegmentFlags {
    pub short0: Field<u16>,
    pub u_char1: Field<u8>,
    pub u_char2: Field<u8>,
}

unsafe impl NtStruct for SegmentFlags {}

impl SegmentFlags {
    /// `TotalNumberOfPtes4132`: bits 0..=9 de `short0`.
    pub const TOTAL_NUMBER_OF_PTES4132_SHIFT: u32 = 0;
    pub const TOTAL_NUMBER_OF_PTES4132_MASK: u16 = 0x3ff;
    #[inline(always)]
    pub fn total_number_of_ptes4132(&self) -> u16 {
        self.short0.bits(0, 10) as u16
    }
    #[inline(always)]
    pub fn set_total_number_of_ptes4132(&self, value: u16) {
        self.short0.set_bits(0, 10, value as u64)
    }
    /// `Spare0`: bits 10..=10 de `short0`.
    pub const SPARE0_SHIFT: u32 = 10;
    pub const SPARE0_MASK: u16 = 0x400;
    #[inline(always)]
    pub fn spare0(&self) -> u16 {
        self.short0.bits(10, 1) as u16
    }
    #[inline(always)]
    pub fn set_spare0(&self, value: u16) {
        self.short0.set_bits(10, 1, value as u64)
    }
    /// `SessionDriverProtos`: bits 11..=11 de `short0`.
    pub const SESSION_DRIVER_PROTOS_SHIFT: u32 = 11;
    pub const SESSION_DRIVER_PROTOS_MASK: u16 = 0x800;
    #[inline(always)]
    pub fn session_driver_protos(&self) -> u16 {
        self.short0.bits(11, 1) as u16
    }
    #[inline(always)]
    pub fn set_session_driver_protos(&self, value: u16) {
        self.short0.set_bits(11, 1, value as u64)
    }
    /// `LargePages`: bits 12..=12 de `short0`.
    pub const LARGE_PAGES_SHIFT: u32 = 12;
    pub const LARGE_PAGES_MASK: u16 = 0x1000;
    #[inline(always)]
    pub fn large_pages(&self) -> u16 {
        self.short0.bits(12, 1) as u16
    }
    #[inline(always)]
    pub fn set_large_pages(&self, value: u16) {
        self.short0.set_bits(12, 1, value as u64)
    }
    /// `DebugSymbolsLoaded`: bits 13..=13 de `short0`.
    pub const DEBUG_SYMBOLS_LOADED_SHIFT: u32 = 13;
    pub const DEBUG_SYMBOLS_LOADED_MASK: u16 = 0x2000;
    #[inline(always)]
    pub fn debug_symbols_loaded(&self) -> u16 {
        self.short0.bits(13, 1) as u16
    }
    #[inline(always)]
    pub fn set_debug_symbols_loaded(&self, value: u16) {
        self.short0.set_bits(13, 1, value as u64)
    }
    /// `WriteCombined`: bits 14..=14 de `short0`.
    pub const WRITE_COMBINED_SHIFT: u32 = 14;
    pub const WRITE_COMBINED_MASK: u16 = 0x4000;
    #[inline(always)]
    pub fn write_combined(&self) -> u16 {
        self.short0.bits(14, 1) as u16
    }
    #[inline(always)]
    pub fn set_write_combined(&self, value: u16) {
        self.short0.set_bits(14, 1, value as u64)
    }
    /// `NoCache`: bits 15..=15 de `short0`.
    pub const NO_CACHE_SHIFT: u32 = 15;
    pub const NO_CACHE_MASK: u16 = 0x8000;
    #[inline(always)]
    pub fn no_cache(&self) -> u16 {
        self.short0.bits(15, 1) as u16
    }
    #[inline(always)]
    pub fn set_no_cache(&self, value: u16) {
        self.short0.set_bits(15, 1, value as u64)
    }
    /// `Spare`: bits 0..=0 de `u_char1`.
    pub const SPARE_SHIFT: u32 = 0;
    pub const SPARE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn spare(&self) -> u8 {
        self.u_char1.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u8) {
        self.u_char1.set_bits(0, 1, value as u64)
    }
    /// `DefaultProtectionMask`: bits 1..=5 de `u_char1`.
    pub const DEFAULT_PROTECTION_MASK_SHIFT: u32 = 1;
    pub const DEFAULT_PROTECTION_MASK_MASK: u8 = 0x3e;
    #[inline(always)]
    pub fn default_protection_mask(&self) -> u8 {
        self.u_char1.bits(1, 5) as u8
    }
    #[inline(always)]
    pub fn set_default_protection_mask(&self, value: u8) {
        self.u_char1.set_bits(1, 5, value as u64)
    }
    /// `Binary32`: bits 6..=6 de `u_char1`.
    pub const BINARY32_SHIFT: u32 = 6;
    pub const BINARY32_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn binary32(&self) -> u8 {
        self.u_char1.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_binary32(&self, value: u8) {
        self.u_char1.set_bits(6, 1, value as u64)
    }
    /// `ContainsDebug`: bits 7..=7 de `u_char1`.
    pub const CONTAINS_DEBUG_SHIFT: u32 = 7;
    pub const CONTAINS_DEBUG_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn contains_debug(&self) -> u8 {
        self.u_char1.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_contains_debug(&self, value: u8) {
        self.u_char1.set_bits(7, 1, value as u64)
    }
    /// `ForceCollision`: bits 0..=0 de `u_char2`.
    pub const FORCE_COLLISION_SHIFT: u32 = 0;
    pub const FORCE_COLLISION_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn force_collision(&self) -> u8 {
        self.u_char2.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_force_collision(&self, value: u8) {
        self.u_char2.set_bits(0, 1, value as u64)
    }
    /// `ImageSigningType`: bits 1..=3 de `u_char2`.
    pub const IMAGE_SIGNING_TYPE_SHIFT: u32 = 1;
    pub const IMAGE_SIGNING_TYPE_MASK: u8 = 0xe;
    #[inline(always)]
    pub fn image_signing_type(&self) -> u8 {
        self.u_char2.bits(1, 3) as u8
    }
    #[inline(always)]
    pub fn set_image_signing_type(&self, value: u8) {
        self.u_char2.set_bits(1, 3, value as u64)
    }
    /// `ImageSigningLevel`: bits 4..=7 de `u_char2`.
    pub const IMAGE_SIGNING_LEVEL_SHIFT: u32 = 4;
    pub const IMAGE_SIGNING_LEVEL_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn image_signing_level(&self) -> u8 {
        self.u_char2.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_image_signing_level(&self, value: u8) {
        self.u_char2.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SegmentFlags>() == 0x4);
    assert!(core::mem::offset_of!(SegmentFlags, short0) == 0x0);
    assert!(core::mem::offset_of!(SegmentFlags, u_char1) == 0x2);
    assert!(core::mem::offset_of!(SegmentFlags, u_char2) == 0x3);
};

/// `_SEGMENT::u1` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SegmentU1View1`, alcançada por `Deref`.
#[repr(C)]
pub struct SegmentU1 {
    pub image_commitment: Field<u64>,
}

/// Vista 1 de `_SEGMENT::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SegmentU1View1 {
    _align: [u64; 0],
    pub creating_process_id: Field<u32>,
    _pad_4: Reserved<0x4>,
}

impl core::ops::Deref for SegmentU1 {
    type Target = SegmentU1View1;
    #[inline(always)]
    fn deref(&self) -> &SegmentU1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SegmentU1View1>() }
    }
}

unsafe impl NtStruct for SegmentU1 {}

const _: () = {
    assert!(core::mem::size_of::<SegmentU1>() == 0x8);
    assert!(core::mem::offset_of!(SegmentU1, image_commitment) == 0x0);
    assert!(core::mem::size_of::<SegmentU1View1>() == 0x8);
    assert!(core::mem::align_of::<SegmentU1View1>() == core::mem::align_of::<SegmentU1>());
    assert!(core::mem::offset_of!(SegmentU1View1, creating_process_id) == 0x0);
};

/// `_SEGMENT::u2` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SegmentU2View1`, alcançada por `Deref`.
#[repr(C)]
pub struct SegmentU2 {
    /// -> `_MI_SECTION_IMAGE_INFORMATION`
    pub image_information: Field<u64>,
}

/// Vista 1 de `_SEGMENT::u2` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SegmentU2View1 {
    /// -> `void`
    pub first_mapped_va: Field<u64>,
}

impl core::ops::Deref for SegmentU2 {
    type Target = SegmentU2View1;
    #[inline(always)]
    fn deref(&self) -> &SegmentU2View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SegmentU2View1>() }
    }
}

unsafe impl NtStruct for SegmentU2 {}

const _: () = {
    assert!(core::mem::size_of::<SegmentU2>() == 0x8);
    assert!(core::mem::offset_of!(SegmentU2, image_information) == 0x0);
    assert!(core::mem::size_of::<SegmentU2View1>() == 0x8);
    assert!(core::mem::align_of::<SegmentU2View1>() == core::mem::align_of::<SegmentU2>());
    assert!(core::mem::offset_of!(SegmentU2View1, first_mapped_va) == 0x0);
};

/// `_IMAGE_RUNTIME_FUNCTION_ENTRY` (0xc bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ImageRuntimeFunctionEntryView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ImageRuntimeFunctionEntry {
    pub begin_address: Field<u32>,
    pub end_address: Field<u32>,
    pub unwind_info_address: Field<u32>,
}

/// Vista 1 de `_IMAGE_RUNTIME_FUNCTION_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ImageRuntimeFunctionEntryView1 {
    _pad_0: Reserved<0x8>,
    pub unwind_data: Field<u32>,
}

impl core::ops::Deref for ImageRuntimeFunctionEntry {
    type Target = ImageRuntimeFunctionEntryView1;
    #[inline(always)]
    fn deref(&self) -> &ImageRuntimeFunctionEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ImageRuntimeFunctionEntryView1>() }
    }
}

unsafe impl NtStruct for ImageRuntimeFunctionEntry {}

const _: () = {
    assert!(core::mem::size_of::<ImageRuntimeFunctionEntry>() == 0xc);
    assert!(core::mem::offset_of!(ImageRuntimeFunctionEntry, begin_address) == 0x0);
    assert!(core::mem::offset_of!(ImageRuntimeFunctionEntry, end_address) == 0x4);
    assert!(core::mem::offset_of!(ImageRuntimeFunctionEntry, unwind_info_address) == 0x8);
    assert!(core::mem::size_of::<ImageRuntimeFunctionEntryView1>() == 0xc);
    assert!(core::mem::align_of::<ImageRuntimeFunctionEntryView1>() == core::mem::align_of::<ImageRuntimeFunctionEntry>());
    assert!(core::mem::offset_of!(ImageRuntimeFunctionEntryView1, unwind_data) == 0x8);
};

/// `_SECTION_IMAGE_INFORMATION` (0x40 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SectionImageInformationView1`, alcançada por `Deref`.
#[repr(C)]
pub struct SectionImageInformation {
    /// -> `void`
    pub transfer_address: Field<u64>,
    pub zero_bits: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub maximum_stack_size: Field<u64>,
    pub committed_stack_size: Field<u64>,
    pub sub_system_type: Field<u32>,
    pub sub_system_minor_version: Field<u16>,
    pub sub_system_major_version: Field<u16>,
    pub major_operating_system_version: Field<u16>,
    pub minor_operating_system_version: Field<u16>,
    pub image_characteristics: Field<u16>,
    pub dll_characteristics: Field<u16>,
    pub machine: Field<u16>,
    pub image_contains_code: Field<u8>,
    pub image_flags: Field<u8>,
    pub loader_flags: Field<u32>,
    pub image_file_size: Field<u32>,
    pub check_sum: Field<u32>,
}

/// Vista 1 de `_SECTION_IMAGE_INFORMATION` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SectionImageInformationView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x24>,
    pub sub_system_version: Field<u32>,
    pub operating_system_version: Field<u32>,
    _pad_2c: Reserved<0x14>,
}

impl core::ops::Deref for SectionImageInformation {
    type Target = SectionImageInformationView1;
    #[inline(always)]
    fn deref(&self) -> &SectionImageInformationView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SectionImageInformationView1>() }
    }
}

unsafe impl NtStruct for SectionImageInformation {}

impl SectionImageInformation {
    /// `ComPlusNativeReady`: bits 0..=0 de `image_flags`.
    pub const COM_PLUS_NATIVE_READY_SHIFT: u32 = 0;
    pub const COM_PLUS_NATIVE_READY_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn com_plus_native_ready(&self) -> u8 {
        self.image_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_com_plus_native_ready(&self, value: u8) {
        self.image_flags.set_bits(0, 1, value as u64)
    }
    /// `ComPlusILOnly`: bits 1..=1 de `image_flags`.
    pub const COM_PLUS_IL_ONLY_SHIFT: u32 = 1;
    pub const COM_PLUS_IL_ONLY_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn com_plus_il_only(&self) -> u8 {
        self.image_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_com_plus_il_only(&self, value: u8) {
        self.image_flags.set_bits(1, 1, value as u64)
    }
    /// `ImageDynamicallyRelocated`: bits 2..=2 de `image_flags`.
    pub const IMAGE_DYNAMICALLY_RELOCATED_SHIFT: u32 = 2;
    pub const IMAGE_DYNAMICALLY_RELOCATED_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn image_dynamically_relocated(&self) -> u8 {
        self.image_flags.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_image_dynamically_relocated(&self, value: u8) {
        self.image_flags.set_bits(2, 1, value as u64)
    }
    /// `ImageMappedFlat`: bits 3..=3 de `image_flags`.
    pub const IMAGE_MAPPED_FLAT_SHIFT: u32 = 3;
    pub const IMAGE_MAPPED_FLAT_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn image_mapped_flat(&self) -> u8 {
        self.image_flags.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_image_mapped_flat(&self, value: u8) {
        self.image_flags.set_bits(3, 1, value as u64)
    }
    /// `BaseBelow4gb`: bits 4..=4 de `image_flags`.
    pub const BASE_BELOW4GB_SHIFT: u32 = 4;
    pub const BASE_BELOW4GB_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn base_below4gb(&self) -> u8 {
        self.image_flags.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_base_below4gb(&self, value: u8) {
        self.image_flags.set_bits(4, 1, value as u64)
    }
    /// `ComPlusPrefer32bit`: bits 5..=5 de `image_flags`.
    pub const COM_PLUS_PREFER32BIT_SHIFT: u32 = 5;
    pub const COM_PLUS_PREFER32BIT_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn com_plus_prefer32bit(&self) -> u8 {
        self.image_flags.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_com_plus_prefer32bit(&self, value: u8) {
        self.image_flags.set_bits(5, 1, value as u64)
    }
    /// `Reserved`: bits 6..=7 de `image_flags`.
    pub const RESERVED_SHIFT: u32 = 6;
    pub const RESERVED_MASK: u8 = 0xc0;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.image_flags.bits(6, 2) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.image_flags.set_bits(6, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SectionImageInformation>() == 0x40);
    assert!(core::mem::offset_of!(SectionImageInformation, transfer_address) == 0x0);
    assert!(core::mem::offset_of!(SectionImageInformation, zero_bits) == 0x8);
    assert!(core::mem::offset_of!(SectionImageInformation, maximum_stack_size) == 0x10);
    assert!(core::mem::offset_of!(SectionImageInformation, committed_stack_size) == 0x18);
    assert!(core::mem::offset_of!(SectionImageInformation, sub_system_type) == 0x20);
    assert!(core::mem::offset_of!(SectionImageInformation, sub_system_minor_version) == 0x24);
    assert!(core::mem::offset_of!(SectionImageInformation, sub_system_major_version) == 0x26);
    assert!(core::mem::offset_of!(SectionImageInformation, major_operating_system_version) == 0x28);
    assert!(core::mem::offset_of!(SectionImageInformation, minor_operating_system_version) == 0x2a);
    assert!(core::mem::offset_of!(SectionImageInformation, image_characteristics) == 0x2c);
    assert!(core::mem::offset_of!(SectionImageInformation, dll_characteristics) == 0x2e);
    assert!(core::mem::offset_of!(SectionImageInformation, machine) == 0x30);
    assert!(core::mem::offset_of!(SectionImageInformation, image_contains_code) == 0x32);
    assert!(core::mem::offset_of!(SectionImageInformation, image_flags) == 0x33);
    assert!(core::mem::offset_of!(SectionImageInformation, loader_flags) == 0x34);
    assert!(core::mem::offset_of!(SectionImageInformation, image_file_size) == 0x38);
    assert!(core::mem::offset_of!(SectionImageInformation, check_sum) == 0x3c);
    assert!(core::mem::size_of::<SectionImageInformationView1>() == 0x40);
    assert!(core::mem::align_of::<SectionImageInformationView1>() == core::mem::align_of::<SectionImageInformation>());
    assert!(core::mem::offset_of!(SectionImageInformationView1, sub_system_version) == 0x24);
    assert!(core::mem::offset_of!(SectionImageInformationView1, operating_system_version) == 0x28);
};

/// `_MM_SESSION_SPACE` (0x5000 bytes).
#[repr(C)]
pub struct MmSessionSpace {
    pub reference_count: Field<i32>,
    pub u: MmSessionSpaceU,
    pub session_id: Field<u32>,
    pub process_reference_to_session: Field<i32>,
    pub process_list: ListEntry,
    pub session_page_directory_index: Field<u64>,
    pub non_pagable_pages: Field<u64>,
    pub committed_pages: Field<u64>,
    /// -> `void`
    pub paged_pool_start: Field<u64>,
    /// -> `void`
    pub paged_pool_end: Field<u64>,
    /// -> `void`
    pub session_object: Field<u64>,
    /// -> `void`
    pub session_object_handle: Field<u64>,
    pub image_tree: RtlAvlTree,
    pub locale_id: Field<u32>,
    pub attach_count: Field<u32>,
    pub attach_gate: Kgate,
    pub ws_list_entry: ListEntry,
    pub ws_tree_entry: RtlBalancedNode,
    pub paged_pool_info: MmPagedPoolInfo,
    pub session: Mmsession,
    pub combine_domain: Field<u64>,
    _pad_e8: Reserved<0x18>,
    pub vm: MmsupportFull,
    pub working_set_list: MmwslInstance,
    _pad_268: Reserved<0x18>,
    pub aggregate_session_ws: MmsupportAggregation,
    /// -> `void`
    pub heap_state: Field<u64>,
    pub driver_unload: MiSessionDriverUnload,
    pub top_level_pte_lock_bits: [Field<u32>; 32],
    pub page_directory: Mmpte,
    pub session_va_lock: ExPushLock,
    pub dynamic_va_bit_map: RtlBitmapEx,
    pub dynamic_va_hint: Field<u64>,
    pub session_pte_lock: ExPushLock,
    pub pool_big_entries_in_use: Field<i32>,
    pub paged_pool_pde_count: Field<i32>,
    pub dynamic_session_pde_count: Field<u32>,
    _pad_36c: Reserved<0x4>,
    pub system_pte_info: MiSystemPteType,
    /// -> `void`
    pub pool_track_table_expansion: Field<u64>,
    pub pool_track_table_expansion_size: Field<u64>,
    /// -> `void`
    pub pool_track_big_pages: Field<u64>,
    pub pool_track_big_pages_size: Field<u64>,
    pub permitted_faults_tree: RtlAvlTree,
    pub io_state: Field<IoSessionState>,
    pub io_state_sequence: Field<u32>,
    pub io_notification_event: Kevent,
    /// -> `_EJOB`
    pub server_silo: Field<u64>,
    pub create_time: Field<u64>,
    _pad_428: Reserved<0xbd8>,
    pub pool_tags: [Field<u8>; 16384],
}

unsafe impl NtStruct for MmSessionSpace {}

const _: () = {
    assert!(core::mem::size_of::<MmSessionSpace>() == 0x5000);
    assert!(core::mem::offset_of!(MmSessionSpace, reference_count) == 0x0);
    assert!(core::mem::offset_of!(MmSessionSpace, u) == 0x4);
    assert!(core::mem::offset_of!(MmSessionSpace, session_id) == 0x8);
    assert!(core::mem::offset_of!(MmSessionSpace, process_reference_to_session) == 0xc);
    assert!(core::mem::offset_of!(MmSessionSpace, process_list) == 0x10);
    assert!(core::mem::offset_of!(MmSessionSpace, session_page_directory_index) == 0x20);
    assert!(core::mem::offset_of!(MmSessionSpace, non_pagable_pages) == 0x28);
    assert!(core::mem::offset_of!(MmSessionSpace, committed_pages) == 0x30);
    assert!(core::mem::offset_of!(MmSessionSpace, paged_pool_start) == 0x38);
    assert!(core::mem::offset_of!(MmSessionSpace, paged_pool_end) == 0x40);
    assert!(core::mem::offset_of!(MmSessionSpace, session_object) == 0x48);
    assert!(core::mem::offset_of!(MmSessionSpace, session_object_handle) == 0x50);
    assert!(core::mem::offset_of!(MmSessionSpace, image_tree) == 0x58);
    assert!(core::mem::offset_of!(MmSessionSpace, locale_id) == 0x60);
    assert!(core::mem::offset_of!(MmSessionSpace, attach_count) == 0x64);
    assert!(core::mem::offset_of!(MmSessionSpace, attach_gate) == 0x68);
    assert!(core::mem::offset_of!(MmSessionSpace, ws_list_entry) == 0x80);
    assert!(core::mem::offset_of!(MmSessionSpace, ws_tree_entry) == 0x90);
    assert!(core::mem::offset_of!(MmSessionSpace, paged_pool_info) == 0xa8);
    assert!(core::mem::offset_of!(MmSessionSpace, session) == 0xc0);
    assert!(core::mem::offset_of!(MmSessionSpace, combine_domain) == 0xe0);
    assert!(core::mem::offset_of!(MmSessionSpace, vm) == 0x100);
    assert!(core::mem::offset_of!(MmSessionSpace, working_set_list) == 0x240);
    assert!(core::mem::offset_of!(MmSessionSpace, aggregate_session_ws) == 0x280);
    assert!(core::mem::offset_of!(MmSessionSpace, heap_state) == 0x2a0);
    assert!(core::mem::offset_of!(MmSessionSpace, driver_unload) == 0x2a8);
    assert!(core::mem::offset_of!(MmSessionSpace, top_level_pte_lock_bits) == 0x2b0);
    assert!(core::mem::offset_of!(MmSessionSpace, page_directory) == 0x330);
    assert!(core::mem::offset_of!(MmSessionSpace, session_va_lock) == 0x338);
    assert!(core::mem::offset_of!(MmSessionSpace, dynamic_va_bit_map) == 0x340);
    assert!(core::mem::offset_of!(MmSessionSpace, dynamic_va_hint) == 0x350);
    assert!(core::mem::offset_of!(MmSessionSpace, session_pte_lock) == 0x358);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_big_entries_in_use) == 0x360);
    assert!(core::mem::offset_of!(MmSessionSpace, paged_pool_pde_count) == 0x364);
    assert!(core::mem::offset_of!(MmSessionSpace, dynamic_session_pde_count) == 0x368);
    assert!(core::mem::offset_of!(MmSessionSpace, system_pte_info) == 0x370);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_track_table_expansion) == 0x3d0);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_track_table_expansion_size) == 0x3d8);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_track_big_pages) == 0x3e0);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_track_big_pages_size) == 0x3e8);
    assert!(core::mem::offset_of!(MmSessionSpace, permitted_faults_tree) == 0x3f0);
    assert!(core::mem::offset_of!(MmSessionSpace, io_state) == 0x3f8);
    assert!(core::mem::offset_of!(MmSessionSpace, io_state_sequence) == 0x3fc);
    assert!(core::mem::offset_of!(MmSessionSpace, io_notification_event) == 0x400);
    assert!(core::mem::offset_of!(MmSessionSpace, server_silo) == 0x418);
    assert!(core::mem::offset_of!(MmSessionSpace, create_time) == 0x420);
    assert!(core::mem::offset_of!(MmSessionSpace, pool_tags) == 0x1000);
};

/// `_MM_SESSION_SPACE::u` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmSessionSpaceUView1`, alcançada por `Deref`.
#[repr(C)]
pub struct MmSessionSpaceU {
    pub long_flags: Field<u32>,
}

/// Vista 1 de `_MM_SESSION_SPACE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmSessionSpaceUView1 {
    pub flags: MmSessionSpaceFlags,
}

impl core::ops::Deref for MmSessionSpaceU {
    type Target = MmSessionSpaceUView1;
    #[inline(always)]
    fn deref(&self) -> &MmSessionSpaceUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmSessionSpaceUView1>() }
    }
}

unsafe impl NtStruct for MmSessionSpaceU {}

const _: () = {
    assert!(core::mem::size_of::<MmSessionSpaceU>() == 0x4);
    assert!(core::mem::offset_of!(MmSessionSpaceU, long_flags) == 0x0);
    assert!(core::mem::size_of::<MmSessionSpaceUView1>() == 0x4);
    assert!(core::mem::align_of::<MmSessionSpaceUView1>() == core::mem::align_of::<MmSessionSpaceU>());
    assert!(core::mem::offset_of!(MmSessionSpaceUView1, flags) == 0x0);
};

/// `_MM_SESSION_SPACE_FLAGS` (0x4 bytes).
#[repr(C)]
pub struct MmSessionSpaceFlags {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for MmSessionSpaceFlags {}

impl MmSessionSpaceFlags {
    /// `Initialized`: bits 0..=0 de `bitfield_0`.
    pub const INITIALIZED_SHIFT: u32 = 0;
    pub const INITIALIZED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn initialized(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `DeletePending`: bits 1..=1 de `bitfield_0`.
    pub const DELETE_PENDING_SHIFT: u32 = 1;
    pub const DELETE_PENDING_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn delete_pending(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_delete_pending(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `PoolInitialized`: bits 2..=2 de `bitfield_0`.
    pub const POOL_INITIALIZED_SHIFT: u32 = 2;
    pub const POOL_INITIALIZED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn pool_initialized(&self) -> u32 {
        self.bitfield_0.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_pool_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `DynamicVaInitialized`: bits 3..=3 de `bitfield_0`.
    pub const DYNAMIC_VA_INITIALIZED_SHIFT: u32 = 3;
    pub const DYNAMIC_VA_INITIALIZED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn dynamic_va_initialized(&self) -> u32 {
        self.bitfield_0.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_dynamic_va_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `WsInitialized`: bits 4..=4 de `bitfield_0`.
    pub const WS_INITIALIZED_SHIFT: u32 = 4;
    pub const WS_INITIALIZED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn ws_initialized(&self) -> u32 {
        self.bitfield_0.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_ws_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `PoolDestroyed`: bits 5..=5 de `bitfield_0`.
    pub const POOL_DESTROYED_SHIFT: u32 = 5;
    pub const POOL_DESTROYED_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn pool_destroyed(&self) -> u32 {
        self.bitfield_0.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_pool_destroyed(&self, value: u32) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `ObjectInitialized`: bits 6..=6 de `bitfield_0`.
    pub const OBJECT_INITIALIZED_SHIFT: u32 = 6;
    pub const OBJECT_INITIALIZED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn object_initialized(&self) -> u32 {
        self.bitfield_0.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_object_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `SessionHeapInitialized`: bits 7..=7 de `bitfield_0`.
    pub const SESSION_HEAP_INITIALIZED_SHIFT: u32 = 7;
    pub const SESSION_HEAP_INITIALIZED_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn session_heap_initialized(&self) -> u32 {
        self.bitfield_0.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_session_heap_initialized(&self, value: u32) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `SessionHeapDestroyed`: bits 8..=8 de `bitfield_0`.
    pub const SESSION_HEAP_DESTROYED_SHIFT: u32 = 8;
    pub const SESSION_HEAP_DESTROYED_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn session_heap_destroyed(&self) -> u32 {
        self.bitfield_0.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_session_heap_destroyed(&self, value: u32) {
        self.bitfield_0.set_bits(8, 1, value as u64)
    }
    /// `LeakedPoolDeliberately`: bits 9..=9 de `bitfield_0`.
    pub const LEAKED_POOL_DELIBERATELY_SHIFT: u32 = 9;
    pub const LEAKED_POOL_DELIBERATELY_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn leaked_pool_deliberately(&self) -> u32 {
        self.bitfield_0.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_leaked_pool_deliberately(&self, value: u32) {
        self.bitfield_0.set_bits(9, 1, value as u64)
    }
    /// `Filler`: bits 10..=31 de `bitfield_0`.
    pub const FILLER_SHIFT: u32 = 10;
    pub const FILLER_MASK: u32 = 0xfffffc00;
    #[inline(always)]
    pub fn filler(&self) -> u32 {
        self.bitfield_0.bits(10, 22) as u32
    }
    #[inline(always)]
    pub fn set_filler(&self, value: u32) {
        self.bitfield_0.set_bits(10, 22, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmSessionSpaceFlags>() == 0x4);
    assert!(core::mem::offset_of!(MmSessionSpaceFlags, bitfield_0) == 0x0);
};

/// `_MM_PAGED_POOL_INFO` (0x18 bytes).
#[repr(C)]
pub struct MmPagedPoolInfo {
    pub lock: ExPushLock,
    pub maximum_size: Field<u64>,
    pub allocated_paged_pool: Field<u64>,
}

unsafe impl NtStruct for MmPagedPoolInfo {}

const _: () = {
    assert!(core::mem::size_of::<MmPagedPoolInfo>() == 0x18);
    assert!(core::mem::offset_of!(MmPagedPoolInfo, lock) == 0x0);
    assert!(core::mem::offset_of!(MmPagedPoolInfo, maximum_size) == 0x8);
    assert!(core::mem::offset_of!(MmPagedPoolInfo, allocated_paged_pool) == 0x10);
};

/// `_MMSESSION` (0x20 bytes).
#[repr(C)]
pub struct Mmsession {
    pub system_space_view_lock: ExPushLock,
    /// -> `_EX_PUSH_LOCK`
    pub system_space_view_lock_pointer: Field<u64>,
    pub view_root: RtlAvlTree,
    pub view_count: Field<u32>,
    pub bitmap_failures: Field<u32>,
}

unsafe impl NtStruct for Mmsession {}

const _: () = {
    assert!(core::mem::size_of::<Mmsession>() == 0x20);
    assert!(core::mem::offset_of!(Mmsession, system_space_view_lock) == 0x0);
    assert!(core::mem::offset_of!(Mmsession, system_space_view_lock_pointer) == 0x8);
    assert!(core::mem::offset_of!(Mmsession, view_root) == 0x10);
    assert!(core::mem::offset_of!(Mmsession, view_count) == 0x18);
    assert!(core::mem::offset_of!(Mmsession, bitmap_failures) == 0x1c);
};

/// `_MMWSL_INSTANCE` (0x28 bytes).
#[repr(C)]
pub struct MmwslInstance {
    /// -> `_MMPTE`
    pub next_pte_to_trim: Field<u64>,
    /// -> `_MMPTE`
    pub next_pte_to_age: Field<u64>,
    /// -> `_MMPTE`
    pub next_pte_to_access_clear: Field<u64>,
    pub last_access_clearing_remainder: Field<u32>,
    pub last_aging_remainder: Field<u32>,
    pub locked_entries: Field<u64>,
}

unsafe impl NtStruct for MmwslInstance {}

const _: () = {
    assert!(core::mem::size_of::<MmwslInstance>() == 0x28);
    assert!(core::mem::offset_of!(MmwslInstance, next_pte_to_trim) == 0x0);
    assert!(core::mem::offset_of!(MmwslInstance, next_pte_to_age) == 0x8);
    assert!(core::mem::offset_of!(MmwslInstance, next_pte_to_access_clear) == 0x10);
    assert!(core::mem::offset_of!(MmwslInstance, last_access_clearing_remainder) == 0x18);
    assert!(core::mem::offset_of!(MmwslInstance, last_aging_remainder) == 0x1c);
    assert!(core::mem::offset_of!(MmwslInstance, locked_entries) == 0x20);
};

/// `_MMSUPPORT_AGGREGATION` (0x20 bytes).
#[repr(C)]
pub struct MmsupportAggregation {
    pub page_fault_count: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub working_set_size: Field<u64>,
    pub working_set_leaf_size: Field<u64>,
    pub peak_working_set_size: Field<u64>,
}

unsafe impl NtStruct for MmsupportAggregation {}

const _: () = {
    assert!(core::mem::size_of::<MmsupportAggregation>() == 0x20);
    assert!(core::mem::offset_of!(MmsupportAggregation, page_fault_count) == 0x0);
    assert!(core::mem::offset_of!(MmsupportAggregation, working_set_size) == 0x8);
    assert!(core::mem::offset_of!(MmsupportAggregation, working_set_leaf_size) == 0x10);
    assert!(core::mem::offset_of!(MmsupportAggregation, peak_working_set_size) == 0x18);
};

/// `_MI_SESSION_DRIVER_UNLOAD` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MiSessionDriverUnloadView1`, alcançada por `Deref`.
#[repr(C)]
pub struct MiSessionDriverUnload {
    /// -> `fn`
    pub function: Field<u64>,
}

/// Vista 1 de `_MI_SESSION_DRIVER_UNLOAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MiSessionDriverUnloadView1 {
    pub function_value: Field<u64>,
}

impl core::ops::Deref for MiSessionDriverUnload {
    type Target = MiSessionDriverUnloadView1;
    #[inline(always)]
    fn deref(&self) -> &MiSessionDriverUnloadView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MiSessionDriverUnloadView1>() }
    }
}

unsafe impl NtStruct for MiSessionDriverUnload {}

const _: () = {
    assert!(core::mem::size_of::<MiSessionDriverUnload>() == 0x8);
    assert!(core::mem::offset_of!(MiSessionDriverUnload, function) == 0x0);
    assert!(core::mem::size_of::<MiSessionDriverUnloadView1>() == 0x8);
    assert!(core::mem::align_of::<MiSessionDriverUnloadView1>() == core::mem::align_of::<MiSessionDriverUnload>());
    assert!(core::mem::offset_of!(MiSessionDriverUnloadView1, function_value) == 0x0);
};

/// `_MMPTE` (0x8 bytes).
#[repr(C)]
pub struct Mmpte {
    pub u: MmpteU,
}

unsafe impl NtStruct for Mmpte {}

const _: () = {
    assert!(core::mem::size_of::<Mmpte>() == 0x8);
    assert!(core::mem::offset_of!(Mmpte, u) == 0x0);
};

/// `_MMPTE::u` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmpteUView1`..`MmpteUView8`, alcançadas por `Deref`.
#[repr(C)]
pub struct MmpteU {
    pub long: Field<u64>,
}

/// Vista 1 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView1 {
    pub volatile_long: Field<u64>,
}

/// Vista 2 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView2 {
    pub hard: MmpteHardware,
}

/// Vista 3 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView3 {
    pub proto: MmptePrototype,
}

/// Vista 4 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView4 {
    pub soft: MmpteSoftware,
}

/// Vista 5 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView5 {
    pub time_stamp: MmpteTimestamp,
}

/// Vista 6 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView6 {
    pub trans: MmpteTransition,
}

/// Vista 7 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView7 {
    pub subsect: MmpteSubsection,
}

/// Vista 8 de `_MMPTE::u` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpteUView8 {
    pub list: MmpteList,
}

impl core::ops::Deref for MmpteU {
    type Target = MmpteUView1;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView1>() }
    }
}

impl core::ops::Deref for MmpteUView1 {
    type Target = MmpteUView2;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView2>() }
    }
}

impl core::ops::Deref for MmpteUView2 {
    type Target = MmpteUView3;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView3>() }
    }
}

impl core::ops::Deref for MmpteUView3 {
    type Target = MmpteUView4;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView4>() }
    }
}

impl core::ops::Deref for MmpteUView4 {
    type Target = MmpteUView5;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView5>() }
    }
}

impl core::ops::Deref for MmpteUView5 {
    type Target = MmpteUView6;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView6>() }
    }
}

impl core::ops::Deref for MmpteUView6 {
    type Target = MmpteUView7;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView7>() }
    }
}

impl core::ops::Deref for MmpteUView7 {
    type Target = MmpteUView8;
    #[inline(always)]
    fn deref(&self) -> &MmpteUView8 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpteUView8>() }
    }
}

unsafe impl NtStruct for MmpteU {}

const _: () = {
    assert!(core::mem::size_of::<MmpteU>() == 0x8);
    assert!(core::mem::offset_of!(MmpteU, long) == 0x0);
    assert!(core::mem::size_of::<MmpteUView1>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView1>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView1, volatile_long) == 0x0);
    assert!(core::mem::size_of::<MmpteUView2>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView2>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView2, hard) == 0x0);
    assert!(core::mem::size_of::<MmpteUView3>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView3>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView3, proto) == 0x0);
    assert!(core::mem::size_of::<MmpteUView4>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView4>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView4, soft) == 0x0);
    assert!(core::mem::size_of::<MmpteUView5>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView5>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView5, time_stamp) == 0x0);
    assert!(core::mem::size_of::<MmpteUView6>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView6>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView6, trans) == 0x0);
    assert!(core::mem::size_of::<MmpteUView7>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView7>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView7, subsect) == 0x0);
    assert!(core::mem::size_of::<MmpteUView8>() == 0x8);
    assert!(core::mem::align_of::<MmpteUView8>() == core::mem::align_of::<MmpteU>());
    assert!(core::mem::offset_of!(MmpteUView8, list) == 0x0);
};

/// `_MMPTE_HARDWARE` (0x8 bytes).
#[repr(C)]
pub struct MmpteHardware {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteHardware {}

impl MmpteHardware {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Dirty1`: bits 1..=1 de `bitfield_0`.
    pub const DIRTY1_SHIFT: u32 = 1;
    pub const DIRTY1_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn dirty1(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_dirty1(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `Owner`: bits 2..=2 de `bitfield_0`.
    pub const OWNER_SHIFT: u32 = 2;
    pub const OWNER_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn owner(&self) -> u64 {
        self.bitfield_0.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_owner(&self, value: u64) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `WriteThrough`: bits 3..=3 de `bitfield_0`.
    pub const WRITE_THROUGH_SHIFT: u32 = 3;
    pub const WRITE_THROUGH_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn write_through(&self) -> u64 {
        self.bitfield_0.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_write_through(&self, value: u64) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `CacheDisable`: bits 4..=4 de `bitfield_0`.
    pub const CACHE_DISABLE_SHIFT: u32 = 4;
    pub const CACHE_DISABLE_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn cache_disable(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_cache_disable(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Accessed`: bits 5..=5 de `bitfield_0`.
    pub const ACCESSED_SHIFT: u32 = 5;
    pub const ACCESSED_MASK: u64 = 0x20;
    #[inline(always)]
    pub fn accessed(&self) -> u64 {
        self.bitfield_0.bits(5, 1) as u64
    }
    #[inline(always)]
    pub fn set_accessed(&self, value: u64) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `Dirty`: bits 6..=6 de `bitfield_0`.
    pub const DIRTY_SHIFT: u32 = 6;
    pub const DIRTY_MASK: u64 = 0x40;
    #[inline(always)]
    pub fn dirty(&self) -> u64 {
        self.bitfield_0.bits(6, 1) as u64
    }
    #[inline(always)]
    pub fn set_dirty(&self, value: u64) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `LargePage`: bits 7..=7 de `bitfield_0`.
    pub const LARGE_PAGE_SHIFT: u32 = 7;
    pub const LARGE_PAGE_MASK: u64 = 0x80;
    #[inline(always)]
    pub fn large_page(&self) -> u64 {
        self.bitfield_0.bits(7, 1) as u64
    }
    #[inline(always)]
    pub fn set_large_page(&self, value: u64) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `Global`: bits 8..=8 de `bitfield_0`.
    pub const GLOBAL_SHIFT: u32 = 8;
    pub const GLOBAL_MASK: u64 = 0x100;
    #[inline(always)]
    pub fn global(&self) -> u64 {
        self.bitfield_0.bits(8, 1) as u64
    }
    #[inline(always)]
    pub fn set_global(&self, value: u64) {
        self.bitfield_0.set_bits(8, 1, value as u64)
    }
    /// `CopyOnWrite`: bits 9..=9 de `bitfield_0`.
    pub const COPY_ON_WRITE_SHIFT: u32 = 9;
    pub const COPY_ON_WRITE_MASK: u64 = 0x200;
    #[inline(always)]
    pub fn copy_on_write(&self) -> u64 {
        self.bitfield_0.bits(9, 1) as u64
    }
    #[inline(always)]
    pub fn set_copy_on_write(&self, value: u64) {
        self.bitfield_0.set_bits(9, 1, value as u64)
    }
    /// `Unused`: bits 10..=10 de `bitfield_0`.
    pub const UNUSED_SHIFT: u32 = 10;
    pub const UNUSED_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Write`: bits 11..=11 de `bitfield_0`.
    pub const WRITE_SHIFT: u32 = 11;
    pub const WRITE_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn write(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_write(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `PageFrameNumber`: bits 12..=47 de `bitfield_0`.
    pub const PAGE_FRAME_NUMBER_SHIFT: u32 = 12;
    pub const PAGE_FRAME_NUMBER_MASK: u64 = 0xfffffffff000;
    #[inline(always)]
    pub fn page_frame_number(&self) -> u64 {
        self.bitfield_0.bits(12, 36) as u64
    }
    #[inline(always)]
    pub fn set_page_frame_number(&self, value: u64) {
        self.bitfield_0.set_bits(12, 36, value as u64)
    }
    /// `ReservedForHardware`: bits 48..=51 de `bitfield_0`.
    pub const RESERVED_FOR_HARDWARE_SHIFT: u32 = 48;
    pub const RESERVED_FOR_HARDWARE_MASK: u64 = 0xf000000000000;
    #[inline(always)]
    pub fn reserved_for_hardware(&self) -> u64 {
        self.bitfield_0.bits(48, 4) as u64
    }
    #[inline(always)]
    pub fn set_reserved_for_hardware(&self, value: u64) {
        self.bitfield_0.set_bits(48, 4, value as u64)
    }
    /// `ReservedForSoftware`: bits 52..=55 de `bitfield_0`.
    pub const RESERVED_FOR_SOFTWARE_SHIFT: u32 = 52;
    pub const RESERVED_FOR_SOFTWARE_MASK: u64 = 0xf0000000000000;
    #[inline(always)]
    pub fn reserved_for_software(&self) -> u64 {
        self.bitfield_0.bits(52, 4) as u64
    }
    #[inline(always)]
    pub fn set_reserved_for_software(&self, value: u64) {
        self.bitfield_0.set_bits(52, 4, value as u64)
    }
    /// `WsleAge`: bits 56..=59 de `bitfield_0`.
    pub const WSLE_AGE_SHIFT: u32 = 56;
    pub const WSLE_AGE_MASK: u64 = 0xf00000000000000;
    #[inline(always)]
    pub fn wsle_age(&self) -> u64 {
        self.bitfield_0.bits(56, 4) as u64
    }
    #[inline(always)]
    pub fn set_wsle_age(&self, value: u64) {
        self.bitfield_0.set_bits(56, 4, value as u64)
    }
    /// `WsleProtection`: bits 60..=62 de `bitfield_0`.
    pub const WSLE_PROTECTION_SHIFT: u32 = 60;
    pub const WSLE_PROTECTION_MASK: u64 = 0x7000000000000000;
    #[inline(always)]
    pub fn wsle_protection(&self) -> u64 {
        self.bitfield_0.bits(60, 3) as u64
    }
    #[inline(always)]
    pub fn set_wsle_protection(&self, value: u64) {
        self.bitfield_0.set_bits(60, 3, value as u64)
    }
    /// `NoExecute`: bits 63..=63 de `bitfield_0`.
    pub const NO_EXECUTE_SHIFT: u32 = 63;
    pub const NO_EXECUTE_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn no_execute(&self) -> u64 {
        self.bitfield_0.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_no_execute(&self, value: u64) {
        self.bitfield_0.set_bits(63, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteHardware>() == 0x8);
    assert!(core::mem::offset_of!(MmpteHardware, bitfield_0) == 0x0);
};

/// `_MMPTE_PROTOTYPE` (0x8 bytes).
#[repr(C)]
pub struct MmptePrototype {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmptePrototype {}

impl MmptePrototype {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `DemandFillProto`: bits 1..=1 de `bitfield_0`.
    pub const DEMAND_FILL_PROTO_SHIFT: u32 = 1;
    pub const DEMAND_FILL_PROTO_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn demand_fill_proto(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_demand_fill_proto(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `HiberVerifyConverted`: bits 2..=2 de `bitfield_0`.
    pub const HIBER_VERIFY_CONVERTED_SHIFT: u32 = 2;
    pub const HIBER_VERIFY_CONVERTED_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn hiber_verify_converted(&self) -> u64 {
        self.bitfield_0.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_hiber_verify_converted(&self, value: u64) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `ReadOnly`: bits 3..=3 de `bitfield_0`.
    pub const READ_ONLY_SHIFT: u32 = 3;
    pub const READ_ONLY_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn read_only(&self) -> u64 {
        self.bitfield_0.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_read_only(&self, value: u64) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Combined`: bits 11..=11 de `bitfield_0`.
    pub const COMBINED_SHIFT: u32 = 11;
    pub const COMBINED_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn combined(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_combined(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `Unused1`: bits 12..=15 de `bitfield_0`.
    pub const UNUSED1_SHIFT: u32 = 12;
    pub const UNUSED1_MASK: u64 = 0xf000;
    #[inline(always)]
    pub fn unused1(&self) -> u64 {
        self.bitfield_0.bits(12, 4) as u64
    }
    #[inline(always)]
    pub fn set_unused1(&self, value: u64) {
        self.bitfield_0.set_bits(12, 4, value as u64)
    }
    /// `ProtoAddress`: bits 16..=63 de `bitfield_0`.
    pub const PROTO_ADDRESS_SHIFT: u32 = 16;
    pub const PROTO_ADDRESS_MASK: u64 = 0xffffffffffff0000;
    #[inline(always)]
    pub fn proto_address(&self) -> u64 {
        self.bitfield_0.bits(16, 48) as u64
    }
    #[inline(always)]
    pub fn set_proto_address(&self, value: u64) {
        self.bitfield_0.set_bits(16, 48, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmptePrototype>() == 0x8);
    assert!(core::mem::offset_of!(MmptePrototype, bitfield_0) == 0x0);
};

/// `_MMPTE_SOFTWARE` (0x8 bytes).
#[repr(C)]
pub struct MmpteSoftware {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteSoftware {}

impl MmpteSoftware {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `PageFileReserved`: bits 1..=1 de `bitfield_0`.
    pub const PAGE_FILE_RESERVED_SHIFT: u32 = 1;
    pub const PAGE_FILE_RESERVED_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn page_file_reserved(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_file_reserved(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `PageFileAllocated`: bits 2..=2 de `bitfield_0`.
    pub const PAGE_FILE_ALLOCATED_SHIFT: u32 = 2;
    pub const PAGE_FILE_ALLOCATED_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn page_file_allocated(&self) -> u64 {
        self.bitfield_0.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_file_allocated(&self, value: u64) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `ColdPage`: bits 3..=3 de `bitfield_0`.
    pub const COLD_PAGE_SHIFT: u32 = 3;
    pub const COLD_PAGE_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn cold_page(&self) -> u64 {
        self.bitfield_0.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_cold_page(&self, value: u64) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Transition`: bits 11..=11 de `bitfield_0`.
    pub const TRANSITION_SHIFT: u32 = 11;
    pub const TRANSITION_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn transition(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_transition(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `PageFileLow`: bits 12..=15 de `bitfield_0`.
    pub const PAGE_FILE_LOW_SHIFT: u32 = 12;
    pub const PAGE_FILE_LOW_MASK: u64 = 0xf000;
    #[inline(always)]
    pub fn page_file_low(&self) -> u64 {
        self.bitfield_0.bits(12, 4) as u64
    }
    #[inline(always)]
    pub fn set_page_file_low(&self, value: u64) {
        self.bitfield_0.set_bits(12, 4, value as u64)
    }
    /// `UsedPageTableEntries`: bits 16..=25 de `bitfield_0`.
    pub const USED_PAGE_TABLE_ENTRIES_SHIFT: u32 = 16;
    pub const USED_PAGE_TABLE_ENTRIES_MASK: u64 = 0x3ff0000;
    #[inline(always)]
    pub fn used_page_table_entries(&self) -> u64 {
        self.bitfield_0.bits(16, 10) as u64
    }
    #[inline(always)]
    pub fn set_used_page_table_entries(&self, value: u64) {
        self.bitfield_0.set_bits(16, 10, value as u64)
    }
    /// `ShadowStack`: bits 26..=26 de `bitfield_0`.
    pub const SHADOW_STACK_SHIFT: u32 = 26;
    pub const SHADOW_STACK_MASK: u64 = 0x4000000;
    #[inline(always)]
    pub fn shadow_stack(&self) -> u64 {
        self.bitfield_0.bits(26, 1) as u64
    }
    #[inline(always)]
    pub fn set_shadow_stack(&self, value: u64) {
        self.bitfield_0.set_bits(26, 1, value as u64)
    }
    /// `Unused`: bits 27..=31 de `bitfield_0`.
    pub const UNUSED_SHIFT: u32 = 27;
    pub const UNUSED_MASK: u64 = 0xf8000000;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.bitfield_0.bits(27, 5) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.bitfield_0.set_bits(27, 5, value as u64)
    }
    /// `PageFileHigh`: bits 32..=63 de `bitfield_0`.
    pub const PAGE_FILE_HIGH_SHIFT: u32 = 32;
    pub const PAGE_FILE_HIGH_MASK: u64 = 0xffffffff00000000;
    #[inline(always)]
    pub fn page_file_high(&self) -> u64 {
        self.bitfield_0.bits(32, 32) as u64
    }
    #[inline(always)]
    pub fn set_page_file_high(&self, value: u64) {
        self.bitfield_0.set_bits(32, 32, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteSoftware>() == 0x8);
    assert!(core::mem::offset_of!(MmpteSoftware, bitfield_0) == 0x0);
};

/// `_MMPTE_TIMESTAMP` (0x8 bytes).
#[repr(C)]
pub struct MmpteTimestamp {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteTimestamp {}

impl MmpteTimestamp {
    /// `MustBeZero`: bits 0..=0 de `bitfield_0`.
    pub const MUST_BE_ZERO_SHIFT: u32 = 0;
    pub const MUST_BE_ZERO_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn must_be_zero(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_must_be_zero(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Unused`: bits 1..=3 de `bitfield_0`.
    pub const UNUSED_SHIFT: u32 = 1;
    pub const UNUSED_MASK: u64 = 0xe;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.bitfield_0.bits(1, 3) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.bitfield_0.set_bits(1, 3, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Transition`: bits 11..=11 de `bitfield_0`.
    pub const TRANSITION_SHIFT: u32 = 11;
    pub const TRANSITION_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn transition(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_transition(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `PageFileLow`: bits 12..=15 de `bitfield_0`.
    pub const PAGE_FILE_LOW_SHIFT: u32 = 12;
    pub const PAGE_FILE_LOW_MASK: u64 = 0xf000;
    #[inline(always)]
    pub fn page_file_low(&self) -> u64 {
        self.bitfield_0.bits(12, 4) as u64
    }
    #[inline(always)]
    pub fn set_page_file_low(&self, value: u64) {
        self.bitfield_0.set_bits(12, 4, value as u64)
    }
    /// `Reserved`: bits 16..=31 de `bitfield_0`.
    pub const RESERVED_SHIFT: u32 = 16;
    pub const RESERVED_MASK: u64 = 0xffff0000;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.bitfield_0.bits(16, 16) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.bitfield_0.set_bits(16, 16, value as u64)
    }
    /// `GlobalTimeStamp`: bits 32..=63 de `bitfield_0`.
    pub const GLOBAL_TIME_STAMP_SHIFT: u32 = 32;
    pub const GLOBAL_TIME_STAMP_MASK: u64 = 0xffffffff00000000;
    #[inline(always)]
    pub fn global_time_stamp(&self) -> u64 {
        self.bitfield_0.bits(32, 32) as u64
    }
    #[inline(always)]
    pub fn set_global_time_stamp(&self, value: u64) {
        self.bitfield_0.set_bits(32, 32, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteTimestamp>() == 0x8);
    assert!(core::mem::offset_of!(MmpteTimestamp, bitfield_0) == 0x0);
};

/// `_MMPTE_TRANSITION` (0x8 bytes).
#[repr(C)]
pub struct MmpteTransition {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteTransition {}

impl MmpteTransition {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Write`: bits 1..=1 de `bitfield_0`.
    pub const WRITE_SHIFT: u32 = 1;
    pub const WRITE_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn write(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_write(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `Spare`: bits 2..=2 de `bitfield_0`.
    pub const SPARE_SHIFT: u32 = 2;
    pub const SPARE_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn spare(&self) -> u64 {
        self.bitfield_0.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u64) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `IoTracker`: bits 3..=3 de `bitfield_0`.
    pub const IO_TRACKER_SHIFT: u32 = 3;
    pub const IO_TRACKER_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn io_tracker(&self) -> u64 {
        self.bitfield_0.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_io_tracker(&self, value: u64) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Transition`: bits 11..=11 de `bitfield_0`.
    pub const TRANSITION_SHIFT: u32 = 11;
    pub const TRANSITION_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn transition(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_transition(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `PageFrameNumber`: bits 12..=47 de `bitfield_0`.
    pub const PAGE_FRAME_NUMBER_SHIFT: u32 = 12;
    pub const PAGE_FRAME_NUMBER_MASK: u64 = 0xfffffffff000;
    #[inline(always)]
    pub fn page_frame_number(&self) -> u64 {
        self.bitfield_0.bits(12, 36) as u64
    }
    #[inline(always)]
    pub fn set_page_frame_number(&self, value: u64) {
        self.bitfield_0.set_bits(12, 36, value as u64)
    }
    /// `Unused`: bits 48..=63 de `bitfield_0`.
    pub const UNUSED_SHIFT: u32 = 48;
    pub const UNUSED_MASK: u64 = 0xffff000000000000;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.bitfield_0.bits(48, 16) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.bitfield_0.set_bits(48, 16, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteTransition>() == 0x8);
    assert!(core::mem::offset_of!(MmpteTransition, bitfield_0) == 0x0);
};

/// `_MMPTE_SUBSECTION` (0x8 bytes).
#[repr(C)]
pub struct MmpteSubsection {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteSubsection {}

impl MmpteSubsection {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Unused0`: bits 1..=3 de `bitfield_0`.
    pub const UNUSED0_SHIFT: u32 = 1;
    pub const UNUSED0_MASK: u64 = 0xe;
    #[inline(always)]
    pub fn unused0(&self) -> u64 {
        self.bitfield_0.bits(1, 3) as u64
    }
    #[inline(always)]
    pub fn set_unused0(&self, value: u64) {
        self.bitfield_0.set_bits(1, 3, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `ColdPage`: bits 11..=11 de `bitfield_0`.
    pub const COLD_PAGE_SHIFT: u32 = 11;
    pub const COLD_PAGE_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn cold_page(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_cold_page(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `Unused1`: bits 12..=14 de `bitfield_0`.
    pub const UNUSED1_SHIFT: u32 = 12;
    pub const UNUSED1_MASK: u64 = 0x7000;
    #[inline(always)]
    pub fn unused1(&self) -> u64 {
        self.bitfield_0.bits(12, 3) as u64
    }
    #[inline(always)]
    pub fn set_unused1(&self, value: u64) {
        self.bitfield_0.set_bits(12, 3, value as u64)
    }
    /// `ExecutePrivilege`: bits 15..=15 de `bitfield_0`.
    pub const EXECUTE_PRIVILEGE_SHIFT: u32 = 15;
    pub const EXECUTE_PRIVILEGE_MASK: u64 = 0x8000;
    #[inline(always)]
    pub fn execute_privilege(&self) -> u64 {
        self.bitfield_0.bits(15, 1) as u64
    }
    #[inline(always)]
    pub fn set_execute_privilege(&self, value: u64) {
        self.bitfield_0.set_bits(15, 1, value as u64)
    }
    /// `SubsectionAddress`: bits 16..=63 de `bitfield_0`.
    pub const SUBSECTION_ADDRESS_SHIFT: u32 = 16;
    pub const SUBSECTION_ADDRESS_MASK: u64 = 0xffffffffffff0000;
    #[inline(always)]
    pub fn subsection_address(&self) -> u64 {
        self.bitfield_0.bits(16, 48) as u64
    }
    #[inline(always)]
    pub fn set_subsection_address(&self, value: u64) {
        self.bitfield_0.set_bits(16, 48, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteSubsection>() == 0x8);
    assert!(core::mem::offset_of!(MmpteSubsection, bitfield_0) == 0x0);
};

/// `_MMPTE_LIST` (0x8 bytes).
#[repr(C)]
pub struct MmpteList {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MmpteList {}

impl MmpteList {
    /// `Valid`: bits 0..=0 de `bitfield_0`.
    pub const VALID_SHIFT: u32 = 0;
    pub const VALID_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn valid(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_valid(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `OneEntry`: bits 1..=1 de `bitfield_0`.
    pub const ONE_ENTRY_SHIFT: u32 = 1;
    pub const ONE_ENTRY_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn one_entry(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_one_entry(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `filler0`: bits 2..=3 de `bitfield_0`.
    pub const FILLER0_SHIFT: u32 = 2;
    pub const FILLER0_MASK: u64 = 0xc;
    #[inline(always)]
    pub fn filler0(&self) -> u64 {
        self.bitfield_0.bits(2, 2) as u64
    }
    #[inline(always)]
    pub fn set_filler0(&self, value: u64) {
        self.bitfield_0.set_bits(2, 2, value as u64)
    }
    /// `SwizzleBit`: bits 4..=4 de `bitfield_0`.
    pub const SWIZZLE_BIT_SHIFT: u32 = 4;
    pub const SWIZZLE_BIT_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn swizzle_bit(&self) -> u64 {
        self.bitfield_0.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_swizzle_bit(&self, value: u64) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `Protection`: bits 5..=9 de `bitfield_0`.
    pub const PROTECTION_SHIFT: u32 = 5;
    pub const PROTECTION_MASK: u64 = 0x3e0;
    #[inline(always)]
    pub fn protection(&self) -> u64 {
        self.bitfield_0.bits(5, 5) as u64
    }
    #[inline(always)]
    pub fn set_protection(&self, value: u64) {
        self.bitfield_0.set_bits(5, 5, value as u64)
    }
    /// `Prototype`: bits 10..=10 de `bitfield_0`.
    pub const PROTOTYPE_SHIFT: u32 = 10;
    pub const PROTOTYPE_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn prototype(&self) -> u64 {
        self.bitfield_0.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype(&self, value: u64) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `Transition`: bits 11..=11 de `bitfield_0`.
    pub const TRANSITION_SHIFT: u32 = 11;
    pub const TRANSITION_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn transition(&self) -> u64 {
        self.bitfield_0.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_transition(&self, value: u64) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `filler1`: bits 12..=27 de `bitfield_0`.
    pub const FILLER1_SHIFT: u32 = 12;
    pub const FILLER1_MASK: u64 = 0xffff000;
    #[inline(always)]
    pub fn filler1(&self) -> u64 {
        self.bitfield_0.bits(12, 16) as u64
    }
    #[inline(always)]
    pub fn set_filler1(&self, value: u64) {
        self.bitfield_0.set_bits(12, 16, value as u64)
    }
    /// `NextEntry`: bits 28..=63 de `bitfield_0`.
    pub const NEXT_ENTRY_SHIFT: u32 = 28;
    pub const NEXT_ENTRY_MASK: u64 = 0xfffffffff0000000;
    #[inline(always)]
    pub fn next_entry(&self) -> u64 {
        self.bitfield_0.bits(28, 36) as u64
    }
    #[inline(always)]
    pub fn set_next_entry(&self, value: u64) {
        self.bitfield_0.set_bits(28, 36, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpteList>() == 0x8);
    assert!(core::mem::offset_of!(MmpteList, bitfield_0) == 0x0);
};

/// `_MI_SYSTEM_PTE_TYPE` (0x60 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MiSystemPteTypeView1`, alcançada por `Deref`.
#[repr(C)]
pub struct MiSystemPteType {
    pub bitmap: RtlBitmapEx,
    /// -> `_MMPTE`
    pub base_pte: Field<u64>,
    pub flags: Field<u32>,
    pub va_type: Field<MiSystemVaType>,
    /// -> `u32`
    pub failure_count: Field<u64>,
    pub pte_failures: Field<u32>,
    _pad_2c: Reserved<0x4>,
    pub spin_lock: Field<u64>,
    pub total_system_ptes: Field<u64>,
    pub hint: Field<u64>,
    pub lowest_bit_ever_allocated: Field<u64>,
    /// -> `_MI_CACHED_PTES`
    pub cached_ptes: Field<u64>,
    pub total_free_system_ptes: Field<u64>,
}

/// Vista 1 de `_MI_SYSTEM_PTE_TYPE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MiSystemPteTypeView1 {
    _pad_0: Reserved<0x30>,
    /// -> `_EX_PUSH_LOCK`
    pub global_push_lock: Field<u64>,
    _pad_38: Reserved<0x28>,
}

impl core::ops::Deref for MiSystemPteType {
    type Target = MiSystemPteTypeView1;
    #[inline(always)]
    fn deref(&self) -> &MiSystemPteTypeView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MiSystemPteTypeView1>() }
    }
}

unsafe impl NtStruct for MiSystemPteType {}

const _: () = {
    assert!(core::mem::size_of::<MiSystemPteType>() == 0x60);
    assert!(core::mem::offset_of!(MiSystemPteType, bitmap) == 0x0);
    assert!(core::mem::offset_of!(MiSystemPteType, base_pte) == 0x10);
    assert!(core::mem::offset_of!(MiSystemPteType, flags) == 0x18);
    assert!(core::mem::offset_of!(MiSystemPteType, va_type) == 0x1c);
    assert!(core::mem::offset_of!(MiSystemPteType, failure_count) == 0x20);
    assert!(core::mem::offset_of!(MiSystemPteType, pte_failures) == 0x28);
    assert!(core::mem::offset_of!(MiSystemPteType, spin_lock) == 0x30);
    assert!(core::mem::offset_of!(MiSystemPteType, total_system_ptes) == 0x38);
    assert!(core::mem::offset_of!(MiSystemPteType, hint) == 0x40);
    assert!(core::mem::offset_of!(MiSystemPteType, lowest_bit_ever_allocated) == 0x48);
    assert!(core::mem::offset_of!(MiSystemPteType, cached_ptes) == 0x50);
    assert!(core::mem::offset_of!(MiSystemPteType, total_free_system_ptes) == 0x58);
    assert!(core::mem::size_of::<MiSystemPteTypeView1>() == 0x60);
    assert!(core::mem::align_of::<MiSystemPteTypeView1>() == core::mem::align_of::<MiSystemPteType>());
    assert!(core::mem::offset_of!(MiSystemPteTypeView1, global_push_lock) == 0x30);
};

/// `_MI_SYSTEM_VA_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct MiSystemVaType(pub i32);

impl MiSystemVaType {
    pub const MI_VA_UNUSED: Self = Self(0);
    pub const MI_VA_SESSION_SPACE: Self = Self(1);
    pub const MI_VA_PROCESS_SPACE: Self = Self(2);
    pub const MI_VA_BOOT_LOADED: Self = Self(3);
    pub const MI_VA_PFN_DATABASE: Self = Self(4);
    pub const MI_VA_NON_PAGED_POOL: Self = Self(5);
    pub const MI_VA_PAGED_POOL: Self = Self(6);
    pub const MI_VA_SPECIAL_POOL_PAGED: Self = Self(7);
    pub const MI_VA_SYSTEM_CACHE: Self = Self(8);
    pub const MI_VA_SYSTEM_PTES: Self = Self(9);
    pub const MI_VA_HAL: Self = Self(10);
    pub const MI_VA_SESSION_GLOBAL_SPACE: Self = Self(11);
    pub const MI_VA_DRIVER_IMAGES: Self = Self(12);
    pub const MI_VA_SYSTEM_PTES_LARGE: Self = Self(13);
    pub const MI_VA_KERNEL_STACKS: Self = Self(14);
    pub const MI_VA_SECURE_NON_PAGED_POOL: Self = Self(15);
    pub const MI_VA_MAXIMUM_TYPE: Self = Self(16);
}

impl GuestScalar for MiSystemVaType {
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

/// `_MMPFN` (0x30 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmpfnView1`..`MmpfnView3`, alcançadas por `Deref`.
#[repr(C)]
pub struct Mmpfn {
    pub list_entry: ListEntry,
    pub original_pte: Mmpte,
    pub u2: Mipfnblink,
    pub u3: MmpfnU3,
    pub node_blink_low: Field<u16>,
    pub bitfield_26: Field<u8>,
    pub view_count: Field<u8>,
    pub u4: MmpfnU4,
}

/// Vista 1 de `_MMPFN` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnView1 {
    pub tree_node: RtlBalancedNode,
    _pad_18: Reserved<0xf>,
    pub node_flink_low: Field<u8>,
    _pad_28: Reserved<0x8>,
}

/// Vista 2 de `_MMPFN` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnView2 {
    pub u1: MmpfnU1,
    /// -> `_MMPTE`
    pub pte_address: Field<u64>,
    _pad_10: Reserved<0x20>,
}

/// Vista 3 de `_MMPFN` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnView3 {
    _pad_0: Reserved<0x8>,
    pub pte_long: Field<u64>,
    _pad_10: Reserved<0x20>,
}

impl core::ops::Deref for Mmpfn {
    type Target = MmpfnView1;
    #[inline(always)]
    fn deref(&self) -> &MmpfnView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnView1>() }
    }
}

impl core::ops::Deref for MmpfnView1 {
    type Target = MmpfnView2;
    #[inline(always)]
    fn deref(&self) -> &MmpfnView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnView2>() }
    }
}

impl core::ops::Deref for MmpfnView2 {
    type Target = MmpfnView3;
    #[inline(always)]
    fn deref(&self) -> &MmpfnView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnView3>() }
    }
}

unsafe impl NtStruct for Mmpfn {}

impl Mmpfn {
    /// `Unused`: bits 0..=3 de `bitfield_26`.
    pub const UNUSED_SHIFT: u32 = 0;
    pub const UNUSED_MASK: u8 = 0xf;
    #[inline(always)]
    pub fn unused(&self) -> u8 {
        self.bitfield_26.bits(0, 4) as u8
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u8) {
        self.bitfield_26.set_bits(0, 4, value as u64)
    }
    /// `Unused2`: bits 4..=7 de `bitfield_26`.
    pub const UNUSED2_SHIFT: u32 = 4;
    pub const UNUSED2_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn unused2(&self) -> u8 {
        self.bitfield_26.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_unused2(&self, value: u8) {
        self.bitfield_26.set_bits(4, 4, value as u64)
    }
    /// `ModifiedListBucketIndex`: bits 0..=3 de `view_count`.
    pub const MODIFIED_LIST_BUCKET_INDEX_SHIFT: u32 = 0;
    pub const MODIFIED_LIST_BUCKET_INDEX_MASK: u8 = 0xf;
    #[inline(always)]
    pub fn modified_list_bucket_index(&self) -> u8 {
        self.view_count.bits(0, 4) as u8
    }
    #[inline(always)]
    pub fn set_modified_list_bucket_index(&self, value: u8) {
        self.view_count.set_bits(0, 4, value as u64)
    }
    /// `AnchorLargePageSize`: bits 0..=1 de `view_count`.
    pub const ANCHOR_LARGE_PAGE_SIZE_SHIFT: u32 = 0;
    pub const ANCHOR_LARGE_PAGE_SIZE_MASK: u8 = 0x3;
    #[inline(always)]
    pub fn anchor_large_page_size(&self) -> u8 {
        self.view_count.bits(0, 2) as u8
    }
    #[inline(always)]
    pub fn set_anchor_large_page_size(&self, value: u8) {
        self.view_count.set_bits(0, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Mmpfn>() == 0x30);
    assert!(core::mem::offset_of!(Mmpfn, list_entry) == 0x0);
    assert!(core::mem::offset_of!(Mmpfn, original_pte) == 0x10);
    assert!(core::mem::offset_of!(Mmpfn, u2) == 0x18);
    assert!(core::mem::offset_of!(Mmpfn, u3) == 0x20);
    assert!(core::mem::offset_of!(Mmpfn, node_blink_low) == 0x24);
    assert!(core::mem::offset_of!(Mmpfn, bitfield_26) == 0x26);
    assert!(core::mem::offset_of!(Mmpfn, view_count) == 0x27);
    assert!(core::mem::offset_of!(Mmpfn, u4) == 0x28);
    assert!(core::mem::size_of::<MmpfnView1>() == 0x30);
    assert!(core::mem::align_of::<MmpfnView1>() == core::mem::align_of::<Mmpfn>());
    assert!(core::mem::offset_of!(MmpfnView1, tree_node) == 0x0);
    assert!(core::mem::offset_of!(MmpfnView1, node_flink_low) == 0x27);
    assert!(core::mem::size_of::<MmpfnView2>() == 0x30);
    assert!(core::mem::align_of::<MmpfnView2>() == core::mem::align_of::<Mmpfn>());
    assert!(core::mem::offset_of!(MmpfnView2, u1) == 0x0);
    assert!(core::mem::offset_of!(MmpfnView2, pte_address) == 0x8);
    assert!(core::mem::size_of::<MmpfnView3>() == 0x30);
    assert!(core::mem::align_of::<MmpfnView3>() == core::mem::align_of::<Mmpfn>());
    assert!(core::mem::offset_of!(MmpfnView3, pte_long) == 0x8);
};

/// `_MMPFN::u1` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmpfnU1View1`..`MmpfnU1View2`, alcançadas por `Deref`.
#[repr(C)]
pub struct MmpfnU1 {
    pub next_slist_pfn: SingleListEntry,
}

/// Vista 1 de `_MMPFN::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnU1View1 {
    /// -> `void`
    pub next: Field<u64>,
}

/// Vista 2 de `_MMPFN::u1` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnU1View2 {
    pub active: MiActivePfn,
}

impl core::ops::Deref for MmpfnU1 {
    type Target = MmpfnU1View1;
    #[inline(always)]
    fn deref(&self) -> &MmpfnU1View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnU1View1>() }
    }
}

impl core::ops::Deref for MmpfnU1View1 {
    type Target = MmpfnU1View2;
    #[inline(always)]
    fn deref(&self) -> &MmpfnU1View2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnU1View2>() }
    }
}

unsafe impl NtStruct for MmpfnU1 {}

impl MmpfnU1 {
    /// `Flink`: bits 0..=35 de `next`.
    pub const FLINK_SHIFT: u32 = 0;
    pub const FLINK_MASK: u64 = 0xfffffffff;
    #[inline(always)]
    pub fn flink(&self) -> u64 {
        self.next.bits(0, 36) as u64
    }
    #[inline(always)]
    pub fn set_flink(&self, value: u64) {
        self.next.set_bits(0, 36, value as u64)
    }
    /// `NodeFlinkHigh`: bits 36..=63 de `next`.
    pub const NODE_FLINK_HIGH_SHIFT: u32 = 36;
    pub const NODE_FLINK_HIGH_MASK: u64 = 0xfffffff000000000;
    #[inline(always)]
    pub fn node_flink_high(&self) -> u64 {
        self.next.bits(36, 28) as u64
    }
    #[inline(always)]
    pub fn set_node_flink_high(&self, value: u64) {
        self.next.set_bits(36, 28, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpfnU1>() == 0x8);
    assert!(core::mem::offset_of!(MmpfnU1, next_slist_pfn) == 0x0);
    assert!(core::mem::size_of::<MmpfnU1View1>() == 0x8);
    assert!(core::mem::align_of::<MmpfnU1View1>() == core::mem::align_of::<MmpfnU1>());
    assert!(core::mem::offset_of!(MmpfnU1View1, next) == 0x0);
    assert!(core::mem::size_of::<MmpfnU1View2>() == 0x8);
    assert!(core::mem::align_of::<MmpfnU1View2>() == core::mem::align_of::<MmpfnU1>());
    assert!(core::mem::offset_of!(MmpfnU1View2, active) == 0x0);
};

/// `_MI_ACTIVE_PFN` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MiActivePfnView1`..`MiActivePfnView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct MiActivePfn {
    pub leaf: MiActivePfnLeaf,
}

/// Vista 1 de `_MI_ACTIVE_PFN` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MiActivePfnView1 {
    pub page_table: MiActivePfnPageTable,
}

/// Vista 2 de `_MI_ACTIVE_PFN` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MiActivePfnView2 {
    pub entire_active_field: Field<u64>,
}

impl core::ops::Deref for MiActivePfn {
    type Target = MiActivePfnView1;
    #[inline(always)]
    fn deref(&self) -> &MiActivePfnView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MiActivePfnView1>() }
    }
}

impl core::ops::Deref for MiActivePfnView1 {
    type Target = MiActivePfnView2;
    #[inline(always)]
    fn deref(&self) -> &MiActivePfnView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MiActivePfnView2>() }
    }
}

unsafe impl NtStruct for MiActivePfn {}

const _: () = {
    assert!(core::mem::size_of::<MiActivePfn>() == 0x8);
    assert!(core::mem::offset_of!(MiActivePfn, leaf) == 0x0);
    assert!(core::mem::size_of::<MiActivePfnView1>() == 0x8);
    assert!(core::mem::align_of::<MiActivePfnView1>() == core::mem::align_of::<MiActivePfn>());
    assert!(core::mem::offset_of!(MiActivePfnView1, page_table) == 0x0);
    assert!(core::mem::size_of::<MiActivePfnView2>() == 0x8);
    assert!(core::mem::align_of::<MiActivePfnView2>() == core::mem::align_of::<MiActivePfn>());
    assert!(core::mem::offset_of!(MiActivePfnView2, entire_active_field) == 0x0);
};

/// `_MI_ACTIVE_PFN::Leaf` (0x8 bytes).
#[repr(C)]
pub struct MiActivePfnLeaf {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MiActivePfnLeaf {}

impl MiActivePfnLeaf {
    /// `Tradable`: bits 0..=0 de `bitfield_0`.
    pub const TRADABLE_SHIFT: u32 = 0;
    pub const TRADABLE_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn tradable(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_tradable(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `NonPagedBuddy`: bits 1..=43 de `bitfield_0`.
    pub const NON_PAGED_BUDDY_SHIFT: u32 = 1;
    pub const NON_PAGED_BUDDY_MASK: u64 = 0xffffffffffe;
    #[inline(always)]
    pub fn non_paged_buddy(&self) -> u64 {
        self.bitfield_0.bits(1, 43) as u64
    }
    #[inline(always)]
    pub fn set_non_paged_buddy(&self, value: u64) {
        self.bitfield_0.set_bits(1, 43, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MiActivePfnLeaf>() == 0x8);
    assert!(core::mem::offset_of!(MiActivePfnLeaf, bitfield_0) == 0x0);
};

/// `_MI_ACTIVE_PFN::PageTable` (0x8 bytes).
#[repr(C)]
pub struct MiActivePfnPageTable {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for MiActivePfnPageTable {}

impl MiActivePfnPageTable {
    /// `Tradable`: bits 0..=0 de `bitfield_0`.
    pub const TRADABLE_SHIFT: u32 = 0;
    pub const TRADABLE_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn tradable(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_tradable(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `WsleAge`: bits 1..=3 de `bitfield_0`.
    pub const WSLE_AGE_SHIFT: u32 = 1;
    pub const WSLE_AGE_MASK: u64 = 0xe;
    #[inline(always)]
    pub fn wsle_age(&self) -> u64 {
        self.bitfield_0.bits(1, 3) as u64
    }
    #[inline(always)]
    pub fn set_wsle_age(&self, value: u64) {
        self.bitfield_0.set_bits(1, 3, value as u64)
    }
    /// `OldestWsleLeafEntries`: bits 4..=13 de `bitfield_0`.
    pub const OLDEST_WSLE_LEAF_ENTRIES_SHIFT: u32 = 4;
    pub const OLDEST_WSLE_LEAF_ENTRIES_MASK: u64 = 0x3ff0;
    #[inline(always)]
    pub fn oldest_wsle_leaf_entries(&self) -> u64 {
        self.bitfield_0.bits(4, 10) as u64
    }
    #[inline(always)]
    pub fn set_oldest_wsle_leaf_entries(&self, value: u64) {
        self.bitfield_0.set_bits(4, 10, value as u64)
    }
    /// `OldestWsleLeafAge`: bits 14..=16 de `bitfield_0`.
    pub const OLDEST_WSLE_LEAF_AGE_SHIFT: u32 = 14;
    pub const OLDEST_WSLE_LEAF_AGE_MASK: u64 = 0x1c000;
    #[inline(always)]
    pub fn oldest_wsle_leaf_age(&self) -> u64 {
        self.bitfield_0.bits(14, 3) as u64
    }
    #[inline(always)]
    pub fn set_oldest_wsle_leaf_age(&self, value: u64) {
        self.bitfield_0.set_bits(14, 3, value as u64)
    }
    /// `NonPagedBuddy`: bits 17..=59 de `bitfield_0`.
    pub const NON_PAGED_BUDDY_SHIFT: u32 = 17;
    pub const NON_PAGED_BUDDY_MASK: u64 = 0xffffffffffe0000;
    #[inline(always)]
    pub fn non_paged_buddy(&self) -> u64 {
        self.bitfield_0.bits(17, 43) as u64
    }
    #[inline(always)]
    pub fn set_non_paged_buddy(&self, value: u64) {
        self.bitfield_0.set_bits(17, 43, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MiActivePfnPageTable>() == 0x8);
    assert!(core::mem::offset_of!(MiActivePfnPageTable, bitfield_0) == 0x0);
};

/// `_MIPFNBLINK` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MipfnblinkView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Mipfnblink {
    pub entire_field: Field<u64>,
}

/// Vista 1 de `_MIPFNBLINK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MipfnblinkView1 {
    pub lock: Field<i64>,
}

impl core::ops::Deref for Mipfnblink {
    type Target = MipfnblinkView1;
    #[inline(always)]
    fn deref(&self) -> &MipfnblinkView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MipfnblinkView1>() }
    }
}

unsafe impl NtStruct for Mipfnblink {}

impl Mipfnblink {
    /// `Blink`: bits 0..=35 de `entire_field`.
    pub const BLINK_SHIFT: u32 = 0;
    pub const BLINK_MASK: u64 = 0xfffffffff;
    #[inline(always)]
    pub fn blink(&self) -> u64 {
        self.entire_field.bits(0, 36) as u64
    }
    #[inline(always)]
    pub fn set_blink(&self, value: u64) {
        self.entire_field.set_bits(0, 36, value as u64)
    }
    /// `NodeBlinkHigh`: bits 36..=55 de `entire_field`.
    pub const NODE_BLINK_HIGH_SHIFT: u32 = 36;
    pub const NODE_BLINK_HIGH_MASK: u64 = 0xfffff000000000;
    #[inline(always)]
    pub fn node_blink_high(&self) -> u64 {
        self.entire_field.bits(36, 20) as u64
    }
    #[inline(always)]
    pub fn set_node_blink_high(&self, value: u64) {
        self.entire_field.set_bits(36, 20, value as u64)
    }
    /// `TbFlushStamp`: bits 56..=59 de `entire_field`.
    pub const TB_FLUSH_STAMP_SHIFT: u32 = 56;
    pub const TB_FLUSH_STAMP_MASK: u64 = 0xf00000000000000;
    #[inline(always)]
    pub fn tb_flush_stamp(&self) -> u64 {
        self.entire_field.bits(56, 4) as u64
    }
    #[inline(always)]
    pub fn set_tb_flush_stamp(&self, value: u64) {
        self.entire_field.set_bits(56, 4, value as u64)
    }
    /// `Unused`: bits 60..=61 de `entire_field`.
    pub const UNUSED_SHIFT: u32 = 60;
    pub const UNUSED_MASK: u64 = 0x3000000000000000;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.entire_field.bits(60, 2) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.entire_field.set_bits(60, 2, value as u64)
    }
    /// `PageBlinkDeleteBit`: bits 62..=62 de `entire_field`.
    pub const PAGE_BLINK_DELETE_BIT_SHIFT: u32 = 62;
    pub const PAGE_BLINK_DELETE_BIT_MASK: u64 = 0x4000000000000000;
    #[inline(always)]
    pub fn page_blink_delete_bit(&self) -> u64 {
        self.entire_field.bits(62, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_blink_delete_bit(&self, value: u64) {
        self.entire_field.set_bits(62, 1, value as u64)
    }
    /// `PageBlinkLockBit`: bits 63..=63 de `entire_field`.
    pub const PAGE_BLINK_LOCK_BIT_SHIFT: u32 = 63;
    pub const PAGE_BLINK_LOCK_BIT_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn page_blink_lock_bit(&self) -> u64 {
        self.entire_field.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_blink_lock_bit(&self, value: u64) {
        self.entire_field.set_bits(63, 1, value as u64)
    }
    /// `ShareCount`: bits 0..=61 de `entire_field`.
    pub const SHARE_COUNT_SHIFT: u32 = 0;
    pub const SHARE_COUNT_MASK: u64 = 0x3fffffffffffffff;
    #[inline(always)]
    pub fn share_count(&self) -> u64 {
        self.entire_field.bits(0, 62) as u64
    }
    #[inline(always)]
    pub fn set_share_count(&self, value: u64) {
        self.entire_field.set_bits(0, 62, value as u64)
    }
    /// `PageShareCountDeleteBit`: bits 62..=62 de `entire_field`.
    pub const PAGE_SHARE_COUNT_DELETE_BIT_SHIFT: u32 = 62;
    pub const PAGE_SHARE_COUNT_DELETE_BIT_MASK: u64 = 0x4000000000000000;
    #[inline(always)]
    pub fn page_share_count_delete_bit(&self) -> u64 {
        self.entire_field.bits(62, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_share_count_delete_bit(&self, value: u64) {
        self.entire_field.set_bits(62, 1, value as u64)
    }
    /// `PageShareCountLockBit`: bits 63..=63 de `entire_field`.
    pub const PAGE_SHARE_COUNT_LOCK_BIT_SHIFT: u32 = 63;
    pub const PAGE_SHARE_COUNT_LOCK_BIT_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn page_share_count_lock_bit(&self) -> u64 {
        self.entire_field.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_page_share_count_lock_bit(&self, value: u64) {
        self.entire_field.set_bits(63, 1, value as u64)
    }
    /// `LockNotUsed`: bits 0..=61 de `entire_field`.
    pub const LOCK_NOT_USED_SHIFT: u32 = 0;
    pub const LOCK_NOT_USED_MASK: u64 = 0x3fffffffffffffff;
    #[inline(always)]
    pub fn lock_not_used(&self) -> u64 {
        self.entire_field.bits(0, 62) as u64
    }
    #[inline(always)]
    pub fn set_lock_not_used(&self, value: u64) {
        self.entire_field.set_bits(0, 62, value as u64)
    }
    /// `DeleteBit`: bits 62..=62 de `entire_field`.
    pub const DELETE_BIT_SHIFT: u32 = 62;
    pub const DELETE_BIT_MASK: u64 = 0x4000000000000000;
    #[inline(always)]
    pub fn delete_bit(&self) -> u64 {
        self.entire_field.bits(62, 1) as u64
    }
    #[inline(always)]
    pub fn set_delete_bit(&self, value: u64) {
        self.entire_field.set_bits(62, 1, value as u64)
    }
    /// `LockBit`: bits 63..=63 de `entire_field`.
    pub const LOCK_BIT_SHIFT: u32 = 63;
    pub const LOCK_BIT_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn lock_bit(&self) -> u64 {
        self.entire_field.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_lock_bit(&self, value: u64) {
        self.entire_field.set_bits(63, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Mipfnblink>() == 0x8);
    assert!(core::mem::offset_of!(Mipfnblink, entire_field) == 0x0);
    assert!(core::mem::size_of::<MipfnblinkView1>() == 0x8);
    assert!(core::mem::align_of::<MipfnblinkView1>() == core::mem::align_of::<Mipfnblink>());
    assert!(core::mem::offset_of!(MipfnblinkView1, lock) == 0x0);
};

/// `_MMPFN::u3` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `MmpfnU3View1`..`MmpfnU3View2`, alcançadas por `Deref`.
#[repr(C)]
pub struct MmpfnU3 {
    _align: [u32; 0],
    pub reference_count: Field<u16>,
    pub e1: Mmpfnentry1,
    pub e3: Mmpfnentry3,
}

/// Vista 1 de `_MMPFN::u3` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnU3View1 {
    _align: [u32; 0],
    pub e2: MmpfnU3E2,
    _pad_2: Reserved<0x2>,
}

/// Vista 2 de `_MMPFN::u3` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct MmpfnU3View2 {
    pub e4: MmpfnU3E4,
}

impl core::ops::Deref for MmpfnU3 {
    type Target = MmpfnU3View1;
    #[inline(always)]
    fn deref(&self) -> &MmpfnU3View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnU3View1>() }
    }
}

impl core::ops::Deref for MmpfnU3View1 {
    type Target = MmpfnU3View2;
    #[inline(always)]
    fn deref(&self) -> &MmpfnU3View2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<MmpfnU3View2>() }
    }
}

unsafe impl NtStruct for MmpfnU3 {}

const _: () = {
    assert!(core::mem::size_of::<MmpfnU3>() == 0x4);
    assert!(core::mem::offset_of!(MmpfnU3, reference_count) == 0x0);
    assert!(core::mem::offset_of!(MmpfnU3, e1) == 0x2);
    assert!(core::mem::offset_of!(MmpfnU3, e3) == 0x3);
    assert!(core::mem::size_of::<MmpfnU3View1>() == 0x4);
    assert!(core::mem::align_of::<MmpfnU3View1>() == core::mem::align_of::<MmpfnU3>());
    assert!(core::mem::offset_of!(MmpfnU3View1, e2) == 0x0);
    assert!(core::mem::size_of::<MmpfnU3View2>() == 0x4);
    assert!(core::mem::align_of::<MmpfnU3View2>() == core::mem::align_of::<MmpfnU3>());
    assert!(core::mem::offset_of!(MmpfnU3View2, e4) == 0x0);
};

/// `_MMPFNENTRY1` (0x1 bytes).
#[repr(C)]
pub struct Mmpfnentry1 {
    pub bitfield_0: Field<u8>,
}

unsafe impl NtStruct for Mmpfnentry1 {}

impl Mmpfnentry1 {
    /// `PageLocation`: bits 0..=2 de `bitfield_0`.
    pub const PAGE_LOCATION_SHIFT: u32 = 0;
    pub const PAGE_LOCATION_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn page_location(&self) -> u8 {
        self.bitfield_0.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_page_location(&self, value: u8) {
        self.bitfield_0.set_bits(0, 3, value as u64)
    }
    /// `WriteInProgress`: bits 3..=3 de `bitfield_0`.
    pub const WRITE_IN_PROGRESS_SHIFT: u32 = 3;
    pub const WRITE_IN_PROGRESS_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn write_in_progress(&self) -> u8 {
        self.bitfield_0.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_write_in_progress(&self, value: u8) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `Modified`: bits 4..=4 de `bitfield_0`.
    pub const MODIFIED_SHIFT: u32 = 4;
    pub const MODIFIED_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn modified(&self) -> u8 {
        self.bitfield_0.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_modified(&self, value: u8) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `ReadInProgress`: bits 5..=5 de `bitfield_0`.
    pub const READ_IN_PROGRESS_SHIFT: u32 = 5;
    pub const READ_IN_PROGRESS_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn read_in_progress(&self) -> u8 {
        self.bitfield_0.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_read_in_progress(&self, value: u8) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `CacheAttribute`: bits 6..=7 de `bitfield_0`.
    pub const CACHE_ATTRIBUTE_SHIFT: u32 = 6;
    pub const CACHE_ATTRIBUTE_MASK: u8 = 0xc0;
    #[inline(always)]
    pub fn cache_attribute(&self) -> u8 {
        self.bitfield_0.bits(6, 2) as u8
    }
    #[inline(always)]
    pub fn set_cache_attribute(&self, value: u8) {
        self.bitfield_0.set_bits(6, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Mmpfnentry1>() == 0x1);
    assert!(core::mem::offset_of!(Mmpfnentry1, bitfield_0) == 0x0);
};

/// `_MMPFNENTRY3` (0x1 bytes).
#[repr(C)]
pub struct Mmpfnentry3 {
    pub bitfield_0: Field<u8>,
}

unsafe impl NtStruct for Mmpfnentry3 {}

impl Mmpfnentry3 {
    /// `Priority`: bits 0..=2 de `bitfield_0`.
    pub const PRIORITY_SHIFT: u32 = 0;
    pub const PRIORITY_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn priority(&self) -> u8 {
        self.bitfield_0.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_priority(&self, value: u8) {
        self.bitfield_0.set_bits(0, 3, value as u64)
    }
    /// `OnProtectedStandby`: bits 3..=3 de `bitfield_0`.
    pub const ON_PROTECTED_STANDBY_SHIFT: u32 = 3;
    pub const ON_PROTECTED_STANDBY_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn on_protected_standby(&self) -> u8 {
        self.bitfield_0.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_on_protected_standby(&self, value: u8) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `InPageError`: bits 4..=4 de `bitfield_0`.
    pub const IN_PAGE_ERROR_SHIFT: u32 = 4;
    pub const IN_PAGE_ERROR_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn in_page_error(&self) -> u8 {
        self.bitfield_0.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_in_page_error(&self, value: u8) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `SystemChargedPage`: bits 5..=5 de `bitfield_0`.
    pub const SYSTEM_CHARGED_PAGE_SHIFT: u32 = 5;
    pub const SYSTEM_CHARGED_PAGE_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn system_charged_page(&self) -> u8 {
        self.bitfield_0.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_system_charged_page(&self, value: u8) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `RemovalRequested`: bits 6..=6 de `bitfield_0`.
    pub const REMOVAL_REQUESTED_SHIFT: u32 = 6;
    pub const REMOVAL_REQUESTED_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn removal_requested(&self) -> u8 {
        self.bitfield_0.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_removal_requested(&self, value: u8) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `ParityError`: bits 7..=7 de `bitfield_0`.
    pub const PARITY_ERROR_SHIFT: u32 = 7;
    pub const PARITY_ERROR_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn parity_error(&self) -> u8 {
        self.bitfield_0.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_parity_error(&self, value: u8) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Mmpfnentry3>() == 0x1);
    assert!(core::mem::offset_of!(Mmpfnentry3, bitfield_0) == 0x0);
};

/// `_MMPFN::u3::e2` (0x2 bytes).
#[repr(C)]
pub struct MmpfnU3E2 {
    pub reference_count: Field<u16>,
}

unsafe impl NtStruct for MmpfnU3E2 {}

const _: () = {
    assert!(core::mem::size_of::<MmpfnU3E2>() == 0x2);
    assert!(core::mem::offset_of!(MmpfnU3E2, reference_count) == 0x0);
};

/// `_MMPFN::u3::e4` (0x4 bytes).
#[repr(C)]
pub struct MmpfnU3E4 {
    pub entire_field: Field<u32>,
}

unsafe impl NtStruct for MmpfnU3E4 {}

const _: () = {
    assert!(core::mem::size_of::<MmpfnU3E4>() == 0x4);
    assert!(core::mem::offset_of!(MmpfnU3E4, entire_field) == 0x0);
};

/// `_MMPFN::u4` (0x8 bytes).
#[repr(C)]
pub struct MmpfnU4 {
    pub entire_field: Field<u64>,
}

unsafe impl NtStruct for MmpfnU4 {}

impl MmpfnU4 {
    /// `PteFrame`: bits 0..=35 de `entire_field`.
    pub const PTE_FRAME_SHIFT: u32 = 0;
    pub const PTE_FRAME_MASK: u64 = 0xfffffffff;
    #[inline(always)]
    pub fn pte_frame(&self) -> u64 {
        self.entire_field.bits(0, 36) as u64
    }
    #[inline(always)]
    pub fn set_pte_frame(&self, value: u64) {
        self.entire_field.set_bits(0, 36, value as u64)
    }
    /// `ResidentPage`: bits 36..=36 de `entire_field`.
    pub const RESIDENT_PAGE_SHIFT: u32 = 36;
    pub const RESIDENT_PAGE_MASK: u64 = 0x1000000000;
    #[inline(always)]
    pub fn resident_page(&self) -> u64 {
        self.entire_field.bits(36, 1) as u64
    }
    #[inline(always)]
    pub fn set_resident_page(&self, value: u64) {
        self.entire_field.set_bits(36, 1, value as u64)
    }
    /// `Unused1`: bits 37..=37 de `entire_field`.
    pub const UNUSED1_SHIFT: u32 = 37;
    pub const UNUSED1_MASK: u64 = 0x2000000000;
    #[inline(always)]
    pub fn unused1(&self) -> u64 {
        self.entire_field.bits(37, 1) as u64
    }
    #[inline(always)]
    pub fn set_unused1(&self, value: u64) {
        self.entire_field.set_bits(37, 1, value as u64)
    }
    /// `Unused2`: bits 38..=38 de `entire_field`.
    pub const UNUSED2_SHIFT: u32 = 38;
    pub const UNUSED2_MASK: u64 = 0x4000000000;
    #[inline(always)]
    pub fn unused2(&self) -> u64 {
        self.entire_field.bits(38, 1) as u64
    }
    #[inline(always)]
    pub fn set_unused2(&self, value: u64) {
        self.entire_field.set_bits(38, 1, value as u64)
    }
    /// `Partition`: bits 39..=48 de `entire_field`.
    pub const PARTITION_SHIFT: u32 = 39;
    pub const PARTITION_MASK: u64 = 0x1ff8000000000;
    #[inline(always)]
    pub fn partition(&self) -> u64 {
        self.entire_field.bits(39, 10) as u64
    }
    #[inline(always)]
    pub fn set_partition(&self, value: u64) {
        self.entire_field.set_bits(39, 10, value as u64)
    }
    /// `FileOnly`: bits 49..=49 de `entire_field`.
    pub const FILE_ONLY_SHIFT: u32 = 49;
    pub const FILE_ONLY_MASK: u64 = 0x2000000000000;
    #[inline(always)]
    pub fn file_only(&self) -> u64 {
        self.entire_field.bits(49, 1) as u64
    }
    #[inline(always)]
    pub fn set_file_only(&self, value: u64) {
        self.entire_field.set_bits(49, 1, value as u64)
    }
    /// `PfnExists`: bits 50..=50 de `entire_field`.
    pub const PFN_EXISTS_SHIFT: u32 = 50;
    pub const PFN_EXISTS_MASK: u64 = 0x4000000000000;
    #[inline(always)]
    pub fn pfn_exists(&self) -> u64 {
        self.entire_field.bits(50, 1) as u64
    }
    #[inline(always)]
    pub fn set_pfn_exists(&self, value: u64) {
        self.entire_field.set_bits(50, 1, value as u64)
    }
    /// `Spare`: bits 51..=59 de `entire_field`.
    pub const SPARE_SHIFT: u32 = 51;
    pub const SPARE_MASK: u64 = 0xff8000000000000;
    #[inline(always)]
    pub fn spare(&self) -> u64 {
        self.entire_field.bits(51, 9) as u64
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u64) {
        self.entire_field.set_bits(51, 9, value as u64)
    }
    /// `PageIdentity`: bits 60..=62 de `entire_field`.
    pub const PAGE_IDENTITY_SHIFT: u32 = 60;
    pub const PAGE_IDENTITY_MASK: u64 = 0x7000000000000000;
    #[inline(always)]
    pub fn page_identity(&self) -> u64 {
        self.entire_field.bits(60, 3) as u64
    }
    #[inline(always)]
    pub fn set_page_identity(&self, value: u64) {
        self.entire_field.set_bits(60, 3, value as u64)
    }
    /// `PrototypePte`: bits 63..=63 de `entire_field`.
    pub const PROTOTYPE_PTE_SHIFT: u32 = 63;
    pub const PROTOTYPE_PTE_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn prototype_pte(&self) -> u64 {
        self.entire_field.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_prototype_pte(&self, value: u64) {
        self.entire_field.set_bits(63, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<MmpfnU4>() == 0x8);
    assert!(core::mem::offset_of!(MmpfnU4, entire_field) == 0x0);
};
