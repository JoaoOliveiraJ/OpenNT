//! Rtl: listas, strings, inteiros grandes e estruturas de runtime.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_UNICODE_STRING` (0x10 bytes).
#[repr(C)]
pub struct UnicodeString {
    pub length: Field<u16>,
    pub maximum_length: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `u16`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for UnicodeString {}

const _: () = {
    assert!(core::mem::size_of::<UnicodeString>() == 0x10);
    assert!(core::mem::offset_of!(UnicodeString, length) == 0x0);
    assert!(core::mem::offset_of!(UnicodeString, maximum_length) == 0x2);
    assert!(core::mem::offset_of!(UnicodeString, buffer) == 0x8);
};

/// `_LIST_ENTRY` (0x10 bytes).
#[repr(C)]
pub struct ListEntry {
    /// -> `_LIST_ENTRY`
    pub flink: Field<u64>,
    /// -> `_LIST_ENTRY`
    pub blink: Field<u64>,
}

unsafe impl NtStruct for ListEntry {}

const _: () = {
    assert!(core::mem::size_of::<ListEntry>() == 0x10);
    assert!(core::mem::offset_of!(ListEntry, flink) == 0x0);
    assert!(core::mem::offset_of!(ListEntry, blink) == 0x8);
};

/// `_SINGLE_LIST_ENTRY` (0x8 bytes).
#[repr(C)]
pub struct SingleListEntry {
    /// -> `_SINGLE_LIST_ENTRY`
    pub next: Field<u64>,
}

unsafe impl NtStruct for SingleListEntry {}

const _: () = {
    assert!(core::mem::size_of::<SingleListEntry>() == 0x8);
    assert!(core::mem::offset_of!(SingleListEntry, next) == 0x0);
};

/// `_LARGE_INTEGER` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `LargeIntegerView1`..`LargeIntegerView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct LargeInteger {
    _align: [u64; 0],
    pub low_part: Field<u32>,
    pub high_part: Field<i32>,
}

/// Vista 1 de `_LARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct LargeIntegerView1 {
    _align: [u64; 0],
    pub u: LargeIntegerU,
}

/// Vista 2 de `_LARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct LargeIntegerView2 {
    pub quad_part: Field<i64>,
}

impl core::ops::Deref for LargeInteger {
    type Target = LargeIntegerView1;
    #[inline(always)]
    fn deref(&self) -> &LargeIntegerView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<LargeIntegerView1>() }
    }
}

impl core::ops::Deref for LargeIntegerView1 {
    type Target = LargeIntegerView2;
    #[inline(always)]
    fn deref(&self) -> &LargeIntegerView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<LargeIntegerView2>() }
    }
}

unsafe impl NtStruct for LargeInteger {}

const _: () = {
    assert!(core::mem::size_of::<LargeInteger>() == 0x8);
    assert!(core::mem::offset_of!(LargeInteger, low_part) == 0x0);
    assert!(core::mem::offset_of!(LargeInteger, high_part) == 0x4);
    assert!(core::mem::size_of::<LargeIntegerView1>() == 0x8);
    assert!(core::mem::align_of::<LargeIntegerView1>() == core::mem::align_of::<LargeInteger>());
    assert!(core::mem::offset_of!(LargeIntegerView1, u) == 0x0);
    assert!(core::mem::size_of::<LargeIntegerView2>() == 0x8);
    assert!(core::mem::align_of::<LargeIntegerView2>() == core::mem::align_of::<LargeInteger>());
    assert!(core::mem::offset_of!(LargeIntegerView2, quad_part) == 0x0);
};

/// `_LARGE_INTEGER::u` (0x8 bytes).
#[repr(C)]
pub struct LargeIntegerU {
    pub low_part: Field<u32>,
    pub high_part: Field<i32>,
}

unsafe impl NtStruct for LargeIntegerU {}

const _: () = {
    assert!(core::mem::size_of::<LargeIntegerU>() == 0x8);
    assert!(core::mem::offset_of!(LargeIntegerU, low_part) == 0x0);
    assert!(core::mem::offset_of!(LargeIntegerU, high_part) == 0x4);
};

/// `_ULARGE_INTEGER` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `UlargeIntegerView1`..`UlargeIntegerView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct UlargeInteger {
    _align: [u64; 0],
    pub low_part: Field<u32>,
    pub high_part: Field<u32>,
}

/// Vista 1 de `_ULARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct UlargeIntegerView1 {
    _align: [u64; 0],
    pub u: UlargeIntegerU,
}

/// Vista 2 de `_ULARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct UlargeIntegerView2 {
    pub quad_part: Field<u64>,
}

impl core::ops::Deref for UlargeInteger {
    type Target = UlargeIntegerView1;
    #[inline(always)]
    fn deref(&self) -> &UlargeIntegerView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<UlargeIntegerView1>() }
    }
}

impl core::ops::Deref for UlargeIntegerView1 {
    type Target = UlargeIntegerView2;
    #[inline(always)]
    fn deref(&self) -> &UlargeIntegerView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<UlargeIntegerView2>() }
    }
}

unsafe impl NtStruct for UlargeInteger {}

const _: () = {
    assert!(core::mem::size_of::<UlargeInteger>() == 0x8);
    assert!(core::mem::offset_of!(UlargeInteger, low_part) == 0x0);
    assert!(core::mem::offset_of!(UlargeInteger, high_part) == 0x4);
    assert!(core::mem::size_of::<UlargeIntegerView1>() == 0x8);
    assert!(core::mem::align_of::<UlargeIntegerView1>() == core::mem::align_of::<UlargeInteger>());
    assert!(core::mem::offset_of!(UlargeIntegerView1, u) == 0x0);
    assert!(core::mem::size_of::<UlargeIntegerView2>() == 0x8);
    assert!(core::mem::align_of::<UlargeIntegerView2>() == core::mem::align_of::<UlargeInteger>());
    assert!(core::mem::offset_of!(UlargeIntegerView2, quad_part) == 0x0);
};

/// `_ULARGE_INTEGER::u` (0x8 bytes).
#[repr(C)]
pub struct UlargeIntegerU {
    pub low_part: Field<u32>,
    pub high_part: Field<u32>,
}

unsafe impl NtStruct for UlargeIntegerU {}

const _: () = {
    assert!(core::mem::size_of::<UlargeIntegerU>() == 0x8);
    assert!(core::mem::offset_of!(UlargeIntegerU, low_part) == 0x0);
    assert!(core::mem::offset_of!(UlargeIntegerU, high_part) == 0x4);
};

/// `_GUID` (0x10 bytes).
#[repr(C)]
pub struct Guid {
    pub data1: Field<u32>,
    pub data2: Field<u16>,
    pub data3: Field<u16>,
    pub data4: [Field<u8>; 8],
}

unsafe impl NtStruct for Guid {}

const _: () = {
    assert!(core::mem::size_of::<Guid>() == 0x10);
    assert!(core::mem::offset_of!(Guid, data1) == 0x0);
    assert!(core::mem::offset_of!(Guid, data2) == 0x4);
    assert!(core::mem::offset_of!(Guid, data3) == 0x6);
    assert!(core::mem::offset_of!(Guid, data4) == 0x8);
};

/// `_SLIST_HEADER` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `SlistHeaderView1`, alcançada por `Deref`.
#[repr(C)]
pub struct SlistHeader {
    pub alignment: Field<u64>,
    pub region: Field<u64>,
}

/// Vista 1 de `_SLIST_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct SlistHeaderView1 {
    pub header_x64: SlistHeaderHeaderX64,
}

impl core::ops::Deref for SlistHeader {
    type Target = SlistHeaderView1;
    #[inline(always)]
    fn deref(&self) -> &SlistHeaderView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<SlistHeaderView1>() }
    }
}

unsafe impl NtStruct for SlistHeader {}

const _: () = {
    assert!(core::mem::size_of::<SlistHeader>() == 0x10);
    assert!(core::mem::offset_of!(SlistHeader, alignment) == 0x0);
    assert!(core::mem::offset_of!(SlistHeader, region) == 0x8);
    assert!(core::mem::size_of::<SlistHeaderView1>() == 0x10);
    assert!(core::mem::align_of::<SlistHeaderView1>() == core::mem::align_of::<SlistHeader>());
    assert!(core::mem::offset_of!(SlistHeaderView1, header_x64) == 0x0);
};

/// `_SLIST_HEADER::HeaderX64` (0x10 bytes).
#[repr(C)]
pub struct SlistHeaderHeaderX64 {
    pub bitfield_0: Field<u64>,
    pub bitfield_8: Field<u64>,
}

unsafe impl NtStruct for SlistHeaderHeaderX64 {}

impl SlistHeaderHeaderX64 {
    /// `Depth`: bits 0..=15 de `bitfield_0`.
    pub const DEPTH_SHIFT: u32 = 0;
    pub const DEPTH_MASK: u64 = 0xffff;
    #[inline(always)]
    pub fn depth(&self) -> u64 {
        self.bitfield_0.bits(0, 16) as u64
    }
    #[inline(always)]
    pub fn set_depth(&self, value: u64) {
        self.bitfield_0.set_bits(0, 16, value as u64)
    }
    /// `Sequence`: bits 16..=63 de `bitfield_0`.
    pub const SEQUENCE_SHIFT: u32 = 16;
    pub const SEQUENCE_MASK: u64 = 0xffffffffffff0000;
    #[inline(always)]
    pub fn sequence(&self) -> u64 {
        self.bitfield_0.bits(16, 48) as u64
    }
    #[inline(always)]
    pub fn set_sequence(&self, value: u64) {
        self.bitfield_0.set_bits(16, 48, value as u64)
    }
    /// `Reserved`: bits 0..=3 de `bitfield_8`.
    pub const RESERVED_SHIFT: u32 = 0;
    pub const RESERVED_MASK: u64 = 0xf;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.bitfield_8.bits(0, 4) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.bitfield_8.set_bits(0, 4, value as u64)
    }
    /// `NextEntry`: bits 4..=63 de `bitfield_8`.
    pub const NEXT_ENTRY_SHIFT: u32 = 4;
    pub const NEXT_ENTRY_MASK: u64 = 0xfffffffffffffff0;
    #[inline(always)]
    pub fn next_entry(&self) -> u64 {
        self.bitfield_8.bits(4, 60) as u64
    }
    #[inline(always)]
    pub fn set_next_entry(&self, value: u64) {
        self.bitfield_8.set_bits(4, 60, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<SlistHeaderHeaderX64>() == 0x10);
    assert!(core::mem::offset_of!(SlistHeaderHeaderX64, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(SlistHeaderHeaderX64, bitfield_8) == 0x8);
};

/// `_RTL_BALANCED_NODE` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `RtlBalancedNodeView1`, alcançada por `Deref`.
#[repr(C)]
pub struct RtlBalancedNode {
    /// -> `_RTL_BALANCED_NODE`
    pub children: [Field<u64>; 2],
    pub bitfield_10: Field<u8>,
    _pad_11: Reserved<0x7>,
}

/// Vista 1 de `_RTL_BALANCED_NODE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct RtlBalancedNodeView1 {
    /// -> `_RTL_BALANCED_NODE`
    pub left: Field<u64>,
    /// -> `_RTL_BALANCED_NODE`
    pub right: Field<u64>,
    pub parent_value: Field<u64>,
}

impl core::ops::Deref for RtlBalancedNode {
    type Target = RtlBalancedNodeView1;
    #[inline(always)]
    fn deref(&self) -> &RtlBalancedNodeView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<RtlBalancedNodeView1>() }
    }
}

unsafe impl NtStruct for RtlBalancedNode {}

impl RtlBalancedNode {
    /// `Red`: bits 0..=0 de `bitfield_10`.
    pub const RED_SHIFT: u32 = 0;
    pub const RED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn red(&self) -> u8 {
        self.bitfield_10.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_red(&self, value: u8) {
        self.bitfield_10.set_bits(0, 1, value as u64)
    }
    /// `Balance`: bits 0..=1 de `bitfield_10`.
    pub const BALANCE_SHIFT: u32 = 0;
    pub const BALANCE_MASK: u8 = 0x3;
    #[inline(always)]
    pub fn balance(&self) -> u8 {
        self.bitfield_10.bits(0, 2) as u8
    }
    #[inline(always)]
    pub fn set_balance(&self, value: u8) {
        self.bitfield_10.set_bits(0, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<RtlBalancedNode>() == 0x18);
    assert!(core::mem::offset_of!(RtlBalancedNode, children) == 0x0);
    assert!(core::mem::offset_of!(RtlBalancedNode, bitfield_10) == 0x10);
    assert!(core::mem::size_of::<RtlBalancedNodeView1>() == 0x18);
    assert!(core::mem::align_of::<RtlBalancedNodeView1>() == core::mem::align_of::<RtlBalancedNode>());
    assert!(core::mem::offset_of!(RtlBalancedNodeView1, left) == 0x0);
    assert!(core::mem::offset_of!(RtlBalancedNodeView1, right) == 0x8);
    assert!(core::mem::offset_of!(RtlBalancedNodeView1, parent_value) == 0x10);
};

/// `_RTL_RB_TREE` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `RtlRbTreeView1`, alcançada por `Deref`.
#[repr(C)]
pub struct RtlRbTree {
    /// -> `_RTL_BALANCED_NODE`
    pub root: Field<u64>,
    pub bitfield_8: Field<u8>,
    _pad_9: Reserved<0x7>,
}

/// Vista 1 de `_RTL_RB_TREE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct RtlRbTreeView1 {
    _pad_0: Reserved<0x8>,
    /// -> `_RTL_BALANCED_NODE`
    pub min: Field<u64>,
}

impl core::ops::Deref for RtlRbTree {
    type Target = RtlRbTreeView1;
    #[inline(always)]
    fn deref(&self) -> &RtlRbTreeView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<RtlRbTreeView1>() }
    }
}

unsafe impl NtStruct for RtlRbTree {}

impl RtlRbTree {
    /// `Encoded`: bits 0..=0 de `bitfield_8`.
    pub const ENCODED_SHIFT: u32 = 0;
    pub const ENCODED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn encoded(&self) -> u8 {
        self.bitfield_8.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_encoded(&self, value: u8) {
        self.bitfield_8.set_bits(0, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<RtlRbTree>() == 0x10);
    assert!(core::mem::offset_of!(RtlRbTree, root) == 0x0);
    assert!(core::mem::offset_of!(RtlRbTree, bitfield_8) == 0x8);
    assert!(core::mem::size_of::<RtlRbTreeView1>() == 0x10);
    assert!(core::mem::align_of::<RtlRbTreeView1>() == core::mem::align_of::<RtlRbTree>());
    assert!(core::mem::offset_of!(RtlRbTreeView1, min) == 0x8);
};

/// `_RTL_AVL_TREE` (0x8 bytes).
#[repr(C)]
pub struct RtlAvlTree {
    /// -> `_RTL_BALANCED_NODE`
    pub root: Field<u64>,
}

unsafe impl NtStruct for RtlAvlTree {}

const _: () = {
    assert!(core::mem::size_of::<RtlAvlTree>() == 0x8);
    assert!(core::mem::offset_of!(RtlAvlTree, root) == 0x0);
};

/// `_RTL_BITMAP` (0x10 bytes).
#[repr(C)]
pub struct RtlBitmap {
    pub size_of_bit_map: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `u32`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for RtlBitmap {}

const _: () = {
    assert!(core::mem::size_of::<RtlBitmap>() == 0x10);
    assert!(core::mem::offset_of!(RtlBitmap, size_of_bit_map) == 0x0);
    assert!(core::mem::offset_of!(RtlBitmap, buffer) == 0x8);
};

/// `_LARGE_INTEGER` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `LargeIntegerUnalignedView1`..`LargeIntegerUnalignedView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct LargeIntegerUnaligned {
    pub low_part: UnalignedField<u32>,
    pub high_part: UnalignedField<i32>,
}

/// Vista 1 de `_LARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct LargeIntegerUnalignedView1 {
    pub u: LargeIntegerUUnaligned,
}

/// Vista 2 de `_LARGE_INTEGER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct LargeIntegerUnalignedView2 {
    pub quad_part: UnalignedField<i64>,
}

impl core::ops::Deref for LargeIntegerUnaligned {
    type Target = LargeIntegerUnalignedView1;
    #[inline(always)]
    fn deref(&self) -> &LargeIntegerUnalignedView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<LargeIntegerUnalignedView1>() }
    }
}

impl core::ops::Deref for LargeIntegerUnalignedView1 {
    type Target = LargeIntegerUnalignedView2;
    #[inline(always)]
    fn deref(&self) -> &LargeIntegerUnalignedView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<LargeIntegerUnalignedView2>() }
    }
}

unsafe impl NtStruct for LargeIntegerUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<LargeIntegerUnaligned>() == 0x8);
    assert!(core::mem::offset_of!(LargeIntegerUnaligned, low_part) == 0x0);
    assert!(core::mem::offset_of!(LargeIntegerUnaligned, high_part) == 0x4);
    assert!(core::mem::size_of::<LargeIntegerUnalignedView1>() == 0x8);
    assert!(core::mem::align_of::<LargeIntegerUnalignedView1>() == core::mem::align_of::<LargeIntegerUnaligned>());
    assert!(core::mem::offset_of!(LargeIntegerUnalignedView1, u) == 0x0);
    assert!(core::mem::size_of::<LargeIntegerUnalignedView2>() == 0x8);
    assert!(core::mem::align_of::<LargeIntegerUnalignedView2>() == core::mem::align_of::<LargeIntegerUnaligned>());
    assert!(core::mem::offset_of!(LargeIntegerUnalignedView2, quad_part) == 0x0);
};

/// `_LARGE_INTEGER::u` (0x8 bytes).
#[repr(C)]
pub struct LargeIntegerUUnaligned {
    pub low_part: UnalignedField<u32>,
    pub high_part: UnalignedField<i32>,
}

unsafe impl NtStruct for LargeIntegerUUnaligned {}

const _: () = {
    assert!(core::mem::size_of::<LargeIntegerUUnaligned>() == 0x8);
    assert!(core::mem::offset_of!(LargeIntegerUUnaligned, low_part) == 0x0);
    assert!(core::mem::offset_of!(LargeIntegerUUnaligned, high_part) == 0x4);
};

/// `_NT_TIB` (0x38 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `NtTibView1`, alcançada por `Deref`.
#[repr(C)]
pub struct NtTib {
    /// -> `_EXCEPTION_REGISTRATION_RECORD`
    pub exception_list: Field<u64>,
    /// -> `void`
    pub stack_base: Field<u64>,
    /// -> `void`
    pub stack_limit: Field<u64>,
    /// -> `void`
    pub sub_system_tib: Field<u64>,
    /// -> `void`
    pub fiber_data: Field<u64>,
    /// -> `void`
    pub arbitrary_user_pointer: Field<u64>,
    /// -> `_NT_TIB`
    pub self_: Field<u64>,
}

/// Vista 1 de `_NT_TIB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct NtTibView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x20>,
    pub version: Field<u32>,
    _pad_24: Reserved<0x14>,
}

impl core::ops::Deref for NtTib {
    type Target = NtTibView1;
    #[inline(always)]
    fn deref(&self) -> &NtTibView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<NtTibView1>() }
    }
}

unsafe impl NtStruct for NtTib {}

const _: () = {
    assert!(core::mem::size_of::<NtTib>() == 0x38);
    assert!(core::mem::offset_of!(NtTib, exception_list) == 0x0);
    assert!(core::mem::offset_of!(NtTib, stack_base) == 0x8);
    assert!(core::mem::offset_of!(NtTib, stack_limit) == 0x10);
    assert!(core::mem::offset_of!(NtTib, sub_system_tib) == 0x18);
    assert!(core::mem::offset_of!(NtTib, fiber_data) == 0x20);
    assert!(core::mem::offset_of!(NtTib, arbitrary_user_pointer) == 0x28);
    assert!(core::mem::offset_of!(NtTib, self_) == 0x30);
    assert!(core::mem::size_of::<NtTibView1>() == 0x38);
    assert!(core::mem::align_of::<NtTibView1>() == core::mem::align_of::<NtTib>());
    assert!(core::mem::offset_of!(NtTibView1, version) == 0x20);
};

/// `_M128A` (0x10 bytes).
#[repr(C)]
pub struct M128a {
    pub low: Field<u64>,
    pub high: Field<i64>,
}

unsafe impl NtStruct for M128a {}

const _: () = {
    assert!(core::mem::size_of::<M128a>() == 0x10);
    assert!(core::mem::offset_of!(M128a, low) == 0x0);
    assert!(core::mem::offset_of!(M128a, high) == 0x8);
};

/// `_QUAD` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `QuadView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Quad {
    pub use_this_field_to_copy: Field<i64>,
}

/// Vista 1 de `_QUAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct QuadView1 {
    pub do_not_use_this_field: Field<f64>,
}

impl core::ops::Deref for Quad {
    type Target = QuadView1;
    #[inline(always)]
    fn deref(&self) -> &QuadView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<QuadView1>() }
    }
}

unsafe impl NtStruct for Quad {}

const _: () = {
    assert!(core::mem::size_of::<Quad>() == 0x8);
    assert!(core::mem::offset_of!(Quad, use_this_field_to_copy) == 0x0);
    assert!(core::mem::size_of::<QuadView1>() == 0x8);
    assert!(core::mem::align_of::<QuadView1>() == core::mem::align_of::<Quad>());
    assert!(core::mem::offset_of!(QuadView1, do_not_use_this_field) == 0x0);
};

/// `_STRING` (0x10 bytes).
#[repr(C)]
pub struct String {
    pub length: Field<u16>,
    pub maximum_length: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `i8`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for String {}

const _: () = {
    assert!(core::mem::size_of::<String>() == 0x10);
    assert!(core::mem::offset_of!(String, length) == 0x0);
    assert!(core::mem::offset_of!(String, maximum_length) == 0x2);
    assert!(core::mem::offset_of!(String, buffer) == 0x8);
};

/// `_RTL_RUN_ONCE` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `RtlRunOnceView1`, alcançada por `Deref`.
#[repr(C)]
pub struct RtlRunOnce {
    /// -> `void`
    pub ptr: Field<u64>,
}

/// Vista 1 de `_RTL_RUN_ONCE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct RtlRunOnceView1 {
    pub value: Field<u64>,
}

impl core::ops::Deref for RtlRunOnce {
    type Target = RtlRunOnceView1;
    #[inline(always)]
    fn deref(&self) -> &RtlRunOnceView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<RtlRunOnceView1>() }
    }
}

unsafe impl NtStruct for RtlRunOnce {}

impl RtlRunOnce {
    /// `State`: bits 0..=1 de `value`.
    pub const STATE_SHIFT: u32 = 0;
    pub const STATE_MASK: u64 = 0x3;
    #[inline(always)]
    pub fn state(&self) -> u64 {
        self.value.bits(0, 2) as u64
    }
    #[inline(always)]
    pub fn set_state(&self, value: u64) {
        self.value.set_bits(0, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<RtlRunOnce>() == 0x8);
    assert!(core::mem::offset_of!(RtlRunOnce, ptr) == 0x0);
    assert!(core::mem::size_of::<RtlRunOnceView1>() == 0x8);
    assert!(core::mem::align_of::<RtlRunOnceView1>() == core::mem::align_of::<RtlRunOnce>());
    assert!(core::mem::offset_of!(RtlRunOnceView1, value) == 0x0);
};

/// `_RTL_USER_PROCESS_PARAMETERS` (0x440 bytes).
#[repr(C)]
pub struct RtlUserProcessParameters {
    pub maximum_length: Field<u32>,
    pub length: Field<u32>,
    pub flags: Field<u32>,
    pub debug_flags: Field<u32>,
    /// -> `void`
    pub console_handle: Field<u64>,
    pub console_flags: Field<u32>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub standard_input: Field<u64>,
    /// -> `void`
    pub standard_output: Field<u64>,
    /// -> `void`
    pub standard_error: Field<u64>,
    pub current_directory: Curdir,
    pub dll_path: UnicodeString,
    pub image_path_name: UnicodeString,
    pub command_line: UnicodeString,
    /// -> `void`
    pub environment: Field<u64>,
    pub starting_x: Field<u32>,
    pub starting_y: Field<u32>,
    pub count_x: Field<u32>,
    pub count_y: Field<u32>,
    pub count_chars_x: Field<u32>,
    pub count_chars_y: Field<u32>,
    pub fill_attribute: Field<u32>,
    pub window_flags: Field<u32>,
    pub show_window_flags: Field<u32>,
    _pad_ac: Reserved<0x4>,
    pub window_title: UnicodeString,
    pub desktop_info: UnicodeString,
    pub shell_info: UnicodeString,
    pub runtime_data: UnicodeString,
    pub current_directores: [RtlDriveLetterCurdir; 32],
    pub environment_size: Field<u64>,
    pub environment_version: Field<u64>,
    /// -> `void`
    pub package_dependency_data: Field<u64>,
    pub process_group_id: Field<u32>,
    pub loader_threads: Field<u32>,
    pub redirection_dll_name: UnicodeString,
    pub heap_partition_name: UnicodeString,
    /// -> `u64`
    pub default_threadpool_cpu_set_masks: Field<u64>,
    pub default_threadpool_cpu_set_mask_count: Field<u32>,
    pub default_threadpool_thread_maximum: Field<u32>,
}

unsafe impl NtStruct for RtlUserProcessParameters {}

const _: () = {
    assert!(core::mem::size_of::<RtlUserProcessParameters>() == 0x440);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, maximum_length) == 0x0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, length) == 0x4);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, flags) == 0x8);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, debug_flags) == 0xc);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, console_handle) == 0x10);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, console_flags) == 0x18);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, standard_input) == 0x20);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, standard_output) == 0x28);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, standard_error) == 0x30);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, current_directory) == 0x38);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, dll_path) == 0x50);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, image_path_name) == 0x60);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, command_line) == 0x70);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, environment) == 0x80);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, starting_x) == 0x88);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, starting_y) == 0x8c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, count_x) == 0x90);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, count_y) == 0x94);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, count_chars_x) == 0x98);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, count_chars_y) == 0x9c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, fill_attribute) == 0xa0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, window_flags) == 0xa4);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, show_window_flags) == 0xa8);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, window_title) == 0xb0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, desktop_info) == 0xc0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, shell_info) == 0xd0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, runtime_data) == 0xe0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, current_directores) == 0xf0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, environment_size) == 0x3f0);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, environment_version) == 0x3f8);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, package_dependency_data) == 0x400);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, process_group_id) == 0x408);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, loader_threads) == 0x40c);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, redirection_dll_name) == 0x410);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, heap_partition_name) == 0x420);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, default_threadpool_cpu_set_masks) == 0x430);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, default_threadpool_cpu_set_mask_count) == 0x438);
    assert!(core::mem::offset_of!(RtlUserProcessParameters, default_threadpool_thread_maximum) == 0x43c);
};

/// `_CURDIR` (0x18 bytes).
#[repr(C)]
pub struct Curdir {
    pub dos_path: UnicodeString,
    /// -> `void`
    pub handle: Field<u64>,
}

unsafe impl NtStruct for Curdir {}

const _: () = {
    assert!(core::mem::size_of::<Curdir>() == 0x18);
    assert!(core::mem::offset_of!(Curdir, dos_path) == 0x0);
    assert!(core::mem::offset_of!(Curdir, handle) == 0x10);
};

/// `_RTL_DRIVE_LETTER_CURDIR` (0x18 bytes).
#[repr(C)]
pub struct RtlDriveLetterCurdir {
    pub flags: Field<u16>,
    pub length: Field<u16>,
    pub time_stamp: Field<u32>,
    pub dos_path: String,
}

unsafe impl NtStruct for RtlDriveLetterCurdir {}

const _: () = {
    assert!(core::mem::size_of::<RtlDriveLetterCurdir>() == 0x18);
    assert!(core::mem::offset_of!(RtlDriveLetterCurdir, flags) == 0x0);
    assert!(core::mem::offset_of!(RtlDriveLetterCurdir, length) == 0x2);
    assert!(core::mem::offset_of!(RtlDriveLetterCurdir, time_stamp) == 0x4);
    assert!(core::mem::offset_of!(RtlDriveLetterCurdir, dos_path) == 0x8);
};

/// `_LUID` (0x8 bytes).
#[repr(C)]
pub struct Luid {
    pub low_part: Field<u32>,
    pub high_part: Field<i32>,
}

unsafe impl NtStruct for Luid {}

const _: () = {
    assert!(core::mem::size_of::<Luid>() == 0x8);
    assert!(core::mem::offset_of!(Luid, low_part) == 0x0);
    assert!(core::mem::offset_of!(Luid, high_part) == 0x4);
};

/// `_EXCEPTION_RECORD` (0x98 bytes).
#[repr(C)]
pub struct ExceptionRecord {
    pub exception_code: Field<i32>,
    pub exception_flags: Field<u32>,
    /// -> `_EXCEPTION_RECORD`
    pub exception_record: Field<u64>,
    /// -> `void`
    pub exception_address: Field<u64>,
    pub number_parameters: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub exception_information: [Field<u64>; 15],
}

unsafe impl NtStruct for ExceptionRecord {}

const _: () = {
    assert!(core::mem::size_of::<ExceptionRecord>() == 0x98);
    assert!(core::mem::offset_of!(ExceptionRecord, exception_code) == 0x0);
    assert!(core::mem::offset_of!(ExceptionRecord, exception_flags) == 0x4);
    assert!(core::mem::offset_of!(ExceptionRecord, exception_record) == 0x8);
    assert!(core::mem::offset_of!(ExceptionRecord, exception_address) == 0x10);
    assert!(core::mem::offset_of!(ExceptionRecord, number_parameters) == 0x18);
    assert!(core::mem::offset_of!(ExceptionRecord, exception_information) == 0x20);
};

/// `_RTL_DYNAMIC_HASH_TABLE` (0x28 bytes).
#[repr(C)]
pub struct RtlDynamicHashTable {
    pub flags: Field<u32>,
    pub shift: Field<u32>,
    pub table_size: Field<u32>,
    pub pivot: Field<u32>,
    pub divisor_mask: Field<u32>,
    pub num_entries: Field<u32>,
    pub non_empty_buckets: Field<u32>,
    pub num_enumerators: Field<u32>,
    /// -> `void`
    pub directory: Field<u64>,
}

unsafe impl NtStruct for RtlDynamicHashTable {}

const _: () = {
    assert!(core::mem::size_of::<RtlDynamicHashTable>() == 0x28);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, flags) == 0x0);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, shift) == 0x4);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, table_size) == 0x8);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, pivot) == 0xc);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, divisor_mask) == 0x10);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, num_entries) == 0x14);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, non_empty_buckets) == 0x18);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, num_enumerators) == 0x1c);
    assert!(core::mem::offset_of!(RtlDynamicHashTable, directory) == 0x20);
};

/// `_RTL_DYNAMIC_HASH_TABLE_ENUMERATOR` (0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `RtlDynamicHashTableEnumeratorView1`, alcançada por `Deref`.
#[repr(C)]
pub struct RtlDynamicHashTableEnumerator {
    pub hash_entry: RtlDynamicHashTableEntry,
    /// -> `_LIST_ENTRY`
    pub chain_head: Field<u64>,
    pub bucket_index: Field<u32>,
    _pad_24: Reserved<0x4>,
}

/// Vista 1 de `_RTL_DYNAMIC_HASH_TABLE_ENUMERATOR` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct RtlDynamicHashTableEnumeratorView1 {
    /// -> `_LIST_ENTRY`
    pub cur_entry: Field<u64>,
    _pad_8: Reserved<0x20>,
}

impl core::ops::Deref for RtlDynamicHashTableEnumerator {
    type Target = RtlDynamicHashTableEnumeratorView1;
    #[inline(always)]
    fn deref(&self) -> &RtlDynamicHashTableEnumeratorView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<RtlDynamicHashTableEnumeratorView1>() }
    }
}

unsafe impl NtStruct for RtlDynamicHashTableEnumerator {}

const _: () = {
    assert!(core::mem::size_of::<RtlDynamicHashTableEnumerator>() == 0x28);
    assert!(core::mem::offset_of!(RtlDynamicHashTableEnumerator, hash_entry) == 0x0);
    assert!(core::mem::offset_of!(RtlDynamicHashTableEnumerator, chain_head) == 0x18);
    assert!(core::mem::offset_of!(RtlDynamicHashTableEnumerator, bucket_index) == 0x20);
    assert!(core::mem::size_of::<RtlDynamicHashTableEnumeratorView1>() == 0x28);
    assert!(core::mem::align_of::<RtlDynamicHashTableEnumeratorView1>() == core::mem::align_of::<RtlDynamicHashTableEnumerator>());
    assert!(core::mem::offset_of!(RtlDynamicHashTableEnumeratorView1, cur_entry) == 0x0);
};

/// `_RTL_DYNAMIC_HASH_TABLE_ENTRY` (0x18 bytes).
#[repr(C)]
pub struct RtlDynamicHashTableEntry {
    pub linkage: ListEntry,
    pub signature: Field<u64>,
}

unsafe impl NtStruct for RtlDynamicHashTableEntry {}

const _: () = {
    assert!(core::mem::size_of::<RtlDynamicHashTableEntry>() == 0x18);
    assert!(core::mem::offset_of!(RtlDynamicHashTableEntry, linkage) == 0x0);
    assert!(core::mem::offset_of!(RtlDynamicHashTableEntry, signature) == 0x10);
};

/// `_RTL_AVL_TABLE` (0x68 bytes).
#[repr(C)]
pub struct RtlAvlTable {
    pub balanced_root: RtlBalancedLinks,
    /// -> `void`
    pub ordered_pointer: Field<u64>,
    pub which_ordered_element: Field<u32>,
    pub number_generic_table_elements: Field<u32>,
    pub depth_of_tree: Field<u32>,
    _pad_34: Reserved<0x4>,
    /// -> `_RTL_BALANCED_LINKS`
    pub restart_key: Field<u64>,
    pub delete_count: Field<u32>,
    _pad_44: Reserved<0x4>,
    /// -> `fn`
    pub compare_routine: Field<u64>,
    /// -> `fn`
    pub allocate_routine: Field<u64>,
    /// -> `fn`
    pub free_routine: Field<u64>,
    /// -> `void`
    pub table_context: Field<u64>,
}

unsafe impl NtStruct for RtlAvlTable {}

const _: () = {
    assert!(core::mem::size_of::<RtlAvlTable>() == 0x68);
    assert!(core::mem::offset_of!(RtlAvlTable, balanced_root) == 0x0);
    assert!(core::mem::offset_of!(RtlAvlTable, ordered_pointer) == 0x20);
    assert!(core::mem::offset_of!(RtlAvlTable, which_ordered_element) == 0x28);
    assert!(core::mem::offset_of!(RtlAvlTable, number_generic_table_elements) == 0x2c);
    assert!(core::mem::offset_of!(RtlAvlTable, depth_of_tree) == 0x30);
    assert!(core::mem::offset_of!(RtlAvlTable, restart_key) == 0x38);
    assert!(core::mem::offset_of!(RtlAvlTable, delete_count) == 0x40);
    assert!(core::mem::offset_of!(RtlAvlTable, compare_routine) == 0x48);
    assert!(core::mem::offset_of!(RtlAvlTable, allocate_routine) == 0x50);
    assert!(core::mem::offset_of!(RtlAvlTable, free_routine) == 0x58);
    assert!(core::mem::offset_of!(RtlAvlTable, table_context) == 0x60);
};

/// `_RTL_BALANCED_LINKS` (0x20 bytes).
#[repr(C)]
pub struct RtlBalancedLinks {
    /// -> `_RTL_BALANCED_LINKS`
    pub parent: Field<u64>,
    /// -> `_RTL_BALANCED_LINKS`
    pub left_child: Field<u64>,
    /// -> `_RTL_BALANCED_LINKS`
    pub right_child: Field<u64>,
    pub balance: Field<i8>,
    pub reserved: [Field<u8>; 3],
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for RtlBalancedLinks {}

const _: () = {
    assert!(core::mem::size_of::<RtlBalancedLinks>() == 0x20);
    assert!(core::mem::offset_of!(RtlBalancedLinks, parent) == 0x0);
    assert!(core::mem::offset_of!(RtlBalancedLinks, left_child) == 0x8);
    assert!(core::mem::offset_of!(RtlBalancedLinks, right_child) == 0x10);
    assert!(core::mem::offset_of!(RtlBalancedLinks, balance) == 0x18);
    assert!(core::mem::offset_of!(RtlBalancedLinks, reserved) == 0x19);
};

/// `_RTL_QUERY_REGISTRY_TABLE` (0x38 bytes).
#[repr(C)]
pub struct RtlQueryRegistryTable {
    /// -> `fn`
    pub query_routine: Field<u64>,
    pub flags: Field<u32>,
    _pad_c: Reserved<0x4>,
    /// -> `u16`
    pub name: Field<u64>,
    /// -> `void`
    pub entry_context: Field<u64>,
    pub default_type: Field<u32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub default_data: Field<u64>,
    pub default_length: Field<u32>,
    _pad_34: Reserved<0x4>,
}

unsafe impl NtStruct for RtlQueryRegistryTable {}

const _: () = {
    assert!(core::mem::size_of::<RtlQueryRegistryTable>() == 0x38);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, query_routine) == 0x0);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, flags) == 0x8);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, name) == 0x10);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, entry_context) == 0x18);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, default_type) == 0x20);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, default_data) == 0x28);
    assert!(core::mem::offset_of!(RtlQueryRegistryTable, default_length) == 0x30);
};

/// `_RTL_DYNAMIC_HASH_TABLE_CONTEXT` (0x18 bytes).
#[repr(C)]
pub struct RtlDynamicHashTableContext {
    /// -> `_LIST_ENTRY`
    pub chain_head: Field<u64>,
    /// -> `_LIST_ENTRY`
    pub prev_linkage: Field<u64>,
    pub signature: Field<u64>,
}

unsafe impl NtStruct for RtlDynamicHashTableContext {}

const _: () = {
    assert!(core::mem::size_of::<RtlDynamicHashTableContext>() == 0x18);
    assert!(core::mem::offset_of!(RtlDynamicHashTableContext, chain_head) == 0x0);
    assert!(core::mem::offset_of!(RtlDynamicHashTableContext, prev_linkage) == 0x8);
    assert!(core::mem::offset_of!(RtlDynamicHashTableContext, signature) == 0x10);
};

/// `_RTL_FEATURE_USAGE_REPORT` (0x8 bytes).
#[repr(C)]
pub struct RtlFeatureUsageReport {
    pub feature_id: Field<u32>,
    pub reporting_kind: Field<u16>,
    pub reporting_options: Field<u16>,
}

unsafe impl NtStruct for RtlFeatureUsageReport {}

const _: () = {
    assert!(core::mem::size_of::<RtlFeatureUsageReport>() == 0x8);
    assert!(core::mem::offset_of!(RtlFeatureUsageReport, feature_id) == 0x0);
    assert!(core::mem::offset_of!(RtlFeatureUsageReport, reporting_kind) == 0x4);
    assert!(core::mem::offset_of!(RtlFeatureUsageReport, reporting_options) == 0x6);
};

/// `_TIME_FIELDS` (0x10 bytes).
#[repr(C)]
pub struct TimeFields {
    pub year: Field<i16>,
    pub month: Field<i16>,
    pub day: Field<i16>,
    pub hour: Field<i16>,
    pub minute: Field<i16>,
    pub second: Field<i16>,
    pub milliseconds: Field<i16>,
    pub weekday: Field<i16>,
}

unsafe impl NtStruct for TimeFields {}

const _: () = {
    assert!(core::mem::size_of::<TimeFields>() == 0x10);
    assert!(core::mem::offset_of!(TimeFields, year) == 0x0);
    assert!(core::mem::offset_of!(TimeFields, month) == 0x2);
    assert!(core::mem::offset_of!(TimeFields, day) == 0x4);
    assert!(core::mem::offset_of!(TimeFields, hour) == 0x6);
    assert!(core::mem::offset_of!(TimeFields, minute) == 0x8);
    assert!(core::mem::offset_of!(TimeFields, second) == 0xa);
    assert!(core::mem::offset_of!(TimeFields, milliseconds) == 0xc);
    assert!(core::mem::offset_of!(TimeFields, weekday) == 0xe);
};

/// `_RTL_SPLAY_LINKS` (0x18 bytes).
#[repr(C)]
pub struct RtlSplayLinks {
    /// -> `_RTL_SPLAY_LINKS`
    pub parent: Field<u64>,
    /// -> `_RTL_SPLAY_LINKS`
    pub left_child: Field<u64>,
    /// -> `_RTL_SPLAY_LINKS`
    pub right_child: Field<u64>,
}

unsafe impl NtStruct for RtlSplayLinks {}

const _: () = {
    assert!(core::mem::size_of::<RtlSplayLinks>() == 0x18);
    assert!(core::mem::offset_of!(RtlSplayLinks, parent) == 0x0);
    assert!(core::mem::offset_of!(RtlSplayLinks, left_child) == 0x8);
    assert!(core::mem::offset_of!(RtlSplayLinks, right_child) == 0x10);
};

/// `_RTL_BITMAP_EX` (0x10 bytes).
#[repr(C)]
pub struct RtlBitmapEx {
    pub size_of_bit_map: Field<u64>,
    /// -> `u64`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for RtlBitmapEx {}

const _: () = {
    assert!(core::mem::size_of::<RtlBitmapEx>() == 0x10);
    assert!(core::mem::offset_of!(RtlBitmapEx, size_of_bit_map) == 0x0);
    assert!(core::mem::offset_of!(RtlBitmapEx, buffer) == 0x8);
};

/// `_EXCEPTION_RECORD64` (0x98 bytes).
#[repr(C)]
pub struct ExceptionRecord64 {
    pub exception_code: Field<i32>,
    pub exception_flags: Field<u32>,
    pub exception_record: Field<u64>,
    pub exception_address: Field<u64>,
    pub number_parameters: Field<u32>,
    pub unused_alignment: Field<u32>,
    pub exception_information: [Field<u64>; 15],
}

unsafe impl NtStruct for ExceptionRecord64 {}

const _: () = {
    assert!(core::mem::size_of::<ExceptionRecord64>() == 0x98);
    assert!(core::mem::offset_of!(ExceptionRecord64, exception_code) == 0x0);
    assert!(core::mem::offset_of!(ExceptionRecord64, exception_flags) == 0x4);
    assert!(core::mem::offset_of!(ExceptionRecord64, exception_record) == 0x8);
    assert!(core::mem::offset_of!(ExceptionRecord64, exception_address) == 0x10);
    assert!(core::mem::offset_of!(ExceptionRecord64, number_parameters) == 0x18);
    assert!(core::mem::offset_of!(ExceptionRecord64, unused_alignment) == 0x1c);
    assert!(core::mem::offset_of!(ExceptionRecord64, exception_information) == 0x20);
};

/// `_SLIST_ENTRY` (0x10 bytes).
#[repr(C)]
pub struct SlistEntry {
    /// -> `_SLIST_ENTRY`
    pub next: Field<u64>,
    _pad_8: Reserved<0x8>,
}

unsafe impl NtStruct for SlistEntry {}

const _: () = {
    assert!(core::mem::size_of::<SlistEntry>() == 0x10);
    assert!(core::mem::offset_of!(SlistEntry, next) == 0x0);
};
