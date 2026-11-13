//! Ke: objetos de despacho, threads/processos do kernel, PCR/PRCB e contexto.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_KDEVICE_QUEUE_ENTRY` (0x18 bytes).
#[repr(C)]
pub struct KdeviceQueueEntry {
    pub device_list_entry: ListEntry,
    pub sort_key: Field<u32>,
    pub inserted: Field<u8>,
    _pad_15: Reserved<0x3>,
}

unsafe impl NtStruct for KdeviceQueueEntry {}

const _: () = {
    assert!(core::mem::size_of::<KdeviceQueueEntry>() == 0x18);
    assert!(core::mem::offset_of!(KdeviceQueueEntry, device_list_entry) == 0x0);
    assert!(core::mem::offset_of!(KdeviceQueueEntry, sort_key) == 0x10);
    assert!(core::mem::offset_of!(KdeviceQueueEntry, inserted) == 0x14);
};

/// `_KDEVICE_QUEUE` (0x28 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KdeviceQueueView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KdeviceQueue {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_4: Reserved<0x4>,
    pub device_list_head: ListEntry,
    pub lock: Field<u64>,
    pub busy: Field<u8>,
    _pad_21: Reserved<0x7>,
}

/// Vista 1 de `_KDEVICE_QUEUE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KdeviceQueueView1 {
    _pad_0: Reserved<0x20>,
    pub bitfield_20: Field<u64>,
}

impl core::ops::Deref for KdeviceQueue {
    type Target = KdeviceQueueView1;
    #[inline(always)]
    fn deref(&self) -> &KdeviceQueueView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KdeviceQueueView1>() }
    }
}

unsafe impl NtStruct for KdeviceQueue {}

impl KdeviceQueue {
    /// `Reserved`: bits 0..=7 de `bitfield_20`.
    pub const RESERVED_SHIFT: u32 = 0;
    pub const RESERVED_MASK: u64 = 0xff;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.bitfield_20.bits(0, 8) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.bitfield_20.set_bits(0, 8, value as u64)
    }
    /// `Hint`: bits 8..=63 de `bitfield_20`.
    pub const HINT_SHIFT: u32 = 8;
    pub const HINT_MASK: u64 = 0xffffffffffffff00;
    #[inline(always)]
    pub fn hint(&self) -> u64 {
        self.bitfield_20.bits(8, 56) as u64
    }
    #[inline(always)]
    pub fn set_hint(&self, value: u64) {
        self.bitfield_20.set_bits(8, 56, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KdeviceQueue>() == 0x28);
    assert!(core::mem::offset_of!(KdeviceQueue, type_) == 0x0);
    assert!(core::mem::offset_of!(KdeviceQueue, size) == 0x2);
    assert!(core::mem::offset_of!(KdeviceQueue, device_list_head) == 0x8);
    assert!(core::mem::offset_of!(KdeviceQueue, lock) == 0x18);
    assert!(core::mem::offset_of!(KdeviceQueue, busy) == 0x20);
    assert!(core::mem::size_of::<KdeviceQueueView1>() == 0x28);
    assert!(core::mem::align_of::<KdeviceQueueView1>() == core::mem::align_of::<KdeviceQueue>());
    assert!(core::mem::offset_of!(KdeviceQueueView1, bitfield_20) == 0x20);
};

/// `_KDPC` (0x40 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KdpcView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Kdpc {
    pub target_info_as_ulong: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub dpc_list_entry: SingleListEntry,
    pub processor_history: Field<u64>,
    /// -> `fn`
    pub deferred_routine: Field<u64>,
    /// -> `void`
    pub deferred_context: Field<u64>,
    /// -> `void`
    pub system_argument1: Field<u64>,
    /// -> `void`
    pub system_argument2: Field<u64>,
    /// -> `void`
    pub dpc_data: Field<u64>,
}

/// Vista 1 de `_KDPC` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KdpcView1 {
    _align: [u64; 0],
    pub type_: Field<u8>,
    pub importance: Field<u8>,
    pub number: Field<u16>,
    _pad_4: Reserved<0x3c>,
}

impl core::ops::Deref for Kdpc {
    type Target = KdpcView1;
    #[inline(always)]
    fn deref(&self) -> &KdpcView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KdpcView1>() }
    }
}

unsafe impl NtStruct for Kdpc {}

const _: () = {
    assert!(core::mem::size_of::<Kdpc>() == 0x40);
    assert!(core::mem::offset_of!(Kdpc, target_info_as_ulong) == 0x0);
    assert!(core::mem::offset_of!(Kdpc, dpc_list_entry) == 0x8);
    assert!(core::mem::offset_of!(Kdpc, processor_history) == 0x10);
    assert!(core::mem::offset_of!(Kdpc, deferred_routine) == 0x18);
    assert!(core::mem::offset_of!(Kdpc, deferred_context) == 0x20);
    assert!(core::mem::offset_of!(Kdpc, system_argument1) == 0x28);
    assert!(core::mem::offset_of!(Kdpc, system_argument2) == 0x30);
    assert!(core::mem::offset_of!(Kdpc, dpc_data) == 0x38);
    assert!(core::mem::size_of::<KdpcView1>() == 0x40);
    assert!(core::mem::align_of::<KdpcView1>() == core::mem::align_of::<Kdpc>());
    assert!(core::mem::offset_of!(KdpcView1, type_) == 0x0);
    assert!(core::mem::offset_of!(KdpcView1, importance) == 0x1);
    assert!(core::mem::offset_of!(KdpcView1, number) == 0x2);
};

/// `_KEVENT` (0x18 bytes).
#[repr(C)]
pub struct Kevent {
    pub header: DispatcherHeader,
}

unsafe impl NtStruct for Kevent {}

const _: () = {
    assert!(core::mem::size_of::<Kevent>() == 0x18);
    assert!(core::mem::offset_of!(Kevent, header) == 0x0);
};

/// `_DISPATCHER_HEADER` (0x18 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `DispatcherHeaderView1`..`DispatcherHeaderView7`, alcançadas por `Deref`.
#[repr(C)]
pub struct DispatcherHeader {
    pub lock: Field<i32>,
    pub signal_state: Field<i32>,
    pub wait_list_head: ListEntry,
}

/// Vista 1 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView1 {
    _align: [u64; 0],
    pub lock_nv: Field<i32>,
    _pad_4: Reserved<0x14>,
}

/// Vista 2 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView2 {
    _align: [u64; 0],
    pub type_: Field<u8>,
    pub signalling: Field<u8>,
    pub size: Field<u8>,
    pub reserved1: Field<u8>,
    _pad_4: Reserved<0x14>,
}

/// Vista 3 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView3 {
    _align: [u64; 0],
    pub timer_type: Field<u8>,
    pub timer_control_flags: Field<u8>,
    pub hand: Field<u8>,
    pub timer_misc_flags: Field<u8>,
    _pad_4: Reserved<0x14>,
}

/// Vista 4 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView4 {
    _align: [u64; 0],
    pub timer2_type: Field<u8>,
    pub timer2_flags: Field<u8>,
    pub timer2_component_id: Field<u8>,
    pub timer2_relative_id: Field<u8>,
    _pad_4: Reserved<0x14>,
}

/// Vista 5 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView5 {
    _align: [u64; 0],
    pub queue_type: Field<u8>,
    pub queue_control_flags: Field<u8>,
    pub queue_size: Field<u8>,
    pub queue_reserved: Field<u8>,
    _pad_4: Reserved<0x14>,
}

/// Vista 6 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView6 {
    _align: [u64; 0],
    pub thread_type: Field<u8>,
    pub thread_reserved: Field<u8>,
    pub thread_control_flags: Field<u8>,
    pub debug_active: Field<u8>,
    _pad_4: Reserved<0x14>,
}

/// Vista 7 de `_DISPATCHER_HEADER` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct DispatcherHeaderView7 {
    _align: [u64; 0],
    pub mutant_type: Field<u8>,
    pub mutant_size: Field<u8>,
    pub dpc_active: Field<u8>,
    pub mutant_reserved: Field<u8>,
    _pad_4: Reserved<0x14>,
}

impl core::ops::Deref for DispatcherHeader {
    type Target = DispatcherHeaderView1;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView1>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView1 {
    type Target = DispatcherHeaderView2;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView2>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView2 {
    type Target = DispatcherHeaderView3;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView3 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView3>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView3 {
    type Target = DispatcherHeaderView4;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView4 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView4>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView4 {
    type Target = DispatcherHeaderView5;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView5 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView5>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView5 {
    type Target = DispatcherHeaderView6;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView6 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView6>() }
    }
}

impl core::ops::Deref for DispatcherHeaderView6 {
    type Target = DispatcherHeaderView7;
    #[inline(always)]
    fn deref(&self) -> &DispatcherHeaderView7 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<DispatcherHeaderView7>() }
    }
}

unsafe impl NtStruct for DispatcherHeader {}

impl DispatcherHeader {
    /// `Absolute`: bits 0..=0 de `signalling`.
    pub const ABSOLUTE_SHIFT: u32 = 0;
    pub const ABSOLUTE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn absolute(&self) -> u8 {
        self.signalling.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_absolute(&self, value: u8) {
        self.signalling.set_bits(0, 1, value as u64)
    }
    /// `Wake`: bits 1..=1 de `signalling`.
    pub const WAKE_SHIFT: u32 = 1;
    pub const WAKE_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn wake(&self) -> u8 {
        self.signalling.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_wake(&self, value: u8) {
        self.signalling.set_bits(1, 1, value as u64)
    }
    /// `EncodedTolerableDelay`: bits 2..=7 de `signalling`.
    pub const ENCODED_TOLERABLE_DELAY_SHIFT: u32 = 2;
    pub const ENCODED_TOLERABLE_DELAY_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn encoded_tolerable_delay(&self) -> u8 {
        self.signalling.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_encoded_tolerable_delay(&self, value: u8) {
        self.signalling.set_bits(2, 6, value as u64)
    }
    /// `Timer2Inserted`: bits 0..=0 de `signalling`.
    pub const TIMER2_INSERTED_SHIFT: u32 = 0;
    pub const TIMER2_INSERTED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn timer2_inserted(&self) -> u8 {
        self.signalling.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_inserted(&self, value: u8) {
        self.signalling.set_bits(0, 1, value as u64)
    }
    /// `Timer2Expiring`: bits 1..=1 de `signalling`.
    pub const TIMER2_EXPIRING_SHIFT: u32 = 1;
    pub const TIMER2_EXPIRING_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn timer2_expiring(&self) -> u8 {
        self.signalling.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_expiring(&self, value: u8) {
        self.signalling.set_bits(1, 1, value as u64)
    }
    /// `Timer2CancelPending`: bits 2..=2 de `signalling`.
    pub const TIMER2_CANCEL_PENDING_SHIFT: u32 = 2;
    pub const TIMER2_CANCEL_PENDING_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn timer2_cancel_pending(&self) -> u8 {
        self.signalling.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_cancel_pending(&self, value: u8) {
        self.signalling.set_bits(2, 1, value as u64)
    }
    /// `Timer2SetPending`: bits 3..=3 de `signalling`.
    pub const TIMER2_SET_PENDING_SHIFT: u32 = 3;
    pub const TIMER2_SET_PENDING_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn timer2_set_pending(&self) -> u8 {
        self.signalling.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_set_pending(&self, value: u8) {
        self.signalling.set_bits(3, 1, value as u64)
    }
    /// `Timer2Running`: bits 4..=4 de `signalling`.
    pub const TIMER2_RUNNING_SHIFT: u32 = 4;
    pub const TIMER2_RUNNING_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn timer2_running(&self) -> u8 {
        self.signalling.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_running(&self, value: u8) {
        self.signalling.set_bits(4, 1, value as u64)
    }
    /// `Timer2Disabled`: bits 5..=5 de `signalling`.
    pub const TIMER2_DISABLED_SHIFT: u32 = 5;
    pub const TIMER2_DISABLED_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn timer2_disabled(&self) -> u8 {
        self.signalling.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_timer2_disabled(&self, value: u8) {
        self.signalling.set_bits(5, 1, value as u64)
    }
    /// `Timer2ReservedFlags`: bits 6..=7 de `signalling`.
    pub const TIMER2_RESERVED_FLAGS_SHIFT: u32 = 6;
    pub const TIMER2_RESERVED_FLAGS_MASK: u8 = 0xc0;
    #[inline(always)]
    pub fn timer2_reserved_flags(&self) -> u8 {
        self.signalling.bits(6, 2) as u8
    }
    #[inline(always)]
    pub fn set_timer2_reserved_flags(&self, value: u8) {
        self.signalling.set_bits(6, 2, value as u64)
    }
    /// `Abandoned`: bits 0..=0 de `signalling`.
    pub const ABANDONED_SHIFT: u32 = 0;
    pub const ABANDONED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn abandoned(&self) -> u8 {
        self.signalling.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_abandoned(&self, value: u8) {
        self.signalling.set_bits(0, 1, value as u64)
    }
    /// `DisableIncrement`: bits 1..=1 de `signalling`.
    pub const DISABLE_INCREMENT_SHIFT: u32 = 1;
    pub const DISABLE_INCREMENT_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn disable_increment(&self) -> u8 {
        self.signalling.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_disable_increment(&self, value: u8) {
        self.signalling.set_bits(1, 1, value as u64)
    }
    /// `QueueReservedControlFlags`: bits 2..=7 de `signalling`.
    pub const QUEUE_RESERVED_CONTROL_FLAGS_SHIFT: u32 = 2;
    pub const QUEUE_RESERVED_CONTROL_FLAGS_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn queue_reserved_control_flags(&self) -> u8 {
        self.signalling.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_queue_reserved_control_flags(&self, value: u8) {
        self.signalling.set_bits(2, 6, value as u64)
    }
    /// `CycleProfiling`: bits 0..=0 de `size`.
    pub const CYCLE_PROFILING_SHIFT: u32 = 0;
    pub const CYCLE_PROFILING_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn cycle_profiling(&self) -> u8 {
        self.size.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_cycle_profiling(&self, value: u8) {
        self.size.set_bits(0, 1, value as u64)
    }
    /// `CounterProfiling`: bits 1..=1 de `size`.
    pub const COUNTER_PROFILING_SHIFT: u32 = 1;
    pub const COUNTER_PROFILING_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn counter_profiling(&self) -> u8 {
        self.size.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_counter_profiling(&self, value: u8) {
        self.size.set_bits(1, 1, value as u64)
    }
    /// `GroupScheduling`: bits 2..=2 de `size`.
    pub const GROUP_SCHEDULING_SHIFT: u32 = 2;
    pub const GROUP_SCHEDULING_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn group_scheduling(&self) -> u8 {
        self.size.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_group_scheduling(&self, value: u8) {
        self.size.set_bits(2, 1, value as u64)
    }
    /// `AffinitySet`: bits 3..=3 de `size`.
    pub const AFFINITY_SET_SHIFT: u32 = 3;
    pub const AFFINITY_SET_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn affinity_set(&self) -> u8 {
        self.size.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_affinity_set(&self, value: u8) {
        self.size.set_bits(3, 1, value as u64)
    }
    /// `Tagged`: bits 4..=4 de `size`.
    pub const TAGGED_SHIFT: u32 = 4;
    pub const TAGGED_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn tagged(&self) -> u8 {
        self.size.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_tagged(&self, value: u8) {
        self.size.set_bits(4, 1, value as u64)
    }
    /// `EnergyProfiling`: bits 5..=5 de `size`.
    pub const ENERGY_PROFILING_SHIFT: u32 = 5;
    pub const ENERGY_PROFILING_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn energy_profiling(&self) -> u8 {
        self.size.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_energy_profiling(&self, value: u8) {
        self.size.set_bits(5, 1, value as u64)
    }
    /// `SchedulerAssist`: bits 6..=6 de `size`.
    pub const SCHEDULER_ASSIST_SHIFT: u32 = 6;
    pub const SCHEDULER_ASSIST_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn scheduler_assist(&self) -> u8 {
        self.size.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_scheduler_assist(&self, value: u8) {
        self.size.set_bits(6, 1, value as u64)
    }
    /// `ThreadReservedControlFlags`: bits 7..=7 de `size`.
    pub const THREAD_RESERVED_CONTROL_FLAGS_SHIFT: u32 = 7;
    pub const THREAD_RESERVED_CONTROL_FLAGS_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn thread_reserved_control_flags(&self) -> u8 {
        self.size.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_thread_reserved_control_flags(&self, value: u8) {
        self.size.set_bits(7, 1, value as u64)
    }
    /// `Index`: bits 0..=5 de `reserved1`.
    pub const INDEX_SHIFT: u32 = 0;
    pub const INDEX_MASK: u8 = 0x3f;
    #[inline(always)]
    pub fn index(&self) -> u8 {
        self.reserved1.bits(0, 6) as u8
    }
    #[inline(always)]
    pub fn set_index(&self, value: u8) {
        self.reserved1.set_bits(0, 6, value as u64)
    }
    /// `Inserted`: bits 6..=6 de `reserved1`.
    pub const INSERTED_SHIFT: u32 = 6;
    pub const INSERTED_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn inserted(&self) -> u8 {
        self.reserved1.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_inserted(&self, value: u8) {
        self.reserved1.set_bits(6, 1, value as u64)
    }
    /// `Expired`: bits 7..=7 de `reserved1`.
    pub const EXPIRED_SHIFT: u32 = 7;
    pub const EXPIRED_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn expired(&self) -> u8 {
        self.reserved1.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_expired(&self, value: u8) {
        self.reserved1.set_bits(7, 1, value as u64)
    }
    /// `ActiveDR7`: bits 0..=0 de `reserved1`.
    pub const ACTIVE_DR7_SHIFT: u32 = 0;
    pub const ACTIVE_DR7_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn active_dr7(&self) -> u8 {
        self.reserved1.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_active_dr7(&self, value: u8) {
        self.reserved1.set_bits(0, 1, value as u64)
    }
    /// `Instrumented`: bits 1..=1 de `reserved1`.
    pub const INSTRUMENTED_SHIFT: u32 = 1;
    pub const INSTRUMENTED_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn instrumented(&self) -> u8 {
        self.reserved1.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_instrumented(&self, value: u8) {
        self.reserved1.set_bits(1, 1, value as u64)
    }
    /// `Minimal`: bits 2..=2 de `reserved1`.
    pub const MINIMAL_SHIFT: u32 = 2;
    pub const MINIMAL_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn minimal(&self) -> u8 {
        self.reserved1.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_minimal(&self, value: u8) {
        self.reserved1.set_bits(2, 1, value as u64)
    }
    /// `Reserved4`: bits 3..=4 de `reserved1`.
    pub const RESERVED4_SHIFT: u32 = 3;
    pub const RESERVED4_MASK: u8 = 0x18;
    #[inline(always)]
    pub fn reserved4(&self) -> u8 {
        self.reserved1.bits(3, 2) as u8
    }
    #[inline(always)]
    pub fn set_reserved4(&self, value: u8) {
        self.reserved1.set_bits(3, 2, value as u64)
    }
    /// `AltSyscall`: bits 5..=5 de `reserved1`.
    pub const ALT_SYSCALL_SHIFT: u32 = 5;
    pub const ALT_SYSCALL_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn alt_syscall(&self) -> u8 {
        self.reserved1.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_alt_syscall(&self, value: u8) {
        self.reserved1.set_bits(5, 1, value as u64)
    }
    /// `UmsScheduled`: bits 6..=6 de `reserved1`.
    pub const UMS_SCHEDULED_SHIFT: u32 = 6;
    pub const UMS_SCHEDULED_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn ums_scheduled(&self) -> u8 {
        self.reserved1.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_ums_scheduled(&self, value: u8) {
        self.reserved1.set_bits(6, 1, value as u64)
    }
    /// `UmsPrimary`: bits 7..=7 de `reserved1`.
    pub const UMS_PRIMARY_SHIFT: u32 = 7;
    pub const UMS_PRIMARY_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn ums_primary(&self) -> u8 {
        self.reserved1.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_ums_primary(&self, value: u8) {
        self.reserved1.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<DispatcherHeader>() == 0x18);
    assert!(core::mem::offset_of!(DispatcherHeader, lock) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeader, signal_state) == 0x4);
    assert!(core::mem::offset_of!(DispatcherHeader, wait_list_head) == 0x8);
    assert!(core::mem::size_of::<DispatcherHeaderView1>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView1>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView1, lock_nv) == 0x0);
    assert!(core::mem::size_of::<DispatcherHeaderView2>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView2>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView2, type_) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView2, signalling) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView2, size) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView2, reserved1) == 0x3);
    assert!(core::mem::size_of::<DispatcherHeaderView3>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView3>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView3, timer_type) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView3, timer_control_flags) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView3, hand) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView3, timer_misc_flags) == 0x3);
    assert!(core::mem::size_of::<DispatcherHeaderView4>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView4>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView4, timer2_type) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView4, timer2_flags) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView4, timer2_component_id) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView4, timer2_relative_id) == 0x3);
    assert!(core::mem::size_of::<DispatcherHeaderView5>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView5>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView5, queue_type) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView5, queue_control_flags) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView5, queue_size) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView5, queue_reserved) == 0x3);
    assert!(core::mem::size_of::<DispatcherHeaderView6>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView6>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView6, thread_type) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView6, thread_reserved) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView6, thread_control_flags) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView6, debug_active) == 0x3);
    assert!(core::mem::size_of::<DispatcherHeaderView7>() == 0x18);
    assert!(core::mem::align_of::<DispatcherHeaderView7>() == core::mem::align_of::<DispatcherHeader>());
    assert!(core::mem::offset_of!(DispatcherHeaderView7, mutant_type) == 0x0);
    assert!(core::mem::offset_of!(DispatcherHeaderView7, mutant_size) == 0x1);
    assert!(core::mem::offset_of!(DispatcherHeaderView7, dpc_active) == 0x2);
    assert!(core::mem::offset_of!(DispatcherHeaderView7, mutant_reserved) == 0x3);
};

/// `_KAPC` (0x58 bytes).
#[repr(C)]
pub struct Kapc {
    pub type_: Field<u8>,
    pub all_flags: Field<u8>,
    pub size: Field<u8>,
    pub spare_byte1: Field<u8>,
    pub spare_long0: Field<u32>,
    /// -> `_KTHREAD`
    pub thread: Field<u64>,
    pub apc_list_entry: ListEntry,
    /// -> `void`
    pub reserved: [Field<u64>; 3],
    /// -> `void`
    pub normal_context: Field<u64>,
    /// -> `void`
    pub system_argument1: Field<u64>,
    /// -> `void`
    pub system_argument2: Field<u64>,
    pub apc_state_index: Field<i8>,
    pub apc_mode: Field<i8>,
    pub inserted: Field<u8>,
    _pad_53: Reserved<0x5>,
}

unsafe impl NtStruct for Kapc {}

const _: () = {
    assert!(core::mem::size_of::<Kapc>() == 0x58);
    assert!(core::mem::offset_of!(Kapc, type_) == 0x0);
    assert!(core::mem::offset_of!(Kapc, all_flags) == 0x1);
    assert!(core::mem::offset_of!(Kapc, size) == 0x2);
    assert!(core::mem::offset_of!(Kapc, spare_byte1) == 0x3);
    assert!(core::mem::offset_of!(Kapc, spare_long0) == 0x4);
    assert!(core::mem::offset_of!(Kapc, thread) == 0x8);
    assert!(core::mem::offset_of!(Kapc, apc_list_entry) == 0x10);
    assert!(core::mem::offset_of!(Kapc, reserved) == 0x20);
    assert!(core::mem::offset_of!(Kapc, normal_context) == 0x38);
    assert!(core::mem::offset_of!(Kapc, system_argument1) == 0x40);
    assert!(core::mem::offset_of!(Kapc, system_argument2) == 0x48);
    assert!(core::mem::offset_of!(Kapc, apc_state_index) == 0x50);
    assert!(core::mem::offset_of!(Kapc, apc_mode) == 0x51);
    assert!(core::mem::offset_of!(Kapc, inserted) == 0x52);
};

/// `_KMUTANT` (0x38 bytes).
#[repr(C)]
pub struct Kmutant {
    pub header: DispatcherHeader,
    pub mutant_list_entry: ListEntry,
    /// -> `_KTHREAD`
    pub owner_thread: Field<u64>,
    pub mutant_flags: Field<u8>,
    pub apc_disable: Field<u8>,
    _pad_32: Reserved<0x6>,
}

unsafe impl NtStruct for Kmutant {}

impl Kmutant {
    /// `Abandoned`: bits 0..=0 de `mutant_flags`.
    pub const ABANDONED_SHIFT: u32 = 0;
    pub const ABANDONED_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn abandoned(&self) -> u8 {
        self.mutant_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_abandoned(&self, value: u8) {
        self.mutant_flags.set_bits(0, 1, value as u64)
    }
    /// `Spare1`: bits 1..=7 de `mutant_flags`.
    pub const SPARE1_SHIFT: u32 = 1;
    pub const SPARE1_MASK: u8 = 0xfe;
    #[inline(always)]
    pub fn spare1(&self) -> u8 {
        self.mutant_flags.bits(1, 7) as u8
    }
    #[inline(always)]
    pub fn set_spare1(&self, value: u8) {
        self.mutant_flags.set_bits(1, 7, value as u64)
    }
    /// `Abandoned2`: bits 0..=0 de `mutant_flags`.
    pub const ABANDONED2_SHIFT: u32 = 0;
    pub const ABANDONED2_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn abandoned2(&self) -> u8 {
        self.mutant_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_abandoned2(&self, value: u8) {
        self.mutant_flags.set_bits(0, 1, value as u64)
    }
    /// `AbEnabled`: bits 1..=1 de `mutant_flags`.
    pub const AB_ENABLED_SHIFT: u32 = 1;
    pub const AB_ENABLED_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn ab_enabled(&self) -> u8 {
        self.mutant_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_ab_enabled(&self, value: u8) {
        self.mutant_flags.set_bits(1, 1, value as u64)
    }
    /// `Spare2`: bits 2..=7 de `mutant_flags`.
    pub const SPARE2_SHIFT: u32 = 2;
    pub const SPARE2_MASK: u8 = 0xfc;
    #[inline(always)]
    pub fn spare2(&self) -> u8 {
        self.mutant_flags.bits(2, 6) as u8
    }
    #[inline(always)]
    pub fn set_spare2(&self, value: u8) {
        self.mutant_flags.set_bits(2, 6, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Kmutant>() == 0x38);
    assert!(core::mem::offset_of!(Kmutant, header) == 0x0);
    assert!(core::mem::offset_of!(Kmutant, mutant_list_entry) == 0x18);
    assert!(core::mem::offset_of!(Kmutant, owner_thread) == 0x28);
    assert!(core::mem::offset_of!(Kmutant, mutant_flags) == 0x30);
    assert!(core::mem::offset_of!(Kmutant, apc_disable) == 0x31);
};

/// `_KTIMER` (0x40 bytes).
#[repr(C)]
pub struct Ktimer {
    pub header: DispatcherHeader,
    pub due_time: UlargeInteger,
    pub timer_list_entry: ListEntry,
    /// -> `_KDPC`
    pub dpc: Field<u64>,
    pub processor: Field<u16>,
    pub timer_type: Field<u16>,
    pub period: Field<u32>,
}

unsafe impl NtStruct for Ktimer {}

const _: () = {
    assert!(core::mem::size_of::<Ktimer>() == 0x40);
    assert!(core::mem::offset_of!(Ktimer, header) == 0x0);
    assert!(core::mem::offset_of!(Ktimer, due_time) == 0x18);
    assert!(core::mem::offset_of!(Ktimer, timer_list_entry) == 0x20);
    assert!(core::mem::offset_of!(Ktimer, dpc) == 0x30);
    assert!(core::mem::offset_of!(Ktimer, processor) == 0x38);
    assert!(core::mem::offset_of!(Ktimer, timer_type) == 0x3a);
    assert!(core::mem::offset_of!(Ktimer, period) == 0x3c);
};

/// `_KTHREAD` (0x430 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KthreadView1`..`KthreadView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Kthread {
    pub header: DispatcherHeader,
    /// -> `void`
    pub s_list_fault_address: Field<u64>,
    pub quantum_target: Field<u64>,
    /// -> `void`
    pub initial_stack: Field<u64>,
    /// -> `void`
    pub stack_limit: Field<u64>,
    /// -> `void`
    pub stack_base: Field<u64>,
    pub thread_lock: Field<u64>,
    pub cycle_time: Field<u64>,
    pub current_run_time: Field<u32>,
    pub expected_run_time: Field<u32>,
    /// -> `void`
    pub kernel_stack: Field<u64>,
    /// -> `_XSAVE_FORMAT`
    pub state_save_area: Field<u64>,
    /// -> `_KSCHEDULING_GROUP`
    pub scheduling_group: Field<u64>,
    pub wait_register: KwaitStatusRegister,
    pub running: Field<u8>,
    pub alerted: [Field<u8>; 2],
    pub misc_flags: Field<i32>,
    pub thread_flags: Field<i32>,
    pub tag: Field<u8>,
    pub system_hetero_cpu_policy: Field<u8>,
    pub bitfield_7e: Field<u8>,
    pub spec_ctrl: Field<u8>,
    pub system_call_number: Field<u32>,
    pub ready_time: Field<u32>,
    /// -> `void`
    pub first_argument: Field<u64>,
    /// -> `_KTRAP_FRAME`
    pub trap_frame: Field<u64>,
    pub apc_state: KapcState,
    pub wait_status: Field<i64>,
    /// -> `_KWAIT_BLOCK`
    pub wait_block_list: Field<u64>,
    pub wait_list_entry: ListEntry,
    /// -> `_DISPATCHER_HEADER`
    pub queue: Field<u64>,
    /// -> `void`
    pub teb: Field<u64>,
    pub relative_timer_bias: Field<u64>,
    pub timer: Ktimer,
    pub wait_block: [KwaitBlock; 4],
    pub thread_flags2: Field<i32>,
    pub spare21: Field<u32>,
    pub queue_list_entry: ListEntry,
    pub next_processor: Field<u32>,
    pub queue_priority: Field<i32>,
    /// -> `_KPROCESS`
    pub process: Field<u64>,
    pub user_affinity: GroupAffinity,
    pub affinity_version: Field<u64>,
    pub affinity: GroupAffinity,
    pub npx_state: Field<u64>,
    pub saved_apc_state: KapcState,
    pub scheduler_apc: Kapc,
    pub suspend_event: Kevent,
    pub thread_list_entry: ListEntry,
    pub mutant_list_head: ListEntry,
    pub ab_entry_summary: Field<u8>,
    pub ab_wait_entry_count: Field<u8>,
    pub ab_allocation_region_count: Field<u8>,
    pub system_priority: Field<i8>,
    pub secure_thread_cookie: Field<u32>,
    /// -> `_KLOCK_ENTRY`
    pub lock_entries: Field<u64>,
    pub propagate_boosts_entry: SingleListEntry,
    pub io_self_boosts_entry: SingleListEntry,
    pub priority_floor_counts: [Field<u8>; 16],
    pub priority_floor_counts_reserved: [Field<u8>; 16],
    pub priority_floor_summary: Field<u32>,
    pub ab_completed_io_boost_count: Field<i32>,
    pub ab_completed_io_qo_s_boost_count: Field<i32>,
    pub ke_reference_count: Field<i16>,
    pub ab_orphaned_entry_summary: Field<u8>,
    pub ab_owned_entry_count: Field<u8>,
    pub foreground_loss_time: Field<u32>,
    _pad_36c: Reserved<0x4>,
    pub global_foreground_list_entry: ListEntry,
    pub read_operation_count: Field<i64>,
    pub write_operation_count: Field<i64>,
    pub other_operation_count: Field<i64>,
    pub read_transfer_count: Field<i64>,
    pub write_transfer_count: Field<i64>,
    pub other_transfer_count: Field<i64>,
    /// -> `_KSCB`
    pub queued_scb: Field<u64>,
    pub thread_timer_delay: Field<u32>,
    pub thread_flags3: Field<i32>,
    pub tracing_private: [Field<u64>; 1],
    /// -> `void`
    pub scheduler_assist: Field<u64>,
    /// -> `void`
    pub ab_wait_object: Field<u64>,
    pub reserved_previous_ready_time_value: Field<u32>,
    _pad_3dc: Reserved<0x4>,
    pub kernel_wait_time: Field<u64>,
    pub user_wait_time: Field<u64>,
    pub global_update_vp_thread_priority_list_entry: ListEntry,
    pub scheduler_assist_priority_floor: Field<i32>,
    pub spare28: Field<u32>,
    pub resource_index: Field<u8>,
    pub spare31: [Field<u8>; 3],
    _pad_40c: Reserved<0x4>,
    pub end_padding: [Field<u64>; 4],
}

/// Vista 1 de `_KTHREAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KthreadView1 {
    _pad_0: Reserved<0xc3>,
    pub priority: Field<i8>,
    pub user_ideal_processor: Field<u32>,
    _pad_c8: Reserved<0x10>,
    pub swap_list_entry: SingleListEntry,
    _pad_e0: Reserved<0x74>,
    pub context_switches: Field<u32>,
    _pad_158: Reserved<0x10>,
    /// -> `_KTHREAD_COUNTERS`
    pub thread_counters: Field<u64>,
    _pad_170: Reserved<0x14>,
    pub state: Field<u8>,
    pub spare13: Field<i8>,
    pub wait_irql: Field<u8>,
    pub wait_mode: Field<i8>,
    _pad_188: Reserved<0x10>,
    /// -> `_XSTATE_SAVE`
    pub x_state_save: Field<u64>,
    _pad_1a0: Reserved<0x14>,
    pub wait_time: Field<u32>,
    _pad_1b8: Reserved<0x10>,
    /// -> `void`
    pub win32_thread: Field<u64>,
    _pad_1d0: Reserved<0x14>,
    pub kernel_apc_disable: Field<i16>,
    pub special_apc_disable: Field<i16>,
    _pad_1e8: Reserved<0x8>,
    /// -> `_UMS_CONTROL_BLOCK`
    pub ucb: Field<u64>,
    /// -> `_KUMS_CONTEXT_HEADER`
    pub uch: Field<u64>,
    _pad_200: Reserved<0x32>,
    pub previous_mode: Field<i8>,
    pub base_priority: Field<i8>,
    pub priority_decrement: Field<i8>,
    pub preempted: Field<u8>,
    pub adjust_reason: Field<u8>,
    pub adjust_increment: Field<i8>,
    _pad_238: Reserved<0x12>,
    pub apc_state_index: Field<u8>,
    pub wait_block_count: Field<u8>,
    pub ideal_processor: Field<u32>,
    _pad_250: Reserved<0x33>,
    pub wait_reason: Field<u8>,
    pub suspend_count: Field<i8>,
    pub saturation: Field<i8>,
    pub s_list_fault_count: Field<u16>,
    _pad_288: Reserved<0x3>,
    pub quantum_reset: Field<u8>,
    pub kernel_time: Field<u32>,
    _pad_290: Reserved<0x38>,
    /// -> `_KPRCB`
    pub wait_prcb: Field<u64>,
    /// -> `void`
    pub lego_data: Field<u64>,
    _pad_2d8: Reserved<0x3>,
    pub callback_nesting_level: Field<u8>,
    pub user_time: Field<u32>,
    _pad_2e0: Reserved<0x90>,
    pub foreground_dpc_stack_list_entry: SingleListEntry,
    pub in_global_foreground_list: Field<u64>,
    _pad_380: Reserved<0x70>,
    pub update_vp_thread_priority_dpc_stack_list_entry: SingleListEntry,
    pub in_global_update_vp_thread_priority_list: Field<u64>,
    _pad_400: Reserved<0x30>,
}

/// Vista 2 de `_KTHREAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KthreadView2 {
    _align: [u64; 0],
    _pad_0: Reserved<0x1e4>,
    pub combined_apc_disable: Field<u32>,
    _pad_1e8: Reserved<0x248>,
}

impl core::ops::Deref for Kthread {
    type Target = KthreadView1;
    #[inline(always)]
    fn deref(&self) -> &KthreadView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KthreadView1>() }
    }
}

impl core::ops::Deref for KthreadView1 {
    type Target = KthreadView2;
    #[inline(always)]
    fn deref(&self) -> &KthreadView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KthreadView2>() }
    }
}

unsafe impl NtStruct for Kthread {}

impl Kthread {
    /// `AutoBoostActive`: bits 0..=0 de `misc_flags`.
    pub const AUTO_BOOST_ACTIVE_SHIFT: u32 = 0;
    pub const AUTO_BOOST_ACTIVE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn auto_boost_active(&self) -> u32 {
        self.misc_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_auto_boost_active(&self, value: u32) {
        self.misc_flags.set_bits(0, 1, value as u64)
    }
    /// `ReadyTransition`: bits 1..=1 de `misc_flags`.
    pub const READY_TRANSITION_SHIFT: u32 = 1;
    pub const READY_TRANSITION_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn ready_transition(&self) -> u32 {
        self.misc_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_ready_transition(&self, value: u32) {
        self.misc_flags.set_bits(1, 1, value as u64)
    }
    /// `WaitNext`: bits 2..=2 de `misc_flags`.
    pub const WAIT_NEXT_SHIFT: u32 = 2;
    pub const WAIT_NEXT_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn wait_next(&self) -> u32 {
        self.misc_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_wait_next(&self, value: u32) {
        self.misc_flags.set_bits(2, 1, value as u64)
    }
    /// `SystemAffinityActive`: bits 3..=3 de `misc_flags`.
    pub const SYSTEM_AFFINITY_ACTIVE_SHIFT: u32 = 3;
    pub const SYSTEM_AFFINITY_ACTIVE_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn system_affinity_active(&self) -> u32 {
        self.misc_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_affinity_active(&self, value: u32) {
        self.misc_flags.set_bits(3, 1, value as u64)
    }
    /// `Alertable`: bits 4..=4 de `misc_flags`.
    pub const ALERTABLE_SHIFT: u32 = 4;
    pub const ALERTABLE_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn alertable(&self) -> u32 {
        self.misc_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_alertable(&self, value: u32) {
        self.misc_flags.set_bits(4, 1, value as u64)
    }
    /// `UserStackWalkActive`: bits 5..=5 de `misc_flags`.
    pub const USER_STACK_WALK_ACTIVE_SHIFT: u32 = 5;
    pub const USER_STACK_WALK_ACTIVE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn user_stack_walk_active(&self) -> u32 {
        self.misc_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_user_stack_walk_active(&self, value: u32) {
        self.misc_flags.set_bits(5, 1, value as u64)
    }
    /// `ApcInterruptRequest`: bits 6..=6 de `misc_flags`.
    pub const APC_INTERRUPT_REQUEST_SHIFT: u32 = 6;
    pub const APC_INTERRUPT_REQUEST_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn apc_interrupt_request(&self) -> u32 {
        self.misc_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_apc_interrupt_request(&self, value: u32) {
        self.misc_flags.set_bits(6, 1, value as u64)
    }
    /// `QuantumEndMigrate`: bits 7..=7 de `misc_flags`.
    pub const QUANTUM_END_MIGRATE_SHIFT: u32 = 7;
    pub const QUANTUM_END_MIGRATE_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn quantum_end_migrate(&self) -> u32 {
        self.misc_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_quantum_end_migrate(&self, value: u32) {
        self.misc_flags.set_bits(7, 1, value as u64)
    }
    /// `UmsDirectedSwitchEnable`: bits 8..=8 de `misc_flags`.
    pub const UMS_DIRECTED_SWITCH_ENABLE_SHIFT: u32 = 8;
    pub const UMS_DIRECTED_SWITCH_ENABLE_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn ums_directed_switch_enable(&self) -> u32 {
        self.misc_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_ums_directed_switch_enable(&self, value: u32) {
        self.misc_flags.set_bits(8, 1, value as u64)
    }
    /// `TimerActive`: bits 9..=9 de `misc_flags`.
    pub const TIMER_ACTIVE_SHIFT: u32 = 9;
    pub const TIMER_ACTIVE_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn timer_active(&self) -> u32 {
        self.misc_flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_timer_active(&self, value: u32) {
        self.misc_flags.set_bits(9, 1, value as u64)
    }
    /// `SystemThread`: bits 10..=10 de `misc_flags`.
    pub const SYSTEM_THREAD_SHIFT: u32 = 10;
    pub const SYSTEM_THREAD_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn system_thread(&self) -> u32 {
        self.misc_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_thread(&self, value: u32) {
        self.misc_flags.set_bits(10, 1, value as u64)
    }
    /// `ProcessDetachActive`: bits 11..=11 de `misc_flags`.
    pub const PROCESS_DETACH_ACTIVE_SHIFT: u32 = 11;
    pub const PROCESS_DETACH_ACTIVE_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn process_detach_active(&self) -> u32 {
        self.misc_flags.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_detach_active(&self, value: u32) {
        self.misc_flags.set_bits(11, 1, value as u64)
    }
    /// `CalloutActive`: bits 12..=12 de `misc_flags`.
    pub const CALLOUT_ACTIVE_SHIFT: u32 = 12;
    pub const CALLOUT_ACTIVE_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn callout_active(&self) -> u32 {
        self.misc_flags.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_callout_active(&self, value: u32) {
        self.misc_flags.set_bits(12, 1, value as u64)
    }
    /// `ScbReadyQueue`: bits 13..=13 de `misc_flags`.
    pub const SCB_READY_QUEUE_SHIFT: u32 = 13;
    pub const SCB_READY_QUEUE_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn scb_ready_queue(&self) -> u32 {
        self.misc_flags.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_scb_ready_queue(&self, value: u32) {
        self.misc_flags.set_bits(13, 1, value as u64)
    }
    /// `ApcQueueable`: bits 14..=14 de `misc_flags`.
    pub const APC_QUEUEABLE_SHIFT: u32 = 14;
    pub const APC_QUEUEABLE_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn apc_queueable(&self) -> u32 {
        self.misc_flags.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_apc_queueable(&self, value: u32) {
        self.misc_flags.set_bits(14, 1, value as u64)
    }
    /// `ReservedStackInUse`: bits 15..=15 de `misc_flags`.
    pub const RESERVED_STACK_IN_USE_SHIFT: u32 = 15;
    pub const RESERVED_STACK_IN_USE_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn reserved_stack_in_use(&self) -> u32 {
        self.misc_flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved_stack_in_use(&self, value: u32) {
        self.misc_flags.set_bits(15, 1, value as u64)
    }
    /// `UmsPerformingSyscall`: bits 16..=16 de `misc_flags`.
    pub const UMS_PERFORMING_SYSCALL_SHIFT: u32 = 16;
    pub const UMS_PERFORMING_SYSCALL_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn ums_performing_syscall(&self) -> u32 {
        self.misc_flags.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_ums_performing_syscall(&self, value: u32) {
        self.misc_flags.set_bits(16, 1, value as u64)
    }
    /// `TimerSuspended`: bits 17..=17 de `misc_flags`.
    pub const TIMER_SUSPENDED_SHIFT: u32 = 17;
    pub const TIMER_SUSPENDED_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn timer_suspended(&self) -> u32 {
        self.misc_flags.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_timer_suspended(&self, value: u32) {
        self.misc_flags.set_bits(17, 1, value as u64)
    }
    /// `SuspendedWaitMode`: bits 18..=18 de `misc_flags`.
    pub const SUSPENDED_WAIT_MODE_SHIFT: u32 = 18;
    pub const SUSPENDED_WAIT_MODE_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn suspended_wait_mode(&self) -> u32 {
        self.misc_flags.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_suspended_wait_mode(&self, value: u32) {
        self.misc_flags.set_bits(18, 1, value as u64)
    }
    /// `SuspendSchedulerApcWait`: bits 19..=19 de `misc_flags`.
    pub const SUSPEND_SCHEDULER_APC_WAIT_SHIFT: u32 = 19;
    pub const SUSPEND_SCHEDULER_APC_WAIT_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn suspend_scheduler_apc_wait(&self) -> u32 {
        self.misc_flags.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_suspend_scheduler_apc_wait(&self, value: u32) {
        self.misc_flags.set_bits(19, 1, value as u64)
    }
    /// `CetUserShadowStack`: bits 20..=20 de `misc_flags`.
    pub const CET_USER_SHADOW_STACK_SHIFT: u32 = 20;
    pub const CET_USER_SHADOW_STACK_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn cet_user_shadow_stack(&self) -> u32 {
        self.misc_flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_cet_user_shadow_stack(&self, value: u32) {
        self.misc_flags.set_bits(20, 1, value as u64)
    }
    /// `BypassProcessFreeze`: bits 21..=21 de `misc_flags`.
    pub const BYPASS_PROCESS_FREEZE_SHIFT: u32 = 21;
    pub const BYPASS_PROCESS_FREEZE_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn bypass_process_freeze(&self) -> u32 {
        self.misc_flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_bypass_process_freeze(&self, value: u32) {
        self.misc_flags.set_bits(21, 1, value as u64)
    }
    /// `Reserved`: bits 22..=31 de `misc_flags`.
    pub const RESERVED_SHIFT: u32 = 22;
    pub const RESERVED_MASK: u32 = 0xffc00000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.misc_flags.bits(22, 10) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.misc_flags.set_bits(22, 10, value as u64)
    }
    /// `ThreadFlagsSpare`: bits 0..=1 de `thread_flags`.
    pub const THREAD_FLAGS_SPARE_SHIFT: u32 = 0;
    pub const THREAD_FLAGS_SPARE_MASK: u32 = 0x3;
    #[inline(always)]
    pub fn thread_flags_spare(&self) -> u32 {
        self.thread_flags.bits(0, 2) as u32
    }
    #[inline(always)]
    pub fn set_thread_flags_spare(&self, value: u32) {
        self.thread_flags.set_bits(0, 2, value as u64)
    }
    /// `AutoAlignment`: bits 2..=2 de `thread_flags`.
    pub const AUTO_ALIGNMENT_SHIFT: u32 = 2;
    pub const AUTO_ALIGNMENT_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn auto_alignment(&self) -> u32 {
        self.thread_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_auto_alignment(&self, value: u32) {
        self.thread_flags.set_bits(2, 1, value as u64)
    }
    /// `DisableBoost`: bits 3..=3 de `thread_flags`.
    pub const DISABLE_BOOST_SHIFT: u32 = 3;
    pub const DISABLE_BOOST_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn disable_boost(&self) -> u32 {
        self.thread_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_boost(&self, value: u32) {
        self.thread_flags.set_bits(3, 1, value as u64)
    }
    /// `AlertedByThreadId`: bits 4..=4 de `thread_flags`.
    pub const ALERTED_BY_THREAD_ID_SHIFT: u32 = 4;
    pub const ALERTED_BY_THREAD_ID_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn alerted_by_thread_id(&self) -> u32 {
        self.thread_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_alerted_by_thread_id(&self, value: u32) {
        self.thread_flags.set_bits(4, 1, value as u64)
    }
    /// `QuantumDonation`: bits 5..=5 de `thread_flags`.
    pub const QUANTUM_DONATION_SHIFT: u32 = 5;
    pub const QUANTUM_DONATION_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn quantum_donation(&self) -> u32 {
        self.thread_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_quantum_donation(&self, value: u32) {
        self.thread_flags.set_bits(5, 1, value as u64)
    }
    /// `EnableStackSwap`: bits 6..=6 de `thread_flags`.
    pub const ENABLE_STACK_SWAP_SHIFT: u32 = 6;
    pub const ENABLE_STACK_SWAP_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn enable_stack_swap(&self) -> u32 {
        self.thread_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_stack_swap(&self, value: u32) {
        self.thread_flags.set_bits(6, 1, value as u64)
    }
    /// `GuiThread`: bits 7..=7 de `thread_flags`.
    pub const GUI_THREAD_SHIFT: u32 = 7;
    pub const GUI_THREAD_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn gui_thread(&self) -> u32 {
        self.thread_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_gui_thread(&self, value: u32) {
        self.thread_flags.set_bits(7, 1, value as u64)
    }
    /// `DisableQuantum`: bits 8..=8 de `thread_flags`.
    pub const DISABLE_QUANTUM_SHIFT: u32 = 8;
    pub const DISABLE_QUANTUM_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn disable_quantum(&self) -> u32 {
        self.thread_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_quantum(&self, value: u32) {
        self.thread_flags.set_bits(8, 1, value as u64)
    }
    /// `ChargeOnlySchedulingGroup`: bits 9..=9 de `thread_flags`.
    pub const CHARGE_ONLY_SCHEDULING_GROUP_SHIFT: u32 = 9;
    pub const CHARGE_ONLY_SCHEDULING_GROUP_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn charge_only_scheduling_group(&self) -> u32 {
        self.thread_flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_charge_only_scheduling_group(&self, value: u32) {
        self.thread_flags.set_bits(9, 1, value as u64)
    }
    /// `DeferPreemption`: bits 10..=10 de `thread_flags`.
    pub const DEFER_PREEMPTION_SHIFT: u32 = 10;
    pub const DEFER_PREEMPTION_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn defer_preemption(&self) -> u32 {
        self.thread_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_defer_preemption(&self, value: u32) {
        self.thread_flags.set_bits(10, 1, value as u64)
    }
    /// `QueueDeferPreemption`: bits 11..=11 de `thread_flags`.
    pub const QUEUE_DEFER_PREEMPTION_SHIFT: u32 = 11;
    pub const QUEUE_DEFER_PREEMPTION_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn queue_defer_preemption(&self) -> u32 {
        self.thread_flags.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_queue_defer_preemption(&self, value: u32) {
        self.thread_flags.set_bits(11, 1, value as u64)
    }
    /// `ForceDeferSchedule`: bits 12..=12 de `thread_flags`.
    pub const FORCE_DEFER_SCHEDULE_SHIFT: u32 = 12;
    pub const FORCE_DEFER_SCHEDULE_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn force_defer_schedule(&self) -> u32 {
        self.thread_flags.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_force_defer_schedule(&self, value: u32) {
        self.thread_flags.set_bits(12, 1, value as u64)
    }
    /// `SharedReadyQueueAffinity`: bits 13..=13 de `thread_flags`.
    pub const SHARED_READY_QUEUE_AFFINITY_SHIFT: u32 = 13;
    pub const SHARED_READY_QUEUE_AFFINITY_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn shared_ready_queue_affinity(&self) -> u32 {
        self.thread_flags.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_shared_ready_queue_affinity(&self, value: u32) {
        self.thread_flags.set_bits(13, 1, value as u64)
    }
    /// `FreezeCount`: bits 14..=14 de `thread_flags`.
    pub const FREEZE_COUNT_SHIFT: u32 = 14;
    pub const FREEZE_COUNT_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn freeze_count(&self) -> u32 {
        self.thread_flags.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_freeze_count(&self, value: u32) {
        self.thread_flags.set_bits(14, 1, value as u64)
    }
    /// `TerminationApcRequest`: bits 15..=15 de `thread_flags`.
    pub const TERMINATION_APC_REQUEST_SHIFT: u32 = 15;
    pub const TERMINATION_APC_REQUEST_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn termination_apc_request(&self) -> u32 {
        self.thread_flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_termination_apc_request(&self, value: u32) {
        self.thread_flags.set_bits(15, 1, value as u64)
    }
    /// `AutoBoostEntriesExhausted`: bits 16..=16 de `thread_flags`.
    pub const AUTO_BOOST_ENTRIES_EXHAUSTED_SHIFT: u32 = 16;
    pub const AUTO_BOOST_ENTRIES_EXHAUSTED_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn auto_boost_entries_exhausted(&self) -> u32 {
        self.thread_flags.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_auto_boost_entries_exhausted(&self, value: u32) {
        self.thread_flags.set_bits(16, 1, value as u64)
    }
    /// `KernelStackResident`: bits 17..=17 de `thread_flags`.
    pub const KERNEL_STACK_RESIDENT_SHIFT: u32 = 17;
    pub const KERNEL_STACK_RESIDENT_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn kernel_stack_resident(&self) -> u32 {
        self.thread_flags.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_kernel_stack_resident(&self, value: u32) {
        self.thread_flags.set_bits(17, 1, value as u64)
    }
    /// `TerminateRequestReason`: bits 18..=19 de `thread_flags`.
    pub const TERMINATE_REQUEST_REASON_SHIFT: u32 = 18;
    pub const TERMINATE_REQUEST_REASON_MASK: u32 = 0xc0000;
    #[inline(always)]
    pub fn terminate_request_reason(&self) -> u32 {
        self.thread_flags.bits(18, 2) as u32
    }
    #[inline(always)]
    pub fn set_terminate_request_reason(&self, value: u32) {
        self.thread_flags.set_bits(18, 2, value as u64)
    }
    /// `ProcessStackCountDecremented`: bits 20..=20 de `thread_flags`.
    pub const PROCESS_STACK_COUNT_DECREMENTED_SHIFT: u32 = 20;
    pub const PROCESS_STACK_COUNT_DECREMENTED_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn process_stack_count_decremented(&self) -> u32 {
        self.thread_flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_stack_count_decremented(&self, value: u32) {
        self.thread_flags.set_bits(20, 1, value as u64)
    }
    /// `RestrictedGuiThread`: bits 21..=21 de `thread_flags`.
    pub const RESTRICTED_GUI_THREAD_SHIFT: u32 = 21;
    pub const RESTRICTED_GUI_THREAD_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn restricted_gui_thread(&self) -> u32 {
        self.thread_flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_restricted_gui_thread(&self, value: u32) {
        self.thread_flags.set_bits(21, 1, value as u64)
    }
    /// `VpBackingThread`: bits 22..=22 de `thread_flags`.
    pub const VP_BACKING_THREAD_SHIFT: u32 = 22;
    pub const VP_BACKING_THREAD_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn vp_backing_thread(&self) -> u32 {
        self.thread_flags.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_vp_backing_thread(&self, value: u32) {
        self.thread_flags.set_bits(22, 1, value as u64)
    }
    /// `ThreadFlagsSpare2`: bits 23..=23 de `thread_flags`.
    pub const THREAD_FLAGS_SPARE2_SHIFT: u32 = 23;
    pub const THREAD_FLAGS_SPARE2_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn thread_flags_spare2(&self) -> u32 {
        self.thread_flags.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_thread_flags_spare2(&self, value: u32) {
        self.thread_flags.set_bits(23, 1, value as u64)
    }
    /// `EtwStackTraceApcInserted`: bits 24..=31 de `thread_flags`.
    pub const ETW_STACK_TRACE_APC_INSERTED_SHIFT: u32 = 24;
    pub const ETW_STACK_TRACE_APC_INSERTED_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn etw_stack_trace_apc_inserted(&self) -> u32 {
        self.thread_flags.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_etw_stack_trace_apc_inserted(&self, value: u32) {
        self.thread_flags.set_bits(24, 8, value as u64)
    }
    /// `UserHeteroCpuPolicy`: bits 0..=6 de `bitfield_7e`.
    pub const USER_HETERO_CPU_POLICY_SHIFT: u32 = 0;
    pub const USER_HETERO_CPU_POLICY_MASK: u8 = 0x7f;
    #[inline(always)]
    pub fn user_hetero_cpu_policy(&self) -> u8 {
        self.bitfield_7e.bits(0, 7) as u8
    }
    #[inline(always)]
    pub fn set_user_hetero_cpu_policy(&self, value: u8) {
        self.bitfield_7e.set_bits(0, 7, value as u64)
    }
    /// `ExplicitSystemHeteroCpuPolicy`: bits 7..=7 de `bitfield_7e`.
    pub const EXPLICIT_SYSTEM_HETERO_CPU_POLICY_SHIFT: u32 = 7;
    pub const EXPLICIT_SYSTEM_HETERO_CPU_POLICY_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn explicit_system_hetero_cpu_policy(&self) -> u8 {
        self.bitfield_7e.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_explicit_system_hetero_cpu_policy(&self, value: u8) {
        self.bitfield_7e.set_bits(7, 1, value as u64)
    }
    /// `RunningNonRetpolineCode`: bits 0..=0 de `spec_ctrl`.
    pub const RUNNING_NON_RETPOLINE_CODE_SHIFT: u32 = 0;
    pub const RUNNING_NON_RETPOLINE_CODE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn running_non_retpoline_code(&self) -> u8 {
        self.spec_ctrl.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_running_non_retpoline_code(&self, value: u8) {
        self.spec_ctrl.set_bits(0, 1, value as u64)
    }
    /// `SpecCtrlSpare`: bits 1..=7 de `spec_ctrl`.
    pub const SPEC_CTRL_SPARE_SHIFT: u32 = 1;
    pub const SPEC_CTRL_SPARE_MASK: u8 = 0xfe;
    #[inline(always)]
    pub fn spec_ctrl_spare(&self) -> u8 {
        self.spec_ctrl.bits(1, 7) as u8
    }
    #[inline(always)]
    pub fn set_spec_ctrl_spare(&self, value: u8) {
        self.spec_ctrl.set_bits(1, 7, value as u64)
    }
    /// `BamQosLevel`: bits 0..=7 de `thread_flags2`.
    pub const BAM_QOS_LEVEL_SHIFT: u32 = 0;
    pub const BAM_QOS_LEVEL_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn bam_qos_level(&self) -> u32 {
        self.thread_flags2.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_bam_qos_level(&self, value: u32) {
        self.thread_flags2.set_bits(0, 8, value as u64)
    }
    /// `ThreadFlags2Reserved`: bits 8..=31 de `thread_flags2`.
    pub const THREAD_FLAGS2_RESERVED_SHIFT: u32 = 8;
    pub const THREAD_FLAGS2_RESERVED_MASK: u32 = 0xffffff00;
    #[inline(always)]
    pub fn thread_flags2_reserved(&self) -> u32 {
        self.thread_flags2.bits(8, 24) as u32
    }
    #[inline(always)]
    pub fn set_thread_flags2_reserved(&self, value: u32) {
        self.thread_flags2.set_bits(8, 24, value as u64)
    }
    /// `NextProcessorNumber`: bits 0..=30 de `next_processor`.
    pub const NEXT_PROCESSOR_NUMBER_SHIFT: u32 = 0;
    pub const NEXT_PROCESSOR_NUMBER_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn next_processor_number(&self) -> u32 {
        self.next_processor.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_next_processor_number(&self, value: u32) {
        self.next_processor.set_bits(0, 31, value as u64)
    }
    /// `SharedReadyQueue`: bits 31..=31 de `next_processor`.
    pub const SHARED_READY_QUEUE_SHIFT: u32 = 31;
    pub const SHARED_READY_QUEUE_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn shared_ready_queue(&self) -> u32 {
        self.next_processor.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_shared_ready_queue(&self, value: u32) {
        self.next_processor.set_bits(31, 1, value as u64)
    }
    /// `ForegroundBoost`: bits 0..=3 de `priority_decrement`.
    pub const FOREGROUND_BOOST_SHIFT: u32 = 0;
    pub const FOREGROUND_BOOST_MASK: u8 = 0xf;
    #[inline(always)]
    pub fn foreground_boost(&self) -> u8 {
        self.priority_decrement.bits(0, 4) as u8
    }
    #[inline(always)]
    pub fn set_foreground_boost(&self, value: u8) {
        self.priority_decrement.set_bits(0, 4, value as u64)
    }
    /// `UnusualBoost`: bits 4..=7 de `priority_decrement`.
    pub const UNUSUAL_BOOST_SHIFT: u32 = 4;
    pub const UNUSUAL_BOOST_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn unusual_boost(&self) -> u8 {
        self.priority_decrement.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_unusual_boost(&self, value: u8) {
        self.priority_decrement.set_bits(4, 4, value as u64)
    }
    /// `ThreadFlags3Reserved`: bits 0..=7 de `thread_flags3`.
    pub const THREAD_FLAGS3_RESERVED_SHIFT: u32 = 0;
    pub const THREAD_FLAGS3_RESERVED_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn thread_flags3_reserved(&self) -> u32 {
        self.thread_flags3.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_thread_flags3_reserved(&self, value: u32) {
        self.thread_flags3.set_bits(0, 8, value as u64)
    }
    /// `PpmPolicy`: bits 8..=9 de `thread_flags3`.
    pub const PPM_POLICY_SHIFT: u32 = 8;
    pub const PPM_POLICY_MASK: u32 = 0x300;
    #[inline(always)]
    pub fn ppm_policy(&self) -> u32 {
        self.thread_flags3.bits(8, 2) as u32
    }
    #[inline(always)]
    pub fn set_ppm_policy(&self, value: u32) {
        self.thread_flags3.set_bits(8, 2, value as u64)
    }
    /// `ThreadFlags3Reserved2`: bits 10..=31 de `thread_flags3`.
    pub const THREAD_FLAGS3_RESERVED2_SHIFT: u32 = 10;
    pub const THREAD_FLAGS3_RESERVED2_MASK: u32 = 0xfffffc00;
    #[inline(always)]
    pub fn thread_flags3_reserved2(&self) -> u32 {
        self.thread_flags3.bits(10, 22) as u32
    }
    #[inline(always)]
    pub fn set_thread_flags3_reserved2(&self, value: u32) {
        self.thread_flags3.set_bits(10, 22, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Kthread>() == 0x430);
    assert!(core::mem::offset_of!(Kthread, header) == 0x0);
    assert!(core::mem::offset_of!(Kthread, s_list_fault_address) == 0x18);
    assert!(core::mem::offset_of!(Kthread, quantum_target) == 0x20);
    assert!(core::mem::offset_of!(Kthread, initial_stack) == 0x28);
    assert!(core::mem::offset_of!(Kthread, stack_limit) == 0x30);
    assert!(core::mem::offset_of!(Kthread, stack_base) == 0x38);
    assert!(core::mem::offset_of!(Kthread, thread_lock) == 0x40);
    assert!(core::mem::offset_of!(Kthread, cycle_time) == 0x48);
    assert!(core::mem::offset_of!(Kthread, current_run_time) == 0x50);
    assert!(core::mem::offset_of!(Kthread, expected_run_time) == 0x54);
    assert!(core::mem::offset_of!(Kthread, kernel_stack) == 0x58);
    assert!(core::mem::offset_of!(Kthread, state_save_area) == 0x60);
    assert!(core::mem::offset_of!(Kthread, scheduling_group) == 0x68);
    assert!(core::mem::offset_of!(Kthread, wait_register) == 0x70);
    assert!(core::mem::offset_of!(Kthread, running) == 0x71);
    assert!(core::mem::offset_of!(Kthread, alerted) == 0x72);
    assert!(core::mem::offset_of!(Kthread, misc_flags) == 0x74);
    assert!(core::mem::offset_of!(Kthread, thread_flags) == 0x78);
    assert!(core::mem::offset_of!(Kthread, tag) == 0x7c);
    assert!(core::mem::offset_of!(Kthread, system_hetero_cpu_policy) == 0x7d);
    assert!(core::mem::offset_of!(Kthread, bitfield_7e) == 0x7e);
    assert!(core::mem::offset_of!(Kthread, spec_ctrl) == 0x7f);
    assert!(core::mem::offset_of!(Kthread, system_call_number) == 0x80);
    assert!(core::mem::offset_of!(Kthread, ready_time) == 0x84);
    assert!(core::mem::offset_of!(Kthread, first_argument) == 0x88);
    assert!(core::mem::offset_of!(Kthread, trap_frame) == 0x90);
    assert!(core::mem::offset_of!(Kthread, apc_state) == 0x98);
    assert!(core::mem::offset_of!(Kthread, wait_status) == 0xc8);
    assert!(core::mem::offset_of!(Kthread, wait_block_list) == 0xd0);
    assert!(core::mem::offset_of!(Kthread, wait_list_entry) == 0xd8);
    assert!(core::mem::offset_of!(Kthread, queue) == 0xe8);
    assert!(core::mem::offset_of!(Kthread, teb) == 0xf0);
    assert!(core::mem::offset_of!(Kthread, relative_timer_bias) == 0xf8);
    assert!(core::mem::offset_of!(Kthread, timer) == 0x100);
    assert!(core::mem::offset_of!(Kthread, wait_block) == 0x140);
    assert!(core::mem::offset_of!(Kthread, thread_flags2) == 0x200);
    assert!(core::mem::offset_of!(Kthread, spare21) == 0x204);
    assert!(core::mem::offset_of!(Kthread, queue_list_entry) == 0x208);
    assert!(core::mem::offset_of!(Kthread, next_processor) == 0x218);
    assert!(core::mem::offset_of!(Kthread, queue_priority) == 0x21c);
    assert!(core::mem::offset_of!(Kthread, process) == 0x220);
    assert!(core::mem::offset_of!(Kthread, user_affinity) == 0x228);
    assert!(core::mem::offset_of!(Kthread, affinity_version) == 0x238);
    assert!(core::mem::offset_of!(Kthread, affinity) == 0x240);
    assert!(core::mem::offset_of!(Kthread, npx_state) == 0x250);
    assert!(core::mem::offset_of!(Kthread, saved_apc_state) == 0x258);
    assert!(core::mem::offset_of!(Kthread, scheduler_apc) == 0x288);
    assert!(core::mem::offset_of!(Kthread, suspend_event) == 0x2e0);
    assert!(core::mem::offset_of!(Kthread, thread_list_entry) == 0x2f8);
    assert!(core::mem::offset_of!(Kthread, mutant_list_head) == 0x308);
    assert!(core::mem::offset_of!(Kthread, ab_entry_summary) == 0x318);
    assert!(core::mem::offset_of!(Kthread, ab_wait_entry_count) == 0x319);
    assert!(core::mem::offset_of!(Kthread, ab_allocation_region_count) == 0x31a);
    assert!(core::mem::offset_of!(Kthread, system_priority) == 0x31b);
    assert!(core::mem::offset_of!(Kthread, secure_thread_cookie) == 0x31c);
    assert!(core::mem::offset_of!(Kthread, lock_entries) == 0x320);
    assert!(core::mem::offset_of!(Kthread, propagate_boosts_entry) == 0x328);
    assert!(core::mem::offset_of!(Kthread, io_self_boosts_entry) == 0x330);
    assert!(core::mem::offset_of!(Kthread, priority_floor_counts) == 0x338);
    assert!(core::mem::offset_of!(Kthread, priority_floor_counts_reserved) == 0x348);
    assert!(core::mem::offset_of!(Kthread, priority_floor_summary) == 0x358);
    assert!(core::mem::offset_of!(Kthread, ab_completed_io_boost_count) == 0x35c);
    assert!(core::mem::offset_of!(Kthread, ab_completed_io_qo_s_boost_count) == 0x360);
    assert!(core::mem::offset_of!(Kthread, ke_reference_count) == 0x364);
    assert!(core::mem::offset_of!(Kthread, ab_orphaned_entry_summary) == 0x366);
    assert!(core::mem::offset_of!(Kthread, ab_owned_entry_count) == 0x367);
    assert!(core::mem::offset_of!(Kthread, foreground_loss_time) == 0x368);
    assert!(core::mem::offset_of!(Kthread, global_foreground_list_entry) == 0x370);
    assert!(core::mem::offset_of!(Kthread, read_operation_count) == 0x380);
    assert!(core::mem::offset_of!(Kthread, write_operation_count) == 0x388);
    assert!(core::mem::offset_of!(Kthread, other_operation_count) == 0x390);
    assert!(core::mem::offset_of!(Kthread, read_transfer_count) == 0x398);
    assert!(core::mem::offset_of!(Kthread, write_transfer_count) == 0x3a0);
    assert!(core::mem::offset_of!(Kthread, other_transfer_count) == 0x3a8);
    assert!(core::mem::offset_of!(Kthread, queued_scb) == 0x3b0);
    assert!(core::mem::offset_of!(Kthread, thread_timer_delay) == 0x3b8);
    assert!(core::mem::offset_of!(Kthread, thread_flags3) == 0x3bc);
    assert!(core::mem::offset_of!(Kthread, tracing_private) == 0x3c0);
    assert!(core::mem::offset_of!(Kthread, scheduler_assist) == 0x3c8);
    assert!(core::mem::offset_of!(Kthread, ab_wait_object) == 0x3d0);
    assert!(core::mem::offset_of!(Kthread, reserved_previous_ready_time_value) == 0x3d8);
    assert!(core::mem::offset_of!(Kthread, kernel_wait_time) == 0x3e0);
    assert!(core::mem::offset_of!(Kthread, user_wait_time) == 0x3e8);
    assert!(core::mem::offset_of!(Kthread, global_update_vp_thread_priority_list_entry) == 0x3f0);
    assert!(core::mem::offset_of!(Kthread, scheduler_assist_priority_floor) == 0x400);
    assert!(core::mem::offset_of!(Kthread, spare28) == 0x404);
    assert!(core::mem::offset_of!(Kthread, resource_index) == 0x408);
    assert!(core::mem::offset_of!(Kthread, spare31) == 0x409);
    assert!(core::mem::offset_of!(Kthread, end_padding) == 0x410);
    assert!(core::mem::size_of::<KthreadView1>() == 0x430);
    assert!(core::mem::align_of::<KthreadView1>() == core::mem::align_of::<Kthread>());
    assert!(core::mem::offset_of!(KthreadView1, priority) == 0xc3);
    assert!(core::mem::offset_of!(KthreadView1, user_ideal_processor) == 0xc4);
    assert!(core::mem::offset_of!(KthreadView1, swap_list_entry) == 0xd8);
    assert!(core::mem::offset_of!(KthreadView1, context_switches) == 0x154);
    assert!(core::mem::offset_of!(KthreadView1, thread_counters) == 0x168);
    assert!(core::mem::offset_of!(KthreadView1, state) == 0x184);
    assert!(core::mem::offset_of!(KthreadView1, spare13) == 0x185);
    assert!(core::mem::offset_of!(KthreadView1, wait_irql) == 0x186);
    assert!(core::mem::offset_of!(KthreadView1, wait_mode) == 0x187);
    assert!(core::mem::offset_of!(KthreadView1, x_state_save) == 0x198);
    assert!(core::mem::offset_of!(KthreadView1, wait_time) == 0x1b4);
    assert!(core::mem::offset_of!(KthreadView1, win32_thread) == 0x1c8);
    assert!(core::mem::offset_of!(KthreadView1, kernel_apc_disable) == 0x1e4);
    assert!(core::mem::offset_of!(KthreadView1, special_apc_disable) == 0x1e6);
    assert!(core::mem::offset_of!(KthreadView1, ucb) == 0x1f0);
    assert!(core::mem::offset_of!(KthreadView1, uch) == 0x1f8);
    assert!(core::mem::offset_of!(KthreadView1, previous_mode) == 0x232);
    assert!(core::mem::offset_of!(KthreadView1, base_priority) == 0x233);
    assert!(core::mem::offset_of!(KthreadView1, priority_decrement) == 0x234);
    assert!(core::mem::offset_of!(KthreadView1, preempted) == 0x235);
    assert!(core::mem::offset_of!(KthreadView1, adjust_reason) == 0x236);
    assert!(core::mem::offset_of!(KthreadView1, adjust_increment) == 0x237);
    assert!(core::mem::offset_of!(KthreadView1, apc_state_index) == 0x24a);
    assert!(core::mem::offset_of!(KthreadView1, wait_block_count) == 0x24b);
    assert!(core::mem::offset_of!(KthreadView1, ideal_processor) == 0x24c);
    assert!(core::mem::offset_of!(KthreadView1, wait_reason) == 0x283);
    assert!(core::mem::offset_of!(KthreadView1, suspend_count) == 0x284);
    assert!(core::mem::offset_of!(KthreadView1, saturation) == 0x285);
    assert!(core::mem::offset_of!(KthreadView1, s_list_fault_count) == 0x286);
    assert!(core::mem::offset_of!(KthreadView1, quantum_reset) == 0x28b);
    assert!(core::mem::offset_of!(KthreadView1, kernel_time) == 0x28c);
    assert!(core::mem::offset_of!(KthreadView1, wait_prcb) == 0x2c8);
    assert!(core::mem::offset_of!(KthreadView1, lego_data) == 0x2d0);
    assert!(core::mem::offset_of!(KthreadView1, callback_nesting_level) == 0x2db);
    assert!(core::mem::offset_of!(KthreadView1, user_time) == 0x2dc);
    assert!(core::mem::offset_of!(KthreadView1, foreground_dpc_stack_list_entry) == 0x370);
    assert!(core::mem::offset_of!(KthreadView1, in_global_foreground_list) == 0x378);
    assert!(core::mem::offset_of!(KthreadView1, update_vp_thread_priority_dpc_stack_list_entry) == 0x3f0);
    assert!(core::mem::offset_of!(KthreadView1, in_global_update_vp_thread_priority_list) == 0x3f8);
    assert!(core::mem::size_of::<KthreadView2>() == 0x430);
    assert!(core::mem::align_of::<KthreadView2>() == core::mem::align_of::<Kthread>());
    assert!(core::mem::offset_of!(KthreadView2, combined_apc_disable) == 0x1e4);
};

/// `_KWAIT_STATUS_REGISTER` (0x1 bytes).
#[repr(C)]
pub struct KwaitStatusRegister {
    pub flags: Field<u8>,
}

unsafe impl NtStruct for KwaitStatusRegister {}

impl KwaitStatusRegister {
    /// `State`: bits 0..=2 de `flags`.
    pub const STATE_SHIFT: u32 = 0;
    pub const STATE_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn state(&self) -> u8 {
        self.flags.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_state(&self, value: u8) {
        self.flags.set_bits(0, 3, value as u64)
    }
    /// `Affinity`: bits 3..=3 de `flags`.
    pub const AFFINITY_SHIFT: u32 = 3;
    pub const AFFINITY_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn affinity(&self) -> u8 {
        self.flags.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_affinity(&self, value: u8) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `Priority`: bits 4..=4 de `flags`.
    pub const PRIORITY_SHIFT: u32 = 4;
    pub const PRIORITY_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn priority(&self) -> u8 {
        self.flags.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_priority(&self, value: u8) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `Apc`: bits 5..=5 de `flags`.
    pub const APC_SHIFT: u32 = 5;
    pub const APC_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn apc(&self) -> u8 {
        self.flags.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_apc(&self, value: u8) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `UserApc`: bits 6..=6 de `flags`.
    pub const USER_APC_SHIFT: u32 = 6;
    pub const USER_APC_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn user_apc(&self) -> u8 {
        self.flags.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_user_apc(&self, value: u8) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `Alert`: bits 7..=7 de `flags`.
    pub const ALERT_SHIFT: u32 = 7;
    pub const ALERT_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn alert(&self) -> u8 {
        self.flags.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_alert(&self, value: u8) {
        self.flags.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KwaitStatusRegister>() == 0x1);
    assert!(core::mem::offset_of!(KwaitStatusRegister, flags) == 0x0);
};

/// `_KAPC_STATE` (0x30 bytes).
#[repr(C)]
pub struct KapcState {
    pub apc_list_head: [ListEntry; 2],
    /// -> `_KPROCESS`
    pub process: Field<u64>,
    pub in_progress_flags: Field<u8>,
    pub kernel_apc_pending: Field<u8>,
    pub user_apc_pending_all: Field<u8>,
    _pad_2b: Reserved<0x5>,
}

unsafe impl NtStruct for KapcState {}

impl KapcState {
    /// `KernelApcInProgress`: bits 0..=0 de `in_progress_flags`.
    pub const KERNEL_APC_IN_PROGRESS_SHIFT: u32 = 0;
    pub const KERNEL_APC_IN_PROGRESS_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn kernel_apc_in_progress(&self) -> u8 {
        self.in_progress_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_kernel_apc_in_progress(&self, value: u8) {
        self.in_progress_flags.set_bits(0, 1, value as u64)
    }
    /// `SpecialApcInProgress`: bits 1..=1 de `in_progress_flags`.
    pub const SPECIAL_APC_IN_PROGRESS_SHIFT: u32 = 1;
    pub const SPECIAL_APC_IN_PROGRESS_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn special_apc_in_progress(&self) -> u8 {
        self.in_progress_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_special_apc_in_progress(&self, value: u8) {
        self.in_progress_flags.set_bits(1, 1, value as u64)
    }
    /// `SpecialUserApcPending`: bits 0..=0 de `user_apc_pending_all`.
    pub const SPECIAL_USER_APC_PENDING_SHIFT: u32 = 0;
    pub const SPECIAL_USER_APC_PENDING_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn special_user_apc_pending(&self) -> u8 {
        self.user_apc_pending_all.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_special_user_apc_pending(&self, value: u8) {
        self.user_apc_pending_all.set_bits(0, 1, value as u64)
    }
    /// `UserApcPending`: bits 1..=1 de `user_apc_pending_all`.
    pub const USER_APC_PENDING_SHIFT: u32 = 1;
    pub const USER_APC_PENDING_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn user_apc_pending(&self) -> u8 {
        self.user_apc_pending_all.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_user_apc_pending(&self, value: u8) {
        self.user_apc_pending_all.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KapcState>() == 0x30);
    assert!(core::mem::offset_of!(KapcState, apc_list_head) == 0x0);
    assert!(core::mem::offset_of!(KapcState, process) == 0x20);
    assert!(core::mem::offset_of!(KapcState, in_progress_flags) == 0x28);
    assert!(core::mem::offset_of!(KapcState, kernel_apc_pending) == 0x29);
    assert!(core::mem::offset_of!(KapcState, user_apc_pending_all) == 0x2a);
};

/// `_KWAIT_BLOCK` (0x30 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KwaitBlockView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KwaitBlock {
    pub wait_list_entry: ListEntry,
    pub wait_type: Field<u8>,
    pub block_state: Field<u8>,
    pub wait_key: Field<u16>,
    pub spare_long: Field<i32>,
    /// -> `_KTHREAD`
    pub thread: Field<u64>,
    /// -> `void`
    pub object: Field<u64>,
    /// -> `void`
    pub spare_ptr: Field<u64>,
}

/// Vista 1 de `_KWAIT_BLOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KwaitBlockView1 {
    _pad_0: Reserved<0x18>,
    /// -> `_KQUEUE`
    pub notification_queue: Field<u64>,
    _pad_20: Reserved<0x10>,
}

impl core::ops::Deref for KwaitBlock {
    type Target = KwaitBlockView1;
    #[inline(always)]
    fn deref(&self) -> &KwaitBlockView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KwaitBlockView1>() }
    }
}

unsafe impl NtStruct for KwaitBlock {}

const _: () = {
    assert!(core::mem::size_of::<KwaitBlock>() == 0x30);
    assert!(core::mem::offset_of!(KwaitBlock, wait_list_entry) == 0x0);
    assert!(core::mem::offset_of!(KwaitBlock, wait_type) == 0x10);
    assert!(core::mem::offset_of!(KwaitBlock, block_state) == 0x11);
    assert!(core::mem::offset_of!(KwaitBlock, wait_key) == 0x12);
    assert!(core::mem::offset_of!(KwaitBlock, spare_long) == 0x14);
    assert!(core::mem::offset_of!(KwaitBlock, thread) == 0x18);
    assert!(core::mem::offset_of!(KwaitBlock, object) == 0x20);
    assert!(core::mem::offset_of!(KwaitBlock, spare_ptr) == 0x28);
    assert!(core::mem::size_of::<KwaitBlockView1>() == 0x30);
    assert!(core::mem::align_of::<KwaitBlockView1>() == core::mem::align_of::<KwaitBlock>());
    assert!(core::mem::offset_of!(KwaitBlockView1, notification_queue) == 0x18);
};

/// `_GROUP_AFFINITY` (0x10 bytes).
#[repr(C)]
pub struct GroupAffinity {
    pub mask: Field<u64>,
    pub group: Field<u16>,
    pub reserved: [Field<u16>; 3],
}

unsafe impl NtStruct for GroupAffinity {}

const _: () = {
    assert!(core::mem::size_of::<GroupAffinity>() == 0x10);
    assert!(core::mem::offset_of!(GroupAffinity, mask) == 0x0);
    assert!(core::mem::offset_of!(GroupAffinity, group) == 0x8);
    assert!(core::mem::offset_of!(GroupAffinity, reserved) == 0xa);
};

/// `_KSEMAPHORE` (0x20 bytes).
#[repr(C)]
pub struct Ksemaphore {
    pub header: DispatcherHeader,
    pub limit: Field<i32>,
    _pad_1c: Reserved<0x4>,
}

unsafe impl NtStruct for Ksemaphore {}

const _: () = {
    assert!(core::mem::size_of::<Ksemaphore>() == 0x20);
    assert!(core::mem::offset_of!(Ksemaphore, header) == 0x0);
    assert!(core::mem::offset_of!(Ksemaphore, limit) == 0x18);
};

/// `_KLOCK_ENTRY` (0x60 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KlockEntryView1`..`KlockEntryView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct KlockEntry {
    pub tree_node: RtlBalancedNode,
    pub entry_flags: Field<u32>,
    pub spare_flags: Field<u32>,
    pub lock_state: KlockEntryLockState,
    pub owner_tree: RtlRbTree,
    pub waiter_tree: RtlRbTree,
    pub entry_lock: Field<u64>,
    pub boost_bitmap: KlockEntryBoostBitmap,
    pub spare_pad: Field<u32>,
}

/// Vista 1 de `_KLOCK_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KlockEntryView1 {
    pub free_list_entry: SingleListEntry,
    _pad_8: Reserved<0x10>,
    pub entry_offset: Field<u8>,
    pub thread_local_flags: Field<u8>,
    pub acquired_byte: Field<u8>,
    pub cross_thread_flags: Field<u8>,
    _pad_1c: Reserved<0x4>,
    /// -> `void`
    pub lock_unsafe: Field<u64>,
    /// -> `void`
    pub session_state: Field<u64>,
    pub cpu_priority_key: Field<i8>,
    _pad_31: Reserved<0x2f>,
}

/// Vista 2 de `_KLOCK_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KlockEntryView2 {
    _align: [u64; 0],
    _pad_0: Reserved<0x20>,
    pub cross_thread_releasable_and_busy_byte: Field<u8>,
    pub reserved: [Field<u8>; 6],
    pub in_tree_byte: Field<u8>,
    pub session_id: Field<u32>,
    pub session_pad: Field<u32>,
    _pad_30: Reserved<0x30>,
}

impl core::ops::Deref for KlockEntry {
    type Target = KlockEntryView1;
    #[inline(always)]
    fn deref(&self) -> &KlockEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KlockEntryView1>() }
    }
}

impl core::ops::Deref for KlockEntryView1 {
    type Target = KlockEntryView2;
    #[inline(always)]
    fn deref(&self) -> &KlockEntryView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KlockEntryView2>() }
    }
}

unsafe impl NtStruct for KlockEntry {}

impl KlockEntry {
    /// `StaticState`: bits 0..=7 de `entry_flags`.
    pub const STATIC_STATE_SHIFT: u32 = 0;
    pub const STATIC_STATE_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn static_state(&self) -> u32 {
        self.entry_flags.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_static_state(&self, value: u32) {
        self.entry_flags.set_bits(0, 8, value as u64)
    }
    /// `AllFlags`: bits 8..=31 de `entry_flags`.
    pub const ALL_FLAGS_SHIFT: u32 = 8;
    pub const ALL_FLAGS_MASK: u32 = 0xffffff00;
    #[inline(always)]
    pub fn all_flags(&self) -> u32 {
        self.entry_flags.bits(8, 24) as u32
    }
    #[inline(always)]
    pub fn set_all_flags(&self, value: u32) {
        self.entry_flags.set_bits(8, 24, value as u64)
    }
    /// `WaitingBit`: bits 0..=0 de `thread_local_flags`.
    pub const WAITING_BIT_SHIFT: u32 = 0;
    pub const WAITING_BIT_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn waiting_bit(&self) -> u8 {
        self.thread_local_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_waiting_bit(&self, value: u8) {
        self.thread_local_flags.set_bits(0, 1, value as u64)
    }
    /// `Spare0`: bits 1..=7 de `thread_local_flags`.
    pub const SPARE0_SHIFT: u32 = 1;
    pub const SPARE0_MASK: u8 = 0xfe;
    #[inline(always)]
    pub fn spare0(&self) -> u8 {
        self.thread_local_flags.bits(1, 7) as u8
    }
    #[inline(always)]
    pub fn set_spare0(&self, value: u8) {
        self.thread_local_flags.set_bits(1, 7, value as u64)
    }
    /// `AcquiredBit`: bits 0..=0 de `acquired_byte`.
    pub const ACQUIRED_BIT_SHIFT: u32 = 0;
    pub const ACQUIRED_BIT_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn acquired_bit(&self) -> u8 {
        self.acquired_byte.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_acquired_bit(&self, value: u8) {
        self.acquired_byte.set_bits(0, 1, value as u64)
    }
    /// `HeadNodeBit`: bits 0..=0 de `cross_thread_flags`.
    pub const HEAD_NODE_BIT_SHIFT: u32 = 0;
    pub const HEAD_NODE_BIT_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn head_node_bit(&self) -> u8 {
        self.cross_thread_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_head_node_bit(&self, value: u8) {
        self.cross_thread_flags.set_bits(0, 1, value as u64)
    }
    /// `IoPriorityBit`: bits 1..=1 de `cross_thread_flags`.
    pub const IO_PRIORITY_BIT_SHIFT: u32 = 1;
    pub const IO_PRIORITY_BIT_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn io_priority_bit(&self) -> u8 {
        self.cross_thread_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_io_priority_bit(&self, value: u8) {
        self.cross_thread_flags.set_bits(1, 1, value as u64)
    }
    /// `IoQoSWaiter`: bits 2..=2 de `cross_thread_flags`.
    pub const IO_QO_S_WAITER_SHIFT: u32 = 2;
    pub const IO_QO_S_WAITER_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn io_qo_s_waiter(&self) -> u8 {
        self.cross_thread_flags.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_io_qo_s_waiter(&self, value: u8) {
        self.cross_thread_flags.set_bits(2, 1, value as u64)
    }
    /// `Spare1`: bits 3..=7 de `cross_thread_flags`.
    pub const SPARE1_SHIFT: u32 = 3;
    pub const SPARE1_MASK: u8 = 0xf8;
    #[inline(always)]
    pub fn spare1(&self) -> u8 {
        self.cross_thread_flags.bits(3, 5) as u8
    }
    #[inline(always)]
    pub fn set_spare1(&self, value: u8) {
        self.cross_thread_flags.set_bits(3, 5, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KlockEntry>() == 0x60);
    assert!(core::mem::offset_of!(KlockEntry, tree_node) == 0x0);
    assert!(core::mem::offset_of!(KlockEntry, entry_flags) == 0x18);
    assert!(core::mem::offset_of!(KlockEntry, spare_flags) == 0x1c);
    assert!(core::mem::offset_of!(KlockEntry, lock_state) == 0x20);
    assert!(core::mem::offset_of!(KlockEntry, owner_tree) == 0x30);
    assert!(core::mem::offset_of!(KlockEntry, waiter_tree) == 0x40);
    assert!(core::mem::offset_of!(KlockEntry, entry_lock) == 0x50);
    assert!(core::mem::offset_of!(KlockEntry, boost_bitmap) == 0x58);
    assert!(core::mem::offset_of!(KlockEntry, spare_pad) == 0x5c);
    assert!(core::mem::size_of::<KlockEntryView1>() == 0x60);
    assert!(core::mem::align_of::<KlockEntryView1>() == core::mem::align_of::<KlockEntry>());
    assert!(core::mem::offset_of!(KlockEntryView1, free_list_entry) == 0x0);
    assert!(core::mem::offset_of!(KlockEntryView1, entry_offset) == 0x18);
    assert!(core::mem::offset_of!(KlockEntryView1, thread_local_flags) == 0x19);
    assert!(core::mem::offset_of!(KlockEntryView1, acquired_byte) == 0x1a);
    assert!(core::mem::offset_of!(KlockEntryView1, cross_thread_flags) == 0x1b);
    assert!(core::mem::offset_of!(KlockEntryView1, lock_unsafe) == 0x20);
    assert!(core::mem::offset_of!(KlockEntryView1, session_state) == 0x28);
    assert!(core::mem::offset_of!(KlockEntryView1, cpu_priority_key) == 0x30);
    assert!(core::mem::size_of::<KlockEntryView2>() == 0x60);
    assert!(core::mem::align_of::<KlockEntryView2>() == core::mem::align_of::<KlockEntry>());
    assert!(core::mem::offset_of!(KlockEntryView2, cross_thread_releasable_and_busy_byte) == 0x20);
    assert!(core::mem::offset_of!(KlockEntryView2, reserved) == 0x21);
    assert!(core::mem::offset_of!(KlockEntryView2, in_tree_byte) == 0x27);
    assert!(core::mem::offset_of!(KlockEntryView2, session_id) == 0x28);
    assert!(core::mem::offset_of!(KlockEntryView2, session_pad) == 0x2c);
};

/// `_KLOCK_ENTRY_LOCK_STATE` (0x10 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KlockEntryLockStateView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KlockEntryLockState {
    /// -> `void`
    pub lock_state: Field<u64>,
    /// -> `void`
    pub session_state: Field<u64>,
}

/// Vista 1 de `_KLOCK_ENTRY_LOCK_STATE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KlockEntryLockStateView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x8>,
    pub session_id: Field<u32>,
    pub session_pad: Field<u32>,
}

impl core::ops::Deref for KlockEntryLockState {
    type Target = KlockEntryLockStateView1;
    #[inline(always)]
    fn deref(&self) -> &KlockEntryLockStateView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KlockEntryLockStateView1>() }
    }
}

unsafe impl NtStruct for KlockEntryLockState {}

impl KlockEntryLockState {
    /// `CrossThreadReleasable`: bits 0..=0 de `lock_state`.
    pub const CROSS_THREAD_RELEASABLE_SHIFT: u32 = 0;
    pub const CROSS_THREAD_RELEASABLE_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn cross_thread_releasable(&self) -> u64 {
        self.lock_state.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_cross_thread_releasable(&self, value: u64) {
        self.lock_state.set_bits(0, 1, value as u64)
    }
    /// `Busy`: bits 1..=1 de `lock_state`.
    pub const BUSY_SHIFT: u32 = 1;
    pub const BUSY_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn busy(&self) -> u64 {
        self.lock_state.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_busy(&self, value: u64) {
        self.lock_state.set_bits(1, 1, value as u64)
    }
    /// `Reserved`: bits 2..=62 de `lock_state`.
    pub const RESERVED_SHIFT: u32 = 2;
    pub const RESERVED_MASK: u64 = 0x7ffffffffffffffc;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.lock_state.bits(2, 61) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.lock_state.set_bits(2, 61, value as u64)
    }
    /// `InTree`: bits 63..=63 de `lock_state`.
    pub const IN_TREE_SHIFT: u32 = 63;
    pub const IN_TREE_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn in_tree(&self) -> u64 {
        self.lock_state.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_in_tree(&self, value: u64) {
        self.lock_state.set_bits(63, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KlockEntryLockState>() == 0x10);
    assert!(core::mem::offset_of!(KlockEntryLockState, lock_state) == 0x0);
    assert!(core::mem::offset_of!(KlockEntryLockState, session_state) == 0x8);
    assert!(core::mem::size_of::<KlockEntryLockStateView1>() == 0x10);
    assert!(core::mem::align_of::<KlockEntryLockStateView1>() == core::mem::align_of::<KlockEntryLockState>());
    assert!(core::mem::offset_of!(KlockEntryLockStateView1, session_id) == 0x8);
    assert!(core::mem::offset_of!(KlockEntryLockStateView1, session_pad) == 0xc);
};

/// `_KLOCK_ENTRY_BOOST_BITMAP` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KlockEntryBoostBitmapView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KlockEntryBoostBitmap {
    pub all_fields: Field<u32>,
}

/// Vista 1 de `_KLOCK_ENTRY_BOOST_BITMAP` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KlockEntryBoostBitmapView1 {
    _align: [u32; 0],
    pub bitfield_0: Field<u16>,
    pub bitfield_2: Field<u16>,
}

impl core::ops::Deref for KlockEntryBoostBitmap {
    type Target = KlockEntryBoostBitmapView1;
    #[inline(always)]
    fn deref(&self) -> &KlockEntryBoostBitmapView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KlockEntryBoostBitmapView1>() }
    }
}

unsafe impl NtStruct for KlockEntryBoostBitmap {}

impl KlockEntryBoostBitmap {
    /// `AllBoosts`: bits 0..=16 de `all_fields`.
    pub const ALL_BOOSTS_SHIFT: u32 = 0;
    pub const ALL_BOOSTS_MASK: u32 = 0x1ffff;
    #[inline(always)]
    pub fn all_boosts(&self) -> u32 {
        self.all_fields.bits(0, 17) as u32
    }
    #[inline(always)]
    pub fn set_all_boosts(&self, value: u32) {
        self.all_fields.set_bits(0, 17, value as u64)
    }
    /// `Reserved`: bits 17..=31 de `all_fields`.
    pub const RESERVED_SHIFT: u32 = 17;
    pub const RESERVED_MASK: u32 = 0xfffe0000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.all_fields.bits(17, 15) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.all_fields.set_bits(17, 15, value as u64)
    }
    /// `CpuBoostsBitmap`: bits 0..=14 de `bitfield_0`.
    pub const CPU_BOOSTS_BITMAP_SHIFT: u32 = 0;
    pub const CPU_BOOSTS_BITMAP_MASK: u16 = 0x7fff;
    #[inline(always)]
    pub fn cpu_boosts_bitmap(&self) -> u16 {
        self.bitfield_0.bits(0, 15) as u16
    }
    #[inline(always)]
    pub fn set_cpu_boosts_bitmap(&self, value: u16) {
        self.bitfield_0.set_bits(0, 15, value as u64)
    }
    /// `IoBoost`: bits 15..=15 de `bitfield_0`.
    pub const IO_BOOST_SHIFT: u32 = 15;
    pub const IO_BOOST_MASK: u16 = 0x8000;
    #[inline(always)]
    pub fn io_boost(&self) -> u16 {
        self.bitfield_0.bits(15, 1) as u16
    }
    #[inline(always)]
    pub fn set_io_boost(&self, value: u16) {
        self.bitfield_0.set_bits(15, 1, value as u64)
    }
    /// `IoQoSBoost`: bits 0..=0 de `bitfield_2`.
    pub const IO_QO_S_BOOST_SHIFT: u32 = 0;
    pub const IO_QO_S_BOOST_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn io_qo_s_boost(&self) -> u16 {
        self.bitfield_2.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_io_qo_s_boost(&self, value: u16) {
        self.bitfield_2.set_bits(0, 1, value as u64)
    }
    /// `IoNormalPriorityWaiterCount`: bits 1..=8 de `bitfield_2`.
    pub const IO_NORMAL_PRIORITY_WAITER_COUNT_SHIFT: u32 = 1;
    pub const IO_NORMAL_PRIORITY_WAITER_COUNT_MASK: u16 = 0x1fe;
    #[inline(always)]
    pub fn io_normal_priority_waiter_count(&self) -> u16 {
        self.bitfield_2.bits(1, 8) as u16
    }
    #[inline(always)]
    pub fn set_io_normal_priority_waiter_count(&self, value: u16) {
        self.bitfield_2.set_bits(1, 8, value as u64)
    }
    /// `IoQoSWaiterCount`: bits 9..=15 de `bitfield_2`.
    pub const IO_QO_S_WAITER_COUNT_SHIFT: u32 = 9;
    pub const IO_QO_S_WAITER_COUNT_MASK: u16 = 0xfe00;
    #[inline(always)]
    pub fn io_qo_s_waiter_count(&self) -> u16 {
        self.bitfield_2.bits(9, 7) as u16
    }
    #[inline(always)]
    pub fn set_io_qo_s_waiter_count(&self, value: u16) {
        self.bitfield_2.set_bits(9, 7, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KlockEntryBoostBitmap>() == 0x4);
    assert!(core::mem::offset_of!(KlockEntryBoostBitmap, all_fields) == 0x0);
    assert!(core::mem::size_of::<KlockEntryBoostBitmapView1>() == 0x4);
    assert!(core::mem::align_of::<KlockEntryBoostBitmapView1>() == core::mem::align_of::<KlockEntryBoostBitmap>());
    assert!(core::mem::offset_of!(KlockEntryBoostBitmapView1, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(KlockEntryBoostBitmapView1, bitfield_2) == 0x2);
};

/// `_KPROCESS` (0x438 bytes).
#[repr(C)]
pub struct Kprocess {
    pub header: DispatcherHeader,
    pub profile_list_head: ListEntry,
    pub directory_table_base: Field<u64>,
    pub thread_list_head: ListEntry,
    pub process_lock: Field<u32>,
    pub process_timer_delay: Field<u32>,
    pub deep_freeze_start_time: Field<u64>,
    pub affinity: KaffinityEx,
    pub affinity_padding: [Field<u64>; 12],
    pub ready_list_head: ListEntry,
    pub swap_list_entry: SingleListEntry,
    pub active_processors: KaffinityEx,
    pub active_processors_padding: [Field<u64>; 12],
    pub process_flags: Field<i32>,
    pub active_groups_mask: Field<u32>,
    pub base_priority: Field<i8>,
    pub quantum_reset: Field<i8>,
    pub visited: Field<i8>,
    pub flags: KexecuteOptions,
    pub thread_seed: [Field<u16>; 20],
    pub thread_seed_padding: [Field<u16>; 12],
    pub ideal_processor: [Field<u16>; 20],
    pub ideal_processor_padding: [Field<u16>; 12],
    pub ideal_node: [Field<u16>; 20],
    pub ideal_node_padding: [Field<u16>; 12],
    pub ideal_global_node: Field<u16>,
    pub spare1: Field<u16>,
    pub stack_count: KstackCount,
    _pad_34c: Reserved<0x4>,
    pub process_list_entry: ListEntry,
    pub cycle_time: Field<u64>,
    pub context_switches: Field<u64>,
    /// -> `_KSCHEDULING_GROUP`
    pub scheduling_group: Field<u64>,
    pub freeze_count: Field<u32>,
    pub kernel_time: Field<u32>,
    pub user_time: Field<u32>,
    pub ready_time: Field<u32>,
    pub user_directory_table_base: Field<u64>,
    pub address_policy: Field<u8>,
    pub spare2: [Field<u8>; 71],
    /// -> `void`
    pub instrumentation_callback: Field<u64>,
    pub secure_state: KprocessSecureState,
    pub kernel_wait_time: Field<u64>,
    pub user_wait_time: Field<u64>,
    pub end_padding: [Field<u64>; 8],
}

unsafe impl NtStruct for Kprocess {}

impl Kprocess {
    /// `AutoAlignment`: bits 0..=0 de `process_flags`.
    pub const AUTO_ALIGNMENT_SHIFT: u32 = 0;
    pub const AUTO_ALIGNMENT_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn auto_alignment(&self) -> u32 {
        self.process_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_auto_alignment(&self, value: u32) {
        self.process_flags.set_bits(0, 1, value as u64)
    }
    /// `DisableBoost`: bits 1..=1 de `process_flags`.
    pub const DISABLE_BOOST_SHIFT: u32 = 1;
    pub const DISABLE_BOOST_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn disable_boost(&self) -> u32 {
        self.process_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_boost(&self, value: u32) {
        self.process_flags.set_bits(1, 1, value as u64)
    }
    /// `DisableQuantum`: bits 2..=2 de `process_flags`.
    pub const DISABLE_QUANTUM_SHIFT: u32 = 2;
    pub const DISABLE_QUANTUM_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn disable_quantum(&self) -> u32 {
        self.process_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_quantum(&self, value: u32) {
        self.process_flags.set_bits(2, 1, value as u64)
    }
    /// `DeepFreeze`: bits 3..=3 de `process_flags`.
    pub const DEEP_FREEZE_SHIFT: u32 = 3;
    pub const DEEP_FREEZE_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn deep_freeze(&self) -> u32 {
        self.process_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_deep_freeze(&self, value: u32) {
        self.process_flags.set_bits(3, 1, value as u64)
    }
    /// `TimerVirtualization`: bits 4..=4 de `process_flags`.
    pub const TIMER_VIRTUALIZATION_SHIFT: u32 = 4;
    pub const TIMER_VIRTUALIZATION_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn timer_virtualization(&self) -> u32 {
        self.process_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_timer_virtualization(&self, value: u32) {
        self.process_flags.set_bits(4, 1, value as u64)
    }
    /// `CheckStackExtents`: bits 5..=5 de `process_flags`.
    pub const CHECK_STACK_EXTENTS_SHIFT: u32 = 5;
    pub const CHECK_STACK_EXTENTS_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn check_stack_extents(&self) -> u32 {
        self.process_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_check_stack_extents(&self, value: u32) {
        self.process_flags.set_bits(5, 1, value as u64)
    }
    /// `CacheIsolationEnabled`: bits 6..=6 de `process_flags`.
    pub const CACHE_ISOLATION_ENABLED_SHIFT: u32 = 6;
    pub const CACHE_ISOLATION_ENABLED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn cache_isolation_enabled(&self) -> u32 {
        self.process_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_cache_isolation_enabled(&self, value: u32) {
        self.process_flags.set_bits(6, 1, value as u64)
    }
    /// `PpmPolicy`: bits 7..=9 de `process_flags`.
    pub const PPM_POLICY_SHIFT: u32 = 7;
    pub const PPM_POLICY_MASK: u32 = 0x380;
    #[inline(always)]
    pub fn ppm_policy(&self) -> u32 {
        self.process_flags.bits(7, 3) as u32
    }
    #[inline(always)]
    pub fn set_ppm_policy(&self, value: u32) {
        self.process_flags.set_bits(7, 3, value as u64)
    }
    /// `VaSpaceDeleted`: bits 10..=10 de `process_flags`.
    pub const VA_SPACE_DELETED_SHIFT: u32 = 10;
    pub const VA_SPACE_DELETED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn va_space_deleted(&self) -> u32 {
        self.process_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_va_space_deleted(&self, value: u32) {
        self.process_flags.set_bits(10, 1, value as u64)
    }
    /// `ReservedFlags`: bits 11..=31 de `process_flags`.
    pub const RESERVED_FLAGS_SHIFT: u32 = 11;
    pub const RESERVED_FLAGS_MASK: u32 = 0xfffff800;
    #[inline(always)]
    pub fn reserved_flags(&self) -> u32 {
        self.process_flags.bits(11, 21) as u32
    }
    #[inline(always)]
    pub fn set_reserved_flags(&self, value: u32) {
        self.process_flags.set_bits(11, 21, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Kprocess>() == 0x438);
    assert!(core::mem::offset_of!(Kprocess, header) == 0x0);
    assert!(core::mem::offset_of!(Kprocess, profile_list_head) == 0x18);
    assert!(core::mem::offset_of!(Kprocess, directory_table_base) == 0x28);
    assert!(core::mem::offset_of!(Kprocess, thread_list_head) == 0x30);
    assert!(core::mem::offset_of!(Kprocess, process_lock) == 0x40);
    assert!(core::mem::offset_of!(Kprocess, process_timer_delay) == 0x44);
    assert!(core::mem::offset_of!(Kprocess, deep_freeze_start_time) == 0x48);
    assert!(core::mem::offset_of!(Kprocess, affinity) == 0x50);
    assert!(core::mem::offset_of!(Kprocess, affinity_padding) == 0xf8);
    assert!(core::mem::offset_of!(Kprocess, ready_list_head) == 0x158);
    assert!(core::mem::offset_of!(Kprocess, swap_list_entry) == 0x168);
    assert!(core::mem::offset_of!(Kprocess, active_processors) == 0x170);
    assert!(core::mem::offset_of!(Kprocess, active_processors_padding) == 0x218);
    assert!(core::mem::offset_of!(Kprocess, process_flags) == 0x278);
    assert!(core::mem::offset_of!(Kprocess, active_groups_mask) == 0x27c);
    assert!(core::mem::offset_of!(Kprocess, base_priority) == 0x280);
    assert!(core::mem::offset_of!(Kprocess, quantum_reset) == 0x281);
    assert!(core::mem::offset_of!(Kprocess, visited) == 0x282);
    assert!(core::mem::offset_of!(Kprocess, flags) == 0x283);
    assert!(core::mem::offset_of!(Kprocess, thread_seed) == 0x284);
    assert!(core::mem::offset_of!(Kprocess, thread_seed_padding) == 0x2ac);
    assert!(core::mem::offset_of!(Kprocess, ideal_processor) == 0x2c4);
    assert!(core::mem::offset_of!(Kprocess, ideal_processor_padding) == 0x2ec);
    assert!(core::mem::offset_of!(Kprocess, ideal_node) == 0x304);
    assert!(core::mem::offset_of!(Kprocess, ideal_node_padding) == 0x32c);
    assert!(core::mem::offset_of!(Kprocess, ideal_global_node) == 0x344);
    assert!(core::mem::offset_of!(Kprocess, spare1) == 0x346);
    assert!(core::mem::offset_of!(Kprocess, stack_count) == 0x348);
    assert!(core::mem::offset_of!(Kprocess, process_list_entry) == 0x350);
    assert!(core::mem::offset_of!(Kprocess, cycle_time) == 0x360);
    assert!(core::mem::offset_of!(Kprocess, context_switches) == 0x368);
    assert!(core::mem::offset_of!(Kprocess, scheduling_group) == 0x370);
    assert!(core::mem::offset_of!(Kprocess, freeze_count) == 0x378);
    assert!(core::mem::offset_of!(Kprocess, kernel_time) == 0x37c);
    assert!(core::mem::offset_of!(Kprocess, user_time) == 0x380);
    assert!(core::mem::offset_of!(Kprocess, ready_time) == 0x384);
    assert!(core::mem::offset_of!(Kprocess, user_directory_table_base) == 0x388);
    assert!(core::mem::offset_of!(Kprocess, address_policy) == 0x390);
    assert!(core::mem::offset_of!(Kprocess, spare2) == 0x391);
    assert!(core::mem::offset_of!(Kprocess, instrumentation_callback) == 0x3d8);
    assert!(core::mem::offset_of!(Kprocess, secure_state) == 0x3e0);
    assert!(core::mem::offset_of!(Kprocess, kernel_wait_time) == 0x3e8);
    assert!(core::mem::offset_of!(Kprocess, user_wait_time) == 0x3f0);
    assert!(core::mem::offset_of!(Kprocess, end_padding) == 0x3f8);
};

/// `_KAFFINITY_EX` (0xa8 bytes).
#[repr(C)]
pub struct KaffinityEx {
    pub count: Field<u16>,
    pub size: Field<u16>,
    pub reserved: Field<u32>,
    pub bitmap: [Field<u64>; 20],
}

unsafe impl NtStruct for KaffinityEx {}

const _: () = {
    assert!(core::mem::size_of::<KaffinityEx>() == 0xa8);
    assert!(core::mem::offset_of!(KaffinityEx, count) == 0x0);
    assert!(core::mem::offset_of!(KaffinityEx, size) == 0x2);
    assert!(core::mem::offset_of!(KaffinityEx, reserved) == 0x4);
    assert!(core::mem::offset_of!(KaffinityEx, bitmap) == 0x8);
};

/// `_KEXECUTE_OPTIONS` (0x1 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KexecuteOptionsView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KexecuteOptions {
    pub execute_options: Field<u8>,
}

/// Vista 1 de `_KEXECUTE_OPTIONS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KexecuteOptionsView1 {
    pub execute_options_nv: Field<u8>,
}

impl core::ops::Deref for KexecuteOptions {
    type Target = KexecuteOptionsView1;
    #[inline(always)]
    fn deref(&self) -> &KexecuteOptionsView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KexecuteOptionsView1>() }
    }
}

unsafe impl NtStruct for KexecuteOptions {}

impl KexecuteOptions {
    /// `ExecuteDisable`: bits 0..=0 de `execute_options`.
    pub const EXECUTE_DISABLE_SHIFT: u32 = 0;
    pub const EXECUTE_DISABLE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn execute_disable(&self) -> u8 {
        self.execute_options.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_execute_disable(&self, value: u8) {
        self.execute_options.set_bits(0, 1, value as u64)
    }
    /// `ExecuteEnable`: bits 1..=1 de `execute_options`.
    pub const EXECUTE_ENABLE_SHIFT: u32 = 1;
    pub const EXECUTE_ENABLE_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn execute_enable(&self) -> u8 {
        self.execute_options.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_execute_enable(&self, value: u8) {
        self.execute_options.set_bits(1, 1, value as u64)
    }
    /// `DisableThunkEmulation`: bits 2..=2 de `execute_options`.
    pub const DISABLE_THUNK_EMULATION_SHIFT: u32 = 2;
    pub const DISABLE_THUNK_EMULATION_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn disable_thunk_emulation(&self) -> u8 {
        self.execute_options.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_disable_thunk_emulation(&self, value: u8) {
        self.execute_options.set_bits(2, 1, value as u64)
    }
    /// `Permanent`: bits 3..=3 de `execute_options`.
    pub const PERMANENT_SHIFT: u32 = 3;
    pub const PERMANENT_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn permanent(&self) -> u8 {
        self.execute_options.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_permanent(&self, value: u8) {
        self.execute_options.set_bits(3, 1, value as u64)
    }
    /// `ExecuteDispatchEnable`: bits 4..=4 de `execute_options`.
    pub const EXECUTE_DISPATCH_ENABLE_SHIFT: u32 = 4;
    pub const EXECUTE_DISPATCH_ENABLE_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn execute_dispatch_enable(&self) -> u8 {
        self.execute_options.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_execute_dispatch_enable(&self, value: u8) {
        self.execute_options.set_bits(4, 1, value as u64)
    }
    /// `ImageDispatchEnable`: bits 5..=5 de `execute_options`.
    pub const IMAGE_DISPATCH_ENABLE_SHIFT: u32 = 5;
    pub const IMAGE_DISPATCH_ENABLE_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn image_dispatch_enable(&self) -> u8 {
        self.execute_options.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_image_dispatch_enable(&self, value: u8) {
        self.execute_options.set_bits(5, 1, value as u64)
    }
    /// `DisableExceptionChainValidation`: bits 6..=6 de `execute_options`.
    pub const DISABLE_EXCEPTION_CHAIN_VALIDATION_SHIFT: u32 = 6;
    pub const DISABLE_EXCEPTION_CHAIN_VALIDATION_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn disable_exception_chain_validation(&self) -> u8 {
        self.execute_options.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_disable_exception_chain_validation(&self, value: u8) {
        self.execute_options.set_bits(6, 1, value as u64)
    }
    /// `Spare`: bits 7..=7 de `execute_options`.
    pub const SPARE_SHIFT: u32 = 7;
    pub const SPARE_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn spare(&self) -> u8 {
        self.execute_options.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u8) {
        self.execute_options.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KexecuteOptions>() == 0x1);
    assert!(core::mem::offset_of!(KexecuteOptions, execute_options) == 0x0);
    assert!(core::mem::size_of::<KexecuteOptionsView1>() == 0x1);
    assert!(core::mem::align_of::<KexecuteOptionsView1>() == core::mem::align_of::<KexecuteOptions>());
    assert!(core::mem::offset_of!(KexecuteOptionsView1, execute_options_nv) == 0x0);
};

/// `_KSTACK_COUNT` (0x4 bytes).
#[repr(C)]
pub struct KstackCount {
    pub value: Field<i32>,
}

unsafe impl NtStruct for KstackCount {}

impl KstackCount {
    /// `State`: bits 0..=2 de `value`.
    pub const STATE_SHIFT: u32 = 0;
    pub const STATE_MASK: u32 = 0x7;
    #[inline(always)]
    pub fn state(&self) -> u32 {
        self.value.bits(0, 3) as u32
    }
    #[inline(always)]
    pub fn set_state(&self, value: u32) {
        self.value.set_bits(0, 3, value as u64)
    }
    /// `StackCount`: bits 3..=31 de `value`.
    pub const STACK_COUNT_SHIFT: u32 = 3;
    pub const STACK_COUNT_MASK: u32 = 0xfffffff8;
    #[inline(always)]
    pub fn stack_count(&self) -> u32 {
        self.value.bits(3, 29) as u32
    }
    #[inline(always)]
    pub fn set_stack_count(&self, value: u32) {
        self.value.set_bits(3, 29, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KstackCount>() == 0x4);
    assert!(core::mem::offset_of!(KstackCount, value) == 0x0);
};

/// `_KPROCESS::SecureState` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KprocessSecureStateView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KprocessSecureState {
    pub secure_handle: Field<u64>,
}

/// Vista 1 de `_KPROCESS::SecureState` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KprocessSecureStateView1 {
    pub flags: KprocessSecureStateFlags,
}

impl core::ops::Deref for KprocessSecureState {
    type Target = KprocessSecureStateView1;
    #[inline(always)]
    fn deref(&self) -> &KprocessSecureStateView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KprocessSecureStateView1>() }
    }
}

unsafe impl NtStruct for KprocessSecureState {}

const _: () = {
    assert!(core::mem::size_of::<KprocessSecureState>() == 0x8);
    assert!(core::mem::offset_of!(KprocessSecureState, secure_handle) == 0x0);
    assert!(core::mem::size_of::<KprocessSecureStateView1>() == 0x8);
    assert!(core::mem::align_of::<KprocessSecureStateView1>() == core::mem::align_of::<KprocessSecureState>());
    assert!(core::mem::offset_of!(KprocessSecureStateView1, flags) == 0x0);
};

/// `_KPROCESS::SecureState::Flags` (0x8 bytes).
#[repr(C)]
pub struct KprocessSecureStateFlags {
    pub bitfield_0: Field<u64>,
}

unsafe impl NtStruct for KprocessSecureStateFlags {}

impl KprocessSecureStateFlags {
    /// `SecureProcess`: bits 0..=0 de `bitfield_0`.
    pub const SECURE_PROCESS_SHIFT: u32 = 0;
    pub const SECURE_PROCESS_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn secure_process(&self) -> u64 {
        self.bitfield_0.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_secure_process(&self, value: u64) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `Unused`: bits 1..=1 de `bitfield_0`.
    pub const UNUSED_SHIFT: u32 = 1;
    pub const UNUSED_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn unused(&self) -> u64 {
        self.bitfield_0.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_unused(&self, value: u64) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KprocessSecureStateFlags>() == 0x8);
    assert!(core::mem::offset_of!(KprocessSecureStateFlags, bitfield_0) == 0x0);
};

/// `_KINTERRUPT` (0x120 bytes).
#[repr(C)]
pub struct Kinterrupt {
    pub type_: Field<i16>,
    pub size: Field<i16>,
    _pad_4: Reserved<0x4>,
    pub interrupt_list_entry: ListEntry,
    /// -> `fn`
    pub service_routine: Field<u64>,
    /// -> `fn`
    pub message_service_routine: Field<u64>,
    pub message_index: Field<u32>,
    _pad_2c: Reserved<0x4>,
    /// -> `void`
    pub service_context: Field<u64>,
    pub spin_lock: Field<u64>,
    pub tick_count: Field<u32>,
    _pad_44: Reserved<0x4>,
    /// -> `u64`
    pub actual_lock: Field<u64>,
    /// -> `fn`
    pub dispatch_address: Field<u64>,
    pub vector: Field<u32>,
    pub irql: Field<u8>,
    pub synchronize_irql: Field<u8>,
    pub floating_save: Field<u8>,
    pub connected: Field<u8>,
    pub number: Field<u32>,
    pub share_vector: Field<u8>,
    pub emulate_active_both: Field<u8>,
    pub active_count: Field<u16>,
    pub internal_state: Field<i32>,
    pub mode: Field<KinterruptMode>,
    pub polarity: Field<KinterruptPolarity>,
    pub service_count: Field<u32>,
    pub dispatch_count: Field<u32>,
    _pad_7c: Reserved<0x4>,
    /// -> `_KEVENT`
    pub passive_event: Field<u64>,
    /// -> `_KTRAP_FRAME`
    pub trap_frame: Field<u64>,
    /// -> `void`
    pub disconnect_data: Field<u64>,
    /// -> `_KTHREAD`
    pub service_thread: Field<u64>,
    /// -> `_INTERRUPT_CONNECTION_DATA`
    pub connection_data: Field<u64>,
    /// -> `void`
    pub int_track_entry: Field<u64>,
    pub isr_dpc_stats: Isrdpcstats,
    /// -> `void`
    pub redirect_object: Field<u64>,
    /// -> `void`
    pub physical_device_object: Field<u64>,
}

unsafe impl NtStruct for Kinterrupt {}

const _: () = {
    assert!(core::mem::size_of::<Kinterrupt>() == 0x120);
    assert!(core::mem::offset_of!(Kinterrupt, type_) == 0x0);
    assert!(core::mem::offset_of!(Kinterrupt, size) == 0x2);
    assert!(core::mem::offset_of!(Kinterrupt, interrupt_list_entry) == 0x8);
    assert!(core::mem::offset_of!(Kinterrupt, service_routine) == 0x18);
    assert!(core::mem::offset_of!(Kinterrupt, message_service_routine) == 0x20);
    assert!(core::mem::offset_of!(Kinterrupt, message_index) == 0x28);
    assert!(core::mem::offset_of!(Kinterrupt, service_context) == 0x30);
    assert!(core::mem::offset_of!(Kinterrupt, spin_lock) == 0x38);
    assert!(core::mem::offset_of!(Kinterrupt, tick_count) == 0x40);
    assert!(core::mem::offset_of!(Kinterrupt, actual_lock) == 0x48);
    assert!(core::mem::offset_of!(Kinterrupt, dispatch_address) == 0x50);
    assert!(core::mem::offset_of!(Kinterrupt, vector) == 0x58);
    assert!(core::mem::offset_of!(Kinterrupt, irql) == 0x5c);
    assert!(core::mem::offset_of!(Kinterrupt, synchronize_irql) == 0x5d);
    assert!(core::mem::offset_of!(Kinterrupt, floating_save) == 0x5e);
    assert!(core::mem::offset_of!(Kinterrupt, connected) == 0x5f);
    assert!(core::mem::offset_of!(Kinterrupt, number) == 0x60);
    assert!(core::mem::offset_of!(Kinterrupt, share_vector) == 0x64);
    assert!(core::mem::offset_of!(Kinterrupt, emulate_active_both) == 0x65);
    assert!(core::mem::offset_of!(Kinterrupt, active_count) == 0x66);
    assert!(core::mem::offset_of!(Kinterrupt, internal_state) == 0x68);
    assert!(core::mem::offset_of!(Kinterrupt, mode) == 0x6c);
    assert!(core::mem::offset_of!(Kinterrupt, polarity) == 0x70);
    assert!(core::mem::offset_of!(Kinterrupt, service_count) == 0x74);
    assert!(core::mem::offset_of!(Kinterrupt, dispatch_count) == 0x78);
    assert!(core::mem::offset_of!(Kinterrupt, passive_event) == 0x80);
    assert!(core::mem::offset_of!(Kinterrupt, trap_frame) == 0x88);
    assert!(core::mem::offset_of!(Kinterrupt, disconnect_data) == 0x90);
    assert!(core::mem::offset_of!(Kinterrupt, service_thread) == 0x98);
    assert!(core::mem::offset_of!(Kinterrupt, connection_data) == 0xa0);
    assert!(core::mem::offset_of!(Kinterrupt, int_track_entry) == 0xa8);
    assert!(core::mem::offset_of!(Kinterrupt, isr_dpc_stats) == 0xb0);
    assert!(core::mem::offset_of!(Kinterrupt, redirect_object) == 0x110);
    assert!(core::mem::offset_of!(Kinterrupt, physical_device_object) == 0x118);
};

/// `_KINTERRUPT_MODE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct KinterruptMode(pub i32);

impl KinterruptMode {
    pub const LEVEL_SENSITIVE: Self = Self(0);
    pub const LATCHED: Self = Self(1);
}

/// `_KINTERRUPT_POLARITY`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct KinterruptPolarity(pub i32);

impl KinterruptPolarity {
    pub const INTERRUPT_POLARITY_UNKNOWN: Self = Self(0);
    pub const INTERRUPT_ACTIVE_HIGH: Self = Self(1);
    pub const INTERRUPT_RISING_EDGE: Self = Self(1);
    pub const INTERRUPT_ACTIVE_LOW: Self = Self(2);
    pub const INTERRUPT_FALLING_EDGE: Self = Self(2);
    pub const INTERRUPT_ACTIVE_BOTH: Self = Self(3);
    pub const INTERRUPT_ACTIVE_BOTH_TRIGGER_LOW: Self = Self(3);
    pub const INTERRUPT_ACTIVE_BOTH_TRIGGER_HIGH: Self = Self(4);
}

/// `_ISRDPCSTATS` (0x60 bytes).
#[repr(C)]
pub struct Isrdpcstats {
    pub isr_time: Field<u64>,
    pub isr_time_start: Field<u64>,
    pub isr_count: Field<u64>,
    pub dpc_time: Field<u64>,
    pub dpc_time_start: Field<u64>,
    pub dpc_count: Field<u64>,
    pub isr_active: Field<u8>,
    pub reserved: [Field<u8>; 7],
    pub dpc_watchdog: IsrdpcstatsSequence,
}

unsafe impl NtStruct for Isrdpcstats {}

const _: () = {
    assert!(core::mem::size_of::<Isrdpcstats>() == 0x60);
    assert!(core::mem::offset_of!(Isrdpcstats, isr_time) == 0x0);
    assert!(core::mem::offset_of!(Isrdpcstats, isr_time_start) == 0x8);
    assert!(core::mem::offset_of!(Isrdpcstats, isr_count) == 0x10);
    assert!(core::mem::offset_of!(Isrdpcstats, dpc_time) == 0x18);
    assert!(core::mem::offset_of!(Isrdpcstats, dpc_time_start) == 0x20);
    assert!(core::mem::offset_of!(Isrdpcstats, dpc_count) == 0x28);
    assert!(core::mem::offset_of!(Isrdpcstats, isr_active) == 0x30);
    assert!(core::mem::offset_of!(Isrdpcstats, reserved) == 0x31);
    assert!(core::mem::offset_of!(Isrdpcstats, dpc_watchdog) == 0x38);
};

/// `_ISRDPCSTATS_SEQUENCE` (0x28 bytes).
#[repr(C)]
pub struct IsrdpcstatsSequence {
    pub sequence_number: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub isr_time: Field<u64>,
    pub isr_count: Field<u64>,
    pub dpc_time: Field<u64>,
    pub dpc_count: Field<u64>,
}

unsafe impl NtStruct for IsrdpcstatsSequence {}

const _: () = {
    assert!(core::mem::size_of::<IsrdpcstatsSequence>() == 0x28);
    assert!(core::mem::offset_of!(IsrdpcstatsSequence, sequence_number) == 0x0);
    assert!(core::mem::offset_of!(IsrdpcstatsSequence, isr_time) == 0x8);
    assert!(core::mem::offset_of!(IsrdpcstatsSequence, isr_count) == 0x10);
    assert!(core::mem::offset_of!(IsrdpcstatsSequence, dpc_time) == 0x18);
    assert!(core::mem::offset_of!(IsrdpcstatsSequence, dpc_count) == 0x20);
};

/// `_KPCR` (0xb080 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KpcrView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Kpcr {
    pub nt_tib: NtTib,
    /// -> `_KIDTENTRY64`
    pub idt_base: Field<u64>,
    pub unused: [Field<u64>; 2],
    pub irql: Field<u8>,
    pub second_level_cache_associativity: Field<u8>,
    pub obsolete_number: Field<u8>,
    pub fill0: Field<u8>,
    pub unused0: [Field<u32>; 3],
    pub major_version: Field<u16>,
    pub minor_version: Field<u16>,
    pub stall_scale_factor: Field<u32>,
    /// -> `void`
    pub unused1: [Field<u64>; 3],
    pub kernel_reserved: [Field<u32>; 15],
    pub second_level_cache_size: Field<u32>,
    pub hal_reserved: [Field<u32>; 16],
    pub unused2: Field<u32>,
    _pad_104: Reserved<0x4>,
    /// -> `void`
    pub kd_version_block: Field<u64>,
    /// -> `void`
    pub unused3: Field<u64>,
    pub pcr_align1: [Field<u32>; 24],
    _pad_178: Reserved<0x8>,
    pub prcb: Kprcb,
}

/// Vista 1 de `_KPCR` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KpcrView1 {
    /// -> `_KGDTENTRY64`
    pub gdt_base: Field<u64>,
    /// -> `_KTSS64`
    pub tss_base: Field<u64>,
    pub user_rsp: Field<u64>,
    /// -> `_KPCR`
    pub self_: Field<u64>,
    /// -> `_KPRCB`
    pub current_prcb: Field<u64>,
    /// -> `_KSPIN_LOCK_QUEUE`
    pub lock_array: Field<u64>,
    /// -> `void`
    pub used_self: Field<u64>,
    _pad_38: Reserved<0xb048>,
}

impl core::ops::Deref for Kpcr {
    type Target = KpcrView1;
    #[inline(always)]
    fn deref(&self) -> &KpcrView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KpcrView1>() }
    }
}

unsafe impl NtStruct for Kpcr {}

const _: () = {
    assert!(core::mem::size_of::<Kpcr>() == 0xb080);
    assert!(core::mem::offset_of!(Kpcr, nt_tib) == 0x0);
    assert!(core::mem::offset_of!(Kpcr, idt_base) == 0x38);
    assert!(core::mem::offset_of!(Kpcr, unused) == 0x40);
    assert!(core::mem::offset_of!(Kpcr, irql) == 0x50);
    assert!(core::mem::offset_of!(Kpcr, second_level_cache_associativity) == 0x51);
    assert!(core::mem::offset_of!(Kpcr, obsolete_number) == 0x52);
    assert!(core::mem::offset_of!(Kpcr, fill0) == 0x53);
    assert!(core::mem::offset_of!(Kpcr, unused0) == 0x54);
    assert!(core::mem::offset_of!(Kpcr, major_version) == 0x60);
    assert!(core::mem::offset_of!(Kpcr, minor_version) == 0x62);
    assert!(core::mem::offset_of!(Kpcr, stall_scale_factor) == 0x64);
    assert!(core::mem::offset_of!(Kpcr, unused1) == 0x68);
    assert!(core::mem::offset_of!(Kpcr, kernel_reserved) == 0x80);
    assert!(core::mem::offset_of!(Kpcr, second_level_cache_size) == 0xbc);
    assert!(core::mem::offset_of!(Kpcr, hal_reserved) == 0xc0);
    assert!(core::mem::offset_of!(Kpcr, unused2) == 0x100);
    assert!(core::mem::offset_of!(Kpcr, kd_version_block) == 0x108);
    assert!(core::mem::offset_of!(Kpcr, unused3) == 0x110);
    assert!(core::mem::offset_of!(Kpcr, pcr_align1) == 0x118);
    assert!(core::mem::offset_of!(Kpcr, prcb) == 0x180);
    assert!(core::mem::size_of::<KpcrView1>() == 0xb080);
    assert!(core::mem::align_of::<KpcrView1>() == core::mem::align_of::<Kpcr>());
    assert!(core::mem::offset_of!(KpcrView1, gdt_base) == 0x0);
    assert!(core::mem::offset_of!(KpcrView1, tss_base) == 0x8);
    assert!(core::mem::offset_of!(KpcrView1, user_rsp) == 0x10);
    assert!(core::mem::offset_of!(KpcrView1, self_) == 0x18);
    assert!(core::mem::offset_of!(KpcrView1, current_prcb) == 0x20);
    assert!(core::mem::offset_of!(KpcrView1, lock_array) == 0x28);
    assert!(core::mem::offset_of!(KpcrView1, used_self) == 0x30);
};

/// `_KPRCB` (0xaf00 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KprcbView1`..`KprcbView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Kprcb {
    pub mx_csr: Field<u32>,
    pub legacy_number: Field<u8>,
    pub reserved_must_be_zero: Field<u8>,
    pub interrupt_request: Field<u8>,
    pub idle_halt: Field<u8>,
    /// -> `_KTHREAD`
    pub current_thread: Field<u64>,
    /// -> `_KTHREAD`
    pub next_thread: Field<u64>,
    /// -> `_KTHREAD`
    pub idle_thread: Field<u64>,
    pub nesting_level: Field<u8>,
    pub clock_owner: Field<u8>,
    pub pending_tick_flags: Field<u8>,
    pub idle_state: Field<u8>,
    pub number: Field<u32>,
    pub rsp_base: Field<u64>,
    pub prcb_lock: Field<u64>,
    /// -> `i8`
    pub priority_state: Field<u64>,
    pub cpu_type: Field<i8>,
    pub cpu_id: Field<i8>,
    pub cpu_step: Field<u16>,
    pub m_hz: Field<u32>,
    pub hal_reserved: [Field<u64>; 8],
    pub minor_version: Field<u16>,
    pub major_version: Field<u16>,
    pub build_type: Field<u8>,
    pub cpu_vendor: Field<u8>,
    pub legacy_cores_per_physical_processor: Field<u8>,
    pub legacy_logical_processors_per_core: Field<u8>,
    pub tsc_frequency: Field<u64>,
    pub cores_per_physical_processor: Field<u32>,
    pub logical_processors_per_core: Field<u32>,
    pub prcb_pad04: [Field<u64>; 4],
    /// -> `_KNODE`
    pub parent_node: Field<u64>,
    pub group_set_member: Field<u64>,
    pub group: Field<u8>,
    pub group_index: Field<u8>,
    pub prcb_pad05: [Field<u8>; 2],
    pub initial_apic_id: Field<u32>,
    pub scb_offset: Field<u32>,
    pub apic_mask: Field<u32>,
    /// -> `void`
    pub acpi_reserved: Field<u64>,
    pub c_flush_size: Field<u32>,
    pub prcb_flags: Kprcbflag,
    pub prcb_pad11: [Field<u64>; 2],
    pub processor_state: KprocessorState,
    /// -> `_XSAVE_AREA_HEADER`
    pub extended_supervisor_state: Field<u64>,
    pub processor_signature: Field<u32>,
    pub processor_flags: Field<u32>,
    pub bpb_retpoline_exit_spec_ctrl: Field<u16>,
    pub bpb_trapped_retpoline_exit_spec_ctrl: Field<u16>,
    pub bpb_trapped_bpb_state: Field<u16>,
    pub bpb_retpoline_state: Field<u8>,
    pub prcb_pad12b: Field<u8>,
    pub trapped_security_domain: Field<u64>,
    pub bpb_state: Field<u16>,
    pub bpb_features: Field<u8>,
    pub prcb_pad12e: [Field<u8>; 1],
    pub bpb_current_spec_ctrl: Field<u16>,
    pub bpb_kernel_spec_ctrl: Field<u16>,
    pub bpb_nmi_spec_ctrl: Field<u16>,
    pub bpb_user_spec_ctrl: Field<u16>,
    pub pair_register: Field<i16>,
    pub prcb_pad12d: [Field<u8>; 2],
    pub lock_queue: [KspinLockQueue; 17],
    pub pp_lookaside_list: [PpLookasideList; 16],
    pub pp_nx_paged_lookaside_list: [GeneralLookasidePool; 32],
    pub ppn_paged_lookaside_list: [GeneralLookasidePool; 32],
    pub pp_paged_lookaside_list: [GeneralLookasidePool; 32],
    pub msr_ia32_tsx_ctrl: Field<u64>,
    pub deferred_ready_list_head: SingleListEntry,
    pub mm_page_fault_count: Field<i32>,
    pub mm_copy_on_write_count: Field<i32>,
    pub mm_transition_count: Field<i32>,
    pub mm_demand_zero_count: Field<i32>,
    pub mm_page_read_count: Field<i32>,
    pub mm_page_read_io_count: Field<i32>,
    pub mm_dirty_pages_write_count: Field<i32>,
    pub mm_dirty_write_io_count: Field<i32>,
    pub mm_mapped_pages_write_count: Field<i32>,
    pub mm_mapped_write_io_count: Field<i32>,
    pub ke_system_calls: Field<u32>,
    pub ke_context_switches: Field<u32>,
    pub prcb_pad40: Field<u32>,
    pub cc_fast_read_no_wait: Field<u32>,
    pub cc_fast_read_wait: Field<u32>,
    pub cc_fast_read_not_possible: Field<u32>,
    pub cc_copy_read_no_wait: Field<u32>,
    pub cc_copy_read_wait: Field<u32>,
    pub cc_copy_read_no_wait_miss: Field<u32>,
    pub io_read_operation_count: Field<i32>,
    pub io_write_operation_count: Field<i32>,
    pub io_other_operation_count: Field<i32>,
    pub io_read_transfer_count: LargeInteger,
    pub io_write_transfer_count: LargeInteger,
    pub io_other_transfer_count: LargeInteger,
    pub packet_barrier: Field<i32>,
    pub target_count: Field<i32>,
    pub ipi_frozen: Field<u32>,
    pub prcb_pad30: Field<u32>,
    /// -> `void`
    pub isr_dpc_stats: Field<u64>,
    pub device_interrupts: Field<u32>,
    pub lookaside_irp_float: Field<i32>,
    pub interrupt_last_count: Field<u32>,
    pub interrupt_rate: Field<u32>,
    pub prcb_pad31: Field<u64>,
    /// -> `_KPRCB`
    pub pair_prcb: Field<u64>,
    pub static_affinity: KstaticAffinityBlock,
    pub prcb_pad35: [Field<u64>; 5],
    pub interrupt_object_pool: SlistHeader,
    /// -> `_RTL_HASH_TABLE`
    pub dpc_runtime_history_hash_table: Field<u64>,
    /// -> `_KDPC`
    pub dpc_runtime_history_hash_table_cleanup_dpc: Field<u64>,
    /// -> `fn`
    pub current_dpc_routine: Field<u64>,
    pub current_dpc_runtime_history_cached: Field<u64>,
    pub current_dpc_start_time: Field<u64>,
    pub prcb_pad41: [Field<u64>; 1],
    pub dpc_data: [KdpcData; 2],
    /// -> `void`
    pub dpc_stack: Field<u64>,
    pub maximum_dpc_queue_depth: Field<i32>,
    pub dpc_request_rate: Field<u32>,
    pub minimum_dpc_rate: Field<u32>,
    pub dpc_last_count: Field<u32>,
    pub thread_dpc_enable: Field<u8>,
    pub quantum_end: Field<u8>,
    pub dpc_routine_active: Field<u8>,
    pub idle_schedule: Field<u8>,
    pub dpc_request_summary: Field<i32>,
    pub prcb_pad93: Field<u32>,
    pub last_tick: Field<u32>,
    pub clock_interrupts: Field<u32>,
    pub ready_scan_tick: Field<u32>,
    /// -> `void`
    pub interrupt_object: [Field<u64>; 256],
    pub timer_table: KtimerTable,
    pub prcb_pad92: [Field<u32>; 10],
    pub dpc_gate: Kgate,
    /// -> `void`
    pub prcb_pad52: Field<u64>,
    pub call_dpc: Kdpc,
    pub clock_keep_alive: Field<i32>,
    pub prcb_pad60: [Field<u8>; 2],
    pub nmi_active: Field<u8>,
    pub mce_active: Field<u8>,
    pub dpc_watchdog_period: Field<i32>,
    pub dpc_watchdog_count: Field<i32>,
    pub ke_spin_lock_ordering: Field<i32>,
    pub dpc_watchdog_profile_cumulative_dpc_threshold: Field<u32>,
    /// -> `void`
    pub cached_ptes: Field<u64>,
    pub wait_list_head: ListEntry,
    pub wait_lock: Field<u64>,
    pub ready_summary: Field<u32>,
    pub affinitized_selection_mask: Field<i32>,
    pub queue_index: Field<u32>,
    pub prcb_pad75: [Field<u32>; 2],
    pub dpc_watchdog_sequence_number: Field<u32>,
    pub timer_expiration_dpc: Kdpc,
    pub scb_queue: RtlRbTree,
    pub dispatcher_ready_list_head: [ListEntry; 32],
    pub interrupt_count: Field<u32>,
    pub kernel_time: Field<u32>,
    pub user_time: Field<u32>,
    pub dpc_time: Field<u32>,
    pub interrupt_time: Field<u32>,
    pub adjust_dpc_threshold: Field<u32>,
    pub debugger_saved_irql: Field<u8>,
    pub group_scheduling_over_quota: Field<u8>,
    pub deep_sleep: Field<u8>,
    pub prcb_pad80: Field<u8>,
    pub dpc_time_count: Field<u32>,
    pub dpc_time_limit: Field<u32>,
    pub periodic_count: Field<u32>,
    pub periodic_bias: Field<u32>,
    pub available_time: Field<u32>,
    pub ke_exception_dispatch_count: Field<u32>,
    pub ready_thread_count: Field<u32>,
    pub ready_queue_expected_run_time: Field<u64>,
    pub start_cycles: Field<u64>,
    pub tagged_cycles_start: Field<u64>,
    pub tagged_cycles: [Field<u64>; 3],
    pub affinitized_cycles: Field<u64>,
    pub important_cycles: Field<u64>,
    pub unimportant_cycles: Field<u64>,
    pub dpc_watchdog_profile_single_dpc_threshold: Field<u32>,
    pub mm_spin_lock_ordering: Field<i32>,
    /// -> `void`
    pub cached_stack: Field<u64>,
    pub page_color: Field<u32>,
    pub node_color: Field<u32>,
    pub node_shifted_color: Field<u32>,
    pub secondary_color_mask: Field<u32>,
    pub prcb_pad81: [Field<u8>; 6],
    pub exception_stack_active: Field<u8>,
    pub tb_flush_list_active: Field<u8>,
    /// -> `void`
    pub exception_stack: Field<u64>,
    pub prcb_pad82: [Field<u64>; 1],
    pub cycle_time: Field<u64>,
    pub cycles: [[Field<u64>; 2]; 4],
    pub cc_fast_mdl_read_no_wait: Field<u32>,
    pub cc_fast_mdl_read_wait: Field<u32>,
    pub cc_fast_mdl_read_not_possible: Field<u32>,
    pub cc_map_data_no_wait: Field<u32>,
    pub cc_map_data_wait: Field<u32>,
    pub cc_pin_mapped_data_count: Field<u32>,
    pub cc_pin_read_no_wait: Field<u32>,
    pub cc_pin_read_wait: Field<u32>,
    pub cc_mdl_read_no_wait: Field<u32>,
    pub cc_mdl_read_wait: Field<u32>,
    pub cc_lazy_write_hot_spots: Field<u32>,
    pub cc_lazy_write_ios: Field<u32>,
    pub cc_lazy_write_pages: Field<u32>,
    pub cc_data_flushes: Field<u32>,
    pub cc_data_pages: Field<u32>,
    pub cc_lost_delayed_writes: Field<u32>,
    pub cc_fast_read_resource_miss: Field<u32>,
    pub cc_copy_read_wait_miss: Field<u32>,
    pub cc_fast_mdl_read_resource_miss: Field<u32>,
    pub cc_map_data_no_wait_miss: Field<u32>,
    pub cc_map_data_wait_miss: Field<u32>,
    pub cc_pin_read_no_wait_miss: Field<u32>,
    pub cc_pin_read_wait_miss: Field<u32>,
    pub cc_mdl_read_no_wait_miss: Field<u32>,
    pub cc_mdl_read_wait_miss: Field<u32>,
    pub cc_read_ahead_ios: Field<u32>,
    pub mm_cache_transition_count: Field<i32>,
    pub mm_cache_read_count: Field<i32>,
    pub mm_cache_io_count: Field<i32>,
    pub prcb_pad91: Field<u32>,
    /// -> `void`
    pub mm_internal: Field<u64>,
    pub power_state: ProcessorPowerState,
    /// -> `void`
    pub hyper_pte: Field<u64>,
    pub scb_list: ListEntry,
    pub force_idle_dpc: Kdpc,
    pub dpc_watchdog_dpc: Kdpc,
    pub dpc_watchdog_timer: Ktimer,
    pub cache: [CacheDescriptor; 5],
    pub cache_count: Field<u32>,
    pub cached_commit: Field<u32>,
    pub cached_resident_available: Field<u32>,
    /// -> `void`
    pub whea_info: Field<u64>,
    /// -> `void`
    pub etw_support: Field<u64>,
    /// -> `void`
    pub ex_sa_page_array: Field<u64>,
    pub ke_alignment_fixup_count: Field<u32>,
    pub prcb_pad95: Field<u32>,
    pub hypercall_page_list: SlistHeader,
    /// -> `u64`
    pub statistics_page: Field<u64>,
    pub generation_target: Field<u64>,
    pub prcb_pad85: [Field<u64>; 4],
    /// -> `void`
    pub hypercall_cached_pages: Field<u64>,
    /// -> `void`
    pub virtual_apic_assist: Field<u64>,
    pub package_processor_set: KaffinityEx,
    pub package_id: Field<u32>,
    pub prcb_pad86: Field<u32>,
    pub shared_ready_queue_mask: Field<u64>,
    /// -> `_KSHARED_READY_QUEUE`
    pub shared_ready_queue: Field<u64>,
    pub shared_queue_scan_owner: Field<u32>,
    pub scan_sibling_index: Field<u32>,
    pub core_processor_set: Field<u64>,
    pub scan_sibling_mask: Field<u64>,
    pub llc_mask: Field<u64>,
    pub cache_processor_mask: [Field<u64>; 5],
    /// -> `_PROCESSOR_PROFILE_CONTROL_AREA`
    pub processor_profile_control_area: Field<u64>,
    /// -> `void`
    pub profile_event_index_address: Field<u64>,
    /// -> `void*`
    pub dpc_watchdog_profile: Field<u64>,
    /// -> `void*`
    pub dpc_watchdog_profile_current_empty_capture: Field<u64>,
    /// -> `void`
    pub scheduler_assist: Field<u64>,
    pub synch_counters: SynchCounters,
    pub prcb_pad94: Field<u64>,
    pub fs_counters: FilesystemDiskCounters,
    pub vendor_string: [Field<u8>; 13],
    pub prcb_pad100: [Field<u8>; 3],
    pub feature_bits: Field<u64>,
    pub update_signature: LargeInteger,
    pub pte_bit_cache: Field<u64>,
    pub pte_bit_offset: Field<u32>,
    pub prcb_pad105: Field<u32>,
    /// -> `_CONTEXT`
    pub context: Field<u64>,
    pub context_flags_init: Field<u32>,
    pub prcb_pad115: Field<u32>,
    /// -> `_XSAVE_AREA`
    pub extended_state: Field<u64>,
    /// -> `void`
    pub isr_stack: Field<u64>,
    pub entropy_timing_state: KentropyTimingState,
    pub prcb_pad110: Field<u64>,
    pub stibp_pairing_trace: KprcbStibpPairingTrace,
    pub ab_self_io_boosts_list: SingleListEntry,
    pub ab_propagate_boosts_list: SingleListEntry,
    pub ab_dpc: Kdpc,
    pub io_irp_stack_profiler_current: IopIrpStackProfiler,
    pub io_irp_stack_profiler_previous: IopIrpStackProfiler,
    pub secure_fault: KsecureFaultInformation,
    pub prcb_pad120: Field<u64>,
    pub local_shared_ready_queue: KsharedReadyQueue,
    pub prcb_pad125: [Field<u64>; 2],
    pub timer_expiration_trace_count: Field<u32>,
    pub prcb_pad127: Field<u32>,
    pub timer_expiration_trace: [KtimerExpirationTrace; 16],
    pub prcb_pad128: [Field<u64>; 7],
    /// -> `_REQUEST_MAILBOX`
    pub mailbox: Field<u64>,
    pub prcb_pad130: [Field<u64>; 7],
    pub mcheck_context: [MachineCheckContext; 2],
    pub prcb_pad134: [Field<u64>; 4],
    pub selfmap_lock_handle: [KlockQueueHandle; 4],
    pub prcb_pad134a: [Field<u64>; 4],
    pub prcb_pad138: [Field<u8>; 128],
    pub prcb_pad138a: [Field<u8>; 64],
    pub kernel_directory_table_base: Field<u64>,
    pub rsp_base_shadow: Field<u64>,
    pub user_rsp_shadow: Field<u64>,
    pub shadow_flags: Field<u32>,
    pub prcb_pad138b: Field<u32>,
    pub prcb_pad138c: Field<u64>,
    pub prcb_pad138d: Field<u16>,
    pub verw_selector: Field<u16>,
    pub dbg_mce_nesting_level: Field<u32>,
    pub dbg_mce_flags: Field<u32>,
    pub prcb_pad139b: Field<u32>,
    pub prcb_pad140: [Field<u64>; 505],
    pub prcb_pad140a: [Field<u64>; 8],
    pub prcb_pad141: [Field<u64>; 504],
    pub prcb_pad141a: [Field<u8>; 64],
    pub request_mailbox: [RequestMailbox; 1],
}

/// Vista 1 de `_KPRCB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KprcbView1 {
    _pad_0: Reserved<0x42>,
    pub cpu_stepping: Field<u8>,
    pub cpu_model: Field<u8>,
    _pad_44: Reserved<0x68c>,
    pub prcb_pad12a: Field<u64>,
    pub prcb_pad12c: [Field<u64>; 3],
    _pad_6f0: Reserved<0x2a3c>,
    pub dpc_request_slot: [Field<i16>; 2],
    _pad_3130: Reserved<0x4ab6>,
    pub combined_nmi_mce_active: Field<u16>,
    _pad_7be8: Reserved<0x3318>,
}

/// Vista 2 de `_KPRCB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KprcbView2 {
    _align: [u64; 0],
    _pad_0: Reserved<0x312c>,
    pub normal_dpc_state: Field<i16>,
    pub thread_dpc_state: Field<i16>,
    _pad_3130: Reserved<0x7dd0>,
}

impl core::ops::Deref for Kprcb {
    type Target = KprcbView1;
    #[inline(always)]
    fn deref(&self) -> &KprcbView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KprcbView1>() }
    }
}

impl core::ops::Deref for KprcbView1 {
    type Target = KprcbView2;
    #[inline(always)]
    fn deref(&self) -> &KprcbView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KprcbView2>() }
    }
}

unsafe impl NtStruct for Kprcb {}

impl Kprcb {
    /// `PendingTick`: bits 0..=0 de `pending_tick_flags`.
    pub const PENDING_TICK_SHIFT: u32 = 0;
    pub const PENDING_TICK_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn pending_tick(&self) -> u8 {
        self.pending_tick_flags.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_pending_tick(&self, value: u8) {
        self.pending_tick_flags.set_bits(0, 1, value as u64)
    }
    /// `PendingBackupTick`: bits 1..=1 de `pending_tick_flags`.
    pub const PENDING_BACKUP_TICK_SHIFT: u32 = 1;
    pub const PENDING_BACKUP_TICK_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn pending_backup_tick(&self) -> u8 {
        self.pending_tick_flags.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_pending_backup_tick(&self, value: u8) {
        self.pending_tick_flags.set_bits(1, 1, value as u64)
    }
    /// `BpbTrappedCpuIdle`: bits 0..=0 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_CPU_IDLE_SHIFT: u32 = 0;
    pub const BPB_TRAPPED_CPU_IDLE_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn bpb_trapped_cpu_idle(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_cpu_idle(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(0, 1, value as u64)
    }
    /// `BpbTrappedFlushRsbOnTrap`: bits 1..=1 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_FLUSH_RSB_ON_TRAP_SHIFT: u32 = 1;
    pub const BPB_TRAPPED_FLUSH_RSB_ON_TRAP_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn bpb_trapped_flush_rsb_on_trap(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_flush_rsb_on_trap(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(1, 1, value as u64)
    }
    /// `BpbTrappedIbpbOnReturn`: bits 2..=2 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_IBPB_ON_RETURN_SHIFT: u32 = 2;
    pub const BPB_TRAPPED_IBPB_ON_RETURN_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn bpb_trapped_ibpb_on_return(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_ibpb_on_return(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(2, 1, value as u64)
    }
    /// `BpbTrappedIbpbOnTrap`: bits 3..=3 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_IBPB_ON_TRAP_SHIFT: u32 = 3;
    pub const BPB_TRAPPED_IBPB_ON_TRAP_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn bpb_trapped_ibpb_on_trap(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_ibpb_on_trap(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(3, 1, value as u64)
    }
    /// `BpbTrappedIbpbOnRetpolineExit`: bits 4..=4 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_IBPB_ON_RETPOLINE_EXIT_SHIFT: u32 = 4;
    pub const BPB_TRAPPED_IBPB_ON_RETPOLINE_EXIT_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn bpb_trapped_ibpb_on_retpoline_exit(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_ibpb_on_retpoline_exit(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(4, 1, value as u64)
    }
    /// `BpbTrappedFlushRsbOnReturn`: bits 5..=5 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_FLUSH_RSB_ON_RETURN_SHIFT: u32 = 5;
    pub const BPB_TRAPPED_FLUSH_RSB_ON_RETURN_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn bpb_trapped_flush_rsb_on_return(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_flush_rsb_on_return(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(5, 1, value as u64)
    }
    /// `BpbTrappedFlushRsbOnRetpolineExit`: bits 6..=6 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_FLUSH_RSB_ON_RETPOLINE_EXIT_SHIFT: u32 = 6;
    pub const BPB_TRAPPED_FLUSH_RSB_ON_RETPOLINE_EXIT_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn bpb_trapped_flush_rsb_on_retpoline_exit(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_flush_rsb_on_retpoline_exit(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(6, 1, value as u64)
    }
    /// `BpbTrappedBpbStateReserved`: bits 7..=7 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_BPB_STATE_RESERVED_SHIFT: u32 = 7;
    pub const BPB_TRAPPED_BPB_STATE_RESERVED_MASK: u16 = 0x80;
    #[inline(always)]
    pub fn bpb_trapped_bpb_state_reserved(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(7, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_bpb_state_reserved(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(7, 1, value as u64)
    }
    /// `BpbTrappedBpbStateReserved2`: bits 8..=15 de `bpb_trapped_bpb_state`.
    pub const BPB_TRAPPED_BPB_STATE_RESERVED2_SHIFT: u32 = 8;
    pub const BPB_TRAPPED_BPB_STATE_RESERVED2_MASK: u16 = 0xff00;
    #[inline(always)]
    pub fn bpb_trapped_bpb_state_reserved2(&self) -> u16 {
        self.bpb_trapped_bpb_state.bits(8, 8) as u16
    }
    #[inline(always)]
    pub fn set_bpb_trapped_bpb_state_reserved2(&self, value: u16) {
        self.bpb_trapped_bpb_state.set_bits(8, 8, value as u64)
    }
    /// `BpbRunningNonRetpolineCode`: bits 0..=0 de `bpb_retpoline_state`.
    pub const BPB_RUNNING_NON_RETPOLINE_CODE_SHIFT: u32 = 0;
    pub const BPB_RUNNING_NON_RETPOLINE_CODE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn bpb_running_non_retpoline_code(&self) -> u8 {
        self.bpb_retpoline_state.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_running_non_retpoline_code(&self, value: u8) {
        self.bpb_retpoline_state.set_bits(0, 1, value as u64)
    }
    /// `BpbIndirectCallsSafe`: bits 1..=1 de `bpb_retpoline_state`.
    pub const BPB_INDIRECT_CALLS_SAFE_SHIFT: u32 = 1;
    pub const BPB_INDIRECT_CALLS_SAFE_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn bpb_indirect_calls_safe(&self) -> u8 {
        self.bpb_retpoline_state.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_indirect_calls_safe(&self, value: u8) {
        self.bpb_retpoline_state.set_bits(1, 1, value as u64)
    }
    /// `BpbRetpolineEnabled`: bits 2..=2 de `bpb_retpoline_state`.
    pub const BPB_RETPOLINE_ENABLED_SHIFT: u32 = 2;
    pub const BPB_RETPOLINE_ENABLED_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn bpb_retpoline_enabled(&self) -> u8 {
        self.bpb_retpoline_state.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_retpoline_enabled(&self, value: u8) {
        self.bpb_retpoline_state.set_bits(2, 1, value as u64)
    }
    /// `BpbRetpolineStateReserved`: bits 3..=7 de `bpb_retpoline_state`.
    pub const BPB_RETPOLINE_STATE_RESERVED_SHIFT: u32 = 3;
    pub const BPB_RETPOLINE_STATE_RESERVED_MASK: u8 = 0xf8;
    #[inline(always)]
    pub fn bpb_retpoline_state_reserved(&self) -> u8 {
        self.bpb_retpoline_state.bits(3, 5) as u8
    }
    #[inline(always)]
    pub fn set_bpb_retpoline_state_reserved(&self, value: u8) {
        self.bpb_retpoline_state.set_bits(3, 5, value as u64)
    }
    /// `BpbCpuIdle`: bits 0..=0 de `bpb_state`.
    pub const BPB_CPU_IDLE_SHIFT: u32 = 0;
    pub const BPB_CPU_IDLE_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn bpb_cpu_idle(&self) -> u16 {
        self.bpb_state.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_cpu_idle(&self, value: u16) {
        self.bpb_state.set_bits(0, 1, value as u64)
    }
    /// `BpbFlushRsbOnTrap`: bits 1..=1 de `bpb_state`.
    pub const BPB_FLUSH_RSB_ON_TRAP_SHIFT: u32 = 1;
    pub const BPB_FLUSH_RSB_ON_TRAP_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn bpb_flush_rsb_on_trap(&self) -> u16 {
        self.bpb_state.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_flush_rsb_on_trap(&self, value: u16) {
        self.bpb_state.set_bits(1, 1, value as u64)
    }
    /// `BpbIbpbOnReturn`: bits 2..=2 de `bpb_state`.
    pub const BPB_IBPB_ON_RETURN_SHIFT: u32 = 2;
    pub const BPB_IBPB_ON_RETURN_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn bpb_ibpb_on_return(&self) -> u16 {
        self.bpb_state.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_ibpb_on_return(&self, value: u16) {
        self.bpb_state.set_bits(2, 1, value as u64)
    }
    /// `BpbIbpbOnTrap`: bits 3..=3 de `bpb_state`.
    pub const BPB_IBPB_ON_TRAP_SHIFT: u32 = 3;
    pub const BPB_IBPB_ON_TRAP_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn bpb_ibpb_on_trap(&self) -> u16 {
        self.bpb_state.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_ibpb_on_trap(&self, value: u16) {
        self.bpb_state.set_bits(3, 1, value as u64)
    }
    /// `BpbIbpbOnRetpolineExit`: bits 4..=4 de `bpb_state`.
    pub const BPB_IBPB_ON_RETPOLINE_EXIT_SHIFT: u32 = 4;
    pub const BPB_IBPB_ON_RETPOLINE_EXIT_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn bpb_ibpb_on_retpoline_exit(&self) -> u16 {
        self.bpb_state.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_ibpb_on_retpoline_exit(&self, value: u16) {
        self.bpb_state.set_bits(4, 1, value as u64)
    }
    /// `BpbFlushRsbOnReturn`: bits 5..=5 de `bpb_state`.
    pub const BPB_FLUSH_RSB_ON_RETURN_SHIFT: u32 = 5;
    pub const BPB_FLUSH_RSB_ON_RETURN_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn bpb_flush_rsb_on_return(&self) -> u16 {
        self.bpb_state.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_flush_rsb_on_return(&self, value: u16) {
        self.bpb_state.set_bits(5, 1, value as u64)
    }
    /// `BpbFlushRsbOnRetpolineExit`: bits 6..=6 de `bpb_state`.
    pub const BPB_FLUSH_RSB_ON_RETPOLINE_EXIT_SHIFT: u32 = 6;
    pub const BPB_FLUSH_RSB_ON_RETPOLINE_EXIT_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn bpb_flush_rsb_on_retpoline_exit(&self) -> u16 {
        self.bpb_state.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_flush_rsb_on_retpoline_exit(&self, value: u16) {
        self.bpb_state.set_bits(6, 1, value as u64)
    }
    /// `BpbDivideOnReturn`: bits 7..=7 de `bpb_state`.
    pub const BPB_DIVIDE_ON_RETURN_SHIFT: u32 = 7;
    pub const BPB_DIVIDE_ON_RETURN_MASK: u16 = 0x80;
    #[inline(always)]
    pub fn bpb_divide_on_return(&self) -> u16 {
        self.bpb_state.bits(7, 1) as u16
    }
    #[inline(always)]
    pub fn set_bpb_divide_on_return(&self, value: u16) {
        self.bpb_state.set_bits(7, 1, value as u64)
    }
    /// `VerwOnNonKvaReturn`: bits 8..=8 de `bpb_state`.
    pub const VERW_ON_NON_KVA_RETURN_SHIFT: u32 = 8;
    pub const VERW_ON_NON_KVA_RETURN_MASK: u16 = 0x100;
    #[inline(always)]
    pub fn verw_on_non_kva_return(&self) -> u16 {
        self.bpb_state.bits(8, 1) as u16
    }
    #[inline(always)]
    pub fn set_verw_on_non_kva_return(&self, value: u16) {
        self.bpb_state.set_bits(8, 1, value as u64)
    }
    /// `FlushBhbOnTrap`: bits 9..=9 de `bpb_state`.
    pub const FLUSH_BHB_ON_TRAP_SHIFT: u32 = 9;
    pub const FLUSH_BHB_ON_TRAP_MASK: u16 = 0x200;
    #[inline(always)]
    pub fn flush_bhb_on_trap(&self) -> u16 {
        self.bpb_state.bits(9, 1) as u16
    }
    #[inline(always)]
    pub fn set_flush_bhb_on_trap(&self, value: u16) {
        self.bpb_state.set_bits(9, 1, value as u64)
    }
    /// `Spare`: bits 10..=15 de `bpb_state`.
    pub const SPARE_SHIFT: u32 = 10;
    pub const SPARE_MASK: u16 = 0xfc00;
    #[inline(always)]
    pub fn spare(&self) -> u16 {
        self.bpb_state.bits(10, 6) as u16
    }
    #[inline(always)]
    pub fn set_spare(&self, value: u16) {
        self.bpb_state.set_bits(10, 6, value as u64)
    }
    /// `BpbClearOnIdle`: bits 0..=0 de `bpb_features`.
    pub const BPB_CLEAR_ON_IDLE_SHIFT: u32 = 0;
    pub const BPB_CLEAR_ON_IDLE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn bpb_clear_on_idle(&self) -> u8 {
        self.bpb_features.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_clear_on_idle(&self, value: u8) {
        self.bpb_features.set_bits(0, 1, value as u64)
    }
    /// `BpbEnabled`: bits 1..=1 de `bpb_features`.
    pub const BPB_ENABLED_SHIFT: u32 = 1;
    pub const BPB_ENABLED_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn bpb_enabled(&self) -> u8 {
        self.bpb_features.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_enabled(&self, value: u8) {
        self.bpb_features.set_bits(1, 1, value as u64)
    }
    /// `BpbSmep`: bits 2..=2 de `bpb_features`.
    pub const BPB_SMEP_SHIFT: u32 = 2;
    pub const BPB_SMEP_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn bpb_smep(&self) -> u8 {
        self.bpb_features.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_smep(&self, value: u8) {
        self.bpb_features.set_bits(2, 1, value as u64)
    }
    /// `BpbKCet`: bits 3..=3 de `bpb_features`.
    pub const BPB_K_CET_SHIFT: u32 = 3;
    pub const BPB_K_CET_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn bpb_k_cet(&self) -> u8 {
        self.bpb_features.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_k_cet(&self, value: u8) {
        self.bpb_features.set_bits(3, 1, value as u64)
    }
    /// `BhbFlushSequence`: bits 4..=5 de `bpb_features`.
    pub const BHB_FLUSH_SEQUENCE_SHIFT: u32 = 4;
    pub const BHB_FLUSH_SEQUENCE_MASK: u8 = 0x30;
    #[inline(always)]
    pub fn bhb_flush_sequence(&self) -> u8 {
        self.bpb_features.bits(4, 2) as u8
    }
    #[inline(always)]
    pub fn set_bhb_flush_sequence(&self, value: u8) {
        self.bpb_features.set_bits(4, 2, value as u64)
    }
    /// `VerwOnIdle`: bits 6..=6 de `bpb_features`.
    pub const VERW_ON_IDLE_SHIFT: u32 = 6;
    pub const VERW_ON_IDLE_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn verw_on_idle(&self) -> u8 {
        self.bpb_features.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_verw_on_idle(&self, value: u8) {
        self.bpb_features.set_bits(6, 1, value as u64)
    }
    /// `BpbFeaturesReserved`: bits 7..=7 de `bpb_features`.
    pub const BPB_FEATURES_RESERVED_SHIFT: u32 = 7;
    pub const BPB_FEATURES_RESERVED_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn bpb_features_reserved(&self) -> u8 {
        self.bpb_features.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_bpb_features_reserved(&self, value: u8) {
        self.bpb_features.set_bits(7, 1, value as u64)
    }
    /// `DpcNormalProcessingActive`: bits 0..=0 de `dpc_request_summary`.
    pub const DPC_NORMAL_PROCESSING_ACTIVE_SHIFT: u32 = 0;
    pub const DPC_NORMAL_PROCESSING_ACTIVE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn dpc_normal_processing_active(&self) -> u32 {
        self.dpc_request_summary.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_processing_active(&self, value: u32) {
        self.dpc_request_summary.set_bits(0, 1, value as u64)
    }
    /// `DpcNormalProcessingRequested`: bits 1..=1 de `dpc_request_summary`.
    pub const DPC_NORMAL_PROCESSING_REQUESTED_SHIFT: u32 = 1;
    pub const DPC_NORMAL_PROCESSING_REQUESTED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn dpc_normal_processing_requested(&self) -> u32 {
        self.dpc_request_summary.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_processing_requested(&self, value: u32) {
        self.dpc_request_summary.set_bits(1, 1, value as u64)
    }
    /// `DpcNormalThreadSignal`: bits 2..=2 de `dpc_request_summary`.
    pub const DPC_NORMAL_THREAD_SIGNAL_SHIFT: u32 = 2;
    pub const DPC_NORMAL_THREAD_SIGNAL_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn dpc_normal_thread_signal(&self) -> u32 {
        self.dpc_request_summary.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_thread_signal(&self, value: u32) {
        self.dpc_request_summary.set_bits(2, 1, value as u64)
    }
    /// `DpcNormalTimerExpiration`: bits 3..=3 de `dpc_request_summary`.
    pub const DPC_NORMAL_TIMER_EXPIRATION_SHIFT: u32 = 3;
    pub const DPC_NORMAL_TIMER_EXPIRATION_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn dpc_normal_timer_expiration(&self) -> u32 {
        self.dpc_request_summary.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_timer_expiration(&self, value: u32) {
        self.dpc_request_summary.set_bits(3, 1, value as u64)
    }
    /// `DpcNormalDpcPresent`: bits 4..=4 de `dpc_request_summary`.
    pub const DPC_NORMAL_DPC_PRESENT_SHIFT: u32 = 4;
    pub const DPC_NORMAL_DPC_PRESENT_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn dpc_normal_dpc_present(&self) -> u32 {
        self.dpc_request_summary.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_dpc_present(&self, value: u32) {
        self.dpc_request_summary.set_bits(4, 1, value as u64)
    }
    /// `DpcNormalLocalInterrupt`: bits 5..=5 de `dpc_request_summary`.
    pub const DPC_NORMAL_LOCAL_INTERRUPT_SHIFT: u32 = 5;
    pub const DPC_NORMAL_LOCAL_INTERRUPT_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn dpc_normal_local_interrupt(&self) -> u32 {
        self.dpc_request_summary.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_local_interrupt(&self, value: u32) {
        self.dpc_request_summary.set_bits(5, 1, value as u64)
    }
    /// `DpcNormalSpare`: bits 6..=15 de `dpc_request_summary`.
    pub const DPC_NORMAL_SPARE_SHIFT: u32 = 6;
    pub const DPC_NORMAL_SPARE_MASK: u32 = 0xffc0;
    #[inline(always)]
    pub fn dpc_normal_spare(&self) -> u32 {
        self.dpc_request_summary.bits(6, 10) as u32
    }
    #[inline(always)]
    pub fn set_dpc_normal_spare(&self, value: u32) {
        self.dpc_request_summary.set_bits(6, 10, value as u64)
    }
    /// `DpcThreadActive`: bits 16..=16 de `dpc_request_summary`.
    pub const DPC_THREAD_ACTIVE_SHIFT: u32 = 16;
    pub const DPC_THREAD_ACTIVE_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn dpc_thread_active(&self) -> u32 {
        self.dpc_request_summary.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_thread_active(&self, value: u32) {
        self.dpc_request_summary.set_bits(16, 1, value as u64)
    }
    /// `DpcThreadRequested`: bits 17..=17 de `dpc_request_summary`.
    pub const DPC_THREAD_REQUESTED_SHIFT: u32 = 17;
    pub const DPC_THREAD_REQUESTED_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn dpc_thread_requested(&self) -> u32 {
        self.dpc_request_summary.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpc_thread_requested(&self, value: u32) {
        self.dpc_request_summary.set_bits(17, 1, value as u64)
    }
    /// `DpcThreadSpare`: bits 18..=31 de `dpc_request_summary`.
    pub const DPC_THREAD_SPARE_SHIFT: u32 = 18;
    pub const DPC_THREAD_SPARE_MASK: u32 = 0xfffc0000;
    #[inline(always)]
    pub fn dpc_thread_spare(&self) -> u32 {
        self.dpc_request_summary.bits(18, 14) as u32
    }
    #[inline(always)]
    pub fn set_dpc_thread_spare(&self, value: u32) {
        self.dpc_request_summary.set_bits(18, 14, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Kprcb>() == 0xaf00);
    assert!(core::mem::offset_of!(Kprcb, mx_csr) == 0x0);
    assert!(core::mem::offset_of!(Kprcb, legacy_number) == 0x4);
    assert!(core::mem::offset_of!(Kprcb, reserved_must_be_zero) == 0x5);
    assert!(core::mem::offset_of!(Kprcb, interrupt_request) == 0x6);
    assert!(core::mem::offset_of!(Kprcb, idle_halt) == 0x7);
    assert!(core::mem::offset_of!(Kprcb, current_thread) == 0x8);
    assert!(core::mem::offset_of!(Kprcb, next_thread) == 0x10);
    assert!(core::mem::offset_of!(Kprcb, idle_thread) == 0x18);
    assert!(core::mem::offset_of!(Kprcb, nesting_level) == 0x20);
    assert!(core::mem::offset_of!(Kprcb, clock_owner) == 0x21);
    assert!(core::mem::offset_of!(Kprcb, pending_tick_flags) == 0x22);
    assert!(core::mem::offset_of!(Kprcb, idle_state) == 0x23);
    assert!(core::mem::offset_of!(Kprcb, number) == 0x24);
    assert!(core::mem::offset_of!(Kprcb, rsp_base) == 0x28);
    assert!(core::mem::offset_of!(Kprcb, prcb_lock) == 0x30);
    assert!(core::mem::offset_of!(Kprcb, priority_state) == 0x38);
    assert!(core::mem::offset_of!(Kprcb, cpu_type) == 0x40);
    assert!(core::mem::offset_of!(Kprcb, cpu_id) == 0x41);
    assert!(core::mem::offset_of!(Kprcb, cpu_step) == 0x42);
    assert!(core::mem::offset_of!(Kprcb, m_hz) == 0x44);
    assert!(core::mem::offset_of!(Kprcb, hal_reserved) == 0x48);
    assert!(core::mem::offset_of!(Kprcb, minor_version) == 0x88);
    assert!(core::mem::offset_of!(Kprcb, major_version) == 0x8a);
    assert!(core::mem::offset_of!(Kprcb, build_type) == 0x8c);
    assert!(core::mem::offset_of!(Kprcb, cpu_vendor) == 0x8d);
    assert!(core::mem::offset_of!(Kprcb, legacy_cores_per_physical_processor) == 0x8e);
    assert!(core::mem::offset_of!(Kprcb, legacy_logical_processors_per_core) == 0x8f);
    assert!(core::mem::offset_of!(Kprcb, tsc_frequency) == 0x90);
    assert!(core::mem::offset_of!(Kprcb, cores_per_physical_processor) == 0x98);
    assert!(core::mem::offset_of!(Kprcb, logical_processors_per_core) == 0x9c);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad04) == 0xa0);
    assert!(core::mem::offset_of!(Kprcb, parent_node) == 0xc0);
    assert!(core::mem::offset_of!(Kprcb, group_set_member) == 0xc8);
    assert!(core::mem::offset_of!(Kprcb, group) == 0xd0);
    assert!(core::mem::offset_of!(Kprcb, group_index) == 0xd1);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad05) == 0xd2);
    assert!(core::mem::offset_of!(Kprcb, initial_apic_id) == 0xd4);
    assert!(core::mem::offset_of!(Kprcb, scb_offset) == 0xd8);
    assert!(core::mem::offset_of!(Kprcb, apic_mask) == 0xdc);
    assert!(core::mem::offset_of!(Kprcb, acpi_reserved) == 0xe0);
    assert!(core::mem::offset_of!(Kprcb, c_flush_size) == 0xe8);
    assert!(core::mem::offset_of!(Kprcb, prcb_flags) == 0xec);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad11) == 0xf0);
    assert!(core::mem::offset_of!(Kprcb, processor_state) == 0x100);
    assert!(core::mem::offset_of!(Kprcb, extended_supervisor_state) == 0x6c0);
    assert!(core::mem::offset_of!(Kprcb, processor_signature) == 0x6c8);
    assert!(core::mem::offset_of!(Kprcb, processor_flags) == 0x6cc);
    assert!(core::mem::offset_of!(Kprcb, bpb_retpoline_exit_spec_ctrl) == 0x6d0);
    assert!(core::mem::offset_of!(Kprcb, bpb_trapped_retpoline_exit_spec_ctrl) == 0x6d2);
    assert!(core::mem::offset_of!(Kprcb, bpb_trapped_bpb_state) == 0x6d4);
    assert!(core::mem::offset_of!(Kprcb, bpb_retpoline_state) == 0x6d6);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad12b) == 0x6d7);
    assert!(core::mem::offset_of!(Kprcb, trapped_security_domain) == 0x6d8);
    assert!(core::mem::offset_of!(Kprcb, bpb_state) == 0x6e0);
    assert!(core::mem::offset_of!(Kprcb, bpb_features) == 0x6e2);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad12e) == 0x6e3);
    assert!(core::mem::offset_of!(Kprcb, bpb_current_spec_ctrl) == 0x6e4);
    assert!(core::mem::offset_of!(Kprcb, bpb_kernel_spec_ctrl) == 0x6e6);
    assert!(core::mem::offset_of!(Kprcb, bpb_nmi_spec_ctrl) == 0x6e8);
    assert!(core::mem::offset_of!(Kprcb, bpb_user_spec_ctrl) == 0x6ea);
    assert!(core::mem::offset_of!(Kprcb, pair_register) == 0x6ec);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad12d) == 0x6ee);
    assert!(core::mem::offset_of!(Kprcb, lock_queue) == 0x6f0);
    assert!(core::mem::offset_of!(Kprcb, pp_lookaside_list) == 0x800);
    assert!(core::mem::offset_of!(Kprcb, pp_nx_paged_lookaside_list) == 0x900);
    assert!(core::mem::offset_of!(Kprcb, ppn_paged_lookaside_list) == 0x1500);
    assert!(core::mem::offset_of!(Kprcb, pp_paged_lookaside_list) == 0x2100);
    assert!(core::mem::offset_of!(Kprcb, msr_ia32_tsx_ctrl) == 0x2d00);
    assert!(core::mem::offset_of!(Kprcb, deferred_ready_list_head) == 0x2d08);
    assert!(core::mem::offset_of!(Kprcb, mm_page_fault_count) == 0x2d10);
    assert!(core::mem::offset_of!(Kprcb, mm_copy_on_write_count) == 0x2d14);
    assert!(core::mem::offset_of!(Kprcb, mm_transition_count) == 0x2d18);
    assert!(core::mem::offset_of!(Kprcb, mm_demand_zero_count) == 0x2d1c);
    assert!(core::mem::offset_of!(Kprcb, mm_page_read_count) == 0x2d20);
    assert!(core::mem::offset_of!(Kprcb, mm_page_read_io_count) == 0x2d24);
    assert!(core::mem::offset_of!(Kprcb, mm_dirty_pages_write_count) == 0x2d28);
    assert!(core::mem::offset_of!(Kprcb, mm_dirty_write_io_count) == 0x2d2c);
    assert!(core::mem::offset_of!(Kprcb, mm_mapped_pages_write_count) == 0x2d30);
    assert!(core::mem::offset_of!(Kprcb, mm_mapped_write_io_count) == 0x2d34);
    assert!(core::mem::offset_of!(Kprcb, ke_system_calls) == 0x2d38);
    assert!(core::mem::offset_of!(Kprcb, ke_context_switches) == 0x2d3c);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad40) == 0x2d40);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_read_no_wait) == 0x2d44);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_read_wait) == 0x2d48);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_read_not_possible) == 0x2d4c);
    assert!(core::mem::offset_of!(Kprcb, cc_copy_read_no_wait) == 0x2d50);
    assert!(core::mem::offset_of!(Kprcb, cc_copy_read_wait) == 0x2d54);
    assert!(core::mem::offset_of!(Kprcb, cc_copy_read_no_wait_miss) == 0x2d58);
    assert!(core::mem::offset_of!(Kprcb, io_read_operation_count) == 0x2d5c);
    assert!(core::mem::offset_of!(Kprcb, io_write_operation_count) == 0x2d60);
    assert!(core::mem::offset_of!(Kprcb, io_other_operation_count) == 0x2d64);
    assert!(core::mem::offset_of!(Kprcb, io_read_transfer_count) == 0x2d68);
    assert!(core::mem::offset_of!(Kprcb, io_write_transfer_count) == 0x2d70);
    assert!(core::mem::offset_of!(Kprcb, io_other_transfer_count) == 0x2d78);
    assert!(core::mem::offset_of!(Kprcb, packet_barrier) == 0x2d80);
    assert!(core::mem::offset_of!(Kprcb, target_count) == 0x2d84);
    assert!(core::mem::offset_of!(Kprcb, ipi_frozen) == 0x2d88);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad30) == 0x2d8c);
    assert!(core::mem::offset_of!(Kprcb, isr_dpc_stats) == 0x2d90);
    assert!(core::mem::offset_of!(Kprcb, device_interrupts) == 0x2d98);
    assert!(core::mem::offset_of!(Kprcb, lookaside_irp_float) == 0x2d9c);
    assert!(core::mem::offset_of!(Kprcb, interrupt_last_count) == 0x2da0);
    assert!(core::mem::offset_of!(Kprcb, interrupt_rate) == 0x2da4);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad31) == 0x2da8);
    assert!(core::mem::offset_of!(Kprcb, pair_prcb) == 0x2db0);
    assert!(core::mem::offset_of!(Kprcb, static_affinity) == 0x2db8);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad35) == 0x3058);
    assert!(core::mem::offset_of!(Kprcb, interrupt_object_pool) == 0x3080);
    assert!(core::mem::offset_of!(Kprcb, dpc_runtime_history_hash_table) == 0x3090);
    assert!(core::mem::offset_of!(Kprcb, dpc_runtime_history_hash_table_cleanup_dpc) == 0x3098);
    assert!(core::mem::offset_of!(Kprcb, current_dpc_routine) == 0x30a0);
    assert!(core::mem::offset_of!(Kprcb, current_dpc_runtime_history_cached) == 0x30a8);
    assert!(core::mem::offset_of!(Kprcb, current_dpc_start_time) == 0x30b0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad41) == 0x30b8);
    assert!(core::mem::offset_of!(Kprcb, dpc_data) == 0x30c0);
    assert!(core::mem::offset_of!(Kprcb, dpc_stack) == 0x3110);
    assert!(core::mem::offset_of!(Kprcb, maximum_dpc_queue_depth) == 0x3118);
    assert!(core::mem::offset_of!(Kprcb, dpc_request_rate) == 0x311c);
    assert!(core::mem::offset_of!(Kprcb, minimum_dpc_rate) == 0x3120);
    assert!(core::mem::offset_of!(Kprcb, dpc_last_count) == 0x3124);
    assert!(core::mem::offset_of!(Kprcb, thread_dpc_enable) == 0x3128);
    assert!(core::mem::offset_of!(Kprcb, quantum_end) == 0x3129);
    assert!(core::mem::offset_of!(Kprcb, dpc_routine_active) == 0x312a);
    assert!(core::mem::offset_of!(Kprcb, idle_schedule) == 0x312b);
    assert!(core::mem::offset_of!(Kprcb, dpc_request_summary) == 0x312c);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad93) == 0x3130);
    assert!(core::mem::offset_of!(Kprcb, last_tick) == 0x3134);
    assert!(core::mem::offset_of!(Kprcb, clock_interrupts) == 0x3138);
    assert!(core::mem::offset_of!(Kprcb, ready_scan_tick) == 0x313c);
    assert!(core::mem::offset_of!(Kprcb, interrupt_object) == 0x3140);
    assert!(core::mem::offset_of!(Kprcb, timer_table) == 0x3940);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad92) == 0x7b58);
    assert!(core::mem::offset_of!(Kprcb, dpc_gate) == 0x7b80);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad52) == 0x7b98);
    assert!(core::mem::offset_of!(Kprcb, call_dpc) == 0x7ba0);
    assert!(core::mem::offset_of!(Kprcb, clock_keep_alive) == 0x7be0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad60) == 0x7be4);
    assert!(core::mem::offset_of!(Kprcb, nmi_active) == 0x7be6);
    assert!(core::mem::offset_of!(Kprcb, mce_active) == 0x7be7);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_period) == 0x7be8);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_count) == 0x7bec);
    assert!(core::mem::offset_of!(Kprcb, ke_spin_lock_ordering) == 0x7bf0);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_profile_cumulative_dpc_threshold) == 0x7bf4);
    assert!(core::mem::offset_of!(Kprcb, cached_ptes) == 0x7bf8);
    assert!(core::mem::offset_of!(Kprcb, wait_list_head) == 0x7c00);
    assert!(core::mem::offset_of!(Kprcb, wait_lock) == 0x7c10);
    assert!(core::mem::offset_of!(Kprcb, ready_summary) == 0x7c18);
    assert!(core::mem::offset_of!(Kprcb, affinitized_selection_mask) == 0x7c1c);
    assert!(core::mem::offset_of!(Kprcb, queue_index) == 0x7c20);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad75) == 0x7c24);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_sequence_number) == 0x7c2c);
    assert!(core::mem::offset_of!(Kprcb, timer_expiration_dpc) == 0x7c30);
    assert!(core::mem::offset_of!(Kprcb, scb_queue) == 0x7c70);
    assert!(core::mem::offset_of!(Kprcb, dispatcher_ready_list_head) == 0x7c80);
    assert!(core::mem::offset_of!(Kprcb, interrupt_count) == 0x7e80);
    assert!(core::mem::offset_of!(Kprcb, kernel_time) == 0x7e84);
    assert!(core::mem::offset_of!(Kprcb, user_time) == 0x7e88);
    assert!(core::mem::offset_of!(Kprcb, dpc_time) == 0x7e8c);
    assert!(core::mem::offset_of!(Kprcb, interrupt_time) == 0x7e90);
    assert!(core::mem::offset_of!(Kprcb, adjust_dpc_threshold) == 0x7e94);
    assert!(core::mem::offset_of!(Kprcb, debugger_saved_irql) == 0x7e98);
    assert!(core::mem::offset_of!(Kprcb, group_scheduling_over_quota) == 0x7e99);
    assert!(core::mem::offset_of!(Kprcb, deep_sleep) == 0x7e9a);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad80) == 0x7e9b);
    assert!(core::mem::offset_of!(Kprcb, dpc_time_count) == 0x7e9c);
    assert!(core::mem::offset_of!(Kprcb, dpc_time_limit) == 0x7ea0);
    assert!(core::mem::offset_of!(Kprcb, periodic_count) == 0x7ea4);
    assert!(core::mem::offset_of!(Kprcb, periodic_bias) == 0x7ea8);
    assert!(core::mem::offset_of!(Kprcb, available_time) == 0x7eac);
    assert!(core::mem::offset_of!(Kprcb, ke_exception_dispatch_count) == 0x7eb0);
    assert!(core::mem::offset_of!(Kprcb, ready_thread_count) == 0x7eb4);
    assert!(core::mem::offset_of!(Kprcb, ready_queue_expected_run_time) == 0x7eb8);
    assert!(core::mem::offset_of!(Kprcb, start_cycles) == 0x7ec0);
    assert!(core::mem::offset_of!(Kprcb, tagged_cycles_start) == 0x7ec8);
    assert!(core::mem::offset_of!(Kprcb, tagged_cycles) == 0x7ed0);
    assert!(core::mem::offset_of!(Kprcb, affinitized_cycles) == 0x7ee8);
    assert!(core::mem::offset_of!(Kprcb, important_cycles) == 0x7ef0);
    assert!(core::mem::offset_of!(Kprcb, unimportant_cycles) == 0x7ef8);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_profile_single_dpc_threshold) == 0x7f00);
    assert!(core::mem::offset_of!(Kprcb, mm_spin_lock_ordering) == 0x7f04);
    assert!(core::mem::offset_of!(Kprcb, cached_stack) == 0x7f08);
    assert!(core::mem::offset_of!(Kprcb, page_color) == 0x7f10);
    assert!(core::mem::offset_of!(Kprcb, node_color) == 0x7f14);
    assert!(core::mem::offset_of!(Kprcb, node_shifted_color) == 0x7f18);
    assert!(core::mem::offset_of!(Kprcb, secondary_color_mask) == 0x7f1c);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad81) == 0x7f20);
    assert!(core::mem::offset_of!(Kprcb, exception_stack_active) == 0x7f26);
    assert!(core::mem::offset_of!(Kprcb, tb_flush_list_active) == 0x7f27);
    assert!(core::mem::offset_of!(Kprcb, exception_stack) == 0x7f28);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad82) == 0x7f30);
    assert!(core::mem::offset_of!(Kprcb, cycle_time) == 0x7f38);
    assert!(core::mem::offset_of!(Kprcb, cycles) == 0x7f40);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_mdl_read_no_wait) == 0x7f80);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_mdl_read_wait) == 0x7f84);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_mdl_read_not_possible) == 0x7f88);
    assert!(core::mem::offset_of!(Kprcb, cc_map_data_no_wait) == 0x7f8c);
    assert!(core::mem::offset_of!(Kprcb, cc_map_data_wait) == 0x7f90);
    assert!(core::mem::offset_of!(Kprcb, cc_pin_mapped_data_count) == 0x7f94);
    assert!(core::mem::offset_of!(Kprcb, cc_pin_read_no_wait) == 0x7f98);
    assert!(core::mem::offset_of!(Kprcb, cc_pin_read_wait) == 0x7f9c);
    assert!(core::mem::offset_of!(Kprcb, cc_mdl_read_no_wait) == 0x7fa0);
    assert!(core::mem::offset_of!(Kprcb, cc_mdl_read_wait) == 0x7fa4);
    assert!(core::mem::offset_of!(Kprcb, cc_lazy_write_hot_spots) == 0x7fa8);
    assert!(core::mem::offset_of!(Kprcb, cc_lazy_write_ios) == 0x7fac);
    assert!(core::mem::offset_of!(Kprcb, cc_lazy_write_pages) == 0x7fb0);
    assert!(core::mem::offset_of!(Kprcb, cc_data_flushes) == 0x7fb4);
    assert!(core::mem::offset_of!(Kprcb, cc_data_pages) == 0x7fb8);
    assert!(core::mem::offset_of!(Kprcb, cc_lost_delayed_writes) == 0x7fbc);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_read_resource_miss) == 0x7fc0);
    assert!(core::mem::offset_of!(Kprcb, cc_copy_read_wait_miss) == 0x7fc4);
    assert!(core::mem::offset_of!(Kprcb, cc_fast_mdl_read_resource_miss) == 0x7fc8);
    assert!(core::mem::offset_of!(Kprcb, cc_map_data_no_wait_miss) == 0x7fcc);
    assert!(core::mem::offset_of!(Kprcb, cc_map_data_wait_miss) == 0x7fd0);
    assert!(core::mem::offset_of!(Kprcb, cc_pin_read_no_wait_miss) == 0x7fd4);
    assert!(core::mem::offset_of!(Kprcb, cc_pin_read_wait_miss) == 0x7fd8);
    assert!(core::mem::offset_of!(Kprcb, cc_mdl_read_no_wait_miss) == 0x7fdc);
    assert!(core::mem::offset_of!(Kprcb, cc_mdl_read_wait_miss) == 0x7fe0);
    assert!(core::mem::offset_of!(Kprcb, cc_read_ahead_ios) == 0x7fe4);
    assert!(core::mem::offset_of!(Kprcb, mm_cache_transition_count) == 0x7fe8);
    assert!(core::mem::offset_of!(Kprcb, mm_cache_read_count) == 0x7fec);
    assert!(core::mem::offset_of!(Kprcb, mm_cache_io_count) == 0x7ff0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad91) == 0x7ff4);
    assert!(core::mem::offset_of!(Kprcb, mm_internal) == 0x7ff8);
    assert!(core::mem::offset_of!(Kprcb, power_state) == 0x8000);
    assert!(core::mem::offset_of!(Kprcb, hyper_pte) == 0x8200);
    assert!(core::mem::offset_of!(Kprcb, scb_list) == 0x8208);
    assert!(core::mem::offset_of!(Kprcb, force_idle_dpc) == 0x8218);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_dpc) == 0x8258);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_timer) == 0x8298);
    assert!(core::mem::offset_of!(Kprcb, cache) == 0x82d8);
    assert!(core::mem::offset_of!(Kprcb, cache_count) == 0x8314);
    assert!(core::mem::offset_of!(Kprcb, cached_commit) == 0x8318);
    assert!(core::mem::offset_of!(Kprcb, cached_resident_available) == 0x831c);
    assert!(core::mem::offset_of!(Kprcb, whea_info) == 0x8320);
    assert!(core::mem::offset_of!(Kprcb, etw_support) == 0x8328);
    assert!(core::mem::offset_of!(Kprcb, ex_sa_page_array) == 0x8330);
    assert!(core::mem::offset_of!(Kprcb, ke_alignment_fixup_count) == 0x8338);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad95) == 0x833c);
    assert!(core::mem::offset_of!(Kprcb, hypercall_page_list) == 0x8340);
    assert!(core::mem::offset_of!(Kprcb, statistics_page) == 0x8350);
    assert!(core::mem::offset_of!(Kprcb, generation_target) == 0x8358);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad85) == 0x8360);
    assert!(core::mem::offset_of!(Kprcb, hypercall_cached_pages) == 0x8380);
    assert!(core::mem::offset_of!(Kprcb, virtual_apic_assist) == 0x8388);
    assert!(core::mem::offset_of!(Kprcb, package_processor_set) == 0x8390);
    assert!(core::mem::offset_of!(Kprcb, package_id) == 0x8438);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad86) == 0x843c);
    assert!(core::mem::offset_of!(Kprcb, shared_ready_queue_mask) == 0x8440);
    assert!(core::mem::offset_of!(Kprcb, shared_ready_queue) == 0x8448);
    assert!(core::mem::offset_of!(Kprcb, shared_queue_scan_owner) == 0x8450);
    assert!(core::mem::offset_of!(Kprcb, scan_sibling_index) == 0x8454);
    assert!(core::mem::offset_of!(Kprcb, core_processor_set) == 0x8458);
    assert!(core::mem::offset_of!(Kprcb, scan_sibling_mask) == 0x8460);
    assert!(core::mem::offset_of!(Kprcb, llc_mask) == 0x8468);
    assert!(core::mem::offset_of!(Kprcb, cache_processor_mask) == 0x8470);
    assert!(core::mem::offset_of!(Kprcb, processor_profile_control_area) == 0x8498);
    assert!(core::mem::offset_of!(Kprcb, profile_event_index_address) == 0x84a0);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_profile) == 0x84a8);
    assert!(core::mem::offset_of!(Kprcb, dpc_watchdog_profile_current_empty_capture) == 0x84b0);
    assert!(core::mem::offset_of!(Kprcb, scheduler_assist) == 0x84b8);
    assert!(core::mem::offset_of!(Kprcb, synch_counters) == 0x84c0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad94) == 0x8578);
    assert!(core::mem::offset_of!(Kprcb, fs_counters) == 0x8580);
    assert!(core::mem::offset_of!(Kprcb, vendor_string) == 0x8590);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad100) == 0x859d);
    assert!(core::mem::offset_of!(Kprcb, feature_bits) == 0x85a0);
    assert!(core::mem::offset_of!(Kprcb, update_signature) == 0x85a8);
    assert!(core::mem::offset_of!(Kprcb, pte_bit_cache) == 0x85b0);
    assert!(core::mem::offset_of!(Kprcb, pte_bit_offset) == 0x85b8);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad105) == 0x85bc);
    assert!(core::mem::offset_of!(Kprcb, context) == 0x85c0);
    assert!(core::mem::offset_of!(Kprcb, context_flags_init) == 0x85c8);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad115) == 0x85cc);
    assert!(core::mem::offset_of!(Kprcb, extended_state) == 0x85d0);
    assert!(core::mem::offset_of!(Kprcb, isr_stack) == 0x85d8);
    assert!(core::mem::offset_of!(Kprcb, entropy_timing_state) == 0x85e0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad110) == 0x8730);
    assert!(core::mem::offset_of!(Kprcb, stibp_pairing_trace) == 0x8738);
    assert!(core::mem::offset_of!(Kprcb, ab_self_io_boosts_list) == 0x8770);
    assert!(core::mem::offset_of!(Kprcb, ab_propagate_boosts_list) == 0x8778);
    assert!(core::mem::offset_of!(Kprcb, ab_dpc) == 0x8780);
    assert!(core::mem::offset_of!(Kprcb, io_irp_stack_profiler_current) == 0x87c0);
    assert!(core::mem::offset_of!(Kprcb, io_irp_stack_profiler_previous) == 0x8814);
    assert!(core::mem::offset_of!(Kprcb, secure_fault) == 0x8868);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad120) == 0x8878);
    assert!(core::mem::offset_of!(Kprcb, local_shared_ready_queue) == 0x8880);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad125) == 0x8af0);
    assert!(core::mem::offset_of!(Kprcb, timer_expiration_trace_count) == 0x8b00);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad127) == 0x8b04);
    assert!(core::mem::offset_of!(Kprcb, timer_expiration_trace) == 0x8b08);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad128) == 0x8c08);
    assert!(core::mem::offset_of!(Kprcb, mailbox) == 0x8c40);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad130) == 0x8c48);
    assert!(core::mem::offset_of!(Kprcb, mcheck_context) == 0x8c80);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad134) == 0x8d20);
    assert!(core::mem::offset_of!(Kprcb, selfmap_lock_handle) == 0x8d40);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad134a) == 0x8da0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad138) == 0x8dc0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad138a) == 0x8e40);
    assert!(core::mem::offset_of!(Kprcb, kernel_directory_table_base) == 0x8e80);
    assert!(core::mem::offset_of!(Kprcb, rsp_base_shadow) == 0x8e88);
    assert!(core::mem::offset_of!(Kprcb, user_rsp_shadow) == 0x8e90);
    assert!(core::mem::offset_of!(Kprcb, shadow_flags) == 0x8e98);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad138b) == 0x8e9c);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad138c) == 0x8ea0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad138d) == 0x8ea8);
    assert!(core::mem::offset_of!(Kprcb, verw_selector) == 0x8eaa);
    assert!(core::mem::offset_of!(Kprcb, dbg_mce_nesting_level) == 0x8eac);
    assert!(core::mem::offset_of!(Kprcb, dbg_mce_flags) == 0x8eb0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad139b) == 0x8eb4);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad140) == 0x8eb8);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad140a) == 0x9e80);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad141) == 0x9ec0);
    assert!(core::mem::offset_of!(Kprcb, prcb_pad141a) == 0xae80);
    assert!(core::mem::offset_of!(Kprcb, request_mailbox) == 0xaec0);
    assert!(core::mem::size_of::<KprcbView1>() == 0xaf00);
    assert!(core::mem::align_of::<KprcbView1>() == core::mem::align_of::<Kprcb>());
    assert!(core::mem::offset_of!(KprcbView1, cpu_stepping) == 0x42);
    assert!(core::mem::offset_of!(KprcbView1, cpu_model) == 0x43);
    assert!(core::mem::offset_of!(KprcbView1, prcb_pad12a) == 0x6d0);
    assert!(core::mem::offset_of!(KprcbView1, prcb_pad12c) == 0x6d8);
    assert!(core::mem::offset_of!(KprcbView1, dpc_request_slot) == 0x312c);
    assert!(core::mem::offset_of!(KprcbView1, combined_nmi_mce_active) == 0x7be6);
    assert!(core::mem::size_of::<KprcbView2>() == 0xaf00);
    assert!(core::mem::align_of::<KprcbView2>() == core::mem::align_of::<Kprcb>());
    assert!(core::mem::offset_of!(KprcbView2, normal_dpc_state) == 0x312c);
    assert!(core::mem::offset_of!(KprcbView2, thread_dpc_state) == 0x312e);
};

/// `_KPRCBFLAG` (0x4 bytes).
#[repr(C)]
pub struct Kprcbflag {
    pub prcb_flags: Field<i32>,
}

unsafe impl NtStruct for Kprcbflag {}

impl Kprcbflag {
    /// `BamQosLevel`: bits 0..=7 de `prcb_flags`.
    pub const BAM_QOS_LEVEL_SHIFT: u32 = 0;
    pub const BAM_QOS_LEVEL_MASK: u32 = 0xff;
    #[inline(always)]
    pub fn bam_qos_level(&self) -> u32 {
        self.prcb_flags.bits(0, 8) as u32
    }
    #[inline(always)]
    pub fn set_bam_qos_level(&self, value: u32) {
        self.prcb_flags.set_bits(0, 8, value as u64)
    }
    /// `PendingQosUpdate`: bits 8..=9 de `prcb_flags`.
    pub const PENDING_QOS_UPDATE_SHIFT: u32 = 8;
    pub const PENDING_QOS_UPDATE_MASK: u32 = 0x300;
    #[inline(always)]
    pub fn pending_qos_update(&self) -> u32 {
        self.prcb_flags.bits(8, 2) as u32
    }
    #[inline(always)]
    pub fn set_pending_qos_update(&self, value: u32) {
        self.prcb_flags.set_bits(8, 2, value as u64)
    }
    /// `CacheIsolationEnabled`: bits 10..=10 de `prcb_flags`.
    pub const CACHE_ISOLATION_ENABLED_SHIFT: u32 = 10;
    pub const CACHE_ISOLATION_ENABLED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn cache_isolation_enabled(&self) -> u32 {
        self.prcb_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_cache_isolation_enabled(&self, value: u32) {
        self.prcb_flags.set_bits(10, 1, value as u64)
    }
    /// `TracepointActive`: bits 11..=11 de `prcb_flags`.
    pub const TRACEPOINT_ACTIVE_SHIFT: u32 = 11;
    pub const TRACEPOINT_ACTIVE_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn tracepoint_active(&self) -> u32 {
        self.prcb_flags.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_tracepoint_active(&self, value: u32) {
        self.prcb_flags.set_bits(11, 1, value as u64)
    }
    /// `PrcbFlagsReserved`: bits 12..=31 de `prcb_flags`.
    pub const PRCB_FLAGS_RESERVED_SHIFT: u32 = 12;
    pub const PRCB_FLAGS_RESERVED_MASK: u32 = 0xfffff000;
    #[inline(always)]
    pub fn prcb_flags_reserved(&self) -> u32 {
        self.prcb_flags.bits(12, 20) as u32
    }
    #[inline(always)]
    pub fn set_prcb_flags_reserved(&self, value: u32) {
        self.prcb_flags.set_bits(12, 20, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Kprcbflag>() == 0x4);
    assert!(core::mem::offset_of!(Kprcbflag, prcb_flags) == 0x0);
};

/// `_KPROCESSOR_STATE` (0x5c0 bytes).
#[repr(C)]
pub struct KprocessorState {
    pub special_registers: KspecialRegisters,
    pub context_frame: Context,
}

unsafe impl NtStruct for KprocessorState {}

const _: () = {
    assert!(core::mem::size_of::<KprocessorState>() == 0x5c0);
    assert!(core::mem::offset_of!(KprocessorState, special_registers) == 0x0);
    assert!(core::mem::offset_of!(KprocessorState, context_frame) == 0xf0);
};

/// `_KSPECIAL_REGISTERS` (0xf0 bytes).
#[repr(C)]
pub struct KspecialRegisters {
    pub cr0: Field<u64>,
    pub cr2: Field<u64>,
    pub cr3: Field<u64>,
    pub cr4: Field<u64>,
    pub kernel_dr0: Field<u64>,
    pub kernel_dr1: Field<u64>,
    pub kernel_dr2: Field<u64>,
    pub kernel_dr3: Field<u64>,
    pub kernel_dr6: Field<u64>,
    pub kernel_dr7: Field<u64>,
    pub gdtr: Kdescriptor,
    pub idtr: Kdescriptor,
    pub tr: Field<u16>,
    pub ldtr: Field<u16>,
    pub mx_csr: Field<u32>,
    pub debug_control: Field<u64>,
    pub last_branch_to_rip: Field<u64>,
    pub last_branch_from_rip: Field<u64>,
    pub last_exception_to_rip: Field<u64>,
    pub last_exception_from_rip: Field<u64>,
    pub cr8: Field<u64>,
    pub msr_gs_base: Field<u64>,
    pub msr_gs_swap: Field<u64>,
    pub msr_star: Field<u64>,
    pub msr_l_star: Field<u64>,
    pub msr_c_star: Field<u64>,
    pub msr_syscall_mask: Field<u64>,
    pub xcr0: Field<u64>,
    pub msr_fs_base: Field<u64>,
    pub special_padding0: Field<u64>,
}

unsafe impl NtStruct for KspecialRegisters {}

const _: () = {
    assert!(core::mem::size_of::<KspecialRegisters>() == 0xf0);
    assert!(core::mem::offset_of!(KspecialRegisters, cr0) == 0x0);
    assert!(core::mem::offset_of!(KspecialRegisters, cr2) == 0x8);
    assert!(core::mem::offset_of!(KspecialRegisters, cr3) == 0x10);
    assert!(core::mem::offset_of!(KspecialRegisters, cr4) == 0x18);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr0) == 0x20);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr1) == 0x28);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr2) == 0x30);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr3) == 0x38);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr6) == 0x40);
    assert!(core::mem::offset_of!(KspecialRegisters, kernel_dr7) == 0x48);
    assert!(core::mem::offset_of!(KspecialRegisters, gdtr) == 0x50);
    assert!(core::mem::offset_of!(KspecialRegisters, idtr) == 0x60);
    assert!(core::mem::offset_of!(KspecialRegisters, tr) == 0x70);
    assert!(core::mem::offset_of!(KspecialRegisters, ldtr) == 0x72);
    assert!(core::mem::offset_of!(KspecialRegisters, mx_csr) == 0x74);
    assert!(core::mem::offset_of!(KspecialRegisters, debug_control) == 0x78);
    assert!(core::mem::offset_of!(KspecialRegisters, last_branch_to_rip) == 0x80);
    assert!(core::mem::offset_of!(KspecialRegisters, last_branch_from_rip) == 0x88);
    assert!(core::mem::offset_of!(KspecialRegisters, last_exception_to_rip) == 0x90);
    assert!(core::mem::offset_of!(KspecialRegisters, last_exception_from_rip) == 0x98);
    assert!(core::mem::offset_of!(KspecialRegisters, cr8) == 0xa0);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_gs_base) == 0xa8);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_gs_swap) == 0xb0);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_star) == 0xb8);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_l_star) == 0xc0);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_c_star) == 0xc8);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_syscall_mask) == 0xd0);
    assert!(core::mem::offset_of!(KspecialRegisters, xcr0) == 0xd8);
    assert!(core::mem::offset_of!(KspecialRegisters, msr_fs_base) == 0xe0);
    assert!(core::mem::offset_of!(KspecialRegisters, special_padding0) == 0xe8);
};

/// `_KDESCRIPTOR` (0x10 bytes).
#[repr(C)]
pub struct Kdescriptor {
    pub pad: [Field<u16>; 3],
    pub limit: Field<u16>,
    /// -> `void`
    pub base: Field<u64>,
}

unsafe impl NtStruct for Kdescriptor {}

const _: () = {
    assert!(core::mem::size_of::<Kdescriptor>() == 0x10);
    assert!(core::mem::offset_of!(Kdescriptor, pad) == 0x0);
    assert!(core::mem::offset_of!(Kdescriptor, limit) == 0x6);
    assert!(core::mem::offset_of!(Kdescriptor, base) == 0x8);
};

/// `_CONTEXT` (0x4d0 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ContextView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Context {
    pub p1_home: Field<u64>,
    pub p2_home: Field<u64>,
    pub p3_home: Field<u64>,
    pub p4_home: Field<u64>,
    pub p5_home: Field<u64>,
    pub p6_home: Field<u64>,
    pub context_flags: Field<u32>,
    pub mx_csr: Field<u32>,
    pub seg_cs: Field<u16>,
    pub seg_ds: Field<u16>,
    pub seg_es: Field<u16>,
    pub seg_fs: Field<u16>,
    pub seg_gs: Field<u16>,
    pub seg_ss: Field<u16>,
    pub e_flags: Field<u32>,
    pub dr0: Field<u64>,
    pub dr1: Field<u64>,
    pub dr2: Field<u64>,
    pub dr3: Field<u64>,
    pub dr6: Field<u64>,
    pub dr7: Field<u64>,
    pub rax: Field<u64>,
    pub rcx: Field<u64>,
    pub rdx: Field<u64>,
    pub rbx: Field<u64>,
    pub rsp: Field<u64>,
    pub rbp: Field<u64>,
    pub rsi: Field<u64>,
    pub rdi: Field<u64>,
    pub r8: Field<u64>,
    pub r9: Field<u64>,
    pub r10: Field<u64>,
    pub r11: Field<u64>,
    pub r12: Field<u64>,
    pub r13: Field<u64>,
    pub r14: Field<u64>,
    pub r15: Field<u64>,
    pub rip: Field<u64>,
    pub flt_save: XsaveFormat,
    pub vector_register: [M128a; 26],
    pub vector_control: Field<u64>,
    pub debug_control: Field<u64>,
    pub last_branch_to_rip: Field<u64>,
    pub last_branch_from_rip: Field<u64>,
    pub last_exception_to_rip: Field<u64>,
    pub last_exception_from_rip: Field<u64>,
}

/// Vista 1 de `_CONTEXT` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ContextView1 {
    _pad_0: Reserved<0x100>,
    pub header: [M128a; 2],
    pub legacy: [M128a; 8],
    pub xmm0: M128a,
    pub xmm1: M128a,
    pub xmm2: M128a,
    pub xmm3: M128a,
    pub xmm4: M128a,
    pub xmm5: M128a,
    pub xmm6: M128a,
    pub xmm7: M128a,
    pub xmm8: M128a,
    pub xmm9: M128a,
    pub xmm10: M128a,
    pub xmm11: M128a,
    pub xmm12: M128a,
    pub xmm13: M128a,
    pub xmm14: M128a,
    pub xmm15: M128a,
    _pad_2a0: Reserved<0x230>,
}

impl core::ops::Deref for Context {
    type Target = ContextView1;
    #[inline(always)]
    fn deref(&self) -> &ContextView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ContextView1>() }
    }
}

unsafe impl NtStruct for Context {}

const _: () = {
    assert!(core::mem::size_of::<Context>() == 0x4d0);
    assert!(core::mem::offset_of!(Context, p1_home) == 0x0);
    assert!(core::mem::offset_of!(Context, p2_home) == 0x8);
    assert!(core::mem::offset_of!(Context, p3_home) == 0x10);
    assert!(core::mem::offset_of!(Context, p4_home) == 0x18);
    assert!(core::mem::offset_of!(Context, p5_home) == 0x20);
    assert!(core::mem::offset_of!(Context, p6_home) == 0x28);
    assert!(core::mem::offset_of!(Context, context_flags) == 0x30);
    assert!(core::mem::offset_of!(Context, mx_csr) == 0x34);
    assert!(core::mem::offset_of!(Context, seg_cs) == 0x38);
    assert!(core::mem::offset_of!(Context, seg_ds) == 0x3a);
    assert!(core::mem::offset_of!(Context, seg_es) == 0x3c);
    assert!(core::mem::offset_of!(Context, seg_fs) == 0x3e);
    assert!(core::mem::offset_of!(Context, seg_gs) == 0x40);
    assert!(core::mem::offset_of!(Context, seg_ss) == 0x42);
    assert!(core::mem::offset_of!(Context, e_flags) == 0x44);
    assert!(core::mem::offset_of!(Context, dr0) == 0x48);
    assert!(core::mem::offset_of!(Context, dr1) == 0x50);
    assert!(core::mem::offset_of!(Context, dr2) == 0x58);
    assert!(core::mem::offset_of!(Context, dr3) == 0x60);
    assert!(core::mem::offset_of!(Context, dr6) == 0x68);
    assert!(core::mem::offset_of!(Context, dr7) == 0x70);
    assert!(core::mem::offset_of!(Context, rax) == 0x78);
    assert!(core::mem::offset_of!(Context, rcx) == 0x80);
    assert!(core::mem::offset_of!(Context, rdx) == 0x88);
    assert!(core::mem::offset_of!(Context, rbx) == 0x90);
    assert!(core::mem::offset_of!(Context, rsp) == 0x98);
    assert!(core::mem::offset_of!(Context, rbp) == 0xa0);
    assert!(core::mem::offset_of!(Context, rsi) == 0xa8);
    assert!(core::mem::offset_of!(Context, rdi) == 0xb0);
    assert!(core::mem::offset_of!(Context, r8) == 0xb8);
    assert!(core::mem::offset_of!(Context, r9) == 0xc0);
    assert!(core::mem::offset_of!(Context, r10) == 0xc8);
    assert!(core::mem::offset_of!(Context, r11) == 0xd0);
    assert!(core::mem::offset_of!(Context, r12) == 0xd8);
    assert!(core::mem::offset_of!(Context, r13) == 0xe0);
    assert!(core::mem::offset_of!(Context, r14) == 0xe8);
    assert!(core::mem::offset_of!(Context, r15) == 0xf0);
    assert!(core::mem::offset_of!(Context, rip) == 0xf8);
    assert!(core::mem::offset_of!(Context, flt_save) == 0x100);
    assert!(core::mem::offset_of!(Context, vector_register) == 0x300);
    assert!(core::mem::offset_of!(Context, vector_control) == 0x4a0);
    assert!(core::mem::offset_of!(Context, debug_control) == 0x4a8);
    assert!(core::mem::offset_of!(Context, last_branch_to_rip) == 0x4b0);
    assert!(core::mem::offset_of!(Context, last_branch_from_rip) == 0x4b8);
    assert!(core::mem::offset_of!(Context, last_exception_to_rip) == 0x4c0);
    assert!(core::mem::offset_of!(Context, last_exception_from_rip) == 0x4c8);
    assert!(core::mem::size_of::<ContextView1>() == 0x4d0);
    assert!(core::mem::align_of::<ContextView1>() == core::mem::align_of::<Context>());
    assert!(core::mem::offset_of!(ContextView1, header) == 0x100);
    assert!(core::mem::offset_of!(ContextView1, legacy) == 0x120);
    assert!(core::mem::offset_of!(ContextView1, xmm0) == 0x1a0);
    assert!(core::mem::offset_of!(ContextView1, xmm1) == 0x1b0);
    assert!(core::mem::offset_of!(ContextView1, xmm2) == 0x1c0);
    assert!(core::mem::offset_of!(ContextView1, xmm3) == 0x1d0);
    assert!(core::mem::offset_of!(ContextView1, xmm4) == 0x1e0);
    assert!(core::mem::offset_of!(ContextView1, xmm5) == 0x1f0);
    assert!(core::mem::offset_of!(ContextView1, xmm6) == 0x200);
    assert!(core::mem::offset_of!(ContextView1, xmm7) == 0x210);
    assert!(core::mem::offset_of!(ContextView1, xmm8) == 0x220);
    assert!(core::mem::offset_of!(ContextView1, xmm9) == 0x230);
    assert!(core::mem::offset_of!(ContextView1, xmm10) == 0x240);
    assert!(core::mem::offset_of!(ContextView1, xmm11) == 0x250);
    assert!(core::mem::offset_of!(ContextView1, xmm12) == 0x260);
    assert!(core::mem::offset_of!(ContextView1, xmm13) == 0x270);
    assert!(core::mem::offset_of!(ContextView1, xmm14) == 0x280);
    assert!(core::mem::offset_of!(ContextView1, xmm15) == 0x290);
};

/// `_XSAVE_FORMAT` (0x200 bytes).
#[repr(C)]
pub struct XsaveFormat {
    pub control_word: Field<u16>,
    pub status_word: Field<u16>,
    pub tag_word: Field<u8>,
    pub reserved1: Field<u8>,
    pub error_opcode: Field<u16>,
    pub error_offset: Field<u32>,
    pub error_selector: Field<u16>,
    pub reserved2: Field<u16>,
    pub data_offset: Field<u32>,
    pub data_selector: Field<u16>,
    pub reserved3: Field<u16>,
    pub mx_csr: Field<u32>,
    pub mx_csr_mask: Field<u32>,
    pub float_registers: [M128a; 8],
    pub xmm_registers: [M128a; 16],
    pub reserved4: [Field<u8>; 96],
}

unsafe impl NtStruct for XsaveFormat {}

const _: () = {
    assert!(core::mem::size_of::<XsaveFormat>() == 0x200);
    assert!(core::mem::offset_of!(XsaveFormat, control_word) == 0x0);
    assert!(core::mem::offset_of!(XsaveFormat, status_word) == 0x2);
    assert!(core::mem::offset_of!(XsaveFormat, tag_word) == 0x4);
    assert!(core::mem::offset_of!(XsaveFormat, reserved1) == 0x5);
    assert!(core::mem::offset_of!(XsaveFormat, error_opcode) == 0x6);
    assert!(core::mem::offset_of!(XsaveFormat, error_offset) == 0x8);
    assert!(core::mem::offset_of!(XsaveFormat, error_selector) == 0xc);
    assert!(core::mem::offset_of!(XsaveFormat, reserved2) == 0xe);
    assert!(core::mem::offset_of!(XsaveFormat, data_offset) == 0x10);
    assert!(core::mem::offset_of!(XsaveFormat, data_selector) == 0x14);
    assert!(core::mem::offset_of!(XsaveFormat, reserved3) == 0x16);
    assert!(core::mem::offset_of!(XsaveFormat, mx_csr) == 0x18);
    assert!(core::mem::offset_of!(XsaveFormat, mx_csr_mask) == 0x1c);
    assert!(core::mem::offset_of!(XsaveFormat, float_registers) == 0x20);
    assert!(core::mem::offset_of!(XsaveFormat, xmm_registers) == 0xa0);
    assert!(core::mem::offset_of!(XsaveFormat, reserved4) == 0x1a0);
};

/// `_KSPIN_LOCK_QUEUE` (0x10 bytes).
#[repr(C)]
pub struct KspinLockQueue {
    /// -> `_KSPIN_LOCK_QUEUE`
    pub next: Field<u64>,
    /// -> `u64`
    pub lock: Field<u64>,
}

unsafe impl NtStruct for KspinLockQueue {}

const _: () = {
    assert!(core::mem::size_of::<KspinLockQueue>() == 0x10);
    assert!(core::mem::offset_of!(KspinLockQueue, next) == 0x0);
    assert!(core::mem::offset_of!(KspinLockQueue, lock) == 0x8);
};

/// `_KSTATIC_AFFINITY_BLOCK` (0x2a0 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KstaticAffinityBlockView1`..`KstaticAffinityBlockView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct KstaticAffinityBlock {
    pub ke_flush_tb_affinity: KaffinityEx,
    pub ke_flush_tb_deep_idle_affinity: KaffinityEx,
    pub ke_ipi_send_affinity: KaffinityEx,
    pub ke_ipi_send_ipi_set: KaffinityEx,
}

/// Vista 1 de `_KSTATIC_AFFINITY_BLOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KstaticAffinityBlockView1 {
    pub ke_flush_wb_affinity: KaffinityEx,
    _pad_a8: Reserved<0x1f8>,
}

/// Vista 2 de `_KSTATIC_AFFINITY_BLOCK` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KstaticAffinityBlockView2 {
    pub ke_sync_context_affinity: KaffinityEx,
    _pad_a8: Reserved<0x1f8>,
}

impl core::ops::Deref for KstaticAffinityBlock {
    type Target = KstaticAffinityBlockView1;
    #[inline(always)]
    fn deref(&self) -> &KstaticAffinityBlockView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KstaticAffinityBlockView1>() }
    }
}

impl core::ops::Deref for KstaticAffinityBlockView1 {
    type Target = KstaticAffinityBlockView2;
    #[inline(always)]
    fn deref(&self) -> &KstaticAffinityBlockView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KstaticAffinityBlockView2>() }
    }
}

unsafe impl NtStruct for KstaticAffinityBlock {}

const _: () = {
    assert!(core::mem::size_of::<KstaticAffinityBlock>() == 0x2a0);
    assert!(core::mem::offset_of!(KstaticAffinityBlock, ke_flush_tb_affinity) == 0x0);
    assert!(core::mem::offset_of!(KstaticAffinityBlock, ke_flush_tb_deep_idle_affinity) == 0xa8);
    assert!(core::mem::offset_of!(KstaticAffinityBlock, ke_ipi_send_affinity) == 0x150);
    assert!(core::mem::offset_of!(KstaticAffinityBlock, ke_ipi_send_ipi_set) == 0x1f8);
    assert!(core::mem::size_of::<KstaticAffinityBlockView1>() == 0x2a0);
    assert!(core::mem::align_of::<KstaticAffinityBlockView1>() == core::mem::align_of::<KstaticAffinityBlock>());
    assert!(core::mem::offset_of!(KstaticAffinityBlockView1, ke_flush_wb_affinity) == 0x0);
    assert!(core::mem::size_of::<KstaticAffinityBlockView2>() == 0x2a0);
    assert!(core::mem::align_of::<KstaticAffinityBlockView2>() == core::mem::align_of::<KstaticAffinityBlock>());
    assert!(core::mem::offset_of!(KstaticAffinityBlockView2, ke_sync_context_affinity) == 0x0);
};

/// `_KDPC_DATA` (0x28 bytes).
#[repr(C)]
pub struct KdpcData {
    pub dpc_list: KdpcList,
    pub dpc_lock: Field<u64>,
    pub dpc_queue_depth: Field<i32>,
    pub dpc_count: Field<u32>,
    /// -> `_KDPC`
    pub active_dpc: Field<u64>,
}

unsafe impl NtStruct for KdpcData {}

const _: () = {
    assert!(core::mem::size_of::<KdpcData>() == 0x28);
    assert!(core::mem::offset_of!(KdpcData, dpc_list) == 0x0);
    assert!(core::mem::offset_of!(KdpcData, dpc_lock) == 0x10);
    assert!(core::mem::offset_of!(KdpcData, dpc_queue_depth) == 0x18);
    assert!(core::mem::offset_of!(KdpcData, dpc_count) == 0x1c);
    assert!(core::mem::offset_of!(KdpcData, active_dpc) == 0x20);
};

/// `_KDPC_LIST` (0x10 bytes).
#[repr(C)]
pub struct KdpcList {
    pub list_head: SingleListEntry,
    /// -> `_SINGLE_LIST_ENTRY`
    pub last_entry: Field<u64>,
}

unsafe impl NtStruct for KdpcList {}

const _: () = {
    assert!(core::mem::size_of::<KdpcList>() == 0x10);
    assert!(core::mem::offset_of!(KdpcList, list_head) == 0x0);
    assert!(core::mem::offset_of!(KdpcList, last_entry) == 0x8);
};

/// `_KTIMER_TABLE` (0x4218 bytes).
#[repr(C)]
pub struct KtimerTable {
    /// -> `_KTIMER`
    pub timer_expiry: [Field<u64>; 64],
    pub timer_entries: [[KtimerTableEntry; 256]; 2],
    pub table_state: KtimerTableState,
}

unsafe impl NtStruct for KtimerTable {}

const _: () = {
    assert!(core::mem::size_of::<KtimerTable>() == 0x4218);
    assert!(core::mem::offset_of!(KtimerTable, timer_expiry) == 0x0);
    assert!(core::mem::offset_of!(KtimerTable, timer_entries) == 0x200);
    assert!(core::mem::offset_of!(KtimerTable, table_state) == 0x4200);
};

/// `_KTIMER_TABLE_ENTRY` (0x20 bytes).
#[repr(C)]
pub struct KtimerTableEntry {
    pub lock: Field<u64>,
    pub entry: ListEntry,
    pub time: UlargeInteger,
}

unsafe impl NtStruct for KtimerTableEntry {}

const _: () = {
    assert!(core::mem::size_of::<KtimerTableEntry>() == 0x20);
    assert!(core::mem::offset_of!(KtimerTableEntry, lock) == 0x0);
    assert!(core::mem::offset_of!(KtimerTableEntry, entry) == 0x8);
    assert!(core::mem::offset_of!(KtimerTableEntry, time) == 0x18);
};

/// `_KTIMER_TABLE_STATE` (0x18 bytes).
#[repr(C)]
pub struct KtimerTableState {
    pub last_timer_expiration: [Field<u64>; 2],
    pub last_timer_hand: [Field<u32>; 2],
}

unsafe impl NtStruct for KtimerTableState {}

const _: () = {
    assert!(core::mem::size_of::<KtimerTableState>() == 0x18);
    assert!(core::mem::offset_of!(KtimerTableState, last_timer_expiration) == 0x0);
    assert!(core::mem::offset_of!(KtimerTableState, last_timer_hand) == 0x10);
};

/// `_KGATE` (0x18 bytes).
#[repr(C)]
pub struct Kgate {
    pub header: DispatcherHeader,
}

unsafe impl NtStruct for Kgate {}

const _: () = {
    assert!(core::mem::size_of::<Kgate>() == 0x18);
    assert!(core::mem::offset_of!(Kgate, header) == 0x0);
};

/// `_KHETERO_CPU_QOS`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct KheteroCpuQos(pub i32);

impl KheteroCpuQos {
    pub const K_HETERO_CPU_QOS_DEFAULT: Self = Self(0);
    pub const K_HETERO_CPU_QOS_HIGH: Self = Self(0);
    pub const K_HETERO_CPU_QOS_MEDIUM: Self = Self(1);
    pub const K_HETERO_CPU_QOS_LOW: Self = Self(2);
    pub const K_HETERO_CPU_QOS_MULTIMEDIA: Self = Self(3);
    pub const K_HETERO_CPU_QOS_DEADLINE: Self = Self(4);
    pub const K_HETERO_CPU_QOS_DYNAMIC: Self = Self(5);
    pub const K_HETERO_CPU_QOS_MAX: Self = Self(5);
}

/// `_CACHE_DESCRIPTOR` (0xc bytes).
#[repr(C)]
pub struct CacheDescriptor {
    pub level: Field<u8>,
    pub associativity: Field<u8>,
    pub line_size: Field<u16>,
    pub size: Field<u32>,
    pub type_: Field<ProcessorCacheType>,
}

unsafe impl NtStruct for CacheDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<CacheDescriptor>() == 0xc);
    assert!(core::mem::offset_of!(CacheDescriptor, level) == 0x0);
    assert!(core::mem::offset_of!(CacheDescriptor, associativity) == 0x1);
    assert!(core::mem::offset_of!(CacheDescriptor, line_size) == 0x2);
    assert!(core::mem::offset_of!(CacheDescriptor, size) == 0x4);
    assert!(core::mem::offset_of!(CacheDescriptor, type_) == 0x8);
};

/// `_PROCESSOR_CACHE_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ProcessorCacheType(pub i32);

impl ProcessorCacheType {
    pub const CACHE_UNIFIED: Self = Self(0);
    pub const CACHE_INSTRUCTION: Self = Self(1);
    pub const CACHE_DATA: Self = Self(2);
    pub const CACHE_TRACE: Self = Self(3);
}

/// `_SYNCH_COUNTERS` (0xb8 bytes).
#[repr(C)]
pub struct SynchCounters {
    pub spin_lock_acquire_count: Field<u32>,
    pub spin_lock_contention_count: Field<u32>,
    pub spin_lock_spin_count: Field<u32>,
    pub ipi_send_request_broadcast_count: Field<u32>,
    pub ipi_send_request_routine_count: Field<u32>,
    pub ipi_send_software_interrupt_count: Field<u32>,
    pub ex_initialize_resource_count: Field<u32>,
    pub ex_re_initialize_resource_count: Field<u32>,
    pub ex_delete_resource_count: Field<u32>,
    pub executive_resource_acquires_count: Field<u32>,
    pub executive_resource_contentions_count: Field<u32>,
    pub executive_resource_release_exclusive_count: Field<u32>,
    pub executive_resource_release_shared_count: Field<u32>,
    pub executive_resource_converts_count: Field<u32>,
    pub ex_acq_res_exclusive_attempts: Field<u32>,
    pub ex_acq_res_exclusive_acquires_exclusive: Field<u32>,
    pub ex_acq_res_exclusive_acquires_exclusive_recursive: Field<u32>,
    pub ex_acq_res_exclusive_waits: Field<u32>,
    pub ex_acq_res_exclusive_not_acquires: Field<u32>,
    pub ex_acq_res_shared_attempts: Field<u32>,
    pub ex_acq_res_shared_acquires_exclusive: Field<u32>,
    pub ex_acq_res_shared_acquires_shared: Field<u32>,
    pub ex_acq_res_shared_acquires_shared_recursive: Field<u32>,
    pub ex_acq_res_shared_waits: Field<u32>,
    pub ex_acq_res_shared_not_acquires: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_attempts: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_acquires_exclusive: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_acquires_shared: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_acquires_shared_recursive: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_waits: Field<u32>,
    pub ex_acq_res_shared_starve_exclusive_not_acquires: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_attempts: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_acquires_exclusive: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_acquires_shared: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_acquires_shared_recursive: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_waits: Field<u32>,
    pub ex_acq_res_shared_wait_for_exclusive_not_acquires: Field<u32>,
    pub ex_set_res_owner_pointer_exclusive: Field<u32>,
    pub ex_set_res_owner_pointer_shared_new: Field<u32>,
    pub ex_set_res_owner_pointer_shared_old: Field<u32>,
    pub ex_try_to_acq_exclusive_attempts: Field<u32>,
    pub ex_try_to_acq_exclusive_acquires: Field<u32>,
    pub ex_boost_exclusive_owner: Field<u32>,
    pub ex_boost_shared_owners: Field<u32>,
    pub ex_etw_synch_tracking_notifications_count: Field<u32>,
    pub ex_etw_synch_tracking_notifications_accounted_count: Field<u32>,
}

unsafe impl NtStruct for SynchCounters {}

const _: () = {
    assert!(core::mem::size_of::<SynchCounters>() == 0xb8);
    assert!(core::mem::offset_of!(SynchCounters, spin_lock_acquire_count) == 0x0);
    assert!(core::mem::offset_of!(SynchCounters, spin_lock_contention_count) == 0x4);
    assert!(core::mem::offset_of!(SynchCounters, spin_lock_spin_count) == 0x8);
    assert!(core::mem::offset_of!(SynchCounters, ipi_send_request_broadcast_count) == 0xc);
    assert!(core::mem::offset_of!(SynchCounters, ipi_send_request_routine_count) == 0x10);
    assert!(core::mem::offset_of!(SynchCounters, ipi_send_software_interrupt_count) == 0x14);
    assert!(core::mem::offset_of!(SynchCounters, ex_initialize_resource_count) == 0x18);
    assert!(core::mem::offset_of!(SynchCounters, ex_re_initialize_resource_count) == 0x1c);
    assert!(core::mem::offset_of!(SynchCounters, ex_delete_resource_count) == 0x20);
    assert!(core::mem::offset_of!(SynchCounters, executive_resource_acquires_count) == 0x24);
    assert!(core::mem::offset_of!(SynchCounters, executive_resource_contentions_count) == 0x28);
    assert!(core::mem::offset_of!(SynchCounters, executive_resource_release_exclusive_count) == 0x2c);
    assert!(core::mem::offset_of!(SynchCounters, executive_resource_release_shared_count) == 0x30);
    assert!(core::mem::offset_of!(SynchCounters, executive_resource_converts_count) == 0x34);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_exclusive_attempts) == 0x38);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_exclusive_acquires_exclusive) == 0x3c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_exclusive_acquires_exclusive_recursive) == 0x40);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_exclusive_waits) == 0x44);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_exclusive_not_acquires) == 0x48);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_attempts) == 0x4c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_acquires_exclusive) == 0x50);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_acquires_shared) == 0x54);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_acquires_shared_recursive) == 0x58);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_waits) == 0x5c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_not_acquires) == 0x60);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_attempts) == 0x64);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_acquires_exclusive) == 0x68);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_acquires_shared) == 0x6c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_acquires_shared_recursive) == 0x70);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_waits) == 0x74);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_starve_exclusive_not_acquires) == 0x78);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_attempts) == 0x7c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_acquires_exclusive) == 0x80);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_acquires_shared) == 0x84);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_acquires_shared_recursive) == 0x88);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_waits) == 0x8c);
    assert!(core::mem::offset_of!(SynchCounters, ex_acq_res_shared_wait_for_exclusive_not_acquires) == 0x90);
    assert!(core::mem::offset_of!(SynchCounters, ex_set_res_owner_pointer_exclusive) == 0x94);
    assert!(core::mem::offset_of!(SynchCounters, ex_set_res_owner_pointer_shared_new) == 0x98);
    assert!(core::mem::offset_of!(SynchCounters, ex_set_res_owner_pointer_shared_old) == 0x9c);
    assert!(core::mem::offset_of!(SynchCounters, ex_try_to_acq_exclusive_attempts) == 0xa0);
    assert!(core::mem::offset_of!(SynchCounters, ex_try_to_acq_exclusive_acquires) == 0xa4);
    assert!(core::mem::offset_of!(SynchCounters, ex_boost_exclusive_owner) == 0xa8);
    assert!(core::mem::offset_of!(SynchCounters, ex_boost_shared_owners) == 0xac);
    assert!(core::mem::offset_of!(SynchCounters, ex_etw_synch_tracking_notifications_count) == 0xb0);
    assert!(core::mem::offset_of!(SynchCounters, ex_etw_synch_tracking_notifications_accounted_count) == 0xb4);
};

/// `_FILESYSTEM_DISK_COUNTERS` (0x10 bytes).
#[repr(C)]
pub struct FilesystemDiskCounters {
    pub fs_bytes_read: Field<u64>,
    pub fs_bytes_written: Field<u64>,
}

unsafe impl NtStruct for FilesystemDiskCounters {}

const _: () = {
    assert!(core::mem::size_of::<FilesystemDiskCounters>() == 0x10);
    assert!(core::mem::offset_of!(FilesystemDiskCounters, fs_bytes_read) == 0x0);
    assert!(core::mem::offset_of!(FilesystemDiskCounters, fs_bytes_written) == 0x8);
};

/// `_KENTROPY_TIMING_STATE` (0x150 bytes).
#[repr(C)]
pub struct KentropyTimingState {
    pub entropy_count: Field<u32>,
    pub buffer: [Field<u32>; 64],
    _pad_104: Reserved<0x4>,
    pub dpc: Kdpc,
    pub last_delivered_buffer: Field<u32>,
    _pad_14c: Reserved<0x4>,
}

unsafe impl NtStruct for KentropyTimingState {}

const _: () = {
    assert!(core::mem::size_of::<KentropyTimingState>() == 0x150);
    assert!(core::mem::offset_of!(KentropyTimingState, entropy_count) == 0x0);
    assert!(core::mem::offset_of!(KentropyTimingState, buffer) == 0x4);
    assert!(core::mem::offset_of!(KentropyTimingState, dpc) == 0x108);
    assert!(core::mem::offset_of!(KentropyTimingState, last_delivered_buffer) == 0x148);
};

/// `_KPRCB::StibpPairingTrace` (0x38 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KprcbStibpPairingTraceView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KprcbStibpPairingTrace {
    pub update_cycle: Field<u32>,
    pub pair_local: Field<i16>,
    pub pair_remote: Field<i16>,
    pub trace: [Field<u8>; 24],
    pub local_domain: Field<u64>,
    pub remote_domain: Field<u64>,
    /// -> `_KTHREAD`
    pub thread: Field<u64>,
}

/// Vista 1 de `_KPRCB::StibpPairingTrace` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KprcbStibpPairingTraceView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x4>,
    pub pair_local_low: Field<u8>,
    pub bitfield_5: Field<u8>,
    pub pair_remote_low: Field<u8>,
    pub reserved2: Field<u8>,
    _pad_8: Reserved<0x30>,
}

impl core::ops::Deref for KprcbStibpPairingTrace {
    type Target = KprcbStibpPairingTraceView1;
    #[inline(always)]
    fn deref(&self) -> &KprcbStibpPairingTraceView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KprcbStibpPairingTraceView1>() }
    }
}

unsafe impl NtStruct for KprcbStibpPairingTrace {}

impl KprcbStibpPairingTrace {
    /// `PairLocalForceStibp`: bits 0..=0 de `bitfield_5`.
    pub const PAIR_LOCAL_FORCE_STIBP_SHIFT: u32 = 0;
    pub const PAIR_LOCAL_FORCE_STIBP_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn pair_local_force_stibp(&self) -> u8 {
        self.bitfield_5.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_pair_local_force_stibp(&self, value: u8) {
        self.bitfield_5.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=4 de `bitfield_5`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u8 = 0x1e;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.bitfield_5.bits(1, 4) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.bitfield_5.set_bits(1, 4, value as u64)
    }
    /// `Frozen`: bits 5..=5 de `bitfield_5`.
    pub const FROZEN_SHIFT: u32 = 5;
    pub const FROZEN_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn frozen(&self) -> u8 {
        self.bitfield_5.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_frozen(&self, value: u8) {
        self.bitfield_5.set_bits(5, 1, value as u64)
    }
    /// `ForceUntrusted`: bits 6..=6 de `bitfield_5`.
    pub const FORCE_UNTRUSTED_SHIFT: u32 = 6;
    pub const FORCE_UNTRUSTED_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn force_untrusted(&self) -> u8 {
        self.bitfield_5.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_force_untrusted(&self, value: u8) {
        self.bitfield_5.set_bits(6, 1, value as u64)
    }
    /// `SynchIpi`: bits 7..=7 de `bitfield_5`.
    pub const SYNCH_IPI_SHIFT: u32 = 7;
    pub const SYNCH_IPI_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn synch_ipi(&self) -> u8 {
        self.bitfield_5.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_synch_ipi(&self, value: u8) {
        self.bitfield_5.set_bits(7, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KprcbStibpPairingTrace>() == 0x38);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, update_cycle) == 0x0);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, pair_local) == 0x4);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, pair_remote) == 0x6);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, trace) == 0x8);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, local_domain) == 0x20);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, remote_domain) == 0x28);
    assert!(core::mem::offset_of!(KprcbStibpPairingTrace, thread) == 0x30);
    assert!(core::mem::size_of::<KprcbStibpPairingTraceView1>() == 0x38);
    assert!(core::mem::align_of::<KprcbStibpPairingTraceView1>() == core::mem::align_of::<KprcbStibpPairingTrace>());
    assert!(core::mem::offset_of!(KprcbStibpPairingTraceView1, pair_local_low) == 0x4);
    assert!(core::mem::offset_of!(KprcbStibpPairingTraceView1, bitfield_5) == 0x5);
    assert!(core::mem::offset_of!(KprcbStibpPairingTraceView1, pair_remote_low) == 0x6);
    assert!(core::mem::offset_of!(KprcbStibpPairingTraceView1, reserved2) == 0x7);
};

/// `_KSECURE_FAULT_INFORMATION` (0x10 bytes).
#[repr(C)]
pub struct KsecureFaultInformation {
    pub fault_code: Field<u64>,
    pub fault_va: Field<u64>,
}

unsafe impl NtStruct for KsecureFaultInformation {}

const _: () = {
    assert!(core::mem::size_of::<KsecureFaultInformation>() == 0x10);
    assert!(core::mem::offset_of!(KsecureFaultInformation, fault_code) == 0x0);
    assert!(core::mem::offset_of!(KsecureFaultInformation, fault_va) == 0x8);
};

/// `_KSHARED_READY_QUEUE` (0x270 bytes).
#[repr(C)]
pub struct KsharedReadyQueue {
    pub lock: Field<u64>,
    pub ready_summary: Field<u32>,
    _pad_c: Reserved<0x4>,
    pub ready_list_head: [ListEntry; 32],
    pub running_summary: [Field<i8>; 64],
    pub span: Field<u8>,
    pub low_proc_index: Field<u8>,
    pub queue_index: Field<u8>,
    pub proc_count: Field<u8>,
    pub scan_owner: Field<u8>,
    pub spare: [Field<u8>; 3],
    pub affinity: Field<u64>,
    pub ready_thread_count: Field<u32>,
    _pad_264: Reserved<0x4>,
    pub ready_queue_expected_run_time: Field<u64>,
}

unsafe impl NtStruct for KsharedReadyQueue {}

const _: () = {
    assert!(core::mem::size_of::<KsharedReadyQueue>() == 0x270);
    assert!(core::mem::offset_of!(KsharedReadyQueue, lock) == 0x0);
    assert!(core::mem::offset_of!(KsharedReadyQueue, ready_summary) == 0x8);
    assert!(core::mem::offset_of!(KsharedReadyQueue, ready_list_head) == 0x10);
    assert!(core::mem::offset_of!(KsharedReadyQueue, running_summary) == 0x210);
    assert!(core::mem::offset_of!(KsharedReadyQueue, span) == 0x250);
    assert!(core::mem::offset_of!(KsharedReadyQueue, low_proc_index) == 0x251);
    assert!(core::mem::offset_of!(KsharedReadyQueue, queue_index) == 0x252);
    assert!(core::mem::offset_of!(KsharedReadyQueue, proc_count) == 0x253);
    assert!(core::mem::offset_of!(KsharedReadyQueue, scan_owner) == 0x254);
    assert!(core::mem::offset_of!(KsharedReadyQueue, spare) == 0x255);
    assert!(core::mem::offset_of!(KsharedReadyQueue, affinity) == 0x258);
    assert!(core::mem::offset_of!(KsharedReadyQueue, ready_thread_count) == 0x260);
    assert!(core::mem::offset_of!(KsharedReadyQueue, ready_queue_expected_run_time) == 0x268);
};

/// `_KTIMER_EXPIRATION_TRACE` (0x10 bytes).
#[repr(C)]
pub struct KtimerExpirationTrace {
    pub interrupt_time: Field<u64>,
    pub performance_counter: LargeInteger,
}

unsafe impl NtStruct for KtimerExpirationTrace {}

const _: () = {
    assert!(core::mem::size_of::<KtimerExpirationTrace>() == 0x10);
    assert!(core::mem::offset_of!(KtimerExpirationTrace, interrupt_time) == 0x0);
    assert!(core::mem::offset_of!(KtimerExpirationTrace, performance_counter) == 0x8);
};

/// `_MACHINE_CHECK_CONTEXT` (0x50 bytes).
#[repr(C)]
pub struct MachineCheckContext {
    pub machine_frame: MachineFrame,
    pub rax: Field<u64>,
    pub rcx: Field<u64>,
    pub rdx: Field<u64>,
    pub gs_base: Field<u64>,
    pub cr3: Field<u64>,
}

unsafe impl NtStruct for MachineCheckContext {}

const _: () = {
    assert!(core::mem::size_of::<MachineCheckContext>() == 0x50);
    assert!(core::mem::offset_of!(MachineCheckContext, machine_frame) == 0x0);
    assert!(core::mem::offset_of!(MachineCheckContext, rax) == 0x28);
    assert!(core::mem::offset_of!(MachineCheckContext, rcx) == 0x30);
    assert!(core::mem::offset_of!(MachineCheckContext, rdx) == 0x38);
    assert!(core::mem::offset_of!(MachineCheckContext, gs_base) == 0x40);
    assert!(core::mem::offset_of!(MachineCheckContext, cr3) == 0x48);
};

/// `_MACHINE_FRAME` (0x28 bytes).
#[repr(C)]
pub struct MachineFrame {
    pub rip: Field<u64>,
    pub seg_cs: Field<u16>,
    pub fill1: [Field<u16>; 3],
    pub e_flags: Field<u32>,
    pub fill2: Field<u32>,
    pub rsp: Field<u64>,
    pub seg_ss: Field<u16>,
    pub fill3: [Field<u16>; 3],
}

unsafe impl NtStruct for MachineFrame {}

const _: () = {
    assert!(core::mem::size_of::<MachineFrame>() == 0x28);
    assert!(core::mem::offset_of!(MachineFrame, rip) == 0x0);
    assert!(core::mem::offset_of!(MachineFrame, seg_cs) == 0x8);
    assert!(core::mem::offset_of!(MachineFrame, fill1) == 0xa);
    assert!(core::mem::offset_of!(MachineFrame, e_flags) == 0x10);
    assert!(core::mem::offset_of!(MachineFrame, fill2) == 0x14);
    assert!(core::mem::offset_of!(MachineFrame, rsp) == 0x18);
    assert!(core::mem::offset_of!(MachineFrame, seg_ss) == 0x20);
    assert!(core::mem::offset_of!(MachineFrame, fill3) == 0x22);
};

/// `_KLOCK_QUEUE_HANDLE` (0x18 bytes).
#[repr(C)]
pub struct KlockQueueHandle {
    pub lock_queue: KspinLockQueue,
    pub old_irql: Field<u8>,
    _pad_11: Reserved<0x7>,
}

unsafe impl NtStruct for KlockQueueHandle {}

const _: () = {
    assert!(core::mem::size_of::<KlockQueueHandle>() == 0x18);
    assert!(core::mem::offset_of!(KlockQueueHandle, lock_queue) == 0x0);
    assert!(core::mem::offset_of!(KlockQueueHandle, old_irql) == 0x10);
};

/// `_REQUEST_MAILBOX` (0x40 bytes).
#[repr(C)]
pub struct RequestMailbox {
    /// -> `_REQUEST_MAILBOX`
    pub next: Field<u64>,
    pub request_summary: Field<u64>,
    pub request_packet: KrequestPacket,
    /// -> `i32`
    pub node_target_count_addr: Field<u64>,
    pub node_target_count: Field<i32>,
    _pad_3c: Reserved<0x4>,
}

unsafe impl NtStruct for RequestMailbox {}

const _: () = {
    assert!(core::mem::size_of::<RequestMailbox>() == 0x40);
    assert!(core::mem::offset_of!(RequestMailbox, next) == 0x0);
    assert!(core::mem::offset_of!(RequestMailbox, request_summary) == 0x8);
    assert!(core::mem::offset_of!(RequestMailbox, request_packet) == 0x10);
    assert!(core::mem::offset_of!(RequestMailbox, node_target_count_addr) == 0x30);
    assert!(core::mem::offset_of!(RequestMailbox, node_target_count) == 0x38);
};

/// `_KREQUEST_PACKET` (0x20 bytes).
#[repr(C)]
pub struct KrequestPacket {
    /// -> `void`
    pub current_packet: [Field<u64>; 3],
    /// -> `fn`
    pub worker_routine: Field<u64>,
}

unsafe impl NtStruct for KrequestPacket {}

const _: () = {
    assert!(core::mem::size_of::<KrequestPacket>() == 0x20);
    assert!(core::mem::offset_of!(KrequestPacket, current_packet) == 0x0);
    assert!(core::mem::offset_of!(KrequestPacket, worker_routine) == 0x18);
};

/// `_KQUEUE` (0x40 bytes).
#[repr(C)]
pub struct Kqueue {
    pub header: DispatcherHeader,
    pub entry_list_head: ListEntry,
    pub current_count: Field<u32>,
    pub maximum_count: Field<u32>,
    pub thread_list_head: ListEntry,
}

unsafe impl NtStruct for Kqueue {}

const _: () = {
    assert!(core::mem::size_of::<Kqueue>() == 0x40);
    assert!(core::mem::offset_of!(Kqueue, header) == 0x0);
    assert!(core::mem::offset_of!(Kqueue, entry_list_head) == 0x18);
    assert!(core::mem::offset_of!(Kqueue, current_count) == 0x28);
    assert!(core::mem::offset_of!(Kqueue, maximum_count) == 0x2c);
    assert!(core::mem::offset_of!(Kqueue, thread_list_head) == 0x30);
};

/// `_PROCESSOR_NUMBER` (0x4 bytes).
#[repr(C)]
pub struct ProcessorNumber {
    pub group: Field<u16>,
    pub number: Field<u8>,
    pub reserved: Field<u8>,
}

unsafe impl NtStruct for ProcessorNumber {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorNumber>() == 0x4);
    assert!(core::mem::offset_of!(ProcessorNumber, group) == 0x0);
    assert!(core::mem::offset_of!(ProcessorNumber, number) == 0x2);
    assert!(core::mem::offset_of!(ProcessorNumber, reserved) == 0x3);
};

/// `_KTRAP_FRAME` (0x190 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KtrapFrameView1`, alcançada por `Deref`.
#[repr(C)]
pub struct KtrapFrame {
    pub p1_home: Field<u64>,
    pub p2_home: Field<u64>,
    pub p3_home: Field<u64>,
    pub p4_home: Field<u64>,
    pub p5: Field<u64>,
    pub previous_mode: Field<i8>,
    pub previous_irql: Field<u8>,
    pub fault_indicator: Field<u8>,
    pub exception_active: Field<u8>,
    pub mx_csr: Field<u32>,
    pub rax: Field<u64>,
    pub rcx: Field<u64>,
    pub rdx: Field<u64>,
    pub r8: Field<u64>,
    pub r9: Field<u64>,
    pub r10: Field<u64>,
    pub r11: Field<u64>,
    pub gs_base: Field<u64>,
    pub xmm0: M128a,
    pub xmm1: M128a,
    pub xmm2: M128a,
    pub xmm3: M128a,
    pub xmm4: M128a,
    pub xmm5: M128a,
    pub fault_address: Field<u64>,
    pub dr0: Field<u64>,
    pub dr1: Field<u64>,
    pub dr2: Field<u64>,
    pub dr3: Field<u64>,
    pub dr6: Field<u64>,
    pub dr7: Field<u64>,
    pub debug_control: Field<u64>,
    pub last_branch_to_rip: Field<u64>,
    pub last_branch_from_rip: Field<u64>,
    pub last_exception_to_rip: Field<u64>,
    pub last_exception_from_rip: Field<u64>,
    pub seg_ds: Field<u16>,
    pub seg_es: Field<u16>,
    pub seg_fs: Field<u16>,
    pub seg_gs: Field<u16>,
    pub trap_frame: Field<u64>,
    pub nmi_previous_spec_ctrl: Field<u32>,
    pub nmi_previous_spec_ctrl_pad: Field<u32>,
    pub rdi: Field<u64>,
    pub rsi: Field<u64>,
    pub rbp: Field<u64>,
    pub error_code: Field<u64>,
    pub rip: Field<u64>,
    pub seg_cs: Field<u16>,
    pub fill0: Field<u8>,
    pub logging: Field<u8>,
    pub fill1: [Field<u16>; 2],
    pub e_flags: Field<u32>,
    pub fill2: Field<u32>,
    pub rsp: Field<u64>,
    pub seg_ss: Field<u16>,
    pub fill3: Field<u16>,
    pub fill4: Field<u32>,
}

/// Vista 1 de `_KTRAP_FRAME` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KtrapFrameView1 {
    _pad_0: Reserved<0x28>,
    pub interrupt_retpoline_state: Field<u8>,
    _pad_29: Reserved<0x1>,
    pub nmi_msr_ibrs: Field<u8>,
    _pad_2b: Reserved<0x3d>,
    pub gs_swap: Field<u64>,
    _pad_70: Reserved<0x60>,
    pub context_record: Field<u64>,
    _pad_d8: Reserved<0x68>,
    pub rbx: Field<u64>,
    _pad_148: Reserved<0x18>,
    pub exception_frame: Field<u64>,
    _pad_168: Reserved<0x28>,
}

impl core::ops::Deref for KtrapFrame {
    type Target = KtrapFrameView1;
    #[inline(always)]
    fn deref(&self) -> &KtrapFrameView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KtrapFrameView1>() }
    }
}

unsafe impl NtStruct for KtrapFrame {}

const _: () = {
    assert!(core::mem::size_of::<KtrapFrame>() == 0x190);
    assert!(core::mem::offset_of!(KtrapFrame, p1_home) == 0x0);
    assert!(core::mem::offset_of!(KtrapFrame, p2_home) == 0x8);
    assert!(core::mem::offset_of!(KtrapFrame, p3_home) == 0x10);
    assert!(core::mem::offset_of!(KtrapFrame, p4_home) == 0x18);
    assert!(core::mem::offset_of!(KtrapFrame, p5) == 0x20);
    assert!(core::mem::offset_of!(KtrapFrame, previous_mode) == 0x28);
    assert!(core::mem::offset_of!(KtrapFrame, previous_irql) == 0x29);
    assert!(core::mem::offset_of!(KtrapFrame, fault_indicator) == 0x2a);
    assert!(core::mem::offset_of!(KtrapFrame, exception_active) == 0x2b);
    assert!(core::mem::offset_of!(KtrapFrame, mx_csr) == 0x2c);
    assert!(core::mem::offset_of!(KtrapFrame, rax) == 0x30);
    assert!(core::mem::offset_of!(KtrapFrame, rcx) == 0x38);
    assert!(core::mem::offset_of!(KtrapFrame, rdx) == 0x40);
    assert!(core::mem::offset_of!(KtrapFrame, r8) == 0x48);
    assert!(core::mem::offset_of!(KtrapFrame, r9) == 0x50);
    assert!(core::mem::offset_of!(KtrapFrame, r10) == 0x58);
    assert!(core::mem::offset_of!(KtrapFrame, r11) == 0x60);
    assert!(core::mem::offset_of!(KtrapFrame, gs_base) == 0x68);
    assert!(core::mem::offset_of!(KtrapFrame, xmm0) == 0x70);
    assert!(core::mem::offset_of!(KtrapFrame, xmm1) == 0x80);
    assert!(core::mem::offset_of!(KtrapFrame, xmm2) == 0x90);
    assert!(core::mem::offset_of!(KtrapFrame, xmm3) == 0xa0);
    assert!(core::mem::offset_of!(KtrapFrame, xmm4) == 0xb0);
    assert!(core::mem::offset_of!(KtrapFrame, xmm5) == 0xc0);
    assert!(core::mem::offset_of!(KtrapFrame, fault_address) == 0xd0);
    assert!(core::mem::offset_of!(KtrapFrame, dr0) == 0xd8);
    assert!(core::mem::offset_of!(KtrapFrame, dr1) == 0xe0);
    assert!(core::mem::offset_of!(KtrapFrame, dr2) == 0xe8);
    assert!(core::mem::offset_of!(KtrapFrame, dr3) == 0xf0);
    assert!(core::mem::offset_of!(KtrapFrame, dr6) == 0xf8);
    assert!(core::mem::offset_of!(KtrapFrame, dr7) == 0x100);
    assert!(core::mem::offset_of!(KtrapFrame, debug_control) == 0x108);
    assert!(core::mem::offset_of!(KtrapFrame, last_branch_to_rip) == 0x110);
    assert!(core::mem::offset_of!(KtrapFrame, last_branch_from_rip) == 0x118);
    assert!(core::mem::offset_of!(KtrapFrame, last_exception_to_rip) == 0x120);
    assert!(core::mem::offset_of!(KtrapFrame, last_exception_from_rip) == 0x128);
    assert!(core::mem::offset_of!(KtrapFrame, seg_ds) == 0x130);
    assert!(core::mem::offset_of!(KtrapFrame, seg_es) == 0x132);
    assert!(core::mem::offset_of!(KtrapFrame, seg_fs) == 0x134);
    assert!(core::mem::offset_of!(KtrapFrame, seg_gs) == 0x136);
    assert!(core::mem::offset_of!(KtrapFrame, trap_frame) == 0x138);
    assert!(core::mem::offset_of!(KtrapFrame, nmi_previous_spec_ctrl) == 0x140);
    assert!(core::mem::offset_of!(KtrapFrame, nmi_previous_spec_ctrl_pad) == 0x144);
    assert!(core::mem::offset_of!(KtrapFrame, rdi) == 0x148);
    assert!(core::mem::offset_of!(KtrapFrame, rsi) == 0x150);
    assert!(core::mem::offset_of!(KtrapFrame, rbp) == 0x158);
    assert!(core::mem::offset_of!(KtrapFrame, error_code) == 0x160);
    assert!(core::mem::offset_of!(KtrapFrame, rip) == 0x168);
    assert!(core::mem::offset_of!(KtrapFrame, seg_cs) == 0x170);
    assert!(core::mem::offset_of!(KtrapFrame, fill0) == 0x172);
    assert!(core::mem::offset_of!(KtrapFrame, logging) == 0x173);
    assert!(core::mem::offset_of!(KtrapFrame, fill1) == 0x174);
    assert!(core::mem::offset_of!(KtrapFrame, e_flags) == 0x178);
    assert!(core::mem::offset_of!(KtrapFrame, fill2) == 0x17c);
    assert!(core::mem::offset_of!(KtrapFrame, rsp) == 0x180);
    assert!(core::mem::offset_of!(KtrapFrame, seg_ss) == 0x188);
    assert!(core::mem::offset_of!(KtrapFrame, fill3) == 0x18a);
    assert!(core::mem::offset_of!(KtrapFrame, fill4) == 0x18c);
    assert!(core::mem::size_of::<KtrapFrameView1>() == 0x190);
    assert!(core::mem::align_of::<KtrapFrameView1>() == core::mem::align_of::<KtrapFrame>());
    assert!(core::mem::offset_of!(KtrapFrameView1, interrupt_retpoline_state) == 0x28);
    assert!(core::mem::offset_of!(KtrapFrameView1, nmi_msr_ibrs) == 0x2a);
    assert!(core::mem::offset_of!(KtrapFrameView1, gs_swap) == 0x68);
    assert!(core::mem::offset_of!(KtrapFrameView1, context_record) == 0xd0);
    assert!(core::mem::offset_of!(KtrapFrameView1, rbx) == 0x140);
    assert!(core::mem::offset_of!(KtrapFrameView1, exception_frame) == 0x160);
};

/// `_KEXCEPTION_FRAME` (0x140 bytes).
#[repr(C)]
pub struct KexceptionFrame {
    pub p1_home: Field<u64>,
    pub p2_home: Field<u64>,
    pub p3_home: Field<u64>,
    pub p4_home: Field<u64>,
    pub p5: Field<u64>,
    pub spare1: Field<u64>,
    pub xmm6: M128a,
    pub xmm7: M128a,
    pub xmm8: M128a,
    pub xmm9: M128a,
    pub xmm10: M128a,
    pub xmm11: M128a,
    pub xmm12: M128a,
    pub xmm13: M128a,
    pub xmm14: M128a,
    pub xmm15: M128a,
    pub trap_frame: Field<u64>,
    pub output_buffer: Field<u64>,
    pub output_length: Field<u64>,
    pub spare2: Field<u64>,
    pub mx_csr: Field<u64>,
    pub rbp: Field<u64>,
    pub rbx: Field<u64>,
    pub rdi: Field<u64>,
    pub rsi: Field<u64>,
    pub r12: Field<u64>,
    pub r13: Field<u64>,
    pub r14: Field<u64>,
    pub r15: Field<u64>,
    pub return_: Field<u64>,
}

unsafe impl NtStruct for KexceptionFrame {}

const _: () = {
    assert!(core::mem::size_of::<KexceptionFrame>() == 0x140);
    assert!(core::mem::offset_of!(KexceptionFrame, p1_home) == 0x0);
    assert!(core::mem::offset_of!(KexceptionFrame, p2_home) == 0x8);
    assert!(core::mem::offset_of!(KexceptionFrame, p3_home) == 0x10);
    assert!(core::mem::offset_of!(KexceptionFrame, p4_home) == 0x18);
    assert!(core::mem::offset_of!(KexceptionFrame, p5) == 0x20);
    assert!(core::mem::offset_of!(KexceptionFrame, spare1) == 0x28);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm6) == 0x30);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm7) == 0x40);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm8) == 0x50);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm9) == 0x60);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm10) == 0x70);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm11) == 0x80);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm12) == 0x90);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm13) == 0xa0);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm14) == 0xb0);
    assert!(core::mem::offset_of!(KexceptionFrame, xmm15) == 0xc0);
    assert!(core::mem::offset_of!(KexceptionFrame, trap_frame) == 0xd0);
    assert!(core::mem::offset_of!(KexceptionFrame, output_buffer) == 0xd8);
    assert!(core::mem::offset_of!(KexceptionFrame, output_length) == 0xe0);
    assert!(core::mem::offset_of!(KexceptionFrame, spare2) == 0xe8);
    assert!(core::mem::offset_of!(KexceptionFrame, mx_csr) == 0xf0);
    assert!(core::mem::offset_of!(KexceptionFrame, rbp) == 0xf8);
    assert!(core::mem::offset_of!(KexceptionFrame, rbx) == 0x100);
    assert!(core::mem::offset_of!(KexceptionFrame, rdi) == 0x108);
    assert!(core::mem::offset_of!(KexceptionFrame, rsi) == 0x110);
    assert!(core::mem::offset_of!(KexceptionFrame, r12) == 0x118);
    assert!(core::mem::offset_of!(KexceptionFrame, r13) == 0x120);
    assert!(core::mem::offset_of!(KexceptionFrame, r14) == 0x128);
    assert!(core::mem::offset_of!(KexceptionFrame, r15) == 0x130);
    assert!(core::mem::offset_of!(KexceptionFrame, return_) == 0x138);
};

/// `_KSYSTEM_TIME` (0xc bytes).
#[repr(C)]
pub struct KsystemTime {
    pub low_part: Field<u32>,
    pub high1_time: Field<i32>,
    pub high2_time: Field<i32>,
}

unsafe impl NtStruct for KsystemTime {}

const _: () = {
    assert!(core::mem::size_of::<KsystemTime>() == 0xc);
    assert!(core::mem::offset_of!(KsystemTime, low_part) == 0x0);
    assert!(core::mem::offset_of!(KsystemTime, high1_time) == 0x4);
    assert!(core::mem::offset_of!(KsystemTime, high2_time) == 0x8);
};

/// `_KUSER_SHARED_DATA` (0x720 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `KuserSharedDataView1`..`KuserSharedDataView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct KuserSharedData {
    pub tick_count_low_deprecated: Field<u32>,
    pub tick_count_multiplier: Field<u32>,
    pub interrupt_time: KsystemTime,
    pub system_time: KsystemTime,
    pub time_zone_bias: KsystemTime,
    pub image_number_low: Field<u16>,
    pub image_number_high: Field<u16>,
    pub nt_system_root: [Field<u16>; 260],
    pub max_stack_trace_depth: Field<u32>,
    pub crypto_exponent: Field<u32>,
    pub time_zone_id: Field<u32>,
    pub large_page_minimum: Field<u32>,
    pub ait_sampling_value: Field<u32>,
    pub app_compat_flag: Field<u32>,
    pub rng_seed_version: Field<u64>,
    pub global_validation_runlevel: Field<u32>,
    pub time_zone_bias_stamp: Field<i32>,
    pub nt_build_number: Field<u32>,
    pub nt_product_type: Field<NtProductType>,
    pub product_type_is_valid: Field<u8>,
    pub reserved0: [Field<u8>; 1],
    pub native_processor_architecture: Field<u16>,
    pub nt_major_version: Field<u32>,
    pub nt_minor_version: Field<u32>,
    pub processor_features: [Field<u8>; 64],
    pub reserved1: Field<u32>,
    pub reserved3: Field<u32>,
    pub time_slip: Field<u32>,
    pub alternative_architecture: Field<AlternativeArchitectureType>,
    pub boot_id: Field<u32>,
    pub system_expiration_date: LargeInteger,
    pub suite_mask: Field<u32>,
    pub kd_debugger_enabled: Field<u8>,
    pub mitigation_policies: Field<u8>,
    pub cycles_per_yield: Field<u16>,
    pub active_console_id: Field<u32>,
    pub dismount_count: Field<u32>,
    pub com_plus_package: Field<u32>,
    pub last_system_rit_event_tick_count: Field<u32>,
    pub number_of_physical_pages: Field<u32>,
    pub safe_boot_mode: Field<u8>,
    pub virtualization_flags: Field<u8>,
    pub reserved12: [Field<u8>; 2],
    pub shared_data_flags: Field<u32>,
    pub data_flags_pad: [Field<u32>; 1],
    pub test_ret_instruction: Field<u64>,
    pub qpc_frequency: Field<i64>,
    pub system_call: Field<u32>,
    pub reserved2: Field<u32>,
    pub system_call_pad: [Field<u64>; 2],
    pub tick_count: KsystemTime,
    pub tick_count_pad: [Field<u32>; 1],
    pub cookie: Field<u32>,
    pub cookie_pad: [Field<u32>; 1],
    pub console_session_foreground_process_id: Field<i64>,
    pub time_update_lock: Field<u64>,
    pub baseline_system_time_qpc: Field<u64>,
    pub baseline_interrupt_time_qpc: Field<u64>,
    pub qpc_system_time_increment: Field<u64>,
    pub qpc_interrupt_time_increment: Field<u64>,
    pub qpc_system_time_increment_shift: Field<u8>,
    pub qpc_interrupt_time_increment_shift: Field<u8>,
    pub unparked_processor_count: Field<u16>,
    pub enclave_feature_mask: [Field<u32>; 4],
    pub telemetry_coverage_round: Field<u32>,
    pub user_mode_global_logger: [Field<u16>; 16],
    pub image_file_execution_options: Field<u32>,
    pub lang_generation_count: Field<u32>,
    pub reserved4: Field<u64>,
    pub interrupt_time_bias: Field<u64>,
    pub qpc_bias: Field<u64>,
    pub active_processor_count: Field<u32>,
    pub active_group_count: Field<u8>,
    pub reserved9: Field<u8>,
    pub qpc_data: Field<u16>,
    pub time_zone_bias_effective_start: LargeInteger,
    pub time_zone_bias_effective_end: LargeInteger,
    pub x_state: XstateConfiguration,
    pub feature_configuration_change_stamp: KsystemTime,
    pub spare: Field<u32>,
}

/// Vista 1 de `_KUSER_SHARED_DATA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KuserSharedDataView1 {
    _pad_0: Reserved<0x320>,
    pub tick_count_quad: Field<u64>,
    _pad_328: Reserved<0x9e>,
    pub qpc_bypass_enabled: Field<u8>,
    pub qpc_shift: Field<u8>,
    _pad_3c8: Reserved<0x358>,
}

/// Vista 2 de `_KUSER_SHARED_DATA` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct KuserSharedDataView2 {
    _align: [u64; 0],
    _pad_0: Reserved<0x320>,
    pub reserved_tick_count_overlay: [Field<u32>; 3],
    _pad_32c: Reserved<0x3f4>,
}

impl core::ops::Deref for KuserSharedData {
    type Target = KuserSharedDataView1;
    #[inline(always)]
    fn deref(&self) -> &KuserSharedDataView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KuserSharedDataView1>() }
    }
}

impl core::ops::Deref for KuserSharedDataView1 {
    type Target = KuserSharedDataView2;
    #[inline(always)]
    fn deref(&self) -> &KuserSharedDataView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<KuserSharedDataView2>() }
    }
}

unsafe impl NtStruct for KuserSharedData {}

impl KuserSharedData {
    /// `NXSupportPolicy`: bits 0..=1 de `mitigation_policies`.
    pub const NX_SUPPORT_POLICY_SHIFT: u32 = 0;
    pub const NX_SUPPORT_POLICY_MASK: u8 = 0x3;
    #[inline(always)]
    pub fn nx_support_policy(&self) -> u8 {
        self.mitigation_policies.bits(0, 2) as u8
    }
    #[inline(always)]
    pub fn set_nx_support_policy(&self, value: u8) {
        self.mitigation_policies.set_bits(0, 2, value as u64)
    }
    /// `SEHValidationPolicy`: bits 2..=3 de `mitigation_policies`.
    pub const SEH_VALIDATION_POLICY_SHIFT: u32 = 2;
    pub const SEH_VALIDATION_POLICY_MASK: u8 = 0xc;
    #[inline(always)]
    pub fn seh_validation_policy(&self) -> u8 {
        self.mitigation_policies.bits(2, 2) as u8
    }
    #[inline(always)]
    pub fn set_seh_validation_policy(&self, value: u8) {
        self.mitigation_policies.set_bits(2, 2, value as u64)
    }
    /// `CurDirDevicesSkippedForDlls`: bits 4..=5 de `mitigation_policies`.
    pub const CUR_DIR_DEVICES_SKIPPED_FOR_DLLS_SHIFT: u32 = 4;
    pub const CUR_DIR_DEVICES_SKIPPED_FOR_DLLS_MASK: u8 = 0x30;
    #[inline(always)]
    pub fn cur_dir_devices_skipped_for_dlls(&self) -> u8 {
        self.mitigation_policies.bits(4, 2) as u8
    }
    #[inline(always)]
    pub fn set_cur_dir_devices_skipped_for_dlls(&self, value: u8) {
        self.mitigation_policies.set_bits(4, 2, value as u64)
    }
    /// `Reserved`: bits 6..=7 de `mitigation_policies`.
    pub const RESERVED_SHIFT: u32 = 6;
    pub const RESERVED_MASK: u8 = 0xc0;
    #[inline(always)]
    pub fn reserved(&self) -> u8 {
        self.mitigation_policies.bits(6, 2) as u8
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u8) {
        self.mitigation_policies.set_bits(6, 2, value as u64)
    }
    /// `DbgErrorPortPresent`: bits 0..=0 de `shared_data_flags`.
    pub const DBG_ERROR_PORT_PRESENT_SHIFT: u32 = 0;
    pub const DBG_ERROR_PORT_PRESENT_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn dbg_error_port_present(&self) -> u32 {
        self.shared_data_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_error_port_present(&self, value: u32) {
        self.shared_data_flags.set_bits(0, 1, value as u64)
    }
    /// `DbgElevationEnabled`: bits 1..=1 de `shared_data_flags`.
    pub const DBG_ELEVATION_ENABLED_SHIFT: u32 = 1;
    pub const DBG_ELEVATION_ENABLED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn dbg_elevation_enabled(&self) -> u32 {
        self.shared_data_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_elevation_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(1, 1, value as u64)
    }
    /// `DbgVirtEnabled`: bits 2..=2 de `shared_data_flags`.
    pub const DBG_VIRT_ENABLED_SHIFT: u32 = 2;
    pub const DBG_VIRT_ENABLED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn dbg_virt_enabled(&self) -> u32 {
        self.shared_data_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_virt_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(2, 1, value as u64)
    }
    /// `DbgInstallerDetectEnabled`: bits 3..=3 de `shared_data_flags`.
    pub const DBG_INSTALLER_DETECT_ENABLED_SHIFT: u32 = 3;
    pub const DBG_INSTALLER_DETECT_ENABLED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn dbg_installer_detect_enabled(&self) -> u32 {
        self.shared_data_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_installer_detect_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(3, 1, value as u64)
    }
    /// `DbgLkgEnabled`: bits 4..=4 de `shared_data_flags`.
    pub const DBG_LKG_ENABLED_SHIFT: u32 = 4;
    pub const DBG_LKG_ENABLED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn dbg_lkg_enabled(&self) -> u32 {
        self.shared_data_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_lkg_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(4, 1, value as u64)
    }
    /// `DbgDynProcessorEnabled`: bits 5..=5 de `shared_data_flags`.
    pub const DBG_DYN_PROCESSOR_ENABLED_SHIFT: u32 = 5;
    pub const DBG_DYN_PROCESSOR_ENABLED_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn dbg_dyn_processor_enabled(&self) -> u32 {
        self.shared_data_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_dyn_processor_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(5, 1, value as u64)
    }
    /// `DbgConsoleBrokerEnabled`: bits 6..=6 de `shared_data_flags`.
    pub const DBG_CONSOLE_BROKER_ENABLED_SHIFT: u32 = 6;
    pub const DBG_CONSOLE_BROKER_ENABLED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn dbg_console_broker_enabled(&self) -> u32 {
        self.shared_data_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_console_broker_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(6, 1, value as u64)
    }
    /// `DbgSecureBootEnabled`: bits 7..=7 de `shared_data_flags`.
    pub const DBG_SECURE_BOOT_ENABLED_SHIFT: u32 = 7;
    pub const DBG_SECURE_BOOT_ENABLED_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn dbg_secure_boot_enabled(&self) -> u32 {
        self.shared_data_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_secure_boot_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(7, 1, value as u64)
    }
    /// `DbgMultiSessionSku`: bits 8..=8 de `shared_data_flags`.
    pub const DBG_MULTI_SESSION_SKU_SHIFT: u32 = 8;
    pub const DBG_MULTI_SESSION_SKU_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn dbg_multi_session_sku(&self) -> u32 {
        self.shared_data_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_multi_session_sku(&self, value: u32) {
        self.shared_data_flags.set_bits(8, 1, value as u64)
    }
    /// `DbgMultiUsersInSessionSku`: bits 9..=9 de `shared_data_flags`.
    pub const DBG_MULTI_USERS_IN_SESSION_SKU_SHIFT: u32 = 9;
    pub const DBG_MULTI_USERS_IN_SESSION_SKU_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn dbg_multi_users_in_session_sku(&self) -> u32 {
        self.shared_data_flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_multi_users_in_session_sku(&self, value: u32) {
        self.shared_data_flags.set_bits(9, 1, value as u64)
    }
    /// `DbgStateSeparationEnabled`: bits 10..=10 de `shared_data_flags`.
    pub const DBG_STATE_SEPARATION_ENABLED_SHIFT: u32 = 10;
    pub const DBG_STATE_SEPARATION_ENABLED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn dbg_state_separation_enabled(&self) -> u32 {
        self.shared_data_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_state_separation_enabled(&self, value: u32) {
        self.shared_data_flags.set_bits(10, 1, value as u64)
    }
    /// `SpareBits`: bits 11..=31 de `shared_data_flags`.
    pub const SPARE_BITS_SHIFT: u32 = 11;
    pub const SPARE_BITS_MASK: u32 = 0xfffff800;
    #[inline(always)]
    pub fn spare_bits(&self) -> u32 {
        self.shared_data_flags.bits(11, 21) as u32
    }
    #[inline(always)]
    pub fn set_spare_bits(&self, value: u32) {
        self.shared_data_flags.set_bits(11, 21, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<KuserSharedData>() == 0x720);
    assert!(core::mem::offset_of!(KuserSharedData, tick_count_low_deprecated) == 0x0);
    assert!(core::mem::offset_of!(KuserSharedData, tick_count_multiplier) == 0x4);
    assert!(core::mem::offset_of!(KuserSharedData, interrupt_time) == 0x8);
    assert!(core::mem::offset_of!(KuserSharedData, system_time) == 0x14);
    assert!(core::mem::offset_of!(KuserSharedData, time_zone_bias) == 0x20);
    assert!(core::mem::offset_of!(KuserSharedData, image_number_low) == 0x2c);
    assert!(core::mem::offset_of!(KuserSharedData, image_number_high) == 0x2e);
    assert!(core::mem::offset_of!(KuserSharedData, nt_system_root) == 0x30);
    assert!(core::mem::offset_of!(KuserSharedData, max_stack_trace_depth) == 0x238);
    assert!(core::mem::offset_of!(KuserSharedData, crypto_exponent) == 0x23c);
    assert!(core::mem::offset_of!(KuserSharedData, time_zone_id) == 0x240);
    assert!(core::mem::offset_of!(KuserSharedData, large_page_minimum) == 0x244);
    assert!(core::mem::offset_of!(KuserSharedData, ait_sampling_value) == 0x248);
    assert!(core::mem::offset_of!(KuserSharedData, app_compat_flag) == 0x24c);
    assert!(core::mem::offset_of!(KuserSharedData, rng_seed_version) == 0x250);
    assert!(core::mem::offset_of!(KuserSharedData, global_validation_runlevel) == 0x258);
    assert!(core::mem::offset_of!(KuserSharedData, time_zone_bias_stamp) == 0x25c);
    assert!(core::mem::offset_of!(KuserSharedData, nt_build_number) == 0x260);
    assert!(core::mem::offset_of!(KuserSharedData, nt_product_type) == 0x264);
    assert!(core::mem::offset_of!(KuserSharedData, product_type_is_valid) == 0x268);
    assert!(core::mem::offset_of!(KuserSharedData, reserved0) == 0x269);
    assert!(core::mem::offset_of!(KuserSharedData, native_processor_architecture) == 0x26a);
    assert!(core::mem::offset_of!(KuserSharedData, nt_major_version) == 0x26c);
    assert!(core::mem::offset_of!(KuserSharedData, nt_minor_version) == 0x270);
    assert!(core::mem::offset_of!(KuserSharedData, processor_features) == 0x274);
    assert!(core::mem::offset_of!(KuserSharedData, reserved1) == 0x2b4);
    assert!(core::mem::offset_of!(KuserSharedData, reserved3) == 0x2b8);
    assert!(core::mem::offset_of!(KuserSharedData, time_slip) == 0x2bc);
    assert!(core::mem::offset_of!(KuserSharedData, alternative_architecture) == 0x2c0);
    assert!(core::mem::offset_of!(KuserSharedData, boot_id) == 0x2c4);
    assert!(core::mem::offset_of!(KuserSharedData, system_expiration_date) == 0x2c8);
    assert!(core::mem::offset_of!(KuserSharedData, suite_mask) == 0x2d0);
    assert!(core::mem::offset_of!(KuserSharedData, kd_debugger_enabled) == 0x2d4);
    assert!(core::mem::offset_of!(KuserSharedData, mitigation_policies) == 0x2d5);
    assert!(core::mem::offset_of!(KuserSharedData, cycles_per_yield) == 0x2d6);
    assert!(core::mem::offset_of!(KuserSharedData, active_console_id) == 0x2d8);
    assert!(core::mem::offset_of!(KuserSharedData, dismount_count) == 0x2dc);
    assert!(core::mem::offset_of!(KuserSharedData, com_plus_package) == 0x2e0);
    assert!(core::mem::offset_of!(KuserSharedData, last_system_rit_event_tick_count) == 0x2e4);
    assert!(core::mem::offset_of!(KuserSharedData, number_of_physical_pages) == 0x2e8);
    assert!(core::mem::offset_of!(KuserSharedData, safe_boot_mode) == 0x2ec);
    assert!(core::mem::offset_of!(KuserSharedData, virtualization_flags) == 0x2ed);
    assert!(core::mem::offset_of!(KuserSharedData, reserved12) == 0x2ee);
    assert!(core::mem::offset_of!(KuserSharedData, shared_data_flags) == 0x2f0);
    assert!(core::mem::offset_of!(KuserSharedData, data_flags_pad) == 0x2f4);
    assert!(core::mem::offset_of!(KuserSharedData, test_ret_instruction) == 0x2f8);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_frequency) == 0x300);
    assert!(core::mem::offset_of!(KuserSharedData, system_call) == 0x308);
    assert!(core::mem::offset_of!(KuserSharedData, reserved2) == 0x30c);
    assert!(core::mem::offset_of!(KuserSharedData, system_call_pad) == 0x310);
    assert!(core::mem::offset_of!(KuserSharedData, tick_count) == 0x320);
    assert!(core::mem::offset_of!(KuserSharedData, tick_count_pad) == 0x32c);
    assert!(core::mem::offset_of!(KuserSharedData, cookie) == 0x330);
    assert!(core::mem::offset_of!(KuserSharedData, cookie_pad) == 0x334);
    assert!(core::mem::offset_of!(KuserSharedData, console_session_foreground_process_id) == 0x338);
    assert!(core::mem::offset_of!(KuserSharedData, time_update_lock) == 0x340);
    assert!(core::mem::offset_of!(KuserSharedData, baseline_system_time_qpc) == 0x348);
    assert!(core::mem::offset_of!(KuserSharedData, baseline_interrupt_time_qpc) == 0x350);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_system_time_increment) == 0x358);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_interrupt_time_increment) == 0x360);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_system_time_increment_shift) == 0x368);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_interrupt_time_increment_shift) == 0x369);
    assert!(core::mem::offset_of!(KuserSharedData, unparked_processor_count) == 0x36a);
    assert!(core::mem::offset_of!(KuserSharedData, enclave_feature_mask) == 0x36c);
    assert!(core::mem::offset_of!(KuserSharedData, telemetry_coverage_round) == 0x37c);
    assert!(core::mem::offset_of!(KuserSharedData, user_mode_global_logger) == 0x380);
    assert!(core::mem::offset_of!(KuserSharedData, image_file_execution_options) == 0x3a0);
    assert!(core::mem::offset_of!(KuserSharedData, lang_generation_count) == 0x3a4);
    assert!(core::mem::offset_of!(KuserSharedData, reserved4) == 0x3a8);
    assert!(core::mem::offset_of!(KuserSharedData, interrupt_time_bias) == 0x3b0);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_bias) == 0x3b8);
    assert!(core::mem::offset_of!(KuserSharedData, active_processor_count) == 0x3c0);
    assert!(core::mem::offset_of!(KuserSharedData, active_group_count) == 0x3c4);
    assert!(core::mem::offset_of!(KuserSharedData, reserved9) == 0x3c5);
    assert!(core::mem::offset_of!(KuserSharedData, qpc_data) == 0x3c6);
    assert!(core::mem::offset_of!(KuserSharedData, time_zone_bias_effective_start) == 0x3c8);
    assert!(core::mem::offset_of!(KuserSharedData, time_zone_bias_effective_end) == 0x3d0);
    assert!(core::mem::offset_of!(KuserSharedData, x_state) == 0x3d8);
    assert!(core::mem::offset_of!(KuserSharedData, feature_configuration_change_stamp) == 0x710);
    assert!(core::mem::offset_of!(KuserSharedData, spare) == 0x71c);
    assert!(core::mem::size_of::<KuserSharedDataView1>() == 0x720);
    assert!(core::mem::align_of::<KuserSharedDataView1>() == core::mem::align_of::<KuserSharedData>());
    assert!(core::mem::offset_of!(KuserSharedDataView1, tick_count_quad) == 0x320);
    assert!(core::mem::offset_of!(KuserSharedDataView1, qpc_bypass_enabled) == 0x3c6);
    assert!(core::mem::offset_of!(KuserSharedDataView1, qpc_shift) == 0x3c7);
    assert!(core::mem::size_of::<KuserSharedDataView2>() == 0x720);
    assert!(core::mem::align_of::<KuserSharedDataView2>() == core::mem::align_of::<KuserSharedData>());
    assert!(core::mem::offset_of!(KuserSharedDataView2, reserved_tick_count_overlay) == 0x320);
};

/// `_NT_PRODUCT_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct NtProductType(pub i32);

impl NtProductType {
    pub const NT_PRODUCT_WIN_NT: Self = Self(1);
    pub const NT_PRODUCT_LAN_MAN_NT: Self = Self(2);
    pub const NT_PRODUCT_SERVER: Self = Self(3);
}

/// `_ALTERNATIVE_ARCHITECTURE_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct AlternativeArchitectureType(pub i32);

impl AlternativeArchitectureType {
    pub const STANDARD_DESIGN: Self = Self(0);
    pub const NEC98X86: Self = Self(1);
    pub const END_ALTERNATIVES: Self = Self(2);
}

/// `_XSTATE_CONFIGURATION` (0x338 bytes).
#[repr(C)]
pub struct XstateConfiguration {
    pub enabled_features: Field<u64>,
    pub enabled_volatile_features: Field<u64>,
    pub size: Field<u32>,
    pub control_flags: Field<u32>,
    pub features: [XstateFeature; 64],
    pub enabled_supervisor_features: Field<u64>,
    pub aligned_features: Field<u64>,
    pub all_feature_size: Field<u32>,
    pub all_features: [Field<u32>; 64],
    _pad_32c: Reserved<0x4>,
    pub enabled_user_visible_supervisor_features: Field<u64>,
}

unsafe impl NtStruct for XstateConfiguration {}

impl XstateConfiguration {
    /// `OptimizedSave`: bits 0..=0 de `control_flags`.
    pub const OPTIMIZED_SAVE_SHIFT: u32 = 0;
    pub const OPTIMIZED_SAVE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn optimized_save(&self) -> u32 {
        self.control_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_optimized_save(&self, value: u32) {
        self.control_flags.set_bits(0, 1, value as u64)
    }
    /// `CompactionEnabled`: bits 1..=1 de `control_flags`.
    pub const COMPACTION_ENABLED_SHIFT: u32 = 1;
    pub const COMPACTION_ENABLED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn compaction_enabled(&self) -> u32 {
        self.control_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_compaction_enabled(&self, value: u32) {
        self.control_flags.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<XstateConfiguration>() == 0x338);
    assert!(core::mem::offset_of!(XstateConfiguration, enabled_features) == 0x0);
    assert!(core::mem::offset_of!(XstateConfiguration, enabled_volatile_features) == 0x8);
    assert!(core::mem::offset_of!(XstateConfiguration, size) == 0x10);
    assert!(core::mem::offset_of!(XstateConfiguration, control_flags) == 0x14);
    assert!(core::mem::offset_of!(XstateConfiguration, features) == 0x18);
    assert!(core::mem::offset_of!(XstateConfiguration, enabled_supervisor_features) == 0x218);
    assert!(core::mem::offset_of!(XstateConfiguration, aligned_features) == 0x220);
    assert!(core::mem::offset_of!(XstateConfiguration, all_feature_size) == 0x228);
    assert!(core::mem::offset_of!(XstateConfiguration, all_features) == 0x22c);
    assert!(core::mem::offset_of!(XstateConfiguration, enabled_user_visible_supervisor_features) == 0x330);
};

/// `_XSTATE_FEATURE` (0x8 bytes).
#[repr(C)]
pub struct XstateFeature {
    pub offset: Field<u32>,
    pub size: Field<u32>,
}

unsafe impl NtStruct for XstateFeature {}

const _: () = {
    assert!(core::mem::size_of::<XstateFeature>() == 0x8);
    assert!(core::mem::offset_of!(XstateFeature, offset) == 0x0);
    assert!(core::mem::offset_of!(XstateFeature, size) == 0x4);
};

/// `_HV_X64_HYPERVISOR_FEATURES` (0x10 bytes).
#[repr(C)]
pub struct HvX64HypervisorFeatures {
    pub partition_privileges: HvPartitionPrivilegeMask,
    pub bitfield_8: Field<u32>,
    pub bitfield_c: Field<u32>,
}

unsafe impl NtStruct for HvX64HypervisorFeatures {}

impl HvX64HypervisorFeatures {
    /// `MaxSupportedCState`: bits 0..=3 de `bitfield_8`.
    pub const MAX_SUPPORTED_C_STATE_SHIFT: u32 = 0;
    pub const MAX_SUPPORTED_C_STATE_MASK: u32 = 0xf;
    #[inline(always)]
    pub fn max_supported_c_state(&self) -> u32 {
        self.bitfield_8.bits(0, 4) as u32
    }
    #[inline(always)]
    pub fn set_max_supported_c_state(&self, value: u32) {
        self.bitfield_8.set_bits(0, 4, value as u64)
    }
    /// `HpetNeededForC3PowerState_Deprecated`: bits 4..=4 de `bitfield_8`.
    pub const HPET_NEEDED_FOR_C3_POWER_STATE_DEPRECATED_SHIFT: u32 = 4;
    pub const HPET_NEEDED_FOR_C3_POWER_STATE_DEPRECATED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn hpet_needed_for_c3_power_state_deprecated(&self) -> u32 {
        self.bitfield_8.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_hpet_needed_for_c3_power_state_deprecated(&self, value: u32) {
        self.bitfield_8.set_bits(4, 1, value as u64)
    }
    /// `Reserved`: bits 5..=31 de `bitfield_8`.
    pub const RESERVED_SHIFT: u32 = 5;
    pub const RESERVED_MASK: u32 = 0xffffffe0;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.bitfield_8.bits(5, 27) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.bitfield_8.set_bits(5, 27, value as u64)
    }
    /// `MwaitAvailable_Deprecated`: bits 0..=0 de `bitfield_c`.
    pub const MWAIT_AVAILABLE_DEPRECATED_SHIFT: u32 = 0;
    pub const MWAIT_AVAILABLE_DEPRECATED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn mwait_available_deprecated(&self) -> u32 {
        self.bitfield_c.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_mwait_available_deprecated(&self, value: u32) {
        self.bitfield_c.set_bits(0, 1, value as u64)
    }
    /// `GuestDebuggingAvailable`: bits 1..=1 de `bitfield_c`.
    pub const GUEST_DEBUGGING_AVAILABLE_SHIFT: u32 = 1;
    pub const GUEST_DEBUGGING_AVAILABLE_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn guest_debugging_available(&self) -> u32 {
        self.bitfield_c.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_guest_debugging_available(&self, value: u32) {
        self.bitfield_c.set_bits(1, 1, value as u64)
    }
    /// `PerformanceMonitorsAvailable`: bits 2..=2 de `bitfield_c`.
    pub const PERFORMANCE_MONITORS_AVAILABLE_SHIFT: u32 = 2;
    pub const PERFORMANCE_MONITORS_AVAILABLE_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn performance_monitors_available(&self) -> u32 {
        self.bitfield_c.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_performance_monitors_available(&self, value: u32) {
        self.bitfield_c.set_bits(2, 1, value as u64)
    }
    /// `CpuDynamicPartitioningAvailable`: bits 3..=3 de `bitfield_c`.
    pub const CPU_DYNAMIC_PARTITIONING_AVAILABLE_SHIFT: u32 = 3;
    pub const CPU_DYNAMIC_PARTITIONING_AVAILABLE_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn cpu_dynamic_partitioning_available(&self) -> u32 {
        self.bitfield_c.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_cpu_dynamic_partitioning_available(&self, value: u32) {
        self.bitfield_c.set_bits(3, 1, value as u64)
    }
    /// `XmmRegistersForFastHypercallAvailable`: bits 4..=4 de `bitfield_c`.
    pub const XMM_REGISTERS_FOR_FAST_HYPERCALL_AVAILABLE_SHIFT: u32 = 4;
    pub const XMM_REGISTERS_FOR_FAST_HYPERCALL_AVAILABLE_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn xmm_registers_for_fast_hypercall_available(&self) -> u32 {
        self.bitfield_c.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_xmm_registers_for_fast_hypercall_available(&self, value: u32) {
        self.bitfield_c.set_bits(4, 1, value as u64)
    }
    /// `GuestIdleAvailable`: bits 5..=5 de `bitfield_c`.
    pub const GUEST_IDLE_AVAILABLE_SHIFT: u32 = 5;
    pub const GUEST_IDLE_AVAILABLE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn guest_idle_available(&self) -> u32 {
        self.bitfield_c.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_guest_idle_available(&self, value: u32) {
        self.bitfield_c.set_bits(5, 1, value as u64)
    }
    /// `HypervisorSleepStateSupportAvailable`: bits 6..=6 de `bitfield_c`.
    pub const HYPERVISOR_SLEEP_STATE_SUPPORT_AVAILABLE_SHIFT: u32 = 6;
    pub const HYPERVISOR_SLEEP_STATE_SUPPORT_AVAILABLE_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn hypervisor_sleep_state_support_available(&self) -> u32 {
        self.bitfield_c.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_hypervisor_sleep_state_support_available(&self, value: u32) {
        self.bitfield_c.set_bits(6, 1, value as u64)
    }
    /// `NumaDistanceQueryAvailable`: bits 7..=7 de `bitfield_c`.
    pub const NUMA_DISTANCE_QUERY_AVAILABLE_SHIFT: u32 = 7;
    pub const NUMA_DISTANCE_QUERY_AVAILABLE_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn numa_distance_query_available(&self) -> u32 {
        self.bitfield_c.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_numa_distance_query_available(&self, value: u32) {
        self.bitfield_c.set_bits(7, 1, value as u64)
    }
    /// `FrequencyRegsAvailable`: bits 8..=8 de `bitfield_c`.
    pub const FREQUENCY_REGS_AVAILABLE_SHIFT: u32 = 8;
    pub const FREQUENCY_REGS_AVAILABLE_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn frequency_regs_available(&self) -> u32 {
        self.bitfield_c.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_frequency_regs_available(&self, value: u32) {
        self.bitfield_c.set_bits(8, 1, value as u64)
    }
    /// `SyntheticMachineCheckAvailable`: bits 9..=9 de `bitfield_c`.
    pub const SYNTHETIC_MACHINE_CHECK_AVAILABLE_SHIFT: u32 = 9;
    pub const SYNTHETIC_MACHINE_CHECK_AVAILABLE_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn synthetic_machine_check_available(&self) -> u32 {
        self.bitfield_c.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_synthetic_machine_check_available(&self, value: u32) {
        self.bitfield_c.set_bits(9, 1, value as u64)
    }
    /// `GuestCrashRegsAvailable`: bits 10..=10 de `bitfield_c`.
    pub const GUEST_CRASH_REGS_AVAILABLE_SHIFT: u32 = 10;
    pub const GUEST_CRASH_REGS_AVAILABLE_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn guest_crash_regs_available(&self) -> u32 {
        self.bitfield_c.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_guest_crash_regs_available(&self, value: u32) {
        self.bitfield_c.set_bits(10, 1, value as u64)
    }
    /// `DebugRegsAvailable`: bits 11..=11 de `bitfield_c`.
    pub const DEBUG_REGS_AVAILABLE_SHIFT: u32 = 11;
    pub const DEBUG_REGS_AVAILABLE_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn debug_regs_available(&self) -> u32 {
        self.bitfield_c.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_debug_regs_available(&self, value: u32) {
        self.bitfield_c.set_bits(11, 1, value as u64)
    }
    /// `Npiep1Available`: bits 12..=12 de `bitfield_c`.
    pub const NPIEP1_AVAILABLE_SHIFT: u32 = 12;
    pub const NPIEP1_AVAILABLE_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn npiep1_available(&self) -> u32 {
        self.bitfield_c.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_npiep1_available(&self, value: u32) {
        self.bitfield_c.set_bits(12, 1, value as u64)
    }
    /// `DisableHypervisorAvailable`: bits 13..=13 de `bitfield_c`.
    pub const DISABLE_HYPERVISOR_AVAILABLE_SHIFT: u32 = 13;
    pub const DISABLE_HYPERVISOR_AVAILABLE_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn disable_hypervisor_available(&self) -> u32 {
        self.bitfield_c.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_hypervisor_available(&self, value: u32) {
        self.bitfield_c.set_bits(13, 1, value as u64)
    }
    /// `ExtendedGvaRangesForFlushVirtualAddressListAvailable`: bits 14..=14 de `bitfield_c`.
    pub const EXTENDED_GVA_RANGES_FOR_FLUSH_VIRTUAL_ADDRESS_LIST_AVAILABLE_SHIFT: u32 = 14;
    pub const EXTENDED_GVA_RANGES_FOR_FLUSH_VIRTUAL_ADDRESS_LIST_AVAILABLE_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn extended_gva_ranges_for_flush_virtual_address_list_available(&self) -> u32 {
        self.bitfield_c.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_extended_gva_ranges_for_flush_virtual_address_list_available(&self, value: u32) {
        self.bitfield_c.set_bits(14, 1, value as u64)
    }
    /// `FastHypercallOutputAvailable`: bits 15..=15 de `bitfield_c`.
    pub const FAST_HYPERCALL_OUTPUT_AVAILABLE_SHIFT: u32 = 15;
    pub const FAST_HYPERCALL_OUTPUT_AVAILABLE_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn fast_hypercall_output_available(&self) -> u32 {
        self.bitfield_c.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_fast_hypercall_output_available(&self, value: u32) {
        self.bitfield_c.set_bits(15, 1, value as u64)
    }
    /// `SvmFeaturesAvailable`: bits 16..=16 de `bitfield_c`.
    pub const SVM_FEATURES_AVAILABLE_SHIFT: u32 = 16;
    pub const SVM_FEATURES_AVAILABLE_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn svm_features_available(&self) -> u32 {
        self.bitfield_c.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_svm_features_available(&self, value: u32) {
        self.bitfield_c.set_bits(16, 1, value as u64)
    }
    /// `SintPollingModeAvailable`: bits 17..=17 de `bitfield_c`.
    pub const SINT_POLLING_MODE_AVAILABLE_SHIFT: u32 = 17;
    pub const SINT_POLLING_MODE_AVAILABLE_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn sint_polling_mode_available(&self) -> u32 {
        self.bitfield_c.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_sint_polling_mode_available(&self, value: u32) {
        self.bitfield_c.set_bits(17, 1, value as u64)
    }
    /// `HypercallMsrLockAvailable`: bits 18..=18 de `bitfield_c`.
    pub const HYPERCALL_MSR_LOCK_AVAILABLE_SHIFT: u32 = 18;
    pub const HYPERCALL_MSR_LOCK_AVAILABLE_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn hypercall_msr_lock_available(&self) -> u32 {
        self.bitfield_c.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_hypercall_msr_lock_available(&self, value: u32) {
        self.bitfield_c.set_bits(18, 1, value as u64)
    }
    /// `DirectSyntheticTimers`: bits 19..=19 de `bitfield_c`.
    pub const DIRECT_SYNTHETIC_TIMERS_SHIFT: u32 = 19;
    pub const DIRECT_SYNTHETIC_TIMERS_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn direct_synthetic_timers(&self) -> u32 {
        self.bitfield_c.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_direct_synthetic_timers(&self, value: u32) {
        self.bitfield_c.set_bits(19, 1, value as u64)
    }
    /// `RegisterPatAvailable`: bits 20..=20 de `bitfield_c`.
    pub const REGISTER_PAT_AVAILABLE_SHIFT: u32 = 20;
    pub const REGISTER_PAT_AVAILABLE_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn register_pat_available(&self) -> u32 {
        self.bitfield_c.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_register_pat_available(&self, value: u32) {
        self.bitfield_c.set_bits(20, 1, value as u64)
    }
    /// `RegisterBndcfgsAvailable`: bits 21..=21 de `bitfield_c`.
    pub const REGISTER_BNDCFGS_AVAILABLE_SHIFT: u32 = 21;
    pub const REGISTER_BNDCFGS_AVAILABLE_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn register_bndcfgs_available(&self) -> u32 {
        self.bitfield_c.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_register_bndcfgs_available(&self, value: u32) {
        self.bitfield_c.set_bits(21, 1, value as u64)
    }
    /// `WatchdogTimerAvailable`: bits 22..=22 de `bitfield_c`.
    pub const WATCHDOG_TIMER_AVAILABLE_SHIFT: u32 = 22;
    pub const WATCHDOG_TIMER_AVAILABLE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn watchdog_timer_available(&self) -> u32 {
        self.bitfield_c.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_watchdog_timer_available(&self, value: u32) {
        self.bitfield_c.set_bits(22, 1, value as u64)
    }
    /// `SyntheticTimeUnhaltedTimerAvailable`: bits 23..=23 de `bitfield_c`.
    pub const SYNTHETIC_TIME_UNHALTED_TIMER_AVAILABLE_SHIFT: u32 = 23;
    pub const SYNTHETIC_TIME_UNHALTED_TIMER_AVAILABLE_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn synthetic_time_unhalted_timer_available(&self) -> u32 {
        self.bitfield_c.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_synthetic_time_unhalted_timer_available(&self, value: u32) {
        self.bitfield_c.set_bits(23, 1, value as u64)
    }
    /// `DeviceDomainsAvailable`: bits 24..=24 de `bitfield_c`.
    pub const DEVICE_DOMAINS_AVAILABLE_SHIFT: u32 = 24;
    pub const DEVICE_DOMAINS_AVAILABLE_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn device_domains_available(&self) -> u32 {
        self.bitfield_c.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_device_domains_available(&self, value: u32) {
        self.bitfield_c.set_bits(24, 1, value as u64)
    }
    /// `S1DeviceDomainsAvailable`: bits 25..=25 de `bitfield_c`.
    pub const S1_DEVICE_DOMAINS_AVAILABLE_SHIFT: u32 = 25;
    pub const S1_DEVICE_DOMAINS_AVAILABLE_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn s1_device_domains_available(&self) -> u32 {
        self.bitfield_c.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_s1_device_domains_available(&self, value: u32) {
        self.bitfield_c.set_bits(25, 1, value as u64)
    }
    /// `LbrAvailable`: bits 26..=26 de `bitfield_c`.
    pub const LBR_AVAILABLE_SHIFT: u32 = 26;
    pub const LBR_AVAILABLE_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn lbr_available(&self) -> u32 {
        self.bitfield_c.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_lbr_available(&self, value: u32) {
        self.bitfield_c.set_bits(26, 1, value as u64)
    }
    /// `IptAvailable`: bits 27..=27 de `bitfield_c`.
    pub const IPT_AVAILABLE_SHIFT: u32 = 27;
    pub const IPT_AVAILABLE_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn ipt_available(&self) -> u32 {
        self.bitfield_c.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_ipt_available(&self, value: u32) {
        self.bitfield_c.set_bits(27, 1, value as u64)
    }
    /// `CrossVtlFlushAvailable`: bits 28..=28 de `bitfield_c`.
    pub const CROSS_VTL_FLUSH_AVAILABLE_SHIFT: u32 = 28;
    pub const CROSS_VTL_FLUSH_AVAILABLE_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn cross_vtl_flush_available(&self) -> u32 {
        self.bitfield_c.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_cross_vtl_flush_available(&self, value: u32) {
        self.bitfield_c.set_bits(28, 1, value as u64)
    }
    /// `IdleSpecCtrlAvailable`: bits 29..=29 de `bitfield_c`.
    pub const IDLE_SPEC_CTRL_AVAILABLE_SHIFT: u32 = 29;
    pub const IDLE_SPEC_CTRL_AVAILABLE_MASK: u32 = 0x20000000;
    #[inline(always)]
    pub fn idle_spec_ctrl_available(&self) -> u32 {
        self.bitfield_c.bits(29, 1) as u32
    }
    #[inline(always)]
    pub fn set_idle_spec_ctrl_available(&self, value: u32) {
        self.bitfield_c.set_bits(29, 1, value as u64)
    }
    /// `Reserved1`: bits 30..=31 de `bitfield_c`.
    pub const RESERVED1_SHIFT: u32 = 30;
    pub const RESERVED1_MASK: u32 = 0xc0000000;
    #[inline(always)]
    pub fn reserved1(&self) -> u32 {
        self.bitfield_c.bits(30, 2) as u32
    }
    #[inline(always)]
    pub fn set_reserved1(&self, value: u32) {
        self.bitfield_c.set_bits(30, 2, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HvX64HypervisorFeatures>() == 0x10);
    assert!(core::mem::offset_of!(HvX64HypervisorFeatures, partition_privileges) == 0x0);
    assert!(core::mem::offset_of!(HvX64HypervisorFeatures, bitfield_8) == 0x8);
    assert!(core::mem::offset_of!(HvX64HypervisorFeatures, bitfield_c) == 0xc);
};

/// `_HV_PARTITION_PRIVILEGE_MASK` (0x8 bytes).
#[repr(C)]
pub struct HvPartitionPrivilegeMask {
    pub as_uint64: Field<u64>,
}

unsafe impl NtStruct for HvPartitionPrivilegeMask {}

impl HvPartitionPrivilegeMask {
    /// `AccessVpRunTimeReg`: bits 0..=0 de `as_uint64`.
    pub const ACCESS_VP_RUN_TIME_REG_SHIFT: u32 = 0;
    pub const ACCESS_VP_RUN_TIME_REG_MASK: u64 = 0x1;
    #[inline(always)]
    pub fn access_vp_run_time_reg(&self) -> u64 {
        self.as_uint64.bits(0, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_vp_run_time_reg(&self, value: u64) {
        self.as_uint64.set_bits(0, 1, value as u64)
    }
    /// `AccessPartitionReferenceCounter`: bits 1..=1 de `as_uint64`.
    pub const ACCESS_PARTITION_REFERENCE_COUNTER_SHIFT: u32 = 1;
    pub const ACCESS_PARTITION_REFERENCE_COUNTER_MASK: u64 = 0x2;
    #[inline(always)]
    pub fn access_partition_reference_counter(&self) -> u64 {
        self.as_uint64.bits(1, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_partition_reference_counter(&self, value: u64) {
        self.as_uint64.set_bits(1, 1, value as u64)
    }
    /// `AccessSynicRegs`: bits 2..=2 de `as_uint64`.
    pub const ACCESS_SYNIC_REGS_SHIFT: u32 = 2;
    pub const ACCESS_SYNIC_REGS_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn access_synic_regs(&self) -> u64 {
        self.as_uint64.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_synic_regs(&self, value: u64) {
        self.as_uint64.set_bits(2, 1, value as u64)
    }
    /// `AccessSyntheticTimerRegs`: bits 3..=3 de `as_uint64`.
    pub const ACCESS_SYNTHETIC_TIMER_REGS_SHIFT: u32 = 3;
    pub const ACCESS_SYNTHETIC_TIMER_REGS_MASK: u64 = 0x8;
    #[inline(always)]
    pub fn access_synthetic_timer_regs(&self) -> u64 {
        self.as_uint64.bits(3, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_synthetic_timer_regs(&self, value: u64) {
        self.as_uint64.set_bits(3, 1, value as u64)
    }
    /// `AccessIntrCtrlRegs`: bits 4..=4 de `as_uint64`.
    pub const ACCESS_INTR_CTRL_REGS_SHIFT: u32 = 4;
    pub const ACCESS_INTR_CTRL_REGS_MASK: u64 = 0x10;
    #[inline(always)]
    pub fn access_intr_ctrl_regs(&self) -> u64 {
        self.as_uint64.bits(4, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_intr_ctrl_regs(&self, value: u64) {
        self.as_uint64.set_bits(4, 1, value as u64)
    }
    /// `AccessHypercallMsrs`: bits 5..=5 de `as_uint64`.
    pub const ACCESS_HYPERCALL_MSRS_SHIFT: u32 = 5;
    pub const ACCESS_HYPERCALL_MSRS_MASK: u64 = 0x20;
    #[inline(always)]
    pub fn access_hypercall_msrs(&self) -> u64 {
        self.as_uint64.bits(5, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_hypercall_msrs(&self, value: u64) {
        self.as_uint64.set_bits(5, 1, value as u64)
    }
    /// `AccessVpIndex`: bits 6..=6 de `as_uint64`.
    pub const ACCESS_VP_INDEX_SHIFT: u32 = 6;
    pub const ACCESS_VP_INDEX_MASK: u64 = 0x40;
    #[inline(always)]
    pub fn access_vp_index(&self) -> u64 {
        self.as_uint64.bits(6, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_vp_index(&self, value: u64) {
        self.as_uint64.set_bits(6, 1, value as u64)
    }
    /// `AccessResetReg`: bits 7..=7 de `as_uint64`.
    pub const ACCESS_RESET_REG_SHIFT: u32 = 7;
    pub const ACCESS_RESET_REG_MASK: u64 = 0x80;
    #[inline(always)]
    pub fn access_reset_reg(&self) -> u64 {
        self.as_uint64.bits(7, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_reset_reg(&self, value: u64) {
        self.as_uint64.set_bits(7, 1, value as u64)
    }
    /// `AccessStatsReg`: bits 8..=8 de `as_uint64`.
    pub const ACCESS_STATS_REG_SHIFT: u32 = 8;
    pub const ACCESS_STATS_REG_MASK: u64 = 0x100;
    #[inline(always)]
    pub fn access_stats_reg(&self) -> u64 {
        self.as_uint64.bits(8, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_stats_reg(&self, value: u64) {
        self.as_uint64.set_bits(8, 1, value as u64)
    }
    /// `AccessPartitionReferenceTsc`: bits 9..=9 de `as_uint64`.
    pub const ACCESS_PARTITION_REFERENCE_TSC_SHIFT: u32 = 9;
    pub const ACCESS_PARTITION_REFERENCE_TSC_MASK: u64 = 0x200;
    #[inline(always)]
    pub fn access_partition_reference_tsc(&self) -> u64 {
        self.as_uint64.bits(9, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_partition_reference_tsc(&self, value: u64) {
        self.as_uint64.set_bits(9, 1, value as u64)
    }
    /// `AccessGuestIdleReg`: bits 10..=10 de `as_uint64`.
    pub const ACCESS_GUEST_IDLE_REG_SHIFT: u32 = 10;
    pub const ACCESS_GUEST_IDLE_REG_MASK: u64 = 0x400;
    #[inline(always)]
    pub fn access_guest_idle_reg(&self) -> u64 {
        self.as_uint64.bits(10, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_guest_idle_reg(&self, value: u64) {
        self.as_uint64.set_bits(10, 1, value as u64)
    }
    /// `AccessFrequencyRegs`: bits 11..=11 de `as_uint64`.
    pub const ACCESS_FREQUENCY_REGS_SHIFT: u32 = 11;
    pub const ACCESS_FREQUENCY_REGS_MASK: u64 = 0x800;
    #[inline(always)]
    pub fn access_frequency_regs(&self) -> u64 {
        self.as_uint64.bits(11, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_frequency_regs(&self, value: u64) {
        self.as_uint64.set_bits(11, 1, value as u64)
    }
    /// `AccessDebugRegs`: bits 12..=12 de `as_uint64`.
    pub const ACCESS_DEBUG_REGS_SHIFT: u32 = 12;
    pub const ACCESS_DEBUG_REGS_MASK: u64 = 0x1000;
    #[inline(always)]
    pub fn access_debug_regs(&self) -> u64 {
        self.as_uint64.bits(12, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_debug_regs(&self, value: u64) {
        self.as_uint64.set_bits(12, 1, value as u64)
    }
    /// `AccessReenlightenmentControls`: bits 13..=13 de `as_uint64`.
    pub const ACCESS_REENLIGHTENMENT_CONTROLS_SHIFT: u32 = 13;
    pub const ACCESS_REENLIGHTENMENT_CONTROLS_MASK: u64 = 0x2000;
    #[inline(always)]
    pub fn access_reenlightenment_controls(&self) -> u64 {
        self.as_uint64.bits(13, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_reenlightenment_controls(&self, value: u64) {
        self.as_uint64.set_bits(13, 1, value as u64)
    }
    /// `AccessRootSchedulerReg`: bits 14..=14 de `as_uint64`.
    pub const ACCESS_ROOT_SCHEDULER_REG_SHIFT: u32 = 14;
    pub const ACCESS_ROOT_SCHEDULER_REG_MASK: u64 = 0x4000;
    #[inline(always)]
    pub fn access_root_scheduler_reg(&self) -> u64 {
        self.as_uint64.bits(14, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_root_scheduler_reg(&self, value: u64) {
        self.as_uint64.set_bits(14, 1, value as u64)
    }
    /// `AccessTscInvariantControls`: bits 15..=15 de `as_uint64`.
    pub const ACCESS_TSC_INVARIANT_CONTROLS_SHIFT: u32 = 15;
    pub const ACCESS_TSC_INVARIANT_CONTROLS_MASK: u64 = 0x8000;
    #[inline(always)]
    pub fn access_tsc_invariant_controls(&self) -> u64 {
        self.as_uint64.bits(15, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_tsc_invariant_controls(&self, value: u64) {
        self.as_uint64.set_bits(15, 1, value as u64)
    }
    /// `Reserved1`: bits 16..=31 de `as_uint64`.
    pub const RESERVED1_SHIFT: u32 = 16;
    pub const RESERVED1_MASK: u64 = 0xffff0000;
    #[inline(always)]
    pub fn reserved1(&self) -> u64 {
        self.as_uint64.bits(16, 16) as u64
    }
    #[inline(always)]
    pub fn set_reserved1(&self, value: u64) {
        self.as_uint64.set_bits(16, 16, value as u64)
    }
    /// `CreatePartitions`: bits 32..=32 de `as_uint64`.
    pub const CREATE_PARTITIONS_SHIFT: u32 = 32;
    pub const CREATE_PARTITIONS_MASK: u64 = 0x100000000;
    #[inline(always)]
    pub fn create_partitions(&self) -> u64 {
        self.as_uint64.bits(32, 1) as u64
    }
    #[inline(always)]
    pub fn set_create_partitions(&self, value: u64) {
        self.as_uint64.set_bits(32, 1, value as u64)
    }
    /// `AccessPartitionId`: bits 33..=33 de `as_uint64`.
    pub const ACCESS_PARTITION_ID_SHIFT: u32 = 33;
    pub const ACCESS_PARTITION_ID_MASK: u64 = 0x200000000;
    #[inline(always)]
    pub fn access_partition_id(&self) -> u64 {
        self.as_uint64.bits(33, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_partition_id(&self, value: u64) {
        self.as_uint64.set_bits(33, 1, value as u64)
    }
    /// `AccessMemoryPool`: bits 34..=34 de `as_uint64`.
    pub const ACCESS_MEMORY_POOL_SHIFT: u32 = 34;
    pub const ACCESS_MEMORY_POOL_MASK: u64 = 0x400000000;
    #[inline(always)]
    pub fn access_memory_pool(&self) -> u64 {
        self.as_uint64.bits(34, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_memory_pool(&self, value: u64) {
        self.as_uint64.set_bits(34, 1, value as u64)
    }
    /// `AdjustMessageBuffers`: bits 35..=35 de `as_uint64`.
    pub const ADJUST_MESSAGE_BUFFERS_SHIFT: u32 = 35;
    pub const ADJUST_MESSAGE_BUFFERS_MASK: u64 = 0x800000000;
    #[inline(always)]
    pub fn adjust_message_buffers(&self) -> u64 {
        self.as_uint64.bits(35, 1) as u64
    }
    #[inline(always)]
    pub fn set_adjust_message_buffers(&self, value: u64) {
        self.as_uint64.set_bits(35, 1, value as u64)
    }
    /// `PostMessages`: bits 36..=36 de `as_uint64`.
    pub const POST_MESSAGES_SHIFT: u32 = 36;
    pub const POST_MESSAGES_MASK: u64 = 0x1000000000;
    #[inline(always)]
    pub fn post_messages(&self) -> u64 {
        self.as_uint64.bits(36, 1) as u64
    }
    #[inline(always)]
    pub fn set_post_messages(&self, value: u64) {
        self.as_uint64.set_bits(36, 1, value as u64)
    }
    /// `SignalEvents`: bits 37..=37 de `as_uint64`.
    pub const SIGNAL_EVENTS_SHIFT: u32 = 37;
    pub const SIGNAL_EVENTS_MASK: u64 = 0x2000000000;
    #[inline(always)]
    pub fn signal_events(&self) -> u64 {
        self.as_uint64.bits(37, 1) as u64
    }
    #[inline(always)]
    pub fn set_signal_events(&self, value: u64) {
        self.as_uint64.set_bits(37, 1, value as u64)
    }
    /// `CreatePort`: bits 38..=38 de `as_uint64`.
    pub const CREATE_PORT_SHIFT: u32 = 38;
    pub const CREATE_PORT_MASK: u64 = 0x4000000000;
    #[inline(always)]
    pub fn create_port(&self) -> u64 {
        self.as_uint64.bits(38, 1) as u64
    }
    #[inline(always)]
    pub fn set_create_port(&self, value: u64) {
        self.as_uint64.set_bits(38, 1, value as u64)
    }
    /// `ConnectPort`: bits 39..=39 de `as_uint64`.
    pub const CONNECT_PORT_SHIFT: u32 = 39;
    pub const CONNECT_PORT_MASK: u64 = 0x8000000000;
    #[inline(always)]
    pub fn connect_port(&self) -> u64 {
        self.as_uint64.bits(39, 1) as u64
    }
    #[inline(always)]
    pub fn set_connect_port(&self, value: u64) {
        self.as_uint64.set_bits(39, 1, value as u64)
    }
    /// `AccessStats`: bits 40..=40 de `as_uint64`.
    pub const ACCESS_STATS_SHIFT: u32 = 40;
    pub const ACCESS_STATS_MASK: u64 = 0x10000000000;
    #[inline(always)]
    pub fn access_stats(&self) -> u64 {
        self.as_uint64.bits(40, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_stats(&self, value: u64) {
        self.as_uint64.set_bits(40, 1, value as u64)
    }
    /// `Reserved2`: bits 41..=42 de `as_uint64`.
    pub const RESERVED2_SHIFT: u32 = 41;
    pub const RESERVED2_MASK: u64 = 0x60000000000;
    #[inline(always)]
    pub fn reserved2(&self) -> u64 {
        self.as_uint64.bits(41, 2) as u64
    }
    #[inline(always)]
    pub fn set_reserved2(&self, value: u64) {
        self.as_uint64.set_bits(41, 2, value as u64)
    }
    /// `Debugging`: bits 43..=43 de `as_uint64`.
    pub const DEBUGGING_SHIFT: u32 = 43;
    pub const DEBUGGING_MASK: u64 = 0x80000000000;
    #[inline(always)]
    pub fn debugging(&self) -> u64 {
        self.as_uint64.bits(43, 1) as u64
    }
    #[inline(always)]
    pub fn set_debugging(&self, value: u64) {
        self.as_uint64.set_bits(43, 1, value as u64)
    }
    /// `CpuManagement`: bits 44..=44 de `as_uint64`.
    pub const CPU_MANAGEMENT_SHIFT: u32 = 44;
    pub const CPU_MANAGEMENT_MASK: u64 = 0x100000000000;
    #[inline(always)]
    pub fn cpu_management(&self) -> u64 {
        self.as_uint64.bits(44, 1) as u64
    }
    #[inline(always)]
    pub fn set_cpu_management(&self, value: u64) {
        self.as_uint64.set_bits(44, 1, value as u64)
    }
    /// `ConfigureProfiler`: bits 45..=45 de `as_uint64`.
    pub const CONFIGURE_PROFILER_SHIFT: u32 = 45;
    pub const CONFIGURE_PROFILER_MASK: u64 = 0x200000000000;
    #[inline(always)]
    pub fn configure_profiler(&self) -> u64 {
        self.as_uint64.bits(45, 1) as u64
    }
    #[inline(always)]
    pub fn set_configure_profiler(&self, value: u64) {
        self.as_uint64.set_bits(45, 1, value as u64)
    }
    /// `AccessVpExitTracing`: bits 46..=46 de `as_uint64`.
    pub const ACCESS_VP_EXIT_TRACING_SHIFT: u32 = 46;
    pub const ACCESS_VP_EXIT_TRACING_MASK: u64 = 0x400000000000;
    #[inline(always)]
    pub fn access_vp_exit_tracing(&self) -> u64 {
        self.as_uint64.bits(46, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_vp_exit_tracing(&self, value: u64) {
        self.as_uint64.set_bits(46, 1, value as u64)
    }
    /// `EnableExtendedGvaRangesForFlushVirtualAddressList`: bits 47..=47 de `as_uint64`.
    pub const ENABLE_EXTENDED_GVA_RANGES_FOR_FLUSH_VIRTUAL_ADDRESS_LIST_SHIFT: u32 = 47;
    pub const ENABLE_EXTENDED_GVA_RANGES_FOR_FLUSH_VIRTUAL_ADDRESS_LIST_MASK: u64 = 0x800000000000;
    #[inline(always)]
    pub fn enable_extended_gva_ranges_for_flush_virtual_address_list(&self) -> u64 {
        self.as_uint64.bits(47, 1) as u64
    }
    #[inline(always)]
    pub fn set_enable_extended_gva_ranges_for_flush_virtual_address_list(&self, value: u64) {
        self.as_uint64.set_bits(47, 1, value as u64)
    }
    /// `AccessVsm`: bits 48..=48 de `as_uint64`.
    pub const ACCESS_VSM_SHIFT: u32 = 48;
    pub const ACCESS_VSM_MASK: u64 = 0x1000000000000;
    #[inline(always)]
    pub fn access_vsm(&self) -> u64 {
        self.as_uint64.bits(48, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_vsm(&self, value: u64) {
        self.as_uint64.set_bits(48, 1, value as u64)
    }
    /// `AccessVpRegisters`: bits 49..=49 de `as_uint64`.
    pub const ACCESS_VP_REGISTERS_SHIFT: u32 = 49;
    pub const ACCESS_VP_REGISTERS_MASK: u64 = 0x2000000000000;
    #[inline(always)]
    pub fn access_vp_registers(&self) -> u64 {
        self.as_uint64.bits(49, 1) as u64
    }
    #[inline(always)]
    pub fn set_access_vp_registers(&self, value: u64) {
        self.as_uint64.set_bits(49, 1, value as u64)
    }
    /// `UnusedBit`: bits 50..=50 de `as_uint64`.
    pub const UNUSED_BIT_SHIFT: u32 = 50;
    pub const UNUSED_BIT_MASK: u64 = 0x4000000000000;
    #[inline(always)]
    pub fn unused_bit(&self) -> u64 {
        self.as_uint64.bits(50, 1) as u64
    }
    #[inline(always)]
    pub fn set_unused_bit(&self, value: u64) {
        self.as_uint64.set_bits(50, 1, value as u64)
    }
    /// `FastHypercallOutput`: bits 51..=51 de `as_uint64`.
    pub const FAST_HYPERCALL_OUTPUT_SHIFT: u32 = 51;
    pub const FAST_HYPERCALL_OUTPUT_MASK: u64 = 0x8000000000000;
    #[inline(always)]
    pub fn fast_hypercall_output(&self) -> u64 {
        self.as_uint64.bits(51, 1) as u64
    }
    #[inline(always)]
    pub fn set_fast_hypercall_output(&self, value: u64) {
        self.as_uint64.set_bits(51, 1, value as u64)
    }
    /// `EnableExtendedHypercalls`: bits 52..=52 de `as_uint64`.
    pub const ENABLE_EXTENDED_HYPERCALLS_SHIFT: u32 = 52;
    pub const ENABLE_EXTENDED_HYPERCALLS_MASK: u64 = 0x10000000000000;
    #[inline(always)]
    pub fn enable_extended_hypercalls(&self) -> u64 {
        self.as_uint64.bits(52, 1) as u64
    }
    #[inline(always)]
    pub fn set_enable_extended_hypercalls(&self, value: u64) {
        self.as_uint64.set_bits(52, 1, value as u64)
    }
    /// `StartVirtualProcessor`: bits 53..=53 de `as_uint64`.
    pub const START_VIRTUAL_PROCESSOR_SHIFT: u32 = 53;
    pub const START_VIRTUAL_PROCESSOR_MASK: u64 = 0x20000000000000;
    #[inline(always)]
    pub fn start_virtual_processor(&self) -> u64 {
        self.as_uint64.bits(53, 1) as u64
    }
    #[inline(always)]
    pub fn set_start_virtual_processor(&self, value: u64) {
        self.as_uint64.set_bits(53, 1, value as u64)
    }
    /// `Isolation`: bits 54..=54 de `as_uint64`.
    pub const ISOLATION_SHIFT: u32 = 54;
    pub const ISOLATION_MASK: u64 = 0x40000000000000;
    #[inline(always)]
    pub fn isolation(&self) -> u64 {
        self.as_uint64.bits(54, 1) as u64
    }
    #[inline(always)]
    pub fn set_isolation(&self, value: u64) {
        self.as_uint64.set_bits(54, 1, value as u64)
    }
    /// `Reserved3`: bits 55..=63 de `as_uint64`.
    pub const RESERVED3_SHIFT: u32 = 55;
    pub const RESERVED3_MASK: u64 = 0xff80000000000000;
    #[inline(always)]
    pub fn reserved3(&self) -> u64 {
        self.as_uint64.bits(55, 9) as u64
    }
    #[inline(always)]
    pub fn set_reserved3(&self, value: u64) {
        self.as_uint64.set_bits(55, 9, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<HvPartitionPrivilegeMask>() == 0x8);
    assert!(core::mem::offset_of!(HvPartitionPrivilegeMask, as_uint64) == 0x0);
};

/// `_XSTATE_SAVE` (0x38 bytes).
#[repr(C)]
pub struct XstateSave {
    /// -> `_XSTATE_SAVE`
    pub prev: Field<u64>,
    /// -> `_KTHREAD`
    pub thread: Field<u64>,
    pub level: Field<u8>,
    _pad_11: Reserved<0x7>,
    pub x_state_context: XstateContext,
}

unsafe impl NtStruct for XstateSave {}

const _: () = {
    assert!(core::mem::size_of::<XstateSave>() == 0x38);
    assert!(core::mem::offset_of!(XstateSave, prev) == 0x0);
    assert!(core::mem::offset_of!(XstateSave, thread) == 0x8);
    assert!(core::mem::offset_of!(XstateSave, level) == 0x10);
    assert!(core::mem::offset_of!(XstateSave, x_state_context) == 0x18);
};

/// `_XSTATE_CONTEXT` (0x20 bytes).
#[repr(C)]
pub struct XstateContext {
    pub mask: Field<u64>,
    pub length: Field<u32>,
    pub reserved1: Field<u32>,
    /// -> `_XSAVE_AREA`
    pub area: Field<u64>,
    /// -> `void`
    pub buffer: Field<u64>,
}

unsafe impl NtStruct for XstateContext {}

const _: () = {
    assert!(core::mem::size_of::<XstateContext>() == 0x20);
    assert!(core::mem::offset_of!(XstateContext, mask) == 0x0);
    assert!(core::mem::offset_of!(XstateContext, length) == 0x8);
    assert!(core::mem::offset_of!(XstateContext, reserved1) == 0xc);
    assert!(core::mem::offset_of!(XstateContext, area) == 0x10);
    assert!(core::mem::offset_of!(XstateContext, buffer) == 0x18);
};
