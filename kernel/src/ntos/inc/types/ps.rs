//! Ps: processos, threads, jobs, PEB/TEB e parâmetros de processo.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_ETHREAD` (0x898 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EthreadView1`..`EthreadView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Ethread {
    pub tcb: Kthread,
    pub create_time: LargeInteger,
    pub exit_time: LargeInteger,
    _pad_440: Reserved<0x8>,
    pub post_block_list: ListEntry,
    /// -> `_TERMINATION_PORT`
    pub termination_port: Field<u64>,
    pub active_timer_list_lock: Field<u64>,
    pub active_timer_list_head: ListEntry,
    pub cid: ClientId,
    pub keyed_wait_semaphore: Ksemaphore,
    pub client_security: PsClientSecurityContext,
    pub irp_list: ListEntry,
    pub top_level_irp: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub device_to_verify: Field<u64>,
    /// -> `void`
    pub win32_start_address: Field<u64>,
    /// -> `void`
    pub charge_only_session: Field<u64>,
    /// -> `void`
    pub legacy_power_object: Field<u64>,
    pub thread_list_entry: ListEntry,
    pub rundown_protect: ExRundownRef,
    pub thread_lock: ExPushLock,
    pub read_cluster_size: Field<u32>,
    pub mm_lock_ordering: Field<i32>,
    pub cross_thread_flags: Field<u32>,
    pub same_thread_passive_flags: Field<u32>,
    pub same_thread_apc_flags: Field<u32>,
    pub cache_manager_active: Field<u8>,
    pub disable_page_fault_clustering: Field<u8>,
    pub active_fault_count: Field<u8>,
    pub lock_order_state: Field<u8>,
    pub performance_count_low_reserved: Field<u32>,
    pub performance_count_high_reserved: Field<i32>,
    pub alpc_message_id: Field<u64>,
    /// -> `void`
    pub alpc_message: Field<u64>,
    pub alpc_wait_list_entry: ListEntry,
    pub exit_status: Field<i32>,
    pub cache_manager_count: Field<u32>,
    pub io_boost_count: Field<u32>,
    pub io_qo_s_boost_count: Field<u32>,
    pub io_qo_s_throttle_count: Field<u32>,
    pub kernel_stack_reference: Field<u32>,
    pub boost_list: ListEntry,
    pub deboost_list: ListEntry,
    pub boost_list_lock: Field<u64>,
    pub irp_list_lock: Field<u64>,
    /// -> `void`
    pub reserved_for_synch_tracking: Field<u64>,
    pub cm_callback_list_head: SingleListEntry,
    /// -> `_GUID`
    pub activity_id: Field<u64>,
    pub se_learning_mode_list_head: SingleListEntry,
    /// -> `void`
    pub verifier_context: Field<u64>,
    /// -> `void`
    pub adjusted_client_token: Field<u64>,
    /// -> `void`
    pub work_on_behalf_thread: Field<u64>,
    pub property_set: PsPropertySet,
    /// -> `void`
    pub pico_context: Field<u64>,
    pub user_fs_base: Field<u64>,
    pub user_gs_base: Field<u64>,
    /// -> `_THREAD_ENERGY_VALUES`
    pub energy_values: Field<u64>,
    pub selected_cpu_sets: Field<u64>,
    /// -> `_EJOB`
    pub silo: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub thread_name: Field<u64>,
    /// -> `_CONTEXT`
    pub set_context_state: Field<u64>,
    pub last_expected_run_time: Field<u32>,
    pub heap_data: Field<u32>,
    pub owner_entry_list_head: ListEntry,
    pub disowned_owner_entry_list_lock: Field<u64>,
    pub disowned_owner_entry_list_head: ListEntry,
    pub lock_entries: [KlockEntry; 6],
    /// -> `void`
    pub cm_dbg_info: Field<u64>,
}

/// Vista 1 de `_ETHREAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EthreadView1 {
    _pad_0: Reserved<0x438>,
    pub keyed_wait_chain: ListEntry,
    /// -> `void`
    pub forward_link_shadow: Field<u64>,
    /// -> `void`
    pub start_address: Field<u64>,
    /// -> `_ETHREAD`
    pub reaper_link: Field<u64>,
    _pad_460: Reserved<0x28>,
    pub alpc_wait_semaphore: Ksemaphore,
    _pad_4a8: Reserved<0x70>,
    pub bitfield_518: Field<u8>,
    pub bitfield_519: Field<u8>,
    _pad_51a: Reserved<0x16>,
    pub alpc_receive_attribute_set: Field<u32>,
    _pad_534: Reserved<0xcc>,
    /// -> `u64`
    pub selected_cpu_sets_indirect: Field<u64>,
    _pad_608: Reserved<0x290>,
}

/// Vista 2 de `_ETHREAD` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EthreadView2 {
    _pad_0: Reserved<0x458>,
    /// -> `void`
    pub keyed_wait_value: Field<u64>,
    _pad_460: Reserved<0x438>,
}

impl core::ops::Deref for Ethread {
    type Target = EthreadView1;
    #[inline(always)]
    fn deref(&self) -> &EthreadView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EthreadView1>() }
    }
}

impl core::ops::Deref for EthreadView1 {
    type Target = EthreadView2;
    #[inline(always)]
    fn deref(&self) -> &EthreadView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EthreadView2>() }
    }
}

unsafe impl NtStruct for Ethread {}

impl Ethread {
    /// `Terminated`: bits 0..=0 de `cross_thread_flags`.
    pub const TERMINATED_SHIFT: u32 = 0;
    pub const TERMINATED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn terminated(&self) -> u32 {
        self.cross_thread_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_terminated(&self, value: u32) {
        self.cross_thread_flags.set_bits(0, 1, value as u64)
    }
    /// `ThreadInserted`: bits 1..=1 de `cross_thread_flags`.
    pub const THREAD_INSERTED_SHIFT: u32 = 1;
    pub const THREAD_INSERTED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn thread_inserted(&self) -> u32 {
        self.cross_thread_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_thread_inserted(&self, value: u32) {
        self.cross_thread_flags.set_bits(1, 1, value as u64)
    }
    /// `HideFromDebugger`: bits 2..=2 de `cross_thread_flags`.
    pub const HIDE_FROM_DEBUGGER_SHIFT: u32 = 2;
    pub const HIDE_FROM_DEBUGGER_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn hide_from_debugger(&self) -> u32 {
        self.cross_thread_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_hide_from_debugger(&self, value: u32) {
        self.cross_thread_flags.set_bits(2, 1, value as u64)
    }
    /// `ActiveImpersonationInfo`: bits 3..=3 de `cross_thread_flags`.
    pub const ACTIVE_IMPERSONATION_INFO_SHIFT: u32 = 3;
    pub const ACTIVE_IMPERSONATION_INFO_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn active_impersonation_info(&self) -> u32 {
        self.cross_thread_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_active_impersonation_info(&self, value: u32) {
        self.cross_thread_flags.set_bits(3, 1, value as u64)
    }
    /// `HardErrorsAreDisabled`: bits 4..=4 de `cross_thread_flags`.
    pub const HARD_ERRORS_ARE_DISABLED_SHIFT: u32 = 4;
    pub const HARD_ERRORS_ARE_DISABLED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn hard_errors_are_disabled(&self) -> u32 {
        self.cross_thread_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_hard_errors_are_disabled(&self, value: u32) {
        self.cross_thread_flags.set_bits(4, 1, value as u64)
    }
    /// `BreakOnTermination`: bits 5..=5 de `cross_thread_flags`.
    pub const BREAK_ON_TERMINATION_SHIFT: u32 = 5;
    pub const BREAK_ON_TERMINATION_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn break_on_termination(&self) -> u32 {
        self.cross_thread_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_break_on_termination(&self, value: u32) {
        self.cross_thread_flags.set_bits(5, 1, value as u64)
    }
    /// `SkipCreationMsg`: bits 6..=6 de `cross_thread_flags`.
    pub const SKIP_CREATION_MSG_SHIFT: u32 = 6;
    pub const SKIP_CREATION_MSG_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn skip_creation_msg(&self) -> u32 {
        self.cross_thread_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_skip_creation_msg(&self, value: u32) {
        self.cross_thread_flags.set_bits(6, 1, value as u64)
    }
    /// `SkipTerminationMsg`: bits 7..=7 de `cross_thread_flags`.
    pub const SKIP_TERMINATION_MSG_SHIFT: u32 = 7;
    pub const SKIP_TERMINATION_MSG_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn skip_termination_msg(&self) -> u32 {
        self.cross_thread_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_skip_termination_msg(&self, value: u32) {
        self.cross_thread_flags.set_bits(7, 1, value as u64)
    }
    /// `CopyTokenOnOpen`: bits 8..=8 de `cross_thread_flags`.
    pub const COPY_TOKEN_ON_OPEN_SHIFT: u32 = 8;
    pub const COPY_TOKEN_ON_OPEN_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn copy_token_on_open(&self) -> u32 {
        self.cross_thread_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_copy_token_on_open(&self, value: u32) {
        self.cross_thread_flags.set_bits(8, 1, value as u64)
    }
    /// `ThreadIoPriority`: bits 9..=11 de `cross_thread_flags`.
    pub const THREAD_IO_PRIORITY_SHIFT: u32 = 9;
    pub const THREAD_IO_PRIORITY_MASK: u32 = 0xe00;
    #[inline(always)]
    pub fn thread_io_priority(&self) -> u32 {
        self.cross_thread_flags.bits(9, 3) as u32
    }
    #[inline(always)]
    pub fn set_thread_io_priority(&self, value: u32) {
        self.cross_thread_flags.set_bits(9, 3, value as u64)
    }
    /// `ThreadPagePriority`: bits 12..=14 de `cross_thread_flags`.
    pub const THREAD_PAGE_PRIORITY_SHIFT: u32 = 12;
    pub const THREAD_PAGE_PRIORITY_MASK: u32 = 0x7000;
    #[inline(always)]
    pub fn thread_page_priority(&self) -> u32 {
        self.cross_thread_flags.bits(12, 3) as u32
    }
    #[inline(always)]
    pub fn set_thread_page_priority(&self, value: u32) {
        self.cross_thread_flags.set_bits(12, 3, value as u64)
    }
    /// `RundownFail`: bits 15..=15 de `cross_thread_flags`.
    pub const RUNDOWN_FAIL_SHIFT: u32 = 15;
    pub const RUNDOWN_FAIL_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn rundown_fail(&self) -> u32 {
        self.cross_thread_flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_rundown_fail(&self, value: u32) {
        self.cross_thread_flags.set_bits(15, 1, value as u64)
    }
    /// `UmsForceQueueTermination`: bits 16..=16 de `cross_thread_flags`.
    pub const UMS_FORCE_QUEUE_TERMINATION_SHIFT: u32 = 16;
    pub const UMS_FORCE_QUEUE_TERMINATION_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn ums_force_queue_termination(&self) -> u32 {
        self.cross_thread_flags.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_ums_force_queue_termination(&self, value: u32) {
        self.cross_thread_flags.set_bits(16, 1, value as u64)
    }
    /// `IndirectCpuSets`: bits 17..=17 de `cross_thread_flags`.
    pub const INDIRECT_CPU_SETS_SHIFT: u32 = 17;
    pub const INDIRECT_CPU_SETS_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn indirect_cpu_sets(&self) -> u32 {
        self.cross_thread_flags.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_indirect_cpu_sets(&self, value: u32) {
        self.cross_thread_flags.set_bits(17, 1, value as u64)
    }
    /// `DisableDynamicCodeOptOut`: bits 18..=18 de `cross_thread_flags`.
    pub const DISABLE_DYNAMIC_CODE_OPT_OUT_SHIFT: u32 = 18;
    pub const DISABLE_DYNAMIC_CODE_OPT_OUT_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn disable_dynamic_code_opt_out(&self) -> u32 {
        self.cross_thread_flags.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_dynamic_code_opt_out(&self, value: u32) {
        self.cross_thread_flags.set_bits(18, 1, value as u64)
    }
    /// `ExplicitCaseSensitivity`: bits 19..=19 de `cross_thread_flags`.
    pub const EXPLICIT_CASE_SENSITIVITY_SHIFT: u32 = 19;
    pub const EXPLICIT_CASE_SENSITIVITY_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn explicit_case_sensitivity(&self) -> u32 {
        self.cross_thread_flags.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_explicit_case_sensitivity(&self, value: u32) {
        self.cross_thread_flags.set_bits(19, 1, value as u64)
    }
    /// `PicoNotifyExit`: bits 20..=20 de `cross_thread_flags`.
    pub const PICO_NOTIFY_EXIT_SHIFT: u32 = 20;
    pub const PICO_NOTIFY_EXIT_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn pico_notify_exit(&self) -> u32 {
        self.cross_thread_flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_pico_notify_exit(&self, value: u32) {
        self.cross_thread_flags.set_bits(20, 1, value as u64)
    }
    /// `DbgWerUserReportActive`: bits 21..=21 de `cross_thread_flags`.
    pub const DBG_WER_USER_REPORT_ACTIVE_SHIFT: u32 = 21;
    pub const DBG_WER_USER_REPORT_ACTIVE_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn dbg_wer_user_report_active(&self) -> u32 {
        self.cross_thread_flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_dbg_wer_user_report_active(&self, value: u32) {
        self.cross_thread_flags.set_bits(21, 1, value as u64)
    }
    /// `ForcedSelfTrimActive`: bits 22..=22 de `cross_thread_flags`.
    pub const FORCED_SELF_TRIM_ACTIVE_SHIFT: u32 = 22;
    pub const FORCED_SELF_TRIM_ACTIVE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn forced_self_trim_active(&self) -> u32 {
        self.cross_thread_flags.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_forced_self_trim_active(&self, value: u32) {
        self.cross_thread_flags.set_bits(22, 1, value as u64)
    }
    /// `SamplingCoverage`: bits 23..=23 de `cross_thread_flags`.
    pub const SAMPLING_COVERAGE_SHIFT: u32 = 23;
    pub const SAMPLING_COVERAGE_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn sampling_coverage(&self) -> u32 {
        self.cross_thread_flags.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_sampling_coverage(&self, value: u32) {
        self.cross_thread_flags.set_bits(23, 1, value as u64)
    }
    /// `ReservedCrossThreadFlags`: bits 24..=31 de `cross_thread_flags`.
    pub const RESERVED_CROSS_THREAD_FLAGS_SHIFT: u32 = 24;
    pub const RESERVED_CROSS_THREAD_FLAGS_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn reserved_cross_thread_flags(&self) -> u32 {
        self.cross_thread_flags.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_reserved_cross_thread_flags(&self, value: u32) {
        self.cross_thread_flags.set_bits(24, 8, value as u64)
    }
    /// `ActiveExWorker`: bits 0..=0 de `same_thread_passive_flags`.
    pub const ACTIVE_EX_WORKER_SHIFT: u32 = 0;
    pub const ACTIVE_EX_WORKER_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn active_ex_worker(&self) -> u32 {
        self.same_thread_passive_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_active_ex_worker(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(0, 1, value as u64)
    }
    /// `MemoryMaker`: bits 1..=1 de `same_thread_passive_flags`.
    pub const MEMORY_MAKER_SHIFT: u32 = 1;
    pub const MEMORY_MAKER_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn memory_maker(&self) -> u32 {
        self.same_thread_passive_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_memory_maker(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(1, 1, value as u64)
    }
    /// `StoreLockThread`: bits 2..=3 de `same_thread_passive_flags`.
    pub const STORE_LOCK_THREAD_SHIFT: u32 = 2;
    pub const STORE_LOCK_THREAD_MASK: u32 = 0xc;
    #[inline(always)]
    pub fn store_lock_thread(&self) -> u32 {
        self.same_thread_passive_flags.bits(2, 2) as u32
    }
    #[inline(always)]
    pub fn set_store_lock_thread(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(2, 2, value as u64)
    }
    /// `ClonedThread`: bits 4..=4 de `same_thread_passive_flags`.
    pub const CLONED_THREAD_SHIFT: u32 = 4;
    pub const CLONED_THREAD_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn cloned_thread(&self) -> u32 {
        self.same_thread_passive_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_cloned_thread(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(4, 1, value as u64)
    }
    /// `KeyedEventInUse`: bits 5..=5 de `same_thread_passive_flags`.
    pub const KEYED_EVENT_IN_USE_SHIFT: u32 = 5;
    pub const KEYED_EVENT_IN_USE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn keyed_event_in_use(&self) -> u32 {
        self.same_thread_passive_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_keyed_event_in_use(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(5, 1, value as u64)
    }
    /// `SelfTerminate`: bits 6..=6 de `same_thread_passive_flags`.
    pub const SELF_TERMINATE_SHIFT: u32 = 6;
    pub const SELF_TERMINATE_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn self_terminate(&self) -> u32 {
        self.same_thread_passive_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_self_terminate(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(6, 1, value as u64)
    }
    /// `RespectIoPriority`: bits 7..=7 de `same_thread_passive_flags`.
    pub const RESPECT_IO_PRIORITY_SHIFT: u32 = 7;
    pub const RESPECT_IO_PRIORITY_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn respect_io_priority(&self) -> u32 {
        self.same_thread_passive_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_respect_io_priority(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(7, 1, value as u64)
    }
    /// `ActivePageLists`: bits 8..=8 de `same_thread_passive_flags`.
    pub const ACTIVE_PAGE_LISTS_SHIFT: u32 = 8;
    pub const ACTIVE_PAGE_LISTS_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn active_page_lists(&self) -> u32 {
        self.same_thread_passive_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_active_page_lists(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(8, 1, value as u64)
    }
    /// `SecureContext`: bits 9..=9 de `same_thread_passive_flags`.
    pub const SECURE_CONTEXT_SHIFT: u32 = 9;
    pub const SECURE_CONTEXT_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn secure_context(&self) -> u32 {
        self.same_thread_passive_flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_secure_context(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(9, 1, value as u64)
    }
    /// `ZeroPageThread`: bits 10..=10 de `same_thread_passive_flags`.
    pub const ZERO_PAGE_THREAD_SHIFT: u32 = 10;
    pub const ZERO_PAGE_THREAD_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn zero_page_thread(&self) -> u32 {
        self.same_thread_passive_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_zero_page_thread(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(10, 1, value as u64)
    }
    /// `WorkloadClass`: bits 11..=11 de `same_thread_passive_flags`.
    pub const WORKLOAD_CLASS_SHIFT: u32 = 11;
    pub const WORKLOAD_CLASS_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn workload_class(&self) -> u32 {
        self.same_thread_passive_flags.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_workload_class(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(11, 1, value as u64)
    }
    /// `ReservedSameThreadPassiveFlags`: bits 12..=31 de `same_thread_passive_flags`.
    pub const RESERVED_SAME_THREAD_PASSIVE_FLAGS_SHIFT: u32 = 12;
    pub const RESERVED_SAME_THREAD_PASSIVE_FLAGS_MASK: u32 = 0xfffff000;
    #[inline(always)]
    pub fn reserved_same_thread_passive_flags(&self) -> u32 {
        self.same_thread_passive_flags.bits(12, 20) as u32
    }
    #[inline(always)]
    pub fn set_reserved_same_thread_passive_flags(&self, value: u32) {
        self.same_thread_passive_flags.set_bits(12, 20, value as u64)
    }
    /// `OwnsProcessAddressSpaceExclusive`: bits 0..=0 de `bitfield_518`.
    pub const OWNS_PROCESS_ADDRESS_SPACE_EXCLUSIVE_SHIFT: u32 = 0;
    pub const OWNS_PROCESS_ADDRESS_SPACE_EXCLUSIVE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn owns_process_address_space_exclusive(&self) -> u8 {
        self.bitfield_518.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_owns_process_address_space_exclusive(&self, value: u8) {
        self.bitfield_518.set_bits(0, 1, value as u64)
    }
    /// `OwnsProcessAddressSpaceShared`: bits 1..=1 de `bitfield_518`.
    pub const OWNS_PROCESS_ADDRESS_SPACE_SHARED_SHIFT: u32 = 1;
    pub const OWNS_PROCESS_ADDRESS_SPACE_SHARED_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn owns_process_address_space_shared(&self) -> u8 {
        self.bitfield_518.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_owns_process_address_space_shared(&self, value: u8) {
        self.bitfield_518.set_bits(1, 1, value as u64)
    }
    /// `HardFaultBehavior`: bits 2..=2 de `bitfield_518`.
    pub const HARD_FAULT_BEHAVIOR_SHIFT: u32 = 2;
    pub const HARD_FAULT_BEHAVIOR_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn hard_fault_behavior(&self) -> u8 {
        self.bitfield_518.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_hard_fault_behavior(&self, value: u8) {
        self.bitfield_518.set_bits(2, 1, value as u64)
    }
    /// `StartAddressInvalid`: bits 3..=3 de `bitfield_518`.
    pub const START_ADDRESS_INVALID_SHIFT: u32 = 3;
    pub const START_ADDRESS_INVALID_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn start_address_invalid(&self) -> u8 {
        self.bitfield_518.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_start_address_invalid(&self, value: u8) {
        self.bitfield_518.set_bits(3, 1, value as u64)
    }
    /// `EtwCalloutActive`: bits 4..=4 de `bitfield_518`.
    pub const ETW_CALLOUT_ACTIVE_SHIFT: u32 = 4;
    pub const ETW_CALLOUT_ACTIVE_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn etw_callout_active(&self) -> u8 {
        self.bitfield_518.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_etw_callout_active(&self, value: u8) {
        self.bitfield_518.set_bits(4, 1, value as u64)
    }
    /// `SuppressSymbolLoad`: bits 5..=5 de `bitfield_518`.
    pub const SUPPRESS_SYMBOL_LOAD_SHIFT: u32 = 5;
    pub const SUPPRESS_SYMBOL_LOAD_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn suppress_symbol_load(&self) -> u8 {
        self.bitfield_518.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_suppress_symbol_load(&self, value: u8) {
        self.bitfield_518.set_bits(5, 1, value as u64)
    }
    /// `Prefetching`: bits 6..=6 de `bitfield_518`.
    pub const PREFETCHING_SHIFT: u32 = 6;
    pub const PREFETCHING_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn prefetching(&self) -> u8 {
        self.bitfield_518.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_prefetching(&self, value: u8) {
        self.bitfield_518.set_bits(6, 1, value as u64)
    }
    /// `OwnsVadExclusive`: bits 7..=7 de `bitfield_518`.
    pub const OWNS_VAD_EXCLUSIVE_SHIFT: u32 = 7;
    pub const OWNS_VAD_EXCLUSIVE_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn owns_vad_exclusive(&self) -> u8 {
        self.bitfield_518.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_owns_vad_exclusive(&self, value: u8) {
        self.bitfield_518.set_bits(7, 1, value as u64)
    }
    /// `SystemPagePriorityActive`: bits 0..=0 de `bitfield_519`.
    pub const SYSTEM_PAGE_PRIORITY_ACTIVE_SHIFT: u32 = 0;
    pub const SYSTEM_PAGE_PRIORITY_ACTIVE_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn system_page_priority_active(&self) -> u8 {
        self.bitfield_519.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_system_page_priority_active(&self, value: u8) {
        self.bitfield_519.set_bits(0, 1, value as u64)
    }
    /// `SystemPagePriority`: bits 1..=3 de `bitfield_519`.
    pub const SYSTEM_PAGE_PRIORITY_SHIFT: u32 = 1;
    pub const SYSTEM_PAGE_PRIORITY_MASK: u8 = 0xe;
    #[inline(always)]
    pub fn system_page_priority(&self) -> u8 {
        self.bitfield_519.bits(1, 3) as u8
    }
    #[inline(always)]
    pub fn set_system_page_priority(&self, value: u8) {
        self.bitfield_519.set_bits(1, 3, value as u64)
    }
    /// `AllowUserWritesToExecutableMemory`: bits 4..=4 de `bitfield_519`.
    pub const ALLOW_USER_WRITES_TO_EXECUTABLE_MEMORY_SHIFT: u32 = 4;
    pub const ALLOW_USER_WRITES_TO_EXECUTABLE_MEMORY_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn allow_user_writes_to_executable_memory(&self) -> u8 {
        self.bitfield_519.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_allow_user_writes_to_executable_memory(&self, value: u8) {
        self.bitfield_519.set_bits(4, 1, value as u64)
    }
    /// `AllowKernelWritesToExecutableMemory`: bits 5..=5 de `bitfield_519`.
    pub const ALLOW_KERNEL_WRITES_TO_EXECUTABLE_MEMORY_SHIFT: u32 = 5;
    pub const ALLOW_KERNEL_WRITES_TO_EXECUTABLE_MEMORY_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn allow_kernel_writes_to_executable_memory(&self) -> u8 {
        self.bitfield_519.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_allow_kernel_writes_to_executable_memory(&self, value: u8) {
        self.bitfield_519.set_bits(5, 1, value as u64)
    }
    /// `OwnsVadShared`: bits 6..=6 de `bitfield_519`.
    pub const OWNS_VAD_SHARED_SHIFT: u32 = 6;
    pub const OWNS_VAD_SHARED_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn owns_vad_shared(&self) -> u8 {
        self.bitfield_519.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_owns_vad_shared(&self, value: u8) {
        self.bitfield_519.set_bits(6, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Ethread>() == 0x898);
    assert!(core::mem::offset_of!(Ethread, tcb) == 0x0);
    assert!(core::mem::offset_of!(Ethread, create_time) == 0x430);
    assert!(core::mem::offset_of!(Ethread, exit_time) == 0x438);
    assert!(core::mem::offset_of!(Ethread, post_block_list) == 0x448);
    assert!(core::mem::offset_of!(Ethread, termination_port) == 0x458);
    assert!(core::mem::offset_of!(Ethread, active_timer_list_lock) == 0x460);
    assert!(core::mem::offset_of!(Ethread, active_timer_list_head) == 0x468);
    assert!(core::mem::offset_of!(Ethread, cid) == 0x478);
    assert!(core::mem::offset_of!(Ethread, keyed_wait_semaphore) == 0x488);
    assert!(core::mem::offset_of!(Ethread, client_security) == 0x4a8);
    assert!(core::mem::offset_of!(Ethread, irp_list) == 0x4b0);
    assert!(core::mem::offset_of!(Ethread, top_level_irp) == 0x4c0);
    assert!(core::mem::offset_of!(Ethread, device_to_verify) == 0x4c8);
    assert!(core::mem::offset_of!(Ethread, win32_start_address) == 0x4d0);
    assert!(core::mem::offset_of!(Ethread, charge_only_session) == 0x4d8);
    assert!(core::mem::offset_of!(Ethread, legacy_power_object) == 0x4e0);
    assert!(core::mem::offset_of!(Ethread, thread_list_entry) == 0x4e8);
    assert!(core::mem::offset_of!(Ethread, rundown_protect) == 0x4f8);
    assert!(core::mem::offset_of!(Ethread, thread_lock) == 0x500);
    assert!(core::mem::offset_of!(Ethread, read_cluster_size) == 0x508);
    assert!(core::mem::offset_of!(Ethread, mm_lock_ordering) == 0x50c);
    assert!(core::mem::offset_of!(Ethread, cross_thread_flags) == 0x510);
    assert!(core::mem::offset_of!(Ethread, same_thread_passive_flags) == 0x514);
    assert!(core::mem::offset_of!(Ethread, same_thread_apc_flags) == 0x518);
    assert!(core::mem::offset_of!(Ethread, cache_manager_active) == 0x51c);
    assert!(core::mem::offset_of!(Ethread, disable_page_fault_clustering) == 0x51d);
    assert!(core::mem::offset_of!(Ethread, active_fault_count) == 0x51e);
    assert!(core::mem::offset_of!(Ethread, lock_order_state) == 0x51f);
    assert!(core::mem::offset_of!(Ethread, performance_count_low_reserved) == 0x520);
    assert!(core::mem::offset_of!(Ethread, performance_count_high_reserved) == 0x524);
    assert!(core::mem::offset_of!(Ethread, alpc_message_id) == 0x528);
    assert!(core::mem::offset_of!(Ethread, alpc_message) == 0x530);
    assert!(core::mem::offset_of!(Ethread, alpc_wait_list_entry) == 0x538);
    assert!(core::mem::offset_of!(Ethread, exit_status) == 0x548);
    assert!(core::mem::offset_of!(Ethread, cache_manager_count) == 0x54c);
    assert!(core::mem::offset_of!(Ethread, io_boost_count) == 0x550);
    assert!(core::mem::offset_of!(Ethread, io_qo_s_boost_count) == 0x554);
    assert!(core::mem::offset_of!(Ethread, io_qo_s_throttle_count) == 0x558);
    assert!(core::mem::offset_of!(Ethread, kernel_stack_reference) == 0x55c);
    assert!(core::mem::offset_of!(Ethread, boost_list) == 0x560);
    assert!(core::mem::offset_of!(Ethread, deboost_list) == 0x570);
    assert!(core::mem::offset_of!(Ethread, boost_list_lock) == 0x580);
    assert!(core::mem::offset_of!(Ethread, irp_list_lock) == 0x588);
    assert!(core::mem::offset_of!(Ethread, reserved_for_synch_tracking) == 0x590);
    assert!(core::mem::offset_of!(Ethread, cm_callback_list_head) == 0x598);
    assert!(core::mem::offset_of!(Ethread, activity_id) == 0x5a0);
    assert!(core::mem::offset_of!(Ethread, se_learning_mode_list_head) == 0x5a8);
    assert!(core::mem::offset_of!(Ethread, verifier_context) == 0x5b0);
    assert!(core::mem::offset_of!(Ethread, adjusted_client_token) == 0x5b8);
    assert!(core::mem::offset_of!(Ethread, work_on_behalf_thread) == 0x5c0);
    assert!(core::mem::offset_of!(Ethread, property_set) == 0x5c8);
    assert!(core::mem::offset_of!(Ethread, pico_context) == 0x5e0);
    assert!(core::mem::offset_of!(Ethread, user_fs_base) == 0x5e8);
    assert!(core::mem::offset_of!(Ethread, user_gs_base) == 0x5f0);
    assert!(core::mem::offset_of!(Ethread, energy_values) == 0x5f8);
    assert!(core::mem::offset_of!(Ethread, selected_cpu_sets) == 0x600);
    assert!(core::mem::offset_of!(Ethread, silo) == 0x608);
    assert!(core::mem::offset_of!(Ethread, thread_name) == 0x610);
    assert!(core::mem::offset_of!(Ethread, set_context_state) == 0x618);
    assert!(core::mem::offset_of!(Ethread, last_expected_run_time) == 0x620);
    assert!(core::mem::offset_of!(Ethread, heap_data) == 0x624);
    assert!(core::mem::offset_of!(Ethread, owner_entry_list_head) == 0x628);
    assert!(core::mem::offset_of!(Ethread, disowned_owner_entry_list_lock) == 0x638);
    assert!(core::mem::offset_of!(Ethread, disowned_owner_entry_list_head) == 0x640);
    assert!(core::mem::offset_of!(Ethread, lock_entries) == 0x650);
    assert!(core::mem::offset_of!(Ethread, cm_dbg_info) == 0x890);
    assert!(core::mem::size_of::<EthreadView1>() == 0x898);
    assert!(core::mem::align_of::<EthreadView1>() == core::mem::align_of::<Ethread>());
    assert!(core::mem::offset_of!(EthreadView1, keyed_wait_chain) == 0x438);
    assert!(core::mem::offset_of!(EthreadView1, forward_link_shadow) == 0x448);
    assert!(core::mem::offset_of!(EthreadView1, start_address) == 0x450);
    assert!(core::mem::offset_of!(EthreadView1, reaper_link) == 0x458);
    assert!(core::mem::offset_of!(EthreadView1, alpc_wait_semaphore) == 0x488);
    assert!(core::mem::offset_of!(EthreadView1, bitfield_518) == 0x518);
    assert!(core::mem::offset_of!(EthreadView1, bitfield_519) == 0x519);
    assert!(core::mem::offset_of!(EthreadView1, alpc_receive_attribute_set) == 0x530);
    assert!(core::mem::offset_of!(EthreadView1, selected_cpu_sets_indirect) == 0x600);
    assert!(core::mem::size_of::<EthreadView2>() == 0x898);
    assert!(core::mem::align_of::<EthreadView2>() == core::mem::align_of::<Ethread>());
    assert!(core::mem::offset_of!(EthreadView2, keyed_wait_value) == 0x458);
};

/// `_CLIENT_ID` (0x10 bytes).
#[repr(C)]
pub struct ClientId {
    /// -> `void`
    pub unique_process: Field<u64>,
    /// -> `void`
    pub unique_thread: Field<u64>,
}

unsafe impl NtStruct for ClientId {}

const _: () = {
    assert!(core::mem::size_of::<ClientId>() == 0x10);
    assert!(core::mem::offset_of!(ClientId, unique_process) == 0x0);
    assert!(core::mem::offset_of!(ClientId, unique_thread) == 0x8);
};

/// `_PS_CLIENT_SECURITY_CONTEXT` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PsClientSecurityContextView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PsClientSecurityContext {
    pub impersonation_data: Field<u64>,
}

/// Vista 1 de `_PS_CLIENT_SECURITY_CONTEXT` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PsClientSecurityContextView1 {
    /// -> `void`
    pub impersonation_token: Field<u64>,
}

impl core::ops::Deref for PsClientSecurityContext {
    type Target = PsClientSecurityContextView1;
    #[inline(always)]
    fn deref(&self) -> &PsClientSecurityContextView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PsClientSecurityContextView1>() }
    }
}

unsafe impl NtStruct for PsClientSecurityContext {}

impl PsClientSecurityContext {
    /// `ImpersonationLevel`: bits 0..=1 de `impersonation_data`.
    pub const IMPERSONATION_LEVEL_SHIFT: u32 = 0;
    pub const IMPERSONATION_LEVEL_MASK: u64 = 0x3;
    #[inline(always)]
    pub fn impersonation_level(&self) -> u64 {
        self.impersonation_data.bits(0, 2) as u64
    }
    #[inline(always)]
    pub fn set_impersonation_level(&self, value: u64) {
        self.impersonation_data.set_bits(0, 2, value as u64)
    }
    /// `EffectiveOnly`: bits 2..=2 de `impersonation_data`.
    pub const EFFECTIVE_ONLY_SHIFT: u32 = 2;
    pub const EFFECTIVE_ONLY_MASK: u64 = 0x4;
    #[inline(always)]
    pub fn effective_only(&self) -> u64 {
        self.impersonation_data.bits(2, 1) as u64
    }
    #[inline(always)]
    pub fn set_effective_only(&self, value: u64) {
        self.impersonation_data.set_bits(2, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PsClientSecurityContext>() == 0x8);
    assert!(core::mem::offset_of!(PsClientSecurityContext, impersonation_data) == 0x0);
    assert!(core::mem::size_of::<PsClientSecurityContextView1>() == 0x8);
    assert!(core::mem::align_of::<PsClientSecurityContextView1>() == core::mem::align_of::<PsClientSecurityContext>());
    assert!(core::mem::offset_of!(PsClientSecurityContextView1, impersonation_token) == 0x0);
};

/// `_PS_PROPERTY_SET` (0x18 bytes).
#[repr(C)]
pub struct PsPropertySet {
    pub list_head: ListEntry,
    pub lock: Field<u64>,
}

unsafe impl NtStruct for PsPropertySet {}

const _: () = {
    assert!(core::mem::size_of::<PsPropertySet>() == 0x18);
    assert!(core::mem::offset_of!(PsPropertySet, list_head) == 0x0);
    assert!(core::mem::offset_of!(PsPropertySet, lock) == 0x10);
};

/// `_EPROCESS` (0xa40 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EprocessView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Eprocess {
    pub pcb: Kprocess,
    pub process_lock: ExPushLock,
    /// -> `void`
    pub unique_process_id: Field<u64>,
    pub active_process_links: ListEntry,
    pub rundown_protect: ExRundownRef,
    pub flags2: Field<u32>,
    pub flags: Field<u32>,
    pub create_time: LargeInteger,
    pub process_quota_usage: [Field<u64>; 2],
    pub process_quota_peak: [Field<u64>; 2],
    pub peak_virtual_size: Field<u64>,
    pub virtual_size: Field<u64>,
    pub session_process_links: ListEntry,
    /// -> `void`
    pub exception_port_data: Field<u64>,
    pub token: ExFastRef,
    pub mm_reserved: Field<u64>,
    pub address_creation_lock: ExPushLock,
    pub page_table_commitment_lock: ExPushLock,
    /// -> `_ETHREAD`
    pub rotate_in_progress: Field<u64>,
    /// -> `_ETHREAD`
    pub fork_in_progress: Field<u64>,
    /// -> `_EJOB`
    pub commit_charge_job: Field<u64>,
    pub clone_root: RtlAvlTree,
    pub number_of_private_pages: Field<u64>,
    pub number_of_locked_pages: Field<u64>,
    /// -> `void`
    pub win32_process: Field<u64>,
    /// -> `_EJOB`
    pub job: Field<u64>,
    /// -> `void`
    pub section_object: Field<u64>,
    /// -> `void`
    pub section_base_address: Field<u64>,
    pub cookie: Field<u32>,
    _pad_52c: Reserved<0x4>,
    /// -> `_PAGEFAULT_HISTORY`
    pub working_set_watch: Field<u64>,
    /// -> `void`
    pub win32_window_station: Field<u64>,
    /// -> `void`
    pub inherited_from_unique_process_id: Field<u64>,
    pub owner_process_id: Field<u64>,
    /// -> `_PEB`
    pub peb: Field<u64>,
    /// -> `_MM_SESSION_SPACE`
    pub session: Field<u64>,
    /// -> `void`
    pub spare1: Field<u64>,
    /// -> `_EPROCESS_QUOTA_BLOCK`
    pub quota_block: Field<u64>,
    /// -> `_HANDLE_TABLE`
    pub object_table: Field<u64>,
    /// -> `void`
    pub debug_port: Field<u64>,
    /// -> `_EWOW64PROCESS`
    pub wo_w64_process: Field<u64>,
    /// -> `void`
    pub device_map: Field<u64>,
    /// -> `void`
    pub etw_data_source: Field<u64>,
    pub page_directory_pte: Field<u64>,
    /// -> `_FILE_OBJECT`
    pub image_file_pointer: Field<u64>,
    pub image_file_name: [Field<u8>; 15],
    pub priority_class: Field<u8>,
    /// -> `void`
    pub security_port: Field<u64>,
    pub se_audit_process_creation_info: SeAuditProcessCreationInfo,
    pub job_links: ListEntry,
    /// -> `void`
    pub highest_user_address: Field<u64>,
    pub thread_list_head: ListEntry,
    pub active_threads: Field<u32>,
    pub image_path_hash: Field<u32>,
    pub default_hard_error_processing: Field<u32>,
    pub last_thread_exit_status: Field<i32>,
    pub prefetch_trace: ExFastRef,
    /// -> `void`
    pub locked_pages_list: Field<u64>,
    pub read_operation_count: LargeInteger,
    pub write_operation_count: LargeInteger,
    pub other_operation_count: LargeInteger,
    pub read_transfer_count: LargeInteger,
    pub write_transfer_count: LargeInteger,
    pub other_transfer_count: LargeInteger,
    pub commit_charge_limit: Field<u64>,
    pub commit_charge: Field<u64>,
    pub commit_charge_peak: Field<u64>,
    _pad_658: Reserved<0x28>,
    pub vm: MmsupportFull,
    pub mm_process_links: ListEntry,
    pub modified_page_count: Field<u32>,
    pub exit_status: Field<i32>,
    pub vad_root: RtlAvlTree,
    /// -> `void`
    pub vad_hint: Field<u64>,
    pub vad_count: Field<u64>,
    pub vad_physical_pages: Field<u64>,
    pub vad_physical_pages_limit: Field<u64>,
    pub alpc_context: AlpcProcessContext,
    pub timer_resolution_link: ListEntry,
    /// -> `_PO_DIAG_STACK_RECORD`
    pub timer_resolution_stack_record: Field<u64>,
    pub requested_timer_resolution: Field<u32>,
    pub smallest_timer_resolution: Field<u32>,
    pub exit_time: LargeInteger,
    /// -> `_INVERTED_FUNCTION_TABLE`
    pub inverted_function_table: Field<u64>,
    pub inverted_function_table_lock: ExPushLock,
    pub active_threads_high_watermark: Field<u32>,
    pub large_private_vad_count: Field<u32>,
    pub thread_list_lock: ExPushLock,
    /// -> `void`
    pub wnf_context: Field<u64>,
    /// -> `_EJOB`
    pub server_silo: Field<u64>,
    pub signature_level: Field<u8>,
    pub section_signature_level: Field<u8>,
    pub protection: PsProtection,
    pub bitfield_87b: Field<u8>,
    pub flags3: Field<u32>,
    pub device_asid: Field<i32>,
    _pad_884: Reserved<0x4>,
    /// -> `void`
    pub svm_data: Field<u64>,
    pub svm_process_lock: ExPushLock,
    pub svm_lock: Field<u64>,
    pub svm_process_device_list_head: ListEntry,
    pub last_freeze_interrupt_time: Field<u64>,
    /// -> `_PROCESS_DISK_COUNTERS`
    pub disk_counters: Field<u64>,
    /// -> `void`
    pub pico_context: Field<u64>,
    /// -> `void`
    pub enclave_table: Field<u64>,
    pub enclave_number: Field<u64>,
    pub enclave_lock: ExPushLock,
    pub high_priority_faults_allowed: Field<u32>,
    _pad_8e4: Reserved<0x4>,
    /// -> `_PO_PROCESS_ENERGY_CONTEXT`
    pub energy_context: Field<u64>,
    /// -> `void`
    pub vm_context: Field<u64>,
    pub sequence_number: Field<u64>,
    pub create_interrupt_time: Field<u64>,
    pub create_unbiased_interrupt_time: Field<u64>,
    pub total_unbiased_frozen_time: Field<u64>,
    pub last_app_state_update_time: Field<u64>,
    pub bitfield_920: Field<u64>,
    pub shared_commit_charge: Field<u64>,
    pub shared_commit_lock: ExPushLock,
    pub shared_commit_links: ListEntry,
    pub allowed_cpu_sets: Field<u64>,
    pub default_cpu_sets: Field<u64>,
    /// -> `void`
    pub disk_io_attribution: Field<u64>,
    /// -> `void`
    pub dxg_process: Field<u64>,
    pub win32_k_filter_set: Field<u32>,
    _pad_96c: Reserved<0x4>,
    pub process_timer_delay: PsInterlockedTimerDelayValues,
    pub k_timer_sets: Field<u32>,
    pub k_timer2_sets: Field<u32>,
    pub thread_timer_sets: Field<u32>,
    _pad_984: Reserved<0x4>,
    pub virtual_timer_list_lock: Field<u64>,
    pub virtual_timer_list_head: ListEntry,
    pub wake_channel: WnfStateName,
    _pad_9a8: Reserved<0x28>,
    pub mitigation_flags: Field<u32>,
    pub mitigation_flags2: Field<u32>,
    /// -> `void`
    pub partition_object: Field<u64>,
    pub security_domain: Field<u64>,
    pub parent_security_domain: Field<u64>,
    /// -> `void`
    pub coverage_sampler_context: Field<u64>,
    /// -> `void`
    pub mm_hot_patch_context: Field<u64>,
    pub dynamic_eh_continuation_targets_tree: RtlAvlTree,
    pub dynamic_eh_continuation_targets_lock: ExPushLock,
    pub dynamic_enforced_cet_compatible_ranges: PsDynamicEnforcedAddressRanges,
    pub disabled_component_flags: Field<u32>,
    _pad_a24: Reserved<0x4>,
    /// -> `u32`
    pub path_redirection_hashes: Field<u64>,
    pub mitigation_flags3: Field<u32>,
    _pad_a34: Reserved<0xc>,
}

/// Vista 1 de `_EPROCESS` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EprocessView1 {
    _pad_0: Reserved<0x4b0>,
    pub exception_port_value: Field<u64>,
    _pad_4b8: Reserved<0x490>,
    /// -> `u64`
    pub allowed_cpu_sets_indirect: Field<u64>,
    /// -> `u64`
    pub default_cpu_sets_indirect: Field<u64>,
    _pad_958: Reserved<0x48>,
    pub wake_info: PsProcessWakeInformation,
    pub mitigation_flags_values: EprocessMitigationFlagsValues,
    pub mitigation_flags2_values: EprocessMitigationFlags2Values,
    _pad_9d8: Reserved<0x58>,
    pub mitigation_flags3_values: EprocessMitigationFlags3Values,
    _pad_a34: Reserved<0xc>,
}

impl core::ops::Deref for Eprocess {
    type Target = EprocessView1;
    #[inline(always)]
    fn deref(&self) -> &EprocessView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EprocessView1>() }
    }
}

unsafe impl NtStruct for Eprocess {}

impl Eprocess {
    /// `JobNotReallyActive`: bits 0..=0 de `flags2`.
    pub const JOB_NOT_REALLY_ACTIVE_SHIFT: u32 = 0;
    pub const JOB_NOT_REALLY_ACTIVE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn job_not_really_active(&self) -> u32 {
        self.flags2.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_job_not_really_active(&self, value: u32) {
        self.flags2.set_bits(0, 1, value as u64)
    }
    /// `AccountingFolded`: bits 1..=1 de `flags2`.
    pub const ACCOUNTING_FOLDED_SHIFT: u32 = 1;
    pub const ACCOUNTING_FOLDED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn accounting_folded(&self) -> u32 {
        self.flags2.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_accounting_folded(&self, value: u32) {
        self.flags2.set_bits(1, 1, value as u64)
    }
    /// `NewProcessReported`: bits 2..=2 de `flags2`.
    pub const NEW_PROCESS_REPORTED_SHIFT: u32 = 2;
    pub const NEW_PROCESS_REPORTED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn new_process_reported(&self) -> u32 {
        self.flags2.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_new_process_reported(&self, value: u32) {
        self.flags2.set_bits(2, 1, value as u64)
    }
    /// `ExitProcessReported`: bits 3..=3 de `flags2`.
    pub const EXIT_PROCESS_REPORTED_SHIFT: u32 = 3;
    pub const EXIT_PROCESS_REPORTED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn exit_process_reported(&self) -> u32 {
        self.flags2.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_exit_process_reported(&self, value: u32) {
        self.flags2.set_bits(3, 1, value as u64)
    }
    /// `ReportCommitChanges`: bits 4..=4 de `flags2`.
    pub const REPORT_COMMIT_CHANGES_SHIFT: u32 = 4;
    pub const REPORT_COMMIT_CHANGES_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn report_commit_changes(&self) -> u32 {
        self.flags2.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_report_commit_changes(&self, value: u32) {
        self.flags2.set_bits(4, 1, value as u64)
    }
    /// `LastReportMemory`: bits 5..=5 de `flags2`.
    pub const LAST_REPORT_MEMORY_SHIFT: u32 = 5;
    pub const LAST_REPORT_MEMORY_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn last_report_memory(&self) -> u32 {
        self.flags2.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_last_report_memory(&self, value: u32) {
        self.flags2.set_bits(5, 1, value as u64)
    }
    /// `ForceWakeCharge`: bits 6..=6 de `flags2`.
    pub const FORCE_WAKE_CHARGE_SHIFT: u32 = 6;
    pub const FORCE_WAKE_CHARGE_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn force_wake_charge(&self) -> u32 {
        self.flags2.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_force_wake_charge(&self, value: u32) {
        self.flags2.set_bits(6, 1, value as u64)
    }
    /// `CrossSessionCreate`: bits 7..=7 de `flags2`.
    pub const CROSS_SESSION_CREATE_SHIFT: u32 = 7;
    pub const CROSS_SESSION_CREATE_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn cross_session_create(&self) -> u32 {
        self.flags2.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_cross_session_create(&self, value: u32) {
        self.flags2.set_bits(7, 1, value as u64)
    }
    /// `NeedsHandleRundown`: bits 8..=8 de `flags2`.
    pub const NEEDS_HANDLE_RUNDOWN_SHIFT: u32 = 8;
    pub const NEEDS_HANDLE_RUNDOWN_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn needs_handle_rundown(&self) -> u32 {
        self.flags2.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_needs_handle_rundown(&self, value: u32) {
        self.flags2.set_bits(8, 1, value as u64)
    }
    /// `RefTraceEnabled`: bits 9..=9 de `flags2`.
    pub const REF_TRACE_ENABLED_SHIFT: u32 = 9;
    pub const REF_TRACE_ENABLED_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn ref_trace_enabled(&self) -> u32 {
        self.flags2.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_ref_trace_enabled(&self, value: u32) {
        self.flags2.set_bits(9, 1, value as u64)
    }
    /// `PicoCreated`: bits 10..=10 de `flags2`.
    pub const PICO_CREATED_SHIFT: u32 = 10;
    pub const PICO_CREATED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn pico_created(&self) -> u32 {
        self.flags2.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_pico_created(&self, value: u32) {
        self.flags2.set_bits(10, 1, value as u64)
    }
    /// `EmptyJobEvaluated`: bits 11..=11 de `flags2`.
    pub const EMPTY_JOB_EVALUATED_SHIFT: u32 = 11;
    pub const EMPTY_JOB_EVALUATED_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn empty_job_evaluated(&self) -> u32 {
        self.flags2.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_empty_job_evaluated(&self, value: u32) {
        self.flags2.set_bits(11, 1, value as u64)
    }
    /// `DefaultPagePriority`: bits 12..=14 de `flags2`.
    pub const DEFAULT_PAGE_PRIORITY_SHIFT: u32 = 12;
    pub const DEFAULT_PAGE_PRIORITY_MASK: u32 = 0x7000;
    #[inline(always)]
    pub fn default_page_priority(&self) -> u32 {
        self.flags2.bits(12, 3) as u32
    }
    #[inline(always)]
    pub fn set_default_page_priority(&self, value: u32) {
        self.flags2.set_bits(12, 3, value as u64)
    }
    /// `PrimaryTokenFrozen`: bits 15..=15 de `flags2`.
    pub const PRIMARY_TOKEN_FROZEN_SHIFT: u32 = 15;
    pub const PRIMARY_TOKEN_FROZEN_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn primary_token_frozen(&self) -> u32 {
        self.flags2.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_primary_token_frozen(&self, value: u32) {
        self.flags2.set_bits(15, 1, value as u64)
    }
    /// `ProcessVerifierTarget`: bits 16..=16 de `flags2`.
    pub const PROCESS_VERIFIER_TARGET_SHIFT: u32 = 16;
    pub const PROCESS_VERIFIER_TARGET_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn process_verifier_target(&self) -> u32 {
        self.flags2.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_verifier_target(&self, value: u32) {
        self.flags2.set_bits(16, 1, value as u64)
    }
    /// `RestrictSetThreadContext`: bits 17..=17 de `flags2`.
    pub const RESTRICT_SET_THREAD_CONTEXT_SHIFT: u32 = 17;
    pub const RESTRICT_SET_THREAD_CONTEXT_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn restrict_set_thread_context(&self) -> u32 {
        self.flags2.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_restrict_set_thread_context(&self, value: u32) {
        self.flags2.set_bits(17, 1, value as u64)
    }
    /// `AffinityPermanent`: bits 18..=18 de `flags2`.
    pub const AFFINITY_PERMANENT_SHIFT: u32 = 18;
    pub const AFFINITY_PERMANENT_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn affinity_permanent(&self) -> u32 {
        self.flags2.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_affinity_permanent(&self, value: u32) {
        self.flags2.set_bits(18, 1, value as u64)
    }
    /// `AffinityUpdateEnable`: bits 19..=19 de `flags2`.
    pub const AFFINITY_UPDATE_ENABLE_SHIFT: u32 = 19;
    pub const AFFINITY_UPDATE_ENABLE_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn affinity_update_enable(&self) -> u32 {
        self.flags2.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_affinity_update_enable(&self, value: u32) {
        self.flags2.set_bits(19, 1, value as u64)
    }
    /// `PropagateNode`: bits 20..=20 de `flags2`.
    pub const PROPAGATE_NODE_SHIFT: u32 = 20;
    pub const PROPAGATE_NODE_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn propagate_node(&self) -> u32 {
        self.flags2.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_propagate_node(&self, value: u32) {
        self.flags2.set_bits(20, 1, value as u64)
    }
    /// `ExplicitAffinity`: bits 21..=21 de `flags2`.
    pub const EXPLICIT_AFFINITY_SHIFT: u32 = 21;
    pub const EXPLICIT_AFFINITY_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn explicit_affinity(&self) -> u32 {
        self.flags2.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_explicit_affinity(&self, value: u32) {
        self.flags2.set_bits(21, 1, value as u64)
    }
    /// `ProcessExecutionState`: bits 22..=23 de `flags2`.
    pub const PROCESS_EXECUTION_STATE_SHIFT: u32 = 22;
    pub const PROCESS_EXECUTION_STATE_MASK: u32 = 0xc00000;
    #[inline(always)]
    pub fn process_execution_state(&self) -> u32 {
        self.flags2.bits(22, 2) as u32
    }
    #[inline(always)]
    pub fn set_process_execution_state(&self, value: u32) {
        self.flags2.set_bits(22, 2, value as u64)
    }
    /// `EnableReadVmLogging`: bits 24..=24 de `flags2`.
    pub const ENABLE_READ_VM_LOGGING_SHIFT: u32 = 24;
    pub const ENABLE_READ_VM_LOGGING_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn enable_read_vm_logging(&self) -> u32 {
        self.flags2.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_read_vm_logging(&self, value: u32) {
        self.flags2.set_bits(24, 1, value as u64)
    }
    /// `EnableWriteVmLogging`: bits 25..=25 de `flags2`.
    pub const ENABLE_WRITE_VM_LOGGING_SHIFT: u32 = 25;
    pub const ENABLE_WRITE_VM_LOGGING_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn enable_write_vm_logging(&self) -> u32 {
        self.flags2.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_write_vm_logging(&self, value: u32) {
        self.flags2.set_bits(25, 1, value as u64)
    }
    /// `FatalAccessTerminationRequested`: bits 26..=26 de `flags2`.
    pub const FATAL_ACCESS_TERMINATION_REQUESTED_SHIFT: u32 = 26;
    pub const FATAL_ACCESS_TERMINATION_REQUESTED_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn fatal_access_termination_requested(&self) -> u32 {
        self.flags2.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_fatal_access_termination_requested(&self, value: u32) {
        self.flags2.set_bits(26, 1, value as u64)
    }
    /// `DisableSystemAllowedCpuSet`: bits 27..=27 de `flags2`.
    pub const DISABLE_SYSTEM_ALLOWED_CPU_SET_SHIFT: u32 = 27;
    pub const DISABLE_SYSTEM_ALLOWED_CPU_SET_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn disable_system_allowed_cpu_set(&self) -> u32 {
        self.flags2.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_system_allowed_cpu_set(&self, value: u32) {
        self.flags2.set_bits(27, 1, value as u64)
    }
    /// `ProcessStateChangeRequest`: bits 28..=29 de `flags2`.
    pub const PROCESS_STATE_CHANGE_REQUEST_SHIFT: u32 = 28;
    pub const PROCESS_STATE_CHANGE_REQUEST_MASK: u32 = 0x30000000;
    #[inline(always)]
    pub fn process_state_change_request(&self) -> u32 {
        self.flags2.bits(28, 2) as u32
    }
    #[inline(always)]
    pub fn set_process_state_change_request(&self, value: u32) {
        self.flags2.set_bits(28, 2, value as u64)
    }
    /// `ProcessStateChangeInProgress`: bits 30..=30 de `flags2`.
    pub const PROCESS_STATE_CHANGE_IN_PROGRESS_SHIFT: u32 = 30;
    pub const PROCESS_STATE_CHANGE_IN_PROGRESS_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn process_state_change_in_progress(&self) -> u32 {
        self.flags2.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_state_change_in_progress(&self, value: u32) {
        self.flags2.set_bits(30, 1, value as u64)
    }
    /// `InPrivate`: bits 31..=31 de `flags2`.
    pub const IN_PRIVATE_SHIFT: u32 = 31;
    pub const IN_PRIVATE_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn in_private(&self) -> u32 {
        self.flags2.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_in_private(&self, value: u32) {
        self.flags2.set_bits(31, 1, value as u64)
    }
    /// `CreateReported`: bits 0..=0 de `flags`.
    pub const CREATE_REPORTED_SHIFT: u32 = 0;
    pub const CREATE_REPORTED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn create_reported(&self) -> u32 {
        self.flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_create_reported(&self, value: u32) {
        self.flags.set_bits(0, 1, value as u64)
    }
    /// `NoDebugInherit`: bits 1..=1 de `flags`.
    pub const NO_DEBUG_INHERIT_SHIFT: u32 = 1;
    pub const NO_DEBUG_INHERIT_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn no_debug_inherit(&self) -> u32 {
        self.flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_debug_inherit(&self, value: u32) {
        self.flags.set_bits(1, 1, value as u64)
    }
    /// `ProcessExiting`: bits 2..=2 de `flags`.
    pub const PROCESS_EXITING_SHIFT: u32 = 2;
    pub const PROCESS_EXITING_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn process_exiting(&self) -> u32 {
        self.flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_exiting(&self, value: u32) {
        self.flags.set_bits(2, 1, value as u64)
    }
    /// `ProcessDelete`: bits 3..=3 de `flags`.
    pub const PROCESS_DELETE_SHIFT: u32 = 3;
    pub const PROCESS_DELETE_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn process_delete(&self) -> u32 {
        self.flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_delete(&self, value: u32) {
        self.flags.set_bits(3, 1, value as u64)
    }
    /// `ManageExecutableMemoryWrites`: bits 4..=4 de `flags`.
    pub const MANAGE_EXECUTABLE_MEMORY_WRITES_SHIFT: u32 = 4;
    pub const MANAGE_EXECUTABLE_MEMORY_WRITES_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn manage_executable_memory_writes(&self) -> u32 {
        self.flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_manage_executable_memory_writes(&self, value: u32) {
        self.flags.set_bits(4, 1, value as u64)
    }
    /// `VmDeleted`: bits 5..=5 de `flags`.
    pub const VM_DELETED_SHIFT: u32 = 5;
    pub const VM_DELETED_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn vm_deleted(&self) -> u32 {
        self.flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_vm_deleted(&self, value: u32) {
        self.flags.set_bits(5, 1, value as u64)
    }
    /// `OutswapEnabled`: bits 6..=6 de `flags`.
    pub const OUTSWAP_ENABLED_SHIFT: u32 = 6;
    pub const OUTSWAP_ENABLED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn outswap_enabled(&self) -> u32 {
        self.flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_outswap_enabled(&self, value: u32) {
        self.flags.set_bits(6, 1, value as u64)
    }
    /// `Outswapped`: bits 7..=7 de `flags`.
    pub const OUTSWAPPED_SHIFT: u32 = 7;
    pub const OUTSWAPPED_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn outswapped(&self) -> u32 {
        self.flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_outswapped(&self, value: u32) {
        self.flags.set_bits(7, 1, value as u64)
    }
    /// `FailFastOnCommitFail`: bits 8..=8 de `flags`.
    pub const FAIL_FAST_ON_COMMIT_FAIL_SHIFT: u32 = 8;
    pub const FAIL_FAST_ON_COMMIT_FAIL_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn fail_fast_on_commit_fail(&self) -> u32 {
        self.flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_fail_fast_on_commit_fail(&self, value: u32) {
        self.flags.set_bits(8, 1, value as u64)
    }
    /// `Wow64VaSpace4Gb`: bits 9..=9 de `flags`.
    pub const WOW64_VA_SPACE4_GB_SHIFT: u32 = 9;
    pub const WOW64_VA_SPACE4_GB_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn wow64_va_space4_gb(&self) -> u32 {
        self.flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_wow64_va_space4_gb(&self, value: u32) {
        self.flags.set_bits(9, 1, value as u64)
    }
    /// `AddressSpaceInitialized`: bits 10..=11 de `flags`.
    pub const ADDRESS_SPACE_INITIALIZED_SHIFT: u32 = 10;
    pub const ADDRESS_SPACE_INITIALIZED_MASK: u32 = 0xc00;
    #[inline(always)]
    pub fn address_space_initialized(&self) -> u32 {
        self.flags.bits(10, 2) as u32
    }
    #[inline(always)]
    pub fn set_address_space_initialized(&self, value: u32) {
        self.flags.set_bits(10, 2, value as u64)
    }
    /// `SetTimerResolution`: bits 12..=12 de `flags`.
    pub const SET_TIMER_RESOLUTION_SHIFT: u32 = 12;
    pub const SET_TIMER_RESOLUTION_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn set_timer_resolution(&self) -> u32 {
        self.flags.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_set_timer_resolution(&self, value: u32) {
        self.flags.set_bits(12, 1, value as u64)
    }
    /// `BreakOnTermination`: bits 13..=13 de `flags`.
    pub const BREAK_ON_TERMINATION_SHIFT: u32 = 13;
    pub const BREAK_ON_TERMINATION_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn break_on_termination(&self) -> u32 {
        self.flags.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_break_on_termination(&self, value: u32) {
        self.flags.set_bits(13, 1, value as u64)
    }
    /// `DeprioritizeViews`: bits 14..=14 de `flags`.
    pub const DEPRIORITIZE_VIEWS_SHIFT: u32 = 14;
    pub const DEPRIORITIZE_VIEWS_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn deprioritize_views(&self) -> u32 {
        self.flags.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_deprioritize_views(&self, value: u32) {
        self.flags.set_bits(14, 1, value as u64)
    }
    /// `WriteWatch`: bits 15..=15 de `flags`.
    pub const WRITE_WATCH_SHIFT: u32 = 15;
    pub const WRITE_WATCH_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn write_watch(&self) -> u32 {
        self.flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_write_watch(&self, value: u32) {
        self.flags.set_bits(15, 1, value as u64)
    }
    /// `ProcessInSession`: bits 16..=16 de `flags`.
    pub const PROCESS_IN_SESSION_SHIFT: u32 = 16;
    pub const PROCESS_IN_SESSION_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn process_in_session(&self) -> u32 {
        self.flags.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_in_session(&self, value: u32) {
        self.flags.set_bits(16, 1, value as u64)
    }
    /// `OverrideAddressSpace`: bits 17..=17 de `flags`.
    pub const OVERRIDE_ADDRESS_SPACE_SHIFT: u32 = 17;
    pub const OVERRIDE_ADDRESS_SPACE_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn override_address_space(&self) -> u32 {
        self.flags.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_override_address_space(&self, value: u32) {
        self.flags.set_bits(17, 1, value as u64)
    }
    /// `HasAddressSpace`: bits 18..=18 de `flags`.
    pub const HAS_ADDRESS_SPACE_SHIFT: u32 = 18;
    pub const HAS_ADDRESS_SPACE_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn has_address_space(&self) -> u32 {
        self.flags.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_has_address_space(&self, value: u32) {
        self.flags.set_bits(18, 1, value as u64)
    }
    /// `LaunchPrefetched`: bits 19..=19 de `flags`.
    pub const LAUNCH_PREFETCHED_SHIFT: u32 = 19;
    pub const LAUNCH_PREFETCHED_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn launch_prefetched(&self) -> u32 {
        self.flags.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_launch_prefetched(&self, value: u32) {
        self.flags.set_bits(19, 1, value as u64)
    }
    /// `Background`: bits 20..=20 de `flags`.
    pub const BACKGROUND_SHIFT: u32 = 20;
    pub const BACKGROUND_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn background(&self) -> u32 {
        self.flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_background(&self, value: u32) {
        self.flags.set_bits(20, 1, value as u64)
    }
    /// `VmTopDown`: bits 21..=21 de `flags`.
    pub const VM_TOP_DOWN_SHIFT: u32 = 21;
    pub const VM_TOP_DOWN_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn vm_top_down(&self) -> u32 {
        self.flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_vm_top_down(&self, value: u32) {
        self.flags.set_bits(21, 1, value as u64)
    }
    /// `ImageNotifyDone`: bits 22..=22 de `flags`.
    pub const IMAGE_NOTIFY_DONE_SHIFT: u32 = 22;
    pub const IMAGE_NOTIFY_DONE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn image_notify_done(&self) -> u32 {
        self.flags.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_image_notify_done(&self, value: u32) {
        self.flags.set_bits(22, 1, value as u64)
    }
    /// `PdeUpdateNeeded`: bits 23..=23 de `flags`.
    pub const PDE_UPDATE_NEEDED_SHIFT: u32 = 23;
    pub const PDE_UPDATE_NEEDED_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn pde_update_needed(&self) -> u32 {
        self.flags.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_pde_update_needed(&self, value: u32) {
        self.flags.set_bits(23, 1, value as u64)
    }
    /// `VdmAllowed`: bits 24..=24 de `flags`.
    pub const VDM_ALLOWED_SHIFT: u32 = 24;
    pub const VDM_ALLOWED_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn vdm_allowed(&self) -> u32 {
        self.flags.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_vdm_allowed(&self, value: u32) {
        self.flags.set_bits(24, 1, value as u64)
    }
    /// `ProcessRundown`: bits 25..=25 de `flags`.
    pub const PROCESS_RUNDOWN_SHIFT: u32 = 25;
    pub const PROCESS_RUNDOWN_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn process_rundown(&self) -> u32 {
        self.flags.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_rundown(&self, value: u32) {
        self.flags.set_bits(25, 1, value as u64)
    }
    /// `ProcessInserted`: bits 26..=26 de `flags`.
    pub const PROCESS_INSERTED_SHIFT: u32 = 26;
    pub const PROCESS_INSERTED_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn process_inserted(&self) -> u32 {
        self.flags.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_inserted(&self, value: u32) {
        self.flags.set_bits(26, 1, value as u64)
    }
    /// `DefaultIoPriority`: bits 27..=29 de `flags`.
    pub const DEFAULT_IO_PRIORITY_SHIFT: u32 = 27;
    pub const DEFAULT_IO_PRIORITY_MASK: u32 = 0x38000000;
    #[inline(always)]
    pub fn default_io_priority(&self) -> u32 {
        self.flags.bits(27, 3) as u32
    }
    #[inline(always)]
    pub fn set_default_io_priority(&self, value: u32) {
        self.flags.set_bits(27, 3, value as u64)
    }
    /// `ProcessSelfDelete`: bits 30..=30 de `flags`.
    pub const PROCESS_SELF_DELETE_SHIFT: u32 = 30;
    pub const PROCESS_SELF_DELETE_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn process_self_delete(&self) -> u32 {
        self.flags.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_self_delete(&self, value: u32) {
        self.flags.set_bits(30, 1, value as u64)
    }
    /// `SetTimerResolutionLink`: bits 31..=31 de `flags`.
    pub const SET_TIMER_RESOLUTION_LINK_SHIFT: u32 = 31;
    pub const SET_TIMER_RESOLUTION_LINK_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn set_timer_resolution_link(&self) -> u32 {
        self.flags.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_set_timer_resolution_link(&self, value: u32) {
        self.flags.set_bits(31, 1, value as u64)
    }
    /// `ExceptionPortState`: bits 0..=2 de `exception_port_value`.
    pub const EXCEPTION_PORT_STATE_SHIFT: u32 = 0;
    pub const EXCEPTION_PORT_STATE_MASK: u64 = 0x7;
    #[inline(always)]
    pub fn exception_port_state(&self) -> u64 {
        self.exception_port_value.bits(0, 3) as u64
    }
    #[inline(always)]
    pub fn set_exception_port_state(&self, value: u64) {
        self.exception_port_value.set_bits(0, 3, value as u64)
    }
    /// `HangCount`: bits 0..=2 de `bitfield_87b`.
    pub const HANG_COUNT_SHIFT: u32 = 0;
    pub const HANG_COUNT_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn hang_count(&self) -> u8 {
        self.bitfield_87b.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_hang_count(&self, value: u8) {
        self.bitfield_87b.set_bits(0, 3, value as u64)
    }
    /// `GhostCount`: bits 3..=5 de `bitfield_87b`.
    pub const GHOST_COUNT_SHIFT: u32 = 3;
    pub const GHOST_COUNT_MASK: u8 = 0x38;
    #[inline(always)]
    pub fn ghost_count(&self) -> u8 {
        self.bitfield_87b.bits(3, 3) as u8
    }
    #[inline(always)]
    pub fn set_ghost_count(&self, value: u8) {
        self.bitfield_87b.set_bits(3, 3, value as u64)
    }
    /// `PrefilterException`: bits 6..=6 de `bitfield_87b`.
    pub const PREFILTER_EXCEPTION_SHIFT: u32 = 6;
    pub const PREFILTER_EXCEPTION_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn prefilter_exception(&self) -> u8 {
        self.bitfield_87b.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_prefilter_exception(&self, value: u8) {
        self.bitfield_87b.set_bits(6, 1, value as u64)
    }
    /// `Minimal`: bits 0..=0 de `flags3`.
    pub const MINIMAL_SHIFT: u32 = 0;
    pub const MINIMAL_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn minimal(&self) -> u32 {
        self.flags3.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_minimal(&self, value: u32) {
        self.flags3.set_bits(0, 1, value as u64)
    }
    /// `ReplacingPageRoot`: bits 1..=1 de `flags3`.
    pub const REPLACING_PAGE_ROOT_SHIFT: u32 = 1;
    pub const REPLACING_PAGE_ROOT_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn replacing_page_root(&self) -> u32 {
        self.flags3.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_replacing_page_root(&self, value: u32) {
        self.flags3.set_bits(1, 1, value as u64)
    }
    /// `Crashed`: bits 2..=2 de `flags3`.
    pub const CRASHED_SHIFT: u32 = 2;
    pub const CRASHED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn crashed(&self) -> u32 {
        self.flags3.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_crashed(&self, value: u32) {
        self.flags3.set_bits(2, 1, value as u64)
    }
    /// `JobVadsAreTracked`: bits 3..=3 de `flags3`.
    pub const JOB_VADS_ARE_TRACKED_SHIFT: u32 = 3;
    pub const JOB_VADS_ARE_TRACKED_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn job_vads_are_tracked(&self) -> u32 {
        self.flags3.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_job_vads_are_tracked(&self, value: u32) {
        self.flags3.set_bits(3, 1, value as u64)
    }
    /// `VadTrackingDisabled`: bits 4..=4 de `flags3`.
    pub const VAD_TRACKING_DISABLED_SHIFT: u32 = 4;
    pub const VAD_TRACKING_DISABLED_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn vad_tracking_disabled(&self) -> u32 {
        self.flags3.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_vad_tracking_disabled(&self, value: u32) {
        self.flags3.set_bits(4, 1, value as u64)
    }
    /// `AuxiliaryProcess`: bits 5..=5 de `flags3`.
    pub const AUXILIARY_PROCESS_SHIFT: u32 = 5;
    pub const AUXILIARY_PROCESS_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn auxiliary_process(&self) -> u32 {
        self.flags3.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_auxiliary_process(&self, value: u32) {
        self.flags3.set_bits(5, 1, value as u64)
    }
    /// `SubsystemProcess`: bits 6..=6 de `flags3`.
    pub const SUBSYSTEM_PROCESS_SHIFT: u32 = 6;
    pub const SUBSYSTEM_PROCESS_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn subsystem_process(&self) -> u32 {
        self.flags3.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_subsystem_process(&self, value: u32) {
        self.flags3.set_bits(6, 1, value as u64)
    }
    /// `IndirectCpuSets`: bits 7..=7 de `flags3`.
    pub const INDIRECT_CPU_SETS_SHIFT: u32 = 7;
    pub const INDIRECT_CPU_SETS_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn indirect_cpu_sets(&self) -> u32 {
        self.flags3.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_indirect_cpu_sets(&self, value: u32) {
        self.flags3.set_bits(7, 1, value as u64)
    }
    /// `RelinquishedCommit`: bits 8..=8 de `flags3`.
    pub const RELINQUISHED_COMMIT_SHIFT: u32 = 8;
    pub const RELINQUISHED_COMMIT_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn relinquished_commit(&self) -> u32 {
        self.flags3.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_relinquished_commit(&self, value: u32) {
        self.flags3.set_bits(8, 1, value as u64)
    }
    /// `HighGraphicsPriority`: bits 9..=9 de `flags3`.
    pub const HIGH_GRAPHICS_PRIORITY_SHIFT: u32 = 9;
    pub const HIGH_GRAPHICS_PRIORITY_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn high_graphics_priority(&self) -> u32 {
        self.flags3.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_high_graphics_priority(&self, value: u32) {
        self.flags3.set_bits(9, 1, value as u64)
    }
    /// `CommitFailLogged`: bits 10..=10 de `flags3`.
    pub const COMMIT_FAIL_LOGGED_SHIFT: u32 = 10;
    pub const COMMIT_FAIL_LOGGED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn commit_fail_logged(&self) -> u32 {
        self.flags3.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_commit_fail_logged(&self, value: u32) {
        self.flags3.set_bits(10, 1, value as u64)
    }
    /// `ReserveFailLogged`: bits 11..=11 de `flags3`.
    pub const RESERVE_FAIL_LOGGED_SHIFT: u32 = 11;
    pub const RESERVE_FAIL_LOGGED_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn reserve_fail_logged(&self) -> u32 {
        self.flags3.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserve_fail_logged(&self, value: u32) {
        self.flags3.set_bits(11, 1, value as u64)
    }
    /// `SystemProcess`: bits 12..=12 de `flags3`.
    pub const SYSTEM_PROCESS_SHIFT: u32 = 12;
    pub const SYSTEM_PROCESS_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn system_process(&self) -> u32 {
        self.flags3.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_process(&self, value: u32) {
        self.flags3.set_bits(12, 1, value as u64)
    }
    /// `HideImageBaseAddresses`: bits 13..=13 de `flags3`.
    pub const HIDE_IMAGE_BASE_ADDRESSES_SHIFT: u32 = 13;
    pub const HIDE_IMAGE_BASE_ADDRESSES_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn hide_image_base_addresses(&self) -> u32 {
        self.flags3.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_hide_image_base_addresses(&self, value: u32) {
        self.flags3.set_bits(13, 1, value as u64)
    }
    /// `AddressPolicyFrozen`: bits 14..=14 de `flags3`.
    pub const ADDRESS_POLICY_FROZEN_SHIFT: u32 = 14;
    pub const ADDRESS_POLICY_FROZEN_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn address_policy_frozen(&self) -> u32 {
        self.flags3.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_address_policy_frozen(&self, value: u32) {
        self.flags3.set_bits(14, 1, value as u64)
    }
    /// `ProcessFirstResume`: bits 15..=15 de `flags3`.
    pub const PROCESS_FIRST_RESUME_SHIFT: u32 = 15;
    pub const PROCESS_FIRST_RESUME_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn process_first_resume(&self) -> u32 {
        self.flags3.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_first_resume(&self, value: u32) {
        self.flags3.set_bits(15, 1, value as u64)
    }
    /// `ForegroundExternal`: bits 16..=16 de `flags3`.
    pub const FOREGROUND_EXTERNAL_SHIFT: u32 = 16;
    pub const FOREGROUND_EXTERNAL_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn foreground_external(&self) -> u32 {
        self.flags3.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_foreground_external(&self, value: u32) {
        self.flags3.set_bits(16, 1, value as u64)
    }
    /// `ForegroundSystem`: bits 17..=17 de `flags3`.
    pub const FOREGROUND_SYSTEM_SHIFT: u32 = 17;
    pub const FOREGROUND_SYSTEM_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn foreground_system(&self) -> u32 {
        self.flags3.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_foreground_system(&self, value: u32) {
        self.flags3.set_bits(17, 1, value as u64)
    }
    /// `HighMemoryPriority`: bits 18..=18 de `flags3`.
    pub const HIGH_MEMORY_PRIORITY_SHIFT: u32 = 18;
    pub const HIGH_MEMORY_PRIORITY_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn high_memory_priority(&self) -> u32 {
        self.flags3.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_high_memory_priority(&self, value: u32) {
        self.flags3.set_bits(18, 1, value as u64)
    }
    /// `EnableProcessSuspendResumeLogging`: bits 19..=19 de `flags3`.
    pub const ENABLE_PROCESS_SUSPEND_RESUME_LOGGING_SHIFT: u32 = 19;
    pub const ENABLE_PROCESS_SUSPEND_RESUME_LOGGING_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn enable_process_suspend_resume_logging(&self) -> u32 {
        self.flags3.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_process_suspend_resume_logging(&self, value: u32) {
        self.flags3.set_bits(19, 1, value as u64)
    }
    /// `EnableThreadSuspendResumeLogging`: bits 20..=20 de `flags3`.
    pub const ENABLE_THREAD_SUSPEND_RESUME_LOGGING_SHIFT: u32 = 20;
    pub const ENABLE_THREAD_SUSPEND_RESUME_LOGGING_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn enable_thread_suspend_resume_logging(&self) -> u32 {
        self.flags3.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_thread_suspend_resume_logging(&self, value: u32) {
        self.flags3.set_bits(20, 1, value as u64)
    }
    /// `SecurityDomainChanged`: bits 21..=21 de `flags3`.
    pub const SECURITY_DOMAIN_CHANGED_SHIFT: u32 = 21;
    pub const SECURITY_DOMAIN_CHANGED_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn security_domain_changed(&self) -> u32 {
        self.flags3.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_security_domain_changed(&self, value: u32) {
        self.flags3.set_bits(21, 1, value as u64)
    }
    /// `SecurityFreezeComplete`: bits 22..=22 de `flags3`.
    pub const SECURITY_FREEZE_COMPLETE_SHIFT: u32 = 22;
    pub const SECURITY_FREEZE_COMPLETE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn security_freeze_complete(&self) -> u32 {
        self.flags3.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_security_freeze_complete(&self, value: u32) {
        self.flags3.set_bits(22, 1, value as u64)
    }
    /// `VmProcessorHost`: bits 23..=23 de `flags3`.
    pub const VM_PROCESSOR_HOST_SHIFT: u32 = 23;
    pub const VM_PROCESSOR_HOST_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn vm_processor_host(&self) -> u32 {
        self.flags3.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_vm_processor_host(&self, value: u32) {
        self.flags3.set_bits(23, 1, value as u64)
    }
    /// `VmProcessorHostTransition`: bits 24..=24 de `flags3`.
    pub const VM_PROCESSOR_HOST_TRANSITION_SHIFT: u32 = 24;
    pub const VM_PROCESSOR_HOST_TRANSITION_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn vm_processor_host_transition(&self) -> u32 {
        self.flags3.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_vm_processor_host_transition(&self, value: u32) {
        self.flags3.set_bits(24, 1, value as u64)
    }
    /// `AltSyscall`: bits 25..=25 de `flags3`.
    pub const ALT_SYSCALL_SHIFT: u32 = 25;
    pub const ALT_SYSCALL_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn alt_syscall(&self) -> u32 {
        self.flags3.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_alt_syscall(&self, value: u32) {
        self.flags3.set_bits(25, 1, value as u64)
    }
    /// `TimerResolutionIgnore`: bits 26..=26 de `flags3`.
    pub const TIMER_RESOLUTION_IGNORE_SHIFT: u32 = 26;
    pub const TIMER_RESOLUTION_IGNORE_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn timer_resolution_ignore(&self) -> u32 {
        self.flags3.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_timer_resolution_ignore(&self, value: u32) {
        self.flags3.set_bits(26, 1, value as u64)
    }
    /// `DisallowUserTerminate`: bits 27..=27 de `flags3`.
    pub const DISALLOW_USER_TERMINATE_SHIFT: u32 = 27;
    pub const DISALLOW_USER_TERMINATE_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn disallow_user_terminate(&self) -> u32 {
        self.flags3.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_user_terminate(&self, value: u32) {
        self.flags3.set_bits(27, 1, value as u64)
    }
    /// `LastAppStateUptime`: bits 0..=60 de `bitfield_920`.
    pub const LAST_APP_STATE_UPTIME_SHIFT: u32 = 0;
    pub const LAST_APP_STATE_UPTIME_MASK: u64 = 0x1fffffffffffffff;
    #[inline(always)]
    pub fn last_app_state_uptime(&self) -> u64 {
        self.bitfield_920.bits(0, 61) as u64
    }
    #[inline(always)]
    pub fn set_last_app_state_uptime(&self, value: u64) {
        self.bitfield_920.set_bits(0, 61, value as u64)
    }
    /// `LastAppState`: bits 61..=63 de `bitfield_920`.
    pub const LAST_APP_STATE_SHIFT: u32 = 61;
    pub const LAST_APP_STATE_MASK: u64 = 0xe000000000000000;
    #[inline(always)]
    pub fn last_app_state(&self) -> u64 {
        self.bitfield_920.bits(61, 3) as u64
    }
    #[inline(always)]
    pub fn set_last_app_state(&self, value: u64) {
        self.bitfield_920.set_bits(61, 3, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Eprocess>() == 0xa40);
    assert!(core::mem::offset_of!(Eprocess, pcb) == 0x0);
    assert!(core::mem::offset_of!(Eprocess, process_lock) == 0x438);
    assert!(core::mem::offset_of!(Eprocess, unique_process_id) == 0x440);
    assert!(core::mem::offset_of!(Eprocess, active_process_links) == 0x448);
    assert!(core::mem::offset_of!(Eprocess, rundown_protect) == 0x458);
    assert!(core::mem::offset_of!(Eprocess, flags2) == 0x460);
    assert!(core::mem::offset_of!(Eprocess, flags) == 0x464);
    assert!(core::mem::offset_of!(Eprocess, create_time) == 0x468);
    assert!(core::mem::offset_of!(Eprocess, process_quota_usage) == 0x470);
    assert!(core::mem::offset_of!(Eprocess, process_quota_peak) == 0x480);
    assert!(core::mem::offset_of!(Eprocess, peak_virtual_size) == 0x490);
    assert!(core::mem::offset_of!(Eprocess, virtual_size) == 0x498);
    assert!(core::mem::offset_of!(Eprocess, session_process_links) == 0x4a0);
    assert!(core::mem::offset_of!(Eprocess, exception_port_data) == 0x4b0);
    assert!(core::mem::offset_of!(Eprocess, token) == 0x4b8);
    assert!(core::mem::offset_of!(Eprocess, mm_reserved) == 0x4c0);
    assert!(core::mem::offset_of!(Eprocess, address_creation_lock) == 0x4c8);
    assert!(core::mem::offset_of!(Eprocess, page_table_commitment_lock) == 0x4d0);
    assert!(core::mem::offset_of!(Eprocess, rotate_in_progress) == 0x4d8);
    assert!(core::mem::offset_of!(Eprocess, fork_in_progress) == 0x4e0);
    assert!(core::mem::offset_of!(Eprocess, commit_charge_job) == 0x4e8);
    assert!(core::mem::offset_of!(Eprocess, clone_root) == 0x4f0);
    assert!(core::mem::offset_of!(Eprocess, number_of_private_pages) == 0x4f8);
    assert!(core::mem::offset_of!(Eprocess, number_of_locked_pages) == 0x500);
    assert!(core::mem::offset_of!(Eprocess, win32_process) == 0x508);
    assert!(core::mem::offset_of!(Eprocess, job) == 0x510);
    assert!(core::mem::offset_of!(Eprocess, section_object) == 0x518);
    assert!(core::mem::offset_of!(Eprocess, section_base_address) == 0x520);
    assert!(core::mem::offset_of!(Eprocess, cookie) == 0x528);
    assert!(core::mem::offset_of!(Eprocess, working_set_watch) == 0x530);
    assert!(core::mem::offset_of!(Eprocess, win32_window_station) == 0x538);
    assert!(core::mem::offset_of!(Eprocess, inherited_from_unique_process_id) == 0x540);
    assert!(core::mem::offset_of!(Eprocess, owner_process_id) == 0x548);
    assert!(core::mem::offset_of!(Eprocess, peb) == 0x550);
    assert!(core::mem::offset_of!(Eprocess, session) == 0x558);
    assert!(core::mem::offset_of!(Eprocess, spare1) == 0x560);
    assert!(core::mem::offset_of!(Eprocess, quota_block) == 0x568);
    assert!(core::mem::offset_of!(Eprocess, object_table) == 0x570);
    assert!(core::mem::offset_of!(Eprocess, debug_port) == 0x578);
    assert!(core::mem::offset_of!(Eprocess, wo_w64_process) == 0x580);
    assert!(core::mem::offset_of!(Eprocess, device_map) == 0x588);
    assert!(core::mem::offset_of!(Eprocess, etw_data_source) == 0x590);
    assert!(core::mem::offset_of!(Eprocess, page_directory_pte) == 0x598);
    assert!(core::mem::offset_of!(Eprocess, image_file_pointer) == 0x5a0);
    assert!(core::mem::offset_of!(Eprocess, image_file_name) == 0x5a8);
    assert!(core::mem::offset_of!(Eprocess, priority_class) == 0x5b7);
    assert!(core::mem::offset_of!(Eprocess, security_port) == 0x5b8);
    assert!(core::mem::offset_of!(Eprocess, se_audit_process_creation_info) == 0x5c0);
    assert!(core::mem::offset_of!(Eprocess, job_links) == 0x5c8);
    assert!(core::mem::offset_of!(Eprocess, highest_user_address) == 0x5d8);
    assert!(core::mem::offset_of!(Eprocess, thread_list_head) == 0x5e0);
    assert!(core::mem::offset_of!(Eprocess, active_threads) == 0x5f0);
    assert!(core::mem::offset_of!(Eprocess, image_path_hash) == 0x5f4);
    assert!(core::mem::offset_of!(Eprocess, default_hard_error_processing) == 0x5f8);
    assert!(core::mem::offset_of!(Eprocess, last_thread_exit_status) == 0x5fc);
    assert!(core::mem::offset_of!(Eprocess, prefetch_trace) == 0x600);
    assert!(core::mem::offset_of!(Eprocess, locked_pages_list) == 0x608);
    assert!(core::mem::offset_of!(Eprocess, read_operation_count) == 0x610);
    assert!(core::mem::offset_of!(Eprocess, write_operation_count) == 0x618);
    assert!(core::mem::offset_of!(Eprocess, other_operation_count) == 0x620);
    assert!(core::mem::offset_of!(Eprocess, read_transfer_count) == 0x628);
    assert!(core::mem::offset_of!(Eprocess, write_transfer_count) == 0x630);
    assert!(core::mem::offset_of!(Eprocess, other_transfer_count) == 0x638);
    assert!(core::mem::offset_of!(Eprocess, commit_charge_limit) == 0x640);
    assert!(core::mem::offset_of!(Eprocess, commit_charge) == 0x648);
    assert!(core::mem::offset_of!(Eprocess, commit_charge_peak) == 0x650);
    assert!(core::mem::offset_of!(Eprocess, vm) == 0x680);
    assert!(core::mem::offset_of!(Eprocess, mm_process_links) == 0x7c0);
    assert!(core::mem::offset_of!(Eprocess, modified_page_count) == 0x7d0);
    assert!(core::mem::offset_of!(Eprocess, exit_status) == 0x7d4);
    assert!(core::mem::offset_of!(Eprocess, vad_root) == 0x7d8);
    assert!(core::mem::offset_of!(Eprocess, vad_hint) == 0x7e0);
    assert!(core::mem::offset_of!(Eprocess, vad_count) == 0x7e8);
    assert!(core::mem::offset_of!(Eprocess, vad_physical_pages) == 0x7f0);
    assert!(core::mem::offset_of!(Eprocess, vad_physical_pages_limit) == 0x7f8);
    assert!(core::mem::offset_of!(Eprocess, alpc_context) == 0x800);
    assert!(core::mem::offset_of!(Eprocess, timer_resolution_link) == 0x820);
    assert!(core::mem::offset_of!(Eprocess, timer_resolution_stack_record) == 0x830);
    assert!(core::mem::offset_of!(Eprocess, requested_timer_resolution) == 0x838);
    assert!(core::mem::offset_of!(Eprocess, smallest_timer_resolution) == 0x83c);
    assert!(core::mem::offset_of!(Eprocess, exit_time) == 0x840);
    assert!(core::mem::offset_of!(Eprocess, inverted_function_table) == 0x848);
    assert!(core::mem::offset_of!(Eprocess, inverted_function_table_lock) == 0x850);
    assert!(core::mem::offset_of!(Eprocess, active_threads_high_watermark) == 0x858);
    assert!(core::mem::offset_of!(Eprocess, large_private_vad_count) == 0x85c);
    assert!(core::mem::offset_of!(Eprocess, thread_list_lock) == 0x860);
    assert!(core::mem::offset_of!(Eprocess, wnf_context) == 0x868);
    assert!(core::mem::offset_of!(Eprocess, server_silo) == 0x870);
    assert!(core::mem::offset_of!(Eprocess, signature_level) == 0x878);
    assert!(core::mem::offset_of!(Eprocess, section_signature_level) == 0x879);
    assert!(core::mem::offset_of!(Eprocess, protection) == 0x87a);
    assert!(core::mem::offset_of!(Eprocess, bitfield_87b) == 0x87b);
    assert!(core::mem::offset_of!(Eprocess, flags3) == 0x87c);
    assert!(core::mem::offset_of!(Eprocess, device_asid) == 0x880);
    assert!(core::mem::offset_of!(Eprocess, svm_data) == 0x888);
    assert!(core::mem::offset_of!(Eprocess, svm_process_lock) == 0x890);
    assert!(core::mem::offset_of!(Eprocess, svm_lock) == 0x898);
    assert!(core::mem::offset_of!(Eprocess, svm_process_device_list_head) == 0x8a0);
    assert!(core::mem::offset_of!(Eprocess, last_freeze_interrupt_time) == 0x8b0);
    assert!(core::mem::offset_of!(Eprocess, disk_counters) == 0x8b8);
    assert!(core::mem::offset_of!(Eprocess, pico_context) == 0x8c0);
    assert!(core::mem::offset_of!(Eprocess, enclave_table) == 0x8c8);
    assert!(core::mem::offset_of!(Eprocess, enclave_number) == 0x8d0);
    assert!(core::mem::offset_of!(Eprocess, enclave_lock) == 0x8d8);
    assert!(core::mem::offset_of!(Eprocess, high_priority_faults_allowed) == 0x8e0);
    assert!(core::mem::offset_of!(Eprocess, energy_context) == 0x8e8);
    assert!(core::mem::offset_of!(Eprocess, vm_context) == 0x8f0);
    assert!(core::mem::offset_of!(Eprocess, sequence_number) == 0x8f8);
    assert!(core::mem::offset_of!(Eprocess, create_interrupt_time) == 0x900);
    assert!(core::mem::offset_of!(Eprocess, create_unbiased_interrupt_time) == 0x908);
    assert!(core::mem::offset_of!(Eprocess, total_unbiased_frozen_time) == 0x910);
    assert!(core::mem::offset_of!(Eprocess, last_app_state_update_time) == 0x918);
    assert!(core::mem::offset_of!(Eprocess, bitfield_920) == 0x920);
    assert!(core::mem::offset_of!(Eprocess, shared_commit_charge) == 0x928);
    assert!(core::mem::offset_of!(Eprocess, shared_commit_lock) == 0x930);
    assert!(core::mem::offset_of!(Eprocess, shared_commit_links) == 0x938);
    assert!(core::mem::offset_of!(Eprocess, allowed_cpu_sets) == 0x948);
    assert!(core::mem::offset_of!(Eprocess, default_cpu_sets) == 0x950);
    assert!(core::mem::offset_of!(Eprocess, disk_io_attribution) == 0x958);
    assert!(core::mem::offset_of!(Eprocess, dxg_process) == 0x960);
    assert!(core::mem::offset_of!(Eprocess, win32_k_filter_set) == 0x968);
    assert!(core::mem::offset_of!(Eprocess, process_timer_delay) == 0x970);
    assert!(core::mem::offset_of!(Eprocess, k_timer_sets) == 0x978);
    assert!(core::mem::offset_of!(Eprocess, k_timer2_sets) == 0x97c);
    assert!(core::mem::offset_of!(Eprocess, thread_timer_sets) == 0x980);
    assert!(core::mem::offset_of!(Eprocess, virtual_timer_list_lock) == 0x988);
    assert!(core::mem::offset_of!(Eprocess, virtual_timer_list_head) == 0x990);
    assert!(core::mem::offset_of!(Eprocess, wake_channel) == 0x9a0);
    assert!(core::mem::offset_of!(Eprocess, mitigation_flags) == 0x9d0);
    assert!(core::mem::offset_of!(Eprocess, mitigation_flags2) == 0x9d4);
    assert!(core::mem::offset_of!(Eprocess, partition_object) == 0x9d8);
    assert!(core::mem::offset_of!(Eprocess, security_domain) == 0x9e0);
    assert!(core::mem::offset_of!(Eprocess, parent_security_domain) == 0x9e8);
    assert!(core::mem::offset_of!(Eprocess, coverage_sampler_context) == 0x9f0);
    assert!(core::mem::offset_of!(Eprocess, mm_hot_patch_context) == 0x9f8);
    assert!(core::mem::offset_of!(Eprocess, dynamic_eh_continuation_targets_tree) == 0xa00);
    assert!(core::mem::offset_of!(Eprocess, dynamic_eh_continuation_targets_lock) == 0xa08);
    assert!(core::mem::offset_of!(Eprocess, dynamic_enforced_cet_compatible_ranges) == 0xa10);
    assert!(core::mem::offset_of!(Eprocess, disabled_component_flags) == 0xa20);
    assert!(core::mem::offset_of!(Eprocess, path_redirection_hashes) == 0xa28);
    assert!(core::mem::offset_of!(Eprocess, mitigation_flags3) == 0xa30);
    assert!(core::mem::size_of::<EprocessView1>() == 0xa40);
    assert!(core::mem::align_of::<EprocessView1>() == core::mem::align_of::<Eprocess>());
    assert!(core::mem::offset_of!(EprocessView1, exception_port_value) == 0x4b0);
    assert!(core::mem::offset_of!(EprocessView1, allowed_cpu_sets_indirect) == 0x948);
    assert!(core::mem::offset_of!(EprocessView1, default_cpu_sets_indirect) == 0x950);
    assert!(core::mem::offset_of!(EprocessView1, wake_info) == 0x9a0);
    assert!(core::mem::offset_of!(EprocessView1, mitigation_flags_values) == 0x9d0);
    assert!(core::mem::offset_of!(EprocessView1, mitigation_flags2_values) == 0x9d4);
    assert!(core::mem::offset_of!(EprocessView1, mitigation_flags3_values) == 0xa30);
};

/// `_MMSUPPORT_SHARED` (0x80 bytes).
#[repr(C)]
pub struct MmsupportShared {
    pub working_set_lock: Field<i32>,
    pub good_citizen_waiting: Field<i32>,
    pub released_commit_debt: Field<u64>,
    pub reset_pages_repurposed_count: Field<u64>,
    /// -> `void`
    pub ws_swap_support: Field<u64>,
    /// -> `void`
    pub commit_release_context: Field<u64>,
    /// -> `void`
    pub access_log: Field<u64>,
    pub charged_wsle_pages: Field<u64>,
    pub actual_wsle_pages: Field<u64>,
    pub working_set_core_lock: Field<u64>,
    /// -> `void`
    pub shadow_mapping: Field<u64>,
    _pad_50: Reserved<0x30>,
}

unsafe impl NtStruct for MmsupportShared {}

const _: () = {
    assert!(core::mem::size_of::<MmsupportShared>() == 0x80);
    assert!(core::mem::offset_of!(MmsupportShared, working_set_lock) == 0x0);
    assert!(core::mem::offset_of!(MmsupportShared, good_citizen_waiting) == 0x4);
    assert!(core::mem::offset_of!(MmsupportShared, released_commit_debt) == 0x8);
    assert!(core::mem::offset_of!(MmsupportShared, reset_pages_repurposed_count) == 0x10);
    assert!(core::mem::offset_of!(MmsupportShared, ws_swap_support) == 0x18);
    assert!(core::mem::offset_of!(MmsupportShared, commit_release_context) == 0x20);
    assert!(core::mem::offset_of!(MmsupportShared, access_log) == 0x28);
    assert!(core::mem::offset_of!(MmsupportShared, charged_wsle_pages) == 0x30);
    assert!(core::mem::offset_of!(MmsupportShared, actual_wsle_pages) == 0x38);
    assert!(core::mem::offset_of!(MmsupportShared, working_set_core_lock) == 0x40);
    assert!(core::mem::offset_of!(MmsupportShared, shadow_mapping) == 0x48);
};

/// `_PS_PROTECTION` (0x1 bytes).
#[repr(C)]
pub struct PsProtection {
    pub level: Field<u8>,
}

unsafe impl NtStruct for PsProtection {}

impl PsProtection {
    /// `Type`: bits 0..=2 de `level`.
    pub const TYPE_SHIFT: u32 = 0;
    pub const TYPE_MASK: u8 = 0x7;
    #[inline(always)]
    pub fn type_(&self) -> u8 {
        self.level.bits(0, 3) as u8
    }
    #[inline(always)]
    pub fn set_type(&self, value: u8) {
        self.level.set_bits(0, 3, value as u64)
    }
    /// `Audit`: bits 3..=3 de `level`.
    pub const AUDIT_SHIFT: u32 = 3;
    pub const AUDIT_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn audit(&self) -> u8 {
        self.level.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_audit(&self, value: u8) {
        self.level.set_bits(3, 1, value as u64)
    }
    /// `Signer`: bits 4..=7 de `level`.
    pub const SIGNER_SHIFT: u32 = 4;
    pub const SIGNER_MASK: u8 = 0xf0;
    #[inline(always)]
    pub fn signer(&self) -> u8 {
        self.level.bits(4, 4) as u8
    }
    #[inline(always)]
    pub fn set_signer(&self, value: u8) {
        self.level.set_bits(4, 4, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PsProtection>() == 0x1);
    assert!(core::mem::offset_of!(PsProtection, level) == 0x0);
};

/// `_PS_INTERLOCKED_TIMER_DELAY_VALUES` (0x8 bytes).
#[repr(C)]
pub struct PsInterlockedTimerDelayValues {
    pub all: Field<u64>,
}

unsafe impl NtStruct for PsInterlockedTimerDelayValues {}

impl PsInterlockedTimerDelayValues {
    /// `DelayMs`: bits 0..=29 de `all`.
    pub const DELAY_MS_SHIFT: u32 = 0;
    pub const DELAY_MS_MASK: u64 = 0x3fffffff;
    #[inline(always)]
    pub fn delay_ms(&self) -> u64 {
        self.all.bits(0, 30) as u64
    }
    #[inline(always)]
    pub fn set_delay_ms(&self, value: u64) {
        self.all.set_bits(0, 30, value as u64)
    }
    /// `CoalescingWindowMs`: bits 30..=59 de `all`.
    pub const COALESCING_WINDOW_MS_SHIFT: u32 = 30;
    pub const COALESCING_WINDOW_MS_MASK: u64 = 0xfffffffc0000000;
    #[inline(always)]
    pub fn coalescing_window_ms(&self) -> u64 {
        self.all.bits(30, 30) as u64
    }
    #[inline(always)]
    pub fn set_coalescing_window_ms(&self, value: u64) {
        self.all.set_bits(30, 30, value as u64)
    }
    /// `Reserved`: bits 60..=60 de `all`.
    pub const RESERVED_SHIFT: u32 = 60;
    pub const RESERVED_MASK: u64 = 0x1000000000000000;
    #[inline(always)]
    pub fn reserved(&self) -> u64 {
        self.all.bits(60, 1) as u64
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u64) {
        self.all.set_bits(60, 1, value as u64)
    }
    /// `NewTimerWheel`: bits 61..=61 de `all`.
    pub const NEW_TIMER_WHEEL_SHIFT: u32 = 61;
    pub const NEW_TIMER_WHEEL_MASK: u64 = 0x2000000000000000;
    #[inline(always)]
    pub fn new_timer_wheel(&self) -> u64 {
        self.all.bits(61, 1) as u64
    }
    #[inline(always)]
    pub fn set_new_timer_wheel(&self, value: u64) {
        self.all.set_bits(61, 1, value as u64)
    }
    /// `Retry`: bits 62..=62 de `all`.
    pub const RETRY_SHIFT: u32 = 62;
    pub const RETRY_MASK: u64 = 0x4000000000000000;
    #[inline(always)]
    pub fn retry(&self) -> u64 {
        self.all.bits(62, 1) as u64
    }
    #[inline(always)]
    pub fn set_retry(&self, value: u64) {
        self.all.set_bits(62, 1, value as u64)
    }
    /// `Locked`: bits 63..=63 de `all`.
    pub const LOCKED_SHIFT: u32 = 63;
    pub const LOCKED_MASK: u64 = 0x8000000000000000;
    #[inline(always)]
    pub fn locked(&self) -> u64 {
        self.all.bits(63, 1) as u64
    }
    #[inline(always)]
    pub fn set_locked(&self, value: u64) {
        self.all.set_bits(63, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PsInterlockedTimerDelayValues>() == 0x8);
    assert!(core::mem::offset_of!(PsInterlockedTimerDelayValues, all) == 0x0);
};

/// `_PS_PROCESS_WAKE_INFORMATION` (0x30 bytes).
#[repr(C)]
pub struct PsProcessWakeInformation {
    pub notification_channel: Field<u64>,
    pub wake_counters: [Field<u32>; 7],
    pub wake_filter: JobobjectWakeFilter,
    pub no_wake_counter: Field<u32>,
}

unsafe impl NtStruct for PsProcessWakeInformation {}

const _: () = {
    assert!(core::mem::size_of::<PsProcessWakeInformation>() == 0x30);
    assert!(core::mem::offset_of!(PsProcessWakeInformation, notification_channel) == 0x0);
    assert!(core::mem::offset_of!(PsProcessWakeInformation, wake_counters) == 0x8);
    assert!(core::mem::offset_of!(PsProcessWakeInformation, wake_filter) == 0x24);
    assert!(core::mem::offset_of!(PsProcessWakeInformation, no_wake_counter) == 0x2c);
};

/// `_JOBOBJECT_WAKE_FILTER` (0x8 bytes).
#[repr(C)]
pub struct JobobjectWakeFilter {
    pub high_edge_filter: Field<u32>,
    pub low_edge_filter: Field<u32>,
}

unsafe impl NtStruct for JobobjectWakeFilter {}

const _: () = {
    assert!(core::mem::size_of::<JobobjectWakeFilter>() == 0x8);
    assert!(core::mem::offset_of!(JobobjectWakeFilter, high_edge_filter) == 0x0);
    assert!(core::mem::offset_of!(JobobjectWakeFilter, low_edge_filter) == 0x4);
};

/// `_EPROCESS::MitigationFlagsValues` (0x4 bytes).
#[repr(C)]
pub struct EprocessMitigationFlagsValues {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for EprocessMitigationFlagsValues {}

impl EprocessMitigationFlagsValues {
    /// `ControlFlowGuardEnabled`: bits 0..=0 de `bitfield_0`.
    pub const CONTROL_FLOW_GUARD_ENABLED_SHIFT: u32 = 0;
    pub const CONTROL_FLOW_GUARD_ENABLED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn control_flow_guard_enabled(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_control_flow_guard_enabled(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `ControlFlowGuardExportSuppressionEnabled`: bits 1..=1 de `bitfield_0`.
    pub const CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION_ENABLED_SHIFT: u32 = 1;
    pub const CONTROL_FLOW_GUARD_EXPORT_SUPPRESSION_ENABLED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn control_flow_guard_export_suppression_enabled(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_control_flow_guard_export_suppression_enabled(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `ControlFlowGuardStrict`: bits 2..=2 de `bitfield_0`.
    pub const CONTROL_FLOW_GUARD_STRICT_SHIFT: u32 = 2;
    pub const CONTROL_FLOW_GUARD_STRICT_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn control_flow_guard_strict(&self) -> u32 {
        self.bitfield_0.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_control_flow_guard_strict(&self, value: u32) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `DisallowStrippedImages`: bits 3..=3 de `bitfield_0`.
    pub const DISALLOW_STRIPPED_IMAGES_SHIFT: u32 = 3;
    pub const DISALLOW_STRIPPED_IMAGES_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn disallow_stripped_images(&self) -> u32 {
        self.bitfield_0.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_stripped_images(&self, value: u32) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `ForceRelocateImages`: bits 4..=4 de `bitfield_0`.
    pub const FORCE_RELOCATE_IMAGES_SHIFT: u32 = 4;
    pub const FORCE_RELOCATE_IMAGES_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn force_relocate_images(&self) -> u32 {
        self.bitfield_0.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_force_relocate_images(&self, value: u32) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `HighEntropyASLREnabled`: bits 5..=5 de `bitfield_0`.
    pub const HIGH_ENTROPY_ASLR_ENABLED_SHIFT: u32 = 5;
    pub const HIGH_ENTROPY_ASLR_ENABLED_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn high_entropy_aslr_enabled(&self) -> u32 {
        self.bitfield_0.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_high_entropy_aslr_enabled(&self, value: u32) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `StackRandomizationDisabled`: bits 6..=6 de `bitfield_0`.
    pub const STACK_RANDOMIZATION_DISABLED_SHIFT: u32 = 6;
    pub const STACK_RANDOMIZATION_DISABLED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn stack_randomization_disabled(&self) -> u32 {
        self.bitfield_0.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_stack_randomization_disabled(&self, value: u32) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `ExtensionPointDisable`: bits 7..=7 de `bitfield_0`.
    pub const EXTENSION_POINT_DISABLE_SHIFT: u32 = 7;
    pub const EXTENSION_POINT_DISABLE_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn extension_point_disable(&self) -> u32 {
        self.bitfield_0.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_extension_point_disable(&self, value: u32) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `DisableDynamicCode`: bits 8..=8 de `bitfield_0`.
    pub const DISABLE_DYNAMIC_CODE_SHIFT: u32 = 8;
    pub const DISABLE_DYNAMIC_CODE_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn disable_dynamic_code(&self) -> u32 {
        self.bitfield_0.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_dynamic_code(&self, value: u32) {
        self.bitfield_0.set_bits(8, 1, value as u64)
    }
    /// `DisableDynamicCodeAllowOptOut`: bits 9..=9 de `bitfield_0`.
    pub const DISABLE_DYNAMIC_CODE_ALLOW_OPT_OUT_SHIFT: u32 = 9;
    pub const DISABLE_DYNAMIC_CODE_ALLOW_OPT_OUT_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn disable_dynamic_code_allow_opt_out(&self) -> u32 {
        self.bitfield_0.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_dynamic_code_allow_opt_out(&self, value: u32) {
        self.bitfield_0.set_bits(9, 1, value as u64)
    }
    /// `DisableDynamicCodeAllowRemoteDowngrade`: bits 10..=10 de `bitfield_0`.
    pub const DISABLE_DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE_SHIFT: u32 = 10;
    pub const DISABLE_DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn disable_dynamic_code_allow_remote_downgrade(&self) -> u32 {
        self.bitfield_0.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_dynamic_code_allow_remote_downgrade(&self, value: u32) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `AuditDisableDynamicCode`: bits 11..=11 de `bitfield_0`.
    pub const AUDIT_DISABLE_DYNAMIC_CODE_SHIFT: u32 = 11;
    pub const AUDIT_DISABLE_DYNAMIC_CODE_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn audit_disable_dynamic_code(&self) -> u32 {
        self.bitfield_0.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_disable_dynamic_code(&self, value: u32) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `DisallowWin32kSystemCalls`: bits 12..=12 de `bitfield_0`.
    pub const DISALLOW_WIN32K_SYSTEM_CALLS_SHIFT: u32 = 12;
    pub const DISALLOW_WIN32K_SYSTEM_CALLS_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn disallow_win32k_system_calls(&self) -> u32 {
        self.bitfield_0.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_win32k_system_calls(&self, value: u32) {
        self.bitfield_0.set_bits(12, 1, value as u64)
    }
    /// `AuditDisallowWin32kSystemCalls`: bits 13..=13 de `bitfield_0`.
    pub const AUDIT_DISALLOW_WIN32K_SYSTEM_CALLS_SHIFT: u32 = 13;
    pub const AUDIT_DISALLOW_WIN32K_SYSTEM_CALLS_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn audit_disallow_win32k_system_calls(&self) -> u32 {
        self.bitfield_0.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_disallow_win32k_system_calls(&self, value: u32) {
        self.bitfield_0.set_bits(13, 1, value as u64)
    }
    /// `EnableFilteredWin32kAPIs`: bits 14..=14 de `bitfield_0`.
    pub const ENABLE_FILTERED_WIN32K_AP_IS_SHIFT: u32 = 14;
    pub const ENABLE_FILTERED_WIN32K_AP_IS_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn enable_filtered_win32k_ap_is(&self) -> u32 {
        self.bitfield_0.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_filtered_win32k_ap_is(&self, value: u32) {
        self.bitfield_0.set_bits(14, 1, value as u64)
    }
    /// `AuditFilteredWin32kAPIs`: bits 15..=15 de `bitfield_0`.
    pub const AUDIT_FILTERED_WIN32K_AP_IS_SHIFT: u32 = 15;
    pub const AUDIT_FILTERED_WIN32K_AP_IS_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn audit_filtered_win32k_ap_is(&self) -> u32 {
        self.bitfield_0.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_filtered_win32k_ap_is(&self, value: u32) {
        self.bitfield_0.set_bits(15, 1, value as u64)
    }
    /// `DisableNonSystemFonts`: bits 16..=16 de `bitfield_0`.
    pub const DISABLE_NON_SYSTEM_FONTS_SHIFT: u32 = 16;
    pub const DISABLE_NON_SYSTEM_FONTS_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn disable_non_system_fonts(&self) -> u32 {
        self.bitfield_0.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_non_system_fonts(&self, value: u32) {
        self.bitfield_0.set_bits(16, 1, value as u64)
    }
    /// `AuditNonSystemFontLoading`: bits 17..=17 de `bitfield_0`.
    pub const AUDIT_NON_SYSTEM_FONT_LOADING_SHIFT: u32 = 17;
    pub const AUDIT_NON_SYSTEM_FONT_LOADING_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn audit_non_system_font_loading(&self) -> u32 {
        self.bitfield_0.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_non_system_font_loading(&self, value: u32) {
        self.bitfield_0.set_bits(17, 1, value as u64)
    }
    /// `PreferSystem32Images`: bits 18..=18 de `bitfield_0`.
    pub const PREFER_SYSTEM32_IMAGES_SHIFT: u32 = 18;
    pub const PREFER_SYSTEM32_IMAGES_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn prefer_system32_images(&self) -> u32 {
        self.bitfield_0.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_prefer_system32_images(&self, value: u32) {
        self.bitfield_0.set_bits(18, 1, value as u64)
    }
    /// `ProhibitRemoteImageMap`: bits 19..=19 de `bitfield_0`.
    pub const PROHIBIT_REMOTE_IMAGE_MAP_SHIFT: u32 = 19;
    pub const PROHIBIT_REMOTE_IMAGE_MAP_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn prohibit_remote_image_map(&self) -> u32 {
        self.bitfield_0.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_prohibit_remote_image_map(&self, value: u32) {
        self.bitfield_0.set_bits(19, 1, value as u64)
    }
    /// `AuditProhibitRemoteImageMap`: bits 20..=20 de `bitfield_0`.
    pub const AUDIT_PROHIBIT_REMOTE_IMAGE_MAP_SHIFT: u32 = 20;
    pub const AUDIT_PROHIBIT_REMOTE_IMAGE_MAP_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn audit_prohibit_remote_image_map(&self) -> u32 {
        self.bitfield_0.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_prohibit_remote_image_map(&self, value: u32) {
        self.bitfield_0.set_bits(20, 1, value as u64)
    }
    /// `ProhibitLowILImageMap`: bits 21..=21 de `bitfield_0`.
    pub const PROHIBIT_LOW_IL_IMAGE_MAP_SHIFT: u32 = 21;
    pub const PROHIBIT_LOW_IL_IMAGE_MAP_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn prohibit_low_il_image_map(&self) -> u32 {
        self.bitfield_0.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_prohibit_low_il_image_map(&self, value: u32) {
        self.bitfield_0.set_bits(21, 1, value as u64)
    }
    /// `AuditProhibitLowILImageMap`: bits 22..=22 de `bitfield_0`.
    pub const AUDIT_PROHIBIT_LOW_IL_IMAGE_MAP_SHIFT: u32 = 22;
    pub const AUDIT_PROHIBIT_LOW_IL_IMAGE_MAP_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn audit_prohibit_low_il_image_map(&self) -> u32 {
        self.bitfield_0.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_prohibit_low_il_image_map(&self, value: u32) {
        self.bitfield_0.set_bits(22, 1, value as u64)
    }
    /// `SignatureMitigationOptIn`: bits 23..=23 de `bitfield_0`.
    pub const SIGNATURE_MITIGATION_OPT_IN_SHIFT: u32 = 23;
    pub const SIGNATURE_MITIGATION_OPT_IN_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn signature_mitigation_opt_in(&self) -> u32 {
        self.bitfield_0.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_signature_mitigation_opt_in(&self, value: u32) {
        self.bitfield_0.set_bits(23, 1, value as u64)
    }
    /// `AuditBlockNonMicrosoftBinaries`: bits 24..=24 de `bitfield_0`.
    pub const AUDIT_BLOCK_NON_MICROSOFT_BINARIES_SHIFT: u32 = 24;
    pub const AUDIT_BLOCK_NON_MICROSOFT_BINARIES_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn audit_block_non_microsoft_binaries(&self) -> u32 {
        self.bitfield_0.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_block_non_microsoft_binaries(&self, value: u32) {
        self.bitfield_0.set_bits(24, 1, value as u64)
    }
    /// `AuditBlockNonMicrosoftBinariesAllowStore`: bits 25..=25 de `bitfield_0`.
    pub const AUDIT_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE_SHIFT: u32 = 25;
    pub const AUDIT_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn audit_block_non_microsoft_binaries_allow_store(&self) -> u32 {
        self.bitfield_0.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_block_non_microsoft_binaries_allow_store(&self, value: u32) {
        self.bitfield_0.set_bits(25, 1, value as u64)
    }
    /// `LoaderIntegrityContinuityEnabled`: bits 26..=26 de `bitfield_0`.
    pub const LOADER_INTEGRITY_CONTINUITY_ENABLED_SHIFT: u32 = 26;
    pub const LOADER_INTEGRITY_CONTINUITY_ENABLED_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn loader_integrity_continuity_enabled(&self) -> u32 {
        self.bitfield_0.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_loader_integrity_continuity_enabled(&self, value: u32) {
        self.bitfield_0.set_bits(26, 1, value as u64)
    }
    /// `AuditLoaderIntegrityContinuity`: bits 27..=27 de `bitfield_0`.
    pub const AUDIT_LOADER_INTEGRITY_CONTINUITY_SHIFT: u32 = 27;
    pub const AUDIT_LOADER_INTEGRITY_CONTINUITY_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn audit_loader_integrity_continuity(&self) -> u32 {
        self.bitfield_0.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_loader_integrity_continuity(&self, value: u32) {
        self.bitfield_0.set_bits(27, 1, value as u64)
    }
    /// `EnableModuleTamperingProtection`: bits 28..=28 de `bitfield_0`.
    pub const ENABLE_MODULE_TAMPERING_PROTECTION_SHIFT: u32 = 28;
    pub const ENABLE_MODULE_TAMPERING_PROTECTION_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn enable_module_tampering_protection(&self) -> u32 {
        self.bitfield_0.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_module_tampering_protection(&self, value: u32) {
        self.bitfield_0.set_bits(28, 1, value as u64)
    }
    /// `EnableModuleTamperingProtectionNoInherit`: bits 29..=29 de `bitfield_0`.
    pub const ENABLE_MODULE_TAMPERING_PROTECTION_NO_INHERIT_SHIFT: u32 = 29;
    pub const ENABLE_MODULE_TAMPERING_PROTECTION_NO_INHERIT_MASK: u32 = 0x20000000;
    #[inline(always)]
    pub fn enable_module_tampering_protection_no_inherit(&self) -> u32 {
        self.bitfield_0.bits(29, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_module_tampering_protection_no_inherit(&self, value: u32) {
        self.bitfield_0.set_bits(29, 1, value as u64)
    }
    /// `RestrictIndirectBranchPrediction`: bits 30..=30 de `bitfield_0`.
    pub const RESTRICT_INDIRECT_BRANCH_PREDICTION_SHIFT: u32 = 30;
    pub const RESTRICT_INDIRECT_BRANCH_PREDICTION_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn restrict_indirect_branch_prediction(&self) -> u32 {
        self.bitfield_0.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_restrict_indirect_branch_prediction(&self, value: u32) {
        self.bitfield_0.set_bits(30, 1, value as u64)
    }
    /// `IsolateSecurityDomain`: bits 31..=31 de `bitfield_0`.
    pub const ISOLATE_SECURITY_DOMAIN_SHIFT: u32 = 31;
    pub const ISOLATE_SECURITY_DOMAIN_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn isolate_security_domain(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_isolate_security_domain(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EprocessMitigationFlagsValues>() == 0x4);
    assert!(core::mem::offset_of!(EprocessMitigationFlagsValues, bitfield_0) == 0x0);
};

/// `_EPROCESS::MitigationFlags2Values` (0x4 bytes).
#[repr(C)]
pub struct EprocessMitigationFlags2Values {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for EprocessMitigationFlags2Values {}

impl EprocessMitigationFlags2Values {
    /// `EnableExportAddressFilter`: bits 0..=0 de `bitfield_0`.
    pub const ENABLE_EXPORT_ADDRESS_FILTER_SHIFT: u32 = 0;
    pub const ENABLE_EXPORT_ADDRESS_FILTER_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn enable_export_address_filter(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_export_address_filter(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `AuditExportAddressFilter`: bits 1..=1 de `bitfield_0`.
    pub const AUDIT_EXPORT_ADDRESS_FILTER_SHIFT: u32 = 1;
    pub const AUDIT_EXPORT_ADDRESS_FILTER_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn audit_export_address_filter(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_export_address_filter(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `EnableExportAddressFilterPlus`: bits 2..=2 de `bitfield_0`.
    pub const ENABLE_EXPORT_ADDRESS_FILTER_PLUS_SHIFT: u32 = 2;
    pub const ENABLE_EXPORT_ADDRESS_FILTER_PLUS_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn enable_export_address_filter_plus(&self) -> u32 {
        self.bitfield_0.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_export_address_filter_plus(&self, value: u32) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `AuditExportAddressFilterPlus`: bits 3..=3 de `bitfield_0`.
    pub const AUDIT_EXPORT_ADDRESS_FILTER_PLUS_SHIFT: u32 = 3;
    pub const AUDIT_EXPORT_ADDRESS_FILTER_PLUS_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn audit_export_address_filter_plus(&self) -> u32 {
        self.bitfield_0.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_export_address_filter_plus(&self, value: u32) {
        self.bitfield_0.set_bits(3, 1, value as u64)
    }
    /// `EnableRopStackPivot`: bits 4..=4 de `bitfield_0`.
    pub const ENABLE_ROP_STACK_PIVOT_SHIFT: u32 = 4;
    pub const ENABLE_ROP_STACK_PIVOT_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn enable_rop_stack_pivot(&self) -> u32 {
        self.bitfield_0.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_rop_stack_pivot(&self, value: u32) {
        self.bitfield_0.set_bits(4, 1, value as u64)
    }
    /// `AuditRopStackPivot`: bits 5..=5 de `bitfield_0`.
    pub const AUDIT_ROP_STACK_PIVOT_SHIFT: u32 = 5;
    pub const AUDIT_ROP_STACK_PIVOT_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn audit_rop_stack_pivot(&self) -> u32 {
        self.bitfield_0.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_rop_stack_pivot(&self, value: u32) {
        self.bitfield_0.set_bits(5, 1, value as u64)
    }
    /// `EnableRopCallerCheck`: bits 6..=6 de `bitfield_0`.
    pub const ENABLE_ROP_CALLER_CHECK_SHIFT: u32 = 6;
    pub const ENABLE_ROP_CALLER_CHECK_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn enable_rop_caller_check(&self) -> u32 {
        self.bitfield_0.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_rop_caller_check(&self, value: u32) {
        self.bitfield_0.set_bits(6, 1, value as u64)
    }
    /// `AuditRopCallerCheck`: bits 7..=7 de `bitfield_0`.
    pub const AUDIT_ROP_CALLER_CHECK_SHIFT: u32 = 7;
    pub const AUDIT_ROP_CALLER_CHECK_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn audit_rop_caller_check(&self) -> u32 {
        self.bitfield_0.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_rop_caller_check(&self, value: u32) {
        self.bitfield_0.set_bits(7, 1, value as u64)
    }
    /// `EnableRopSimExec`: bits 8..=8 de `bitfield_0`.
    pub const ENABLE_ROP_SIM_EXEC_SHIFT: u32 = 8;
    pub const ENABLE_ROP_SIM_EXEC_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn enable_rop_sim_exec(&self) -> u32 {
        self.bitfield_0.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_rop_sim_exec(&self, value: u32) {
        self.bitfield_0.set_bits(8, 1, value as u64)
    }
    /// `AuditRopSimExec`: bits 9..=9 de `bitfield_0`.
    pub const AUDIT_ROP_SIM_EXEC_SHIFT: u32 = 9;
    pub const AUDIT_ROP_SIM_EXEC_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn audit_rop_sim_exec(&self) -> u32 {
        self.bitfield_0.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_rop_sim_exec(&self, value: u32) {
        self.bitfield_0.set_bits(9, 1, value as u64)
    }
    /// `EnableImportAddressFilter`: bits 10..=10 de `bitfield_0`.
    pub const ENABLE_IMPORT_ADDRESS_FILTER_SHIFT: u32 = 10;
    pub const ENABLE_IMPORT_ADDRESS_FILTER_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn enable_import_address_filter(&self) -> u32 {
        self.bitfield_0.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_import_address_filter(&self, value: u32) {
        self.bitfield_0.set_bits(10, 1, value as u64)
    }
    /// `AuditImportAddressFilter`: bits 11..=11 de `bitfield_0`.
    pub const AUDIT_IMPORT_ADDRESS_FILTER_SHIFT: u32 = 11;
    pub const AUDIT_IMPORT_ADDRESS_FILTER_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn audit_import_address_filter(&self) -> u32 {
        self.bitfield_0.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_import_address_filter(&self, value: u32) {
        self.bitfield_0.set_bits(11, 1, value as u64)
    }
    /// `DisablePageCombine`: bits 12..=12 de `bitfield_0`.
    pub const DISABLE_PAGE_COMBINE_SHIFT: u32 = 12;
    pub const DISABLE_PAGE_COMBINE_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn disable_page_combine(&self) -> u32 {
        self.bitfield_0.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_disable_page_combine(&self, value: u32) {
        self.bitfield_0.set_bits(12, 1, value as u64)
    }
    /// `SpeculativeStoreBypassDisable`: bits 13..=13 de `bitfield_0`.
    pub const SPECULATIVE_STORE_BYPASS_DISABLE_SHIFT: u32 = 13;
    pub const SPECULATIVE_STORE_BYPASS_DISABLE_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn speculative_store_bypass_disable(&self) -> u32 {
        self.bitfield_0.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_speculative_store_bypass_disable(&self, value: u32) {
        self.bitfield_0.set_bits(13, 1, value as u64)
    }
    /// `CetUserShadowStacks`: bits 14..=14 de `bitfield_0`.
    pub const CET_USER_SHADOW_STACKS_SHIFT: u32 = 14;
    pub const CET_USER_SHADOW_STACKS_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn cet_user_shadow_stacks(&self) -> u32 {
        self.bitfield_0.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_cet_user_shadow_stacks(&self, value: u32) {
        self.bitfield_0.set_bits(14, 1, value as u64)
    }
    /// `AuditCetUserShadowStacks`: bits 15..=15 de `bitfield_0`.
    pub const AUDIT_CET_USER_SHADOW_STACKS_SHIFT: u32 = 15;
    pub const AUDIT_CET_USER_SHADOW_STACKS_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn audit_cet_user_shadow_stacks(&self) -> u32 {
        self.bitfield_0.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_cet_user_shadow_stacks(&self, value: u32) {
        self.bitfield_0.set_bits(15, 1, value as u64)
    }
    /// `AuditCetUserShadowStacksLogged`: bits 16..=16 de `bitfield_0`.
    pub const AUDIT_CET_USER_SHADOW_STACKS_LOGGED_SHIFT: u32 = 16;
    pub const AUDIT_CET_USER_SHADOW_STACKS_LOGGED_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn audit_cet_user_shadow_stacks_logged(&self) -> u32 {
        self.bitfield_0.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_cet_user_shadow_stacks_logged(&self, value: u32) {
        self.bitfield_0.set_bits(16, 1, value as u64)
    }
    /// `UserCetSetContextIpValidation`: bits 17..=17 de `bitfield_0`.
    pub const USER_CET_SET_CONTEXT_IP_VALIDATION_SHIFT: u32 = 17;
    pub const USER_CET_SET_CONTEXT_IP_VALIDATION_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn user_cet_set_context_ip_validation(&self) -> u32 {
        self.bitfield_0.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_user_cet_set_context_ip_validation(&self, value: u32) {
        self.bitfield_0.set_bits(17, 1, value as u64)
    }
    /// `AuditUserCetSetContextIpValidation`: bits 18..=18 de `bitfield_0`.
    pub const AUDIT_USER_CET_SET_CONTEXT_IP_VALIDATION_SHIFT: u32 = 18;
    pub const AUDIT_USER_CET_SET_CONTEXT_IP_VALIDATION_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn audit_user_cet_set_context_ip_validation(&self) -> u32 {
        self.bitfield_0.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_user_cet_set_context_ip_validation(&self, value: u32) {
        self.bitfield_0.set_bits(18, 1, value as u64)
    }
    /// `AuditUserCetSetContextIpValidationLogged`: bits 19..=19 de `bitfield_0`.
    pub const AUDIT_USER_CET_SET_CONTEXT_IP_VALIDATION_LOGGED_SHIFT: u32 = 19;
    pub const AUDIT_USER_CET_SET_CONTEXT_IP_VALIDATION_LOGGED_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn audit_user_cet_set_context_ip_validation_logged(&self) -> u32 {
        self.bitfield_0.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_user_cet_set_context_ip_validation_logged(&self, value: u32) {
        self.bitfield_0.set_bits(19, 1, value as u64)
    }
    /// `CetUserShadowStacksStrictMode`: bits 20..=20 de `bitfield_0`.
    pub const CET_USER_SHADOW_STACKS_STRICT_MODE_SHIFT: u32 = 20;
    pub const CET_USER_SHADOW_STACKS_STRICT_MODE_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn cet_user_shadow_stacks_strict_mode(&self) -> u32 {
        self.bitfield_0.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_cet_user_shadow_stacks_strict_mode(&self, value: u32) {
        self.bitfield_0.set_bits(20, 1, value as u64)
    }
    /// `BlockNonCetBinaries`: bits 21..=21 de `bitfield_0`.
    pub const BLOCK_NON_CET_BINARIES_SHIFT: u32 = 21;
    pub const BLOCK_NON_CET_BINARIES_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn block_non_cet_binaries(&self) -> u32 {
        self.bitfield_0.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_block_non_cet_binaries(&self, value: u32) {
        self.bitfield_0.set_bits(21, 1, value as u64)
    }
    /// `BlockNonCetBinariesNonEhcont`: bits 22..=22 de `bitfield_0`.
    pub const BLOCK_NON_CET_BINARIES_NON_EHCONT_SHIFT: u32 = 22;
    pub const BLOCK_NON_CET_BINARIES_NON_EHCONT_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn block_non_cet_binaries_non_ehcont(&self) -> u32 {
        self.bitfield_0.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_block_non_cet_binaries_non_ehcont(&self, value: u32) {
        self.bitfield_0.set_bits(22, 1, value as u64)
    }
    /// `AuditBlockNonCetBinaries`: bits 23..=23 de `bitfield_0`.
    pub const AUDIT_BLOCK_NON_CET_BINARIES_SHIFT: u32 = 23;
    pub const AUDIT_BLOCK_NON_CET_BINARIES_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn audit_block_non_cet_binaries(&self) -> u32 {
        self.bitfield_0.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_block_non_cet_binaries(&self, value: u32) {
        self.bitfield_0.set_bits(23, 1, value as u64)
    }
    /// `AuditBlockNonCetBinariesLogged`: bits 24..=24 de `bitfield_0`.
    pub const AUDIT_BLOCK_NON_CET_BINARIES_LOGGED_SHIFT: u32 = 24;
    pub const AUDIT_BLOCK_NON_CET_BINARIES_LOGGED_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn audit_block_non_cet_binaries_logged(&self) -> u32 {
        self.bitfield_0.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_block_non_cet_binaries_logged(&self, value: u32) {
        self.bitfield_0.set_bits(24, 1, value as u64)
    }
    /// `Reserved1`: bits 25..=25 de `bitfield_0`.
    pub const RESERVED1_SHIFT: u32 = 25;
    pub const RESERVED1_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn reserved1(&self) -> u32 {
        self.bitfield_0.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved1(&self, value: u32) {
        self.bitfield_0.set_bits(25, 1, value as u64)
    }
    /// `Reserved2`: bits 26..=26 de `bitfield_0`.
    pub const RESERVED2_SHIFT: u32 = 26;
    pub const RESERVED2_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn reserved2(&self) -> u32 {
        self.bitfield_0.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved2(&self, value: u32) {
        self.bitfield_0.set_bits(26, 1, value as u64)
    }
    /// `Reserved3`: bits 27..=27 de `bitfield_0`.
    pub const RESERVED3_SHIFT: u32 = 27;
    pub const RESERVED3_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn reserved3(&self) -> u32 {
        self.bitfield_0.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved3(&self, value: u32) {
        self.bitfield_0.set_bits(27, 1, value as u64)
    }
    /// `Reserved4`: bits 28..=28 de `bitfield_0`.
    pub const RESERVED4_SHIFT: u32 = 28;
    pub const RESERVED4_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn reserved4(&self) -> u32 {
        self.bitfield_0.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved4(&self, value: u32) {
        self.bitfield_0.set_bits(28, 1, value as u64)
    }
    /// `Reserved5`: bits 29..=29 de `bitfield_0`.
    pub const RESERVED5_SHIFT: u32 = 29;
    pub const RESERVED5_MASK: u32 = 0x20000000;
    #[inline(always)]
    pub fn reserved5(&self) -> u32 {
        self.bitfield_0.bits(29, 1) as u32
    }
    #[inline(always)]
    pub fn set_reserved5(&self, value: u32) {
        self.bitfield_0.set_bits(29, 1, value as u64)
    }
    /// `CetDynamicApisOutOfProcOnly`: bits 30..=30 de `bitfield_0`.
    pub const CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY_SHIFT: u32 = 30;
    pub const CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn cet_dynamic_apis_out_of_proc_only(&self) -> u32 {
        self.bitfield_0.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_cet_dynamic_apis_out_of_proc_only(&self, value: u32) {
        self.bitfield_0.set_bits(30, 1, value as u64)
    }
    /// `UserCetSetContextIpValidationRelaxedMode`: bits 31..=31 de `bitfield_0`.
    pub const USER_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE_SHIFT: u32 = 31;
    pub const USER_CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn user_cet_set_context_ip_validation_relaxed_mode(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_user_cet_set_context_ip_validation_relaxed_mode(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EprocessMitigationFlags2Values>() == 0x4);
    assert!(core::mem::offset_of!(EprocessMitigationFlags2Values, bitfield_0) == 0x0);
};

/// `_PS_DYNAMIC_ENFORCED_ADDRESS_RANGES` (0x10 bytes).
#[repr(C)]
pub struct PsDynamicEnforcedAddressRanges {
    pub tree: RtlAvlTree,
    pub lock: ExPushLock,
}

unsafe impl NtStruct for PsDynamicEnforcedAddressRanges {}

const _: () = {
    assert!(core::mem::size_of::<PsDynamicEnforcedAddressRanges>() == 0x10);
    assert!(core::mem::offset_of!(PsDynamicEnforcedAddressRanges, tree) == 0x0);
    assert!(core::mem::offset_of!(PsDynamicEnforcedAddressRanges, lock) == 0x8);
};

/// `_EPROCESS::MitigationFlags3Values` (0x4 bytes).
#[repr(C)]
pub struct EprocessMitigationFlags3Values {
    pub bitfield_0: Field<u32>,
}

unsafe impl NtStruct for EprocessMitigationFlags3Values {}

impl EprocessMitigationFlags3Values {
    /// `RestrictCoreSharing`: bits 0..=0 de `bitfield_0`.
    pub const RESTRICT_CORE_SHARING_SHIFT: u32 = 0;
    pub const RESTRICT_CORE_SHARING_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn restrict_core_sharing(&self) -> u32 {
        self.bitfield_0.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_restrict_core_sharing(&self, value: u32) {
        self.bitfield_0.set_bits(0, 1, value as u64)
    }
    /// `DisallowFsctlSystemCalls`: bits 1..=1 de `bitfield_0`.
    pub const DISALLOW_FSCTL_SYSTEM_CALLS_SHIFT: u32 = 1;
    pub const DISALLOW_FSCTL_SYSTEM_CALLS_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn disallow_fsctl_system_calls(&self) -> u32 {
        self.bitfield_0.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_fsctl_system_calls(&self, value: u32) {
        self.bitfield_0.set_bits(1, 1, value as u64)
    }
    /// `AuditDisallowFsctlSystemCalls`: bits 2..=2 de `bitfield_0`.
    pub const AUDIT_DISALLOW_FSCTL_SYSTEM_CALLS_SHIFT: u32 = 2;
    pub const AUDIT_DISALLOW_FSCTL_SYSTEM_CALLS_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn audit_disallow_fsctl_system_calls(&self) -> u32 {
        self.bitfield_0.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_audit_disallow_fsctl_system_calls(&self, value: u32) {
        self.bitfield_0.set_bits(2, 1, value as u64)
    }
    /// `MitigationFlags3Spare`: bits 3..=31 de `bitfield_0`.
    pub const MITIGATION_FLAGS3_SPARE_SHIFT: u32 = 3;
    pub const MITIGATION_FLAGS3_SPARE_MASK: u32 = 0xfffffff8;
    #[inline(always)]
    pub fn mitigation_flags3_spare(&self) -> u32 {
        self.bitfield_0.bits(3, 29) as u32
    }
    #[inline(always)]
    pub fn set_mitigation_flags3_spare(&self, value: u32) {
        self.bitfield_0.set_bits(3, 29, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<EprocessMitigationFlags3Values>() == 0x4);
    assert!(core::mem::offset_of!(EprocessMitigationFlags3Values, bitfield_0) == 0x0);
};

/// `_EJOB` (0x640 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `EjobView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Ejob {
    pub event: Kevent,
    pub job_links: ListEntry,
    pub process_list_head: ListEntry,
    pub job_lock: Eresource,
    pub total_user_time: LargeInteger,
    pub total_kernel_time: LargeInteger,
    pub total_cycle_time: LargeInteger,
    pub this_period_total_user_time: LargeInteger,
    pub this_period_total_kernel_time: LargeInteger,
    pub total_context_switches: Field<u64>,
    pub total_page_fault_count: Field<u32>,
    pub total_processes: Field<u32>,
    pub active_processes: Field<u32>,
    pub total_terminated_processes: Field<u32>,
    pub per_process_user_time_limit: LargeInteger,
    pub per_job_user_time_limit: LargeInteger,
    pub minimum_working_set_size: Field<u64>,
    pub maximum_working_set_size: Field<u64>,
    pub limit_flags: Field<u32>,
    pub active_process_limit: Field<u32>,
    pub affinity: KaffinityEx,
    /// -> `_JOB_ACCESS_STATE`
    pub access_state: Field<u64>,
    /// -> `void`
    pub access_state_quota_reference: Field<u64>,
    pub ui_restrictions_class: Field<u32>,
    pub end_of_job_time_action: Field<u32>,
    /// -> `void`
    pub completion_port: Field<u64>,
    /// -> `void`
    pub completion_key: Field<u64>,
    pub completion_count: Field<u64>,
    pub session_id: Field<u32>,
    pub scheduling_class: Field<u32>,
    pub read_operation_count: Field<u64>,
    pub write_operation_count: Field<u64>,
    pub other_operation_count: Field<u64>,
    pub read_transfer_count: Field<u64>,
    pub write_transfer_count: Field<u64>,
    pub other_transfer_count: Field<u64>,
    pub disk_io_info: ProcessDiskCounters,
    pub process_memory_limit: Field<u64>,
    pub job_memory_limit: Field<u64>,
    pub job_total_memory_limit: Field<u64>,
    pub peak_process_memory_used: Field<u64>,
    pub peak_job_memory_used: Field<u64>,
    pub effective_affinity: KaffinityEx,
    pub effective_per_process_user_time_limit: LargeInteger,
    pub effective_minimum_working_set_size: Field<u64>,
    pub effective_maximum_working_set_size: Field<u64>,
    pub effective_process_memory_limit: Field<u64>,
    /// -> `_EJOB`
    pub effective_process_memory_limit_job: Field<u64>,
    /// -> `_EJOB`
    pub effective_per_process_user_time_limit_job: Field<u64>,
    /// -> `_EJOB`
    pub effective_net_io_rate_limit_job: Field<u64>,
    /// -> `_EJOB`
    pub effective_heap_attribution_job: Field<u64>,
    pub effective_limit_flags: Field<u32>,
    pub effective_scheduling_class: Field<u32>,
    pub effective_freeze_count: Field<u32>,
    pub effective_background_count: Field<u32>,
    pub effective_swap_count: Field<u32>,
    pub effective_notification_limit_count: Field<u32>,
    pub effective_priority_class: Field<u8>,
    pub priority_class: Field<u8>,
    pub nesting_depth: Field<u8>,
    pub reserved1: [Field<u8>; 1],
    pub completion_filter: Field<u32>,
    pub wake_channel: WnfStateName,
    _pad_378: Reserved<0x40>,
    pub wake_filter: JobobjectWakeFilter,
    pub low_edge_latch_filter: Field<u32>,
    _pad_3c4: Reserved<0x4>,
    /// -> `_EJOB`
    pub notification_link: Field<u64>,
    pub current_job_memory_used: Field<u64>,
    /// -> `_JOB_NOTIFICATION_INFORMATION`
    pub notification_info: Field<u64>,
    /// -> `void`
    pub notification_info_quota_reference: Field<u64>,
    /// -> `_IO_MINI_COMPLETION_PACKET_USER`
    pub notification_packet: Field<u64>,
    /// -> `_JOB_CPU_RATE_CONTROL`
    pub cpu_rate_control: Field<u64>,
    /// -> `void`
    pub effective_scheduling_group: Field<u64>,
    pub ready_time: Field<u64>,
    pub memory_limits_lock: ExPushLock,
    pub sibling_job_links: ListEntry,
    pub child_job_list_head: ListEntry,
    /// -> `_EJOB`
    pub parent_job: Field<u64>,
    /// -> `_EJOB`
    pub root_job: Field<u64>,
    pub iterator_list_head: ListEntry,
    pub ancestor_count: Field<u64>,
    /// -> `_EJOB*`
    pub ancestors: Field<u64>,
    pub accounting: EprocessValues,
    pub shadow_active_process_count: Field<u32>,
    pub active_auxiliary_process_count: Field<u32>,
    pub sequence_number: Field<u32>,
    pub job_id: Field<u32>,
    pub container_id: Guid,
    pub container_telemetry_id: Guid,
    /// -> `_ESERVERSILO_GLOBALS`
    pub server_silo_globals: Field<u64>,
    pub property_set: PsPropertySet,
    /// -> `_PSP_STORAGE`
    pub storage: Field<u64>,
    /// -> `_JOB_NET_RATE_CONTROL`
    pub net_rate_control: Field<u64>,
    pub job_flags: Field<u32>,
    pub job_flags2: Field<u32>,
    /// -> `_PROCESS_EXTENDED_ENERGY_VALUES`
    pub energy_values: Field<u64>,
    pub shared_commit_charge: Field<u64>,
    pub disk_io_attribution_user_ref_count: Field<u32>,
    pub disk_io_attribution_ref_count: Field<u32>,
    /// -> `void`
    pub disk_io_attribution_context: Field<u64>,
    pub io_rate_control_header: JobRateControlHeader,
    pub global_io_control: PsIoControlEntry,
    pub io_control_state_lock: Field<i32>,
    _pad_5b4: Reserved<0x4>,
    pub volume_io_control_tree: RtlRbTree,
    pub io_rate_over_quota_history: Field<u64>,
    pub io_rate_current_generation: Field<u32>,
    pub io_rate_last_query_generation: Field<u32>,
    pub io_rate_generation_length: Field<u32>,
    pub io_rate_over_quota_notify_sequence_id: Field<u32>,
    pub last_throttled_io_time: Field<u64>,
    pub io_control_lock: ExPushLock,
    pub silo_hard_reference_count: Field<i64>,
    pub rundown_work_item: WorkQueueItem,
    /// -> `void`
    pub partition_object: Field<u64>,
    /// -> `_EJOB`
    pub partition_owner_job: Field<u64>,
    pub energy_tracking_state: JobobjectEnergyTrackingState,
    pub kernel_wait_time: Field<u64>,
    pub user_wait_time: Field<u64>,
}

/// Vista 1 de `_EJOB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct EjobView1 {
    _pad_0: Reserved<0x370>,
    pub wake_info: PsJobWakeInformation,
    _pad_3b8: Reserved<0xa0>,
    /// -> `void`
    pub session_object: Field<u64>,
    _pad_460: Reserved<0xe8>,
    /// -> `_EJOB`
    pub disk_io_attribution_owner_job: Field<u64>,
    _pad_550: Reserved<0xf0>,
}

impl core::ops::Deref for Ejob {
    type Target = EjobView1;
    #[inline(always)]
    fn deref(&self) -> &EjobView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<EjobView1>() }
    }
}

unsafe impl NtStruct for Ejob {}

impl Ejob {
    /// `CloseDone`: bits 0..=0 de `job_flags`.
    pub const CLOSE_DONE_SHIFT: u32 = 0;
    pub const CLOSE_DONE_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn close_done(&self) -> u32 {
        self.job_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_close_done(&self, value: u32) {
        self.job_flags.set_bits(0, 1, value as u64)
    }
    /// `MultiGroup`: bits 1..=1 de `job_flags`.
    pub const MULTI_GROUP_SHIFT: u32 = 1;
    pub const MULTI_GROUP_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn multi_group(&self) -> u32 {
        self.job_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_multi_group(&self, value: u32) {
        self.job_flags.set_bits(1, 1, value as u64)
    }
    /// `OutstandingNotification`: bits 2..=2 de `job_flags`.
    pub const OUTSTANDING_NOTIFICATION_SHIFT: u32 = 2;
    pub const OUTSTANDING_NOTIFICATION_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn outstanding_notification(&self) -> u32 {
        self.job_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_outstanding_notification(&self, value: u32) {
        self.job_flags.set_bits(2, 1, value as u64)
    }
    /// `NotificationInProgress`: bits 3..=3 de `job_flags`.
    pub const NOTIFICATION_IN_PROGRESS_SHIFT: u32 = 3;
    pub const NOTIFICATION_IN_PROGRESS_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn notification_in_progress(&self) -> u32 {
        self.job_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_notification_in_progress(&self, value: u32) {
        self.job_flags.set_bits(3, 1, value as u64)
    }
    /// `UILimits`: bits 4..=4 de `job_flags`.
    pub const UI_LIMITS_SHIFT: u32 = 4;
    pub const UI_LIMITS_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn ui_limits(&self) -> u32 {
        self.job_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_ui_limits(&self, value: u32) {
        self.job_flags.set_bits(4, 1, value as u64)
    }
    /// `CpuRateControlActive`: bits 5..=5 de `job_flags`.
    pub const CPU_RATE_CONTROL_ACTIVE_SHIFT: u32 = 5;
    pub const CPU_RATE_CONTROL_ACTIVE_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn cpu_rate_control_active(&self) -> u32 {
        self.job_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_cpu_rate_control_active(&self, value: u32) {
        self.job_flags.set_bits(5, 1, value as u64)
    }
    /// `OwnCpuRateControl`: bits 6..=6 de `job_flags`.
    pub const OWN_CPU_RATE_CONTROL_SHIFT: u32 = 6;
    pub const OWN_CPU_RATE_CONTROL_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn own_cpu_rate_control(&self) -> u32 {
        self.job_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_own_cpu_rate_control(&self, value: u32) {
        self.job_flags.set_bits(6, 1, value as u64)
    }
    /// `Terminating`: bits 7..=7 de `job_flags`.
    pub const TERMINATING_SHIFT: u32 = 7;
    pub const TERMINATING_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn terminating(&self) -> u32 {
        self.job_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_terminating(&self, value: u32) {
        self.job_flags.set_bits(7, 1, value as u64)
    }
    /// `WorkingSetLock`: bits 8..=8 de `job_flags`.
    pub const WORKING_SET_LOCK_SHIFT: u32 = 8;
    pub const WORKING_SET_LOCK_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn working_set_lock(&self) -> u32 {
        self.job_flags.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_working_set_lock(&self, value: u32) {
        self.job_flags.set_bits(8, 1, value as u64)
    }
    /// `JobFrozen`: bits 9..=9 de `job_flags`.
    pub const JOB_FROZEN_SHIFT: u32 = 9;
    pub const JOB_FROZEN_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn job_frozen(&self) -> u32 {
        self.job_flags.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_job_frozen(&self, value: u32) {
        self.job_flags.set_bits(9, 1, value as u64)
    }
    /// `Background`: bits 10..=10 de `job_flags`.
    pub const BACKGROUND_SHIFT: u32 = 10;
    pub const BACKGROUND_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn background(&self) -> u32 {
        self.job_flags.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_background(&self, value: u32) {
        self.job_flags.set_bits(10, 1, value as u64)
    }
    /// `WakeNotificationAllocated`: bits 11..=11 de `job_flags`.
    pub const WAKE_NOTIFICATION_ALLOCATED_SHIFT: u32 = 11;
    pub const WAKE_NOTIFICATION_ALLOCATED_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn wake_notification_allocated(&self) -> u32 {
        self.job_flags.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_notification_allocated(&self, value: u32) {
        self.job_flags.set_bits(11, 1, value as u64)
    }
    /// `WakeNotificationEnabled`: bits 12..=12 de `job_flags`.
    pub const WAKE_NOTIFICATION_ENABLED_SHIFT: u32 = 12;
    pub const WAKE_NOTIFICATION_ENABLED_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn wake_notification_enabled(&self) -> u32 {
        self.job_flags.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_notification_enabled(&self, value: u32) {
        self.job_flags.set_bits(12, 1, value as u64)
    }
    /// `WakeNotificationPending`: bits 13..=13 de `job_flags`.
    pub const WAKE_NOTIFICATION_PENDING_SHIFT: u32 = 13;
    pub const WAKE_NOTIFICATION_PENDING_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn wake_notification_pending(&self) -> u32 {
        self.job_flags.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_wake_notification_pending(&self, value: u32) {
        self.job_flags.set_bits(13, 1, value as u64)
    }
    /// `LimitNotificationRequired`: bits 14..=14 de `job_flags`.
    pub const LIMIT_NOTIFICATION_REQUIRED_SHIFT: u32 = 14;
    pub const LIMIT_NOTIFICATION_REQUIRED_MASK: u32 = 0x4000;
    #[inline(always)]
    pub fn limit_notification_required(&self) -> u32 {
        self.job_flags.bits(14, 1) as u32
    }
    #[inline(always)]
    pub fn set_limit_notification_required(&self, value: u32) {
        self.job_flags.set_bits(14, 1, value as u64)
    }
    /// `ZeroCountNotificationRequired`: bits 15..=15 de `job_flags`.
    pub const ZERO_COUNT_NOTIFICATION_REQUIRED_SHIFT: u32 = 15;
    pub const ZERO_COUNT_NOTIFICATION_REQUIRED_MASK: u32 = 0x8000;
    #[inline(always)]
    pub fn zero_count_notification_required(&self) -> u32 {
        self.job_flags.bits(15, 1) as u32
    }
    #[inline(always)]
    pub fn set_zero_count_notification_required(&self, value: u32) {
        self.job_flags.set_bits(15, 1, value as u64)
    }
    /// `CycleTimeNotificationRequired`: bits 16..=16 de `job_flags`.
    pub const CYCLE_TIME_NOTIFICATION_REQUIRED_SHIFT: u32 = 16;
    pub const CYCLE_TIME_NOTIFICATION_REQUIRED_MASK: u32 = 0x10000;
    #[inline(always)]
    pub fn cycle_time_notification_required(&self) -> u32 {
        self.job_flags.bits(16, 1) as u32
    }
    #[inline(always)]
    pub fn set_cycle_time_notification_required(&self, value: u32) {
        self.job_flags.set_bits(16, 1, value as u64)
    }
    /// `CycleTimeNotificationPending`: bits 17..=17 de `job_flags`.
    pub const CYCLE_TIME_NOTIFICATION_PENDING_SHIFT: u32 = 17;
    pub const CYCLE_TIME_NOTIFICATION_PENDING_MASK: u32 = 0x20000;
    #[inline(always)]
    pub fn cycle_time_notification_pending(&self) -> u32 {
        self.job_flags.bits(17, 1) as u32
    }
    #[inline(always)]
    pub fn set_cycle_time_notification_pending(&self, value: u32) {
        self.job_flags.set_bits(17, 1, value as u64)
    }
    /// `TimersVirtualized`: bits 18..=18 de `job_flags`.
    pub const TIMERS_VIRTUALIZED_SHIFT: u32 = 18;
    pub const TIMERS_VIRTUALIZED_MASK: u32 = 0x40000;
    #[inline(always)]
    pub fn timers_virtualized(&self) -> u32 {
        self.job_flags.bits(18, 1) as u32
    }
    #[inline(always)]
    pub fn set_timers_virtualized(&self, value: u32) {
        self.job_flags.set_bits(18, 1, value as u64)
    }
    /// `JobSwapped`: bits 19..=19 de `job_flags`.
    pub const JOB_SWAPPED_SHIFT: u32 = 19;
    pub const JOB_SWAPPED_MASK: u32 = 0x80000;
    #[inline(always)]
    pub fn job_swapped(&self) -> u32 {
        self.job_flags.bits(19, 1) as u32
    }
    #[inline(always)]
    pub fn set_job_swapped(&self, value: u32) {
        self.job_flags.set_bits(19, 1, value as u64)
    }
    /// `ViolationDetected`: bits 20..=20 de `job_flags`.
    pub const VIOLATION_DETECTED_SHIFT: u32 = 20;
    pub const VIOLATION_DETECTED_MASK: u32 = 0x100000;
    #[inline(always)]
    pub fn violation_detected(&self) -> u32 {
        self.job_flags.bits(20, 1) as u32
    }
    #[inline(always)]
    pub fn set_violation_detected(&self, value: u32) {
        self.job_flags.set_bits(20, 1, value as u64)
    }
    /// `EmptyJobNotified`: bits 21..=21 de `job_flags`.
    pub const EMPTY_JOB_NOTIFIED_SHIFT: u32 = 21;
    pub const EMPTY_JOB_NOTIFIED_MASK: u32 = 0x200000;
    #[inline(always)]
    pub fn empty_job_notified(&self) -> u32 {
        self.job_flags.bits(21, 1) as u32
    }
    #[inline(always)]
    pub fn set_empty_job_notified(&self, value: u32) {
        self.job_flags.set_bits(21, 1, value as u64)
    }
    /// `NoSystemCharge`: bits 22..=22 de `job_flags`.
    pub const NO_SYSTEM_CHARGE_SHIFT: u32 = 22;
    pub const NO_SYSTEM_CHARGE_MASK: u32 = 0x400000;
    #[inline(always)]
    pub fn no_system_charge(&self) -> u32 {
        self.job_flags.bits(22, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_system_charge(&self, value: u32) {
        self.job_flags.set_bits(22, 1, value as u64)
    }
    /// `DropNoWakeCharges`: bits 23..=23 de `job_flags`.
    pub const DROP_NO_WAKE_CHARGES_SHIFT: u32 = 23;
    pub const DROP_NO_WAKE_CHARGES_MASK: u32 = 0x800000;
    #[inline(always)]
    pub fn drop_no_wake_charges(&self) -> u32 {
        self.job_flags.bits(23, 1) as u32
    }
    #[inline(always)]
    pub fn set_drop_no_wake_charges(&self, value: u32) {
        self.job_flags.set_bits(23, 1, value as u64)
    }
    /// `NoWakeChargePolicyDecided`: bits 24..=24 de `job_flags`.
    pub const NO_WAKE_CHARGE_POLICY_DECIDED_SHIFT: u32 = 24;
    pub const NO_WAKE_CHARGE_POLICY_DECIDED_MASK: u32 = 0x1000000;
    #[inline(always)]
    pub fn no_wake_charge_policy_decided(&self) -> u32 {
        self.job_flags.bits(24, 1) as u32
    }
    #[inline(always)]
    pub fn set_no_wake_charge_policy_decided(&self, value: u32) {
        self.job_flags.set_bits(24, 1, value as u64)
    }
    /// `NetRateControlActive`: bits 25..=25 de `job_flags`.
    pub const NET_RATE_CONTROL_ACTIVE_SHIFT: u32 = 25;
    pub const NET_RATE_CONTROL_ACTIVE_MASK: u32 = 0x2000000;
    #[inline(always)]
    pub fn net_rate_control_active(&self) -> u32 {
        self.job_flags.bits(25, 1) as u32
    }
    #[inline(always)]
    pub fn set_net_rate_control_active(&self, value: u32) {
        self.job_flags.set_bits(25, 1, value as u64)
    }
    /// `OwnNetRateControl`: bits 26..=26 de `job_flags`.
    pub const OWN_NET_RATE_CONTROL_SHIFT: u32 = 26;
    pub const OWN_NET_RATE_CONTROL_MASK: u32 = 0x4000000;
    #[inline(always)]
    pub fn own_net_rate_control(&self) -> u32 {
        self.job_flags.bits(26, 1) as u32
    }
    #[inline(always)]
    pub fn set_own_net_rate_control(&self, value: u32) {
        self.job_flags.set_bits(26, 1, value as u64)
    }
    /// `IoRateControlActive`: bits 27..=27 de `job_flags`.
    pub const IO_RATE_CONTROL_ACTIVE_SHIFT: u32 = 27;
    pub const IO_RATE_CONTROL_ACTIVE_MASK: u32 = 0x8000000;
    #[inline(always)]
    pub fn io_rate_control_active(&self) -> u32 {
        self.job_flags.bits(27, 1) as u32
    }
    #[inline(always)]
    pub fn set_io_rate_control_active(&self, value: u32) {
        self.job_flags.set_bits(27, 1, value as u64)
    }
    /// `OwnIoRateControl`: bits 28..=28 de `job_flags`.
    pub const OWN_IO_RATE_CONTROL_SHIFT: u32 = 28;
    pub const OWN_IO_RATE_CONTROL_MASK: u32 = 0x10000000;
    #[inline(always)]
    pub fn own_io_rate_control(&self) -> u32 {
        self.job_flags.bits(28, 1) as u32
    }
    #[inline(always)]
    pub fn set_own_io_rate_control(&self, value: u32) {
        self.job_flags.set_bits(28, 1, value as u64)
    }
    /// `DisallowNewProcesses`: bits 29..=29 de `job_flags`.
    pub const DISALLOW_NEW_PROCESSES_SHIFT: u32 = 29;
    pub const DISALLOW_NEW_PROCESSES_MASK: u32 = 0x20000000;
    #[inline(always)]
    pub fn disallow_new_processes(&self) -> u32 {
        self.job_flags.bits(29, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_new_processes(&self, value: u32) {
        self.job_flags.set_bits(29, 1, value as u64)
    }
    /// `Silo`: bits 30..=30 de `job_flags`.
    pub const SILO_SHIFT: u32 = 30;
    pub const SILO_MASK: u32 = 0x40000000;
    #[inline(always)]
    pub fn silo(&self) -> u32 {
        self.job_flags.bits(30, 1) as u32
    }
    #[inline(always)]
    pub fn set_silo(&self, value: u32) {
        self.job_flags.set_bits(30, 1, value as u64)
    }
    /// `ContainerTelemetryIdSet`: bits 31..=31 de `job_flags`.
    pub const CONTAINER_TELEMETRY_ID_SET_SHIFT: u32 = 31;
    pub const CONTAINER_TELEMETRY_ID_SET_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn container_telemetry_id_set(&self) -> u32 {
        self.job_flags.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_container_telemetry_id_set(&self, value: u32) {
        self.job_flags.set_bits(31, 1, value as u64)
    }
    /// `ParentLocked`: bits 0..=0 de `job_flags2`.
    pub const PARENT_LOCKED_SHIFT: u32 = 0;
    pub const PARENT_LOCKED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn parent_locked(&self) -> u32 {
        self.job_flags2.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_parent_locked(&self, value: u32) {
        self.job_flags2.set_bits(0, 1, value as u64)
    }
    /// `EnableUsermodeSiloThreadImpersonation`: bits 1..=1 de `job_flags2`.
    pub const ENABLE_USERMODE_SILO_THREAD_IMPERSONATION_SHIFT: u32 = 1;
    pub const ENABLE_USERMODE_SILO_THREAD_IMPERSONATION_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn enable_usermode_silo_thread_impersonation(&self) -> u32 {
        self.job_flags2.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_enable_usermode_silo_thread_impersonation(&self, value: u32) {
        self.job_flags2.set_bits(1, 1, value as u64)
    }
    /// `DisallowUsermodeSiloThreadImpersonation`: bits 2..=2 de `job_flags2`.
    pub const DISALLOW_USERMODE_SILO_THREAD_IMPERSONATION_SHIFT: u32 = 2;
    pub const DISALLOW_USERMODE_SILO_THREAD_IMPERSONATION_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn disallow_usermode_silo_thread_impersonation(&self) -> u32 {
        self.job_flags2.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_disallow_usermode_silo_thread_impersonation(&self, value: u32) {
        self.job_flags2.set_bits(2, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Ejob>() == 0x640);
    assert!(core::mem::offset_of!(Ejob, event) == 0x0);
    assert!(core::mem::offset_of!(Ejob, job_links) == 0x18);
    assert!(core::mem::offset_of!(Ejob, process_list_head) == 0x28);
    assert!(core::mem::offset_of!(Ejob, job_lock) == 0x38);
    assert!(core::mem::offset_of!(Ejob, total_user_time) == 0xa0);
    assert!(core::mem::offset_of!(Ejob, total_kernel_time) == 0xa8);
    assert!(core::mem::offset_of!(Ejob, total_cycle_time) == 0xb0);
    assert!(core::mem::offset_of!(Ejob, this_period_total_user_time) == 0xb8);
    assert!(core::mem::offset_of!(Ejob, this_period_total_kernel_time) == 0xc0);
    assert!(core::mem::offset_of!(Ejob, total_context_switches) == 0xc8);
    assert!(core::mem::offset_of!(Ejob, total_page_fault_count) == 0xd0);
    assert!(core::mem::offset_of!(Ejob, total_processes) == 0xd4);
    assert!(core::mem::offset_of!(Ejob, active_processes) == 0xd8);
    assert!(core::mem::offset_of!(Ejob, total_terminated_processes) == 0xdc);
    assert!(core::mem::offset_of!(Ejob, per_process_user_time_limit) == 0xe0);
    assert!(core::mem::offset_of!(Ejob, per_job_user_time_limit) == 0xe8);
    assert!(core::mem::offset_of!(Ejob, minimum_working_set_size) == 0xf0);
    assert!(core::mem::offset_of!(Ejob, maximum_working_set_size) == 0xf8);
    assert!(core::mem::offset_of!(Ejob, limit_flags) == 0x100);
    assert!(core::mem::offset_of!(Ejob, active_process_limit) == 0x104);
    assert!(core::mem::offset_of!(Ejob, affinity) == 0x108);
    assert!(core::mem::offset_of!(Ejob, access_state) == 0x1b0);
    assert!(core::mem::offset_of!(Ejob, access_state_quota_reference) == 0x1b8);
    assert!(core::mem::offset_of!(Ejob, ui_restrictions_class) == 0x1c0);
    assert!(core::mem::offset_of!(Ejob, end_of_job_time_action) == 0x1c4);
    assert!(core::mem::offset_of!(Ejob, completion_port) == 0x1c8);
    assert!(core::mem::offset_of!(Ejob, completion_key) == 0x1d0);
    assert!(core::mem::offset_of!(Ejob, completion_count) == 0x1d8);
    assert!(core::mem::offset_of!(Ejob, session_id) == 0x1e0);
    assert!(core::mem::offset_of!(Ejob, scheduling_class) == 0x1e4);
    assert!(core::mem::offset_of!(Ejob, read_operation_count) == 0x1e8);
    assert!(core::mem::offset_of!(Ejob, write_operation_count) == 0x1f0);
    assert!(core::mem::offset_of!(Ejob, other_operation_count) == 0x1f8);
    assert!(core::mem::offset_of!(Ejob, read_transfer_count) == 0x200);
    assert!(core::mem::offset_of!(Ejob, write_transfer_count) == 0x208);
    assert!(core::mem::offset_of!(Ejob, other_transfer_count) == 0x210);
    assert!(core::mem::offset_of!(Ejob, disk_io_info) == 0x218);
    assert!(core::mem::offset_of!(Ejob, process_memory_limit) == 0x240);
    assert!(core::mem::offset_of!(Ejob, job_memory_limit) == 0x248);
    assert!(core::mem::offset_of!(Ejob, job_total_memory_limit) == 0x250);
    assert!(core::mem::offset_of!(Ejob, peak_process_memory_used) == 0x258);
    assert!(core::mem::offset_of!(Ejob, peak_job_memory_used) == 0x260);
    assert!(core::mem::offset_of!(Ejob, effective_affinity) == 0x268);
    assert!(core::mem::offset_of!(Ejob, effective_per_process_user_time_limit) == 0x310);
    assert!(core::mem::offset_of!(Ejob, effective_minimum_working_set_size) == 0x318);
    assert!(core::mem::offset_of!(Ejob, effective_maximum_working_set_size) == 0x320);
    assert!(core::mem::offset_of!(Ejob, effective_process_memory_limit) == 0x328);
    assert!(core::mem::offset_of!(Ejob, effective_process_memory_limit_job) == 0x330);
    assert!(core::mem::offset_of!(Ejob, effective_per_process_user_time_limit_job) == 0x338);
    assert!(core::mem::offset_of!(Ejob, effective_net_io_rate_limit_job) == 0x340);
    assert!(core::mem::offset_of!(Ejob, effective_heap_attribution_job) == 0x348);
    assert!(core::mem::offset_of!(Ejob, effective_limit_flags) == 0x350);
    assert!(core::mem::offset_of!(Ejob, effective_scheduling_class) == 0x354);
    assert!(core::mem::offset_of!(Ejob, effective_freeze_count) == 0x358);
    assert!(core::mem::offset_of!(Ejob, effective_background_count) == 0x35c);
    assert!(core::mem::offset_of!(Ejob, effective_swap_count) == 0x360);
    assert!(core::mem::offset_of!(Ejob, effective_notification_limit_count) == 0x364);
    assert!(core::mem::offset_of!(Ejob, effective_priority_class) == 0x368);
    assert!(core::mem::offset_of!(Ejob, priority_class) == 0x369);
    assert!(core::mem::offset_of!(Ejob, nesting_depth) == 0x36a);
    assert!(core::mem::offset_of!(Ejob, reserved1) == 0x36b);
    assert!(core::mem::offset_of!(Ejob, completion_filter) == 0x36c);
    assert!(core::mem::offset_of!(Ejob, wake_channel) == 0x370);
    assert!(core::mem::offset_of!(Ejob, wake_filter) == 0x3b8);
    assert!(core::mem::offset_of!(Ejob, low_edge_latch_filter) == 0x3c0);
    assert!(core::mem::offset_of!(Ejob, notification_link) == 0x3c8);
    assert!(core::mem::offset_of!(Ejob, current_job_memory_used) == 0x3d0);
    assert!(core::mem::offset_of!(Ejob, notification_info) == 0x3d8);
    assert!(core::mem::offset_of!(Ejob, notification_info_quota_reference) == 0x3e0);
    assert!(core::mem::offset_of!(Ejob, notification_packet) == 0x3e8);
    assert!(core::mem::offset_of!(Ejob, cpu_rate_control) == 0x3f0);
    assert!(core::mem::offset_of!(Ejob, effective_scheduling_group) == 0x3f8);
    assert!(core::mem::offset_of!(Ejob, ready_time) == 0x400);
    assert!(core::mem::offset_of!(Ejob, memory_limits_lock) == 0x408);
    assert!(core::mem::offset_of!(Ejob, sibling_job_links) == 0x410);
    assert!(core::mem::offset_of!(Ejob, child_job_list_head) == 0x420);
    assert!(core::mem::offset_of!(Ejob, parent_job) == 0x430);
    assert!(core::mem::offset_of!(Ejob, root_job) == 0x438);
    assert!(core::mem::offset_of!(Ejob, iterator_list_head) == 0x440);
    assert!(core::mem::offset_of!(Ejob, ancestor_count) == 0x450);
    assert!(core::mem::offset_of!(Ejob, ancestors) == 0x458);
    assert!(core::mem::offset_of!(Ejob, accounting) == 0x460);
    assert!(core::mem::offset_of!(Ejob, shadow_active_process_count) == 0x4c8);
    assert!(core::mem::offset_of!(Ejob, active_auxiliary_process_count) == 0x4cc);
    assert!(core::mem::offset_of!(Ejob, sequence_number) == 0x4d0);
    assert!(core::mem::offset_of!(Ejob, job_id) == 0x4d4);
    assert!(core::mem::offset_of!(Ejob, container_id) == 0x4d8);
    assert!(core::mem::offset_of!(Ejob, container_telemetry_id) == 0x4e8);
    assert!(core::mem::offset_of!(Ejob, server_silo_globals) == 0x4f8);
    assert!(core::mem::offset_of!(Ejob, property_set) == 0x500);
    assert!(core::mem::offset_of!(Ejob, storage) == 0x518);
    assert!(core::mem::offset_of!(Ejob, net_rate_control) == 0x520);
    assert!(core::mem::offset_of!(Ejob, job_flags) == 0x528);
    assert!(core::mem::offset_of!(Ejob, job_flags2) == 0x52c);
    assert!(core::mem::offset_of!(Ejob, energy_values) == 0x530);
    assert!(core::mem::offset_of!(Ejob, shared_commit_charge) == 0x538);
    assert!(core::mem::offset_of!(Ejob, disk_io_attribution_user_ref_count) == 0x540);
    assert!(core::mem::offset_of!(Ejob, disk_io_attribution_ref_count) == 0x544);
    assert!(core::mem::offset_of!(Ejob, disk_io_attribution_context) == 0x548);
    assert!(core::mem::offset_of!(Ejob, io_rate_control_header) == 0x550);
    assert!(core::mem::offset_of!(Ejob, global_io_control) == 0x578);
    assert!(core::mem::offset_of!(Ejob, io_control_state_lock) == 0x5b0);
    assert!(core::mem::offset_of!(Ejob, volume_io_control_tree) == 0x5b8);
    assert!(core::mem::offset_of!(Ejob, io_rate_over_quota_history) == 0x5c8);
    assert!(core::mem::offset_of!(Ejob, io_rate_current_generation) == 0x5d0);
    assert!(core::mem::offset_of!(Ejob, io_rate_last_query_generation) == 0x5d4);
    assert!(core::mem::offset_of!(Ejob, io_rate_generation_length) == 0x5d8);
    assert!(core::mem::offset_of!(Ejob, io_rate_over_quota_notify_sequence_id) == 0x5dc);
    assert!(core::mem::offset_of!(Ejob, last_throttled_io_time) == 0x5e0);
    assert!(core::mem::offset_of!(Ejob, io_control_lock) == 0x5e8);
    assert!(core::mem::offset_of!(Ejob, silo_hard_reference_count) == 0x5f0);
    assert!(core::mem::offset_of!(Ejob, rundown_work_item) == 0x5f8);
    assert!(core::mem::offset_of!(Ejob, partition_object) == 0x618);
    assert!(core::mem::offset_of!(Ejob, partition_owner_job) == 0x620);
    assert!(core::mem::offset_of!(Ejob, energy_tracking_state) == 0x628);
    assert!(core::mem::offset_of!(Ejob, kernel_wait_time) == 0x630);
    assert!(core::mem::offset_of!(Ejob, user_wait_time) == 0x638);
    assert!(core::mem::size_of::<EjobView1>() == 0x640);
    assert!(core::mem::align_of::<EjobView1>() == core::mem::align_of::<Ejob>());
    assert!(core::mem::offset_of!(EjobView1, wake_info) == 0x370);
    assert!(core::mem::offset_of!(EjobView1, session_object) == 0x458);
    assert!(core::mem::offset_of!(EjobView1, disk_io_attribution_owner_job) == 0x548);
};

/// `_PROCESS_DISK_COUNTERS` (0x28 bytes).
#[repr(C)]
pub struct ProcessDiskCounters {
    pub bytes_read: Field<u64>,
    pub bytes_written: Field<u64>,
    pub read_operation_count: Field<u64>,
    pub write_operation_count: Field<u64>,
    pub flush_operation_count: Field<u64>,
}

unsafe impl NtStruct for ProcessDiskCounters {}

const _: () = {
    assert!(core::mem::size_of::<ProcessDiskCounters>() == 0x28);
    assert!(core::mem::offset_of!(ProcessDiskCounters, bytes_read) == 0x0);
    assert!(core::mem::offset_of!(ProcessDiskCounters, bytes_written) == 0x8);
    assert!(core::mem::offset_of!(ProcessDiskCounters, read_operation_count) == 0x10);
    assert!(core::mem::offset_of!(ProcessDiskCounters, write_operation_count) == 0x18);
    assert!(core::mem::offset_of!(ProcessDiskCounters, flush_operation_count) == 0x20);
};

/// `_PS_JOB_WAKE_INFORMATION` (0x48 bytes).
#[repr(C)]
pub struct PsJobWakeInformation {
    pub notification_channel: Field<u64>,
    pub wake_counters: [Field<u64>; 7],
    pub no_wake_counter: Field<u64>,
}

unsafe impl NtStruct for PsJobWakeInformation {}

const _: () = {
    assert!(core::mem::size_of::<PsJobWakeInformation>() == 0x48);
    assert!(core::mem::offset_of!(PsJobWakeInformation, notification_channel) == 0x0);
    assert!(core::mem::offset_of!(PsJobWakeInformation, wake_counters) == 0x8);
    assert!(core::mem::offset_of!(PsJobWakeInformation, no_wake_counter) == 0x40);
};

/// `_EPROCESS_VALUES` (0x68 bytes).
#[repr(C)]
pub struct EprocessValues {
    pub kernel_time: Field<u64>,
    pub user_time: Field<u64>,
    pub ready_time: Field<u64>,
    pub cycle_time: Field<u64>,
    pub context_switches: Field<u64>,
    pub read_operation_count: Field<i64>,
    pub write_operation_count: Field<i64>,
    pub other_operation_count: Field<i64>,
    pub read_transfer_count: Field<i64>,
    pub write_transfer_count: Field<i64>,
    pub other_transfer_count: Field<i64>,
    pub kernel_wait_time: Field<u64>,
    pub user_wait_time: Field<u64>,
}

unsafe impl NtStruct for EprocessValues {}

const _: () = {
    assert!(core::mem::size_of::<EprocessValues>() == 0x68);
    assert!(core::mem::offset_of!(EprocessValues, kernel_time) == 0x0);
    assert!(core::mem::offset_of!(EprocessValues, user_time) == 0x8);
    assert!(core::mem::offset_of!(EprocessValues, ready_time) == 0x10);
    assert!(core::mem::offset_of!(EprocessValues, cycle_time) == 0x18);
    assert!(core::mem::offset_of!(EprocessValues, context_switches) == 0x20);
    assert!(core::mem::offset_of!(EprocessValues, read_operation_count) == 0x28);
    assert!(core::mem::offset_of!(EprocessValues, write_operation_count) == 0x30);
    assert!(core::mem::offset_of!(EprocessValues, other_operation_count) == 0x38);
    assert!(core::mem::offset_of!(EprocessValues, read_transfer_count) == 0x40);
    assert!(core::mem::offset_of!(EprocessValues, write_transfer_count) == 0x48);
    assert!(core::mem::offset_of!(EprocessValues, other_transfer_count) == 0x50);
    assert!(core::mem::offset_of!(EprocessValues, kernel_wait_time) == 0x58);
    assert!(core::mem::offset_of!(EprocessValues, user_wait_time) == 0x60);
};

/// `_JOB_RATE_CONTROL_HEADER` (0x28 bytes).
#[repr(C)]
pub struct JobRateControlHeader {
    /// -> `void`
    pub rate_control_quota_reference: Field<u64>,
    pub over_quota_history: RtlBitmap,
    /// -> `u8`
    pub bit_map_buffer: Field<u64>,
    pub bit_map_buffer_size: Field<u64>,
}

unsafe impl NtStruct for JobRateControlHeader {}

const _: () = {
    assert!(core::mem::size_of::<JobRateControlHeader>() == 0x28);
    assert!(core::mem::offset_of!(JobRateControlHeader, rate_control_quota_reference) == 0x0);
    assert!(core::mem::offset_of!(JobRateControlHeader, over_quota_history) == 0x8);
    assert!(core::mem::offset_of!(JobRateControlHeader, bit_map_buffer) == 0x18);
    assert!(core::mem::offset_of!(JobRateControlHeader, bit_map_buffer_size) == 0x20);
};

/// `_PS_IO_CONTROL_ENTRY` (0x38 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PsIoControlEntryView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PsIoControlEntry {
    pub volume_tree_node: RtlBalancedNode,
    pub volume_key: Field<u64>,
    pub rundown: ExRundownRef,
    /// -> `void`
    pub io_control: Field<u64>,
    /// -> `void`
    pub volume_io_attribution: Field<u64>,
}

/// Vista 1 de `_PS_IO_CONTROL_ENTRY` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PsIoControlEntryView1 {
    pub free_list_entry: ListEntry,
    pub reserved_for_parent_value: Field<u64>,
    _pad_18: Reserved<0x20>,
}

impl core::ops::Deref for PsIoControlEntry {
    type Target = PsIoControlEntryView1;
    #[inline(always)]
    fn deref(&self) -> &PsIoControlEntryView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PsIoControlEntryView1>() }
    }
}

unsafe impl NtStruct for PsIoControlEntry {}

const _: () = {
    assert!(core::mem::size_of::<PsIoControlEntry>() == 0x38);
    assert!(core::mem::offset_of!(PsIoControlEntry, volume_tree_node) == 0x0);
    assert!(core::mem::offset_of!(PsIoControlEntry, volume_key) == 0x18);
    assert!(core::mem::offset_of!(PsIoControlEntry, rundown) == 0x20);
    assert!(core::mem::offset_of!(PsIoControlEntry, io_control) == 0x28);
    assert!(core::mem::offset_of!(PsIoControlEntry, volume_io_attribution) == 0x30);
    assert!(core::mem::size_of::<PsIoControlEntryView1>() == 0x38);
    assert!(core::mem::align_of::<PsIoControlEntryView1>() == core::mem::align_of::<PsIoControlEntry>());
    assert!(core::mem::offset_of!(PsIoControlEntryView1, free_list_entry) == 0x0);
    assert!(core::mem::offset_of!(PsIoControlEntryView1, reserved_for_parent_value) == 0x10);
};

/// `_JOBOBJECT_ENERGY_TRACKING_STATE` (0x8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `JobobjectEnergyTrackingStateView1`, alcançada por `Deref`.
#[repr(C)]
pub struct JobobjectEnergyTrackingState {
    pub value: Field<u64>,
}

/// Vista 1 de `_JOBOBJECT_ENERGY_TRACKING_STATE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct JobobjectEnergyTrackingStateView1 {
    _align: [u64; 0],
    pub update_mask: Field<u32>,
    pub desired_state: Field<u32>,
}

impl core::ops::Deref for JobobjectEnergyTrackingState {
    type Target = JobobjectEnergyTrackingStateView1;
    #[inline(always)]
    fn deref(&self) -> &JobobjectEnergyTrackingStateView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<JobobjectEnergyTrackingStateView1>() }
    }
}

unsafe impl NtStruct for JobobjectEnergyTrackingState {}

const _: () = {
    assert!(core::mem::size_of::<JobobjectEnergyTrackingState>() == 0x8);
    assert!(core::mem::offset_of!(JobobjectEnergyTrackingState, value) == 0x0);
    assert!(core::mem::size_of::<JobobjectEnergyTrackingStateView1>() == 0x8);
    assert!(core::mem::align_of::<JobobjectEnergyTrackingStateView1>() == core::mem::align_of::<JobobjectEnergyTrackingState>());
    assert!(core::mem::offset_of!(JobobjectEnergyTrackingStateView1, update_mask) == 0x0);
    assert!(core::mem::offset_of!(JobobjectEnergyTrackingStateView1, desired_state) == 0x4);
};

/// `_PEB_LDR_DATA` (0x58 bytes).
#[repr(C)]
pub struct PebLdrData {
    pub length: Field<u32>,
    pub initialized: Field<u8>,
    _pad_5: Reserved<0x3>,
    /// -> `void`
    pub ss_handle: Field<u64>,
    pub in_load_order_module_list: ListEntry,
    pub in_memory_order_module_list: ListEntry,
    pub in_initialization_order_module_list: ListEntry,
    /// -> `void`
    pub entry_in_progress: Field<u64>,
    pub shutdown_in_progress: Field<u8>,
    _pad_49: Reserved<0x7>,
    /// -> `void`
    pub shutdown_thread_id: Field<u64>,
}

unsafe impl NtStruct for PebLdrData {}

const _: () = {
    assert!(core::mem::size_of::<PebLdrData>() == 0x58);
    assert!(core::mem::offset_of!(PebLdrData, length) == 0x0);
    assert!(core::mem::offset_of!(PebLdrData, initialized) == 0x4);
    assert!(core::mem::offset_of!(PebLdrData, ss_handle) == 0x8);
    assert!(core::mem::offset_of!(PebLdrData, in_load_order_module_list) == 0x10);
    assert!(core::mem::offset_of!(PebLdrData, in_memory_order_module_list) == 0x20);
    assert!(core::mem::offset_of!(PebLdrData, in_initialization_order_module_list) == 0x30);
    assert!(core::mem::offset_of!(PebLdrData, entry_in_progress) == 0x40);
    assert!(core::mem::offset_of!(PebLdrData, shutdown_in_progress) == 0x48);
    assert!(core::mem::offset_of!(PebLdrData, shutdown_thread_id) == 0x50);
};

/// `_PEB` (0x7c8 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PebView1`, alcançada por `Deref`.
#[repr(C)]
pub struct Peb {
    pub inherited_address_space: Field<u8>,
    pub read_image_file_exec_options: Field<u8>,
    pub being_debugged: Field<u8>,
    pub bit_field: Field<u8>,
    pub padding0: [Field<u8>; 4],
    /// -> `void`
    pub mutant: Field<u64>,
    /// -> `void`
    pub image_base_address: Field<u64>,
    /// -> `_PEB_LDR_DATA`
    pub ldr: Field<u64>,
    /// -> `_RTL_USER_PROCESS_PARAMETERS`
    pub process_parameters: Field<u64>,
    /// -> `void`
    pub sub_system_data: Field<u64>,
    /// -> `void`
    pub process_heap: Field<u64>,
    /// -> `_RTL_CRITICAL_SECTION`
    pub fast_peb_lock: Field<u64>,
    /// -> `_SLIST_HEADER`
    pub atl_thunk_s_list_ptr: Field<u64>,
    /// -> `void`
    pub ifeo_key: Field<u64>,
    pub cross_process_flags: Field<u32>,
    pub padding1: [Field<u8>; 4],
    /// -> `void`
    pub kernel_callback_table: Field<u64>,
    pub system_reserved: Field<u32>,
    pub atl_thunk_s_list_ptr32: Field<u32>,
    /// -> `void`
    pub api_set_map: Field<u64>,
    pub tls_expansion_counter: Field<u32>,
    pub padding2: [Field<u8>; 4],
    /// -> `void`
    pub tls_bitmap: Field<u64>,
    pub tls_bitmap_bits: [Field<u32>; 2],
    /// -> `void`
    pub read_only_shared_memory_base: Field<u64>,
    /// -> `void`
    pub shared_data: Field<u64>,
    /// -> `void*`
    pub read_only_static_server_data: Field<u64>,
    /// -> `void`
    pub ansi_code_page_data: Field<u64>,
    /// -> `void`
    pub oem_code_page_data: Field<u64>,
    /// -> `void`
    pub unicode_case_table_data: Field<u64>,
    pub number_of_processors: Field<u32>,
    pub nt_global_flag: Field<u32>,
    pub critical_section_timeout: LargeInteger,
    pub heap_segment_reserve: Field<u64>,
    pub heap_segment_commit: Field<u64>,
    pub heap_de_commit_total_free_threshold: Field<u64>,
    pub heap_de_commit_free_block_threshold: Field<u64>,
    pub number_of_heaps: Field<u32>,
    pub maximum_number_of_heaps: Field<u32>,
    /// -> `void*`
    pub process_heaps: Field<u64>,
    /// -> `void`
    pub gdi_shared_handle_table: Field<u64>,
    /// -> `void`
    pub process_starter_helper: Field<u64>,
    pub gdi_dc_attribute_list: Field<u32>,
    pub padding3: [Field<u8>; 4],
    /// -> `_RTL_CRITICAL_SECTION`
    pub loader_lock: Field<u64>,
    pub os_major_version: Field<u32>,
    pub os_minor_version: Field<u32>,
    pub os_build_number: Field<u16>,
    pub oscsd_version: Field<u16>,
    pub os_platform_id: Field<u32>,
    pub image_subsystem: Field<u32>,
    pub image_subsystem_major_version: Field<u32>,
    pub image_subsystem_minor_version: Field<u32>,
    pub padding4: [Field<u8>; 4],
    pub active_process_affinity_mask: Field<u64>,
    pub gdi_handle_buffer: [Field<u32>; 60],
    /// -> `fn`
    pub post_process_init_routine: Field<u64>,
    /// -> `void`
    pub tls_expansion_bitmap: Field<u64>,
    pub tls_expansion_bitmap_bits: [Field<u32>; 32],
    pub session_id: Field<u32>,
    pub padding5: [Field<u8>; 4],
    pub app_compat_flags: UlargeInteger,
    pub app_compat_flags_user: UlargeInteger,
    /// -> `void`
    pub p_shim_data: Field<u64>,
    /// -> `void`
    pub app_compat_info: Field<u64>,
    pub csd_version: UnicodeString,
    /// -> `_ACTIVATION_CONTEXT_DATA`
    pub activation_context_data: Field<u64>,
    /// -> `_ASSEMBLY_STORAGE_MAP`
    pub process_assembly_storage_map: Field<u64>,
    /// -> `_ACTIVATION_CONTEXT_DATA`
    pub system_default_activation_context_data: Field<u64>,
    /// -> `_ASSEMBLY_STORAGE_MAP`
    pub system_assembly_storage_map: Field<u64>,
    pub minimum_stack_commit: Field<u64>,
    /// -> `void`
    pub spare_pointers: [Field<u64>; 4],
    pub spare_ulongs: [Field<u32>; 5],
    _pad_354: Reserved<0x4>,
    /// -> `void`
    pub wer_registration_data: Field<u64>,
    /// -> `void`
    pub wer_ship_assert_ptr: Field<u64>,
    /// -> `void`
    pub p_unused: Field<u64>,
    /// -> `void`
    pub p_image_header_hash: Field<u64>,
    pub tracing_flags: Field<u32>,
    pub padding6: [Field<u8>; 4],
    pub csr_server_read_only_shared_memory_base: Field<u64>,
    pub tpp_workerp_list_lock: Field<u64>,
    pub tpp_workerp_list: ListEntry,
    /// -> `void`
    pub wait_on_address_hash_table: [Field<u64>; 128],
    /// -> `void`
    pub telemetry_coverage_header: Field<u64>,
    pub cloud_file_flags: Field<u32>,
    pub cloud_file_diag_flags: Field<u32>,
    pub placeholder_compatibility_mode: Field<i8>,
    pub placeholder_compatibility_mode_reserved: [Field<i8>; 7],
    /// -> `_LEAP_SECOND_DATA`
    pub leap_second_data: Field<u64>,
    pub leap_second_flags: Field<u32>,
    pub nt_global_flag2: Field<u32>,
}

/// Vista 1 de `_PEB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PebView1 {
    _pad_0: Reserved<0x58>,
    /// -> `void`
    pub user_shared_info_ptr: Field<u64>,
    _pad_60: Reserved<0x768>,
}

impl core::ops::Deref for Peb {
    type Target = PebView1;
    #[inline(always)]
    fn deref(&self) -> &PebView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PebView1>() }
    }
}

unsafe impl NtStruct for Peb {}

impl Peb {
    /// `ImageUsesLargePages`: bits 0..=0 de `bit_field`.
    pub const IMAGE_USES_LARGE_PAGES_SHIFT: u32 = 0;
    pub const IMAGE_USES_LARGE_PAGES_MASK: u8 = 0x1;
    #[inline(always)]
    pub fn image_uses_large_pages(&self) -> u8 {
        self.bit_field.bits(0, 1) as u8
    }
    #[inline(always)]
    pub fn set_image_uses_large_pages(&self, value: u8) {
        self.bit_field.set_bits(0, 1, value as u64)
    }
    /// `IsProtectedProcess`: bits 1..=1 de `bit_field`.
    pub const IS_PROTECTED_PROCESS_SHIFT: u32 = 1;
    pub const IS_PROTECTED_PROCESS_MASK: u8 = 0x2;
    #[inline(always)]
    pub fn is_protected_process(&self) -> u8 {
        self.bit_field.bits(1, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_protected_process(&self, value: u8) {
        self.bit_field.set_bits(1, 1, value as u64)
    }
    /// `IsImageDynamicallyRelocated`: bits 2..=2 de `bit_field`.
    pub const IS_IMAGE_DYNAMICALLY_RELOCATED_SHIFT: u32 = 2;
    pub const IS_IMAGE_DYNAMICALLY_RELOCATED_MASK: u8 = 0x4;
    #[inline(always)]
    pub fn is_image_dynamically_relocated(&self) -> u8 {
        self.bit_field.bits(2, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_image_dynamically_relocated(&self, value: u8) {
        self.bit_field.set_bits(2, 1, value as u64)
    }
    /// `SkipPatchingUser32Forwarders`: bits 3..=3 de `bit_field`.
    pub const SKIP_PATCHING_USER32_FORWARDERS_SHIFT: u32 = 3;
    pub const SKIP_PATCHING_USER32_FORWARDERS_MASK: u8 = 0x8;
    #[inline(always)]
    pub fn skip_patching_user32_forwarders(&self) -> u8 {
        self.bit_field.bits(3, 1) as u8
    }
    #[inline(always)]
    pub fn set_skip_patching_user32_forwarders(&self, value: u8) {
        self.bit_field.set_bits(3, 1, value as u64)
    }
    /// `IsPackagedProcess`: bits 4..=4 de `bit_field`.
    pub const IS_PACKAGED_PROCESS_SHIFT: u32 = 4;
    pub const IS_PACKAGED_PROCESS_MASK: u8 = 0x10;
    #[inline(always)]
    pub fn is_packaged_process(&self) -> u8 {
        self.bit_field.bits(4, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_packaged_process(&self, value: u8) {
        self.bit_field.set_bits(4, 1, value as u64)
    }
    /// `IsAppContainer`: bits 5..=5 de `bit_field`.
    pub const IS_APP_CONTAINER_SHIFT: u32 = 5;
    pub const IS_APP_CONTAINER_MASK: u8 = 0x20;
    #[inline(always)]
    pub fn is_app_container(&self) -> u8 {
        self.bit_field.bits(5, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_app_container(&self, value: u8) {
        self.bit_field.set_bits(5, 1, value as u64)
    }
    /// `IsProtectedProcessLight`: bits 6..=6 de `bit_field`.
    pub const IS_PROTECTED_PROCESS_LIGHT_SHIFT: u32 = 6;
    pub const IS_PROTECTED_PROCESS_LIGHT_MASK: u8 = 0x40;
    #[inline(always)]
    pub fn is_protected_process_light(&self) -> u8 {
        self.bit_field.bits(6, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_protected_process_light(&self, value: u8) {
        self.bit_field.set_bits(6, 1, value as u64)
    }
    /// `IsLongPathAwareProcess`: bits 7..=7 de `bit_field`.
    pub const IS_LONG_PATH_AWARE_PROCESS_SHIFT: u32 = 7;
    pub const IS_LONG_PATH_AWARE_PROCESS_MASK: u8 = 0x80;
    #[inline(always)]
    pub fn is_long_path_aware_process(&self) -> u8 {
        self.bit_field.bits(7, 1) as u8
    }
    #[inline(always)]
    pub fn set_is_long_path_aware_process(&self, value: u8) {
        self.bit_field.set_bits(7, 1, value as u64)
    }
    /// `ProcessInJob`: bits 0..=0 de `cross_process_flags`.
    pub const PROCESS_IN_JOB_SHIFT: u32 = 0;
    pub const PROCESS_IN_JOB_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn process_in_job(&self) -> u32 {
        self.cross_process_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_in_job(&self, value: u32) {
        self.cross_process_flags.set_bits(0, 1, value as u64)
    }
    /// `ProcessInitializing`: bits 1..=1 de `cross_process_flags`.
    pub const PROCESS_INITIALIZING_SHIFT: u32 = 1;
    pub const PROCESS_INITIALIZING_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn process_initializing(&self) -> u32 {
        self.cross_process_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_initializing(&self, value: u32) {
        self.cross_process_flags.set_bits(1, 1, value as u64)
    }
    /// `ProcessUsingVEH`: bits 2..=2 de `cross_process_flags`.
    pub const PROCESS_USING_VEH_SHIFT: u32 = 2;
    pub const PROCESS_USING_VEH_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn process_using_veh(&self) -> u32 {
        self.cross_process_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_using_veh(&self, value: u32) {
        self.cross_process_flags.set_bits(2, 1, value as u64)
    }
    /// `ProcessUsingVCH`: bits 3..=3 de `cross_process_flags`.
    pub const PROCESS_USING_VCH_SHIFT: u32 = 3;
    pub const PROCESS_USING_VCH_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn process_using_vch(&self) -> u32 {
        self.cross_process_flags.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_using_vch(&self, value: u32) {
        self.cross_process_flags.set_bits(3, 1, value as u64)
    }
    /// `ProcessUsingFTH`: bits 4..=4 de `cross_process_flags`.
    pub const PROCESS_USING_FTH_SHIFT: u32 = 4;
    pub const PROCESS_USING_FTH_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn process_using_fth(&self) -> u32 {
        self.cross_process_flags.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_using_fth(&self, value: u32) {
        self.cross_process_flags.set_bits(4, 1, value as u64)
    }
    /// `ProcessPreviouslyThrottled`: bits 5..=5 de `cross_process_flags`.
    pub const PROCESS_PREVIOUSLY_THROTTLED_SHIFT: u32 = 5;
    pub const PROCESS_PREVIOUSLY_THROTTLED_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn process_previously_throttled(&self) -> u32 {
        self.cross_process_flags.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_previously_throttled(&self, value: u32) {
        self.cross_process_flags.set_bits(5, 1, value as u64)
    }
    /// `ProcessCurrentlyThrottled`: bits 6..=6 de `cross_process_flags`.
    pub const PROCESS_CURRENTLY_THROTTLED_SHIFT: u32 = 6;
    pub const PROCESS_CURRENTLY_THROTTLED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn process_currently_throttled(&self) -> u32 {
        self.cross_process_flags.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_currently_throttled(&self, value: u32) {
        self.cross_process_flags.set_bits(6, 1, value as u64)
    }
    /// `ProcessImagesHotPatched`: bits 7..=7 de `cross_process_flags`.
    pub const PROCESS_IMAGES_HOT_PATCHED_SHIFT: u32 = 7;
    pub const PROCESS_IMAGES_HOT_PATCHED_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn process_images_hot_patched(&self) -> u32 {
        self.cross_process_flags.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_process_images_hot_patched(&self, value: u32) {
        self.cross_process_flags.set_bits(7, 1, value as u64)
    }
    /// `ReservedBits0`: bits 8..=31 de `cross_process_flags`.
    pub const RESERVED_BITS0_SHIFT: u32 = 8;
    pub const RESERVED_BITS0_MASK: u32 = 0xffffff00;
    #[inline(always)]
    pub fn reserved_bits0(&self) -> u32 {
        self.cross_process_flags.bits(8, 24) as u32
    }
    #[inline(always)]
    pub fn set_reserved_bits0(&self, value: u32) {
        self.cross_process_flags.set_bits(8, 24, value as u64)
    }
    /// `HeapTracingEnabled`: bits 0..=0 de `tracing_flags`.
    pub const HEAP_TRACING_ENABLED_SHIFT: u32 = 0;
    pub const HEAP_TRACING_ENABLED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn heap_tracing_enabled(&self) -> u32 {
        self.tracing_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_heap_tracing_enabled(&self, value: u32) {
        self.tracing_flags.set_bits(0, 1, value as u64)
    }
    /// `CritSecTracingEnabled`: bits 1..=1 de `tracing_flags`.
    pub const CRIT_SEC_TRACING_ENABLED_SHIFT: u32 = 1;
    pub const CRIT_SEC_TRACING_ENABLED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn crit_sec_tracing_enabled(&self) -> u32 {
        self.tracing_flags.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_crit_sec_tracing_enabled(&self, value: u32) {
        self.tracing_flags.set_bits(1, 1, value as u64)
    }
    /// `LibLoaderTracingEnabled`: bits 2..=2 de `tracing_flags`.
    pub const LIB_LOADER_TRACING_ENABLED_SHIFT: u32 = 2;
    pub const LIB_LOADER_TRACING_ENABLED_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn lib_loader_tracing_enabled(&self) -> u32 {
        self.tracing_flags.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_lib_loader_tracing_enabled(&self, value: u32) {
        self.tracing_flags.set_bits(2, 1, value as u64)
    }
    /// `SpareTracingBits`: bits 3..=31 de `tracing_flags`.
    pub const SPARE_TRACING_BITS_SHIFT: u32 = 3;
    pub const SPARE_TRACING_BITS_MASK: u32 = 0xfffffff8;
    #[inline(always)]
    pub fn spare_tracing_bits(&self) -> u32 {
        self.tracing_flags.bits(3, 29) as u32
    }
    #[inline(always)]
    pub fn set_spare_tracing_bits(&self, value: u32) {
        self.tracing_flags.set_bits(3, 29, value as u64)
    }
    /// `SixtySecondEnabled`: bits 0..=0 de `leap_second_flags`.
    pub const SIXTY_SECOND_ENABLED_SHIFT: u32 = 0;
    pub const SIXTY_SECOND_ENABLED_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn sixty_second_enabled(&self) -> u32 {
        self.leap_second_flags.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_sixty_second_enabled(&self, value: u32) {
        self.leap_second_flags.set_bits(0, 1, value as u64)
    }
    /// `Reserved`: bits 1..=31 de `leap_second_flags`.
    pub const RESERVED_SHIFT: u32 = 1;
    pub const RESERVED_MASK: u32 = 0xfffffffe;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.leap_second_flags.bits(1, 31) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.leap_second_flags.set_bits(1, 31, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Peb>() == 0x7c8);
    assert!(core::mem::offset_of!(Peb, inherited_address_space) == 0x0);
    assert!(core::mem::offset_of!(Peb, read_image_file_exec_options) == 0x1);
    assert!(core::mem::offset_of!(Peb, being_debugged) == 0x2);
    assert!(core::mem::offset_of!(Peb, bit_field) == 0x3);
    assert!(core::mem::offset_of!(Peb, padding0) == 0x4);
    assert!(core::mem::offset_of!(Peb, mutant) == 0x8);
    assert!(core::mem::offset_of!(Peb, image_base_address) == 0x10);
    assert!(core::mem::offset_of!(Peb, ldr) == 0x18);
    assert!(core::mem::offset_of!(Peb, process_parameters) == 0x20);
    assert!(core::mem::offset_of!(Peb, sub_system_data) == 0x28);
    assert!(core::mem::offset_of!(Peb, process_heap) == 0x30);
    assert!(core::mem::offset_of!(Peb, fast_peb_lock) == 0x38);
    assert!(core::mem::offset_of!(Peb, atl_thunk_s_list_ptr) == 0x40);
    assert!(core::mem::offset_of!(Peb, ifeo_key) == 0x48);
    assert!(core::mem::offset_of!(Peb, cross_process_flags) == 0x50);
    assert!(core::mem::offset_of!(Peb, padding1) == 0x54);
    assert!(core::mem::offset_of!(Peb, kernel_callback_table) == 0x58);
    assert!(core::mem::offset_of!(Peb, system_reserved) == 0x60);
    assert!(core::mem::offset_of!(Peb, atl_thunk_s_list_ptr32) == 0x64);
    assert!(core::mem::offset_of!(Peb, api_set_map) == 0x68);
    assert!(core::mem::offset_of!(Peb, tls_expansion_counter) == 0x70);
    assert!(core::mem::offset_of!(Peb, padding2) == 0x74);
    assert!(core::mem::offset_of!(Peb, tls_bitmap) == 0x78);
    assert!(core::mem::offset_of!(Peb, tls_bitmap_bits) == 0x80);
    assert!(core::mem::offset_of!(Peb, read_only_shared_memory_base) == 0x88);
    assert!(core::mem::offset_of!(Peb, shared_data) == 0x90);
    assert!(core::mem::offset_of!(Peb, read_only_static_server_data) == 0x98);
    assert!(core::mem::offset_of!(Peb, ansi_code_page_data) == 0xa0);
    assert!(core::mem::offset_of!(Peb, oem_code_page_data) == 0xa8);
    assert!(core::mem::offset_of!(Peb, unicode_case_table_data) == 0xb0);
    assert!(core::mem::offset_of!(Peb, number_of_processors) == 0xb8);
    assert!(core::mem::offset_of!(Peb, nt_global_flag) == 0xbc);
    assert!(core::mem::offset_of!(Peb, critical_section_timeout) == 0xc0);
    assert!(core::mem::offset_of!(Peb, heap_segment_reserve) == 0xc8);
    assert!(core::mem::offset_of!(Peb, heap_segment_commit) == 0xd0);
    assert!(core::mem::offset_of!(Peb, heap_de_commit_total_free_threshold) == 0xd8);
    assert!(core::mem::offset_of!(Peb, heap_de_commit_free_block_threshold) == 0xe0);
    assert!(core::mem::offset_of!(Peb, number_of_heaps) == 0xe8);
    assert!(core::mem::offset_of!(Peb, maximum_number_of_heaps) == 0xec);
    assert!(core::mem::offset_of!(Peb, process_heaps) == 0xf0);
    assert!(core::mem::offset_of!(Peb, gdi_shared_handle_table) == 0xf8);
    assert!(core::mem::offset_of!(Peb, process_starter_helper) == 0x100);
    assert!(core::mem::offset_of!(Peb, gdi_dc_attribute_list) == 0x108);
    assert!(core::mem::offset_of!(Peb, padding3) == 0x10c);
    assert!(core::mem::offset_of!(Peb, loader_lock) == 0x110);
    assert!(core::mem::offset_of!(Peb, os_major_version) == 0x118);
    assert!(core::mem::offset_of!(Peb, os_minor_version) == 0x11c);
    assert!(core::mem::offset_of!(Peb, os_build_number) == 0x120);
    assert!(core::mem::offset_of!(Peb, oscsd_version) == 0x122);
    assert!(core::mem::offset_of!(Peb, os_platform_id) == 0x124);
    assert!(core::mem::offset_of!(Peb, image_subsystem) == 0x128);
    assert!(core::mem::offset_of!(Peb, image_subsystem_major_version) == 0x12c);
    assert!(core::mem::offset_of!(Peb, image_subsystem_minor_version) == 0x130);
    assert!(core::mem::offset_of!(Peb, padding4) == 0x134);
    assert!(core::mem::offset_of!(Peb, active_process_affinity_mask) == 0x138);
    assert!(core::mem::offset_of!(Peb, gdi_handle_buffer) == 0x140);
    assert!(core::mem::offset_of!(Peb, post_process_init_routine) == 0x230);
    assert!(core::mem::offset_of!(Peb, tls_expansion_bitmap) == 0x238);
    assert!(core::mem::offset_of!(Peb, tls_expansion_bitmap_bits) == 0x240);
    assert!(core::mem::offset_of!(Peb, session_id) == 0x2c0);
    assert!(core::mem::offset_of!(Peb, padding5) == 0x2c4);
    assert!(core::mem::offset_of!(Peb, app_compat_flags) == 0x2c8);
    assert!(core::mem::offset_of!(Peb, app_compat_flags_user) == 0x2d0);
    assert!(core::mem::offset_of!(Peb, p_shim_data) == 0x2d8);
    assert!(core::mem::offset_of!(Peb, app_compat_info) == 0x2e0);
    assert!(core::mem::offset_of!(Peb, csd_version) == 0x2e8);
    assert!(core::mem::offset_of!(Peb, activation_context_data) == 0x2f8);
    assert!(core::mem::offset_of!(Peb, process_assembly_storage_map) == 0x300);
    assert!(core::mem::offset_of!(Peb, system_default_activation_context_data) == 0x308);
    assert!(core::mem::offset_of!(Peb, system_assembly_storage_map) == 0x310);
    assert!(core::mem::offset_of!(Peb, minimum_stack_commit) == 0x318);
    assert!(core::mem::offset_of!(Peb, spare_pointers) == 0x320);
    assert!(core::mem::offset_of!(Peb, spare_ulongs) == 0x340);
    assert!(core::mem::offset_of!(Peb, wer_registration_data) == 0x358);
    assert!(core::mem::offset_of!(Peb, wer_ship_assert_ptr) == 0x360);
    assert!(core::mem::offset_of!(Peb, p_unused) == 0x368);
    assert!(core::mem::offset_of!(Peb, p_image_header_hash) == 0x370);
    assert!(core::mem::offset_of!(Peb, tracing_flags) == 0x378);
    assert!(core::mem::offset_of!(Peb, padding6) == 0x37c);
    assert!(core::mem::offset_of!(Peb, csr_server_read_only_shared_memory_base) == 0x380);
    assert!(core::mem::offset_of!(Peb, tpp_workerp_list_lock) == 0x388);
    assert!(core::mem::offset_of!(Peb, tpp_workerp_list) == 0x390);
    assert!(core::mem::offset_of!(Peb, wait_on_address_hash_table) == 0x3a0);
    assert!(core::mem::offset_of!(Peb, telemetry_coverage_header) == 0x7a0);
    assert!(core::mem::offset_of!(Peb, cloud_file_flags) == 0x7a8);
    assert!(core::mem::offset_of!(Peb, cloud_file_diag_flags) == 0x7ac);
    assert!(core::mem::offset_of!(Peb, placeholder_compatibility_mode) == 0x7b0);
    assert!(core::mem::offset_of!(Peb, placeholder_compatibility_mode_reserved) == 0x7b1);
    assert!(core::mem::offset_of!(Peb, leap_second_data) == 0x7b8);
    assert!(core::mem::offset_of!(Peb, leap_second_flags) == 0x7c0);
    assert!(core::mem::offset_of!(Peb, nt_global_flag2) == 0x7c4);
    assert!(core::mem::size_of::<PebView1>() == 0x7c8);
    assert!(core::mem::align_of::<PebView1>() == core::mem::align_of::<Peb>());
    assert!(core::mem::offset_of!(PebView1, user_shared_info_ptr) == 0x58);
};

/// `_TEB` (0x1838 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `TebView1`..`TebView2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Teb {
    pub nt_tib: NtTib,
    /// -> `void`
    pub environment_pointer: Field<u64>,
    pub client_id: ClientId,
    /// -> `void`
    pub active_rpc_handle: Field<u64>,
    /// -> `void`
    pub thread_local_storage_pointer: Field<u64>,
    /// -> `_PEB`
    pub process_environment_block: Field<u64>,
    pub last_error_value: Field<u32>,
    pub count_of_owned_critical_sections: Field<u32>,
    /// -> `void`
    pub csr_client_thread: Field<u64>,
    /// -> `void`
    pub win32_thread_info: Field<u64>,
    pub user32_reserved: [Field<u32>; 26],
    pub user_reserved: [Field<u32>; 5],
    _pad_fc: Reserved<0x4>,
    /// -> `void`
    pub wow32_reserved: Field<u64>,
    pub current_locale: Field<u32>,
    pub fp_software_status_register: Field<u32>,
    /// -> `void`
    pub reserved_for_debugger_instrumentation: [Field<u64>; 16],
    /// -> `void`
    pub system_reserved1: [Field<u64>; 30],
    pub placeholder_compatibility_mode: Field<i8>,
    pub placeholder_hydration_always_explicit: Field<u8>,
    pub placeholder_reserved: [Field<i8>; 10],
    pub proxied_process_id: Field<u32>,
    pub activation_stack: ActivationContextStack,
    pub working_on_behalf_ticket: [Field<u8>; 8],
    pub exception_code: Field<i32>,
    pub padding0: [Field<u8>; 4],
    /// -> `_ACTIVATION_CONTEXT_STACK`
    pub activation_context_stack_pointer: Field<u64>,
    pub instrumentation_callback_sp: Field<u64>,
    pub instrumentation_callback_previous_pc: Field<u64>,
    pub instrumentation_callback_previous_sp: Field<u64>,
    pub tx_fs_context: Field<u32>,
    pub instrumentation_callback_disabled: Field<u8>,
    pub unaligned_load_store_exceptions: Field<u8>,
    pub padding1: [Field<u8>; 2],
    pub gdi_teb_batch: GdiTebBatch,
    pub real_client_id: ClientId,
    /// -> `void`
    pub gdi_cached_process_handle: Field<u64>,
    pub gdi_client_pid: Field<u32>,
    pub gdi_client_tid: Field<u32>,
    /// -> `void`
    pub gdi_thread_local_info: Field<u64>,
    pub win32_client_info: [Field<u64>; 62],
    /// -> `void`
    pub gl_dispatch_table: [Field<u64>; 233],
    pub gl_reserved1: [Field<u64>; 29],
    /// -> `void`
    pub gl_reserved2: Field<u64>,
    /// -> `void`
    pub gl_section_info: Field<u64>,
    /// -> `void`
    pub gl_section: Field<u64>,
    /// -> `void`
    pub gl_table: Field<u64>,
    /// -> `void`
    pub gl_current_rc: Field<u64>,
    /// -> `void`
    pub gl_context: Field<u64>,
    pub last_status_value: Field<u32>,
    pub padding2: [Field<u8>; 4],
    pub static_unicode_string: UnicodeString,
    pub static_unicode_buffer: [Field<u16>; 261],
    pub padding3: [Field<u8>; 6],
    /// -> `void`
    pub deallocation_stack: Field<u64>,
    /// -> `void`
    pub tls_slots: [Field<u64>; 64],
    pub tls_links: ListEntry,
    /// -> `void`
    pub vdm: Field<u64>,
    /// -> `void`
    pub reserved_for_nt_rpc: Field<u64>,
    /// -> `void`
    pub dbg_ss_reserved: [Field<u64>; 2],
    pub hard_error_mode: Field<u32>,
    pub padding4: [Field<u8>; 4],
    /// -> `void`
    pub instrumentation: [Field<u64>; 11],
    pub activity_id: Guid,
    /// -> `void`
    pub sub_process_tag: Field<u64>,
    /// -> `void`
    pub perflib_data: Field<u64>,
    /// -> `void`
    pub etw_trace_data: Field<u64>,
    /// -> `void`
    pub win_sock_data: Field<u64>,
    pub gdi_batch_count: Field<u32>,
    pub current_ideal_processor: ProcessorNumber,
    pub guaranteed_stack_bytes: Field<u32>,
    pub padding5: [Field<u8>; 4],
    /// -> `void`
    pub reserved_for_perf: Field<u64>,
    /// -> `void`
    pub reserved_for_ole: Field<u64>,
    pub waiting_on_loader_lock: Field<u32>,
    pub padding6: [Field<u8>; 4],
    /// -> `void`
    pub saved_priority_state: Field<u64>,
    pub reserved_for_code_coverage: Field<u64>,
    /// -> `void`
    pub thread_pool_data: Field<u64>,
    /// -> `void*`
    pub tls_expansion_slots: Field<u64>,
    /// -> `void`
    pub deallocation_b_store: Field<u64>,
    /// -> `void`
    pub b_store_limit: Field<u64>,
    pub mui_generation: Field<u32>,
    pub is_impersonating: Field<u32>,
    /// -> `void`
    pub nls_cache: Field<u64>,
    /// -> `void`
    pub p_shim_data: Field<u64>,
    pub heap_data: Field<u32>,
    pub padding7: [Field<u8>; 4],
    /// -> `void`
    pub current_transaction_handle: Field<u64>,
    /// -> `_TEB_ACTIVE_FRAME`
    pub active_frame: Field<u64>,
    /// -> `void`
    pub fls_data: Field<u64>,
    /// -> `void`
    pub preferred_languages: Field<u64>,
    /// -> `void`
    pub user_pref_languages: Field<u64>,
    /// -> `void`
    pub merged_pref_languages: Field<u64>,
    pub mui_impersonation: Field<u32>,
    pub cross_teb_flags: Field<u16>,
    pub same_teb_flags: Field<u16>,
    /// -> `void`
    pub txn_scope_enter_callback: Field<u64>,
    /// -> `void`
    pub txn_scope_exit_callback: Field<u64>,
    /// -> `void`
    pub txn_scope_context: Field<u64>,
    pub lock_count: Field<u32>,
    pub wow_teb_offset: Field<i32>,
    /// -> `void`
    pub resource_ret_value: Field<u64>,
    /// -> `void`
    pub reserved_for_wdf: Field<u64>,
    pub reserved_for_crt: Field<u64>,
    pub effective_container_id: Guid,
}

/// Vista 1 de `_TEB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct TebView1 {
    _align: [u64; 0],
    _pad_0: Reserved<0x1744>,
    pub ideal_processor_value: Field<u32>,
    _pad_1748: Reserved<0xf0>,
}

/// Vista 2 de `_TEB` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct TebView2 {
    _align: [u64; 0],
    _pad_0: Reserved<0x1744>,
    pub reserved_pad0: Field<u8>,
    pub reserved_pad1: Field<u8>,
    pub reserved_pad2: Field<u8>,
    pub ideal_processor: Field<u8>,
    _pad_1748: Reserved<0xf0>,
}

impl core::ops::Deref for Teb {
    type Target = TebView1;
    #[inline(always)]
    fn deref(&self) -> &TebView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<TebView1>() }
    }
}

impl core::ops::Deref for TebView1 {
    type Target = TebView2;
    #[inline(always)]
    fn deref(&self) -> &TebView2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<TebView2>() }
    }
}

unsafe impl NtStruct for Teb {}

impl Teb {
    /// `SpareCrossTebBits`: bits 0..=15 de `cross_teb_flags`.
    pub const SPARE_CROSS_TEB_BITS_SHIFT: u32 = 0;
    pub const SPARE_CROSS_TEB_BITS_MASK: u16 = 0xffff;
    #[inline(always)]
    pub fn spare_cross_teb_bits(&self) -> u16 {
        self.cross_teb_flags.bits(0, 16) as u16
    }
    #[inline(always)]
    pub fn set_spare_cross_teb_bits(&self, value: u16) {
        self.cross_teb_flags.set_bits(0, 16, value as u64)
    }
    /// `SafeThunkCall`: bits 0..=0 de `same_teb_flags`.
    pub const SAFE_THUNK_CALL_SHIFT: u32 = 0;
    pub const SAFE_THUNK_CALL_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn safe_thunk_call(&self) -> u16 {
        self.same_teb_flags.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_safe_thunk_call(&self, value: u16) {
        self.same_teb_flags.set_bits(0, 1, value as u64)
    }
    /// `InDebugPrint`: bits 1..=1 de `same_teb_flags`.
    pub const IN_DEBUG_PRINT_SHIFT: u32 = 1;
    pub const IN_DEBUG_PRINT_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn in_debug_print(&self) -> u16 {
        self.same_teb_flags.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_in_debug_print(&self, value: u16) {
        self.same_teb_flags.set_bits(1, 1, value as u64)
    }
    /// `HasFiberData`: bits 2..=2 de `same_teb_flags`.
    pub const HAS_FIBER_DATA_SHIFT: u32 = 2;
    pub const HAS_FIBER_DATA_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn has_fiber_data(&self) -> u16 {
        self.same_teb_flags.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_has_fiber_data(&self, value: u16) {
        self.same_teb_flags.set_bits(2, 1, value as u64)
    }
    /// `SkipThreadAttach`: bits 3..=3 de `same_teb_flags`.
    pub const SKIP_THREAD_ATTACH_SHIFT: u32 = 3;
    pub const SKIP_THREAD_ATTACH_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn skip_thread_attach(&self) -> u16 {
        self.same_teb_flags.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_skip_thread_attach(&self, value: u16) {
        self.same_teb_flags.set_bits(3, 1, value as u64)
    }
    /// `WerInShipAssertCode`: bits 4..=4 de `same_teb_flags`.
    pub const WER_IN_SHIP_ASSERT_CODE_SHIFT: u32 = 4;
    pub const WER_IN_SHIP_ASSERT_CODE_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn wer_in_ship_assert_code(&self) -> u16 {
        self.same_teb_flags.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_wer_in_ship_assert_code(&self, value: u16) {
        self.same_teb_flags.set_bits(4, 1, value as u64)
    }
    /// `RanProcessInit`: bits 5..=5 de `same_teb_flags`.
    pub const RAN_PROCESS_INIT_SHIFT: u32 = 5;
    pub const RAN_PROCESS_INIT_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn ran_process_init(&self) -> u16 {
        self.same_teb_flags.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_ran_process_init(&self, value: u16) {
        self.same_teb_flags.set_bits(5, 1, value as u64)
    }
    /// `ClonedThread`: bits 6..=6 de `same_teb_flags`.
    pub const CLONED_THREAD_SHIFT: u32 = 6;
    pub const CLONED_THREAD_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn cloned_thread(&self) -> u16 {
        self.same_teb_flags.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_cloned_thread(&self, value: u16) {
        self.same_teb_flags.set_bits(6, 1, value as u64)
    }
    /// `SuppressDebugMsg`: bits 7..=7 de `same_teb_flags`.
    pub const SUPPRESS_DEBUG_MSG_SHIFT: u32 = 7;
    pub const SUPPRESS_DEBUG_MSG_MASK: u16 = 0x80;
    #[inline(always)]
    pub fn suppress_debug_msg(&self) -> u16 {
        self.same_teb_flags.bits(7, 1) as u16
    }
    #[inline(always)]
    pub fn set_suppress_debug_msg(&self, value: u16) {
        self.same_teb_flags.set_bits(7, 1, value as u64)
    }
    /// `DisableUserStackWalk`: bits 8..=8 de `same_teb_flags`.
    pub const DISABLE_USER_STACK_WALK_SHIFT: u32 = 8;
    pub const DISABLE_USER_STACK_WALK_MASK: u16 = 0x100;
    #[inline(always)]
    pub fn disable_user_stack_walk(&self) -> u16 {
        self.same_teb_flags.bits(8, 1) as u16
    }
    #[inline(always)]
    pub fn set_disable_user_stack_walk(&self, value: u16) {
        self.same_teb_flags.set_bits(8, 1, value as u64)
    }
    /// `RtlExceptionAttached`: bits 9..=9 de `same_teb_flags`.
    pub const RTL_EXCEPTION_ATTACHED_SHIFT: u32 = 9;
    pub const RTL_EXCEPTION_ATTACHED_MASK: u16 = 0x200;
    #[inline(always)]
    pub fn rtl_exception_attached(&self) -> u16 {
        self.same_teb_flags.bits(9, 1) as u16
    }
    #[inline(always)]
    pub fn set_rtl_exception_attached(&self, value: u16) {
        self.same_teb_flags.set_bits(9, 1, value as u64)
    }
    /// `InitialThread`: bits 10..=10 de `same_teb_flags`.
    pub const INITIAL_THREAD_SHIFT: u32 = 10;
    pub const INITIAL_THREAD_MASK: u16 = 0x400;
    #[inline(always)]
    pub fn initial_thread(&self) -> u16 {
        self.same_teb_flags.bits(10, 1) as u16
    }
    #[inline(always)]
    pub fn set_initial_thread(&self, value: u16) {
        self.same_teb_flags.set_bits(10, 1, value as u64)
    }
    /// `SessionAware`: bits 11..=11 de `same_teb_flags`.
    pub const SESSION_AWARE_SHIFT: u32 = 11;
    pub const SESSION_AWARE_MASK: u16 = 0x800;
    #[inline(always)]
    pub fn session_aware(&self) -> u16 {
        self.same_teb_flags.bits(11, 1) as u16
    }
    #[inline(always)]
    pub fn set_session_aware(&self, value: u16) {
        self.same_teb_flags.set_bits(11, 1, value as u64)
    }
    /// `LoadOwner`: bits 12..=12 de `same_teb_flags`.
    pub const LOAD_OWNER_SHIFT: u32 = 12;
    pub const LOAD_OWNER_MASK: u16 = 0x1000;
    #[inline(always)]
    pub fn load_owner(&self) -> u16 {
        self.same_teb_flags.bits(12, 1) as u16
    }
    #[inline(always)]
    pub fn set_load_owner(&self, value: u16) {
        self.same_teb_flags.set_bits(12, 1, value as u64)
    }
    /// `LoaderWorker`: bits 13..=13 de `same_teb_flags`.
    pub const LOADER_WORKER_SHIFT: u32 = 13;
    pub const LOADER_WORKER_MASK: u16 = 0x2000;
    #[inline(always)]
    pub fn loader_worker(&self) -> u16 {
        self.same_teb_flags.bits(13, 1) as u16
    }
    #[inline(always)]
    pub fn set_loader_worker(&self, value: u16) {
        self.same_teb_flags.set_bits(13, 1, value as u64)
    }
    /// `SkipLoaderInit`: bits 14..=14 de `same_teb_flags`.
    pub const SKIP_LOADER_INIT_SHIFT: u32 = 14;
    pub const SKIP_LOADER_INIT_MASK: u16 = 0x4000;
    #[inline(always)]
    pub fn skip_loader_init(&self) -> u16 {
        self.same_teb_flags.bits(14, 1) as u16
    }
    #[inline(always)]
    pub fn set_skip_loader_init(&self, value: u16) {
        self.same_teb_flags.set_bits(14, 1, value as u64)
    }
    /// `SpareSameTebBits`: bits 15..=15 de `same_teb_flags`.
    pub const SPARE_SAME_TEB_BITS_SHIFT: u32 = 15;
    pub const SPARE_SAME_TEB_BITS_MASK: u16 = 0x8000;
    #[inline(always)]
    pub fn spare_same_teb_bits(&self) -> u16 {
        self.same_teb_flags.bits(15, 1) as u16
    }
    #[inline(always)]
    pub fn set_spare_same_teb_bits(&self, value: u16) {
        self.same_teb_flags.set_bits(15, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Teb>() == 0x1838);
    assert!(core::mem::offset_of!(Teb, nt_tib) == 0x0);
    assert!(core::mem::offset_of!(Teb, environment_pointer) == 0x38);
    assert!(core::mem::offset_of!(Teb, client_id) == 0x40);
    assert!(core::mem::offset_of!(Teb, active_rpc_handle) == 0x50);
    assert!(core::mem::offset_of!(Teb, thread_local_storage_pointer) == 0x58);
    assert!(core::mem::offset_of!(Teb, process_environment_block) == 0x60);
    assert!(core::mem::offset_of!(Teb, last_error_value) == 0x68);
    assert!(core::mem::offset_of!(Teb, count_of_owned_critical_sections) == 0x6c);
    assert!(core::mem::offset_of!(Teb, csr_client_thread) == 0x70);
    assert!(core::mem::offset_of!(Teb, win32_thread_info) == 0x78);
    assert!(core::mem::offset_of!(Teb, user32_reserved) == 0x80);
    assert!(core::mem::offset_of!(Teb, user_reserved) == 0xe8);
    assert!(core::mem::offset_of!(Teb, wow32_reserved) == 0x100);
    assert!(core::mem::offset_of!(Teb, current_locale) == 0x108);
    assert!(core::mem::offset_of!(Teb, fp_software_status_register) == 0x10c);
    assert!(core::mem::offset_of!(Teb, reserved_for_debugger_instrumentation) == 0x110);
    assert!(core::mem::offset_of!(Teb, system_reserved1) == 0x190);
    assert!(core::mem::offset_of!(Teb, placeholder_compatibility_mode) == 0x280);
    assert!(core::mem::offset_of!(Teb, placeholder_hydration_always_explicit) == 0x281);
    assert!(core::mem::offset_of!(Teb, placeholder_reserved) == 0x282);
    assert!(core::mem::offset_of!(Teb, proxied_process_id) == 0x28c);
    assert!(core::mem::offset_of!(Teb, activation_stack) == 0x290);
    assert!(core::mem::offset_of!(Teb, working_on_behalf_ticket) == 0x2b8);
    assert!(core::mem::offset_of!(Teb, exception_code) == 0x2c0);
    assert!(core::mem::offset_of!(Teb, padding0) == 0x2c4);
    assert!(core::mem::offset_of!(Teb, activation_context_stack_pointer) == 0x2c8);
    assert!(core::mem::offset_of!(Teb, instrumentation_callback_sp) == 0x2d0);
    assert!(core::mem::offset_of!(Teb, instrumentation_callback_previous_pc) == 0x2d8);
    assert!(core::mem::offset_of!(Teb, instrumentation_callback_previous_sp) == 0x2e0);
    assert!(core::mem::offset_of!(Teb, tx_fs_context) == 0x2e8);
    assert!(core::mem::offset_of!(Teb, instrumentation_callback_disabled) == 0x2ec);
    assert!(core::mem::offset_of!(Teb, unaligned_load_store_exceptions) == 0x2ed);
    assert!(core::mem::offset_of!(Teb, padding1) == 0x2ee);
    assert!(core::mem::offset_of!(Teb, gdi_teb_batch) == 0x2f0);
    assert!(core::mem::offset_of!(Teb, real_client_id) == 0x7d8);
    assert!(core::mem::offset_of!(Teb, gdi_cached_process_handle) == 0x7e8);
    assert!(core::mem::offset_of!(Teb, gdi_client_pid) == 0x7f0);
    assert!(core::mem::offset_of!(Teb, gdi_client_tid) == 0x7f4);
    assert!(core::mem::offset_of!(Teb, gdi_thread_local_info) == 0x7f8);
    assert!(core::mem::offset_of!(Teb, win32_client_info) == 0x800);
    assert!(core::mem::offset_of!(Teb, gl_dispatch_table) == 0x9f0);
    assert!(core::mem::offset_of!(Teb, gl_reserved1) == 0x1138);
    assert!(core::mem::offset_of!(Teb, gl_reserved2) == 0x1220);
    assert!(core::mem::offset_of!(Teb, gl_section_info) == 0x1228);
    assert!(core::mem::offset_of!(Teb, gl_section) == 0x1230);
    assert!(core::mem::offset_of!(Teb, gl_table) == 0x1238);
    assert!(core::mem::offset_of!(Teb, gl_current_rc) == 0x1240);
    assert!(core::mem::offset_of!(Teb, gl_context) == 0x1248);
    assert!(core::mem::offset_of!(Teb, last_status_value) == 0x1250);
    assert!(core::mem::offset_of!(Teb, padding2) == 0x1254);
    assert!(core::mem::offset_of!(Teb, static_unicode_string) == 0x1258);
    assert!(core::mem::offset_of!(Teb, static_unicode_buffer) == 0x1268);
    assert!(core::mem::offset_of!(Teb, padding3) == 0x1472);
    assert!(core::mem::offset_of!(Teb, deallocation_stack) == 0x1478);
    assert!(core::mem::offset_of!(Teb, tls_slots) == 0x1480);
    assert!(core::mem::offset_of!(Teb, tls_links) == 0x1680);
    assert!(core::mem::offset_of!(Teb, vdm) == 0x1690);
    assert!(core::mem::offset_of!(Teb, reserved_for_nt_rpc) == 0x1698);
    assert!(core::mem::offset_of!(Teb, dbg_ss_reserved) == 0x16a0);
    assert!(core::mem::offset_of!(Teb, hard_error_mode) == 0x16b0);
    assert!(core::mem::offset_of!(Teb, padding4) == 0x16b4);
    assert!(core::mem::offset_of!(Teb, instrumentation) == 0x16b8);
    assert!(core::mem::offset_of!(Teb, activity_id) == 0x1710);
    assert!(core::mem::offset_of!(Teb, sub_process_tag) == 0x1720);
    assert!(core::mem::offset_of!(Teb, perflib_data) == 0x1728);
    assert!(core::mem::offset_of!(Teb, etw_trace_data) == 0x1730);
    assert!(core::mem::offset_of!(Teb, win_sock_data) == 0x1738);
    assert!(core::mem::offset_of!(Teb, gdi_batch_count) == 0x1740);
    assert!(core::mem::offset_of!(Teb, current_ideal_processor) == 0x1744);
    assert!(core::mem::offset_of!(Teb, guaranteed_stack_bytes) == 0x1748);
    assert!(core::mem::offset_of!(Teb, padding5) == 0x174c);
    assert!(core::mem::offset_of!(Teb, reserved_for_perf) == 0x1750);
    assert!(core::mem::offset_of!(Teb, reserved_for_ole) == 0x1758);
    assert!(core::mem::offset_of!(Teb, waiting_on_loader_lock) == 0x1760);
    assert!(core::mem::offset_of!(Teb, padding6) == 0x1764);
    assert!(core::mem::offset_of!(Teb, saved_priority_state) == 0x1768);
    assert!(core::mem::offset_of!(Teb, reserved_for_code_coverage) == 0x1770);
    assert!(core::mem::offset_of!(Teb, thread_pool_data) == 0x1778);
    assert!(core::mem::offset_of!(Teb, tls_expansion_slots) == 0x1780);
    assert!(core::mem::offset_of!(Teb, deallocation_b_store) == 0x1788);
    assert!(core::mem::offset_of!(Teb, b_store_limit) == 0x1790);
    assert!(core::mem::offset_of!(Teb, mui_generation) == 0x1798);
    assert!(core::mem::offset_of!(Teb, is_impersonating) == 0x179c);
    assert!(core::mem::offset_of!(Teb, nls_cache) == 0x17a0);
    assert!(core::mem::offset_of!(Teb, p_shim_data) == 0x17a8);
    assert!(core::mem::offset_of!(Teb, heap_data) == 0x17b0);
    assert!(core::mem::offset_of!(Teb, padding7) == 0x17b4);
    assert!(core::mem::offset_of!(Teb, current_transaction_handle) == 0x17b8);
    assert!(core::mem::offset_of!(Teb, active_frame) == 0x17c0);
    assert!(core::mem::offset_of!(Teb, fls_data) == 0x17c8);
    assert!(core::mem::offset_of!(Teb, preferred_languages) == 0x17d0);
    assert!(core::mem::offset_of!(Teb, user_pref_languages) == 0x17d8);
    assert!(core::mem::offset_of!(Teb, merged_pref_languages) == 0x17e0);
    assert!(core::mem::offset_of!(Teb, mui_impersonation) == 0x17e8);
    assert!(core::mem::offset_of!(Teb, cross_teb_flags) == 0x17ec);
    assert!(core::mem::offset_of!(Teb, same_teb_flags) == 0x17ee);
    assert!(core::mem::offset_of!(Teb, txn_scope_enter_callback) == 0x17f0);
    assert!(core::mem::offset_of!(Teb, txn_scope_exit_callback) == 0x17f8);
    assert!(core::mem::offset_of!(Teb, txn_scope_context) == 0x1800);
    assert!(core::mem::offset_of!(Teb, lock_count) == 0x1808);
    assert!(core::mem::offset_of!(Teb, wow_teb_offset) == 0x180c);
    assert!(core::mem::offset_of!(Teb, resource_ret_value) == 0x1810);
    assert!(core::mem::offset_of!(Teb, reserved_for_wdf) == 0x1818);
    assert!(core::mem::offset_of!(Teb, reserved_for_crt) == 0x1820);
    assert!(core::mem::offset_of!(Teb, effective_container_id) == 0x1828);
    assert!(core::mem::size_of::<TebView1>() == 0x1838);
    assert!(core::mem::align_of::<TebView1>() == core::mem::align_of::<Teb>());
    assert!(core::mem::offset_of!(TebView1, ideal_processor_value) == 0x1744);
    assert!(core::mem::size_of::<TebView2>() == 0x1838);
    assert!(core::mem::align_of::<TebView2>() == core::mem::align_of::<Teb>());
    assert!(core::mem::offset_of!(TebView2, reserved_pad0) == 0x1744);
    assert!(core::mem::offset_of!(TebView2, reserved_pad1) == 0x1745);
    assert!(core::mem::offset_of!(TebView2, reserved_pad2) == 0x1746);
    assert!(core::mem::offset_of!(TebView2, ideal_processor) == 0x1747);
};

/// `_ACTIVATION_CONTEXT_STACK` (0x28 bytes).
#[repr(C)]
pub struct ActivationContextStack {
    /// -> `_RTL_ACTIVATION_CONTEXT_STACK_FRAME`
    pub active_frame: Field<u64>,
    pub frame_list_cache: ListEntry,
    pub flags: Field<u32>,
    pub next_cookie_sequence_number: Field<u32>,
    pub stack_id: Field<u32>,
    _pad_24: Reserved<0x4>,
}

unsafe impl NtStruct for ActivationContextStack {}

const _: () = {
    assert!(core::mem::size_of::<ActivationContextStack>() == 0x28);
    assert!(core::mem::offset_of!(ActivationContextStack, active_frame) == 0x0);
    assert!(core::mem::offset_of!(ActivationContextStack, frame_list_cache) == 0x8);
    assert!(core::mem::offset_of!(ActivationContextStack, flags) == 0x18);
    assert!(core::mem::offset_of!(ActivationContextStack, next_cookie_sequence_number) == 0x1c);
    assert!(core::mem::offset_of!(ActivationContextStack, stack_id) == 0x20);
};

/// `_GDI_TEB_BATCH` (0x4e8 bytes).
#[repr(C)]
pub struct GdiTebBatch {
    pub bitfield_0: Field<u32>,
    _pad_4: Reserved<0x4>,
    pub hdc: Field<u64>,
    pub buffer: [Field<u32>; 310],
}

unsafe impl NtStruct for GdiTebBatch {}

impl GdiTebBatch {
    /// `Offset`: bits 0..=30 de `bitfield_0`.
    pub const OFFSET_SHIFT: u32 = 0;
    pub const OFFSET_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn offset(&self) -> u32 {
        self.bitfield_0.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_offset(&self, value: u32) {
        self.bitfield_0.set_bits(0, 31, value as u64)
    }
    /// `HasRenderingCommand`: bits 31..=31 de `bitfield_0`.
    pub const HAS_RENDERING_COMMAND_SHIFT: u32 = 31;
    pub const HAS_RENDERING_COMMAND_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn has_rendering_command(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_has_rendering_command(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<GdiTebBatch>() == 0x4e8);
    assert!(core::mem::offset_of!(GdiTebBatch, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(GdiTebBatch, hdc) == 0x8);
    assert!(core::mem::offset_of!(GdiTebBatch, buffer) == 0x10);
};

/// `_ESERVERSILO_GLOBALS` (0x4a0 bytes).
#[repr(C)]
pub struct EserversiloGlobals {
    pub ob_silo_state: ObpSilodriverstate,
    pub se_silo_state: SepSilostate,
    pub se_rm_silo_state: SepRmLsaConnectionState,
    /// -> `_ETW_SILODRIVERSTATE`
    pub etw_silo_state: Field<u64>,
    /// -> `_EPROCESS`
    pub mi_session_leader_process: Field<u64>,
    /// -> `_EPROCESS`
    pub exp_default_error_port_process: Field<u64>,
    /// -> `void`
    pub exp_default_error_port: Field<u64>,
    pub hard_error_state: Field<u32>,
    _pad_384: Reserved<0x4>,
    /// -> `_EXP_LICENSE_STATE`
    pub exp_license_state: Field<u64>,
    pub wnf_silo_state: WnfSilodriverstate,
    pub dbgk_silo_state: DbgkSilostate,
    pub ps_protected_current_directory: UnicodeString,
    pub ps_protected_environment: UnicodeString,
    /// -> `void`
    pub api_set_section: Field<u64>,
    /// -> `void`
    pub api_set_schema: Field<u64>,
    pub one_core_forwarders_enabled: Field<u8>,
    pub tz_virtualization_supported: Field<u8>,
    _pad_41a: Reserved<0x6>,
    /// -> `void`
    pub img_file_exec_options: Field<u64>,
    /// -> `_EX_TIMEZONE_STATE`
    pub ex_time_zone_state: Field<u64>,
    pub nt_system_root: UnicodeString,
    pub silo_root_directory_name: UnicodeString,
    /// -> `_PSP_STORAGE`
    pub storage: Field<u64>,
    pub state: Field<ServersiloState>,
    pub exit_status: Field<i32>,
    /// -> `_KEVENT`
    pub delete_event: Field<u64>,
    /// -> `_SILO_USER_SHARED_DATA`
    pub user_shared_data: Field<u64>,
    /// -> `void`
    pub user_shared_section: Field<u64>,
    pub terminate_work_item: WorkQueueItem,
    pub is_downlevel_container: Field<u8>,
    _pad_499: Reserved<0x7>,
}

unsafe impl NtStruct for EserversiloGlobals {}

const _: () = {
    assert!(core::mem::size_of::<EserversiloGlobals>() == 0x4a0);
    assert!(core::mem::offset_of!(EserversiloGlobals, ob_silo_state) == 0x0);
    assert!(core::mem::offset_of!(EserversiloGlobals, se_silo_state) == 0x2e0);
    assert!(core::mem::offset_of!(EserversiloGlobals, se_rm_silo_state) == 0x310);
    assert!(core::mem::offset_of!(EserversiloGlobals, etw_silo_state) == 0x360);
    assert!(core::mem::offset_of!(EserversiloGlobals, mi_session_leader_process) == 0x368);
    assert!(core::mem::offset_of!(EserversiloGlobals, exp_default_error_port_process) == 0x370);
    assert!(core::mem::offset_of!(EserversiloGlobals, exp_default_error_port) == 0x378);
    assert!(core::mem::offset_of!(EserversiloGlobals, hard_error_state) == 0x380);
    assert!(core::mem::offset_of!(EserversiloGlobals, exp_license_state) == 0x388);
    assert!(core::mem::offset_of!(EserversiloGlobals, wnf_silo_state) == 0x390);
    assert!(core::mem::offset_of!(EserversiloGlobals, dbgk_silo_state) == 0x3c8);
    assert!(core::mem::offset_of!(EserversiloGlobals, ps_protected_current_directory) == 0x3e8);
    assert!(core::mem::offset_of!(EserversiloGlobals, ps_protected_environment) == 0x3f8);
    assert!(core::mem::offset_of!(EserversiloGlobals, api_set_section) == 0x408);
    assert!(core::mem::offset_of!(EserversiloGlobals, api_set_schema) == 0x410);
    assert!(core::mem::offset_of!(EserversiloGlobals, one_core_forwarders_enabled) == 0x418);
    assert!(core::mem::offset_of!(EserversiloGlobals, tz_virtualization_supported) == 0x419);
    assert!(core::mem::offset_of!(EserversiloGlobals, img_file_exec_options) == 0x420);
    assert!(core::mem::offset_of!(EserversiloGlobals, ex_time_zone_state) == 0x428);
    assert!(core::mem::offset_of!(EserversiloGlobals, nt_system_root) == 0x430);
    assert!(core::mem::offset_of!(EserversiloGlobals, silo_root_directory_name) == 0x440);
    assert!(core::mem::offset_of!(EserversiloGlobals, storage) == 0x450);
    assert!(core::mem::offset_of!(EserversiloGlobals, state) == 0x458);
    assert!(core::mem::offset_of!(EserversiloGlobals, exit_status) == 0x45c);
    assert!(core::mem::offset_of!(EserversiloGlobals, delete_event) == 0x460);
    assert!(core::mem::offset_of!(EserversiloGlobals, user_shared_data) == 0x468);
    assert!(core::mem::offset_of!(EserversiloGlobals, user_shared_section) == 0x470);
    assert!(core::mem::offset_of!(EserversiloGlobals, terminate_work_item) == 0x478);
    assert!(core::mem::offset_of!(EserversiloGlobals, is_downlevel_container) == 0x498);
};

/// `_DBGK_SILOSTATE` (0x20 bytes).
#[repr(C)]
pub struct DbgkSilostate {
    pub error_port_lock: ExPushLock,
    /// -> `_DBGKP_ERROR_PORT`
    pub error_port: Field<u64>,
    /// -> `_EPROCESS`
    pub error_process: Field<u64>,
    /// -> `_KEVENT`
    pub error_port_registered_event: Field<u64>,
}

unsafe impl NtStruct for DbgkSilostate {}

const _: () = {
    assert!(core::mem::size_of::<DbgkSilostate>() == 0x20);
    assert!(core::mem::offset_of!(DbgkSilostate, error_port_lock) == 0x0);
    assert!(core::mem::offset_of!(DbgkSilostate, error_port) == 0x8);
    assert!(core::mem::offset_of!(DbgkSilostate, error_process) == 0x10);
    assert!(core::mem::offset_of!(DbgkSilostate, error_port_registered_event) == 0x18);
};

/// `_SERVERSILO_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ServersiloState(pub i32);

impl ServersiloState {
    pub const SERVERSILO_INITING: Self = Self(0);
    pub const SERVERSILO_STARTED: Self = Self(1);
    pub const SERVERSILO_SHUTTING_DOWN: Self = Self(2);
    pub const SERVERSILO_TERMINATING: Self = Self(3);
    pub const SERVERSILO_TERMINATED: Self = Self(4);
}

impl GuestScalar for ServersiloState {
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

/// `_EWOW64PROCESS` (0x10 bytes).
#[repr(C)]
pub struct Ewow64process {
    /// -> `void`
    pub peb: Field<u64>,
    pub machine: Field<u16>,
    _pad_a: Reserved<0x2>,
    pub ntdll_type: Field<SystemDllType>,
}

unsafe impl NtStruct for Ewow64process {}

const _: () = {
    assert!(core::mem::size_of::<Ewow64process>() == 0x10);
    assert!(core::mem::offset_of!(Ewow64process, peb) == 0x0);
    assert!(core::mem::offset_of!(Ewow64process, machine) == 0x8);
    assert!(core::mem::offset_of!(Ewow64process, ntdll_type) == 0xc);
};

/// `_SYSTEM_DLL_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SystemDllType(pub i32);

impl SystemDllType {
    pub const PS_NATIVE_SYSTEM_DLL: Self = Self(0);
    pub const PS_WOW_X86_SYSTEM_DLL: Self = Self(1);
    pub const PS_WOW_ARM32_SYSTEM_DLL: Self = Self(2);
    pub const PS_WOW_AMD64_SYSTEM_DLL: Self = Self(3);
    pub const PS_WOW_CHPE_X86_SYSTEM_DLL: Self = Self(4);
    pub const PS_VSM_ENCLAVE_RUNTIME_DLL: Self = Self(5);
    pub const PS_SYSTEM_DLL_TOTAL_TYPES: Self = Self(6);
}

impl GuestScalar for SystemDllType {
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

/// `_SILO_USER_SHARED_DATA` (0x270 bytes).
#[repr(C)]
pub struct SiloUserSharedData {
    pub service_session_id: Field<u32>,
    pub active_console_id: Field<u32>,
    pub console_session_foreground_process_id: Field<i64>,
    pub nt_product_type: Field<NtProductType>,
    pub suite_mask: Field<u32>,
    pub shared_user_session_id: Field<u32>,
    pub is_multi_session_sku: Field<u8>,
    _pad_1d: Reserved<0x1>,
    pub nt_system_root: [Field<u16>; 260],
    pub user_mode_global_logger: [Field<u16>; 16],
    _pad_246: Reserved<0x2>,
    pub time_zone_id: Field<u32>,
    pub time_zone_bias_stamp: Field<i32>,
    pub time_zone_bias: KsystemTime,
    _pad_25c: Reserved<0x4>,
    pub time_zone_bias_effective_start: LargeInteger,
    pub time_zone_bias_effective_end: LargeInteger,
}

unsafe impl NtStruct for SiloUserSharedData {}

const _: () = {
    assert!(core::mem::size_of::<SiloUserSharedData>() == 0x270);
    assert!(core::mem::offset_of!(SiloUserSharedData, service_session_id) == 0x0);
    assert!(core::mem::offset_of!(SiloUserSharedData, active_console_id) == 0x4);
    assert!(core::mem::offset_of!(SiloUserSharedData, console_session_foreground_process_id) == 0x8);
    assert!(core::mem::offset_of!(SiloUserSharedData, nt_product_type) == 0x10);
    assert!(core::mem::offset_of!(SiloUserSharedData, suite_mask) == 0x14);
    assert!(core::mem::offset_of!(SiloUserSharedData, shared_user_session_id) == 0x18);
    assert!(core::mem::offset_of!(SiloUserSharedData, is_multi_session_sku) == 0x1c);
    assert!(core::mem::offset_of!(SiloUserSharedData, nt_system_root) == 0x1e);
    assert!(core::mem::offset_of!(SiloUserSharedData, user_mode_global_logger) == 0x226);
    assert!(core::mem::offset_of!(SiloUserSharedData, time_zone_id) == 0x248);
    assert!(core::mem::offset_of!(SiloUserSharedData, time_zone_bias_stamp) == 0x24c);
    assert!(core::mem::offset_of!(SiloUserSharedData, time_zone_bias) == 0x250);
    assert!(core::mem::offset_of!(SiloUserSharedData, time_zone_bias_effective_start) == 0x260);
    assert!(core::mem::offset_of!(SiloUserSharedData, time_zone_bias_effective_end) == 0x268);
};

/// `_TEB32` (0x1000 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `Teb32View1`..`Teb32View2`, alcançadas por `Deref`.
#[repr(C)]
pub struct Teb32 {
    pub nt_tib: NtTib32,
    pub environment_pointer: Field<u32>,
    pub client_id: ClientId32,
    pub active_rpc_handle: Field<u32>,
    pub thread_local_storage_pointer: Field<u32>,
    pub process_environment_block: Field<u32>,
    pub last_error_value: Field<u32>,
    pub count_of_owned_critical_sections: Field<u32>,
    pub csr_client_thread: Field<u32>,
    pub win32_thread_info: Field<u32>,
    pub user32_reserved: [Field<u32>; 26],
    pub user_reserved: [Field<u32>; 5],
    pub wow32_reserved: Field<u32>,
    pub current_locale: Field<u32>,
    pub fp_software_status_register: Field<u32>,
    pub reserved_for_debugger_instrumentation: [Field<u32>; 16],
    pub system_reserved1: [Field<u32>; 26],
    pub placeholder_compatibility_mode: Field<i8>,
    pub placeholder_hydration_always_explicit: Field<u8>,
    pub placeholder_reserved: [Field<i8>; 10],
    pub proxied_process_id: Field<u32>,
    pub activation_stack: ActivationContextStack32,
    pub working_on_behalf_ticket: [Field<u8>; 8],
    pub exception_code: Field<i32>,
    pub activation_context_stack_pointer: Field<u32>,
    pub instrumentation_callback_sp: Field<u32>,
    pub instrumentation_callback_previous_pc: Field<u32>,
    pub instrumentation_callback_previous_sp: Field<u32>,
    pub instrumentation_callback_disabled: Field<u8>,
    pub spare_bytes: [Field<u8>; 23],
    pub tx_fs_context: Field<u32>,
    pub gdi_teb_batch: GdiTebBatch32,
    pub real_client_id: ClientId32,
    pub gdi_cached_process_handle: Field<u32>,
    pub gdi_client_pid: Field<u32>,
    pub gdi_client_tid: Field<u32>,
    pub gdi_thread_local_info: Field<u32>,
    pub win32_client_info: [Field<u32>; 62],
    pub gl_dispatch_table: [Field<u32>; 233],
    pub gl_reserved1: [Field<u32>; 29],
    pub gl_reserved2: Field<u32>,
    pub gl_section_info: Field<u32>,
    pub gl_section: Field<u32>,
    pub gl_table: Field<u32>,
    pub gl_current_rc: Field<u32>,
    pub gl_context: Field<u32>,
    pub last_status_value: Field<u32>,
    pub static_unicode_string: String32,
    pub static_unicode_buffer: [Field<u16>; 261],
    _pad_e0a: Reserved<0x2>,
    pub deallocation_stack: Field<u32>,
    pub tls_slots: [Field<u32>; 64],
    pub tls_links: ListEntry32,
    pub vdm: Field<u32>,
    pub reserved_for_nt_rpc: Field<u32>,
    pub dbg_ss_reserved: [Field<u32>; 2],
    pub hard_error_mode: Field<u32>,
    pub instrumentation: [Field<u32>; 9],
    pub activity_id: Guid,
    pub sub_process_tag: Field<u32>,
    pub perflib_data: Field<u32>,
    pub etw_trace_data: Field<u32>,
    pub win_sock_data: Field<u32>,
    pub gdi_batch_count: Field<u32>,
    pub current_ideal_processor: ProcessorNumber,
    pub guaranteed_stack_bytes: Field<u32>,
    pub reserved_for_perf: Field<u32>,
    pub reserved_for_ole: Field<u32>,
    pub waiting_on_loader_lock: Field<u32>,
    pub saved_priority_state: Field<u32>,
    pub reserved_for_code_coverage: Field<u32>,
    pub thread_pool_data: Field<u32>,
    pub tls_expansion_slots: Field<u32>,
    pub mui_generation: Field<u32>,
    pub is_impersonating: Field<u32>,
    pub nls_cache: Field<u32>,
    pub p_shim_data: Field<u32>,
    pub heap_data: Field<u32>,
    pub current_transaction_handle: Field<u32>,
    pub active_frame: Field<u32>,
    pub fls_data: Field<u32>,
    pub preferred_languages: Field<u32>,
    pub user_pref_languages: Field<u32>,
    pub merged_pref_languages: Field<u32>,
    pub mui_impersonation: Field<u32>,
    pub cross_teb_flags: Field<u16>,
    pub same_teb_flags: Field<u16>,
    pub txn_scope_enter_callback: Field<u32>,
    pub txn_scope_exit_callback: Field<u32>,
    pub txn_scope_context: Field<u32>,
    pub lock_count: Field<u32>,
    pub wow_teb_offset: Field<i32>,
    pub resource_ret_value: Field<u32>,
    pub reserved_for_wdf: Field<u32>,
    pub reserved_for_crt: Field<u64>,
    pub effective_container_id: Guid,
}

/// Vista 1 de `_TEB32` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct Teb32View1 {
    _align: [u64; 0],
    _pad_0: Reserved<0xf74>,
    pub ideal_processor_value: Field<u32>,
    _pad_f78: Reserved<0x88>,
}

/// Vista 2 de `_TEB32` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct Teb32View2 {
    _align: [u64; 0],
    _pad_0: Reserved<0xf74>,
    pub reserved_pad0: Field<u8>,
    pub reserved_pad1: Field<u8>,
    pub reserved_pad2: Field<u8>,
    pub ideal_processor: Field<u8>,
    _pad_f78: Reserved<0x88>,
}

impl core::ops::Deref for Teb32 {
    type Target = Teb32View1;
    #[inline(always)]
    fn deref(&self) -> &Teb32View1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<Teb32View1>() }
    }
}

impl core::ops::Deref for Teb32View1 {
    type Target = Teb32View2;
    #[inline(always)]
    fn deref(&self) -> &Teb32View2 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<Teb32View2>() }
    }
}

unsafe impl NtStruct for Teb32 {}

impl Teb32 {
    /// `SpareCrossTebBits`: bits 0..=15 de `cross_teb_flags`.
    pub const SPARE_CROSS_TEB_BITS_SHIFT: u32 = 0;
    pub const SPARE_CROSS_TEB_BITS_MASK: u16 = 0xffff;
    #[inline(always)]
    pub fn spare_cross_teb_bits(&self) -> u16 {
        self.cross_teb_flags.bits(0, 16) as u16
    }
    #[inline(always)]
    pub fn set_spare_cross_teb_bits(&self, value: u16) {
        self.cross_teb_flags.set_bits(0, 16, value as u64)
    }
    /// `SafeThunkCall`: bits 0..=0 de `same_teb_flags`.
    pub const SAFE_THUNK_CALL_SHIFT: u32 = 0;
    pub const SAFE_THUNK_CALL_MASK: u16 = 0x1;
    #[inline(always)]
    pub fn safe_thunk_call(&self) -> u16 {
        self.same_teb_flags.bits(0, 1) as u16
    }
    #[inline(always)]
    pub fn set_safe_thunk_call(&self, value: u16) {
        self.same_teb_flags.set_bits(0, 1, value as u64)
    }
    /// `InDebugPrint`: bits 1..=1 de `same_teb_flags`.
    pub const IN_DEBUG_PRINT_SHIFT: u32 = 1;
    pub const IN_DEBUG_PRINT_MASK: u16 = 0x2;
    #[inline(always)]
    pub fn in_debug_print(&self) -> u16 {
        self.same_teb_flags.bits(1, 1) as u16
    }
    #[inline(always)]
    pub fn set_in_debug_print(&self, value: u16) {
        self.same_teb_flags.set_bits(1, 1, value as u64)
    }
    /// `HasFiberData`: bits 2..=2 de `same_teb_flags`.
    pub const HAS_FIBER_DATA_SHIFT: u32 = 2;
    pub const HAS_FIBER_DATA_MASK: u16 = 0x4;
    #[inline(always)]
    pub fn has_fiber_data(&self) -> u16 {
        self.same_teb_flags.bits(2, 1) as u16
    }
    #[inline(always)]
    pub fn set_has_fiber_data(&self, value: u16) {
        self.same_teb_flags.set_bits(2, 1, value as u64)
    }
    /// `SkipThreadAttach`: bits 3..=3 de `same_teb_flags`.
    pub const SKIP_THREAD_ATTACH_SHIFT: u32 = 3;
    pub const SKIP_THREAD_ATTACH_MASK: u16 = 0x8;
    #[inline(always)]
    pub fn skip_thread_attach(&self) -> u16 {
        self.same_teb_flags.bits(3, 1) as u16
    }
    #[inline(always)]
    pub fn set_skip_thread_attach(&self, value: u16) {
        self.same_teb_flags.set_bits(3, 1, value as u64)
    }
    /// `WerInShipAssertCode`: bits 4..=4 de `same_teb_flags`.
    pub const WER_IN_SHIP_ASSERT_CODE_SHIFT: u32 = 4;
    pub const WER_IN_SHIP_ASSERT_CODE_MASK: u16 = 0x10;
    #[inline(always)]
    pub fn wer_in_ship_assert_code(&self) -> u16 {
        self.same_teb_flags.bits(4, 1) as u16
    }
    #[inline(always)]
    pub fn set_wer_in_ship_assert_code(&self, value: u16) {
        self.same_teb_flags.set_bits(4, 1, value as u64)
    }
    /// `RanProcessInit`: bits 5..=5 de `same_teb_flags`.
    pub const RAN_PROCESS_INIT_SHIFT: u32 = 5;
    pub const RAN_PROCESS_INIT_MASK: u16 = 0x20;
    #[inline(always)]
    pub fn ran_process_init(&self) -> u16 {
        self.same_teb_flags.bits(5, 1) as u16
    }
    #[inline(always)]
    pub fn set_ran_process_init(&self, value: u16) {
        self.same_teb_flags.set_bits(5, 1, value as u64)
    }
    /// `ClonedThread`: bits 6..=6 de `same_teb_flags`.
    pub const CLONED_THREAD_SHIFT: u32 = 6;
    pub const CLONED_THREAD_MASK: u16 = 0x40;
    #[inline(always)]
    pub fn cloned_thread(&self) -> u16 {
        self.same_teb_flags.bits(6, 1) as u16
    }
    #[inline(always)]
    pub fn set_cloned_thread(&self, value: u16) {
        self.same_teb_flags.set_bits(6, 1, value as u64)
    }
    /// `SuppressDebugMsg`: bits 7..=7 de `same_teb_flags`.
    pub const SUPPRESS_DEBUG_MSG_SHIFT: u32 = 7;
    pub const SUPPRESS_DEBUG_MSG_MASK: u16 = 0x80;
    #[inline(always)]
    pub fn suppress_debug_msg(&self) -> u16 {
        self.same_teb_flags.bits(7, 1) as u16
    }
    #[inline(always)]
    pub fn set_suppress_debug_msg(&self, value: u16) {
        self.same_teb_flags.set_bits(7, 1, value as u64)
    }
    /// `DisableUserStackWalk`: bits 8..=8 de `same_teb_flags`.
    pub const DISABLE_USER_STACK_WALK_SHIFT: u32 = 8;
    pub const DISABLE_USER_STACK_WALK_MASK: u16 = 0x100;
    #[inline(always)]
    pub fn disable_user_stack_walk(&self) -> u16 {
        self.same_teb_flags.bits(8, 1) as u16
    }
    #[inline(always)]
    pub fn set_disable_user_stack_walk(&self, value: u16) {
        self.same_teb_flags.set_bits(8, 1, value as u64)
    }
    /// `RtlExceptionAttached`: bits 9..=9 de `same_teb_flags`.
    pub const RTL_EXCEPTION_ATTACHED_SHIFT: u32 = 9;
    pub const RTL_EXCEPTION_ATTACHED_MASK: u16 = 0x200;
    #[inline(always)]
    pub fn rtl_exception_attached(&self) -> u16 {
        self.same_teb_flags.bits(9, 1) as u16
    }
    #[inline(always)]
    pub fn set_rtl_exception_attached(&self, value: u16) {
        self.same_teb_flags.set_bits(9, 1, value as u64)
    }
    /// `InitialThread`: bits 10..=10 de `same_teb_flags`.
    pub const INITIAL_THREAD_SHIFT: u32 = 10;
    pub const INITIAL_THREAD_MASK: u16 = 0x400;
    #[inline(always)]
    pub fn initial_thread(&self) -> u16 {
        self.same_teb_flags.bits(10, 1) as u16
    }
    #[inline(always)]
    pub fn set_initial_thread(&self, value: u16) {
        self.same_teb_flags.set_bits(10, 1, value as u64)
    }
    /// `SessionAware`: bits 11..=11 de `same_teb_flags`.
    pub const SESSION_AWARE_SHIFT: u32 = 11;
    pub const SESSION_AWARE_MASK: u16 = 0x800;
    #[inline(always)]
    pub fn session_aware(&self) -> u16 {
        self.same_teb_flags.bits(11, 1) as u16
    }
    #[inline(always)]
    pub fn set_session_aware(&self, value: u16) {
        self.same_teb_flags.set_bits(11, 1, value as u64)
    }
    /// `LoadOwner`: bits 12..=12 de `same_teb_flags`.
    pub const LOAD_OWNER_SHIFT: u32 = 12;
    pub const LOAD_OWNER_MASK: u16 = 0x1000;
    #[inline(always)]
    pub fn load_owner(&self) -> u16 {
        self.same_teb_flags.bits(12, 1) as u16
    }
    #[inline(always)]
    pub fn set_load_owner(&self, value: u16) {
        self.same_teb_flags.set_bits(12, 1, value as u64)
    }
    /// `LoaderWorker`: bits 13..=13 de `same_teb_flags`.
    pub const LOADER_WORKER_SHIFT: u32 = 13;
    pub const LOADER_WORKER_MASK: u16 = 0x2000;
    #[inline(always)]
    pub fn loader_worker(&self) -> u16 {
        self.same_teb_flags.bits(13, 1) as u16
    }
    #[inline(always)]
    pub fn set_loader_worker(&self, value: u16) {
        self.same_teb_flags.set_bits(13, 1, value as u64)
    }
    /// `SkipLoaderInit`: bits 14..=14 de `same_teb_flags`.
    pub const SKIP_LOADER_INIT_SHIFT: u32 = 14;
    pub const SKIP_LOADER_INIT_MASK: u16 = 0x4000;
    #[inline(always)]
    pub fn skip_loader_init(&self) -> u16 {
        self.same_teb_flags.bits(14, 1) as u16
    }
    #[inline(always)]
    pub fn set_skip_loader_init(&self, value: u16) {
        self.same_teb_flags.set_bits(14, 1, value as u64)
    }
    /// `SpareSameTebBits`: bits 15..=15 de `same_teb_flags`.
    pub const SPARE_SAME_TEB_BITS_SHIFT: u32 = 15;
    pub const SPARE_SAME_TEB_BITS_MASK: u16 = 0x8000;
    #[inline(always)]
    pub fn spare_same_teb_bits(&self) -> u16 {
        self.same_teb_flags.bits(15, 1) as u16
    }
    #[inline(always)]
    pub fn set_spare_same_teb_bits(&self, value: u16) {
        self.same_teb_flags.set_bits(15, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<Teb32>() == 0x1000);
    assert!(core::mem::offset_of!(Teb32, nt_tib) == 0x0);
    assert!(core::mem::offset_of!(Teb32, environment_pointer) == 0x1c);
    assert!(core::mem::offset_of!(Teb32, client_id) == 0x20);
    assert!(core::mem::offset_of!(Teb32, active_rpc_handle) == 0x28);
    assert!(core::mem::offset_of!(Teb32, thread_local_storage_pointer) == 0x2c);
    assert!(core::mem::offset_of!(Teb32, process_environment_block) == 0x30);
    assert!(core::mem::offset_of!(Teb32, last_error_value) == 0x34);
    assert!(core::mem::offset_of!(Teb32, count_of_owned_critical_sections) == 0x38);
    assert!(core::mem::offset_of!(Teb32, csr_client_thread) == 0x3c);
    assert!(core::mem::offset_of!(Teb32, win32_thread_info) == 0x40);
    assert!(core::mem::offset_of!(Teb32, user32_reserved) == 0x44);
    assert!(core::mem::offset_of!(Teb32, user_reserved) == 0xac);
    assert!(core::mem::offset_of!(Teb32, wow32_reserved) == 0xc0);
    assert!(core::mem::offset_of!(Teb32, current_locale) == 0xc4);
    assert!(core::mem::offset_of!(Teb32, fp_software_status_register) == 0xc8);
    assert!(core::mem::offset_of!(Teb32, reserved_for_debugger_instrumentation) == 0xcc);
    assert!(core::mem::offset_of!(Teb32, system_reserved1) == 0x10c);
    assert!(core::mem::offset_of!(Teb32, placeholder_compatibility_mode) == 0x174);
    assert!(core::mem::offset_of!(Teb32, placeholder_hydration_always_explicit) == 0x175);
    assert!(core::mem::offset_of!(Teb32, placeholder_reserved) == 0x176);
    assert!(core::mem::offset_of!(Teb32, proxied_process_id) == 0x180);
    assert!(core::mem::offset_of!(Teb32, activation_stack) == 0x184);
    assert!(core::mem::offset_of!(Teb32, working_on_behalf_ticket) == 0x19c);
    assert!(core::mem::offset_of!(Teb32, exception_code) == 0x1a4);
    assert!(core::mem::offset_of!(Teb32, activation_context_stack_pointer) == 0x1a8);
    assert!(core::mem::offset_of!(Teb32, instrumentation_callback_sp) == 0x1ac);
    assert!(core::mem::offset_of!(Teb32, instrumentation_callback_previous_pc) == 0x1b0);
    assert!(core::mem::offset_of!(Teb32, instrumentation_callback_previous_sp) == 0x1b4);
    assert!(core::mem::offset_of!(Teb32, instrumentation_callback_disabled) == 0x1b8);
    assert!(core::mem::offset_of!(Teb32, spare_bytes) == 0x1b9);
    assert!(core::mem::offset_of!(Teb32, tx_fs_context) == 0x1d0);
    assert!(core::mem::offset_of!(Teb32, gdi_teb_batch) == 0x1d4);
    assert!(core::mem::offset_of!(Teb32, real_client_id) == 0x6b4);
    assert!(core::mem::offset_of!(Teb32, gdi_cached_process_handle) == 0x6bc);
    assert!(core::mem::offset_of!(Teb32, gdi_client_pid) == 0x6c0);
    assert!(core::mem::offset_of!(Teb32, gdi_client_tid) == 0x6c4);
    assert!(core::mem::offset_of!(Teb32, gdi_thread_local_info) == 0x6c8);
    assert!(core::mem::offset_of!(Teb32, win32_client_info) == 0x6cc);
    assert!(core::mem::offset_of!(Teb32, gl_dispatch_table) == 0x7c4);
    assert!(core::mem::offset_of!(Teb32, gl_reserved1) == 0xb68);
    assert!(core::mem::offset_of!(Teb32, gl_reserved2) == 0xbdc);
    assert!(core::mem::offset_of!(Teb32, gl_section_info) == 0xbe0);
    assert!(core::mem::offset_of!(Teb32, gl_section) == 0xbe4);
    assert!(core::mem::offset_of!(Teb32, gl_table) == 0xbe8);
    assert!(core::mem::offset_of!(Teb32, gl_current_rc) == 0xbec);
    assert!(core::mem::offset_of!(Teb32, gl_context) == 0xbf0);
    assert!(core::mem::offset_of!(Teb32, last_status_value) == 0xbf4);
    assert!(core::mem::offset_of!(Teb32, static_unicode_string) == 0xbf8);
    assert!(core::mem::offset_of!(Teb32, static_unicode_buffer) == 0xc00);
    assert!(core::mem::offset_of!(Teb32, deallocation_stack) == 0xe0c);
    assert!(core::mem::offset_of!(Teb32, tls_slots) == 0xe10);
    assert!(core::mem::offset_of!(Teb32, tls_links) == 0xf10);
    assert!(core::mem::offset_of!(Teb32, vdm) == 0xf18);
    assert!(core::mem::offset_of!(Teb32, reserved_for_nt_rpc) == 0xf1c);
    assert!(core::mem::offset_of!(Teb32, dbg_ss_reserved) == 0xf20);
    assert!(core::mem::offset_of!(Teb32, hard_error_mode) == 0xf28);
    assert!(core::mem::offset_of!(Teb32, instrumentation) == 0xf2c);
    assert!(core::mem::offset_of!(Teb32, activity_id) == 0xf50);
    assert!(core::mem::offset_of!(Teb32, sub_process_tag) == 0xf60);
    assert!(core::mem::offset_of!(Teb32, perflib_data) == 0xf64);
    assert!(core::mem::offset_of!(Teb32, etw_trace_data) == 0xf68);
    assert!(core::mem::offset_of!(Teb32, win_sock_data) == 0xf6c);
    assert!(core::mem::offset_of!(Teb32, gdi_batch_count) == 0xf70);
    assert!(core::mem::offset_of!(Teb32, current_ideal_processor) == 0xf74);
    assert!(core::mem::offset_of!(Teb32, guaranteed_stack_bytes) == 0xf78);
    assert!(core::mem::offset_of!(Teb32, reserved_for_perf) == 0xf7c);
    assert!(core::mem::offset_of!(Teb32, reserved_for_ole) == 0xf80);
    assert!(core::mem::offset_of!(Teb32, waiting_on_loader_lock) == 0xf84);
    assert!(core::mem::offset_of!(Teb32, saved_priority_state) == 0xf88);
    assert!(core::mem::offset_of!(Teb32, reserved_for_code_coverage) == 0xf8c);
    assert!(core::mem::offset_of!(Teb32, thread_pool_data) == 0xf90);
    assert!(core::mem::offset_of!(Teb32, tls_expansion_slots) == 0xf94);
    assert!(core::mem::offset_of!(Teb32, mui_generation) == 0xf98);
    assert!(core::mem::offset_of!(Teb32, is_impersonating) == 0xf9c);
    assert!(core::mem::offset_of!(Teb32, nls_cache) == 0xfa0);
    assert!(core::mem::offset_of!(Teb32, p_shim_data) == 0xfa4);
    assert!(core::mem::offset_of!(Teb32, heap_data) == 0xfa8);
    assert!(core::mem::offset_of!(Teb32, current_transaction_handle) == 0xfac);
    assert!(core::mem::offset_of!(Teb32, active_frame) == 0xfb0);
    assert!(core::mem::offset_of!(Teb32, fls_data) == 0xfb4);
    assert!(core::mem::offset_of!(Teb32, preferred_languages) == 0xfb8);
    assert!(core::mem::offset_of!(Teb32, user_pref_languages) == 0xfbc);
    assert!(core::mem::offset_of!(Teb32, merged_pref_languages) == 0xfc0);
    assert!(core::mem::offset_of!(Teb32, mui_impersonation) == 0xfc4);
    assert!(core::mem::offset_of!(Teb32, cross_teb_flags) == 0xfc8);
    assert!(core::mem::offset_of!(Teb32, same_teb_flags) == 0xfca);
    assert!(core::mem::offset_of!(Teb32, txn_scope_enter_callback) == 0xfcc);
    assert!(core::mem::offset_of!(Teb32, txn_scope_exit_callback) == 0xfd0);
    assert!(core::mem::offset_of!(Teb32, txn_scope_context) == 0xfd4);
    assert!(core::mem::offset_of!(Teb32, lock_count) == 0xfd8);
    assert!(core::mem::offset_of!(Teb32, wow_teb_offset) == 0xfdc);
    assert!(core::mem::offset_of!(Teb32, resource_ret_value) == 0xfe0);
    assert!(core::mem::offset_of!(Teb32, reserved_for_wdf) == 0xfe4);
    assert!(core::mem::offset_of!(Teb32, reserved_for_crt) == 0xfe8);
    assert!(core::mem::offset_of!(Teb32, effective_container_id) == 0xff0);
    assert!(core::mem::size_of::<Teb32View1>() == 0x1000);
    assert!(core::mem::align_of::<Teb32View1>() == core::mem::align_of::<Teb32>());
    assert!(core::mem::offset_of!(Teb32View1, ideal_processor_value) == 0xf74);
    assert!(core::mem::size_of::<Teb32View2>() == 0x1000);
    assert!(core::mem::align_of::<Teb32View2>() == core::mem::align_of::<Teb32>());
    assert!(core::mem::offset_of!(Teb32View2, reserved_pad0) == 0xf74);
    assert!(core::mem::offset_of!(Teb32View2, reserved_pad1) == 0xf75);
    assert!(core::mem::offset_of!(Teb32View2, reserved_pad2) == 0xf76);
    assert!(core::mem::offset_of!(Teb32View2, ideal_processor) == 0xf77);
};

/// `_CLIENT_ID32` (0x8 bytes).
#[repr(C)]
pub struct ClientId32 {
    pub unique_process: Field<u32>,
    pub unique_thread: Field<u32>,
}

unsafe impl NtStruct for ClientId32 {}

const _: () = {
    assert!(core::mem::size_of::<ClientId32>() == 0x8);
    assert!(core::mem::offset_of!(ClientId32, unique_process) == 0x0);
    assert!(core::mem::offset_of!(ClientId32, unique_thread) == 0x4);
};

/// `_ACTIVATION_CONTEXT_STACK32` (0x18 bytes).
#[repr(C)]
pub struct ActivationContextStack32 {
    pub active_frame: Field<u32>,
    pub frame_list_cache: ListEntry32,
    pub flags: Field<u32>,
    pub next_cookie_sequence_number: Field<u32>,
    pub stack_id: Field<u32>,
}

unsafe impl NtStruct for ActivationContextStack32 {}

const _: () = {
    assert!(core::mem::size_of::<ActivationContextStack32>() == 0x18);
    assert!(core::mem::offset_of!(ActivationContextStack32, active_frame) == 0x0);
    assert!(core::mem::offset_of!(ActivationContextStack32, frame_list_cache) == 0x4);
    assert!(core::mem::offset_of!(ActivationContextStack32, flags) == 0xc);
    assert!(core::mem::offset_of!(ActivationContextStack32, next_cookie_sequence_number) == 0x10);
    assert!(core::mem::offset_of!(ActivationContextStack32, stack_id) == 0x14);
};

/// `_GDI_TEB_BATCH32` (0x4e0 bytes).
#[repr(C)]
pub struct GdiTebBatch32 {
    pub bitfield_0: Field<u32>,
    pub hdc: Field<u32>,
    pub buffer: [Field<u32>; 310],
}

unsafe impl NtStruct for GdiTebBatch32 {}

impl GdiTebBatch32 {
    /// `Offset`: bits 0..=30 de `bitfield_0`.
    pub const OFFSET_SHIFT: u32 = 0;
    pub const OFFSET_MASK: u32 = 0x7fffffff;
    #[inline(always)]
    pub fn offset(&self) -> u32 {
        self.bitfield_0.bits(0, 31) as u32
    }
    #[inline(always)]
    pub fn set_offset(&self, value: u32) {
        self.bitfield_0.set_bits(0, 31, value as u64)
    }
    /// `HasRenderingCommand`: bits 31..=31 de `bitfield_0`.
    pub const HAS_RENDERING_COMMAND_SHIFT: u32 = 31;
    pub const HAS_RENDERING_COMMAND_MASK: u32 = 0x80000000;
    #[inline(always)]
    pub fn has_rendering_command(&self) -> u32 {
        self.bitfield_0.bits(31, 1) as u32
    }
    #[inline(always)]
    pub fn set_has_rendering_command(&self, value: u32) {
        self.bitfield_0.set_bits(31, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<GdiTebBatch32>() == 0x4e0);
    assert!(core::mem::offset_of!(GdiTebBatch32, bitfield_0) == 0x0);
    assert!(core::mem::offset_of!(GdiTebBatch32, hdc) == 0x4);
    assert!(core::mem::offset_of!(GdiTebBatch32, buffer) == 0x8);
};
