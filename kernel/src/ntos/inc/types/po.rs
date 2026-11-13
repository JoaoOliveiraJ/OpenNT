//! Po: estado de energia e gerenciamento de processador.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_SYSTEM_POWER_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SystemPowerState(pub i32);

impl SystemPowerState {
    pub const POWER_SYSTEM_UNSPECIFIED: Self = Self(0);
    pub const POWER_SYSTEM_WORKING: Self = Self(1);
    pub const POWER_SYSTEM_SLEEPING1: Self = Self(2);
    pub const POWER_SYSTEM_SLEEPING2: Self = Self(3);
    pub const POWER_SYSTEM_SLEEPING3: Self = Self(4);
    pub const POWER_SYSTEM_HIBERNATE: Self = Self(5);
    pub const POWER_SYSTEM_SHUTDOWN: Self = Self(6);
    pub const POWER_SYSTEM_MAXIMUM: Self = Self(7);
}

impl GuestScalar for SystemPowerState {
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

/// `_POWER_STATE_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PowerStateType(pub i32);

impl PowerStateType {
    pub const SYSTEM_POWER_STATE: Self = Self(0);
    pub const DEVICE_POWER_STATE: Self = Self(1);
}

impl GuestScalar for PowerStateType {
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

/// `_POWER_STATE` (0x4 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `PowerStateView1`, alcançada por `Deref`.
#[repr(C)]
pub struct PowerState {
    pub system_state: Field<SystemPowerState>,
}

/// Vista 1 de `_POWER_STATE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct PowerStateView1 {
    pub device_state: Field<DevicePowerState>,
}

impl core::ops::Deref for PowerState {
    type Target = PowerStateView1;
    #[inline(always)]
    fn deref(&self) -> &PowerStateView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<PowerStateView1>() }
    }
}

unsafe impl NtStruct for PowerState {}

const _: () = {
    assert!(core::mem::size_of::<PowerState>() == 0x4);
    assert!(core::mem::offset_of!(PowerState, system_state) == 0x0);
    assert!(core::mem::size_of::<PowerStateView1>() == 0x4);
    assert!(core::mem::align_of::<PowerStateView1>() == core::mem::align_of::<PowerState>());
    assert!(core::mem::offset_of!(PowerStateView1, device_state) == 0x0);
};

/// `POWER_ACTION`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct PowerAction(pub i32);

impl PowerAction {
    pub const POWER_ACTION_NONE: Self = Self(0);
    pub const POWER_ACTION_RESERVED: Self = Self(1);
    pub const POWER_ACTION_SLEEP: Self = Self(2);
    pub const POWER_ACTION_HIBERNATE: Self = Self(3);
    pub const POWER_ACTION_SHUTDOWN: Self = Self(4);
    pub const POWER_ACTION_SHUTDOWN_RESET: Self = Self(5);
    pub const POWER_ACTION_SHUTDOWN_OFF: Self = Self(6);
    pub const POWER_ACTION_WARM_EJECT: Self = Self(7);
    pub const POWER_ACTION_DISPLAY_OFF: Self = Self(8);
}

impl GuestScalar for PowerAction {
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

/// `_PROCESSOR_POWER_STATE` (0x200 bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `ProcessorPowerStateView1`, alcançada por `Deref`.
#[repr(C)]
pub struct ProcessorPowerState {
    /// -> `_PPM_IDLE_STATES`
    pub idle_states: Field<u64>,
    /// -> `_PROC_IDLE_ACCOUNTING`
    pub idle_accounting: Field<u64>,
    pub idle_time_last: Field<u64>,
    pub idle_time_total: Field<u64>,
    pub idle_time_entry: Field<u64>,
    pub idle_time_expiration: Field<u64>,
    pub non_interruptible_transition: Field<u8>,
    pub pep_woken_transition: Field<u8>,
    pub hv_target_state: Field<u8>,
    pub soft_parked: Field<u8>,
    pub target_idle_state: Field<u32>,
    pub idle_policy: ProcIdlePolicy,
    _pad_3e: Reserved<0x2>,
    pub synchronization: PpmIdleSynchronizationState,
    _pad_44: Reserved<0x4>,
    pub perf_feedback: ProcFeedback,
    pub hypervisor: Field<ProcHypervisorState>,
    pub last_sys_time: Field<u32>,
    pub wmi_dispatch_ptr: Field<u64>,
    pub wmi_interface_enabled: Field<i32>,
    _pad_ec: Reserved<0x4>,
    pub ffh_throttle_state_info: PpmFfhThrottleStateInfo,
    pub perf_action_dpc: Kdpc,
    pub perf_action_mask: Field<i32>,
    _pad_154: Reserved<0x4>,
    pub hv_idle_check: ProcIdleSnap,
    pub check_context: ProcPerfCheckContext,
    /// -> `_PPM_CONCURRENCY_ACCOUNTING`
    pub concurrency: Field<u64>,
    /// -> `_PPM_CONCURRENCY_ACCOUNTING`
    pub class_concurrency: Field<u64>,
    pub architectural_efficiency_class: Field<u8>,
    pub performance_scheduling_class: Field<u8>,
    pub efficiency_scheduling_class: Field<u8>,
    pub unused: Field<u8>,
    pub parked: Field<u8>,
    pub long_prior_qos_period: Field<u8>,
    _pad_1be: Reserved<0x2>,
    pub snap_time_last: Field<u64>,
    pub active_time: Field<u64>,
    pub total_time: Field<u64>,
    /// -> `_POP_FX_DEVICE`
    pub fx_device: Field<u64>,
    pub last_qos_transtion_tsc: Field<u64>,
    pub qos_transition_hysteresis: Field<u64>,
    pub requested_qos_class: Field<KheteroCpuQos>,
    pub resolved_qos_class: Field<KheteroCpuQos>,
    pub qos_equivalency_mask: Field<u16>,
    pub hw_feedback_table_index: Field<u16>,
    pub hw_feedback_park_hint: Field<u8>,
    pub hw_feedback_performance_class: Field<u8>,
    pub hw_feedback_efficiency_class: Field<u8>,
    pub hetero_core_type: Field<u8>,
}

/// Vista 1 de `_PROCESSOR_POWER_STATE` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct ProcessorPowerStateView1 {
    _pad_0: Reserved<0x1c0>,
    pub energy_consumed: Field<u64>,
    _pad_1c8: Reserved<0x38>,
}

impl core::ops::Deref for ProcessorPowerState {
    type Target = ProcessorPowerStateView1;
    #[inline(always)]
    fn deref(&self) -> &ProcessorPowerStateView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<ProcessorPowerStateView1>() }
    }
}

unsafe impl NtStruct for ProcessorPowerState {}

const _: () = {
    assert!(core::mem::size_of::<ProcessorPowerState>() == 0x200);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_states) == 0x0);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_accounting) == 0x8);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_time_last) == 0x10);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_time_total) == 0x18);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_time_entry) == 0x20);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_time_expiration) == 0x28);
    assert!(core::mem::offset_of!(ProcessorPowerState, non_interruptible_transition) == 0x30);
    assert!(core::mem::offset_of!(ProcessorPowerState, pep_woken_transition) == 0x31);
    assert!(core::mem::offset_of!(ProcessorPowerState, hv_target_state) == 0x32);
    assert!(core::mem::offset_of!(ProcessorPowerState, soft_parked) == 0x33);
    assert!(core::mem::offset_of!(ProcessorPowerState, target_idle_state) == 0x34);
    assert!(core::mem::offset_of!(ProcessorPowerState, idle_policy) == 0x38);
    assert!(core::mem::offset_of!(ProcessorPowerState, synchronization) == 0x40);
    assert!(core::mem::offset_of!(ProcessorPowerState, perf_feedback) == 0x48);
    assert!(core::mem::offset_of!(ProcessorPowerState, hypervisor) == 0xd8);
    assert!(core::mem::offset_of!(ProcessorPowerState, last_sys_time) == 0xdc);
    assert!(core::mem::offset_of!(ProcessorPowerState, wmi_dispatch_ptr) == 0xe0);
    assert!(core::mem::offset_of!(ProcessorPowerState, wmi_interface_enabled) == 0xe8);
    assert!(core::mem::offset_of!(ProcessorPowerState, ffh_throttle_state_info) == 0xf0);
    assert!(core::mem::offset_of!(ProcessorPowerState, perf_action_dpc) == 0x110);
    assert!(core::mem::offset_of!(ProcessorPowerState, perf_action_mask) == 0x150);
    assert!(core::mem::offset_of!(ProcessorPowerState, hv_idle_check) == 0x158);
    assert!(core::mem::offset_of!(ProcessorPowerState, check_context) == 0x168);
    assert!(core::mem::offset_of!(ProcessorPowerState, concurrency) == 0x1a8);
    assert!(core::mem::offset_of!(ProcessorPowerState, class_concurrency) == 0x1b0);
    assert!(core::mem::offset_of!(ProcessorPowerState, architectural_efficiency_class) == 0x1b8);
    assert!(core::mem::offset_of!(ProcessorPowerState, performance_scheduling_class) == 0x1b9);
    assert!(core::mem::offset_of!(ProcessorPowerState, efficiency_scheduling_class) == 0x1ba);
    assert!(core::mem::offset_of!(ProcessorPowerState, unused) == 0x1bb);
    assert!(core::mem::offset_of!(ProcessorPowerState, parked) == 0x1bc);
    assert!(core::mem::offset_of!(ProcessorPowerState, long_prior_qos_period) == 0x1bd);
    assert!(core::mem::offset_of!(ProcessorPowerState, snap_time_last) == 0x1c0);
    assert!(core::mem::offset_of!(ProcessorPowerState, active_time) == 0x1c8);
    assert!(core::mem::offset_of!(ProcessorPowerState, total_time) == 0x1d0);
    assert!(core::mem::offset_of!(ProcessorPowerState, fx_device) == 0x1d8);
    assert!(core::mem::offset_of!(ProcessorPowerState, last_qos_transtion_tsc) == 0x1e0);
    assert!(core::mem::offset_of!(ProcessorPowerState, qos_transition_hysteresis) == 0x1e8);
    assert!(core::mem::offset_of!(ProcessorPowerState, requested_qos_class) == 0x1f0);
    assert!(core::mem::offset_of!(ProcessorPowerState, resolved_qos_class) == 0x1f4);
    assert!(core::mem::offset_of!(ProcessorPowerState, qos_equivalency_mask) == 0x1f8);
    assert!(core::mem::offset_of!(ProcessorPowerState, hw_feedback_table_index) == 0x1fa);
    assert!(core::mem::offset_of!(ProcessorPowerState, hw_feedback_park_hint) == 0x1fc);
    assert!(core::mem::offset_of!(ProcessorPowerState, hw_feedback_performance_class) == 0x1fd);
    assert!(core::mem::offset_of!(ProcessorPowerState, hw_feedback_efficiency_class) == 0x1fe);
    assert!(core::mem::offset_of!(ProcessorPowerState, hetero_core_type) == 0x1ff);
    assert!(core::mem::size_of::<ProcessorPowerStateView1>() == 0x200);
    assert!(core::mem::align_of::<ProcessorPowerStateView1>() == core::mem::align_of::<ProcessorPowerState>());
    assert!(core::mem::offset_of!(ProcessorPowerStateView1, energy_consumed) == 0x1c0);
};

/// `_PROC_IDLE_POLICY` (0x6 bytes).
#[repr(C)]
pub struct ProcIdlePolicy {
    pub promote_percent: Field<u8>,
    pub demote_percent: Field<u8>,
    pub promote_percent_base: Field<u8>,
    pub demote_percent_base: Field<u8>,
    pub allow_scaling: Field<u8>,
    pub force_light_idle: Field<u8>,
}

unsafe impl NtStruct for ProcIdlePolicy {}

const _: () = {
    assert!(core::mem::size_of::<ProcIdlePolicy>() == 0x6);
    assert!(core::mem::offset_of!(ProcIdlePolicy, promote_percent) == 0x0);
    assert!(core::mem::offset_of!(ProcIdlePolicy, demote_percent) == 0x1);
    assert!(core::mem::offset_of!(ProcIdlePolicy, promote_percent_base) == 0x2);
    assert!(core::mem::offset_of!(ProcIdlePolicy, demote_percent_base) == 0x3);
    assert!(core::mem::offset_of!(ProcIdlePolicy, allow_scaling) == 0x4);
    assert!(core::mem::offset_of!(ProcIdlePolicy, force_light_idle) == 0x5);
};

/// `_PPM_IDLE_SYNCHRONIZATION_STATE` (0x4 bytes).
#[repr(C)]
pub struct PpmIdleSynchronizationState {
    pub as_long: Field<i32>,
}

unsafe impl NtStruct for PpmIdleSynchronizationState {}

impl PpmIdleSynchronizationState {
    /// `RefCount`: bits 0..=23 de `as_long`.
    pub const REF_COUNT_SHIFT: u32 = 0;
    pub const REF_COUNT_MASK: u32 = 0xffffff;
    #[inline(always)]
    pub fn ref_count(&self) -> u32 {
        self.as_long.bits(0, 24) as u32
    }
    #[inline(always)]
    pub fn set_ref_count(&self, value: u32) {
        self.as_long.set_bits(0, 24, value as u64)
    }
    /// `State`: bits 24..=31 de `as_long`.
    pub const STATE_SHIFT: u32 = 24;
    pub const STATE_MASK: u32 = 0xff000000;
    #[inline(always)]
    pub fn state(&self) -> u32 {
        self.as_long.bits(24, 8) as u32
    }
    #[inline(always)]
    pub fn set_state(&self, value: u32) {
        self.as_long.set_bits(24, 8, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PpmIdleSynchronizationState>() == 0x4);
    assert!(core::mem::offset_of!(PpmIdleSynchronizationState, as_long) == 0x0);
};

/// `_PROC_FEEDBACK` (0x90 bytes).
#[repr(C)]
pub struct ProcFeedback {
    pub lock: Field<u64>,
    pub cycles_last: Field<u64>,
    pub cycles_active: Field<u64>,
    /// -> `_PROC_FEEDBACK_COUNTER`
    pub counters: [Field<u64>; 2],
    pub last_update_time: Field<u64>,
    pub unscaled_time: Field<u64>,
    pub unaccounted_time: Field<i64>,
    pub scaled_time: [Field<u64>; 2],
    pub unaccounted_kernel_time: Field<u64>,
    pub performance_scaled_kernel_time: Field<u64>,
    pub user_time_last: Field<u32>,
    pub kernel_time_last: Field<u32>,
    pub idle_generation_number_last: Field<u64>,
    pub hv_active_time_last: Field<u64>,
    pub stall_cycles_last: Field<u64>,
    pub stall_time: Field<u64>,
    pub kernel_times_index: Field<u8>,
    pub counter_discards_idle_time: Field<u8>,
    _pad_8a: Reserved<0x6>,
}

unsafe impl NtStruct for ProcFeedback {}

const _: () = {
    assert!(core::mem::size_of::<ProcFeedback>() == 0x90);
    assert!(core::mem::offset_of!(ProcFeedback, lock) == 0x0);
    assert!(core::mem::offset_of!(ProcFeedback, cycles_last) == 0x8);
    assert!(core::mem::offset_of!(ProcFeedback, cycles_active) == 0x10);
    assert!(core::mem::offset_of!(ProcFeedback, counters) == 0x18);
    assert!(core::mem::offset_of!(ProcFeedback, last_update_time) == 0x28);
    assert!(core::mem::offset_of!(ProcFeedback, unscaled_time) == 0x30);
    assert!(core::mem::offset_of!(ProcFeedback, unaccounted_time) == 0x38);
    assert!(core::mem::offset_of!(ProcFeedback, scaled_time) == 0x40);
    assert!(core::mem::offset_of!(ProcFeedback, unaccounted_kernel_time) == 0x50);
    assert!(core::mem::offset_of!(ProcFeedback, performance_scaled_kernel_time) == 0x58);
    assert!(core::mem::offset_of!(ProcFeedback, user_time_last) == 0x60);
    assert!(core::mem::offset_of!(ProcFeedback, kernel_time_last) == 0x64);
    assert!(core::mem::offset_of!(ProcFeedback, idle_generation_number_last) == 0x68);
    assert!(core::mem::offset_of!(ProcFeedback, hv_active_time_last) == 0x70);
    assert!(core::mem::offset_of!(ProcFeedback, stall_cycles_last) == 0x78);
    assert!(core::mem::offset_of!(ProcFeedback, stall_time) == 0x80);
    assert!(core::mem::offset_of!(ProcFeedback, kernel_times_index) == 0x88);
    assert!(core::mem::offset_of!(ProcFeedback, counter_discards_idle_time) == 0x89);
};

/// `_PROC_HYPERVISOR_STATE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct ProcHypervisorState(pub i32);

impl ProcHypervisorState {
    pub const PROC_HYPERVISOR_NONE: Self = Self(0);
    pub const PROC_HYPERVISOR_PRESENT: Self = Self(1);
    pub const PROC_HYPERVISOR_POWER: Self = Self(2);
    pub const PROC_HYPERVISOR_HV_COUNTERS: Self = Self(3);
}

impl GuestScalar for ProcHypervisorState {
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

/// `_PPM_FFH_THROTTLE_STATE_INFO` (0x20 bytes).
#[repr(C)]
pub struct PpmFfhThrottleStateInfo {
    pub enable_logging: Field<u8>,
    _pad_1: Reserved<0x3>,
    pub mismatch_count: Field<u32>,
    pub initialized: Field<u8>,
    _pad_9: Reserved<0x7>,
    pub last_value: Field<u64>,
    pub last_log_tick_count: LargeInteger,
}

unsafe impl NtStruct for PpmFfhThrottleStateInfo {}

const _: () = {
    assert!(core::mem::size_of::<PpmFfhThrottleStateInfo>() == 0x20);
    assert!(core::mem::offset_of!(PpmFfhThrottleStateInfo, enable_logging) == 0x0);
    assert!(core::mem::offset_of!(PpmFfhThrottleStateInfo, mismatch_count) == 0x4);
    assert!(core::mem::offset_of!(PpmFfhThrottleStateInfo, initialized) == 0x8);
    assert!(core::mem::offset_of!(PpmFfhThrottleStateInfo, last_value) == 0x10);
    assert!(core::mem::offset_of!(PpmFfhThrottleStateInfo, last_log_tick_count) == 0x18);
};

/// `_PROC_IDLE_SNAP` (0x10 bytes).
#[repr(C)]
pub struct ProcIdleSnap {
    pub time: Field<u64>,
    pub idle: Field<u64>,
}

unsafe impl NtStruct for ProcIdleSnap {}

const _: () = {
    assert!(core::mem::size_of::<ProcIdleSnap>() == 0x10);
    assert!(core::mem::offset_of!(ProcIdleSnap, time) == 0x0);
    assert!(core::mem::offset_of!(ProcIdleSnap, idle) == 0x8);
};

/// `_PROC_PERF_CHECK_CONTEXT` (0x40 bytes).
#[repr(C)]
pub struct ProcPerfCheckContext {
    /// -> `_PROC_PERF_DOMAIN`
    pub domain: Field<u64>,
    /// -> `_PROC_PERF_CONSTRAINT`
    pub constraint: Field<u64>,
    /// -> `_PROC_PERF_CHECK`
    pub perf_check: Field<u64>,
    /// -> `_PROC_PERF_LOAD`
    pub load: Field<u64>,
    /// -> `_PROC_PERF_HISTORY`
    pub perf_history: Field<u64>,
    pub utility: Field<u32>,
    pub affinitized_utility: Field<u32>,
    pub media_utility: Field<u32>,
    pub latest_affinitized_percent: Field<u16>,
    pub average_performance_percent: Field<u16>,
    pub relative_performance: Field<u32>,
    pub nt_processor: Field<u8>,
    _pad_3d: Reserved<0x3>,
}

unsafe impl NtStruct for ProcPerfCheckContext {}

const _: () = {
    assert!(core::mem::size_of::<ProcPerfCheckContext>() == 0x40);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, domain) == 0x0);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, constraint) == 0x8);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, perf_check) == 0x10);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, load) == 0x18);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, perf_history) == 0x20);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, utility) == 0x28);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, affinitized_utility) == 0x2c);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, media_utility) == 0x30);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, latest_affinitized_percent) == 0x34);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, average_performance_percent) == 0x36);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, relative_performance) == 0x38);
    assert!(core::mem::offset_of!(ProcPerfCheckContext, nt_processor) == 0x3c);
};

/// `_POP_FX_DEVICE` (0x4b8 bytes).
#[repr(C)]
pub struct PopFxDevice {
    pub link: ListEntry,
    /// -> `_IRP`
    pub irp: Field<u64>,
    /// -> `_POP_IRP_DATA`
    pub irp_data: Field<u64>,
    pub status: PopFxDeviceStatus,
    pub power_req_call: Field<i32>,
    pub power_not_req_call: Field<i32>,
    _pad_2c: Reserved<0x4>,
    /// -> `_DEVICE_NODE`
    pub dev_node: Field<u64>,
    /// -> `PEPHANDLE__`
    pub dpm_context: Field<u64>,
    /// -> `_POP_FX_PLUGIN`
    pub plugin: Field<u64>,
    /// -> `PEPHANDLE__`
    pub plugin_handle: Field<u64>,
    /// -> `_POP_FX_PLUGIN`
    pub acpi_plugin: Field<u64>,
    /// -> `PEPHANDLE__`
    pub acpi_plugin_handle: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub device_object: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub target_device: Field<u64>,
    pub callbacks: PopFxDriverCallbacks,
    /// -> `void`
    pub driver_context: Field<u64>,
    pub acpi_link: ListEntry,
    pub device_id: UnicodeString,
    pub common_reference_flags: Field<i32>,
    _pad_ec: Reserved<0x4>,
    pub remove_lock: IoRemoveLock,
    pub acpi_remove_lock: IoRemoveLock,
    pub work_order: PopFxWorkOrder,
    pub idle_lock: Field<u64>,
    pub idle_timer: Ktimer,
    pub idle_dpc: Kdpc,
    pub idle_timeout: Field<u64>,
    pub idle_stamp: Field<u64>,
    /// -> `_DEVICE_OBJECT`
    pub next_irp_device_object: [Field<u64>; 2],
    pub next_irp_power_state: [PowerState; 2],
    /// -> `fn`
    pub next_irp_caller_completion: [Field<u64>; 2],
    /// -> `void`
    pub next_irp_caller_context: [Field<u64>; 2],
    pub irp_complete_event: Kevent,
    /// -> `fn`
    pub power_on_dump_device_callback: Field<u64>,
    pub accounting: PopFxAccounting,
    pub flags: Field<u32>,
    pub component_count: Field<u32>,
    /// -> `_POP_FX_COMPONENT*`
    pub components: Field<u64>,
    pub log_entries: Field<u32>,
    _pad_34c: Reserved<0x4>,
    /// -> `_POP_FX_LOG_ENTRY`
    pub log: Field<u64>,
    pub log_index: Field<i32>,
    _pad_35c: Reserved<0x4>,
    /// -> `_DRIVER_OBJECT`
    pub drips_watchdog_driver_object: Field<u64>,
    pub drips_watchdog_context: PopFxDripsWatchdogContext,
    pub directed_timeout: Field<u32>,
    _pad_394: Reserved<0x4>,
    pub directed_work_order: PopFxWorkOrder,
    pub directed_work_watchdog_info: PopFxWorkOrderWatchdogInfo,
    pub directed_lock: Field<u64>,
    pub directed_transition_call_count: Field<i32>,
    _pad_48c: Reserved<0x4>,
    pub directed_transition_state: PopFxDeviceDirectedTransitionState,
    /// -> `_POP_DEVICE_POWER_PROFILE`
    pub power_profile: Field<u64>,
    pub friendly_name: UnicodeString,
}

unsafe impl NtStruct for PopFxDevice {}

const _: () = {
    assert!(core::mem::size_of::<PopFxDevice>() == 0x4b8);
    assert!(core::mem::offset_of!(PopFxDevice, link) == 0x0);
    assert!(core::mem::offset_of!(PopFxDevice, irp) == 0x10);
    assert!(core::mem::offset_of!(PopFxDevice, irp_data) == 0x18);
    assert!(core::mem::offset_of!(PopFxDevice, status) == 0x20);
    assert!(core::mem::offset_of!(PopFxDevice, power_req_call) == 0x24);
    assert!(core::mem::offset_of!(PopFxDevice, power_not_req_call) == 0x28);
    assert!(core::mem::offset_of!(PopFxDevice, dev_node) == 0x30);
    assert!(core::mem::offset_of!(PopFxDevice, dpm_context) == 0x38);
    assert!(core::mem::offset_of!(PopFxDevice, plugin) == 0x40);
    assert!(core::mem::offset_of!(PopFxDevice, plugin_handle) == 0x48);
    assert!(core::mem::offset_of!(PopFxDevice, acpi_plugin) == 0x50);
    assert!(core::mem::offset_of!(PopFxDevice, acpi_plugin_handle) == 0x58);
    assert!(core::mem::offset_of!(PopFxDevice, device_object) == 0x60);
    assert!(core::mem::offset_of!(PopFxDevice, target_device) == 0x68);
    assert!(core::mem::offset_of!(PopFxDevice, callbacks) == 0x70);
    assert!(core::mem::offset_of!(PopFxDevice, driver_context) == 0xc0);
    assert!(core::mem::offset_of!(PopFxDevice, acpi_link) == 0xc8);
    assert!(core::mem::offset_of!(PopFxDevice, device_id) == 0xd8);
    assert!(core::mem::offset_of!(PopFxDevice, common_reference_flags) == 0xe8);
    assert!(core::mem::offset_of!(PopFxDevice, remove_lock) == 0xf0);
    assert!(core::mem::offset_of!(PopFxDevice, acpi_remove_lock) == 0x110);
    assert!(core::mem::offset_of!(PopFxDevice, work_order) == 0x130);
    assert!(core::mem::offset_of!(PopFxDevice, idle_lock) == 0x168);
    assert!(core::mem::offset_of!(PopFxDevice, idle_timer) == 0x170);
    assert!(core::mem::offset_of!(PopFxDevice, idle_dpc) == 0x1b0);
    assert!(core::mem::offset_of!(PopFxDevice, idle_timeout) == 0x1f0);
    assert!(core::mem::offset_of!(PopFxDevice, idle_stamp) == 0x1f8);
    assert!(core::mem::offset_of!(PopFxDevice, next_irp_device_object) == 0x200);
    assert!(core::mem::offset_of!(PopFxDevice, next_irp_power_state) == 0x210);
    assert!(core::mem::offset_of!(PopFxDevice, next_irp_caller_completion) == 0x218);
    assert!(core::mem::offset_of!(PopFxDevice, next_irp_caller_context) == 0x228);
    assert!(core::mem::offset_of!(PopFxDevice, irp_complete_event) == 0x238);
    assert!(core::mem::offset_of!(PopFxDevice, power_on_dump_device_callback) == 0x250);
    assert!(core::mem::offset_of!(PopFxDevice, accounting) == 0x258);
    assert!(core::mem::offset_of!(PopFxDevice, flags) == 0x338);
    assert!(core::mem::offset_of!(PopFxDevice, component_count) == 0x33c);
    assert!(core::mem::offset_of!(PopFxDevice, components) == 0x340);
    assert!(core::mem::offset_of!(PopFxDevice, log_entries) == 0x348);
    assert!(core::mem::offset_of!(PopFxDevice, log) == 0x350);
    assert!(core::mem::offset_of!(PopFxDevice, log_index) == 0x358);
    assert!(core::mem::offset_of!(PopFxDevice, drips_watchdog_driver_object) == 0x360);
    assert!(core::mem::offset_of!(PopFxDevice, drips_watchdog_context) == 0x368);
    assert!(core::mem::offset_of!(PopFxDevice, directed_timeout) == 0x390);
    assert!(core::mem::offset_of!(PopFxDevice, directed_work_order) == 0x398);
    assert!(core::mem::offset_of!(PopFxDevice, directed_work_watchdog_info) == 0x3d0);
    assert!(core::mem::offset_of!(PopFxDevice, directed_lock) == 0x480);
    assert!(core::mem::offset_of!(PopFxDevice, directed_transition_call_count) == 0x488);
    assert!(core::mem::offset_of!(PopFxDevice, directed_transition_state) == 0x490);
    assert!(core::mem::offset_of!(PopFxDevice, power_profile) == 0x4a0);
    assert!(core::mem::offset_of!(PopFxDevice, friendly_name) == 0x4a8);
};

/// `_POP_FX_DEVICE_STATUS` (0x4 bytes).
#[repr(C)]
pub struct PopFxDeviceStatus {
    pub value: Field<i32>,
}

unsafe impl NtStruct for PopFxDeviceStatus {}

impl PopFxDeviceStatus {
    /// `SystemTransition`: bits 0..=0 de `value`.
    pub const SYSTEM_TRANSITION_SHIFT: u32 = 0;
    pub const SYSTEM_TRANSITION_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn system_transition(&self) -> u32 {
        self.value.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_system_transition(&self, value: u32) {
        self.value.set_bits(0, 1, value as u64)
    }
    /// `PepD0Notify`: bits 1..=1 de `value`.
    pub const PEP_D0_NOTIFY_SHIFT: u32 = 1;
    pub const PEP_D0_NOTIFY_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn pep_d0_notify(&self) -> u32 {
        self.value.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_pep_d0_notify(&self, value: u32) {
        self.value.set_bits(1, 1, value as u64)
    }
    /// `IdleTimerOn`: bits 2..=2 de `value`.
    pub const IDLE_TIMER_ON_SHIFT: u32 = 2;
    pub const IDLE_TIMER_ON_MASK: u32 = 0x4;
    #[inline(always)]
    pub fn idle_timer_on(&self) -> u32 {
        self.value.bits(2, 1) as u32
    }
    #[inline(always)]
    pub fn set_idle_timer_on(&self, value: u32) {
        self.value.set_bits(2, 1, value as u64)
    }
    /// `IgnoreIdleTimeout`: bits 3..=3 de `value`.
    pub const IGNORE_IDLE_TIMEOUT_SHIFT: u32 = 3;
    pub const IGNORE_IDLE_TIMEOUT_MASK: u32 = 0x8;
    #[inline(always)]
    pub fn ignore_idle_timeout(&self) -> u32 {
        self.value.bits(3, 1) as u32
    }
    #[inline(always)]
    pub fn set_ignore_idle_timeout(&self, value: u32) {
        self.value.set_bits(3, 1, value as u64)
    }
    /// `IrpInUse`: bits 4..=4 de `value`.
    pub const IRP_IN_USE_SHIFT: u32 = 4;
    pub const IRP_IN_USE_MASK: u32 = 0x10;
    #[inline(always)]
    pub fn irp_in_use(&self) -> u32 {
        self.value.bits(4, 1) as u32
    }
    #[inline(always)]
    pub fn set_irp_in_use(&self, value: u32) {
        self.value.set_bits(4, 1, value as u64)
    }
    /// `IrpPending`: bits 5..=5 de `value`.
    pub const IRP_PENDING_SHIFT: u32 = 5;
    pub const IRP_PENDING_MASK: u32 = 0x20;
    #[inline(always)]
    pub fn irp_pending(&self) -> u32 {
        self.value.bits(5, 1) as u32
    }
    #[inline(always)]
    pub fn set_irp_pending(&self, value: u32) {
        self.value.set_bits(5, 1, value as u64)
    }
    /// `DPNRDeviceNotified`: bits 6..=6 de `value`.
    pub const DPNR_DEVICE_NOTIFIED_SHIFT: u32 = 6;
    pub const DPNR_DEVICE_NOTIFIED_MASK: u32 = 0x40;
    #[inline(always)]
    pub fn dpnr_device_notified(&self) -> u32 {
        self.value.bits(6, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpnr_device_notified(&self, value: u32) {
        self.value.set_bits(6, 1, value as u64)
    }
    /// `DPNRReceivedFromPep`: bits 7..=7 de `value`.
    pub const DPNR_RECEIVED_FROM_PEP_SHIFT: u32 = 7;
    pub const DPNR_RECEIVED_FROM_PEP_MASK: u32 = 0x80;
    #[inline(always)]
    pub fn dpnr_received_from_pep(&self) -> u32 {
        self.value.bits(7, 1) as u32
    }
    #[inline(always)]
    pub fn set_dpnr_received_from_pep(&self, value: u32) {
        self.value.set_bits(7, 1, value as u64)
    }
    /// `IrpFirstPendingIndex`: bits 8..=8 de `value`.
    pub const IRP_FIRST_PENDING_INDEX_SHIFT: u32 = 8;
    pub const IRP_FIRST_PENDING_INDEX_MASK: u32 = 0x100;
    #[inline(always)]
    pub fn irp_first_pending_index(&self) -> u32 {
        self.value.bits(8, 1) as u32
    }
    #[inline(always)]
    pub fn set_irp_first_pending_index(&self, value: u32) {
        self.value.set_bits(8, 1, value as u64)
    }
    /// `IrpLastPendingIndex`: bits 9..=9 de `value`.
    pub const IRP_LAST_PENDING_INDEX_SHIFT: u32 = 9;
    pub const IRP_LAST_PENDING_INDEX_MASK: u32 = 0x200;
    #[inline(always)]
    pub fn irp_last_pending_index(&self) -> u32 {
        self.value.bits(9, 1) as u32
    }
    #[inline(always)]
    pub fn set_irp_last_pending_index(&self, value: u32) {
        self.value.set_bits(9, 1, value as u64)
    }
    /// `SIrpBlocked`: bits 10..=10 de `value`.
    pub const S_IRP_BLOCKED_SHIFT: u32 = 10;
    pub const S_IRP_BLOCKED_MASK: u32 = 0x400;
    #[inline(always)]
    pub fn s_irp_blocked(&self) -> u32 {
        self.value.bits(10, 1) as u32
    }
    #[inline(always)]
    pub fn set_s_irp_blocked(&self, value: u32) {
        self.value.set_bits(10, 1, value as u64)
    }
    /// `BlockFastResume`: bits 11..=11 de `value`.
    pub const BLOCK_FAST_RESUME_SHIFT: u32 = 11;
    pub const BLOCK_FAST_RESUME_MASK: u32 = 0x800;
    #[inline(always)]
    pub fn block_fast_resume(&self) -> u32 {
        self.value.bits(11, 1) as u32
    }
    #[inline(always)]
    pub fn set_block_fast_resume(&self, value: u32) {
        self.value.set_bits(11, 1, value as u64)
    }
    /// `DirectedPoweredDown`: bits 12..=12 de `value`.
    pub const DIRECTED_POWERED_DOWN_SHIFT: u32 = 12;
    pub const DIRECTED_POWERED_DOWN_MASK: u32 = 0x1000;
    #[inline(always)]
    pub fn directed_powered_down(&self) -> u32 {
        self.value.bits(12, 1) as u32
    }
    #[inline(always)]
    pub fn set_directed_powered_down(&self, value: u32) {
        self.value.set_bits(12, 1, value as u64)
    }
    /// `DirectedTransitionInProgress`: bits 13..=13 de `value`.
    pub const DIRECTED_TRANSITION_IN_PROGRESS_SHIFT: u32 = 13;
    pub const DIRECTED_TRANSITION_IN_PROGRESS_MASK: u32 = 0x2000;
    #[inline(always)]
    pub fn directed_transition_in_progress(&self) -> u32 {
        self.value.bits(13, 1) as u32
    }
    #[inline(always)]
    pub fn set_directed_transition_in_progress(&self, value: u32) {
        self.value.set_bits(13, 1, value as u64)
    }
    /// `Reserved`: bits 14..=31 de `value`.
    pub const RESERVED_SHIFT: u32 = 14;
    pub const RESERVED_MASK: u32 = 0xffffc000;
    #[inline(always)]
    pub fn reserved(&self) -> u32 {
        self.value.bits(14, 18) as u32
    }
    #[inline(always)]
    pub fn set_reserved(&self, value: u32) {
        self.value.set_bits(14, 18, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PopFxDeviceStatus>() == 0x4);
    assert!(core::mem::offset_of!(PopFxDeviceStatus, value) == 0x0);
};

/// `_POP_FX_DRIVER_CALLBACKS` (0x50 bytes).
#[repr(C)]
pub struct PopFxDriverCallbacks {
    /// -> `fn`
    pub component_active: Field<u64>,
    /// -> `fn`
    pub component_idle: Field<u64>,
    /// -> `fn`
    pub component_idle_state: Field<u64>,
    /// -> `fn`
    pub device_power_required: Field<u64>,
    /// -> `fn`
    pub device_power_not_required: Field<u64>,
    /// -> `fn`
    pub power_control: Field<u64>,
    /// -> `fn`
    pub component_critical_transition: Field<u64>,
    /// -> `fn`
    pub drips_watchdog_callback: Field<u64>,
    /// -> `fn`
    pub directed_power_up_callback: Field<u64>,
    /// -> `fn`
    pub directed_power_down_callback: Field<u64>,
}

unsafe impl NtStruct for PopFxDriverCallbacks {}

const _: () = {
    assert!(core::mem::size_of::<PopFxDriverCallbacks>() == 0x50);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, component_active) == 0x0);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, component_idle) == 0x8);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, component_idle_state) == 0x10);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, device_power_required) == 0x18);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, device_power_not_required) == 0x20);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, power_control) == 0x28);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, component_critical_transition) == 0x30);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, drips_watchdog_callback) == 0x38);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, directed_power_up_callback) == 0x40);
    assert!(core::mem::offset_of!(PopFxDriverCallbacks, directed_power_down_callback) == 0x48);
};

/// `_POP_FX_WORK_ORDER` (0x38 bytes).
#[repr(C)]
pub struct PopFxWorkOrder {
    pub work_item: WorkQueueItem,
    pub work_count: Field<i32>,
    _pad_24: Reserved<0x4>,
    /// -> `void`
    pub context: Field<u64>,
    /// -> `_POP_FX_WORK_ORDER_WATCHDOG_INFO`
    pub watchdog_timer_info: Field<u64>,
}

unsafe impl NtStruct for PopFxWorkOrder {}

const _: () = {
    assert!(core::mem::size_of::<PopFxWorkOrder>() == 0x38);
    assert!(core::mem::offset_of!(PopFxWorkOrder, work_item) == 0x0);
    assert!(core::mem::offset_of!(PopFxWorkOrder, work_count) == 0x20);
    assert!(core::mem::offset_of!(PopFxWorkOrder, context) == 0x28);
    assert!(core::mem::offset_of!(PopFxWorkOrder, watchdog_timer_info) == 0x30);
};

/// `_POP_FX_ACCOUNTING` (0xe0 bytes).
#[repr(C)]
pub struct PopFxAccounting {
    pub lock: Field<u64>,
    pub active: Field<u8>,
    _pad_9: Reserved<0x3>,
    pub drips_required_state: Field<u32>,
    pub level: Field<i32>,
    _pad_14: Reserved<0x4>,
    pub active_stamp: Field<i64>,
    pub cs_active_time_accounting: PopFxActiveTimeAccounting,
    pub cs_critical_active_time_accounting: PopFxActiveTimeAccounting,
}

unsafe impl NtStruct for PopFxAccounting {}

const _: () = {
    assert!(core::mem::size_of::<PopFxAccounting>() == 0xe0);
    assert!(core::mem::offset_of!(PopFxAccounting, lock) == 0x0);
    assert!(core::mem::offset_of!(PopFxAccounting, active) == 0x8);
    assert!(core::mem::offset_of!(PopFxAccounting, drips_required_state) == 0xc);
    assert!(core::mem::offset_of!(PopFxAccounting, level) == 0x10);
    assert!(core::mem::offset_of!(PopFxAccounting, active_stamp) == 0x18);
    assert!(core::mem::offset_of!(PopFxAccounting, cs_active_time_accounting) == 0x20);
    assert!(core::mem::offset_of!(PopFxAccounting, cs_critical_active_time_accounting) == 0x80);
};

/// `_POP_FX_ACTIVE_TIME_ACCOUNTING` (0x60 bytes).
#[repr(C)]
pub struct PopFxActiveTimeAccounting {
    pub total: Field<u64>,
    pub unattributed: Field<u64>,
    pub buckets: [Field<u64>; 5],
    pub per_bucket: [Field<u64>; 5],
}

unsafe impl NtStruct for PopFxActiveTimeAccounting {}

const _: () = {
    assert!(core::mem::size_of::<PopFxActiveTimeAccounting>() == 0x60);
    assert!(core::mem::offset_of!(PopFxActiveTimeAccounting, total) == 0x0);
    assert!(core::mem::offset_of!(PopFxActiveTimeAccounting, unattributed) == 0x8);
    assert!(core::mem::offset_of!(PopFxActiveTimeAccounting, buckets) == 0x10);
    assert!(core::mem::offset_of!(PopFxActiveTimeAccounting, per_bucket) == 0x38);
};

/// `_POP_FX_DRIPS_WATCHDOG_CONTEXT` (0x28 bytes).
#[repr(C)]
pub struct PopFxDripsWatchdogContext {
    pub link: ListEntry,
    pub component_index: Field<u32>,
    _pad_14: Reserved<0x4>,
    /// -> `_DEVICE_NODE*`
    pub child_devices: Field<u64>,
    pub child_device_count: Field<u32>,
    _pad_24: Reserved<0x4>,
}

unsafe impl NtStruct for PopFxDripsWatchdogContext {}

const _: () = {
    assert!(core::mem::size_of::<PopFxDripsWatchdogContext>() == 0x28);
    assert!(core::mem::offset_of!(PopFxDripsWatchdogContext, link) == 0x0);
    assert!(core::mem::offset_of!(PopFxDripsWatchdogContext, component_index) == 0x10);
    assert!(core::mem::offset_of!(PopFxDripsWatchdogContext, child_devices) == 0x18);
    assert!(core::mem::offset_of!(PopFxDripsWatchdogContext, child_device_count) == 0x20);
};

/// `_POP_FX_WORK_ORDER_WATCHDOG_INFO` (0xb0 bytes).
#[repr(C)]
pub struct PopFxWorkOrderWatchdogInfo {
    pub link: ListEntry,
    pub timer: Ktimer,
    pub dpc: Kdpc,
    /// -> `_POP_FX_WORK_ORDER`
    pub work_order: Field<u64>,
    /// -> `_PEP_WORK_INFORMATION`
    pub current_work_info: Field<u64>,
    pub watchdog_start: Field<u64>,
    /// -> `_KTHREAD`
    pub worker_thread: Field<u64>,
}

unsafe impl NtStruct for PopFxWorkOrderWatchdogInfo {}

const _: () = {
    assert!(core::mem::size_of::<PopFxWorkOrderWatchdogInfo>() == 0xb0);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, link) == 0x0);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, timer) == 0x10);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, dpc) == 0x50);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, work_order) == 0x90);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, current_work_info) == 0x98);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, watchdog_start) == 0xa0);
    assert!(core::mem::offset_of!(PopFxWorkOrderWatchdogInfo, worker_thread) == 0xa8);
};

/// `_POP_FX_DEVICE_DIRECTED_TRANSITION_STATE` (0x10 bytes).
#[repr(C)]
pub struct PopFxDeviceDirectedTransitionState {
    /// -> `void`
    pub completion_context: Field<u64>,
    pub completion_status: Field<i32>,
    pub bitfield_c: Field<u32>,
}

unsafe impl NtStruct for PopFxDeviceDirectedTransitionState {}

impl PopFxDeviceDirectedTransitionState {
    /// `DIrpPending`: bits 0..=0 de `bitfield_c`.
    pub const D_IRP_PENDING_SHIFT: u32 = 0;
    pub const D_IRP_PENDING_MASK: u32 = 0x1;
    #[inline(always)]
    pub fn d_irp_pending(&self) -> u32 {
        self.bitfield_c.bits(0, 1) as u32
    }
    #[inline(always)]
    pub fn set_d_irp_pending(&self, value: u32) {
        self.bitfield_c.set_bits(0, 1, value as u64)
    }
    /// `DIrpCompleted`: bits 1..=1 de `bitfield_c`.
    pub const D_IRP_COMPLETED_SHIFT: u32 = 1;
    pub const D_IRP_COMPLETED_MASK: u32 = 0x2;
    #[inline(always)]
    pub fn d_irp_completed(&self) -> u32 {
        self.bitfield_c.bits(1, 1) as u32
    }
    #[inline(always)]
    pub fn set_d_irp_completed(&self, value: u32) {
        self.bitfield_c.set_bits(1, 1, value as u64)
    }
}

const _: () = {
    assert!(core::mem::size_of::<PopFxDeviceDirectedTransitionState>() == 0x10);
    assert!(core::mem::offset_of!(PopFxDeviceDirectedTransitionState, completion_context) == 0x0);
    assert!(core::mem::offset_of!(PopFxDeviceDirectedTransitionState, completion_status) == 0x8);
    assert!(core::mem::offset_of!(PopFxDeviceDirectedTransitionState, bitfield_c) == 0xc);
};
