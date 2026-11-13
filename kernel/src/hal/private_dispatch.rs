//! HalPrivateDispatchTable — o HAL_PRIVATE_DISPATCH do ntoskrnl.
//!
//! Export de dados de 0x4B0 bytes (versão 51, 149 ponteiros) que o NT expõe
//! aos drivers e que a HAL preenche na inicialização. O layout vem do PDB do
//! ntoskrnl de referência; para cada slot vale o que o boot real deixa nele:
//! - os slots que a HAL nunca grava ficam com o inicializador padrão do
//!   kernel (stubs mínimos: retornar zero, STATUS_NOT_SUPPORTED, identidade,
//!   TRUE, ou nada), reproduzidos como corpos nativos próprios;
//! - os slots que a HAL grava apontam para as rotinas deste módulo, que
//!   seguem a rotina real da HAL (`Halp*`/`Hali*`) com o estado desta
//!   plataforma: PC ACPI com boot por BIOS, sem IOMMU, sem firmware EFI,
//!   sem timer de watchdog, sem contador auxiliar, sem LBR/PMC ativos, sem
//!   processadores ocultos e sem enlightenments de hipervisor. Onde a rotina
//!   real consulta um recurso que esta máquina não tem, ela devolve o mesmo
//!   resultado de "recurso ausente"; onde o OpenNT tem o recurso (ACPI,
//!   configuração PCI, memória física, TSC, APICs, PIC), ela o usa.
//!
//! Cada rotina tem um stub nativo próprio (id privado `0x80000100 + slot`)
//! dentro da imagem do kernel, como os ponteiros do NT apontam para o
//! próprio ntoskrnl.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::{cpu, physical, port};
use crate::hal::amd64::private_entries;
use crate::ntos::inc::types::{
    Field, HalClockTimerConfiguration, HalIntelEnlightenmentInformation, HalIommuDispatch, HalPrivateDispatch, HalUnmaskedInterruptInformation,
    InterruptConnectionType, InterruptVectorData, KinterruptMode, KinterruptPolarity, LargeInteger, NtStruct, WheaErrorRecordSectionDescriptor,
    WheaErrorSeverity, WheaProcessorGenericErrorSection,
};
use crate::ntos::mm::{kernel_address, kernel_data};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::init::exports::Call;

/// HAL_PRIVATE_DISPATCH_VERSION do ntoskrnl de referência.
pub const VERSION: u32 = 51;
pub const SIZE: u64 = core::mem::size_of::<HalPrivateDispatch>() as u64;

/// Deslocamento de um campo do HAL_PRIVATE_DISPATCH (tipo gerado dos símbolos).
macro_rules! slot {
    ($field:ident) => {
        core::mem::offset_of!(HalPrivateDispatch, $field) as u64
    };
}

/// Saída escalar de uma rotina da HAL (PULONG, PULONG64, PVOID*...).
fn output<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: parâmetro de saída do chamador nativo.
    unsafe { Field::<T>::at(address) }
}
/// Ids privados das rotinas: `BASE + índice do slot`.
pub const BASE: u64 = 0x8000_0100;
pub const SLOT_COUNT: usize = 149;

/// O que o boot deixa em cada slot.
#[derive(Clone, Copy)]
enum Entry {
    /// Ponteiro nulo (Dummy e os que nem o kernel nem a HAL preenchem).
    Null,
    /// Inicializador padrão do kernel (corpo nativo próprio).
    Default(&'static str),
    /// Rotina da HAL gravada no boot (nome da rotina real).
    Routine(&'static str),
}

use Entry::{Default as D, Null as N, Routine as R};

/// (offset, campo do HAL_PRIVATE_DISPATCH, conteúdo depois da HAL).
const SLOTS: [(u64, &str, Entry); SLOT_COUNT] = [
    (slot!(hal_handler_for_bus), "HalHandlerForBus", D("zero")),
    (slot!(hal_handler_for_config_space), "HalHandlerForConfigSpace", D("zero")),
    (slot!(hal_locate_hiber_ranges), "HalLocateHiberRanges", R("HaliLocateHiberRanges")),
    (slot!(hal_register_bus_handler), "HalRegisterBusHandler", D("not_supported")),
    (slot!(hal_set_wake_enable), "HalSetWakeEnable", N),
    (slot!(hal_set_wake_alarm), "HalSetWakeAlarm", R("HaliSetWakeAlarm")),
    (slot!(hal_pci_translate_bus_address), "HalPciTranslateBusAddress", R("HalpTranslateBusAddress")),
    (slot!(hal_pci_assign_slot_resources), "HalPciAssignSlotResources", D("not_supported")),
    (slot!(hal_halt_system), "HalHaltSystem", R("HaliHaltSystem")),
    (slot!(hal_find_bus_address_translation), "HalFindBusAddressTranslation", R("HalpFindBusAddressTranslation")),
    (slot!(hal_reset_display), "HalResetDisplay", R("HalpBiosDisplayReset")),
    (slot!(hal_allocate_map_registers), "HalAllocateMapRegisters", R("HalpAllocateMapRegisters")),
    (slot!(kd_setup_pci_device_for_debugging), "KdSetupPciDeviceForDebugging", R("HalpKdSetupDebuggingDevice")),
    (slot!(kd_release_pci_device_for_debugging), "KdReleasePciDeviceForDebugging", R("HalpKdReleaseDebuggingDevice")),
    (slot!(kd_get_acpi_table_phase0), "KdGetAcpiTablePhase0", R("HalAcpiGetTable")),
    (slot!(kd_check_power_button), "KdCheckPowerButton", R("HalpCheckPowerButton")),
    (slot!(hal_vector_to_idt_entry), "HalVectorToIDTEntry", D("vector_identity")),
    (slot!(kd_map_physical_memory64), "KdMapPhysicalMemory64", R("HalpMapPhysicalMemoryWriteThrough64")),
    (slot!(kd_unmap_virtual_address), "KdUnmapVirtualAddress", R("HalpUnmapVirtualAddress")),
    (slot!(kd_get_pci_data_by_offset), "KdGetPciDataByOffset", R("HalpKdReadPCIConfig")),
    (slot!(kd_set_pci_data_by_offset), "KdSetPciDataByOffset", R("HalpKdWritePCIConfig")),
    (slot!(hal_get_interrupt_vector_override), "HalGetInterruptVectorOverride", D("zero")),
    (slot!(hal_get_vector_input_override), "HalGetVectorInputOverride", D("not_supported")),
    (slot!(hal_load_microcode), "HalLoadMicrocode", R("HalpLoadMicrocode")),
    (slot!(hal_unload_microcode), "HalUnloadMicrocode", R("HalpUnloadMicrocode")),
    (slot!(hal_post_microcode_update), "HalPostMicrocodeUpdate", R("HalpMcUpdatePostUpdate")),
    (slot!(hal_allocate_message_target_override), "HalAllocateMessageTargetOverride", D("not_supported")),
    (slot!(hal_free_message_target_override), "HalFreeMessageTargetOverride", D("void")),
    (slot!(hal_dp_replace_begin), "HalDpReplaceBegin", R("HalpDpReplaceBegin")),
    (slot!(hal_dp_replace_target), "HalDpReplaceTarget", R("HalpDpReplaceTarget")),
    (slot!(hal_dp_replace_control), "HalDpReplaceControl", R("HalpDpReplaceControl")),
    (slot!(hal_dp_replace_end), "HalDpReplaceEnd", R("HalpDpReplaceEnd")),
    (slot!(hal_prepare_for_bugcheck), "HalPrepareForBugcheck", R("HalpPrepareForBugcheck")),
    (slot!(hal_query_wake_time), "HalQueryWakeTime", R("HalpTimerQueryWakeTime")),
    (slot!(hal_report_idle_state_usage), "HalReportIdleStateUsage", R("HalpTimerReportIdleStateUsage")),
    (slot!(hal_tsc_synchronization), "HalTscSynchronization", R("HalpTscSynchronization")),
    (slot!(hal_whea_init_processor_generic_section), "HalWheaInitProcessorGenericSection", R("HalpWheaInitProcessorGenericSection")),
    (slot!(hal_stop_legacy_usb_interrupts), "HalStopLegacyUsbInterrupts", R("HalpStopLegacyUsbInterrupts")),
    (slot!(hal_read_whea_physical_memory), "HalReadWheaPhysicalMemory", R("HalpReadWheaPhysicalMemory")),
    (slot!(hal_write_whea_physical_memory), "HalWriteWheaPhysicalMemory", R("HalpWriteWheaPhysicalMemory")),
    (slot!(hal_dp_mask_level_triggered_interrupts), "HalDpMaskLevelTriggeredInterrupts", R("HalpInterruptMaskLevelTriggeredLines")),
    (slot!(hal_dp_unmask_level_triggered_interrupts), "HalDpUnmaskLevelTriggeredInterrupts", R("HalpInterruptUnmaskLevelTriggeredLines")),
    (slot!(hal_dp_get_interrupt_replay_state), "HalDpGetInterruptReplayState", R("HalpDpGetInterruptReplayState")),
    (slot!(hal_dp_replay_interrupts), "HalDpReplayInterrupts", R("HalpDpReplayInterrupts")),
    (slot!(hal_query_io_port_access_supported), "HalQueryIoPortAccessSupported", D("true")),
    (slot!(kd_setup_integrated_device_for_debugging), "KdSetupIntegratedDeviceForDebugging", R("HalpKdSetupDebuggingDevice")),
    (slot!(kd_release_integrated_device_for_debugging), "KdReleaseIntegratedDeviceForDebugging", R("HalpKdReleaseDebuggingDevice")),
    (slot!(hal_get_enlightenment_information), "HalGetEnlightenmentInformation", R("HvlGetEnlightenmentInfo")),
    (slot!(hal_allocate_early_pages), "HalAllocateEarlyPages", R("HalpAllocateEarlyPages")),
    (slot!(hal_map_early_pages), "HalMapEarlyPages", R("HalpMapEarlyPages")),
    (slot!(dummy1), "Dummy1", N),
    (slot!(dummy2), "Dummy2", N),
    (slot!(hal_notify_processor_freeze), "HalNotifyProcessorFreeze", R("HalpTimerNotifyProcessorFreeze")),
    (slot!(hal_prepare_processor_for_idle), "HalPrepareProcessorForIdle", R("HalpProcessorPrepareForIdle")),
    (slot!(hal_register_log_routine), "HalRegisterLogRoutine", D("void")),
    (slot!(hal_resume_processor_from_idle), "HalResumeProcessorFromIdle", R("HalpProcessorResumeFromIdle")),
    (slot!(dummy), "Dummy", N),
    (slot!(hal_vector_to_idt_entry_ex), "HalVectorToIDTEntryEx", D("ulong_identity")),
    (slot!(hal_secondary_interrupt_query_primary_information), "HalSecondaryInterruptQueryPrimaryInformation", R("HalpSecondaryInterruptQueryPrimaryInformation")),
    (slot!(hal_mask_interrupt), "HalMaskInterrupt", R("HalpMaskInterrupt")),
    (slot!(hal_unmask_interrupt), "HalUnmaskInterrupt", R("HalpUnmaskInterrupt")),
    (slot!(hal_is_interrupt_type_secondary), "HalIsInterruptTypeSecondary", R("HalpIsInterruptTypeSecondary")),
    (slot!(hal_allocate_gsiv_for_secondary_interrupt), "HalAllocateGsivForSecondaryInterrupt", R("HalpAllocateGsivForSecondaryInterrupt")),
    (slot!(hal_add_interrupt_remapping), "HalAddInterruptRemapping", R("HaliAddInterruptRemapping")),
    (slot!(hal_remove_interrupt_remapping), "HalRemoveInterruptRemapping", R("HaliRemoveInterruptRemapping")),
    (slot!(hal_save_and_disable_hv_enlightenment), "HalSaveAndDisableHvEnlightenment", R("HalpSaveAndDisableEnlightenment")),
    (slot!(hal_restore_hv_enlightenment), "HalRestoreHvEnlightenment", R("HalpRestoreHvEnlightenment")),
    (slot!(hal_flush_io_buffers_external_cache), "HalFlushIoBuffersExternalCache", D("void")),
    (slot!(hal_flush_external_cache), "HalFlushExternalCache", D("void")),
    (slot!(hal_pci_early_restore), "HalPciEarlyRestore", D("zero")),
    (slot!(hal_get_processor_id), "HalGetProcessorId", R("HalpInterruptGetIdentifiers")),
    (slot!(hal_allocate_pmc_counter_set), "HalAllocatePmcCounterSet", R("HalpAllocatePmcCounterSet")),
    (slot!(hal_collect_pmc_counters), "HalCollectPmcCounters", R("HalpCollectPmcCounters")),
    (slot!(hal_free_pmc_counter_set), "HalFreePmcCounterSet", R("HalpFreePmcCounterSet")),
    (slot!(hal_processor_halt), "HalProcessorHalt", D("processor_halt")),
    (slot!(hal_timer_query_cycle_counter), "HalTimerQueryCycleCounter", R("HalpTimerQueryCycleCounter")),
    (slot!(dummy3), "Dummy3", N),
    (slot!(hal_pci_mark_hiber_phase), "HalPciMarkHiberPhase", D("void")),
    (slot!(hal_query_processor_restart_entry_point), "HalQueryProcessorRestartEntryPoint", R("HalpInterruptQueryProcessorRestartEntryPoint")),
    (slot!(hal_request_interrupt), "HalRequestInterrupt", R("HalpInterruptRequestInterrupt")),
    (slot!(hal_enumerate_unmasked_interrupts), "HalEnumerateUnmaskedInterrupts", R("HalpInterruptEnumerateUnmaskedInterrupts")),
    (slot!(hal_flush_and_invalidate_page_external_cache), "HalFlushAndInvalidatePageExternalCache", D("void")),
    (slot!(kd_enumerate_debugging_devices), "KdEnumerateDebuggingDevices", R("HalpKdEnumerateDebuggingDevices")),
    (slot!(hal_flush_io_rectangle_external_cache), "HalFlushIoRectangleExternalCache", D("void")),
    (slot!(hal_power_early_restore), "HalPowerEarlyRestore", R("HalpPowerEarlyRestore")),
    (slot!(hal_query_capsule_capabilities), "HalQueryCapsuleCapabilities", R("HalpQueryCapsuleCapabilities")),
    (slot!(hal_update_capsule), "HalUpdateCapsule", R("HalpUpdateCapsule")),
    (slot!(hal_pci_multi_stage_resume_capable), "HalPciMultiStageResumeCapable", D("true")),
    (slot!(hal_dma_free_crash_dump_registers), "HalDmaFreeCrashDumpRegisters", R("HalpDmaFreeCrashDumpRegisters")),
    (slot!(hal_acpi_aoac_capable), "HalAcpiAoacCapable", R("HalpAcpiAoacCapable")),
    (slot!(hal_interrupt_set_destination), "HalInterruptSetDestination", R("HalpInterruptSetDestination")),
    (slot!(hal_get_clock_configuration), "HalGetClockConfiguration", R("HalpTimerGetClockConfiguration")),
    (slot!(hal_clock_timer_activate), "HalClockTimerActivate", R("HalpTimerClockActivate")),
    (slot!(hal_clock_timer_initialize), "HalClockTimerInitialize", R("HalpTimerClockInitialize")),
    (slot!(hal_clock_timer_stop), "HalClockTimerStop", R("HalpTimerClockStop")),
    (slot!(hal_clock_timer_arm), "HalClockTimerArm", R("HalpTimerClockArm")),
    (slot!(hal_timer_only_clock_interrupt_pending), "HalTimerOnlyClockInterruptPending", R("HalpTimerOnlyClockInterruptPending")),
    (slot!(hal_acpi_get_multi_node), "HalAcpiGetMultiNode", R("HalAcpiGetRsdpDispatch")),
    (slot!(hal_power_set_reboot_handler), "HalPowerSetRebootHandler", R("HalpPowerSetRebootHandler")),
    (slot!(hal_iommu_register_dispatch_table), "HalIommuRegisterDispatchTable", R("HalpIommuRegisterDispatchTable")),
    (slot!(hal_timer_watchdog_start), "HalTimerWatchdogStart", R("HalpTimerWatchdogStart")),
    (slot!(hal_timer_watchdog_reset_countdown), "HalTimerWatchdogResetCountdown", R("HalpTimerWatchdogResetCountdown")),
    (slot!(hal_timer_watchdog_stop), "HalTimerWatchdogStop", R("HalpTimerWatchdogStop")),
    (slot!(hal_timer_watchdog_generated_last_reset), "HalTimerWatchdogGeneratedLastReset", R("HalpTimerWatchdogGeneratedLastReset")),
    (slot!(hal_timer_watchdog_trigger_system_reset), "HalTimerWatchdogTriggerSystemReset", R("HalpTimerWatchdogTriggerSystemReset")),
    (slot!(hal_interrupt_vector_data_to_gsiv), "HalInterruptVectorDataToGsiv", R("HalpInterruptVectorDataToGsiv")),
    (slot!(hal_interrupt_get_highest_priority_interrupt), "HalInterruptGetHighestPriorityInterrupt", R("HalpInterruptGetHighestPriorityInterrupt")),
    (slot!(hal_processor_on), "HalProcessorOn", D("not_supported")),
    (slot!(hal_processor_off), "HalProcessorOff", D("not_supported")),
    (slot!(hal_processor_freeze), "HalProcessorFreeze", D("not_supported")),
    (slot!(hal_dma_link_device_object_by_token), "HalDmaLinkDeviceObjectByToken", R("HalpDmaLinkDeviceObjectByToken")),
    (slot!(hal_dma_check_adapter_token), "HalDmaCheckAdapterToken", R("HalpDmaCheckAdapterToken")),
    (slot!(dummy4), "Dummy4", N),
    (slot!(hal_timer_convert_performance_counter_to_auxiliary_counter), "HalTimerConvertPerformanceCounterToAuxiliaryCounter", R("HalpTimerConvertPerformanceCounterToAuxiliaryCounter")),
    (slot!(hal_timer_convert_auxiliary_counter_to_performance_counter), "HalTimerConvertAuxiliaryCounterToPerformanceCounter", R("HalpTimerConvertAuxiliaryCounterToPerformanceCounter")),
    (slot!(hal_timer_query_auxiliary_counter_frequency), "HalTimerQueryAuxiliaryCounterFrequency", R("HalpTimerQueryAuxiliaryCounterFrequency")),
    (slot!(hal_connect_thermal_interrupt), "HalConnectThermalInterrupt", R("HalpConnectThermalInterrupt")),
    (slot!(hal_is_efi_runtime_active), "HalIsEFIRuntimeActive", R("HalpIsEFIRuntimeActive")),
    (slot!(hal_timer_query_and_reset_rtc_errors), "HalTimerQueryAndResetRtcErrors", R("HalpTimerQueryAndResetRtcErrors")),
    (slot!(hal_acpi_late_restore), "HalAcpiLateRestore", D("void")),
    (slot!(kd_watchdog_delay_expiration), "KdWatchdogDelayExpiration", R("HalpWatchdogDelayExpiration")),
    (slot!(hal_get_processor_stats), "HalGetProcessorStats", D("not_supported")),
    (slot!(hal_timer_watchdog_query_due_time), "HalTimerWatchdogQueryDueTime", R("HalpTimerWatchdogQueryDueTime")),
    (slot!(hal_connect_synthetic_interrupt), "HalConnectSyntheticInterrupt", D("not_supported")),
    (slot!(hal_preprocess_nmi), "HalPreprocessNmi", R("HalpPreprocessNmi")),
    (slot!(hal_enumerate_environment_variables_with_filter), "HalEnumerateEnvironmentVariablesWithFilter", R("HalpEnumerateEnvironmentVariablesWithFilter")),
    (slot!(hal_capture_last_branch_record_stack), "HalCaptureLastBranchRecordStack", R("HalpLbrCaptureStack")),
    (slot!(hal_clear_last_branch_record_stack), "HalClearLastBranchRecordStack", R("HalpLbrClearStack")),
    (slot!(hal_configure_last_branch_record), "HalConfigureLastBranchRecord", R("HalpLbrConfigureRecording")),
    (slot!(hal_get_last_branch_information), "HalGetLastBranchInformation", R("HalpLbrGetInformation")),
    (slot!(hal_resume_last_branch_record), "HalResumeLastBranchRecord", R("HalpLbrResumeRecording")),
    (slot!(hal_start_last_branch_record), "HalStartLastBranchRecord", R("HalpLbrStartRecording")),
    (slot!(hal_stop_last_branch_record), "HalStopLastBranchRecord", R("HalpLbrStopRecording")),
    (slot!(hal_iommu_block_device), "HalIommuBlockDevice", R("HalpIommuBlockDevice")),
    (slot!(hal_iommu_unblock_device), "HalIommuUnblockDevice", R("HalpIommuUnblockDevice")),
    (slot!(hal_get_iommu_interface), "HalGetIommuInterface", R("HalpGetIommuInterface")),
    (slot!(hal_request_generic_error_recovery), "HalRequestGenericErrorRecovery", R("HalpRequestGenericErrorRecovery")),
    (slot!(hal_timer_query_host_performance_counter), "HalTimerQueryHostPerformanceCounter", R("HalpTimerQueryHostPerformanceCounter")),
    (slot!(hal_topology_query_processor_relationships), "HalTopologyQueryProcessorRelationships", D("not_supported")),
    (slot!(hal_init_platform_debug_triggers), "HalInitPlatformDebugTriggers", R("HaliInitializePlatformDebugTriggers")),
    (slot!(hal_run_platform_debug_triggers), "HalRunPlatformDebugTriggers", R("HaliRunPlatformDebugTriggers")),
    (slot!(hal_timer_get_reference_page), "HalTimerGetReferencePage", R("HalpTimerGetReferencePage")),
    (slot!(hal_get_hidden_processor_power_interface), "HalGetHiddenProcessorPowerInterface", R("HalpBlkPoGetPowerInterface")),
    (slot!(hal_get_hidden_processor_package_id), "HalGetHiddenProcessorPackageId", R("HalpBlkPoGetPackageId")),
    (slot!(hal_get_hidden_package_processor_count), "HalGetHiddenPackageProcessorCount", R("HalpBlkPoGetProcessorCount")),
    (slot!(hal_get_hidden_processor_apic_id_by_index), "HalGetHiddenProcessorApicIdByIndex", R("HalpBlkPoGetApicIdByIndex")),
    (slot!(hal_register_hidden_processor_idle_state), "HalRegisterHiddenProcessorIdleState", R("HalpBlkPoRegisterIdleState")),
    (slot!(hal_iommu_report_iommu_fault), "HalIommuReportIommuFault", R("HalpIommuReportIommuFault")),
    (slot!(hal_iommu_dma_remapping_capable), "HalIommuDmaRemappingCapable", R("HalpIommuDmaRemappingCapable")),
];

const STATUS_SUCCESS: u64 = 0;
const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;
const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
const STATUS_INVALID_HANDLE: u64 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_INVALID_DEVICE_REQUEST: u64 = 0xC000_0010;
const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u64 = 0xC000_00BB;
const STATUS_NOT_FOUND: u64 = 0xC000_0225;

/// PROCESSOR_GENERIC_ERROR_SECTION_GUID {9876CCAD-47B4-4BDB-B65E-16F193C4F3DB}.
const PROCESSOR_GENERIC_SECTION_GUID: [u8; 16] = [0xAD, 0xCC, 0x76, 0x98, 0xB4, 0x47, 0xDB, 0x4B, 0xB6, 0x5E, 0x16, 0xF1, 0x93, 0xC4, 0xF3, 0xDB];

/// Estado da HAL que as rotinas consultam (o equivalente das globais Halp*).
struct HalState {
    reboot_handler: u64,
    iommu_dispatch_called: bool,
    deepest_idle_state: u64,
    /// HalpDmaInsertDeviceObjectByToken: token -> DEVICE_OBJECT.
    dma_tokens: BTreeMap<u64, u64>,
}

static STATE: SpinLock<HalState> = SpinLock::new(HalState { reboot_handler: 0, iommu_dispatch_called: false, deepest_idle_state: 0, dma_tokens: BTreeMap::new() });
static TABLE: AtomicU64 = AtomicU64::new(0);

/// Nome da rotina real de um id privado deste módulo.
pub fn routine_name(index: usize) -> Option<&'static str> {
    match SLOTS.get(index)?.2 {
        Entry::Routine(name) => Some(name),
        _ => None,
    }
}

fn native(symbol: &str) -> Result<u64, KernelError> {
    let entry = private_entries::entry(symbol).ok_or_else(|| KernelError::new(alloc::format!("corpo nativo ausente: {symbol}")))?;
    kernel_address::image_address(entry)
}

/// HalInitSystem: grava a versão e os ponteiros do boot na tabela exportada.
pub fn initialize() -> Result<(), KernelError> {
    let table = kernel_data::address("HalPrivateDispatchTable")?;
    let stubs = native("hal_private_stubs")?;
    // SAFETY: a célula do export de dados HalPrivateDispatchTable.
    unsafe { HalPrivateDispatch::at(table) }.version.set(VERSION);
    for (index, &(offset, _, entry)) in SLOTS.iter().enumerate() {
        let pointer = match entry {
            Entry::Null => 0,
            Entry::Default(body) => native(&alloc::format!("hal_default_{body}"))?,
            Entry::Routine(_) => stubs + index as u64 * crate::hal::amd64::win32_thunk::STUB_SIZE,
        };
        output::<u64>(table + offset).set(pointer);
    }
    TABLE.store(table, Ordering::SeqCst);
    let routines = SLOTS.iter().filter(|(_, _, entry)| matches!(entry, Entry::Routine(_))).count();
    debug_print!("[hal] HalPrivateDispatchTable versao {} em {:#x}: {} rotinas da HAL, {} inicializadores padrao", VERSION, table, routines, SLOT_COUNT - routines);
    Ok(())
}

fn pci_location(slot: u32) -> (u32, u32) {
    (slot & 0x1F, (slot >> 5) & 0x7)
}

/// KdGet/SetPciDataByOffset: bytes do espaço de configuração (HaliPciInterface*).
fn pci_transfer(call: &Call, write: bool) -> u64 {
    let (bus, slot, buffer, offset, length) = (call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5) as u32);
    let (device, function) = pci_location(slot);
    if buffer == 0 || offset >= 256 || !super::pci_config::valid(bus, device, function) {
        return 0;
    }
    let length = length.min(256 - offset);
    if write {
        let bytes = guest::read_bytes(buffer, length as usize);
        for (index, &byte) in bytes.iter().enumerate() {
            if super::pci_config::write(bus, device, function, offset + index as u32, 1, byte as u32).is_err() {
                return index as u64;
            }
        }
        return length as u64;
    }
    let mut bytes = alloc::vec::Vec::with_capacity(length as usize);
    for index in 0..length {
        match super::pci_config::read(bus, device, function, offset + index, 1) {
            Ok(value) => bytes.push(value as u8),
            Err(_) => break,
        }
    }
    guest::write_bytes(buffer, &bytes);
    bytes.len() as u64
}

/// Linha do PIC legado de uma GSIV (as 16 primeiras são as IRQs ISA).
fn mask_pic_line(gsiv: u32, masked: bool) -> u64 {
    if gsiv > 15 {
        return STATUS_INVALID_PARAMETER;
    }
    let (data, bit) = if gsiv >= 8 { (0xA1, gsiv - 8) } else { (0x21, gsiv) };
    let flags = cpu::save_and_disable_interrupts();
    let current = port::read8(data);
    port::write8(data, if masked { current | (1 << bit) } else { current & !(1 << bit) });
    cpu::restore_interrupts(flags);
    STATUS_SUCCESS
}

fn current_apic_id() -> u32 {
    let identifier = cpu::cpuid(1)[1] >> 24;
    identifier
}

/// Despacho das rotinas (id privado `BASE + slot`).
pub fn dispatch(index: usize, call: &Call) -> Result<u64, KernelError> {
    let Some(Entry::Routine(name)) = SLOTS.get(index).map(|slot| slot.2) else {
        return Err(KernelError::new(alloc::format!("slot da HAL privada sem rotina: {index}")));
    };
    let result = routine(name, call)?;
    if crate::ntos::init::exports::api_trace_enabled() {
        debug_print!("[hal] {}({:#x}, {:#x}, {:#x}, {:#x}) -> {:#x} @{:#x}", name, call.arg(1), call.arg(2), call.arg(3), call.arg(4), result, call.return_address);
    }
    Ok(result)
}

fn routine(name: &str, call: &Call) -> Result<u64, KernelError> {
    Ok(match name {
        // ---- energia e firmware ----------------------------------------------
        // Sem hibernação no OpenNT: não há faixas da HAL a marcar.
        "HaliLocateHiberRanges" => 0,
        // Sem alarme de RTC armável pelo ACPI nesta plataforma.
        "HaliSetWakeAlarm" => STATUS_UNSUCCESSFUL,
        // Desliga a CPU depois do bugcheck/shutdown (HalpShutdown).
        "HaliHaltSystem" => {
            debug_print!("[hal] HalHaltSystem: sistema parado");
            cpu::halt_forever()
        }
        // Sem bloco de eventos PM1 tratado pelo OpenNT: nenhum botão a ler.
        "HalpCheckPowerButton" => 0,
        // Reinicializa o vídeo em modo texto (equivale ao int 10h modo 3).
        "HalpBiosDisplayReset" => {
            crate::drivers::video::vga::clear();
            1
        }
        "HalpPowerEarlyRestore" | "HalpPrepareForBugcheck" | "HalpStopLegacyUsbInterrupts" | "HaliInitializePlatformDebugTriggers" | "HaliRunPlatformDebugTriggers" | "HalpPreprocessNmi" => 0,
        // Firmware BIOS: cápsulas e variáveis EFI não existem.
        "HalpQueryCapsuleCapabilities" | "HalpUpdateCapsule" | "HalpEnumerateEnvironmentVariablesWithFilter" => STATUS_NOT_IMPLEMENTED,
        "HalpIsEFIRuntimeActive" => 0,
        // HalpPlatformFlags bit 3: FADT LOW_POWER_S0_IDLE_CAPABLE (bit 21).
        "HalpAcpiAoacCapable" => super::acpi::get_table("FACP", 0, false).filter(|table| table.length >= 116).map_or(0, |table| (physical::read32(table.address + 112) >> 21) as u64 & 1),
        // Não é um sistema ACPI multinó.
        "HalAcpiGetRsdpDispatch" => 0,
        "HalpPowerSetRebootHandler" => {
            let mut state = STATE.lock();
            core::mem::replace(&mut state.reboot_handler, call.arg(1))
        }
        // ---- barramentos e DMA -----------------------------------------------
        // Tradução identidade: *TranslatedAddress = BusAddress, TRUE.
        "HalpTranslateBusAddress" => {
            // SAFETY: PPHYSICAL_ADDRESS TranslatedAddress do chamador.
            unsafe { LargeInteger::at(call.arg(5)) }.quad_part.set(call.arg(3) as i64);
            1
        }
        "HalpFindBusAddressTranslation" => {
            let (bus_address, translated, context, next_bus) = (call.arg(1), call.arg(3), call.arg(4), call.arg(5) as u8);
            if context == 0 || (output::<u64>(context).get() != 0 && next_bus == 1) {
                0
            } else {
                output::<u64>(context).set(1);
                // SAFETY: PPHYSICAL_ADDRESS TranslatedAddress do chamador.
                unsafe { LargeInteger::at(translated) }.quad_part.set(bus_address as i64);
                1
            }
        }
        // O OpenNT não cria adaptadores com map registers (DMA direto).
        "HalpAllocateMapRegisters" => STATUS_INVALID_DEVICE_REQUEST,
        "HalpDmaFreeCrashDumpRegisters" => 0,
        "HalpDmaLinkDeviceObjectByToken" => {
            STATE.lock().dma_tokens.insert(call.arg(1), call.arg(2));
            STATUS_SUCCESS
        }
        "HalpDmaCheckAdapterToken" => {
            if STATE.lock().dma_tokens.contains_key(&call.arg(1)) { STATUS_SUCCESS } else { STATUS_NOT_FOUND }
        }
        // ---- depurador do kernel -----------------------------------------------
        // Nenhum dispositivo de depuração enumerado pela HAL.
        "HalpKdSetupDebuggingDevice" => {
            if call.arg(2) == 0 { STATUS_INVALID_PARAMETER } else { STATUS_NOT_FOUND }
        }
        "HalpKdReleaseDebuggingDevice" => STATUS_NOT_FOUND,
        "HalpKdEnumerateDebuggingDevices" => {
            if call.arg(2) == 0 { STATUS_INVALID_PARAMETER } else { STATUS_NOT_FOUND }
        }
        "HalAcpiGetTable" => {
            let signature = call.arg(2) as u32;
            let text: alloc::string::String = signature.to_le_bytes().iter().map(|&byte| byte as char).collect();
            // A tabela pela VA do mapa direto (um ponteiro de sistema).
            super::acpi::get_table(&text, 0, false).map_or(0, |table| physical::to_virtual(table.address))
        }
        // Toda a faixa física está no mapa direto (como o MmMapIoSpace).
        "HalpMapPhysicalMemoryWriteThrough64" | "HalpMapEarlyPages" => {
            let end = call.arg(1).checked_add(call.arg(2) as u32 as u64 * 0x1000);
            if end.is_some_and(|end| end <= crate::ntos::mm::memory_map::PHYSICAL_MEMORY_LIMIT) { physical::to_virtual(call.arg(1)) } else { 0 }
        }
        "HalpUnmapVirtualAddress" => {
            if call.arg(3) & 0xFF != 0 {
                for page in 0..call.arg(2) {
                    cpu::invalidate_page((call.arg(1) & !0xFFF) + page * 0x1000);
                }
            }
            0
        }
        "HalpKdReadPCIConfig" => pci_transfer(call, false),
        "HalpKdWritePCIConfig" => pci_transfer(call, true),
        "HalpWatchdogDelayExpiration" => STATUS_UNSUCCESSFUL,
        // ---- memória de boot -------------------------------------------------
        "HalpAllocateEarlyPages" => {
            let pages = call.arg(2) as u32 as u64;
            match crate::ntos::mm::contiguous_memory::allocate_default(pages * 0x1000, u64::MAX) {
                Ok(address) => {
                    if call.arg(3) != 0 {
                        output::<u64>(call.arg(3)).set(crate::ntos::mm::paging::translate(address));
                    }
                    address
                }
                Err(_) => 0,
            }
        }
        // ---- microcódigo e partição dinâmica -----------------------------------
        // O OpenNT não aplica atualizações de microcódigo.
        "HalpLoadMicrocode" => STATUS_NOT_SUPPORTED,
        "HalpUnloadMicrocode" | "HalpMcUpdatePostUpdate" => STATUS_SUCCESS,
        // Sem substituição de hardware a quente nesta plataforma.
        "HalpDpReplaceBegin" | "HalpDpReplaceControl" => STATUS_NOT_SUPPORTED,
        "HalpDpReplaceTarget" | "HalpDpReplaceEnd" => 0,
        "HalpInterruptMaskLevelTriggeredLines" | "HalpInterruptUnmaskLevelTriggeredLines" => STATUS_SUCCESS,
        "HalpDpGetInterruptReplayState" => {
            if call.arg(2) != 0 {
                output::<u64>(call.arg(2)).set(0);
            }
            STATUS_NOT_SUPPORTED
        }
        "HalpDpReplayInterrupts" => STATUS_NOT_SUPPORTED,
        // ---- WHEA ------------------------------------------------------------
        "HalpWheaInitProcessorGenericSection" => {
            let (descriptor_address, section_address) = (call.arg(1), call.arg(2));
            guest::write_bytes(descriptor_address, &[0; WheaErrorRecordSectionDescriptor::SIZE as usize]);
            guest::write_bytes(section_address, &[0; WheaProcessorGenericErrorSection::SIZE as usize]);
            // SAFETY: descritor e seção de erro do chamador (recém-zerados).
            let (descriptor, section) = unsafe { (WheaErrorRecordSectionDescriptor::at(descriptor_address), WheaProcessorGenericErrorSection::at(section_address)) };
            descriptor.section_length.set(WheaProcessorGenericErrorSection::SIZE as u32);
            descriptor.revision.as_ushort.set(0x300);
            guest::write_bytes(descriptor.section_type.address(), &PROCESSOR_GENERIC_SECTION_GUID);
            descriptor.section_severity.set(WheaErrorSeverity::WHEA_ERR_SEV_INFORMATIONAL);
            // InstructionSet X64; ValidBits: tipo, conjunto, versão e id do processador.
            section.instruction_set.set(2);
            section.valid_bits.valid_bits.set(0x143);
            section.cpu_version.set(cpu::cpuid(1)[0] as u64);
            section.processor_id.set(current_apic_id() as u64);
            STATUS_SUCCESS
        }
        "HalpReadWheaPhysicalMemory" => {
            let bytes = physical::read_bytes(call.arg(1), call.arg(2) as u32 as usize);
            guest::write_bytes(call.arg(3), &bytes);
            STATUS_SUCCESS
        }
        "HalpWriteWheaPhysicalMemory" => {
            physical::write_bytes(call.arg(1), &guest::read_bytes(call.arg(3), call.arg(2) as u32 as usize));
            STATUS_SUCCESS
        }
        // Sem fontes de erro GHES registradas.
        "HalpRequestGenericErrorRecovery" => STATUS_NOT_FOUND,
        // ---- timers ----------------------------------------------------------
        "HalpTimerQueryWakeTime" => {
            for pointer in [call.arg(1), call.arg(2)] {
                if pointer != 0 {
                    output::<u64>(pointer).set(0);
                }
            }
            0
        }
        "HalpTimerReportIdleStateUsage" => {
            STATE.lock().deepest_idle_state = call.arg(1) & 0xFF;
            0
        }
        "HalpTscSynchronization" | "HalpTimerNotifyProcessorFreeze" => 0,
        "HalpTimerQueryCycleCounter" => {
            if call.arg(1) != 0 {
                output::<u64>(call.arg(1)).set(crate::ntos::ke::clock::tsc_frequency_hz());
            }
            cpu::rdtsc()
        }
        // Timer do relógio: LAPIC periódico de 100 Hz por CPU (10 ms fixos).
        "HalpTimerGetClockConfiguration" => {
            let address = call.arg(1);
            guest::write_bytes(address, &[0; HalClockTimerConfiguration::SIZE as usize]);
            // SAFETY: HAL_CLOCK_TIMER_CONFIGURATION do chamador (recém-zerada).
            let configuration = unsafe { HalClockTimerConfiguration::at(address) };
            configuration.flags.set(1 << 2); // PerCpuTimer
            configuration.known_type.set(0);
            configuration.capabilities.set(1);
            configuration.max_increment.set(100_000);
            configuration.min_increment.set(100_000);
            0
        }
        "HalpTimerClockActivate" | "HalpTimerClockInitialize" | "HalpTimerClockStop" => 0,
        "HalpTimerClockArm" => {
            if call.arg(3) != 0 {
                output::<u64>(call.arg(3)).set(100_000);
            }
            STATUS_SUCCESS
        }
        "HalpTimerOnlyClockInterruptPending" => 0,
        // Sem timer de watchdog (WDAT) nesta plataforma.
        "HalpTimerWatchdogStart" | "HalpTimerWatchdogResetCountdown" | "HalpTimerWatchdogStop" => 0,
        "HalpTimerWatchdogGeneratedLastReset" => 0,
        "HalpTimerWatchdogTriggerSystemReset" => STATUS_UNSUCCESSFUL,
        "HalpTimerWatchdogQueryDueTime" => 0,
        // Sem contador auxiliar nem contador de referência do hipervisor.
        "HalpTimerConvertPerformanceCounterToAuxiliaryCounter" | "HalpTimerConvertAuxiliaryCounterToPerformanceCounter" | "HalpTimerQueryAuxiliaryCounterFrequency" | "HalpTimerQueryHostPerformanceCounter" => STATUS_NOT_SUPPORTED,
        "HalpTimerQueryAndResetRtcErrors" => 0,
        "HalpTimerGetReferencePage" => 0,
        // ---- interrupções ----------------------------------------------------
        // Sem controladores secundários.
        "HalpSecondaryInterruptQueryPrimaryInformation" => STATUS_NOT_FOUND,
        "HalpIsInterruptTypeSecondary" => 0,
        "HalpAllocateGsivForSecondaryInterrupt" => STATUS_INSUFFICIENT_RESOURCES,
        "HalpMaskInterrupt" => mask_pic_line(call.arg(1) as u32, true),
        "HalpUnmaskInterrupt" => mask_pic_line(call.arg(1) as u32, false),
        // Sem remapeamento de interrupções (não há IOMMU).
        "HaliAddInterruptRemapping" => STATUS_SUCCESS,
        "HaliRemoveInterruptRemapping" => 0,
        "HalpInterruptGetIdentifiers" => {
            let apic_ids = crate::ntos::ke::smp::discovered_apic_ids();
            match apic_ids.get(call.arg(1) as u32 as usize) {
                Some(&apic_id) => {
                    for pointer in [call.arg(2), call.arg(3)] {
                        if pointer != 0 {
                            output::<u32>(pointer).set(apic_id);
                        }
                    }
                    STATUS_SUCCESS
                }
                None => STATUS_NOT_FOUND,
            }
        }
        "HalpInterruptQueryProcessorRestartEntryPoint" => {
            output::<u64>(call.arg(1)).set(0);
            STATUS_NOT_SUPPORTED
        }
        // O OpenNT não gera interrupções por GSIV nem redireciona destinos.
        "HalpInterruptRequestInterrupt" => STATUS_INVALID_PARAMETER,
        "HalpInterruptSetDestination" => STATUS_NOT_SUPPORTED,
        // Enumera as linhas desmascaradas do PIC: callback(contexto, informação).
        "HalpInterruptEnumerateUnmaskedInterrupts" => {
            let (callback, context, information) = (call.arg(1), call.arg(2), call.arg(3));
            if callback == 0 || information == 0 {
                STATUS_INVALID_PARAMETER
            } else {
                let mask = port::read8(0x21) as u16 | (port::read8(0xA1) as u16) << 8;
                // Version u16, Size u16, Flags u16, Mode @8 (Latched = 1),
                // Polarity @0xC (ActiveHigh = 1), Gsiv @0x10, PinNumber @0x14.
                for line in (0..16u32).filter(|line| mask & (1 << line) == 0 && *line != 2) {
                    guest::write_bytes(information, &[0; HalUnmaskedInterruptInformation::SIZE as usize]);
                    // SAFETY: HAL_UNMASKED_INTERRUPT_INFORMATION do chamador (recém-zerada).
                    let entry = unsafe { HalUnmaskedInterruptInformation::at(information) };
                    entry.version.set(1);
                    entry.size.set(HalUnmaskedInterruptInformation::SIZE as u16);
                    entry.mode.set(KinterruptMode::LATCHED);
                    entry.polarity.set(KinterruptPolarity::INTERRUPT_ACTIVE_HIGH);
                    entry.gsiv.set(line);
                    entry.pin_number.set(line as u16);
                    if crate::hal::amd64::native_call::call(callback, &[context, information]) & 0xFF == 0 {
                        break;
                    }
                }
                STATUS_SUCCESS
            }
        }
        "HalpInterruptVectorDataToGsiv" => {
            // SAFETY: INTERRUPT_VECTOR_DATA do chamador.
            let vector_data = unsafe { InterruptVectorData::at(call.arg(1)) };
            match vector_data.type_.get() {
                InterruptConnectionType::INTERRUPT_TYPE_CONTROLLER_INPUT => {
                    output::<u32>(call.arg(2)).set(vector_data.controller_input.gsiv.get());
                    STATUS_SUCCESS
                }
                InterruptConnectionType::INTERRUPT_TYPE_MESSAGE_REQUEST => STATUS_NOT_SUPPORTED,
                _ => STATUS_UNSUCCESSFUL,
            }
        }
        "HalpInterruptGetHighestPriorityInterrupt" => STATUS_NOT_SUPPORTED,
        // Interrupção térmica do LAPIC só com o monitor térmico do CPUID.
        "HalpConnectThermalInterrupt" => {
            if cpu::cpuid(1)[3] & (1 << 22) != 0 { STATUS_SUCCESS } else { STATUS_NOT_SUPPORTED }
        }
        // ---- processadores, PMU e LBR ------------------------------------------
        // HalpPmuInUse = 0.
        "HalpProcessorPrepareForIdle" => STATUS_SUCCESS,
        "HalpProcessorResumeFromIdle" => 0,
        "HalpAllocatePmcCounterSet" => STATUS_NOT_SUPPORTED,
        "HalpCollectPmcCounters" | "HalpFreePmcCounterSet" => 0,
        // HalpLbrStackSize = 0: as operações de LBR não estão liberadas.
        "HalpLbrCaptureStack" | "HalpLbrStartRecording" => STATUS_NOT_SUPPORTED,
        "HalpLbrClearStack" | "HalpLbrGetInformation" => 0,
        "HalpLbrConfigureRecording" => STATUS_INVALID_PARAMETER,
        "HalpLbrResumeRecording" => 0,
        "HalpLbrStopRecording" => STATUS_INVALID_HANDLE,
        // Sem processadores ocultos (HalpBlkNumberProcessors = 0).
        "HalpBlkPoGetPowerInterface" => STATUS_NOT_SUPPORTED,
        "HalpBlkPoGetPackageId" => crate::ntos::ke::bugcheck::bug_check_ex(0x1DA, 3, call.arg(1) as u32 as u64, 0, 0),
        "HalpBlkPoGetProcessorCount" => 0,
        "HalpBlkPoGetApicIdByIndex" => STATUS_NOT_FOUND,
        "HalpBlkPoRegisterIdleState" => STATUS_NOT_SUPPORTED,
        // ---- hipervisor --------------------------------------------------------
        // Sem enlightenments: a estrutura de 504 bytes volta zerada.
        "HvlGetEnlightenmentInfo" => {
            guest::write_bytes(call.arg(1), &[0; HalIntelEnlightenmentInformation::SIZE as usize]);
            0
        }
        "HalpSaveAndDisableEnlightenment" | "HalpRestoreHvEnlightenment" => 0,
        // ---- IOMMU (ausente) -------------------------------------------------
        "HalpIommuRegisterDispatchTable" => {
            let mut state = STATE.lock();
            if !state.iommu_dispatch_called && call.arg(1) != 0 {
                state.iommu_dispatch_called = true;
                // SAFETY: HAL_IOMMU_DISPATCH do chamador.
                unsafe { HalIommuDispatch::at(call.arg(1)) }.hal_iommu_support_enabled.set(native("hal_default_false")?);
            }
            0
        }
        "HalpIommuBlockDevice" | "HalpIommuUnblockDevice" | "HalpGetIommuInterface" => STATUS_NOT_SUPPORTED,
        "HalpIommuReportIommuFault" => 0,
        "HalpIommuDmaRemappingCapable" => 0,
        other => return Err(KernelError::new(alloc::format!("rotina da HAL sem implementacao: {other}"))),
    })
}

/// O endereço da tabela publicada (0 antes da inicialização da HAL).
pub fn table_address() -> u64 {
    TABLE.load(Ordering::SeqCst)
}

/// Célula do export de dados HalPrivateDispatchTable na imagem do kernel
/// (válida também antes da inicialização da HAL).
pub fn data_export_address() -> u64 {
    kernel_data::address("HalPrivateDispatchTable").unwrap_or_else(|error| panic!("HalPrivateDispatchTable: {error}"))
}
