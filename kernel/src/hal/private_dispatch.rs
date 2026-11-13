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
use crate::ntos::mm::{kernel_address, kernel_data};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::init::exports::Call;

/// HAL_PRIVATE_DISPATCH_VERSION do ntoskrnl de referência.
pub const VERSION: u32 = 51;
pub const SIZE: u64 = 0x4B0;
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
    (0x008, "HalHandlerForBus", D("zero")),
    (0x010, "HalHandlerForConfigSpace", D("zero")),
    (0x018, "HalLocateHiberRanges", R("HaliLocateHiberRanges")),
    (0x020, "HalRegisterBusHandler", D("not_supported")),
    (0x028, "HalSetWakeEnable", N),
    (0x030, "HalSetWakeAlarm", R("HaliSetWakeAlarm")),
    (0x038, "HalPciTranslateBusAddress", R("HalpTranslateBusAddress")),
    (0x040, "HalPciAssignSlotResources", D("not_supported")),
    (0x048, "HalHaltSystem", R("HaliHaltSystem")),
    (0x050, "HalFindBusAddressTranslation", R("HalpFindBusAddressTranslation")),
    (0x058, "HalResetDisplay", R("HalpBiosDisplayReset")),
    (0x060, "HalAllocateMapRegisters", R("HalpAllocateMapRegisters")),
    (0x068, "KdSetupPciDeviceForDebugging", R("HalpKdSetupDebuggingDevice")),
    (0x070, "KdReleasePciDeviceForDebugging", R("HalpKdReleaseDebuggingDevice")),
    (0x078, "KdGetAcpiTablePhase0", R("HalAcpiGetTable")),
    (0x080, "KdCheckPowerButton", R("HalpCheckPowerButton")),
    (0x088, "HalVectorToIDTEntry", D("vector_identity")),
    (0x090, "KdMapPhysicalMemory64", R("HalpMapPhysicalMemoryWriteThrough64")),
    (0x098, "KdUnmapVirtualAddress", R("HalpUnmapVirtualAddress")),
    (0x0A0, "KdGetPciDataByOffset", R("HalpKdReadPCIConfig")),
    (0x0A8, "KdSetPciDataByOffset", R("HalpKdWritePCIConfig")),
    (0x0B0, "HalGetInterruptVectorOverride", D("zero")),
    (0x0B8, "HalGetVectorInputOverride", D("not_supported")),
    (0x0C0, "HalLoadMicrocode", R("HalpLoadMicrocode")),
    (0x0C8, "HalUnloadMicrocode", R("HalpUnloadMicrocode")),
    (0x0D0, "HalPostMicrocodeUpdate", R("HalpMcUpdatePostUpdate")),
    (0x0D8, "HalAllocateMessageTargetOverride", D("not_supported")),
    (0x0E0, "HalFreeMessageTargetOverride", D("void")),
    (0x0E8, "HalDpReplaceBegin", R("HalpDpReplaceBegin")),
    (0x0F0, "HalDpReplaceTarget", R("HalpDpReplaceTarget")),
    (0x0F8, "HalDpReplaceControl", R("HalpDpReplaceControl")),
    (0x100, "HalDpReplaceEnd", R("HalpDpReplaceEnd")),
    (0x108, "HalPrepareForBugcheck", R("HalpPrepareForBugcheck")),
    (0x110, "HalQueryWakeTime", R("HalpTimerQueryWakeTime")),
    (0x118, "HalReportIdleStateUsage", R("HalpTimerReportIdleStateUsage")),
    (0x120, "HalTscSynchronization", R("HalpTscSynchronization")),
    (0x128, "HalWheaInitProcessorGenericSection", R("HalpWheaInitProcessorGenericSection")),
    (0x130, "HalStopLegacyUsbInterrupts", R("HalpStopLegacyUsbInterrupts")),
    (0x138, "HalReadWheaPhysicalMemory", R("HalpReadWheaPhysicalMemory")),
    (0x140, "HalWriteWheaPhysicalMemory", R("HalpWriteWheaPhysicalMemory")),
    (0x148, "HalDpMaskLevelTriggeredInterrupts", R("HalpInterruptMaskLevelTriggeredLines")),
    (0x150, "HalDpUnmaskLevelTriggeredInterrupts", R("HalpInterruptUnmaskLevelTriggeredLines")),
    (0x158, "HalDpGetInterruptReplayState", R("HalpDpGetInterruptReplayState")),
    (0x160, "HalDpReplayInterrupts", R("HalpDpReplayInterrupts")),
    (0x168, "HalQueryIoPortAccessSupported", D("true")),
    (0x170, "KdSetupIntegratedDeviceForDebugging", R("HalpKdSetupDebuggingDevice")),
    (0x178, "KdReleaseIntegratedDeviceForDebugging", R("HalpKdReleaseDebuggingDevice")),
    (0x180, "HalGetEnlightenmentInformation", R("HvlGetEnlightenmentInfo")),
    (0x188, "HalAllocateEarlyPages", R("HalpAllocateEarlyPages")),
    (0x190, "HalMapEarlyPages", R("HalpMapEarlyPages")),
    (0x198, "Dummy1", N),
    (0x1A0, "Dummy2", N),
    (0x1A8, "HalNotifyProcessorFreeze", R("HalpTimerNotifyProcessorFreeze")),
    (0x1B0, "HalPrepareProcessorForIdle", R("HalpProcessorPrepareForIdle")),
    (0x1B8, "HalRegisterLogRoutine", D("void")),
    (0x1C0, "HalResumeProcessorFromIdle", R("HalpProcessorResumeFromIdle")),
    (0x1C8, "Dummy", N),
    (0x1D0, "HalVectorToIDTEntryEx", D("ulong_identity")),
    (0x1D8, "HalSecondaryInterruptQueryPrimaryInformation", R("HalpSecondaryInterruptQueryPrimaryInformation")),
    (0x1E0, "HalMaskInterrupt", R("HalpMaskInterrupt")),
    (0x1E8, "HalUnmaskInterrupt", R("HalpUnmaskInterrupt")),
    (0x1F0, "HalIsInterruptTypeSecondary", R("HalpIsInterruptTypeSecondary")),
    (0x1F8, "HalAllocateGsivForSecondaryInterrupt", R("HalpAllocateGsivForSecondaryInterrupt")),
    (0x200, "HalAddInterruptRemapping", R("HaliAddInterruptRemapping")),
    (0x208, "HalRemoveInterruptRemapping", R("HaliRemoveInterruptRemapping")),
    (0x210, "HalSaveAndDisableHvEnlightenment", R("HalpSaveAndDisableEnlightenment")),
    (0x218, "HalRestoreHvEnlightenment", R("HalpRestoreHvEnlightenment")),
    (0x220, "HalFlushIoBuffersExternalCache", D("void")),
    (0x228, "HalFlushExternalCache", D("void")),
    (0x230, "HalPciEarlyRestore", D("zero")),
    (0x238, "HalGetProcessorId", R("HalpInterruptGetIdentifiers")),
    (0x240, "HalAllocatePmcCounterSet", R("HalpAllocatePmcCounterSet")),
    (0x248, "HalCollectPmcCounters", R("HalpCollectPmcCounters")),
    (0x250, "HalFreePmcCounterSet", R("HalpFreePmcCounterSet")),
    (0x258, "HalProcessorHalt", D("processor_halt")),
    (0x260, "HalTimerQueryCycleCounter", R("HalpTimerQueryCycleCounter")),
    (0x268, "Dummy3", N),
    (0x270, "HalPciMarkHiberPhase", D("void")),
    (0x278, "HalQueryProcessorRestartEntryPoint", R("HalpInterruptQueryProcessorRestartEntryPoint")),
    (0x280, "HalRequestInterrupt", R("HalpInterruptRequestInterrupt")),
    (0x288, "HalEnumerateUnmaskedInterrupts", R("HalpInterruptEnumerateUnmaskedInterrupts")),
    (0x290, "HalFlushAndInvalidatePageExternalCache", D("void")),
    (0x298, "KdEnumerateDebuggingDevices", R("HalpKdEnumerateDebuggingDevices")),
    (0x2A0, "HalFlushIoRectangleExternalCache", D("void")),
    (0x2A8, "HalPowerEarlyRestore", R("HalpPowerEarlyRestore")),
    (0x2B0, "HalQueryCapsuleCapabilities", R("HalpQueryCapsuleCapabilities")),
    (0x2B8, "HalUpdateCapsule", R("HalpUpdateCapsule")),
    (0x2C0, "HalPciMultiStageResumeCapable", D("true")),
    (0x2C8, "HalDmaFreeCrashDumpRegisters", R("HalpDmaFreeCrashDumpRegisters")),
    (0x2D0, "HalAcpiAoacCapable", R("HalpAcpiAoacCapable")),
    (0x2D8, "HalInterruptSetDestination", R("HalpInterruptSetDestination")),
    (0x2E0, "HalGetClockConfiguration", R("HalpTimerGetClockConfiguration")),
    (0x2E8, "HalClockTimerActivate", R("HalpTimerClockActivate")),
    (0x2F0, "HalClockTimerInitialize", R("HalpTimerClockInitialize")),
    (0x2F8, "HalClockTimerStop", R("HalpTimerClockStop")),
    (0x300, "HalClockTimerArm", R("HalpTimerClockArm")),
    (0x308, "HalTimerOnlyClockInterruptPending", R("HalpTimerOnlyClockInterruptPending")),
    (0x310, "HalAcpiGetMultiNode", R("HalAcpiGetRsdpDispatch")),
    (0x318, "HalPowerSetRebootHandler", R("HalpPowerSetRebootHandler")),
    (0x320, "HalIommuRegisterDispatchTable", R("HalpIommuRegisterDispatchTable")),
    (0x328, "HalTimerWatchdogStart", R("HalpTimerWatchdogStart")),
    (0x330, "HalTimerWatchdogResetCountdown", R("HalpTimerWatchdogResetCountdown")),
    (0x338, "HalTimerWatchdogStop", R("HalpTimerWatchdogStop")),
    (0x340, "HalTimerWatchdogGeneratedLastReset", R("HalpTimerWatchdogGeneratedLastReset")),
    (0x348, "HalTimerWatchdogTriggerSystemReset", R("HalpTimerWatchdogTriggerSystemReset")),
    (0x350, "HalInterruptVectorDataToGsiv", R("HalpInterruptVectorDataToGsiv")),
    (0x358, "HalInterruptGetHighestPriorityInterrupt", R("HalpInterruptGetHighestPriorityInterrupt")),
    (0x360, "HalProcessorOn", D("not_supported")),
    (0x368, "HalProcessorOff", D("not_supported")),
    (0x370, "HalProcessorFreeze", D("not_supported")),
    (0x378, "HalDmaLinkDeviceObjectByToken", R("HalpDmaLinkDeviceObjectByToken")),
    (0x380, "HalDmaCheckAdapterToken", R("HalpDmaCheckAdapterToken")),
    (0x388, "Dummy4", N),
    (0x390, "HalTimerConvertPerformanceCounterToAuxiliaryCounter", R("HalpTimerConvertPerformanceCounterToAuxiliaryCounter")),
    (0x398, "HalTimerConvertAuxiliaryCounterToPerformanceCounter", R("HalpTimerConvertAuxiliaryCounterToPerformanceCounter")),
    (0x3A0, "HalTimerQueryAuxiliaryCounterFrequency", R("HalpTimerQueryAuxiliaryCounterFrequency")),
    (0x3A8, "HalConnectThermalInterrupt", R("HalpConnectThermalInterrupt")),
    (0x3B0, "HalIsEFIRuntimeActive", R("HalpIsEFIRuntimeActive")),
    (0x3B8, "HalTimerQueryAndResetRtcErrors", R("HalpTimerQueryAndResetRtcErrors")),
    (0x3C0, "HalAcpiLateRestore", D("void")),
    (0x3C8, "KdWatchdogDelayExpiration", R("HalpWatchdogDelayExpiration")),
    (0x3D0, "HalGetProcessorStats", D("not_supported")),
    (0x3D8, "HalTimerWatchdogQueryDueTime", R("HalpTimerWatchdogQueryDueTime")),
    (0x3E0, "HalConnectSyntheticInterrupt", D("not_supported")),
    (0x3E8, "HalPreprocessNmi", R("HalpPreprocessNmi")),
    (0x3F0, "HalEnumerateEnvironmentVariablesWithFilter", R("HalpEnumerateEnvironmentVariablesWithFilter")),
    (0x3F8, "HalCaptureLastBranchRecordStack", R("HalpLbrCaptureStack")),
    (0x400, "HalClearLastBranchRecordStack", R("HalpLbrClearStack")),
    (0x408, "HalConfigureLastBranchRecord", R("HalpLbrConfigureRecording")),
    (0x410, "HalGetLastBranchInformation", R("HalpLbrGetInformation")),
    (0x418, "HalResumeLastBranchRecord", R("HalpLbrResumeRecording")),
    (0x420, "HalStartLastBranchRecord", R("HalpLbrStartRecording")),
    (0x428, "HalStopLastBranchRecord", R("HalpLbrStopRecording")),
    (0x430, "HalIommuBlockDevice", R("HalpIommuBlockDevice")),
    (0x438, "HalIommuUnblockDevice", R("HalpIommuUnblockDevice")),
    (0x440, "HalGetIommuInterface", R("HalpGetIommuInterface")),
    (0x448, "HalRequestGenericErrorRecovery", R("HalpRequestGenericErrorRecovery")),
    (0x450, "HalTimerQueryHostPerformanceCounter", R("HalpTimerQueryHostPerformanceCounter")),
    (0x458, "HalTopologyQueryProcessorRelationships", D("not_supported")),
    (0x460, "HalInitPlatformDebugTriggers", R("HaliInitializePlatformDebugTriggers")),
    (0x468, "HalRunPlatformDebugTriggers", R("HaliRunPlatformDebugTriggers")),
    (0x470, "HalTimerGetReferencePage", R("HalpTimerGetReferencePage")),
    (0x478, "HalGetHiddenProcessorPowerInterface", R("HalpBlkPoGetPowerInterface")),
    (0x480, "HalGetHiddenProcessorPackageId", R("HalpBlkPoGetPackageId")),
    (0x488, "HalGetHiddenPackageProcessorCount", R("HalpBlkPoGetProcessorCount")),
    (0x490, "HalGetHiddenProcessorApicIdByIndex", R("HalpBlkPoGetApicIdByIndex")),
    (0x498, "HalRegisterHiddenProcessorIdleState", R("HalpBlkPoRegisterIdleState")),
    (0x4A0, "HalIommuReportIommuFault", R("HalpIommuReportIommuFault")),
    (0x4A8, "HalIommuDmaRemappingCapable", R("HalpIommuDmaRemappingCapable")),
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
    kernel_address::virtual_address(entry)
}

/// HalInitSystem: grava a versão e os ponteiros do boot na tabela exportada.
pub fn initialize() -> Result<(), KernelError> {
    let table = kernel_data::address("HalPrivateDispatchTable")?;
    let stubs = native("hal_private_stubs")?;
    guest::write32(table, VERSION);
    for (index, &(offset, _, entry)) in SLOTS.iter().enumerate() {
        let pointer = match entry {
            Entry::Null => 0,
            Entry::Default(body) => native(&alloc::format!("hal_default_{body}"))?,
            Entry::Routine(_) => stubs + index as u64 * crate::hal::amd64::win32_thunk::STUB_SIZE,
        };
        guest::write64(table + offset, pointer);
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
    for index in 0..length {
        let ok = if write {
            super::pci_config::write(bus, device, function, offset + index, 1, guest::read8(buffer + index as u64) as u32).is_ok()
        } else {
            match super::pci_config::read(bus, device, function, offset + index, 1) {
                Ok(value) => {
                    guest::write8(buffer + index as u64, value as u8);
                    true
                }
                Err(_) => false,
            }
        };
        if !ok {
            return index as u64;
        }
    }
    length as u64
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
        // Reinicializa o vídeo em modo texto (o int 10h modo 3 do original).
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
            guest::write64(call.arg(5), call.arg(3));
            1
        }
        "HalpFindBusAddressTranslation" => {
            let (bus_address, translated, context, next_bus) = (call.arg(1), call.arg(3), call.arg(4), call.arg(5) as u8);
            if context == 0 || (guest::read64(context) != 0 && next_bus == 1) {
                0
            } else {
                guest::write64(context, 1);
                guest::write64(translated, bus_address);
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
            super::acpi::get_table(&text, 0, false).map_or(0, |table| table.address)
        }
        // A memória física baixa é mapeada em identidade (como o MmMapIoSpace).
        "HalpMapPhysicalMemoryWriteThrough64" | "HalpMapEarlyPages" => call.arg(1),
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
                        guest::write64(call.arg(3), crate::ntos::mm::paging::translate(address));
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
                guest::write64(call.arg(2), 0);
            }
            STATUS_NOT_SUPPORTED
        }
        "HalpDpReplayInterrupts" => STATUS_NOT_SUPPORTED,
        // ---- WHEA ------------------------------------------------------------
        "HalpWheaInitProcessorGenericSection" => {
            let (descriptor, section) = (call.arg(1), call.arg(2));
            guest::write_bytes(descriptor, &[0; 0x48]);
            guest::write32(descriptor + 4, 0xC0);
            guest::write16(descriptor + 8, 0x300);
            guest::write_bytes(descriptor + 0x10, &PROCESSOR_GENERIC_SECTION_GUID);
            guest::write32(descriptor + 0x30, 3);
            guest::write_bytes(section, &[0; 0xC0]);
            guest::write8(section + 9, 2);
            guest::write64(section, 0x143);
            guest::write64(section + 0x10, cpu::cpuid(1)[0] as u64);
            guest::write64(section + 0x98, current_apic_id() as u64);
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
            for output in [call.arg(1), call.arg(2)] {
                if output != 0 {
                    guest::write64(output, 0);
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
                guest::write64(call.arg(1), crate::ntos::ke::clock::tsc_frequency_hz());
            }
            cpu::rdtsc()
        }
        // Timer do relógio: LAPIC periódico de 100 Hz por CPU (10 ms fixos).
        "HalpTimerGetClockConfiguration" => {
            let configuration = call.arg(1);
            guest::write_bytes(configuration, &[0; 32]);
            guest::write8(configuration, 1 << 2);
            guest::write32(configuration + 4, 0);
            guest::write32(configuration + 8, 1);
            guest::write64(configuration + 0x10, 100_000);
            guest::write32(configuration + 0x18, 100_000);
            0
        }
        "HalpTimerClockActivate" | "HalpTimerClockInitialize" | "HalpTimerClockStop" => 0,
        "HalpTimerClockArm" => {
            if call.arg(3) != 0 {
                guest::write64(call.arg(3), 100_000);
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
                    for output in [call.arg(2), call.arg(3)] {
                        if output != 0 {
                            guest::write32(output, apic_id);
                        }
                    }
                    STATUS_SUCCESS
                }
                None => STATUS_NOT_FOUND,
            }
        }
        "HalpInterruptQueryProcessorRestartEntryPoint" => {
            guest::write64(call.arg(1), 0);
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
                    guest::write_bytes(information, &[0; 0x20]);
                    guest::write16(information, 1);
                    guest::write16(information + 2, 0x20);
                    guest::write32(information + 8, 1);
                    guest::write32(information + 0xC, 1);
                    guest::write32(information + 0x10, line);
                    guest::write16(information + 0x14, line as u16);
                    if crate::hal::amd64::native_call::call(callback, &[context, information]) & 0xFF == 0 {
                        break;
                    }
                }
                STATUS_SUCCESS
            }
        }
        "HalpInterruptVectorDataToGsiv" => {
            let vector_data = call.arg(1);
            match guest::read32(vector_data) {
                0 => {
                    guest::write32(call.arg(2), guest::read32(vector_data + 0x38));
                    STATUS_SUCCESS
                }
                3 => STATUS_NOT_SUPPORTED,
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
            guest::write_bytes(call.arg(1), &[0; 504]);
            0
        }
        "HalpSaveAndDisableEnlightenment" | "HalpRestoreHvEnlightenment" => 0,
        // ---- IOMMU (ausente) -------------------------------------------------
        "HalpIommuRegisterDispatchTable" => {
            let mut state = STATE.lock();
            if !state.iommu_dispatch_called && call.arg(1) != 0 {
                state.iommu_dispatch_called = true;
                guest::write64(call.arg(1), native("hal_default_false")?);
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
