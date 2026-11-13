//! Consultas do Driver Verifier feitas pelo Mm (o `verifier.c` do NT, lado Mm).
//!
//! O OpenNT não tem Driver Verifier: os ramos abaixo são os que o ntoskrnl
//! 19041 executa numa máquina sem verificador, não stubs. As duas consultas por
//! imagem leem o bit real da entrada do loader.
//!
//! - MmIsVerifierEnabled: `ViVerifierDriverAddedThunkListHead == 0` -> zera a
//!   saída opcional e devolve STATUS_NOT_SUPPORTED.
//! - MmIsDriverVerifying: `DriverObject->DriverSection` (+0x28) ->
//!   KLDR_DATA_TABLE_ENTRY.Flags (+0x68) bit 25 (LDRP_IMAGE_VERIFYING).
//! - MmIsDriverVerifyingByAddress: MiLookupDataTableEntry(Address) -> o mesmo
//!   bit (o OpenNT publica `LoadedImage.loader_flags` em +0x68).
//! - MmAddVerifierThunks: `MiFlags & 1` / VfIsVerifierEnabled falsos ->
//!   STATUS_NOT_SUPPORTED.
//! - MmIsDriverSuspectForVerifier: DriverSection NULL -> FALSE; senão
//!   ViIsDriverSuspectForVerifier percorre VfSuspectDriversList, vazia sem
//!   verificador -> FALSE.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DriverObject, KldrDataTableEntry};
use crate::ntos::mm::loaded_images;

const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// LDRP_IMAGE_VERIFYING (`bt eax, 0x19`).
const IMAGE_VERIFYING: u32 = 1 << 25;

fn entry_verifying(entry: u64) -> bool {
    // SAFETY: DRIVER_OBJECT.DriverSection é a KLDR_DATA_TABLE_ENTRY do driver.
    entry != 0 && unsafe { KldrDataTableEntry::at(entry) }.flags.get() & IMAGE_VERIFYING != 0
}

/// MmIsVerifierEnabled(PULONG VerifierFlags).
pub fn is_enabled(verifier_flags: u64) -> u32 {
    if verifier_flags != 0 {
        // SAFETY: PULONG de saída do chamador de kernel.
        unsafe { Field::<u32>::at(verifier_flags) }.set(0);
    }
    STATUS_NOT_SUPPORTED
}

/// MmIsDriverVerifying(DriverObject).
pub fn is_driver_verifying(driver: u64) -> bool {
    // SAFETY: o DRIVER_OBJECT do chamador.
    entry_verifying(unsafe { DriverObject::at(driver) }.driver_section.get())
}

/// MmIsDriverVerifyingByAddress(Address): nenhuma imagem = FALSE.
pub fn is_driver_verifying_by_address(address: u64) -> bool {
    loaded_images::find(address).is_some_and(|image| image.loader_flags & IMAGE_VERIFYING != 0)
}

/// MmAddVerifierThunks(ThunkBuffer, ThunkBufferSize): verificador inativo.
pub fn add_thunks(_buffer: u64, _size: u32) -> u32 {
    STATUS_NOT_SUPPORTED
}

/// MmIsDriverSuspectForVerifier(DriverObject): a lista de suspeitos está
/// vazia sem verificador, com ou sem DriverSection.
pub fn is_driver_suspect(driver: u64) -> bool {
    // SAFETY: o DRIVER_OBJECT do chamador.
    let _section = unsafe { DriverObject::at(driver) }.driver_section.get();
    false
}

// ---- VfIsVerificationEnabled / VfFailDeviceNode / VfFailSystemBIOS ----------
//
// ntoskrnl 19041: VfIsVerificationEnabled rva 0x3a6b10 devolve FALSE enquanto
// ViDdiInitialized == 0 (o verificador de DDI nunca inicializou: Driver Verifier
// desligado); VfFailDeviceNode rva 0x3a6ad0 só chama
// VerifierBugCheckIfAppropriate quando VfIsVerificationEnabled(VFOBJTYPE_DEVICE)
// é verdadeiro, e VfFailSystemBIOS rva 0x5a0750 só com ViDdiInitialized e o bit
// 0x40000000 de MmVerifierData. Sem Driver Verifier no OpenNT, os três seguem o
// ramo "verificador desligado": FALSE e nenhuma ação.

/// VfIsVerificationEnabled(VerifierObjectType, Object).
pub fn is_verification_enabled(_object_type: u32, _object: u64) -> bool {
    false
}

/// VfFailDeviceNode(PhysicalDeviceObject, BugCheckMajorCode, BugCheckMinorCode,
/// FailureClass, AssertionControl, DebuggerMessageText, ParameterFormatString, ...):
/// sem verificação ligada para o PDO, retorna sem efeito.
pub fn fail_device_node(physical_device: u64) {
    let _ = is_verification_enabled(1, physical_device);
}

/// VfFailSystemBIOS(BugCheckMajorCode, BugCheckMinorCode, FailureClass, ...).
pub fn fail_system_bios() {}
