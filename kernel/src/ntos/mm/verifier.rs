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

use crate::ntos::inc::nt_abi::driver_object;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images;

const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// KLDR_DATA_TABLE_ENTRY.Flags.
const LDR_FLAGS: u64 = 0x68;
/// LDRP_IMAGE_VERIFYING (`bt eax, 0x19`).
const IMAGE_VERIFYING: u32 = 1 << 25;

fn entry_verifying(entry: u64) -> bool {
    entry != 0 && guest::read32(entry + LDR_FLAGS) & IMAGE_VERIFYING != 0
}

/// MmIsVerifierEnabled(PULONG VerifierFlags).
pub fn is_enabled(verifier_flags: u64) -> u32 {
    if verifier_flags != 0 {
        guest::write32(verifier_flags, 0);
    }
    STATUS_NOT_SUPPORTED
}

/// MmIsDriverVerifying(DriverObject).
pub fn is_driver_verifying(driver: u64) -> bool {
    entry_verifying(guest::read64(driver + driver_object::DRIVER_SECTION))
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
    let _section = guest::read64(driver + driver_object::DRIVER_SECTION);
    false
}
