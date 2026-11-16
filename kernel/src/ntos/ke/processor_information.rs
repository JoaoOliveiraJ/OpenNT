//! SystemProcessorInformation e SystemProcessorFeaturesInformation.
//!
//! O ExpGetSystemProcessorInformation do 19041 devolve
//! KeProcessorArchitecture (0 na classe emulada), KeProcessorLevel,
//! KeProcessorRevision, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS)
//! e o ULONG baixo de KeFeatureBits; o
//! ExpGetSystemProcessorFeaturesInformation, o KeFeatureBits inteiro e três
//! ULONGLONG reservados zerados. Os valores são os que
//! `processor_identity` montou na KPRCB do BSP.

use super::{processor_group, processor_identity};
use crate::ntos::inc::types::{NtStruct, SystemProcessorInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;

/// PROCESSOR_ARCHITECTURE_AMD64.
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
/// ALL_PROCESSOR_GROUPS.
const ALL_PROCESSOR_GROUPS: u32 = 0xFFFF;
/// sizeof(SYSTEM_PROCESSOR_FEATURES_INFORMATION).
pub const FEATURES_INFORMATION_SIZE: u32 = 0x20;

/// SYSTEM_PROCESSOR_INFORMATION (12 bytes). A arquitetura emulada altera só
/// o identificador de arquitetura.
pub fn query(
    output: u64,
    buffer_length: u32,
    output_length_pointer: u64,
    from_user_mode: bool,
    report_emulated_architecture: bool,
) -> u32 {
    if from_user_mode {
        if buffer_length != 0 && output % 4 != 0 {
            return 0x8000_0002;
        }
        if !user_probe::probe_user_write(output, buffer_length as u64)
            || (output_length_pointer != 0 && !user_probe::probe_user_write(output_length_pointer, 4))
        {
            return 0xC000_0005;
        }
    }
    let size = SystemProcessorInformation::SIZE as u32;
    // ReturnLength: ponteiro do chamador (do modo usuário quando a chamada vem
    // de lá), escrita sondada.
    let report_length = || output_length_pointer == 0 || guest::try_write::<u32>(output_length_pointer, size).is_ok();
    if buffer_length < size {
        if !report_length() {
            return 0xC000_0005;
        }
        return 0xC000_0004;
    }
    if output == 0 {
        return 0xC000_0005;
    }
    let Ok(information) = SystemProcessorInformation::try_at(output) else { return 0xC000_0005 };
    let architecture = if report_emulated_architecture { 0 } else { PROCESSOR_ARCHITECTURE_AMD64 };
    let written = information.processor_architecture.probe_set(architecture).is_ok()
        && information.processor_level.probe_set(processor_identity::processor_level()).is_ok()
        && information.processor_revision.probe_set(processor_identity::processor_revision()).is_ok()
        && information.maximum_processors.probe_set(processor_group::maximum_processor_count_ex(ALL_PROCESSOR_GROUPS) as u16).is_ok()
        && information.processor_feature_bits.probe_set(processor_identity::feature_bits() as u32).is_ok();
    if !written || !report_length() {
        return 0xC000_0005;
    }
    0
}

/// SYSTEM_PROCESSOR_FEATURES_INFORMATION: KeFeatureBits e três ULONGLONG
/// zerados; com menos de 0x20 bytes, STATUS_INFO_LENGTH_MISMATCH com 0x20 no
/// ReturnLength.
pub fn query_features(output: u64, buffer_length: u32, output_length_pointer: u64, from_user_mode: bool) -> u32 {
    if from_user_mode {
        if buffer_length != 0 && output % 4 != 0 {
            return 0x8000_0002;
        }
        if !user_probe::probe_user_write(output, buffer_length as u64)
            || (output_length_pointer != 0 && !user_probe::probe_user_write(output_length_pointer, 4))
        {
            return 0xC000_0005;
        }
    }
    let report_length = || output_length_pointer == 0 || guest::try_write::<u32>(output_length_pointer, FEATURES_INFORMATION_SIZE).is_ok();
    if buffer_length < FEATURES_INFORMATION_SIZE {
        return if report_length() { 0xC000_0004 } else { 0xC000_0005 };
    }
    let mut bytes = [0u8; FEATURES_INFORMATION_SIZE as usize];
    bytes[..8].copy_from_slice(&processor_identity::feature_bits().to_le_bytes());
    if guest::try_write_bytes(output, &bytes).is_err() || !report_length() {
        return 0xC000_0005;
    }
    0
}
