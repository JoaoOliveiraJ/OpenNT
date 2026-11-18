//! PsBootPhaseComplete: as políticas do Process Manager lidas quando o
//! Registro fica completo, no CmCompleteRegistryInitialization do
//! NtInitializeRegistry que o smss pede (`cm/hive_init.rs`).
//!
//! Do PsBootPhaseComplete do ntoskrnl 19041 (rva 0x7a8c1c), o OpenNT faz a
//! parte do UAC: os bits DbgElevationEnabled (1), DbgVirtEnabled (2) e
//! DbgInstallerDetectEnabled (3) do KUSER_SHARED_DATA.SharedDataFlags, que o
//! RtlQueryElevationFlags devolve e o lsass lê no LoadParameters
//! (CheckElevationEnabled, o LsapGlobalLUAEnabled). Eles só são olhados com
//! o UAC instalado (`Control\LsaInformation\UACInstalled` REG_DWORD não
//! nulo); então cada um dos valores EnableLUA, EnableVirtualization e
//! EnableInstallerDetection de `Software\...\Policies\System` liga o seu
//! bit, a não ser que seja um REG_DWORD de 4 bytes igual a 0: um valor
//! ausente, de outro tipo, ou a chave ausente também ligam o bit. As outras
//! leituras da rotina (as opções de execução de imagem DevOverrideEnable,
//! MaxLoaderThreads e NoRemoteThreadBeforeProcessInit, o DFSS e os
//! forwarders do silo) não existem no OpenNT.
//!
//! As hives que o xtask grava não têm o `UACInstalled`: no OpenNT o UAC fica
//! desligado até a semente dele entrar.

use core::sync::atomic::Ordering;

use crate::ntos::cm::registry::{self, Value};
use crate::ntos::mm::shared_user_data;

const LSA_INFORMATION: &str = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\LsaInformation";
const SYSTEM_POLICIES: &str = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";
const REG_DWORD: u32 = 4;
/// Os valores de política e o bit de SharedDataFlags de cada um.
const ELEVATION_VALUES: [(&str, u32); 3] = [("EnableLUA", 1), ("EnableVirtualization", 2), ("EnableInstallerDetection", 3)];

/// O dado de um REG_DWORD de 4 bytes (o KEY_VALUE_PARTIAL_INFORMATION que a
/// rotina confere: Type 4 e DataLength 4).
fn dword(value: &Value) -> Option<u32> {
    (value.value_type == REG_DWORD && value.data.len() == 4).then(|| u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]))
}

/// Os bits de SharedDataFlags que o PsBootPhaseComplete liga, lidos das
/// chaves `lsa_information` (o UACInstalled) e `policies`.
pub fn elevation_bits(lsa_information: &str, policies: &str) -> u32 {
    let installed = registry::read_value_by_path(lsa_information, "UACInstalled").and_then(|value| dword(&value)).is_some_and(|value| value != 0);
    if !installed {
        return 0;
    }
    let key = registry::node_by_path(policies).is_some();
    ELEVATION_VALUES
        .iter()
        .filter(|(name, _)| !(key && registry::read_value_by_path(policies, name).and_then(|value| dword(&value)) == Some(0)))
        .fold(0, |bits, &(_, bit)| bits | 1 << bit)
}

/// PsBootPhaseComplete: os bits do UAC na KUSER_SHARED_DATA (o `lock bts`
/// de cada um).
pub fn complete() {
    let bits = elevation_bits(LSA_INFORMATION, SYSTEM_POLICIES);
    if bits == 0 {
        return;
    }
    if let Some(shared) = shared_user_data::data() {
        shared.shared_data_flags.atomic().fetch_or(bits, Ordering::SeqCst);
    }
}
