//! Identificação do sistema publicada pelo Rtl — versão (RtlGetVersion,
//! RtlVerifyVersionInfo, VerSetConditionMask), produto (RtlGetNtProductType,
//! RtlGetProductInfo, RtlGetSuiteMask, RtlIsMultiSessionSku), a raiz do
//! sistema (RtlGetNtSystemRoot) e os recursos estendidos da CPU
//! (RtlGetEnabledExtendedFeatures) e as versões de DDI que ele aceita
//! (RtlIsNtDdiVersionAvailable).
//!
//! Windows 10.0.26100, Win32 NT, estação de trabalho Professional, sem
//! multissessão; os recursos estendidos são os da XState (`ke::xsave`).

use alloc::vec::Vec;

use crate::ntos::inc::types::{Field, NtStruct, OsVersionInfoExW};

/// Versão publicada (10.0.26100).
const VERSION: (u32, u32, u32) = (10, 0, 26100);

/// Status de versão que não confere.
const VERSION_MISMATCH: u32 = 0xC000_0428;

/// KUSER_SHARED_DATA.NtSystemRoot.
const NT_SYSTEM_ROOT: u64 = 0xFFFF_F780_0000_0030;

/// NtProductWinNt.
const NT_PRODUCT_WIN_NT: u32 = 1;

/// PRODUCT_PROFESSIONAL.
const PRODUCT_PROFESSIONAL: u32 = 0x0000_0030;

/// VER_PLATFORM_WIN32_NT.
const VER_PLATFORM_WIN32_NT: u32 = 2;
/// VER_SUITE_SINGLEUSERTS (estação de trabalho com uma sessão interativa).
const VER_SUITE_SINGLEUSERTS: u16 = 0x100;
/// VER_NT_WORKSTATION.
const VER_NT_WORKSTATION: u8 = 1;

/// RTL_OSVERSIONINFO[EX]W do chamador: os campos comuns às duas versões
/// valem para ambas; os do EX só existem quando dwOSVersionInfoSize diz.
fn version_info(info: u64) -> &'static OsVersionInfoExW {
    // SAFETY: estrutura de versão viva e alinhada do chamador; só os campos
    // da versão declarada em dwOSVersionInfoSize são tocados.
    unsafe { OsVersionInfoExW::at(info) }
}

/// RtlVerifyVersionInfo: blocos de 3 bits da máscara de condição. Devolve o
/// NTSTATUS.
pub fn verify(info: u64, type_mask: u32, condition: u64) -> u32 {
    let info = version_info(info);
    let mut checks = Vec::new();
    if type_mask & 1 != 0 {
        checks.push((info.dw_major_version.get(), VERSION.0));
    }
    if type_mask & 2 != 0 {
        checks.push((info.dw_minor_version.get(), VERSION.1));
    }
    if type_mask & 4 != 0 {
        checks.push((info.dw_build_number.get(), VERSION.2));
    }
    // Aplica o operador do bloco baixo a todos os campos.
    let operator = condition & 7;
    for (expected, actual) in checks {
        let matches = match operator {
            1 => actual == expected,
            2 => actual > expected,
            4 => actual < expected,
            3 => actual >= expected,
            5 => actual <= expected,
            _ => true,
        };
        if !matches {
            return VERSION_MISMATCH;
        }
    }
    0
}

/// VerSetConditionMask: condição deslocada por 3 bits × tipo (aproximação).
pub fn set_condition_mask(mask: u64, type_mask: u32, condition: u32) -> u64 {
    let shift = type_mask.saturating_mul(3);
    let increment = if shift < 64 { (condition as u64) << shift } else { 0 };
    mask.wrapping_add(increment)
}

/// RtlGetVersion: 10.0.26100, Win32 NT, sem service pack (szCSDVersion
/// vazio). Os campos do RTL_OSVERSIONINFOEXW (service pack, suíte e tipo de
/// produto: estação de trabalho) só são escritos quando dwOSVersionInfoSize
/// é o tamanho do EX — um RTL_OSVERSIONINFOW termina antes deles.
pub fn write_version_information(info: u64) {
    let info = version_info(info);
    info.dw_major_version.set(VERSION.0);
    info.dw_minor_version.set(VERSION.1);
    info.dw_build_number.set(VERSION.2);
    info.dw_platform_id.set(VER_PLATFORM_WIN32_NT);
    info.sz_csd_version[0].set(0);
    if info.dw_os_version_info_size.get() as u64 == OsVersionInfoExW::SIZE {
        info.w_service_pack_major.set(0);
        info.w_service_pack_minor.set(0);
        info.w_suite_mask.set(VER_SUITE_SINGLEUSERTS);
        info.w_product_type.set(VER_NT_WORKSTATION);
        info.w_reserved.set(0);
    }
}

/// RtlGetNtProductType(PNT_PRODUCT_TYPE): NtProductWinNt, TRUE.
pub fn nt_product_type(output: u64) -> bool {
    // SAFETY: PNT_PRODUCT_TYPE do chamador.
    unsafe { Field::<u32>::at(output) }.set(NT_PRODUCT_WIN_NT);
    true
}

/// RtlGetSuiteMask(): KUSER_SHARED_DATA.SuiteMask (estação de trabalho = 0).
pub fn suite_mask() -> u32 {
    0
}

/// RtlIsMultiSessionSku() (0x6816a0): o bit 8 de SharedDataFlags fora de
/// server silos, o byte do silo dentro de um.
pub fn is_multi_session_sku() -> bool {
    crate::ntos::se::capability::policy::is_multi_session() != 0
}

/// RtlGetProductInfo(OSMajor, OSMinor, SpMajor, SpMinor, PULONG ProductType):
/// edição fixa PRODUCT_PROFESSIONAL, TRUE.
pub fn product_info(product_type: u64) -> bool {
    // SAFETY: PULONG ReturnedProductType do chamador.
    unsafe { Field::<u32>::at(product_type) }.set(PRODUCT_PROFESSIONAL);
    true
}

/// NTDDI_WIN10_VB: a versão de DDI do ntoskrnl 19041.
const NTDDI_WIN10_VB: u32 = 0x0A00_0008;

/// RtlIsNtDdiVersionAvailable(Version) (ntoskrnl 19041 0x3cc5e0): os dois
/// bytes baixos (o service pack de OSVER e o sub-release) precisam ser zero e
/// a versão não pode passar de NTDDI_WIN10_VB.
pub fn is_ntddi_version_available(version: u32) -> bool {
    (version >> 8 | version) & 0xFF == 0 && version <= NTDDI_WIN10_VB
}

/// RtlGetNtSystemRoot: o texto em KUSER_SHARED_DATA.
pub fn nt_system_root() -> u64 {
    NT_SYSTEM_ROOT
}

/// RtlGetEnabledExtendedFeatures(FeatureMask): (XState.EnabledFeatures |
/// XState.EnabledUserVisibleSupervisorFeatures) & FeatureMask.
pub fn enabled_extended_features(feature_mask: u64) -> u64 {
    use crate::ntos::ke::xsave;
    (xsave::enabled_features() | xsave::enabled_user_visible_supervisor_features()) & feature_mask
}

/// RtlGetEnabledExtendedAndSupervisorFeatures(FeatureMask):
/// (XState.EnabledFeatures | XState.EnabledSupervisorFeatures) & FeatureMask.
pub fn enabled_extended_and_supervisor_features(feature_mask: u64) -> u64 {
    use crate::ntos::ke::xsave;
    (xsave::enabled_features() | xsave::enabled_supervisor_features()) & feature_mask
}
