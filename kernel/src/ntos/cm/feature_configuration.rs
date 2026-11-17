//! As consultas de configuração de features do NtQuerySystemInformationEx:
//! SystemFeatureConfigurationInformation (210) e
//! SystemFeatureConfigurationSectionInformation (211), como o ntoskrnl
//! 19041 as responde.
//!
//! - CmQuerySingleFeatureConfiguration (rva 0x86b11c), a 210: a entrada são
//!   exatamente 8 bytes (FeatureId e ConfigurationType, capturados), senão
//!   STATUS_INFO_LENGTH_MISMATCH sem tamanho; a saída exatamente 0x18 bytes,
//!   senão STATUS_INFO_LENGTH_MISMATCH com o tamanho 0x18. Depois vem o
//!   RtlQueryFeatureConfiguration do kernel: com STATUS_NOT_FOUND (ou
//!   0x80000022) a saída é zerada com o carimbo de mudança nos primeiros
//!   8 bytes, o tamanho é 0x18 e o status volta ao chamador (a ntdll guarda
//!   só o carimbo e trata a feature como não configurada).
//! - CmQueryFeatureConfigurationSections (rva 0x6842dc), a 211: a entrada
//!   são exatamente 0x18 bytes (o carimbo que o chamador conhece de cada uma
//!   das três seções), a saída exatamente 0x50 bytes (o tamanho 0x50 também
//!   na recusa). O CmFcManagerQueryFeatureConfigurationSectionInformation
//!   copia o estado das seções mais novas que o carimbo do chamador e abre um
//!   handle para cada uma; a saída leva o carimbo geral e, por seção, o
//!   carimbo, o handle e o tamanho. O Cm do OpenNT não tem seções de
//!   configuração (o armazém está vazio e os carimbos são zero, os mesmos do
//!   RtlQueryFeatureConfigurationChangeStamp): nenhuma seção é mais nova, a
//!   saída vai zerada com o carimbo geral, o tamanho é 0x50 e o status
//!   STATUS_SUCCESS.
//!
//! O tamanho (`reported`) é a célula local do ExpQuerySystemInformation,
//! que começa em zero e vai para o ReturnLength também nas falhas.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;
use crate::ntos::rtl::feature_configuration as rtl_feature_configuration;
use crate::rtl::KernelError;

pub const SYSTEM_FEATURE_CONFIGURATION_INFORMATION: u32 = 210;
pub const SYSTEM_FEATURE_CONFIGURATION_SECTION_INFORMATION: u32 = 211;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// O status de consulta adiada do RtlQueryFeatureConfiguration (acima de
/// DISPATCH_LEVEL ou no desligamento).
const STATUS_FEATURE_QUERY_DEFERRED: u32 = 0x8000_0022;
const SINGLE_INPUT: u32 = 8;
const SINGLE_OUTPUT: u32 = 0x18;
const SECTIONS_INPUT: u32 = 0x18;
const SECTIONS_OUTPUT: u32 = 0x50;

/// CmQuerySingleFeatureConfiguration, com a entrada e a saída já sondadas
/// quando o chamador é de modo usuário.
pub fn query_single(input: u64, input_length: u32, output: u64, output_length: u32, reported: &mut u32) -> Result<u32, KernelError> {
    if input_length != SINGLE_INPUT {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    // FeatureId e ConfigurationType, capturados (o armazém vazio não os usa).
    let _request = guest::try_read::<u64>(input)?;
    if output_length != SINGLE_OUTPUT {
        *reported = SINGLE_OUTPUT;
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let status = rtl_feature_configuration::query();
    if status == STATUS_NOT_FOUND || status == STATUS_FEATURE_QUERY_DEFERRED {
        let mut bytes = [0u8; SINGLE_OUTPUT as usize];
        bytes[..8].copy_from_slice(&rtl_feature_configuration::change_stamp().to_le_bytes());
        guest::try_write_bytes(output, &bytes)?;
        *reported = SINGLE_OUTPUT;
    }
    Ok(status)
}

/// CmQueryFeatureConfigurationSections, com a entrada e a saída já sondadas
/// quando o chamador é de modo usuário.
pub fn query_sections(input: u64, input_length: u32, output: u64, output_length: u32, reported: &mut u32) -> Result<u32, KernelError> {
    if input_length != SECTIONS_INPUT {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    // Os carimbos que o chamador conhece, capturados: nenhuma seção do
    // armazém vazio é mais nova que eles.
    let _known = guest::try_read_bytes(input, SECTIONS_INPUT as usize)?;
    if output_length != SECTIONS_OUTPUT {
        *reported = SECTIONS_OUTPUT;
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let mut bytes = [0u8; SECTIONS_OUTPUT as usize];
    bytes[..8].copy_from_slice(&rtl_feature_configuration::change_stamp().to_le_bytes());
    guest::try_write_bytes(output, &bytes)?;
    *reported = SECTIONS_OUTPUT;
    Ok(0)
}

/// As duas classes pelo NtQuerySystemInformationEx de modo usuário: a
/// entrada não nula nem vazia (STATUS_INVALID_PARAMETER), o ProbeForRead
/// dela com o alinhamento da classe (4 na 210, 8 na 211), o ProbeForWrite
/// da saída (alinhamento 4) e do ReturnLength; o ReturnLength recebe a
/// célula de tamanho no fim.
pub fn query_user(class: u32, input: u64, input_length: u32, output: u64, output_length: u32, returned: u64) -> Result<u32, KernelError> {
    if input == 0 || input_length == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let alignment = if class == SYSTEM_FEATURE_CONFIGURATION_INFORMATION { 4 } else { 8 };
    if input & (alignment - 1) != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !user_probe::probe_user_read(input, input_length as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if output_length != 0 && output & 3 != 0 {
        return Ok(STATUS_DATATYPE_MISALIGNMENT);
    }
    if (output_length != 0 && !user_probe::probe_user_write(output, output_length as u64)) || (returned != 0 && !user_probe::probe_user_write(returned, 4)) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let mut reported = 0u32;
    let status = match if class == SYSTEM_FEATURE_CONFIGURATION_INFORMATION { query_single(input, input_length, output, output_length, &mut reported) } else { query_sections(input, input_length, output, output_length, &mut reported) } {
        Ok(status) => status,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    if returned != 0 && guest::try_write::<u32>(returned, reported).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}
