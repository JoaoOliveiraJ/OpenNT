//! Acessores do EPROCESS: os PsGetProcess*, PsIsProtectedProcess[Light],
//! PsIsSystemProcess e as consultas WOW64.
//!
//! Leem os campos do layout 19041 que o OpenNT mantém, pelo endereço do
//! objeto dado; uma referência válida mantém o objeto consultável depois da
//! saída. Não referenciam nem substituem o processo pelo corrente, salvo nas
//! variantes `current_*` (o processo corrente é o anexado, como o
//! PsGetCurrentProcess).

use super::process;
use crate::ntos::inc::nt_abi::{eprocess, kthread};
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// PsGetProcessId: EPROCESS.UniqueProcessId.
pub fn id(process: u64) -> u64 {
    guest::read64(process + eprocess::UNIQUE_PROCESS_ID)
}

/// PsGetProcessCreateTimeQuadPart: EPROCESS.CreateTime, separado do
/// RundownProtect (+0x458).
pub fn create_time(process: u64) -> u64 {
    guest::read64(process + eprocess::CREATE_TIME)
}

/// PsGetProcessExitStatus.
pub fn exit_status(process: u64) -> u32 {
    guest::read32(process + eprocess::EXIT_STATUS)
}

/// PsGetProcessExitProcessCalled: bit 2 de Flags.
pub fn exit_process_called(process: u64) -> u32 {
    (guest::read32(process + eprocess::FLAGS) >> 2) & 1
}

/// LARGE_INTEGER PsGetProcessExitTime(VOID): o ExitTime do processo corrente.
pub fn current_exit_time() -> u64 {
    guest::read64(process::get_current_process() + eprocess::EXIT_TIME)
}

/// PsGetProcessPeb.
pub fn peb(process: u64) -> u64 {
    guest::read64(process + eprocess::PEB)
}

/// PsGetProcessImageFileName: o endereço do campo ImageFileName.
pub fn image_file_name(process: u64) -> u64 {
    process.wrapping_add(eprocess::IMAGE_FILE_NAME)
}

/// PsGetProcessSectionBaseAddress.
pub fn section_base_address(process: u64) -> u64 {
    guest::read64(process + eprocess::SECTION_BASE_ADDRESS)
}

/// PsGetProcessProtection: PS_PROTECTION completo (Type, Audit e Signer);
/// os testes de tipo usam só os três bits baixos.
pub fn protection(process: u64) -> u8 {
    guest::read8(process + eprocess::PROTECTION)
}

/// PsIsProtectedProcess: qualquer tipo de proteção.
pub fn is_protected(process: u64) -> bool {
    protection(process) & 7 != 0
}

/// PsIsProtectedProcessLight: tipo PsProtectedTypeProtectedLight (1).
pub fn is_protected_light(process: u64) -> bool {
    protection(process) & 7 == 1
}

/// PsGetProcessSignatureLevel: escreve o nível da seção (se houver saída)
/// antes de ler o da imagem, preservando o resultado quando a saída aponta
/// para um dos campos.
pub fn signature_level(process: u64, section_signature_level: u64) -> u8 {
    if section_signature_level != 0 {
        guest::write8(section_signature_level, guest::read8(process + eprocess::SECTION_SIGNATURE_LEVEL));
    }
    guest::read8(process + eprocess::SIGNATURE_LEVEL)
}

/// PsGetProcessWin32Process.
pub fn win32_process(process: u64) -> u64 {
    guest::read64(process + eprocess::WIN32_PROCESS)
}

/// PsGetCurrentProcessWin32Process.
pub fn current_win32_process() -> u64 {
    win32_process(process::get_current_process())
}

/// PsGetProcessWow64Process: PEB do EWOW64PROCESS; sem ele o processo não
/// tem ambiente WOW64.
pub fn wow64_process(process: u64) -> u64 {
    let wow64_process = guest::read64(process + eprocess::WOW64_PROCESS);
    if wow64_process == 0 {
        0
    } else {
        guest::read64(wow64_process)
    }
}

/// PsGetCurrentProcessWow64Process: processo da thread atual pela região
/// de controle do processador.
pub fn current_wow64_process() -> Result<u64, KernelError> {
    let region = pcr::get_pcr_address();
    if region == 0 {
        return Err(KernelError::new("current WOW64 query requires an initialized KPCR"));
    }
    let thread = guest::read64(region + pcr::layout::PRCB_CURRENT_THREAD);
    Ok(wow64_process(guest::read64(thread + kthread::APC_STATE_PROCESS)))
}

/// PsGetProcessInheritedFromUniqueProcessId.
pub fn inherited_from_unique_process_id(process: u64) -> u64 {
    guest::read64(process + eprocess::INHERITED_FROM_UNIQUE_PROCESS_ID)
}

/// PsGetProcessJob.
pub fn job(process: u64) -> u64 {
    guest::read64(process + eprocess::JOB)
}

/// PsGetProcessSequenceNumber.
pub fn sequence_number(process: u64) -> u64 {
    guest::read64(process + eprocess::SEQUENCE_NUMBER)
}

/// PsGetProcessPriorityClass.
pub fn priority_class(process: u64) -> u8 {
    guest::read8(process + eprocess::PRIORITY_CLASS)
}

/// PsGetProcessWin32WindowStation.
pub fn win32_window_station(process: u64) -> u64 {
    guest::read64(process + eprocess::WIN32_WINDOW_STATION)
}

/// PsGetProcessSecurityPort.
pub fn security_port(process: u64) -> u64 {
    guest::read64(process + eprocess::SECURITY_PORT)
}

/// PsGetProcessDxgProcess.
pub fn dxg_process(process: u64) -> u64 {
    guest::read64(process + eprocess::DXG_PROCESS)
}

/// PsIsSystemProcess: Flags3.SystemProcess.
pub fn is_system_process(process: u64) -> bool {
    guest::read32(process + eprocess::FLAGS3) & eprocess::SYSTEM_PROCESS_FLAG != 0
}
