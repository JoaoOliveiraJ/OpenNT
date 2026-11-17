//! Ambiente de firmware.
//!
//! As capacidades de firmware vêm do loader que realmente iniciou o sistema:
//! o handoff BIOS do stage2 não tem serviços de runtime EFI nem armazém de
//! variáveis. NtQuerySystemEnvironmentValueEx (KernelMode) também confere
//! essa propriedade da plataforma antes de ler argumentos ou gravar saídas.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::physical;
use crate::ntos::mm::memory_map;
use crate::rtl::KernelError;

/// 0 = ainda não inicializado; 1 = BIOS legado.
static FIRMWARE_TYPE: AtomicU32 = AtomicU32::new(0);

/// Lê o handoff "FWT1" do stage2.
pub fn init() -> Result<(), KernelError> {
    let base = memory_map::BOOT_FIRMWARE_PHYS;
    if physical::read32(base) != 0x3154_5746 {
        return Err(KernelError::new("missing firmware boot handoff"));
    }
    let actual = physical::read32(base + 4);
    if actual != 1 {
        return Err(KernelError::new(alloc::format!("unsupported firmware boot handoff type {actual}")));
    }
    FIRMWARE_TYPE.store(actual, Ordering::Release);
    debug_print!("[firmware] BIOS loader; EFI runtime variables unavailable");
    Ok(())
}

pub fn firmware_type() -> Result<u32, KernelError> {
    match FIRMWARE_TYPE.load(Ordering::Acquire) {
        0 => Err(KernelError::new("firmware boot handoff not initialized")),
        value => Ok(value),
    }
}

/// NtGetEnvironmentVariableEx e NtQueryEnvironmentVariableInfoEx (ntoskrnl
/// 19041): fora do firmware EFI (ExpFirmwareType != 2), STATUS_NOT_IMPLEMENTED
/// antes de tocar qualquer argumento.
pub fn nt_environment_variable_ex() -> Result<u32, KernelError> {
    if firmware_type()? == 1 {
        return Ok(0xC000_0002);
    }
    Err(KernelError::new("firmware variable provider unavailable"))
}

/// HalSetEnvironmentVariableEx: sem HalFirmwareTypeEfi, STATUS_NOT_IMPLEMENTED.
/// HalEnumerateEnvironmentVariablesEx(InformationClass, Buffer, BufferLength)
/// é o HalpEnumerateEnvironmentVariablesWithFilter sem filtro, que no BIOS
/// também devolve STATUS_NOT_IMPLEMENTED.
pub fn hal_environment_variable_ex() -> Result<u32, KernelError> {
    nt_environment_variable_ex()
}

/// ExSetFirmwareEnvironmentVariable(VariableName, VendorGuid, Value,
/// ValueLength, Attributes): fora do firmware EFI (ExpFirmwareType != 2) o
/// ntoskrnl devolve STATUS_NOT_IMPLEMENTED antes de converter o nome (o
/// ExpUnicodeStringToNonpagedWStr) e sem ler o valor.
pub fn set(_name: u64, _guid: u64, _value: u64, _length: u32, _attributes: u32) -> Result<u32, KernelError> {
    if firmware_type()? == 1 {
        return Ok(0xC000_0002);
    }
    Err(KernelError::new("firmware variable provider unavailable"))
}

/// NtQuerySystemEnvironmentValueEx de modo usuário (ntoskrnl 19041, rva
/// 0x6a3220): o acesso vem do SeSystemEnvironmentPrivilege do chamador ou,
/// sem ele, de ser membro de SeUserModeDriversSid (S-1-5-84-0-0-0-0-0, o
/// RtlCheckTokenMembershipEx do token efetivo). O ExpFirmwareAccessAppContainerCheck
/// de um AppContainer ainda falta no OpenNT, que segue para a mesma checagem
/// de membro. Sem acesso, STATUS_PRIVILEGE_NOT_HELD; com ele, o firmware BIOS
/// dá STATUS_NOT_IMPLEMENTED antes de tocar os argumentos.
pub fn query_user() -> Result<u32, KernelError> {
    const SE_SYSTEM_ENVIRONMENT_PRIVILEGE: u64 = 22;
    if !crate::ntos::se::privilege::single_privilege_check(SE_SYSTEM_ENVIRONMENT_PRIVILEGE, 1) && !user_mode_driver_member()? {
        return Ok(0xC000_0061);
    }
    if firmware_type()? == 1 {
        return Ok(0xC000_0002);
    }
    Err(KernelError::new("firmware variable provider unavailable"))
}

/// O token efetivo da thread tem o SeUserModeDriversSid.
fn user_mode_driver_member() -> Result<bool, KernelError> {
    use crate::ntos::mm::guest_memory as guest;
    let sid = crate::ntos::se::model::sid(5, &[84, 0, 0, 0, 0, 0]);
    let block = guest::alloc_bytes(sid.len() as u64 + 8);
    if block == 0 {
        return Ok(false);
    }
    guest::write_bytes(block, &sid);
    guest::write8(block + sid.len() as u64, 0);
    let status = crate::ntos::se::capability::token_checks::check_membership(0, block, 0, block + sid.len() as u64)?;
    let member = status & 0x8000_0000 == 0 && guest::read8(block + sid.len() as u64) != 0;
    guest::free_bytes(block);
    Ok(member)
}

/// Sem sondagem, conversão de nome, alocação nem modificação de saídas,
/// inclusive com argumentos NULL ou desalinhados.
pub fn query(_name: u64, _guid: u64, _value: u64, _length: u64, _attributes: u64) -> Result<u32, KernelError> {
    if firmware_type()? == 1 {
        return Ok(0xC000_0002); // STATUS_NOT_IMPLEMENTED no BIOS legado
    }
    Err(KernelError::new("firmware variable provider unavailable"))
}
