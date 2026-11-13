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

/// Sem sondagem, conversão de nome, alocação nem modificação de saídas,
/// inclusive com argumentos NULL ou desalinhados.
pub fn query(_name: u64, _guid: u64, _value: u64, _length: u64, _attributes: u64) -> Result<u32, KernelError> {
    if firmware_type()? == 1 {
        return Ok(0xC000_0002); // STATUS_NOT_IMPLEMENTED no BIOS legado
    }
    Err(KernelError::new("firmware variable provider unavailable"))
}
