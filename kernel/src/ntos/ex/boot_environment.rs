//! Identidade e flags desta inicialização — `system32/ntos/ex/boot-environment.js`.
//!
//! O loader é dono das flags e do firmware; o kernel cria uma identidade
//! para o boot (UUID v4 por RDRAND) antes de carregar drivers. Falta de
//! entropia não vira constante nem GUID derivado do relógio.

use crate::hal::cpu;
use crate::hal::firmware_environment;
use crate::ntos::mm::memory_map;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

static INFORMATION: SpinLock<Option<[u8; 32]>> = SpinLock::new(None);

pub fn init() -> Result<(), KernelError> {
    if INFORMATION.lock().is_some() {
        return Err(KernelError::new("boot environment already initialized"));
    }
    let handoff = memory_map::BOOT_FLAGS_PHYS;
    if guest::read32(handoff) != 0x3146_4F42 || guest::read32(handoff + 4) != 16 {
        return Err(KernelError::new("missing boot flags handoff"));
    }
    let firmware_type = firmware_environment::firmware_type()?;
    let boot_flags = guest::read64(handoff + 8);
    let mut information = [0u8; 32];
    for chunk in information[..16].chunks_mut(8) {
        let random = cpu::hardware_random_u64().ok_or_else(|| KernelError::new("hardware entropy unavailable for boot identity"))?;
        chunk.copy_from_slice(&random.to_le_bytes());
    }
    // UUID versão 4: Data3 little-endian no GUID Windows; variante no
    // primeiro byte de Data4.
    information[7] = (information[7] & 0x0F) | 0x40;
    information[8] = (information[8] & 0x3F) | 0x80;
    information[16..20].copy_from_slice(&firmware_type.to_le_bytes());
    information[24..32].copy_from_slice(&boot_flags.to_le_bytes());
    // Só publica depois de validar todas as entradas.
    *INFORMATION.lock() = Some(information);
    Ok(())
}

pub fn get_information() -> Result<[u8; 32], KernelError> {
    INFORMATION.lock().ok_or_else(|| KernelError::new("boot environment not initialized"))
}

/// FIRMWARE_TYPE::FirmwareTypeUefi (0 Unknown, 1 Bios, 2 Uefi).
const FIRMWARE_TYPE_UEFI: u64 = 2;

/// ExGetFirmwareType: o OpenNT inicia por UEFI.
pub fn get_firmware_type() -> u64 {
    FIRMWARE_TYPE_UEFI
}
