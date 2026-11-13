//! Identidade e flags desta inicialização.
//!
//! O loader é dono das flags e do firmware; o kernel cria uma identidade
//! para o boot (UUID v4 por RDRAND) antes de carregar drivers. Falta de
//! entropia não vira constante nem GUID derivado do relógio.

use crate::hal::cpu;
use crate::hal::firmware_environment;
use crate::ntos::mm::memory_map;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::rtl::{KernelError, SpinLock};

static INFORMATION: SpinLock<Option<[u8; 32]>> = SpinLock::new(None);

/// Página de passagem do loader: assinatura 'BOF1', tamanho e as flags.
#[repr(C)]
struct BootFlagsHandoff {
    signature: Field<u32>,
    size: Field<u32>,
    flags: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for BootFlagsHandoff {}

const _: () = assert!(core::mem::size_of::<BootFlagsHandoff>() == 16);

pub fn init() -> Result<(), KernelError> {
    if INFORMATION.lock().is_some() {
        return Err(KernelError::new("boot environment already initialized"));
    }
    // SAFETY: handoff físico preenchido pelo loader, lido pelo mapa direto.
    let handoff = unsafe { BootFlagsHandoff::at(crate::hal::physical::range_to_virtual(memory_map::BOOT_FLAGS_PHYS, BootFlagsHandoff::SIZE)) };
    if handoff.signature.get() != 0x3146_4F42 || handoff.size.get() as u64 != BootFlagsHandoff::SIZE {
        return Err(KernelError::new("missing boot flags handoff"));
    }
    let firmware_type = firmware_environment::firmware_type()?;
    let boot_flags = handoff.flags.get();
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
