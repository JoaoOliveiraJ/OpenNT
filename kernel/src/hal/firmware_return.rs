//! Saída para o firmware no fim do desligamento (o HalReturnToFirmware).
//!
//! - Halt: interrupções desligadas e HLT para sempre (é seguro desligar).
//! - Reboot: o registrador de reset do FADT quando a plataforma o declara
//!   (RESET_REG_SUP, FADT.Flags bit 10, num espaço de I/O), depois o
//!   registrador de controle de reset do chipset (0xCF9 = 0x06) e o pulso
//!   0xFE no controlador de teclado (porta 0x64).
//! - PowerOff: o estado S5 da ACPI: SLP_TYPa do pacote `\_S5_` da DSDT
//!   gravado com SLP_EN no PM1a_CNT_BLK do FADT. Sem FADT ou sem o pacote,
//!   cai no Halt.
//!
//! O HalBugCheckSystem para o sistema por um erro de hardware fatal
//! relatado pelo WHEA/PSHED.

use crate::hal::{acpi, cpu, port};
use crate::ntos::mm::guest_memory as guest;

/// NMI_SECTION_GUID {e71254e7-c1b9-4940-ab76-909703a4320f}.
const NMI_SECTION_GUID: [u8; 16] = [0xE7, 0x54, 0x12, 0xE7, 0xB9, 0xC1, 0x40, 0x49, 0xAB, 0x76, 0x90, 0x97, 0x03, 0xA4, 0x32, 0x0F];
/// XPF_MCA_SECTION_GUID {8a1e1d01-42f9-4557-9c33-565e5cce4e5d}.
const XPF_MCA_SECTION_GUID: [u8; 16] = [0x01, 0x1D, 0x1E, 0x8A, 0xF9, 0x42, 0x57, 0x45, 0x9C, 0x33, 0x56, 0x5E, 0x5C, 0xCE, 0x4E, 0x5D];

/// HalBugCheckSystem(ErrorSource, ErrorRecord) (ntoskrnl 19041 rva
/// 0x4b90a0): percorre os descritores de seção do WHEA_ERROR_RECORD
/// (SectionCount em +0xA, descritores de 0x48 bytes a partir de +0x80, o
/// tipo de seção em +0x10 de cada um). Uma seção NMI sem o bit 0 dos flags
/// do corpo para com NMI_HARDWARE_FAILURE (0x80, 'TDO'); a primeira seção
/// MCA dá o MCi_STATUS (corpo +0x28) aos dois últimos parâmetros do
/// WHEA_UNCORRECTABLE_ERROR (0x124, tipo da fonte em +8, o registro).
pub fn bug_check_system(error_source: u64, error_record: u64) -> ! {
    let sections = guest::read16(error_record + 0xA) as u64;
    let (mut low, mut high) = (0u64, 0u64);
    for index in 0..sections {
        let descriptor = error_record + 0x80 + index * 0x48;
        let section_type = guest::read_bytes(descriptor + 0x10, 16);
        let body = error_record + guest::read32(descriptor) as u64;
        if section_type == NMI_SECTION_GUID && guest::read8(body + 8) & 1 == 0 {
            crate::ntos::ke::bugcheck::bug_check_ex(0x80, 0x004F_4454, 0, 0, 0);
        }
        if section_type == XPF_MCA_SECTION_GUID {
            let status = guest::read64(body + 0x28);
            low = status & 0xFFFF_FFFF;
            high = status >> 32;
            break;
        }
    }
    let source_type = guest::read32(error_source + 8) as i32 as i64 as u64;
    crate::ntos::ke::bugcheck::bug_check_ex(0x124, source_type, error_record, high, low)
}

/// FIRMWARE_REENTRY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Routine {
    Halt,
    Reboot,
    PowerOff,
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

/// SLP_TYPa do `\_S5_` (NameOp '_S5_' PackageOp PkgLength NumElements e o
/// primeiro elemento: ZeroOp, OneOp ou BytePrefix valor).
pub fn s5_sleep_type(dsdt: &[u8]) -> Option<u8> {
    let at = dsdt.windows(4).position(|window| window == b"_S5_")?;
    let mut index = at + 4;
    if *dsdt.get(index)? != 0x12 {
        return None;
    }
    index += 1;
    // PkgLength: os dois bits altos do primeiro byte contam os bytes extras.
    index += 1 + (*dsdt.get(index)? >> 6) as usize;
    index += 1; // NumElements
    match *dsdt.get(index)? {
        0x00 => Some(0),
        0x01 => Some(1),
        0x0A => dsdt.get(index + 1).copied(),
        _ => None,
    }
}

fn reset() {
    if let Some(fadt) = acpi::get_table("FACP", 0, false) {
        let flags = u32_at(&fadt.bytes, 112).unwrap_or(0);
        // RESET_REG (GAS em 116) e RESET_VALUE (128), espaço de I/O (1).
        if flags & (1 << 10) != 0 && fadt.bytes.get(116) == Some(&1) {
            if let (Some(low), Some(&value)) = (u32_at(&fadt.bytes, 120), fadt.bytes.get(128)) {
                port::write8(low as u16, value);
            }
        }
    }
    port::write8(0xCF9, 0x06);
    port::write8(0x64, 0xFE);
}

fn power_off() {
    let Some(fadt) = acpi::get_table("FACP", 0, false) else { return };
    let Some(control) = u32_at(&fadt.bytes, 64).filter(|&port| port != 0) else { return };
    let Some(sleep_type) = acpi::get_table("DSDT", 0, false).and_then(|dsdt| s5_sleep_type(&dsdt.bytes)) else { return };
    port::write16(control as u16, ((sleep_type as u16) << 10) | (1 << 13));
}

/// HalReturnToFirmware: nunca volta.
pub fn return_to_firmware(routine: Routine) -> ! {
    match routine {
        Routine::Reboot => reset(),
        Routine::PowerOff => power_off(),
        Routine::Halt => {}
    }
    cpu::halt_forever()
}
