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

use crate::hal::{acpi, cpu, port};

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
