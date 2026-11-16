//! Saída para o firmware no fim do desligamento (o HalReturnToFirmware).
//!
//! Como no ntoskrnl 19041 (HalReturnToFirmware rva 0x4be0f0):
//! - HalPowerDownRoutine (1): o HalpShutdown (rva 0x4be3dc): os bits de
//!   status do PM1a_EVT e do PM1b_EVT são limpos (lidos e regravados) e,
//!   com o HalpShutdownContext do S5, o PM1a_CNT recebe SLP_TYPa | SLP_EN
//!   ((contexto & 7 | 8) << 10), preservando os bits 0x203 (SCI_EN, BM_RLD e
//!   o bit 9) do valor lido; o PM1b_CNT, se existe, o SLP_TYPb do segundo
//!   nibble. O contexto vem do acpi.sys (HaliAcpiMachineStateInit, ver
//!   `acpi_pm`); sem o acpi.sys carregado, o suporte de boot do OpenNT tira
//!   o SLP_TYPa do pacote `\_S5_` da DSDT, o mesmo objeto que o acpi.sys
//!   avaliaria. Se a máquina não desliga, segue o reinício, como no NT.
//! - HalHaltRoutine (0), HalRestartRoutine (2) e HalRebootRoutine (3): o
//!   HalpPowerWriteResetCommand (rva 0x4be25c), num boot de BIOS (o
//!   HalpMiscIsLegacyPcType): a CMOS 0x0F (estado de desligamento) volta a
//!   0 e o sinal de reinício quente 0x1234 vai a 0x472 (a BIOS Data Area);
//!   com o bit 2 do HalpPlatformFlags, o índice 0x15 vai à porta 0x70; o
//!   RESET_REG da FADT (quando a plataforma o declara) recebe o RESET_VALUE,
//!   com 500 us de espera; com o bit 1, o pulso 0xFE na porta 0x64 (o 8042),
//!   com 5 ms de espera; e o processador para. O HalpPlatformFlags começa em
//!   7 e só uma FADT de revisão 5 ou maior o estreita (HalpSetPlatformFlags,
//!   rva 0xa65198): HW_REDUCED_ACPI tira o bit 0, um IAPC_BOOT_ARCH sem o
//!   8042 tira o bit 1 e o CMOS_RTC_NOT_PRESENT tira o bit 2.
//! - Outras rotinas não fazem nada (o NT só imprime um aviso).
//!
//! As marcas `POWER_OFF` e `REBOOT` saem na serial logo antes da escrita
//! que desliga ou reinicia a máquina.
//!
//! O HalBugCheckSystem para o sistema por um erro de hardware fatal
//! relatado pelo WHEA/PSHED.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::hal::acpi_pm::{self, register};
use crate::hal::{acpi, cpu, physical, port, rtc};
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
    PowerDown,
    Restart,
    Reboot,
}

impl Routine {
    /// O valor do FIRMWARE_REENTRY.
    pub fn from_raw(value: u32) -> Option<Routine> {
        Some(match value {
            0 => Routine::Halt,
            1 => Routine::PowerDown,
            2 => Routine::Restart,
            3 => Routine::Reboot,
            _ => return None,
        })
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(offset..offset + 2)?.try_into().ok()?))
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

/// O HalpShutdownContext: o do acpi.sys, ou o do `\_S5_` da DSDT (o mesmo
/// SLP_TYP nos dois blocos) quando o acpi.sys não o informou. 0 = sem S5.
pub fn shutdown_context() -> u32 {
    let reported = acpi_pm::acpi_shutdown_context();
    if reported != 0 {
        return reported;
    }
    acpi::get_table("DSDT", 0, false).and_then(|dsdt| s5_sleep_type(&dsdt.bytes)).map_or(0, |sleep_type| acpi_pm::shutdown_context(sleep_type as u32, sleep_type as u32))
}

/// O valor do PM1x_CNT que entra no S5: SLP_TYP do nibble, SLP_EN e os bits
/// 0x203 do valor atual.
pub fn sleep_control(current: u16, sleep_type: u32) -> u16 {
    ((((sleep_type & 7) | 8) << 10) as u16) | (current & 0x203)
}

fn pm_read(id: usize) -> Option<u16> {
    let pm = acpi_pm::pm_register(id).filter(|pm| pm.present)?;
    Some(if pm.size == 1 { port::read8(pm.port) as u16 } else { port::read16(pm.port) })
}

fn pm_write(id: usize, value: u16) {
    let Some(pm) = acpi_pm::pm_register(id).filter(|pm| pm.present) else { return };
    if pm.size == 1 {
        port::write8(pm.port, value as u8);
    } else {
        port::write16(pm.port, value);
    }
}

/// HalpShutdownActive: só o primeiro processador entra no HalpShutdown.
static SHUTDOWN_ACTIVE: AtomicBool = AtomicBool::new(false);

/// HalpShutdown: S5 pelo PM1x_CNT. Volta se a máquina não desligou.
fn shutdown() {
    if SHUTDOWN_ACTIVE.swap(true, Ordering::SeqCst) {
        cpu::halt_forever();
    }
    // Os bits de status (escrever 1 limpa) dos dois blocos de eventos.
    if let Some(status) = pm_read(register::PM1A_EVT) {
        let combined = status | pm_read(register::PM1B_EVT).unwrap_or(0);
        pm_write(register::PM1A_EVT, combined);
        pm_write(register::PM1B_EVT, combined);
    }
    let context = shutdown_context();
    let control = pm_read(register::PM1A_CNT);
    debug_print!("POWER_OFF contexto={:#x} PM1a_CNT={:?}", context, acpi_pm::pm_register(register::PM1A_CNT).map(|pm| pm.port));
    if context == 0 {
        return;
    }
    if let Some(current) = control {
        pm_write(register::PM1A_CNT, sleep_control(current, context));
    }
    if let Some(current) = pm_read(register::PM1B_CNT) {
        pm_write(register::PM1B_CNT, sleep_control(current, context >> 4));
    }
}

/// HalpPlatformFlags da FADT (HalpSetPlatformFlags, sem a opção de carga
/// FORCELEGACYPLATFORM): 7, estreitado só numa FADT de revisão >= 5.
pub fn platform_flags(fadt: &[u8]) -> u32 {
    let mut flags = 7;
    if fadt.get(8).copied().unwrap_or(0) < 5 {
        return flags;
    }
    let fadt_flags = u32_at(fadt, 0x70).unwrap_or(0);
    // HW_REDUCED_ACPI.
    if fadt_flags & 0x10_0000 != 0 {
        flags &= !1;
    }
    // IAPC_BOOT_ARCH (FADT +0x6D): 8042 (bit 1) e CMOS_RTC_NOT_PRESENT (bit 5).
    let boot_architecture = u16_at(fadt, 0x6D).unwrap_or(0);
    if boot_architecture & 2 == 0 {
        flags &= !2;
    }
    if boot_architecture & 0x20 != 0 {
        flags &= !4;
    }
    // LOW_POWER_S0_IDLE_CAPABLE.
    if fadt_flags & 0x20_0000 != 0 {
        flags |= 8;
    }
    flags
}

/// HalpPowerWriteResetCommand: os caminhos de reinício do PC, na ordem do
/// NT, e a parada.
fn reset() -> ! {
    cpu::save_and_disable_interrupts();
    let fadt = acpi::get_table("FACP", 0, false);
    let flags = fadt.as_ref().map_or(7, |fadt| platform_flags(&fadt.bytes));
    // Boot de BIOS: o estado de desligamento da CMOS e o BootBiosWarmReset
    // (o BIOS pula o teste de memória).
    rtc::cmos_write(0x0F, 0);
    crate::ntos::ke::clock::stall_execution_processor(100);
    physical::write16(0x472, 0x1234);
    if flags & 4 != 0 {
        port::write8(0x70, 0x15);
        crate::ntos::ke::clock::stall_execution_processor(1);
    }
    let reset_value = fadt.as_ref().and_then(|fadt| fadt.bytes.get(128).copied());
    let reset_register = acpi_pm::pm_register(register::RESET).filter(|pm| pm.present);
    debug_print!("REBOOT RESET_REG={:?} valor={:?} HalpPlatformFlags={:#x}", reset_register.map(|pm| pm.port), reset_value, flags);
    if let (Some(pm), Some(value)) = (reset_register, reset_value) {
        port::write8(pm.port, value);
        crate::ntos::ke::clock::stall_execution_processor(500);
    }
    if flags & 2 != 0 {
        port::write8(0x64, 0xFE);
        crate::ntos::ke::clock::stall_execution_processor(5000);
    }
    cpu::halt_forever()
}

/// HalReturnToFirmware(Routine): nunca volta numa rotina conhecida.
pub fn return_to_firmware(routine: Routine) -> ! {
    if routine == Routine::PowerDown {
        shutdown();
    }
    reset()
}
