//! Relógio de tempo real via CMOS (portas 0x70/0x71).
//!
//! O índice (0x70) e o dado (0x71) formam uma transação: quem lê ou grava um
//! registrador da CMOS o faz sob o lock da CMOS (o HalpSystemHardwareLock que
//! o HalpAcquireCmosSpinLock do NT toma), com interrupções desligadas: o
//! relógio e o emulador do BIOS de vídeo (`hal::x86bios`).

use super::port;
use crate::rtl::SpinLock;

/// Lock da CMOS: uma transação índice + dado de cada vez.
static CMOS_LOCK: SpinLock<()> = SpinLock::new(());

/// Lê o registrador `register` da CMOS (índice em 0x70, dado em 0x71).
pub fn cmos_read(register: u8) -> u8 {
    let _held = CMOS_LOCK.lock();
    port::write8(0x70, register);
    port::read8(0x71)
}

/// Grava o registrador `register` da CMOS.
pub fn cmos_write(register: u8, value: u8) {
    let _held = CMOS_LOCK.lock();
    port::write8(0x70, register);
    port::write8(0x71, value);
}

#[derive(Clone, Copy, Debug)]
pub struct RealTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn bcd(value: u8) -> u8 {
    (value & 0x0F) + (value >> 4) * 10
}

pub fn read() -> RealTime {
    let register_b = cmos_read(0x0B);
    let is_bcd = register_b & 0x04 == 0;
    let mut second = cmos_read(0x00);
    let mut minute = cmos_read(0x02);
    let mut hour = cmos_read(0x04);
    let mut day = cmos_read(0x07);
    let mut month = cmos_read(0x08);
    let mut year = cmos_read(0x09);
    if is_bcd {
        second = bcd(second);
        minute = bcd(minute);
        hour = bcd(hour);
        day = bcd(day);
        month = bcd(month);
        year = bcd(year);
    }
    RealTime { year: 2000 + year as u16, month, day, hour, minute, second }
}
