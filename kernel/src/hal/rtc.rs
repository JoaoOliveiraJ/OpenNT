//! Relógio de tempo real via CMOS (portas 0x70/0x71).

use super::port;

#[derive(Clone, Copy, Debug)]
pub struct RealTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

fn cmos_read(register: u8) -> u8 {
    port::write8(0x70, register);
    port::read8(0x71)
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
