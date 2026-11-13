//! I/O de porta (IN/OUT).

use core::arch::asm;

#[inline]
pub fn write8(port: u16, value: u8) {
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) }
}

#[inline]
pub fn read8(port: u16) -> u8 {
    let value: u8;
    unsafe { asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}

#[inline]
pub fn write16(port: u16, value: u16) {
    unsafe { asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)) }
}

#[inline]
pub fn read16(port: u16) -> u16 {
    let value: u16;
    unsafe { asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}

#[inline]
pub fn write32(port: u16, value: u32) {
    unsafe { asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags)) }
}

#[inline]
pub fn read32(port: u16) -> u32 {
    let value: u32;
    unsafe { asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags)) }
    value
}
