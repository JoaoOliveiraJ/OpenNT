//! Acesso à memória física: leituras, escritas, zeragem e compare-exchange.
//!
//! O stage2 mapeia os primeiros 4 GB em identidade, então o endereço físico
//! é usado diretamente como ponteiro. Todos os acessos são voláteis: essas
//! células são compartilhadas com os trampolins de IRQ e com o hardware.

use core::arch::asm;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// Cada acesso é um MOV único, como `*(volatile T *)` no C: nunca é elidido
// nem dividido e aceita endereços desalinhados (o x86 permite).

#[inline]
pub fn read8(address: u64) -> u8 {
    let value: u8;
    unsafe { asm!("mov {0}, byte ptr [{1}]", out(reg_byte) value, in(reg) address, options(nostack, preserves_flags, readonly)) }
    value
}

#[inline]
pub fn read16(address: u64) -> u16 {
    let value: u16;
    unsafe { asm!("mov {0:x}, word ptr [{1}]", out(reg) value, in(reg) address, options(nostack, preserves_flags, readonly)) }
    value
}

#[inline]
pub fn read32(address: u64) -> u32 {
    let value: u32;
    unsafe { asm!("mov {0:e}, dword ptr [{1}]", out(reg) value, in(reg) address, options(nostack, preserves_flags, readonly)) }
    value
}

#[inline]
pub fn read64(address: u64) -> u64 {
    let value: u64;
    unsafe { asm!("mov {0}, qword ptr [{1}]", out(reg) value, in(reg) address, options(nostack, preserves_flags, readonly)) }
    value
}

#[inline]
pub fn write8(address: u64, value: u8) {
    unsafe { asm!("mov byte ptr [{0}], {1}", in(reg) address, in(reg_byte) value, options(nostack, preserves_flags)) }
}

#[inline]
pub fn write16(address: u64, value: u16) {
    unsafe { asm!("mov word ptr [{0}], {1:x}", in(reg) address, in(reg) value, options(nostack, preserves_flags)) }
}

#[inline]
pub fn write32(address: u64, value: u32) {
    unsafe { asm!("mov dword ptr [{0}], {1:e}", in(reg) address, in(reg) value, options(nostack, preserves_flags)) }
}

#[inline]
pub fn write64(address: u64, value: u64) {
    unsafe { asm!("mov qword ptr [{0}], {1}", in(reg) address, in(reg) value, options(nostack, preserves_flags)) }
}

pub fn read_bytes(address: u64, length: usize) -> alloc::vec::Vec<u8> {
    (0..length as u64).map(|offset| read8(address + offset)).collect()
}

pub fn write_bytes(address: u64, bytes: &[u8]) {
    for (offset, &byte) in bytes.iter().enumerate() {
        write8(address + offset as u64, byte);
    }
}

pub fn equal_bytes(address: u64, bytes: &[u8]) -> bool {
    bytes.iter().enumerate().all(|(offset, &byte)| read8(address + offset as u64) == byte)
}

pub fn zero(address: u64, length: usize) {
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, length) }
}

/// CMPXCHG de 32 bits: devolve o valor anterior.
pub fn compare_exchange32(address: u64, expected: u32, desired: u32) -> u32 {
    let cell = unsafe { &*(address as *const AtomicU32) };
    match cell.compare_exchange(expected, desired, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(previous) | Err(previous) => previous,
    }
}

/// CMPXCHG de 64 bits: devolve o valor anterior.
pub fn compare_exchange64(address: u64, expected: u64, desired: u64) -> u64 {
    let cell = unsafe { &*(address as *const AtomicU64) };
    match cell.compare_exchange(expected, desired, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(previous) | Err(previous) => previous,
    }
}

/// CMPXCHG16B: devolve o valor anterior (baixo, alto). O endereço precisa
/// estar alinhado a 16 bytes.
pub fn compare_exchange128(address: u64, expected: (u64, u64), replacement: (u64, u64)) -> (u64, u64) {
    let (mut low, mut high) = expected;
    unsafe {
        core::arch::asm!(
            "xchg rbx, {replacement_low}",
            "lock cmpxchg16b [{address}]",
            "xchg rbx, {replacement_low}",
            address = in(reg) address,
            replacement_low = inout(reg) replacement.0 => _,
            in("rcx") replacement.1,
            inout("rax") low,
            inout("rdx") high,
        );
    }
    (low, high)
}
