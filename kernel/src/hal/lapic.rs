//! Local APIC em modo xAPIC (MMIO físico em 0xFEE00000, alcançado pelo mapa
//! direto via `hal::physical`).
//! Leitura e escrita dos registradores.

use super::physical;

pub const BASE: u64 = 0xFEE0_0000;

pub fn read(register: u32) -> u32 {
    physical::read32(BASE + register as u64)
}

pub fn write(register: u32, value: u32) {
    physical::write32(BASE + register as u64, value)
}
