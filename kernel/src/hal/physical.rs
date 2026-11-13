//! Acesso à memória física: leituras, escritas, zeragem e compare-exchange.
//!
//! O endereço recebido é FÍSICO e nunca é usado como ponteiro: cada acesso
//! passa pelo mapa direto da metade de sistema (`DIRECT_MAP_BASE + PA`,
//! montado pelo stage2 e descrito em `ntos/mm/memory_map.rs`). Um endereço
//! fora da faixa física mapeada (uma VA passada por engano, por exemplo) para
//! o sistema e aponta quem chamou. Todos os acessos são voláteis
//! (`hal::volatile`): as células são compartilhadas com os trampolins de IRQ,
//! com os APs e com o hardware.

use core::sync::atomic::{AtomicU32, AtomicU64};

use super::volatile;
use crate::ntos::mm::memory_map as map;

/// VA do mapa direto que alcança `physical_address`. Endereços acima do
/// limite físico (VAs, sobretudo) não têm tradução e param o sistema.
#[inline]
#[track_caller]
pub fn to_virtual(physical_address: u64) -> u64 {
    assert!(physical_address < map::PHYSICAL_MEMORY_LIMIT, "endereco fisico fora do mapa direto: {physical_address:#x}");
    map::direct_map(physical_address)
}

/// Faixa física inteira dentro do mapa direto: VA do início.
#[inline]
#[track_caller]
pub fn range_to_virtual(physical_address: u64, length: u64) -> u64 {
    let end = physical_address.checked_add(length);
    assert!(end.is_some_and(|end| end <= map::PHYSICAL_MEMORY_LIMIT), "faixa fisica fora do mapa direto: {physical_address:#x}+{length:#x}");
    map::direct_map(physical_address)
}

#[inline]
#[track_caller]
pub fn read8(address: u64) -> u8 {
    volatile::read8(to_virtual(address))
}

#[inline]
#[track_caller]
pub fn read16(address: u64) -> u16 {
    volatile::read16(to_virtual(address))
}

#[inline]
#[track_caller]
pub fn read32(address: u64) -> u32 {
    volatile::read32(to_virtual(address))
}

#[inline]
#[track_caller]
pub fn read64(address: u64) -> u64 {
    volatile::read64(to_virtual(address))
}

#[inline]
#[track_caller]
pub fn write8(address: u64, value: u8) {
    volatile::write8(to_virtual(address), value)
}

#[inline]
#[track_caller]
pub fn write16(address: u64, value: u16) {
    volatile::write16(to_virtual(address), value)
}

#[inline]
#[track_caller]
pub fn write32(address: u64, value: u32) {
    volatile::write32(to_virtual(address), value)
}

#[inline]
#[track_caller]
pub fn write64(address: u64, value: u64) {
    volatile::write64(to_virtual(address), value)
}

#[track_caller]
pub fn read_bytes(address: u64, length: usize) -> alloc::vec::Vec<u8> {
    volatile::read_bytes(range_to_virtual(address, length as u64), length)
}

#[track_caller]
pub fn write_bytes(address: u64, bytes: &[u8]) {
    volatile::write_bytes(range_to_virtual(address, bytes.len() as u64), bytes)
}

#[track_caller]
pub fn equal_bytes(address: u64, bytes: &[u8]) -> bool {
    volatile::equal_bytes(range_to_virtual(address, bytes.len() as u64), bytes)
}

#[track_caller]
pub fn zero(address: u64, length: usize) {
    volatile::zero(range_to_virtual(address, length as u64), length)
}

/// A célula física de 32 bits como atômico (pela VA do mapa direto).
#[track_caller]
pub fn atomic_u32(address: u64) -> &'static AtomicU32 {
    assert!(address % 4 == 0, "celula fisica desalinhada: {address:#x}");
    // SAFETY: o mapa direto cobre toda a faixa física e nunca é desfeito.
    unsafe { volatile::atomic_u32(to_virtual(address)) }
}

/// A célula física de 64 bits como atômico (pela VA do mapa direto).
#[track_caller]
pub fn atomic_u64(address: u64) -> &'static AtomicU64 {
    assert!(address % 8 == 0, "celula fisica desalinhada: {address:#x}");
    // SAFETY: o mapa direto cobre toda a faixa física e nunca é desfeito.
    unsafe { volatile::atomic_u64(to_virtual(address)) }
}

/// CMPXCHG de 32 bits: devolve o valor anterior.
#[track_caller]
pub fn compare_exchange32(address: u64, expected: u32, desired: u32) -> u32 {
    volatile::compare_exchange32(to_virtual(address), expected, desired)
}

/// CMPXCHG de 64 bits: devolve o valor anterior.
#[track_caller]
pub fn compare_exchange64(address: u64, expected: u64, desired: u64) -> u64 {
    volatile::compare_exchange64(to_virtual(address), expected, desired)
}
