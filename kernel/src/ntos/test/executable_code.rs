//! Código de máquina gerado pelos autotestes e executado pelo kernel
//! (rotinas de driver de teste, callbacks, corpos de thread nativa): fica
//! numa alocação executável da janela de sistema, como a de um driver que
//! gera código (MmAllocateContiguousNodeMemory com PAGE_EXECUTE_READWRITE). O
//! heap do kernel e a arena não executam.

use crate::ntos::mm::contiguous_memory;
use crate::ntos::mm::guest_memory as guest;

/// PAGE_EXECUTE_READWRITE.
const PAGE_EXECUTE_READWRITE: u32 = 0x40;

/// Copia `bytes` para uma alocação executável nova e devolve o endereço (0
/// sem memória).
pub fn place(bytes: &[u8]) -> u64 {
    let size = (bytes.len() as u64 + 16).div_ceil(0x1000) * 0x1000;
    let pointer = contiguous_memory::allocate_node(size, 0, u64::MAX, 0, PAGE_EXECUTE_READWRITE, 0).unwrap_or(0);
    if pointer != 0 {
        guest::write_bytes(pointer, bytes);
    }
    pointer
}

/// Uma alocação executável vazia de `size` bytes, para o chamador escrever.
pub fn reserve(size: u64) -> u64 {
    contiguous_memory::allocate_node(size.div_ceil(0x1000) * 0x1000, 0, u64::MAX, 0, PAGE_EXECUTE_READWRITE, 0).unwrap_or(0)
}

/// Devolve uma alocação de [`place`]/[`reserve`] (0 é ignorado).
pub fn release(pointer: u64) {
    if pointer != 0 {
        let _ = contiguous_memory::free(pointer);
    }
}
