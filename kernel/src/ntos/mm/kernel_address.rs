//! Endereço virtual do kernel <-> mapeamento físico permanente da imagem.

use core::sync::atomic::{AtomicU64, Ordering};

use super::memory_map as map;
use crate::rtl::KernelError;

/// O tamanho só vale depois que a inicialização publica a imagem completa.
static IMAGE_SIZE: AtomicU64 = AtomicU64::new(0);

pub fn publish(size: u64) {
    IMAGE_SIZE.store(size, Ordering::Release);
}

pub fn image_size() -> u64 {
    IMAGE_SIZE.load(Ordering::Acquire)
}

/// Endereço físico da imagem -> endereço virtual nativo.
pub fn virtual_address(physical_address: u64) -> Result<u64, KernelError> {
    let size = image_size();
    if size == 0
        || physical_address < map::KERNEL_IMAGE_BASE
        || physical_address >= map::KERNEL_IMAGE_BASE + size
    {
        return Err(KernelError::new("address outside published kernel image"));
    }
    Ok(map::KERNEL_VIRTUAL_BASE + (physical_address - map::KERNEL_IMAGE_BASE))
}

/// Conversão inversa; `None` se o endereço não pertence à imagem.
pub fn physical_address(virtual_address: u64) -> Option<u64> {
    let size = image_size();
    let offset = virtual_address.wrapping_sub(map::KERNEL_VIRTUAL_BASE);
    (size != 0 && virtual_address >= map::KERNEL_VIRTUAL_BASE && offset < size)
        .then(|| map::KERNEL_IMAGE_BASE + offset)
}
