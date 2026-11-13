//! Endereços da imagem do kernel em execução.
//!
//! O kernel executa na sua ImageBase (`KERNEL_VIRTUAL_BASE`, mapeada pelo
//! stage2): o endereço de uma rotina, célula ou trampolim do kernel já é o
//! que os módulos nativos recebem. Este módulo só confere que o endereço cai
//! na imagem publicada por `loaded_images::init_kernel`.

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

/// O endereço de um símbolo do kernel, conferido contra a imagem publicada.
pub fn image_address(address: u64) -> Result<u64, KernelError> {
    let size = image_size();
    if size == 0 || address < map::KERNEL_VIRTUAL_BASE || address - map::KERNEL_VIRTUAL_BASE >= size {
        return Err(KernelError::new("address outside published kernel image"));
    }
    Ok(address)
}
