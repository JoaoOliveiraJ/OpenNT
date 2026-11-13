//! Volume de paginação — o volume montado em `\NTFS` que o pool
//! executivo e a paginação de imagens usam como armazenamento de apoio.
//!
//! O NTFS (fase 4) se registra aqui ao ser montado.

use alloc::vec::Vec;

use crate::rtl::{KernelError, SpinLock};

pub trait PagingVolume: Sync {
    fn exists(&self, path: &str) -> bool;
    fn create(&self, path: &str, directory: bool, attributes: u32, size: u64) -> Result<(), KernelError>;
    fn resize(&self, path: &str, size: u64) -> Result<(), KernelError>;
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Result<Vec<u8>, KernelError>;
    fn write(&self, path: &str, offset: u64, data: &[u8]) -> Result<u64, KernelError>;
    fn remove(&self, path: &str) -> Result<(), KernelError>;
}

static VOLUME: SpinLock<Option<&'static dyn PagingVolume>> = SpinLock::new(None);

pub fn register(volume: &'static dyn PagingVolume) {
    *VOLUME.lock() = Some(volume);
}

pub fn current() -> Option<&'static dyn PagingVolume> {
    *VOLUME.lock()
}
