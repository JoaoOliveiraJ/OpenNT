//! Sistema de arquivos em memória com namespace plano.
//! Guarda texto ou binário
//! (por exemplo, um .exe).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::kmalloc;
use crate::ntos::inc::status::*;
use crate::rtl::time::unix_milliseconds_to_nt_time;
use crate::rtl::{KernelError, SpinLock};

#[derive(Clone, Debug)]
pub enum FileData {
    Text(String),
    Binary(Vec<u8>),
}

impl FileData {
    pub fn len(&self) -> usize {
        match self {
            FileData::Text(text) => text.len(),
            FileData::Binary(bytes) => bytes.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Conteúdo como bytes (texto vira os bytes de cada caractere).
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            FileData::Text(text) => text.chars().map(|character| character as u32 as u8).collect(),
            FileData::Binary(bytes) => bytes.clone(),
        }
    }
}

static FILES: SpinLock<BTreeMap<String, FileData>> = SpinLock::new(BTreeMap::new());
static CREATION_TIME: AtomicU64 = AtomicU64::new(0);

/// Registra o instante de criação do volume (o `Date.now()` da carga do
/// módulo no original).
pub fn init(now_unix_ms: u64) {
    CREATION_TIME.store(unix_milliseconds_to_nt_time(now_unix_ms), Ordering::Relaxed);
}

fn norm(path: &str) -> Result<String, KernelError> {
    let mut path = String::from(if path.is_empty() { "/" } else { path });
    if !path.starts_with('/') {
        path.insert(0, '/');
    }
    if path.split('/').any(|part| part.chars().count() > 255) {
        return Err(KernelError::with_status(
            "RAMFS: componente de nome excede 255 caracteres",
            STATUS_NAME_TOO_LONG,
        ));
    }
    Ok(path)
}

#[derive(Clone, Debug)]
pub struct VolumeInformation {
    pub label: &'static str,
    pub serial: u32,
    pub creation_time: u64,
    pub file_system: &'static str,
    pub attributes: u32,
    pub maximum_component_length: u32,
    pub supports_objects: bool,
    pub device_type: u32,
    pub characteristics: u32,
}

pub fn volume_information() -> VolumeInformation {
    let creation_time = CREATION_TIME.load(Ordering::Relaxed);
    VolumeInformation {
        label: "OpenNT",
        serial: creation_time as u32,
        creation_time,
        file_system: "RAMFS",
        attributes: 7,
        maximum_component_length: 255,
        supports_objects: false,
        device_type: 7,
        characteristics: 0,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Space {
    pub clusters: u64,
    pub free_clusters: u64,
    pub cluster_size: u32,
    pub sector_size: u32,
    pub sectors_per_cluster: u32,
}

/// O RAMFS aloca do heap compartilhado: a capacidade disponível muda com
/// todo consumidor do heap, não só com os bytes armazenados.
pub fn space() -> Space {
    let (total, used) = kmalloc::info();
    Space {
        clusters: total as u64,
        free_clusters: total.saturating_sub(used) as u64,
        cluster_size: 1,
        sector_size: 1,
        sectors_per_cluster: 1,
    }
}

pub fn write(path: &str, data: &str) -> Result<bool, KernelError> {
    FILES.lock().insert(norm(path)?, FileData::Text(String::from(data)));
    Ok(true)
}

pub fn write_bytes(path: &str, bytes: Vec<u8>) -> Result<bool, KernelError> {
    FILES.lock().insert(norm(path)?, FileData::Binary(bytes));
    Ok(true)
}

pub fn resize(path: &str, size: usize) -> Result<bool, KernelError> {
    let path = norm(path)?;
    let mut files = FILES.lock();
    let Some(old) = files.get(&path) else {
        return Err(KernelError::with_status("RAMFS: file missing", STATUS_OBJECT_NAME_NOT_FOUND));
    };
    let old = old.to_bytes();
    let mut next = vec![0u8; size];
    let keep = size.min(old.len());
    next[..keep].copy_from_slice(&old[..keep]);
    files.insert(path, FileData::Binary(next));
    Ok(true)
}

pub fn write_at(path: &str, offset: usize, bytes: &[u8]) -> Result<usize, KernelError> {
    let path = norm(path)?;
    let mut files = FILES.lock();
    let Some(old) = files.get(&path) else {
        return Err(KernelError::with_status("RAMFS: file missing", STATUS_OBJECT_NAME_NOT_FOUND));
    };
    let Some(end) = offset.checked_add(bytes.len()) else {
        return Err(KernelError::with_status("RAMFS: invalid offset", STATUS_INVALID_PARAMETER));
    };
    if bytes.is_empty() {
        return Ok(0);
    }
    let mut next = old.to_bytes();
    if next.len() < end {
        next.resize(end, 0);
    }
    next[offset..end].copy_from_slice(bytes);
    files.insert(path, FileData::Binary(next));
    Ok(bytes.len())
}

pub fn read(path: &str) -> Option<FileData> {
    let path = norm(path).ok()?;
    FILES.lock().get(&path).cloned()
}

pub fn read_bytes(path: &str) -> Option<Vec<u8>> {
    match read(path)? {
        FileData::Binary(bytes) => Some(bytes),
        FileData::Text(_) => None,
    }
}

pub fn is_binary(path: &str) -> bool {
    matches!(read(path), Some(FileData::Binary(_)))
}

pub fn exists(path: &str) -> bool {
    match norm(path) {
        Ok(path) => FILES.lock().contains_key(&path),
        Err(_) => false,
    }
}

pub fn remove(path: &str) -> bool {
    match norm(path) {
        Ok(path) => FILES.lock().remove(&path).is_some(),
        Err(_) => false,
    }
}

/// Caminhos em ordem.
pub fn list() -> Vec<String> {
    FILES.lock().keys().cloned().collect()
}

/// Tamanho em bytes, ou `None` se o arquivo não existe.
pub fn size(path: &str) -> Option<usize> {
    read(path).map(|data| data.len())
}

/// O MemoryFileSystem como volume montável (`ObjectManager.mount('\FS', ...)`).
pub struct MemoryVolume;

pub static VOLUME: MemoryVolume = MemoryVolume;

impl crate::drivers::fs::volume::FileSystem for MemoryVolume {
    fn name(&self) -> &str {
        "MemoryFileSystem"
    }

    fn exists(&self, path: &str) -> bool {
        exists(path)
    }

    fn list(&self) -> Vec<String> {
        list()
    }

    fn writable(&self) -> bool {
        true
    }

    fn read_bytes(&self, path: &str) -> Option<Vec<u8>> {
        read_bytes(path)
    }

    fn size(&self, path: &str) -> Option<u64> {
        size(path).map(|size| size as u64)
    }

    fn write_at(&self, path: &str, offset: u64, bytes: &[u8]) -> Result<u64, KernelError> {
        write_at(path, offset as usize, bytes).map(|written| written as u64)
    }

    fn truncate(&self, path: &str) -> Result<(), KernelError> {
        write_bytes(path, Vec::new()).map(|_| ())
    }

    fn remove(&self, path: &str) -> Option<Result<bool, KernelError>> {
        Some(Ok(remove(path)))
    }

    fn volume_serial(&self) -> Option<u64> {
        Some(volume_information().serial as u64)
    }

    fn volume_query(&self) -> Option<&dyn crate::drivers::fs::volume_information::VolumeQuery> {
        Some(self)
    }
}
