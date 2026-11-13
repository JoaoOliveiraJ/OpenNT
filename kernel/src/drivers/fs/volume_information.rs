//! Layouts NT de informação de volume — `system32/ntos/fs/volume-information.js`.
//!
//! Identidade e capacidade pertencem ao volume montado, nunca a um caminho
//! nem a uma lista de arquivos.

use alloc::string::String;
use alloc::vec::Vec;

use super::memory_file_system::{self, MemoryVolume};
use super::ntfs::{Ntfs, VolumeInformation};
use super::ntfs_write::Space;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// Tamanho mínimo de cada FS_INFORMATION_CLASS suportada.
pub fn minimum(class: u32) -> Option<u32> {
    match class {
        1 | 3 => Some(24),
        4 => Some(8),
        5 => Some(12),
        7 => Some(32),
        _ => None,
    }
}

/// Volume montado que responde identidade e (opcionalmente) espaço.
pub trait VolumeQuery {
    fn volume_information(&self) -> Result<VolumeInformation, KernelError>;
    fn space(&self) -> Option<Result<Space, KernelError>>;
}

impl VolumeQuery for Ntfs {
    fn volume_information(&self) -> Result<VolumeInformation, KernelError> {
        Ntfs::volume_information(self)
    }

    fn space(&self) -> Option<Result<Space, KernelError>> {
        Some(Ntfs::space(self))
    }
}

/// O RAMFS responde com a própria identidade e o espaço do heap.
impl VolumeQuery for MemoryVolume {
    fn volume_information(&self) -> Result<VolumeInformation, KernelError> {
        let identity = memory_file_system::volume_information();
        Ok(VolumeInformation {
            label: String::from(identity.label),
            serial: identity.serial,
            creation_time: identity.creation_time,
            file_system: identity.file_system,
            attributes: identity.attributes,
            maximum_component_length: identity.maximum_component_length,
            supports_objects: identity.supports_objects,
            device_type: identity.device_type,
            characteristics: identity.characteristics,
        })
    }

    fn space(&self) -> Option<Result<Space, KernelError>> {
        let space = memory_file_system::space();
        Some(Ok(Space { clusters: space.clusters, free_clusters: space.free_clusters, cluster_size: space.cluster_size as u64, sector_size: space.sector_size as u64, sectors_per_cluster: space.sectors_per_cluster as u64 }))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResult {
    pub status: u32,
    pub information: u32,
    pub bytes: Vec<u8>,
}

fn fail(status: u32) -> QueryResult {
    QueryResult { status, information: 0, bytes: Vec::new() }
}

fn put(bytes: &mut [u8], at: usize, value: u64, count: usize) {
    bytes[at..at + count].copy_from_slice(&value.to_le_bytes()[..count]);
}

/// FileFsVolume (1), Size (3), Device (4), Attribute (5) e FullSize (7). O
/// nome é copiado byte a byte, inclusive um último byte ímpar, sem
/// terminador; o campo de comprimento sempre descreve o nome inteiro.
pub fn query(volume: Option<&dyn VolumeQuery>, class: u32, length: u32) -> Result<QueryResult, KernelError> {
    let Some(minimum) = minimum(class) else { return Ok(fail(0xC000_0003)) };
    if length < minimum {
        return Ok(fail(0xC000_0004));
    }
    let Some(volume) = volume else { return Ok(fail(0xC000_0010)) };
    let identity = volume.volume_information()?;
    let mut text: Vec<u16> = Vec::new();
    let mut offset = 0usize;
    let mut size = minimum as usize;
    if class == 1 {
        text = identity.label.encode_utf16().collect();
        offset = 18;
    }
    if class == 5 {
        text = identity.file_system.encode_utf16().collect();
        offset = 12;
    }
    let mut space = None;
    if class == 3 || class == 7 {
        match volume.space() {
            Some(found) => space = Some(found?),
            None => return Ok(fail(0xC000_0010)),
        }
    }
    if offset != 0 {
        size = offset + (length as usize - offset).min(text.len() * 2);
    }
    let mut bytes = alloc::vec![0u8; size];
    match class {
        1 => {
            put(&mut bytes, 0, identity.creation_time, 8);
            put(&mut bytes, 8, identity.serial as u64, 4);
            put(&mut bytes, 12, text.len() as u64 * 2, 4);
            bytes[16] = identity.supports_objects as u8;
        }
        5 => {
            put(&mut bytes, 0, identity.attributes as u64, 4);
            put(&mut bytes, 4, identity.maximum_component_length as u64, 4);
            put(&mut bytes, 8, text.len() as u64 * 2, 4);
        }
        4 => {
            put(&mut bytes, 0, identity.device_type as u64, 4);
            put(&mut bytes, 4, identity.characteristics as u64, 4);
        }
        _ => {
            let space = space.expect("espaco consultado");
            put(&mut bytes, 0, space.clusters, 8);
            put(&mut bytes, 8, space.free_clusters, 8);
            let tail = if class == 7 { 24 } else { 16 };
            if class == 7 {
                put(&mut bytes, 16, space.free_clusters, 8);
            }
            put(&mut bytes, tail, space.sectors_per_cluster, 4);
            put(&mut bytes, tail + 4, space.sector_size, 4);
        }
    }
    if offset != 0 {
        for index in 0..size - offset {
            bytes[offset + index] = (text[index >> 1] >> ((index & 1) * 8)) as u8;
        }
    }
    let status = if offset != 0 && size < offset + text.len() * 2 { 0x8000_0005 } else { 0 };
    Ok(QueryResult { status, information: size as u32, bytes })
}

pub fn write(result: &QueryResult, pointer: u64) {
    guest::write_bytes(pointer, &result.bytes);
}
