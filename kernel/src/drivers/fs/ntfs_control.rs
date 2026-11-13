//! Controles de sistema de arquivos do NTFS.
//!
//! Respondem pelos metadados e pelo estado de alocação do volume montado.

use alloc::vec::Vec;

use super::ntfs::{find_attribute, u16_at, Ntfs};
use crate::rtl::KernelError;

/// Resultado de um FSCTL: status, bytes devolvidos e o comprimento deles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlResult {
    pub status: u32,
    pub information: u32,
    pub bytes: Vec<u8>,
}

fn result(status: u32, bytes: Vec<u8>) -> ControlResult {
    ControlResult { status, information: bytes.len() as u32, bytes }
}

/// Escrita little-endian que descarta bytes além do fim, como um Uint8Array.
fn put(bytes: &mut [u8], at: usize, value: u64, count: usize) {
    for (index, byte) in value.to_le_bytes()[..count].iter().enumerate() {
        if let Some(slot) = bytes.get_mut(at + index) {
            *slot = *byte;
        }
    }
}

impl Ntfs {
    pub fn control(&self, path: &str, code: u32, _input: &[u8], output_length: u32) -> Result<ControlResult, KernelError> {
        let Some(stat) = self.stat(path)? else { return Ok(result(0xC000_0034, Vec::new())) };
        // FSCTL_IS_VOLUME_MOUNTED: este é um sistema de arquivos montado e vivo.
        if code == 0x9_0028 {
            return Ok(result(0, Vec::new()));
        }
        // Sem $UsnJrnl o journal está inativo, não vazio; formatos existentes
        // não são emulados em silêncio.
        if code == 0x9_00F4 || code == 0x9_00EF || code == 0x9_00EB {
            return Ok(result(if self.exists("/$Extend/$UsnJrnl")? { 0xC000_00BB } else { 0xC000_02B8 }, Vec::new()));
        }
        // FSCTL_GET_COMPRESSION.
        if code == 0x9_003C {
            if output_length < 2 {
                return Ok(result(0xC000_0023, Vec::new()));
            }
            let record = self.read_record(stat.reference)?;
            let compressed = find_attribute(&record, 0x80)?.is_some_and(|data| u16_at(&data.raw, 12) & 1 != 0);
            return Ok(result(0, alloc::vec![if compressed { 2 } else { 0 }, 0]));
        }
        // FSCTL_GET_NTFS_VOLUME_DATA.
        if code != 0x9_0064 {
            return Ok(result(0xC000_0010, Vec::new()));
        }
        if output_length < 96 {
            return Ok(result(0xC000_0023, Vec::new()));
        }
        let extension = if output_length >= 100 { (output_length - 96).min(8) as usize } else { 0 };
        let space = self.space()?;
        let mft = find_attribute(&self.read_record(0)?, 0x80)?.filter(|mft| mft.non_resident).ok_or_else(|| KernelError::new("NTFS: $MFT DATA invalido"))?;
        let volume = self.geometry;
        let mut out = alloc::vec![0u8; 96 + extension];
        put(&mut out, 0, volume.serial, 8);
        put(&mut out, 8, volume.total_sectors, 8);
        put(&mut out, 16, space.clusters, 8);
        put(&mut out, 24, space.free_clusters, 8);
        // Nenhum cluster livre é reservado fora da extensão alocada da $MFT.
        put(&mut out, 32, 0, 8);
        put(&mut out, 40, volume.sector_size, 4);
        put(&mut out, 44, volume.cluster_size, 4);
        put(&mut out, 48, volume.record_size, 4);
        put(&mut out, 52, (volume.record_size / volume.cluster_size).max(1), 4);
        put(&mut out, 56, mft.initialized_size, 8);
        put(&mut out, 64, volume.mft_lcn, 8);
        put(&mut out, 72, volume.mirror_lcn, 8);
        // O alocador reserva a área fixa de registros MFT na formatação.
        put(&mut out, 80, volume.mft_lcn, 8);
        put(&mut out, 88, volume.mft_lcn + mft.allocated_size / volume.cluster_size, 8);
        if extension != 0 {
            let info = find_attribute(&self.read_record(3)?, 0x70)?.filter(|info| !info.non_resident && info.value.len() >= 12).ok_or_else(|| KernelError::new("NTFS: $VOLUME_INFORMATION invalido"))?;
            put(&mut out, 96, extension as u64, 4);
            put(&mut out, 100, info.value[8] as u64, 2);
            put(&mut out, 102, info.value[9] as u64, 2);
        }
        Ok(result(0, out))
    }
}
