//! O container MSF 7.00 de um PDB: superbloco, diretório e streams, mais a
//! identidade (GUID do stream PDB e idade do DBI) que o RSDS do PE cita.
//!
//! Segue o formato público do MSF. Os símbolos do depurador leem daqui os
//! nomes públicos; o `cargo xtask nt-types` lê os tipos (TPI) pelo mesmo
//! container.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

const MSF_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00";

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("PDB truncado em {at:#x}"))
}

/// Os streams do diretório: os blocos de cada um e o tamanho (um stream
/// apagado, tamanho `u32::MAX`, fica vazio).
fn parse_directory(directory: &[u8], block_size: usize) -> Result<Vec<(Vec<u32>, u32)>, String> {
    let stream_count = u32_at(directory, 0)? as usize;
    let mut cursor = 4 + 4 * stream_count;
    let mut streams = Vec::with_capacity(stream_count);
    for stream in 0..stream_count {
        let size = u32_at(directory, 4 + 4 * stream)?;
        if size == u32::MAX {
            streams.push((Vec::new(), 0));
            continue;
        }
        let count = (size as usize).div_ceil(block_size);
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            blocks.push(u32_at(directory, cursor)?);
            cursor += 4;
        }
        streams.push((blocks, size));
    }
    Ok(streams)
}

/// Container MSF: superbloco, diretório e streams.
pub struct Msf {
    data: Vec<u8>,
    block_size: usize,
    streams: Vec<(Vec<u32>, u32)>,
}

impl Msf {
    pub fn parse(data: Vec<u8>) -> Result<Msf, String> {
        if data.len() < 56 || &data[..32] != MSF_MAGIC {
            return Err("nao e um PDB (MSF 7.00)".into());
        }
        let block_size = u32_at(&data, 32)? as usize;
        let directory_bytes = u32_at(&data, 44)? as usize;
        let block_map_address = u32_at(&data, 52)? as usize;
        if block_size == 0 {
            return Err("PDB com bloco de tamanho zero".into());
        }
        let mut msf = Msf { data, block_size, streams: Vec::new() };
        let directory_blocks = directory_bytes.div_ceil(block_size);
        let mut directory = Vec::with_capacity(directory_blocks * block_size);
        for index in 0..directory_blocks {
            let block = u32_at(&msf.data, block_map_address * block_size + 4 * index)?;
            directory.extend_from_slice(msf.block(block)?);
        }
        directory.truncate(directory_bytes);
        msf.streams = parse_directory(&directory, block_size)?;
        Ok(msf)
    }

    fn block(&self, index: u32) -> Result<&[u8], String> {
        let start = index as usize * self.block_size;
        self.data.get(start..start + self.block_size).ok_or_else(|| format!("PDB: bloco {index} fora do arquivo"))
    }

    pub fn stream(&self, index: usize) -> Result<Vec<u8>, String> {
        let (blocks, size) = self.streams.get(index).ok_or_else(|| format!("PDB sem o stream {index}"))?;
        let mut bytes = Vec::with_capacity(blocks.len() * self.block_size);
        for &block in blocks {
            bytes.extend_from_slice(self.block(block)?);
        }
        bytes.truncate(*size as usize);
        Ok(bytes)
    }

    /// Quantos streams o diretório tem.
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// GUID (stream PDB) e idade (DBI) — a identidade que o RSDS do PE cita.
    pub fn identity(&self) -> Result<([u8; 16], u32), String> {
        let info = self.stream(1)?;
        let guid: [u8; 16] = info.get(12..28).ok_or("PDB: stream de informacao truncado")?.try_into().unwrap();
        let dbi = self.stream(3)?;
        Ok((guid, u32_at(&dbi, 8)?))
    }
}

/// A identidade de um PDB no disco lendo só o superbloco, o diretório e o
/// começo dos streams 1 e 3: o cache confere vários candidatos, e um PDB
/// inteiro pode ter centenas de MB.
pub fn identity_of_file(path: &Path) -> Result<([u8; 16], u32), String> {
    let mut file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut read_at = |offset: u64, length: usize| -> Result<Vec<u8>, String> {
        file.seek(SeekFrom::Start(offset)).map_err(|error| format!("{}: {error}", path.display()))?;
        let mut buffer = vec![0u8; length];
        file.read_exact(&mut buffer).map_err(|error| format!("{}: {error}", path.display()))?;
        Ok(buffer)
    };
    let header = read_at(0, 56)?;
    if &header[..32] != MSF_MAGIC {
        return Err(format!("{}: nao e um PDB (MSF 7.00)", path.display()));
    }
    let block_size = u32_at(&header, 32)? as usize;
    let directory_bytes = u32_at(&header, 44)? as usize;
    let block_map_address = u32_at(&header, 52)? as u64;
    if !(64..=0x10000).contains(&block_size) || directory_bytes > 0x100_0000 {
        return Err(format!("{}: superbloco invalido", path.display()));
    }
    let directory_blocks = directory_bytes.div_ceil(block_size);
    let map = read_at(block_map_address * block_size as u64, 4 * directory_blocks)?;
    let mut directory = Vec::with_capacity(directory_blocks * block_size);
    for index in 0..directory_blocks {
        let block = u32_at(&map, 4 * index)? as u64;
        directory.extend_from_slice(&read_at(block * block_size as u64, block_size)?);
    }
    directory.truncate(directory_bytes);
    let streams = parse_directory(&directory, block_size)?;
    // O GUID está nos bytes 12..28 do stream 1 e a idade nos bytes 8..12 do
    // stream 3: os dois dentro do primeiro bloco de cada um.
    let first_block = |index: usize| -> Result<u64, String> {
        let (blocks, size) = streams.get(index).ok_or_else(|| format!("{}: sem o stream {index}", path.display()))?;
        match blocks.first() {
            Some(&block) if *size >= 28 || (index == 3 && *size >= 12) => Ok(block as u64 * block_size as u64),
            _ => Err(format!("{}: stream {index} truncado", path.display())),
        }
    };
    let (info, dbi) = (first_block(1)?, first_block(3)?);
    let guid: [u8; 16] = read_at(info + 12, 16)?.try_into().map_err(|_| "GUID".to_string())?;
    let age = u32_at(&read_at(dbi + 8, 4)?, 0)?;
    Ok((guid, age))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Um MSF mínimo com blocos de 512 bytes e os streams dados (o stream 0
    /// é o primeiro da lista).
    pub(crate) fn tiny_msf(streams: &[Vec<u8>]) -> Vec<u8> {
        const BLOCK: usize = 512;
        // Blocos: 0 superbloco, 1 mapa do diretório, 2 diretório, depois os
        // dados de cada stream.
        let mut data_blocks: Vec<Vec<u32>> = Vec::new();
        let mut next = 3u32;
        for stream in streams {
            let count = stream.len().div_ceil(BLOCK);
            data_blocks.push((next..next + count as u32).collect());
            next += count as u32;
        }
        let mut directory = (streams.len() as u32).to_le_bytes().to_vec();
        for stream in streams {
            directory.extend_from_slice(&(stream.len() as u32).to_le_bytes());
        }
        for blocks in &data_blocks {
            for block in blocks {
                directory.extend_from_slice(&block.to_le_bytes());
            }
        }
        assert!(directory.len() <= BLOCK);
        let mut file = vec![0u8; next as usize * BLOCK];
        file[..32].copy_from_slice(MSF_MAGIC);
        file[32..36].copy_from_slice(&(BLOCK as u32).to_le_bytes());
        file[40..44].copy_from_slice(&next.to_le_bytes());
        file[44..48].copy_from_slice(&(directory.len() as u32).to_le_bytes());
        file[52..56].copy_from_slice(&1u32.to_le_bytes());
        file[BLOCK..BLOCK + 4].copy_from_slice(&2u32.to_le_bytes());
        file[2 * BLOCK..2 * BLOCK + directory.len()].copy_from_slice(&directory);
        for (stream, blocks) in streams.iter().zip(&data_blocks) {
            for (chunk, block) in stream.chunks(BLOCK).zip(blocks) {
                let at = *block as usize * BLOCK;
                file[at..at + chunk.len()].copy_from_slice(chunk);
            }
        }
        file
    }

    /// O stream 1 (informação) com o GUID e o stream 3 (DBI) com a idade.
    pub(crate) fn identity_streams(guid: [u8; 16], age: u32) -> (Vec<u8>, Vec<u8>) {
        let mut info = vec![0u8; 28];
        info[12..28].copy_from_slice(&guid);
        let mut dbi = vec![0u8; 64];
        dbi[8..12].copy_from_slice(&age.to_le_bytes());
        (info, dbi)
    }

    #[test]
    fn identity_without_reading_the_whole_file() {
        let guid = [7u8; 16];
        let (info, dbi) = identity_streams(guid, 3);
        let bytes = tiny_msf(&[Vec::new(), info, Vec::new(), dbi]);
        let msf = Msf::parse(bytes.clone()).unwrap();
        assert_eq!(msf.identity(), Ok((guid, 3)));
        assert_eq!(msf.stream_count(), 4);
        let directory = std::env::temp_dir().join(format!("kd-msf-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("tiny.pdb");
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(identity_of_file(&path), Ok((guid, 3)));
        std::fs::write(&path, b"nada").unwrap();
        assert!(identity_of_file(&path).is_err());
        let _ = std::fs::remove_dir_all(&directory);
    }
}
