//! O container MSF 7.00 de um PDB: superbloco, diretório e streams, mais a
//! identidade (GUID do stream PDB e idade do DBI) que o RSDS do PE cita.
//!
//! Segue o formato público do MSF. Os símbolos do depurador leem daqui os
//! nomes públicos; o `cargo xtask nt-types` lê os tipos (TPI) pelo mesmo
//! container.

const MSF_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00";

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("PDB truncado em {at:#x}"))
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
        let stream_count = u32_at(&directory, 0)? as usize;
        let mut cursor = 4 + 4 * stream_count;
        for stream in 0..stream_count {
            let size = u32_at(&directory, 4 + 4 * stream)?;
            if size == u32::MAX {
                msf.streams.push((Vec::new(), 0));
                continue;
            }
            let count = (size as usize).div_ceil(block_size);
            let mut blocks = Vec::with_capacity(count);
            for _ in 0..count {
                blocks.push(u32_at(&directory, cursor)?);
                cursor += 4;
            }
            msf.streams.push((blocks, size));
        }
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

    /// GUID (stream PDB) e idade (DBI) — a identidade que o RSDS do PE cita.
    pub fn identity(&self) -> Result<([u8; 16], u32), String> {
        let info = self.stream(1)?;
        let guid: [u8; 16] = info.get(12..28).ok_or("PDB: stream de informacao truncado")?.try_into().unwrap();
        let dbi = self.stream(3)?;
        Ok((guid, u32_at(&dbi, 8)?))
    }
}
