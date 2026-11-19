//! Leitor dos tipos de um PDB para o `nt-types`: o TPI e o container MSF
//! são os do cliente do depurador (`opennt_kd::tpi`, `opennt_kd::msf`);
//! aqui fica só o PE em disco (o RSDS e, nos testes, o código de um export).

pub use opennt_kd::pe::guid_text;
pub use opennt_kd::tpi::*;

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| format!("PDB truncado em {at:#x}"))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("PDB truncado em {at:#x}"))
}

fn read_cstring(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    let tail = data.get(offset..).ok_or("string fora do registro")?;
    let length = tail.iter().position(|&byte| byte == 0).ok_or("string sem terminador")?;
    Ok((String::from_utf8_lossy(&tail[..length]).into_owned(), offset + length + 1))
}

/// Um PE em disco: seções e diretórios, o suficiente para o RSDS (CodeView)
/// e, nos testes, para achar o código de um export.
pub struct PeFile<'a> {
    bytes: &'a [u8],
    directories: usize,
    /// (VA, tamanho virtual, offset no arquivo, tamanho no arquivo)
    sections: Vec<(u32, u32, u32, u32)>,
}

impl<'a> PeFile<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<PeFile<'a>, String> {
        let pe = u32_at(bytes, 0x3C)? as usize;
        if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err("PE: assinatura ausente".into());
        }
        let section_count = u16_at(bytes, pe + 6)? as usize;
        let optional_size = u16_at(bytes, pe + 20)? as usize;
        let optional = pe + 24;
        let directories = match u16_at(bytes, optional)? {
            0x20B => optional + 112,
            0x10B => optional + 96,
            magic => return Err(format!("PE: optional header desconhecido {magic:#x}")),
        };
        let mut sections = Vec::with_capacity(section_count);
        for section in 0..section_count {
            let header = optional + optional_size + 40 * section;
            sections.push((
                u32_at(bytes, header + 12)?,
                u32_at(bytes, header + 8)?,
                u32_at(bytes, header + 20)?,
                u32_at(bytes, header + 16)?,
            ));
        }
        Ok(PeFile { bytes, directories, sections })
    }

    fn file_offset(&self, rva: u32) -> Result<usize, String> {
        for &(virtual_address, virtual_size, raw_offset, raw_size) in &self.sections {
            if rva >= virtual_address && rva - virtual_address < virtual_size.max(raw_size) {
                return Ok((raw_offset + (rva - virtual_address)) as usize);
            }
        }
        Err(format!("PE: RVA {rva:#x} fora das secoes"))
    }

    fn directory(&self, index: usize) -> Result<(u32, u32), String> {
        let at = self.directories + 8 * index;
        Ok((u32_at(self.bytes, at)?, u32_at(self.bytes, at + 4)?))
    }

    /// GUID e idade do RSDS (CodeView), e o nome do PDB.
    pub fn rsds(&self) -> Result<([u8; 16], u32, String), String> {
        let (debug_rva, debug_size) = self.directory(6)?;
        let directory = self.file_offset(debug_rva)?;
        for entry in 0..debug_size as usize / 28 {
            let at = directory + 28 * entry;
            // IMAGE_DEBUG_TYPE_CODEVIEW
            if u32_at(self.bytes, at + 12)? != 2 {
                continue;
            }
            let data = u32_at(self.bytes, at + 24)? as usize;
            if self.bytes.get(data..data + 4) != Some(b"RSDS") {
                continue;
            }
            let guid: [u8; 16] = self.bytes.get(data + 4..data + 20).ok_or("RSDS truncado")?.try_into().unwrap();
            let age = u32_at(self.bytes, data + 20)?;
            let (name, _) = read_cstring(self.bytes, data + 24)?;
            return Ok((guid, age, name));
        }
        Err("PE sem registro RSDS (CodeView)".into())
    }

    /// Os bytes a partir do início de um export nomeado.
    #[cfg(test)]
    pub fn export_code(&self, wanted: &str) -> Result<&'a [u8], String> {
        let (export_rva, _) = self.directory(0)?;
        let directory = self.file_offset(export_rva)?;
        let names = u32_at(self.bytes, directory + 24)? as usize;
        let functions = self.file_offset(u32_at(self.bytes, directory + 28)?)?;
        let name_table = self.file_offset(u32_at(self.bytes, directory + 32)?)?;
        let ordinals = self.file_offset(u32_at(self.bytes, directory + 36)?)?;
        for index in 0..names {
            let name_at = self.file_offset(u32_at(self.bytes, name_table + 4 * index)?)?;
            if read_cstring(self.bytes, name_at)?.0 == wanted {
                let ordinal = u16_at(self.bytes, ordinals + 2 * index)? as usize;
                let rva = u32_at(self.bytes, functions + 4 * ordinal)?;
                return Ok(&self.bytes[self.file_offset(rva)?..]);
            }
        }
        Err(format!("PE sem o export {wanted}"))
    }
}
