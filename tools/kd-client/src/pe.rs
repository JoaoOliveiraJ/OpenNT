//! Um PE (imagem x64 do Windows) em bytes: cabeçalhos, seções, exports, o
//! RSDS (CodeView) que cita o PDB e a tabela de funções (`.pdata`, as
//! RUNTIME_FUNCTION que o desenrolar da pilha usa).
//!
//! Os bytes vêm do arquivo desta máquina (offsets de arquivo pelas seções)
//! ou da imagem já carregada no alvo (`mapped`: o RVA é o offset).

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn c_string(bytes: &[u8], at: usize) -> Option<String> {
    let tail = bytes.get(at..)?;
    let end = tail.iter().position(|&byte| byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/// Uma seção: nome, RVA, tamanho virtual, offset e tamanho no arquivo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub address: u32,
    pub virtual_size: u32,
    pub raw: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

/// Uma entrada da `.pdata`: começo e fim da função (RVAs) e o RVA do
/// UNWIND_INFO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

/// Campos do cabeçalho que o `lmv` mostra.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub machine: u16,
    pub time_date_stamp: u32,
    pub characteristics: u16,
    pub image_base: u64,
    pub size_of_image: u32,
    pub entry_point: u32,
    pub checksum: u32,
    pub subsystem: u16,
}

pub struct PeImage {
    pub bytes: Vec<u8>,
    pub sections: Vec<Section>,
    pub header: Header,
    directories: usize,
    directory_count: usize,
    /// Os bytes são a imagem mapeada (RVA = offset), não o arquivo.
    mapped: bool,
}

impl PeImage {
    /// Um PE em disco.
    pub fn parse(bytes: Vec<u8>) -> Option<Self> {
        Self::parse_as(bytes, false)
    }

    /// Os primeiros bytes (ou a imagem inteira) de um PE já carregado.
    pub fn parse_mapped(bytes: Vec<u8>) -> Option<Self> {
        Self::parse_as(bytes, true)
    }

    fn parse_as(bytes: Vec<u8>, mapped: bool) -> Option<Self> {
        let pe = u32_at(&bytes, 0x3C)? as usize;
        if bytes.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let machine = u16_at(&bytes, pe + 4)?;
        let count = u16_at(&bytes, pe + 6)? as usize;
        let time_date_stamp = u32_at(&bytes, pe + 8)?;
        let optional_size = u16_at(&bytes, pe + 20)? as usize;
        let characteristics = u16_at(&bytes, pe + 22)?;
        let optional = pe + 24;
        let magic = u16_at(&bytes, optional)?;
        let (image_base, directories, directory_count) = match magic {
            0x20B => (u64::from_le_bytes(bytes.get(optional + 24..optional + 32)?.try_into().ok()?), optional + 112, u32_at(&bytes, optional + 108)? as usize),
            0x10B => (u32_at(&bytes, optional + 28)? as u64, optional + 96, u32_at(&bytes, optional + 92)? as usize),
            _ => return None,
        };
        let header = Header {
            machine,
            time_date_stamp,
            characteristics,
            image_base,
            size_of_image: u32_at(&bytes, optional + 56)?,
            entry_point: u32_at(&bytes, optional + 16)?,
            checksum: u32_at(&bytes, optional + 64)?,
            subsystem: u16_at(&bytes, optional + 68)?,
        };
        let mut sections = Vec::with_capacity(count);
        for index in 0..count {
            let at = optional + optional_size + 40 * index;
            let raw_name = bytes.get(at..at + 8)?;
            let name = String::from_utf8_lossy(&raw_name[..raw_name.iter().position(|&byte| byte == 0).unwrap_or(8)]).into_owned();
            sections.push(Section {
                name,
                virtual_size: u32_at(&bytes, at + 8)?,
                address: u32_at(&bytes, at + 12)?,
                raw_size: u32_at(&bytes, at + 16)?,
                raw: u32_at(&bytes, at + 20)?,
                characteristics: u32_at(&bytes, at + 36)?,
            });
        }
        Some(Self { bytes, sections, header, directories, directory_count: directory_count.min(16), mapped })
    }

    /// Offset nos bytes de um RVA.
    pub fn offset(&self, rva: u32) -> Option<usize> {
        if self.mapped {
            return ((rva as usize) < self.bytes.len()).then_some(rva as usize);
        }
        if (rva as usize) < self.sections.first().map_or(0x1000, |section| section.address as usize) {
            return Some(rva as usize);
        }
        self.sections.iter().find_map(|section| (rva >= section.address && rva - section.address < section.virtual_size.max(section.raw_size)).then(|| (section.raw + rva - section.address) as usize))
    }

    /// Bytes a partir de um RVA (menos se o arquivo acabar antes).
    pub fn bytes_at(&self, rva: u32, length: usize) -> Option<&[u8]> {
        let start = self.offset(rva)?;
        let end = (start + length).min(self.bytes.len());
        self.bytes.get(start..end)
    }

    /// Diretório `index` (RVA, tamanho).
    pub fn directory(&self, index: usize) -> Option<(u32, u32)> {
        if index >= self.directory_count {
            return None;
        }
        Some((u32_at(&self.bytes, self.directories + 8 * index)?, u32_at(&self.bytes, self.directories + 8 * index + 4)?))
    }

    /// (RVA, nome) dos exports nomeados que não são encaminhamentos.
    pub fn exports(&self) -> Vec<(u32, String)> {
        let mut exports = Vec::new();
        let Some((rva, size)) = self.directory(0) else { return exports };
        let Some(directory) = self.offset(rva) else { return exports };
        let (Some(names), Some(functions), Some(name_table), Some(ordinals)) = (
            u32_at(&self.bytes, directory + 24),
            u32_at(&self.bytes, directory + 28).and_then(|rva| self.offset(rva)),
            u32_at(&self.bytes, directory + 32).and_then(|rva| self.offset(rva)),
            u32_at(&self.bytes, directory + 36).and_then(|rva| self.offset(rva)),
        ) else {
            return exports;
        };
        for index in 0..names as usize {
            let Some(name) = u32_at(&self.bytes, name_table + 4 * index).and_then(|rva| self.offset(rva)).and_then(|at| c_string(&self.bytes, at)) else { continue };
            let Some(ordinal) = u16_at(&self.bytes, ordinals + 2 * index) else { continue };
            let Some(function) = u32_at(&self.bytes, functions + 4 * ordinal as usize) else { continue };
            if function >= rva && function < rva + size {
                continue;
            }
            exports.push((function, name));
        }
        exports
    }

    /// GUID, idade e nome do PDB (RSDS).
    pub fn rsds(&self) -> Option<([u8; 16], u32, String)> {
        let (rva, size) = self.directory(6)?;
        let directory = self.offset(rva)?;
        for entry in 0..size as usize / 28 {
            let at = directory + 28 * entry;
            if u32_at(&self.bytes, at + 12)? != 2 {
                continue;
            }
            // Na imagem mapeada o dado está pelo RVA; no arquivo, pelo offset.
            let data = if self.mapped { u32_at(&self.bytes, at + 20)? as usize } else { u32_at(&self.bytes, at + 24)? as usize };
            if self.bytes.get(data..data + 4)? != b"RSDS" {
                continue;
            }
            let guid: [u8; 16] = self.bytes.get(data + 4..data + 20)?.try_into().ok()?;
            return Some((guid, u32_at(&self.bytes, data + 20)?, c_string(&self.bytes, data + 24)?));
        }
        None
    }

    /// As RUNTIME_FUNCTION da `.pdata` (diretório 3), ordenadas pelo começo.
    pub fn runtime_functions(&self) -> Vec<RuntimeFunction> {
        let Some((rva, size)) = self.directory(3) else { return Vec::new() };
        let Some(table) = self.bytes_at(rva, size as usize) else { return Vec::new() };
        let mut functions: Vec<RuntimeFunction> = table
            .chunks_exact(12)
            .map(|entry| RuntimeFunction { begin: u32::from_le_bytes(entry[0..4].try_into().unwrap()), end: u32::from_le_bytes(entry[4..8].try_into().unwrap()), unwind: u32::from_le_bytes(entry[8..12].try_into().unwrap()) })
            .filter(|function| function.end > function.begin)
            .collect();
        functions.sort_by_key(|function| function.begin);
        functions
    }
}

/// A entrada da `.pdata` que contém o RVA.
pub fn find_function(functions: &[RuntimeFunction], rva: u32) -> Option<RuntimeFunction> {
    let index = functions.partition_point(|function| function.begin <= rva);
    let function = *functions.get(index.checked_sub(1)?)?;
    (rva < function.end).then_some(function)
}

/// GUID no formato do servidor de símbolos (Data1-3 em little-endian).
pub fn guid_text(guid: &[u8; 16]) -> String {
    let data1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let data2 = u16::from_le_bytes([guid[4], guid[5]]);
    let data3 = u16::from_le_bytes([guid[6], guid[7]]);
    let mut text = format!("{data1:08X}{data2:04X}{data3:04X}");
    for byte in &guid[8..] {
        text.push_str(&format!("{byte:02X}"));
    }
    text
}

#[cfg(test)]
pub mod tests {
    use super::*;

    /// Um PE x64 mínimo: uma seção `.text` (RVA 0x1000, arquivo 0x400) e
    /// uma `.rdata` (RVA 0x2000, arquivo 0x600) com a `.pdata` e o
    /// UNWIND_INFO passados.
    pub fn tiny_pe(pdata: &[RuntimeFunction], rdata: &[u8], exports: bool) -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];
        bytes[0] = b'M';
        bytes[1] = b'Z';
        bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        bytes[0x88..0x8C].copy_from_slice(&0x5F00_0000u32.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = 0x98;
        bytes[optional..optional + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        bytes[optional + 16..optional + 20].copy_from_slice(&0x1010u32.to_le_bytes());
        bytes[optional + 24..optional + 32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&0x3000u32.to_le_bytes());
        bytes[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        let directories = optional + 112;
        // .pdata no começo da .rdata; o UNWIND_INFO logo depois.
        let pdata_bytes = pdata.len() * 12;
        bytes[directories + 24..directories + 28].copy_from_slice(&0x2000u32.to_le_bytes());
        bytes[directories + 28..directories + 32].copy_from_slice(&(pdata_bytes as u32).to_le_bytes());
        let sections = optional + 0xF0;
        for (index, (name, rva, raw)) in [(b".text\0\0\0", 0x1000u32, 0x400u32), (b".rdata\0\0", 0x2000, 0x600)].into_iter().enumerate() {
            let at = sections + 40 * index;
            bytes[at..at + 8].copy_from_slice(name);
            bytes[at + 8..at + 12].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[at + 12..at + 16].copy_from_slice(&rva.to_le_bytes());
            bytes[at + 16..at + 20].copy_from_slice(&0x200u32.to_le_bytes());
            bytes[at + 20..at + 24].copy_from_slice(&raw.to_le_bytes());
        }
        for (index, function) in pdata.iter().enumerate() {
            let at = 0x600 + 12 * index;
            bytes[at..at + 4].copy_from_slice(&function.begin.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&function.end.to_le_bytes());
            bytes[at + 8..at + 12].copy_from_slice(&function.unwind.to_le_bytes());
        }
        bytes[0x600 + pdata_bytes..0x600 + pdata_bytes + rdata.len()].copy_from_slice(rdata);
        if exports {
            // Diretório de exports em .rdata + 0x100: um nome, "Funcao", em 0x1010.
            let directory = 0x700;
            bytes[directories..directories + 4].copy_from_slice(&0x2100u32.to_le_bytes());
            bytes[directories + 4..directories + 8].copy_from_slice(&0x60u32.to_le_bytes());
            bytes[directory + 20..directory + 24].copy_from_slice(&1u32.to_le_bytes());
            bytes[directory + 24..directory + 28].copy_from_slice(&1u32.to_le_bytes());
            bytes[directory + 28..directory + 32].copy_from_slice(&0x2130u32.to_le_bytes());
            bytes[directory + 32..directory + 36].copy_from_slice(&0x2134u32.to_le_bytes());
            bytes[directory + 36..directory + 40].copy_from_slice(&0x2138u32.to_le_bytes());
            bytes[0x730..0x734].copy_from_slice(&0x1010u32.to_le_bytes());
            bytes[0x734..0x738].copy_from_slice(&0x2140u32.to_le_bytes());
            bytes[0x738..0x73A].copy_from_slice(&0u16.to_le_bytes());
            bytes[0x740..0x747].copy_from_slice(b"Funcao\0");
        }
        bytes
    }

    #[test]
    fn parses_headers_sections_and_pdata() {
        let pdata = [RuntimeFunction { begin: 0x1100, end: 0x1180, unwind: 0x2020 }, RuntimeFunction { begin: 0x1000, end: 0x1040, unwind: 0x2018 }];
        let image = PeImage::parse(tiny_pe(&pdata, &[0x01, 0x04, 0x01, 0x00, 0x04, 0x42], true)).unwrap();
        assert_eq!(image.header.machine, 0x8664);
        assert_eq!(image.header.entry_point, 0x1010);
        assert_eq!(image.header.image_base, 0x1_4000_0000);
        assert_eq!(image.sections.len(), 2);
        assert_eq!(image.sections[1].name, ".rdata");
        assert_eq!(image.offset(0x2004), Some(0x604));
        let functions = image.runtime_functions();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[0].begin, 0x1000);
        assert_eq!(find_function(&functions, 0x1120), Some(pdata[0]));
        assert_eq!(find_function(&functions, 0x1050), None);
        assert_eq!(find_function(&functions, 0x0FFF), None);
        assert_eq!(image.bytes_at(0x2018, 6), Some(&[0x01, 0x04, 0x01, 0x00, 0x04, 0x42][..]));
        assert_eq!(image.exports(), vec![(0x1010, "Funcao".to_string())]);
    }

    #[test]
    fn guid_in_symbol_server_format() {
        let guid = [0x78, 0x56, 0x34, 0x12, 0xBC, 0x9A, 0xF0, 0xDE, 1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(guid_text(&guid), "123456789ABCDEF00102030405060708");
    }
}
