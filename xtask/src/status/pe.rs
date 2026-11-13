//! Leitura do diretório de exports de um PE (PE32 ou PE32+), o suficiente
//! para listar os nomes exportados pelo `ntoskrnl.exe` de referência.
//!
//! Cada export nomeado é classificado como função ou dado pela seção do
//! alvo: alvo numa seção sem IMAGE_SCN_MEM_EXECUTE é uma variável
//! exportada (o `DATA` de um `.def`). Forwarders contam como função.

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const VS_FIXEDFILEINFO_SIGNATURE: [u8; 4] = [0xBD, 0x04, 0xEF, 0xFE];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Export {
    pub name: String,
    pub data: bool,
}

pub struct PeExports {
    pub exports: Vec<Export>,
    /// Versão do arquivo (VS_FIXEDFILEINFO), quando há recurso de versão.
    pub file_version: Option<String>,
    /// Entradas da EAT sem nome (só ordinal).
    pub unnamed: usize,
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
    characteristics: u32,
    name: String,
}

struct Image<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes
        .get(at..at + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or_else(|| format!("PE truncado no offset {at:#x}"))
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    bytes
        .get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or_else(|| format!("PE truncado no offset {at:#x}"))
}

impl Image<'_> {
    fn section_of(&self, rva: u32) -> Option<&Section> {
        self.sections.iter().find(|section| {
            let span = section.virtual_size.max(section.raw_size);
            rva >= section.virtual_address && rva - section.virtual_address < span
        })
    }

    fn offset(&self, rva: u32) -> Result<usize, String> {
        let section = self.section_of(rva).ok_or_else(|| format!("RVA {rva:#x} fora das secoes"))?;
        let delta = rva - section.virtual_address;
        if delta >= section.raw_size {
            return Err(format!("RVA {rva:#x} sem bytes no arquivo"));
        }
        Ok(section.raw_offset as usize + delta as usize)
    }

    fn c_string(&self, rva: u32) -> Result<String, String> {
        let start = self.offset(rva)?;
        let tail = &self.bytes[start..];
        let length = tail.iter().position(|&byte| byte == 0).ok_or("nome de export sem terminador")?;
        String::from_utf8(tail[..length].to_vec()).map_err(|_| format!("nome de export invalido em {rva:#x}"))
    }
}

/// Versão do arquivo a partir do VS_FIXEDFILEINFO dentro de `.rsrc`.
fn file_version(image: &Image) -> Option<String> {
    let section = image.sections.iter().find(|section| section.name == ".rsrc")?;
    let start = section.raw_offset as usize;
    let end = (start + section.raw_size as usize).min(image.bytes.len());
    let resources = image.bytes.get(start..end)?;
    let position = resources.windows(4).position(|window| window == VS_FIXEDFILEINFO_SIGNATURE)?;
    let most = u32_at(resources, position + 8).ok()?;
    let least = u32_at(resources, position + 12).ok()?;
    Some(format!("{}.{}.{}.{}", most >> 16, most & 0xFFFF, least >> 16, least & 0xFFFF))
}

pub fn read_exports(bytes: &[u8]) -> Result<PeExports, String> {
    if bytes.get(0..2) != Some(b"MZ") {
        return Err("arquivo sem assinatura MZ".into());
    }
    let pe = u32_at(bytes, 0x3C)? as usize;
    if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("arquivo sem assinatura PE".into());
    }
    let section_count = u16_at(bytes, pe + 6)? as usize;
    let optional_size = u16_at(bytes, pe + 20)? as usize;
    let optional = pe + 24;
    let (directory_count_at, directories_at) = match u16_at(bytes, optional)? {
        0x20B => (optional + 108, optional + 112),
        0x10B => (optional + 92, optional + 96),
        magic => return Err(format!("optional header desconhecido ({magic:#x})")),
    };
    if u32_at(bytes, directory_count_at)? == 0 {
        return Err("PE sem diretorios de dados".into());
    }
    let export_rva = u32_at(bytes, directories_at)?;
    let export_size = u32_at(bytes, directories_at + 4)?;

    let mut sections = Vec::with_capacity(section_count);
    let table = optional + optional_size;
    for index in 0..section_count {
        let at = table + index * 40;
        let raw_name = bytes.get(at..at + 8).ok_or("tabela de secoes truncada")?;
        let name_length = raw_name.iter().position(|&byte| byte == 0).unwrap_or(8);
        sections.push(Section {
            name: String::from_utf8_lossy(&raw_name[..name_length]).into_owned(),
            virtual_size: u32_at(bytes, at + 8)?,
            virtual_address: u32_at(bytes, at + 12)?,
            raw_size: u32_at(bytes, at + 16)?,
            raw_offset: u32_at(bytes, at + 20)?,
            characteristics: u32_at(bytes, at + 36)?,
        });
    }
    let image = Image { bytes, sections };
    let version = file_version(&image);
    if export_rva == 0 || export_size == 0 {
        return Ok(PeExports { exports: Vec::new(), file_version: version, unnamed: 0 });
    }

    let directory = image.offset(export_rva)?;
    let function_count = u32_at(bytes, directory + 20)? as usize;
    let name_count = u32_at(bytes, directory + 24)? as usize;
    let functions = image.offset(u32_at(bytes, directory + 28)?)?;
    let names = image.offset(u32_at(bytes, directory + 32)?)?;
    let ordinals = image.offset(u32_at(bytes, directory + 36)?)?;

    let mut named_slots = vec![false; function_count];
    let mut exports = Vec::with_capacity(name_count);
    for index in 0..name_count {
        let name = image.c_string(u32_at(bytes, names + index * 4)?)?;
        let slot = u16_at(bytes, ordinals + index * 2)? as usize;
        if slot >= function_count {
            return Err(format!("export {name} com ordinal fora da EAT"));
        }
        named_slots[slot] = true;
        let target = u32_at(bytes, functions + slot * 4)?;
        let forwarder = target >= export_rva && target - export_rva < export_size;
        let data = !forwarder
            && image
                .section_of(target)
                .is_some_and(|section| section.characteristics & IMAGE_SCN_MEM_EXECUTE == 0);
        exports.push(Export { name, data });
    }
    let mut unnamed = 0;
    for (slot, named) in named_slots.iter().enumerate() {
        if !named && u32_at(bytes, functions + slot * 4)? != 0 {
            unnamed += 1;
        }
    }
    exports.sort_by(|left, right| left.name.cmp(&right.name));
    exports.dedup_by(|left, right| left.name == right.name);
    Ok(PeExports { exports, file_version: version, unnamed })
}
