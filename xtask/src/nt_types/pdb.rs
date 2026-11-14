//! Leitor dos tipos de um PDB: o container MSF 7.00, o stream PDB (GUID),
//! o DBI (idade) e o TPI (stream 2, os registros de tipo).
//!
//! Segue o formato público do MSF/PDB e as folhas do `cvinfo.h`. Decodifica
//! o necessário para reconstruir layouts: LF_MODIFIER, LF_POINTER,
//! LF_PROCEDURE/LF_MFUNCTION, LF_FIELDLIST (LF_MEMBER,
//! LF_STMEMBER, LF_NESTTYPE, LF_ENUMERATE, LF_BCLASS, LF_VBCLASS, LF_INDEX,
//! LF_VFUNCTAB, LF_ONEMETHOD, LF_METHOD, LF_FRIENDFCN), LF_BITFIELD,
//! LF_ARRAY, LF_CLASS/LF_STRUCTURE/LF_INTERFACE/LF_UNION/LF_ENUM e as
//! folhas numéricas. Os demais registros ficam só com o código da folha.

use std::collections::HashMap;

const MSF_MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00";

pub const LF_MODIFIER: u16 = 0x1001;
pub const LF_POINTER: u16 = 0x1002;
pub const LF_PROCEDURE: u16 = 0x1008;
pub const LF_MFUNCTION: u16 = 0x1009;
pub const LF_FIELDLIST: u16 = 0x1203;
pub const LF_BITFIELD: u16 = 0x1205;
const LF_BCLASS: u16 = 0x1400;
const LF_VBCLASS: u16 = 0x1401;
const LF_IVBCLASS: u16 = 0x1402;
const LF_INDEX: u16 = 0x1404;
const LF_VFUNCTAB: u16 = 0x1409;
const LF_ENUMERATE: u16 = 0x1502;
pub const LF_ARRAY: u16 = 0x1503;
pub const LF_CLASS: u16 = 0x1504;
pub const LF_STRUCTURE: u16 = 0x1505;
pub const LF_UNION: u16 = 0x1506;
pub const LF_ENUM: u16 = 0x1507;
const LF_FRIENDFCN: u16 = 0x150C;
const LF_MEMBER: u16 = 0x150D;
const LF_STMEMBER: u16 = 0x150E;
const LF_METHOD: u16 = 0x150F;
const LF_NESTTYPE: u16 = 0x1510;
const LF_ONEMETHOD: u16 = 0x1511;
pub const LF_INTERFACE: u16 = 0x1519;

const LF_NUMERIC: u16 = 0x8000;

pub const PROP_FWDREF: u16 = 0x0080;
const PROP_HASUNIQUENAME: u16 = 0x0200;

/// Tipos simples (índices < 0x1000): nome, tamanho.
pub fn simple_type(code: u32) -> Option<(&'static str, u64)> {
    Some(match code {
        0x03 => ("void", 0),
        0x08 => ("HRESULT", 4),
        0x10 | 0x70 | 0x68 => ("i8", 1),
        0x20 | 0x69 => ("u8", 1),
        0x71 | 0x7A | 0x21 | 0x73 => ("u16", 2),
        0x7B | 0x22 | 0x75 => ("u32", 4),
        0x11 | 0x72 => ("i16", 2),
        0x12 | 0x74 => ("i32", 4),
        0x13 | 0x76 => ("i64", 8),
        0x23 | 0x77 => ("u64", 8),
        0x14 | 0x78 => ("i128", 16),
        0x24 | 0x79 => ("u128", 16),
        0x40 => ("f32", 4),
        0x41 => ("f64", 8),
        0x42 => ("f80", 10),
        0x30 => ("bool8", 1),
        0x31 => ("bool16", 2),
        0x32 => ("bool32", 4),
        0x33 => ("bool64", 8),
        _ => return None,
    })
}

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    data.get(at..at + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or_else(|| format!("PDB truncado em {at:#x}"))
}

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

/// Folha numérica: valor e novo offset.
fn read_numeric(data: &[u8], offset: usize) -> Result<(i128, usize), String> {
    let leaf = u16_at(data, offset)?;
    let at = offset + 2;
    if leaf < LF_NUMERIC {
        return Ok((leaf as i128, at));
    }
    let bytes = |count: usize| data.get(at..at + count).ok_or_else(|| format!("folha numerica truncada em {at:#x}"));
    Ok(match leaf {
        0x8000 => (bytes(1)?[0] as i8 as i128, at + 1),
        0x8001 => (i16::from_le_bytes(bytes(2)?.try_into().unwrap()) as i128, at + 2),
        0x8002 => (u16::from_le_bytes(bytes(2)?.try_into().unwrap()) as i128, at + 2),
        0x8003 => (i32::from_le_bytes(bytes(4)?.try_into().unwrap()) as i128, at + 4),
        0x8004 => (u32::from_le_bytes(bytes(4)?.try_into().unwrap()) as i128, at + 4),
        0x8009 => (i64::from_le_bytes(bytes(8)?.try_into().unwrap()) as i128, at + 8),
        0x800A => (u64::from_le_bytes(bytes(8)?.try_into().unwrap()) as i128, at + 8),
        other => return Err(format!("folha numerica nao suportada {other:#x}")),
    })
}

fn read_cstring(data: &[u8], offset: usize) -> Result<(String, usize), String> {
    let tail = data.get(offset..).ok_or("string fora do registro")?;
    let length = tail.iter().position(|&byte| byte == 0).ok_or("string sem terminador")?;
    Ok((String::from_utf8_lossy(&tail[..length]).into_owned(), offset + length + 1))
}

/// Um membro de LF_FIELDLIST (só os que o gerador usa guardam os dados).
#[derive(Clone, Debug)]
pub enum FieldMember {
    Member { name: String, type_index: u32, offset: u64 },
    Enumerate { name: String, value: i128 },
    Index(u32),
    Other,
}

#[derive(Clone, Debug)]
pub struct Udt {
    pub property: u16,
    pub field: u32,
    pub size: u64,
    pub name: String,
    pub unique: Option<String>,
    /// Só LF_ENUM: o tipo inteiro subjacente.
    pub underlying: u32,
}

#[derive(Clone, Debug)]
pub enum Body {
    Modifier { modified: u32 },
    Pointer { referent: u32, size: u64 },
    Bitfield { base: u32, length: u32, position: u32 },
    Array { element: u32, size: u64 },
    Udt(Udt),
    FieldList(Vec<FieldMember>),
    Other,
}

pub struct TypeRecord {
    pub kind: u16,
    pub body: Body,
}

impl TypeRecord {
    pub fn udt(&self) -> Option<&Udt> {
        match &self.body {
            Body::Udt(udt) => Some(udt),
            _ => None,
        }
    }

    fn is_udt_kind(&self) -> bool {
        matches!(self.kind, LF_STRUCTURE | LF_CLASS | LF_UNION | LF_ENUM | LF_INTERFACE)
    }
}

/// Stream TPI: cabeçalho e os registros de tipo, indexados a partir de
/// `first_index`.
pub struct Tpi {
    first_index: u32,
    records: Vec<TypeRecord>,
    by_name: HashMap<String, u32>,
    by_unique: HashMap<String, u32>,
}

impl Tpi {
    pub fn parse(data: &[u8]) -> Result<Tpi, String> {
        let header_size = u32_at(data, 4)? as usize;
        let first_index = u32_at(data, 8)?;
        let record_bytes = u32_at(data, 16)? as usize;
        let end = header_size + record_bytes;
        let mut offset = header_size;
        let mut records = Vec::new();
        while offset < end {
            let length = u16_at(data, offset)? as usize;
            let kind = u16_at(data, offset + 2)?;
            let body = data.get(offset + 4..offset + 2 + length).ok_or("TPI: registro truncado")?;
            let index = first_index as usize + records.len();
            let body = decode(kind, body).map_err(|error| format!("TPI: registro {index:#x}: {error}"))?;
            records.push(TypeRecord { kind, body });
            offset += 2 + length;
        }
        let mut tpi = Tpi { first_index, records, by_name: HashMap::new(), by_unique: HashMap::new() };
        for position in 0..tpi.records.len() {
            let record = &tpi.records[position];
            if !record.is_udt_kind() {
                continue;
            }
            let udt = record.udt().unwrap();
            if udt.property & PROP_FWDREF != 0 {
                continue;
            }
            let index = tpi.first_index + position as u32;
            tpi.by_name.entry(udt.name.clone()).or_insert(index);
            if let Some(unique) = &udt.unique {
                if !unique.is_empty() {
                    tpi.by_unique.entry(unique.clone()).or_insert(index);
                }
            }
        }
        Ok(tpi)
    }

    /// Índices de todos os registros, em ordem.
    pub fn indices(&self) -> impl Iterator<Item = u32> + '_ {
        (0..self.records.len() as u32).map(move |position| self.first_index + position)
    }

    pub fn get(&self, index: u32) -> Option<&TypeRecord> {
        index.checked_sub(self.first_index).and_then(|position| self.records.get(position as usize))
    }

    pub fn record(&self, index: u32) -> Result<&TypeRecord, String> {
        self.get(index).ok_or_else(|| format!("TPI: indice de tipo {index:#x} inexistente"))
    }

    /// Troca uma declaração antecipada (fwdref) pela definição completa.
    pub fn resolve(&self, index: u32) -> u32 {
        let Some(record) = self.get(index) else { return index };
        if !record.is_udt_kind() {
            return index;
        }
        let udt = record.udt().unwrap();
        if udt.property & PROP_FWDREF == 0 {
            return index;
        }
        if let Some(unique) = udt.unique.as_ref().filter(|unique| !unique.is_empty()) {
            if let Some(&found) = self.by_unique.get(unique) {
                return found;
            }
        }
        self.by_name.get(&udt.name).copied().unwrap_or(index)
    }

    /// Membros de uma LF_FIELDLIST, seguindo as continuações LF_INDEX.
    pub fn field_members(&self, mut field_index: u32) -> Result<Vec<FieldMember>, String> {
        let mut members = Vec::new();
        while field_index != 0 {
            let Body::FieldList(list) = &self.record(field_index)?.body else {
                return Err(format!("TPI: {field_index:#x} nao e uma LF_FIELDLIST"));
            };
            field_index = 0;
            for member in list {
                match member {
                    FieldMember::Index(next) => field_index = *next,
                    other => members.push(other.clone()),
                }
            }
        }
        Ok(members)
    }

    pub fn type_size(&self, index: u32) -> Result<u64, String> {
        if index < 0x1000 {
            return Ok(match (index >> 8) & 0xF {
                6 => 8,
                4 | 5 => 4,
                _ => simple_type(index & 0xFF).map_or(0, |(_, size)| size),
            });
        }
        let index = self.resolve(index);
        let record = self.record(index)?;
        match (&record.body, record.kind) {
            (Body::Modifier { modified }, _) => self.type_size(*modified),
            (Body::Pointer { size, .. }, _) => Ok(if *size == 0 { 8 } else { *size }),
            (Body::Udt(udt), LF_ENUM) => self.type_size(udt.underlying),
            (Body::Udt(udt), _) => Ok(udt.size),
            (Body::Array { size, .. }, _) => Ok(*size),
            (Body::Bitfield { base, .. }, _) => self.type_size(*base),
            (_, LF_PROCEDURE | LF_MFUNCTION) => Ok(0),
            (_, kind) => Err(format!("tamanho desconhecido para {index:#x} ({kind:#x})")),
        }
    }

    /// Nome legível de um tipo (o que os comentários `-> ...` citam).
    pub fn type_name(&self, index: u32) -> Result<String, String> {
        if index < 0x1000 {
            let base = match simple_type(index & 0xFF) {
                Some((name, _)) => name.to_string(),
                None => format!("?{:#x}", index & 0xFF),
            };
            return Ok(if (index >> 8) & 0xF != 0 { base + "*" } else { base });
        }
        let index = self.resolve(index);
        let record = self.record(index)?;
        Ok(match (&record.body, record.kind) {
            (Body::Modifier { modified }, _) => self.type_name(*modified)?,
            (Body::Pointer { referent, .. }, _) => self.type_name(*referent)? + "*",
            (Body::Udt(udt), _) => udt.name.clone(),
            (Body::Array { element, size }, _) => {
                let element_size = self.type_size(*element)?;
                let count = if element_size != 0 { size / element_size } else { 0 };
                format!("{}[{count}]", self.type_name(*element)?)
            }
            (Body::Bitfield { base, length, position }, _) => {
                format!("{}:{length}@{position}", self.type_name(*base)?)
            }
            (_, LF_PROCEDURE | LF_MFUNCTION) => "fn".into(),
            (_, kind) => format!("?{kind:#x}"),
        })
    }
}

fn decode(kind: u16, body: &[u8]) -> Result<Body, String> {
    Ok(match kind {
        LF_MODIFIER => Body::Modifier { modified: u32_at(body, 0)? },
        LF_POINTER => {
            let attributes = u32_at(body, 4)?;
            Body::Pointer { referent: u32_at(body, 0)?, size: ((attributes >> 13) & 0x3F) as u64 }
        }
        LF_BITFIELD => Body::Bitfield {
            base: u32_at(body, 0)?,
            length: *body.get(4).ok_or("LF_BITFIELD truncado")? as u32,
            position: *body.get(5).ok_or("LF_BITFIELD truncado")? as u32,
        },
        LF_ARRAY => {
            let (size, _) = read_numeric(body, 8)?;
            Body::Array { element: u32_at(body, 0)?, size: size as u64 }
        }
        LF_CLASS | LF_STRUCTURE | LF_INTERFACE => {
            let (size, offset) = read_numeric(body, 16)?;
            Body::Udt(udt(body, u16_at(body, 2)?, u32_at(body, 4)?, size as u64, offset, 0)?)
        }
        LF_UNION => {
            let (size, offset) = read_numeric(body, 8)?;
            Body::Udt(udt(body, u16_at(body, 2)?, u32_at(body, 4)?, size as u64, offset, 0)?)
        }
        LF_ENUM => Body::Udt(udt(body, u16_at(body, 2)?, u32_at(body, 8)?, 0, 12, u32_at(body, 4)?)?),
        LF_FIELDLIST => Body::FieldList(field_list(body)?),
        _ => Body::Other,
    })
}

fn udt(body: &[u8], property: u16, field: u32, size: u64, offset: usize, underlying: u32) -> Result<Udt, String> {
    let (name, offset) = read_cstring(body, offset)?;
    let unique = if property & PROP_HASUNIQUENAME != 0 && offset < body.len() {
        Some(read_cstring(body, offset)?.0)
    } else {
        None
    };
    Ok(Udt { property, field, size, name, unique, underlying })
}

fn field_list(body: &[u8]) -> Result<Vec<FieldMember>, String> {
    let mut members = Vec::new();
    let mut offset = 0;
    let end = body.len();
    loop {
        // Registros alinhados por bytes LF_PAD (0xF0..0xFF).
        while offset < end && body[offset] >= 0xF0 {
            offset += (body[offset] & 0x0F) as usize;
        }
        if offset >= end {
            break;
        }
        let leaf = u16_at(body, offset)?;
        offset += 2;
        match leaf {
            LF_MEMBER => {
                let type_index = u32_at(body, offset + 2)?;
                let (position, next) = read_numeric(body, offset + 6)?;
                let (name, next) = read_cstring(body, next)?;
                offset = next;
                members.push(FieldMember::Member { name, type_index, offset: position as u64 });
            }
            LF_STMEMBER | LF_NESTTYPE | LF_METHOD | LF_FRIENDFCN => {
                offset = read_cstring(body, offset + 6)?.1;
                members.push(FieldMember::Other);
            }
            LF_ENUMERATE => {
                let (value, next) = read_numeric(body, offset + 2)?;
                let (name, next) = read_cstring(body, next)?;
                offset = next;
                members.push(FieldMember::Enumerate { name, value });
            }
            LF_BCLASS => {
                offset = read_numeric(body, offset + 6)?.1;
                members.push(FieldMember::Other);
            }
            LF_VBCLASS | LF_IVBCLASS => {
                let (_, next) = read_numeric(body, offset + 10)?;
                offset = read_numeric(body, next)?.1;
                members.push(FieldMember::Other);
            }
            LF_INDEX => {
                let next = u32_at(body, offset + 2)?;
                offset += 6;
                members.push(FieldMember::Index(next));
            }
            LF_VFUNCTAB => {
                offset += 6;
                members.push(FieldMember::Other);
            }
            LF_ONEMETHOD => {
                let attributes = u16_at(body, offset)?;
                offset += 6;
                // Virtual introdutório (4) e puro introdutório (6) trazem o offset na vtable.
                if matches!((attributes >> 2) & 0x7, 4 | 6) {
                    offset += 4;
                }
                offset = read_cstring(body, offset)?.1;
                members.push(FieldMember::Other);
            }
            other => return Err(format!("folha de lista de campos nao suportada {other:#x}")),
        }
    }
    Ok(members)
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
