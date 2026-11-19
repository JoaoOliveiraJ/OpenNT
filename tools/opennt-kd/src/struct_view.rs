//! A vista de um endereço como um tipo do PDB ("ver como tipo"): a árvore
//! campo a campo de uma struct, com structs aninhadas, arrays, ponteiros
//! seguidos e listas (LIST_ENTRY percorrida pelo Flink, cada entrada como
//! a struct que a contém), e a edição de um campo escalar (o valor em
//! texto vira os bytes a gravar, com os bitfields lidos e regravados).
//!
//! A árvore é plana: cada linha tem a profundidade e uma chave (o caminho
//! dos nomes, `Pcb/ThreadListHead/#3`); a interface guarda as chaves
//! abertas e pede a árvore de novo.

use std::collections::{HashMap, HashSet};

use super::types::{Field, Kind, TypeDb};
use super::unwind::ReadMemory;

/// Entradas de lista e elementos de array mostrados no máximo.
pub const LIST_LIMIT: usize = 256;
pub const ARRAY_LIMIT: usize = 256;

/// O que uma linha é.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowKind {
    Scalar,
    Struct,
    Array,
    Pointer,
    /// Uma LIST_ENTRY que abre como lista.
    List,
    /// Uma entrada de lista (o elemento que a contém).
    ListEntry,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub key: String,
    pub depth: usize,
    pub name: String,
    pub offset: u64,
    pub address: u64,
    pub ty: u32,
    pub type_name: String,
    pub value: String,
    pub kind: RowKind,
    pub expandable: bool,
    pub expanded: bool,
    /// Escalar que dá para editar.
    pub editable: bool,
    /// O valor numérico (escalares, ponteiros, entradas de lista).
    pub number: Option<u64>,
}

/// O tipo do elemento de uma lista: o tipo que contém a LIST_ENTRY e o
/// campo de ligação.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListElement {
    pub ty: u32,
    pub link_offset: u64,
    pub description: String,
}

/// As listas conhecidas do NT: (struct, campo da cabeça) -> (tipo do
/// elemento, campo de ligação).
const KNOWN_LISTS: &[(&str, &str, &str, &str)] = &[
    ("_EPROCESS", "ActiveProcessLinks", "_EPROCESS", "ActiveProcessLinks"),
    ("_EPROCESS", "ThreadListHead", "_ETHREAD", "ThreadListEntry"),
    ("_KPROCESS", "ThreadListHead", "_KTHREAD", "ThreadListEntry"),
    ("_KPROCESS", "ProcessListEntry", "_KPROCESS", "ProcessListEntry"),
    ("_ETHREAD", "IrpList", "_IRP", "ThreadListEntry"),
    ("_ETHREAD", "ThreadListEntry", "_ETHREAD", "ThreadListEntry"),
    ("_KTHREAD", "ThreadListEntry", "_KTHREAD", "ThreadListEntry"),
    ("_PEB_LDR_DATA", "InLoadOrderModuleList", "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"),
    ("_PEB_LDR_DATA", "InMemoryOrderModuleList", "_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks"),
    ("_PEB_LDR_DATA", "InInitializationOrderModuleList", "_LDR_DATA_TABLE_ENTRY", "InInitializationOrderLinks"),
    ("_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks", "_LDR_DATA_TABLE_ENTRY", "InLoadOrderLinks"),
    ("_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks", "_LDR_DATA_TABLE_ENTRY", "InMemoryOrderLinks"),
    ("_OBJECT_TYPE", "TypeList", "_OBJECT_HEADER_CREATOR_INFO", "TypeList"),
];

fn base_name(name: &str) -> &str {
    name.trim_start_matches('_')
}

/// O elemento de uma lista pela struct e pelo campo, pelas listas
/// conhecidas; sem elas, a própria struct pelo mesmo campo.
pub fn guess_list_element(db: &TypeDb, parent: u32, field: &str) -> Option<ListElement> {
    let parent_name = db.name(db.resolve(parent));
    let known = KNOWN_LISTS.iter().find(|(structure, head, _, _)| base_name(structure) == base_name(&parent_name) && *head == field);
    let (element, link) = match known {
        Some((_, _, element, link)) => (db.find(element)?, link.to_string()),
        None => (db.resolve(parent), field.to_string()),
    };
    let offset = db.member(element, &link)?.offset;
    Some(ListElement { ty: element, link_offset: offset, description: format!("{}.{}", db.name(element), link) })
}

/// O elemento de uma lista escolhido pelo nome (`_ETHREAD.ThreadListEntry`).
pub fn list_element_named(db: &TypeDb, text: &str) -> Result<ListElement, String> {
    let (type_name, field) = text.trim().split_once('.').ok_or("use Tipo.CampoDeLigacao")?;
    let ty = db.find(type_name).ok_or_else(|| format!("tipo {type_name} nao encontrado"))?;
    let member = db.member(ty, field).ok_or_else(|| format!("{type_name} nao tem o campo {field}"))?;
    Ok(ListElement { ty, link_offset: member.offset, description: format!("{}.{}", db.name(ty), member.name) })
}

/// Percorre uma LIST_ENTRY pelo Flink a partir da cabeça: os endereços das
/// entradas (sem a cabeça), até voltar, um ponteiro nulo ou o limite.
pub fn walk_list(memory: &mut dyn ReadMemory, head: u64, limit: usize) -> Vec<u64> {
    let mut entries = Vec::new();
    let mut current = memory.read_u64(head).unwrap_or(0);
    let mut seen = HashSet::new();
    while current != 0 && current != head && entries.len() < limit && seen.insert(current) {
        entries.push(current);
        current = memory.read_u64(current).unwrap_or(0);
    }
    entries
}

fn is_list_entry(db: &TypeDb, ty: u32) -> bool {
    matches!(db.kind(ty), Kind::Struct { name, .. } if name == "_LIST_ENTRY")
}

fn struct_name(db: &TypeDb, ty: u32) -> Option<String> {
    match db.kind(ty) {
        Kind::Struct { name, .. } => Some(name),
        _ => None,
    }
}

/// O texto de uma UNICODE_STRING/STRING num valor de struct.
fn counted_text(db: &TypeDb, memory: &mut dyn ReadMemory, ty: u32, address: u64) -> Option<String> {
    let name = struct_name(db, ty)?;
    let wide = match name.as_str() {
        "_UNICODE_STRING" => true,
        "_STRING" | "_ANSI_STRING" => false,
        _ => return None,
    };
    let bytes = memory.read(address, 16).ok().filter(|bytes| bytes.len() >= 16)?;
    let length = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let buffer = u64::from_le_bytes(bytes[8..16].try_into().ok()?);
    if buffer == 0 || length == 0 {
        return Some("\"\"".into());
    }
    let data = memory.read(buffer, length.min(512)).ok()?;
    Some(if wide {
        let units: Vec<u16> = data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        format!("\"{}\"", String::from_utf16_lossy(&units))
    } else {
        format!("\"{}\"", String::from_utf8_lossy(&data))
    })
}

/// O pedido de uma árvore.
pub struct Request<'a> {
    pub ty: u32,
    pub address: u64,
    /// As chaves abertas.
    pub expanded: &'a HashSet<String>,
    /// O elemento escolhido para cada lista (pela chave da linha).
    pub lists: &'a HashMap<String, ListElement>,
}

/// A árvore aberta de `ty` em `address`.
pub fn build(db: &TypeDb, memory: &mut dyn ReadMemory, request: &Request, describe: &dyn Fn(u64) -> Option<String>) -> Vec<Row> {
    let mut rows = Vec::new();
    let fields = db.fields(memory, request.ty, request.address, describe);
    for field in fields {
        push_field(db, memory, request, describe, request.ty, &field, String::new(), 0, &mut rows, 0);
    }
    rows
}

#[allow(clippy::too_many_arguments)]
fn push_field(db: &TypeDb, memory: &mut dyn ReadMemory, request: &Request, describe: &dyn Fn(u64) -> Option<String>, parent: u32, field: &Field, prefix: String, depth: usize, rows: &mut Vec<Row>, budget: usize) {
    if rows.len() > 20_000 || budget > 24 {
        return;
    }
    let key = if prefix.is_empty() { field.name.clone() } else { format!("{prefix}/{}", field.name) };
    let kind_of = db.kind(field.ty);
    let list = is_list_entry(db, field.ty);
    let kind = if list {
        RowKind::List
    } else {
        match kind_of {
            Kind::Struct { .. } => RowKind::Struct,
            Kind::Array { .. } => RowKind::Array,
            Kind::Pointer { .. } => RowKind::Pointer,
            Kind::Primitive { .. } | Kind::Enum { .. } | Kind::Bitfield { .. } => RowKind::Scalar,
            _ => RowKind::Other,
        }
    };
    let value = counted_text(db, memory, field.ty, field.address).unwrap_or_else(|| field.value.clone());
    let expandable = field.expandable || list;
    let expanded = expandable && request.expanded.contains(&key);
    rows.push(Row {
        key: key.clone(),
        depth,
        name: field.name.clone(),
        offset: field.offset,
        address: field.address,
        ty: field.ty,
        type_name: field.type_name.clone(),
        value,
        kind,
        expandable,
        expanded,
        editable: kind == RowKind::Scalar || kind == RowKind::Pointer,
        number: field.number,
    });
    if !expanded {
        return;
    }
    if list {
        let element = request.lists.get(&key).cloned().or_else(|| guess_list_element(db, parent, &field.name));
        let entries = walk_list(memory, field.address, LIST_LIMIT);
        for (index, entry) in entries.iter().enumerate() {
            let entry_key = format!("{key}/#{index}");
            let (container, ty, type_name, value) = match &element {
                Some(element) => (entry.wrapping_sub(element.link_offset), element.ty, db.name(element.ty), format!("{} em {:#x}", element.description, entry.wrapping_sub(element.link_offset))),
                None => (*entry, field.ty, field.type_name.clone(), format!("LIST_ENTRY em {entry:#x}")),
            };
            let open = request.expanded.contains(&entry_key);
            rows.push(Row { key: entry_key.clone(), depth: depth + 1, name: format!("[{index}]"), offset: 0, address: container, ty, type_name, value, kind: RowKind::ListEntry, expandable: true, expanded: open, editable: false, number: Some(container) });
            if open {
                for child in db.fields(memory, ty, container, describe) {
                    push_field(db, memory, request, describe, ty, &child, entry_key.clone(), depth + 2, rows, budget + 1);
                }
            }
        }
        return;
    }
    let children = match kind_of {
        Kind::Array { element, size } => {
            let element_size = db.size(element).max(1);
            let count = (size / element_size).min(ARRAY_LIMIT as u64);
            (0..count).map(|position| db.field(memory, &format!("[{position}]"), position * element_size, element, field.address + position * element_size, describe)).collect()
        }
        _ => db.fields(memory, field.ty, field.address, describe),
    };
    let child_parent = match kind_of {
        Kind::Pointer { target } => target,
        _ => field.ty,
    };
    for child in children {
        push_field(db, memory, request, describe, child_parent, &child, key.clone(), depth + 1, rows, budget + 1);
    }
}

fn parse_integer(text: &str) -> Result<i128, String> {
    let text = text.trim().replace(['`', '_'], "");
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest.to_string()),
        None => (false, text.clone()),
    };
    let value = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        i128::from_str_radix(hex, 16)
    } else if let Some(decimal) = digits.strip_prefix("0n") {
        decimal.parse::<i128>()
    } else if digits.chars().all(|character| character.is_ascii_digit()) {
        digits.parse::<i128>()
    } else {
        i128::from_str_radix(&digits, 16)
    }
    .map_err(|_| format!("numero invalido: {text}"))?;
    Ok(if negative { -value } else { value })
}

/// O que gravar para pôr `text` num campo escalar: o endereço e os bytes.
/// `current` lê a memória (os bitfields mantêm os outros bits).
pub fn encode_edit(db: &TypeDb, memory: &mut dyn ReadMemory, ty: u32, address: u64, text: &str) -> Result<(u64, Vec<u8>), String> {
    let (size, bits) = match db.kind(ty) {
        Kind::Primitive { size, float, .. } => {
            if float {
                let value: f64 = text.trim().parse().map_err(|_| format!("numero de ponto flutuante invalido: {text}"))?;
                return Ok((address, if size == 4 { (value as f32).to_le_bytes().to_vec() } else { value.to_le_bytes().to_vec() }));
            }
            (size, None)
        }
        Kind::Pointer { .. } => (8, None),
        Kind::Enum { underlying, .. } => {
            let size = db.size(underlying).max(1);
            // O nome de um enumerador vale como o número.
            if let Some(value) = (0..4096i128).find(|value| db.enumerator(ty, *value).is_some_and(|name| name == text.trim())) {
                let bytes = (value as u64).to_le_bytes();
                return Ok((address, bytes[..size as usize].to_vec()));
            }
            (size, None)
        }
        Kind::Bitfield { base, length, position } => (db.size(base).max(1), Some((length, position))),
        other => return Err(format!("{} nao e editavel ({other:?})", db.name(ty))),
    };
    let size = size.clamp(1, 8) as usize;
    let value = parse_integer(text)?;
    let raw = value as u64;
    let bytes = match bits {
        Some((length, position)) => {
            let current = memory.read(address, size)?;
            if current.len() < size {
                return Err(format!("memoria em {address:#x} inacessivel"));
            }
            let mut buffer = [0u8; 8];
            buffer[..size].copy_from_slice(&current[..size]);
            let mut unit = u64::from_le_bytes(buffer);
            let mask = if length >= 64 { u64::MAX } else { (1u64 << length) - 1 };
            if raw & !mask != 0 {
                return Err(format!("o valor nao cabe em {length} bits"));
            }
            unit = (unit & !(mask << position)) | (raw & mask) << position;
            unit.to_le_bytes()[..size].to_vec()
        }
        None => {
            if size < 8 {
                let limit = 1i128 << (8 * size);
                if value >= limit || value < -(limit / 2) {
                    return Err(format!("o valor nao cabe em {size} bytes"));
                }
            }
            raw.to_le_bytes()[..size].to_vec()
        }
    };
    Ok((address, bytes))
}

/// O texto da árvore (o `dtv` do prompt e a ferramenta MCP).
pub fn format_rows(rows: &[Row]) -> String {
    let mut text = String::new();
    for row in rows {
        let marker = if row.expandable { if row.expanded { "- " } else { "+ " } } else { "  " };
        text.push_str(&format!("{}{marker}+{:#05x} {:<28} : {:<24} {}\n", "  ".repeat(row.depth), row.offset, row.name, row.type_name, row.value));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tests::Builder;

    /// `_EPROCESS` e `_ETHREAD` reduzidos, com a lista de threads.
    fn sample() -> TypeDb {
        let mut builder = Builder::new();
        let mut entry = Builder::member("Flink", 0x23, 0);
        entry.extend(Builder::member("Blink", 0x23, 8));
        let entry_fields = builder.add(0x1203, entry);
        let list_entry = builder.add(0x1505, Builder::structure(entry_fields, 0x10, "_LIST_ENTRY"));
        let mut thread = Builder::member("Cid", 0x23, 0);
        thread.extend(Builder::member("ThreadListEntry", list_entry, 0x10));
        let thread_fields = builder.add(0x1203, thread);
        builder.add(0x1505, Builder::structure(thread_fields, 0x20, "_ETHREAD"));
        let mut array = 0x70u32.to_le_bytes().to_vec();
        array.extend_from_slice(&0x23u32.to_le_bytes());
        array.extend_from_slice(&15u16.to_le_bytes());
        array.push(0);
        let name = builder.add(0x1503, array);
        let mut process = Builder::member("UniqueProcessId", 0x23, 0);
        process.extend(Builder::member("ThreadListHead", list_entry, 0x10));
        process.extend(Builder::member("ImageFileName", name, 0x20));
        let process_fields = builder.add(0x1203, process);
        builder.add(0x1505, Builder::structure(process_fields, 0x30, "_EPROCESS"));
        builder.build()
    }

    /// Memória de mentira: um EPROCESS com dois threads na lista.
    struct Memory(HashMap<u64, u8>);

    impl Memory {
        fn put(&mut self, address: u64, bytes: &[u8]) {
            for (index, byte) in bytes.iter().enumerate() {
                self.0.insert(address + index as u64, *byte);
            }
        }
    }

    impl ReadMemory for Memory {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
            Ok((0..length as u64).map(|index| self.0.get(&(address + index)).copied().unwrap_or(0)).collect())
        }
    }

    #[test]
    fn tree_with_lists_and_edits() {
        let db = sample();
        let process = db.find("_EPROCESS").expect("_EPROCESS do tipo de exemplo");
        let mut memory = Memory(HashMap::new());
        let base = 0x1000u64;
        let list = base + db.member(process, "ThreadListHead").expect("ThreadListHead").offset;
        let thread = db.find("_ETHREAD").expect("_ETHREAD");
        let link = db.member(thread, "ThreadListEntry").expect("ThreadListEntry").offset;
        let (first, second) = (0x5000u64, 0x6000u64);
        memory.put(list, &(first + link).to_le_bytes());
        memory.put(first + link, &(second + link).to_le_bytes());
        memory.put(second + link, &list.to_le_bytes());
        let name = base + db.member(process, "ImageFileName").expect("ImageFileName").offset;
        memory.put(name, b"smss.exe\0");
        let mut expanded = HashSet::new();
        let lists = HashMap::new();
        let rows = build(&db, &mut memory, &Request { ty: process, address: base, expanded: &expanded, lists: &lists }, &|_| None);
        let image = rows.iter().find(|row| row.name == "ImageFileName").expect("ImageFileName");
        assert!(image.value.contains("smss.exe"), "{}", image.value);
        let head = rows.iter().find(|row| row.name == "ThreadListHead").expect("ThreadListHead");
        assert_eq!(head.kind, RowKind::List);
        expanded.insert("ThreadListHead".to_string());
        expanded.insert("ThreadListHead/#1".to_string());
        let rows = build(&db, &mut memory, &Request { ty: process, address: base, expanded: &expanded, lists: &lists }, &|_| None);
        let entries: Vec<&Row> = rows.iter().filter(|row| row.kind == RowKind::ListEntry).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].number, Some(first));
        assert_eq!(entries[1].number, Some(second));
        assert!(entries[1].type_name.contains("ETHREAD"), "{}", entries[1].type_name);
        assert!(rows.iter().any(|row| row.key.starts_with("ThreadListHead/#1/") && row.depth == 2));
        assert_eq!(walk_list(&mut memory, list, 1).len(), 1);
        // Editar: um ULONG e um valor grande demais.
        let pid = db.member(process, "UniqueProcessId").expect("UniqueProcessId");
        let (address, bytes) = encode_edit(&db, &mut memory, pid.ty, base + pid.offset, "0x2a").expect("edicao");
        assert_eq!(address, base + pid.offset);
        assert_eq!(bytes.len(), db.size(pid.ty).clamp(1, 8) as usize);
        assert_eq!(bytes[0], 0x2a);
        let text = format_rows(&rows);
        assert!(text.contains("ThreadListHead"));
        assert!(list_element_named(&db, "_ETHREAD.ThreadListEntry").is_ok());
        assert!(list_element_named(&db, "_ETHREAD.Nada").is_err());
    }

    #[test]
    fn integers() {
        assert_eq!(parse_integer("0x10"), Ok(16));
        assert_eq!(parse_integer("-1"), Ok(-1));
        assert_eq!(parse_integer("0n12"), Ok(12));
        assert_eq!(parse_integer("ff"), Ok(255));
        assert!(parse_integer("zz").is_err());
    }
}
