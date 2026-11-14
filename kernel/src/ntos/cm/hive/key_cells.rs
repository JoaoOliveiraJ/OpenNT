//! Células de chave e de valor de uma hive ('nk', 'vk', dados e 'db').
//!
//! As operações que o Cm faz sobre a hive quando uma chave muda, como no
//! ntoskrnl 19041:
//! - criação (CmpDoCreateChild / CmpCreateHiveRootCell, rva 0x78da10): 'nk'
//!   com o nome comprimido em bytes quando todos os caracteres cabem em 8
//!   bits (CmpCopyName, rva 0x657770, flag KEY_COMP_NAME), listas e classe
//!   nil, a célula de segurança e a entrada na lista de subchaves do pai; a
//!   raiz leva KEY_HIVE_ENTRY | KEY_NO_DELETE e pai nil;
//! - valor novo (CmpAddValueKeyNew, rva 0x657630): 'vk' com o nome
//!   comprimido (VALUE_COMP_NAME); até 4 bytes de dado ficam no próprio
//!   campo Data com o bit CM_KEY_VALUE_SPECIAL_SIZE; acima de 16344 bytes,
//!   numa hive de versão 4 ou mais, os dados vão para uma célula 'db' com
//!   segmentos de 16344 bytes (CmpSetValueDataNew, rva 0x6e1b84); entre os
//!   dois, numa célula só;
//! - a lista de valores cresce uma entrada por vez até 100 e depois em
//!   blocos de 100 (CmpAddValueToListEx, rva 0x6e0174);
//! - MaxNameLen, MaxValueNameLen e MaxValueDataLen guardam os maiores
//!   comprimentos em bytes de UTF-16 e de dados vistos pela chave.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry::Value;
use crate::ntos::inc::types::{CmBigData, CmKeyNode, CmKeyValue};
use crate::ntos::inc::types::NtStruct;
use crate::ntos::inc::field::Field;
use crate::ntos::se::inherit_descriptor::Captured;

use super::storage::{Storage, HCELL_NIL, STATUS_REGISTRY_CORRUPT};
use super::{index, security_cells};

/// 'nk', 'vk' e 'db'.
pub const NK: u16 = 0x6b6e;
pub const VK: u16 = 0x6b76;
pub const DB: u16 = 0x6264;

pub const KEY_VOLATILE: u16 = 0x0001;
pub const KEY_HIVE_EXIT: u16 = 0x0002;
pub const KEY_HIVE_ENTRY: u16 = 0x0004;
pub const KEY_NO_DELETE: u16 = 0x0008;
pub const KEY_SYM_LINK: u16 = 0x0010;
pub const KEY_COMP_NAME: u16 = 0x0020;
pub const VALUE_COMP_NAME: u16 = 0x0001;

/// CM_KEY_VALUE_SPECIAL_SIZE e CM_KEY_VALUE_BIG.
const SPECIAL_SIZE: u32 = 0x8000_0000;
pub const BIG_SEGMENT: u32 = 0x3fd8;

fn node_at(address: u64) -> &'static CmKeyNode {
    // SAFETY: dados de uma célula 'nk' alocada.
    unsafe { CmKeyNode::at(address) }
}

fn value_at(address: u64) -> &'static CmKeyValue {
    // SAFETY: dados de uma célula 'vk' alocada.
    unsafe { CmKeyValue::at(address) }
}

/// O 'nk' de uma célula, conferindo assinatura e tamanho do nome.
pub fn node(storage: &Storage, cell: u32) -> Option<&'static CmKeyNode> {
    let address = storage.cell(cell, 0x4c)?;
    let node = node_at(address);
    (node.signature.get() == NK && storage.cell(cell, 0x4c + node.name_length.get() as u32).is_some()).then_some(node)
}

fn vk(storage: &Storage, cell: u32) -> Option<&'static CmKeyValue> {
    let address = storage.cell(cell, 0x14)?;
    let value = value_at(address);
    (value.signature.get() == VK && storage.cell(cell, 0x14 + value.name_length.get() as u32).is_some()).then_some(value)
}

/// CmpCopyName: bytes quando todos os caracteres cabem em 8 bits.
fn stored_name(name: &[u16]) -> (Vec<u8>, bool) {
    if !name.is_empty() && name.iter().all(|&unit| unit <= 0xFF) {
        (name.iter().map(|&unit| unit as u8).collect(), true)
    } else {
        (name.iter().flat_map(|unit| unit.to_le_bytes()).collect(), false)
    }
}

fn decode_name(bytes: &[u8], compressed: bool) -> Vec<u16> {
    if compressed {
        bytes.iter().map(|&byte| byte as u16).collect()
    } else {
        bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
    }
}

/// O nome de uma chave em UTF-16.
pub fn key_name(storage: &Storage, cell: u32) -> Option<Vec<u16>> {
    let node = node(storage, cell)?;
    let bytes = storage.read_cell(cell, 0x4c + node.name_length.get() as u32)?;
    Some(decode_name(&bytes[0x4c..], node.flags.get() & KEY_COMP_NAME != 0))
}

fn value_name(storage: &Storage, cell: u32) -> Option<Vec<u16>> {
    let value = vk(storage, cell)?;
    let bytes = storage.read_cell(cell, 0x14 + value.name_length.get() as u32)?;
    Some(decode_name(&bytes[0x14..], value.flags.get() & VALUE_COMP_NAME != 0))
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn raise(field: &Field<u32>, value: u32) {
    if value > field.get() {
        field.set(value);
    }
}

/// A célula de segurança da raiz (início da lista de 'sk').
fn root_security(storage: &Storage) -> u32 {
    node(storage, storage.root_cell()).map_or(HCELL_NIL, |root| root.security.get())
}

/// Cria um 'nk'. `parent` nil cria a raiz da hive.
pub fn create_key(storage: &mut Storage, parent: u32, name: &str, security: &Captured, time: u64) -> Option<u32> {
    let name_units = units(name);
    let (stored, compressed) = stored_name(&name_units);
    let cell = storage.allocate(0x4c + stored.len() as u32)?;
    storage.write_cell(cell, 0x4c, &stored);
    let address = storage.cell(cell, 0x4c)?;
    let key = node_at(address);
    key.signature.set(NK);
    let mut flags = if compressed { KEY_COMP_NAME } else { 0 };
    if parent == HCELL_NIL {
        flags |= KEY_HIVE_ENTRY | KEY_NO_DELETE;
    }
    key.flags.set(flags);
    key.last_write_time.quad_part.set(time as i64);
    key.parent.set(parent);
    key.sub_key_lists[0].set(HCELL_NIL);
    key.sub_key_lists[1].set(HCELL_NIL);
    key.value_list.list.set(HCELL_NIL);
    key.security.set(HCELL_NIL);
    key.class.set(HCELL_NIL);
    key.name_length.set(stored.len() as u16);
    let anchor = if parent == HCELL_NIL { HCELL_NIL } else { node(storage, parent)?.security.get() };
    let root = if parent == HCELL_NIL { HCELL_NIL } else { root_security(storage) };
    let security_cell = security_cells::assign(storage, anchor, root, security)?;
    node_at(storage.cell(cell, 0x4c)?).security.set(security_cell);
    if parent != HCELL_NIL {
        let parent_node = node(storage, parent)?;
        let list = parent_node.sub_key_lists[0].get();
        let new_list = index::add(storage, list, cell, &name_units, &|storage, child| key_name(storage, child))?;
        let parent_node = node(storage, parent)?;
        parent_node.sub_key_lists[0].set(new_list);
        parent_node.sub_key_counts[0].set(parent_node.sub_key_counts[0].get() + 1);
        if name_units.len() as u32 * 2 > parent_node.max_name_len() {
            parent_node.set_max_name_len(name_units.len() as u32 * 2);
        }
        parent_node.last_write_time.quad_part.set(time as i64);
        storage.mark_cell_dirty(parent);
    }
    storage.mark_cell_dirty(cell);
    Some(cell)
}

/// O dado de um valor.
fn read_data(storage: &Storage, value: &CmKeyValue) -> Result<Vec<u8>, u32> {
    let length = value.data_length.get();
    if length & SPECIAL_SIZE != 0 {
        let length = length & !SPECIAL_SIZE;
        if length > 4 {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        return Ok(value.data.get().to_le_bytes()[..length as usize].to_vec());
    }
    let cell = value.data.get();
    if length == 0 {
        return Ok(Vec::new());
    }
    if storage.minor() >= 4 && length > BIG_SEGMENT {
        let address = storage.cell(cell, 8).ok_or(STATUS_REGISTRY_CORRUPT)?;
        // SAFETY: célula 'db' alocada (assinatura conferida a seguir).
        let big = unsafe { CmBigData::at(address) };
        let count = big.count.get() as u32;
        if big.signature.get() != DB || count == 0 || count.saturating_mul(BIG_SEGMENT) < length {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        let list = storage.read_cell(big.list.get(), count * 4).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let mut data = Vec::with_capacity(length as usize);
        for segment in list.chunks_exact(4) {
            let segment = u32::from_le_bytes([segment[0], segment[1], segment[2], segment[3]]);
            let take = (length - data.len() as u32).min(BIG_SEGMENT);
            data.extend(storage.read_cell(segment, take).ok_or(STATUS_REGISTRY_CORRUPT)?);
            if data.len() as u32 == length {
                break;
            }
        }
        return Ok(data);
    }
    storage.read_cell(cell, length).ok_or(STATUS_REGISTRY_CORRUPT)
}

/// CmpSetValueDataNew: a célula de dados (ou 'db') para dados acima de 4
/// bytes.
fn write_data(storage: &mut Storage, data: &[u8]) -> Option<u32> {
    let length = data.len() as u32;
    if storage.minor() < 4 || length <= BIG_SEGMENT {
        let cell = storage.allocate(length)?;
        storage.write_cell(cell, 0, data);
        return Some(cell);
    }
    let count = length.div_ceil(BIG_SEGMENT);
    let big = storage.allocate(8)?;
    let list = storage.allocate(count * 4)?;
    let mut segments = Vec::with_capacity(count as usize);
    for chunk in data.chunks(BIG_SEGMENT as usize) {
        let segment = storage.allocate(BIG_SEGMENT)?;
        storage.write_cell(segment, 0, chunk);
        segments.push(segment);
    }
    let bytes: Vec<u8> = segments.iter().flat_map(|segment| segment.to_le_bytes()).collect();
    storage.write_cell(list, 0, &bytes);
    // SAFETY: célula 'db' recém-alocada.
    let header = unsafe { CmBigData::at(storage.cell(big, 8)?) };
    header.signature.set(DB);
    header.count.set(count as u16);
    header.list.set(list);
    storage.mark_cell_dirty(big);
    Some(big)
}

/// CmpFreeValueData.
fn free_data(storage: &mut Storage, length: u32, cell: u32) {
    if length & SPECIAL_SIZE != 0 || length == 0 || cell == HCELL_NIL {
        return;
    }
    if storage.minor() >= 4 && length > BIG_SEGMENT {
        if let Some(address) = storage.cell(cell, 8) {
            // SAFETY: célula 'db' alocada.
            let big = unsafe { CmBigData::at(address) };
            if big.signature.get() == DB {
                let (count, list) = (big.count.get() as u32, big.list.get());
                if let Some(bytes) = storage.read_cell(list, count * 4) {
                    for segment in bytes.chunks_exact(4) {
                        storage.free(u32::from_le_bytes([segment[0], segment[1], segment[2], segment[3]]));
                    }
                }
                storage.free(list);
            }
        }
    }
    storage.free(cell);
}

/// Grava tipo e dado num 'vk' (o dado antigo já foi liberado).
fn store_value_data(storage: &mut Storage, cell: u32, value_type: u32, data: &[u8]) -> Option<()> {
    let (length, field) = if data.len() <= 4 {
        let mut inline = [0u8; 4];
        inline[..data.len()].copy_from_slice(data);
        (SPECIAL_SIZE | data.len() as u32, u32::from_le_bytes(inline))
    } else {
        (data.len() as u32, write_data(storage, data)?)
    };
    let value = vk(storage, cell)?;
    value.data_length.set(length);
    value.data.set(field);
    value.type_.set(value_type);
    storage.mark_cell_dirty(cell);
    Some(())
}

/// As células 'vk' de uma chave, em ordem.
fn value_cells(storage: &Storage, key: &CmKeyNode) -> Option<Vec<u32>> {
    let count = key.value_list.count.get();
    if count == 0 {
        return Some(Vec::new());
    }
    let bytes = storage.read_cell(key.value_list.list.get(), count * 4)?;
    Some(bytes.chunks_exact(4).map(|entry| u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]])).collect())
}

fn find_value(storage: &Storage, key: &CmKeyNode, name: &[u16]) -> Option<(usize, u32)> {
    value_cells(storage, key)?.into_iter().enumerate().find(|&(_, cell)| value_name(storage, cell).is_some_and(|other| index::compare(&other, name).is_eq()))
}

/// CmSetValueKey sobre a hive: troca o dado de um valor existente ou cria
/// o 'vk' no fim da lista.
pub fn set_value(storage: &mut Storage, key_cell: u32, name: &str, value_type: u32, data: &[u8], time: u64) -> Option<()> {
    let name_units = units(name);
    let key = node(storage, key_cell)?;
    match find_value(storage, key, &name_units) {
        Some((_, cell)) => {
            let old = vk(storage, cell)?;
            let (length, field) = (old.data_length.get(), old.data.get());
            free_data(storage, length, field);
            store_value_data(storage, cell, value_type, data)?;
        }
        None => {
            let (stored, compressed) = stored_name(&name_units);
            let cell = storage.allocate(0x14 + stored.len() as u32)?;
            storage.write_cell(cell, 0x14, &stored);
            let value = value_at(storage.cell(cell, 0x14)?);
            value.signature.set(VK);
            value.name_length.set(stored.len() as u16);
            value.flags.set(if compressed { VALUE_COMP_NAME } else { 0 });
            store_value_data(storage, cell, value_type, data)?;
            let key = node(storage, key_cell)?;
            let count = key.value_list.count.get();
            let list = key.value_list.list.get();
            let entries = count + 1;
            let capacity = if entries < 100 { entries } else { entries.div_ceil(100) * 100 };
            let list = if list == HCELL_NIL { storage.allocate(capacity * 4)? } else { storage.reallocate(list, capacity * 4)? };
            storage.write_cell(list, count * 4, &cell.to_le_bytes());
            let key = node(storage, key_cell)?;
            key.value_list.list.set(list);
            key.value_list.count.set(entries);
        }
    }
    let key = node(storage, key_cell)?;
    raise(&key.max_value_name_len, name_units.len() as u32 * 2);
    raise(&key.max_value_data_len, data.len() as u32);
    key.last_write_time.quad_part.set(time as i64);
    storage.mark_cell_dirty(key_cell);
    Some(())
}

/// CmDeleteValueKey sobre a hive. `None` quando o valor não existe.
pub fn delete_value(storage: &mut Storage, key_cell: u32, name: &str, time: u64) -> Option<()> {
    let name_units = units(name);
    let key = node(storage, key_cell)?;
    let (position, cell) = find_value(storage, key, &name_units)?;
    let mut cells = value_cells(storage, key)?;
    cells.remove(position);
    let value = vk(storage, cell)?;
    let (length, field) = (value.data_length.get(), value.data.get());
    free_data(storage, length, field);
    storage.free(cell);
    let list = key.value_list.list.get();
    if cells.is_empty() {
        storage.free(list);
        let key = node(storage, key_cell)?;
        key.value_list.list.set(HCELL_NIL);
        key.value_list.count.set(0);
    } else {
        let bytes: Vec<u8> = cells.iter().flat_map(|cell| cell.to_le_bytes()).collect();
        storage.write_cell(list, 0, &bytes);
        key.value_list.count.set(cells.len() as u32);
    }
    let key = node(storage, key_cell)?;
    key.last_write_time.quad_part.set(time as i64);
    storage.mark_cell_dirty(key_cell);
    Some(())
}

/// CmpFreeKeyByCell: uma chave sem subchaves sai da lista do pai e tem as
/// células (valores, classe, segurança e o 'nk') liberadas.
pub fn delete_key(storage: &mut Storage, key_cell: u32, time: u64) -> Option<()> {
    let key = node(storage, key_cell)?;
    if key.sub_key_counts[0].get() != 0 || key.flags.get() & KEY_NO_DELETE != 0 {
        return None;
    }
    let parent = key.parent.get();
    let parent_node = node(storage, parent)?;
    let list = parent_node.sub_key_lists[0].get();
    let new_list = index::remove(storage, list, key_cell, &|storage, child| key_name(storage, child))?;
    let parent_node = node(storage, parent)?;
    parent_node.sub_key_lists[0].set(new_list);
    parent_node.sub_key_counts[0].set(parent_node.sub_key_counts[0].get().saturating_sub(1));
    parent_node.last_write_time.quad_part.set(time as i64);
    storage.mark_cell_dirty(parent);
    let key = node(storage, key_cell)?;
    for cell in value_cells(storage, key)? {
        if let Some(value) = vk(storage, cell) {
            let (length, field) = (value.data_length.get(), value.data.get());
            free_data(storage, length, field);
        }
        storage.free(cell);
    }
    let key = node(storage, key_cell)?;
    let (values, class, security) = (key.value_list.list.get(), key.class.get(), key.security.get());
    if values != HCELL_NIL {
        storage.free(values);
    }
    if class != HCELL_NIL {
        storage.free(class);
    }
    security_cells::release(storage, security);
    storage.free(key_cell);
    Some(())
}

/// LastWriteTime de uma chave.
pub fn set_last_write_time(storage: &mut Storage, key_cell: u32, time: u64) {
    if let Some(key) = node(storage, key_cell) {
        key.last_write_time.quad_part.set(time as i64);
        storage.mark_cell_dirty(key_cell);
    }
}

/// Uma chave lida da hive.
pub struct KeyRecord {
    pub name: String,
    pub last_write_time: u64,
    pub security: Captured,
    pub values: Vec<Value>,
    pub children: Vec<u32>,
    pub flags: u16,
}

/// Lê um 'nk' com os valores, a segurança e as células das subchaves
/// (CmpCheckKey em versão de leitura: assinaturas, contagens e limites).
pub fn read_key(storage: &Storage, cell: u32) -> Result<KeyRecord, u32> {
    let key = node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let name = key_name(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let security = security_cells::read(storage, key.security.get())?;
    let children = index::enumerate(storage, key.sub_key_lists[0].get())?;
    if children.len() != key.sub_key_counts[0].get() as usize {
        return Err(STATUS_REGISTRY_CORRUPT);
    }
    let mut values = Vec::new();
    for value_cell in value_cells(storage, key).ok_or(STATUS_REGISTRY_CORRUPT)? {
        let value = vk(storage, value_cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let value_name = value_name(storage, value_cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
        values.push(Value { name: String::from_utf16_lossy(&value_name), value_type: value.type_.get(), data: read_data(storage, value)? });
    }
    Ok(KeyRecord { name: String::from_utf16_lossy(&name), last_write_time: key.last_write_time.quad_part.get() as u64, security, values, children, flags: key.flags.get() })
}

/// A célula de uma subchave pelo nome (para os testes de conferência).
pub fn find_child(storage: &Storage, key_cell: u32, name: &str) -> Option<u32> {
    let wanted = units(name);
    let key = node(storage, key_cell)?;
    index::enumerate(storage, key.sub_key_lists[0].get()).ok()?.into_iter().find(|&child| key_name(storage, child).is_some_and(|other| index::compare(&other, &wanted).is_eq()))
}

/// Célula 'vk' e campos crus de um valor (para os testes de conferência):
/// (DataLength, Data).
pub fn value_layout(storage: &Storage, key_cell: u32, name: &str) -> Option<(u32, u32)> {
    let key = node(storage, key_cell)?;
    let (_, cell) = find_value(storage, key, &units(name))?;
    let value = vk(storage, cell)?;
    Some((value.data_length.get(), value.data.get()))
}

/// A assinatura da célula de dados de um valor ('db' para dados grandes).
pub fn data_signature(storage: &Storage, cell: u32) -> Option<u16> {
    // SAFETY: a célula tem ao menos 2 bytes.
    storage.cell(cell, 2).map(|address| unsafe { Field::<u16>::at(address) }.get())
}
