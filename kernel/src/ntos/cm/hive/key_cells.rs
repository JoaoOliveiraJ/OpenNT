//! Células de chave e de valor de uma hive ('nk', 'vk', dados e 'db').
//!
//! As operações que o Cm faz sobre a hive quando uma chave muda, como no
//! ntoskrnl 19041:
//! - criação (CmpDoCreateChild / CmpCreateHiveRootCell, rva 0x78da10): 'nk'
//!   com o nome comprimido em bytes quando todos os caracteres cabem em 8
//!   bits (CmpCopyName, rva 0x657770, flag KEY_COMP_NAME), listas nil, a
//!   classe numa célula própria com os bytes do UNICODE_STRING (ClassLength
//!   em bytes, sem terminador, e o MaxClassLen do pai acompanha; sem classe,
//!   Class nil), a célula de segurança e a entrada na lista de subchaves do
//!   pai; a raiz leva KEY_HIVE_ENTRY | KEY_NO_DELETE e pai nil;
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
//!
//! As leituras (nome, valores, classe e LastWriteTime de uma chave) vêm
//! direto das células, sem cópia do nome: o Registro não guarda outra cópia
//! do conteúdo de uma hive (o HvpGetCellPaged e o CmpFindValueByName do
//! 19041).

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

/// O nome guardado numa célula ('nk' ou 'vk'), em caracteres UTF-16: um
/// byte por caractere num nome comprimido, pares little-endian no outro.
#[derive(Clone, Copy)]
pub struct Units<'a> {
    bytes: &'a [u8],
    compressed: bool,
}

impl<'a> Units<'a> {
    /// Caracteres UTF-16 do nome.
    pub fn len(&self) -> usize {
        if self.compressed { self.bytes.len() } else { self.bytes.len() / 2 }
    }

    pub fn iter(&self) -> UnitIter<'a> {
        UnitIter { bytes: self.bytes, compressed: self.compressed, at: 0 }
    }

    pub fn to_vec(&self) -> Vec<u16> {
        self.iter().collect()
    }

    /// O nome como texto (um substituto no lugar de cada surrogate solto,
    /// como o `String::from_utf16_lossy`).
    pub fn to_string_lossy(&self) -> String {
        char::decode_utf16(self.iter()).map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
    }
}

/// Os caracteres de [`Units`] em ordem.
#[derive(Clone)]
pub struct UnitIter<'a> {
    bytes: &'a [u8],
    compressed: bool,
    at: usize,
}

impl Iterator for UnitIter<'_> {
    type Item = u16;

    fn next(&mut self) -> Option<u16> {
        if self.compressed {
            let byte = *self.bytes.get(self.at)?;
            self.at += 1;
            Some(byte as u16)
        } else {
            let pair = self.bytes.get(self.at..self.at + 2)?;
            self.at += 2;
            Some(u16::from_le_bytes([pair[0], pair[1]]))
        }
    }
}

/// O nome de uma chave, lido da célula.
pub fn key_name_units(storage: &Storage, cell: u32) -> Option<Units<'_>> {
    let node = node(storage, cell)?;
    let bytes = storage.cell_bytes(cell, 0x4c + node.name_length.get() as u32)?;
    Some(Units { bytes: &bytes[0x4c..], compressed: node.flags.get() & KEY_COMP_NAME != 0 })
}

/// O nome de uma chave em UTF-16.
pub fn key_name(storage: &Storage, cell: u32) -> Option<Vec<u16>> {
    key_name_units(storage, cell).map(|units| units.to_vec())
}

/// O nome de um valor, lido da célula 'vk'.
pub fn value_name_units(storage: &Storage, cell: u32) -> Option<Units<'_>> {
    let value = vk(storage, cell)?;
    let bytes = storage.cell_bytes(cell, 0x14 + value.name_length.get() as u32)?;
    Some(Units { bytes: &bytes[0x14..], compressed: value.flags.get() & VALUE_COMP_NAME != 0 })
}

fn value_name(storage: &Storage, cell: u32) -> Option<Vec<u16>> {
    value_name_units(storage, cell).map(|units| units.to_vec())
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

/// Liga bits de Flags de um 'nk' (KEY_SYM_LINK de uma chave de link, como
/// o CmpDoCreateChild com REG_OPTION_CREATE_LINK).
pub fn set_key_flags(storage: &mut Storage, cell: u32, flags: u16) {
    if let Some(key) = node(storage, cell) {
        key.flags.set(key.flags.get() | flags);
        storage.mark_cell_dirty(cell);
    }
}

/// Cria um 'nk' com a classe `class` (UTF-16, vazia = sem classe). `parent`
/// nil cria a raiz da hive.
pub fn create_key(storage: &mut Storage, parent: u32, name: &str, class: &[u16], security: &Captured, time: u64) -> Option<u32> {
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
    if !class.is_empty() {
        let bytes: Vec<u8> = class.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let class_cell = storage.allocate(bytes.len() as u32)?;
        storage.write_cell(class_cell, 0, &bytes);
        let key = node_at(storage.cell(cell, 0x4c)?);
        key.class.set(class_cell);
        key.class_length.set(bytes.len() as u16);
    }
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
        raise(&parent_node.max_class_len, class.len() as u32 * 2);
        parent_node.last_write_time.quad_part.set(time as i64);
        storage.mark_cell_dirty(parent);
    }
    storage.mark_cell_dirty(cell);
    Some(cell)
}

/// Os trechos do dado de um valor em ordem, sem cópia: o campo Data (até
/// 4 bytes, CM_KEY_VALUE_SPECIAL_SIZE), a célula de dados ou os segmentos
/// de uma célula 'db'. Um dado que não cabe nas células é
/// STATUS_REGISTRY_CORRUPT.
fn data_chunks(storage: &Storage, value: &CmKeyValue, mut chunk: impl FnMut(&[u8])) -> Result<(), u32> {
    let length = value.data_length.get();
    if length & SPECIAL_SIZE != 0 {
        let length = length & !SPECIAL_SIZE;
        if length > 4 {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        chunk(&value.data.get().to_le_bytes()[..length as usize]);
        return Ok(());
    }
    let cell = value.data.get();
    if length == 0 {
        return Ok(());
    }
    if storage.minor() >= 4 && length > BIG_SEGMENT {
        let address = storage.cell(cell, 8).ok_or(STATUS_REGISTRY_CORRUPT)?;
        // SAFETY: célula 'db' alocada (assinatura conferida a seguir).
        let big = unsafe { CmBigData::at(address) };
        let count = big.count.get() as u32;
        if big.signature.get() != DB || count == 0 || count.saturating_mul(BIG_SEGMENT) < length {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        let list = storage.cell_bytes(big.list.get(), count * 4).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let mut taken = 0u32;
        for segment in list.chunks_exact(4) {
            let segment = u32::from_le_bytes([segment[0], segment[1], segment[2], segment[3]]);
            let take = (length - taken).min(BIG_SEGMENT);
            chunk(storage.cell_bytes(segment, take).ok_or(STATUS_REGISTRY_CORRUPT)?);
            taken += take;
            if taken == length {
                break;
            }
        }
        return Ok(());
    }
    chunk(storage.cell_bytes(cell, length).ok_or(STATUS_REGISTRY_CORRUPT)?);
    Ok(())
}

/// O dado de um valor.
fn read_data(storage: &Storage, value: &CmKeyValue) -> Result<Vec<u8>, u32> {
    let mut data = Vec::with_capacity((value.data_length.get() & !SPECIAL_SIZE) as usize);
    data_chunks(storage, value, |bytes| data.extend_from_slice(bytes))?;
    Ok(data)
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
    let key = node(storage, key_cell)?;
    let existing = find_value(storage, key, &units(name)).map(|(_, cell)| cell);
    set_value_at(storage, key_cell, existing, name, value_type, data, time)
}

/// [`set_value`] com o valor já procurado: `existing` é a célula 'vk' do
/// valor com esse nome (o dado dela é trocado), ou nenhuma para um 'vk' novo
/// no fim da lista.
pub fn set_value_at(storage: &mut Storage, key_cell: u32, existing: Option<u32>, name: &str, value_type: u32, data: &[u8], time: u64) -> Option<()> {
    let name_units = units(name);
    node(storage, key_cell)?;
    match existing {
        Some(cell) => {
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
    let key = node(storage, key_cell)?;
    let (_, cell) = find_value(storage, key, &units(name))?;
    delete_value_at(storage, key_cell, cell, time)
}

/// [`delete_value`] do valor da célula 'vk' `cell` da chave.
pub fn delete_value_at(storage: &mut Storage, key_cell: u32, cell: u32, time: u64) -> Option<()> {
    let key = node(storage, key_cell)?;
    let mut cells = value_cells(storage, key)?;
    let position = cells.iter().position(|&candidate| candidate == cell)?;
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

/// O descritor de uma chave troca (CmpSetSecurityDescriptorInfo): a
/// célula 'sk' com esses bytes (a que já existe na lista, com a contagem
/// incrementada, ou uma nova depois da atual), e a antiga perde a
/// referência (a última a libera). Devolve a célula nova.
pub fn set_security(storage: &mut Storage, key_cell: u32, security: &Captured) -> Option<u32> {
    let old = node(storage, key_cell)?.security.get();
    let root = root_security(storage);
    let new = security_cells::assign(storage, old, root, security)?;
    security_cells::release(storage, old);
    node(storage, key_cell)?.security.set(new);
    storage.mark_cell_dirty(key_cell);
    Some(new)
}

/// A célula 'sk' de uma chave.
pub fn security_cell(storage: &Storage, key_cell: u32) -> Option<u32> {
    node(storage, key_cell).map(|key| key.security.get())
}

/// O tamanho em bytes de UTF-16 do nome guardado de uma chave.
pub fn name_length(storage: &Storage, key_cell: u32) -> u32 {
    key_name_units(storage, key_cell).map_or(0, |units| units.len() as u32 * 2)
}

/// Os máximos que o 'nk' guarda (MaxNameLen, MaxClassLen, MaxValueNameLen
/// e MaxValueDataLen): os maiores comprimentos que a chave já teve.
pub fn maxima(storage: &Storage, key_cell: u32) -> (u32, u32, u32, u32) {
    node(storage, key_cell).map_or((0, 0, 0, 0), |key| (key.max_name_len(), key.max_class_len.get(), key.max_value_name_len.get(), key.max_value_data_len.get()))
}

/// A subchave de nome `name` (CmpFindSubKeyByName sobre a lista estável).
pub fn find_subkey(storage: &Storage, key_cell: u32, name: &[u16]) -> Option<u32> {
    let list = node(storage, key_cell)?.sub_key_lists[0].get();
    index::find(storage, list, &|child| key_name_units(storage, child).map(|units| index::compare_units(units.iter(), name)))
}

/// A subchave `index` na ordem da lista estável (CmpFindSubKeyByNumber).
pub fn nth_subkey(storage: &Storage, key_cell: u32, index: usize) -> Option<u32> {
    index::nth(storage, node(storage, key_cell)?.sub_key_lists[0].get(), index)
}

/// LastWriteTime de uma chave.
pub fn set_last_write_time(storage: &mut Storage, key_cell: u32, time: u64) {
    if let Some(key) = node(storage, key_cell) {
        key.last_write_time.quad_part.set(time as i64);
        storage.mark_cell_dirty(key_cell);
    }
}

/// CmpCheckKey em versão de leitura, sem copiar nada: o nome, a lista de
/// valores com cada 'vk', o nome e o dado dele, e a classe cabem nas
/// células. A lista de subchaves e o descritor ficam com o passeio
/// (`tree::check`).
pub fn check_key(storage: &Storage, cell: u32) -> Result<(), u32> {
    let key = node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    key_name_units(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let count = key.value_list.count.get();
    if count != 0 {
        let length = count.checked_mul(4).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let list = storage.cell_bytes(key.value_list.list.get(), length).ok_or(STATUS_REGISTRY_CORRUPT)?;
        for entry in list.chunks_exact(4) {
            let value_cell = u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]);
            let value = vk(storage, value_cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
            value_name_units(storage, value_cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
            data_chunks(storage, value, |_| {})?;
        }
    }
    match (key.class.get(), key.class_length.get() as u32) {
        (HCELL_NIL, _) | (_, 0) => Ok(()),
        (class, length) => storage.cell_bytes(class, length).map(|_| ()).ok_or(STATUS_REGISTRY_CORRUPT),
    }
}

/// Os valores de uma chave (o ValueList.Count).
pub fn value_count(storage: &Storage, key_cell: u32) -> u32 {
    node(storage, key_cell).map_or(0, |key| key.value_list.count.get())
}

/// A célula 'vk' do valor `index` de uma chave, na ordem da lista.
pub fn value_cell(storage: &Storage, key_cell: u32, index: u32) -> Option<u32> {
    let key = node(storage, key_cell)?;
    if index >= key.value_list.count.get() {
        return None;
    }
    let entry = storage.cell_bytes(key.value_list.list.get(), (index + 1) * 4)?;
    let at = index as usize * 4;
    Some(u32::from_le_bytes([entry[at], entry[at + 1], entry[at + 2], entry[at + 3]]))
}

/// A primeira célula 'vk' de uma chave cujo nome satisfaz `matches`.
pub fn find_value_cell(storage: &Storage, key_cell: u32, matches: impl Fn(Units) -> bool) -> Option<u32> {
    (0..value_count(storage, key_cell)).filter_map(|index| value_cell(storage, key_cell, index)).find(|&cell| value_name_units(storage, cell).is_some_and(&matches))
}

/// A cópia de um valor (nome, tipo e dado) de uma célula 'vk'.
pub fn read_value(storage: &Storage, cell: u32) -> Option<Value> {
    let value = vk(storage, cell)?;
    let name = value_name_units(storage, cell)?.to_string_lossy();
    Some(Value { name, value_type: value.type_.get(), data: read_data(storage, value).ok()? })
}

/// O tamanho do nome (bytes de UTF-16) e o do dado de um valor.
pub fn value_sizes(storage: &Storage, cell: u32) -> Option<(u32, u32)> {
    let value = vk(storage, cell)?;
    let name = value_name_units(storage, cell)?.len() as u32 * 2;
    Some((name, value.data_length.get() & !SPECIAL_SIZE))
}

/// A classe de uma chave em UTF-16 (vazia sem classe).
pub fn class_units(storage: &Storage, key_cell: u32) -> Vec<u16> {
    let Some(key) = node(storage, key_cell) else { return Vec::new() };
    match (key.class.get(), key.class_length.get() as u32) {
        (HCELL_NIL, _) | (_, 0) => Vec::new(),
        (cell, length) => storage.cell_bytes(cell, length).map_or(Vec::new(), |bytes| bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()),
    }
}

/// O tamanho em bytes da classe de uma chave (o que [`class_units`] lê).
pub fn class_length(storage: &Storage, key_cell: u32) -> u32 {
    let Some(key) = node(storage, key_cell) else { return 0 };
    match (key.class.get(), key.class_length.get() as u32) {
        (HCELL_NIL, _) | (_, 0) => 0,
        (cell, length) => storage.cell_bytes(cell, length).map_or(0, |_| length & !1),
    }
}

/// LastWriteTime de uma chave.
pub fn last_write_time(storage: &Storage, key_cell: u32) -> u64 {
    node(storage, key_cell).map_or(0, |key| key.last_write_time.quad_part.get() as u64)
}

/// SubKeyCounts[Stable] de uma chave.
pub fn sub_key_count(storage: &Storage, key_cell: u32) -> u32 {
    node(storage, key_cell).map_or(0, |key| key.sub_key_counts[0].get())
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
