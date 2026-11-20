//! Listas de subchaves de uma hive (o cmindex do NT): 'li', 'lf', 'lh' e
//! 'ri'.
//!
//! Como no ntoskrnl 19041:
//! - a lista começa com uma folha 'lh' nas hives de versão 5 ou mais e com
//!   uma 'lf' nas anteriores (CmpAddSubKeyEx, rva 0x6e18f4); uma folha com
//!   1013 entradas vira filha de uma raiz 'ri';
//! - a entrada de 'lh' leva o hash do nome, h = h * 37 + NLS_UPCASE(c)
//!   (CmpHashUnicodeComponent, rva 0x6e2f34); a de 'lf', os quatro
//!   primeiros caracteres em bytes quando todos cabem em 8 bits, senão zero
//!   (CmpGenerateFastLeafHintForUnicodeString, rva 0x692dd4);
//! - as entradas ficam em ordem pelo nome comparado sem caixa.

use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::ntos::inc::types::{CmIndex, CmKeyIndex};
use crate::ntos::inc::types::NtStruct;
use crate::ntos::inc::field::Field;
use crate::ntos::rtl::unicode_case;

use super::storage::{Storage, HCELL_NIL, STATUS_REGISTRY_CORRUPT};

pub const LI: u16 = 0x696c;
pub const LF: u16 = 0x666c;
pub const LH: u16 = 0x686c;
pub const RI: u16 = 0x6972;

/// Entradas de uma folha antes de ela ir para baixo de uma 'ri'.
const MAX_LEAF: usize = 1012;

/// CmpHashUnicodeComponent.
pub fn hash(name: &[u16]) -> u32 {
    name.iter().fold(0u32, |hash, &unit| hash.wrapping_mul(37).wrapping_add(unicode_case::nls_upcase(unit) as u32))
}

/// CmpGenerateFastLeafHintForUnicodeString.
pub fn hint(name: &[u16]) -> u32 {
    let mut bytes = [0u8; 4];
    for (index, &unit) in name.iter().take(4).enumerate() {
        if unit > 0xFF {
            return 0;
        }
        bytes[index] = unit as u8;
    }
    u32::from_le_bytes(bytes)
}

/// Comparação de nomes sem caixa (a ordem das folhas).
pub fn compare(left: &[u16], right: &[u16]) -> Ordering {
    left.iter().map(|&unit| unicode_case::nls_upcase(unit)).cmp(right.iter().map(|&unit| unicode_case::nls_upcase(unit)))
}

fn index_at(address: u64) -> &'static CmKeyIndex {
    // SAFETY: dados de uma célula alocada da hive com pelo menos 4 bytes.
    unsafe { CmKeyIndex::at(address) }
}

/// As células de chave de uma folha ('li', 'lf' ou 'lh'), em ordem.
fn leaf_cells(storage: &Storage, cell: u32) -> Result<(u16, Vec<u32>), u32> {
    let address = storage.cell(cell, 4).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let header = index_at(address);
    let (signature, count) = (header.signature.get(), header.count.get() as usize);
    let entry = if signature == LI { 4 } else if signature == LF || signature == LH { 8 } else { return Err(STATUS_REGISTRY_CORRUPT) };
    storage.cell(cell, 4 + (count * entry) as u32).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let cells = if signature == LI {
        // SAFETY: `count` entradas de 4 bytes conferidas acima.
        unsafe { Field::<u32>::array_at(address + 4, count) }.iter().map(|entry| entry.get()).collect()
    } else {
        // SAFETY: `count` entradas de 8 bytes conferidas acima.
        unsafe { CmIndex::array_at(address + 4, count) }.iter().map(|entry| entry.cell.get()).collect()
    };
    Ok((signature, cells))
}

/// Uma folha conferida: a assinatura, as entradas e o endereço delas.
fn leaf_header(storage: &Storage, cell: u32) -> Option<(u16, usize, u64)> {
    let address = storage.cell(cell, 4)?;
    let header = index_at(address);
    let (signature, count) = (header.signature.get(), header.count.get() as usize);
    let entry = match signature {
        LI => 4,
        LF | LH => 8,
        _ => return None,
    };
    storage.cell(cell, 4 + (count * entry) as u32)?;
    Some((signature, count, address + 4))
}

/// A célula da entrada `index` de uma folha.
fn leaf_entry(storage: &Storage, leaf: u32, index: usize) -> Option<u32> {
    let (signature, count, entries) = leaf_header(storage, leaf)?;
    if index >= count {
        return None;
    }
    if signature == LI {
        // SAFETY: entrada `index` dentro da folha conferida.
        Some(unsafe { Field::<u32>::at(entries + index as u64 * 4) }.get())
    } else {
        // SAFETY: idem, entrada de 8 bytes.
        Some(unsafe { CmIndex::at(entries + index as u64 * 8) }.cell.get())
    }
}

/// As folhas de uma lista: a própria lista, ou as filhas de uma 'ri'.
fn leaves(storage: &Storage, list: u32) -> Option<Vec<u32>> {
    let address = storage.cell(list, 4)?;
    let header = index_at(address);
    if header.signature.get() != RI {
        return Some(alloc::vec![list]);
    }
    let count = header.count.get() as usize;
    storage.cell(list, 4 + 4 * count as u32)?;
    // SAFETY: `count` células de folha conferidas acima.
    Some(unsafe { Field::<u32>::array_at(address + 4, count) }.iter().map(|entry| entry.get()).collect())
}

/// CmpFindSubKeyByName: a subchave de uma lista cujo nome `compare` diz
/// igual, pela busca binária nas folhas (as entradas estão em ordem de nome
/// sem caixa). `compare(célula)` compara o nome da subchave com o procurado.
/// Numa 'ri', a folha é a primeira cuja última entrada não é menor que o
/// nome (CmpFindSubKeyInRoot).
pub fn find(storage: &Storage, list: u32, compare: &dyn Fn(u32) -> Option<Ordering>) -> Option<u32> {
    if list == HCELL_NIL {
        return None;
    }
    for leaf in leaves(storage, list)? {
        let (_, count, _) = leaf_header(storage, leaf)?;
        if count == 0 || compare(leaf_entry(storage, leaf, count - 1)?)? == Ordering::Less {
            continue;
        }
        let (mut low, mut high) = (0, count);
        while low < high {
            let middle = (low + high) / 2;
            let cell = leaf_entry(storage, leaf, middle)?;
            match compare(cell)? {
                Ordering::Less => low = middle + 1,
                Ordering::Greater => high = middle,
                Ordering::Equal => return Some(cell),
            }
        }
        return None;
    }
    None
}

/// CmpFindSubKeyByNumber: a subchave `index` de uma lista, na ordem dela.
pub fn nth(storage: &Storage, list: u32, mut index: usize) -> Option<u32> {
    if list == HCELL_NIL {
        return None;
    }
    for leaf in leaves(storage, list)? {
        let (_, count, _) = leaf_header(storage, leaf)?;
        if index < count {
            return leaf_entry(storage, leaf, index);
        }
        index -= count;
    }
    None
}

/// Comparação sem caixa de um nome em caracteres UTF-16 com outro (a
/// ordem das folhas), sem copiar o primeiro.
pub fn compare_units(left: impl Iterator<Item = u16>, right: &[u16]) -> Ordering {
    left.map(unicode_case::nls_upcase).cmp(right.iter().map(|&unit| unicode_case::nls_upcase(unit)))
}

/// Todas as subchaves de uma lista (folha ou 'ri'), em ordem.
pub fn enumerate(storage: &Storage, list: u32) -> Result<Vec<u32>, u32> {
    if list == HCELL_NIL {
        return Ok(Vec::new());
    }
    let address = storage.cell(list, 4).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let header = index_at(address);
    if header.signature.get() != RI {
        return Ok(leaf_cells(storage, list)?.1);
    }
    let count = header.count.get() as usize;
    storage.cell(list, 4 + 4 * count as u32).ok_or(STATUS_REGISTRY_CORRUPT)?;
    // SAFETY: `count` células de folha conferidas acima.
    let leaves: Vec<u32> = unsafe { Field::<u32>::array_at(address + 4, count) }.iter().map(|entry| entry.get()).collect();
    let mut cells = Vec::new();
    for leaf in leaves {
        cells.extend(leaf_cells(storage, leaf)?.1);
    }
    Ok(cells)
}

/// Uma entrada a gravar: célula e nome da subchave.
pub struct Entry<'a> {
    pub cell: u32,
    pub name: &'a [u16],
}

/// Grava uma folha nova com as entradas (já em ordem).
fn write_leaf(storage: &mut Storage, signature: u16, entries: &[Entry]) -> Option<u32> {
    let entry_size = if signature == LI { 4 } else { 8 };
    let cell = storage.allocate(4 + (entries.len() as u32) * entry_size)?;
    let address = storage.cell(cell, 4)?;
    let header = index_at(address);
    header.signature.set(signature);
    header.count.set(entries.len() as u16);
    for (index, entry) in entries.iter().enumerate() {
        if signature == LI {
            // SAFETY: entrada `index` dentro da célula alocada acima.
            unsafe { Field::<u32>::at(address + 4 + index as u64 * 4) }.set(entry.cell);
        } else {
            // SAFETY: idem, entrada de 8 bytes.
            let slot = unsafe { CmIndex::at(address + 4 + index as u64 * 8) };
            slot.cell.set(entry.cell);
            slot.hash_key.hash.set(if signature == LH { hash(entry.name) } else { hint(entry.name) });
        }
    }
    Some(cell)
}

/// Libera a estrutura da lista (folhas e 'ri'), sem as chaves.
pub fn free_list(storage: &mut Storage, list: u32) {
    if list == HCELL_NIL {
        return;
    }
    if let Some(address) = storage.cell(list, 4) {
        let header = index_at(address);
        if header.signature.get() == RI {
            let count = header.count.get() as usize;
            if storage.cell(list, 4 + 4 * count as u32).is_some() {
                // SAFETY: `count` células de folha conferidas acima.
                let leaves: Vec<u32> = unsafe { Field::<u32>::array_at(address + 4, count) }.iter().map(|entry| entry.get()).collect();
                for leaf in leaves {
                    storage.free(leaf);
                }
            }
        }
    }
    storage.free(list);
}

/// Monta a lista inteira para as entradas (já em ordem): uma folha até
/// 1012 entradas, senão uma 'ri' com folhas de até 1012.
pub fn build(storage: &mut Storage, entries: &[Entry]) -> Option<u32> {
    if entries.is_empty() {
        return Some(HCELL_NIL);
    }
    let signature = if storage.minor() >= 5 { LH } else { LF };
    if entries.len() <= MAX_LEAF {
        return write_leaf(storage, signature, entries);
    }
    let leaves: Option<Vec<u32>> = entries.chunks(MAX_LEAF).map(|chunk| write_leaf(storage, signature, chunk)).collect();
    let leaves = leaves?;
    let root = storage.allocate(4 + 4 * leaves.len() as u32)?;
    let address = storage.cell(root, 4)?;
    let header = index_at(address);
    header.signature.set(RI);
    header.count.set(leaves.len() as u16);
    for (index, leaf) in leaves.iter().enumerate() {
        // SAFETY: entrada `index` da 'ri' alocada acima.
        unsafe { Field::<u32>::at(address + 4 + index as u64 * 4) }.set(*leaf);
    }
    Some(root)
}

/// CmpAddSubKey: insere a subchave na posição pela ordem dos nomes. Numa
/// folha única com espaço, realoca a própria folha e desloca as entradas
/// (CmpAddToLeaf); senão remonta a lista.
pub fn add(storage: &mut Storage, list: u32, cell: u32, name: &[u16], names: &dyn Fn(&Storage, u32) -> Option<Vec<u16>>) -> Option<u32> {
    let existing = enumerate(storage, list).ok()?;
    let mut keyed: Vec<(u32, Vec<u16>)> = Vec::with_capacity(existing.len() + 1);
    for child in existing {
        keyed.push((child, names(storage, child)?));
    }
    let position = keyed.partition_point(|(_, other)| compare(other, name) == Ordering::Less);
    if list != HCELL_NIL && keyed.len() < MAX_LEAF {
        let address = storage.cell(list, 4)?;
        let signature = index_at(address).signature.get();
        if signature != RI {
            let entry_size: u32 = if signature == LI { 4 } else { 8 };
            let count = keyed.len() as u32;
            let leaf = storage.reallocate(list, 4 + (count + 1) * entry_size)?;
            let address = storage.cell(leaf, 4)?;
            let tail = storage.read_cell(leaf, 4 + count * entry_size)?[(4 + position as u32 * entry_size) as usize..].to_vec();
            storage.write_cell(leaf, 4 + (position as u32 + 1) * entry_size, &tail);
            if signature == LI {
                // SAFETY: entrada nova dentro da folha realocada.
                unsafe { Field::<u32>::at(address + 4 + position as u64 * 4) }.set(cell);
            } else {
                // SAFETY: idem, entrada de 8 bytes.
                let slot = unsafe { CmIndex::at(address + 4 + position as u64 * 8) };
                slot.cell.set(cell);
                slot.hash_key.hash.set(if signature == LH { hash(name) } else { hint(name) });
            }
            index_at(address).count.set(count as u16 + 1);
            storage.mark_cell_dirty(leaf);
            return Some(leaf);
        }
    }
    keyed.insert(position, (cell, name.to_vec()));
    let entries: Vec<Entry> = keyed.iter().map(|(cell, name)| Entry { cell: *cell, name }).collect();
    let rebuilt = build(storage, &entries)?;
    free_list(storage, list);
    Some(rebuilt)
}

/// CmpRemoveSubKey: tira a subchave da lista; a lista vazia é liberada e
/// vira nil.
pub fn remove(storage: &mut Storage, list: u32, cell: u32, names: &dyn Fn(&Storage, u32) -> Option<Vec<u16>>) -> Option<u32> {
    let existing = enumerate(storage, list).ok()?;
    let position = existing.iter().position(|&child| child == cell)?;
    let address = storage.cell(list, 4)?;
    let signature = index_at(address).signature.get();
    if signature != RI {
        let count = existing.len() as u32;
        if count == 1 {
            storage.free(list);
            return Some(HCELL_NIL);
        }
        let entry_size: u32 = if signature == LI { 4 } else { 8 };
        let tail = storage.read_cell(list, 4 + count * entry_size)?[(4 + (position as u32 + 1) * entry_size) as usize..].to_vec();
        storage.write_cell(list, 4 + position as u32 * entry_size, &tail);
        index_at(address).count.set(count as u16 - 1);
        storage.mark_cell_dirty(list);
        return Some(list);
    }
    let mut keyed: Vec<(u32, Vec<u16>)> = Vec::with_capacity(existing.len());
    for child in existing.into_iter().filter(|&child| child != cell) {
        keyed.push((child, names(storage, child)?));
    }
    let entries: Vec<Entry> = keyed.iter().map(|(cell, name)| Entry { cell: *cell, name }).collect();
    let rebuilt = build(storage, &entries)?;
    free_list(storage, list);
    Some(rebuilt)
}

/// Assinatura de uma lista (para conferência nos testes).
pub fn signature(storage: &Storage, list: u32) -> Option<u16> {
    storage.cell(list, 4).map(|address| index_at(address).signature.get())
}
