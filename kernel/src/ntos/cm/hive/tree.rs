//! A árvore de chaves de uma hive em ordem de pré-ordem: a leitura de uma
//! hive carregada (CmCheckRegistry em versão de leitura) e a montagem de
//! uma hive nova a partir de uma árvore (o CmpCopyTree do CmSaveKey).
//!
//! As duas andam com pilha explícita, sem recursão: a profundidade de uma
//! hive vinda de arquivo não limita a pilha do kernel. Uma célula visitada
//! duas vezes, um 'nk' cujo Parent não é a chave que o lista ou uma raiz
//! sem KEY_HIVE_ENTRY tornam a hive corrompida.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::registry::Value;
use crate::ntos::se::inherit_descriptor::Captured;

use super::key_cells::{self, KeyRecord, KEY_HIVE_ENTRY};
use super::storage::{Storage, HCELL_NIL, STATUS_REGISTRY_CORRUPT};

/// Uma chave lida, com o índice do pai na lista (nenhum para a raiz).
pub struct FlatKey {
    pub cell: u32,
    pub parent: Option<usize>,
    pub record: KeyRecord,
}

/// Todas as chaves da hive, em pré-ordem (pai antes dos filhos, irmãos na
/// ordem da lista de subchaves).
pub fn read(storage: &Storage) -> Result<Vec<FlatKey>, u32> {
    let root = storage.root_cell();
    let mut keys: Vec<FlatKey> = Vec::new();
    let mut visited = BTreeSet::new();
    let mut stack = alloc::vec![(root, None::<usize>)];
    while let Some((cell, parent)) = stack.pop() {
        if !visited.insert(cell) {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        let record = key_cells::read_key(storage, cell)?;
        let node = key_cells::node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
        match parent {
            None if record.flags & KEY_HIVE_ENTRY == 0 => return Err(STATUS_REGISTRY_CORRUPT),
            Some(index) if node.parent.get() != keys[index].cell => return Err(STATUS_REGISTRY_CORRUPT),
            _ => {}
        }
        let index = keys.len();
        for &child in record.children.iter().rev() {
            stack.push((child, Some(index)));
        }
        keys.push(FlatKey { cell, parent, record });
    }
    Ok(keys)
}

/// Uma chave a gravar numa hive nova, em pré-ordem.
pub struct NewKey {
    pub name: String,
    pub last_write_time: u64,
    pub security: Captured,
    pub values: Vec<Value>,
    pub parent: Option<usize>,
}

/// Monta uma hive nova com as chaves (a primeira é a raiz). Devolve a hive
/// e a célula de cada chave.
pub fn build(keys: &[NewKey], minor: u32, time: u64, file_name: &str) -> Option<(Storage, Vec<u32>)> {
    let mut storage = Storage::new(minor, time, file_name);
    let mut cells: Vec<u32> = Vec::with_capacity(keys.len());
    for key in keys {
        let parent = match key.parent {
            Some(index) => *cells.get(index)?,
            None if cells.is_empty() => HCELL_NIL,
            None => return None,
        };
        let cell = key_cells::create_key(&mut storage, parent, &key.name, &key.security, time)?;
        if parent == HCELL_NIL {
            storage.set_root_cell(cell);
        }
        for value in &key.values {
            key_cells::set_value(&mut storage, cell, &value.name, value.value_type, &value.data, time)?;
        }
        cells.push(cell);
    }
    // A criação dos filhos e dos valores atualiza o LastWriteTime: a cópia
    // conserva o de cada chave de origem.
    for (key, &cell) in keys.iter().zip(&cells) {
        key_cells::set_last_write_time(&mut storage, cell, key.last_write_time);
    }
    Some((storage, cells))
}
