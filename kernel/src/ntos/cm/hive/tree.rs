//! A árvore de chaves de uma hive em pré-ordem: a conferência de uma hive
//! carregada (CmCheckRegistry em versão de leitura), o passeio que liga as
//! chaves ao namespace e a montagem de uma hive nova a partir de uma árvore
//! (o CmpCopyTree do CmSaveKey).
//!
//! Os passeios andam com pilha explícita, sem recursão: a profundidade de
//! uma hive vinda de arquivo não limita a pilha do kernel. Uma célula
//! visitada duas vezes, um 'nk' cujo Parent não é a chave que o lista, uma
//! contagem de subchaves diferente da lista ou uma raiz sem KEY_HIVE_ENTRY
//! tornam a hive corrompida.
//!
//! A conferência não copia o conteúdo das chaves: nomes, valores e classes
//! ficam nas células, que o Registro lê quando precisa (como o 19041 lê
//! pelo mapa de células). Ela lê cada célula 'sk' uma vez só e guarda o
//! descritor dela para as chaves que a usam (o CmpSecurityCache da hive).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::cm::registry::Value;
use crate::ntos::se::inherit_descriptor::Captured;

use super::key_cells::{self, KEY_HIVE_ENTRY, KEY_SYM_LINK};
use super::storage::{Storage, HCELL_NIL, STATUS_REGISTRY_CORRUPT};
use super::{index, security_cells};

/// Uma hive conferida: quantas chaves ela tem e o descritor de cada célula
/// 'sk' que as chaves usam, pela célula.
pub struct Checked {
    pub keys: usize,
    pub security: BTreeMap<u32, Arc<Captured>>,
}

impl Checked {
    /// O descritor compartilhado da célula 'sk' `cell`.
    pub fn descriptor(&self, cell: u32) -> Option<Arc<Captured>> {
        self.security.get(&cell).cloned()
    }
}

/// Visita as chaves em pré-ordem (pai antes dos filhos, irmãos na ordem da
/// lista de subchaves). `visit(célula, ficha do pai)` devolve a ficha da
/// chave, que vai para os filhos dela; a raiz recebe `None`. A lista de
/// cada chave precisa ter SubKeyCounts[Stable] entradas.
pub fn preorder<T: Copy>(storage: &Storage, visit: impl FnMut(u32, Option<T>) -> Result<T, u32>) -> Result<(), u32> {
    preorder_from(storage, storage.root_cell(), visit)
}

/// [`preorder`] da subárvore da chave da célula `start`.
pub fn preorder_from<T: Copy>(storage: &Storage, start: u32, mut visit: impl FnMut(u32, Option<T>) -> Result<T, u32>) -> Result<(), u32> {
    let mut stack: Vec<(u32, Option<T>)> = alloc::vec![(start, None)];
    while let Some((cell, parent)) = stack.pop() {
        let token = visit(cell, parent)?;
        let node = key_cells::node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
        let children = index::enumerate(storage, node.sub_key_lists[0].get())?;
        if children.len() != node.sub_key_counts[0].get() as usize {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        stack.extend(children.iter().rev().map(|&child| (child, Some(token))));
    }
    Ok(())
}

/// Confere a hive inteira (CmpCheckKey de cada chave: assinaturas, nomes,
/// listas, valores com os dados, classe e descritor) sem copiar o conteúdo.
pub fn check(storage: &Storage) -> Result<Checked, u32> {
    // Uma marca por célula (os índices são múltiplos de 8).
    let mut visited: Vec<u64> = alloc::vec![0; (storage.length() as usize / 8).div_ceil(64)];
    let mut checked = Checked { keys: 0, security: BTreeMap::new() };
    preorder(storage, |cell, parent: Option<u32>| {
        let slot = (cell / 8) as usize;
        let mark = visited.get_mut(slot / 64).ok_or(STATUS_REGISTRY_CORRUPT)?;
        if *mark & (1 << (slot % 64)) != 0 {
            return Err(STATUS_REGISTRY_CORRUPT);
        }
        *mark |= 1 << (slot % 64);
        let node = key_cells::node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
        match parent {
            None if node.flags.get() & KEY_HIVE_ENTRY == 0 => return Err(STATUS_REGISTRY_CORRUPT),
            Some(parent) if node.parent.get() != parent => return Err(STATUS_REGISTRY_CORRUPT),
            _ => {}
        }
        key_cells::check_key(storage, cell)?;
        let security = node.security.get();
        if !checked.security.contains_key(&security) {
            checked.security.insert(security, Arc::new(security_cells::read(storage, security)?));
        }
        checked.keys += 1;
        Ok(cell)
    })?;
    Ok(checked)
}

/// Todas as chaves de uma hive conferida, copiadas (nome, valores, classe,
/// descritor e LastWriteTime), em pré-ordem: para as cópias que montam
/// outra hive (a reorganização da carga e o REG_WHOLE_HIVE_VOLATILE).
pub fn records(storage: &Storage, checked: &Checked) -> Result<Vec<NewKey>, u32> {
    let mut keys: Vec<NewKey> = Vec::with_capacity(checked.keys);
    preorder(storage, |cell, parent: Option<usize>| {
        keys.push(record(storage, checked, cell, parent)?);
        Ok(keys.len() - 1)
    })?;
    Ok(keys)
}

/// A cópia de uma chave conferida, com o índice do pai na lista.
pub fn record(storage: &Storage, checked: &Checked, cell: u32, parent: Option<usize>) -> Result<NewKey, u32> {
    let node = key_cells::node(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let name = key_cells::key_name_units(storage, cell).ok_or(STATUS_REGISTRY_CORRUPT)?.to_string_lossy();
    let security = checked.descriptor(node.security.get()).ok_or(STATUS_REGISTRY_CORRUPT)?;
    let count = key_cells::value_count(storage, cell);
    let mut values = Vec::with_capacity(count as usize);
    for index in 0..count {
        values.push(key_cells::value_cell(storage, cell, index).and_then(|value| key_cells::read_value(storage, value)).ok_or(STATUS_REGISTRY_CORRUPT)?);
    }
    Ok(NewKey { name, last_write_time: key_cells::last_write_time(storage, cell), security: Captured::clone(&security), values, parent, link: node.flags.get() & KEY_SYM_LINK != 0, class: key_cells::class_units(storage, cell) })
}

/// Uma chave a gravar numa hive nova, em pré-ordem.
pub struct NewKey {
    pub name: String,
    pub last_write_time: u64,
    pub security: Captured,
    pub values: Vec<Value>,
    pub parent: Option<usize>,
    /// Chave de link (KEY_SYM_LINK).
    pub link: bool,
    /// A classe da chave em UTF-16 (vazia sem classe).
    pub class: Vec<u16>,
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
        let cell = key_cells::create_key(&mut storage, parent, &key.name, &key.class, &key.security, time)?;
        if key.link {
            key_cells::set_key_flags(&mut storage, cell, key_cells::KEY_SYM_LINK);
        }
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
