//! O namespace do Registro do Configuration Manager.
//!
//! Árvore de chaves e valores sem diferença entre maiúsculas e minúsculas. Os
//! handles internos identificam nós e caminhos; as fronteiras de syscall
//! acrescentam direitos, captura e notificações nativas. Os nós vivem numa
//! arena e são identificados por [`NodeId`]; um nó excluído continua na arena
//! (marcado) enquanto handles antigos ainda o referenciam.
//!
//! A arena faz o papel dos KCBs com cache completo: um nó de uma hive
//! carregada de arquivo (`cm/hive_list.rs`) guarda a célula 'nk' dele, e
//! toda mudança no nó (chave criada ou excluída, valor gravado ou removido)
//! vai na mesma hora para as células da hive, sob a mesma trava, marcando os
//! setores sujos que a descarga grava. Os nós sem célula (as chaves mestras,
//! as subárvores montadas só em memória e as chaves voláteis) não têm cópia
//! em arquivo. Uma operação de célula que falha (uma hive inconsistente)
//! marca a hive como quebrada, sem desfazer a mudança do nó, e a descarga
//! dela passa a falhar.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::cm::hive::key_cells;
use crate::ntos::cm::hive::storage::Storage;
use crate::ntos::cm::hive::tree::{FlatKey, NewKey};
use crate::ntos::cm::key::policy as key_policy;
use crate::ntos::ke::clock;
use crate::ntos::ob::handle_ids;
use crate::ntos::se::inherit_descriptor::Captured;
use crate::rtl::{KernelError, SpinLock};

pub type NodeId = u64;
pub const ROOT: NodeId = 1;

/// Valor: nome preservado para exibição, tipo REG_* e bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// Nó da hive: subchaves e valores em ordem de inserção (chave = nome em
/// minúsculas) e LastWriteTime em 100 ns desde 1601.
#[derive(Clone, Debug)]
pub struct KeyNode {
    pub name: String,
    pub parent: Option<NodeId>,
    pub children: Vec<(String, NodeId)>,
    pub values: Vec<(String, Value)>,
    pub security: Captured,
    pub last_write_time: u64,
    pub deleted: bool,
    /// (hive, célula 'nk') de um nó guardado numa hive de arquivo.
    pub cell: Option<(u32, u32)>,
    /// Criado com REG_OPTION_VOLATILE (ou abaixo de uma chave volátil).
    pub volatile: bool,
}

impl KeyNode {
    pub fn child(&self, lower: &str) -> Option<NodeId> {
        self.children.iter().find(|(name, _)| name == lower).map(|&(_, id)| id)
    }

    pub fn value(&self, lower: &str) -> Option<&Value> {
        self.values.iter().find(|(name, _)| name == lower).map(|(_, value)| value)
    }
}

/// Entrada da tabela de handles internos: caminho de abertura e identidade.
#[derive(Clone, Debug)]
pub struct HandleEntry {
    pub path: String,
    pub node: NodeId,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectStatistics {
    pub objects: usize,
    pub handles: usize,
    pub peak_objects: usize,
    pub peak_handles: usize,
}

/// Integração com o ciclo de objetos do kernel, instalada pelos serviços de
/// chave depois do carregamento dos provedores.
#[derive(Clone, Copy)]
pub struct NativeHooks {
    pub close: fn(u32, fn(u32) -> bool) -> bool,
    pub remove: Option<fn(u32, &dyn Fn() -> bool) -> bool>,
    pub detach: fn(u32),
}

pub type Observer = Arc<dyn Fn(&str) + Send + Sync>;

struct Hive {
    nodes: BTreeMap<NodeId, KeyNode>,
    next_node: NodeId,
    handles: BTreeMap<u32, HandleEntry>,
    statistics: ObjectStatistics,
    /// As células das hives carregadas e o nó raiz de cada uma.
    storages: BTreeMap<u32, (Storage, NodeId)>,
}

static HIVE: SpinLock<Option<Hive>> = SpinLock::new(None);
static OBSERVERS: SpinLock<Vec<(u64, String, Observer)>> = SpinLock::new(Vec::new());
static NEXT_OBSERVER: SpinLock<u64> = SpinLock::new(1);
static HOOKS: SpinLock<Option<NativeHooks>> = SpinLock::new(None);
/// Chamado (fora das travas) depois de cada handle fechado: as descargas
/// pendentes do NtUnloadKeyEx (`hive_list`).
static CLOSE_OBSERVER: SpinLock<Option<fn()>> = SpinLock::new(None);

fn now() -> u64 {
    clock::system_time_100ns()
}

fn with_hive<T>(body: impl FnOnce(&mut Hive) -> T) -> T {
    let mut hive = HIVE.lock();
    let hive = hive.get_or_insert_with(|| {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT, KeyNode { name: String::new(), parent: None, children: Vec::new(), values: Vec::new(), security: key_policy::boot_root(), last_write_time: now(), deleted: false, cell: None, volatile: false });
        Hive { nodes, next_node: ROOT + 1, handles: BTreeMap::new(), statistics: ObjectStatistics::default(), storages: BTreeMap::new() }
    });
    body(hive)
}

/// Separa por barra invertida e ignora componentes vazios.
pub fn split_path(path: &str) -> Vec<&str> {
    path.split('\\').filter(|component| !component.is_empty()).collect()
}

fn normalized(path: &str) -> String {
    let mut text = String::from("\\");
    text.push_str(&split_path(path).join("\\").to_lowercase());
    text
}

/// Registra um observador do caminho e da subárvore; devolve o identificador
/// da inscrição para [`unwatch`].
pub fn watch(path: &str, callback: Observer) -> u64 {
    let identifier = {
        let mut next = NEXT_OBSERVER.lock();
        let identifier = *next;
        *next += 1;
        identifier
    };
    OBSERVERS.lock().push((identifier, normalized(path), callback));
    identifier
}

pub fn unwatch(identifier: u64) -> bool {
    let mut observers = OBSERVERS.lock();
    let before = observers.len();
    observers.retain(|(candidate, _, _)| *candidate != identifier);
    observers.len() != before
}

/// Notifica uma cópia da lista (inscrição e remoção durante a entrega são
/// permitidas); nenhum lock fica retido durante os callbacks.
fn notify_path_changed(path: &str) {
    let target = normalized(path);
    let observers: Vec<(String, Observer)> = OBSERVERS.lock().iter().map(|(_, path, callback)| (path.clone(), callback.clone())).collect();
    for (observed, callback) in observers {
        if target == observed || target.starts_with(&(observed.clone() + "\\")) {
            callback(path);
        }
    }
}

/// Aplica uma mudança à célula do nó na hive dele; uma falha marca a hive
/// como quebrada.
fn mirror(hive: &mut Hive, node: NodeId, change: impl FnOnce(&mut Storage, u32, u64) -> Option<()>) {
    let Some((identifier, cell)) = hive.nodes.get(&node).and_then(|key| key.cell) else { return };
    let time = hive.nodes[&node].last_write_time;
    if let Some((storage, _)) = hive.storages.get_mut(&identifier) {
        if !storage.broken && change(storage, cell, time).is_none() {
            storage.broken = true;
            crate::debug_print!("[cm] hive {}: a celula {:#x} nao acompanhou a mudanca; a descarga fica recusada", identifier, cell);
        }
    }
}

fn create_node(hive: &mut Hive, name: &str, parent: NodeId, security: Option<Captured>, volatile: bool) -> Result<NodeId, KernelError> {
    let security = match security {
        Some(security) => security,
        None => key_policy::boot_child(&hive.nodes[&parent].security)?,
    };
    let volatile = volatile || hive.nodes[&parent].volatile;
    let time = now();
    // A chave nova vai para a hive do pai, salvo se for volátil.
    let mut cell = None;
    if let Some((identifier, parent_cell)) = hive.nodes[&parent].cell.filter(|_| !volatile) {
        if let Some((storage, _)) = hive.storages.get_mut(&identifier).filter(|(storage, _)| !storage.broken) {
            match key_cells::create_key(storage, parent_cell, name, &security, time) {
                Some(created) => cell = Some((identifier, created)),
                None => {
                    storage.broken = true;
                    crate::debug_print!("[cm] hive {}: a chave {} nao coube nas celulas; a descarga fica recusada", identifier, name);
                }
            }
        }
    }
    let identifier = hive.next_node;
    hive.next_node += 1;
    hive.nodes.insert(identifier, KeyNode { name: name.to_string(), parent: Some(parent), children: Vec::new(), values: Vec::new(), security, last_write_time: time, deleted: false, cell, volatile });
    Ok(identifier)
}

/// Percorre desde a raiz, criando componentes ausentes só quando pedido.
fn walk(hive: &mut Hive, path: &str, create: bool, security: Option<Captured>, volatile: bool) -> Result<Option<NodeId>, KernelError> {
    let mut node = ROOT;
    let components = split_path(path);
    let last = components.len().saturating_sub(1);
    let mut security = security;
    for (index, component) in components.iter().enumerate() {
        let lower = component.to_lowercase();
        let existing = hive.nodes[&node].child(&lower);
        node = match existing {
            Some(child) => child,
            None if !create => return Ok(None),
            None => {
                let child = create_node(hive, component, node, if index == last { security.take() } else { None }, volatile && index == last)?;
                if let Some(parent) = hive.nodes.get_mut(&node) {
                    parent.children.push((lower, child));
                }
                child
            }
        };
    }
    Ok(Some(node))
}

fn update_statistics(hive: &mut Hive) {
    let mut distinct: Vec<NodeId> = hive.handles.values().map(|entry| entry.node).collect();
    distinct.sort_unstable();
    distinct.dedup();
    let statistics = &mut hive.statistics;
    statistics.objects = distinct.len();
    statistics.handles = hive.handles.len();
    statistics.peak_objects = statistics.peak_objects.max(statistics.objects);
    statistics.peak_handles = statistics.peak_handles.max(statistics.handles);
}

fn publish(hive: &mut Hive, path: &str, node: NodeId) -> Result<u32, KernelError> {
    let handle = handle_ids::allocate(4)?;
    hive.handles.insert(handle, HandleEntry { path: path.to_string(), node });
    update_statistics(hive);
    Ok(handle)
}

/// Nomes das subchaves em ordem de inserção.
pub fn list_keys(path: &str) -> Vec<String> {
    with_hive(|hive| match walk(hive, path, false, None, false) {
        Ok(Some(node)) => hive.nodes[&node].children.iter().map(|(_, child)| hive.nodes[child].name.clone()).collect(),
        _ => Vec::new(),
    })
}

/// Consulta interna de valor pelo caminho (cópia do registro).
pub fn read_value_by_path(path: &str, name: &str) -> Option<Value> {
    with_hive(|hive| {
        let node = walk(hive, path, false, None, false).ok()??;
        hive.nodes[&node].value(&name.to_lowercase()).cloned()
    })
}

/// Cria o caminho se necessário e publica um handle; um caminho novo
/// notifica seus observadores.
pub fn open_or_create(path: &str, security: Option<Captured>) -> Result<u32, KernelError> {
    open_or_create_options(path, security, false)
}

/// [`open_or_create`] com REG_OPTION_VOLATILE para a chave final.
pub fn open_or_create_options(path: &str, security: Option<Captured>, volatile: bool) -> Result<u32, KernelError> {
    let (handle, created) = with_hive(|hive| -> Result<(u32, bool), KernelError> {
        let existing = walk(hive, path, false, None, false)?;
        let Some(node) = walk(hive, path, true, security, volatile)? else { return Ok((0, false)) };
        Ok((publish(hive, path, node)?, existing.is_none()))
    })?;
    if created {
        notify_path_changed(path);
    }
    Ok(handle)
}

/// Abre só um nó existente; ausência devolve zero.
pub fn open(path: &str) -> Result<u32, KernelError> {
    with_hive(|hive| match walk(hive, path, false, None, false)? {
        Some(node) => publish(hive, path, node),
        None => Ok(0),
    })
}

/// Handle adicional para uma identidade já resolvida.
pub fn open_node(node: NodeId, path: &str) -> Result<u32, KernelError> {
    with_hive(|hive| publish(hive, path, node))
}

/// Nó do handle enquanto não estiver excluído.
pub fn get_node(handle: u32) -> Option<NodeId> {
    with_hive(|hive| hive.handles.get(&handle).filter(|entry| !hive.nodes[&entry.node].deleted).map(|entry| entry.node))
}

pub fn get_path(handle: u32) -> Option<String> {
    with_hive(|hive| hive.handles.get(&handle).filter(|entry| !hive.nodes[&entry.node].deleted).map(|entry| entry.path.clone()))
}

pub fn delete_key(handle: u32) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    delete_node(entry.node, &entry.path)
}

/// Exclui só nó vivo, sem filhos e com pai resolvido; a identidade fica
/// marcada para que handles antigos não a tratem como chave válida.
pub fn delete_node(node: NodeId, path: &str) -> bool {
    let removed = with_hive(|hive| {
        let Some(key) = hive.nodes.get(&node) else { return false };
        // A raiz de uma hive carregada é KEY_NO_DELETE.
        if key.deleted || !key.children.is_empty() || hive.storages.values().any(|&(_, root)| root == node) {
            return false;
        }
        let components = split_path(path);
        let Some(last) = components.last() else { return false };
        let lower = last.to_lowercase();
        let parent_path = components[..components.len() - 1].join("\\");
        let Ok(Some(parent)) = walk(hive, &parent_path, false, None, false) else { return false };
        let parent = hive.nodes.get_mut(&parent).expect("pai resolvido");
        let before = parent.children.len();
        parent.children.retain(|(name, _)| *name != lower);
        let removed = parent.children.len() != before;
        if removed {
            if let Some(key) = hive.nodes.get_mut(&node) {
                key.deleted = true;
            }
            mirror(hive, node, |storage, cell, _| key_cells::delete_key(storage, cell, now()));
        }
        removed
    });
    if removed {
        notify_path_changed(path);
    }
    removed
}

pub fn set_native_hooks(hooks: Option<NativeHooks>) {
    *HOOKS.lock() = hooks;
}

/// Delega o fechamento aos hooks nativos quando instalados; a remoção
/// efetiva continua em [`close_raw`].
pub fn close_handle(handle: u32) -> bool {
    if !with_hive(|hive| hive.handles.contains_key(&handle)) {
        return false;
    }
    let hooks = *HOOKS.lock();
    match hooks {
        Some(hooks) => (hooks.close)(handle, close_raw),
        None => close_raw(handle),
    }
}

/// Remove o handle, atualiza contadores e desassocia a identidade nativa; o
/// hook de remoção controla a exclusividade da operação.
pub fn close_raw(handle: u32) -> bool {
    if !with_hive(|hive| hive.handles.contains_key(&handle)) {
        return false;
    }
    let hooks = *HOOKS.lock();
    let detach = move || {
        let removed = with_hive(|hive| {
            let removed = hive.handles.remove(&handle).is_some();
            if removed {
                update_statistics(hive);
            }
            removed
        });
        if removed {
            if let Some(hooks) = hooks {
                (hooks.detach)(handle);
            }
            let observer = *CLOSE_OBSERVER.lock();
            if let Some(observer) = observer {
                observer();
            }
        }
        removed
    };
    match hooks.and_then(|hooks| hooks.remove) {
        Some(remove) => remove(handle, &detach),
        None => detach(),
    }
}

pub fn set_value(handle: u32, name: &str, value_type: u32, data: Vec<u8>) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    set_node_value(entry.node, &entry.path, name, value_type, data)
}

/// Grava o valor, atualiza LastWriteTime e avisa os observadores.
pub fn set_node_value(node: NodeId, path: &str, name: &str, value_type: u32, data: Vec<u8>) -> bool {
    let written = with_hive(|hive| {
        let Some(key) = hive.nodes.get_mut(&node).filter(|key| !key.deleted) else { return false };
        let lower = name.to_lowercase();
        let value = Value { name: name.to_string(), value_type, data };
        let stored = value.clone();
        match key.values.iter_mut().find(|(candidate, _)| *candidate == lower) {
            Some(slot) => slot.1 = value,
            None => key.values.push((lower, value)),
        }
        key.last_write_time = now();
        mirror(hive, node, |storage, cell, time| key_cells::set_value(storage, cell, &stored.name, stored.value_type, &stored.data, time));
        true
    });
    if written {
        notify_path_changed(path);
    }
    written
}

pub fn get_value(handle: u32, name: &str) -> Option<Value> {
    let node = get_node(handle)?;
    with_hive(|hive| hive.nodes[&node].value(&name.to_lowercase()).cloned())
}

pub fn delete_value(handle: u32, name: &str) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    delete_node_value(entry.node, &entry.path, name)
}

/// Remove um valor existente e só então atualiza o tempo e notifica.
pub fn delete_node_value(node: NodeId, path: &str, name: &str) -> bool {
    let removed = with_hive(|hive| {
        let Some(key) = hive.nodes.get_mut(&node).filter(|key| !key.deleted) else { return false };
        let lower = name.to_lowercase();
        let before = key.values.len();
        key.values.retain(|(candidate, _)| *candidate != lower);
        let removed = key.values.len() != before;
        if removed {
            key.last_write_time = now();
            mirror(hive, node, |storage, cell, time| key_cells::delete_value(storage, cell, name, time));
        }
        removed
    });
    if removed {
        notify_path_changed(path);
    }
    removed
}

pub fn node_by_path(path: &str) -> Option<NodeId> {
    with_hive(|hive| walk(hive, path, false, None, false).ok().flatten())
}

pub fn handle_entries() -> Vec<(u32, HandleEntry)> {
    with_hive(|hive| hive.handles.iter().map(|(&handle, entry)| (handle, entry.clone())).collect())
}

pub fn handle_entry(handle: u32) -> Option<HandleEntry> {
    with_hive(|hive| hive.handles.get(&handle).cloned())
}

pub fn object_stats() -> ObjectStatistics {
    with_hive(|hive| hive.statistics)
}

/// Lê um nó da arena (sem chamar o registro de dentro da closure).
pub fn with_node<T>(node: NodeId, body: impl FnOnce(&KeyNode) -> T) -> Option<T> {
    with_hive(|hive| hive.nodes.get(&node).map(body))
}

/// Altera um nó da arena (descritor, LastWriteTime).
pub fn with_node_mut<T>(node: NodeId, body: impl FnOnce(&mut KeyNode) -> T) -> Option<T> {
    with_hive(|hive| hive.nodes.get_mut(&node).map(body))
}

/// Subchaves vivas em ordem de inserção.
pub fn children(node: NodeId) -> Vec<NodeId> {
    with_node(node, |key| key.children.iter().map(|&(_, child)| child).collect()).unwrap_or_default()
}

pub fn is_deleted(node: NodeId) -> bool {
    with_node(node, |key| key.deleted).unwrap_or(true)
}

/// REG_SZ em UTF-16 little-endian com o terminador de dois bytes.
pub fn encode_wide(text: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

// ---- hives de arquivo -------------------------------------------------------

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;

/// Liga as chaves lidas de uma hive em `path` (CmpLinkHiveToMaster): o pai
/// precisa existir e o nome não (o vínculo sobre uma chave existente é
/// STATUS_OBJECT_NAME_COLLISION, como no CmpDoParseKey com CreateLink). Em
/// falha as células voltam ao chamador.
pub fn link_hive(path: &str, identifier: u32, storage: Storage, keys: Vec<FlatKey>) -> Result<NodeId, (u32, Storage)> {
    let components = split_path(path);
    let Some((name, parents)) = components.split_last() else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
    let parent_path = parents.join("\\");
    let linked = with_hive(|hive| {
        let Ok(Some(parent)) = walk(hive, &parent_path, false, None, false) else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
        if hive.nodes[&parent].child(&name.to_lowercase()).is_some() {
            return Err((STATUS_OBJECT_NAME_COLLISION, storage));
        }
        let mut ids: Vec<NodeId> = Vec::with_capacity(keys.len());
        for key in keys {
            let (parent_node, display) = match key.parent {
                Some(index) => (ids[index], key.record.name.clone()),
                None => (parent, String::from(*name)),
            };
            let node = hive.next_node;
            hive.next_node += 1;
            let values = key.record.values.into_iter().map(|value| (value.name.to_lowercase(), value)).collect();
            hive.nodes.insert(node, KeyNode { name: display.clone(), parent: Some(parent_node), children: Vec::new(), values, security: key.record.security, last_write_time: key.record.last_write_time, deleted: false, cell: Some((identifier, key.cell)), volatile: false });
            if let Some(parent_key) = hive.nodes.get_mut(&parent_node) {
                parent_key.children.push((display.to_lowercase(), node));
            }
            ids.push(node);
        }
        let root = ids[0];
        hive.storages.insert(identifier, (storage, root));
        Ok(root)
    })?;
    notify_path_changed(path);
    Ok(linked)
}

/// Os nós da subárvore (o próprio incluído), em pré-ordem.
fn subtree(hive: &Hive, node: NodeId) -> Vec<NodeId> {
    let mut order = Vec::new();
    let mut stack = alloc::vec![node];
    while let Some(current) = stack.pop() {
        order.push(current);
        if let Some(key) = hive.nodes.get(&current) {
            for &(_, child) in key.children.iter().rev() {
                stack.push(child);
            }
        }
    }
    order
}

fn has_open_handles(hive: &Hive, nodes: &[NodeId]) -> bool {
    hive.handles.values().any(|entry| nodes.contains(&entry.node))
}

/// Caminho absoluto de um nó pelos nomes.
fn node_path(hive: &Hive, node: NodeId) -> String {
    let mut names = Vec::new();
    let mut current = Some(node);
    while let Some(id) = current.filter(|&id| id != ROOT) {
        let Some(key) = hive.nodes.get(&id) else { break };
        names.push(key.name.clone());
        current = key.parent;
    }
    let mut path = String::new();
    for name in names.iter().rev() {
        path.push('\\');
        path.push_str(name);
    }
    path
}

/// Desliga uma hive (CmpPerformUnloadKey): com handles abertos em chaves
/// dela, STATUS_CANNOT_DELETE, salvo `force` (REG_FORCE_UNLOAD), que deixa
/// os handles apontando para chaves excluídas. Devolve as células.
pub fn unlink_hive(identifier: u32, force: bool) -> Result<Storage, u32> {
    let (storage, path) = with_hive(|hive| {
        let Some(&(_, root)) = hive.storages.get(&identifier) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        let nodes = subtree(hive, root);
        if !force && has_open_handles(hive, &nodes) {
            return Err(STATUS_CANNOT_DELETE);
        }
        let path = node_path(hive, root);
        let lower = hive.nodes[&root].name.to_lowercase();
        if let Some(parent) = hive.nodes[&root].parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
            parent.children.retain(|(name, _)| *name != lower);
        }
        for node in &nodes {
            if let Some(key) = hive.nodes.get_mut(node) {
                key.deleted = true;
                key.cell = None;
            }
        }
        let (storage, _) = hive.storages.remove(&identifier).expect("hive registrada");
        Ok((storage, path))
    })?;
    notify_path_changed(&path);
    Ok(storage)
}

/// Caminho absoluto de um nó vivo pelos nomes.
pub fn path_of(node: NodeId) -> Option<String> {
    with_hive(|hive| hive.nodes.get(&node).filter(|key| !key.deleted).map(|_| node_path(hive, node)))
}

pub fn set_close_observer(observer: Option<fn()>) {
    *CLOSE_OBSERVER.lock() = observer;
}

/// O nó raiz de uma hive carregada.
pub fn hive_root(identifier: u32) -> Option<NodeId> {
    with_hive(|hive| hive.storages.get(&identifier).map(|&(_, root)| root))
}

/// Executa `body` sobre as células de uma hive carregada.
pub fn with_storage<T>(identifier: u32, body: impl FnOnce(&mut Storage) -> T) -> Option<T> {
    with_hive(|hive| hive.storages.get_mut(&identifier).map(|(storage, _)| body(storage)))
}

/// A hive de arquivo de um nó e se ele é a raiz dela.
pub fn hive_of(node: NodeId) -> Option<(u32, bool)> {
    with_hive(|hive| {
        let (identifier, _) = hive.nodes.get(&node)?.cell?;
        let root = hive.storages.get(&identifier)?.1;
        Some((identifier, root == node))
    })
}

/// As chaves da subárvore de um nó em pré-ordem, sem as voláteis (o que o
/// CmSaveKey copia). A primeira é o próprio nó.
pub fn snapshot(node: NodeId) -> Option<Vec<NewKey>> {
    with_hive(|hive| {
        let key = hive.nodes.get(&node).filter(|key| !key.deleted && !key.volatile)?;
        let _ = key;
        let mut keys: Vec<NewKey> = Vec::new();
        let mut stack: Vec<(NodeId, Option<usize>)> = alloc::vec![(node, None)];
        while let Some((current, parent)) = stack.pop() {
            let Some(key) = hive.nodes.get(&current).filter(|key| !key.deleted && !key.volatile) else { continue };
            let index = keys.len();
            keys.push(NewKey { name: key.name.clone(), last_write_time: key.last_write_time, security: key.security.clone(), values: key.values.iter().map(|(_, value)| value.clone()).collect(), parent });
            for &(_, child) in key.children.iter().rev() {
                stack.push((child, Some(index)));
            }
        }
        Some(keys)
    })
}

/// Há handles abertos em chaves da subárvore (o próprio nó incluído
/// quando pedido)?
pub fn subtree_has_open_handles(node: NodeId, include_self: bool) -> bool {
    with_hive(|hive| {
        let mut nodes = subtree(hive, node);
        if !include_self {
            nodes.retain(|&candidate| candidate != node);
        }
        has_open_handles(hive, &nodes)
    })
}

/// CmRestoreKey: troca as subchaves e os valores do nó pelos da árvore lida
/// (a primeira chave é a raiz da hive de origem), pelas mesmas operações de
/// célula das chaves comuns. O descritor do próprio nó fica.
pub fn restore_subtree(node: NodeId, keys: Vec<FlatKey>) -> Result<(), KernelError> {
    let path = with_hive(|hive| -> Result<String, KernelError> {
        let mut nodes = subtree(hive, node);
        nodes.retain(|&candidate| candidate != node);
        for &child in nodes.iter().rev() {
            let parent = hive.nodes.get(&child).and_then(|key| key.parent);
            let lower = hive.nodes.get(&child).map(|key| key.name.to_lowercase()).unwrap_or_default();
            if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.children.retain(|(name, _)| *name != lower);
            }
            if let Some(key) = hive.nodes.get_mut(&child) {
                key.deleted = true;
            }
            mirror(hive, child, |storage, cell, _| key_cells::delete_key(storage, cell, now()));
            if let Some(key) = hive.nodes.get_mut(&child) {
                key.cell = None;
            }
        }
        let names: Vec<String> = hive.nodes[&node].values.iter().map(|(_, value)| value.name.clone()).collect();
        for name in names {
            if let Some(key) = hive.nodes.get_mut(&node) {
                key.values.retain(|(_, value)| value.name != name);
            }
            mirror(hive, node, |storage, cell, _| key_cells::delete_value(storage, cell, &name, now()));
        }
        let mut ids: Vec<NodeId> = Vec::with_capacity(keys.len());
        for key in keys {
            let target = match key.parent {
                None => node,
                Some(index) => {
                    let parent = ids[index];
                    let child = create_node(hive, &key.record.name, parent, Some(key.record.security.clone()), false)?;
                    if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                        parent_key.children.push((key.record.name.to_lowercase(), child));
                    }
                    child
                }
            };
            for value in key.record.values {
                let lower = value.name.to_lowercase();
                let stored = value.clone();
                if let Some(entry) = hive.nodes.get_mut(&target) {
                    match entry.values.iter_mut().find(|(candidate, _)| *candidate == lower) {
                        Some(slot) => slot.1 = value,
                        None => entry.values.push((lower, value)),
                    }
                }
                mirror(hive, target, |storage, cell, _| key_cells::set_value(storage, cell, &stored.name, stored.value_type, &stored.data, now()));
            }
            if let Some(entry) = hive.nodes.get_mut(&target) {
                entry.last_write_time = key.record.last_write_time;
            }
            mirror(hive, target, |storage, cell, time| {
                key_cells::set_last_write_time(storage, cell, time);
                Some(())
            });
            ids.push(target);
        }
        Ok(node_path(hive, node))
    })?;
    notify_path_changed(&path);
    Ok(())
}
