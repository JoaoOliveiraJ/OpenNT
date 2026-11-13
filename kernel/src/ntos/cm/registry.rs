//! Hive em memória do Configuration Manager — `system32/ntos/cm/registry.js`.
//!
//! Árvore de chaves e valores sem diferença entre maiúsculas e minúsculas. Os
//! handles internos identificam nós e caminhos; as fronteiras de syscall
//! acrescentam direitos, captura e notificações nativas. Os nós vivem numa
//! arena e são identificados por [`NodeId`]; um nó excluído continua na arena
//! (marcado) enquanto handles antigos ainda o referenciam.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

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
}

static HIVE: SpinLock<Option<Hive>> = SpinLock::new(None);
static OBSERVERS: SpinLock<Vec<(u64, String, Observer)>> = SpinLock::new(Vec::new());
static NEXT_OBSERVER: SpinLock<u64> = SpinLock::new(1);
static HOOKS: SpinLock<Option<NativeHooks>> = SpinLock::new(None);

fn now() -> u64 {
    clock::system_time_100ns()
}

fn with_hive<T>(body: impl FnOnce(&mut Hive) -> T) -> T {
    let mut hive = HIVE.lock();
    let hive = hive.get_or_insert_with(|| {
        let mut nodes = BTreeMap::new();
        nodes.insert(ROOT, KeyNode { name: String::new(), parent: None, children: Vec::new(), values: Vec::new(), security: key_policy::boot_root(), last_write_time: now(), deleted: false });
        Hive { nodes, next_node: ROOT + 1, handles: BTreeMap::new(), statistics: ObjectStatistics::default() }
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

fn create_node(hive: &mut Hive, name: &str, parent: NodeId, security: Option<Captured>) -> Result<NodeId, KernelError> {
    let security = match security {
        Some(security) => security,
        None => key_policy::boot_child(&hive.nodes[&parent].security)?,
    };
    let identifier = hive.next_node;
    hive.next_node += 1;
    hive.nodes.insert(identifier, KeyNode { name: name.to_string(), parent: Some(parent), children: Vec::new(), values: Vec::new(), security, last_write_time: now(), deleted: false });
    Ok(identifier)
}

/// Percorre desde a raiz, criando componentes ausentes só quando pedido.
fn walk(hive: &mut Hive, path: &str, create: bool, security: Option<Captured>) -> Result<Option<NodeId>, KernelError> {
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
                let child = create_node(hive, component, node, if index == last { security.take() } else { None })?;
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
    with_hive(|hive| match walk(hive, path, false, None) {
        Ok(Some(node)) => hive.nodes[&node].children.iter().map(|(_, child)| hive.nodes[child].name.clone()).collect(),
        _ => Vec::new(),
    })
}

/// Consulta interna de valor pelo caminho (cópia do registro).
pub fn read_value_by_path(path: &str, name: &str) -> Option<Value> {
    with_hive(|hive| {
        let node = walk(hive, path, false, None).ok()??;
        hive.nodes[&node].value(&name.to_lowercase()).cloned()
    })
}

/// Cria o caminho se necessário e publica um handle; um caminho novo
/// notifica seus observadores.
pub fn open_or_create(path: &str, security: Option<Captured>) -> Result<u32, KernelError> {
    let (handle, created) = with_hive(|hive| -> Result<(u32, bool), KernelError> {
        let existing = walk(hive, path, false, None)?;
        let Some(node) = walk(hive, path, true, security)? else { return Ok((0, false)) };
        Ok((publish(hive, path, node)?, existing.is_none()))
    })?;
    if created {
        notify_path_changed(path);
    }
    Ok(handle)
}

/// Abre só um nó existente; ausência devolve zero.
pub fn open(path: &str) -> Result<u32, KernelError> {
    with_hive(|hive| match walk(hive, path, false, None)? {
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
        if key.deleted || !key.children.is_empty() {
            return false;
        }
        let components = split_path(path);
        let Some(last) = components.last() else { return false };
        let lower = last.to_lowercase();
        let parent_path = components[..components.len() - 1].join("\\");
        let Ok(Some(parent)) = walk(hive, &parent_path, false, None) else { return false };
        let parent = hive.nodes.get_mut(&parent).expect("pai resolvido");
        let before = parent.children.len();
        parent.children.retain(|(name, _)| *name != lower);
        let removed = parent.children.len() != before;
        if removed {
            if let Some(key) = hive.nodes.get_mut(&node) {
                key.deleted = true;
            }
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
        match key.values.iter_mut().find(|(candidate, _)| *candidate == lower) {
            Some(slot) => slot.1 = value,
            None => key.values.push((lower, value)),
        }
        key.last_write_time = now();
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
        }
        removed
    });
    if removed {
        notify_path_changed(path);
    }
    removed
}

pub fn node_by_path(path: &str) -> Option<NodeId> {
    with_hive(|hive| walk(hive, path, false, None).ok().flatten())
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
