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
//!
//! Chaves de link (KEY_SYM_LINK) são seguidas como no CmpDoParseKey do
//! ntoskrnl 19041: um componente do caminho que é link (no meio do caminho,
//! ou no fim sem OBJ_OPENLINK) troca o caminho já percorrido pelo alvo do
//! valor `SymbolicLinkValue` (REG_LINK, exatamente DataLength bytes de
//! UTF-16; CmpGetSymbolicLinkTarget), com o resto do nome acrescentado, e a
//! busca recomeça da raiz (o STATUS_REPARSE do ObpLookupObjectName, no
//! máximo 64 vezes; depois, STATUS_OBJECT_NAME_NOT_FOUND). Um link sem o
//! valor (ou com outro tipo) dá STATUS_OBJECT_NAME_NOT_FOUND. Os handles
//! guardam o caminho resolvido, o nome real da chave: o
//! KeyNameInformation de `CurrentControlSet\Services` é o de
//! `ControlSet001\Services`, e as notificações de mudança seguem o nó real.
//! Um link de uma hive não confiável (carregada pelo NtLoadKey) só leva a
//! chaves da mesma hive ou das hives da classe de confiança dela (o
//! TrustClassKey do NtLoadKeyEx); fora disso o nome dá STATUS_ACCESS_DENIED
//! (CmpOKToFollowLink).
//!
//! Uma hive volátil (HARDWARE, as do REG_WHOLE_HIVE_VOLATILE) tem células
//! como as de arquivo, mas nenhum arquivo: a descarga não grava nada.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::cm::hive::key_cells;
use crate::ntos::cm::hive::storage::Storage;
use crate::ntos::cm::hive::tree::{FlatKey, NewKey};
use crate::ntos::cm::key::notify as key_notify;
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

/// Nó da hive: subchaves e valores em ordem de inserção e LastWriteTime em
/// 100 ns desde 1601. Cada subchave vem com o hash do nome sem diferença de
/// caixa ([`name_hash`]): a busca compara o hash e confirma pelo nome do filho,
/// sem guardar outra cópia do nome. O descritor é compartilhado entre as
/// chaves com o mesmo descritor, como a célula 'sk' de uma hive.
#[derive(Clone, Debug)]
pub struct KeyNode {
    pub name: String,
    pub parent: Option<NodeId>,
    pub children: Vec<(u32, NodeId)>,
    pub values: Vec<Value>,
    pub security: Arc<Captured>,
    pub last_write_time: u64,
    pub deleted: bool,
    /// (hive, célula 'nk') de um nó guardado numa hive de arquivo.
    pub cell: Option<(u32, u32)>,
    /// Criado com REG_OPTION_VOLATILE (ou abaixo de uma chave volátil).
    pub volatile: bool,
    /// Chave de link (REG_OPTION_CREATE_LINK, KEY_SYM_LINK na célula).
    pub link: bool,
    /// A classe da chave em UTF-16 (vazia sem classe).
    pub class: Vec<u16>,
}

impl KeyNode {
    /// O valor de nome `lower` (já em minúsculas), sem diferença de caixa.
    pub fn value(&self, lower: &str) -> Option<&Value> {
        self.values.iter().find(|value| same_name(&value.name, lower))
    }

    fn value_mut(&mut self, lower: &str) -> Option<&mut Value> {
        self.values.iter_mut().find(|value| same_name(&value.name, lower))
    }
}

/// Os dois nomes são iguais sem diferença de caixa (comparados em
/// maiúsculas, como o NT compara nomes de chave), sem alocar cópias.
pub fn same_name(name: &str, other: &str) -> bool {
    name.chars().flat_map(char::to_uppercase).eq(other.chars().flat_map(char::to_uppercase))
}

/// Hash do nome sem diferença de caixa (FNV-1a sobre os caracteres em
/// maiúsculas): nomes iguais por [`same_name`] têm o mesmo hash.
pub fn name_hash(name: &str) -> u32 {
    name.chars().flat_map(char::to_uppercase).fold(0x811C_9DC5u32, |hash, character| (hash ^ character as u32).wrapping_mul(0x0100_0193))
}

/// A subchave de `node` com o nome `lower` (já em minúsculas).
fn child_of(hive: &Hive, node: NodeId, lower: &str) -> Option<NodeId> {
    let hash = name_hash(lower);
    hive.nodes[&node].children.iter().filter(|&&(candidate, _)| candidate == hash).map(|&(_, child)| child).find(|child| hive.nodes.get(child).is_some_and(|key| same_name(&key.name, lower)))
}

/// Os descritores já vistos numa carga de hive: chaves com o mesmo
/// descritor compartilham a cópia.
#[derive(Default)]
struct SecurityCache {
    known: Vec<Arc<Captured>>,
}

impl SecurityCache {
    fn share(&mut self, security: Captured) -> Arc<Captured> {
        if let Some(found) = self.known.iter().find(|known| ***known == security) {
            return found.clone();
        }
        let shared = Arc::new(security);
        self.known.push(shared.clone());
        shared
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
    /// As hives não confiáveis (as do NtLoadKey: o bit 0 de CMHIVE.Flags)
    /// e a classe de confiança de cada uma (a lista
    /// CMHIVE.TrustClassEntry): hives da mesma classe têm o mesmo número.
    /// As hives ausentes daqui são confiáveis.
    trust: BTreeMap<u32, u32>,
    /// Uma hive limpa ficou suja desde o último aviso (HvpMarkDirty).
    dirtied: bool,
}

static HIVE: SpinLock<Option<Hive>> = SpinLock::new(None);
static OBSERVERS: SpinLock<Vec<(u64, String, Observer)>> = SpinLock::new(Vec::new());
static NEXT_OBSERVER: SpinLock<u64> = SpinLock::new(1);
static HOOKS: SpinLock<Option<NativeHooks>> = SpinLock::new(None);
/// Chamado (fora das travas) depois de cada handle fechado: as descargas
/// pendentes do NtUnloadKeyEx e as hives de aplicativo (`hive_list`).
static CLOSE_OBSERVER: SpinLock<Option<fn()>> = SpinLock::new(None);
/// Chamado (fora das travas) quando uma hive limpa fica suja: o
/// CmpArmLazyWriter que o HvpMarkDirty chama (`lazy_flush`).
static DIRTY_OBSERVER: SpinLock<Option<fn()>> = SpinLock::new(None);

/// O valor do alvo de uma chave de link e o tipo dele.
pub const SYMBOLIC_LINK_VALUE: &str = "SymbolicLinkValue";
pub const REG_LINK: u32 = 6;
/// Reparses de um nome antes de desistir (ObpLookupObjectName).
const MAX_REPARSE: u32 = 64;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;

fn now() -> u64 {
    clock::system_time_100ns()
}

fn with_hive<T>(body: impl FnOnce(&mut Hive) -> T) -> T {
    let (result, dirtied) = {
        let mut hive = HIVE.lock();
        let hive = hive.get_or_insert_with(|| {
            let mut nodes = BTreeMap::new();
            nodes.insert(ROOT, KeyNode { name: String::new(), parent: None, children: Vec::new(), values: Vec::new(), security: Arc::new(key_policy::boot_root()), last_write_time: now(), deleted: false, cell: None, volatile: false, link: false, class: Vec::new() });
            Hive { nodes, next_node: ROOT + 1, handles: BTreeMap::new(), statistics: ObjectStatistics::default(), storages: BTreeMap::new(), trust: BTreeMap::new(), dirtied: false }
        });
        let result = body(hive);
        (result, core::mem::take(&mut hive.dirtied))
    };
    if dirtied {
        let observer = *DIRTY_OBSERVER.lock();
        if let Some(observer) = observer {
            observer();
        }
    }
    result
}

/// Registra a rotina chamada quando uma hive de arquivo fica suja.
pub fn set_dirty_observer(observer: Option<fn()>) {
    *DIRTY_OBSERVER.lock() = observer;
}

/// Uma mudança de célula: a hive que estava limpa avisa o escritor
/// preguiçoso depois de soltar a trava.
fn note_change(hive: &mut Hive, identifier: u32, was_dirty: bool) {
    if !was_dirty && hive.storages.get(&identifier).is_some_and(|(storage, _)| storage.is_dirty()) {
        hive.dirtied = true;
    }
}

fn is_registry_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "\\registry" || lower.starts_with("\\registry\\")
}

/// O alvo de uma chave de link (CmpGetSymbolicLinkTarget): o valor
/// `SymbolicLinkValue` do tipo REG_LINK, DataLength bytes de UTF-16.
fn link_target(key: &KeyNode) -> Option<String> {
    let value = key.value("symboliclinkvalue").filter(|value| value.value_type == REG_LINK)?;
    let units: Vec<u16> = value.data.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    Some(String::from_utf16_lossy(&units))
}

/// A hive de arquivo (ou volátil) que guarda o nó: a do próprio nó ou, para
/// uma chave volátil sem célula, a do ancestral mais próximo com célula
/// (o KeyHive do KCB). `None` é a hive mestra.
fn owning_hive_of(hive: &Hive, node: NodeId) -> Option<u32> {
    let mut current = Some(node);
    while let Some(id) = current {
        let key = hive.nodes.get(&id)?;
        if let Some((identifier, _)) = key.cell {
            return Some(identifier);
        }
        current = key.parent;
    }
    None
}

/// CmpOKToFollowLink: depois de seguir um link de uma hive não confiável
/// (`source`), o nome só pode parar na mesma hive ou numa hive não
/// confiável da mesma classe de confiança; senão, STATUS_ACCESS_DENIED.
fn ok_to_follow_link(hive: &Hive, source: u32, target: Option<u32>) -> bool {
    match target {
        Some(target) if target == source => true,
        Some(target) => hive.trust.get(&target).is_some_and(|class| hive.trust.get(&source) == Some(class)),
        None => false,
    }
}

/// O caminho com cada link do prefixo existente trocado pelo alvo (o
/// reparse do CmpDoParseKey). O último componente só é seguido sem
/// `open_link` (OBJ_OPENLINK). Um componente ausente encerra a resolução: o
/// resto do nome fica como está.
///
/// O primeiro link seguido que mora numa hive não confiável fica guardado
/// (o campo do contexto de parse que o CmpDoParseKey preenche no
/// STATUS_REPARSE), e a chave mais funda que o nome final alcança precisa
/// estar numa hive da classe de confiança dele (CmpOKToFollowLink, depois
/// do CmpPerformCompleteKcbCacheLookup).
fn resolve(hive: &Hive, path: &str, open_link: bool) -> Result<String, u32> {
    let mut current = String::from(path);
    let mut reparses = 0;
    let mut link_source: Option<u32> = None;
    'reparse: loop {
        let components = split_path(&current);
        let mut node = ROOT;
        for (index, component) in components.iter().enumerate() {
            let Some(child) = child_of(hive, node, &component.to_lowercase()) else { break };
            let key = &hive.nodes[&child];
            let last = index + 1 == components.len();
            if key.link && !(last && open_link) {
                reparses += 1;
                if reparses > MAX_REPARSE {
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                }
                if link_source.is_none() {
                    link_source = owning_hive_of(hive, child).filter(|identifier| hive.trust.contains_key(identifier));
                }
                let mut target = link_target(key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
                // O nome novo recomeça na raiz do namespace de objetos.
                if !target.starts_with('\\') {
                    return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
                }
                if !is_registry_path(&target) {
                    return Err(STATUS_OBJECT_TYPE_MISMATCH);
                }
                for rest in &components[index + 1..] {
                    target.push('\\');
                    target.push_str(rest);
                }
                current = target;
                continue 'reparse;
            }
            node = child;
        }
        if let Some(source) = link_source {
            if !ok_to_follow_link(hive, source, owning_hive_of(hive, node)) {
                return Err(STATUS_ACCESS_DENIED);
            }
        }
        return Ok(current);
    }
}

/// [`resolve`] com a trava: o caminho real de um nome, ou o NTSTATUS do
/// parse (um link sem alvo, um ciclo).
pub fn resolve_path(path: &str, open_link: bool) -> Result<String, u32> {
    with_hive(|hive| resolve(hive, path, open_link))
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

/// O nó e os ancestrais dele até a raiz (a pilha de KCBs que o
/// CmpReportNotifyHelper sobe para achar os blocos de notificação).
fn ancestry(hive: &Hive, node: NodeId) -> Vec<NodeId> {
    let mut chain = Vec::new();
    let mut current = Some(node);
    while let Some(id) = current {
        chain.push(id);
        current = hive.nodes.get(&id).and_then(|key| key.parent);
    }
    chain
}

/// [`ancestry`] com a trava.
pub fn ancestors(node: NodeId) -> Vec<NodeId> {
    with_hive(|hive| ancestry(hive, node))
}

/// CmpReportNotify de uma mudança na chave `chain[0]` com o filtro
/// REG_NOTIFY_CHANGE_* dela, fora das travas.
fn report_change(chain: &[NodeId], filter: u32) {
    if !chain.is_empty() {
        key_notify::report(chain, filter);
    }
}

/// O nó existente mais fundo de um caminho já resolvido: o pai da primeira
/// chave que uma criação acrescentaria.
fn deepest_existing(hive: &Hive, path: &str) -> NodeId {
    let mut node = ROOT;
    for component in split_path(path) {
        match child_of(hive, node, &component.to_lowercase()) {
            Some(child) => node = child,
            None => break,
        }
    }
    node
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
    let mut was_dirty = true;
    if let Some((storage, _)) = hive.storages.get_mut(&identifier) {
        was_dirty = storage.is_dirty();
        if !storage.broken && change(storage, cell, time).is_none() {
            storage.broken = true;
            crate::debug_print!("[cm] hive {}: a celula {:#x} nao acompanhou a mudanca; a descarga fica recusada", identifier, cell);
        }
    }
    note_change(hive, identifier, was_dirty);
}

fn create_node(hive: &mut Hive, name: &str, parent: NodeId, security: Option<Captured>, volatile: bool, link: bool, class: &[u16]) -> Result<NodeId, KernelError> {
    let security = match security {
        Some(security) => security,
        None => key_policy::boot_child(&hive.nodes[&parent].security)?,
    };
    let volatile = volatile || hive.nodes[&parent].volatile;
    let time = now();
    // A chave nova vai para a hive do pai, salvo se for volátil.
    let mut cell = None;
    if let Some((identifier, parent_cell)) = hive.nodes[&parent].cell.filter(|_| !volatile) {
        let mut was_dirty = true;
        if let Some((storage, _)) = hive.storages.get_mut(&identifier).filter(|(storage, _)| !storage.broken) {
            was_dirty = storage.is_dirty();
            match key_cells::create_key(storage, parent_cell, name, class, &security, time) {
                Some(created) => {
                    if link {
                        key_cells::set_key_flags(storage, created, key_cells::KEY_SYM_LINK);
                    }
                    cell = Some((identifier, created));
                }
                None => {
                    storage.broken = true;
                    crate::debug_print!("[cm] hive {}: a chave {} nao coube nas celulas; a descarga fica recusada", identifier, name);
                }
            }
        }
        note_change(hive, identifier, was_dirty);
    }
    let identifier = hive.next_node;
    hive.next_node += 1;
    hive.nodes.insert(identifier, KeyNode { name: name.to_string(), parent: Some(parent), children: Vec::new(), values: Vec::new(), security: Arc::new(security), last_write_time: time, deleted: false, cell, volatile, link, class: class.to_vec() });
    Ok(identifier)
}

/// Percorre desde a raiz, criando componentes ausentes só quando pedido. Não
/// segue links: o caminho já vem resolvido ([`resolve`]).
fn walk(hive: &mut Hive, path: &str, create: bool, security: Option<Captured>, volatile: bool) -> Result<Option<NodeId>, KernelError> {
    walk_link(hive, path, create, security, volatile, false, &[])
}

/// [`walk`] com o último componente criado como chave de link e com a
/// classe `class`.
fn walk_link(hive: &mut Hive, path: &str, create: bool, security: Option<Captured>, volatile: bool, link: bool, class: &[u16]) -> Result<Option<NodeId>, KernelError> {
    let mut node = ROOT;
    let components = split_path(path);
    let last = components.len().saturating_sub(1);
    let mut security = security;
    for (index, component) in components.iter().enumerate() {
        let lower = component.to_lowercase();
        let existing = child_of(hive, node, &lower);
        node = match existing {
            Some(child) => child,
            None if !create => return Ok(None),
            None => {
                let child = create_node(hive, component, node, if index == last { security.take() } else { None }, volatile && index == last, link && index == last, if index == last { class } else { &[] })?;
                if let Some(parent) = hive.nodes.get_mut(&node) {
                    parent.children.push((name_hash(&lower), child));
                }
                child
            }
        };
    }
    Ok(Some(node))
}

/// Resolve os links e percorre sem criar.
fn find(hive: &mut Hive, path: &str) -> Option<NodeId> {
    let resolved = resolve(hive, path, false).ok()?;
    walk(hive, &resolved, false, None, false).ok().flatten()
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
    with_hive(|hive| match find(hive, path) {
        Some(node) => hive.nodes[&node].children.iter().map(|(_, child)| hive.nodes[child].name.clone()).collect(),
        None => Vec::new(),
    })
}

/// Consulta interna de valor pelo caminho (cópia do registro).
pub fn read_value_by_path(path: &str, name: &str) -> Option<Value> {
    with_hive(|hive| {
        let node = find(hive, path)?;
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
    let resolved = match resolve_path(path, false) {
        Ok(resolved) => resolved,
        Err(_) => return Ok(0),
    };
    create_resolved(&resolved, security, volatile, false).map(|(handle, _)| handle)
}

/// Cria ou abre um caminho já resolvido ([`resolve_path`]), com a chave final
/// volátil e/ou de link quando criada. Devolve o handle (zero se o caminho
/// não existe nem pode ser criado) e se a chave foi criada.
pub fn create_resolved(path: &str, security: Option<Captured>, volatile: bool, link: bool) -> Result<(u32, bool), KernelError> {
    create_resolved_class(path, security, volatile, link, &[])
}

/// [`create_resolved`] com a classe da chave final quando criada (o Class
/// do NtCreateKey); uma chave que já existe fica com a classe dela.
pub fn create_resolved_class(path: &str, security: Option<Captured>, volatile: bool, link: bool, class: &[u16]) -> Result<(u32, bool), KernelError> {
    let (handle, created, parent_chain) = with_hive(|hive| -> Result<(u32, bool, Vec<NodeId>), KernelError> {
        let existing = walk(hive, path, false, None, false)?;
        let parent = deepest_existing(hive, path);
        let Some(node) = walk_link(hive, path, true, security, volatile, link, class)? else { return Ok((0, false, Vec::new())) };
        let created = existing.is_none();
        Ok((publish(hive, path, node)?, created, if created { ancestry(hive, parent) } else { Vec::new() }))
    })?;
    if created {
        // CmpCreateChild: REG_NOTIFY_CHANGE_NAME no pai.
        report_change(&parent_chain, key_notify::REG_NOTIFY_CHANGE_NAME);
        notify_path_changed(path);
    }
    Ok((handle, created))
}

/// Abre só um nó existente; ausência devolve zero.
pub fn open(path: &str) -> Result<u32, KernelError> {
    let Ok(resolved) = resolve_path(path, false) else { return Ok(0) };
    open_resolved(&resolved)
}

/// [`open`] de um caminho já resolvido: o último componente não é seguido
/// (a abertura de uma chave de link com OBJ_OPENLINK).
pub fn open_resolved(path: &str) -> Result<u32, KernelError> {
    with_hive(|hive| match walk(hive, path, false, None, false)? {
        Some(node) => publish(hive, path, node),
        None => Ok(0),
    })
}

/// O nó de um caminho já resolvido, sem seguir o último componente.
pub fn node_by_resolved_path(path: &str) -> Option<NodeId> {
    with_hive(|hive| walk(hive, path, false, None, false).ok().flatten())
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
        let Some(key) = hive.nodes.get(&node) else { return None };
        // A raiz de uma hive carregada é KEY_NO_DELETE.
        if key.deleted || !key.children.is_empty() || hive.storages.values().any(|&(_, root)| root == node) {
            return None;
        }
        // O pai é o do próprio nó: um handle aberto por um link guarda o
        // caminho resolvido, e a árvore é a fonte de verdade.
        let parent = key.parent?;
        let real = node_path(hive, node);
        let parent_chain = ancestry(hive, parent);
        let parent = hive.nodes.get_mut(&parent)?;
        let before = parent.children.len();
        parent.children.retain(|&(_, child)| child != node);
        if parent.children.len() == before {
            return None;
        }
        if let Some(key) = hive.nodes.get_mut(&node) {
            key.deleted = true;
        }
        mirror(hive, node, |storage, cell, _| key_cells::delete_key(storage, cell, now()));
        if let Some(key) = hive.nodes.get_mut(&node) {
            key.cell = None;
        }
        Some((real, parent_chain))
    });
    match removed {
        Some((real, parent_chain)) => {
            // CmDeleteKey: REG_NOTIFY_CHANGE_NAME no pai; os pedidos nos
            // handles da chave excluída completam com STATUS_NOTIFY_CLEANUP
            // (CmpFlushNotifiesOnKeyBodyList).
            report_change(&parent_chain, key_notify::REG_NOTIFY_CHANGE_NAME);
            key_notify::flush_node(node);
            notify_path_changed(if path.is_empty() { &real } else { path });
            true
        }
        None => false,
    }
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
                handle_ids::release(handle);
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

/// Grava o valor, atualiza LastWriteTime e avisa os observadores
/// (CmSetValueKey: REG_NOTIFY_CHANGE_LAST_SET na chave).
pub fn set_node_value(node: NodeId, path: &str, name: &str, value_type: u32, data: Vec<u8>) -> bool {
    let written = with_hive(|hive| {
        let Some(key) = hive.nodes.get_mut(&node).filter(|key| !key.deleted) else { return None };
        let lower = name.to_lowercase();
        let value = Value { name: name.to_string(), value_type, data };
        let stored = value.clone();
        match key.value_mut(&lower) {
            Some(slot) => *slot = value,
            None => key.values.push(value),
        }
        key.last_write_time = now();
        mirror(hive, node, |storage, cell, time| key_cells::set_value(storage, cell, &stored.name, stored.value_type, &stored.data, time));
        Some(ancestry(hive, node))
    });
    match written {
        Some(chain) => {
            report_change(&chain, key_notify::REG_NOTIFY_CHANGE_LAST_SET);
            notify_path_changed(path);
            true
        }
        None => false,
    }
}

pub fn get_value(handle: u32, name: &str) -> Option<Value> {
    let node = get_node(handle)?;
    with_hive(|hive| hive.nodes[&node].value(&name.to_lowercase()).cloned())
}

pub fn delete_value(handle: u32, name: &str) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    delete_node_value(entry.node, &entry.path, name)
}

/// Remove um valor existente e só então atualiza o tempo e notifica
/// (CmDeleteValueKey: REG_NOTIFY_CHANGE_LAST_SET na chave).
pub fn delete_node_value(node: NodeId, path: &str, name: &str) -> bool {
    let removed = with_hive(|hive| {
        let Some(key) = hive.nodes.get_mut(&node).filter(|key| !key.deleted) else { return None };
        let lower = name.to_lowercase();
        let before = key.values.len();
        key.values.retain(|value| !same_name(&value.name, &lower));
        if key.values.len() == before {
            return None;
        }
        key.last_write_time = now();
        mirror(hive, node, |storage, cell, time| key_cells::delete_value(storage, cell, name, time));
        Some(ancestry(hive, node))
    });
    match removed {
        Some(chain) => {
            report_change(&chain, key_notify::REG_NOTIFY_CHANGE_LAST_SET);
            notify_path_changed(path);
            true
        }
        None => false,
    }
}

/// O nó de um caminho, seguindo os links.
pub fn node_by_path(path: &str) -> Option<NodeId> {
    with_hive(|hive| find(hive, path))
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
        let Some(parent) = find(hive, &parent_path) else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
        if child_of(hive, parent, &name.to_lowercase()).is_some() {
            return Err((STATUS_OBJECT_NAME_COLLISION, storage));
        }
        let mut ids: Vec<NodeId> = Vec::with_capacity(keys.len());
        let mut descriptors = SecurityCache::default();
        for key in keys {
            let (parent_node, display) = match key.parent {
                Some(index) => (ids[index], key.record.name),
                None => (parent, String::from(*name)),
            };
            let node = hive.next_node;
            hive.next_node += 1;
            let hash = name_hash(&display);
            let mut values = key.record.values;
            values.shrink_to_fit();
            hive.nodes.insert(node, KeyNode { name: display, parent: Some(parent_node), children: Vec::new(), values, security: descriptors.share(key.record.security), last_write_time: key.record.last_write_time, deleted: false, cell: Some((identifier, key.cell)), volatile: false, link: key.record.flags & key_cells::KEY_SYM_LINK != 0, class: key.record.class });
            if let Some(parent_key) = hive.nodes.get_mut(&parent_node) {
                parent_key.children.push((hash, node));
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
    let (storage, path, parent_chain) = with_hive(|hive| {
        let Some(&(_, root)) = hive.storages.get(&identifier) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        let nodes = subtree(hive, root);
        if !force && has_open_handles(hive, &nodes) {
            return Err(STATUS_CANNOT_DELETE);
        }
        let path = node_path(hive, root);
        let parent_chain = hive.nodes[&root].parent.map(|parent| ancestry(hive, parent)).unwrap_or_default();
        if let Some(parent) = hive.nodes[&root].parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
            parent.children.retain(|&(_, child)| child != root);
        }
        for node in &nodes {
            if let Some(key) = hive.nodes.get_mut(node) {
                key.deleted = true;
                key.cell = None;
            }
        }
        let (storage, _) = hive.storages.remove(&identifier).expect("hive registrada");
        // CmpUnJoinClassOfTrust.
        hive.trust.remove(&identifier);
        Ok((storage, path, parent_chain))
    })?;
    // CmpPerformUnloadKey: a raiz some do pai.
    report_change(&parent_chain, key_notify::REG_NOTIFY_CHANGE_NAME);
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
            keys.push(NewKey { name: key.name.clone(), last_write_time: key.last_write_time, security: Captured::clone(&key.security), values: key.values.clone(), parent, link: key.link, class: key.class.clone() });
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
            if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.children.retain(|&(_, candidate)| candidate != child);
            }
            if let Some(key) = hive.nodes.get_mut(&child) {
                key.deleted = true;
            }
            mirror(hive, child, |storage, cell, _| key_cells::delete_key(storage, cell, now()));
            if let Some(key) = hive.nodes.get_mut(&child) {
                key.cell = None;
            }
        }
        let names: Vec<String> = hive.nodes[&node].values.iter().map(|value| value.name.clone()).collect();
        for name in names {
            if let Some(key) = hive.nodes.get_mut(&node) {
                key.values.retain(|value| value.name != name);
            }
            mirror(hive, node, |storage, cell, _| key_cells::delete_value(storage, cell, &name, now()));
        }
        let mut ids: Vec<NodeId> = Vec::with_capacity(keys.len());
        for key in keys {
            let target = match key.parent {
                None => node,
                Some(index) => {
                    let parent = ids[index];
                    let child = create_node(hive, &key.record.name, parent, Some(key.record.security.clone()), false, key.record.flags & key_cells::KEY_SYM_LINK != 0, &key.record.class)?;
                    if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                        parent_key.children.push((name_hash(&key.record.name), child));
                    }
                    child
                }
            };
            for value in key.record.values {
                let lower = value.name.to_lowercase();
                let stored = value.clone();
                if let Some(entry) = hive.nodes.get_mut(&target) {
                    match entry.value_mut(&lower) {
                        Some(slot) => *slot = value,
                        None => entry.values.push(value),
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

/// Uma hive volátil nova ligada em `path` (CmpCreateHive com HIVE_VOLATILE
/// e CmpLinkHiveToMaster): a raiz com o descritor da política de boot sob o
/// pai, células só na memória e nenhum arquivo.
pub fn create_volatile_hive(path: &str, identifier: u32) -> Result<NodeId, u32> {
    let components = split_path(path);
    let Some((name, parents)) = components.split_last() else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
    let parent_security = with_hive(|hive| find(hive, &parents.join("\\")).map(|parent| hive.nodes[&parent].security.clone())).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let security = key_policy::boot_child(&parent_security).map_err(|_| crate::ntos::cm::hive::storage::STATUS_INSUFFICIENT_RESOURCES)?;
    let root = NewKey { name: String::from(*name), last_write_time: now(), security, values: Vec::new(), parent: None, link: false, class: Vec::new() };
    let (storage, _) = crate::ntos::cm::hive::tree::build(&[root], 5, now(), "").ok_or(crate::ntos::cm::hive::storage::STATUS_INSUFFICIENT_RESOURCES)?;
    let keys = crate::ntos::cm::hive::tree::read(&storage)?;
    link_hive(path, identifier, storage, keys).map_err(|(status, _)| status)
}

/// CmpRefreshHive: as células da hive viram as relidas do arquivo e a
/// árvore é reconciliada com elas. Uma chave que existe nas duas fica com o
/// mesmo nó (os handles continuam valendo), com valores, descritor,
/// LastWriteTime e célula do arquivo; uma chave que só existe na memória
/// (inclusive as voláteis) é excluída; uma que só existe no arquivo é
/// criada.
pub fn refresh_hive(identifier: u32, storage: Storage, keys: Vec<FlatKey>) -> Result<(), u32> {
    let path = with_hive(|hive| -> Result<String, u32> {
        let Some(&(_, root)) = hive.storages.get(&identifier) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        let old: Vec<NodeId> = subtree(hive, root);
        let mut kept: alloc::collections::BTreeSet<NodeId> = alloc::collections::BTreeSet::new();
        let mut ids: Vec<NodeId> = Vec::with_capacity(keys.len());
        let mut descriptors = SecurityCache::default();
        for key in keys {
            let node = match key.parent {
                None => root,
                Some(index) => {
                    let parent = ids[index];
                    let lower = key.record.name.to_lowercase();
                    let hash = name_hash(&lower);
                    let existing = hive.nodes[&parent].children.iter().filter(|&&(candidate, child)| candidate == hash && !kept.contains(&child)).map(|&(_, child)| child).find(|child| hive.nodes.get(child).is_some_and(|key| same_name(&key.name, &lower)));
                    match existing {
                        Some(child) => child,
                        None => {
                            let child = hive.next_node;
                            hive.next_node += 1;
                            hive.nodes.insert(child, KeyNode { name: key.record.name.clone(), parent: Some(parent), children: Vec::new(), values: Vec::new(), security: Arc::new(key.record.security.clone()), last_write_time: 0, deleted: false, cell: None, volatile: false, link: false, class: Vec::new() });
                            if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                                parent_key.children.push((hash, child));
                            }
                            child
                        }
                    }
                }
            };
            kept.insert(node);
            if let Some(entry) = hive.nodes.get_mut(&node) {
                entry.values = key.record.values;
                entry.security = descriptors.share(key.record.security);
                entry.last_write_time = key.record.last_write_time;
                entry.cell = Some((identifier, key.cell));
                entry.link = key.record.flags & key_cells::KEY_SYM_LINK != 0;
                entry.class = key.record.class;
                entry.volatile = false;
            }
            ids.push(node);
        }
        for node in old.into_iter().filter(|node| !kept.contains(node)) {
            let parent = hive.nodes.get(&node).and_then(|key| key.parent);
            if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.children.retain(|&(_, child)| child != node);
            }
            if let Some(key) = hive.nodes.get_mut(&node) {
                key.deleted = true;
                key.cell = None;
            }
        }
        if let Some(entry) = hive.storages.get_mut(&identifier) {
            entry.0 = storage;
        }
        Ok(node_path(hive, root))
    })?;
    notify_path_changed(&path);
    Ok(())
}

/// A hive que guarda um nó (a de um nó volátil é a do ancestral com
/// célula); `None` para a hive mestra.
pub fn owning_hive(node: NodeId) -> Option<u32> {
    with_hive(|hive| owning_hive_of(hive, node))
}

/// A classe de confiança de uma hive não confiável; `None` se a hive é
/// confiável.
pub fn trust_class(identifier: u32) -> Option<u32> {
    with_hive(|hive| hive.trust.get(&identifier).copied())
}

/// Marca a hive como não confiável na classe `class` (o bit 0 de
/// CMHIVE.Flags e a TrustClassEntry), ou confiável com `None`.
pub fn set_trust_class(identifier: u32, class: Option<u32>) {
    with_hive(|hive| match class {
        Some(class) => {
            hive.trust.insert(identifier, class);
        }
        None => {
            hive.trust.remove(&identifier);
        }
    });
}

/// O caminho da raiz de uma hive carregada.
pub fn hive_path(identifier: u32) -> Option<String> {
    with_hive(|hive| hive.storages.get(&identifier).map(|&(_, root)| node_path(hive, root)))
}

/// As hives carregadas (identificador e se a células estão sujas).
pub fn dirty_hives() -> Vec<(u32, bool)> {
    with_hive(|hive| hive.storages.iter().map(|(&identifier, (storage, _))| (identifier, storage.is_dirty())).collect())
}

/// O nó tem handles abertos nele ou na subárvore?
pub fn hive_has_open_handles(identifier: u32) -> bool {
    with_hive(|hive| hive.storages.get(&identifier).is_some_and(|&(_, root)| has_open_handles(hive, &subtree(hive, root))))
}
