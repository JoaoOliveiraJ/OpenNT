//! O namespace do Registro do Configuration Manager.
//!
//! Árvore de chaves e valores sem diferença entre maiúsculas e minúsculas. Os
//! handles internos identificam nós e caminhos; as fronteiras de syscall
//! acrescentam direitos, captura e notificações nativas. Os nós vivem numa
//! arena em blocos de [`CHUNK`] e são identificados por [`NodeId`], que
//! nunca se repete.
//!
//! Um nó faz o papel do KCB: identidade, pai, subchaves, descritor e
//! flags. O conteúdo de uma chave guardada numa hive (nome, valores, classe
//! e LastWriteTime) não é copiado para o nó: ele fica nas células e é lido
//! delas a cada consulta ([`KeyView`]), como o 19041 lê pelo mapa de células
//! (HvpGetCellPaged, CmpFindValueByName, CmpGetValueData). Toda mudança
//! numa chave dessas (chave criada ou excluída, valor gravado ou removido)
//! vai direto às células, sob a mesma trava, marcando os setores sujos que a
//! descarga grava; uma operação de célula que falha (sem espaço, ou uma
//! hive inconsistente) não muda a chave, marca a hive como quebrada e a
//! descarga dela passa a falhar. Os nós sem célula (as chaves mestras, as
//! subárvores montadas só em memória e as chaves voláteis) guardam o
//! próprio conteúdo. A raiz de uma hive carregada tem o nome do ponto de
//! montagem (o nome do link na hive mestra), não o da célula.
//!
//! Uma chave excluída (ou de uma hive descarregada) sai da arena na hora;
//! com handle aberto nela, fica só o nome e o LastWriteTime (o KCB
//! excluído), sem valores, classe nem subchaves, até o último handle
//! fechar.
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

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ops::{Deref, Index};

use crate::ntos::cm::hive::key_cells;
use crate::ntos::cm::hive::storage::{Storage, STATUS_INSUFFICIENT_RESOURCES};
use crate::ntos::cm::hive::tree::{self, Checked, NewKey};
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

/// Nó da arena: pai, subchaves em ordem de inserção (cada uma com o hash do
/// nome sem diferença de caixa, [`name_hash`]: a busca compara o hash e
/// confirma pelo nome do filho), o descritor (compartilhado entre as chaves
/// da mesma célula 'sk') e as flags. O conteúdo vem das células
/// ([`KeyView`]); só um nó sem célula guarda o dele.
#[derive(Clone, Debug)]
pub struct KeyNode {
    pub parent: Option<NodeId>,
    pub children: Vec<(u32, NodeId)>,
    pub security: Arc<Captured>,
    pub deleted: bool,
    /// (hive, célula 'nk') de um nó guardado numa hive.
    pub cell: Option<(u32, u32)>,
    /// Criado com REG_OPTION_VOLATILE (ou abaixo de uma chave volátil).
    pub volatile: bool,
    /// Chave de link (REG_OPTION_CREATE_LINK, KEY_SYM_LINK na célula).
    pub link: bool,
    /// O nome quando ele não vem da célula: os nós sem célula, a raiz de
    /// uma hive carregada (o nome do ponto de montagem) e as chaves
    /// excluídas com handle aberto.
    name: Option<Box<str>>,
    /// Valores, classe e LastWriteTime de um nó sem célula.
    owned: Option<Box<OwnedKey>>,
}

/// O conteúdo de um nó sem célula: valores em ordem de inserção, a classe
/// em UTF-16 e o LastWriteTime em 100 ns desde 1601.
#[derive(Clone, Debug, Default)]
struct OwnedKey {
    values: Vec<Value>,
    class: Vec<u16>,
    last_write_time: u64,
}

impl KeyNode {
    /// Um nó que guarda o próprio conteúdo (sem célula).
    fn in_memory(name: &str, parent: Option<NodeId>, security: Arc<Captured>, volatile: bool, link: bool, class: &[u16], time: u64) -> KeyNode {
        let owned = OwnedKey { values: Vec::new(), class: class.to_vec(), last_write_time: time };
        KeyNode { parent, children: Vec::new(), security, deleted: false, cell: None, volatile, link, name: Some(Box::from(name)), owned: Some(Box::new(owned)) }
    }

    /// Um nó de uma chave guardada na célula 'nk' `cell` da hive `hive`.
    fn stored(parent: Option<NodeId>, security: Arc<Captured>, hive: u32, cell: u32, link: bool) -> KeyNode {
        KeyNode { parent, children: Vec::new(), security, deleted: false, cell: Some((hive, cell)), volatile: false, link, name: None, owned: None }
    }
}

/// Um nó com as células da hive dele: o nome, os valores, a classe e o
/// LastWriteTime lidos das células (ou do próprio nó, sem célula). Os
/// campos do nó (`children`, `security`, `deleted`, `cell`, `link`...)
/// ficam acessíveis pelo `Deref`.
pub struct KeyView<'a> {
    node: &'a KeyNode,
    storage: Option<&'a Storage>,
}

impl Deref for KeyView<'_> {
    type Target = KeyNode;

    fn deref(&self) -> &KeyNode {
        self.node
    }
}

impl<'a> KeyView<'a> {
    /// As células e a célula 'nk' de um nó guardado numa hive.
    fn stored(&self) -> Option<(&'a Storage, u32)> {
        Some((self.storage?, self.node.cell?.1))
    }

    fn name_units(&self) -> Option<key_cells::Units<'a>> {
        self.stored().and_then(|(storage, cell)| key_cells::key_name_units(storage, cell))
    }

    /// O nome da chave.
    pub fn name(&self) -> String {
        match &self.node.name {
            Some(name) => name.to_string(),
            None => self.name_units().map(|units| units.to_string_lossy()).unwrap_or_default(),
        }
    }

    /// O nome é `lower` (já em minúsculas), sem diferença de caixa.
    pub fn name_is(&self, lower: &str) -> bool {
        match &self.node.name {
            Some(name) => same_name(name, lower),
            None => self.name_units().is_some_and(|units| same_chars(lossy_chars(units.iter()), lower.chars())),
        }
    }

    /// O tamanho do nome em bytes de UTF-16.
    pub fn name_length(&self) -> u32 {
        match &self.node.name {
            Some(name) => name.encode_utf16().count() as u32 * 2,
            None => self.name_units().map_or(0, |units| units.len() as u32 * 2),
        }
    }

    /// LastWriteTime em 100 ns desde 1601.
    pub fn last_write_time(&self) -> u64 {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.last_write_time,
            (None, Some((storage, cell))) => key_cells::last_write_time(storage, cell),
            (None, None) => 0,
        }
    }

    /// A classe em UTF-16 (vazia sem classe).
    pub fn class(&self) -> Vec<u16> {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.class.clone(),
            (None, Some((storage, cell))) => key_cells::class_units(storage, cell),
            (None, None) => Vec::new(),
        }
    }

    /// O tamanho da classe em bytes.
    pub fn class_length(&self) -> u32 {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.class.len() as u32 * 2,
            (None, Some((storage, cell))) => key_cells::class_length(storage, cell),
            (None, None) => 0,
        }
    }

    /// Quantos valores a chave tem.
    pub fn value_count(&self) -> usize {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.values.len(),
            (None, Some((storage, cell))) => key_cells::value_count(storage, cell) as usize,
            (None, None) => 0,
        }
    }

    /// A cópia do valor `index`, na ordem da chave.
    pub fn value_at(&self, index: usize) -> Option<Value> {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.values.get(index).cloned(),
            (None, Some((storage, cell))) => key_cells::value_cell(storage, cell, u32::try_from(index).ok()?).and_then(|value| key_cells::read_value(storage, value)),
            (None, None) => None,
        }
    }

    /// A célula 'vk' do valor de nome `lower` (já em minúsculas).
    fn value_cell(&self, lower: &str) -> Option<u32> {
        let (storage, cell) = self.stored()?;
        key_cells::find_value_cell(storage, cell, |units| same_chars(lossy_chars(units.iter()), lower.chars()))
    }

    /// A cópia do valor de nome `lower` (já em minúsculas), sem diferença
    /// de caixa.
    pub fn value(&self, lower: &str) -> Option<Value> {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.values.iter().find(|value| same_name(&value.name, lower)).cloned(),
            (None, Some((storage, _))) => key_cells::read_value(storage, self.value_cell(lower)?),
            (None, None) => None,
        }
    }

    /// A chave tem o valor de nome `lower` (já em minúsculas)?
    pub fn has_value(&self, lower: &str) -> bool {
        match &self.node.owned {
            Some(owned) => owned.values.iter().any(|value| same_name(&value.name, lower)),
            None => self.value_cell(lower).is_some(),
        }
    }

    /// Cópias de todos os valores, em ordem.
    pub fn values(&self) -> Vec<Value> {
        (0..self.value_count()).filter_map(|index| self.value_at(index)).collect()
    }

    /// Os nomes dos valores, em ordem.
    pub fn value_names(&self) -> Vec<String> {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.values.iter().map(|value| value.name.clone()).collect(),
            (None, Some((storage, cell))) => (0..key_cells::value_count(storage, cell)).filter_map(|index| key_cells::value_cell(storage, cell, index)).filter_map(|value| key_cells::value_name_units(storage, value)).map(|units| units.to_string_lossy()).collect(),
            (None, None) => Vec::new(),
        }
    }

    /// O tamanho do nome (bytes de UTF-16) e do dado de cada valor, em
    /// ordem, sem copiar os dados.
    pub fn value_sizes(&self) -> Vec<(u32, u32)> {
        match (&self.node.owned, self.stored()) {
            (Some(owned), _) => owned.values.iter().map(|value| (value.name.encode_utf16().count() as u32 * 2, value.data.len() as u32)).collect(),
            (None, Some((storage, cell))) => (0..key_cells::value_count(storage, cell)).filter_map(|index| key_cells::value_cell(storage, cell, index)).filter_map(|value| key_cells::value_sizes(storage, value)).collect(),
            (None, None) => Vec::new(),
        }
    }
}

/// Os caracteres de um nome em UTF-16, com um substituto no lugar de cada
/// surrogate solto (como o `String::from_utf16_lossy`).
fn lossy_chars(units: impl Iterator<Item = u16>) -> impl Iterator<Item = char> {
    char::decode_utf16(units).map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
}

/// As duas sequências são o mesmo nome sem diferença de caixa (comparadas em
/// maiúsculas, como o NT compara nomes de chave).
fn same_chars(name: impl Iterator<Item = char>, other: impl Iterator<Item = char>) -> bool {
    name.flat_map(char::to_uppercase).eq(other.flat_map(char::to_uppercase))
}

/// Os dois nomes são iguais sem diferença de caixa, sem alocar cópias.
pub fn same_name(name: &str, other: &str) -> bool {
    same_chars(name.chars(), other.chars())
}

fn hash_chars(name: impl Iterator<Item = char>) -> u32 {
    name.flat_map(char::to_uppercase).fold(0x811C_9DC5u32, |hash, character| (hash ^ character as u32).wrapping_mul(0x0100_0193))
}

/// Hash do nome sem diferença de caixa (FNV-1a sobre os caracteres em
/// maiúsculas): nomes iguais por [`same_name`] têm o mesmo hash.
pub fn name_hash(name: &str) -> u32 {
    hash_chars(name.chars())
}

/// Os nós de uma arena bloco: [`CHUNK`] posições pelo NodeId.
struct Chunk {
    slots: Box<[Option<KeyNode>]>,
    live: usize,
}

/// Nós por bloco da arena.
pub const CHUNK: usize = 128;

/// A arena dos nós: o bloco `id / CHUNK` guarda o nó na posição
/// `id % CHUNK`. Um bloco sem nós vivos volta ao heap (salvo o último, onde
/// os nós novos entram).
#[derive(Default)]
struct NodeArena {
    chunks: Vec<Option<Chunk>>,
}

impl NodeArena {
    fn get(&self, id: &NodeId) -> Option<&KeyNode> {
        let chunk = self.chunks.get(*id as usize / CHUNK)?.as_ref()?;
        chunk.slots[*id as usize % CHUNK].as_ref()
    }

    fn get_mut(&mut self, id: &NodeId) -> Option<&mut KeyNode> {
        let chunk = self.chunks.get_mut(*id as usize / CHUNK)?.as_mut()?;
        chunk.slots[*id as usize % CHUNK].as_mut()
    }

    fn contains_key(&self, id: &NodeId) -> bool {
        self.get(id).is_some()
    }

    fn insert(&mut self, id: NodeId, node: KeyNode) {
        let (index, slot) = (id as usize / CHUNK, id as usize % CHUNK);
        if self.chunks.len() <= index {
            self.chunks.resize_with(index + 1, || None);
        }
        let chunk = self.chunks[index].get_or_insert_with(|| {
            let mut slots = Vec::with_capacity(CHUNK);
            slots.resize_with(CHUNK, || None);
            Chunk { slots: slots.into_boxed_slice(), live: 0 }
        });
        if chunk.slots[slot].replace(node).is_none() {
            chunk.live += 1;
        }
    }

    fn remove(&mut self, id: &NodeId) -> Option<KeyNode> {
        let index = *id as usize / CHUNK;
        let last = self.chunks.len().saturating_sub(1);
        let chunk = self.chunks.get_mut(index)?.as_mut()?;
        let node = chunk.slots[*id as usize % CHUNK].take()?;
        chunk.live -= 1;
        if chunk.live == 0 && index != last {
            self.chunks[index] = None;
        }
        Some(node)
    }

    /// Nós vivos e blocos alocados.
    fn counts(&self) -> (usize, usize) {
        self.chunks.iter().flatten().fold((0, 0), |(nodes, chunks), chunk| (nodes + chunk.live, chunks + 1))
    }
}

impl Index<&NodeId> for NodeArena {
    type Output = KeyNode;

    fn index(&self, id: &NodeId) -> &KeyNode {
        self.get(id).expect("no ausente da arena do Registro")
    }
}

/// A subchave de `node` com o nome `lower` (já em minúsculas).
fn child_of(hive: &Hive, node: NodeId, lower: &str) -> Option<NodeId> {
    let hash = name_hash(lower);
    hive.nodes.get(&node)?.children.iter().filter(|&&(candidate, _)| candidate == hash).map(|&(_, child)| child).find(|&child| hive.view(child).is_some_and(|key| key.name_is(lower)))
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
    nodes: NodeArena,
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

impl Hive {
    /// O nó com as células da hive dele.
    fn view(&self, id: NodeId) -> Option<KeyView<'_>> {
        let node = self.nodes.get(&id)?;
        let storage = node.cell.and_then(|(identifier, _)| self.storages.get(&identifier)).map(|(storage, _)| storage);
        Some(KeyView { node, storage })
    }

    fn allocate_id(&mut self) -> NodeId {
        let id = self.next_node;
        self.next_node += 1;
        id
    }
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
const STATUS_KEY_DELETED: u32 = 0xC000_017C;

fn now() -> u64 {
    clock::system_time_100ns()
}

fn with_hive<T>(body: impl FnOnce(&mut Hive) -> T) -> T {
    let (result, dirtied) = {
        let mut hive = HIVE.lock();
        let hive = hive.get_or_insert_with(|| {
            let mut nodes = NodeArena::default();
            nodes.insert(ROOT, KeyNode::in_memory("", None, Arc::new(key_policy::boot_root()), false, false, &[], now()));
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

/// Aplica uma operação às células da hive `identifier` (a da chave da
/// célula `cell`). Uma falha marca a hive como quebrada: as células podem
/// ter ficado pela metade e a descarga fica recusada.
fn cell_op(hive: &mut Hive, identifier: u32, cell: u32, change: impl FnOnce(&mut Storage) -> Option<()>) -> bool {
    let Some((storage, _)) = hive.storages.get_mut(&identifier) else { return false };
    let was_dirty = storage.is_dirty();
    let done = change(storage).is_some();
    if !done {
        storage.broken = true;
        crate::debug_print!("[cm] hive {}: a mudanca na celula {:#x} falhou; a descarga fica recusada", identifier, cell);
    }
    note_change(hive, identifier, was_dirty);
    done
}

fn is_registry_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower == "\\registry" || lower.starts_with("\\registry\\")
}

/// O alvo de uma chave de link (CmpGetSymbolicLinkTarget): o valor
/// `SymbolicLinkValue` do tipo REG_LINK, DataLength bytes de UTF-16.
fn link_target(key: &KeyView) -> Option<String> {
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
            let Some(key) = hive.view(child) else { break };
            let last = index + 1 == components.len();
            if key.link && !(last && open_link) {
                reparses += 1;
                if reparses > MAX_REPARSE {
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                }
                if link_source.is_none() {
                    link_source = owning_hive_of(hive, child).filter(|identifier| hive.trust.contains_key(identifier));
                }
                let mut target = link_target(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
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

/// Os nós com handle aberto.
fn open_nodes(hive: &Hive) -> BTreeSet<NodeId> {
    hive.handles.values().map(|entry| entry.node).collect()
}

/// O nó sai do namespace (chave excluída, hive descarregada ou trocada):
/// sem handle aberto nele (`open`), a arena o libera; com handle, fica só o
/// nome e o LastWriteTime (o KCB excluído), sem valores, classe e
/// subchaves, até o último handle fechar ([`close_raw`]). Chamado antes de
/// as células dele serem liberadas: o nome ainda vem da célula.
fn retire(hive: &mut Hive, node: NodeId, open: bool) {
    if !open {
        hive.nodes.remove(&node);
        return;
    }
    let Some((name, time)) = hive.view(node).map(|key| (key.name(), key.last_write_time())) else { return };
    if let Some(key) = hive.nodes.get_mut(&node) {
        key.deleted = true;
        key.cell = None;
        key.children = Vec::new();
        key.name = Some(name.into_boxed_str());
        key.owned = Some(Box::new(OwnedKey { values: Vec::new(), class: Vec::new(), last_write_time: time }));
    }
}

/// Cria a chave `name` sob `parent`. Abaixo de uma chave guardada numa hive
/// (e sem ser volátil), as células vêm primeiro (CmpDoCreateChild): sem
/// espaço nelas, STATUS_INSUFFICIENT_RESOURCES e nada muda no namespace.
fn create_node(hive: &mut Hive, name: &str, parent: NodeId, security: Option<Captured>, volatile: bool, link: bool, class: &[u16]) -> Result<NodeId, KernelError> {
    let parent_key = hive.nodes.get(&parent).ok_or_else(|| KernelError::with_status("registry: parent key is gone", STATUS_KEY_DELETED))?;
    let security = match security {
        Some(security) => security,
        None => key_policy::boot_child(&parent_key.security)?,
    };
    let volatile = volatile || parent_key.volatile;
    let time = now();
    // A chave nova vai para a hive do pai, salvo se for volátil.
    let node = match parent_key.cell.filter(|_| !volatile) {
        Some((identifier, parent_cell)) => {
            let mut created = None;
            let done = cell_op(hive, identifier, parent_cell, |storage| {
                let cell = key_cells::create_key(storage, parent_cell, name, class, &security, time)?;
                if link {
                    key_cells::set_key_flags(storage, cell, key_cells::KEY_SYM_LINK);
                }
                created = Some(cell);
                Some(())
            });
            match created.filter(|_| done) {
                Some(cell) => KeyNode::stored(Some(parent), Arc::new(security), identifier, cell, link),
                None => return Err(KernelError::with_status("registry: no room for the key cells", STATUS_INSUFFICIENT_RESOURCES)),
            }
        }
        None => KeyNode::in_memory(name, Some(parent), Arc::new(security), volatile, link, class, time),
    };
    let identifier = hive.allocate_id();
    hive.nodes.insert(identifier, node);
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
    with_hive(|hive| match find(hive, path).and_then(|node| hive.nodes.get(&node)) {
        Some(key) => key.children.iter().filter_map(|&(_, child)| hive.view(child).map(|child| child.name())).collect(),
        None => Vec::new(),
    })
}

/// Consulta interna de valor pelo caminho (cópia do registro).
pub fn read_value_by_path(path: &str, name: &str) -> Option<Value> {
    with_hive(|hive| {
        let node = find(hive, path)?;
        hive.view(node)?.value(&name.to_lowercase())
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
    with_hive(|hive| {
        if !hive.nodes.contains_key(&node) {
            return Err(KernelError::with_status("registry: key is gone", STATUS_KEY_DELETED));
        }
        publish(hive, path, node)
    })
}

/// O nó existe e não foi excluído.
fn live(hive: &Hive, node: NodeId) -> bool {
    hive.nodes.get(&node).is_some_and(|key| !key.deleted)
}

/// Nó do handle enquanto não estiver excluído.
pub fn get_node(handle: u32) -> Option<NodeId> {
    with_hive(|hive| hive.handles.get(&handle).filter(|entry| live(hive, entry.node)).map(|entry| entry.node))
}

pub fn get_path(handle: u32) -> Option<String> {
    with_hive(|hive| hive.handles.get(&handle).filter(|entry| live(hive, entry.node)).map(|entry| entry.path.clone()))
}

pub fn delete_key(handle: u32) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    delete_node(entry.node, &entry.path)
}

/// Exclui só nó vivo, sem filhos e com pai resolvido. As células da chave
/// são liberadas (CmpFreeKeyByCell) e o nó sai da arena; com handles
/// abertos, fica marcado como excluído para que eles não o tratem como
/// chave válida.
pub fn delete_node(node: NodeId, path: &str) -> bool {
    let removed = with_hive(|hive| {
        let key = hive.nodes.get(&node)?;
        // A raiz de uma hive carregada é KEY_NO_DELETE.
        if key.deleted || !key.children.is_empty() || hive.storages.values().any(|&(_, root)| root == node) {
            return None;
        }
        // O pai é o do próprio nó: um handle aberto por um link guarda o
        // caminho resolvido, e a árvore é a fonte de verdade.
        let parent = key.parent?;
        let cell = key.cell;
        let real = node_path(hive, node);
        let parent_chain = ancestry(hive, parent);
        let parent = hive.nodes.get_mut(&parent)?;
        let before = parent.children.len();
        parent.children.retain(|&(_, child)| child != node);
        if parent.children.len() == before {
            return None;
        }
        let open = hive.handles.values().any(|entry| entry.node == node);
        retire(hive, node, open);
        if let Some((identifier, cell)) = cell {
            cell_op(hive, identifier, cell, |storage| key_cells::delete_key(storage, cell, now()));
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
/// hook de remoção controla a exclusividade da operação. O último handle de
/// uma chave excluída leva o nó dela.
pub fn close_raw(handle: u32) -> bool {
    if !with_hive(|hive| hive.handles.contains_key(&handle)) {
        return false;
    }
    let hooks = *HOOKS.lock();
    let detach = move || {
        let removed = with_hive(|hive| {
            let Some(entry) = hive.handles.remove(&handle) else { return false };
            update_statistics(hive);
            handle_ids::release(handle);
            if hive.nodes.get(&entry.node).is_some_and(|key| key.deleted) && !hive.handles.values().any(|other| other.node == entry.node) {
                hive.nodes.remove(&entry.node);
            }
            true
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

/// Grava um valor no nó: nas células de uma chave guardada numa hive (o
/// 'vk' do valor que já existe com esse nome, sem diferença de caixa, ou um
/// novo no fim da lista), no próprio nó sem célula. O valor que já existe
/// fica com o nome e a posição dele e troca só o tipo e o dado
/// (CmpSetValueKeyExisting, rva 0x6df998). Devolve se gravou.
fn store_value(hive: &mut Hive, node: NodeId, name: &str, value_type: u32, data: Vec<u8>, time: u64) -> bool {
    let lower = name.to_lowercase();
    let Some(key) = hive.view(node) else { return false };
    if let Some((identifier, cell)) = key.cell {
        let existing = key.value_cell(&lower);
        return cell_op(hive, identifier, cell, |storage| key_cells::set_value_at(storage, cell, existing, name, value_type, &data, time));
    }
    let Some(owned) = hive.nodes.get_mut(&node).and_then(|key| key.owned.as_mut()) else { return false };
    match owned.values.iter_mut().find(|value| same_name(&value.name, &lower)) {
        Some(slot) => {
            slot.value_type = value_type;
            slot.data = data;
        }
        None => owned.values.push(Value { name: name.to_string(), value_type, data }),
    }
    owned.last_write_time = time;
    true
}

/// O LastWriteTime de um nó (nas células, ou no próprio nó).
fn store_last_write_time(hive: &mut Hive, node: NodeId, time: u64) {
    let Some(key) = hive.nodes.get_mut(&node) else { return };
    if let Some(owned) = key.owned.as_mut() {
        owned.last_write_time = time;
        return;
    }
    let Some((identifier, cell)) = key.cell else { return };
    cell_op(hive, identifier, cell, |storage| {
        key_cells::set_last_write_time(storage, cell, time);
        Some(())
    });
}

/// Grava o valor, atualiza LastWriteTime e avisa os observadores
/// (CmSetValueKey: REG_NOTIFY_CHANGE_LAST_SET na chave). Uma chave excluída
/// ou células sem espaço deixam tudo como estava.
pub fn set_node_value(node: NodeId, path: &str, name: &str, value_type: u32, data: Vec<u8>) -> bool {
    let written = with_hive(|hive| {
        if !live(hive, node) || !store_value(hive, node, name, value_type, data, now()) {
            return None;
        }
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
    with_hive(|hive| hive.view(node)?.value(&name.to_lowercase()))
}

pub fn delete_value(handle: u32, name: &str) -> bool {
    let Some(entry) = with_hive(|hive| hive.handles.get(&handle).cloned()) else { return false };
    delete_node_value(entry.node, &entry.path, name)
}

/// Tira o valor de nome `lower` (já em minúsculas) do nó; `false` se ele
/// não existe.
fn remove_value(hive: &mut Hive, node: NodeId, lower: &str, time: u64) -> bool {
    let Some(key) = hive.view(node) else { return false };
    if let Some((identifier, cell)) = key.cell {
        let Some(value) = key.value_cell(lower) else { return false };
        return cell_op(hive, identifier, cell, |storage| key_cells::delete_value_at(storage, cell, value, time));
    }
    let Some(owned) = hive.nodes.get_mut(&node).and_then(|key| key.owned.as_mut()) else { return false };
    let before = owned.values.len();
    owned.values.retain(|value| !same_name(&value.name, lower));
    if owned.values.len() == before {
        return false;
    }
    owned.last_write_time = time;
    true
}

/// Remove um valor existente e só então atualiza o tempo e notifica
/// (CmDeleteValueKey: REG_NOTIFY_CHANGE_LAST_SET na chave).
pub fn delete_node_value(node: NodeId, path: &str, name: &str) -> bool {
    let removed = with_hive(|hive| {
        if !live(hive, node) || !remove_value(hive, node, &name.to_lowercase(), now()) {
            return None;
        }
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

/// Os nós vivos na arena e os blocos dela (para a medida do heap).
pub fn arena_counts() -> (usize, usize) {
    with_hive(|hive| hive.nodes.counts())
}

/// Lê um nó com as células dele (sem chamar o registro de dentro da
/// closure).
pub fn with_node<T>(node: NodeId, body: impl FnOnce(&KeyView) -> T) -> Option<T> {
    with_hive(|hive| hive.view(node).map(|view| body(&view)))
}

/// Altera os campos de um nó da arena (descritor, flags).
pub fn with_node_mut<T>(node: NodeId, body: impl FnOnce(&mut KeyNode) -> T) -> Option<T> {
    with_hive(|hive| hive.nodes.get_mut(&node).map(body))
}

/// Subchaves vivas em ordem de inserção.
pub fn children(node: NodeId) -> Vec<NodeId> {
    with_node(node, |key| key.children.iter().map(|&(_, child)| child).collect()).unwrap_or_default()
}

/// A subchave `index` na ordem de inserção.
pub fn child_at(node: NodeId, index: usize) -> Option<NodeId> {
    with_node(node, |key| key.children.get(index).map(|&(_, child)| child)).flatten()
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

/// Liga as chaves de uma hive conferida (`tree::check`) em `path`
/// (CmpLinkHiveToMaster): o pai precisa existir e o nome não (o vínculo
/// sobre uma chave existente é STATUS_OBJECT_NAME_COLLISION, como no
/// CmpDoParseKey com CreateLink). Cada chave vira um nó com a célula dela,
/// sem cópia do conteúdo, e o descritor compartilhado da célula 'sk'. Em
/// falha as células voltam ao chamador.
pub fn link_hive(path: &str, identifier: u32, storage: Storage, checked: Checked) -> Result<NodeId, (u32, Storage)> {
    let components = split_path(path);
    let Some((name, parents)) = components.split_last() else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
    let parent_path = parents.join("\\");
    let linked = with_hive(|hive| {
        let Some(parent) = find(hive, &parent_path) else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
        if child_of(hive, parent, &name.to_lowercase()).is_some() {
            return Err((STATUS_OBJECT_NAME_COLLISION, storage));
        }
        let first = hive.next_node;
        let walked = tree::preorder(&storage, |cell, parent_node: Option<NodeId>| {
            let node = key_cells::node(&storage, cell).ok_or(crate::ntos::cm::hive::storage::STATUS_REGISTRY_CORRUPT)?;
            let security = checked.descriptor(node.security.get()).ok_or(crate::ntos::cm::hive::storage::STATUS_REGISTRY_CORRUPT)?;
            let mut key = KeyNode::stored(Some(parent_node.unwrap_or(parent)), security, identifier, cell, node.flags.get() & key_cells::KEY_SYM_LINK != 0);
            key.children = Vec::with_capacity(node.sub_key_counts[0].get() as usize);
            let hash = match parent_node {
                Some(_) => key_cells::key_name_units(&storage, cell).map_or(0, |units| hash_chars(lossy_chars(units.iter()))),
                None => {
                    // A raiz tem o nome do ponto de montagem.
                    key.name = Some(Box::from(*name));
                    name_hash(name)
                }
            };
            let id = hive.allocate_id();
            hive.nodes.insert(id, key);
            if let Some(parent_key) = hive.nodes.get_mut(&parent_node.unwrap_or(parent)) {
                parent_key.children.push((hash, id));
            }
            Ok(id)
        });
        if let Err(status) = walked {
            // Desfaz o vínculo parcial.
            if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                parent_key.children.retain(|&(_, child)| child != first);
            }
            for id in first..hive.next_node {
                hive.nodes.remove(&id);
            }
            return Err((status, storage));
        }
        hive.storages.insert(identifier, (storage, first));
        Ok(first)
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
    let open = open_nodes(hive);
    nodes.iter().any(|node| open.contains(node))
}

/// Caminho absoluto de um nó pelos nomes.
fn node_path(hive: &Hive, node: NodeId) -> String {
    let mut names = Vec::new();
    let mut current = Some(node);
    while let Some(id) = current.filter(|&id| id != ROOT) {
        let Some(key) = hive.view(id) else { break };
        names.push(key.name());
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
/// os handles apontando para chaves excluídas. Os nós da hive saem da arena
/// (os com handle ficam excluídos até o último fechar). Devolve as células.
pub fn unlink_hive(identifier: u32, force: bool) -> Result<Storage, u32> {
    let (storage, path, parent_chain) = with_hive(|hive| {
        let Some(&(_, root)) = hive.storages.get(&identifier) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        let nodes = subtree(hive, root);
        let open = open_nodes(hive);
        if !force && nodes.iter().any(|node| open.contains(node)) {
            return Err(STATUS_CANNOT_DELETE);
        }
        let path = node_path(hive, root);
        let parent = hive.nodes.get(&root).and_then(|key| key.parent);
        let parent_chain = parent.map(|parent| ancestry(hive, parent)).unwrap_or_default();
        if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
            parent.children.retain(|&(_, child)| child != root);
        }
        for &node in &nodes {
            retire(hive, node, open.contains(&node));
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
    with_hive(|hive| live(hive, node).then(|| node_path(hive, node)))
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
        hive.nodes.get(&node).filter(|key| !key.deleted && !key.volatile)?;
        let mut keys: Vec<NewKey> = Vec::new();
        let mut stack: Vec<(NodeId, Option<usize>)> = alloc::vec![(node, None)];
        while let Some((current, parent)) = stack.pop() {
            let Some(key) = hive.view(current).filter(|key| !key.deleted && !key.volatile) else { continue };
            let index = keys.len();
            keys.push(NewKey { name: key.name(), last_write_time: key.last_write_time(), security: Captured::clone(&key.security), values: key.values(), parent, link: key.link, class: key.class() });
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

/// Os handles internos abertos em chaves da subárvore de `node` (o próprio
/// nó incluído) guardadas pela mesma hive, com o caminho de cada chave (o
/// nome que o CmpConstructNameWithStatus monta para o KCB): primeiro os do
/// próprio nó (o CmpDumpKeyBodyList do KCB pedido), depois os dos
/// descendentes (o CmpEnumerateAllOpenSubKeys, rva 0x66d0e4, que percorre
/// só a tabela de KCBs da hive do KCB: as hives montadas abaixo ficam fora).
pub fn open_handles_in_hive(node: NodeId) -> Vec<(u32, String)> {
    with_hive(|hive| {
        let owner = owning_hive_of(hive, node);
        let mut by_node: BTreeMap<NodeId, Vec<u32>> = BTreeMap::new();
        for (&handle, entry) in &hive.handles {
            by_node.entry(entry.node).or_default().push(handle);
        }
        let mut opened = Vec::new();
        for candidate in subtree(hive, node) {
            let Some(handles) = by_node.get(&candidate) else { continue };
            if owning_hive_of(hive, candidate) != owner {
                continue;
            }
            let path = node_path(hive, candidate);
            opened.extend(handles.iter().map(|&handle| (handle, path.clone())));
        }
        opened
    })
}

fn status_of(error: KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }
}

/// CmRestoreKey: troca as subchaves e os valores do nó pelos da hive
/// conferida `source` (a raiz dela é a do nó), pelas mesmas operações de
/// célula das chaves comuns. O descritor do próprio nó fica.
pub fn restore_subtree(node: NodeId, source: &Storage, checked: &Checked) -> Result<(), KernelError> {
    let path = with_hive(|hive| -> Result<String, KernelError> {
        if !live(hive, node) {
            return Err(KernelError::with_status("registry: key is gone", STATUS_KEY_DELETED));
        }
        let mut nodes = subtree(hive, node);
        nodes.retain(|&candidate| candidate != node);
        let open = open_nodes(hive);
        for &child in nodes.iter().rev() {
            let (parent, cell) = hive.nodes.get(&child).map_or((None, None), |key| (key.parent, key.cell));
            if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.children.retain(|&(_, candidate)| candidate != child);
            }
            retire(hive, child, open.contains(&child));
            if let Some((identifier, cell)) = cell {
                cell_op(hive, identifier, cell, |storage| key_cells::delete_key(storage, cell, now()));
            }
        }
        let names = hive.view(node).map(|key| key.value_names()).unwrap_or_default();
        for name in names {
            remove_value(hive, node, &name.to_lowercase(), now());
        }
        tree::preorder(source, |cell, parent: Option<NodeId>| {
            let key = tree::record(source, checked, cell, None)?;
            let target = match parent {
                None => node,
                Some(parent) => {
                    let child = create_node(hive, &key.name, parent, Some(key.security), false, key.link, &key.class).map_err(status_of)?;
                    if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                        parent_key.children.push((name_hash(&key.name), child));
                    }
                    child
                }
            };
            for value in key.values {
                store_value(hive, target, &value.name, value.value_type, value.data, now());
            }
            store_last_write_time(hive, target, key.last_write_time);
            Ok(target)
        })
        .map_err(|status| KernelError::with_status("registry: restore failed", status))?;
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
    let parent_security = with_hive(|hive| find(hive, &parents.join("\\")).and_then(|parent| hive.nodes.get(&parent)).map(|parent| parent.security.clone())).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let security = key_policy::boot_child(&parent_security).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let root = NewKey { name: String::from(*name), last_write_time: now(), security, values: Vec::new(), parent: None, link: false, class: Vec::new() };
    let (storage, _) = tree::build(&[root], 5, now(), "").ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let checked = tree::check(&storage)?;
    link_hive(path, identifier, storage, checked).map_err(|(status, _)| status)
}

/// CmpRefreshHive: as células da hive viram as relidas do arquivo
/// (conferidas por `tree::check`) e a árvore é reconciliada com elas. Uma
/// chave que existe nas duas fica com o mesmo nó (os handles continuam
/// valendo), agora com a célula do arquivo (valores, descritor e
/// LastWriteTime vêm dela); uma chave que só existe na memória (inclusive
/// as voláteis) é excluída; uma que só existe no arquivo é criada.
pub fn refresh_hive(identifier: u32, storage: Storage, checked: Checked) -> Result<(), u32> {
    let path = with_hive(|hive| -> Result<String, u32> {
        let Some(&(_, root)) = hive.storages.get(&identifier) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        let old: Vec<NodeId> = subtree(hive, root);
        let mut kept: BTreeSet<NodeId> = BTreeSet::new();
        // As chaves que ficam recebem a célula nova só depois do passeio:
        // até lá os nomes delas vêm das células antigas.
        let mut assigned: Vec<(NodeId, u32, Arc<Captured>, bool)> = Vec::with_capacity(checked.keys);
        tree::preorder(&storage, |cell, parent: Option<NodeId>| {
            let key = key_cells::node(&storage, cell).ok_or(crate::ntos::cm::hive::storage::STATUS_REGISTRY_CORRUPT)?;
            let security = checked.descriptor(key.security.get()).ok_or(crate::ntos::cm::hive::storage::STATUS_REGISTRY_CORRUPT)?;
            let link = key.flags.get() & key_cells::KEY_SYM_LINK != 0;
            let node = match parent {
                None => {
                    assigned.push((root, cell, security, link));
                    root
                }
                Some(parent) => {
                    let name = key_cells::key_name_units(&storage, cell).map(|units| units.to_string_lossy()).unwrap_or_default();
                    let lower = name.to_lowercase();
                    let hash = name_hash(&lower);
                    let existing = hive.nodes.get(&parent).and_then(|parent| parent.children.iter().filter(|&&(candidate, child)| candidate == hash && !kept.contains(&child)).map(|&(_, child)| child).find(|&child| hive.view(child).is_some_and(|key| key.name_is(&lower))));
                    match existing {
                        Some(child) => {
                            assigned.push((child, cell, security, link));
                            child
                        }
                        None => {
                            let mut node = KeyNode::stored(Some(parent), security, identifier, cell, link);
                            node.children = Vec::with_capacity(key.sub_key_counts[0].get() as usize);
                            let child = hive.allocate_id();
                            hive.nodes.insert(child, node);
                            if let Some(parent_key) = hive.nodes.get_mut(&parent) {
                                parent_key.children.push((hash, child));
                            }
                            child
                        }
                    }
                }
            };
            kept.insert(node);
            Ok(node)
        })?;
        let open = open_nodes(hive);
        for node in old.into_iter().filter(|node| !kept.contains(node)) {
            let parent = hive.nodes.get(&node).and_then(|key| key.parent);
            if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.children.retain(|&(_, child)| child != node);
            }
            retire(hive, node, open.contains(&node));
        }
        for (node, cell, security, link) in assigned {
            if let Some(entry) = hive.nodes.get_mut(&node) {
                entry.cell = Some((identifier, cell));
                entry.security = security;
                entry.link = link;
                entry.volatile = false;
                entry.owned = None;
                if node != root {
                    entry.name = None;
                }
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
