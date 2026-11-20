//! O namespace do Registro do Configuration Manager.
//!
//! Árvore de chaves e valores sem diferença entre maiúsculas e minúsculas. Os
//! handles internos identificam nós e caminhos; as fronteiras de syscall
//! acrescentam direitos, captura e notificações nativas.
//!
//! Um nó faz o papel do KCB do 19041 e só existe enquanto alguém o usa
//! (CmpCreateKeyControlBlock, CmpDereferenceKeyControlBlock): um handle
//! aberto na chave, uma subchave viva (o filho segura o pai) ou a fixação
//! das chaves que não têm célula (as chaves mestras, as voláteis, as
//! subárvores montadas em memória) e da raiz de cada hive montada. Um nó de
//! uma chave guardada numa hive é criado quando um nome passa por ela e,
//! sem referências, vai para a lista de fechamento adiado
//! (CmpAddToDelayedClose), de onde volta se a chave é aberta de novo; a
//! lista guarda no máximo [`DELAYED_CLOSE`] nós (o CmpDelayedCloseSize,
//! 0x800 no 19041) e o mais antigo sai da arena. Cada célula 'nk' tem no
//! máximo um nó vivo (o mapa por célula, o papel do
//! CmpFindKcbInHashEntryByCellIndex). O [`NodeId`] nunca se repete: um id
//! guardado de um nó que já saiu da arena só deixa de valer.
//!
//! O conteúdo de uma chave guardada numa hive (nome, valores, classe,
//! LastWriteTime, subchaves) não é copiado para o nó: ele fica nas células
//! e é lido delas a cada consulta ([`KeyView`]), como o 19041 lê pelo mapa
//! de células. A busca de uma subchave pelo nome é a busca binária no
//! índice dela (CmpFindSubKeyByName) e a enumeração anda pelo índice
//! (CmpFindSubKeyByNumber): primeiro as subchaves da hive em ordem de nome,
//! depois as que só existem em memória (as voláteis), também em ordem de
//! nome. Toda mudança numa chave dessas (chave criada ou excluída, valor
//! gravado ou removido, descritor trocado) vai direto às células, sob a
//! mesma trava, marcando os setores sujos que a descarga grava; uma
//! operação de célula que falha não muda a chave, marca a hive como
//! quebrada e a descarga dela passa a falhar. Os nós sem célula guardam o
//! próprio conteúdo. A raiz de uma hive carregada tem o nome do ponto de
//! montagem (o nome do link na hive mestra), não o da célula.
//!
//! Uma chave excluída (ou de uma hive descarregada) sai da arena na hora;
//! com handle aberto, fica só o nome e o LastWriteTime (o KCB excluído),
//! sem valores, classe nem subchaves, até o último handle fechar.
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
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::num::NonZeroU64;
use core::ops::{Deref, Index};

use crate::ntos::cm::hive::storage::{Storage, STATUS_INSUFFICIENT_RESOURCES, STATUS_REGISTRY_CORRUPT};
use crate::ntos::cm::hive::tree::{self, Checked, NewKey};
use crate::ntos::cm::hive::{index, key_cells, security_cells};
use crate::ntos::cm::key::notify as key_notify;
use crate::ntos::cm::key::policy as key_policy;
use crate::ntos::ke::clock;
use crate::ntos::ob::handle_ids;
use crate::ntos::se::inherit_descriptor::Captured;
use crate::rtl::{KernelError, SpinLock};

pub type NodeId = u64;
pub const ROOT: NodeId = 1;

/// Os nós sem referências que a lista de fechamento adiado guarda (o
/// CmpDelayedCloseSize do 19041, lido em .data 0xc12128).
pub const DELAYED_CLOSE: usize = 0x800;

/// Valor: nome preservado para exibição, tipo REG_* e bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Value {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
}

/// Nó da arena (o KCB): pai, as subchaves que as células não dão, o
/// descritor (compartilhado entre as chaves da mesma célula 'sk'), as flags
/// e as referências. O conteúdo vem das células ([`KeyView`]); só um nó
/// sem célula guarda o dele.
#[derive(Clone, Debug)]
pub struct KeyNode {
    parent: Option<NonZeroU64>,
    /// As subchaves vivas que não estão nas células da chave: as sem célula
    /// (voláteis, mestras) e as raízes de hive montadas aqui, em ordem de
    /// nome, cada uma com o hash do nome sem caixa ([`name_hash`]).
    linked: Vec<(u32, NodeId)>,
    pub security: Arc<Captured>,
    pub deleted: bool,
    /// (hive, célula 'nk') de um nó guardado numa hive.
    pub cell: Option<(u32, u32)>,
    /// Criado com REG_OPTION_VOLATILE (ou abaixo de uma chave volátil).
    pub volatile: bool,
    /// Chave de link (REG_OPTION_CREATE_LINK, KEY_SYM_LINK na célula).
    pub link: bool,
    /// O nome quando ele não vem da célula (os nós sem célula, a raiz de
    /// uma hive carregada e as chaves excluídas com handle aberto) e o
    /// conteúdo de um nó sem célula.
    extra: Option<Box<Extra>>,
    /// Handles abertos na chave, subchaves vivas na arena e a fixação de um
    /// nó sem célula ou da raiz de uma hive montada.
    refs: u32,
    /// A marca do nó na lista de fechamento adiado (zero: fora dela).
    delayed: u64,
}

const _: () = assert!(core::mem::size_of::<KeyNode>() <= 80);

/// O que um nó guarda além da identidade: o nome que não vem da célula e,
/// sem célula, o conteúdo.
#[derive(Clone, Debug)]
struct Extra {
    name: Box<str>,
    owned: Option<OwnedKey>,
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
    /// Um nó que guarda o próprio conteúdo (sem célula), fixado.
    fn in_memory(name: &str, parent: Option<NodeId>, security: Arc<Captured>, volatile: bool, link: bool, class: &[u16], time: u64) -> KeyNode {
        let owned = OwnedKey { values: Vec::new(), class: class.to_vec(), last_write_time: time };
        KeyNode { parent: parent.and_then(NonZeroU64::new), linked: Vec::new(), security, deleted: false, cell: None, volatile, link, extra: Some(Box::new(Extra { name: Box::from(name), owned: Some(owned) })), refs: 1, delayed: 0 }
    }

    /// Um nó de uma chave guardada na célula 'nk' `cell` da hive `hive`,
    /// ainda sem referências.
    fn stored(parent: Option<NodeId>, security: Arc<Captured>, hive: u32, cell: u32, link: bool) -> KeyNode {
        KeyNode { parent: parent.and_then(NonZeroU64::new), linked: Vec::new(), security, deleted: false, cell: Some((hive, cell)), volatile: false, link, extra: None, refs: 0, delayed: 0 }
    }

    /// O pai (nenhum só na raiz do Registro).
    pub fn parent(&self) -> Option<NodeId> {
        self.parent.map(NonZeroU64::get)
    }

    fn name_override(&self) -> Option<&str> {
        self.extra.as_deref().map(|extra| &*extra.name)
    }

    fn owned(&self) -> Option<&OwnedKey> {
        self.extra.as_deref().and_then(|extra| extra.owned.as_ref())
    }

    fn owned_mut(&mut self) -> Option<&mut OwnedKey> {
        self.extra.as_deref_mut().and_then(|extra| extra.owned.as_mut())
    }
}

/// O que o KeyFullInformation e o KeyCachedInformation contam de uma
/// chave: subchaves, valores e os maiores comprimentos (bytes de UTF-16 e
/// de dados).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyCounts {
    pub subkeys: u32,
    pub max_name: u32,
    pub max_class: u32,
    pub values: u32,
    pub max_value_name: u32,
    pub max_value_data: u32,
}

/// Um nó com as células da hive dele: o nome, os valores, a classe e o
/// LastWriteTime lidos das células (ou do próprio nó, sem célula). Os
/// campos do nó (`security`, `deleted`, `cell`, `link`...) ficam acessíveis
/// pelo `Deref`.
pub struct KeyView<'a> {
    node: &'a KeyNode,
    hive: &'a Hive,
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
        let (identifier, cell) = self.node.cell?;
        Some((&self.hive.storages.get(&identifier)?.storage, cell))
    }

    fn name_units(&self) -> Option<key_cells::Units<'a>> {
        self.stored().and_then(|(storage, cell)| key_cells::key_name_units(storage, cell))
    }

    /// As subchaves vivas sem célula (voláteis e raízes de hive), em ordem.
    fn linked_views(&self) -> impl Iterator<Item = KeyView<'a>> + '_ {
        self.node.linked.iter().filter_map(|&(_, child)| self.hive.view(child)).filter(|child| !child.deleted)
    }

    /// O nome da chave.
    pub fn name(&self) -> String {
        match self.node.name_override() {
            Some(name) => name.to_string(),
            None => self.name_units().map(|units| units.to_string_lossy()).unwrap_or_default(),
        }
    }

    /// O nome em UTF-16.
    pub fn name_utf16(&self) -> Vec<u16> {
        match self.node.name_override() {
            Some(name) => name.encode_utf16().collect(),
            None => self.name_units().map(|units| units.to_vec()).unwrap_or_default(),
        }
    }

    /// O nome é `lower` (já em minúsculas), sem diferença de caixa.
    pub fn name_is(&self, lower: &str) -> bool {
        match self.node.name_override() {
            Some(name) => same_name(name, lower),
            None => self.name_units().is_some_and(|units| same_chars(lossy_chars(units.iter()), lower.chars())),
        }
    }

    /// O tamanho do nome em bytes de UTF-16.
    pub fn name_length(&self) -> u32 {
        match self.node.name_override() {
            Some(name) => name.encode_utf16().count() as u32 * 2,
            None => self.name_units().map_or(0, |units| units.len() as u32 * 2),
        }
    }

    /// LastWriteTime em 100 ns desde 1601.
    pub fn last_write_time(&self) -> u64 {
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.last_write_time,
            (None, Some((storage, cell))) => key_cells::last_write_time(storage, cell),
            (None, None) => 0,
        }
    }

    /// A classe em UTF-16 (vazia sem classe).
    pub fn class(&self) -> Vec<u16> {
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.class.clone(),
            (None, Some((storage, cell))) => key_cells::class_units(storage, cell),
            (None, None) => Vec::new(),
        }
    }

    /// O tamanho da classe em bytes.
    pub fn class_length(&self) -> u32 {
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.class.len() as u32 * 2,
            (None, Some((storage, cell))) => key_cells::class_length(storage, cell),
            (None, None) => 0,
        }
    }

    /// Quantas subchaves a chave tem: as da hive (SubKeyCounts[Stable]) e
    /// as que só existem em memória.
    pub fn subkey_count(&self) -> usize {
        self.stored().map_or(0, |(storage, cell)| key_cells::sub_key_count(storage, cell) as usize) + self.linked_views().count()
    }

    /// Os nomes das subchaves, na ordem da enumeração.
    pub fn subkey_names(&self) -> Vec<String> {
        let mut names: Vec<String> = match self.stored() {
            Some((storage, cell)) => (0..key_cells::sub_key_count(storage, cell) as usize).filter_map(|index| key_cells::nth_subkey(storage, cell, index)).filter_map(|child| key_cells::key_name_units(storage, child)).map(|units| units.to_string_lossy()).collect(),
            None => Vec::new(),
        };
        names.extend(self.linked_views().map(|child| child.name()));
        names
    }

    /// As contagens e os máximos do KeyFullInformation. Numa chave guardada
    /// numa hive os máximos são os que o 'nk' guarda (MaxNameLen,
    /// MaxClassLen, MaxValueNameLen e MaxValueDataLen: os maiores que a
    /// chave já teve, como o CmpQueryKeyData lê do KCB), somados às
    /// subchaves que só existem em memória; sem célula, os de agora.
    pub fn counts(&self) -> KeyCounts {
        let mut counts = KeyCounts::default();
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => {
                counts.values = owned.values.len() as u32;
                counts.max_value_name = owned.values.iter().map(|value| value.name.encode_utf16().count() as u32 * 2).max().unwrap_or(0);
                counts.max_value_data = owned.values.iter().map(|value| value.data.len() as u32).max().unwrap_or(0);
            }
            (None, Some((storage, cell))) => {
                let (name, class, value_name, value_data) = key_cells::maxima(storage, cell);
                counts.subkeys = key_cells::sub_key_count(storage, cell);
                counts.max_name = name;
                counts.max_class = class;
                counts.values = key_cells::value_count(storage, cell);
                counts.max_value_name = value_name;
                counts.max_value_data = value_data;
            }
            (None, None) => {}
        }
        for child in self.linked_views() {
            counts.subkeys += 1;
            counts.max_name = counts.max_name.max(child.name_length());
            counts.max_class = counts.max_class.max(child.class_length());
        }
        counts
    }

    /// Quantos valores a chave tem.
    pub fn value_count(&self) -> usize {
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.values.len(),
            (None, Some((storage, cell))) => key_cells::value_count(storage, cell) as usize,
            (None, None) => 0,
        }
    }

    /// A cópia do valor `index`, na ordem da chave.
    pub fn value_at(&self, index: usize) -> Option<Value> {
        match (self.node.owned(), self.stored()) {
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
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.values.iter().find(|value| same_name(&value.name, lower)).cloned(),
            (None, Some((storage, _))) => key_cells::read_value(storage, self.value_cell(lower)?),
            (None, None) => None,
        }
    }

    /// A chave tem o valor de nome `lower` (já em minúsculas)?
    pub fn has_value(&self, lower: &str) -> bool {
        match self.node.owned() {
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
        match (self.node.owned(), self.stored()) {
            (Some(owned), _) => owned.values.iter().map(|value| value.name.clone()).collect(),
            (None, Some((storage, cell))) => (0..key_cells::value_count(storage, cell)).filter_map(|index| key_cells::value_cell(storage, cell, index)).filter_map(|value| key_cells::value_name_units(storage, value)).map(|units| units.to_string_lossy()).collect(),
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

/// Hash do nome sem diferença de caixa (FNV-1a sobre os caracteres em
/// maiúsculas): nomes iguais por [`same_name`] têm o mesmo hash.
pub fn name_hash(name: &str) -> u32 {
    name.chars().flat_map(char::to_uppercase).fold(0x811C_9DC5u32, |hash, character| (hash ^ character as u32).wrapping_mul(0x0100_0193))
}

/// Uma posição da arena: a geração (que muda a cada reuso, para um id
/// antigo não achar o nó novo) e o nó.
struct Slot {
    generation: u32,
    node: Option<KeyNode>,
}

/// Posições por bloco da arena.
pub const CHUNK: usize = 128;

/// A arena dos nós vivos: posições em blocos de [`CHUNK`], reusadas pela
/// lista de livres. O NodeId é a geração nos 32 bits altos e a posição nos
/// baixos (a posição 0 não é usada: nenhum id é zero).
#[derive(Default)]
struct NodeArena {
    chunks: Vec<Box<[Slot]>>,
    free: Vec<u32>,
    live: usize,
}

impl NodeArena {
    fn slot(&self, id: NodeId) -> Option<&Slot> {
        let index = (id & 0xFFFF_FFFF) as usize;
        let slot = self.chunks.get(index / CHUNK)?.get(index % CHUNK)?;
        (slot.generation == (id >> 32) as u32).then_some(slot)
    }

    fn get(&self, id: &NodeId) -> Option<&KeyNode> {
        self.slot(*id)?.node.as_ref()
    }

    fn get_mut(&mut self, id: &NodeId) -> Option<&mut KeyNode> {
        let index = (*id & 0xFFFF_FFFF) as usize;
        let slot = self.chunks.get_mut(index / CHUNK)?.get_mut(index % CHUNK)?;
        if slot.generation != (*id >> 32) as u32 {
            return None;
        }
        slot.node.as_mut()
    }

    fn contains_key(&self, id: &NodeId) -> bool {
        self.get(id).is_some()
    }

    fn insert(&mut self, node: KeyNode) -> NodeId {
        if self.free.is_empty() {
            let base = (self.chunks.len() * CHUNK) as u32;
            let mut slots = Vec::with_capacity(CHUNK);
            slots.resize_with(CHUNK, || Slot { generation: 0, node: None });
            self.chunks.push(slots.into_boxed_slice());
            // As posições mais baixas saem primeiro; a 0 nunca.
            self.free.extend((base.max(1)..base + CHUNK as u32).rev());
        }
        let index = self.free.pop().expect("posicao livre na arena do Registro") as usize;
        let slot = &mut self.chunks[index / CHUNK][index % CHUNK];
        slot.node = Some(node);
        self.live += 1;
        ((slot.generation as u64) << 32) | index as u64
    }

    fn remove(&mut self, id: &NodeId) -> Option<KeyNode> {
        let index = (*id & 0xFFFF_FFFF) as usize;
        let slot = self.chunks.get_mut(index / CHUNK)?.get_mut(index % CHUNK)?;
        if slot.generation != (*id >> 32) as u32 {
            return None;
        }
        let node = slot.node.take()?;
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(index as u32);
        self.live -= 1;
        Some(node)
    }

    /// Os ids dos nós vivos.
    fn ids(&self) -> Vec<NodeId> {
        let mut ids = Vec::with_capacity(self.live);
        for (chunk_index, chunk) in self.chunks.iter().enumerate() {
            for (offset, slot) in chunk.iter().enumerate() {
                if slot.node.is_some() {
                    ids.push(((slot.generation as u64) << 32) | (chunk_index * CHUNK + offset) as u64);
                }
            }
        }
        ids
    }

    /// Nós vivos e blocos alocados.
    fn counts(&self) -> (usize, usize) {
        (self.live, self.chunks.len())
    }
}

impl Index<&NodeId> for NodeArena {
    type Output = KeyNode;

    fn index(&self, id: &NodeId) -> &KeyNode {
        self.get(id).expect("no ausente da arena do Registro")
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

/// Uma hive ligada ao namespace: as células, o nó da raiz (fixado enquanto
/// a hive está montada) e o descritor de cada célula 'sk' já lida (o
/// CmpSecurityCache da hive).
struct LoadedCells {
    storage: Storage,
    root: NodeId,
    security: BTreeMap<u32, Arc<Captured>>,
}

impl LoadedCells {
    /// O descritor da célula 'sk' `cell`, do cache ou lido da célula.
    fn descriptor(&mut self, cell: u32) -> Option<Arc<Captured>> {
        if let Some(found) = self.security.get(&cell).filter(|_| security_cells::reference_count(&self.storage, cell).is_some()) {
            return Some(found.clone());
        }
        let read = Arc::new(security_cells::read(&self.storage, cell).ok()?);
        self.security.insert(cell, read.clone());
        Some(read)
    }

    /// Tira do cache uma célula 'sk' que deixou de existir.
    fn forget_descriptor(&mut self, cell: u32) {
        if security_cells::reference_count(&self.storage, cell).is_none() {
            self.security.remove(&cell);
        }
    }
}

struct Hive {
    nodes: NodeArena,
    handles: BTreeMap<u32, HandleEntry>,
    statistics: ObjectStatistics,
    /// As hives carregadas.
    storages: BTreeMap<u32, LoadedCells>,
    /// O nó vivo de cada célula 'nk': (hive, célula) -> nó.
    cells: BTreeMap<(u32, u32), NodeId>,
    /// A lista de fechamento adiado: marca (crescente) -> nó.
    delayed: BTreeMap<u64, NodeId>,
    clock: u64,
    /// Os nós que saíram da arena sob a trava (a identidade deles é
    /// liberada depois, fora dela).
    destroyed: Vec<NodeId>,
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
        Some(KeyView { node: self.nodes.get(&id)?, hive: self })
    }

    fn storage(&self, identifier: u32) -> Option<&Storage> {
        self.storages.get(&identifier).map(|loaded| &loaded.storage)
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

/// Registra a rotina chamada quando uma hive de arquivo fica suja.
pub fn set_dirty_observer(observer: Option<fn()>) {
    *DIRTY_OBSERVER.lock() = observer;
}

fn with_hive<T>(body: impl FnOnce(&mut Hive) -> T) -> T {
    let (result, dirtied, destroyed) = {
        let mut hive = HIVE.lock();
        let hive = hive.get_or_insert_with(|| {
            let mut nodes = NodeArena::default();
            let root = nodes.insert(KeyNode::in_memory("", None, Arc::new(key_policy::boot_root()), false, false, &[], now()));
            assert_eq!(root, ROOT);
            Hive { nodes, handles: BTreeMap::new(), statistics: ObjectStatistics::default(), storages: BTreeMap::new(), cells: BTreeMap::new(), delayed: BTreeMap::new(), clock: 0, destroyed: Vec::new(), trust: BTreeMap::new(), dirtied: false }
        });
        let result = body(hive);
        trim(hive);
        (result, core::mem::take(&mut hive.dirtied), core::mem::take(&mut hive.destroyed))
    };
    if !destroyed.is_empty() {
        crate::ntos::cm::key::objects::forget(&destroyed);
    }
    if dirtied {
        let observer = *DIRTY_OBSERVER.lock();
        if let Some(observer) = observer {
            observer();
        }
    }
    result
}

// ---- referências e fechamento adiado ----------------------------------------

/// Mais uma referência no nó; um nó na lista de fechamento adiado sai dela
/// (CmpRemoveFromDelayedClose).
fn add_ref(hive: &mut Hive, id: NodeId) {
    let Some(node) = hive.nodes.get_mut(&id) else { return };
    node.refs += 1;
    let stamp = core::mem::take(&mut node.delayed);
    if stamp != 0 {
        hive.delayed.remove(&stamp);
    }
}

/// Uma referência a menos (CmpDereferenceKeyControlBlock): sem nenhuma, a
/// chave excluída sai da arena (soltando o pai) e a guardada numa hive vai
/// para a lista de fechamento adiado.
fn release(hive: &mut Hive, id: NodeId) {
    let mut pending = Some(id);
    while let Some(id) = pending.take() {
        let Some(node) = hive.nodes.get_mut(&id) else { return };
        node.refs = node.refs.saturating_sub(1);
        if node.refs != 0 {
            return;
        }
        if node.deleted {
            pending = destroy(hive, id);
        } else if node.cell.is_some() {
            delay(hive, id);
        }
    }
}

/// CmpAddToDelayedClose: o nó sem referências entra no fim da lista.
fn delay(hive: &mut Hive, id: NodeId) {
    hive.clock += 1;
    let stamp = hive.clock;
    if let Some(node) = hive.nodes.get_mut(&id) {
        node.delayed = stamp;
        hive.delayed.insert(stamp, id);
    }
}

/// Tira o nó da arena (e do mapa por célula e da lista do pai). Devolve o
/// pai, cuja referência o chamador solta.
fn destroy(hive: &mut Hive, id: NodeId) -> Option<NodeId> {
    let node = hive.nodes.remove(&id)?;
    if node.delayed != 0 {
        hive.delayed.remove(&node.delayed);
    }
    if let Some(cell) = node.cell {
        if hive.cells.get(&cell) == Some(&id) {
            hive.cells.remove(&cell);
        }
    }
    let parent = node.parent();
    if let Some(parent_key) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
        parent_key.linked.retain(|&(_, child)| child != id);
    }
    hive.destroyed.push(id);
    parent
}

/// A lista de fechamento adiado volta ao limite: os mais antigos saem da
/// arena (o pai de cada um perde a referência e pode entrar na lista).
fn trim(hive: &mut Hive) {
    while hive.delayed.len() > DELAYED_CLOSE {
        let Some((&stamp, &id)) = hive.delayed.iter().next() else { break };
        hive.delayed.remove(&stamp);
        if let Some(node) = hive.nodes.get_mut(&id) {
            node.delayed = 0;
        }
        if let Some(parent) = destroy(hive, id) {
            release(hive, parent);
        }
    }
}

/// O nó da chave da célula `cell` da hive `identifier`, filha de `parent`:
/// o vivo, ou um novo (CmpCreateKeyControlBlock), sem referências e na
/// lista de fechamento adiado até alguém o usar.
fn materialize(hive: &mut Hive, parent: NodeId, identifier: u32, cell: u32) -> Option<NodeId> {
    if let Some(&id) = hive.cells.get(&(identifier, cell)) {
        return Some(id);
    }
    let loaded = hive.storages.get_mut(&identifier)?;
    let key = key_cells::node(&loaded.storage, cell)?;
    let (security_cell, link) = (key.security.get(), key.flags.get() & key_cells::KEY_SYM_LINK != 0);
    let security = loaded.descriptor(security_cell)?;
    let id = hive.nodes.insert(KeyNode::stored(Some(parent), security, identifier, cell, link));
    hive.cells.insert((identifier, cell), id);
    add_ref(hive, parent);
    delay(hive, id);
    Some(id)
}

/// O nome e o LastWriteTime que um nó guarda quando sai do namespace com
/// referências além da fixação (um handle aberto, uma subchave excluída que
/// ainda o segura). Lido antes de as células da chave serem liberadas.
fn tombstone_of(hive: &Hive, node: NodeId) -> Option<(String, u64)> {
    let key = hive.nodes.get(&node)?;
    let remaining = key.refs.saturating_sub(key.cell.is_none() as u32);
    if remaining == 0 {
        return None;
    }
    hive.view(node).map(|key| (key.name(), key.last_write_time()))
}

/// O nó sai do namespace (chave excluída, hive descarregada ou trocada):
/// sem referências além da fixação, a arena o libera; com handle aberto (ou
/// uma subchave excluída que ainda o segura), fica só o nome e o
/// LastWriteTime (o KCB excluído), até a última referência sair. Chamado
/// antes de as células dele serem liberadas: o nome ainda vem da célula.
fn retire(hive: &mut Hive, node: NodeId) {
    let tombstone = tombstone_of(hive, node);
    retire_as(hive, node, tombstone);
}

/// [`retire`] com o nome e o tempo já lidos ([`tombstone_of`]).
fn retire_as(hive: &mut Hive, node: NodeId, tombstone: Option<(String, u64)>) {
    let Some(key) = hive.nodes.get(&node) else { return };
    if key.deleted {
        return;
    }
    let pinned = key.cell.is_none();
    let remaining = key.refs.saturating_sub(pinned as u32);
    let Some(key) = hive.nodes.get_mut(&node) else { return };
    key.deleted = true;
    let cell = key.cell.take();
    let stamp = core::mem::take(&mut key.delayed);
    if let Some((name, time)) = tombstone.filter(|_| remaining > 0) {
        key.extra = Some(Box::new(Extra { name: name.into_boxed_str(), owned: Some(OwnedKey { values: Vec::new(), class: Vec::new(), last_write_time: time }) }));
    }
    if let Some(cell) = cell {
        if hive.cells.get(&cell) == Some(&node) {
            hive.cells.remove(&cell);
        }
    }
    if stamp != 0 {
        hive.delayed.remove(&stamp);
    }
    if pinned {
        release(hive, node);
    } else if remaining == 0 {
        if let Some(parent) = destroy(hive, node) {
            release(hive, parent);
        }
    }
}

/// Os nós vivos da subárvore de `root` (o próprio incluído), dos mais
/// fundos para os mais rasos.
fn live_subtree(hive: &Hive, root: NodeId) -> Vec<NodeId> {
    let mut found: Vec<(usize, NodeId)> = Vec::new();
    for id in hive.nodes.ids() {
        let mut depth = 0;
        let mut current = Some(id);
        while let Some(at) = current {
            if at == root {
                found.push((depth, id));
                break;
            }
            depth += 1;
            current = hive.nodes.get(&at).and_then(|key| key.parent());
        }
    }
    found.sort_unstable_by(|left, right| right.0.cmp(&left.0));
    found.into_iter().map(|(_, id)| id).collect()
}

/// `ancestor` é o próprio `node` ou um ancestral dele?
fn within(hive: &Hive, node: NodeId, ancestor: NodeId) -> bool {
    let mut current = Some(node);
    while let Some(at) = current {
        if at == ancestor {
            return true;
        }
        current = hive.nodes.get(&at).and_then(|key| key.parent());
    }
    false
}

// ---- nomes e caminhos ------------------------------------------------------

/// A subchave `name` de `node`: as vivas sem célula (sem caixa) e, numa
/// chave guardada numa hive, a da busca binária no índice
/// (CmpFindSubKeyByName), com o nó criado se faltar.
fn lookup_child(hive: &mut Hive, node: NodeId, name: &str) -> Option<NodeId> {
    let lower = name.to_lowercase();
    let hash = name_hash(&lower);
    let key = hive.nodes.get(&node)?;
    if let Some(child) = key.linked.iter().filter(|&&(candidate, _)| candidate == hash).map(|&(_, child)| child).find(|&child| hive.view(child).is_some_and(|key| !key.deleted && key.name_is(&lower))) {
        return Some(child);
    }
    let (identifier, cell) = key.cell?;
    let units: Vec<u16> = name.encode_utf16().collect();
    let child = key_cells::find_subkey(hive.storage(identifier)?, cell, &units)?;
    materialize(hive, node, identifier, child)
}

/// Insere uma subchave sem célula (volátil, mestra ou a raiz de uma hive
/// montada) na lista do pai, em ordem de nome sem caixa.
fn link_child(hive: &mut Hive, parent: NodeId, child: NodeId, name: &str) {
    let units: Vec<u16> = name.encode_utf16().collect();
    let position = match hive.nodes.get(&parent) {
        Some(key) => key.linked.partition_point(|&(_, other)| hive.view(other).is_some_and(|other| index::compare_units(other.name_utf16().into_iter(), &units) == Ordering::Less)),
        None => return,
    };
    if let Some(key) = hive.nodes.get_mut(&parent) {
        key.linked.insert(position, (name_hash(&name.to_lowercase()), child));
    }
}

/// Uma subchave na enumeração: um nó vivo ou uma célula da hive.
enum Child {
    Node(NodeId),
    Cell(u32, u32),
}

/// A subchave `index` na ordem da enumeração (CmpFindSubKeyByNumber): as
/// da hive pelo índice, depois as sem célula.
fn child_at_index(hive: &Hive, node: NodeId, index: usize) -> Option<Child> {
    let key = hive.nodes.get(&node)?;
    let mut index = index;
    if let Some((identifier, cell)) = key.cell {
        let storage = hive.storage(identifier)?;
        let stable = key_cells::sub_key_count(storage, cell) as usize;
        if index < stable {
            let child = key_cells::nth_subkey(storage, cell, index)?;
            return Some(match hive.cells.get(&(identifier, child)) {
                Some(&id) => Child::Node(id),
                None => Child::Cell(identifier, child),
            });
        }
        index -= stable;
    }
    key.linked.iter().map(|&(_, child)| child).filter(|child| hive.nodes.get(child).is_some_and(|key| !key.deleted)).nth(index).map(Child::Node)
}

/// A chave tem subchaves (na hive ou em memória)?
fn has_subkeys(hive: &Hive, node: NodeId) -> bool {
    hive.view(node).is_some_and(|key| key.subkey_count() != 0)
}

/// Uma mudança de célula: a hive que estava limpa avisa o escritor
/// preguiçoso depois de soltar a trava.
fn note_change(hive: &mut Hive, identifier: u32, was_dirty: bool) {
    if !was_dirty && hive.storage(identifier).is_some_and(Storage::is_dirty) {
        hive.dirtied = true;
    }
}

/// Aplica uma operação às células da hive `identifier` (a da chave da
/// célula `cell`). Uma falha marca a hive como quebrada: as células podem
/// ter ficado pela metade e a descarga fica recusada.
fn cell_op<T>(hive: &mut Hive, identifier: u32, cell: u32, change: impl FnOnce(&mut Storage) -> Option<T>) -> Option<T> {
    let loaded = hive.storages.get_mut(&identifier)?;
    let was_dirty = loaded.storage.is_dirty();
    let done = change(&mut loaded.storage);
    if done.is_none() {
        loaded.storage.broken = true;
        crate::debug_print!("[cm] hive {}: a mudanca na celula {:#x} falhou; a descarga fica recusada", identifier, cell);
    }
    note_change(hive, identifier, was_dirty);
    done
}

/// CmpFreeKeyByCell de uma chave sem subchaves, com a célula 'sk' dela
/// tirada do cache se deixou de existir.
fn free_key_cells(hive: &mut Hive, identifier: u32, cell: u32) -> bool {
    let security = hive.storage(identifier).and_then(|storage| key_cells::security_cell(storage, cell));
    let freed = cell_op(hive, identifier, cell, |storage| key_cells::delete_key(storage, cell, now())).is_some();
    if let (Some(security), Some(loaded)) = (security, hive.storages.get_mut(&identifier)) {
        loaded.forget_descriptor(security);
    }
    freed
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
        current = key.parent();
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
fn resolve(hive: &mut Hive, path: &str, open_link: bool) -> Result<String, u32> {
    let mut current = String::from(path);
    let mut reparses = 0;
    let mut link_source: Option<u32> = None;
    'reparse: loop {
        let components = split_path(&current);
        let mut node = ROOT;
        for (index, component) in components.iter().enumerate() {
            let Some(child) = lookup_child(hive, node, component) else { break };
            let Some(key) = hive.view(child) else { break };
            let last = index + 1 == components.len();
            if key.link && !(last && open_link) {
                reparses += 1;
                if reparses > MAX_REPARSE {
                    return Err(STATUS_OBJECT_NAME_NOT_FOUND);
                }
                let mut target = link_target(&key).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
                if link_source.is_none() {
                    link_source = owning_hive_of(hive, child).filter(|identifier| hive.trust.contains_key(identifier));
                }
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
        current = hive.nodes.get(&id).and_then(|key| key.parent());
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
    match parent_key.cell.filter(|_| !volatile) {
        Some((identifier, parent_cell)) => {
            let created = cell_op(hive, identifier, parent_cell, |storage| {
                let cell = key_cells::create_key(storage, parent_cell, name, class, &security, time)?;
                if link {
                    key_cells::set_key_flags(storage, cell, key_cells::KEY_SYM_LINK);
                }
                Some(cell)
            });
            let Some(cell) = created else { return Err(KernelError::with_status("registry: no room for the key cells", STATUS_INSUFFICIENT_RESOURCES)) };
            materialize(hive, parent, identifier, cell).ok_or_else(|| KernelError::with_status("registry: key cell unreadable", STATUS_REGISTRY_CORRUPT))
        }
        None => {
            let identifier = hive.nodes.insert(KeyNode::in_memory(name, Some(parent), Arc::new(security), volatile, link, class, time));
            add_ref(hive, parent);
            link_child(hive, parent, identifier, name);
            Ok(identifier)
        }
    }
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
        node = match lookup_child(hive, node, component) {
            Some(child) => child,
            None if !create => return Ok(None),
            None => create_node(hive, component, node, if index == last { security.take() } else { None }, volatile && index == last, link && index == last, if index == last { class } else { &[] })?,
        };
    }
    Ok(Some(node))
}

/// O nó existente mais fundo de um caminho já resolvido: o pai da primeira
/// chave que uma criação acrescentaria.
fn deepest_existing(hive: &mut Hive, path: &str) -> NodeId {
    let mut node = ROOT;
    for component in split_path(path) {
        match lookup_child(hive, node, component) {
            Some(child) => node = child,
            None => break,
        }
    }
    node
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

/// Um handle novo na chave (que passa a segurar o nó).
fn publish(hive: &mut Hive, path: &str, node: NodeId) -> Result<u32, KernelError> {
    let handle = handle_ids::allocate(4)?;
    hive.handles.insert(handle, HandleEntry { path: path.to_string(), node });
    add_ref(hive, node);
    update_statistics(hive);
    Ok(handle)
}

/// Nomes das subchaves na ordem da enumeração.
pub fn list_keys(path: &str) -> Vec<String> {
    with_hive(|hive| match find(hive, path) {
        Some(node) => hive.view(node).map(|key| key.subkey_names()).unwrap_or_default(),
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

/// Exclui só nó vivo, sem subchaves e com pai: as células da chave são
/// liberadas (CmpFreeKeyByCell) e o nó sai da arena; com handles abertos,
/// fica marcado como excluído para que eles não o tratem como chave
/// válida.
pub fn delete_node(node: NodeId, path: &str) -> bool {
    let removed = with_hive(|hive| {
        let key = hive.nodes.get(&node)?;
        // A raiz de uma hive carregada é KEY_NO_DELETE.
        if key.deleted || hive.storages.values().any(|loaded| loaded.root == node) || has_subkeys(hive, node) {
            return None;
        }
        // O pai é o do próprio nó: um handle aberto por um link guarda o
        // caminho resolvido, e a árvore é a fonte de verdade.
        let (parent, cell) = (key.parent()?, key.cell);
        let real = node_path(hive, node);
        let tombstone = tombstone_of(hive, node);
        if let Some((identifier, cell)) = cell {
            if !free_key_cells(hive, identifier, cell) {
                return None;
            }
        }
        let parent_chain = ancestry(hive, parent);
        if let Some(parent_key) = hive.nodes.get_mut(&parent) {
            parent_key.linked.retain(|&(_, child)| child != node);
        }
        retire_as(hive, node, tombstone);
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

/// CmDeleteKeyRecursive: as subchaves de `node` (as mais fundas primeiro) e
/// depois a própria chave, cada uma como pelo [`delete_node`].
pub fn delete_tree(node: NodeId) -> bool {
    loop {
        // A primeira folha da subárvore.
        let leaf = with_hive(|hive| {
            let mut current = node;
            while let Some(child) = match child_at_index(hive, current, 0) {
                Some(Child::Node(id)) => Some(id),
                Some(Child::Cell(identifier, cell)) => materialize(hive, current, identifier, cell),
                None => None,
            } {
                current = child;
            }
            current
        });
        if leaf == node {
            return delete_node(node, "");
        }
        if !delete_node(leaf, "") {
            return false;
        }
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
/// hook de remoção controla a exclusividade da operação. O handle solta o
/// nó (o último de uma chave excluída a tira da arena; o de uma chave viva
/// a põe na lista de fechamento adiado).
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
            release(hive, entry.node);
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
        return cell_op(hive, identifier, cell, |storage| key_cells::set_value_at(storage, cell, existing, name, value_type, &data, time)).is_some();
    }
    let Some(owned) = hive.nodes.get_mut(&node).and_then(|key| key.owned_mut()) else { return false };
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
    if let Some(owned) = key.owned_mut() {
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
        return cell_op(hive, identifier, cell, |storage| key_cells::delete_value_at(storage, cell, value, time)).is_some();
    }
    let Some(owned) = hive.nodes.get_mut(&node).and_then(|key| key.owned_mut()) else { return false };
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

/// Troca o descritor de uma chave viva (o CmpSetSecurityDescriptorInfo): numa
/// chave guardada numa hive, a célula 'sk' nova vem primeiro (a que já tem
/// esses bytes, ou uma nova) e a antiga perde a referência; sem célula, só
/// o nó. `false` para uma chave excluída ou células sem espaço.
pub fn set_security(node: NodeId, security: Captured) -> bool {
    with_hive(|hive| {
        let Some(cell) = hive.nodes.get(&node).filter(|key| !key.deleted).map(|key| key.cell) else { return false };
        let shared = match cell {
            Some((identifier, cell)) => {
                let old = hive.storage(identifier).and_then(|storage| key_cells::security_cell(storage, cell));
                let Some(new) = cell_op(hive, identifier, cell, |storage| key_cells::set_security(storage, cell, &security)) else { return false };
                let Some(loaded) = hive.storages.get_mut(&identifier) else { return false };
                if let Some(old) = old {
                    loaded.forget_descriptor(old);
                }
                let shared = Arc::new(security);
                loaded.security.insert(new, shared.clone());
                shared
            }
            None => Arc::new(security),
        };
        if let Some(key) = hive.nodes.get_mut(&node) {
            key.security = shared;
        }
        true
    })
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

/// Quantos nós estão na lista de fechamento adiado.
pub fn delayed_close_count() -> usize {
    with_hive(|hive| hive.delayed.len())
}

/// Lê um nó com as células dele (sem chamar o registro de dentro da
/// closure).
pub fn with_node<T>(node: NodeId, body: impl FnOnce(&KeyView) -> T) -> Option<T> {
    with_hive(|hive| hive.view(node).map(|view| body(&view)))
}

/// Lê a subchave `index` de `node` na ordem da enumeração
/// (CmpFindSubKeyByNumber), sem criar nó para ela: uma subchave que não
/// está viva é lida direto da célula (o CmEnumerateKey não cria KCB).
pub fn with_child_at<T>(node: NodeId, index: usize, body: impl FnOnce(&KeyView) -> T) -> Option<T> {
    with_hive(|hive| match child_at_index(hive, node, index)? {
        Child::Node(child) => hive.view(child).map(|view| body(&view)),
        Child::Cell(identifier, cell) => {
            let loaded = hive.storages.get_mut(&identifier)?;
            let key = key_cells::node(&loaded.storage, cell)?;
            let (security_cell, link) = (key.security.get(), key.flags.get() & key_cells::KEY_SYM_LINK != 0);
            let security = loaded.descriptor(security_cell)?;
            let transient = KeyNode::stored(Some(node), security, identifier, cell, link);
            Some(body(&KeyView { node: &transient, hive: &*hive }))
        }
    })
}

/// Quantas subchaves a chave tem.
pub fn child_count(node: NodeId) -> usize {
    with_node(node, |key| key.subkey_count()).unwrap_or(0)
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

/// Liga uma hive conferida (`tree::check`) em `path` (CmpLinkHiveToMaster):
/// o pai precisa existir e o nome não (o vínculo sobre uma chave existente
/// é STATUS_OBJECT_NAME_COLLISION, como no CmpDoParseKey com CreateLink).
/// Só a raiz ganha nó, fixado enquanto a hive está montada e com o nome do
/// ponto de montagem; as outras chaves ficam nas células até alguém
/// passar por elas. Os descritores lidos pela conferência ficam como o
/// cache da hive. Em falha as células voltam ao chamador.
pub fn link_hive(path: &str, identifier: u32, storage: Storage, checked: Checked) -> Result<NodeId, (u32, Storage)> {
    let components = split_path(path);
    let Some((name, parents)) = components.split_last() else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
    let parent_path = parents.join("\\");
    let linked = with_hive(|hive| {
        let Some(parent) = find(hive, &parent_path) else { return Err((STATUS_OBJECT_NAME_NOT_FOUND, storage)) };
        if lookup_child(hive, parent, name).is_some() {
            return Err((STATUS_OBJECT_NAME_COLLISION, storage));
        }
        let root_cell = storage.root_cell();
        let Some((security, link)) = key_cells::node(&storage, root_cell).and_then(|key| Some((checked.descriptor(key.security.get())?, key.flags.get() & key_cells::KEY_SYM_LINK != 0))) else { return Err((STATUS_REGISTRY_CORRUPT, storage)) };
        let mut root = KeyNode::stored(Some(parent), security, identifier, root_cell, link);
        root.extra = Some(Box::new(Extra { name: Box::from(*name), owned: None }));
        // A fixação da hive montada.
        root.refs = 1;
        let id = hive.nodes.insert(root);
        hive.cells.insert((identifier, root_cell), id);
        add_ref(hive, parent);
        link_child(hive, parent, id, name);
        hive.storages.insert(identifier, LoadedCells { storage, root: id, security: checked.security });
        Ok(id)
    })?;
    notify_path_changed(path);
    Ok(linked)
}

/// Caminho absoluto de um nó pelos nomes.
fn node_path(hive: &Hive, node: NodeId) -> String {
    let mut names = Vec::new();
    let mut current = Some(node);
    while let Some(id) = current.filter(|&id| id != ROOT) {
        let Some(key) = hive.view(id) else { break };
        names.push(key.name());
        current = key.parent();
    }
    let mut path = String::new();
    for name in names.iter().rev() {
        path.push('\\');
        path.push_str(name);
    }
    path
}

/// Há handle aberto numa chave da subárvore de `node` (o próprio incluído
/// quando pedido)?
fn subtree_handles(hive: &Hive, node: NodeId, include_self: bool) -> bool {
    hive.handles.values().any(|entry| (include_self || entry.node != node) && within(hive, entry.node, node))
}

/// Desliga uma hive (CmpPerformUnloadKey): com handles abertos em chaves
/// dela, STATUS_CANNOT_DELETE, salvo `force` (REG_FORCE_UNLOAD), que deixa
/// os handles apontando para chaves excluídas. Os nós vivos da hive saem da
/// arena (os com handle ficam excluídos até o último fechar). Devolve as
/// células.
pub fn unlink_hive(identifier: u32, force: bool) -> Result<Storage, u32> {
    let (storage, path, parent_chain) = with_hive(|hive| {
        let Some(root) = hive.storages.get(&identifier).map(|loaded| loaded.root) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        if !force && subtree_handles(hive, root, true) {
            return Err(STATUS_CANNOT_DELETE);
        }
        let path = node_path(hive, root);
        let parent = hive.nodes.get(&root).and_then(|key| key.parent());
        let parent_chain = parent.map(|parent| ancestry(hive, parent)).unwrap_or_default();
        if let Some(parent) = parent.and_then(|parent| hive.nodes.get_mut(&parent)) {
            parent.linked.retain(|&(_, child)| child != root);
        }
        for node in live_subtree(hive, root) {
            if node == root {
                // A fixação da hive montada sai antes.
                if let Some(key) = hive.nodes.get_mut(&root) {
                    key.refs = key.refs.saturating_sub(1);
                }
            }
            retire(hive, node);
        }
        let loaded = hive.storages.remove(&identifier).expect("hive registrada");
        // CmpUnJoinClassOfTrust.
        hive.trust.remove(&identifier);
        Ok((loaded.storage, path, parent_chain))
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
    with_hive(|hive| hive.storages.get(&identifier).map(|loaded| loaded.root))
}

/// Executa `body` sobre as células de uma hive carregada.
pub fn with_storage<T>(identifier: u32, body: impl FnOnce(&mut Storage) -> T) -> Option<T> {
    with_hive(|hive| hive.storages.get_mut(&identifier).map(|loaded| body(&mut loaded.storage)))
}

/// A hive de arquivo de um nó e se ele é a raiz dela.
pub fn hive_of(node: NodeId) -> Option<(u32, bool)> {
    with_hive(|hive| {
        let (identifier, _) = hive.nodes.get(&node)?.cell?;
        let root = hive.storages.get(&identifier)?.root;
        Some((identifier, root == node))
    })
}

/// A cópia de uma chave guardada numa hive (para o CmSaveKey).
fn stored_record(hive: &mut Hive, identifier: u32, cell: u32, parent: Option<usize>) -> Option<NewKey> {
    let loaded = hive.storages.get_mut(&identifier)?;
    let security = loaded.descriptor(key_cells::security_cell(&loaded.storage, cell)?)?;
    let storage = &loaded.storage;
    let key = key_cells::node(storage, cell)?;
    let count = key_cells::value_count(storage, cell);
    let values = (0..count).filter_map(|index| key_cells::value_cell(storage, cell, index)).filter_map(|value| key_cells::read_value(storage, value)).collect();
    Some(NewKey { name: key_cells::key_name_units(storage, cell)?.to_string_lossy(), last_write_time: key_cells::last_write_time(storage, cell), security: Captured::clone(&security), values, parent, link: key.flags.get() & key_cells::KEY_SYM_LINK != 0, class: key_cells::class_units(storage, cell) })
}

/// As chaves da subárvore de um nó em pré-ordem, sem as voláteis (o que o
/// CmSaveKey copia). A primeira é o próprio nó.
pub fn snapshot(node: NodeId) -> Option<Vec<NewKey>> {
    with_hive(|hive| {
        let key = hive.view(node).filter(|key| !key.deleted && !key.volatile)?;
        let mut keys: Vec<NewKey> = alloc::vec![NewKey { name: key.name(), last_write_time: key.last_write_time(), security: Captured::clone(&key.security), values: key.values(), parent: None, link: key.link, class: key.class() }];
        let mut stack: Vec<(Child, usize)> = Vec::new();
        let push_children = |hive: &Hive, stack: &mut Vec<(Child, usize)>, node: NodeId, index: usize| {
            let count = hive.view(node).map_or(0, |key| key.subkey_count());
            for position in (0..count).rev() {
                if let Some(child) = child_at_index(hive, node, position) {
                    stack.push((child, index));
                }
            }
        };
        push_children(hive, &mut stack, node, 0);
        while let Some((child, parent)) = stack.pop() {
            let index = keys.len();
            match child {
                Child::Node(id) => {
                    let Some(key) = hive.view(id).filter(|key| !key.deleted && !key.volatile) else { continue };
                    keys.push(NewKey { name: key.name(), last_write_time: key.last_write_time(), security: Captured::clone(&key.security), values: key.values(), parent: Some(parent), link: key.link, class: key.class() });
                    push_children(hive, &mut stack, id, index);
                }
                Child::Cell(identifier, cell) => {
                    keys.push(stored_record(hive, identifier, cell, Some(parent))?);
                    let storage = hive.storage(identifier)?;
                    for position in (0..key_cells::sub_key_count(storage, cell) as usize).rev() {
                        let child = key_cells::nth_subkey(storage, cell, position)?;
                        stack.push((match hive.cells.get(&(identifier, child)) {
                            Some(&id) => Child::Node(id),
                            None => Child::Cell(identifier, child),
                        }, index));
                    }
                }
            }
        }
        Some(keys)
    })
}

/// Há handles abertos em chaves da subárvore (o próprio nó incluído
/// quando pedido)?
pub fn subtree_has_open_handles(node: NodeId, include_self: bool) -> bool {
    with_hive(|hive| subtree_handles(hive, node, include_self))
}

/// Os handles internos abertos em chaves da subárvore de `node` (o próprio
/// nó incluído) guardadas pela mesma hive, com o caminho de cada chave (o
/// nome que o CmpConstructNameWithStatus monta para o KCB): primeiro os do
/// próprio nó (o CmpDumpKeyBodyList do KCB pedido), depois os dos
/// descendentes pelo caminho (o CmpEnumerateAllOpenSubKeys, rva 0x66d0e4,
/// que percorre só a tabela de KCBs da hive do KCB: as hives montadas
/// abaixo ficam fora).
pub fn open_handles_in_hive(node: NodeId) -> Vec<(u32, String)> {
    with_hive(|hive| {
        let owner = owning_hive_of(hive, node);
        let mut own: Vec<(u32, String)> = Vec::new();
        let mut below: Vec<(String, u32)> = Vec::new();
        for (&handle, entry) in &hive.handles {
            if !within(hive, entry.node, node) || owning_hive_of(hive, entry.node) != owner {
                continue;
            }
            let path = node_path(hive, entry.node);
            if entry.node == node {
                own.push((handle, path));
            } else {
                below.push((path, handle));
            }
        }
        below.sort();
        own.extend(below.into_iter().map(|(path, handle)| (handle, path)));
        own
    })
}

fn status_of(error: KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES }
}

/// Onde uma chave da cópia do CmRestoreKey vai: um nó (a chave restaurada
/// e as filhas sem célula) ou uma célula da hive do nó.
#[derive(Clone, Copy)]
enum Target {
    Node(NodeId),
    Cell(u32, u32),
}

/// Exclui as subchaves de `node` (os nós vivos e as células, das mais
/// fundas para as mais rasas), sem a própria chave.
fn clear_subkeys(hive: &mut Hive, node: NodeId) -> bool {
    for child in live_subtree(hive, node) {
        if child == node {
            continue;
        }
        if let Some(parent) = hive.nodes.get(&child).and_then(|key| key.parent()).and_then(|parent| hive.nodes.get_mut(&parent)) {
            parent.linked.retain(|&(_, candidate)| candidate != child);
        }
        retire(hive, child);
    }
    let Some((identifier, cell)) = hive.nodes.get(&node).and_then(|key| key.cell) else { return true };
    // As células abaixo da chave, uma folha por vez.
    loop {
        let Some(storage) = hive.storage(identifier) else { return false };
        let mut current = cell;
        while let Some(child) = key_cells::nth_subkey(storage, current, 0) {
            current = child;
        }
        if current == cell {
            return true;
        }
        if !free_key_cells(hive, identifier, current) {
            return false;
        }
    }
}

/// CmRestoreKey: troca as subchaves e os valores do nó pelos da hive
/// conferida `source` (a raiz dela é a do nó), pelas mesmas operações de
/// célula das chaves comuns. O descritor do próprio nó fica.
pub fn restore_subtree(node: NodeId, source: &Storage, checked: &Checked) -> Result<(), KernelError> {
    let path = with_hive(|hive| -> Result<String, KernelError> {
        if !live(hive, node) {
            return Err(KernelError::with_status("registry: key is gone", STATUS_KEY_DELETED));
        }
        if !clear_subkeys(hive, node) {
            return Err(KernelError::with_status("registry: restore could not free the subkeys", STATUS_INSUFFICIENT_RESOURCES));
        }
        let names = hive.view(node).map(|key| key.value_names()).unwrap_or_default();
        for name in names {
            remove_value(hive, node, &name.to_lowercase(), now());
        }
        tree::preorder(source, |cell, parent: Option<Target>| {
            let key = tree::record(source, checked, cell, None)?;
            let target = match parent {
                None => Target::Node(node),
                Some(Target::Node(parent)) if hive.nodes.get(&parent).is_some_and(|key| key.cell.is_none()) => Target::Node(create_node(hive, &key.name, parent, Some(key.security), false, key.link, &key.class).map_err(status_of)?),
                Some(Target::Node(parent)) => {
                    let (identifier, parent_cell) = hive.nodes.get(&parent).and_then(|key| key.cell).ok_or(STATUS_REGISTRY_CORRUPT)?;
                    Target::Cell(identifier, restore_cell(hive, identifier, parent_cell, &key)?)
                }
                Some(Target::Cell(identifier, parent_cell)) => Target::Cell(identifier, restore_cell(hive, identifier, parent_cell, &key)?),
            };
            match target {
                Target::Node(target) => {
                    for value in key.values {
                        store_value(hive, target, &value.name, value.value_type, value.data, now());
                    }
                    store_last_write_time(hive, target, key.last_write_time);
                }
                Target::Cell(identifier, cell) => {
                    cell_op(hive, identifier, cell, |storage| {
                        for value in &key.values {
                            key_cells::set_value(storage, cell, &value.name, value.value_type, &value.data, now())?;
                        }
                        key_cells::set_last_write_time(storage, cell, key.last_write_time);
                        Some(())
                    })
                    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
                }
            }
            Ok(target)
        })
        .map_err(|status| KernelError::with_status("registry: restore failed", status))?;
        Ok(node_path(hive, node))
    })?;
    notify_path_changed(&path);
    Ok(())
}

/// A célula de uma chave da cópia do CmRestoreKey sob `parent_cell`.
fn restore_cell(hive: &mut Hive, identifier: u32, parent_cell: u32, key: &NewKey) -> Result<u32, u32> {
    cell_op(hive, identifier, parent_cell, |storage| {
        let cell = key_cells::create_key(storage, parent_cell, &key.name, &key.class, &key.security, now())?;
        if key.link {
            key_cells::set_key_flags(storage, cell, key_cells::KEY_SYM_LINK);
        }
        Some(cell)
    })
    .ok_or(STATUS_INSUFFICIENT_RESOURCES)
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
/// (conferidas por `tree::check`) e os nós vivos são reconciliados com
/// elas. Uma chave viva que existe no arquivo fica com o mesmo nó (os
/// handles continuam valendo), agora com a célula do arquivo (valores,
/// descritor e LastWriteTime vêm dela); uma que só existe na memória
/// (inclusive as voláteis) é excluída.
pub fn refresh_hive(identifier: u32, storage: Storage, checked: Checked) -> Result<(), u32> {
    let path = with_hive(|hive| -> Result<String, u32> {
        let Some(root) = hive.storages.get(&identifier).map(|loaded| loaded.root) else { return Err(STATUS_OBJECT_NAME_NOT_FOUND) };
        // Dos mais rasos para os mais fundos: a célula nova do pai antes.
        let mut nodes = live_subtree(hive, root);
        nodes.reverse();
        let mut mapped: BTreeMap<NodeId, u32> = BTreeMap::new();
        let mut dropped: Vec<NodeId> = Vec::new();
        for &node in &nodes {
            let new_cell = if node == root {
                Some(storage.root_cell())
            } else {
                let key = hive.view(node).filter(|key| !key.deleted);
                let parent_cell = key.as_ref().and_then(|key| key.parent()).and_then(|parent| mapped.get(&parent).copied());
                match (key, parent_cell) {
                    (Some(key), Some(parent_cell)) => key_cells::find_subkey(&storage, parent_cell, &key.name_utf16()),
                    _ => None,
                }
            };
            match new_cell {
                Some(cell) => {
                    mapped.insert(node, cell);
                }
                None => dropped.push(node),
            }
        }
        // As que somem: das mais fundas para as mais rasas.
        for &node in dropped.iter().rev() {
            if let Some(parent) = hive.nodes.get(&node).and_then(|key| key.parent()).and_then(|parent| hive.nodes.get_mut(&parent)) {
                parent.linked.retain(|&(_, child)| child != node);
            }
            retire(hive, node);
        }
        hive.cells.retain(|&(hive_identifier, _), _| hive_identifier != identifier);
        for (&node, &cell) in &mapped {
            let Some(key) = key_cells::node(&storage, cell) else { continue };
            let security = checked.descriptor(key.security.get()).ok_or(STATUS_REGISTRY_CORRUPT)?;
            let link = key.flags.get() & key_cells::KEY_SYM_LINK != 0;
            let was_memory = hive.nodes.get(&node).is_some_and(|entry| entry.cell.is_none());
            if let Some(entry) = hive.nodes.get_mut(&node) {
                entry.cell = Some((identifier, cell));
                entry.security = security;
                entry.link = link;
                entry.volatile = false;
                match entry.extra.as_deref_mut() {
                    Some(extra) if node == root => extra.owned = None,
                    _ => entry.extra = None,
                }
            }
            hive.cells.insert((identifier, cell), node);
            if was_memory && node != root {
                // Uma chave sem célula que o arquivo tem: deixa a lista do
                // pai e a fixação.
                if let Some(parent) = hive.nodes.get(&node).and_then(|key| key.parent()).and_then(|parent| hive.nodes.get_mut(&parent)) {
                    parent.linked.retain(|&(_, child)| child != node);
                }
                release(hive, node);
            }
        }
        if let Some(loaded) = hive.storages.get_mut(&identifier) {
            loaded.storage = storage;
            loaded.security = checked.security;
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
    with_hive(|hive| hive.storages.get(&identifier).map(|loaded| loaded.root).map(|root| node_path(hive, root)))
}

/// As hives carregadas (identificador e se a células estão sujas).
pub fn dirty_hives() -> Vec<(u32, bool)> {
    with_hive(|hive| hive.storages.iter().map(|(&identifier, loaded)| (identifier, loaded.storage.is_dirty())).collect())
}

/// O nó tem handles abertos nele ou na subárvore?
pub fn hive_has_open_handles(identifier: u32) -> bool {
    with_hive(|hive| hive.storages.get(&identifier).map(|loaded| loaded.root).is_some_and(|root| subtree_handles(hive, root, true)))
}
