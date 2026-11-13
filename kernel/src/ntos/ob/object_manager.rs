//! Gerenciador de objetos — `system32/ntos/ob/object-manager.js`.
//!
//! Organiza nomes numa árvore compartilhada e associa handles aos objetos
//! donos. Um nó pode delegar o restante do caminho a um sistema de arquivos
//! montado. As operações comuns ignoram a caixa; criações explicitamente
//! sensíveis à caixa podem coexistir.
//!
//! Modelo Rust: os nós vivem numa arena (`NodeId` monotônico, nunca
//! reutilizado). Um nó desligado da árvore, sem handles e sem corpo de
//! namespace é recolhido; um id antigo passa a resolver para `None` (o
//! `pathOf` nulo do original). Os dados dinâmicos de cada dono ficam em
//! [`ObjectData`]; os ganchos `onHandleOpen`/`onHandleClose` e o estado
//! específico do dono são um `Arc<dyn ObjectHooks>` chamado fora do lock.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::any::Any;

use super::handle_table::HandleDescription;
use crate::ntos::ob::handles::process::{self as process_handles, Binding};
use super::{callbacks, handle_ids, object_types};
use crate::ntos::ob::objects::namespace as namespace_objects;
use crate::drivers::fs::native_file_name;
use crate::drivers::fs::volume::FileSystem;
use crate::ntos::ps::process;
use crate::ntos::se::object_security;
use crate::rtl::{KernelError, SpinLock};

pub type NodeId = u64;
pub const ROOT: NodeId = 1;

/// Ganchos e estado específico do dono de um objeto.
pub trait ObjectHooks: Send + Sync {
    /// Uma falha (por exemplo, de alocação) cancela a abertura.
    fn on_handle_open(&self) -> Result<(), KernelError> {
        Ok(())
    }
    fn on_handle_close(&self) {}
    /// Estado do dono, recuperado por downcast.
    fn as_any(&self) -> &dyn Any;
}

/// Abertura por ponteiro (`ob/open-pointer`): registro e nó dono.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeOpen {
    pub record: u64,
    pub node: Option<NodeId>,
}

/// `node.data` do original: o ponteiro nativo canônico (o primeiro de
/// `nativePointer`, `processPointer`, `threadPointer`, `driverObjectPointer`,
/// `fileObject`, `eventPointer`, `nativeDevicePointer`, `token.pointer`,
/// `section.nativePointer`) e os metadados comuns de abertura.
#[derive(Clone, Default)]
pub struct ObjectData {
    pub native_pointer: u64,
    /// Destino de um link simbólico (o `node.data` string do original).
    pub symlink_target: Option<String>,
    /// Caminho no volume de um arquivo aberto por montagem.
    pub file_path: Option<String>,
    pub access: Option<u32>,
    pub attributes: u32,
    pub open_attributes: Option<u32>,
    pub kernel_handle: bool,
    pub owner_process: Option<u64>,
    pub process_id: Option<u64>,
    pub native_open: Option<NativeOpen>,
    pub native_body: u64,
    pub hooks: Option<Arc<dyn ObjectHooks>>,
}

impl ObjectData {
    pub fn pointer(native_pointer: u64) -> Self {
        Self { native_pointer, ..Self::default() }
    }

    pub fn symlink(target: &str) -> Self {
        Self { symlink_target: Some(String::from(target)), ..Self::default() }
    }
}

/// Opções por abertura, separadas dos dados que vários handles compartilham.
#[derive(Clone, Default)]
pub struct OpenOptions {
    pub access: Option<u32>,
    pub attributes: Option<u32>,
    pub open_attributes: Option<u32>,
    pub kernel_handle: bool,
    pub owner_process: Option<u64>,
    pub on_open: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    pub on_close: Option<Arc<dyn Fn(u32) + Send + Sync>>,
    /// Metadados próprios do dono da abertura.
    pub extra: Option<Arc<dyn Any + Send + Sync>>,
}

#[derive(Clone)]
pub struct Node {
    pub id: NodeId,
    pub name: String,
    pub type_name: String,
    pub children: Option<BTreeMap<String, NodeId>>,
    pub mount: Option<&'static dyn FileSystem>,
    pub data: Option<ObjectData>,
    pub refs: u32,
    pub parent: Option<NodeId>,
    /// `false` marca um objeto temporário (o nome some no último handle).
    pub permanent: Option<bool>,
    /// Corpo nativo de diretório/link (`node.nativeNamespace`), 0 = nenhum.
    pub native_namespace: u64,
}

/// Contagens do namespace para Directory e SymbolicLink.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TypeStatistics {
    pub objects: u32,
    pub handles: u32,
    pub peak_objects: u32,
    pub peak_handles: u32,
}

/// `handleRecord`: opções da abertura combinadas com a linha nativa vigente.
#[derive(Clone)]
pub struct HandleRecord {
    pub node: NodeId,
    pub options: OpenOptions,
    pub pointer: u64,
    pub type_name: Option<String>,
    pub access: u32,
    pub attributes: u32,
}

struct State {
    nodes: BTreeMap<NodeId, Node>,
    next_node: NodeId,
    handles: BTreeMap<u32, NodeId>,
    bindings: BTreeMap<u32, Binding>,
    options: BTreeMap<u32, OpenOptions>,
    statistics: [(&'static str, TypeStatistics); 2],
    namespace_bodies: BTreeSet<NodeId>,
}

static STATE: SpinLock<State> = SpinLock::new(State {
    nodes: BTreeMap::new(),
    next_node: ROOT + 1,
    handles: BTreeMap::new(),
    bindings: BTreeMap::new(),
    options: BTreeMap::new(),
    // A raiz já conta como um diretório.
    statistics: [("Directory", TypeStatistics { objects: 1, handles: 0, peak_objects: 1, peak_handles: 0 }), ("SymbolicLink", TypeStatistics { objects: 0, handles: 0, peak_objects: 0, peak_handles: 0 })],
    namespace_bodies: BTreeSet::new(),
});

fn with_state<T>(body: impl FnOnce(&mut State) -> T) -> T {
    let mut state = STATE.lock();
    if !state.nodes.contains_key(&ROOT) {
        state.nodes.insert(
            ROOT,
            Node { id: ROOT, name: String::new(), type_name: String::from("Directory"), children: Some(BTreeMap::new()), mount: None, data: None, refs: 0, parent: None, permanent: None, native_namespace: 0 },
        );
    }
    body(&mut state)
}

fn is_namespace_type(type_name: &str) -> bool {
    type_name == "Directory" || type_name == "SymbolicLink"
}

fn split_path(path: &str) -> Vec<&str> {
    path.split('\\').filter(|component| !component.is_empty()).collect()
}

/// Cópia do nó (consulta sem reter o lock).
pub fn node(id: NodeId) -> Option<Node> {
    with_state(|state| state.nodes.get(&id).cloned())
}

/// Atualiza um nó vivo (o dono altera `node.data`, `permanent`...).
pub fn update_node<T>(id: NodeId, body: impl FnOnce(&mut Node) -> T) -> Option<T> {
    with_state(|state| state.nodes.get_mut(&id).map(body))
}

/// Cria um nó fora da árvore (o literal `{ name, type, data, refs: 0 }`
/// entregue a `openObject` no original).
pub fn new_node(name: &str, type_name: &str, data: Option<ObjectData>) -> NodeId {
    with_state(|state| {
        let id = state.next_node;
        state.next_node += 1;
        let children = (type_name == "Directory").then(BTreeMap::new);
        state.nodes.insert(id, Node { id, name: String::from(name), type_name: String::from(type_name), children, mount: None, data, refs: 0, parent: None, permanent: None, native_namespace: 0 });
        id
    })
}

fn attached(state: &State, id: NodeId) -> bool {
    if id == ROOT {
        return true;
    }
    let Some(node) = state.nodes.get(&id) else { return false };
    node.parent.and_then(|parent| state.nodes.get(&parent)).and_then(|parent| parent.children.as_ref()).is_some_and(|children| children.values().any(|&child| child == id))
}

/// Recolhe um nó desligado, sem handles e sem corpo de namespace.
fn collect(id: NodeId) {
    let removed = with_state(|state| {
        let Some(node) = state.nodes.get(&id) else { return false };
        if id == ROOT || node.refs != 0 || node.native_namespace != 0 || attached(state, id) || node.children.as_ref().is_some_and(|children| !children.is_empty()) {
            return false;
        }
        state.nodes.remove(&id);
        true
    });
    if removed {
        object_security::forget(id);
    }
}

/// Entradas (nó, caminho) da árvore.
pub fn namespace_entries() -> Vec<(NodeId, String)> {
    with_state(|state| {
        let mut result = Vec::new();
        let mut stack = alloc::vec![(ROOT, String::new())];
        while let Some((id, path)) = stack.pop() {
            result.push((id, if path.is_empty() { String::from("\\") } else { path.clone() }));
            if let Some(children) = state.nodes.get(&id).and_then(|node| node.children.as_ref()) {
                let mut pending: Vec<(NodeId, String)> = children.values().filter_map(|&child| state.nodes.get(&child).map(|node| (child, alloc::format!("{}\\{}", path, node.name)))).collect();
                pending.reverse();
                stack.extend(pending);
            }
        }
        result
    })
}

/// Recalcula objetos e handles de diretórios e links, contando uma vez os
/// corpos presentes na árvore e em handles abertos.
fn update_namespace_statistics() {
    let nodes: Vec<NodeId> = namespace_entries().into_iter().map(|(id, _)| id).collect();
    with_state(|state| {
        for index in 0..2 {
            let name = state.statistics[index].0;
            let open: Vec<NodeId> = state.handles.values().copied().filter(|id| state.nodes.get(id).is_some_and(|node| node.type_name == name)).collect();
            let mut live: BTreeSet<NodeId> = nodes.iter().copied().filter(|id| state.nodes.get(id).is_some_and(|node| node.type_name == name)).collect();
            for &id in &open {
                let owner = state.nodes.get(&id).and_then(|node| node.data.as_ref()).and_then(|data| data.native_open).and_then(|open| open.node);
                live.insert(owner.unwrap_or(id));
            }
            for &id in &state.namespace_bodies {
                if state.nodes.get(&id).is_some_and(|node| node.type_name == name) {
                    live.insert(id);
                }
            }
            let mut handles = open
                .iter()
                .filter(|id| state.nodes.get(id).is_some_and(|node| node.native_namespace == 0 && node.data.as_ref().is_none_or(|data| data.native_open.is_none())))
                .count() as u32;
            for id in &live {
                if let Some(node) = state.nodes.get(id) {
                    if node.native_namespace != 0 {
                        handles += namespace_objects::handles(node.native_namespace);
                    }
                }
            }
            let statistics = &mut state.statistics[index].1;
            statistics.objects = live.len() as u32;
            statistics.handles = handles;
            statistics.peak_objects = statistics.peak_objects.max(statistics.objects);
            statistics.peak_handles = statistics.peak_handles.max(statistics.handles);
        }
    });
}

/// Percorre a árvore a partir de `start` e segue links até a profundidade 8.
/// Devolve o nó encontrado e o trecho delegado a um volume montado.
pub fn resolve_from(path: &str, link_depth: u32, case_insensitive: bool, open_symbolic_link: bool, start: NodeId) -> (Option<NodeId>, Option<String>) {
    if link_depth > 8 {
        return (None, None); // laço de links
    }
    let parts = split_path(path);
    let mut current = start;
    for (index, part) in parts.iter().enumerate() {
        let step = with_state(|state| {
            let node = state.nodes.get(&current)?;
            if node.mount.is_some() {
                return Some(Err(parts[index..].join("/")));
            }
            let children = node.children.as_ref()?;
            let lower = part.to_lowercase();
            let next = if case_insensitive {
                children.get(&lower).copied().or_else(|| children.values().copied().find(|child| state.nodes.get(child).is_some_and(|child| child.name.to_lowercase() == lower)))
            } else {
                children.values().copied().find(|child| state.nodes.get(child).is_some_and(|child| child.name == *part))
            }?;
            let next_node = state.nodes.get(&next)?;
            Some(Ok((next, next_node.type_name == "SymbolicLink", next_node.native_namespace, next_node.data.as_ref().and_then(|data| data.symlink_target.clone()))))
        });
        match step {
            None => return (None, None),
            Some(Err(rest)) => return (Some(current), Some(rest)),
            Some(Ok((next, is_link, body, target))) => {
                if is_link && !(open_symbolic_link && index == parts.len() - 1) {
                    let rest = parts[index + 1..].join("\\");
                    let target = if body != 0 { namespace_objects::target(body).unwrap_or_default() } else { target.unwrap_or_default() };
                    let full = if rest.is_empty() { target } else { alloc::format!("{}\\{}", target, rest) };
                    return resolve_from(&full, link_depth + 1, case_insensitive, open_symbolic_link, ROOT);
                }
                current = next;
            }
        }
    }
    let mounted = with_state(|state| state.nodes.get(&current).is_some_and(|node| node.mount.is_some()));
    (Some(current), mounted.then(String::new))
}

pub fn resolve(path: &str) -> (Option<NodeId>, Option<String>) {
    resolve_from(path, 0, true, false, ROOT)
}

/// Busca um filho pela chave minúscula ou pelo nome sem caixa.
fn find_child(state: &State, parent: NodeId, lower: &str) -> Option<NodeId> {
    let children = state.nodes.get(&parent)?.children.as_ref()?;
    children.get(lower).copied().or_else(|| children.values().copied().find(|child| state.nodes.get(child).is_some_and(|child| child.name.to_lowercase() == lower)))
}

fn notify_changed(parent: NodeId) {
    let body = with_state(|state| state.nodes.get(&parent).map_or(0, |node| node.native_namespace));
    if body != 0 {
        let _ = namespace_objects::changed(body);
    }
}

/// Cria os componentes ausentes e reutiliza diretórios existentes sem caixa.
pub fn create_directory(path: &str) -> Result<NodeId, KernelError> {
    let mut current = ROOT;
    for part in split_path(path) {
        let key = part.to_lowercase();
        let (child, created) = with_state(|state| {
            if state.nodes.get(&current).is_none_or(|node| node.children.is_none()) {
                return Err(KernelError::new(alloc::format!("objeto nao e diretorio: {part}")));
            }
            if let Some(child) = find_child(state, current, &key) {
                return Ok((child, false));
            }
            let id = state.next_node;
            state.next_node += 1;
            state.nodes.insert(id, Node { id, name: String::from(part), type_name: String::from("Directory"), children: Some(BTreeMap::new()), mount: None, data: None, refs: 0, parent: Some(current), permanent: None, native_namespace: 0 });
            state.nodes.get_mut(&current).unwrap().children.as_mut().unwrap().insert(key.clone(), id);
            Ok((id, true))
        })?;
        if created {
            notify_changed(current);
            update_namespace_statistics();
        }
        current = child;
    }
    Ok(current)
}

/// Insere um novo nó sob `parent_path`, rejeitando colisões; registra os
/// tipos nativos de dispositivos e eventos.
pub fn create_object(parent_path: &str, name: &str, type_name: &str, data: Option<ObjectData>) -> Result<NodeId, KernelError> {
    let parent = resolve(parent_path).0;
    let key = name.to_lowercase();
    let native = data.as_ref().map_or(0, |data| data.native_pointer);
    let id = with_state(|state| {
        let Some(parent) = parent.filter(|parent| state.nodes.get(parent).is_some_and(|node| node.children.is_some())) else {
            return Err(KernelError::new(alloc::format!("dir inexistente: {parent_path}")));
        };
        let collision = state.nodes[&parent].children.as_ref().unwrap().values().any(|child| state.nodes.get(child).is_some_and(|child| child.name.to_lowercase() == key));
        if collision {
            return Err(KernelError::new(alloc::format!("objeto ja existe: {parent_path}\\{name}")));
        }
        let id = state.next_node;
        state.next_node += 1;
        state.nodes.insert(id, Node { id, name: String::from(name), type_name: String::from(type_name), children: None, mount: None, data, refs: 0, parent: Some(parent), permanent: None, native_namespace: 0 });
        state.nodes.get_mut(&parent).unwrap().children.as_mut().unwrap().insert(key.clone(), id);
        Ok(id)
    })?;
    if type_name == "Device" && native != 0 {
        object_types::device_type();
        object_types::bind_native(native, "Device")?;
    }
    if type_name == "Event" && native != 0 {
        object_types::event_type();
        object_types::bind_native(native, "Event")?;
    }
    if let Some(parent) = parent {
        notify_changed(parent);
    }
    if is_namespace_type(type_name) {
        update_namespace_statistics();
    }
    Ok(id)
}

/// Associa um sistema de arquivos ao diretório criado ou encontrado.
pub fn mount(path: &str, file_system: &'static dyn FileSystem) -> Result<NodeId, KernelError> {
    let node = create_directory(path)?;
    update_node(node, |node| node.mount = Some(file_system));
    native_file_name::register_mount(file_system, node);
    Ok(node)
}

/// Cria um nó SymbolicLink cujo dado é o caminho de destino.
pub fn create_symlink(path: &str, target: &str) -> Result<NodeId, KernelError> {
    let parts = split_path(path);
    let Some((name, parents)) = parts.split_last() else {
        return Err(KernelError::new("symbolic link without name"));
    };
    let parent_path = alloc::format!("\\{}", parents.join("\\"));
    create_object(&parent_path, name, "SymbolicLink", Some(ObjectData::symlink(target)))
}

/// Resolve um nome; em pontos de montagem cria a descrição temporária do
/// arquivo. `Ok(0)` quando o nome não existe.
pub fn open(path: &str) -> Result<u32, KernelError> {
    let (Some(found), rest) = resolve(path) else { return Ok(0) };
    let mount = node(found).and_then(|node| node.mount);
    let target = match mount {
        Some(volume) => {
            let rest = rest.unwrap_or_default();
            let mut volume_path = alloc::format!("/{rest}");
            if !volume.exists(&volume_path) {
                // Fallback sem caixa dentro do volume montado (como NT/Win32).
                let requested = rest.to_lowercase();
                match volume.list().into_iter().find(|path| path[1..].to_lowercase() == requested) {
                    Some(path) => volume_path = path,
                    None => return Ok(0),
                }
            }
            let id = new_node(&volume_path[1..], "File", Some(ObjectData { file_path: Some(volume_path.clone()), ..ObjectData::default() }));
            update_node(id, |node| node.mount = Some(volume));
            id
        }
        None => found,
    };
    let result = open_object(target, None);
    if result.is_err() || matches!(result, Ok(0)) {
        collect(target);
    }
    result
}

/// Garante o corpo nativo dos objetos de namespace e aplica os callbacks de
/// abertura/duplicação antes de inserir o handle.
pub fn open_object(id: NodeId, options: Option<OpenOptions>) -> Result<u32, KernelError> {
    let Some(snapshot) = node(id) else {
        return Err(KernelError::new("object node is gone"));
    };
    let native_open = snapshot.data.as_ref().and_then(|data| data.native_open);
    if is_namespace_type(&snapshot.type_name) && native_open.is_none() {
        namespace_objects::ensure(id)?;
    }
    let result = match &snapshot.data {
        Some(data) if native_open.is_none() || snapshot.refs > 0 => {
            let operation = if snapshot.refs > 0 { 2 } else { 1 };
            callbacks::route(&snapshot.type_name, data, operation, false, &mut |_granted| insert_handle(id, options.clone()))
        }
        _ => insert_handle(id, options),
    };
    if result.is_err() {
        collect(id);
    }
    result
}

fn close_from_table(_process: u64, handle: u32) {
    let _ = close(handle);
}

/// Retém o objeto, publica os metadados e insere a entrada na tabela nativa
/// do processo; uma falha desfaz cada retenção e vínculo.
fn insert_handle(id: NodeId, options: Option<OpenOptions>) -> Result<u32, KernelError> {
    let handle = handle_ids::allocate(4)?;
    let snapshot = node(id).ok_or_else(|| KernelError::new("object node is gone"))?;
    if snapshot.native_namespace != 0 {
        namespace_objects::open(snapshot.native_namespace)?;
    }
    let hooks = snapshot.data.as_ref().and_then(|data| data.hooks.clone());
    if let Some(hooks) = &hooks {
        if let Err(error) = hooks.on_handle_open() {
            if snapshot.native_namespace != 0 {
                let _ = namespace_objects::close(snapshot.native_namespace);
            }
            return Err(error);
        }
    }
    with_state(|state| {
        if let Some(node) = state.nodes.get_mut(&id) {
            node.refs += 1;
        }
        state.handles.insert(handle, id);
        if let Some(options) = &options {
            state.options.insert(handle, options.clone());
        }
    });
    let result = publish(id, handle, &snapshot, options.as_ref());
    if let Err(error) = result {
        let on_close = with_state(|state| {
            state.bindings.remove(&handle);
            state.options.remove(&handle);
            state.handles.remove(&handle);
            if let Some(node) = state.nodes.get_mut(&id) {
                node.refs -= 1;
            }
            options.as_ref().and_then(|options| options.on_close.clone())
        });
        if let Some(on_close) = on_close {
            on_close(handle);
        }
        if let Some(hooks) = &hooks {
            hooks.on_handle_close();
        }
        if snapshot.native_namespace != 0 {
            let _ = namespace_objects::close(snapshot.native_namespace);
        }
        return Err(error);
    }
    if is_namespace_type(&snapshot.type_name) {
        update_namespace_statistics();
    }
    Ok(handle)
}

fn publish(id: NodeId, handle: u32, snapshot: &Node, options: Option<&OpenOptions>) -> Result<(), KernelError> {
    let data = snapshot.data.clone().unwrap_or_default();
    let pointer = if snapshot.native_namespace != 0 { snapshot.native_namespace } else { data.native_pointer };
    let on_open = options.and_then(|options| options.on_open.clone());
    if pointer == 0 {
        if let Some(on_open) = on_open {
            on_open(handle);
        }
        return Ok(());
    }
    if object_types::by_name(&snapshot.type_name).is_none() {
        return Err(KernelError::new("native handle object type is not registered"));
    }
    // As opções da abertura prevalecem sobre os dados compartilhados.
    let attributes = options.and_then(|options| options.attributes).unwrap_or(data.attributes);
    let flags = options.and_then(|options| options.open_attributes).or(data.open_attributes).unwrap_or(attributes);
    let kernel_handle = options.is_some_and(|options| options.kernel_handle) || data.kernel_handle || flags & 0x200 != 0;
    let access = options.and_then(|options| options.access).or(data.access).unwrap_or(0);
    // Handles de kernel pertencem à tabela do System; os demais seguem o
    // dono da abertura.
    let owner = if kernel_handle { process::get_system_process() } else { options.and_then(|options| options.owner_process).or(data.owner_process).unwrap_or_else(process::get_current_process) };
    let mut merged = options.cloned().unwrap_or_default();
    merged.owner_process = Some(owner);
    merged.kernel_handle = kernel_handle;
    merged.open_attributes = Some(flags);
    merged.attributes = Some(attributes & 7);
    merged.access = Some(access);
    with_state(|state| state.options.insert(handle, merged));
    let native_body = if snapshot.native_namespace != 0 { snapshot.native_namespace } else if let Some(open) = data.native_open { open.record } else { data.native_body };
    let description = HandleDescription { pointer, type_name: snapshot.type_name.clone(), identity: id, native_body, attributes: attributes & 7, access };
    process_handles::publish(
        owner,
        handle as u64,
        &description,
        close_from_table,
        Some(&mut |binding: &Binding| {
            with_state(|state| state.bindings.insert(handle, *binding));
            if let Some(on_open) = &on_open {
                on_open(handle);
            }
            Ok(())
        }),
    )
    .map(|_| ())
}

/// O nó retido pelo handle.
pub fn get_object(handle: u32) -> Option<NodeId> {
    with_state(|state| state.handles.get(&handle).copied())
}

/// Direitos e atributos alterados sob bloqueio são lidos da própria linha.
pub fn handle_record(handle: u32) -> Option<HandleRecord> {
    let (node, options, binding) = with_state(|state| Some((*state.handles.get(&handle)?, state.options.get(&handle).cloned().unwrap_or_default(), state.bindings.get(&handle).copied())))?;
    let row = binding.and_then(|binding| super::handle_table::row(binding.table, binding.handle).filter(|row| row.serial == binding.serial));
    Some(HandleRecord {
        node,
        pointer: row.as_ref().map_or(0, |row| row.pointer),
        type_name: row.as_ref().map(|row| row.type_name.clone()),
        access: row.as_ref().map(|row| row.access).or(options.access).unwrap_or(0),
        attributes: row.as_ref().map(|row| row.attributes).or(options.attributes).unwrap_or(0),
        options,
    })
}

/// Remove a linha e os vínculos antes de notificar o dono e soltar a
/// referência.
pub fn close(handle: u32) -> Result<bool, KernelError> {
    let Some((id, binding, options)) = with_state(|state| Some((*state.handles.get(&handle)?, state.bindings.get(&handle).copied(), state.options.get(&handle).cloned()))) else {
        return Ok(false);
    };
    let mut detach = || {
        with_state(|state| {
            state.bindings.remove(&handle);
            state.options.remove(&handle);
            state.handles.remove(&handle);
            if let Some(node) = state.nodes.get_mut(&id) {
                node.refs -= 1;
            }
        });
        if let Some(on_close) = options.as_ref().and_then(|options| options.on_close.clone()) {
            on_close(handle);
        }
    };
    match binding {
        Some(binding) => {
            if !process_handles::remove(&binding, Some(&mut detach))? {
                return Ok(false);
            }
        }
        None => detach(),
    }
    let snapshot = node(id);
    if let Some(hooks) = snapshot.as_ref().and_then(|node| node.data.as_ref()).and_then(|data| data.hooks.clone()) {
        hooks.on_handle_close();
    }
    let body = snapshot.as_ref().map_or(0, |node| node.native_namespace);
    if body != 0 {
        namespace_objects::close(body)?;
    }
    if snapshot.as_ref().is_some_and(|node| is_namespace_type(&node.type_name)) {
        update_namespace_statistics();
    }
    collect(id);
    Ok(true)
}

/// Fecha os handles do processo, preservando os de kernel.
pub fn close_process_native_handles(process: u64) {
    let handles: Vec<u32> = with_state(|state| state.handles.keys().copied().collect());
    for handle in handles {
        if let Some(record) = handle_record(handle) {
            if record.options.owner_process == Some(process) && !record.options.kernel_handle {
                let _ = close(handle);
            }
        }
    }
}

/// Contagem de handles do nó pelo caminho; -1 se o nome não existe.
pub fn reference_count(path: &str) -> i64 {
    resolve(path).0.and_then(node).map_or(-1, |node| node.refs as i64)
}

/// Linhas de diagnóstico com caminho, tipo, montagem e referências.
pub fn dump() -> Vec<String> {
    fn walk(id: NodeId, prefix: &str, lines: &mut Vec<String>) {
        let Some(node) = node(id) else { return };
        lines.push(alloc::format!("{}\\{}  [{}{}, refs={}]", prefix, node.name, node.type_name, if node.mount.is_some() { ", mount" } else { "" }, node.refs));
        if let Some(children) = &node.children {
            let child_prefix = alloc::format!("{}\\{}", prefix, node.name);
            for &child in children.values() {
                walk(child, &child_prefix, lines);
            }
        }
    }
    let mut lines = Vec::new();
    walk(ROOT, "", &mut lines);
    lines
}

/// Resolve um nome sem abrir handle.
pub fn lookup(path: &str) -> Option<NodeId> {
    resolve(path).0
}

/// Remove o filho da árvore, sem descartar referências de handles.
pub fn unlink(path: &str) -> bool {
    let parts = split_path(path);
    let Some((name, parents)) = parts.split_last() else { return false };
    let parent_path = alloc::format!("\\{}", parents.join("\\"));
    let Some(parent) = resolve(&parent_path).0 else { return false };
    let child = with_state(|state| find_child(state, parent, &name.to_lowercase()));
    child.is_some_and(remove_named)
}

/// Insere um nome com a regra de caixa pedida; chaves com terminadores
/// distintos permitem nomes que só diferem na caixa.
pub fn insert_named(parent: NodeId, name: &str, type_name: &str, data: Option<ObjectData>, case_insensitive: bool) -> Option<NodeId> {
    if name.is_empty() || name.contains('\\') {
        return None;
    }
    let id = with_state(|state| {
        let children = state.nodes.get(&parent)?.children.as_ref()?;
        let collision = children.values().any(|child| state.nodes.get(child).is_some_and(|child| if case_insensitive { child.name.to_lowercase() == name.to_lowercase() } else { child.name == name }));
        if collision {
            return None;
        }
        let mut key = name.to_lowercase();
        while children.contains_key(&key) {
            key.push('\0');
        }
        let id = state.next_node;
        state.next_node += 1;
        let node_children = (type_name == "Directory").then(BTreeMap::new);
        state.nodes.insert(id, Node { id, name: String::from(name), type_name: String::from(type_name), children: node_children, mount: None, data, refs: 0, parent: Some(parent), permanent: None, native_namespace: 0 });
        state.nodes.get_mut(&parent).unwrap().children.as_mut().unwrap().insert(key, id);
        Some(id)
    })?;
    notify_changed(parent);
    if is_namespace_type(type_name) {
        update_namespace_statistics();
    }
    Some(id)
}

/// Desliga exatamente o nó informado e atualiza os corpos do filho e do pai.
pub fn remove_named(id: NodeId) -> bool {
    let removed = with_state(|state| {
        let parent = state.nodes.get(&id)?.parent?;
        let children = state.nodes.get_mut(&parent)?.children.as_mut()?;
        let key = children.iter().find(|(_, &child)| child == id).map(|(key, _)| key.clone())?;
        children.remove(&key);
        let node = &state.nodes[&id];
        Some((parent, node.native_namespace, node.type_name.clone()))
    });
    let Some((parent, body, type_name)) = removed else { return false };
    if body != 0 {
        let _ = namespace_objects::detach(body);
    }
    notify_changed(parent);
    if is_namespace_type(&type_name) {
        update_namespace_statistics();
    }
    collect(id);
    true
}

/// Caminho atual de um nó pela identidade; `None` se saiu da árvore.
pub fn path_of(target: NodeId) -> Option<String> {
    namespace_entries().into_iter().find(|(id, _)| *id == target).map(|(_, path)| path)
}

pub fn handle_entries() -> Vec<(u32, NodeId)> {
    with_state(|state| state.handles.iter().map(|(&handle, &node)| (handle, node)).collect())
}

/// Corpos vivos por referências mesmo fora da árvore.
pub fn track_namespace(id: NodeId, live: bool) {
    with_state(|state| {
        if live {
            state.namespace_bodies.insert(id);
        } else {
            state.namespace_bodies.remove(&id);
        }
    });
    update_namespace_statistics();
    if !live {
        collect(id);
    }
}

pub fn type_stats(name: &str) -> TypeStatistics {
    with_state(|state| state.statistics.iter().find(|(type_name, _)| *type_name == name).map(|(_, statistics)| *statistics).unwrap_or_default())
}

/// Nome curto de um nó (diagnóstico).
pub fn name_of(id: NodeId) -> Option<String> {
    node(id).map(|node| node.name.to_string())
}

/// Número de filhos do diretório (o `children.size` do original).
pub fn child_count(id: NodeId) -> u64 {
    node(id).and_then(|node| node.children.map(|children| children.len() as u64)).unwrap_or(0)
}

/// O nó está ligado ao pai.
pub fn is_attached(id: NodeId) -> bool {
    with_state(|state| attached(state, id))
}

/// Liga o corpo de namespace ao nó (`node.nativeNamespace`).
pub fn set_native_namespace(id: NodeId, body: u64) {
    update_node(id, |node| node.native_namespace = body);
}

/// ObIsDosDeviceLocallyMapped: sem device maps por LUID (sem sessões de
/// logon), nenhuma letra é mapeada localmente.
pub fn is_dos_device_locally_mapped() -> bool {
    false
}
