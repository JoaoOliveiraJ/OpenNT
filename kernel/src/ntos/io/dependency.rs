//! O grafo de dependências entre dispositivos: IoSetDependency,
//! IoReserveDependency, IoResolveDependency, IoDuplicateDependency e
//! IoTestDependency.
//!
//! Mesmas estruturas e regras do ntoskrnl 19041 (as Pip* do grafo):
//! - nó (0x60 bytes, NonPagedPoolNx 'PnpS'): elo da lista global, as
//!   arestas em que é dependente (+0x10, pelo elo +0x00 da aresta) e as em
//!   que é provedor (+0x20, pelo elo +0x10), o DEVICE_OBJECT (NULL num nó
//!   só de nome), os ids de ligação (+0x38), o elo da fila de relações de
//!   energia (+0x48) e a contagem de referências (+0x58: o vínculo com o
//!   dispositivo, cada aresta e as referências locais). O nó de um
//!   dispositivo fica em DEVOBJ_EXTENSION.DependencyNode.
//! - aresta (0x50 bytes, NonPagedPoolNx 'PnpS'): provedor, dependente, o
//!   OU das flags dos pedidos e a lista de pedidos (0x28 bytes, PagedPool
//!   'PnpS': tipo 0 = DEVICE_OBJECT, tipo 1 = cópia do nome de ligação).
//! - id de ligação (0x20 bytes, PagedPool 'PnpS'): o nome duplicado.
//! Uma aresta nova recusa (STATUS_UNSUCCESSFUL) o próprio nó e a aresta
//! inversa direta; o NT também recusa um provedor descendente do
//! dependente na árvore de devnodes, que o PnP do OpenNT não guarda como
//! DEVICE_NODE (a verificação de ancestralidade fica de fora). Os nomes são
//! procurados sem distinção de caixa e apagados com distinção, como no
//! original. A fila de reconstrução das relações de energia (a ordem de
//! energia entre provedores e dependentes), a liberação do início dos
//! dependentes pelo PnP e a notificação de mudança de propriedade ao modo
//! usuário não existem no OpenNT e não são feitas.

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, ListEntry, UnicodeString};
use crate::ntos::ke::bugcheck;
use crate::ntos::rtl::unicode;
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const NON_PAGED_POOL_NX: u32 = 0x200;
const PAGED_POOL: u32 = 1;
const DEPENDENCY_TAG: u32 = u32::from_le_bytes(*b"PnpS");
/// Tipos do descritor de ligação.
const BINDING_DEVICE: u32 = 0;
const BINDING_NAME: u32 = 1;

#[repr(C)]
struct DependencyNode {
    global_link: ListEntry,
    provider_edges: ListEntry,
    dependent_edges: ListEntry,
    device_object: Field<u64>,
    binding_ids: ListEntry,
    rebuild_link: ListEntry,
    reference_count: Field<u32>,
    flags: Field<u32>,
}

#[repr(C)]
struct DependencyEdge {
    dependent_link: ListEntry,
    provider_link: ListEntry,
    provider: Field<u64>,
    dependent: Field<u64>,
    flags: Field<u32>,
    _pad_34: Reserved<0x4>,
    requests: ListEntry,
    converted: Field<u8>,
    _pad_49: Reserved<0x7>,
}

#[repr(C)]
struct DependencyRequest {
    link: ListEntry,
    kind: Field<u32>,
    _pad_14: Reserved<0x4>,
    value: Field<u64>,
    flags: Field<u32>,
    _pad_24: Reserved<0x4>,
}

#[repr(C)]
struct BindingId {
    link: ListEntry,
    name: UnicodeString,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DependencyNode {}
unsafe impl NtStruct for DependencyEdge {}
unsafe impl NtStruct for DependencyRequest {}
unsafe impl NtStruct for BindingId {}

const _: () = {
    assert!(core::mem::size_of::<DependencyNode>() == 0x60);
    assert!(core::mem::offset_of!(DependencyNode, device_object) == 0x30);
    assert!(core::mem::offset_of!(DependencyNode, binding_ids) == 0x38);
    assert!(core::mem::offset_of!(DependencyNode, reference_count) == 0x58);
    assert!(core::mem::size_of::<DependencyEdge>() == 0x50);
    assert!(core::mem::offset_of!(DependencyEdge, provider) == 0x20);
    assert!(core::mem::offset_of!(DependencyEdge, flags) == 0x30);
    assert!(core::mem::offset_of!(DependencyEdge, requests) == 0x38);
    assert!(core::mem::size_of::<DependencyRequest>() == 0x28);
    assert!(core::mem::size_of::<BindingId>() == 0x20);
};

/// O descritor de ligação {Type, Value, Flags} dos exports.
#[derive(Clone, Copy)]
struct Binding {
    kind: u32,
    value: u64,
    flags: u32,
}

/// PiDependencyRelationsLock com a cabeça da PiDependencyNodeListHead.
static GRAPH: SpinLock<u64> = SpinLock::new(0);

fn node(address: u64) -> &'static DependencyNode {
    // SAFETY: um nó vivo do grafo.
    unsafe { DependencyNode::at(address) }
}

fn edge(address: u64) -> &'static DependencyEdge {
    // SAFETY: uma aresta viva do grafo.
    unsafe { DependencyEdge::at(address) }
}

fn link(address: u64) -> &'static ListEntry {
    // SAFETY: elos de uma lista viva do grafo.
    unsafe { ListEntry::at(address) }
}

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(0x139, 3, 0, 0, 0)
}

fn initialize_head(head: &ListEntry) {
    head.flink.set(head.address());
    head.blink.set(head.address());
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let last = head.blink.get();
    if link(last).flink.get() != head.address() {
        corrupt_list();
    }
    entry.flink.set(head.address());
    entry.blink.set(last);
    link(last).flink.set(entry.address());
    head.blink.set(entry.address());
}

fn remove(entry: &ListEntry) {
    let (flink, blink) = (entry.flink.get(), entry.blink.get());
    if link(flink).blink.get() != entry.address() || link(blink).flink.get() != entry.address() {
        corrupt_list();
    }
    link(blink).flink.set(flink);
    link(flink).blink.set(blink);
}

/// Os endereços dos elos de uma lista (capturados antes de mexer nela).
fn links(head: &ListEntry) -> alloc::vec::Vec<u64> {
    let mut found = alloc::vec::Vec::new();
    let mut current = head.flink.get();
    while current != head.address() {
        found.push(current);
        current = link(current).flink.get();
    }
    found
}

fn allocate(pool_type: u32, size: u64) -> u64 {
    pool_allocation::allocate_tagged(pool_type, size, DEPENDENCY_TAG).unwrap_or(0)
}

fn free(block: u64) {
    let _ = pool_allocation::free(block, 0);
}

/// DEVOBJ_EXTENSION.DependencyNode do dispositivo.
fn node_slot(device: u64) -> &'static Field<u64> {
    // SAFETY: o DEVICE_OBJECT vivo do chamador e a extensão dele.
    let extension = unsafe { DevobjExtension::at(DeviceObject::at(device).device_object_extension.get()) };
    // SAFETY: a célula vive enquanto a extensão vive.
    unsafe { Field::<u64>::at(extension.dependency_node.address()) }
}

fn node_of(device: u64) -> u64 {
    if device == 0 { 0 } else { node_slot(device).get() }
}

fn names_equal(left: u64, right: u64, case_insensitive: bool) -> bool {
    unicode::equal_string(left, right, case_insensitive as u32).unwrap_or(0) != 0
}

/// A cabeça da lista global (criada na primeira operação).
fn global_head(head: &mut u64) -> Option<&'static ListEntry> {
    if *head == 0 {
        let block = allocate(NON_PAGED_POOL_NX, ListEntry::SIZE);
        if block == 0 {
            return None;
        }
        initialize_head(link(block));
        *head = block;
    }
    Some(link(*head))
}

/// PipQueryBindingResolution.
fn resolve(head: u64, binding: &Binding) -> u64 {
    match binding.kind {
        BINDING_DEVICE => node_of(binding.value),
        BINDING_NAME if head != 0 => {
            for global in links(link(head)) {
                let candidate = node(global);
                for id in links(&candidate.binding_ids) {
                    // SAFETY: o registro do id de ligação.
                    let id = unsafe { BindingId::at(id) };
                    if names_equal(id.name.address(), binding.value, true) {
                        return candidate.address();
                    }
                }
            }
            0
        }
        _ => 0,
    }
}

/// PipAddBindingId.
fn add_binding_id(target: &DependencyNode, name: u64) -> u32 {
    let block = allocate(PAGED_POOL, BindingId::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: o bloco recém-alocado.
    let id = unsafe { BindingId::at(block) };
    let status = unicode::duplicate(0, name, id.name.address());
    if (status as i32) < 0 {
        // O original não devolve o registro nesse caso.
        return status;
    }
    insert_tail(&target.binding_ids, &id.link);
    status
}

/// PipFreeBindingId.
fn free_binding_id(address: u64) {
    // SAFETY: um id de ligação fora da lista.
    let id = unsafe { BindingId::at(address) };
    let _ = unicode::free(id.name.address());
    free(address);
}

/// PipDeleteBindingId: comparação com distinção de caixa.
fn delete_binding_id(target: &DependencyNode, name: u64) -> u32 {
    for address in links(&target.binding_ids) {
        // SAFETY: o registro do id de ligação.
        let id = unsafe { BindingId::at(address) };
        if names_equal(id.name.address(), name, false) {
            remove(&id.link);
            free_binding_id(address);
            return STATUS_SUCCESS;
        }
    }
    STATUS_NOT_FOUND
}

/// PipDeleteDependencyNode.
fn delete_node(target: &DependencyNode) {
    for address in links(&target.binding_ids).into_iter().rev() {
        remove(link(address));
        free_binding_id(address);
    }
    remove(&target.global_link);
    remove(&target.rebuild_link);
    free(target.address());
}

fn reference(target: &DependencyNode) {
    target.reference_count.set(target.reference_count.get().wrapping_add(1));
}

/// PipDereferenceDependencyNode.
fn dereference(target: &DependencyNode) {
    let count = target.reference_count.get().wrapping_sub(1);
    target.reference_count.set(count);
    if count == 0 {
        delete_node(target);
    }
}

/// PipLinkDeviceObjectAndDependencyNode.
fn link_device(device: u64, target: &DependencyNode) {
    reference(target);
    target.device_object.set(device);
    node_slot(device).set(target.address());
}

/// PipCreateDependencyNode: referência do chamador mais a do vínculo.
fn create_node(head: &ListEntry, binding: &Binding) -> u64 {
    let block = allocate(NON_PAGED_POOL_NX, DependencyNode::SIZE);
    if block == 0 {
        return 0;
    }
    let created = node(block);
    created.flags.set(0);
    for list in [&created.binding_ids, &created.dependent_edges, &created.provider_edges, &created.rebuild_link] {
        initialize_head(list);
    }
    created.reference_count.set(0);
    created.device_object.set(0);
    insert_tail(head, &created.global_link);
    if binding.kind == BINDING_NAME {
        if (add_binding_id(created, binding.value) as i32) < 0 {
            delete_node(created);
            return 0;
        }
    } else if binding.kind == BINDING_DEVICE {
        link_device(binding.value, created);
    }
    reference(created);
    block
}

/// PipAddRequestToEdge: o pedido igual soma as flags; senão um novo.
fn add_request(target: &DependencyEdge, binding: &Binding) -> bool {
    let mut found = 0u64;
    for address in links(&target.requests) {
        // SAFETY: um pedido da aresta.
        let request = unsafe { DependencyRequest::at(address) };
        let same = request.kind.get() == binding.kind
            && match binding.kind {
                BINDING_DEVICE => request.value.get() == binding.value,
                BINDING_NAME => names_equal(request.value.get(), binding.value, false),
                _ => false,
            };
        if same {
            found = address;
            break;
        }
    }
    if found != 0 {
        // SAFETY: o pedido achado acima.
        let request = unsafe { DependencyRequest::at(found) };
        request.flags.set(request.flags.get() | binding.flags);
    } else {
        let block = allocate(PAGED_POOL, DependencyRequest::SIZE);
        if block == 0 {
            return false;
        }
        // SAFETY: o bloco recém-alocado.
        let request = unsafe { DependencyRequest::at(block) };
        request.flags.set(binding.flags);
        request.kind.set(binding.kind);
        request.value.set(0);
        if binding.kind == BINDING_DEVICE {
            request.value.set(binding.value);
        } else if binding.kind == BINDING_NAME {
            let name = allocate(PAGED_POOL, UnicodeString::SIZE);
            if name == 0 || (unicode::duplicate(0, binding.value, name) as i32) < 0 {
                if name != 0 {
                    free(name);
                }
                free(block);
                return false;
            }
            request.value.set(name);
        }
        insert_tail(&target.requests, &request.link);
    }
    target.flags.set(target.flags.get() | binding.flags);
    true
}

/// PipCheckValidNewDependencyEdge (sem a ancestralidade dos devnodes).
fn valid_new_edge(dependent: &DependencyNode, provider: &DependencyNode) -> bool {
    if dependent.address() == provider.address() {
        return false;
    }
    !links(&provider.provider_edges).into_iter().any(|address| edge(address).provider.get() == dependent.address())
}

/// PipAddDependencyEdgeBetweenNodes.
fn add_edge(dependent: &DependencyNode, provider: &DependencyNode, binding: &Binding) -> u32 {
    if let Some(existing) = links(&dependent.provider_edges).into_iter().find(|&address| edge(address).provider.get() == provider.address()) {
        add_request(edge(existing), binding);
        return STATUS_SUCCESS;
    }
    if !valid_new_edge(dependent, provider) {
        return STATUS_UNSUCCESSFUL;
    }
    let block = allocate(NON_PAGED_POOL_NX, DependencyEdge::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let created = edge(block);
    created.flags.set(0);
    initialize_head(&created.requests);
    created.dependent.set(dependent.address());
    created.provider.set(provider.address());
    created.converted.set(0);
    if !add_request(created, binding) {
        free(block);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    reference(dependent);
    reference(provider);
    insert_tail(&provider.dependent_edges, &created.provider_link);
    insert_tail(&dependent.provider_edges, &created.dependent_link);
    STATUS_SUCCESS
}

/// Um nó achado (com referência) ou criado.
fn find_or_create(head: &ListEntry, binding: &Binding) -> u64 {
    let found = resolve(head.address(), binding);
    if found != 0 {
        reference(node(found));
        return found;
    }
    create_node(head, binding)
}

/// PipSetDependency.
fn set_dependency(head: &ListEntry, dependent: &Binding, provider: &Binding) -> u32 {
    let first = find_or_create(head, dependent);
    if first == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let second = find_or_create(head, provider);
    let status = if second == 0 { STATUS_INSUFFICIENT_RESOURCES } else { add_edge(node(first), node(second), provider) };
    dereference(node(first));
    if second != 0 {
        dereference(node(second));
    }
    status
}

/// Flags 1, 2 ou 3.
fn valid_flags(flags: u32) -> bool {
    flags & 3 != 0 && flags & !3 == 0
}

/// IoSetDependency(Dependent, Provider, Flags).
pub fn set(dependent: u64, provider: u64, flags: u32) -> u32 {
    if dependent == 0 || provider == 0 || !valid_flags(flags) {
        return STATUS_INVALID_PARAMETER;
    }
    if dependent == provider {
        return STATUS_UNSUCCESSFUL;
    }
    let mut graph = GRAPH.lock();
    let Some(head) = global_head(&mut graph) else { return STATUS_INSUFFICIENT_RESOURCES };
    set_dependency(head, &Binding { kind: BINDING_DEVICE, value: dependent, flags: 0 }, &Binding { kind: BINDING_DEVICE, value: provider, flags })
}

/// IoReserveDependency(Dependent, ProviderBindingName, Flags).
pub fn reserve(dependent: u64, name: u64, flags: u32) -> u32 {
    // SAFETY: o PUNICODE_STRING do chamador (lido só se não for nulo).
    if dependent == 0 || name == 0 || unsafe { UnicodeString::at(name) }.length.get() == 0 || !valid_flags(flags) {
        return STATUS_INVALID_PARAMETER;
    }
    let mut graph = GRAPH.lock();
    let Some(head) = global_head(&mut graph) else { return STATUS_INSUFFICIENT_RESOURCES };
    set_dependency(head, &Binding { kind: BINDING_DEVICE, value: dependent, flags: 0 }, &Binding { kind: BINDING_NAME, value: name, flags })
}

/// PipMergeDependencyNodes(A, B): B entra em A (ids e arestas).
fn merge(keep: &DependencyNode, absorbed: &DependencyNode) {
    reference(keep);
    reference(absorbed);
    keep.flags.set(keep.flags.get() | absorbed.flags.get());
    for address in links(&absorbed.binding_ids) {
        remove(link(address));
        insert_tail(&keep.binding_ids, link(address));
    }
    for provider_side in [false, true] {
        let (keep_list, absorbed_list) = if provider_side { (&keep.dependent_edges, &absorbed.dependent_edges) } else { (&keep.provider_edges, &absorbed.provider_edges) };
        let offset = if provider_side { core::mem::offset_of!(DependencyEdge, provider_link) as u64 } else { 0 };
        for entry in links(absorbed_list) {
            let moving = edge(entry - offset);
            let far = |candidate: &DependencyEdge| if provider_side { candidate.dependent.get() } else { candidate.provider.get() };
            let twin = links(keep_list).into_iter().map(|other| edge(other - offset)).find(|other| far(other) == far(moving));
            if let Some(twin) = twin {
                for request in links(&moving.requests) {
                    // SAFETY: um pedido da aresta absorvida.
                    let request = unsafe { DependencyRequest::at(request) };
                    add_request(twin, &Binding { kind: request.kind.get(), value: request.value.get(), flags: request.flags.get() });
                }
                free_edge(moving, Some(twin));
            } else {
                if provider_side {
                    moving.provider.set(keep.address());
                } else {
                    moving.dependent.set(keep.address());
                }
                remove(link(entry));
                insert_tail(keep_list, link(entry));
                reference(keep);
                dereference(absorbed);
            }
        }
    }
    dereference(keep);
    dereference(absorbed);
}

/// PipFreeDependencyEdge.
fn free_edge(target: &DependencyEdge, merge_into: Option<&DependencyEdge>) {
    for address in links(&target.requests) {
        remove(link(address));
        // SAFETY: o pedido fora da lista.
        let request = unsafe { DependencyRequest::at(address) };
        if request.kind.get() == BINDING_NAME && request.value.get() != 0 {
            let _ = unicode::free(request.value.get());
            free(request.value.get());
        }
        free(address);
    }
    if let Some(into) = merge_into {
        into.flags.set(into.flags.get() | target.flags.get());
    }
    remove(&target.dependent_link);
    remove(&target.provider_link);
    let (provider, dependent) = (target.provider.get(), target.dependent.get());
    dereference(node(provider));
    dereference(node(dependent));
    free(target.address());
}

/// IoResolveDependency(BindingName, ProviderDevice).
pub fn resolve_dependency(name: u64, provider: u64) -> u32 {
    let mut graph = GRAPH.lock();
    let Some(head) = global_head(&mut graph) else { return STATUS_INSUFFICIENT_RESOURCES };
    let mut status = STATUS_SUCCESS;
    let mut named = resolve(head.address(), &Binding { kind: BINDING_NAME, value: name, flags: 0 });
    if named != 0 {
        let found = node(named);
        if found.device_object.get() != 0 {
            if found.device_object.get() == provider {
                return STATUS_SUCCESS;
            }
            status = delete_binding_id(found, name);
            named = 0;
        } else {
            let existing = node_of(provider);
            if existing == 0 {
                link_device(provider, found);
            } else {
                merge(node(existing), found);
            }
        }
    }
    if named == 0 {
        let existing = node_of(provider);
        if existing != 0 {
            status = add_binding_id(node(existing), name);
            if (status as i32) < 0 {
                return status;
            }
        } else {
            let created = create_node(head, &Binding { kind: BINDING_DEVICE, value: provider, flags: 0 });
            if created == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            status = add_binding_id(node(created), name);
            if (status as i32) < 0 {
                // PipUnlinkDeviceObjectAndDependencyNode e a referência local.
                node_slot(provider).set(0);
                node(created).device_object.set(0);
                dereference(node(created));
                dereference(node(created));
                return status;
            }
            dereference(node(created));
        }
    }
    status
}

/// IoDuplicateDependency(ExistingProvider, NewProvider).
pub fn duplicate(existing: u64, new: u64) -> u32 {
    if existing == 0 || new == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut graph = GRAPH.lock();
    let Some(head) = global_head(&mut graph) else { return STATUS_INSUFFICIENT_RESOURCES };
    let source = node_of(existing);
    if source == 0 {
        return STATUS_SUCCESS;
    }
    let target = find_or_create(head, &Binding { kind: BINDING_DEVICE, value: new, flags: 0 });
    if target == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let mut status = STATUS_SUCCESS;
    'edges: for entry in links(&node(source).dependent_edges) {
        let copied = edge(entry - core::mem::offset_of!(DependencyEdge, provider_link) as u64);
        for request in links(&copied.requests) {
            // SAFETY: um pedido da aresta copiada.
            let request = unsafe { DependencyRequest::at(request) };
            let result = add_edge(node(copied.dependent.get()), node(target), &Binding { kind: request.kind.get(), value: request.value.get(), flags: request.flags.get() });
            if (result as i32) < 0 {
                status = result;
                break 'edges;
            }
        }
    }
    dereference(node(target));
    status
}

/// PipDependencyGraphDepthFirstSearch: (profundidade, flags da primeira
/// aresta do caminho). Um conjunto de visitados evita a recursão sem fim
/// do original num ciclo de três ou mais nós (o resultado num grafo
/// acíclico não muda).
fn depth_first(current: u64, target: u64, visited: &mut alloc::vec::Vec<u64>) -> Option<(u32, u32)> {
    if current == target {
        return Some((0, 0));
    }
    if visited.contains(&current) {
        return None;
    }
    visited.push(current);
    for address in links(&node(current).provider_edges) {
        let next = edge(address);
        if let Some((depth, _)) = depth_first(next.provider.get(), target, visited) {
            return Some((depth + 1, next.flags.get()));
        }
    }
    None
}

/// IoTestDependency(Dependent, Provider, PathType*, EdgeFlags*).
pub fn test(dependent: u64, provider: u64, path_type: &Field<u32>, edge_flags: &Field<u32>) -> u32 {
    if dependent == 0 || provider == 0 || dependent == provider {
        return STATUS_INVALID_PARAMETER;
    }
    let _graph = GRAPH.lock();
    let (from, to) = (node_of(dependent), node_of(provider));
    if from == 0 || to == 0 {
        path_type.set(0);
        edge_flags.set(0);
        return STATUS_SUCCESS;
    }
    let (depth, flags) = depth_first(from, to, &mut alloc::vec::Vec::new()).unwrap_or((0, 0));
    path_type.set(match depth {
        0 => 0,
        1 => 1,
        _ => 2,
    });
    edge_flags.set(flags);
    STATUS_SUCCESS
}
