//! Namespace WNF.
//!
//! Instâncias de escopo e de nome: listas, árvore AVL, rundown e caches na
//! memória do convidado. O serviço fornece a desmontagem dos assinantes; uma
//! instância só é liberada depois que esses vínculos saem. Há um namespace
//! por vez (o do serviço WNF), porque as rotinas de saída de processo e de
//! destruição de silo são globais.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::ntos::ex::wnf::data_block::{self as state_data, NameState};
use crate::ntos::ex::wnf::definition::Definition;
use crate::ntos::ex::{pool_allocation, pool_quota, push_lock, rundown};
use crate::ntos::ex::wnf::{physical as wnf_physical, registry as wnf_registry, scope_identity as wnf_scope_identity};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close;
use crate::ntos::ps::{previous_mode, process, process_context};
use crate::ntos::ps::silo::{contexts as silo_contexts, query as silo_query};
use crate::ntos::rtl::avl;
use crate::ntos::se::descriptor;
use core::mem::offset_of;
use core::sync::atomic::Ordering::SeqCst;

use super::objects::{name_at, process_at, process_context_at, scope_at, scope_map_at};
use crate::ntos::ex::list_entry;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{
    Ejob, EserversiloGlobals, ExPushLock, ListEntry, Sid, WnfDataScope, WnfNameInstance, WnfProcessContext, WnfScopeInstance, WnfScopeMap,
    Guid,
};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const STATE_TAG: u32 = 0x2066_6E57;
const DESCRIPTOR_TAG: u32 = 0x6353_624F;
const FRAME_TAG: u32 = 0x6E66_6E57;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Estado WNF do host: o mapa de escopos, as raízes de definição por tempo
/// de vida (handles), a lista de contextos de processo e o lock dela.
#[repr(C)]
struct HostStorage {
    /// -> WNF_SCOPE_MAP do host.
    scope_map: Field<u64>,
    root_keys: [Field<u64>; 3],
    process_contexts: ListEntry,
    process_contexts_lock: ExPushLock,
    _pad_38: Reserved<0x8>,
}

/// Entrada do cache de descritores: o contador de referências, o hash e o
/// tamanho; a cópia autocontida do descritor vem logo depois.
#[repr(C)]
struct DescriptorCacheEntry {
    _reserved: Field<u64>,
    reference_count: Field<u64>,
    hash: Field<u64>,
    length: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

/// Moldura de pool da identidade corrente: o valor (ou ponteiro), o tamanho
/// e se o escopo pode ir para o cache.
#[repr(C)]
struct IdentityFrame {
    identity: Field<u64>,
    length: Field<u32>,
    cacheable: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for HostStorage {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DescriptorCacheEntry {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for IdentityFrame {}

const _: () = {
    assert!(core::mem::size_of::<HostStorage>() == 64);
    assert!(core::mem::offset_of!(HostStorage, process_contexts) == 32);
    assert!(core::mem::offset_of!(HostStorage, process_contexts_lock) == 48);
    assert!(core::mem::size_of::<DescriptorCacheEntry>() == 0x20);
    assert!(core::mem::size_of::<IdentityFrame>() == 16);
};

fn host_at(host: u64) -> &'static HostStorage {
    // SAFETY: o estado do host alocado por `ensure_host_storage`.
    unsafe { HostStorage::at(host) }
}

fn cache_entry(allocation: u64) -> &'static DescriptorCacheEntry {
    // SAFETY: entradas do cache alocadas por `retain_descriptor`.
    unsafe { DescriptorCacheEntry::at(allocation) }
}

/// Uma célula de handle (raiz de definições ou armazém permanente).
fn slot_at(slot: u64) -> &'static Field<u64> {
    // SAFETY: slots do host, do SILO_GLOBALS ou da instância de escopo.
    unsafe { Field::<u64>::at(slot) }
}

/// ESERVERSILO_GLOBALS.WnfSiloState do silo.
fn silo_state(silo: u64) -> Result<&'static crate::ntos::inc::types::WnfSilodriverstate, KernelError> {
    let globals = silo_globals(silo)?;
    // SAFETY: os globais vivos do silo de servidor.
    Ok(&unsafe { EserversiloGlobals::at(globals) }.wnf_silo_state)
}
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

/// Desmontagem dos assinantes, fornecida pelo serviço de notificações.
#[derive(Clone, Copy)]
pub struct Lifecycle {
    pub delete_name_subscriptions: fn(u64),
    pub delete_process_subscriptions: fn(u64, u64),
}

/// Definição usada para criar um nome (cópia da hive ou do chamador).
#[derive(Clone, Copy, Debug)]
pub struct NameDefinition {
    pub maximum_size: u32,
    pub type_identifier: u64,
    pub security_descriptor: u64,
}

impl From<&Definition> for NameDefinition {
    fn from(definition: &Definition) -> Self {
        Self { maximum_size: definition.maximum_size, type_identifier: definition.type_identifier, security_descriptor: definition.security_descriptor }
    }
}

struct DescriptorEntry {
    allocation: u64,
    key: Vec<u8>,
}

struct Namespace {
    lifecycle: Lifecycle,
    host_storage: u64,
    processes: BTreeMap<u64, u64>,
    scopes: BTreeSet<u64>,
    scope_maps: BTreeMap<u64, u64>,
    silo_map_slots: BTreeMap<u64, u64>,
    names: BTreeSet<u64>,
    descriptor_entries: BTreeMap<Vec<u8>, u64>,
    descriptors_by_pointer: BTreeMap<u64, DescriptorEntry>,
    silo_root_slots: BTreeMap<u64, BTreeSet<u64>>,
}

static NAMESPACE: SpinLock<Option<Namespace>> = SpinLock::new(None);

type Outcome<T> = Result<Result<T, u32>, KernelError>;

fn with<T>(body: impl FnOnce(&mut Namespace) -> T) -> Result<T, KernelError> {
    let mut namespace = NAMESPACE.lock();
    let namespace = namespace.as_mut().ok_or_else(|| KernelError::new("WNF namespace already disposed"))?;
    Ok(body(namespace))
}

fn clear_bytes(pointer: u64, length: u64) {
    guest::write_bytes(pointer, &alloc::vec![0u8; length as usize]);
}

fn copy_bytes(destination: u64, source: u64, length: u64) {
    if length != 0 {
        guest::write_bytes(destination, &guest::read_bytes(source, length as usize));
    }
}

fn insert_last(head: &ListEntry, entry: &ListEntry) -> Result<(), KernelError> {
    if !list_entry::tail_consistent(head) {
        return Err(KernelError::new("corrupt WNF list tail"));
    }
    list_entry::insert_tail(head, entry);
    Ok(())
}

fn unlink(entry: &ListEntry) -> Result<(), KernelError> {
    list_entry::remove(entry).ok_or_else(|| KernelError::new("corrupt WNF list links"))?;
    entry.flink.set(0);
    Ok(())
}

fn with_lock<T>(pointer: u64, exclusive: bool, action: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if exclusive {
        push_lock::acquire_exclusive(pointer, 0)?;
    } else {
        push_lock::acquire_shared(pointer, 0)?;
    }
    let result = action();
    if exclusive {
        push_lock::release_exclusive(pointer, 0)?;
    } else {
        push_lock::release_shared(pointer, 0)?;
    }
    result
}

/// Acessores vivos da instância de nome.
pub fn describe_name(pointer: u64) -> NameState {
    NameState { pointer }
}

/// A instância de nome dona do nó AVL (`TreeLinks`).
fn name_of_node(node: u64) -> &'static WnfNameInstance {
    name_at(node - offset_of!(WnfNameInstance, tree_links) as u64)
}

fn find_name(scope_instance: u64, decoded_name: u64) -> u64 {
    let mut node = scope_at(scope_instance).name_set.root.get();
    while node != 0 {
        let name = name_of_node(node);
        let candidate = name.state_name.bitfield_0.get();
        if candidate == decoded_name {
            return name.address();
        }
        node = name.tree_links.children[if decoded_name < candidate { 0 } else { 1 }].get();
    }
    0
}

fn find_scope(head: &ListEntry, identity: u64, length: u32) -> u64 {
    let mut entry = head.flink.get();
    while entry != head.address() {
        let instance = scope_at(entry - offset_of!(WnfScopeInstance, resolver_list_entry) as u64);
        if instance.instance_id_size.get() == length {
            let stored = instance.instance_id_data.get();
            if guest::read_bytes(stored, length as usize) == guest::read_bytes(identity, length as usize) {
                return instance.address();
            }
        }
        entry = list_entry::at(entry).flink.get();
    }
    0
}

fn exit_routine(process: u64) {
    if NAMESPACE.lock().is_some() {
        if let Err(error) = release_process(process) {
            debug_print!("[wnf] {}", error);
        }
    }
}

fn destroy_routine(silo: u64) {
    if NAMESPACE.lock().is_some() {
        if let Err(error) = release_silo(silo) {
            debug_print!("[wnf] {}", error);
        }
    }
}

/// Cria o namespace do serviço e registra as rotinas de saída de processo e
/// destruição de silo.
pub fn create(lifecycle: Lifecycle) -> Result<(), KernelError> {
    {
        let mut namespace = NAMESPACE.lock();
        if namespace.is_some() {
            return Err(KernelError::new("WNF namespace already exists"));
        }
        *namespace = Some(Namespace {
            lifecycle,
            host_storage: 0,
            processes: BTreeMap::new(),
            scopes: BTreeSet::new(),
            scope_maps: BTreeMap::new(),
            silo_map_slots: BTreeMap::new(),
            names: BTreeSet::new(),
            descriptor_entries: BTreeMap::new(),
            descriptors_by_pointer: BTreeMap::new(),
            silo_root_slots: BTreeMap::new(),
        });
    }
    process::register_process_exit_routine(exit_routine);
    silo_contexts::register_destroy_routine(destroy_routine);
    Ok(())
}

pub fn exists() -> bool {
    NAMESPACE.lock().is_some()
}

/// Mapa, três slots de raízes e a lista de contextos de processo do host.
fn ensure_host_storage() -> Result<u64, KernelError> {
    let existing = with(|namespace| namespace.host_storage)?;
    if existing != 0 {
        return Ok(existing);
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, HostStorage::SIZE, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, HostStorage::SIZE);
    list_entry::initialize(&host_at(candidate).process_contexts);
    let winner = with(|namespace| {
        if namespace.host_storage == 0 {
            namespace.host_storage = candidate;
        }
        namespace.host_storage
    })?;
    if winner != candidate {
        let _ = kernel_pool::free(candidate, Some(STATE_TAG));
    }
    Ok(winner)
}

fn silo_globals(silo: u64) -> Result<u64, KernelError> {
    // SAFETY: o silo de servidor corrente (vivo enquanto anexado).
    let globals = unsafe { Ejob::at(silo) }.server_silo_globals.get();
    if globals == 0 {
        return Err(KernelError::new("WNF server silo has no globals"));
    }
    Ok(globals)
}

/// Slot da raiz de definições do tempo de vida (host ou SILO_GLOBALS).
fn root_slot(lifetime: u32) -> Result<u64, KernelError> {
    let host = ensure_host_storage()?;
    if host == 0 {
        return Ok(0);
    }
    let silo = if lifetime == 0 { 0 } else { silo_query::current_server_silo() };
    if silo == 0 {
        return Ok(host_at(host).root_keys[lifetime as usize].address());
    }
    let state = silo_state(silo)?;
    let slot = if lifetime == 1 { state.permanent_name_store_root_key.address() } else { state.persistent_name_store_root_key.address() };
    with(|namespace| namespace.silo_root_slots.entry(silo).or_default().insert(slot))?;
    Ok(slot)
}

fn ensure_scope_map(silo: u64) -> Result<u64, KernelError> {
    let host = ensure_host_storage()?;
    if host == 0 {
        return Ok(0);
    }
    let mut slot = host_at(host).scope_map.address();
    if silo != 0 {
        slot = silo_state(silo)?.scope_map.address();
        with(|namespace| namespace.silo_map_slots.insert(silo, slot))?;
    }
    let pointer = slot_at(slot).get();
    if pointer != 0 {
        return Ok(pointer);
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, WnfScopeMap::SIZE, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, WnfScopeMap::SIZE);
    let map = scope_map_at(candidate);
    map.header.node_type_code.set(0x901);
    map.header.node_byte_size.set(WnfScopeMap::SIZE as u16);
    for entry in &map.by_data_scope {
        list_entry::initialize(&entry.map_entry_head);
    }
    let previous = match slot_at(slot).atomic().compare_exchange(0, candidate, SeqCst, SeqCst) {
        Ok(value) | Err(value) => value,
    };
    if previous != 0 {
        let _ = kernel_pool::free(candidate, Some(STATE_TAG));
        return Ok(previous);
    }
    Ok(candidate)
}

/// Contexto WNF do EPROCESS, publicado por compare-exchange sob o lock do host.
pub fn ensure_process_context(process: u64) -> Result<u64, KernelError> {
    let host = ensure_host_storage()?;
    if host == 0 {
        return Ok(0);
    }
    let field = &process_at(process).wnf_context;
    let existing = field.get();
    if existing != 0 {
        if with(|namespace| namespace.processes.get(&process).copied())? != Some(existing) {
            return Err(KernelError::new("WNF process context has a different owner"));
        }
        return Ok(existing);
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, WnfProcessContext::SIZE, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, WnfProcessContext::SIZE);
    let context = process_context_at(candidate);
    context.header.node_type_code.set(0x906);
    context.header.node_byte_size.set(WnfProcessContext::SIZE as u16);
    context.process.set(process);
    for head in [&context.temporary_names_list_head, &context.process_subscription_list_head, &context.delivery_pending_list_head] {
        list_entry::initialize(head);
    }
    let host = host_at(host);
    let winner = with_lock(host.process_contexts_lock.address(), true, || {
        let previous = match field.atomic().compare_exchange(0, candidate, SeqCst, SeqCst) {
            Ok(value) | Err(value) => value,
        };
        if previous != 0 {
            return Ok(previous);
        }
        insert_last(&host.process_contexts, &context.wnf_processes_list_entry)?;
        with(|namespace| namespace.processes.insert(process, candidate))?;
        Ok(candidate)
    })?;
    if winner != candidate {
        let _ = kernel_pool::free(candidate, Some(STATE_TAG));
    }
    Ok(winner)
}

/// Resolve (ou cria) a instância de escopo com uma referência de rundown.
/// Nt usa o silo corrente para sistema/sessão/usuário/processo; máquina e
/// máquina física são globais e o Zw sempre usa o mapa do host.
fn resolve_scope(process: u64, scope: u32, explicit_identity: u64, thread: u64, from_user_mode: bool) -> Outcome<u64> {
    if scope > 5 {
        return Err(KernelError::new("WNF scope must be captured before resolution"));
    }
    let silo = if from_user_mode && scope < 4 { silo_query::current_server_silo() } else { 0 };
    let map = ensure_scope_map(silo)?;
    if map == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let context = ensure_process_context(process)?;
    if context == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let map_object = scope_map_at(map);
    let cache_slot = match scope {
        0 => &map_object.system_scope_instance,
        4 => &map_object.machine_scope_instance,
        5 => &map_object.physical_machine_scope_instance,
        _ => &process_context_at(context).implicit_scope_instances[scope as usize - 1],
    };
    let explicit = explicit_identity != 0;
    let mut can_cache = (!explicit && thread == 0) || scope == 0 || scope >= 4;
    let cached = if can_cache { cache_slot.get() } else { 0 };
    if cached != 0 {
        return Ok(if rundown::acquire(scope_at(cached).run_ref.address())? { Ok(cached) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
    }
    let mut identity = explicit_identity;
    let mut length = 0u32;
    let mut frame = 0u64;
    let mut identity_allocation = 0u64;
    let mut candidate = 0u64;
    let result = (|| -> Outcome<u64> {
        if explicit {
            // SeCaptureSid em KernelMode só empresta o ponteiro.
            length = match scope {
                1 => 4,
                3 => 8,
                // SID de modo kernel emprestado pelo chamador (sem exigir alinhamento).
                2 => offset_of!(Sid, sub_authority) as u32 + guest::read::<u8>(identity + offset_of!(Sid, sub_authority_count) as u64) as u32 * 4,
                _ => 0,
            };
        } else {
            frame = kernel_pool::allocate(IdentityFrame::SIZE, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }).unwrap_or(0);
            if frame == 0 {
                return Ok(Err(0xC000_0017));
            }
            // SAFETY: alocação nova do tamanho da moldura.
            let identity_frame = unsafe { IdentityFrame::at(frame) };
            identity_frame.length.set(8);
            identity_frame.cacheable.set(can_cache as u32);
            identity = identity_frame.identity.address();
            let mut status = wnf_scope_identity::query_current(process, thread, scope, identity, identity_frame.length.address(), identity_frame.cacheable.address())?;
            if status == 0xC000_0023 {
                identity_allocation = pool_allocation::allocate_tagged(1, identity_frame.length.get() as u64, STATE_TAG).unwrap_or(0);
                if identity_allocation == 0 {
                    return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
                }
                identity = identity_allocation;
                status = wnf_scope_identity::query_current(process, thread, scope, identity, identity_frame.length.address(), identity_frame.cacheable.address())?;
            }
            if status & 0x8000_0000 != 0 {
                return Ok(Err(status));
            }
            length = identity_frame.length.get();
            can_cache = identity_frame.cacheable.get() != 0;
        }
        let map_entry = &map_object.by_data_scope[scope as usize];
        let lock = map_entry.map_entry_lock.address();
        let head = &map_entry.map_entry_head;
        let found = with_lock(lock, false, || {
            let pointer = find_scope(head, identity, length);
            Ok(if pointer != 0 { Some((pointer, rundown::acquire(scope_at(pointer).run_ref.address())?)) } else { None })
        })?;
        if let Some((pointer, acquired)) = found {
            return Ok(if acquired { Ok(pointer) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
        }
        candidate = pool_allocation::allocate_tagged(1, length.wrapping_add(WnfScopeInstance::SIZE as u32) as u64, STATE_TAG).unwrap_or(0);
        if candidate == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        clear_bytes(candidate, WnfScopeInstance::SIZE);
        let instance = scope_at(candidate);
        instance.header.node_type_code.set(0x902);
        instance.header.node_byte_size.set(WnfScopeInstance::SIZE as u16);
        instance.data_scope.set(WnfDataScope(scope as i32));
        instance.instance_id_size.set(length);
        if length != 0 {
            // A identidade fica logo depois da instância.
            instance.instance_id_data.set(candidate + WnfScopeInstance::SIZE);
            copy_bytes(candidate + WnfScopeInstance::SIZE, identity, length as u64);
        }
        with_lock(lock, true, || {
            let winner = find_scope(head, identity, length);
            if winner != 0 {
                return Ok(if rundown::acquire(scope_at(winner).run_ref.address())? { Ok(winner) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
            }
            let published = candidate;
            if !rundown::acquire(instance.run_ref.address())? {
                return Err(KernelError::new("new WNF scope already in rundown"));
            }
            insert_last(head, &instance.resolver_list_entry)?;
            with(|namespace| {
                namespace.scopes.insert(published);
                namespace.scope_maps.insert(published, map);
            })?;
            candidate = 0;
            if can_cache {
                let _ = cache_slot.atomic().compare_exchange(0, published, SeqCst, SeqCst);
            }
            Ok(Ok(published))
        })
    })();
    if candidate != 0 {
        let _ = kernel_pool::free(candidate, Some(STATE_TAG));
    }
    if identity_allocation != 0 {
        let _ = kernel_pool::free(identity_allocation, Some(STATE_TAG));
    }
    if frame != 0 {
        let _ = kernel_pool::free(frame, Some(FRAME_TAG));
    }
    result
}

pub fn resolve_kernel_scope(process: u64, scope: u32, explicit_identity: u64) -> Outcome<u64> {
    resolve_scope(process, scope, explicit_identity, 0, false)
}

pub fn resolve_user_scope(process: u64, scope: u32, explicit_identity: u64) -> Outcome<u64> {
    resolve_scope(process, scope, explicit_identity, process::get_current_thread(), true)
}

/// Cópia do descritor no cache compartilhado por nomes distintos; o
/// contador nativo impede liberar um descritor em uso.
fn retain_descriptor(source: u64) -> Result<u64, KernelError> {
    let length = descriptor::length(source) as u64;
    let key = guest::read_bytes(source, length as usize);
    let mut hash = 0u64;
    let mut offset = 0usize;
    while offset < (length & !7) as usize {
        hash ^= u64::from_le_bytes(key[offset..offset + 8].try_into().unwrap_or([0; 8]));
        hash = hash.rotate_left(3);
        offset += 16;
    }
    let header = DescriptorCacheEntry::SIZE;
    // A referência é tomada sob o lock do namespace, junto da busca: uma
    // liberação concorrente não solta a entrada entre as duas.
    let retained = with(|namespace| {
        namespace.descriptor_entries.get(&key).copied().inspect(|&allocation| {
            cache_entry(allocation).reference_count.atomic().fetch_add(1, SeqCst);
        })
    })?;
    if let Some(allocation) = retained {
        return Ok(allocation + header);
    }
    let Ok(created) = pool_allocation::allocate_tagged(5, length + header + 8, DESCRIPTOR_TAG) else { return Ok(0) };
    clear_bytes(created, header + 8);
    copy_bytes(created + header, source, length);
    let entry = cache_entry(created);
    entry.hash.set(hash);
    entry.length.set(length as u32);
    let allocation = with(|namespace| {
        let allocation = match namespace.descriptor_entries.get(&key) {
            Some(&existing) => existing,
            None => {
                namespace.descriptor_entries.insert(key.clone(), created);
                namespace.descriptors_by_pointer.insert(created + header, DescriptorEntry { allocation: created, key: key.clone() });
                created
            }
        };
        cache_entry(allocation).reference_count.atomic().fetch_add(1, SeqCst);
        allocation
    })?;
    if allocation != created {
        let _ = kernel_pool::free(created, Some(DESCRIPTOR_TAG));
    }
    Ok(allocation + header)
}

fn release_descriptor(pointer: u64) -> Result<(), KernelError> {
    // Decremento atômico e retirada do cache sob o mesmo lock da busca.
    let released = with(|namespace| -> Result<Option<u64>, KernelError> {
        let allocation = namespace.descriptors_by_pointer.get(&pointer).map(|entry| entry.allocation).ok_or_else(|| KernelError::new("WNF descriptor has no owner"))?;
        let previous = cache_entry(allocation)
            .reference_count
            .atomic()
            .try_update(SeqCst, SeqCst, |count| count.checked_sub(1))
            .map_err(|_| KernelError::new("WNF descriptor reference underflow"))?;
        if previous != 1 {
            return Ok(None);
        }
        if let Some(entry) = namespace.descriptors_by_pointer.remove(&pointer) {
            namespace.descriptor_entries.remove(&entry.key);
        }
        Ok(Some(allocation))
    })??;
    if let Some(allocation) = released {
        let _ = kernel_pool::free(allocation, Some(DESCRIPTOR_TAG));
    }
    Ok(())
}

/// Procura o nome na árvore do escopo e adquire seu rundown.
pub fn lookup_name(scope_instance: u64, decoded_name: u64) -> Outcome<NameState> {
    with_lock(scope_at(scope_instance).name_set_lock.address(), false, || {
        let pointer = find_name(scope_instance, decoded_name);
        Ok(if pointer != 0 && rundown::acquire(name_at(pointer).run_ref.address())? { Ok(describe_name(pointer)) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) })
    })
}

/// Definição do nome pela raiz do tempo de vida; nomes bem conhecidos são
/// lidos anexados ao host.
pub fn lookup_definition(decoded_name: u64) -> Outcome<Definition> {
    let lifetime = ((decoded_name >> 4) & 3) as u32;
    if lifetime == 3 {
        return Ok(Err(STATUS_OBJECT_NAME_NOT_FOUND));
    }
    let previous = (lifetime == 0).then(|| silo_query::attach(0));
    let result = (|| match root_slot(lifetime)? {
        0 => Ok(Err(STATUS_INSUFFICIENT_RESOURCES)),
        slot => wnf_registry::lookup_definition(decoded_name, slot),
    })();
    if let Some(previous) = previous {
        silo_query::detach(previous);
    }
    result
}

fn free_unpublished_name(pointer: u64) -> Result<(), KernelError> {
    let state = describe_name(pointer);
    if state.data_pointer() > 1 {
        let _ = kernel_pool::free(state.data_pointer(), Some(STATE_TAG));
    }
    if state.security_descriptor() != 0 {
        release_descriptor(state.security_descriptor())?;
    }
    let _ = kernel_pool::free(pointer, Some(STATE_TAG));
    Ok(())
}

/// Cria a instância do nome a partir da definição, carrega os dados (hive
/// local ou transporte físico) e só então a insere na árvore do escopo.
pub fn create_name(scope_instance: u64, decoded_name: u64, definition: NameDefinition, creator_process: u64) -> Outcome<NameState> {
    let lifetime = ((decoded_name >> 4) & 3) as u32;
    // Um TypeId vai logo depois da instância.
    let size = WnfNameInstance::SIZE + if definition.type_identifier != 0 { Guid::SIZE } else { 0 };
    let mut candidate = if lifetime == 3 && creator_process != process::get_system_process() {
        process_context::with_process(creator_process, || pool_quota::allocate(9, size, STATE_TAG))?.unwrap_or(0)
    } else {
        pool_allocation::allocate_tagged(1, size, STATE_TAG).unwrap_or(0)
    };
    if candidate == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    clear_bytes(candidate, WnfNameInstance::SIZE);
    let result = (|| -> Outcome<NameState> {
        let name = name_at(candidate);
        name.header.node_type_code.set(0x903);
        name.header.node_byte_size.set(WnfNameInstance::SIZE as u16);
        name.state_name.bitfield_0.set(decoded_name);
        name.scope_instance.set(scope_instance);
        name.state_name_info.max_state_size.set(definition.maximum_size);
        if definition.type_identifier != 0 {
            name.state_name_info.type_id.set(candidate + WnfNameInstance::SIZE);
            copy_bytes(candidate + WnfNameInstance::SIZE, definition.type_identifier, Guid::SIZE);
        }
        let security = retain_descriptor(definition.security_descriptor)?;
        if security == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        name.state_name_info.security_descriptor.set(security);
        list_entry::initialize(&name.state_subscription_list_head);
        if decoded_name & 1024 != 0 {
            let slot = root_slot(1)?;
            if slot == 0 {
                return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
            }
            match wnf_registry::get_permanent_store(scope_instance, lifetime, 1, slot)? {
                Ok(store) => name.permanent_data_store.set(store.handle),
                Err(_) => return Ok(Err(STATUS_INSUFFICIENT_RESOURCES)),
            }
        }
        let state = describe_name(candidate);
        let mut status = if (decoded_name >> 6) & 15 == 5 { wnf_physical::populate(candidate) } else { 0xC000_0002 };
        if status == 0xC000_0002 {
            status = state_data::load_local(&state)?;
        } else if status & 0x8000_0000 == 0 {
            status = 0;
        }
        if status != 0 {
            return Ok(Err(status));
        }
        let temporary_context = if lifetime == 3 { ensure_process_context(creator_process)? } else { 0 };
        if lifetime == 3 && temporary_context == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        let scope = scope_at(scope_instance);
        with_lock(scope.name_set_lock.address(), true, || {
            let winner = find_name(scope_instance, decoded_name);
            if winner != 0 {
                return Ok(if rundown::acquire(name_at(winner).run_ref.address())? { Ok(describe_name(winner)) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
            }
            let mut parent = scope.name_set.root.get();
            let mut right = false;
            while parent != 0 {
                let parent_name = name_of_node(parent);
                right = decoded_name >= parent_name.state_name.bitfield_0.get();
                let next = parent_name.tree_links.children[right as usize].get();
                if next == 0 {
                    break;
                }
                parent = next;
            }
            let published = candidate;
            if !rundown::acquire(name.run_ref.address())? {
                return Err(KernelError::new("new WNF name already in rundown"));
            }
            avl::insert(scope.name_set.address(), parent, right as u64, name.tree_links.address())?;
            if lifetime == 3 {
                name.creator_process.set(creator_process);
                let context = process_context_at(temporary_context);
                with_lock(context.temporary_names_list_lock.address(), true, || insert_last(&context.temporary_names_list_head, &name.temporary_name_list_entry))?;
            }
            with(|namespace| namespace.names.insert(published))?;
            candidate = 0;
            Ok(Ok(describe_name(published)))
        })
    })();
    if candidate != 0 {
        free_unpublished_name(candidate)?;
    }
    result
}

/// Retira o nome da árvore, desmonta os assinantes, espera o rundown e
/// libera a instância.
pub fn delete_name(pointer: u64) -> Result<(), KernelError> {
    if !with(|namespace| namespace.names.contains(&pointer))? {
        return Err(KernelError::new("WNF name has no namespace owner"));
    }
    let name = name_at(pointer);
    let scope = scope_at(name.scope_instance.get());
    with_lock(scope.name_set_lock.address(), true, || {
        with_lock(name.state_subscription_list_lock.address(), true, || {
            avl::remove(scope.name_set.address(), name.tree_links.address())?;
            name.scope_instance.set(0);
            Ok(())
        })
    })?;
    let lifecycle = with(|namespace| namespace.lifecycle)?;
    (lifecycle.delete_name_subscriptions)(pointer);
    let creator = name.creator_process.get();
    if creator != 0 {
        let context = with(|namespace| namespace.processes.get(&creator).copied())?.ok_or_else(|| KernelError::new("temporary WNF name lost its creator"))?;
        let context = process_context_at(context);
        with_lock(context.temporary_names_list_lock.address(), true, || unlink(&name.temporary_name_list_entry))?;
        name.creator_process.set(0);
    }
    rundown::wait(name.run_ref.address())?;
    with(|namespace| namespace.names.remove(&pointer))?;
    free_unpublished_name(pointer)
}

fn close_slot(slot: u64) -> Result<(), KernelError> {
    let handle = slot_at(slot).get();
    if handle == 0 {
        return Ok(());
    }
    let status = previous_mode::with_kernel(|| close::close(handle, Some(0)))??;
    if status != 0 {
        return Err(KernelError::new("WNF owner could not close registry handle"));
    }
    slot_at(slot).set(0);
    Ok(())
}

fn delete_scope(pointer: u64) -> Result<(), KernelError> {
    let map = with(|namespace| namespace.scopes.contains(&pointer).then(|| namespace.scope_maps.get(&pointer).copied()).flatten())?.ok_or_else(|| KernelError::new("WNF scope has no namespace owner"))?;
    let instance = scope_at(pointer);
    let map = scope_map_at(map);
    let map_entry = &map.by_data_scope[instance.data_scope.get().0 as usize];
    with_lock(map_entry.map_entry_lock.address(), true, || unlink(&instance.resolver_list_entry))?;
    for slot in [&map.system_scope_instance, &map.machine_scope_instance, &map.physical_machine_scope_instance] {
        let _ = slot.atomic().compare_exchange(pointer, 0, SeqCst, SeqCst);
    }
    let contexts: Vec<u64> = with(|namespace| namespace.processes.values().copied().collect())?;
    for context in contexts {
        for slot in &process_context_at(context).implicit_scope_instances {
            let _ = slot.atomic().compare_exchange(pointer, 0, SeqCst, SeqCst);
        }
    }
    rundown::wait(instance.run_ref.address())?;
    loop {
        let node = instance.name_set.root.get();
        if node == 0 {
            break;
        }
        delete_name(name_of_node(node).address())?;
    }
    close_slot(instance.permanent_data_store.address())?;
    close_slot(instance.volatile_permanent_data_store.address())?;
    with(|namespace| {
        namespace.scopes.remove(&pointer);
        namespace.scope_maps.remove(&pointer);
    })?;
    let _ = kernel_pool::free(pointer, Some(STATE_TAG));
    Ok(())
}

/// Saída de processo: assinantes, nomes temporários, escopo de processo e
/// o contexto do EPROCESS.
pub fn release_process(process: u64) -> Result<(), KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<(), KernelError> {
        let (context, lifecycle, host) = with(|namespace| (namespace.processes.get(&process).copied(), namespace.lifecycle, namespace.host_storage))?;
        if let Some(context) = context {
            (lifecycle.delete_process_subscriptions)(process, context);
            let head = &process_context_at(context).temporary_names_list_head;
            loop {
                let entry = head.flink.get();
                if entry == head.address() {
                    break;
                }
                delete_name(entry - offset_of!(WnfNameInstance, temporary_name_list_entry) as u64)?;
            }
        }
        let scopes: Vec<u64> = with(|namespace| namespace.scopes.iter().copied().collect())?;
        for scope in scopes {
            // O escopo de processo guarda o EPROCESS logo depois da instância.
            if scope_at(scope).data_scope.get().0 == 3 && slot_at(scope + WnfScopeInstance::SIZE).get() == process {
                delete_scope(scope)?;
            }
        }
        let Some(context) = context else { return Ok(()) };
        with_lock(host_at(host).process_contexts_lock.address(), true, || {
            if process_at(process).wnf_context.atomic().compare_exchange(context, 0, SeqCst, SeqCst).is_err() {
                return Err(KernelError::new("WNF process context changed owner"));
            }
            unlink(&process_context_at(context).wnf_processes_list_entry)?;
            with(|namespace| namespace.processes.remove(&process))?;
            Ok(())
        })?;
        let _ = kernel_pool::free(context, Some(STATE_TAG));
        Ok(())
    })();
    let left = critical_region::leave_critical();
    result?;
    left
}

/// Destruição de silo: escopos do mapa do silo e os handles das raízes.
pub fn release_silo(silo: u64) -> Result<(), KernelError> {
    if let Some(map_slot) = with(|namespace| namespace.silo_map_slots.get(&silo).copied())? {
        let map = slot_at(map_slot).get();
        let owned: Vec<u64> = with(|namespace| namespace.scope_maps.iter().filter(|&(_, &owner)| owner == map).map(|(&scope, _)| scope).collect())?;
        for scope in owned {
            delete_scope(scope)?;
        }
        if map != 0 {
            let _ = kernel_pool::free(map, Some(STATE_TAG));
        }
        slot_at(map_slot).set(0);
        with(|namespace| namespace.silo_map_slots.remove(&silo))?;
    }
    let slots: Vec<u64> = with(|namespace| namespace.silo_root_slots.remove(&silo).map(|slots| slots.into_iter().collect()).unwrap_or_default())?;
    for slot in slots {
        close_slot(slot)?;
    }
    Ok(())
}

/// Desmonta tudo; recursos de nome remanescentes são erro de propriedade.
pub fn dispose() -> Result<(), KernelError> {
    critical_region::enter_critical()?;
    let result = (|| -> Result<(), KernelError> {
        let processes: Vec<u64> = with(|namespace| namespace.processes.keys().copied().collect())?;
        for process in processes {
            release_process(process)?;
        }
        let scopes: Vec<u64> = with(|namespace| namespace.scopes.iter().copied().collect())?;
        for scope in scopes {
            delete_scope(scope)?;
        }
        let silos: Vec<u64> = with(|namespace| namespace.silo_map_slots.keys().chain(namespace.silo_root_slots.keys()).copied().collect())?;
        for silo in silos {
            release_silo(silo)?;
        }
        let host = with(|namespace| namespace.host_storage)?;
        if host != 0 {
            let storage = host_at(host);
            for slot in &storage.root_keys {
                close_slot(slot.address())?;
            }
            let map = storage.scope_map.get();
            if map != 0 {
                let _ = kernel_pool::free(map, Some(STATE_TAG));
            }
            let _ = kernel_pool::free(host, Some(STATE_TAG));
            with(|namespace| namespace.host_storage = 0)?;
        }
        if with(|namespace| !namespace.descriptor_entries.is_empty() || !namespace.names.is_empty())? {
            return Err(KernelError::new("WNF namespace still owns name resources"));
        }
        process::unregister_process_exit_routine(exit_routine);
        silo_contexts::unregister_destroy_routine(destroy_routine);
        *NAMESPACE.lock() = None;
        Ok(())
    })();
    let left = critical_region::leave_critical();
    result?;
    left
}

pub fn release_scope(pointer: u64) -> Result<(), KernelError> {
    rundown::release(scope_at(pointer).run_ref.address())
}

pub fn release_name(state: &NameState) -> Result<(), KernelError> {
    rundown::release(name_at(state.pointer).run_ref.address())
}
