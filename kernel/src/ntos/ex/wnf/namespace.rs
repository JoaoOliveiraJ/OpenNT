//! Namespace WNF — `system32/ntos/ex/wnf-namespace.js`.
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
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::ejob;

const STATE_TAG: u32 = 0x2066_6E57;
const DESCRIPTOR_TAG: u32 = 0x6353_624F;
const FRAME_TAG: u32 = 0x6E66_6E57;
/// EPROCESS.WnfContext (19041).
const PROCESS_CONTEXT_OFFSET: u64 = 0x868;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
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

fn initialize_list(head: u64) {
    guest::write64(head, head);
    guest::write64(head + 8, head);
}

fn insert_last(head: u64, entry: u64) -> Result<(), KernelError> {
    let previous = guest::read64(head + 8);
    if guest::read64(previous) != head {
        return Err(KernelError::new("corrupt WNF list tail"));
    }
    guest::write64(entry, head);
    guest::write64(entry + 8, previous);
    guest::write64(previous, entry);
    guest::write64(head + 8, entry);
    Ok(())
}

fn unlink(entry: u64) -> Result<(), KernelError> {
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("corrupt WNF list links"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    guest::write64(entry, 0);
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

fn find_name(scope_instance: u64, decoded_name: u64) -> u64 {
    let mut node = guest::read64(scope_instance + 0x38);
    while node != 0 {
        let candidate = guest::read64(node + 0x18);
        if candidate == decoded_name {
            return node - 0x10;
        }
        node = guest::read64(node + if decoded_name < candidate { 0 } else { 8 });
    }
    0
}

fn find_scope(head: u64, identity: u64, length: u32) -> u64 {
    let mut entry = guest::read64(head);
    while entry != head {
        let instance = entry - 0x20;
        if guest::read32(instance + 0x14) == length {
            let stored = guest::read64(instance + 0x18);
            if (0..length as u64).all(|offset| guest::read8(stored + offset) == guest::read8(identity + offset)) {
                return instance;
            }
        }
        entry = guest::read64(entry);
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
    let Ok(candidate) = pool_allocation::allocate_tagged(1, 64, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, 64);
    initialize_list(candidate + 32);
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
    let globals = guest::read64(silo + ejob::SERVER_SILO_GLOBALS);
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
        return Ok(host + 8 + lifetime as u64 * 8);
    }
    let slot = silo_globals(silo)? + if lifetime == 1 { 0x398 } else { 0x3A0 };
    with(|namespace| namespace.silo_root_slots.entry(silo).or_default().insert(slot))?;
    Ok(slot)
}

fn ensure_scope_map(silo: u64) -> Result<u64, KernelError> {
    let host = ensure_host_storage()?;
    if host == 0 {
        return Ok(0);
    }
    let mut slot = host;
    if silo != 0 {
        slot = silo_globals(silo)? + 0x390;
        with(|namespace| namespace.silo_map_slots.insert(silo, slot))?;
    }
    let pointer = guest::read64(slot);
    if pointer != 0 {
        return Ok(pointer);
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, 0xB0, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, 0xB0);
    guest::write32(candidate, 0x00B0_0901);
    for scope in 0..6u64 {
        initialize_list(candidate + 0x28 + scope * 0x18);
    }
    let previous = guest::compare_exchange64(slot, 0, candidate)?;
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
    let field = process + PROCESS_CONTEXT_OFFSET;
    let existing = guest::read64(field);
    if existing != 0 {
        if with(|namespace| namespace.processes.get(&process).copied())? != Some(existing) {
            return Err(KernelError::new("WNF process context has a different owner"));
        }
        return Ok(existing);
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, 0x88, STATE_TAG) else { return Ok(0) };
    clear_bytes(candidate, 0x88);
    guest::write32(candidate, 0x0088_0906);
    guest::write64(candidate + 8, process);
    for offset in [0x40u64, 0x58, 0x70] {
        initialize_list(candidate + offset);
    }
    let winner = with_lock(host + 48, true, || {
        let previous = guest::compare_exchange64(field, 0, candidate)?;
        if previous != 0 {
            return Ok(previous);
        }
        insert_last(host + 32, candidate + 0x10)?;
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
    let cache_slot = match scope {
        0 => map + 8,
        4 | 5 => map + (scope as u64 - 2) * 8,
        _ => context + (scope as u64 + 3) * 8,
    };
    let explicit = explicit_identity != 0;
    let mut can_cache = (!explicit && thread == 0) || scope == 0 || scope >= 4;
    let cached = if can_cache { guest::read64(cache_slot) } else { 0 };
    if cached != 0 {
        return Ok(if rundown::acquire(cached + 8)? { Ok(cached) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
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
                2 => 8 + guest::read8(identity + 1) as u32 * 4,
                _ => 0,
            };
        } else {
            frame = kernel_pool::allocate(16, AllocateOptions { zero: true, tag: FRAME_TAG, ..Default::default() }).unwrap_or(0);
            if frame == 0 {
                return Ok(Err(0xC000_0017));
            }
            guest::write32(frame + 8, 8);
            guest::write32(frame + 12, can_cache as u32);
            identity = frame;
            let mut status = wnf_scope_identity::query_current(process, thread, scope, identity, frame + 8, frame + 12)?;
            if status == 0xC000_0023 {
                identity_allocation = pool_allocation::allocate_tagged(1, guest::read32(frame + 8) as u64, STATE_TAG).unwrap_or(0);
                if identity_allocation == 0 {
                    return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
                }
                identity = identity_allocation;
                status = wnf_scope_identity::query_current(process, thread, scope, identity, frame + 8, frame + 12)?;
            }
            if status & 0x8000_0000 != 0 {
                return Ok(Err(status));
            }
            length = guest::read32(frame + 8);
            can_cache = guest::read32(frame + 12) != 0;
        }
        let lock = map + 0x20 + scope as u64 * 0x18;
        let head = lock + 8;
        let found = with_lock(lock, false, || {
            let pointer = find_scope(head, identity, length);
            Ok(if pointer != 0 { Some((pointer, rundown::acquire(pointer + 8)?)) } else { None })
        })?;
        if let Some((pointer, acquired)) = found {
            return Ok(if acquired { Ok(pointer) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
        }
        candidate = pool_allocation::allocate_tagged(1, length.wrapping_add(0x50) as u64, STATE_TAG).unwrap_or(0);
        if candidate == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        clear_bytes(candidate, 0x50);
        guest::write32(candidate, 0x0050_0902);
        guest::write32(candidate + 0x10, scope);
        guest::write32(candidate + 0x14, length);
        if length != 0 {
            guest::write64(candidate + 0x18, candidate + 0x50);
            copy_bytes(candidate + 0x50, identity, length as u64);
        }
        with_lock(lock, true, || {
            let winner = find_scope(head, identity, length);
            if winner != 0 {
                return Ok(if rundown::acquire(winner + 8)? { Ok(winner) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
            }
            let published = candidate;
            if !rundown::acquire(published + 8)? {
                return Err(KernelError::new("new WNF scope already in rundown"));
            }
            insert_last(head, published + 0x20)?;
            with(|namespace| {
                namespace.scopes.insert(published);
                namespace.scope_maps.insert(published, map);
            })?;
            candidate = 0;
            if can_cache {
                guest::compare_exchange64(cache_slot, 0, published)?;
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
    let mut offset = 0u64;
    while offset < (length & !7) {
        hash ^= guest::read64(source + offset);
        hash = hash.rotate_left(3);
        offset += 16;
    }
    let mut allocation = with(|namespace| namespace.descriptor_entries.get(&key).copied())?.unwrap_or(0);
    if allocation == 0 {
        let Ok(created) = pool_allocation::allocate_tagged(5, length + 0x28, DESCRIPTOR_TAG) else { return Ok(0) };
        clear_bytes(created, 0x28);
        copy_bytes(created + 0x20, source, length);
        guest::write64(created + 0x10, hash);
        guest::write32(created + 0x18, length as u32);
        allocation = with(|namespace| match namespace.descriptor_entries.get(&key) {
            Some(&existing) => existing,
            None => {
                namespace.descriptor_entries.insert(key.clone(), created);
                namespace.descriptors_by_pointer.insert(created + 0x20, DescriptorEntry { allocation: created, key: key.clone() });
                created
            }
        })?;
        if allocation != created {
            let _ = kernel_pool::free(created, Some(DESCRIPTOR_TAG));
        }
    }
    guest::write64(allocation + 8, guest::read64(allocation + 8) + 1);
    Ok(allocation + 0x20)
}

fn release_descriptor(pointer: u64) -> Result<(), KernelError> {
    let allocation = with(|namespace| namespace.descriptors_by_pointer.get(&pointer).map(|entry| entry.allocation))?.ok_or_else(|| KernelError::new("WNF descriptor has no owner"))?;
    let count = guest::read64(allocation + 8);
    if count == 0 {
        return Err(KernelError::new("WNF descriptor reference underflow"));
    }
    guest::write64(allocation + 8, count - 1);
    if count != 1 {
        return Ok(());
    }
    with(|namespace| {
        if let Some(entry) = namespace.descriptors_by_pointer.remove(&pointer) {
            namespace.descriptor_entries.remove(&entry.key);
        }
    })?;
    let _ = kernel_pool::free(allocation, Some(DESCRIPTOR_TAG));
    Ok(())
}

/// Procura o nome na árvore do escopo e adquire seu rundown.
pub fn lookup_name(scope_instance: u64, decoded_name: u64) -> Outcome<NameState> {
    with_lock(scope_instance + 0x30, false, || {
        let pointer = find_name(scope_instance, decoded_name);
        Ok(if pointer != 0 && rundown::acquire(pointer + 8)? { Ok(describe_name(pointer)) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) })
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
    let size = if definition.type_identifier != 0 { 0xB8 } else { 0xA8 };
    let mut candidate = if lifetime == 3 && creator_process != process::get_system_process() {
        process_context::with_process(creator_process, || pool_quota::allocate(9, size, STATE_TAG))?.unwrap_or(0)
    } else {
        pool_allocation::allocate_tagged(1, size, STATE_TAG).unwrap_or(0)
    };
    if candidate == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    clear_bytes(candidate, 0xA8);
    let result = (|| -> Outcome<NameState> {
        guest::write32(candidate, 0x00A8_0903);
        guest::write64(candidate + 0x28, decoded_name);
        guest::write64(candidate + 0x30, scope_instance);
        guest::write32(candidate + 0x38, definition.maximum_size);
        if definition.type_identifier != 0 {
            guest::write64(candidate + 0x40, candidate + 0xA8);
            copy_bytes(candidate + 0xA8, definition.type_identifier, 16);
        }
        let security = retain_descriptor(definition.security_descriptor)?;
        if security == 0 {
            return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
        }
        guest::write64(candidate + 0x48, security);
        initialize_list(candidate + 0x78);
        if decoded_name & 1024 != 0 {
            let slot = root_slot(1)?;
            if slot == 0 {
                return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
            }
            match wnf_registry::get_permanent_store(scope_instance, lifetime, 1, slot)? {
                Ok(store) => guest::write64(candidate + 0x68, store.handle),
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
        with_lock(scope_instance + 0x30, true, || {
            let winner = find_name(scope_instance, decoded_name);
            if winner != 0 {
                return Ok(if rundown::acquire(winner + 8)? { Ok(describe_name(winner)) } else { Err(STATUS_OBJECT_NAME_NOT_FOUND) });
            }
            let mut parent = guest::read64(scope_instance + 0x38);
            let mut right = false;
            while parent != 0 {
                right = decoded_name >= guest::read64(parent + 0x18);
                let next = guest::read64(parent + if right { 8 } else { 0 });
                if next == 0 {
                    break;
                }
                parent = next;
            }
            let published = candidate;
            if !rundown::acquire(published + 8)? {
                return Err(KernelError::new("new WNF name already in rundown"));
            }
            avl::insert(scope_instance + 0x38, parent, right as u64, published + 0x10)?;
            if lifetime == 3 {
                guest::write64(published + 0x98, creator_process);
                with_lock(temporary_context + 0x38, true, || insert_last(temporary_context + 0x40, published + 0x88))?;
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
    let scope_instance = guest::read64(pointer + 0x30);
    with_lock(scope_instance + 0x30, true, || {
        with_lock(pointer + 0x70, true, || {
            avl::remove(scope_instance + 0x38, pointer + 0x10)?;
            guest::write64(pointer + 0x30, 0);
            Ok(())
        })
    })?;
    let lifecycle = with(|namespace| namespace.lifecycle)?;
    (lifecycle.delete_name_subscriptions)(pointer);
    let creator = guest::read64(pointer + 0x98);
    if creator != 0 {
        let context = with(|namespace| namespace.processes.get(&creator).copied())?.ok_or_else(|| KernelError::new("temporary WNF name lost its creator"))?;
        with_lock(context + 0x38, true, || unlink(pointer + 0x88))?;
        guest::write64(pointer + 0x98, 0);
    }
    rundown::wait(pointer + 8)?;
    with(|namespace| namespace.names.remove(&pointer))?;
    free_unpublished_name(pointer)
}

fn close_slot(slot: u64) -> Result<(), KernelError> {
    let handle = guest::read64(slot);
    if handle == 0 {
        return Ok(());
    }
    let status = previous_mode::with_kernel(|| close::close(handle, Some(0)))??;
    if status != 0 {
        return Err(KernelError::new("WNF owner could not close registry handle"));
    }
    guest::write64(slot, 0);
    Ok(())
}

fn delete_scope(pointer: u64) -> Result<(), KernelError> {
    let map = with(|namespace| namespace.scopes.contains(&pointer).then(|| namespace.scope_maps.get(&pointer).copied()).flatten())?.ok_or_else(|| KernelError::new("WNF scope has no namespace owner"))?;
    let scope = guest::read32(pointer + 0x10) as u64;
    with_lock(map + 0x20 + scope * 0x18, true, || unlink(pointer + 0x20))?;
    for slot in [map + 8, map + 0x10, map + 0x18] {
        guest::compare_exchange64(slot, pointer, 0)?;
    }
    let contexts: Vec<u64> = with(|namespace| namespace.processes.values().copied().collect())?;
    for context in contexts {
        for offset in [0x20u64, 0x28, 0x30] {
            guest::compare_exchange64(context + offset, pointer, 0)?;
        }
    }
    rundown::wait(pointer + 8)?;
    loop {
        let node = guest::read64(pointer + 0x38);
        if node == 0 {
            break;
        }
        delete_name(node - 0x10)?;
    }
    close_slot(pointer + 0x40)?;
    close_slot(pointer + 0x48)?;
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
            loop {
                let entry = guest::read64(context + 0x40);
                if entry == context + 0x40 {
                    break;
                }
                delete_name(entry - 0x88)?;
            }
        }
        let scopes: Vec<u64> = with(|namespace| namespace.scopes.iter().copied().collect())?;
        for scope in scopes {
            if guest::read32(scope + 0x10) == 3 && guest::read64(scope + 0x50) == process {
                delete_scope(scope)?;
            }
        }
        let Some(context) = context else { return Ok(()) };
        with_lock(host + 48, true, || {
            if guest::compare_exchange64(process + PROCESS_CONTEXT_OFFSET, context, 0)? != context {
                return Err(KernelError::new("WNF process context changed owner"));
            }
            unlink(context + 0x10)?;
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
        let map = guest::read64(map_slot);
        let owned: Vec<u64> = with(|namespace| namespace.scope_maps.iter().filter(|&(_, &owner)| owner == map).map(|(&scope, _)| scope).collect())?;
        for scope in owned {
            delete_scope(scope)?;
        }
        if map != 0 {
            let _ = kernel_pool::free(map, Some(STATE_TAG));
        }
        guest::write64(map_slot, 0);
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
            for offset in [8u64, 16, 24] {
                close_slot(host + offset)?;
            }
            let map = guest::read64(host);
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
    rundown::release(pointer + 8)
}

pub fn release_name(state: &NameState) -> Result<(), KernelError> {
    rundown::release(state.pointer + 8)
}
