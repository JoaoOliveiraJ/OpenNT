//! Corpos nativos de diretório e link simbólico.
//!
//! O nó do namespace é o dono compartilhado por aberturas por nome e por
//! ponteiro. O corpo privado (64 bytes) guarda referências (+0), handles
//! (+8), permanência (+12), o UNICODE_STRING do destino do link (+0x10) e o
//! número de filhos (+0x20). As contagens vivem só na memória do corpo e
//! mudam por operações atômicas, como o PointerCount/HandleCount do NT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::object_security;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

pub const SIZE: u64 = 0x40;

struct Body {
    node: NodeId,
    directory: bool,
    target_buffer: u64,
    attached: bool,
    security: SecurityPolicy,
}

static BODIES: SpinLock<BTreeMap<u64, Body>> = SpinLock::new(BTreeMap::new());

fn status(code: u32) -> KernelError {
    KernelError::with_status(alloc::format!("namespace object status {code:x}"), code)
}

/// Materializa o corpo uma única vez; o nó ligado à árvore mantém uma
/// referência própria, independente dos handles abertos.
pub fn ensure(node: NodeId) -> Result<Option<u64>, KernelError> {
    let Some(snapshot) = object_manager::node(node) else { return Ok(None) };
    if snapshot.native_namespace != 0 {
        return Ok(Some(snapshot.native_namespace));
    }
    let directory = snapshot.type_name == "Directory";
    if !directory && snapshot.type_name != "SymbolicLink" {
        return Ok(None);
    }
    let type_name = if directory { object_types::directory_type().name } else { object_types::symbolic_link_type().name };
    let text: String = if directory { String::new() } else { snapshot.data.as_ref().and_then(|data| data.symlink_target.clone()).unwrap_or_default() };
    let units: alloc::vec::Vec<u16> = text.encode_utf16().collect();
    let target_length = units.len() * 2;
    if target_length > 0xFFFC {
        return Err(status(0xC000_0106));
    }
    let pointer = guest::alloc_bytes(SIZE);
    if pointer == 0 {
        return Err(status(0xC000_009A));
    }
    let mut target_buffer = 0;
    if !directory {
        target_buffer = guest::alloc_bytes(target_length as u64 + 2);
        if target_buffer == 0 {
            guest::free_bytes(pointer);
            return Err(status(0xC000_009A));
        }
        for (index, &unit) in units.iter().enumerate() {
            guest::write16(target_buffer + index as u64 * 2, unit);
        }
        guest::write16(target_buffer + target_length as u64, 0);
        guest::write16(pointer + 0x10, target_length as u16);
        guest::write16(pointer + 0x12, target_length as u16 + 2);
        guest::write64(pointer + 0x18, target_buffer);
    }
    // Um nó ainda ligado à árvore recebe a referência inicial de namespace.
    let attached = snapshot.parent.is_none() || object_manager::is_attached(node);
    guest::write64(pointer, attached as u64);
    guest::write32(pointer + 12, if snapshot.permanent == Some(false) { 0 } else { 1 });
    guest::write64(pointer + 0x20, snapshot.children.as_ref().map_or(0, |children| children.len() as u64));
    let security = object_security::namespace(node, directory);
    BODIES.lock().insert(pointer, Body { node, directory, target_buffer, attached, security });
    object_manager::set_native_namespace(node, pointer);
    if let Err(error) = object_types::bind_native(pointer, &type_name) {
        BODIES.lock().remove(&pointer);
        object_manager::set_native_namespace(node, 0);
        if target_buffer != 0 {
            guest::free_bytes(target_buffer);
        }
        guest::free_bytes(pointer);
        return Err(error);
    }
    update_counts(node);
    Ok(Some(pointer))
}

fn assert_live(pointer: u64) -> Result<NodeId, KernelError> {
    BODIES.lock().get(&pointer).map(|body| body.node).ok_or_else(|| KernelError::new("namespace body has been released"))
}

fn update_counts(node: NodeId) {
    object_manager::track_namespace(node, true);
    sync_types();
}

/// Libera só corpos sem referências e sem filhos; desliga os vínculos antes
/// de liberar o texto e a alocação.
fn collect(pointer: u64) {
    let Some(node) = BODIES.lock().get(&pointer).map(|body| body.node) else { return };
    if refs(pointer) != 0 || object_manager::child_count(node) != 0 {
        return;
    }
    let Some(body) = BODIES.lock().remove(&pointer) else { return };
    object_manager::set_native_namespace(body.node, 0);
    object_types::unbind_native(pointer);
    object_manager::track_namespace(body.node, false);
    sync_types();
    if body.target_buffer != 0 {
        guest::free_bytes(body.target_buffer);
    }
    guest::free_bytes(pointer);
}

pub fn refs(pointer: u64) -> u64 {
    guest::read64(pointer)
}

pub fn handles(pointer: u64) -> u32 {
    if BODIES.lock().contains_key(&pointer) { guest::read32(pointer + 8) } else { 0 }
}

pub fn permanent(pointer: u64) -> bool {
    guest::read32(pointer + 12) != 0
}

pub fn set_permanent(pointer: u64, permanent: bool) {
    guest::write32(pointer + 12, permanent as u32);
}

fn reference_cell(pointer: u64) -> &'static AtomicU64 {
    guest::atomic_u64(pointer)
}

fn handle_cell(pointer: u64) -> &'static AtomicU32 {
    guest::atomic_u32(pointer + 8)
}

pub fn reference(pointer: u64) -> Result<u64, KernelError> {
    assert_live(pointer)?;
    Ok(reference_cell(pointer).fetch_add(1, Ordering::SeqCst) + 1)
}

pub fn dereference(pointer: u64) -> Result<u64, KernelError> {
    assert_live(pointer)?;
    let current = reference_cell(pointer)
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| current.checked_sub(1))
        .map_err(|_| KernelError::new("namespace reference underflow"))?;
    collect(pointer);
    Ok(current - 1)
}

/// Retém o corpo e contabiliza mais um handle.
pub fn open(pointer: u64) -> Result<(), KernelError> {
    let node = assert_live(pointer)?;
    reference(pointer)?;
    handle_cell(pointer).fetch_add(1, Ordering::SeqCst);
    update_counts(node);
    Ok(())
}

/// Fecha um handle; um objeto temporário perde o nome no último fechamento,
/// preservando referências por ponteiro.
pub fn close(pointer: u64) -> Result<(), KernelError> {
    let node = assert_live(pointer)?;
    let open_handles = handle_cell(pointer)
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |handles| handles.checked_sub(1))
        .map_err(|_| KernelError::new("namespace handle underflow"))?;
    let attached = BODIES.lock().get(&pointer).is_some_and(|body| body.attached);
    if open_handles == 1 && !permanent(pointer) && attached {
        object_manager::remove_named(node);
    }
    if BODIES.lock().contains_key(&pointer) {
        update_counts(node);
        dereference(pointer)?;
    }
    Ok(())
}

/// Solta uma única vez a referência que a ligação à árvore mantinha.
pub fn detach(pointer: u64) -> Result<(), KernelError> {
    let was_attached = {
        let mut bodies = BODIES.lock();
        let Some(body) = bodies.get_mut(&pointer) else { return Ok(()) };
        core::mem::replace(&mut body.attached, false)
    };
    if was_attached {
        dereference(pointer)?;
    }
    Ok(())
}

/// Atualiza o número de filhos e reavalia a coleta.
pub fn changed(pointer: u64) -> Result<(), KernelError> {
    let node = assert_live(pointer)?;
    guest::write64(pointer + 0x20, object_manager::child_count(node));
    collect(pointer);
    Ok(())
}

/// Destino atual do UNICODE_STRING do corpo do link.
pub fn target(pointer: u64) -> Result<String, KernelError> {
    assert_live(pointer)?;
    Ok(guest_strings::read_unicode_string(pointer + 0x10))
}

/// Nó dono e tipo de um corpo vivo.
pub fn get(pointer: u64) -> Option<(NodeId, bool)> {
    BODIES.lock().get(&pointer).map(|body| (body.node, body.directory))
}

pub fn security(pointer: u64) -> Option<SecurityPolicy> {
    BODIES.lock().get(&pointer).map(|body| body.security.clone())
}

/// Publica em OBJECT_TYPE a diferença entre os totais do namespace e a
/// contagem já registrada.
pub fn sync_types() {
    for name in ["Directory", "SymbolicLink"] {
        let Some((objects, handles, _, _)) = object_types::counts(name) else { continue };
        let statistics = object_manager::type_stats(name);
        let _ = object_types::account(name, statistics.objects as i64 - objects as i64, statistics.handles as i64 - handles as i64);
    }
}

/// Substitui a política do corpo (descritor capturado na criação).
pub fn set_security(pointer: u64, policy: SecurityPolicy) {
    if let Some(body) = BODIES.lock().get_mut(&pointer) {
        body.security = policy;
    }
}
