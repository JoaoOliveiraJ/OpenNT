//! Identidades nativas opacas de chaves.
//!
//! Respaldadas pelos nós reais da hive. Handles e operações em andamento
//! mantêm contagens separadas; não se fabricam ponteiros para KCBs privados.
//! A identidade de um corpo é o seu ponteiro de 104 bytes.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const BODY_SIZE: u64 = 104;

#[derive(Clone, Debug)]
pub struct KeyBody {
    pub pointer: u64,
    pub node: NodeId,
    pub path: String,
    pub handles: u32,
    pub references: u32,
}

#[derive(Default)]
struct Bodies {
    by_handle: BTreeMap<u32, u64>,
    by_pointer: BTreeMap<u64, KeyBody>,
}

static BODIES: SpinLock<Option<Bodies>> = SpinLock::new(None);

fn with<T>(body: impl FnOnce(&mut Bodies) -> T) -> T {
    let mut bodies = BODIES.lock();
    body(bodies.get_or_insert_with(Bodies::default))
}

/// Aloca o corpo, associa o tipo Key e registra a identidade; a criação
/// ainda não é referência de handle nem de operação.
fn create_body(node: NodeId, path: &str) -> Option<u64> {
    let pointer = guest::alloc_bytes(BODY_SIZE);
    if pointer == 0 {
        return None;
    }
    // +24: identificador do processo criador; o resto permanece opaco.
    guest::write64(pointer + 24, process::get_current_process_id());
    let key_type = object_types::key_type();
    if object_types::bind_native(pointer, &key_type.name).is_err() {
        guest::free_bytes(pointer);
        return None;
    }
    with(|bodies| bodies.by_pointer.insert(pointer, KeyBody { pointer, node, path: path.to_string(), handles: 0, references: 0 }));
    Some(pointer)
}

/// Libera só quando handles e referências chegaram a zero.
fn collect(bodies: &mut Bodies, pointer: u64) -> bool {
    let unreferenced = bodies.by_pointer.get(&pointer).is_some_and(|body| body.handles == 0 && body.references == 0);
    if unreferenced {
        bodies.by_pointer.remove(&pointer);
    }
    unreferenced
}

fn free_body(pointer: u64) {
    object_types::unbind_native(pointer);
    guest::free_bytes(pointer);
}

/// Reutiliza a associação do handle ou materializa um corpo para o nó real;
/// a nova associação conta um handle exatamente uma vez.
pub fn for_handle(handle: u32) -> Option<u64> {
    if let Some(pointer) = with(|bodies| bodies.by_handle.get(&handle).copied()) {
        return Some(pointer);
    }
    let entry = registry::handle_entry(handle)?;
    let pointer = create_body(entry.node, &entry.path)?;
    with(|bodies| {
        if let Some(body) = bodies.by_pointer.get_mut(&pointer) {
            body.handles += 1;
        }
        bodies.by_handle.insert(handle, pointer);
    });
    Some(pointer)
}

/// Retém o corpo durante uma operação.
pub fn hold(pointer: u64) -> u64 {
    with(|bodies| {
        if let Some(body) = bodies.by_pointer.get_mut(&pointer) {
            body.references += 1;
        }
    });
    pointer
}

/// Devolve uma retenção; underflow é erro de propriedade.
pub fn release(pointer: u64) -> Result<(), KernelError> {
    let freed = with(|bodies| -> Result<bool, KernelError> {
        let body = bodies.by_pointer.get_mut(&pointer).ok_or_else(|| KernelError::new("key reference underflow"))?;
        if body.references == 0 {
            return Err(KernelError::new("key reference underflow"));
        }
        body.references -= 1;
        Ok(collect(bodies, pointer))
    })?;
    if freed {
        free_body(pointer);
    }
    Ok(())
}

/// Remove a associação de um handle.
pub fn detach(handle: u32) {
    let freed = with(|bodies| {
        let pointer = bodies.by_handle.remove(&handle)?;
        if let Some(body) = bodies.by_pointer.get_mut(&pointer) {
            body.handles -= 1;
        }
        collect(bodies, pointer).then_some(pointer)
    });
    if let Some(pointer) = freed {
        free_body(pointer);
    }
}

/// Associa um handle novo a um corpo existente.
pub fn attach(handle: u32, pointer: u64) -> Result<(), KernelError> {
    with(|bodies| {
        if bodies.by_handle.contains_key(&handle) {
            return Err(KernelError::new("key handle already bound"));
        }
        let body = bodies.by_pointer.get_mut(&pointer).ok_or_else(|| KernelError::new("unknown key body"))?;
        body.handles += 1;
        bodies.by_handle.insert(handle, pointer);
        Ok(())
    })
}

/// Corpo sem handle com uma retenção de operação, a liberar pelo chamador.
pub fn temporary(node: NodeId, path: &str) -> Option<u64> {
    create_body(node, path).map(hold)
}

pub fn get(pointer: u64) -> Option<KeyBody> {
    with(|bodies| bodies.by_pointer.get(&pointer).cloned())
}

pub fn by_handle(handle: u32) -> Option<u64> {
    with(|bodies| bodies.by_handle.get(&handle).copied())
}
