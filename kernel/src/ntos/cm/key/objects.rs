//! Identidades nativas opacas de chaves.
//!
//! Respaldadas pelos nós reais da hive. Handles e operações em andamento
//! mantêm contagens separadas; não se fabricam KCBs privados. A identidade
//! de um corpo é o seu ponteiro de 104 bytes; o campo KeyControlBlock do
//! CM_KEY_BODY guarda o bloco de identidade da chave (um por nó, opaco
//! para quem o lê), que o CmCallbackGetKeyObjectID devolve como ObjectID.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use crate::ntos::cm::registry::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{CmKeyBody, NtStruct};

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
    /// A identidade de cada chave (o papel do KCB): um bloco por nó, com o
    /// nome em cache do CmCallbackGetKeyObjectID.
    identities: BTreeMap<NodeId, u64>,
}

/// 'ky02', o Type de um CM_KEY_BODY vivo.
pub const KEY_BODY_TYPE: u32 = 0x6b79_3032;
/// O bloco de identidade de uma chave: o UNICODE_STRING do nome em cache.
pub const IDENTITY_SIZE: u64 = 0x10;

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
    // Type 'ky02', a identidade da chave no lugar do KeyControlBlock e o
    // ProcessID do processo criador; o resto do CM_KEY_BODY é zero (sem
    // transação: Trans nulo).
    let Some(identity) = identity(node) else {
        guest::free_bytes(pointer);
        return None;
    };
    // SAFETY: corpo próprio recém-alocado com sizeof(CM_KEY_BODY).
    let body = unsafe { CmKeyBody::at(pointer) };
    body.type_.set(KEY_BODY_TYPE);
    body.key_control_block.set(identity);
    body.process_id.set(process::get_current_process_id());
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
    // O bloco de notificação do corpo (CmpFlushNotify) sai com ele.
    crate::ntos::cm::key::notify::flush(pointer);
    // RegNtCallbackObjectContextCleanup: os contextos dos filtros neste
    // objeto saem antes dele.
    crate::ntos::cm::callbacks::object_destroyed(pointer);
    object_types::unbind_native(pointer);
    guest::free_bytes(pointer);
}

/// O bloco de identidade do nó (criado no primeiro corpo dele e mantido
/// enquanto o nó existe na arena).
pub fn identity(node: NodeId) -> Option<u64> {
    if let Some(identity) = with(|bodies| bodies.identities.get(&node).copied()) {
        return Some(identity);
    }
    let block = guest::alloc_bytes(IDENTITY_SIZE);
    if block == 0 {
        return None;
    }
    let chosen = with(|bodies| *bodies.identities.entry(node).or_insert(block));
    if chosen != block {
        guest::free_bytes(block);
    }
    Some(chosen)
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

/// Remove a associação de um handle. O fechamento do último handle do
/// corpo completa os pedidos de notificação dele (CmpCloseKeyObject →
/// CmpFlushNotify), mesmo com uma operação ainda retendo o corpo.
pub fn detach(handle: u32) {
    let detached = with(|bodies| {
        let pointer = bodies.by_handle.remove(&handle)?;
        let last = bodies.by_pointer.get_mut(&pointer).is_some_and(|body| {
            body.handles -= 1;
            body.handles == 0
        });
        Some((pointer, last, collect(bodies, pointer)))
    });
    match detached {
        Some((pointer, _, true)) => free_body(pointer),
        Some((pointer, true, false)) => crate::ntos::cm::key::notify::flush(pointer),
        _ => {}
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

/// O CM_KEY_BODY de um corpo vivo deste módulo.
fn key_body(pointer: u64) -> Option<&'static CmKeyBody> {
    // SAFETY: corpo próprio (sizeof(CM_KEY_BODY)) registrado em by_pointer.
    with(|bodies| bodies.by_pointer.contains_key(&pointer)).then(|| unsafe { CmKeyBody::at(pointer) })
}

/// CM_KEY_BODY.HandleTags (o KeyHandleTagsInformation do NtQueryKey).
pub fn handle_tags(pointer: u64) -> u32 {
    key_body(pointer).map_or(0, |body| body.handle_tags())
}

/// O KeySetHandleTagsInformation do NtSetInformationKey: a palavra baixa
/// das tags no HandleTags do corpo (`mov word ptr [body+0x32]`).
pub fn set_handle_tags(pointer: u64, tags: u32) {
    if let Some(body) = key_body(pointer) {
        body.set_handle_tags(tags & 0xFFFF);
    }
}

pub fn by_handle(handle: u32) -> Option<u64> {
    with(|bodies| bodies.by_handle.get(&handle).copied())
}
