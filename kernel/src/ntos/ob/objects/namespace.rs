//! Corpos nativos de diretório e link simbólico.
//!
//! O nó do namespace é o dono compartilhado por aberturas por nome e por
//! ponteiro. O corpo privado (0x50 bytes) guarda referências (+0), handles
//! (+8), permanência (+12), o UNICODE_STRING do destino do link (+0x10), o
//! número de filhos (+0x20) e, num diretório, os campos do OBJECT_DIRECTORY
//! que o OpenNT usa: SessionId (+0x28), Flags (+0x2C), SessionObject
//! (+0x30), ShadowDirectory (+0x38, o corpo do diretório sombra, retido),
//! NamespaceEntry (+0x40, o OBJECT_NAMESPACE_ENTRY de um namespace
//! privado) e DeviceMap (+0x48, o DEVICE_MAP de um diretório de devices
//! DOS, `ob/device_map.rs`). As contagens vivem só na memória do corpo e
//! mudam por operações atômicas, como o PointerCount/HandleCount do NT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::UnicodeString;

use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::object_security;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

/// Corpo privado de diretório/link (layout do OpenNT; o NT usa
/// OBJECT_DIRECTORY e OBJECT_SYMBOLIC_LINK).
#[repr(C)]
struct NamespaceBody {
    references: Field<u64>,
    handles: Field<u32>,
    permanent: Field<u32>,
    link_target: UnicodeString,
    children: Field<u64>,
    /// OBJECT_DIRECTORY.SessionId: -1 (sem sessão) na criação, como o
    /// ObpCreateDirectoryObject; o NtSetInformationObject
    /// (ObjectSessionInformation) grava a sessão de quem chama.
    session_id: Field<u32>,
    /// OBJECT_DIRECTORY.Flags (os DIRECTORY_* abaixo).
    flags: Field<u32>,
    /// OBJECT_DIRECTORY.SessionObject: o objeto Session ligado pelo
    /// NtSetInformationObject (ObjectSessionObjectInformation), retido.
    session_object: Field<u64>,
    /// OBJECT_DIRECTORY.ShadowDirectory: o corpo do diretório sombra do
    /// NtCreateDirectoryObjectEx, com a referência que o diretório guarda.
    shadow_directory: Field<u64>,
    /// OBJECT_DIRECTORY.NamespaceEntry: o OBJECT_NAMESPACE_ENTRY de um
    /// namespace privado registrado (0 fora da tabela).
    namespace_entry: Field<u64>,
    /// OBJECT_DIRECTORY.DeviceMap: o DEVICE_MAP cujo DosDevicesDirectory é
    /// este diretório (sem referência própria: o mapa retém o diretório e
    /// zera o campo ao sair), sob o DeviceMapLock.
    device_map: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for NamespaceBody {}

const _: () = {
    assert!(core::mem::size_of::<NamespaceBody>() == 0x50);
    assert!(core::mem::offset_of!(NamespaceBody, link_target) == 0x10);
    assert!(core::mem::offset_of!(NamespaceBody, children) == 0x20);
    assert!(core::mem::offset_of!(NamespaceBody, session_id) == 0x28);
    assert!(core::mem::offset_of!(NamespaceBody, flags) == 0x2C);
    assert!(core::mem::offset_of!(NamespaceBody, session_object) == 0x30);
    assert!(core::mem::offset_of!(NamespaceBody, shadow_directory) == 0x38);
    assert!(core::mem::offset_of!(NamespaceBody, namespace_entry) == 0x40);
    assert!(core::mem::offset_of!(NamespaceBody, device_map) == 0x48);
};

/// SessionId de diretório sem sessão.
pub const NO_SESSION: u32 = u32::MAX;

/// OBJECT_DIRECTORY.Flags (ntoskrnl 19041): diretório de um namespace
/// privado (NtCreatePrivateNamespace).
pub const DIRECTORY_PRIVATE_NAMESPACE: u32 = 0x1;
/// O namespace privado saiu da tabela (ObpRemoveNamespaceFromTable).
pub const DIRECTORY_NAMESPACE_REMOVED: u32 = 0x2;
/// ShadowDirectory válido (NtCreateDirectoryObjectEx com sombra).
pub const DIRECTORY_SHADOW: u32 = 0x4;
/// O bit 0 dos Flags do NtCreateDirectoryObjectEx: os objetos criados no
/// diretório recebem o descritor com SEF_DACL_AUTO_INHERIT |
/// SEF_SACL_AUTO_INHERIT (ObpInsertOrLocateNamedObject).
pub const DIRECTORY_AUTO_INHERIT: u32 = 0x8;
/// Criado por um token sandbox: a sombra só vale para quem também é
/// (ObpGetShadowDirectory).
pub const DIRECTORY_SANDBOXED_SHADOW: u32 = 0x10;
/// O bit 1 dos Flags (só de modo kernel): o ObQueryNameString para de
/// subir neste diretório.
pub const DIRECTORY_NAME_ROOT: u32 = 0x20;

pub const SIZE: u64 = NamespaceBody::SIZE;

fn body(pointer: u64) -> &'static NamespaceBody {
    // SAFETY: corpos alocados por `ensure`, liberados só por `collect`.
    unsafe { NamespaceBody::at(pointer) }
}

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
        let mut text: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        text.extend_from_slice(&[0, 0]);
        guest::write_bytes(target_buffer, &text);
        let target = &body(pointer).link_target;
        target.length.set(target_length as u16);
        target.maximum_length.set(target_length as u16 + 2);
        target.buffer.set(target_buffer);
    }
    // Um nó ainda ligado à árvore recebe a referência inicial de namespace.
    let attached = snapshot.parent.is_none() || object_manager::is_attached(node);
    let fresh = body(pointer);
    fresh.references.set(attached as u64);
    fresh.permanent.set(if snapshot.permanent == Some(false) { 0 } else { 1 });
    fresh.children.set(snapshot.children.as_ref().map_or(0, |children| children.len() as u64));
    fresh.session_id.set(NO_SESSION);
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
    let session_object = self::body(pointer).session_object.atomic().swap(0, Ordering::SeqCst);
    if session_object != 0 {
        crate::ntos::ob::object_header::dereference(session_object, true);
    }
    // ObpDeleteDirectoryObject: a referência do diretório sombra sai junto.
    let shadow = self::body(pointer).shadow_directory.atomic().swap(0, Ordering::SeqCst);
    // O OBJECT_NAMESPACE_ENTRY de um namespace privado vive com o diretório.
    if self::body(pointer).flags.get() & DIRECTORY_PRIVATE_NAMESPACE != 0 {
        crate::ntos::ob::private_namespace::release_directory(pointer);
    }
    object_manager::set_native_namespace(body.node, 0);
    object_types::unbind_native(pointer);
    object_manager::track_namespace(body.node, false);
    sync_types();
    if body.target_buffer != 0 {
        guest::free_bytes(body.target_buffer);
    }
    guest::free_bytes(pointer);
    if shadow != 0 {
        let _ = dereference(shadow);
    }
}

pub fn refs(pointer: u64) -> u64 {
    body(pointer).references.get()
}

pub fn handles(pointer: u64) -> u32 {
    if BODIES.lock().contains_key(&pointer) { body(pointer).handles.get() } else { 0 }
}

pub fn permanent(pointer: u64) -> bool {
    body(pointer).permanent.get() != 0
}

pub fn set_permanent(pointer: u64, permanent: bool) {
    body(pointer).permanent.set(permanent as u32);
}

/// OBJECT_DIRECTORY.SessionId de um diretório vivo.
pub fn session_id(pointer: u64) -> Result<u32, KernelError> {
    assert_live(pointer)?;
    Ok(body(pointer).session_id.get())
}

/// Grava o SessionId de um diretório vivo (o NT o faz com o diretório
/// travado em exclusivo; aqui é um store único da célula).
pub fn set_session_id(pointer: u64, session_id: u32) -> Result<(), KernelError> {
    assert_live(pointer)?;
    body(pointer).session_id.set(session_id);
    Ok(())
}

/// OBJECT_DIRECTORY.Flags de um diretório vivo (0 para outro corpo).
pub fn directory_flags(pointer: u64) -> u32 {
    if BODIES.lock().get(&pointer).is_some_and(|body| body.directory) { body(pointer).flags.get() } else { 0 }
}

/// Liga bits em OBJECT_DIRECTORY.Flags (o `lock or` do NT); devolve o valor
/// anterior.
pub fn set_directory_flags(pointer: u64, bits: u32) -> Result<u32, KernelError> {
    assert_live(pointer)?;
    Ok(body(pointer).flags.atomic().fetch_or(bits, Ordering::SeqCst))
}

/// OBJECT_DIRECTORY.ShadowDirectory (o corpo do diretório sombra, 0 sem).
pub fn shadow_directory(pointer: u64) -> u64 {
    if BODIES.lock().get(&pointer).is_some_and(|body| body.directory) { body(pointer).shadow_directory.get() } else { 0 }
}

/// Grava o ShadowDirectory de um diretório novo; a referência do `shadow`
/// passa a ser do diretório (solta no ObpDeleteDirectoryObject).
pub fn set_shadow_directory(pointer: u64, shadow: u64) -> Result<(), KernelError> {
    assert_live(pointer)?;
    body(pointer).shadow_directory.set(shadow);
    Ok(())
}

/// OBJECT_DIRECTORY.NamespaceEntry (0 fora da tabela de namespaces).
pub fn namespace_entry(pointer: u64) -> u64 {
    if BODIES.lock().get(&pointer).is_some_and(|body| body.directory) { body(pointer).namespace_entry.get() } else { 0 }
}

/// Grava o NamespaceEntry (o chamador serializa pela trava da tabela).
pub fn set_namespace_entry(pointer: u64, entry: u64) -> Result<(), KernelError> {
    assert_live(pointer)?;
    body(pointer).namespace_entry.set(entry);
    Ok(())
}

/// OBJECT_DIRECTORY.DeviceMap (0 sem mapa, ou para outro corpo).
pub fn device_map(pointer: u64) -> u64 {
    if BODIES.lock().get(&pointer).is_some_and(|body| body.directory) { body(pointer).device_map.get() } else { 0 }
}

/// Grava o DeviceMap de um diretório vivo (o chamador segura o
/// DeviceMapLock, como o ObpSetDeviceMap e o ObfDereferenceDeviceMap).
pub fn set_device_map(pointer: u64, map: u64) -> Result<(), KernelError> {
    assert_live(pointer)?;
    body(pointer).device_map.set(map);
    Ok(())
}

fn reference_cell(pointer: u64) -> &'static AtomicU64 {
    body(pointer).references.atomic()
}

fn handle_cell(pointer: u64) -> &'static AtomicU32 {
    body(pointer).handles.atomic()
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
    // ObpCloseDirectoryObject: o último handle de um namespace privado o
    // tira da tabela.
    if open_handles == 1 && directory_flags(pointer) & DIRECTORY_PRIVATE_NAMESPACE != 0 {
        let _ = crate::ntos::ob::private_namespace::remove_from_table(pointer);
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
    body(pointer).children.set(object_manager::child_count(node));
    collect(pointer);
    Ok(())
}

/// Destino atual do UNICODE_STRING do corpo do link.
pub fn target(pointer: u64) -> Result<String, KernelError> {
    assert_live(pointer)?;
    Ok(guest_strings::read_unicode_string(body(pointer).link_target.address()))
}

/// Nó dono e tipo de um corpo vivo.
pub fn get(pointer: u64) -> Option<(NodeId, bool)> {
    BODIES.lock().get(&pointer).map(|body| (body.node, body.directory))
}

/// O ObjectSessionObjectInformation num diretório: o SessionObject recebe
/// `object` (com a referência de quem chama) se ainda está vazio; `false`
/// quando já há um (o NT devolve STATUS_ACCESS_DENIED).
pub fn attach_session_object(pointer: u64, object: u64) -> bool {
    if !BODIES.lock().get(&pointer).is_some_and(|body| body.directory) {
        return false;
    }
    body(pointer).session_object.atomic().compare_exchange(0, object, Ordering::SeqCst, Ordering::SeqCst).is_ok()
}

/// O SessionObject de um diretório (0 sem objeto).
pub fn session_object(pointer: u64) -> u64 {
    if BODIES.lock().contains_key(&pointer) { body(pointer).session_object.get() } else { 0 }
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

/// Substitui o descritor do corpo (o atribuído na criação ou o do
/// NtSetSecurityObject); o do nó, que as buscas pelo namespace leem, muda
/// junto. `false` sem o corpo.
pub fn set_security(pointer: u64, policy: SecurityPolicy) -> bool {
    let node = BODIES.lock().get_mut(&pointer).map(|body| {
        body.security = policy.clone();
        body.node
    });
    match node {
        Some(node) => {
            object_security::replace(node, policy);
            true
        }
        None => false,
    }
}
