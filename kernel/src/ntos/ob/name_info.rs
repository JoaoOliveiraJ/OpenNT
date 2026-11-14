//! O OBJECT_HEADER_NAME_INFO dos objetos com nome — ObQueryNameInfo.
//!
//! No NT o nome de um objeto mora no cabeçalho opcional de nome, antes do
//! OBJECT_HEADER (InfoMask bit 2): Directory (o OBJECT_DIRECTORY que o
//! contém), Name (só o componente final) e ReferenceCount; ObQueryNameInfo
//! devolve esse cabeçalho, ou NULL para um objeto sem nome. O OpenNT não
//! guarda cabeçalhos antes dos corpos: o ObInsertObject de um objeto com
//! nome registra aqui um OBJECT_HEADER_NAME_INFO (memória do kernel, com o
//! texto logo depois), com o diretório pai do namespace, e o desfaz quando o
//! objeto sai do namespace.

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::{NtStruct, ObjectHeaderNameInfo};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::rtl::guest_strings;
use crate::rtl::SpinLock;

/// Corpo -> (cabeçalho de nome, nó do namespace).
static NAMES: SpinLock<BTreeMap<u64, (u64, NodeId)>> = SpinLock::new(BTreeMap::new());

/// O corpo nativo do diretório `node` (0 se ele não tem um).
fn directory_body(node: NodeId) -> u64 {
    object_manager::node(node).and_then(|node| node.data).map_or(0, |data| if data.native_body != 0 { data.native_body } else { data.native_pointer })
}

/// Registra o nome de `object`, inserido como `name` no diretório `parent`
/// (o nó `node`). Um registro anterior do mesmo corpo é trocado.
pub fn record(object: u64, parent: NodeId, node: NodeId, name: &str) {
    let units = name.encode_utf16().count() as u64;
    let block = guest::alloc_bytes(ObjectHeaderNameInfo::SIZE + (units + 1) * 2);
    if block == 0 {
        return;
    }
    // SAFETY: bloco recém-alocado com o cabeçalho e o texto.
    let info = unsafe { ObjectHeaderNameInfo::at(block) };
    let text = block + ObjectHeaderNameInfo::SIZE;
    info.directory.set(directory_body(parent));
    info.name.length.set((units * 2) as u16);
    info.name.maximum_length.set((units * 2 + 2) as u16);
    info.name.buffer.set(text);
    info.reference_count.set(0);
    guest_strings::write_wide_string(text, name);
    if let Some((previous, _)) = NAMES.lock().insert(object, (block, node)) {
        guest::free_bytes(previous);
    }
}

/// ObQueryNameInfo: o cabeçalho de nome de `object`, ou 0 se ele não tem
/// nome (ou o nome já saiu do namespace, quando o registro é desfeito).
pub fn query(object: u64) -> u64 {
    let entry = NAMES.lock().get(&object).copied();
    match entry {
        Some((block, node)) if object_manager::is_attached(node) => block,
        Some(_) => {
            forget(object);
            0
        }
        None => 0,
    }
}

/// Desfaz o registro de `object`.
pub fn forget(object: u64) {
    if let Some((block, _)) = NAMES.lock().remove(&object) {
        guest::free_bytes(block);
    }
}
