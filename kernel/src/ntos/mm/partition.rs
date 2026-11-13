//! Partição de memória do sistema.
//!
//! A partição do sistema é o alocador físico real, retida pela vida do
//! boot. O corpo de 0x20 bytes é privado do OpenNT (não é a MM_PARTITION do
//! Windows): referências (+0), handles (+8), total (+16) e disponível (+24),
//! espelhados do objeto e do banco de PFNs.

use alloc::string::String;
use alloc::vec;

use super::pfn;
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::{object_access, object_manager, object_types, open_pointer};
use crate::ntos::ps::user::state;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::inc::status::STATUS_UNSUCCESSFUL;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::section::create::{caller_read, caller_units};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ObjectAttributes, UnicodeString};

/// Corpo da partição do sistema (layout do OpenNT, não a MM_PARTITION):
/// contagens espelhadas do objeto e do banco de PFNs.
#[repr(C)]
pub(crate) struct PartitionBody {
    pub(crate) references: Field<u64>,
    pub(crate) handles: Field<u32>,
    _pad_c: Reserved<4>,
    pub(crate) total: Field<u64>,
    pub(crate) available: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PartitionBody {}

const _: () = assert!(core::mem::size_of::<PartitionBody>() == 0x20);

pub const SIZE: u64 = PartitionBody::SIZE;

impl PartitionBody {
    /// O corpo publicado (ou em publicação) em `pointer`.
    pub(crate) fn of(pointer: u64) -> &'static PartitionBody {
        // SAFETY: corpo alocado por `init` e vivo até `dispose`.
        unsafe { PartitionBody::at(pointer) }
    }
}

/// Corpo da partição do sistema (0 = ainda não publicado).
static BODY: SpinLock<u64> = SpinLock::new(0);

pub fn get() -> Option<u64> {
    let body = *BODY.lock();
    (body != 0).then_some(body)
}

fn dispose(pointer: u64) {
    pfn::unbind_partition(pointer);
    guest::free_bytes(pointer);
}

/// Publica o corpo depois da inicialização do PFN.
pub fn init() -> Result<u64, KernelError> {
    if let Some(body) = get() {
        return Ok(body);
    }
    let record = pfn::partition();
    if record.total == 0 {
        return Err(KernelError::new("partition published before PFN initialization"));
    }
    let pointer = guest::alloc_bytes(SIZE);
    if pointer == 0 {
        return Err(KernelError::new("system partition allocation failed"));
    }
    // A vida é mantida pela referência do alocador, não por OBJ_PERMANENT:
    // o NtQueryObject da partição nativa não informa a flag permanente.
    let body = PartitionBody::of(pointer);
    body.references.set(0);
    body.handles.set(0);
    pfn::bind_partition(pointer);
    let result = (|| -> Result<(), KernelError> {
        dispatcher_objects::create(pointer, "partition", dispose, None, 0, false, dispatcher_objects::DispatcherHooks::default())?;
        dispatcher_objects::mirror_counts(pointer);
        let administrators = sid(5, &[32, 544]);
        dispatcher_objects::set_security(pointer, SecurityPolicy { owner: administrators.clone(), group: Some(sid(5, &[18])), dacl: Some(vec![Ace { sid: Some(administrators), mask: 0x1F_0003, deny: false, flags: 0, raw: None }]), ..SecurityPolicy::default() });
        object_manager::create_directory("\\KernelObjects")?;
        object_manager::create_object("\\KernelObjects", "MemoryPartition0", "Partition", Some(object_manager::ObjectData::pointer(pointer)))?;
        // Dono permanente: o próprio alocador físico.
        dispatcher_objects::reference(pointer)?;
        Ok(())
    })();
    if let Err(error) = result {
        if dispatcher_objects::get(pointer).is_some() {
            dispatcher_objects::collect(pointer);
        } else {
            pfn::unbind_partition(pointer);
            guest::free_bytes(pointer);
        }
        return Err(error);
    }
    *BODY.lock() = pointer;
    Ok(pointer)
}

/// OBJECT_ATTRIBUTES capturados: corpo e atributos efetivos.
fn capture(attributes: u64, user: bool) -> Result<Result<(u64, u32), u32>, KernelError> {
    if attributes == 0 {
        return Ok(Err(0xC000_000D));
    }
    if user && !state::probe_user_read(attributes, 48) {
        return Ok(Err(0xC000_0005));
    }
    let mode = user as u8;
    let read_attributes = || -> Result<(u32, u32, u64, u64), u32> {
        let at = |offset: usize| attributes + offset as u64;
        Ok((
            caller_read(at(core::mem::offset_of!(ObjectAttributes, length)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, attributes)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, root_directory)), mode)?,
            caller_read(at(core::mem::offset_of!(ObjectAttributes, object_name)), mode)?,
        ))
    };
    let (length, flags, root, unicode) = match read_attributes() {
        Ok(fields) => fields,
        Err(status) => return Ok(Err(status)),
    };
    if length != ObjectAttributes::SIZE as u32 {
        return Ok(Err(0xC000_000D));
    }
    if flags & !0x1FE2 != 0 {
        return Ok(Err(0xC000_000D));
    }
    if unicode == 0 {
        return Ok(Err(0xC000_003B));
    }
    if user && !state::probe_user_read(unicode, 16) {
        return Ok(Err(0xC000_0005));
    }
    let read_name = || -> Result<(u64, u64, u64), u32> {
        let at = |offset: usize| unicode + offset as u64;
        Ok((
            caller_read::<u16>(at(core::mem::offset_of!(UnicodeString, length)), mode)? as u64,
            caller_read::<u16>(at(core::mem::offset_of!(UnicodeString, maximum_length)), mode)? as u64,
            caller_read(at(core::mem::offset_of!(UnicodeString, buffer)), mode)?,
        ))
    };
    let (length, maximum, buffer) = match read_name() {
        Ok(fields) => fields,
        Err(status) => return Ok(Err(status)),
    };
    if length & 1 != 0 || length > maximum {
        return Ok(Err(0xC000_0033));
    }
    if length != 0 && (buffer == 0 || (user && !state::probe_user_read(buffer, length))) {
        return Ok(Err(0xC000_0005));
    }
    let units = match caller_units(buffer, length, mode) {
        Ok(units) => units,
        Err(status) => return Ok(Err(status)),
    };
    let name: String = units.iter().map(|&unit| char::from_u32(unit as u32).unwrap_or('\u{FFFD}')).collect();
    let mut start = object_manager::ROOT;
    if root != 0 {
        let opened = match namespace_handles::resolve(root, user) {
            Ok(opened) => opened,
            Err(status) => return Ok(Err(status)),
        };
        if !opened.directory {
            return Ok(Err(0xC000_0024));
        }
        if name.starts_with('\\') {
            return Ok(Err(0xC000_003B));
        }
        start = opened.node;
    } else if !name.starts_with('\\') {
        return Ok(Err(0xC000_003B));
    }
    let insensitive = flags & 0x40 != 0;
    let (found, rest) = object_manager::resolve_from(&name, 0, insensitive, false, start);
    if rest.is_some() {
        return Ok(Err(0xC000_003A));
    }
    let Some(found) = found.and_then(object_manager::node) else {
        let parent_path = name.rfind('\\').map_or("", |at| &name[..at]);
        let parent = object_manager::resolve_from(parent_path, 0, insensitive, false, start).0.and_then(object_manager::node);
        return Ok(Err(if parent.is_none_or(|parent| parent.type_name != "Directory") { 0xC000_003A } else { 0xC000_0034 }));
    };
    if found.type_name != "Partition" {
        return Ok(Err(0xC000_0024));
    }
    let resolved = found.data.map_or(0, |data| data.native_pointer);
    if resolved == 0 || Some(resolved) != get() {
        return Err(KernelError::new("partition namespace has no allocator owner"));
    }
    Ok(Ok((resolved, if user { flags & !0x200 } else { flags })))
}

/// NtOpenPartition / ZwOpenPartition.
pub fn open(output: u64, access: u32, attributes: u64, user: bool) -> Result<u32, KernelError> {
    if user && !state::probe_user_write(output, 8) {
        return Ok(0xC000_0005);
    }
    let (body, flags) = match capture(attributes, user)? {
        Ok(input) => input,
        Err(status) => return Ok(status),
    };
    // O tipo nativo exige segurança e recusa máscara de acesso zero.
    if user && access == 0 {
        return Ok(0xC000_0022);
    }
    let Some(object_type) = object_types::user_type("partition") else { return Ok(0xC000_0024) };
    if user && flags & 0x20 != 0 {
        let policy = dispatcher_objects::security(body).unwrap_or_default();
        if let Err(status) = object_access::check(&policy, object_access::subject(), access, &object_type, false) {
            return Ok(status);
        }
    }
    let scratch = guest::alloc_bytes(8);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    let result = (|| -> Result<u32, KernelError> {
        let status = open_pointer::open(body, flags, 0, access, object_type.pointer, if user { 1 } else { 0 }, scratch)?;
        if status != 0 {
            return Ok(status);
        }
        // SAFETY: a célula de 8 bytes alocada acima.
        let handle = unsafe { Field::<u64>::at(scratch) }.get();
        if guest::try_write64(output, handle).is_err() {
            let _ = open_pointer::close(handle);
            return Ok(0xC000_0005);
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    match result {
        Err(error) if error.status != STATUS_UNSUCCESSFUL => Ok(error.status),
        other => other,
    }
}

fn user_open(output: u64, access: u32, attributes: u64) -> Result<u32, KernelError> {
    open(output, access, attributes, true)
}

/// Handle de partição com o acesso pedido (em modo usuário).
pub fn resolve(handle: u64, access: u32, mode: u8) -> Result<u64, u32> {
    let resolved = match open_pointer::resolve(handle, mode != 0) {
        None => return Err(0xC000_0008),
        Some(Err(status)) => return Err(if status != 0 { status } else { 0xC000_0008 }),
        Some(Ok(resolved)) => resolved,
    };
    let Some(body) = get().filter(|&body| body == resolved.item.pointer) else { return Err(0xC000_0024) };
    if mode != 0 && resolved.access & access != access {
        return Err(0xC000_0022);
    }
    Ok(body)
}

/// Liga o NtOpenPartition de usuário.
pub fn install() {
    crate::ntos::ps::user::syscalls_core::set_partition_opener(user_open);
}
