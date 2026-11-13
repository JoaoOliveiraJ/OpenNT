//! Identidade nativa das seções.
//!
//! Referências por ponteiro, handles e vistas mapeadas retêm o objeto de
//! forma independente. O estado de memória da seção pertence ao Mm; aqui
//! ficam o corpo _SECTION (0x40 bytes, SizeOfSection em +0x30) e as
//! contagens que decidem a destruição.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use crate::ntos::ob::object_manager::{self, ObjectData, ObjectHooks};
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Estado de vida da seção, visível ao dono (Mm).
#[derive(Clone, Debug, Default)]
pub struct SectionState {
    pub size: u64,
    pub name: String,
    pub handles: u32,
    pub views: u32,
    pub permanent: bool,
    pub image_file_object: u64,
    /// OBJ_EXCLUSIVE: único processo que pode abrir handles.
    pub exclusive_process: u64,
    /// Atributos capturados pelo MmCreateSection para o ObInsertObject.
    pub creation_attributes: Option<CreationAttributes>,
}

/// Nome e flags capturados antes da inserção (sem publicar no namespace).
#[derive(Clone, Debug, Default)]
pub struct CreationAttributes {
    pub flags: u32,
    pub security_descriptor: u64,
    pub name: Option<String>,
    pub root: u64,
    pub insensitive: bool,
}

struct Record {
    state: SectionState,
    references: u32,
    destroy: fn(u64) -> Result<(), KernelError>,
    security: SecurityPolicy,
}

static SECTIONS: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());

struct SectionOwner;

static OWNER: SectionOwner = SectionOwner;

impl ObjectOwner for SectionOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        object_types::section_type()
    }
    fn reference(&self, pointer: u64) {
        reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn open_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(retain(pointer))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(release(pointer))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        SECTIONS.lock().get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let Some((state, references)) = SECTIONS.lock().get(&pointer).map(|record| (record.state.clone(), record.references)) else { return crate::ntos::ob::open_pointer::QueryRecord::default() };
        // O nome vale só enquanto o namespace ainda aponta para esta seção.
        let named = !state.name.is_empty() && object_manager::lookup(&state.name).and_then(object_manager::node).and_then(|node| node.data).is_some_and(|data| data.native_pointer == pointer);
        crate::ntos::ob::open_pointer::QueryRecord { handles: Some(state.handles), references: references + state.handles + state.views, permanent: state.permanent, name: if named { state.name.clone() } else { alloc::string::String::new() } }
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

/// Aloca o corpo, publica o tamanho e captura a segurança inicial. 0 sem
/// memória.
pub fn register(state: SectionState, destroy: fn(u64) -> Result<(), KernelError>) -> Result<u64, KernelError> {
    let object_type = object_types::section_type();
    let pointer = guest::alloc_bytes(0x40);
    if pointer == 0 {
        return Ok(0);
    }
    guest::write64(pointer + 0x30, state.size);
    let security = object_access::capture(object_access::subject());
    SECTIONS.lock().insert(pointer, Record { state: SectionState { handles: 0, ..state }, references: 0, destroy, security });
    object_types::account(&object_type.name, 1, 0)?;
    open_pointer::register_owner(Slot::Section, is_section, &OWNER);
    Ok(pointer)
}

/// Destrói só seções não permanentes sem handles, vistas ou referências. Se
/// o destrutor falhar, o objeto continua dono dos recursos.
pub fn collect(pointer: u64) -> Result<(), KernelError> {
    let destroy = {
        let sections = SECTIONS.lock();
        let Some(record) = sections.get(&pointer) else { return Ok(()) };
        if record.state.permanent || record.state.handles != 0 || record.state.views != 0 || record.references != 0 {
            return Ok(());
        }
        record.destroy
    };
    destroy(pointer)?;
    SECTIONS.lock().remove(&pointer);
    object_types::account("Section", -1, 0)?;
    guest::free_bytes(pointer);
    Ok(())
}

pub fn reference(pointer: u64) -> Option<u32> {
    let mut sections = SECTIONS.lock();
    let record = sections.get_mut(&pointer)?;
    record.references += 1;
    Some(record.references)
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut sections = SECTIONS.lock();
        let Some(record) = sections.get_mut(&pointer) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("section reference underflow"));
        }
        record.references -= 1;
        record.references
    };
    collect(pointer)?;
    Ok(Some(count))
}

/// Retenção por handle.
pub fn retain(pointer: u64) -> Result<(), KernelError> {
    {
        let mut sections = SECTIONS.lock();
        let record = sections.get_mut(&pointer).ok_or_else(|| KernelError::new("handle to destroyed section"))?;
        record.state.handles += 1;
    }
    object_types::account("Section", 0, 1)
}

pub fn release(pointer: u64) -> Result<(), KernelError> {
    let had_handle = {
        let mut sections = SECTIONS.lock();
        let record = sections.get_mut(&pointer).ok_or_else(|| KernelError::new("release of destroyed section"))?;
        let had = record.state.handles != 0;
        if had {
            record.state.handles -= 1;
        }
        had
    };
    if had_handle {
        object_types::account("Section", 0, -1)?;
    }
    collect(pointer)
}

/// Atualiza o estado mantido pelo Mm (vistas, permanência...).
pub fn update(pointer: u64, body: impl FnOnce(&mut SectionState)) -> Option<()> {
    SECTIONS.lock().get_mut(&pointer).map(|record| body(&mut record.state))
}

pub fn state(pointer: u64) -> Option<SectionState> {
    SECTIONS.lock().get(&pointer).map(|record| record.state.clone())
}

/// Segurança definida pelo criador (descritor capturado ou padrão).
pub fn set_security(pointer: u64, security: SecurityPolicy) -> Option<()> {
    SECTIONS.lock().get_mut(&pointer).map(|record| record.security = security)
}

/// Genéricos e MAXIMUM_ALLOWED pela máscara de Section; `None` fora dela.
pub fn access(requested: u32) -> Option<u32> {
    let object_type = object_types::section_type();
    let mut mapped = requested;
    for (index, &value) in object_type.mapping.iter().enumerate() {
        if mapped & (0x8000_0000 >> index) != 0 {
            mapped |= value;
        }
    }
    mapped &= 0x0FFF_FFFF;
    if mapped & 0x0200_0000 != 0 {
        mapped = (mapped & !0x0200_0000) | object_type.valid_access;
    }
    if mapped & !object_type.valid_access != 0 { None } else { Some(mapped) }
}

struct SectionHandle {
    pointer: u64,
}

impl ObjectHooks for SectionHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        retain(self.pointer)
    }
    fn on_handle_close(&self) {
        let _ = release(self.pointer);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Handle de kernel ou do processo que retém a seção.
pub fn open_handle(pointer: u64, requested: u32, attributes: u32) -> Result<u64, KernelError> {
    let Some(name) = SECTIONS.lock().get(&pointer).map(|record| record.state.name.clone()) else { return Ok(0) };
    let Some(granted) = access(requested) else { return Ok(0) };
    let data = ObjectData { native_pointer: pointer, access: Some(granted), attributes, hooks: Some(Arc::new(SectionHandle { pointer })), ..ObjectData::default() };
    let node = object_manager::new_node(&name, "Section", Some(data));
    let identifier = object_manager::open_object(node, None)?;
    Ok(if attributes & 0x200 != 0 { 0xFFFF_FFFF_8000_0000 | identifier as u64 } else { identifier as u64 })
}

pub fn file_object(pointer: u64) -> Result<u64, KernelError> {
    SECTIONS.lock().get(&pointer).map(|record| record.state.image_file_object).ok_or_else(|| KernelError::new("unknown section object"))
}

pub fn is_section(pointer: u64) -> bool {
    SECTIONS.lock().contains_key(&pointer)
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    SECTIONS.lock().get(&pointer).map(|record| record.references)
}
