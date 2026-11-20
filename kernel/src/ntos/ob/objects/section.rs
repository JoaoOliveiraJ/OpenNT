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
use crate::ntos::ob::open_pointer::{self, HandleOpen, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{NtStruct, Section};
use crate::ntos::mm::guest_memory as guest;

/// Estado de vida da seção, visível ao dono (Mm).
#[derive(Clone, Debug, Default)]
pub struct SectionState {
    pub size: u64,
    pub name: String,
    pub handles: u32,
    pub views: u32,
    pub permanent: bool,
    /// KernelOnlyAccess (o OBJ_KERNEL_EXCLUSIVE da criação): handle só em
    /// KernelMode sem OBJ_FORCE_ACCESS_CHECK.
    pub kernel_only: bool,
    pub image_file_object: u64,
    /// OBJ_EXCLUSIVE: único processo que pode abrir handles.
    pub exclusive_process: u64,
    /// Atributos capturados pelo MmCreateSection para o ObInsertObject; a
    /// seção continua um objeto novo (OB_FLAG_NEW_OBJECT) até a inserção.
    pub creation_attributes: Option<CreationAttributes>,
    /// O SecurityDescriptor nulo do NT: seção sem nome criada sem descritor
    /// (o tipo Section não exige um), aberta por ponteiro sem SeAccessCheck.
    pub no_descriptor: bool,
    /// O SECTION_IMAGE_INFORMATION de uma seção de imagem (o da imagem
    /// principal de um processo, capturado ao mapeá-la).
    pub image_information: Option<alloc::vec::Vec<u8>>,
    /// O nível de assinatura que a CI deu à imagem principal de um processo
    /// (no 19041, o Segment+0xF bits 4-7 da seção, gravado na criação):
    /// `None` antes da primeira resposta, `Some(None)` para a imagem recusada.
    pub signing_level: Option<Option<u8>>,
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

const OBJ_FORCE_ACCESS_CHECK: u32 = 0x400;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

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
    /// A recusa do ObpIncrementHandleCountEx num objeto KernelOnlyAccess:
    /// UserMode (ou OBJ_FORCE_ACCESS_CHECK) dá STATUS_ACCESS_DENIED. Os
    /// demais seguem pelo `open_handle`.
    fn open_handle_for(&self, pointer: u64, open: &mut HandleOpen) -> Option<Result<(), KernelError>> {
        let access_mode = if open.attributes & OBJ_FORCE_ACCESS_CHECK != 0 { 1 } else { open.access_mode };
        let kernel_only = SECTIONS.lock().get(&pointer).is_some_and(|record| record.state.kernel_only);
        (kernel_only && access_mode != 0).then(|| Err(KernelError::with_status("secao so de modo kernel", STATUS_ACCESS_DENIED)))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(release(pointer))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        SECTIONS.lock().get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn set_security(&self, pointer: u64, security: SecurityPolicy) -> bool {
        SECTIONS
            .lock()
            .get_mut(&pointer)
            .map(|record| {
                record.security = security;
                record.state.no_descriptor = false;
            })
            .is_some()
    }
    fn has_descriptor(&self, pointer: u64) -> bool {
        SECTIONS.lock().get(&pointer).is_none_or(|record| !record.state.no_descriptor)
    }
    /// O processo que criou a seção com OBJ_EXCLUSIVE (0 = compartilhada),
    /// como o OBJECT_HEADER_PROCESS_INFO do NT.
    fn exclusive_process(&self, pointer: u64) -> u64 {
        SECTIONS.lock().get(&pointer).map_or(0, |record| record.state.exclusive_process)
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
    let pointer = guest::alloc_bytes(Section::SIZE);
    if pointer == 0 {
        return Ok(0);
    }
    // SAFETY: alocação nova (zerada) do tamanho de um _SECTION.
    unsafe { Section::at(pointer) }.size_of_section.set(state.size);
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

/// O SECTION_IMAGE_INFORMATION da seção de imagem `pointer`.
pub fn set_image_information(pointer: u64, information: alloc::vec::Vec<u8>) -> Option<()> {
    SECTIONS.lock().get_mut(&pointer).map(|record| record.state.image_information = Some(information))
}

/// O nível de assinatura guardado da seção de imagem `pointer`
/// ([`SectionState::signing_level`]); `None` para seção desconhecida.
pub fn signing_level(pointer: u64) -> Option<Option<Option<u8>>> {
    SECTIONS.lock().get(&pointer).map(|record| record.state.signing_level)
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
