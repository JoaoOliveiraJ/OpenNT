//! Criação nativa de seções.
//!
//! A validação nunca publica um handle: o handle só aparece depois de o
//! backing, o nome e a posse do objeto existirem. MmCreateSection usa o
//! mesmo construtor e devolve um SECTION referenciado, sem handle nem nome.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::section::file::{self as section_file, CapturedFile};
use crate::ntos::mm::section::parameters::{self as section_parameters, Decoded};
use crate::ntos::mm::partition;
use crate::ntos::ex::callback_security;
use crate::ntos::ke::irql;
use crate::ntos::ob::object_manager::{self, NodeId, ObjectData, ROOT};
use crate::ntos::ob::objects::section::{self as section_objects, CreationAttributes};
use crate::ntos::ob::{object_access, object_types, open_pointer};
use crate::ntos::ps::user::sections::{self, CreateOptions, SectionFile};
use crate::ntos::ps::user::state;
use crate::ntos::ps::{process, user_probe};
use crate::ntos::se::object_security;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;
use core::mem::offset_of;

use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Acl, ObjectAttributes, SecurityDescriptor, SecurityDescriptorRelative, Sid, UnicodeString};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Lê um campo de uma estrutura do chamador (OBJECT_ATTRIBUTES, nome,
/// descritor): em UserMode a leitura é sondada — a página pode sumir depois
/// da sondagem do intervalo, o `__try` do NT — e falha com
/// STATUS_ACCESS_VIOLATION; em KernelMode é direta. Pelo endereço do campo:
/// o NT só exige alinhamento de 4 nessas estruturas.
pub(crate) fn caller_read<T: GuestScalar>(address: u64, mode: u8) -> Result<T, u32> {
    if mode != 0 { guest::try_read(address).map_err(|_| STATUS_ACCESS_VIOLATION) } else { Ok(guest::read(address)) }
}

/// Os caracteres de um nome do chamador (`length` bytes), lidos em bloco.
pub(crate) fn caller_units(buffer: u64, length: u64, mode: u8) -> Result<Vec<u16>, u32> {
    let bytes = if mode != 0 { guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? } else { guest::read_bytes(buffer, length as usize) };
    Ok(bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect())
}

fn readable(pointer: u64, length: u64) -> bool {
    user_probe::probe_user_read(pointer, length)
}

/// Sonda um descritor de usuário: cabeçalho e cada componente presente.
pub fn descriptor_probe(pointer: u64) -> bool {
    if pointer == 0 {
        return true;
    }
    if !readable(pointer, 4) {
        return false;
    }
    let Ok(control) = guest::try_read::<u16>(pointer + offset_of!(SecurityDescriptor, control) as u64) else { return false };
    let relative = control & 0x8000 != 0;
    if !readable(pointer, if relative { 20 } else { 40 }) {
        return false;
    }
    for index in 0..4u64 {
        if (index == 2 && control & 16 == 0) || (index == 3 && control & 4 == 0) {
            continue;
        }
        // Owner, Group, Sacl e Dacl: deslocamentos (auto-relativo) ou ponteiros.
        let field = if relative {
            guest::try_read::<u32>(pointer + offset_of!(SecurityDescriptorRelative, owner) as u64 + index * 4).map(u64::from)
        } else {
            guest::try_read::<u64>(pointer + offset_of!(SecurityDescriptor, owner) as u64 + index * 8)
        };
        let Ok(field) = field else { return false };
        if field == 0 {
            continue;
        }
        let component = if relative { pointer + field } else { field };
        if !readable(component, 8) {
            return false;
        }
        // SID: cabeçalho de 8 bytes + SubAuthorityCount DWORDs; ACL: AclSize.
        let size = if index < 2 {
            guest::try_read::<u8>(component + offset_of!(Sid, sub_authority_count) as u64).map(|count| offset_of!(Sid, sub_authority) as u64 + 4 * count as u64)
        } else {
            guest::try_read::<u16>(component + offset_of!(Acl, acl_size) as u64).map(u64::from)
        };
        let Ok(size) = size else { return false };
        if !readable(component, size) {
            return false;
        }
    }
    true
}

/// OBJECT_ATTRIBUTES capturados para a seção.
#[derive(Clone, Debug, Default)]
pub struct Attributes {
    pub flags: u32,
    pub security_descriptor: u64,
    pub name: Option<String>,
    pub root: u64,
    pub insensitive: bool,
    pub parent: Option<NodeId>,
    pub leaf: String,
    pub node: Option<NodeId>,
}

/// Captura e resolve os atributos: nome sem NUL, barra final nem barras
/// duplas; raiz por handle de diretório (de kernel ou do processo); pai
/// existente e não montado. `capture_only` (MmCreateSection) guarda o nome
/// sem abrir nem publicar o objeto homônimo.
pub fn attributes(pointer: u64, mode: u8, capture_only: bool) -> Result<Attributes, u32> {
    if pointer == 0 {
        return Ok(Attributes::default());
    }
    if caller_read::<u32>(pointer + offset_of!(ObjectAttributes, length) as u64, mode)? != ObjectAttributes::SIZE as u32 {
        return Err(0xC000_000D);
    }
    let flags: u32 = caller_read(pointer + offset_of!(ObjectAttributes, attributes) as u64, mode)?;
    let root: u64 = caller_read(pointer + offset_of!(ObjectAttributes, root_directory) as u64, mode)?;
    let unicode: u64 = caller_read(pointer + offset_of!(ObjectAttributes, object_name) as u64, mode)?;
    if flags & !0x1FF2 != 0 || (mode != 0 && flags & 0x200 != 0) {
        return Err(0xC000_000D);
    }
    let security_descriptor: u64 = caller_read(pointer + offset_of!(ObjectAttributes, security_descriptor) as u64, mode)?;
    if mode != 0 && !descriptor_probe(security_descriptor) {
        return Err(0xC000_0005);
    }
    let unnamed = |root: u64| if root != 0 { Err(0xC000_003B) } else { Ok(Attributes { flags, security_descriptor, ..Attributes::default() }) };
    if unicode == 0 {
        return unnamed(root);
    }
    if mode != 0 && !readable(unicode, 16) {
        return Err(0xC000_0005);
    }
    let length = caller_read::<u16>(unicode + offset_of!(UnicodeString, length) as u64, mode)? as u64;
    let maximum = caller_read::<u16>(unicode + offset_of!(UnicodeString, maximum_length) as u64, mode)? as u64;
    let buffer: u64 = caller_read(unicode + offset_of!(UnicodeString, buffer) as u64, mode)?;
    if length & 1 != 0 || length > maximum || (buffer == 0 && length != 0) {
        return Err(0xC000_0033);
    }
    if length == 0 {
        return unnamed(root);
    }
    if mode != 0 && !readable(buffer, length) {
        return Err(0xC000_0005);
    }
    let units = caller_units(buffer, length, mode)?;
    let mut name = String::from_utf16_lossy(&units);
    if name.contains('\0') || name.ends_with('\\') || name.contains("\\\\") {
        return Err(0xC000_0033);
    }
    let insensitive = flags & 0x40 != 0;
    if capture_only {
        return Ok(Attributes { flags, security_descriptor, name: Some(name), root, insensitive, ..Attributes::default() });
    }
    if root != 0 {
        if name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        let mut directory = if root <= 0x7FFF_FFFF { object_manager::get_object(root as u32) } else { None };
        let current = process::get_current_process();
        if root <= 0x7FFF_FFFF && current != process::get_system_process() && state::is_user_process(current) {
            if let Some(entry) = state::get_user_handle(root) {
                if entry.kind() != "directory" {
                    return Err(0xC000_0024);
                }
                directory = entry.object.namespace_node();
            } else if let Ok(opened) = crate::ntos::ob::handles::namespace::resolve(root, true) {
                // O handle nativo de um diretório criado pelo processo
                // (NtCreateDirectoryObject).
                if !opened.directory {
                    return Err(0xC000_0024);
                }
                directory = Some(opened.node);
            }
        }
        let Some(directory) = directory else { return Err(0xC000_0008) };
        if object_manager::node(directory).is_none_or(|node| node.type_name != "Directory") {
            return Err(0xC000_0024);
        }
        let Some(path) = object_manager::path_of(directory) else { return Err(0xC000_003A) };
        name = alloc::format!("{}\\{}", if path == "\\" { "" } else { &path }, name);
    } else if !name.starts_with('\\') {
        return Err(0xC000_003B);
    }
    let at = name.rfind('\\').unwrap_or(0);
    let parent_path = if at == 0 { "\\" } else { &name[..at] };
    let Some(parent) = object_manager::resolve_from(parent_path, 0, insensitive, false, ROOT).0 else { return Err(0xC000_003A) };
    if object_manager::node(parent).is_none_or(|node| node.type_name != "Directory" || node.mount.is_some()) {
        return Err(0xC000_0024);
    }
    let node = object_manager::resolve_from(&name, 0, insensitive, false, ROOT).0;
    let leaf = String::from(&name[at + 1..]);
    Ok(Attributes { flags, security_descriptor, name: Some(name), root, insensitive, parent: Some(parent), leaf, node })
}

/// Privilégio habilitado no token do sujeito (modo kernel dispensa).
fn privilege(id: u64, mode: u8) -> bool {
    if mode == 0 {
        return true;
    }
    object_access::subject().and_then(|token| tokens::with(token, |token| token.privileges.iter().any(|privilege| privilege.id == id && privilege.attributes & 2 != 0))).unwrap_or(false)
}

/// Abre o corpo e entrega o handle; uma falha ao gravar a saída fecha o
/// handle recém-aberto.
fn open_and_publish(pointer: u64, flags: u32, access: u32, mode: u8, output: u64) -> Result<u32, KernelError> {
    let scratch = guest::alloc_bytes(8);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    let result = (|| {
        let status = open_pointer::open(pointer, flags & !0x90, 0, access, object_types::section_type().pointer, mode, scratch)?;
        if status != 0 {
            return Ok(status);
        }
        // SAFETY: a célula de 8 bytes alocada acima.
        let handle = unsafe { Field::<u64>::at(scratch) }.get();
        if let Err(error) = guest::try_write64(output, handle) {
            open_pointer::close(handle);
            return Err(error);
        }
        Ok(0)
    })();
    guest::free_bytes(scratch);
    result
}

/// NtCreateSection/ZwCreateSection (e o corpo de MmCreateSection quando
/// `file_object` vem preenchido).
#[allow(clippy::too_many_arguments)]
pub fn create(output: u64, access: u32, object_attributes: u64, size_pointer: u64, protect: u32, allocation: u32, file_handle: u64, mode: u8, object_request: Option<u64>) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwCreateSection requires PASSIVE_LEVEL"));
    }
    if mode != 0 && object_request.is_none() && (!state::probe_user_write(output, 8) || (object_attributes != 0 && !state::probe_user_read(object_attributes, 48)) || (size_pointer != 0 && !state::probe_user_read(size_pointer, 8))) {
        return Ok(0xC000_0005);
    }
    // A entrada Mm recebe MaximumSize por ponteiro obrigatório; Nt/Zw aceitam NULL.
    let size = if size_pointer != 0 || object_request.is_some() { guest::try_read64(size_pointer)? } else { 0 };
    let kernel_object = object_request.is_some();
    let mut file_handle = file_handle;
    let mut partition_body = None;
    let request = match section_parameters::decode(allocation, protect, size, file_handle, 1, kernel_object) {
        Decoded::Status(status) => return Ok(status),
        Decoded::Request(request) => request,
        Decoded::Partition { partition_handle, .. } => {
            match partition::resolve(partition_handle, 2, mode) {
                Ok(body) => partition_body = Some(body),
                Err(status) => return Ok(status),
            }
            file_handle = 0;
            match section_parameters::decode(allocation & !0x40000, protect, size, 0, 1, kernel_object) {
                Decoded::Request(request) => request,
                Decoded::Status(status) => return Ok(status),
                Decoded::Partition { .. } => return Ok(0xC000_000D),
            }
        }
    };
    let image = request.attributes & 0x0100_0000 != 0;
    let info = match attributes(object_attributes, mode, kernel_object) {
        Ok(info) => info,
        Err(status) => return Ok(status),
    };
    if let Some(node) = info.node {
        let Some(existing) = object_manager::node(node) else { return Ok(0xC000_0024) };
        if existing.type_name != "Section" {
            return Ok(0xC000_0024);
        }
        if info.flags & 0x80 == 0 {
            return Ok(0xC000_0035);
        }
        let pointer = existing.data.map_or(0, |data| data.native_pointer);
        let status = open_and_publish(pointer, info.flags, access, mode, output)?;
        return Ok(if status != 0 { status } else { 0x4000_0000 });
    }
    if info.flags & 0x10 != 0 && !privilege(16, mode) {
        return Ok(0xC000_0061);
    }
    if let Some(parent) = info.parent.filter(|_| mode != 0 || info.flags & 0x400 != 0) {
        let Some(subject) = object_access::subject() else { return Ok(0xC000_007C) };
        if let Err(status) = object_security::access(&object_security::directory(parent), subject, 4) {
            return Ok(status);
        }
    }
    let security = if info.security_descriptor != 0 {
        match callback_security::capture(info.security_descriptor) {
            Ok(policy) => policy,
            Err(status) => return Ok(status),
        }
    } else {
        object_access::capture(object_access::subject())
    };
    if mode != 0 && security.sacl.as_deref().is_some_and(crate::ntos::se::model::sacl_requires_security_privilege) && !privilege(8, mode) {
        return Ok(0xC000_0061);
    }
    let mut file: Option<Arc<CapturedFile>> = None;
    let mut held = false;
    let mut created: Option<Arc<sections::Section>> = None;
    let result = (|| -> Result<u32, KernelError> {
        let file_object = object_request.unwrap_or(0);
        if file_handle != 0 || file_object != 0 {
            let required = match section_parameters::file_request(&request) {
                Ok(required) => required,
                Err(status) => return Ok(status),
            };
            // FILE_OBJECT explícito tem identidade própria e precede o
            // FileHandle; nenhum handle temporário é fabricado.
            let captured = if file_object != 0 { section_file::capture_pointer(file_object, request.page_protect, image, required) } else { section_file::capture(file_handle, mode, request.page_protect, image, required) };
            let captured = match captured {
                Ok(captured) => captured,
                Err(status) => return Ok(status),
            };
            captured.acquire()?;
            held = true;
            file = Some(captured);
        }
        let mut dimensions = None;
        match &file {
            None => {
                if request.attributes & 0x8000_0000 != 0 && !privilege(4, mode) {
                    return Ok(0xC000_0061);
                }
                match section_parameters::pagefile_size(&request) {
                    Ok(size) => dimensions = Some((size.rounded_size, size.committed, size.large)),
                    Err(status) => return Ok(status),
                }
            }
            Some(captured) if !image => {
                if request.size > 0x7FFF_FFFF_FFFF_F000 {
                    return Ok(0xC000_0040);
                }
                let maximum = if request.size != 0 { request.size } else { captured.size() };
                if maximum == 0 {
                    return Ok(0xC000_011E);
                }
                if maximum > (1 << 53) - 1 {
                    return Ok(0xC000_0040);
                }
                if maximum > captured.size() {
                    let status = captured.resize(maximum)?;
                    if status != 0 {
                        return Ok(status);
                    }
                }
                dimensions = Some(((maximum + 4095) & !4095, true, false));
            }
            Some(_) => {}
        }
        // Imagens protegidas/especiais exigem a política de MM/CI; SEC_BASED
        // exige reserva independente de processo. Nenhuma vira seção comum.
        if request.flags & 0x370 != 0 || request.attributes & 0x0020_0000 != 0 {
            return Ok(0xC000_00BB);
        }
        let backing: Option<Arc<dyn SectionFile>> = file.clone().map(|captured| captured as Arc<dyn SectionFile>);
        let outcome = if image {
            sections::create_image(backing.ok_or_else(|| KernelError::new("image section without file"))?, None, request.page_protect, request.flags & 0x400 == 0)?
        } else {
            let (rounded, committed, large) = dimensions.unwrap_or((0, false, false));
            sections::create(CreateOptions { size: rounded, page_protect: request.page_protect, attributes: request.attributes, file: backing, large, committed: Some(committed), ..CreateOptions::default() })?
        };
        let section = match outcome {
            Ok(section) => section,
            Err(status) => return Ok(status),
        };
        created = Some(section.clone());
        let pointer = section.pointer();
        // A seção retém a partição escolhida até a destruição.
        if let Some(body) = partition_body {
            crate::ntos::ob::objects::dispatcher::reference(body)?;
            section.state.lock().partition = Some(alloc::boxed::Box::new(move || {
                let _ = crate::ntos::ob::objects::dispatcher::dereference(body);
            }));
        }
        // O arquivo retido passa para o objeto, inclusive em imagens.
        if let Some(captured) = &file {
            let owner = captured.clone();
            section.state.lock().release_file = Some(alloc::boxed::Box::new(move || {
                let _ = owner.release();
            }));
            held = false;
            section.state.lock().image_file_object = captured.pointer();
            section_objects::update(pointer, |state| state.image_file_object = captured.pointer());
        }
        section_objects::set_security(pointer, security.clone());
        if info.flags & 0x20 != 0 {
            let current = process::get_current_process();
            section_objects::update(pointer, |state| state.exclusive_process = current);
        }
        if kernel_object {
            // O chamador recebe uma referência real; nenhum handle ou nome
            // foi publicado.
            let creation = CreationAttributes { flags: info.flags, security_descriptor: info.security_descriptor, name: info.name.clone(), root: info.root, insensitive: info.insensitive };
            section_objects::update(pointer, |state| state.creation_attributes = Some(creation));
            section_objects::reference(pointer);
            if let Err(error) = guest::try_write64(output, pointer) {
                section_objects::dereference(pointer)?;
                return Err(error);
            }
            created = None;
            return Ok(0);
        }
        section_objects::update(pointer, |state| state.permanent = info.flags & 0x10 != 0);
        if let (Some(_), Some(parent)) = (&info.name, info.parent) {
            let Some(node) = object_manager::insert_named(parent, &info.leaf, "Section", Some(ObjectData::pointer(pointer)), info.insensitive) else { return Ok(0xC000_0035) };
            let path = object_manager::path_of(node);
            {
                let mut owner = section.state.lock();
                owner.node = Some(node);
                owner.name = path.clone();
            }
            section_objects::update(pointer, |state| state.name = path.unwrap_or_default());
        }
        // Como no ObInsertObject, quem cria a seção recebe o acesso pedido
        // sem a checagem pela DACL do descritor que ele mesmo deu (o handle
        // continua na tabela do processo de quem chama).
        let status = open_and_publish(pointer, info.flags, access, 0, output)?;
        if status != 0 {
            return Ok(status);
        }
        created = None;
        Ok(0)
    })();
    let result = match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    };
    if let Some(section) = created {
        section_objects::update(section.pointer(), |state| state.permanent = false);
        section_objects::collect(section.pointer())?;
    }
    if held {
        if let Some(captured) = &file {
            captured.release()?;
        }
    }
    result
}

/// MmCreateSection: mesmo construtor de backing, proteção, segurança e
/// rollback; DesiredAccess é ignorado na criação do corpo.
#[allow(clippy::too_many_arguments)]
pub fn create_object(output_object: u64, _desired_access: u32, object_attributes: u64, maximum_size: u64, protect: u32, allocation: u32, file_handle: u64, file_object: u64, previous_mode: u8) -> Result<u32, KernelError> {
    create(output_object, 0, object_attributes, maximum_size, protect, allocation, file_handle, previous_mode, Some(file_object))
}
