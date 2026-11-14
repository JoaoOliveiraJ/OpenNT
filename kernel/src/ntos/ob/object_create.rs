//! Criação de objetos — ObCreateObject, ObInsertObject e
//! ObDeleteCapturedInsertInfo, como no ntoskrnl 19041.
//!
//! ObCreateObject captura os OBJECT_ATTRIBUTES num OBJECT_CREATE_INFORMATION
//! (o ObpCaptureObjectCreateInformation, com o nome num buffer próprio) e
//! aloca o objeto com o OBJECT_HEADER do NT na frente (`object_header`); a
//! informação de criação fica presa ao cabeçalho (ObjectCreateInfo, Flags
//! NewObject) até o ObInsertObject ou o ObDeleteCapturedInsertInfo.
//! ObInsertObject publica o nome no namespace e abre o handle de criação
//! (ObCreateHandle) pela tabela do processo (`open_pointer::insert_with`).
//! ObCreateObjectType(Ex) mora em `object_types`.

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::extra_ob_header::ObjectCreateInformation;
use crate::ntos::inc::types::{Field, Kthread, NtStruct, ObjectAttributes, ObjectHeaderNameInfo};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::namespace;
use crate::ntos::ob::object_header::{self, OpenReason};
use crate::ntos::ob::object_manager::{self, ObjectData};
use crate::ntos::ob::{callbacks, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::se::{descriptor, privilege};
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_OBJECT_NAME_EXISTS: u32 = 0x4000_0000;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_OBJECT_PATH_SYNTAX_BAD: u32 = 0xC000_003B;
const STATUS_UNKNOWN_REVISION: u32 = 0xC000_0058;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;

const OBJ_PERMANENT: u32 = 0x10;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_OPENIF: u32 = 0x80;
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// Os atributos que o ObpCaptureObjectCreateInformation aceita: o
/// complemento de 0xFFFEE00D (OBJ_VALID_ATTRIBUTES e o bit 0x10000).
const VALID_CAPTURED_ATTRIBUTES: u32 = !0xFFFE_E00D;
/// MAXIMUM_ALLOWED vira GENERIC_ALL no ObpCreateHandle.
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const GENERIC_ALL: u32 = 0x1000_0000;
/// O fim da metade de usuário que as sondas do ObpCapture* aceitam.
const USER_PROBE_LIMIT: u64 = 0x7FFF_FFFF_0000;
/// O buffer de nome do ObpNameBufferLookasideList (nomes de até 0xF6 bytes).
const NAME_LOOKASIDE_SIZE: u32 = 0xF8;
const NON_PAGED_POOL_NX: u32 = 0x200;
const PAGED_POOL: u32 = 1;
/// TypeInfo.ObjectTypeFlags: SecurityRequired.
const TYPE_SECURITY_REQUIRED: u8 = 0x08;

/// Saída escalar (`PVOID*`, `PHANDLE`) de um chamador de kernel.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<T>::at(address) }
}

fn create_info_at(address: u64) -> &'static ObjectCreateInformation {
    // SAFETY: OBJECT_CREATE_INFORMATION alocado por `create` (memória do kernel).
    unsafe { ObjectCreateInformation::at(address) }
}

/// O PreviousMode da thread corrente (KTHREAD.PreviousMode).
fn thread_previous_mode() -> u8 {
    let thread = process::get_current_thread();
    if thread == 0 {
        return 0;
    }
    // SAFETY: a KTHREAD corrente.
    unsafe { Kthread::at(thread) }.previous_mode.get() as u8
}

/// O tipo de um objeto criado pelo ObCreateObject (com OBJECT_HEADER).
pub fn created_type(body: u64) -> Option<object_types::ObjectType> {
    object_header::object_type_info(body)
}

/// O nome capturado (UNICODE_STRING do kernel).
#[derive(Clone, Copy, Default)]
pub struct CapturedName {
    pub length: u16,
    pub maximum_length: u16,
    pub buffer: u64,
}

impl CapturedName {
    fn free(&self) {
        if self.buffer != 0 {
            let _ = pool_allocation::free(self.buffer, object_header::NAME_BUFFER_TAG as u64);
        }
    }
}

/// Lê um escalar dos OBJECT_ATTRIBUTES: com sonda quando a origem é
/// UserMode.
fn read<T: crate::ntos::mm::guest_memory::GuestScalar>(address: u64, probe: bool) -> Result<T, u32> {
    if probe {
        guest::try_read::<T>(address).map_err(|_| STATUS_ACCESS_VIOLATION)
    } else {
        Ok(guest::read::<T>(address))
    }
}

// --- ObpCaptureObjectName ---------------------------------------------------
// O texto vai para um buffer do kernel com NUL no fim (o do lookaside, de
// 0xF8 bytes, quando cabe; senão Length + 2 do pool paginável 'ObNm'). Nome
// vazio não aloca; Length ímpar ou 0xFFFE é STATUS_OBJECT_NAME_INVALID; em
// UserMode a estrutura e o texto ficam abaixo de 0x7FFFFFFF0000 e o buffer
// precisa de alinhamento par.
fn capture_name(name: u64, probe: bool) -> Result<CapturedName, u32> {
    if probe && name >= USER_PROBE_LIMIT {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let length = read::<u16>(name, probe)?;
    let buffer = read::<u64>(name + 8, probe)?;
    if probe && length != 0 {
        if buffer & 1 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let end = buffer.checked_add(length as u64).ok_or(STATUS_ACCESS_VIOLATION)?;
        if end > USER_PROBE_LIMIT {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    if length == 0 {
        return Ok(CapturedName::default());
    }
    if length & 1 != 0 || length == 0xFFFE {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let maximum = (length as u32 + 2).max(NAME_LOOKASIDE_SIZE);
    let text = if probe { guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? } else { guest::read_bytes(buffer, length as usize) };
    let copy = pool_allocation::allocate_tagged(PAGED_POOL, maximum as u64, object_header::NAME_BUFFER_TAG).unwrap_or(0);
    if copy == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(copy, &text);
    guest::write_bytes(copy + length as u64, &[0, 0]);
    Ok(CapturedName { length, maximum_length: maximum as u16, buffer: copy })
}

/// SeComputeQuotaInformationSize: o grupo (8 + 4 por subautoridade) mais a
/// DACL presente (AclSize arredondado a 4); revisão diferente de 1 é
/// STATUS_UNKNOWN_REVISION.
fn security_quota_size(sd: u64) -> Result<u32, u32> {
    if guest::read::<u8>(sd) != 1 {
        return Err(STATUS_UNKNOWN_REVISION);
    }
    let control = descriptor::control(sd);
    let group = descriptor::component(sd, control, 1);
    let dacl = descriptor::component(sd, control, 3);
    let mut size = 0u32;
    if group != 0 {
        size += (guest::read::<u8>(group + 1) as u32 * 4 + 0xB) & !3;
    }
    if dacl != 0 {
        size += (guest::read::<u16>(dacl + 2) as u32 + 3) & !3;
    }
    Ok(size)
}

// --- ObpCaptureObjectCreateInformation ----------------------------------------
// Como no ntoskrnl 19041 (rva 0x6cf200): sem OBJECT_ATTRIBUTES tudo fica
// zerado; Length precisa ser 0x30; OwnerMode UserMode tira OBJ_KERNEL_HANDLE
// e atributo fora de 0x11FF2 é STATUS_INVALID_PARAMETER; RootDirectory,
// SECURITY_QUALITY_OF_SERVICE (copiado, ContextTrackingMode até 1 e
// ImpersonationLevel até Delegation), o descritor (SeCaptureSecurityDescriptor
// e o tamanho da cobrança) e o nome; RootDirectory sem nome é
// STATUS_OBJECT_NAME_INVALID. Em UserMode as leituras passam por sonda.
fn capture(probe_mode: u8, owner_mode: u8, attributes: u64, create_info: u64) -> Result<CapturedName, u32> {
    let create = create_info_at(create_info);
    if attributes == 0 {
        return Ok(CapturedName::default());
    }
    create.probe_mode.set(probe_mode);
    let probe = probe_mode != 0 && thread_previous_mode() != 0;
    if probe && (attributes & 7 != 0 || attributes >= USER_PROBE_LIMIT) {
        return Err(if attributes & 7 != 0 { STATUS_DATATYPE_MISALIGNMENT } else { STATUS_ACCESS_VIOLATION });
    }
    if read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, length) as u64, probe)? != ObjectAttributes::SIZE as u32 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    create.root_directory.set(read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, root_directory) as u64, probe)?);
    let mut flags = read::<u32>(attributes + core::mem::offset_of!(ObjectAttributes, attributes) as u64, probe)?;
    if owner_mode != 0 {
        flags &= !OBJ_KERNEL_HANDLE;
    }
    if flags & !VALID_CAPTURED_ATTRIBUTES != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    create.attributes.set(flags);
    let name = read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, object_name) as u64, probe)?;
    let sd = read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, security_descriptor) as u64, probe)?;
    let qos = read::<u64>(attributes + core::mem::offset_of!(ObjectAttributes, security_quality_of_service) as u64, probe)?;
    let release = |create: &ObjectCreateInformation| {
        let captured = create.security_descriptor.get();
        if captured != 0 {
            descriptor::release_captured(captured);
            create.security_descriptor.set(0);
        }
    };
    if sd != 0 {
        let status = descriptor::capture(sd, create.security_descriptor.address());
        if status != STATUS_SUCCESS {
            create.security_descriptor.set(0);
            return Err(status);
        }
        match security_quota_size(create.security_descriptor.get()) {
            Ok(size) => create.security_descriptor_charge.set(size),
            Err(status) => {
                release(create);
                return Err(status);
            }
        }
    }
    if qos != 0 {
        if probe && (qos & 3 != 0 || qos >= USER_PROBE_LIMIT) {
            release(create);
            return Err(if qos & 3 != 0 { STATUS_DATATYPE_MISALIGNMENT } else { STATUS_ACCESS_VIOLATION });
        }
        let bytes = if probe { guest::try_read_bytes(qos, 12).map_err(|_| STATUS_ACCESS_VIOLATION) } else { Ok(guest::read_bytes(qos, 12)) };
        let bytes = match bytes {
            Ok(bytes) => bytes,
            Err(status) => {
                release(create);
                return Err(status);
            }
        };
        let quality = &create.security_quality_of_service;
        guest::write_bytes(quality.address(), &bytes);
        quality.length.set(12);
        create.security_qos.set(quality.address());
        if quality.context_tracking_mode.get() >= 2 {
            release(create);
            return Err(STATUS_INVALID_PARAMETER);
        }
        if quality.impersonation_level.get().0 > 3 {
            release(create);
            return Err(STATUS_BAD_IMPERSONATION_LEVEL);
        }
    }
    if name == 0 {
        if create.root_directory.get() != 0 {
            release(create);
            return Err(STATUS_OBJECT_NAME_INVALID);
        }
        return Ok(CapturedName::default());
    }
    capture_name(name, probe).inspect_err(|_| release(create))
}

// --- ObCreateObject ---------------------------------------------------------
// NTSTATUS ObCreateObject(KPROCESSOR_MODE ProbeMode, POBJECT_TYPE Type,
//   POBJECT_ATTRIBUTES Attr, KPROCESSOR_MODE OwnerMode, PVOID ParseContext,
//   ULONG BodySize, ULONG PagedCharge, ULONG NonPagedCharge, PVOID *Object)
//
// O ObCreateObjectEx (rva 0x651ea0): a captura num OBJECT_CREATE_INFORMATION
// do pool não paginável ('ObCi'); atributo proibido pelo
// TypeInfo.InvalidAttributes é STATUS_INVALID_PARAMETER; OBJ_PERMANENT pede o
// SeCreatePermanentPrivilege (STATUS_PRIVILEGE_NOT_HELD); cobranças zero
// viram as padrão do tipo; o ObpAllocateObject monta o cabeçalho e *Object
// recebe o corpo.
#[allow(clippy::too_many_arguments)]
pub fn create(probe_mode: u8, type_pointer: u64, attributes: u64, owner_mode: u8, body_size: u32, paged_charge: u32, non_paged_charge: u32, output: u64) -> u32 {
    let Some(object_type) = object_types::type_object(type_pointer) else { return STATUS_INVALID_PARAMETER };
    let create_info = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX | 0x400, ObjectCreateInformation::SIZE, object_header::CREATE_INFO_TAG).unwrap_or(0);
    if create_info == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let name = match capture(probe_mode, owner_mode, attributes, create_info) {
        Ok(name) => name,
        Err(status) => {
            let _ = pool_allocation::free(create_info, object_header::CREATE_INFO_TAG as u64);
            return status;
        }
    };
    let create = create_info_at(create_info);
    let failure = |status: u32| {
        name.free();
        object_header::free_create_info(create_info);
        status
    };
    let flags = create.attributes.get();
    if flags & object_type.type_info.invalid_attributes.get() != 0 {
        return failure(STATUS_INVALID_PARAMETER);
    }
    if flags & OBJ_PERMANENT != 0 && !privilege::single_privilege_check(probe_mode as u32) {
        return failure(STATUS_PRIVILEGE_NOT_HELD);
    }
    create.paged_pool_charge.set(if paged_charge != 0 { paged_charge } else { object_type.type_info.default_paged_pool_charge.get() });
    create.non_paged_pool_charge.set(if non_paged_charge != 0 { non_paged_charge } else { object_type.type_info.default_non_paged_pool_charge.get() });
    match object_header::allocate(create_info, owner_mode, type_pointer, (name.length, name.maximum_length, name.buffer), body_size) {
        Ok(header) => {
            if output != 0 {
                out::<u64>(output).set(header + object_header::BODY_OFFSET);
            }
            STATUS_SUCCESS
        }
        Err(status) => failure(status),
    }
}

/// O diretório e o componente final do nome de um objeto a inserir:
/// relativo ao RootDirectory (um diretório do namespace) ou absoluto.
fn name_target(root: u64, name: &str, from_user_mode: bool) -> Result<(object_manager::NodeId, alloc::string::String), u32> {
    let (start, path) = if root != 0 {
        let opened = namespace::resolve(root, from_user_mode)?;
        if !opened.directory {
            // A ParseProcedure de um RootDirectory que não é diretório mora na
            // busca de nomes do namespace.
            return Err(STATUS_OBJECT_NAME_NOT_FOUND);
        }
        if name.starts_with('\\') {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        (opened.node, name)
    } else {
        let Some(path) = name.strip_prefix('\\') else { return Err(STATUS_OBJECT_PATH_SYNTAX_BAD) };
        (object_manager::ROOT, path)
    };
    let (parent, leaf) = path.rsplit_once('\\').unwrap_or(("", path));
    if leaf.is_empty() {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let directory = if parent.is_empty() { Some(start) } else { object_manager::resolve_from(parent, 0, true, false, start).0 };
    let directory = directory.filter(|&node| object_manager::node(node).is_some_and(|node| node.children.is_some() && node.mount.is_none())).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    Ok((directory, alloc::string::String::from(leaf)))
}

/// O corpo do OBJECT_DIRECTORY de um nó do namespace (0 se não tem).
fn directory_body(node: object_manager::NodeId) -> u64 {
    object_manager::node(node).and_then(|node| node.data).map_or(0, |data| if data.native_body != 0 { data.native_body } else { data.native_pointer })
}

/// O ObpInsertOrLocateNamedObject: o nome do NameInfo entra no diretório
/// (a entrada retém o objeto e o NameInfo aponta o diretório); um nome já
/// presente é o objeto existente com OBJ_OPENIF (do mesmo tipo) ou
/// STATUS_OBJECT_NAME_COLLISION.
fn insert_name(object: u64, root: u64, attributes: u32, from_user_mode: bool) -> Result<Option<u64>, u32> {
    let info = object_header::name_info(object);
    // SAFETY: NameInfo do cabeçalho do objeto.
    let name = crate::ntos::rtl::guest_strings::read_unicode_string(unsafe { ObjectHeaderNameInfo::at(info) }.name.address());
    let (directory, leaf) = name_target(root, &name, from_user_mode)?;
    let object_type = object_header::object_type_info(object).ok_or(STATUS_INVALID_PARAMETER)?;
    let case_insensitive = attributes & OBJ_CASE_INSENSITIVE != 0;
    match object_manager::insert_named(directory, &leaf, &object_type.name, Some(ObjectData::pointer(object)), case_insensitive) {
        Some(node) => {
            object_header::attach_name(object, node, directory_body(directory), &leaf);
            Ok(None)
        }
        None => {
            let existing = object_manager::resolve_from(&leaf, 0, case_insensitive, true, directory).0.and_then(object_manager::node).and_then(|node| node.data).map_or(0, |data| data.native_pointer);
            if attributes & OBJ_OPENIF != 0 && existing != 0 && object_header::object_type(existing) == Some(object_type.pointer) {
                Ok(Some(existing))
            } else {
                Err(STATUS_OBJECT_NAME_COLLISION)
            }
        }
    }
}

/// O ObpCreateHandle de um objeto novo: MAXIMUM_ALLOWED vira GENERIC_ALL e
/// os genéricos passam pelo mapeamento do tipo; o handle (ObCreateHandle)
/// entra na tabela do System (OBJ_KERNEL_HANDLE) ou do processo corrente
/// depois do nome, passando pelos callbacks de objeto do tipo. Devolve o
/// status e o handle.
fn create_handle(object: u64, desired: u32, attributes: u32, mode: u8, root: u64, named: bool) -> Result<(u32, u64), u32> {
    let object_type = object_header::object_type_info(object).ok_or(STATUS_INVALID_PARAMETER)?;
    let mut access = desired;
    if access & MAXIMUM_ALLOWED != 0 {
        access = (access & !MAXIMUM_ALLOWED) | GENERIC_ALL;
    }
    let access = crate::ntos::ob::object_access::map_generic_access(access, &object_type);
    let kernel = attributes & OBJ_KERNEL_HANDLE != 0;
    let owner = if kernel { process::get_system_process() } else { process::get_current_process() };
    let mut target = object;
    let mut status = STATUS_SUCCESS;
    if named {
        match insert_name(object, root, attributes, mode != 0) {
            Ok(None) => {}
            Ok(Some(existing)) => {
                target = existing;
                status = STATUS_OBJECT_NAME_EXISTS;
            }
            Err(status) => return Err(status),
        }
    }
    let Some(item) = open_pointer::describe(target) else { return Err(STATUS_INVALID_PARAMETER) };
    let reason = if target == object { OpenReason::Create } else { OpenReason::Open };
    let options = callbacks::PerformOptions { operation: 1, enforce: mode != 0, kernel_handle: kernel, source_process: 0, target_process: 0 };
    let outcome = callbacks::perform(&item, access, &options, &mut |granted| match open_pointer::insert_with(&item, granted, attributes & !0x0001_0000, owner, reason, mode) {
        Ok(identifier) => callbacks::Outcome { status: 0, granted: Some(granted), value: identifier, error: None },
        Err(error) => callbacks::Outcome { status: if error.status != 0 { error.status } else { 0xC000_0001 }, granted: None, value: 0, error: Some(error) },
    })
    .map_err(|error| if error.status != 0 { error.status } else { 0xC000_0001 })?;
    if outcome.status != 0 {
        if target == object {
            object_header::delete_name_check(object);
        }
        return Err(outcome.status);
    }
    let handle = if kernel { 0xFFFF_FFFF_8000_0000 | outcome.value as u64 } else { outcome.value as u64 };
    Ok((status, handle))
}

// --- ObInsertObject -----------------------------------------------------------
// NTSTATUS ObInsertObject(PVOID Object, PACCESS_STATE AccessState,
//   ACCESS_MASK DesiredAccess, ULONG ObjectPointerBias, PVOID *NewObject,
//   PHANDLE Handle)
//
// O ObInsertObjectEx (rva 0x6520b0): o ObjectCreateInfo sai do cabeçalho;
// com Handle, o handle de criação (e o nome do NameInfo, que entra no
// namespace antes dele) recebe ObjectPointerBias + 1 referências e a de
// criação é solta; sem Handle, um objeto sem nome nem segurança obrigatória
// é solto (a referência de criação some), e os demais pagam a cota e ficam
// com a referência de quem chamou, sem nome no namespace. *NewObject recebe
// o objeto (o existente, com OBJ_OPENIF e STATUS_OBJECT_NAME_EXISTS). A
// informação de criação e o descritor capturado voltam ao pool.
pub fn insert(object: u64, desired: u32, bias: u32, new_object_out: u64, handle_out: u64) -> Result<u32, KernelError> {
    let Some(header) = object_header::header(object) else { return Ok(STATUS_INVALID_PARAMETER) };
    let create_info = header.object_create_info.get();
    if header.flags.get() & object_header::FLAG_NEW_OBJECT == 0 || create_info == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let create = create_info_at(create_info);
    let attributes = create.attributes.get();
    let root = create.root_directory.get();
    let named = object_header::name_info(object) != 0;
    let mode = thread_previous_mode();
    let security_required = object_header::object_type(object).and_then(object_types::type_object).is_some_and(|object_type| object_type.type_info.bitfield_2.get() & TYPE_SECURITY_REQUIRED != 0);
    let fast = !security_required && !named && create.security_descriptor.get() == 0;
    header.object_create_info.set(0);
    let mut status = STATUS_SUCCESS;
    if handle_out != 0 {
        out::<u64>(handle_out).set(0);
        match create_handle(object, desired, attributes, mode, root, named) {
            Ok((created, handle)) => {
                let target = if created == STATUS_OBJECT_NAME_EXISTS { open_pointer::resolve(handle, false).and_then(|resolved| resolved.ok()).map_or(object, |resolved| resolved.item.pointer) } else { object };
                if let Some(item) = open_pointer::describe(target) {
                    for _ in 0..bias {
                        item.reference();
                    }
                }
                if new_object_out != 0 {
                    out::<u64>(new_object_out).set(target);
                }
                out::<u64>(handle_out).set(handle);
                status = created;
            }
            Err(failed) => status = failed,
        }
        object_header::free_create_info(create_info);
        object_header::dereference(object, false);
        return Ok(status);
    }
    if fast {
        object_header::free_create_info(create_info);
        object_header::dereference(object, false);
        return Ok(STATUS_SUCCESS);
    }
    if let Err(failed) = object_header::charge_quota_for_object(object, create.security_descriptor_charge.get()) {
        object_header::dereference(object, false);
        status = failed;
    } else if new_object_out != 0 {
        out::<u64>(new_object_out).set(object);
    }
    object_header::free_create_info(create_info);
    Ok(status)
}

// --- ObDeleteCapturedInsertInfo -------------------------------------------------
// VOID ObDeleteCapturedInsertInfo(PVOID Object) (rva 0x6eac60): num objeto
// ainda NewObject, libera a informação de criação (e o descritor capturado)
// e zera ObjectCreateInfo; o objeto continua com a referência de criação.
pub fn delete_captured_insert_info(object: u64) {
    let Some(header) = object_header::header(object) else { return };
    let create_info = header.object_create_info.get();
    if header.flags.get() & object_header::FLAG_NEW_OBJECT == 0 || create_info == 0 {
        return;
    }
    object_header::free_create_info(create_info);
    header.object_create_info.set(0);
}
