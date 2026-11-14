//! Segurança dos objetos — ObSetSecurityObjectByPointer, ObGetObjectSecurity,
//! ObReleaseObjectSecurity e ObCheckObjectAccess.
//!
//! O descritor escrito por ObSetSecurityObjectByPointer fica numa tabela
//! lateral por objeto (o slot do OBJECT_HEADER no NT); ObGetObjectSecurity o
//! devolve sem alocar. A checagem de acesso usa a política capturada pelo
//! dono do corpo e o mapeamento genérico do tipo.

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::{AccessState, Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::type_procedures::{self, SecurityOperation};
use crate::ntos::ob::{object_access, object_create, object_header, object_types, open_pointer};
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Saída escalar (`PVOID*`, `PHANDLE`, `PULONG`...) de um chamador de kernel.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<T>::at(address) }
}

/// Descritor escrito por ObSetSecurityObjectByPointer, por objeto.
static SECURITY_DESCRIPTORS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// O descritor do objeto: o do OBJECT_HEADER (sem as referências do
/// EX_FAST_REF) para os objetos com cabeçalho, senão o da tabela lateral.
pub fn security_descriptor(object: u64) -> Option<u64> {
    if object_header::is_object(object) {
        let descriptor = header_descriptor(object);
        return (descriptor != 0).then_some(descriptor);
    }
    SECURITY_DESCRIPTORS.lock().get(&object).copied()
}

/// ObSetSecurityObjectByPointer: o descritor fica na tabela lateral (o
/// slot do OBJECT_HEADER no NT).
pub fn set_security_object_by_pointer(object: u64, descriptor: u64) -> u32 {
    if object == 0 {
        return STATUS_INVALID_HANDLE;
    }
    SECURITY_DESCRIPTORS.lock().insert(object, descriptor);
    STATUS_SUCCESS
}

// --- ObCheckObjectAccess --------------------------------------------------
// BOOLEAN ObCheckObjectAccess(PVOID Object, PSECURITY_SUBJECT_CONTEXT,
//   BOOLEAN LockHeld, KPROCESSOR_MODE Mode, PACCESS_MASK GrantedAccess,
//   PNTSTATUS Status). GrantedAccess is in/out (desired on entry, granted
//   on exit). Wraps object_access::check against the type generic-mapping.
pub fn check_object_access(object: u64, mode: u8, granted_out: u64, status_out: u64) -> bool {
    let desired = if granted_out != 0 { out::<u32>(granted_out).get() } else { 0 };
    let (object_type, policy) = if let Some(described) = open_pointer::describe(object) {
        (described.object_type.clone(), described.owner.security(object))
    } else if let Some(object_type) = object_types::bound(object).or_else(|| object_create::created_type(object)) {
        (object_type, object_access::capture(None))
    } else {
        if status_out != 0 {
            out::<u32>(status_out).set(STATUS_INVALID_HANDLE);
        }
        return false;
    };
    match object_access::check(&policy, object_access::subject(), desired, &object_type, mode == 0) {
        Ok(granted) => {
            if granted_out != 0 {
                out::<u32>(granted_out).set(granted);
            }
            if status_out != 0 {
                out::<u32>(status_out).set(STATUS_SUCCESS);
            }
            true
        }
        Err(status) => {
            if granted_out != 0 {
                out::<u32>(granted_out).set(0);
            }
            if status_out != 0 {
                out::<u32>(status_out).set(status);
            }
            false
        }
    }
}

// --- ObGetObjectSecurity --------------------------------------------------
// NTSTATUS ObGetObjectSecurity(PVOID Object, PSECURITY_DESCRIPTOR *Sd,
//   PBOOLEAN MemoryAllocated). Returns the side-table SD; nothing is
//   allocated, so MemoryAllocated is FALSE (pairs with ObReleaseObjectSecurity).
pub fn get_object_security(object: u64, sd_out: u64, allocated_out: u64) -> u32 {
    if let Some(object_type) = object_header::object_type(object) {
        return get_header_security(object, object_type, sd_out, allocated_out);
    }
    let sd = security_descriptor(object).unwrap_or(0);
    if sd_out != 0 {
        out::<u64>(sd_out).set(sd);
    }
    if allocated_out != 0 {
        out::<u8>(allocated_out).set(0);
    }
    STATUS_SUCCESS
}

// --- ObReleaseObjectSecurity ----------------------------------------------
// VOID ObReleaseObjectSecurity(PSECURITY_DESCRIPTOR Sd, BOOLEAN MemoryAllocated).
/// Com MemoryAllocated a cópia volta ao pool; sem ela, um descritor do
/// cache perde a referência que o ObGetObjectSecurity tomou.
pub fn release_object_security(sd: u64, allocated: bool) {
    if allocated && sd != 0 {
        let _ = crate::ntos::ex::pool_allocation::free(sd, 0);
    } else if sd != 0 && cached_descriptor_state(sd).is_some() {
        let _ = dereference_security_descriptor(sd, 1);
    }
}

// ---- Cache de descritores de segurança (como no NT) ------------------------
// ObsSecurityDescriptorCache, conferido contra o ntoskrnl 19041:
// ObLogSecurityDescriptor 0x6d8b90, ObpCreateCacheEntry 0x6d8e84,
// ObReferenceSecurityDescriptor 0x697550, ObDereferenceSecurityDescriptor
// 0x6d8380. Cada entrada é um bloco do convidado com o cabeçalho
// SECURITY_DESCRIPTOR_HEADER seguido da cópia do SD, que é o ponteiro
// devolvido. Descritores iguais (mesmo tamanho e bytes) compartilham a
// entrada. Os caminhos de criação de objetos do OpenNT ainda não passam por
// aqui.

const SD_CACHE_STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// ObpCreateCacheEntry aloca Size + 0x28 (ULONG, recusado se transbordar).
const SD_CACHE_ALLOCATION_SLACK: u32 = 0x28;

/// SECURITY_DESCRIPTOR_HEADER (interno do Ob; layout de ObpCreateCacheEntry):
/// Link, RefCount (lock xadd), FullHash e Size; o SD começa logo depois.
#[repr(C)]
struct SecurityDescriptorHeader {
    link: Field<u64>,
    ref_count: Field<u64>,
    full_hash: Field<u64>,
    size: Field<u32>,
    _reserved_1c: crate::ntos::inc::field::Reserved<4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SecurityDescriptorHeader {}

const _: () = {
    assert!(core::mem::size_of::<SecurityDescriptorHeader>() == 0x20);
    assert!(core::mem::offset_of!(SecurityDescriptorHeader, ref_count) == 0x08);
    assert!(core::mem::offset_of!(SecurityDescriptorHeader, full_hash) == 0x10);
    assert!(core::mem::offset_of!(SecurityDescriptorHeader, size) == 0x18);
};

struct SecurityDescriptorCache {
    /// Cabeçalhos por FullHash (o NT ordena cada balde pelo hash).
    by_hash: BTreeMap<u64, alloc::vec::Vec<u64>>,
    /// Cabeçalhos vivos, para recusar ponteiros que não vieram do cache.
    live: alloc::collections::BTreeSet<u64>,
}

static SECURITY_DESCRIPTOR_CACHE: SpinLock<SecurityDescriptorCache> = SpinLock::new(SecurityDescriptorCache { by_hash: BTreeMap::new(), live: alloc::collections::BTreeSet::new() });

fn cache_header(header: u64) -> &'static SecurityDescriptorHeader {
    // SAFETY: cabeçalho vivo do cache (conferido em `live` pelo chamador).
    unsafe { SecurityDescriptorHeader::at(header) }
}

/// Cabeçalho de um SD devolvido pelo cache.
fn header_of(descriptor: u64) -> u64 {
    descriptor.wrapping_sub(SecurityDescriptorHeader::SIZE)
}

/// FullHash do ObLogSecurityDescriptor sobre os bytes do SD: XOR de um QWORD
/// a cada 16 bytes da parte alinhada a 8, com rol 3 depois de cada passo.
pub fn security_descriptor_hash(bytes: &[u8]) -> u64 {
    let limit = bytes.len() & !7;
    (0..limit).step_by(16).fold(0u64, |hash, offset| {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[offset..offset + 8]);
        (hash ^ u64::from_le_bytes(word)).rotate_left(3)
    })
}

/// FAST_FAIL_INVALID_REFERENCE_COUNT (int 0x29, código 0xE).
fn invalid_reference_count(operation: &str) -> crate::rtl::KernelError {
    crate::rtl::KernelError::new(alloc::format!("{operation}: FAST_FAIL_INVALID_REFERENCE_COUNT"))
}

/// Estado de uma entrada viva (RefCount, FullHash, Size), para os autotestes.
pub fn cached_descriptor_state(descriptor: u64) -> Option<(u64, u64, u32)> {
    let header = header_of(descriptor);
    if !SECURITY_DESCRIPTOR_CACHE.lock().live.contains(&header) {
        return None;
    }
    let entry = cache_header(header);
    Some((entry.ref_count.get(), entry.full_hash.get(), entry.size.get()))
}

/// ObLogSecurityDescriptor(InputSD, OutputSD*, RefBias): devolve a entrada
/// existente com RefCount += RefBias, ou cria uma com RefCount = RefBias.
/// Devolve o NTSTATUS.
pub fn log_security_descriptor(input: u64, output: &Field<u64>, bias: u32) -> Result<u32, crate::rtl::KernelError> {
    let length = crate::ntos::se::descriptor::length(input);
    let bytes = guest::read_bytes(input, length as usize);
    let hash = security_descriptor_hash(&bytes);
    let mut cache = SECURITY_DESCRIPTOR_CACHE.lock();
    let existing = cache.by_hash.get(&hash).and_then(|headers| headers.iter().copied().find(|&header| cache_header(header).size.get() == length && guest::read_bytes(header + SecurityDescriptorHeader::SIZE, length as usize) == bytes));
    if let Some(header) = existing {
        let previous = cache_header(header).ref_count.atomic().fetch_add(bias as u64, core::sync::atomic::Ordering::SeqCst);
        if previous as i64 <= 0 {
            return Err(invalid_reference_count("ObLogSecurityDescriptor"));
        }
        output.set(header + SecurityDescriptorHeader::SIZE);
        return Ok(0);
    }
    let Some(allocation) = length.checked_add(SD_CACHE_ALLOCATION_SLACK) else { return Ok(SD_CACHE_STATUS_INSUFFICIENT_RESOURCES) };
    let header = guest::alloc_bytes(allocation as u64);
    if header == 0 {
        return Ok(SD_CACHE_STATUS_INSUFFICIENT_RESOURCES);
    }
    let entry = cache_header(header);
    entry.link.set(0);
    entry.ref_count.set(bias as u64);
    entry.full_hash.set(hash);
    entry.size.set(length);
    guest::write_bytes(header + SecurityDescriptorHeader::SIZE, &bytes);
    cache.by_hash.entry(hash).or_default().push(header);
    cache.live.insert(header);
    output.set(header + SecurityDescriptorHeader::SIZE);
    Ok(0)
}

/// ObReferenceSecurityDescriptor(SD, Count): lock xadd no RefCount; um valor
/// anterior não positivo é falha rápida.
pub fn reference_security_descriptor(descriptor: u64, count: u32) -> Result<(), crate::rtl::KernelError> {
    let header = header_of(descriptor);
    if !SECURITY_DESCRIPTOR_CACHE.lock().live.contains(&header) {
        return Err(crate::rtl::KernelError::new("ObReferenceSecurityDescriptor: descriptor not from the cache"));
    }
    let previous = cache_header(header).ref_count.atomic().fetch_add(count as u64, core::sync::atomic::Ordering::SeqCst);
    if previous as i64 <= 0 {
        return Err(invalid_reference_count("ObReferenceSecurityDescriptor"));
    }
    Ok(())
}

/// ObDereferenceSecurityDescriptor(SD, Count): sob o lock do cache (o do
/// balde no NT), no zero a entrada sai do balde e é liberada; abaixo de zero é
/// falha rápida.
pub fn dereference_security_descriptor(descriptor: u64, count: u32) -> Result<(), crate::rtl::KernelError> {
    let header = header_of(descriptor);
    let mut cache = SECURITY_DESCRIPTOR_CACHE.lock();
    if !cache.live.contains(&header) {
        return Err(crate::rtl::KernelError::new("ObDereferenceSecurityDescriptor: descriptor not from the cache"));
    }
    let entry = cache_header(header);
    let remaining = entry.ref_count.atomic().fetch_sub(count as u64, core::sync::atomic::Ordering::SeqCst).wrapping_sub(count as u64) as i64;
    if remaining < 0 {
        return Err(invalid_reference_count("ObDereferenceSecurityDescriptor"));
    }
    if remaining == 0 {
        let hash = entry.full_hash.get();
        if let Some(headers) = cache.by_hash.get_mut(&hash) {
            headers.retain(|&candidate| candidate != header);
            if headers.is_empty() {
                cache.by_hash.remove(&hash);
            }
        }
        cache.live.remove(&header);
        drop(cache);
        guest::free_bytes(header);
    }
    Ok(())
}

// ---- NtSetSecurityObject em modo kernel (ZwSetSecurityObject) ---------------
//
// ntoskrnl 19041 NtSetSecurityObject rva 0x67b860:
//   SecurityDescriptor NULL                         -> STATUS_ACCESS_VIOLATION
//   o acesso pedido ao handle vem de SeSetSecurityAccessMask (WRITE_OWNER para
//   OWNER/GROUP/LABEL, WRITE_DAC para DACL, ACCESS_SYSTEM_SECURITY para SACL) —
//   em KernelMode não é comparado ao concedido;
//   o descritor é capturado (SeCaptureSecurityDescriptor, cópia self-relative);
//   OWNER_SECURITY_INFORMATION sem Owner        -> STATUS_INVALID_OWNER
//   GROUP_SECURITY_INFORMATION sem Group        -> STATUS_INVALID_PRIMARY_GROUP
//   ObSetSecurityObjectByPointer chama o SecurityProcedure do tipo: para
//   arquivos o IopGetSetSecurityObject envia IRP_MJ_SET_SECURITY ao dispositivo
//   do arquivo (Parameters.SetSecurity { SecurityInformation, SecurityDescriptor });
//   os demais tipos trocam o descritor do objeto.
// No OpenNT os tipos não-arquivo usam a tabela lateral do
// ObSetSecurityObjectByPointer acima (o slot do OBJECT_HEADER). Diferença
// honesta: chaves de registro e objetos com política própria continuam
// respondendo às consultas pela política do dono (o registro do OpenNT não
// regrava o descritor da chave).

const SET_SECURITY_STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const SET_SECURITY_STATUS_INVALID_OWNER: u32 = 0xC000_005A;
const SET_SECURITY_STATUS_INVALID_PRIMARY_GROUP: u32 = 0xC000_005B;
const SET_SECURITY_STATUS_PENDING: u32 = 0x103;
const OWNER_SECURITY_INFORMATION: u32 = 1;
const GROUP_SECURITY_INFORMATION: u32 = 2;
const IRP_MJ_SET_SECURITY: u8 = 0x15;

/// IRP_MJ_SET_SECURITY síncrono ao dispositivo do arquivo.
fn set_file_security(file: u64, information: u32, captured: u64) -> Result<u32, crate::rtl::KernelError> {
    use crate::ntos::inc::types::{IoStackLocation, IoStatusBlock, Irp, Kevent};
    let device = crate::ntos::io::file::information::related_device(file)?;
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
    let packet = crate::ntos::io::io_manager::build_synchronous_fsd_request(IRP_MJ_SET_SECURITY, device, 0, 0, 0, event, io_status);
    let mut status = 0xC000_009A;
    if packet != 0 {
        // SAFETY: IRP recém-montado pelo I/O Manager.
        let irp = unsafe { Irp::at(packet) };
        // SAFETY: a posição do primeiro driver, logo abaixo de CurrentStackLocation.
        let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
        location.parameters.set_security.security_information.set(information);
        location.parameters.set_security.security_descriptor.set(captured);
        location.file_object.set(file);
        irp.tail.overlay.original_file_object.set(file);
        status = crate::ntos::io::io_manager::iof_call_driver(device, packet) as u32;
        if status == SET_SECURITY_STATUS_PENDING {
            crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
            // SAFETY: IO_STATUS_BLOCK alocado acima.
            status = unsafe { IoStatusBlock::at(io_status) }.status.get() as u32;
        }
        guest::free_bytes(packet);
    }
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    Ok(status)
}

/// O acesso que o handle precisa para alterar as partes pedidas
/// (SeSetSecurityAccessMask): dono, grupo e rótulo pedem WRITE_OWNER, a DACL
/// WRITE_DAC e a SACL ACCESS_SYSTEM_SECURITY.
fn set_security_access_mask(information: u32) -> u32 {
    let mut mask = 0;
    if information & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | 0x10) != 0 {
        mask |= 0x8_0000;
    }
    if information & 4 != 0 {
        mask |= 0x4_0000;
    }
    if information & 8 != 0 {
        mask |= 0x100_0000;
    }
    mask
}

/// NtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor) de
/// modo usuário: o handle da tabela do processo (ou o handle nativo de um
/// objeto do namespace) com o acesso que as partes pedem, o descritor
/// capturado em UserMode e aplicado como no ZwSetSecurityObject (um arquivo
/// recebe o IRP_MJ_SET_SECURITY no driver dele).
pub fn set_security_object_from_user(handle: u64, information: u32, descriptor: u64) -> Result<u32, crate::rtl::KernelError> {
    const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
    if descriptor == 0 {
        return Ok(SET_SECURITY_STATUS_ACCESS_VIOLATION);
    }
    let desired = set_security_access_mask(information);
    // NtCurrentProcess/NtCurrentThread: o corpo corrente, com o acesso total
    // que os pseudo-handles têm.
    let (pointer, type_name, access) = if handle == u64::MAX {
        (crate::ntos::ps::process::get_current_process(), object_types::process_type().name, 0x1F_FFFF)
    } else if handle == u64::MAX - 1 {
        (crate::ntos::ps::process::get_current_thread(), object_types::thread_type().name, 0x1F_FFFF)
    } else if let Some(entry) = crate::ntos::ps::user::state::get_user_handle(handle) {
        let Some(body) = entry.object.native_body() else { return Ok(STATUS_OBJECT_TYPE_MISMATCH) };
        (body.pointer, body.type_name, entry.access())
    } else {
        match crate::ntos::ob::open_pointer::resolve(handle, true) {
            Some(Ok(resolved)) => (resolved.item.pointer, resolved.item.object_type.name.clone(), resolved.access),
            Some(Err(status)) => return Ok(status),
            None => return Ok(STATUS_INVALID_HANDLE),
        }
    };
    if access & desired != desired {
        return Ok(STATUS_ACCESS_DENIED);
    }
    let output = guest::alloc_bytes(8);
    let captured_status = crate::ntos::init::exports::invoke_handler("SeCaptureSecurityDescriptor", &[descriptor, 1, 1, 1, output])? as u32;
    // SAFETY: PSECURITY_DESCRIPTOR* alocado acima.
    let captured = unsafe { Field::<u64>::at(output) }.get();
    guest::free_bytes(output);
    if captured_status != 0 {
        return Ok(captured_status);
    }
    let control = crate::ntos::se::descriptor::control(captured);
    if information & OWNER_SECURITY_INFORMATION != 0 && crate::ntos::se::descriptor::component(captured, control, 0) == 0 {
        guest::free_bytes(captured);
        return Ok(SET_SECURITY_STATUS_INVALID_OWNER);
    }
    if information & GROUP_SECURITY_INFORMATION != 0 && crate::ntos::se::descriptor::component(captured, control, 1) == 0 {
        guest::free_bytes(captured);
        return Ok(SET_SECURITY_STATUS_INVALID_PRIMARY_GROUP);
    }
    if type_name == object_types::file_type().name {
        let status = set_file_security(pointer, information, captured);
        guest::free_bytes(captured);
        return status;
    }
    Ok(set_security_object_by_pointer(pointer, captured))
}

/// ZwSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor).
pub fn set_security_object(handle: u64, information: u32, descriptor: u64) -> Result<u32, crate::rtl::KernelError> {
    if descriptor == 0 {
        return Ok(SET_SECURITY_STATUS_ACCESS_VIOLATION);
    }
    let mut reference = match crate::ntos::ob::handles::security::reference_kernel_handle(handle)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, crate::rtl::KernelError> {
        let output = guest::alloc_bytes(8);
        let captured_status = crate::ntos::init::exports::invoke_handler("SeCaptureSecurityDescriptor", &[descriptor, 0, 1, 1, output])? as u32;
        // SAFETY: PSECURITY_DESCRIPTOR* alocado acima.
        let captured = unsafe { Field::<u64>::at(output) }.get();
        guest::free_bytes(output);
        if captured_status != 0 {
            return Ok(captured_status);
        }
        let control = crate::ntos::se::descriptor::control(captured);
        if information & OWNER_SECURITY_INFORMATION != 0 && crate::ntos::se::descriptor::component(captured, control, 0) == 0 {
            guest::free_bytes(captured);
            return Ok(SET_SECURITY_STATUS_INVALID_OWNER);
        }
        if information & GROUP_SECURITY_INFORMATION != 0 && crate::ntos::se::descriptor::component(captured, control, 1) == 0 {
            guest::free_bytes(captured);
            return Ok(SET_SECURITY_STATUS_INVALID_PRIMARY_GROUP);
        }
        if reference.object_type.name == object_types::file_type().name {
            let status = set_file_security(reference.pointer, information, captured);
            guest::free_bytes(captured);
            return status;
        }
        // O descritor capturado passa a ser o do objeto.
        Ok(set_security_object_by_pointer(reference.pointer, captured))
    })();
    reference.release()?;
    result
}

// ---- Atribuição e troca do descritor de um objeto ---------------------------

/// O mapeamento genérico de um tipo, como o GENERIC_MAPPING que o NT passa
/// por ponteiro (bloco do kernel; o chamador libera).
fn mapping_block(object_type: &object_types::ObjectType) -> u64 {
    let block = guest::alloc_bytes(16);
    for (index, &value) in object_type.mapping.iter().enumerate() {
        out::<u32>(block + index as u64 * 4).set(value);
    }
    block
}

/// O tipo de `object` (o vínculo registrado, a descrição do dono ou o
/// ObCreateObject ainda não inserido).
fn type_of(object: u64) -> Option<object_types::ObjectType> {
    object_types::bound(object).or_else(|| open_pointer::describe(object).map(|described| described.object_type)).or_else(|| object_create::created_type(object))
}

// --- ObAssignSecurity -----------------------------------------------------
// NTSTATUS ObAssignSecurity(PACCESS_STATE AccessState, PSECURITY_DESCRIPTOR
//   ParentDescriptor, PVOID Object, POBJECT_TYPE ObjectType): o
// ObpAssignSecurity — o SeAssignSecurity do descritor pedido no AccessState
// sobre o do pai (contêiner se o tipo é Directory), com o contexto do
// sujeito capturado e o mapeamento do tipo, e o resultado vira o descritor
// do objeto (a tabela lateral, o slot do OBJECT_HEADER no NT).
pub fn assign_security(access_state: &AccessState, parent: u64, object: u64, object_type: u64) -> u32 {
    if object_header::is_object(object) {
        return assign_object_security(object, parent, access_state.security_descriptor.get(), access_state.subject_security_context.address(), 0);
    }
    let Some(object_type) = object_types::find(object_type) else { return STATUS_INVALID_PARAMETER };
    let mapping = mapping_block(&object_type);
    let slot = guest::alloc_bytes(8);
    let container = object_type.name == "Directory";
    let status = crate::ntos::se::assign::assign(parent, access_state.security_descriptor.get(), slot, container, 0, access_state.subject_security_context.address(), mapping);
    if status == STATUS_SUCCESS {
        set_security_object_by_pointer(object, out::<u64>(slot).get());
    }
    guest::free_bytes(slot);
    guest::free_bytes(mapping);
    status
}

// --- ObSetSecurityDescriptorInfo ------------------------------------------
// NTSTATUS ObSetSecurityDescriptorInfo(PVOID Object, PSECURITY_INFORMATION,
//   PSECURITY_DESCRIPTOR SecurityDescriptor, PSECURITY_DESCRIPTOR
//   *ObjectsSecurityDescriptor, POOL_TYPE, PGENERIC_MAPPING): como no NT, o
// descritor corrente é o do objeto (não o que o chamador passa); o
// SeSetSecurityDescriptorInfo mescla os componentes pedidos e o novo
// descritor vira o do objeto e vai para *ObjectsSecurityDescriptor.
pub fn set_security_descriptor_info(object: u64, information: u64, descriptor: u64, objects_descriptor: u64, mapping: u64) -> u32 {
    let current = security_descriptor(object).unwrap_or_else(|| out::<u64>(objects_descriptor).get());
    let slot = guest::alloc_bytes(8);
    out::<u64>(slot).set(current);
    let status = crate::ntos::se::set_security::set_security_descriptor_info(information, descriptor, slot, 0, mapping);
    if status == STATUS_SUCCESS {
        let new = out::<u64>(slot).get();
        match object_header::header(object) {
            // Num objeto com cabeçalho a mescla vira uma entrada do cache no
            // EX_FAST_REF do OBJECT_HEADER.
            Some(header) => {
                let logged = log_with_fast_ref(new);
                guest::free_bytes(new);
                match logged {
                    Ok(cached) => {
                        replace_fast_ref(&header.security_descriptor, cached);
                        out::<u64>(objects_descriptor).set(cached);
                    }
                    Err(failed) => {
                        guest::free_bytes(slot);
                        return failed;
                    }
                }
            }
            None => {
                set_security_object_by_pointer(object, new);
                out::<u64>(objects_descriptor).set(new);
            }
        }
    }
    guest::free_bytes(slot);
    status
}

// --- ObCheckCreateObjectAccess --------------------------------------------
// BOOLEAN ObCheckCreateObjectAccess(PVOID DirectoryObject, ACCESS_MASK
//   CreateAccess, PACCESS_STATE, PUNICODE_STRING ComponentName, BOOLEAN
//   LockHeld, KPROCESSOR_MODE AccessMode, PNTSTATUS AccessStatus): o acesso
// de criação no diretório pela política dele e o sujeito corrente; em
// KernelMode tudo é concedido. FALSE com o status da recusa.
pub fn check_create_object_access(directory: u64, create_access: u32, mode: u8, status_out: u64) -> bool {
    let object_type = type_of(directory).unwrap_or_else(object_types::directory_type);
    let policy = open_pointer::describe(directory).map_or_else(|| object_access::capture(None), |described| described.owner.security(directory));
    let result = object_access::check(&policy, object_access::subject(), create_access, &object_type, mode == 0);
    if status_out != 0 {
        out::<u32>(status_out).set(result.err().unwrap_or(STATUS_SUCCESS));
    }
    result.is_ok()
}

// ---- SeDefaultObjectMethod e o descritor no OBJECT_HEADER --------------------
//
// O SecurityProcedure padrão (o ObCreateObjectTypeEx o põe nos tipos que não
// trazem um), como no ntoskrnl 19041 (rva 0x6d8930), para os objetos com
// OBJECT_HEADER: o descritor do objeto é uma entrada do cache
// (ObLogSecurityDescriptor) guardada em OBJECT_HEADER.SecurityDescriptor como
// EX_FAST_REF (os 4 bits baixos são referências pré-cobradas).
//   AssignSecurityDescriptor: registra no cache com 16 referências, guarda
//     entrada | 0xF no cabeçalho e libera o descritor recebido;
//   DeleteSecurityDescriptor: zera *ObjectsSecurityDescriptor e devolve as
//     referências (bits + 1);
//   QuerySecurityDescriptor: o SeQuerySecurityDescriptorInfo sobre o
//     descritor do objeto;
//   SetSecurityDescriptor: o ObSetSecurityDescriptorInfo sobre
//     *ObjectsSecurityDescriptor (a mescla vira uma entrada nova do cache).

const FAST_REF_MASK: u64 = 0xF;
const STATUS_NO_SECURITY_ON_OBJECT: u32 = 0xC000_00D7;

/// O descritor (entrada do cache) de um objeto com OBJECT_HEADER, ou 0.
pub fn header_descriptor(object: u64) -> u64 {
    crate::ntos::ob::object_header::header(object).map_or(0, |header| header.security_descriptor.get() & !FAST_REF_MASK)
}

/// Troca o EX_FAST_REF `slot` por `cached` (com 15 referências pré-cobradas)
/// e devolve as do anterior.
fn replace_fast_ref(slot: &Field<u64>, cached: u64) {
    let old = slot.get();
    slot.set(if cached != 0 { cached | FAST_REF_MASK } else { 0 });
    if old & !FAST_REF_MASK != 0 {
        let _ = dereference_security_descriptor(old & !FAST_REF_MASK, (old & FAST_REF_MASK) as u32 + 1);
    }
}

/// O descritor registrado no cache com as 16 referências do EX_FAST_REF.
fn log_with_fast_ref(descriptor: u64) -> Result<u64, u32> {
    let output = guest::alloc_bytes(8);
    if output == 0 {
        return Err(0xC000_009A);
    }
    let status = log_security_descriptor(descriptor, out::<u64>(output), 16).unwrap_or(0xC000_0001);
    let cached = out::<u64>(output).get();
    guest::free_bytes(output);
    if status != STATUS_SUCCESS {
        return Err(status);
    }
    Ok(cached)
}

/// SeDefaultObjectMethod(Object, OperationCode, SecurityInformation,
/// SecurityDescriptor, CapturedLength, ObjectsSecurityDescriptor, PoolType,
/// GenericMapping, Mode).
#[allow(clippy::too_many_arguments)]
pub extern "win64" fn default_object_method(object: u64, operation: u32, information: u64, descriptor: u64, captured_length: u64, objects_descriptor: u64, _pool_type: u32, mapping: u64, _mode: u8) -> u32 {
    match operation {
        // SetSecurityDescriptor: ObSetSecurityDescriptorInfo.
        0 => {
            let slot = out::<u64>(objects_descriptor);
            let current = slot.get() & !FAST_REF_MASK;
            if current == 0 {
                return STATUS_NO_SECURITY_ON_OBJECT;
            }
            let working = guest::alloc_bytes(8);
            out::<u64>(working).set(current);
            let status = crate::ntos::se::set_security::set_security_descriptor_info(information, descriptor, working, 0, mapping);
            let merged = out::<u64>(working).get();
            guest::free_bytes(working);
            if status != STATUS_SUCCESS {
                return status;
            }
            let logged = log_with_fast_ref(merged);
            guest::free_bytes(merged);
            match logged {
                Ok(cached) => {
                    replace_fast_ref(slot, cached);
                    STATUS_SUCCESS
                }
                Err(status) => status,
            }
        }
        // QuerySecurityDescriptor: SeQuerySecurityDescriptorInfo.
        1 => {
            let cell = guest::alloc_bytes(8);
            out::<u64>(cell).set(out::<u64>(objects_descriptor).get() & !FAST_REF_MASK);
            let status = crate::ntos::se::query_descriptor::query_info(information, descriptor, captured_length, cell);
            guest::free_bytes(cell);
            status
        }
        // DeleteSecurityDescriptor.
        2 => {
            replace_fast_ref(out::<u64>(objects_descriptor), 0);
            STATUS_SUCCESS
        }
        // AssignSecurityDescriptor: o descritor novo vai para o cabeçalho.
        3 => {
            let Some(header) = crate::ntos::ob::object_header::header(object) else { return STATUS_INVALID_PARAMETER };
            if descriptor == 0 {
                header.security_descriptor.set(0);
                return STATUS_SUCCESS;
            }
            match log_with_fast_ref(descriptor) {
                Ok(cached) => {
                    let _ = crate::ntos::ex::pool_allocation::free(descriptor, 0);
                    header.security_descriptor.set(cached | FAST_REF_MASK);
                    STATUS_SUCCESS
                }
                Err(status) => status,
            }
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// O endereço do SeDefaultObjectMethod (o SecurityProcedure padrão).
pub fn default_object_method_address() -> u64 {
    default_object_method as extern "win64" fn(u64, u32, u64, u64, u64, u64, u32, u64, u8) -> u32 as usize as u64
}

/// ObGetObjectSecurity de um objeto com cabeçalho (o ObpGetObjectSecurity,
/// rva 0x6d84e0): com o SeDefaultObjectMethod, o descritor do cabeçalho com
/// uma referência a mais e MemoryAllocated FALSE; com outro
/// SecurityProcedure, QuerySecurityDescriptor num buffer do pool paginável
/// (refeito com o tamanho pedido em STATUS_BUFFER_TOO_SMALL) e
/// MemoryAllocated TRUE.
fn get_header_security(object: u64, object_type: u64, sd_out: u64, allocated_out: u64) -> u32 {
    let procedure = object_types::type_object(object_type).map_or(0, |native| native.type_info.security_procedure.get());
    if procedure == default_object_method_address() || procedure == 0 {
        let descriptor = header_descriptor(object);
        if descriptor != 0 {
            let _ = reference_security_descriptor(descriptor, 1);
        }
        out::<u64>(sd_out).set(descriptor);
        out::<u8>(allocated_out).set(0);
        return STATUS_SUCCESS;
    }
    let Some(header) = object_header::header(object) else { return STATUS_INVALID_PARAMETER };
    let information = guest::alloc_bytes(8);
    out::<u32>(information).set(0x1BF);
    let length = information + 4;
    let mut size = 0x100u32;
    let status = loop {
        let buffer = crate::ntos::ex::pool_allocation::allocate_tagged(1, size as u64, 0x7153_624F).unwrap_or(0);
        if buffer == 0 {
            break 0xC000_009A;
        }
        out::<u32>(length).set(size);
        let status = type_procedures::security(object_type, object, SecurityOperation::Query, information, buffer, length, header.security_descriptor.address(), 1, 0);
        if status == 0xC000_0023 && out::<u32>(length).get() > size {
            let _ = crate::ntos::ex::pool_allocation::free(buffer, 0);
            size = out::<u32>(length).get();
            continue;
        }
        if status as i32 >= 0 {
            out::<u64>(sd_out).set(buffer);
            out::<u8>(allocated_out).set(1);
        } else {
            let _ = crate::ntos::ex::pool_allocation::free(buffer, 0);
            out::<u64>(sd_out).set(0);
            out::<u8>(allocated_out).set(0);
        }
        break status;
    };
    guest::free_bytes(information);
    status
}

// --- ObpAssignSecurity ----------------------------------------------------------
// Como no ntoskrnl 19041 (rva 0x6dbcbc): SeAssignSecurity do descritor
// pedido sobre o do pai (contêiner num Directory), com o contexto do sujeito
// (o dado, ou o capturado da thread) e o mapeamento do tipo, e o
// SecurityProcedure recebe AssignSecurityDescriptor com o descritor novo; na
// falha o descritor é desfeito (SeDeassignSecurity).
pub fn assign_object_security(object: u64, parent: u64, explicit: u64, subject_context: u64, mode: u8) -> u32 {
    use crate::ntos::inc::types::SecuritySubjectContext;
    let Some(object_type) = object_header::object_type(object) else { return STATUS_INVALID_PARAMETER };
    let Some(info) = object_types::find(object_type) else { return STATUS_INVALID_PARAMETER };
    let captured = if subject_context == 0 {
        let context = guest::alloc_bytes(SecuritySubjectContext::SIZE);
        let _ = crate::ntos::init::exports::invoke_handler("SeCaptureSubjectContext", &[context]);
        context
    } else {
        0
    };
    let context = if subject_context != 0 { subject_context } else { captured };
    let mapping = mapping_block(&info);
    let slot = guest::alloc_bytes(8);
    let mut status = crate::ntos::se::assign::assign(parent, explicit, slot, info.name == "Directory", 0, context, mapping);
    if status == STATUS_SUCCESS {
        status = type_procedures::security(object_type, object, SecurityOperation::Assign, 0, out::<u64>(slot).get(), 0, 0, 1, mode);
        if status as i32 >= 0 {
            status = STATUS_SUCCESS;
        } else {
            crate::ntos::se::assign::deassign(slot);
        }
    }
    guest::free_bytes(slot);
    guest::free_bytes(mapping);
    if captured != 0 {
        let _ = crate::ntos::init::exports::invoke_handler("SeReleaseSubjectContext", &[captured]);
        guest::free_bytes(captured);
    }
    status
}
