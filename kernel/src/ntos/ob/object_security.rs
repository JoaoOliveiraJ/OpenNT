//! Segurança dos objetos — ObSetSecurityObjectByPointer, ObGetObjectSecurity,
//! ObReleaseObjectSecurity e ObCheckObjectAccess.
//!
//! O descritor escrito por ObSetSecurityObjectByPointer fica numa tabela
//! lateral por objeto (o slot do OBJECT_HEADER no NT); ObGetObjectSecurity o
//! devolve sem alocar. A checagem de acesso usa a política capturada pelo
//! dono do corpo e o mapeamento genérico do tipo.

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_access, object_create, object_types, open_pointer};
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// Saída escalar (`PVOID*`, `PHANDLE`, `PULONG`...) de um chamador de kernel.
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída fornecido por um chamador de kernel.
    unsafe { Field::<T>::at(address) }
}

/// Descritor escrito por ObSetSecurityObjectByPointer, por objeto.
static SECURITY_DESCRIPTORS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

pub fn security_descriptor(object: u64) -> Option<u64> {
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
pub fn release_object_security(sd: u64, allocated: bool) {
    if allocated && sd != 0 {
        guest::free_bytes(sd);
    }
}

// ---- Cache de descritores de segurança (o `obsdata.c` do NT) ---------------
// ObsSecurityDescriptorCache, transcrito do ntoskrnl 19041:
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
