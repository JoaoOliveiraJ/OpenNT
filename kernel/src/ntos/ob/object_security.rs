//! Segurança dos objetos — ObSetSecurityObjectByPointer, ObGetObjectSecurity,
//! ObReleaseObjectSecurity e ObCheckObjectAccess, como o `obse.c` do NT.
//!
//! O descritor escrito por ObSetSecurityObjectByPointer fica numa tabela
//! lateral por objeto (o slot do OBJECT_HEADER no NT); ObGetObjectSecurity o
//! devolve sem alocar. A checagem de acesso usa a política capturada pelo
//! dono do corpo e o mapeamento genérico do tipo.

use alloc::collections::BTreeMap;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_access, object_create, object_types, open_pointer};
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

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
    let desired = if granted_out != 0 { guest::read32(granted_out) } else { 0 };
    let (object_type, policy) = if let Some(described) = open_pointer::describe(object) {
        (described.object_type.clone(), described.owner.security(object))
    } else if let Some(object_type) = object_types::bound(object).or_else(|| object_create::created_type(object)) {
        (object_type, object_access::capture(None))
    } else {
        if status_out != 0 {
            guest::write32(status_out, STATUS_INVALID_HANDLE);
        }
        return false;
    };
    match object_access::check(&policy, object_access::subject(), desired, &object_type, mode == 0) {
        Ok(granted) => {
            if granted_out != 0 {
                guest::write32(granted_out, granted);
            }
            if status_out != 0 {
                guest::write32(status_out, STATUS_SUCCESS);
            }
            true
        }
        Err(status) => {
            if granted_out != 0 {
                guest::write32(granted_out, 0);
            }
            if status_out != 0 {
                guest::write32(status_out, status);
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
        guest::write64(sd_out, sd);
    }
    if allocated_out != 0 {
        guest::write8(allocated_out, 0);
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
