//! ACCESS_STATE + AUX_ACCESS_DATA: criação a partir do contexto do sujeito e
//! liberação, como o par SeCreateAccessState/SeDeleteAccessState do NT.
//! Conferido contra o ntoskrnl 19041: SeCreateAccessState 0x6da590,
//! SeCreateAccessStateEx 0x6da5e0, SepCreateAccessStateFromSubjectContext
//! 0x345810, SeDeleteAccessState 0x5dc900 / SepDeleteAccessState 0x345670.
//!
//! O contexto do sujeito é o SeCaptureSubjectContextEx de `subject_context`;
//! o mapeamento genérico é o RtlMapGenericMask de `rtl::security`; o
//! OperationID vem do contador de LUIDs dos tokens (o ExpLuid do NT).
//! Lacuna honesta: TOKEN_IS_FILTERED (0x800) não existe no modelo de token,
//! então Flags só recebe TOKEN_HAS_TRAVERSE_PRIVILEGE e TOKEN_IS_RESTRICTED.

use core::mem::size_of;

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{AccessState, AuxAccessData, GenericMapping};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::security as rtl_security;
use crate::ntos::se::{assign, subject_context};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const GENERIC_MASK: u32 = 0xF000_0000;
const SE_CHANGE_NOTIFY_PRIVILEGE: u64 = 23;
const SE_PRIVILEGE_ENABLED: u32 = 0x2;
const TOKEN_HAS_TRAVERSE_PRIVILEGE: u32 = 0x01;
const TOKEN_IS_RESTRICTED: u32 = 0x10;

/// TokenFlags & (TOKEN_IS_FILTERED | TOKEN_IS_RESTRICTED), mais
/// TOKEN_HAS_TRAVERSE_PRIVILEGE com SeChangeNotifyPrivilege habilitado.
fn access_flags(token: u64) -> u32 {
    tokens::with(token, |record| {
        let traverse = record.privileges.iter().any(|privilege| privilege.id == SE_CHANGE_NOTIFY_PRIVILEGE && privilege.attributes & SE_PRIVILEGE_ENABLED != 0);
        let restricted = !record.restricted_sids.is_empty() || record.write_restricted;
        (if traverse { TOKEN_HAS_TRAVERSE_PRIVILEGE } else { 0 }) | (if restricted { TOKEN_IS_RESTRICTED } else { 0 })
    })
    .unwrap_or(0)
}

/// SeCreateAccessStateEx(Thread, Process, AccessState, AuxData,
/// DesiredAccess, GenericMapping) (SeCreateAccessState passa a thread
/// corrente e o seu ApcState.Process). Zera os dois blocos, liga o AuxData,
/// captura o sujeito, mapeia os bits genéricos (só com mapeamento) e grava
/// Remaining/Original, PrivilegesUsed inline, OperationID e a cópia do
/// GENERIC_MAPPING. Devolve o NTSTATUS (sempre sucesso no NT).
pub fn create(thread: u64, process: u64, access_state: &AccessState, aux: &AuxAccessData, desired: u32, mapping: Option<&GenericMapping>) -> Result<u32, KernelError> {
    guest::write_bytes(access_state.address(), &[0; size_of::<AccessState>()]);
    guest::write_bytes(aux.address(), &[0; size_of::<AuxAccessData>()]);
    access_state.aux_data.set(aux.address());
    // O NT captura numa cópia local zerada e copia os 32 bytes: capturar
    // direto no estado (já zerado) dá o mesmo conteúdo.
    let subject = &access_state.subject_security_context;
    subject_context::capture_ex(thread, process, subject)?;
    let client = subject.client_token.get();
    access_state.flags.set(access_flags(if client != 0 { client } else { subject.primary_token.get() }));
    access_state.remaining_desired_access.set(desired);
    if let Some(mapping) = mapping.filter(|_| desired & GENERIC_MASK != 0) {
        rtl_security::map_generic_mask(access_state.remaining_desired_access.address(), mapping.address());
    }
    access_state.original_desired_access.set(access_state.remaining_desired_access.get());
    aux.privileges_used.set(access_state.privileges.address());
    tokens::set_luid(&access_state.operation_id, tokens::allocate_luid());
    if let Some(mapping) = mapping {
        let copy = &aux.generic_mapping;
        copy.generic_read.set(mapping.generic_read.get());
        copy.generic_write.set(mapping.generic_write.get());
        copy.generic_execute.set(mapping.generic_execute.get());
        copy.generic_all.set(mapping.generic_all.get());
    }
    Ok(0)
}

/// SeDeleteAccessState: o conjunto de privilégios alocado (ExFreePool), os
/// nomes capturados, o NewSecurityDescriptor (SeDeassignSecurity), os
/// descritores existente/pai pelo DeRefSecurityDescriptor do chamador (com o
/// SDLock) e, por fim, o contexto do sujeito (SeReleaseSubjectContext).
pub fn delete(access_state: &AccessState) -> Result<(), KernelError> {
    let aux_address = access_state.aux_data.get();
    // SAFETY: AuxData ligado por SeCreateAccessState (ou NULL).
    let aux = (aux_address != 0).then(|| unsafe { AuxAccessData::at(aux_address) });
    if access_state.privileges_allocated.get() != 0 {
        if let Some(aux) = aux {
            pool_allocation::free(aux.privileges_used.get(), 0)?;
        }
    }
    for buffer in [access_state.object_name.buffer.get(), access_state.object_type_name.buffer.get()] {
        if buffer != 0 {
            pool_allocation::free(buffer, 0)?;
        }
    }
    if let Some(aux) = aux {
        if aux.new_security_descriptor.get() != 0 {
            assign::deassign(aux.new_security_descriptor.address());
        }
        let (dereference, lock) = (aux.de_ref_security_descriptor.get(), aux.sd_lock.get());
        if dereference != 0 && lock != 0 {
            for descriptor in [aux.existing_security_descriptor.get(), aux.parent_security_descriptor.get()] {
                if descriptor != 0 {
                    native_call::call(dereference, &[lock, descriptor]);
                }
            }
        }
    }
    subject_context::release(access_state.subject_security_context.address())
}
