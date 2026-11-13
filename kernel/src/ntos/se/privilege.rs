//! Privilégios: verificação contra o token efetivo do sujeito e o conjunto
//! de privilégios usados de um ACCESS_STATE.
//!
//! Todo código aqui roda em modo kernel: o contexto kernel tem todos os
//! privilégios habilitados, e KernelMode passa direto.

use crate::ntos::inc::types::{AccessState, AuxAccessData, LuidAndAttributes, NtStruct, PrivilegeSet, SecurityImpersonationLevel, SecuritySubjectContext};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::token::tokens;

const SECURITY_IMPERSONATION: SecurityImpersonationLevel = SecurityImpersonationLevel::SECURITY_IMPERSONATION;

const SE_PRIVILEGE_ENABLED: u32 = 0x02;
const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
const PRIVILEGE_SET_ALL_NECESSARY: u32 = 0x01;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

// ACCESS_STATE: Privileges guarda um INITIAL_PRIVILEGE_SET inline (até 3).
const INITIAL_PRIVILEGE_COUNT: u32 = 3;

/// Os `count` LUID_AND_ATTRIBUTES de um PRIVILEGE_SET (vetor declarado com
/// um elemento no NT).
fn entries(set: &PrivilegeSet, count: usize) -> &'static [LuidAndAttributes] {
    laa(set.privilege[0].address(), count)
}

fn laa(first: u64, count: usize) -> &'static [LuidAndAttributes] {
    // SAFETY: o conjunto tem `count` entradas a partir de Privilege[0].
    unsafe { LuidAndAttributes::array_at(first, count) }
}

fn privilege_set(address: u64) -> &'static PrivilegeSet {
    // SAFETY: PPRIVILEGE_SET vivo do chamador (ou alocado aqui).
    unsafe { PrivilegeSet::at(address) }
}

fn copy_entry(destination: &LuidAndAttributes, source: &LuidAndAttributes) {
    destination.luid.low_part.set(source.luid.low_part.get());
    destination.luid.high_part.set(source.luid.high_part.get());
    destination.attributes.set(source.attributes.get());
}

/// SeSinglePrivilegeCheck: o contexto kernel tem todos os privilégios; só
/// o PreviousMode KernelMode (0) passa.
pub fn single_privilege_check(previous_mode: u32) -> bool {
    previous_mode == 0
}

/// SePrivilegeCheck(RequiredPrivileges, Subj, Mode): KernelMode → TRUE
/// imediato; senão testa cada LUID do PRIVILEGE_SET contra os privilégios
/// habilitados do token efetivo, marcando os usados.
pub fn privilege_check(set: u64, subject_context: u64, mode: u32) -> bool {
    if mode == 0 {
        return true;
    }
    // SAFETY: PSECURITY_SUBJECT_CONTEXT do chamador de SePrivilegeCheck.
    let context = unsafe { SecuritySubjectContext::at(subject_context) };
    let client = context.client_token.get();
    let token = if client != 0 && context.impersonation_level.get().0 >= SECURITY_IMPERSONATION.0 {
        client
    } else {
        context.primary_token.get()
    };
    let Some(held) = tokens::with(token, |token| token.privileges.clone()) else {
        return false;
    };
    let set = privilege_set(set);
    let count = set.privilege_count.get();
    let all_necessary = set.control.get() & PRIVILEGE_SET_ALL_NECESSARY != 0;
    let mut held_all = true;
    let mut held_any = false;
    for entry in entries(set, count as usize) {
        let luid = entry.luid.low_part.get() as u64 | (entry.luid.high_part.get() as u32 as u64) << 32;
        if held.iter().any(|privilege| privilege.id == luid && privilege.attributes & SE_PRIVILEGE_ENABLED != 0) {
            held_any = true;
            // Conjunto do chamador: o NT também faz `Attributes |= ...` simples.
            entry.attributes.set(entry.attributes.get() | SE_PRIVILEGE_USED_FOR_ACCESS);
        } else {
            held_all = false;
        }
    }
    if all_necessary { held_all } else { held_any }
}

/// SeAppendPrivileges(AccessState, Privileges): acrescenta o PRIVILEGE_SET
/// ao conjunto inline (INITIAL_PRIVILEGE_SET@0x50); no transbordo (> 3)
/// aloca um PRIVILEGE_SET agrupado, copia inline + novos, marca
/// PrivilegesAllocated e o liga em AuxData->PrivilegesUsed quando há AuxData
/// (convenção do SeCreateAccessState). O caminho inline é o dos chamadores
/// comuns (ntfs/http/ks/npfs), que logo liberam. Devolve o NTSTATUS.
pub fn append_privileges(access_state: u64, privileges: u64) -> u32 {
    // SAFETY: PACCESS_STATE do chamador de SeAppendPrivileges.
    let state = unsafe { AccessState::at(access_state) };
    let inline = &state.privileges.initial_privilege_set;
    let current = inline.privilege_count.get();
    let source = privilege_set(privileges);
    let appended = source.privilege_count.get();
    if appended == 0 {
        return 0;
    }
    let total = current + appended;
    let incoming = entries(source, appended as usize);
    if total <= INITIAL_PRIVILEGE_COUNT {
        for (destination, entry) in laa(inline.privilege[0].address(), total as usize)[current as usize..].iter().zip(incoming) {
            copy_entry(destination, entry);
        }
        inline.privilege_count.set(total);
        return 0;
    }
    // Transbordo: PRIVILEGE_SET agrupado (cabeçalho de 8 + total LAA).
    let pooled = guest::alloc_bytes(8 + total as u64 * LuidAndAttributes::SIZE);
    if pooled == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let grouped = privilege_set(pooled);
    grouped.privilege_count.set(total);
    grouped.control.set(inline.control.get());
    let slots = entries(grouped, total as usize);
    for (destination, entry) in slots.iter().zip(laa(inline.privilege[0].address(), current as usize).iter().chain(incoming)) {
        copy_entry(destination, entry);
    }
    state.privileges_allocated.set(1);
    let aux = state.aux_data.get();
    if aux != 0 {
        // SAFETY: AuxData aponta para o AUX_ACCESS_DATA do mesmo ACCESS_STATE.
        let aux = unsafe { AuxAccessData::at(aux) };
        let previous = aux.privileges_used.get();
        if previous != 0 && previous != inline.address() && guest::owns_allocation(previous) {
            guest::free_bytes(previous);
        }
        aux.privileges_used.set(pooled);
    }
    0
}

/// SeFreePrivileges(Privileges) = ExFreePool: libera só um PRIVILEGE_SET que
/// o OpenNT alocou (ignora o conjunto inline do ACCESS_STATE).
pub fn free_privileges(privileges: u64) {
    if privileges != 0 && guest::owns_allocation(privileges) {
        guest::free_bytes(privileges);
    }
}
