//! Privilégios: verificação contra o token efetivo do sujeito e o conjunto
//! de privilégios usados de um ACCESS_STATE.
//!
//! Todo código aqui roda em modo kernel: o contexto kernel tem todos os
//! privilégios habilitados, e KernelMode passa direto.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::subject_context::{CLIENT_TOKEN, IMPERSONATION_LEVEL, PRIMARY_TOKEN};
use crate::ntos::se::token::tokens;

// SECURITY_IMPERSONATION_LEVEL: SecurityImpersonation.
const SECURITY_IMPERSONATION: u32 = 2;

const SE_PRIVILEGE_ENABLED: u32 = 0x02;
const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
const PRIVILEGE_SET_ALL_NECESSARY: u32 = 0x01;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

// ACCESS_STATE (0xA0): PrivilegesAllocated@0x0B, AuxData@0x48,
// Privileges (INITIAL_PRIVILEGE_SET inline, até 3)@0x50.
const AS_PRIVILEGES_ALLOCATED: u64 = 0x0B;
const AS_AUX_DATA: u64 = 0x48;
const AS_PRIVILEGES: u64 = 0x50;
const INITIAL_PRIVILEGE_COUNT: u32 = 3;
// LUID_AND_ATTRIBUTES: Luid@0 (8), Attributes@8 (4).
const LAA_STRIDE: u64 = 12;

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
    let client = guest::read64(subject_context + CLIENT_TOKEN);
    let token = if client != 0 && guest::read32(subject_context + IMPERSONATION_LEVEL) >= SECURITY_IMPERSONATION {
        client
    } else {
        guest::read64(subject_context + PRIMARY_TOKEN)
    };
    let Some(held) = tokens::with(token, |token| token.privileges.clone()) else {
        return false;
    };
    let count = guest::read32(set);
    let all_necessary = guest::read32(set + 4) & PRIVILEGE_SET_ALL_NECESSARY != 0;
    let mut held_all = true;
    let mut held_any = false;
    for index in 0..count as u64 {
        let entry = set + 8 + index * LAA_STRIDE;
        let luid = guest::read64(entry);
        if held.iter().any(|privilege| privilege.id == luid && privilege.attributes & SE_PRIVILEGE_ENABLED != 0) {
            held_any = true;
            guest::write32(entry + 8, guest::read32(entry + 8) | SE_PRIVILEGE_USED_FOR_ACCESS);
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
    let current = guest::read32(access_state + AS_PRIVILEGES);
    let appended = guest::read32(privileges);
    if appended == 0 {
        return 0;
    }
    let total = current + appended;
    let copy_laa = |destination: u64, source: u64| {
        for byte in 0..LAA_STRIDE {
            guest::write8(destination + byte, guest::read8(source + byte));
        }
    };
    if total <= INITIAL_PRIVILEGE_COUNT {
        for index in 0..appended as u64 {
            copy_laa(
                access_state + AS_PRIVILEGES + 8 + (current as u64 + index) * LAA_STRIDE,
                privileges + 8 + index * LAA_STRIDE,
            );
        }
        guest::write32(access_state + AS_PRIVILEGES, total);
        return 0;
    }
    // Transbordo: PRIVILEGE_SET agrupado (cabeçalho de 8 + total LAA).
    let pooled = guest::alloc_bytes(8 + total as u64 * LAA_STRIDE);
    if pooled == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write32(pooled, total);
    guest::write32(pooled + 4, guest::read32(access_state + AS_PRIVILEGES + 4));
    for index in 0..current as u64 {
        copy_laa(pooled + 8 + index * LAA_STRIDE, access_state + AS_PRIVILEGES + 8 + index * LAA_STRIDE);
    }
    for index in 0..appended as u64 {
        copy_laa(pooled + 8 + (current as u64 + index) * LAA_STRIDE, privileges + 8 + index * LAA_STRIDE);
    }
    guest::write8(access_state + AS_PRIVILEGES_ALLOCATED, 1);
    let aux = guest::read64(access_state + AS_AUX_DATA);
    if aux != 0 {
        let previous = guest::read64(aux);
        if previous != 0 && previous != access_state + AS_PRIVILEGES && guest::owns_allocation(previous) {
            guest::free_bytes(previous);
        }
        guest::write64(aux, pooled);
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
