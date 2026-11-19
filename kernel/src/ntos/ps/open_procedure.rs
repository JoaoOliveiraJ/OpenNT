//! A OpenProcedure dos tipos Process e Thread (PspProcessOpen e
//! PspThreadOpen do ntoskrnl 19041, rvas 0x6078e0 e 0x607820): chamada a
//! cada handle novo (criação, abertura, duplicação), depois dos callbacks de
//! objeto, com o acesso que o handle vai receber.
//!
//! - Processo: um handle de UserMode com PROCESS_TERMINATE num processo com
//!   Flags3.DisallowUserTerminate é STATUS_ACCESS_DENIED;
//!   PROCESS_QUERY_INFORMATION, ou PROCESS_VM_OPERATION com
//!   PROCESS_VM_WRITE, implicam PROCESS_QUERY_LIMITED_INFORMATION, e
//!   PROCESS_SET_INFORMATION implica PROCESS_SET_LIMITED_INFORMATION.
//! - Thread: THREAD_QUERY_INFORMATION implica
//!   THREAD_QUERY_LIMITED_INFORMATION, THREAD_SET_INFORMATION implica
//!   THREAD_SET_LIMITED_INFORMATION e THREAD_SUSPEND_RESUME implica
//!   THREAD_RESUME.
//!
//! Antes disso, a proteção do alvo (EPROCESS.Protection, o PS_PROTECTION):
//! os direitos negados pelo signatário dele (RtlProtectedAccess, rva
//! 0x984450, DeniedProcessAccess ou DeniedThreadAccess), sem o de término
//! quando quem abre é o pai do alvo (PspIsParentProcess 0x251bf0), recusam o
//! handle com STATUS_ACCESS_DENIED quando o PsTestProtectedProcessIncompatibility
//! (0x6079d8) diz que quem abre não pode: não é o próprio alvo, o modo é
//! UserMode (PspCheckForInvalidAccessByProtection 0x607a2c), a proteção dele
//! não domina a do alvo (RtlTestProtectedAccess 0x607a5c) e a política de
//! depuração da CI não libera (SeCiCallbacks+0xC0). Quem abre é o processo
//! dono do handle (o Process do OB_OPEN_REASON). Assim o lsass sem proteção
//! recebe STATUS_ACCESS_DENIED no 0x478 do LsapOpenCaller para o
//! services.exe (WinTcb-Light) e abre com 0x1000.
//!
//! A verificação de processo pico não corta nada no OpenNT: nenhum processo
//! tem PicoContext.

use crate::ntos::inc::types::{Eprocess, Ethread, NtStruct};

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;

const THREAD_TERMINATE: u32 = 0x0001;
const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const THREAD_SET_INFORMATION: u32 = 0x0020;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const THREAD_RESUME: u32 = 0x1000;

/// RtlProtectedAccess (ntoskrnl 19041 rva 0x984450, seção PAGE): por
/// signatário do PS_PROTECTION (0 a 8), os signatários que ele domina e os
/// direitos negados em processos e threads protegidos por ele.
const PROTECTED_ACCESS: [(u32, u32, u32); 9] = [
    (0x000, 0x0_0000, 0x0_0000), // None
    (0x002, 0xF_C7FE, 0xF_E3FD), // Authenticode
    (0x004, 0xF_C7FE, 0xF_E3FD), // CodeGen
    (0x108, 0xF_C7FF, 0xF_E3FF), // Antimalware
    (0x110, 0xF_C7FF, 0xF_E3FF), // Lsa
    (0x13E, 0xF_C7FE, 0xF_E3FD), // Windows
    (0x17E, 0xF_C7FF, 0xF_E3FF), // WinTcb
    (0x1FE, 0xF_EFFF, 0xF_F7FF), // WinSystem
    (0x000, 0xF_C6FE, 0xF_E3FD), // App
];

/// O PS_PROTECTION de um EPROCESS.
fn protection(process: u64) -> u8 {
    // SAFETY: EPROCESS vivo (alvo ou dono do handle).
    unsafe { Eprocess::at(process) }.protection.level.get()
}

/// A entrada de RtlProtectedAccess do signatário (bits 4..7) de `level`.
fn signer_entry(level: u8) -> (u32, u32, u32) {
    PROTECTED_ACCESS.get((level >> 4) as usize).copied().unwrap_or((0, 0, 0))
}

/// RtlTestProtectedAccess(Source, Target) (0x607a5c): alvo sem proteção,
/// TRUE; tipo de quem abre menor que o do alvo, FALSE; senão o bit do
/// signatário do alvo no DominateMask do signatário de quem abre.
pub fn test_protected_access(source: u8, target: u8) -> bool {
    let target_type = target & 7;
    if target_type == 0 {
        return true;
    }
    if source & 7 < target_type {
        return false;
    }
    signer_entry(source).0 & (1 << (target >> 4)) != 0
}

/// PsTestProtectedProcessIncompatibility(AccessMode, Opener, Target)
/// (0x6079d8), com o PspCheckForInvalidAccessByProtection (0x607a2c): FALSE
/// (compatível) para o próprio alvo, KernelMode, proteção que domina a do
/// alvo ou a política de depuração da CI; senão TRUE.
pub fn protected_incompatible(access_mode: u8, opener: u64, target: u64) -> bool {
    if opener == target || opener == 0 || access_mode == 0 || test_protected_access(protection(opener), protection(target)) {
        return false;
    }
    !crate::ntos::se::code_integrity::process_debug_access_allowed(opener, target)
}

/// PspIsParentProcess(Opener, Target) (0x251bf0): o alvo herdou o PID de
/// quem abre e nasceu depois dele (SequenceNumber maior).
fn is_parent_process(opener: u64, target: u64) -> bool {
    // SAFETY: EPROCESS vivos.
    let (opener, target) = unsafe { (Eprocess::at(opener), Eprocess::at(target)) };
    target.inherited_from_unique_process_id.get() == opener.unique_process_id.get() && target.sequence_number.get() > opener.sequence_number.get()
}

/// Os direitos negados pelo signatário de `target`, sem o de término quando
/// `opener` é o pai dele.
fn denied_access(opener: u64, target: u64, denied: u32, terminate: u32) -> u32 {
    if opener != 0 && is_parent_process(opener, target) { denied & !terminate } else { denied }
}

/// PspProcessOpen(OpenReason, AccessMode, Process, Object, *GrantedAccess):
/// o acesso final do handle de `target` aberto para `opener` (o processo
/// dono do handle), ou o NTSTATUS da recusa.
pub fn process_open(access_mode: u8, opener: u64, target: u64, granted: u32) -> Result<u32, u32> {
    let denied = denied_access(opener, target, signer_entry(protection(target)).1, PROCESS_TERMINATE);
    if granted & denied != 0 && protected_incompatible(access_mode, opener, target) {
        return Err(STATUS_ACCESS_DENIED);
    }
    // SAFETY: EPROCESS vivo do handle sendo aberto.
    let process = unsafe { Eprocess::at(target) };
    if granted & PROCESS_TERMINATE != 0 && access_mode == 1 && process.flags3.get() & Eprocess::DISALLOW_USER_TERMINATE_MASK != 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    let mut granted = granted;
    if granted & (PROCESS_VM_OPERATION | PROCESS_VM_WRITE) == PROCESS_VM_OPERATION | PROCESS_VM_WRITE || granted & PROCESS_QUERY_INFORMATION != 0 {
        granted |= PROCESS_QUERY_LIMITED_INFORMATION;
    }
    if granted & PROCESS_SET_INFORMATION != 0 {
        granted |= PROCESS_SET_LIMITED_INFORMATION;
    }
    Ok(granted)
}

/// PspThreadOpen(OpenReason, AccessMode, Process, Object, *GrantedAccess)
/// (0x607820): a proteção do processo da thread, com o DeniedThreadAccess e
/// sem THREAD_TERMINATE para o pai, e os direitos implícitos.
pub fn thread_open(access_mode: u8, opener: u64, thread: u64, granted: u32) -> Result<u32, u32> {
    // SAFETY: ETHREAD vivo do handle sendo aberto.
    let target = unsafe { Ethread::at(thread) }.tcb.process.get();
    if target != 0 {
        let denied = denied_access(opener, target, signer_entry(protection(target)).2, THREAD_TERMINATE);
        if granted & denied != 0 && protected_incompatible(access_mode, opener, target) {
            return Err(STATUS_ACCESS_DENIED);
        }
    }
    let mut granted = granted;
    if granted & THREAD_QUERY_INFORMATION != 0 {
        granted |= THREAD_QUERY_LIMITED_INFORMATION;
    }
    if granted & THREAD_SET_INFORMATION != 0 {
        granted |= THREAD_SET_LIMITED_INFORMATION;
    }
    if granted & THREAD_SUSPEND_RESUME != 0 {
        granted |= THREAD_RESUME;
    }
    Ok(granted)
}

/// A OpenProcedure do tipo `type_name` (só Process e Thread a têm), para o
/// handle de `target` na tabela de `opener`.
pub fn apply(type_name: &str, access_mode: u8, opener: u64, target: u64, granted: u32) -> Result<u32, u32> {
    match type_name {
        "Process" => process_open(access_mode, opener, target, granted),
        "Thread" => thread_open(access_mode, opener, target, granted),
        _ => Ok(granted),
    }
}
