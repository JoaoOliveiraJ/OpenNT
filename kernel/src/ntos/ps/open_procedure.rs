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
//! As verificações de processo protegido (a tabela por signatário do
//! EPROCESS.Protection, vazia para o signatário 0) e de processo pico não
//! cortam nada no OpenNT: nenhum processo é protegido nem tem PicoContext.

use crate::ntos::inc::types::{Eprocess, NtStruct};

const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;

const THREAD_SUSPEND_RESUME: u32 = 0x0002;
const THREAD_SET_INFORMATION: u32 = 0x0020;
const THREAD_QUERY_INFORMATION: u32 = 0x0040;
const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
const THREAD_RESUME: u32 = 0x1000;

/// PspProcessOpen(OpenReason, AccessMode, Process, Object, *GrantedAccess):
/// o acesso final do handle de `target`, ou o NTSTATUS da recusa.
pub fn process_open(access_mode: u8, target: u64, granted: u32) -> Result<u32, u32> {
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

/// PspThreadOpen(OpenReason, AccessMode, Process, Object, *GrantedAccess).
pub fn thread_open(granted: u32) -> u32 {
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
    granted
}

/// A OpenProcedure do tipo `type_name` (só Process e Thread a têm).
pub fn apply(type_name: &str, access_mode: u8, target: u64, granted: u32) -> Result<u32, u32> {
    match type_name {
        "Process" => process_open(access_mode, target, granted),
        "Thread" => Ok(thread_open(granted)),
        _ => Ok(granted),
    }
}
