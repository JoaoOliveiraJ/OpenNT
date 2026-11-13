//! Contexto de segurança do sujeito (SECURITY_SUBJECT_CONTEXT): captura,
//! liberação e bloqueio, como o `se\subject.c` do NT.
//!
//! O subject context retém o token primário do processo e o token opcional
//! de impersonação da thread; a liberação devolve essas referências.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};

// SECURITY_SUBJECT_CONTEXT (wdm.h x64, 0x20 bytes).
pub const CLIENT_TOKEN: u64 = 0x00;
pub const IMPERSONATION_LEVEL: u64 = 0x08;
pub const PRIMARY_TOKEN: u64 = 0x10;
pub const PROCESS_AUDIT_ID: u64 = 0x18;

/// Estado de bloqueio do adaptador e profundidade de aninhamento.
struct SubjectLock {
    locked: bool,
    depth: u32,
}

static SUBJECT_LOCK: SpinLock<SubjectLock> = SpinLock::new(SubjectLock { locked: false, depth: 0 });

/// O subject context está bloqueado (SeLockSubjectContext pendente)?
pub fn is_locked() -> bool {
    SUBJECT_LOCK.lock().locked
}

fn current_primary_token() -> Result<u64, KernelError> {
    process::get_primary_token(process::get_current_process()).ok_or_else(|| KernelError::new("SeCaptureSubjectContext: process has no primary token"))
}

fn reference_token(pointer: u64) -> Result<(), KernelError> {
    if tokens::get(pointer).is_none() {
        return Err(KernelError::new("Referencing an invalid token"));
    }
    tokens::retain(pointer)?;
    Ok(())
}

fn dereference_token(pointer: u64) -> Result<(), KernelError> {
    if tokens::get(pointer).is_none() {
        return Err(KernelError::new("Dereferencing an invalid token"));
    }
    tokens::release(pointer)?;
    Ok(())
}

/// SeCaptureSubjectContext: captura o contexto da thread corrente em
/// `context`, retendo o token primário e o de impersonação.
pub fn capture(context: u64) -> Result<(), KernelError> {
    let impersonation = thread_tokens::get(process::get_current_thread());
    let token = current_primary_token()?;
    reference_token(token)?;
    if let Some(impersonation) = &impersonation {
        reference_token(impersonation.token)?;
    }
    guest::write64(context + CLIENT_TOKEN, impersonation.as_ref().map_or(0, |impersonation| impersonation.token));
    guest::write64(context + PRIMARY_TOKEN, token);
    guest::write32(context + IMPERSONATION_LEVEL, impersonation.as_ref().map_or(0, |impersonation| impersonation.level));
    guest::write64(context + PROCESS_AUDIT_ID, process::get_current_process_id());
    Ok(())
}

/// SeReleaseSubjectContext: devolve as referências capturadas.
pub fn release(context: u64) -> Result<(), KernelError> {
    let primary = guest::read64(context + PRIMARY_TOKEN);
    let client = guest::read64(context + CLIENT_TOKEN);
    if primary != 0 {
        dereference_token(primary)?;
    }
    if client != 0 {
        dereference_token(client)?;
    }
    guest::write64(context + PRIMARY_TOKEN, 0);
    guest::write64(context + CLIENT_TOKEN, 0);
    Ok(())
}

/// SeLockSubjectContext: bloqueio aninhado.
pub fn lock() {
    let mut lock = SUBJECT_LOCK.lock();
    if lock.depth == 0 {
        lock.locked = true;
    }
    lock.depth += 1;
}

/// SeUnlockSubjectContext: desfaz um nível; o último desbloqueia.
pub fn unlock() {
    let mut lock = SUBJECT_LOCK.lock();
    lock.depth = lock.depth.saturating_sub(1);
    if lock.depth == 0 {
        lock.locked = false;
    }
}
