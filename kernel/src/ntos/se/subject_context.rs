//! Contexto de segurança do sujeito (SECURITY_SUBJECT_CONTEXT): captura,
//! liberação e bloqueio.
//!
//! O subject context retém o token primário do processo e o token opcional
//! de impersonação da thread; a liberação devolve essas referências.

use crate::ntos::inc::types::{NtStruct, SecurityImpersonationLevel, SecuritySubjectContext};
use crate::ntos::ps::process;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};

fn context_at(context: u64) -> &'static SecuritySubjectContext {
    // SAFETY: PSECURITY_SUBJECT_CONTEXT do chamador (Se{Capture,Release}SubjectContext).
    unsafe { SecuritySubjectContext::at(context) }
}

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
    let context = context_at(context);
    context.client_token.set(impersonation.as_ref().map_or(0, |impersonation| impersonation.token));
    context.primary_token.set(token);
    context.impersonation_level.set(SecurityImpersonationLevel(impersonation.as_ref().map_or(0, |impersonation| impersonation.level) as i32));
    context.process_audit_id.set(process::get_current_process_id());
    Ok(())
}

/// SeReleaseSubjectContext: devolve as referências capturadas.
pub fn release(context: u64) -> Result<(), KernelError> {
    let context = context_at(context);
    let primary = context.primary_token.get();
    let client = context.client_token.get();
    if primary != 0 {
        dereference_token(primary)?;
    }
    if client != 0 {
        dereference_token(client)?;
    }
    context.primary_token.set(0);
    context.client_token.set(0);
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

/// SeCaptureSubjectContextEx(Thread, Process, SubjectContext) (ntoskrnl 19041,
/// 0x6d0a20): ProcessAuditId do processo dado, o token de impersonação
/// referenciado (e o nível) quando a thread tem ActiveImpersonationInfo, e o
/// primário do processo referenciado. Sem impersonação o NT não escreve
/// ImpersonationLevel (os chamadores internos zeram o contexto antes);
/// Thread NULL captura só o processo.
pub fn capture_ex(thread: u64, process: u64, subject: &SecuritySubjectContext) -> Result<(), KernelError> {
    // SAFETY: PEPROCESS do chamador, vivo durante a captura.
    let owner = unsafe { crate::ntos::inc::types::Eprocess::at(process) };
    subject.process_audit_id.set(owner.unique_process_id.get());
    let impersonation = if thread != 0 { thread_tokens::get(thread) } else { None };
    let client = match impersonation {
        Some(state) => {
            reference_token(state.token)?;
            subject.impersonation_level.set(SecurityImpersonationLevel((state.level & 3) as i32));
            state.token
        }
        None => 0,
    };
    subject.client_token.set(client);
    let primary = process::get_primary_token(process).unwrap_or(0);
    if primary != 0 {
        reference_token(primary)?;
    }
    subject.primary_token.set(primary);
    Ok(())
}
