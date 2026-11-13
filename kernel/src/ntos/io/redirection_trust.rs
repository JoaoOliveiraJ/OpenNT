//! Confiança de redirecionamento (junções/links simbólicos criados por
//! chamadores sem privilégio) — io\iomgr: IoComputeRedirectionTrustLevel
//! (RVA 0x3f0b10), IoCheckRedirectionTrustLevel (RVA 0x3f09c0) e o
//! SeTokenGetRedirectionTrustPolicy (RVA 0x3f8654) que elas leem.
//!
//! O nível é 2 para chamadas do modo kernel e para tokens administradores
//! (SeTokenIsAdmin do token de impersonação, senão do primário) e 1 para o
//! resto. A checagem só age quando o token tem os bits de política
//! TOKEN_ENFORCE_REDIRECTION_TRUST (TokenFlags bit 23) / AUDIT (bit 24), que
//! o NT liga pela mitigação de processo RedirectionTrust. Os tokens do OpenNT
//! (`se::token::tokens::Token`) não carregam TokenFlags nem essa mitigação:
//! a política é sempre (não impor, não auditar), exatamente o caso de um
//! processo Windows sem a mitigação — a checagem devolve STATUS_SUCCESS.
//! O SECURITY_SUBJECT_CONTEXT do chamador, quando ausente, é capturado e
//! liberado por `se::subject_context` (SeCapture/SeReleaseSubjectContext).

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::SecuritySubjectContext;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::{subject_context, token::information as token_information};
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
/// Devolvido pelo NT quando a política do token impõe a confiança.
pub const STATUS_REDIRECTION_POLICY_ENFORCED: u32 = 0xC000_04BC;

/// IO_REDIRECTION_TRUST_LEVEL: chamador comum / kernel ou administrador.
pub const TRUST_LEVEL_USER: u32 = 1;
pub const TRUST_LEVEL_ADMINISTRATOR: u32 = 2;

/// SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation.
const SECURITY_IMPERSONATION: i32 = 2;
/// Flags da checagem que pedem avaliação (o bit 1 sozinho não pede).
const CHECK_FLAGS_IGNORED: u32 = 2;

/// O contexto recebido ou um capturado agora (liberado por `release`).
struct Subject {
    context: &'static SecuritySubjectContext,
    captured: bool,
}

fn capture(subject: Option<&'static SecuritySubjectContext>) -> Result<Subject, KernelError> {
    if let Some(context) = subject {
        return Ok(Subject { context, captured: false });
    }
    let scratch = guest::alloc_bytes(SecuritySubjectContext::SIZE);
    subject_context::capture(scratch)?;
    // SAFETY: bloco recém-alocado com o tamanho do SECURITY_SUBJECT_CONTEXT.
    Ok(Subject { context: unsafe { SecuritySubjectContext::at(scratch) }, captured: true })
}

fn release(subject: Subject) -> Result<(), KernelError> {
    if subject.captured {
        subject_context::release(subject.context.address())?;
        guest::free_bytes(subject.context.address());
    }
    Ok(())
}

/// SeTokenGetRedirectionTrustPolicy(Token, *Enforce, *Audit): TokenFlags
/// bits 23/24. Sem TokenFlags/mitigação no OpenNT: (false, false).
fn token_redirection_policy(_token: u64) -> (bool, bool) {
    (false, false)
}

/// IoComputeRedirectionTrustLevel(Reserved, UserMode, SubjectContext, *TrustLevel).
pub fn compute_trust_level(user_mode: bool, subject_context: Option<&'static SecuritySubjectContext>, output: &Field<u32>) -> Result<u32, KernelError> {
    if !user_mode {
        output.set(TRUST_LEVEL_ADMINISTRATOR);
        return Ok(STATUS_SUCCESS);
    }
    let subject = capture(subject_context)?;
    let client = subject.context.client_token.get();
    let token = if client != 0 { client } else { subject.context.primary_token.get() };
    output.set(if token_information::is_admin(token) { TRUST_LEVEL_ADMINISTRATOR } else { TRUST_LEVEL_USER });
    release(subject)?;
    Ok(STATUS_SUCCESS)
}

/// IoCheckRedirectionTrustLevel(TrustLevel, UserMode, SubjectContext, Flags,
/// Context): a política do primário combinada (E lógico) com a do token de
/// impersonação de nível >= SecurityImpersonation. O nível só alimenta o
/// evento ETW de telemetria (EtwTimLogRedirectionTrustPolicy), que o OpenNT
/// não tem sessão para receber; só auditar também termina em sucesso.
pub fn check_trust_level(user_mode: bool, subject_context: Option<&'static SecuritySubjectContext>, flags: u32) -> Result<u32, KernelError> {
    if !user_mode || flags & !CHECK_FLAGS_IGNORED == 0 {
        return Ok(STATUS_SUCCESS);
    }
    let subject = capture(subject_context)?;
    let (primary_enforce, _primary_audit) = token_redirection_policy(subject.context.primary_token.get());
    let client = subject.context.client_token.get();
    let (client_enforce, _client_audit) = if client != 0 && subject.context.impersonation_level.get().0 >= SECURITY_IMPERSONATION {
        token_redirection_policy(client)
    } else {
        (true, true)
    };
    release(subject)?;
    Ok(if primary_enforce && client_enforce { STATUS_REDIRECTION_POLICY_ENFORCED } else { STATUS_SUCCESS })
}
