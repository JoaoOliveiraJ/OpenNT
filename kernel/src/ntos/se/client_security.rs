//! Contexto de segurança do cliente (SECURITY_CLIENT_CONTEXT): criação a
//! partir de uma thread ou de um contexto de sujeito e impersonação do
//! cliente pelo servidor, como o `se\seclient.c` do NT. Transcrito do
//! ntoskrnl 19041: SeCreateClientSecurity 0x6d6a50,
//! SeCreateClientSecurityFromSubjectContext 0x6a1230,
//! SepCreateClientSecurityEx 0x6d6e40, SeCopyClientToken 0x6daa14,
//! SeImpersonateClientEx 0x7146a0, SeGetTokenControlInformation 0x922a54.
//! A impersonação em si é o PsImpersonateClient de `ps::security`. As
//! funções que devolvem `u32` devolvem o NTSTATUS.
//!
//! Lacunas honestas: sem TrustLevelSid (SepReconcileTrustSidWithProcessProtection
//! não muda nada), sem o ramo de server silo do rastreamento estático
//! (SepCopyClientTokenAndSetSilo: o OpenNT não cria silos) e sem TOKEN_SOURCE
//! no modelo (TOKEN_CONTROL.TokenSource sai zerado).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_obpsse::{SecurityClientContext, TokenControl};
use crate::ntos::inc::types::{Ethread, SecurityImpersonationLevel, SecurityQualityOfService, SecuritySubjectContext, TokenSource};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, reference_trace};
use crate::ntos::ps::{process, security as ps_security};
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
const TOKEN_PRIMARY: u32 = 1;
const TOKEN_IMPERSONATION: u32 = 2;
const SECURITY_DELEGATION: u32 = 3;
/// SECURITY_QUALITY_OF_SERVICE.Length do contexto.
const QUALITY_OF_SERVICE_LENGTH: u32 = 12;

/// ObfReferenceObject / ObDereferenceObject do token.
fn reference(token: u64) -> Result<(), KernelError> {
    object_reference::reference_with_tag(token, reference_trace::DEFAULT_TAG, true).map(|_| ())
}

fn dereference(token: u64) -> Result<(), KernelError> {
    object_reference::dereference_with_tag(token, reference_trace::DEFAULT_TAG, true).map(|_| ())
}

/// SeGetTokenControlInformation: TokenId, AuthenticationId, ModifiedId e
/// TokenSource (ausente no modelo: zeros).
fn write_token_control(token: u64, control: &TokenControl) {
    let (id, authentication_id, modified_id) = tokens::with(token, |record| (record.id, record.authentication_id, record.modified_id)).unwrap_or((0, 0, 0));
    tokens::set_luid(&control.token_id, id);
    tokens::set_luid(&control.authentication_id, authentication_id);
    tokens::set_luid(&control.modified_id, modified_id);
    guest::write_bytes(control.token_source.address(), &[0; TokenSource::SIZE as usize]);
}

/// SepCreateClientSecurityEx (sem o ramo anônimo, que os exports desligam):
/// valida o QOS contra o nível que o cliente concedeu à thread e preenche o
/// contexto. Rastreamento dinâmico usa o próprio token (a referência do
/// chamador passa ao contexto); estático guarda uma cópia de impersonação no
/// nível do QOS (SeCopyClientToken).
fn create_ex(token: u64, qos: &SecurityQualityOfService, remote: bool, token_type: u32, thread_effective_only: bool, thread_level: u32, context: &SecurityClientContext) -> Result<u32, KernelError> {
    let mode = qos.context_tracking_mode.get();
    let level = qos.impersonation_level.get().0 as u32;
    let qos_effective_only = qos.effective_only.get();
    if mode >= 2 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if level > SECURITY_DELEGATION {
        return Ok(STATUS_BAD_IMPERSONATION_LEVEL);
    }
    let direct_effective_only = if token_type == TOKEN_IMPERSONATION {
        // O servidor não sobe acima do nível do cliente; Anonymous e
        // Identification não delegam; remoto exige Delegation.
        if (level as i32) > (thread_level as i32) || thread_level <= 1 || (remote && thread_level != SECURITY_DELEGATION) {
            return Ok(STATUS_BAD_IMPERSONATION_LEVEL);
        }
        thread_effective_only || qos_effective_only != 0
    } else {
        qos_effective_only != 0
    };
    context.direct_access_effective_only.set(direct_effective_only as u8);
    let client = if mode != 0 {
        context.directly_access_client_token.set(1);
        if remote {
            write_token_control(token, &context.client_token_control);
        }
        token
    } else {
        context.directly_access_client_token.set(0);
        match tokens::duplicate(token, level, false, TOKEN_IMPERSONATION) {
            Ok(copy) => copy,
            Err(error) if error.status != STATUS_UNSUCCESSFUL => return Ok(error.status),
            Err(error) => return Err(error),
        }
    };
    let context_qos = &context.security_qos;
    context_qos.length.set(QUALITY_OF_SERVICE_LENGTH);
    context_qos.impersonation_level.set(SecurityImpersonationLevel(level as i32));
    context_qos.context_tracking_mode.set(mode);
    context.client_token.set(client);
    context_qos.effective_only.set(qos_effective_only);
    context.server_is_remote.set(remote as u8);
    Ok(0)
}

/// Na falha ou no rastreamento estático a referência tomada pelo export
/// volta (o contexto guarda a cópia); no dinâmico ela pertence ao contexto.
fn finish(token: u64, qos: &SecurityQualityOfService, status: u32) -> Result<u32, KernelError> {
    if status != 0 || qos.context_tracking_mode.get() == 0 {
        dereference(token)?;
    }
    Ok(status)
}

/// SeCreateClientSecurity(ClientThread, Qos, RemoteSession, ClientContext):
/// o token de impersonação da thread (PsReferenceImpersonationTokenEx sem
/// AdjustedClientToken) ou o primário do seu processo (o ApcState.Process
/// para a thread corrente).
pub fn create(thread: u64, qos: &SecurityQualityOfService, remote: bool, context: &SecurityClientContext) -> Result<u32, KernelError> {
    // SAFETY: PETHREAD do chamador (ou a corrente).
    let object = unsafe { Ethread::at(thread) };
    let owner = if thread == process::get_current_thread() { object.tcb.apc_state.process.get() } else { object.tcb.process.get() };
    let (token, token_type, effective_only, level) = match thread_tokens::get(thread) {
        Some(state) => (state.token, TOKEN_IMPERSONATION, state.effective_only, state.level & 3),
        None => (process::get_primary_token(owner).ok_or_else(|| KernelError::new("SeCreateClientSecurity: process has no primary token"))?, TOKEN_PRIMARY, false, 0),
    };
    reference(token)?;
    let status = create_ex(token, qos, remote, token_type, effective_only, level, context)?;
    finish(token, qos, status)
}

/// SeCreateClientSecurityFromSubjectContext(Subject, Qos, ServerIsRemote,
/// ClientContext): ClientToken (impersonação, nível do contexto) ou
/// PrimaryToken; o EffectiveOnly da thread não entra.
pub fn create_from_subject_context(subject: &SecuritySubjectContext, qos: &SecurityQualityOfService, remote: bool, context: &SecurityClientContext) -> Result<u32, KernelError> {
    let client = subject.client_token.get();
    let token = if client != 0 { client } else { subject.primary_token.get() };
    reference(token)?;
    let token_type = if client != 0 { TOKEN_IMPERSONATION } else { TOKEN_PRIMARY };
    let status = create_ex(token, qos, remote, token_type, false, subject.impersonation_level.get().0 as u32, context)?;
    finish(token, qos, status)
}

/// SeImpersonateClientEx(ClientContext, ServerThread) (SeImpersonateClient é
/// a mesma chamada, VOID): PsImpersonateClient com CopyOnOpen TRUE, o
/// EffectiveOnly direto (rastreamento dinâmico) ou o do QOS, e o nível do
/// QOS; thread NULL = a corrente.
pub fn impersonate_client(context: &SecurityClientContext, server_thread: u64) -> Result<u32, KernelError> {
    let effective_only = if context.directly_access_client_token.get() != 0 { context.direct_access_effective_only.get() } else { context.security_qos.effective_only.get() };
    let thread = if server_thread != 0 { server_thread } else { process::get_current_thread() };
    ps_security::impersonate_client(thread, context.client_token.get(), true, effective_only != 0, context.security_qos.impersonation_level.get().0 as u32)
}
