//! Exports Se* (Security Reference Monitor) — `system32/win32/ntoskrnl/se.js`.
//!
//! O subject context retém o token primário do processo e o token opcional
//! de impersonação da thread. As auditorias ficam num anel do kernel e saem
//! na serial (não há serviço de eventlog em modo usuário).

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::ke::clock;
use crate::ntos::ps::process;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// SECURITY_SUBJECT_CONTEXT (wdm.h x64).
mod subject_context {
    pub const CLIENT_TOKEN: u64 = 0x00;
    pub const IMPERSONATION_LEVEL: u64 = 0x08;
    pub const PRIMARY_TOKEN: u64 = 0x10;
    pub const PROCESS_AUDIT_ID: u64 = 0x18;
}

/// Evento de auditoria gravado no anel.
#[derive(Clone, Debug)]
pub struct AuditEvent {
    pub kind: &'static str,
    pub detail: String,
    pub at_ms: u64,
}

const AUDIT_RING_LIMIT: usize = 256;
static AUDIT_RING: SpinLock<VecDeque<AuditEvent>> = SpinLock::new(VecDeque::new());

/// Estado de bloqueio do adaptador e profundidade de aninhamento.
struct SubjectLock {
    locked: bool,
    depth: u32,
}

static SUBJECT_LOCK: SpinLock<SubjectLock> = SpinLock::new(SubjectLock { locked: false, depth: 0 });

/// Consulta interna (eventlog/depuração futuros): os eventos gravados.
pub fn audit_events() -> alloc::vec::Vec<AuditEvent> {
    AUDIT_RING.lock().iter().cloned().collect()
}

pub fn subject_context_locked() -> bool {
    SUBJECT_LOCK.lock().locked
}

fn record_audit_event(kind: &'static str, detail: String) {
    let line = if detail.is_empty() { format!("[se-audit] {kind}") } else { format!("[se-audit] {kind}: {detail}") };
    let mut ring = AUDIT_RING.lock();
    ring.push_back(AuditEvent { kind, detail, at_ms: clock::now_ms() });
    if ring.len() > AUDIT_RING_LIMIT {
        ring.pop_front();
    }
    drop(ring);
    debug_print!("{}", line);
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

/// Todo código aqui roda em modo kernel: o contexto kernel tem todos os
/// privilégios habilitados.
fn single_privilege_check(call: &Call) -> Result<u64, KernelError> {
    Ok((call.arg(2) as u32 == 0) as u64)
}

/// Captura o contexto da thread corrente, retendo o token primário e o
/// de impersonação.
fn capture_subject_context(call: &Call) -> Result<u64, KernelError> {
    let context = call.arg(1);
    let impersonation = thread_tokens::get(process::get_current_thread());
    let token = current_primary_token()?;
    reference_token(token)?;
    if let Some(impersonation) = &impersonation {
        reference_token(impersonation.token)?;
    }
    guest::write64(context + subject_context::CLIENT_TOKEN, impersonation.as_ref().map_or(0, |impersonation| impersonation.token));
    guest::write64(context + subject_context::PRIMARY_TOKEN, token);
    guest::write32(context + subject_context::IMPERSONATION_LEVEL, impersonation.as_ref().map_or(0, |impersonation| impersonation.level));
    guest::write64(context + subject_context::PROCESS_AUDIT_ID, process::get_current_process_id());
    Ok(0)
}

/// Devolve as referências capturadas.
fn release_subject_context(call: &Call) -> Result<u64, KernelError> {
    let context = call.arg(1);
    let primary = guest::read64(context + subject_context::PRIMARY_TOKEN);
    let client = guest::read64(context + subject_context::CLIENT_TOKEN);
    if primary != 0 {
        dereference_token(primary)?;
    }
    if client != 0 {
        dereference_token(client)?;
    }
    guest::write64(context + subject_context::PRIMARY_TOKEN, 0);
    guest::write64(context + subject_context::CLIENT_TOKEN, 0);
    Ok(0)
}

fn lock_subject_context(_: &Call) -> Result<u64, KernelError> {
    let mut lock = SUBJECT_LOCK.lock();
    if lock.depth == 0 {
        lock.locked = true;
    }
    lock.depth += 1;
    Ok(0)
}

fn unlock_subject_context(_: &Call) -> Result<u64, KernelError> {
    let mut lock = SUBJECT_LOCK.lock();
    lock.depth = lock.depth.saturating_sub(1);
    if lock.depth == 0 {
        lock.locked = false;
    }
    Ok(0)
}

/// AuthenticationId lido do campo do token (SYSTEM_LUID no token do
/// Sistema).
fn query_authentication_id_token(call: &Call) -> Result<u64, KernelError> {
    if tokens::get(call.arg(1)).is_none() {
        return Ok(signed_status(0xC000_0008));
    }
    guest::write64(call.arg(2), guest::read64(call.arg(1)));
    Ok(0)
}

/// Registra tipo, categoria e endereço; não copia o conteúdo apontado.
fn set_audit_parameter(call: &Call) -> Result<u64, KernelError> {
    record_audit_event("SetAuditParameter", format!("type={} category={} params={:#x}", call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32));
    Ok(0)
}

fn report_security_event_with_sub_category(call: &Call) -> Result<u64, KernelError> {
    record_audit_event("SecurityEvent", format!("category={}", call.arg(2) as u32));
    Ok(0)
}

/// O cng audita o resultado dos selftests FIPS por aqui.
fn audit_fips_crypto_selftests(call: &Call) -> Result<u64, KernelError> {
    record_audit_event("FipsCryptoSelftest", format!("general={} causing={} extra={:#x}", call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32));
    Ok(0)
}

pub static GROUP: Group = Group {
    name: "se",
    names: &[
        "SeSinglePrivilegeCheck",
        "SeCaptureSubjectContext",
        "SeReleaseSubjectContext",
        "SeLockSubjectContext",
        "SeUnlockSubjectContext",
        "SeQueryAuthenticationIdToken",
        "SeSetAuditParameter",
        "SeReportSecurityEventWithSubCategory",
        "SeAuditFipsCryptoSelftests",
    ],
    handlers: &[
        single_privilege_check,
        capture_subject_context,
        release_subject_context,
        lock_subject_context,
        unlock_subject_context,
        query_authentication_id_token,
        set_audit_parameter,
        report_security_event_with_sub_category,
        audit_fips_crypto_selftests,
    ],
    data_exports: &[],
};

pub mod image_verification {
    //! SeRegisterImageVerificationCallback — `ntos/se/image-verification`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::image_verification;
    use crate::rtl::KernelError;

    fn register(call: &Call) -> Result<u64, KernelError> {
        Ok(image_verification::register(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }

    pub static GROUP: Group = Group { name: "image-verification", names: &["SeRegisterImageVerificationCallback"], handlers: &[register], data_exports: &[] };
}

pub mod image_verification_remove {
    //! SeUnregisterImageVerificationCallback — `ntos/se/image-verification`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::image_verification;
    use crate::rtl::KernelError;

    fn remove(call: &Call) -> Result<u64, KernelError> {
        image_verification::remove(call.arg(1))?;
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "image-verification-remove", names: &["SeUnregisterImageVerificationCallback"], handlers: &[remove], data_exports: &[] };
}

pub mod platform_manifest {
    //! SeQuerySecureBootPlatformManifest — `system32/win32/ntoskrnl/platform-manifest.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::platform_manifest;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("platform-manifest", platform_manifest::query(call.arg(1), call.arg(2)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "platform-manifest",
        names: &["SeQuerySecureBootPlatformManifest"],
        handlers: &[query],
        data_exports: &[],
    };
}

pub mod secure_boot_policy {
    //! SeQuerySecureBootPolicyValue — `system32/win32/ntoskrnl/secure-boot-policy.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::secure_boot_policy;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("secure-boot-policy", secure_boot_policy::query(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6)))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "secure-boot-policy",
        names: &["SeQuerySecureBootPolicyValue"],
        handlers: &[query],
        data_exports: &[],
    };
}

pub mod duplicate_token {
    //! ZwDuplicateToken — `system32/win32/ntoskrnl/duplicate-token.js`.
    //!
    //! A entrada Zw usa KernelMode, inclusive numa thread com PreviousMode
    //! UserMode; EffectiveOnly vale pelo byte baixo.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::token::duplicate as duplicate_token;

    fn duplicate(call: &Call) -> Result<u64, KernelError> {
        Ok(duplicate_token::duplicate(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) & 0xFF != 0, call.arg(5) as u32, call.arg(6), 0)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "duplicate-token",
        names: &["ZwDuplicateToken"],
        handlers: &[duplicate],
        data_exports: &[],
    };
}

pub mod open_process_token {
    //! ZwOpenProcessTokenEx — `system32/win32/ntoskrnl/open-process-token.js`.
    //!
    //! A entrada Zw abre em KernelMode.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::token::open_process as open_process_token;

    fn open_process_token_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(open_process_token::open(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), 0)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "open-process-token",
        names: &["ZwOpenProcessTokenEx"],
        handlers: &[open_process_token_ex],
        data_exports: &[],
    };
}

pub mod query_token {
    //! ZwQueryInformationToken — `system32/win32/ntoskrnl/query-token.js`.
    //!
    //! Falha interna interrompe o sistema; o sinal de transferência do CONTEXT
    //! continua propagando.

    use crate::ntos::init::exports::{fatal_unless_transfer, Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::token::query as query_token;

    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(fatal_unless_transfer("query-token", query_token::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), 0))? as u64)
    }

    pub static GROUP: Group = Group {
        name: "query-token",
        names: &["ZwQueryInformationToken"],
        handlers: &[query],
        data_exports: &[],
    };
}

pub mod impersonate_anonymous {
    //! ZwImpersonateAnonymousToken — `system32/win32/ntoskrnl/impersonate-anonymous.js`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::rtl::KernelError;
    use crate::ntos::se::token::impersonate_anonymous;

    fn impersonate_anonymous_token(call: &Call) -> Result<u64, KernelError> {
        Ok(impersonate_anonymous::impersonate(call.arg(1), 0)? as u64)
    }

    pub static GROUP: Group = Group {
        name: "impersonate-anonymous",
        names: &["ZwImpersonateAnonymousToken"],
        handlers: &[impersonate_anonymous_token],
        data_exports: &[],
    };
}

pub mod token_handles {
    //! ZwOpenThreadTokenEx — `ntos/se/token-handles`; fora de PASSIVE_LEVEL o
    //! sistema para com IRQL_NOT_LESS_OR_EQUAL (0xC4, 0x2001F).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::ke::irql;
    use crate::ntos::se::token::handles as token_handles;
    use crate::rtl::KernelError;

    fn open_thread(call: &Call) -> Result<u64, KernelError> {
        if irql::get_irql() != 0 {
            crate::ntos::ke::exports::raise_bug_check(0xC4, 0x2_001F, 0, 0, 0);
        }
        Ok(token_handles::open_thread(call.arg(1), call.arg(2) as u32, call.arg(3) & 0xFF != 0, call.arg(4) as u32, call.arg(5), false)? as u64)
    }

    pub static GROUP: Group = Group { name: "token-handles", names: &["ZwOpenThreadTokenEx"], handlers: &[open_thread], data_exports: &[] };
}

pub mod locally_unique_id {
    //! ZwAllocateLocallyUniqueId: o LUID sai do contador único de LUIDs.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::se::token::tokens;
    use crate::rtl::KernelError;

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        if call.arg(1) == 0 {
            return Ok(signed_status(0xC000_0005));
        }
        let luid = tokens::allocate_luid();
        if guest::try_write32(call.arg(1), luid as u32).and_then(|_| guest::try_write32(call.arg(1) + 4, (luid >> 32) as u32)).is_err() {
            return Ok(signed_status(0xC000_0005));
        }
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "locally-unique-id", names: &["ZwAllocateLocallyUniqueId"], handlers: &[allocate], data_exports: &[] };
}

pub mod se_descriptor {
    //! Captura, validação e liberação de SECURITY_DESCRIPTOR que drivers reais
    //! de FS, armazenamento e rede importam. Reusa o `se/descriptor.rs`; a
    //! captura devolve sempre uma cópia self-relative na arena do convidado.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::se::descriptor;
    use crate::rtl::KernelError;

    const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;
    const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
    const SELF_RELATIVE: u16 = 0x8000;

    /// SeCaptureSecurityDescriptor: devolve em `*arg5` uma cópia self-relative
    /// do descritor (ou NULL se a entrada for NULL), validando antes de copiar.
    fn capture(call: &Call) -> Result<u64, KernelError> {
        let (input, output) = (call.arg(1), call.arg(5));
        if input == 0 {
            guest::write64(output, 0);
            return Ok(0);
        }
        if !descriptor::valid(input) {
            return Ok(signed_status(STATUS_INVALID_SECURITY_DESCR));
        }
        let length = descriptor::length(input) as u64;
        let captured = guest::alloc_bytes(length);
        if guest::read16(input + 2) & SELF_RELATIVE != 0 {
            for offset in 0..length {
                guest::write8(captured + offset, guest::read8(input + offset));
            }
        } else {
            let capacity = guest::alloc_bytes(4);
            guest::write32(capacity, length as u32);
            let status = descriptor::absolute_to_relative(input, captured, capacity);
            guest::free_bytes(capacity);
            if status != 0 {
                guest::free_bytes(captured);
                return Ok(signed_status(status));
            }
        }
        guest::write64(output, captured);
        Ok(0)
    }

    /// SeReleaseSecurityDescriptor: libera a cópia feita pela captura.
    fn release(call: &Call) -> Result<u64, KernelError> {
        if call.arg(1) != 0 {
            guest::free_bytes(call.arg(1));
        }
        Ok(0)
    }

    /// SeDeassignSecurity: libera `*arg1` e zera o ponteiro.
    fn deassign(call: &Call) -> Result<u64, KernelError> {
        let pointer = guest::read64(call.arg(1));
        if pointer != 0 {
            guest::free_bytes(pointer);
        }
        guest::write64(call.arg(1), 0);
        Ok(0)
    }

    /// SeValidSecurityDescriptor(Length, Sd): valida um SD self-relative.
    fn valid(call: &Call) -> Result<u64, KernelError> {
        Ok(descriptor::valid_relative(call.arg(2), call.arg(1) as u32, 0) as u64)
    }

    /// SeConvertStringSecurityDescriptorToSecurityDescriptor: sem parser SDDL
    /// nesta plataforma; devolve STATUS_NOT_IMPLEMENTED de forma honesta.
    fn convert_string(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(STATUS_NOT_IMPLEMENTED))
    }

    pub static GROUP: Group = Group {
        name: "se-descriptor",
        names: &[
            "SeCaptureSecurityDescriptor", "SeReleaseSecurityDescriptor", "SeValidSecurityDescriptor",
            "SeDeassignSecurity", "SeConvertStringSecurityDescriptorToSecurityDescriptor",
        ],
        handlers: &[capture, release, valid, deassign, convert_string],
        data_exports: &[],
    };
}
