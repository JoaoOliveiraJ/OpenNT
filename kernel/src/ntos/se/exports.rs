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

pub mod se_token_info {
    //! SeQueryInformationToken e acessores de token — `system32/ntos/se/*`.
    //!
    //! `SeQueryInformationToken` é a forma *alocadora* (ExAllocatePool): serializa
    //! TOKEN_USER/GROUPS/PRIVILEGES/OWNER/PRIMARY_GROUP/STATISTICS a partir do
    //! registro mantido em `token/tokens.rs` e devolve o ponteiro em `*arg3` (o
    //! chamador libera com ExFreePool). Os campos vêm do side-table via
    //! `tokens::with`/`tokens::get`, e não dos offsets nativos 0xC0/0xC4/0xC8.

    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::se::model::sid;
    use crate::ntos::se::security_attributes;
    use crate::ntos::se::token::statistics;
    use crate::ntos::se::token::tokens::{self, Token};
    use crate::rtl::KernelError;

    const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    /// SE_GROUP_ENABLED.
    const SE_GROUP_ENABLED: u32 = 0x4;
    /// TOKEN_TYPE: 1 = primário, 2 = impersonação.
    const TOKEN_IMPERSONATION: u32 = 2;
    /// SecurityImpersonation (mínimo para um token de impersonação ser admin).
    const SECURITY_IMPERSONATION: u32 = 2;

    // ---- SeQueryInformationToken: produtores que serializam o side-table -----

    /// TOKEN_USER = SID_AND_ATTRIBUTES (Sid@0, Attributes@8, 16 bytes) + corpo
    /// do SID logo após; o ponteiro aponta para esse corpo.
    fn encode_token_user(record: &Token, base: u64) -> Vec<u8> {
        let sid = &record.user;
        let mut bytes = vec![0u8; 16 + sid.len()];
        bytes[0..8].copy_from_slice(&(base + 16).to_le_bytes());
        bytes[8..12].copy_from_slice(&record.user_attributes.to_le_bytes());
        bytes[16..16 + sid.len()].copy_from_slice(sid);
        bytes
    }

    /// TOKEN_GROUPS = GroupCount@0 (+pad) e o array SID_AND_ATTRIBUTES@8; os
    /// corpos dos SIDs ficam depois do array, com ponteiros absolutos.
    fn encode_token_groups(record: &Token, base: u64) -> Vec<u8> {
        let count = record.groups.len();
        let mut sids_at = 8 + count * 16;
        let total = sids_at + record.groups.iter().map(|group| group.sid.len()).sum::<usize>();
        let mut bytes = vec![0u8; total];
        bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        for (index, group) in record.groups.iter().enumerate() {
            let entry = 8 + index * 16;
            bytes[entry..entry + 8].copy_from_slice(&(base + sids_at as u64).to_le_bytes());
            bytes[entry + 8..entry + 12].copy_from_slice(&group.attributes.to_le_bytes());
            bytes[sids_at..sids_at + group.sid.len()].copy_from_slice(&group.sid);
            sids_at += group.sid.len();
        }
        bytes
    }

    /// TOKEN_PRIVILEGES = PrivilegeCount@0 e o array LUID_AND_ATTRIBUTES@4
    /// (Luid 8 + Attributes 4, stride 12).
    fn encode_token_privileges(record: &Token) -> Vec<u8> {
        let count = record.privileges.len();
        let mut bytes = vec![0u8; 4 + count * 12];
        bytes[0..4].copy_from_slice(&(count as u32).to_le_bytes());
        for (index, privilege) in record.privileges.iter().enumerate() {
            let entry = 4 + index * 12;
            bytes[entry..entry + 8].copy_from_slice(&privilege.id.to_le_bytes());
            bytes[entry + 8..entry + 12].copy_from_slice(&privilege.attributes.to_le_bytes());
        }
        bytes
    }

    /// TOKEN_OWNER / TOKEN_PRIMARY_GROUP: ponteiro@0 para o corpo do SID em @8.
    fn encode_sid_struct(sid: &[u8], base: u64) -> Vec<u8> {
        let mut bytes = vec![0u8; 8 + sid.len()];
        bytes[0..8].copy_from_slice(&(base + 8).to_le_bytes());
        bytes[8..8 + sid.len()].copy_from_slice(sid);
        bytes
    }

    /// SeQueryInformationToken(Token, Class, *TokenInformation): aloca a
    /// estrutura da classe e devolve o ponteiro em `*arg3`. Classes comuns
    /// implementadas; as demais devolvem STATUS_INVALID_INFO_CLASS.
    fn query_information(call: &Call) -> Result<u64, KernelError> {
        let (token, class, output) = (call.arg(1), call.arg(2) as u32, call.arg(3));
        let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        };
        // Comprimento primeiro: a alocação precede os ponteiros absolutos.
        let length = match class {
            1 => 16 + record.user.len(),
            2 => 8 + record.groups.len() * 16 + record.groups.iter().map(|group| group.sid.len()).sum::<usize>(),
            3 => 4 + record.privileges.len() * 12,
            4 => 8 + record.owner.len(),
            5 => 8 + record.primary_group.len(),
            10 => 56,
            _ => return Ok(signed_status(STATUS_INVALID_INFO_CLASS)),
        };
        let base = guest::alloc_bytes(length as u64);
        if base == 0 {
            return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
        }
        let bytes = match class {
            1 => encode_token_user(&record, base),
            2 => encode_token_groups(&record, base),
            3 => encode_token_privileges(&record),
            4 => encode_sid_struct(&record.owner, base),
            5 => encode_sid_struct(&record.primary_group, base),
            10 => match statistics::encode(token) {
                Ok(statistics) => statistics.to_vec(),
                Err(error) => {
                    guest::free_bytes(base);
                    return Err(error);
                }
            },
            _ => unreachable!(),
        };
        guest::write_bytes(base, &bytes);
        guest::write64(output, base);
        Ok(0)
    }

    // ---- Acessores de campo (via side-table, não via offset nativo) ----------

    /// SeTokenType = TOKEN_TYPE (1 primário, 2 impersonação) do registro.
    fn token_type(call: &Call) -> Result<u64, KernelError> {
        Ok(tokens::with(call.arg(1), |token| token.kind as u64).unwrap_or(0))
    }

    /// SeTokenImpersonationLevel: o nível guardado no registro.
    fn token_impersonation_level(call: &Call) -> Result<u64, KernelError> {
        Ok(tokens::with(call.arg(1), |token| token.impersonation_level as u64).unwrap_or(0))
    }

    /// SeTokenIsRestricted: OpenNT modela a restrição pelos SIDs restritos (o
    /// NT testa TokenFlags>>4 & 1), que acompanham o write-restricted.
    fn token_is_restricted(call: &Call) -> Result<u64, KernelError> {
        Ok(tokens::with(call.arg(1), |token| (!token.restricted_sids.is_empty() || token.write_restricted) as u64).unwrap_or(0))
    }

    /// SeTokenIsAdmin: Administrators S-1-5-32-544 (export de dado
    /// `SeAliasAdminsSid`) habilitado nos grupos e token não restrito; um token
    /// de impersonação abaixo de SecurityImpersonation nunca é admin.
    fn token_is_admin(call: &Call) -> Result<u64, KernelError> {
        let administrators = sid(5, &[32, 544]);
        Ok(tokens::with(call.arg(1), |token| {
            if token.kind == TOKEN_IMPERSONATION && token.impersonation_level < SECURITY_IMPERSONATION {
                return 0u64;
            }
            if !token.restricted_sids.is_empty() || token.write_restricted {
                return 0;
            }
            token.groups.iter().any(|group| group.sid == administrators && group.attributes & SE_GROUP_ENABLED != 0) as u64
        })
        .unwrap_or(0))
    }

    // ---- Atributos de segurança / claims -------------------------------------

    /// SeQuerySecurityAttributesTokenAccessInformation(Token, *AttributesInfo):
    /// aloca um TOKEN_SECURITY_ATTRIBUTES_INFORMATION com o conjunto de
    /// atributos do token e devolve o ponteiro em `*arg2`. O token do Sistema
    /// tem conjunto vazio → cabeçalho bem-formado de 16 bytes (Version=1,
    /// AttributeCount=0, pAttributeV1=NULL).
    fn query_access_information(call: &Call) -> Result<u64, KernelError> {
        let (token, output) = (call.arg(1), call.arg(2));
        let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        };
        let size = match security_attributes::measure(&record.security_attributes) {
            Ok(size) => size,
            Err(status) => return Ok(signed_status(status)),
        };
        let base = guest::alloc_bytes(size);
        if base == 0 {
            return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
        }
        match security_attributes::encode(&record.security_attributes, base) {
            Ok(bytes) => guest::write_bytes(base, &bytes),
            Err(status) => {
                guest::free_bytes(base);
                return Ok(signed_status(status));
            }
        }
        guest::write64(output, base);
        Ok(0)
    }

    /// SeSecurityAttributePresent(Token, Name): existe o claim nomeado? O
    /// conjunto vazio do token do Sistema devolve FALSE.
    fn security_attribute_present(call: &Call) -> Result<u64, KernelError> {
        let (token, name_pointer) = (call.arg(1), call.arg(2));
        let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
            return Ok(0);
        };
        if name_pointer == 0 {
            return Ok(0);
        }
        // UNICODE_STRING: Length@0 (USHORT), Buffer@8 (PWSTR).
        let length = guest::read16(name_pointer) as u64;
        let buffer = guest::read64(name_pointer + 8);
        if length == 0 || buffer == 0 || length & 1 != 0 {
            return Ok(0);
        }
        let units: Vec<u16> = (0..length / 2).map(|index| guest::read16(buffer + index * 2)).collect();
        let name = String::from_utf16_lossy(&units);
        let present = security_attributes::select(&record.security_attributes, Some(&[name]))?.is_some();
        Ok(present as u64)
    }

    pub static GROUP: Group = Group {
        name: "se-token-info",
        names: &[
            "SeQueryInformationToken",
            "SeTokenType",
            "SeTokenImpersonationLevel",
            "SeTokenIsRestricted",
            "SeTokenIsAdmin",
            "SeQuerySecurityAttributesTokenAccessInformation",
            "SeSecurityAttributePresent",
        ],
        handlers: &[
            query_information,
            token_type,
            token_impersonation_level,
            token_is_restricted,
            token_is_admin,
            query_access_information,
            security_attribute_present,
        ],
        data_exports: &[],
    };
}

pub mod se_assign {
    //! Atribuição, consulta e ajuste do SECURITY_DESCRIPTOR de objetos, que os
    //! drivers reais de FS/IPC (ntfs, refs, npfs, msfs, clfs, afd, http, ks…)
    //! importam ao criar objetos. Reusa `inherit_descriptor::assign` (herança) e
    //! `query_descriptor` (seleção de componentes); a serialização self-relative
    //! é a única montagem nova, sobre as peças existentes.

    use alloc::vec::Vec;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::ps::process;
    use crate::ntos::se::inherit_descriptor::{self, Captured};
    use crate::ntos::se::model::sid;
    use crate::ntos::se::query_descriptor;
    use crate::ntos::se::token::tokens;
    use crate::rtl::KernelError;

    // SECURITY_INFORMATION bits.
    const OWNER_INFORMATION: u32 = 0x0000_0001;
    const GROUP_INFORMATION: u32 = 0x0000_0002;
    const DACL_INFORMATION: u32 = 0x0000_0004;
    /// SACL(8) | LABEL(0x10) | ATTRIBUTE(0x20) | SCOPE(0x40) | TRUST(0x80) | FILTER(0x100).
    const SACL_SELECTORS: u32 = 0x0000_01F8;

    // SECURITY_DESCRIPTOR control bits.
    const SELF_RELATIVE: u16 = 0x8000;
    const DACL_PRESENT: u16 = 0x0004;
    const DACL_DEFAULTED: u16 = 0x0008;
    const SACL_PRESENT: u16 = 0x0010;
    const SACL_DEFAULTED: u16 = 0x0020;
    const DACL_AUTO_INHERITED: u16 = 0x0400;
    const SACL_AUTO_INHERITED: u16 = 0x0800;
    const DACL_PROTECTED: u16 = 0x1000;
    const SACL_PROTECTED: u16 = 0x2000;

    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;

    /// GENERIC_MAPPING (Read/Write/Execute/All). Map NULL só ocorre por engano
    /// do chamador; nesse caso deixa os direitos específicos passarem.
    fn read_mapping(map: u64) -> [u32; 4] {
        if map == 0 {
            return [0, 0, 0, 0xFFFF_FFFF];
        }
        [guest::read32(map), guest::read32(map + 4), guest::read32(map + 8), guest::read32(map + 12)]
    }

    /// Lê um SECURITY_DESCRIPTOR (absoluto ou self-relative) do convidado para um
    /// `Captured`; owner/group ausentes ficam vazios.
    fn captured_from(pointer: u64) -> Option<Captured> {
        query_descriptor::read_descriptor(pointer).map(|descriptor| Captured {
            control: descriptor.control,
            owner: descriptor.owner.unwrap_or_default(),
            group: descriptor.group.unwrap_or_default(),
            dacl: descriptor.dacl,
            sacl: descriptor.sacl,
        })
    }

    /// Owner/group padrão para CREATOR OWNER/GROUP: do token primário do subject
    /// context, com recuo ao token corrente e, em último caso, ao SYSTEM.
    fn subject_owner_group(subject: u64) -> (Vec<u8>, Vec<u8>) {
        let mut token = 0;
        if subject != 0 {
            let primary = guest::read64(subject + 0x10);
            token = if primary != 0 { primary } else { guest::read64(subject) };
        }
        if token == 0 {
            token = process::get_primary_token(process::get_current_process()).unwrap_or(0);
        }
        let default = || sid(5, &[18]);
        tokens::with(token, |token| (token.owner.clone(), token.primary_group.clone()))
            .map(|(owner, group)| (if owner.is_empty() { default() } else { owner }, if group.is_empty() { default() } else { group }))
            .unwrap_or_else(|| (default(), default()))
    }

    /// Captured -> SECURITY_DESCRIPTOR_RELATIVE. Ordem de campos indiferente; os
    /// componentes do assign já são múltiplos de 4, mantendo o alinhamento que o
    /// `descriptor::valid_relative` exige. (Montagem nova, sobre peças existentes.)
    fn serialize_relative(descriptor: &Captured) -> Vec<u8> {
        let mut header = [0u8; 20];
        header[0] = 1;
        header[2..4].copy_from_slice(&(descriptor.control | SELF_RELATIVE).to_le_bytes());
        let mut body = Vec::new();
        let mut offset = 20u32;
        if !descriptor.owner.is_empty() {
            header[4..8].copy_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&descriptor.owner);
            offset += descriptor.owner.len() as u32;
        }
        if !descriptor.group.is_empty() {
            header[8..12].copy_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&descriptor.group);
            offset += descriptor.group.len() as u32;
        }
        if let Some(sacl) = &descriptor.sacl {
            header[12..16].copy_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(sacl);
            offset += sacl.len() as u32;
        }
        if let Some(dacl) = &descriptor.dacl {
            header[16..20].copy_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(dacl);
            offset += dacl.len() as u32;
        }
        let _ = offset;
        let mut bytes = Vec::with_capacity(20 + body.len());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        bytes
    }

    /// Serializa e publica `*out` com uma cópia pooled self-relative do descritor.
    fn publish(descriptor: &Captured, out: u64) {
        let bytes = serialize_relative(descriptor);
        let pointer = guest::alloc_bytes(bytes.len() as u64);
        guest::write_bytes(pointer, &bytes);
        guest::write64(out, pointer);
    }

    /// Núcleo comum de SeAssignSecurity/SeAssignSecurityEx: monta o `creator`
    /// (owner/group explícitos ou do token) e delega a herança ao
    /// `inherit_descriptor::assign`, que faz mapeamento genérico, CREATOR
    /// OWNER/GROUP, AutoInherit e proteção. ObjectType (GUID) é ignorado.
    fn do_assign(parent_ptr: u64, explicit_ptr: u64, out: u64, container: bool, auto_flags: u32, subject: u64, map: u64) -> Result<u64, KernelError> {
        if out == 0 {
            return Ok(signed_status(STATUS_INVALID_PARAMETER));
        }
        let mapping = read_mapping(map);
        let parent = captured_from(parent_ptr);
        let explicit = captured_from(explicit_ptr);
        let (owner_default, group_default) = subject_owner_group(subject);
        let creator = Captured {
            control: explicit.as_ref().map_or(0, |captured| captured.control),
            owner: explicit.as_ref().filter(|captured| !captured.owner.is_empty()).map_or(owner_default, |captured| captured.owner.clone()),
            group: explicit.as_ref().filter(|captured| !captured.group.is_empty()).map_or(group_default, |captured| captured.group.clone()),
            dacl: explicit.as_ref().and_then(|captured| captured.dacl.clone()),
            sacl: explicit.as_ref().and_then(|captured| captured.sacl.clone()),
        };
        match inherit_descriptor::assign(parent.as_ref(), &creator, &mapping, auto_flags & 3, container) {
            Ok(Ok(result)) => {
                publish(&result, out);
                Ok(0)
            }
            Ok(Err(status)) => Ok(signed_status(status)),
            Err(_) => Ok(signed_status(STATUS_INVALID_SECURITY_DESCR)),
        }
    }

    /// SeAssignSecurity(Parent, Explicit, *New, IsDirectory, Subject, Map, Pool).
    fn assign(call: &Call) -> Result<u64, KernelError> {
        do_assign(call.arg(1), call.arg(2), call.arg(3), call.arg(4) & 0xFF != 0, 0, call.arg(5), call.arg(6))
    }

    /// SeAssignSecurityEx(Parent, Explicit, *New, ObjectType, IsDirectory,
    /// AutoInheritFlags, Subject, Map, Pool).
    fn assign_ex(call: &Call) -> Result<u64, KernelError> {
        do_assign(call.arg(1), call.arg(2), call.arg(3), call.arg(5) & 0xFF != 0, call.arg(6) as u32, call.arg(7), call.arg(8))
    }

    /// SeQuerySecurityDescriptorInfo(*Information, Out, *Length, *ObjectSd):
    /// shim de ABI sobre `query_descriptor::query_descriptor`, que já faz filtro
    /// de SACL, LengthNeeded e BUFFER_TOO_SMALL.
    fn query_info(call: &Call) -> Result<u64, KernelError> {
        let information = guest::read32(call.arg(1));
        let object_sd = guest::read64(call.arg(4));
        let descriptor = query_descriptor::read_descriptor(object_sd);
        let length = guest::read32(call.arg(3));
        let result = query_descriptor::query_descriptor(descriptor.as_ref(), information, call.arg(2), length);
        guest::write32(call.arg(3), result.needed as u32);
        Ok(signed_status(result.status))
    }

    /// SeSetSecurityDescriptorInfo(Object, *Information, Modification, *ObjectSd,
    /// Pool, Map). Mescla os componentes selecionados da Modification sobre o SD
    /// atual, pooleia um novo SD self-relative e troca `*ObjectSd` (liberando o
    /// antigo). Parcial: owner/group/DACL e troca inteira de SACL/label.
    fn set_info(call: &Call) -> Result<u64, KernelError> {
        let information = guest::read32(call.arg(2));
        let object_sd_pointer = call.arg(4);
        let current = captured_from(guest::read64(object_sd_pointer));
        let modification = captured_from(call.arg(3));
        let mapping = read_mapping(call.arg(6));
        // Cada componente vem da Modification se o seu bit estiver em Information,
        // senão permanece o do objeto.
        let pick = |from_modification: bool| if from_modification { modification.as_ref() } else { current.as_ref() };
        let owner_source = pick(information & OWNER_INFORMATION != 0);
        let group_source = pick(information & GROUP_INFORMATION != 0);
        let dacl_source = pick(information & DACL_INFORMATION != 0);
        let sacl_source = pick(information & SACL_SELECTORS != 0);
        let mut control = 0u16;
        control |= dacl_source.map_or(0, |captured| captured.control) & (DACL_PRESENT | DACL_DEFAULTED | DACL_PROTECTED);
        control |= sacl_source.map_or(0, |captured| captured.control) & (SACL_PRESENT | SACL_DEFAULTED | SACL_PROTECTED);
        let merged = Captured {
            control,
            owner: owner_source.filter(|captured| !captured.owner.is_empty()).map_or_else(|| sid(5, &[18]), |captured| captured.owner.clone()),
            group: group_source.filter(|captured| !captured.group.is_empty()).map_or_else(|| sid(5, &[18]), |captured| captured.group.clone()),
            dacl: dacl_source.and_then(|captured| captured.dacl.clone()),
            sacl: sacl_source.and_then(|captured| captured.sacl.clone()),
        };
        // Reaproveita AutoInherit do assign para mapear genéricos e remontar ACLs.
        let flags = (dacl_source.map_or(0, |captured| captured.control) & DACL_AUTO_INHERITED != 0) as u32
            | (((sacl_source.map_or(0, |captured| captured.control) & SACL_AUTO_INHERITED != 0) as u32) << 1);
        match inherit_descriptor::assign(None, &merged, &mapping, flags, false) {
            Ok(Ok(result)) => {
                let old = guest::read64(object_sd_pointer);
                publish(&result, object_sd_pointer);
                if old != 0 {
                    guest::free_bytes(old);
                }
                Ok(0)
            }
            Ok(Err(status)) => Ok(signed_status(status)),
            Err(_) => Ok(signed_status(STATUS_INVALID_SECURITY_DESCR)),
        }
    }

    pub static GROUP: Group = Group {
        name: "se-assign",
        names: &["SeAssignSecurity", "SeAssignSecurityEx", "SeQuerySecurityDescriptorInfo", "SeSetSecurityDescriptorInfo"],
        handlers: &[assign, assign_ex, query_info, set_info],
        data_exports: &[],
    };
}

// ============================================================================

pub mod se_access {
    //! Verificação de acesso e de privilégio contra um SECURITY_DESCRIPTOR e o
    //! contexto de segurança do sujeito, que drivers reais de FS, rede e
    //! armazenamento importam. Reusa a avaliação ordenada de DACL do
    //! `token/access.rs`/`object_security.rs`, dirigida agora por um descritor
    //! e pelo GENERIC_MAPPING do chamador em vez do mapeamento fixo de token.
    //!
    //! Lacuna honesta: não há caminho de concessão por privilégio ligado a
    //! descritores (SeSecurityPrivilege para ACCESS_SYSTEM_SECURITY,
    //! SeTakeOwnership para WRITE_OWNER); `*Privileges` sai NULL e esse ramo é
    //! pulado — igual ao `token/access.rs`, que só honra 8/9 habilitados no
    //! objeto token.

    use alloc::vec::Vec;

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::mm::guest_memory as guest;
    use crate::ntos::se::descriptor;
    use crate::ntos::se::model::Sid;
    use crate::ntos::se::token::tokens;
    use crate::rtl::KernelError;

    // SECURITY_SUBJECT_CONTEXT (0x20): ClientToken@0, ImpersonationLevel@8,
    // PrimaryToken@16, ProcessAuditId@24.
    const CLIENT_TOKEN: u64 = 0x00;
    const IMPERSONATION_LEVEL: u64 = 0x08;
    const PRIMARY_TOKEN: u64 = 0x10;

    // SECURITY_IMPERSONATION_LEVEL: SecurityImpersonation.
    const SECURITY_IMPERSONATION: u32 = 2;

    // ACCESS_MASK bits.
    const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;
    const GENERIC_MASK: u32 = 0xF000_0000;

    // SECURITY_DESCRIPTOR control + ACE/ACL + privilege/group attribute bits.
    const DACL_PRESENT: u16 = 0x0004;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
    const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
    const SE_GROUP_ENABLED: u32 = 0x04;
    const SE_GROUP_USE_FOR_DENY_ONLY: u32 = 0x10;
    const SE_PRIVILEGE_ENABLED: u32 = 0x02;
    const SE_PRIVILEGE_USED_FOR_ACCESS: u32 = 0x8000_0000;
    const PRIVILEGE_SET_ALL_NECESSARY: u32 = 0x01;

    // NTSTATUS.
    const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
    const STATUS_BAD_IMPERSONATION_LEVEL: u32 = 0xC000_00A5;
    const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

    // ACCESS_STATE (0xA0): PrivilegesAllocated@0x0B, AuxData@0x48,
    // Privileges (INITIAL_PRIVILEGE_SET inline, até 3)@0x50.
    const AS_PRIVILEGES_ALLOCATED: u64 = 0x0B;
    const AS_AUX_DATA: u64 = 0x48;
    const AS_PRIVILEGES: u64 = 0x50;
    const INITIAL_PRIVILEGE_COUNT: u32 = 3;
    // LUID_AND_ATTRIBUTES: Luid@0 (8), Attributes@8 (4).
    const LAA_STRIDE: u64 = 12;

    /// Identidade efetiva usada na avaliação da DACL: SID do usuário e os
    /// grupos (SID + atributos). Vale tanto para um objeto token quanto para um
    /// TOKEN_ACCESS_INFORMATION capturado.
    struct Subject {
        user: Sid,
        groups: Vec<(Sid, u32)>,
    }

    /// Lê um SID do convidado (cabeçalho de 8 bytes + 4 por subautoridade).
    fn read_sid(pointer: u64) -> Sid {
        let count = guest::read8(pointer.wrapping_add(1)) as usize;
        guest::read_bytes(pointer, 8 + 4 * count)
    }

    /// RtlMapGenericMask: expande os quatro bits genéricos pelo GENERIC_MAPPING
    /// do chamador (Read/Write/Execute/All em 0/4/8/12) e os remove.
    fn map_generic(mut mask: u32, mapping: u64) -> u32 {
        if mapping != 0 {
            if mask & 0x8000_0000 != 0 {
                mask |= guest::read32(mapping);
            }
            if mask & 0x4000_0000 != 0 {
                mask |= guest::read32(mapping + 4);
            }
            if mask & 0x2000_0000 != 0 {
                mask |= guest::read32(mapping + 8);
            }
            if mask & 0x1000_0000 != 0 {
                mask |= guest::read32(mapping + 12);
            }
        }
        mask & !GENERIC_MASK
    }

    /// Conjunto "todo o acesso" para MAXIMUM_ALLOWED: GenericAll do mapeamento
    /// mais os direitos padrão.
    fn all_access(mapping: u64) -> u32 {
        if mapping != 0 {
            guest::read32(mapping + 12) | STANDARD_RIGHTS_ALL
        } else {
            STANDARD_RIGHTS_ALL | 0x1FF
        }
    }

    fn write_result(granted_out: u64, status_out: u64, granted: u32, status: u32) {
        if granted_out != 0 {
            guest::write32(granted_out, granted);
        }
        if status_out != 0 {
            guest::write32(status_out, status);
        }
    }

    /// KernelMode concede o pedido inteiro (ou tudo, com MAXIMUM_ALLOWED), como
    /// o SeAccessCheck real antes de qualquer avaliação de DACL.
    fn kernel_grant(desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> u64 {
        let granted = if desired & MAXIMUM_ALLOWED != 0 {
            all_access(mapping) | (desired & !MAXIMUM_ALLOWED) | previous
        } else {
            desired | previous
        };
        write_result(granted_out, status_out, granted, 0);
        1
    }

    /// Avaliação ordenada da DACL do descritor pela identidade `subject`.
    /// `None` = DACL nula (ausente ou ponteiro nulo) → concede tudo; `Some(m)` =
    /// máscara acumulada de concessões (deny acumula à parte, respeitando a
    /// ordem das ACEs, como em `token/access.rs`).
    fn evaluate(descriptor: u64, subject: &Subject) -> Option<u32> {
        let control = descriptor::control(descriptor);
        // O dono recebe READ_CONTROL e WRITE_DAC de saída.
        let owner = descriptor::component(descriptor, control, 0);
        let mut granted = if owner != 0 && read_sid(owner) == subject.user { READ_CONTROL | WRITE_DAC } else { 0 };
        if control & DACL_PRESENT == 0 {
            return None;
        }
        let dacl = descriptor::component(descriptor, control, 3);
        if dacl == 0 {
            return None;
        }
        let mut denied = 0u32;
        let count = guest::read16(dacl + 4);
        let mut cursor = dacl + 8;
        for _ in 0..count {
            let ace_type = guest::read8(cursor);
            let ace_size = guest::read16(cursor + 2) as u64;
            if ace_size == 0 {
                break;
            }
            if ace_type == ACCESS_ALLOWED_ACE_TYPE || ace_type == ACCESS_DENIED_ACE_TYPE {
                let mask = guest::read32(cursor + 4);
                let ace_sid = read_sid(cursor + 8);
                let deny = ace_type == ACCESS_DENIED_ACE_TYPE;
                let matches = ace_sid == subject.user
                    || subject.groups.iter().any(|(sid, attributes)| {
                        let attributes = *attributes;
                        *sid == ace_sid
                            && ((attributes & SE_GROUP_ENABLED != 0 && attributes & SE_GROUP_USE_FOR_DENY_ONLY == 0)
                                || (deny && attributes & SE_GROUP_USE_FOR_DENY_ONLY != 0))
                    });
                if matches {
                    if deny {
                        denied |= mask & !granted;
                    } else {
                        granted |= mask & !denied;
                    }
                }
            }
            cursor += ace_size;
        }
        Some(granted)
    }

    /// Decisão comum de SeAccessCheck/SeAccessCheckFromState depois de resolver
    /// a identidade e já com `desired` mapeado. `subject` ausente (sujeito não
    /// resolvido) nega.
    fn decide(descriptor: u64, subject: Option<Subject>, desired: u32, previous: u32, mapping: u64, granted_out: u64, status_out: u64) -> u64 {
        let Some(subject) = subject else {
            write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
            return 0;
        };
        let maximum = desired & MAXIMUM_ALLOWED != 0;
        let explicit = desired & !MAXIMUM_ALLOWED;
        match evaluate(descriptor, &subject) {
            // DACL nula: todos têm acesso total.
            None => {
                let granted = if maximum { all_access(mapping) | explicit | previous } else { explicit | previous };
                write_result(granted_out, status_out, granted, 0);
                1
            }
            Some(dacl) => {
                let accumulated = dacl | previous;
                if maximum {
                    if accumulated == 0 {
                        write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                        0
                    } else {
                        write_result(granted_out, status_out, accumulated, 0);
                        1
                    }
                } else if explicit & !accumulated != 0 {
                    write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
                    0
                } else {
                    write_result(granted_out, status_out, explicit | previous, 0);
                    1
                }
            }
        }
    }

    /// SeAccessCheck(Sd, Subj, SubjLocked, Desired, PrevGranted, Privileges**,
    /// Map, Mode, GrantedAccess*, AccessStatus*).
    fn access_check(call: &Call) -> Result<u64, KernelError> {
        let (descriptor, subject_context) = (call.arg(1), call.arg(2));
        let mut desired = call.arg(4) as u32;
        let previous = call.arg(5) as u32;
        let (privileges_out, mapping, mode) = (call.arg(6), call.arg(7), call.arg(8) as u32);
        let (granted_out, status_out) = (call.arg(9), call.arg(10));
        // Sem caminho de concessão por privilégio: nenhum privilégio foi usado.
        if privileges_out != 0 {
            guest::write64(privileges_out, 0);
        }
        if mode == 0 {
            return Ok(kernel_grant(desired, previous, mapping, granted_out, status_out));
        }
        if descriptor == 0 {
            write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
            return Ok(0);
        }
        if desired & GENERIC_MASK != 0 {
            desired = map_generic(desired, mapping);
        }
        // Token efetivo: ClientToken ao personificar (>= Impersonation), senão
        // PrimaryToken. Personificação fraca com ClientToken nega.
        let client = guest::read64(subject_context + CLIENT_TOKEN);
        let token = if client != 0 {
            if guest::read32(subject_context + IMPERSONATION_LEVEL) < SECURITY_IMPERSONATION {
                write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
                return Ok(0);
            }
            client
        } else {
            guest::read64(subject_context + PRIMARY_TOKEN)
        };
        let subject = tokens::with(token, |token| Subject {
            user: token.user.clone(),
            groups: token.groups.iter().map(|group| (group.sid.clone(), group.attributes)).collect(),
        });
        Ok(decide(descriptor, subject, desired, previous, mapping, granted_out, status_out))
    }

    /// Lê um TOKEN_ACCESS_INFORMATION capturado num `Subject`. SidHash@0 →
    /// (SidCount@0, SidAttr@8); SID_AND_ATTRIBUTES = (Sid@0, Attributes@8),
    /// stride 0x10; o primeiro SID é o usuário, os demais são grupos.
    fn subject_from_access_information(information: u64) -> Option<Subject> {
        if information == 0 {
            return None;
        }
        let hash = guest::read64(information);
        if hash == 0 {
            return None;
        }
        let count = guest::read32(hash);
        let array = guest::read64(hash + 8);
        if array == 0 || count == 0 {
            return None;
        }
        let mut sids: Vec<(Sid, u32)> = Vec::new();
        for index in 0..count as u64 {
            let entry = array + index * 0x10;
            let sid = guest::read64(entry);
            if sid != 0 {
                sids.push((read_sid(sid), guest::read32(entry + 8)));
            }
        }
        if sids.is_empty() {
            return None;
        }
        let user = sids.remove(0).0;
        Some(Subject { user, groups: sids })
    }

    /// SeAccessCheckFromState(Sd, PrimaryTokenInfo, ClientTokenInfo, Desired,
    /// PrevGranted, Privileges**, Map, Mode, GrantedAccess*, AccessStatus*):
    /// mesmo algoritmo, com a identidade vinda de um TOKEN_ACCESS_INFORMATION.
    fn access_check_from_state(call: &Call) -> Result<u64, KernelError> {
        let (descriptor, primary_info, client_info) = (call.arg(1), call.arg(2), call.arg(3));
        let mut desired = call.arg(4) as u32;
        let previous = call.arg(5) as u32;
        let (privileges_out, mapping, mode) = (call.arg(6), call.arg(7), call.arg(8) as u32);
        let (granted_out, status_out) = (call.arg(9), call.arg(10));
        if privileges_out != 0 {
            guest::write64(privileges_out, 0);
        }
        if mode == 0 {
            return Ok(kernel_grant(desired, previous, mapping, granted_out, status_out));
        }
        if descriptor == 0 {
            write_result(granted_out, status_out, 0, STATUS_ACCESS_DENIED);
            return Ok(0);
        }
        if desired & GENERIC_MASK != 0 {
            desired = map_generic(desired, mapping);
        }
        // ImpersonationLevel@0x24 do TOKEN_ACCESS_INFORMATION do cliente.
        let information = if client_info != 0 {
            if guest::read32(client_info + 0x24) < SECURITY_IMPERSONATION {
                write_result(granted_out, status_out, 0, STATUS_BAD_IMPERSONATION_LEVEL);
                return Ok(0);
            }
            client_info
        } else {
            primary_info
        };
        let subject = subject_from_access_information(information);
        Ok(decide(descriptor, subject, desired, previous, mapping, granted_out, status_out))
    }

    /// SePrivilegeCheck(RequiredPrivileges, Subj, Mode): BOOLEAN. KernelMode →
    /// TRUE imediato; senão testa cada LUID do PRIVILEGE_SET contra os
    /// privilégios habilitados do token efetivo, marcando os usados.
    fn privilege_check(call: &Call) -> Result<u64, KernelError> {
        let (set, subject_context, mode) = (call.arg(1), call.arg(2), call.arg(3) as u32);
        if mode == 0 {
            return Ok(1);
        }
        let client = guest::read64(subject_context + CLIENT_TOKEN);
        let token = if client != 0 && guest::read32(subject_context + IMPERSONATION_LEVEL) >= SECURITY_IMPERSONATION {
            client
        } else {
            guest::read64(subject_context + PRIMARY_TOKEN)
        };
        let Some(held) = tokens::with(token, |token| token.privileges.clone()) else {
            return Ok(0);
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
        Ok((if all_necessary { held_all } else { held_any }) as u64)
    }

    /// SeAppendPrivileges(AccessState, Privileges): acrescenta o PRIVILEGE_SET
    /// ao conjunto inline (INITIAL_PRIVILEGE_SET@0x50); no transbordo (> 3)
    /// aloca um PRIVILEGE_SET agrupado, copia inline + novos, marca
    /// PrivilegesAllocated e o liga em AuxData->PrivilegesUsed quando há AuxData
    /// (convenção do SeCreateAccessState). O caminho inline é o dos chamadores
    /// comuns (ntfs/http/ks/npfs), que logo liberam.
    fn append_privileges(call: &Call) -> Result<u64, KernelError> {
        let (access_state, privileges) = (call.arg(1), call.arg(2));
        let current = guest::read32(access_state + AS_PRIVILEGES);
        let appended = guest::read32(privileges);
        if appended == 0 {
            return Ok(0);
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
            return Ok(0);
        }
        // Transbordo: PRIVILEGE_SET agrupado (cabeçalho de 8 + total LAA).
        let pooled = guest::alloc_bytes(8 + total as u64 * LAA_STRIDE);
        if pooled == 0 {
            return Ok(signed_status(STATUS_INSUFFICIENT_RESOURCES));
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
        Ok(0)
    }

    /// SeFreePrivileges(Privileges) = ExFreePool: libera só um PRIVILEGE_SET que
    /// o OpenNT alocou (ignora o conjunto inline do ACCESS_STATE).
    fn free_privileges(call: &Call) -> Result<u64, KernelError> {
        let privileges = call.arg(1);
        if privileges != 0 && guest::owns_allocation(privileges) {
            guest::free_bytes(privileges);
        }
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "se-access",
        names: &[
            "SeAccessCheck", "SeAccessCheckFromState", "SePrivilegeCheck",
            "SeAppendPrivileges", "SeFreePrivileges",
        ],
        handlers: &[access_check, access_check_from_state, privilege_check, append_privileges, free_privileges],
        data_exports: &[],
    };
}

// =============================================================================
