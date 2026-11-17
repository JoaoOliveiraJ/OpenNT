//! Exports Se* (Security Reference Monitor).
//!
//! Só adaptadores: a lógica mora nos arquivos de assunto do `se`
//! (`subject_context.rs`, `audit.rs`, `privilege.rs`, `access_check.rs`,
//! `assign.rs`, `descriptor.rs`, `query_descriptor.rs` e `token/`).

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::se::token::information as token_information;
use crate::ntos::se::{audit, privilege, subject_context};
use crate::rtl::KernelError;

/// SeSinglePrivilegeCheck(PrivilegeValue (LUID por valor), PreviousMode).
fn single_privilege_check(call: &Call) -> Result<u64, KernelError> {
    Ok(privilege::single_privilege_check(call.arg(1), call.arg(2) as u32) as u64)
}

fn capture_subject_context(call: &Call) -> Result<u64, KernelError> {
    subject_context::capture(call.arg(1))?;
    Ok(0)
}

fn release_subject_context(call: &Call) -> Result<u64, KernelError> {
    subject_context::release(call.arg(1))?;
    Ok(0)
}

fn lock_subject_context(_: &Call) -> Result<u64, KernelError> {
    subject_context::lock();
    Ok(0)
}

fn unlock_subject_context(_: &Call) -> Result<u64, KernelError> {
    subject_context::unlock();
    Ok(0)
}

fn query_authentication_id_token(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(token_information::query_authentication_id(call.arg(1), call.arg(2))))
}

fn set_audit_parameter(call: &Call) -> Result<u64, KernelError> {
    audit::set_audit_parameter(call.arg(2) as u32, call.arg(3) as u32, call.arg(4) as u32);
    Ok(0)
}

fn report_security_event_with_sub_category(call: &Call) -> Result<u64, KernelError> {
    audit::report_security_event(call.arg(2) as u32);
    Ok(0)
}

fn audit_fips_crypto_selftests(call: &Call) -> Result<u64, KernelError> {
    audit::fips_crypto_selftests(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32);
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
    //! SeRegisterImageVerificationCallback — `ntos/se/image_verification`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::image_verification;
    use crate::rtl::KernelError;

    fn register(call: &Call) -> Result<u64, KernelError> {
        Ok(image_verification::register(call.arg(1) as u32, call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5), call.arg(6))? as u64)
    }

    pub static GROUP: Group = Group { name: "image-verification", names: &["SeRegisterImageVerificationCallback"], handlers: &[register], data_exports: &[] };
}

pub mod image_verification_remove {
    //! SeUnregisterImageVerificationCallback — `ntos/se/image_verification`.

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
    //! SeQuerySecureBootPlatformManifest.
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
    //! SeQuerySecureBootPolicyValue.
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
    //! ZwDuplicateToken.
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
    //! ZwOpenProcessTokenEx.
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
    //! ZwQueryInformationToken.
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
    //! ZwImpersonateAnonymousToken.

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
    //! ZwOpenThreadTokenEx — `ntos/se/token/handles`; fora de PASSIVE_LEVEL o
    //! sistema para com IRQL_NOT_LESS_OR_EQUAL (0xC4, 0x2001F).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::token::handles as token_handles;
    use crate::rtl::KernelError;

    fn open_thread(call: &Call) -> Result<u64, KernelError> {
        Ok(token_handles::open_thread_from_kernel(call.arg(1), call.arg(2) as u32, call.arg(3) & 0xFF != 0, call.arg(4) as u32, call.arg(5))? as u64)
    }

    pub static GROUP: Group = Group { name: "token-handles", names: &["ZwOpenThreadTokenEx"], handlers: &[open_thread], data_exports: &[] };
}

pub mod locally_unique_id {
    //! ZwAllocateLocallyUniqueId: o LUID sai do contador único de LUIDs.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::tokens;
    use crate::rtl::KernelError;

    fn allocate(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(tokens::allocate_luid_into(call.arg(1))))
    }

    pub static GROUP: Group = Group { name: "locally-unique-id", names: &["ZwAllocateLocallyUniqueId"], handlers: &[allocate], data_exports: &[] };
}

pub mod se_descriptor {
    //! Captura, validação e liberação de SECURITY_DESCRIPTOR que drivers reais
    //! de FS, armazenamento e rede importam — lógica em `se/descriptor.rs` e
    //! `se/assign.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{assign, descriptor};
    use crate::rtl::KernelError;

    /// SeCaptureSecurityDescriptor(Sd, Mode, Pool, Force, *Captured).
    fn capture(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::capture_mode(call.arg(1), call.arg(2) as u8, call.arg(5))))
    }

    fn release(call: &Call) -> Result<u64, KernelError> {
        descriptor::release_captured(call.arg(1));
        Ok(0)
    }

    fn deassign(call: &Call) -> Result<u64, KernelError> {
        assign::deassign(call.arg(1));
        Ok(0)
    }

    /// SeValidSecurityDescriptor(Length, Sd): valida um SD self-relative.
    fn valid(call: &Call) -> Result<u64, KernelError> {
        Ok(descriptor::valid_relative(call.arg(2), call.arg(1) as u32, 0) as u64)
    }

    /// SeConvertStringSecurityDescriptorToSecurityDescriptor(String,
    /// StringSDRevision, SecurityDescriptor*, SecurityDescriptorSize*).
    fn convert_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(crate::ntos::se::sddl::convert_string_to_descriptor(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4))))
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
    //! SeQueryInformationToken e acessores de token — lógica em
    //! `se/token/information.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::information;
    use crate::rtl::KernelError;

    fn query_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(information::query_information(call.arg(1), call.arg(2) as u32, call.arg(3))?))
    }

    fn token_type(call: &Call) -> Result<u64, KernelError> {
        Ok(information::token_type(call.arg(1)) as u64)
    }

    fn token_impersonation_level(call: &Call) -> Result<u64, KernelError> {
        Ok(information::impersonation_level(call.arg(1)) as u64)
    }

    fn token_is_restricted(call: &Call) -> Result<u64, KernelError> {
        Ok(information::is_restricted(call.arg(1)) as u64)
    }

    fn token_is_admin(call: &Call) -> Result<u64, KernelError> {
        Ok(information::is_admin(call.arg(1)) as u64)
    }

    fn query_access_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(crate::ntos::ps::security::query_attributes_from_access_information(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6))?))
    }

    fn security_attribute_present(call: &Call) -> Result<u64, KernelError> {
        Ok(information::security_attribute_present(call.arg(1), call.arg(2))? as u64)
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

pub mod se_query_session_id_token {
    //! SeQuerySessionIdToken — lógica em `se/token/information.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::token::information;
    use crate::rtl::KernelError;

    fn query_session_id_token(call: &Call) -> Result<u64, KernelError> {
        Ok(information::query_session_id_token(call.arg(1), call.arg(2)) as u64)
    }

    pub static GROUP: Group = Group { name: "se-query-session-id-token", names: &["SeQuerySessionIdToken"], handlers: &[query_session_id_token], data_exports: &[] };
}

pub mod se_assign {
    //! Atribuição, consulta e ajuste do SECURITY_DESCRIPTOR de objetos, que os
    //! drivers reais de FS/IPC (ntfs, refs, npfs, msfs, clfs, afd, http, ks…)
    //! importam ao criar objetos — lógica em `se/assign.rs` e
    //! `se/query_descriptor.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{assign as security_assign, query_descriptor};
    use crate::rtl::KernelError;

    /// SeAssignSecurity(Parent, Explicit, *New, IsDirectory, Subject, Map, Pool).
    fn assign(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security_assign::assign(call.arg(1), call.arg(2), call.arg(3), call.arg(4) & 0xFF != 0, 0, call.arg(5), call.arg(6))))
    }

    /// SeAssignSecurityEx(Parent, Explicit, *New, ObjectType, IsDirectory,
    /// AutoInheritFlags, Subject, Map, Pool).
    fn assign_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security_assign::assign(call.arg(1), call.arg(2), call.arg(3), call.arg(5) & 0xFF != 0, call.arg(6) as u32, call.arg(7), call.arg(8))))
    }

    /// SeQuerySecurityDescriptorInfo(*Information, Out, *Length, *ObjectSd).
    fn query_info(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(query_descriptor::query_info(call.arg(1), call.arg(2), call.arg(3), call.arg(4))))
    }

    /// SeSetSecurityDescriptorInfo(Object, *Information, Modification, *ObjectSd,
    /// Pool, Map).
    fn set_info(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(security_assign::set_info(call.arg(2), call.arg(3), call.arg(4), call.arg(6))))
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
    //! armazenamento importam — lógica em `se/access_check.rs` e
    //! `se/privilege.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{access_check as security_access_check, privilege};
    use crate::rtl::KernelError;

    /// SeAccessCheck(Sd, Subj, SubjLocked, Desired, PrevGranted, Privileges**,
    /// Map, Mode, GrantedAccess*, AccessStatus*).
    fn access_check(call: &Call) -> Result<u64, KernelError> {
        Ok(security_access_check::access_check(call.arg(1), call.arg(2), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10)) as u64)
    }

    /// SeAccessCheckFromState(Sd, PrimaryTokenInfo, ClientTokenInfo, Desired,
    /// PrevGranted, Privileges**, Map, Mode, GrantedAccess*, AccessStatus*).
    fn access_check_from_state(call: &Call) -> Result<u64, KernelError> {
        Ok(security_access_check::access_check_from_state(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8) as u32, call.arg(9), call.arg(10)) as u64)
    }

    /// SePrivilegeCheck(RequiredPrivileges, Subj, Mode): BOOLEAN.
    fn privilege_check(call: &Call) -> Result<u64, KernelError> {
        Ok(privilege::privilege_check(call.arg(1), call.arg(2), call.arg(3) as u32) as u64)
    }

    /// SeAppendPrivileges(AccessState, Privileges).
    fn append_privileges(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(privilege::append_privileges(call.arg(1), call.arg(2))))
    }

    /// SeFreePrivileges(Privileges).
    fn free_privileges(call: &Call) -> Result<u64, KernelError> {
        privilege::free_privileges(call.arg(1));
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

pub mod se_access_from_state {
    //! Adaptadores de SeTokenFromAccessInformation e SeAccessCheckFromStateEx
    //! (lógica em `se/access_check.rs`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::access_check;
    use crate::rtl::KernelError;

    /// (PTOKEN_ACCESS_INFORMATION, PVOID Token, ULONG Length, PULONG RequiredLength).
    fn token_from_access_information(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(access_check::token_from_access_information_checked(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4))))
    }

    /// (Sd, PrimaryToken, ClientToken, Desired, PrevGranted, Privileges,
    /// GenericMapping, AccessMode, GrantedAccess, AccessStatus) -> BOOLEAN.
    fn access_check_from_state_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(access_check::access_check_from_state_ex(call.arg(1), call.arg(2), call.arg(3), call.arg(4) as u32, call.arg(5) as u32, call.arg(6), call.arg(7), call.arg(8) as u8 as u32, call.arg(9), call.arg(10)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "se-access-from-state",
        names: &["SeTokenFromAccessInformation", "SeAccessCheckFromStateEx"],
        handlers: &[token_from_access_information, access_check_from_state_ex],
        data_exports: &[],
    };
}

pub mod se_client_security {
    //! Contexto de segurança do cliente e captura do sujeito de outra
    //! thread/processo (tcpip, win32kfull, drivers de FS/RPC) — lógica em
    //! `se/client_security.rs` e `se/subject_context.rs`.

    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::extra_obpsse::SecurityClientContext;
    use crate::ntos::inc::types::{SecurityQualityOfService, SecuritySubjectContext};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{client_security, subject_context};
    use crate::rtl::KernelError;

    fn qos(call: &Call, index: usize) -> &'static SecurityQualityOfService {
        // SAFETY: PSECURITY_QUALITY_OF_SERVICE do chamador (modo kernel).
        unsafe { SecurityQualityOfService::at(call.arg(index)) }
    }

    fn client_context(call: &Call, index: usize) -> &'static SecurityClientContext {
        // SAFETY: PSECURITY_CLIENT_CONTEXT do chamador (modo kernel).
        unsafe { SecurityClientContext::at(call.arg(index)) }
    }

    fn subject(call: &Call, index: usize) -> &'static SecuritySubjectContext {
        // SAFETY: PSECURITY_SUBJECT_CONTEXT do chamador (modo kernel).
        unsafe { SecuritySubjectContext::at(call.arg(index)) }
    }

    /// SeCaptureSubjectContextEx(Thread, Process, SubjectContext).
    fn capture_subject_context_ex(call: &Call) -> Result<u64, KernelError> {
        subject_context::capture_ex(call.arg(1), call.arg(2), subject(call, 3))?;
        Ok(0)
    }

    /// SeCreateClientSecurity(ClientThread, Qos, RemoteSession, ClientContext).
    fn create_client_security(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(client_security::create(call.arg(1), qos(call, 2), call.arg(3) as u8 != 0, client_context(call, 4))?))
    }

    /// SeCreateClientSecurityFromSubjectContext(Subject, Qos, ServerIsRemote, ClientContext).
    fn create_client_security_from_subject_context(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(client_security::create_from_subject_context(subject(call, 1), qos(call, 2), call.arg(3) as u8 != 0, client_context(call, 4))?))
    }

    /// SeImpersonateClientEx(ClientContext, ServerThread); SeImpersonateClient
    /// (VOID) é a mesma chamada.
    fn impersonate_client_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(client_security::impersonate_client(client_context(call, 1), call.arg(2))?))
    }

    pub static GROUP: Group = Group {
        name: "se-client-security",
        names: &["SeCaptureSubjectContextEx", "SeCreateClientSecurity", "SeCreateClientSecurityFromSubjectContext", "SeImpersonateClientEx", "SeImpersonateClient"],
        handlers: &[capture_subject_context_ex, create_client_security, create_client_security_from_subject_context, impersonate_client_ex, impersonate_client_ex],
        data_exports: &[],
    };
}

pub mod se_access_state {
    //! ACCESS_STATE + AUX_ACCESS_DATA (win32kbase, dxgkrnl, drivers de FS) —
    //! lógica em `se/access_state.rs`.

    use crate::ntos::inc::field::NtStruct;
    use crate::ntos::inc::types::{AccessState, AuxAccessData, GenericMapping};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::ps::process;
    use crate::ntos::se::access_state;
    use crate::rtl::KernelError;

    /// (PACCESS_STATE, PAUX_ACCESS_DATA, PGENERIC_MAPPING opcional) do chamador.
    fn blocks(call: &Call, first: usize) -> (&'static AccessState, &'static AuxAccessData, Option<&'static GenericMapping>) {
        let mapping = call.arg(first + 3);
        // SAFETY: ponteiros de modo kernel do chamador, como no NT; o
        // GENERIC_MAPPING é opcional.
        unsafe { (AccessState::at(call.arg(first)), AuxAccessData::at(call.arg(first + 1)), (mapping != 0).then(|| GenericMapping::at(mapping))) }
    }

    /// SeCreateAccessState(AccessState, AuxData, DesiredAccess, GenericMapping):
    /// a thread corrente e o seu ApcState.Process.
    fn create_access_state(call: &Call) -> Result<u64, KernelError> {
        let (state, aux, mapping) = blocks(call, 1);
        Ok(signed_status(access_state::create(process::get_current_thread(), process::get_current_process(), state, aux, call.arg(3) as u32, mapping)?))
    }

    /// SeCreateAccessStateEx(Thread, Process, AccessState, AuxData, DesiredAccess, GenericMapping).
    fn create_access_state_ex(call: &Call) -> Result<u64, KernelError> {
        let (state, aux, mapping) = blocks(call, 3);
        Ok(signed_status(access_state::create(call.arg(1), call.arg(2), state, aux, call.arg(5) as u32, mapping)?))
    }

    fn delete_access_state(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PACCESS_STATE criado por SeCreateAccessState(Ex).
        access_state::delete(unsafe { AccessState::at(call.arg(1)) })?;
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "se-access-state",
        names: &["SeCreateAccessState", "SeCreateAccessStateEx", "SeDeleteAccessState"],
        handlers: &[create_access_state, create_access_state_ex, delete_access_state],
        data_exports: &[],
    };
}

pub mod se_appcontainer {
    //! SeIsParentOfChildAppContainer (win32kbase/win32kfull) — lógica em
    //! `se/capability/appcontainer.rs`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::capability::appcontainer;
    use crate::rtl::KernelError;

    /// SeIsParentOfChildAppContainer(SessionId, ParentLowboxNumber, ChildLowboxNumber) -> BOOLEAN.
    fn is_parent_of_child_app_container(call: &Call) -> Result<u64, KernelError> {
        Ok(appcontainer::is_parent_of_child_lowbox(call.arg(1) as u32, call.arg(2) as u32, call.arg(3) as u32) as u64)
    }

    pub static GROUP: Group = Group {
        name: "se-appcontainer",
        names: &["SeIsParentOfChildAppContainer"],
        handlers: &[is_parent_of_child_app_container],
        data_exports: &[],
    };
}

pub mod se_access_check_ex {
    //! Adaptadores de `se/access_check.rs`: access check com requisição/
    //! resposta e com hint, e os ajustes por restrições de acesso que o ntfs
    //! chama no caminho de create (TxfAccessCheck, NtfsAccessCheck).

    use crate::ntos::inc::types::{AccessState, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::access_check;
    use crate::rtl::KernelError;

    /// SeAccessCheckEx(Subject, SubjectLocked, AccessRequest, AccessReply,
    /// AuditInfo, AccessMode) -> BOOLEAN. Os ponteiros nulos fazem parte do
    /// contrato (validação na ordem do NT), então seguem como endereços.
    fn access_check_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(access_check::access_check_ex(call.arg(1), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u8 as u32) as u64)
    }

    /// SeAccessCheckWithHint(Sd, Hint, Subject, Locked, Desired, Previous,
    /// *Privileges, Mapping, Mode, *Granted, *Status) -> BOOLEAN.
    fn access_check_with_hint(call: &Call) -> Result<u64, KernelError> {
        Ok(access_check::access_check_with_hint(call.arg(1), call.arg(3), call.arg(5) as u32, call.arg(6) as u32, call.arg(7), call.arg(8), call.arg(9) as u8 as u32, call.arg(10), call.arg(11)) as u64)
    }

    /// SeAdjustAccessStateForAccessConstraints(ObjectType, Sd, AccessState).
    fn adjust_access_state_for_access_constraints(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PACCESS_STATE de um chamador de kernel (NtfsAccessCheck).
        let access_state = unsafe { AccessState::at(call.arg(3)) };
        access_check::adjust_access_state_for_access_constraints(call.arg(1), call.arg(2), access_state);
        Ok(0)
    }

    /// SeShouldCheckForAccessRightsFromParent(ObjectType, ChildSd, AccessState) -> BOOLEAN.
    fn should_check_for_access_rights_from_parent(call: &Call) -> Result<u64, KernelError> {
        Ok(access_check::should_check_for_access_rights_from_parent(call.arg(2)) as u64)
    }

    pub static GROUP: Group = Group {
        name: "se-access-check-ex",
        names: &["SeAccessCheckEx", "SeAccessCheckWithHint", "SeAdjustAccessStateForAccessConstraints", "SeShouldCheckForAccessRightsFromParent"],
        handlers: &[access_check_ex, access_check_with_hint, adjust_access_state_for_access_constraints, should_check_for_access_rights_from_parent],
        data_exports: &[],
    };
}

pub mod se_audit_alarms {
    //! Adaptadores de `se/audit.rs`: portões da política de auditoria de
    //! arquivos, alarmes de abertura/exclusão de objeto e os registros de
    //! hard link e de transação que o ntfs chama (NtfsAccessCheck,
    //! NtfsSetDispositionInfo, NtfsSetLinkInfo, TxfAuditTransactionState).

    use crate::ntos::inc::types::{AccessState, NtStruct};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::audit;
    use crate::rtl::KernelError;

    fn access_state(address: u64) -> &'static AccessState {
        // SAFETY: PACCESS_STATE do chamador de kernel (SeCreateAccessState).
        unsafe { AccessState::at(address) }
    }

    /// SeAuditHardLinkCreation(FileName, LinkName, bSuccess).
    fn audit_hard_link_creation(call: &Call) -> Result<u64, KernelError> {
        audit::audit_hard_link_creation(call.arg(1), call.arg(2), call.arg(3) as u8 != 0, 0);
        Ok(0)
    }

    /// SeAuditHardLinkCreationWithTransaction(FileName, LinkName, bSuccess, TransactionId).
    fn audit_hard_link_creation_with_transaction(call: &Call) -> Result<u64, KernelError> {
        audit::audit_hard_link_creation(call.arg(1), call.arg(2), call.arg(3) as u8 != 0, call.arg(4));
        Ok(0)
    }

    /// SeAuditTransactionStateChange(TransactionId, ResourceManagerId, NewState).
    fn audit_transaction_state_change(call: &Call) -> Result<u64, KernelError> {
        audit::audit_transaction_state_change(call.arg(1), call.arg(2), call.arg(3) as u32);
        Ok(0)
    }

    /// SeAuditingAnyFileEventsWithContextEx(Sd, Subject, *StagingEnabled) -> BOOLEAN.
    fn auditing_any_file_events(call: &Call) -> Result<u64, KernelError> {
        Ok(audit::auditing_any_file_events(call.arg(3)) as u64)
    }

    /// SeAuditingFileEventsWithContextEx(AccessGranted, Sd, Subject, *StagingEnabled) -> BOOLEAN.
    fn auditing_file_events(call: &Call) -> Result<u64, KernelError> {
        Ok(audit::auditing_file_events(call.arg(1) as u8 != 0, call.arg(4)) as u64)
    }

    /// SeAuditingHardLinkEventsWithContext(AccessGranted, Sd, Subject) -> BOOLEAN.
    fn auditing_hard_link_events(call: &Call) -> Result<u64, KernelError> {
        Ok(audit::auditing_hard_link_events(call.arg(1) as u8 != 0, call.arg(2)) as u64)
    }

    /// SeDeleteObjectAuditAlarm(Object, Handle).
    fn delete_object_audit_alarm(call: &Call) -> Result<u64, KernelError> {
        audit::delete_object_audit_alarm(call.arg(1), call.arg(2), 0);
        Ok(0)
    }

    /// SeDeleteObjectAuditAlarmWithTransaction(Object, Handle, TransactionId).
    fn delete_object_audit_alarm_with_transaction(call: &Call) -> Result<u64, KernelError> {
        audit::delete_object_audit_alarm(call.arg(1), call.arg(2), call.arg(3));
        Ok(0)
    }

    /// SeOpenObjectAuditAlarm(TypeName, Object, AbsoluteName, Sd, AccessState,
    /// ObjectCreated, AccessGranted, AccessMode, *GenerateOnClose).
    fn open_object_audit_alarm(call: &Call) -> Result<u64, KernelError> {
        audit::open_object_audit_alarm(call.arg(1), call.arg(2), call.arg(3), call.arg(4), access_state(call.arg(5)), call.arg(7) as u8 != 0, call.arg(8) as u8, 0, call.arg(9));
        Ok(0)
    }

    /// SeOpenObjectAuditAlarmWithTransaction(..., AccessMode, TransactionId, *GenerateOnClose).
    fn open_object_audit_alarm_with_transaction(call: &Call) -> Result<u64, KernelError> {
        audit::open_object_audit_alarm(call.arg(1), call.arg(2), call.arg(3), call.arg(4), access_state(call.arg(5)), call.arg(7) as u8 != 0, call.arg(8) as u8, call.arg(9), call.arg(10));
        Ok(0)
    }

    /// SeOpenObjectForDeleteAuditAlarm(TypeName, Object, AbsoluteName, Sd,
    /// AccessState, ObjectCreated, AccessGranted, AccessMode, *GenerateOnClose).
    fn open_object_for_delete_audit_alarm(call: &Call) -> Result<u64, KernelError> {
        audit::open_object_for_delete_audit_alarm(call.arg(1), call.arg(2), call.arg(3), call.arg(4), access_state(call.arg(5)), call.arg(7) as u8 != 0, call.arg(8) as u8, 0, call.arg(9));
        Ok(0)
    }

    /// SeOpenObjectForDeleteAuditAlarmWithTransaction(..., AccessMode, TransactionId, *GenerateOnClose).
    fn open_object_for_delete_audit_alarm_with_transaction(call: &Call) -> Result<u64, KernelError> {
        audit::open_object_for_delete_audit_alarm(call.arg(1), call.arg(2), call.arg(3), call.arg(4), access_state(call.arg(5)), call.arg(7) as u8 != 0, call.arg(8) as u8, call.arg(9), call.arg(10));
        Ok(0)
    }

    pub static GROUP: Group = Group {
        name: "se-audit-alarms",
        names: &[
            "SeAuditHardLinkCreation",
            "SeAuditHardLinkCreationWithTransaction",
            "SeAuditTransactionStateChange",
            "SeAuditingAnyFileEventsWithContextEx",
            "SeAuditingFileEventsWithContextEx",
            "SeAuditingHardLinkEventsWithContext",
            "SeDeleteObjectAuditAlarm",
            "SeDeleteObjectAuditAlarmWithTransaction",
            "SeOpenObjectAuditAlarm",
            "SeOpenObjectAuditAlarmWithTransaction",
            "SeOpenObjectForDeleteAuditAlarm",
            "SeOpenObjectForDeleteAuditAlarmWithTransaction",
        ],
        handlers: &[
            audit_hard_link_creation,
            audit_hard_link_creation_with_transaction,
            audit_transaction_state_change,
            auditing_any_file_events,
            auditing_file_events,
            auditing_hard_link_events,
            delete_object_audit_alarm,
            delete_object_audit_alarm_with_transaction,
            open_object_audit_alarm,
            open_object_audit_alarm_with_transaction,
            open_object_for_delete_audit_alarm,
            open_object_for_delete_audit_alarm_with_transaction,
        ],
        data_exports: &[],
    };
}

pub mod se_set_security {
    //! Adaptadores de `se/set_security.rs`: troca de componentes do descritor
    //! de um objeto existente e as verificações auxiliares que o ntfs chama
    //! ao mudar a segurança (NtfsModifySecurity, NtfsCacheSharedSecurityForCreate).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::set_security;
    use crate::rtl::KernelError;

    /// SeSetSecurityDescriptorInfoEx(Object, *SecurityInformation, Modification,
    /// *ObjectsSecurityDescriptor, AutoInheritFlags, PoolType, GenericMapping).
    fn set_security_descriptor_info_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(set_security::set_security_descriptor_info(call.arg(2), call.arg(3), call.arg(4), call.arg(5) as u32, call.arg(7))))
    }

    /// SeComputeAutoInheritByObjectType(ObjectType, Sd, ParentSd) -> ULONG.
    fn compute_auto_inherit_by_object_type(call: &Call) -> Result<u64, KernelError> {
        Ok(set_security::compute_auto_inherit_by_object_type(call.arg(2), call.arg(3)) as u64)
    }

    /// SeCheckForCriticalAceRemoval(CurrentSd, NewSd, Subject, *AceRemoved).
    fn check_for_critical_ace_removal(call: &Call) -> Result<u64, KernelError> {
        set_security::check_for_critical_ace_removal(call.arg(4));
        Ok(0)
    }

    /// SeAdjustObjectSecurity(...) -> NTSTATUS.
    fn adjust_object_security(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(set_security::adjust_object_security()))
    }

    pub static GROUP: Group = Group {
        name: "se-set-security",
        names: &["SeSetSecurityDescriptorInfoEx", "SeComputeAutoInheritByObjectType", "SeCheckForCriticalAceRemoval", "SeAdjustObjectSecurity"],
        handlers: &[set_security_descriptor_info_ex, compute_auto_inherit_by_object_type, check_for_critical_ace_removal, adjust_object_security],
        data_exports: &[],
    };
}

pub mod se_privilege_audit {
    //! SePrivilegeObjectAuditAlarm; a lógica mora em `se/audit`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::audit;
    use crate::rtl::KernelError;

    /// SePrivilegeObjectAuditAlarm(Handle, SubjectSecurityContext,
    /// DesiredAccess, Privileges, AccessGranted, AccessMode).
    fn privilege_object_audit_alarm(call: &Call) -> Result<u64, KernelError> {
        audit::privilege_object_audit_alarm(call.arg(1), call.arg(3) as u32, call.arg(4), call.arg(5) as u8 != 0, call.arg(6) as u8);
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "se-privilege-audit", names: &["SePrivilegeObjectAuditAlarm"], handlers: &[privilege_object_audit_alarm], data_exports: &[] };
}

pub mod se_logon_session {
    //! SeSetSessionIdTokenWithLinked; a lógica mora em `se/logon_session`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::logon_session;
    use crate::rtl::KernelError;

    /// SeSetSessionIdTokenWithLinked(TokenHandle, SessionId).
    fn set_session_id_token_with_linked(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logon_session::set_session_id_token_with_linked(call.arg(1), call.arg(2) as u32)?))
    }

    pub static GROUP: Group = Group { name: "se-logon-session", names: &["SeSetSessionIdTokenWithLinked"], handlers: &[set_session_id_token_with_linked], data_exports: &[] };
}

pub mod se_non_ob_audit {
    //! SeOpenObjectAuditAlarmForNonObObject; a lógica mora em `se/audit`.

    use crate::ntos::inc::types::{NtStruct, SecuritySubjectContext};
    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::audit;
    use crate::rtl::KernelError;

    /// SeOpenObjectAuditAlarmForNonObObject(SubsystemName, HandleId,
    /// ObjectTypeName, ObjectName, Sd, SubjectContext, DesiredAccess,
    /// GrantedAccess, Privileges, AccessGranted, *GenerateOnClose).
    fn open_object_audit_alarm_for_non_ob_object(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: o SECURITY_SUBJECT_CONTEXT capturado pelo chamador de modo kernel.
        let subject = unsafe { SecuritySubjectContext::at(call.arg(6)) };
        audit::open_object_audit_alarm_for_non_ob_object(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), subject, call.arg(7) as u32, call.arg(8) as u32, call.arg(9), call.arg(10) as u8 != 0, call.arg(11));
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "se-non-ob-audit", names: &["SeOpenObjectAuditAlarmForNonObObject"], handlers: &[open_object_audit_alarm_for_non_ob_object], data_exports: &[] };
}

pub mod se_srp_access_check {
    //! SeSrpAccessCheck; a lógica mora em `se/access_check`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::access_check;
    use crate::rtl::KernelError;

    /// SeSrpAccessCheck(Subject, SubjectLocked, AccessRequest, AccessReply,
    /// AuditInfo, AccessMode) -> BOOLEAN.
    fn srp_access_check(call: &Call) -> Result<u64, KernelError> {
        Ok(access_check::srp_access_check(call.arg(1), call.arg(3), call.arg(4), call.arg(5), call.arg(6) as u8 as u32) as u64)
    }

    pub static GROUP: Group = Group { name: "se-srp-access-check", names: &["SeSrpAccessCheck"], handlers: &[srp_access_check], data_exports: &[] };
}

pub mod se_filter_token {
    //! SeFilterToken; a lógica mora em `se/token/filter.rs`.

    use crate::ntos::inc::types::{Field, NtStruct};
    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::filter;
    use crate::rtl::KernelError;

    /// SeFilterToken(ExistingToken, Flags, SidsToDisable, PrivilegesToDelete,
    /// RestrictedSids, FilteredToken*) -> NTSTATUS.
    fn filter_token(call: &Call) -> Result<u64, KernelError> {
        // SAFETY: PACCESS_TOKEN* de saída do chamador.
        let filtered = unsafe { Field::<u64>::at(call.arg(6)) };
        Ok(signed_status(filter::filter_token(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5), filtered)?))
    }

    pub static GROUP: Group = Group { name: "se-filter-token", names: &["SeFilterToken"], handlers: &[filter_token], data_exports: &[] };
}

pub mod query_security_attributes {
    //! ZwQuerySecurityAttributesToken; a lógica mora em `se/token/attributes.rs`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::attributes;
    use crate::rtl::KernelError;

    /// ZwQuerySecurityAttributesToken(TokenHandle, Attributes,
    /// NumberOfAttributes, Buffer, Length, ReturnLength) -> NTSTATUS.
    fn query(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(attributes::query(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6))?))
    }

    pub static GROUP: Group = Group { name: "query-security-attributes", names: &["ZwQuerySecurityAttributesToken"], handlers: &[query], data_exports: &[] };
}

pub mod zw_adjust_privileges_token {
    //! ZwAdjustPrivilegesToken; a lógica mora em `se/token/adjust`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::adjust;
    use crate::rtl::KernelError;

    /// ZwAdjustPrivilegesToken(TokenHandle, DisableAllPrivileges, NewState,
    /// BufferLength, PreviousState, ReturnLength).
    fn adjust_privileges_token(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(adjust::adjust_privileges_token(call.arg(1), call.arg(2) & 0xFF != 0, call.arg(3), call.arg(4) as u32, call.arg(5), call.arg(6))?))
    }

    pub static GROUP: Group = Group { name: "zw-adjust-privileges-token", names: &["ZwAdjustPrivilegesToken"], handlers: &[adjust_privileges_token], data_exports: &[] };
}

pub mod se_sddl_strings {
    //! SeConvertSidToStringSid, SeConvertStringSidToSid e
    //! SeConvertSecurityDescriptorToStringSecurityDescriptor; a lógica mora
    //! em `se/sddl`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::sddl;
    use crate::rtl::KernelError;

    /// SeConvertSidToStringSid(Sid, StringSid*) -> NTSTATUS.
    fn sid_to_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sddl::convert_sid_to_string(call.arg(1), call.arg(2))))
    }

    /// SeConvertStringSidToSid(StringSid, Sid*) -> NTSTATUS.
    fn string_to_sid(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sddl::convert_string_to_sid(call.arg(1), call.arg(2))))
    }

    /// SeConvertSecurityDescriptorToStringSecurityDescriptor(Sd, Revision,
    /// SecurityInformation, String*, StringLength*) -> NTSTATUS.
    fn descriptor_to_string(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(sddl::convert_descriptor_to_string(call.arg(1), call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5))))
    }

    pub static GROUP: Group = Group { name: "se-sddl-strings", names: &["SeConvertSidToStringSid", "SeConvertStringSidToSid", "SeConvertSecurityDescriptorToStringSecurityDescriptor"], handlers: &[sid_to_string, string_to_sid, descriptor_to_string], data_exports: &[] };
}

pub mod se_signing_levels {
    //! SeCompareSigningLevels, ZwGetCachedSigningLevel e
    //! ZwSetCachedSigningLevel; a lógica mora em `se/signing_level`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::signing_level;
    use crate::rtl::KernelError;

    /// SeCompareSigningLevels(ActualSigningLevel, ExpectedSigningLevel) -> BOOLEAN.
    fn compare(call: &Call) -> Result<u64, KernelError> {
        Ok(signing_level::compare(call.arg(1) as u8, call.arg(2) as u8))
    }

    /// ZwGetCachedSigningLevel(File, Flags*, SigningLevel*, Thumbprint,
    /// ThumbprintSize*, ThumbprintAlgorithm*) -> NTSTATUS.
    fn get_cached(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(signing_level::get_cached(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))?))
    }

    /// ZwSetCachedSigningLevel(Flags, InputSigningLevel, SourceFiles,
    /// SourceFileCount, TargetFile) -> NTSTATUS.
    fn set_cached(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(signing_level::set_cached(call.arg(1) as u32, call.arg(2) as u8, call.arg(3), call.arg(4) as u32, call.arg(5))?))
    }

    pub static GROUP: Group = Group { name: "se-signing-levels", names: &["SeCompareSigningLevels", "ZwGetCachedSigningLevel", "ZwSetCachedSigningLevel"], handlers: &[compare, get_cached, set_cached], data_exports: &[] };
}

pub mod zw_open_process_token {
    //! ZwOpenProcessToken: o NtOpenProcessTokenEx sem atributos, em
    //! KernelMode (`se/token/open_process`).

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::token::open_process as open_process_token;
    use crate::rtl::KernelError;

    /// ZwOpenProcessToken(ProcessHandle, DesiredAccess, TokenHandle*) -> NTSTATUS.
    fn open_process_token(call: &Call) -> Result<u64, KernelError> {
        Ok(open_process_token::open(call.arg(1), call.arg(2) as u32, 0, call.arg(3), 0)? as u64)
    }

    pub static GROUP: Group = Group { name: "zw-open-process-token", names: &["ZwOpenProcessToken"], handlers: &[open_process_token], data_exports: &[] };
}

pub mod lsa_return_buffer {
    //! LsaFreeReturnBuffer; a lógica mora em `se/extension_hosts`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::extension_hosts;
    use crate::rtl::KernelError;

    /// LsaFreeReturnBuffer(Buffer) -> NTSTATUS.
    fn free_return_buffer(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(extension_hosts::free_return_buffer(call.arg(1))?))
    }

    pub static GROUP: Group = Group { name: "lsa-return-buffer", names: &["LsaFreeReturnBuffer"], handlers: &[free_return_buffer], data_exports: &[] };
}

pub mod se_logon_session_notify {
    //! SeRegisterLogonSessionTerminatedRoutineEx,
    //! SeUnregisterLogonSessionTerminatedRoutineEx e
    //! SeMarkLogonSessionForTerminationNotificationEx; a lógica mora em
    //! `se/logon_session`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::{logon_session, out};
    use crate::rtl::KernelError;

    /// SeRegisterLogonSessionTerminatedRoutineEx(Routine, Context) -> NTSTATUS.
    fn register(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logon_session::register_terminated_routine(call.arg(1), call.arg(2))))
    }

    /// SeUnregisterLogonSessionTerminatedRoutineEx(Routine, Context) -> NTSTATUS.
    fn unregister(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logon_session::unregister_terminated_routine(call.arg(1), call.arg(2))))
    }

    /// SeMarkLogonSessionForTerminationNotificationEx(LogonId*, ServerSilo) -> NTSTATUS.
    fn mark(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logon_session::mark_for_termination_notification(out::<u64>(call.arg(1)).get(), call.arg(2))))
    }

    pub static GROUP: Group = Group {
        name: "se-logon-session-notify",
        names: &["SeRegisterLogonSessionTerminatedRoutineEx", "SeUnregisterLogonSessionTerminatedRoutineEx", "SeMarkLogonSessionForTerminationNotificationEx"],
        handlers: &[register, unregister, mark],
        data_exports: &[],
    };
}

pub mod se_token_session_queries {
    //! SeGetLogonSessionToken (`se/logon_session`) e SeQueryServerSiloToken
    //! (`se/token/information`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::token::information;
    use crate::ntos::se::{logon_session, out};
    use crate::rtl::KernelError;

    /// SeGetLogonSessionToken(TokenHandle, AccessMode, NewTokenHandle*) -> NTSTATUS.
    fn get_logon_session_token(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(logon_session::get_logon_session_token(call.arg(1), call.arg(2) as u8, out::<u64>(call.arg(3)))?))
    }

    /// SeQueryServerSiloToken(Token, Silo*) -> NTSTATUS.
    fn query_server_silo(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(information::query_server_silo(call.arg(1), out::<u64>(call.arg(2)))))
    }

    pub static GROUP: Group = Group { name: "se-token-session-queries", names: &["SeGetLogonSessionToken", "SeQueryServerSiloToken"], handlers: &[get_logon_session_token, query_server_silo], data_exports: &[] };
}

pub mod se_token_attributes_set {
    //! SeSetSecurityAttributesToken e SeSetSecurityAttributesTokenEx; a
    //! lógica mora em `se/token/attributes`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::out;
    use crate::ntos::se::token::attributes;
    use crate::rtl::KernelError;

    /// SeSetSecurityAttributesToken(TokenHandle, AccessMode, Operations,
    /// Attributes) -> NTSTATUS.
    fn set(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(attributes::set_security_attributes(call.arg(1), call.arg(2) as u8, false, call.arg(3), call.arg(4))?))
    }

    /// SeSetSecurityAttributesTokenEx(TokenHandle, AccessMode, Reserved,
    /// Singleton, Operations, Attributes, SingletonSet*) -> NTSTATUS.
    fn set_ex(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(attributes::set_security_attributes_ex(call.arg(1), call.arg(2) as u8, call.arg(3), call.arg(4) as u8 != 0, call.arg(5), call.arg(6), out::<u8>(call.arg(7)))?))
    }

    pub static GROUP: Group = Group { name: "se-token-attributes-set", names: &["SeSetSecurityAttributesToken", "SeSetSecurityAttributesTokenEx"], handlers: &[set, set_ex], data_exports: &[] };
}

pub mod zw_compare_tokens {
    //! ZwCompareTokens: o NtCompareTokens em KernelMode (`se/token/compare`).

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::out;
    use crate::ntos::se::token::compare;
    use crate::rtl::KernelError;

    /// ZwCompareTokens(FirstTokenHandle, SecondTokenHandle, Equal*) -> NTSTATUS.
    fn compare_tokens(call: &Call) -> Result<u64, KernelError> {
        let (status, equal) = compare::compare_tokens(call.arg(1), call.arg(2), 0)?;
        out::<u8>(call.arg(3)).set(equal as u8);
        Ok(signed_status(status))
    }

    pub static GROUP: Group = Group { name: "zw-compare-tokens", names: &["ZwCompareTokens"], handlers: &[compare_tokens], data_exports: &[] };
}

pub mod se_examine_sacl {
    //! SeExamineSacl; a lógica mora em `se/audit`.

    use crate::ntos::init::exports::{Call, Group};
    use crate::ntos::se::{audit, out};
    use crate::rtl::KernelError;

    /// SeExamineSacl(Sacl, ResourceSacl, Token, DesiredAccess, AccessGranted,
    /// GenerateAudit*, GenerateAlarm*).
    fn examine_sacl(call: &Call) -> Result<u64, KernelError> {
        let audit = audit::examine_sacl_for_audit(call.arg(1), call.arg(3), call.arg(4) as u32, call.arg(5) as u8 != 0);
        out::<u8>(call.arg(6)).set(audit as u8);
        out::<u8>(call.arg(7)).set(0);
        Ok(0)
    }

    pub static GROUP: Group = Group { name: "se-examine-sacl", names: &["SeExamineSacl"], handlers: &[examine_sacl], data_exports: &[] };
}

pub mod se_cached_signing_level {
    //! SeGetCachedSigningLevel; a lógica mora em `se/signing_level`.

    use crate::ntos::init::exports::{signed_status, Call, Group};
    use crate::ntos::se::signing_level;
    use crate::rtl::KernelError;

    /// SeGetCachedSigningLevel(FileObject, Flags*, SigningLevel*, Thumbprint,
    /// ThumbprintSize*, ThumbprintAlgorithm*) -> NTSTATUS.
    fn get_cached(call: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(signing_level::get_for_file_object(call.arg(1), call.arg(2), call.arg(3), call.arg(4), call.arg(5), call.arg(6))))
    }

    pub static GROUP: Group = Group { name: "se-cached-signing-level", names: &["SeGetCachedSigningLevel"], handlers: &[get_cached], data_exports: &[] };
}

pub mod se_public_default_dacl {
    //! O export de dado SePublicDefaultDacl (`se/system_dacls`).

    use crate::ntos::init::exports::Group;
    use crate::ntos::se::system_dacls;

    fn public_default_dacl_cell() -> u64 {
        system_dacls::public_default_dacl_cell()
    }

    pub static GROUP: Group = Group { name: "se-public-default-dacl", names: &[], handlers: &[], data_exports: &[("SePublicDefaultDacl", public_default_dacl_cell)] };
}
