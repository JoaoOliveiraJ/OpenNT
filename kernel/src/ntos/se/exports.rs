//! Exports Se* (Security Reference Monitor) — `system32/win32/ntoskrnl/se.js`.
//!
//! Só adaptadores: a lógica mora nos arquivos de assunto do `se`
//! (`subject_context.rs`, `audit.rs`, `privilege.rs`, `access_check.rs`,
//! `assign.rs`, `descriptor.rs`, `query_descriptor.rs` e `token/`).

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::se::token::information as token_information;
use crate::ntos::se::{audit, privilege, subject_context};
use crate::rtl::KernelError;

fn single_privilege_check(call: &Call) -> Result<u64, KernelError> {
    Ok(privilege::single_privilege_check(call.arg(2) as u32) as u64)
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
        Ok(signed_status(descriptor::capture(call.arg(1), call.arg(5))))
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

    fn convert_string(_: &Call) -> Result<u64, KernelError> {
        Ok(signed_status(descriptor::convert_string_to_descriptor()))
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
        Ok(signed_status(information::query_security_attributes_access_information(call.arg(1), call.arg(2))))
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
