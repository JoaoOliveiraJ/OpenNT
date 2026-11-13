//! Se: tokens, SIDs, ACLs, descritores de segurança e estado de acesso.
//!
//! Gerado a partir dos símbolos do ntoskrnl; ver `types/mod.rs`.

use super::*;

/// `_SE_AUDIT_PROCESS_CREATION_INFO` (0x8 bytes).
#[repr(C)]
pub struct SeAuditProcessCreationInfo {
    /// -> `_OBJECT_NAME_INFORMATION`
    pub image_file_name: Field<u64>,
}

unsafe impl NtStruct for SeAuditProcessCreationInfo {}

const _: () = {
    assert!(core::mem::size_of::<SeAuditProcessCreationInfo>() == 0x8);
    assert!(core::mem::offset_of!(SeAuditProcessCreationInfo, image_file_name) == 0x0);
};

/// `_GENERIC_MAPPING` (0x10 bytes).
#[repr(C)]
pub struct GenericMapping {
    pub generic_read: Field<u32>,
    pub generic_write: Field<u32>,
    pub generic_execute: Field<u32>,
    pub generic_all: Field<u32>,
}

unsafe impl NtStruct for GenericMapping {}

const _: () = {
    assert!(core::mem::size_of::<GenericMapping>() == 0x10);
    assert!(core::mem::offset_of!(GenericMapping, generic_read) == 0x0);
    assert!(core::mem::offset_of!(GenericMapping, generic_write) == 0x4);
    assert!(core::mem::offset_of!(GenericMapping, generic_execute) == 0x8);
    assert!(core::mem::offset_of!(GenericMapping, generic_all) == 0xc);
};

/// `_TOKEN` (0x498 bytes).
#[repr(C)]
pub struct Token {
    pub token_source: TokenSource,
    pub token_id: Luid,
    pub authentication_id: Luid,
    pub parent_token_id: Luid,
    pub expiration_time: LargeInteger,
    /// -> `_ERESOURCE`
    pub token_lock: Field<u64>,
    pub modified_id: Luid,
    pub privileges: SepTokenPrivileges,
    pub audit_policy: SepAuditPolicy,
    pub session_id: Field<u32>,
    pub user_and_group_count: Field<u32>,
    pub restricted_sid_count: Field<u32>,
    pub variable_length: Field<u32>,
    pub dynamic_charged: Field<u32>,
    pub dynamic_available: Field<u32>,
    pub default_owner_index: Field<u32>,
    _pad_94: Reserved<0x4>,
    /// -> `_SID_AND_ATTRIBUTES`
    pub user_and_groups: Field<u64>,
    /// -> `_SID_AND_ATTRIBUTES`
    pub restricted_sids: Field<u64>,
    /// -> `void`
    pub primary_group: Field<u64>,
    /// -> `u32`
    pub dynamic_part: Field<u64>,
    /// -> `_ACL`
    pub default_dacl: Field<u64>,
    pub token_type: Field<TokenType>,
    pub impersonation_level: Field<SecurityImpersonationLevel>,
    pub token_flags: Field<u32>,
    pub token_in_use: Field<u8>,
    _pad_cd: Reserved<0x3>,
    pub integrity_level_index: Field<u32>,
    pub mandatory_policy: Field<u32>,
    /// -> `_SEP_LOGON_SESSION_REFERENCES`
    pub logon_session: Field<u64>,
    pub originating_logon_session: Luid,
    pub sid_hash: SidAndAttributesHash,
    pub restricted_sid_hash: SidAndAttributesHash,
    /// -> `_AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION`
    pub p_security_attributes: Field<u64>,
    /// -> `void`
    pub package: Field<u64>,
    /// -> `_SID_AND_ATTRIBUTES`
    pub capabilities: Field<u64>,
    pub capability_count: Field<u32>,
    _pad_324: Reserved<0x4>,
    pub capabilities_hash: SidAndAttributesHash,
    /// -> `_SEP_LOWBOX_NUMBER_ENTRY`
    pub lowbox_number_entry: Field<u64>,
    /// -> `_SEP_CACHED_HANDLES_ENTRY`
    pub lowbox_handles_entry: Field<u64>,
    /// -> `_AUTHZBASEP_CLAIM_ATTRIBUTES_COLLECTION`
    pub p_claim_attributes: Field<u64>,
    /// -> `void`
    pub trust_level_sid: Field<u64>,
    /// -> `_TOKEN`
    pub trust_linked_token: Field<u64>,
    /// -> `void`
    pub integrity_level_sid_value: Field<u64>,
    /// -> `_SEP_SID_VALUES_BLOCK`
    pub token_sid_values: Field<u64>,
    /// -> `_SEP_LUID_TO_INDEX_MAP_ENTRY`
    pub index_entry: Field<u64>,
    /// -> `_SEP_TOKEN_DIAG_TRACK_ENTRY`
    pub diagnostic_info: Field<u64>,
    /// -> `_SEP_CACHED_HANDLES_ENTRY`
    pub bno_isolation_handles_entry: Field<u64>,
    /// -> `void`
    pub session_object: Field<u64>,
    pub variable_part: Field<u64>,
}

unsafe impl NtStruct for Token {}

const _: () = {
    assert!(core::mem::size_of::<Token>() == 0x498);
    assert!(core::mem::offset_of!(Token, token_source) == 0x0);
    assert!(core::mem::offset_of!(Token, token_id) == 0x10);
    assert!(core::mem::offset_of!(Token, authentication_id) == 0x18);
    assert!(core::mem::offset_of!(Token, parent_token_id) == 0x20);
    assert!(core::mem::offset_of!(Token, expiration_time) == 0x28);
    assert!(core::mem::offset_of!(Token, token_lock) == 0x30);
    assert!(core::mem::offset_of!(Token, modified_id) == 0x38);
    assert!(core::mem::offset_of!(Token, privileges) == 0x40);
    assert!(core::mem::offset_of!(Token, audit_policy) == 0x58);
    assert!(core::mem::offset_of!(Token, session_id) == 0x78);
    assert!(core::mem::offset_of!(Token, user_and_group_count) == 0x7c);
    assert!(core::mem::offset_of!(Token, restricted_sid_count) == 0x80);
    assert!(core::mem::offset_of!(Token, variable_length) == 0x84);
    assert!(core::mem::offset_of!(Token, dynamic_charged) == 0x88);
    assert!(core::mem::offset_of!(Token, dynamic_available) == 0x8c);
    assert!(core::mem::offset_of!(Token, default_owner_index) == 0x90);
    assert!(core::mem::offset_of!(Token, user_and_groups) == 0x98);
    assert!(core::mem::offset_of!(Token, restricted_sids) == 0xa0);
    assert!(core::mem::offset_of!(Token, primary_group) == 0xa8);
    assert!(core::mem::offset_of!(Token, dynamic_part) == 0xb0);
    assert!(core::mem::offset_of!(Token, default_dacl) == 0xb8);
    assert!(core::mem::offset_of!(Token, token_type) == 0xc0);
    assert!(core::mem::offset_of!(Token, impersonation_level) == 0xc4);
    assert!(core::mem::offset_of!(Token, token_flags) == 0xc8);
    assert!(core::mem::offset_of!(Token, token_in_use) == 0xcc);
    assert!(core::mem::offset_of!(Token, integrity_level_index) == 0xd0);
    assert!(core::mem::offset_of!(Token, mandatory_policy) == 0xd4);
    assert!(core::mem::offset_of!(Token, logon_session) == 0xd8);
    assert!(core::mem::offset_of!(Token, originating_logon_session) == 0xe0);
    assert!(core::mem::offset_of!(Token, sid_hash) == 0xe8);
    assert!(core::mem::offset_of!(Token, restricted_sid_hash) == 0x1f8);
    assert!(core::mem::offset_of!(Token, p_security_attributes) == 0x308);
    assert!(core::mem::offset_of!(Token, package) == 0x310);
    assert!(core::mem::offset_of!(Token, capabilities) == 0x318);
    assert!(core::mem::offset_of!(Token, capability_count) == 0x320);
    assert!(core::mem::offset_of!(Token, capabilities_hash) == 0x328);
    assert!(core::mem::offset_of!(Token, lowbox_number_entry) == 0x438);
    assert!(core::mem::offset_of!(Token, lowbox_handles_entry) == 0x440);
    assert!(core::mem::offset_of!(Token, p_claim_attributes) == 0x448);
    assert!(core::mem::offset_of!(Token, trust_level_sid) == 0x450);
    assert!(core::mem::offset_of!(Token, trust_linked_token) == 0x458);
    assert!(core::mem::offset_of!(Token, integrity_level_sid_value) == 0x460);
    assert!(core::mem::offset_of!(Token, token_sid_values) == 0x468);
    assert!(core::mem::offset_of!(Token, index_entry) == 0x470);
    assert!(core::mem::offset_of!(Token, diagnostic_info) == 0x478);
    assert!(core::mem::offset_of!(Token, bno_isolation_handles_entry) == 0x480);
    assert!(core::mem::offset_of!(Token, session_object) == 0x488);
    assert!(core::mem::offset_of!(Token, variable_part) == 0x490);
};

/// `_TOKEN_SOURCE` (0x10 bytes).
#[repr(C)]
pub struct TokenSource {
    pub source_name: [Field<i8>; 8],
    pub source_identifier: Luid,
}

unsafe impl NtStruct for TokenSource {}

const _: () = {
    assert!(core::mem::size_of::<TokenSource>() == 0x10);
    assert!(core::mem::offset_of!(TokenSource, source_name) == 0x0);
    assert!(core::mem::offset_of!(TokenSource, source_identifier) == 0x8);
};

/// `_SEP_TOKEN_PRIVILEGES` (0x18 bytes).
#[repr(C)]
pub struct SepTokenPrivileges {
    pub present: Field<u64>,
    pub enabled: Field<u64>,
    pub enabled_by_default: Field<u64>,
}

unsafe impl NtStruct for SepTokenPrivileges {}

const _: () = {
    assert!(core::mem::size_of::<SepTokenPrivileges>() == 0x18);
    assert!(core::mem::offset_of!(SepTokenPrivileges, present) == 0x0);
    assert!(core::mem::offset_of!(SepTokenPrivileges, enabled) == 0x8);
    assert!(core::mem::offset_of!(SepTokenPrivileges, enabled_by_default) == 0x10);
};

/// `_SEP_AUDIT_POLICY` (0x20 bytes).
#[repr(C)]
pub struct SepAuditPolicy {
    pub adt_token_policy: TokenAuditPolicy,
    pub policy_set_status: Field<u8>,
}

unsafe impl NtStruct for SepAuditPolicy {}

const _: () = {
    assert!(core::mem::size_of::<SepAuditPolicy>() == 0x20);
    assert!(core::mem::offset_of!(SepAuditPolicy, adt_token_policy) == 0x0);
    assert!(core::mem::offset_of!(SepAuditPolicy, policy_set_status) == 0x1f);
};

/// `_TOKEN_AUDIT_POLICY` (0x1f bytes).
#[repr(C)]
pub struct TokenAuditPolicy {
    pub per_user_policy: [Field<u8>; 31],
}

unsafe impl NtStruct for TokenAuditPolicy {}

const _: () = {
    assert!(core::mem::size_of::<TokenAuditPolicy>() == 0x1f);
    assert!(core::mem::offset_of!(TokenAuditPolicy, per_user_policy) == 0x0);
};

/// `_TOKEN_TYPE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct TokenType(pub i32);

impl TokenType {
    pub const TOKEN_PRIMARY: Self = Self(1);
    pub const TOKEN_IMPERSONATION: Self = Self(2);
}

impl GuestScalar for TokenType {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_SECURITY_IMPERSONATION_LEVEL`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct SecurityImpersonationLevel(pub i32);

impl SecurityImpersonationLevel {
    pub const SECURITY_ANONYMOUS: Self = Self(0);
    pub const SECURITY_IDENTIFICATION: Self = Self(1);
    pub const SECURITY_IMPERSONATION: Self = Self(2);
    pub const SECURITY_DELEGATION: Self = Self(3);
}

impl GuestScalar for SecurityImpersonationLevel {
    const SIZE: u64 = 4;
    #[inline(always)]
    fn from_bits(bits: u64) -> Self {
        Self(bits as u32 as i32)
    }
    #[inline(always)]
    fn to_bits(self) -> u64 {
        self.0 as u32 as u64
    }
}

/// `_SID_AND_ATTRIBUTES_HASH` (0x110 bytes).
#[repr(C)]
pub struct SidAndAttributesHash {
    pub sid_count: Field<u32>,
    _pad_4: Reserved<0x4>,
    /// -> `_SID_AND_ATTRIBUTES`
    pub sid_attr: Field<u64>,
    pub hash: [Field<u64>; 32],
}

unsafe impl NtStruct for SidAndAttributesHash {}

const _: () = {
    assert!(core::mem::size_of::<SidAndAttributesHash>() == 0x110);
    assert!(core::mem::offset_of!(SidAndAttributesHash, sid_count) == 0x0);
    assert!(core::mem::offset_of!(SidAndAttributesHash, sid_attr) == 0x8);
    assert!(core::mem::offset_of!(SidAndAttributesHash, hash) == 0x10);
};

/// `_SECURITY_DESCRIPTOR` (0x28 bytes).
#[repr(C)]
pub struct SecurityDescriptor {
    pub revision: Field<u8>,
    pub sbz1: Field<u8>,
    pub control: Field<u16>,
    _pad_4: Reserved<0x4>,
    /// -> `void`
    pub owner: Field<u64>,
    /// -> `void`
    pub group: Field<u64>,
    /// -> `_ACL`
    pub sacl: Field<u64>,
    /// -> `_ACL`
    pub dacl: Field<u64>,
}

unsafe impl NtStruct for SecurityDescriptor {}

const _: () = {
    assert!(core::mem::size_of::<SecurityDescriptor>() == 0x28);
    assert!(core::mem::offset_of!(SecurityDescriptor, revision) == 0x0);
    assert!(core::mem::offset_of!(SecurityDescriptor, sbz1) == 0x1);
    assert!(core::mem::offset_of!(SecurityDescriptor, control) == 0x2);
    assert!(core::mem::offset_of!(SecurityDescriptor, owner) == 0x8);
    assert!(core::mem::offset_of!(SecurityDescriptor, group) == 0x10);
    assert!(core::mem::offset_of!(SecurityDescriptor, sacl) == 0x18);
    assert!(core::mem::offset_of!(SecurityDescriptor, dacl) == 0x20);
};

/// `_SECURITY_DESCRIPTOR_RELATIVE` (0x14 bytes).
#[repr(C)]
pub struct SecurityDescriptorRelative {
    pub revision: Field<u8>,
    pub sbz1: Field<u8>,
    pub control: Field<u16>,
    pub owner: Field<u32>,
    pub group: Field<u32>,
    pub sacl: Field<u32>,
    pub dacl: Field<u32>,
}

unsafe impl NtStruct for SecurityDescriptorRelative {}

const _: () = {
    assert!(core::mem::size_of::<SecurityDescriptorRelative>() == 0x14);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, revision) == 0x0);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, sbz1) == 0x1);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, control) == 0x2);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, owner) == 0x4);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, group) == 0x8);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, sacl) == 0xc);
    assert!(core::mem::offset_of!(SecurityDescriptorRelative, dacl) == 0x10);
};

/// `_SID` (0xc bytes).
#[repr(C)]
pub struct Sid {
    pub revision: Field<u8>,
    pub sub_authority_count: Field<u8>,
    pub identifier_authority: SidIdentifierAuthority,
    pub sub_authority: [Field<u32>; 1],
}

unsafe impl NtStruct for Sid {}

const _: () = {
    assert!(core::mem::size_of::<Sid>() == 0xc);
    assert!(core::mem::offset_of!(Sid, revision) == 0x0);
    assert!(core::mem::offset_of!(Sid, sub_authority_count) == 0x1);
    assert!(core::mem::offset_of!(Sid, identifier_authority) == 0x2);
    assert!(core::mem::offset_of!(Sid, sub_authority) == 0x8);
};

/// `_SID_IDENTIFIER_AUTHORITY` (0x6 bytes).
#[repr(C)]
pub struct SidIdentifierAuthority {
    pub value: [Field<u8>; 6],
}

unsafe impl NtStruct for SidIdentifierAuthority {}

const _: () = {
    assert!(core::mem::size_of::<SidIdentifierAuthority>() == 0x6);
    assert!(core::mem::offset_of!(SidIdentifierAuthority, value) == 0x0);
};

/// `_ACL` (0x8 bytes).
#[repr(C)]
pub struct Acl {
    pub acl_revision: Field<u8>,
    pub sbz1: Field<u8>,
    pub acl_size: Field<u16>,
    pub ace_count: Field<u16>,
    pub sbz2: Field<u16>,
}

unsafe impl NtStruct for Acl {}

const _: () = {
    assert!(core::mem::size_of::<Acl>() == 0x8);
    assert!(core::mem::offset_of!(Acl, acl_revision) == 0x0);
    assert!(core::mem::offset_of!(Acl, sbz1) == 0x1);
    assert!(core::mem::offset_of!(Acl, acl_size) == 0x2);
    assert!(core::mem::offset_of!(Acl, ace_count) == 0x4);
    assert!(core::mem::offset_of!(Acl, sbz2) == 0x6);
};

/// `_ACCESS_STATE` (0xa0 bytes).
#[repr(C)]
pub struct AccessState {
    pub operation_id: Luid,
    pub security_evaluated: Field<u8>,
    pub generate_audit: Field<u8>,
    pub generate_on_close: Field<u8>,
    pub privileges_allocated: Field<u8>,
    pub flags: Field<u32>,
    pub remaining_desired_access: Field<u32>,
    pub previously_granted_access: Field<u32>,
    pub original_desired_access: Field<u32>,
    _pad_1c: Reserved<0x4>,
    pub subject_security_context: SecuritySubjectContext,
    /// -> `void`
    pub security_descriptor: Field<u64>,
    /// -> `void`
    pub aux_data: Field<u64>,
    pub privileges: AccessStatePrivileges,
    pub audit_privileges: Field<u8>,
    _pad_7d: Reserved<0x3>,
    pub object_name: UnicodeString,
    pub object_type_name: UnicodeString,
}

unsafe impl NtStruct for AccessState {}

const _: () = {
    assert!(core::mem::size_of::<AccessState>() == 0xa0);
    assert!(core::mem::offset_of!(AccessState, operation_id) == 0x0);
    assert!(core::mem::offset_of!(AccessState, security_evaluated) == 0x8);
    assert!(core::mem::offset_of!(AccessState, generate_audit) == 0x9);
    assert!(core::mem::offset_of!(AccessState, generate_on_close) == 0xa);
    assert!(core::mem::offset_of!(AccessState, privileges_allocated) == 0xb);
    assert!(core::mem::offset_of!(AccessState, flags) == 0xc);
    assert!(core::mem::offset_of!(AccessState, remaining_desired_access) == 0x10);
    assert!(core::mem::offset_of!(AccessState, previously_granted_access) == 0x14);
    assert!(core::mem::offset_of!(AccessState, original_desired_access) == 0x18);
    assert!(core::mem::offset_of!(AccessState, subject_security_context) == 0x20);
    assert!(core::mem::offset_of!(AccessState, security_descriptor) == 0x40);
    assert!(core::mem::offset_of!(AccessState, aux_data) == 0x48);
    assert!(core::mem::offset_of!(AccessState, privileges) == 0x50);
    assert!(core::mem::offset_of!(AccessState, audit_privileges) == 0x7c);
    assert!(core::mem::offset_of!(AccessState, object_name) == 0x80);
    assert!(core::mem::offset_of!(AccessState, object_type_name) == 0x90);
};

/// `_SECURITY_SUBJECT_CONTEXT` (0x20 bytes).
#[repr(C)]
pub struct SecuritySubjectContext {
    /// -> `void`
    pub client_token: Field<u64>,
    pub impersonation_level: Field<SecurityImpersonationLevel>,
    _pad_c: Reserved<0x4>,
    /// -> `void`
    pub primary_token: Field<u64>,
    /// -> `void`
    pub process_audit_id: Field<u64>,
}

unsafe impl NtStruct for SecuritySubjectContext {}

const _: () = {
    assert!(core::mem::size_of::<SecuritySubjectContext>() == 0x20);
    assert!(core::mem::offset_of!(SecuritySubjectContext, client_token) == 0x0);
    assert!(core::mem::offset_of!(SecuritySubjectContext, impersonation_level) == 0x8);
    assert!(core::mem::offset_of!(SecuritySubjectContext, primary_token) == 0x10);
    assert!(core::mem::offset_of!(SecuritySubjectContext, process_audit_id) == 0x18);
};

/// `_ACCESS_STATE::Privileges` (0x2c bytes).
///
/// Membros sobrepostos (uniões anônimas do C) ficam nas vistas
/// `AccessStatePrivilegesView1`, alcançada por `Deref`.
#[repr(C)]
pub struct AccessStatePrivileges {
    pub initial_privilege_set: InitialPrivilegeSet,
}

/// Vista 1 de `_ACCESS_STATE::Privileges` (membros sobrepostos à vista anterior).
#[repr(C)]
pub struct AccessStatePrivilegesView1 {
    pub privilege_set: PrivilegeSet,
    _pad_14: Reserved<0x18>,
}

impl core::ops::Deref for AccessStatePrivileges {
    type Target = AccessStatePrivilegesView1;
    #[inline(always)]
    fn deref(&self) -> &AccessStatePrivilegesView1 {
        // SAFETY: vistas do mesmo objeto, mesmo tamanho e alinhamento, só de células.
        unsafe { &*(self as *const Self).cast::<AccessStatePrivilegesView1>() }
    }
}

unsafe impl NtStruct for AccessStatePrivileges {}

const _: () = {
    assert!(core::mem::size_of::<AccessStatePrivileges>() == 0x2c);
    assert!(core::mem::offset_of!(AccessStatePrivileges, initial_privilege_set) == 0x0);
    assert!(core::mem::size_of::<AccessStatePrivilegesView1>() == 0x2c);
    assert!(core::mem::align_of::<AccessStatePrivilegesView1>() == core::mem::align_of::<AccessStatePrivileges>());
    assert!(core::mem::offset_of!(AccessStatePrivilegesView1, privilege_set) == 0x0);
};

/// `_INITIAL_PRIVILEGE_SET` (0x2c bytes).
#[repr(C)]
pub struct InitialPrivilegeSet {
    pub privilege_count: Field<u32>,
    pub control: Field<u32>,
    pub privilege: [LuidAndAttributes; 3],
}

unsafe impl NtStruct for InitialPrivilegeSet {}

const _: () = {
    assert!(core::mem::size_of::<InitialPrivilegeSet>() == 0x2c);
    assert!(core::mem::offset_of!(InitialPrivilegeSet, privilege_count) == 0x0);
    assert!(core::mem::offset_of!(InitialPrivilegeSet, control) == 0x4);
    assert!(core::mem::offset_of!(InitialPrivilegeSet, privilege) == 0x8);
};

/// `_LUID_AND_ATTRIBUTES` (0xc bytes).
#[repr(C)]
pub struct LuidAndAttributes {
    pub luid: Luid,
    pub attributes: Field<u32>,
}

unsafe impl NtStruct for LuidAndAttributes {}

const _: () = {
    assert!(core::mem::size_of::<LuidAndAttributes>() == 0xc);
    assert!(core::mem::offset_of!(LuidAndAttributes, luid) == 0x0);
    assert!(core::mem::offset_of!(LuidAndAttributes, attributes) == 0x8);
};

/// `_PRIVILEGE_SET` (0x14 bytes).
#[repr(C)]
pub struct PrivilegeSet {
    pub privilege_count: Field<u32>,
    pub control: Field<u32>,
    pub privilege: [LuidAndAttributes; 1],
}

unsafe impl NtStruct for PrivilegeSet {}

const _: () = {
    assert!(core::mem::size_of::<PrivilegeSet>() == 0x14);
    assert!(core::mem::offset_of!(PrivilegeSet, privilege_count) == 0x0);
    assert!(core::mem::offset_of!(PrivilegeSet, control) == 0x4);
    assert!(core::mem::offset_of!(PrivilegeSet, privilege) == 0x8);
};

/// `_AUX_ACCESS_DATA` (0xe0 bytes).
#[repr(C)]
pub struct AuxAccessData {
    /// -> `_PRIVILEGE_SET`
    pub privileges_used: Field<u64>,
    pub generic_mapping: GenericMapping,
    pub accesses_to_audit: Field<u32>,
    pub maximum_audit_mask: Field<u32>,
    pub transaction_id: Guid,
    /// -> `void`
    pub new_security_descriptor: Field<u64>,
    /// -> `void`
    pub existing_security_descriptor: Field<u64>,
    /// -> `void`
    pub parent_security_descriptor: Field<u64>,
    /// -> `fn`
    pub de_ref_security_descriptor: Field<u64>,
    /// -> `void`
    pub sd_lock: Field<u64>,
    pub access_reasons: AccessReasons,
    pub generate_staging_events: Field<u8>,
    _pad_d9: Reserved<0x7>,
}

unsafe impl NtStruct for AuxAccessData {}

const _: () = {
    assert!(core::mem::size_of::<AuxAccessData>() == 0xe0);
    assert!(core::mem::offset_of!(AuxAccessData, privileges_used) == 0x0);
    assert!(core::mem::offset_of!(AuxAccessData, generic_mapping) == 0x8);
    assert!(core::mem::offset_of!(AuxAccessData, accesses_to_audit) == 0x18);
    assert!(core::mem::offset_of!(AuxAccessData, maximum_audit_mask) == 0x1c);
    assert!(core::mem::offset_of!(AuxAccessData, transaction_id) == 0x20);
    assert!(core::mem::offset_of!(AuxAccessData, new_security_descriptor) == 0x30);
    assert!(core::mem::offset_of!(AuxAccessData, existing_security_descriptor) == 0x38);
    assert!(core::mem::offset_of!(AuxAccessData, parent_security_descriptor) == 0x40);
    assert!(core::mem::offset_of!(AuxAccessData, de_ref_security_descriptor) == 0x48);
    assert!(core::mem::offset_of!(AuxAccessData, sd_lock) == 0x50);
    assert!(core::mem::offset_of!(AuxAccessData, access_reasons) == 0x58);
    assert!(core::mem::offset_of!(AuxAccessData, generate_staging_events) == 0xd8);
};

/// `_ACCESS_REASONS` (0x80 bytes).
#[repr(C)]
pub struct AccessReasons {
    pub data: [Field<u32>; 32],
}

unsafe impl NtStruct for AccessReasons {}

const _: () = {
    assert!(core::mem::size_of::<AccessReasons>() == 0x80);
    assert!(core::mem::offset_of!(AccessReasons, data) == 0x0);
};

/// `_SECURITY_QUALITY_OF_SERVICE` (0xc bytes).
#[repr(C)]
pub struct SecurityQualityOfService {
    pub length: Field<u32>,
    pub impersonation_level: Field<SecurityImpersonationLevel>,
    pub context_tracking_mode: Field<u8>,
    pub effective_only: Field<u8>,
    _pad_a: Reserved<0x2>,
}

unsafe impl NtStruct for SecurityQualityOfService {}

const _: () = {
    assert!(core::mem::size_of::<SecurityQualityOfService>() == 0xc);
    assert!(core::mem::offset_of!(SecurityQualityOfService, length) == 0x0);
    assert!(core::mem::offset_of!(SecurityQualityOfService, impersonation_level) == 0x4);
    assert!(core::mem::offset_of!(SecurityQualityOfService, context_tracking_mode) == 0x8);
    assert!(core::mem::offset_of!(SecurityQualityOfService, effective_only) == 0x9);
};

/// `_SID_AND_ATTRIBUTES` (0x10 bytes).
#[repr(C)]
pub struct SidAndAttributes {
    /// -> `void`
    pub sid: Field<u64>,
    pub attributes: Field<u32>,
    _pad_c: Reserved<0x4>,
}

unsafe impl NtStruct for SidAndAttributes {}

const _: () = {
    assert!(core::mem::size_of::<SidAndAttributes>() == 0x10);
    assert!(core::mem::offset_of!(SidAndAttributes, sid) == 0x0);
    assert!(core::mem::offset_of!(SidAndAttributes, attributes) == 0x8);
};

/// `_SEP_SILOSTATE` (0x30 bytes).
#[repr(C)]
pub struct SepSilostate {
    /// -> `_SEP_LOGON_SESSION_REFERENCES`
    pub system_logon_session: Field<u64>,
    /// -> `_SEP_LOGON_SESSION_REFERENCES`
    pub anonymous_logon_session: Field<u64>,
    /// -> `void`
    pub anonymous_logon_token: Field<u64>,
    /// -> `void`
    pub anonymous_logon_token_no_everyone: Field<u64>,
    /// -> `_UNICODE_STRING`
    pub unc_system_paths: Field<u64>,
    /// -> `_CI_NGEN_PATHS`
    pub ngen_paths: Field<u64>,
}

unsafe impl NtStruct for SepSilostate {}

const _: () = {
    assert!(core::mem::size_of::<SepSilostate>() == 0x30);
    assert!(core::mem::offset_of!(SepSilostate, system_logon_session) == 0x0);
    assert!(core::mem::offset_of!(SepSilostate, anonymous_logon_session) == 0x8);
    assert!(core::mem::offset_of!(SepSilostate, anonymous_logon_token) == 0x10);
    assert!(core::mem::offset_of!(SepSilostate, anonymous_logon_token_no_everyone) == 0x18);
    assert!(core::mem::offset_of!(SepSilostate, unc_system_paths) == 0x20);
    assert!(core::mem::offset_of!(SepSilostate, ngen_paths) == 0x28);
};

/// `_SEP_RM_LSA_CONNECTION_STATE` (0x50 bytes).
#[repr(C)]
pub struct SepRmLsaConnectionState {
    /// -> `void`
    pub lsa_process_handle: Field<u64>,
    /// -> `void`
    pub lsa_command_port_handle: Field<u64>,
    /// -> `void`
    pub sep_rm_thread_handle: Field<u64>,
    /// -> `void`
    pub rm_command_port_handle: Field<u64>,
    /// -> `void`
    pub rm_command_server_port_handle: Field<u64>,
    /// -> `void`
    pub lsa_command_port_section_handle: Field<u64>,
    pub lsa_command_port_section_size: LargeInteger,
    /// -> `void`
    pub lsa_view_port_memory: Field<u64>,
    /// -> `void`
    pub rm_view_port_memory: Field<u64>,
    pub lsa_command_port_memory_delta: Field<i32>,
    pub lsa_command_port_active: Field<u8>,
    _pad_4d: Reserved<0x3>,
}

unsafe impl NtStruct for SepRmLsaConnectionState {}

const _: () = {
    assert!(core::mem::size_of::<SepRmLsaConnectionState>() == 0x50);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_process_handle) == 0x0);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_command_port_handle) == 0x8);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, sep_rm_thread_handle) == 0x10);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, rm_command_port_handle) == 0x18);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, rm_command_server_port_handle) == 0x20);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_command_port_section_handle) == 0x28);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_command_port_section_size) == 0x30);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_view_port_memory) == 0x38);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, rm_view_port_memory) == 0x40);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_command_port_memory_delta) == 0x48);
    assert!(core::mem::offset_of!(SepRmLsaConnectionState, lsa_command_port_active) == 0x4c);
};

/// `_TOKEN_ACCESS_INFORMATION` (0x58 bytes).
#[repr(C)]
pub struct TokenAccessInformation {
    /// -> `_SID_AND_ATTRIBUTES_HASH`
    pub sid_hash: Field<u64>,
    /// -> `_SID_AND_ATTRIBUTES_HASH`
    pub restricted_sid_hash: Field<u64>,
    /// -> `_TOKEN_PRIVILEGES`
    pub privileges: Field<u64>,
    pub authentication_id: Luid,
    pub token_type: Field<TokenType>,
    pub impersonation_level: Field<SecurityImpersonationLevel>,
    pub mandatory_policy: TokenMandatoryPolicy,
    pub flags: Field<u32>,
    pub app_container_number: Field<u32>,
    _pad_34: Reserved<0x4>,
    /// -> `void`
    pub package_sid: Field<u64>,
    /// -> `_SID_AND_ATTRIBUTES_HASH`
    pub capabilities_hash: Field<u64>,
    /// -> `void`
    pub trust_level_sid: Field<u64>,
    /// -> `void`
    pub security_attributes: Field<u64>,
}

unsafe impl NtStruct for TokenAccessInformation {}

const _: () = {
    assert!(core::mem::size_of::<TokenAccessInformation>() == 0x58);
    assert!(core::mem::offset_of!(TokenAccessInformation, sid_hash) == 0x0);
    assert!(core::mem::offset_of!(TokenAccessInformation, restricted_sid_hash) == 0x8);
    assert!(core::mem::offset_of!(TokenAccessInformation, privileges) == 0x10);
    assert!(core::mem::offset_of!(TokenAccessInformation, authentication_id) == 0x18);
    assert!(core::mem::offset_of!(TokenAccessInformation, token_type) == 0x20);
    assert!(core::mem::offset_of!(TokenAccessInformation, impersonation_level) == 0x24);
    assert!(core::mem::offset_of!(TokenAccessInformation, mandatory_policy) == 0x28);
    assert!(core::mem::offset_of!(TokenAccessInformation, flags) == 0x2c);
    assert!(core::mem::offset_of!(TokenAccessInformation, app_container_number) == 0x30);
    assert!(core::mem::offset_of!(TokenAccessInformation, package_sid) == 0x38);
    assert!(core::mem::offset_of!(TokenAccessInformation, capabilities_hash) == 0x40);
    assert!(core::mem::offset_of!(TokenAccessInformation, trust_level_sid) == 0x48);
    assert!(core::mem::offset_of!(TokenAccessInformation, security_attributes) == 0x50);
};

/// `_TOKEN_MANDATORY_POLICY` (0x4 bytes).
#[repr(C)]
pub struct TokenMandatoryPolicy {
    pub policy: Field<u32>,
}

unsafe impl NtStruct for TokenMandatoryPolicy {}

const _: () = {
    assert!(core::mem::size_of::<TokenMandatoryPolicy>() == 0x4);
    assert!(core::mem::offset_of!(TokenMandatoryPolicy, policy) == 0x0);
};

/// `_TOKEN_PRIVILEGES` (0x10 bytes).
#[repr(C)]
pub struct TokenPrivileges {
    pub privilege_count: Field<u32>,
    pub privileges: [LuidAndAttributes; 1],
}

unsafe impl NtStruct for TokenPrivileges {}

const _: () = {
    assert!(core::mem::size_of::<TokenPrivileges>() == 0x10);
    assert!(core::mem::offset_of!(TokenPrivileges, privilege_count) == 0x0);
    assert!(core::mem::offset_of!(TokenPrivileges, privileges) == 0x4);
};
