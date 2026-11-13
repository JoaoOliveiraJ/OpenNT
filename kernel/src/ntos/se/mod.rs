//! Security Reference Monitor (Se).

use crate::ntos::inc::types::{Field, NtStruct};

/// Célula escalar passada por ponteiro (PULONG, PBOOLEAN, PHANDLE, PVOID*,
/// globais de dado): a célula no endereço, como `*Saida = valor` no C.
pub(crate) fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: o export recebe um ponteiro de saída vivo e alinhado ao tipo,
    // como o NT; ponteiros de modo usuário usam `probe_get`/`probe_set`.
    unsafe { Field::<T>::at(address) }
}

pub mod model;
pub mod object_security;
pub mod security_attributes;
pub mod capability;
pub mod token;
pub mod acl;
pub mod descriptor;
pub mod sid;
pub mod inherit_descriptor;
pub mod policy_descriptor;
pub mod query_descriptor;
pub mod runtime_signing_policy;
pub mod platform_manifest;
pub mod secure_boot_policy;
pub mod se_exports;
pub mod package_claims;
pub mod package_identity;
pub mod code_integrity;
pub mod code_integrity_information;
pub mod secure_boot_information;
pub mod image_verification;
pub mod subject_context;
pub mod audit;
pub mod privilege;
pub mod access_check;
pub mod assign;
pub mod exports;
