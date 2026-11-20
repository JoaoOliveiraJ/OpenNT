//! Licenciamento do Executive (ZwQueryLicenseValue): dados de licença, cache,
//! índice, estado, Registry e boot; o canal cifrado do
//! SystemPolicyInformation (classe 134).

mod layout;
pub mod values;
pub mod cache;
pub mod data;
pub mod state;
pub mod registry;
pub mod index;
pub mod special;
pub mod service;
pub mod boot;
pub mod update;
pub mod policy_cipher;
pub mod system_policy;
