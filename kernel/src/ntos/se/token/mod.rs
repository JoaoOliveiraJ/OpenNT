//! Tokens de acesso: o objeto token, duplicação, consulta, abertura,
//! referência, associação, estatísticas, handles e tokens de thread e
//! anônimos.

pub mod tokens;
pub mod statistics;
pub mod capability_access;
pub mod access;
pub mod reference;
pub mod membership;
pub mod handles;
pub mod thread;
pub mod anonymous;
pub mod duplicate;
pub mod query;
pub mod open_process;
pub mod impersonate_anonymous;
