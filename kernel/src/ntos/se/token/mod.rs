//! Tokens de acesso: o objeto token, duplicação, consulta (por handle e pelo
//! kernel), abertura, referência, associação, estatísticas, handles, tokens
//! de thread e anônimos e o ajuste de privilégios.

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
pub mod information;
pub mod open_process;
pub mod impersonate_anonymous;
pub mod impersonation;
pub mod filter;
pub mod attributes;
pub mod adjust;
