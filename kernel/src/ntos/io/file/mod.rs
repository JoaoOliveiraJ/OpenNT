//! Operações de arquivo do I/O Manager: leitura, escrita, consulta, exclusão,
//! informação, ciclo de vida, requisições, os serviços Zw de arquivo e a
//! consulta de atributos estendidos (NtQueryEaFile).

pub mod read;
pub mod write;
pub mod query;
pub mod delete;
pub mod information;
pub mod lifetime;
pub mod request;
pub mod convert_handle;
pub mod native_security;
pub mod zw;
pub mod ea;
