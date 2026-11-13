//! Handles por tipo de objeto: processo, thread, arquivo, segurança e
//! namespace, além dos handles dos objetos inseridos por ObInsertObject.

pub mod thread;
pub mod security;
pub mod file;
pub mod namespace;
pub mod process;
pub mod inserted;
