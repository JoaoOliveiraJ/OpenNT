//! Operações de arquivo do I/O Manager: leitura, escrita, consulta, exclusão,
//! informação, ciclo de vida, requisições, os serviços Zw de arquivo, a
//! consulta de atributos estendidos (NtQueryEaFile), os serviços de modo
//! usuário sobre IRP, a criação de pipes e mailslots e a contagem de
//! keep-alive dos processos por arquivo.

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
pub mod irp_service;
pub mod pipe_mailslot;
pub mod keep_alive;
