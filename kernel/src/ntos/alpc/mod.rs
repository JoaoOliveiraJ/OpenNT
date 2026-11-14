//! ALPC.
//!
//! Buffers, identidade de mensagens, recursos da comunicação (seções,
//! vistas, contextos de segurança e reservas), a referência da IOCP, a
//! espera retomável, os tipos do transporte e o lado servidor das portas de
//! modo usuário (`server`). O serviço de portas de usuário entra com
//! `ps/user/alpc`.

pub mod cancel_message;
pub mod completion_association;
pub mod completion_reference;
pub mod connect;
pub mod message;
pub mod resource;
pub mod kernel_entry;
pub mod kernel_wait;
pub mod legacy_service;
pub mod port_reference;
pub mod port_sections;
pub mod query_information;
pub mod query_message;
pub mod section_views;
pub mod security_contexts;
pub mod server;
pub mod small;
pub mod transport;
pub mod exports;
