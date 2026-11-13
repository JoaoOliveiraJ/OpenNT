//! Ponto de entrada interno da atualização WNF.
//!
//! Consulta e escrita pertencem à única instância do serviço WNF.

pub use crate::ntos::ex::wnf::service::{query, update};
