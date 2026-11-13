//! Ponto de entrada interno da atualização WNF — `system32/ntos/ex/wnf-update.js`.
//!
//! Consulta e escrita pertencem à única instância do serviço WNF.

pub use crate::ntos::ex::wnf::service::{query, update};
