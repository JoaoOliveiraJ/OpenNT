//! Inicialização do sistema — o `init` do NT.
//!
//! Boot em fases: fase 0 (núcleo mínimo) -> fase 1 (I/O, drivers, serviços
//! do Registry, PnP) -> laço principal com o escalonador. Aqui também mora a
//! tabela de exports do ntoskrnl.

pub mod boot_config;
pub mod main;
pub mod phase0;
pub mod phase1;
pub mod initial_process;
pub mod exports;
pub mod export_names;
pub mod native_export_layout;
