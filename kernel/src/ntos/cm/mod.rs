//! Configuration Manager (Cm).
//!
//! Hive em memória, objetos de chave, serviços e provedores de boot.

pub mod callbacks;
pub mod check_registry_key;
pub mod cng_defaults;
pub mod computer_name;
pub mod crypto_defaults;
pub mod feature_usage;
pub mod feature_usage_buffer;
pub mod feature_usage_delivery;
pub mod hw_description;
pub mod key;
pub mod service;
pub mod persisted_state;
pub mod physical_memory_resources;
pub mod primitive_provider;
pub mod registry;
pub mod state_separation;
pub mod value_information;
pub mod wnf_defaults;
pub mod exports;
