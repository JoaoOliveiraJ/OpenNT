//! Executive (Ex) — `system32/ntos/ex/`.

pub mod syscalls;
pub mod push_lock;
pub mod rundown;
pub mod callback_security;
pub mod lookaside;
pub mod pool_allocation;
pub mod slist;
pub mod spin_lock;
pub mod resource;
pub mod callbacks;
pub mod unblock_push_lock;
pub mod pool_quota;
pub mod enum_handles;
pub mod service_table;
pub mod license;
pub mod wnf;
pub mod boot_environment_information;
pub mod boot_environment;
pub mod service_abi;
pub mod system_services;
pub mod exports;
