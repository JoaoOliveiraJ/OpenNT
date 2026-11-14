//! Suítes de autoteste do kernel.
//!
//! Só entram no fluxo de boot com `--kernel-test-scope` diferente de `none`.

pub mod self_test;
pub mod phase3;
pub mod phase4;
pub mod phase5;
pub mod phase6;
pub mod executive_support;
pub mod object_header;
pub mod phase7;
pub mod multiprocess;
pub mod executable_code;
pub mod system_allocations;
pub mod system_images;
pub mod user_half;
pub mod resource_search_fixtures;
pub mod cc_fixture;
pub mod rtl_atom_heap_nls;
pub mod device_removal;
pub mod rtl_ranges_resources;
pub mod platform_support;
pub mod power_io_support;
pub mod file_system_mount;
pub mod fsrtl_fs_support;
pub mod boot_drivers;
