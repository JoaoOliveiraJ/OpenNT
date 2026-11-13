//! I/O Manager (Io) — `system32/ntos/io/`.
//!
//! Fase 3: work items. O restante do I/O Manager entra na fase 4.

pub mod work_items;
pub mod io_manager;
pub mod device_resources;
pub mod cancel;
pub mod small;
pub mod threads;
pub mod controller;
pub mod completion;
pub mod file;
pub mod transfer;
pub mod kernel_ea;
pub mod kernel_fs_control;
pub mod ndr;
pub mod lrpc;
pub mod retained_irp;
pub mod pnp;
pub mod device_control;
pub mod volume_dos_name;
pub mod volume_parameters;
pub mod exports;
pub mod lifecycle;
pub mod irp_builder;
