//! Runtime do kernel: impressão, locks, erros com NTSTATUS e tempo.

#[macro_use]
pub mod print;
pub mod error;
pub mod ptr_map;
pub mod sync;
pub mod text;
pub mod time;

pub use error::KernelError;
pub use ptr_map::PtrMap;
pub use sync::{SharedLock, SharedLockGuard, SpinLock};
