//! Runtime do kernel: impressão, locks, erros com NTSTATUS e tempo.

#[macro_use]
pub mod print;
pub mod error;
pub mod sync;
pub mod text;
pub mod time;

pub use error::KernelError;
pub use sync::{SharedLock, SpinLock};
