//! SeILSigningPolicyRuntime — `system32/ntos/se/runtime-signing-policy.js`.
//!
//! O byte pertence à memória nativa do kernel: o setter da CI e os
//! consumidores leem a mesma célula, sem cópia de estado em Rust.

use crate::hal::amd64::runtime_signing_policy as storage;
use crate::ntos::mm::kernel_address;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub fn address() -> Result<u64, KernelError> {
    kernel_address::virtual_address(storage::entry(1).unwrap_or(0))
}

pub fn read() -> Result<u8, KernelError> {
    Ok(guest::read8(address()?))
}

/// SepSetRuntimeUpdatableSigningLevel (rotina privada, fora dos exports).
pub fn callback_address() -> Result<u64, KernelError> {
    kernel_address::virtual_address(storage::entry(0).unwrap_or(0))
}
