//! Erro do kernel com NTSTATUS opcional — o equivalente de
//! `Object.assign(new Error(mensagem), { status })` usado em todo o original.

use alloc::string::String;
use core::fmt;

use crate::ntos::inc::status;

#[derive(Debug, Clone)]
pub struct KernelError {
    pub message: String,
    /// NTSTATUS associado; `STATUS_UNSUCCESSFUL` quando o chamador não informa.
    pub status: u32,
}

impl KernelError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), status: status::STATUS_UNSUCCESSFUL }
    }

    pub fn with_status(message: impl Into<String>, status: u32) -> Self {
        Self { message: message.into(), status }
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

pub type KernelResult<T> = Result<T, KernelError>;
