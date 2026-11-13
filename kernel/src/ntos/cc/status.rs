//! Falhas do Cache Manager e a conversão para o modelo do NT.
//!
//! As rotinas Cc do NT não devolvem erro: levantam a exceção com
//! ExRaiseStatus (falha de I/O de página, buffer de usuário inválido, falta
//! de recursos) e o driver de arquivo a captura no seu try/except. Aqui toda
//! rotina do assunto devolve [`CcResult`]: `Failure::Raise(status)` é o que o
//! NT levantaria. O adaptador do export entrega a exceção ao driver chamador
//! ([`into_export`]); um chamador Rust (FsRtlCopyRead) pode tratá-la como o
//! `except` do NT.

use crate::rtl::KernelError;

/// Falha de uma rotina do Cc.
#[derive(Debug)]
pub enum Failure {
    /// O NT levantaria este NTSTATUS (ExRaiseStatus).
    Raise(u32),
    /// Falha interna do kernel (inclui o sinal de transferência do SEH).
    Kernel(KernelError),
}

impl From<KernelError> for Failure {
    fn from(error: KernelError) -> Self {
        Failure::Kernel(error)
    }
}

pub type CcResult<T> = Result<T, Failure>;

/// Resultado de um export: `Raise` vira a exceção no driver chamador.
pub fn into_export(result: CcResult<u64>) -> Result<u64, KernelError> {
    match result {
        Ok(value) => Ok(value),
        Err(Failure::Raise(status)) => crate::ntos::rtl::exceptions::raise_status(status, 0, 0, 1),
        Err(Failure::Kernel(error)) => Err(error),
    }
}

/// FsRtlNormalizeNtstatus(status, generic): o status esperado passa, os
/// demais viram `generic` (`fsrtl::ntstatus`).
pub fn normalize(status: u32, generic: u32) -> u32 {
    crate::ntos::fsrtl::ntstatus::normalize_ntstatus(status, generic)
}

/// O que CcCopyRead/CcCopyWrite levantam para uma falha de I/O de página:
/// FsRtlNormalizeNtstatus(status, STATUS_UNEXPECTED_IO_ERROR).
pub fn copy_failure(status: u32) -> Failure {
    Failure::Raise(normalize(status, super::layout::status::UNEXPECTED_IO_ERROR))
}

/// Endereço do chamador sem tradução durante uma cópia: o filtro do
/// CcCopyRead/CcCopyWrite converte o ACCESS_VIOLATION em
/// STATUS_INVALID_USER_BUFFER.
pub fn user_buffer_failure() -> Failure {
    Failure::Raise(super::layout::status::INVALID_USER_BUFFER)
}
