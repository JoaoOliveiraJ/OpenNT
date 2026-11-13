//! Política de separação de estado capturada no boot.
//!
//! A consulta não ativa isolamento de arquivos/hives e não relê o Registro.
//! CmControlVector copia até quatro bytes do valor `Enabled`; bytes ausentes
//! ficam zero. Até o Registro ser transcrito (fase 5), a hive deste boot não
//! tem a chave, o que resulta em 0 — o mesmo valor que o original obtém.

use core::sync::atomic::{AtomicI64, Ordering};

use crate::rtl::KernelError;

pub const POLICY_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\Policy";

/// -1 = não inicializado; caso contrário, o DWORD capturado.
static ENABLED_VALUE: AtomicI64 = AtomicI64::new(-1);

/// Leitor do valor (instalado pelo Registro na fase 5).
pub type ValueReader = fn(&str, &str) -> Option<alloc::vec::Vec<u8>>;

pub fn init(reader: Option<ValueReader>) {
    if ENABLED_VALUE.load(Ordering::Relaxed) >= 0 {
        return;
    }
    let mut enabled = 0u32;
    if let Some(data) = reader.and_then(|read| read(POLICY_KEY, "Enabled")) {
        for (index, &byte) in data.iter().take(4).enumerate() {
            enabled |= (byte as u32) << (index * 8);
        }
    }
    ENABLED_VALUE.store(enabled as i64, Ordering::Relaxed);
}

/// BOOLEAN: o DWORD capturado comparado com zero (CmIsStateSeparationEnabled).
pub fn is_enabled() -> Result<bool, KernelError> {
    match ENABLED_VALUE.load(Ordering::Relaxed) {
        -1 => Err(KernelError::new("StateSeparation: boot policy not initialized")),
        value => Ok(value != 0),
    }
}

/// O boot mantém o modelo comum de arquivos/hives: recusa Factory OS antes
/// de carregar drivers ou publicar capacidades sem enforcement real.
pub fn require_supported_boot() -> Result<(), KernelError> {
    if is_enabled()? {
        return Err(KernelError::new(
            "StateSeparation: Enabled requires filesystem and registry enforcement unavailable in this boot",
        ));
    }
    Ok(())
}
