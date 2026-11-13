//! SystemCodeIntegrityInformation (103).
//!
//! Compartilhado pelos exports de kernel e pela chamada de usuário. A ABI tem
//! dois ULONGs: Length e CodeIntegrityOptions.

use crate::ntos::ps::user_probe;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::SystemCodeintegrityInformation;
use core::mem::offset_of;

const INFORMATION_BYTE_LENGTH: u32 = 8;

pub type CodeIntegrityQuery = fn(u64, u32, u64) -> Result<u32, KernelError>;

/// A CI publica esta consulta junto com a fiscalização real do carregador.
static INSTALLED: SpinLock<Option<CodeIntegrityQuery>> = SpinLock::new(None);

pub fn install_query(query: CodeIntegrityQuery) -> Result<(), KernelError> {
    let mut installed = INSTALLED.lock();
    if installed.is_some() {
        return Err(KernelError::new("invalid CI information provider registration"));
    }
    *installed = Some(query);
    Ok(())
}

/// Confere alinhamento, acesso e tamanho antes de escrever o estado.
pub fn query(output: u64, buffer_length: u64, output_length: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    let length = buffer_length as u32;
    if from_user_mode {
        // O alinhamento vem antes das páginas, inclusive com tamanho errado.
        if length != 0 && output % 4 != 0 {
            return Ok(0x8000_0002);
        }
        if !user_probe::probe_user_write(output, length as u64) || (output_length != 0 && !user_probe::probe_user_write(output_length, 4)) {
            return Ok(0xC000_0005);
        }
    }
    // Saídas do chamador (sondadas acima quando de modo usuário): acessos
    // sondados, falha = STATUS_ACCESS_VIOLATION como o `__except` do NT.
    let publish_length = || -> Result<(), KernelError> { if output_length != 0 { guest::try_write::<u32>(output_length, INFORMATION_BYTE_LENGTH) } else { Ok(()) } };
    if length != INFORMATION_BYTE_LENGTH {
        if publish_length().is_err() {
            return Ok(0xC000_0005);
        }
        return Ok(0xC000_0004);
    }
    if output == 0 {
        return Ok(0xC000_0005);
    }
    let Ok(declared) = guest::try_read::<u32>(output + offset_of!(SystemCodeintegrityInformation, length) as u64) else {
        return Ok(0xC000_0005);
    };
    if declared != INFORMATION_BYTE_LENGTH {
        if publish_length().is_err() {
            return Ok(0xC000_0005);
        }
        return Ok(0xC000_0004);
    }
    let installed = *INSTALLED.lock();
    if let Some(query) = installed {
        return query(output, length, output_length);
    }
    // Antes da ativação do carregador, tornar ci.dll visível não habilita CI.
    if guest::try_write::<u32>(output + offset_of!(SystemCodeintegrityInformation, code_integrity_options) as u64, 0).is_err() || publish_length().is_err() {
        return Ok(0xC000_0005);
    }
    Ok(0)
}
