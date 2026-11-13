//! SystemCodeIntegrityInformation (103).
//!
//! Compartilhado pelos exports de kernel e pela chamada de usuário. A ABI tem
//! dois ULONGs: Length e CodeIntegrityOptions.

use crate::ntos::ps::user_probe;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

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
    if length != INFORMATION_BYTE_LENGTH {
        if output_length != 0 {
            guest::write32(output_length, INFORMATION_BYTE_LENGTH);
        }
        return Ok(0xC000_0004);
    }
    if output == 0 {
        return Ok(0xC000_0005);
    }
    if guest::read32(output) != INFORMATION_BYTE_LENGTH {
        if output_length != 0 {
            guest::write32(output_length, INFORMATION_BYTE_LENGTH);
        }
        return Ok(0xC000_0004);
    }
    let installed = *INSTALLED.lock();
    if let Some(query) = installed {
        return query(output, length, output_length);
    }
    // Antes da ativação do carregador, tornar ci.dll visível não habilita CI.
    guest::write32(output + 4, 0);
    if output_length != 0 {
        guest::write32(output_length, INFORMATION_BYTE_LENGTH);
    }
    Ok(0)
}
