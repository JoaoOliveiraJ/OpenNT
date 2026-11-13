//! TOKEN_STATISTICS.
//!
//! Identidade, contadores e memória do próprio token, na ordem e largura do
//! serviço nativo observado no MSRPC. O armazenamento dinâmico vive em
//! `tokens`.

use alloc::vec::Vec;

use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

/// (offset, largura, valor) de cada campo de TOKEN_STATISTICS.
pub fn fields(token: u64) -> Result<Vec<(u64, u8, u64)>, KernelError> {
    let Some(record) = tokens::get(token).filter(|record| record.refs > 0) else {
        return Err(KernelError::new("Statistics requested for an unowned token"));
    };
    let (charged, available) = tokens::accounting(token)?;
    Ok(alloc::vec![
        (0, 8, record.id),
        (8, 8, record.authentication_id),
        (16, 8, record.expiration_time),
        (24, 4, record.kind as u64),
        (28, 4, record.impersonation_level as u64),
        (32, 4, charged),
        (36, 4, available),
        (40, 4, record.groups.len() as u64),
        (44, 4, record.privileges.len() as u64),
        (48, 8, record.modified_id),
    ])
}

/// Os 56 bytes do caminho de usuário, da mesma fotografia.
pub fn encode(token: u64) -> Result<[u8; 56], KernelError> {
    let mut bytes = [0u8; 56];
    for (offset, width, value) in fields(token)? {
        let offset = offset as usize;
        if width == 8 {
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        } else {
            bytes[offset..offset + 4].copy_from_slice(&(value as u32).to_le_bytes());
        }
    }
    Ok(bytes)
}
