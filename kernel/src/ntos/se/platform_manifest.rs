//! Manifesto de plataforma.
//!
//! Consulta o manifesto da política entregue no boot. A captura conserva uma
//! cópia privada; consultar um identificador não registra política, não
//! autentica assinatura e não habilita Secure Boot.

use alloc::vec::Vec;

use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const HEADER_BYTES: usize = 24;
const METADATA_RECORD_BYTES: u64 = 0x114;
const IDENTIFIER_BYTES: usize = 32;
const STATUS_NOT_ACTIVE: u32 = 0xC0EB_0006;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Consulta capturada: sem manifesto, ou os identificadores ordenados.
#[derive(Clone)]
pub enum Captured {
    Inactive,
    Active { identifiers: Vec<u8>, count: usize },
}

/// Só a inicialização do boot publica a consulta global.
static BOOT: SpinLock<Option<Captured>> = SpinLock::new(None);

fn read_count(bytes: &[u8], offset: usize) -> u64 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]]) as u64
}

/// memcmp do kernel: bytes até alinhar a chave, depois QWORDs e cauda; uma
/// diferença encerra a leitura progressiva.
fn compare_identifier(key: u64, identifiers: &[u8], entry: usize) -> i32 {
    let mut index = 0usize;
    while index < IDENTIFIER_BYTES {
        let current = key + index as u64;
        let width = if current & 7 == 0 && index + 8 <= IDENTIFIER_BYTES { 8 } else { 1 };
        let value = if width == 8 { guest::read64(current) } else { guest::read8(current) as u64 };
        // Ordem lexicográfica, não a ordem numérica do QWORD.
        for within in 0..width {
            let key_byte = (value >> (within * 8)) as u8;
            let entry_byte = identifiers[entry + index + within];
            if key_byte != entry_byte {
                return if key_byte < entry_byte { -1 } else { 1 };
            }
        }
        index += width;
    }
    0
}

/// Captura um bloco já pertencente ao chamador de boot; a validação é
/// estrutural (a autenticidade continua sendo dever do loader). Ponteiros do
/// cabeçalho nunca são aceitos como endereços.
pub fn capture(manifest: Option<&[u8]>) -> Result<Captured, KernelError> {
    let Some(bytes) = manifest else { return Ok(Captured::Inactive) };
    if bytes.len() < HEADER_BYTES {
        return Err(KernelError::new("PlatformManifest: invalid loader manifest header"));
    }
    let metadata_bytes = read_count(bytes, 0) * METADATA_RECORD_BYTES;
    let count = read_count(bytes, 4);
    let identifier_bytes = count * IDENTIFIER_BYTES as u64;
    let identifier_offset = HEADER_BYTES as u64 + metadata_bytes;
    let length = bytes.len() as u64;
    if length > 0xFFFF_FFFF || metadata_bytes > 0xFFFF_FFFF || identifier_bytes > 0xFFFF_FFFF || identifier_offset > length || identifier_bytes > length - identifier_offset {
        return Err(KernelError::new("PlatformManifest: loader manifest tables exceed owned buffer"));
    }
    let start = identifier_offset as usize;
    Ok(Captured::Active { identifiers: bytes[start..start + identifier_bytes as usize].to_vec(), count: count as usize })
}

impl Captured {
    pub fn query(&self, key: u64, key_length: u64) -> u32 {
        let Captured::Active { identifiers, count } = self else { return STATUS_NOT_ACTIVE };
        // NULL antes do tamanho; uma tabela vazia não lê a chave.
        if key == 0 {
            return STATUS_NOT_FOUND;
        }
        if key_length as u32 as usize != IDENTIFIER_BYTES {
            return STATUS_INVALID_PARAMETER;
        }
        let mut first = 0usize;
        let mut remaining = *count;
        while remaining > 0 {
            // bsearch_s escolhe o central inferior quando o tamanho é par.
            let lower = (remaining - 1) / 2;
            let candidate = first + lower;
            match compare_identifier(key, identifiers, candidate * IDENTIFIER_BYTES) {
                0 => return 0,
                order if order < 0 => remaining = lower,
                _ => {
                    first = candidate + 1;
                    remaining -= lower + 1;
                }
            }
        }
        STATUS_NOT_FOUND
    }
}

/// A ausência é informada explicitamente com `None`.
pub fn init(manifest: Option<&[u8]>) -> Result<(), KernelError> {
    let mut boot = BOOT.lock();
    if boot.is_some() {
        return Err(KernelError::new("PlatformManifest: boot already initialized"));
    }
    *boot = Some(capture(manifest)?);
    Ok(())
}

pub fn query(key: u64, key_length: u64) -> Result<u32, KernelError> {
    let captured = BOOT.lock().clone().ok_or_else(|| KernelError::new("PlatformManifest: boot not initialized"))?;
    Ok(captured.query(key, key_length))
}
