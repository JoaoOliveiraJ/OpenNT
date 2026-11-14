//! Captura do COUNTED_REASON_CONTEXT (PoCaptureReasonContext em modo
//! kernel) e a liberação dele (PoDestroyReasonContext).
//!
//! As validações são as do PopCaptureReasonContext do ntoskrnl 19041:
//! Version acima de POWER_REQUEST_CONTEXT_VERSION (0) é inválida;
//! POWER_REQUEST_CONTEXT_SIMPLE_STRING (1) exige SimpleString com Length
//! par; POWER_REQUEST_CONTEXT_DETAILED_STRING (2) exige ResourceFileName
//! com Length par e StringCount * 16 dentro de 32 bits; sem nenhum dos
//! dois, só o bit 31 (contexto não especificado) é aceito, e um contexto
//! NULL vale como ele. O bloco capturado é de pool paginado 'PRCx' com o
//! tamanho do original (0x38 sem textos, 0x58 + textos com os
//! terminadores); por dentro guarda Version, Flags e os textos copiados,
//! no layout próprio do OpenNT (o requisitante, que o NT referencia com a
//! tag 'PoDg', não é registrado).

use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const PAGED_POOL: u32 = 1;
const REASON_TAG: u32 = u32::from_le_bytes(*b"PRCx");
const SIMPLE_STRING: u32 = 1;
const DETAILED_STRING: u32 = 2;
const NOT_SPECIFIED: u32 = 0x8000_0000;
/// Cabeçalho do bloco capturado: Version, Flags, requisitante, contagem.
const HEADER_SIZE: u64 = 0x38;
const TEXT_HEADER_SIZE: u64 = 0x58;

/// (Length, Buffer) de um UNICODE_STRING em `address`.
fn unicode(address: u64) -> (u16, u64) {
    (guest::read16(address), guest::read64(address + 8))
}

/// PoCaptureReasonContext(Context, KernelMode): o bloco capturado.
pub fn capture(context: u64) -> Result<u64, u32> {
    let mut texts: Vec<(u16, u64)> = Vec::new();
    let (flags, size) = if context == 0 {
        (NOT_SPECIFIED, HEADER_SIZE)
    } else {
        if guest::read32(context) > 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let flags = guest::read32(context + 4);
        if flags & SIMPLE_STRING != 0 || flags & DETAILED_STRING != 0 {
            let first = unicode(context + 8);
            if first.0 & 1 != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let mut size = first.0 as u64 + 2 + TEXT_HEADER_SIZE;
            texts.push(first);
            if flags & SIMPLE_STRING == 0 {
                let count = guest::read32(context + 0x1C);
                if (count as u64) << 4 > u32::MAX as u64 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let strings = guest::read64(context + 0x20);
                for index in 0..count as u64 {
                    let text = unicode(strings + index * 0x10);
                    size = size.checked_add(text.0 as u64 + 2).ok_or(STATUS_INVALID_PARAMETER)?;
                    texts.push(text);
                }
            }
            (flags, size)
        } else if flags & NOT_SPECIFIED != 0 {
            (flags, HEADER_SIZE)
        } else {
            return Err(STATUS_INVALID_PARAMETER);
        }
    };
    let block = pool_allocation::allocate_tagged(PAGED_POOL, size, REASON_TAG).unwrap_or(0);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    guest::write32(block, 0);
    guest::write32(block + 4, flags);
    guest::write32(block + 0x30, texts.len() as u32);
    let mut cursor = block + if texts.is_empty() { HEADER_SIZE } else { TEXT_HEADER_SIZE };
    for (length, buffer) in texts {
        if length != 0 {
            guest::write_bytes(cursor, &guest::read_bytes(buffer, length as usize));
        }
        cursor += length as u64 + 2;
    }
    Ok(block)
}

/// PoDestroyReasonContext.
pub fn destroy(block: u64) {
    if block != 0 {
        let _ = pool_allocation::free(block, 0);
    }
}
