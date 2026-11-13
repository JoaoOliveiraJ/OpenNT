//! Memória não volátil do Rtl (`RtlGetNonVolatileToken`,
//! `RtlFreeNonVolatileToken`, `RtlFillNonVolatileMemory`), ntoskrnl 19045.
//!
//! O token é um valor: bit 0 = válido, bit 1 = o flush de cache é necessário
//! (`RtlpIsFlushRequired`). O NT inicializa esse estado em
//! `RtlpInitializeNonVolatileFlush` consultando SystemFlushInformation (0xC0):
//! só um sistema que declara persistência sem flush (bit 0 de
//! SystemFlushCapabilities) zera `RtlpIsFlushRequired`, cujo valor da imagem é 1.
//! O OpenNT não oferece essa classe (a consulta falha), então vale o padrão da
//! imagem — flush necessário, token 3 —, que é também o de uma máquina sem
//! NVDIMM. Os flushes (CLFLUSH/CLFLUSHOPT/CLWB + SFENCE) não têm efeito
//! observável sem memória persistente; o preenchimento é o mesmo memset em
//! todos os caminhos do original.

use crate::ntos::inc::types::Field;
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const TOKEN_VALID: u64 = 1;
const TOKEN_FLUSH_REQUIRED: u64 = 2;

/// RtlGetNonVolatileToken(NvBuffer, Size, *NvToken): token 3 (válido e com
/// flush necessário); STATUS_SUCCESS.
pub fn get_token(token_out: &Field<u64>) -> u32 {
    token_out.set(TOKEN_VALID | TOKEN_FLUSH_REQUIRED);
    0
}

/// RtlFreeNonVolatileToken(NvToken): STATUS_INVALID_PARAMETER sem o bit válido.
pub fn free_token(token: u64) -> u32 {
    if token & TOKEN_VALID == 0 { STATUS_INVALID_PARAMETER } else { 0 }
}

/// RtlFillNonVolatileMemory(NvToken, NvDestination, Size, Value, Flags):
/// preenche `Size` bytes com `Value` (memset, memset+flush ou preenchimento
/// não temporal, conforme token e Flags); o flush de um token válido sempre
/// devolve STATUS_SUCCESS.
pub fn fill_memory(token: u64, destination: u64, size: u64, value: u8) -> u32 {
    if token & TOKEN_VALID == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut remaining = size;
    let mut cursor = destination;
    let block = alloc::vec![value; 0x1000];
    while remaining != 0 {
        let chunk = remaining.min(block.len() as u64);
        guest::write_bytes(cursor, &block[..chunk as usize]);
        cursor += chunk;
        remaining -= chunk;
    }
    0
}
