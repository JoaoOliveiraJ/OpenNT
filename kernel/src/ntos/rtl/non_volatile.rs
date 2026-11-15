//! Memória não volátil do Rtl (`RtlGetNonVolatileToken`,
//! `RtlFreeNonVolatileToken`, `RtlFillNonVolatileMemory`,
//! `RtlWriteNonVolatileMemory`, `RtlFlushNonVolatileMemory`), ntoskrnl 19045.
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

// ---- RtlWriteNonVolatileMemory e RtlFlushNonVolatileMemory (ntoskrnl 19041) --
//
// RtlFlushNonVolatileMemory 0x585b50 (NvToken, NvBuffer, Size, Flags): token
// sem o bit válido = STATUS_INVALID_PARAMETER; com o bit de flush, cada linha
// de cache de [NvBuffer alinhado a RtlpClFlushSize, NvBuffer + Size) é
// escrita de volta (CLWB, CLFLUSHOPT ou CLFLUSH, o RtlpOptimalFlushMethod) e,
// sem FLUSH_NV_MEMORY_IN_FLAG_NO_DRAIN (bit 0), o RtlDrainNonVolatileFlush
// fecha com SFENCE; STATUS_SUCCESS. Aqui o método é o CLFLUSH (o que toda
// CPU x64 tem) com a linha do KPRCB.CFlushSize.
//
// RtlWriteNonVolatileMemory 0x58cd90 (NvToken, NvDestination, Source, Size,
// Flags): token inválido = STATUS_INVALID_PARAMETER; Flags & 3 == 1
// (WRITE_NV_MEMORY_FLAG_FLUSH) copia e faz o flush (bit 8 = sem o dreno),
// devolvendo o status dele; com o bit 1 (WRITE_NV_MEMORY_FLAG_NON_TEMPORAL),
// Size >= 8 vira RtlCopyMemoryNonTemporal e Size < 8 copia e faz o flush
// (com dreno); sem flags, só a cópia; nos caminhos sem flush,
// STATUS_SUCCESS.

const FLUSH_NO_DRAIN: u32 = 1;
const WRITE_FLUSH: u32 = 1;
const WRITE_NON_TEMPORAL: u32 = 2;
const WRITE_NO_DRAIN: u32 = 0x100;

/// RtlFlushNonVolatileMemory.
pub fn flush_memory(token: u64, buffer: u64, size: u64, flags: u32) -> u32 {
    if token & TOKEN_VALID == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if token & TOKEN_FLUSH_REQUIRED != 0 {
        let line = crate::ntos::ke::cache_flush::cache_flush_line_size().max(1);
        let end = buffer.wrapping_add(size);
        let mut address = buffer & line.wrapping_neg();
        while address < end {
            crate::hal::cpu::flush_cache_line(address);
            address += line;
        }
        if flags & FLUSH_NO_DRAIN == 0 {
            crate::hal::volatile::store_fence();
        }
    }
    0
}

/// RtlWriteNonVolatileMemory.
pub fn write_memory(token: u64, destination: u64, source: u64, size: u64, flags: u32) -> u32 {
    if token & TOKEN_VALID == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mode = flags & 3;
    if mode != WRITE_FLUSH && flags & WRITE_NON_TEMPORAL == 0 {
        crate::ntos::rtl::memory::move_memory(destination, source, size);
        return 0;
    }
    if mode != WRITE_FLUSH && size >= 8 {
        crate::ntos::rtl::memory::copy_memory_non_temporal(destination, source, size);
        return 0;
    }
    let drain = if mode == WRITE_FLUSH && flags & WRITE_NO_DRAIN != 0 { FLUSH_NO_DRAIN } else { 0 };
    crate::ntos::rtl::memory::move_memory(destination, source, size);
    flush_memory(token, destination, size, drain)
}
