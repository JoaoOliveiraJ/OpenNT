//! Somas de verificação do Rtl — RtlComputeCrc32.
//!
//! RtlCrc32Table do ntoskrnl é a tabela refletida padrão do polinômio
//! 0xEDB88320 (conferida entrada a entrada contra a imagem com pefile);
//! aqui é gerada em tempo de compilação.

use crate::ntos::mm::guest_memory as guest;

const fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 { (value >> 1) ^ 0xEDB8_8320 } else { value >> 1 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC32_TABLE: [u32; 256] = crc32_table();

/// RtlComputeCrc32(PartialCrc, Buffer, Length): CRC-32 IEEE encadeável
/// (inversão na entrada e na saída); Length 0 devolve PartialCrc.
pub fn compute_crc32(partial: u32, buffer: u64, length: u32) -> u32 {
    let mut crc = !partial;
    if length != 0 {
        for byte in guest::read_bytes(buffer, length as usize) {
            crc = CRC32_TABLE[((crc ^ byte as u32) & 0xFF) as usize] ^ (crc >> 8);
        }
    }
    !crc
}

// ---- RtlCrc64 (ntoskrnl 19045, 0x305d70 -> RtlpComputeCrcInternal, Crc64Ctrl) ----
//
// Crc64Ctrl: polinômio refletido 0x9A6C9329AC4BC9B5 (CRC-64/NVME) e valor de
// inversão 0xFFFFFFFFFFFFFFFF; o estado começa em InitialCrc ^ ~0 e o resultado
// é invertido de novo (conferido contra o RtlCrc64 do ntdll).

const fn crc64_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u64;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 { (value >> 1) ^ 0x9A6C_9329_AC4B_C9B5 } else { value >> 1 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC64_TABLE: [u64; 256] = crc64_table();

/// RtlCrc64(Buffer, Size, InitialCrc) -> ULONGLONG.
pub fn crc64(buffer: u64, size: u64, initial: u64) -> u64 {
    let mut crc = !initial;
    let mut cursor = buffer;
    let mut remaining = size;
    while remaining != 0 {
        let chunk = remaining.min(0x1000);
        for byte in guest::read_bytes(cursor, chunk as usize) {
            crc = CRC64_TABLE[((crc ^ byte as u64) & 0xFF) as usize] ^ (crc >> 8);
        }
        cursor += chunk;
        remaining -= chunk;
    }
    !crc
}
