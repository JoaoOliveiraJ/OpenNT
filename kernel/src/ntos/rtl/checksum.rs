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
