//! O bloco base de uma hive (`_HBASE_BLOCK`): a soma de verificação, a
//! validação do arquivo primário e o nome do arquivo.
//!
//! Como no ntoskrnl 19041: HvpHeaderCheckSum (rva 0x723b98) faz o XOR dos
//! 127 primeiros DWORDs, troca 0xFFFFFFFF por 0xFFFFFFFE e 0 por 1; a
//! validação do HvHiveStartMemoryBacked/HvpGetHiveHeader exige 'regf', Type
//! 0 (primário), Format 1, Major 1, Minor de 3 a 6, Length até 0x7FFFE000 e
//! a soma batendo.

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::HbaseBlock;
use crate::ntos::inc::types::NtStruct;

use super::storage::{HBASE_SIGNATURE, STATUS_REGISTRY_CORRUPT};

/// HFILE_TYPE_PRIMARY e o tipo do bloco base de um log no formato
/// incremental (HvpGenerateLogEntryHeader grava 6).
pub const HFILE_TYPE_PRIMARY: u32 = 0;
pub const HFILE_TYPE_LOG: u32 = 6;

/// HvpHeaderCheckSum.
pub fn checksum(base: &HbaseBlock) -> u32 {
    // SAFETY: os 508 primeiros bytes do bloco base (127 DWORDs).
    let words = unsafe { Field::<u32>::array_at(base.address(), 127) };
    let sum = words.iter().fold(0u32, |sum, word| sum ^ word.get());
    match sum {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        sum => sum,
    }
}

/// A soma sobre bytes soltos (o bloco base copiado no início de um log).
pub fn checksum_bytes(bytes: &[u8]) -> u32 {
    let sum = bytes[..508].chunks_exact(4).fold(0u32, |sum, word| sum ^ u32::from_le_bytes([word[0], word[1], word[2], word[3]]));
    match sum {
        0xFFFF_FFFF => 0xFFFF_FFFE,
        0 => 1,
        sum => sum,
    }
}

/// Validação do bloco base de um arquivo primário de `file_length` bytes.
pub fn validate_primary(base: &HbaseBlock, file_length: u64) -> Result<(), u32> {
    let length = base.length.get();
    let coherent = base.signature.get() == HBASE_SIGNATURE
        && base.type_.get() == HFILE_TYPE_PRIMARY
        && base.format.get() == 1
        && base.major.get() == 1
        && (3..=6).contains(&base.minor.get())
        && length <= 0x7FFF_E000
        && length % 0x1000 == 0
        && 0x1000 + length as u64 <= file_length
        && checksum(base) == base.check_sum.get();
    if coherent { Ok(()) } else { Err(STATUS_REGISTRY_CORRUPT) }
}

/// HvpFillFileName: os últimos 31 caracteres do nome, terminados em NUL.
pub fn fill_file_name(base: &HbaseBlock, name: &str) {
    let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    let start = units.len().saturating_sub(31);
    // FileName são 64 bytes de UTF-16LE.
    for (index, slot) in base.file_name.iter().enumerate() {
        let unit = units.get(start + index / 2).copied().unwrap_or(0);
        slot.set(unit.to_le_bytes()[index % 2]);
    }
}
