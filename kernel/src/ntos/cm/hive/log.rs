//! Os logs de transação de uma hive (.LOG1/.LOG2) no formato incremental.
//!
//! Como no ntoskrnl 19041 (HvpGenerateLogEntry, rva 0x720c50, e
//! HvpGenerateLogEntryHeader, rva 0x3619e0): um log que começa vazio leva
//! primeiro os 512 bytes iniciais do bloco base, com Sequence1 = Sequence2
//! = a sequência da entrada, Type 6, Length = o tamanho dos bins, Cluster 1
//! e a soma refeita; depois vêm as entradas 'HvLE':
//!
//! | offset | campo |
//! | --- | --- |
//! | 0x00 | 'HvLE' |
//! | 0x04 | tamanho da entrada (o buffer arredondado para 0x1000, menos os 512 bytes do bloco base quando é a primeira) |
//! | 0x08 | Flags do bloco base & 1 |
//! | 0x0c | sequência |
//! | 0x10 | tamanho dos bins |
//! | 0x14 | número de faixas sujas |
//! | 0x18 | Marvin32 de [0x28, fim da entrada) |
//! | 0x20 | Marvin32 dos primeiros 0x20 bytes |
//! | 0x28 | (offset, tamanho) de cada faixa, depois os bytes de cada uma |
//!
//! O Marvin32 é o do SymCrypt com a semente 0x82EF4D887A4E55C5
//! (HvInitializeHashLibrary, rva 0x7a58d0; SymCryptMarvin32, rva 0x3eb528).
//!
//! Recuperação: um primário com Sequence1 != Sequence2 foi invalidado antes
//! de uma descarga que não terminou; as entradas de log com sequência a
//! partir de Sequence2 + 1, consecutivas e com os dois hashes certos, são
//! aplicadas sobre os bins.

use alloc::vec::Vec;

use super::base_block::{checksum_bytes, HFILE_TYPE_LOG};
use super::storage::{Storage, HBASE_SIGNATURE, HBLOCK_SIZE, HSECTOR_SIZE};

/// 'HvLE'.
const ENTRY_SIGNATURE: u32 = 0x454c_7648;
const ENTRY_HEADER: usize = 0x28;
const MARVIN_SEED: u64 = 0x82EF_4D88_7A4E_55C5;

fn round(s0: &mut u32, s1: &mut u32) {
    *s1 ^= *s0;
    *s0 = s0.rotate_left(20);
    *s0 = s0.wrapping_add(*s1);
    *s1 = s1.rotate_left(9);
    *s1 ^= *s0;
    *s0 = s0.rotate_left(27);
    *s0 = s0.wrapping_add(*s1);
    *s1 = s1.rotate_left(19);
}

/// SymCryptMarvin32 com a semente das hives.
pub fn marvin32(data: &[u8]) -> u64 {
    let (mut s0, mut s1) = (MARVIN_SEED as u32, (MARVIN_SEED >> 32) as u32);
    let mut blocks = data.chunks_exact(4);
    for block in &mut blocks {
        s0 = s0.wrapping_add(u32::from_le_bytes([block[0], block[1], block[2], block[3]]));
        round(&mut s0, &mut s1);
    }
    let rest = blocks.remainder();
    let last = match rest.len() {
        0 => 0x80,
        1 => rest[0] as u32 | 0x8000,
        2 => u16::from_le_bytes([rest[0], rest[1]]) as u32 | 0x80_0000,
        _ => rest[0] as u32 | (rest[1] as u32) << 8 | (rest[2] as u32) << 16 | 0x8000_0000,
    };
    s0 = s0.wrapping_add(last);
    round(&mut s0, &mut s1);
    round(&mut s0, &mut s1);
    s0 as u64 | (s1 as u64) << 32
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn get32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// Um log novo com uma entrada das faixas sujas, na sequência dada.
pub fn build(storage: &Storage, sequence: u32, runs: &[(u32, u32)]) -> Vec<u8> {
    let dirty: u32 = runs.iter().map(|&(_, length)| length).sum();
    let used = HSECTOR_SIZE as usize + ENTRY_HEADER + runs.len() * 8 + dirty as usize;
    let total = used.div_ceil(HBLOCK_SIZE as usize) * HBLOCK_SIZE as usize;
    let mut log = alloc::vec![0u8; total];
    let base = storage.base_bytes();
    log[..HSECTOR_SIZE as usize].copy_from_slice(&base[..HSECTOR_SIZE as usize]);
    put32(&mut log, 4, sequence);
    put32(&mut log, 8, sequence);
    put32(&mut log, 0x1c, HFILE_TYPE_LOG);
    put32(&mut log, 0x28, storage.length());
    put32(&mut log, 0x2c, 1);
    let sum = checksum_bytes(&log);
    put32(&mut log, 0x1fc, sum);
    let entry = &mut log[HSECTOR_SIZE as usize..];
    let size = entry.len();
    put32(entry, 0, ENTRY_SIGNATURE);
    put32(entry, 4, size as u32);
    put32(entry, 8, get32(&base, 0x90) & 1);
    put32(entry, 0xc, sequence);
    put32(entry, 0x10, storage.length());
    put32(entry, 0x14, runs.len() as u32);
    let mut cursor = ENTRY_HEADER;
    for &(offset, length) in runs {
        put32(entry, cursor, offset);
        put32(entry, cursor + 4, length);
        cursor += 8;
    }
    for &(offset, length) in runs {
        entry[cursor..cursor + length as usize].copy_from_slice(&storage.read_bins(offset, length));
        cursor += length as usize;
    }
    let first = marvin32(&entry[ENTRY_HEADER..]);
    entry[0x18..0x20].copy_from_slice(&first.to_le_bytes());
    let second = marvin32(&entry[..0x20]);
    entry[0x20..0x28].copy_from_slice(&second.to_le_bytes());
    log
}

/// Uma entrada válida de um log.
struct Entry<'a> {
    sequence: u32,
    length: u32,
    runs: Vec<(u32, &'a [u8])>,
}

/// As entradas íntegras de um log, na ordem do arquivo.
fn entries(log: &[u8]) -> Vec<Entry<'_>> {
    let mut found = Vec::new();
    let header = HSECTOR_SIZE as usize;
    if log.len() < header || get32(log, 0) != HBASE_SIGNATURE || get32(log, 0x1fc) != checksum_bytes(log) {
        return found;
    }
    let mut cursor = header;
    while cursor + ENTRY_HEADER <= log.len() {
        let entry = &log[cursor..];
        let size = get32(entry, 4) as usize;
        if get32(entry, 0) != ENTRY_SIGNATURE || size < ENTRY_HEADER || size % HSECTOR_SIZE as usize != 0 || size > entry.len() {
            break;
        }
        let entry = &entry[..size];
        if marvin32(&entry[..0x20]).to_le_bytes() != entry[0x20..0x28] || marvin32(&entry[ENTRY_HEADER..]).to_le_bytes() != entry[0x18..0x20] {
            break;
        }
        let count = get32(entry, 0x14) as usize;
        let mut data = ENTRY_HEADER + count * 8;
        let mut runs = Vec::with_capacity(count);
        let mut valid = data <= size;
        for index in 0..count {
            if !valid {
                break;
            }
            let (offset, length) = (get32(entry, ENTRY_HEADER + index * 8), get32(entry, ENTRY_HEADER + index * 8 + 4) as usize);
            valid = data + length <= size;
            if valid {
                runs.push((offset, &entry[data..data + length]));
                data += length;
            }
        }
        if !valid {
            break;
        }
        found.push(Entry { sequence: get32(entry, 0xc), length: get32(entry, 0x10), runs });
        cursor += size;
    }
    found
}

/// Aplica os logs sobre a imagem de um primário invalidado. Devolve quantas
/// entradas entraram; a imagem volta com o bloco base validado.
pub fn recover(image: &mut Vec<u8>, logs: &[Vec<u8>]) -> u32 {
    if image.len() < HBLOCK_SIZE as usize {
        return 0;
    }
    let (sequence1, sequence2) = (get32(image, 4), get32(image, 8));
    if sequence1 == sequence2 {
        return 0;
    }
    let all: Vec<Entry> = logs.iter().flat_map(|log| entries(log)).collect();
    let mut next = sequence2.wrapping_add(1);
    let mut applied = 0;
    while let Some(entry) = all.iter().find(|entry| entry.sequence == next) {
        let length = entry.length as usize;
        if image.len() < HBLOCK_SIZE as usize + length {
            image.resize(HBLOCK_SIZE as usize + length, 0);
        }
        for &(offset, bytes) in &entry.runs {
            let start = HBLOCK_SIZE as usize + offset as usize;
            if start + bytes.len() <= image.len() {
                image[start..start + bytes.len()].copy_from_slice(bytes);
            }
        }
        put32(image, 0x28, entry.length);
        applied += 1;
        next = next.wrapping_add(1);
    }
    let sequence = if applied == 0 { sequence1 } else { next };
    put32(image, 4, sequence);
    put32(image, 8, sequence);
    let sum = checksum_bytes(image);
    put32(image, 0x1fc, sum);
    applied
}
