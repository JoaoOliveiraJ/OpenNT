//! A descarga de uma hive para os arquivos (o HvSyncHive do NT).
//!
//! Como no ntoskrnl 19041, com o log incremental e a reconciliação do
//! primário na mesma descarga:
//! 1. o bloco base do primário é invalidado (HvValidateOrInvalidate-
//!    PrimaryFileHeader, rva 0x7249fc: Sequence1 = S, Sequence2 = S - 1,
//!    S = a sequência corrente) e gravado;
//! 2. as faixas sujas vão para o log corrente numa entrada de sequência S;
//! 3. as mesmas faixas são gravadas no primário, no offset 0x1000 + offset;
//! 4. o bloco base volta validado com Sequence1 = Sequence2 = S + 1, e o
//!    log seguinte é o outro arquivo (HvSwapLogFiles).
//!
//! O plano é montado sob a trava do Registro (uma fotografia coerente dos
//! bins); a E/S acontece fora dela. Uma descarga que falha devolve as
//! faixas ao vetor de sujeira.

use alloc::vec::Vec;

use super::log;
use super::storage::{Storage, HBLOCK_SIZE};

/// O que gravar, na ordem.
pub struct Plan {
    pub invalid_header: Vec<u8>,
    pub log: Vec<u8>,
    pub writes: Vec<(u64, Vec<u8>)>,
    pub file_length: u64,
    pub valid_header: Vec<u8>,
    pub runs: Vec<(u32, u32)>,
    pub sequence: u32,
}

/// Monta a descarga e limpa o vetor de sujeira (`None` quando não há nada
/// sujo). A sequência nova já fica no bloco base da hive.
pub fn prepare(storage: &mut Storage) -> Option<Plan> {
    if !storage.is_dirty() {
        return None;
    }
    let runs = storage.dirty_runs();
    let base = storage.base_block();
    let sequence = base.sequence1.get();
    base.sequence2.set(sequence.wrapping_sub(1));
    let invalid_header = storage.base_bytes();
    let log = log::build(storage, sequence, &runs);
    let writes = runs.iter().map(|&(offset, length)| (HBLOCK_SIZE as u64 + offset as u64, storage.read_bins(offset, length))).collect();
    let base = storage.base_block();
    base.sequence1.set(sequence.wrapping_add(1));
    base.sequence2.set(sequence.wrapping_add(1));
    let valid_header = storage.base_bytes();
    storage.clear_dirty();
    Some(Plan { invalid_header, log, writes, file_length: HBLOCK_SIZE as u64 + storage.length() as u64, valid_header, runs, sequence })
}

/// Desfaz o efeito de uma descarga que não chegou ao arquivo.
pub fn abandon(storage: &mut Storage, plan: &Plan) {
    storage.restore_dirty(&plan.runs);
    let base = storage.base_block();
    base.sequence1.set(plan.sequence);
    base.sequence2.set(plan.sequence);
}
