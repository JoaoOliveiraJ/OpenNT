//! Dados de estado WNF internos — `system32/ntos/ex/wnf-state-data.js`.
//!
//! Registros do kernel para o transporte de uso de funcionalidades. A camada
//! de syscalls valida namespace, escopo, ACL e tipos antes de chegar aqui.

use alloc::collections::BTreeMap;

use crate::rtl::SpinLock;
use crate::ntos::mm::guest_memory as guest;

const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

#[derive(Clone, Copy)]
struct State {
    maximum_size: u32,
    pointer: u64,
    size: u32,
    stamp: u32,
}

static STATES: SpinLock<BTreeMap<u64, State>> = SpinLock::new(BTreeMap::new());

/// Estado vazio com nome de 64 bits e limite de até 4096 bytes; um nome
/// registrado não é substituído.
pub fn register(name: u64, maximum_size: u32) -> u32 {
    if name == 0 || maximum_size > 4096 {
        return 0xC000_000D;
    }
    let mut states = STATES.lock();
    if states.contains_key(&name) {
        return 0xC000_0035;
    }
    states.insert(name, State { maximum_size, pointer: 0, size: 0, stamp: 0 });
    0
}

pub fn remove(name: u64) -> u32 {
    let Some(state) = STATES.lock().remove(&name) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    if state.pointer != 0 {
        guest::free_bytes(state.pointer);
    }
    0
}

/// Resultado da consulta: NTSTATUS, tamanho e carimbo vigentes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QueryResult {
    pub status: u32,
    pub size: u32,
    pub stamp: u32,
}

/// Sucesso e buffer curto informam tamanho e carimbo vigentes.
pub fn query(name: u64, buffer: u64, capacity: u32) -> QueryResult {
    let Some(state) = STATES.lock().get(&name).copied() else { return QueryResult { status: STATUS_OBJECT_NAME_NOT_FOUND, size: 0, stamp: 0 } };
    if capacity < state.size {
        return QueryResult { status: 0xC000_0023, size: state.size, stamp: state.stamp };
    }
    if state.size != 0 {
        guest::write_bytes(buffer, &guest::read_bytes(state.pointer, state.size as usize));
    }
    QueryResult { status: 0, size: state.size, stamp: state.stamp }
}

/// Valida o tamanho e o carimbo opcional, copia para uma alocação própria e
/// só então publica e incrementa o carimbo (zero é pulado no transbordo).
pub fn update(name: u64, buffer: u64, length: u32, matching_stamp: u32, check_stamp: bool) -> u32 {
    let Some(state) = STATES.lock().get(&name).copied() else { return STATUS_OBJECT_NAME_NOT_FOUND };
    if length > state.maximum_size {
        return 0xC000_000D;
    }
    if check_stamp && state.stamp != matching_stamp {
        return 0xC000_0001;
    }
    let replacement = if length != 0 { guest::alloc_bytes(length as u64) } else { 0 };
    if length != 0 && replacement == 0 {
        return 0xC000_009A;
    }
    if length != 0 {
        guest::write_bytes(replacement, &guest::read_bytes(buffer, length as usize));
    }
    let previous = {
        let mut states = STATES.lock();
        let Some(current) = states.get_mut(&name) else {
            if replacement != 0 {
                guest::free_bytes(replacement);
            }
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if check_stamp && current.stamp != matching_stamp {
            drop(states);
            if replacement != 0 {
                guest::free_bytes(replacement);
            }
            return 0xC000_0001;
        }
        let previous = current.pointer;
        current.pointer = replacement;
        current.size = length;
        current.stamp = current.stamp.wrapping_add(1).max(1);
        previous
    };
    if previous != 0 {
        guest::free_bytes(previous);
    }
    0
}
