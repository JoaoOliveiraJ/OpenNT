//! Os pontos de controle das transições de energia (ntoskrnl 19041).
//!
//! - PopTransitionCheckpoint(Id, Type) (rva 0x7760f8): só no silo do host.
//!   Sob o PopTransitionCheckpointLock, com a lista PopTransitionCheckpoints
//!   não vazia ou com Id 1 (o começo de uma transição), um registro {número
//!   de sequência, Id, Type, InterruptTime da KUSER_SHARED_DATA} entra no fim
//!   da lista; sempre, o PopBsdTransitionLatestCheckpointSeqNumber/Id/Type
//!   recebe o número, o Id e o Type, e o número sobe. O PopGracefulShutdown
//!   marca (10, 1) no começo e (10, 2) depois do MmShutdownSystem(0).
//! - O PowerInformationInternal tipo 0x1b do NtPowerInformation (o
//!   RecordPowerTransitionCheckpoint do wininit e do winsrvext), caso de
//!   0x6f1ef3 do PopPowerInformationInternal: menos de 0x10 bytes de entrada
//!   é STATUS_BUFFER_TOO_SMALL; com saída, STATUS_INVALID_PARAMETER; senão o
//!   PopTransitionCheckpoint(*(ULONG*)(In + 8), *(ULONG*)(In + 0xC)) e
//!   sucesso.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// POWER_INFORMATION_LEVEL_INTERNAL do ponto de controle.
pub const TRANSITION_CHECKPOINT: u32 = 0x1B;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// KUSER_SHARED_DATA.InterruptTime.
const INTERRUPT_TIME: u64 = 0xFFFF_F780_0000_0008;

/// Um registro da PopTransitionCheckpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub sequence: u32,
    pub id: u32,
    pub kind: u32,
    pub interrupt_time: u64,
}

struct State {
    checkpoints: Vec<Checkpoint>,
    /// PopTransitionCheckpointsSequenceNumber.
    sequence: u32,
    /// PopBsdTransitionLatestCheckpointSeqNumber, Id e Type.
    latest: (u32, u32, u32),
}

static STATE: SpinLock<State> = SpinLock::new(State { checkpoints: Vec::new(), sequence: 0, latest: (0, 0, 0) });

/// PopTransitionCheckpoint(Id, Type).
pub fn record(id: u32, kind: u32) {
    let mut state = STATE.lock();
    let sequence = state.sequence;
    if !state.checkpoints.is_empty() || id == 1 {
        state.checkpoints.push(Checkpoint { sequence, id, kind, interrupt_time: guest::read64(INTERRUPT_TIME) });
    }
    state.latest = (sequence, id, kind);
    state.sequence = sequence.wrapping_add(1);
}

/// O último ponto de controle: (número de sequência, Id, Type).
pub fn latest() -> (u32, u32, u32) {
    STATE.lock().latest
}

/// A lista PopTransitionCheckpoints.
pub fn checkpoints() -> Vec<Checkpoint> {
    STATE.lock().checkpoints.clone()
}

/// O PowerInformationInternal TransitionCheckpoint sobre a entrada
/// capturada (cabeçalho {InternalType, Version}, Id e Type).
pub fn request(input: &[u8], has_output: bool) -> u32 {
    if input.len() < 0x10 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if has_output {
        return STATUS_INVALID_PARAMETER;
    }
    let word = |offset: usize| u32::from_le_bytes([input[offset], input[offset + 1], input[offset + 2], input[offset + 3]]);
    record(word(8), word(0xC));
    0
}
