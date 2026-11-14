//! Ações de energia do sistema: ZwInitiatePowerAction (o
//! NtInitiatePowerAction em modo kernel), PoShutdownBugCheck e
//! PoSetHiberRange.
//!
//! - ZwInitiatePowerAction(SystemAction, LightestSystemState, Flags,
//!   Asynchronous): as validações do NtInitiatePowerAction do ntoskrnl
//!   19041 (ação e estado até 7, sem o bit 28 nem os bits 0x0CFFFFC0 das
//!   flags, PowerActionSleep só até S3). PowerActionNone não tem o que
//!   fazer e devolve STATUS_SUCCESS; as demais ações vão ao
//!   PopExecutePowerAction da política de energia, que o OpenNT não tem
//!   (não há transição de estado do sistema): STATUS_NOT_SUPPORTED.
//! - PoShutdownBugCheck(AllowCrashDump, Code, P1..P4): pede o
//!   desligamento crítico (PowerActionShutdownReset, S3 como mínimo,
//!   POWER_ACTION_CRITICAL | 0x40000000 | POWER_ACTION_OVERRIDE_APPS) e,
//!   se ele volta, para o sistema com o código pedido, como o original.
//! - PoSetHiberRange(MapHandle, Flags, Address, Length, Tag): só vale
//!   durante a montagem do mapa de hibernação. O OpenNT não hiberna, então
//!   não há contexto global nem mapa: um handle nulo é
//!   INTERNAL_POWER_ERROR (0x10B, 0xA), um mapa já fechado (estado 9) não
//!   faz nada e qualquer outro estado é o mesmo erro com o estado.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ke::bugcheck;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const POWER_ACTION_NONE: u32 = 0;
const POWER_ACTION_SLEEP: u32 = 2;
const POWER_ACTION_SHUTDOWN_RESET: u32 = 5;
const POWER_SYSTEM_SLEEPING3: u32 = 4;
const POWER_SYSTEM_HIBERNATE: u32 = 5;
const SHUTDOWN_FLAGS: u32 = 0xC000_0004;
const INTERNAL_POWER_ERROR: u32 = 0xA0;
/// Estado do contexto de hibernação: mapa fechado (o PoSetHiberRange volta).
const HIBER_MAP_CLOSED: u32 = 9;
/// Offset do estado no contexto de hibernação.
const HIBER_STATE_OFFSET: u64 = 0xB8;

/// ZwInitiatePowerAction em modo kernel.
pub fn initiate(system_action: u32, lightest_state: u32, flags: u32, _asynchronous: bool) -> u32 {
    if lightest_state as i32 > 7 || system_action as i32 > 7 || flags & (1 << 28) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if system_action == POWER_ACTION_SLEEP && lightest_state as i32 >= POWER_SYSTEM_HIBERNATE as i32 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & 0x0CFF_FFC0 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if system_action == POWER_ACTION_NONE {
        return STATUS_SUCCESS;
    }
    STATUS_NOT_SUPPORTED
}

/// PoShutdownBugCheck: o desligamento crítico e, se ele volta, o bugcheck.
pub fn shutdown_bug_check(_allow_crash_dump: bool, code: u32, parameters: [u64; 4]) -> ! {
    let _ = initiate(POWER_ACTION_SHUTDOWN_RESET, POWER_SYSTEM_SLEEPING3, SHUTDOWN_FLAGS, false);
    bugcheck::bug_check_ex(code, parameters[0], parameters[1], parameters[2], parameters[3])
}

/// PoSetHiberRange.
pub fn set_hiber_range(map: u64, _flags: u32, _address: u64, _length: u64, _tag: u32) {
    if bugcheck::is_active() {
        return;
    }
    if map == 0 {
        bugcheck::bug_check_ex(INTERNAL_POWER_ERROR, 0x10B, 0xA, 0, 0);
    }
    // SAFETY: o contexto de hibernação que o chamador recebeu.
    let state = unsafe { Field::<u32>::at(map + HIBER_STATE_OFFSET) }.get();
    if state == HIBER_MAP_CLOSED {
        return;
    }
    bugcheck::bug_check_ex(INTERNAL_POWER_ERROR, 0x10B, 0xA, state as u64, 0);
}
