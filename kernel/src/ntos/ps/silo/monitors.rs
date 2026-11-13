//! Monitores de server silo.
//!
//! PsRegisterSiloMonitor / PsStartSiloMonitor / PsUnregisterSiloMonitor.
//! Corpo do monitor (0x38 + nome): LIST_ENTRY, CreateAsHost (+0x10),
//! RequestedOnSystemSilo (+0x11), slot (+0x14), CreateCallback (+0x18),
//! TerminateCallback (+0x20) e UNICODE_STRING do nome (+0x28).

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ntos::ps::{process, process_context};
use crate::ntos::ps::silo::{contexts as silo_contexts, query as silo_query};
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::ke::critical_region;
use crate::ntos::mm::data_pool;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::ejob;

const INVALID: u32 = 0xC000_000D;
const NO_MEMORY: u32 = 0xC000_009A;
const NOT_SUPPORTED: u32 = 0xC000_00BB;

struct State {
    records: BTreeSet<u64>,
    globals: u64,
}

static STATE: SpinLock<State> = SpinLock::new(State { records: BTreeSet::new(), globals: 0 });

/// Lista global de monitores (cabeça + push lock em +16).
fn initialize() -> u64 {
    let mut state = STATE.lock();
    if state.globals != 0 {
        return state.globals;
    }
    let globals = guest::alloc_bytes(24);
    if globals != 0 {
        guest::write64(globals, globals);
        guest::write64(globals + 8, globals);
        guest::write64(globals + 16, 0);
        state.globals = globals;
    }
    globals
}

fn require(pointer: u64) -> Result<(), KernelError> {
    if STATE.lock().records.contains(&pointer) { Ok(()) } else { Err(KernelError::new("invalid silo monitor")) }
}

/// Silos com globais em estado de criação/execução (1–3).
fn existing() -> Vec<u64> {
    silo_contexts::owned_silos()
        .into_iter()
        .filter(|&silo| {
            let global = guest::read64(silo + ejob::SERVER_SILO_GLOBALS);
            global != 0 && (1..=3).contains(&guest::read32(global + 0x458))
        })
        .collect()
}

fn with_lock<T>(globals: u64, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(globals + 16, 0)?;
        let result = body();
        push_lock::release_exclusive(globals + 16, 0)?;
        result
    })
}

fn with_system<T>(body: impl FnOnce() -> T) -> Result<T, KernelError> {
    process_context::with_process(process::get_system_process(), body)
}

/// Chama a rotina do monitor em +offset com o silo; devolve o NTSTATUS com sinal.
fn invoke(pointer: u64, offset: u64, silo: u64) -> i32 {
    native_call::call(guest::read64(pointer + offset), &[silo]) as u32 as i32
}

/// PsRegisterSiloMonitor(SILO_MONITOR_REGISTRATION, saída).
pub fn register(registration: u64, output: u64) -> Result<u32, KernelError> {
    if guest::read8(registration) == 0 {
        return Ok(INVALID);
    }
    let name = guest::read64(registration + 8);
    if name == 0 || guest::read16(name) == 0 || (guest::read64(registration + 0x10) == 0 && guest::read64(registration + 0x18) == 0) {
        return Ok(INVALID);
    }
    if silo_query::current_silo() != 0 {
        return Ok(0xC000_0061);
    }
    if initialize() == 0 {
        return Ok(NO_MEMORY);
    }
    let length = guest::read16(name);
    let pointer = data_pool::alloc(length as u64 + 0x38);
    if pointer == 0 {
        return Ok(NO_MEMORY);
    }
    guest::write8(pointer + 0x10, guest::read8(registration + 1));
    guest::write8(pointer + 0x11, guest::read8(registration + 2));
    guest::write64(pointer + 0x18, guest::read64(registration + 0x10));
    guest::write64(pointer + 0x20, guest::read64(registration + 0x18));
    guest::write16(pointer + 0x28, length);
    guest::write16(pointer + 0x2A, length);
    guest::write64(pointer + 0x30, pointer + 0x38);
    let bytes = guest::read_bytes(guest::read64(name + 8), length as usize);
    guest::write_bytes(pointer + 0x38, &bytes);
    let status = silo_contexts::alloc_slot(pointer + 0x14);
    if status != 0 {
        data_pool::free(pointer)?;
        return Ok(status);
    }
    STATE.lock().records.insert(pointer);
    guest::write64(output, pointer);
    Ok(0)
}

/// PsStartSiloMonitor: CREATE para o host (CreateAsHost) e para cada silo
/// existente; uma falha desfaz com TERMINATE e devolve
/// STATUS_SILO_MONITOR_START_FAILED... (0xC0000240).
pub fn start(pointer: u64) -> Result<u32, KernelError> {
    require(pointer)?;
    let globals = initialize();
    with_lock(globals, || {
        if guest::read64(pointer) != 0 || guest::read64(pointer + 8) != 0 {
            return Ok(0);
        }
        if guest::read8(pointer + 0x11) == 0 && !existing().is_empty() {
            return Ok(NOT_SUPPORTED);
        }
        // Monitores só de término ficam fora da lista.
        if guest::read64(pointer + 0x18) == 0 {
            return Ok(0);
        }
        let terminate = guest::read64(pointer + 0x20) != 0;
        if guest::read8(pointer + 0x10) != 0 {
            let status = with_system(|| {
                let result = invoke(pointer, 0x18, 0);
                if result < 0 && terminate {
                    invoke(pointer, 0x20, 0);
                }
                result
            })?;
            if status < 0 {
                return Ok(status as u32);
            }
        }
        let failed = with_system(|| existing().into_iter().fold(false, |failed, silo| invoke(pointer, 0x18, silo) < 0 || failed))?;
        if failed {
            if terminate {
                with_system(|| {
                    for silo in existing() {
                        invoke(pointer, 0x20, silo);
                    }
                    // O rollback frio do 19041 chama CREATE do host de novo.
                    if guest::read8(pointer + 0x10) != 0 {
                        invoke(pointer, 0x18, 0);
                    }
                })?;
            }
            return Ok(0xC000_0240);
        }
        let tail = guest::read64(globals + 8);
        if guest::read64(tail) != globals {
            return Err(KernelError::new("corrupt silo monitor list"));
        }
        guest::write64(pointer, globals);
        guest::write64(pointer + 8, tail);
        guest::write64(tail, pointer);
        guest::write64(globals + 8, pointer);
        Ok(0)
    })
}

/// PsUnregisterSiloMonitor: TERMINATE para os silos e o host, depois o
/// contexto do host e o slot.
pub fn unregister(pointer: u64) -> Result<u32, KernelError> {
    require(pointer)?;
    let globals = initialize();
    with_lock(globals, || {
        let next = guest::read64(pointer);
        let previous = guest::read64(pointer + 8);
        if next == 0 && previous == 0 {
            return Ok(());
        }
        if guest::read64(pointer + 0x20) != 0 {
            with_system(|| {
                for silo in existing() {
                    invoke(pointer, 0x20, silo);
                }
                if guest::read8(pointer + 0x10) != 0 {
                    invoke(pointer, 0x20, 0);
                }
            })?;
        }
        if guest::read64(next + 8) != pointer || guest::read64(previous) != pointer {
            return Err(KernelError::new("corrupt silo monitor list"));
        }
        guest::write64(previous, next);
        guest::write64(next + 8, previous);
        guest::write64(pointer, 0);
        guest::write64(pointer + 8, 0);
        Ok(())
    })?;
    let slot = guest::read32(pointer + 0x14);
    if guest::read8(pointer + 0x10) != 0 {
        let status = with_system(|| silo_contexts::remove(0, slot, 0, true))??;
        if status != 0 && status != 0xC000_0225 {
            return Err(KernelError::new("monitor host context removal failed"));
        }
    }
    silo_contexts::release_slot(slot);
    STATE.lock().records.remove(&pointer);
    data_pool::free(pointer)?;
    Ok(0)
}

/// PsGetSiloMonitorContextSlot.
pub fn get_slot(pointer: u64) -> Result<u32, KernelError> {
    require(pointer)?;
    Ok(guest::read32(pointer + 0x14))
}
