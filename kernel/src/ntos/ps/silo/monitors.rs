//! Monitores de server silo.
//!
//! PsRegisterSiloMonitor / PsStartSiloMonitor / PsUnregisterSiloMonitor.
//! Corpo do monitor ([`SiloMonitor`], 0x38 + nome): LIST_ENTRY,
//! CreateAsHost (+0x10), RequestedOnSystemSilo (+0x11), slot (+0x14),
//! CreateCallback (+0x18), TerminateCallback (+0x20) e UNICODE_STRING do nome
//! (+0x28), com os caracteres logo depois.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ntos::ps::{process, process_context};
use crate::ntos::ps::silo::{contexts as silo_contexts, query as silo_query};
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Ejob, EserversiloGlobals, ExPushLock, ListEntry, SiloMonitorRegistration, UnicodeString};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::data_pool;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const INVALID: u32 = 0xC000_000D;
const NO_MEMORY: u32 = 0xC000_009A;
const NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Corpo do monitor (layout do OpenNT; drivers só veem o PSILO_MONITOR opaco).
#[repr(C)]
struct SiloMonitor {
    /// Elo na lista global dos monitores iniciados (zerado fora dela).
    links: ListEntry,
    create_as_host: Field<u8>,
    requested_on_system_silo: Field<u8>,
    _pad_12: Reserved<2>,
    /// Slot de contexto de silo do monitor.
    slot: Field<u32>,
    create_callback: Field<u64>,
    terminate_callback: Field<u64>,
    /// Nome do componente; o buffer fica logo depois do corpo.
    name: UnicodeString,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SiloMonitor {}

/// Lista global dos monitores: cabeça + push lock.
#[repr(C)]
struct MonitorList {
    head: ListEntry,
    lock: ExPushLock,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for MonitorList {}

const _: () = {
    assert!(core::mem::size_of::<SiloMonitor>() == 0x38);
    assert!(core::mem::offset_of!(SiloMonitor, create_as_host) == 0x10);
    assert!(core::mem::offset_of!(SiloMonitor, slot) == 0x14);
    assert!(core::mem::offset_of!(SiloMonitor, create_callback) == 0x18);
    assert!(core::mem::offset_of!(SiloMonitor, terminate_callback) == 0x20);
    assert!(core::mem::offset_of!(SiloMonitor, name) == 0x28);
    assert!(core::mem::size_of::<MonitorList>() == 0x18);
};

struct State {
    records: BTreeSet<u64>,
    globals: u64,
}

static STATE: SpinLock<State> = SpinLock::new(State { records: BTreeSet::new(), globals: 0 });

fn monitor(pointer: u64) -> &'static SiloMonitor {
    // SAFETY: `pointer` é um corpo registrado por `register` (conferido por `require`).
    unsafe { SiloMonitor::at(pointer) }
}

fn list(globals: u64) -> &'static MonitorList {
    // SAFETY: a lista global alocada por `initialize`.
    unsafe { MonitorList::at(globals) }
}

/// Lista global de monitores (cabeça + push lock em +16).
fn initialize() -> u64 {
    let mut state = STATE.lock();
    if state.globals != 0 {
        return state.globals;
    }
    let globals = guest::alloc_bytes(MonitorList::SIZE);
    if globals != 0 {
        let list = list(globals);
        list.head.flink.set(globals);
        list.head.blink.set(globals);
        list.lock.value.set(0);
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
            // SAFETY: os silos donos de tabela de contexto estão vivos.
            let global = unsafe { Ejob::at(silo) }.server_silo_globals.get();
            // SAFETY: EJOB.ServerSiloGlobals aponta para o ESERVERSILO_GLOBALS do silo.
            global != 0 && (1..=3).contains(&unsafe { EserversiloGlobals::at(global) }.state.get().0)
        })
        .collect()
}

fn with_lock<T>(globals: u64, body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let lock = list(globals).lock.value.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let result = body();
        push_lock::release_exclusive(lock, 0)?;
        result
    })
}

fn with_system<T>(body: impl FnOnce() -> T) -> Result<T, KernelError> {
    process_context::with_process(process::get_system_process(), body)
}

/// Chama a rotina do monitor com o silo; devolve o NTSTATUS com sinal.
fn invoke(routine: &Field<u64>, silo: u64) -> i32 {
    native_call::call(routine.get(), &[silo]) as u32 as i32
}

/// PsRegisterSiloMonitor(SILO_MONITOR_REGISTRATION, saída).
pub fn register(registration: u64, output: u64) -> Result<u32, KernelError> {
    // SAFETY: SILO_MONITOR_REGISTRATION do driver chamador.
    let registration = unsafe { SiloMonitorRegistration::at(registration) };
    if registration.version.get() == 0 {
        return Ok(INVALID);
    }
    let name = registration.driver_object_name.get();
    // SAFETY: PUNICODE_STRING do registro (conferido não nulo).
    if name == 0 || unsafe { UnicodeString::at(name) }.length.get() == 0 || (registration.create_callback.get() == 0 && registration.terminate_callback.get() == 0) {
        return Ok(INVALID);
    }
    // SAFETY: idem.
    let name = unsafe { UnicodeString::at(name) };
    if silo_query::current_silo() != 0 {
        return Ok(0xC000_0061);
    }
    if initialize() == 0 {
        return Ok(NO_MEMORY);
    }
    let length = name.length.get();
    let pointer = data_pool::alloc(length as u64 + SiloMonitor::SIZE);
    if pointer == 0 {
        return Ok(NO_MEMORY);
    }
    let body = monitor(pointer);
    body.create_as_host.set(registration.monitor_host.get());
    body.requested_on_system_silo.set(registration.monitor_existing_silos.get());
    body.create_callback.set(registration.create_callback.get());
    body.terminate_callback.set(registration.terminate_callback.get());
    body.name.length.set(length);
    body.name.maximum_length.set(length);
    body.name.buffer.set(pointer + SiloMonitor::SIZE);
    let bytes = guest::read_bytes(name.buffer.get(), length as usize);
    guest::write_bytes(pointer + SiloMonitor::SIZE, &bytes);
    let status = silo_contexts::alloc_slot(body.slot.address());
    if status != 0 {
        data_pool::free(pointer)?;
        return Ok(status);
    }
    STATE.lock().records.insert(pointer);
    // SAFETY: PSILO_MONITOR* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(pointer);
    Ok(0)
}

/// PsStartSiloMonitor: CREATE para o host (CreateAsHost) e para cada silo
/// existente; uma falha desfaz com TERMINATE e devolve
/// STATUS_SILO_MONITOR_START_FAILED... (0xC0000240).
pub fn start(pointer: u64) -> Result<u32, KernelError> {
    require(pointer)?;
    let body = monitor(pointer);
    let globals = initialize();
    with_lock(globals, || {
        if body.links.flink.get() != 0 || body.links.blink.get() != 0 {
            return Ok(0);
        }
        if body.requested_on_system_silo.get() == 0 && !existing().is_empty() {
            return Ok(NOT_SUPPORTED);
        }
        // Monitores só de término ficam fora da lista.
        if body.create_callback.get() == 0 {
            return Ok(0);
        }
        let terminate = body.terminate_callback.get() != 0;
        if body.create_as_host.get() != 0 {
            let status = with_system(|| {
                let result = invoke(&body.create_callback, 0);
                if result < 0 && terminate {
                    invoke(&body.terminate_callback, 0);
                }
                result
            })?;
            if status < 0 {
                return Ok(status as u32);
            }
        }
        let failed = with_system(|| existing().into_iter().fold(false, |failed, silo| invoke(&body.create_callback, silo) < 0 || failed))?;
        if failed {
            if terminate {
                with_system(|| {
                    for silo in existing() {
                        invoke(&body.terminate_callback, silo);
                    }
                    // O rollback frio do 19041 chama CREATE do host de novo.
                    if body.create_as_host.get() != 0 {
                        invoke(&body.create_callback, 0);
                    }
                })?;
            }
            return Ok(0xC000_0240);
        }
        let head = &list(globals).head;
        let tail = head.blink.get();
        // SAFETY: Blink da cabeça é o último elo da lista global.
        let last = unsafe { ListEntry::at(tail) };
        if last.flink.get() != globals {
            return Err(KernelError::new("corrupt silo monitor list"));
        }
        body.links.flink.set(globals);
        body.links.blink.set(tail);
        last.flink.set(pointer);
        head.blink.set(pointer);
        Ok(0)
    })
}

/// PsUnregisterSiloMonitor: TERMINATE para os silos e o host, depois o
/// contexto do host e o slot.
pub fn unregister(pointer: u64) -> Result<u32, KernelError> {
    require(pointer)?;
    let body = monitor(pointer);
    let globals = initialize();
    with_lock(globals, || {
        let next = body.links.flink.get();
        let previous = body.links.blink.get();
        if next == 0 && previous == 0 {
            return Ok(());
        }
        if body.terminate_callback.get() != 0 {
            with_system(|| {
                for silo in existing() {
                    invoke(&body.terminate_callback, silo);
                }
                if body.create_as_host.get() != 0 {
                    invoke(&body.terminate_callback, 0);
                }
            })?;
        }
        // SAFETY: vizinhos na lista global, que o lock exclusivo protege.
        let (following, preceding) = unsafe { (ListEntry::at(next), ListEntry::at(previous)) };
        if following.blink.get() != pointer || preceding.flink.get() != pointer {
            return Err(KernelError::new("corrupt silo monitor list"));
        }
        preceding.flink.set(next);
        following.blink.set(previous);
        body.links.flink.set(0);
        body.links.blink.set(0);
        Ok(())
    })?;
    let slot = body.slot.get();
    if body.create_as_host.get() != 0 {
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
    Ok(monitor(pointer).slot.get())
}
