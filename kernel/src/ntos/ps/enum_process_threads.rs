//! PsGetNextProcessThread / PsEnumProcessThreads.
//!
//! Também os ZwGetNextProcess/ZwGetNextThread em KernelMode, como o
//! NtGetNextProcess/NtGetNextThread do NT: a partir do handle dado (ou do
//! começo), abrem o próximo processo da PsActiveProcessHead (para trás com o
//! bit 0 de Flags) ou a próxima thread do processo; quem não abre é pulado, e
//! o fim da lista é STATUS_NO_MORE_ENTRIES.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use super::process;
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ob::{object_types, open_pointer};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

fn dereference(pointer: u64) {
    match open_pointer::describe(pointer) {
        Some(item) => item.dereference(),
        None => {
            let _ = process::dereference_thread(pointer);
        }
    }
}

fn validate(target: u64) -> Result<(), KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("process thread enumeration requires IRQL <= APC_LEVEL"));
    }
    if !process::is_process(target) {
        return Err(KernelError::new("process thread enumeration requires a live process object"));
    }
    Ok(())
}

/// Seleção da próxima thread. A referência anterior do chamador passa para a
/// requisição; a sucessora devolvida pertence ao chamador, mesmo após cancel.
pub struct NextRequest {
    process: u64,
    previous: u64,
    region: bool,
    done: bool,
    cancelled: bool,
    result: u64,
}

pub fn begin_next(target: u64, previous: u64) -> Result<NextRequest, KernelError> {
    validate(target)?;
    if previous != 0 {
        let owned = process::thread_record(previous).is_some_and(|record| record.process == target) && process::thread_reference_count(previous).unwrap_or(0) != 0;
        if !owned {
            return Err(KernelError::new("previous thread must be referenced and belong to the process"));
        }
    }
    Ok(NextRequest { process: target, previous, region: false, done: false, cancelled: false, result: 0 })
}

impl NextRequest {
    fn leave(&mut self) -> Result<(), KernelError> {
        if self.region {
            self.region = false;
            critical_region::leave_critical()?;
        }
        Ok(())
    }

    fn release_previous(&mut self) {
        let pointer = core::mem::take(&mut self.previous);
        if pointer != 0 {
            dereference(pointer);
        }
    }

    pub fn cancel(&mut self) {
        if self.done {
            return;
        }
        self.cancelled = true;
        self.done = true;
        let _ = self.leave();
        self.release_previous();
    }

    /// `Some(thread)` (0 = fim da lista) ou `None` enquanto um escritor tem o lock.
    pub fn poll(&mut self) -> Result<Option<u64>, KernelError> {
        if self.cancelled {
            return Err(KernelError::new("thread selection was cancelled"));
        }
        if self.done {
            return Ok(Some(self.result));
        }
        if !self.region {
            critical_region::enter_critical()?;
            self.region = true;
        }
        let lock = self.process + eprocess::PROCESS_LOCK;
        // A tentativa real não publica um aguardante não cancelável.
        if !push_lock::try_shared(lock, 0)? {
            return Ok(None);
        }
        let head = self.process + eprocess::THREAD_LIST_HEAD;
        let selected = (|| -> Result<u64, KernelError> {
            let mut cursor = guest::read64(if self.previous != 0 { self.previous + kthread::THREAD_LIST_ENTRY } else { head });
            let mut seen = BTreeSet::new();
            while cursor != head {
                if cursor == 0 || !seen.insert(cursor) {
                    return Err(KernelError::new("corrupt process thread enumeration list"));
                }
                let pointer = cursor - kthread::THREAD_LIST_ENTRY;
                if !process::thread_record(pointer).is_some_and(|record| record.process == self.process) {
                    return Err(KernelError::new("thread list contains an unowned object"));
                }
                if process::reference_thread_safe(pointer) {
                    return Ok(pointer);
                }
                cursor = guest::read64(cursor);
            }
            Ok(0)
        })();
        push_lock::release_shared(lock, 0)?;
        match selected {
            Ok(next) => {
                self.leave()?;
                self.release_previous();
                self.result = next;
                self.done = true;
                Ok(Some(next))
            }
            Err(error) => {
                self.cancel();
                Err(error)
            }
        }
    }
}

/// PsGetNextProcessThread.
pub fn get_next(target: u64, previous: u64) -> Result<u64, KernelError> {
    let mut request = begin_next(target, previous)?;
    let result = loop {
        match request.poll() {
            Ok(Some(next)) => break Ok(next),
            Ok(None) => dispatcher::pump_kernel(),
            Err(error) => break Err(error),
        }
    };
    request.cancel();
    result
}

/// PsEnumProcessThreads: cada thread passa pela rotina (processo, thread,
/// contexto); um NTSTATUS de erro encerra a enumeração.
pub fn enumerate(target: u64, callback: u64, context: u64) -> Result<u32, KernelError> {
    validate(target)?;
    if callback == 0 {
        return Err(KernelError::new("PsEnumProcessThreads requires a callback"));
    }
    let mut previous = 0u64;
    let mut result = 0u32;
    loop {
        let mut selection = begin_next(target, previous)?;
        let next = loop {
            match selection.poll() {
                Ok(Some(next)) => break next,
                Ok(None) => dispatcher::pump_kernel(),
                Err(error) => return Err(error),
            }
        };
        previous = next;
        if previous == 0 {
            return Ok(result);
        }
        result = native_call::call(callback, &[target, previous, context]) as u32;
        if result & 0x8000_0000 != 0 {
            dereference(previous);
            return Ok(result);
        }
    }
}

/// ObReferenceObjectByHandle em KernelMode: Ok(objeto) ou Err(status).
fn reference_handle(handle: u64, object_type: u64) -> Result<Result<u64, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let status = invoke_handler("ObReferenceObjectByHandle", &[handle, 0, object_type, 0, slot, 0]);
    let object = guest::read64(slot);
    guest::free_bytes(slot);
    let status = status? as u32;
    Ok(if status == 0 { Ok(object) } else { Err(status) })
}

/// ObfDereferenceObject.
fn dereference_object(object: u64) -> Result<(), KernelError> {
    invoke_handler("ObfDereferenceObject", &[object]).map(|_| ())
}

/// ZwGetNextProcess(handle, access, attributes, flags, handle*): devolve o
/// NTSTATUS.
pub fn open_next_process(handle: u64, access: u32, attributes: u32, flags: u32, output: u64) -> Result<u32, KernelError> {
    if flags & !1 != 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    let backward = flags & 1 != 0;
    let process_type = object_types::process_type().pointer;
    let current = if handle == 0 {
        None
    } else {
        match reference_handle(handle, process_type)? {
            Ok(object) => Some(object),
            Err(status) => return Ok(status),
        }
    };
    let mut list: Vec<u64> = process::list_active_processes().into_iter().map(|entry| entry.address).collect();
    if backward {
        list.reverse();
    }
    let start = match current {
        Some(object) => list.iter().position(|&address| address == object).map_or(list.len(), |index| index + 1),
        None => 0,
    };
    if let Some(object) = current {
        dereference_object(object)?;
    }
    for &candidate in &list[start.min(list.len())..] {
        if open_pointer::open(candidate, attributes, 0, access, process_type, 0, output)? == 0 {
            return Ok(0);
        }
    }
    Ok(STATUS_NO_MORE_ENTRIES)
}

/// ZwGetNextThread(process, thread, access, attributes, flags, handle*):
/// devolve o NTSTATUS.
pub fn open_next_thread(process_handle: u64, thread_handle: u64, access: u32, attributes: u32, flags: u32, output: u64) -> Result<u32, KernelError> {
    if flags != 0 {
        return Ok(STATUS_INVALID_PARAMETER_5);
    }
    let target = match reference_handle(process_handle, object_types::process_type().pointer)? {
        Ok(object) => object,
        Err(status) => return Ok(status),
    };
    let thread_type = object_types::thread_type().pointer;
    // A referência da thread anterior passa para PsGetNextProcessThread.
    let mut previous = 0;
    if thread_handle != 0 {
        match reference_handle(thread_handle, thread_type)? {
            Ok(thread) if guest::read64(thread + kthread::PROCESS) == target => previous = thread,
            Ok(thread) => {
                dereference_object(thread)?;
                dereference_object(target)?;
                return Ok(STATUS_INVALID_PARAMETER);
            }
            Err(status) => {
                dereference_object(target)?;
                return Ok(status);
            }
        }
    }
    let status = loop {
        let next = get_next(target, previous)?;
        if next == 0 {
            break STATUS_NO_MORE_ENTRIES;
        }
        if open_pointer::open(next, attributes, 0, access, thread_type, 0, output)? == 0 {
            dereference_object(next)?;
            break 0;
        }
        previous = next;
    };
    dereference_object(target)?;
    Ok(status)
}
