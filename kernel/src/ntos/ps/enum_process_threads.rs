//! PsGetNextProcessThread / PsEnumProcessThreads — `system32/ntos/ps/enum-process-threads.js`.

use alloc::collections::BTreeSet;

use super::process;
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ob::open_pointer;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{eprocess, kthread};

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
