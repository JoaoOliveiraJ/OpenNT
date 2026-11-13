//! PsLookupThreadByThreadId — `system32/ntos/ps/lookup-thread.js`.

use super::process;
use crate::ntos::ps::silo::query as silo_query;
use crate::ntos::ex::push_lock;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ob::open_pointer;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{ejob, eprocess, kthread};

const INVALID: u32 = 0xC000_000B;

fn dereference(pointer: u64) {
    // Threads do kernel passam também pela coleta do escalonador.
    if let Some(item) = open_pointer::describe(pointer) {
        item.dereference();
    } else {
        let _ = process::dereference_thread(pointer);
    }
}

/// O processo da thread é visível no server silo corrente.
fn visible(target: u64, silo: u64) -> bool {
    if silo == 0 || target == process::get_system_process() {
        return true;
    }
    let mut job = silo_query::job_silo(guest::read64(target + eprocess::JOB));
    while job != 0 {
        if job == silo {
            return true;
        }
        job = guest::read64(job + ejob::PARENT);
    }
    false
}

/// Consulta suspensível: espera o InsertionLock de uma thread ainda sendo
/// inserida.
pub struct LookupRequest {
    pointer: u64,
    output: u64,
    silo: u64,
    wait: Option<push_lock::PushLockRequest>,
    closed: bool,
    result: u32,
}

impl LookupRequest {
    fn close(&mut self) -> Result<(), KernelError> {
        if !self.closed {
            self.closed = true;
            critical_region::leave_guarded()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<u32, KernelError> {
        if self.pointer != 0 && guest::read32(self.pointer + kthread::CROSS_THREAD_FLAGS) & 2 != 0 && visible(guest::read64(self.pointer + kthread::PROCESS), self.silo) {
            guest::write64(self.output, self.pointer);
            self.pointer = 0;
            self.result = 0; // o chamador fica com a referência
        } else if self.pointer != 0 {
            dereference(self.pointer);
            self.pointer = 0;
        }
        self.close()?;
        Ok(self.result)
    }

    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if self.closed {
            return Ok(Some(self.result));
        }
        let Some(wait) = self.wait.as_mut() else { return self.finish().map(Some) };
        if wait.poll()?.is_none() {
            return Ok(None);
        }
        push_lock::release_exclusive(self.pointer + kthread::INSERTION_LOCK, 0)?;
        self.wait = None;
        self.finish().map(Some)
    }
}

pub fn begin(id: u64, output: u64) -> Result<LookupRequest, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("PsLookupThreadByThreadId requires IRQL <= APC_LEVEL"));
    }
    critical_region::enter_guarded()?;
    let pointer = process::reference_thread_by_id(id);
    let mut request = LookupRequest { pointer, output, silo: 0, wait: None, closed: false, result: INVALID };
    if pointer != 0 {
        request.silo = silo_query::current_server_silo();
        if guest::read32(pointer + kthread::CROSS_THREAD_FLAGS) & 2 == 0 && guest::read64(pointer + kthread::INSERTION_LOCK) & 1 != 0 {
            request.wait = Some(push_lock::begin(pointer + kthread::INSERTION_LOCK, false, 0)?);
        }
    }
    if request.wait.is_none() {
        request.finish()?;
    }
    Ok(request)
}

pub fn lookup(id: u64, output: u64) -> Result<u32, KernelError> {
    let mut request = begin(id, output)?;
    loop {
        if let Some(status) = request.poll()? {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}
