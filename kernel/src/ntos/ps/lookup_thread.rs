//! PsLookupThreadByThreadId.

use super::process;
use crate::ntos::ps::silo::query as silo_query;
use crate::ntos::ex::push_lock;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ob::open_pointer;
use crate::rtl::KernelError;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Ejob, Eprocess, Ethread};

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: thread referenciada por esta consulta.
    unsafe { Ethread::at(thread) }
}

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
    // SAFETY: o processo dono da thread referenciada.
    let mut job = silo_query::job_silo(unsafe { Eprocess::at(target) }.job.get());
    while job != 0 {
        if job == silo {
            return true;
        }
        // SAFETY: jobs da cadeia de pais, vivos enquanto o processo vive.
        job = unsafe { Ejob::at(job) }.parent_job.get();
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
        if self.pointer != 0 && ethread(self.pointer).thread_inserted() != 0 && visible(ethread(self.pointer).tcb.process.get(), self.silo) {
            // SAFETY: PETHREAD* de saída do chamador de kernel.
            unsafe { Field::<u64>::at(self.output) }.set(self.pointer);
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
        push_lock::release_exclusive(ethread(self.pointer).thread_lock.value.address(), 0)?;
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
        let thread = ethread(pointer);
        if thread.thread_inserted() == 0 && thread.thread_lock.value.get() & 1 != 0 {
            request.wait = Some(push_lock::begin(thread.thread_lock.value.address(), false, 0)?);
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
