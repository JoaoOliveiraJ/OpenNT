//! Transporte de conclusão de uma operação de contexto.
//!
//! A operação roda na thread de destino, sob as filas KAPC e os contadores
//! de desabilitação existentes; não é a implementação pública de
//! PsSetContextThread nem uma sonda de export.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use crate::ntos::ke::{apc, critical_region, irql};
use crate::ntos::ps::{kernel_threads, process};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::init::exports::private_routines;

const UNSUCCESSFUL: u32 = 0xC000_0001;

/// Operação executada na thread de destino; devolve o NTSTATUS.
pub type Operation = Box<dyn FnMut() -> Result<u32, KernelError> + Send>;

struct EntryState {
    operation: Option<Operation>,
    pointer: u64,
    done: bool,
    status: u32,
    error: Option<KernelError>,
}

struct Entry {
    thread: u64,
    state: SpinLock<EntryState>,
}

static REQUESTS: SpinLock<BTreeMap<u64, Arc<Entry>>> = SpinLock::new(BTreeMap::new());

fn dereference(thread: u64) {
    if !matches!(kernel_threads::dereference(thread), Ok(Some(_))) {
        let _ = process::dereference_thread(thread);
    }
}

fn finish(entry: &Entry, status: u32, error: Option<KernelError>) {
    let pointer = {
        let mut state = entry.state.lock();
        if state.done {
            return;
        }
        state.done = true;
        state.status = status;
        state.error = error;
        core::mem::replace(&mut state.pointer, 0)
    };
    if pointer != 0 {
        REQUESTS.lock().remove(&pointer);
        guest::free_bytes(pointer);
    }
    dereference(entry.thread);
}

fn invoke(entry: &Entry) {
    let operation = entry.state.lock().operation.take();
    let (status, error) = match operation.map(|mut operation| operation()) {
        Some(Ok(status)) => (status, None),
        Some(Err(error)) => (UNSUCCESSFUL, Some(error)),
        None => (UNSUCCESSFUL, Some(KernelError::new("context operation already consumed"))),
    };
    finish(entry, status, error);
}

/// Operação em andamento: `poll` devolve o status quando concluída.
pub struct Request {
    entry: Arc<Entry>,
}

impl Request {
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        let mut state = self.entry.state.lock();
        if !state.done {
            return Ok(None);
        }
        if let Some(error) = state.error.take() {
            return Err(error);
        }
        Ok(Some(state.status))
    }

    pub fn cancel(&mut self) -> Result<(), KernelError> {
        let (done, pointer) = {
            let state = self.entry.state.lock();
            (state.done, state.pointer)
        };
        if done {
            return Ok(());
        }
        if pointer != 0 && !apc::remove(pointer)? {
            return Err(KernelError::new("context APC cancellation raced delivery"));
        }
        finish(&self.entry, UNSUCCESSFUL, None);
        Ok(())
    }
}

pub fn begin(thread: u64, operation: Operation) -> Result<Request, KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("context operation requires IRQL <= APC_LEVEL"));
    }
    let Some(record) = process::thread_record(thread) else { return Err(KernelError::new("context operation requires an existing ETHREAD")) };
    let entry = Arc::new(Entry { thread, state: SpinLock::new(EntryState { operation: Some(operation), pointer: 0, done: false, status: UNSUCCESSFUL, error: None }) });
    if record.exiting || !process::reference_thread_safe(thread) {
        entry.state.lock().done = true;
        return Ok(Request { entry });
    }
    let request = Request { entry: entry.clone() };
    let started = (|| -> Result<(), KernelError> {
        if thread == process::get_current_thread() {
            critical_region::enter_guarded()?;
            invoke(&entry);
            critical_region::leave_guarded()?;
            return Ok(());
        }
        let pointer = guest::alloc_bytes(apc::kapc::SIZE as u64);
        if pointer == 0 {
            finish(&entry, 0xC000_009A, None);
            return Ok(());
        }
        entry.state.lock().pointer = pointer;
        REQUESTS.lock().insert(pointer, entry.clone());
        apc::initialize(pointer, thread, 0, private_routines::address("PspContextOperationApc"), private_routines::address("PspContextOperationRundown"), 0, 0, 0);
        if !apc::insert(pointer, 0, 0) {
            finish(&entry, UNSUCCESSFUL, None);
        }
        Ok(())
    })();
    if let Err(error) = started {
        let pointer = entry.state.lock().pointer;
        if pointer != 0 && guest::read8(pointer + 0x52) != 0 {
            let _ = apc::remove(pointer);
        }
        if entry.state.lock().done {
            return Err(error);
        }
        finish(&entry, UNSUCCESSFUL, Some(error));
    }
    Ok(request)
}

/// PspContextOperationApc: a entrega na thread de destino.
pub fn deliver(pointer: u64) -> Result<u64, KernelError> {
    let Some(entry) = REQUESTS.lock().get(&pointer).cloned().filter(|entry| !entry.state.lock().done) else { return Err(KernelError::new("unknown context APC")) };
    if entry.thread != process::get_current_thread() {
        return Err(KernelError::new("context APC delivered to the wrong thread"));
    }
    if process::thread_record(entry.thread).is_some_and(|record| !record.exiting) {
        invoke(&entry);
    } else {
        finish(&entry, UNSUCCESSFUL, None);
    }
    Ok(0)
}

/// PspContextOperationRundown: a thread saiu antes da entrega.
pub fn rundown(pointer: u64) -> Result<u64, KernelError> {
    let Some(entry) = REQUESTS.lock().get(&pointer).cloned().filter(|entry| !entry.state.lock().done) else { return Err(KernelError::new("unknown context APC rundown")) };
    finish(&entry, UNSUCCESSFUL, None);
    Ok(0)
}

pub fn execute(thread: u64, operation: Operation) -> Result<u32, KernelError> {
    let mut request = begin(thread, operation)?;
    let result = loop {
        match request.poll() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) => crate::ntos::ke::dispatcher::pump_kernel(),
            Err(error) => break Err(error),
        }
    };
    request.cancel()?;
    result
}
