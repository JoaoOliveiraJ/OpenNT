//! Retirada de pacotes de conclusão — `system32/ntos/io/remove-completion.js`
//! (a indireção de `io/completion-entry` não é necessária em Rust).
//!
//! Captura Nt/Zw, associação do consumidor à fila e a continuação da
//! espera: uma reserva tira o lote da FIFO antes de qualquer callback de
//! liberação; pacotes gerados por esses callbacks são da próxima retirada.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::completion_reference::{self, Reference};
use crate::ntos::alpc::kernel_wait;
use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::ke::{clock, dispatcher, thread_alert, thread_dispatch};
use crate::ntos::ob::objects::completion::{self as completion_objects, Packet, Waiter};
use crate::ntos::ps::process;
use crate::ntos::rtl::native_context;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const ACCESS_VIOLATION: u32 = 0xC000_0005;
const WINDOWS_EPOCH: u64 = 116_444_736_000_000_000;

struct Shared {
    batch: Option<Vec<Packet>>,
    completed: Option<u32>,
    armed: bool,
}

/// Retirada em curso: `poll` conclui ou devolve `None`; `cancel` desfaz.
pub struct Removal {
    immediate: Option<u32>,
    state: Option<Active>,
}

struct Active {
    thread: u64,
    consumer: u64,
    output: u64,
    removed: u64,
    count: u32,
    access_mode: u8,
    alertable: bool,
    interval: Option<i64>,
    relative_deadline: Option<u64>,
    scratch: u64,
    reference: Reference,
    alerts: Arc<SpinLock<thread_alert::AlertWait>>,
    shared: Arc<SpinLock<Shared>>,
    waiter: Arc<Waiter>,
}

impl Removal {
    fn status(status: u32) -> Self {
        Removal { immediate: Some(status), state: None }
    }

    pub fn poll(&mut self) -> Option<u32> {
        if let Some(status) = self.immediate {
            return Some(status);
        }
        let active = self.state.as_mut()?;
        let status = active.poll();
        if let Some(status) = status {
            self.immediate = Some(status);
            self.state = None;
        }
        status
    }

    pub fn cancel(&mut self) {
        if let Some(mut active) = self.state.take() {
            let packets = active.shared.lock().batch.take();
            for packet in packets.into_iter().flatten() {
                if let Some(on_dequeue) = packet.on_dequeue {
                    on_dequeue();
                }
            }
            let status = active.cleanup(0xC000_0120);
            self.immediate = Some(status);
        }
    }
}

impl Active {
    fn port(&self) -> &Arc<completion_objects::Port> {
        &self.reference.port
    }

    fn cleanup(&mut self, status: u32) -> u32 {
        if let Some(result) = self.shared.lock().completed {
            return result;
        }
        self.shared.lock().completed = Some(status);
        let _ = self.alerts.lock().finish(status);
        let waiter = self.waiter.clone();
        self.port().with(|state| state.waiters.retain(|candidate| !Arc::ptr_eq(candidate, &waiter)));
        completion_objects::activate(self.consumer);
        if self.scratch != 0 {
            guest::free_bytes(self.scratch);
            self.scratch = 0;
        }
        let _ = self.reference.release();
        let _ = process::dereference_thread(self.thread);
        status
    }

    fn finish(&mut self, status: u32, number_removed: u32) -> u32 {
        let mut status = status;
        if status & 0x8000_0000 == 0 {
            if !message_buffer::accessible(self.removed, 4, self.access_mode, true) {
                status = ACCESS_VIOLATION;
            } else {
                guest::write32(self.removed, number_removed);
            }
        }
        self.cleanup(status)
    }

    /// A referência original libera cada pacote mesmo se uma cópia falhar.
    fn deliver(&mut self) -> u32 {
        let packets = self.shared.lock().batch.take().unwrap_or_default();
        let mut status = 0;
        let count = packets.len() as u32;
        for (index, packet) in packets.into_iter().enumerate() {
            let (key, context, packet_status, information) = packet.values();
            if let Some(on_dequeue) = packet.on_dequeue {
                on_dequeue();
            }
            for (field, value) in [key, context, packet_status as u64, information].into_iter().enumerate() {
                let address = self.output + index as u64 * 32 + field as u64 * 8;
                if !message_buffer::accessible(address, 8, self.access_mode, true) {
                    status = ACCESS_VIOLATION;
                    break;
                }
                guest::write64(address, value);
            }
        }
        self.finish(status, count)
    }

    fn reserve(&mut self) -> bool {
        reserve(&self.shared, self.port(), &self.alerts, self.consumer, self.count, self.thread)
    }

    fn poll(&mut self) -> Option<u32> {
        if let Some(result) = self.shared.lock().completed {
            return Some(result);
        }
        if self.shared.lock().batch.is_some() {
            return Some(self.deliver());
        }
        let interrupted = self.alerts.lock().interrupted().or_else(|| kernel_wait::interruption(self.thread, self.access_mode, self.alertable));
        if let Some(interrupted) = interrupted {
            return Some(self.finish(interrupted, 1));
        }
        if self.port().closed() {
            return Some(self.finish(0x80, 1));
        }
        let waiter = self.waiter.clone();
        let last = self.port().with(|state| state.waiters.iter().rev().find(|candidate| candidate.thread.is_none_or(completion_objects::thread_eligible)).cloned());
        if last.is_some_and(|last| Arc::ptr_eq(&last, &waiter)) && self.reserve() {
            return Some(self.deliver());
        }
        let expired = self.relative_deadline.is_some_and(|deadline| clock::uptime_ms() * 10_000 >= deadline) || self.interval.is_some_and(|interval| interval > 0 && clock::now_ms() * 10_000 + WINDOWS_EPOCH >= interval as u64);
        if expired {
            return Some(self.finish(0x102, 1));
        }
        if self.alerts.lock().arm().is_err() {
            return Some(self.cleanup(0xC000_0120));
        }
        self.shared.lock().armed = true;
        None
    }
}

/// O lote sai da FIFO antes de qualquer callback de liberação.
fn reserve(shared: &SpinLock<Shared>, port: &completion_objects::Port, alerts: &SpinLock<thread_alert::AlertWait>, consumer: u64, count: u32, thread: u64) -> bool {
    {
        let state = shared.lock();
        if state.completed.is_some() || state.batch.is_some() {
            return false;
        }
    }
    let batch = port.with(|state| {
        if state.packets.is_empty() || port.closed() || state.active.len() as u32 >= port.concurrency() {
            return None;
        }
        let take = (count as usize).min(state.packets.len());
        let batch: Vec<Packet> = state.packets.drain(..take).collect();
        state.active.insert(consumer);
        Some(batch)
    });
    let Some(batch) = batch else { return false };
    let armed = {
        let mut state = shared.lock();
        state.batch = Some(batch);
        state.armed
    };
    let _ = alerts.lock().finish(0);
    if armed && thread_dispatch::owner(thread).is_some() {
        let _ = thread_dispatch::make_ready(thread);
    }
    true
}

/// Começa a retirada de até `count` pacotes (FILE_IO_COMPLETION_INFORMATION
/// de 32 bytes cada) sondando antes o vetor e o ULONG de saída.
#[allow(clippy::too_many_arguments)]
pub fn begin(handle: u64, output: u64, count: u32, removed: u64, timeout: u64, alertable: bool, access_mode: u8, cooperative: bool, consumer: Option<u64>) -> Result<Removal, KernelError> {
    if count == 0 || count > 0x7FF_FFFF {
        return Ok(Removal::status(0xC000_000D));
    }
    // O original sonda o vetor inteiro e o ULONG de saída antes da fila.
    if access_mode != 0 {
        if output & 7 != 0 {
            return Ok(Removal::status(0x8000_0002));
        }
        if !message_buffer::accessible(output, count as u64 * 32, access_mode, true) || !message_buffer::accessible(removed, 4, access_mode, true) {
            return Ok(Removal::status(ACCESS_VIOLATION));
        }
    }
    if access_mode != 0 && timeout != 0 && !message_buffer::accessible(timeout, 8, access_mode, false) {
        return Ok(Removal::status(ACCESS_VIOLATION));
    }
    let mut interval = if access_mode != 0 && timeout != 0 { Some(guest::read64(timeout) as i64) } else { None };
    let mut count = count;
    let mut scratch = 0;
    if count > 16 {
        // Sem o vetor temporário o lote cai para 16, como no 19041.
        scratch = guest::alloc_bytes(count as u64 * 8);
        if scratch == 0 {
            count = 16;
        }
    }
    let mut reference = match completion_reference::reference(handle, access_mode)? {
        Ok(reference) => reference,
        Err(status) => {
            if scratch != 0 {
                guest::free_bytes(scratch);
            }
            return Ok(Removal::status(status));
        }
    };
    if access_mode == 0 && timeout != 0 {
        if !message_buffer::accessible(timeout, 8, 0, false) {
            let _ = reference.release();
            if scratch != 0 {
                guest::free_bytes(scratch);
            }
            return Ok(Removal::status(ACCESS_VIOLATION));
        }
        interval = Some(guest::read64(timeout) as i64);
    }
    let thread = process::get_current_thread();
    if process::thread_record(thread).is_none() {
        let _ = reference.release();
        if scratch != 0 {
            guest::free_bytes(scratch);
        }
        return Err(KernelError::new("completion removal requires a live thread"));
    }
    let consumer = consumer.unwrap_or(thread);
    let alerts = Arc::new(SpinLock::new(thread_alert::wait(thread, access_mode, alertable, cooperative)?));
    let relative_deadline = interval.filter(|&interval| interval <= 0).map(|interval| clock::uptime_ms() * 10_000 + interval.unsigned_abs());
    let shared = Arc::new(SpinLock::new(Shared { batch: None, completed: None, armed: false }));
    process::reference_thread(thread);
    completion_objects::associate(consumer, &reference.port);
    // O consumidor fica na fila LIFO; a reserva é a continuação da espera.
    let (waiting_shared, waiting_alerts) = (shared.clone(), alerts.clone());
    let (reserve_shared, reserve_alerts, reserve_port) = (shared.clone(), alerts.clone(), reference.port.clone());
    let waiter = Arc::new(Waiter {
        thread: Some(consumer),
        waiting: Some(alloc::boxed::Box::new(move || {
            let state = waiting_shared.lock();
            state.armed && state.completed.is_none() && state.batch.is_none() && waiting_alerts.lock().interrupted().is_none()
        })),
        reserve: Some(alloc::boxed::Box::new(move || {
            let armed = reserve_shared.lock().armed;
            armed && reserve_alerts.lock().interrupted().is_none() && reserve(&reserve_shared, &reserve_port, &reserve_alerts, consumer, count, thread)
        })),
    });
    reference.port.with(|state| state.waiters.push(waiter.clone()));
    Ok(Removal { immediate: None, state: Some(Active { thread, consumer, output, removed, count, access_mode, alertable, interval, relative_deadline, scratch, reference, alerts, shared, waiter }) })
}

/// ZwRemoveIoCompletionEx: a entrada Zw de seis argumentos (KernelMode),
/// com espera cooperativa sem contexto suspenso — bombeia o kernel até a
/// retirada concluir. O sinal de transferência continua propagando; outra
/// falha interna interrompe o sistema.
pub fn remove_cooperative(handle: u64, output: u64, count: u32, removed: u64, timeout: u64, alertable: bool) -> Result<u32, KernelError> {
    let result = (|| -> Result<u32, KernelError> {
        let mut request = begin(handle, output, count, removed, timeout, alertable, 0, true, None)?;
        loop {
            if let Some(status) = request.poll() {
                return Ok(status);
            }
            dispatcher::pump_kernel();
        }
    })();
    match result {
        Ok(status) => Ok(status),
        Err(error) if native_context::is_transfer(&error) => Err(error),
        Err(error) => panic!("[remove-completion] fatal kernel failure: {error}"),
    }
}
