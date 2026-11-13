//! Espera ALPC retomável.
//!
//! O pedido mantém seu chamador e libera os recursos ao concluir; o
//! escalonador consulta `poll` e pode cancelar sem suspender um frame.

use alloc::boxed::Box;

use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::ke::{clock, thread_alert, thread_lock};
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

const WINDOWS_EPOCH: u64 = 116_444_736_000_000_000;

/// A entrada Zw fornece PreviousMode zero; WAIT_USER_MODE tem precedência
/// sobre a combinação interna que força KernelMode no envio síncrono.
pub fn select_mode(flags: u32, previous_mode: u8) -> u8 {
    if flags & 0x10_0000 != 0 {
        return 1;
    }
    if flags & 0x200_0000 != 0 && flags & 2 != 0 {
        return 0;
    }
    previous_mode
}

/// LARGE_INTEGER capturado antes da espera: intervalos relativos usam o
/// uptime (em 100 ns), prazos absolutos acompanham o relógio de parede.
#[derive(Clone, Copy, Default)]
pub struct Timeout {
    pub relative_deadline: Option<u64>,
    pub absolute_deadline: Option<u64>,
}

pub fn capture_timeout(pointer: u64, access_mode: u8) -> Result<Timeout, u32> {
    if pointer == 0 {
        return Ok(Timeout::default());
    }
    if !message_buffer::accessible(pointer, 8, access_mode, false) {
        return Err(0xC000_0005);
    }
    let interval = guest::read64(pointer) as i64;
    Ok(if interval <= 0 {
        Timeout { relative_deadline: Some(clock::uptime_ms() * 10_000 + interval.unsigned_abs()), absolute_deadline: None }
    } else {
        Timeout { relative_deadline: None, absolute_deadline: Some(interval as u64) }
    })
}

impl Timeout {
    pub fn expired(&self) -> bool {
        self.relative_deadline.is_some_and(|deadline| clock::uptime_ms() * 10_000 >= deadline) || self.absolute_deadline.is_some_and(|deadline| clock::now_ms() * 10_000 + WINDOWS_EPOCH >= deadline)
    }
}

/// A ordem de KeWaitForSingleObject: alerta do modo pedido, APC de usuário
/// enfileirada e alerta de kernel; sem Alertable, só a pendência já
/// publicada de APC interrompe em UserMode.
pub fn interruption(thread: u64, wait_mode: u8, alertable: bool) -> Option<u32> {
    thread_lock::with_lock(thread, || {
        let kernel_alert = thread + kthread::ALERTED;
        let selected = kernel_alert + wait_mode as u64;
        let pending = thread + kthread::APC_STATE + 0x2A;
        if alertable {
            if guest::read8(selected) != 0 {
                guest::write8(selected, 0);
                return Some(0x101);
            }
            let user_queue = thread + kthread::APC_STATE + 0x10;
            if wait_mode != 0 && guest::read64(user_queue) != user_queue {
                guest::write8(pending, guest::read8(pending) | 2);
                return Some(0xC0);
            }
            if guest::read8(kernel_alert) != 0 {
                guest::write8(kernel_alert, 0);
                return Some(0x101);
            }
        } else if wait_mode != 0 && guest::read8(pending) & 2 != 0 {
            return Some(0xC0);
        }
        None
    })
}

/// Operação de transporte esperada: `poll` devolve o status quando pronta;
/// `cleanup` recebe exatamente o status que encerrou a espera.
pub struct Operation {
    pub poll: Box<dyn FnMut() -> Option<u32>>,
    pub cleanup: Box<dyn FnMut(u32)>,
}

pub struct Request {
    thread: u64,
    operation: Operation,
    timeout: Timeout,
    wait_mode: u8,
    alertable: bool,
    alerts: thread_alert::AlertWait,
    result: Option<u32>,
}

pub fn begin(operation: Operation, timeout: Timeout, wait_mode: u8, alertable: bool) -> Result<Request, KernelError> {
    let thread = process::get_current_thread();
    if process::thread_record(thread).is_none() {
        return Err(KernelError::new("ALPC wait requires a live thread"));
    }
    if wait_mode > 1 {
        return Err(KernelError::new("invalid ALPC wait mode"));
    }
    process::reference_thread(thread);
    let alerts = thread_alert::wait(thread, wait_mode, alertable, false)?;
    Ok(Request { thread, operation, timeout, wait_mode, alertable, alerts, result: None })
}

impl Request {
    fn finish(&mut self, status: u32) -> u32 {
        if let Some(result) = self.result {
            return result;
        }
        self.result = Some(status);
        let _ = self.alerts.finish(status);
        (self.operation.cleanup)(status);
        let _ = process::dereference_thread(self.thread);
        status
    }

    pub fn poll(&mut self) -> Option<u32> {
        if let Some(result) = self.result {
            return Some(result);
        }
        if let Some(signaled) = self.alerts.interrupted() {
            return Some(self.finish(signaled));
        }
        if let Some(ready) = (self.operation.poll)() {
            return Some(self.finish(ready));
        }
        if let Some(interrupted) = interruption(self.thread, self.wait_mode, self.alertable) {
            return Some(self.finish(interrupted));
        }
        if self.timeout.expired() {
            return Some(self.finish(0x102));
        }
        if self.alerts.arm().is_err() {
            return Some(self.finish(0xC000_0120));
        }
        None
    }

    pub fn cancel(&mut self) {
        self.finish(0xC000_0120);
    }
}
