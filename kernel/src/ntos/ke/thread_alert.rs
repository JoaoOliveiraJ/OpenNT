//! Alertas de thread.
//!
//! Os alertas pertencem à KTHREAD; o descritor de espera retido permite
//! interromper uma espera real. Esperas podem aninhar (uma APC espera durante
//! outra espera): os campos nativos da espera externa são restaurados.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{thread_dispatch, thread_lock};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

pub const STATUS_ALERTED: u32 = 0x101;

/// Espera armada: identidade e resultado da interrupção.
#[derive(Clone, Copy)]
struct Waiter {
    id: u64,
    interrupted: Option<u32>,
    completed: bool,
}

static WAITING: SpinLock<BTreeMap<u64, Waiter>> = SpinLock::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Sinaliza a espera armada da thread; `true` se interrompeu.
fn signal(thread: u64) -> bool {
    let mut waiting = WAITING.lock();
    let Some(waiter) = waiting.get_mut(&thread) else { return false };
    if waiter.completed || waiter.interrupted.is_some() {
        return false;
    }
    waiter.interrupted = Some(STATUS_ALERTED);
    guest::write64(thread + kthread::WAIT_STATUS, STATUS_ALERTED as u64);
    true
}

/// KeAlertThread: devolve o byte anterior; alertas repetidos não contam.
pub fn alert(thread: u64, mode: u8) -> Result<u8, KernelError> {
    let mode_index = mode as i8 as i64;
    let mut delivered = false;
    let previous = thread_lock::with_lock(thread, || {
        let alert_address = (thread + kthread::ALERTED).wrapping_add(mode_index as u64);
        let previous = guest::read8(alert_address);
        if previous != 0 {
            return previous;
        }
        let register = guest::read8(thread + kthread::WAIT_REGISTER);
        let state = register & 7;
        if guest::read8(thread + kthread::STATE) == 5
            && state != 3
            && state != 4
            && guest::read32(thread + kthread::MISC_FLAGS) & 0x10 != 0
            && mode_index <= guest::read8(thread + kthread::WAIT_MODE) as i64
        {
            delivered = signal(thread);
            guest::write8(thread + kthread::WAIT_REGISTER, register | 0x80);
        }
        if !delivered {
            guest::write8(alert_address, 1);
        }
        previous
    });
    // A prontidão é publicada depois de soltar o ThreadLock.
    if delivered && thread_dispatch::owner(thread).is_some() {
        thread_dispatch::make_ready(thread)?;
    }
    Ok(previous)
}

/// Um alerta de kernel também interrompe espera alertável de usuário.
pub fn consume(thread: u64, wait_mode: u8, alertable: bool) -> Option<u32> {
    if !alertable {
        return None;
    }
    thread_lock::with_lock(thread, || {
        let kernel = thread + kthread::ALERTED;
        let selected = kernel + wait_mode as u64;
        let addresses: &[u64] = if wait_mode != 0 { &[selected, kernel] } else { &[kernel] };
        for &address in addresses {
            if guest::read8(address) != 0 {
                guest::write8(address, 0);
                return Some(STATUS_ALERTED);
            }
        }
        None
    })
}

struct SavedFields {
    alertable: u32,
    mode: u8,
    register: u8,
    status: u64,
}

/// Descritor de uma espera (registrado só quando de fato fica pendente).
pub struct AlertWait {
    thread: u64,
    mode: u8,
    alertable: bool,
    cooperative: bool,
    id: u64,
    armed: bool,
    completed: bool,
    previous_waiter: Option<Waiter>,
    previous_state: u8,
    previous_fields: Option<SavedFields>,
}

pub fn wait(thread: u64, wait_mode: u8, alertable: bool, cooperative: bool) -> Result<AlertWait, KernelError> {
    if wait_mode > 1 {
        return Err(KernelError::new("invalid alert wait mode"));
    }
    Ok(AlertWait {
        thread,
        mode: wait_mode,
        alertable,
        cooperative,
        id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
        armed: false,
        completed: false,
        previous_waiter: None,
        previous_state: 0,
        previous_fields: None,
    })
}

impl AlertWait {
    pub fn interrupted(&self) -> Option<u32> {
        WAITING.lock().get(&self.thread).filter(|waiter| waiter.id == self.id).and_then(|waiter| waiter.interrupted)
    }

    pub fn pending(&self) -> Option<u32> {
        self.interrupted().or_else(|| consume(self.thread, self.mode, self.alertable))
    }

    pub fn arm(&mut self) -> Result<(), KernelError> {
        if self.armed || self.completed {
            return Ok(());
        }
        let thread = self.thread;
        self.previous_state = thread_dispatch::thread_state(thread);
        let me = Waiter { id: self.id, interrupted: None, completed: false };
        let (previous_waiter, previous_fields) = thread_lock::with_lock(thread, || {
            let flags = thread + kthread::MISC_FLAGS;
            let previous_waiter = WAITING.lock().insert(thread, me);
            let previous_fields = previous_waiter.map(|_| SavedFields {
                alertable: guest::read32(flags) & 0x10,
                mode: guest::read8(thread + kthread::WAIT_MODE),
                register: guest::read8(thread + kthread::WAIT_REGISTER),
                status: guest::read64(thread + kthread::WAIT_STATUS),
            });
            guest::write32(flags, (guest::read32(flags) & !0x10) | if self.alertable { 0x10 } else { 0 });
            guest::write8(thread + kthread::WAIT_MODE, self.mode);
            guest::write8(thread + kthread::WAIT_REGISTER, 1);
            (previous_waiter, previous_fields)
        });
        self.previous_waiter = previous_waiter;
        self.previous_fields = previous_fields;
        self.armed = true;
        // A fila nativa perde o vínculo pronto quando a thread passa a esperar.
        if thread_dispatch::owner(thread).is_some() {
            thread_dispatch::suspend(thread, thread_dispatch::state::WAITING)?;
        } else {
            guest::write8(thread + kthread::STATE, 5);
        }
        Ok(())
    }

    pub fn finish(&mut self, status: u32) -> Result<(), KernelError> {
        if self.completed {
            return Ok(());
        }
        self.completed = true;
        if !self.armed {
            return Ok(());
        }
        let thread = self.thread;
        if WAITING.lock().get(&thread).map(|waiter| waiter.id) != Some(self.id) {
            return Err(KernelError::new("alert wait ownership mismatch"));
        }
        let previous_waiter = self.previous_waiter.take();
        let previous_fields = self.previous_fields.take();
        thread_lock::with_lock(thread, || match (previous_waiter, previous_fields) {
            (Some(waiter), Some(fields)) => {
                WAITING.lock().insert(thread, waiter);
                let flags = thread + kthread::MISC_FLAGS;
                guest::write32(flags, (guest::read32(flags) & !0x10) | fields.alertable);
                guest::write8(thread + kthread::WAIT_MODE, fields.mode);
                guest::write8(thread + kthread::WAIT_REGISTER, fields.register);
                guest::write64(thread + kthread::WAIT_STATUS, fields.status);
            }
            _ => {
                WAITING.lock().remove(&thread);
                guest::write64(thread + kthread::WAIT_STATUS, status as u64);
            }
        });
        if self.cooperative && thread_dispatch::owner(thread).is_some() {
            thread_dispatch::suspend(thread, self.previous_state)?;
        } else if thread_dispatch::owner(thread).is_none() {
            guest::write8(thread + kthread::STATE, self.previous_state);
        }
        Ok(())
    }
}

/// Espera cooperativa: `poll` devolve `Some(status)` quando pronta; `pump`
/// entrega as demais threads entre tentativas.
pub fn cooperate(thread: u64, wait_mode: u8, alertable: bool, poll: &mut dyn FnMut() -> Option<u32>, pump: fn()) -> u32 {
    let Ok(mut alerts) = wait(thread, wait_mode, alertable, true) else { return 0xC000_000D };
    let mut result = 0xC000_0120;
    loop {
        let ready = alerts.pending().or_else(&mut *poll);
        if let Some(status) = ready {
            result = status;
            break;
        }
        if alerts.arm().is_err() {
            break;
        }
        pump();
    }
    let _ = alerts.finish(result);
    result
}
