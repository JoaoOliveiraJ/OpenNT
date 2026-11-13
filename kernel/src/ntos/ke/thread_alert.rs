//! Alertas de thread.
//!
//! Os alertas pertencem à KTHREAD; o descritor de espera retido permite
//! interromper uma espera real. Esperas podem aninhar (uma APC espera durante
//! outra espera): os campos nativos da espera externa são restaurados.

use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{thread_dispatch, thread_lock};
use crate::ntos::inc::types::{Kthread, NtStruct};
use crate::rtl::{KernelError, SpinLock};

pub const STATUS_ALERTED: u32 = 0x101;
pub const STATUS_USER_APC: u32 = 0xC0;

/// KWAIT_STATUS_REGISTER.Alert (bit 7).
const WAIT_REGISTER_ALERT: u8 = 0x80;
/// KWAIT_STATUS_REGISTER: WaitInProgress.
const WAIT_IN_PROGRESS: u8 = 1;
/// KTHREAD.State Waiting.
const STATE_WAITING: u8 = 5;

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva (a thread alertada ou a que espera).
    unsafe { Kthread::at(thread) }
}

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
    kthread(thread).wait_status.set(STATUS_ALERTED as i64);
    true
}

/// KeAlertThread: devolve o byte anterior; alertas repetidos não contam.
pub fn alert(thread: u64, mode: u8) -> Result<u8, KernelError> {
    let mode_index = mode as i8 as i64;
    let mut delivered = false;
    let target = kthread(thread);
    let previous = thread_lock::with_lock(thread, || {
        // Alerted[mode]: KernelMode 0, UserMode 1.
        let alerted = &target.alerted[mode_index as usize];
        let previous = alerted.get();
        if previous != 0 {
            return previous;
        }
        let register = target.wait_register.flags.get();
        let state = register & 7;
        if target.state.get() == STATE_WAITING
            && state != 3
            && state != 4
            && target.alertable() != 0
            && mode_index <= target.wait_mode.get() as u8 as i64
        {
            delivered = signal(thread);
            target.wait_register.flags.set(register | WAIT_REGISTER_ALERT);
        }
        if !delivered {
            alerted.set(1);
        }
        previous
    });
    // A prontidão é publicada depois de soltar o ThreadLock.
    if delivered && thread_dispatch::owner(thread).is_some() {
        thread_dispatch::make_ready(thread)?;
    }
    Ok(previous)
}

/// A ordem de KeWaitForSingleObject: alerta do modo pedido, APC de
/// usuário enfileirada (publica UserApcPending) e alerta de kernel;
/// sem Alertable, só a pendência já publicada interrompe uma espera
/// de UserMode.
pub fn consume(thread: u64, wait_mode: u8, alertable: bool) -> Option<u32> {
    if !alertable && wait_mode == 0 {
        return None;
    }
    let target = kthread(thread);
    thread_lock::with_lock(thread, || {
        let apc_state = &target.apc_state;
        if !alertable {
            return (apc_state.user_apc_pending() != 0).then_some(STATUS_USER_APC);
        }
        let selected = &target.alerted[wait_mode as usize];
        if selected.get() != 0 {
            selected.set(0);
            return Some(STATUS_ALERTED);
        }
        // ApcListHead[UserMode] não vazia: UserApcPending por CAS no byte.
        let user_queue = &apc_state.apc_list_head[1];
        if wait_mode != 0 && user_queue.flink.get() != user_queue.address() {
            apc_state.set_user_apc_pending(1);
            return Some(STATUS_USER_APC);
        }
        let kernel = &target.alerted[0];
        if kernel.get() != 0 {
            kernel.set(0);
            return Some(STATUS_ALERTED);
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
        let target = kthread(thread);
        let (previous_waiter, previous_fields) = thread_lock::with_lock(thread, || {
            let previous_waiter = WAITING.lock().insert(thread, me);
            let previous_fields = previous_waiter.map(|_| SavedFields {
                alertable: target.alertable(),
                mode: target.wait_mode.get() as u8,
                register: target.wait_register.flags.get(),
                status: target.wait_status.get() as u64,
            });
            // MiscFlags.Alertable: CAS atômico (o DWORD tem outros donos).
            target.set_alertable(self.alertable as u32);
            target.wait_mode.set(self.mode as i8);
            target.wait_register.flags.set(WAIT_IN_PROGRESS);
            (previous_waiter, previous_fields)
        });
        self.previous_waiter = previous_waiter;
        self.previous_fields = previous_fields;
        self.armed = true;
        // A fila nativa perde o vínculo pronto quando a thread passa a esperar.
        if thread_dispatch::owner(thread).is_some() {
            thread_dispatch::suspend(thread, thread_dispatch::state::WAITING)?;
        } else {
            target.state.set(STATE_WAITING);
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
        let target = kthread(thread);
        thread_lock::with_lock(thread, || match (previous_waiter, previous_fields) {
            (Some(waiter), Some(fields)) => {
                WAITING.lock().insert(thread, waiter);
                target.set_alertable(fields.alertable);
                target.wait_mode.set(fields.mode as i8);
                target.wait_register.flags.set(fields.register);
                target.wait_status.set(fields.status as i64);
            }
            _ => {
                WAITING.lock().remove(&thread);
                target.wait_status.set(status as i64);
            }
        });
        if self.cooperative && thread_dispatch::owner(thread).is_some() {
            thread_dispatch::suspend(thread, self.previous_state)?;
        } else if thread_dispatch::owner(thread).is_none() {
            target.state.set(self.previous_state);
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
