//! PsSetCreateThreadNotifyRoutine — `system32/ntos/ps/thread-notify.js`.
//!
//! A rotina nativa medida não verifica imagem nem rejeita ponteiro repetido;
//! o chamador responde por fornecer código válido.

use alloc::vec::Vec;

use crate::ntos::ps::process;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::kernel_pool;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const POOL_TAG: u32 = 0x6272_6243;

#[derive(Clone, Copy)]
struct Registration {
    pointer: u64,
    callback: u64,
    active: u32,
    removed: bool,
    freed: bool,
}

struct State {
    slots: [Option<usize>; 64],
    records: Vec<Registration>,
    executing: Vec<(u64, u32)>,
}

static STATE: SpinLock<State> = SpinLock::new(State { slots: [None; 64], records: Vec::new(), executing: Vec::new() });

fn level(maximum: u8) -> Result<(), KernelError> {
    if irql::get_irql() > maximum {
        return Err(KernelError::new("thread notify at invalid IRQL"));
    }
    Ok(())
}

pub fn register(callback: u64) -> Result<u32, KernelError> {
    level(0)?;
    let pointer = kernel_pool::allocate(24, kernel_pool::AllocateOptions { tag: POOL_TAG, zero: true, ..Default::default() })?;
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    let mut state = STATE.lock();
    let Some(index) = state.slots.iter().position(Option::is_none) else {
        drop(state);
        kernel_pool::free(pointer, None)?;
        return Ok(0xC000_009A);
    };
    guest::write64(pointer + 8, callback);
    state.records.push(Registration { pointer, callback, active: 0, removed: false, freed: false });
    let record = state.records.len() - 1;
    state.slots[index] = Some(record);
    Ok(0)
}

fn collect(record: usize) -> Result<bool, KernelError> {
    let pointer = {
        let mut state = STATE.lock();
        let entry = &mut state.records[record];
        if !(entry.removed && entry.active == 0 && !entry.freed) {
            return Ok(entry.freed);
        }
        entry.freed = true;
        entry.pointer
    };
    kernel_pool::free(pointer, None)?;
    Ok(true)
}

pub struct RemoveRequest {
    record: Option<usize>,
}

impl RemoveRequest {
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        match self.record {
            None => Ok(Some(0xC000_007A)),
            Some(record) => Ok(collect(record)?.then_some(0)),
        }
    }
}

/// A remoção também pode ocorrer depois que a busca do registro passou.
pub fn begin_remove(callback: u64) -> Result<RemoveRequest, KernelError> {
    level(1)?;
    let thread = process::get_current_thread();
    let record = {
        let mut state = STATE.lock();
        if state.executing.iter().any(|&(owner, depth)| owner == thread && depth > 0) {
            return Err(KernelError::new("thread notify removal inside a notification"));
        }
        let found = state.slots.iter().position(|slot| slot.is_some_and(|record| state.records[record].callback == callback));
        let Some(index) = found else { return Ok(RemoveRequest { record: None }) };
        let record = state.slots[index].take().unwrap();
        state.records[record].removed = true;
        record
    };
    collect(record)?;
    Ok(RemoveRequest { record: Some(record) })
}

pub fn remove(callback: u64) -> Result<u32, KernelError> {
    let mut request = begin_remove(callback)?;
    loop {
        if let Some(status) = request.poll()? {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

pub fn notify(owner_id: u64, thread_id: u64, created: bool) -> Result<(), KernelError> {
    if STATE.lock().slots.iter().all(Option::is_none) {
        return Ok(());
    }
    level(1)?;
    let thread = process::get_current_thread();
    critical_region::with_critical(|| {
        {
            let mut state = STATE.lock();
            match state.executing.iter_mut().find(|(owner, _)| *owner == thread) {
                Some((_, depth)) => *depth += 1,
                None => state.executing.push((thread, 1)),
            }
        }
        let mut failure = None;
        for index in 0..64 {
            let entry = {
                let mut state = STATE.lock();
                let Some(record) = state.slots[index] else { continue };
                state.records[record].active += 1;
                (record, state.records[record].callback)
            };
            native_call::call(entry.1, &[owner_id, thread_id, created as u64]);
            STATE.lock().records[entry.0].active -= 1;
            if let Err(error) = collect(entry.0) {
                failure.get_or_insert(error);
            }
        }
        {
            let mut state = STATE.lock();
            if let Some(position) = state.executing.iter().position(|&(owner, _)| owner == thread) {
                state.executing[position].1 -= 1;
                if state.executing[position].1 == 0 {
                    state.executing.remove(position);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    })
}
