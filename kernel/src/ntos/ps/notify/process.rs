//! PsSetCreateProcessNotifyRoutine(Ex).
//!
//! Os registros compartilham a tabela nativa de 64 slots. Um slot removido
//! não recebe nova notificação; seu bloco vive até que toda invocação que o
//! segura retorne.

use alloc::vec::Vec;

use crate::ntos::ps::process::{self, ProcessImage};
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::{kernel_pool, loaded_images};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const POOL_TAG: u32 = 0x6272_6243; // 'Cbrb'

#[derive(Clone, Copy)]
struct Registration {
    pointer: u64,
    callback: u64,
    extended: bool,
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

fn passive() -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("process notify requires PASSIVE_LEVEL"));
    }
    Ok(())
}

/// Ex exige IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY (0x80) na imagem.
fn verified(callback: u64, extended: bool) -> bool {
    let Some(image) = loaded_images::find(callback) else { return false };
    if !extended {
        return true;
    }
    let pe = guest::read32(image.image_base + 0x3C) as u64;
    guest::read16(image.image_base + pe + 24 + 70) & 0x80 != 0
}

fn register(callback: u64, extended: bool) -> Result<u32, KernelError> {
    passive()?;
    if !verified(callback, extended) {
        return Ok(0xC000_0022);
    }
    let pointer = kernel_pool::allocate(24, kernel_pool::AllocateOptions { tag: POOL_TAG, zero: true, ..Default::default() })?;
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    let mut state = STATE.lock();
    let Some(index) = state.slots.iter().position(Option::is_none) else {
        drop(state);
        kernel_pool::free(pointer, None)?;
        return Ok(0xC000_000D);
    };
    // A imagem de referência permite registros duplicados; cada um ocupa um
    // slot e é removido separadamente.
    guest::write64(pointer + 8, callback);
    guest::write64(pointer + 16, if extended { 2 } else { 0 });
    state.records.push(Registration { pointer, callback, extended, active: 0, removed: false, freed: false });
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

fn executing(thread: u64) -> bool {
    STATE.lock().executing.iter().any(|&(owner, depth)| owner == thread && depth > 0)
}

/// Remoção suspensível.
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

pub fn begin_remove(callback: u64, extended: bool) -> Result<RemoveRequest, KernelError> {
    passive()?;
    if executing(process::get_current_thread()) {
        return Err(KernelError::new("process notify removal inside a notification"));
    }
    let record = {
        let mut state = STATE.lock();
        let found = state.slots.iter().position(|slot| slot.is_some_and(|record| {
            let entry = &state.records[record];
            entry.callback == callback && entry.extended == extended
        }));
        let Some(index) = found else { return Ok(RemoveRequest { record: None }) };
        let record = state.slots[index].take().unwrap();
        state.records[record].removed = true;
        record
    };
    collect(record)?;
    Ok(RemoveRequest { record: Some(record) })
}

fn remove(callback: u64, extended: bool) -> Result<u32, KernelError> {
    let mut request = begin_remove(callback, extended)?;
    loop {
        if let Some(status) = request.poll()? {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

/// PsSetCreateProcessNotifyRoutine(Ex).
pub fn set(callback: u64, remove_flag: u8, extended: bool) -> Result<u32, KernelError> {
    if remove_flag != 0 { remove(callback, extended) } else { register(callback, extended) }
}

/// Dados do processo usados pela notificação.
pub struct NotifyRecord<'a> {
    pub parent_id: u64,
    pub image: Option<&'a ProcessImage>,
    pub command_line: Option<&'a str>,
}

fn enter_executing(thread: u64) {
    let mut state = STATE.lock();
    match state.executing.iter_mut().find(|(owner, _)| *owner == thread) {
        Some((_, depth)) => *depth += 1,
        None => state.executing.push((thread, 1)),
    }
}

fn leave_executing(thread: u64) {
    let mut state = STATE.lock();
    if let Some(index) = state.executing.iter().position(|&(owner, _)| owner == thread) {
        state.executing[index].1 -= 1;
        if state.executing[index].1 == 0 {
            state.executing.remove(index);
        }
    }
}

/// Monta PS_CREATE_NOTIFY_INFO (72 bytes) quando há imagem.
fn build_info(record: &NotifyRecord, command: &mut u64) -> Result<u64, KernelError> {
    let Some(image) = record.image else { return Ok(0) };
    let info = guest::alloc_bytes(72);
    if info == 0 {
        return Ok(0);
    }
    guest::write64(info, 72);
    guest::write32(info + 8, 1);
    guest::write64(info + 16, record.parent_id);
    guest::write64(info + 24, process::get_current_process_id());
    guest::write64(info + 32, process::get_current_thread_id());
    guest::write64(info + 40, image.file);
    guest::write64(info + 48, image.cache);
    guest::write64(info + 56, 0);
    if let Some(value) = record.command_line {
        let units: Vec<u16> = value.encode_utf16().collect();
        if units.len() > 32766 {
            guest::free_bytes(info);
            return Err(KernelError::new("process command line too long"));
        }
        let bytes = units.len() as u64 * 2;
        *command = guest::alloc_bytes(18 + bytes);
        if *command == 0 {
            guest::free_bytes(info);
            return Ok(u64::MAX);
        }
        guest::write16(*command, bytes as u16);
        guest::write16(*command + 2, bytes as u16 + 2);
        guest::write64(*command + 8, *command + 16);
        for (index, &unit) in units.iter().enumerate() {
            guest::write16(*command + 16 + index as u64 * 2, unit);
        }
        guest::write64(info + 56, *command);
    }
    guest::write32(info + 64, 0);
    Ok(info)
}

/// Notifica criação/saída; devolve CreationStatus (Ex) ou zero.
pub fn notify(pointer: u64, pid: u64, record: &NotifyRecord, created: bool) -> Result<u32, KernelError> {
    // Ex cobre processos executáveis; tarefas do kernel não têm imagem.
    let any = {
        let state = STATE.lock();
        state.slots.iter().flatten().any(|&index| !state.records[index].extended || record.image.is_some())
    };
    if !any {
        return Ok(0);
    }
    passive()?;
    let thread = process::get_current_thread();
    let mut command = 0;
    let info = if created { build_info(record, &mut command)? } else { 0 };
    if info == u64::MAX || (created && record.image.is_some() && info == 0) {
        return Ok(0xC000_009A);
    }
    let result = critical_region::with_critical(|| {
        enter_executing(thread);
        let mut failure = None;
        for index in 0..64 {
            let entry = {
                let mut state = STATE.lock();
                let Some(record_index) = state.slots[index] else { continue };
                let entry = &mut state.records[record_index];
                if entry.extended && record.image.is_none() {
                    continue;
                }
                entry.active += 1;
                (record_index, *entry)
            };
            let (record_index, registration) = entry;
            let arguments = if registration.extended { [pointer, pid, info] } else { [record.parent_id, pid, created as u64] };
            native_call::call(registration.callback, &arguments);
            STATE.lock().records[record_index].active -= 1;
            if let Err(error) = collect(record_index) {
                failure.get_or_insert(error);
            }
            // PspCallProcessNotifyRoutines para no primeiro CreationStatus negativo.
            if info != 0 && guest::read32(info + 64) & 0x8000_0000 != 0 {
                break;
            }
        }
        leave_executing(thread);
        match failure {
            Some(error) => Err(error),
            None => Ok(if info != 0 { guest::read32(info + 64) } else { 0 }),
        }
    });
    if command != 0 {
        guest::free_bytes(command);
    }
    if info != 0 {
        guest::free_bytes(info);
    }
    result
}
