//! PsSetCreateThreadNotifyRoutine e PsSetCreateThreadNotifyRoutineEx.
//!
//! A rotina simples não verifica imagem nem rejeita ponteiro repetido; o
//! chamador responde por fornecer código válido. Como no
//! PspSetCreateThreadNotifyRoutine do NT, cada registro guarda as flags (o
//! contexto do bloco): 0 para a rotina simples, 1 para a de código não de
//! sistema (PsCreateThreadNotifyNonSystem) e 2 para a de subsistemas
//! (PsCreateThreadNotifySubsystems). A Ex exige que a rotina more numa
//! imagem carregada com LDRP_IMAGE_INTEGRITY_FORCED (o
//! MmVerifyCallbackFunctionCheckFlags(rotina, 0x20)).
//!
//! Os pontos de chamada são os do PspCallThreadNotifyRoutines: na criação,
//! no contexto de quem cria (o PspInsertThread), só as rotinas sem a flag 1;
//! as rotinas de código não de sistema são chamadas na criação de uma thread
//! de usuário no contexto da thread nova (o PspInitializeThunkContext do
//! NT, antes de ela chegar ao modo usuário); na saída todas são chamadas. O
//! OpenNT não cria threads de outros subsistemas (pico), então a flag 2 não
//! filtra nada.

use alloc::vec::Vec;

use crate::ntos::ps::process;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::{kernel_pool, loaded_images};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::NtStruct;
use super::CallbackBlock;

const POOL_TAG: u32 = 0x6272_6243;

/// Flags do registro: rotina de código não de sistema e de subsistemas.
pub const NOTIFY_NON_SYSTEM: u32 = 1;
pub const NOTIFY_SUBSYSTEMS: u32 = 2;
/// PSCREATETHREADNOTIFYTYPE.
const NOTIFY_TYPE_NON_SYSTEM: u32 = 0;
const NOTIFY_TYPE_SUBSYSTEMS: u32 = 1;
/// KLDR_DATA_TABLE_ENTRY.Flags: LDRP_IMAGE_INTEGRITY_FORCED.
const IMAGE_INTEGRITY_FORCED: u32 = 0x20;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Onde o PspCallThreadNotifyRoutines é chamado.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum NotifyPoint {
    /// Criação, no contexto de quem cria: as rotinas sem a flag 1.
    Create,
    /// Criação de thread de usuário, no contexto da thread nova: só as
    /// rotinas com a flag 1.
    CreateNonSystem,
    /// Saída: todas.
    Exit,
}

impl NotifyPoint {
    fn selects(self, flags: u32) -> bool {
        match self {
            NotifyPoint::Create => flags & NOTIFY_NON_SYSTEM == 0,
            NotifyPoint::CreateNonSystem => flags & NOTIFY_NON_SYSTEM != 0,
            NotifyPoint::Exit => true,
        }
    }
}

#[derive(Clone, Copy)]
struct Registration {
    pointer: u64,
    callback: u64,
    flags: u32,
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

/// PsSetCreateThreadNotifyRoutine: registro com flags 0.
pub fn register(callback: u64) -> Result<u32, KernelError> {
    register_with_flags(callback, 0)
}

/// PspSetCreateThreadNotifyRoutine: o bloco ('Cbrb', rotina e flags no
/// contexto) num slot livre; sem pool ou sem slot é
/// STATUS_INSUFFICIENT_RESOURCES.
fn register_with_flags(callback: u64, flags: u32) -> Result<u32, KernelError> {
    level(0)?;
    let pointer = kernel_pool::allocate(CallbackBlock::SIZE, kernel_pool::AllocateOptions { tag: POOL_TAG, zero: true, ..Default::default() })?;
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    let mut state = STATE.lock();
    let Some(index) = state.slots.iter().position(Option::is_none) else {
        drop(state);
        kernel_pool::free(pointer, None)?;
        return Ok(0xC000_009A);
    };
    let block = CallbackBlock::of(pointer);
    block.function.set(callback);
    block.context.set(flags as u64);
    state.records.push(Registration { pointer, callback, flags, active: 0, removed: false, freed: false });
    let record = state.records.len() - 1;
    state.slots[index] = Some(record);
    Ok(0)
}

/// MmVerifyCallbackFunctionCheckFlags(rotina, Flags): uma VA do espaço de
/// sessão (região MiVaSessionSpace) nunca serve; a rotina tem de morar numa
/// imagem da lista de módulos carregados cujas Flags da entrada tenham algum
/// bit de `flags` (0 aceita qualquer imagem).
fn verify_callback(callback: u64, flags: u32) -> bool {
    if crate::ntos::mm::memory_map::is_session_address(callback) {
        return false;
    }
    loaded_images::find(callback).is_some_and(|image| flags == 0 || image.loader_flags & flags != 0)
}

/// PsSetCreateThreadNotifyRoutineEx(NotifyType, NotifyInformation): tipo 0
/// (código não de sistema) registra com a flag 1, tipo 1 (subsistemas) com
/// a 2, outro tipo é STATUS_INVALID_PARAMETER; a rotina fora de imagem com
/// integridade forçada é STATUS_ACCESS_DENIED.
pub fn register_ex(notify_type: u32, callback: u64) -> Result<u32, KernelError> {
    let flags = match notify_type {
        NOTIFY_TYPE_NON_SYSTEM => NOTIFY_NON_SYSTEM,
        NOTIFY_TYPE_SUBSYSTEMS => NOTIFY_SUBSYSTEMS,
        _ => return Ok(STATUS_INVALID_PARAMETER),
    };
    if !verify_callback(callback, IMAGE_INTEGRITY_FORCED) {
        return Ok(STATUS_ACCESS_DENIED);
    }
    register_with_flags(callback, flags)
}

/// Flags do registro vivo da rotina (o primeiro slot que a tem).
pub fn registered_flags(callback: u64) -> Option<u32> {
    let state = STATE.lock();
    state.slots.iter().flatten().map(|&record| state.records[record]).find(|entry| entry.callback == callback).map(|entry| entry.flags)
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

/// Há registro vivo que o ponto `point` chamaria (o PspNotifyEnableMask).
pub fn wants(point: NotifyPoint) -> bool {
    let state = STATE.lock();
    state.slots.iter().flatten().any(|&record| point.selects(state.records[record].flags))
}

/// Chama as rotinas que o ponto `point` seleciona (ProcessId, ThreadId,
/// Create).
pub fn notify(owner_id: u64, thread_id: u64, point: NotifyPoint) -> Result<(), KernelError> {
    if !wants(point) {
        return Ok(());
    }
    let created = point != NotifyPoint::Exit;
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
                if !point.selects(state.records[record].flags) {
                    continue;
                }
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
