//! APCs com KAPC x64 de 0x58 bytes — `system32/ntos/ke/apc.js`.
//!
//! As filas pertencem à thread de destino; anexações de processo conservam
//! ambientes separados. A entrega ocorre nos pontos de drenagem cooperativa,
//! respeitando modo, IRQL e contadores de desabilitação.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::{irql, thread_lock};
use crate::hal::amd64::native_call;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// Offsets da KAPC.
pub mod kapc {
    pub const TYPE: u64 = 0x00;
    pub const SIZE_FIELD: u64 = 0x02;
    pub const THREAD: u64 = 0x08;
    pub const LIST_ENTRY: u64 = 0x10;
    pub const KERNEL_ROUTINE: u64 = 0x20;
    pub const RUNDOWN_ROUTINE: u64 = 0x28;
    pub const NORMAL_ROUTINE: u64 = 0x30;
    pub const NORMAL_CONTEXT: u64 = 0x38;
    pub const SYSTEM_ARGUMENT_1: u64 = 0x40;
    pub const SYSTEM_ARGUMENT_2: u64 = 0x48;
    pub const APC_STATE_INDEX: u64 = 0x50;
    pub const APC_MODE: u64 = 0x51;
    pub const INSERTED: u64 = 0x52;
    pub const SIZE: u8 = 0x58;
    pub const TYPE_APC: u8 = 0x12;
}

/// O byte em ApcState +0x28 acompanha a execução de uma rotina normal.
const PROGRESS_OFFSET: u64 = kthread::APC_STATE + 0x28;

/// Ambiente salvo por uma anexação de processo.
pub struct SavedEnvironment {
    pub queue: Vec<u64>,
    pub state: u64,
    pub owns_state: bool,
    /// Liberação adicional (retenção do processo anexado): (rotina, argumento).
    pub release: Option<(fn(u64), u64)>,
}

struct ApcState {
    queue_by_thread: BTreeMap<u64, Vec<u64>>,
    attachments: BTreeMap<u64, Vec<SavedEnvironment>>,
    in_rundown: BTreeSet<u64>,
    disabled_provider: Option<fn(bool) -> bool>,
}

static STATE: SpinLock<ApcState> = SpinLock::new(ApcState {
    queue_by_thread: BTreeMap::new(),
    attachments: BTreeMap::new(),
    in_rundown: BTreeSet::new(),
    disabled_provider: None,
});

fn environment_address(thread: u64) -> u64 {
    thread + kthread::APC_STATE
}

/// Insere no fim da lista nativa do modo e publica a pendência de kernel.
fn link(state: u64, apc: u64) {
    let head = state + guest::read8(apc + kapc::APC_MODE) as u64 * 16;
    let entry = apc + kapc::LIST_ENTRY;
    let last = guest::read64(head + 8);
    guest::write64(entry, head);
    guest::write64(entry + 8, last);
    guest::write64(last, entry);
    guest::write64(head + 8, entry);
    if head == state {
        guest::write8(state + 0x29, 1);
    }
}

fn unlink(apc: u64) {
    let entry = apc + kapc::LIST_ENTRY;
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    guest::write64(entry, 0);
    guest::write64(entry + 8, 0);
}

/// KiMoveApcState: campos definidos e religação das listas no destino; o
/// padding em +0x2B fica intacto.
fn copy_environment_state(source: u64, destination: u64) {
    guest::write64(destination + 0x20, guest::read64(source + 0x20));
    for offset in [0x28, 0x29, 0x2A] {
        guest::write8(destination + offset, guest::read8(source + offset));
    }
    for offset in [0u64, 0x10] {
        let source_head = source + offset;
        let head = destination + offset;
        let first = guest::read64(source_head);
        let last = guest::read64(source_head + 8);
        if first == source_head {
            guest::write64(head, head);
            guest::write64(head + 8, head);
            guest::write8(destination + if offset == 0 { 0x29 } else { 0x2A }, 0);
        } else {
            guest::write64(head, first);
            guest::write64(head + 8, last);
            guest::write64(first + 8, head);
            guest::write64(last, head);
        }
    }
}

/// Consulta dos contadores de desabilitação (instalada pelas regiões críticas).
pub fn register_disabled_provider(provider: fn(bool) -> bool) {
    STATE.lock().disabled_provider = Some(provider);
}

/// KeInitializeApc. Sem rotina normal: modo kernel e contexto zero.
#[allow(clippy::too_many_arguments)]
pub fn initialize(apc: u64, thread: u64, environment: u8, kernel_routine: u64, rundown_routine: u64, normal_routine: u64, mode: u8, normal_context: u64) {
    guest::write8(apc + kapc::TYPE, kapc::TYPE_APC);
    guest::write8(apc + kapc::SIZE_FIELD, kapc::SIZE);
    guest::write64(apc + kapc::THREAD, thread);
    guest::write64(apc + kapc::LIST_ENTRY, 0);
    guest::write64(apc + kapc::LIST_ENTRY + 8, 0);
    guest::write64(apc + kapc::KERNEL_ROUTINE, kernel_routine);
    guest::write64(apc + kapc::RUNDOWN_ROUTINE, rundown_routine);
    guest::write64(apc + kapc::NORMAL_ROUTINE, normal_routine);
    guest::write64(apc + kapc::NORMAL_CONTEXT, if normal_routine != 0 { normal_context } else { 0 });
    guest::write64(apc + kapc::SYSTEM_ARGUMENT_1, 0);
    guest::write64(apc + kapc::SYSTEM_ARGUMENT_2, 0);
    // CurrentEnvironment é resolvido aqui; InsertEnvironment no enfileiramento.
    let resolved = if environment == 2 { STATE.lock().attachments.contains_key(&thread) as u8 } else { environment };
    guest::write8(apc + kapc::APC_STATE_INDEX, resolved);
    guest::write8(apc + kapc::APC_MODE, if normal_routine != 0 { mode } else { 0 });
    guest::write8(apc + kapc::INSERTED, 0);
}

/// KeInsertQueueApc sob KTHREAD.ThreadLock.
pub fn insert(apc: u64, first: u64, second: u64) -> bool {
    let thread = guest::read64(apc + kapc::THREAD);
    thread_lock::with_lock(thread, || {
        if guest::read8(apc + kapc::INSERTED) != 0 {
            return false;
        }
        let mut state = STATE.lock();
        if state.in_rundown.contains(&thread) || (guest::read8(thread) == 6 && guest::read32(thread + 4) != 0) {
            return false;
        }
        guest::write64(apc + kapc::SYSTEM_ARGUMENT_1, first);
        guest::write64(apc + kapc::SYSTEM_ARGUMENT_2, second);
        guest::write8(apc + kapc::INSERTED, 1);
        let attached = state.attachments.contains_key(&thread);
        let mut environment = guest::read8(apc + kapc::APC_STATE_INDEX);
        if environment == 3 {
            environment = attached as u8;
            guest::write8(apc + kapc::APC_STATE_INDEX, environment);
        }
        // Uma APC de OriginalEnvironment pertence ao primeiro ambiente salvo.
        if attached && environment == 0 {
            let saved = &mut state.attachments.get_mut(&thread).unwrap()[0];
            saved.queue.push(apc);
            let saved_state = saved.state;
            drop(state);
            link(saved_state, apc);
        } else {
            state.queue_by_thread.entry(thread).or_default().push(apc);
            drop(state);
            link(environment_address(thread), apc);
        }
        true
    })
}

/// KeRemoveQueueApc: procura a fila dona no ambiente atual ou num salvo.
pub fn remove(apc: u64) -> Result<bool, KernelError> {
    let thread = guest::read64(apc + 8);
    thread_lock::with_lock(thread, || {
        if guest::read8(apc + 0x52) == 0 {
            return Ok(false);
        }
        let mut state = STATE.lock();
        let mut owner_state = None;
        if let Some(queue) = state.queue_by_thread.get_mut(&thread) {
            if let Some(index) = queue.iter().position(|&queued| queued == apc) {
                queue.remove(index);
                owner_state = Some(environment_address(thread));
            }
        }
        if owner_state.is_none() {
            if let Some(saved) = state.attachments.get_mut(&thread) {
                for environment in saved.iter_mut() {
                    if let Some(index) = environment.queue.iter().position(|&queued| queued == apc) {
                        environment.queue.remove(index);
                        owner_state = Some(environment.state);
                        break;
                    }
                }
            }
        }
        drop(state);
        let Some(environment_state) = owner_state else {
            return Err(KernelError::new("inserted APC has no owning queue"));
        };
        let mode = guest::read8(apc + 0x51) as u64;
        let head = environment_state + mode * 16;
        unlink(apc);
        guest::write8(apc + 0x52, 0);
        if guest::read64(head) == head {
            guest::write8(environment_state + if mode != 0 { 0x2A } else { 0x29 }, 0);
        }
        Ok(true)
    })
}

/// Executa KernelRoutine em APC_LEVEL sobre cópias independentes dos quatro
/// argumentos e relê a rotina normal (a KAPC pode ser liberada antes).
fn deliver_one(apc: u64) -> Result<(), KernelError> {
    let kernel_routine = guest::read64(apc + kapc::KERNEL_ROUTINE);
    let block = guest::alloc_bytes(72);
    if block == 0 {
        return Err(KernelError::new("APC callback frame allocation failed"));
    }
    guest::write64(block, apc);
    let fields = [kapc::NORMAL_ROUTINE, kapc::NORMAL_CONTEXT, kapc::SYSTEM_ARGUMENT_1, kapc::SYSTEM_ARGUMENT_2];
    for (index, &field) in fields.iter().enumerate() {
        let copy = block + 40 + index as u64 * 8;
        guest::write64(copy, guest::read64(apc + field));
        guest::write64(block + 8 + index as u64 * 8, copy);
    }
    guest::write8(apc + kapc::INSERTED, 0);
    let previous = irql::raise_irql(irql::APC_LEVEL);
    let arguments: Vec<u64> = (0..5).map(|index| guest::read64(block + index * 8)).collect();
    native_call::call(kernel_routine, &arguments);
    irql::lower_irql(previous as u64);
    let normal_routine = guest::read64(block + 40);
    if normal_routine != 0 {
        let flags = process::get_current_thread() + PROGRESS_OFFSET;
        guest::write8(flags, guest::read8(flags) | 1);
        let arguments: Vec<u64> = (0..3).map(|index| guest::read64(block + 48 + index * 8)).collect();
        native_call::call(normal_routine, &arguments);
        guest::write8(flags, guest::read8(flags) & !1);
    }
    guest::free_bytes(block);
    Ok(())
}

/// Entrega só APCs de kernel da thread corrente em PASSIVE_LEVEL.
pub fn deliver_all_queued() -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Ok(());
    }
    let thread = process::get_current_thread();
    let mut index = 0;
    loop {
        let (apc, disabled_provider) = {
            let state = STATE.lock();
            let Some(queue) = state.queue_by_thread.get(&thread) else { return Ok(()) };
            let Some(&apc) = queue.get(index) else { break };
            (apc, state.disabled_provider)
        };
        // APCs de usuário voltam pelo dispatcher de usuário.
        if guest::read8(apc + kapc::APC_MODE) != 0 {
            index += 1;
            continue;
        }
        let special = guest::read64(apc + kapc::NORMAL_ROUTINE) == 0;
        let disabled = disabled_provider.is_some_and(|provider| provider(special));
        if disabled || (!special && guest::read8(thread + PROGRESS_OFFSET) & 1 != 0) {
            index += 1;
            continue;
        }
        thread_lock::with_lock(thread, || {
            if let Some(queue) = STATE.lock().queue_by_thread.get_mut(&thread) {
                if let Some(position) = queue.iter().position(|&queued| queued == apc) {
                    queue.remove(position);
                }
            }
            unlink(apc);
            let environment = environment_address(thread);
            if guest::read64(environment) == environment {
                guest::write8(environment + 0x29, 0);
            }
        });
        deliver_one(apc)?;
    }
    let mut state = STATE.lock();
    if state.queue_by_thread.get(&thread).is_some_and(|queue| queue.is_empty()) {
        state.queue_by_thread.remove(&thread);
    }
    Ok(())
}

pub fn has_pending(thread: u64) -> bool {
    STATE.lock().queue_by_thread.get(&thread).is_some_and(|queue| !queue.is_empty())
}

fn release_attachment(saved: SavedEnvironment) {
    if saved.owns_state {
        guest::free_bytes(saved.state);
    }
    if let Some((release, argument)) = saved.release {
        release(argument);
    }
}

/// Drena ambientes atual e salvos da thread em saída; conserva a primeira
/// falha mas continua liberando as demais pendências.
pub fn rundown(thread: u64) -> Result<(), KernelError> {
    let (queue, saved) = {
        let mut state = STATE.lock();
        let mut all: Vec<u64> = state.queue_by_thread.remove(&thread).unwrap_or_default();
        let saved = state.attachments.remove(&thread).unwrap_or_default();
        for environment in &saved {
            for &apc in &environment.queue {
                if !all.contains(&apc) {
                    all.push(apc);
                }
            }
        }
        if all.is_empty() && saved.is_empty() {
            return Ok(());
        }
        state.in_rundown.insert(thread);
        (all, saved)
    };
    let mut failure = None;
    for apc in queue {
        let rundown_routine = guest::read64(apc + kapc::RUNDOWN_ROUTINE);
        thread_lock::with_lock(thread, || unlink(apc));
        guest::write8(apc + kapc::INSERTED, 0);
        if rundown_routine != 0 {
            native_call::call(rundown_routine, &[apc]);
        }
    }
    STATE.lock().in_rundown.remove(&thread);
    guest::write8(environment_address(thread) + 0x29, 0);
    guest::write8(environment_address(thread) + 0x2A, 0);
    for environment in saved.into_iter().rev() {
        release_attachment(environment);
    }
    if let Some(error) = failure.take() {
        return Err(error);
    }
    Ok(())
}

/// Salva ambiente e fila antes de anexar a outro processo; as APCs do
/// ambiente original não executam no contexto anexado. Devolve o índice do
/// ambiente salvo na pilha da thread.
pub fn begin_attachment(thread: u64, supplied_state: Option<u64>, transition: Option<&mut dyn FnMut(u64)>) -> Result<usize, KernelError> {
    let state_pointer = match supplied_state {
        Some(state) => state,
        None => guest::alloc_bytes(0x30),
    };
    if state_pointer == 0 {
        return Err(KernelError::new("APC attachment state allocation failed"));
    }
    let mut transition = transition;
    let depth = thread_lock::with_lock(thread, || {
        copy_environment_state(environment_address(thread), state_pointer);
        let mut state = STATE.lock();
        let queue = state.queue_by_thread.remove(&thread).unwrap_or_default();
        let frames = state.attachments.entry(thread).or_default();
        frames.push(SavedEnvironment { queue, state: state_pointer, owns_state: supplied_state.is_none(), release: None });
        let depth = frames.len() - 1;
        state.queue_by_thread.insert(thread, Vec::new());
        drop(state);
        if let Some(transition) = transition.as_mut() {
            transition(state_pointer);
        }
        depth
    });
    Ok(depth)
}

/// Define a liberação adicional da anexação mais recente.
pub fn set_attachment_release(thread: u64, release: (fn(u64), u64)) {
    if let Some(saved) = STATE.lock().attachments.get_mut(&thread).and_then(|frames| frames.last_mut()) {
        saved.release = Some(release);
    }
}

/// Exige a última anexação e sua fila vazia; restaura o ambiente anterior.
pub fn end_attachment(thread: u64, depth: usize, transition: Option<&mut dyn FnMut()>) -> Result<(), KernelError> {
    {
        let state = STATE.lock();
        let frames = state.attachments.get(&thread);
        if frames.is_none_or(|frames| frames.len() != depth + 1) {
            return Err(KernelError::new("unbalanced APC attachment"));
        }
        if state.queue_by_thread.get(&thread).is_some_and(|queue| !queue.is_empty()) {
            return Err(KernelError::new("detaching process with pending attached APCs"));
        }
    }
    let mut transition = transition;
    let saved = thread_lock::with_lock(thread, || {
        let mut state = STATE.lock();
        let frames = state.attachments.get_mut(&thread).unwrap();
        let mut saved = frames.pop().unwrap();
        if frames.is_empty() {
            state.attachments.remove(&thread);
        }
        copy_environment_state(saved.state, environment_address(thread));
        let queue = core::mem::take(&mut saved.queue);
        if queue.is_empty() {
            state.queue_by_thread.remove(&thread);
        } else {
            state.queue_by_thread.insert(thread, queue);
        }
        drop(state);
        if let Some(transition) = transition.as_mut() {
            transition();
        }
        saved
    });
    release_attachment(saved);
    Ok(())
}

/// Profundidade da última anexação da thread (`None` sem anexação).
pub fn current_attachment(thread: u64) -> Option<usize> {
    STATE.lock().attachments.get(&thread).map(|frames| frames.len() - 1)
}

/// Estado nativo (KAPC_STATE salvo) da última anexação.
pub fn current_attachment_state(thread: u64) -> Option<u64> {
    STATE.lock().attachments.get(&thread).and_then(|frames| frames.last()).map(|saved| saved.state)
}
