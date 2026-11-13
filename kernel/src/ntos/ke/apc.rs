//! APCs com KAPC x64 de 0x58 bytes.
//!
//! As filas pertencem à thread de destino; anexações de processo conservam
//! ambientes separados. A entrega ocorre nos pontos de drenagem cooperativa,
//! respeitando modo, IRQL e contadores de desabilitação.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::{irql, thread_lock};
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, Kapc, KapcState, Kthread, ListEntry, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

/// Tamanho e tipo da KAPC (o resto do layout vem de `inc::types::Kapc`).
pub mod kapc {
    pub const SIZE: u8 = 0x58;
    pub const TYPE_APC: u8 = 0x12;
}

const _: () = assert!(kapc::SIZE as u64 == core::mem::size_of::<Kapc>() as u64);

/// KAPC.Reserved[3] dos símbolos públicos: KernelRoutine, RundownRoutine e
/// NormalRoutine.
const KERNEL_ROUTINE: usize = 0;
const RUNDOWN_ROUTINE: usize = 1;
const NORMAL_ROUTINE: usize = 2;

/// KAPC_STATE.InProgressFlags bit 0: KernelApcInProgress (rotina normal).
const KERNEL_APC_IN_PROGRESS: u8 = 1;

/// Frame de chamada da KernelRoutine (memória do OpenNT): a KAPC, os quatro
/// ponteiros PKNORMAL_ROUTINE*/PVOID* e as cópias que eles apontam.
#[repr(C)]
struct ApcCallFrame {
    apc: Field<u64>,
    pointers: [Field<u64>; 4],
    copies: [Field<u64>; 4],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ApcCallFrame {}

const _: () = assert!(core::mem::size_of::<ApcCallFrame>() == 72);

fn apc_at(apc: u64) -> &'static Kapc {
    // SAFETY: KAPC viva do chamador (inicializada por KeInitializeApc).
    unsafe { Kapc::at(apc) }
}

fn state_at(state: u64) -> &'static KapcState {
    // SAFETY: KTHREAD.ApcState/SavedApcState ou um KAPC_STATE salvo.
    unsafe { KapcState::at(state) }
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva dona das filas.
    unsafe { Kthread::at(thread) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: vínculo de uma lista de APCs viva.
    unsafe { ListEntry::at(address) }
}

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
    kthread(thread).apc_state.address()
}

/// KernelApcPending (modo kernel) ou UserApcPendingAll (modo usuário).
fn pending_flag(state: &KapcState, mode: usize) -> &Field<u8> {
    if mode == 0 { &state.kernel_apc_pending } else { &state.user_apc_pending_all }
}

/// Insere no fim da lista nativa do modo e publica a pendência de kernel.
fn link(state: &KapcState, apc: &Kapc) {
    let head = &state.apc_list_head[apc.apc_mode.get() as u8 as usize];
    let entry = &apc.apc_list_entry;
    let last = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(last);
    list_entry(last).flink.set(entry.address());
    head.blink.set(entry.address());
    if head.address() == state.address() {
        state.kernel_apc_pending.set(1);
    }
}

fn unlink(apc: &Kapc) {
    let entry = &apc.apc_list_entry;
    let next = entry.flink.get();
    let previous = entry.blink.get();
    list_entry(previous).flink.set(next);
    list_entry(next).blink.set(previous);
    entry.flink.set(0);
    entry.blink.set(0);
}

/// KiMoveApcState: campos definidos e religação das listas no destino; o
/// padding depois de UserApcPendingAll fica intacto.
fn copy_environment_state(source: &KapcState, destination: &KapcState) {
    destination.process.set(source.process.get());
    destination.in_progress_flags.set(source.in_progress_flags.get());
    destination.kernel_apc_pending.set(source.kernel_apc_pending.get());
    destination.user_apc_pending_all.set(source.user_apc_pending_all.get());
    for mode in 0..2 {
        let source_head = &source.apc_list_head[mode];
        let head = &destination.apc_list_head[mode];
        let first = source_head.flink.get();
        let last = source_head.blink.get();
        if first == source_head.address() {
            head.flink.set(head.address());
            head.blink.set(head.address());
            pending_flag(destination, mode).set(0);
        } else {
            head.flink.set(first);
            head.blink.set(last);
            list_entry(first).blink.set(head.address());
            list_entry(last).flink.set(head.address());
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
    let packet = apc_at(apc);
    packet.type_.set(kapc::TYPE_APC);
    packet.size.set(kapc::SIZE);
    packet.thread.set(thread);
    packet.apc_list_entry.flink.set(0);
    packet.apc_list_entry.blink.set(0);
    packet.reserved[KERNEL_ROUTINE].set(kernel_routine);
    packet.reserved[RUNDOWN_ROUTINE].set(rundown_routine);
    packet.reserved[NORMAL_ROUTINE].set(normal_routine);
    packet.normal_context.set(if normal_routine != 0 { normal_context } else { 0 });
    packet.system_argument1.set(0);
    packet.system_argument2.set(0);
    // CurrentEnvironment é resolvido aqui; InsertEnvironment no enfileiramento.
    let resolved = if environment == 2 { STATE.lock().attachments.contains_key(&thread) as u8 } else { environment };
    packet.apc_state_index.set(resolved as i8);
    packet.apc_mode.set(if normal_routine != 0 { mode as i8 } else { 0 });
    packet.inserted.set(0);
}

/// KeInsertQueueApc sob KTHREAD.ThreadLock.
pub fn insert(apc: u64, first: u64, second: u64) -> bool {
    let packet = apc_at(apc);
    let thread = packet.thread.get();
    thread_lock::with_lock(thread, || {
        if packet.inserted.get() != 0 {
            return false;
        }
        let mut state = STATE.lock();
        let target = kthread(thread);
        // Thread terminada (ThreadObject sinalizado) não recebe APCs.
        if state.in_rundown.contains(&thread) || (target.header.type_.get() == 6 && target.header.signal_state.get() != 0) {
            return false;
        }
        packet.system_argument1.set(first);
        packet.system_argument2.set(second);
        packet.inserted.set(1);
        let attached = state.attachments.contains_key(&thread);
        let mut environment = packet.apc_state_index.get() as u8;
        if environment == 3 {
            environment = attached as u8;
            packet.apc_state_index.set(environment as i8);
        }
        // Uma APC de OriginalEnvironment pertence ao primeiro ambiente salvo.
        if attached && environment == 0 {
            let saved = &mut state.attachments.get_mut(&thread).unwrap()[0];
            saved.queue.push(apc);
            let saved_state = saved.state;
            drop(state);
            link(state_at(saved_state), packet);
        } else {
            state.queue_by_thread.entry(thread).or_default().push(apc);
            drop(state);
            link(state_at(environment_address(thread)), packet);
        }
        true
    })
}

/// KeRemoveQueueApc: procura a fila dona no ambiente atual ou num salvo.
pub fn remove(apc: u64) -> Result<bool, KernelError> {
    let packet = apc_at(apc);
    let thread = packet.thread.get();
    thread_lock::with_lock(thread, || {
        if packet.inserted.get() == 0 {
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
        let mode = packet.apc_mode.get() as u8 as usize;
        let environment = state_at(environment_state);
        let head = &environment.apc_list_head[mode];
        unlink(packet);
        packet.inserted.set(0);
        if head.flink.get() == head.address() {
            pending_flag(environment, mode).set(0);
        }
        Ok(true)
    })
}

/// Executa KernelRoutine em APC_LEVEL sobre cópias independentes dos quatro
/// argumentos e relê a rotina normal (a KAPC pode ser liberada antes).
fn deliver_one(apc: u64) -> Result<(), KernelError> {
    let packet = apc_at(apc);
    let kernel_routine = packet.reserved[KERNEL_ROUTINE].get();
    let block = guest::alloc_bytes(core::mem::size_of::<ApcCallFrame>() as u64);
    if block == 0 {
        return Err(KernelError::new("APC callback frame allocation failed"));
    }
    // SAFETY: bloco recém-alocado do tamanho do frame.
    let frame = unsafe { ApcCallFrame::at(block) };
    frame.apc.set(apc);
    let fields = [&packet.reserved[NORMAL_ROUTINE], &packet.normal_context, &packet.system_argument1, &packet.system_argument2];
    for (index, field) in fields.iter().enumerate() {
        frame.copies[index].set(field.get());
        frame.pointers[index].set(frame.copies[index].address());
    }
    packet.inserted.set(0);
    let previous = irql::raise_irql(irql::APC_LEVEL);
    let arguments = [frame.apc.get(), frame.pointers[0].get(), frame.pointers[1].get(), frame.pointers[2].get(), frame.pointers[3].get()];
    native_call::call(kernel_routine, &arguments);
    irql::lower_irql(previous as u64);
    let normal_routine = frame.copies[0].get();
    if normal_routine != 0 {
        let flags = &kthread(process::get_current_thread()).apc_state.in_progress_flags;
        flags.set(flags.get() | KERNEL_APC_IN_PROGRESS);
        let arguments = [frame.copies[1].get(), frame.copies[2].get(), frame.copies[3].get()];
        native_call::call(normal_routine, &arguments);
        flags.set(flags.get() & !KERNEL_APC_IN_PROGRESS);
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
        let packet = apc_at(apc);
        // APCs de usuário voltam pelo dispatcher de usuário.
        if packet.apc_mode.get() != 0 {
            index += 1;
            continue;
        }
        let special = packet.reserved[NORMAL_ROUTINE].get() == 0;
        let disabled = disabled_provider.is_some_and(|provider| provider(special));
        if disabled || (!special && kthread(thread).apc_state.in_progress_flags.get() & KERNEL_APC_IN_PROGRESS != 0) {
            index += 1;
            continue;
        }
        thread_lock::with_lock(thread, || {
            if let Some(queue) = STATE.lock().queue_by_thread.get_mut(&thread) {
                if let Some(position) = queue.iter().position(|&queued| queued == apc) {
                    queue.remove(position);
                }
            }
            unlink(packet);
            let environment = &kthread(thread).apc_state;
            let kernel_head = &environment.apc_list_head[0];
            if kernel_head.flink.get() == kernel_head.address() {
                environment.kernel_apc_pending.set(0);
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
        let packet = apc_at(apc);
        let rundown_routine = packet.reserved[RUNDOWN_ROUTINE].get();
        thread_lock::with_lock(thread, || unlink(packet));
        packet.inserted.set(0);
        if rundown_routine != 0 {
            native_call::call(rundown_routine, &[apc]);
        }
    }
    STATE.lock().in_rundown.remove(&thread);
    let environment = &kthread(thread).apc_state;
    environment.kernel_apc_pending.set(0);
    environment.user_apc_pending_all.set(0);
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
        None => guest::alloc_bytes(KapcState::SIZE),
    };
    if state_pointer == 0 {
        return Err(KernelError::new("APC attachment state allocation failed"));
    }
    let mut transition = transition;
    let depth = thread_lock::with_lock(thread, || {
        copy_environment_state(state_at(environment_address(thread)), state_at(state_pointer));
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
        copy_environment_state(state_at(saved.state), state_at(environment_address(thread)));
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
