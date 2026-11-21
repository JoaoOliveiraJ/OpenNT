//! Esperas que bloqueiam: os blocos de espera do despachante.
//!
//! Uma thread de kernel que espera (KeWaitForSingleObject/Multiple,
//! KeDelayExecutionThread, KeRemoveQueue(Ex), as esperas dos locks do Ex e as
//! esperas explícitas dos serviços, como a retirada de uma porta de conclusão
//! e as esperas do ALPC) sai do conjunto de prontas e troca de contexto
//! (`context_switch::switch_out`), como no KiCommitThreadWait do 19041. Cada
//! objeto esperado recebe um KWAIT_BLOCK da KTHREAD (WaitBlock[0..3); acima de
//! três, um vetor do pool) ligado à DISPATCHER_HEADER.WaitListHead dele, com
//! WaitType (WaitAll 0, WaitAny 1, WaitNotification 2, WaitDequeue 3),
//! BlockState (WaitBlockActive 4, WaitBlockInactive 5) e WaitKey (o índice do
//! objeto); o prazo arma o KTIMER da própria thread (KTHREAD.Timer), com o
//! bloco WaitBlock[3] (o TIMER_WAIT_BLOCK) e a chave STATUS_TIMEOUT (zero
//! num KeDelayExecutionThread). A thread publica KTHREAD.State = Waiting,
//! WaitReason, WaitMode, Alertable, WaitTime, WaitBlockList, WaitBlockCount
//! e o estado da espera no KWAIT_STATUS_REGISTER: WaitInProgress até o
//! despachante confirmar que ela deixou a CPU ([`commit`], WaitCommitted);
//! uma saída da espera antes da confirmação a marca WaitAborted, e a thread
//! volta direto à fila.
//!
//! Quem apronta a thread é o sinal (o KiWaitTest, [`signal`]): KeSetEvent,
//! KePulseEvent, KeReleaseSemaphore, KeReleaseMutex, o vencimento de um
//! timer e o fim de uma thread ou de um processo percorrem a WaitListHead do
//! objeto e satisfazem os blocos, consumindo pela thread que espera (o evento
//! de sincronização, a permissão do semáforo, a posse do mutant) e, num
//! WaitAll, só quando todos os objetos da thread estão disponíveis; um bloco
//! de notificação (as esperas dos locks do Ex, que conferem a própria palavra
//! ao voltar) só acorda. Depois das threads, já fora do lock, o sinal passa
//! pelo observador instalado ([`set_signal_observer`]): os pacotes de espera
//! associados ao objeto, os blocos de notificação com fila do
//! KeRegisterObjectNotification, vão para a porta deles (`ps/user/wait_packets`).
//! O KeInsertQueue entrega a entrada direto à thread
//! parada na fila (`ke::queue`, o KiInsertQueue). A saída da espera (o
//! KiUnwaitThread, [`DispatcherLock::unwait`]) desliga todos os blocos da
//! thread, cancela o timer, grava KTHREAD.WaitStatus e põe a thread na fila
//! pronta. Um alerta numa espera alertável sai com STATUS_ALERTED
//! ([`alert`]); uma APC de usuário numa espera alertável de UserMode, com
//! STATUS_USER_APC, e uma APC de kernel numa espera em PASSIVE_LEVEL, com
//! STATUS_KERNEL_APC ([`apc_queued`]): a thread entrega as APCs de kernel ao
//! voltar e espera de novo pelo prazo restante, como o NT.
//!
//! As listas de espera e os registros ficam sob um lock só, o do despachante
//! ([`lock`]). Os sinalizadores mudam o estado do objeto (atomicamente) e
//! então testam as esperas sob o lock; quem espera tenta o objeto e liga os
//! blocos sob o mesmo lock, então nenhum sinal se perde entre a tentativa e
//! o bloqueio. As threads de usuário registram blocos do mesmo jeito: a
//! espera de um serviço bloqueado no kernel (o KeWaitFor*, o
//! KeDelayExecutionThread, a aquisição de um lock do Ex) passa pelo mesmo
//! laço e deixa a CPU com o serviço suspenso
//! (`context_switch::block_registered`); a espera adiada de um serviço de
//! UserMode (o NtWaitFor*, o NtDelayExecution, as esperas acordadas do
//! alerta por id, da porta de conclusão e do ALPC) liga os blocos dentro do
//! serviço ([`begin_user_wait`]) e volta STATUS_PENDING. O despacho de
//! usuário confirma a espera quando a thread deixa a CPU
//! ([`commit_user_wait`]) e grava o KTHREAD.State; o sinal a apronta. Só o
//! contexto de boot (o próprio despachante) consulta o objeto entre voltas
//! do pump.

use alloc::vec::Vec;

use super::{bugcheck, clock, context_switch, dispatcher, thread_alert, thread_dispatch, timer};
use super::context_switch::SwitchReason;
use crate::ntos::inc::types::{DispatcherHeader, Kthread, KwaitBlock, ListEntry, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::scheduler;
use crate::rtl::sync::SpinLockGuard;
use crate::rtl::{PtrMap, SpinLock};

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_ABANDONED: u32 = 0x80;
pub const STATUS_USER_APC: u32 = 0xC0;
pub const STATUS_KERNEL_APC: u32 = 0x100;
pub const STATUS_ALERTED: u32 = 0x101;
pub const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// WAIT_TYPE do 19041.
pub mod wait_type {
    pub const ALL: u8 = 0;
    pub const ANY: u8 = 1;
    pub const NOTIFICATION: u8 = 2;
    pub const DEQUEUE: u8 = 3;
}

/// KWAIT_REASON do 19041 (as que o kernel usa).
pub mod reason {
    pub const EXECUTIVE: u8 = 0;
    pub const DELAY_EXECUTION: u8 = 4;
    pub const USER_REQUEST: u8 = 6;
    pub const WR_EXECUTIVE: u8 = 7;
    pub const WR_QUEUE: u8 = 15;
    pub const WR_LPC_RECEIVE: u8 = 16;
    pub const WR_LPC_REPLY: u8 = 17;
    pub const WR_RESOURCE: u8 = 27;
    pub const WR_PUSH_LOCK: u8 = 28;
    pub const WR_FAST_MUTEX: u8 = 34;
    pub const WR_GUARDED_MUTEX: u8 = 35;
    pub const WR_RUNDOWN: u8 = 36;
    pub const WR_ALERT_BY_THREAD_ID: u8 = 37;
}

/// KWAIT_BLOCK_STATE.
const BLOCK_ACTIVE: u8 = 4;
const BLOCK_INACTIVE: u8 = 5;
/// THREAD_WAIT_OBJECTS: blocos embutidos para objetos; o quarto é o do timer.
const THREAD_WAIT_OBJECTS: usize = 3;
const TIMER_WAIT_BLOCK: usize = 3;
/// KWAIT_STATE no KWAIT_STATUS_REGISTER (bits 0-2).
const WAIT_STATE_MASK: u8 = 7;
const WAIT_IN_PROGRESS: u8 = 1;
const WAIT_COMMITTED: u8 = 2;
const WAIT_ABORTED: u8 = 3;
/// KTHREAD.State Waiting.
const STATE_WAITING: u8 = 5;
/// TimerNotificationObject: o KTHREAD.Timer do prazo.
const TIMER_NOTIFICATION: u32 = 8;
/// KERNEL_SECURITY_CHECK_FAILURE / FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// A espera registrada de uma thread.
struct ActiveWait {
    /// O primeiro bloco dos objetos (KTHREAD.WaitBlock ou o vetor do pool).
    blocks: u64,
    count: usize,
    allocated: bool,
    timer: bool,
    alertable: bool,
    mode: u8,
    /// Uma APC de kernel interrompe a espera (WaitIrql em PASSIVE_LEVEL).
    kernel_apcs: bool,
    /// Espera explícita: um `wake` a conclui.
    explicit: bool,
    /// O número da espera (cada registro tem o seu): quem guarda uma espera
    /// de usuário só desfaz a dele, nunca uma registrada depois.
    serial: u64,
}

/// O número da próxima espera registrada.
static NEXT_SERIAL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

struct WaitTable {
    /// As esperas ligadas, pela KTHREAD (consultado a cada sinal, alerta,
    /// APC e despertar: um `PtrMap`).
    waits: PtrMap<ActiveWait>,
}

static DISPATCHER: SpinLock<WaitTable> = SpinLock::new(WaitTable { waits: PtrMap::new() });

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: as esperas só registram KTHREADs vivas (a thread não termina
    // parada numa espera).
    unsafe { Kthread::at(thread) }
}

fn header(object: u64) -> &'static DispatcherHeader {
    // SAFETY: os objetos esperados começam no DISPATCHER_HEADER e ficam vivos
    // enquanto há quem espere neles.
    unsafe { DispatcherHeader::at(object) }
}

fn block_at(address: u64) -> &'static KwaitBlock {
    // SAFETY: blocos de espera de uma KTHREAD viva (ou do vetor dela).
    unsafe { KwaitBlock::at(address) }
}

fn link(address: u64) -> &'static ListEntry {
    // SAFETY: vínculos de uma lista de espera conferida.
    unsafe { ListEntry::at(address) }
}

fn corrupt_list() -> ! {
    bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, 0, 0, 0)
}

/// A WaitListHead é uma lista válida (vazia, ou com os vizinhos da cabeça
/// apontando de volta para ela).
fn valid_list(head: &ListEntry) -> bool {
    let (first, last) = (head.flink.get(), head.blink.get());
    if first == 0 || last == 0 {
        return false;
    }
    if first == head.address() && last == head.address() {
        return true;
    }
    guest::try_read64(first + 8).is_ok_and(|back| back == head.address()) && guest::try_read64(last).is_ok_and(|forward| forward == head.address())
}

/// Um objeto cujo cabeçalho nunca teve a lista iniciada (memória zerada que
/// recebeu só o estado) ganha a lista vazia antes do primeiro bloco.
fn ensure_list(head: &ListEntry) {
    if valid_list(head) {
        return;
    }
    if head.flink.get() != 0 {
        debug_print!("[wait] WaitListHead {:#x} sem lista valida; iniciada vazia", head.address());
    }
    head.flink.set(head.address());
    head.blink.set(head.address());
}

fn insert(head: &ListEntry, entry: &ListEntry, at_head: bool) {
    let (previous, next) = if at_head { (head.address(), head.flink.get()) } else { (head.blink.get(), head.address()) };
    if link(previous).flink.get() != next || link(next).blink.get() != previous {
        corrupt_list();
    }
    entry.flink.set(next);
    entry.blink.set(previous);
    link(previous).flink.set(entry.address());
    link(next).blink.set(entry.address());
}

fn remove_entry(entry: &ListEntry) {
    let (next, previous) = (entry.flink.get(), entry.blink.get());
    if link(next).blink.get() != entry.address() || link(previous).flink.get() != entry.address() {
        corrupt_list();
    }
    link(previous).flink.set(next);
    link(next).blink.set(previous);
    entry.flink.set(entry.address());
    entry.blink.set(entry.address());
}

/// O lock do despachante. As threads que uma saída de espera apronta entram
/// na fila depois de o lock ser solto, com o ajuste de prioridade de quem
/// sai de uma espera e o incremento do sinal (o KiExitDispatcher que drena a
/// DeferredReadyListHead, `thread_dispatch::ready_after_wait`).
pub struct DispatcherLock {
    guard: Option<SpinLockGuard<'static, WaitTable>>,
    ready: Vec<u64>,
    /// O Increment do KeSetEvent, KeReleaseSemaphore, KeReleaseMutant,
    /// KePulseEvent, KeInsertQueueApc ou KeAlertThread que tirou as threads
    /// da espera (zero no vencimento de um timer, como o KiTimerWaitTest,
    /// 0x24767b, e nos sinais internos).
    increment: i8,
}

/// Toma o lock do despachante.
pub fn lock() -> DispatcherLock {
    lock_with_increment(0)
}

/// Toma o lock do despachante para um sinal com o incremento `increment`.
pub fn lock_with_increment(increment: i8) -> DispatcherLock {
    DispatcherLock { guard: Some(DISPATCHER.lock()), ready: Vec::new(), increment }
}

impl Drop for DispatcherLock {
    fn drop(&mut self) {
        self.guard.take();
        for thread in core::mem::take(&mut self.ready) {
            if let Err(error) = thread_dispatch::ready_after_wait(thread, self.increment) {
                debug_print!("[wait] thread {:#x} nao entrou na fila pronta: {}", thread, error);
            }
            scheduler::thread_readied(thread);
        }
    }
}

/// Os parâmetros de uma espera registrada.
#[derive(Clone, Copy)]
pub struct WaitSpec {
    /// O WAIT_TYPE dos blocos dos objetos.
    pub kind: u8,
    /// O prazo relativo, em 100 ns (nenhum = infinito).
    pub timeout: Option<u64>,
    /// A chave do bloco do timer (o status quando o prazo vence).
    pub timeout_key: u32,
    pub alertable: bool,
    pub mode: u8,
    pub reason: u8,
    /// Os blocos entram na cabeça das listas (a espera de uma fila).
    pub at_head: bool,
    /// Um `wake` conclui a espera.
    pub explicit: bool,
    /// A espera é de uma thread de usuário (`ps/user/threads`): ela ainda
    /// roda o serviço quando os blocos são ligados, e o despacho de usuário
    /// grava o KTHREAD.State e confirma a espera quando ela deixa a CPU
    /// ([`commit_user_wait`]).
    pub user: bool,
    /// Uma espera adiada de UserMode (o serviço devolve STATUS_PENDING com a
    /// espera instalada): uma APC de kernel não a interrompe, porque o
    /// despachante entrega as APCs de kernel no contexto da thread sem
    /// desfazer a espera (o serviço já voltou).
    pub deferred: bool,
}

impl WaitSpec {
    pub fn new(kind: u8, timeout: Option<u64>, mode: u8, alertable: bool, reason: u8) -> Self {
        WaitSpec { kind, timeout, timeout_key: STATUS_TIMEOUT, alertable, mode, reason, at_head: false, explicit: false, user: false, deferred: false }
    }
}

impl DispatcherLock {
    fn table(&mut self) -> &mut WaitTable {
        self.guard.as_mut().expect("lock do despachante solto")
    }

    /// A thread tem uma espera registrada.
    pub fn waiting(&mut self, thread: u64) -> bool {
        self.table().waits.contains_key(&thread)
    }

    /// Liga os blocos de `objects` e o do timer e publica a espera de
    /// `thread` (KTHREAD.State Waiting, WaitInProgress). Falha só sem pool
    /// para o vetor de blocos.
    pub fn link_wait(&mut self, thread: u64, objects: &[u64], spec: WaitSpec) -> Result<(), u32> {
        // Uma thread espera numa coisa só: os blocos embutidos ainda ligados
        // de outra espera dela seriam religados por cima, e a lista do objeto
        // antigo ficaria corrompida.
        assert!(!self.waiting(thread), "espera registrada da thread {:#x} sobre outra ainda ligada", thread);
        let target = kthread(thread);
        let (blocks, allocated) = if objects.len() <= THREAD_WAIT_OBJECTS {
            (target.wait_block[0].address(), false)
        } else {
            let vector = guest::alloc_bytes((objects.len() * KwaitBlock::SIZE as usize) as u64);
            if vector == 0 {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            (vector, true)
        };
        // Só os campos do bloco que o KiWaitMultiple do 19041 grava: o
        // SpareLong e o SparePtr dos blocos embutidos são outros campos da
        // KTHREAD na mesma memória (WaitBlockFill4..11: ContextSwitches,
        // State/WaitIrql/WaitMode, WaitTime, ThreadCounters, XStateSave,
        // Win32Thread no SparePtr do WaitBlock[2], Ucb/Uch), e zerá-los apagaria
        // a W32THREAD de uma thread de usuário que espera em três objetos.
        for (index, &object) in objects.iter().enumerate() {
            let block = block_at(blocks + (index as u64) * KwaitBlock::SIZE);
            block.wait_type.set(spec.kind);
            block.block_state.set(BLOCK_ACTIVE);
            block.wait_key.set(index as u16);
            block.thread.set(thread);
            block.object.set(object);
            let head = &header(object).wait_list_head;
            ensure_list(head);
            insert(head, &block.wait_list_entry, spec.at_head);
        }
        let timed = match spec.timeout {
            Some(timeout) => {
                let timer_address = target.timer.address();
                timer::initialize_timer(timer_address, TIMER_NOTIFICATION);
                let block = &target.wait_block[TIMER_WAIT_BLOCK];
                block.wait_type.set(wait_type::ANY);
                block.block_state.set(BLOCK_ACTIVE);
                block.wait_key.set(spec.timeout_key as u16);
                block.thread.set(thread);
                block.object.set(timer_address);
                insert(&target.timer.header.wait_list_head, &block.wait_list_entry, false);
                timer::set_timer(timer_address, -(timeout.max(1) as i64), 0, 0);
                true
            }
            None => false,
        };
        target.wait_block_list.set(if objects.is_empty() { target.wait_block[TIMER_WAIT_BLOCK].address() } else { blocks });
        target.wait_block_count.set(objects.len() as u8);
        target.wait_status.set(0);
        target.wait_mode.set(spec.mode as i8);
        target.set_alertable(spec.alertable as u32);
        target.wait_reason.set(spec.reason);
        target.wait_time.set(thread_dispatch::tick_count());
        // Uma espera nova começa sem o Alert de uma anterior (bit 7).
        let register = target.wait_register.flags.get();
        target.wait_register.flags.set((register & 0x78) | WAIT_IN_PROGRESS);
        if !spec.user {
            target.state.set(STATE_WAITING);
        }
        let kernel_apcs = !spec.deferred && super::irql::get_irql() == super::irql::PASSIVE_LEVEL;
        let serial = NEXT_SERIAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        self.table().waits.insert(thread, ActiveWait { blocks, count: objects.len(), allocated, timer: timed, alertable: spec.alertable, mode: spec.mode, kernel_apcs, explicit: spec.explicit, serial });
        Ok(())
    }

    /// O KiUnwaitThread: desliga os blocos e o timer da espera de `thread`,
    /// grava KTHREAD.WaitStatus e a apronta (ou, antes da confirmação da
    /// saída da CPU, marca a espera abortada). `false` sem espera registrada.
    pub fn unwait(&mut self, thread: u64, status: u64) -> bool {
        let Some(wait) = self.table().waits.remove(&thread) else { return false };
        let target = kthread(thread);
        for index in 0..wait.count {
            let block = block_at(wait.blocks + (index as u64) * KwaitBlock::SIZE);
            remove_entry(&block.wait_list_entry);
            block.block_state.set(BLOCK_INACTIVE);
        }
        if wait.timer {
            let block = &target.wait_block[TIMER_WAIT_BLOCK];
            remove_entry(&block.wait_list_entry);
            block.block_state.set(BLOCK_INACTIVE);
            timer::cancel_timer(target.timer.address());
        }
        if wait.allocated {
            guest::free_bytes(wait.blocks);
        }
        target.wait_status.set(status as i64);
        let register = target.wait_register.flags.get();
        if register & WAIT_STATE_MASK == WAIT_IN_PROGRESS {
            target.wait_register.flags.set((register & !WAIT_STATE_MASK) | WAIT_ABORTED);
        } else {
            target.wait_register.flags.set(register & !WAIT_STATE_MASK);
            self.ready.push(thread);
        }
        true
    }

    /// O KiWaitTest: depois de uma mudança de estado de `object`, satisfaz
    /// os blocos da lista dele na ordem, consumindo pela thread que espera.
    pub fn wait_test(&mut self, object: u64) {
        let head = &header(object).wait_list_head;
        if !valid_list(head) {
            ensure_list(head);
            return;
        }
        let mut entry = head.flink.get();
        while entry != head.address() {
            let block = block_at(entry);
            let thread = block.thread.get();
            // O próximo bloco de outra thread: os seguintes da mesma thread na
            // mesma lista (um WaitAny no mesmo objeto duas vezes, que o 19041
            // aceita) saem todos com ela no `unwait`, e o vínculo de um bloco
            // desligado aponta para ele mesmo; testá-los de novo também não
            // muda nada (o mesmo objeto, a mesma thread).
            let mut next = block.wait_list_entry.flink.get();
            while next != head.address() && block_at(next).thread.get() == thread {
                next = block_at(next).wait_list_entry.flink.get();
            }
            let key = block.wait_key.get() as u32;
            match block.wait_type.get() {
                wait_type::ANY => {
                    if let Some(status) = dispatcher::acquire_status_for(object, true, thread) {
                        let status = if status & 0x8000_0000 != 0 { status } else { status + key };
                        self.unwait(thread, status as u64);
                    }
                }
                wait_type::ALL => self.try_wait_all(thread),
                wait_type::NOTIFICATION => {
                    self.unwait(thread, key as u64);
                }
                _ => {}
            }
            entry = next;
        }
    }

    /// Um WaitAll satisfeito só quando todos os objetos da thread estão
    /// disponíveis para ela; então consome todos.
    fn try_wait_all(&mut self, thread: u64) {
        let Some(wait) = self.table().waits.get(&thread) else { return };
        let objects: Vec<u64> = (0..wait.count).map(|index| block_at(wait.blocks + (index as u64) * KwaitBlock::SIZE).object.get()).collect();
        if let Some(status) = dispatcher::try_wait_objects_for(&objects, wait_type::ALL as u32, thread) {
            self.unwait(thread, status as u64);
        }
    }

    /// A thread mais recente parada na fila `queue` (o primeiro bloco
    /// WaitDequeue da WaitListHead, inserida na cabeça), para o KiInsertQueue.
    pub fn first_dequeue_waiter(&mut self, queue: u64) -> Option<u64> {
        let head = &header(queue).wait_list_head;
        if !valid_list(head) || head.flink.get() == head.address() {
            return None;
        }
        let block = block_at(head.flink.get());
        (block.wait_type.get() == wait_type::DEQUEUE).then(|| block.thread.get())
    }
}

/// O observador do sinal: os blocos de notificação com fila do
/// KeRegisterObjectNotification (os pacotes de espera,
/// `ps/user/wait_packets`), que o KiWaitTest do 19041 satisfaz dentro do
/// próprio sinal, pondo o pacote na fila da porta.
static SIGNAL_OBSERVER: SpinLock<Option<fn(u64)>> = SpinLock::new(None);

/// Instala o observador do sinal ([`signal`]).
pub fn set_signal_observer(observer: fn(u64)) {
    *SIGNAL_OBSERVER.lock() = Some(observer);
}

/// O KiWaitTest de fora: depois de mudar o estado de `object`, satisfaz quem
/// espera nele: as threads de kernel registradas e, já fora do lock do
/// despachante, os pacotes de espera associados ao objeto.
pub fn signal(object: u64) {
    signal_with_increment(object, 0);
}

/// [`signal`] com o Increment do sinal (o KeSetEvent, o KeReleaseSemaphore,
/// o KeReleaseMutant, o KePulseEvent): as threads que ele tira da espera
/// ganham o impulso (`thread_dispatch::ready_after_wait`).
pub fn signal_with_increment(object: u64, increment: i8) {
    dispatcher::note_wake();
    lock_with_increment(increment).wait_test(object);
    let observer = *SIGNAL_OBSERVER.lock();
    if let Some(observer) = observer {
        observer(object);
    }
}

/// Testa de novo as esperas de `object` sem mudar o estado dele: os blocos
/// de notificação (as esperas acordadas, que sondam a condição delas)
/// saem, e os de objeto só se o estado já os satisfaz. Para uma mudança que
/// o estado do objeto não mostra (uma vaga de concorrência na porta de
/// conclusão, o encerramento de uma worker factory).
pub fn retest(object: u64) {
    lock().wait_test(object);
}

/// O despachante confirma que a thread deixou a CPU numa espera
/// (WaitCommitted). `false` quando a espera já saiu antes disso (abortada):
/// a thread volta direto à fila.
pub fn commit(thread: u64) -> bool {
    let mut lock = lock();
    let target = kthread(thread);
    let register = target.wait_register.flags.get();
    if lock.waiting(thread) && register & WAIT_STATE_MASK == WAIT_IN_PROGRESS {
        target.wait_register.flags.set((register & !WAIT_STATE_MASK) | WAIT_COMMITTED);
        true
    } else {
        target.wait_register.flags.set(register & !WAIT_STATE_MASK);
        false
    }
}

/// Quem espera: a thread de kernel na própria pilha ou a thread de usuário
/// dentro de um serviço que pode deixar a CPU (`context_switch::can_block`):
/// as duas registram os blocos e saem das prontas do mesmo jeito.
#[derive(Clone, Copy)]
struct Waiter {
    thread: u64,
    /// A de usuário: o despacho de usuário grava o KTHREAD.State e confirma
    /// a espera quando ela deixa a CPU.
    user: bool,
}

/// A troca de contexto de uma espera registrada: a thread de kernel volta ao
/// despachante dela (`switch_out`); a de usuário deixa a CPU com o serviço
/// suspenso na própria pilha (`context_switch::block_registered`) até o
/// sinal a aprontar e o despachante de usuário a retomar. Uma thread
/// retomada com a espera ainda registrada (aprontada por fora do sinal)
/// desfaz o registro e recomeça a espera, como depois de uma APC de kernel.
fn switch_waiting(waiter: Waiter) {
    let thread = waiter.thread;
    if waiter.user {
        let serial = {
            let mut lock = lock();
            lock.table().waits.get(&thread).map_or(0, |wait| wait.serial)
        };
        context_switch::block_registered(serial);
    } else {
        context_switch::switch_out(SwitchReason::Wait);
    }
    let mut lock = lock();
    if lock.waiting(thread) {
        lock.unwait(thread, STATUS_KERNEL_APC as u64);
        let target = kthread(thread);
        let register = target.wait_register.flags.get();
        target.wait_register.flags.set(register & !WAIT_STATE_MASK);
        lock.ready.retain(|&ready| ready != thread);
    }
}

/// A thread que espera agora: a de kernel da pilha em que a CPU está, ou a de
/// usuário cujo serviço pode deixar a CPU.
fn current_waiter() -> Waiter {
    if let Some(thread) = context_switch::on_kernel_thread_stack() {
        return Waiter { thread, user: false };
    }
    assert!(context_switch::can_block(), "espera registrada fora de uma thread que pode deixar a CPU");
    Waiter { thread: crate::ntos::ps::process::get_current_thread(), user: true }
}

/// Uma espera registrada cabe aqui: numa thread de kernel que pode deixar a
/// CPU, ou numa thread de usuário dentro de um serviço que pode
/// (`context_switch::can_block`). Senão (o contexto de boot, um pump
/// aninhado) a espera é sondada no lugar.
pub fn can_wait() -> bool {
    context_switch::kernel_thread_can_block() || (context_switch::on_kernel_thread_stack().is_none() && context_switch::can_block())
}

/// O status de uma espera concluída: KTHREAD.WaitStatus da thread.
fn wait_status(thread: u64) -> u64 {
    kthread(thread).wait_status.get() as u64
}

/// O prazo de uma espera.
#[derive(Clone, Copy)]
pub enum Deadline {
    Infinite,
    /// Uptime (100 ns) em que vence.
    Uptime(u64),
    /// Hora do sistema (100 ns desde 1601) em que vence.
    SystemTime(u64),
}

impl Deadline {
    /// Um prazo relativo em 100 ns a partir de agora.
    pub fn after(timeout: Option<u64>) -> Deadline {
        match timeout {
            None => Deadline::Infinite,
            Some(timeout) => Deadline::Uptime(clock::uptime_100ns().saturating_add(timeout)),
        }
    }

    /// O que falta, em 100 ns (nenhum = infinito).
    pub fn remaining(self) -> Option<u64> {
        match self {
            Deadline::Infinite => None,
            Deadline::Uptime(deadline) => Some(deadline.saturating_sub(clock::uptime_100ns())),
            Deadline::SystemTime(deadline) => Some(deadline.saturating_sub(clock::system_time_100ns())),
        }
    }
}

/// O laço de uma espera registrada da thread de kernel corrente: o alerta
/// pendente primeiro, a tentativa e o registro sob o lock, a troca de
/// contexto e, numa APC de kernel, a entrega e a espera de novo pelo prazo
/// restante. `attempt` tenta sob o lock e devolve o status se já concluiu.
fn wait_loop(objects: &[u64], deadline: Deadline, mut spec: WaitSpec, mut attempt: impl FnMut(&mut DispatcherLock, u64) -> Option<u64>) -> u64 {
    let waiter = current_waiter();
    let thread = waiter.thread;
    spec.user = waiter.user;
    context_switch::assert_wait_allowed();
    loop {
        if let Some(status) = thread_alert::consume(thread, spec.mode, spec.alertable) {
            return status as u64;
        }
        {
            let mut lock = lock();
            if let Some(status) = attempt(&mut lock, thread) {
                return status;
            }
            spec.timeout = deadline.remaining();
            if spec.timeout == Some(0) {
                return spec.timeout_key as u64;
            }
            if let Err(status) = lock.link_wait(thread, objects, spec) {
                return status as u64;
            }
        }
        switch_waiting(waiter);
        let status = wait_status(thread);
        if status != STATUS_KERNEL_APC as u64 {
            return status;
        }
        super::deliver_thread_apcs();
    }
}

/// KeWaitForSingleObject/KeWaitForMultipleObjects numa thread de kernel: os
/// objetos (até 64, distintos) por WaitAny ou WaitAll, com o prazo.
pub fn wait_for_objects(objects: &[u64], wait_all: bool, deadline: Deadline, mode: u8, alertable: bool, wait_reason: u8) -> u32 {
    let kind = if wait_all { wait_type::ALL } else { wait_type::ANY };
    let spec = WaitSpec::new(kind, None, mode, alertable, wait_reason);
    wait_loop(objects, deadline, spec, |_, thread| dispatcher::try_wait_objects_for(objects, kind as u32, thread).map(|status| status as u64)) as u32
}

/// KeDelayExecutionThread numa thread de kernel: só o timer da thread, com
/// STATUS_SUCCESS no vencimento.
pub fn delay(deadline: Deadline, mode: u8, alertable: bool) -> u32 {
    let spec = WaitSpec { timeout_key: STATUS_SUCCESS, ..WaitSpec::new(wait_type::ANY, None, mode, alertable, reason::DELAY_EXECUTION) };
    wait_loop(&[], deadline, spec, |_, _| None) as u32
}

/// O resultado da espera de uma fila.
pub enum QueueWait {
    /// A entrada entregue pelo KeInsertQueue (KiInsertQueue).
    Entry(u64),
    /// A tentativa concluiu sob o lock (`attempt` devolveu o status).
    Attempt(u64),
    /// A espera saiu com o status (prazo, alerta, APC de usuário).
    Status(u32),
}

/// A espera de uma fila (KeRemoveQueueEx) numa thread de kernel, como no
/// 19041: `attempt` tenta a fila sob o lock do despachante; sem entrada,
/// `on_block` libera a vaga da thread (CurrentCount--, ainda sob o lock), o
/// bloco WaitDequeue entra na cabeça da WaitListHead da fila (a mais recente
/// é a primeira atendida) e a thread deixa a CPU. O KeInsertQueue entrega a
/// entrada direto pelo KTHREAD.WaitStatus e ocupa a vaga por ela; qualquer
/// outra saída a ocupa aqui (`on_wake`, sob o lock). Uma APC de kernel é
/// entregue e a espera recomeça pelo prazo restante.
pub fn wait_queue(queue: u64, deadline: Deadline, mode: u8, alertable: bool, mut attempt: impl FnMut() -> Option<u64>, mut on_block: impl FnMut(), mut on_wake: impl FnMut()) -> QueueWait {
    let waiter = current_waiter();
    let thread = waiter.thread;
    context_switch::assert_wait_allowed();
    loop {
        if let Some(status) = thread_alert::consume(thread, mode, alertable) {
            return QueueWait::Status(status);
        }
        {
            let mut lock = lock();
            if let Some(result) = attempt() {
                return QueueWait::Attempt(result);
            }
            let timeout = deadline.remaining();
            if timeout == Some(0) {
                return QueueWait::Status(STATUS_TIMEOUT);
            }
            on_block();
            let spec = WaitSpec { at_head: true, user: waiter.user, ..WaitSpec::new(wait_type::DEQUEUE, timeout, mode, alertable, reason::WR_QUEUE) };
            if let Err(status) = lock.link_wait(thread, &[queue], spec) {
                on_wake();
                return QueueWait::Status(status);
            }
        }
        switch_waiting(waiter);
        let status = wait_status(thread);
        // Uma entrada é um ponteiro de sistema; os status são pequenos.
        if status >= 0xFFFF_8000_0000_0000 {
            return QueueWait::Entry(status);
        }
        {
            let _lock = lock();
            on_wake();
        }
        if status != STATUS_KERNEL_APC as u64 {
            return QueueWait::Status(status as u32);
        }
        super::deliver_thread_apcs();
    }
}

/// Uma espera explícita da thread de kernel corrente: o registro antes da
/// sondagem (nenhum `wake` se perde entre as duas), a sondagem fora do lock
/// e a troca de contexto até um [`wake`], o sinal de `watch` (um bloco de
/// notificação, que não consome), o prazo, um alerta ou uma APC. Devolve o
/// status de `poll`; um alerta, uma APC de usuário ou o prazo vencido sem a
/// sondagem concluir devolvem o status da espera.
pub fn wait_woken(poll: &mut dyn FnMut() -> Option<u32>, watch: Option<u64>, deadline: Deadline, mode: u8, alertable: bool, wait_reason: u8) -> u32 {
    let thread = current_waiter().thread;
    context_switch::assert_wait_allowed();
    loop {
        if let Some(status) = poll() {
            return status;
        }
        if let Some(status) = thread_alert::consume(thread, mode, alertable) {
            return status;
        }
        if deadline.remaining() == Some(0) {
            return poll().unwrap_or(STATUS_TIMEOUT);
        }
        match wait_once(poll, watch, deadline, mode, alertable, wait_reason) {
            WaitOnce::Done(status) => return status,
            WaitOnce::Woken(STATUS_KERNEL_APC) => {
                super::deliver_thread_apcs();
            }
            WaitOnce::Woken(status @ (STATUS_ALERTED | STATUS_USER_APC | STATUS_TIMEOUT)) => return poll().unwrap_or(status),
            WaitOnce::Woken(_) => {}
        }
    }
}

/// O resultado de uma volta de [`wait_once`].
pub enum WaitOnce {
    /// A sondagem concluiu (antes da troca) com o status dela.
    Done(u32),
    /// A thread saiu da espera com o status (STATUS_SUCCESS num `wake` ou no
    /// sinal de `watch`).
    Woken(u32),
}

/// Uma volta de espera explícita: registra (bloco de notificação em `watch`,
/// o timer do prazo), sonda (um `wake` entre o registro e a sondagem não se
/// perde) e, se a sondagem não concluiu, deixa a CPU até sair da espera.
pub fn wait_once(poll: &mut dyn FnMut() -> Option<u32>, watch: Option<u64>, deadline: Deadline, mode: u8, alertable: bool, wait_reason: u8) -> WaitOnce {
    let waiter = current_waiter();
    let thread = waiter.thread;
    let objects: &[u64] = match &watch {
        Some(object) => core::slice::from_ref(object),
        None => &[],
    };
    let spec = WaitSpec { explicit: true, user: waiter.user, ..WaitSpec::new(wait_type::NOTIFICATION, deadline.remaining(), mode, alertable, wait_reason) };
    if lock().link_wait(thread, objects, spec).is_err() {
        return WaitOnce::Done(STATUS_INSUFFICIENT_RESOURCES);
    }
    // O registro vem antes da sondagem: um `wake` entre as duas marca a
    // espera abortada e a troca volta logo.
    if let Some(status) = poll() {
        cancel(thread);
        return WaitOnce::Done(status);
    }
    switch_waiting(waiter);
    WaitOnce::Woken(wait_status(thread) as u32)
}

/// Desfaz a espera registrada da thread corrente que não chegou a deixar a
/// CPU (a condição concluiu entre o registro e a troca).
fn cancel(thread: u64) {
    let mut lock = lock();
    lock.unwait(thread, STATUS_SUCCESS as u64);
    let target = kthread(thread);
    let register = target.wait_register.flags.get();
    target.wait_register.flags.set(register & !WAIT_STATE_MASK);
    // A thread segue em execução: nada a aprontar.
    lock.ready.retain(|&ready| ready != thread);
}

/// Conclui a espera explícita de `thread` (a retirada de uma porta de
/// conclusão, uma mensagem ALPC que chegou): ela volta à fila e sonda de
/// novo. Uma espera de objeto não é tocada.
pub fn wake(thread: u64) -> bool {
    wake_with_increment(thread, 0)
}

/// [`wake`] com o incremento de quem acorda (o KeAlertThreadByThreadId, 1 em
/// 0x25c312; o KeReleaseSemaphoreEx do AlpcpSignal, 1 em 0x20571a).
pub fn wake_with_increment(thread: u64, increment: i8) -> bool {
    dispatcher::note_wake();
    let mut lock = lock_with_increment(increment);
    if !lock.table().waits.get(&thread).is_some_and(|wait| wait.explicit) {
        return false;
    }
    lock.unwait(thread, STATUS_SUCCESS as u64)
}

/// Um alerta para `thread` (KeAlertThread): uma espera registrada alertável,
/// de modo igual ou menor que o da espera, sai com STATUS_ALERTED. `true` se
/// a espera saiu. Quem chama segura a ThreadLock dela e a apronta depois de
/// soltá-la, com o ALERT_INCREMENT (`thread_alert::alert`): aqui ela não
/// entra na fila.
pub fn alert(thread: u64, mode: u8) -> bool {
    let mut lock = lock();
    let Some(wait) = lock.table().waits.get(&thread) else { return false };
    if !wait.alertable || mode > wait.mode {
        return false;
    }
    let woken = lock.unwait(thread, STATUS_ALERTED as u64);
    lock.ready.retain(|&ready| ready != thread);
    woken
}

/// Uma APC enfileirada para `thread` (o KiInsertQueueApc): a de usuário numa
/// espera alertável de UserMode publica UserApcPending e sai com
/// STATUS_USER_APC; a de kernel numa espera em PASSIVE_LEVEL, com as APCs
/// do tipo dela habilitadas, sai com STATUS_KERNEL_APC.
pub fn apc_queued(thread: u64, user_mode: bool, special: bool, increment: i8) {
    let mut lock = lock_with_increment(increment);
    let target = kthread(thread);
    let Some(wait) = lock.table().waits.get(&thread) else {
        // Uma thread de kernel numa espera sondada, parada em PASSIVE_LEVEL,
        // volta à fila para entregar a APC de kernel na própria pilha.
        drop(lock);
        let enabled = if special { target.special_apc_disable.get() == 0 } else { target.kernel_apc_disable.get() == 0 && target.special_apc_disable.get() == 0 };
        if !user_mode && enabled && target.wait_irql.get() == super::irql::PASSIVE_LEVEL {
            scheduler::wake_polled(thread);
        }
        return;
    };
    if user_mode {
        if wait.alertable && wait.mode == 1 {
            target.apc_state.set_user_apc_pending(1);
            lock.unwait(thread, STATUS_USER_APC as u64);
        }
        return;
    }
    let enabled = if special { target.special_apc_disable.get() == 0 } else { target.kernel_apc_disable.get() == 0 && target.special_apc_disable.get() == 0 };
    if wait.kernel_apcs && enabled {
        lock.unwait(thread, STATUS_KERNEL_APC as u64);
    }
}

/// O pedido de término publicou UserApcPending na thread
/// (`ps/user/threads::request_termination`): a espera registrada de
/// UserMode dela, alertável ou não, sai com STATUS_USER_APC. No 19041 a
/// SchedulerApc do término interrompe a espera em PASSIVE_LEVEL e a espera
/// recomeçada vê a UserApcPending pelo KiCheckAlertability; a de KernelMode
/// continua. `true` se a espera saiu.
pub fn user_apc_published(thread: u64) -> bool {
    let mut lock = lock();
    if !lock.table().waits.get(&thread).is_some_and(|wait| wait.mode == 1) {
        return false;
    }
    lock.unwait(thread, STATUS_USER_APC as u64)
}

/// Os campos de espera da KTHREAD numa espera de UserMode do despacho de
/// usuário (o que o KiCommitThreadWait grava): WaitStatus zerado, WaitMode
/// UserMode, Alertable, WaitReason e WaitTime. O State Waiting vem do
/// despacho quando a thread deixa a CPU. O SystemProcessInformation e o kd
/// leem o motivo daqui.
pub fn publish_user_wait(thread: u64, reason: u8, alertable: bool) {
    if thread == 0 {
        return;
    }
    let target = kthread(thread);
    target.wait_status.set(0);
    target.wait_mode.set(1);
    target.set_alertable(alertable as u32);
    target.wait_reason.set(reason);
    target.wait_time.set(thread_dispatch::tick_count());
}

/// Diagnóstico de parada: os objetos da espera registrada de `thread`
/// (endereço, tipo e sinal de cada um) e se ela é explícita.
pub fn describe_waiting(thread: u64) -> Option<(alloc::vec::Vec<(u64, u8, i32)>, bool)> {
    let mut lock = lock();
    let wait = lock.table().waits.get(&thread)?;
    let (blocks, count, explicit) = (wait.blocks, wait.count, wait.explicit);
    let objects = (0..count.min(8) as u64).map(|index| {
        let object = block_at(blocks + index * core::mem::size_of::<KwaitBlock>() as u64).object.get();
        let header = header(object);
        (object, header.type_.get() & 0x7F, header.signal_state.get())
    }).collect();
    Some((objects, explicit))
}

/// `thread` tem uma espera registrada (diagnóstico e autotestes).
pub fn is_waiting(thread: u64) -> bool {
    lock().waiting(thread)
}

// ---- As esperas registradas das threads de usuário -------------------------

/// O começo de uma espera registrada: concluída ali mesmo, com o status, ou
/// com os blocos ligados, com o número da espera.
pub enum UserWaitStart {
    Done(u32),
    Linked(u64),
}

/// O começo de uma espera registrada da thread de usuário `thread`, ainda
/// dentro do serviço dela (o KeWaitForMultipleObjects antes do
/// KiCommitThreadWait), sob o lock do despachante: num WaitAny ou WaitAll os
/// objetos já disponíveis a satisfazem ali mesmo, consumidos pela thread; um
/// prazo vencido devolve a chave do timer; senão os blocos e o timer são
/// ligados (WaitInProgress) e o sinal que vier a satisfaz (o KiUnwaitThread
/// põe a thread na fila). `Err` sem pool para os blocos.
pub fn begin_user_wait(thread: u64, objects: &[u64], deadline: Deadline, spec: WaitSpec) -> Result<UserWaitStart, u32> {
    let mut lock = lock();
    if matches!(spec.kind, wait_type::ANY | wait_type::ALL) && !objects.is_empty() {
        if let Some(status) = dispatcher::try_wait_objects_for(objects, spec.kind as u32, thread) {
            return Ok(UserWaitStart::Done(status));
        }
    }
    let timeout = deadline.remaining();
    if timeout == Some(0) {
        return Ok(UserWaitStart::Done(spec.timeout_key));
    }
    lock.link_wait(thread, objects, WaitSpec { timeout, user: true, ..spec })?;
    let serial = lock.table().waits.get(&thread).map_or(0, |wait| wait.serial);
    Ok(UserWaitStart::Linked(serial))
}

/// O KiCommitThreadWait de uma thread de usuário que acabou de deixar a CPU
/// com a espera registrada (depois do `end_execution`, como o `run_step` das
/// threads de kernel): um alerta do modo da espera ou uma APC de usuário que
/// chegou com a espera em curso (o WaitRegister.Alert do 19041) a desfaz com
/// o status dele; então ela passa a WaitCommitted. `false` quando a espera
/// já saiu (WaitAborted: o sinal veio antes de a thread deixar a CPU), e a
/// thread volta à fila por quem chama.
pub fn commit_user_wait(thread: u64) -> bool {
    let parameters = {
        let mut lock = lock();
        lock.table().waits.get(&thread).map(|wait| (wait.mode, wait.alertable))
    };
    if let Some((mode, alertable)) = parameters {
        if let Some(status) = thread_alert::consume(thread, mode, alertable) {
            lock().unwait(thread, status as u64);
        }
    }
    commit(thread)
}

/// O desfecho da espera registrada número `serial` de `thread`: `None`
/// enquanto os blocos dela estão ligados; depois, o KTHREAD.WaitStatus que
/// a saída gravou (o índice do objeto, STATUS_ABANDONED + índice,
/// STATUS_TIMEOUT, STATUS_ALERTED, STATUS_USER_APC).
pub fn user_wait_outcome(thread: u64, serial: u64) -> Option<u32> {
    let mut lock = lock();
    if lock.table().waits.get(&thread).is_some_and(|wait| wait.serial == serial) {
        None
    } else {
        Some(wait_status(thread) as u32)
    }
}

/// Desfaz, com `status`, a espera registrada número `serial` de `thread`,
/// que já deixou a CPU (o término, o fim do processo): ela volta à fila.
/// `false` se essa espera não está mais ligada.
pub fn cancel_user_wait(thread: u64, serial: u64, status: u32) -> bool {
    let mut lock = lock();
    if !lock.table().waits.get(&thread).is_some_and(|wait| wait.serial == serial) {
        return false;
    }
    lock.unwait(thread, status as u64)
}

/// Desfaz a espera registrada número `serial` de `thread` sem aprontá-la: a
/// thread corrente, que ainda não deixou a CPU (a condição concluiu entre o
/// registro e a volta do serviço), ou uma espera descartada sem conclusão.
pub fn withdraw_user_wait(thread: u64, serial: u64) {
    let mut lock = lock();
    if !lock.table().waits.get(&thread).is_some_and(|wait| wait.serial == serial) {
        return;
    }
    lock.unwait(thread, STATUS_SUCCESS as u64);
    let target = kthread(thread);
    let register = target.wait_register.flags.get();
    target.wait_register.flags.set(register & !WAIT_STATE_MASK);
    lock.ready.retain(|&ready| ready != thread);
}
