//! Troca de espaço de endereçamento: o KiSwapProcess do NT.
//!
//! Invariante, fora da troca: o CR3 de cada CPU é a raiz
//! (KPROCESS.DirectoryTableBase) do processo corrente da sua thread
//! corrente, `KTHREAD.ApcState.Process` — o processo anexado, durante uma
//! anexação. Quem muda esse processo mantém o invariante:
//!
//! - a anexação ([`swap_process`], chamada por `process_attachment`): no
//!   attach carrega a raiz do destino, no detach a do processo que o
//!   KAPC_STATE salvo devolve (o aninhamento é o dos KAPC_STATE, como no
//!   NT), e move a CPU em KPROCESS.ActiveProcessors;
//! - a troca de thread corrente ([`load_process`], chamada por
//!   `ps::process::set_current_thread`): carrega a raiz do processo da nova
//!   thread quando ela difere da carregada e move a CPU em
//!   KPROCESS.ActiveProcessors.
//!
//! Cada CPU registra aqui a raiz que carregou ([`loaded_root`],
//! [`is_root_loaded`]): o Mm não devolve ao PFN uma raiz que alguma CPU
//! esteja usando (`process_address_space::delete`). Só esta troca carrega
//! uma raiz diferente; os outros escritores do CR3 (`cpu::reload_cr3`, a
//! partida dos APs na raiz do System) recarregam a mesma.
//!
//! Cada CPU também registra o processo em cujo KPROCESS.ActiveProcessors
//! ela tem o bit ([`active_process`]): a troca tira o bit do processo
//! registrado, não do processo da thread que sai — que pode já ter sido
//! liberada (a thread de um processo que acabou de terminar). O último
//! dereference de um processo o tira do registro ([`forget_process`]) antes
//! de o EPROCESS voltar ao pool.
//!
//! Sem PCID nem páginas globais, cada troca esvazia a TLB não global da CPU.
//! Cada processo de usuário tem a própria raiz (`ps::process::create_process`
//! a cria com o processo); o System, os processos de kernel e os APs ficam
//! na raiz do System, e só o BSP carrega a raiz de um processo de usuário
//! para rodar o anel 3 dele.
//!
//! O assert do invariante ([`check_loaded_root`], instalado em
//! `guest_memory` no armar do anel 3) confere, a cada VA de usuário que o
//! kernel toca, que a raiz carregada é a do processo corrente da thread
//! corrente desta CPU.
//!
//! Aqui também mora a decisão do KiSwapContext (a troca de pilha em si é
//! `hal::amd64::context_switch`). Toda thread de kernel — as threads de
//! sistema dos drivers (PsCreateSystemThread), os processos de kernel do
//! escalonador e as requisições do kernel com thread própria — roda inteira
//! na própria pilha de kernel: o despachante da CPU entra nela por uma troca
//! de contexto ([`resume`]) e ela devolve a CPU por outra ([`switch_out`]),
//! ao ceder a vez, ao esperar ou ao terminar. Cada lado da troca leva o seu
//! estado da CPU: o IRQL (KTHREAD.WaitIrql numa espera), a posse de execução
//! nativa, as posses de SharedLock e a thread corrente. Uma espera de uma
//! thread de kernel tira a thread do conjunto de prontas e troca de contexto
//! (`ke::wait`), e quem a apronta é o sinal; nada gira o despachante de
//! dentro de uma espera, e o tick do escalonador nunca roda na pilha de uma
//! thread de kernel ([`on_kernel_thread_stack`]).
//!
//! Uma thread de usuário que espera dentro de uma syscall ([`can_block`])
//! deixa a CPU ([`block_current`]), e o despachante de `ps/user/threads.rs`
//! roda as outras; quando a espera, sondada por ele no contexto da thread,
//! conclui, ele a retoma na própria pilha ([`switch_to`]). As esperas
//! genéricas (uma condição sondada, [`wait_until`]/[`acquire_until`]) numa
//! thread de kernel tiram a thread das prontas com a condição sondada pelo
//! despachante (`scheduler::block_polled`); só o contexto de boot, que é o
//! próprio despachante, espera girando o pump. Como no NT, esperar de fato
//! com prazo não nulo em DISPATCH_LEVEL ou acima, ou com um SpinLock retido,
//! para o sistema.

use alloc::boxed::Box;
use core::panic::Location;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use super::{irql, pcr, thread_dispatch};
use crate::hal::amd64::{context_switch as switch, native_call, usermode};
use crate::hal::cpu;
use crate::ntos::inc::types::{Kpcr, Kprocess, Kthread, NtStruct};
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::process_address_space::{self, SYSTEM_ROOT};
use crate::ntos::ps::process;
use crate::ntos::ps::scheduler;
use crate::ntos::ps::user::threads::{self, UserThread, Wait};
use crate::rtl::{sync, KernelError};

/// Bits do DirectoryTableBase que formam o endereço físico da PML4.
const ROOT_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// A raiz carregada em cada CPU, pelo número do processador. Toda CPU
/// começa na raiz do System (o BSP desde o boot; os APs recebem a mesma na
/// partida).
static LOADED: [AtomicU64; map::MAX_CPUS] = [const { AtomicU64::new(SYSTEM_ROOT) }; map::MAX_CPUS];
/// O processo em que cada CPU está (o bit dela em KPROCESS.ActiveProcessors),
/// pelo número do processador; 0 antes da primeira troca.
static ACTIVE: [AtomicU64; map::MAX_CPUS] = [const { AtomicU64::new(0) }; map::MAX_CPUS];

/// A KPCR desta CPU (gs:[KPCR.Self]); nenhuma antes da do BSP.
fn current_pcr() -> Option<&'static Kpcr> {
    (pcr::get_pcr_address() != 0).then(pcr::current)
}

/// O número desta CPU (KPRCB.Number); 0 antes da KPCR do BSP.
pub fn processor() -> usize {
    current_pcr().map_or(0, |kpcr| (kpcr.prcb.number.get() as usize).min(map::MAX_CPUS - 1))
}

/// KPROCESS.DirectoryTableBase de `process`; sem processo, a raiz do System.
pub fn directory_table_base(process: u64) -> u64 {
    if process == 0 {
        return SYSTEM_ROOT;
    }
    // SAFETY: EPROCESS gerido pelo Ps, vivo enquanto é o processo de uma
    // thread ou o alvo retido de uma anexação.
    unsafe { Kprocess::at(process) }.directory_table_base.get() & ROOT_MASK
}

/// A raiz de `process` pode ser carregada: a do System ou uma raiz de
/// espaço de endereçamento do Mm. Usado antes de mudar o KAPC_STATE, para
/// que a troca não falhe no meio.
pub fn require_loadable(process: u64) -> Result<u64, KernelError> {
    let root = directory_table_base(process);
    if !process_address_space::is_root(root) {
        return Err(KernelError::new("process has no loadable address-space root"));
    }
    Ok(root)
}

/// A raiz carregada nesta CPU.
pub fn loaded_root() -> u64 {
    LOADED[processor()].load(Ordering::Acquire)
}

/// O assert do invariante (`guest_memory::set_root_check`): a raiz no CR3
/// desta CPU é a do processo corrente da thread corrente dela
/// (KPRCB.CurrentThread pelo GS, e dela KTHREAD.ApcState.Process, o anexado
/// quando há attach; sem KPCR ou sem thread, o System). Uma VA de usuário que
/// o kernel toca cai, então, no espaço desse processo. A divergência (uma
/// troca que não carregou a raiz, ou memória de usuário tocada por outra
/// CPU) para o sistema com a VA, as raízes, o processo e a linha do chamador.
pub fn check_loaded_root(va: u64, caller: &'static Location<'static>) {
    let loaded = cpu::read_cr3() & ROOT_MASK;
    let thread = current_pcr().map_or(0, |kpcr| kpcr.prcb.current_thread.get());
    // SAFETY: a thread corrente desta CPU está viva enquanto é a corrente.
    let process = if thread != 0 { unsafe { Kthread::at(thread) }.apc_state.process.get() } else { process::get_system_process() };
    let expected = directory_table_base(process);
    if loaded != expected {
        panic!("assert de CR3: VA de usuario {va:#x} tocada com a raiz {loaded:#x} carregada na CPU {}, mas o processo corrente {process:#x} (thread {thread:#x}) usa a raiz {expected:#x}; chamado de {caller}", processor());
    }
}

/// Alguma CPU está com `root` carregada.
pub fn is_root_loaded(root: u64) -> bool {
    LOADED.iter().any(|loaded| loaded.load(Ordering::SeqCst) == root)
}

/// Carrega `root` no CR3 desta CPU quando ela ainda não é a carregada. A
/// raiz tem de ser a do System ou uma raiz do Mm. Interrupções ficam
/// desligadas entre o registro e o CR3, para que uma troca aninhada (uma
/// rotina de interrupção que muda a thread corrente e a restaura) não deixe
/// os dois divergirem.
pub fn load_root(root: u64) -> Result<(), KernelError> {
    let flags = cpu::save_and_disable_interrupts();
    let loaded = &LOADED[processor()];
    let result = if loaded.load(Ordering::Relaxed) == root {
        Ok(())
    } else if !process_address_space::is_root(root) {
        Err(KernelError::new("not an address-space root"))
    } else {
        // Publicado antes do CR3: o delete de outra CPU nunca vê a raiz
        // livre enquanto esta a carrega.
        loaded.store(root, Ordering::SeqCst);
        cpu::write_cr3(root);
        Ok(())
    };
    cpu::restore_interrupts(flags);
    result
}

/// O processo em que esta CPU está (o bit dela em
/// KPROCESS.ActiveProcessors); 0 antes da primeira troca.
pub fn active_process() -> u64 {
    ACTIVE[processor()].load(Ordering::Acquire)
}

/// Esta CPU passa a estar em `next`: o bit dela (grupo e número da KPRCB)
/// sai de KPROCESS.ActiveProcessors do processo registrado e entra no de
/// `next`. O processo que sai é o registrado, nunca lido da thread que sai.
/// Interrupções desligadas: uma troca aninhada não intercala o registro.
fn enter_process(next: u64) {
    let Some(kpcr) = current_pcr() else { return };
    let flags = cpu::save_and_disable_interrupts();
    let slot = &ACTIVE[processor()];
    let previous = slot.load(Ordering::Acquire);
    if previous != next {
        let group = kpcr.prcb.group.get() as usize;
        let bit = 1u64 << kpcr.prcb.group_index.get();
        if previous != 0 {
            // SAFETY: o processo registrado está vivo: o último dereference
            // o tira do registro antes de liberar o EPROCESS.
            unsafe { Kprocess::at(previous) }.active_processors.bitmap[group].atomic().fetch_and(!bit, Ordering::SeqCst);
        }
        if next != 0 {
            // SAFETY: o processo da nova thread corrente (ou o alvo de uma
            // anexação), retido por ela ou pelo chamador.
            unsafe { Kprocess::at(next) }.active_processors.bitmap[group].atomic().fetch_or(bit, Ordering::SeqCst);
        }
        slot.store(next, Ordering::Release);
    }
    cpu::restore_interrupts(flags);
}

/// O EPROCESS `process` vai ser liberado (o último dereference): nenhuma
/// CPU fica com ele registrado. Como no NT, um processo só é liberado
/// depois que nenhuma thread dele roda e ninguém está anexado a ele.
pub fn forget_process(process: u64) {
    for slot in &ACTIVE {
        let _ = slot.compare_exchange(process, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// A troca de thread corrente: carrega a raiz de `process`, o
/// `ApcState.Process` da nova thread, e move a CPU em
/// KPROCESS.ActiveProcessors. Uma raiz que não é de espaço de endereçamento
/// (EPROCESS corrompido) não é carregada: a CPU fica na raiz do System, que
/// não tem página de usuário de nenhum espaço próprio.
pub fn load_process(process: u64) {
    let root = directory_table_base(process);
    if let Err(error) = load_root(root) {
        debug_print!("[ke] raiz {:#x} do processo {:#x} nao carregada: {}", root, process, error);
        let _ = load_root(SYSTEM_ROOT);
    }
    enter_process(process);
}

/// KiSwapProcess: esta CPU sai do processo registrado (`previous`, para o
/// chamador, é o mesmo) e entra em `next`. Carrega a raiz de `next` quando
/// ela difere da carregada e move o bit da CPU de
/// KPROCESS.ActiveProcessors. Os dois processos estão retidos pelo chamador.
pub fn swap_process(_previous: u64, next: u64) -> Result<(), KernelError> {
    load_root(directory_table_base(next))?;
    enter_process(next);
    Ok(())
}

// ---- KiSwapContext: esperas que bloqueiam --------------------------------

/// O status com que termina a espera de uma thread terminada enquanto
/// bloqueada no kernel (o papel da APC de término do NT).
pub const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;

/// O RSP de quem chama.
fn current_rsp() -> u64 {
    let rsp: u64;
    // SAFETY: só lê o registrador.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    rsp
}

/// Uma espera pode deixar a CPU: a thread corrente é a thread de usuário de
/// uma syscall despachada nesta CPU (o BSP, no M0), roda na própria pilha de
/// kernel e é a execução em curso (nada de contexto aninhado: um passo do
/// escalonador, uma APC drenada em nome de outra thread, um callback de
/// modo usuário), abaixo de
/// DISPATCH_LEVEL e sem SpinLock nem SharedLock retidos.
pub fn can_block() -> bool {
    let Some(thread) = threads::current() else { return false };
    let pointer = thread.pointer();
    if pointer == 0 || pointer != process::get_current_thread() || processor() != 0 || !usermode::in_service() {
        return false;
    }
    if irql::get_irql() >= irql::DISPATCH_LEVEL || sync::spin_locks_held() != 0 || sync::shared_locks_held() != 0 {
        return false;
    }
    if thread_dispatch::active_thread() != Some(pointer) {
        return false;
    }
    // SAFETY: a KTHREAD da thread corrente está viva enquanto ela executa.
    let kthread = unsafe { Kthread::at(pointer) };
    // Dentro de um callback de modo usuário o intervalo é aninhado: quem o
    // conclui é o laço do KeUserModeCallback, não o despachante.
    if kthread.callback_nesting_level.get() != 0 {
        return false;
    }
    let (initial, limit, rsp) = (kthread.initial_stack.get(), kthread.stack_limit.get(), current_rsp());
    map::is_kernel_stack(initial) && rsp > limit && rsp < initial
}

/// Esperar de fato (a condição ainda não vale e o prazo não é nulo) exige,
/// como no NT, IRQL abaixo de DISPATCH_LEVEL e nenhum spin lock retido.
pub fn assert_wait_allowed() {
    let level = irql::get_irql();
    assert!(level < irql::DISPATCH_LEVEL, "espera com prazo nao nulo em IRQL {} (DISPATCH_LEVEL ou acima)", level);
    let held = sync::spin_locks_held();
    assert!(held == 0, "espera com prazo nao nulo com {} SpinLock(s) retido(s)", held);
}

/// A sondagem de quem bloqueou, emprestada ao despachante: vive na pilha da
/// thread bloqueada, que só volta a executar depois que o despachante
/// conclui (e descarta) a espera.
struct BorrowedPoll(*mut (dyn FnMut() -> Option<u32> + 'static));

// SAFETY: a sondagem só é chamada pelo despachante, na CPU da thread
// bloqueada, enquanto ela não executa.
unsafe impl Send for BorrowedPoll {}

impl BorrowedPoll {
    fn call(&mut self) -> Option<u32> {
        // SAFETY: o quadro da thread bloqueada continua vivo até a espera ser
        // concluída e descartada (`threads::finish_wait`), antes da retomada.
        unsafe { (*self.0)() }
    }
}

/// O lado de saída do KiSwapContext: a thread de usuário corrente
/// ([`can_block`]) deixa a CPU até `poll` concluir. O despachante sonda
/// `poll` no contexto dela (thread corrente e CR3 dela, na pilha dele) e,
/// quando conclui, a retoma aqui. A IRQL da espera fica em KTHREAD.WaitIrql:
/// a CPU volta ao despachante em PASSIVE_LEVEL e a thread a recupera ao
/// retomar. Devolve o status da sondagem, ou
/// [`STATUS_THREAD_IS_TERMINATING`] se a thread foi terminada enquanto
/// esperava.
pub fn block_current(poll: &mut dyn FnMut() -> Option<u32>) -> u32 {
    let thread = threads::current().expect("bloqueio sem thread de usuario corrente");
    let pointer = thread.pointer();
    // SAFETY: a KTHREAD da thread corrente está viva enquanto ela executa.
    let kthread = unsafe { Kthread::at(pointer) };
    let raw: *mut (dyn FnMut() -> Option<u32> + '_) = poll;
    // SAFETY: só o tempo de vida do objeto muda; a espera que guarda o
    // ponteiro é concluída e descartada antes de este quadro voltar a rodar.
    let raw: *mut (dyn FnMut() -> Option<u32> + 'static) = unsafe { core::mem::transmute(raw) };
    let mut borrowed = BorrowedPoll(raw);
    threads::block_in_kernel(&thread, Wait { poll: Some(Box::new(move || borrowed.call())), ..Wait::default() });
    let wait_irql = irql::get_irql();
    kthread.wait_irql.set(wait_irql);
    if wait_irql != irql::PASSIVE_LEVEL {
        irql::lower_irql(irql::PASSIVE_LEVEL as u64);
    }
    usermode::block_in_service(&kthread.kernel_stack);
    // Retomada por `switch_to`, na própria pilha: nenhum quadro salvo.
    kthread.kernel_stack.set(kthread.initial_stack.get());
    if wait_irql > irql::get_irql() {
        irql::raise_irql(wait_irql);
    }
    threads::take_kernel_wait_status(&thread)
}

/// O lado de entrada do KiSwapContext, chamado pelo despachante com a thread
/// corrente já trocada para `thread` (bloqueada no kernel, espera
/// concluída): retoma o quadro salvo em KTHREAD.KernelStack e devolve o
/// resultado do intervalo, como `exec_user_context` — o serviço concluído,
/// ou outro bloqueio (`EXIT_BLOCKED`).
pub fn switch_to(thread: &UserThread) -> u32 {
    let (pointer, teb) = thread.with(|thread| (thread.thread_pointer, thread.teb_va));
    assert!(pointer != 0 && pointer == process::get_current_thread(), "retomada de uma thread que nao e a corrente");
    assert!(sync::spin_locks_held() == 0, "retomada com SpinLock retido pelo despachante");
    // SAFETY: KTHREAD viva, retida pela thread de usuário.
    let kthread = unsafe { Kthread::at(pointer) };
    let saved = kthread.kernel_stack.get();
    assert!(saved > kthread.stack_limit.get() && saved < kthread.initial_stack.get(), "KernelStack fora da pilha da thread bloqueada");
    usermode::resume_kernel_context(saved, teb)
}

/// Espera até `poll` concluir e devolve o status dela: sonda uma vez; se a
/// condição ainda não vale, a thread sai das prontas (a de kernel com a
/// condição sondada pelo despachante, a de usuário numa syscall pelo
/// despachante de usuário); só o contexto de boot gira `pump` entre
/// sondagens. Uma thread de usuário terminada enquanto bloqueada recebe
/// [`STATUS_THREAD_IS_TERMINATING`].
pub fn wait_until(poll: &mut dyn FnMut() -> Option<u32>, pump: fn()) -> u32 {
    if let Some(status) = poll() {
        return status;
    }
    assert_wait_allowed();
    loop {
        if kernel_thread_can_block() {
            return scheduler::block_polled(poll);
        }
        if can_block() {
            return block_current(poll);
        }
        pump();
        if let Some(status) = poll() {
            return status;
        }
    }
}

// ---- Threads de kernel: a troca com o despachante -------------------------

/// Por que uma thread de kernel devolveu a CPU ao despachante.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwitchReason {
    /// Cedeu a vez e continua pronta; `retain` mantém o quantum.
    Yield { retain: bool },
    /// Saiu do conjunto de prontas numa espera.
    Wait,
    /// Terminou: nunca mais é retomada.
    Exit,
}

impl SwitchReason {
    fn encode(self) -> u8 {
        match self {
            SwitchReason::Yield { retain: false } => 1,
            SwitchReason::Yield { retain: true } => 2,
            SwitchReason::Wait => 3,
            SwitchReason::Exit => 4,
        }
    }

    fn decode(value: u8) -> SwitchReason {
        match value {
            1 => SwitchReason::Yield { retain: false },
            2 => SwitchReason::Yield { retain: true },
            3 => SwitchReason::Wait,
            _ => SwitchReason::Exit,
        }
    }
}

/// O lado do despachante de cada CPU numa troca com uma thread de kernel.
struct CpuSwitch {
    /// RSP do quadro de troca do despachante enquanto a thread roda.
    resumer: AtomicU64,
    /// A thread de kernel em execução na própria pilha (0 = o despachante).
    running: AtomicU64,
    /// O motivo da última devolução da CPU.
    reason: AtomicU8,
}

static SWITCH: [CpuSwitch; map::MAX_CPUS] = [const { CpuSwitch { resumer: AtomicU64::new(0), running: AtomicU64::new(0), reason: AtomicU8::new(0) } }; map::MAX_CPUS];

/// O estado da CPU que cada lado de uma troca leva consigo e recoloca ao
/// voltar a executar: o IRQL, a posse de execução nativa síncrona, as posses
/// de SharedLock e a thread corrente (com a raiz do processo dela).
struct CarriedState {
    irql: u8,
    native: u64,
    shared: u32,
    thread: u64,
}

fn carry_out() -> CarriedState {
    CarriedState { irql: irql::get_irql(), native: native_call::sync_active(), shared: sync::swap_shared_locks_held(0), thread: process::get_current_thread() }
}

fn carry_in(state: CarriedState) {
    irql::swap_irql(state.irql);
    native_call::set_sync_active(state.native);
    sync::swap_shared_locks_held(state.shared);
    if process::get_current_thread() != state.thread {
        process::set_current_thread(state.thread);
    }
}

/// A thread de kernel em cuja pilha a CPU está executando, se é o caso: a
/// thread que o despachante desta CPU retomou e cujo intervalo de pilha
/// contém o RSP (um serviço de usuário despachado de dentro dela roda em
/// outra pilha e não conta). O tick e as esperas que giram o despachante
/// nunca rodam aqui.
pub fn on_kernel_thread_stack() -> Option<u64> {
    if pcr::get_pcr_address() == 0 {
        return None;
    }
    let running = SWITCH[processor()].running.load(Ordering::Acquire);
    if running == 0 {
        return None;
    }
    // SAFETY: a thread em execução está viva enquanto roda.
    let kthread = unsafe { Kthread::at(running) };
    let rsp = current_rsp();
    (rsp > kthread.stack_limit.get() && rsp <= kthread.stack_base.get()).then_some(running)
}

/// A thread de kernel corrente pode deixar a CPU numa espera: a CPU está na
/// pilha dela, abaixo de DISPATCH_LEVEL e sem SpinLock retido.
pub fn kernel_thread_can_block() -> bool {
    on_kernel_thread_stack().is_some() && irql::get_irql() < irql::DISPATCH_LEVEL && sync::spin_locks_held() == 0
}

/// Prepara a pilha de uma thread de kernel nova: o quadro de troca inicial
/// em KTHREAD.KernelStack, que entra em `entry(argument)` na primeira
/// retomada.
pub fn initialize_kernel_thread(thread: u64, entry: extern "C" fn(u64) -> !, argument: u64) {
    // SAFETY: KTHREAD recém-criada com pilha própria, ainda sem executar.
    let kthread = unsafe { Kthread::at(thread) };
    let top = kthread.initial_stack.get();
    assert!(map::is_kernel_stack(top), "thread de kernel sem pilha propria");
    // SAFETY: a pilha da thread está mapeada e sem uso.
    let frame = unsafe { switch::build_initial_frame(top, entry, argument) };
    kthread.kernel_stack.set(frame);
}

/// O começo de uma thread de kernel, chamado pela rotina de entrada antes de
/// qualquer outra coisa: como no KiStartSystemThread, ela parte em
/// PASSIVE_LEVEL, sem posse nativa nem de SharedLock, com a thread corrente
/// que o despachante publicou.
pub fn begin_kernel_thread() {
    irql::swap_irql(irql::PASSIVE_LEVEL);
    native_call::set_sync_active(0);
    sync::swap_shared_locks_held(0);
}

/// O lado de entrada da troca, no despachante: entra na thread de kernel
/// `thread` (já a corrente desta CPU) pelo quadro salvo em
/// KTHREAD.KernelStack e volta quando ela devolve a CPU, com o motivo. O
/// estado do despachante (IRQL, posses, thread corrente) volta intacto.
pub fn resume(thread: u64) -> SwitchReason {
    let slot = &SWITCH[processor()];
    assert!(on_kernel_thread_stack().is_none() && slot.running.load(Ordering::Acquire) == 0, "thread de kernel retomada de dentro de outra");
    assert!(sync::spin_locks_held() == 0, "thread de kernel retomada com SpinLock retido pelo despachante");
    // SAFETY: KTHREAD viva, retida pelo escalonador.
    let kthread = unsafe { Kthread::at(thread) };
    let saved = kthread.kernel_stack.get();
    assert!(saved > kthread.stack_limit.get() && saved < kthread.stack_base.get(), "KernelStack fora da pilha da thread de kernel");
    let carried = carry_out();
    slot.running.store(thread, Ordering::Release);
    // SAFETY: `saved` é o quadro de troca que a thread gravou ao sair (ou o
    // inicial); a célula do despachante vive na reserva estática da CPU.
    unsafe { switch::swap(slot.resumer.as_ptr(), saved) };
    slot.running.store(0, Ordering::Release);
    carry_in(carried);
    SwitchReason::decode(slot.reason.load(Ordering::Acquire))
}

/// O lado de saída da troca: a thread de kernel corrente devolve a CPU ao
/// despachante, com o motivo, e volta quando ele a retomar. O quadro fica na
/// pilha dela e o RSP em KTHREAD.KernelStack; o IRQL vai para
/// KTHREAD.WaitIrql.
pub fn switch_out(reason: SwitchReason) {
    let thread = on_kernel_thread_stack().expect("troca de contexto fora de uma thread de kernel");
    assert!(sync::spin_locks_held() == 0, "thread de kernel deixa a CPU com SpinLock retido");
    let slot = &SWITCH[processor()];
    // SAFETY: a KTHREAD da thread em execução está viva.
    let kthread = unsafe { Kthread::at(thread) };
    let carried = carry_out();
    kthread.wait_irql.set(carried.irql);
    slot.reason.store(reason.encode(), Ordering::Release);
    // SAFETY: a célula é o KernelStack da própria thread; o quadro do
    // despachante foi salvo por `resume` nesta CPU e ainda não retomado.
    unsafe { switch::swap(kthread.kernel_stack.address() as *mut u64, slot.resumer.load(Ordering::Acquire)) };
    carry_in(carried);
}

/// A thread de kernel corrente termina: a última troca, sem volta. O
/// despachante recolhe a pilha dela depois, fora dela.
pub fn exit_kernel_thread() -> ! {
    switch_out(SwitchReason::Exit);
    panic!("thread de kernel terminada foi retomada");
}

/// A thread de kernel corrente cede a vez e continua pronta.
pub fn yield_kernel_thread(retain: bool) {
    switch_out(SwitchReason::Yield { retain });
}

/// Na entrada de um export chamado por código nativo de uma thread de
/// kernel: se o quantum da thread acabou (KTHREAD.CycleTime alcançou o
/// QuantumTarget, como no KiQuantumEnd), em PASSIVE_LEVEL e sem trava
/// retida, ela cede a vez antes do serviço, e o despachante atende as
/// interrupções e as outras threads.
pub fn quantum_end_at_service_entry() {
    let Some(thread) = on_kernel_thread_stack() else { return };
    if thread != process::get_current_thread() || irql::get_irql() != irql::PASSIVE_LEVEL || sync::spin_locks_held() != 0 {
        return;
    }
    // SAFETY: a KTHREAD da thread em execução está viva.
    let kthread = unsafe { Kthread::at(thread) };
    if thread_dispatch::sample_cycles(thread) >= kthread.quantum_target.get() {
        yield_kernel_thread(false);
    }
    // As APCs de kernel pendentes entram ao cair para PASSIVE_LEVEL.
    if super::apc::has_pending(thread) {
        let _ = super::apc::deliver_all_queued();
    }
}

/// Aquisição de um lock do Ex (fast/guarded mutex, ERESOURCE, push lock,
/// rundown): `poll` tenta a palavra do lock e devolve, junto, o evento em
/// que a requisição ficou estacionada (o Event do FAST_MUTEX, o WakeEvent do
/// bloco de espera do push lock e do rundown, o evento do bloco do
/// ERESOURCE). Numa thread de kernel a thread sai das prontas com um bloco
/// de notificação nesse evento (`ke::wait`): o KeSetEvent de quem solta o
/// lock a apronta, e ela confere a palavra de novo ao voltar, como o laço do
/// ExpAcquireFastMutexContended. Fora dela, [`acquire_until`].
pub fn acquire_signaled<T>(mut poll: impl FnMut() -> (Result<Option<T>, KernelError>, Option<u64>), wait_reason: u8, pump: fn()) -> Result<T, KernelError> {
    if !kernel_thread_can_block() {
        return acquire_until(|| poll().0, pump);
    }
    let mut outcome: Option<Result<T, KernelError>> = None;
    loop {
        let (result, watched) = poll();
        if let Some(done) = result.transpose() {
            return done;
        }
        let mut retry = || match poll() {
            (Ok(None), _) => None,
            (done, _) => {
                outcome = done.transpose();
                Some(0)
            }
        };
        match watched {
            Some(event) => {
                super::wait::wait_once(&mut retry, Some(event), super::wait::Deadline::Infinite, 0, false, wait_reason);
            }
            // Sem evento estacionado: a condição fica com o despachante.
            None => {
                scheduler::block_polled(&mut retry);
            }
        }
        if let Some(done) = outcome.take() {
            return done;
        }
    }
}

/// Aquisição (fast mutex, ERESOURCE, push lock, rundown): `poll` conclui com
/// o valor ou com uma falha. Como a espera de um mutex no NT, o término da
/// thread não a interrompe: depois dele a aquisição segue até concluir.
pub fn acquire_until<T>(mut poll: impl FnMut() -> Result<Option<T>, KernelError>, pump: fn()) -> Result<T, KernelError> {
    let mut outcome: Option<Result<T, KernelError>> = None;
    loop {
        wait_until(
            &mut || match poll() {
                Ok(None) => None,
                done => {
                    outcome = done.transpose();
                    Some(0)
                }
            },
            pump,
        );
        if let Some(result) = outcome.take() {
            return result;
        }
    }
}
