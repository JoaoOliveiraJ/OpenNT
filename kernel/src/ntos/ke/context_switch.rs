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
//! `hal::amd64::context_switch`): uma thread de usuário que espera dentro de
//! uma syscall ([`can_block`]) deixa a CPU ([`block_current`]) em vez de
//! girar o `pump_kernel`, e o despachante de `ps/user/threads.rs` roda as
//! outras; quando a espera, sondada por ele no contexto da thread, conclui,
//! ele a retoma na própria pilha ([`switch_to`]). As esperas do Ke e do Ex
//! (KeWaitForSingleObject/Multiple, KeDelayExecutionThread, alertáveis ou
//! não, fast mutex, ERESOURCE, push locks, rundown) passam por
//! [`wait_until`]/[`acquire_until`]; fora de uma syscall (boot, threads de
//! sistema, APCs e conclusões drenadas na pilha do despachante) continuam
//! girando o pump. Como no NT, esperar de fato com prazo não nulo em
//! DISPATCH_LEVEL ou acima, ou com um SpinLock retido, para o sistema.

use alloc::boxed::Box;
use core::panic::Location;
use core::sync::atomic::{AtomicU64, Ordering};

use super::{irql, pcr, thread_dispatch};
use crate::hal::amd64::usermode;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kpcr, Kprocess, Kthread, NtStruct};
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::process_address_space::{self, SYSTEM_ROOT};
use crate::ntos::ps::process;
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
/// condição ainda não vale, bloqueia quando pode e, senão, gira `pump`
/// entre sondagens. Uma thread terminada enquanto bloqueada recebe
/// [`STATUS_THREAD_IS_TERMINATING`].
pub fn wait_until(poll: &mut dyn FnMut() -> Option<u32>, pump: fn()) -> u32 {
    if let Some(status) = poll() {
        return status;
    }
    assert_wait_allowed();
    loop {
        if can_block() {
            return block_current(poll);
        }
        pump();
        if let Some(status) = poll() {
            return status;
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
