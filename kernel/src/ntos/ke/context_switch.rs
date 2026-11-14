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
//!   thread quando ela difere da carregada.
//!
//! Cada CPU registra aqui a raiz que carregou ([`loaded_root`],
//! [`is_root_loaded`]): o Mm não devolve ao PFN uma raiz que alguma CPU
//! esteja usando (`process_address_space::delete`). Só esta troca carrega
//! uma raiz diferente; os outros escritores do CR3 (`cpu::reload_cr3`, a
//! partida dos APs na raiz do System) recarregam a mesma.
//!
//! Sem PCID nem páginas globais, cada troca esvazia a TLB não global da CPU.
//! Os processos de usuário vivos ainda usam a raiz do System, e para eles a
//! troca de thread não muda o CR3.

use core::sync::atomic::{AtomicU64, Ordering};

use super::pcr;
use crate::hal::cpu;
use crate::ntos::inc::types::{Kpcr, Kprocess, NtStruct};
use crate::ntos::mm::memory_map as map;
use crate::ntos::mm::process_address_space::{self, SYSTEM_ROOT};
use crate::rtl::KernelError;

/// Bits do DirectoryTableBase que formam o endereço físico da PML4.
const ROOT_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// A raiz carregada em cada CPU, pelo número do processador. Toda CPU
/// começa na raiz do System (o BSP desde o boot; os APs recebem a mesma na
/// partida).
static LOADED: [AtomicU64; map::MAX_CPUS] = [const { AtomicU64::new(SYSTEM_ROOT) }; map::MAX_CPUS];

/// A KPCR desta CPU (gs:[KPCR.Self]); nenhuma antes da do BSP.
fn current_pcr() -> Option<&'static Kpcr> {
    (pcr::get_pcr_address() != 0).then(pcr::current)
}

/// O número desta CPU (KPRCB.Number); 0 antes da KPCR do BSP.
fn processor() -> usize {
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

/// A troca de thread corrente: carrega a raiz de `process`, o
/// `ApcState.Process` da nova thread. Uma raiz que não é de espaço de
/// endereçamento (EPROCESS corrompido) não é carregada: a CPU fica na raiz
/// do System, que não tem página de usuário de nenhum espaço próprio.
pub fn load_process(process: u64) {
    let root = directory_table_base(process);
    if let Err(error) = load_root(root) {
        debug_print!("[ke] raiz {:#x} do processo {:#x} nao carregada: {}", root, process, error);
        let _ = load_root(SYSTEM_ROOT);
    }
}

/// KiSwapProcess: esta CPU sai de `previous` e entra em `next`. Carrega a
/// raiz de `next` quando ela difere da carregada e move o bit da CPU (grupo
/// e número da KPRCB) de KPROCESS.ActiveProcessors de `previous` para
/// `next`. Os dois processos estão retidos pelo chamador.
pub fn swap_process(previous: u64, next: u64) -> Result<(), KernelError> {
    load_root(directory_table_base(next))?;
    let Some(kpcr) = current_pcr() else { return Ok(()) };
    let group = kpcr.prcb.group.get() as usize;
    let bit = 1u64 << kpcr.prcb.group_index.get();
    for (process, active) in [(next, true), (previous, false)] {
        if process == 0 {
            continue;
        }
        // SAFETY: processo retido pelo chamador.
        let mask = unsafe { Kprocess::at(process) }.active_processors.bitmap[group].atomic();
        if active {
            mask.fetch_or(bit, Ordering::SeqCst);
        } else {
            mask.fetch_and(!bit, Ordering::SeqCst);
        }
    }
    Ok(())
}
