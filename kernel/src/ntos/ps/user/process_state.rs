//! Estado de modo usuário por processo.
//!
//! No NT, o que um processo tem de próprio mora no EPROCESS (ObjectTable,
//! VadRoot, Peb...). O OpenNT guarda a parte que ainda não tem forma de
//! estrutura do NT num `ProcessState`, num registro indexado pelo endereço do
//! EPROCESS.
//!
//! Contrato:
//! - todo EPROCESS vivo tem exatamente um estado, inclusive o System e os
//!   processos de kernel do escalonador: `ps::process::create_process` cria o
//!   estado antes de pôr o processo em PsActiveProcessHead, e
//!   `ps::process::terminate_process` o destrói depois de tirá-lo de lá. Daí
//!   todo processo da lista ativa ter estado a qualquer momento;
//! - o estado some no término, não no último dereference: um EPROCESS ainda
//!   retido por referência ou handle não tem mais estado, como a ObjectTable
//!   NULL de um processo que já passou pelo rundown de handles;
//! - o processo corrente é `KTHREAD.ApcState.Process` (`process::
//!   get_current_process`), então `current` segue o processo anexado.
//!
//! Travas: `PROCESSES` nunca fica retida numa chamada que volte ao registro;
//! um estado destruído é liberado fora dela. Ordem: `PROCESSES` antes do
//! `vad` de um estado.
//!
//! Já mora aqui a tabela de handles de usuário (`handles`, operada por
//! `state.rs`) e a raiz das tabelas de páginas (`directory_table_base`,
//! gravada por `mm::process_address_space`); o resto do estado global de
//! `state.rs` continua valendo para o
//! processo de usuário em execução, e os campos entram aqui à medida que saem
//! de lá.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

use super::memory::{self, Vad};
use crate::ntos::mm::process_address_space;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state::{self, UserHandleTable};
use crate::rtl::{KernelError, SpinLock};

/// O estado de um processo.
pub struct ProcessState {
    /// O EPROCESS dono (a chave do registro).
    pub process: u64,
    /// EPROCESS.UniqueProcessId na criação.
    pub process_id: u64,
    /// A tabela de handles de usuário (o papel da ObjectTable).
    pub handles: SpinLock<UserHandleTable>,
    /// As regiões de usuário do processo (o papel do EPROCESS.VadRoot).
    pub vad: SpinLock<Vad>,
    /// A raiz das tabelas de páginas, a mesma de KPROCESS.DirectoryTableBase:
    /// a do System até `mm::process_address_space::create` dar ao processo
    /// uma própria.
    pub directory_table_base: AtomicU64,
}

static PROCESSES: SpinLock<BTreeMap<u64, Arc<ProcessState>>> = SpinLock::new(BTreeMap::new());

/// Cria o estado do EPROCESS `process`. Um estado que já existe para o mesmo
/// endereço é recusado: seria de um processo que não passou pelo término.
pub fn create(process: u64, process_id: u64) -> Result<Arc<ProcessState>, KernelError> {
    if process == 0 {
        return Err(KernelError::new("estado de processo sem EPROCESS"));
    }
    let state = Arc::new(ProcessState {
        process,
        process_id,
        handles: SpinLock::new(UserHandleTable::new()),
        vad: SpinLock::new(Vad::default()),
        directory_table_base: AtomicU64::new(process_address_space::SYSTEM_ROOT),
    });
    let mut processes = PROCESSES.lock();
    if processes.contains_key(&process) {
        return Err(KernelError::new(format!("EPROCESS {process:#x} ja tem estado")));
    }
    processes.insert(process, state.clone());
    Ok(state)
}

/// O estado do EPROCESS `process`, se ele estiver vivo.
pub fn get(process: u64) -> Option<Arc<ProcessState>> {
    PROCESSES.lock().get(&process).cloned()
}

/// O estado do processo corrente (o anexado, quando há attach). `None`
/// antes do Ps criar o System ou depois do término do processo corrente.
pub fn current() -> Option<Arc<ProcessState>> {
    get(process::get_current_process())
}

/// Os estados vivos (o System inclusive), em ordem de EPROCESS.
pub fn all() -> Vec<Arc<ProcessState>> {
    PROCESSES.lock().values().cloned().collect()
}

/// Destrói o estado do EPROCESS `process`; um segundo término não acha
/// nada. Devolve se havia estado. Fora da trava, na ordem do término do NT
/// (rundown de handles antes do espaço de endereçamento): os handles de
/// usuário que restarem na tabela são fechados e o VAD volta inteiro (as
/// regiões do processo, só as dele).
pub fn destroy(process: u64) -> bool {
    let removed = PROCESSES.lock().remove(&process);
    if let Some(removed) = &removed {
        state::sweep_user_handles(removed);
        memory::release_vad(removed);
    }
    // O último Arc cai aqui, fora da trava.
    removed.is_some()
}
