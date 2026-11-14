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
//! Moram aqui a tabela de handles de usuário (`handles`, operada por
//! `state.rs`; um processo novo pode herdar os handles inherit do pai,
//! [`inherit_handles`]), o VAD, a raiz das tabelas de páginas (`directory_table_base`,
//! gravada por `mm::process_address_space`), as threads de usuário e o
//! início do laço (`threads`, `started`), os módulos do loader do kernel, a
//! imagem principal e as cópias privadas da ntdll, do apiset e do NLS na
//! raiz própria, e a parte da identidade do processo de usuário que não cabe
//! no EPROCESS (caminho da imagem, PEB_LDR_DATA do kernel, exports das
//! imagens mapeadas); PID, PEB e cookie são do próprio EPROCESS. O resto do
//! estado global de `state.rs` entra aqui à medida que sai de lá.
//!
//! Ciclo de vida: o que o processo possui volta quando ELE termina, nunca
//! num reinício global entre processos. O término (`ps::process::
//! terminate_process`) chama primeiro as rotinas de saída de processo (a de
//! `files::release_user_resources` libera threads, E/S pendente, fábricas de
//! workers, mutantes, instrumentação e canais RPC do processo) e, fora da
//! lista ativa, `destroy`: handles, VAD, módulos, imagens e cópias de
//! sistema, nesta ordem. Daí em diante a metade de usuário da raiz própria
//! só tem a visão da KUSER_SHARED_DATA, e o último dereference do EPROCESS
//! devolve a raiz (`mm::process_address_space::delete`).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::loader::LoadedModule;
use super::memory::{self, Vad};
use super::threads::UserThread;
use crate::ntos::ke::smp;
use crate::ntos::mm::pe_loader::PeImage;
use crate::ntos::mm::process_address_space;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state::{self, UserHandleTable};
use crate::rtl::{KernelError, SpinLock};

/// Exports de uma imagem mapeada (nome → VA de usuário).
pub type Exports = BTreeMap<String, u64>;

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
    /// Caminho DOS da imagem (o ImagePathName dos parâmetros do processo).
    image_path: SpinLock<String>,
    /// A PEB_LDR_DATA montada pelo kernel, onde o loader do kernel insere
    /// as entradas LDR (a PEB.Ldr fica com a da ntdll).
    ldr: AtomicU64,
    /// Imagens nativas mapeadas no processo por NtMapViewOfSection (nome
    /// minúsculo → exports), registradas pela vista de imagem.
    mapped_image_exports: SpinLock<BTreeMap<String, Exports>>,
    /// As threads de usuário do processo, na ordem de criação. O índice
    /// global de `threads.rs` também as tem (despachante e busca por id de
    /// cliente) até cada uma ser liberada.
    pub threads: SpinLock<Vec<Arc<UserThread>>>,
    /// O laço de execução do processo começou: só então ele aceita threads
    /// novas (NtCreateThreadEx, workers de fábrica).
    pub started: AtomicBool,
    /// Módulos que o loader do kernel carregou no processo (nome minúsculo
    /// → módulo e imagem); a ntdll é do sistema e vale em todos sem entrar
    /// aqui.
    modules: SpinLock<BTreeMap<String, LoadedModule>>,
    /// Imagens de usuário que o processo possui fora do loader do kernel e
    /// das seções: a imagem principal (o papel da vista da seção de imagem
    /// no VAD do NT), desfeita na raiz dele no término.
    images: SpinLock<Vec<PeImage>>,
    /// As cópias privadas das faixas de sistema (ntdll, apiset, NLS) na raiz
    /// própria do processo, (VA, frame); vazio na raiz do System.
    system_pages: SpinLock<Vec<(u64, u64)>>,
}

impl ProcessState {
    pub fn image_path(&self) -> String {
        self.image_path.lock().clone()
    }

    pub fn set_image_path(&self, path: &str) {
        *self.image_path.lock() = String::from(path);
    }

    pub fn ldr(&self) -> u64 {
        self.ldr.load(Ordering::Acquire)
    }

    pub fn set_ldr(&self, ldr: u64) {
        self.ldr.store(ldr, Ordering::Release);
    }

    /// Acesso aos exports das imagens mapeadas; a trava não atravessa
    /// chamadas que voltem ao estado.
    pub fn with_mapped_image_exports<R>(&self, body: impl FnOnce(&mut BTreeMap<String, Exports>) -> R) -> R {
        body(&mut self.mapped_image_exports.lock())
    }

    /// Acesso aos módulos do loader do kernel; a trava não atravessa
    /// chamadas que voltem ao estado.
    pub fn with_modules<R>(&self, body: impl FnOnce(&mut BTreeMap<String, LoadedModule>) -> R) -> R {
        body(&mut self.modules.lock())
    }

    /// O processo passa a possuir a imagem (mapeada na raiz dele).
    pub fn adopt_image(&self, image: PeImage) {
        self.images.lock().push(image);
    }

    /// O processo passa a possuir as cópias privadas de sistema.
    pub fn adopt_system_pages(&self, pages: Vec<(u64, u64)>) {
        self.system_pages.lock().extend(pages);
    }

    /// Quantas páginas de cópia de sistema o processo tem.
    pub fn system_page_count(&self) -> usize {
        self.system_pages.lock().len()
    }
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
        image_path: SpinLock::new(String::new()),
        ldr: AtomicU64::new(0),
        mapped_image_exports: SpinLock::new(BTreeMap::new()),
        threads: SpinLock::new(Vec::new()),
        started: AtomicBool::new(false),
        modules: SpinLock::new(BTreeMap::new()),
        images: SpinLock::new(Vec::new()),
        system_pages: SpinLock::new(Vec::new()),
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

/// O estado do processo vivo com o PID `process_id` (os PIDs são únicos na
/// tabela de ids de cliente).
pub fn by_id(process_id: u64) -> Option<Arc<ProcessState>> {
    PROCESSES.lock().values().find(|state| state.process_id == process_id).cloned()
}

/// A herança de handles de um processo novo (o ObInitProcess do
/// PspAllocateProcess com PROCESS_CREATE_FLAGS_INHERIT_HANDLES): os handles
/// de `parent` marcados OBJ_INHERIT entram na tabela de `child` com os
/// mesmos valores (`state::inherit_user_handles`). Um pai que já terminou
/// não tem tabela: STATUS_PROCESS_IS_TERMINATING. Devolve quantos.
pub fn inherit_handles(parent: u64, child: u64) -> Result<usize, KernelError> {
    let parent = get(parent).ok_or_else(|| KernelError::with_status("pai sem tabela de handles", 0xC000_010A))?;
    let child = get(child).ok_or_else(|| KernelError::new("processo novo sem estado"))?;
    state::inherit_user_handles(&parent, &child)
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
/// usuário que restarem na tabela são fechados, o VAD volta inteiro (as
/// regiões do processo, só as dele), depois as imagens dos módulos do
/// loader, a imagem principal e as cópias privadas de sistema, todas
/// desfeitas na raiz do processo. A lista de threads se desfaz; uma thread
/// ainda retida (handle em outro processo, ou a que encerrou o processo de
/// dentro de um serviço) continua no índice global até a liberação dela.
pub fn destroy(process: u64) -> bool {
    let removed = PROCESSES.lock().remove(&process);
    if let Some(removed) = &removed {
        removed.started.store(false, Ordering::Release);
        state::sweep_user_handles(removed);
        memory::release_vad(removed);
        let modules = core::mem::take(&mut *removed.modules.lock());
        drop(modules);
        let images = core::mem::take(&mut *removed.images.lock());
        let released = !images.is_empty();
        for mut image in images {
            if let Err(error) = image.release() {
                crate::debug_print!("[usermode] imagem em {:#x} retida no termino do processo: {}", image.image_base, error);
            }
        }
        if released {
            if let Err(error) = smp::flush_remote_tlb(false) {
                crate::debug_print!("[usermode] TLB das imagens do processo: {}", error);
            }
        }
        let root = removed.directory_table_base.load(Ordering::Acquire);
        memory::release_private_copies(root, core::mem::take(&mut *removed.system_pages.lock()));
        let threads = core::mem::take(&mut *removed.threads.lock());
        drop(threads);
    }
    // O último Arc cai aqui, fora da trava.
    removed.is_some()
}
