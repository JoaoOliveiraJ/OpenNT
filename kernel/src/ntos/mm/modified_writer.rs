//! As listas de páginas modificadas e de reserva das alocações privadas e
//! o modified page writer do ntoskrnl 19041 (MiModifiedPageWriter, a
//! thread de sistema que o MiInsertPageFileInList cria com o primeiro
//! arquivo de paginação):
//!
//! - Lista de modificadas (ModifiedPageListHead): páginas em transição cujo
//!   conteúdo não está no arquivo de paginação. O writer junta até 16 delas
//!   num espaço contíguo do arquivo (MiGatherPagefilePages e
//!   MiFindPageFileWriteCluster), grava o cluster por um IRP de paginação
//!   (`paging_file::write`) e as passa para a lista de reserva, agora com a
//!   cópia; a PTE continua de transição.
//! - Lista de reserva (StandbyPageListHead): páginas em transição com
//!   cópia. Reaproveitar uma delas (o MiRemoveAnyPage/MiUnlinkPageFromList
//!   de uma alocação) troca a PTE de transição pela PTE de arquivo de
//!   paginação e devolve o frame ao PFN.
//!
//! Cada passo confere, com a região travada, que a página ainda está no
//! mesmo estado e no mesmo frame (o papel das conferências do PFN do NT):
//! uma falta de transição, uma liberação ou o término do processo no meio
//! do caminho tiram a página da lista. Uma região retida por uma operação
//! em curso (`PrivateRegion::busy`) não perde frames. Com o arquivo cheio,
//! as cópias que páginas residentes limpas ainda guardam nele voltam ao
//! espaço livre antes de o writer desistir.
//!
//! A thread espera o ModifiedPageWriterEvent, que o corte sinaliza quando
//! não pode gravar no próprio contexto; o alocador que espera por memória
//! livre grava no próprio contexto (o OpenNT não tem a espera do
//! MiWaitForFreePage). Um evento de sincronização serializa os dois
//! escritores. A escrita do NT é assíncrona (IoAsynchronousPageWrite com o
//! MiWriteComplete); aqui ela é síncrona, um cluster por vez.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::paging;
use super::paging_file::{self, extend, Slot, MAXIMUM_WRITE_CLUSTER};
use super::pfn;
use super::working_set::{self, ListedPage, COUNTERS};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Kevent;
use crate::ntos::ke::{context_switch, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// A prioridade da thread do MiModifiedPageWriter no 19041.
const WRITER_PRIORITY: u64 = 18;

static MODIFIED: SpinLock<VecDeque<ListedPage>> = SpinLock::new(VecDeque::new());
static STANDBY: SpinLock<VecDeque<ListedPage>> = SpinLock::new(VecDeque::new());
/// ModifiedPageWriterEvent (sincronização).
static WORK_EVENT: AtomicU64 = AtomicU64::new(0);
/// O direito de gravar (evento de sincronização sinalizado = livre).
static WRITER_LOCK: AtomicU64 = AtomicU64::new(0);
static STARTED: AtomicBool = AtomicBool::new(false);
/// Uma escrita falhou (registrado uma vez).
static WRITE_FAILED: AtomicBool = AtomicBool::new(false);
/// O arquivo de paginação encheu (registrado uma vez).
static NO_SPACE: AtomicBool = AtomicBool::new(false);
/// O ETHREAD do writer.
static THREAD: AtomicU64 = AtomicU64::new(0);

pub fn insert_modified(page: ListedPage) {
    MODIFIED.lock().push_back(page);
}

pub fn insert_standby(page: ListedPage) {
    STANDBY.lock().push_back(page);
}

/// Tamanhos das listas: (modificadas, reserva).
pub fn list_sizes() -> (usize, usize) {
    (MODIFIED.lock().len(), STANDBY.lock().len())
}

/// O ETHREAD do MiModifiedPageWriter (0 antes do primeiro arquivo).
pub fn thread() -> u64 {
    THREAD.load(Ordering::Acquire)
}

/// Os eventos e a thread do writer, uma vez; instala o provedor do working
/// set.
pub fn start() {
    if STARTED.swap(true, Ordering::AcqRel) {
        return;
    }
    let work = guest::alloc_bytes(Kevent::SIZE);
    let lock = guest::alloc_bytes(Kevent::SIZE);
    if work == 0 || lock == 0 {
        crate::debug_print!("[mm] eventos do modified page writer sem memoria");
        return;
    }
    dispatcher::initialize_event(work, 1, false);
    dispatcher::initialize_event(lock, 1, true);
    WORK_EVENT.store(work, Ordering::Release);
    WRITER_LOCK.store(lock, Ordering::Release);
    working_set::install();
    let entry: extern "win64" fn(u64) = modified_page_writer;
    let started = crate::ntos::mm::kernel_address::image_address(entry as usize as u64).and_then(|start| crate::ntos::ps::kernel_threads::create_system_thread(0, start, 0, 0x1F_FFFF, 0, None));
    match started {
        Ok(handle) => {
            THREAD.store(crate::ntos::ps::kernel_threads::of_handle(handle).unwrap_or(0), Ordering::Release);
            let _ = crate::ntos::ob::object_manager::close(handle as u32);
        }
        Err(error) => crate::debug_print!("[mm] thread do modified page writer nao criada: {}", error),
    }
}

/// Sinaliza o ModifiedPageWriterEvent.
pub fn wake() {
    let event = WORK_EVENT.load(Ordering::Acquire);
    if event != 0 && !MODIFIED.lock().is_empty() {
        dispatcher::set_event(event);
    }
}

/// MiModifiedPageWriter: espera trabalho e grava a lista de modificadas
/// inteira. O 19041 põe a thread em prioridade de tempo real 18
/// (KeSetActualBasePriorityThread); aqui pelo KeSetPriorityThread, que dá a
/// mesma prioridade efetiva.
extern "win64" fn modified_page_writer(_context: u64) {
    let _ = crate::ntos::ke::thread_priority::set_priority(crate::ntos::ps::process::get_current_thread(), WRITER_PRIORITY);
    loop {
        dispatcher::wait_for_single_object(WORK_EVENT.load(Ordering::Acquire), 0, 0, false);
        while write_modified(MAXIMUM_WRITE_CLUSTER as u64 * 8) > 0 {}
    }
}

/// O direito de gravar: espera se o contexto pode bloquear.
fn acquire_writer() -> bool {
    let lock = WRITER_LOCK.load(Ordering::Acquire);
    if lock == 0 {
        return false;
    }
    if dispatcher::try_wait_objects(&[lock], 1).is_some() {
        return true;
    }
    context_switch::kernel_thread_can_block() && dispatcher::wait_for_single_object(lock, 0, 0, false) == 0
}

fn release_writer() {
    dispatcher::set_event(WRITER_LOCK.load(Ordering::Acquire));
}

/// A página continua em transição no mesmo frame, sem cópia (`modified`)
/// ou com ela.
/// Abaixo disto de frames livres, o writer grava uma página por vez.
const SMALL_CLUSTER_FRAMES: u64 = 4;

fn still_listed(page: &ListedPage, modified: bool) -> bool {
    let Some(owner) = page.owner() else { return false };
    let state = owner.state.lock();
    state.frames.get(&page.index) == Some(&page.frame) && state.paging.get(&page.index).is_some_and(|paged| paged.transition && paged.slot.is_none() == modified)
}

/// Grava até `limit` páginas da lista de modificadas, em clusters; devolve
/// quantas foram gravadas. Sem espaço nos arquivos, pede a extensão deles
/// (MiPageFileNoFreeSpace) e, se o contexto pode esperar, espera o pedido
/// e continua gravando no espaço novo.
pub fn write_modified(limit: u64) -> u64 {
    let mut written = 0;
    loop {
        let (count, no_space) = write_clusters(limit - written);
        written += count;
        if !no_space || written >= limit || !extend::wait_for_attempt() {
            return written;
        }
    }
}

/// Uma passada do writer: (páginas gravadas, os arquivos ficaram sem
/// espaço).
fn write_clusters(limit: u64) -> (u64, bool) {
    if !acquire_writer() {
        return (0, false);
    }
    let mut written = 0;
    let mut no_space = false;
    while written < limit {
        // Sem frames livres, uma página por escrita: o MDL dela usa o mapa
        // direto, e a de várias páginas mapearia o cluster em PTEs de
        // sistema, que podem pedir uma tabela nova sem frame para ela (a
        // escrita falhava com STATUS_INSUFFICIENT_RESOURCES e a memória não
        // andava). O writer do 19041 tem MDLs e PTEs reservados para nunca
        // depender de memória nova.
        let cluster_limit = if pfn::free_count() < SMALL_CLUSTER_FRAMES { 1 } else { MAXIMUM_WRITE_CLUSTER };
        let mut cluster: Vec<ListedPage> = Vec::new();
        while cluster.len() < cluster_limit {
            let Some(page) = MODIFIED.lock().pop_front() else { break };
            if still_listed(&page, true) {
                cluster.push(page);
            }
        }
        if cluster.is_empty() {
            break;
        }
        // Sem espaço, as cópias das páginas residentes limpas saem do
        // arquivo antes de desistir.
        let space = paging_file::allocate(cluster.len() as u64).or_else(|| (working_set::release_clean_copies() > 0).then(|| paging_file::allocate(cluster.len() as u64)).flatten());
        let Some((first, count)) = space else {
            // Sem espaço: as páginas ficam em transição na lista, e os
            // arquivos podem crescer.
            let waiting = {
                let mut list = MODIFIED.lock();
                for page in cluster.into_iter().rev() {
                    list.push_front(page);
                }
                list.len() as u64
            };
            if !NO_SPACE.swap(true, Ordering::Relaxed) {
                let commitment = super::commit::snapshot();
                crate::debug_print!("[mm] arquivo de paginacao sem espaco para o modified page writer: {} paginas esperando, commit {} de {} (maximo {})", waiting, commitment.committed, commitment.limit, commitment.limit_maximum);
            }
            extend::page_file_no_free_space(waiting);
            no_space = true;
            break;
        };
        let rest: Vec<ListedPage> = cluster.split_off(count as usize);
        if !rest.is_empty() {
            let mut list = MODIFIED.lock();
            for page in rest.into_iter().rev() {
                list.push_front(page);
            }
        }
        let frames: Vec<u64> = cluster.iter().map(|page| page.frame).collect();
        let status = paging_file::write(first, &frames);
        COUNTERS.dirty_write_ios.fetch_add(1, Ordering::Relaxed);
        if status & 0x8000_0000 != 0 && !WRITE_FAILED.swap(true, Ordering::Relaxed) {
            crate::debug_print!("[mm] escrita no arquivo de paginacao {} pagina {:#x} ({} paginas) -> {:#x}", first.file, first.offset, count, status);
        }
        if status & 0x8000_0000 != 0 {
            // A escrita falhou (sem recurso para o MDL ou o pedido, sob
            // pressão de memória): as páginas voltam à lista de modificadas
            // para uma escrita seguinte, como no MiWriteComplete do 19041, e
            // os slots voltam ao arquivo. Fora de toda lista, uma página em
            // transição sem slot nunca mais seria gravada nem reaproveitada,
            // e o frame dela ficaria preso. A rodada para aqui.
            let mut list = MODIFIED.lock();
            for (position, page) in cluster.into_iter().enumerate().rev() {
                paging_file::release(Slot { file: first.file, offset: first.offset + position as u64 });
                list.push_front(page);
            }
            break;
        }
        for (position, page) in cluster.into_iter().enumerate() {
            let slot = Slot { file: first.file, offset: first.offset + position as u64 };
            let recorded = status & 0x8000_0000 == 0 && page.owner().is_some_and(|owner| {
                let mut state = owner.state.lock();
                let current = state.frames.get(&page.index) == Some(&page.frame);
                match state.paging.get_mut(&page.index) {
                    Some(paged) if current && paged.transition && paged.slot.is_none() => {
                        paged.slot = Some(slot);
                        true
                    }
                    _ => false,
                }
            });
            if recorded {
                COUNTERS.dirty_pages_written.fetch_add(1, Ordering::Relaxed);
                insert_standby(page);
            } else {
                paging_file::release(slot);
            }
        }
        written += count;
    }
    release_writer();
    (written, no_space)
}

/// Reaproveita até `goal` páginas de reserva: a PTE vira de arquivo de
/// paginação e o frame volta ao PFN. Devolve quantos frames voltaram.
pub fn repurpose(goal: u64) -> u64 {
    let mut freed = 0;
    let mut deferred: Vec<ListedPage> = Vec::new();
    while freed < goal {
        let Some(page) = STANDBY.lock().pop_front() else { break };
        let Some(owner) = page.owner() else { continue };
        let va = page.va();
        let mut state = owner.state.lock();
        let current = state.frames.get(&page.index) == Some(&page.frame);
        let slot = match state.paging.get(&page.index) {
            Some(paged) if current && paged.transition => paged.slot,
            _ => continue,
        };
        let Some(slot) = slot else { continue };
        if state.busy != 0 {
            // Uma operação em curso vai trazê-la de volta ou liberá-la.
            drop(state);
            deferred.push(page);
            continue;
        }
        let protection = working_set::page_protection(owner, &state, page.index);
        if !paging::write_leaf_in(page.root, va, working_set::page_file_pte(slot, protection)) {
            continue;
        }
        if let Some(paged) = state.paging.get_mut(&page.index) {
            paged.transition = false;
        }
        state.frames.remove(&page.index);
        state.protected_frames.remove(&page.index);
        drop(state);
        if pfn::free_page(page.frame) {
            freed += 1;
        } else {
            crate::debug_print!("[mm] frame {:#x} da reserva ainda referenciado", page.frame);
        }
    }
    if !deferred.is_empty() {
        let mut list = STANDBY.lock();
        list.extend(deferred);
    }
    freed
}
