//! Espaços de sessão (MM_SESSION_SPACE).
//!
//! O papel do MiSessionCreate e do MiSessionAddProcess/MiSessionRemoveProcess
//! do NT, no que os processos de usuário enxergam:
//!
//! - [`create`]: um processo criado com PROCESS_CREATE_FLAGS_CREATE_SESSION
//!   (o MiMapProcessExecutable chama o MiSessionCreate) ganha uma sessão
//!   nova, com o menor id livre (o RtlFindClearBitsAndSet sobre o bitmap de
//!   ids do NT), e é o primeiro processo dela;
//! - [`join`]: os demais processos entram na sessão do pai;
//! - [`leave`]: no PspProcessDelete o processo sai da lista da sessão; a
//!   sessão sem processos devolve o id e a memória.
//!
//! O EPROCESS.Session aponta para o MM_SESSION_SPACE e os processos ficam
//! na ProcessList dela pelo EPROCESS.SessionProcessLinks, como no NT; o
//! `ps::session::query` (PsGetProcessSessionId) lê o SessionId de lá. Ainda
//! não existem aqui o espaço virtual de sessão (o pool e as imagens de
//! sessão) nem o objeto Session do MiSessionObjectCreate: um processo sem
//! sessão (Session NULL) continua na sessão 0.

use alloc::collections::BTreeSet;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, ListEntry, MmSessionSpace};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// Os ids de sessão em uso.
static SESSION_IDS: SpinLock<BTreeSet<u32>> = SpinLock::new(BTreeSet::new());

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (em criação ou no PspProcessDelete).
    unsafe { Eprocess::at(process) }
}

fn space(pointer: u64) -> &'static MmSessionSpace {
    // SAFETY: MM_SESSION_SPACE alocado por `create` e vivo enquanto houver
    // processo na lista.
    unsafe { MmSessionSpace::at(pointer) }
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let last = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(last);
    // SAFETY: o último elemento da lista (ou a própria cabeça).
    unsafe { ListEntry::at(last) }.flink.set(entry.address());
    head.blink.set(entry.address());
}

fn remove_entry(entry: &ListEntry) {
    let (next, previous) = (entry.flink.get(), entry.blink.get());
    if next == 0 || previous == 0 {
        return;
    }
    // SAFETY: vizinhos na mesma lista.
    unsafe { ListEntry::at(previous) }.flink.set(next);
    // SAFETY: idem.
    unsafe { ListEntry::at(next) }.blink.set(previous);
    entry.flink.set(0);
    entry.blink.set(0);
}

/// Põe `process` na sessão `pointer` (MiSessionAddProcess).
fn add(process: u64, pointer: u64) {
    let session = space(pointer);
    let object = eprocess(process);
    insert_tail(&session.process_list, &object.session_process_links);
    session.process_reference_to_session.set(session.process_reference_to_session.get() + 1);
    session.reference_count.set(session.reference_count.get() + 1);
    object.session.set(pointer);
}

/// MiSessionCreate: uma sessão nova para `process`, com o menor id livre.
/// Devolve o id.
pub fn create(process: u64) -> Result<u32, KernelError> {
    let id = {
        let mut ids = SESSION_IDS.lock();
        let id = (0..).find(|candidate| !ids.contains(candidate)).unwrap_or(0);
        ids.insert(id);
        id
    };
    let pointer = guest::alloc_bytes(MmSessionSpace::SIZE);
    if pointer == 0 {
        SESSION_IDS.lock().remove(&id);
        return Err(KernelError::with_status("sem memoria para o MM_SESSION_SPACE", 0xC000_0017));
    }
    let session = space(pointer);
    session.session_id.set(id);
    session.process_list.flink.set(session.process_list.address());
    session.process_list.blink.set(session.process_list.address());
    add(process, pointer);
    crate::debug_print!("[mm] sessao {} criada para o processo {:#x}", id, process);
    Ok(id)
}

/// O processo novo entra na sessão de `parent` (nenhuma, se o pai não tem).
pub fn join(process: u64, parent: u64) {
    let pointer = if parent == 0 { 0 } else { eprocess(parent).session.get() };
    if pointer != 0 {
        add(process, pointer);
    }
}

/// PspProcessDelete: `process` sai da sessão; a última saída devolve o id e
/// a memória (MiDereferenceSession).
pub fn leave(process: u64) {
    let object = eprocess(process);
    let pointer = object.session.get();
    if pointer == 0 {
        return;
    }
    let session = space(pointer);
    remove_entry(&object.session_process_links);
    object.session.set(0);
    session.process_reference_to_session.set(session.process_reference_to_session.get() - 1);
    let references = session.reference_count.get() - 1;
    session.reference_count.set(references);
    if references == 0 {
        let id = session.session_id.get();
        guest::free_bytes(pointer);
        SESSION_IDS.lock().remove(&id);
        crate::debug_print!("[mm] sessao {} encerrada", id);
    }
}
