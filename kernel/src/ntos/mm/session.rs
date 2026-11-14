//! Espaços de sessão (MM_SESSION_SPACE) e o espaço virtual de sessão.
//!
//! O papel do MiSessionCreate/MiSessionCreateInternal, do
//! MiSessionAddProcess/MiJoinSession e do MiDereferenceSessionFinal do
//! Windows 10 19041:
//!
//! - **Espaço de sessão.** O slot de sessão da PML4
//!   (`memory_map::SESSION_SPACE_PML4_INDEX`) não é compartilhado: cada sessão
//!   tem a própria tabela de topo (a PDPT do slot; o PFN dela é o
//!   MM_SESSION_SPACE.SessionPageDirectoryIndex e a entrada da PML4 que a
//!   aponta é o PageDirectory), e a raiz de cada processo da sessão recebe
//!   essa entrada (`paging::set_session_top_level`). Trocar de raiz, na troca
//!   de thread ou no attach, troca o espaço de sessão junto, sem nenhum passo
//!   a mais; a raiz do System e a dos processos sem sessão deixam o slot
//!   vazio, e uma VA de sessão tocada fora de uma sessão falta, como no NT.
//! - **Criação** ([`create`], PROCESS_CREATE_FLAGS_CREATE_SESSION): o menor
//!   id livre (o RtlFindClearBitsAndSet sobre o bitmap de ids), a tabela de
//!   topo, as 5 páginas do MM_SESSION_SPACE em SessionCore (a mesma VA em toda
//!   sessão) e a primeira delas também numa VA global de sistema (o
//!   MiReservePtes de uma PTE), que vai para o EPROCESS.Session: os campos da
//!   primeira página (id, contagens, lista de processos) são lidos de
//!   qualquer contexto; o PoolTags (+0x1000) só dentro da sessão. O processo
//!   que cria é o mestre (MiMarkSessionMasterProcess: Vm.Flags.SessionMaster)
//!   e todo processo da sessão tem EPROCESS.Flags.ProcessInSession.
//! - [`join`]: os demais processos entram na sessão de quem os cria
//!   (MiJoinSession: só se o criador não é processo de sistema e a sessão
//!   ainda tem referências), com a tabela de topo ligada na raiz deles.
//! - [`leave`]: no PspProcessDelete o processo sai da lista e a tabela de
//!   topo sai da raiz dele (MiDeleteTopLevelSessionMapping); a última saída
//!   (MiDereferenceSessionFinal) descarrega as imagens de sessão, devolve o
//!   pool de sessão, desfaz todo o espaço de sessão e devolve o id.
//! - [`attach`]/[`detach`] (MmAttachSession/MmDetachSession) anexam a thread
//!   a um processo da sessão (KiStackAttachProcess), contando AttachCount;
//!   [`by_id`] (MmGetSessionById) devolve um processo referenciado da sessão
//!   para isso.
//!
//! As páginas de sessão são editadas por uma raiz de edição da sessão (uma
//! PML4 com a metade de sistema e só esta sessão no slot, nunca carregada):
//! as tabelas abaixo da tabela de topo são as mesmas em todas as raízes da
//! sessão, então uma edição por ela vale em todos os processos da sessão, e
//! o Mm mapeia e desfaz páginas de sessão sem anexar a ninguém. Desfazer uma
//! página de sessão invalida a TLB em todas as CPUs antes de o frame voltar.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{memory_map as map, paging, pfn, process_address_space};
use crate::hal::physical;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DriverObject, Eprocess, ListEntry, MmSessionSpace};
use crate::ntos::ke::{clock, process_attachment, smp};
use crate::ntos::ps::{locale, process};
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = 0x1000;
/// O MM_SESSION_SPACE ocupa 0x5000 bytes em SessionCore.
const CORE_PAGES: usize = 5;
/// MiSessionCreateInternal: NonPagablePages = CommittedPages = 8 (a tabela de
/// topo, a PD e a PT de SessionCore e as 5 páginas do MM_SESSION_SPACE).
const CREATE_PAGES: u64 = 8;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
/// PTE de supervisor RW, sem o bit Global: cada sessão tem as próprias
/// traduções, descartadas na troca de raiz.
const SESSION_PTE: u64 = paging::PAGE_PRESENT | paging::PAGE_RW;
/// MMSUPPORT_FLAGS.CommitReleaseState == 2 (o espaço já está sendo desfeito).
const COMMIT_RELEASE_DELETING: u8 = 2;

/// O que o Mm do OpenNT guarda de cada sessão viva.
struct Session {
    id: u32,
    /// A tabela de topo do slot de sessão (frame).
    top_level: u64,
    /// A raiz de edição da sessão (nunca carregada).
    edit_root: u64,
    /// Os frames do MM_SESSION_SPACE em SessionCore.
    core: [u64; CORE_PAGES],
    /// VA dinâmica (o pool paginado de sessão): o topo já usado e as faixas
    /// devolvidas abaixo dele.
    dynamic_next: u64,
    dynamic_free: Vec<(u64, u64)>,
}

/// Sessões vivas, pela VA global do MM_SESSION_SPACE (o EPROCESS.Session).
/// A trava também protege a ProcessList e as contagens de cada sessão (o
/// papel da trava de sessões do MiSessionAddProcess/MmAttachSession).
static SESSIONS: SpinLock<BTreeMap<u64, Session>> = SpinLock::new(BTreeMap::new());
/// Os ids em uso (o bitmap MiVisibleState.SessionIdBitmap).
static SESSION_IDS: SpinLock<BTreeSet<u32>> = SpinLock::new(BTreeSet::new());
/// As VAs globais em uso na janela `SESSION_GLOBAL_BASE..TOP`.
static GLOBAL_PAGES: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (em criação, retido ou no PspProcessDelete).
    unsafe { Eprocess::at(process) }
}

/// O MM_SESSION_SPACE pela VA global: só a primeira página (os campos abaixo
/// de 0x1000) está mapeada ali.
fn space(pointer: u64) -> &'static MmSessionSpace {
    // SAFETY: VA global de uma sessão viva (`SESSIONS`).
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

// ---- consultas (MmIsSessionAddress, MmGetSessionId...) ----------------------

/// MmIsSessionAddress: VA de sistema no slot do tipo MiVaSessionSpace.
pub fn is_session_address(va: u64) -> bool {
    map::is_session_address(va)
}

/// MmGetSessionIdEx: o SessionId do MM_SESSION_SPACE; (ULONG)-1 sem sessão ou
/// para um processo de sistema (Flags3.SystemProcess).
pub fn session_id_ex(process: u64) -> u32 {
    let object = eprocess(process);
    let pointer = object.session.get();
    if pointer == 0 || object.system_process() != 0 {
        return u32::MAX;
    }
    space(pointer).session_id.get()
}

/// MmGetSessionId: o mesmo, com o -1 virando 0.
pub fn session_id(process: u64) -> u32 {
    match session_id_ex(process) {
        u32::MAX => 0,
        id => id,
    }
}

/// MiGetSessionIdForVa: a sessão do processo corrente para uma VA de
/// usuário ou de sessão; -1 para as demais VAs de sistema.
pub fn session_id_for_va(va: u64) -> u32 {
    if va < 0xFFFF_8000_0000_0000 || is_session_address(va) { session_id_ex(process::get_current_process()) } else { u32::MAX }
}

/// A sessão (VA global) do processo corrente, o anexado durante um attach;
/// 0 fora de uma sessão ou num processo de sistema.
pub fn current() -> u64 {
    let object = eprocess(process::get_current_process());
    if object.system_process() != 0 { 0 } else { object.session.get() }
}

/// A sessão (VA global) de um processo.
pub fn of_process(process: u64) -> u64 {
    eprocess(process).session.get()
}

/// O id de uma sessão viva.
pub fn id_of(session: u64) -> Option<u32> {
    SESSIONS.lock().get(&session).map(|state| state.id)
}

/// Quantas sessões vivas.
pub fn count() -> usize {
    SESSIONS.lock().len()
}

/// A tabela de topo da sessão (frame) e a raiz de edição dela.
pub fn tables(session: u64) -> Option<(u64, u64)> {
    SESSIONS.lock().get(&session).map(|state| (state.top_level, state.edit_root))
}

// ---- edição do espaço de sessão ---------------------------------------------

/// Mapeia `frame` na VA de sessão `va` da sessão `session`, pela raiz de
/// edição (vale em todos os processos dela).
pub fn map_page(session: u64, va: u64, frame: u64, writable: bool, executable: bool) -> Result<(), KernelError> {
    let Some((_, root)) = tables(session) else { return Err(KernelError::new("mapping in a session that no longer exists")) };
    if !is_session_address(va) {
        return Err(KernelError::new("session mapping outside session space"));
    }
    let flags = paging::PAGE_PRESENT | if writable { paging::PAGE_RW } else { 0 };
    if !paging::map_page_in(root, va, frame, flags, paging::MapOptions { nx: !executable, ..Default::default() }) {
        return Err(KernelError::with_status("no page table for a session page", STATUS_NO_MEMORY));
    }
    Ok(())
}

/// O frame mapeado na VA de sessão `va` da sessão `session` (0 sem página).
pub fn translate(session: u64, va: u64) -> u64 {
    tables(session).map_or(0, |(_, root)| paging::translate_in(root, va))
}

/// Desfaz as páginas de sessão `pages` da sessão `session` e invalida a TLB
/// em todas as CPUs; só depois disso os frames podem voltar ao PFN (o
/// chamador os devolve). As tabelas que ficarem vazias voltam junto.
pub fn unmap_pages(session: u64, pages: &[u64]) -> Result<(), KernelError> {
    let Some((_, root)) = tables(session) else { return Err(KernelError::new("unmapping in a session that no longer exists")) };
    let mut retired = Vec::new();
    for &va in pages {
        paging::unmap_page_in(root, va, paging::MapOptions { deferred_tables: Some(&mut retired), ..Default::default() });
    }
    smp::flush_remote_tlb(false)?;
    crate::hal::cpu::reload_cr3();
    for frame in retired {
        pfn::free_page(frame);
    }
    Ok(())
}

/// Reserva `size` bytes (múltiplo da página) de VA dinâmica da sessão.
pub fn reserve_dynamic(session: u64, size: u64) -> Option<u64> {
    let mut sessions = SESSIONS.lock();
    let state = sessions.get_mut(&session)?;
    if let Some(index) = state.dynamic_free.iter().position(|&(_, length)| length >= size) {
        let base = state.dynamic_free[index].0;
        state.dynamic_free[index].0 += size;
        state.dynamic_free[index].1 -= size;
        if state.dynamic_free[index].1 == 0 {
            state.dynamic_free.remove(index);
        }
        return Some(base);
    }
    let base = state.dynamic_next;
    if map::SESSION_DYNAMIC_VA_TOP - base < size {
        return None;
    }
    state.dynamic_next = base + size;
    Some(base)
}

/// Devolve uma faixa de [`reserve_dynamic`] (já desfeita).
pub fn release_dynamic(session: u64, base: u64, size: u64) {
    let mut sessions = SESSIONS.lock();
    let Some(state) = sessions.get_mut(&session) else { return };
    let free = &mut state.dynamic_free;
    free.push((base, size));
    free.sort_unstable();
    let mut index = 0;
    while index + 1 < free.len() {
        if free[index].0 + free[index].1 == free[index + 1].0 {
            free[index].1 += free[index + 1].1;
            free.remove(index + 1);
        } else {
            index += 1;
        }
    }
    if let Some(&(last, length)) = free.last() {
        if last + length == state.dynamic_next {
            state.dynamic_next = last;
            free.pop();
        }
    }
}

// ---- criação, entrada e saída -----------------------------------------------

fn allocate_id() -> u32 {
    let mut ids = SESSION_IDS.lock();
    let id = (0..).find(|candidate| !ids.contains(candidate)).unwrap_or(0);
    ids.insert(id);
    id
}

fn reserve_global() -> Option<u64> {
    let mut pages = GLOBAL_PAGES.lock();
    let va = (map::SESSION_GLOBAL_BASE..map::SESSION_GLOBAL_TOP).step_by(PAGE as usize).find(|va| !pages.contains(va))?;
    pages.insert(va);
    Some(va)
}

/// O que [`build`] montou, para desfazer numa falha.
#[derive(Default)]
struct Built {
    top_level: u64,
    edit_root: u64,
    core: Vec<u64>,
    global: u64,
    mapped_core: usize,
}

impl Built {
    fn release(&mut self) {
        if self.global != 0 {
            paging::unmap_page_in(process_address_space::SYSTEM_ROOT, self.global, paging::MapOptions::default());
            GLOBAL_PAGES.lock().remove(&self.global);
        }
        for index in 0..self.mapped_core {
            paging::unmap_page_in(self.edit_root, map::SESSION_CORE_BASE + index as u64 * PAGE, paging::MapOptions::default());
        }
        let _ = smp::flush_remote_tlb(false);
        if self.edit_root != 0 {
            paging::set_session_top_level(self.edit_root, 0);
            let _ = process_address_space::delete_root(self.edit_root);
        }
        for &frame in &self.core {
            pfn::free_page(frame);
        }
        if self.top_level != 0 {
            pfn::free_page(self.top_level);
        }
    }
}

/// MiMapNewSession: a tabela de topo, a raiz de edição, as páginas do
/// MM_SESSION_SPACE em SessionCore e a VA global da primeira delas.
fn build(built: &mut Built) -> Result<(), KernelError> {
    let no_memory = || KernelError::with_status("no memory for a new session space", STATUS_NO_MEMORY);
    built.top_level = pfn::alloc_page();
    if built.top_level == 0 {
        return Err(no_memory());
    }
    physical::zero(built.top_level, PAGE as usize);
    for _ in 0..CORE_PAGES {
        let frame = pfn::alloc_page();
        if frame == 0 {
            return Err(no_memory());
        }
        physical::zero(frame, PAGE as usize);
        built.core.push(frame);
    }
    built.edit_root = process_address_space::create_root()?;
    paging::set_session_top_level(built.edit_root, built.top_level | SESSION_PTE);
    for (index, &frame) in built.core.iter().enumerate() {
        if !paging::map_page_in(built.edit_root, map::SESSION_CORE_BASE + index as u64 * PAGE, frame, SESSION_PTE, paging::MapOptions { nx: true, ..Default::default() }) {
            return Err(no_memory());
        }
        built.mapped_core = index + 1;
    }
    built.global = reserve_global().ok_or_else(no_memory)?;
    if !paging::map_page_in(process_address_space::SYSTEM_ROOT, built.global, built.core[0], SESSION_PTE, paging::MapOptions { nx: true, ..Default::default() }) {
        return Err(no_memory());
    }
    Ok(())
}

/// MiSessionAddProcess (+ a inserção na ProcessList): EPROCESS.Session, o
/// bit ProcessInSession e a tabela de topo da sessão na raiz do processo.
/// Roda com `SESSIONS` travada.
fn add_process(process: u64, pointer: u64, root: u64, master: bool) {
    let object = eprocess(process);
    paging::set_session_top_level(root, space(pointer).page_directory.u.long.get());
    object.session.set(pointer);
    object.flags.atomic().fetch_or(Eprocess::PROCESS_IN_SESSION_MASK, Ordering::SeqCst);
    if master {
        object.vm.instance.flags.set_session_master(1);
    }
    insert_tail(&space(pointer).process_list, &object.session_process_links);
}

/// MiSessionCreate: uma sessão nova para `process` (que precisa de raiz
/// própria), com o menor id livre; `process` é o mestre dela. Devolve o id.
pub fn create(process: u64) -> Result<u32, KernelError> {
    let Some(root) = process_address_space::root_of(process) else {
        return Err(KernelError::new("a session process needs its own address space"));
    };
    let id = allocate_id();
    let mut built = Built::default();
    if let Err(error) = build(&mut built) {
        built.release();
        SESSION_IDS.lock().remove(&id);
        return Err(error);
    }
    let pointer = built.global;
    let session = space(pointer);
    // MiSessionCreateInternal.
    session.u.long_flags.set(0);
    session.reference_count.set(1);
    session.process_reference_to_session.set(1);
    session.session_id.set(id);
    session.locale_id.set(locale::default_system_locale());
    session.create_time.set(clock::query_interrupt_time_precise(0));
    session.session_page_directory_index.set(built.top_level >> 12);
    session.page_directory.u.long.set(built.top_level | SESSION_PTE);
    session.non_pagable_pages.set(CREATE_PAGES);
    session.committed_pages.set(CREATE_PAGES);
    session.process_list.flink.set(session.process_list.address());
    session.process_list.blink.set(session.process_list.address());
    let state = Session {
        id,
        top_level: built.top_level,
        edit_root: built.edit_root,
        core: [built.core[0], built.core[1], built.core[2], built.core[3], built.core[4]],
        dynamic_next: map::SESSION_DYNAMIC_VA_BASE,
        dynamic_free: Vec::new(),
    };
    let mut sessions = SESSIONS.lock();
    sessions.insert(pointer, state);
    // MiMarkSessionMasterProcess.
    add_process(process, pointer, root, true);
    drop(sessions);
    crate::debug_print!("[mm] sessao {} criada para o processo {:#x} (topo {:#x}, VA global {:#x})", id, process, built.top_level, pointer);
    Ok(id)
}

/// MiJoinSession: o processo novo entra na sessão de `parent` (nenhuma se o
/// pai não tem sessão, é processo de sistema ou a sessão já não tem
/// referências).
pub fn join(process: u64, parent: u64) {
    if parent == 0 || eprocess(parent).system_process() != 0 {
        return;
    }
    let pointer = eprocess(parent).session.get();
    if pointer == 0 {
        return;
    }
    let Some(root) = process_address_space::root_of(process) else {
        crate::debug_print!("[mm] processo {:#x} sem raiz propria fica fora da sessao do pai", process);
        return;
    };
    let sessions = SESSIONS.lock();
    if !sessions.contains_key(&pointer) {
        return;
    }
    let session = space(pointer);
    let references = session.reference_count.get();
    if references == 0 {
        return;
    }
    session.reference_count.set(references + 1);
    session.process_reference_to_session.set(session.process_reference_to_session.get() + 1);
    add_process(process, pointer, root, false);
}

/// PspProcessDelete: `process` sai da sessão e a tabela de topo sai da raiz
/// dele; a última referência desfaz a sessão (MiDereferenceSessionFinal).
pub fn leave(process: u64) {
    let object = eprocess(process);
    let pointer = object.session.get();
    if pointer == 0 {
        return;
    }
    let last = {
        let sessions = SESSIONS.lock();
        if !sessions.contains_key(&pointer) {
            object.session.set(0);
            return;
        }
        let session = space(pointer);
        remove_entry(&object.session_process_links);
        object.session.set(0);
        object.flags.atomic().fetch_and(!Eprocess::PROCESS_IN_SESSION_MASK, Ordering::SeqCst);
        if let Some(root) = process_address_space::root_of(process) {
            paging::set_session_top_level(root, 0);
        }
        session.process_reference_to_session.set(session.process_reference_to_session.get() - 1);
        let references = session.reference_count.get() - 1;
        session.reference_count.set(references);
        if references == 0 {
            session.u.flags.set_delete_pending(1);
        }
        references == 0
    };
    if last {
        destroy(pointer);
    }
}

/// MiDereferenceSessionFinal: as imagens de sessão, o pool de sessão, as
/// páginas do MM_SESSION_SPACE e as tabelas do espaço de sessão, a VA
/// global e o id. Uma página de sessão que alguém deixou mapeada fica
/// retida (com aviso), nunca liberada debaixo de quem a usa.
fn destroy(pointer: u64) {
    let id = space(pointer).session_id.get();
    super::session_image::release_session(pointer);
    super::session_pool::release_session(pointer);
    let core_pages: Vec<u64> = (0..CORE_PAGES as u64).map(|index| map::SESSION_CORE_BASE + index * PAGE).collect();
    if let Err(error) = unmap_pages(pointer, &core_pages) {
        crate::debug_print!("[mm] sessao {}: paginas do MM_SESSION_SPACE retidas: {}", id, error);
        return;
    }
    let Some(state) = SESSIONS.lock().remove(&pointer) else { return };
    paging::unmap_page_in(process_address_space::SYSTEM_ROOT, pointer, paging::MapOptions::default());
    if let Err(error) = smp::flush_remote_tlb(false) {
        crate::debug_print!("[mm] sessao {}: VA global retida: {}", id, error);
        return;
    }
    GLOBAL_PAGES.lock().remove(&pointer);
    for frame in state.core {
        pfn::free_page(frame);
    }
    let leftover = (0..512).find(|index| physical::read64(state.top_level + index * 8) != 0);
    paging::set_session_top_level(state.edit_root, 0);
    if let Err(error) = process_address_space::delete_root(state.edit_root) {
        crate::debug_print!("[mm] sessao {}: raiz de edicao retida: {}", id, error);
    }
    match leftover {
        Some(index) => crate::debug_print!("[mm] sessao {}: tabela de topo retida (entrada {} ainda presente)", id, index),
        None => {
            pfn::free_page(state.top_level);
        }
    }
    SESSION_IDS.lock().remove(&id);
    crate::debug_print!("[mm] sessao {} encerrada", id);
}

// ---- attach (MmAttachSession/MmDetachSession) e MmGetSessionById -----------

/// MmAttachSession(SessionProcess, ApcState): AttachCount++ (sessão com
/// DeletePending: STATUS_PROCESS_IS_TERMINATING) e KiStackAttachProcess no
/// processo da sessão; quem já está nela (e não é processo de sistema)
/// anexa a si mesmo.
pub fn attach(session_process: u64, apc_state: u64) -> Result<u32, KernelError> {
    let target = eprocess(session_process).session.get();
    let current_process = process::get_current_process();
    let current_session = eprocess(current_process).session.get();
    {
        let sessions = SESSIONS.lock();
        if target == 0 || !sessions.contains_key(&target) {
            return Err(KernelError::new("MmAttachSession on a process without a session"));
        }
        let session = space(target);
        if session.u.flags.delete_pending() != 0 {
            return Ok(STATUS_PROCESS_IS_TERMINATING);
        }
        session.attach_count.set(session.attach_count.get() + 1);
    }
    let same = current_session != 0 && eprocess(current_process).system_process() == 0 && current_session == target;
    let attached = process_attachment::attach(if same { current_process } else { session_process }, apc_state);
    if attached.is_err() {
        let _sessions = SESSIONS.lock();
        let session = space(target);
        session.attach_count.set(session.attach_count.get() - 1);
    }
    attached.map(|_| 0)
}

/// MmDetachSession(SessionProcess, ApcState): AttachCount-- e
/// KiUnstackDetachProcess.
pub fn detach(session_process: u64, apc_state: u64) -> Result<u32, KernelError> {
    let target = eprocess(session_process).session.get();
    {
        let sessions = SESSIONS.lock();
        if target != 0 && sessions.contains_key(&target) {
            let session = space(target);
            session.attach_count.set(session.attach_count.get().saturating_sub(1));
        }
    }
    process_attachment::detach(apc_state).map(|_| 0)
}

/// MmSessionSetUnloadAddress(DriverObject): a sessão do processo corrente
/// guarda o DriverUnload do driver de sessão (1 sem rotina), uma vez só.
pub fn set_unload_address(driver_object: u64) {
    let pointer = current();
    let _sessions = SESSIONS.lock();
    if pointer == 0 {
        return;
    }
    // SAFETY: DRIVER_OBJECT vivo do chamador de kernel.
    let unload = unsafe { DriverObject::at(driver_object) }.driver_unload.get();
    let session = space(pointer);
    if session.driver_unload.function.get() == 0 {
        session.driver_unload.function.set(if unload == 0 { 1 } else { unload });
    }
}

/// MmGetSessionById(SessionId): um processo referenciado da sessão para o
/// MmAttachSession (o chamador o dereferencia), ou 0. Como o
/// MiSelectSessionAttachProcess, só serve sessão com driver de sessão
/// carregado (DriverUnload), fora de DeletePending, e pula o processo mestre
/// e o que já desfaz o espaço (CommitReleaseState). O AddressSpaceInitialized
/// do NT corresponde, no OpenNT, a ter estado de processo vivo.
pub fn by_id(id: u32) -> u64 {
    let sessions = SESSIONS.lock();
    let Some((&pointer, _)) = sessions.iter().find(|(_, state)| state.id == id) else { return 0 };
    let session = space(pointer);
    if session.driver_unload.function.get() == 0 || session.u.flags.delete_pending() != 0 {
        return 0;
    }
    let head = session.process_list.address();
    let mut link = session.process_list.flink.get();
    while link != head && link != 0 {
        let candidate = link - core::mem::offset_of!(Eprocess, session_process_links) as u64;
        let object = eprocess(candidate);
        let flags = &object.vm.instance.flags;
        let usable = flags.session_master() == 0 && flags.commit_release_state() != COMMIT_RELEASE_DELETING && crate::ntos::ps::user::process_state::get(candidate).is_some();
        if usable && process::reference(candidate).is_some() {
            return candidate;
        }
        link = object.session_process_links.flink.get();
    }
    0
}
