//! O working set das alocações privadas dos processos e as faltas de
//! página que trazem as páginas de volta, sobre as PTEs do ntoskrnl 19041:
//!
//! - Corte (o MiTrimWorkingSet/MiFreeWsleList da falta de memória): com a
//!   memória livre esgotada, as páginas residentes das alocações privadas
//!   saem do working set — a PTE válida vira PTE de transição
//!   (MMPTE_TRANSITION: Valid 0, Write, Protection, Transition 1 e o
//!   PageFrameNumber do frame, que segue dono dela). Uma página suja (bit
//!   Dirty da PTE), ou sem cópia no arquivo de paginação, vai para a lista
//!   de páginas modificadas; uma limpa com cópia, para a de reserva
//!   (`mm/modified_writer`). O bit Accessed dá uma segunda chance: a
//!   primeira passada só o limpa.
//! - Falta de transição (MiResolveTransitionFault): o frame volta a valer
//!   na mesma PTE, sem E/S; a cópia no arquivo, se havia, continua valendo
//!   enquanto a página não for escrita.
//! - Falta de arquivo de paginação (MiResolvePageFileFault e a leitura do
//!   MiResolveIoFault): um frame novo, o IoPageRead do arquivo
//!   (IRP_PAGING_IO) e a PTE válida; a página fica limpa, com a cópia.
//!
//! Este módulo é um provedor de `page_residency`: a falta de página de
//! usuário e de kernel numa VA de usuário, o resolvedor das sondas de
//! `guest_memory` e o recuperador do PFN chegam aqui. Ele só entra com o
//! primeiro arquivo de paginação (`paging_file::insert`).
//!
//! Diferenças declaradas: o OpenNT não tem working sets por processo nem o
//! gerente de working sets: o corte só acontece na falta de memória e
//! escolhe as páginas numa varredura circular das alocações privadas de
//! todos os processos com espaço próprio. As alocações que o kernel monta
//! para o processo ficam residentes (`PrivateRegion::pageable`). Os
//! programas de usuário rodam só no processador de boot, então as PTEs são
//! gravadas sem compare-exchange; o TLB dos outros processadores é
//! descartado depois de cada corte. Uma falta com spin lock retido, ou uma
//! de arquivo de paginação acima de APC_LEVEL, não é atendida (no NT, um
//! bugcheck), e a página fica como está; o recuperador também não corta com
//! spin lock retido.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::page_residency::{self, FaultResult, Provider};
use super::paging::{self, MapOptions};
use super::paging_file::{self, Slot};
use super::process_address_space::SYSTEM_ROOT;
use super::{io_pins, memory_map as map, modified_writer, pfn};
use crate::ntos::ke::{irql, smp};
use crate::ntos::ps::user::memory::{self, PagedPage, PrivateRegion, Space};
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::user::state::Region;
use crate::rtl::{sync, KernelError, SpinLock};

const PAGE: u64 = map::PAGE_SIZE;
const PTE_VALID: u64 = 0x1;
const PTE_WRITE: u64 = 0x2;
const PTE_OWNER: u64 = 0x4;
const PTE_WRITE_THROUGH: u64 = 0x8;
const PTE_CACHE_DISABLE: u64 = 0x10;
const PTE_ACCESSED: u64 = 0x20;
const PTE_DIRTY: u64 = 0x40;
/// MMPTE_TRANSITION.Transition.
const PTE_TRANSITION: u64 = 1 << 11;
const PTE_NO_EXECUTE: u64 = 1 << 63;
const PTE_FRAME: u64 = 0x000F_FFFF_FFFF_F000;
/// Os bits da PTE válida que a volta repete.
const TEMPLATE_BITS: u64 = PTE_VALID | PTE_WRITE | PTE_OWNER | PTE_WRITE_THROUGH | PTE_CACHE_DISABLE | PTE_NO_EXECUTE;
/// Páginas que um corte tira de uma vez, no mínimo.
const TRIM_BATCH: u64 = 64;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;

static INSTALLED: AtomicBool = AtomicBool::new(false);
/// Páginas fora do working set (em transição ou só no arquivo de paginação).
static NONRESIDENT: AtomicU64 = AtomicU64::new(0);
/// Frames travados por MmProbeAndLockPages (contagem por frame).
static LOCKED: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());
/// Onde a próxima varredura do corte começa: (raiz, base da região, página).
static CURSOR: SpinLock<(u64, u64, u64)> = SpinLock::new((0, 0, 0));

/// Os contadores que a SystemPerformanceInformation soma dos KPRCBs.
pub struct Counters {
    pub page_faults: AtomicU64,
    pub transition_faults: AtomicU64,
    pub page_reads: AtomicU64,
    pub page_read_ios: AtomicU64,
    pub dirty_pages_written: AtomicU64,
    pub dirty_write_ios: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    page_faults: AtomicU64::new(0),
    transition_faults: AtomicU64::new(0),
    page_reads: AtomicU64::new(0),
    page_read_ios: AtomicU64::new(0),
    dirty_pages_written: AtomicU64::new(0),
    dirty_write_ios: AtomicU64::new(0),
};

/// Uma página que o corte pôs numa lista do Mm.
#[derive(Clone)]
pub struct ListedPage {
    pub region: Region,
    pub root: u64,
    pub index: u64,
    pub frame: u64,
}

impl ListedPage {
    pub fn owner(&self) -> Option<&PrivateRegion> {
        private(&self.region)
    }

    pub fn va(&self) -> u64 {
        self.owner().map_or(0, |owner| owner.base + self.index * PAGE)
    }
}

fn private(region: &Region) -> Option<&PrivateRegion> {
    region.as_any().downcast_ref::<PrivateRegion>()
}

/// MmProtectToValue: a proteção de página do Win32 no valor de 5 bits do
/// campo Protection das PTEs de software.
pub fn mm_protection(protect: u32) -> u64 {
    let base = match protect & 0xFF {
        0x01 => return 0x18,
        0x02 => 1,
        0x04 => 4,
        0x08 => 5,
        0x10 => 2,
        0x20 => 3,
        0x40 => 6,
        0x80 => 7,
        _ => 0,
    };
    let mut value = base;
    if protect & 0x200 != 0 {
        value |= 0x08;
    }
    if protect & 0x100 != 0 {
        value |= 0x10;
    }
    if protect & 0x400 != 0 {
        value |= 0x18;
    }
    value
}

/// A PTE de transição do frame.
fn transition_pte(frame: u64, protection: u64, writable: bool) -> u64 {
    frame | PTE_TRANSITION | (protection << 5) | if writable { PTE_WRITE } else { 0 }
}

/// A PTE de arquivo de paginação (MiMakePageFilePte, sem a máscara de PTE
/// inválida): PageFileHigh = a página no arquivo, PageFileLow = o arquivo.
pub fn page_file_pte(slot: Slot, protection: u64) -> u64 {
    (slot.offset << 32) | ((slot.file as u64 & 0xF) << 12) | (protection << 5)
}

/// A proteção corrente de uma página da região.
pub fn page_protection(owner: &PrivateRegion, state: &memory::PrivateMut, index: u64) -> u64 {
    mm_protection(state.page_protects.get(&index).copied().filter(|&protect| protect != 0).unwrap_or(owner.protect))
}

/// Instala o provedor (o primeiro arquivo de paginação).
pub fn install() {
    if INSTALLED.swap(true, Ordering::AcqRel) {
        return;
    }
    let provider = Provider { fault, resolve, reclaim, prepare: || Ok(()), resolve_range: Some((map::LOWEST_USER_ADDRESS, map::USER_ADDRESS_LIMIT)) };
    if let Err(error) = page_residency::register("private pages", provider) {
        crate::debug_print!("[mm] provedor do working set: {}", error);
    }
}

/// Páginas fora do working set agora.
pub fn nonresident_pages() -> u64 {
    NONRESIDENT.load(Ordering::Acquire)
}

pub(super) fn count_resident(pages: u64) {
    NONRESIDENT.fetch_sub(pages.min(NONRESIDENT.load(Ordering::Acquire)), Ordering::AcqRel);
}

/// O contexto pode fazer E/S de paginação e esperar por ela.
fn can_do_io() -> bool {
    irql::get_irql() <= irql::APC_LEVEL && sync::spin_locks_held() == 0
}

/// Trava os frames de um MDL de páginas de usuário (MmProbeAndLockPages).
pub fn lock_frame(frame: u64) {
    *LOCKED.lock().entry(frame & !(PAGE - 1)).or_insert(0) += 1;
}

/// Destrava (MmUnlockPages).
pub fn unlock_frame(frame: u64) {
    let mut locked = LOCKED.lock();
    let key = frame & !(PAGE - 1);
    match locked.get(&key).copied() {
        Some(1) => {
            locked.remove(&key);
        }
        Some(count) => {
            locked.insert(key, count - 1);
        }
        None => {}
    }
}

fn locked(frame: u64) -> bool {
    LOCKED.lock().contains_key(&frame)
}

fn fault(address: u64, error: u32) -> FaultResult {
    if NONRESIDENT.load(Ordering::Acquire) == 0 || error & 1 != 0 || !(map::LOWEST_USER_ADDRESS..map::USER_ADDRESS_LIMIT).contains(&address) {
        return FaultResult::NotMine;
    }
    match resolve_current(address) {
        Ok(true) => FaultResult::Resolved,
        Ok(false) => FaultResult::NotMine,
        Err(status) => FaultResult::InPageError(status),
    }
}

fn resolve(address: u64) -> Result<Option<u64>, KernelError> {
    if NONRESIDENT.load(Ordering::Acquire) == 0 {
        return Ok(None);
    }
    match resolve_current(address) {
        Ok(true) => Ok(Some(paging::translate(address & !(PAGE - 1)))),
        Ok(false) => Ok(None),
        Err(status) => Err(KernelError::with_status("falta de pagina de usuario sem a pagina", status)),
    }
}

/// A página de `address` no processo corrente volta ao working set, se
/// estava fora dele.
fn resolve_current(address: u64) -> Result<bool, u32> {
    // O VAD e a região são spin locks: com um já retido (talvez o mesmo),
    // a página fica como está.
    if sync::spin_locks_held() != 0 {
        return Ok(false);
    }
    let space = Space::current();
    let Some(region) = space.find(address) else { return Ok(false) };
    let Some(owner) = private(&region) else { return Ok(false) };
    page_in(space.root(), owner, (address - owner.base) / PAGE)
}

/// Traz de volta as páginas `[first, end)` da região que estão fora do
/// working set; o NTSTATUS da primeira que falhar.
pub fn make_resident(root: u64, owner: &PrivateRegion, first: u64, end: u64) -> u32 {
    if NONRESIDENT.load(Ordering::Acquire) == 0 {
        return 0;
    }
    for index in first..end {
        match page_in(root, owner, index) {
            Ok(_) => {}
            Err(status) => return status,
        }
    }
    0
}

/// MiResolveTransitionFault / MiResolvePageFileFault da página `index`:
/// `Ok(false)` se ela já está no working set.
fn page_in(root: u64, owner: &PrivateRegion, index: u64) -> Result<bool, u32> {
    let va = owner.base + index * PAGE;
    loop {
        let page = match owner.state.lock().paging.get(&index) {
            None => return Ok(false),
            Some(page) => *page,
        };
        COUNTERS.page_faults.fetch_add(1, Ordering::Relaxed);
        if page.transition {
            let mut state = owner.state.lock();
            let Some(current) = state.paging.get(&index).copied().filter(|current| current.transition) else { continue };
            let Some(&frame) = state.frames.get(&index) else { continue };
            if !paging::map_page_in(root, va, frame, current.template & 0xFFF, MapOptions { nx: current.template & PTE_NO_EXECUTE != 0, ..MapOptions::default() }) {
                return Err(STATUS_NO_MEMORY);
            }
            state.paging.remove(&index);
            if let Some(slot) = current.slot {
                state.clean.insert(index, slot);
            }
            drop(state);
            count_resident(1);
            COUNTERS.transition_faults.fetch_add(1, Ordering::Relaxed);
            return Ok(true);
        }
        let Some(slot) = page.slot else { return Err(STATUS_IN_PAGE_ERROR) };
        if !can_do_io() {
            return Err(STATUS_IN_PAGE_ERROR);
        }
        let frame = pfn::alloc_page();
        if frame == 0 {
            let (modified, standby) = modified_writer::list_sizes();
            crate::debug_print!("[mm] falta de arquivo de paginacao em {:#x} sem frame livre (modificadas {}, reserva {})", va, modified, standby);
            return Err(STATUS_NO_MEMORY);
        }
        let status = paging_file::read(slot, frame);
        COUNTERS.page_read_ios.fetch_add(1, Ordering::Relaxed);
        if status & 0x8000_0000 != 0 {
            pfn::free_page(frame);
            crate::debug_print!("[mm] leitura do arquivo de paginacao {} pagina {:#x} -> {:#x}", slot.file, slot.offset, status);
            return Err(STATUS_IN_PAGE_ERROR);
        }
        let mut state = owner.state.lock();
        let unchanged = state.paging.get(&index).is_some_and(|current| !current.transition && current.slot == Some(slot));
        if !unchanged {
            drop(state);
            pfn::free_page(frame);
            continue;
        }
        if !paging::map_page_in(root, va, frame, page.template & 0xFFF, MapOptions { nx: page.template & PTE_NO_EXECUTE != 0, ..MapOptions::default() }) {
            drop(state);
            pfn::free_page(frame);
            return Err(STATUS_NO_MEMORY);
        }
        state.frames.insert(index, frame);
        state.paging.remove(&index);
        state.clean.insert(index, slot);
        drop(state);
        count_resident(1);
        COUNTERS.page_reads.fetch_add(1, Ordering::Relaxed);
        return Ok(true);
    }
}

/// Uma página que sai da região (liberação ou término): a PTE de arquivo
/// de paginação some e as cópias no arquivo voltam ao espaço livre. A PTE
/// de transição e o frame dela são do chamador, que desmapeia e devolve o
/// frame.
pub fn discard(root: u64, va: u64, paged: Option<PagedPage>, clean: Option<Slot>) {
    if let Some(page) = paged {
        count_resident(1);
        if !page.transition {
            paging::unmap_page_in(root, va, MapOptions::default());
        }
        if let Some(slot) = page.slot {
            paging_file::release(slot);
        }
    }
    if let Some(slot) = clean {
        paging_file::release(slot);
    }
}

/// As alocações privadas que o corte pode tocar, na ordem da varredura.
fn trim_candidates() -> Vec<(u64, Region)> {
    let mut candidates = Vec::new();
    for state in process_state::all() {
        let root = state.directory_table_base.load(Ordering::Acquire);
        if root == 0 || root == SYSTEM_ROOT {
            continue;
        }
        let vad = state.vad.lock();
        candidates.extend(vad.regions.iter().filter(|region| private(region).is_some_and(|owner| owner.pageable)).map(|region| (root, region.clone())));
    }
    candidates.sort_by_key(|(root, region)| (*root, region.base()));
    candidates
}

/// Arquivo de paginação cheio: as cópias que páginas residentes ainda
/// guardam no arquivo (limpas desde a leitura) voltam ao espaço livre, e
/// essas páginas ficam como as escritas (o próximo corte as leva à lista de
/// modificadas). Devolve quantas cópias saíram.
pub fn release_clean_copies() -> u64 {
    let mut released = 0;
    for (_, region) in trim_candidates() {
        let Some(owner) = private(&region) else { continue };
        let slots: Vec<Slot> = core::mem::take(&mut owner.state.lock().clean).into_values().collect();
        for slot in slots {
            paging_file::release(slot);
            released += 1;
        }
    }
    released
}

/// MiTrimWorkingSet: tira até `goal` páginas residentes do working set,
/// numa varredura circular; devolve quantas saíram.
pub fn trim(goal: u64) -> u64 {
    let candidates = trim_candidates();
    if candidates.is_empty() {
        return 0;
    }
    let cursor = *CURSOR.lock();
    let start = candidates.iter().position(|(root, region)| (*root, region.base()) >= (cursor.0, cursor.1)).unwrap_or(0);
    let mut moved = 0;
    'passes: for pass in 0..2 {
        for step in 0..=candidates.len() {
            let (root, region) = &candidates[(start + step) % candidates.len()];
            let Some(owner) = private(region) else { continue };
            // A primeira região recomeça de onde o corte anterior parou.
            let first_index = if step == 0 && pass == 0 && (*root, owner.base) == (cursor.0, cursor.1) { cursor.2 } else { 0 };
            moved += trim_region(*root, region, owner, first_index, pass == 0, goal - moved);
            if moved >= goal {
                break 'passes;
            }
        }
    }
    if moved > 0 && smp::online_cpu_count() > 1 {
        let _ = smp::flush_remote_tlb(false);
    }
    moved
}

/// MiEmptyWorkingSet: tira do working set todas as páginas pagináveis do
/// processo, sem a segunda chance; devolve quantas saíram.
pub fn empty_working_set(process: u64) -> u64 {
    let Some(state) = process_state::get(process) else { return 0 };
    let root = state.directory_table_base.load(Ordering::Acquire);
    if root == 0 || root == SYSTEM_ROOT {
        return 0;
    }
    let regions: Vec<Region> = state.vad.lock().regions.iter().filter(|region| private(region).is_some_and(|owner| owner.pageable)).cloned().collect();
    let mut moved = 0;
    for region in &regions {
        if let Some(owner) = private(region) {
            moved += trim_region(root, region, owner, 0, false, u64::MAX);
        }
    }
    if moved > 0 && smp::online_cpu_count() > 1 {
        let _ = smp::flush_remote_tlb(false);
    }
    moved
}

/// O corte dentro de uma região, a partir da página `first_index`.
fn trim_region(root: u64, region: &Region, owner: &PrivateRegion, first_index: u64, second_chance: bool, goal: u64) -> u64 {
    let mut state = owner.state.lock();
    if state.busy != 0 {
        return 0;
    }
    let resident: Vec<(u64, u64)> = state.frames.range(first_index..).filter(|(index, _)| !state.paging.contains_key(index)).map(|(&index, &frame)| (index, frame)).collect();
    let mut moved = 0;
    for (index, frame) in resident {
        let va = owner.base + index * PAGE;
        if io_pins::is_pinned(va) || locked(frame) || state.locked.contains_key(&index) {
            continue;
        }
        let Some(pte) = paging::read_leaf_in(root, va) else { continue };
        if pte & PTE_VALID == 0 || pte & PTE_FRAME != frame {
            continue;
        }
        if second_chance && pte & PTE_ACCESSED != 0 {
            paging::write_leaf_in(root, va, pte & !PTE_ACCESSED);
            continue;
        }
        let protection = page_protection(owner, &state, index);
        let mut slot = state.clean.remove(&index);
        if pte & PTE_DIRTY != 0 {
            // A cópia no arquivo deixou de valer (MiCaptureDirtyBitToPfn).
            if let Some(stale) = slot.take() {
                paging_file::release(stale);
            }
        }
        paging::write_leaf_in(root, va, transition_pte(frame, protection, pte & PTE_WRITE != 0));
        state.paging.insert(index, PagedPage { slot, template: pte & TEMPLATE_BITS, transition: true });
        NONRESIDENT.fetch_add(1, Ordering::AcqRel);
        let listed = ListedPage { region: region.clone(), root, index, frame };
        if slot.is_some() {
            modified_writer::insert_standby(listed);
        } else {
            modified_writer::insert_modified(listed);
        }
        moved += 1;
        *CURSOR.lock() = (root, owner.base, index + 1);
        if moved >= goal {
            break;
        }
    }
    moved
}

/// O recuperador do PFN: reaproveita páginas de reserva, corta o working
/// set e, se o contexto permite, grava as modificadas como o modified page
/// writer faria para o alocador que espera por memória livre.
fn reclaim(count: u64) -> Result<u64, KernelError> {
    // O corte trava VADs e regiões: um alocador que já segura um spin lock
    // (um VAD, uma região) não corta.
    if paging_file::count() == 0 || sync::spin_locks_held() != 0 {
        return Ok(0);
    }
    let mut freed = modified_writer::repurpose(count);
    if freed >= count {
        return Ok(freed);
    }
    trim(count.max(TRIM_BATCH));
    freed += modified_writer::repurpose(count - freed);
    if freed < count {
        if can_do_io() && sync::shared_locks_held() == 0 {
            modified_writer::write_modified(count.max(TRIM_BATCH));
            freed += modified_writer::repurpose(count - freed);
        } else {
            modified_writer::wake();
        }
    }
    Ok(freed)
}
