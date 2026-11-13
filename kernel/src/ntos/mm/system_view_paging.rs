//! Paginação de vistas globais de arquivos.
//!
//! O arquivo real conserva os bytes antes de devolver os PFNs; o page-in
//! restaura todos os aliases da control area. Os limites de resolução são
//! vivos (crescem a cada vista registrada), então o provedor é registrado
//! sem limites fixos e o próprio `resolve` aplica a faixa.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::page_residency::{self, FaultResult, Provider};
use super::paging::{self, MapOptions, PageQuery};
use super::{io_pins, pfn};
use crate::ntos::mm::section::cache as section_cache;
use crate::hal::physical;
use crate::ntos::ke::{bugcheck, irql, smp};
use crate::ntos::ps::user::sections::{self, AreaPaging, AreaRef, Section, View};
use crate::rtl::{KernelError, SpinLock};

struct Record {
    area: AreaRef,
    evicted: BTreeSet<u64>,
    busy: bool,
}

type RecordRef = Arc<SpinLock<Record>>;

static AREAS: SpinLock<BTreeMap<usize, RecordRef>> = SpinLock::new(BTreeMap::new());
static RANGE: SpinLock<(u64, u64)> = SpinLock::new((0, 0));
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn area_key(area: &AreaRef) -> usize {
    Arc::as_ptr(area) as *const u8 as usize
}

fn record_of(view: &View) -> Option<RecordRef> {
    let area = view.section.control_area()?;
    AREAS.lock().get(&area_key(&area)).cloned()
}

/// Gancho instalado na control area.
struct AreaHook {
    record: RecordRef,
    key: usize,
}

impl AreaPaging for AreaHook {
    fn materialize(&self, section: &Arc<Section>) -> Result<(), KernelError> {
        materialize(&self.record, Some(section))
    }

    fn release(&self) {
        AREAS.lock().remove(&self.key);
        let area = self.record.lock().area.clone();
        area.lock().system_paging = None;
    }
}

fn find_view(address: u64) -> Option<Arc<View>> {
    sections::find_system_view(address).filter(|view| view.state.lock().system_paging)
}

struct Reservation {
    view: Arc<View>,
    index: u64,
    address: u64,
    protect: Option<u32>,
    mapping: Option<PageQuery>,
}

/// O rollback do commit desfaz PTEs novas; as reservas anteriores e os
/// aliases COW privados continuam das vistas depois de uma falha de I/O.
fn restore_page(record: &RecordRef, section: &Arc<Section>, section_page: u64) -> Result<(), KernelError> {
    let area = {
        let owner = record.lock();
        if irql::get_irql() > 1 || owner.busy {
            return Err(KernelError::new("system section page-in cannot run in this context"));
        }
        owner.area.clone()
    };
    let views = area.lock().views.clone();
    let mut reservations = Vec::new();
    for view in views {
        let first = view.offset / 4096;
        if section_page < first {
            continue;
        }
        let index = section_page - first;
        let (retiring, committed, protect) = {
            let state = view.state.lock();
            (state.retirement.is_some(), state.committed_pages.contains(&index), state.page_protects.get(&index).copied())
        };
        if retiring || !committed {
            continue;
        }
        let address = view.base + index * 4096;
        reservations.push(Reservation { mapping: paging::query_page(address, true), view, index, address, protect });
    }
    record.lock().busy = true;
    let result = (|| -> Result<(), KernelError> {
        let status = sections::restore_file_page(section, section_page)?;
        if status != 0 {
            for saved in &reservations {
                let private = {
                    let mut state = saved.view.state.lock();
                    state.committed_pages.insert(saved.index);
                    match saved.protect {
                        Some(protect) => state.page_protects.insert(saved.index, protect),
                        None => state.page_protects.remove(&saved.index),
                    };
                    state.private_frames.get(&saved.index).copied()
                };
                let (flags, nx) = match (private, &saved.mapping) {
                    (Some(_), Some(mapping)) => (mapping.flags, mapping.nx),
                    (Some(_), None) => (0, false),
                    (None, _) => (0x200, saved.protect.unwrap_or(0) & 0xF0 == 0),
                };
                if !paging::map_page(saved.address, private.unwrap_or(0), flags, MapOptions { nx, ..MapOptions::default() }) {
                    return Err(KernelError::new("cannot restore section reservation after failed page-in"));
                }
                let mut state = saved.view.state.lock();
                match private {
                    Some(frame) => state.frames.insert(saved.index, frame),
                    None => state.frames.remove(&saved.index),
                };
            }
            return Err(KernelError::with_status("system section page-in failed", status));
        }
        record.lock().evicted.remove(&section_page);
        Ok(())
    })();
    record.lock().busy = false;
    result
}

fn page_in(view: &View, page_index: u64) -> Result<(), KernelError> {
    let Some(record) = record_of(view) else { return Ok(()) };
    let section_page = page_index + view.offset / 4096;
    let evicted = record.lock().evicted.contains(&section_page);
    if evicted {
        restore_page(&record, &view.section, section_page)?;
    }
    Ok(())
}

/// Páginas sem vista continuam do arquivo; a próxima vista materializa pelo
/// gancho antes de publicar aliases.
fn materialize(record: &RecordRef, incoming: Option<&Arc<Section>>) -> Result<(), KernelError> {
    let (area, evicted) = {
        let owner = record.lock();
        (owner.area.clone(), owner.evicted.iter().copied().collect::<Vec<u64>>())
    };
    for section_page in evicted {
        let views = area.lock().views.clone();
        let covering = views.iter().find(|candidate| !candidate.retiring() && section_page >= candidate.offset / 4096 && section_page < (candidate.offset + candidate.size) / 4096).cloned();
        match covering {
            Some(view) => page_in(&view, section_page - view.offset / 4096)?,
            None => {
                let contains_page = |section: &Section| section.size > section_page * 4096;
                let owner = views.iter().find(|candidate| !candidate.retiring() && contains_page(&candidate.section)).map(|view| view.section.clone());
                let section = owner.or_else(|| incoming.filter(|section| contains_page(section)).cloned());
                if let Some(section) = section {
                    restore_page(record, &section, section_page)?;
                }
            }
        }
    }
    Ok(())
}

/// Liga a vista global de dados à paginação; `flags & 1` entrega
/// STATUS_IN_PAGE_ERROR em vez de bugcheck na falha de page-in.
pub fn register(view: &Arc<View>, flags: u64) -> Result<(), KernelError> {
    let Some(area) = view.section.control_area().filter(|_| view.system_space) else { return Err(KernelError::new("system paging requires an owned global data view")) };
    {
        let mut state = view.state.lock();
        state.system_paging = true;
        state.in_page_exceptions = flags & 1 != 0;
    }
    {
        let mut range = RANGE.lock();
        let (base, top) = (view.base, view.base + view.size);
        if range.1 == 0 || base < range.0 {
            range.0 = base;
        }
        if top > range.1 {
            range.1 = top;
        }
    }
    let key = area_key(&area);
    let exists = AREAS.lock().contains_key(&key);
    if !exists {
        let record = Arc::new(SpinLock::new(Record { area: area.clone(), evicted: BTreeSet::new(), busy: false }));
        AREAS.lock().insert(key, record.clone());
        area.lock().system_paging = Some(Arc::new(AreaHook { record, key }));
    }
    if !INSTALLED.swap(true, Ordering::AcqRel) {
        page_residency::register("system-section", Provider { fault: provider_fault, resolve, reclaim, prepare, resolve_range: None })?;
    }
    Ok(())
}

struct Alias {
    view: Arc<View>,
    index: u64,
    address: u64,
    mapping: PageQuery,
}

/// Devolve o PFN de uma página: grava o arquivo, retira todos os aliases
/// (PTE reservada 0x200), espera os ACKs, grava de novo e libera. Até o fim,
/// uma falha restaura os aliases e o PFN continua da seção.
pub fn evict(view: &View, page_index: u64) -> Result<bool, KernelError> {
    let Some(record) = record_of(view) else { return Ok(false) };
    let section = &view.section;
    if record.lock().busy || view.retiring() || section.large || section.page_protect() & 0x600 != 0 || section.file.is_none() || smp::has_active_jobs() {
        return Ok(false);
    }
    if irql::get_irql() > 1 {
        return Err(KernelError::new("system section eviction above APC_LEVEL"));
    }
    if page_index >= view.size / 4096 {
        return Err(KernelError::new("invalid system section page index"));
    }
    let section_page = view.offset / 4096 + page_index;
    let Some(frame) = section.frame(section_page) else { return Ok(false) };
    let area = record.lock().area.clone();
    let mut aliases = Vec::new();
    for candidate in area.lock().views.clone() {
        let (system_paging, retiring) = {
            let state = candidate.state.lock();
            (state.system_paging, state.retirement.is_some())
        };
        if !system_paging || retiring {
            return Ok(false);
        }
        let first = candidate.offset / 4096;
        if section_page < first {
            continue;
        }
        let index = section_page - first;
        if index >= candidate.size / 4096 || candidate.state.lock().private_frames.contains_key(&index) {
            continue;
        }
        let address = candidate.base + index * 4096;
        if io_pins::is_pinned(address) {
            return Ok(false);
        }
        let mapping = paging::query_page(address, true);
        let Some(mapping) = mapping.filter(|mapping| mapping.page_size == 4096 && mapping.physical_address == frame) else { return Err(KernelError::new("system section alias lost its backing")) };
        aliases.push(Alias { view: candidate, index, address, mapping });
    }
    if aliases.is_empty() {
        return Ok(false);
    }
    record.lock().busy = true;
    let mut changed = 0usize;
    let result = (|| -> Result<bool, KernelError> {
        sections::flush(section)?;
        for alias in &aliases {
            if !paging::map_page(alias.address, 0, 0x200, MapOptions { nx: alias.mapping.nx, ..MapOptions::default() }) {
                return Err(KernelError::new("cannot retire a system section PTE"));
            }
            changed += 1;
        }
        smp::flush_remote_tlb(false)?;
        sections::flush(section)?;
        section_cache::restore(&[frame])?;
        if !pfn::free_page(frame) {
            return Err(KernelError::new("system section lost physical ownership"));
        }
        area.lock().frames.remove(&section_page);
        for alias in &aliases {
            alias.view.state.lock().frames.remove(&alias.index);
        }
        record.lock().evicted.insert(section_page);
        Ok(true)
    })();
    let result = match result {
        Ok(evicted) => Ok(evicted),
        Err(error) => {
            // O PFN ainda pertence à seção: restaurar os aliases conserva os
            // bytes mesmo quando uma escrita ou um ACK impede o page-out.
            let mut restored = Err(error);
            for alias in aliases.iter().take(changed) {
                if !paging::map_page(alias.address, frame, alias.mapping.flags, MapOptions { nx: alias.mapping.nx, ..MapOptions::default() }) {
                    restored = Err(KernelError::new("cannot restore system section after failed eviction"));
                    break;
                }
            }
            if changed != 0 {
                let _ = smp::flush_remote_tlb(false);
            }
            restored
        }
    };
    record.lock().busy = false;
    result
}

/// Falta de supervisor não presente numa página despejada: page-in; uma
/// escrita em WRITECOPY repete e entra no tratador COW com P=1. Falha de
/// I/O: STATUS_IN_PAGE_ERROR (se pedido) ou bugcheck 0x7A.
pub fn fault(address: u64, error_code: u32) -> FaultResult {
    if error_code & 13 != 0 || irql::get_irql() > 1 {
        return FaultResult::NotMine;
    }
    let Some(view) = find_view(address) else { return FaultResult::NotMine };
    let index = (address - view.base) / 4096;
    let (protection, in_page_exceptions) = {
        let state = view.state.lock();
        (state.page_protects.get(&index).copied().filter(|&protect| protect != 0).unwrap_or(view.protect) & 255, state.in_page_exceptions)
    };
    if protection == 1 || (error_code & 16 != 0 && protection & 0xF0 == 0) || (error_code & 2 != 0 && protection & 0xCC == 0) {
        return FaultResult::NotMine;
    }
    let Some(record) = record_of(&view) else { return FaultResult::NotMine };
    if !record.lock().evicted.contains(&(view.offset / 4096 + index)) {
        return FaultResult::NotMine;
    }
    let entry_address = paging::query_page(address, true).map_or(0, |mapping| mapping.entry_address);
    // A PTE inteira numa única leitura de 64 bits (sem observar duas metades).
    let entry_contents = if entry_address != 0 { physical::read64(entry_address) } else { 0 };
    match page_in(&view, index) {
        Ok(()) => FaultResult::Resolved,
        Err(error) if error.status == 0 => panic!("{}", error.message),
        Err(error) if in_page_exceptions => FaultResult::InPageError(error.status),
        Err(error) => bugcheck::bug_check_ex(0x7A, entry_address, error.status as i32 as i64 as u64, entry_contents, address),
    }
}

fn provider_fault(address: u64, error_code: u32) -> FaultResult {
    fault(address, error_code)
}

/// Acesso do próprio gerenciador não fabrica um EXCEPTION_RECORD de CPU.
pub fn resolve(address: u64) -> Result<Option<u64>, KernelError> {
    let (base, top) = *RANGE.lock();
    if top == 0 || address < base || address >= top {
        return Ok(None);
    }
    let Some(view) = find_view(address) else { return Ok(None) };
    page_in(&view, (address - view.base) / 4096)?;
    Ok(paging::query_page(address, false).map(|mapping| mapping.physical_address))
}

pub fn reclaim(count: u64) -> Result<u64, KernelError> {
    if smp::has_active_jobs() {
        return Ok(0);
    }
    let mut freed = 0u64;
    for view in sections::system_views() {
        let (system_paging, retiring, committed) = {
            let state = view.state.lock();
            (state.system_paging, state.retirement.is_some(), state.committed_pages.iter().copied().collect::<Vec<u64>>())
        };
        if !system_paging || retiring {
            continue;
        }
        for index in committed {
            if freed >= count {
                return Ok(freed);
            }
            if evict(&view, index)? {
                freed += 1;
            }
        }
    }
    Ok(freed)
}

pub fn prepare() -> Result<(), KernelError> {
    let records: Vec<RecordRef> = AREAS.lock().values().cloned().collect();
    for record in records {
        materialize(&record, None)?;
    }
    Ok(())
}

/// Páginas despejadas da control area da seção (diagnóstico e testes).
pub fn evicted(section: &Section) -> Vec<u64> {
    let Some(area) = section.control_area() else { return Vec::new() };
    AREAS.lock().get(&area_key(&area)).map(|record| record.lock().evicted.iter().copied().collect()).unwrap_or_default()
}
