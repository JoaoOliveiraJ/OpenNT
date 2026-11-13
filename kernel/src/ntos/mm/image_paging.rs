//! Residência das imagens de drivers nativos.
//!
//! Os slots virtuais das imagens ficam reservados; o conteúdo residente vai
//! para frames PFN e o despejado mora no NTFS. Nem um flag paginável nem uma
//! PTE ausente substituem salvar os dados. O estado fica sob um spin lock
//! liberado durante alocações de frame e I/O (a recuperação de memória pode
//! reentrar aqui); `busy`, `faulting` e `reclaiming` são as proteções de
//! reentrada do original.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::page_residency::{self, FaultResult, Provider};
use super::{io_pins, paging, pfn};
use crate::hal::physical;
use crate::drivers::fs::ntfs::{self, Ntfs};
use crate::ntos::ke::{irql, smp};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::{self, SectionInfo};

#[derive(Clone, Copy)]
struct Original {
    frame: u64,
    flags: u64,
    nx: bool,
}

struct Page {
    va: u64,
    offset: u64,
    original: Original,
    frame: u64,
    locks: u32,
    default_pageable: bool,
    saved: bool,
    faulting: bool,
}

struct Record {
    base: u64,
    sections: Vec<SectionInfo>,
    pages: Vec<Page>,
    /// Seção (índice) → handle de trava.
    section_handles: BTreeMap<usize, u64>,
    entire: bool,
    migrated: bool,
    busy: bool,
    path: Option<String>,
    faults: u64,
    evictions: u64,
}

struct Handle {
    base: u64,
    count: u32,
    pages: Vec<usize>,
}

struct State {
    records: BTreeMap<u64, Record>,
    pages_by_va: BTreeMap<u64, (u64, usize)>,
    handles: BTreeMap<u64, Handle>,
    identifier: u64,
    initialized: bool,
    reclaiming: bool,
}

static STATE: SpinLock<State> = SpinLock::new(State { records: BTreeMap::new(), pages_by_va: BTreeMap::new(), handles: BTreeMap::new(), identifier: 0, initialized: false, reclaiming: false });

fn low_irql() -> Result<(), KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("pageable image operation above APC_LEVEL"));
    }
    Ok(())
}

fn default_pageable(section: &SectionInfo) -> bool {
    section.name.starts_with(".eda") || (section.name.starts_with("PAGE") && !section.name.starts_with("PAGEKD"))
}

fn section_extent(section: &SectionInfo) -> (u64, u64) {
    (section.va as u64, section.va as u64 + section.virtual_size.max(section.raw_size) as u64)
}

/// Registro da imagem que contém o endereço (criado sob demanda para
/// drivers nativos carregáveis).
fn record_for(address: u64, create: bool) -> Result<Option<u64>, KernelError> {
    let Some(entry) = crate::ntos::mm::loaded_images::find(address) else { return Ok(None) };
    let base = entry.image_base;
    if STATE.lock().records.contains_key(&base) {
        return Ok(Some(base));
    }
    if !create {
        return Ok(None);
    }
    // O motor/handler de boot não é um driver nativo carregável.
    let Some((size, sections)) = pe_loader::native_image(base) else { return Ok(None) };
    let mut pages = Vec::new();
    let mut offset = 0;
    while offset < size {
        let va = base + offset;
        let Some(mapping) = paging::query_page(va, false) else { return Err(KernelError::new("driver image has an unmapped page")) };
        let covering: Vec<&SectionInfo> = sections.iter().filter(|section| {
            let (start, end) = section_extent(section);
            offset < end && offset + 4096 > start
        }).collect();
        let original = Original { frame: mapping.physical_address & !0xFFF, flags: (mapping.flags & !0x80) | if mapping.pat { 0x80 } else { 0 }, nx: mapping.nx };
        pages.push(Page { va, offset, original, frame: original.frame, locks: 0, default_pageable: !covering.is_empty() && covering.iter().all(|section| default_pageable(section)), saved: false, faulting: false });
        offset += 4096;
    }
    let mut state = STATE.lock();
    state.records.entry(base).or_insert(Record { base, sections, pages, section_handles: BTreeMap::new(), entire: false, migrated: false, busy: false, path: None, faults: 0, evictions: 0 });
    Ok(Some(base))
}

fn eligible(record: &Record, page: &Page) -> bool {
    page.locks == 0 && (record.entire || page.default_pageable)
}

fn set_busy(base: u64, busy: bool) {
    if let Some(record) = STATE.lock().records.get_mut(&base) {
        record.busy = busy;
    }
}

/// Copia toda página antes de trocar qualquer alias (VAs baixas podem ser o
/// identity map do próprio staging) e passa a imagem para frames PFN.
fn migrate(base: u64) -> Result<(), KernelError> {
    let originals: Vec<(u64, Original)> = {
        let state = STATE.lock();
        let Some(record) = state.records.get(&base) else { return Ok(()) };
        if record.migrated {
            return Ok(());
        }
        record.pages.iter().map(|page| (page.va, page.original)).collect()
    };
    if originals.iter().any(|&(va, _)| io_pins::is_pinned(va)) {
        return Err(KernelError::new("cannot migrate an image with outstanding direct I/O"));
    }
    if smp::has_active_jobs() {
        return Err(KernelError::new("cannot remap driver image during an AP job"));
    }
    let mut frames = Vec::new();
    let mut mapped = 0;
    let result = (|| -> Result<(), KernelError> {
        for &(_, original) in &originals {
            let frame = pfn::alloc_page();
            if frame == 0 {
                return Err(KernelError::new("no frames for driver residency"));
            }
            frames.push(frame);
            physical::write_bytes(frame, &physical::read_bytes(original.frame, 4096));
        }
        for (index, &(va, original)) in originals.iter().enumerate() {
            if !paging::map_page(va, frames[index], original.flags, paging::MapOptions { nx: original.nx, ..Default::default() }) {
                return Err(KernelError::new("cannot map resident driver frame"));
            }
            mapped += 1;
        }
        Ok(())
    })();
    if let Err(error) = result {
        for &(va, original) in originals.iter().take(mapped) {
            if !paging::map_page(va, original.frame, original.flags, paging::MapOptions { nx: original.nx, ..Default::default() }) {
                return Err(KernelError::new("cannot restore driver mapping"));
            }
        }
        for frame in frames {
            pfn::free_page(frame);
        }
        return Err(error);
    }
    let mut state = STATE.lock();
    let record = state.records.get_mut(&base).ok_or_else(|| KernelError::new("driver image record vanished during migration"))?;
    for (index, page) in record.pages.iter_mut().enumerate() {
        page.frame = frames[index];
    }
    record.migrated = true;
    let vas: Vec<(u64, usize)> = record.pages.iter().enumerate().map(|(index, page)| (page.va, index)).collect();
    for (va, index) in vas {
        state.pages_by_va.insert(va, (base, index));
    }
    Ok(())
}

fn volume() -> Result<Arc<Ntfs>, KernelError> {
    ntfs::mounted().ok_or_else(|| KernelError::new("NTFS unavailable for driver paging"))
}

/// Arquivo de apoio no NTFS (tamanho da imagem).
fn backing(base: u64) -> Result<(), KernelError> {
    let pages = {
        let state = STATE.lock();
        let Some(record) = state.records.get(&base) else { return Ok(()) };
        if record.path.is_some() {
            return Ok(());
        }
        record.pages.len() as u64
    };
    let volume = volume()?;
    let path = loop {
        let identifier = {
            let mut state = STATE.lock();
            state.identifier += 1;
            state.identifier
        };
        let path = format!("/$opennt-image-page-{identifier}.sys");
        if !volume.exists(&path)? {
            break path;
        }
    };
    volume.create(&path, false, 6, pages * 4096)?;
    if let Err(error) = volume.resize(&path, pages * 4096) {
        let _ = volume.remove(&path);
        return Err(error);
    }
    if let Some(record) = STATE.lock().records.get_mut(&base) {
        record.path = Some(path);
    }
    Ok(())
}

/// Traz a página de volta do NTFS para um frame novo.
fn page_in(base: u64, index: usize) -> Result<(), KernelError> {
    let (saved, offset, original, path) = {
        let state = STATE.lock();
        let Some(record) = state.records.get(&base) else { return Ok(()) };
        let page = &record.pages[index];
        if page.frame != 0 {
            return Ok(());
        }
        (page.saved, page.offset, page.original, record.path.clone())
    };
    low_irql()?;
    if !saved {
        return Err(KernelError::new("page has no backing data"));
    }
    let frame = pfn::alloc_page();
    if frame == 0 {
        return Err(KernelError::new("no frame for driver page fault"));
    }
    let loaded = (|| -> Result<(), KernelError> {
        let path = path.ok_or_else(|| KernelError::new("page has no backing data"))?;
        let data = volume()?.read_range(&path, offset, 4096)?;
        let Some(data) = data.filter(|data| data.len() == 4096) else { return Err(KernelError::new("short driver paging read")) };
        physical::write_bytes(frame, &data);
        let va = { STATE.lock().records.get(&base).map(|record| record.pages[index].va).unwrap_or(0) };
        if !paging::map_page(va, frame, original.flags, paging::MapOptions { nx: original.nx, ..Default::default() }) {
            return Err(KernelError::new("driver page-in mapping failed"));
        }
        Ok(())
    })();
    if let Err(error) = loaded {
        pfn::free_page(frame);
        return Err(error);
    }
    if let Some(record) = STATE.lock().records.get_mut(&base) {
        record.pages[index].frame = frame;
        record.faults += 1;
    }
    Ok(())
}

fn fault_inner(address: u64, error: u32) -> Result<bool, KernelError> {
    if error & 13 != 0 || irql::get_irql() > 1 {
        return Ok(false);
    }
    let (base, index) = {
        let mut state = STATE.lock();
        let Some(&(base, index)) = state.pages_by_va.get(&(address & !4095)) else { return Ok(false) };
        let record = state.records.get_mut(&base).unwrap();
        let busy = record.busy;
        let page = &mut record.pages[index];
        if page.frame != 0 || busy || page.faulting {
            return Ok(false);
        }
        if error & 2 != 0 && page.original.flags & paging::PAGE_RW == 0 {
            return Ok(false);
        }
        if error & 16 != 0 && page.original.nx {
            return Ok(false);
        }
        // A recuperação pode despejar outra página desta imagem para obter
        // o frame: só a página em I/O fica protegida.
        page.faulting = true;
        (base, index)
    };
    let result = page_in(base, index);
    if let Some(record) = STATE.lock().records.get_mut(&base) {
        record.pages[index].faulting = false;
    }
    result.map(|()| true)
}

fn fault(address: u64, error: u32) -> FaultResult {
    match fault_inner(address, error) {
        Ok(true) => FaultResult::Resolved,
        Ok(false) => FaultResult::NotMine,
        Err(error) => {
            debug_print!("[image-paging] {}", error);
            FaultResult::InPageError(0xC000_0006)
        }
    }
}

fn resolve(address: u64) -> Result<Option<u64>, KernelError> {
    let located = {
        let state = STATE.lock();
        state.pages_by_va.get(&(address & !4095)).map(|&(base, index)| state.records[&base].pages[index].frame)
    };
    let Some(frame) = located else { return Ok(None) };
    if frame == 0 {
        if !fault_inner(address, 0)? {
            return Err(KernelError::new("unavailable pageable guest image"));
        }
        let state = STATE.lock();
        let &(base, index) = state.pages_by_va.get(&(address & !4095)).unwrap();
        return Ok(Some(state.records[&base].pages[index].frame + (address & 4095)));
    }
    Ok(Some(frame + (address & 4095)))
}

/// Despeja até `maximum` páginas elegíveis (de uma imagem ou de todas).
pub fn trim(maximum: u64, address: Option<u64>, from_pressure: bool) -> Result<u64, KernelError> {
    low_irql()?;
    {
        let state = STATE.lock();
        if state.reclaiming || smp::has_active_jobs() {
            return Ok(0);
        }
    }
    let only = match address {
        Some(address) => match record_for(address, false)? {
            Some(base) => Some(base),
            None => return Ok(0),
        },
        None => None,
    };
    let bases: Vec<u64> = {
        let mut state = STATE.lock();
        state.reclaiming = true;
        match only {
            Some(base) => alloc::vec![base],
            None => state.records.keys().copied().collect(),
        }
    };
    let mut count = 0;
    let result = (|| -> Result<(), KernelError> {
        for base in bases {
            if count >= maximum {
                break;
            }
            {
                let mut state = STATE.lock();
                let Some(record) = state.records.get_mut(&base) else { continue };
                if from_pressure && !record.migrated {
                    continue;
                }
                if record.busy || !record.pages.iter().any(|page| eligible(record, page)) {
                    continue;
                }
                record.busy = true;
            }
            let evicted = (|| -> Result<(), KernelError> {
                backing(base)?;
                migrate(base)?;
                let page_count = STATE.lock().records.get(&base).map_or(0, |record| record.pages.len());
                for index in 0..page_count {
                    if count >= maximum {
                        break;
                    }
                    let (frame, va, offset, path, ok) = {
                        let state = STATE.lock();
                        let record = &state.records[&base];
                        let page = &record.pages[index];
                        (page.frame, page.va, page.offset, record.path.clone(), page.frame != 0 && eligible(record, page))
                    };
                    if !ok || io_pins::is_pinned(va) {
                        continue;
                    }
                    let data = physical::read_bytes(frame, 4096);
                    let path = path.ok_or_else(|| KernelError::new("driver paging without backing"))?;
                    if volume()?.write(&path, offset, &data)? != 4096 {
                        return Err(KernelError::new("short driver paging write"));
                    }
                    // Marcador de software conserva a folha; o frame só é
                    // reutilizado depois da invalidação do TLB.
                    if !paging::map_page(va, 0, 0x200, paging::MapOptions::default()) {
                        return Err(KernelError::new("driver page-out mapping failed"));
                    }
                    if let Some(record) = STATE.lock().records.get_mut(&base) {
                        record.pages[index].frame = 0;
                        record.pages[index].saved = true;
                        record.evictions += 1;
                    }
                    pfn::free_page(frame);
                    count += 1;
                }
                Ok(())
            })();
            set_busy(base, false);
            evicted?;
        }
        Ok(())
    })();
    STATE.lock().reclaiming = false;
    result.map(|()| count)
}

/// MmPageEntireDriver: migra (se possível) e marca a imagem inteira como
/// paginável; devolve a base.
pub fn make_pageable(address: u64) -> Result<u64, KernelError> {
    low_irql()?;
    let Some(base) = record_for(address, true)? else { return Ok(0) };
    let migrated = STATE.lock().records.get(&base).is_some_and(|record| record.migrated);
    if !migrated && !smp::has_active_jobs() {
        set_busy(base, true);
        let result = migrate(base);
        set_busy(base, false);
        result?;
    }
    if let Some(record) = STATE.lock().records.get_mut(&base) {
        record.entire = true;
    }
    Ok(base)
}

/// MmResetDriverPaging: volta as páginas não pagináveis por padrão.
pub fn reset(address: u64) -> Result<u64, KernelError> {
    low_irql()?;
    let Some(base) = record_for(address, false)? else { return Ok(0) };
    let pending: Vec<usize> = {
        let state = STATE.lock();
        let record = &state.records[&base];
        if !record.entire {
            return Ok(0);
        }
        record.pages.iter().enumerate().filter(|(_, page)| !page.default_pageable).map(|(index, _)| index).collect()
    };
    set_busy(base, true);
    let result = pending.into_iter().try_for_each(|index| page_in(base, index));
    if result.is_ok() {
        if let Some(record) = STATE.lock().records.get_mut(&base) {
            record.entire = false;
        }
    }
    set_busy(base, false);
    result.map(|()| 0)
}

/// MmLockPagableCodeSection/DataSection: handle da seção que contém o
/// endereço, com as páginas residentes e travadas.
pub fn lock(address: u64) -> Result<u64, KernelError> {
    low_irql()?;
    let Some(base) = record_for(address, true)? else { return Ok(0) };
    let pointer = {
        let mut state = STATE.lock();
        let record = state.records.get_mut(&base).unwrap();
        let offset = address - base;
        let Some(section) = record.sections.iter().position(|section| {
            let (start, end) = section_extent(section);
            offset >= start && offset < end
        }) else {
            return Ok(0);
        };
        match record.section_handles.get(&section) {
            Some(&pointer) => pointer,
            None => {
                let pointer = guest::alloc_bytes(16);
                if pointer == 0 {
                    return Ok(0);
                }
                let (start, end) = section_extent(&record.sections[section]);
                let pages = record.pages.iter().enumerate().filter(|(_, page)| page.offset < end && page.offset + 4096 > start).map(|(index, _)| index).collect();
                record.section_handles.insert(section, pointer);
                state.handles.insert(pointer, Handle { base, count: 0, pages });
                pointer
            }
        }
    };
    lock_handle(pointer)?;
    Ok(pointer)
}

/// MmLockPagableSectionByHandle.
pub fn lock_handle(pointer: u64) -> Result<u64, KernelError> {
    low_irql()?;
    let (base, pages) = {
        let state = STATE.lock();
        let handle = state.handles.get(&pointer).ok_or_else(|| KernelError::new("invalid pageable section handle"))?;
        (handle.base, handle.pages.clone())
    };
    set_busy(base, true);
    let result = pages.iter().try_for_each(|&index| page_in(base, index));
    if result.is_ok() {
        let mut state = STATE.lock();
        if let Some(record) = state.records.get_mut(&base) {
            for &index in &pages {
                record.pages[index].locks += 1;
            }
        }
        if let Some(handle) = state.handles.get_mut(&pointer) {
            handle.count += 1;
        }
    }
    set_busy(base, false);
    result.map(|()| 0)
}

/// MmUnlockPagableImageSection.
pub fn unlock(pointer: u64) -> Result<u64, KernelError> {
    let mut state = STATE.lock();
    let handle = state.handles.get_mut(&pointer).filter(|handle| handle.count != 0).ok_or_else(|| KernelError::new("pageable section lock underflow"))?;
    handle.count -= 1;
    let (base, pages) = (handle.base, handle.pages.clone());
    if let Some(record) = state.records.get_mut(&base) {
        for index in pages {
            record.pages[index].locks -= 1;
        }
    }
    Ok(0)
}

/// Antes de jobs nativos nos APs, todas as páginas voltam a ser residentes.
fn prepare() -> Result<(), KernelError> {
    low_irql()?;
    let previous = {
        let mut state = STATE.lock();
        let previous = state.reclaiming;
        state.reclaiming = true;
        previous
    };
    let work: Vec<(u64, usize)> = STATE.lock().records.values().flat_map(|record| (0..record.pages.len()).map(move |index| (record.base, index))).collect();
    let result = work.into_iter().try_for_each(|(base, index)| {
        set_busy(base, true);
        let result = page_in(base, index);
        set_busy(base, false);
        result
    });
    STATE.lock().reclaiming = previous;
    result
}

fn reclaim(count: u64) -> Result<u64, KernelError> {
    trim(count, None, true)
}

/// Liberação da imagem (gancho `release_paging` do `loaded_images`):
/// restaura o staging, devolve os frames, os handles e o arquivo de apoio.
pub fn release_image(base: u64) {
    let Some(record) = STATE.lock().records.remove(&base) else { return };
    if record.migrated {
        if smp::has_active_jobs() {
            debug_print!("[image-paging] cannot release image residency during an AP job");
        }
        for page in &record.pages {
            if !paging::map_page(page.va, page.original.frame, page.original.flags, paging::MapOptions { nx: page.original.nx, ..Default::default() }) {
                debug_print!("[image-paging] cannot restore image staging mapping at {:#x}", page.va);
            }
            STATE.lock().pages_by_va.remove(&page.va);
            if page.frame != 0 {
                pfn::free_page(page.frame);
            }
        }
    }
    {
        let mut state = STATE.lock();
        for &pointer in record.section_handles.values() {
            state.handles.remove(&pointer);
            guest::free_bytes(pointer);
        }
    }
    if let (Some(path), Ok(volume)) = (record.path.as_deref(), volume()) {
        let _ = volume.remove(path);
    }
}

/// Estado observável de uma imagem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageState {
    pub entire: bool,
    pub migrated: bool,
    pub pages: usize,
    pub resident: usize,
    pub pageable: usize,
    pub locked: usize,
    pub faults: u64,
    pub evictions: u64,
    pub path: Option<String>,
}

pub fn state(address: u64) -> Option<ImageState> {
    let base = record_for(address, false).ok()??;
    let state = STATE.lock();
    let record = state.records.get(&base)?;
    Some(ImageState {
        entire: record.entire,
        migrated: record.migrated,
        pages: record.pages.len(),
        resident: record.pages.iter().filter(|page| page.frame != 0).count(),
        pageable: record.pages.iter().filter(|page| eligible(record, page)).count(),
        locked: record.pages.iter().filter(|page| page.locks != 0).count(),
        faults: record.faults,
        evictions: record.evictions,
        path: record.path.clone(),
    })
}

pub fn init() -> Result<(), KernelError> {
    {
        let mut state = STATE.lock();
        if state.initialized {
            return Ok(());
        }
        state.initialized = true;
    }
    page_residency::register("driver images", Provider { fault, resolve, reclaim, prepare, resolve_range: None })
}
