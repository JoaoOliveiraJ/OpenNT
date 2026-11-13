//! Armazenamento do pool executivo.
//!
//! Independe da política de falha/SEH da ABI NT. Alocações pequenas
//! compartilham páginas sem cruzar seus limites. O conteúdo paginável tem
//! apoio real no NTFS (`paging_volume`); o não paginável sempre possui seus
//! frames do PFN.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::page_residency::{self, FaultResult, Provider};
use super::paging::{self, MapOptions};
use super::{io_pins, memory_map as map, paging_volume, pfn};
use crate::hal::physical;
use crate::ntos::ke::{irql, smp};
use crate::rtl::{KernelError, SpinLock};

/// Cobrança de quota transferida ao bloco; liberada no free.
pub struct PoolQuota {
    pub process_pointer: u64,
    /// Contador cobrado: paginável (true) ou não paginável.
    pub paged: bool,
    pub bytes: u64,
    pub release: fn(u64, bool, u64),
}

struct Page {
    va: u64,
    offset: u64,
    frame: u64,
    saved: bool,
    faulting: bool,
}

struct Region {
    base: u64,
    bytes: u64,
    paged: bool,
    nx: bool,
    cold: bool,
    pages: Vec<Page>,
    free: Vec<(u64, u64)>,
    live: u64,
    busy: bool,
    path: Option<String>,
}

struct Record {
    base: u64,
    bytes: u64,
    rounded: u64,
    offset: u64,
    tag: u32,
    priority: u32,
    region: u64,
    quota: Option<PoolQuota>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TagCounts {
    pub paged_bytes: i64,
    pub nonpaged_bytes: i64,
    pub allocations: u64,
    pub frees: u64,
    pub live: i64,
}

struct Pool {
    ranges: Vec<(u64, u64)>,
    regions: BTreeMap<u64, Region>,
    retired: BTreeMap<u64, Region>,
    pages_by_va: BTreeMap<u64, (u64, usize)>,
    allocations: BTreeMap<u64, Record>,
    tags: BTreeMap<u32, TagCounts>,
    initialized: bool,
    identifier: u64,
    next_region: u64,
}

static POOL: SpinLock<Pool> = SpinLock::new(Pool {
    ranges: Vec::new(),
    regions: BTreeMap::new(),
    retired: BTreeMap::new(),
    pages_by_va: BTreeMap::new(),
    allocations: BTreeMap::new(),
    tags: BTreeMap::new(),
    initialized: false,
    identifier: 0,
    next_region: 1,
});

fn check_irql(paged: bool) -> Result<(), KernelError> {
    if irql::get_irql() > if paged { 1 } else { 2 } {
        return Err(KernelError::new("kernel pool operation at invalid IRQL"));
    }
    Ok(())
}

impl Pool {
    fn return_range(&mut self, base: u64, size: u64) {
        self.ranges.push((base, size));
        self.ranges.sort();
        let mut index = 0;
        while index + 1 < self.ranges.len() {
            if self.ranges[index].0 + self.ranges[index].1 == self.ranges[index + 1].0 {
                self.ranges[index].1 += self.ranges[index + 1].1;
                self.ranges.remove(index + 1);
            } else {
                index += 1;
            }
        }
    }

    fn take_range(&mut self, size: u64) -> Option<u64> {
        let index = self.ranges.iter().position(|&(_, length)| length >= size)?;
        let range = &mut self.ranges[index];
        let base = range.0;
        range.0 += size;
        range.1 -= size;
        if range.1 == 0 {
            self.ranges.remove(index);
        }
        Some(base)
    }

    fn account(&mut self, tag: u32, paged: bool, bytes: u64, delta: i64) {
        let counts = self.tags.entry(tag).or_default();
        if paged {
            counts.paged_bytes += delta * bytes as i64;
        } else {
            counts.nonpaged_bytes += delta * bytes as i64;
        }
        if delta > 0 {
            counts.allocations += 1;
        } else {
            counts.frees += 1;
        }
        counts.live += delta;
    }

    fn create_region(&mut self, bytes: u64, paged: bool, nx: bool, cold: bool) -> Option<u64> {
        let base = self.take_range(bytes)?;
        let mut pages: Vec<Page> = Vec::new();
        let mut failed = false;
        for offset in (0..bytes).step_by(4096) {
            let frame = pfn::alloc_page();
            if frame == 0 {
                failed = true;
                break;
            }
            pages.push(Page { va: base + offset, offset, frame, saved: false, faulting: false });
            if !paging::map_page(base + offset, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions { nx, ..Default::default() }) {
                failed = true;
                break;
            }
        }
        if failed {
            for page in &pages {
                paging::unmap_page(page.va, MapOptions::default());
                pfn::free_page(page.frame);
            }
            self.return_range(base, bytes);
            return None;
        }
        let id = self.next_region;
        self.next_region += 1;
        for (index, page) in pages.iter().enumerate() {
            self.pages_by_va.insert(page.va, (id, index));
        }
        self.regions.insert(id, Region { base, bytes, paged, nx, cold, pages, free: alloc::vec![(0, bytes)], live: 0, busy: false, path: None });
        Some(id)
    }

    /// Arquivo de apoio no volume de paginação.
    fn backing(&mut self, id: u64) -> Result<(), KernelError> {
        if self.regions[&id].path.is_some() {
            return Ok(());
        }
        let volume = paging_volume::current().ok_or_else(|| KernelError::new("NTFS unavailable for pool paging"))?;
        let path = loop {
            self.identifier += 1;
            let path = alloc::format!("/$opennt-pool-page-{}.sys", self.identifier);
            if !volume.exists(&path) {
                break path;
            }
        };
        let bytes = self.regions[&id].bytes;
        volume.create(&path, false, 6, bytes)?;
        if let Err(error) = volume.resize(&path, bytes) {
            let _ = volume.remove(&path);
            return Err(error);
        }
        self.regions.get_mut(&id).unwrap().path = Some(path);
        Ok(())
    }

    fn page_in(&mut self, id: u64, index: usize) -> Result<(), KernelError> {
        let region = &self.regions[&id];
        let page = &region.pages[index];
        if page.frame != 0 {
            return Ok(());
        }
        check_irql(true)?;
        let (Some(path), true) = (region.path.clone(), page.saved) else {
            return Err(KernelError::new("pool page has no backing"));
        };
        let volume = paging_volume::current().ok_or_else(|| KernelError::new("NTFS unavailable for pool paging"))?;
        let frame = pfn::alloc_page();
        if frame == 0 {
            return Err(KernelError::new("no frame for pool page-in"));
        }
        let (va, offset, nx) = (page.va, page.offset, region.nx);
        let result = volume.read_range(&path, offset, 4096).and_then(|data| {
            if data.len() != 4096 {
                return Err(KernelError::new("short pool paging read"));
            }
            physical::write_bytes(frame, &data);
            if !paging::map_page(va, frame, paging::PAGE_PRESENT | paging::PAGE_RW, MapOptions { nx, ..Default::default() }) {
                return Err(KernelError::new("pool page-in mapping failed"));
            }
            Ok(())
        });
        if let Err(error) = result {
            pfn::free_page(frame);
            return Err(error);
        }
        self.regions.get_mut(&id).unwrap().pages[index].frame = frame;
        Ok(())
    }

    fn fault_page(&mut self, address: u64, error: u32) -> bool {
        if error & 13 != 0 || irql::get_irql() > 1 {
            return false;
        }
        let Some(&(id, index)) = self.pages_by_va.get(&(address & !4095)) else { return false };
        let Some(region) = self.regions.get(&id) else { return false };
        let page = &region.pages[index];
        if page.frame != 0 || !region.paged || region.busy || page.faulting || (error & 16 != 0 && region.nx) {
            return false;
        }
        self.regions.get_mut(&id).unwrap().pages[index].faulting = true;
        let resolved = self.page_in(id, index).is_ok();
        self.regions.get_mut(&id).unwrap().pages[index].faulting = false;
        resolved
    }

    fn destroy(&mut self, region: Region) -> Result<(), KernelError> {
        if let (Some(path), Some(volume)) = (&region.path, paging_volume::current()) {
            let _ = volume.remove(path);
        }
        for page in &region.pages {
            if !paging::unmap_page(page.va, MapOptions::default()) {
                return Err(KernelError::new("cannot unmap pool page"));
            }
            self.pages_by_va.remove(&page.va);
            if page.frame != 0 && !pfn::free_page(page.frame) {
                return Err(KernelError::new("pool free lost frame ownership"));
            }
        }
        self.return_range(region.base, region.bytes);
        Ok(())
    }

    /// Os APs só executam jobs próprios e recarregam CR3 antes de cada um.
    /// Até os jobs atuais terminarem, regiões retiradas mantêm mapeamento,
    /// tabelas, VA e frames; o próximo free/alocação as recolhe.
    fn reap(&mut self) -> u64 {
        if smp::has_active_jobs() || irql::get_irql() > 2 {
            return 0;
        }
        let ids: Vec<u64> = self.retired.keys().copied().collect();
        let mut count = 0;
        for id in ids {
            if self.retired[&id].paged && irql::get_irql() > 1 {
                continue;
            }
            let region = self.retired.remove(&id).unwrap();
            if self.destroy(region).is_ok() {
                count += 1;
            }
        }
        count
    }
}

fn fit(region: &Region, bytes: u64, alignment: u64) -> Option<(usize, u64)> {
    region.free.iter().enumerate().find_map(|(index, &(offset, length))| {
        let aligned = offset.div_ceil(alignment) * alignment;
        (aligned + bytes <= offset + length).then_some((index, aligned))
    })
}

/// Limiares de reserva são política, não emulação de contadores privados.
/// Prioridade alta pode consumir a última página disponível.
fn reserve_for(priority: u32) -> Result<u64, KernelError> {
    let base = priority & !9;
    if ![0, 16, 32].contains(&base) || ![0, 8, 9].contains(&(priority & 15)) {
        return Err(KernelError::new("invalid pool priority"));
    }
    if base == 32 {
        return Ok(0);
    }
    let divisor = if base == 0 { 32 } else { 128 };
    Ok((if base == 0 { 256 } else { 64 }).min(pfn::total_count().div_ceil(divisor).max(1)))
}

/// Opções de [`allocate`].
#[derive(Clone, Copy, Debug)]
pub struct AllocateOptions {
    pub paged: bool,
    pub nx: bool,
    pub alignment: u64,
    pub tag: u32,
    pub priority: u32,
    pub zero: bool,
    pub cold: bool,
    pub prefix_bytes: u64,
    pub suffix_bytes: u64,
}

impl Default for AllocateOptions {
    fn default() -> Self {
        Self { paged: false, nx: true, alignment: 16, tag: 0, priority: 16, zero: false, cold: false, prefix_bytes: 0, suffix_bytes: 0 }
    }
}

/// Endereço do bloco, ou 0 sem memória.
pub fn allocate(bytes: u64, options: AllocateOptions) -> Result<u64, KernelError> {
    check_irql(options.paged)?;
    init();
    POOL.lock().reap();
    if options.alignment != 16 && options.alignment != 64 {
        return Err(KernelError::new("unsupported pool alignment"));
    }
    // O pool com quota reserva cabeçalho/alinhamento dentro do bloco.
    if ![0, 16, 64].contains(&options.prefix_bytes) || ![0, 16].contains(&options.suffix_bytes) || options.prefix_bytes % options.alignment != 0 {
        return Err(KernelError::new("invalid pool prefix/suffix"));
    }
    let reserve = reserve_for(options.priority)?;
    let rounding = if options.prefix_bytes != 0 { 16 } else { options.alignment };
    let Some(rounded) = bytes.max(1).checked_next_multiple_of(rounding).map(|value| value + options.prefix_bytes + options.suffix_bytes) else {
        return Ok(0);
    };
    if rounded > map::KERNEL_POOL_TOP - map::KERNEL_POOL_BASE {
        return Ok(0);
    }
    let mut chosen = None;
    let needed = {
        let pool = POOL.lock();
        if rounded <= 4096 {
            for (&id, region) in &pool.regions {
                if region.bytes != 4096 || region.busy || region.paged != options.paged || region.nx != options.nx || region.cold != options.cold {
                    continue;
                }
                if let Some(choice) = fit(region, rounded, options.alignment) {
                    chosen = Some((id, choice));
                    break;
                }
            }
        }
        match chosen {
            Some((id, _)) => (pool.regions[&id].pages[0].frame == 0) as u64,
            None => rounded.div_ceil(4096),
        }
    };
    if pfn::free_count() < needed + reserve {
        page_residency::reclaim(needed + reserve - pfn::free_count());
    }
    if reserve != 0 && pfn::free_count() < needed + reserve {
        return Ok(0);
    }
    let mut pool = POOL.lock();
    let (id, (free_index, offset)) = match chosen {
        Some(choice) => choice,
        None => match pool.create_region(rounded.div_ceil(4096) * 4096, options.paged, options.nx, options.cold) {
            Some(id) => (id, (0, 0)),
            None => return Ok(0),
        },
    };
    // Prende a região enquanto faz page-in e inicializa.
    pool.regions.get_mut(&id).unwrap().busy = true;
    let first = (offset / 4096) as usize;
    let last = ((offset + rounded - 1) / 4096) as usize;
    let mut result = Ok(());
    for index in first..=last {
        result = pool.page_in(id, index);
        if result.is_err() {
            break;
        }
    }
    if result.is_ok() && options.zero {
        let region = &pool.regions[&id];
        let mut position = offset + options.prefix_bytes;
        let end = offset + options.prefix_bytes + bytes;
        while position < end {
            let page = &region.pages[(position / 4096) as usize];
            let within = position % 4096;
            let length = (4096 - within).min(end - position);
            physical::zero(page.frame + within, length as usize);
            position += length;
        }
    }
    pool.regions.get_mut(&id).unwrap().busy = false;
    if result.is_err() {
        if pool.regions[&id].live == 0 {
            let region = pool.regions.remove(&id).unwrap();
            let _ = pool.destroy(region);
        }
        return Ok(0);
    }
    let region = pool.regions.get_mut(&id).unwrap();
    let (range_offset, range_bytes) = region.free[free_index];
    let mut pieces = Vec::new();
    if offset > range_offset {
        pieces.push((range_offset, offset - range_offset));
    }
    let end = offset + rounded;
    if end < range_offset + range_bytes {
        pieces.push((end, range_offset + range_bytes - end));
    }
    region.free.splice(free_index..=free_index, pieces);
    region.live += 1;
    let paged = region.paged;
    let base = region.base + offset + options.prefix_bytes;
    pool.allocations.insert(base, Record { base, bytes, rounded, offset, tag: options.tag, priority: options.priority, region: id, quota: None });
    pool.account(options.tag, paged, bytes, 1);
    Ok(base)
}

pub fn free(pointer: u64, tag: Option<u32>) -> Result<(), KernelError> {
    let quota = {
        let mut pool = POOL.lock();
        let Some(record) = pool.allocations.get(&pointer) else {
            return Err(KernelError::new("invalid or duplicate pool free"));
        };
        let id = record.region;
        let paged = pool.regions.get(&id).map_or(false, |region| region.paged);
        check_irql(paged)?;
        if tag.is_some_and(|tag| tag != record.tag) {
            return Err(KernelError::new("pool tag mismatch"));
        }
        let record = pool.allocations.remove(&pointer).unwrap();
        let region = pool.regions.get_mut(&id).unwrap();
        // Uma slab não vazia mantém o mapeamento físico.
        if region.live == 1 {
            let mut region = pool.regions.remove(&id).unwrap();
            region.live = 0;
            if smp::has_active_jobs() {
                region.busy = true;
                pool.retired.insert(id, region);
            } else {
                pool.destroy(region)?;
            }
        } else {
            region.free.push((record.offset, record.rounded));
            region.free.sort();
            let mut index = 0;
            while index + 1 < region.free.len() {
                if region.free[index].0 + region.free[index].1 == region.free[index + 1].0 {
                    region.free[index].1 += region.free[index + 1].1;
                    region.free.remove(index + 1);
                } else {
                    index += 1;
                }
            }
            region.live -= 1;
        }
        pool.account(record.tag, paged, record.bytes, -1);
        record.quota
    };
    // A cobrança segue o bloco, mesmo se outra thread/processo fizer o free.
    if let Some(quota) = quota {
        (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
    }
    POOL.lock().reap();
    Ok(())
}

/// Transfere ao bloco uma cobrança já confirmada.
pub fn attach_quota(pointer: u64, quota: PoolQuota) -> Result<(), KernelError> {
    let mut pool = POOL.lock();
    match pool.allocations.get_mut(&pointer) {
        Some(record) if record.quota.is_none() && quota.bytes == record.rounded => {
            record.quota = Some(quota);
            Ok(())
        }
        _ => Err(KernelError::new("invalid pool quota ownership")),
    }
}

/// Um pacote devolvido ao cache deixa de cobrar o processo anterior.
pub fn return_quota(pointer: u64) -> Result<bool, KernelError> {
    let quota = {
        let mut pool = POOL.lock();
        let Some(record) = pool.allocations.get(&pointer) else {
            return Err(KernelError::new("quota return requires a live pool allocation"));
        };
        let paged = pool.regions.get(&record.region).map_or(false, |region| region.paged);
        check_irql(paged)?;
        pool.allocations.get_mut(&pointer).unwrap().quota.take()
    };
    match quota {
        Some(quota) => {
            (quota.release)(quota.process_pointer, quota.paged, quota.bytes);
            Ok(true)
        }
        None => Ok(false),
    }
}

#[derive(Clone, Debug)]
pub struct AllocationInfo {
    pub base: u64,
    pub bytes: u64,
    pub rounded: u64,
    pub quota_owner: u64,
    pub quota_bytes: u64,
    pub tag: u32,
    pub priority: u32,
    pub paged: bool,
    pub nx: bool,
    pub resident: usize,
    pub pages: usize,
    pub path: Option<String>,
}

pub fn info(pointer: u64) -> Option<AllocationInfo> {
    let pool = POOL.lock();
    let record = pool.allocations.get(&pointer)?;
    let region = pool.regions.get(&record.region)?;
    Some(AllocationInfo {
        base: record.base,
        bytes: record.bytes,
        rounded: record.rounded,
        quota_owner: record.quota.as_ref().map_or(0, |quota| quota.process_pointer),
        quota_bytes: record.quota.as_ref().map_or(0, |quota| quota.bytes),
        tag: record.tag,
        priority: record.priority,
        paged: region.paged,
        nx: region.nx,
        resident: region.pages.iter().filter(|page| page.frame != 0).count(),
        pages: region.pages.len(),
        path: region.path.clone(),
    })
}

#[derive(Clone, Debug)]
pub struct PoolStats {
    pub live: usize,
    pub regions: usize,
    pub pages: usize,
    pub retired_regions: usize,
    pub resident: usize,
    pub tags: Vec<(u32, TagCounts)>,
}

pub fn stats() -> PoolStats {
    let pool = POOL.lock();
    PoolStats {
        live: pool.allocations.len(),
        regions: pool.regions.len(),
        pages: pool.pages_by_va.len(),
        retired_regions: pool.retired.len(),
        resident: pool.regions.values().map(|region| region.pages.iter().filter(|page| page.frame != 0).count()).sum(),
        tags: pool.tags.iter().map(|(&tag, &counts)| (tag, counts)).collect(),
    }
}

pub fn owns(pointer: u64) -> bool {
    POOL.lock().allocations.contains_key(&pointer)
}

/// Pagina páginas pagináveis para o volume. Reentrância (pool já em uso)
/// não recupera nada.
pub fn trim(count: u64) -> Result<u64, KernelError> {
    check_irql(true)?;
    if smp::has_active_jobs() {
        return Ok(0);
    }
    let Some(mut pool) = POOL.try_lock() else { return Ok(0) };
    let mut freed = 0;
    // Dicas frias afetam a seleção, nunca a permissão ou a preservação.
    let mut ids: Vec<(bool, u64)> = pool.regions.iter().map(|(&id, region)| (region.cold, id)).collect();
    ids.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, id) in ids {
        if freed >= count {
            break;
        }
        let (paged, busy) = { let region = &pool.regions[&id]; (region.paged, region.busy) };
        if !paged || busy {
            continue;
        }
        pool.regions.get_mut(&id).unwrap().busy = true;
        let result = (|| -> Result<(), KernelError> {
            for index in 0..pool.regions[&id].pages.len() {
                if freed >= count {
                    break;
                }
                let (frame, faulting, va, offset) = {
                    let page = &pool.regions[&id].pages[index];
                    (page.frame, page.faulting, page.va, page.offset)
                };
                if frame == 0 || faulting || io_pins::is_pinned(va) {
                    continue;
                }
                pool.backing(id)?;
                let volume = paging_volume::current().ok_or_else(|| KernelError::new("NTFS unavailable for pool paging"))?;
                let data = physical::read_bytes(frame, 4096);
                let path = pool.regions[&id].path.clone().unwrap();
                if volume.write(&path, offset, &data)? != 4096 {
                    return Err(KernelError::new("short pool paging write"));
                }
                if !paging::map_page(va, 0, 0x200, MapOptions::default()) {
                    return Err(KernelError::new("pool page-out mapping failed"));
                }
                let page = &mut pool.regions.get_mut(&id).unwrap().pages[index];
                page.frame = 0;
                page.saved = true;
                if !pfn::free_page(frame) {
                    return Err(KernelError::new("pool page-out lost frame ownership"));
                }
                freed += 1;
            }
            Ok(())
        })();
        pool.regions.get_mut(&id).unwrap().busy = false;
        result?;
    }
    Ok(freed)
}

fn prepare() -> Result<(), KernelError> {
    let mut pool = POOL.lock();
    pool.reap();
    check_irql(true)?;
    let ids: Vec<u64> = pool.regions.keys().copied().collect();
    for id in ids {
        pool.regions.get_mut(&id).unwrap().busy = true;
        let mut result = Ok(());
        for index in 0..pool.regions[&id].pages.len() {
            result = pool.page_in(id, index);
            if result.is_err() {
                break;
            }
        }
        pool.regions.get_mut(&id).unwrap().busy = false;
        result?;
    }
    Ok(())
}

fn provider_fault(address: u64, error: u32) -> FaultResult {
    match POOL.try_lock() {
        Some(mut pool) => {
            if pool.fault_page(address, error) { FaultResult::Resolved } else { FaultResult::NotMine }
        }
        None => FaultResult::NotMine,
    }
}

fn provider_resolve(address: u64) -> Result<Option<u64>, KernelError> {
    let mut pool = POOL.lock();
    let Some(&(id, index)) = pool.pages_by_va.get(&(address & !4095)) else { return Ok(None) };
    if pool.regions[&id].pages[index].frame == 0 && !pool.fault_page(address, 0) {
        return Err(KernelError::new("unavailable paged pool address"));
    }
    Ok(Some(pool.regions[&id].pages[index].frame + (address & 4095)))
}

pub fn reap() -> u64 {
    POOL.lock().reap()
}

pub fn init() {
    {
        let mut pool = POOL.lock();
        if pool.initialized {
            return;
        }
        pool.initialized = true;
        pool.ranges = alloc::vec![(map::KERNEL_POOL_BASE, map::KERNEL_POOL_TOP - map::KERNEL_POOL_BASE)];
    }
    let _ = page_residency::register(
        "executive pool",
        Provider {
            fault: provider_fault,
            resolve: provider_resolve,
            reclaim: trim,
            prepare,
            resolve_range: Some((map::KERNEL_POOL_BASE, map::KERNEL_POOL_TOP)),
        },
    );
}
