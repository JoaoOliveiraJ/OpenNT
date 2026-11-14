//! Pool de sessão: PagedPoolSession e NonPagedPoolSession.
//!
//! Como o ExAllocateHeapPool/ExFreeHeapPool do Windows 10 19041:
//!
//! - **PagedPoolSession** (`PoolType & 0x21 == 0x21`: 33 e o 37 alinhado ao
//!   cache) sai do heap da sessão do processo corrente
//!   (EPROCESS.Session->HeapState), em VA de sessão: a VA dinâmica da sessão,
//!   mapeada só nas raízes dela. Outra sessão, na mesma VA, não vê nada (ou
//!   vê o próprio pool). Aqui o heap é um alocador por sessão: blocos
//!   pequenos (até 0xFE0 bytes) em regiões de 64 KB, alinhados a 16 (64 no
//!   alinhado ao cache), e os maiores numa faixa própria de páginas; os
//!   frames ficam residentes (o pool paginado de sessão do OpenNT não pagina).
//! - **NonPagedPoolSession** (32, 36 e os Nx 544/548) sai do pool não
//!   paginado global, uma VA de sistema que toda sessão vê; só a
//!   contabilidade é de sessão.
//! - **Contabilidade**: o bloco de um tipo de sessão leva o bit 0x20 no tipo
//!   do POOL_HEADER e a tag vai para a tabela de sessão (ExpSessionPoolTrackTable,
//!   a VA de sessão do MM_SESSION_SPACE.PoolTags: 0x100 POOL_TRACKER_TABLE
//!   com o hash `((tag * 0x9E5F) >> 32 ^ tag * 0x9E5F) & 0xFF` e sondagem
//!   linear), a da sessão corrente: alocar soma Allocs e Bytes (paginado em
//!   +0x20/+0x28, não paginado em +0x08/+0x10), liberar soma Frees
//!   (+0x30/+0x18) e subtrai os bytes. Os bytes de um bloco pequeno são os
//!   do bloco com o cabeçalho, `(bytes + 0x1F) & !0xF`; os de um grande, as
//!   páginas. A tabela cheia iria para a tabela de expansão do NT, que o
//!   OpenNT não tem: a tag fica sem contabilidade.
//! - **Liberação**: um endereço de sessão é liberado no heap da sessão
//!   corrente; se ela não é dona do bloco (outra sessão, nenhuma sessão,
//!   endereço que não é início de bloco), o 19041 não acha o heap do
//!   segmento e para com BAD_POOL_CALLER (0xC2) com os parâmetros
//!   (0, 0, endereço, 0) — [`check_free`] devolve esse veredito.
//! - **Fim da sessão** ([`release_session`], do MiDereferenceSessionFinal):
//!   o heap inteiro some com o espaço de sessão, com os blocos que ainda
//!   estavam vivos; a tabela de tags morre com as páginas do
//!   MM_SESSION_SPACE (o MiCheckSessionPoolAllocations do 19041 não para o
//!   sistema por blocos vivos).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::{memory_map as map, pfn, session};
use crate::hal::physical;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::PoolTrackerTable;
use crate::rtl::{KernelError, SpinLock};

const PAGE: u64 = 0x1000;
/// SessionPoolMask: o bit de sessão do POOL_TYPE.
pub const SESSION_POOL_MASK: u32 = 0x20;
/// Maior bloco servido de uma região compartilhada (o resto vai para páginas
/// próprias, o big pool do NT).
const SMALL_LIMIT: u64 = 0xFE0;
/// Tamanho de uma região de blocos pequenos.
const REGION_SIZE: u64 = 0x1_0000;
/// ExpSessionPoolTrackTable: o MM_SESSION_SPACE.PoolTags na VA de sessão.
const TRACK_TABLE: u64 = map::SESSION_CORE_BASE + 0x1000;
/// ExpSessionPoolTrackTableSize (a máscara é o tamanho - 1).
const TRACK_ENTRIES: u64 = 0x100;
/// BAD_POOL_CALLER.
const BAD_POOL_CALLER: u32 = 0xC2;

struct Region {
    frames: Vec<u64>,
    /// Faixas livres (base, tamanho), ordenadas.
    free: Vec<(u64, u64)>,
    live: u64,
    /// Região de um bloco grande só.
    large: bool,
}

struct Block {
    region: u64,
    span: (u64, u64),
    tag: u32,
    tracked: u64,
}

#[derive(Default)]
struct Pool {
    regions: BTreeMap<u64, Region>,
    blocks: BTreeMap<u64, Block>,
}

/// O heap paginado de cada sessão, pela VA global do MM_SESSION_SPACE.
static POOLS: SpinLock<BTreeMap<u64, Pool>> = SpinLock::new(BTreeMap::new());
/// Blocos NonPagedPoolSession vivos: endereço -> (tag, bytes contados).
static NONPAGED: SpinLock<BTreeMap<u64, (u32, u64)>> = SpinLock::new(BTreeMap::new());

/// O tipo é de sessão.
pub fn is_session_type(pool_type: u32) -> bool {
    pool_type & SESSION_POOL_MASK != 0
}

/// O tipo é PagedPoolSession (o heap da sessão).
pub fn is_paged_session_type(pool_type: u32) -> bool {
    pool_type & 0x21 == 0x21
}

/// Os bytes que a tabela de tags conta para um bloco.
pub fn tracked_bytes(bytes: u64) -> u64 {
    if bytes <= SMALL_LIMIT { (bytes + 0x1F) & !0xF } else { bytes.div_ceil(PAGE) * PAGE }
}

/// O índice inicial da tag na tabela de sessão.
pub fn track_index(tag: u32) -> u64 {
    let product = tag as u64 * 0x9E5F;
    (((product >> 32) as u32 ^ product as u32) as u64) & (TRACK_ENTRIES - 1)
}

fn tracker(index: u64) -> &'static PoolTrackerTable {
    // SAFETY: entrada da tabela de tags da sessão corrente (PoolTags, nas
    // páginas do MM_SESSION_SPACE mapeadas em toda raiz da sessão).
    unsafe { PoolTrackerTable::at(TRACK_TABLE + index * core::mem::size_of::<PoolTrackerTable>() as u64) }
}

/// A entrada da tag na tabela da sessão corrente (criada se `claim`).
fn tracker_entry(tag: u32, claim: bool) -> Option<&'static PoolTrackerTable> {
    if session::current() == 0 {
        return None;
    }
    let start = track_index(tag);
    let mut index = start;
    loop {
        let entry = tracker(index);
        let key = entry.key.get() as u32;
        if key == tag {
            return Some(entry);
        }
        if key == 0 {
            if !claim {
                return None;
            }
            match entry.key.atomic().compare_exchange(0, tag as i32, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(entry),
                Err(observed) if observed as u32 == tag => return Some(entry),
                Err(_) => {}
            }
        }
        index = (index + 1) & (TRACK_ENTRIES - 1);
        if index == start {
            return None;
        }
    }
}

fn account_allocation(tag: u32, paged: bool, bytes: u64) {
    if let Some(entry) = tracker_entry(tag, true) {
        let (allocs, total) = if paged { (&entry.paged_allocs, &entry.paged_bytes) } else { (&entry.non_paged_allocs, &entry.non_paged_bytes) };
        allocs.atomic().fetch_add(1, Ordering::SeqCst);
        total.atomic().fetch_add(bytes, Ordering::SeqCst);
    }
}

fn account_free(tag: u32, paged: bool, bytes: u64) {
    if let Some(entry) = tracker_entry(tag, true) {
        let (frees, total) = if paged { (&entry.paged_frees, &entry.paged_bytes) } else { (&entry.non_paged_frees, &entry.non_paged_bytes) };
        frees.atomic().fetch_add(1, Ordering::SeqCst);
        total.atomic().fetch_sub(bytes, Ordering::SeqCst);
    }
}

/// Contabilidade da tag na sessão corrente: (PagedAllocs, PagedFrees,
/// PagedBytes, NonPagedAllocs, NonPagedFrees, NonPagedBytes).
pub fn tag_counts(tag: u32) -> Option<[u64; 6]> {
    let entry = tracker_entry(tag, false)?;
    Some([entry.paged_allocs.get(), entry.paged_frees.get(), entry.paged_bytes.get(), entry.non_paged_allocs.get(), entry.non_paged_frees.get(), entry.non_paged_bytes.get()])
}

/// Primeira faixa livre de `free` com `size` bytes alinhados a `alignment`.
fn take(free: &mut Vec<(u64, u64)>, size: u64, alignment: u64) -> Option<u64> {
    let index = free.iter().position(|&(base, length)| {
        let start = base.next_multiple_of(alignment);
        start - base + size <= length
    })?;
    let (base, length) = free.remove(index);
    let start = base.next_multiple_of(alignment);
    if start > base {
        free.insert(index, (base, start - base));
    }
    let end = start + size;
    if end < base + length {
        free.push((end, base + length - end));
        free.sort_unstable();
    }
    Some(start)
}

fn give_back(free: &mut Vec<(u64, u64)>, base: u64, size: u64) {
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
}

/// Uma região nova de `size` bytes na VA dinâmica da sessão, com frames
/// zerados e mapeados nas raízes dela.
fn new_region(pointer: u64, size: u64, large: bool) -> Result<(u64, Region), KernelError> {
    let base = session::reserve_dynamic(pointer, size).ok_or_else(|| KernelError::with_status("session pool VA exhausted", 0xC000_009A))?;
    let mut frames = Vec::new();
    let mut failure = None;
    for page in 0..size / PAGE {
        let frame = pfn::alloc_page();
        if frame == 0 {
            failure = Some(KernelError::with_status("no frame for the session pool", 0xC000_009A));
            break;
        }
        physical::zero(frame, PAGE as usize);
        frames.push(frame);
        if let Err(error) = session::map_page(pointer, base + page * PAGE, frame, true, false) {
            failure = Some(error);
            break;
        }
    }
    if let Some(error) = failure {
        let pages: Vec<u64> = (0..frames.len() as u64).map(|page| base + page * PAGE).collect();
        let _ = session::unmap_pages(pointer, &pages);
        for frame in frames {
            pfn::free_page(frame);
        }
        session::release_dynamic(pointer, base, size);
        return Err(error);
    }
    Ok((base, Region { frames, free: alloc::vec![(base, size)], live: 0, large }))
}

/// PagedPoolSession: um bloco do heap da sessão corrente. `None` fora de
/// uma sessão (o chamador recusa o pedido).
pub fn allocate_paged(bytes: u64, tag: u32, alignment: u64, zero: bool) -> Option<Result<u64, KernelError>> {
    let pointer = session::current();
    if pointer == 0 {
        return None;
    }
    let bytes = bytes.max(1);
    let (size, alignment, large) = if bytes > SMALL_LIMIT { (bytes.div_ceil(PAGE) * PAGE, PAGE, true) } else { (bytes.next_multiple_of(16), alignment.max(16), false) };
    let existing = if large {
        None
    } else {
        let mut pools = POOLS.lock();
        let pool = pools.entry(pointer).or_default();
        pool.regions.iter_mut().filter(|(_, region)| !region.large).find_map(|(&base, region)| take(&mut region.free, size, alignment).map(|address| (base, address)))
    };
    let (region_base, address) = match existing {
        Some(found) => found,
        None => {
            let (base, mut region) = match new_region(pointer, if large { size } else { REGION_SIZE }, large) {
                Ok(created) => created,
                Err(error) => return Some(Err(error)),
            };
            let address = take(&mut region.free, size, alignment).unwrap_or(base);
            POOLS.lock().entry(pointer).or_default().regions.insert(base, region);
            (base, address)
        }
    };
    let tracked = tracked_bytes(bytes);
    {
        let mut pools = POOLS.lock();
        let pool = pools.entry(pointer).or_default();
        let Some(region) = pool.regions.get_mut(&region_base) else { return Some(Err(KernelError::new("session pool region vanished"))) };
        region.live += 1;
        if zero {
            for offset in (0..size).step_by(16) {
                let at = address + offset;
                let frame = region.frames[((at - region_base) / PAGE) as usize];
                physical::zero(frame + at % PAGE, 16);
            }
        }
        pool.blocks.insert(address, Block { region: region_base, span: (address, size), tag, tracked });
    }
    account_allocation(tag, true, tracked);
    Some(Ok(address))
}

/// O veredito do ExFreeHeapPool para um endereço de sessão: os parâmetros
/// do BAD_POOL_CALLER quando a sessão corrente não é dona do bloco.
pub fn check_free(address: u64) -> Option<(u32, [u64; 4])> {
    let pointer = session::current();
    let owned = pointer != 0 && POOLS.lock().get(&pointer).is_some_and(|pool| pool.blocks.contains_key(&address));
    (!owned).then_some((BAD_POOL_CALLER, [0, 0, address, 0]))
}

/// ExFreePool de um endereço de sessão, no heap da sessão corrente. `Err`
/// com o veredito de [`check_free`] quando a sessão corrente não é dona.
pub fn free_paged(address: u64) -> Result<(), (u32, [u64; 4])> {
    if let Some(verdict) = check_free(address) {
        return Err(verdict);
    }
    let pointer = session::current();
    let (block, emptied) = {
        let mut pools = POOLS.lock();
        let Some(pool) = pools.get_mut(&pointer) else { return Err((BAD_POOL_CALLER, [0, 0, address, 0])) };
        let Some(block) = pool.blocks.remove(&address) else { return Err((BAD_POOL_CALLER, [0, 0, address, 0])) };
        let region = pool.regions.get_mut(&block.region).expect("session pool block without region");
        region.live -= 1;
        give_back(&mut region.free, block.span.0, block.span.1);
        let emptied = region.live == 0 && (region.large || pool.regions.values().filter(|region| !region.large).count() > 1);
        let emptied = if emptied { pool.regions.remove(&block.region).map(|region| (block.region, region)) } else { None };
        (block, emptied)
    };
    account_free(block.tag, true, block.tracked);
    if let Some((base, region)) = emptied {
        retire_region(pointer, base, region);
    }
    Ok(())
}

fn retire_region(pointer: u64, base: u64, region: Region) {
    let pages: Vec<u64> = (0..region.frames.len() as u64).map(|page| base + page * PAGE).collect();
    if let Err(error) = session::unmap_pages(pointer, &pages) {
        crate::debug_print!("[pool] regiao de sessao {:#x} retida: {}", base, error);
        return;
    }
    for frame in &region.frames {
        pfn::free_page(*frame);
    }
    session::release_dynamic(pointer, base, region.frames.len() as u64 * PAGE);
}

/// NonPagedPoolSession: o bloco do pool global `address` passa a contar na
/// sessão corrente. `false` fora de uma sessão (o chamador recusa).
pub fn track_nonpaged(address: u64, bytes: u64, tag: u32) -> bool {
    if session::current() == 0 {
        return false;
    }
    let tracked = tracked_bytes(bytes);
    NONPAGED.lock().insert(address, (tag, tracked));
    account_allocation(tag, false, tracked);
    true
}

/// ExFreePool de um bloco NonPagedPoolSession: a liberação conta na sessão
/// corrente (a tabela de sessão é uma VA de sessão).
pub fn untrack_nonpaged(address: u64) {
    if let Some((tag, tracked)) = NONPAGED.lock().remove(&address) {
        account_free(tag, false, tracked);
    }
}

/// O bloco PagedPoolSession vivo em `address` na sessão `session`:
/// (tamanho reservado, tag).
pub fn block(session: u64, address: u64) -> Option<(u64, u32)> {
    POOLS.lock().get(&session).and_then(|pool| pool.blocks.get(&address)).map(|block| (block.span.1, block.tag))
}

/// Blocos e páginas do heap da sessão.
pub fn usage(session: u64) -> (usize, u64) {
    POOLS.lock().get(&session).map_or((0, 0), |pool| (pool.blocks.len(), pool.regions.values().map(|region| region.frames.len() as u64).sum()))
}

/// MiDereferenceSessionFinal: o heap da sessão some inteiro, com os blocos
/// ainda vivos.
pub fn release_session(pointer: u64) {
    let Some(pool) = POOLS.lock().remove(&pointer) else { return };
    if !pool.blocks.is_empty() {
        crate::debug_print!("[pool] sessao encerrada com {} blocos de pool de sessao vivos", pool.blocks.len());
    }
    for (base, region) in pool.regions {
        retire_region(pointer, base, region);
    }
}
