//! Edição real das tabelas de páginas x86-64.
//!
//! Anda PML4->PDPT->PD->PT criando os níveis que faltam com frames do PFN,
//! divide páginas de 2MB em PTs de 4KB sob demanda e invalida a TLB.
//! Índices de uma VA: PML4[39-47] PDPT[30-38] PD[21-29] PT[12-20].
//!
//! Tabelas e entradas são endereçadas pelo endereço FÍSICO (o "entry
//! address" de [`PageQuery`] e das funções públicas); cada leitura e escrita
//! passa pelo mapa direto da metade de sistema (`hal::physical`), nunca pela
//! identidade baixa.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{frame_mapping_tracker as tracker, memory_map as map, native_frame_descriptors as descriptors, pfn};
use crate::hal::{cpu, physical};
use crate::rtl::SpinLock;

pub const PAGE_PRESENT: u64 = 0x01;
pub const PAGE_RW: u64 = 0x02;
/// U/S: acessível de ring 3 (precisa estar ligado em TODOS os níveis).
pub const PAGE_USER: u64 = 0x04;
pub const PAGE_PWT: u64 = 0x08;
pub const PAGE_PCD: u64 = 0x10;
/// Bit 7 na PD = página de 2MB.
pub const PAGE_PS: u64 = 0x80;

const PML4: u64 = map::PML4_PHYS;
const NX_BIT: u64 = 1 << 63;
/// Bits que `read_entry` conserva: endereço + flags baixas, sem NX nem 52..62.
const ENTRY_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;

struct PagingState {
    /// Só tabelas alocadas aqui voltam ao PFN (entrada pai -> frame filho).
    owned_tables: BTreeMap<u64, u64>,
    /// Lembra uma célula não vazia, sem presumir que continua igual.
    nonempty_table_hints: BTreeMap<u64, u64>,
}

static STATE: SpinLock<PagingState> =
    SpinLock::new(PagingState { owned_tables: BTreeMap::new(), nonempty_table_hints: BTreeMap::new() });

/// Rastreador de mapeamentos instalado (existe o banco nativo de PFNs).
static OBSERVED: AtomicBool = AtomicBool::new(false);

pub fn set_observed(installed: bool) {
    OBSERVED.store(installed, Ordering::Release);
}

fn observed() -> bool {
    OBSERVED.load(Ordering::Acquire)
}

/// Entrada sem NX: NX não faz parte do endereço nem das permissões baixas.
pub fn read_entry(address: u64) -> u64 {
    physical::read64(address) & ENTRY_MASK
}

/// A entrada inteira (com NX), numa única leitura de 64 bits.
pub fn read_entry_exact(address: u64) -> u64 {
    physical::read64(address)
}

/// Grava a entrada numa única escrita de 64 bits, como o NT grava uma PTE:
/// outra CPU percorrendo a tabela nunca vê metade da entrada antiga e metade
/// da nova.
fn write_entry(address: u64, value: u64, nx: bool) {
    let tracked = observed() && tracker::tracks_entry(address);
    let previous = if tracked { read_entry_exact(address) } else { 0 };
    let replacement = (value & !NX_BIT) | if nx { NX_BIT } else { 0 };
    physical::write64(address, replacement);
    if tracked {
        tracker::entry_changed(address, previous, replacement);
    }
}

fn index_at(va: u64, shift: u32) -> u64 {
    (va >> shift) & 511
}

fn offset_at(va: u64, size: u64) -> u64 {
    va % size
}

fn frame_of(entry: u64, size: u64) -> u64 {
    entry / size * size
}

fn add_entry_flags(address: u64, flags: u64) {
    // Uma atualização de permissão não pode apagar NX nem os bits altos nem
    // perder Accessed/Dirty gravados pela CPU: OR atômico na entrada.
    physical::atomic_u64(address).fetch_or(flags & 0xFFFF_FFFF, Ordering::SeqCst);
}

fn table_of(entry: u64) -> u64 {
    let frame = frame_of(entry, 4096);
    assert!(frame < map::PHYSICAL_MEMORY_LIMIT, "paging-structure frame outside the direct map");
    frame
}

/// A folha é um alias físico do kernel (identidade baixa, mapa direto ou
/// janela do heap), não um dono do frame.
fn physical_alias(va: u64, pa: u64) -> bool {
    va == pa
        || va == map::direct_map(pa)
        || ((map::KERNEL_HEAP_PHYS_BASE..map::KERNEL_HEAP_PHYS_TOP).contains(&pa) && va == map::kernel_heap_virtual(pa))
}

/// Monta a janela do heap do kernel (`KERNEL_HEAP_BASE..TOP`): os frames do
/// heap em páginas de 2 MB de supervisor, RW e executáveis, com a PDPT e a
/// PD fixas de `memory_map`. Roda uma vez no boot, antes da primeira
/// alocação (o heap ainda não existe e o rastreador de frames não foi
/// instalado); a entrada da PML4 é a mesma para todas as CPUs.
pub fn map_kernel_heap_window() {
    let (pdpt, pd) = (map::KERNEL_HEAP_PDPT_PHYS, map::KERNEL_HEAP_PD_PHYS);
    physical::zero(pdpt, 4096);
    physical::zero(pd, 4096);
    let pages = (map::KERNEL_HEAP_PHYS_TOP - map::KERNEL_HEAP_PHYS_BASE) / map::LARGE_PAGE_SIZE;
    for index in 0..pages {
        let frame = map::KERNEL_HEAP_PHYS_BASE + index * map::LARGE_PAGE_SIZE;
        write_entry(pd + (pd_index(map::KERNEL_HEAP_BASE) + index) * 8, frame | PAGE_PRESENT | PAGE_RW | PAGE_PS, false);
    }
    write_entry(pdpt + pdpt_index(map::KERNEL_HEAP_BASE) * 8, pd | PAGE_PRESENT | PAGE_RW, false);
    write_entry(PML4 + map::KERNEL_HEAP_PML4_INDEX * 8, pdpt | PAGE_PRESENT | PAGE_RW, false);
    cpu::reload_cr3();
}

pub fn pml4_index(va: u64) -> u64 {
    index_at(va, 39)
}

pub fn pdpt_index(va: u64) -> u64 {
    index_at(va, 30)
}

pub fn pd_index(va: u64) -> u64 {
    index_at(va, 21)
}

pub fn pt_index(va: u64) -> u64 {
    index_at(va, 12)
}

/// Alterar esta região pela API comum modificaria as próprias tabelas.
pub fn is_recursive_mapping_address(va: u64) -> bool {
    pml4_index(va) == map::PAGE_TABLE_RECURSIVE_INDEX
}

fn zero_frame(frame: u64) {
    // Tabelas novas não têm pai publicado nem referências de PFN; mantém as
    // notificações se o rastreador já conhece esta tabela.
    if !(observed() && tracker::tracks_entry(frame)) {
        physical::zero(frame, 4096);
        return;
    }
    for index in 0..512 {
        write_entry(frame + index * 8, 0, false);
    }
}

fn record_owned(parent_entry: u64, frame: u64) {
    STATE.lock().owned_tables.insert(parent_entry, frame);
}

/// Anda PML4->PDPT->PD até a entrada da PD que contém `va`. `create` cria
/// os níveis que faltam; `user` liga U/S nos níveis intermediários.
fn pd_entry_address(va: u64, create: bool, user: bool) -> u64 {
    let middle_flags = PAGE_PRESENT | PAGE_RW | if user { PAGE_USER } else { 0 };
    let pml4_entry_address = PML4 + pml4_index(va) * 8;
    let entry = read_entry(pml4_entry_address);
    if entry & PAGE_PRESENT == 0 {
        if !create {
            return 0;
        }
        let pdpt_frame = pfn::alloc_page();
        if pdpt_frame == 0 {
            return 0;
        }
        zero_frame(pdpt_frame);
        write_entry(pml4_entry_address, pdpt_frame | middle_flags, false);
        record_owned(pml4_entry_address, pdpt_frame);
    } else if user && entry & PAGE_USER == 0 {
        add_entry_flags(pml4_entry_address, PAGE_USER);
    }
    let pdpt_address = table_of(read_entry(pml4_entry_address));
    let pdpt_entry_address = pdpt_address + pdpt_index(va) * 8;
    let entry = read_entry(pdpt_entry_address);
    if entry & PAGE_PRESENT == 0 {
        if !create {
            return 0;
        }
        let pd_frame = pfn::alloc_page();
        if pd_frame == 0 {
            return 0;
        }
        zero_frame(pd_frame);
        write_entry(pdpt_entry_address, pd_frame | middle_flags, false);
        record_owned(pdpt_entry_address, pd_frame);
    } else if user && entry & PAGE_USER == 0 {
        add_entry_flags(pdpt_entry_address, PAGE_USER);
    }
    assert!(entry & PAGE_PS == 0, "cannot edit a 1GB leaf as a page directory");
    let pd_address = table_of(read_entry(pdpt_entry_address));
    pd_address + pd_index(va) * 8
}

/// Resultado de [`query_page`].
#[derive(Clone, Copy, Debug)]
pub struct PageQuery {
    pub physical_address: u64,
    pub page_size: u64,
    pub access: u64,
    pub nx: bool,
    pub flags: u64,
    pub pat: bool,
    pub entry_address: u64,
}

/// Traduz VA -> PA andando pelas tabelas.
pub fn query_page(va: u64, include_non_present: bool) -> Option<PageQuery> {
    let mut table = PML4;
    let mut access = PAGE_PRESENT | PAGE_RW | PAGE_USER;
    let mut nx = false;
    let shifts = [39u32, 30, 21, 12];
    for (level, &shift) in shifts.iter().enumerate() {
        let at = table + index_at(va, shift) * 8;
        let entry = read_entry(at);
        access &= entry;
        if access & PAGE_PRESENT == 0 && !(include_non_present && level == 3) {
            return None;
        }
        nx = nx || physical::read32(at + 4) & 0x8000_0000 != 0;
        if level == 3 || ((level == 1 || level == 2) && entry & PAGE_PS != 0) {
            let page_size = 1u64 << shift;
            return Some(PageQuery {
                physical_address: frame_of(entry, page_size) + offset_at(va, page_size),
                page_size,
                access,
                nx,
                flags: entry & 0xFFF,
                pat: if level == 3 { entry & 0x80 != 0 } else { entry & 0x1000 != 0 },
                entry_address: at,
            });
        }
        table = table_of(entry);
    }
    None
}

/// VA -> PA pelos bits PRESENT e PFN vivos (0 = sem mapeamento).
pub fn translate(va: u64) -> u64 {
    let mut entry = read_entry(PML4 + pml4_index(va) * 8);
    if entry & PAGE_PRESENT == 0 {
        return 0;
    }
    entry = read_entry(table_of(entry) + pdpt_index(va) * 8);
    if entry & PAGE_PRESENT == 0 {
        return 0;
    }
    if entry & PAGE_PS != 0 {
        return frame_of(entry, 0x4000_0000) + offset_at(va, 0x4000_0000);
    }
    entry = read_entry(table_of(entry) + pd_index(va) * 8);
    if entry & PAGE_PRESENT == 0 {
        return 0;
    }
    if entry & PAGE_PS != 0 {
        return frame_of(entry, 0x20_0000) + offset_at(va, 0x20_0000);
    }
    entry = read_entry(table_of(entry) + pt_index(va) * 8);
    if entry & PAGE_PRESENT != 0 { frame_of(entry, 4096) + offset_at(va, 4096) } else { 0 }
}

/// Acha uma folha ocupada sem varrer cada 4KB de uma faixa esparsa. Folhas
/// não presentes com backing (NOACCESS/guarda) também contam.
pub fn find_mapping(base: u64, size: u64) -> Option<(u64, u64)> {
    let end = base.wrapping_add(size);
    let shifts = [39u32, 30, 21, 12];
    let mut address = base;
    while address < end {
        let mut table = PML4;
        let mut advanced = false;
        for (level, &shift) in shifts.iter().enumerate() {
            let span = 1u64 << shift;
            let start = address / span * span;
            let entry = read_entry(table + index_at(address, shift) * 8);
            if entry == 0 {
                match start.checked_add(span) {
                    Some(next) => address = next,
                    None => return None,
                }
                advanced = true;
                break;
            }
            if level == 3 || entry & PAGE_PRESENT == 0 || (level > 0 && entry & PAGE_PS != 0) {
                return Some((start, span));
            }
            table = table_of(entry);
        }
        if !advanced {
            return None;
        }
    }
    None
}

/// Permissões efetivas: interseção de todos os níveis.
pub fn access_flags(va: u64) -> u64 {
    let mut table = PML4;
    let mut access = PAGE_PRESENT | PAGE_RW | PAGE_USER;
    let indices = [pml4_index(va), pdpt_index(va), pd_index(va), pt_index(va)];
    for (level, &index) in indices.iter().enumerate() {
        let entry = read_entry(table + index * 8);
        access &= entry;
        if access & PAGE_PRESENT == 0 {
            return 0;
        }
        if level == 3 || ((level == 1 || level == 2) && entry & PAGE_PS != 0) {
            return access;
        }
        table = table_of(entry);
    }
    0
}

/// Divide a página de 2MB que contém `va` numa PT de 512 páginas de 4KB,
/// preservando o mapeamento. `user` só liga U/S na entrada da PD.
pub fn split_large_page(va: u64, user: bool) -> bool {
    if is_recursive_mapping_address(va) {
        return false;
    }
    let pd_entry_address = pd_entry_address(va, false, false);
    if pd_entry_address == 0 {
        return false;
    }
    let pd_entry = read_entry(pd_entry_address);
    if pd_entry & PAGE_PRESENT == 0 {
        return false;
    }
    if pd_entry & PAGE_PS == 0 {
        if user && pd_entry & PAGE_USER == 0 {
            add_entry_flags(pd_entry_address, PAGE_USER);
        }
        return true; // já dividida
    }
    let large_base = frame_of(pd_entry, 0x20_0000);
    let nx = physical::read32(pd_entry_address + 4) & 0x8000_0000 != 0;
    // PS vira o bit PAT da PTE; o PAT de página grande vai do bit 12 ao 7.
    let leaf_flags = (pd_entry & 0xF7F) | if pd_entry & 0x1000 != 0 { 0x80 } else { 0 };
    let pt_frame = pfn::alloc_page();
    if pt_frame == 0 {
        return false;
    }
    for index in 0..512 {
        write_entry(pt_frame + index * 8, large_base + index * 0x1000 + leaf_flags, nx);
    }
    let user_flag = if user || pd_entry & PAGE_USER != 0 { PAGE_USER } else { 0 };
    write_entry(pd_entry_address, pt_frame | PAGE_PRESENT | PAGE_RW | user_flag, false);
    record_owned(pd_entry_address, pt_frame);
    cpu::reload_cr3(); // o split muda a estrutura: flush total da TLB
    true
}

/// Endereço físico da PT que contém `va` (cria/divide se preciso).
fn ensure_page_table(va: u64, user: bool) -> u64 {
    let pd_entry_address = pd_entry_address(va, true, user);
    if pd_entry_address == 0 {
        return 0;
    }
    let pd_entry = read_entry(pd_entry_address);
    if pd_entry & PAGE_PRESENT == 0 {
        let pt_frame = pfn::alloc_page();
        if pt_frame == 0 {
            return 0;
        }
        zero_frame(pt_frame);
        write_entry(pd_entry_address, pt_frame | PAGE_PRESENT | PAGE_RW | if user { PAGE_USER } else { 0 }, false);
        record_owned(pd_entry_address, pt_frame);
        return pt_frame;
    }
    if pd_entry & PAGE_PS != 0 {
        if !split_large_page(va, user) {
            return 0;
        }
        return table_of(read_entry(pd_entry_address));
    }
    if user && pd_entry & PAGE_USER == 0 {
        add_entry_flags(pd_entry_address, PAGE_USER);
    }
    table_of(read_entry(pd_entry_address))
}

/// Libera tabelas vazias do caminho de `va`. Com `deferred`, as tabelas
/// retiradas ficam com o chamador até todas as CPUs confirmarem a
/// invalidação.
fn reclaim_empty_tables(va: u64, deferred: Option<&mut Vec<u64>>) {
    let mut path = Vec::new();
    let mut table = PML4;
    for index in [pml4_index(va), pdpt_index(va), pd_index(va)] {
        let at = table + index * 8;
        let entry = read_entry(at);
        if entry & PAGE_PRESENT == 0 || entry & PAGE_PS != 0 {
            break;
        }
        table = table_of(entry);
        path.push((at, table));
    }
    let mut retired = Vec::new();
    for &(at, frame) in path.iter().rev() {
        let first_offset = {
            let state = STATE.lock();
            if state.owned_tables.get(&at) != Some(&frame) {
                break;
            }
            state.nonempty_table_hints.get(&frame).copied().unwrap_or(0)
        };
        // Relê a pista antes de confiar nela e dá uma volta completa antes
        // de declarar a tabela vazia.
        let mut empty = true;
        let mut scanned = 0;
        while scanned < 4096 {
            let offset = (first_offset + scanned) & 4095;
            if physical::read32(frame + offset) != 0 {
                STATE.lock().nonempty_table_hints.insert(frame, offset);
                empty = false;
                break;
            }
            scanned += 4;
        }
        if !empty {
            break;
        }
        write_entry(at, 0, false);
        {
            let mut state = STATE.lock();
            state.owned_tables.remove(&at);
            state.nonempty_table_hints.remove(&frame);
        }
        retired.push(frame);
    }
    if retired.is_empty() {
        return;
    }
    if let Some(deferred) = deferred {
        deferred.extend(retired);
        return;
    }
    cpu::reload_cr3(); // descarta caches de estruturas antes de reusar os frames
    for frame in retired {
        pfn::free_page(frame);
    }
}

/// Opções de [`map_page`]/[`unmap_page`].
#[derive(Default)]
pub struct MapOptions<'a> {
    pub nx: bool,
    /// `false` dispensa o INVLPG (o chamador invalida em lote).
    pub skip_invalidate: bool,
    pub deferred_tables: Option<&'a mut Vec<u64>>,
}

/// Mapeia uma página de 4KB: va -> pa com flags. PAGE_USER propaga U/S.
pub fn map_page(va: u64, pa: u64, flags: u64, options: MapOptions<'_>) -> bool {
    if is_recursive_mapping_address(va) || pa >= 0x10_0000_0000_0000 || pa % 4096 != 0 {
        return false;
    }
    // A identidade e o mapa direto são acesso físico do kernel, não donos do
    // frame. As demais folhas, inclusive NOACCESS com backing, exigem RAM
    // reservada.
    if observed() && !physical_alias(va, pa) && (pa != 0 || flags & PAGE_PRESENT != 0) && !descriptors::can_map_range(pa, 4096) {
        return false;
    }
    let pt_address = ensure_page_table(va, flags & PAGE_USER != 0);
    if pt_address == 0 {
        reclaim_empty_tables(va, None);
        return false;
    }
    write_entry(pt_address + pt_index(va) * 8, pa + (flags & 0xFFF), options.nx);
    if !options.skip_invalidate {
        cpu::invalidate_page(va);
    }
    true
}

pub fn unmap_page(va: u64, options: MapOptions<'_>) -> bool {
    if is_recursive_mapping_address(va) {
        return false;
    }
    let pd_entry_address = pd_entry_address(va, false, false);
    let mut entry = if pd_entry_address != 0 { read_entry(pd_entry_address) } else { 0 };
    if entry & PAGE_PRESENT == 0 {
        reclaim_empty_tables(va, options.deferred_tables);
        return true;
    }
    if entry & PAGE_PS != 0 {
        if !split_large_page(va, false) {
            return false;
        }
        entry = read_entry(pd_entry_address);
    }
    let pt_address = table_of(entry);
    write_entry(pt_address + pt_index(va) * 8, 0, false);
    if !options.skip_invalidate {
        cpu::invalidate_page(va);
    }
    reclaim_empty_tables(va, options.deferred_tables);
    true
}

pub fn map_large_page(va: u64, pa: u64, flags: u64, nx: bool) -> bool {
    if is_recursive_mapping_address(va) || offset_at(va, 0x20_0000) != 0 || pa >= 0x10_0000_0000_0000 || pa % 0x20_0000 != 0 {
        return false;
    }
    if observed() && !physical_alias(va, pa) && (pa != 0 || flags & PAGE_PRESENT != 0) && !descriptors::can_map_range(pa, 0x20_0000) {
        return false;
    }
    let at = pd_entry_address(va, true, flags & PAGE_USER != 0);
    if at == 0 {
        reclaim_empty_tables(va, None);
        return false;
    }
    let prior = read_entry(at);
    if prior != 0 && prior & PAGE_PS == 0 {
        return false; // não descarta uma tabela de páginas viva
    }
    let large_flags = (flags & 0xF7F) | PAGE_PS | if flags & 0x80 != 0 { 0x1000 } else { 0 };
    write_entry(at, pa + large_flags, nx);
    cpu::invalidate_page(va);
    true
}

pub fn unmap_large_page(va: u64, deferred_tables: Option<&mut Vec<u64>>) -> bool {
    if is_recursive_mapping_address(va) || offset_at(va, 0x20_0000) != 0 {
        return false;
    }
    let at = pd_entry_address(va, false, false);
    if at != 0 && read_entry(at) != 0 {
        if read_entry(at) & PAGE_PS == 0 {
            return false;
        }
        write_entry(at, 0, false);
        cpu::invalidate_page(va);
    }
    reclaim_empty_tables(va, deferred_tables);
    true
}
