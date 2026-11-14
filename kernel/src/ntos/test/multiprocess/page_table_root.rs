//! Raiz explícita das tabelas de páginas e metade de sistema congelada
//! (`mm/paging.rs`, `mm/process_address_space.rs`):
//!
//! - as 256 entradas de sistema da PML4 do boot estão presentes e são
//!   permanentes: [256] é a auto-referência e [257..512) apontam para PDPTs
//!   de supervisor que nunca voltam ao PFN, nem quando a última página de um
//!   slot vazio é desfeita;
//! - andar pela raiz do boot dá o mesmo que andar pela raiz corrente, em
//!   amostras das duas metades;
//! - uma raiz nova copia a metade de sistema: as VAs de kernel caem nos
//!   mesmos frames, a metade de usuário vem vazia, e uma página mapeada nela
//!   não aparece na raiz do boot.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::ntos::mm::paging::{self, MapOptions, PAGE_PRESENT, PAGE_PS, PAGE_RW, PAGE_USER};
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::mm::shared_user_data::SHARED_USER_DATA_VA;
use crate::ntos::mm::{memory_map as map, pfn, recursive_mapping};
use crate::ntos::ps::user::state::KUSER_SHARED_DATA_USER_VA;

type Assert = fn(bool, &str);

const FRAME_MASK: u64 = 0x000F_FFFF_FFFF_F000;
const SLOT_SIZE: u64 = 1 << 39;

fn slot_base(index: u64) -> u64 {
    0xFFFF_0000_0000_0000 | (index << 39)
}

fn entry(root: u64, index: u64) -> u64 {
    paging::read_entry_exact(root + index * 8)
}

pub fn run(assert: Assert) {
    assert(paging::current_root() == SYSTEM_ROOT, "raiz: o CR3 segue na PML4 do boot");
    kernel_entries(assert);
    assert(paging::kernel_half_frozen(), "raiz: metade de sistema congelada no boot");
    empty_slot_keeps_its_table(assert);
    same_walk_from_both_roots(assert);
    scratch_root(assert);
}

/// As 256 entradas de sistema da PML4 do boot.
fn kernel_entries(assert: Assert) {
    let recursive = map::PAGE_TABLE_RECURSIVE_INDEX;
    assert(entry(SYSTEM_ROOT, recursive) == recursive_mapping::self_reference(SYSTEM_ROOT), "raiz: PML4[256] e a auto-referencia");
    let mut absent = Vec::new();
    let mut transient = Vec::new();
    for index in map::USER_PML4_ENTRIES..512 {
        if index == recursive {
            continue;
        }
        let value = entry(SYSTEM_ROOT, index);
        if value & PAGE_PRESENT == 0 || value & (PAGE_USER | PAGE_PS) != 0 || value & PAGE_RW == 0 {
            absent.push(index);
        } else if !paging::is_permanent_table(value & FRAME_MASK) {
            transient.push(index);
        }
    }
    if let (Some(first), count) = (absent.first(), absent.len()) {
        debug_print!("[raiz] {} entradas de sistema ausentes na PML4, a primeira em {}", count, first);
    }
    if let (Some(first), count) = (transient.first(), transient.len()) {
        debug_print!("[raiz] {} PDPTs de sistema sem marca permanente, a primeira em {}", count, first);
    }
    assert(absent.is_empty(), "raiz: as 255 PML4E de sistema abaixo da auto-referencia estao presentes, de supervisor e RW");
    assert(transient.is_empty(), "raiz: toda PDPT da metade de sistema e permanente");
}

/// Mapear e desfazer a única página de um slot de sistema vazio não cria nem
/// libera a entrada da PML4: a PDPT fica, vazia.
fn empty_slot_keeps_its_table(assert: Assert) {
    let Some(index) = (map::USER_PML4_ENTRIES + 2..512).find(|&index| paging::find_mapping(slot_base(index), SLOT_SIZE).is_none()) else {
        assert(false, "raiz: algum slot de sistema sem mapeamento");
        return;
    };
    let va = slot_base(index);
    let before = entry(SYSTEM_ROOT, index);
    let frame = pfn::alloc_page();
    if frame == 0 {
        assert(false, "raiz: frame de teste");
        return;
    }
    let mapped = paging::map_page(va, frame, PAGE_PRESENT | PAGE_RW, MapOptions { nx: true, ..MapOptions::default() });
    let while_mapped = entry(SYSTEM_ROOT, index);
    let translated = paging::translate(va);
    let unmapped = paging::unmap_page(va, MapOptions::default());
    let after = entry(SYSTEM_ROOT, index);
    let emptied = paging::find_mapping(va, SLOT_SIZE).is_none();
    let user_refused = !paging::map_page(va, frame, PAGE_PRESENT | PAGE_USER, MapOptions::default());
    if !user_refused {
        paging::unmap_page(va, MapOptions::default());
    }
    pfn::free_page(frame);
    assert(mapped && translated == frame, "raiz: pagina de kernel mapeada num slot vazio");
    assert(before & PAGE_PRESENT != 0 && while_mapped == before, "raiz: o mapeamento nao cria a PML4E (ja existia)");
    assert(unmapped && after == before && paging::is_permanent_table(after & FRAME_MASK), "raiz: desfazer a ultima pagina nao libera a PDPT do slot");
    assert(emptied, "raiz: o slot volta a ficar vazio");
    assert(user_refused, "raiz: metade de sistema recusa pagina de usuario");
}

/// Amostras das duas metades: presentes, ausentes, guarda, recursiva.
fn samples(stack: u64, heap: u64, recursive_root: u64) -> [u64; 20] {
    [
        0,
        map::LOWEST_USER_ADDRESS,
        KUSER_SHARED_DATA_USER_VA,
        0x1_4000_0000,
        map::HIGHEST_USER_ADDRESS & !0xFFF,
        map::KERNEL_VIRTUAL_BASE,
        map::KERNEL_VIRTUAL_BASE + 0x1000,
        map::BOOT_STACK_TOP - 8,
        map::BOOT_STACK_LIMIT - map::PAGE_SIZE,
        stack,
        heap,
        map::direct_map(0x1000),
        map::direct_map(map::PML4_PHYS),
        map::PFN_DATABASE_BASE,
        SHARED_USER_DATA_VA,
        map::PCR_VIRTUAL_BASE,
        map::KERNEL_POOL_BASE,
        map::SYSTEM_IMAGE_BASE,
        recursive_root,
        slot_base(511),
    ]
}

fn same_walk_from_both_roots(assert: Assert) {
    let marker = 0u64;
    let heap = Box::new(0u64);
    let recursive_root = recursive_mapping::layout().map_or(0, |layout| layout.root_table_address);
    let mut differing = Vec::new();
    for va in samples(&marker as *const u64 as u64, &*heap as *const u64 as u64, recursive_root) {
        let same = [false, true].iter().all(|&include| paging::query_page_in(SYSTEM_ROOT, va, include) == paging::query_page(va, include))
            && paging::translate_in(SYSTEM_ROOT, va) == paging::translate(va)
            && paging::access_flags_in(SYSTEM_ROOT, va) == paging::access_flags(va);
        if !same {
            differing.push(va);
        }
    }
    for va in &differing {
        debug_print!("[raiz] raiz do boot e raiz corrente divergem em {:#x}", va);
    }
    assert(differing.is_empty(), "raiz: query/translate/access pela raiz do boot == pela raiz corrente");
    assert(recursive_root != 0 && paging::translate_in(SYSTEM_ROOT, recursive_root) == SYSTEM_ROOT, "raiz: janela recursiva mostra a PML4 do boot");
}

fn scratch_root(assert: Assert) {
    let scratch = match address_space::create_root() {
        Ok(root) => root,
        Err(error) => {
            debug_print!("[raiz] create_root: {}", error);
            assert(false, "raiz: raiz nova criada");
            return;
        }
    };
    let recursive = map::PAGE_TABLE_RECURSIVE_INDEX;
    let copied = (map::USER_PML4_ENTRIES..512).filter(|&index| index != recursive).all(|index| entry(scratch, index) == entry(SYSTEM_ROOT, index));
    assert(copied, "raiz nova: PML4[257..512) copiadas da raiz do boot");
    assert(entry(scratch, recursive) == recursive_mapping::self_reference(scratch), "raiz nova: auto-referencia propria em [256]");
    assert((0..map::USER_PML4_ENTRIES).all(|index| entry(scratch, index) == 0), "raiz nova: metade de usuario vazia");
    assert(paging::find_mapping_in(scratch, map::LOWEST_USER_ADDRESS, map::USER_PROBE_ADDRESS - map::LOWEST_USER_ADDRESS).is_none(), "raiz nova: nenhuma pagina de usuario");

    let marker = 0u64;
    let heap = Box::new(0u64);
    let recursive_root = recursive_mapping::layout().map_or(0, |layout| layout.root_table_address);
    let stack = &marker as *const u64 as u64;
    let heap = &*heap as *const u64 as u64;
    let mut differing = Vec::new();
    for va in samples(stack, heap, recursive_root) {
        if !(paging::pml4_index(va) >= map::USER_PML4_ENTRIES && paging::pml4_index(va) != recursive) {
            continue;
        }
        if paging::translate_in(scratch, va) != paging::translate_in(SYSTEM_ROOT, va) || paging::query_page_in(scratch, va, true) != paging::query_page_in(SYSTEM_ROOT, va, true) {
            differing.push(va);
        }
    }
    for va in &differing {
        debug_print!("[raiz] raiz nova diverge da raiz do boot na VA de kernel {:#x}", va);
    }
    assert(differing.is_empty(), "raiz nova: VAs de kernel nos mesmos frames da raiz do boot");
    let present = [map::KERNEL_VIRTUAL_BASE, stack, heap, map::direct_map(0x1000), SHARED_USER_DATA_VA];
    assert(present.iter().all(|&va| paging::translate_in(scratch, va) != 0), "raiz nova: imagem, pilha, heap, mapa direto e KUSER de kernel presentes");
    assert(paging::translate_in(scratch, recursive_root) == scratch, "raiz nova: janela recursiva mostra a propria raiz");

    // Uma página de usuário na raiz nova não aparece na do boot.
    let boot_view = paging::translate(KUSER_SHARED_DATA_USER_VA);
    assert(paging::translate_in(scratch, KUSER_SHARED_DATA_USER_VA) == 0, "raiz nova: sem a visao de usuario da KUSER do boot");
    let frame = pfn::alloc_page();
    if frame == 0 {
        assert(false, "raiz nova: frame de teste");
        let _ = address_space::delete_root(scratch);
        return;
    }
    let mapped = paging::map_page_in(scratch, KUSER_SHARED_DATA_USER_VA, frame, PAGE_PRESENT | PAGE_USER, MapOptions::default());
    let private = paging::translate_in(scratch, KUSER_SHARED_DATA_USER_VA);
    let access = paging::access_flags_in(scratch, KUSER_SHARED_DATA_USER_VA);
    let boot_after = paging::translate(KUSER_SHARED_DATA_USER_VA);
    let refused_while_mapped = address_space::delete_root(scratch).is_err();
    let unmapped = paging::unmap_page_in(scratch, KUSER_SHARED_DATA_USER_VA, MapOptions::default());
    let user_half_empty = (0..map::USER_PML4_ENTRIES).all(|index| entry(scratch, index) == 0);
    pfn::free_page(frame);
    assert(mapped && private == frame && access & (PAGE_PRESENT | PAGE_USER) == PAGE_PRESENT | PAGE_USER, "raiz nova: pagina de usuario mapeada so nela");
    assert(boot_after == boot_view, "raiz nova: a raiz do boot nao ve a pagina da raiz nova");
    assert(refused_while_mapped, "raiz nova: delete_root recusa com a metade de usuario mapeada");
    assert(unmapped && user_half_empty, "raiz nova: desfazer devolve as tabelas de usuario");
    assert(address_space::delete_root(SYSTEM_ROOT).is_err(), "raiz: a raiz do boot nao e liberada");
    assert(address_space::delete_root(scratch).is_ok(), "raiz nova: liberada");
}
