//! O rastreador de frames segue as tabelas de cada raiz de processo
//! (`mm/frame_mapping_tracker.rs`): a raiz entra com `create_root` e sai com
//! `delete_root`, e as tabelas da metade de usuário dela e as folhas dessas
//! tabelas têm referências no banco nativo de PFNs, como as do System.
//!
//! - Um processo de usuário criado pelo caminho real: a raiz e as tabelas
//!   de usuário dela estão no rastreador, cada uma ainda referenciada (o PFN
//!   recusaria devolvê-la: nem duas vezes nem em uso), e a página da PEB tem
//!   ShareCount, PteAddress (o alias recursivo da PTE) e PteFrame (a PT
//!   dela) no MMPFN. O processo roda e sai; depois do último dereference
//!   nenhuma tabela dele sobra no rastreador, e a contagem de tabelas e a de
//!   frames livres voltam às de antes.
//! - Uma raiz avulsa com uma página mapeada: enquanto ligadas, a PT e a
//!   página não podem voltar ao PFN; com a entrada da PML4 apagada por fora
//!   (uma desmontagem que esquecesse as tabelas), o `delete_root` recusa,
//!   porque as tabelas da raiz ainda estão no rastreador (o vazamento é
//!   pego); desfeito direito, a raiz volta e não passa duas vezes.
//!
//! No código anterior o rastreador não via a raiz de um processo: nenhuma
//! tabela de usuário dele aparecia, a PEB não tinha referência no MMPFN, a
//! PT ligada podia voltar ao PFN e o `delete_root` da raiz com tabelas
//! esquecidas devolvia a raiz e vazava as tabelas.

use alloc::format;
use alloc::vec::Vec;

use crate::hal::physical;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::ntos::mm::process_address_space as address_space;
use crate::ntos::mm::{frame_mapping_tracker as tracker, kernel_stack, native_frame_descriptors as descriptors, paging, pfn, recursive_mapping};
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::process;
use crate::ntos::ps::user::process::{self as user_process, RunOptions};
use crate::ntos::ps::user::{loader, state};

type Assert = fn(bool, &str);

const IMAGE_BASE: u64 = 0x1_4000_0000;
const EXIT_CODE: u32 = 0x5C;
/// VA de usuário da raiz avulsa.
const LOOSE_VA: u64 = 0x2_0000_0000;
const ADDRESS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

/// NtTerminateProcess(-1, EXIT_CODE) depois do LdrInitializeThunk.
fn program() -> Vec<u8> {
    let code = EXIT_CODE.to_le_bytes();
    let entry: &[u8] = &[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, code[0], code[1], code[2], code[3], 0x49, 0x89, 0xCA, 0xB8, 0x2C, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xFE];
    crate::ntos::test::phase7::single_section_image(IMAGE_BASE, 0x0022, b".text", 0x6000_0020, 0x1000, entry)
}

fn create_process() -> Option<CreatedProcess> {
    let name = "tabelas.exe";
    let request = user_process::windows_process_request(ImageOrigin::Bytes(program()), name, &format!("C:\\{name}"), &RunOptions::default());
    match create::create_user_process(&request) {
        Ok(created) => {
            process::reference(created.process_pointer);
            Some(created)
        }
        Err(failure) => {
            crate::debug_print!("[tabelas] processo nao criado: {}", failure);
            None
        }
    }
}

/// Os frames da PDPT, da PD e da PT que levam a `va` na raiz `root`.
fn walk(root: u64, va: u64) -> [u64; 3] {
    let mut frames = [0; 3];
    let mut table = root;
    for (level, shift) in [39u64, 30, 21].into_iter().enumerate() {
        let entry = paging::read_entry_exact(table + ((va >> shift) & 511) * 8);
        if entry & 1 == 0 {
            break;
        }
        table = entry & ADDRESS_MASK;
        frames[level] = table;
    }
    frames
}

/// O frame não tem mais nenhuma referência de PTE: livre, ou em uso com
/// ShareCount 0 no MMPFN.
fn unreferenced(frame: u64) -> bool {
    descriptors::mapping_of(frame).is_none_or(|(share, _, _)| share == 0)
}

/// A PteAddress de uma folha de usuário: o alias recursivo da PTE de `va`.
fn pte_alias(va: u64) -> u64 {
    recursive_mapping::layout().map_or(0, |layout| layout.page_table_base + (va >> 12) * 8)
}

fn process_scenario(assert: Assert) {
    let ready = loader::ensure_ntdll().and_then(|_| loader::ensure_api_set_schema()).and_then(|_| loader::ensure_nls_data().map(|_| ())).and_then(|_| loader::parse_api_set_schema());
    assert(ready.is_ok(), "tabelas: ntdll, apiset e NLS de sistema prontos");
    kernel_stack::reap();
    let (tables_before, free_before) = (tracker::table_count(), pfn::free_count());
    let Some(created) = create_process() else {
        assert(false, "tabelas: processo de usuario criado pelo caminho real");
        return;
    };
    let pointer = created.process_pointer;
    let root = address_space::root_of(pointer).unwrap_or(0);
    let tables = tracker::tables_of(root);
    let linked = tables.iter().all(|&table| !descriptors::can_release(table));
    assert(root != 0 && tables.contains(&root) && tables.len() >= 4 && linked, "tabelas: a raiz do processo e as tabelas de usuario dela estao no rastreador, cada uma referenciada (o PFN nao as devolve)");
    // SAFETY: EPROCESS retido pelo teste.
    let peb = unsafe { Eprocess::at(pointer) }.peb.get();
    let frame = if root != 0 && peb != 0 { paging::translate_in(root, peb) & ADDRESS_MASK } else { 0 };
    let page_table = walk(root, peb)[2];
    let mapping = descriptors::mapping_of(frame);
    let described = mapping.is_some_and(|(share, pte_address, pte_frame)| share >= 1 && pte_address == pte_alias(peb) && pte_frame == page_table / 4096) && tables.contains(&page_table);
    if !described {
        crate::debug_print!("[tabelas] PEB {:#x} frame {:#x} PT {:#x} MMPFN {:x?}", peb, frame, page_table, mapping);
    }
    assert(frame != 0 && described, "tabelas: a pagina da PEB tem ShareCount, PteAddress (alias recursivo da PTE) e PteFrame (a PT do processo) no MMPFN");

    let exit = user_process::run_created(created);
    assert(matches!(exit, Ok(code) if code == EXIT_CODE), "tabelas: o processo roda e sai com o proprio codigo");
    let _ = process::dereference(pointer);
    kernel_stack::reap();
    // Os frames das tabelas podem já ter sido reaproveitados pelo PFN: o que
    // conta é nenhuma tabela da raiz seguir no rastreador.
    let leftover = tracker::tables_of(root);
    let root_gone = address_space::root_of(pointer).is_none();
    let (tables_after, free_after) = (tracker::table_count(), pfn::free_count());
    if tables_after != tables_before || free_after != free_before || !leftover.is_empty() || !root_gone {
        crate::debug_print!("[tabelas] raiz {:#x} devolvida={} restantes {:x?}; tabelas {} -> {}, PFN livre {} -> {}", root, root_gone, leftover, tables_before, tables_after, free_before, free_after);
    }
    assert(root_gone && leftover.is_empty(), "tabelas: depois do ultimo dereference nenhuma tabela do processo sobra no rastreador");
    assert(tables_after == tables_before && free_after == free_before, "tabelas: a contagem de tabelas do rastreador e a de frames livres voltam as de antes do processo");
}

fn loose_root_scenario(assert: Assert) {
    let Ok(root) = address_space::create_root() else {
        assert(false, "tabelas: raiz avulsa criada");
        return;
    };
    let frame = pfn::alloc_page();
    let mapped = frame != 0 && paging::map_page_in(root, LOOSE_VA, frame, paging::PAGE_PRESENT | paging::PAGE_RW | paging::PAGE_USER, paging::MapOptions { nx: true, ..paging::MapOptions::default() });
    let [pdpt, pd, pt] = walk(root, LOOSE_VA);
    let tracked = tracker::tables_of(root);
    let all_tracked = [root, pdpt, pd, pt].iter().all(|table| *table != 0 && tracked.contains(table));
    assert(mapped && all_tracked, "tabelas: a raiz avulsa e a PDPT, a PD e a PT da pagina mapeada nela estao no rastreador");
    assert(!descriptors::can_release(pt) && !descriptors::can_release(frame) && !descriptors::can_release(root), "tabelas: a PT ligada, a pagina mapeada e a raiz nao podem voltar ao PFN");
    // Uma desmontagem que esquecesse as tabelas: a PML4E some por fora.
    let entry_address = root + paging::pml4_index(LOOSE_VA) * 8;
    let saved = paging::read_entry_exact(entry_address);
    physical::write64(entry_address, 0);
    let refused = address_space::delete_root(root).is_err() && address_space::is_root(root);
    physical::write64(entry_address, saved);
    assert(refused, "tabelas: delete_root recusa uma raiz cujas tabelas ainda estao no rastreador (vazamento pego)");
    // Desmontagem certa, como a do término: a folha, a metade de usuário e a
    // raiz.
    let unmapped = paging::unmap_page_in(root, LOOSE_VA, paging::MapOptions::default());
    let freed = frame != 0 && pfn::free_page(frame);
    let released = paging::release_user_half_in(root, &[]);
    let deleted = address_space::delete_root(root);
    let gone = tracker::tables_of(root).is_empty() && [root, pdpt, pd, pt].iter().all(|&table| unreferenced(table));
    let ok = unmapped && freed && released.is_ok() && deleted.is_ok() && gone;
    if !ok {
        crate::debug_print!("[tabelas] raiz avulsa: desmapeada={} folha devolvida={} metade={:?} delete={:?} fora={}", unmapped, freed, released.as_ref().map_err(|error| alloc::format!("{error}")), deleted.as_ref().map_err(|error| alloc::format!("{error}")), gone);
    }
    assert(ok, "tabelas: desfeita a pagina, as tabelas e a raiz voltam e saem do rastreador");
    assert(address_space::delete_root(root).is_err(), "tabelas: a raiz devolvida nao passa duas vezes");
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 || state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        assert(false, "tabelas: thread corrente e ntdll com LdrInitializeThunk");
        return;
    }
    process_scenario(assert);
    loose_root_scenario(assert);
}
