//! Espaço de endereçamento por processo (`mm/process_address_space.rs`,
//! MmCreateProcessAddressSpace/MmDeleteProcessAddressSpace):
//!
//! - dois processos novos ganham raízes próprias, gravadas em
//!   KPROCESS.DirectoryTableBase e no `ProcessState`; o CR3 continua na raiz
//!   do boot;
//! - a visão de usuário da KUSER_SHARED_DATA em 0x7FFE0000 está presente nas
//!   duas, somente leitura e sem execução, no frame da visão de kernel;
//! - a mesma VA de usuário mapeada nos dois espaços cai em frames diferentes
//!   (e a raiz do boot não vê nenhum dos dois), enquanto as VAs de kernel caem
//!   nos mesmos frames;
//! - o delete recusa, sem mudar nada, com página de usuário ainda mapeada;
//!   depois devolve todas as tabelas e a raiz: a contagem livre do PFN volta
//!   ao valor de antes da criação;
//! - o último dereference de um processo com espaço próprio libera o espaço.

use alloc::boxed::Box;
use core::sync::atomic::Ordering;

use crate::hal::physical;
use crate::ntos::inc::types::{Kprocess, NtStruct};
use crate::ntos::mm::paging::{self, MapOptions, PAGE_PRESENT, PAGE_RW, PAGE_USER};
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::mm::shared_user_data::{self, MM_SHARED_USER_DATA_VA, SHARED_USER_DATA_VA};
use crate::ntos::mm::{memory_map as map, pfn};
use crate::ntos::ps::{cid, process};
use crate::ntos::ps::user::process_state;

type Assert = fn(bool, &str);

/// Uma VA no mesmo slot da PML4 (e na mesma PDPT) da visão da KUSER.
const LOW_USER_VA: u64 = 0x1_4000_0000;
/// Uma VA no último slot de usuário da PML4.
const HIGH_USER_VA: u64 = map::HIGHEST_VAD_ADDRESS & !0xFFF;

fn directory_table_base(process: u64) -> u64 {
    // SAFETY: EPROCESS vivo criado pelo teste.
    unsafe { Kprocess::at(process) }.directory_table_base.get()
}

fn state_root(process: u64) -> Option<u64> {
    process_state::get(process).map(|state| state.directory_table_base.load(Ordering::Acquire))
}

pub fn run(assert: Assert) {
    let Ok(first) = process::create_process(cid::ALLOCATE, "espaco-a.exe", 0, None) else {
        assert(false, "espaco: primeiro processo criado");
        return;
    };
    let Ok(second) = process::create_process(cid::ALLOCATE, "espaco-b.exe", 0, None) else {
        let _ = process::terminate_process(first, 0);
        assert(false, "espaco: segundo processo criado");
        return;
    };
    assert(directory_table_base(first) == SYSTEM_ROOT && state_root(first) == Some(SYSTEM_ROOT), "espaco: processo do Ps nasce na raiz do System");
    assert(address_space::delete(first).is_err(), "espaco: delete sem espaco proprio recusado");

    let free_before = pfn::free_count();
    let (first_root, second_root) = match (address_space::create(first), address_space::create(second)) {
        (Ok(first_root), Ok(second_root)) => (first_root, second_root),
        (first_root, second_root) => {
            for (process, root) in [(first, first_root), (second, second_root)] {
                if let Err(error) = &root {
                    debug_print!("[espaco] create: {}", error);
                } else {
                    let _ = address_space::delete(process);
                }
            }
            let _ = process::terminate_process(first, 0);
            let _ = process::terminate_process(second, 0);
            assert(false, "espaco: dois espacos criados");
            return;
        }
    };
    exercise(assert, first, second, first_root, second_root);
    let deleted = address_space::delete(first).is_ok() && address_space::delete(second).is_ok();
    let free_after = pfn::free_count();
    if free_after != free_before {
        debug_print!("[espaco] PFN livre antes {} depois {}", free_before, free_after);
    }
    assert(deleted, "espaco: delete dos dois espacos");
    assert(free_after == free_before, "espaco: delete devolve todas as tabelas e a raiz (contagem do PFN igual)");
    assert(
        [first, second].iter().all(|&process| address_space::root_of(process).is_none() && directory_table_base(process) == SYSTEM_ROOT && state_root(process) == Some(SYSTEM_ROOT)),
        "espaco: depois do delete o processo volta a raiz do System",
    );
    assert(address_space::delete(first).is_err(), "espaco: segundo delete recusado");
    let _ = process::terminate_process(first, 0);
    let _ = process::terminate_process(second, 0);

    last_dereference(assert);
}

fn exercise(assert: Assert, first: u64, second: u64, first_root: u64, second_root: u64) {
    assert(paging::current_root() == SYSTEM_ROOT, "espaco: o CR3 segue na raiz do boot");
    assert(first_root != second_root && first_root != SYSTEM_ROOT && second_root != SYSTEM_ROOT, "espaco: raizes proprias e distintas");
    assert(directory_table_base(first) == first_root && directory_table_base(second) == second_root, "espaco: raiz em KPROCESS.DirectoryTableBase");
    assert(state_root(first) == Some(first_root) && state_root(second) == Some(second_root), "espaco: raiz no ProcessState");
    assert(address_space::root_of(first) == Some(first_root) && address_space::root_of(second) == Some(second_root), "espaco: raiz registrada no Mm");
    assert(address_space::create(first).is_err() && address_space::root_of(first) == Some(first_root), "espaco: segundo espaco do mesmo processo recusado");

    // A visão de usuário da KUSER_SHARED_DATA.
    let shared = shared_user_data::frame();
    for root in [first_root, second_root] {
        let query = paging::query_page_in(root, MM_SHARED_USER_DATA_VA, false);
        let access = paging::access_flags_in(root, MM_SHARED_USER_DATA_VA);
        assert(shared != 0 && paging::translate_in(root, MM_SHARED_USER_DATA_VA) == shared && paging::translate(SHARED_USER_DATA_VA) == shared, "espaco: KUSER em 0x7FFE0000 no frame da visao de kernel");
        assert(access & (PAGE_PRESENT | PAGE_USER | PAGE_RW) == PAGE_PRESENT | PAGE_USER, "espaco: KUSER de usuario presente e somente leitura");
        assert(query.is_some_and(|query| query.nx && query.page_size == 0x1000), "espaco: KUSER de usuario sem execucao, pagina de 4 KB");
    }

    // VAs de kernel: os mesmos frames nas três raízes.
    let marker = 0u64;
    let heap = Box::new(0u64);
    let kernel = [map::KERNEL_VIRTUAL_BASE, &marker as *const u64 as u64, &*heap as *const u64 as u64, SHARED_USER_DATA_VA, map::direct_map(0x1000), map::PFN_DATABASE_BASE];
    assert(
        kernel.iter().all(|&va| {
            let frame = paging::translate_in(SYSTEM_ROOT, va);
            frame != 0 && paging::translate_in(first_root, va) == frame && paging::translate_in(second_root, va) == frame
        }),
        "espaco: VAs de kernel nos mesmos frames nos dois espacos",
    );

    // A mesma VA de usuário nos dois espaços.
    let frames = [pfn::alloc_page(), pfn::alloc_page()];
    if frames.contains(&0) {
        frames.iter().filter(|&&frame| frame != 0).for_each(|&frame| {
            pfn::free_page(frame);
        });
        assert(false, "espaco: frames de teste");
        return;
    }
    let boot_view = [LOW_USER_VA, HIGH_USER_VA].map(|va| paging::translate_in(SYSTEM_ROOT, va));
    let mut mapped = true;
    for (root, frame, value) in [(first_root, frames[0], 0xA11CE_u64), (second_root, frames[1], 0xB0B_u64)] {
        physical::write64(frame, value);
        for va in [LOW_USER_VA, HIGH_USER_VA] {
            mapped &= paging::map_page_in(root, va, frame, PAGE_PRESENT | PAGE_RW | PAGE_USER, MapOptions { nx: true, ..MapOptions::default() });
        }
    }
    let isolated = [LOW_USER_VA, HIGH_USER_VA].iter().all(|&va| {
        let (in_first, in_second) = (paging::translate_in(first_root, va), paging::translate_in(second_root, va));
        in_first == frames[0] && in_second == frames[1] && physical::read64(in_first) == 0xA11CE && physical::read64(in_second) == 0xB0B
    });
    let boot_unchanged = [LOW_USER_VA, HIGH_USER_VA].map(|va| paging::translate_in(SYSTEM_ROOT, va)) == boot_view;
    assert(mapped, "espaco: a mesma VA de usuario mapeada nos dois espacos");
    assert(isolated, "espaco: a mesma VA de usuario cai em frames diferentes (conteudos diferentes)");
    assert(boot_unchanged, "espaco: a raiz do boot nao ve as paginas dos espacos novos");

    // Com página de usuário mapeada, o delete recusa e não muda nada.
    let refused = address_space::delete(first).is_err();
    let intact = address_space::root_of(first) == Some(first_root)
        && directory_table_base(first) == first_root
        && paging::translate_in(first_root, LOW_USER_VA) == frames[0]
        && paging::translate_in(first_root, MM_SHARED_USER_DATA_VA) == shared;
    assert(refused && intact, "espaco: delete recusa com pagina de usuario mapeada, sem mudar nada");

    for root in [first_root, second_root] {
        for va in [LOW_USER_VA, HIGH_USER_VA] {
            paging::unmap_page_in(root, va, MapOptions { skip_invalidate: true, ..MapOptions::default() });
        }
    }
    for frame in frames {
        pfn::free_page(frame);
    }
}

/// O último dereference de um processo com espaço próprio (o papel do
/// PspProcessDelete) devolve a raiz e as tabelas.
fn last_dereference(assert: Assert) {
    let free_before = pfn::free_count();
    let Ok(third) = process::create_process(cid::ALLOCATE, "espaco-c.exe", 0, None) else {
        assert(false, "espaco: terceiro processo criado");
        return;
    };
    let created = address_space::create(third).is_ok();
    let terminated = process::terminate_process(third, 0).is_ok();
    let collected = !process::is_process(third) && address_space::root_of(third).is_none();
    let free_after = pfn::free_count();
    if free_after != free_before {
        debug_print!("[espaco] PFN livre antes {} depois {} (ultimo dereference)", free_before, free_after);
    }
    assert(created && terminated && collected, "espaco: ultimo dereference libera o espaco do processo");
    assert(free_after == free_before, "espaco: processo com espaco proprio criado e recolhido sem perder frames");
}
