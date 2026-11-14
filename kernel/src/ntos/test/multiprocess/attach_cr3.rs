//! O attach troca o CR3 (`ke/context_switch.rs`, `ke/process_attachment.rs`):
//!
//! - anexado (KeStackAttachProcess) a um processo com espaço próprio
//!   (`process_address_space::create`), o CR3 é a raiz dele, e uma página
//!   mapeada só nessa raiz (e registrada no VAD dele, como as sondas do modo
//!   estrito de posse exigem) é lida e escrita pela VA de usuário, por sonda;
//! - desanexado, o CR3 volta à raiz do System e a mesma VA dá
//!   STATUS_ACCESS_VIOLATION na sonda;
//! - um attach aninhado (A, depois B; detach, detach) restaura cada raiz, e
//!   KeAttachProcess/KeDetachProcess fazem o mesmo;
//! - a troca de thread corrente carrega a raiz do processo da nova thread e
//!   a restauração volta à do System;
//! - o delete de um espaço carregado é recusado sem mudar nada e passa
//!   depois do detach.

use alloc::sync::Arc;
use core::any::Any;

use crate::hal::physical;
use crate::ntos::inc::types::{KapcState, Kprocess, NtStruct};
use crate::ntos::ke::{context_switch, process_attachment};
use crate::ntos::mm::guest_memory::{self as guest, STATUS_ACCESS_VIOLATION};
use crate::ntos::mm::paging::{self, MapOptions, PAGE_PRESENT, PAGE_RW, PAGE_USER};
use crate::ntos::mm::process_address_space::{self as address_space, SYSTEM_ROOT};
use crate::ntos::mm::shared_user_data::{self, MM_SHARED_USER_DATA_VA};
use crate::ntos::mm::pfn;
use crate::ntos::ps::process;
use crate::ntos::ps::user::memory::{self, Space};
use crate::ntos::ps::user::state::{RegionKind, UserRegion};

type Assert = fn(bool, &str);

const A_ID: u64 = 0x7ED0;
const A_THREAD_ID: u64 = 0x7ED4;
const B_ID: u64 = 0x7EE0;
const C_ID: u64 = 0x7EF0;
/// Uma VA de usuário que a raiz do System não mapeia.
const USER_VA: u64 = 0x0000_3A40_0000_0000;
const A_VALUE: u64 = 0xA4A4_0000_0000_00A4;
const B_VALUE: u64 = 0xB4B4_0000_0000_00B4;

/// A página de teste no VAD do processo: mapeada à mão na raiz dele, sem
/// página do PFN de região (o teste a desfaz antes do término).
struct TestPage;

impl UserRegion for TestPage {
    fn base(&self) -> u64 {
        USER_VA
    }
    fn size(&self) -> u64 {
        0x1000
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn directory_table_base(process: u64) -> u64 {
    // SAFETY: EPROCESS vivo criado pelo teste.
    unsafe { Kprocess::at(process) }.directory_table_base.get()
}

/// A raiz no CR3 e a registrada para esta CPU.
fn loaded(root: u64) -> bool {
    paging::current_root() == root && context_switch::loaded_root() == root
}

/// A sonda da VA de usuário dá ACCESS_VIOLATION.
fn faults() -> bool {
    guest::try_read64(USER_VA).is_err_and(|error| error.status == STATUS_ACCESS_VIOLATION)
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "attach-cr3: thread corrente para o attach");
        return;
    }
    let created = [process::create_process(A_ID, "cr3-a.exe", 0, None), process::create_process(B_ID, "cr3-b.exe", 0, None), process::create_process(C_ID, "cr3-c.exe", 0, None)];
    let [Ok(a), Ok(b), Ok(c)] = created else {
        for process in created.into_iter().flatten() {
            let _ = process::terminate_process(process, 0);
        }
        assert(false, "attach-cr3: tres processos criados");
        return;
    };
    let roots = [a, b, c].map(address_space::create);
    let frames = [pfn::alloc_page(), pfn::alloc_page()];
    let ready = match (&roots, frames) {
        ([Ok(a_root), Ok(b_root), Ok(c_root)], [a_frame, b_frame]) if a_frame != 0 && b_frame != 0 => Some(([*a_root, *b_root, *c_root], [a_frame, b_frame])),
        _ => None,
    };
    if let Some(([a_root, b_root, c_root], [a_frame, b_frame])) = ready {
        assert(paging::translate_in(SYSTEM_ROOT, USER_VA) == 0 && loaded(SYSTEM_ROOT), "attach-cr3: a raiz do System carregada e sem a VA de teste");
        let mut mapped = true;
        for (process, root, frame, value) in [(a, a_root, a_frame, A_VALUE), (b, b_root, b_frame, B_VALUE)] {
            physical::write64(frame, value);
            mapped &= paging::map_page_in(root, USER_VA, frame, PAGE_PRESENT | PAGE_RW | PAGE_USER, MapOptions { nx: true, ..MapOptions::default() });
            mapped &= memory::insert_region(Space::of(process), RegionKind::User, Arc::new(TestPage));
        }
        assert(mapped, "attach-cr3: pagina de usuario mapeada nos espacos de A e B");
        if mapped {
            stack_attach(assert, [a, b], [a_root, b_root], a_frame);
            legacy_attach(assert, b, b_root);
            current_thread(assert, a, a_root);
        }
        for root in [a_root, b_root] {
            paging::unmap_page_in(root, USER_VA, MapOptions { skip_invalidate: true, ..MapOptions::default() });
        }
        delete_while_loaded(assert, c, c_root);
    } else {
        assert(false, "attach-cr3: espacos e frames de teste");
    }
    for frame in frames.into_iter().filter(|&frame| frame != 0) {
        pfn::free_page(frame);
    }
    let deleted = [a, b, c].into_iter().zip(roots).all(|(process, root)| root.is_err() || address_space::root_of(process).is_none() || address_space::delete(process).is_ok());
    assert(deleted, "attach-cr3: espacos devolvidos depois do detach");
    for process in [a, b, c] {
        let _ = process::terminate_process(process, 0);
    }
}

/// KeStackAttachProcess/KeUnstackDetachProcess, simples e aninhados.
fn stack_attach(assert: Assert, [a, b]: [u64; 2], [a_root, b_root]: [u64; 2], a_frame: u64) {
    assert(faults(), "attach-cr3: sem attach, a VA de usuario da ACCESS_VIOLATION");
    let states = [guest::alloc_bytes(KapcState::SIZE), guest::alloc_bytes(KapcState::SIZE)];
    if states.contains(&0) {
        states.into_iter().filter(|&state| state != 0).for_each(guest::free_bytes);
        assert(false, "attach-cr3: KAPC_STATE de teste");
        return;
    }
    let [outer, inner] = states;

    let attached = process_attachment::attach(a, outer).is_ok();
    let read = guest::try_read64(USER_VA).ok();
    let written = guest::try_write64(USER_VA, A_VALUE + 1).is_ok() && physical::read64(a_frame) == A_VALUE + 1 && guest::try_read64(USER_VA).ok() == Some(A_VALUE + 1);
    assert(attached && loaded(a_root) && context_switch::is_root_loaded(a_root), "attach-cr3: anexado, o CR3 e a raiz do processo");
    assert(read == Some(A_VALUE), "attach-cr3: anexado, le o valor gravado na pagina do espaco");
    assert(written, "attach-cr3: anexado, a escrita pela VA cai no frame do espaco");

    // Aninhado: A -> B -> A -> System.
    let nested = attached && process_attachment::attach(b, inner).is_ok();
    assert(nested && loaded(b_root) && guest::try_read64(USER_VA).ok() == Some(B_VALUE), "attach-cr3: attach aninhado carrega a raiz do segundo processo");
    let back = nested && process_attachment::detach(inner).is_ok();
    assert(back && loaded(a_root) && guest::try_read64(USER_VA).ok() == Some(A_VALUE + 1), "attach-cr3: detach aninhado restaura a raiz do primeiro");
    let detached = attached && process_attachment::detach(outer).is_ok();
    assert(detached && loaded(SYSTEM_ROOT) && !context_switch::is_root_loaded(a_root) && !context_switch::is_root_loaded(b_root), "attach-cr3: detach restaura a raiz do System");
    assert(faults(), "attach-cr3: desanexado, a mesma VA da ACCESS_VIOLATION");
    states.into_iter().for_each(guest::free_bytes);
}

/// KeAttachProcess/KeDetachProcess.
fn legacy_attach(assert: Assert, b: u64, b_root: u64) {
    let attached = process_attachment::attach_legacy(b).is_ok();
    let during = loaded(b_root) && guest::try_read64(USER_VA).ok() == Some(B_VALUE);
    let detached = attached && process_attachment::detach_legacy().is_ok();
    assert(attached && during, "attach-cr3: KeAttachProcess carrega a raiz do processo");
    assert(detached && loaded(SYSTEM_ROOT) && faults(), "attach-cr3: KeDetachProcess restaura a raiz do System");
}

/// A troca de thread corrente carrega a raiz do processo da thread.
fn current_thread(assert: Assert, a: u64, a_root: u64) {
    let Ok(thread) = process::create_kernel_thread(a, A_THREAD_ID, false, 0, None) else {
        assert(false, "attach-cr3: thread do processo com espaco proprio");
        return;
    };
    let previous = process::get_current_thread();
    process::set_current_thread(thread);
    let during = loaded(a_root) && guest::try_read64(USER_VA).ok() == Some(A_VALUE + 1);
    process::set_current_thread(previous);
    assert(during, "attach-cr3: a thread corrente de outro espaco carrega a raiz dele");
    assert(loaded(SYSTEM_ROOT) && faults(), "attach-cr3: restaurar a thread anterior volta a raiz do System");
    let _ = process::release_thread(thread);
    assert(loaded(SYSTEM_ROOT), "attach-cr3: o termino da thread (rodado como ela) volta a raiz do System");
}

/// O delete de um espaço carregado é recusado sem mudar nada.
fn delete_while_loaded(assert: Assert, c: u64, c_root: u64) {
    let state = guest::alloc_bytes(KapcState::SIZE);
    if state == 0 {
        assert(false, "attach-cr3: KAPC_STATE de teste");
        return;
    }
    let shared = shared_user_data::frame();
    let attached = process_attachment::attach(c, state).is_ok();
    let refused = attached && loaded(c_root) && address_space::delete(c).is_err();
    let intact = address_space::root_of(c) == Some(c_root) && directory_table_base(c) == c_root && paging::translate_in(c_root, MM_SHARED_USER_DATA_VA) == shared && loaded(c_root);
    let detached = attached && process_attachment::detach(state).is_ok();
    guest::free_bytes(state);
    assert(refused && intact, "attach-cr3: delete de espaco carregado recusado sem mudar nada");
    let deleted = detached && loaded(SYSTEM_ROOT) && address_space::delete(c).is_ok();
    assert(deleted && address_space::root_of(c).is_none() && directory_table_base(c) == SYSTEM_ROOT, "attach-cr3: depois do detach o delete passa");
}
