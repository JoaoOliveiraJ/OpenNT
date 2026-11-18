//! Autotestes da varredura anti-inanição do KiQuantumEnd 19041 (0x257550,
//! `ke/thread_dispatch.rs::boost_starved_threads_locked`), num processo de
//! teste com duas threads de usuário:
//!
//! - a thread A (base 10) gasta o quantum com a B (base 6) pronta há mais de
//!   300 ticks: a B sai da fila e volta com prioridade 15, com o
//!   PriorityDecrement de (15 - 6) << 4, e o despacho seguinte a escolhe;
//! - no fim do quantum seguinte da B, o compute_quantum_end_priority desfaz
//!   o impulso e ela volta à base;
//! - a varredura seguinte só vem 75 ticks depois: uma B faminta de novo não
//!   sobe antes disso.
//!
//! As threads nunca rodam: o processo de teste não entrou no despachante e
//! as duas voltam a ficar suspensas antes do fim.

use alloc::sync::Arc;

use crate::ntos::inc::types::{ImageDosHeader, ImageNtHeaders64, Kthread, NtStruct, Peb};
use crate::ntos::ke::{thread_dispatch, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::multiprocess::identity::{with_test_process, TestProcess};

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u32 = 0;

pub fn run(assert: Assert) {
    let ran = with_test_process("starve.exe", None, |test| run_in(assert, test));
    assert(ran.is_some(), "anti-inanicao: processo de usuario do teste");
}

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: KTHREAD das threads de teste, vivas até o fim.
    unsafe { Kthread::at(thread) }
}

/// Uma fatia de execução de `thread` com o quantum gasto.
fn expire(thread: u64, owner: &Arc<UserThread>) -> bool {
    let previous_thread = process::get_current_thread();
    let began = thread_dispatch::begin_execution(thread).is_ok();
    process::set_current_thread(thread);
    threads::set_running(true, Some(owner.clone()));
    kthread(thread).quantum_target.set(kthread(thread).cycle_time.get());
    let ended = began && thread_dispatch::end_execution(thread, thread_dispatch::state::READY).is_ok();
    process::set_current_thread(previous_thread);
    threads::set_running(true, None);
    ended
}

fn run_in(assert: Assert, test: &TestProcess) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "anti-inanicao: memoria de usuario");
        return;
    };
    let (out, info, image, rsp) = (block, block + 0x40, block + 0x1000, block + 0x3000);
    let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(1);
    // PEB e cabeçalho de imagem mínimos (reserva de pilha de 0x20000).
    // SAFETY: memória de usuário do teste.
    unsafe {
        Peb::at(test.peb).image_base_address.set(image);
        ImageDosHeader::at(image).e_lfanew.set(0x80);
        ImageNtHeaders64::at(image + 0x80).optional_header.size_of_stack_reserve.set(0x20000);
    }
    let process_pointer = test.process;
    // SAFETY: o EPROCESS do teste.
    let baseline = unsafe { crate::ntos::inc::types::Eprocess::at(process_pointer) }.active_threads.get();
    if baseline == 0 {
        process::add_thread(process_pointer);
    }
    // NtCreateThreadEx suspensa e oculta, sem lista de atributos.
    for (offset, value) in [(0x28u64, block + 0x800), (0x30, 0), (0x38, 5), (0x40, 0), (0x48, 0), (0x50, 0), (0x58, 0)] {
        guest::write64(rsp + offset, value);
    }
    threads::set_running(true, None);
    let create = || -> Option<(u64, Arc<UserThread>)> {
        if call("NtCreateThreadEx", out, 0x1F_FFFF, 0, u64::MAX) != STATUS_SUCCESS {
            return None;
        }
        let handle = guest::read64(out);
        threads::resolve(handle, 0).ok().map(|thread| (handle, thread))
    };
    let (Some((handle_a, thread_a)), Some((handle_b, thread_b))) = (create(), create()) else {
        assert(false, "anti-inanicao: duas threads suspensas");
        threads::set_running(false, None);
        return;
    };
    let (a, b) = (thread_a.pointer(), thread_b.pointer());

    // ThreadBasePriority (3): A com +2 (base 10), B com -2 (base 6).
    guest::write32(info, 2);
    let raised = call("NtSetInformationThread", handle_a, 3, info, 4) == STATUS_SUCCESS;
    guest::write32(info, (-2i32) as u32);
    let lowered = call("NtSetInformationThread", handle_b, 3, info, 4) == STATUS_SUCCESS;
    let resumed = call("NtResumeThread", handle_b, 0, 0, 0) == STATUS_SUCCESS && call("NtResumeThread", handle_a, 0, 0, 0) == STATUS_SUCCESS;
    let bases = thread_priority::query_base_priority(a) == 10 && thread_priority::query_base_priority(b) == 6 && thread_priority::query_priority(b) == 6;
    assert(raised && lowered && resumed && bases, "anti-inanicao: A com base 10 e B com base 6, prontas");

    // B pronta há 5 s; A gasta o quantum com a varredura vencida.
    kthread(b).wait_time.set(thread_dispatch::tick_count().wrapping_sub(5000));
    thread_dispatch::force_starvation_scan();
    let expired_a = expire(a, &thread_a);
    let boosted = thread_priority::query_priority(b) == 15 && (kthread(b).priority_decrement.get() as u8) >> 4 == 9;
    let a_kept = thread_priority::query_priority(a) == 10;
    let selected = thread_dispatch::peek().ok().flatten().map(|(thread, _)| thread);
    assert(expired_a && boosted && a_kept && selected == Some(b), "anti-inanicao: a pronta faminta sobe a 15 no fim do quantum e o despacho seguinte a escolhe");

    // O fim do quantum da B desfaz o impulso: volta à base 6.
    let expired_b = expire(b, &thread_b);
    assert(expired_b && thread_priority::query_priority(b) == 6, "anti-inanicao: o fim do quantum seguinte desfaz o impulso");

    // A varredura seguinte só vem 75 ticks depois.
    kthread(b).wait_time.set(thread_dispatch::tick_count().wrapping_sub(5000));
    let expired_again = expire(a, &thread_a);
    assert(expired_again && thread_priority::query_priority(b) == 6, "anti-inanicao: sem nova varredura antes de 75 ticks");

    // As duas voltam a ficar suspensas e terminam.
    let suspended = call("NtSuspendThread", handle_a, 0, 0, 0) == STATUS_SUCCESS && call("NtSuspendThread", handle_b, 0, 0, 0) == STATUS_SUCCESS && thread_dispatch::next_thread() != b && thread_dispatch::next_thread() != a;
    assert(suspended, "anti-inanicao: as threads saem da fila suspensas");
    for (handle, thread) in [(handle_a, &thread_a), (handle_b, &thread_b)] {
        let _ = call("NtTerminateThread", handle, 0, 0, 0);
        let _ = call("NtClose", handle, 0, 0, 0);
        threads::release_execution_resources(thread);
    }
    threads::set_running(false, None);
    if baseline == 0 {
        process::remove_thread(process_pointer);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
