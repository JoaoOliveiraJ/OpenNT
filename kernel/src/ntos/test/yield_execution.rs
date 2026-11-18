//! Autotestes do NtYieldExecution como o KeYieldExecution(0) do ntoskrnl
//! 19041 (`ke/thread_dispatch.rs::request_yield_execution`), num processo de
//! teste com duas threads de usuário:
//!
//! - a thread A (prioridade 10, base 8) em execução cede com só a B
//!   (prioridade 8) e threads do sistema na fila: o KiSelectReadyThreadEx(
//!   Prcb, NULL, 1) aceita qualquer pronta a partir da prioridade 1, então o
//!   serviço devolve STATUS_SUCCESS (com a regra de "igual ou maior" seria
//!   STATUS_NO_YIELD_PERFORMED);
//! - no fim da execução a prioridade de A cai como no fim do quantum (o
//!   KiComputeNewPriority com ajuste 1: 9) e o despacho seguinte não escolhe
//!   A; quando a B é a sucessora, ela fica reservada na NextThread (Standby)
//!   mesmo com A, mais prioritária, na fila.
//!
//! As threads nunca rodam: o processo de teste não entrou no despachante e
//! as duas voltam a ficar suspensas antes do fim.

use alloc::sync::Arc;

use crate::ntos::inc::types::{ImageDosHeader, ImageNtHeaders64, NtStruct, Peb};
use crate::ntos::ke::{thread_dispatch, thread_priority};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::multiprocess::identity::{with_test_process, TestProcess};

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u32 = 0;

pub fn run(assert: Assert) {
    let ran = with_test_process("yield.exe", None, |test| run_in(assert, test));
    assert(ran.is_some(), "yield: processo de usuario do teste");
}

fn run_in(assert: Assert, test: &TestProcess) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "yield: memoria de usuario");
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
        assert(false, "yield: duas threads suspensas");
        threads::set_running(false, None);
        return;
    };
    let (a, b) = (thread_a.pointer(), thread_b.pointer());

    // A com prioridade 10 (base 8), B com 8; as duas prontas.
    guest::write32(info, 10);
    let raised = call("NtSetInformationThread", handle_a, 2, info, 4) == STATUS_SUCCESS && thread_priority::query_priority(a) == 10 && thread_priority::query_base_priority(a) == thread_priority::query_base_priority(b) && thread_priority::query_priority(b) < 10;
    let resumed = call("NtResumeThread", handle_b, 0, 0, 0) == STATUS_SUCCESS && call("NtResumeThread", handle_a, 0, 0, 0) == STATUS_SUCCESS && thread_dispatch::thread_state(a) == thread_dispatch::state::READY && thread_dispatch::thread_state(b) == thread_dispatch::state::READY;
    // A em execução, como num intervalo do despachante, chama o serviço.
    let previous_thread = process::get_current_thread();
    let began = thread_dispatch::begin_execution(a).is_ok();
    process::set_current_thread(a);
    threads::set_running(true, Some(thread_a.clone()));
    let yielded = call("NtYieldExecution", 0, 0, 0, 0);
    let ended = began && thread_dispatch::end_execution(a, thread_dispatch::state::READY).is_ok();
    process::set_current_thread(previous_thread);
    threads::set_running(true, None);
    let decayed = thread_priority::query_priority(a) == 9;
    let selected = thread_dispatch::peek().ok().flatten().map(|(thread, _)| thread);
    let reserved = selected != Some(b) || thread_dispatch::thread_state(b) == thread_dispatch::state::STANDBY;
    assert(raised && resumed, "yield: A com prioridade 10 e B com 8, prontas");
    assert(yielded == STATUS_SUCCESS && ended, "yield: NtYieldExecution cede a uma pronta de prioridade menor");
    assert(decayed && selected.is_some_and(|thread| thread != a) && reserved, "yield: prioridade de quem cede cai como no fim do quantum e o despacho seguinte escolhe outra thread");

    // As duas voltam a ficar suspensas e terminam.
    let suspended = call("NtSuspendThread", handle_a, 0, 0, 0) == STATUS_SUCCESS && call("NtSuspendThread", handle_b, 0, 0, 0) == STATUS_SUCCESS && thread_dispatch::thread_state(a) == thread_dispatch::state::WAITING && thread_dispatch::thread_state(b) == thread_dispatch::state::WAITING && thread_dispatch::next_thread() != b;
    assert(suspended, "yield: as threads saem da fila e da NextThread suspensas");
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
