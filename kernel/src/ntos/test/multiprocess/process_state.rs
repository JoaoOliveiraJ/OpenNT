//! O registro de estado por EPROCESS (`ps/user/process_state`): o System e
//! todo processo da lista ativa têm estado; dois processos novos ganham
//! estados distintos; o estado corrente segue a thread corrente e o attach;
//! cada estado some no término do seu processo, sem tocar no do outro.

use alloc::sync::Arc;

use crate::ntos::ke::process_attachment;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::ntos::ps::cid;
use crate::ntos::ps::process::{self, SYSTEM_PROCESS_ID};
use crate::ntos::ps::user::process_state::{self, ProcessState};

type Assert = fn(bool, &str);

/// EPROCESS.UniqueProcessId (os processos do teste pegam o próximo id livre).
fn process_id(process: u64) -> u64 {
    // SAFETY: EPROCESS vivo criado pelo teste.
    unsafe { Eprocess::at(process) }.unique_process_id.get()
}

fn same(left: &Option<Arc<ProcessState>>, right: &Option<Arc<ProcessState>>) -> bool {
    matches!((left, right), (Some(left), Some(right)) if Arc::ptr_eq(left, right))
}

pub fn run(assert: Assert) {
    let system = process::get_system_process();
    let system_state = process_state::get(system);
    assert(system_state.as_ref().is_some_and(|state| state.process == system && state.process_id == SYSTEM_PROCESS_ID), "estado: System tem estado proprio");
    assert(process::list_active_processes().iter().all(|entry| process_state::get(entry.address).is_some_and(|state| state.process_id == entry.pid)), "estado: todo processo ativo tem estado");
    assert(same(&process_state::current(), &process_state::get(process::get_current_process())), "estado: corrente vem do ApcState.Process");

    let Ok(first) = process::create_process(cid::ALLOCATE, "estado-a.exe", 0, None) else {
        assert(false, "estado: primeiro processo criado");
        return;
    };
    let Ok(second) = process::create_process(cid::ALLOCATE, "estado-b.exe", 0, None) else {
        let _ = process::terminate_process(first, 0);
        assert(false, "estado: segundo processo criado");
        return;
    };
    let first_state = process_state::get(first);
    let second_state = process_state::get(second);
    let (first_id, second_id) = (process_id(first), process_id(second));
    assert(first_state.as_ref().is_some_and(|state| state.process == first && state.process_id == first_id), "estado: primeiro processo ganha estado");
    assert(second_state.as_ref().is_some_and(|state| state.process == second && state.process_id == second_id), "estado: segundo processo ganha estado");
    assert(!same(&first_state, &second_state) && !same(&first_state, &system_state), "estado: estados distintos");
    assert(process_state::create(first, first_id).is_err() && same(&process_state::get(first), &first_state), "estado: segundo estado do mesmo EPROCESS recusado");

    // A thread corrente decide o processo corrente.
    let thread = process::create_kernel_thread(first, cid::ALLOCATE, false, 0, None);
    assert(thread.is_ok(), "estado: thread do primeiro processo");
    if let Ok(thread) = thread {
        let previous = process::get_current_thread();
        process::set_current_thread(thread);
        let current = process_state::current();
        process::set_current_thread(previous);
        assert(same(&current, &first_state), "estado: corrente segue a thread corrente");
    }

    // Anexado, o processo corrente é o destino.
    if process::get_current_thread() != 0 {
        let original = process_state::current();
        let saved = guest::alloc_bytes(0x30);
        let attached = process_attachment::attach(second, saved);
        let during = process_state::current();
        let detached = process_attachment::detach(saved);
        assert(attached.is_ok() && same(&during, &second_state), "estado: corrente segue o processo anexado");
        assert(detached.is_ok() && same(&process_state::current(), &original), "estado: desanexado volta ao original");
        guest::free_bytes(saved);
    }

    // A thread ainda retém o EPROCESS, mas o estado já se foi.
    assert(process::terminate_process(first, 0).is_ok() && process_state::get(first).is_none() && (thread.is_err() || process::is_process(first)), "estado: some no termino do primeiro");
    assert(same(&process_state::get(second), &second_state), "estado: o outro processo mantem o seu");
    assert(!process_state::destroy(first), "estado: termino repetido nao acha estado");
    if let Ok(thread) = thread {
        let _ = process::release_thread(thread);
    }
    assert(!process::is_process(first), "estado: primeiro EPROCESS recolhido");
    assert(process::terminate_process(second, 0).is_ok() && process_state::get(second).is_none() && !process::is_process(second), "estado: some no termino do segundo");
    assert(same(&process_state::get(system), &system_state), "estado: System intacto");
}
