//! Autotestes do recolhimento de threads: tudo o que uma thread de usuário
//! possui volta quando ela sai e a última referência some, como o
//! PspExitThread, o ceifador (PspReaper) e o PspThreadDelete do 19041 o
//! devolvem, num processo de teste com milhares de threads:
//!
//! - criar, terminar, fechar o handle e recolher 2000 threads não deixa o
//!   heap do kernel nem a arena dos convidados crescerem além de um limite
//!   pequeno (bem menos que um bloco por thread), e nada delas sobra no
//!   índice de threads nem no registro das ETHREADs;
//! - com os handles guardados, as 2000 threads mortas seguem com a ETHREAD
//!   (o objeto vive enquanto há handle, como no NT) e o resto delas (pilhas,
//!   TEB, CONTEXT, pilha de kernel) já voltou; fechar os handles devolve as
//!   ETHREADs e o heap volta ao que era;
//! - o vigia de thread do Explorer (CreateThread + CreateThreadpoolWait +
//!   SetThreadpoolWait no handle da thread): um pacote de espera associado
//!   ao handle de cada thread vai para a IOCP quando ela sai, é retirado, e
//!   fechar o pacote e o handle da thread devolve os dois objetos.
//!
//! As threads nunca rodam: nascem suspensas pelo NtCreateThreadEx e saem
//! pelo NtTerminateThread de outra thread do processo; o teste faz o papel
//! do ceifador do despachante (`threads::release_execution_resources`).

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::hal::kmalloc;
use crate::ntos::inc::types::{Eprocess, ImageDosHeader, ImageNtHeaders64, NtStruct, Peb};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::{dispatcher as dispatcher_objects, work as work_objects};
use crate::ntos::ps::process;
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::user::{memory, state, wait_packets};
use crate::ntos::test::multiprocess::identity::{with_test_process, TestProcess};

type Assert = fn(bool, &str);

const STATUS_SUCCESS: u32 = 0;
/// Threads de cada rodada medida.
const THREADS: usize = 2000;
/// Rodada de aquecimento antes da medida (tabelas que crescem uma vez).
const WARM_UP: usize = 64;
/// Crescimento aceito do heap do kernel e da arena numa rodada inteira:
/// 4 bytes por thread, menos que o menor bloco que uma thread vazasse.
const SLACK: usize = THREADS * 4;

pub fn run(assert: Assert) {
    let ran = with_test_process("recolhe.exe", None, |test| run_in(assert, test));
    assert(ran.is_some(), "recolhimento: processo de usuario do teste");
}

/// Bytes usados no heap do kernel e na arena dos convidados.
fn usage() -> (usize, usize) {
    (kmalloc::info().1, guest::usage().1 as usize)
}

/// `after` não passa de `before` mais `slack`, nos dois heaps.
fn within(before: (usize, usize), after: (usize, usize), slack: usize) -> bool {
    after.0 <= before.0 + slack && after.1 <= before.1 + slack
}

/// A medida de uma rodada na serial: heap do kernel e arena, em bytes.
fn report(phase: &str, before: (usize, usize), after: (usize, usize)) {
    crate::debug_print!("[recolhimento] {}: heap {} -> {} bytes, arena {} -> {} bytes", phase, before.0, after.0, before.1, after.1);
}

/// O ambiente de chamadas: memória de usuário do teste e a pilha de
/// argumentos dos serviços.
struct Calls {
    block: u64,
    out: u64,
    info: u64,
    raw: u64,
    rsp: u64,
}

impl Calls {
    fn call(&self, name: &str, a1: u64, a2: u64, a3: u64, a4: u64) -> u32 {
        state::handler(name).map(|handler| handler(a1, a2, a3, a4, self.rsp).unwrap_or(1)).unwrap_or(1)
    }

    /// NtCreateThreadEx suspensa, sem lista de atributos; o handle e a
    /// thread de usuário.
    fn create(&self) -> Option<(u64, Arc<UserThread>)> {
        for (offset, value) in [(0x28u64, self.block + 0x800), (0x30, 0), (0x38, 1), (0x40, 0), (0x48, 0), (0x50, 0), (0x58, 0)] {
            guest::write64(self.rsp + offset, value);
        }
        if self.call("NtCreateThreadEx", self.out, 0x1F_FFFF, 0, u64::MAX) != STATUS_SUCCESS {
            return None;
        }
        let handle = guest::read64(self.out);
        threads::resolve(handle, 0).ok().map(|thread| (handle, thread))
    }

    /// NtTerminateThread por outra thread e o recolhimento do ceifador.
    fn terminate(&self, handle: u64, thread: &Arc<UserThread>) -> bool {
        let terminated = self.call("NtTerminateThread", handle, 0, 0, 0) == STATUS_SUCCESS && thread.dead();
        threads::release_execution_resources(thread);
        terminated
    }

    /// Uma thread inteira: cria, termina, recolhe e fecha o handle.
    fn lifecycle(&self) -> bool {
        let Some((handle, thread)) = self.create() else { return false };
        let terminated = self.terminate(handle, &thread);
        terminated && self.call("NtClose", handle, 0, 0, 0) == STATUS_SUCCESS && thread.pointer() == 0
    }

    /// O vigia do Explorer: o pacote de espera associado ao handle da
    /// thread vai para a porta quando ela sai e é retirado; o pacote e o
    /// handle da thread são fechados. Devolve o ponteiro do corpo do pacote.
    fn watched_lifecycle(&self, port: u64) -> Option<u64> {
        let (handle, thread) = self.create()?;
        let created = self.call("NtCreateWaitCompletionPacket", self.out, 0xF_0001, 0, 0) == STATUS_SUCCESS;
        let packet_handle = guest::read64(self.out);
        let packet = state::get_user_handle(packet_handle).and_then(|entry| entry.downcast::<dispatcher_objects::UserDispatcher>().map(|dispatcher| dispatcher.pointer)).unwrap_or(0);
        // Chave do frame bruto; contexto, status e informação na pilha; sem
        // AlreadySignaled.
        guest::write64(self.raw + 32, 0x5649_4749_4100_0000 | handle);
        for (offset, value) in [(0x28u64, packet), (0x30, 0), (0x38, 0), (0x40, 0)] {
            guest::write64(self.rsp + offset, value);
        }
        let associated = created && state::with_syscall_record(state::SyscallRecord::raw(self.raw), || self.call("NtAssociateWaitCompletionPacket", packet_handle, port, handle, 0)) == STATUS_SUCCESS;
        let terminated = self.terminate(handle, &thread);
        wait_packets::pump();
        // Retirada sem prazo: o pacote já está na fila.
        guest::write64(self.rsp + 0x28, 0);
        let removed = self.call("NtRemoveIoCompletion", port, self.info, self.info + 8, self.info + 16) == STATUS_SUCCESS && guest::read64(self.info + 8) == packet;
        let closed = self.call("NtClose", handle, 0, 0, 0) == STATUS_SUCCESS && self.call("NtClose", packet_handle, 0, 0, 0) == STATUS_SUCCESS;
        (associated && terminated && removed && closed && thread.pointer() == 0).then_some(packet)
    }
}

fn run_in(assert: Assert, test: &TestProcess) {
    let Ok(block) = memory::map_user_region(0x4000) else {
        assert(false, "recolhimento: memoria de usuario");
        return;
    };
    let image = block + 0x1000;
    let calls = Calls { block, out: block, info: block + 0x40, raw: block + 0x100, rsp: block + 0x3000 };
    // PEB e cabeçalho de imagem mínimos (reserva de pilha de 0x20000).
    // SAFETY: memória de usuário do teste.
    unsafe {
        Peb::at(test.peb).image_base_address.set(image);
        ImageDosHeader::at(image).e_lfanew.set(0x80);
        ImageNtHeaders64::at(image + 0x80).optional_header.size_of_stack_reserve.set(0x20000);
    }
    let process_pointer = test.process;
    // SAFETY: o EPROCESS do teste.
    let baseline_threads = unsafe { Eprocess::at(process_pointer) }.active_threads.get();
    if baseline_threads == 0 {
        process::add_thread(process_pointer);
    }
    threads::set_running(true, None);
    let indexed = || threads::of_process(process_pointer).len();
    let registered = || process::thread_census().0 as usize;

    // Criar, terminar, recolher e fechar: nada sobra.
    let warmed = (0..WARM_UP).all(|_| calls.lifecycle());
    let (index_before, records_before, before) = (indexed(), registered(), usage());
    let completed = (0..THREADS).all(|_| calls.lifecycle());
    let after = usage();
    report("2000 threads fechadas", before, after);
    assert(warmed && completed, "recolhimento: 2000 threads criadas, terminadas e fechadas");
    assert(indexed() == index_before && registered() == records_before, "recolhimento: nada das threads fechadas no indice nem no registro das ETHREADs");
    assert(within(before, after, SLACK), "recolhimento: o heap do kernel e a arena voltam ao inicio depois de 2000 threads");

    // Com os handles guardados as ETHREADs ficam; fechar os handles as
    // devolve. Uma rodada de aquecimento faz a tabela de handles crescer.
    let keep = |count: usize| -> Option<Vec<(u64, Arc<UserThread>)>> {
        let mut kept = Vec::with_capacity(count);
        for _ in 0..count {
            let (handle, thread) = calls.create()?;
            let terminated = calls.terminate(handle, &thread);
            kept.push((handle, thread));
            if !terminated {
                return None;
            }
        }
        Some(kept)
    };
    let close_all = |kept: Vec<(u64, Arc<UserThread>)>| kept.iter().all(|(handle, thread)| calls.call("NtClose", *handle, 0, 0, 0) == STATUS_SUCCESS && thread.pointer() == 0);
    let warmed = keep(THREADS).is_some_and(close_all);
    let (records_before, before) = (registered(), usage());
    let kept = keep(THREADS);
    let held = kept.as_ref().is_some_and(|kept| {
        let alive = kept.iter().all(|(_, thread)| thread.dead() && thread.pointer() != 0 && thread.with(|thread| thread.regions.is_none() && thread.context == 0));
        alive && registered() == records_before + THREADS && indexed() == index_before + THREADS
    });
    let holding = usage();
    let closed = kept.is_some_and(close_all);
    let after = usage();
    report("2000 threads com os handles guardados", before, holding);
    report("os 2000 handles fechados", before, after);
    assert(warmed && held, "recolhimento: com os handles guardados as threads mortas seguem com a ETHREAD e sem pilha, TEB nem CONTEXT");
    assert(holding.1 > before.1 + SLACK, "recolhimento: as ETHREADs retidas pelos handles ocupam a arena");
    assert(closed && registered() == records_before && indexed() == index_before && within(before, after, SLACK), "recolhimento: fechar os handles devolve as ETHREADs e o heap volta ao inicio");

    // O vigia do Explorer: pacote de espera no handle de cada thread.
    guest::write64(calls.rsp + 0x28, 0);
    let port_created = calls.call("NtCreateIoCompletion", calls.out, 0x1F_0003, 0, 1) == STATUS_SUCCESS;
    let port = guest::read64(calls.out);
    let warmed = port_created && (0..WARM_UP).all(|_| calls.watched_lifecycle(port).is_some());
    let (records_before, before) = (registered(), usage());
    let mut freed = true;
    let mut completed = warmed;
    for _ in 0..THREADS {
        match calls.watched_lifecycle(port) {
            Some(packet) => freed &= work_objects::packet_of(packet).is_none() && dispatcher_objects::get(packet).is_none(),
            None => completed = false,
        }
        if !completed {
            break;
        }
    }
    let after = usage();
    report("2000 threads vigiadas por pacotes de espera", before, after);
    let _ = calls.call("NtClose", port, 0, 0, 0);
    assert(completed, "recolhimento: o pacote de espera no handle de cada thread vai para a IOCP quando ela sai");
    assert(freed && registered() == records_before && indexed() == index_before, "recolhimento: fechar o pacote e o handle da thread devolve os dois objetos");
    assert(within(before, after, SLACK), "recolhimento: o heap volta ao inicio depois de 2000 threads vigiadas por pacotes de espera");

    threads::set_running(false, None);
    if baseline_threads == 0 {
        process::remove_thread(process_pointer);
    }
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
}
