//! Identidade por processo e ids de cliente (`ps/cid.rs`).
//!
//! PIDs e TIDs de todos os processos e threads vivos nunca colidem, nem
//! entre dois processos de usuário criados ao mesmo tempo. Cada processo vê
//! o próprio PID, PEB, cookie e caminho de imagem pelos serviços Nt, e o
//! registro do serviço em curso é de cada thread.
//!
//! Inclui o fixture `with_test_process`, que roda o corpo de um autoteste
//! como um processo de usuário real.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread, ProcessBasicInformation, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::cid::{self, Entry, Kind};
use crate::ntos::ps::process;
use crate::ntos::ps::user::state::{self, SyscallRecord};
use crate::ntos::ps::user::{memory, process_state};

type Assert = fn(bool, &str);

/// Um processo de usuário real criado para um autoteste.
pub struct TestProcess {
    pub process: u64,
    pub process_id: u64,
    /// A thread de modo usuário corrente durante o corpo.
    pub thread: u64,
    pub thread_id: u64,
    pub peb: u64,
}

/// Executa `body` como um processo de usuário real: um EPROCESS novo (com
/// estado por processo e PID da tabela de ids de cliente), uma thread de
/// modo usuário dele como thread corrente e uma PEB em EPROCESS.Peb — a
/// `peb` dada pelo teste ou uma página de usuário mapeada aqui, no espaço do
/// próprio processo. No fim volta à thread anterior, solta a thread e
/// termina o processo. `None` se o processo não pôde ser montado.
pub fn with_test_process<R>(name: &str, peb: Option<u64>, body: impl FnOnce(&TestProcess) -> R) -> Option<R> {
    let process = process::create_process(cid::ALLOCATE, name, 0, None).ok()?;
    let Ok(thread) = process::create_kernel_thread(process, cid::ALLOCATE, true, 1, None) else {
        let _ = process::terminate_process(process, 0);
        return None;
    };
    let previous = process::get_current_thread();
    process::set_current_thread(thread);
    let owned = if peb.is_none() { memory::map_user_region(0x1000).ok() } else { None };
    let peb = peb.or(owned).unwrap_or(0);
    // SAFETY: EPROCESS e ETHREAD recém-criados, retidos até o fim.
    let (eprocess, ethread) = unsafe { (Eprocess::at(process), Ethread::at(thread)) };
    eprocess.peb.set(peb);
    let test = TestProcess { process, process_id: eprocess.unique_process_id.get(), thread, thread_id: ethread.cid.unique_thread.get(), peb };
    let result = (peb != 0).then(|| body(&test));
    if let Some(region) = owned.and_then(memory::find_region) {
        memory::release_private_region(&region);
    }
    process::set_current_thread(previous);
    let _ = process::release_thread(thread);
    let _ = process::terminate_process(process, 0);
    result
}

/// Os ids de todos os processos ativos e das threads vivas deles.
fn live_ids() -> Vec<(u64, Kind, u64)> {
    let mut ids = Vec::new();
    for entry in process::list_active_processes() {
        ids.push((entry.pid, Kind::Process, entry.address));
        for thread in entry.threads {
            ids.push((process::thread_record(thread).map_or(0, |record| record.id), Kind::Thread, thread));
        }
    }
    ids
}

/// Ids distintos, válidos e publicados na tabela com o dono certo.
fn consistent(ids: &[(u64, Kind, u64)]) -> bool {
    let mut values: Vec<u64> = ids.iter().map(|&(id, _, _)| id).collect();
    values.sort_unstable();
    values.dedup();
    values.len() == ids.len() && ids.iter().all(|&(id, kind, object)| cid::valid(id) && cid::lookup(id) == Some(Entry { kind, object }))
}

/// O que o processo corrente vê de si pelos serviços Nt.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    process_id: u64,
    peb: u64,
    cookie: u32,
    image: String,
}

fn seen() -> Option<Seen> {
    let block = memory::map_user_region(0x1000).ok()?;
    let (buffer, returned, rsp) = (block, block + 0x400, block + 0x800);
    guest::write64(rsp + 0x28, returned);
    let call = |class: u64, length: u64| state::handler("NtQueryInformationProcess").map(|handler| handler(u64::MAX, class, buffer, length, rsp).unwrap_or(1)).unwrap_or(1);
    let result = (|| {
        if call(0, ProcessBasicInformation::SIZE) != 0 {
            return None;
        }
        // SAFETY: saída recém-escrita pelo serviço no bloco do teste.
        let basic = unsafe { ProcessBasicInformation::at(buffer) };
        let (process_id, peb) = (basic.unique_process_id.get(), basic.peb_base_address.get());
        let cookie = (call(36, 4) == 0).then(|| guest::read32(buffer))?;
        let again = (call(36, 4) == 0).then(|| guest::read32(buffer))?;
        if call(27, 0x200) != 0 || again != cookie {
            return None;
        }
        // SAFETY: idem.
        let name = unsafe { UnicodeString::at(buffer) };
        let image = state::read_user_wide_string(name.buffer.get(), name.length.get() as u64 / 2);
        Some(Seen { process_id, peb, cookie, image })
    })();
    if let Some(region) = memory::find_region(block) {
        memory::release_private_region(&region);
    }
    result
}

/// Dentro do segundo processo, com o primeiro ainda vivo.
struct Inner {
    process_id: u64,
    thread_id: u64,
    seen: Option<Seen>,
    own: (u64, u64, String),
    record: SyscallRecord,
    ids: bool,
    extra: bool,
    lookups: bool,
    refused: bool,
}

pub fn run(assert: Assert) {
    let system = process::get_system_process();
    assert(cid::lookup(process::SYSTEM_PROCESS_ID) == Some(Entry { kind: Kind::Process, object: system }) && !cid::valid(0) && !cid::valid(0x400) && !cid::valid(6) && cid::valid(8), "identidade: System com o PID 4 na tabela de ids e regras dos ids do NT");
    assert(consistent(&live_ids()), "identidade: PIDs e TIDs vivos distintos e publicados na tabela");

    let record = SyscallRecord::raw(0x7E_A000);
    let outer = with_test_process("identidade-a.exe", None, |first| {
        if let Some(identity) = process_state::get(first.process) {
            identity.set_image_path("C:\\identidade-a.exe");
        }
        let before = seen();
        let own = (state::current_process_id(), state::current_peb(), process_state::current().map(|identity| identity.image_path()).unwrap_or_default());
        // O registro do serviço gravado nesta thread não aparece na thread do
        // outro processo e continua aqui quando ela volta.
        let (inner, kept) = state::with_syscall_record(record, || {
            let inner = with_test_process("identidade-b.exe", None, |second| {
                if let Some(identity) = process_state::get(second.process) {
                    identity.set_image_path("C:\\identidade-b.exe");
                }
                let seen = seen();
                let own = (state::current_process_id(), state::current_peb(), process_state::current().map(|identity| identity.image_path()).unwrap_or_default());
                let mut ids = alloc::vec![first.process_id, first.thread_id, second.process_id, second.thread_id];
                ids.sort_unstable();
                ids.dedup();
                // Mais threads no segundo processo: TIDs novos, nunca um PID.
                let threads: Vec<u64> = (0..3).filter_map(|_| process::create_kernel_thread(second.process, cid::ALLOCATE, true, 1, None).ok()).collect();
                let extra = threads.len() == 3 && consistent(&live_ids()) && threads.iter().all(|&thread| {
                    // SAFETY: ETHREAD recém-criado acima.
                    let id = unsafe { Ethread::at(thread) }.cid.unique_thread.get();
                    !ids.contains(&id) && cid::lookup(id) == Some(Entry { kind: Kind::Thread, object: thread })
                });
                for thread in threads {
                    let _ = process::release_thread(thread);
                }
                // Busca por id: o PID do primeiro dá o EPROCESS dele e o TID do
                // segundo dá a thread dele.
                let output = guest::alloc_bytes(8);
                let found_process = process::lookup_process_by_id(first.process_id, output) == 0 && guest::read64(output) == first.process;
                if found_process {
                    let _ = process::dereference(first.process);
                }
                guest::free_bytes(output);
                let found_thread = process::reference_thread_by_id(second.thread_id);
                if found_thread != 0 {
                    let _ = process::dereference_thread(found_thread);
                }
                let lookups = found_process && found_thread == second.thread && process::reference_thread_by_id(first.process_id) == 0;
                // Um id em uso não serve a outro objeto, nem de outro tipo.
                let reused_thread = process::create_kernel_thread(second.process, first.process_id, true, 1, None);
                let reused_process = process::create_process(second.thread_id, "identidade-c.exe", 0, None);
                let refused = reused_thread.is_err() && reused_process.is_err();
                if let Ok(thread) = reused_thread {
                    let _ = process::release_thread(thread);
                }
                if let Ok(process) = reused_process {
                    let _ = process::terminate_process(process, 0);
                }
                Inner { process_id: second.process_id, thread_id: second.thread_id, seen, own, record: state::syscall_record(), ids: ids.len() == 4 && consistent(&live_ids()), extra, lookups, refused }
            });
            (inner, state::syscall_record())
        });
        // Fora do serviço, a thread volta ao registro vazio.
        let restored = (kept, state::syscall_record());
        let after = seen();
        (first.process_id, first.thread_id, first.peb, before, own, inner, restored, after)
    });
    let Some((first_id, first_thread_id, first_peb, before, own, inner, restored, after)) = outer else {
        assert(false, "identidade: primeiro processo de usuario");
        return;
    };
    let Some(inner) = inner else {
        assert(false, "identidade: segundo processo de usuario");
        return;
    };
    let (second_id, second_thread_id) = (inner.process_id, inner.thread_id);
    let first_seen = before.clone().unwrap_or(Seen { process_id: 0, peb: 0, cookie: 0, image: String::new() });
    assert(before.as_ref().is_some_and(|seen| seen.process_id == first_id && seen.peb == first_peb && seen.cookie != 0 && seen.image == "C:\\identidade-a.exe") && own == (first_id, first_peb, String::from("C:\\identidade-a.exe")), "identidade: o primeiro processo ve o proprio PID, PEB, cookie e imagem");
    assert(inner.seen.as_ref().is_some_and(|seen| seen.process_id == second_id && seen.peb != first_peb && seen.peb != 0 && seen.cookie != 0 && seen.cookie != first_seen.cookie && seen.image == "C:\\identidade-b.exe") && inner.own.0 == second_id && inner.own.1 != first_peb && inner.own.2 == "C:\\identidade-b.exe", "identidade: o segundo processo ve a propria identidade, nao a do primeiro");
    assert(inner.ids && first_id != second_id && first_thread_id != second_thread_id, "identidade: PIDs e TIDs dos dois processos sem colisao");
    assert(inner.extra, "identidade: threads novas recebem TIDs que nao colidem com nenhum PID ou TID");
    assert(inner.lookups, "identidade: busca por PID e por TID acha o objeto certo e um PID nao e TID");
    assert(inner.refused, "identidade: id em uso recusado para outro objeto");
    assert(inner.record == SyscallRecord::default() && restored == (record, SyscallRecord::default()), "identidade: registro do servico em curso e por thread");
    assert(after == before, "identidade: o primeiro processo mantem a identidade depois do segundo");
    assert([first_id, first_thread_id, second_id, second_thread_id].iter().all(|&id| cid::lookup(id).is_none()), "identidade: ids devolvidos a tabela quando os objetos sao recolhidos");
    assert(consistent(&live_ids()), "identidade: tabela consistente depois dos dois processos");
}
