//! Tabelas de handles por processo: um handle de usuário só vale no processo
//! que o abriu (o anexado, quando há attach); o mesmo objeto aberto em dois
//! processos tem um handle e um acesso em cada tabela; fechar num processo
//! não toca no outro; o término esvazia a tabela do processo; um handle de
//! kernel mora na tabela do System e vale em qualquer processo.

use alloc::sync::Arc;
use core::any::Any;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::KapcState;
use crate::ntos::ke::process_attachment;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ob::{close, handle_table, object_reference, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::handles::{self as user_handles, UserProcess};
use crate::ntos::ps::user::state::{self, UserObject};

type Assert = fn(bool, &str);

const A_ID: u64 = 0x7EA0;
const B_ID: u64 = 0x7EB0;
const TARGET_ID: u64 = 0x7EC0;

const INVALID_HANDLE: u32 = 0xC000_0008;
const ACCESS_DENIED: u32 = 0xC000_0022;
const NOT_SUPPORTED: u32 = 0xC000_00BB;
/// PROCESS_QUERY_LIMITED_INFORMATION e PROCESS_ALL_ACCESS.
const LIMITED: u32 = 0x1000;
const ALL_ACCESS: u32 = 0x1F_FFFF;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// Objeto sem corpo nativo (nenhuma linha na HANDLE_TABLE): só a tabela de
/// usuário o conhece.
struct Plain {
    closes: AtomicU32,
    released: AtomicU32,
}

impl UserObject for Plain {
    fn kind(&self) -> &'static str {
        "event"
    }
    fn on_each_handle_close(&self) {
        self.closes.fetch_add(1, Ordering::Relaxed);
    }
    fn release(&self) {
        self.released.fetch_add(1, Ordering::Relaxed);
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// Roda `body` anexado a `process` (KeStackAttachProcess).
fn attached<T>(process: u64, body: impl FnOnce() -> T) -> Option<T> {
    let saved = guest::alloc_bytes(KapcState::SIZE);
    if saved == 0 {
        return None;
    }
    let result = match process_attachment::attach(process, saved) {
        Ok(_) => {
            let value = body();
            process_attachment::detach(saved).ok().map(|_| value)
        }
        Err(_) => None,
    };
    guest::free_bytes(saved);
    result
}

/// Abre um handle de usuário para o EPROCESS `target` no processo corrente.
fn open_process(target: u64, process_id: u64, access: u32) -> Option<u64> {
    state::alloc_user_handle(Arc::new(UserProcess { pointer: target, process_id }), access, 0).ok().map(u64::from)
}

/// ObReferenceObjectByHandle(Process) no modo dado: o status e o corpo; a
/// referência obtida é solta em seguida.
fn reference(handle: u64, access: u32, mode: u8) -> (u32, u64) {
    let output = guest::alloc_bytes(8);
    guest::write64(output, 0);
    let status = object_reference::reference_by_handle(handle, access, object_types::process_type().pointer, mode, output, 0).map_or(u32::MAX, |status| status as u32);
    let pointer = guest::read64(output);
    guest::free_bytes(output);
    if status == 0 {
        if let Some(item) = open_pointer::describe(pointer) {
            item.dereference();
        }
    }
    (status, pointer)
}

/// A linha da HANDLE_TABLE nativa (EPROCESS.ObjectTable) de `process`.
fn row(process: u64, handle: u64) -> Option<handle_table::Row> {
    process_handles::get(process).and_then(|table| handle_table::row(table, handle as u32))
}

/// As referências do EPROCESS fora as de teste.
fn references(process: u64) -> u32 {
    let count = process::reference(process).unwrap_or(0);
    let _ = process::dereference(process);
    count.saturating_sub(1)
}

pub fn run(assert: Assert) {
    if process::get_current_thread() == 0 {
        assert(false, "handles: thread corrente para o attach");
        return;
    }
    let system = process::get_system_process();
    let created = (process::create_process(A_ID, "handles-a.exe", 0, None), process::create_process(B_ID, "handles-b.exe", 0, None), process::create_process(TARGET_ID, "handles-alvo.exe", 0, None));
    let (Ok(a), Ok(b), Ok(target)) = created else {
        for process in [created.0, created.1, created.2].into_iter().flatten() {
            let _ = process::terminate_process(process, 0);
        }
        assert(false, "handles: tres processos criados");
        return;
    };
    let baseline = references(target);

    // O mesmo objeto aberto em A e em B, com acessos distintos.
    let in_a = attached(a, || open_process(target, TARGET_ID, LIMITED)).flatten().unwrap_or(0);
    let in_b = attached(b, || open_process(target, TARGET_ID, ALL_ACCESS)).flatten().unwrap_or(0);
    assert(in_a != 0 && in_b != 0 && in_a != in_b, "handles: o mesmo processo aberto em A e em B");
    let seen_by_a = attached(a, || (state::get_user_handle(in_a).map(|entry| entry.access()), state::get_user_handle(in_b).is_none()));
    let seen_by_b = attached(b, || (state::get_user_handle(in_b).map(|entry| entry.access()), state::get_user_handle(in_a).is_none()));
    assert(seen_by_a == Some((Some(LIMITED), true)) && seen_by_b == Some((Some(ALL_ACCESS), true)), "handles: cada processo ve so o seu handle, com o seu acesso");
    assert(state::get_user_handle(in_a).is_none() && state::get_user_handle(in_b).is_none(), "handles: o System nao ve os handles de A e de B");
    let rows = row(a, in_a).is_some_and(|row| row.pointer == target && row.access == LIMITED) && row(b, in_b).is_some_and(|row| row.pointer == target && row.access == ALL_ACCESS);
    assert(rows && row(a, in_b).is_none() && row(b, in_a).is_none() && row(system, in_a).is_none(), "handles: cada linha na ObjectTable do seu processo");
    assert(references(target) == baseline + 2, "handles: cada handle retem o corpo");

    // O handle de A é inválido em B, pelo NtClose, pelos atributos e pelo
    // ObReferenceObjectByHandle.
    let from_b = attached(b, || (close::handle_attributes(in_a, true), reference(in_a, LIMITED, 1).0, close::close(in_a, Some(1)).ok()));
    assert(from_b == Some((None, INVALID_HANDLE, Some(INVALID_HANDLE))), "handles: handle de A invalido em B");
    let from_a = attached(a, || (close::handle_attributes(in_a, true), reference(in_a, LIMITED, 1), reference(in_a, ALL_ACCESS, 1).0));
    assert(from_a == Some((Some(0), (0, target), ACCESS_DENIED)), "handles: em A o handle resolve com o acesso de A");
    assert(attached(b, || reference(in_b, ALL_ACCESS, 1)) == Some((0, target)), "handles: em B o mesmo objeto resolve com o acesso de B");

    // O processo de um handle é comparado com o processo corrente (o
    // anexado), e o handle é procurado na tabela dele.
    let duplicate_checks = attached(a, || {
        let own = open_process(a, A_ID, ALL_ACCESS).unwrap_or(0);
        let checks = (user_handles::current_process(own, 0x40), user_handles::current_process(in_a, 0));
        let _ = close::close(own, Some(1));
        checks
    });
    assert(duplicate_checks == Some((0, NOT_SUPPORTED)) && attached(b, || user_handles::current_process(in_a, 0)) == Some(INVALID_HANDLE), "handles: o processo do handle confere com o processo anexado");

    // Fechar em A não afeta B.
    let closed = attached(a, || (close::close(in_a, Some(1)).ok(), state::get_user_handle(in_a).is_none(), close::close(in_a, Some(1)).ok()));
    assert(closed == Some((Some(0), true, Some(INVALID_HANDLE))) && row(a, in_a).is_none(), "handles: fechado em A");
    let survives = attached(b, || (state::get_user_handle(in_b).map(|entry| entry.access()), reference(in_b, ALL_ACCESS, 1).0));
    assert(survives == Some((Some(ALL_ACCESS), 0)) && row(b, in_b).is_some_and(|row| row.access == ALL_ACCESS) && references(target) == baseline + 1, "handles: o handle de B sobrevive ao fechamento em A");

    // Um handle de kernel mora na tabela do System e vale em qualquer
    // processo, só em KernelMode.
    let output = guest::alloc_bytes(8);
    let opened = open_pointer::open(target, OBJ_KERNEL_HANDLE, 0, LIMITED, object_types::process_type().pointer, 0, output).ok();
    let kernel = guest::read64(output);
    guest::free_bytes(output);
    assert(opened == Some(0) && kernel & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000, "handles: handle de kernel aberto");
    let identifier = kernel & 0x7FFF_FFFF;
    assert(row(system, identifier).is_some_and(|row| row.pointer == target) && row(a, identifier).is_none() && row(b, identifier).is_none(), "handles: o handle de kernel fica na tabela do System");
    let kernel_in_a = attached(a, || (close::handle_attributes(kernel, false).is_some(), reference(kernel, LIMITED, 0), reference(kernel, LIMITED, 1).0, close::handle_attributes(kernel, true)));
    assert(kernel_in_a == Some((true, (0, target), INVALID_HANDLE, None)), "handles: handle de kernel vale em A, so em KernelMode");
    let kernel_in_b = attached(b, || (reference(kernel, LIMITED, 0), close::close(kernel, Some(0)).ok()));
    assert(kernel_in_b == Some(((0, target), Some(0))) && close::handle_attributes(kernel, false).is_none() && row(system, identifier).is_none(), "handles: handle de kernel resolvido e fechado em B");

    // O término de B esvazia a tabela dele, com e sem linha nativa, sem
    // tocar na de A.
    let plain = Arc::new(Plain { closes: AtomicU32::new(0), released: AtomicU32::new(0) });
    let plain_object: Arc<dyn UserObject> = plain.clone();
    let plain_handle = attached(b, || state::alloc_user_handle(plain_object, ALL_ACCESS, 0).ok()).flatten().map_or(0, u64::from);
    let kept = attached(a, || open_process(target, TARGET_ID, LIMITED)).flatten().unwrap_or(0);
    assert(plain_handle != 0 && kept != 0 && row(b, plain_handle).is_none(), "handles: handle sem linha nativa em B e outro em A");
    assert(process::terminate_process(b, 0).is_ok() && references(target) == baseline + 1, "handles: o termino de B fecha o handle com linha nativa");
    assert(plain.closes.load(Ordering::Relaxed) == 1 && plain.released.load(Ordering::Relaxed) == 1, "handles: o termino de B fecha o handle sem linha nativa");
    let kept_in_a = attached(a, || state::get_user_handle(kept).map(|entry| entry.access()));
    assert(kept_in_a == Some(Some(LIMITED)) && row(a, kept).is_some(), "handles: o termino de B nao toca na tabela de A");

    let _ = process::terminate_process(a, 0);
    assert(references(target) == baseline, "handles: o termino de A solta o corpo");
    let _ = process::terminate_process(target, 0);
}
