//! Autotestes dos keyed events (`ex/keyed_event.rs`) num processo de
//! teste, pelos serviços de modo usuário, contra o NtCreateKeyedEvent, o
//! NtOpenKeyedEvent, o NtWaitForKeyedEvent e o NtReleaseKeyedEvent do
//! ntoskrnl 19041:
//!
//! - criação: saída desalinhada dá STATUS_DATATYPE_MISALIGNMENT; Flags
//!   diferente de zero dá STATUS_INVALID_PARAMETER_4 com a saída zerada; o
//!   objeto é do tipo KeyedEvent, com os 64 baldes vazios, e o handle tem o
//!   acesso pedido;
//! - nome: o keyed event criado com nome abre pelo NtOpenKeyedEvent (o mesmo
//!   objeto, com o acesso pedido), o `\KernelObjects\CritSecOutOfMemoryEvent`
//!   abre com KEYEDEVENT_WAIT e um nome inexistente dá
//!   STATUS_OBJECT_NAME_NOT_FOUND;
//! - Key com o bit 0 dá STATUS_INVALID_PARAMETER_1; o NtReleaseKeyedEvent
//!   num handle só com KEYEDEVENT_WAIT dá STATUS_ACCESS_DENIED;
//! - prazo zero sem parceira (inclusive no handle NULL, o
//!   CritSecOutOfMemoryEvent): a espera vence com STATUS_TIMEOUT, a thread sai
//!   da lista do balde, o KeyedWaitValue volta ao valor anterior e o
//!   KeyedEventInUse é limpo;
//! - encontro: uma segunda thread do processo parada no NtWaitForKeyedEvent
//!   (KeyedWaitValue = Key e a KeyedWaitChain no fim do balde, o estado que
//!   o serviço deixa) é achada pelo NtReleaseKeyedEvent, sai da lista e
//!   recebe o KeyedWaitSemaphore, sem a thread que libera esperar; a espera
//!   de uma thread de outro processo com a mesma chave não é achada; do lado
//!   oposto, a thread parada no NtReleaseKeyedEvent (Key | 1, na cabeça) é
//!   achada pelo NtWaitForKeyedEvent.
//!
//! Sem os serviços, nenhum dos quatro tem handler (STATUS_NOT_IMPLEMENTED).

use crate::ntos::ex::{keyed_event, list_entry};
use crate::ntos::inc::types::{Ethread, ListEntry, NtStruct, ObjectAttributes};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_header, object_manager, open_pointer};
use crate::ntos::ps::user::{memory, state};
use crate::ntos::ps::{cid, process};
use crate::ntos::test::multiprocess::identity::with_test_process;

type Assert = fn(bool, &str);

const KEYEDEVENT_ALL_ACCESS: u64 = 0xF_0003;
const KEYEDEVENT_WAIT: u64 = 1;
const STATUS_TIMEOUT: u32 = 0x102;
const KEY: u64 = 0x0000_7FF0_1234_5620;
const NAME: &str = "\\OpenNtKeyedEventTeste";

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREADs vivas criadas pelo teste.
    unsafe { Ethread::at(thread) }
}

/// A KeyedWaitChain de `thread` está fora de qualquer lista.
fn unlinked(thread: u64) -> bool {
    let chain = &ethread(thread).keyed_wait_chain;
    chain.flink.get() == chain.address() && chain.blink.get() == chain.address()
}

fn empty(list: &ListEntry) -> bool {
    list.flink.get() == list.address()
}

/// O objeto e o acesso concedido de um handle do processo corrente.
fn resolved(handle: u64) -> Option<(u64, u32)> {
    open_pointer::resolve(handle, true).and_then(|resolved| resolved.ok()).map(|resolved| (resolved.item.pointer, resolved.access))
}

/// O estado que o serviço deixa numa thread parada: KeyedWaitValue e a
/// KeyedWaitChain na lista (no fim para quem espera, na cabeça para quem
/// libera).
fn park(thread: u64, object: u64, releasing: bool) {
    let list = keyed_event::wait_list(object, KEY);
    let target = ethread(thread);
    target.keyed_wait_value.set(if releasing { KEY | 1 } else { KEY });
    if releasing {
        list_entry::insert_head(list, &target.keyed_wait_chain);
    } else {
        list_entry::insert_tail(list, &target.keyed_wait_chain);
    }
}

/// Consome a liberação do KeyedWaitSemaphore de `thread`.
fn released(thread: u64) -> bool {
    let semaphore = ethread(thread).keyed_wait_semaphore.address();
    dispatcher::read_state(semaphore) == 1 && dispatcher::acquire_status(semaphore, true) == Some(0) && dispatcher::read_state(semaphore) == 0
}

pub fn run(assert: Assert) {
    if keyed_event::initialize().is_err() {
        assert(false, "keyed: tipo KeyedEvent e CritSecOutOfMemoryEvent");
        return;
    }
    let outcome = with_test_process("keyed-event.exe", None, |test| {
        let user = memory::map_user_region(0x1000).ok()?;
        let (out, timeout, attributes, rsp) = (user, user + 0x10, user + 0x100, user + 0x800);
        let call = |name: &str, a1: u64, a2: u64, a3: u64, a4: u64| state::handler(name).map(|handler| handler(a1, a2, a3, a4, rsp).unwrap_or(1)).unwrap_or(0xC000_0002);
        let named = |name: &str| {
            let (string, text) = (attributes + 0x40, attributes + 0x60);
            state::write_user_wide(text, name);
            state::write_unicode_string(string, text, name);
            // SAFETY: OBJECT_ATTRIBUTES na região de usuário do teste.
            let object = unsafe { ObjectAttributes::at(attributes) };
            object.length.set(ObjectAttributes::SIZE as u32);
            object.root_directory.set(0);
            object.object_name.set(string);
            object.attributes.set(0x40);
            object.security_descriptor.set(0);
            object.security_quality_of_service.set(0);
            attributes
        };
        guest::write64(timeout, 0);
        let mut checks = [false; 7];
        // Criação.
        let misaligned = call("NtCreateKeyedEvent", out + 4, KEYEDEVENT_ALL_ACCESS, 0, 0) == 0x8000_0002;
        guest::write64(out, 0xDEAD);
        let flags = call("NtCreateKeyedEvent", out, KEYEDEVENT_ALL_ACCESS, 0, 1) == 0xC000_00F2 && guest::read64(out) == 0;
        let created = call("NtCreateKeyedEvent", out, KEYEDEVENT_ALL_ACCESS, 0, 0) == 0;
        let handle = guest::read64(out);
        let Some((object, access)) = resolved(handle).filter(|_| created) else { return Some(checks) };
        let buckets = (0..64u64).all(|index| empty(keyed_event::wait_list(object, index << 5)));
        checks[0] = misaligned && flags && access == KEYEDEVENT_ALL_ACCESS as u32 && object_header::object_type(object) == Some(keyed_event::object_type()) && buckets;
        // Nome.
        let named_created = call("NtCreateKeyedEvent", out, KEYEDEVENT_ALL_ACCESS, named(NAME), 0) == 0;
        let named_handle = guest::read64(out);
        let opened = call("NtOpenKeyedEvent", out, KEYEDEVENT_WAIT, named(NAME), 0) == 0;
        let wait_only = guest::read64(out);
        let same = named_created && opened && resolved(named_handle).map(|(pointer, _)| pointer) == resolved(wait_only).map(|(pointer, _)| pointer) && resolved(wait_only).is_some_and(|(_, access)| access == KEYEDEVENT_WAIT as u32);
        let global = call("NtOpenKeyedEvent", out, KEYEDEVENT_WAIT, named(keyed_event::CRIT_SEC_OUT_OF_MEMORY_EVENT), 0) == 0;
        let global_handle = guest::read64(out);
        let global_same = global && resolved(global_handle).is_some_and(|(pointer, _)| pointer == keyed_event::crit_sec_out_of_memory_event());
        let missing = call("NtOpenKeyedEvent", out, KEYEDEVENT_WAIT, named("\\OpenNtKeyedEventInexistente"), 0) == 0xC000_0034;
        checks[1] = same && global_same && missing;
        // Parâmetros e acesso.
        let odd = call("NtWaitForKeyedEvent", handle, KEY | 1, 0, timeout) == 0xC000_00EF && call("NtReleaseKeyedEvent", handle, 1, 0, 0) == 0xC000_00EF;
        let denied = call("NtReleaseKeyedEvent", wait_only, KEY, 0, timeout) == 0xC000_0022;
        checks[2] = odd && denied;
        // Prazo zero sem parceira: a thread entra e sai da lista.
        let current = ethread(test.thread);
        current.keyed_wait_value.set(0x5A5A_0000);
        let list = keyed_event::wait_list(object, KEY);
        let timed_out = call("NtWaitForKeyedEvent", handle, KEY, 0, timeout) == STATUS_TIMEOUT && call("NtReleaseKeyedEvent", handle, KEY, 0, timeout) == STATUS_TIMEOUT && call("NtWaitForKeyedEvent", wait_only, KEY, 0, timeout) == STATUS_TIMEOUT;
        let global_timeout = call("NtReleaseKeyedEvent", 0, KEY, 0, timeout) == STATUS_TIMEOUT && empty(keyed_event::wait_list(keyed_event::crit_sec_out_of_memory_event(), KEY));
        checks[3] = timed_out && global_timeout && empty(list) && unlinked(test.thread) && current.keyed_wait_value.get() == 0x5A5A_0000 && current.keyed_event_in_use() == 0;
        // Encontro com uma thread de outro processo (não achada) e com a
        // segunda thread do processo.
        let other = process::create_process(cid::ALLOCATE, "keyed-outro.exe", 0, None).ok()?;
        let foreign = process::create_kernel_thread(other, cid::ALLOCATE, true, 1, None).ok();
        let partner = process::create_kernel_thread(test.process, cid::ALLOCATE, true, 1, None).ok();
        if let (Some(foreign), Some(partner)) = (foreign, partner) {
            park(foreign, object, false);
            let skipped = call("NtReleaseKeyedEvent", handle, KEY, 0, timeout) == STATUS_TIMEOUT && !unlinked(foreign) && dispatcher::read_state(ethread(foreign).keyed_wait_semaphore.address()) == 0;
            park(partner, object, false);
            // O prazo zero só valeria se a parceira não fosse achada.
            let found = call("NtReleaseKeyedEvent", handle, KEY, 0, timeout) == 0 && unlinked(partner) && released(partner) && list.flink.get() == ethread(foreign).keyed_wait_chain.address() && list.blink.get() == list.flink.get();
            checks[4] = skipped && found;
            park(partner, object, true);
            let found_releaser = call("NtWaitForKeyedEvent", handle, KEY, 0, timeout) == 0 && unlinked(partner) && released(partner);
            checks[5] = found_releaser && unlinked(test.thread) && current.keyed_wait_value.get() == 0x5A5A_0000;
            let _ = list_entry::remove(&ethread(foreign).keyed_wait_chain);
            list_entry::initialize(&ethread(foreign).keyed_wait_chain);
        }
        for thread in [foreign, partner].into_iter().flatten() {
            let _ = process::release_thread(thread);
        }
        let _ = process::terminate_process(other, 0);
        // Fechados os handles, o objeto nomeado sai do namespace.
        let closed = [handle, named_handle, wait_only, global_handle].iter().all(|&handle| call("NtClose", handle, 0, 0, 0) == 0);
        checks[6] = closed && object_manager::lookup(NAME).is_none() && !object_header::is_object(object);
        if let Some(region) = memory::find_region(user) {
            memory::release_private_region(&region);
        }
        Some(checks)
    })
    .flatten();
    let Some(checks) = outcome else {
        assert(false, "keyed: processo de teste");
        return;
    };
    assert(checks[0], "keyed: NtCreateKeyedEvent confere o alinhamento da saida e as Flags e cria o KeyedEvent com 64 baldes vazios e o acesso pedido");
    assert(checks[1], "keyed: NtOpenKeyedEvent abre pelo nome (o mesmo objeto) e o \\KernelObjects\\CritSecOutOfMemoryEvent; nome inexistente recusado");
    assert(checks[2], "keyed: chave impar e STATUS_INVALID_PARAMETER_1 e o NtReleaseKeyedEvent exige KEYEDEVENT_WAKE");
    assert(checks[3], "keyed: prazo zero sem parceira vence com STATUS_TIMEOUT, tira a thread da lista e restaura o KeyedWaitValue");
    assert(checks[4], "keyed: NtReleaseKeyedEvent acha a thread do mesmo processo parada na chave, a tira da lista e libera o KeyedWaitSemaphore dela; a de outro processo fica");
    assert(checks[5], "keyed: NtWaitForKeyedEvent acha a thread parada no NtReleaseKeyedEvent (Key | 1 na cabeca do balde)");
    assert(checks[6], "keyed: fechados os handles, o keyed event e o nome saem");
}
