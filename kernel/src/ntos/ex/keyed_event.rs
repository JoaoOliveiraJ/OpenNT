//! Keyed events: o tipo KeyedEvent, o objeto permanente
//! `\KernelObjects\CritSecOutOfMemoryEvent` e os serviços
//! NtCreateKeyedEvent, NtOpenKeyedEvent, NtWaitForKeyedEvent e
//! NtReleaseKeyedEvent.
//!
//! ExpKeyedEventInitialization (ntoskrnl 19041 rva 0xa6f2ec, do
//! ExpInitSystemPhase1):
//!
//! - ObCreateObjectType("KeyedEvent") com UseDefaultObject, PagedPool,
//!   GenericMapping {0x20001, 0x20002, 0x20000, 0xF0003} e ValidAccessMask
//!   KEYEDEVENT_ALL_ACCESS (0xF0003); o ObCreateObjectTypeEx soma o
//!   SYNCHRONIZE e aponta o DefaultObject para o ObpDefaultObject;
//! - o descritor: DACL com World 0x20003 e Administrators e SYSTEM 0xF0003;
//!   SACL com o rótulo Low (SYSTEM_MANDATORY_LABEL_NO_WRITE_UP);
//! - ZwCreateKeyedEvent(KEYEDEVENT_ALL_ACCESS, {nome, OBJ_PERMANENT}, 0);
//! - o kernel guarda o objeto em ExpCritSecOutOfMemoryEvent
//!   (ObReferenceObjectByHandle) e fecha o handle. É o keyed event que o
//!   NtWaitForKeyedEvent/NtReleaseKeyedEvent usam quando a ntdll passa o
//!   handle NULL.
//!
//! Serviços:
//!
//! - NtCreateKeyedEvent(Handle*, DesiredAccess, ObjectAttributes, Flags)
//!   (rva 0x7c58f0): em UserMode o Handle precisa de alinhamento 8 (senão
//!   STATUS_DATATYPE_MISALIGNMENT) e é sondado; a saída é zerada; Flags
//!   diferente de zero é STATUS_INVALID_PARAMETER_4;
//!   ObCreateObjectEx(PreviousMode, tipo, OA, PreviousMode, 0x600), os 64
//!   baldes {push lock livre, lista vazia} e ObInsertObjectEx com o acesso
//!   pedido; o handle volta pela saída.
//! - NtOpenKeyedEvent(Handle*, DesiredAccess, ObjectAttributes) (rva
//!   0x95b0b0): a mesma sonda da saída e o ObOpenObjectByName com o tipo.
//! - NtWaitForKeyedEvent / NtReleaseKeyedEvent(Handle, Key, Alertable,
//!   Timeout*) (rva 0x95b570 / 0x95b1b0): Key com o bit 0 é
//!   STATUS_INVALID_PARAMETER_1; o Timeout é capturado (sonda de 8 bytes em
//!   UserMode); Handle NULL é o ExpCritSecOutOfMemoryEvent, senão o
//!   ObReferenceObjectByHandle com KEYEDEVENT_WAIT (1) ou KEYEDEVENT_WAKE
//!   (2). O balde é o (Key >> 5) & 63. Sob o push lock dele, numa região
//!   crítica, a thread procura a parceira do mesmo processo (o
//!   KTHREAD.Process dela igual ao ApcState.Process de quem chama): quem
//!   libera procura em toda a lista uma ETHREAD com KeyedWaitValue == Key;
//!   quem espera procura KeyedWaitValue == Key | 1 a partir da cabeça e
//!   para na primeira entrada sem o bit 0 (as que liberam entram na cabeça,
//!   as que esperam no fim). Achada, a parceira sai da lista (a
//!   KeyedWaitChain volta a apontar para si), o KeyedWaitSemaphore dela é
//!   liberado e o serviço devolve sucesso. Senão a thread guarda o
//!   KeyedWaitValue (união com o TerminationPort), grava Key (ou Key | 1),
//!   entra na lista e espera o próprio KeyedWaitSemaphore (PreviousMode,
//!   Alertable, Timeout). Uma espera interrompida (prazo, alerta, APC de
//!   usuário) tira a thread da lista; se a parceira já a tirou, a liberação
//!   veio ou está vindo, e a thread espera o semáforo de novo, sem prazo e em
//!   KernelMode, e devolve sucesso. O KeyedEventInUse
//!   (SameThreadPassiveFlags) marca a thread durante o serviço.
//!
//! A parceira libera o semáforo antes de soltar o push lock do balde (no NT
//! logo depois): quem acha a própria cadeia fora da lista sob o push lock já
//! tem o semáforo sinalizado, e uma thread terminada nunca é liberada depois
//! de sair do serviço. O PspAllocateThread inicializa o KeyedWaitSemaphore
//! (contagem 0, limite 1) e a KeyedWaitChain vazia (`ps/process.rs`).

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::{list_entry, push_lock};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Ethread, EthreadView1, LargeInteger, ListEntry, ObjectAttributes, ObjectTypeInitializer, PoolType, UnicodeString};
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
use crate::ntos::ob::{object_create, object_header, object_open, object_reference, object_types, reference_trace};
use crate::ntos::ps::{process, user_probe};
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

/// KEYEDEVENT_ALL_ACCESS.
const KEYEDEVENT_ALL_ACCESS: u32 = 0xF_0003;
/// KEYEDEVENT_WAIT e KEYEDEVENT_WAKE.
const KEYEDEVENT_WAIT: u32 = 1;
const KEYEDEVENT_WAKE: u32 = 2;
/// KEYEDEVENT_WAIT | KEYEDEVENT_WAKE | READ_CONTROL.
const WORLD_ACCESS: u32 = 0x2_0003;
/// OBJECT_TYPE_INITIALIZER.UseDefaultObject.
const USE_DEFAULT_OBJECT: u16 = 0x4;
const OBJ_PERMANENT: u32 = 0x10;
/// SECURITY_MANDATORY_LOW_RID.
const LOW_INTEGRITY: u32 = 0x1000;
/// DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION.
const DACL_AND_LABEL: u32 = 0x14;
const BUCKETS: usize = 64;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;

pub const CRIT_SEC_OUT_OF_MEMORY_EVENT: &str = "\\KernelObjects\\CritSecOutOfMemoryEvent";

/// Um balde do corpo do keyed event: o push lock e a lista de esperas.
#[repr(C)]
struct KeyedEventBucket {
    lock: Field<u64>,
    wait_list: ListEntry,
}

/// O corpo do objeto KeyedEvent (0x600 bytes).
#[repr(C)]
struct KeyedEventObject {
    buckets: [KeyedEventBucket; BUCKETS],
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for KeyedEventBucket {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for KeyedEventObject {}

const _: () = {
    assert!(core::mem::size_of::<KeyedEventBucket>() == 0x18);
    assert!(core::mem::size_of::<KeyedEventObject>() == 0x600);
};

/// A KeyedWaitChain na ETHREAD (as entradas da lista de um balde).
const KEYED_WAIT_CHAIN: u64 = core::mem::offset_of!(EthreadView1, keyed_wait_chain) as u64;

/// ExpKeyedEventObjectType.
static KEYED_EVENT_TYPE: AtomicU64 = AtomicU64::new(0);
/// ExpCritSecOutOfMemoryEvent: o corpo, com a referência do kernel.
static CRIT_SEC_OUT_OF_MEMORY: AtomicU64 = AtomicU64::new(0);

/// UNICODE_STRING e texto num bloco do convidado (o chamador libera os dois).
fn unicode(text: &str) -> (u64, u64) {
    let units: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let buffer = guest::alloc_bytes(units.len() as u64 + 2);
    guest::write_bytes(buffer, &units);
    let string = guest::alloc_bytes(UnicodeString::SIZE);
    // SAFETY: UNICODE_STRING recém-alocado.
    let value = unsafe { UnicodeString::at(string) };
    value.length.set(units.len() as u16);
    value.maximum_length.set(units.len() as u16 + 2);
    value.buffer.set(buffer);
    (string, buffer)
}

/// O ObCreateObjectType do tipo KeyedEvent.
fn create_type() -> Result<u64, KernelError> {
    if let Some(existing) = object_types::by_name("KeyedEvent") {
        return Ok(existing.pointer);
    }
    let init = guest::alloc_bytes(ObjectTypeInitializer::SIZE);
    // SAFETY: OBJECT_TYPE_INITIALIZER recém-alocado e zerado.
    let initializer = unsafe { ObjectTypeInitializer::at(init) };
    initializer.length.set(ObjectTypeInitializer::SIZE as u16);
    initializer.object_type_flags.set(USE_DEFAULT_OBJECT);
    let mapping = &initializer.generic_mapping;
    mapping.generic_read.set(0x2_0001);
    mapping.generic_write.set(0x2_0002);
    mapping.generic_execute.set(0x2_0000);
    mapping.generic_all.set(KEYEDEVENT_ALL_ACCESS);
    initializer.valid_access_mask.set(KEYEDEVENT_ALL_ACCESS);
    initializer.pool_type.set(PoolType::PAGED_POOL);
    let (name, buffer) = unicode("KeyedEvent");
    let output = guest::alloc_bytes(8);
    let status = object_types::create_type_ex(name, init, 0, output);
    let created = guest::read64(output);
    for block in [init, name, buffer, output] {
        guest::free_bytes(block);
    }
    if status != 0 {
        return Err(KernelError::with_status(alloc::format!("ObCreateObjectType(KeyedEvent): {status:#x}"), status));
    }
    Ok(created)
}

/// O descritor do ExpKeyedEventInitialization, self-relative no convidado.
fn descriptor() -> u64 {
    let policy = SecurityPolicy {
        dacl: Some(alloc::vec![Ace::allow(sid(1, &[0]), WORLD_ACCESS), Ace::allow(sid(5, &[32, 544]), KEYEDEVENT_ALL_ACCESS), Ace::allow(sid(5, &[18]), KEYEDEVENT_ALL_ACCESS)]),
        integrity: Some(LOW_INTEGRITY),
        ..SecurityPolicy::default()
    };
    let bytes = crate::ntos::se::object_security::encode(&policy, DACL_AND_LABEL);
    let pointer = guest::alloc_bytes(bytes.len() as u64);
    if pointer != 0 {
        guest::write_bytes(pointer, &bytes);
    }
    pointer
}

/// O corpo de um keyed event recém-criado.
fn body(object: u64) -> &'static KeyedEventObject {
    // SAFETY: corpo de 0x600 bytes de um objeto KeyedEvent vivo.
    unsafe { KeyedEventObject::at(object) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREAD viva: a corrente ou uma que está na lista de um balde
    // (só sai dela sob o push lock, antes de deixar o serviço).
    unsafe { Ethread::at(thread) }
}

/// O NtCreateKeyedEvent depois da sonda: ObCreateObjectEx(mode, tipo, OA,
/// mode, 0x600), os 64 baldes vazios e ObInsertObjectEx(access). O corpo
/// vai a `object_cell` e o handle a `handle_cell` (células do kernel).
fn create_object(object_type: u64, mode: u8, attributes: u64, access: u32, object_cell: u64, handle_cell: u64) -> Result<u32, KernelError> {
    let status = object_create::create(mode, object_type, attributes, mode, KeyedEventObject::SIZE as u32, 0, 0, object_cell);
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    let object = guest::read64(object_cell);
    for bucket in &body(object).buckets {
        bucket.lock.set(0);
        list_entry::initialize(&bucket.wait_list);
    }
    object_create::insert(object, access, 0, 0, handle_cell)
}

/// ExpKeyedEventInitialization: o tipo e o objeto permanente, uma vez.
pub fn initialize() -> Result<(), KernelError> {
    if CRIT_SEC_OUT_OF_MEMORY.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let object_type = create_type()?;
    KEYED_EVENT_TYPE.store(object_type, Ordering::Release);
    let (name, buffer) = unicode(CRIT_SEC_OUT_OF_MEMORY_EVENT);
    let security = descriptor();
    let attributes = guest::alloc_bytes(ObjectAttributes::SIZE);
    // SAFETY: OBJECT_ATTRIBUTES recém-alocado.
    let object_attributes = unsafe { ObjectAttributes::at(attributes) };
    object_attributes.length.set(ObjectAttributes::SIZE as u32);
    object_attributes.object_name.set(name);
    object_attributes.attributes.set(OBJ_PERMANENT);
    object_attributes.security_descriptor.set(security);
    let output = guest::alloc_bytes(16);
    let result = crate::ntos::ps::previous_mode::with_kernel(|| -> Result<(), KernelError> {
        let status = create_object(object_type, 0, attributes, KEYEDEVENT_ALL_ACCESS, output, output + 8)?;
        if status != 0 {
            return Err(KernelError::with_status(alloc::format!("NtCreateKeyedEvent: {status:#x}"), status));
        }
        // ObReferenceObjectByHandle e ZwClose: o kernel fica com a referência.
        let object = guest::read64(output);
        object_header::reference(object, 1);
        CRIT_SEC_OUT_OF_MEMORY.store(object, Ordering::Release);
        crate::ntos::ob::close::close(guest::read64(output + 8), Some(0))?;
        Ok(())
    })
    .and_then(|result| result);
    for block in [name, buffer, security, attributes, output] {
        if block != 0 {
            guest::free_bytes(block);
        }
    }
    result
}

/// ExpKeyedEventObjectType (o tipo nasce no ExpKeyedEventInitialization).
pub fn object_type() -> u64 {
    if KEYED_EVENT_TYPE.load(Ordering::Acquire) == 0 {
        let _ = initialize();
    }
    KEYED_EVENT_TYPE.load(Ordering::Acquire)
}

/// ExpCritSecOutOfMemoryEvent: o keyed event do handle NULL.
pub fn crit_sec_out_of_memory_event() -> u64 {
    if CRIT_SEC_OUT_OF_MEMORY.load(Ordering::Acquire) == 0 {
        let _ = initialize();
    }
    CRIT_SEC_OUT_OF_MEMORY.load(Ordering::Acquire)
}

/// A lista de esperas do balde de `key` no keyed event `object`.
pub fn wait_list(object: u64, key: u64) -> &'static ListEntry {
    &body(object).buckets[((key >> 5) & 0x3F) as usize].wait_list
}

/// Grava um HANDLE de saída (sondado em UserMode); `false` = violação.
fn write_handle(mode: u8, address: u64, handle: u64) -> bool {
    if mode != 0 {
        return guest::try_write::<u64>(address, handle).is_ok();
    }
    // SAFETY: PHANDLE de um chamador de modo kernel.
    unsafe { Field::<u64>::at(address) }.set(handle);
    true
}

/// A sonda do PHANDLE de saída (alinhamento 8 e faixa em UserMode) e o
/// zero inicial: o NTSTATUS da recusa, se houver.
fn prepare_handle(mode: u8, address: u64) -> Option<u32> {
    if mode != 0 {
        if address & 7 != 0 {
            return Some(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(address, 8) {
            return Some(STATUS_ACCESS_VIOLATION);
        }
    }
    (!write_handle(mode, address, 0)).then_some(STATUS_ACCESS_VIOLATION)
}

/// NtCreateKeyedEvent no modo `mode`. Devolve o NTSTATUS.
pub fn create(handle_out: u64, access: u32, attributes: u64, flags: u32, mode: u8) -> Result<u32, KernelError> {
    if let Some(status) = prepare_handle(mode, handle_out) {
        return Ok(status);
    }
    if flags != 0 {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    let object_type = object_type();
    let cells = guest::alloc_bytes(16);
    if cells == 0 || object_type == 0 {
        if cells != 0 {
            guest::free_bytes(cells);
        }
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cells, 0);
    guest::write64(cells + 8, 0);
    let status = create_object(object_type, mode, attributes, access, cells, cells + 8);
    let handle = guest::read64(cells + 8);
    guest::free_bytes(cells);
    let status = status?;
    // A escrita do handle é a do bloco try do serviço: falhando, o handle
    // fica aberto e o serviço devolve o código da exceção.
    if status & 0x8000_0000 == 0 && !write_handle(mode, handle_out, handle) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}

/// NtOpenKeyedEvent no modo `mode`. Devolve o NTSTATUS.
pub fn open(handle_out: u64, access: u32, attributes: u64, mode: u8) -> Result<u32, KernelError> {
    if let Some(status) = prepare_handle(mode, handle_out) {
        return Ok(status);
    }
    // ObOpenObjectByName sem OBJECT_ATTRIBUTES.
    if attributes == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let captured = if mode != 0 {
        match object_open::capture_user_attributes(attributes) {
            Ok(block) => Some(block),
            Err(status) => return Ok(status),
        }
    } else {
        None
    };
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        if let Some(block) = captured {
            guest::free_bytes(block);
        }
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, 0);
    let status = object_open::open_by_name(captured.unwrap_or(attributes), object_type(), mode, access, cell).map(|value| value as u32);
    let handle = guest::read64(cell);
    guest::free_bytes(cell);
    if let Some(block) = captured {
        guest::free_bytes(block);
    }
    let status = status?;
    if status & 0x8000_0000 == 0 && !write_handle(mode, handle_out, handle) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(status)
}

/// O *Timeout capturado numa célula do kernel (0 = sem prazo); em UserMode
/// a faixa de 8 bytes fica abaixo de MmUserProbeAddress, sem exigir
/// alinhamento.
fn capture_timeout(timeout: u64, mode: u8) -> Result<u64, u32> {
    if timeout == 0 {
        return Ok(0);
    }
    let value = if mode != 0 {
        let end = timeout.wrapping_add(8);
        if end > USER_PROBE_ADDRESS || end < timeout {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        guest::try_read::<i64>(timeout).map_err(|_| STATUS_ACCESS_VIOLATION)?
    } else {
        // SAFETY: PLARGE_INTEGER de um chamador de modo kernel.
        unsafe { LargeInteger::at(timeout) }.quad_part.get()
    };
    let cell = guest::alloc_bytes(LargeInteger::SIZE);
    if cell == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cell, value as u64);
    Ok(cell)
}

/// A parceira na lista do balde (push lock retido): quem libera procura
/// KeyedWaitValue == Key em toda a lista; quem espera, Key | 1 a partir da
/// cabeça até a primeira entrada sem o bit 0. Só threads de `process`
/// (KTHREAD.Process).
fn find_partner(list: &ListEntry, key: u64, process: u64, releasing: bool) -> Option<u64> {
    let wanted = if releasing { key } else { key | 1 };
    let mut link = list.flink.get();
    while link != list.address() {
        let thread = link - KEYED_WAIT_CHAIN;
        let candidate = ethread(thread);
        let value = candidate.keyed_wait_value.get();
        if !releasing && value & 1 == 0 {
            return None;
        }
        if value == wanted && candidate.tcb.process.get() == process {
            return Some(thread);
        }
        // SAFETY: o Flink de uma entrada viva da lista (push lock retido).
        link = unsafe { ListEntry::at(link) }.flink.get();
    }
    None
}

/// RemoveEntryList da KeyedWaitChain e a cadeia volta a apontar para si.
fn unlink(chain: &ListEntry) {
    let _ = list_entry::remove(chain);
    list_entry::initialize(chain);
}

/// O corpo comum do NtWaitForKeyedEvent (`releasing` falso) e do
/// NtReleaseKeyedEvent, com o objeto já referenciado.
fn rendezvous_on(object: u64, key: u64, alertable: bool, timeout: u64, mode: u8, releasing: bool) -> Result<u32, KernelError> {
    let thread = process::get_current_thread();
    let current = ethread(thread);
    let process = current.tcb.apc_state.process.get();
    let bucket = &body(object).buckets[((key >> 5) & 0x3F) as usize];
    let lock = bucket.lock.address();
    let list = &bucket.wait_list;
    let chain = &current.keyed_wait_chain;
    critical_region::enter_critical()?;
    push_lock::acquire_exclusive(lock, 0)?;
    if let Some(partner) = find_partner(list, key, process, releasing) {
        let partner = ethread(partner);
        unlink(&partner.keyed_wait_chain);
        // KeReleaseSemaphore(&KeyedWaitSemaphore, 1, 1, FALSE).
        let _ = dispatcher::release_semaphore(partner.keyed_wait_semaphore.address(), 1);
        push_lock::release_exclusive(lock, 0)?;
        critical_region::leave_critical()?;
        return Ok(0);
    }
    let saved = current.keyed_wait_value.get();
    current.keyed_wait_value.set(if releasing { key | 1 } else { key });
    if releasing {
        list_entry::insert_head(list, chain);
    } else {
        list_entry::insert_tail(list, chain);
    }
    push_lock::release_exclusive(lock, 0)?;
    critical_region::leave_critical()?;
    let semaphore = current.keyed_wait_semaphore.address();
    let mut status = dispatcher::wait_for_single_object(semaphore, timeout, mode, alertable);
    if status != 0 {
        critical_region::enter_critical()?;
        push_lock::acquire_exclusive(lock, 0)?;
        let linked = chain.flink.get() != chain.address();
        if linked {
            unlink(chain);
        }
        push_lock::release_exclusive(lock, 0)?;
        critical_region::leave_critical()?;
        if !linked {
            // A parceira já tirou a thread da lista e liberou o semáforo.
            status = dispatcher::wait_for_single_object(semaphore, 0, 0, false);
        }
    }
    current.keyed_wait_value.set(saved);
    Ok(status)
}

/// NtWaitForKeyedEvent (`releasing` falso) e NtReleaseKeyedEvent no modo
/// `mode`. Devolve o NTSTATUS.
fn rendezvous(handle: u64, key: u64, alertable: bool, timeout: u64, mode: u8, releasing: bool) -> Result<u32, KernelError> {
    if key & 1 != 0 {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    let timeout = match capture_timeout(timeout, mode) {
        Ok(cell) => cell,
        Err(status) => return Ok(status),
    };
    let release_timeout = || {
        if timeout != 0 {
            guest::free_bytes(timeout);
        }
    };
    let object = if handle == 0 {
        crit_sec_out_of_memory_event()
    } else {
        let slot = guest::alloc_bytes(8);
        if slot == 0 {
            release_timeout();
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        let access = if releasing { KEYEDEVENT_WAKE } else { KEYEDEVENT_WAIT };
        let status = object_reference::reference_by_handle(handle, access, object_type(), mode, slot, 0).map(|value| value as u32);
        let object = guest::read64(slot);
        guest::free_bytes(slot);
        match status {
            Ok(0) => object,
            Ok(status) => {
                release_timeout();
                return Ok(status);
            }
            Err(error) => {
                release_timeout();
                return Err(error);
            }
        }
    };
    if object == 0 {
        release_timeout();
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let thread = process::get_current_thread();
    let current = ethread(thread);
    current.same_thread_passive_flags.atomic().fetch_or(Ethread::KEYED_EVENT_IN_USE_MASK, Ordering::SeqCst);
    let result = rendezvous_on(object, key, alertable, timeout, mode, releasing);
    // A troca atômica ordena o fim do KeyedEventInUse antes da leitura do
    // Terminated (o PspExitThread pode ter adiado o ExitTime).
    current.same_thread_passive_flags.atomic().fetch_and(!Ethread::KEYED_EVENT_IN_USE_MASK, Ordering::SeqCst);
    process::record_exit_time(thread);
    if handle != 0 {
        object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false)?;
    }
    release_timeout();
    result
}

/// NtWaitForKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout).
pub fn wait(handle: u64, key: u64, alertable: bool, timeout: u64, mode: u8) -> Result<u32, KernelError> {
    rendezvous(handle, key, alertable, timeout, mode, false)
}

/// NtReleaseKeyedEvent(KeyedEventHandle, Key, Alertable, Timeout).
pub fn release(handle: u64, key: u64, alertable: bool, timeout: u64, mode: u8) -> Result<u32, KernelError> {
    rendezvous(handle, key, alertable, timeout, mode, true)
}

fn nt_create_keyed_event(handle_out: u64, access: u64, attributes: u64, flags: u64, _rsp: u64) -> Result<u32, KernelError> {
    create(handle_out, access as u32, attributes, flags as u32, 1)
}

fn nt_open_keyed_event(handle_out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    open(handle_out, access as u32, attributes, 1)
}

fn nt_wait_for_keyed_event(handle: u64, key: u64, alertable: u64, timeout: u64, _rsp: u64) -> Result<u32, KernelError> {
    wait(handle, key, crate::ntos::ps::user::state::boolean(alertable), timeout, 1)
}

fn nt_release_keyed_event(handle: u64, key: u64, alertable: u64, timeout: u64, _rsp: u64) -> Result<u32, KernelError> {
    release(handle, key, crate::ntos::ps::user::state::boolean(alertable), timeout, 1)
}

/// Os serviços de modo usuário.
pub fn register_user_services() {
    use crate::ntos::ps::user::state;
    state::register_handler("NtCreateKeyedEvent", nt_create_keyed_event);
    state::register_handler("NtOpenKeyedEvent", nt_open_keyed_event);
    state::register_handler("NtWaitForKeyedEvent", nt_wait_for_keyed_event);
    state::register_handler("NtReleaseKeyedEvent", nt_release_keyed_event);
}
