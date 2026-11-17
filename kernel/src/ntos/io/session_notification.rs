//! As mudanças de estado de sessão do I/O Manager, como no ntoskrnl 19041.
//!
//! O Local Session Manager (lsm.dll) abre o objeto Session de cada sessão
//! (NtOpenSession, `mm/session_object.rs`) e avisa cada mudança pelo
//! NtNotifyChangeSession(SessionHandle, ChangeSequenceNumber,
//! ChangeTimeStamp, Event, NewState, PreviousState, Payload, PayloadSize)
//! (rva 0x6791d0):
//!
//! - PayloadSize acima de 0x100 dá STATUS_INVALID_PARAMETER_6; o handle é
//!   referenciado com SESSION_MODIFY_ACCESS e o MmSessionObjectType;
//! - o evento de sincronização do MM_SESSION_SPACE (IoNotificationEvent) é
//!   esperado em KernelMode e serializa os avisos. Com o número de
//!   sequência igual ao IoStateSequence, a sequência avança. Um número à
//!   frente dela espera a vez: solta o evento, dorme 100 ms e espera de
//!   novo, até 11 vezes; depois a sequência vira o número + 1. Um número
//!   atrás dela não mexe na sequência (até 3 à frente depois da volta do
//!   contador ainda conta como à frente);
//! - Event 0 (IoSessionEventIgnore) só conta a sequência. Os outros gravam
//!   NewState no IoState; o PreviousState não é usado. O Payload de
//!   UserMode é sondado e copiado no pool paginado (tag 'IoSn'); sem pool,
//!   numa cópia local e o aviso é síncrono. Em KernelMode os eventos
//!   Created (1) e Terminated (2) usam o buffer do chamador;
//! - o aviso (o bloco de 0x40 bytes: WORK_QUEUE_ITEM, Event em +0x20,
//!   NewState em +0x24, PayloadSize em +0x28, Payload em +0x30 e o objeto
//!   Session em +0x38) vai ao IopSessionCallbackObject: síncrono para
//!   Created e Terminated, e pelo IopSessionChangeWorker (rva 0x3a6120)
//!   numa fila de trabalho para os outros eventos. O worker notifica, libera
//!   o evento de sincronização (MmSetSessionObjectIoEvent), solta o objeto e
//!   libera o payload e o bloco.
//!
//! O IopSessionCallbackObject é o objeto de callback sem nome do
//! IopInitializeSessionNotifications, que o IoRegisterContainerNotification
//! (IoSessionStateNotification) assina. O OpenNT ainda não exporta o
//! IoRegisterContainerNotification: o objeto existe sem registros.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::{callbacks, pool_allocation};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{IoSessionState, MmSessionSpace};
use crate::ntos::io::work_items;
use crate::ntos::ke::{dispatcher, timer};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::session_object;
use crate::ntos::ob::{object_reference, reference_trace};
use crate::ntos::ps::user_probe;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER_6: u32 = 0xC000_00F4;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SESSION_MODIFY_ACCESS.
const SESSION_MODIFY_ACCESS: u32 = 2;
/// O maior payload aceito.
const MAXIMUM_PAYLOAD: u32 = 0x100;
/// IoSessionEventCreated e IoSessionEventTerminated: avisos síncronos.
const EVENT_CREATED: u32 = 1;
const EVENT_TERMINATED: u32 = 2;
/// NonPagedPoolNx e PagedPool.
const NON_PAGED_POOL_NX: u32 = 0x200;
const PAGED_POOL: u32 = 1;
/// 'IoSn'.
const TAG: u32 = u32::from_le_bytes(*b"IoSn");
/// As esperas da sequência adiantada: 100 ms cada, até 11.
const RETRY_INTERVAL: i64 = -1_000_000;
const MAXIMUM_RETRIES: u16 = 10;

/// O bloco do aviso: o WORK_QUEUE_ITEM do IopSessionChangeWorker e os dados
/// que os callbacks recebem.
#[repr(C)]
struct SessionChange {
    work_item: Reserved<0x20>,
    event: Field<u32>,
    new_state: Field<u32>,
    payload_size: Field<u32>,
    _pad_2c: Reserved<4>,
    payload: Field<u64>,
    session_object: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SessionChange {}

const _: () = {
    assert!(core::mem::size_of::<SessionChange>() == 0x40);
    assert!(core::mem::offset_of!(SessionChange, event) == 0x20);
    assert!(core::mem::offset_of!(SessionChange, payload) == 0x30);
    assert!(core::mem::offset_of!(SessionChange, session_object) == 0x38);
};

/// O IopSessionCallbackObject, criado no primeiro aviso.
static CALLBACK_OBJECT: AtomicU64 = AtomicU64::new(0);

fn callback_object() -> Result<u64, KernelError> {
    let current = CALLBACK_OBJECT.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let created = callbacks::create_internal(true)?;
    match CALLBACK_OBJECT.compare_exchange(0, created, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(created),
        Err(existing) => Ok(existing),
    }
}

/// O MM_SESSION_SPACE do objeto Session (o ponteiro em +0x18 do corpo).
fn session_space(object: u64) -> &'static MmSessionSpace {
    // SAFETY: corpo do objeto Session referenciado; a sessão vive enquanto o
    // objeto guarda a ProcessReferenceToSession.
    unsafe { MmSessionSpace::at(guest::read64(object + 0x18)) }
}

fn wait_turn(space: &MmSessionSpace) {
    dispatcher::wait_for_single_object(space.io_notification_event.address(), 0, 0, false);
}

/// MmSetSessionObjectIoEvent.
fn release_turn(object: u64) {
    dispatcher::set_event(session_space(object).io_notification_event.address());
}

fn dereference(object: u64) -> Result<(), KernelError> {
    object_reference::dereference_with_tag(object, reference_trace::DEFAULT_TAG, false).map(|_| ())
}

/// ObReferenceObjectByHandle(SESSION_MODIFY_ACCESS, MmSessionObjectType).
fn reference_session(handle: u64, mode: u8) -> Result<Result<u64, u32>, KernelError> {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write64(cell, 0);
    let status = object_reference::reference_by_handle(handle, SESSION_MODIFY_ACCESS, session_object::session_type(), mode, cell, 0);
    let object = guest::read64(cell);
    guest::free_bytes(cell);
    match status {
        Ok(0) => Ok(Ok(object)),
        Ok(status) => Ok(Err(status as u32)),
        Err(error) if error.status != 0 => Ok(Err(error.status)),
        Err(error) => Err(error),
    }
}

/// A sequência sob o evento: avança, espera a vez de um número adiantado ou
/// deixa como está num número atrasado.
fn advance_sequence(space: &MmSessionSpace, sequence: u32) -> Result<(), KernelError> {
    let current = space.io_state_sequence.get();
    if current == sequence {
        space.io_state_sequence.set(current.wrapping_add(1));
        return Ok(());
    }
    if current > sequence && current - sequence < 0xFFFF_FFFD {
        return Ok(());
    }
    let interval = guest::alloc_bytes(8);
    guest::write::<i64>(interval, RETRY_INTERVAL);
    let mut retries: u16 = 0;
    loop {
        dispatcher::set_event(space.io_notification_event.address());
        let delayed = timer::delay_execution_thread(interval, 0, false);
        wait_turn(space);
        if let Err(error) = delayed {
            guest::free_bytes(interval);
            return Err(error);
        }
        retries += 1;
        if retries > MAXIMUM_RETRIES || space.io_state_sequence.get() == sequence {
            break;
        }
    }
    guest::free_bytes(interval);
    space.io_state_sequence.set(sequence.wrapping_add(1));
    Ok(())
}

/// O payload que os callbacks recebem: o endereço, quem é dono da cópia e
/// se o aviso fica síncrono (a cópia local de UserMode ou o buffer do
/// chamador de KernelMode sem pool).
struct Payload {
    address: u64,
    owner: Owner,
    synchronous: bool,
}

enum Owner {
    Caller,
    Pool,
    Local,
}

impl Payload {
    fn release(&self) {
        match self.owner {
            Owner::Pool => {
                let _ = pool_allocation::free(self.address, TAG as u64);
            }
            Owner::Local => guest::free_bytes(self.address),
            Owner::Caller => {}
        }
    }
}

/// A cópia do payload do chamador.
fn capture_payload(payload: u64, size: u32, event: u32, mode: u8) -> Result<Payload, u32> {
    let caller = |synchronous| Payload { address: payload, owner: Owner::Caller, synchronous };
    if size == 0 {
        return Ok(Payload { address: 0, owner: Owner::Caller, synchronous: false });
    }
    if mode == 0 && (event == EVENT_CREATED || event == EVENT_TERMINATED) {
        return Ok(caller(false));
    }
    let bytes = if mode != 0 {
        if !user_probe::probe_user_read(payload, size as u64) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        guest::try_read_bytes(payload, size as usize).map_err(|_| STATUS_ACCESS_VIOLATION)?
    } else {
        guest::read_bytes(payload, size as usize)
    };
    if let Ok(copy) = pool_allocation::allocate_tagged(PAGED_POOL, size as u64, TAG) {
        guest::write_bytes(copy, &bytes);
        return Ok(Payload { address: copy, owner: Owner::Pool, synchronous: false });
    }
    if mode == 0 {
        return Ok(caller(true));
    }
    let local = guest::alloc_bytes(size as u64);
    if local == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(local, &bytes);
    Ok(Payload { address: local, owner: Owner::Local, synchronous: true })
}

/// NtNotifyChangeSession no modo `mode`. Devolve o NTSTATUS.
#[allow(clippy::too_many_arguments)]
pub fn notify_change_session(handle: u64, sequence: u32, _time_stamp: u64, event: u32, new_state: u32, _previous_state: u32, payload: u64, payload_size: u32, mode: u8) -> Result<u32, KernelError> {
    if payload_size > MAXIMUM_PAYLOAD {
        return Ok(STATUS_INVALID_PARAMETER_6);
    }
    let object = match reference_session(handle, mode)? {
        Ok(object) => object,
        Err(status) => return Ok(status),
    };
    let space = session_space(object);
    wait_turn(space);
    advance_sequence(space, sequence)?;
    if event == 0 {
        release_turn(object);
        dereference(object)?;
        return Ok(0);
    }
    space.io_state.set(IoSessionState(new_state as i32));
    let captured = match capture_payload(payload, payload_size, event, mode) {
        Ok(captured) => captured,
        Err(status) => {
            release_turn(object);
            dereference(object)?;
            return Ok(status);
        }
    };
    if !captured.synchronous && event != EVENT_CREATED && event != EVENT_TERMINATED {
        if let Ok(block) = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, SessionChange::SIZE, TAG) {
            guest::write_bytes(block, &[0u8; SessionChange::SIZE as usize]);
            fill(block, event, new_state, payload_size, captured.address, object);
            work_items::queue_kernel_ex_work_item(block, session_change_worker, block);
            return Ok(0);
        }
    }
    let block = guest::alloc_bytes(SessionChange::SIZE);
    if block == 0 {
        captured.release();
        release_turn(object);
        dereference(object)?;
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &[0u8; SessionChange::SIZE as usize]);
    fill(block, event, new_state, payload_size, captured.address, object);
    let notified = callback_object().and_then(|callback| callbacks::notify(callback, block, 0));
    guest::free_bytes(block);
    release_turn(object);
    dereference(object)?;
    captured.release();
    notified.map(|()| 0)
}

fn fill(block: u64, event: u32, new_state: u32, payload_size: u32, payload: u64, object: u64) {
    // SAFETY: bloco de 0x40 bytes recém-alocado e zerado.
    let change = unsafe { SessionChange::at(block) };
    change.event.set(event);
    change.new_state.set(new_state);
    change.payload_size.set(payload_size);
    change.payload.set(payload);
    change.session_object.set(object);
}

/// IopSessionChangeWorker: o aviso aos callbacks, o evento de sincronização
/// liberado, o objeto solto e o payload e o bloco liberados. O bloco chega
/// como o Parameter do WORK_QUEUE_ITEM.
fn session_change_worker(_device: u64, block: u64) {
    // SAFETY: o bloco do aviso, vivo até o fim do worker.
    let change = unsafe { SessionChange::at(block) };
    let (object, payload) = (change.session_object.get(), change.payload.get());
    if let Ok(callback) = callback_object() {
        let _ = callbacks::notify(callback, block, 0);
    }
    release_turn(object);
    let _ = dereference(object);
    if payload != 0 {
        let _ = pool_allocation::free(payload, TAG as u64);
    }
    let _ = pool_allocation::free(block, TAG as u64);
}
