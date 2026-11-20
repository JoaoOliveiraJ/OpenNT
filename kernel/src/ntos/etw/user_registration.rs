//! Provedores ETW de modo usuário: o objeto EtwRegistration e as
//! notificações por processo, como no ntoskrnl 19041.
//!
//! - EtwRegistration (EtwpInitializeRegistration): GenericMapping
//!   EtwpGenericMapping, ValidAccessMask 0x804 (TRACELOG_REGISTER_GUIDS |
//!   WMIGUID_NOTIFICATION), SecurityRequired e MaintainHandleCount,
//!   InvalidAttributes OBJ_OPENLINK, NonPagedPoolNx, corpo de 0x70 bytes (o
//!   próprio ETW_REG_ENTRY). A DeleteProcedure (EtwpDeleteRegistrationObject)
//!   tira o registro da entrada do GUID, descarta as notificações dele e
//!   solta o processo. A CloseProcedure do NT só escreve um evento do
//!   provedor Microsoft-Windows-Kernel-EventTracing, que nenhuma sessão
//!   daqui habilita; o tipo fica sem ela.
//! - EtwRegisterGuids (NtTraceControl 15, EtwpRegisterUMGuid): o buffer de
//!   0xA0 bytes traz o GUID, o ETW_NOTIFICATION_TYPE (+0x10), o índice da
//!   ntdll (+0x14) e o contexto (+0x20); o GUID do provedor de segurança é
//!   STATUS_ACCESS_DENIED; o objeto nasce com o processo referenciado e o
//!   handle (0x804) vai para a tabela do chamador em +0x18; +0x2C recebe o
//!   tamanho (0xA0) e, com alguma sessão habilitando o provedor, +0x70 o
//!   TRACE_ENABLE_INFO agregado (zeros sem sessão).
//! - EtwAddNotificationEvent (27, EtwpAddNotificationEvent): o evento
//!   (EVENT_MODIFY_STATE, UserMode) vai para o EPROCESS.EtwDataSource (bloco
//!   'EtwS' de 0x28 bytes: o evento nativo em +0, o WoW64 em +8), criado na
//!   primeira vez; um segundo evento do mesmo tipo é
//!   STATUS_ALREADY_REGISTERED.
//! - Uma sessão que habilita ou desabilita o provedor enfileira no processo
//!   um pacote EtwNotificationTypeEnable de 0x78 bytes
//!   (ETWP_NOTIFICATION_HEADER com DestinationGuid = o provedor, SourceGuid =
//!   o controlador, e o TRACE_ENABLE_INFO agregado em +0x48) e sinaliza o
//!   evento; EtwReceiveNotification (16, EtwpReceiveNotification) entrega o
//!   primeiro pacote do tipo do chamador (nativo ou WoW64) com NotifyeeCount
//!   e RegIndex preenchidos, STATUS_MORE_ENTRIES se sobrar outro,
//!   STATUS_BUFFER_TOO_SMALL (com o tamanho) se não couber,
//!   STATUS_NO_MORE_ENTRIES com a fila vazia e STATUS_INVALID_PARAMETER sem
//!   EtwDataSource.
//! - EtwTrackProviderBinary (26), EtwSetProviderTraits (30) e
//!   EtwUseDescriptorType (31) referenciam o handle com
//!   TRACELOG_REGISTER_GUIDS no modo do chamador; os eventos de imagem do
//!   provedor que o 26 escreve nas sessões habilitadas (e os grupos de
//!   provedores dos traits) não existem aqui.
//! - NtTraceEvent com ETW_NT_FLAGS_TRACE_EVENT (0x300, o EtwEventWrite da
//!   ntdll): o bloco de 0x78 bytes (alinhado a 4) traz o EVENT_DESCRIPTOR
//!   (+0x28), o ActivityId (+0x40), o RelatedActivityId (+0x60, com +0x50
//!   ligado), o EventProperty (+0x52), UserDataCount (+0x54) e UserData
//!   (+0x58); o handle é o do registro.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use super::provider_state::{self, UserNotification, UserOwner};
use crate::hal::amd64::routine_stubs::Routine;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::ntos::init::exports::Call;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::{object_create, object_header, object_reference};
use crate::rtl::{KernelError, SpinLock};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_ALREADY_REGISTERED: u32 = 0xC000_0718;
const STATUS_MORE_ENTRIES: u32 = 0x105;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;

/// TRACELOG_REGISTER_GUIDS.
const TRACELOG_REGISTER_GUIDS: u32 = 0x800;
/// O acesso do handle de um registro novo.
const REGISTRATION_ACCESS: u32 = 0x804;
/// EVENT_MODIFY_STATE.
const EVENT_MODIFY_STATE: u32 = 2;
/// ETW_NOTIFICATION_TYPE EtwNotificationTypeEnable.
const NOTIFICATION_TYPE_ENABLE: u32 = 3;
/// Tamanho do pacote de habilitação.
const ENABLE_PACKET_SIZE: usize = 0x78;
/// O buffer do EtwRegisterGuids.
const REGISTER_SIZE: u32 = 0xA0;
/// SecurityProviderGuid {54849625-5478-4994-A5BA-3E3B0328C30D}.
const SECURITY_PROVIDER_GUID: [u8; 16] = [0x25, 0x96, 0x84, 0x54, 0x78, 0x54, 0x94, 0x49, 0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D];
/// Tags 'EtwR' (referência do processo) e 'EtwS' (EtwDataSource).
const PROCESS_TAG: u32 = 0x5277_7445;
const DATA_SOURCE_TAG: u32 = 0x5377_7445;
const DATA_SOURCE_SIZE: u64 = 0x28;

/// O OBJECT_TYPE_INITIALIZER do EtwpInitializeRegistration.
const REGISTRATION_TYPE: TypeTemplate = TypeTemplate {
    name: "EtwRegistration",
    mapping: [0x2_000D, 0x2_0062, 0x2_1E90, 0x2_1EFF],
    valid_access: REGISTRATION_ACCESS,
    flags: 0x18,
    object_type_code: 0,
    invalid_attributes: 0x100,
    pool_type: 0x200,
    paged_charge: 0,
    non_paged_charge: 0x70,
};

/// Rotinas entregues por ponteiro ao gerenciador de objetos.
pub const ROUTINES: &[Routine] = &[Routine { name: "EtwpDeleteRegistrationObject", handler: delete_routine }];

fn delete_routine(call: &Call) -> Result<u64, KernelError> {
    delete_registration(call.arg(1));
    Ok(0)
}

/// Cria o tipo EtwRegistration (uma vez) com a DeleteProcedure e liga a
/// limpeza do EtwDataSource ao término de processo.
pub fn initialize_type() {
    let pointer = registration_type();
    if let (Some(info), Ok(delete)) = (object_types::type_object(pointer), crate::hal::amd64::routine_stubs::address("EtwpDeleteRegistrationObject")) {
        info.type_info.delete_procedure.set(delete);
    }
    crate::ntos::ps::process::register_process_exit_routine(process_exit);
}

fn registration_type() -> u64 {
    object_types::ensure(&REGISTRATION_TYPE).pointer
}

/// Um pacote na fila de um processo.
struct Queued {
    packet: Vec<u8>,
    registration: u64,
    index: u16,
    wow64: bool,
}

/// As filas de notificação, pelo EtwDataSource do processo.
static QUEUES: SpinLock<BTreeMap<u64, VecDeque<Queued>>> = SpinLock::new(BTreeMap::new());
/// Registros de modo usuário já feitos (o marcador do primeiro sai na serial).
static REGISTERED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (o do chamador ou o retido por um registro).
    unsafe { Eprocess::at(process) }
}

/// EtwpAddDataSource: o EtwDataSource do processo, criado se preciso.
fn data_source(process: u64, create: bool) -> u64 {
    let cell = &eprocess(process).etw_data_source;
    let current = cell.get();
    if current != 0 || !create {
        return current;
    }
    let Ok(block) = kernel_pool::allocate(DATA_SOURCE_SIZE, AllocateOptions { tag: DATA_SOURCE_TAG, zero: true, ..Default::default() }) else { return 0 };
    // A fila (LIST_ENTRY em +0x18) começa vazia.
    guest::write64(block + 0x18, block + 0x18);
    guest::write64(block + 0x20, block + 0x18);
    match cell.atomic().compare_exchange(0, block, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst) {
        Ok(_) => block,
        Err(winner) => {
            let _ = kernel_pool::free(block, None);
            winner
        }
    }
}

/// Término do processo: os eventos soltos, a fila descartada e o bloco
/// devolvido.
fn process_exit(process: u64) {
    let cell = &eprocess(process).etw_data_source;
    let block = cell.atomic().swap(0, core::sync::atomic::Ordering::SeqCst);
    if block == 0 {
        return;
    }
    QUEUES.lock().remove(&block);
    for slot in [block, block + 8] {
        let event = guest::read64(slot);
        if event != 0 {
            release(event);
        }
    }
    let _ = kernel_pool::free(block, None);
}

/// ObDereferenceObject de uma referência do ObReferenceObjectByHandle (o
/// dono real do corpo: evento do executive ou EtwRegistration).
fn release(object: u64) {
    let _ = object_reference::dereference_with_tag(object, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
}

/// Referencia um handle EtwRegistration (TRACELOG_REGISTER_GUIDS) no modo
/// dado: Ok(corpo) ou o status do ObReferenceObjectByHandle.
fn reference_registration(handle: u64, mode: u8) -> Result<Result<u64, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let status = object_reference::reference_by_handle(handle, TRACELOG_REGISTER_GUIDS, registration_type(), mode, slot, 0)? as u32;
    let body = guest::read64(slot);
    guest::free_bytes(slot);
    Ok(if status & 0x8000_0000 != 0 { Err(status) } else { Ok(body) })
}

/// EtwpRegisterUMGuid sobre a cópia de trabalho (0xA0 bytes de entrada,
/// `output_length` de saída). Devolve o ReturnLength ou (status, ReturnLength).
pub fn register_guid(buffer: &mut [u8], output_length: u32, wow64: bool) -> Result<u32, (u32, u32)> {
    let identifier: [u8; 16] = buffer[0..16].try_into().unwrap();
    let kind = u32::from_le_bytes(buffer[0x10..0x14].try_into().unwrap());
    let index = u32::from_le_bytes(buffer[0x14..0x18].try_into().unwrap()) as u16;
    let context = u64::from_le_bytes(buffer[0x20..0x28].try_into().unwrap());
    if identifier == SECURITY_PROVIDER_GUID {
        return Err((STATUS_ACCESS_DENIED, 0));
    }
    if REGISTER_SIZE > output_length {
        return Err((STATUS_BUFFER_TOO_SMALL, REGISTER_SIZE));
    }
    let process = crate::ntos::ps::thread_accessors::current_process();
    let created = create_registration(identifier, process, UserOwner { process, index, kind }, context, wow64);
    let (handle, state) = match created {
        Ok(Ok(created)) => created,
        Ok(Err(status)) => return Err((status, 0)),
        Err(_) => return Err((STATUS_INSUFFICIENT_RESOURCES, 0)),
    };
    buffer[0x18..0x20].copy_from_slice(&handle.to_le_bytes());
    buffer[0x2C..0x30].copy_from_slice(&REGISTER_SIZE.to_le_bytes());
    buffer[0x70..0xA0].fill(0);
    if state.enable_mask != 0 {
        buffer[0x70..0x90].copy_from_slice(&state.information.bytes());
    }
    if REGISTERED.fetch_add(1, core::sync::atomic::Ordering::SeqCst) == 0 {
        crate::debug_print!("[etw] ETW_USER_REGISTRATION_OK provedor {} handle={:#x}", guid_text(&identifier), handle);
    }
    Ok(REGISTER_SIZE)
}

/// O GUID no formato do registro ({xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}).
pub fn guid_text(bytes: &[u8; 16]) -> alloc::string::String {
    let d1 = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let d2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let d3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    alloc::format!("{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}", bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15])
}

/// EtwpAddUmRegEntry: o objeto (ObCreateObjectEx com OwnershipMode
/// UserMode), o processo referenciado, o registro ligado e o handle no
/// processo corrente.
fn create_registration(identifier: [u8; 16], process: u64, owner: UserOwner, context: u64, wow64: bool) -> Result<Result<(u64, provider_state::UserRegistrationState), u32>, KernelError> {
    let cells = guest::alloc_bytes(0x40);
    if cells == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    // PVOID, HANDLE e o OBJECT_ATTRIBUTES (Length 0x30, OBJ_CASE_INSENSITIVE).
    guest::write_bytes(cells, &[0u8; 0x40]);
    let attributes = cells + 0x10;
    guest::write32(attributes, 0x30);
    guest::write32(attributes + 0x18, 0x40);
    // SAFETY: as células PVOID/HANDLE alocadas acima.
    let (object_cell, handle_cell) = unsafe { (Field::<u64>::at(cells), Field::<u64>::at(cells + 8)) };
    let status = object_create::create(0, registration_type(), attributes, 1, REGISTRATION_TYPE.non_paged_charge, 0, 0, cells);
    let result = (|| -> Result<Result<(u64, provider_state::UserRegistrationState), u32>, KernelError> {
        if status & 0x8000_0000 != 0 {
            return Ok(Err(status));
        }
        let body = object_cell.get();
        guest::write_bytes(body, &[0u8; 0x70]);
        let _ = object_reference::reference_with_tag(process, PROCESS_TAG, false);
        let state = match provider_state::register_user(identifier, body, owner, context, wow64) {
            Ok(state) => state,
            Err(status) => {
                let _ = object_reference::dereference_with_tag(process, PROCESS_TAG, false);
                object_header::dereference(body, false);
                return Ok(Err(status));
            }
        };
        object_header::reference(body, 1);
        let status = object_create::insert(body, REGISTRATION_ACCESS, 0, 0, handle_cell.address())?;
        let handle = handle_cell.get();
        object_header::dereference(body, false);
        if status & 0x8000_0000 != 0 {
            return Ok(Err(status));
        }
        Ok(Ok((handle, state)))
    })();
    guest::free_bytes(cells);
    result
}

/// EtwpDeleteRegistrationObject.
fn delete_registration(body: u64) {
    let Some(owner) = provider_state::delete_user(body) else { return };
    // EtwpRundownNotifications: os pacotes do registro saem da fila.
    let block = eprocess(owner.process).etw_data_source.get();
    if block != 0 {
        if let Some(queue) = QUEUES.lock().get_mut(&block) {
            queue.retain(|queued| queued.registration != body);
        }
    }
    let _ = object_reference::dereference_with_tag(owner.process, PROCESS_TAG, false);
}

/// EtwpAddNotificationEvent(Handle, Wow64).
pub fn add_notification_event(handle: u64, wow64: bool, mode: u8) -> Result<u32, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = object_reference::reference_by_handle(handle, EVENT_MODIFY_STATE, object_types::event_type().pointer, mode, slot, 0)? as u32;
    let event = guest::read64(slot);
    guest::free_bytes(slot);
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    let block = data_source(crate::ntos::ps::thread_accessors::current_process(), true);
    if block == 0 {
        release(event);
        return Ok(STATUS_NO_MEMORY);
    }
    // SAFETY: a célula do evento no EtwDataSource (alinhada a 8).
    let cell = unsafe { Field::<u64>::at(block + if wow64 { 8 } else { 0 }) };
    if cell.atomic().compare_exchange(0, event, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
        release(event);
        return Ok(STATUS_ALREADY_REGISTERED);
    }
    Ok(0)
}

/// EtwpQueueNotification de uma habilitação: o pacote vai para a fila do
/// processo dono e o evento de notificação dele é sinalizado. Só os
/// registros EtwNotificationTypeEnable (EventRegister) recebem o pacote.
pub fn queue_enable(notification: &UserNotification) {
    if notification.owner.kind != NOTIFICATION_TYPE_ENABLE {
        return;
    }
    let block = data_source(notification.owner.process, false);
    if block == 0 {
        return;
    }
    // SAFETY: corpo EtwRegistration vivo (o registro está na entrada).
    let native = unsafe { crate::ntos::inc::types::EtwRegEntry::at(notification.registration) };
    let wow64 = native.flags.get() & provider_state::flags::WOW64 != 0;
    let mut packet = alloc::vec![0u8; ENABLE_PACKET_SIZE];
    packet[0..4].copy_from_slice(&NOTIFICATION_TYPE_ENABLE.to_le_bytes());
    packet[4..8].copy_from_slice(&(ENABLE_PACKET_SIZE as u32).to_le_bytes());
    packet[8..12].copy_from_slice(&1u32.to_le_bytes());
    packet[0x28..0x38].copy_from_slice(&notification.provider);
    packet[0x38..0x48].copy_from_slice(&notification.source);
    packet[0x48..0x68].copy_from_slice(&notification.information.bytes());
    QUEUES.lock().entry(block).or_default().push_back(Queued { packet, registration: notification.registration, index: notification.owner.index, wow64 });
    let event = guest::read64(block + if wow64 { 8 } else { 0 });
    if event != 0 {
        crate::ntos::ke::dispatcher::set_event(event);
    }
}

/// Pacotes na fila do processo (autotestes e diagnóstico).
pub fn pending(process: u64) -> usize {
    let block = eprocess(process).etw_data_source.get();
    QUEUES.lock().get(&block).map_or(0, VecDeque::len)
}

/// EtwpReceiveNotification sobre a cópia de trabalho (`output_length` bytes).
pub fn receive_notification(buffer: &mut [u8], output_length: u32, wow64: bool) -> Result<u32, (u32, u32)> {
    let block = data_source(crate::ntos::ps::thread_accessors::current_process(), false);
    if block == 0 {
        return Err((STATUS_INVALID_PARAMETER, 0));
    }
    let mut queues = QUEUES.lock();
    let Some(queue) = queues.get_mut(&block) else { return Err((STATUS_NO_MORE_ENTRIES, 0)) };
    let Some(position) = queue.iter().position(|queued| queued.wow64 == wow64) else { return Err((STATUS_NO_MORE_ENTRIES, 0)) };
    let size = queue[position].packet.len() as u32;
    if size > output_length {
        return Err((STATUS_BUFFER_TOO_SMALL, size));
    }
    let queued = queue.remove(position).expect("posição achada");
    let more = !queue.is_empty();
    drop(queues);
    buffer[..size as usize].copy_from_slice(&queued.packet);
    // NotifyeeCount (a contagem do bloco de dados) e o RegIndex do registro.
    buffer[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    buffer[0x18..0x20].copy_from_slice(&(queued.index as u64).to_le_bytes());
    // STATUS_MORE_ENTRIES é sucesso: o pacote volta copiado do mesmo jeito.
    if more { Err((STATUS_MORE_ENTRIES, size)) } else { Ok(size) }
}

/// EtwpTrackProviderBinary: o handle (TRACELOG_REGISTER_GUIDS) e a marca
/// DbgTrackedBinary no registro.
pub fn track_provider_binary(handle: u64, mode: u8) -> Result<u32, KernelError> {
    let body = match reference_registration(handle, mode)? {
        Ok(body) => body,
        Err(status) => return Ok(status),
    };
    // SAFETY: corpo EtwRegistration referenciado.
    let native = unsafe { crate::ntos::inc::types::EtwRegEntry::at(body) };
    native.flags.atomic().fetch_or(provider_state::flags::TRACKED_BINARY, core::sync::atomic::Ordering::SeqCst);
    release(body);
    Ok(0)
}

/// EtwpUseDescriptorTypeUm: {handle, BOOLEAN}.
pub fn use_descriptor_type(handle: u64, value: u8, mode: u8) -> Result<u32, KernelError> {
    let body = match reference_registration(handle, mode)? {
        Ok(body) => body,
        Err(status) => return Ok(status),
    };
    let status = provider_state::use_descriptor_type(body, value);
    release(body);
    Ok(status)
}

/// EtwpSetProviderTraitsUm: {handle, Traits, USHORT TraitsSize}; o registro
/// precisa ser de modo usuário e não clássico. Sem grupo de provedores a
/// habilitar, não há TRACE_ENABLE_INFO de volta (ReturnLength 0).
pub fn set_traits(buffer: &[u8], mode: u8) -> Result<u32, (u32, u32)> {
    let handle = u64::from_le_bytes(buffer[0..8].try_into().unwrap());
    let traits = u64::from_le_bytes(buffer[8..16].try_into().unwrap());
    let size = u16::from_le_bytes([buffer[0x10], buffer[0x11]]) as u64;
    if traits == 0 || size == 0 {
        return Err((STATUS_INVALID_PARAMETER, 0));
    }
    let body = match reference_registration(handle, mode) {
        Ok(Ok(body)) => body,
        Ok(Err(status)) => return Err((status, 0)),
        Err(_) => return Err((STATUS_INSUFFICIENT_RESOURCES, 0)),
    };
    let status = (|| {
        // SAFETY: corpo EtwRegistration referenciado.
        let native = unsafe { crate::ntos::inc::types::EtwRegEntry::at(body) };
        let flags = native.flags.get();
        if flags & provider_state::flags::CLASSIC != 0 || flags & provider_state::flags::USER == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        if native.traits.get() != 0 {
            return provider_state::STATUS_UNSUCCESSFUL;
        }
        let end = traits.wrapping_add(size);
        if mode != 0 && (end > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS || end < traits) {
            return STATUS_ACCESS_VIOLATION;
        }
        match guest::try_read_bytes(traits, size as usize) {
            Ok(bytes) => provider_state::set_traits(body, &bytes),
            Err(_) => STATUS_ACCESS_VIOLATION,
        }
    })();
    release(body);
    if status & 0x8000_0000 != 0 { Err((status, 0)) } else { Ok(0) }
}

/// NtTraceEvent com flags 0x500 (o EtwWriteUMSecurityEvent da ntdll, os
/// eventos de auditoria do lsasrv), como no NtTraceEvent do 19041: só o
/// processo registrado pelo código 24 do NtTraceControl
/// (`logger::security_provider_pid`) escreve, os outros recebem
/// STATUS_ACCESS_DENIED; o bloco de 0x78 bytes passa pelas mesmas sondas
/// do 0x300 e vai às sessões de segurança do silo. O OpenNT não tem sessão
/// de segurança (o logger do Eventlog-Security): o evento é aceito sem
/// destino, como o EtwpWriteUserEvent com a máscara de loggers vazia.
fn security_event(fields: u64, mode: u8) -> u32 {
    if crate::ntos::ps::process::get_current_process_id() != super::logger::security_provider_pid() {
        return 0xC000_0022;
    }
    if mode != 0 {
        if fields & 3 != 0 {
            return 0x8000_0002;
        }
        let end = fields.wrapping_add(0x78);
        if end > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS || end < fields {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if guest::try_read_bytes(fields, 0x78).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    0
}

/// NtTraceEvent(TraceHandle, Flags, FieldSize, Fields) de modo usuário.
pub fn trace_event(handle: u64, flags: u32, _field_size: u32, fields: u64, mode: u8) -> Result<u32, KernelError> {
    if flags & 0xFF00 == 0x500 {
        return Ok(security_event(fields, mode));
    }
    if flags & 0xFF00 != 0x300 {
        // EVENT_TRACE_HEADER clássico (0x200) e TraceMessage: as sessões
        // daqui não têm o logger clássico por TRACEHANDLE.
        return Ok(0xC000_0010);
    }
    if mode != 0 {
        if fields & 3 != 0 {
            return Ok(0x8000_0002);
        }
        let end = fields.wrapping_add(0x78);
        if end > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS || end < fields {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let Ok(block) = guest::try_read_bytes(fields, 0x78) else { return Ok(STATUS_ACCESS_VIOLATION) };
    let body = match reference_registration(handle, mode)? {
        Ok(body) => body,
        Err(status) => return Ok(status),
    };
    let descriptor: [u8; 16] = block[0x28..0x38].try_into().unwrap();
    let activity: [u8; 16] = block[0x40..0x50].try_into().unwrap();
    let related: Option<[u8; 16]> = (block[0x50] != 0).then(|| block[0x60..0x70].try_into().unwrap());
    let property = u16::from_le_bytes([block[0x52], block[0x53]]);
    let count = u32::from_le_bytes(block[0x54..0x58].try_into().unwrap());
    let data = u64::from_le_bytes(block[0x58..0x60].try_into().unwrap());
    let user = mode != 0;
    let result = provider_state::deliver(body, descriptor, || {
        let read = |address: u64, length: usize| -> Result<Vec<u8>, KernelError> {
            let end = address.wrapping_add(length as u64);
            if user && (end > crate::ntos::mm::memory_map::USER_PROBE_ADDRESS || end < address) {
                return Err(KernelError::with_status("ETW user data outside the user range", STATUS_ACCESS_VIOLATION));
            }
            guest::try_read_bytes(address, length)
        };
        let segments = match provider_state::read_segments(count, data, read, read) {
            Ok(Ok(segments)) => segments,
            Ok(Err(status)) => return Ok(Err(status)),
            Err(_) => return Ok(Err(STATUS_ACCESS_VIOLATION)),
        };
        Ok(Ok(provider_state::Payload { activity, related_activity: related, flags: provider_state::header_flags::SIXTY_FOUR_BIT_HEADER, event_property: property, segments }))
    });
    release(body);
    result
}
