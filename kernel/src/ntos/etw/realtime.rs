//! Consumidores de tempo real do ETW: o objeto EtwConsumer e a entrega dos
//! buffers de uma sessão ao processo consumidor, como no ntoskrnl 19041.
//!
//! - EtwConsumer (EtwpInitializeRealTimeConnection): GenericMapping
//!   EtwpGenericMapping, ValidAccessMask 0x400 (TRACELOG_ACCESS_REALTIME),
//!   SecurityRequired e MaintainHandleCount, InvalidAttributes OBJ_OPENLINK,
//!   NonPagedPoolNx, corpo de 0xA0 bytes (o ETW_REALTIME_CONSUMER). A
//!   OpenProcedure (EtwpOpenRealTimeConnectionObject) só aceita o handle de
//!   criação (outro motivo de abertura dá STATUS_NOT_SUPPORTED); a
//!   CloseProcedure (EtwpCloseRealTimeConnectionObject) pede o desligamento
//!   do consumidor; a DeleteProcedure (EtwpDeleteRealTimeConnectionObject)
//!   solta o processo e os dois eventos. O estado do consumidor fica no
//!   `Consumer` daqui, pelo corpo do objeto.
//! - EtwRealtimeConnect (NtTraceControl 11, EtwpRealtimeConnect): o buffer
//!   de 0x60 bytes que o EtwpSetupRealTimeContext do sechost monta traz o
//!   LoggerId (+0), o tamanho (+4) e o endereço (+8) do espaço reservado no
//!   processo consumidor, o bitmap das páginas dele (+0x10), os handles dos
//!   eventos de desligamento (+0x18) e de dados (+0x20), a cabeça da lista
//!   dos buffers entregues (+0x28), o contador deles (+0x30) e os contadores
//!   de eventos e de buffers perdidos (+0x38, +0x40). As faixas passam pelo
//!   ProbeForWrite (alinhamento 4) mesmo com chamador de kernel; os
//!   eventos são referenciados com EVENT_MODIFY_STATE em UserMode; a sessão
//!   precisa existir e estar em EVENT_TRACE_REAL_TIME_MODE (senão
//!   STATUS_INVALID_PARAMETER). O handle (0x400, na tabela do chamador)
//!   volta em +0x48 e o RealtimeReferenceTime da sessão (StartTime,
//!   StartPerfClock) em +0x50; a thread do logger entrega em seguida os
//!   buffers que a sessão guardou antes de haver consumidor.
//! - Entrega (EtwpRealtimeDeliverBuffer/EtwpRealtimeInjectEtwBuffer), sempre
//!   na thread do logger, anexada ao processo do consumidor: os contadores
//!   de perdas do consumidor recebem os da sessão; com o contador de buffers
//!   entregues em 4 x MaximumBuffers, STATUS_DATA_OVERRUN e o buffer perdido
//!   para esse consumidor; senão os Offset bytes do buffer vão para a
//!   primeira faixa livre de páginas do espaço reservado (pelo bitmap do
//!   consumidor, que o sechost limpa ao terminar o buffer) ou, sem faixa,
//!   para páginas novas do processo (ZwAllocateVirtualMemory, que o sechost
//!   libera com VirtualFree); o SlistEntry do cabeçalho (+0x20) entra na
//!   cabeça da lista por cmpxchg (32 bits num consumidor WoW64), o contador
//!   sobe e, com a lista antes vazia, o evento de dados é sinalizado. Outra
//!   falha desassocia o consumidor. O marcador vazio (BufferType 6, Offset
//!   0x48, BufferFlag ETW_BUFFER_FLAG_FLUSH_MARKER) não vai a sessões de um
//!   fluxo só (EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING) e vai no máximo duas
//!   vezes seguidas a cada consumidor das outras.
//! - EtwRealtimeDisconnect (14, EtwpRealtimeDisconnectConsumerByHandle) e a
//!   CloseProcedure (EtwpRealtimeDisconnectConsumer): um consumidor já
//!   desligando ou desligado dá STATUS_ALREADY_DISCONNECTED; sem a sessão,
//!   STATUS_INVALID_PARAMETER; fora da lista dela,
//!   STATUS_WMI_INSTANCE_NOT_FOUND; senão ShutDownRequested e o flush vão à
//!   thread do logger, que entrega o que restou com o marcador e desassocia
//!   o consumidor (EtwpDisassociateConsumer: fora da lista, Disconnected, o
//!   evento de desligamento sinalizado, a referência da lista solta). O Stop
//!   da sessão desassocia todos (EtwpRealtimeDisconnectAllConsumers).

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::logger::{self, LoggerContext};
use crate::hal::amd64::routine_stubs::Routine;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::init::exports::Call;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::ob::{object_create, object_header, object_reference};
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_WMI_INSTANCE_NOT_FOUND: u32 = 0xC000_0296;
/// STATUS_DATA_OVERRUN: o consumidor ainda não leu os buffers anteriores.
const STATUS_DATA_OVERRUN: u32 = 0xC000_003C;
/// STATUS_ALREADY_DISCONNECTED.
const STATUS_ALREADY_DISCONNECTED: u32 = 0x8000_0025;

/// TRACELOG_ACCESS_REALTIME: o acesso do handle do consumidor.
const TRACELOG_ACCESS_REALTIME: u32 = 0x400;
/// EVENT_MODIFY_STATE.
const EVENT_MODIFY_STATE: u32 = 2;
/// O tamanho do buffer do EtwRealtimeConnect.
pub const CONNECT_SIZE: u32 = 0x60;
/// sizeof(ETW_REALTIME_CONSUMER).
const CONSUMER_SIZE: u32 = 0xA0;
/// O SlistEntry do WMI_BUFFER_HEADER, ligado na lista do consumidor.
const SLIST_ENTRY_OFFSET: u64 = 0x20;
/// Tag da referência do processo consumidor ('EtwC').
const PROCESS_TAG: u32 = 0x4377_7445;
const PAGE: u64 = 0x1000;
/// MEM_COMMIT | MEM_RESERVE e PAGE_READWRITE: o ZwAllocateVirtualMemory com
/// endereço nulo do EtwpFindUserBufferSpace (MEM_COMMIT, que o NT trata
/// como reserva e commit quando o endereço é nulo).
const MEM_COMMIT_RESERVE: u32 = 0x3000;
const MEM_RELEASE: u32 = 0x8000;
const PAGE_READWRITE: u32 = 4;
/// NtCurrentProcess.
const CURRENT_PROCESS: u64 = u64::MAX;

/// Offsets do buffer do EtwRealtimeConnect (o contexto que o sechost monta).
mod connect {
    pub const LOGGER_ID: usize = 0x00;
    pub const SPACE_SIZE: usize = 0x04;
    pub const SPACE: usize = 0x08;
    pub const BITMAP: usize = 0x10;
    pub const DISCONNECT_EVENT: usize = 0x18;
    pub const DATA_EVENT: usize = 0x20;
    pub const LIST_HEAD: usize = 0x28;
    pub const BUFFER_COUNT: usize = 0x30;
    pub const EVENTS_LOST: usize = 0x38;
    pub const BUFFERS_LOST: usize = 0x40;
    pub const HANDLE: usize = 0x48;
    pub const REFERENCE_TIME: usize = 0x50;
}

/// O OBJECT_TYPE_INITIALIZER do EtwpInitializeRealTimeConnection.
const CONSUMER_TYPE: TypeTemplate = TypeTemplate {
    name: "EtwConsumer",
    mapping: [0x2_000D, 0x2_0062, 0x2_1E90, 0x2_1EFF],
    valid_access: TRACELOG_ACCESS_REALTIME,
    flags: 0x18,
    object_type_code: 0,
    invalid_attributes: 0x100,
    pool_type: 0x200,
    paged_charge: 0,
    non_paged_charge: CONSUMER_SIZE,
};

/// Rotinas entregues por ponteiro ao gerenciador de objetos.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "EtwpOpenRealTimeConnectionObject", handler: open_routine },
    Routine { name: "EtwpCloseRealTimeConnectionObject", handler: close_routine },
    Routine { name: "EtwpDeleteRealTimeConnectionObject", handler: delete_routine },
];

/// OpenProcedure(OpenReason, ...): só ObCreateHandle (0).
fn open_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(if call.arg(1) == 0 { 0 } else { STATUS_NOT_SUPPORTED as u64 })
}

/// CloseProcedure(Process, Object, ProcessHandleCount, SystemHandleCount).
fn close_routine(call: &Call) -> Result<u64, KernelError> {
    let _ = disconnect(call.arg(2));
    Ok(0)
}

/// DeleteProcedure(Object).
fn delete_routine(call: &Call) -> Result<u64, KernelError> {
    delete_consumer(call.arg(1));
    Ok(0)
}

/// Cria o tipo EtwConsumer (uma vez) com as três rotinas.
pub fn initialize_type() {
    let pointer = consumer_type();
    let Some(info) = object_types::type_object(pointer) else { return };
    let address = crate::hal::amd64::routine_stubs::address;
    if let Ok(open) = address("EtwpOpenRealTimeConnectionObject") {
        info.type_info.open_procedure.set(open);
    }
    if let Ok(close) = address("EtwpCloseRealTimeConnectionObject") {
        info.type_info.close_procedure.set(close);
    }
    if let Ok(delete) = address("EtwpDeleteRealTimeConnectionObject") {
        info.type_info.delete_procedure.set(delete);
    }
}

fn consumer_type() -> u64 {
    object_types::ensure(&CONSUMER_TYPE).pointer
}

/// Um consumidor de tempo real ligado a uma sessão.
pub struct Consumer {
    /// O corpo do objeto EtwConsumer.
    body: u64,
    /// O EPROCESS consumidor (referenciado).
    process: u64,
    logger_id: u16,
    /// Consumidor WoW64: a lista de buffers tem ponteiros de 32 bits.
    wow64: bool,
    /// Os KEVENTs referenciados: DisconnectEvent e DataAvailableEvent.
    disconnect_event: u64,
    data_event: u64,
    /// Ponteiros no processo consumidor.
    buffer_count: u64,
    list_head: u64,
    events_lost: u64,
    buffers_lost: u64,
    /// O ReservedBufferSpaceBitMap: o Buffer do RTL_BITMAP é do consumidor.
    bitmap: u64,
    pages: u32,
    space: u64,
    space_size: u32,
    /// ShutDownRequested e Disconnected.
    shutdown: AtomicBool,
    disconnected: AtomicBool,
    /// EmptyBuffersCount: marcadores vazios seguidos.
    empty_buffers: AtomicU32,
    /// BuffersLost: buffers que este consumidor não recebeu.
    lost: AtomicU32,
}

impl Consumer {
    pub fn body(&self) -> u64 {
        self.body
    }

    pub fn shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    pub fn disconnected(&self) -> bool {
        self.disconnected.load(Ordering::SeqCst)
    }
}

/// Os consumidores vivos, pelo corpo do objeto.
static CONSUMERS: SpinLock<BTreeMap<u64, Arc<Consumer>>> = SpinLock::new(BTreeMap::new());

fn get32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap())
}

fn get64(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buffer[offset..offset + 8].try_into().unwrap())
}

/// Os campos do buffer do EtwRealtimeConnect.
#[derive(Clone, Copy, Debug)]
pub struct Connection {
    pub logger_id: u32,
    pub space_size: u32,
    pub space: u64,
    pub bitmap: u64,
    pub disconnect_event: u64,
    pub data_event: u64,
    pub list_head: u64,
    pub buffer_count: u64,
    pub events_lost: u64,
    pub buffers_lost: u64,
}

impl Connection {
    pub fn parse(buffer: &[u8]) -> Self {
        Self {
            logger_id: get32(buffer, connect::LOGGER_ID),
            space_size: get32(buffer, connect::SPACE_SIZE),
            space: get64(buffer, connect::SPACE),
            bitmap: get64(buffer, connect::BITMAP),
            disconnect_event: get64(buffer, connect::DISCONNECT_EVENT),
            data_event: get64(buffer, connect::DATA_EVENT),
            list_head: get64(buffer, connect::LIST_HEAD),
            buffer_count: get64(buffer, connect::BUFFER_COUNT),
            events_lost: get64(buffer, connect::EVENTS_LOST),
            buffers_lost: get64(buffer, connect::BUFFERS_LOST),
        }
    }

    /// Páginas do espaço reservado (o SizeOfBitMap).
    fn pages(&self) -> u32 {
        self.space_size >> 12
    }

    /// As sondas do EtwpRealtimeConnect: ProbeForWrite do bitmap (os ULONGs
    /// que cobrem as páginas) e do espaço reservado, ProbeForWriteUlong dos
    /// três contadores e ProbeForWrite da cabeça da lista (4 bytes num
    /// consumidor WoW64), todos com alinhamento 4.
    fn probe(&self, wow64: bool) -> Result<(), u32> {
        let bitmap_size = ((self.pages() + 0x1F) >> 3) & 0x1FFF_FFFC;
        probe_for_write(self.bitmap, bitmap_size, 4)?;
        probe_for_write(self.space, self.space_size, 4)?;
        for counter in [self.buffer_count, self.events_lost, self.buffers_lost] {
            probe_ulong(counter)?;
        }
        probe_for_write(self.list_head, if wow64 { 4 } else { 8 }, 4)
    }
}

/// ProbeForWrite: o alinhamento e a faixa inteira de usuário, gravável.
fn probe_for_write(address: u64, length: u32, alignment: u64) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    if address & (alignment - 1) != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !crate::ntos::ps::user::state::probe_user_write(address, length as u64) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// ProbeForWriteUlong: um endereço acima do limite de usuário vira o
/// próprio limite, que falha.
fn probe_ulong(address: u64) -> Result<(), u32> {
    let limit = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
    if !crate::ntos::ps::user::state::probe_user_write(address.min(limit), 4) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// EtwpRealtimeConnect sobre a cópia de trabalho do NtTraceControl:
/// Ok(ReturnLength) ou (status, ReturnLength).
pub fn connect(buffer: &mut [u8], wow64: bool) -> Result<u32, (u32, u32)> {
    let connection = Connection::parse(buffer);
    connection.probe(wow64).map_err(|status| (status, 0))?;
    let (handle, reference_time) = attach(&connection, wow64).map_err(|status| (status, 0))?;
    buffer[connect::HANDLE..connect::HANDLE + 8].copy_from_slice(&handle.to_le_bytes());
    buffer[connect::REFERENCE_TIME..connect::REFERENCE_TIME + 8].copy_from_slice(&reference_time[0].to_le_bytes());
    buffer[connect::REFERENCE_TIME + 8..connect::REFERENCE_TIME + 16].copy_from_slice(&reference_time[1].to_le_bytes());
    Ok(CONNECT_SIZE)
}

/// ObDereferenceObject de uma referência do ObReferenceObjectByHandle ou
/// da lista da sessão.
fn release(object: u64) {
    let _ = object_reference::dereference_with_tag(object, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
}

/// Referencia o KEVENT de um handle de evento (EVENT_MODIFY_STATE,
/// UserMode).
fn reference_event(handle: u64) -> Result<u64, u32> {
    reference_handle(handle, EVENT_MODIFY_STATE, object_types::event_type().pointer, 1)
}

fn reference_handle(handle: u64, access: u32, object_type: u64, mode: u8) -> Result<u64, u32> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(slot, 0);
    let status = object_reference::reference_by_handle(handle, access, object_type, mode, slot, 0).map_or(STATUS_INSUFFICIENT_RESOURCES, |status| status as u32);
    let object = guest::read64(slot);
    guest::free_bytes(slot);
    if status & 0x8000_0000 != 0 { Err(status) } else { Ok(object) }
}

/// O núcleo do EtwpRealtimeConnect depois das sondas: a sessão, os eventos,
/// o objeto EtwConsumer com o handle no processo corrente e o consumidor
/// na lista da sessão. Devolve o handle e o RealtimeReferenceTime.
pub fn attach(connection: &Connection, wow64: bool) -> Result<(u64, [i64; 2]), u32> {
    let Some(context) = logger::context(connection.logger_id) else { return Err(STATUS_INVALID_PARAMETER) };
    if context.mode() & logger::EVENT_TRACE_REAL_TIME_MODE == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let disconnect_event = reference_event(connection.disconnect_event)?;
    let data_event = match reference_event(connection.data_event) {
        Ok(event) => event,
        Err(status) => {
            release(disconnect_event);
            return Err(status);
        }
    };
    let process = process::get_current_process();
    if object_reference::reference_with_tag(process, PROCESS_TAG, false).is_err() {
        release(disconnect_event);
        release(data_event);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let consumer = |body: u64| Consumer {
        body,
        process,
        logger_id: connection.logger_id as u16,
        wow64,
        disconnect_event,
        data_event,
        buffer_count: connection.buffer_count,
        list_head: connection.list_head,
        events_lost: connection.events_lost,
        buffers_lost: connection.buffers_lost,
        bitmap: connection.bitmap,
        pages: connection.pages(),
        space: connection.space,
        space_size: connection.space_size,
        shutdown: AtomicBool::new(false),
        disconnected: AtomicBool::new(false),
        empty_buffers: AtomicU32::new(0),
        lost: AtomicU32::new(0),
    };
    let (body, handle) = match create_object(consumer) {
        Ok(created) => created,
        Err((status, registered)) => {
            // Sem o objeto, os recursos voltam aqui; com ele, a
            // DeleteProcedure já os soltou.
            if !registered {
                release(disconnect_event);
                release(data_event);
                let _ = object_reference::dereference_with_tag(process, PROCESS_TAG, false);
            }
            return Err(status);
        }
    };
    let Some(registered) = CONSUMERS.lock().get(&body).cloned() else { return Err(STATUS_INSUFFICIENT_RESOURCES) };
    context.add_consumer(registered);
    Ok((handle, context.reference_time))
}

/// ObCreateObjectEx (OwnershipMode UserMode) e ObInsertObjectEx com
/// ObjectPointerBias 1: o handle de criação e a referência da lista da
/// sessão. O consumidor entra em CONSUMERS antes da inserção, para a
/// DeleteProcedure soltar o processo e os eventos se ela falhar. O erro diz
/// se o consumidor chegou a CONSUMERS.
fn create_object(consumer: impl FnOnce(u64) -> Consumer) -> Result<(u64, u64), (u32, bool)> {
    let cells = guest::alloc_bytes(0x40);
    if cells == 0 {
        return Err((STATUS_INSUFFICIENT_RESOURCES, false));
    }
    // PVOID, HANDLE e o OBJECT_ATTRIBUTES (Length 0x30, OBJ_CASE_INSENSITIVE).
    guest::write_bytes(cells, &[0u8; 0x40]);
    let attributes = cells + 0x10;
    guest::write32(attributes, 0x30);
    guest::write32(attributes + 0x18, 0x40);
    // SAFETY: as células PVOID/HANDLE alocadas acima.
    let (object_cell, handle_cell) = unsafe { (Field::<u64>::at(cells), Field::<u64>::at(cells + 8)) };
    let status = object_create::create(0, consumer_type(), attributes, 1, CONSUMER_SIZE, 0, 0, cells);
    let result = (|| -> Result<(u64, u64), (u32, bool)> {
        if status & 0x8000_0000 != 0 {
            return Err((status, false));
        }
        let body = object_cell.get();
        guest::write_bytes(body, &[0u8; CONSUMER_SIZE as usize]);
        CONSUMERS.lock().insert(body, Arc::new(consumer(body)));
        // A referência da lista da sessão (o ObjectPointerBias).
        object_header::reference(body, 1);
        let inserted = object_create::insert(body, TRACELOG_ACCESS_REALTIME, 0, 0, handle_cell.address()).map_or(STATUS_INSUFFICIENT_RESOURCES, |status| status);
        if inserted & 0x8000_0000 != 0 {
            object_header::dereference(body, false);
            return Err((inserted, true));
        }
        Ok((body, handle_cell.get()))
    })();
    guest::free_bytes(cells);
    result
}

/// EtwpDeleteRealTimeConnectionObject: o processo e os eventos soltos.
fn delete_consumer(body: u64) {
    let Some(consumer) = CONSUMERS.lock().remove(&body) else { return };
    release(consumer.disconnect_event);
    release(consumer.data_event);
    let _ = object_reference::dereference_with_tag(consumer.process, PROCESS_TAG, false);
}

/// EtwpRealtimeDisconnectConsumerByHandle (NtTraceControl 14): o handle
/// com TRACELOG_ACCESS_REALTIME no modo do chamador.
pub fn disconnect_by_handle(handle: u64, mode: u8) -> Result<u32, KernelError> {
    let body = match reference_handle(handle, TRACELOG_ACCESS_REALTIME, consumer_type(), mode) {
        Ok(body) => body,
        Err(status) => return Ok(status),
    };
    let status = disconnect(body);
    release(body);
    Ok(status)
}

/// EtwpRealtimeDisconnectConsumer: ShutDownRequested e o flush pedidos à
/// thread do logger, que desassocia o consumidor depois de entregar o que
/// restou.
pub fn disconnect(body: u64) -> u32 {
    let Some(consumer) = CONSUMERS.lock().get(&body).cloned() else { return STATUS_INVALID_PARAMETER };
    if consumer.disconnected() || consumer.shutting_down() {
        return STATUS_ALREADY_DISCONNECTED;
    }
    let Some(context) = logger::context(consumer.logger_id as u32) else { return STATUS_INVALID_PARAMETER };
    if !context.has_consumer(body) {
        return STATUS_WMI_INSTANCE_NOT_FOUND;
    }
    if consumer.shutdown.swap(true, Ordering::SeqCst) {
        return STATUS_ALREADY_DISCONNECTED;
    }
    context.request_flush();
    0
}

/// EtwpDisassociateConsumer: o consumidor sai da lista da sessão, fica
/// Disconnected, o evento de desligamento é sinalizado e a referência da
/// lista é solta. Só a thread do logger chama (ou o Stop, depois dela).
pub fn disassociate(context: &LoggerContext, consumer: &Arc<Consumer>) {
    if !context.remove_consumer(consumer.body) {
        return;
    }
    consumer.disconnected.store(true, Ordering::SeqCst);
    dispatcher::set_event(consumer.disconnect_event);
    // A referência da lista (`object_header::reference` do create_object).
    object_header::dereference(consumer.body, false);
}

/// EtwpRealtimeDisconnectAllConsumers.
pub fn disconnect_all(context: &LoggerContext) {
    for consumer in context.consumers() {
        disassociate(context, &consumer);
    }
}

/// EtwpRealtimeDeliverBuffer: o buffer (os Offset bytes) para cada
/// consumidor da lista; `marker` é o marcador vazio do flush. Um buffer de
/// dados que nenhum consumidor recebeu conta como RealTimeBuffersLost.
pub fn deliver(context: &LoggerContext, consumers: &[Arc<Consumer>], bytes: &[u8], marker: bool) {
    let single_stream = context.single_stream();
    let mut taken = false;
    for consumer in consumers {
        if consumer.disconnected() {
            continue;
        }
        if marker {
            let count = consumer.empty_buffers.fetch_add(1, Ordering::SeqCst) + 1;
            if single_stream || count > 2 {
                taken = true;
                continue;
            }
        } else {
            consumer.empty_buffers.store(0, Ordering::SeqCst);
        }
        match inject(context, consumer, bytes) {
            Ok(()) => taken = true,
            Err(STATUS_DATA_OVERRUN) => {
                consumer.lost.fetch_add(1, Ordering::SeqCst);
            }
            Err(_) => disassociate(context, consumer),
        }
    }
    if !marker {
        context.count_delivery(taken);
    }
}

/// O processo ainda pode receber buffers (a rundown protection do NT).
fn process_alive(process: u64) -> bool {
    process::with_record(process, |record| !record.terminated && !record.exiting).unwrap_or(false)
}

/// EtwpRealtimeInjectEtwBuffer: anexada ao processo do consumidor, a cópia
/// do buffer no espaço dele e o buffer na lista.
fn inject(context: &LoggerContext, consumer: &Consumer, bytes: &[u8]) -> Result<(), u32> {
    if !process_alive(consumer.process) {
        return Err(STATUS_PROCESS_IS_TERMINATING);
    }
    let (events_lost, buffers_lost) = context.loss_counters();
    let limit = context.maximum_buffers.saturating_mul(4);
    let attached = process_context::with_process(consumer.process, || -> Result<(), u32> {
        let fault = |_| STATUS_ACCESS_VIOLATION;
        guest::try_write32(consumer.events_lost, events_lost).map_err(fault)?;
        guest::try_write32(consumer.buffers_lost, buffers_lost).map_err(fault)?;
        if guest::try_read32(consumer.buffer_count).map_err(fault)? >= limit {
            return Err(STATUS_DATA_OVERRUN);
        }
        let length = bytes.len() as u32;
        let destination = find_space(consumer, length)?;
        if guest::try_write_bytes(destination, bytes).is_err() {
            free_space(consumer, destination, length);
            return Err(STATUS_ACCESS_VIOLATION);
        }
        let previous = push(consumer, destination + SLIST_ENTRY_OFFSET)?;
        guest::try_atomic_u32(consumer.buffer_count).map_err(fault)?.fetch_add(1, Ordering::SeqCst);
        // A lista estava vazia: o consumidor espera o evento de dados (com o
        // marcador 1 do sechost na cabeça ele ainda está percorrendo a lista
        // e vê o buffer novo no cmpxchg do fim).
        if previous == 0 {
            dispatcher::set_event(consumer.data_event);
        }
        Ok(())
    });
    attached.unwrap_or(Err(STATUS_PROCESS_IS_TERMINATING))
}

/// InterlockedPushEntrySList na cabeça do consumidor: o SlistEntry recebe a
/// cabeça anterior e a cabeça passa a ele. Devolve a cabeça anterior.
fn push(consumer: &Consumer, entry: u64) -> Result<u64, u32> {
    let fault = |_| STATUS_ACCESS_VIOLATION;
    loop {
        if consumer.wow64 {
            let old = guest::try_read32(consumer.list_head).map_err(fault)?;
            guest::try_write32(entry, old).map_err(fault)?;
            if guest::compare_exchange32(consumer.list_head, old, entry as u32).map_err(fault)? == old {
                return Ok(old as u64);
            }
        } else {
            let old = guest::try_read64(consumer.list_head).map_err(fault)?;
            guest::try_write64(entry, old).map_err(fault)?;
            if guest::compare_exchange64(consumer.list_head, old, entry).map_err(fault)? == old {
                return Ok(old);
            }
        }
    }
}

/// EtwpFindUserBufferSpace: a primeira faixa livre de páginas do bitmap do
/// consumidor (RtlFindNextAlignedForwardRunClear e
/// RtlInterlockedSetClearRun) ou páginas novas do processo.
fn find_space(consumer: &Consumer, length: u32) -> Result<u64, u32> {
    let pages = (length as u64).div_ceil(PAGE) as u32;
    if let Some(index) = find_clear_run(consumer.bitmap, consumer.pages, pages) {
        if set_run(consumer.bitmap, index, pages) {
            return Ok(consumer.space + index as u64 * PAGE);
        }
    }
    allocate_pages(pages)
}

/// EtwpFreeUserBufferSpace: as páginas do espaço reservado voltam ao
/// bitmap; as alocadas à parte, ao processo.
fn free_space(consumer: &Consumer, address: u64, length: u32) {
    let pages = (length as u64).div_ceil(PAGE) as u32;
    if address >= consumer.space && address < consumer.space + consumer.space_size as u64 {
        clear_run(consumer.bitmap, ((address - consumer.space) / PAGE) as u32, pages);
        return;
    }
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return;
    }
    guest::write64(cells, address);
    guest::write64(cells + 8, 0);
    let _ = crate::ntos::mm::virtual_memory_services::free(CURRENT_PROCESS, cells, cells + 8, MEM_RELEASE);
    guest::free_bytes(cells);
}

/// Páginas novas no processo anexado (ZwAllocateVirtualMemory).
fn allocate_pages(pages: u32) -> Result<u64, u32> {
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(cells, 0);
    guest::write64(cells + 8, pages as u64 * PAGE);
    let status = crate::ntos::mm::virtual_memory_services::allocate(CURRENT_PROCESS, cells, 0, cells + 8, MEM_COMMIT_RESERVE, PAGE_READWRITE).map_or(STATUS_INSUFFICIENT_RESOURCES, |status| status);
    let base = guest::read64(cells);
    guest::free_bytes(cells);
    if status & 0x8000_0000 != 0 || base == 0 {
        return Err(if status & 0x8000_0000 != 0 { status } else { STATUS_INSUFFICIENT_RESOURCES });
    }
    Ok(base)
}

/// A primeira faixa de `run` bits limpos do bitmap de `size` bits (a busca
/// do RtlFindNextAlignedForwardRunClear, a partir do bit 0).
fn find_clear_run(bitmap: u64, size: u32, run: u32) -> Option<u32> {
    if run == 0 || run > size {
        return None;
    }
    let (mut start, mut length) = (0u32, 0u32);
    let mut cached: Option<(u32, u32)> = None;
    for index in 0..size {
        let word_index = index / 32;
        let word = match cached {
            Some((cached_index, value)) if cached_index == word_index => value,
            _ => {
                let value = guest::try_read32(bitmap + word_index as u64 * 4).ok()?;
                cached = Some((word_index, value));
                value
            }
        };
        if word & (1 << (index % 32)) == 0 {
            if length == 0 {
                start = index;
            }
            length += 1;
            if length == run {
                return Some(start);
            }
        } else {
            length = 0;
        }
    }
    None
}

/// As palavras do bitmap tocadas pela faixa: (endereço, máscara).
fn run_words(bitmap: u64, start: u32, run: u32) -> alloc::vec::Vec<(u64, u32)> {
    let mut words = alloc::vec::Vec::new();
    let end = start + run;
    let mut index = start;
    while index < end {
        let word_index = index / 32;
        let first = index % 32;
        let last = (end - word_index * 32).min(32);
        let mask = if last - first == 32 { u32::MAX } else { ((1u32 << (last - first)) - 1) << first };
        words.push((bitmap + word_index as u64 * 4, mask));
        index = (word_index + 1) * 32;
    }
    words
}

/// RtlInterlockedSetClearRun: liga a faixa se ela ainda está toda limpa
/// (FALSE, sem mudar nada, se outro a pegou antes).
fn set_run(bitmap: u64, start: u32, run: u32) -> bool {
    let words = run_words(bitmap, start, run);
    for (done, &(address, mask)) in words.iter().enumerate() {
        let claimed = loop {
            let Ok(old) = guest::try_read32(address) else { break false };
            if old & mask != 0 {
                break false;
            }
            match guest::compare_exchange32(address, old, old | mask) {
                Ok(previous) if previous == old => break true,
                Ok(_) => continue,
                Err(_) => break false,
            }
        };
        if !claimed {
            for &(address, mask) in &words[..done] {
                clear_word(address, mask);
            }
            return false;
        }
    }
    true
}

/// RtlInterlockedClearBitRun.
fn clear_run(bitmap: u64, start: u32, run: u32) {
    for (address, mask) in run_words(bitmap, start, run) {
        clear_word(address, mask);
    }
}

fn clear_word(address: u64, mask: u32) {
    loop {
        let Ok(old) = guest::try_read32(address) else { return };
        match guest::compare_exchange32(address, old, old & !mask) {
            Ok(previous) if previous == old => return,
            Ok(_) => continue,
            Err(_) => return,
        }
    }
}

/// Consumidores vivos (autotestes e diagnóstico).
pub fn live_consumers() -> usize {
    CONSUMERS.lock().len()
}
