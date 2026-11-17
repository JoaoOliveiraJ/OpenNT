//! Sessões de log ETW e o NtTraceControl — o logger do NT.
//!
//! Cada sessão (WMI_LOGGER_INFORMATION, 0xB0 bytes) tem um LoggerId de 1 a
//! MaxLoggers-1, uma sessão interna de `provider_state` e os seus buffers:
//! `MinimumBuffers` blocos de `BufferSize` KB do pool, cada um com um
//! WMI_BUFFER_HEADER (0x48 bytes) seguido dos registros. Cada evento aceito
//! pela sessão vira um registro EVENT_HEADER (HeaderType 0xC013, o
//! EventMarker de 64 bits do WMI_LOGGER_CONTEXT) com os itens estendidos e
//! os dados do usuário, alinhado a 8. Um buffer cheio passa a Flush
//! (BuffersWritten) e o seguinte livre recebe os eventos; sem buffer livre,
//! o modo circular (EVENT_TRACE_FILE_MODE_CIRCULAR ou
//! EVENT_TRACE_BUFFERING_MODE) recicla o mais antigo e os outros contam
//! EventsLost. Sem arquivo nem consumidor de tempo real, os buffers ficam
//! na memória até o Stop.
//!
//! O despacho do NtTraceControl segue o ntoskrnl 19041 (rva 0x5eaf60): o
//! bit alto do código em UserMode marca o chamador WoW64; as sondas da
//! entrada (faixa abaixo de MM_USER_PROBE_ADDRESS), da saída (ProbeForWrite)
//! e do ReturnLength obrigatório; a cópia de trabalho com o maior dos dois
//! tamanhos (os códigos 12, 14 e 27 usam os buffers do chamador direto); a
//! validação de tamanhos de cada código; e a cópia de volta e o
//! ReturnLength só em sucesso, exceto STATUS_BUFFER_TOO_SMALL dos códigos
//! 15, 16, 21 e 22 e os códigos 19, 23, 32-34, 36 e 38-40, que sempre o
//! devolvem.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{activity, provider_state, user_registration};
use crate::ntos::inc::types::{EtwBufferState, EventHeader, NtStruct, WmiBufferHeader};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::rtl::{KernelError, SpinLock};

/// EtwpMaxLoggers padrão.
pub const MAX_LOGGERS: u32 = 64;
/// sizeof(WMI_LOGGER_INFORMATION).
pub const INFORMATION_SIZE: usize = 0xB0;
/// {9E814AAD-3204-11D2-9A82-006008A86939}: o logger do kernel.
const SYSTEM_TRACE_CONTROL_GUID: [u8; 16] = [0xAD, 0x4A, 0x81, 0x9E, 0x04, 0x32, 0xD2, 0x11, 0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39];
const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const WNODE_FLAG_TRACED_GUID: u32 = 0x2_0000;
const EVENT_TRACE_FILE_MODE_CIRCULAR: u32 = 0x2;
const EVENT_TRACE_FILE_MODE_NEWFILE: u32 = 0x8;
const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x100;
const EVENT_TRACE_BUFFERING_MODE: u32 = 0x400;
/// WMI_LOGGER_CONTEXT.EventMarker[0]: o HeaderType de um EVENT_HEADER de 64 bits.
const EVENT_HEADER_MARKER: u16 = 0xC013;
/// EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID.
const EXT_TYPE_RELATED_ACTIVITYID: u16 = 1;
/// Tag dos buffers de sessão ('EtwB').
const BUFFER_TAG: u32 = 0x4277_7445;
const BUFFER_HEADER_SIZE: u32 = core::mem::size_of::<WmiBufferHeader>() as u32;

pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_INVALID_BUFFER_SIZE: u32 = 0xC000_0206;
pub const STATUS_WMI_INSTANCE_NOT_FOUND: u32 = 0xC000_0296;
pub const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

/// Offsets do WMI_LOGGER_INFORMATION (WNODE_HEADER nos primeiros 0x30).
mod info {
    pub const BUFFER_SIZE_WNODE: usize = 0x00;
    pub const HISTORICAL_CONTEXT: usize = 0x08;
    pub const GUID: usize = 0x18;
    pub const CLIENT_CONTEXT: usize = 0x28;
    pub const FLAGS: usize = 0x2C;
    pub const BUFFER_SIZE: usize = 0x30;
    pub const MINIMUM_BUFFERS: usize = 0x34;
    pub const MAXIMUM_BUFFERS: usize = 0x38;
    pub const MAXIMUM_FILE_SIZE: usize = 0x3C;
    pub const LOG_FILE_MODE: usize = 0x40;
    pub const FLUSH_TIMER: usize = 0x44;
    pub const ENABLE_FLAGS: usize = 0x48;
    pub const AGE_LIMIT: usize = 0x4C;
    pub const NUMBER_OF_BUFFERS: usize = 0x60;
    pub const FREE_BUFFERS: usize = 0x64;
    pub const EVENTS_LOST: usize = 0x68;
    pub const BUFFERS_WRITTEN: usize = 0x6C;
    pub const LOG_BUFFERS_LOST: usize = 0x70;
    pub const REAL_TIME_BUFFERS_LOST: usize = 0x74;
    pub const LOGGER_THREAD_ID: usize = 0x78;
    pub const LOG_FILE_NAME: usize = 0x80;
    pub const LOGGER_NAME: usize = 0x90;
    pub const REAL_TIME_CONSUMER_COUNT: usize = 0xA0;
}

/// Os buffers de uma sessão e os contadores do que passou por eles.
struct Buffers {
    logger_id: u16,
    clock: u32,
    circular: bool,
    size: u32,
    blocks: Vec<u64>,
    /// Buffer que recebe os eventos (None: todos cheios).
    current: Option<usize>,
    /// Ordem em que os buffers encheram (o mais antigo primeiro).
    full: Vec<usize>,
    sequence: i64,
    events: u32,
    events_lost: u32,
    buffers_written: u32,
}

fn header(block: u64) -> &'static WmiBufferHeader {
    // SAFETY: bloco de buffer de sessão do pool (BufferSize bytes).
    unsafe { WmiBufferHeader::at(block) }
}

/// O relógio da sessão (WNODE_HEADER.ClientContext): 1 contador de
/// desempenho, 2 hora do sistema, 3 ciclos.
fn timestamp(clock: u32) -> i64 {
    match clock {
        2 => crate::ntos::ke::clock::system_time_100ns() as i64,
        3 => crate::hal::cpu::rdtsc() as i64,
        _ => crate::ntos::ke::clock::query_performance_counter(0) as i64,
    }
}

impl Buffers {
    fn new(logger_id: u16, clock: u32, circular: bool, size_kb: u32, count: u32) -> Result<Self, u32> {
        let size = size_kb * 1024;
        let mut buffers = Self { logger_id, clock, circular, size, blocks: Vec::new(), current: None, full: Vec::new(), sequence: 0, events: 0, events_lost: 0, buffers_written: 0 };
        for _ in 0..count {
            let block = kernel_pool::allocate(size as u64, AllocateOptions { tag: BUFFER_TAG, zero: true, ..Default::default() }).map_err(|_| STATUS_INSUFFICIENT_RESOURCES);
            match block {
                Ok(block) => buffers.blocks.push(block),
                Err(status) => {
                    buffers.release();
                    return Err(status);
                }
            }
        }
        buffers.activate(0);
        Ok(buffers)
    }

    /// Entrega o buffer `index` ao log: cabeçalho novo e estado GeneralLogging.
    fn activate(&mut self, index: usize) {
        let block = self.blocks[index];
        guest::write_bytes(block, &alloc::vec![0u8; BUFFER_HEADER_SIZE as usize]);
        let header = header(block);
        header.buffer_size.set(self.size);
        header.current_offset.set(BUFFER_HEADER_SIZE);
        header.time_stamp.quad_part.set(timestamp(self.clock));
        self.sequence += 1;
        header.sequence_number.set(self.sequence);
        header.set_clock_type(self.clock as u64);
        header.client_context.processor_number.set(crate::ntos::ke::processor_group::current_processor_number() as u8);
        header.client_context.alignment.set(8);
        header.client_context.logger_id.set(self.logger_id);
        header.state.set(EtwBufferState::ETW_BUFFER_STATE_GENERAL_LOGGING);
        self.current = Some(index);
    }

    /// O buffer corrente encheu: estado Flush, SavedOffset/Offset fixados.
    fn retire(&mut self, index: usize) {
        let header = header(self.blocks[index]);
        let used = header.current_offset.get();
        header.saved_offset.set(used);
        header.offset.set(used);
        header.state.set(EtwBufferState::ETW_BUFFER_STATE_FLUSH);
        self.full.push(index);
        self.buffers_written += 1;
        self.current = None;
    }

    fn next_buffer(&mut self) -> Option<usize> {
        let free = (0..self.blocks.len()).find(|index| !self.full.contains(index) && Some(*index) != self.current);
        let index = match free {
            Some(index) => index,
            None if self.circular && !self.full.is_empty() => self.full.remove(0),
            None => return None,
        };
        self.activate(index);
        Some(index)
    }

    /// Grava o registro do evento (EVENT_HEADER, itens estendidos e dados).
    fn log(&mut self, event: &provider_state::Event) {
        let extended = if event.has_related { 0x18 } else { 0 };
        let data: usize = event.data.iter().map(Vec::len).sum();
        let record = (EventHeader::SIZE as usize + extended + data) as u32;
        let aligned = (record + 7) & !7;
        if aligned > self.size - BUFFER_HEADER_SIZE || record > 0xFFFF {
            self.events_lost += 1;
            return;
        }
        let mut index = self.current;
        if let Some(current) = index {
            if header(self.blocks[current]).current_offset.get() + aligned > self.size {
                self.retire(current);
                index = None;
            }
        }
        let index = match index.or_else(|| self.next_buffer()) {
            Some(index) => index,
            None => {
                self.events_lost += 1;
                return;
            }
        };
        let block = self.blocks[index];
        let buffer_header = header(block);
        let offset = buffer_header.current_offset.get();
        let mut bytes = alloc::vec![0u8; aligned as usize];
        bytes[0..2].copy_from_slice(&(record as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&EVENT_HEADER_MARKER.to_le_bytes());
        let flags = event.flags | if event.has_related { provider_state::header_flags::EXTENDED_INFO } else { 0 };
        bytes[4..6].copy_from_slice(&flags.to_le_bytes());
        bytes[6..8].copy_from_slice(&event.event_property.to_le_bytes());
        bytes[8..12].copy_from_slice(&event.thread_id.to_le_bytes());
        bytes[12..16].copy_from_slice(&event.process_id.to_le_bytes());
        bytes[16..24].copy_from_slice(&timestamp(self.clock).to_le_bytes());
        bytes[24..40].copy_from_slice(&event.provider);
        bytes[40..56].copy_from_slice(&event.descriptor);
        bytes[64..80].copy_from_slice(&event.activity);
        let mut cursor = EventHeader::SIZE as usize;
        if event.has_related {
            // Item estendido no buffer: Size, ExtType, Linkage, DataSize e o GUID.
            bytes[cursor..cursor + 2].copy_from_slice(&0x18u16.to_le_bytes());
            bytes[cursor + 2..cursor + 4].copy_from_slice(&EXT_TYPE_RELATED_ACTIVITYID.to_le_bytes());
            bytes[cursor + 6..cursor + 8].copy_from_slice(&0x10u16.to_le_bytes());
            bytes[cursor + 8..cursor + 24].copy_from_slice(&event.related_activity);
            cursor += 0x18;
        }
        for segment in &event.data {
            bytes[cursor..cursor + segment.len()].copy_from_slice(segment);
            cursor += segment.len();
        }
        guest::write_bytes(block + offset as u64, &bytes);
        buffer_header.current_offset.set(offset + aligned);
        self.events += 1;
    }

    fn free_count(&self) -> u32 {
        (self.blocks.len() - self.full.len() - self.current.is_some() as usize) as u32
    }

    fn release(&mut self) {
        for block in self.blocks.drain(..) {
            let _ = kernel_pool::free(block, None);
        }
        self.current = None;
        self.full.clear();
    }

    /// Os registros gravados, do buffer mais antigo ao corrente.
    fn records(&self) -> Vec<Vec<u8>> {
        let mut order = self.full.clone();
        order.extend(self.current);
        let mut records = Vec::new();
        for index in order {
            let block = self.blocks[index];
            let end = header(block).current_offset.get();
            let mut offset = BUFFER_HEADER_SIZE;
            while offset + EventHeader::SIZE as u32 <= end {
                let size = guest::read::<u16>(block + offset as u64) as u32;
                if size == 0 {
                    break;
                }
                records.push(guest::read_bytes(block + offset as u64, size as usize));
                offset += (size + 7) & !7;
            }
        }
        records
    }
}

struct Logger {
    id: u16,
    name: String,
    guid: [u8; 16],
    clock: u32,
    buffer_size: u32,
    minimum_buffers: u32,
    maximum_buffers: u32,
    maximum_file_size: u32,
    log_file_mode: u32,
    flush_timer: u32,
    enable_flags: u32,
    age_limit: u32,
    log_file_name: String,
    session: u16,
    buffers: Arc<SpinLock<Buffers>>,
}

static LOGGERS: SpinLock<BTreeMap<u16, Logger>> = SpinLock::new(BTreeMap::new());

fn get32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buffer[offset..offset + 4].try_into().unwrap())
}

fn put32(buffer: &mut [u8], offset: usize, value: u32) {
    buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(buffer: &mut [u8], offset: usize, value: u64) {
    buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn guid(buffer: &[u8]) -> [u8; 16] {
    buffer[info::GUID..info::GUID + 16].try_into().unwrap()
}

/// O texto de um UNICODE_STRING do buffer capturado (o Buffer aponta para a
/// memória do chamador).
fn unicode_at(buffer: &[u8], offset: usize) -> Result<String, u32> {
    let length = u16::from_le_bytes([buffer[offset], buffer[offset + 1]]) as u64;
    if length == 0 {
        return Ok(String::new());
    }
    let pointer = u64::from_le_bytes(buffer[offset + 8..offset + 16].try_into().unwrap());
    let mut text = String::new();
    for index in 0..length / 2 {
        let unit = guest::try_read16(pointer + index * 2).map_err(|_| STATUS_ACCESS_VIOLATION)?;
        text.push(char::from_u32(unit as u32).unwrap_or('?'));
    }
    Ok(text)
}

/// EtwpValidateLoggerInfo: Wnode.BufferSize >= 0xB0 e WNODE_FLAG_TRACED_GUID.
fn validate(buffer: &[u8]) -> Result<(), u32> {
    if (get32(buffer, info::BUFFER_SIZE_WNODE) as usize) < INFORMATION_SIZE {
        return Err(STATUS_INVALID_BUFFER_SIZE);
    }
    if get32(buffer, info::FLAGS) & WNODE_FLAG_TRACED_GUID == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// EtwpAcquireLoggerContext: o GUID do logger do kernel, o nome ou o
/// LoggerId (0xFFFF = logger do kernel).
fn find(loggers: &BTreeMap<u16, Logger>, buffer: &[u8]) -> Result<u16, u32> {
    let kernel = || loggers.values().find(|logger| logger.guid == SYSTEM_TRACE_CONTROL_GUID).map(|logger| logger.id).ok_or(STATUS_WMI_INSTANCE_NOT_FOUND);
    if guid(buffer) == SYSTEM_TRACE_CONTROL_GUID {
        return kernel();
    }
    let name = unicode_at(buffer, info::LOGGER_NAME)?;
    if !name.is_empty() {
        return loggers.values().find(|logger| logger.name.eq_ignore_ascii_case(&name)).map(|logger| logger.id).ok_or(STATUS_WMI_INSTANCE_NOT_FOUND);
    }
    let id = u16::from_le_bytes([buffer[info::HISTORICAL_CONTEXT], buffer[info::HISTORICAL_CONTEXT + 1]]);
    if id == 0xFFFF {
        return kernel();
    }
    if id as u32 >= MAX_LOGGERS {
        return Err(STATUS_INVALID_HANDLE);
    }
    if loggers.contains_key(&id) { Ok(id) } else { Err(STATUS_WMI_INSTANCE_NOT_FOUND) }
}

/// EtwpGetLoggerInfoFromContext: as propriedades da sessão no buffer.
fn fill(buffer: &mut [u8], logger: &Logger) {
    put64(buffer, info::HISTORICAL_CONTEXT, logger.id as u64);
    buffer[info::GUID..info::GUID + 16].copy_from_slice(&logger.guid);
    put32(buffer, info::CLIENT_CONTEXT, logger.clock);
    put32(buffer, info::BUFFER_SIZE, logger.buffer_size);
    put32(buffer, info::MINIMUM_BUFFERS, logger.minimum_buffers);
    put32(buffer, info::MAXIMUM_BUFFERS, logger.maximum_buffers);
    put32(buffer, info::MAXIMUM_FILE_SIZE, logger.maximum_file_size);
    put32(buffer, info::LOG_FILE_MODE, logger.log_file_mode);
    put32(buffer, info::FLUSH_TIMER, logger.flush_timer);
    put32(buffer, info::ENABLE_FLAGS, logger.enable_flags);
    put32(buffer, info::AGE_LIMIT, logger.age_limit);
    let buffers = logger.buffers.lock();
    put32(buffer, info::NUMBER_OF_BUFFERS, buffers.blocks.len() as u32);
    put32(buffer, info::FREE_BUFFERS, buffers.free_count());
    put32(buffer, info::EVENTS_LOST, buffers.events_lost);
    put32(buffer, info::BUFFERS_WRITTEN, buffers.buffers_written);
    put32(buffer, info::LOG_BUFFERS_LOST, 0);
    put32(buffer, info::REAL_TIME_BUFFERS_LOST, 0);
    put64(buffer, info::LOGGER_THREAD_ID, 0);
    put32(buffer, info::REAL_TIME_CONSUMER_COUNT, 0);
}

/// EtwpStartTrace.
fn start(buffer: &mut [u8]) -> Result<(), u32> {
    let kernel = guid(buffer) == SYSTEM_TRACE_CONTROL_GUID;
    let mut name = unicode_at(buffer, info::LOGGER_NAME)?;
    if kernel && name.is_empty() {
        name = String::from(KERNEL_LOGGER_NAME);
    }
    if name.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let log_file_name = unicode_at(buffer, info::LOG_FILE_NAME)?;
    let processors = crate::ntos::ke::smp::online_cpu_count().max(1) as u32;
    let buffer_size = match get32(buffer, info::BUFFER_SIZE) {
        0 => 64,
        size => size.clamp(4, 1024),
    };
    let minimum_buffers = get32(buffer, info::MINIMUM_BUFFERS).max(2 * processors);
    let maximum_buffers = get32(buffer, info::MAXIMUM_BUFFERS).max(minimum_buffers);
    let id = {
        let loggers = LOGGERS.lock();
        if loggers.values().any(|logger| logger.name.eq_ignore_ascii_case(&name) || (kernel && logger.guid == SYSTEM_TRACE_CONTROL_GUID)) {
            return Err(STATUS_OBJECT_NAME_COLLISION);
        }
        (1..MAX_LOGGERS as u16).find(|id| !loggers.contains_key(id)).ok_or(STATUS_INSUFFICIENT_RESOURCES)?
    };
    let clock = match get32(buffer, info::CLIENT_CONTEXT) {
        0 => 1,
        clock => clock,
    };
    let log_file_mode = get32(buffer, info::LOG_FILE_MODE);
    let circular = log_file_mode & (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_BUFFERING_MODE) != 0;
    let buffers = Arc::new(SpinLock::new(Buffers::new(id, clock, circular, buffer_size, minimum_buffers)?));
    let sink = buffers.clone();
    let consumer: provider_state::Consumer = Arc::new(move |event| sink.lock().log(event));
    let session = match provider_state::open_session(consumer, None, Some(guid(buffer))) {
        Ok(session) => session,
        Err(_) => {
            buffers.lock().release();
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
    };
    let logger = Logger {
        id,
        name,
        guid: guid(buffer),
        clock,
        buffer_size,
        minimum_buffers,
        maximum_buffers,
        maximum_file_size: get32(buffer, info::MAXIMUM_FILE_SIZE),
        log_file_mode,
        flush_timer: get32(buffer, info::FLUSH_TIMER),
        enable_flags: get32(buffer, info::ENABLE_FLAGS),
        age_limit: get32(buffer, info::AGE_LIMIT),
        log_file_name,
        session,
        buffers,
    };
    fill(buffer, &logger);
    let mut loggers = LOGGERS.lock();
    if loggers.contains_key(&id) {
        drop(loggers);
        let _ = provider_state::close_session(session);
        logger.buffers.lock().release();
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    loggers.insert(id, logger);
    Ok(())
}

/// Stop: os provedores desabilitados, o buffer corrente fechado, as
/// propriedades finais e os buffers devolvidos.
fn stop(buffer: &mut [u8]) -> Result<(), u32> {
    let logger = {
        let mut loggers = LOGGERS.lock();
        let id = find(&loggers, buffer)?;
        loggers.remove(&id).unwrap()
    };
    let _ = provider_state::close_session(logger.session);
    {
        let mut buffers = logger.buffers.lock();
        if let Some(current) = buffers.current {
            if header(buffers.blocks[current]).current_offset.get() > BUFFER_HEADER_SIZE {
                buffers.retire(current);
            }
        }
    }
    fill(buffer, &logger);
    logger.buffers.lock().release();
    Ok(())
}

fn with_logger(buffer: &mut [u8], change: impl FnOnce(&mut Logger, &[u8]) -> Result<(), u32>) -> Result<(), u32> {
    let mut loggers = LOGGERS.lock();
    let id = find(&loggers, buffer)?;
    let logger = loggers.get_mut(&id).unwrap();
    let input = buffer.to_vec();
    change(logger, &input)?;
    fill(buffer, logger);
    Ok(())
}

/// Update: FlushTimer, EnableFlags, mais buffers, o arquivo e o modo de tempo real.
fn update(buffer: &mut [u8]) -> Result<(), u32> {
    let file_name = unicode_at(buffer, info::LOG_FILE_NAME)?;
    with_logger(buffer, |logger, input| {
        let flush_timer = get32(input, info::FLUSH_TIMER);
        if flush_timer != 0 {
            logger.flush_timer = flush_timer;
        }
        logger.enable_flags = get32(input, info::ENABLE_FLAGS);
        logger.maximum_buffers = logger.maximum_buffers.max(get32(input, info::MAXIMUM_BUFFERS));
        logger.log_file_mode = (logger.log_file_mode & !EVENT_TRACE_REAL_TIME_MODE) | (get32(input, info::LOG_FILE_MODE) & EVENT_TRACE_REAL_TIME_MODE);
        if !file_name.is_empty() {
            logger.log_file_name = file_name;
        }
        Ok(())
    })
}

/// Flush: o buffer corrente com eventos passa a Flush e o próximo assume.
fn flush(buffer: &mut [u8]) -> Result<(), u32> {
    with_logger(buffer, |logger, _| {
        let mut buffers = logger.buffers.lock();
        if let Some(current) = buffers.current {
            if header(buffers.blocks[current]).current_offset.get() > BUFFER_HEADER_SIZE {
                buffers.retire(current);
                buffers.next_buffer();
            }
        }
        Ok(())
    })
}

/// A operação de um código do NtTraceControl sobre a cópia de trabalho:
/// Ok(ReturnLength) ou (status, ReturnLength).
type Outcome = Result<u32, (u32, u32)>;

fn status_only(status: u32) -> Outcome {
    if status & 0x8000_0000 == 0 { Ok(0) } else { Err((status, 0)) }
}

/// Códigos 1-7: EtwpValidateUserModeLoggerInfo e a operação da sessão.
fn logger_control(code: u32, buffer: &mut [u8], input_length: u32, output_length: u32) -> Outcome {
    let mut run = || -> Result<(), u32> {
        if (input_length as usize) < INFORMATION_SIZE || (output_length as usize) < INFORMATION_SIZE {
            return Err(STATUS_INVALID_BUFFER_SIZE);
        }
        validate(buffer)?;
        if get32(buffer, info::BUFFER_SIZE_WNODE) > input_length {
            return Err(STATUS_INVALID_BUFFER_SIZE);
        }
        match code {
            1 => start(buffer),
            2 => stop(buffer),
            3 => with_logger(buffer, |_, _| Ok(())),
            4 => update(buffer),
            5 => flush(buffer),
            6 => with_logger(buffer, |logger, _| if logger.log_file_mode & EVENT_TRACE_FILE_MODE_NEWFILE != 0 { Ok(()) } else { Err(STATUS_INVALID_PARAMETER) }),
            _ => with_logger(buffer, |logger, _| {
                logger.log_file_mode |= EVENT_TRACE_REAL_TIME_MODE;
                Ok(())
            }),
        }
    };
    run().map(|()| INFORMATION_SIZE as u32).map_err(|status| (status, INFORMATION_SIZE as u32))
}

/// O SecurityProviderPID do ETW_SILODRIVERSTATE do silo hospedeiro: o
/// processo do provedor de eventos de segurança (o lsass.exe).
static SECURITY_PROVIDER_PID: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// EtwpRegisterSecurityProvider (rva 0x7d50a0), o código 24 do
/// NtTraceControl (o EtwRegisterSecurityProvider da ntdll, que o
/// AdtpInitializeAuditingCommon do lsasrv chama): o primeiro processo fica
/// como provedor de segurança; um segundo registro dá STATUS_ACCESS_DENIED.
fn register_security_provider() -> u32 {
    let pid = crate::ntos::ps::process::get_current_process_id();
    match SECURITY_PROVIDER_PID.compare_exchange(0, pid, core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire) {
        Ok(_) => 0,
        Err(_) => STATUS_ACCESS_DENIED,
    }
}

/// O processo registrado como provedor de eventos de segurança (0 sem
/// registro).
pub fn security_provider_pid() -> u64 {
    SECURITY_PROVIDER_PID.load(core::sync::atomic::Ordering::Acquire)
}

/// NtTraceControl/ZwTraceControl: `mode` é o modo anterior do chamador.
pub fn trace_control(code: u32, input: u64, input_length: u32, output: u64, output_length: u32, return_length: u64, mode: u8) -> Result<u32, KernelError> {
    let user = mode != 0;
    let wow64 = user && code & 0x8000_0000 != 0;
    let code = if user { code & 0x7FFF_FFFF } else { code };
    let (input_length, output_length) = (if input == 0 { 0 } else { input_length }, if output == 0 { 0 } else { output_length });
    if user {
        let limit = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
        let end = input.wrapping_add(input_length as u64);
        if input_length != 0 && (end > limit || end < input) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if output_length != 0 && !crate::ntos::ps::user::state::probe_user_write(output, output_length as u64) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if return_length == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if !crate::ntos::ps::user::state::probe_user_write(return_length.min(limit), 4) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    // 12 (EtwActivityIdCreate), 14 (EtwRealtimeDisconnect) e 27
    // (EtwAddNotificationEvent) usam os buffers do chamador; os outros, a
    // cópia de trabalho zerada com o maior dos dois tamanhos.
    let direct = matches!(code, 12 | 14 | 27);
    let mut buffer = alloc::vec![0u8; if direct { 0 } else { input_length.max(output_length) as usize }];
    if !direct && input_length != 0 {
        match guest::try_read_bytes(input, input_length as usize) {
            Ok(bytes) => buffer[..bytes.len()].copy_from_slice(&bytes),
            Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
        }
    }
    let invalid: Outcome = Err((STATUS_INVALID_PARAMETER, 0));
    let unsupported: Outcome = Err((STATUS_INVALID_DEVICE_REQUEST, 0));
    let result: Outcome = match code {
        1..=7 => logger_control(code, &mut buffer, input_length, output_length),
        // EtwRealtimeConnect: nenhuma sessão entrega em tempo real.
        11 if input_length != 0x60 || output_length != 0x60 => invalid,
        12 if output_length != 0x10 => invalid,
        12 => match activity::create_id(output) {
            Ok(()) => Ok(0),
            Err(_) => Err((STATUS_ACCESS_VIOLATION, 0)),
        },
        // WDI e o desligamento de consumidores de tempo real.
        13 if input_length != 0x30 || output_length != 0 => invalid,
        14 if input_length != 8 || output_length != 0 => invalid,
        15 if input_length != 0xA0 || !(0xA0..=0x1_0000).contains(&output_length) => invalid,
        15 => user_registration::register_guid(&mut buffer, output_length, wow64),
        16 if input_length != 0 || !(0x48..=0x1_0000).contains(&output_length) => invalid,
        16 => user_registration::receive_notification(&mut buffer, output_length, wow64),
        17 if input_length < 0x48 || output_length != 0x48 || get32(&buffer, 4) != input_length => invalid,
        17 if get32(&buffer, 0) == 3 && input_length < 0x78 => invalid,
        18 if input_length < 0x48 || get32(&buffer, 4) != input_length => invalid,
        19 if input_length != 8 => invalid,
        20 if input_length != 0 || output_length != 0 => invalid,
        22 if input_length != 0x10 => invalid,
        24 if input_length != 0 || output_length != 0 => invalid,
        24 => status_only(register_security_provider()),
        25 if input_length != 4 || output_length != 0x10 => invalid,
        26 if input_length != 8 => invalid,
        26 => status_only(user_registration::track_provider_binary(u64::from_le_bytes(buffer[0..8].try_into().unwrap()), mode)?),
        27 if input_length != 4 => invalid,
        27 => match guest::try_read::<u32>(input) {
            Err(_) => Err((STATUS_ACCESS_VIOLATION, 0)),
            Ok(0) => invalid,
            Ok(handle) => status_only(user_registration::add_notification_event(handle as u64, wow64, mode)?),
        },
        28 if input_length < 8 || get32(&buffer, 4) as u64 * 16 + 8 != input_length as u64 => invalid,
        30 if input_length != 0x18 || !(0x78..=0x1_0000).contains(&output_length) => invalid,
        30 => user_registration::set_traits(&buffer, mode),
        31 if input_length != 0x10 || output_length != 0 => invalid,
        31 => status_only(user_registration::use_descriptor_type(u64::from_le_bytes(buffer[0..8].try_into().unwrap()), buffer[8], mode)?),
        33 if input_length != 0x10 => invalid,
        34 if input_length != 8 => invalid,
        35 if input_length != 0x10 || output_length != 0 => invalid,
        36 if input_length != 8 || output_length != 0x10 => invalid,
        37 if input_length < 0xC => invalid,
        38 if input_length < 8 || input_length % 8 != 0 || output_length < 2 => invalid,
        39 if input_length < 2 || output_length < 8 => invalid,
        40 if input_length < 8 || output_length < 2 => invalid,
        41 if input_length < 8 => invalid,
        // MaxLoggers da silo e os contadores PMC do ETW (nenhum sem PMC na HAL).
        42 | 43 if output_length < 4 => invalid,
        42 | 43 => {
            put32(&mut buffer, 0, if code == 42 { MAX_LOGGERS } else { 0 });
            Ok(4)
        }
        // 8-10 e 29 não existem; os demais pedem consumidores de tempo
        // real, WDI, respostas a notificações, listas e compressão que
        // nenhuma sessão daqui oferece.
        _ => unsupported,
    };
    let (status, length) = match result {
        Ok(length) => (0, length),
        Err((status, length)) => (status, length),
    };
    let write_length = |length: u32| guest::try_write32(return_length, length).is_ok();
    if status & 0x8000_0000 == 0 {
        if length != 0 && guest::try_write_bytes(output, &buffer[..length as usize]).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if !write_length(length) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let always = matches!(code, 19 | 23 | 32 | 33 | 34 | 36 | 38 | 39 | 40);
    if (status == STATUS_BUFFER_TOO_SMALL && matches!(code, 15 | 16 | 21 | 22)) || always {
        if !write_length(length) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    Ok(status)
}

/// EtwEnableTrace: habilita (1), desabilita (0) ou pede captura de estado
/// (2) do provedor na sessão do LoggerId; nível 0 vale todos e o
/// EVENT_ENABLE_PROPERTY_IGNORE_KEYWORD_0 (0x10) tira a keyword zero.
#[allow(clippy::too_many_arguments)]
pub fn enable_trace(provider: u64, _source: u64, logger_id: u16, control_code: u32, level: u8, any_keyword: u64, all_keyword: u64, property: u32) -> Result<u32, KernelError> {
    if provider == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Some(session) = LOGGERS.lock().get(&logger_id).map(|logger| logger.session) else { return Ok(STATUS_WMI_INSTANCE_NOT_FOUND) };
    match control_code {
        0 => provider_state::disable(session, provider)?,
        1 => provider_state::enable(session, provider, provider_state::EnableOptions { level, any_keyword, all_keyword, include_keyword_zero: property & 0x10 == 0 })?,
        2 => provider_state::capture_state(session, provider)?,
        _ => return Ok(STATUS_INVALID_PARAMETER),
    }
    Ok(0)
}

/// Habilita um provedor (16 bytes do GUID) na sessão do LoggerId, como o
/// EtwEnableTrace com nível e keywords.
pub fn enable_provider(logger_id: u16, provider: [u8; 16], level: u8, any_keyword: u64) -> Result<u32, KernelError> {
    let Some(session) = LOGGERS.lock().get(&logger_id).map(|logger| logger.session) else { return Ok(STATUS_WMI_INSTANCE_NOT_FOUND) };
    provider_state::enable_identifier(session, provider, provider_state::EnableOptions { level, any_keyword, ..Default::default() })?;
    Ok(0)
}

/// Quantas sessões estão ativas (autotestes).
pub fn active_sessions() -> usize {
    LOGGERS.lock().len()
}

/// Os registros EVENT_HEADER gravados nos buffers da sessão, em ordem.
pub fn records(logger_id: u16) -> Option<Vec<Vec<u8>>> {
    let buffers = LOGGERS.lock().get(&logger_id).map(|logger| logger.buffers.clone())?;
    let records = buffers.lock().records();
    Some(records)
}

/// (eventos gravados, perdidos, buffers escritos) da sessão.
pub fn counters(logger_id: u16) -> Option<(u32, u32, u32)> {
    let buffers = LOGGERS.lock().get(&logger_id).map(|logger| logger.buffers.clone())?;
    let buffers = buffers.lock();
    Some((buffers.events, buffers.events_lost, buffers.buffers_written))
}

/// EVENT_TRACE_BUFFER_INTERFACE_MODE: a sessão aceita buffers prontos.
const EVENT_TRACE_BUFFER_INTERFACE_MODE: u32 = 0x4_0000;
/// WMI_BUFFER_HEADER.BufferType do buffer entregue pelo EtwSendTraceBuffer.
const SENT_BUFFER_TYPE: u16 = 5;
/// BufferFlag que preserva o ClientContext.Alignment.
const BUFFER_FLAG_KEEP_ALIGNMENT: u16 = 0x20;

/// EtwSendTraceBuffer(LoggerId, Buffer, EventsLost, StartTime,
/// StartPerfClock), ntoskrnl 19041: entrega um buffer pronto
/// (WMI_BUFFER_HEADER) a uma sessão em EVENT_TRACE_BUFFER_INTERFACE_MODE.
/// LoggerId fora de MaxLoggers ou sessão sem esse modo dá
/// STATUS_INVALID_HANDLE; sem a sessão, STATUS_WMI_INSTANCE_NOT_FOUND. O
/// cabeçalho é preparado como no NT (SavedOffset = Offset, CurrentOffset =
/// Offset + BufferSize, estado ETW_BUFFER_STATE_FLUSH, tipo 5, a hora de
/// referência e o TimeStamp do relógio da sessão) e os EventsLost somam no
/// contador da sessão. A sessão do OpenNT não grava arquivo: o buffer conta
/// como escrito na hora (BuffersWritten), sem ficar retido.
pub fn send_trace_buffer(logger_id: u16, buffer: u64, events_lost: u32, start_time: u64, start_perf_clock: u64) -> u32 {
    if logger_id as u32 >= MAX_LOGGERS {
        return STATUS_INVALID_HANDLE;
    }
    let (mode, buffers) = {
        let loggers = LOGGERS.lock();
        let Some(logger) = loggers.get(&logger_id) else { return STATUS_WMI_INSTANCE_NOT_FOUND };
        (logger.log_file_mode, logger.buffers.clone())
    };
    if mode & EVENT_TRACE_BUFFER_INTERFACE_MODE == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let mut buffers = buffers.lock();
    buffers.events_lost = buffers.events_lost.wrapping_add(events_lost);
    let header = header(buffer);
    let offset = header.offset.get();
    header.saved_offset.set(offset);
    header.current_offset.set(offset.wrapping_add(header.buffer_size.get()));
    header.state.set(EtwBufferState::ETW_BUFFER_STATE_FLUSH);
    header.buffer_type.set(SENT_BUFFER_TYPE);
    if header.buffer_flag.get() & BUFFER_FLAG_KEEP_ALIGNMENT == 0 {
        header.client_context.alignment.set(0);
    }
    header.reference_time.start_perf_clock.quad_part.set(start_perf_clock as i64);
    header.reference_time.start_time.quad_part.set(start_time as i64);
    header.time_stamp.quad_part.set(timestamp(buffers.clock));
    buffers.buffers_written = buffers.buffers_written.wrapping_add(1);
    0
}
