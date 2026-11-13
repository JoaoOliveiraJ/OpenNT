//! Sessões de log ETW e o NtTraceControl — o logger do NT.
//!
//! Cada sessão (WMI_LOGGER_INFORMATION, 0xB0 bytes) tem um LoggerId de 1 a
//! MaxLoggers-1 e uma sessão interna de `provider_state`, cujo consumidor conta
//! os eventos entregues pelos provedores habilitados para ela. O despacho do
//! NtTraceControl segue o ntoskrnl 19041: captura dos buffers, validação do
//! WMI_LOGGER_INFORMATION (tamanho, WNODE_FLAG_TRACED_GUID) e a busca da sessão
//! pelo GUID do logger do kernel, pelo nome ou pelo LoggerId.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use super::provider_state;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

/// EtwpMaxLoggers padrão.
pub const MAX_LOGGERS: u32 = 64;
/// sizeof(WMI_LOGGER_INFORMATION).
pub const INFORMATION_SIZE: usize = 0xB0;
/// {9E814AAD-3204-11D2-9A82-006008A86939}: o logger do kernel.
const SYSTEM_TRACE_CONTROL_GUID: [u8; 16] = [0xAD, 0x4A, 0x81, 0x9E, 0x04, 0x32, 0xD2, 0x11, 0x9A, 0x82, 0x00, 0x60, 0x08, 0xA8, 0x69, 0x39];
const KERNEL_LOGGER_NAME: &str = "NT Kernel Logger";
const WNODE_FLAG_TRACED_GUID: u32 = 0x2_0000;
const EVENT_TRACE_FILE_MODE_NEWFILE: u32 = 0x8;
const EVENT_TRACE_REAL_TIME_MODE: u32 = 0x100;

pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
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
    events: Arc<AtomicU32>,
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
    put32(buffer, info::NUMBER_OF_BUFFERS, logger.minimum_buffers);
    put32(buffer, info::FREE_BUFFERS, logger.minimum_buffers);
    put32(buffer, info::EVENTS_LOST, 0);
    let events = logger.events.load(Ordering::Relaxed);
    let per_buffer = (logger.buffer_size.max(1) * 1024 / 0x80).max(1);
    put32(buffer, info::BUFFERS_WRITTEN, events.div_ceil(per_buffer));
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
    let events = Arc::new(AtomicU32::new(0));
    let counter = events.clone();
    let consumer: provider_state::Consumer = Arc::new(move |_event| {
        counter.fetch_add(1, Ordering::Relaxed);
    });
    let session = provider_state::open_session(consumer, None, Some(guid(buffer))).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let logger = Logger {
        id,
        name,
        guid: guid(buffer),
        clock: match get32(buffer, info::CLIENT_CONTEXT) {
            0 => 1,
            clock => clock,
        },
        buffer_size,
        minimum_buffers,
        maximum_buffers,
        maximum_file_size: get32(buffer, info::MAXIMUM_FILE_SIZE),
        log_file_mode: get32(buffer, info::LOG_FILE_MODE),
        flush_timer: get32(buffer, info::FLUSH_TIMER),
        enable_flags: get32(buffer, info::ENABLE_FLAGS),
        age_limit: get32(buffer, info::AGE_LIMIT),
        log_file_name,
        session,
        events,
    };
    fill(buffer, &logger);
    let mut loggers = LOGGERS.lock();
    if loggers.contains_key(&id) {
        drop(loggers);
        let _ = provider_state::close_session(session);
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    loggers.insert(id, logger);
    Ok(())
}

/// Stop: as propriedades finais e a sessão encerrada.
fn stop(buffer: &mut [u8]) -> Result<(), u32> {
    let logger = {
        let mut loggers = LOGGERS.lock();
        let id = find(&loggers, buffer)?;
        loggers.remove(&id).unwrap()
    };
    fill(buffer, &logger);
    let _ = provider_state::close_session(logger.session);
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

/// NtTraceControl/ZwTraceControl: `mode` é o modo anterior do chamador.
pub fn trace_control(code: u32, input: u64, input_length: u32, output: u64, output_length: u32, return_length: u64, mode: u8) -> Result<u32, KernelError> {
    let code = if mode != 0 { code & 0x7FFF_FFFF } else { code };
    if mode != 0 {
        let limit = crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT;
        if input != 0 && input_length != 0 && (input + input_length as u64 > limit || input + (input_length as u64) < input) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if output != 0 && output_length != 0 && output + output_length as u64 > limit {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        if return_length == 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
    }
    let (input_length, output_length) = (if input == 0 { 0 } else { input_length }, if output == 0 { 0 } else { output_length });
    // A cópia de trabalho tem o maior dos dois tamanhos, zerada.
    let mut buffer = alloc::vec![0u8; input_length.max(output_length) as usize];
    if input_length != 0 {
        match guest::try_read_bytes(input, input_length as usize) {
            Ok(bytes) => buffer[..bytes.len()].copy_from_slice(&bytes),
            Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
        }
    }
    let result: Result<u32, u32> = match code {
        1..=7 => (|| {
            if (input_length as usize) < INFORMATION_SIZE || (output_length as usize) < INFORMATION_SIZE {
                return Err(STATUS_INVALID_BUFFER_SIZE);
            }
            validate(&buffer)?;
            if get32(&buffer, info::BUFFER_SIZE_WNODE) > input_length {
                return Err(STATUS_INVALID_BUFFER_SIZE);
            }
            match code {
                1 => start(&mut buffer)?,
                2 => stop(&mut buffer)?,
                3 | 5 => with_logger(&mut buffer, |_, _| Ok(()))?,
                4 => update(&mut buffer)?,
                6 => with_logger(&mut buffer, |logger, _| if logger.log_file_mode & EVENT_TRACE_FILE_MODE_NEWFILE != 0 { Ok(()) } else { Err(STATUS_INVALID_PARAMETER) })?,
                _ => with_logger(&mut buffer, |logger, _| {
                    logger.log_file_mode |= EVENT_TRACE_REAL_TIME_MODE;
                    Ok(())
                })?,
            }
            Ok(INFORMATION_SIZE as u32)
        })(),
        // MaxLoggers da silo e os contadores PMC do ETW (nenhum sem PMC na HAL).
        42 | 43 => {
            if output_length < 4 {
                Err(STATUS_INVALID_PARAMETER)
            } else {
                put32(&mut buffer, 0, if code == 42 { MAX_LOGGERS } else { 0 });
                Ok(4)
            }
        }
        _ => Err(STATUS_INVALID_DEVICE_REQUEST),
    };
    match result {
        Ok(length) => {
            if length != 0 && guest::try_write_bytes(output, &buffer[..length as usize]).is_err() {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            if guest::try_write32(return_length, length).is_err() {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            Ok(0)
        }
        Err(status) => Ok(status),
    }
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

/// Quantas sessões estão ativas (autotestes).
pub fn active_sessions() -> usize {
    LOGGERS.lock().len()
}
