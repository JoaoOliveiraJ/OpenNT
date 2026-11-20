//! Consumidores de tempo real do ETW (`etw/realtime.rs`, a thread do logger
//! em `etw/logger.rs`):
//!
//! - uma sessão de tempo real de um fluxo só tem thread do logger
//!   (LoggerThreadId) e nenhum consumidor;
//! - o NtTraceControl 11 passa as faixas do consumidor pelo ProbeForWrite
//!   mesmo com chamador de kernel (ponteiros de kernel dão
//!   STATUS_ACCESS_VIOLATION) e recusa um LoggerId sem sessão;
//! - um buffer fechado antes de haver consumidor fica guardado e vai ao
//!   consumidor quando ele conecta: os bytes na primeira página livre do
//!   espaço reservado (o bit dela ligado no bitmap), o SlistEntry na
//!   cabeça da lista, o contador em 1 e o evento de dados sinalizado, com o
//!   processador 0, o LoggerId e o registro EVENT_HEADER do evento;
//! - depois de o consumidor devolver o buffer (como o sechost: lista vazia,
//!   contador em 0, bit limpo), o flush seguinte entrega o próximo buffer
//!   na mesma página, sem marcador vazio (um fluxo só);
//! - o NtTraceControl 14 desliga o consumidor: a thread do logger sinaliza o
//!   evento de desligamento, a sessão fica sem consumidor e um segundo
//!   pedido dá STATUS_ALREADY_DISCONNECTED; fechar o handle apaga o
//!   EtwConsumer.

use alloc::vec::Vec;

use super::phase6::call_export;
use crate::ntos::etw::{logger, realtime};
use crate::ntos::inc::types::{EventHeader, NtStruct, WmiBufferHeader};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

/// O NTSTATUS como o trampolim devolve (estendido com sinal).
fn status(value: u32) -> Option<u64> {
    Some(value as i32 as i64 as u64)
}

fn buffer_header(address: u64) -> &'static WmiBufferHeader {
    // SAFETY: um buffer entregue pelo teste no espaço reservado (pool do kernel).
    unsafe { WmiBufferHeader::at(address) }
}

fn event_header(address: u64) -> &'static EventHeader {
    // SAFETY: o primeiro registro de um buffer entregue.
    unsafe { EventHeader::at(address) }
}

/// LogFileMode da sessão: tempo real, um fluxo só.
const MODE: u32 = logger::EVENT_TRACE_REAL_TIME_MODE | logger::EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING;
/// O espaço reservado do consumidor: quatro páginas.
const SPACE_SIZE: u32 = 0x4000;

pub fn run(assert: Assert) {
    let block = guest::alloc_bytes(0x400);
    let space = guest::alloc_aligned(SPACE_SIZE as u64, 0x1000, true);
    if block == 0 || space == 0 {
        assert(false, "etw-realtime: memoria do teste");
        return;
    }
    let (properties, returned, name, connect, cells) = (block, block + 0x180, block + 0x100, block + 0x200, block + 0x300);
    // As células do consumidor (como as do TRACELOG_CONTEXT do sechost).
    let (bitmap, list_head, buffer_count, events_lost, buffers_lost, timeout, provider, registration, descriptor, data, payload, handle_cell, attributes) =
        (cells, cells + 0x08, cells + 0x10, cells + 0x14, cells + 0x18, cells + 0x20, cells + 0x28, cells + 0x38, cells + 0x40, cells + 0x50, cells + 0x60, cells + 0x68, cells + 0x70);
    let text: Vec<u16> = "OpenNT-TempoReal".encode_utf16().collect();
    guest::write_bytes(name, &text.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let prepare = || {
        guest::write_bytes(properties, &[0; 0xB0]);
        guest::write32(properties, 0xB0);
        guest::write32(properties + 0x2C, 0x2_0000);
        guest::write32(properties + 0x30, 4);
        guest::write32(properties + 0x40, MODE);
        guest::write16(properties + 0x90, (text.len() * 2) as u16);
        guest::write16(properties + 0x92, (text.len() * 2) as u16);
        guest::write64(properties + 0x98, name);
    };
    let control = |code: u64| call_export("ZwTraceControl", &[code, properties, 0xB0, properties, 0xB0, returned]);
    prepare();
    let started = control(1);
    let logger_id = (guest::read64(properties + 8) & 0xFFFF) as u16;
    prepare();
    let queried = control(3);
    assert(started == Some(0) && queried == Some(0) && guest::read32(properties + 0x40) & MODE == MODE && guest::read64(properties + 0x78) != 0 && guest::read32(properties + 0xA0) == 0, "etw-realtime: a sessao de tempo real tem thread do logger e nenhum consumidor");

    // Os eventos do consumidor: desligamento (notificação) e dados
    // (sincronização, o CreateEventW(FALSE, FALSE) do sechost).
    guest::write32(attributes, 0x30);
    let created_disconnect = call_export("ZwCreateEvent", &[handle_cell, 0x1F_0003, attributes, 0, 0]);
    let disconnect_event = guest::read64(handle_cell);
    let created_data = call_export("ZwCreateEvent", &[handle_cell, 0x1F_0003, attributes, 1, 0]);
    let data_event = guest::read64(handle_cell);
    let connection = realtime::Connection {
        logger_id: logger_id as u32,
        space_size: SPACE_SIZE,
        space,
        bitmap,
        disconnect_event,
        data_event,
        list_head,
        buffer_count,
        events_lost,
        buffers_lost,
    };
    // O mesmo pedido pelo NtTraceControl 11: ponteiros de kernel não passam
    // pelo ProbeForWrite.
    guest::write_bytes(connect, &[0; 0x60]);
    guest::write32(connect, logger_id as u32);
    guest::write32(connect + 4, SPACE_SIZE);
    guest::write64(connect + 8, space);
    guest::write64(connect + 0x10, bitmap);
    guest::write64(connect + 0x18, disconnect_event);
    guest::write64(connect + 0x20, data_event);
    guest::write64(connect + 0x28, list_head);
    guest::write64(connect + 0x30, buffer_count);
    guest::write64(connect + 0x38, events_lost);
    guest::write64(connect + 0x40, buffers_lost);
    let probed = call_export("ZwTraceControl", &[11, connect, 0x60, connect, 0x60, returned]);
    let short = call_export("ZwTraceControl", &[11, connect, 0x58, connect, 0x60, returned]);
    let missing = realtime::attach(&realtime::Connection { logger_id: 63, ..connection }, false).err();
    assert(created_disconnect == Some(0) && created_data == Some(0) && probed == status(0xC000_0005) && short == status(0xC000_000D) && missing == Some(0xC000_000D), "etw-realtime: EtwRealtimeConnect sonda as faixas e recusa sessao inexistente");

    // Um provedor de kernel habilitado na sessão e um evento antes de haver
    // consumidor: o flush guarda o buffer.
    guest::write_bytes(provider, &[0x52, 0x54, 0x2D, 0x4F, 0x70, 0x65, 0x6E, 0x4E, 0x54, 0x2D, 0x45, 0x54, 0x57, 0x2D, 0x52, 0x54]);
    let registered = call_export("EtwRegister", &[provider, 0, 0, registration]);
    let handle = guest::read64(registration);
    let enabled = logger::enable_provider(logger_id, guest::read_bytes(provider, 16).try_into().unwrap_or([0; 16]), 4, 0x10);
    let write = |id: u16| {
        guest::write_bytes(descriptor, &[0; 16]);
        guest::write16(descriptor, id);
        guest::write8(descriptor + 4, 4);
        guest::write64(descriptor + 8, 0x10);
        guest::write_bytes(payload, b"rt!");
        guest::write64(data, payload);
        guest::write32(data + 8, 3);
        call_export("EtwWrite", &[handle, descriptor, 0, 1, data])
    };
    let first = write(7036);
    prepare();
    let saved = control(5);
    assert(registered == Some(0) && matches!(enabled, Ok(0)) && first == Some(0) && saved == Some(0) && guest::read32(properties + 0x6C) == 1, "etw-realtime: o buffer fechado sem consumidor fica guardado");

    // O consumidor conecta e recebe o buffer guardado.
    let before = realtime::live_consumers();
    let attached = realtime::attach(&connection, false);
    let consumer_handle = attached.map(|(handle, _)| handle).unwrap_or(0);
    let reference = attached.map(|(_, reference)| reference).unwrap_or([0; 2]);
    guest::write64(timeout, (-50_000_000i64) as u64);
    let waited = call_export("ZwWaitForSingleObject", &[data_event, 0, timeout]);
    let entry = guest::read64(list_head);
    let delivered = entry.wrapping_sub(0x20);
    let in_space = entry != 0 && delivered == space;
    assert(attached.is_ok() && consumer_handle != 0 && reference[0] != 0 && realtime::live_consumers() == before + 1 && waited == Some(0) && in_space && guest::read32(buffer_count) == 1 && guest::read32(bitmap) & 1 == 1, "etw-realtime: o consumidor recebe o buffer guardado na primeira pagina do espaco reservado");
    if in_space {
        let header = buffer_header(delivered);
        let record = event_header(delivered + 0x48);
        assert(guest::read64(entry) == 0 && header.offset.get() > 0x48 && header.client_context.processor_number.get() == 0 && header.client_context.logger_id.get() == logger_id && header.buffer_type.get() == 0, "etw-realtime: o buffer entregue com Offset, processador 0 e LoggerId");
        assert(record.header_type.get() == 0xC013 && guest::read_bytes(record.provider_id.address(), 16) == guest::read_bytes(provider, 16) && record.event_descriptor.id.get() == 7036, "etw-realtime: o registro EVENT_HEADER do evento no buffer entregue");
    }
    prepare();
    let with_consumer = control(3);
    assert(with_consumer == Some(0) && guest::read32(properties + 0xA0) == 1, "etw-realtime: a consulta conta o consumidor");

    // O consumidor devolve o buffer (lista vazia, contador zero, bit limpo)
    // e o flush seguinte entrega o próximo na mesma página.
    guest::write64(list_head, 0);
    guest::write32(buffer_count, 0);
    guest::write32(bitmap, 0);
    let second = write(7040);
    prepare();
    let flushed = control(5);
    let waited_again = call_export("ZwWaitForSingleObject", &[data_event, 0, timeout]);
    let again = guest::read64(list_head);
    assert(second == Some(0) && flushed == Some(0) && waited_again == Some(0) && again == space + 0x20 && guest::read32(buffer_count) == 1 && event_header(space + 0x48).event_descriptor.id.get() == 7040, "etw-realtime: o proximo buffer volta a pagina devolvida, sem marcador vazio");

    // O desligamento pelo NtTraceControl 14.
    guest::write64(handle_cell, consumer_handle);
    let disconnected = call_export("ZwTraceControl", &[14, handle_cell, 8, 0, 0, returned]);
    let signaled = call_export("ZwWaitForSingleObject", &[disconnect_event, 0, timeout]);
    let twice = call_export("ZwTraceControl", &[14, handle_cell, 8, 0, 0, returned]);
    prepare();
    let after = control(3);
    assert(disconnected == Some(0) && signaled == Some(0) && twice == status(0x8000_0025) && after == Some(0) && guest::read32(properties + 0xA0) == 0, "etw-realtime: o NtTraceControl 14 desliga o consumidor e sinaliza o evento");
    let closed = call_export("ZwClose", &[consumer_handle]);
    assert(closed == Some(0) && realtime::live_consumers() == before, "etw-realtime: fechar o handle apaga o EtwConsumer");

    let _ = call_export("EtwUnregister", &[handle]);
    prepare();
    let stopped = control(2);
    assert(stopped == Some(0) && logger::context(logger_id as u32).is_none(), "etw-realtime: o Stop termina a sessao de tempo real");
    let _ = call_export("ZwClose", &[disconnect_event]);
    let _ = call_export("ZwClose", &[data_event]);
    guest::free_bytes(space);
    guest::free_bytes(block);
}
