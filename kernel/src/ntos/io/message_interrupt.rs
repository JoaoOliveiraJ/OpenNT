//! IoConnectInterruptEx CONNECT_MESSAGE_BASED e o IoDisconnectInterruptEx
//! das mensagens.
//!
//! Como o IopConnectMessageBasedInterrupt do ntoskrnl 19041 (rva 0x761394):
//! - as mensagens vêm dos dados de conexão do PDO
//!   (INTERRUPT_CONNECTION_DATA_PKEY, que o PnP manager grava na tradução,
//!   `pnp::message_interrupts`); só as entradas de mensagem contam (os tipos
//!   XapicMessage, Hypertransport e MessageRequest), e sem nenhuma o pedido
//!   falha com STATUS_INVALID_PARAMETER (o IoConnectInterruptEx, sem
//!   FallBackServiceRoutine, devolve então STATUS_NOT_SUPPORTED; com ela,
//!   conecta a linha e devolve Version = LINE_BASED);
//! - o UnifiedIrql da tabela é o SynchronizeIrql pedido (que não pode ficar
//!   abaixo do IRQL de nenhuma mensagem: STATUS_INVALID_PARAMETER), ou, com
//!   um SpinLock e sem SynchronizeIrql, o maior IRQL das mensagens, ou 0;
//! - cada mensagem ganha um objeto de interrupção no vetor dela, com a
//!   MessageServiceRoutine chamada com o MessageID (a posição na tabela) e
//!   sincronizada no UnifiedIrql (ou no IRQL da própria mensagem quando ele
//!   é 0); uma entrada MessageRequest pede o endereço e o dado ao
//!   HalGetMessageRoutingInfo;
//! - a IO_INTERRUPT_MESSAGE_INFO (8 + 0x30 por mensagem) vai para
//!   *ConnectionContext com o endereço, o destino, o objeto, o dado, o
//!   vetor, o IRQL, o modo e a polaridade de cada mensagem.
//! Se o dispositivo não tem mensagens e o chamador deu a
//! FallBackServiceRoutine, o IoConnectInterruptEx conecta a linha com ela
//! (o IopConnectLineBasedInterrupt) e devolve Version = CONNECT_LINE_BASED.

use alloc::vec::Vec;

use crate::ntos::inc::types::extra_storage::{IoInterruptMessageInfo, IoInterruptMessageInfoEntry};
use crate::ntos::inc::types::{InterruptVectorData, IoConnectInterruptParameters, NtStruct};
use crate::ntos::io::pnp::message_interrupts;
use crate::ntos::ke::interrupt_object;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const CONNECT_LINE_BASED: u32 = 2;
/// Cabeçalho da IO_INTERRUPT_MESSAGE_INFO (UnifiedIrql e MessageCount).
const MESSAGE_INFO_HEADER: u64 = 8;

/// Uma entrada de mensagem dos dados de conexão, já com endereço e dado.
struct Entry {
    message: message_interrupts::Message,
    mode: u32,
    polarity: u32,
    target: u64,
}

/// As entradas de mensagem (tipos 1 a 3) dos dados de conexão do PDO.
fn message_entries(pdo: u64) -> Vec<Entry> {
    let Some((_, bytes)) = crate::ntos::io::device_property::device_property_value(pdo, message_interrupts::INTERRUPT_CONNECTION_DATA_PKEY, message_interrupts::INTERRUPT_CONNECTION_DATA_PID) else { return Vec::new() };
    let count = bytes.get(0..4).map_or(0, |count| u32::from_le_bytes([count[0], count[1], count[2], count[3]])) as usize;
    let block = guest::alloc_bytes(bytes.len().max(1) as u64);
    guest::write_bytes(block, &bytes);
    let mut entries = Vec::new();
    for index in 0..count {
        let start = 8 + index * InterruptVectorData::SIZE as usize;
        if start + InterruptVectorData::SIZE as usize > bytes.len() {
            break;
        }
        // SAFETY: entrada dentro da cópia dos dados de conexão.
        let entry = unsafe { InterruptVectorData::at(block + start as u64) };
        // Hypertransport não tem rota nesta HAL (sem HyperTransport).
        if let Some(message) = message_interrupts::entry_message(entry) {
            entries.push(Entry { message, mode: entry.mode.get().0 as u32, polarity: entry.polarity.get().0 as u32, target: entry.target_processors.mask.get() });
        }
    }
    guest::free_bytes(block);
    entries
}

/// O status com sinal do export.
fn status(value: u32) -> u64 {
    crate::ntos::init::exports::signed_status(value)
}

/// IopConnectMessageBasedInterrupt: a tabela em *ConnectionContext.
fn connect_messages(parameters: &IoConnectInterruptParameters) -> Result<u32, KernelError> {
    let message_based = &parameters.message_based;
    let pdo = message_based.physical_device_object.get();
    let output = message_based.connection_context.get();
    let routine = message_based.message_service_routine.get();
    let synchronize = message_based.synchronize_irql.get();
    let spin_lock = message_based.spin_lock.get();
    guest::write64(output, 0);
    if pdo == 0 || routine == 0 || crate::ntos::io::pnp::devnode::get(pdo).is_none() {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let entries = message_entries(pdo);
    if entries.is_empty() {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut unified = 0u8;
    for entry in &entries {
        if synchronize != 0 {
            if synchronize < entry.message.irql {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            unified = synchronize;
        } else if spin_lock != 0 {
            unified = unified.max(entry.message.irql);
        }
    }
    let size = MESSAGE_INFO_HEADER + entries.len() as u64 * IoInterruptMessageInfoEntry::SIZE;
    let table_address = guest::alloc_bytes(size);
    if table_address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: tabela recém-alocada com espaço para todas as entradas.
    let table = unsafe { IoInterruptMessageInfo::at(table_address) };
    table.unified_irql.set(unified);
    table.message_count.set(0);
    // SAFETY: as entradas seguem o cabeçalho no mesmo bloco.
    let slots = unsafe { IoInterruptMessageInfoEntry::array_at(table.message_info[0].address(), entries.len()) };
    let context = message_based.service_context.get();
    for (id, (entry, slot)) in entries.iter().zip(slots).enumerate() {
        let irql = entry.message.irql;
        let synchronize_irql = if unified != 0 { unified } else { irql };
        let object = guest::alloc_bytes(8);
        let connected = interrupt_object::io_connect_message_interrupt(object, routine, context, spin_lock, entry.message.vector, irql, synchronize_irql, id as u32);
        let interrupt = guest::read64(object);
        guest::free_bytes(object);
        if connected.is_err() || interrupt == 0 {
            disconnect_table(table_address);
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        slot.message_address.set(entry.message.address as i64);
        slot.target_processor_set.set(entry.target);
        slot.interrupt_object.set(interrupt);
        slot.message_data.set(entry.message.data);
        slot.vector.set(entry.message.vector);
        slot.irql.set(irql);
        slot.mode.set(entry.mode);
        slot.polarity.set(entry.polarity);
        table.message_count.set(id as u32 + 1);
        debug_print!("[io] interrupt MESSAGE_BASED: mensagem {} vetor 0x{:x} irql {} -> ISR 0x{:x}", id, entry.message.vector, irql, routine);
    }
    guest::write64(output, table_address);
    Ok(0)
}

/// IoConnectInterruptEx com CONNECT_MESSAGE_BASED, como o ntoskrnl 19041:
/// se o IopConnectMessageBasedInterrupt falha, sem FallBackServiceRoutine o
/// resultado é STATUS_NOT_SUPPORTED; com ela, a linha. Devolve o valor do
/// export.
pub fn connect_interrupt_ex(parameters_address: u64) -> Result<u64, KernelError> {
    // SAFETY: IO_CONNECT_INTERRUPT_PARAMETERS do driver (modo kernel).
    let parameters = unsafe { IoConnectInterruptParameters::at(parameters_address) };
    let result = connect_messages(parameters)?;
    if result == 0 {
        return Ok(0);
    }
    let message_based = &parameters.message_based;
    let fallback = message_based.fall_back_service_routine.get();
    if fallback == 0 {
        debug_print!("[io] IoConnectInterruptEx MESSAGE_BASED: mensagens -> {:#x}, sem FallBackServiceRoutine", result);
        return Ok(status(STATUS_NOT_SUPPORTED));
    }
    // A linha com a FallBackServiceRoutine (IopConnectLineBasedInterrupt):
    // os mesmos campos na forma LINE_BASED, e a versão devolvida ao chamador.
    let line = guest::alloc_bytes(IoConnectInterruptParameters::SIZE);
    // SAFETY: parâmetros recém-alocados.
    let line_parameters = unsafe { IoConnectInterruptParameters::at(line) };
    line_parameters.version.set(CONNECT_LINE_BASED);
    let line_based = &line_parameters.line_based;
    line_based.physical_device_object.set(message_based.physical_device_object.get());
    line_based.interrupt_object.set(message_based.connection_context.get());
    line_based.service_routine.set(fallback);
    line_based.service_context.set(message_based.service_context.get());
    line_based.spin_lock.set(message_based.spin_lock.get());
    line_based.synchronize_irql.set(message_based.synchronize_irql.get());
    line_based.floating_save.set(message_based.floating_save.get());
    let connected = super::interrupt::connect_interrupt_ex(line);
    guest::free_bytes(line);
    parameters.version.set(CONNECT_LINE_BASED);
    connected
}

/// Desconecta os objetos de uma IO_INTERRUPT_MESSAGE_INFO e a libera.
fn disconnect_table(table_address: u64) {
    // SAFETY: tabela devolvida por `connect_messages`.
    let table = unsafe { IoInterruptMessageInfo::at(table_address) };
    let count = table.message_count.get() as usize;
    // SAFETY: as MessageCount entradas da tabela.
    for slot in unsafe { IoInterruptMessageInfoEntry::array_at(table.message_info[0].address(), count) } {
        let object = slot.interrupt_object.get();
        if object != 0 {
            interrupt_object::io_disconnect_interrupt(object);
        }
    }
    guest::free_bytes(table_address);
}

/// IoDisconnectInterruptEx com CONNECT_MESSAGE_BASED: o ConnectionContext é
/// a IO_INTERRUPT_MESSAGE_INFO.
pub fn disconnect_interrupt_ex(table_address: u64) -> u32 {
    if table_address == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    disconnect_table(table_address);
    0
}
