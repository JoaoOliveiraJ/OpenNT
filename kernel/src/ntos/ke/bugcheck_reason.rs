//! Callbacks de motivo de bugcheck e o consumidor de dados secundários.
//!
//! O chamador possui a memória do registro; o kernel guarda só os vínculos e
//! nunca a libera. Os dados secundários vão para a serial: não se cria um
//! MEMORY.DMP nem eventos de escrita de dump.

use alloc::format;
use alloc::string::String;
use core::fmt::Write;

use super::irql;
use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{KbugcheckReasonCallbackRecord, KbugcheckSecondaryDumpData, ListEntry, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

const BUFFER_EMPTY: u8 = 0;
const BUFFER_INSERTED: u8 = 1;
const BUFFER_STARTED: u8 = 2;
const BUFFER_FINISHED: u8 = 3;
const BUFFER_INCOMPLETE: u8 = 4;
const MAXIMUM_SECONDARY_BYTES: u64 = 64 * 1024;

struct Lists {
    /// Duas LIST_ENTRY permanentes: motivos gerais e AddPages/RemovePages.
    heads: [u64; 2],
    counts: [u64; 2],
    descriptor: u64,
    storage: u64,
}

static LISTS: SpinLock<Lists> = SpinLock::new(Lists { heads: [0; 2], counts: [0; 2], descriptor: 0, storage: 0 });
static PUBLISHING: SpinLock<bool> = SpinLock::new(false);

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: cabeça própria ou o Entry de um registro do chamador.
    unsafe { ListEntry::at(address) }
}

fn record_at(record: u64) -> &'static KbugcheckReasonCallbackRecord {
    // SAFETY: o chamador possui o registro enquanto ele está inserido.
    unsafe { KbugcheckReasonCallbackRecord::at(record) }
}

fn lists() -> Result<[u64; 2], KernelError> {
    let mut lists = LISTS.lock();
    if lists.heads[0] == 0 {
        let storage = guest::alloc_bytes(2 * ListEntry::SIZE);
        if storage == 0 {
            return Err(KernelError::new("bugcheck callback storage allocation failed"));
        }
        lists.heads = [storage, storage + ListEntry::SIZE];
        for head in lists.heads {
            let entry = list_entry(head);
            entry.flink.set(head);
            entry.blink.set(head);
        }
    }
    Ok(lists.heads)
}

fn list_index(reason: u32) -> usize {
    if reason == 4 || reason == 6 { 1 } else { 0 }
}

/// A soma usa o enum C com sinal.
fn checksum(routine: u64, component: u64, reason: u32) -> u64 {
    routine.wrapping_add(component).wrapping_add(reason as i32 as i64 as u64)
}

/// Uma lista corrompida não pode produzir sucesso nem caminhada infinita.
fn verify_links(record: u64) -> Result<(u64, u64), KernelError> {
    let entry = list_entry(record);
    let next = entry.flink.get();
    let previous = entry.blink.get();
    if next == 0 || previous == 0 || list_entry(next).blink.get() != record || list_entry(previous).flink.get() != record {
        return Err(KernelError::new("corrupt bugcheck callback LIST_ENTRY"));
    }
    Ok((next, previous))
}

/// Identidade pelo registro (dois registros podem chamar a mesma rotina).
fn contains(head: u64, count: u64, record: u64) -> Result<bool, KernelError> {
    let mut current = list_entry(head).flink.get();
    verify_links(head)?;
    for _ in 0..count {
        if current == head {
            return Err(KernelError::new("short bugcheck callback list"));
        }
        let (next, _) = verify_links(current)?;
        if current == record {
            return Ok(true);
        }
        current = next;
    }
    if current != head {
        return Err(KernelError::new("cyclic bugcheck callback list"));
    }
    Ok(false)
}

fn at_high_level<T>(body: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    let previous = irql::raise_irql(irql::HIGH_LEVEL);
    let result = body();
    irql::lower_irql(previous as u64);
    result
}

/// KeRegisterBugCheckReasonCallback. Triagem (7) entra no fim; os demais
/// motivos no início.
pub fn register(record: u64, routine: u64, reason: u32, component: u64) -> Result<bool, KernelError> {
    let heads = lists()?;
    let index = list_index(reason);
    let entry = record_at(record);
    at_high_level(|| {
        let count = LISTS.lock().counts[index];
        if entry.state.get() != BUFFER_EMPTY || contains(heads[index], count, record)? {
            return Ok(false);
        }
        let head = heads[index];
        let previous = if reason == 7 { list_entry(head).blink.get() } else { head };
        let next = list_entry(previous).flink.get();
        if list_entry(next).blink.get() != previous {
            return Err(KernelError::new("corrupt bugcheck callback insertion"));
        }
        entry.callback_routine.set(routine);
        entry.component.set(component);
        entry.checksum.set(checksum(routine, component, reason));
        entry.reason.set(reason as i32);
        entry.state.set(BUFFER_INSERTED);
        entry.entry.flink.set(next);
        entry.entry.blink.set(previous);
        list_entry(previous).flink.set(record);
        list_entry(next).blink.set(record);
        LISTS.lock().counts[index] += 1;
        Ok(true)
    })
}

/// KeDeregisterBugCheckReasonCallback: State volta a zero; os campos do
/// driver e os vínculos antigos ficam no registro.
pub fn remove(record: u64) -> Result<bool, KernelError> {
    let heads = lists()?;
    let entry = record_at(record);
    at_high_level(|| {
        if entry.state.get() != BUFFER_INSERTED {
            return Ok(false);
        }
        let index = list_index(entry.reason.get() as u32);
        let count = LISTS.lock().counts[index];
        if !contains(heads[index], count, record)? {
            return Err(KernelError::new("unowned bugcheck callback record"));
        }
        let (next, previous) = verify_links(record)?;
        entry.state.set(BUFFER_EMPTY);
        list_entry(previous).flink.set(next);
        list_entry(next).blink.set(previous);
        LISTS.lock().counts[index] -= 1;
        Ok(true)
    })
}

/// O consumidor real fornece a estrutura do motivo; `invoke(dados, tamanho)`
/// chama a rotina nativa com o frame de quatro argumentos.
pub fn consume(
    reason: u32,
    consumer: &mut dyn FnMut(u64, &mut dyn FnMut(u64, u64)) -> Result<(), KernelError>,
    selected_record: u64,
) -> Result<(), KernelError> {
    let heads = lists()?;
    let index = list_index(reason);
    let head = heads[index];
    let count = LISTS.lock().counts[index];
    at_high_level(|| {
        let mut current = list_entry(head).flink.get();
        for _ in 0..count {
            if current == head {
                return Err(KernelError::new("short bugcheck callback consumption list"));
            }
            let record = current;
            current = verify_links(record)?.0;
            if selected_record != 0 && record != selected_record {
                continue;
            }
            let entry = record_at(record);
            if entry.reason.get() as u32 != reason || entry.state.get() != BUFFER_INSERTED {
                continue;
            }
            let routine = entry.callback_routine.get();
            let component = entry.component.get();
            if routine == 0 || entry.checksum.get() != checksum(routine, component, reason) {
                entry.state.set(BUFFER_INCOMPLETE);
                debug_print!("KERNEL_BUGCHECK_CALLBACK_INVALID record={:#x}", record);
                continue;
            }
            entry.state.set(BUFFER_STARTED);
            // KBUGCHECK_REASON_CALLBACK_ROUTINE(Reason, Record, Data, Length).
            let mut invoke = |data: u64, length: u64| {
                native_call::call(routine, &[reason as u64, record, data, length]);
            };
            match consumer(record, &mut invoke) {
                Ok(()) => entry.state.set(BUFFER_FINISHED),
                Err(error) => {
                    entry.state.set(BUFFER_INCOMPLETE);
                    return Err(error);
                }
            }
        }
        if current != head {
            return Err(KernelError::new("cyclic bugcheck callback consumption list"));
        }
        Ok(())
    })
}

// ---- dados secundários (motivo 2) ------------------------------------------

fn workspace() -> Result<(u64, u64), KernelError> {
    let mut lists = LISTS.lock();
    if lists.descriptor == 0 {
        let descriptor = guest::alloc_bytes(KbugcheckSecondaryDumpData::SIZE);
        let storage = guest::alloc_bytes(MAXIMUM_SECONDARY_BYTES);
        if descriptor == 0 || storage == 0 {
            return Err(KernelError::new("bugcheck secondary workspace allocation failed"));
        }
        lists.descriptor = descriptor;
        lists.storage = storage;
    }
    Ok((lists.descriptor, lists.storage))
}

fn hexadecimal(address: u64, length: u64) -> Result<String, KernelError> {
    let mut text = String::new();
    for byte in guest::try_read_bytes(address, length as usize)? {
        let _ = write!(text, "{byte:02x}");
    }
    Ok(text)
}

/// Publica na serial os bytes efetivamente entregues pelos drivers.
pub fn publish_secondary_data(selected_record: u64) -> Result<(), KernelError> {
    {
        let mut publishing = PUBLISHING.lock();
        if *publishing {
            return Err(KernelError::new("recursive bugcheck secondary collection"));
        }
        *publishing = true;
    }
    let (descriptor_address, storage) = workspace()?;
    // SAFETY: descritor próprio de 0x30 bytes (workspace).
    let descriptor = unsafe { KbugcheckSecondaryDumpData::at(descriptor_address) };
    let clear_descriptor = || {
        guest::write_bytes(descriptor_address, &[0; KbugcheckSecondaryDumpData::SIZE as usize]);
        descriptor.in_buffer.set(storage);
        descriptor.in_buffer_length.set(MAXIMUM_SECONDARY_BYTES as u32);
        descriptor.maximum_allowed.set(MAXIMUM_SECONDARY_BYTES as u32);
    };
    let result = consume(
        2,
        &mut |record, invoke| {
            clear_descriptor();
            // OutBuffer nulo pede o tamanho; InBuffer já oferece memória real.
            invoke(descriptor_address, KbugcheckSecondaryDumpData::SIZE);
            let requested = descriptor.out_buffer_length.get() as u64;
            if requested == 0 {
                return Ok(());
            }
            if requested > MAXIMUM_SECONDARY_BYTES {
                return Err(KernelError::new("bugcheck secondary data exceeds MaximumAllowed"));
            }
            guest::write_bytes(storage, &alloc::vec![0u8; requested as usize]);
            descriptor.in_buffer.set(storage);
            descriptor.in_buffer_length.set(requested as u32);
            // OutBuffer == InBuffer distingue a entrega da consulta de tamanho.
            descriptor.out_buffer.set(storage);
            invoke(descriptor_address, KbugcheckSecondaryDumpData::SIZE);
            let output = descriptor.out_buffer.get();
            let length = descriptor.out_buffer_length.get() as u64;
            if length == 0 {
                return Ok(());
            }
            if output == 0 || length > requested {
                return Err(KernelError::new("invalid bugcheck secondary output"));
            }
            debug_print!(
                "KERNEL_BUGCHECK_SECONDARY_RECORD {{\"record\":\"{:#x}\",\"guidBytes\":\"{}\",\"length\":{}}}",
                record,
                hexadecimal(descriptor.guid.address(), 16)?,
                length
            );
            let mut offset = 0;
            while offset < length {
                let bytes = hexadecimal(output + offset, 128.min(length - offset))?;
                debug_print!("{}", format!("KERNEL_BUGCHECK_SECONDARY_BYTES {{\"record\":\"{record:#x}\",\"offset\":{offset},\"bytes\":\"{bytes}\"}}"));
                offset += 128;
            }
            Ok(())
        },
        selected_record,
    );
    *PUBLISHING.lock() = false;
    result
}
