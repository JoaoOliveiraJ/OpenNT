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
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

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
    callback_frame: u64,
    descriptor: u64,
    storage: u64,
}

static LISTS: SpinLock<Lists> =
    SpinLock::new(Lists { heads: [0; 2], counts: [0; 2], callback_frame: 0, descriptor: 0, storage: 0 });
static PUBLISHING: SpinLock<bool> = SpinLock::new(false);

fn lists() -> Result<([u64; 2], u64), KernelError> {
    let mut lists = LISTS.lock();
    if lists.heads[0] == 0 {
        let storage = guest::alloc_bytes(32);
        let frame = guest::alloc_bytes(32);
        if storage == 0 || frame == 0 {
            return Err(KernelError::new("bugcheck callback storage allocation failed"));
        }
        lists.heads = [storage, storage + 16];
        lists.callback_frame = frame;
        for head in lists.heads {
            guest::write64(head, head);
            guest::write64(head + 8, head);
        }
    }
    Ok((lists.heads, lists.callback_frame))
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
    let next = guest::read64(record);
    let previous = guest::read64(record + 8);
    if next == 0 || previous == 0 || guest::read64(next + 8) != record || guest::read64(previous) != record {
        return Err(KernelError::new("corrupt bugcheck callback LIST_ENTRY"));
    }
    Ok((next, previous))
}

/// Identidade pelo registro (dois registros podem chamar a mesma rotina).
fn contains(head: u64, count: u64, record: u64) -> Result<bool, KernelError> {
    let mut current = guest::read64(head);
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
    let (heads, _) = lists()?;
    let index = list_index(reason);
    at_high_level(|| {
        let count = LISTS.lock().counts[index];
        if guest::read8(record + 44) != BUFFER_EMPTY || contains(heads[index], count, record)? {
            return Ok(false);
        }
        let head = heads[index];
        let previous = if reason == 7 { guest::read64(head + 8) } else { head };
        let next = guest::read64(previous);
        if guest::read64(next + 8) != previous {
            return Err(KernelError::new("corrupt bugcheck callback insertion"));
        }
        guest::write64(record + 16, routine);
        guest::write64(record + 24, component);
        guest::write64(record + 32, checksum(routine, component, reason));
        guest::write32(record + 40, reason);
        guest::write8(record + 44, BUFFER_INSERTED);
        guest::write64(record, next);
        guest::write64(record + 8, previous);
        guest::write64(previous, record);
        guest::write64(next + 8, record);
        LISTS.lock().counts[index] += 1;
        Ok(true)
    })
}

/// KeDeregisterBugCheckReasonCallback: State volta a zero; os campos do
/// driver e os vínculos antigos ficam no registro.
pub fn remove(record: u64) -> Result<bool, KernelError> {
    let (heads, _) = lists()?;
    at_high_level(|| {
        if guest::read8(record + 44) != BUFFER_INSERTED {
            return Ok(false);
        }
        let index = list_index(guest::read32(record + 40));
        let count = LISTS.lock().counts[index];
        if !contains(heads[index], count, record)? {
            return Err(KernelError::new("unowned bugcheck callback record"));
        }
        let (next, previous) = verify_links(record)?;
        guest::write8(record + 44, BUFFER_EMPTY);
        guest::write64(previous, next);
        guest::write64(next + 8, previous);
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
    let (heads, frame) = lists()?;
    let index = list_index(reason);
    let head = heads[index];
    let count = LISTS.lock().counts[index];
    at_high_level(|| {
        let mut current = guest::read64(head);
        for _ in 0..count {
            if current == head {
                return Err(KernelError::new("short bugcheck callback consumption list"));
            }
            let record = current;
            current = verify_links(record)?.0;
            if selected_record != 0 && record != selected_record {
                continue;
            }
            if guest::read32(record + 40) != reason || guest::read8(record + 44) != BUFFER_INSERTED {
                continue;
            }
            let routine = guest::read64(record + 16);
            let component = guest::read64(record + 24);
            if routine == 0 || guest::read64(record + 32) != checksum(routine, component, reason) {
                guest::write8(record + 44, BUFFER_INCOMPLETE);
                debug_print!("KERNEL_BUGCHECK_CALLBACK_INVALID record={:#x}", record);
                continue;
            }
            guest::write8(record + 44, BUFFER_STARTED);
            let mut invoke = |data: u64, length: u64| {
                guest::write64(frame, reason as u64);
                guest::write64(frame + 8, record);
                guest::write64(frame + 16, data);
                guest::write64(frame + 24, length);
                native_call::call(routine, &[guest::read64(frame), guest::read64(frame + 8), guest::read64(frame + 16), guest::read64(frame + 24)]);
            };
            match consumer(record, &mut invoke) {
                Ok(()) => guest::write8(record + 44, BUFFER_FINISHED),
                Err(error) => {
                    guest::write8(record + 44, BUFFER_INCOMPLETE);
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
        let descriptor = guest::alloc_bytes(48);
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
    for offset in 0..length {
        let _ = write!(text, "{:02x}", guest::try_read8(address + offset)?);
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
    let (descriptor, storage) = workspace()?;
    let clear_descriptor = || {
        for offset in (0..48).step_by(8) {
            guest::write64(descriptor + offset, 0);
        }
        guest::write64(descriptor, storage);
        guest::write32(descriptor + 8, MAXIMUM_SECONDARY_BYTES as u32);
        guest::write32(descriptor + 12, MAXIMUM_SECONDARY_BYTES as u32);
    };
    let result = consume(
        2,
        &mut |record, invoke| {
            clear_descriptor();
            // OutBuffer nulo pede o tamanho; InBuffer já oferece memória real.
            invoke(descriptor, 48);
            let requested = guest::read32(descriptor + 40) as u64;
            if requested == 0 {
                return Ok(());
            }
            if requested > MAXIMUM_SECONDARY_BYTES {
                return Err(KernelError::new("bugcheck secondary data exceeds MaximumAllowed"));
            }
            guest::write_bytes(storage, &alloc::vec![0u8; requested as usize]);
            guest::write64(descriptor, storage);
            guest::write32(descriptor + 8, requested as u32);
            // OutBuffer == InBuffer distingue a entrega da consulta de tamanho.
            guest::write64(descriptor + 32, storage);
            invoke(descriptor, 48);
            let output = guest::read64(descriptor + 32);
            let length = guest::read32(descriptor + 40) as u64;
            if length == 0 {
                return Ok(());
            }
            if output == 0 || length > requested {
                return Err(KernelError::new("invalid bugcheck secondary output"));
            }
            debug_print!(
                "KERNEL_BUGCHECK_SECONDARY_RECORD {{\"record\":\"{:#x}\",\"guidBytes\":\"{}\",\"length\":{}}}",
                record,
                hexadecimal(descriptor + 16, 16)?,
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
