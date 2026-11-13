//! Rotinas Rtl de strings contadas: anexar e copiar UNICODE_STRING e
//! inicializar ANSI_STRING.

use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MAXIMUM_SOURCE_CHARACTERS: u64 = 0x7FFE;

/// memmove sondado: a origem inteira é lida antes da escrita (sobreposição
/// preservada).
fn memmove(destination: u64, source: u64, length: u64) -> Result<(), KernelError> {
    guest::try_write_bytes(destination, &guest::try_read_bytes(source, length as usize)?)
}

/// RtlAppendUnicodeToString: concatena uma origem WCHAR terminada em NUL.
pub fn append_unicode_to_string(destination: u64, source: u64) -> Result<u32, KernelError> {
    // O caminho NULL retorna sem consultar o descritor de destino.
    if source == 0 {
        return Ok(0);
    }
    // RtlInitUnicodeStringEx procura o NUL antes de rejeitar o tamanho.
    let mut cursor = source;
    let mut characters = 0u64;
    while guest::try_read16(cursor)? != 0 {
        if characters <= MAXIMUM_SOURCE_CHARACTERS {
            characters += 1;
        }
        cursor = cursor.wrapping_add(2);
    }
    if characters > MAXIMUM_SOURCE_CHARACTERS {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let destination = UnicodeString::try_at(destination)?;
    let original_length = destination.length.probe_get()? as u64;
    let appended = characters * 2;
    let maximum = destination.maximum_length.probe_get()? as u64;
    if original_length + appended > maximum {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let buffer = destination.buffer.probe_get()?;
    // O índice WCHAR trunca um Length ímpar.
    let append_address = buffer.wrapping_add(original_length & !1);
    memmove(append_address, source, appended)?;
    // Soma ao Length presente após a cópia (o buffer pode sobrepor o descritor).
    let updated = (destination.length.probe_get()? as u64 + appended) & 0xFFFF;
    destination.length.probe_set(updated as u16)?;
    if (destination.length.probe_get()? as u64) + 1 < destination.maximum_length.probe_get()? as u64 {
        guest::try_write_bytes(append_address.wrapping_add(appended), &[0, 0])?;
    }
    Ok(0)
}

/// RtlCopyUnicodeString: cópia por bytes, inclusive comprimentos ímpares.
pub fn copy_unicode_string(destination: u64, source: u64) -> Result<u32, KernelError> {
    let destination = UnicodeString::try_at(destination)?;
    if source == 0 {
        destination.length.probe_set(0)?;
        return Ok(0);
    }
    let source = UnicodeString::try_at(source)?;
    let source_length = source.length.probe_get()? as u64;
    let maximum = destination.maximum_length.probe_get()? as u64;
    let source_buffer = source.buffer.probe_get()?;
    let destination_buffer = destination.buffer.probe_get()?;
    let copied = source_length.min(maximum);
    destination.length.probe_set(copied as u16)?;
    memmove(destination_buffer, source_buffer, copied)?;
    // Relê os campos e escreve NUL só se houver dois bytes adicionais.
    if destination.length.probe_get()? as u64 + 2 <= destination.maximum_length.probe_get()? as u64 {
        guest::try_write_bytes(destination_buffer.wrapping_add(copied & !1), &[0, 0])?;
    }
    Ok(0)
}

/// RtlInitAnsiString: escreve o descritor antes de procurar o NUL.
pub fn initialize_ansi_string(destination: u64, source: u64) -> Result<u32, KernelError> {
    let destination = AnsiString::try_at(destination)?;
    destination.length.probe_set(0)?;
    destination.maximum_length.probe_set(0)?;
    destination.buffer.probe_set(source)?;
    if source != 0 {
        let mut current = source;
        let mut length = 0u16;
        while guest::try_read8(current)? != 0 {
            if length < 0xFFFE {
                length += 1;
            }
            current = current.wrapping_add(1);
        }
        destination.length.probe_set(length)?;
        destination.maximum_length.probe_set(length + 1)?;
    }
    Ok(0)
}
