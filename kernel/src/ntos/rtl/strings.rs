//! Rotinas Rtl de strings contadas: anexar e copiar UNICODE_STRING e
//! inicializar ANSI_STRING.

use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const MAXIMUM_SOURCE_CHARACTERS: u64 = 0x7FFE;

/// Cópia byte a byte com a direção do memmove (preserva a origem sobreposta).
fn memmove(destination: u64, source: u64, length: u64) -> Result<(), KernelError> {
    let backwards = destination > source && destination < source.wrapping_add(length);
    for index in 0..length {
        let offset = if backwards { length - index - 1 } else { index };
        guest::try_write8(destination.wrapping_add(offset), guest::try_read8(source.wrapping_add(offset))?)?;
    }
    Ok(())
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
    let original_length = guest::try_read16(destination)? as u64;
    let appended = characters * 2;
    let maximum = guest::try_read16(destination + 2)? as u64;
    if original_length + appended > maximum {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let buffer = guest::try_read64(destination + 8)?;
    // O índice WCHAR trunca um Length ímpar.
    let append_address = buffer.wrapping_add(original_length & !1);
    memmove(append_address, source, appended)?;
    // Soma ao Length presente após a cópia (o buffer pode sobrepor o descritor).
    let updated = (guest::try_read16(destination)? as u64 + appended) & 0xFFFF;
    guest::try_write16(destination, updated as u16)?;
    if (guest::try_read16(destination)? as u64) + 1 < guest::try_read16(destination + 2)? as u64 {
        guest::try_write16(append_address.wrapping_add(appended), 0)?;
    }
    Ok(0)
}

/// RtlCopyUnicodeString: cópia por bytes, inclusive comprimentos ímpares.
pub fn copy_unicode_string(destination: u64, source: u64) -> Result<u32, KernelError> {
    if source == 0 {
        guest::try_write16(destination, 0)?;
        return Ok(0);
    }
    let source_length = guest::try_read16(source)? as u64;
    let maximum = guest::try_read16(destination + 2)? as u64;
    let source_buffer = guest::try_read64(source + 8)?;
    let destination_buffer = guest::try_read64(destination + 8)?;
    let copied = source_length.min(maximum);
    guest::try_write16(destination, copied as u16)?;
    memmove(destination_buffer, source_buffer, copied)?;
    // Relê os campos e escreve NUL só se houver dois bytes adicionais.
    if guest::try_read16(destination)? as u64 + 2 <= guest::try_read16(destination + 2)? as u64 {
        guest::try_write16(destination_buffer.wrapping_add(copied & !1), 0)?;
    }
    Ok(0)
}

/// RtlInitAnsiString: escreve o descritor antes de procurar o NUL.
pub fn initialize_ansi_string(destination: u64, source: u64) -> Result<u32, KernelError> {
    guest::try_write64(destination, 0)?;
    guest::try_write64(destination + 8, source)?;
    if source != 0 {
        let mut current = source;
        let mut length = 0u16;
        while guest::try_read8(current)? != 0 {
            if length < 0xFFFE {
                length += 1;
            }
            current = current.wrapping_add(1);
        }
        guest::try_write16(destination, length)?;
        guest::try_write16(destination + 2, length + 1)?;
    }
    Ok(0)
}
