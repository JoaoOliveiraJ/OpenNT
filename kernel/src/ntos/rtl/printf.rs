//! Formatação estilo printf da CRT do kernel e da saída de depuração —
//! sprintf, _snprintf, _snprintf_s, _vsnprintf, _snwprintf, _vsnwprintf,
//! swprintf_s, vswprintf_s e vDbgPrintExWithPrefix.
//!
//! O texto sai do formatador comum (`guest_strings::format_guest_text`); as
//! variantes variádicas recebem os argumentos já lidos, as `v*` leem a
//! va_list do convidado. Cada rotina devolve o valor de retorno da CRT.

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::{crt, guest_strings};
use crate::rtl::KernelError;

/// Argumento variádico `index` (zero além dos lidos).
fn variadic(arguments: &[u64]) -> impl FnMut(usize) -> u64 + '_ {
    move |index| arguments.get(index).copied().unwrap_or(0)
}

/// sprintf(buf, fmt, ...): devolve o tamanho do texto.
pub fn sprintf(buffer: u64, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), &mut variadic(arguments), false)?;
    crt::write_c_text(buffer, &text, None);
    Ok(text.len() as u64)
}

/// _snprintf(buf, count, fmt, ...).
pub fn snprintf(buffer: u64, count: u64, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), &mut variadic(arguments), false)?;
    Ok(guest_strings::write_formatted_text(buffer, count, &text, false, false) as u64)
}

/// _vsnprintf(buf, count, fmt, va_list).
pub fn vsnprintf(buffer: u64, count: u64, format: u64, va_list: u64) -> Result<u64, KernelError> {
    let mut arguments = guest_strings::guest_format_arguments(va_list);
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), &mut arguments, false)?;
    Ok(guest_strings::write_formatted_text(buffer, count, &text, false, true) as u64)
}

/// _snprintf_s(buffer, size, count, format, ...): _TRUNCATE (-1) limita ao
/// buffer; truncar com `count` explícito devolve -1.
pub fn snprintf_s(buffer: u64, size: u32, count: i32, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), &mut variadic(arguments), false)?;
    let capacity = size as i64;
    let limit = if count < 0 { capacity - 1 } else { (count as i64).min(capacity - 1) };
    let bytes = text.as_bytes();
    let writable = (bytes.len() as i64).min(limit).max(0);
    for index in 0..writable {
        guest::write8(buffer + index as u64, bytes[index as usize]);
    }
    if capacity > 0 {
        guest::write8(buffer + writable as u64, 0);
    }
    Ok(if writable < bytes.len() as i64 && count >= 0 { (-1i64) as u64 } else { writable as u64 })
}

/// _vsnwprintf(buffer, capacity, format, va_list).
pub fn vsnwprintf(buffer: u64, count: u64, format: u64, va_list: u64) -> Result<u64, KernelError> {
    let format = guest_strings::read_wide_string(format);
    let mut arguments = guest_strings::guest_format_arguments(va_list);
    let text = guest_strings::format_guest_text(&format, &mut arguments, true)?;
    Ok(guest_strings::write_formatted_text(buffer, count, &text, true, true) as u64)
}

/// _snwprintf(wchar_t*, size_t, const wchar_t*, ...): formatador largo
/// (semântica legada: -1 quando a saída não cabe).
pub fn snwprintf(buffer: u64, count: u64, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let text = guest_strings::format_guest_text(&guest_strings::read_wide_string(format), &mut variadic(arguments), true)?;
    Ok(guest_strings::write_formatted_text(buffer, count, &text, true, true) as u64)
}

/// Grava até `capacity - 1` WCHARs e o terminador; -1 quando truncou.
fn write_wide_bounded(buffer: u64, capacity: u64, text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let writable = (units.len() as i64).min(capacity as i64 - 1).max(0) as usize;
    for (index, unit) in units.iter().take(writable).enumerate() {
        guest::write16(buffer + index as u64 * 2, *unit);
    }
    if capacity > 0 {
        guest::write16(buffer + writable as u64 * 2, 0);
    }
    if writable < units.len() {
        (-1i64) as u64
    } else {
        writable as u64
    }
}

/// swprintf_s(buffer, capacity, format, ...).
pub fn swprintf_s(buffer: u64, capacity: u64, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    let text = guest_strings::format_guest_text(&guest_strings::read_wide_string(format), &mut variadic(arguments), true)?;
    Ok(write_wide_bounded(buffer, capacity, &text))
}

/// vswprintf_s(buffer, capacity, format, va_list).
pub fn vswprintf_s(buffer: u64, capacity: u64, format: u64, va_list: u64) -> Result<u64, KernelError> {
    let mut arguments = guest_strings::guest_format_arguments(va_list);
    let text = guest_strings::format_guest_text(&guest_strings::read_wide_string(format), &mut arguments, true)?;
    Ok(write_wide_bounded(buffer, capacity, &text))
}

/// vDbgPrintExWithPrefix: prefixo + texto formatado na serial (sem a quebra
/// de linha final).
pub fn debug_print_with_prefix(prefix: u64, format: u64, va_list: u64) -> Result<(), KernelError> {
    let prefix = if prefix != 0 { guest_strings::read_c_string(prefix) } else { String::new() };
    let mut arguments = guest_strings::guest_format_arguments(va_list);
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), &mut arguments, false)?;
    let text = text.strip_suffix('\n').map(|rest| rest.strip_suffix('\r').unwrap_or(rest)).unwrap_or(&text);
    debug_print!("{}{}", prefix, text);
    Ok(())
}

// ---- sprintf_s e vsprintf_s (crt-formatting) -------------------------------
//
// Contrato do original (vsprintf_s -> soutput_s -> output_s): Buffer,
// SizeOfBuffer e Format não nulos, senão -1; SizeOfBuffer acima de 0x7FFFFFFF
// (exceto SIZE_MAX, que vale 0x7FFFFFFF) recusa com Buffer[0] = 0. O texto vai
// até SizeOfBuffer caracteres e Buffer[Size-1] recebe NUL sempre; se texto +
// NUL não couberem, Buffer[0] = 0 e -1, senão o comprimento sem o NUL. O
// tratador de parâmetro inválido do kernel é `ret`.

/// Corpo comum de sprintf_s/vsprintf_s; devolve o int da CRT estendido.
fn print_secure(buffer: u64, size: u64, format: u64, arguments: &mut dyn FnMut(usize) -> u64) -> Result<u64, KernelError> {
    const FAILED: u64 = -1i64 as u64;
    const MAXIMUM_COUNT: u64 = 0x7FFF_FFFF;
    if buffer == 0 || size == 0 || format == 0 {
        return Ok(FAILED);
    }
    if size > MAXIMUM_COUNT && size != u64::MAX {
        guest::write8(buffer, 0);
        return Ok(FAILED);
    }
    let count = size.min(MAXIMUM_COUNT);
    let text = guest_strings::format_guest_text(&guest_strings::read_c_string(format), arguments, false)?;
    // Texto estreito: cada `char` é um byte (Latin-1).
    let bytes: Vec<u8> = text.chars().map(|character| character as u32 as u8).collect();
    let length = bytes.len() as u64;
    guest::write_bytes(buffer, &bytes[..length.min(count) as usize]);
    guest::write8(buffer.wrapping_add(size).wrapping_sub(1), 0);
    if length < count {
        guest::write8(buffer + length, 0);
        Ok(length)
    } else {
        guest::write8(buffer, 0);
        Ok(FAILED)
    }
}

/// sprintf_s(Buffer, SizeOfBuffer, Format, ...): o va_list começa no quarto
/// argumento.
pub fn sprintf_s(buffer: u64, size: u64, format: u64, arguments: &[u64]) -> Result<u64, KernelError> {
    print_secure(buffer, size, format, &mut variadic(arguments))
}

/// vsprintf_s(Buffer, SizeOfBuffer, Format, ArgList).
pub fn vsprintf_s(buffer: u64, size: u64, format: u64, va_list: u64) -> Result<u64, KernelError> {
    print_secure(buffer, size, format, &mut guest_strings::guest_format_arguments(va_list))
}
