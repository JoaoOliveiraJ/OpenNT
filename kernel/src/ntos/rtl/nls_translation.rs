//! Traduções entre ANSI e Unicode do Rtl — RtlUnicodeStringToAnsiString,
//! RtlxAnsiStringToUnicodeSize, RtlMultiByteToUnicodeN,
//! RtlAnsiCharToUnicodeChar e RtlUpcaseUnicodeChar.
//!
//! As conversões contadas mapeiam byte a byte (byte baixo de cada WCHAR e
//! byte → WCHAR); RtlAnsiCharToUnicodeChar passa o intervalo alto pela página
//! ANSI instalada, com identidade se o NLS não estiver disponível.

use crate::ntos::inc::types::{Field, NtStruct, String as AnsiString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// Parâmetro de saída escalar do chamador (PULONG, PUCHAR*...).
fn out<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro do chamador, vivo e alinhado.
    unsafe { Field::<T>::at(address) }
}

/// RtlUnicodeStringToAnsiString: byte baixo de cada unidade; aloca quando
/// pedido ou sem buffer de destino.
pub fn unicode_string_to_ansi_string(ansi: u64, unicode: u64, allocate: bool) -> Result<(), KernelError> {
    let units = guest_strings::try_read_unicode_units(unicode)?;
    // SAFETY: PANSI_STRING DestinationString do chamador.
    let mut buffer = unsafe { AnsiString::at(ansi) }.buffer.get();
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(units.len() as u64 + 1);
    }
    let bytes: alloc::vec::Vec<u8> = units.iter().map(|&unit| unit as u8).chain(core::iter::once(0)).collect();
    guest::write_bytes(buffer, &bytes);
    guest_strings::write_string_fields(ansi, units.len() as u16, units.len() as u16 + 1, buffer);
    Ok(())
}

/// RtlxAnsiStringToUnicodeSize: bytes da UNICODE_STRING com terminador.
pub fn ansi_string_to_unicode_size(ansi: u64) -> u64 {
    // SAFETY: PCANSI_STRING do chamador.
    (unsafe { AnsiString::at(ansi) }.length.get() as u64 + 1) * 2
}

/// RtlMultiByteToUnicodeN: byte → WCHAR até caber em `maximum_bytes`; o
/// tamanho pedido conta a origem inteira.
pub fn multi_byte_to_unicode_n(destination: u64, maximum_bytes: u32, needed: u64, source: u64, length: u32) {
    let (maximum, length) = (maximum_bytes as u64, length as u64);
    let capacity = maximum / 2;
    let written = length.min(capacity);
    let units: alloc::vec::Vec<u8> = guest::read_bytes(source, written as usize).into_iter().flat_map(|byte| (byte as u16).to_le_bytes()).collect();
    guest::write_bytes(destination, &units);
    if needed != 0 {
        out::<u32>(needed).set((length * 2) as u32);
    }
}

/// RtlAnsiCharToUnicodeChar(PUCHAR* SourcePtr): traduz um char ANSI pela
/// página de código instalada e avança *SourcePtr (SBCS = 1 byte).
pub fn ansi_char_to_unicode_char(pointer_field: u64) -> u16 {
    let cursor = out::<u64>(pointer_field);
    let source = cursor.get();
    let byte = guest::read8(source);
    cursor.set(source + 1);
    // ASCII é identidade; o intervalo alto passa pela página instalada,
    // com recuo para identidade se o NLS não estiver disponível.
    if byte < 0x80 {
        byte as u16
    } else {
        installed_ansi_char(byte)
    }
}

/// RtlUpcaseUnicodeChar: ASCII e Latin-1 (exceto ÷).
pub fn upcase_unicode_char(code: u16) -> u16 {
    if (0x61..=0x7A).contains(&code) || ((0xE0..=0xFE).contains(&code) && code != 0xF7) { code - 0x20 } else { code }
}

// ---- RtlUnicodeToMultiByteN / RtlUnicodeToMultiByteSize (rtl-strings) -----
//
// Pela WideCharTable da página ANSI instalada (c_1252.nls). O ramo de
// processo UTF-8 do original (RtlpIsUtf8Process: PEB sem AnsiCodePageData)
// não existe no OpenNT, cujos processos recebem a página instalada.

/// RtlUnicodeToMultiByteN(MbString, MaxBytes, BytesWritten*, Unicode,
/// UnicodeBytes): SBCS copia min(MaxBytes, WCHARs) bytes; DBCS grava 1 ou 2
/// bytes por WCHAR e para quando um par não cabe. Sempre STATUS_SUCCESS.
pub fn unicode_to_multi_byte_n(output: u64, maximum: u32, written: u64, source: u64, source_bytes: u32) -> Result<u32, KernelError> {
    let code_page = crate::ntos::rtl::ansi_code_page::current()?;
    let units = source_bytes >> 1;
    if !code_page.double_byte {
        let count = maximum.min(units);
        if written != 0 {
            out::<u32>(written).set(count);
        }
        let text = guest::read_bytes(source, count as usize * 2);
        let mut bytes = alloc::vec::Vec::with_capacity(count as usize);
        for pair in text.chunks_exact(2) {
            bytes.push(code_page.unicode_to_multi_byte(u16::from_le_bytes([pair[0], pair[1]]))? as u8);
        }
        guest::write_bytes(output, &bytes);
        return Ok(0);
    }
    let (mut cursor, mut remaining, mut left, mut unit_pointer) = (output, maximum, units, source);
    while left != 0 && remaining != 0 {
        let code = code_page.unicode_to_multi_byte(guest::read16(unit_pointer))?;
        unit_pointer += 2;
        let lead = (code >> 8) as u8;
        if lead != 0 {
            let available = remaining;
            remaining = remaining.wrapping_sub(1);
            if available < 2 {
                break;
            }
            guest::write8(cursor, lead);
            cursor += 1;
        }
        guest::write8(cursor, code as u8);
        remaining = remaining.wrapping_sub(1);
        cursor += 1;
        left -= 1;
    }
    if written != 0 {
        out::<u32>(written).set((cursor - output) as u32);
    }
    Ok(0)
}

/// RtlUnicodeToMultiByteSize(BytesInMultiByte*, Unicode, UnicodeBytes): SBCS
/// = WCHARs; DBCS soma 2 por WCHAR com inicial. Sempre STATUS_SUCCESS.
pub fn unicode_to_multi_byte_size(output: u64, source: u64, source_bytes: u32) -> Result<u32, KernelError> {
    let code_page = crate::ntos::rtl::ansi_code_page::current()?;
    let units = source_bytes >> 1;
    let mut size = units;
    if code_page.double_byte {
        size = 0;
        for index in 0..units as u64 {
            let code = code_page.unicode_to_multi_byte(guest::read16(source + index * 2))?;
            size += if code >> 8 != 0 { 2 } else { 1 };
        }
    }
    out::<u32>(output).set(size);
    Ok(0)
}

// ---- RtlAnsiCharToUnicodeChar: intervalo alto pela página (correção) -------
//
// O ramo alto de `ansi_char_to_unicode_char` chamava
// `write_unicode(input, 1, output, 1)`: com capacidade de 1 byte nada cabe
// (`written + 2 <= capacity` falha), o WCHAR de saída ficava no zero da
// alocação e todo byte >= 0x80 virava U+0000. O original lê
// NlsAnsiToUnicodeData[byte]; este é esse acesso, sem buffers temporários.

/// NlsAnsiToUnicodeData[byte] da página instalada; identidade se o NLS não
/// estiver disponível (o recuo que `ansi_char_to_unicode_char` documenta).
fn installed_ansi_char(byte: u8) -> u16 {
    crate::ntos::rtl::ansi_code_page::current()
        .ok()
        .and_then(|code_page| code_page.multi_byte_to_unicode(byte as u16).ok())
        .unwrap_or(byte as u16)
}
