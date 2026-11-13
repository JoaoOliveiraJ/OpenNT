//! Traduções entre ANSI e Unicode do Rtl — RtlUnicodeStringToAnsiString,
//! RtlxAnsiStringToUnicodeSize, RtlMultiByteToUnicodeN,
//! RtlAnsiCharToUnicodeChar e RtlUpcaseUnicodeChar.
//!
//! As conversões contadas mapeiam byte a byte (byte baixo de cada WCHAR e
//! byte → WCHAR); RtlAnsiCharToUnicodeChar passa o intervalo alto pela página
//! ANSI instalada, com identidade se o NLS não estiver disponível.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// RtlUnicodeStringToAnsiString: byte baixo de cada unidade; aloca quando
/// pedido ou sem buffer de destino.
pub fn unicode_string_to_ansi_string(ansi: u64, unicode: u64, allocate: bool) -> Result<(), KernelError> {
    let units = guest_strings::try_read_unicode_units(unicode)?;
    let mut buffer = guest::read64(ansi + 8);
    if allocate || buffer == 0 {
        buffer = guest::alloc_bytes(units.len() as u64 + 1);
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write8(buffer + index as u64, *unit as u8);
    }
    guest::write8(buffer + units.len() as u64, 0);
    guest_strings::write_string_fields(ansi, units.len() as u16, units.len() as u16 + 1, buffer);
    Ok(())
}

/// RtlxAnsiStringToUnicodeSize: bytes da UNICODE_STRING com terminador.
pub fn ansi_string_to_unicode_size(ansi: u64) -> u64 {
    (guest::read16(ansi) as u64 + 1) * 2
}

/// RtlMultiByteToUnicodeN: byte → WCHAR até caber em `maximum_bytes`; o
/// tamanho pedido conta a origem inteira.
pub fn multi_byte_to_unicode_n(destination: u64, maximum_bytes: u32, needed: u64, source: u64, length: u32) {
    let (maximum, length) = (maximum_bytes as u64, length as u64);
    let capacity = maximum / 2;
    let mut written = 0;
    while written < length && written < capacity {
        guest::write16(destination + written * 2, guest::read8(source + written) as u16);
        written += 1;
    }
    if needed != 0 {
        guest::write32(needed, (length * 2) as u32);
    }
}

/// RtlAnsiCharToUnicodeChar(PUCHAR* SourcePtr): traduz um char ANSI pela
/// página de código instalada e avança *SourcePtr (SBCS = 1 byte).
pub fn ansi_char_to_unicode_char(pointer_field: u64) -> u16 {
    let source = guest::read64(pointer_field);
    let byte = guest::read8(source);
    guest::write64(pointer_field, source + 1);
    // ASCII é identidade; o intervalo alto passa pela página instalada,
    // com recuo para identidade se o NLS não estiver disponível.
    if byte < 0x80 {
        byte as u16
    } else {
        match crate::ntos::rtl::ansi_code_page::current() {
            Ok(code_page) => {
                let input = guest::alloc_bytes(1);
                let output = guest::alloc_bytes(2);
                guest::write8(input, byte);
                let unit = code_page.write_unicode(input, 1, output, 1).ok().map_or(byte as u16, |_| guest::read16(output));
                guest::free_bytes(input);
                guest::free_bytes(output);
                unit
            }
            Err(_) => byte as u16,
        }
    }
}

/// RtlUpcaseUnicodeChar: ASCII e Latin-1 (exceto ÷).
pub fn upcase_unicode_char(code: u16) -> u16 {
    if (0x61..=0x7A).contains(&code) || ((0xE0..=0xFE).contains(&code) && code != 0xF7) { code - 0x20 } else { code }
}
