//! Tabelas de página de código do chamador (CPTABLEINFO), como no ntoskrnl
//! 19041: RtlInitCodePageTable monta a descrição sobre os bytes de uma
//! tabela c_<página>.nls já carregada, e RtlCustomCPToUnicodeN /
//! RtlUnicodeToCustomCPN convertem por ela.
//!
//! Layout da tabela (palavras little-endian): [0] tamanho do cabeçalho em
//! palavras, [1] página, [2] MaximumCharacterSize, [3..6] os caracteres
//! padrão, bytes 0xE..0x1A os LeadByte; a MultiByteTable (256 WCHAR) começa
//! depois do cabeçalho, seguida da tabela de glifos opcional (contagem e
//! 256 WCHAR) e das faixas DBCS (contagem e os deslocamentos por byte
//! inicial); a WideCharTable começa em (cabeçalho + [cabeçalho] + 1)
//! palavras. A página 65001 (ou TableBase NULL) é a pseudo-tabela UTF-8,
//! convertida pelo RtlUTF8ToUnicodeN / RtlUnicodeToUTF8N.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_rtl::CpTableInfo;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::utf8;
use crate::rtl::KernelError;

const CP_UTF8: u16 = 65001;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;

/// RtlInitCodePageTable(TableBase, CodePageTable).
pub fn init_code_page_table(table: u64, info: &CpTableInfo) {
    if table == 0 || guest::read16(table + 2) == CP_UTF8 {
        info.code_page.set(CP_UTF8);
        info.maximum_character_size.set(4);
        info.default_char.set(0x3F);
        info.uni_default_char.set(0xFFFD);
        info.trans_default_char.set(0x3F);
        info.trans_uni_default_char.set(0x3F);
        info.dbcs_code_page.set(0);
        info.multi_byte_table.set(0);
        info.dbcs_ranges.set(0);
        info.dbcs_offsets.set(0);
        return;
    }
    let word = |index: u64| guest::read16(table + index * 2);
    let header = word(0) as u64;
    info.code_page.set(word(1));
    info.maximum_character_size.set(word(2));
    info.default_char.set(word(3));
    info.uni_default_char.set(word(4));
    info.trans_default_char.set(word(5));
    info.trans_uni_default_char.set(word(6));
    for (index, lead) in info.lead_byte.iter().enumerate() {
        lead.set(guest::read8(table + 0xE + index as u64));
    }
    let multi_byte = table + (header + 1) * 2;
    info.multi_byte_table.set(multi_byte);
    let glyphs = multi_byte + 0x200;
    let ranges = glyphs + 2 + if guest::read16(glyphs) != 0 { 0x200 } else { 0 };
    info.dbcs_ranges.set(ranges);
    let double_byte = guest::read16(ranges) != 0;
    info.dbcs_code_page.set(double_byte as u16);
    info.dbcs_offsets.set(if double_byte { ranges + 2 } else { 0 });
    // A WideCharTable fica (word[cabeçalho] + cabeçalho + 1) palavras adiante.
    let wide = (word(header) as u16).wrapping_add(header as u16) as u64 + 1;
    info.wide_char_table.set(table + wide * 2);
}

/// O resultado UTF-8 do original: só STATUS_BUFFER_TOO_SMALL vira
/// STATUS_BUFFER_OVERFLOW; qualquer outro status vira sucesso.
fn utf8_status(status: u32) -> u32 {
    if status == STATUS_BUFFER_TOO_SMALL { STATUS_BUFFER_OVERFLOW } else { 0 }
}

/// RtlCustomCPToUnicodeN(CustomCP, UnicodeString, MaxBytesInUnicodeString,
/// BytesInUnicodeString, CustomCPString, BytesInCustomCPString).
pub fn custom_cp_to_unicode_n(info: &CpTableInfo, destination: u64, maximum: u32, written: Option<&Field<u32>>, source: u64, length: u32) -> Result<u32, KernelError> {
    if info.code_page.get() == CP_UTF8 {
        if length == 0 {
            if let Some(written) = written {
                written.set(0);
            }
            return Ok(0);
        }
        let scratch = guest::alloc_bytes(4);
        let output = written.map_or(scratch, |field| field.address());
        let status = utf8::utf8_to_unicode(destination, maximum, output, source, length);
        guest::free_bytes(scratch);
        return Ok(utf8_status(status?));
    }
    let mut units = maximum >> 1;
    let mut bytes = length;
    let table = info.multi_byte_table.get();
    if info.dbcs_code_page.get() == 0 {
        let count = units.min(bytes);
        if let Some(written) = written {
            written.set(count * 2);
        }
        let text = guest::read_bytes(source, count as usize);
        let output: alloc::vec::Vec<u8> = text.iter().flat_map(|&byte| guest::read16(table + byte as u64 * 2).to_le_bytes()).collect();
        guest::write_bytes(destination, &output);
        return Ok(if units < bytes { STATUS_BUFFER_OVERFLOW } else { 0 });
    }
    let offsets = info.dbcs_offsets.get();
    let (mut cursor, mut output) = (source, destination);
    while units != 0 && bytes != 0 {
        let first = guest::read8(cursor) as u64;
        units -= 1;
        bytes -= 1;
        let offset = guest::read16(offsets + first * 2) as u64;
        let character = if offset != 0 {
            if bytes == 0 {
                // Inicial sem o segundo byte: WCHAR zero e fim.
                guest::write16(output, 0);
                output += 2;
                break;
            }
            cursor += 1;
            bytes -= 1;
            guest::read16(offsets + (guest::read8(cursor) as u64 + offset) * 2)
        } else {
            guest::read16(table + first * 2)
        };
        guest::write16(output, character);
        output += 2;
        cursor += 1;
    }
    if let Some(written) = written {
        written.set((output - destination) as u32);
    }
    Ok(if units < bytes { STATUS_BUFFER_OVERFLOW } else { 0 })
}

/// RtlUnicodeToCustomCPN(CustomCP, CustomCPString, MaxBytesInCustomCPString,
/// BytesInCustomCPString, UnicodeString, BytesInUnicodeString).
pub fn unicode_to_custom_cp_n(info: &CpTableInfo, destination: u64, maximum: u32, written: Option<&Field<u32>>, source: u64, length: u32) -> Result<u32, KernelError> {
    if info.code_page.get() == CP_UTF8 {
        if length == 0 {
            if let Some(written) = written {
                written.set(0);
            }
            return Ok(0);
        }
        let scratch = guest::alloc_bytes(4);
        let output = written.map_or(scratch, |field| field.address());
        let status = utf8::unicode_to_utf8(destination, maximum, output, source, length);
        guest::free_bytes(scratch);
        return Ok(utf8_status(status?));
    }
    let mut units = length >> 1;
    let mut remaining = maximum;
    let table = info.wide_char_table.get();
    if info.dbcs_code_page.get() == 0 {
        let count = units.min(remaining);
        if let Some(written) = written {
            written.set(count);
        }
        let output: alloc::vec::Vec<u8> = (0..count as u64).map(|index| guest::read8(table + guest::read16(source + index * 2) as u64)).collect();
        guest::write_bytes(destination, &output);
        return Ok(if remaining < units { STATUS_BUFFER_OVERFLOW } else { 0 });
    }
    let (mut cursor, mut output) = (source, destination);
    while units != 0 && remaining != 0 {
        let code = guest::read16(table + guest::read16(cursor) as u64 * 2);
        cursor += 2;
        let lead = (code >> 8) as u8;
        if lead != 0 {
            let available = remaining;
            remaining -= 1;
            if available < 2 {
                break;
            }
            guest::write8(output, lead);
            output += 1;
        }
        guest::write8(output, code as u8);
        remaining = remaining.wrapping_sub(1);
        output += 1;
        units -= 1;
    }
    if let Some(written) = written {
        written.set((output - destination) as u32);
    }
    Ok(if remaining < units { STATUS_BUFFER_OVERFLOW } else { 0 })
}

/// O CPTABLEINFO do chamador.
pub fn info_at(address: u64) -> &'static CpTableInfo {
    // SAFETY: PCPTABLEINFO do chamador de kernel.
    unsafe { CpTableInfo::at(address) }
}
