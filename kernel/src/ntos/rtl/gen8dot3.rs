//! Nomes 8.3 do DOS (RtlIsNameLegalDOS8Dot3 e RtlGenerate8dot3Name).
//!
//! ntoskrnl 10.0.19045, RVA 0x678d00: Name.Length > 24 -> FALSE; o nome vai
//! para OEM em maiúsculas (RtlUpcaseUnicodeStringToCountedOemString no OemName
//! do chamador ou num buffer local de 12 bytes; falha -> FALSE); "." e ".."
//! são legais sem espaços; cada caractere < 0x80 é recusado pelo bitmap de
//! 256 bits em 0x983bb0 (controles e "*+,/:;<=>?[\]|); base de até 8,
//! um ponto com extensão de até 3 sem espaço antes; nada de espaço ou ponto no
//! fim. *NameContainsSpaces recebe se houve espaço.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::{ansi_code_page, oem_code_page};
use crate::rtl::KernelError;

/// O bitmap de caracteres ilegais do ntoskrnl (0x983bb0), conferido byte a byte.
const ILLEGAL_8DOT3: [u32; 8] = [0xFFFF_FFFF, 0xFC00_9C04, 0x3800_0000, 0x1000_0000, 0x0016_0014, 0, 0x4098_D118, 0x1];

fn illegal(byte: u8) -> bool {
    byte < 0x80 && (ILLEGAL_8DOT3[(byte >> 5) as usize] >> (byte & 31)) & 1 != 0
}

/// RtlIsNameLegalDOS8Dot3(Name, OemName, *NameContainsSpaces) -> BOOLEAN.
pub fn is_name_legal_dos_8dot3(name: &UnicodeString, oem_name: Option<&AnsiString>, contains_spaces: Option<&Field<u8>>) -> Result<bool, KernelError> {
    if name.length.get() > 0x18 {
        return Ok(false);
    }
    // Sem OemName, o NT usa um OEM_STRING local de 12 bytes na pilha.
    let local = if oem_name.is_none() { guest::alloc_bytes(AnsiString::SIZE + 0x10) } else { 0 };
    let oem = match oem_name {
        Some(oem) => oem,
        None => {
            if local == 0 {
                return Err(KernelError::with_status("RtlIsNameLegalDOS8Dot3: no memory", 0xC000_0017));
            }
            // SAFETY: o bloco local acabou de ser alocado (OEM_STRING + 16 bytes de buffer).
            let string = unsafe { AnsiString::at(local) };
            string.length.set(0);
            string.maximum_length.set(12);
            string.buffer.set(local + AnsiString::SIZE);
            string
        }
    };
    let status = oem_code_page::unicode_string_to_oem(oem, name, false, true, true)?;
    let bytes = guest::read_bytes(oem.buffer.get(), oem.length.get() as usize);
    if local != 0 {
        guest::free_bytes(local);
    }
    if status & 0x8000_0000 != 0 {
        return Ok(false);
    }
    let report = |spaces: bool| {
        if let Some(cell) = contains_spaces {
            cell.set(spaces as u8);
        }
    };
    if bytes == b"." || bytes == b".." {
        report(false);
        return Ok(true);
    }
    let (mut spaces, mut extension) = (false, false);
    for (index, &byte) in bytes.iter().enumerate() {
        if illegal(byte) {
            return Ok(false);
        }
        spaces |= byte == b' ';
        if byte == b'.' {
            if extension || index == 0 || bytes[index - 1] == b' ' || bytes.len() - index - 1 > 3 {
                return Ok(false);
            }
            extension = true;
        }
        if index >= 8 && !extension {
            return Ok(false);
        }
    }
    if matches!(bytes.last(), Some(b' ') | Some(b'.')) {
        return Ok(false);
    }
    report(spaces);
    Ok(true)
}

// ---- RtlGenerate8dot3Name (rtl-8dot3-names) ----------------------------------
//
// ntoskrnl 10.0.19041: RtlGenerate8dot3Name 0x670180, GetNextWchar 0x670558,
// RtlComputeLfnChecksum 0x670630, RtlIsValidOemCharacter 0x916440.
//
// Primeira chamada (Context.NameLength == 0): o último ponto do nome separa
// a extensão (ponto final não conta); até 6 caracteres de nome e 3 de
// extensão, cada um pelo GetNextWchar (pula controles e espaço, pontos no
// nome, caracteres >= 0x7F sem AllowExtendedCharacters ou sem OEM válido,
// troca os ilegais do FAT por '_' e põe em maiúsculas). Nome com até 2
// caracteres recebe já 4 dígitos hexadecimais do checksum do nome longo; uma
// extensão maior que 3 tem o último caractere trocado por '~'
// (FsRtlSafeExtensions, TRUE no ntoskrnl). Toda chamada incrementa
// LastIndexValue e monta NAME~N.EXT; passando de 4, uma única vez, o nome
// vira 2 caracteres + 4 dígitos do checksum e o índice volta a 1. Quando
// todos os dígitos de N são 9, o nome perde um caractere para o próximo
// índice; nome vazio devolve STATUS_FILE_SYSTEM_LIMITATION. Name8dot3 recebe
// Length e o texto, sem NUL. Os ramos DBCS (NlsMbOemCodePageTag) contam
// bytes da página OEM instalada; com a 437, nunca são tomados.

/// GENERATE_NAME_CONTEXT (ntifs.h, 0x24 bytes): o estado entre as chamadas
/// do mesmo nome longo.
#[repr(C)]
pub struct GenerateNameContext {
    pub checksum: Field<u16>,
    pub checksum_inserted: Field<u8>,
    pub name_length: Field<u8>,
    pub name_buffer: [Field<u16>; 8],
    pub extension_length: Field<u32>,
    pub extension_buffer: [Field<u16>; 4],
    pub last_index_value: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for GenerateNameContext {}

const _: () = {
    assert!(core::mem::size_of::<GenerateNameContext>() == 0x24);
    assert!(core::mem::offset_of!(GenerateNameContext, checksum_inserted) == 0x2);
    assert!(core::mem::offset_of!(GenerateNameContext, name_length) == 0x3);
    assert!(core::mem::offset_of!(GenerateNameContext, name_buffer) == 0x4);
    assert!(core::mem::offset_of!(GenerateNameContext, extension_length) == 0x14);
    assert!(core::mem::offset_of!(GenerateNameContext, extension_buffer) == 0x18);
    assert!(core::mem::offset_of!(GenerateNameContext, last_index_value) == 0x20);
};

/// STATUS_FILE_SYSTEM_LIMITATION: não há mais nomes 8.3 para o índice.
pub const STATUS_FILE_SYSTEM_LIMITATION: u32 = 0xC000_0427;
/// FsRtlSafeExtensions (PAGEDATA 0xd2d04c = 1): extensão longa termina em '~'.
const SAFE_EXTENSIONS: bool = true;

/// NLS_UPCASE: ASCII direto, < 0xC0 inalterado, o resto pela tabela NLS.
fn nls_upcase(unit: u16) -> Result<u16, KernelError> {
    Ok(match unit {
        0x61..=0x7A => unit - 0x20,
        0..=0xBF => unit,
        _ => crate::ntos::rtl::unicode_case::upcase_char(unit)?,
    })
}

/// RtlIsValidOemCharacter: ida e volta pela página OEM e maiúscula; o
/// caractere que cai no DefaultChar não é válido. Devolve a forma maiúscula.
/// O ramo de processo UTF-8 não existe no OpenNT (todo processo recebe a
/// página instalada).
fn valid_oem_character(table: &ansi_code_page::CodePage, unit: u16) -> Result<Option<u16>, KernelError> {
    let code = table.unicode_to_multi_byte(unit)?;
    let upcased = nls_upcase(table.multi_byte_to_unicode(code)?)?;
    let back = table.unicode_to_multi_byte(upcased)?;
    // SBCS compara o byte com sinal estendido (movsx) com o USHORT.
    let compared = if table.double_byte { back } else { back as u8 as i8 as i16 as u16 };
    Ok((compared != table.default_char()?).then_some(upcased))
}

/// GetNextWchar(Name, *Index, SkipDots, AllowExtendedCharacters): o próximo
/// caractere aproveitável, 0 no fim.
fn next_char(table: &ansi_code_page::CodePage, name: &[u16], index: &mut usize, skip_dots: bool, allow_extended: bool) -> Result<u16, KernelError> {
    while *index < name.len() {
        let mut unit = name[*index];
        *index += 1;
        if unit <= 0x20 {
            continue;
        }
        if unit >= 0x7F {
            if !allow_extended {
                continue;
            }
            match valid_oem_character(table, unit)? {
                Some(upcased) => unit = upcased,
                None => continue,
            }
        }
        if unit == b'.' as u16 {
            if skip_dots {
                continue;
            }
        } else if unit < 0x80 && illegal(unit as u8) {
            unit = b'_' as u16;
        }
        if (0x61..=0x7A).contains(&unit) {
            unit -= 0x20;
        }
        return Ok(unit);
    }
    Ok(0)
}

/// RtlComputeLfnChecksum: hash de 16 bits dos WCHARs (h * 37 + c) e o resto
/// de |h * 314159269| (aritmética de 32 bits com sinal) por 1000000007.
pub fn compute_lfn_checksum(name: &[u16]) -> u16 {
    let mut hash = 0u16;
    for &unit in name {
        hash = hash.wrapping_mul(37).wrapping_add(unit);
    }
    let product = (hash as i32).wrapping_mul(314_159_269);
    product.wrapping_abs().wrapping_rem(1_000_000_007) as u16
}

/// Bytes OEM de um caractere já aceito (1, ou 2 para um DBCS).
fn oem_width(table: &ansi_code_page::CodePage, unit: u16) -> Result<u32, KernelError> {
    Ok(if unit > 0x7F && table.unicode_to_multi_byte(unit)? >> 8 != 0 { 2 } else { 1 })
}

fn hex_digit(nibble: u16) -> u16 {
    if nibble > 9 { 0x37 + nibble } else { 0x30 + nibble }
}

/// Primeira chamada: nome (até 6), checksum de nome curto e extensão.
fn split_long_name(table: &ansi_code_page::CodePage, units: &[u16], allow_extended: bool, dbcs: bool, context: &GenerateNameContext) -> Result<(), KernelError> {
    // Último ponto (índice depois dele); ponto final = sem extensão.
    let mut dot = u32::MAX;
    let mut index = 0usize;
    let mut skip_dots = units.first() == Some(&(b'.' as u16));
    loop {
        let unit = next_char(table, units, &mut index, skip_dots, allow_extended)?;
        if unit == 0 {
            break;
        }
        skip_dots = false;
        if unit == b'.' as u16 {
            dot = index as u32;
        }
    }
    if dot == units.len() as u32 {
        dot = u32::MAX;
    }
    let mut index = 0usize;
    let mut bytes = 0u32;
    context.name_length.set(0);
    loop {
        let unit = next_char(table, units, &mut index, true, allow_extended)?;
        let length = context.name_length.get();
        if unit == 0 || index as u32 >= dot || length >= 6 {
            break;
        }
        if dbcs {
            bytes += oem_width(table, unit)?;
            if bytes > 6 {
                break;
            }
        }
        context.name_buffer[length as usize].set(unit);
        context.name_length.set(length + 1);
    }
    if !dbcs {
        bytes = context.name_length.get() as u32;
    }
    if bytes <= 2 {
        let mut checksum = compute_lfn_checksum(units);
        context.checksum.set(checksum);
        let length = context.name_length.get() as usize;
        for slot in 0..4 {
            context.name_buffer[length + slot].set(hex_digit(checksum & 0xF));
            checksum >>= 4;
        }
        context.name_length.set(length as u8 + 4);
        context.checksum_inserted.set(1);
    }
    if dot == u32::MAX {
        context.extension_length.set(0);
        return Ok(());
    }
    context.extension_buffer[0].set(b'.' as u16);
    context.extension_length.set(1);
    let mut index = dot as usize;
    let mut bytes = 1u32;
    loop {
        let unit = next_char(table, units, &mut index, true, allow_extended)?;
        if unit == 0 {
            return Ok(());
        }
        let length = context.extension_length.get();
        let full = length >= 4
            || (dbcs && {
                bytes += oem_width(table, unit)?;
                bytes > 4
            });
        if full {
            if SAFE_EXTENSIONS {
                context.extension_buffer[(length - 1) as usize].set(b'~' as u16);
            }
            return Ok(());
        }
        context.extension_buffer[length as usize].set(unit);
        context.extension_length.set(length + 1);
    }
}

/// RtlGenerate8dot3Name(Name, AllowExtendedCharacters, Context, Name8dot3)
/// -> NTSTATUS.
pub fn generate_8dot3_name(name: &UnicodeString, allow_extended: bool, context: &GenerateNameContext, short_name: &UnicodeString) -> Result<u32, KernelError> {
    let table = oem_code_page::oem()?;
    // Ramos DBCS só numa página OEM multibyte.
    let dbcs = allow_extended && table.double_byte;
    let count = (name.length.get() / 2) as usize;
    let units: alloc::vec::Vec<u16> = guest::read_bytes(name.buffer.get(), count * 2).chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    if context.name_length.get() == 0 {
        split_long_name(&table, &units, allow_extended, dbcs, context)?;
    }
    let mut index = context.last_index_value.get().wrapping_add(1);
    context.last_index_value.set(index);
    if index > 4 && context.checksum_inserted.get() == 0 {
        // Dois primeiros caracteres (um, se algum deles é DBCS) e o checksum.
        let keep = if dbcs { (oem_width(&table, context.name_buffer[0].get())? == 2 || oem_width(&table, context.name_buffer[1].get())? == 2) as u32 } else { 0 };
        let mut checksum = compute_lfn_checksum(&units);
        context.checksum.set(checksum);
        for slot in (2 - keep)..(6 - keep) {
            context.name_buffer[slot as usize].set(hex_digit(checksum & 0xF));
            checksum >>= 4;
        }
        context.name_length.set((6 - keep) as u8);
        context.last_index_value.set(1);
        index = 1;
        context.checksum_inserted.set(1);
    }
    // "~N": até 7 dígitos, do fim de um buffer de 8 WCHARs.
    let mut digits = [0u16; 8];
    let mut count = 1u32;
    let mut all_nines = true;
    while index != 0 && count <= 7 {
        let digit = (index % 10) as u16 + b'0' as u16;
        index /= 10;
        digits[(8 - count) as usize] = digit;
        all_nines &= digit == b'9' as u16;
        count += 1;
    }
    let first = (8 - count) as usize;
    digits[first] = b'~' as u16;
    let mut text: alloc::vec::Vec<u16> = alloc::vec::Vec::new();
    let name_length = context.name_length.get();
    if (1..=12).contains(&name_length) {
        text.extend(context.name_buffer.iter().take(name_length as usize).map(|cell| cell.get()));
    }
    text.extend_from_slice(&digits[first..first + count as usize]);
    text.extend(context.extension_buffer.iter().take(context.extension_length.get() as usize).map(|cell| cell.get()));
    let bytes: alloc::vec::Vec<u8> = text.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(short_name.buffer.get(), &bytes);
    short_name.length.set(bytes.len() as u16);
    if all_nines {
        // O próximo índice ganha um dígito: o nome encolhe.
        let length = context.name_length.get() as u32;
        let shrunk = if dbcs {
            let available = 7 - count;
            let (mut kept, mut used) = (0u32, 0u32);
            while kept < length {
                used += oem_width(&table, context.name_buffer[kept as usize].get())?;
                if used > available {
                    break;
                }
                kept += 1;
            }
            kept
        } else {
            length.wrapping_sub(1)
        };
        context.name_length.set(shrunk as u8);
        if shrunk as u8 == 0 {
            return Ok(STATUS_FILE_SYSTEM_LIMITATION);
        }
    }
    Ok(0)
}
