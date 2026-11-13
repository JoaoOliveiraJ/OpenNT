//! Nomes 8.3 do DOS (RtlIsNameLegalDOS8Dot3).
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
use crate::ntos::rtl::oem_code_page;
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
