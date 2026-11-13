//! Página OEM e strings OEM do Rtl — rtl\nls.c (RtlOemToUnicodeN,
//! RtlOemStringTo[Counted]UnicodeString, RtlUnicodeStringTo[Counted]OemString,
//! RtlUpcaseUnicodeStringToCountedOemString, RtlxOemStringToUnicodeSize,
//! RtlUpperString) e os dados NlsMbOemCodePageTag / NlsOemLeadByteInfo.
//!
//! A tabela é a c_437.nls real do volume (a página OEM de en-US, a mesma que o
//! carregador NLS instala), decodificada por `ansi_code_page::parse` e pelas
//! direções Unicode<->MB do `CodePage`. ntoskrnl 10.0.19045:
//!   RtlOemToUnicodeN 0x760380 (SBCS: min(Max/2, OemBytes) WCHARs, Bytes = 2*n,
//!     STATUS_BUFFER_OVERFLOW se truncou)
//!   RtlUnicodeStringToCountedOemString 0x678c40 (tamanho sem NUL; >0xFFFF ->
//!     STATUS_INVALID_PARAMETER_2; RtlpDidUnicodeToOemWork falso ->
//!     STATUS_UNMAPPABLE_CHARACTER)
//!   RtlxOemStringToUnicodeSize 0x760430 (RtlMultiByteToUnicodeSize + 2)
//! NlsMbOemCodePageTag é FALSE e NlsOemLeadByteInfo aponta para
//! NlsOemLeadByteInfoTable (256 USHORT zerados) numa página SBCS — conferido
//! byte a byte no ntoskrnl (0xd2d000 = 0; 0xd2fc20.. = 512 zeros).

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{kernel_data, kernel_pool};
use crate::ntos::rtl::ansi_code_page::{self, CodePage};
use crate::ntos::rtl::unicode_case;
use crate::rtl::{KernelError, SpinLock};

pub const OEM_CODE_PAGE: u32 = 437;
const STATUS_SUCCESS: u32 = 0;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_UNMAPPABLE_CHARACTER: u32 = 0xC000_0162;
const STRING_POOL_TAG: u32 = 0x6772_7453; // 'Strg'

static INSTALLED: SpinLock<Option<Arc<CodePage>>> = SpinLock::new(None);

/// A página OEM instalada (C:\Windows\System32\c_437.nls); ausência é erro real.
pub fn oem() -> Result<Arc<CodePage>, KernelError> {
    if let Some(table) = INSTALLED.lock().clone() {
        return Ok(table);
    }
    let path = alloc::format!("C:\\Windows\\System32\\c_{}.nls", OEM_CODE_PAGE);
    let file = crate::drivers::fs::volume_files::lookup_volume_file(&path).filter(|file| !file.directory()).ok_or_else(|| KernelError::new("NLS: installed OEM code page missing"))?;
    let table = Arc::new(ansi_code_page::parse(file.read_at(0, file.size())?)?);
    if table.code_page != OEM_CODE_PAGE {
        return Err(KernelError::new("NLS: installed OEM code page mismatch"));
    }
    *INSTALLED.lock() = Some(table.clone());
    Ok(table)
}

fn units_from_bytes(bytes: &[u8]) -> Vec<u16> {
    bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()
}

fn bytes_from_units(units: &[u16]) -> Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn units_of(string: &UnicodeString) -> Vec<u16> {
    units_from_bytes(&guest::read_bytes(string.buffer.get(), (string.length.get() & !1) as usize))
}

fn bytes_of(string: &AnsiString) -> Vec<u8> {
    guest::read_bytes(string.buffer.get(), string.length.get() as usize)
}

/// OEM -> Unicode pela tabela (`CodePage::write_unicode`: inicial DBCS isolado
/// vira WCHAR zero, como a ANSI). O tradutor trabalha sobre endereços: os
/// bytes vão e voltam por um rascunho em cópias de bloco.
fn oem_to_units(table: &CodePage, bytes: &[u8]) -> Result<Vec<u16>, KernelError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let scratch = guest::alloc_bytes(bytes.len() as u64 * 3 + 2);
    if scratch == 0 {
        return Err(KernelError::with_status("OEM translation scratch", STATUS_NO_MEMORY));
    }
    let (source, output) = (scratch, scratch + bytes.len() as u64);
    guest::write_bytes(source, bytes);
    let written = table.write_unicode(source, bytes.len() as u64, output, bytes.len() as u64 * 2);
    let units = written.map(|written| units_from_bytes(&guest::read_bytes(output, written as usize)));
    guest::free_bytes(scratch);
    units
}

/// Unicode -> OEM (iniciais DBCS no byte alto do código).
fn units_to_oem(table: &CodePage, units: &[u16]) -> Result<Vec<u8>, KernelError> {
    let mut bytes = Vec::new();
    for &unit in units {
        let code = table.unicode_to_multi_byte(unit)?;
        if code >> 8 != 0 {
            bytes.push((code >> 8) as u8);
        }
        bytes.push(code as u8);
    }
    Ok(bytes)
}

fn allocate_string(bytes: u64) -> u64 {
    pool_allocation::allocate_tagged(1, bytes, STRING_POOL_TAG).unwrap_or(0)
}

/// RtlOemToUnicodeN(UnicodeString, MaxBytesInUnicodeString, *BytesInUnicodeString,
/// OemString, BytesInOemString): `destination`/`source` são os buffers crus (PWCH/PCCH).
pub fn oem_to_unicode_n(destination: u64, maximum_bytes: u32, written: Option<&Field<u32>>, source: u64, length: u32) -> Result<u32, KernelError> {
    let table = oem()?;
    let units = oem_to_units(&table, &guest::read_bytes(source, length as usize))?;
    let capacity = (maximum_bytes / 2) as usize;
    let count = units.len().min(capacity);
    if let Some(written) = written {
        written.set(count as u32 * 2);
    }
    guest::write_bytes(destination, &bytes_from_units(&units[..count]));
    Ok(if capacity < units.len() { STATUS_BUFFER_OVERFLOW } else { STATUS_SUCCESS })
}

/// RtlxOemStringToUnicodeSize: bytes com o terminador.
pub fn oem_string_to_unicode_size(source: &AnsiString) -> Result<u32, KernelError> {
    Ok(oem_to_units(&*oem()?, &bytes_of(source))?.len() as u32 * 2 + 2)
}

/// RtlOemStringToUnicodeString / ...ToCountedUnicodeString(Destination, Source,
/// AllocateDestinationString).
pub fn oem_string_to_unicode(destination: &UnicodeString, source: &AnsiString, allocate: bool, counted: bool) -> Result<u32, KernelError> {
    let units = oem_to_units(&*oem()?, &bytes_of(source))?;
    let bytes = units.len() as u64 * 2;
    let terminator = if counted { 0 } else { 2 };
    if bytes + terminator > 0xFFFE {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if counted && bytes == 0 {
        destination.length.set(0);
        destination.maximum_length.set(0);
        destination.buffer.set(0);
        return Ok(STATUS_SUCCESS);
    }
    destination.length.set(bytes as u16);
    if allocate {
        let buffer = allocate_string(bytes + terminator);
        destination.maximum_length.set((bytes + terminator) as u16);
        destination.buffer.set(buffer);
        if buffer == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
    } else if bytes + terminator > destination.maximum_length.get() as u64 {
        return Ok(STATUS_BUFFER_OVERFLOW);
    }
    let mut payload = bytes_from_units(&units);
    if !counted {
        payload.extend_from_slice(&[0, 0]);
    }
    guest::write_bytes(destination.buffer.get(), &payload);
    Ok(STATUS_SUCCESS)
}

/// RtlpDidUnicodeToOemWork: um DefaultChar OEM que não veio do UniDefaultChar
/// denuncia caractere sem mapeamento.
fn round_trips(table: &CodePage, units: &[u16]) -> Result<bool, KernelError> {
    let default = table.unicode_to_multi_byte(b'?' as u16)?;
    for &unit in units {
        if unit != b'?' as u16 && table.unicode_to_multi_byte(unit)? == default {
            return Ok(false);
        }
    }
    Ok(true)
}

/// RtlUnicodeStringToOemString / ...ToCountedOemString /
/// RtlUpcaseUnicodeStringToCountedOemString(Destination, Source, Allocate).
pub fn unicode_string_to_oem(destination: &AnsiString, source: &UnicodeString, allocate: bool, counted: bool, upcase: bool) -> Result<u32, KernelError> {
    let table = oem()?;
    let mut units = units_of(source);
    if upcase {
        units = unicode_case::upcase_units(&units)?;
    }
    let bytes = units_to_oem(&table, &units)?;
    let terminator = if counted { 0 } else { 1 };
    let size = bytes.len() as u64 + terminator;
    if size > 0xFFFF {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if counted && bytes.is_empty() {
        destination.length.set(0);
        destination.maximum_length.set(0);
        destination.buffer.set(0);
        return Ok(STATUS_SUCCESS);
    }
    destination.length.set(bytes.len() as u16);
    let mut allocated = 0;
    if allocate {
        allocated = allocate_string(size);
        destination.maximum_length.set(size as u16);
        destination.buffer.set(allocated);
        if allocated == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
    } else if size > destination.maximum_length.get() as u64 {
        return Ok(STATUS_BUFFER_OVERFLOW);
    }
    let mut payload = bytes.clone();
    if !counted {
        payload.push(0);
    }
    guest::write_bytes(destination.buffer.get(), &payload);
    if counted && !round_trips(&table, &units)? {
        if allocated != 0 {
            kernel_pool::free(allocated, None)?;
            destination.buffer.set(0);
        }
        return Ok(STATUS_UNMAPPABLE_CHARACTER);
    }
    Ok(STATUS_SUCCESS)
}

/// RtlUpperString(Destination, Source): RtlUpperChar por caractere pela
/// página ANSI (ASCII direto; o resto via Unicode e de volta), cortado em
/// Destination.MaximumLength.
pub fn upper_string(destination: &AnsiString, source: &AnsiString) -> Result<(), KernelError> {
    let table = ansi_code_page::current()?;
    let bytes = bytes_of(source);
    let count = bytes.len().min(destination.maximum_length.get() as usize);
    let mut upper = Vec::with_capacity(count);
    for &byte in bytes.iter().take(count) {
        upper.push(if byte.is_ascii_lowercase() {
            byte - 0x20
        } else if byte < 0x80 {
            byte
        } else {
            let unit = unicode_case::upcase_char(table.multi_byte_to_unicode(byte as u16)?)?;
            let code = table.unicode_to_multi_byte(unit)?;
            if code >> 8 == 0 { code as u8 } else { byte }
        });
    }
    guest::write_bytes(destination.buffer.get(), &upper);
    destination.length.set(count as u16);
    Ok(())
}

/// Célula de NlsMbOemCodePageTag (BOOLEAN; a página 437 é SBCS).
pub fn mb_oem_code_page_tag_address() -> u64 {
    kernel_data::address("NlsMbOemCodePageTag").unwrap_or_else(|error| panic!("NlsMbOemCodePageTag: {error}"))
}

/// Célula de NlsOemLeadByteInfo: o ponteiro é publicado na primeira
/// resolução, para a tabela de 256 USHORT zerados guardada logo depois dele.
pub fn oem_lead_byte_info_address() -> u64 {
    let (address, _) = kernel_data::region("NlsOemLeadByteInfo").unwrap_or_else(|error| panic!("NlsOemLeadByteInfo: {error}"));
    // SAFETY: a célula PUSHORT da região de dados do kernel.
    let pointer = unsafe { Field::<u64>::at(address) };
    let _ = pointer.atomic().compare_exchange(0, address + 8, Ordering::AcqRel, Ordering::Acquire);
    address
}
