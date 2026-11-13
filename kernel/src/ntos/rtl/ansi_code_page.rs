//! Página ANSI instalada.
//!
//! Decodifica a tabela NLS real do volume (c_<página>.nls, como o
//! RtlInitCodePageTable); ausência ou corrupção é erro real, sem fallback
//! para ASCII. A conversão ANSI_STRING → UNICODE_STRING usa essa tabela.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::nls_configuration;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{NtStruct, String as AnsiString, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
/// 'Strg', a tag do alocador de strings.
const STRING_POOL_TAG: u32 = 0x6772_7453;

/// Tabela decodificada (a variante de glifos não participa da conversão).
pub struct CodePage {
    pub code_page: u32,
    pub double_byte: bool,
    single: [u16; 256],
    leading: [u16; 256],
    table: Vec<u8>,
    double_byte_offset: usize,
}

fn word(table: &[u8], offset: usize) -> Result<u16, KernelError> {
    table.get(offset..offset + 2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])).ok_or_else(|| KernelError::new("NLS: invalid code-page table offset"))
}

/// Offsets em palavras little-endian, como o RtlInitCodePageTable.
pub fn parse(table: Vec<u8>) -> Result<CodePage, KernelError> {
    let header = word(&table, 0)? as usize;
    let code_page = word(&table, 2)? as u32;
    let maximum_character_size = word(&table, 4)?;
    if header < 13 || ![1, 2].contains(&maximum_character_size) {
        return Err(KernelError::new("NLS: invalid ANSI code-page header"));
    }
    let single_offset = (header + 1) * 2;
    let glyph_offset = single_offset + 512;
    let ranges_offset = glyph_offset + 2 + if word(&table, glyph_offset)? != 0 { 512 } else { 0 };
    let double_byte = word(&table, ranges_offset)? != 0;
    let double_byte_offset = ranges_offset + 2;
    let mut single = [0u16; 256];
    let mut leading = [0u16; 256];
    for value in 0..256 {
        single[value] = word(&table, single_offset + value * 2)?;
        if double_byte {
            let offset = word(&table, double_byte_offset + value * 2)?;
            leading[value] = offset;
            if offset != 0 {
                word(&table, double_byte_offset + (offset as usize + 255) * 2)?;
            }
        }
    }
    Ok(CodePage { code_page, double_byte, single, leading, table, double_byte_offset })
}

impl CodePage {
    /// SBCS: só Length; DBCS: os bytes iniciais contam as unidades WCHAR.
    pub fn unicode_byte_length(&self, source: u64, length: u64) -> u64 {
        if !self.double_byte {
            return length * 2;
        }
        let text = guest::read_bytes(source, length as usize);
        let (mut offset, mut count) = (0, 0);
        while offset < text.len() {
            let first = text[offset];
            offset += 1;
            if self.leading[first as usize] != 0 && offset < text.len() {
                offset += 1;
            }
            count += 1;
        }
        count * 2
    }

    /// String contada (NUL interno é dado); inicial DBCS isolado gera WCHAR zero.
    pub fn write_unicode(&self, source: u64, length: u64, destination: u64, capacity: u64) -> Result<u64, KernelError> {
        // A origem contada só é lida até onde a saída alcança (2 bytes por
        // WCHAR no pior caso de DBCS).
        let text = guest::read_bytes(source, length.min(capacity) as usize);
        let mut output = alloc::vec::Vec::new();
        let mut offset = 0;
        while offset < text.len() && output.len() as u64 + 2 <= capacity {
            let first = text[offset] as usize;
            offset += 1;
            let leading = self.leading[first];
            let mut character = self.single[first];
            if leading != 0 {
                character = 0;
                if offset < text.len() {
                    let second = text[offset] as usize;
                    offset += 1;
                    character = word(&self.table, self.double_byte_offset + (leading as usize + second) * 2)?;
                }
            }
            output.extend_from_slice(&character.to_le_bytes());
        }
        guest::write_bytes(destination, &output);
        Ok(output.len() as u64)
    }
}

static INSTALLED: SpinLock<Option<Arc<CodePage>>> = SpinLock::new(None);

/// A tabela instalada (C:\Windows\System32\c_<página>.nls no volume do sistema).
pub fn current() -> Result<Arc<CodePage>, KernelError> {
    if let Some(table) = INSTALLED.lock().clone() {
        return Ok(table);
    }
    let path = alloc::format!("C:\\Windows\\System32\\c_{}.nls", nls_configuration::ANSI_CODE_PAGE);
    let file = crate::drivers::fs::volume_files::lookup_volume_file(&path).filter(|file| !file.directory()).ok_or_else(|| KernelError::new("NLS: installed ANSI code page missing"))?;
    let table = Arc::new(parse(file.read_at(0, file.size())?)?);
    if table.code_page != nls_configuration::ANSI_CODE_PAGE {
        return Err(KernelError::new("NLS: installed ANSI code page mismatch"));
    }
    *INSTALLED.lock() = Some(table.clone());
    Ok(table)
}

/// RtlAnsiStringToUnicodeString pela página instalada.
pub fn ansi_to_unicode(destination: u64, source: u64, allocate: bool) -> Result<u32, KernelError> {
    // SAFETY: PUNICODE_STRING e PCANSI_STRING do chamador.
    let (destination, source) = unsafe { (UnicodeString::at(destination), AnsiString::at(source)) };
    let length = source.length.get() as u64;
    let buffer = source.buffer.get();
    let code_page = current()?;
    let bytes = code_page.unicode_byte_length(buffer, length);
    let required = bytes + 2;
    // O terminador precisa caber no limite de Length do NT; a recusa vem
    // antes de alterar o descritor de destino.
    if required > 0xFFFE {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    destination.length.set(bytes as u16);
    if allocate {
        // Buffer e MaximumLength publicados mesmo se a alocação falhar.
        destination.maximum_length.set(required as u16);
        let allocated = pool_allocation::allocate_tagged(1, required, STRING_POOL_TAG).unwrap_or(0);
        destination.buffer.set(allocated);
        if allocated == 0 {
            return Ok(STATUS_NO_MEMORY);
        }
    } else if required > destination.maximum_length.get() as u64 {
        return Ok(STATUS_BUFFER_OVERFLOW);
    }
    // Relê os descritores depois das escritas, como o código original.
    let written = code_page.write_unicode(source.buffer.get(), source.length.get() as u64, destination.buffer.get(), destination.length.get() as u64);
    match written {
        Ok(written) => {
            guest::write_bytes(destination.buffer.get() + written, &[0, 0]);
            Ok(0)
        }
        Err(error) => {
            // O __finally original libera a alocação e limpa o Buffer.
            if allocate {
                let _ = kernel_pool::free(destination.buffer.get(), None);
                destination.buffer.set(0);
            }
            Err(error)
        }
    }
}

// ---- Direção Unicode -> MB da página instalada (rtl-strings) ---------------

impl CodePage {
    /// WideCharTable do RtlInitCodePageTable (NlsUnicodeToAnsiData /
    /// NlsUnicodeToMbAnsiData): começa em (cabeçalho + word[cabeçalho] + 1)
    /// words; SBCS guarda um byte por WCHAR e DBCS uma word (byte alto =
    /// inicial). Conferido na c_1252.nls real: cabeçalho 13, word[13] = 259,
    /// tabela no byte 546 com exatamente 65536 bytes (U+20AC -> 0x80,
    /// U+4E00 -> 0x3F).
    pub fn unicode_to_multi_byte(&self, unit: u16) -> Result<u16, KernelError> {
        let header = word(&self.table, 0)? as usize;
        let base = (header + word(&self.table, header * 2)? as usize + 1) * 2;
        if self.double_byte {
            word(&self.table, base + unit as usize * 2)
        } else {
            self.table.get(base + unit as usize).map(|&byte| byte as u16).ok_or_else(|| KernelError::new("NLS: invalid code-page table offset"))
        }
    }

    /// Código MB (byte alto = inicial DBCS, como sai da WideCharTable) de
    /// volta a WCHAR: NlsMbAnsiCodePageTables para iniciais, senão
    /// NlsAnsiToUnicodeData.
    pub fn multi_byte_to_unicode(&self, code: u16) -> Result<u16, KernelError> {
        let leading = if self.double_byte { self.leading[(code >> 8) as usize] } else { 0 };
        if leading != 0 {
            word(&self.table, self.double_byte_offset + (leading as usize + (code & 0xFF) as usize) * 2)
        } else {
            Ok(self.single[(code & 0xFF) as usize])
        }
    }
}
