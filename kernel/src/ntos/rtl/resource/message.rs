//! Tabelas de mensagens (RT_MESSAGETABLE): RtlFindMessage.
//!
//! No ntoskrnl 19041 (0x6724a0) o RtlFindMessage procura o recurso
//! [MessageTableId, 1, MessageLanguageId] da imagem, chega aos bytes do
//! recurso (o arquivo de idioma, quando a entrada está nele) e percorre a
//! MESSAGE_RESOURCE_DATA (RtlpFindMessageInTable). Aqui a procura e o acesso
//! aos bytes são os do LdrResFindResource (com o mesmo fallback de idioma e
//! os satélites MUI); a tabela é lida pelas leituras protegidas do
//! resolvedor de recursos.

use core::mem::offset_of;

use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::extra_rtl::{MessageResourceBlock, MessageResourceData};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::resource::{find, memory as resource_memory};
use crate::rtl::KernelError;

const STATUS_MESSAGE_NOT_FOUND: u32 = 0xC000_0109;

/// RtlpFindMessageInTable(Data, Size, MessageId, Entry): o primeiro bloco
/// com LowId <= MessageId <= HighId; as entradas são puladas pelo Length e
/// passar do último byte do recurso é "não achada".
fn find_in_table(data: u64, size: u32, message: u32, entry_output: &Field<u64>) -> Result<u32, KernelError> {
    let last = data + size as u64 - 1;
    let blocks = data + offset_of!(MessageResourceData, blocks) as u64;
    let count = resource_memory::read32(data + offset_of!(MessageResourceData, number_of_blocks) as u64)?;
    for index in 0..count as u64 {
        let block = blocks + index * core::mem::size_of::<MessageResourceBlock>() as u64;
        let low = resource_memory::read32(block + offset_of!(MessageResourceBlock, low_id) as u64)?;
        let high = resource_memory::read32(block + offset_of!(MessageResourceBlock, high_id) as u64)?;
        if message < low || message > high {
            continue;
        }
        let mut entry = data + resource_memory::read32(block + offset_of!(MessageResourceBlock, offset_to_entries) as u64)? as u64;
        for _ in 0..message - low {
            entry += resource_memory::read16(entry)? as u64;
            if entry > last {
                return Ok(STATUS_MESSAGE_NOT_FOUND);
            }
        }
        entry_output.set(entry);
        return Ok(0);
    }
    Ok(STATUS_MESSAGE_NOT_FOUND)
}

/// RtlFindMessage(DllHandle, MessageTableId, MessageLanguageId, MessageId,
/// MessageEntry).
pub fn find_message(image_base: u64, table: u32, language: u32, message: u32, entry_output: &Field<u64>) -> Result<u32, KernelError> {
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(0xC000_009A);
    }
    let status = find::find(image_base, table as u64, 1, language as u64, cells, cells + 8, 0, 0, 0);
    let result = match status {
        Ok(0) => {
            let (data, size) = (guest::read64(cells), guest::read64(cells + 8) as u32);
            if size == 0 { Ok(STATUS_MESSAGE_NOT_FOUND) } else { find_in_table(data, size, message, entry_output) }
        }
        other => other,
    };
    guest::free_bytes(cells);
    result
}
