//! Validação dos buffers de EA e de cota que os file systems recebem de
//! chamadores — io\iomgr (IoCheckEaBufferValidity RVA 0x60cf10,
//! IoCheckQuotaBufferValidity RVA 0x893720, ntoskrnl 10.0.19045).
//!
//! As listas são `FILE_FULL_EA_INFORMATION` e `FILE_QUOTA_INFORMATION`
//! (`inc::types::extra_fs_ntfs`). Em erro, `*ErrorOffset` recebe a distância
//! (aritmética de 32 bits, como no NT) da entrada inconsistente ao início do
//! buffer; com o comprimento acima de MAXLONG ou o buffer de cota desalinhado
//! ele recebe zero.
//!
//! O buffer pode ter vindo do modo usuário (o FS repassa o UserBuffer de um
//! IRP_MJ_SET_EA/SET_QUOTA), então cada entrada é sondada (`try_at`/
//! `probe_get`): uma página ausente devolve STATUS_ACCESS_VIOLATION, onde o
//! NT levanta a exceção para o `__try` do chamador. O SID da cota passa pelo
//! RtlValidSid do kernel, que recusa endereços de usuário antes de ler (a
//! mesma recusa do NT, `se::sid::valid`).

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::status::STATUS_ACCESS_VIOLATION;
use crate::ntos::inc::types::extra_fs_ntfs::{FileFullEaInformation, FileQuotaInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::sid;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
pub const STATUS_EA_LIST_INCONSISTENT: u32 = 0x8000_0014;
pub const STATUS_QUOTA_LIST_INCONSISTENT: u32 = 0xC000_0266;

const MAXIMUM_LENGTH: u32 = 0x7FFF_FFFF;
/// NextEntryOffset + Flags + EaNameLength + EaValueLength.
const EA_HEADER: u32 = 8;
/// Cabeçalho mais o NUL do nome.
const EA_FIXED: u32 = 9;
/// Cabeçalho da cota mais o menor SID que o NT aceita olhar (12 bytes).
const QUOTA_MINIMUM: u32 = 0x34;
const QUOTA_ALIGNMENT: u64 = 7;

/// Status de uma sonda que falhou (ACCESS_VIOLATION ou o da sonda).
fn probe_status(error: KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_ACCESS_VIOLATION }
}

fn report(error_offset: &Field<u32>, entry: u64, buffer: u64, status: u32) -> u32 {
    error_offset.set((entry as u32).wrapping_sub(buffer as u32));
    status
}

/// Entrada inconsistente (`Some`) ou lista válida (`None`).
fn first_bad_ea(buffer: u64, length: u32) -> Result<Option<u64>, KernelError> {
    let mut entry = buffer;
    let mut remaining = length;
    loop {
        if remaining < EA_HEADER {
            return Ok(Some(entry));
        }
        let ea = FileFullEaInformation::try_at(entry)?;
        let name_length = ea.ea_name_length.probe_get()? as u32;
        let size = name_length + EA_FIXED + ea.ea_value_length.probe_get()? as u32;
        if remaining < size || guest::try_read::<u8>(ea.ea_name[0].address() + name_length as u64)? != 0 {
            return Ok(Some(entry));
        }
        let next = ea.next_entry_offset.probe_get()?;
        if next == 0 {
            return Ok(None);
        }
        if (size + 3) & !3 != next || (next as i32) < 0 || remaining < next {
            return Ok(Some(entry));
        }
        remaining -= next;
        entry += next as u64;
    }
}

/// IoCheckEaBufferValidity(EaBuffer, EaLength, ErrorOffset): cada entrada
/// cabe no que resta, o nome termina em NUL e NextEntryOffset é o tamanho
/// da entrada arredondado a 4 (a última tem NextEntryOffset 0).
pub fn check_ea_buffer_validity(buffer: u64, length: u32, error_offset: &Field<u32>) -> u32 {
    if length > MAXIMUM_LENGTH {
        error_offset.set(0);
        return STATUS_EA_LIST_INCONSISTENT;
    }
    match first_bad_ea(buffer, length) {
        Ok(None) => STATUS_SUCCESS,
        Ok(Some(entry)) => report(error_offset, entry, buffer, STATUS_EA_LIST_INCONSISTENT),
        Err(error) => probe_status(error),
    }
}

fn first_bad_quota(buffer: u64, length: u32) -> Result<Option<u64>, KernelError> {
    let mut entry = buffer;
    let mut remaining = length;
    while remaining >= QUOTA_MINIMUM {
        let quota = FileQuotaInformation::try_at(entry)?;
        let identifier = quota.sid.address();
        if !sid::valid(identifier) {
            break;
        }
        let sid_length = sid::length(identifier);
        let size = sid_length + core::mem::offset_of!(FileQuotaInformation, sid) as u32;
        if remaining < size || quota.sid_length.probe_get()? != sid_length {
            break;
        }
        let next = quota.next_entry_offset.probe_get()?;
        if next == 0 {
            return Ok(None);
        }
        if size > next || next as u64 & QUOTA_ALIGNMENT != 0 || (next as i32) < 0 || remaining < next {
            break;
        }
        remaining -= next;
        entry += next as u64;
    }
    Ok(Some(entry))
}

/// IoCheckQuotaBufferValidity(QuotaBuffer, QuotaLength, ErrorOffset): buffer
/// alinhado a 8, SID válido cujo tamanho bate com SidLength e
/// NextEntryOffset múltiplo de 8 que cobre a entrada.
pub fn check_quota_buffer_validity(buffer: u64, length: u32, error_offset: &Field<u32>) -> u32 {
    if length > MAXIMUM_LENGTH {
        error_offset.set(0);
        return STATUS_EA_LIST_INCONSISTENT;
    }
    if buffer & QUOTA_ALIGNMENT != 0 {
        error_offset.set(0);
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    match first_bad_quota(buffer, length) {
        Ok(None) => STATUS_SUCCESS,
        Ok(Some(entry)) => report(error_offset, entry, buffer, STATUS_QUOTA_LIST_INCONSISTENT),
        Err(error) => probe_status(error),
    }
}
