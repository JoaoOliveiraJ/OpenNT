//! Validação de buffers de reparse point — `fsrtl` do NT
//! (FsRtlValidateReparsePointBuffer, RVA 0x309a70 no ntoskrnl 19045).
//!
//! Regras na ordem exata do NT:
//! 1. 8 <= BufferLength <= 0x4000 (MAXIMUM_REPARSE_DATA_BUFFER_SIZE), senão
//!    STATUS_IO_REPARSE_DATA_INVALID — antes de qualquer leitura do buffer.
//! 2. Tag: bits 16..27 zerados, maior que IO_REPARSE_TAG_RESERVED_TWO (2),
//!    nunca com só o bit "name surrogate" (bits 31:30 == 01), nunca com os
//!    bits 29:28 ambos ligados, nunca IO_REPARSE_TAG_GLOBAL_REPARSE
//!    (0xA0000019); senão STATUS_IO_REPARSE_TAG_INVALID.
//! 3. BufferLength == ReparseDataLength + 8 (REPARSE_DATA_BUFFER, só tags
//!    Microsoft, bit 31) ou == ReparseDataLength + 0x18
//!    (REPARSE_GUID_DATA_BUFFER). No formato com GUID uma tag não Microsoft
//!    exige GUID não nulo, e MOUNT_POINT/SYMLINK nunca podem usá-lo.
//! 4. MOUNT_POINT: ReparseDataLength >= 8, SubstituteNameOffset == 0,
//!    PrintNameOffset == SubstituteNameLength + 2 e ReparseDataLength ==
//!    SubstituteNameLength + PrintNameLength + 12.
//!    SYMLINK: ReparseDataLength >= 12, cada nome dentro do buffer
//!    (Offset + Length + 0x14 <= ReparseDataLength + 8), comprimentos não
//!    nulos e offsets/comprimentos pares.
//!    Somas de USHORT que estouram devolvem STATUS_INTEGER_OVERFLOW
//!    (RtlUShortAdd).
//! Cada campo só é lido depois das checagens de tamanho que o NT faz antes
//! dele (o buffer pode ser menor que `sizeof(REPARSE_DATA_BUFFER)`).

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_fs_ntfs::{ReparseDataBuffer, ReparseGuidDataBuffer};
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_IO_REPARSE_TAG_INVALID: u32 = 0xC000_0276;
pub const STATUS_IO_REPARSE_DATA_INVALID: u32 = 0xC000_0278;
pub const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;

const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: u32 = 0x4000;
/// REPARSE_DATA_BUFFER_HEADER_SIZE / REPARSE_GUID_DATA_BUFFER_HEADER_SIZE.
const DATA_HEADER_SIZE: u32 = core::mem::offset_of!(ReparseDataBuffer, symbolic_link_reparse_buffer) as u32;
const GUID_HEADER_SIZE: u32 = core::mem::offset_of!(ReparseGuidDataBuffer, data_buffer) as u32;
/// Cabeçalho do SymbolicLinkReparseBuffer até PathBuffer, mais o do buffer.
const SYMLINK_PATH_OFFSET: u32 = 0x14;
/// Cabeçalho do MountPointReparseBuffer mais os dois NULs dos nomes.
const MOUNT_POINT_OVERHEAD: u32 = 0xC;
const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
const IO_REPARSE_TAG_GLOBAL_REPARSE: u32 = 0xA000_0019;
const IO_REPARSE_TAG_RESERVED_TWO: u32 = 2;

/// RtlUShortAdd: soma de USHORT com estouro detectado.
fn ushort_add(a: u16, b: u16) -> Result<u16, u32> {
    a.checked_add(b).ok_or(STATUS_INTEGER_OVERFLOW)
}

fn tag_is_valid(tag: u32) -> bool {
    tag & 0x0FFF_0000 == 0
        && tag > IO_REPARSE_TAG_RESERVED_TWO
        && tag & 0xC000_0000 != 0x4000_0000
        && tag & 0x3000_0000 != 0x3000_0000
        && tag != IO_REPARSE_TAG_GLOBAL_REPARSE
}

fn mount_point(buffer: &ReparseDataBuffer, data_length: u16) -> Result<(), u32> {
    if data_length < 8 {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let names = &buffer.mount_point_reparse_buffer;
    let substitute_length = names.substitute_name_length.get();
    let total = ushort_add(substitute_length, names.print_name_length.get())?;
    let print_offset = ushort_add(substitute_length, 2)?;
    if names.substitute_name_offset.get() != 0 || names.print_name_offset.get() != print_offset || data_length as u32 != total as u32 + MOUNT_POINT_OVERHEAD {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    Ok(())
}

fn symbolic_link(buffer: &ReparseDataBuffer, data_length: u16) -> Result<(), u32> {
    if data_length < 0xC {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let names = &buffer.symbolic_link_reparse_buffer;
    let (substitute_offset, substitute_length) = (names.substitute_name_offset.get(), names.substitute_name_length.get());
    let (print_offset, print_length) = (names.print_name_offset.get(), names.print_name_length.get());
    let substitute_end = ushort_add(substitute_offset, substitute_length)? as u32 + SYMLINK_PATH_OFFSET;
    let print_end = ushort_add(print_offset, print_length)? as u32 + SYMLINK_PATH_OFFSET;
    let total = data_length as u32 + DATA_HEADER_SIZE;
    if total < substitute_end || total < print_end || substitute_length == 0 || print_length == 0 || (substitute_length | print_length | substitute_offset | print_offset) & 1 != 0 {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    Ok(())
}

fn validate(buffer_length: u32, address: u64) -> Result<(), u32> {
    if buffer_length.wrapping_sub(8) > MAXIMUM_REPARSE_DATA_BUFFER_SIZE - 8 {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    // SAFETY: buffer do file system com pelo menos BufferLength (>= 8) bytes;
    // cada campo seguinte só é lido depois da checagem de tamanho que o cobre.
    let buffer = unsafe { ReparseDataBuffer::at(address) };
    let tag = buffer.reparse_tag.get();
    if !tag_is_valid(tag) {
        return Err(STATUS_IO_REPARSE_TAG_INVALID);
    }
    let microsoft = tag & 0x8000_0000 != 0;
    let data_length = buffer.reparse_data_length.get();
    let plain = data_length as u32 + DATA_HEADER_SIZE == buffer_length;
    let with_guid = data_length as u32 + GUID_HEADER_SIZE == buffer_length;
    if !plain && !with_guid || plain && !microsoft {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    if with_guid {
        // SAFETY: BufferLength == ReparseDataLength + 0x18 cobre o GUID.
        let guid = &unsafe { ReparseGuidDataBuffer::at(address) }.reparse_guid;
        let guid_is_null = guest::read_bytes(guid.address(), core::mem::size_of_val(guid)).iter().all(|&byte| byte == 0);
        if (!microsoft && guid_is_null) || tag == IO_REPARSE_TAG_MOUNT_POINT || tag == IO_REPARSE_TAG_SYMLINK {
            return Err(STATUS_IO_REPARSE_DATA_INVALID);
        }
    }
    match tag {
        IO_REPARSE_TAG_MOUNT_POINT => mount_point(buffer, data_length),
        IO_REPARSE_TAG_SYMLINK => symbolic_link(buffer, data_length),
        _ => Ok(()),
    }
}

/// FsRtlValidateReparsePointBuffer(BufferLength, ReparseBuffer) -> NTSTATUS.
/// Recebe o endereço: o NT rejeita BufferLength fora da faixa sem tocar no
/// buffer, então a referência só é criada depois dessa checagem.
pub fn validate_reparse_point_buffer(buffer_length: u32, buffer: u64) -> u32 {
    match validate(buffer_length, buffer) {
        Ok(()) => 0,
        Err(status) => status,
    }
}

// ---- FsRtlIsNonEmptyDirectoryReparsePointAllowed (anexo do grupo fsrtl-misc) ----
//
// FsRtlIsNonEmptyDirectoryReparsePointAllowed (RVA 0x322400) só chama
// RtlIsNonEmptyDirectoryReparsePointAllowed (0x322420), como aqui.

/// Tag cujo reparse point pode ficar num diretório não vazio.
pub fn is_non_empty_directory_reparse_point_allowed(reparse_tag: u32) -> bool {
    crate::ntos::rtl::reparse::is_non_empty_directory_reparse_point_allowed(reparse_tag)
}
