//! RtlQueryModuleInformation (ntoskrnl 19045, 0x787fb0): a lista de módulos do
//! kernel em RTL_MODULE_BASIC_INFO (8 bytes: ImageBase) ou
//! RTL_MODULE_EXTENDED_INFO (0x110: ImageBase, ImageSize, FileNameOffset,
//! FullPathName[256]), traduzida de SystemModuleInformation (11).
//!
//! Contrato: SizePerModule diferente de 8/0x110 → STATUS_INVALID_PARAMETER_2;
//! buffer desalinhado de 8 → STATUS_INVALID_PARAMETER_3; buffer NULL →
//! STATUS_SUCCESS com `*InformationLength` = módulos × SizePerModule; buffer
//! curto → STATUS_BUFFER_TOO_SMALL, ainda com o tamanho necessário. A consulta
//! começa com 0x130 bytes (um RTL_PROCESS_MODULES) e repete com o tamanho
//! devolvido.

use crate::ntos::ex::system_information;
use crate::ntos::inc::types::extra_fs_ntfs::{RtlModuleBasicInfo, RtlModuleExtendedInfo};
use crate::ntos::inc::types::{Field, NtStruct, RtlProcessModuleInformation, RtlProcessModules};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_2: u32 = 0xC000_00F0;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const SYSTEM_MODULE_INFORMATION: u32 = 11;
const MODULES_OFFSET: u64 = core::mem::offset_of!(RtlProcessModules, modules) as u64;

/// Traduz os módulos de SystemModuleInformation para o vetor do chamador.
fn translate(modules: &RtlProcessModules, buffer: u64, size_per_module: u32) {
    let count = modules.number_of_modules.get() as usize;
    // SAFETY: os `count` registros vêm logo após o cabeçalho no bloco consultado.
    let records = unsafe { RtlProcessModuleInformation::array_at(modules.address() + MODULES_OFFSET, count) };
    if size_per_module == RtlModuleBasicInfo::SIZE as u32 {
        // SAFETY: vetor do chamador com `count` elementos (tamanho conferido antes).
        let entries = unsafe { RtlModuleBasicInfo::array_at(buffer, count) };
        for (entry, record) in entries.iter().zip(records) {
            entry.image_base.set(record.image_base.get());
        }
        return;
    }
    // SAFETY: idem, elementos de 0x110 bytes.
    let entries = unsafe { RtlModuleExtendedInfo::array_at(buffer, count) };
    for (entry, record) in entries.iter().zip(records) {
        entry.basic_info.image_base.set(record.image_base.get());
        entry.image_size.set(record.image_size.get());
        entry.file_name_offset.set(record.offset_to_file_name.get());
        let path = guest::read_bytes(record.full_path_name[0].address(), record.full_path_name.len());
        guest::write_bytes(entry.full_path_name[0].address(), &path);
    }
}

/// RtlQueryModuleInformation(*InformationLength, SizePerModule, InformationBuffer).
pub fn query(information_length: &Field<u32>, size_per_module: u32, buffer: u64) -> Result<u32, KernelError> {
    if size_per_module != RtlModuleExtendedInfo::SIZE as u32 && size_per_module != RtlModuleBasicInfo::SIZE as u32 {
        return Ok(STATUS_INVALID_PARAMETER_2);
    }
    if buffer & 7 != 0 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    let returned = guest::alloc_bytes(4);
    // SAFETY: ULONG ReturnLength alocado acima.
    let returned_length = unsafe { Field::<u32>::at(returned) };
    let mut capacity = RtlProcessModules::SIZE as u32;
    let mut block = guest::alloc_bytes(capacity as u64);
    let status = loop {
        returned_length.set(0);
        let status = system_information::query(SYSTEM_MODULE_INFORMATION, block, capacity, returned)?;
        if status & 0x8000_0000 != 0 && status != STATUS_INFO_LENGTH_MISMATCH {
            break status;
        }
        if buffer == 0 {
            let count = returned_length.get().wrapping_sub(MODULES_OFFSET as u32) / RtlProcessModuleInformation::SIZE as u32;
            information_length.set(count.wrapping_mul(size_per_module));
            break 0;
        }
        if status & 0x8000_0000 != 0 {
            guest::free_bytes(block);
            capacity = returned_length.get();
            block = guest::alloc_bytes(capacity as u64);
            if block == 0 {
                guest::free_bytes(returned);
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            continue;
        }
        // SAFETY: bloco RTL_PROCESS_MODULES preenchido pela consulta.
        let modules = unsafe { RtlProcessModules::at(block) };
        let needed = modules.number_of_modules.get().wrapping_mul(size_per_module);
        let status = if information_length.get() < needed {
            STATUS_BUFFER_TOO_SMALL
        } else {
            translate(modules, buffer, size_per_module);
            0
        };
        information_length.set(needed);
        break status;
    };
    guest::free_bytes(block);
    guest::free_bytes(returned);
    Ok(status)
}
