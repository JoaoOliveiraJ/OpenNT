//! Serviço Nt/ZwQueryInformationFile.
//!
//! Os metadados pertencem ao arquivo aberto; dispositivos recebem
//! IRP_MJ_QUERY_INFORMATION e o arquivo fica retido até a conclusão. Os
//! handles de usuário entram com o estado de modo usuário (fase 7).

use alloc::string::String;

use crate::ntos::io::file::information as file_information;
use crate::drivers::fs::volume::VolumeStat;
use crate::ntos::ke::irql;
use crate::ntos::mm::{kernel_pool, paging};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::{previous_mode, user_probe};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::io::file::zw as zw_files;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{
    FileAccessInformation, FileAlignmentInformation, FileAllInformation, FileAttributeTagInformation, FileBasicInformation, FileEaInformation, FileIdInformation, FileInternalInformation, FileModeInformation,
    FileNameInformation, FileNetworkOpenInformation, FileObject, FilePositionInformation, FileStandardInformation, IoStatusBlock, NtStruct,
};

/// Tamanho mínimo, alinhamento e acesso exigido por classe (FILE_INFORMATION_CLASS).
pub const MINIMUM: [u32; 76] = [
    0, 0, 0, 0, 40, 24, 8, 4, 4, 8, 0, 0, 0, 0, 8, 0, 4, 4, 104, 0, 0, 8, 32, 8, 40, 16, 24, 0, 16, 72, 0, 0, 56, 16, 56, 8, 0, 0, 0, 0, 0, 4, 0, 4, 20, 12, 32, 16, 8, 8, 0, 1, 0, 2, 12, 116, 0, 0, 8, 24, 0, 0, 36, 0, 0, 0, 0, 8, 72, 0, 96, 4, 0, 0, 4, 4,
];
pub const ALIGNMENT: [u32; 76] = [
    0, 8, 8, 8, 8, 8, 8, 4, 4, 4, 4, 4, 4, 1, 8, 4, 4, 4, 8, 8, 8, 4, 8, 4, 4, 4, 8, 4, 8, 4, 4, 4, 4, 4, 8, 4, 4, 8, 8, 8, 4, 4, 8, 8, 8, 4, 8, 8, 4, 4, 8, 1, 1, 2, 8, 8, 4, 4, 4, 4, 8, 4, 8, 8, 4, 4, 4, 8, 8, 8, 8, 4, 4, 4, 4, 4,
];
pub const ACCESS: [u32; 76] = [
    0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 128, 0, 0, 0, 0, 128, 128, 128, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128, 0, 0, 0, 0, 0, 128, 128, 1, 1, 128, 0, 128, 0, 0, 0, 128, 0xFFFF_FFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 128, 0, 136, 0, 0, 0, 128, 0,
];
const AV: u32 = 0xC000_0005;
const HANDLE: u32 = 0xC000_0008;
const CLASS: u32 = 0xC000_0003;
const SHORT: u32 = 0xC000_0004;

/// FILE_OBJECT vivo (retido pelo chamador).
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o pedido mantém a referência do FILE_OBJECT.
    unsafe { FileObject::at(file) }
}

/// O buffer aceita a escrita (usuário: sonda; kernel: faixa canônica com
/// páginas presentes e graváveis).
pub fn writable(pointer: u64, length: u64, user: bool) -> bool {
    if user {
        return pointer < crate::ntos::mm::memory_map::USER_PROBE_ADDRESS && user_probe::probe_user_write(pointer, length);
    }
    let Some(end) = pointer.checked_add(length) else { return false };
    if pointer == 0 || (pointer < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let mut at = pointer;
    while at < end {
        if paging::access_flags(at) & 3 != 3 {
            return false;
        }
        at = (at & !4095) + 4096;
    }
    true
}

/// Validação de modo usuário: classe, tamanho, IOSB, alinhamento e buffer.
pub fn validate(mode: u8, class: u32, length: u32, io_status: u64, buffer: u64) -> u32 {
    if mode == 0 {
        return 0;
    }
    let index = class as usize;
    let minimum = MINIMUM.get(index).copied().unwrap_or(0);
    if minimum == 0 {
        return CLASS;
    }
    if length < minimum {
        return SHORT;
    }
    if !writable(io_status, 4, true) {
        return AV;
    }
    if buffer & (ALIGNMENT[index] as u64 - 1) != 0 {
        return 0x8000_0002;
    }
    if writable(buffer, length as u64, true) {
        0
    } else {
        AV
    }
}

/// Handle de arquivo resolvido: FILE_OBJECT, acesso e opções.
#[derive(Clone, Copy, Debug)]
pub struct Selected {
    pub pointer: u64,
    pub access: u32,
    pub options: Option<u32>,
}

/// Handle nativo (Object Manager) ou de arquivo do kernel.
pub fn resolve(handle: u64, user: bool) -> Result<Selected, u32> {
    if let Some(resolved) = open_pointer::resolve(handle, user) {
        let resolved = resolved?;
        if resolved.item.object_type.name != "File" {
            return Err(0xC000_0024);
        }
        return Ok(Selected { pointer: resolved.item.pointer, access: resolved.access, options: None });
    }
    if handle > 0x7FFF_FFFF && handle & 0xFFFF_FFFF_8000_0000 != 0xFFFF_FFFF_8000_0000 {
        return Err(HANDLE);
    }
    match zw_files::query_file_handle(handle, user) {
        Some(Ok((pointer, access, options))) => Ok(Selected { pointer, access, options: Some(options) }),
        Some(Err(status)) => Err(status),
        None => Err(HANDLE),
    }
}

struct Metadata {
    stat: VolumeStat,
    has_stat: bool,
    size: u64,
    name: String,
    position: u64,
    options: u32,
    pending_delete: bool,
    directory: bool,
}

fn metadata(selected: &Selected) -> Result<Option<Metadata>, u32> {
    let pointer = selected.pointer;
    let source = file_objects::source(pointer);
    let backing = zw_files::file_backing(pointer);
    if source.is_none() && backing.is_none() {
        return Ok(None);
    }
    let stat = backing.as_ref().and_then(|(volume, path)| volume.stat(path)).or_else(|| source.as_ref().and_then(|source| source.stat()));
    let size = match &backing {
        Some((volume, path)) => volume.size(path),
        None => stat.as_ref().map(|stat| stat.size).or_else(|| source.as_ref().map(|source| source.size())),
    };
    let Some(size) = size else { return Err(0xC000_0123) };
    let has_stat = stat.is_some();
    let stat = stat.unwrap_or_default();
    let directory = stat.directory || stat.attributes & 0x10 != 0;
    Ok(Some(Metadata {
        name: backing.as_ref().map(|(_, path)| path.clone()).or_else(|| source.as_ref().map(|source| String::from(source.name()))).unwrap_or_default(),
        position: file_at(pointer).current_byte_offset.quad_part.get() as u64,
        options: selected.options.unwrap_or_else(|| zw_files::file_options(pointer)),
        pending_delete: file_at(pointer).delete_pending.get() != 0,
        directory,
        stat,
        has_stat,
        size,
    }))
}

/// Serializa a classe pedida; devolve (status, information).
fn format(info: &Metadata, selected: &Selected, class: u32, buffer: u64, length: u32, mode: u8) -> (u32, Option<u64>) {
    let stat = &info.stat;
    let name: alloc::vec::Vec<u16> = info.name.replace('/', "\\").encode_utf16().collect();
    let name_bytes = name.len() as u32 * 2;
    let name_offset = core::mem::offset_of!(FileNameInformation, file_name) as u32;
    let all_name_offset = core::mem::offset_of!(FileAllInformation, name_information) as u32;
    let needed: u32 = match class {
        4 => FileBasicInformation::SIZE as u32,
        5 => FileStandardInformation::SIZE as u32,
        6 => FileInternalInformation::SIZE as u32,
        7 => FileEaInformation::SIZE as u32,
        8 => FileAccessInformation::SIZE as u32,
        9 => name_offset + name_bytes,
        14 => FilePositionInformation::SIZE as u32,
        16 => FileModeInformation::SIZE as u32,
        17 => FileAlignmentInformation::SIZE as u32,
        18 => all_name_offset + name_offset + name_bytes,
        34 => FileNetworkOpenInformation::SIZE as u32,
        35 => FileAttributeTagInformation::SIZE as u32,
        59 => FileIdInformation::SIZE as u32,
        _ => return (CLASS, None),
    };
    let variable = class == 9 || class == 18;
    let head = if class == 9 { name_offset } else { all_name_offset + name_offset };
    if length < if variable { head } else { needed } {
        return (SHORT, None);
    }
    let written = length.min(needed);
    if !writable(buffer, written as u64, mode != 0) {
        return (AV, None);
    }
    // A resposta inteira é montada num rascunho do kernel com as estruturas
    // do NT e copiada de uma vez: o buffer pode ser de modo usuário, e a
    // cópia sondada devolve ACCESS_VIOLATION se ele sumir no meio.
    let scratch = guest::alloc_bytes(needed.max(8) as u64);
    if scratch == 0 {
        return (0xC000_009A, None);
    }
    let attributes = if info.has_stat { stat.attributes } else if info.directory { 0x10 } else { 0x80 };
    let time = |origin: usize| if stat.times.len() >= 32 { i64::from_le_bytes(stat.times[origin..origin + 8].try_into().unwrap_or([0; 8])) } else { 0 };
    let basic = |basic: &FileBasicInformation| {
        basic.creation_time.quad_part.set(time(0));
        basic.last_access_time.quad_part.set(time(24));
        basic.last_write_time.quad_part.set(time(8));
        basic.change_time.quad_part.set(time(16));
        basic.file_attributes.set(attributes);
    };
    let standard = |standard: &FileStandardInformation| {
        standard.allocation_size.quad_part.set(if info.has_stat { stat.allocated } else { info.size } as i64);
        standard.end_of_file.quad_part.set(info.size as i64);
        standard.number_of_links.set(1);
        standard.delete_pending.set(info.pending_delete as u8);
        standard.directory.set(info.directory as u8);
    };
    let name_information = |information: &FileNameInformation| {
        information.file_name_length.set(name_bytes);
        let units: alloc::vec::Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(information.file_name[0].address(), &units);
    };
    let reference = stat.reference.unwrap_or(0);
    let mode_flags = info.options & 0x103E;
    let alignment = if info.options & 8 != 0 { 511 } else { 0 };
    // SAFETY: rascunho zerado de `needed` bytes, do tamanho da classe pedida.
    unsafe {
        match class {
            4 => basic(FileBasicInformation::at(scratch)),
            5 => standard(FileStandardInformation::at(scratch)),
            6 => FileInternalInformation::at(scratch).index_number.quad_part.set(reference as i64),
            7 => FileEaInformation::at(scratch).ea_size.set(stat.ea_size),
            8 => FileAccessInformation::at(scratch).access_flags.set(selected.access),
            9 => name_information(FileNameInformation::at(scratch)),
            14 => FilePositionInformation::at(scratch).current_byte_offset.quad_part.set(info.position as i64),
            16 => FileModeInformation::at(scratch).mode.set(mode_flags),
            17 => FileAlignmentInformation::at(scratch).alignment_requirement.set(alignment),
            18 => {
                let all = FileAllInformation::at(scratch);
                basic(&all.basic_information);
                standard(&all.standard_information);
                all.internal_information.index_number.quad_part.set(reference as i64);
                all.ea_information.ea_size.set(stat.ea_size);
                all.access_information.access_flags.set(selected.access);
                all.position_information.current_byte_offset.quad_part.set(info.position as i64);
                all.mode_information.mode.set(mode_flags);
                all.alignment_information.alignment_requirement.set(alignment);
                name_information(&all.name_information);
            }
            34 => {
                let open = FileNetworkOpenInformation::at(scratch);
                open.creation_time.quad_part.set(time(0));
                open.last_access_time.quad_part.set(time(24));
                open.last_write_time.quad_part.set(time(8));
                open.change_time.quad_part.set(time(16));
                open.allocation_size.quad_part.set(if info.has_stat { stat.allocated } else { info.size } as i64);
                open.end_of_file.quad_part.set(info.size as i64);
                open.file_attributes.set(if info.has_stat { stat.attributes } else { 0x80 });
            }
            35 => FileAttributeTagInformation::at(scratch).file_attributes.set(if info.has_stat { stat.attributes } else { 0x80 }),
            59 => {
                let serial = zw_files::file_backing(selected.pointer).and_then(|(volume, _)| volume.volume_serial()).unwrap_or(0);
                let id = FileIdInformation::at(scratch);
                id.volume_serial_number.set(serial);
                // FileId: a referência do arquivo, com o número de sequência
                // nos 16 bits altos do primeiro qword.
                let mut identifier = [0u8; 16];
                identifier[..8].copy_from_slice(&reference.to_le_bytes());
                identifier[6..8].copy_from_slice(&stat.sequence.to_le_bytes());
                guest::write_bytes(id.file_id.identifier[0].address(), &identifier);
            }
            _ => {}
        }
    }
    let bytes = guest::read_bytes(scratch, written as usize);
    guest::free_bytes(scratch);
    let copied = if mode != 0 { guest::try_write_bytes(buffer, &bytes).is_ok() } else { guest::write_bytes(buffer, &bytes); true };
    if !copied {
        return (AV, None);
    }
    (if written < needed { 0x8000_0005 } else { 0 }, Some(written as u64))
}

/// NtQueryInformationFile/ZwQueryInformationFile.
pub fn query(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("NtQueryInformationFile requires PASSIVE_LEVEL"));
    }
    let mode = previous_mode::get()?;
    let checked = validate(mode, class, length, io_status, buffer);
    if checked != 0 {
        return Ok(checked);
    }
    if class as usize >= MINIMUM.len() {
        return Ok(CLASS);
    }
    let selected = match resolve(handle, mode != 0) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    if mode != 0 && ACCESS[class as usize] & !selected.access != 0 {
        return Ok(0xC000_0022);
    }
    if !writable(io_status, 16, mode != 0) {
        return Ok(AV);
    }
    let mut retained = false;
    let mut temporary = 0;
    let mut scratch = 0;
    let result = (|| -> Result<u32, KernelError> {
        if selected.pointer != 0 {
            if file_objects::reference(selected.pointer)?.is_none() {
                return Ok(HANDLE);
            }
            retained = true;
        }
        let info = match metadata(&selected) {
            Ok(info) => info,
            Err(status) => return Ok(status),
        };
        let empty = |position: u64| Metadata { stat: VolumeStat::default(), has_stat: false, size: 0, name: String::new(), position, options: selected.options.unwrap_or(0), pending_delete: false, directory: false };
        let (status, information) = if class == 8 {
            format(&empty(0), &selected, class, buffer, length, mode)
        } else if let Some(info) = &info {
            format(info, &selected, class, buffer, length, mode)
        } else if class == 14 && file_at(selected.pointer).flags.get() & 2 != 0 {
            file_information::acquire_file(selected.pointer)?;
            let formatted = format(&empty(file_at(selected.pointer).current_byte_offset.quad_part.get() as u64), &selected, class, buffer, length, mode);
            file_information::release_file(selected.pointer)?;
            formatted
        } else {
            if !writable(buffer, length as u64, mode != 0) {
                return Ok(AV);
            }
            scratch = guest::alloc_bytes(8);
            if scratch == 0 {
                return Ok(0xC000_009A);
            }
            let mut output = buffer;
            if mode != 0 && length != 0 {
                temporary = kernel_pool::allocate(length as u64, kernel_pool::AllocateOptions { paged: false, tag: 0x6651_7249, ..Default::default() }).unwrap_or(0);
                if temporary == 0 {
                    return Ok(0xC000_009A);
                }
                output = temporary;
            }
            // SAFETY: célula de 8 bytes recém-alocada para o ReturnLength.
            let returned = unsafe { Field::<u64>::at(scratch) };
            returned.set(0);
            let status = file_information::query_native(selected.pointer, class, length, output, scratch, false, false, mode)?;
            let information = returned.get() as u32;
            if information > length {
                return Err(KernelError::new("file query driver wrote an invalid completion length"));
            }
            if temporary != 0 && information != 0 && status & 0xC000_0000 != 0xC000_0000 {
                // Buffer de modo usuário: cópia sondada.
                guest::try_write_bytes(buffer, &guest::read_bytes(temporary, information as usize))?;
            }
            (status, Some(information as u64))
        };
        if let Some(information) = information {
            // IoStatusBlock pode ser de modo usuário (sondado acima): escrita sondada.
            guest::try_write::<i32>(io_status + core::mem::offset_of!(IoStatusBlock, status) as u64, status as i32)?;
            guest::try_write::<u64>(io_status + core::mem::offset_of!(IoStatusBlock, information) as u64, information)?;
        }
        Ok(status)
    })();
    if temporary != 0 {
        let _ = kernel_pool::free(temporary, None);
    }
    if scratch != 0 {
        guest::free_bytes(scratch);
    }
    if retained {
        file_objects::dereference(selected.pointer)?;
    }
    result
}
