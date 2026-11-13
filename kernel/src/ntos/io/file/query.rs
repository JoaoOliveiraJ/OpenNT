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

/// O buffer aceita a escrita (usuário: sonda; kernel: faixa canônica com
/// páginas presentes e graváveis).
pub fn writable(pointer: u64, length: u64, user: bool) -> bool {
    if user {
        return pointer < 0x7FFF_FFFF_0000 && user_probe::probe_user_write(pointer, length);
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
        position: guest::read64(pointer + 0x68),
        options: selected.options.unwrap_or_else(|| zw_files::file_options(pointer)),
        pending_delete: guest::read8(pointer + 0x49) != 0,
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
    let needed: u32 = match class {
        4 => 40,
        5 => 24,
        6 => 8,
        7 => 4,
        8 => 4,
        9 => 4 + name.len() as u32 * 2,
        14 => 8,
        16 => 4,
        17 => 4,
        18 => 100 + name.len() as u32 * 2,
        34 => 56,
        35 => 8,
        59 => 24,
        _ => return (CLASS, None),
    };
    let variable = class == 9 || class == 18;
    let head = if class == 9 { 4 } else { 100 };
    if length < if variable { head } else { needed } {
        return (SHORT, None);
    }
    let written = length.min(needed);
    if !writable(buffer, written as u64, mode != 0) {
        return (AV, None);
    }
    for offset in 0..written as u64 {
        guest::write8(buffer + offset, 0);
    }
    let put32 = |at: u64, value: u32| guest::write32(buffer + at, value);
    let put64 = |at: u64, value: u64| guest::write64(buffer + at, value);
    let attributes = if info.has_stat { stat.attributes } else if info.directory { 0x10 } else { 0x80 };
    let basic = |at: u64| {
        if stat.times.len() >= 32 {
            for (field, origin) in [0usize, 24, 8, 16].iter().enumerate() {
                guest::write_bytes(buffer + at + field as u64 * 8, &stat.times[*origin..*origin + 8]);
            }
        }
        put32(at + 32, attributes);
    };
    let standard = |at: u64| {
        put64(at, if info.has_stat { stat.allocated } else { info.size });
        put64(at + 8, info.size);
        put32(at + 16, 1);
        guest::write8(buffer + at + 20, info.pending_delete as u8);
        guest::write8(buffer + at + 21, info.directory as u8);
    };
    let reference = stat.reference.unwrap_or(0);
    match class {
        4 => basic(0),
        5 => standard(0),
        6 => put64(0, reference),
        7 => put32(0, stat.ea_size),
        8 => put32(0, selected.access),
        14 => put64(0, info.position),
        16 => put32(0, info.options & 0x103E),
        17 => put32(0, if info.options & 8 != 0 { 511 } else { 0 }),
        18 => {
            basic(0);
            standard(40);
            put64(64, reference);
            put32(72, stat.ea_size);
            put32(76, selected.access);
            put64(80, info.position);
            put32(88, info.options & 0x103E);
            put32(92, if info.options & 8 != 0 { 511 } else { 0 });
        }
        34 => {
            basic(0);
            put64(32, if info.has_stat { stat.allocated } else { info.size });
            put64(40, info.size);
            put32(48, if info.has_stat { stat.attributes } else { 0x80 });
        }
        35 => put32(0, if info.has_stat { stat.attributes } else { 0x80 }),
        59 => {
            let serial = zw_files::file_backing(selected.pointer).and_then(|(volume, _)| volume.volume_serial()).unwrap_or(0);
            put64(0, serial);
            put64(8, reference);
            guest::write16(buffer + 14, stat.sequence);
        }
        _ => {}
    }
    if variable {
        let offset = if class == 9 { 0 } else { 96 };
        put32(offset, name.len() as u32 * 2);
        let capacity = (written as u64).saturating_sub(offset + 4) / 2;
        for (index, unit) in name.iter().take(capacity as usize).enumerate() {
            guest::write16(buffer + offset + 4 + index as u64 * 2, *unit);
        }
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
        } else if class == 14 && guest::read32(selected.pointer + 0x50) & 2 != 0 {
            file_information::acquire_file(selected.pointer)?;
            let formatted = format(&empty(guest::read64(selected.pointer + 0x68)), &selected, class, buffer, length, mode);
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
            guest::write64(scratch, 0);
            let status = file_information::query_native(selected.pointer, class, length, output, scratch, false, false, mode)?;
            let information = guest::read32(scratch);
            if information > length {
                return Err(KernelError::new("file query driver wrote an invalid completion length"));
            }
            if temporary != 0 && information != 0 && status & 0xC000_0000 != 0xC000_0000 {
                for offset in 0..information as u64 {
                    guest::write8(buffer + offset, guest::read8(temporary + offset));
                }
            }
            (status, Some(information as u64))
        };
        if let Some(information) = information {
            guest::write32(io_status, status);
            guest::write64(io_status + 8, information);
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
