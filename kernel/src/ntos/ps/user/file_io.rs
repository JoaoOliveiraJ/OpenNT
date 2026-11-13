//! Contratos de arquivo de modo usuário sobre o NTFS persistente.
//!
//! Implementado: abertura/criação pelo volume (validação de disposição,
//! opções, compartilhamento, superseded/overwrite/create, DELETE_ON_CLOSE),
//! NtQueryAttributesFile/NtQueryFullAttributesFile, NtQueryInformationFile e
//! NtReadFile/NtWriteFile de arquivos (e de console). Pendente: o restante do
//! módulo (NtSetInformationFile em diante) e a transferência de
//! dispositivos (`ps/user/device_io`).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::file_objects::{self, UserFile};
use super::registry::parse_user_object_attributes;
use super::state::{self, UserHandle};
use crate::drivers::fs::ntfs::Stat;
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::io::file::lifetime as file_lifetime;
use crate::ntos::ke::dispatcher;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const AV: u32 = 0xC000_0005;
const INVALID: u32 = 0xC000_000D;
const HANDLE: u32 = 0xC000_0008;
const DENIED: u32 = 0xC000_0022;

fn fail<T>(status: u32) -> Result<T, KernelError> {
    Err(KernelError::with_status(alloc::format!("file status 0x{status:x}"), status))
}

fn complete(iosb: u64, status: u32, information: u64) -> u32 {
    guest::write64(iosb, status as u64);
    guest::write64(iosb + 8, information);
    status
}

/// Sonda o IO_STATUS_BLOCK; uma falha com status vira o IOSB e o retorno.
fn run(iosb: u64, operation: impl FnOnce() -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    if !state::probe_user_write(iosb, 16) {
        return Ok(AV);
    }
    match operation() {
        Ok(status) => Ok(status),
        Err(error) => {
            if error.status == 0 {
                debug_print!("[file-io] {}", error.message);
            }
            Ok(complete(iosb, if error.status != 0 { error.status } else { 0xC000_0185 }, 0))
        }
    }
}

/// Genéricos de arquivo mapeados para os direitos específicos.
pub fn access(mask: u32) -> u32 {
    let mut access = mask;
    if access & 0x8000_0000 != 0 {
        access |= 0x12_0089;
    }
    if access & 0x4000_0000 != 0 {
        access |= 0x12_0116;
    }
    if access & 0x2000_0000 != 0 {
        access |= 0x12_00A0;
    }
    if access & 0x1000_0000 != 0 {
        access |= 0x1F_01FF;
    }
    access & 0x0FFF_FFFF
}

/// Handle de arquivo do processo revalidado no volume.
fn object(handle: u64) -> Result<(Arc<UserHandle>, Arc<UserFile>), KernelError> {
    let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "file") else { return fail(HANDLE) };
    let Some(user_file) = user_file_of(&entry) else { return fail(HANDLE) };
    user_file.file.refresh();
    if user_file.file.deleted() {
        return fail(0xC000_0123);
    }
    Ok((entry, user_file))
}

/// A descrição `UserFile` de um handle (pelo registro de aberturas).
fn user_file_of(entry: &UserHandle) -> Option<Arc<UserFile>> {
    let id = entry.downcast::<UserFile>()?.id;
    file_objects::lookup(id)
}

fn size64(pointer: u64) -> Result<u64, KernelError> {
    let low = guest::read32(pointer) as u64;
    let high = guest::read32(pointer + 4) as u64;
    let value = low + (high << 32);
    if high & 0x8000_0000 != 0 || value > (1 << 53) - 1 {
        return fail(INVALID);
    }
    Ok(value)
}

/// Parâmetros de NtCreateFile/NtOpenFile.
#[derive(Clone, Copy, Default)]
pub struct OpenRequest {
    pub access: u32,
    pub share: u32,
    pub options: u32,
    pub allocation_pointer: u64,
    pub attributes: u32,
    pub ea_length: u32,
    pub handle_attributes: u32,
}

/// Abre ou cria o arquivo do volume e publica o handle `file`.
pub fn open(out: u64, name: &str, iosb: u64, disposition: u32, request: &OpenRequest) -> Result<u32, KernelError> {
    run(iosb, || {
        if !state::probe_user_write(out, 8) {
            return fail(AV);
        }
        let granted = access(request.access);
        let (share, options) = (request.share, request.options);
        let directory = options & 1 != 0;
        let non_directory = options & 0x40 != 0;
        if disposition > 5 || share & !7 != 0 || (directory && non_directory) || options & 0x30 == 0x30 || (options & 0x30 != 0 && granted & 0x10_0000 == 0) || (directory && ![1, 2, 3].contains(&disposition)) {
            return fail(INVALID);
        }
        if options & 0x1000 != 0 && granted & 0x1_0000 == 0 {
            return fail(INVALID);
        }
        // EA, oplocks, abertura por id e contextos estendidos exigem
        // contratos próprios: pedidos sem suporte nunca têm sucesso.
        let supported = 1 | 2 | 4 | 8 | 0x10 | 0x20 | 0x40 | 0x800 | 0x1000 | 0x4000 | 0x8000 | 0x2_0000 | 0x20_0000 | 0x40_0000;
        if options & !supported != 0 || request.ea_length != 0 || granted & 0x0200_0000 != 0 {
            debug_print!("[file-io] create unsupported name={} access=0x{:x} options=0x{:x} eaLength={}", name, granted, options, request.ea_length);
            return fail(0xC000_00BB);
        }
        let mut reservation = 0;
        if request.allocation_pointer != 0 {
            if !state::probe_user_read(request.allocation_pointer, 8) {
                return fail(AV);
            }
            reservation = size64(request.allocation_pointer)?;
            if directory && reservation != 0 {
                return fail(INVALID);
            }
        }
        let Some(path) = volume_files::nt_path_to_volume_path(name) else { return fail(0xC000_0033) };
        let volume = volume_files::volume().ok_or_else(|| KernelError::with_status("volume de boot ausente", 0xC000_000E))?;
        let mut file = volume_files::lookup_volume_file(name);
        let mut information = 1u64;
        match file.clone() {
            Some(existing) => {
                let stat = existing.stat();
                if existing.pending_delete() {
                    return fail(0xC000_0056);
                }
                // FILE_DISALLOW_EXCLUSIVE: um somente-leitura existente não
                // abre negando o compartilhamento de leitura.
                if options & 0x2_0000 != 0 && share & 1 == 0 && stat.attributes & 1 != 0 {
                    return fail(DENIED);
                }
                if stat.attributes & 1 != 0 && (granted & 6 != 0 || options & 0x1000 != 0) {
                    return fail(DENIED);
                }
                if directory && !existing.directory() {
                    return fail(0xC000_0103);
                }
                if non_directory && existing.directory() {
                    return fail(0xC000_00BA);
                }
                if disposition == 2 {
                    return fail(0xC000_0035);
                }
                let fixed = volume_files::fixed_volume().ok_or_else(|| KernelError::new("volume de boot ausente"))?;
                let sharing = file_lifetime::validate_open(&file_lifetime::lifetime_volume(fixed), &existing.volume_path(), granted, share);
                if sharing != 0 {
                    return fail(sharing);
                }
                if [0, 4, 5].contains(&disposition) {
                    if existing.directory() || stat.attributes & 1 != 0 {
                        return fail(DENIED);
                    }
                    if if disposition == 0 { granted & 0x1_0000 == 0 } else { granted & 2 == 0 } {
                        return fail(DENIED);
                    }
                    if disposition == 0 {
                        // Descrições abertas mantêm o inode antigo: supersede
                        // nunca vira overwrite em silêncio.
                        if !existing.opens.lock().is_empty() {
                            return fail(0xC000_00BB);
                        }
                        volume.supersede(&path, request.attributes, reservation)?;
                        volume_files::forget(&path);
                        file = volume_files::lookup_volume_file(name);
                        information = 0;
                    } else {
                        volume.overwrite(&path, reservation, request.attributes)?;
                        existing.refresh();
                        information = 3;
                    }
                }
            }
            None => {
                if disposition == 1 || disposition == 4 {
                    let parent = match path.rfind('/') {
                        Some(0) | None => String::from("/"),
                        Some(index) => String::from(&path[..index]),
                    };
                    if volume.stat(&parent)?.is_none() {
                        return fail(0xC000_003A);
                    }
                    return fail(0xC000_0034);
                }
                volume.create(&path, directory, request.attributes, reservation)?;
                file = volume_files::lookup_volume_file(name);
                information = 2;
            }
        }
        let Some(file) = file else { return fail(0xC000_0034) };
        let entry = UserFile::new(file.clone(), granted, share, options, name);
        let aborted = Arc::new(AtomicBool::new(false));
        let destroy = {
            let (entry, file, aborted, volume) = (entry.clone(), file.clone(), aborted.clone(), volume.clone());
            Arc::new(move || {
                file.opens.lock().retain(|&id| id != entry.id);
                if !aborted.load(Ordering::Acquire) && (entry.delete_requested.load(Ordering::Acquire) || entry.delete_on_close.load(Ordering::Acquire)) {
                    file.set_pending_delete(true);
                }
                file_objects::update_delete_state(&file);
                if !file.deleted() && file.opens.lock().is_empty() && file.pending_delete() {
                    let _ = volume.remove(&file.volume_path());
                    volume_files::forget(&file.volume_path());
                    file.set_deleted(true);
                }
                file_objects::forget(entry.id);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        let pointer = file_objects::bind(&entry, destroy)?;
        file.opens.lock().push(entry.id);
        match state::alloc_user_handle(entry.clone(), granted, request.handle_attributes & 2) {
            Ok(handle) => {
                guest::write64(out, handle as u64);
                let status = complete(iosb, 0, information);
                debug_print!("[usermode] arquivo {}{} ({} bytes)", if information == 2 { "criado: " } else { "aberto: " }, name, file.size());
                Ok(status)
            }
            Err(error) => {
                aborted.store(true, Ordering::Release);
                let _ = crate::ntos::ob::objects::file::dereference(pointer);
                Err(error)
            }
        }
    })
}

/// FILE_BASIC_INFORMATION: os quatro tempos na ordem da ABI e os atributos.
fn basic(out: u64, stat: &Stat) -> Result<(), KernelError> {
    for (index, at) in [0usize, 24, 8, 16].iter().enumerate() {
        let slice: Vec<u8> = (0..8).map(|offset| stat.times.get(at + offset).copied().unwrap_or(0)).collect();
        state::write_user_bytes(out + index as u64 * 8, &slice)?;
    }
    guest::write32(out + 32, stat.attributes);
    guest::write32(out + 36, 0);
    Ok(())
}

fn standard(out: u64, file: &VolumeFile) {
    let stat = file.stat();
    guest::write64(out, stat.allocated);
    guest::write64(out + 8, file.size());
    guest::write32(out + 16, 1);
    guest::write8(out + 20, file.pending_delete() as u8);
    guest::write8(out + 21, file.directory() as u8);
    guest::write16(out + 22, 0);
}

fn network(out: u64, file: &VolumeFile) -> Result<(), KernelError> {
    let stat = file.stat();
    basic(out, &stat)?;
    guest::write64(out + 32, stat.allocated);
    guest::write64(out + 40, file.size());
    guest::write32(out + 48, stat.attributes);
    guest::write32(out + 52, 0);
    Ok(())
}

fn query_attributes(attributes: u64, out: u64, length: u64) -> Result<u32, KernelError> {
    if !state::probe_user_read(attributes, 48) || !state::probe_user_write(out, length) {
        return Ok(AV);
    }
    let Some(parsed) = parse_user_object_attributes(attributes) else { return Ok(INVALID) };
    let Some(file) = volume_files::lookup_volume_file(&parsed.path) else {
        debug_print!("[file-io] attributes absent: {}", parsed.path);
        return Ok(0xC000_0034);
    };
    if file.pending_delete() {
        return Ok(0xC000_0056);
    }
    let result = if length == 40 { basic(out, &file.stat()) } else { network(out, &file) };
    Ok(match result {
        Ok(()) => 0,
        Err(error) if error.status != 0 => error.status,
        Err(_) => 0xC000_0185,
    })
}

fn nt_query_attributes_file(attributes: u64, out: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    query_attributes(attributes, out, 40)
}

fn nt_query_full_attributes_file(attributes: u64, out: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    query_attributes(attributes, out, 56)
}

/// NtQueryInformationFile das classes de arquivo do volume.
pub fn nt_query_information_file(handle: u64, iosb: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    run(iosb, || {
        let (entry, user_file) = object(handle)?;
        let file = &user_file.file;
        let class = state::stack_arg32(rsp, 5);
        let name: Vec<u16> = file.volume_path().replace('/', "\\").encode_utf16().collect();
        let name_bytes = name.len() as u64 * 2;
        let need = match class {
            4 => 40,
            5 => 24,
            6 => 8,
            7 => 4,
            8 => 4,
            9 => 4 + name_bytes,
            14 => 8,
            16 => 4,
            17 => 4,
            18 => 100 + name_bytes,
            34 => 56,
            35 => 8,
            59 => 24,
            _ => return fail(0xC000_0003),
        };
        let variable = class == 9 || class == 18;
        if length < if variable { if class == 9 { 4 } else { 100 } } else { need } {
            return fail(0xC000_0004);
        }
        let writable = need.min(length);
        if !state::probe_user_write(out, writable) {
            return fail(AV);
        }
        for offset in 0..writable {
            guest::write8(out + offset, 0);
        }
        let stat = file.stat();
        let handle_access = entry.access();
        let options = user_file.options;
        match class {
            4 => basic(out, &stat)?,
            5 => standard(out, file),
            6 => guest::write64(out, stat.reference),
            7 => guest::write32(out, stat.ea_size),
            8 => guest::write32(out, handle_access),
            14 => guest::write64(out, user_file.position()),
            16 => guest::write32(out, options & 0x103E),
            17 => guest::write32(out, if options & 8 != 0 { 511 } else { 0 }),
            18 => {
                guest::write32(out + 72, stat.ea_size);
                basic(out, &stat)?;
                standard(out + 40, file);
                guest::write64(out + 64, stat.reference);
                guest::write32(out + 76, handle_access);
                guest::write64(out + 80, user_file.position());
                guest::write32(out + 88, options & 0x103E);
                guest::write32(out + 92, if options & 8 != 0 { 511 } else { 0 });
            }
            34 => network(out, file)?,
            35 => guest::write32(out, stat.attributes),
            59 => {
                guest::write32(out, 0x5354_3421);
                guest::write32(out + 4, 0x4A53_534F);
                guest::write64(out + 8, stat.reference);
                guest::write16(out + 14, stat.sequence);
            }
            _ => {}
        }
        if variable {
            let offset = if class == 9 { 0 } else { 96 };
            guest::write32(out + offset, name_bytes as u32);
            let characters = (name.len() as u64).min((length - offset - 4) / 2);
            for (index, unit) in name.iter().take(characters as usize).enumerate() {
                guest::write16(out + offset + 4 + index as u64 * 2, *unit);
            }
        }
        Ok(complete(iosb, if length < need { 0x8000_0005 } else { 0 }, length.min(need)))
    })
}

/// NtReadFile/NtWriteFile: posição síncrona, append-only sem FILE_WRITE_DATA,
/// alinhamento de NO_INTERMEDIATE_BUFFERING e o evento de conclusão.
fn file_transfer(handle: u64, event: u64, apc: u64, rsp: u64, write: bool) -> Result<u32, KernelError> {
    let iosb = state::stack_arg(rsp, 5);
    let out = state::stack_arg(rsp, 6);
    let length = state::stack_arg32(rsp, 7) as u64;
    let pointer = state::stack_arg(rsp, 8);
    run(iosb, || {
        let Some(entry) = state::get_user_handle(handle) else { return fail(HANDLE) };
        if apc != 0 {
            return fail(0xC000_00BB);
        }
        let completion = if event != 0 { state::get_user_handle(event) } else { None };
        if event != 0 && completion.as_ref().is_none_or(|completion| completion.kind() != "event") {
            return fail(HANDLE);
        }
        if !(if write { state::probe_user_read(out, length) } else { state::probe_user_write(out, length) }) {
            return fail(AV);
        }
        if pointer != 0 && !state::probe_user_read(pointer, 8) {
            return fail(AV);
        }
        if entry.kind() == "device" {
            return super::device_io::transfer(&entry, event, iosb, out, length, pointer, write);
        }
        if entry.kind() == "console" && write {
            let text: String = (0..length).map(|offset| guest::read8(out + offset) as char).collect();
            debug_print!("{}", text.trim_end_matches(['\r', '\n']));
            crate::drivers::console::print(text.trim_end_matches(['\r', '\n']));
            return Ok(complete(iosb, 0, length));
        }
        let (entry, user_file) = object(handle)?;
        let file = &user_file.file;
        if file.directory() {
            return fail(0xC000_00BA);
        }
        let handle_access = entry.access();
        if handle_access & if write { 6 } else { 1 } == 0 {
            return fail(DENIED);
        }
        let options = user_file.options;
        let mut offset = if pointer == 0 {
            if options & 0x30 == 0 {
                return fail(INVALID);
            }
            user_file.position()
        } else {
            let high = guest::read32(pointer + 4);
            let low = guest::read32(pointer);
            if high == 0xFFFF_FFFF && low == 0xFFFF_FFFE && options & 0x30 != 0 {
                user_file.position()
            } else if high == 0xFFFF_FFFF && low == 0xFFFF_FFFF && write {
                file.size()
            } else {
                size64(pointer)?
            }
        };
        if write && handle_access & 2 == 0 {
            offset = file.size();
        }
        if options & 8 != 0 && (offset % 512 != 0 || length % 512 != 0 || out % 512 != 0) {
            return fail(INVALID);
        }
        let mut status = 0;
        let mut count = 0u64;
        if length != 0 {
            if write {
                let data: Vec<u8> = (0..length).map(|index| guest::read8(out + index)).collect();
                let volume = volume_files::volume().ok_or_else(|| KernelError::with_status("volume de boot ausente", 0xC000_000E))?;
                count = volume.write(&file.volume_path(), offset, &data)?;
                file.refresh();
            } else if offset >= file.size() {
                status = 0xC000_0011;
            } else {
                let data = file.read_at(offset, length.min(file.size() - offset))?;
                state::write_user_bytes(out, &data)?;
                count = data.len() as u64;
            }
        }
        if status == 0 && options & 0x30 != 0 {
            user_file.set_position(offset + count);
        }
        complete(iosb, status, count);
        if let Some(body) = completion.and_then(|completion| completion.object.native_body()) {
            dispatcher::set_event(body.pointer);
        }
        Ok(status)
    })
}

fn nt_read_file(handle: u64, event: u64, apc: u64, _context: u64, rsp: u64) -> Result<u32, KernelError> {
    file_transfer(handle, event, apc, rsp, false)
}

fn nt_write_file(handle: u64, event: u64, apc: u64, _context: u64, rsp: u64) -> Result<u32, KernelError> {
    file_transfer(handle, event, apc, rsp, true)
}

/// Registra os handlers implementados.
pub fn init() {
    state::register_handler("NtQueryAttributesFile", nt_query_attributes_file);
    state::register_handler("NtQueryFullAttributesFile", nt_query_full_attributes_file);
    state::register_handler("NtQueryInformationFile", nt_query_information_file);
    state::register_handler("NtReadFile", nt_read_file);
    state::register_handler("NtWriteFile", nt_write_file);
    init_part2();
}

// ---- parte 2: NtSetInformationFile, flush, diretórios e volume -------------

fn volume_or_fail() -> Result<Arc<crate::drivers::fs::ntfs::Ntfs>, KernelError> {
    volume_files::volume().ok_or_else(|| KernelError::with_status("volume de boot ausente", 0xC000_000E))
}

/// NtSetInformationFile: tempos/atributos, renomear (com raiz de diretório e
/// renomeação de descendentes), disposição de exclusão, posição, alocação e
/// fim de arquivo.
fn nt_set_information_file(handle: u64, iosb: u64, buffer: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    run(iosb, || {
        let (entry, user_file) = object(handle)?;
        let file = user_file.file.clone();
        let class = state::stack_arg32(rsp, 5);
        let minimum = match class {
            4 => 40,
            10 => 20,
            13 => 1,
            14 => 8,
            19 => 8,
            20 => 8,
            64 => 4,
            65 => 20,
            _ => return fail(0xC000_0003),
        };
        if length < minimum {
            return fail(0xC000_0004);
        }
        if !state::probe_user_read(buffer, length) {
            return fail(AV);
        }
        let handle_access = entry.access();
        match class {
            14 => {
                let position = size64(buffer)?;
                if user_file.options & 8 != 0 && position % 512 != 0 {
                    return fail(INVALID);
                }
                user_file.set_position(position);
            }
            19 | 20 => {
                if handle_access & 2 == 0 {
                    return fail(DENIED);
                }
                let size = size64(buffer)?;
                let volume = volume_or_fail()?;
                if class == 19 {
                    volume.allocate(&file.volume_path(), size)?;
                } else {
                    volume.resize(&file.volume_path(), size)?;
                }
                file.refresh();
            }
            4 => {
                if handle_access & 0x100 == 0 {
                    return fail(DENIED);
                }
                let mut times = [0u8; 32];
                for (index, at) in [0usize, 24, 8, 16].iter().enumerate() {
                    for offset in 0..8 {
                        times[at + offset] = guest::read8(buffer + index as u64 * 8 + offset as u64);
                    }
                }
                volume_or_fail()?.set_basic(&file.volume_path(), Some(&times), guest::read32(buffer + 32))?;
                file.refresh();
            }
            13 | 64 => {
                if handle_access & 0x1_0000 == 0 {
                    return fail(DENIED);
                }
                let flags = if class == 13 { guest::read8(buffer) as u32 } else { guest::read32(buffer) };
                if flags & !1 != 0 {
                    return fail(0xC000_00BB);
                }
                if flags != 0 && file.stat().attributes & 1 != 0 {
                    return fail(0xC000_0121);
                }
                if flags != 0 && file.directory() && volume_or_fail()?.list(&file.volume_path())?.is_some_and(|children| !children.is_empty()) {
                    return fail(0xC000_0101);
                }
                user_file.delete_requested.store(flags != 0, Ordering::Release);
                let any = file.opens.lock().clone().iter().filter_map(|&id| file_objects::lookup(id)).any(|open| open.delete_requested.load(Ordering::Acquire));
                file.set_pending_delete(any);
                file_objects::update_delete_state(&file);
            }
            _ => {
                if handle_access & 0x1_0000 == 0 {
                    return fail(DENIED);
                }
                let flags = if class == 10 { guest::read8(buffer) as u32 } else { guest::read32(buffer) };
                if flags & !1 != 0 {
                    return fail(0xC000_00BB);
                }
                let root = guest::read64(buffer + 8);
                let size = guest::read32(buffer + 16) as u64;
                if size == 0 || size % 2 != 0 || size > length - 20 {
                    return fail(INVALID);
                }
                let units: Vec<u16> = (0..size / 2).map(|index| guest::read16(buffer + 20 + index * 2)).collect();
                let mut name = String::from_utf16_lossy(&units);
                let old = file.volume_path();
                if root != 0 {
                    let (_, parent) = object(root)?;
                    if !parent.file.directory() {
                        return fail(0xC000_0103);
                    }
                    name = alloc::format!("{}/{}", parent.file.volume_path(), name);
                } else if !name.starts_with('\\') && !name.starts_with('/') && name.chars().nth(1) != Some(':') {
                    name = alloc::format!("{}{}", &old[..old.rfind('/').map_or(0, |index| index + 1)], name);
                }
                let Some(target) = volume_files::nt_path_to_volume_path(&name) else { return fail(0xC000_0033) };
                if let Some(existing) = volume_files::lookup_volume_file(&target) {
                    if !Arc::ptr_eq(&existing, &file) && !existing.opens.lock().is_empty() {
                        return fail(0xC000_0043);
                    }
                }
                for id in file.opens.lock().clone() {
                    if id != user_file.id && file_objects::lookup(id).is_some_and(|previous| previous.share & 4 == 0) {
                        return fail(0xC000_0043);
                    }
                }
                volume_or_fail()?.rename(&old, &target, flags != 0)?;
                // Renomear diretório atualiza as descrições descendentes.
                for item in volume_files::retarget(&old, &target) {
                    let nt_path = item.nt_path();
                    for id in item.opens.lock().clone() {
                        if let Some(opened) = file_objects::lookup(id) {
                            *opened.nt_path.lock() = nt_path.clone();
                        }
                    }
                }
            }
        }
        Ok(complete(iosb, 0, 0))
    })
}

fn nt_flush_buffers_file(handle: u64, iosb: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    run(iosb, || {
        let (entry, _) = object(handle)?;
        if entry.access() & (2 | 4 | 0x100) == 0 {
            return fail(DENIED);
        }
        volume_or_fail()?.flush()?;
        Ok(complete(iosb, 0, 0))
    })
}

/// Curingas DOS: `*`, `?`, `<` (DOS_STAR), `>` (DOS_QM), `"` (DOS_DOT);
/// `*.*` equivale a `*`. Sem distinção de caixa.
pub fn matches(pattern: &str, name: &str) -> bool {
    let mut pattern: Vec<char> = pattern.to_uppercase().chars().collect();
    let name: Vec<char> = name.to_uppercase().chars().collect();
    if pattern.iter().collect::<String>() == "*.*" {
        pattern = alloc::vec!['*'];
    }
    let final_dot = name.iter().rposition(|&character| character == '.');
    let mut memo: alloc::collections::BTreeMap<(usize, usize), bool> = alloc::collections::BTreeMap::new();
    fn step(p: usize, n: usize, pattern: &[char], name: &[char], final_dot: Option<usize>, memo: &mut alloc::collections::BTreeMap<(usize, usize), bool>) -> bool {
        if let Some(&known) = memo.get(&(p, n)) {
            return known;
        }
        let result = if p == pattern.len() {
            n == name.len()
        } else {
            match pattern[p] {
                '*' => step(p + 1, n, pattern, name, final_dot, memo) || (n < name.len() && step(p, n + 1, pattern, name, final_dot, memo)),
                '<' => step(p + 1, n, pattern, name, final_dot, memo) || (n < name.len() && final_dot.is_none_or(|dot| n < dot) && step(p, n + 1, pattern, name, final_dot, memo)),
                '>' => {
                    if n == name.len() || name[n] == '.' {
                        step(p + 1, n, pattern, name, final_dot, memo)
                    } else {
                        step(p + 1, n + 1, pattern, name, final_dot, memo)
                    }
                }
                '"' => {
                    if n == name.len() {
                        step(p + 1, n, pattern, name, final_dot, memo)
                    } else {
                        name[n] == '.' && step(p + 1, n + 1, pattern, name, final_dot, memo)
                    }
                }
                character => n < name.len() && (character == '?' || character == name[n]) && step(p + 1, n + 1, pattern, name, final_dot, memo),
            }
        };
        memo.insert((p, n), result);
        result
    }
    step(0, 0, &pattern, &name, final_dot, &mut memo)
}

/// NtQueryDirectoryFile(Ex): enumeração compartilhada pela descrição
/// (padrão fixado na primeira chamada, `.` e `..` fora da raiz), entradas
/// alinhadas a 8 com NextEntryOffset, RETURN_SINGLE_ENTRY, RESTART_SCAN,
/// INDEX_SPECIFIED, NO_SUCH_FILE na primeira e NO_MORE_FILES depois.
fn query_directory(handle: u64, event: u64, apc: u64, rsp: u64, extended: bool) -> Result<u32, KernelError> {
    let iosb = state::stack_arg(rsp, 5);
    let out = state::stack_arg(rsp, 6);
    let length = state::stack_arg32(rsp, 7) as u64;
    run(iosb, || {
        let (entry, user_file) = object(handle)?;
        let file = user_file.file.clone();
        if !file.directory() {
            return fail(0xC000_0103);
        }
        if entry.access() & 1 == 0 {
            return fail(DENIED);
        }
        if apc != 0 {
            return fail(0xC000_00BB);
        }
        let completion = if event != 0 { state::get_user_handle(event) } else { None };
        if event != 0 && completion.as_ref().is_none_or(|completion| completion.kind() != "event") {
            return fail(HANDLE);
        }
        let class = state::stack_arg32(rsp, 8);
        let name_pointer = state::stack_arg(rsp, 10);
        let flags = if extended { state::stack_arg32(rsp, 9) } else { (if state::stack_arg32(rsp, 9) != 0 { 2 } else { 0 }) | (if state::stack_arg32(rsp, 11) != 0 { 1 } else { 0 }) };
        if flags & !0x1B != 0 {
            return fail(0xC000_00BB);
        }
        let start: u64 = match class {
            1 => 64,
            2 => 68,
            3 => 94,
            12 => 12,
            37 => 104,
            38 => 80,
            _ => return fail(0xC000_0003),
        };
        if length < start {
            return fail(0xC000_0004);
        }
        if !state::probe_user_write(out, length) {
            return fail(AV);
        }
        let first = user_file.enumeration.lock().is_none();
        let mut pattern = user_file.enumeration.lock().as_ref().map_or_else(|| String::from("*"), |scan| scan.pattern.clone());
        if first && name_pointer != 0 {
            if !state::probe_user_read(name_pointer, 16) {
                return fail(AV);
            }
            let name_length = guest::read16(name_pointer) as u64;
            let pointer = guest::read64(name_pointer + 8);
            if name_length % 2 != 0 || name_length > 510 {
                return fail(INVALID);
            }
            if !state::probe_user_read(pointer, name_length) {
                return fail(AV);
            }
            let units: Vec<u16> = (0..name_length / 2).map(|index| guest::read16(pointer + index * 2)).collect();
            pattern = String::from_utf16_lossy(&units);
            if pattern.contains(['\\', '/', '\0']) {
                return fail(INVALID);
            }
        }
        let volume = volume_or_fail()?;
        if first || flags & 0x11 != 0 {
            let directory_path = file.volume_path();
            let mut entries: Vec<(String, String)> = volume.list(&directory_path)?.unwrap_or_default().into_iter().map(|path| (String::from(&path[path.rfind('/').map_or(0, |index| index + 1)..]), path)).collect();
            if directory_path != "/" {
                let parent = match directory_path.rfind('/') {
                    Some(0) | None => String::from("/"),
                    Some(index) => String::from(&directory_path[..index]),
                };
                entries.insert(0, (String::from(".."), parent));
                entries.insert(0, (String::from("."), directory_path.clone()));
            }
            let entries = entries.into_iter().filter(|(name, _)| matches(&pattern, name)).collect();
            *user_file.enumeration.lock() = Some(file_objects::Enumeration { pattern: pattern.clone(), entries, cursor: 0 });
        }
        let (entries, mut cursor) = {
            let scan = user_file.enumeration.lock();
            let scan = scan.as_ref().ok_or_else(|| KernelError::new("enumeration lost"))?;
            (scan.entries.clone(), scan.cursor)
        };
        let mut used = 0u64;
        let mut previous: Option<u64> = None;
        let mut status = 0u32;
        while cursor < entries.len() {
            let (name, path) = &entries[cursor];
            let Some(stat) = volume.stat(path)? else {
                cursor += 1;
                continue;
            };
            let units: Vec<u16> = name.encode_utf16().collect();
            let size = start + units.len() as u64 * 2;
            let at = used.div_ceil(8) * 8;
            if at + size > length && used != 0 {
                break;
            }
            if size > length && !first {
                break;
            }
            let take = size.min(length - at);
            for offset in 0..take {
                guest::write8(out + at + offset, 0);
            }
            if let Some(previous) = previous {
                guest::write32(out + previous, (at - previous) as u32);
            }
            if class != 12 {
                for (index, origin) in [0usize, 24, 8, 16].iter().enumerate() {
                    let slice: Vec<u8> = (0..8).map(|offset| stat.times.get(origin + offset).copied().unwrap_or(0)).collect();
                    state::write_user_bytes(out + at + 8 + index as u64 * 8, &slice)?;
                }
                guest::write64(out + at + 40, stat.size);
                guest::write64(out + at + 48, stat.allocated);
                guest::write32(out + at + 56, stat.attributes);
                guest::write32(out + at + 60, units.len() as u32 * 2);
                if [2, 3, 37, 38].contains(&class) {
                    guest::write32(out + at + 64, stat.ea_size);
                }
                if class == 37 || class == 38 {
                    let id = if class == 37 { 96 } else { 72 };
                    guest::write64(out + at + id, stat.reference);
                    guest::write16(out + at + id + 6, stat.sequence);
                }
            } else {
                guest::write32(out + at + 8, units.len() as u32 * 2);
            }
            let characters = (take.saturating_sub(start) / 2) as usize;
            for (index, unit) in units.iter().take(characters).enumerate() {
                guest::write16(out + at + start + index as u64 * 2, *unit);
            }
            used = at + take;
            previous = Some(at);
            if take < size {
                status = 0x8000_0005;
                break;
            }
            cursor += 1;
            if flags & 2 != 0 {
                break;
            }
        }
        if flags & 0x10 == 0 {
            if let Some(scan) = user_file.enumeration.lock().as_mut() {
                scan.cursor = cursor;
            }
        }
        if used == 0 && cursor >= entries.len() {
            status = if first { 0xC000_000F } else { 0x8000_0006 };
        }
        complete(iosb, status, used);
        if let Some(body) = completion.and_then(|completion| completion.object.native_body()) {
            dispatcher::set_event(body.pointer);
        }
        Ok(status)
    })
}

fn nt_query_directory_file(handle: u64, event: u64, apc: u64, _context: u64, rsp: u64) -> Result<u32, KernelError> {
    query_directory(handle, event, apc, rsp, false)
}

fn nt_query_directory_file_ex(handle: u64, event: u64, apc: u64, _context: u64, rsp: u64) -> Result<u32, KernelError> {
    query_directory(handle, event, apc, rsp, true)
}

/// NtQueryVolumeInformationFile: arquivos pelo volume do arquivo. Handles
/// de dispositivo (classe FileFsDevice) entram com `ps/user/files`.
fn nt_query_volume_information_file(handle: u64, iosb: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    run(iosb, || {
        let Some(entry) = state::get_user_handle(handle).filter(|entry| entry.kind() == "file" || entry.kind() == "device") else { return fail(HANDLE) };
        let class = state::stack_arg32(rsp, 5);
        let Some(need) = crate::drivers::fs::volume_information::minimum(class) else { return fail(0xC000_0003) };
        if entry.kind() == "device" && class != 4 {
            return fail(0xC000_0010);
        }
        if length < need as u64 {
            return fail(0xC000_0004);
        }
        if !state::probe_user_write(out, length) {
            return fail(AV);
        }
        if entry.kind() == "device" {
            return fail(0xC000_0010);
        }
        let (_, user_file) = object(handle)?;
        let volume = user_file.file.volume().clone();
        let query: &dyn crate::drivers::fs::volume_information::VolumeQuery = volume.as_ref();
        let result = crate::drivers::fs::volume_information::query(Some(query), class, length as u32)?;
        crate::drivers::fs::volume_information::write(&result, out);
        Ok(complete(iosb, result.status, result.information as u64))
    })
}

/// Registra os handlers da segunda parte.
pub fn init_part2() {
    state::register_handler("NtSetInformationFile", nt_set_information_file);
    state::register_handler("NtFlushBuffersFile", nt_flush_buffers_file);
    state::register_handler("NtQueryDirectoryFile", nt_query_directory_file);
    state::register_handler("NtQueryDirectoryFileEx", nt_query_directory_file_ex);
    state::register_handler("NtQueryVolumeInformationFile", nt_query_volume_information_file);
}
