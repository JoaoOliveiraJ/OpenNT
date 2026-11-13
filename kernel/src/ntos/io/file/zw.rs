//! Serviços de arquivo do kernel — núcleo do `system32/win32/ntoskrnl/zw.js`.
//!
//! ZwCreateFile sobre dispositivos (CREATE IRP pelo I/O Manager) e sobre
//! volumes montados no namespace (disco em memória, NTFS), a tabela de
//! handles de arquivo do kernel publicada na tabela do processo dono, o
//! vínculo FILE_OBJECT → volume/caminho (`file_backing`) e os registros de
//! fechamento consumidos pelo NtClose (`close_record`).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;

use crate::ntos::cm::key::services as key_services;
use crate::drivers::fs::volume::FileSystem;
use crate::drivers::fs::volume_information;
use crate::ntos::io::file::lifetime as file_lifetime;
use crate::ntos::io::io_manager;
use crate::ntos::ob::close::{self, ZwRecord};
use crate::ntos::ob::objects::file::{self as file_objects, FileCallbacks};
use crate::ntos::ob::handle_table::HandleDescription;
use crate::ntos::ob::handles::process::{self as process_handles, Binding};
use crate::ntos::ob::{handle_ids, object_manager};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::inc::nt_abi::{file_object, io_status_block, object_attributes};

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

/// Disposições FILE_* (wdm.h) e resultados em IO_STATUS_BLOCK.Information.
const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_SUPERSEDED: u64 = 0;
const FILE_OPENED: u64 = 1;
const FILE_CREATED: u64 = 2;
const FILE_OVERWRITTEN: u64 = 3;
const FILE_EXISTS: u64 = 4;

/// Origem de uma abertura de arquivo do kernel.
#[derive(Clone)]
pub enum Backing {
    Volume { volume: &'static dyn FileSystem, path: String },
    Device { path: String, handle: u64 },
}

/// Registro de um handle de arquivo do kernel.
#[derive(Clone)]
pub struct FileEntry {
    pub backing: Backing,
    pub file_object: u64,
    pub access: u32,
    pub share: u32,
    pub options: u32,
    pub owner_process: u64,
    pub attributes: u32,
    pub kernel_handle: bool,
    binding: Option<Binding>,
    closed: bool,
    /// Posição da listagem do ZwQueryDirectoryFile (estado por handle).
    scan_index: Option<usize>,
}

/// handle → registro (os handles de arquivo do kernel).
static FILE_HANDLES: SpinLock<BTreeMap<u32, FileEntry>> = SpinLock::new(BTreeMap::new());
/// FILE_OBJECT → (volume, caminho, opções) dos arquivos de volume.
static FILES_BY_OBJECT: SpinLock<BTreeMap<u64, (&'static dyn FileSystem, String, u32)>> = SpinLock::new(BTreeMap::new());

/// NTSTATUS de 32 bits e Information de 64 bits.
pub fn write_io_status(io_status: u64, status: u32, information: u64) {
    if io_status == 0 {
        return;
    }
    guest::write32(io_status + io_status_block::STATUS, status);
    guest::write64(io_status + io_status_block::INFORMATION, information);
}

/// Captura o nome antes de tocar no volume ou nos buffers de saída. Sem
/// RootDirectory o nome NT começa na raiz; um handle de diretório do Object
/// Manager ou de um arquivo-diretório permite nomes relativos.
pub fn file_path_from_object_attributes(attributes: u64) -> Result<String, u32> {
    if attributes == 0 || guest::read32(attributes) != 48 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let root = guest::read64(attributes + 8);
    let name_pointer = guest::read64(attributes + 16);
    if name_pointer != 0 && guest::read16(name_pointer) & 1 != 0 {
        return Err(0xC000_0033);
    }
    let name = if name_pointer != 0 { guest_strings::read_unicode_string(name_pointer) } else { String::new() };
    if root == 0 {
        return if name.starts_with('\\') { Ok(name) } else { Err(0xC000_003B) };
    }
    // Diretórios do Object Manager e diretórios de disco são tipos diferentes.
    if let Ok(opened) = namespace_handles::resolve(root, false) {
        if opened.directory {
            if name.starts_with('\\') {
                return Err(0xC000_003B);
            }
            let root_path = object_manager::path_of(opened.node).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
            return Ok(format!("{}\\{}", root_path.trim_end_matches('\\'), name));
        }
    }
    // Raiz arquivo: os handles de arquivo do kernel (os de usuário entram com o estado de usuário).
    let entry = query_file_handle(root, false).ok_or(STATUS_INVALID_HANDLE)?.map_err(|status| status)?;
    if name.starts_with('\\') {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let Some((volume, path)) = file_backing(entry.0) else { return Err(0xC000_003A) };
    if !volume.stat(&path).is_some_and(|stat| stat.directory) {
        return Err(0xC000_003A);
    }
    let root_path = crate::drivers::fs::native_file_name::from_volume(volume, &path).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    Ok(format!("{}\\{}", root_path.trim_end_matches('\\'), name))
}

/// Resolve os links do namespace até um volume montado.
pub fn resolve_mounted_file(object_name: &str) -> Option<(&'static dyn FileSystem, String)> {
    let (node, rest) = object_manager::resolve(object_name);
    let mount = object_manager::node(node?)?.mount?;
    Some((mount, format!("/{}", rest.unwrap_or_default())))
}

fn release_entry(entry: &FileEntry) {
    match &entry.backing {
        Backing::Device { handle, .. } => {
            let _ = io_manager::close_device(*handle);
        }
        Backing::Volume { .. } => {
            let _ = file_objects::close_handle(entry.file_object);
        }
    }
}

/// Fechamento pela tabela do processo dono (o `close` da descrição).
fn closer(_process: u64, handle: u32) {
    close_file_entry(handle);
}

/// Retira o handle da tabela dona antes de liberar a referência do arquivo.
pub fn close_file_entry(handle: u32) -> u32 {
    let Some(entry) = FILE_HANDLES.lock().get(&(handle & !3)).cloned() else { return STATUS_INVALID_HANDLE };
    let Some(binding) = entry.binding else { return STATUS_INVALID_HANDLE };
    let mut commit = || {
        if let Some(entry) = FILE_HANDLES.lock().get_mut(&(handle & !3)) {
            entry.closed = true;
        }
        FILE_HANDLES.lock().remove(&(handle & !3));
    };
    if !matches!(process_handles::remove(&binding, Some(&mut commit)), Ok(true)) {
        return STATUS_INVALID_HANDLE;
    }
    release_entry(&entry);
    0
}

/// Liga o arquivo à tabela do processo antes de o handle ficar visível.
fn publish_file_handle(mut entry: FileEntry, output: u64, io_status: u64, information: u64) -> Result<u32, KernelError> {
    let handle = match handle_ids::allocate(4) {
        Ok(handle) => handle,
        Err(error) => {
            release_entry(&entry);
            return Err(error);
        }
    };
    let description = HandleDescription { pointer: entry.file_object, type_name: String::from("File"), identity: entry.file_object, native_body: 0, attributes: entry.attributes, access: entry.access };
    let owner = entry.owner_process;
    let mut stored = false;
    let published = {
        let entry_ref = &mut entry;
        let stored_ref = &mut stored;
        let mut commit = |binding: &Binding| -> Result<(), KernelError> {
            entry_ref.binding = Some(*binding);
            FILE_HANDLES.lock().insert(handle, entry_ref.clone());
            *stored_ref = true;
            Ok(())
        };
        process_handles::publish(owner, handle as u64, &description, closer, Some(&mut commit))
    };
    match published {
        Ok(_) => {
            guest::write64(output, handle as u64);
            write_io_status(io_status, 0, information);
            Ok(0)
        }
        Err(error) => {
            if stored {
                close_file_entry(handle);
            } else {
                release_entry(&entry);
            }
            if error.status != status_unsuccessful() {
                write_io_status(io_status, error.status, 0);
                return Ok(error.status);
            }
            Err(error)
        }
    }
}

fn status_unsuccessful() -> u32 {
    0xC000_0001
}

/// Flags do FILE_OBJECT pelas opções de criação (síncrono, alerta,
/// sem buffer intermediário, escrita direta).
fn option_flags(options: u32) -> u32 {
    (if options & 0x30 != 0 { 2 } else { 0 }) | (if options & 0x10 != 0 { 4 } else { 0 }) | (options & 8) | (if options & 2 != 0 { 0x10 } else { 0 })
}

/// ZwCreateFile/ZwOpenFile/IoCreateFile do kernel.
#[allow(clippy::too_many_arguments)]
pub fn create_kernel_file(output: u64, desired_access: u32, attributes_pointer: u64, io_status: u64, share_access: u32, disposition: u32, options: u32) -> Result<u32, KernelError> {
    let object_name = match file_path_from_object_attributes(attributes_pointer) {
        Ok(path) => path,
        Err(status) => return Ok(status),
    };
    let open_flags = guest::read32(attributes_pointer + object_attributes::ATTRIBUTES);
    let owner_process = if open_flags & 0x200 != 0 { process::get_system_process() } else { process::get_current_process() };
    let access = file_objects::access(desired_access);
    // Dispositivo: CREATE IRP pelo I/O Manager.
    if let Some(node) = object_manager::lookup(&object_name).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Device")) {
        let _ = node;
        let opened = io_manager::open_device(&object_name, true);
        let Ok(opened) = opened.map_err(|_| ()).and_then(|opened| if opened.status == 0 { Ok(opened) } else { Err(()) }) else {
            write_io_status(io_status, STATUS_OBJECT_NAME_NOT_FOUND, 0);
            return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
        };
        let flags = opened.file_object + file_object::FLAGS;
        guest::write32(flags, guest::read32(flags) | option_flags(options));
        let entry = FileEntry { backing: Backing::Device { path: object_name, handle: opened.handle }, file_object: opened.file_object, access, share: share_access, options, owner_process, attributes: open_flags & 2, kernel_handle: open_flags & 0x200 != 0, binding: None, closed: false, scan_index: None };
        return publish_file_handle(entry, output, io_status, FILE_OPENED);
    }
    let Some((volume, path)) = resolve_mounted_file(&object_name) else {
        write_io_status(io_status, STATUS_OBJECT_NAME_NOT_FOUND, 0);
        return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
    };
    let exists = volume.exists(&path);
    let writable = volume.writable();
    let lifetime = file_lifetime::lifetime_volume(volume);
    // Exclusão pendente e compartilhamento pertencem ao arquivo.
    let sharing = file_lifetime::validate_open(&lifetime, &path, access, share_access);
    if sharing != 0 {
        write_io_status(io_status, sharing, 0);
        return Ok(sharing);
    }
    let not_found = |io_status: u64| {
        write_io_status(io_status, STATUS_OBJECT_NAME_NOT_FOUND, 0);
        Ok(STATUS_OBJECT_NAME_NOT_FOUND)
    };
    let information = match disposition {
        FILE_SUPERSEDE => {
            if !writable {
                return Ok(STATUS_MEDIA_WRITE_PROTECTED);
            }
            volume.truncate(&path)?;
            if exists {
                FILE_SUPERSEDED
            } else {
                FILE_CREATED
            }
        }
        FILE_OPEN => {
            if !exists {
                return not_found(io_status);
            }
            FILE_OPENED
        }
        FILE_CREATE => {
            if exists {
                FILE_EXISTS
            } else {
                if !writable {
                    return Ok(STATUS_MEDIA_WRITE_PROTECTED);
                }
                volume.truncate(&path)?;
                FILE_CREATED
            }
        }
        FILE_OPEN_IF => {
            if exists {
                FILE_OPENED
            } else {
                if !writable {
                    return Ok(STATUS_MEDIA_WRITE_PROTECTED);
                }
                volume.truncate(&path)?;
                FILE_CREATED
            }
        }
        FILE_OVERWRITE | FILE_OVERWRITE_IF => {
            if !writable {
                return Ok(STATUS_MEDIA_WRITE_PROTECTED);
            }
            if disposition == FILE_OVERWRITE && !exists {
                return not_found(io_status);
            }
            volume.truncate(&path)?;
            if exists {
                FILE_OVERWRITTEN
            } else {
                FILE_CREATED
            }
        }
        _ => return Ok(STATUS_INVALID_PARAMETER),
    };
    let file = file_objects::create(0, &object_name)?;
    guest::write8(file + 0x4A, (access & 1 != 0) as u8);
    guest::write8(file + 0x4B, (access & 6 != 0) as u8);
    guest::write8(file + 0x4C, (access & 0x10000 != 0) as u8);
    for bit in 0..3 {
        guest::write8(file + 0x4D + bit, ((share_access >> bit) & 1) as u8);
    }
    guest::write32(file + file_object::FLAGS, option_flags(options));
    FILES_BY_OBJECT.lock().insert(file, (volume, path.clone(), options));
    file_objects::set_callbacks(file, FileCallbacks { destroy: Some(Arc::new(move || { FILES_BY_OBJECT.lock().remove(&file); })), ..Default::default() })?;
    file_lifetime::bind(file_lifetime::Entry { access, share: share_access, file_object: file, file: None }, &lifetime, &path)?;
    file_objects::open_handle(file)?;
    file_objects::dereference(file)?;
    let entry = FileEntry { backing: Backing::Volume { volume, path }, file_object: file, access, share: share_access, options, owner_process, attributes: open_flags & 2, kernel_handle: open_flags & 0x200 != 0, binding: None, closed: false, scan_index: None };
    publish_file_handle(entry, output, io_status, information)
}

/// FILE_OBJECT, acesso e opções de um handle de arquivo do kernel; recusa
/// handle de outro processo ou de kernel pedido do modo usuário.
pub fn query_file_handle(handle: u64, user: bool) -> Option<Result<(u64, u32, u32), u32>> {
    let entry = FILE_HANDLES.lock().get(&((handle as u32) & !3)).cloned()?;
    if (user && entry.kernel_handle) || (!entry.kernel_handle && entry.owner_process != process::get_current_process()) {
        return Some(Err(STATUS_INVALID_HANDLE));
    }
    Some(Ok((entry.file_object, entry.access, entry.options)))
}

/// ObReferenceObjectByHandle com IoFileObjectType.
pub fn file_object_of_handle(handle: u64) -> u64 {
    FILE_HANDLES.lock().get(&((handle as u32) & !3)).map_or(0, |entry| entry.file_object)
}

pub fn file_access_of_handle(handle: u64) -> u32 {
    FILE_HANDLES.lock().get(&((handle as u32) & !3)).map_or(0, |entry| entry.access)
}

pub fn file_options(file: u64) -> u32 {
    FILES_BY_OBJECT.lock().get(&file).map_or(0, |entry| entry.2)
}

/// Volume e caminho do FILE_OBJECT (arquivos de volume).
pub fn file_backing(file: u64) -> Option<(&'static dyn FileSystem, String)> {
    FILES_BY_OBJECT.lock().get(&file).map(|(volume, path, _)| (*volume, path.clone()))
}

/// IoQueryFileInformation/ZwQueryInformationFile por FILE_OBJECT para os
/// arquivos de volume e de fonte (imagens); arquivos de dispositivo vão ao
/// driver por IRP.
pub fn query_file_information_by_object(file: u64, class: u32, length: u32, output: u64, output_length: u64) -> Result<u32, KernelError> {
    let source = file_objects::source(file);
    let backing = file_backing(file);
    let (size, name, entry_stat) = match (&backing, &source) {
        (Some((volume, path)), _) => (volume.size(path).unwrap_or(0), path.clone(), volume.stat(path)),
        (None, Some(source)) => (source.size(), String::from(source.name()), None),
        (None, None) => {
            return if file_objects::is_file(file) {
                crate::ntos::io::file::information::query_native(file, class, length, output, output_length, false, false, 0)
            } else {
                Ok(STATUS_INVALID_HANDLE)
            };
        }
    };
    let source_stat = source.as_ref().and_then(|source| source.stat());
    match class {
        // FileEaInformation pelos atributos presentes no volume.
        7 => {
            if length < 4 {
                return Ok(0xC000_0023);
            }
            let stat = backing.as_ref().and_then(|(volume, path)| volume.stat(path)).or_else(|| source_stat.clone());
            guest::write32(output, stat.map_or(0, |stat| stat.ea_size));
            guest::write32(output_length, 4);
            Ok(0)
        }
        // FileBasicInformation: tempos da fonte quando existem; atributos.
        4 => {
            if length < 0x28 {
                return Ok(0xC000_0023);
            }
            for offset in 0..0x28 {
                guest::write8(output + offset, 0);
            }
            if let Some(times) = source_stat.as_ref().map(|stat| &stat.times).filter(|times| times.len() >= 32) {
                for (field, origin) in [0usize, 24, 8, 16].iter().enumerate() {
                    guest::write_bytes(output + field as u64 * 8, &times[*origin..*origin + 8]);
                }
            }
            guest::write32(output + 0x20, source_stat.as_ref().map_or(0x80, |stat| stat.attributes));
            guest::write32(output_length, 0x28);
            Ok(0)
        }
        // FileStandardInformation.
        5 => {
            if length < 0x18 {
                return Ok(0xC000_0023);
            }
            guest::write64(output, source_stat.as_ref().map_or(size, |stat| stat.allocated));
            guest::write64(output + 8, size);
            guest::write32(output + 16, 1);
            guest::write8(output + 20, 0);
            let stat = if source.is_some() { source_stat.clone() } else { entry_stat };
            guest::write8(output + 21, stat.is_some_and(|stat| stat.directory || stat.attributes & 0x10 != 0) as u8);
            guest::write16(output + 22, 0);
            guest::write32(output_length, 0x18);
            Ok(0)
        }
        // FileNameInformation { Length, Name[] }.
        9 => {
            let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
            let name_bytes = units.len() as u32 * 2;
            if length < 4 + name_bytes {
                guest::write32(output_length, 4 + name_bytes);
                return Ok(0xC000_0023);
            }
            guest::write32(output, name_bytes);
            for (index, unit) in units.iter().enumerate() {
                guest::write16(output + 4 + index as u64 * 2, *unit);
            }
            guest::write32(output_length, 4 + name_bytes);
            Ok(0)
        }
        _ => Ok(0xC000_0003),
    }
}

/// Cria/abre arquivo ou diretório por nome pelo ZwCreateFile e fecha em
/// seguida (RtlCreateSystemVolumeInformationFolder). Os OBJECT_ATTRIBUTES
/// levam Length = 48: o original deixava Length zerado e a captura do nome
/// recusava a chamada.
pub fn create_file_by_name(object_name: &str, disposition: u32, options: u32) -> Result<u32, KernelError> {
    let units: alloc::vec::Vec<u16> = object_name.encode_utf16().collect();
    let block = guest::alloc_bytes(0x80 + units.len() as u64 * 2 + 2);
    if block == 0 {
        return Ok(0xC000_009A);
    }
    let text = block + 0x80;
    guest_strings::write_wide_string(text, object_name);
    let unicode = block + 0x40;
    guest::write16(unicode, units.len() as u16 * 2);
    guest::write16(unicode + 2, units.len() as u16 * 2 + 2);
    guest::write64(unicode + 8, text);
    guest::write32(block, 48);
    guest::write64(block + object_attributes::OBJECT_NAME, unicode);
    guest::write32(block + object_attributes::ATTRIBUTES, 0x240);
    let output = block + 0x30;
    let io_status = block + 0x60;
    let status = create_kernel_file(output, 0, block, io_status, 0, disposition, options);
    if status.as_ref().is_ok_and(|&status| status == 0) {
        close_file_entry(guest::read32(output));
    }
    guest::free_bytes(block);
    status
}

/// Registro de fechamento de um handle de kernel ou de arquivo
/// (`zw.closeRecord`), instalado como provedor do NtClose.
fn entry_of(handle: u64) -> Option<FileEntry> {
    FILE_HANDLES.lock().get(&((handle as u32) & !3)).cloned()
}

/// Volume do FILE_OBJECT (registro do zw ou volume da fonte) e a classe
/// serializada; arquivos de outro provedor usam o caminho nativo.
pub fn query_volume_information_by_object(file: u64, class: u32, length: u32, buffer: u64, returned: u64) -> Result<u32, KernelError> {
    let volume = FILES_BY_OBJECT.lock().get(&file).map(|entry| entry.0).or_else(|| file_objects::source(file).and_then(|source| source.volume()));
    let Some(volume) = volume else {
        return if file_objects::is_file(file) { crate::ntos::io::file::information::query_native(file, class, length, buffer, returned, false, true, 0) } else { Ok(STATUS_INVALID_HANDLE) };
    };
    let result = match volume_information::query(volume.volume_query(), class, length) {
        Ok(result) => result,
        Err(error) => {
            if returned != 0 {
                guest::write32(returned, 0);
            }
            return Ok(if error.status != 0xC000_0001 { error.status } else { 0xC000_0185 });
        }
    };
    volume_information::write(&result, buffer);
    if returned != 0 {
        guest::write32(returned, result.information);
    }
    Ok(result.status)
}

/// ZwQueryVolumeInformationFile pelo handle de arquivo do kernel.
pub fn query_volume_information_file(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> Result<u32, KernelError> {
    let Some(entry) = entry_of(handle) else { return Ok(STATUS_INVALID_HANDLE) };
    let returned = guest::alloc_bytes(8);
    if returned == 0 {
        return Ok(0xC000_009A);
    }
    let status = query_volume_information_by_object(entry.file_object, class, length, buffer, returned);
    if let Ok(status) = status {
        write_io_status(io_status, status, guest::read32(returned) as u64);
    }
    guest::free_bytes(returned);
    status
}

/// ZwSetInformationFile: FileDisposition[Ex]Information apaga de fato no
/// volume gravável; volume somente leitura = MEDIA_WRITE_PROTECTED.
pub fn set_information_file(handle: u64, io_status: u64, input: u64, class: u32) -> Result<u32, KernelError> {
    let Some(entry) = entry_of(handle) else { return Ok(STATUS_INVALID_HANDLE) };
    if class != 13 && class != 64 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if guest::read8(input) != 0 {
        let Backing::Volume { volume, path } = &entry.backing else { return Ok(STATUS_MEDIA_WRITE_PROTECTED) };
        match volume.remove(path) {
            None => return Ok(STATUS_MEDIA_WRITE_PROTECTED),
            Some(result) => {
                result?;
            }
        }
    }
    write_io_status(io_status, 0, 0);
    Ok(0)
}

/// ZwQueryDirectoryFile: FileDirectoryInformation (1) do diretório aberto,
/// com posição de listagem por handle e filtro de nome exato.
#[allow(clippy::too_many_arguments)]
pub fn query_directory_file(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32, single: bool, file_name: u64, restart: bool) -> u32 {
    if class != 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let key = (handle as u32) & !3;
    let Some(entry) = FILE_HANDLES.lock().get(&key).cloned() else { return STATUS_INVALID_HANDLE };
    let Backing::Volume { volume, path } = &entry.backing else { return STATUS_INVALID_HANDLE };
    let mut index = if restart { 0 } else { entry.scan_index.unwrap_or(0) };
    let prefix = if path == "/" { String::from("/") } else { format!("{path}/") };
    let names: alloc::vec::Vec<String> = volume.list().into_iter().filter(|candidate| candidate.starts_with(&prefix) && !candidate[prefix.len()..].contains('/')).map(|candidate| String::from(&candidate[prefix.len()..])).collect();
    let pattern = if file_name != 0 { Some(guest_strings::read_unicode_string(file_name)) } else { None };
    let matched: alloc::vec::Vec<String> = match &pattern {
        Some(pattern) if pattern != "*" => names.into_iter().filter(|name| name.to_lowercase() == pattern.to_lowercase()).collect(),
        _ => names,
    };
    let mut cursor = buffer;
    let mut previous = 0u64;
    let mut emitted = 0;
    while index < matched.len() {
        let name: alloc::vec::Vec<u16> = matched[index].encode_utf16().collect();
        let record = 0x40 + name.len() as u64 * 2;
        if cursor - buffer + record > length as u64 {
            break;
        }
        guest::write32(cursor + 4, index as u32);
        guest::write64(cursor + 0x28, volume.size(&format!("{prefix}{}", matched[index])).unwrap_or(0));
        guest::write64(cursor + 0x30, 0);
        guest::write32(cursor + 0x38, 0x80);
        guest::write32(cursor + 0x3C, name.len() as u32 * 2);
        for (offset, unit) in name.iter().enumerate() {
            guest::write16(cursor + 0x40 + offset as u64 * 2, *unit);
        }
        if previous != 0 {
            guest::write32(previous, (cursor - previous) as u32);
        }
        previous = cursor;
        cursor += record;
        index += 1;
        emitted += 1;
        if single {
            break;
        }
    }
    if let Some(stored) = FILE_HANDLES.lock().get_mut(&key) {
        stored.scan_index = Some(index);
    }
    if previous != 0 {
        guest::write32(previous, 0);
    }
    let status = if emitted != 0 { 0 } else { 0x8000_0006 };
    write_io_status(io_status, status, cursor - buffer);
    status
}

/// ZwFlushBuffersFile: as escritas são síncronas; só valida o handle.
pub fn flush_buffers_file(handle: u64, io_status: u64) -> u32 {
    if entry_of(handle).is_none() {
        return STATUS_INVALID_HANDLE;
    }
    write_io_status(io_status, 0, 0);
    0
}

/// ZwFsControlFile: IRP_MJ_FILE_SYSTEM_CONTROL ao dispositivo do handle.
pub fn fs_control_file(handle: u64, io_status: u64, code: u32, input: u64, input_length: u32, output: u64, output_length: u32) -> Result<u32, KernelError> {
    let Some(entry) = entry_of(handle) else { return Ok(STATUS_INVALID_HANDLE) };
    let Backing::Device { path, handle: device_handle } = &entry.backing else { return Ok(STATUS_INVALID_HANDLE) };
    if *device_handle == 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    let data = guest::read_bytes(input, input_length as usize);
    let mut request = io_manager::make_io_request(io_manager::irp_mj::FILE_SYSTEM_CONTROL, io_manager::IoParams { control_code: code, data: Some(data), binary: true, buffer_length: Some(output_length), ..Default::default() });
    io_manager::call_driver(path, &mut request)?;
    let status = request.status as u32;
    write_io_status(io_status, status, request.info);
    if status == 0 && request.info > 0 && output != 0 {
        let bytes: alloc::vec::Vec<u8> = match &request.result {
            io_manager::IoResult::Bytes(bytes) => bytes.clone(),
            io_manager::IoResult::Text(text) => text.chars().map(|character| character as u32 as u8).collect(),
            io_manager::IoResult::None => alloc::vec::Vec::new(),
        };
        for index in 0..request.info as usize {
            guest::write8(output + index as u64, bytes.get(index).copied().unwrap_or(0));
        }
    }
    Ok(status)
}

/// ZwQueryFullAttributesFile: tempos = agora e atributos NORMAL de um
/// arquivo existente num volume montado.
pub fn query_full_attributes_file(attributes: u64, output: u64) -> u32 {
    let name = guest_strings::read_unicode_string(guest::read64(attributes + object_attributes::OBJECT_NAME));
    let Some((volume, path)) = resolve_mounted_file(&name) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    if !volume.exists(&path) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let now = crate::rtl::time::unix_milliseconds_to_nt_time(crate::ntos::ke::clock::now_ms());
    for field in 0..4 {
        guest::write64(output + field * 8, now);
    }
    guest::write32(output + 0x20, 0x80);
    0
}

/// Handle de evento, diretório ou link aberto pelo zw: tipo, nó, processo
/// dono e o corpo nativo do evento.
#[derive(Clone)]
struct KernelObjectEntry {
    kind: String,
    access: u32,
    owner_process: u64,
    kernel_handle: bool,
    attributes: u32,
    data_pointer: u64,
}

static KERNEL_OBJECT_HANDLES: SpinLock<BTreeMap<u32, KernelObjectEntry>> = SpinLock::new(BTreeMap::new());

/// Publica o objeto no gerenciador; OBJ_KERNEL_HANDLE escolhe o processo
/// System e a representação de modo kernel do handle.
pub fn open_kernel_object(output: u64, node: object_manager::NodeId, access: u32, attributes_pointer: u64) -> Result<u32, KernelError> {
    let flags = guest::read32(attributes_pointer + 24);
    let Some(snapshot) = object_manager::node(node) else { return Ok(0xC000_0034) };
    let kernel_handle = flags & 0x200 != 0;
    let entry = KernelObjectEntry {
        kind: snapshot.type_name.clone(),
        access,
        owner_process: if kernel_handle { process::get_system_process() } else { process::get_current_process() },
        kernel_handle,
        attributes: flags & 2,
        data_pointer: if snapshot.type_name == "Event" { snapshot.data.as_ref().map_or(0, |data| data.native_pointer) } else { 0 },
    };
    let opened = entry.clone();
    let options = object_manager::OpenOptions {
        access: Some(access),
        attributes: Some(flags & 2),
        kernel_handle,
        owner_process: Some(entry.owner_process),
        on_open: Some(Arc::new(move |handle| {
            KERNEL_OBJECT_HANDLES.lock().insert(handle, opened.clone());
        })),
        on_close: Some(Arc::new(|handle| {
            KERNEL_OBJECT_HANDLES.lock().remove(&handle);
        })),
        ..Default::default()
    };
    let handle = match object_manager::open_object(node, Some(options)) {
        Ok(handle) => handle,
        Err(error) if error.status != 0xC000_0001 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    guest::write64(output, if kernel_handle { 0xFFFF_FFFF_8000_0000 | handle as u64 } else { handle as u64 });
    Ok(0)
}

/// Registro de acesso de um handle (closeRecord do original): os handles de
/// objetos do zw primeiro, depois a tabela do Object Manager. Devolve (forma
/// de kernel, processo dono, atributos, acesso concedido).
pub fn handle_access_record(handle: u32) -> Option<(bool, u64, u32, u32)> {
    let low = handle & 0x7FFF_FFFC;
    if let Some(entry) = KERNEL_OBJECT_HANDLES.lock().get(&low).cloned() {
        return Some((entry.kernel_handle, entry.owner_process, entry.attributes, entry.access));
    }
    let record = object_manager::handle_record(low)?;
    Some((record.options.kernel_handle, record.options.owner_process.unwrap_or(0), record.attributes, record.access))
}

/// Evento de um handle aberto pelo zw (ZwWaitForSingleObject).
pub fn wait_object_of_handle(handle: u64) -> u64 {
    let kernel = handle & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !kernel && handle > 0x7FFF_FFFF {
        return 0;
    }
    let Some(entry) = KERNEL_OBJECT_HANDLES.lock().get(&((handle & 0x7FFF_FFFC) as u32)).cloned() else { return 0 };
    if kernel != entry.kernel_handle || (!kernel && entry.owner_process != process::get_current_process()) {
        return 0;
    }
    if entry.kind == "Event" {
        entry.data_pointer
    } else {
        0
    }
}

fn close_record(handle: u32) -> Option<ZwRecord> {
    let low = handle & !3;
    if let Some(entry) = KERNEL_OBJECT_HANDLES.lock().get(&low).cloned() {
        return Some(ZwRecord { kernel_handle: entry.kernel_handle, owner_process: entry.owner_process, attributes: entry.attributes, close: Box::new(move || match object_manager::close(low) {
            Ok(true) => 0,
            _ => 0xC000_0008,
        }) });
    }
    if let Some(entry) = FILE_HANDLES.lock().get(&low).cloned() {
        return Some(ZwRecord { kernel_handle: entry.kernel_handle, owner_process: entry.owner_process, attributes: entry.attributes, close: Box::new(move || close_file_entry(low)) });
    }
    key_services::zw_record(low)
}

/// Instala os provedores: o NtClose completo e a consulta por objeto.
pub fn init() {
    close::set_zw_provider(close_record);
    crate::ntos::io::file::information::set_object_query(query_file_information_by_object);
}
