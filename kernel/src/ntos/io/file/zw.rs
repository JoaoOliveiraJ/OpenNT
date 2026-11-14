//! Serviços de arquivo do kernel.
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
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{
    FileBasicInformation, FileDirectoryInformation, FileDispositionInformation, FileEaInformation, FileIdFullDirInformation, FileNameInformation, FileNetworkOpenInformation, FileObject,
    FileStandardInformation, IoStatusBlock, NtStruct, ObjectAttributes, UnicodeString,
};

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
    /// Arquivo de um volume montado por um file system real (`io/parse.rs`).
    Mounted { path: String },
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
    // SAFETY: PIO_STATUS_BLOCK do chamador Zw de modo kernel.
    let iosb = unsafe { IoStatusBlock::at(io_status) };
    iosb.status.set(status as i32);
    iosb.information.set(information);
}

/// OBJECT_ATTRIBUTES do chamador Zw (modo kernel).
fn object_attributes_at(attributes: u64) -> &'static ObjectAttributes {
    // SAFETY: POBJECT_ATTRIBUTES de um chamador de modo kernel.
    unsafe { ObjectAttributes::at(attributes) }
}

/// Parâmetro de saída escalar (PHANDLE, PULONG...) de um chamador de modo kernel.
fn output_at<T: Copy>(address: u64) -> &'static Field<T> {
    // SAFETY: ponteiro de saída de um chamador de modo kernel.
    unsafe { Field::<T>::at(address) }
}

/// Captura o nome antes de tocar no volume ou nos buffers de saída. Sem
/// RootDirectory o nome NT começa na raiz; um handle de diretório do Object
/// Manager ou de um arquivo-diretório permite nomes relativos.
pub fn file_path_from_object_attributes(attributes: u64) -> Result<String, u32> {
    if attributes == 0 || object_attributes_at(attributes).length.get() != ObjectAttributes::SIZE as u32 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let root = object_attributes_at(attributes).root_directory.get();
    let name_pointer = object_attributes_at(attributes).object_name.get();
    // SAFETY: ObjectName (PUNICODE_STRING) dos OBJECT_ATTRIBUTES do chamador.
    if name_pointer != 0 && unsafe { UnicodeString::at(name_pointer) }.length.get() & 1 != 0 {
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
        Backing::Volume { .. } | Backing::Mounted { .. } => {
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
            output_at::<u64>(output).set(handle as u64);
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

/// Argumentos do ZwCreateFile montados pelo create_file_by_name (bloco
/// privado: o texto do nome segue a estrutura).
#[repr(C)]
struct CreateByName {
    attributes: ObjectAttributes,
    handle: Field<u64>,
    name: UnicodeString,
    io_status: IoStatusBlock,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CreateByName {}

/// Unidades UTF-16 em bytes little-endian (para uma cópia em bloco).
fn utf16_bytes(units: &[u16]) -> alloc::vec::Vec<u8> {
    units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
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
    let open_flags = object_attributes_at(attributes_pointer).attributes.get();
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
        // SAFETY: FILE_OBJECT vivo devolvido pelo open_device.
        unsafe { FileObject::at(opened.file_object) }.flags.atomic().fetch_or(option_flags(options), core::sync::atomic::Ordering::SeqCst);
        let entry = FileEntry { backing: Backing::Device { path: object_name, handle: opened.handle }, file_object: opened.file_object, access, share: share_access, options, owner_process, attributes: open_flags & 2, kernel_handle: open_flags & 0x200 != 0, binding: None, closed: false, scan_index: None };
        return publish_file_handle(entry, output, io_status, FILE_OPENED);
    }
    let Some((volume, path)) = resolve_mounted_file(&object_name) else {
        // Arquivo de um volume com VPB: o IopParseDevice monta e abre pelo
        // file system dono (`io/parse.rs`).
        if let Some((device, remaining)) = crate::ntos::io::parse::split_volume_path(&object_name) {
            let request = crate::ntos::io::parse::OpenRequest { desired_access, file_attributes: 0, share_access, disposition, create_options: options, case_insensitive: open_flags & 0x40 != 0 };
            let opened = crate::ntos::io::parse::open_file(device, &remaining, &request)?;
            if opened.status & 0x8000_0000 != 0 {
                write_io_status(io_status, opened.status, 0);
                return Ok(opened.status);
            }
            file_objects::open_handle(opened.file_object)?;
            file_objects::dereference(opened.file_object)?;
            let entry = FileEntry { backing: Backing::Mounted { path: object_name }, file_object: opened.file_object, access, share: share_access, options, owner_process, attributes: open_flags & 2, kernel_handle: open_flags & 0x200 != 0, binding: None, closed: false, scan_index: None };
            return publish_file_handle(entry, output, io_status, opened.information);
        }
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
    // SAFETY: FILE_OBJECT recém-criado.
    let body = unsafe { FileObject::at(file) };
    body.read_access.set((access & 1 != 0) as u8);
    body.write_access.set((access & 6 != 0) as u8);
    body.delete_access.set((access & 0x10000 != 0) as u8);
    body.shared_read.set((share_access & 1) as u8);
    body.shared_write.set(((share_access >> 1) & 1) as u8);
    body.shared_delete.set(((share_access >> 2) & 1) as u8);
    body.flags.set(option_flags(options));
    FILES_BY_OBJECT.lock().insert(file, (volume, path.clone(), options));
    file_objects::set_callbacks(file, FileCallbacks { destroy: Some(Arc::new(move || { FILES_BY_OBJECT.lock().remove(&file); })), ..Default::default() })?;
    file_lifetime::bind(file_lifetime::Entry { access, share: share_access, file_object: file, file: None }, &lifetime, &path)?;
    file_objects::open_handle(file)?;
    file_objects::dereference(file)?;
    let entry = FileEntry { backing: Backing::Volume { volume, path }, file_object: file, access, share: share_access, options, owner_process, attributes: open_flags & 2, kernel_handle: open_flags & 0x200 != 0, binding: None, closed: false, scan_index: None };
    publish_file_handle(entry, output, io_status, information)
}

/// ZwOpenFile = ZwCreateFile com FILE_OPEN (compartilhamento e opções não
/// são repassados).
pub fn open_kernel_file(output: u64, desired_access: u32, attributes_pointer: u64, io_status: u64) -> Result<u32, KernelError> {
    create_kernel_file(output, desired_access, attributes_pointer, io_status, 0, FILE_OPEN, 0)
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
            // SAFETY: buffer de saída do chamador de modo kernel (tamanho conferido).
            unsafe { FileEaInformation::at(output) }.ea_size.set(stat.map_or(0, |stat| stat.ea_size));
            output_at::<u32>(output_length).set(FileEaInformation::SIZE as u32);
            Ok(0)
        }
        // FileBasicInformation: tempos da fonte quando existem; atributos.
        4 => {
            if length < FileBasicInformation::SIZE as u32 {
                return Ok(0xC000_0023);
            }
            guest::write_bytes(output, &[0; FileBasicInformation::SIZE as usize]);
            // SAFETY: buffer de saída do chamador de modo kernel (tamanho conferido).
            let basic = unsafe { FileBasicInformation::at(output) };
            if let Some(times) = source_stat.as_ref().map(|stat| &stat.times).filter(|times| times.len() >= 32) {
                let time = |origin: usize| i64::from_le_bytes(times[origin..origin + 8].try_into().unwrap_or([0; 8]));
                basic.creation_time.quad_part.set(time(0));
                basic.last_access_time.quad_part.set(time(24));
                basic.last_write_time.quad_part.set(time(8));
                basic.change_time.quad_part.set(time(16));
            }
            basic.file_attributes.set(source_stat.as_ref().map_or(0x80, |stat| stat.attributes));
            output_at::<u32>(output_length).set(FileBasicInformation::SIZE as u32);
            Ok(0)
        }
        // FileStandardInformation.
        5 => {
            if length < FileStandardInformation::SIZE as u32 {
                return Ok(0xC000_0023);
            }
            // SAFETY: buffer de saída do chamador de modo kernel (tamanho conferido).
            let standard = unsafe { FileStandardInformation::at(output) };
            standard.allocation_size.quad_part.set(source_stat.as_ref().map_or(size, |stat| stat.allocated) as i64);
            standard.end_of_file.quad_part.set(size as i64);
            standard.number_of_links.set(1);
            standard.delete_pending.set(0);
            let stat = if source.is_some() { source_stat.clone() } else { entry_stat };
            standard.directory.set(stat.is_some_and(|stat| stat.directory || stat.attributes & 0x10 != 0) as u8);
            // Os dois bytes de preenchimento finais também saem zerados.
            guest::write_bytes(standard.directory.address() + 1, &[0; 2]);
            output_at::<u32>(output_length).set(FileStandardInformation::SIZE as u32);
            Ok(0)
        }
        // FileNameInformation { Length, Name[] }.
        9 => {
            let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
            let name_bytes = units.len() as u32 * 2;
            if length < 4 + name_bytes {
                output_at::<u32>(output_length).set(4 + name_bytes);
                return Ok(0xC000_0023);
            }
            // SAFETY: buffer de saída do chamador de modo kernel (tamanho conferido).
            let information = unsafe { FileNameInformation::at(output) };
            information.file_name_length.set(name_bytes);
            guest::write_bytes(information.file_name[0].address(), &utf16_bytes(&units));
            output_at::<u32>(output_length).set(4 + name_bytes);
            Ok(0)
        }
        _ => Ok(0xC000_0003),
    }
}

/// Cria/abre arquivo ou diretório por nome pelo ZwCreateFile e fecha em
/// seguida (RtlCreateSystemVolumeInformationFolder). Os OBJECT_ATTRIBUTES
/// levam Length = 48: com Length zerado, a captura do nome recusaria a
/// chamada.
pub fn create_file_by_name(object_name: &str, disposition: u32, options: u32) -> Result<u32, KernelError> {
    let units: alloc::vec::Vec<u16> = object_name.encode_utf16().collect();
    let block = guest::alloc_bytes(CreateByName::SIZE + units.len() as u64 * 2 + 2);
    if block == 0 {
        return Ok(0xC000_009A);
    }
    // SAFETY: bloco zerado recém-alocado; o texto vem logo depois dele.
    let request = unsafe { CreateByName::at(block) };
    let text = block + CreateByName::SIZE;
    guest_strings::write_wide_string(text, object_name);
    request.name.length.set(units.len() as u16 * 2);
    request.name.maximum_length.set(units.len() as u16 * 2 + 2);
    request.name.buffer.set(text);
    request.attributes.length.set(ObjectAttributes::SIZE as u32);
    request.attributes.object_name.set(request.name.address());
    request.attributes.attributes.set(0x240);
    let status = create_kernel_file(request.handle.address(), 0, request.attributes.address(), request.io_status.address(), 0, disposition, options);
    if status.as_ref().is_ok_and(|&status| status == 0) {
        close_file_entry(request.handle.get() as u32);
    }
    guest::free_bytes(block);
    status
}

/// Registro de fechamento de um handle de kernel ou de arquivo, instalado
/// como provedor do NtClose.
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
                output_at::<u32>(returned).set(0);
            }
            return Ok(if error.status != 0xC000_0001 { error.status } else { 0xC000_0185 });
        }
    };
    volume_information::write(&result, buffer);
    if returned != 0 {
        output_at::<u32>(returned).set(result.information);
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
        write_io_status(io_status, status, output_at::<u32>(returned).get() as u64);
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
    // FileDispositionInformation.DeleteFile ou o byte baixo do
    // FILE_DISPOSITION_INFORMATION_EX.Flags (FILE_DISPOSITION_DELETE).
    // SAFETY: buffer de entrada do chamador Zw de modo kernel.
    if unsafe { FileDispositionInformation::at(input) }.delete_file.get() != 0 {
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
    if class != 1 && class != 38 {
        return STATUS_INVALID_PARAMETER;
    }
    // FileDirectoryInformation (1) poe o nome do arquivo em +0x40; a
    // FileIdFullDirectoryInformation (38), que a ci.dll usa para varrer o
    // CatRoot atras dos catalogos, o poe em +0x50 (apos EaSize e FileId).
    let name_offset = if class == 38 { core::mem::offset_of!(FileIdFullDirInformation, file_name) } else { core::mem::offset_of!(FileDirectoryInformation, file_name) } as u64;
    let key = (handle as u32) & !3;
    let Some(entry) = FILE_HANDLES.lock().get(&key).cloned() else { return STATUS_INVALID_HANDLE };
    let Backing::Volume { volume, path } = &entry.backing else { return STATUS_INVALID_HANDLE };
    let mut index = if restart { 0 } else { entry.scan_index.unwrap_or(0) };
    let prefix = if path == "/" { String::from("/") } else { format!("{path}/") };
    let names: alloc::vec::Vec<String> = volume.list_directory(path).into_iter().filter(|candidate| candidate.starts_with(&prefix) && !candidate[prefix.len()..].contains('/')).map(|candidate| String::from(&candidate[prefix.len()..])).collect();
    // Casa um nome contra um padrão DOS (`*` e `?`), sem diferenciar
    // maiúsculas — a ci.dll enumera os catálogos por `*.cat`, não por nome
    // exato, então o filtro precisa entender curingas.
    fn wildcard_match(name: &[char], pattern: &[char]) -> bool {
        match pattern.first() {
            None => name.is_empty(),
            Some('*') => wildcard_match(name, &pattern[1..]) || (!name.is_empty() && wildcard_match(&name[1..], pattern)),
            Some('?') => !name.is_empty() && wildcard_match(&name[1..], &pattern[1..]),
            Some(&expected) => !name.is_empty() && name[0] == expected && wildcard_match(&name[1..], &pattern[1..]),
        }
    }
    let pattern = if file_name != 0 { Some(guest_strings::read_unicode_string(file_name)) } else { None };
    let matched: alloc::vec::Vec<String> = match &pattern {
        Some(pattern) => {
            let lowered: alloc::vec::Vec<char> = pattern.to_lowercase().chars().collect();
            names.into_iter().filter(|name| wildcard_match(&name.to_lowercase().chars().collect::<alloc::vec::Vec<char>>(), &lowered)).collect()
        }
        None => names,
    };
    let mut cursor = buffer;
    let mut previous = 0u64;
    let mut emitted = 0;
    while index < matched.len() {
        let name: alloc::vec::Vec<u16> = matched[index].encode_utf16().collect();
        let record = name_offset + name.len() as u64 * 2;
        if cursor - buffer + record > length as u64 {
            break;
        }
        // Os campos comuns são os do FILE_DIRECTORY_INFORMATION; a classe 38
        // acrescenta EaSize e FileId antes do nome.
        // SAFETY: registro dentro do buffer do chamador (tamanho conferido acima).
        let record_view = unsafe { FileDirectoryInformation::at(cursor) };
        record_view.next_entry_offset.set(0);
        record_view.file_index.set(index as u32);
        record_view.end_of_file.quad_part.set(volume.size(&format!("{prefix}{}", matched[index])).unwrap_or(0) as i64);
        record_view.allocation_size.quad_part.set(0);
        record_view.file_attributes.set(0x80);
        record_view.file_name_length.set(name.len() as u32 * 2);
        if class == 38 {
            // SAFETY: mesmo registro, na forma FILE_ID_FULL_DIR_INFORMATION.
            let full = unsafe { FileIdFullDirInformation::at(cursor) };
            full.ea_size.set(0);
            full.file_id.quad_part.set(index as i64 + 1);
        }
        guest::write_bytes(cursor + name_offset, &utf16_bytes(&name));
        if previous != 0 {
            // SAFETY: registro anterior do mesmo buffer.
            unsafe { FileDirectoryInformation::at(previous) }.next_entry_offset.set((cursor - previous) as u32);
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
        // SAFETY: último registro escrito no buffer do chamador.
        unsafe { FileDirectoryInformation::at(previous) }.next_entry_offset.set(0);
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
        let mut data = bytes;
        data.resize(request.info as usize, 0);
        guest::write_bytes(output, &data);
    }
    Ok(status)
}

/// ZwQueryFullAttributesFile: tempos = agora e atributos NORMAL de um
/// arquivo existente num volume montado.
pub fn query_full_attributes_file(attributes: u64, output: u64) -> u32 {
    let name = guest_strings::read_unicode_string(object_attributes_at(attributes).object_name.get());
    let Some((volume, path)) = resolve_mounted_file(&name) else { return STATUS_OBJECT_NAME_NOT_FOUND };
    if !volume.exists(&path) {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let now = crate::rtl::time::unix_milliseconds_to_nt_time(crate::ntos::ke::clock::now_ms()) as i64;
    let size = volume.size(&path).unwrap_or(0) as i64;
    // SAFETY: PFILE_NETWORK_OPEN_INFORMATION do chamador Zw de modo kernel.
    let information = unsafe { FileNetworkOpenInformation::at(output) };
    information.creation_time.quad_part.set(now);
    information.last_access_time.quad_part.set(now);
    information.last_write_time.quad_part.set(now);
    information.change_time.quad_part.set(now);
    information.allocation_size.quad_part.set(size);
    information.end_of_file.quad_part.set(size);
    information.file_attributes.set(0x80);
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
    let flags = object_attributes_at(attributes_pointer).attributes.get();
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
    output_at::<u64>(output).set(if kernel_handle { 0xFFFF_FFFF_8000_0000 | handle as u64 } else { handle as u64 });
    Ok(0)
}

/// Registro de acesso de um handle: os handles de objetos do zw primeiro,
/// depois a tabela do Object Manager. Devolve (forma de kernel, processo
/// dono, atributos, acesso concedido).
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

// ---- NtSetVolumeInformationFile (kernel) e IoQueryInformationByName -------------

/// IopSetFsOperationLength (ntoskrnl 0x983880): tamanho mínimo por
/// FS_INFORMATION_CLASS; 0 = classe que não se define.
const SET_FS_OPERATION_LENGTH: [u32; 15] = [0, 0, 8, 0, 0, 0, 48, 0, 64, 0, 4, 0, 0, 0, 0];
/// IopQueryOperationLength (ntoskrnl 0x984b10), FILE_INFORMATION_CLASS < 0x4C.
const QUERY_OPERATION_LENGTH: [u8; 0x4C] = [
    0, 0, 0, 0, 40, 24, 8, 4, 4, 8, 0, 0, 0, 0, 8, 0, 4, 4, 104, 0, 0, 8, 32, 8, 40, 16, 24, 0, 16, 72, 0, 0, 56, 16, 56, 8, 0, 0,
    0, 0, 0, 4, 0, 4, 20, 12, 32, 16, 8, 8, 0, 1, 0, 2, 12, 116, 0, 0, 8, 24, 0, 0, 36, 0, 0, 0, 0, 8, 72, 0, 96, 4, 0, 0, 4, 4,
];
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;

/// ZwSetVolumeInformationFile(Handle, IoStatusBlock, FsInformation, Length, Class).
/// Um handle de dispositivo nativo recebe IRP_MJ_SET_VOLUME_INFORMATION real;
/// os volumes servidos pelo próprio kernel (`drivers::fs`) não implementam
/// rótulo/controle/ObjectId de volume.
pub fn set_volume_information_file(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> Result<u32, KernelError> {
    let required = SET_FS_OPERATION_LENGTH.get(class as usize).copied().unwrap_or(0);
    if required == 0 {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if length < required {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let Some(entry) = entry_of(handle) else { return Ok(STATUS_INVALID_HANDLE) };
    match &entry.backing {
        Backing::Device { .. } | Backing::Mounted { .. } => {
            let (status, information) = crate::ntos::io::file::information::set_volume_native(entry.file_object, class, length, buffer)?;
            if status != 0x103 {
                write_io_status(io_status, status, information);
            }
            Ok(status)
        }
        Backing::Volume { .. } => Ok(STATUS_INVALID_DEVICE_REQUEST),
    }
}

/// IoQueryInformationByName(ObjectAttributes, IoStatusBlock, Buffer, Length,
/// Class, Options, DriverContext) (RVA 0x5d8b10): só FileStatInformation (68),
/// FileStatLxInformation (70), FileCaseSensitiveInformation (71) e, em modo
/// kernel, 75; o modo usuário passa antes pelo IopValidateQueryInformationParameters.
/// O NT faz CREATE+QUERY+CLOSE num OPEN_PACKET "QueryOnly" sem handle; aqui a
/// mesma sequência passa pelos serviços de arquivo do kernel (abrir com
/// FILE_READ_ATTRIBUTES, compartilhamento total, FILE_OPEN_REPARSE_POINT |
/// FILE_OPEN_FOR_BACKUP_INTENT; consultar; fechar).
pub fn query_information_by_name(attributes: u64, io_status: u64, buffer: u64, length: u32, class: u32, options: u32) -> Result<u32, KernelError> {
    use crate::ntos::init::exports::invoke_handler;
    let thread = process::get_current_thread();
    // IO_NO_PARAMETER_CHECKING (0x100) trata o pedido como de modo kernel;
    // senão vale o PreviousMode da thread.
    // SAFETY: o KTHREAD corrente.
    let mode = if options & 0x100 != 0 || thread == 0 { 0 } else { unsafe { crate::ntos::inc::types::Kthread::at(thread) }.previous_mode.get() };
    if mode != 0 {
        let minimum = QUERY_OPERATION_LENGTH.get(class as usize).copied().unwrap_or(0) as u32;
        if minimum == 0 {
            return Ok(STATUS_INVALID_INFO_CLASS);
        }
        if length < minimum {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
    }
    let effective = if class == 75 && mode == 0 { 71 } else { class };
    if !matches!(effective, 68 | 70 | 71) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let scratch = guest::alloc_bytes(0x20);
    if scratch == 0 {
        return Ok(0xC000_009A);
    }
    let (handle_output, open_status) = (scratch, scratch + 0x10);
    let status = invoke_handler("ZwOpenFile", &[handle_output, 0x80, attributes, open_status, 7, 0x20_4000])? as u32;
    let result = if status & 0x8000_0000 != 0 {
        write_io_status(io_status, status, 0);
        Ok(status)
    } else {
        // SAFETY: o PHANDLE de rascunho que o ZwOpenFile preencheu.
        let handle = unsafe { Field::<u64>::at(handle_output) }.get();
        let status = invoke_handler("ZwQueryInformationFile", &[handle, io_status, buffer, length as u64, class as u64])? as u32;
        invoke_handler("ZwClose", &[handle])?;
        Ok(status)
    };
    guest::free_bytes(scratch);
    result
}
