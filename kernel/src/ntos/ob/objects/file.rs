//! Armazenamento e posse de FILE_OBJECT.
//!
//! CLEANUP acompanha o último handle; CLOSE e a liberação do corpo esperam a
//! última referência por ponteiro, inclusive de operações de I/O.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::ob::object_manager::ObjectData;
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ob::object_access;
use crate::ntos::ke::dispatcher;
use crate::ntos::se::model::SecurityPolicy;
use core::sync::atomic::Ordering;

use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{FileObject, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// IO_TYPE_FILE.
const IO_TYPE_FILE: i16 = 5;

/// O FILE_OBJECT de `pointer` (corpo alocado por `create` ou pelo provedor).
fn file(pointer: u64) -> &'static FileObject {
    // SAFETY: os chamadores passam FILE_OBJECTs vivos.
    unsafe { FileObject::at(pointer) }
}

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const FO_CLEANUP_COMPLETE: u32 = 0x4000;
const FO_HANDLE_CREATED: u32 = 0x40000;

/// Fonte exata dos bytes de uma imagem carregada.
pub trait FileSource: Send + Sync {
    fn name(&self) -> &str;
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError>;
    fn acquire(&self) {}
    fn release(&self) {}
    /// Metadados do arquivo de origem.
    fn stat(&self) -> Option<crate::drivers::fs::volume::VolumeStat> {
        None
    }
    /// Volume que guarda os bytes, quando a fonte é um arquivo de volume.
    fn volume(&self) -> Option<&'static dyn crate::drivers::fs::volume::FileSystem> {
        None
    }
}

/// Rotinas de vida definidas pelo dono do arquivo.
#[derive(Clone, Default)]
pub struct FileCallbacks {
    pub cleanup: Option<Arc<dyn Fn() -> u32 + Send + Sync>>,
    pub close: Option<Arc<dyn Fn() + Send + Sync>>,
    pub destroy: Option<Arc<dyn Fn() + Send + Sync>>,
}

struct Record {
    name_buffer: u64,
    references: u32,
    handles: u32,
    opened: bool,
    cleaned: bool,
    closing: bool,
    callbacks: FileCallbacks,
    source: Option<Arc<dyn FileSource>>,
    ea_index: u32,
    security: SecurityPolicy,
}

static FILES: SpinLock<BTreeMap<u64, Record>> = SpinLock::new(BTreeMap::new());

fn file_type() -> ObjectType {
    object_types::file_type()
}

struct FileOwner;

static OWNER: FileOwner = FileOwner;

impl ObjectOwner for FileOwner {
    fn object_type(&self, _pointer: u64) -> ObjectType {
        file_type()
    }
    fn reference(&self, pointer: u64) {
        let _ = reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn open_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(open_handle(pointer))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(close_handle(pointer).map(|_| ()))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        FILES.lock().get(&pointer).map(|record| record.security.clone()).unwrap_or_default()
    }
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let (handles, references) = FILES.lock().get(&pointer).map_or((0, 0), |record| (record.handles, record.references));
        let name = crate::ntos::rtl::guest_strings::read_unicode_string(file(pointer).file_name.address());
        let device = file(pointer).device_object.get();
        let prefix = crate::ntos::ob::open_pointer::namespace_path_of(device).unwrap_or_default();
        let full = if prefix.is_empty() { name } else { alloc::format!("{}{}{}", prefix, if name.starts_with('\\') { "" } else { "\\" }, name) };
        crate::ntos::ob::open_pointer::QueryRecord { handles: Some(handles), references, permanent: false, name: full }
    }
    fn file_usable(&self, pointer: u64) -> bool {
        FILES.lock().get(&pointer).is_some_and(|record| record.opened && !record.cleaned && !record.closing)
    }
    fn data(&self, pointer: u64) -> ObjectData {
        ObjectData::pointer(pointer)
    }
}

/// Aloca FILE_OBJECT e o nome UTF-16, inicializa eventos e lista de IRPs e
/// captura a segurança inicial. Uma referência pertence ao chamador.
pub fn create(device: u64, name: &str) -> Result<u64, KernelError> {
    let pointer = guest::alloc_bytes(FileObject::SIZE);
    if pointer == 0 {
        return Err(KernelError::with_status("FILE_OBJECT allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    let units: Vec<u16> = name.encode_utf16().collect();
    let name_buffer = if units.is_empty() { 0 } else { guest::alloc_bytes((units.len() as u64 + 1) * 2) };
    if !units.is_empty() && name_buffer == 0 {
        guest::free_bytes(pointer);
        return Err(KernelError::with_status("file name allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    let object = file(pointer);
    object.type_.set(IO_TYPE_FILE);
    object.size.set(FileObject::SIZE as i16);
    object.device_object.set(device);
    object.file_name.length.set(units.len() as u16 * 2);
    object.file_name.maximum_length.set(if units.is_empty() { 0 } else { (units.len() as u16 + 1) * 2 });
    object.file_name.buffer.set(name_buffer);
    if !units.is_empty() {
        let text: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        guest::write_bytes(name_buffer, &text);
    }
    dispatcher::initialize_event(object.lock.address(), 1, false);
    dispatcher::initialize_event(object.event.address(), 0, false);
    object.irp_list.flink.set(object.irp_list.address());
    object.irp_list.blink.set(object.irp_list.address());
    let security = object_access::capture(object_access::subject());
    FILES.lock().insert(pointer, Record { name_buffer, references: 1, handles: 0, opened: false, cleaned: false, closing: false, callbacks: FileCallbacks::default(), source: None, ea_index: 0, security });
    object_types::account(&file_type().name, 1, 0)?;
    open_pointer::register_owner(Slot::File, is_file, &OWNER);
    Ok(pointer)
}

/// Troca as rotinas de vida enquanto o corpo ainda aceita mudanças.
pub fn set_callbacks(pointer: u64, callbacks: FileCallbacks) -> Result<(), KernelError> {
    let mut files = FILES.lock();
    let record = files.get_mut(&pointer).filter(|record| !record.closing).ok_or_else(|| KernelError::new("unknown file object"))?;
    if callbacks.cleanup.is_some() {
        record.callbacks.cleanup = callbacks.cleanup;
    }
    if callbacks.close.is_some() {
        record.callbacks.close = callbacks.close;
    }
    if callbacks.destroy.is_some() {
        record.callbacks.destroy = callbacks.destroy;
    }
    Ok(())
}

/// Rotinas de vida atuais (para encadear sem substituir as existentes).
pub fn callbacks(pointer: u64) -> Option<FileCallbacks> {
    FILES.lock().get(&pointer).map(|record| record.callbacks.clone())
}

/// Retém o corpo; recusa referência durante a destruição.
pub fn reference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let mut files = FILES.lock();
    let Some(record) = files.get_mut(&pointer) else { return Ok(None) };
    if record.closing {
        return Err(KernelError::new("reference to closing file object"));
    }
    record.references += 1;
    Ok(Some(record.references))
}

/// CLEANUP uma única vez, publicando FO_CLEANUP_COMPLETE.
pub fn cleanup(pointer: u64) -> Result<u32, KernelError> {
    let routine = {
        let mut files = FILES.lock();
        let record = files.get_mut(&pointer).ok_or_else(|| KernelError::new("unknown file cleanup"))?;
        if record.cleaned {
            return Ok(0);
        }
        record.cleaned = true;
        record.callbacks.cleanup.clone()
    };
    let status = routine.map_or(0, |routine| routine());
    // OR atômico: drivers de sistema de arquivos mexem nos mesmos flags.
    file(pointer).flags.atomic().fetch_or(FO_CLEANUP_COMPLETE, Ordering::SeqCst);
    Ok(status)
}

/// A última referência executa cleanup pendente, close e destroy antes de
/// liberar nome e corpo.
pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let (opened, callbacks) = {
        let mut files = FILES.lock();
        let Some(record) = files.get_mut(&pointer) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("file reference underflow"));
        }
        record.references -= 1;
        if record.references != 0 {
            return Ok(Some(record.references));
        }
        if record.handles != 0 || record.closing {
            return Err(KernelError::new("invalid file destruction"));
        }
        record.closing = true;
        (record.opened, record.callbacks.clone())
    };
    if opened {
        cleanup(pointer)?;
    }
    if let Some(close) = callbacks.close {
        close();
    }
    if let Some(destroy) = callbacks.destroy {
        destroy();
    }
    let record = FILES.lock().remove(&pointer);
    object_types::account(&file_type().name, -1, 0)?;
    if let Some(record) = record {
        if record.name_buffer != 0 {
            guest::free_bytes(record.name_buffer);
        }
    }
    // IopDeleteFile: FILE_OBJECT.FileObjectExtension vai junto.
    crate::ntos::io::extensions::free_file_object_extension(pointer);
    guest::free_bytes(pointer);
    Ok(Some(0))
}

/// Primeira abertura, referências e handles; publica FO_HANDLE_CREATED.
pub fn open_handle(pointer: u64) -> Result<(), KernelError> {
    {
        let mut files = FILES.lock();
        let record = files.get_mut(&pointer).filter(|record| !record.cleaned && !record.closing).ok_or_else(|| KernelError::new("cannot open cleaned file object"))?;
        record.opened = true;
        record.handles += 1;
        record.references += 1;
    }
    file(pointer).flags.atomic().fetch_or(FO_HANDLE_CREATED, Ordering::SeqCst);
    object_types::account(&file_type().name, 0, 1)
}

/// Marca a abertura sem publicar handle: o provedor de usuário é dono de
/// cada handle publicado (`record.opened = true`).
pub fn mark_opened(pointer: u64) -> Result<(), KernelError> {
    FILES.lock().get_mut(&pointer).map(|record| record.opened = true).ok_or_else(|| KernelError::new("unknown file object"))
}

/// Fecha um handle; o último inicia o cleanup e solta a referência.
pub fn close_handle(pointer: u64) -> Result<u32, KernelError> {
    let remaining = {
        let mut files = FILES.lock();
        let record = files.get_mut(&pointer).filter(|record| record.handles != 0).ok_or_else(|| KernelError::new("file handle underflow"))?;
        record.handles -= 1;
        record.handles
    };
    object_types::account(&file_type().name, 0, -1)?;
    let status = if remaining != 0 { 0 } else { cleanup(pointer)? };
    dereference(pointer)?;
    Ok(status)
}

/// Direitos genéricos de arquivo, sem os bits genéricos.
pub fn access(requested: u32) -> u32 {
    let mut result = requested;
    for (index, &value) in file_type().mapping.iter().enumerate() {
        if result & (0x8000_0000 >> index) != 0 {
            result |= value;
        }
    }
    result & 0x0FFF_FFFF
}

/// Retém a fonte exata de uma imagem e liga sua liberação ao FILE_OBJECT.
pub fn create_source(source: Arc<dyn FileSource>) -> Result<u64, KernelError> {
    source.acquire();
    let pointer = match create(0, source.name()) {
        Ok(pointer) => pointer,
        Err(error) => {
            source.release();
            return Err(error);
        }
    };
    let releaser = source.clone();
    if let Some(record) = FILES.lock().get_mut(&pointer) {
        record.source = Some(source);
        record.callbacks.destroy = Some(Arc::new(move || releaser.release()));
    }
    file(pointer).read_access.set(1);
    file(pointer).shared_read.set(1);
    Ok(pointer)
}

pub fn source(pointer: u64) -> Option<Arc<dyn FileSource>> {
    FILES.lock().get(&pointer).and_then(|record| record.source.clone())
}

/// Cursor de enumeração de EAs do arquivo.
pub fn ea_index(pointer: u64) -> Result<u32, KernelError> {
    FILES.lock().get(&pointer).map(|record| record.ea_index).ok_or_else(|| KernelError::new("unknown EA file object"))
}

pub fn set_ea_index(pointer: u64, index: u32) -> Result<(), KernelError> {
    FILES.lock().get_mut(&pointer).map(|record| record.ea_index = index).ok_or_else(|| KernelError::new("unknown EA file object"))
}

pub fn is_file(pointer: u64) -> bool {
    FILES.lock().contains_key(&pointer)
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    FILES.lock().get(&pointer).map(|record| record.references)
}

/// (handles, aberto, cleanup feito, fechando).
pub fn state(pointer: u64) -> Option<(u32, bool, bool, bool)> {
    FILES.lock().get(&pointer).map(|record| (record.handles, record.opened, record.cleaned, record.closing))
}

/// IoReplaceFileObjectName: FileName.Buffer passou a ser outro bloco da arena
/// (o antigo já foi liberado pelo chamador); a destruição libera o novo.
pub fn set_name_buffer(pointer: u64, buffer: u64) -> Result<(), KernelError> {
    FILES.lock().get_mut(&pointer).map(|record| record.name_buffer = buffer).ok_or_else(|| KernelError::new("unknown file object"))
}
