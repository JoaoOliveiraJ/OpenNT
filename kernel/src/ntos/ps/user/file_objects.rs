//! Um FILE_OBJECT por descrição aberta.
//!
//! Aliases de usuário, aberturas nativas por ponteiro e referências de seção
//! retêm o mesmo corpo e o mesmo backing. A posição do arquivo vive no
//! CurrentByteOffset do FILE_OBJECT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::any::Any;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::state::{NativeBody, UserObject};
use crate::drivers::fs::volume::{FileSystem, VolumeStat};
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::io::file::lifetime::{self as file_lifetime, Entry};
use crate::ntos::ob::objects::file::{self as file_objects, FileCallbacks, FileSource};
use crate::ntos::ob::object_types;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::file_object;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static OPEN_FILES: SpinLock<BTreeMap<u64, Weak<UserFile>>> = SpinLock::new(BTreeMap::new());

/// Enumeração de diretório da descrição aberta.
#[derive(Clone)]
pub struct Enumeration {
    pub pattern: String,
    /// (nome, caminho no volume).
    pub entries: Vec<(String, String)>,
    pub cursor: usize,
}

/// Descrição aberta de um arquivo do volume, compartilhada pelos handles
/// duplicados.
pub struct UserFile {
    pub id: u64,
    pub file: Arc<VolumeFile>,
    pub access: u32,
    pub share: u32,
    pub options: u32,
    pub nt_path: SpinLock<String>,
    pub delete_requested: AtomicBool,
    pub delete_on_close: AtomicBool,
    pub enumeration: SpinLock<Option<Enumeration>>,
    file_object: AtomicU64,
}

impl UserFile {
    pub fn new(file: Arc<VolumeFile>, access: u32, share: u32, options: u32, nt_path: &str) -> Arc<Self> {
        let entry = Arc::new(Self { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), file, access, share, options, nt_path: SpinLock::new(String::from(nt_path)), delete_requested: AtomicBool::new(false), delete_on_close: AtomicBool::new(options & 0x1000 != 0), enumeration: SpinLock::new(None), file_object: AtomicU64::new(0) });
        OPEN_FILES.lock().insert(entry.id, Arc::downgrade(&entry));
        entry
    }

    pub fn file_object(&self) -> u64 {
        self.file_object.load(Ordering::Acquire)
    }

    /// CurrentByteOffset do FILE_OBJECT.
    pub fn position(&self) -> u64 {
        match self.file_object() {
            0 => 0,
            pointer => guest::read64(pointer + file_object::CURRENT_BYTE_OFFSET),
        }
    }

    pub fn set_position(&self, value: u64) {
        let pointer = self.file_object();
        if pointer != 0 {
            guest::write64(pointer + file_object::CURRENT_BYTE_OFFSET, value);
        }
    }
}

impl UserObject for UserFile {
    fn kind(&self) -> &'static str {
        "file"
    }
    fn native_body(&self) -> Option<NativeBody> {
        let pointer = self.file_object();
        if pointer == 0 {
            return None;
        }
        Some(NativeBody {
            pointer,
            type_name: object_types::file_type().name.clone(),
            record: pointer,
            reference: Arc::new(move || {
                let _ = file_objects::reference(pointer);
            }),
            dereference: Arc::new(move || {
                let _ = file_objects::dereference(pointer);
            }),
        })
    }
    fn on_each_handle_open(&self) -> Result<bool, KernelError> {
        file_objects::open_handle(self.file_object())?;
        Ok(true)
    }
    fn on_each_handle_close(&self) {
        let _ = file_objects::close_handle(self.file_object());
    }
    /// A referência da descrição aberta sobrevive às esperas de usuário.
    fn release(&self) {
        let _ = file_objects::dereference(self.file_object());
    }
    fn object_path(&self) -> Option<String> {
        self.file.directory().then(|| self.nt_path.lock().clone())
    }
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// A fonte do FILE_OBJECT: o arquivo do volume com o nome da abertura.
struct UserFileSource {
    file: Arc<VolumeFile>,
    name: String,
}

impl FileSource for UserFileSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.file.refresh();
        self.file.size()
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        self.file.read_at(offset, length as u64)
    }
    fn stat(&self) -> Option<VolumeStat> {
        self.file.refresh();
        let stat = self.file.stat();
        Some(VolumeStat { reference: Some(stat.reference), sequence: stat.sequence, directory: stat.directory, size: stat.size, allocated: stat.allocated, attributes: stat.attributes, ea_size: stat.ea_size, need_ea: stat.need_ea, times: stat.times })
    }
    fn volume(&self) -> Option<&'static dyn FileSystem> {
        volume_files::fixed_volume().map(|fixed| fixed as &'static dyn FileSystem)
    }
}

/// Cria o FILE_OBJECT da descrição (acessos, compartilhamento, flags e
/// DeletePending), liga a destruição e a vida do arquivo; uma falha solta o
/// corpo recém-criado.
pub fn bind(entry: &Arc<UserFile>, destroy: Arc<dyn Fn() + Send + Sync>) -> Result<u64, KernelError> {
    let file = &entry.file;
    let pointer = file_objects::create_source(Arc::new(UserFileSource { file: file.clone(), name: entry.nt_path.lock().clone() }))?;
    let result = (|| -> Result<(), KernelError> {
        guest::write8(pointer + 0x4A, (entry.access & 1 != 0) as u8);
        guest::write8(pointer + 0x4B, (entry.access & 6 != 0) as u8);
        guest::write8(pointer + 0x4C, (entry.access & 0x1_0000 != 0) as u8);
        for bit in 0..3 {
            guest::write8(pointer + 0x4D + bit, ((entry.share >> bit) & 1) as u8);
        }
        let options = entry.options;
        let flags = (if options & 0x30 != 0 { 2 } else { 0 }) | (if options & 0x10 != 0 { 4 } else { 0 }) | (options & 8) | (if options & 2 != 0 { 0x10 } else { 0 }) | (if options & 0x1000 != 0 { 0x1_0000 } else { 0 });
        guest::write32(pointer + file_object::FLAGS, flags);
        guest::write8(pointer + 0x49, file.pending_delete() as u8);
        entry.file_object.store(pointer, Ordering::Release);
        file_objects::set_callbacks(pointer, FileCallbacks { cleanup: None, close: None, destroy: Some(destroy) })?;
        let marks = file.marks.clone();
        file_lifetime::bind(Entry { access: entry.access, share: entry.share, file_object: pointer, file: Some(marks) }, &file_lifetime::lifetime_volume(volume_files::fixed_volume().ok_or_else(|| KernelError::new("volume de boot ausente"))?), &file.volume_path())
    })();
    if let Err(error) = result {
        let _ = file_objects::dereference(pointer);
        return Err(error);
    }
    Ok(pointer)
}

/// DeletePending de todas as aberturas do arquivo.
pub fn update_delete_state(file: &VolumeFile) {
    let pending = file.pending_delete() as u8;
    let opens = file.opens.lock().clone();
    let entries: Vec<Arc<UserFile>> = {
        let registry = OPEN_FILES.lock();
        opens.iter().filter_map(|id| registry.get(id).and_then(Weak::upgrade)).collect()
    };
    for entry in entries {
        let pointer = entry.file_object();
        if pointer != 0 {
            guest::write8(pointer + 0x49, pending);
        }
    }
}

/// A descrição viva pelo id.
pub fn lookup(id: u64) -> Option<Arc<UserFile>> {
    OPEN_FILES.lock().get(&id).and_then(Weak::upgrade)
}

/// Esquece a descrição destruída.
pub fn forget(id: u64) {
    OPEN_FILES.lock().remove(&id);
}
