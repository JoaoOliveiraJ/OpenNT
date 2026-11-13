//! Arquivo capturado por uma seção.
//!
//! Captura o arquivo aberto, nunca uma nova busca inferida pelo nome. A seção
//! é dona desta referência até a última vista, handle ou ponteiro. O ramo de
//! handles de arquivo de usuário entra com `ps/user/files`; hoje o resolvedor
//! devolve handles nativos e de kernel.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::hal::physical;
use crate::drivers::fs::native_file_name;
use crate::drivers::fs::volume::FileSystem;
use crate::ntos::io::file::{lifetime as file_lifetime, query as query_file};
use crate::ntos::ob::objects::file::{self as file_objects, FileSource};
use crate::ntos::ps::user::sections::SectionFile;
use crate::rtl::{KernelError, SpinLock};

/// Identidade por objeto + caminho em minúsculas.
static IDENTITIES: SpinLock<(BTreeMap<usize, u64>, u64)> = SpinLock::new((BTreeMap::new(), 0));

fn key(object: usize, path: &str) -> String {
    let mut identities = IDENTITIES.lock();
    let id = match identities.0.get(&object) {
        Some(&id) => id,
        None => {
            identities.1 += 1;
            let id = identities.1;
            identities.0.insert(object, id);
            id
        }
    };
    format!("{}:{}", id, path.to_lowercase())
}

fn volume_address(volume: &'static dyn FileSystem) -> usize {
    volume as *const dyn FileSystem as *const u8 as usize
}

/// O arquivo retido pela seção.
pub struct CapturedFile {
    size: AtomicU64,
    pub name: String,
    pub base_name: String,
    identity: String,
    pointer: AtomicU64,
    pub access: u32,
    backing: Option<(&'static dyn FileSystem, String)>,
    source: Option<Arc<dyn FileSource>>,
    image: bool,
    held: AtomicBool,
    backing_reference: AtomicU64,
}

impl CapturedFile {
    pub fn pointer(&self) -> u64 {
        self.pointer.load(Ordering::Acquire)
    }

    pub fn volume(&self) -> Option<&'static dyn FileSystem> {
        self.backing.as_ref().map(|(volume, _)| *volume)
    }

    pub fn volume_path(&self) -> Option<String> {
        self.backing.as_ref().map(|(_, path)| path.clone())
    }

    /// Retém o FILE_OBJECT e, com backing de volume, a vida do arquivo para
    /// a seção (imagem impede DELETE_ON_CLOSE).
    pub fn acquire(&self) -> Result<(), KernelError> {
        if self.held.load(Ordering::Acquire) {
            return Err(KernelError::new("section file already retained"));
        }
        if file_objects::reference(self.pointer())?.is_none() {
            return Err(KernelError::new("section file disappeared"));
        }
        if let Some((volume, path)) = &self.backing {
            let reference = file_lifetime::retain_section(&file_lifetime::lifetime_volume(*volume), path, self.image);
            self.backing_reference.store(reference, Ordering::Release);
        }
        self.held.store(true, Ordering::Release);
        Ok(())
    }

    pub fn release(&self) -> Result<(), KernelError> {
        if !self.held.swap(false, Ordering::AcqRel) {
            return Err(KernelError::new("section file reference underflow"));
        }
        file_objects::dereference(self.pointer())?;
        let reference = self.backing_reference.swap(0, Ordering::AcqRel);
        if reference != 0 {
            file_lifetime::release_section(reference)?;
        }
        Ok(())
    }

    /// Estende o arquivo até o tamanho máximo pedido pela seção.
    pub fn resize(&self, length: u64) -> Result<u32, KernelError> {
        if self.access & 2 == 0 {
            return Ok(0xC000_0022);
        }
        let Some((volume, path)) = &self.backing else { return Ok(0xC000_00A2) };
        match volume.resize(path, length) {
            None => Ok(0xC000_00A2),
            Some(result) => {
                result?;
                self.size.store(length, Ordering::Release);
                Ok(0)
            }
        }
    }
}

impl SectionFile for CapturedFile {
    fn identity(&self) -> Option<String> {
        Some(self.identity.clone())
    }

    fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    /// Bytes desligados (arquivo apagado com seção viva) têm precedência.
    fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        if let Some(detached) = file_lifetime::read_detached(self.backing_reference.load(Ordering::Acquire), offset as usize, length as usize) {
            return Ok(detached);
        }
        let mut data = match (&self.backing, &self.source) {
            (Some((volume, path)), _) => volume.read_range(path, offset, length)?,
            (None, Some(source)) => Some(source.read_at(offset, length as usize)?),
            (None, None) => None,
        };
        if data.is_none() {
            if let Some((volume, path)) = &self.backing {
                data = volume.read_bytes(path).map(|all| {
                    let start = (offset as usize).min(all.len());
                    let end = start.saturating_add(length as usize).min(all.len());
                    all[start..end].to_vec()
                });
            }
        }
        data.ok_or_else(|| KernelError::with_status("section read failed", 0xC000_0185))
    }

    fn has_copy_to_physical(&self) -> bool {
        true
    }

    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Result<(), KernelError> {
        let detached = file_lifetime::read_detached(self.backing_reference.load(Ordering::Acquire), offset as usize, length as usize);
        if detached.is_none() {
            if let Some((volume, path)) = &self.backing {
                if let Some(result) = volume.copy_range_to_physical(path, offset, address, length) {
                    return result;
                }
            }
        }
        let data = match detached {
            Some(data) => data,
            None => self.read_at(offset, length)?,
        };
        if data.len() as u64 != length {
            return Err(KernelError::with_status("short section read", 0xC000_0185));
        }
        physical::write_bytes(address, &data);
        Ok(())
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), KernelError> {
        if file_lifetime::write_detached(self.backing_reference.load(Ordering::Acquire), offset as usize, data)? {
            return Ok(());
        }
        match &self.backing {
            Some((volume, path)) if volume.writable() => volume.write_at(path, offset, data).map(|_| ()),
            _ => Err(KernelError::with_status("readonly section file", 0xC000_00A2)),
        }
    }

    fn nt_path(&self) -> Option<String> {
        Some(self.name.clone())
    }

    fn base_name(&self) -> Option<String> {
        Some(self.base_name.clone()).filter(|name| !name.is_empty())
    }
}

/// Handle de arquivo pelo resolvedor de NtQueryInformationFile.
pub fn capture(handle: u64, mode: u8, protect: u32, image: bool, required: u32) -> Result<Arc<CapturedFile>, u32> {
    let selected = query_file::resolve(handle, mode != 0)?;
    capture_selected(selected.pointer, selected.access, mode, protect, image, required)
}

/// A variante Mm aceita o FILE_OBJECT do chamador, mesmo depois de ele
/// fechar o handle.
pub fn capture_pointer(file_object: u64, protect: u32, image: bool, required: u32) -> Result<Arc<CapturedFile>, u32> {
    if !file_objects::is_file(file_object) {
        return Err(0xC000_0024);
    }
    capture_selected(file_object, required, 0, protect, image, required)
}

fn capture_selected(pointer: u64, access: u32, mode: u8, protect: u32, image: bool, required: u32) -> Result<Arc<CapturedFile>, u32> {
    let base = protect & 255;
    let write = base == 4 || base == 0x40;
    if mode != 0 && required & !access != 0 {
        return Err(0xC000_0022);
    }
    let source = file_objects::source(pointer);
    let backing = crate::ntos::io::file::zw::file_backing(pointer);
    // Um dispositivo sem provedor de seções de sistema de arquivos não
    // fornece control area: é o tipo real do arquivo, não um leitor inventado.
    if source.is_none() && backing.is_none() {
        return Err(0xC000_0020);
    }
    let stat = match &backing {
        Some((volume, path)) => volume.stat(path),
        None => source.as_ref().and_then(|source| source.stat()),
    };
    let size = match &backing {
        Some((volume, path)) => volume.size(path),
        None => stat.as_ref().map(|stat| stat.size).or_else(|| source.as_ref().map(|source| source.size())),
    };
    let Some(size) = size.filter(|&size| size <= (1 << 53) - 1) else { return Err(0xC000_0123) };
    if stat.as_ref().is_some_and(|stat| stat.directory) {
        return Err(0xC000_00BA);
    }
    let backing_writable = backing.as_ref().is_some_and(|(volume, _)| volume.writable());
    if write && !image && (!backing_writable || stat.as_ref().is_some_and(|stat| stat.attributes & 1 != 0)) {
        return Err(0xC000_0022);
    }
    let name = backing
        .as_ref()
        .and_then(|(volume, path)| native_file_name::from_volume(*volume, path))
        .or_else(|| native_file_name::from_file(None, source.as_ref().map(|source| source.name())))
        .or_else(|| backing.as_ref().map(|(_, path)| path.clone()))
        .unwrap_or_default();
    let identity = match (&backing, &source) {
        (Some((volume, path)), _) => {
            let detail = match stat.as_ref().and_then(|stat| stat.reference) {
                Some(reference) => format!("{}:{}", reference, stat.as_ref().map_or(0, |stat| stat.sequence)),
                None => path.clone(),
            };
            key(volume_address(*volume), &detail)
        }
        (None, Some(source)) => key(Arc::as_ptr(source) as *const u8 as usize, "source"),
        (None, None) => unreachable!(),
    };
    let base_name = String::from(&name[name.rfind('\\').map_or(0, |index| index + 1)..]);
    Ok(Arc::new(CapturedFile {
        size: AtomicU64::new(size),
        name,
        base_name,
        identity,
        pointer: AtomicU64::new(pointer),
        access,
        backing,
        source,
        image,
        held: AtomicBool::new(false),
        backing_reference: AtomicU64::new(0),
    }))
}
