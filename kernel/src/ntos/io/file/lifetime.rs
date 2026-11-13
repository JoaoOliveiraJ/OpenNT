//! Exclusão por nome compartilhada — `system32/ntos/io/file-lifetime.js`.
//!
//! Descrições de arquivo do kernel, handles de usuário e SECTIONs dividem o
//! SHARE_ACCESS e a remoção pendente. CLEANUP encerra o compartilhamento; uma
//! referência de SECTION pode conservar os bytes depois da retirada do nome.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::drivers::fs::ntfs::Ntfs;
use crate::ntos::ob::objects::file::{self as file_objects, FileCallbacks};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Metadados que o tempo de vida consulta no volume.
#[derive(Clone, Copy, Debug, Default)]
pub struct LifeStat {
    /// Número do registro (provedores sem inode usam o caminho).
    pub reference: Option<u64>,
    pub sequence: u16,
    pub directory: bool,
    pub attributes: u32,
    pub size: u64,
}

/// Sistema de arquivos montado sob as descrições.
pub trait LifetimeFileSystem: Send + Sync {
    fn stat(&self, path: &str) -> Option<LifeStat>;
    fn size(&self, path: &str) -> u64;
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Option<Vec<u8>>;
    /// `None` = o volume não remove arquivos.
    fn remove(&self, path: &str) -> Option<Result<bool, KernelError>>;
    fn list(&self, path: &str) -> Vec<String>;
}

impl LifetimeFileSystem for Ntfs {
    fn stat(&self, path: &str) -> Option<LifeStat> {
        Ntfs::stat(self, path).ok().flatten().map(|stat| LifeStat { reference: Some(stat.reference), sequence: stat.sequence, directory: stat.directory, attributes: stat.attributes, size: stat.size })
    }
    fn size(&self, path: &str) -> u64 {
        Ntfs::size(self, path).unwrap_or(-1).max(0) as u64
    }
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Option<Vec<u8>> {
        Ntfs::read_range(self, path, offset, length).ok().flatten()
    }
    fn remove(&self, path: &str) -> Option<Result<bool, KernelError>> {
        Some(Ntfs::remove(self, path).map(|_| true))
    }
    fn list(&self, path: &str) -> Vec<String> {
        Ntfs::list(self, path).ok().flatten().unwrap_or_default()
    }
}

/// Adaptador de um volume montado (`node.mount`) para o registro de vida.
struct MountedVolume(&'static dyn crate::drivers::fs::volume::FileSystem);

impl LifetimeFileSystem for MountedVolume {
    fn stat(&self, path: &str) -> Option<LifeStat> {
        let stat = self.0.stat(path).or_else(|| self.0.exists(path).then(|| crate::drivers::fs::volume::VolumeStat { size: self.0.size(path).unwrap_or(0), attributes: 0x20, ..Default::default() }))?;
        Some(LifeStat { reference: stat.reference, sequence: stat.sequence, directory: stat.directory, attributes: stat.attributes, size: stat.size })
    }
    fn size(&self, path: &str) -> u64 {
        self.0.size(path).unwrap_or(0)
    }
    fn read_range(&self, path: &str, offset: u64, length: u64) -> Option<Vec<u8>> {
        self.0.read_range(path, offset, length).ok().flatten()
    }
    fn remove(&self, path: &str) -> Option<Result<bool, KernelError>> {
        self.0.remove(path)
    }
    fn list(&self, path: &str) -> Vec<String> {
        let prefix = alloc::format!("{}/", path.trim_end_matches('/'));
        self.0.list().into_iter().filter(|entry| entry.starts_with(&prefix)).collect()
    }
}

static MOUNTED: SpinLock<BTreeMap<usize, Arc<dyn LifetimeFileSystem>>> = SpinLock::new(BTreeMap::new());

/// Identidade estável de um volume montado: o NTFS usa o próprio `Arc`
/// (o mesmo das aberturas de usuário); os demais, um adaptador único.
pub fn lifetime_volume(volume: &'static dyn crate::drivers::fs::volume::FileSystem) -> Arc<dyn LifetimeFileSystem> {
    if let Some(ntfs) = crate::drivers::fs::ntfs::mounted() {
        let ntfs_volume: &dyn crate::drivers::fs::volume::FileSystem = ntfs.as_ref();
        if core::ptr::addr_eq(ntfs_volume as *const dyn crate::drivers::fs::volume::FileSystem, volume as *const dyn crate::drivers::fs::volume::FileSystem) {
            return ntfs;
        }
    }
    let key = volume as *const dyn crate::drivers::fs::volume::FileSystem as *const () as usize;
    MOUNTED.lock().entry(key).or_insert_with(|| Arc::new(MountedVolume(volume))).clone()
}

/// Marcas de um arquivo de usuário (`entry.file` do original).
#[derive(Default)]
pub struct FileMarks {
    pub pending_delete: AtomicBool,
    pub deleted: AtomicBool,
}

/// Descrição aberta: acesso, compartilhamento e FILE_OBJECT.
#[derive(Clone)]
pub struct Entry {
    pub access: u32,
    pub share: u32,
    pub file_object: u64,
    pub file: Option<Arc<FileMarks>>,
}

struct Description {
    state: u64,
    entry: Entry,
    cleaned: bool,
}

struct State {
    file_system: Arc<dyn LifetimeFileSystem>,
    key: (usize, String),
    path: String,
    descriptions: Vec<u64>,
    sections: Vec<u64>,
    pending: bool,
    removed: bool,
    orphan_bytes: Option<Vec<u8>>,
}

struct Section {
    state: u64,
    image: bool,
}

#[derive(Default)]
struct Registry {
    next: u64,
    keys: BTreeMap<(usize, String), u64>,
    states: BTreeMap<u64, State>,
    descriptions: BTreeMap<u64, Description>,
    sections: BTreeMap<u64, Section>,
    /// FILE_OBJECT -> descrição (`record.fileLifetime`).
    bound: BTreeMap<u64, u64>,
}

static REGISTRY: SpinLock<Option<Registry>> = SpinLock::new(None);

fn with<T>(body: impl FnOnce(&mut Registry) -> T) -> T {
    let mut registry = REGISTRY.lock();
    body(registry.get_or_insert_with(Registry::default))
}

fn file_system_id(file_system: &Arc<dyn LifetimeFileSystem>) -> usize {
    Arc::as_ptr(file_system) as *const () as usize
}

/// Cada volume tem suas identidades; registros NTFS reutilizados se
/// distinguem pela sequência e os provedores sem inode usam o caminho.
fn state_for(file_system: &Arc<dyn LifetimeFileSystem>, path: &str) -> u64 {
    let metadata = file_system.stat(path);
    let identity = match metadata.and_then(|stat| stat.reference) {
        Some(reference) => alloc::format!("{reference}:{}", metadata.map_or(0, |stat| stat.sequence)),
        None => path.to_uppercase(),
    };
    let key = (file_system_id(file_system), identity);
    with(|registry| {
        if let Some(&id) = registry.keys.get(&key) {
            let state = registry.states.get_mut(&id).expect("estado registrado");
            if !state.removed {
                state.path = String::from(path);
            }
            return id;
        }
        registry.next += 1;
        let id = registry.next;
        registry.keys.insert(key.clone(), id);
        registry.states.insert(id, State { file_system: file_system.clone(), key, path: String::from(path), descriptions: Vec::new(), sections: Vec::new(), pending: false, removed: false, orphan_bytes: None });
        id
    })
}

/// Consultas sem descrições vivas não acumulam entradas.
fn collect(state: u64) {
    with(|registry| {
        let Some(found) = registry.states.get(&state) else { return };
        if found.descriptions.is_empty() && found.sections.is_empty() && !found.pending {
            let key = found.key.clone();
            if registry.keys.get(&key) == Some(&state) {
                registry.keys.remove(&key);
            }
            registry.states.remove(&state);
        }
    });
}

fn needed_sharing(access: u32) -> u32 {
    (if access & 0x21 != 0 { 1 } else { 0 }) | (if access & 6 != 0 { 2 } else { 0 }) | (if access & 0x1_0000 != 0 { 4 } else { 0 })
}

/// Aberturas só de metadados não entram no SHARE_ACCESS; descrições já
/// limpas, retidas por SECTIONs, não bloqueiam novas aberturas.
fn sharing_status(state: u64, access: u32, share: u32) -> u32 {
    let needed = needed_sharing(access);
    if needed == 0 {
        return 0;
    }
    with(|registry| {
        let Some(found) = registry.states.get(&state) else { return 0 };
        for id in &found.descriptions {
            let description = &registry.descriptions[id];
            let previous = needed_sharing(description.entry.access);
            if description.cleaned || previous == 0 {
                continue;
            }
            if needed & !description.entry.share != 0 || previous & !share != 0 {
                return 0xC000_0043;
            }
        }
        0
    })
}

pub fn validate_open(file_system: &Arc<dyn LifetimeFileSystem>, path: &str, access: u32, share: u32) -> u32 {
    let state = state_for(file_system, path);
    let pending = with(|registry| registry.states.get(&state).is_some_and(|found| found.pending));
    let status = if pending { 0xC000_0056 } else { sharing_status(state, access, share) };
    collect(state);
    status
}

fn publish_pending(state: u64, pending: bool) {
    let entries: Vec<Entry> = with(|registry| {
        let Some(found) = registry.states.get_mut(&state) else { return Vec::new() };
        found.pending = pending;
        found.descriptions.iter().map(|id| registry.descriptions[id].entry.clone()).collect()
    });
    for entry in entries {
        if let Some(file) = &entry.file {
            file.pending_delete.store(pending, Ordering::SeqCst);
        }
        // FILE_OBJECT.DeletePending.
        guest::write8(entry.file_object + 0x49, pending as u8);
    }
}

/// Dados de uma SECTION ganham armazenamento próprio antes de o volume
/// liberar o registro: leituras e writeback não atingem um arquivo novo.
fn capture_orphan(file_system: &Arc<dyn LifetimeFileSystem>, path: &str, sections: bool) -> Result<Option<Vec<u8>>, KernelError> {
    if !sections {
        return Ok(None);
    }
    let size = file_system.size(path);
    match file_system.read_range(path, 0, size) {
        Some(bytes) if bytes.len() as u64 == size => Ok(Some(bytes)),
        _ => Err(KernelError::with_status("cannot retain deleted section backing", 0xC000_0185)),
    }
}

/// NtDeleteFile abre com DELETE_ON_CLOSE; um diretório não vazio conclui a
/// abertura, mas o CLEANUP conserva o diretório e seus filhos.
fn remove_when_closed(state: u64) -> Result<(), KernelError> {
    let snapshot = with(|registry| {
        let found = registry.states.get(&state)?;
        if !found.pending || found.removed || found.descriptions.iter().any(|id| !registry.descriptions[id].cleaned) {
            return None;
        }
        Some((found.file_system.clone(), found.path.clone(), !found.sections.is_empty()))
    });
    let Some((file_system, path, sections)) = snapshot else { return Ok(()) };
    if file_system.stat(&path).is_some_and(|stat| stat.directory) && !file_system.list(&path).is_empty() {
        publish_pending(state, false);
        return Ok(());
    }
    let orphan = capture_orphan(&file_system, &path, sections)?;
    match file_system.remove(&path) {
        Some(Ok(true)) => {}
        Some(Ok(false)) => return Err(KernelError::with_status("file disappeared during deletion", 0xC000_0034)),
        Some(Err(error)) => return Err(error),
        None => return Err(KernelError::with_status("volume sem remocao", 0xC000_00A2)),
    }
    let marks: Vec<Arc<FileMarks>> = with(|registry| {
        let Some(found) = registry.states.get_mut(&state) else { return Vec::new() };
        found.orphan_bytes = orphan;
        found.removed = true;
        found.pending = false;
        let key = found.key.clone();
        let marks = found.descriptions.iter().filter_map(|id| registry.descriptions[id].entry.file.clone()).collect();
        if registry.keys.get(&key) == Some(&state) {
            registry.keys.remove(&key);
        }
        marks
    });
    // Uma descrição antiga não volta a representar outro arquivo do mesmo nome.
    for mark in marks {
        mark.deleted.store(true, Ordering::SeqCst);
    }
    Ok(())
}

/// Encadeia as rotinas existentes do FILE_OBJECT, sem substituir nenhuma
/// retenção do Object Manager, do volume ou do processo.
pub fn bind(entry: Entry, file_system: &Arc<dyn LifetimeFileSystem>, path: &str) -> Result<(), KernelError> {
    let pointer = entry.file_object;
    let existing = file_objects::callbacks(pointer);
    if existing.is_none() || with(|registry| registry.bound.contains_key(&pointer)) {
        return Err(KernelError::new("invalid file lifetime binding"));
    }
    let existing = existing.unwrap_or_default();
    let state = state_for(file_system, path);
    let description = with(|registry| {
        registry.next += 1;
        let id = registry.next;
        registry.descriptions.insert(id, Description { state, entry, cleaned: false });
        registry.bound.insert(pointer, id);
        registry.states.get_mut(&state).expect("estado registrado").descriptions.push(id);
        id
    });
    let cleanup = existing.cleanup.clone();
    let destroy = existing.destroy.clone();
    file_objects::set_callbacks(pointer, FileCallbacks {
        cleanup: Some(Arc::new(move || {
            let status = cleanup.as_ref().map_or(0, |cleanup| cleanup());
            with(|registry| {
                if let Some(found) = registry.descriptions.get_mut(&description) {
                    found.cleaned = true;
                }
            });
            if let Err(error) = remove_when_closed(state) {
                return if error.status != 0 { error.status } else { 0xC000_0185 };
            }
            status
        })),
        close: None,
        destroy: Some(Arc::new(move || {
            if let Some(destroy) = &destroy {
                destroy();
            }
            with(|registry| {
                registry.descriptions.remove(&description);
                registry.bound.remove(&pointer);
                if let Some(found) = registry.states.get_mut(&state) {
                    found.descriptions.retain(|&id| id != description);
                }
            });
            let _ = remove_when_closed(state);
            collect(state);
        })),
    })
}

/// A seção informa se protege uma imagem executável: dados permitem retirar
/// o nome; imagem impede DELETE_ON_CLOSE com CANNOT_DELETE.
pub fn retain_section(file_system: &Arc<dyn LifetimeFileSystem>, path: &str, image: bool) -> u64 {
    let state = state_for(file_system, path);
    with(|registry| {
        registry.next += 1;
        let id = registry.next;
        registry.sections.insert(id, Section { state, image });
        registry.states.get_mut(&state).expect("estado registrado").sections.push(id);
        id
    })
}

pub fn release_section(section: u64) -> Result<(), KernelError> {
    let state = with(|registry| {
        let found = registry.sections.remove(&section)?;
        if let Some(state) = registry.states.get_mut(&found.state) {
            state.sections.retain(|&id| id != section);
        }
        Some(found.state)
    });
    let Some(state) = state else { return Err(KernelError::new("section backing reference underflow")) };
    collect(state);
    Ok(())
}

pub fn read_detached(section: u64, offset: usize, length: usize) -> Option<Vec<u8>> {
    with(|registry| {
        let state = registry.sections.get(&section)?.state;
        let bytes = registry.states.get(&state)?.orphan_bytes.as_ref()?;
        let end = (offset + length).min(bytes.len());
        Some(bytes[offset.min(end)..end].to_vec())
    })
}

pub fn write_detached(section: u64, offset: usize, bytes: &[u8]) -> Result<bool, KernelError> {
    with(|registry| {
        let Some(state) = registry.sections.get(&section).map(|found| found.state) else { return Ok(false) };
        let Some(backing) = registry.states.get_mut(&state).and_then(|found| found.orphan_bytes.as_mut()) else { return Ok(false) };
        if offset + bytes.len() > backing.len() {
            return Err(KernelError::with_status("deleted section write exceeds backing", 0xC000_000D));
        }
        backing[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(true)
    })
}

/// DELETE_PENDING só depois das verificações; uma falha de armazenamento
/// desfaz a marca e propaga o erro real da transação.
pub fn request_delete(file_system: &Arc<dyn LifetimeFileSystem>, path: &str, related: u64) -> Result<u32, KernelError> {
    let related_state = if related != 0 { with(|registry| registry.bound.get(&related).map(|id| registry.descriptions[id].state)) } else { None };
    let state = related_state.unwrap_or_else(|| state_for(file_system, path));
    let result = (|| {
        let (pending, image) = with(|registry| {
            let found = registry.states.get(&state);
            (found.is_some_and(|found| found.pending), found.is_some_and(|found| found.sections.iter().any(|id| registry.sections[id].image)))
        });
        if pending {
            return Ok(if related_state.is_some() { 0 } else { 0xC000_0056 });
        }
        if file_system.stat(path).is_some_and(|stat| stat.attributes & 1 != 0) || image {
            return Ok(0xC000_0121);
        }
        let status = sharing_status(state, 0x1_0000, 7);
        if status != 0 {
            return Ok(status);
        }
        publish_pending(state, true);
        if let Err(error) = remove_when_closed(state) {
            publish_pending(state, false);
            return Err(error);
        }
        Ok(0)
    })();
    collect(state);
    result
}
