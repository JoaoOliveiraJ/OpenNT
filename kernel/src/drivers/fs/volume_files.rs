//! Arquivos do volume de boot — `system32/ntos/fs/volume-files.js`.
//!
//! Compartilha a tradução de caminhos e os objetos de arquivo do volume
//! entre o loader de usuário, o leitor NLS e as seções. Importar não monta o
//! disco: a montagem do boot é reutilizada sob demanda. O cache de leitura
//! guarda blocos de 64 KiB (oito por arquivo, 4 MiB no total, LRU global);
//! descartar um bloco não altera o arquivo nem as páginas de uma seção.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::native_file_name;
use super::ntfs::{self, Ntfs, Stat};
use crate::ntos::io::file::lifetime::FileMarks;
use crate::ntos::ps::user::sections::SectionFile;
use crate::rtl::{KernelError, SpinLock};

const READ_CACHE_BLOCK_BYTES: u64 = 64 * 1024;
const READ_CACHE_BLOCKS_PER_FILE: usize = 8;
const READ_CACHE_BYTE_LIMIT: u64 = 4 * 1024 * 1024;

/// Cache de blocos: (arquivo, offset) → bytes, ordem LRU global e ordem de
/// inserção por arquivo.
struct ReadCache {
    blocks: BTreeMap<(u64, u64), Arc<Vec<u8>>>,
    lru: VecDeque<(u64, u64)>,
    per_file: BTreeMap<u64, VecDeque<u64>>,
    bytes: u64,
}

static CACHE: SpinLock<ReadCache> = SpinLock::new(ReadCache { blocks: BTreeMap::new(), lru: VecDeque::new(), per_file: BTreeMap::new(), bytes: 0 });
static FILES: SpinLock<BTreeMap<String, Arc<VolumeFile>>> = SpinLock::new(BTreeMap::new());
static VOLUME: SpinLock<Option<(Arc<Ntfs>, &'static Ntfs)>> = SpinLock::new(None);
static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

impl ReadCache {
    fn evict(&mut self, key: (u64, u64)) {
        if let Some(bytes) = self.blocks.remove(&key) {
            self.bytes -= bytes.len() as u64;
        }
        self.lru.retain(|entry| *entry != key);
        if let Some(order) = self.per_file.get_mut(&key.0) {
            order.retain(|&offset| offset != key.1);
        }
    }

    fn clear(&mut self, file: u64) {
        let offsets: Vec<u64> = self.per_file.get(&file).map(|order| order.iter().copied().collect()).unwrap_or_default();
        for offset in offsets {
            self.evict((file, offset));
        }
        self.per_file.remove(&file);
    }

    /// Libera antes de alocar o bloco novo: a leitura pode falhar sem deixar
    /// referência órfã nem estourar o orçamento.
    fn reserve(&mut self, file: u64, length: u64) -> Result<(), KernelError> {
        if self.per_file.get(&file).map_or(0, |order| order.len()) >= READ_CACHE_BLOCKS_PER_FILE {
            if let Some(&oldest) = self.per_file.get(&file).and_then(|order| order.front()) {
                self.evict((file, oldest));
            }
        }
        while self.bytes + length > READ_CACHE_BYTE_LIMIT {
            let Some(&oldest) = self.lru.front() else { return Err(KernelError::new("volume read cache accounting mismatch")) };
            self.evict(oldest);
        }
        Ok(())
    }

    fn touch(&mut self, key: (u64, u64)) -> Result<(), KernelError> {
        let Some(position) = self.lru.iter().position(|entry| *entry == key) else { return Err(KernelError::new("volume read cache lost block ownership")) };
        self.lru.remove(position);
        self.lru.push_back(key);
        Ok(())
    }
}

/// Normaliza separadores e prefixos NT/DOS, aceita as unidades C e D e
/// preserva subdiretórios; só os aliases de instalação apontam para a raiz
/// do disco de boot. `.`/`..` e caracteres proibidos são recusados.
pub fn nt_path_to_volume_path(nt_path: &str) -> Option<String> {
    let mut path = nt_path.replace('/', "\\");
    for prefix in ["\\??\\", "\\\\?\\", "\\?\\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = String::from(rest);
            break;
        }
    }
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' {
        if !matches!(bytes[0].to_ascii_lowercase(), b'c' | b'd') {
            return None;
        }
        path = String::from(&path[2..]);
    }
    let mut path = String::from(path.trim_matches('\\'));
    for prefix in ["ntfs", "windows\\globalization\\sorting", "systemroot\\globalization\\sorting", "windows\\system32", "systemroot\\system32", "windows", "systemroot"] {
        let lower = path.to_lowercase();
        if lower == prefix {
            path = String::new();
            break;
        }
        if lower.starts_with(&alloc::format!("{prefix}\\")) {
            path = String::from(&path[prefix.len() + 1..]);
            break;
        }
    }
    let components: Vec<&str> = path.split('\\').filter(|component| !component.is_empty()).collect();
    if components.iter().any(|component| *component == "." || *component == ".." || component.chars().any(|character| (character as u32) < 0x20 || ":*?\"<>|".contains(character))) {
        return None;
    }
    Some(alloc::format!("/{}", components.join("/")))
}

struct FileState {
    size: u64,
    directory: bool,
    stat: Stat,
    generation: u64,
    bytes: Option<Arc<Vec<u8>>>,
}

/// Arquivo do volume com metadados por geração, dados completos opcionais e
/// blocos de leitura.
struct Paths {
    nt_path: String,
    volume_path: String,
    base_name: String,
}

pub struct VolumeFile {
    id: u64,
    paths: SpinLock<Paths>,
    volume: Arc<Ntfs>,
    state: SpinLock<FileState>,
    /// `pendingDelete`/`deleted`, compartilhadas com o `file-lifetime`.
    pub marks: Arc<FileMarks>,
    /// Descrições abertas pelo processo (`opens`), por id.
    pub opens: SpinLock<Vec<u64>>,
}

impl VolumeFile {
    pub fn nt_path(&self) -> String {
        self.paths.lock().nt_path.clone()
    }

    pub fn volume_path(&self) -> String {
        self.paths.lock().volume_path.clone()
    }

    pub fn base_name(&self) -> String {
        self.paths.lock().base_name.clone()
    }

    pub fn volume(&self) -> &Arc<Ntfs> {
        &self.volume
    }

    pub fn size(&self) -> u64 {
        self.state.lock().size
    }

    pub fn directory(&self) -> bool {
        self.state.lock().directory
    }

    pub fn deleted(&self) -> bool {
        self.marks.deleted.load(Ordering::Acquire)
    }

    pub fn set_deleted(&self, deleted: bool) {
        self.marks.deleted.store(deleted, Ordering::Release);
    }

    pub fn pending_delete(&self) -> bool {
        self.marks.pending_delete.load(Ordering::Acquire)
    }

    pub fn set_pending_delete(&self, pending: bool) {
        self.marks.pending_delete.store(pending, Ordering::Release);
    }

    pub fn stat(&self) -> Stat {
        self.state.lock().stat.clone()
    }

    /// Uma geração nova invalida bytes e blocos; referência e sequência do
    /// registro distinguem o mesmo arquivo de outro que reutilizou a posição.
    pub fn refresh(&self) {
        let current_generation = self.volume.generation();
        if self.state.lock().generation == current_generation {
            return;
        }
        let current = self.volume.stat(&self.volume_path()).ok().flatten();
        {
            let mut state = self.state.lock();
            let deleted = current.as_ref().is_none_or(|stat| stat.reference != state.stat.reference || stat.sequence != state.stat.sequence);
            self.marks.deleted.store(deleted, Ordering::Release);
            if !deleted {
                if let Some(stat) = current {
                    state.size = stat.size;
                    state.directory = stat.directory;
                    state.stat = stat;
                }
            }
            state.bytes = None;
            state.generation = current_generation;
        }
        CACHE.lock().clear(self.id);
    }

    /// Materializa o arquivo inteiro só no primeiro uso da geração.
    pub fn read_all(&self) -> Option<Arc<Vec<u8>>> {
        self.refresh();
        if let Some(bytes) = self.state.lock().bytes.clone() {
            return Some(bytes);
        }
        let bytes = Arc::new(self.volume.read_range(&self.volume_path(), 0, self.size()).ok().flatten()?);
        self.state.lock().bytes = Some(bytes.clone());
        Some(bytes)
    }

    /// Limitado ao EOF; pedidos acima de 64 KiB leem direto, os menores
    /// passam pelo cache.
    pub fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        self.refresh();
        let size = self.size();
        if offset >= size {
            return Ok(Vec::new());
        }
        let length = length.min(size - offset);
        if length > READ_CACHE_BLOCK_BYTES {
            return self.volume.read_range(&self.volume_path(), offset, length)?.ok_or_else(|| KernelError::new(alloc::format!("NTFS: leitura falhou: {}", self.volume_path())));
        }
        let mut result = Vec::with_capacity(length as usize);
        while (result.len() as u64) < length {
            let current = offset + result.len() as u64;
            let block_offset = current / READ_CACHE_BLOCK_BYTES * READ_CACHE_BLOCK_BYTES;
            let key = (self.id, block_offset);
            let cached = CACHE.lock().blocks.get(&key).cloned();
            let block = match cached {
                Some(block) => block,
                None => {
                    let block_length = READ_CACHE_BLOCK_BYTES.min(size - block_offset);
                    CACHE.lock().reserve(self.id, block_length)?;
                    let fetched = self.volume.read_range(&self.volume_path(), block_offset, block_length)?;
                    let Some(fetched) = fetched.filter(|bytes| bytes.len() as u64 == block_length) else { return Err(KernelError::new(alloc::format!("NTFS: leitura falhou: {}", self.volume_path()))) };
                    let block = Arc::new(fetched);
                    let mut cache = CACHE.lock();
                    cache.blocks.insert(key, block.clone());
                    cache.lru.push_back(key);
                    cache.per_file.entry(self.id).or_default().push_back(block_offset);
                    cache.bytes += block.len() as u64;
                    block
                }
            };
            CACHE.lock().touch(key)?;
            let start = (current - block_offset) as usize;
            let count = ((length - result.len() as u64) as usize).min(block.len() - start);
            result.extend_from_slice(&block[start..start + count]);
        }
        Ok(result)
    }

    /// Cópia física pelo volume, sem buffer completo intermediário.
    pub fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Result<(), KernelError> {
        self.volume.copy_range_to_physical(&self.volume_path(), offset, address, length)
    }
}

impl SectionFile for VolumeFile {
    fn size(&self) -> u64 {
        VolumeFile::size(self)
    }
    fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        VolumeFile::read_at(self, offset, length)
    }
    fn has_copy_to_physical(&self) -> bool {
        true
    }
    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Result<(), KernelError> {
        VolumeFile::copy_to_physical(self, offset, address, length)
    }
    fn nt_path(&self) -> Option<String> {
        Some(VolumeFile::nt_path(self))
    }
}

/// O volume do loader: a montagem do boot (mesmo cache e identidade das
/// aberturas do kernel) ou o disco 1; falha de montagem é ausência.
pub fn volume() -> Option<Arc<Ntfs>> {
    volume_entry().map(|(volume, _)| volume)
}

/// O volume e a referência estática com o mesmo ponteiro de dados (a forma
/// usada pela montagem do boot no namespace).
fn volume_entry() -> Option<(Arc<Ntfs>, &'static Ntfs)> {
    let mut volume = VOLUME.lock();
    if volume.is_none() {
        if let Some(mounted) = ntfs::mounted().or_else(|| ntfs::mount(1).ok()) {
            let fixed: &'static Ntfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(mounted.clone()));
            *volume = Some((mounted, fixed));
        }
    }
    volume.clone()
}

/// A referência estática do volume (a forma registrada no namespace).
pub fn fixed_volume() -> Option<&'static Ntfs> {
    volume_entry().map(|(_, fixed)| fixed)
}

/// Descarta a entrada do cache (`cache.delete`).
pub fn forget(volume_path: &str) {
    FILES.lock().remove(&volume_path.to_uppercase());
}

/// Busca pelo caminho normalizado, revalida por geração e descarta
/// arquivos removidos ou substituídos.
pub fn lookup_volume_file(nt_path: &str) -> Option<Arc<VolumeFile>> {
    let volume_path = nt_path_to_volume_path(nt_path)?;
    let key = volume_path.to_uppercase();
    let cached = FILES.lock().get(&key).cloned();
    if let Some(file) = cached {
        file.refresh();
        if !file.deleted() {
            return Some(file);
        }
        FILES.lock().remove(&key);
    }
    let (volume, fixed) = volume_entry()?;
    let stat = volume.stat(&volume_path).ok().flatten()?;
    let fs: &'static dyn super::volume::FileSystem = fixed;
    let file = Arc::new(VolumeFile {
        id: NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        paths: SpinLock::new(Paths { nt_path: native_file_name::from_volume(fs, &volume_path).unwrap_or_else(|| String::from(nt_path)), base_name: String::from(&volume_path[1..]), volume_path }),
        state: SpinLock::new(FileState { size: stat.size, directory: stat.directory, generation: volume.generation(), stat, bytes: None }),
        volume,
        marks: Arc::new(FileMarks::default()),
        opens: SpinLock::new(Vec::new()),
    });
    FILES.lock().insert(key, file.clone());
    Some(file)
}

/// Renomeação no volume: o arquivo e os descendentes (renomear diretório)
/// trocam caminho, nome nativo e chave de cache. Devolve os atualizados.
pub fn retarget(old: &str, target: &str) -> Vec<Arc<VolumeFile>> {
    let old_upper = old.to_uppercase();
    let fixed = fixed_volume();
    let items: Vec<(String, Arc<VolumeFile>)> = FILES.lock().iter().map(|(key, item)| (key.clone(), item.clone())).collect();
    let mut updated = Vec::new();
    for (key, item) in items {
        let current = item.volume_path();
        let upper = current.to_uppercase();
        if upper != old_upper && !upper.starts_with(&alloc::format!("{old_upper}/")) {
            continue;
        }
        FILES.lock().remove(&key);
        let volume_path = alloc::format!("{}{}", target, &current[old.len()..]);
        let nt_path = fixed.and_then(|fixed| native_file_name::from_volume(fixed, &volume_path)).unwrap_or_else(|| alloc::format!("\\??\\C:{}", volume_path.replace('/', "\\")));
        let base_name = String::from(&volume_path[volume_path.rfind('/').map_or(0, |index| index + 1)..]);
        *item.paths.lock() = Paths { nt_path, volume_path: volume_path.clone(), base_name };
        item.refresh();
        FILES.lock().insert(volume_path.to_uppercase(), item.clone());
        updated.push(item);
    }
    updated
}
