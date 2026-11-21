//! Arquivos do volume de boot.
//!
//! Compartilha a tradução de caminhos e os objetos de arquivo do volume
//! entre o loader de usuário, o leitor NLS e as seções. Importar não monta o
//! disco: a montagem do boot é reutilizada sob demanda. O cache de leitura
//! guarda blocos de 64 KiB (oito por arquivo, 4 MiB no total, LRU global)
//! em frames do PFN, lidos do disco direto para eles, como as páginas do
//! cache de sistema do NT (nada do cache fica no heap do kernel); descartar
//! um bloco devolve os frames e não altera o arquivo nem as páginas de uma
//! seção.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::native_file_name;
use super::ntfs::{self, Ntfs, Stat};
use crate::hal::physical;
use crate::ntos::io::file::lifetime::FileMarks;
use crate::ntos::mm::pfn;
use crate::ntos::ps::user::sections::SectionFile;
use crate::rtl::{KernelError, SpinLock};

const READ_CACHE_BLOCK_BYTES: u64 = 64 * 1024;
const READ_CACHE_BLOCKS_PER_FILE: usize = 8;
const READ_CACHE_BYTE_LIMIT: u64 = 4 * 1024 * 1024;
const PAGE: u64 = 0x1000;

/// Um bloco do cache: `length` bytes do arquivo em frames do PFN, uma página
/// por frame. O último `Arc` devolve os frames.
struct CacheBlock {
    frames: Vec<u64>,
    length: u64,
}

impl CacheBlock {
    /// Lê `[offset, offset + length)` do arquivo direto para frames novos,
    /// todos de uma vez (um comando de DMA por trecho contíguo no disco).
    fn read(volume: &Ntfs, path: &str, offset: u64, length: u64) -> Result<CacheBlock, KernelError> {
        let mut block = CacheBlock { frames: Vec::with_capacity(length.div_ceil(PAGE) as usize), length };
        for _ in 0..length.div_ceil(PAGE) {
            let frame = pfn::alloc_page();
            if frame == 0 {
                return Err(KernelError::with_status("volume read cache: PFN esgotado", 0xC000_009A));
            }
            block.frames.push(frame);
        }
        volume.copy_range_to_pages(path, offset, &block.frames, length)?;
        Ok(block)
    }

    /// Acrescenta `[start, start + count)` do bloco a `out`.
    fn copy_out(&self, start: u64, count: u64, out: &mut Vec<u8>) {
        let mut at = start;
        while at < start + count {
            let take = (PAGE - at % PAGE).min(start + count - at);
            let address = physical::range_to_virtual(self.frames[(at / PAGE) as usize] + at % PAGE, take);
            // SAFETY: frames do bloco (só ele os escreve, na leitura), pelo
            // mapa direto.
            out.extend_from_slice(unsafe { core::slice::from_raw_parts(address as *const u8, take as usize) });
            at += take;
        }
    }
}

impl Drop for CacheBlock {
    fn drop(&mut self) {
        for &frame in &self.frames {
            pfn::free_page(frame);
        }
    }
}

/// Cache de blocos: (arquivo, offset) → bytes, ordem LRU global e ordem de
/// inserção por arquivo.
struct ReadCache {
    blocks: BTreeMap<(u64, u64), Arc<CacheBlock>>,
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
        if let Some(block) = self.blocks.remove(&key) {
            self.bytes -= block.length;
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

    /// Libera antes de inserir o bloco novo: o orçamento nunca estoura, e
    /// uma leitura que falha não deixa referência órfã.
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

/// Os diretórios de instalação cujo conteúdo o volume de boot guarda na
/// raiz, do mais longo ao mais curto: os mesmos aliases de
/// [`nt_path_to_volume_path`], já relativos ao volume.
const INSTALL_ALIASES: [&str; 3] = ["/windows/globalization/sorting/", "/windows/system32/", "/windows/"];

/// O alias de instalação para um caminho já relativo ao volume de boot (a
/// abertura pelo dispositivo ou pelo `\SystemRoot`,
/// `\Device\KernelVolume1\Windows\System32\X`, `\SystemRoot\Fonts\X`): o
/// conteúdo de `\Windows` (os programas de System32, as fontes, os temas...)
/// fica na raiz do volume, como o modo usuário o abre por
/// [`nt_path_to_volume_path`]; então `/Windows/System32/X` ou
/// `/Windows/Fonts/X` que não existe vira `/X` ou `/Fonts/X` quando este
/// existe, e o kernel e o modo usuário abrem o mesmo arquivo. O caminho
/// literal que existe (os drivers e catálogos de `/Windows/System32`) fica
/// como está; fora de `\Windows`, `None`.
pub fn install_alias(volume_path: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    let lower = volume_path.replace('\\', "/").to_lowercase();
    let prefix = INSTALL_ALIASES.iter().find(|prefix| lower.starts_with(*prefix))?;
    let rest = &volume_path[prefix.len()..];
    if rest.is_empty() || exists(volume_path) {
        return None;
    }
    let aliased = alloc::format!("/{rest}");
    exists(&aliased).then_some(aliased)
}

/// O nome de um arquivo do volume relativo ao dispositivo, como o
/// IopParseDevice o deixa no FILE_OBJECT.FileName: o caminho depois da
/// unidade ou do dispositivo do volume (`\SystemRoot` é o `\Windows` dele),
/// sem os aliases de instalação de [`nt_path_to_volume_path`] — o
/// `C:\Windows\System32\kbdus.dll` continua `\Windows\System32\kbdus.dll`.
pub fn nt_path_to_device_name(nt_path: &str) -> Option<String> {
    let mut path = nt_path.replace('/', "\\");
    for prefix in ["\\??\\", "\\\\?\\", "\\?\\", "\\DosDevices\\", "\\GLOBAL??\\"] {
        if path.len() >= prefix.len() && path[..prefix.len()].eq_ignore_ascii_case(prefix) {
            path = String::from(&path[prefix.len()..]);
            break;
        }
    }
    let bytes = path.as_bytes();
    let rest = if bytes.len() >= 2 && bytes[1] == b':' {
        String::from(&path[2..])
    } else {
        let trimmed = path.trim_start_matches('\\');
        let lower = trimmed.to_lowercase();
        if let Some(rest) = ["device\\kernelvolume1"].iter().find_map(|device| lower.strip_prefix(device).map(|_| &trimmed[device.len()..])) {
            String::from(rest)
        } else if lower == "systemroot" || lower.starts_with("systemroot\\") {
            alloc::format!("\\Windows{}", &trimmed["systemroot".len()..])
        } else {
            return None;
        }
    };
    let rest = alloc::format!("\\{}", rest.trim_start_matches('\\'));
    Some(if rest == "\\" { String::new() } else { rest })
}

/// O nome normalizado (NtfsQueryNameInfo com Normalized, ntfs.sys
/// 0xefb00/0xf015c): o nome do dispositivo da abertura
/// ([`nt_path_to_device_name`]) com cada componente trocado pelo nome longo
/// gravado; um componente que só existe pelo alias de instalação
/// ([`install_alias`]) usa o nome da entrada no lugar do alias; um que não
/// existe fica como veio. A raiz é `\`.
pub fn normalized_device_name(volume: &Ntfs, device_name: &str) -> String {
    let (mut literal, mut result) = (String::new(), String::new());
    for component in device_name.split('\\').filter(|part| !part.is_empty()) {
        let next = alloc::format!("{literal}/{component}");
        let stored = volume.long_name(&next).ok().flatten().or_else(|| install_alias(&next, |candidate| volume.exists(candidate).unwrap_or(false)).and_then(|aliased| volume.long_name(&aliased).ok().flatten()));
        result.push('\\');
        result.push_str(stored.as_deref().unwrap_or(component));
        literal = next;
    }
    if result.is_empty() {
        String::from("\\")
    } else {
        result
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
    for prefix in ["device\\kernelvolume1", "windows\\globalization\\sorting", "systemroot\\globalization\\sorting", "windows\\system32", "systemroot\\system32", "windows", "systemroot"] {
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
    /// A geração do drive em que o estado foi conferido pela última vez.
    generation: u64,
    /// Os registros de que a resolução do caminho depende: os diretórios
    /// da raiz ao pai e, por último, o próprio arquivo
    /// (`Ntfs::stat_with_references`).
    references: Vec<u64>,
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
    /// `pending_delete`/`deleted`, compartilhadas com `io::file::lifetime`.
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

    /// Confere o estado contra as mudanças confirmadas no volume desde a
    /// última conferência, por registro: sem mudança no arquivo nem nos
    /// diretórios do caminho, nada muda (os bytes e os blocos continuam
    /// valendo); com um diretório do caminho mudado, o caminho é resolvido de
    /// novo (referência e sequência do registro distinguem o mesmo arquivo
    /// de outro que reutilizou a posição); com o próprio registro mudado
    /// (conteúdo, tamanho ou atributos), o stat é relido e os bytes e os
    /// blocos caem.
    pub fn refresh(&self) {
        let current_generation = self.volume.generation();
        let (since, references) = {
            let state = self.state.lock();
            if state.generation == current_generation {
                return;
            }
            (state.generation, state.references.clone())
        };
        let changed = |reference: &u64| self.volume.changed_since(*reference, since);
        let (file, path) = references.split_last().map_or((true, true), |(file, path)| (changed(file), path.iter().any(changed)));
        if !file && !path {
            let mut state = self.state.lock();
            if state.generation == since {
                state.generation = current_generation;
            }
            return;
        }
        let current = self.volume.stat_with_references(&self.volume_path()).ok().flatten();
        let mut drop_blocks = file;
        {
            let mut state = self.state.lock();
            let deleted = current.as_ref().is_none_or(|(stat, _)| stat.reference != state.stat.reference || stat.sequence != state.stat.sequence);
            self.marks.deleted.store(deleted, Ordering::Release);
            if deleted {
                drop_blocks = true;
            } else if let Some((stat, references)) = current {
                state.size = stat.size;
                state.directory = stat.directory;
                state.stat = stat;
                state.references = references;
            }
            if drop_blocks {
                state.bytes = None;
            }
            state.generation = current_generation;
        }
        if drop_blocks {
            CACHE.lock().clear(self.id);
        }
    }

    /// Materializa o arquivo inteiro só no primeiro uso da geração. Os bytes
    /// só ficam guardados se a geração não mudou durante a leitura: um
    /// refresh de outra CPU no meio já descartou o estado em que ela começou.
    pub fn read_all(&self) -> Option<Arc<Vec<u8>>> {
        self.refresh();
        let (generation, size) = {
            let state = self.state.lock();
            if let Some(bytes) = state.bytes.clone() {
                return Some(bytes);
            }
            (state.generation, state.size)
        };
        let bytes = Arc::new(self.volume.read_range(&self.volume_path(), 0, size).ok().flatten()?);
        let mut state = self.state.lock();
        if state.generation == generation {
            state.bytes = Some(bytes.clone());
        }
        Some(bytes)
    }

    /// Guarda um bloco lido na geração `generation`. Se outra CPU guardou o
    /// mesmo bloco antes, vale o dela; se a geração mudou no meio, o bloco
    /// serve só a esta leitura. Conferir e inserir sob o lock do cache fecha
    /// a corrida com o `refresh`, que troca a geração antes de limpar os
    /// blocos.
    fn publish_block(&self, key: (u64, u64), generation: u64, block: Arc<CacheBlock>) -> Result<Arc<CacheBlock>, KernelError> {
        let mut cache = CACHE.lock();
        if let Some(existing) = cache.blocks.get(&key).cloned() {
            cache.touch(key)?;
            return Ok(existing);
        }
        if self.state.lock().generation != generation {
            return Ok(block);
        }
        cache.reserve(self.id, block.length)?;
        cache.blocks.insert(key, block.clone());
        cache.lru.push_back(key);
        cache.per_file.entry(self.id).or_default().push_back(key.1);
        cache.bytes += block.length;
        Ok(block)
    }

    /// Limitado ao EOF; pedidos acima de 64 KiB leem direto, os menores
    /// passam pelo cache.
    pub fn read_at(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        self.refresh();
        let (generation, size) = {
            let state = self.state.lock();
            (state.generation, state.size)
        };
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
            let cached = {
                let mut cache = CACHE.lock();
                let block = cache.blocks.get(&key).cloned();
                if block.is_some() {
                    cache.touch(key)?;
                }
                block
            };
            let block = match cached {
                Some(block) => block,
                None => {
                    let block_length = READ_CACHE_BLOCK_BYTES.min(size - block_offset);
                    let fetched = CacheBlock::read(&self.volume, &self.volume_path(), block_offset, block_length)?;
                    self.publish_block(key, generation, Arc::new(fetched))?
                }
            };
            let start = current - block_offset;
            let count = (length - result.len() as u64).min(block.length - start);
            block.copy_out(start, count, &mut result);
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
        // O volume montado no boot (a mesma identidade do namespace); sem
        // ele, um volume próprio do segundo disco.
        let entry = match (ntfs::mounted(), ntfs::fixed()) {
            (Some(mounted), Some(fixed)) => Some((mounted, fixed)),
            _ => ntfs::mount(1).ok().map(|mounted| {
                let fixed: &'static Ntfs = alloc::boxed::Box::leak(alloc::boxed::Box::new(mounted.clone()));
                (mounted, fixed)
            }),
        };
        if let Some(entry) = entry {
            *volume = Some(entry);
        }
    }
    volume.clone()
}

/// A referência estática do volume (a forma registrada no namespace).
pub fn fixed_volume() -> Option<&'static Ntfs> {
    volume_entry().map(|(_, fixed)| fixed)
}

/// Descarta a entrada do cache.
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
    // A geração vem antes do stat: uma mudança entre os dois deixa o
    // arquivo numa geração velha (e o próximo refresh relê), nunca um stat
    // velho numa geração nova.
    let generation = volume.generation();
    let (stat, references) = volume.stat_with_references(&volume_path).ok().flatten()?;
    let fs: &'static dyn super::volume::FileSystem = fixed;
    let file = Arc::new(VolumeFile {
        id: NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        paths: SpinLock::new(Paths { nt_path: native_file_name::from_volume(fs, &volume_path).unwrap_or_else(|| String::from(nt_path)), base_name: String::from(&volume_path[1..]), volume_path }),
        state: SpinLock::new(FileState { size: stat.size, directory: stat.directory, generation, stat, references, bytes: None }),
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
