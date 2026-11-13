//! Loader de executáveis PE32+ (x86-64).
//!
//! Faz o parse do PE, copia cabeçalhos e seções para frames do PFN, mapeia a
//! imagem na VA escolhida, aplica relocações, semeia o cookie GS e resolve a
//! IAT pelos resolvedores registrados (endereços nativos de outros módulos ou
//! exports do kernel). Os encaminhamentos de exports são resolvidos pelo
//! gerenciador de módulos.
//!
//! Imagem de kernel (driver, hal.dll, biblioteca de export): como no
//! MiLoadSystemImage do NT, a VA vem do espaço de sistema (a janela
//! `memory_map::SYSTEM_IMAGE_BASE..TOP`), nunca da ImageBase do cabeçalho, e
//! a imagem é relocada pela diferença. Imagem de usuário: a base preferida do
//! cabeçalho na metade de usuário, ou a próxima faixa livre.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::mm::sysload::kernel_image_source::{ImageSource, MemorySource};
use crate::ntos::rtl::image::pe_exports::{self, Exports};
use crate::ntos::rtl::image::pe_image_information;
use crate::ntos::rtl::image::pe_metadata_reader::MetadataReader;
use crate::hal::{cpu, physical};
use crate::ntos::ke::smp;
use crate::ntos::mm::{kernel_address, loaded_images, memory_map, paging, pfn};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ps::notify::image as image_notify;
use crate::rtl::{KernelError, SpinLock};

/// Bytes por trampolim da tabela de thunks (`hal::amd64::win32_thunk`).
const STUB_SIZE: u64 = 10;
/// IMAGE_FILE_RELOCS_STRIPPED: a imagem só roda na própria ImageBase.
const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;
/// STATUS_CONFLICTING_ADDRESSES: imagem sem relocações fora da ImageBase.
const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
/// STATUS_INSUFFICIENT_RESOURCES: sem VA de sistema ou sem frames.
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Faixas de VA das imagens.
struct Arenas {
    /// Primeira VA nunca usada da janela de imagens de sistema.
    next_system: u64,
    /// Faixas devolvidas da janela de sistema (base, tamanho), ordenadas e
    /// coalescidas, todas abaixo de `next_system`.
    free_system: Vec<(u64, u64)>,
    /// Próxima VA das imagens de usuário fora da base preferida.
    next_user_bump: u64,
    /// Faixas ocupadas pelas imagens de usuário. As de kernel ficam só na
    /// janela de sistema e nunca entram aqui.
    preferred_ranges: Vec<(u64, u64)>,
}

static ARENAS: SpinLock<Arenas> = SpinLock::new(Arenas {
    next_system: memory_map::SYSTEM_IMAGE_BASE,
    free_system: Vec::new(),
    next_user_bump: 0x1_8100_0000,
    preferred_ranges: Vec::new(),
});

/// Reserva a faixa de uma imagem de kernel na janela de sistema: a primeira
/// que couber a partir da base, em múltiplos de `SYSTEM_IMAGE_ALIGN` (o papel
/// da reserva de PTEs de sistema do MiLoadSystemImage).
fn reserve_system_image_range(size: u64) -> Result<(u64, u64), KernelError> {
    let length = size.div_ceil(memory_map::SYSTEM_IMAGE_ALIGN) * memory_map::SYSTEM_IMAGE_ALIGN;
    if length == 0 {
        return Err(KernelError::new("PE: SizeOfImage nulo"));
    }
    let mut arenas = ARENAS.lock();
    if let Some(index) = arenas.free_system.iter().position(|&(_, available)| available >= length) {
        let base = arenas.free_system[index].0;
        arenas.free_system[index].0 += length;
        arenas.free_system[index].1 -= length;
        if arenas.free_system[index].1 == 0 {
            arenas.free_system.remove(index);
        }
        return Ok((base, base + length));
    }
    let base = arenas.next_system;
    if memory_map::SYSTEM_IMAGE_TOP - base < length {
        return Err(KernelError::with_status("janela de imagens de sistema esgotada", STATUS_INSUFFICIENT_RESOURCES));
    }
    arenas.next_system = base + length;
    Ok((base, base + length))
}

/// Devolve a faixa à janela de sistema, coalesce com as vizinhas e recua o
/// topo usado quando a última faixa livre encosta nele.
fn release_system_image_range((base, top): (u64, u64)) {
    let mut arenas = ARENAS.lock();
    let arenas = &mut *arenas;
    let free = &mut arenas.free_system;
    free.push((base, top - base));
    free.sort_unstable();
    let mut index = 0;
    while index + 1 < free.len() {
        if free[index].0 + free[index].1 == free[index + 1].0 {
            free[index].1 += free[index + 1].1;
            free.remove(index + 1);
        } else {
            index += 1;
        }
    }
    if let Some(&(last, length)) = free.last() {
        if last + length == arenas.next_system {
            arenas.next_system = last;
            free.pop();
        }
    }
}

fn preferred_range_is_free(ranges: &[(u64, u64)], base: u64, size: u64) -> bool {
    ranges.iter().all(|&(used_base, used_top)| !(base < used_top && base + size > used_base))
}

/// Dependência retida por um import nativo (outro módulo carregado).
pub trait ImageDependency: Send + Sync {
    fn retain(&self);
    fn release(&self) -> Result<(), KernelError>;
}

/// Resultado de um resolvedor: endereço nativo (com as dependências que o
/// importador passa a reter) ou índice da tabela de trampolins.
pub enum ResolvedImport {
    Address { address: u64, dependencies: Vec<Arc<dyn ImageDependency>> },
    Thunk(u32),
}

/// Símbolo importado: nome ou ordinal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportSymbol {
    Name(String),
    Ordinal(u32),
}

pub type ImportLookup = Arc<dyn Fn(&str, &ImportSymbol) -> Option<ResolvedImport> + Send + Sync>;

struct Resolver {
    pattern: fn(&str) -> bool,
    lookup: ImportLookup,
}

/// Imagens nativas carregadas (base → tamanho e seções), para a residência
/// das imagens de drivers (`mm::image_paging`).
static NATIVE_IMAGES: SpinLock<alloc::collections::BTreeMap<u64, (u64, Vec<SectionInfo>)>> = SpinLock::new(alloc::collections::BTreeMap::new());

/// Tamanho e seções de um driver nativo carregado por este loader.
pub fn native_image(image_base: u64) -> Option<(u64, Vec<SectionInfo>)> {
    NATIVE_IMAGES.lock().get(&image_base).cloned()
}

static RESOLVERS: SpinLock<Vec<Resolver>> = SpinLock::new(Vec::new());
/// (base física, quantidade) da tabela de trampolins.
static THUNK_TABLE: SpinLock<Option<(u64, u32)>> = SpinLock::new(None);

pub fn register_resolver(pattern: fn(&str) -> bool, lookup: ImportLookup) {
    RESOLVERS.lock().push(Resolver { pattern, lookup });
}

pub fn set_thunk_table(table: Option<(u64, u32)>) {
    *THUNK_TABLE.lock() = table;
}

fn resolve(dll: &str, symbol: &ImportSymbol) -> Option<ResolvedImport> {
    let lookup = RESOLVERS.lock().iter().find(|resolver| (resolver.pattern)(dll)).map(|resolver| resolver.lookup.clone())?;
    lookup(dll, symbol)
}

/// Decisão da integridade de código sobre a imagem.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CodeIntegrity {
    pub status: u32,
    pub validation_mode: u32,
    pub signature_context: u64,
    pub signing_level: u32,
}

/// Validação da CI: decisão, fonte retida e liberação.
pub struct Validation {
    pub result: CodeIntegrity,
    pub source: Arc<dyn ImageSource>,
    pub release: Box<dyn FnOnce() + Send>,
}

pub type KernelImageValidator = fn(&Arc<dyn ImageSource>, &LoadOptions) -> Result<Validation, KernelError>;

static VALIDATOR: SpinLock<Option<KernelImageValidator>> = SpinLock::new(None);

/// Instalado pela CI depois da inicialização da política original.
pub fn register_kernel_image_validator(validator: KernelImageValidator) -> Result<(), KernelError> {
    let mut current = VALIDATOR.lock();
    if current.is_some() {
        return Err(KernelError::new("invalid kernel image validator registration"));
    }
    *current = Some(validator);
    Ok(())
}

/// Vista parcial de uma imagem de usuário.
#[derive(Clone, Copy, Debug)]
pub struct UserView {
    pub base: u64,
    pub offset: u64,
    pub size: u64,
}

/// Sem `user_space`, a imagem é de kernel e vai para a janela de sistema.
#[derive(Clone, Debug)]
pub struct LoadOptions {
    pub user_space: bool,
    pub skip_imports: bool,
    pub user_view: Option<UserView>,
    pub no_execute: bool,
    pub skip_relocations: bool,
    pub skip_security_cookie: bool,
    pub image_name: Option<String>,
    pub notify_image: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self { user_space: false, skip_imports: false, user_view: None, no_execute: false, skip_relocations: false, skip_security_cookie: false, image_name: None, notify_image: true }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub va: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedImportRecord {
    pub dll: String,
    pub name: String,
    pub rva: u64,
    pub address: u64,
    pub native_default: bool,
}

#[derive(Default)]
struct Owned {
    /// Faixa da janela de imagens de sistema (imagem de kernel).
    system_range: Option<(u64, u64)>,
    /// Faixa em `preferred_ranges` (imagem de usuário).
    range: Option<(u64, u64)>,
    mapped: Vec<u64>,
    dependencies: Vec<Arc<dyn ImageDependency>>,
    registered: Option<u64>,
    native_base: Option<u64>,
    /// Frames do PFN da imagem, um por página.
    frames: Vec<u64>,
    released: bool,
}

impl Owned {
    fn release(&mut self) -> Result<(), KernelError> {
        if self.released {
            return Ok(());
        }
        self.released = true;
        if let Some(id) = self.registered.take() {
            loaded_images::unregister(id)?;
        }
        if let Some(base) = self.native_base.take() {
            NATIVE_IMAGES.lock().remove(&base);
        }
        for &address in &self.mapped {
            paging::unmap_page(address, paging::MapOptions::default());
        }
        let mut failure = None;
        // Outra CPU pode guardar a tradução antiga: a VA de sistema e os
        // frames só voltam ao uso depois da invalidação em todas.
        if self.system_range.is_some() && !self.mapped.is_empty() {
            if let Err(error) = smp::flush_remote_tlb(false) {
                debug_print!("[pe] imagem de sistema retida: {}", error);
                self.system_range = None;
                self.frames.clear();
                failure = Some(error);
            }
        }
        self.mapped.clear();
        if let Some(range) = self.range.take() {
            let mut arenas = ARENAS.lock();
            if let Some(index) = arenas.preferred_ranges.iter().position(|&candidate| candidate == range) {
                arenas.preferred_ranges.remove(index);
            }
        }
        if let Some(range) = self.system_range.take() {
            release_system_image_range(range);
        }
        for &frame in &self.frames {
            pfn::free_page(frame);
        }
        self.frames.clear();
        for dependency in self.dependencies.drain(..).rev() {
            if let Err(error) = dependency.release() {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// Imagem carregada.
pub struct PeImage {
    pub entry_point: u64,
    pub image_base: u64,
    pub size_of_image: u64,
    pub exports: Exports,
    /// Frame da primeira página (as demais não são contíguas).
    pub physical_base: u64,
    pub preferred_base: u64,
    /// Frames de uma imagem de usuário (vazio na de kernel).
    pub pages: Vec<u64>,
    pub page_protects: Vec<u32>,
    pub sections: Vec<SectionInfo>,
    pub resolved_imports: Vec<ResolvedImportRecord>,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub image_information: [u8; pe_image_information::INFORMATION_SIZE],
    pub code_integrity: Option<CodeIntegrity>,
    pub loader_flags: u32,
    pub loaded_image: Option<loaded_images::LoadedImage>,
    owned: Owned,
}

impl PeImage {
    /// Desfaz mapeamentos, registro, faixa de VA, frames e dependências.
    pub fn release(&mut self) -> Result<(), KernelError> {
        self.owned.release()
    }
}

/// Fonte do arquivo entregue às notificações de imagem.
struct NotifySource {
    name: String,
    source: Arc<dyn ImageSource>,
}

impl FileSource for NotifySource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.source.size()
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        self.source.read_bytes(offset, length as u64)
    }
}

/// Imagem em memória (bundle/VFS).
pub fn load(bytes: Vec<u8>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    load_from_source(Arc::new(MemorySource { name: String::new(), bytes }), options)
}

/// Processo de usuário (ring 3): base preferida alta sobre frames PFN.
pub fn load_user(bytes: Vec<u8>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    let options = LoadOptions { user_space: true, ..options.clone() };
    load_from_source(Arc::new(MemorySource { name: String::new(), bytes }), &options)
}

/// O arquivo validado pela CI fica retido durante a cópia e os imports; a
/// recusa acontece antes de qualquer imagem executável ser publicada.
pub fn load_from_source(source: Arc<dyn ImageSource>, options: &LoadOptions) -> Result<PeImage, KernelError> {
    let validator = *VALIDATOR.lock();
    let Some(validator) = validator.filter(|_| !options.user_space) else { return load_prepared(source, options, None) };
    let validation = validator(&source, options)?;
    let code_integrity = validation.result;
    let result = if code_integrity.status & 0x8000_0000 != 0 {
        Err(KernelError::with_status("CI rejected kernel image", code_integrity.status))
    } else {
        load_prepared(validation.source.clone(), options, Some(code_integrity))
    };
    (validation.release)();
    result
}

/// A imagem durante a carga: um frame do PFN por página, não contíguos.
struct Mapping {
    frames: Vec<u64>,
}

impl Mapping {
    /// Offset da imagem -> endereço físico.
    fn to_phys(&self, offset: u64) -> u64 {
        self.frames[(offset / 0x1000) as usize] + offset % 0x1000
    }

    fn write(&self, offset: u64, bytes: &[u8]) {
        let mut done = 0usize;
        while done < bytes.len() {
            let at = offset + done as u64;
            let length = ((0x1000 - at % 0x1000) as usize).min(bytes.len() - done);
            physical::write_bytes(self.to_phys(at), &bytes[done..done + length]);
            done += length;
        }
    }

    fn read_bytes(&self, offset: u64, length: usize) -> Vec<u8> {
        (0..length as u64).map(|index| physical::read8(self.to_phys(offset + index))).collect()
    }

    /// Um campo que cruza a página passa byte a byte (frames não contíguos).
    fn read32(&self, offset: u64) -> u32 {
        if offset % 0x1000 > 0x1000 - 4 {
            let bytes = self.read_bytes(offset, 4);
            return u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        physical::read32(self.to_phys(offset))
    }

    fn write32(&self, offset: u64, value: u32) {
        if offset % 0x1000 > 0x1000 - 4 {
            self.write(offset, &value.to_le_bytes());
            return;
        }
        physical::write32(self.to_phys(offset), value);
    }

    fn read16(&self, offset: u64) -> u16 {
        let bytes = self.read_bytes(offset, 2);
        u16::from_le_bytes([bytes[0], bytes[1]])
    }

    fn write16(&self, offset: u64, value: u16) {
        self.write(offset, &value.to_le_bytes());
    }

    fn read64(&self, offset: u64) -> u64 {
        self.read32(offset) as u64 | (self.read32(offset + 4) as u64) << 32
    }

    fn write64(&self, offset: u64, value: u64) {
        self.write32(offset, value as u32);
        self.write32(offset + 4, (value >> 32) as u32);
    }
}

fn load_prepared(source: Arc<dyn ImageSource>, options: &LoadOptions, code_integrity: Option<CodeIntegrity>) -> Result<PeImage, KernelError> {
    let metadata = MetadataReader::new(source.as_ref());
    if metadata.read_u16(0)? != 0x5A4D {
        return Err(KernelError::new("MZ ausente (nao e PE)"));
    }
    let pe_header = metadata.read_u32(0x3C)? as u64;
    if metadata.read_u32(pe_header)? != 0x4550 {
        return Err(KernelError::new("assinatura PE ausente"));
    }
    let coff = pe_header + 4;
    if metadata.read_u16(coff)? != 0x8664 {
        return Err(KernelError::new("so suportamos PE x86-64"));
    }
    let section_count = metadata.read_u16(coff + 2)? as u64;
    let optional_size = metadata.read_u16(coff + 16)? as u64;
    let optional = coff + 20;
    if metadata.read_u16(optional)? != 0x20B {
        return Err(KernelError::new("nao e PE32+"));
    }
    let entry_rva = metadata.read_u32(optional + 16)? as u64;
    let preferred_base = metadata.read_u32(optional + 24)? as u64 | (metadata.read_u32(optional + 28)? as u64) << 32;
    let size_of_image = metadata.read_u32(optional + 56)? as u64;
    let size_of_headers = metadata.read_u32(optional + 60)? as u64;
    let export_rva = metadata.read_u32(optional + 112)? as u64;
    let export_size = metadata.read_u32(optional + 116)? as u64;
    let import_rva = metadata.read_u32(optional + 120)? as u64;
    let reloc_rva = metadata.read_u32(optional + 152)? as u64;
    let reloc_size = metadata.read_u32(optional + 156)? as u64;
    let section_table = optional + optional_size;
    let mut sections = Vec::new();
    for index in 0..section_count {
        let header = section_table + index * 40;
        let mut name = String::new();
        for character in 0..8 {
            let byte = metadata.read_u8(header + character)?;
            if byte == 0 {
                break;
            }
            name.push(byte as u8 as char);
        }
        sections.push(SectionInfo { name, virtual_size: metadata.read_u32(header + 8)?, va: metadata.read_u32(header + 12)?, raw_size: metadata.read_u32(header + 16)?, characteristics: metadata.read_u32(header + 36)? });
    }
    let user_space = options.user_space;
    let user_view = if user_space { options.user_view } else { None };
    let (view_offset, view_size) = user_view.map_or((0, size_of_image), |view| (view.offset, view.size));
    if let Some(view) = user_view {
        if view.base < 0x1_0000_0000 || view.base % 0x10000 != 0 || view.base + view_size > memory_map::USER_ADDRESS_LIMIT || view_offset % 4096 != 0 || view_size == 0 || view_size % 4096 != 0 || view_offset + view_size > size_of_image {
            return Err(KernelError::new("PE: invalid partial view"));
        }
    }
    if size_of_image == 0 || size_of_headers > size_of_image {
        return Err(KernelError::new("PE: SizeOfImage invalido"));
    }
    let characteristics = metadata.read_u16(coff + 18)? as u16;
    let mut owned = Owned::default();
    let mut image_base = preferred_base;
    let mut relocation_delta: i64 = 0;
    let result = (|| -> Result<PeImage, KernelError> {
        if user_space {
            if user_view.is_none() && (preferred_base < 0x1_0000_0000 || preferred_base + size_of_image > memory_map::USER_ADDRESS_LIMIT) {
                return Err(KernelError::new(alloc::format!("imagem de usuario com base invalida: {preferred_base:#x}")));
            }
            let mut arenas = ARENAS.lock();
            let mut target = user_view.map_or(preferred_base, |view| view.base - view_offset);
            if let Some(view) = user_view {
                if !preferred_range_is_free(&arenas.preferred_ranges, view.base, view_size) {
                    return Err(KernelError::new("PE: requested view conflicts"));
                }
            }
            while user_view.is_none() && !preferred_range_is_free(&arenas.preferred_ranges, target, size_of_image) {
                target = arenas.next_user_bump / 0x10000 * 0x10000;
                arenas.next_user_bump = target + size_of_image.div_ceil(0x10000) * 0x10000;
            }
            if target + view_offset + view_size > memory_map::USER_ADDRESS_LIMIT {
                return Err(KernelError::new("espaco de imagens de usuario esgotado"));
            }
            if target >= arenas.next_user_bump {
                arenas.next_user_bump = target + size_of_image.div_ceil(0x10000) * 0x10000;
            }
            let range = (target + view_offset, target + view_offset + view_size);
            arenas.preferred_ranges.push(range);
            drop(arenas);
            owned.range = Some(range);
            image_base = target;
            relocation_delta = image_base.wrapping_sub(preferred_base) as i64;
            if relocation_delta != 0 && reloc_rva == 0 {
                debug_print!("[pe] sem .reloc: imagem position-independent (data), mapeada em {:#x}", image_base);
            }
        } else {
            // MiLoadSystemImage: a VA vem da janela de sistema e a imagem é
            // relocada pela diferença; sem relocações, só na ImageBase.
            if reloc_rva == 0 && characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0 {
                return Err(KernelError::with_status("PE: imagem de kernel sem relocacoes", STATUS_CONFLICTING_ADDRESSES));
            }
            let range = reserve_system_image_range(size_of_image)?;
            owned.system_range = Some(range);
            image_base = range.0;
            relocation_delta = image_base.wrapping_sub(preferred_base) as i64;
        }
        for _ in 0..size_of_image.div_ceil(0x1000) {
            let frame = pfn::alloc_page();
            if frame == 0 {
                return Err(KernelError::with_status("PFN esgotado carregando imagem", STATUS_INSUFFICIENT_RESOURCES));
            }
            owned.frames.push(frame);
        }
        let physical_base = owned.frames[0];
        let mapping = Mapping { frames: owned.frames.clone() };
        let rva_to_file_offset = |rva: u64| -> Result<u64, KernelError> {
            for index in 0..section_count {
                let header = section_table + index * 40;
                let virtual_size = metadata.read_u32(header + 8)? as u64;
                let virtual_address = metadata.read_u32(header + 12)? as u64;
                let raw_size = metadata.read_u32(header + 16)? as u64;
                let raw_pointer = metadata.read_u32(header + 20)? as u64;
                if rva >= virtual_address && rva < virtual_address + virtual_size.max(raw_size) {
                    return Ok(raw_pointer + (rva - virtual_address));
                }
            }
            if rva < size_of_headers {
                return Ok(rva);
            }
            Err(KernelError::new(alloc::format!("RVA invalido: {rva:#x}")))
        };
        let read_c_string = |mut offset: u64| -> Result<String, KernelError> {
            let mut text = String::new();
            loop {
                let byte = metadata.read_u8(offset)?;
                if byte == 0 {
                    return Ok(text);
                }
                text.push(byte as u8 as char);
                offset += 1;
            }
        };
        debug_print!("[pe] base={:#x} (fisico {:#x}) imagem={} bytes, {} secoes", image_base, physical_base, size_of_image, section_count);
        // Zera a imagem (BSS) e copia cabeçalhos e seções.
        for &frame in &owned.frames {
            physical::zero(frame, 0x1000);
        }
        mapping.write(0, &source.read_bytes(0, size_of_headers)?);
        for index in 0..section_count {
            let header = section_table + index * 40;
            let virtual_address = metadata.read_u32(header + 12)? as u64;
            let raw_size = metadata.read_u32(header + 16)? as u64;
            let raw_pointer = metadata.read_u32(header + 20)? as u64;
            if raw_size == 0 {
                continue;
            }
            if virtual_address + raw_size > size_of_image || raw_pointer + raw_size > source.size() {
                return Err(KernelError::new("PE: secao fora da imagem ou do arquivo"));
            }
            if source.supports_copy_to_physical() && raw_size >= 0x1000 {
                // Agrupa frames fisicamente contíguos; nunca cruza um salto.
                let mut copied = 0u64;
                while copied < raw_size {
                    let rva = virtual_address + copied;
                    let target = mapping.to_phys(rva);
                    let mut take = (raw_size - copied).min(0x1000 - rva % 0x1000);
                    while copied + take < raw_size && mapping.to_phys(rva + take) == target + take {
                        take += 0x1000.min(raw_size - copied - take);
                    }
                    source.copy_to_physical(raw_pointer + copied, target, take).unwrap_or_else(|| Err(KernelError::new("PE: copia direta indisponivel")))?;
                    copied += take;
                }
                // Verificação real da via DMA por amostras.
                for sample in [0u64, 512, 0x10000, raw_size >> 1, raw_size.wrapping_sub(512)] {
                    if sample + 4 > raw_size {
                        continue;
                    }
                    let expected_bytes = source.read_bytes(raw_pointer + sample, 4)?;
                    let expected = u32::from_le_bytes([expected_bytes[0], expected_bytes[1], expected_bytes[2], expected_bytes[3]]);
                    let actual = (0..4u64).fold(0u32, |value, byte| value | (physical::read8(mapping.to_phys(virtual_address + sample + byte)) as u32) << (8 * byte));
                    if actual != expected {
                        return Err(KernelError::new(alloc::format!("DMA diverge em secao {index} +{sample:#x}: lido {actual:#x} esperado {expected:#x}")));
                    }
                }
                continue;
            }
            let mut copied = 0u64;
            while copied < raw_size {
                let chunk = (raw_size - copied).min(0x40_0000);
                mapping.write(virtual_address + copied, &source.read_bytes(raw_pointer + copied, chunk)?);
                copied += chunk;
            }
        }
        let mut page_protects = Vec::new();
        // Mapeia a VA escolhida sobre os frames (PTEs de 4 KB; supervisor na
        // imagem de kernel).
        {
            let mut page = view_offset;
            while page < view_offset + view_size {
                let backing = owned.frames[(page / 0x1000) as usize];
                let (mut present, mut writable, mut nx) = (true, !options.no_execute, options.no_execute);
                if user_view.is_some() && !options.no_execute {
                    let mut characteristics = if page < size_of_headers { 0x4000_0000u32 } else { 0 };
                    for section in &sections {
                        let start = section.va as u64;
                        let length = section.virtual_size.max(section.raw_size) as u64;
                        if page < start + length && page + 4096 > start {
                            characteristics |= section.characteristics;
                        }
                    }
                    present = characteristics & 0xE000_0000 != 0;
                    writable = characteristics & 0x8000_0000 != 0;
                    nx = characteristics & 0x2000_0000 == 0;
                }
                let flags = (if present { paging::PAGE_PRESENT } else { 0 }) | (if writable { paging::PAGE_RW } else { 0 }) | (if user_space { paging::PAGE_USER } else { 0 });
                let index = (page / 4096) as usize;
                if page_protects.len() <= index {
                    page_protects.resize(index + 1, 0);
                }
                page_protects[index] = if !present { 1 } else if nx { if writable { 4 } else { 2 } } else if writable { 0x40 } else { 0x20 };
                if !paging::map_page(image_base + page, backing, flags, paging::MapOptions { nx, ..Default::default() }) {
                    return Err(KernelError::new(alloc::format!("mapPage falhou p/ imagem em {image_base:#x}")));
                }
                owned.mapped.push(image_base + page);
                page += 0x1000;
            }
            debug_print!("[pe] VA {:#x} mapeada ({} paginas)", image_base, size_of_image.div_ceil(0x1000));
            // Verificação real: a página do entry point traduz de volta.
            let entry_page = entry_rva & !0xFFF;
            let expected = owned.frames.get((entry_page / 0x1000) as usize).copied().unwrap_or(0);
            let probe = paging::translate(image_base + entry_page);
            if entry_page >= view_offset && entry_page < view_offset + view_size && probe != expected {
                return Err(KernelError::new(alloc::format!("mapeamento VA quebrado: entry traduz p/ {probe:#x} (esperado {expected:#x})")));
            }
        }
        // Relocação (IMAGE_BASE_RELOCATION): DIR64, HIGHLOW e HIGH.
        let delta = relocation_delta as u64;
        if !options.skip_relocations && relocation_delta != 0 && reloc_rva != 0 {
            let mut count = 0u32;
            let mut block = rva_to_file_offset(reloc_rva)?;
            let end = block + reloc_size;
            while block < end {
                let page_rva = metadata.read_u32(block)? as u64;
                let block_size = metadata.read_u32(block + 4)? as u64;
                if block_size == 0 {
                    break;
                }
                for entry_index in 0..(block_size - 8) / 2 {
                    let entry = metadata.read_u16(block + 8 + entry_index * 2)?;
                    let entry_type = entry >> 12;
                    let target = page_rva + (entry & 0xFFF) as u64;
                    let width = match entry_type {
                        10 => 8,
                        2 => 4,
                        1 => 2,
                        _ => 0,
                    };
                    if target + width > size_of_image {
                        return Err(KernelError::new(alloc::format!("PE: relocacao fora da imagem em {target:#x}")));
                    }
                    match entry_type {
                        10 => {
                            mapping.write64(target, mapping.read64(target).wrapping_add(delta));
                            count += 1;
                        }
                        2 => {
                            mapping.write32(target, mapping.read32(target).wrapping_add(delta as u32));
                            count += 1;
                        }
                        1 => {
                            let value = mapping.read16(target) as i64;
                            let full = (value << 16) + relocation_delta;
                            mapping.write16(target, (full.div_euclid(0x10000) & 0xFFFF) as u16);
                            count += 1;
                        }
                        0 => {}
                        other => return Err(KernelError::new(alloc::format!("reloc tipo {other} nao suportado"))),
                    }
                }
                block += block_size;
            }
            debug_print!("[pe] relocada p/ {:#x} ({} fixups)", image_base, count);
        }
        // Cookie GS: semente de 48 bits, nunca 0 nem o padrão do link.
        if !options.skip_security_cookie {
            let tsc = cpu::rdtsc();
            let mut seed_low = (tsc as u32) ^ (image_base as u32);
            let seed_high = ((tsc >> 32) as u32 ^ 0x9E37) & 0xFFFF;
            if seed_low | seed_high == 0 {
                seed_low = 0x2545_F491;
            }
            if seed_high == 0x2B99 && seed_low == 0x2DDF_A232 {
                seed_low ^= 0x10F3;
            }
            let mut cookie = 0u64;
            let load_config_rva = metadata.read_u32(optional + 192)? as u64;
            let load_config_size = metadata.read_u32(optional + 196)? as u64;
            if load_config_rva != 0 && load_config_size >= 0x60 && load_config_rva + 0x60 <= size_of_image {
                cookie = mapping.read64(load_config_rva + 0x58);
                if cookie < image_base || cookie + 8 > image_base + size_of_image {
                    cookie = 0;
                }
            }
            if cookie == 0 {
                let mut offset = 0u64;
                while offset + 8 <= size_of_image.min(0x80_0000) {
                    if mapping.read32(offset) == 0x2DDF_A232 && mapping.read32(offset + 4) == 0x2B99 {
                        cookie = image_base + offset;
                        break;
                    }
                    offset += 4;
                }
            }
            if cookie != 0 {
                mapping.write32(cookie - image_base, seed_low);
                mapping.write32(cookie - image_base + 4, seed_high);
                debug_print!("[pe] security cookie semeado em {:#x}", cookie);
            }
        }
        let mut resolved_imports = Vec::new();
        if import_rva != 0 && !options.skip_imports {
            let importer = options.image_name.clone().unwrap_or_else(|| source.name().to_string());
            let mut descriptor = rva_to_file_offset(import_rva)?;
            loop {
                let ilt_rva = metadata.read_u32(descriptor)? as u64;
                let name_rva = metadata.read_u32(descriptor + 12)? as u64;
                let iat_rva = metadata.read_u32(descriptor + 16)? as u64;
                if ilt_rva == 0 && name_rva == 0 && iat_rva == 0 {
                    break;
                }
                let dll = read_c_string(rva_to_file_offset(name_rva)?)?;
                let lower = dll.to_lowercase();
                let host = if lower.starts_with("api-") || lower.starts_with("ext-") { crate::ntos::mm::sysload::kernel_api_set::resolve(&dll, &importer)? } else { Some(dll.clone()) };
                let Some(host) = host else { return Err(KernelError::new(alloc::format!("API set desconhecido: {dll}"))) };
                debug_print!("[pe] imports de {}", dll);
                let mut slot = 0u64;
                loop {
                    let entry = rva_to_file_offset(if ilt_rva != 0 { ilt_rva } else { iat_rva })? + slot * 8;
                    let low = metadata.read_u32(entry)?;
                    let high = metadata.read_u32(entry + 4)?;
                    if low == 0 && high == 0 {
                        break;
                    }
                    if iat_rva == 0 || iat_rva + slot * 8 > size_of_image - 8 {
                        return Err(KernelError::new("PE: IAT fora da imagem"));
                    }
                    let iat = iat_rva + slot * 8;
                    let symbol = if high & 0x8000_0000 != 0 {
                        ImportSymbol::Ordinal(low & 0xFFFF)
                    } else {
                        if high != 0 {
                            return Err(KernelError::new("PE: RVA de import invalido"));
                        }
                        ImportSymbol::Name(read_c_string(rva_to_file_offset(low as u64)? + 2)?)
                    };
                    let label = match &symbol {
                        ImportSymbol::Ordinal(ordinal) => alloc::format!("ordinal #{ordinal}"),
                        ImportSymbol::Name(name) => name.clone(),
                    };
                    if host.is_empty() {
                        // Default opcional do linker no IAT (já relocado): o
                        // ponteiro original precisa cair numa seção executável.
                        let address = mapping.read64(iat);
                        let rva = address.wrapping_sub(image_base);
                        let executable = rva < size_of_image && sections.iter().any(|section| section.characteristics & 0x2000_0000 != 0 && rva >= section.va as u64 && rva < section.va as u64 + section.virtual_size.max(section.raw_size) as u64);
                        if !executable {
                            return Err(KernelError::new(alloc::format!("API set sem default nativo executavel: {dll}!{label}")));
                        }
                        resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: true });
                        slot += 1;
                        continue;
                    }
                    match resolve(&host, &symbol) {
                        None => return Err(KernelError::new(alloc::format!("API nao suportada: {dll}!{label}"))),
                        Some(ResolvedImport::Address { address, dependencies }) => {
                            for dependency in dependencies {
                                if !owned.dependencies.iter().any(|held| Arc::ptr_eq(held, &dependency)) {
                                    dependency.retain();
                                    owned.dependencies.push(dependency);
                                }
                            }
                            mapping.write64(iat, address);
                            resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: false });
                        }
                        Some(ResolvedImport::Thunk(id)) => {
                            // Ring 3 não alcança trampolins supervisores.
                            if user_space {
                                return Err(KernelError::new(alloc::format!("API do kernel ({dll}!{label}) inalcancavel de ring 3")));
                            }
                            let Some((table, count)) = *THUNK_TABLE.lock() else { return Err(KernelError::new("tabela de trampolins indisponivel")) };
                            if id >= count {
                                return Err(KernelError::new(alloc::format!("apiId {id} alem da tabela de trampolins ({count})")));
                            }
                            let physical_thunk = table + id as u64 * STUB_SIZE;
                            let address = if id >= 32 { kernel_address::virtual_address(physical_thunk)? } else { physical_thunk };
                            mapping.write64(iat, address);
                            resolved_imports.push(ResolvedImportRecord { dll: dll.clone(), name: label, rva: iat, address, native_default: false });
                        }
                    }
                    slot += 1;
                }
                descriptor += 20;
            }
        }
        let entry_point = if entry_rva != 0 { image_base.wrapping_add(entry_rva) } else { 0 };
        let read_rva = |rva: u64, length: u64| -> Result<Vec<u8>, KernelError> {
            if rva.checked_add(length).is_none_or(|end| end > size_of_image) {
                return Err(KernelError::new(alloc::format!("PE: RVA {rva:#x} fora da imagem")));
            }
            Ok(mapping.read_bytes(rva, length as usize))
        };
        let exports = pe_exports::read_exports(&read_rva, image_base, size_of_image, export_rva, export_size)?;
        debug_print!("[pe] entry point = {:#x}", entry_point);
        // O bit consumido por ObRegisterCallbacks é uma decisão da CI, não
        // uma promessa do cabeçalho: contrato integral aceito no modo 2.
        let loader_flags = match code_integrity {
            Some(ci) if ci.status == 0 && ci.validation_mode == 2 && ci.signature_context == 0 && (2..=15).contains(&ci.signing_level) => 0x20,
            _ => 0,
        };
        let image_information = pe_image_information::capture(&metadata, source.size(), coff, optional, image_base)?;
        Ok(PeImage {
            entry_point,
            image_base,
            size_of_image,
            exports,
            physical_base,
            preferred_base,
            pages: if user_space { owned.frames.clone() } else { Vec::new() },
            page_protects,
            sections: sections.clone(),
            resolved_imports,
            checksum: metadata.read_u32(optional + 64)?,
            time_date_stamp: metadata.read_u32(coff + 4)?,
            image_information,
            code_integrity,
            loader_flags,
            loaded_image: None,
            owned: Owned::default(),
        })
    })();
    match result {
        Ok(mut image) => {
            image.owned = owned;
            let name = options.image_name.clone().unwrap_or_else(|| source.name().to_string());
            if !user_space {
                let registered = loaded_images::register(loaded_images::ImageDescription { image_base: image.image_base, size_of_image, entry_point: image.entry_point, checksum: image.checksum, time_date_stamp: image.time_date_stamp, loader_flags: image.loader_flags, release_paging: Some(crate::ntos::mm::image_paging::release_image) }, &name);
                match registered {
                    Ok(loaded) => {
                        NATIVE_IMAGES.lock().insert(image.image_base, (size_of_image, image.sections.clone()));
                        image.owned.native_base = Some(image.image_base);
                        image.owned.registered = Some(loaded.id);
                        image.loaded_image = Some(loaded);
                    }
                    Err(error) => {
                        let _ = image.release();
                        return Err(error);
                    }
                }
            }
            if options.notify_image {
                let notify = image_notify::NotifyOptions { system: !user_space, name: Some(name.clone()), no_execute: options.no_execute, source: Some(Arc::new(NotifySource { name, source: source.clone() })), ..Default::default() };
                if let Err(error) = image_notify::notify(image_notify::Image { image_base: image.image_base, size_of_image }, &notify) {
                    let _ = image.release();
                    return Err(error);
                }
            }
            Ok(image)
        }
        Err(error) => {
            let _ = owned.release();
            Err(error)
        }
    }
}
