//! Posse das imagens de kernel mapeadas e a vista nativa da lista de imagens
//! (KLDR_DATA_TABLE_ENTRY x64, 0xA0
//! bytes, PDB 19041).
//!
//! Independe do tempo de vida do DRIVER_OBJECT. Imagens de usuário pertencem
//! ao loader do processo e nunca são registradas aqui.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::{kernel_address, memory_map as map};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ImageDosHeader, ImageNtHeaders64, KldrDataTableEntry, ListEntry};

const ENTRY_BYTE_LENGTH: u64 = KldrDataTableEntry::SIZE;

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: cabeça e entradas da lista nativa mantidas por este módulo.
    unsafe { ListEntry::at(address) }
}

/// Registro imutável de uma imagem.
#[derive(Clone, Debug)]
pub struct LoadedImage {
    pub id: u64,
    pub image_base: u64,
    pub size_of_image: u64,
    pub name: String,
    pub entry_point: u64,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub loader_flags: u32,
}

/// Descrição de uma imagem a registrar.
#[derive(Clone, Debug, Default)]
pub struct ImageDescription {
    pub image_base: u64,
    pub size_of_image: u64,
    pub entry_point: u64,
    pub checksum: u32,
    pub time_date_stamp: u32,
    pub loader_flags: u32,
    /// Liberação da paginação da imagem no descarregamento final.
    pub release_paging: Option<fn(u64)>,
}

struct NativeEntry {
    pointer: u64,
}

struct Registry {
    next_id: u64,
    /// Ordem de registro = ordem de enumeração.
    images: Vec<LoadedImage>,
    /// Imagens donas de mapeamento (inclusive as ocultas).
    owned: BTreeMap<u64, (LoadedImage, Option<fn(u64)>)>,
    kernel: Option<u64>,
    unload_observers: Vec<fn(&LoadedImage)>,
    list_head: u64,
    native_entries: BTreeMap<u64, NativeEntry>,
}

static REGISTRY: SpinLock<Registry> = SpinLock::new(Registry {
    next_id: 1,
    images: Vec::new(),
    owned: BTreeMap::new(),
    kernel: None,
    unload_observers: Vec::new(),
    list_head: 0,
    native_entries: BTreeMap::new(),
});

// ---- vista nativa (lista de imagens carregadas) -------------------------

/// Uma alocação contém corpo e nome completo; BaseDllName aponta para o
/// sufixo da mesma string.
fn create_native_entry(image: &LoadedImage) -> Result<NativeEntry, KernelError> {
    let full_name: Vec<u16> = image.name.replace('/', "\\").encode_utf16().collect();
    if full_name.len() > 32766 {
        return Err(KernelError::new("kernel image name exceeds UNICODE_STRING"));
    }
    let name_bytes = full_name.len() as u64 * 2;
    let pointer = guest::alloc_bytes(ENTRY_BYTE_LENGTH + name_bytes + 2);
    if pointer == 0 {
        return Err(KernelError::new("kernel loader list allocation failed"));
    }
    let name_pointer = pointer + ENTRY_BYTE_LENGTH;
    let base_offset = full_name.iter().rposition(|&unit| unit == b'\\' as u16).map_or(0, |index| index + 1) as u64 * 2;
    // SAFETY: entrada recém-alocada (zerada).
    let entry = unsafe { KldrDataTableEntry::at(pointer) };
    entry.dll_base.set(image.image_base);
    entry.entry_point.set(image.entry_point);
    entry.size_of_image.set(image.size_of_image as u32);
    entry.full_dll_name.length.set(name_bytes as u16);
    entry.full_dll_name.maximum_length.set(name_bytes as u16 + 2);
    entry.full_dll_name.buffer.set(name_pointer);
    entry.base_dll_name.length.set((name_bytes - base_offset) as u16);
    entry.base_dll_name.maximum_length.set((name_bytes - base_offset + 2) as u16);
    entry.base_dll_name.buffer.set(name_pointer + base_offset);
    entry.flags.set(image.loader_flags);
    entry.load_count.set(1); // uma referência de propriedade no loader
    entry.check_sum.set(image.checksum);
    entry.size_of_image_not_rounded.set(image.size_of_image as u32);
    entry.time_date_stamp.set(image.time_date_stamp);
    let characters: Vec<u8> = full_name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(name_pointer, &characters);
    Ok(NativeEntry { pointer })
}

impl Registry {
    fn enumerated(&self) -> Vec<LoadedImage> {
        self.images.clone()
    }

    /// A preparação termina antes de mudar a lista; uma falta de memória
    /// libera só as entradas novas.
    fn synchronize(&mut self) -> Result<(), KernelError> {
        if self.list_head == 0 {
            return Ok(());
        }
        let images = self.enumerated();
        let mut prepared = Vec::new();
        for image in &images {
            if !self.native_entries.contains_key(&image.id) {
                match create_native_entry(image) {
                    Ok(entry) => prepared.push((image.id, entry)),
                    Err(error) => {
                        for (_, entry) in prepared {
                            guest::free_bytes(entry.pointer);
                        }
                        return Err(error);
                    }
                }
            }
        }
        for (id, entry) in prepared {
            self.native_entries.insert(id, entry);
        }
        let ordered: Vec<u64> = images.iter().map(|image| self.native_entries[&image.id].pointer).collect();
        let head = self.list_head;
        list_entry(head).flink.set(ordered.first().copied().unwrap_or(head));
        list_entry(head).blink.set(ordered.last().copied().unwrap_or(head));
        for (index, &pointer) in ordered.iter().enumerate() {
            // SAFETY: entrada nativa viva (InLoadOrderLinks no início).
            let links = &unsafe { KldrDataTableEntry::at(pointer) }.in_load_order_links;
            links.flink.set(ordered.get(index + 1).copied().unwrap_or(head));
            links.blink.set(if index > 0 { ordered[index - 1] } else { head });
        }
        let retained: Vec<u64> = images.iter().map(|image| image.id).collect();
        let stale: Vec<u64> = self.native_entries.keys().copied().filter(|id| !retained.contains(id)).collect();
        for id in stale {
            if let Some(entry) = self.native_entries.remove(&id) {
                guest::free_bytes(entry.pointer);
            }
        }
        Ok(())
    }
}

pub fn register(description: ImageDescription, name: &str) -> Result<LoadedImage, KernelError> {
    let (base, size) = (description.image_base, description.size_of_image);
    if base == 0 || size == 0 || base.checked_add(size).is_none() {
        return Err(KernelError::new("invalid kernel image range"));
    }
    let mut registry = REGISTRY.lock();
    let overlaps = registry
        .owned
        .values()
        .any(|(other, _)| base < other.image_base + other.size_of_image && base + size > other.image_base);
    if overlaps {
        return Err(KernelError::new(alloc::format!("overlapping kernel images: {}", if name.is_empty() { "unnamed" } else { name })));
    }
    let image = LoadedImage {
        id: registry.next_id,
        image_base: base,
        size_of_image: size,
        name: String::from(name),
        entry_point: description.entry_point,
        checksum: description.checksum,
        time_date_stamp: description.time_date_stamp,
        loader_flags: description.loader_flags,
    };
    registry.next_id += 1;
    registry.images.push(image.clone());
    registry.owned.insert(image.id, (image.clone(), description.release_paging));
    if let Err(error) = registry.synchronize() {
        registry.images.retain(|other| other.id != image.id);
        registry.owned.remove(&image.id);
        return Err(error);
    }
    Ok(image)
}

pub fn unregister(id: u64) -> Result<bool, KernelError> {
    let observers;
    let image;
    {
        let mut registry = REGISTRY.lock();
        if Some(id) == registry.kernel {
            return Err(KernelError::new("cannot unload the running kernel"));
        }
        let Some((removed, release_paging)) = registry.owned.remove(&id) else { return Ok(false) };
        if let Some(release) = release_paging {
            release(removed.image_base);
        }
        registry.images.retain(|other| other.id != id);
        registry.synchronize()?;
        observers = registry.unload_observers.clone();
        image = removed;
    }
    // Só o descarregamento final de uma imagem possuída notifica.
    for observer in observers {
        observer(&image);
    }
    Ok(true)
}

/// Some da enumeração sem liberar o mapeamento (vistas de diagnóstico).
pub fn hide(id: u64) -> Result<bool, KernelError> {
    let mut registry = REGISTRY.lock();
    if Some(id) == registry.kernel {
        return Err(KernelError::new("cannot hide the running kernel"));
    }
    let before = registry.images.len();
    registry.images.retain(|other| other.id != id);
    let removed = registry.images.len() != before;
    registry.synchronize()?;
    Ok(removed)
}

pub fn observe_unload(observer: fn(&LoadedImage)) {
    REGISTRY.lock().unload_observers.push(observer);
}

pub fn find(address: u64) -> Option<LoadedImage> {
    if address == 0 {
        return None;
    }
    REGISTRY
        .lock()
        .images
        .iter()
        .find(|image| address >= image.image_base && address < image.image_base + image.size_of_image)
        .cloned()
}

/// As imagens na ordem de registro, que é a de enumeração.
pub fn list() -> Vec<LoadedImage> {
    REGISTRY.lock().enumerated()
}

pub fn kernel() -> Option<LoadedImage> {
    let registry = REGISTRY.lock();
    let id = registry.kernel?;
    registry.owned.get(&id).map(|(image, _)| image.clone())
}

/// A vista nativa só é materializada quando um consumidor pede o endereço.
pub fn native_list() -> Result<(u64, Vec<(LoadedImage, u64)>), KernelError> {
    let mut registry = REGISTRY.lock();
    if registry.list_head == 0 {
        let head = guest::alloc_bytes(16);
        if head == 0 {
            return Err(KernelError::new("kernel loader list head allocation failed"));
        }
        list_entry(head).flink.set(head);
        list_entry(head).blink.set(head);
        registry.list_head = head;
    }
    registry.synchronize()?;
    let entries =
        registry.enumerated().into_iter().map(|image| (image.clone(), registry.native_entries[&image.id].pointer)).collect();
    Ok((registry.list_head, entries))
}

/// Registro do `ntoskrnl.exe` na sua ImageBase: o stage2 já mapeou a imagem
/// ali e o kernel executa nessa VA, então a base e o tamanho publicados são
/// os do PE em execução.
pub fn init_kernel() -> Result<LoadedImage, KernelError> {
    if let Some(kernel) = kernel() {
        return Ok(kernel);
    }
    let base = map::KERNEL_VIRTUAL_BASE;
    // SAFETY: os cabeçalhos da imagem em execução, alinhados à página.
    let dos = unsafe { ImageDosHeader::at(base) };
    let pe = dos.e_lfanew.get() as u32 as u64;
    // Campo dos cabeçalhos NT: o e_lfanew não garante o alinhamento natural
    // da estrutura inteira, então cada leitura é um MOV no endereço do campo.
    macro_rules! nt {
        ($($field:tt)+) => {
            guest::read(base + pe + core::mem::offset_of!(ImageNtHeaders64, $($field)+) as u64)
        };
    }
    let signature: u32 = nt!(signature);
    let machine: u16 = nt!(file_header.machine);
    let magic: u16 = nt!(optional_header.magic);
    if dos.e_magic.get() != 0x5A4D || !(0x40..=0xF00).contains(&pe) || signature != 0x4550 || machine != 0x8664 || magic != 0x20B {
        return Err(KernelError::new("running kernel has no valid PE header"));
    }
    let size_of_image: u32 = nt!(optional_header.size_of_image);
    let entry_point: u32 = nt!(optional_header.address_of_entry_point);
    let (size, entry_rva) = (size_of_image as u64, entry_point as u64);
    let image_base: u64 = nt!(optional_header.image_base);
    let running = init_kernel as fn() -> Result<LoadedImage, KernelError> as usize as u64;
    if image_base != base
        || size < 0x2000
        || size > map::KERNEL_IMAGE_MAX
        || size % 4096 != 0
        || entry_rva < 4096
        || entry_rva >= size
        || running < base
        || running >= base + size
    {
        return Err(KernelError::new("running kernel PE range disagrees with boot layout"));
    }
    let kernel = register(
        ImageDescription {
            image_base: base,
            size_of_image: size,
            entry_point: base + entry_rva,
            checksum: nt!(optional_header.check_sum),
            time_date_stamp: nt!(file_header.time_date_stamp),
            ..Default::default()
        },
        "\\SystemRoot\\System32\\ntoskrnl.exe",
    )?;
    REGISTRY.lock().kernel = Some(kernel.id);
    kernel_address::publish(size);
    debug_print!("[mm] kernel PE registrado: base={:#x} size={:#x}", kernel.image_base, size);
    Ok(kernel)
}
