//! Árvore de recursos PE numa vista existente.
//!
//! Não carrega DLLs, não aloca payloads e não fabrica recursos: o resultado
//! aponta para os bytes da vista. Todo acesso passa pelo `resource::memory`.

use core::mem::offset_of;

use crate::ntos::inc::types::{
    ImageDosHeader, ImageNtHeaders64, ImageOptionalHeader64, ImageResourceDataEntry, ImageResourceDirStringU, ImageResourceDirectory, ImageResourceDirectoryEntry,
    ImageSectionHeader, ImageSectionHeaderMisc, NtStruct,
};
use alloc::vec::Vec;

use crate::ntos::rtl::resource::memory as resource_memory;
use crate::rtl::KernelError;

pub const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
pub const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
pub const STATUS_RESOURCE_TYPE_NOT_FOUND: u32 = 0xC000_008A;
pub const STATUS_RESOURCE_NAME_NOT_FOUND: u32 = 0xC000_008B;
pub const STATUS_RESOURCE_LANG_NOT_FOUND: u32 = 0xC000_0204;
const MAXIMUM_POINTER: u128 = u64::MAX as u128;
/// MmHighestUserAddress.
const USER_ADDRESS_LIMIT: u64 = crate::ntos::mm::memory_map::HIGHEST_USER_ADDRESS;

/// Imagem inspecionada: deslocamentos do arquivo, endereços de 64 bits.
#[derive(Clone, Debug, Default)]
pub struct Image {
    pub base: u64,
    pub size: u128,
    pub raw_file: bool,
    pub validate: bool,
    pub optional_header: i64,
    pub directories_offset: i64,
    pub image_size: u32,
    pub section_count: u32,
    pub section_table: i64,
    pub headers_size: u32,
    pub resource_address: u32,
    pub root_offset: i64,
}

/// Chave de pesquisa: identificador inteiro, nome UTF-16 ou ponteiro para
/// uma string terminada (lida só quando há entrada nomeada).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Id(u32),
    Name(Vec<u16>),
    Pointer(u64),
}

/// Plano de idiomas do resolvedor.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    pub candidates: Vec<u32>,
    pub allow_any: bool,
    pub select_first: bool,
}

/// Resultado de uma pesquisa (`status != 0` = falha com o NTSTATUS).
#[derive(Clone, Debug, Default)]
pub struct Found {
    pub status: u32,
    pub address: u64,
    pub size: u32,
    pub language: u32,
    pub directory: bool,
    pub satellite: bool,
    pub published: bool,
    pub next_language: Option<u32>,
}

impl Found {
    pub fn fail(status: u32) -> Self {
        Found { status, ..Found::default() }
    }
}

/// Opções da pesquisa: quantas chaves e se o diretório é o alvo.
#[derive(Clone, Copy, Debug)]
pub struct LookupOptions {
    pub count: u32,
    pub directory: bool,
}

impl Default for LookupOptions {
    fn default() -> Self {
        LookupOptions { count: 3, directory: false }
    }
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_offset: u32,
}

fn address_at(image: &Image, offset: i64) -> u64 {
    image.base.wrapping_add(offset as u64)
}

/// Deslocamento de um campo como `i64` (as contas da árvore são com sinal).
macro_rules! field {
    ($type:ty, $($field:tt)+) => {
        offset_of!($type, $($field)+) as i64
    };
}

/// IMAGE_NT_OPTIONAL_HDR64_MAGIC / IMAGE_NT_OPTIONAL_HDR32_MAGIC.
const PE32_PLUS_MAGIC: u32 = 0x20B;
const PE32_MAGIC: u32 = 0x10B;
/// IMAGE_OPTIONAL_HEADER32.DataDirectory (16 bytes antes do PE32+).
const OPTIONAL32_DATA_DIRECTORY: i64 = 96;
/// IMAGE_DIRECTORY_ENTRY_RESOURCE e o tamanho de um IMAGE_DATA_DIRECTORY.
const RESOURCE_DIRECTORY: i64 = 2;
const DATA_DIRECTORY_SIZE: i64 = 8;

fn read_word(image: &Image, offset: i64) -> Result<u32, KernelError> {
    Ok(resource_memory::read16(address_at(image, offset))? as u32)
}

fn read_dword(image: &Image, offset: i64) -> Result<u32, KernelError> {
    resource_memory::read32(address_at(image, offset))
}

fn contains(image: &Image, offset: i64, length: i64) -> bool {
    let start = offset as i128;
    let end = start + length as i128;
    start >= 0 && end >= start && end as u128 <= image.size && image.base as u128 + end as u128 <= MAXIMUM_POINTER
}

/// A seção é escolhida pelo SizeOfRawData, mesmo com VirtualSize diferente;
/// o limite é exclusivo, salvo o RVA inicial da seção.
fn section_for_address(image: &Image, relative_address: u32) -> Result<Option<Section>, KernelError> {
    let section_size = ImageSectionHeader::SIZE as i64;
    for index in 0..image.section_count as i64 {
        let offset = image.section_table + index * section_size;
        if image.validate && !contains(image, offset, section_size) {
            return Ok(None);
        }
        let virtual_address = read_dword(image, offset + field!(ImageSectionHeader, virtual_address))?;
        let raw_size = read_dword(image, offset + field!(ImageSectionHeader, size_of_raw_data))?;
        let raw_end = virtual_address.wrapping_add(raw_size);
        if relative_address == virtual_address || (relative_address > virtual_address && relative_address < raw_end) {
            // Misc.VirtualSize (a união fica no início de `misc`).
            let virtual_size = read_dword(image, offset + field!(ImageSectionHeader, misc) + field!(ImageSectionHeaderMisc, physical_address))?;
            return Ok(Some(Section { virtual_address, virtual_size, raw_size, raw_offset: read_dword(image, offset + field!(ImageSectionHeader, pointer_to_raw_data))? }));
        }
    }
    Ok(None)
}

/// Cabeçalho validado como RtlImageNtHeaderEx; SizeOfImage e a posse da
/// alocação são decididos pelo chamador.
pub fn inspect_header(image_base: u64, mapping_size: u128, raw_file: bool, validate: bool) -> Result<Result<Image, u32>, KernelError> {
    let mut image = Image { base: image_base & !3, size: mapping_size, raw_file, validate, ..Image::default() };
    let invalid = Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
    let dos_size = ImageDosHeader::SIZE as u128;
    if image.base == 0 || image.base as u128 > MAXIMUM_POINTER - (dos_size - 1) || (validate && image.size < dos_size) || read_word(&image, field!(ImageDosHeader, e_magic))? != 0x5A4D {
        return invalid;
    }
    let header_offset = read_dword(&image, field!(ImageDosHeader, e_lfanew))?;
    let header_address = image.base as u128 + header_offset as u128;
    let optional_start = field!(ImageNtHeaders64, optional_header);
    if (validate && (header_offset >= 0xFFFF_FFE7 || header_offset as u128 + optional_start as u128 >= image.size))
        || header_address > MAXIMUM_POINTER
        || (image.base < USER_ADDRESS_LIMIT && header_address + ImageNtHeaders64::SIZE as u128 >= USER_ADDRESS_LIMIT as u128)
        || read_dword(&image, header_offset as i64 + field!(ImageNtHeaders64, signature))? != 0x4550
    {
        return invalid;
    }
    let optional_header = header_offset as i64 + optional_start;
    let directories_offset = match read_word(&image, optional_header + field!(ImageOptionalHeader64, magic))? {
        PE32_PLUS_MAGIC => field!(ImageOptionalHeader64, data_directory),
        PE32_MAGIC => OPTIONAL32_DATA_DIRECTORY,
        _ => return invalid,
    };
    image.optional_header = optional_header;
    image.directories_offset = directories_offset;
    // SizeOfImage e SizeOfHeaders têm o mesmo deslocamento no PE32.
    image.image_size = read_dword(&image, optional_header + field!(ImageOptionalHeader64, size_of_image))?;
    image.section_count = read_word(&image, header_offset as i64 + field!(ImageNtHeaders64, file_header.number_of_sections))?;
    image.section_table = optional_header + read_word(&image, header_offset as i64 + field!(ImageNtHeaders64, file_header.size_of_optional_header))? as i64;
    image.headers_size = read_dword(&image, optional_header + field!(ImageOptionalHeader64, size_of_headers))?;
    Ok(Ok(image))
}

pub fn inspect(image_base: u64, mapping_size: u128, raw_file: bool, validate: bool) -> Result<Result<Image, u32>, KernelError> {
    let mut image = match inspect_header(image_base, mapping_size, raw_file, validate)? {
        Ok(image) => image,
        Err(status) => return Ok(Err(status)),
    };
    let (optional_header, directories_offset) = (image.optional_header, image.directories_offset);
    let invalid = Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
    // NumberOfRvaAndSizes precede o vetor de diretórios nos dois formatos.
    if read_dword(&image, optional_header + directories_offset - 4)? <= RESOURCE_DIRECTORY as u32 {
        return Ok(Err(STATUS_RESOURCE_DATA_NOT_FOUND));
    }
    image.resource_address = read_dword(&image, optional_header + directories_offset + RESOURCE_DIRECTORY * DATA_DIRECTORY_SIZE)?;
    if image.resource_address == 0 {
        return Ok(Err(STATUS_RESOURCE_DATA_NOT_FOUND));
    }
    let resource = image.base as u128 + image.resource_address as u128;
    if resource > MAXIMUM_POINTER || (image.base < USER_ADDRESS_LIMIT && resource >= USER_ADDRESS_LIMIT as u128) {
        return invalid;
    }
    image.root_offset = image.resource_address as i64;
    if image.raw_file && image.resource_address >= image.headers_size {
        let Some(section) = section_for_address(&image, image.resource_address)? else { return invalid };
        if section.raw_size == 0 {
            return Ok(Err(STATUS_RESOURCE_DATA_NOT_FOUND));
        }
        image.root_offset = image.resource_address as i64 - section.virtual_address as i64 + section.raw_offset as i64;
    }
    if image.validate && (image.root_offset <= 0 || !contains(&image, image.root_offset, ImageResourceDirectory::SIZE as i64)) {
        return invalid;
    }
    // O tamanho do DataDirectory não limita a árvore: o kernel usa a extensão
    // da vista. Directory.Size == 0 continua pesquisável.
    let names = read_word(&image, image.root_offset + field!(ImageResourceDirectory, number_of_named_entries))? as i64;
    let identifiers = read_word(&image, image.root_offset + field!(ImageResourceDirectory, number_of_id_entries))? as i64;
    if image.validate && !contains(&image, image.root_offset, (names + identifiers) * ImageResourceDirectoryEntry::SIZE as i64) {
        return invalid;
    }
    Ok(Ok(image))
}

/// Compara as unidades UTF-16 sem alterar a caixa; identificadores inteiros
/// usam a outra faixa do diretório.
fn compare_name(image: &Image, entry_offset: i64, key: &Key) -> Result<Result<i32, u32>, KernelError> {
    let encoded = read_dword(image, entry_offset + field!(ImageResourceDirectoryEntry, name))?;
    if let Key::Id(identifier) = key {
        if encoded & 0x8000_0000 != 0 {
            return Ok(Ok(1));
        }
        if image.validate && encoded > 0xFFFF {
            return Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
        }
        return Ok(Ok((*identifier as i64 - encoded as i64) as i32));
    }
    if encoded & 0x8000_0000 == 0 {
        return Ok(Ok(-1));
    }
    let name_offset = image.root_offset + (encoded & 0x7FFF_FFFF) as i64;
    if image.validate && (name_offset < image.root_offset || name_offset as u128 > image.size) {
        return Ok(Err(STATUS_INVALID_IMAGE_FORMAT));
    }
    let length = read_word(image, name_offset + field!(ImageResourceDirStringU, length))? as usize;
    for index in 0..length {
        let wanted = match key {
            Key::Name(units) => units.get(index).copied().unwrap_or(0),
            Key::Pointer(pointer) => resource_memory::read16(pointer.wrapping_add(index as u64 * 2))?,
            Key::Id(_) => 0,
        } as u32;
        let available = read_word(image, name_offset + field!(ImageResourceDirStringU, name_string) + index as i64 * 2)?;
        if wanted != available {
            return Ok(Ok(if wanted < available { -1 } else { 1 }));
        }
        if wanted == 0 {
            break;
        }
    }
    // Com o prefixo igual, mede-se a string terminada inteira.
    let key_length = match key {
        Key::Name(units) => units.len(),
        Key::Pointer(pointer) => {
            let mut count = 0usize;
            while resource_memory::read16(pointer.wrapping_add(count as u64 * 2))? != 0 {
                count += 1;
            }
            count
        }
        Key::Id(_) => 0,
    };
    Ok(Ok(match key_length.cmp(&length) {
        core::cmp::Ordering::Equal => 0,
        core::cmp::Ordering::Less => -1,
        core::cmp::Ordering::Greater => 1,
    }))
}

enum Entry {
    Status(u32),
    Missing,
    At(i64),
}

fn find_entry(image: &Image, directory_offset: i64, key: &Key, select_first: bool) -> Result<Entry, KernelError> {
    let entry_size = ImageResourceDirectoryEntry::SIZE as i64;
    let entries = ImageResourceDirectory::SIZE as i64;
    if image.validate && !contains(image, directory_offset, entries + entry_size) {
        return Ok(Entry::Status(STATUS_INVALID_IMAGE_FORMAT));
    }
    let named = read_word(image, directory_offset + field!(ImageResourceDirectory, number_of_named_entries))? as i64;
    let identifiers = read_word(image, directory_offset + field!(ImageResourceDirectory, number_of_id_entries))? as i64;
    let numeric = matches!(key, Key::Id(_));
    // As entradas seguem o diretório: primeiro as nomeadas, depois as de Id.
    let first = directory_offset + entries + if numeric { named * entry_size } else { 0 };
    let count = if numeric { identifiers } else { named };
    if image.validate && (!contains(image, directory_offset + entries, named * entry_size) || !contains(image, first, count * entry_size)) {
        return Ok(Entry::Status(STATUS_INVALID_IMAGE_FORMAT));
    }
    if count == 0 {
        return Ok(Entry::Missing);
    }
    if select_first {
        return Ok(Entry::At(first));
    }
    // A disposição ordenada faz parte do PE: a mesma divisão binária do NT,
    // sem ordenar nem corrigir uma árvore malformada.
    let mut lower = 0i64;
    let mut remaining = count;
    while remaining != 0 {
        let half = remaining >> 1;
        let middle = lower + if half != 0 { half - if remaining % 2 != 0 { 0 } else { 1 } } else { 0 };
        let entry = first + middle * entry_size;
        let order = match compare_name(image, entry, key)? {
            Ok(order) => order,
            Err(status) => return Ok(Entry::Status(status)),
        };
        if order == 0 {
            return Ok(Entry::At(entry));
        }
        if order < 0 {
            remaining = middle - lower;
        } else {
            remaining -= middle - lower + 1;
            lower = middle + 1;
        }
    }
    Ok(Entry::Missing)
}

/// Folha: em layout bruto, o RVA dos dados pode pertencer a outra seção.
/// Sem validação, a aritmética do contrato é preservada.
fn resolve_leaf(image: &Image, entry_offset: i64, selected_language: u32) -> Result<Found, KernelError> {
    let encoded_child = read_dword(image, entry_offset + field!(ImageResourceDirectoryEntry, offset_to_data))?;
    if image.validate && encoded_child & 0x8000_0000 != 0 {
        return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
    }
    let leaf = image.root_offset + encoded_child as i64;
    if image.validate && (leaf <= image.root_offset || !contains(image, leaf, ImageResourceDataEntry::SIZE as i64)) {
        return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
    }
    let data_address = read_dword(image, leaf + field!(ImageResourceDataEntry, offset_to_data))?;
    let data_size = read_dword(image, leaf + field!(ImageResourceDataEntry, size))?;
    let mut data_offset = data_address as i64;
    if image.raw_file {
        let Some(resource_section) = section_for_address(image, image.resource_address)? else { return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT)) };
        let mut adjustment = image.resource_address as i64 - image.root_offset;
        if data_address > resource_section.virtual_size {
            let Some(data_section) = section_for_address(image, data_address)? else { return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT)) };
            let virtual_difference = data_section.virtual_address as i64 - resource_section.virtual_address as i64;
            let file_difference = data_section.raw_offset as i64 - image.root_offset;
            if image.validate && (virtual_difference < 0 || file_difference < 0 || virtual_difference < file_difference) {
                return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
            }
            adjustment += virtual_difference - file_difference;
        }
        data_offset -= adjustment;
    }
    if image.validate && (data_offset < image.root_offset || data_size == 0 || !contains(image, data_offset, data_size as i64)) {
        return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
    }
    Ok(Found { address: address_at(image, data_offset), size: data_size, language: selected_language, ..Found::default() })
}

/// Tipo, nome e idiomas candidatos; a política de idiomas vem do resolvedor.
pub fn lookup_unchecked(image: &Image, resource_type: &Key, resource_name: &Key, plan: &Plan, key_pointers: [u64; 2], options: LookupOptions) -> Result<Found, KernelError> {
    if options.count == 0 {
        return Ok(Found::fail(0xC000_000D));
    }
    let mut directory_offset = image.root_offset;
    for (key, missing, index) in [(resource_type, STATUS_RESOURCE_TYPE_NOT_FOUND, 0usize), (resource_name, STATUS_RESOURCE_NAME_NOT_FOUND, 1)] {
        let entry = match find_entry(image, directory_offset, key, false)? {
            Entry::Status(status) => return Ok(Found::fail(status)),
            Entry::Missing => return Ok(Found::fail(missing)),
            Entry::At(entry) => entry,
        };
        let child = read_dword(image, entry + field!(ImageResourceDirectoryEntry, offset_to_data))?;
        if child & 0x8000_0000 == 0 {
            if image.validate {
                return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
            }
            if options.directory {
                return Ok(Found::fail(missing));
            }
            // Sem checagem estrutural o NT aceita uma folha num nível anterior;
            // o WORD publicado é o da chave corrente, mesmo quando era ponteiro.
            return resolve_leaf(image, entry, (key_pointers[index] & 0xFFFF) as u32);
        }
        directory_offset = image.root_offset + (child & 0x7FFF_FFFF) as i64;
        if options.count == index as u32 + 1 {
            // A própria IMAGE_RESOURCE_DIRECTORY, sem tamanho nem cópia.
            if image.validate && !contains(image, directory_offset, (ImageResourceDirectory::SIZE + ImageResourceDirectoryEntry::SIZE) as i64) {
                return Ok(Found::fail(STATUS_INVALID_IMAGE_FORMAT));
            }
            return Ok(Found { address: address_at(image, directory_offset), directory: true, ..Found::default() });
        }
    }
    let candidates: &[u32] = if plan.select_first { &[] } else { &plan.candidates };
    for &language in candidates {
        match find_entry(image, directory_offset, &Key::Id(language), false)? {
            Entry::Status(status) => return Ok(Found::fail(status)),
            Entry::Missing => {}
            Entry::At(entry) => {
                if options.directory {
                    return Ok(Found::fail(STATUS_RESOURCE_LANG_NOT_FOUND));
                }
                return resolve_leaf(image, entry, language);
            }
        }
    }
    if plan.select_first || plan.allow_any {
        match find_entry(image, directory_offset, &Key::Id(0), true)? {
            Entry::Status(status) => return Ok(Found::fail(status)),
            Entry::Missing => {}
            Entry::At(entry) => {
                if options.directory {
                    return Ok(Found::fail(STATUS_RESOURCE_LANG_NOT_FOUND));
                }
                return resolve_leaf(image, entry, read_dword(image, entry + field!(ImageResourceDirectoryEntry, name))? & 0xFFFF);
            }
        }
    }
    Ok(Found::fail(STATUS_RESOURCE_LANG_NOT_FOUND))
}

/// O escopo SEH da busca devolve o código da exceção de acesso: o
/// coordenador continua o fallback de idiomas, como no kernel.
pub fn lookup(image: &Image, resource_type: &Key, resource_name: &Key, plan: &Plan, key_pointers: [u64; 2], options: LookupOptions) -> Result<Found, KernelError> {
    match lookup_unchecked(image, resource_type, resource_name, plan, key_pointers, options) {
        Err(error) => match resource_memory::access_status(&error) {
            Some(status) => Ok(Found::fail(status)),
            None => Err(error),
        },
        other => other,
    }
}
