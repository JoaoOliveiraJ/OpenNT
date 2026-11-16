//! A API clássica de recursos do Ldr: LdrFindResource_U
//! (LdrpSearchResourceSection_U, ntoskrnl 19041 0x672884) e LdrAccessResource
//! (LdrpAccessResourceData 0x67255c e LdrpAccessResourceDataNoMultipleLanguage
//! 0x672638).
//!
//! A busca desce a árvore de recursos nível a nível (tipo, nome, idioma),
//! com a mesma busca binária do original em cada diretório (entradas com
//! nome primeiro, comparadas por wcsncmp sensível à caixa; IDs pela
//! diferença de 32 bits). No nível do idioma vale a sequência de fallback:
//! o idioma pedido, a cadeia de pais (LdrpGetParentLangId), e — só para um
//! idioma primário neutro — o PsMachineUILanguageId, o
//! PsInstallUILanguageId, o PsDefaultSystemLocaleId, 0x409 e por fim a
//! primeira entrada; um idioma igual ao último tentado é pulado. Um
//! diretório de idiomas vazio encerra com STATUS_RESOURCE_LANG_NOT_FOUND.
//!
//! Depois dos drivers de boot (PnPBootDriversInitialized), a busca consulta
//! o RC_CONFIG do módulo (LdrIsResItemExist: o recurso "MUI" com só a
//! assinatura 0xFECDFECD, sem RC_CONFIG = 0x80000) e tenta os satélites
//! (`resource::satellites`, o LdrLoadAlternateResourceModuleEx): o .mun
//! neutro (idioma 0xF2EE) ao chegar no nível do idioma, e o .mui de cada
//! idioma da sequência quando o tipo não é só do principal; no satélite a
//! busca usa as flags 0x2000030 (só o módulo dado, a primeira entrada de
//! idioma). VERSION (16), MANIFEST (24) e "MUI" com idioma neutro ficam no
//! principal. As entradas internas usam as flags 0 (LdrFindResource_U) e
//! 0x2000030; o ramo de tabela de mensagens (flag 0x40) não é alcançado.
//!
//! O acesso converte o IMAGE_RESOURCE_DATA_ENTRY: numa imagem, base +
//! OffsetToData; numa vista de arquivo (bit 0 do handle), pela seção do
//! diretório de recursos (e pela seção do dado quando o OffsetToData passa
//! do VirtualSize da primeira, como no original). Um endereço fora da
//! imagem é STATUS_INVALID_IMAGE_FORMAT, com *Address zerado. Uma entrada
//! fora do módulo é procurada nos satélites já abertos dele
//! (LdrpGetAlternateResourceModuleHandleEx).

use alloc::vec::Vec;

use crate::ntos::io::small::boot_drivers_state;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::loaded_images;
use crate::ntos::rtl::guest_strings;
use crate::ntos::rtl::image;
use crate::ntos::rtl::nls_configuration;
use crate::ntos::rtl::resource::configuration::{self as resource_configuration, Configuration};
use crate::ntos::rtl::resource::satellites::{self as resource_satellites, Primary};
use crate::ntos::rtl::resource::tree::Key;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
const STATUS_RESOURCE_TYPE_NOT_FOUND: u32 = 0xC000_008A;
const STATUS_RESOURCE_NAME_NOT_FOUND: u32 = 0xC000_008B;
const STATUS_RESOURCE_LANG_NOT_FOUND: u32 = 0xC000_0204;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
const STATUS_MUI_FILE_NOT_FOUND: u32 = 0xC00B_0001;

/// LDR_FIND_RESOURCE_DIRECTORY.
const FIND_DIRECTORY: u32 = 0x2;
/// Só o módulo dado (sem RC_CONFIG nem satélites).
const MAIN_MODULE_ONLY: u32 = 0x10;
/// Aceita a primeira entrada do diretório de idiomas.
const FIRST_LANGUAGE: u32 = 0x20;
/// Pedido de seleção MUI explícita.
const EXPLICIT_MUI: u32 = 0x8;
/// Satélite neutro (.mun) no lugar do de idioma.
const NEUTRAL_MODULE: u32 = 0x100_0000;
/// Flags da busca dentro de um satélite.
const ALTERNATE_SEARCH: u32 = 0x200_0030;
/// Bits do LdrIsResItemExist: sem RC_CONFIG, tipo fora do satélite e o
/// par que exclui os satélites neutros.
const NO_RC_CONFIG: u32 = 0x8_0000;
const NOT_IN_SATELLITE: u32 = 0x2_0000;
const NO_NEUTRAL_SATELLITE: u32 = 0x204_0000;
/// Idioma do satélite neutro.
const NEUTRAL_LANGUAGE: u32 = 0xF2EE;
/// Valor inicial do "último idioma tentado".
const NO_LANGUAGE_YET: u64 = 0xEEEE;
/// MM_HIGHEST_USER_ADDRESS das checagens de seção.
const USER_LIMIT: u64 = 0x7FFF_FFFE_FFFF;

/// Uma chave do caminho: ID ou nome (o valor cru e o PCWSTR, lido uma vez).
#[derive(Clone)]
enum Element {
    Id(u64),
    Name(u64, Vec<u16>),
}

impl Element {
    /// O ULONG_PTR do caminho.
    fn raw(&self) -> u64 {
        match self {
            Element::Id(value) | Element::Name(value, _) => *value,
        }
    }
}

fn element(value: u64) -> Element {
    if value & !0xFFFF != 0 { Element::Name(value, guest_strings::read_wide_units(value)) } else { Element::Id(value) }
}

fn bad_pointer(pointer: u64) -> bool {
    pointer == 0 || pointer == u64::MAX
}

/// IMAGE_DIRECTORY_ENTRY_RESOURCE pelo RtlImageDirectoryEntryToData(Dll, TRUE).
fn resource_directory(dll: u64) -> Result<u64, KernelError> {
    let size = guest::alloc_bytes(4);
    let directory = image::directory_entry(dll, true, 2, size);
    guest::free_bytes(size);
    directory
}

/// wcsncmp(Key, Name, Count): para no NUL da chave, na diferença ou no
/// último dos Count WCHARs; devolve a diferença das unidades.
fn wcsncmp(key: &[u16], name: u64, count: u64) -> Result<i32, KernelError> {
    if count == 0 {
        return Ok(0);
    }
    let unit = |index: usize| key.get(index).copied().unwrap_or(0);
    let mut index = 0usize;
    let mut remaining = count;
    loop {
        remaining -= 1;
        if remaining == 0 {
            break;
        }
        let a = unit(index);
        if a == 0 || a != guest::try_read16(name + index as u64 * 2)? {
            break;
        }
        index += 1;
    }
    Ok(unit(index) as i32 - guest::try_read16(name + index as u64 * 2)? as i32)
}

/// LdrpCompareResourceNamesWithValidation: sinal de chave - entrada.
fn compare(key: &Element, entry: u64, root: u64) -> Result<i32, KernelError> {
    let name = guest::try_read32(entry)?;
    match key {
        Element::Name(_, units) => {
            if name & 0x8000_0000 == 0 {
                return Ok(-1);
            }
            let text = root + (name & 0x7FFF_FFFF) as u64;
            let length = guest::try_read16(text)? as u64;
            let difference = wcsncmp(units, text + 2, length)?;
            Ok(if difference != 0 { difference } else if units.len() as u64 != length { 1 } else { 0 })
        }
        Element::Id(value) => Ok(if name & 0x8000_0000 != 0 { 1 } else { (*value as i32).wrapping_sub(name as i32) }),
    }
}

/// Resultado da busca num diretório.
enum Lookup {
    Directory(u64),
    Data(u64),
    Missing,
    Empty,
}

/// Uma entrada encontrada: subdiretório (bit 31) ou IMAGE_RESOURCE_DATA_ENTRY.
fn found(entry: u64, root: u64) -> Result<Lookup, KernelError> {
    let offset = guest::try_read32(entry + 4)?;
    Ok(if offset & 0x8000_0000 != 0 { Lookup::Directory(root + (offset & 0x7FFF_FFFF) as u64) } else { Lookup::Data(root + offset as u64) })
}

/// A busca binária de um IMAGE_RESOURCE_DIRECTORY, com os mesmos pontos
/// médios do original; `first` toma a primeira entrada de ID sem comparar.
fn lookup(directory: u64, root: u64, key: &Element, first: bool) -> Result<Lookup, KernelError> {
    let named = guest::try_read16(directory + 0xC)?;
    let mut entries = directory + 0x10;
    let mut count = named;
    if matches!(key, Element::Id(_)) {
        entries += named as u64 * 8;
        count = guest::try_read16(directory + 0xE)?;
    }
    if count == 0 {
        return Ok(Lookup::Empty);
    }
    if first {
        // O dado da primeira entrada, sem olhar o bit de subdiretório.
        return Ok(Lookup::Data(root + guest::try_read32(entries + 4)? as u64));
    }
    let mut low = entries;
    let mut high = entries + (count as u64 - 1) * 8;
    while low <= high {
        let half = count >> 1;
        if half == 0 {
            if count != 0 && compare(key, low, root)? == 0 {
                return found(low, root);
            }
            return Ok(Lookup::Missing);
        }
        let middle = if count & 1 != 0 { low + half as u64 * 8 } else { low + (half as u64 - 1) * 8 };
        let difference = compare(key, middle, root)?;
        if difference == 0 {
            return found(middle, root);
        }
        if difference < 0 {
            high = middle.wrapping_sub(8);
            count = if count & 1 != 0 { half } else { half - 1 };
        } else {
            low = middle + 8;
            count = half;
        }
    }
    Ok(Lookup::Missing)
}

/// LdrpGetImageSize: (status, SizeOfImage); vista de arquivo usa a entrada
/// da PsLoadedModuleList que contém o handle (0 se nenhuma).
fn image_size(dll: u64) -> Result<(u32, u64), KernelError> {
    let header = image::nt_header(dll & !3)?;
    if header == 0 {
        return Ok((STATUS_INVALID_IMAGE_FORMAT, 0));
    }
    if dll & 1 != 0 {
        return Ok((0, loaded_images::find(dll).map_or(0, |entry| entry.size_of_image)));
    }
    match guest::try_read16(header + 0x18)? {
        0x10B | 0x20B => Ok((0, guest::try_read32(header + 0x50)? as u64)),
        _ => Ok((STATUS_INVALID_IMAGE_FORMAT, 0)),
    }
}

/// RtlSectionTableFromVirtualAddress (0x301830): a seção cujo
/// [VirtualAddress, VirtualAddress + SizeOfRawData) contém o RVA.
fn section_from_rva(header: u64, rva: u32) -> Result<Option<u64>, KernelError> {
    let first = header + 0x18 + guest::try_read16(header + 0x14)? as u64;
    let count = guest::try_read16(header + 6)? as u64;
    if header <= USER_LIMIT {
        let end = first.wrapping_add(count * 0x28);
        if first > USER_LIMIT || end < first || end >= USER_LIMIT {
            return Ok(None);
        }
    }
    for index in 0..count {
        let section = first + index * 0x28;
        let start = guest::try_read32(section + 0xC)?;
        if rva >= start && rva < start.wrapping_add(guest::try_read32(section + 0x10)?) {
            return Ok(Some(section));
        }
    }
    Ok(None)
}

/// RtlAddressInSectionTable (0x3017dc): base + PointerToRawData -
/// VirtualAddress + RVA, ou 0.
fn address_in_section_table(header: u64, base: u64, rva: u32) -> Result<u64, KernelError> {
    let Some(section) = section_from_rva(header, rva)? else { return Ok(0) };
    let raw = (guest::try_read32(section + 0x14)? as u64).wrapping_sub(guest::try_read32(section + 0xC)? as u64);
    let address = base.wrapping_add(raw).wrapping_add(rva as u64);
    Ok(if base < USER_LIMIT && address >= USER_LIMIT { 0 } else { address })
}

/// LdrpGetRcConfig sem o cache: o recurso "MUI" 1 (primeira entrada de
/// idioma) do módulo, aceito só com a assinatura do RC_CONFIG.
fn rc_config(dll: u64) -> Result<Option<Configuration>, KernelError> {
    let path = [Element::Name(0, "MUI".encode_utf16().collect()), Element::Id(1), Element::Id(0)];
    let Ok(entry) = search(dll, &path, 3, ALTERNATE_SEARCH)? else { return Ok(None) };
    match access_entry(dll, entry, true)? {
        Access::Done { status, address, size } if status & 0x8000_0000 == 0 && guest::try_read32(address)? == 0xFECD_FECD => Ok(Some(Configuration { address, size })),
        _ => Ok(None),
    }
}

/// LdrIsResItemExist: as flags de pertinência do tipo pelo RC_CONFIG.
fn is_res_item_exist(dll: u64, kind: &Element) -> Result<u32, KernelError> {
    let Some(configuration) = rc_config(dll)? else { return Ok(NO_RC_CONFIG) };
    let key = match kind {
        Element::Id(value) => Key::Id(*value as u32),
        Element::Name(_, units) => Key::Name(units.clone()),
    };
    resource_configuration::type_membership(&configuration, &key)
}

/// _wcsicmp(Tipo, L"MUI") == 0 (só A..Z dobram).
fn is_mui_type(kind: &Element) -> bool {
    match kind {
        Element::Name(_, units) => units.len() == 3 && units.iter().zip("mui".encode_utf16()).all(|(&unit, wanted)| if (0x41..=0x5A).contains(&unit) { unit + 0x20 == wanted } else { unit == wanted }),
        Element::Id(_) => false,
    }
}

/// LdrpLoadResourceFromAlternativeModule (0x301d18): o satélite do idioma
/// (ou o .mun com NEUTRAL_MODULE) e a busca nele com ALTERNATE_SEARCH.
fn search_alternate(dll: u64, saved: &[Element; 2], length: u32, language: u16, flags: u32) -> Result<Result<u64, u32>, KernelError> {
    if length.wrapping_sub(3) > 1 {
        return Ok(Err(STATUS_INVALID_PARAMETER_3));
    }
    let language = if flags & NEUTRAL_MODULE != 0 { NEUTRAL_LANGUAGE } else { language as u32 };
    let (_, size) = image_size(dll)?;
    let primary = Primary { base: dll & !3, size: size as u128, raw_file: dll & 1 != 0 };
    let alternate = match resource_satellites::load(&primary, None, language, flags)? {
        Ok(alternate) => alternate,
        Err(STATUS_OBJECT_PATH_NOT_FOUND) | Err(STATUS_OBJECT_NAME_NOT_FOUND) => return Ok(Err(STATUS_MUI_FILE_NOT_FOUND)),
        Err(status) => return Ok(Err(status)),
    };
    let path = [saved[0].clone(), saved[1].clone(), Element::Id(language as u64)];
    search(alternate.base | 1, &path, 3, ALTERNATE_SEARCH)
}

/// Os pontos do laço do original: descer um nível, o fim da descida, o
/// erro do nível e a próxima tentativa de idioma.
enum Step {
    Level,
    End,
    Fail,
    Language,
}

/// LdrpSearchResourceSection_U sobre o caminho já lido: o endereço do
/// IMAGE_RESOURCE_DATA_ENTRY (ou do diretório, com FIND_DIRECTORY) ou o
/// NTSTATUS de erro.
fn search(dll: u64, path: &[Element], length: u32, flags: u32) -> Result<Result<u64, u32>, KernelError> {
    let levels = if length == 4 { 3 } else { length as usize };
    let root = resource_directory(dll)?;
    if root == 0 {
        return Ok(Err(STATUS_RESOURCE_DATA_NOT_FOUND));
    }
    // O LANGID é a palavra baixa do terceiro ULONG_PTR, seja qual for.
    let language = if levels == 3 { path[2].raw() as u16 } else { 0 };
    let mut flags = flags;
    let boot_drivers = boot_drivers_state::is_initialized();
    if flags & MAIN_MODULE_ONLY == 0 && (1..=3).contains(&levels) && boot_drivers {
        let special = matches!(path[0], Element::Id(0x10) | Element::Id(0x18)) || is_mui_type(&path[0]);
        if special && flags & EXPLICIT_MUI == 0 && language & 0xF3FF == 0 && language != 0xC00 {
            flags |= MAIN_MODULE_ONLY;
        } else {
            flags |= is_res_item_exist(dll, &path[0])?;
        }
    }
    let try_alternate = boot_drivers && flags & (NO_RC_CONFIG | NOT_IN_SATELLITE | MAIN_MODULE_ONLY) == 0;
    let try_neutral = boot_drivers && flags & NO_NEUTRAL_SATELLITE == 0;
    let saved = [path[0].clone(), if levels >= 2 { path[1].clone() } else { Element::Id(0) }];
    // PsMachineUILanguageId, PsInstallUILanguageId e PsDefaultSystemLocaleId.
    let machine = nls_configuration::DEFAULT_UI_LANGUAGE as u16;
    let install = nls_configuration::INSTALL_UI_LANGUAGE as u16;
    let locale = crate::ntos::ps::locale::default_system_locale();
    let neutral_primary = language & 0x3FF == 0;

    let mut current = root;
    let mut data = 0u64;
    let mut remaining = levels as i32;
    let mut index = 0usize;
    let mut language_directory = 0u64;
    let mut last_language = NO_LANGUAGE_YET;
    let mut fallback = 0u32;
    let mut retry = true;
    let mut candidate: u16 = 0;
    let mut step = Step::Level;
    loop {
        step = match step {
            Step::Level => {
                if current == 0 {
                    Step::End
                } else {
                    let was = remaining;
                    remaining -= 1;
                    if was == 0 {
                        Step::End
                    } else {
                        if remaining == 0 {
                            if try_neutral {
                                if let Ok(entry) = search_alternate(dll, &saved, length, 0, flags | NEUTRAL_MODULE)? {
                                    return Ok(Ok(entry));
                                }
                            }
                            if levels == 3 {
                                language_directory = current;
                            }
                        }
                        if language_directory != 0 {
                            Step::Language
                        } else {
                            match lookup(current, root, &path[index], false)? {
                                Lookup::Empty => {
                                    current = 0;
                                    retry = false;
                                    Step::Fail
                                }
                                result => {
                                    (current, data) = descend(result, data);
                                    index += 1;
                                    Step::Level
                                }
                            }
                        }
                    }
                }
            }
            Step::End => {
                if data != 0 && flags & FIND_DIRECTORY == 0 {
                    return Ok(Ok(data));
                }
                if current != 0 && flags & FIND_DIRECTORY != 0 {
                    return Ok(Ok(current));
                }
                Step::Fail
            }
            Step::Fail => match (levels as i32).wrapping_sub(remaining).wrapping_sub(1) {
                0 => return Ok(Err(STATUS_RESOURCE_TYPE_NOT_FOUND)),
                1 => return Ok(Err(STATUS_RESOURCE_NAME_NOT_FOUND)),
                2 => {
                    if language_directory == 0 {
                        return Ok(Err(STATUS_RESOURCE_LANG_NOT_FOUND));
                    }
                    data = 0;
                    if !retry {
                        return Ok(Err(STATUS_RESOURCE_LANG_NOT_FOUND));
                    }
                    Step::Language
                }
                _ => return Ok(Err(STATUS_INVALID_PARAMETER)),
            },
            Step::Language => {
                let attempt = fallback;
                fallback += 1;
                let alternate = |language: u16| -> Result<Option<u64>, KernelError> { Ok(search_alternate(dll, &saved, length, language, flags)?.ok()) };
                match attempt {
                    0 => {
                        if try_alternate && language != 0 {
                            if let Some(entry) = alternate(language)? {
                                return Ok(Ok(entry));
                            }
                        }
                        candidate = language;
                    }
                    1 => {
                        if candidate != 0 {
                            candidate = parent_language(candidate);
                        }
                        if candidate != 0 {
                            if try_alternate {
                                if let Some(entry) = alternate(candidate)? {
                                    return Ok(Ok(entry));
                                }
                            }
                            // A cadeia de pais continua neste passo.
                            fallback -= 1;
                        }
                    }
                    2 => {
                        if !neutral_primary {
                            return Ok(Err(STATUS_RESOURCE_LANG_NOT_FOUND));
                        }
                        if try_alternate && machine != 0 {
                            if let Some(entry) = alternate(machine)? {
                                return Ok(Ok(entry));
                            }
                            candidate = machine;
                        } else {
                            candidate = if machine != 0 { machine } else { last_language as u16 };
                        }
                    }
                    3 => {
                        if install == machine {
                            candidate = last_language as u16;
                        } else {
                            if try_alternate {
                                if let Some(entry) = alternate(install)? {
                                    return Ok(Ok(entry));
                                }
                            }
                            candidate = install;
                        }
                    }
                    4 => {
                        candidate = locale as u16;
                        if candidate == install || candidate == machine {
                            candidate = last_language as u16;
                        } else if try_alternate {
                            if let Some(entry) = alternate(candidate)? {
                                return Ok(Ok(entry));
                            }
                        }
                    }
                    5 => {
                        candidate = 0x409;
                        if locale == 0x409 || install == 0x409 || machine == 0x409 {
                            candidate = last_language as u16;
                        } else if try_alternate {
                            if let Some(entry) = alternate(0x409)? {
                                return Ok(Ok(entry));
                            }
                        }
                    }
                    6 => flags |= FIRST_LANGUAGE,
                    _ => return Ok(Err(STATUS_RESOURCE_LANG_NOT_FOUND)),
                }
                if flags & FIRST_LANGUAGE == 0 && candidate as u64 == last_language {
                    Step::Language
                } else {
                    last_language = candidate as u64;
                    current = language_directory;
                    let first = flags & FIRST_LANGUAGE != 0;
                    match lookup(current, root, &Element::Id(last_language), first)? {
                        Lookup::Empty => {
                            current = 0;
                            retry = false;
                            Step::Fail
                        }
                        Lookup::Data(entry) if first => {
                            // A primeira entrada vai direto ao fim da busca.
                            current = 0;
                            data = entry;
                            Step::End
                        }
                        result => {
                            (current, data) = descend(result, data);
                            index += 1;
                            Step::Level
                        }
                    }
                }
            }
        };
    }
}

/// Uma entrada achada (ou não) num nível: (diretório corrente, dado).
fn descend(result: Lookup, data: u64) -> (u64, u64) {
    match result {
        Lookup::Directory(directory) => (directory, data),
        Lookup::Data(entry) => (0, entry),
        Lookup::Missing | Lookup::Empty => (0, data),
    }
}

/// LdrpGetParentLangId: o idioma pai pelo nome (en-US -> en -> neutro);
/// um LANGID desconhecido não tem pai.
fn parent_language(language: u16) -> u16 {
    crate::ntos::rtl::resource::language_data::LANGUAGES.iter().find(|row| row.0 == language as u32).map_or(0, |row| row.2 as u16)
}

/// LdrFindResource_U(DllHandle, ResourceIdPath, ResourceIdPathLength,
/// ResourceDataEntry) = LdrpSearchResourceSection_U(..., Flags 0, ...).
pub fn find_resource(dll: u64, path: u64, length: u32, output: u64) -> Result<u32, KernelError> {
    search_section(dll, path, length, 0, output)
}

/// LdrpSearchResourceSection_U(DllHandle, ResourceIdPath, Length, Flags,
/// ResourceDirectoryOrData): validação e leitura do caminho.
fn search_section(dll: u64, path: u64, length: u32, flags: u32, output: u64) -> Result<u32, KernelError> {
    if (length < 3 && flags & FIND_DIRECTORY == 0) || length > 4 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    let selection = flags & 0x41;
    if (selection != 0 && length != 4) || (length == 4 && selection == 0) {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    if bad_pointer(path) || bad_pointer(dll) || bad_pointer(output) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let levels = if length == 4 { 3 } else { length as u64 };
    let mut elements = Vec::with_capacity(levels as usize);
    for slot in 0..levels {
        elements.push(element(guest::try_read64(path + slot * 8)?));
    }
    match search(dll, &elements, length, flags)? {
        Ok(entry) => {
            guest::try_write64(output, entry)?;
            Ok(0)
        }
        Err(status) => Ok(status),
    }
}

/// Resultado do LdrpAccessResourceDataNoMultipleLanguage.
enum Access {
    /// Erro antes de calcular o endereço (nada é publicado).
    Failed(u32),
    /// O endereço calculado caiu fora da imagem (*Address = 0).
    OutsideImage,
    Done { status: u32, address: u64, size: u32 },
}

/// LdrpAccessResourceDataNoMultipleLanguage; `address_wanted` falso é o
/// Address NULL (o endereço não é calculado nem conferido).
fn access_entry(dll: u64, entry: u64, address_wanted: bool) -> Result<Access, KernelError> {
    let directory = resource_directory(dll)?;
    if directory == 0 {
        return Ok(Access::Failed(STATUS_RESOURCE_DATA_NOT_FOUND));
    }
    let (status, size) = image_size(dll)?;
    if status == STATUS_INVALID_IMAGE_FORMAT {
        return Ok(Access::Failed(status));
    }
    let base = dll & !3;
    if entry <= base || (size != 0 && entry >= base + size) {
        return Ok(Access::Failed(STATUS_INVALID_IMAGE_FORMAT));
    }
    let mut delta = 0u64;
    if dll & 1 != 0 {
        let header = image::nt_header(base)?;
        if header == 0 {
            return Ok(Access::Failed(STATUS_RESOURCE_DATA_NOT_FOUND));
        }
        let rva = match guest::try_read16(header + 0x18)? {
            0x10B => guest::try_read32(header + 0x88)?,
            0x20B => guest::try_read32(header + 0x98)?,
            _ => 0,
        };
        if rva == 0 {
            return Ok(Access::Failed(STATUS_RESOURCE_DATA_NOT_FOUND));
        }
        delta = (rva as u64).wrapping_sub(directory).wrapping_add(base);
        let Some(section) = section_from_rva(header, rva)? else { return Ok(Access::Failed(STATUS_RESOURCE_DATA_NOT_FOUND)) };
        let offset = guest::try_read32(entry)?;
        if offset > guest::try_read32(section + 8)? {
            let first = guest::try_read32(section + 0xC)? as u64;
            let Some(other) = section_from_rva(header, offset)? else { return Ok(Access::Failed(STATUS_RESOURCE_DATA_NOT_FOUND)) };
            let other_start = guest::try_read32(other + 0xC)?;
            let raw = address_in_section_table(header, base, other_start)?;
            delta = delta.wrapping_add((other_start as u64).wrapping_sub(first).wrapping_add(directory).wrapping_sub(raw));
        }
    }
    let mut address = 0u64;
    if address_wanted {
        address = (guest::try_read32(entry)? as u64).wrapping_sub(delta).wrapping_add(base);
        if address <= base || (size != 0 && address >= base + size) {
            return Ok(Access::OutsideImage);
        }
    }
    Ok(Access::Done { status, address, size: guest::try_read32(entry + 4)? })
}

/// LdrAccessResource(DllHandle, ResourceDataEntry, Address, Size)
/// (LdrpAccessResourceData).
pub fn access_resource(dll: u64, entry: u64, address_output: u64, size_output: u64) -> Result<u32, KernelError> {
    if dll == 0 || entry == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let mut handle = dll;
    if boot_drivers_state::is_initialized() {
        let base = dll & !3;
        let directory = resource_directory(dll)?;
        if directory == 0 {
            return Ok(STATUS_RESOURCE_DATA_NOT_FOUND);
        }
        let mut elsewhere = entry < directory;
        if !elsewhere {
            let (status, size) = image_size(dll)?;
            if status == STATUS_INVALID_IMAGE_FORMAT {
                return Ok(status);
            }
            elsewhere = size != 0 && (entry < base || entry >= base + size);
        }
        if elsewhere {
            if let Some(alternate) = resource_satellites::containing(base, entry) {
                handle = alternate;
            }
        }
    }
    match access_entry(handle, entry, address_output != 0)? {
        Access::Failed(status) => Ok(status),
        Access::OutsideImage => {
            guest::try_write64(address_output, 0)?;
            Ok(STATUS_INVALID_IMAGE_FORMAT)
        }
        Access::Done { status, address, size } => {
            if address_output != 0 {
                guest::try_write64(address_output, address)?;
            }
            if size_output != 0 {
                guest::try_write32(size_output, size)?;
            }
            Ok(status)
        }
    }
}
