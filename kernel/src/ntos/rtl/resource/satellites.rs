//! Cache de arquivos de recursos por imagem carregada.
//!
//! Só o arquivo validado fornece um ponteiro; decisões negativas não criam
//! bytes nem estado de CI. O cache vive enquanto a imagem dona estiver
//! carregada.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use crate::ntos::rtl::resource::configuration::{self as resource_configuration, Configuration};
use crate::ntos::rtl::resource::file::{self as resource_file, Opened};
use crate::ntos::rtl::resource::languages as resource_languages;
use crate::ntos::rtl::resource::tree as resource_tree;
use crate::ntos::rtl::unicode_case;
use crate::ntos::mm::loaded_images::{self, LoadedImage};
use crate::rtl::{KernelError, SpinLock};

const STATUS_MUI_FILE_NOT_FOUND: u32 = 0xC00B_0001;
const STATUS_MUI_INVALID_FILE: u32 = 0xC00B_0002;
const STATUS_RESOURCE_ENUM_USER_STOP: u32 = 0xC00B_0006;

/// A imagem principal: base, extensão da vista e layout.
#[derive(Clone, Copy, Debug)]
pub struct Primary {
    pub base: u64,
    pub size: u128,
    pub raw_file: bool,
}

/// Vista publicada de um satélite.
#[derive(Clone, Copy, Debug)]
pub struct Alternate {
    pub base: u64,
    pub size: u64,
}

struct Module {
    entry: Option<u64>,
    retiring: bool,
    resources: BTreeMap<u32, Result<Opened, u32>>,
}

static MODULES: SpinLock<BTreeMap<u64, Module>> = SpinLock::new(BTreeMap::new());
static OBSERVING: AtomicBool = AtomicBool::new(false);

fn last_index_of(units: &[u16], from: usize) -> Option<usize> {
    (0..=from.min(units.len().saturating_sub(1))).rev().find(|&index| units[index] == u16::from(b'\\'))
}

/// `<dir>\<idioma>\<base>.mui`, ou `<pai>\SystemResources\<base>.mun` no
/// módulo neutro.
fn resource_path(entry: &LoadedImage, language_name: &str, neutral_module: bool) -> Result<String, u32> {
    let name: Vec<u16> = entry.name.encode_utf16().collect();
    let Some(separator) = name.iter().rposition(|&unit| unit == u16::from(b'\\')) else { return Err(STATUS_MUI_FILE_NOT_FOUND) };
    let directory = &name[..separator + 1];
    if directory.len() >= 260 {
        return Err(0xC000_008A);
    }
    let basename = &name[separator + 1..];
    let mut path: Vec<u16> = Vec::new();
    if neutral_module {
        let parent = directory.len().checked_sub(2).and_then(|from| last_index_of(directory, from));
        let Some(parent) = parent.filter(|&parent| parent > 0) else { return Err(0xC000_008A) };
        path.extend_from_slice(&directory[..parent + 1]);
        path.extend("SystemResources\\".encode_utf16());
        path.extend_from_slice(basename);
        path.extend(".mun".encode_utf16());
    } else {
        path.extend_from_slice(directory);
        path.extend(language_name.encode_utf16());
        path.push(u16::from(b'\\'));
        path.extend_from_slice(basename);
        path.extend(".mui".encode_utf16());
    }
    if path.len() > 260 {
        return Err(0xC000_0023);
    }
    Ok(String::from_utf16_lossy(&path))
}

fn verify(primary: &Primary, primary_configuration: Option<Configuration>, alternate: &Opened, language_name: &str, flags: u32) -> Result<bool, KernelError> {
    let strict = flags & 0x1000 != 0;
    let neutral_module = flags & 0x100_0000 != 0;
    let inspect_configuration = if strict { resource_configuration::inspect } else { resource_configuration::inspect_legacy };
    let primary_configuration = match primary_configuration {
        Some(configuration) => configuration,
        None => {
            let result = match resource_tree::inspect(primary.base, primary.size, primary.raw_file, strict)? {
                Ok(image) => inspect_configuration(&image)?,
                Err(status) => Err(status),
            };
            match result {
                Ok(configuration) => configuration,
                Err(status) => return Ok(neutral_module && status == 0xC000_008A),
            }
        }
    };
    let Ok(image) = resource_tree::inspect(alternate.base, alternate.size as u128, true, strict)? else { return Ok(false) };
    let Ok(satellite) = inspect_configuration(&image)? else { return Ok(false) };
    if !resource_configuration::service_checksum_matches(&primary_configuration, &satellite)? {
        return Ok(false);
    }
    if neutral_module {
        return Ok(true);
    }
    let wanted: Vec<u16> = language_name.encode_utf16().collect();
    Ok(unicode_case::upcase_units(&resource_configuration::language_name(&satellite)?)? == unicode_case::upcase_units(&wanted)?)
}

fn on_unload(entry: &LoadedImage) {
    let _ = unload(entry.image_base);
}

/// O satélite do idioma, aberto e validado uma vez por imagem dona.
pub fn load(primary: &Primary, primary_configuration: Option<Configuration>, language: u32, flags: u32) -> Result<Result<Alternate, u32>, KernelError> {
    if !OBSERVING.swap(true, Ordering::AcqRel) {
        loaded_images::observe_unload(on_unload);
    }
    let base = primary.base;
    let entry = loaded_images::find(base);
    let entry_id = entry.as_ref().map(|entry| entry.id);
    let stale = MODULES.lock().get(&base).is_some_and(|owner| owner.retiring || owner.entry != entry_id);
    if stale {
        // Uma VA reutilizada pertence a outra imagem: a retirada termina
        // antes de qualquer ponteiro antigo voltar a ser publicado.
        unload(base)?;
    }
    let existing = {
        let mut modules = MODULES.lock();
        let owner = modules.entry(base).or_insert_with(|| Module { entry: entry_id, retiring: false, resources: BTreeMap::new() });
        owner.resources.get(&language).cloned()
    };
    if let Some(existing) = existing {
        return Ok(match existing {
            Ok(opened) => Ok(Alternate { base: opened.base, size: opened.size }),
            Err(_) => Err(STATUS_RESOURCE_ENUM_USER_STOP),
        });
    }
    let neutral_module = flags & 0x100_0000 != 0;
    let language_name = if neutral_module { Some("") } else { resource_languages::name_for_identifier(language) };
    let mut result: Result<Opened, u32> = Err(STATUS_MUI_FILE_NOT_FOUND);
    if let (Some(entry), Some(language_name)) = (entry.as_ref(), language_name) {
        if let Ok(path) = resource_path(entry, language_name, neutral_module).map_err(|status| result = Err(status)) {
            // Revalida o cabeçalho do dono: o subsistema decide a proteção da
            // SECTION; o caminho vem da lista real de módulos carregados.
            result = match resource_tree::inspect_header(base, primary.size, primary.raw_file, false)? {
                Err(status) => Err(status),
                Ok(header) => resource_file::open(&path, &header)?,
            };
            if let Ok(opened) = &result {
                let valid = verify(primary, primary_configuration, opened, language_name, flags);
                if !matches!(valid, Ok(true)) {
                    opened.release()?;
                }
                if !valid? {
                    result = Err(STATUS_MUI_INVALID_FILE);
                }
            }
        }
    }
    if let Some(owner) = MODULES.lock().get_mut(&base) {
        owner.resources.insert(language, result.clone());
    }
    Ok(result.map(|opened| Alternate { base: opened.base, size: opened.size }))
}

pub fn unload(image_base: u64) -> Result<bool, KernelError> {
    let base = image_base & !3;
    let owner = {
        let mut modules = MODULES.lock();
        if let Some(owner) = modules.get_mut(&base) {
            owner.retiring = true;
        }
        modules.remove(&base)
    };
    if let Some(owner) = owner {
        for resource in owner.resources.into_values() {
            if let Ok(opened) = resource {
                opened.release()?;
            }
        }
    }
    resource_file::drain_releases()?;
    Ok(true)
}
