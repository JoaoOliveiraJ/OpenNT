//! Exclusão por OBJECT_ATTRIBUTES.
//!
//! O nome é capturado antes da resolução; handles relativos mantêm o objeto
//! dono referenciado até o fim. A retirada do nome é do volume
//! (`file_lifetime::request_delete`).

use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::io::file::lifetime as file_lifetime;
use crate::ntos::ex::callback_security;
use crate::drivers::fs::volume::FileSystem;
use crate::ntos::ke::pcr;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::object_types;
use crate::ntos::ob::handles::security as security_handles;
use crate::ntos::ps::process;
use crate::ntos::rtl::resource::memory as protected;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::io::file::zw as zw_files;

/// NtDeleteFile incrementa OtherOperationCount antes do OB, mesmo quando os
/// atributos não permitem completar a abertura.
fn count_operation() {
    let counter = process::get_current_thread() + 0x390;
    guest::write64(counter, guest::read64(counter).wrapping_add(1));
    let processor = pcr::get_pcr_address() + 0x2EE4;
    guest::write32(processor, guest::read32(processor).wrapping_add(1));
}

/// Separadores inválidos sem normalizar; "." e ".." chegam ao volume.
fn invalid_name(name: &str) -> bool {
    name.contains('\0') || name.contains('/') || name.contains("\\\\") || (name.chars().count() > 1 && name.ends_with('\\'))
}

fn has_reparse(name: &str, insensitive: bool, start: NodeId) -> bool {
    let mut prefix: Option<String> = if name.starts_with('\\') { Some(String::new()) } else { None };
    for part in name.split('\\').filter(|part| !part.is_empty()) {
        let next = match &prefix {
            None => String::from(part),
            Some(previous) => alloc::format!("{previous}\\{part}"),
        };
        let found = object_manager::resolve_from(&next, 0, insensitive, true, start).0.and_then(object_manager::node);
        if found.as_ref().is_some_and(|node| node.type_name == "SymbolicLink") {
            return true;
        }
        if found.as_ref().is_some_and(|node| node.mount.is_some()) {
            return false;
        }
        prefix = Some(next);
    }
    false
}

/// Pai inexistente, nome inexistente e volume sem escrita diferenciados.
fn remove_from_volume(volume: &'static dyn FileSystem, path: &str, related: u64) -> Result<u32, KernelError> {
    // Volumes com metadados (stat) distinguem o pai inexistente.
    let has_stat = volume.stat("/").is_some();
    let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    if has_stat {
        let mut parent = String::new();
        for component in &components[..components.len().saturating_sub(1)] {
            if *component == "." || *component == ".." {
                return Ok(0xC000_003A);
            }
            parent.push('/');
            parent.push_str(component);
            if !volume.stat(&parent).is_some_and(|stat| stat.directory) {
                return Ok(0xC000_003A);
            }
        }
        if components.last().is_some_and(|last| *last == "." || *last == "..") {
            return Ok(0xC000_0033);
        }
    }
    let metadata = volume.stat(path);
    let exists = metadata.is_some() || volume.exists(path);
    if !exists {
        let parent = match path.rfind('/') {
            Some(0) | None => "/",
            Some(index) => &path[..index],
        };
        if has_stat && volume.stat(parent).is_none() {
            return Ok(0xC000_003A);
        }
        return Ok(0xC000_0034);
    }
    file_lifetime::request_delete(&file_lifetime::lifetime_volume(volume), path, related)
}

/// NtDeleteFile/ZwDeleteFile.
pub fn remove(attributes: u64) -> Result<u32, KernelError> {
    count_operation();
    if attributes == 0 {
        return Ok(0xC000_000D);
    }
    let mut captured_name = 0u64;
    let mut root_reference: Option<security_handles::Retained> = None;
    let result = (|| -> Result<u32, KernelError> {
        if protected::read32(attributes)? != 48 {
            return Ok(0xC000_000D);
        }
        let root = protected::read64(attributes + 8)?;
        let flags = protected::read32(attributes + 24)?;
        if flags & 0xFFFE_E00D != 0 {
            return Ok(0xC000_000D);
        }
        let descriptor = protected::read64(attributes + 16)?;
        let security = protected::read64(attributes + 32)?;
        let quality = protected::read64(attributes + 40)?;
        let (mut impersonation_level, mut tracking_mode) = (0, 0);
        if quality != 0 {
            // Length é lido, mas o OB usa o próprio tamanho 12.
            protected::read32(quality)?;
            impersonation_level = protected::read32(quality + 4)?;
            tracking_mode = protected::read32(quality + 8)? & 255;
        }
        if security != 0 {
            if let Err(status) = callback_security::capture(security) {
                return Ok(status);
            }
        }
        if quality != 0 && tracking_mode >= 2 {
            return Ok(0xC000_000D);
        }
        if quality != 0 && impersonation_level > 3 {
            return Ok(0xC000_00A5);
        }
        if descriptor == 0 {
            return Ok(if root != 0 { 0xC000_0033 } else { 0xC000_003B });
        }
        let length = protected::read32(descriptor)? & 0xFFFF;
        let buffer = protected::read64(descriptor + 8)?;
        if length & 1 != 0 || length == 0xFFFE {
            return Ok(0xC000_0033);
        }
        let mut units = Vec::new();
        if length != 0 {
            // MaximumLength não limita a captura; a alocação é da operação.
            captured_name = kernel_pool::allocate(0xF8.max(length as u64 + 2), AllocateOptions { paged: true, tag: 0x6D4E_624F, ..Default::default() }).unwrap_or(0);
            if captured_name == 0 {
                return Ok(0xC000_009A);
            }
            for offset in (0..length as u64).step_by(2) {
                let unit = protected::read16(buffer + offset)?;
                guest::write16(captured_name + offset, unit);
                units.push(unit);
            }
            guest::write16(captured_name + length as u64, 0);
        }
        let name = String::from_utf16_lossy(&units);
        let mut start = object_manager::ROOT;
        if root != 0 {
            let retained = match security_handles::reference_kernel_handle(root)? {
                Ok(retained) => retained,
                Err(status) => return Ok(status),
            };
            let (pointer, type_name) = (retained.pointer, retained.object_type.name.clone());
            root_reference = Some(retained);
            if type_name == object_types::file_type().name {
                let Some((volume, base)) = zw_files::file_backing(pointer) else { return Ok(0xC000_0010) };
                if name.starts_with('\\') {
                    return Ok(0xC000_000D);
                }
                if invalid_name(&name) {
                    return Ok(0xC000_0033);
                }
                if flags & 0x130 != 0 {
                    return Ok(0xC000_000D);
                }
                let mut path = String::from(base.trim_end_matches('/'));
                if !name.is_empty() {
                    path.push('/');
                    path.push_str(&name.replace('\\', "/"));
                }
                if path.is_empty() {
                    path.push('/');
                }
                return remove_from_volume(volume, &path, if name.is_empty() { pointer } else { 0 });
            }
            if name.starts_with('\\') {
                return Ok(0xC000_003B);
            }
            if type_name != "Directory" {
                return Ok(0xC000_0024);
            }
            match crate::ntos::ob::objects::namespace::get(pointer) {
                Some((node, _)) => start = node,
                None => return Ok(0xC000_0024),
            }
        } else if !name.starts_with('\\') {
            return Ok(0xC000_003B);
        }
        if invalid_name(&name) {
            return Ok(0xC000_0033);
        }
        if flags & 0x130 != 0 {
            return Ok(0xC000_000D);
        }
        if flags & 0x1000 != 0 && has_reparse(&name, flags & 0x40 != 0, start) {
            return Ok(0xC000_050B);
        }
        let (node, rest) = object_manager::resolve_from(&name, 0, flags & 0x40 != 0, false, start);
        let Some(node) = node.and_then(object_manager::node) else { return Ok(0xC000_003A) };
        let Some(volume) = node.mount else { return Ok(if node.type_name == "Device" { 0xC000_0010 } else { 0xC000_0024 }) };
        remove_from_volume(volume, &alloc::format!("/{}", rest.unwrap_or_default()), 0)
    })();
    if let Some(mut retained) = root_reference {
        retained.release()?;
    }
    if captured_name != 0 {
        let _ = kernel_pool::free(captured_name, None);
    }
    match result {
        Err(error) if error.status != 0xC000_0001 => Ok(error.status),
        other => other,
    }
}
