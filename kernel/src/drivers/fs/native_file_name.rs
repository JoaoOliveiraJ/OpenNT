//! Nome nativo do arquivo de uma seção.
//!
//! Identifica o arquivo pelo volume que fornece seus bytes. O Object Manager
//! publica suas montagens aqui; o caminho é consultado no nó atual, então
//! desmontar ou renomear não conserva um caminho que identifique outro volume.

use alloc::string::String;
use alloc::vec::Vec;

use super::volume::{self, FileSystem};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::SpinLock;

struct MountedVolume {
    volume: &'static dyn FileSystem,
    node: NodeId,
}

static MOUNTED: SpinLock<Vec<MountedVolume>> = SpinLock::new(Vec::new());

/// O caminho atual da montagem, enquanto o nó ainda monta este volume.
fn current_path(mounted: &MountedVolume) -> Option<String> {
    let mount = object_manager::node(mounted.node)?.mount?;
    if !volume::same(mount, mounted.volume) {
        return None;
    }
    object_manager::path_of(mounted.node)
}

pub fn register_mount(volume: &'static dyn FileSystem, node: NodeId) {
    let mut mounted = MOUNTED.lock();
    mounted.retain(|entry| entry.node != node);
    mounted.push(MountedVolume { volume, node });
}

fn snapshot() -> Vec<MountedVolume> {
    MOUNTED.lock().iter().map(|entry| MountedVolume { volume: entry.volume, node: entry.node }).collect()
}

pub fn volume_at(mount_path: &str) -> Option<&'static dyn FileSystem> {
    snapshot().into_iter().find(|entry| current_path(entry).is_some_and(|path| path.eq_ignore_ascii_case(mount_path))).map(|entry| entry.volume)
}

/// Compõe o caminho no namespace a partir de uma montagem real do volume;
/// sem montagem não se inventa dispositivo nem letra DOS.
pub fn from_volume(volume: &'static dyn FileSystem, volume_path: &str) -> Option<String> {
    let relative: String = volume_path.replace('/', "\\");
    let relative = relative.trim_start_matches('\\');
    for entry in snapshot() {
        if !volume::same(entry.volume, volume) {
            continue;
        }
        if let Some(mount_path) = current_path(&entry) {
            return Some(alloc::format!("{}\\{}", mount_path.trim_end_matches('\\'), relative));
        }
    }
    None
}

/// Prioriza o backing (volume + caminho); fontes do boot já têm nome nativo
/// absoluto.
pub fn from_file(backing: Option<(&'static dyn FileSystem, &str)>, native_name: Option<&str>) -> Option<String> {
    if let Some((volume, path)) = backing {
        return from_volume(volume, path);
    }
    native_name.filter(|name| name.starts_with('\\')).map(String::from)
}
