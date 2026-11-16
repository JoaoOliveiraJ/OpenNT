//! ObQueryDeviceMapInformation: o DriveMap e o DriveType[32] do mapa de
//! devices DOS de um processo (a ProcessDeviceMap do
//! NtQueryInformationProcess; o GetLogicalDrives e o GetDriveType do
//! kernelbase, o smss e o csrss perguntam por ela).
//!
//! No NT o DEVICE_MAP do diretório DOS guarda as letras: o
//! ObpCreateSymbolicLinkName de um link `X:` nesse diretório liga o bit da
//! letra no DriveMap e grava o tipo da unidade pelo objeto final do destino.
//! O OpenNT tem um só diretório DOS (`\??` e `\DosDevices` são links para
//! `\GLOBAL??`, sem mapa por LUID), e o mapa é lido dele na consulta, com a
//! mesma regra de tipo:
//! - o destino não chega a um DEVICE_OBJECT: DOSDEVICE_DRIVE_CALCULATE (o
//!   kernelbase descobre o tipo abrindo a unidade);
//! - FILE_DEVICE_CD_ROM e o file system de CD-ROM (2, 3): CDROM;
//! - FILE_DEVICE_DISK, o file system de disco e FILE_DEVICE_FILE_SYSTEM
//!   (7 a 9): REMOVABLE com FILE_REMOVABLE_MEDIA nas Characteristics,
//!   senão FIXED;
//! - os devices de rede (0x10, 0x12 a 0x14, 0x28): REMOTE;
//! - FILE_DEVICE_VIRTUAL_DISK (0x24): RAMDISK;
//! - os demais: UNKNOWN.
//!
//! Flags só aceita PROCESS_LUID_DOSDEVICES_ONLY (outro bit dá
//! STATUS_INVALID_PARAMETER); sem mapa por LUID, ele não muda a resposta.

use alloc::string::String;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::DeviceObject;
use crate::ntos::ob::object_manager;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// PROCESS_LUID_DOSDEVICES_ONLY.
const LUID_DOSDEVICES_ONLY: u32 = 1;
/// DOSDEVICE_DRIVE_*.
pub const DRIVE_UNKNOWN: u8 = 0;
pub const DRIVE_CALCULATE: u8 = 1;
pub const DRIVE_REMOVABLE: u8 = 2;
pub const DRIVE_FIXED: u8 = 3;
pub const DRIVE_REMOTE: u8 = 4;
pub const DRIVE_CDROM: u8 = 5;
pub const DRIVE_RAMDISK: u8 = 6;
/// FILE_REMOVABLE_MEDIA.
const FILE_REMOVABLE_MEDIA: u32 = 1;
/// O diretório DOS global.
const DOS_DEVICES: &str = "\\GLOBAL??";

/// A parte de consulta do PROCESS_DEVICEMAP_INFORMATION.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceMapInformation {
    pub drive_map: u32,
    pub drive_type: [u8; 32],
}

/// O tipo de unidade pelo DeviceType e pelas Characteristics do
/// DEVICE_OBJECT final do destino.
pub fn drive_type_of(device_type: u32, characteristics: u32) -> u8 {
    match device_type {
        2 | 3 => DRIVE_CDROM,
        7..=9 => {
            if characteristics & FILE_REMOVABLE_MEDIA != 0 {
                DRIVE_REMOVABLE
            } else {
                DRIVE_FIXED
            }
        }
        0x10 | 0x12..=0x14 | 0x28 => DRIVE_REMOTE,
        0x24 => DRIVE_RAMDISK,
        _ => DRIVE_UNKNOWN,
    }
}

/// A letra de um nome `X:` (A a Z, sem distinção de caixa).
fn drive_letter(name: &str) -> Option<u32> {
    let mut characters = name.chars();
    let (Some(letter), Some(':'), None) = (characters.next(), characters.next(), characters.next()) else { return None };
    let letter = letter.to_ascii_uppercase();
    letter.is_ascii_uppercase().then(|| letter as u32 - 'A' as u32)
}

/// O tipo de unidade de um link: o objeto final do destino.
fn link_drive_type(link_path: &str) -> u8 {
    let (found, rest) = object_manager::resolve(link_path);
    if rest.is_some_and(|rest| !rest.is_empty()) {
        return DRIVE_CALCULATE;
    }
    let Some(node) = found.and_then(object_manager::node) else { return DRIVE_CALCULATE };
    let pointer = node.data.as_ref().map_or(0, |data| data.native_pointer);
    if node.type_name != "Device" || pointer == 0 {
        return DRIVE_CALCULATE;
    }
    // SAFETY: o DEVICE_OBJECT publicado pelo nó do dispositivo.
    let device = unsafe { DeviceObject::at(pointer) };
    drive_type_of(device.device_type.get(), device.characteristics.get())
}

/// ObQueryDeviceMapInformation(Process, DeviceMapInformation, Flags).
pub fn query(flags: u32) -> Result<DeviceMapInformation, u32> {
    if flags & !LUID_DOSDEVICES_ONLY != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let mut information = DeviceMapInformation::default();
    let Some(directory) = object_manager::lookup(DOS_DEVICES).and_then(object_manager::node) else { return Ok(information) };
    for (name, child) in directory.children.unwrap_or_default() {
        let Some(index) = drive_letter(&name) else { continue };
        if object_manager::node(child).is_none_or(|node| node.type_name != "SymbolicLink") {
            continue;
        }
        let path: String = alloc::format!("{DOS_DEVICES}\\{name}");
        information.drive_map |= 1 << index;
        information.drive_type[index as usize] = link_drive_type(&path);
    }
    Ok(information)
}
