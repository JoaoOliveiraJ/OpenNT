//! IopMarkBootPartition e IopAssignBootDriveLetter (ntoskrnl 19041 0xa61890
//! e 0xa61aa8). O PnpBootDeviceWait (0x3b7d54) do fim do
//! IopInitializeBootDrivers (0xa5db88: lea 0xa5e088, call 0xa5e094), depois
//! do IopCallBootDriverReinitializationRoutines e antes do
//! PnPBootDriversInitialized, abre o dispositivo de boot com
//! FILE_READ_ATTRIBUTES (no NT o \ArcName\<ArcBootDeviceName>; no OpenNT o
//! \Device\BootDevice), liga DO_SYSTEM_BOOT_PARTITION no dispositivo do
//! FILE_OBJECT e na base da pilha (0xa619f5/0xa619f9) e manda
//! IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT, sem buffers (0xa61b1c). O mountmgr.sys
//! (MountMgrBootDriveLetterAssignment 0xe1c4), antes da
//! MountMgrDriverReinitialization, acha o volume de boot pelo
//! DO_SYSTEM_BOOT_PARTITION guardado na chegada (MountMgrFindBootVolume
//! 0xf390), dá a ele a letra do MountedDevices ou a primeira livre a partir
//! de C: (MountMgrNextDriveLetterWorker 0x10f20) e a grava no
//! KUSER_SHARED_DATA.NtSystemRoot[0] (0xe2f5).
//!
//! O volume de boot do kernel não tem PDO: chega ao mountmgr.sys pelo
//! `volume_device::announce_to_mount_manager` logo depois da marcação (no NT
//! a notificação de interface do PnP também chega depois dela). O 19041 não
//! tem IoAssignDriveLetters e só o mountmgr.sys cria letras de unidade: o
//! \GLOBAL??\C: que a fase 1 cria para o começo do boot é provisório, sai
//! antes da chegada (o mountmgr.sys cria o do banco ou dá C: pelo
//! BOOT_DL_ASSIGNMENT) e volta, com o mesmo nome global, se o mountmgr.sys
//! não o criar. Só no boot do smss, em que o C: é o volume do sistema.

use alloc::string::String;
use core::sync::atomic::Ordering;

use crate::drivers::fs::{ntfs, volume_device};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DeviceObject, FileObject, UnicodeString};
use crate::ntos::io::{parse, volume_dos_name};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

/// DEVICE_OBJECT.Flags: DO_SYSTEM_BOOT_PARTITION.
const DO_SYSTEM_BOOT_PARTITION: u32 = 0x100;
const IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT: u32 = 0x006D_C044;
const BOOT_DEVICE: &str = "\\Device\\BootDevice";
const MOUNT_MANAGER: &str = "\\Device\\MountPointManager";
/// O link do C: que a fase 1 cria no diretório global de devices DOS.
const PROVISIONAL_DRIVE: &str = "\\GLOBAL??\\C:";

/// IopMarkBootPartition: o ZwOpenFile(FILE_READ_ATTRIBUTES,
/// FILE_NON_DIRECTORY_FILE) do dispositivo de boot é a abertura direta do
/// volume; devolve o dispositivo marcado.
fn mark_boot_partition() -> Result<u64, KernelError> {
    let device = parse::kernel_volume_device(BOOT_DEVICE).ok_or_else(|| KernelError::new("\\Device\\BootDevice sem volume do kernel"))?;
    let request = parse::OpenRequest { desired_access: 0x80, file_attributes: 0, share_access: 0, disposition: 1, create_options: 0x40, case_insensitive: true, driver_context: Default::default() };
    let opened = parse::open_direct(device, &request)?;
    if opened.status & 0x8000_0000 != 0 || opened.file_object == 0 {
        return Err(KernelError::with_status("abertura direta do dispositivo de boot", opened.status));
    }
    // SAFETY: o FILE_OBJECT vivo da abertura direta.
    let named = unsafe { FileObject::at(opened.file_object) }.device_object.get();
    for target in [named, device_objects::base(named)] {
        // SAFETY: DEVICE_OBJECTs vivos (o do nome e a base da pilha dele).
        unsafe { DeviceObject::at(target) }.flags.atomic().fetch_or(DO_SYSTEM_BOOT_PARTITION, Ordering::SeqCst);
    }
    // ZwClose e ObDereferenceObject: CLEANUP e CLOSE ao dispositivo.
    file_objects::open_handle(opened.file_object)?;
    file_objects::close_handle(opened.file_object)?;
    file_objects::dereference(opened.file_object)?;
    Ok(named)
}

/// O nome DOS que o mountmgr.sys dá ao volume (IoVolumeDeviceToDosName);
/// `None` quando ele não tem nome DOS.
fn dos_name(device: u64) -> Option<String> {
    let unicode = guest::alloc_bytes(UnicodeString::SIZE);
    if unicode == 0 {
        return None;
    }
    let name = match volume_dos_name::volume_device_to_dos_name(device, unicode) {
        Ok(0) => {
            let text = guest_strings::read_unicode_string(unicode);
            // SAFETY: a UNICODE_STRING que o IoVolumeDeviceToDosName preencheu.
            let buffer = unsafe { UnicodeString::at(unicode) }.buffer.get();
            // O pool do nome é do chamador (ExFreePool).
            if buffer != 0 {
                let _ = kernel_pool::free(buffer, None);
            }
            Some(text)
        }
        _ => None,
    };
    guest::free_bytes(unicode);
    name
}

/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
/// O volume do sistema no `--volume-sistema=ntfs.sys`: a partição do
/// segundo disco IDE (\Device\Harddisk1) que começa no LBA 2048.
const SYSTEM_DISK: u32 = 1;
const SYSTEM_PARTITION_OFFSET: u64 = 2048 * 512;

/// VOLUME_DISK_EXTENTS (ntddvol.h) com a primeira DISK_EXTENT.
#[repr(C)]
struct VolumeDiskExtents {
    number_of_disk_extents: Field<u32>,
    _reserved: Field<u32>,
    disk_number: Field<u32>,
    _reserved2: Field<u32>,
    starting_offset: Field<u64>,
    _extent_length: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for VolumeDiskExtents {}

const _: () = {
    assert!(core::mem::size_of::<VolumeDiskExtents>() == 0x20);
    assert!(core::mem::offset_of!(VolumeDiskExtents, disk_number) == 0x8);
    assert!(core::mem::offset_of!(VolumeDiskExtents, starting_offset) == 0x10);
};

/// A primeira extensão do volume (DiskNumber e StartingOffset) pelo
/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
fn first_extent(device: u64) -> Option<(u32, u64)> {
    let block = guest::alloc_bytes(0x100);
    if block == 0 {
        return None;
    }
    let (output, scratch) = (block, block + 0x80);
    guest::write_bytes(output, &[0u8; VolumeDiskExtents::SIZE as usize]);
    let status = volume_dos_name::query_device(device, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0, 0, output, VolumeDiskExtents::SIZE as u32, scratch);
    // SAFETY: o VOLUME_DISK_EXTENTS de rascunho no início do bloco.
    let extents = unsafe { VolumeDiskExtents::at(output) };
    let extent = (status & 0x8000_0000 == 0 && extents.number_of_disk_extents.get() >= 1).then(|| (extents.disk_number.get(), extents.starting_offset.get()));
    guest::free_bytes(block);
    extent
}

/// O IopMarkBootPartition de um volume da pilha real: a abertura com
/// FILE_READ_ATTRIBUTES (o IoGetDeviceObjectPointer, que monta o file
/// system no volume) e DO_SYSTEM_BOOT_PARTITION no dispositivo do
/// FILE_OBJECT, na base da pilha dele, no dispositivo relacionado (o volume
/// do file system montado) e na base deste, que é o que o
/// QueryDeviceInformation do mountmgr.sys lê (o IoGetDeviceAttachmentBaseRef
/// do dispositivo da abertura dele).
fn mark_opened_volume(path: &str) -> Result<(), KernelError> {
    let units = path.encode_utf16().count() as u64;
    let block = guest::alloc_bytes(0x40 + units * 2 + 2);
    if block == 0 {
        return Err(KernelError::with_status("sem memoria", 0xC000_009A));
    }
    let (unicode, outputs, text) = (block, block + 0x20, block + 0x40);
    guest_strings::write_wide_string(text, path);
    // SAFETY: a UNICODE_STRING de rascunho no início do bloco.
    let name = unsafe { UnicodeString::at(unicode) };
    name.length.set(units as u16 * 2);
    name.maximum_length.set(units as u16 * 2 + 2);
    name.buffer.set(text);
    let result = match crate::ntos::io::device::get_device_object_pointer(unicode, 0x80, outputs, outputs + 8) {
        Ok(0) => {
            // SAFETY: as duas saídas (PFILE_OBJECT e PDEVICE_OBJECT) do bloco.
            let (file, related) = unsafe { (Field::<u64>::at(outputs).get(), Field::<u64>::at(outputs + 8).get()) };
            // SAFETY: o FILE_OBJECT referenciado pela abertura.
            let named = unsafe { FileObject::at(file) }.device_object.get();
            for target in [named, device_objects::base(named), related, device_objects::base(related)] {
                if target != 0 {
                    // SAFETY: DEVICE_OBJECTs vivos da abertura.
                    unsafe { DeviceObject::at(target) }.flags.atomic().fetch_or(DO_SYSTEM_BOOT_PARTITION, Ordering::SeqCst);
                }
            }
            file_objects::dereference(file).map(|_| ())
        }
        Ok(status) => Err(KernelError::with_status("abertura do volume", status)),
        Err(error) => Err(error),
    };
    guest::free_bytes(block);
    result
}

/// `--volume-sistema=ntfs.sys`: o PnpBootDeviceWait do volume de boot da
/// pilha real, depois da árvore dos drivers de boot. As chegadas das
/// interfaces de volume ficaram retidas (`pnp_notify`, o papel da fila de
/// eventos do PnP do NT); o IopMarkBootPartition abre e marca o volume cuja
/// primeira extensão é a partição de boot, as chegadas vão ao mountmgr.sys
/// já com a marca, e o IopAssignBootDriveLetter pede a letra.
pub fn system_volume_boot_device_wait() {
    let mut boot = None;
    for number in 1..=8 {
        let path = alloc::format!("\\Device\\HarddiskVolume{number}");
        let Some(device) = object_manager::lookup(&path).and_then(crate::ntos::io::io_manager::device).map(|entry| entry.native_device).filter(|&device| device != 0) else { continue };
        match first_extent(device) {
            Some((SYSTEM_DISK, SYSTEM_PARTITION_OFFSET)) if boot.is_none() => match mark_opened_volume(&path) {
                Ok(()) => {
                    debug_print!("[mountmgr] {}: volume da particao de boot (disco {}, deslocamento {:#x}) marcado DO_SYSTEM_BOOT_PARTITION", path, SYSTEM_DISK, SYSTEM_PARTITION_OFFSET);
                    boot = Some(path);
                }
                Err(error) => debug_print!("[mountmgr] FALHOU IopMarkBootPartition de {}: {}", path, error),
            },
            Some((disk, offset)) => debug_print!("[mountmgr] {}: volume do disco {} em {:#x}", path, disk, offset),
            None => debug_print!("[mountmgr] {}: extensoes do volume indisponiveis", path),
        }
    }
    crate::ntos::io::pnp_notify::release_volume_interface_changes();
    match boot {
        Some(path) => {
            let _ = assign_system_volume_letter(&path);
        }
        None => debug_print!("[mountmgr] FALHOU nenhum volume na particao de boot do disco {}", SYSTEM_DISK),
    }
}

/// `--volume-sistema=ntfs.sys`: o IopAssignBootDriveLetter do volume de
/// boot da pilha real (marcado em [`system_volume_boot_device_wait`]): o
/// IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT, com que o mountmgr.sys dá ao volume a
/// letra do MountedDevices ou a primeira livre a partir de C: e a grava no
/// NtSystemRoot. Devolve o nome DOS que o volume ficou.
pub fn assign_system_volume_letter(device_path: &str) -> Option<String> {
    let device = object_manager::lookup(device_path).and_then(crate::ntos::io::io_manager::device).map(|entry| entry.native_device).filter(|&device| device != 0)?;
    // Sem a marca o mountmgr.sys espera para sempre o volume de boot.
    // SAFETY: o DEVICE_OBJECT vivo do volume.
    if unsafe { DeviceObject::at(device) }.flags.get() & DO_SYSTEM_BOOT_PARTITION == 0 {
        debug_print!("[mountmgr] {} sem DO_SYSTEM_BOOT_PARTITION: sem BOOT_DL", device_path);
        return None;
    }
    // O C: provisório da fase 1 (o volume do kernel) sai antes, como no
    // boot do volume do kernel.
    if object_manager::lookup(PROVISIONAL_DRIVE).is_some() {
        object_manager::unlink(PROVISIONAL_DRIVE);
    }
    let assignment = volume_dos_name::mount_manager_control(IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT, &[]);
    let dos = dos_name(device);
    let root = crate::ntos::mm::shared_user_data::data().and_then(|data| char::from_u32(u32::from(data.nt_system_root[0].get()))).unwrap_or('?');
    debug_print!("[mountmgr] {} do volume do sistema: BOOT_DL {:x?}, nome DOS {:?}, NtSystemRoot {}", device_path, assignment, dos, root);
    dos
}

/// O PnpBootDeviceWait com o IopMarkBootPartition do volume de boot do
/// kernel: marca, entrega ao mountmgr.sys e pede a letra. Com
/// `--volume-sistema=ntfs.sys` o volume de boot é o da pilha real
/// ([`system_volume_boot_device_wait`]).
pub fn boot_device_wait() {
    if !crate::ntos::init::boot_config::smss_boot() || crate::ntos::init::boot_config::system_volume_ntfs() {
        return;
    }
    if object_manager::lookup(MOUNT_MANAGER).is_none() {
        debug_print!("[mountmgr] {} ausente: o C: provisorio fica", MOUNT_MANAGER);
        return;
    }
    // A marcação vem antes da chegada: o QueryDeviceInformation do
    // mountmgr.sys guarda os Flags da base (0x15888), e sem
    // DO_SYSTEM_BOOT_PARTITION o BOOT_DL espera para sempre o volume de boot.
    let real = match mark_boot_partition() {
        Ok(real) => real,
        Err(error) => {
            debug_print!("[mountmgr] FALHOU IopMarkBootPartition: {}", error);
            return;
        }
    };
    let device_path = volume_device::device_path(ntfs::DEVICE_INDEX);
    let boot_node = object_manager::lookup(&device_path);
    let provisional = boot_node.is_some() && object_manager::lookup(PROVISIONAL_DRIVE) == boot_node;
    if provisional {
        object_manager::unlink(PROVISIONAL_DRIVE);
    }
    let arrival = volume_device::announce_to_mount_manager(ntfs::DEVICE_INDEX);
    let assignment = volume_dos_name::mount_manager_control(IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT, &[]);
    let dos = dos_name(real);
    let root = crate::ntos::mm::shared_user_data::data().and_then(|data| char::from_u32(u32::from(data.nt_system_root[0].get()))).unwrap_or('?');
    if dos.as_deref() == Some("C:") && object_manager::lookup(PROVISIONAL_DRIVE) == boot_node {
        debug_print!("MOUNTMGR_BOOT_VOLUME_OK {} -> C: (chegada {:x?}, BOOT_DL {:x?}, NtSystemRoot {})", device_path, arrival, assignment, root);
    } else {
        debug_print!("[mountmgr] FALHOU letra do volume de boot: {:?} (chegada {:x?}, BOOT_DL {:x?})", dos, arrival, assignment);
        // O C: provisório volta com o mesmo nome global: com o \?? por
        // sessão de logon, o \DosDevices é o mapa de quem chama.
        if provisional && object_manager::lookup(PROVISIONAL_DRIVE).is_none() {
            let _ = object_manager::create_symlink(PROVISIONAL_DRIVE, &device_path);
        }
    }
}
