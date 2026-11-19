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
use crate::ntos::inc::field::NtStruct;
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

/// O PnpBootDeviceWait com o IopMarkBootPartition do volume de boot do
/// kernel: marca, entrega ao mountmgr.sys e pede a letra.
pub fn boot_device_wait() {
    if !crate::ntos::init::boot_config::smss_boot() {
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
