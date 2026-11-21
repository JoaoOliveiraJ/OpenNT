//! O volume do sistema servido pela pilha de armazenamento real e pelo
//! ntfs.sys (`--volume-sistema=ntfs.sys`, marco S0 do plano em
//! `docs/ARQUITETURA.md` §3.5), depois do STORAGE_REAL_OK:
//!
//! - antes da árvore, o NTFS do kernel (no papel do winload) lê o começo de
//!   arquivos do `\Windows\System32` da partição ([`capture_reference`]);
//! - o volume da partição de boot (o `\Device\HarddiskVolumeN` que o
//!   PnpBootDeviceWait do boot marcou DO_SYSTEM_BOOT_PARTITION,
//!   `io/boot_partition.rs`) recebeu o C: do mountmgr.sys pelo
//!   IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT: o `\GLOBAL??\C:` leva a ele e o
//!   NtSystemRoot do KUSER_SHARED_DATA está com o C:;
//! - os mesmos arquivos abertos por `\??\C:\Windows\System32` (o
//!   IopParseDevice monta o ntfs.sys no volume) e lidos pelo cache dele têm
//!   os bytes que o NTFS do kernel leu, e o volume responde como NTFS ao
//!   FileFsAttributeInformation.
//!
//! A serial mostra `[system-volume]` em cada passo e `SYSTEM_VOLUME_NTFS_OK`
//! no fim.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DeviceObject, IoStatusBlock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::test::file_system_mount::object_attributes;
use crate::ntos::test::phase6::call_export;
use crate::rtl::SpinLock;

/// Os arquivos conferidos (de System32) e quanto de cada um.
const FILES: [&str; 2] = ["ntdll.dll", "drivers/fltmgr.sys"];
const LENGTH: u64 = 0x10000;
/// DEVICE_OBJECT.Flags: DO_SYSTEM_BOOT_PARTITION.
const DO_SYSTEM_BOOT_PARTITION: u32 = 0x100;
const FILE_GENERIC_READ: u64 = 0x0012_0089;
const FILE_SHARE_ALL: u64 = 7;
const FILE_OPEN: u64 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const FILE_FS_ATTRIBUTE_INFORMATION: u64 = 5;

/// FILE_FS_ATTRIBUTE_INFORMATION (ntifs.h) até o começo do FileSystemName.
#[repr(C)]
struct FileFsAttributeInformation {
    _file_system_attributes: Field<u32>,
    _maximum_component_name_length: Field<i32>,
    file_system_name_length: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for FileFsAttributeInformation {}

const _: () = assert!(core::mem::size_of::<FileFsAttributeInformation>() == 0xC);

/// O começo dos arquivos lido pelo NTFS do kernel antes da árvore.
static REFERENCE: SpinLock<Vec<(&'static str, Vec<u8>)>> = SpinLock::new(Vec::new());

/// O começo dos arquivos pelo NTFS do kernel, antes de a pilha real assumir
/// a controladora.
pub fn capture_reference() {
    let Some(volume) = crate::drivers::fs::ntfs::fixed() else { return };
    let files: Vec<(&'static str, Vec<u8>)> = FILES
        .iter()
        .filter_map(|&name| match volume.read_range(&format!("/Windows/System32/{name}"), 0, LENGTH) {
            Ok(Some(bytes)) => Some((name, bytes)),
            Ok(None) => {
                debug_print!("[system-volume] {} ausente no NTFS do kernel", name);
                None
            }
            Err(error) => {
                debug_print!("[system-volume] {} nao lido pelo NTFS do kernel: {}", name, error);
                None
            }
        })
        .collect();
    *REFERENCE.lock() = files;
}

/// Depois do PnpBootDeviceWait do volume do sistema: o resultado na serial.
pub fn check() {
    let reference = core::mem::take(&mut *REFERENCE.lock());
    match run(&reference) {
        Ok(()) => debug_print!("SYSTEM_VOLUME_NTFS_OK"),
        Err(error) => debug_print!("[system-volume] {}", error),
    }
}

/// O volume da partição de boot: o `\Device\HarddiskVolumeN` marcado.
fn boot_volume() -> Option<String> {
    (1..=8).map(|number| format!("\\Device\\HarddiskVolume{number}")).find(|path| {
        object_manager::lookup(path).and_then(crate::ntos::io::io_manager::device).is_some_and(|entry| {
            // SAFETY: o DEVICE_OBJECT vivo do volume.
            entry.native_device != 0 && unsafe { DeviceObject::at(entry.native_device) }.flags.get() & DO_SYSTEM_BOOT_PARTITION != 0
        })
    })
}

fn export(name: &str, arguments: &[u64]) -> u32 {
    call_export(name, arguments).unwrap_or(u64::MAX) as u32
}

/// O começo do arquivo de `\??\C:\Windows\System32` lido pelo ntfs.sys e o
/// nome do file system do volume.
fn read_through_ntfs(block: u64, buffer: u64, name: &str) -> Result<(Vec<u8>, String), String> {
    let path = format!("\\??\\C:\\Windows\\System32\\{}", name.replace('/', "\\"));
    let attributes = object_attributes(block, &path);
    let (handle, iosb, offset, information) = (block + 0x300, block + 0x310, block + 0x320, block + 0x400);
    let status = export("ZwCreateFile", &[handle, FILE_GENERIC_READ, attributes, iosb, 0, 0x80, FILE_SHARE_ALL, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0]);
    if status != 0 {
        return Err(format!("ZwCreateFile({path}) devolveu {status:#x}"));
    }
    // SAFETY: o HANDLE, o LARGE_INTEGER do deslocamento e o IO_STATUS_BLOCK
    // de rascunho no bloco do teste.
    let (file, status_block) = unsafe { (Field::<u64>::at(handle).get(), IoStatusBlock::at(iosb)) };
    // SAFETY: idem.
    unsafe { Field::<u64>::at(offset) }.set(0);
    let read = export("ZwReadFile", &[file, 0, 0, 0, iosb, buffer, LENGTH, offset, 0]);
    let count = status_block.information.get();
    let bytes = guest::read_bytes(buffer, count.min(LENGTH) as usize);
    let queried = export("ZwQueryVolumeInformationFile", &[file, iosb, information, 0x100, FILE_FS_ATTRIBUTE_INFORMATION]);
    let file_system = if queried == 0 {
        // SAFETY: o FILE_FS_ATTRIBUTE_INFORMATION devolvido no bloco.
        let length = unsafe { FileFsAttributeInformation::at(information) }.file_system_name_length.get().min(0xF0) as usize;
        let units: Vec<u16> = guest::read_bytes(information + FileFsAttributeInformation::SIZE, length).chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
        String::from_utf16_lossy(&units)
    } else {
        format!("(consulta {queried:#x})")
    };
    export("ZwClose", &[file]);
    if read != 0 {
        return Err(format!("ZwReadFile({path}) devolveu {read:#x}"));
    }
    Ok((bytes, file_system))
}

/// O volume da partição com o C:, servido pelo ntfs.sys, com os arquivos do
/// NTFS do kernel.
fn run(reference: &[(&'static str, Vec<u8>)]) -> Result<(), String> {
    if reference.len() != FILES.len() {
        return Err(String::from("os arquivos de referencia nao foram lidos antes da arvore"));
    }
    let volume = boot_volume().ok_or_else(|| String::from("nenhum volume da pilha real com DO_SYSTEM_BOOT_PARTITION"))?;
    let linked = object_manager::lookup("\\GLOBAL??\\C:").is_some_and(|link| object_manager::lookup(&volume) == Some(link));
    let root = crate::ntos::mm::shared_user_data::data().map(|data| data.nt_system_root[0].get()).unwrap_or(0);
    debug_print!("[system-volume] {}: \\GLOBAL??\\C: {}, NtSystemRoot[0] {:?}", volume, if linked { "leva ao volume" } else { "NAO leva ao volume" }, char::from_u32(u32::from(root)));
    if !linked || root != u16::from(b'C') {
        return Err(String::from("o volume da particao de boot nao recebeu o C:"));
    }
    // O setor de boot do volume lido pela pilha do volume (volume.sys,
    // volmgr, partmgr, disk e atapi), antes do ntfs.sys.
    let device = object_manager::lookup(&volume).and_then(crate::ntos::io::io_manager::device).map(|entry| entry.native_device).unwrap_or(0);
    match crate::drivers::storage::storage_stack::read_through_stack(device, 0, 1) {
        Ok(sector) if &sector[3..11] == b"NTFS    " => debug_print!("[system-volume] setor 0 de {} pela pilha do volume: OEM \"NTFS    \"", volume),
        Ok(sector) => return Err(format!("setor 0 de {volume} pela pilha do volume sem o OEM do NTFS: {:02x?}", &sector[3..11])),
        Err(error) => return Err(format!("setor 0 de {volume} pela pilha do volume: {error}")),
    }
    let block = guest::alloc_bytes(0x800);
    let buffer = guest::alloc_bytes(LENGTH);
    if block == 0 || buffer == 0 {
        return Err(String::from("sem memoria para o teste"));
    }
    let mut result = Ok(());
    for (name, expected) in reference {
        match read_through_ntfs(block, buffer, name) {
            Ok((bytes, file_system)) => {
                let same = bytes == *expected;
                debug_print!("[system-volume] C:\\Windows\\System32\\{}: {} bytes pelo {} {}", name.replace('/', "\\"), bytes.len(), file_system, if same { "iguais aos do NTFS do kernel" } else { "DIFERENTES" });
                if (!same || file_system != "NTFS") && result.is_ok() {
                    result = Err(format!("{name} pelo ntfs.sys difere do NTFS do kernel"));
                }
            }
            Err(error) => {
                if result.is_ok() {
                    result = Err(error);
                }
            }
        }
    }
    guest::free_bytes(block);
    guest::free_bytes(buffer);
    result
}
