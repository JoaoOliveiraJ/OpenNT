//! Os volumes do próprio kernel como dispositivos do I/O Manager.
//!
//! Como no NT, um volume é alcançado pelo seu dispositivo e por links
//! simbólicos, não por um nome na raiz do namespace: cada volume do kernel
//! (o disco em memória e o leitor NTFS do segundo disco IDE) ganha um
//! DEVICE_OBJECT nativo `\Device\KernelVolumeN` (FILE_DEVICE_DISK, com o VPB
//! do IopCreateVpb e o DeviceLock sinalizado), montado pelo file system
//! embutido do kernel: o VPB fica VPB_MOUNTED, com DeviceObject = o
//! dispositivo de volume do file system (FILE_DEVICE_DISK_FILE_SYSTEM, sem
//! nome, do DRIVER_OBJECT `\FileSystem\KernelVolume`), o número de série e o
//! rótulo do volume. `\SystemRoot`, `\??\C:` e `\??\D:` são links para esses
//! dispositivos; o nó do dispositivo entrega o resto do caminho ao volume
//! (`object_manager::mount_device`).
//!
//! Um FILE_OBJECT aberto num desses volumes nasce como o do IopParseDevice
//! ([`bind_file`]): DeviceObject = o dispositivo real, Vpb = o VPB (com uma
//! referência até a destruição) e FileName = o caminho no volume. O
//! IoGetBaseFileSystemDeviceObject e o IoGetRelatedDeviceObject desses
//! arquivos dão o dispositivo de volume. O file system embutido não tem
//! pilha de IRP para os arquivos: o I/O Manager responde no lugar as
//! operações deles (`io/file/information.rs::related_device` não acha
//! dispositivo de despacho). As exceções:
//! - a E/S de paginação dos arquivos de paginação
//!   (MmIsFileObjectAPagingFile): o IoPageRead e o IoSynchronousPageWrite do
//!   Mm chegam aqui como IRP_MJ_READ/WRITE com IRP_PAGING_IO e um MDL de
//!   páginas inteiras, e vão direto às runs do arquivo
//!   (`FileSystem::paging_read`/`paging_write`);
//! - o IRP_MJ_LOCK_CONTROL do NtLockFile/NtUnlockFile ([`serves`],
//!   `io/file/information.rs::request_device`), que vai às travas do stream
//!   (`volume_streams::lock_control`, o NtfsCommonLockControl), e o
//!   IRP_MJ_DIRECTORY_CONTROL do NtNotifyChangeDirectoryFile(Ex), que vai à
//!   lista de notificação do diretório (`volume_streams::notify_change_directory`).
//!
//! O volume inteiro, aberto pelo nome do volume sem nome restante (`\??\C:`,
//! o `\\.\C:` do Win32), chega por IRP, como no NT (`io/parse.rs`):
//! - a abertura direta (só FILE_READ_ATTRIBUTES, READ_CONTROL, WRITE_DAC,
//!   WRITE_OWNER, SYNCHRONIZE e ACCESS_SYSTEM_SECURITY; FO_DIRECT_DEVICE_OPEN)
//!   vai ao dispositivo real, que faz o papel do dispositivo de volume do
//!   gerenciador de volumes: aceita o IRP_MJ_CREATE sem nome, o
//!   CLEANUP/CLOSE, e responde os IOCTLs de volume e de armazenamento do
//!   disco que guarda o volume ([`volume_control`]); o resto é
//!   STATUS_INVALID_DEVICE_REQUEST;
//! - a abertura do volume pelo file system (mais acesso que o da direta;
//!   FO_VOLUME_OPEN, com o VPB) vai ao dispositivo de volume do file system,
//!   que a trata como a abertura de volume de um file system do NT:
//!   FILE_DIRECTORY_FILE dá STATUS_NOT_A_DIRECTORY, disposição diferente de
//!   FILE_OPEN/FILE_OPEN_IF dá STATUS_ACCESS_DENIED, FILE_DELETE_ON_CLOSE dá
//!   STATUS_CANNOT_DELETE, um compartilhamento sem FILE_SHARE_WRITE e sem
//!   FILE_SHARE_DELETE pede a trava do volume, que um volume do kernel nunca
//!   concede (o sistema mantém arquivos abertos nele) e dá
//!   STATUS_SHARING_VIOLATION, e o compartilhamento entre as aberturas do
//!   volume é o do IoCheckShareAccess sobre o SHARE_ACCESS do volume. Num
//!   handle desses o IRP_MJ_QUERY_VOLUME_INFORMATION responde pelo volume,
//!   os IOCTLs seguem ao dispositivo real (o file system os passa ao
//!   dispositivo alvo) e os FSCTLs de usuário vão ao file system
//!   (`FileSystem::control` na raiz: FSCTL_IS_VOLUME_MOUNTED,
//!   FSCTL_GET_NTFS_VOLUME_DATA...); FSCTL_LOCK_VOLUME e
//!   FSCTL_DISMOUNT_VOLUME dão STATUS_ACCESS_DENIED (volume de boot e de
//!   paginação, com arquivos abertos) e FSCTL_UNLOCK_VOLUME dá
//!   STATUS_NOT_LOCKED.
//!
//! O dispositivo real responde também a interface MOUNTDEV do volume, como
//! o volmgr.sys de um volume básico ([`mount_control`]): o nome do
//! dispositivo, o identificador único ("DMIO:ID:" e o GUID estável do
//! volume), o GUID estável, nenhuma letra sugerida, LINK_CREATED/DELETED e
//! VOLUME_ONLINE. Sem PDO nem gerenciador de volumes, o volume chega ao
//! mountmgr.sys real pelo IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION
//! ([`announce_to_mount_manager`], no boot do smss por
//! `io/boot_partition.rs`), e o mountmgr.sys dá a ele o nome
//! `\??\Volume{...}` e a letra.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use super::volume::{self, DiskExtent, FileSystem};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_fs_fat::{MountdevName, MountdevUniqueId};
use crate::ntos::inc::types::extra_fs_ntfs::ShareAccess;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, FileObject, IoSecurityContext, IoStackLocation, Irp, Mdl, Vpb};
use crate::ntos::io::{file_system, io_manager, share_access};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::{KernelError, SpinLock};

const IO_TYPE_DEVICE: i16 = 3;
const IO_TYPE_DRIVER: i16 = 4;
const FILE_DEVICE_DISK: u32 = 0x07;
const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 0x08;
const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_NOT_LOCKED: u32 = 0xC000_002A;
const STATUS_SHARING_VIOLATION: u32 = 0xC000_0043;
const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
const STATUS_CANNOT_DELETE: u32 = 0xC000_0121;
const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_WRITE: u8 = 4;
const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0A;
const IRP_MJ_SET_VOLUME_INFORMATION: u8 = 0x0B;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_LOCK_CONTROL: u8 = 0x11;
const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0C;
/// IRP_MN_NOTIFY_CHANGE_DIRECTORY e IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX.
const IRP_MN_NOTIFY_CHANGE_DIRECTORY: u8 = 0x02;
const IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX: u8 = 0x03;
const IRP_MJ_CLEANUP: u8 = 0x12;
/// IRP_MN_USER_FS_REQUEST e IRP_MN_KERNEL_CALL do IRP_MJ_FILE_SYSTEM_CONTROL.
const IRP_MN_USER_FS_REQUEST: u8 = 0x00;
const IRP_MN_KERNEL_CALL: u8 = 0x04;
/// IRP.Flags: IRP_PAGING_IO.
const IRP_PAGING_IO: u32 = 0x02;
/// FILE_OBJECT.Flags: FO_VOLUME_OPEN.
const FO_VOLUME_OPEN: u32 = 0x40_0000;
/// Opções e disposições de criação (wdm.h) e o Information FILE_OPENED.
const FILE_DIRECTORY_FILE: u32 = 0x01;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
const FILE_OPENED: u64 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const FILE_SHARE_DELETE: u32 = 4;
const METHOD_BUFFERED: u32 = 0;
/// FSCTLs que o file system trata pelo estado do volume.
const FSCTL_LOCK_VOLUME: u32 = 0x0009_0018;
const FSCTL_UNLOCK_VOLUME: u32 = 0x0009_001C;
const FSCTL_DISMOUNT_VOLUME: u32 = 0x0009_0020;
/// IOCTLs de volume e de armazenamento que o dispositivo real responde.
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x0007_0024;
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
/// IOCTLs do mount manager (mountdev.h) e de volume (ntddvol.h) que o
/// mountmgr.sys manda ao volume.
const IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: u32 = 0x004D_0000;
const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME: u32 = 0x004D_000C;
const IOCTL_MOUNTDEV_LINK_CREATED_LEGACY: u32 = 0x004D_0010;
const IOCTL_MOUNTDEV_LINK_DELETED_LEGACY: u32 = 0x004D_0014;
const IOCTL_MOUNTDEV_QUERY_STABLE_GUID: u32 = 0x004D_0018;
const IOCTL_MOUNTDEV_LINK_CREATED: u32 = 0x004D_C010;
const IOCTL_MOUNTDEV_LINK_DELETED: u32 = 0x004D_C014;
const IOCTL_VOLUME_GET_GPT_ATTRIBUTES: u32 = 0x0056_0038;
const IOCTL_VOLUME_ONLINE: u32 = 0x0056_C008;
const IOCTL_VOLUME_POST_ONLINE: u32 = 0x0056_C064;
/// IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION (mountmgr.h).
const IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION: u32 = 0x006D_402C;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
/// STORAGE_PROPERTY_ID e STORAGE_QUERY_TYPE (ntddstor.h).
const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
const STORAGE_DEVICE_TRIM_PROPERTY: u32 = 8;
const PROPERTY_EXISTS_QUERY: u32 = 1;
const SECTOR: u32 = 512;
const PAGE: u64 = 0x1000;
/// Nome do DRIVER_OBJECT do file system embutido.
const DRIVER_NAME: &str = "\\FileSystem\\KernelVolume";

/// Um volume do kernel montado no seu dispositivo.
#[derive(Clone, Copy)]
struct KernelVolume {
    file_system: &'static dyn FileSystem,
    index: u32,
    /// O DEVICE_OBJECT real (`\Device\KernelVolumeN`).
    real: u64,
    /// O dispositivo de volume do file system embutido.
    volume: u64,
    vpb: u64,
    /// O SHARE_ACCESS das aberturas do volume pelo file system.
    share: u64,
}

// SAFETY: os volumes são estáticos e os endereços são de objetos permanentes.
unsafe impl Send for KernelVolume {}

static VOLUMES: SpinLock<Vec<KernelVolume>> = SpinLock::new(Vec::new());
static DRIVER: SpinLock<u64> = SpinLock::new(0);
/// O lock do SHARE_ACCESS dos volumes (o do VCB no file system do NT).
static SHARE_LOCK: SpinLock<()> = SpinLock::new(());
/// IOCTLs sem resposta já registrados na serial.
static UNKNOWN_CONTROLS: SpinLock<BTreeSet<u32>> = SpinLock::new(BTreeSet::new());

fn device_at(address: u64) -> &'static DeviceObject {
    // SAFETY: DEVICE_OBJECTs permanentes criados por este módulo.
    unsafe { DeviceObject::at(address) }
}

/// Caminho NT do dispositivo do volume de índice `index`.
pub fn device_path(index: u32) -> String {
    alloc::format!("\\Device\\KernelVolume{index}")
}

/// O DRIVER_OBJECT do file system embutido: todas as rotinas IRP_MJ_*
/// apontam para [`dispatch`].
fn driver_object() -> Result<u64, KernelError> {
    let mut driver = DRIVER.lock();
    if *driver != 0 {
        return Ok(*driver);
    }
    let name: Vec<u16> = DRIVER_NAME.encode_utf16().collect();
    let block = guest::alloc_bytes(DriverObject::SIZE + DriverExtension::SIZE + (name.len() as u64 + 1) * 2);
    if block == 0 {
        return Err(KernelError::new("volume do kernel: DRIVER_OBJECT sem memoria"));
    }
    let entry: extern "win64" fn(u64, u64) -> i32 = dispatch;
    let routine = crate::ntos::mm::kernel_address::image_address(entry as usize as u64)?;
    // SAFETY: bloco recém-alocado: o DRIVER_OBJECT, a extensão e o nome.
    let (object, extension) = unsafe { (DriverObject::at(block), DriverExtension::at(block + DriverObject::SIZE)) };
    object.type_.set(IO_TYPE_DRIVER);
    object.size.set(DriverObject::SIZE as i16);
    object.driver_extension.set(extension.address());
    extension.driver_object.set(block);
    let text = block + DriverObject::SIZE + DriverExtension::SIZE;
    guest::write_bytes(text, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    object.driver_name.length.set(name.len() as u16 * 2);
    object.driver_name.maximum_length.set(name.len() as u16 * 2 + 2);
    object.driver_name.buffer.set(text);
    for routine_cell in &object.major_function {
        routine_cell.set(routine);
    }
    *driver = block;
    Ok(block)
}

/// Um DEVICE_OBJECT do volume (o real ou o do file system), registrado com a
/// DEVOBJ_EXTENSION.
fn new_device(device_type: u32, driver: u64) -> Result<u64, KernelError> {
    let address = guest::alloc_bytes(DeviceObject::SIZE);
    if address == 0 {
        return Err(KernelError::new("volume do kernel: DEVICE_OBJECT sem memoria"));
    }
    let object = device_at(address);
    object.type_.set(IO_TYPE_DEVICE);
    object.size.set(DeviceObject::SIZE as u16);
    object.reference_count.set(1);
    object.device_type.set(device_type);
    object.stack_size.set(1);
    object.sector_size.set(512);
    object.driver_object.set(driver);
    dispatcher::initialize_event(object.device_lock.address(), 1, true);
    device_objects::register(address, None, None)?;
    // SAFETY: o DRIVER_OBJECT permanente do file system embutido.
    let driver_object = unsafe { DriverObject::at(driver) };
    object.next_device.set(driver_object.device_object.get());
    driver_object.device_object.set(address);
    Ok(address)
}

/// Monta `file_system` no dispositivo `\Device\KernelVolume<index>` e
/// devolve o caminho do dispositivo.
pub fn mount(index: u32, file_system: &'static dyn FileSystem) -> Result<String, KernelError> {
    let driver = driver_object()?;
    let real = new_device(FILE_DEVICE_DISK, driver)?;
    let volume_device = new_device(FILE_DEVICE_DISK_FILE_SYSTEM, driver)?;
    if file_system::create_vpb(device_at(real))? != STATUS_SUCCESS {
        return Err(KernelError::new("volume do kernel: VPB sem memoria"));
    }
    let vpb_address = device_at(real).vpb.get();
    // SAFETY: o VPB que o IopCreateVpb acabou de ligar ao dispositivo real.
    let vpb = unsafe { Vpb::at(vpb_address) };
    if let Some(Ok(information)) = file_system.volume_query().map(|query| query.volume_information()) {
        vpb.serial_number.set(information.serial);
        let label: Vec<u16> = information.label.encode_utf16().take(vpb.volume_label.len()).collect();
        for (cell, unit) in vpb.volume_label.iter().zip(label.iter()) {
            cell.set(*unit);
        }
        vpb.volume_label_length.set(label.len() as u16 * 2);
    }
    // O mount do file system embutido: o VPB aponta o dispositivo de volume
    // e o IopMountInitializeVpb o marca montado (StackSize do volume, VPB na
    // DEVOBJ_EXTENSION e a referência da montagem).
    vpb.device_object.set(volume_device);
    file_system::mount_initialize_vpb(device_at(real), device_at(real), false, false)?;
    // O SHARE_ACCESS das aberturas do volume (zerado: nenhuma aberta).
    let share = guest::alloc_bytes(ShareAccess::SIZE);
    if share == 0 {
        return Err(KernelError::new("volume do kernel: SHARE_ACCESS sem memoria"));
    }
    let name = alloc::format!("KernelVolume{index}");
    let node = object_manager::create_object("\\Device", &name, "Device", Some(object_manager::ObjectData::pointer(real)))?;
    object_manager::mount_device(node, file_system);
    VOLUMES.lock().push(KernelVolume { file_system, index, real, volume: volume_device, vpb: vpb_address, share });
    Ok(device_path(index))
}

/// O IRP_MJ_SHUTDOWN do file system embutido, no lugar do
/// IopShutdownBaseFileSystems (ele não está na fila dos file systems de
/// disco): cada volume que grava descarrega o disco e passa a recusar
/// escritas. Devolve quantos volumes foram fechados.
pub fn shut_down_volumes() -> u32 {
    let volumes: Vec<KernelVolume> = VOLUMES.lock().clone();
    let mut closed = 0;
    for volume in volumes {
        match volume.file_system.shut_down() {
            Some(Ok(())) => {
                debug_print!("[ntfs] desligamento: {} fechado", device_path(volume.index));
                closed += 1;
            }
            Some(Err(error)) => debug_print!("[ntfs] desligamento: {} falhou: {}", device_path(volume.index), error),
            None => {}
        }
    }
    closed
}

/// O dispositivo é o real de um volume do kernel (`\Device\KernelVolumeN`).
pub fn is_real_device(device: u64) -> bool {
    device != 0 && VOLUMES.lock().iter().any(|entry| entry.real == device)
}

/// O caminho NT do dispositivo real de um volume do kernel.
pub fn real_device_path(device: u64) -> Option<String> {
    VOLUMES.lock().iter().find(|entry| entry.real == device).map(|entry| device_path(entry.index))
}

fn find(file_system: &'static dyn FileSystem) -> Option<KernelVolume> {
    VOLUMES.lock().iter().copied().find(|entry| volume::same(entry.file_system, file_system))
}

/// O VolumeLabel do VPB do volume `\Device\KernelVolume<index>`.
pub fn vpb_label(index: u32) -> Option<String> {
    let vpb = VOLUMES.lock().iter().find(|entry| entry.index == index).map(|entry| entry.vpb).filter(|&vpb| vpb != 0)?;
    // SAFETY: o VPB permanente do volume.
    let vpb = unsafe { Vpb::at(vpb) };
    let units: Vec<u16> = vpb.volume_label.iter().take(vpb.volume_label_length.get() as usize / 2).map(|cell| cell.get()).collect();
    Some(String::from_utf16_lossy(&units))
}

/// O dispositivo é o de volume do file system embutido (sem despacho).
pub fn is_volume_device(device: u64) -> bool {
    device != 0 && VOLUMES.lock().iter().any(|entry| entry.volume == device)
}

/// Os IRPs dos arquivos do volume que o dispositivo de volume atende por
/// despacho (`io/file/information.rs::request_device`): o
/// IRP_MJ_LOCK_CONTROL das travas de faixa de bytes e o
/// IRP_MJ_DIRECTORY_CONTROL da notificação de mudança de diretório.
pub fn serves(major: u8) -> bool {
    major == IRP_MJ_LOCK_CONTROL || major == IRP_MJ_DIRECTORY_CONTROL
}

/// O dispositivo real do volume (o `\Device\KernelVolumeN`).
pub fn real_device(file_system: &'static dyn FileSystem) -> Option<u64> {
    find(file_system).map(|entry| entry.real)
}

/// O vínculo de um FILE_OBJECT com o volume; [`Binding::release`] solta a
/// referência do VPB na destruição do arquivo.
#[derive(Clone, Copy, Default)]
pub struct Binding {
    vpb: u64,
}

impl Binding {
    pub fn release(self) {
        let _ = file_system::dereference_vpb(self.vpb);
    }
}

/// Dá ao FILE_OBJECT de um arquivo do volume o dispositivo, o VPB e o
/// caminho no volume como FileName, como o IopParseDevice. Um volume sem
/// dispositivo deixa o FILE_OBJECT como está.
pub fn bind_file(file: u64, file_system: &'static dyn FileSystem, path: &str) -> Result<Binding, KernelError> {
    let Some(entry) = find(file_system) else { return Ok(Binding::default()) };
    let relative = alloc::format!("\\{}", path.trim_start_matches(['/', '\\']).replace('/', "\\"));
    let relative = if relative == "\\" { String::new() } else { relative };
    crate::ntos::ob::objects::file::set_name(file, &relative)?;
    file_system::reference_vpb(entry.vpb)?;
    // SAFETY: FILE_OBJECT vivo recém-criado pelo chamador.
    let object = unsafe { FileObject::at(file) };
    object.device_object.set(entry.real);
    object.vpb.set(entry.vpb);
    Ok(Binding { vpb: entry.vpb })
}

/// IRP_MJ_READ/WRITE com IRP_PAGING_IO num arquivo de paginação deste
/// volume: (NTSTATUS, Information); `None` para qualquer outro IRP.
fn paging_io(device: u64, irp: &Irp) -> Option<(u32, u64)> {
    if irp.flags.get() & IRP_PAGING_IO == 0 {
        return None;
    }
    // SAFETY: a stack location corrente do IRP entregue a este dispositivo.
    let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let major = stack.major_function.get();
    let file = stack.file_object.get();
    if (major != IRP_MJ_READ && major != IRP_MJ_WRITE) || !crate::ntos::mm::paging_file::is_paging_file(file) {
        return None;
    }
    let entry = VOLUMES.lock().iter().copied().find(|entry| entry.volume == device)?;
    let (file_system, path) = crate::ntos::io::file::zw::file_backing(file).filter(|(file_system, _)| volume::same(*file_system, entry.file_system))?;
    let length = stack.parameters.read.length.get() as u64;
    let offset = stack.parameters.read.byte_offset.quad_part.get() as u64;
    let descriptor = irp.mdl_address.get();
    // SAFETY: o MDL do IRP de paginação, com o vetor de PFNs logo depois.
    let byte_offset = if descriptor != 0 { unsafe { Mdl::at(descriptor) }.byte_offset.get() } else { 1 };
    if descriptor == 0 || byte_offset != 0 || length == 0 || length % PAGE != 0 || offset % PAGE != 0 {
        return Some((STATUS_INVALID_PARAMETER, 0));
    }
    let frames: Vec<u64> = (0..length / PAGE).map(|index| guest::read64(descriptor + Mdl::SIZE + index * 8) * PAGE).collect();
    let result: Result<Option<()>, KernelError> = if major == IRP_MJ_READ {
        let mut outcome = Ok(Some(()));
        for (index, &frame) in frames.iter().enumerate() {
            match file_system.paging_read(&path, offset + index as u64 * PAGE, frame) {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    outcome = Err(error);
                    break;
                }
                None => {
                    outcome = Ok(None);
                    break;
                }
            }
        }
        outcome
    } else {
        let bytes: Vec<u8> = frames.iter().flat_map(|&frame| crate::hal::physical::read_bytes(frame, PAGE as usize)).collect();
        file_system.paging_write(&path, offset, &bytes).transpose()
    };
    match result {
        Ok(Some(())) => Some((STATUS_SUCCESS, length)),
        Ok(None) => None,
        Err(error) => Some((if error.status != 0 { error.status } else { STATUS_UNEXPECTED_IO_ERROR }, 0)),
    }
}

/// A rotina de despacho do file system embutido: o IRP_MJ_LOCK_CONTROL e o
/// IRP_MJ_DIRECTORY_CONTROL de notificação dos arquivos do volume
/// ([`serves`]), a E/S de paginação dos arquivos de
/// paginação e as aberturas do volume inteiro ([`answer`]); as outras
/// operações dos arquivos do volume são respondidas no lugar pelo I/O
/// Manager.
extern "win64" fn dispatch(device: u64, packet: u64) -> i32 {
    // SAFETY: IRP vivo entregue a um dispositivo deste driver.
    let irp = unsafe { Irp::at(packet) };
    if is_volume_device(device) {
        // SAFETY: a stack location corrente do IRP entregue a este dispositivo.
        let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
        // O FsRtl conclui o IRP ou o deixa na fila de espera.
        match stack.major_function.get() {
            IRP_MJ_LOCK_CONTROL => return super::volume_streams::lock_control(packet, irp, stack),
            IRP_MJ_DIRECTORY_CONTROL if matches!(stack.minor_function.get(), IRP_MN_NOTIFY_CHANGE_DIRECTORY | IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX) => return super::volume_streams::notify_change_directory(packet, irp, stack),
            // O NtfsCommonDirectoryControl só atende a notificação por IRP
            // aqui (a listagem do diretório é respondida no lugar pelo I/O
            // Manager): outro minor é STATUS_INVALID_DEVICE_REQUEST
            // (0x1ca363).
            IRP_MJ_DIRECTORY_CONTROL => return super::volume_streams::complete(packet, irp, STATUS_INVALID_DEVICE_REQUEST),
            _ => {}
        }
    }
    let (status, information) = paging_io(device, irp).unwrap_or_else(|| answer(device, irp));
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(packet);
    status as i32
}

fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o FILE_OBJECT da stack location de um IRP vivo.
    unsafe { FileObject::at(file) }
}

fn share_record(entry: &KernelVolume) -> &'static ShareAccess {
    // SAFETY: o SHARE_ACCESS permanente alocado na montagem.
    unsafe { ShareAccess::at(entry.share) }
}

/// Um IRP que não é de paginação: o dispositivo real atende a abertura
/// direta e o de volume do file system, a abertura do volume.
fn answer(device: u64, irp: &Irp) -> (u32, u64) {
    let Some(entry) = VOLUMES.lock().iter().copied().find(|entry| entry.real == device || entry.volume == device) else { return (STATUS_INVALID_DEVICE_REQUEST, 0) };
    // SAFETY: a stack location corrente do IRP entregue a este dispositivo.
    let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let file = stack.file_object.get();
    if device == entry.real {
        real_request(&entry, irp, stack, file)
    } else {
        volume_request(&entry, irp, stack, file)
    }
}

/// O dispositivo real no papel do dispositivo de volume do gerenciador de
/// volumes: só a abertura sem nome (a direta do IopParseDevice) chega a
/// ele.
fn real_request(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation, file: u64) -> (u32, u64) {
    match stack.major_function.get() {
        IRP_MJ_CREATE => {
            if file == 0 || file_at(file).file_name.length.get() != 0 || file_at(file).related_file_object.get() != 0 {
                return (STATUS_INVALID_DEVICE_REQUEST, 0);
            }
            (STATUS_SUCCESS, FILE_OPENED)
        }
        IRP_MJ_CLEANUP | IRP_MJ_CLOSE => (STATUS_SUCCESS, 0),
        IRP_MJ_DEVICE_CONTROL => volume_control(entry, irp, stack),
        _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

/// O dispositivo de volume do file system: a abertura do volume (FileName
/// vazio, sem arquivo relacionado) e os IRPs dos FILE_OBJECTs com
/// FO_VOLUME_OPEN.
fn volume_request(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation, file: u64) -> (u32, u64) {
    if file == 0 {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let object = file_at(file);
    let major = stack.major_function.get();
    if major == IRP_MJ_CREATE {
        return volume_create(entry, stack, object);
    }
    if object.flags.get() & FO_VOLUME_OPEN == 0 {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    match major {
        IRP_MJ_CLEANUP => {
            let _lock = SHARE_LOCK.lock();
            share_access::remove(object, share_record(entry));
            (STATUS_SUCCESS, 0)
        }
        IRP_MJ_CLOSE => (STATUS_SUCCESS, 0),
        IRP_MJ_QUERY_VOLUME_INFORMATION => query_volume(entry, irp, stack),
        IRP_MJ_SET_VOLUME_INFORMATION => set_volume(entry, irp, stack),
        IRP_MJ_FILE_SYSTEM_CONTROL => volume_fs_control(entry, irp, stack),
        // O file system passa os IOCTLs do volume ao dispositivo alvo.
        IRP_MJ_DEVICE_CONTROL => volume_control(entry, irp, stack),
        _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
    }
}

/// A abertura do volume pelo file system: as regras da abertura de volume
/// de um file system do NT e o IoCheckShareAccess no SHARE_ACCESS do
/// volume.
fn volume_create(entry: &KernelVolume, stack: &IoStackLocation, object: &FileObject) -> (u32, u64) {
    if object.file_name.length.get() != 0 || object.related_file_object.get() != 0 {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let create = &stack.parameters.create;
    let options = create.options.get();
    let disposition = options >> 24;
    let share = create.share_access.get() as u32;
    let context = create.security_context.get();
    // SAFETY: o IO_SECURITY_CONTEXT do IRP_MJ_CREATE montado pelo I/O Manager.
    let desired = if context != 0 { unsafe { IoSecurityContext::at(context) }.desired_access.get() } else { 0 };
    if options & FILE_DIRECTORY_FILE != 0 {
        return (STATUS_NOT_A_DIRECTORY, 0);
    }
    if disposition != FILE_OPEN && disposition != FILE_OPEN_IF {
        return (STATUS_ACCESS_DENIED, 0);
    }
    if options & FILE_DELETE_ON_CLOSE != 0 {
        return (STATUS_CANNOT_DELETE, 0);
    }
    // Sem FILE_SHARE_WRITE nem FILE_SHARE_DELETE a abertura trava o volume,
    // o que exige nenhum arquivo aberto nele; um volume do kernel sempre os
    // tem (imagens, hives, o arquivo de paginação).
    if share & (FILE_SHARE_WRITE | FILE_SHARE_DELETE) == 0 {
        return (STATUS_SHARING_VIOLATION, 0);
    }
    let _lock = SHARE_LOCK.lock();
    let status = share_access::check(desired, share, object, share_record(entry), true);
    if status != STATUS_SUCCESS {
        return (status, 0);
    }
    (STATUS_SUCCESS, FILE_OPENED)
}

/// IRP_MJ_QUERY_VOLUME_INFORMATION numa abertura do volume: a identidade e
/// a capacidade do volume montado (`volume_information`).
fn query_volume(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let parameters = &stack.parameters.query_volume;
    let class = parameters.fs_information_class.get().0 as u32;
    let length = parameters.length.get();
    match super::volume_information::query(entry.file_system.volume_query(), class, length) {
        Ok(result) => {
            if result.status >> 30 != 3 {
                super::volume_information::write(&result, irp.associated_irp.system_buffer.get());
            }
            (result.status, result.information as u64)
        }
        Err(error) => (if error.status != 0 { error.status } else { STATUS_UNEXPECTED_IO_ERROR }, 0),
    }
}

/// IRP_MJ_SET_VOLUME_INFORMATION numa abertura do volume: o file system
/// (`FileSystem::set_volume_information`, o NtfsCommonSetVolumeInfo) e,
/// depois de um rótulo novo, o VolumeLabel do VPB, que o NtfsSetFsLabelInfo
/// também troca.
fn set_volume(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let parameters = &stack.parameters.set_volume;
    let class = parameters.fs_information_class.get().0 as u32;
    let length = parameters.length.get() as usize;
    let system = irp.associated_irp.system_buffer.get();
    let bytes = if system != 0 { guest::read_bytes(system, length) } else { Vec::new() };
    match entry.file_system.set_volume_information(class, &bytes) {
        None => (STATUS_INVALID_DEVICE_REQUEST, 0),
        Some(Err(error)) => (if error.status != 0 { error.status } else { STATUS_UNEXPECTED_IO_ERROR }, 0),
        Some(Ok(status)) => {
            if status == STATUS_SUCCESS && class == 2 && entry.vpb != 0 && bytes.len() >= 4 {
                let label_length = (u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize).min(bytes.len() - 4);
                // SAFETY: o VPB permanente do volume.
                let vpb = unsafe { Vpb::at(entry.vpb) };
                let units: Vec<u16> = bytes[4..4 + label_length].chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).take(vpb.volume_label.len()).collect();
                for (cell, unit) in vpb.volume_label.iter().zip(units.iter()) {
                    cell.set(*unit);
                }
                vpb.volume_label_length.set(units.len() as u16 * 2);
            }
            (status, 0)
        }
    }
}

/// IRP_MJ_FILE_SYSTEM_CONTROL numa abertura do volume.
fn volume_fs_control(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let minor = stack.minor_function.get();
    if minor != IRP_MN_USER_FS_REQUEST && minor != IRP_MN_KERNEL_CALL {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let parameters = &stack.parameters.file_system_control;
    let code = parameters.fs_control_code.get();
    match code {
        // A trava pede o volume sem outros arquivos abertos, e a desmontagem
        // é recusada no volume de boot e de paginação.
        FSCTL_LOCK_VOLUME | FSCTL_DISMOUNT_VOLUME => return (STATUS_ACCESS_DENIED, 0),
        FSCTL_UNLOCK_VOLUME => return (STATUS_NOT_LOCKED, 0),
        _ => {}
    }
    if code & 3 != METHOD_BUFFERED {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let output_length = parameters.output_buffer_length.get();
    let input_length = parameters.input_buffer_length.get();
    let system_buffer = irp.associated_irp.system_buffer.get();
    let input = if input_length != 0 && system_buffer != 0 { guest::read_bytes(system_buffer, input_length as usize) } else { Vec::new() };
    // Quem pede: o acesso da abertura (o WriteAccess do FILE_OBJECT, como o
    // FsRtlKernelFsControlFile) e o modo do IRP.
    let file = stack.file_object.get();
    let write = file != 0 && file_at(file).write_access.get() != 0;
    let caller = super::ntfs_control::ControlCaller { access: if write { 0x0012_0196 } else { 0x0012_0089 }, user_mode: irp.requestor_mode.get() == 1 && minor != IRP_MN_KERNEL_CALL };
    let Some(result) = entry.file_system.control("/", code, &input, output_length, &caller) else { return (STATUS_INVALID_DEVICE_REQUEST, 0) };
    match result {
        Ok(result) => {
            let count = result.bytes.len().min(output_length as usize);
            if count != 0 && system_buffer != 0 {
                guest::write_bytes(system_buffer, &result.bytes[..count]);
            }
            (result.status, (result.information as u64).min(output_length as u64))
        }
        Err(error) => (if error.status != 0 { error.status } else { STATUS_UNEXPECTED_IO_ERROR }, 0),
    }
}

/// Grava a resposta no SystemBuffer se couber: (status, Information).
fn reply(irp: &Irp, output_length: u64, bytes: &[u8]) -> (u32, u64) {
    if output_length < bytes.len() as u64 {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    guest::write_bytes(irp.associated_irp.system_buffer.get(), bytes);
    (STATUS_SUCCESS, bytes.len() as u64)
}

/// VOLUME_DISK_EXTENTS com uma extensão: NumberOfDiskExtents, o
/// alinhamento e o DISK_EXTENT { DiskNumber, StartingOffset, ExtentLength }.
fn disk_extents(extent: &DiskExtent) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(0x20);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&extent.disk_number.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&extent.starting_offset.to_le_bytes());
    bytes.extend_from_slice(&extent.length.to_le_bytes());
    bytes
}

/// O GUID estável do volume (MOUNTDEV_STABLE_GUID): "OPEN", "KV", o índice e
/// o número de série do volume, o mesmo a cada boot da mesma imagem (como o
/// stable_guid do storage/ata_volume.rs). O mountmgr.sys nomeia o volume
/// `\??\Volume{4F50454E-4B56-400N-...}` por ele
/// (QuerySymbolicLinkNamesFromStorage 0x164c8).
fn stable_guid(entry: &KernelVolume) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[..4].copy_from_slice(&u32::from_be_bytes(*b"OPEN").to_le_bytes());
    bytes[4..6].copy_from_slice(&u16::from_be_bytes(*b"KV").to_le_bytes());
    bytes[6..8].copy_from_slice(&(0x4000u16 | entry.index as u16).to_le_bytes());
    bytes[8..].copy_from_slice(&entry.file_system.volume_serial().unwrap_or(0).to_le_bytes());
    bytes
}

/// MOUNTDEV_UNIQUE_ID na forma do volmgr.sys para um volume com GUID
/// (VmpQueryUniqueIdInternal 0x1114b): "DMIO:ID:" e o GUID estável. É o
/// valor REG_BINARY do MountedDevices.
fn unique_id(entry: &KernelVolume) -> Vec<u8> {
    let mut bytes = b"DMIO:ID:".to_vec();
    bytes.extend_from_slice(&stable_guid(entry));
    bytes
}

/// Os IOCTLs do mount manager, com a semântica do volmgr.sys 19041; `None`
/// para os outros.
fn mount_control(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation) -> Option<(u32, u64)> {
    let parameters = &stack.parameters.device_io_control;
    let output_length = parameters.output_buffer_length.get();
    let input_length = parameters.input_buffer_length.get();
    let buffer = irp.associated_irp.system_buffer.get();
    let partition = entry.file_system.disk_extent().is_some();
    Some(match parameters.io_control_code.get() {
        // VmpQueryDeviceName 0xc350.
        IOCTL_MOUNTDEV_QUERY_DEVICE_NAME => {
            if output_length < MountdevName::SIZE as u32 {
                return Some((STATUS_INVALID_PARAMETER, 0));
            }
            let name: Vec<u16> = device_path(entry.index).encode_utf16().collect();
            let bytes = name.len() as u32 * 2;
            // SAFETY: SystemBuffer de saída com ao menos um MOUNTDEV_NAME.
            let reply = unsafe { MountdevName::at(buffer) };
            reply.name_length.set(bytes as u16);
            if output_length < bytes + 2 {
                return Some((STATUS_BUFFER_OVERFLOW, 2));
            }
            guest::write_bytes(reply.name[0].address(), &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
            (STATUS_SUCCESS, bytes as u64 + 2)
        }
        // VmpQueryUniqueId 0xf364 e VmpQueryUniqueIdInternal 0xf3cc.
        IOCTL_MOUNTDEV_QUERY_UNIQUE_ID => {
            if output_length < MountdevUniqueId::SIZE as u32 {
                return Some((STATUS_INVALID_PARAMETER, 0));
            }
            let id = unique_id(entry);
            // SAFETY: SystemBuffer de saída com ao menos um MOUNTDEV_UNIQUE_ID.
            let reply = unsafe { MountdevUniqueId::at(buffer) };
            reply.unique_id_length.set(id.len() as u16);
            if output_length - 2 < id.len() as u32 {
                return Some((STATUS_BUFFER_OVERFLOW, 2));
            }
            guest::write_bytes(reply.unique_id[0].address(), &id);
            (STATUS_SUCCESS, 2 + id.len() as u64)
        }
        // VmpQueryStableGuid 0xc4ec (o volume do kernel não é removível).
        IOCTL_MOUNTDEV_QUERY_STABLE_GUID => {
            if output_length < 16 {
                return Some((STATUS_INVALID_PARAMETER, 0));
            }
            guest::write_bytes(buffer, &stable_guid(entry));
            (STATUS_SUCCESS, 16)
        }
        // VmpQuerySuggestedLinkName 0x13bc0: o volmgr.sys nunca sugere letra
        // (o volume de boot e o básico dão STATUS_NOT_FOUND); a letra vem do
        // MountedDevices ou do IOCTL_MOUNTMGR_BOOT_DL_ASSIGNMENT.
        IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME => (
            if !partition {
                STATUS_NO_SUCH_DEVICE
            } else if output_length < 6 {
                STATUS_INVALID_PARAMETER
            } else {
                STATUS_NOT_FOUND
            },
            0,
        ),
        // VmpLinkCreated 0xf584 e VmpLinkDeleted 0x1322c: só o MOUNTDEV_NAME
        // de entrada é conferido.
        IOCTL_MOUNTDEV_LINK_CREATED | IOCTL_MOUNTDEV_LINK_DELETED | IOCTL_MOUNTDEV_LINK_CREATED_LEGACY | IOCTL_MOUNTDEV_LINK_DELETED_LEGACY => (if input_length < 4 { STATUS_INVALID_PARAMETER } else { STATUS_SUCCESS }, 0),
        // VmpGetGptAttributes 0xe96c: não é partição GPT.
        IOCTL_VOLUME_GET_GPT_ATTRIBUTES => (if output_length >= 8 && !partition { STATUS_NO_SUCH_DEVICE } else { STATUS_INVALID_PARAMETER }, 0),
        // VmpOnline 0xd554 e o POST_ONLINE: o volume do kernel já está online.
        IOCTL_VOLUME_ONLINE | IOCTL_VOLUME_POST_ONLINE => (STATUS_SUCCESS, 0),
        _ => return None,
    })
}

/// A chegada do volume ao Mount Manager. O gerenciador de volumes do NT a
/// faz pela interface MOUNTDEV_MOUNTED_DEVICE_GUID no PDO do volume (a
/// notificação que o DriverEntry do mountmgr.sys registra, 0x1a3db); um
/// volume do kernel não tem PDO, e o mountmgr.sys aceita um volume fora do
/// PnP por este IOCTL (MountMgrVolumeArrivalNotification 0x12b1c: OpenDevice
/// e MountMgrMountedDeviceArrival com ManuallyRegistered, sem as
/// notificações de dispositivo alvo do PnP). A entrada é o
/// MOUNTMGR_TARGET_NAME: DeviceNameLength e o nome do dispositivo.
pub fn announce_to_mount_manager(index: u32) -> Result<u32, KernelError> {
    let name: Vec<u16> = device_path(index).encode_utf16().collect();
    let mut input = Vec::with_capacity(2 + name.len() * 2);
    input.extend_from_slice(&(name.len() as u16 * 2).to_le_bytes());
    input.extend(name.iter().flat_map(|unit| unit.to_le_bytes()));
    crate::ntos::io::volume_dos_name::mount_manager_control(IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION, &input)
}

/// IRP_MJ_DEVICE_CONTROL (METHOD_BUFFERED) no volume: os IOCTLs que o
/// gerenciador de volumes responde por um volume simples, com a extensão
/// do volume no disco (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
/// IOCTL_DISK_GET_LENGTH_INFO), e os de armazenamento que ele repassa ao
/// disco, com as respostas que `storage/ata_volume.rs` dá para o mesmo
/// disco. O psmsrv.dll (PsmpInitializeDiskHandleCache 0x14d38) e o
/// PsmServiceExtHost.dll (CrmStateMonitorSystemDiskUsageIndexGet 0x43090)
/// pedem o VOLUME_DISK_EXTENTS de `\\.\C:`; o RtlQueryVolumeDiskSpeedPolicy
/// (0x4293c) pede o StorageDeviceSeekPenaltyProperty. Os demais, como o
/// 0x22096c do RtlpQueryDiskWriteConstraintPolicyByHandle (0x867f0), dão
/// STATUS_INVALID_DEVICE_REQUEST, que esses chamadores tratam como "sem
/// resposta" e usam o padrão. Um volume sem disco (o disco em memória) não
/// tem extensão.
fn volume_control(entry: &KernelVolume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    if let Some(answer) = mount_control(entry, irp, stack) {
        return answer;
    }
    let parameters = &stack.parameters.device_io_control;
    let code = parameters.io_control_code.get();
    let output_length = parameters.output_buffer_length.get() as u64;
    let input_length = parameters.input_buffer_length.get() as u64;
    let system_buffer = irp.associated_irp.system_buffer.get();
    let extent = entry.file_system.disk_extent();
    match (code, extent) {
        (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, Some(extent)) => reply(irp, output_length, &disk_extents(&extent)),
        (IOCTL_DISK_GET_LENGTH_INFO, Some(extent)) => reply(irp, output_length, &extent.length.to_le_bytes()),
        (IOCTL_DISK_IS_WRITABLE, _) => (if entry.file_system.writable() { STATUS_SUCCESS } else { STATUS_MEDIA_WRITE_PROTECTED }, 0),
        (IOCTL_STORAGE_GET_DEVICE_NUMBER, Some(extent)) => {
            // STORAGE_DEVICE_NUMBER: FILE_DEVICE_DISK, o disco e a partição 0
            // (o disco inteiro), como o ata_volume.rs.
            let mut bytes = Vec::with_capacity(12);
            bytes.extend_from_slice(&FILE_DEVICE_DISK.to_le_bytes());
            bytes.extend_from_slice(&extent.disk_number.to_le_bytes());
            bytes.extend_from_slice(&0u32.to_le_bytes());
            reply(irp, output_length, &bytes)
        }
        (IOCTL_STORAGE_QUERY_PROPERTY, Some(_)) => {
            if input_length < 8 || system_buffer == 0 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            let property = guest::read32(system_buffer);
            let query = guest::read32(system_buffer + 4);
            let descriptor: Option<Vec<u8>> = match property {
                STORAGE_ACCESS_ALIGNMENT_PROPERTY => Some([0x1C, 0x1C, 64, 0, SECTOR, SECTOR, 0].iter().flat_map(|value: &u32| value.to_le_bytes()).collect()),
                STORAGE_DEVICE_SEEK_PENALTY_PROPERTY | STORAGE_DEVICE_TRIM_PROPERTY => {
                    // Disco rotativo emulado: há penalidade de busca e não há TRIM.
                    let mut bytes = Vec::with_capacity(12);
                    bytes.extend_from_slice(&12u32.to_le_bytes());
                    bytes.extend_from_slice(&12u32.to_le_bytes());
                    bytes.extend_from_slice(&[(property == STORAGE_DEVICE_SEEK_PENALTY_PROPERTY) as u8, 0, 0, 0]);
                    Some(bytes)
                }
                _ => None,
            };
            match descriptor {
                None => (STATUS_NOT_SUPPORTED, 0),
                Some(_) if query == PROPERTY_EXISTS_QUERY => (STATUS_SUCCESS, 0),
                Some(bytes) => {
                    let count = bytes.len().min(output_length as usize);
                    guest::write_bytes(system_buffer, &bytes[..count]);
                    (STATUS_SUCCESS, count as u64)
                }
            }
        }
        _ => {
            if UNKNOWN_CONTROLS.lock().insert(code) {
                debug_print!("[kvol] IOCTL {:#x} no volume sem resposta -> STATUS_INVALID_DEVICE_REQUEST", code);
            }
            (STATUS_INVALID_DEVICE_REQUEST, 0)
        }
    }
}
