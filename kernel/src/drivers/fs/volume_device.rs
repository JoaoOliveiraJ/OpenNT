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
//! pilha de IRP: o I/O Manager responde no lugar as operações dos arquivos
//! dele (`io/file/information.rs::related_device` não acha dispositivo de
//! despacho), e um IRP que um driver mande ao dispositivo de volume termina
//! com STATUS_INVALID_DEVICE_REQUEST.

use alloc::string::String;
use alloc::vec::Vec;

use super::volume::{self, FileSystem};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, FileObject, Irp, Vpb};
use crate::ntos::io::{file_system, io_manager};
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
/// Nome do DRIVER_OBJECT do file system embutido.
const DRIVER_NAME: &str = "\\FileSystem\\KernelVolume";

/// Um volume do kernel montado no seu dispositivo.
#[derive(Clone, Copy)]
struct KernelVolume {
    file_system: &'static dyn FileSystem,
    /// O DEVICE_OBJECT real (`\Device\KernelVolumeN`).
    real: u64,
    /// O dispositivo de volume do file system embutido.
    volume: u64,
    vpb: u64,
}

// SAFETY: os volumes são estáticos e os endereços são de objetos permanentes.
unsafe impl Send for KernelVolume {}

static VOLUMES: SpinLock<Vec<KernelVolume>> = SpinLock::new(Vec::new());
static DRIVER: SpinLock<u64> = SpinLock::new(0);

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
    let name = alloc::format!("KernelVolume{index}");
    let node = object_manager::create_object("\\Device", &name, "Device", Some(object_manager::ObjectData::pointer(real)))?;
    object_manager::mount_device(node, file_system);
    VOLUMES.lock().push(KernelVolume { file_system, real, volume: volume_device, vpb: vpb_address });
    Ok(device_path(index))
}

fn find(file_system: &'static dyn FileSystem) -> Option<KernelVolume> {
    VOLUMES.lock().iter().copied().find(|entry| volume::same(entry.file_system, file_system))
}

/// O dispositivo é o de volume do file system embutido (sem despacho).
pub fn is_volume_device(device: u64) -> bool {
    device != 0 && VOLUMES.lock().iter().any(|entry| entry.volume == device)
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

/// A rotina de despacho do file system embutido: os arquivos dele são
/// respondidos no lugar pelo I/O Manager, então todo IRP é recusado.
extern "win64" fn dispatch(_device: u64, packet: u64) -> i32 {
    // SAFETY: IRP vivo entregue ao dispositivo de volume.
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(STATUS_INVALID_DEVICE_REQUEST as i32);
    irp.io_status.information.set(0);
    io_manager::iof_complete_request(packet);
    STATUS_INVALID_DEVICE_REQUEST as i32
}
