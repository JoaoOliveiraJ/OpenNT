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
//! com STATUS_INVALID_DEVICE_REQUEST. A exceção é a E/S de paginação dos
//! arquivos de paginação (MmIsFileObjectAPagingFile): o IoPageRead e o
//! IoSynchronousPageWrite do Mm chegam aqui como IRP_MJ_READ/WRITE com
//! IRP_PAGING_IO e um MDL de páginas inteiras, e vão direto às runs do
//! arquivo (`FileSystem::paging_read`/`paging_write`).

use alloc::string::String;
use alloc::vec::Vec;

use super::volume::{self, FileSystem};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, FileObject, IoStackLocation, Irp, Mdl, Vpb};
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
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_UNEXPECTED_IO_ERROR: u32 = 0xC000_00E9;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_WRITE: u8 = 4;
/// IRP.Flags: IRP_PAGING_IO.
const IRP_PAGING_IO: u32 = 0x02;
const PAGE: u64 = 0x1000;
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

/// A rotina de despacho do file system embutido: os arquivos dele são
/// respondidos no lugar pelo I/O Manager, então todo IRP é recusado, salvo
/// a E/S de paginação dos arquivos de paginação.
extern "win64" fn dispatch(device: u64, packet: u64) -> i32 {
    // SAFETY: IRP vivo entregue ao dispositivo de volume.
    let irp = unsafe { Irp::at(packet) };
    let (status, information) = paging_io(device, irp).unwrap_or((STATUS_INVALID_DEVICE_REQUEST, 0));
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(packet);
    status as i32
}
