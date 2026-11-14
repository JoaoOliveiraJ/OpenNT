//! O segundo disco IDE como dispositivo de volume do I/O Manager
//! (`\Device\AtaVolume1`), para os file systems reais montarem.
//!
//! Suporte de boot do driver ATA do kernel, não um substituto do disk.sys: o
//! disco inteiro é um volume (o NTFS que o xtask gera começa no setor 0), num
//! DEVICE_OBJECT nativo sem DRIVER_OBJECT, como os PDOs que o barramento do
//! kernel responde (`io_manager::register_pdo_native_answerer`). O
//! dispositivo nasce como o IoCreateDevice faz com um FILE_DEVICE_DISK: VPB
//! (IopCreateVpb), DeviceLock sinalizado, SectorSize 512, DO_DIRECT_IO e
//! alinhamento de palavra, e é montado pelo caminho do NT
//! (`io/file_system.rs::mount_volume`).
//!
//! O leitor NTFS do kernel continua dono do mesmo disco como D:, então o que
//! o file system grava não vai ao disco: fica numa sobreposição em memória,
//! por página de 4 KB, e é o que as leituras seguintes do volume devolvem
//! (o disco e o leitor do kernel continuam vendo a imagem do boot). Para o
//! file system o volume é um disco gravável comum. IRP_MJ_READ lê setores
//! inteiros para o buffer do MDL (DO_DIRECT_IO) pelo DMA do driver ATA e
//! aplica a sobreposição; IRP_MJ_WRITE grava nela. Os IOCTLs de disco,
//! armazenamento e mount manager que um file system pede na montagem são
//! respondidos com a geometria real do disco (IDENTIFY DEVICE); os demais
//! dão STATUS_INVALID_DEVICE_REQUEST, registrados uma vez na serial.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use crate::drivers::storage::ata_pio;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, IoStackLocation, Irp, Mdl};
use crate::ntos::io::{file_system, io_manager};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::{KernelError, SpinLock};

/// Nome do dispositivo de volume no namespace.
pub const DEVICE_NAME: &str = "AtaVolume1";

const SECTOR: u64 = 512;
const IO_TYPE_DEVICE: i16 = 3;
const FILE_DEVICE_DISK: u32 = 0x07;
const DO_DIRECT_IO: u32 = 0x10;
const FILE_WORD_ALIGNMENT: u32 = 1;
const MDL_MAPPED_TO_SYSTEM_VA: i16 = 0x0001;
const MDL_SOURCE_IS_NONPAGED_POOL: i16 = 0x0004;
/// Setores lidos por comando (o buffer de passagem do driver ATA).
const CHUNK_SECTORS: u64 = 256;

const STATUS_SUCCESS: u32 = 0;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_DEVICE_DATA_ERROR: u32 = 0xC000_009C;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_READ: u8 = 0x03;
const IRP_MJ_WRITE: u8 = 0x04;
const IRP_MJ_FLUSH_BUFFERS: u8 = 0x09;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
const IRP_MJ_CLEANUP: u8 = 0x12;

const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x0007_4004;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x0007_0024;
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;
const IOCTL_DISK_CHECK_VERIFY: u32 = 0x0007_4800;
const IOCTL_STORAGE_CHECK_VERIFY: u32 = 0x002D_4800;
const IOCTL_STORAGE_CHECK_VERIFY2: u32 = 0x002D_0800;
const IOCTL_STORAGE_GET_HOTPLUG_INFO: u32 = 0x002D_0C14;
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: u32 = 0x004D_0000;
const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

/// STORAGE_PROPERTY_ID e STORAGE_QUERY_TYPE (ntddstor.h).
const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
const STORAGE_DEVICE_TRIM_PROPERTY: u32 = 8;
const PROPERTY_EXISTS_QUERY: u32 = 1;
/// MEDIA_TYPE FixedMedia e PARTITION_IFS.
const FIXED_MEDIA: u32 = 12;
const PARTITION_IFS: u8 = 0x07;

/// O dispositivo criado: (DEVICE_OBJECT, drive ATA, setores do disco).
#[derive(Clone, Copy)]
struct Volume {
    device: u64,
    drive: u8,
    sectors: u64,
}

static VOLUME: SpinLock<Option<Volume>> = SpinLock::new(None);
/// Páginas de 4 KB gravadas pelo file system (índice da página -> bytes).
static OVERLAY: SpinLock<BTreeMap<u64, Box<[u8; PAGE]>>> = SpinLock::new(BTreeMap::new());
const PAGE: usize = 4096;
const SECTORS_PER_PAGE: u64 = PAGE as u64 / SECTOR;
static UNKNOWN_CONTROLS: SpinLock<BTreeSet<u32>> = SpinLock::new(BTreeSet::new());

/// O DEVICE_OBJECT do volume, se já criado.
pub fn device() -> Option<u64> {
    VOLUME.lock().map(|volume| volume.device)
}

/// Cria `\Device\AtaVolume1` sobre o drive ATA dado (idempotente).
pub fn create(drive: u8) -> Result<u64, KernelError> {
    if let Some(volume) = *VOLUME.lock() {
        return Ok(volume.device);
    }
    if !ata_pio::present(drive)? {
        return Err(KernelError::new("ATA: drive ausente para o volume"));
    }
    let sectors = ata_pio::capacity_sectors(drive)?;
    let address = guest::alloc_bytes(DeviceObject::SIZE);
    if address == 0 {
        return Err(KernelError::new("volume ATA: DEVICE_OBJECT sem memoria"));
    }
    // SAFETY: bloco recém-alocado do tamanho de um DEVICE_OBJECT.
    let object = unsafe { DeviceObject::at(address) };
    object.type_.set(IO_TYPE_DEVICE);
    object.size.set(DeviceObject::SIZE as u16);
    object.reference_count.set(1);
    object.device_type.set(FILE_DEVICE_DISK);
    object.stack_size.set(1);
    object.flags.set(DO_DIRECT_IO);
    object.alignment_requirement.set(FILE_WORD_ALIGNMENT);
    object.sector_size.set(SECTOR as u16);
    dispatcher::initialize_event(object.device_lock.address(), 1, true);
    if file_system::create_vpb(object)? != STATUS_SUCCESS {
        guest::free_bytes(address);
        return Err(KernelError::new("volume ATA: VPB sem memoria"));
    }
    device_objects::register(address, None, None)?;
    let node = object_manager::create_object("\\Device", DEVICE_NAME, "Device", Some(object_manager::ObjectData::pointer(address)))?;
    io_manager::register_device(node, io_manager::DeviceEntry { native_device: address, ..Default::default() });
    *VOLUME.lock() = Some(Volume { device: address, drive, sectors });
    io_manager::register_pdo_native_answerer(answer);
    debug_print!("[atavol] \\Device\\{} criado sobre o drive {} ({} setores, escrita em memoria)", DEVICE_NAME, drive, sectors);
    Ok(address)
}

/// IRP do volume: responde e completa; outros dispositivos seguem adiante.
fn answer(device: u64, packet: u64) -> Option<i32> {
    let volume = (*VOLUME.lock()).filter(|volume| volume.device == device)?;
    // SAFETY: IRP vivo entregue ao dispositivo; CurrentStackLocation aponta o slot dele.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: a stack location corrente do mesmo IRP.
    let stack = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let (status, information) = match stack.major_function.get() {
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP | IRP_MJ_FLUSH_BUFFERS => (STATUS_SUCCESS, 0),
        IRP_MJ_READ => read(&volume, irp, stack),
        IRP_MJ_WRITE => write(&volume, irp, stack),
        IRP_MJ_DEVICE_CONTROL | IRP_MJ_INTERNAL_DEVICE_CONTROL => device_control(&volume, irp, stack),
        // PnP sem tratamento mantém STATUS_NOT_SUPPORTED, como manda o WDM.
        _ => (STATUS_NOT_SUPPORTED, 0),
    };
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    io_manager::iof_complete_request(packet);
    Some(status as i32)
}

/// Endereço de sistema do buffer de uma transferência DO_DIRECT_IO (o
/// MmGetSystemAddressForMdlSafe), ou o UserBuffer sem MDL.
fn transfer_buffer(irp: &Irp) -> u64 {
    let mdl_address = irp.mdl_address.get();
    if mdl_address == 0 {
        return irp.user_buffer.get();
    }
    // SAFETY: o MDL do IRP, descrito por quem montou o pedido.
    let mdl = unsafe { Mdl::at(mdl_address) };
    if mdl.mdl_flags.get() & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        mdl.mapped_system_va.get()
    } else {
        mdl.start_va.get() + mdl.byte_offset.get() as u64
    }
}

/// IRP_MJ_READ: setores inteiros dentro do disco.
fn read(volume: &Volume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let length = stack.parameters.read.length.get() as u64;
    let offset = stack.parameters.read.byte_offset.quad_part.get();
    if offset < 0 || length % SECTOR != 0 || offset as u64 % SECTOR != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let first = offset as u64 / SECTOR;
    if first + length / SECTOR > volume.sectors {
        return (STATUS_END_OF_FILE, 0);
    }
    let buffer = transfer_buffer(irp);
    if buffer == 0 && length != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let mut done = 0;
    while done < length / SECTOR {
        let count = CHUNK_SECTORS.min(length / SECTOR - done);
        match ata_pio::read_sectors(first + done, count as u32, volume.drive) {
            Ok(mut bytes) => {
                apply_overlay(first + done, &mut bytes);
                guest::write_bytes(buffer + done * SECTOR, &bytes);
            }
            Err(error) => {
                debug_print!("[atavol] leitura do setor {} falhou: {}", first + done, error);
                return (STATUS_DEVICE_DATA_ERROR, done * SECTOR);
            }
        }
        done += count;
    }
    (STATUS_SUCCESS, length)
}

/// Troca nos setores lidos a partir de `first` o que a sobreposição tem.
fn apply_overlay(first: u64, bytes: &mut [u8]) {
    let count = bytes.len() as u64 / SECTOR;
    if count == 0 {
        return;
    }
    let overlay = OVERLAY.lock();
    for (&page, data) in overlay.range(first / SECTORS_PER_PAGE..=(first + count - 1) / SECTORS_PER_PAGE) {
        for sector in page * SECTORS_PER_PAGE..(page + 1) * SECTORS_PER_PAGE {
            if (first..first + count).contains(&sector) {
                let source = ((sector - page * SECTORS_PER_PAGE) * SECTOR) as usize;
                let target = ((sector - first) * SECTOR) as usize;
                bytes[target..target + SECTOR as usize].copy_from_slice(&data[source..source + SECTOR as usize]);
            }
        }
    }
}

/// IRP_MJ_WRITE: setores inteiros para a sobreposição; uma página nova
/// começa com o conteúdo do disco.
fn write(volume: &Volume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let length = stack.parameters.write.length.get() as u64;
    let offset = stack.parameters.write.byte_offset.quad_part.get();
    if offset < 0 || length % SECTOR != 0 || offset as u64 % SECTOR != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let first = offset as u64 / SECTOR;
    if first + length / SECTOR > volume.sectors {
        return (STATUS_END_OF_FILE, 0);
    }
    let buffer = transfer_buffer(irp);
    if buffer == 0 && length != 0 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let data = guest::read_bytes(buffer, length as usize);
    for index in 0..length / SECTOR {
        let sector = first + index;
        let page = sector / SECTORS_PER_PAGE;
        if !OVERLAY.lock().contains_key(&page) {
            let available = SECTORS_PER_PAGE.min(volume.sectors - page * SECTORS_PER_PAGE);
            let Ok(original) = ata_pio::read_sectors(page * SECTORS_PER_PAGE, available as u32, volume.drive) else {
                return (STATUS_DEVICE_DATA_ERROR, index * SECTOR);
            };
            let mut fresh = Box::new([0u8; PAGE]);
            fresh[..original.len()].copy_from_slice(&original);
            OVERLAY.lock().entry(page).or_insert(fresh);
        }
        let source = (index * SECTOR) as usize;
        let target = ((sector - page * SECTORS_PER_PAGE) * SECTOR) as usize;
        if let Some(stored) = OVERLAY.lock().get_mut(&page) {
            stored[target..target + SECTOR as usize].copy_from_slice(&data[source..source + SECTOR as usize]);
        }
    }
    (STATUS_SUCCESS, length)
}

/// Grava a resposta no SystemBuffer se couber: (status, Information).
fn reply(irp: &Irp, output_length: u64, bytes: &[u8]) -> (u32, u64) {
    if output_length < bytes.len() as u64 {
        return (STATUS_BUFFER_TOO_SMALL, 0);
    }
    guest::write_bytes(irp.associated_irp.system_buffer.get(), bytes);
    (STATUS_SUCCESS, bytes.len() as u64)
}

fn le32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn le64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

/// DISK_GEOMETRY: 255 cabeças e 63 setores por trilha, cilindros pelo tamanho.
fn geometry(volume: &Volume) -> Vec<u8> {
    let mut bytes = Vec::new();
    le64(&mut bytes, volume.sectors / (255 * 63));
    le32(&mut bytes, FIXED_MEDIA);
    le32(&mut bytes, 255);
    le32(&mut bytes, 63);
    le32(&mut bytes, SECTOR as u32);
    bytes
}

/// IRP_MJ_DEVICE_CONTROL com METHOD_BUFFERED.
fn device_control(volume: &Volume, irp: &Irp, stack: &IoStackLocation) -> (u32, u64) {
    let parameters = &stack.parameters.device_io_control;
    let code = parameters.io_control_code.get();
    let output_length = parameters.output_buffer_length.get() as u64;
    let input_length = parameters.input_buffer_length.get() as u64;
    let system_buffer = irp.associated_irp.system_buffer.get();
    let length = volume.sectors * SECTOR;
    match code {
        IOCTL_DISK_GET_DRIVE_GEOMETRY => reply(irp, output_length, &geometry(volume)),
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX => {
            let mut bytes = geometry(volume);
            le64(&mut bytes, length);
            bytes.extend_from_slice(&[0; 8]);
            reply(irp, output_length, &bytes)
        }
        IOCTL_DISK_GET_LENGTH_INFO => reply(irp, output_length, &length.to_le_bytes()),
        IOCTL_DISK_GET_PARTITION_INFO => {
            // PARTITION_INFORMATION: o disco inteiro, partição 0, PARTITION_IFS.
            let mut bytes = Vec::new();
            le64(&mut bytes, 0);
            le64(&mut bytes, length);
            le32(&mut bytes, 0);
            le32(&mut bytes, 0);
            bytes.extend_from_slice(&[PARTITION_IFS, 0, 1, 0]);
            bytes.extend_from_slice(&[0; 4]);
            reply(irp, output_length, &bytes)
        }
        IOCTL_DISK_GET_PARTITION_INFO_EX => {
            // PARTITION_INFORMATION_EX (0x90 bytes) no estilo MBR.
            let mut bytes = alloc::vec![0u8; 0x90];
            bytes[8..16].copy_from_slice(&0u64.to_le_bytes());
            bytes[16..24].copy_from_slice(&length.to_le_bytes());
            bytes[32] = PARTITION_IFS;
            bytes[34] = 1;
            reply(irp, output_length, &bytes)
        }
        IOCTL_DISK_IS_WRITABLE => (STATUS_SUCCESS, 0),
        IOCTL_DISK_CHECK_VERIFY | IOCTL_STORAGE_CHECK_VERIFY | IOCTL_STORAGE_CHECK_VERIFY2 => {
            if output_length >= 4 {
                reply(irp, output_length, &0u32.to_le_bytes())
            } else {
                (STATUS_SUCCESS, 0)
            }
        }
        IOCTL_STORAGE_GET_HOTPLUG_INFO => {
            // STORAGE_HOTPLUG_INFO: Size 8, disco fixo sem hotplug.
            let mut bytes = Vec::new();
            le32(&mut bytes, 8);
            bytes.extend_from_slice(&[0, 0, 0, 0]);
            reply(irp, output_length, &bytes)
        }
        IOCTL_STORAGE_GET_DEVICE_NUMBER => {
            let mut bytes = Vec::new();
            le32(&mut bytes, FILE_DEVICE_DISK);
            le32(&mut bytes, volume.drive as u32);
            le32(&mut bytes, 0);
            reply(irp, output_length, &bytes)
        }
        IOCTL_STORAGE_QUERY_PROPERTY => {
            if input_length < 8 {
                return (STATUS_INVALID_PARAMETER, 0);
            }
            let property = guest::read32(system_buffer);
            let query = guest::read32(system_buffer + 4);
            let descriptor: Option<Vec<u8>> = match property {
                STORAGE_ACCESS_ALIGNMENT_PROPERTY => {
                    let mut bytes = Vec::new();
                    for value in [0x1C, 0x1C, 64, 0, SECTOR as u32, SECTOR as u32, 0] {
                        le32(&mut bytes, value);
                    }
                    Some(bytes)
                }
                STORAGE_DEVICE_SEEK_PENALTY_PROPERTY | STORAGE_DEVICE_TRIM_PROPERTY => {
                    // Disco rotativo emulado: há penalidade de busca e não há TRIM.
                    let mut bytes = Vec::new();
                    le32(&mut bytes, 12);
                    le32(&mut bytes, 12);
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
        IOCTL_MOUNTDEV_QUERY_DEVICE_NAME => {
            let name: Vec<u8> = alloc::format!("\\Device\\{DEVICE_NAME}").encode_utf16().flat_map(u16::to_le_bytes).collect();
            mount_reply(irp, output_length, &name)
        }
        IOCTL_MOUNTDEV_QUERY_UNIQUE_ID => mount_reply(irp, output_length, DEVICE_NAME.as_bytes()),
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS => {
            let mut bytes = Vec::new();
            le32(&mut bytes, 1);
            le32(&mut bytes, 0);
            le32(&mut bytes, volume.drive as u32);
            le32(&mut bytes, 0);
            le64(&mut bytes, 0);
            le64(&mut bytes, length);
            reply(irp, output_length, &bytes)
        }
        _ => {
            if UNKNOWN_CONTROLS.lock().insert(code) {
                debug_print!("[atavol] IOCTL {:#x} sem suporte -> STATUS_INVALID_DEVICE_REQUEST", code);
            }
            (STATUS_INVALID_DEVICE_REQUEST, 0)
        }
    }
}

/// MOUNTDEV_NAME/MOUNTDEV_UNIQUE_ID: comprimento (USHORT) e os bytes; sem
/// espaço para tudo, só o comprimento com STATUS_BUFFER_OVERFLOW.
fn mount_reply(irp: &Irp, output_length: u64, payload: &[u8]) -> (u32, u64) {
    if output_length < 4 {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let buffer = irp.associated_irp.system_buffer.get();
    guest::write16(buffer, payload.len() as u16);
    if output_length < 2 + payload.len() as u64 {
        return (STATUS_BUFFER_OVERFLOW, 4);
    }
    guest::write_bytes(buffer + 2, payload);
    (STATUS_SUCCESS, 2 + payload.len() as u64)
}
