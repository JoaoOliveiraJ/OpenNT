//! O segundo disco IDE como dispositivo de volume do I/O Manager
//! (`\Device\AtaVolume1`), para os file systems reais montarem.
//!
//! Suporte de boot do driver ATA do kernel, não um substituto do disk.sys: o
//! disco inteiro é um volume (o NTFS que o xtask gera começa no setor 0), num
//! DEVICE_OBJECT nativo respondido pelo próprio kernel: o DRIVER_OBJECT dele
//! (`\Driver\AtaVolume`) tem em cada IRP_MJ_* a rotina `dispatch`, a mesma
//! resposta do IofCallDriver (`io_manager::register_pdo_native_answerer`). O
//! dispositivo nasce como o IoCreateDevice faz com um FILE_DEVICE_DISK: VPB
//! (IopCreateVpb), DeviceLock sinalizado, SectorSize 512, DO_DIRECT_IO e
//! alinhamento de palavra, e é montado pelo caminho do NT
//! (`io/file_system.rs::mount_volume`).
//!
//! O leitor NTFS do kernel continua dono do mesmo disco como D:, então o que
//! o file system grava não vai ao disco durante o boot: fica numa
//! sobreposição em memória, por página de 4 KB com os setores gravados
//! marcados, e é o que as leituras seguintes do volume devolvem (o disco e o
//! leitor do kernel continuam vendo a imagem do boot). A sobreposição é o
//! cache de escrita do dispositivo: no desligamento o volume, registrado na
//! fila de última chance (IoRegisterLastChanceShutdownNotification, depois
//! dos file systems), recebe o IRP_MJ_SHUTDOWN e grava no disco só os
//! setores que o file system gravou, seguidos do FLUSH CACHE do drive; dali
//! em diante as escritas vão direto ao disco. Para o file system o volume é
//! um disco gravável comum. IRP_MJ_READ lê setores
//! inteiros para o buffer do MDL (DO_DIRECT_IO) pelo DMA do driver ATA e
//! aplica a sobreposição; IRP_MJ_WRITE grava nela. Os IOCTLs de disco,
//! armazenamento e mount manager que um file system pede na montagem são
//! respondidos com a geometria real do disco (IDENTIFY DEVICE); os demais
//! dão STATUS_INVALID_DEVICE_REQUEST, registrados uma vez na serial.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::drivers::storage::ata_pio;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, IoStackLocation, Irp, Mdl};
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
const IO_TYPE_DRIVER: i16 = 4;
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
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
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
const IRP_MJ_SHUTDOWN: u8 = 0x10;
const IRP_MJ_CLEANUP: u8 = 0x12;

const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x0007_0000;
const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x0007_4004;
const IOCTL_DISK_IS_WRITABLE: u32 = 0x0007_0024;
const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x0007_0048;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x0007_405C;
const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x0007_00A0;
const IOCTL_DISK_GET_CLUSTER_INFO: u32 = 0x0007_0214;
/// DISK_CLUSTER_INFO.Version (o tamanho da estrutura).
const DISK_CLUSTER_INFO_SIZE: u32 = 0x20;
const IOCTL_DISK_CHECK_VERIFY: u32 = 0x0007_4800;
const IOCTL_DISK_MEDIA_REMOVAL: u32 = 0x0007_4804;
const IOCTL_STORAGE_MEDIA_REMOVAL: u32 = 0x002D_4804;
const IOCTL_STORAGE_CHECK_VERIFY: u32 = 0x002D_4800;
const IOCTL_STORAGE_CHECK_VERIFY2: u32 = 0x002D_0800;
const IOCTL_STORAGE_GET_HOTPLUG_INFO: u32 = 0x002D_0C14;
const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002D_1080;
const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: u32 = 0x004D_0000;
const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D_0008;
const IOCTL_MOUNTDEV_QUERY_STABLE_GUID: u32 = 0x004D_0018;
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
/// Uma página de 4 KB da sobreposição: os bytes e os setores (bit por setor)
/// que o file system gravou.
struct OverlayPage {
    data: Box<[u8; PAGE]>,
    dirty: u8,
}

/// Páginas gravadas pelo file system (índice da página -> página).
static OVERLAY: SpinLock<BTreeMap<u64, OverlayPage>> = SpinLock::new(BTreeMap::new());
const PAGE: usize = 4096;
const SECTORS_PER_PAGE: u64 = PAGE as u64 / SECTOR;
static UNKNOWN_CONTROLS: SpinLock<BTreeSet<u32>> = SpinLock::new(BTreeSet::new());
/// O IRP_MJ_SHUTDOWN já gravou a sobreposição: as escritas vão ao disco.
static WRITE_THROUGH: AtomicBool = AtomicBool::new(false);
/// Setores gravados no disco pelo desligamento.
static COMMITTED: AtomicU64 = AtomicU64::new(0);

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
    object.driver_object.set(driver_object(address)?);
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
    // Depois dos file systems no desligamento: o cache de escrita vai ao disco.
    crate::ntos::io::shutdown::register_last_chance(address)?;
    debug_print!("[atavol] \\Device\\{} criado sobre o drive {} ({} setores, escrita em memoria)", DEVICE_NAME, drive, sectors);
    Ok(address)
}

/// O DRIVER_OBJECT do volume (`\Driver\AtaVolume`, como o de um driver de
/// disco): todas as rotinas IRP_MJ_* apontam para `dispatch`, que o próprio
/// kernel responde. Um file system pode chamar a rotina do dispositivo alvo
/// sem o IofCallDriver (o NtfsFlushDiskCache do ntfs.sys monta o
/// IRP_MJ_FLUSH_BUFFERS e chama o MajorFunction direto).
fn driver_object(device: u64) -> Result<u64, KernelError> {
    let name: Vec<u16> = "\\Driver\\AtaVolume".encode_utf16().collect();
    let block = guest::alloc_bytes(DriverObject::SIZE + DriverExtension::SIZE + (name.len() as u64 + 1) * 2);
    if block == 0 {
        return Err(KernelError::new("volume ATA: DRIVER_OBJECT sem memoria"));
    }
    let entry: extern "win64" fn(u64, u64) -> i32 = dispatch;
    let routine = crate::ntos::mm::kernel_address::image_address(entry as usize as u64)?;
    // SAFETY: bloco recém-alocado: o DRIVER_OBJECT, a extensão e o nome.
    let (driver, extension) = unsafe { (DriverObject::at(block), DriverExtension::at(block + DriverObject::SIZE)) };
    driver.type_.set(IO_TYPE_DRIVER);
    driver.size.set(DriverObject::SIZE as i16);
    driver.device_object.set(device);
    driver.driver_extension.set(extension.address());
    extension.driver_object.set(block);
    let text = block + DriverObject::SIZE + DriverExtension::SIZE;
    guest::write_bytes(text, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    driver.driver_name.length.set(name.len() as u16 * 2);
    driver.driver_name.maximum_length.set(name.len() as u16 * 2 + 2);
    driver.driver_name.buffer.set(text);
    for routine_cell in &driver.major_function {
        routine_cell.set(routine);
    }
    Ok(block)
}

/// A rotina de despacho do DRIVER_OBJECT do volume.
extern "win64" fn dispatch(device: u64, packet: u64) -> i32 {
    answer(device, packet).unwrap_or(STATUS_INVALID_DEVICE_REQUEST as i32)
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
        IRP_MJ_SHUTDOWN => commit(&volume),
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
    for (&page, stored) in overlay.range(first / SECTORS_PER_PAGE..=(first + count - 1) / SECTORS_PER_PAGE) {
        let data = &stored.data;
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
    if WRITE_THROUGH.load(Ordering::Acquire) {
        return match ata_pio::write_sectors(first, &data, volume.drive) {
            Ok(()) => (STATUS_SUCCESS, length),
            Err(error) => {
                debug_print!("[atavol] escrita do setor {} falhou: {}", first, error);
                (STATUS_DEVICE_DATA_ERROR, 0)
            }
        };
    }
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
            OVERLAY.lock().entry(page).or_insert(OverlayPage { data: fresh, dirty: 0 });
        }
        let source = (index * SECTOR) as usize;
        let slot = sector - page * SECTORS_PER_PAGE;
        let target = (slot * SECTOR) as usize;
        if let Some(stored) = OVERLAY.lock().get_mut(&page) {
            stored.data[target..target + SECTOR as usize].copy_from_slice(&data[source..source + SECTOR as usize]);
            stored.dirty |= 1 << slot;
        }
    }
    (STATUS_SUCCESS, length)
}

/// IRP_MJ_SHUTDOWN: os setores gravados da sobreposição vão ao disco, em
/// séries contíguas, e o drive descarrega o cache dele (FLUSH CACHE). As
/// páginas gravadas saem da sobreposição e as escritas seguintes vão direto
/// ao disco.
fn commit(volume: &Volume) -> (u32, u64) {
    let pages = core::mem::take(&mut *OVERLAY.lock());
    WRITE_THROUGH.store(true, Ordering::Release);
    let mut sectors: Vec<(u64, &[u8])> = Vec::new();
    for (&page, stored) in &pages {
        for slot in 0..SECTORS_PER_PAGE {
            if stored.dirty & (1 << slot) != 0 {
                let offset = (slot * SECTOR) as usize;
                sectors.push((page * SECTORS_PER_PAGE + slot, &stored.data[offset..offset + SECTOR as usize]));
            }
        }
    }
    let mut index = 0;
    let mut written = 0u64;
    while index < sectors.len() {
        let first = sectors[index].0;
        let mut run = Vec::new();
        while index < sectors.len() && sectors[index].0 == first + (run.len() as u64 / SECTOR) && (run.len() as u64) < CHUNK_SECTORS * SECTOR {
            run.extend_from_slice(sectors[index].1);
            index += 1;
        }
        if let Err(error) = ata_pio::write_sectors(first, &run, volume.drive) {
            debug_print!("[atavol] desligamento: gravacao do setor {} falhou: {}", first, error);
            return (STATUS_DEVICE_DATA_ERROR, 0);
        }
        written += run.len() as u64 / SECTOR;
    }
    let flushed = ata_pio::flush(volume.drive);
    COMMITTED.fetch_add(written, Ordering::AcqRel);
    debug_print!("[atavol] desligamento: {} setores gravados no disco, FLUSH CACHE {}", written, if flushed.is_ok() { "ok" } else { "falhou" });
    (if flushed.is_ok() { STATUS_SUCCESS } else { STATUS_DEVICE_DATA_ERROR }, 0)
}

/// Setores da sobreposição gravados no disco pelo desligamento.
pub fn committed_sectors() -> u64 {
    COMMITTED.load(Ordering::Acquire)
}

/// Setores gravados pelo file system que ainda estão só na sobreposição.
pub fn pending_sectors() -> u64 {
    OVERLAY.lock().values().map(|page| page.dirty.count_ones() as u64).sum()
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
        // DISK_CLUSTER_INFO como o partmgr.sys responde por um disco que não é
        // de cluster: Version = 0x20 e Flags, FlagsMask e Notify zerados (o
        // storqosflt pergunta se o volume é um CSV oculto).
        IOCTL_DISK_GET_CLUSTER_INFO => {
            let mut bytes = alloc::vec![0u8; DISK_CLUSTER_INFO_SIZE as usize];
            bytes[..4].copy_from_slice(&DISK_CLUSTER_INFO_SIZE.to_le_bytes());
            reply(irp, output_length, &bytes)
        }
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
        // PREVENT_MEDIA_REMOVAL num disco fixo: o ClassDeviceControl do
        // classpnp traduz o IOCTL de disco para o de armazenamento e o
        // ClasspEjectionControl só conta a trava (sem mídia removível não há
        // comando ao dispositivo); a entrada menor que o BOOLEAN é recusada.
        IOCTL_DISK_MEDIA_REMOVAL | IOCTL_STORAGE_MEDIA_REMOVAL => {
            if input_length < 1 {
                return (STATUS_INFO_LENGTH_MISMATCH, 0);
            }
            (STATUS_SUCCESS, 0)
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
        IOCTL_MOUNTDEV_QUERY_STABLE_GUID => reply(irp, output_length, &stable_guid(volume)),
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

/// MOUNTDEV_STABLE_GUID: o GUID estável do volume, que o gerenciador de
/// volumes devolve para o FsRtlVolumeDeviceToCorrelationId dos file systems.
/// Aqui ele sai do próprio disco: "OPEN" e "AT" em Data1/Data2, o drive em
/// Data3 e a capacidade em setores em Data4, o mesmo a cada boot.
fn stable_guid(volume: &Volume) -> Vec<u8> {
    let mut bytes = Vec::new();
    le32(&mut bytes, u32::from_be_bytes(*b"OPEN"));
    bytes.extend_from_slice(&u16::from_be_bytes(*b"AT").to_le_bytes());
    bytes.extend_from_slice(&(0x4100 | volume.drive as u16).to_le_bytes());
    le64(&mut bytes, volume.sectors);
    bytes
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
