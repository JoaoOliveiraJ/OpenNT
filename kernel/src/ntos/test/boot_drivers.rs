//! Conferência dos drivers reais iniciados por `--start-driver`: depois do
//! DRIVER_START_COMPLETED, com o anel 3 armado, o que o driver publicou é
//! usado como um programa usaria, e o resultado vai à serial.
//!
//! - null.sys: um processo de teste abre \Device\Null pelo NtCreateFile; a
//!   leitura devolve STATUS_END_OF_FILE sem tocar no buffer e a escrita
//!   conclui com o tamanho inteiro (o despacho do driver, por IRPs neither).
//! - beep.sys: o processo abre \Device\Beep, deixa pendente o IOCTL de
//!   redirecionamento da sessão (0x10004) e manda IOCTL_BEEP_SET: o pedido
//!   passa pelo IoStartPacket, pela DeviceQueue e pelo StartIo do driver, que
//!   entrega a frequência e a duração ao redirecionamento e chama o
//!   IoStartNextPacket (adiado, DOE_SIO_DEFERRED); sem redirecionamento o
//!   StartIo conclui com STATUS_NOT_FOUND, e um tom sem duração conclui sem
//!   passar pela fila.
//! - fs_rec.sys: os reconhecedores registrados pelo IoRegisterFileSystem
//!   estão nas filas de disco e de CD-ROM, e cada reconhecedor de disco
//!   responde a um IRP_MN_MOUNT_VOLUME sobre o volume NTFS do segundo disco
//!   (lido por um DEVICE_OBJECT de teste, criado pelo IoCreateDriver, que
//!   serve os setores e a geometria) sem montar nada.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{DeviceObject, DevobjExtension, IoStackLocation, Irp, NtStruct};
use crate::ntos::io::{file_system, io_manager};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::user::{memory, state};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

const STATUS_PENDING: u32 = 0x103;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
const STATUS_FS_DRIVER_REQUIRED: u32 = 0xC000_019C;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const IOCTL_BEEP_SET: u64 = 0x1_0000;
/// O IOCTL com que o componente da sessão recebe os tons (beep.sys).
const IOCTL_BEEP_REDIRECT: u64 = 0x1_0004;
const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x7_0000;
const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x7_405C;
const FILE_DEVICE_DISK: u64 = 7;
const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 3;
const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 8;
const DOE_SIO_DEFERRED: u32 = 0x100;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_DEVICE_CONTROL: u8 = 0xE;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0xD;
const IRP_MN_MOUNT_VOLUME: u8 = 1;
/// O segundo disco IDE, com o volume NTFS a partir do setor 0.
const NTFS_DRIVE: u8 = 1;

/// Inicia a conferência do driver dado, quando há uma para ele.
pub fn after_start(name: &str) {
    match name.to_ascii_lowercase().as_str() {
        "null" => null_device(),
        "beep" => beep_device(),
        "fs_rec" => file_system_recognizers(),
        _ => {}
    }
}

/// Chamadas de sistema de um processo de teste pelos handlers de usuário,
/// com os ponteiros e os buffers numa região de usuário dele.
struct UserCalls {
    block: u64,
}

impl UserCalls {
    const HANDLE: u64 = 0x000;
    const NAME: u64 = 0x100;
    const ATTRIBUTES: u64 = 0x200;
    const IOSB: u64 = 0x300;
    const SECOND_IOSB: u64 = 0x320;
    const DATA: u64 = 0x400;
    const RSP: u64 = 0x800;

    fn new() -> Option<Self> {
        memory::map_user_region(0x1000).ok().map(|block| Self { block })
    }

    fn at(&self, offset: u64) -> u64 {
        self.block + offset
    }

    /// Argumentos 5 em diante, em [rsp+0x28]...
    fn stack(&self, arguments: &[u64]) {
        for (index, value) in arguments.iter().enumerate() {
            guest::write64(self.at(Self::RSP) + 0x28 + index as u64 * 8, *value);
        }
    }

    fn call(&self, name: &str, arguments: [u64; 4]) -> u32 {
        state::handler(name).and_then(|handler| handler(arguments[0], arguments[1], arguments[2], arguments[3], self.at(Self::RSP)).ok()).unwrap_or(u32::MAX)
    }

    fn iosb(&self, offset: u64) -> (u32, u64) {
        (guest::read32(self.at(offset)), guest::read64(self.at(offset) + 8))
    }

    /// NtCreateFile(GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, FILE_OPEN,
    /// FILE_SYNCHRONOUS_IO_NONALERT) do caminho: o status e o handle.
    fn open(&self, path: &str) -> (u32, u64) {
        let units: Vec<u16> = path.encode_utf16().collect();
        let (name, text) = (self.at(Self::NAME), self.at(Self::NAME) + 0x10);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(text + index as u64 * 2, *unit);
        }
        guest::write16(name, units.len() as u16 * 2);
        guest::write16(name + 2, units.len() as u16 * 2);
        guest::write64(name + 8, text);
        let attributes = self.at(Self::ATTRIBUTES);
        guest::write_bytes(attributes, &[0; 0x30]);
        guest::write32(attributes, 0x30);
        guest::write64(attributes + 0x10, name);
        guest::write32(attributes + 0x18, 0x40);
        self.stack(&[0, 0, 3, 1, 0x20, 0, 0]);
        let status = self.call("NtCreateFile", [self.at(Self::HANDLE), 0xC010_0000, attributes, self.at(Self::IOSB)]);
        (status, guest::read64(self.at(Self::HANDLE)))
    }

    /// NtDeviceIoControlFile síncrono (sem evento) com o IOSB em `iosb`.
    fn ioctl(&self, handle: u64, iosb: u64, code: u64, input: u64, input_length: u64, output: u64, output_length: u64) -> u32 {
        self.stack(&[self.at(iosb), code, input, input_length, output, output_length]);
        self.call("NtDeviceIoControlFile", [handle, 0, 0, 0])
    }

    fn close(&self, handle: u64) -> u32 {
        self.call("NtClose", [handle, 0, 0, 0])
    }
}

/// O DEVICE_OBJECT nativo publicado num caminho \Device\X.
fn device_at_path(path: &str) -> Option<&'static DeviceObject> {
    let node = object_manager::lookup(path)?;
    let native = io_manager::device(node)?.native_device;
    // SAFETY: DEVICE_OBJECT vivo de um driver carregado.
    (native != 0).then(|| unsafe { DeviceObject::at(native) })
}

fn null_device() {
    let outcome = with_test_process("null-teste.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open("\\Device\\Null");
        let data = user.at(UserCalls::DATA);
        guest::write_bytes(data, &[0x5A; 0x100]);
        user.stack(&[user.at(UserCalls::IOSB), data, 64, 0, 0]);
        let read = user.call("NtReadFile", [handle, 0, 0, 0]);
        let read_iosb = user.iosb(UserCalls::IOSB);
        let untouched = guest::read_bytes(data, 64).iter().all(|&byte| byte == 0x5A);
        user.stack(&[user.at(UserCalls::IOSB), data, 77, 0, 0]);
        let written = user.call("NtWriteFile", [handle, 0, 0, 0]);
        let write_iosb = user.iosb(UserCalls::IOSB);
        let closed = user.close(handle);
        Some((opened, read, read_iosb, untouched, written, write_iosb, closed))
    })
    .flatten();
    let Some((opened, read, read_iosb, untouched, written, write_iosb, closed)) = outcome else {
        debug_print!("[null] processo de teste nao montado");
        return;
    };
    debug_print!("[null] \\Device\\Null: abertura={:#x} leitura={:#x} (iosb {:#x}, {} bytes, buffer intacto={}) escrita={:#x} (iosb {:#x}, {} bytes) fechamento={:#x}", opened, read, read_iosb.0, read_iosb.1, untouched, written, write_iosb.0, write_iosb.1, closed);
    if opened == 0 && read == STATUS_END_OF_FILE && read_iosb.1 == 0 && untouched && written == 0 && write_iosb == (0, 77) && closed == 0 {
        debug_print!("NULL_DEVICE_OK leitura=EOF escrita=77");
    }
}

fn beep_device() {
    let outcome = with_test_process("beep-teste.exe", None, |_| {
        let user = UserCalls::new()?;
        let (opened, handle) = user.open("\\Device\\Beep");
        let (tone, redirected) = (user.at(UserCalls::DATA), user.at(UserCalls::DATA) + 0x40);
        guest::write_bytes(redirected, &[0xEE; 8]);
        // O componente da sessão espera os tons: o IOCTL fica pendente na CSQ do driver.
        let waiting = user.ioctl(handle, UserCalls::SECOND_IOSB, IOCTL_BEEP_REDIRECT, 0, 0, redirected, 8);
        // BEEP_SET_PARAMETERS { Frequency 440, Duration 100 }.
        guest::write32(tone, 440);
        guest::write32(tone + 4, 100);
        let beep = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let delivered = (user.iosb(UserCalls::SECOND_IOSB), guest::read32(redirected), guest::read32(redirected + 4));
        let device = device_at_path("\\Device\\Beep");
        let queue = device.map(|device| {
            // SAFETY: a DEVOBJ_EXTENSION do DEVICE_OBJECT vivo.
            let extension = unsafe { DevobjExtension::at(device.device_object_extension.get()) };
            (device.device_queue.busy.get(), device.current_irp.get(), extension.start_io_flags.get() & DOE_SIO_DEFERRED != 0, extension.start_io_count.get())
        });
        // Sem redirecionamento pendente: o StartIo conclui com STATUS_NOT_FOUND.
        let alone = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let alone_iosb = user.iosb(UserCalls::IOSB);
        // Frequência sem duração: concluído no despacho, sem a fila.
        guest::write32(tone + 4, 0);
        let instant = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 8, 0, 0);
        let short = user.ioctl(handle, UserCalls::IOSB, IOCTL_BEEP_SET, tone, 4, 0, 0);
        let closed = user.close(handle);
        Some((opened, waiting, beep, delivered, queue, alone, alone_iosb, instant, short, closed))
    })
    .flatten();
    let Some((opened, waiting, beep, delivered, queue, alone, alone_iosb, instant, short, closed)) = outcome else {
        debug_print!("[beep] processo de teste nao montado");
        return;
    };
    let ((redirect_status, redirect_bytes), frequency, duration) = delivered;
    debug_print!("[beep] \\Device\\Beep: abertura={:#x} redirecionamento={:#x} BEEP_SET={:#x} entregue=({:#x}, {} bytes, {} Hz, {} ms) fila={:?} sem-redirecionamento={:#x}/{:#x} tom-sem-duracao={:#x} curto={:#x} fechamento={:#x}", opened, waiting, beep, redirect_status, redirect_bytes, frequency, duration, queue, alone, alone_iosb.0, instant, short, closed);
    let queue_ok = queue == Some((0, 0, true, 0));
    if opened == 0 && waiting == STATUS_PENDING && beep == 0 && (redirect_status, redirect_bytes, frequency, duration) == (0, 8, 440, 100) && queue_ok && alone == STATUS_NOT_FOUND && instant == 0 && short == 0xC000_000D && closed == 0 {
        debug_print!("BEEP_DEVICE_OK StartIo=440Hz/100ms fila=livre");
    }
}

// ---- fs_rec.sys --------------------------------------------------------------

/// O DEVICE_OBJECT de teste do volume e os setores dele.
static VOLUME_DEVICE: AtomicU64 = AtomicU64::new(0);
static VOLUME_SECTORS: AtomicU64 = AtomicU64::new(0);

/// Despacho do volume de teste: IRP_MJ_READ do segundo disco e os IOCTLs de
/// geometria e tamanho que o fs_rec pede.
extern "win64" fn volume_dispatch(_device: u64, packet: u64) -> u32 {
    // SAFETY: o IRP vivo que o I/O Manager entrega ao despacho.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: CurrentStackLocation de um IRP vivo.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let buffer = match irp.associated_irp.system_buffer.get() {
        0 => irp.user_buffer.get(),
        system => system,
    };
    let (status, information) = match location.major_function.get() {
        IRP_MJ_READ => {
            let (length, offset) = (location.parameters.read.length.get(), location.parameters.read.byte_offset.quad_part.get() as u64);
            match crate::drivers::storage::ata_pio::read_sectors(offset / 512, length.div_ceil(512), NTFS_DRIVE) {
                Ok(bytes) if buffer != 0 => {
                    guest::write_bytes(buffer, &bytes[..length as usize]);
                    (0, length as u64)
                }
                _ => (0xC000_0185, 0),
            }
        }
        IRP_MJ_DEVICE_CONTROL => {
            let sectors = VOLUME_SECTORS.load(Ordering::SeqCst);
            match location.parameters.device_io_control.io_control_code.get() {
                IOCTL_DISK_GET_LENGTH_INFO => {
                    guest::write64(buffer, sectors * 512);
                    (0, 8)
                }
                IOCTL_DISK_GET_DRIVE_GEOMETRY => {
                    // DISK_GEOMETRY: Cylinders, FixedMedia, 255 trilhas, 63 setores, 512 bytes.
                    guest::write64(buffer, sectors / (255 * 63));
                    guest::write32(buffer + 8, 12);
                    guest::write32(buffer + 12, 255);
                    guest::write32(buffer + 16, 63);
                    guest::write32(buffer + 20, 512);
                    (0, 0x18)
                }
                _ => (STATUS_INVALID_DEVICE_REQUEST, 0),
            }
        }
        _ => (0, 0),
    };
    irp.io_status.status.set(status as i32);
    irp.io_status.information.set(information);
    let _ = call_export("IofCompleteRequest", &[packet, 0]);
    status
}

/// DriverEntry do volume de teste (IoCreateDriver): o despacho e o
/// DEVICE_OBJECT de disco.
extern "win64" fn volume_driver_entry(driver: u64, _registry: u64) -> u32 {
    use crate::ntos::inc::types::DriverObject;
    // SAFETY: o DRIVER_OBJECT que o IoCreateDriver acabou de criar.
    let driver_object = unsafe { DriverObject::at(driver) };
    let dispatch = volume_dispatch as extern "win64" fn(u64, u64) -> u32 as usize as u64;
    for major in [0usize, 2, IRP_MJ_READ as usize, IRP_MJ_DEVICE_CONTROL as usize] {
        driver_object.major_function[major].set(dispatch);
    }
    let block = guest::alloc_bytes(0x80);
    let name = "\\Device\\OpenNtFsRecVolume";
    let units: Vec<u16> = name.encode_utf16().collect();
    for (index, unit) in units.iter().enumerate() {
        guest::write16(block + 0x20 + index as u64 * 2, *unit);
    }
    guest::write16(block, units.len() as u16 * 2);
    guest::write16(block + 2, units.len() as u16 * 2);
    guest::write64(block + 8, block + 0x20);
    let status = call_export("IoCreateDevice", &[driver, 0, block, FILE_DEVICE_DISK, 0, 0, block + 0x10]).unwrap_or(1) as u32;
    let device = guest::read64(block + 0x10);
    if status == 0 && device != 0 {
        // SAFETY: o DEVICE_OBJECT recém-criado.
        let flags = &unsafe { DeviceObject::at(device) }.flags;
        flags.set(flags.get() & !0x80);
        VOLUME_DEVICE.store(device, Ordering::SeqCst);
    }
    guest::free_bytes(block);
    status
}

/// IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_MOUNT_VOLUME ao reconhecedor, com o
/// VPB e o dispositivo do volume em Parameters.MountVolume.
fn mount_request(recognizer: &DeviceObject, volume: u64) -> u32 {
    let stack_count = (recognizer.stack_size.get() as u8).max(1) as u32;
    let packet = guest::alloc_bytes(irp_builder::size_for(stack_count));
    let vpb = guest::alloc_bytes(0x60);
    guest::write_bytes(vpb, &[0; 0x60]);
    irp_builder::build(packet, &BuildOptions { major: IRP_MJ_FILE_SYSTEM_CONTROL, minor: IRP_MN_MOUNT_VOLUME, device_object: recognizer.address(), stack_count, ..BuildOptions::default() });
    // SAFETY: o IRP recém-montado e o slot do topo dele.
    let location = unsafe { IoStackLocation::at(Irp::at(packet).tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    location.parameters.mount_volume.vpb.set(vpb);
    location.parameters.mount_volume.device_object.set(volume);
    let status = io_manager::iof_call_driver(recognizer.address(), packet) as u32;
    guest::free_bytes(packet);
    guest::free_bytes(vpb);
    status
}

fn file_system_recognizers() {
    // (nome, fila, é o reconhecedor de NTFS).
    let recognizers = [
        ("NtfsRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("FatDiskRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ExFatRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ReFSRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("ReFSv1Recognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("UdfsDiskRecognizer", FILE_DEVICE_DISK_FILE_SYSTEM),
        ("FatCdRomRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
        ("UdfsCdRomRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
        ("CdfsRecognizer", FILE_DEVICE_CD_ROM_FILE_SYSTEM),
    ];
    let mut present = Vec::new();
    let mut misplaced = 0;
    for (name, queue) in recognizers {
        let Some(device) = device_at_path(&alloc::format!("\\FileSystem\\{name}")) else { continue };
        if !file_system::registered_file_systems(queue).contains(&device.address()) {
            misplaced += 1;
        }
        present.push((name, queue, device));
    }
    let listed: Vec<&str> = present.iter().map(|&(name, _, _)| name).collect();
    debug_print!("[fs_rec] reconhecedores registrados: {:?} (fora da fila certa: {})", listed, misplaced);
    // O volume NTFS do segundo disco, servido pelo DEVICE_OBJECT de teste.
    let boot = crate::drivers::storage::ata_pio::read_sectors(0, 1, NTFS_DRIVE).unwrap_or_default();
    if boot.len() < 0x30 {
        debug_print!("[fs_rec] segundo disco ilegivel");
        return;
    }
    // Setores do volume (+1 do setor de boot de reserva no fim).
    VOLUME_SECTORS.store(u64::from_le_bytes(boot[0x28..0x30].try_into().unwrap_or([0; 8])) + 1, Ordering::SeqCst);
    let entry = volume_driver_entry as extern "win64" fn(u64, u64) -> u32 as usize as u64;
    let created = call_export("IoCreateDriver", &[0, entry]).unwrap_or(1) as u32;
    let volume = VOLUME_DEVICE.load(Ordering::SeqCst);
    if created != 0 || volume == 0 {
        debug_print!("[fs_rec] volume de teste nao criado: {:#x}", created);
        return;
    }
    let mut all_answered = !present.is_empty() && misplaced == 0;
    let mut ntfs_recognized = false;
    for &(name, queue, device) in present.iter().filter(|&&(_, queue, _)| queue == FILE_DEVICE_DISK_FILE_SYSTEM) {
        let status = mount_request(device, volume);
        let expected = if name == "NtfsRecognizer" { STATUS_FS_DRIVER_REQUIRED } else { STATUS_UNRECOGNIZED_VOLUME };
        ntfs_recognized |= name == "NtfsRecognizer" && status == STATUS_FS_DRIVER_REQUIRED;
        all_answered &= status == expected;
        debug_print!("[fs_rec] IRP_MN_MOUNT_VOLUME do volume NTFS -> {} (fila {}): {:#x}", name, queue, status);
    }
    // O reconhecedor de NTFS só existe sem um \Ntfs no namespace.
    let ntfs_expected = listed.contains(&"NtfsRecognizer");
    debug_print!("[fs_rec] volume NTFS reconhecido pelo NtfsRecognizer: {} (reconhecedor presente: {})", ntfs_recognized, ntfs_expected);
    if all_answered && ntfs_recognized == ntfs_expected {
        debug_print!("FS_REC_OK reconhecedores={} ntfs={}", present.len(), if ntfs_recognized { "STATUS_FS_DRIVER_REQUIRED" } else { "sem reconhecedor" });
    }
}
