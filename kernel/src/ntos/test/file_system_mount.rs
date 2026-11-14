//! Montagem de um volume por um file system real, depois do
//! `--start-driver=<serviço>` de um driver de file system (Type = 2).
//!
//! Com o driver rodando, o volume do segundo disco IDE vira um dispositivo
//! (`drivers/storage/ata_volume.rs`) e um arquivo conhecido do volume é
//! aberto e lido pelos exports, como um driver faria: ZwCreateFile em
//! `\Device\AtaVolume1\HELLO.TXT` (o IopParseDevice monta o volume pelo
//! IopMountVolume, com o IRP_MN_MOUNT_VOLUME ao file system registrado),
//! ZwReadFile (IRP_MJ_READ ao dispositivo de volume do file system, que lê
//! pelo Cache Manager) e ZwClose. Os bytes são comparados com os que o
//! leitor NTFS do kernel lê do mesmo arquivo. A serial mostra cada passo e,
//! no fim, `FILE_SYSTEM_MOUNT_OK name=<serviço>` ou a falha.
//!
//! `run` (fase 6) cobre o mesmo caminho com dois file systems sintéticos
//! sobre o volume: o IoCreateDevice de um FILE_DEVICE_DISK dá VPB, DeviceLock
//! e SectorSize; o primeiro file system da fila recusa a montagem
//! (STATUS_UNRECOGNIZED_VOLUME), o segundo aceita com o seu dispositivo de
//! volume; o VPB fica montado e o IRP_MJ_CREATE chega ao dispositivo de
//! volume com o FILE_OBJECT e os parâmetros do NT; uma segunda abertura não
//! monta de novo; o fechamento manda CLEANUP e CLOSE e devolve as
//! referências do VPB.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::drivers::storage::ata_volume;
use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::test::phase6::call_export;

/// O arquivo de texto que o xtask grava na raiz do volume.
const KNOWN_FILE: &str = "HELLO.TXT";
const FILE_GENERIC_READ: u64 = 0x0012_0089;
const FILE_SHARE_READ: u64 = 1;
const FILE_OPEN: u64 = 1;
const FILE_SYNCHRONOUS_IO_NONALERT: u64 = 0x20;
const FILE_NON_DIRECTORY_FILE: u64 = 0x40;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos do convidado alocados por este teste.
    unsafe { T::at(address) }
}

/// OBJECT_ATTRIBUTES com o UNICODE_STRING do nome, no bloco dado.
fn object_attributes(block: u64, name: &str) -> u64 {
    let units: Vec<u16> = name.encode_utf16().collect();
    let text = block + 0x80;
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    let unicode = at::<nt::UnicodeString>(block + 0x40);
    unicode.length.set(units.len() as u16 * 2);
    unicode.maximum_length.set(units.len() as u16 * 2);
    unicode.buffer.set(text);
    let attributes = at::<nt::ObjectAttributes>(block);
    attributes.length.set(48);
    attributes.object_name.set(unicode.address());
    attributes.attributes.set(OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
    block
}

fn service_type(name: &str) -> u32 {
    crate::ntos::cm::service::database::read(name).ok().flatten().map_or(0, |configuration| configuration.service_type)
}

/// Depois do início de um driver pelo `--start-driver`.
pub fn after_driver_start(name: &str) {
    if service_type(name) != 2 {
        return;
    }
    match mount_and_read() {
        Ok(()) => debug_print!("FILE_SYSTEM_MOUNT_OK name={}", name),
        Err(message) => debug_print!("FILE_SYSTEM_MOUNT_FALHOU name={}: {}", name, message),
    }
}

fn mount_and_read() -> Result<(), alloc::string::String> {
    use alloc::format;
    let expected = crate::drivers::fs::ntfs::mounted().and_then(|volume| volume.read_bytes(&format!("/{KNOWN_FILE}")).ok().flatten()).ok_or("o leitor do kernel nao achou o arquivo conhecido")?;
    let device = ata_volume::create(1).map_err(|error| format!("dispositivo do volume: {error}"))?;
    let block = guest::alloc_bytes(0x400);
    let path = format!("\\Device\\{}\\{}", ata_volume::DEVICE_NAME, KNOWN_FILE);
    let attributes = object_attributes(block, &path);
    let (handle, iosb, buffer, offset) = (block + 0x300, block + 0x310, guest::alloc_bytes(0x1000), block + 0x320);
    let created = call_export("ZwCreateFile", &[handle, FILE_GENERIC_READ, attributes, iosb, 0, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0]).unwrap_or(u64::MAX) as u32;
    // SAFETY: o DEVICE_OBJECT do volume e o seu VPB.
    let vpb_address = at::<nt::DeviceObject>(device).vpb.get();
    let vpb = at::<nt::Vpb>(vpb_address);
    debug_print!("[fs-mount] ZwCreateFile({}) -> {:#x}, Information {}; VPB flags {:#x}, volume {:#x}", path, created, guest::read64(iosb + 8), vpb.flags.get(), vpb.device_object.get());
    if created != 0 {
        return Err(format!("ZwCreateFile devolveu {created:#x}"));
    }
    let file_handle = guest::read64(handle);
    guest::write64(offset, 0);
    let read = call_export("ZwReadFile", &[file_handle, 0, 0, 0, iosb, buffer, 0x1000, offset, 0]).unwrap_or(u64::MAX) as u32;
    let count = guest::read64(iosb + 8) as usize;
    let bytes = guest::read_bytes(buffer, count.min(0x1000));
    let file_object = crate::ntos::io::file::zw::file_object_of_handle(file_handle);
    let pointers = if file_object != 0 { at::<nt::FileObject>(file_object).section_object_pointer.get() } else { 0 };
    let cached = pointers != 0 && at::<nt::SectionObjectPointers>(pointers).shared_cache_map.get() != 0;
    debug_print!("[fs-mount] ZwReadFile -> {:#x}, {} bytes, SharedCacheMap {}: {:?}", read, count, if cached { "presente" } else { "ausente" }, core::str::from_utf8(&bytes).unwrap_or("<binario>"));
    let closed = call_export("ZwClose", &[file_handle]).unwrap_or(u64::MAX) as u32;
    guest::free_bytes(buffer);
    guest::free_bytes(block);
    if read != 0 || bytes != expected {
        return Err(format!("leitura {read:#x} com {count} bytes diferentes dos {} esperados", expected.len()));
    }
    if !cached {
        return Err(alloc::string::String::from("a leitura nao passou pelo Cache Manager"));
    }
    if closed != 0 {
        return Err(format!("ZwClose devolveu {closed:#x}"));
    }
    Ok(())
}

// ---- fase 6: o caminho de montagem com file systems sintéticos -------------

type Assert = fn(bool, &str);

/// Chamadas recebidas pelos file systems sintéticos.
static REFUSED_MOUNTS: AtomicU32 = AtomicU32::new(0);
static ACCEPTED_MOUNTS: AtomicU32 = AtomicU32::new(0);
static CREATES: AtomicU32 = AtomicU32::new(0);
static CLEANUPS: AtomicU32 = AtomicU32::new(0);
static CLOSES: AtomicU32 = AtomicU32::new(0);
/// O dispositivo de volume do file system que aceita e o que ele recebeu.
static VOLUME_DEVICE: AtomicU64 = AtomicU64::new(0);
static MOUNT_VPB: AtomicU64 = AtomicU64::new(0);
static MOUNT_TARGET: AtomicU64 = AtomicU64::new(0);
static MOUNT_FLAGS: AtomicU32 = AtomicU32::new(0);
static CREATE_FILE: AtomicU64 = AtomicU64::new(0);
static CREATE_OPTIONS: AtomicU64 = AtomicU64::new(0);
static CREATE_ACCESS: AtomicU32 = AtomicU32::new(0);

const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
const FS_CONTEXT: u64 = 0x5A5A_F5C0;

fn complete(irp: u64, status: u32, information: u64) -> i32 {
    let request = at::<nt::Irp>(irp);
    request.io_status.status.set(status as i32);
    request.io_status.information.set(information);
    crate::ntos::io::io_manager::iof_complete_request(irp);
    status as i32
}

fn current_stack(irp: u64) -> &'static nt::IoStackLocation {
    at::<nt::IoStackLocation>(at::<nt::Irp>(irp).tail.overlay.current_stack_location.get())
}

/// File system que não reconhece nenhum volume.
extern "win64" fn refusing_dispatch(_device: u64, irp: u64) -> i32 {
    REFUSED_MOUNTS.fetch_add(1, Ordering::SeqCst);
    complete(irp, STATUS_UNRECOGNIZED_VOLUME, 0)
}

/// File system que monta o volume no seu dispositivo de volume e abre
/// arquivos nele.
extern "win64" fn accepting_dispatch(_device: u64, irp: u64) -> i32 {
    let stack = current_stack(irp);
    match stack.major_function.get() {
        0x0D => {
            ACCEPTED_MOUNTS.fetch_add(1, Ordering::SeqCst);
            let vpb = stack.parameters.mount_volume.vpb.get();
            MOUNT_VPB.store(vpb, Ordering::SeqCst);
            MOUNT_TARGET.store(stack.parameters.mount_volume.device_object.get(), Ordering::SeqCst);
            MOUNT_FLAGS.store(at::<nt::Irp>(irp).flags.get() | (stack.minor_function.get() as u32) << 16, Ordering::SeqCst);
            at::<nt::Vpb>(vpb).device_object.set(VOLUME_DEVICE.load(Ordering::SeqCst));
            complete(irp, 0, 0)
        }
        0x00 => {
            CREATES.fetch_add(1, Ordering::SeqCst);
            let file = stack.file_object.get();
            CREATE_FILE.store(file, Ordering::SeqCst);
            let create = &stack.parameters.create;
            CREATE_OPTIONS.store(create.options.get() as u64 | (create.share_access.get() as u64) << 32, Ordering::SeqCst);
            let context = create.security_context.get();
            CREATE_ACCESS.store(if context != 0 { guest::read32(context + 0x10) } else { 0 }, Ordering::SeqCst);
            at::<nt::FileObject>(file).fs_context.set(FS_CONTEXT);
            complete(irp, 0, 1)
        }
        0x12 => {
            CLEANUPS.fetch_add(1, Ordering::SeqCst);
            complete(irp, 0, 0)
        }
        0x02 => {
            CLOSES.fetch_add(1, Ordering::SeqCst);
            complete(irp, 0, 0)
        }
        _ => complete(irp, 0xC000_0010, 0),
    }
}

fn routine_address(routine: extern "win64" fn(u64, u64) -> i32) -> u64 {
    let pointer = routine as usize as u64;
    crate::ntos::mm::kernel_address::image_address(pointer).unwrap_or(pointer)
}

/// DRIVER_OBJECT sintético com a rotina em CREATE, CLOSE, CLEANUP e FSCTL.
fn synthetic_driver(routine: u64) -> u64 {
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let object = at::<nt::DriverObject>(driver);
    object.driver_init.set(1);
    for major in [0x00, 0x02, 0x0D, 0x12] {
        object.major_function[major].set(routine);
    }
    driver
}

/// CDO de file system de disco (FILE_DEVICE_DISK_FILE_SYSTEM) registrado.
fn register_file_system(driver: u64) -> u64 {
    let address = guest::alloc_bytes(nt::DeviceObject::SIZE);
    let device = at::<nt::DeviceObject>(address);
    device.type_.set(3);
    device.driver_object.set(driver);
    device.flags.set(0x80);
    device.device_type.set(8);
    device.stack_size.set(1);
    call_export("IoRegisterFileSystem", &[address]);
    address
}

/// IRP_MJ_READ/WRITE (IoBuildAsynchronousFsdRequest, com o MDL do
/// DO_DIRECT_IO, + IofCallDriver) de `length` bytes no deslocamento dado; o
/// volume conclui na hora. Devolve (status, Information).
fn transfer(device: u64, major: u64, buffer: u64, length: u64, offset: u64) -> (u32, u64) {
    let scratch = guest::alloc_bytes(0x40);
    let (iosb, position) = (scratch, scratch + 0x30);
    guest::write64(position, offset);
    let irp = call_export("IoBuildAsynchronousFsdRequest", &[major, device, buffer, length, position, iosb]).unwrap_or(0);
    let mdl = if irp != 0 { at::<nt::Irp>(irp).mdl_address.get() } else { 0 };
    let status = if irp != 0 { call_export("IofCallDriver", &[device, irp]).unwrap_or(u64::MAX) as u32 } else { u32::MAX };
    let information = if irp != 0 { at::<nt::Irp>(irp).io_status.information.get() } else { 0 };
    if mdl != 0 {
        call_export("IoFreeMdl", &[mdl]);
    }
    if irp != 0 {
        call_export("IoFreeIrp", &[irp]);
    }
    guest::free_bytes(scratch);
    (status, information)
}

/// O volume ATA: geometria pelo IOCTL, leitura do setor de boot e escrita
/// que fica na sobreposição em memória, sem chegar ao disco.
fn volume_io(assert: Assert, device: u64) {
    let buffer = guest::alloc_bytes(0x1000);
    let (read, count) = transfer(device, 3, buffer, 512, 0);
    let boot = guest::read_bytes(buffer, 512);
    debug_print!("[fs-mount] IRP_MJ_READ do volume: {:#x}, {} bytes, OEM {:?}", read, count, core::str::from_utf8(&boot[3..11]).unwrap_or("?"));
    assert(read == 0 && count == 512 && &boot[3..11] == b"NTFS    " && boot[510] == 0x55 && boot[511] == 0xAA, "fs-mount: volume ATA le o setor de boot por IRP_MJ_READ");
    let geometry = guest::alloc_bytes(0x40);
    let scratch = guest::alloc_bytes(0x40);
    crate::ntos::ke::dispatcher::initialize_event(scratch, 0, false);
    let irp = call_export("IoBuildDeviceIoControlRequest", &[0x0007_405C, device, 0, 0, geometry, 8, 0, scratch, scratch + 0x18]).unwrap_or(0);
    let status = if irp != 0 { call_export("IofCallDriver", &[device, irp]).unwrap_or(u64::MAX) as u32 } else { u32::MAX };
    let length = guest::read64(geometry);
    let sectors = crate::drivers::storage::ata_pio::capacity_sectors(1).unwrap_or(0);
    assert(status == 0 && sectors != 0 && length == sectors * 512, "fs-mount: IOCTL_DISK_GET_LENGTH_INFO pela capacidade do IDENTIFY");
    // Último setor: escreve um padrão e lê de volta pelo volume; o disco não muda.
    let last = (sectors - 1) * 512;
    let original = crate::drivers::storage::ata_pio::read_sectors(sectors - 1, 1, 1).unwrap_or_default();
    let pattern: Vec<u8> = (0..512u32).map(|index| (index * 7 + 3) as u8).collect();
    guest::write_bytes(buffer, &pattern);
    let (written, written_count) = transfer(device, 4, buffer, 512, last);
    guest::write_bytes(buffer, &[0u8; 512]);
    let (again, _) = transfer(device, 3, buffer, 512, last);
    let disk = crate::drivers::storage::ata_pio::read_sectors(sectors - 1, 1, 1).unwrap_or_default();
    assert(written == 0 && written_count == 512 && again == 0 && guest::read_bytes(buffer, 512) == pattern && disk == original && original.len() == 512, "fs-mount: escrita do volume fica na sobreposicao em memoria");
    for block in [buffer, geometry, scratch] {
        guest::free_bytes(block);
    }
}

fn open(block: u64, name: &str) -> (u32, u64, u64) {
    let attributes = object_attributes(block, name);
    let (handle, iosb) = (block + 0x300, block + 0x310);
    let status = call_export("ZwCreateFile", &[handle, FILE_GENERIC_READ, attributes, iosb, 0, 0, FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, 0, 0]).unwrap_or(u64::MAX) as u32;
    (status, guest::read64(handle), guest::read64(iosb + 8))
}

/// ZwQueryDirectoryFile (FileIdFullDirectoryInformation, como a ci.dll varre
/// o CatRoot) em `D:\Windows\System32` do volume NTFS do kernel: cada registro
/// começa alinhado a 8 bytes e Information termina no fim do último nome.
fn directory_records(assert: Assert) {
    let block = guest::alloc_bytes(0x400);
    let buffer = guest::alloc_bytes(0x2000);
    let attributes = object_attributes(block, "\\??\\D:\\Windows\\System32");
    let (handle, iosb) = (block + 0x300, block + 0x310);
    // FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT.
    let opened = call_export("ZwCreateFile", &[handle, 0x0010_0001, attributes, iosb, 0, 0, 7, FILE_OPEN, 0x21, 0, 0]).unwrap_or(u64::MAX) as u32;
    let directory = guest::read64(handle);
    let queried = if opened == 0 { call_export("ZwQueryDirectoryFile", &[directory, 0, 0, 0, iosb, buffer, 0x2000, 38, 0, 0, 1]).unwrap_or(u64::MAX) as u32 } else { u32::MAX };
    let information = guest::read64(iosb + 8);
    let (mut offset, mut records, mut aligned, mut end) = (0u64, 0, true, 0u64);
    while queried == 0 && records < 64 {
        let record = buffer + offset;
        let next = guest::read32(record) as u64;
        let name_length = guest::read32(record + 0x3C) as u64;
        aligned &= record % 8 == 0;
        end = offset + 0x50 + name_length;
        records += 1;
        if next == 0 {
            break;
        }
        offset += next;
    }
    if opened == 0 {
        call_export("ZwClose", &[directory]);
    }
    debug_print!("[fs-mount] ZwQueryDirectoryFile: abertura {:#x}, consulta {:#x}, {} registros, alinhados {}, Information {} / {}", opened, queried, records, aligned, information, end);
    assert(opened == 0 && queried == 0 && records >= 2 && aligned && information == end, "fs-mount: ZwQueryDirectoryFile alinha cada registro a 8 bytes");
    guest::free_bytes(buffer);
    guest::free_bytes(block);
}

pub fn run(assert: Assert) {
    directory_records(assert);
    // IoCreateDevice: VPB, DeviceLock e SectorSize de um FILE_DEVICE_DISK.
    let creator = synthetic_driver(0);
    let output = guest::alloc_bytes(8);
    let created = call_export("IoCreateDevice", &[creator, 0, 0, 7, 0, 0, output]).unwrap_or(u64::MAX) as u32;
    let disk = guest::read64(output);
    let disk_object = at::<nt::DeviceObject>(disk);
    let disk_vpb = disk_object.vpb.get();
    assert(
        created == 0 && disk_vpb != 0 && at::<nt::Vpb>(disk_vpb).type_.get() == 10 && at::<nt::Vpb>(disk_vpb).size.get() == 0x60 && at::<nt::Vpb>(disk_vpb).real_device.get() == disk && disk_object.device_lock.header.type_.get() == 1 && disk_object.device_lock.header.signal_state.get() == 1 && disk_object.sector_size.get() == 512,
        "fs-mount: IoCreateDevice de disco cria VPB, DeviceLock e SectorSize",
    );
    // O dispositivo de volume pertence ao file system que aceita a montagem.
    let accepting_driver = synthetic_driver(routine_address(accepting_dispatch));
    let volume_created = call_export("IoCreateDevice", &[accepting_driver, 0, 0, 8, 0, 0, output]).unwrap_or(u64::MAX) as u32;
    let volume_device = guest::read64(output);
    assert(volume_created == 0 && at::<nt::DeviceObject>(volume_device).vpb.get() == 0 && at::<nt::DeviceObject>(volume_device).sector_size.get() == 512, "fs-mount: IoCreateDevice de file system sem VPB, SectorSize 512");
    VOLUME_DEVICE.store(volume_device, Ordering::SeqCst);

    // O volume do segundo disco, com dois file systems na fila: o primeiro recusa.
    let Ok(device) = ata_volume::create(1) else {
        assert(false, "fs-mount: dispositivo do volume ATA");
        return;
    };
    volume_io(assert, device);
    let accepting = register_file_system(accepting_driver);
    let refusing = register_file_system(synthetic_driver(routine_address(refusing_dispatch)));
    let queue = crate::ntos::io::file_system::registered_file_systems(8);
    let block = guest::alloc_bytes(0x400);
    let name = alloc::format!("\\Device\\{}\\TESTE.TXT", ata_volume::DEVICE_NAME);
    let (status, handle, information) = open(block, &name);
    let vpb_address = at::<nt::DeviceObject>(device).vpb.get();
    let vpb = at::<nt::Vpb>(vpb_address);
    // Sem o RAW no fim da fila, quem montou não é o RAW: só VPB_MOUNTED.
    let expected_flags = 1;
    debug_print!(
        "[fs-mount] abertura {:#x} info {} recusas {} aceites {} vpb {:#x}/{:#x} alvo {:#x}/{:#x} flags {:#x} fila {}",
        status,
        information,
        REFUSED_MOUNTS.load(Ordering::SeqCst),
        ACCEPTED_MOUNTS.load(Ordering::SeqCst),
        MOUNT_VPB.load(Ordering::SeqCst),
        vpb_address,
        MOUNT_TARGET.load(Ordering::SeqCst),
        device,
        MOUNT_FLAGS.load(Ordering::SeqCst),
        queue.len()
    );
    assert(
        status == 0 && information == 1 && REFUSED_MOUNTS.load(Ordering::SeqCst) == 1 && ACCEPTED_MOUNTS.load(Ordering::SeqCst) == 1 && MOUNT_VPB.load(Ordering::SeqCst) == vpb_address && MOUNT_TARGET.load(Ordering::SeqCst) == device && MOUNT_FLAGS.load(Ordering::SeqCst) == (0x42 | 1 << 16),
        "fs-mount: IopMountVolume tenta a fila em ordem e o segundo file system monta",
    );
    let volume_object = at::<nt::DeviceObject>(volume_device);
    let extension = volume_object.device_object_extension.get();
    debug_print!(
        "[fs-mount] VPB flags {:#x} volume {:#x}/{:#x} stack {} ext {:#x} ref {}",
        vpb.flags.get(),
        vpb.device_object.get(),
        volume_device,
        volume_object.stack_size.get(),
        if extension != 0 { at::<nt::DevobjExtension>(extension).vpb.get() } else { 0 },
        vpb.reference_count.get()
    );
    assert(
        vpb.flags.get() == expected_flags && vpb.device_object.get() == volume_device && volume_object.stack_size.get() == 2 && extension != 0 && at::<nt::DevobjExtension>(extension).vpb.get() == vpb_address && vpb.reference_count.get() == 1,
        "fs-mount: IopMountInitializeVpb monta o VPB e referencia a abertura",
    );
    let file = CREATE_FILE.load(Ordering::SeqCst);
    let file_object = at::<nt::FileObject>(file);
    let file_name = crate::ntos::rtl::guest_strings::read_unicode_string(file_object.file_name.address());
    assert(
        CREATES.load(Ordering::SeqCst) == 1 && file == crate::ntos::io::file::zw::file_object_of_handle(handle) && file_object.device_object.get() == device && file_object.vpb.get() == vpb_address && file_name == "\\TESTE.TXT" && file_object.flags.get() & 2 != 0 && file_object.fs_context.get() == FS_CONTEXT && CREATE_OPTIONS.load(Ordering::SeqCst) == ((1 << 24) | 0x60 | 1 << 32) && CREATE_ACCESS.load(Ordering::SeqCst) == FILE_GENERIC_READ as u32,
        "fs-mount: IRP_MJ_CREATE chega ao volume com o FILE_OBJECT e os parametros do NT",
    );
    let (second, second_handle, _) = open(block, &name);
    assert(second == 0 && ACCEPTED_MOUNTS.load(Ordering::SeqCst) == 1 && REFUSED_MOUNTS.load(Ordering::SeqCst) == 1 && CREATES.load(Ordering::SeqCst) == 2 && vpb.reference_count.get() == 2, "fs-mount: volume montado nao monta de novo");
    call_export("ZwClose", &[second_handle]);
    call_export("ZwClose", &[handle]);
    assert(CLEANUPS.load(Ordering::SeqCst) == 2 && CLOSES.load(Ordering::SeqCst) == 2 && vpb.reference_count.get() == 0, "fs-mount: fechamento manda CLEANUP e CLOSE e devolve o VPB");

    // Volume desmontado de novo para os próximos testes; a fila volta ao que era.
    vpb.flags.set(0);
    vpb.device_object.set(0);
    vpb.reference_count.set(0);
    call_export("IoUnregisterFileSystem", &[refusing]);
    call_export("IoUnregisterFileSystem", &[accepting]);
    guest::free_bytes(block);
    guest::free_bytes(output);
}
