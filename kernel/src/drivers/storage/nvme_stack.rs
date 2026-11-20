//! A pilha de armazenamento NVMe do Windows (`--storage=nvme`).
//!
//! Com a opção, o QEMU tem um controlador NVMe (PCI\VEN_1B36&DEV_0010,
//! classe 01.08.02) com o disco particionado do xtask (`nvme.img`: MBR com
//! uma partição NTFS a partir do LBA 2048). A árvore do PnP do fim da fase 1
//! (`device_tree::build`, com o pci.sys real enumerando o barramento sob a
//! raiz ACPI) chama `before_tree` e `check`, e o controlador é instalado como
//! no Windows: o stornvme.inf dá o serviço stornvme a todo PCI\CC_010802
//! (classe SCSIAdapter). O stornvme.sys importa o storport.sys, que é o
//! driver de porta: o AddDevice e o START do controlador vão a ele, que
//! chama o HwFindAdapter e o HwInitialize do miniport, conecta as mensagens
//! MSI-X que o árbitro de IRQ do acpi.sys deu (a linha INTx sem mensagens) e
//! enumera as LUNs pelo próprio barramento (INQUIRY e REPORT LUNS
//! que o stornvme traduz em comandos NVMe). A LUN do namespace recebe o
//! disk.sys com o classpnp.sys e o filtro partmgr.sys (GenDisk), que lê a
//! tabela de partições e entrega a partição ao volmgr.sys, que cria o
//! `\Device\HarddiskVolumeN` e relata o devnode STORAGE\Volume, que o
//! volume.inf instala com o volume.sys. Com o volume iniciado, o
//! mountmgr.sys recebe a chegada da interface do volume e dá a ele a
//! primeira letra livre (E:, gravada no MountedDevices), porque a
//! reinicialização do driver (MountMgrDriverReinitialization) já ligou a
//! atribuição automática de letras; o WorkerThread que ele põe na fila espera o
//! `\Device\VolumesSafeForWriteAccess` numa worker thread do sistema, sem
//! prender o boot.
//!
//! Os marcadores: `NVME_DISK_OK` quando o `\Device\HarddiskN\DRN` do disk.sys
//! está sobre a LUN do storport e o setor 0 lido pela pilha é o MBR do xtask;
//! `NVME_VOLUME_OK` quando o volume tem a letra do mountmgr.sys, o ntfs.sys
//! real montou o volume da partição e leu o arquivo do xtask, e um arquivo
//! novo foi gravado, fechado e lido de volta pela letra.
//!
//! Sem a opção nada disto roda e o boot comum não muda.

use alloc::format;
use alloc::string::String;

use crate::drivers::storage::storage_stack;
use crate::ntos::inc::types::{DeviceObject, NtStruct};
use crate::ntos::io::lifecycle;
use crate::ntos::io::pnp;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::device as device_objects;

/// `--storage=nvme`: a pilha NVMe sobe pelo PnP.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::nvme_storage()
}

/// O que o xtask grava no MBR do `nvme.img`: a assinatura de disco, a
/// partição NTFS (tipo 0x07) e o seu primeiro setor.
const DISK_SIGNATURE: u32 = 0x4F4E_5654;
const PARTITION_IFS: u8 = 0x07;
const PARTITION_START_LBA: u32 = 2048;

/// O disco do disk.sys cuja pilha está sobre uma LUN do stornvme: o número
/// N de `\Device\HarddiskN\DRN` e o DEVICE_OBJECT.
fn nvme_disk() -> Option<(u32, u64)> {
    let miniport = lifecycle::initialized_driver("stornvme")?;
    (0..16).find_map(|number| {
        let disk = storage_stack::disk_device(number)?;
        let base = device_objects::attached_reference(disk, true).ok()?;
        // SAFETY: DEVICE_OBJECT da base da pilha, referenciado.
        let owner = unsafe { DeviceObject::at(base) }.driver_object.get();
        let _ = device_objects::dereference(base);
        (owner == miniport).then_some((number, disk))
    })
}

/// O setor 0 lido pela pilha é o MBR do xtask.
fn check_master_boot_record(disk: u64) -> Result<(), String> {
    let sector = storage_stack::read_through_stack(disk, 0, 1).map_err(|error| format!("leitura do setor 0: {error}"))?;
    let signature = u32::from_le_bytes([sector[0x1B8], sector[0x1B9], sector[0x1BA], sector[0x1BB]]);
    let start = u32::from_le_bytes([sector[0x1C6], sector[0x1C7], sector[0x1C8], sector[0x1C9]]);
    debug_print!("[nvme] setor 0 pela pilha: assinatura {:#010x}, particao tipo {:#04x} no LBA {}, {:#04x}{:02x}", signature, sector[0x1C2], start, sector[510], sector[511]);
    if signature != DISK_SIGNATURE || sector[0x1C2] != PARTITION_IFS || start != PARTITION_START_LBA || sector[510] != 0x55 || sector[511] != 0xAA {
        return Err(String::from("o setor 0 nao e o MBR do nvme.img"));
    }
    Ok(())
}

/// Os registradores do controlador NVMe (o BAR0 pelo mapa direto) e o
/// comando/estado PCI, no log: o que o stornvme.sys deixou nele quando a
/// pilha não chega ao disco.
fn log_controller_state() {
    let Some(function) = crate::drivers::bus::pci::find_by_id(0x1B36, 0x0010) else { return };
    let Some(bar) = function.bars.iter().find(|bar| bar.index == 0) else { return };
    let base = (bar.value & 0xFFFF_C000) as u64 | (bar.high_value as u64) << 32;
    let command = crate::hal::pci_config::read(function.bus, function.device, function.function, 0x04, 4).unwrap_or(0);
    if base == 0 || base >= crate::hal::physical::direct_map_limit() {
        debug_print!("[nvme] BAR0 {:#x} fora do mapa direto; comando/estado PCI {:#010x}", base, command);
        return;
    }
    let register = |offset: u64| crate::hal::volatile::read32(crate::hal::physical::to_virtual(base + offset));
    let pair = |offset: u64| register(offset) as u64 | (register(offset + 4) as u64) << 32;
    debug_print!(
        "[nvme] controlador em {:#x}: CAP {:#018x} VS {:#x} INTMS {:#x} CC {:#x} CSTS {:#x} AQA {:#x} ASQ {:#x} ACQ {:#x}; comando/estado PCI {:#010x}",
        base,
        pair(0x00),
        register(0x08),
        register(0x0C),
        register(0x14),
        register(0x1C),
        register(0x24),
        pair(0x28),
        pair(0x30),
        command
    );
    // As filas de administração pela memória física: de cada comando o
    // opcode e o CID (64 bytes por entrada), de cada conclusão o SQHD, o
    // CID, a fase e o status (16 bytes), as entradas não vazias.
    if function.irq_line != 0 {
        let count = crate::hal::physical::read32(crate::hal::amd64::irqstubs::IRQ_COUNT_BASE + (0x20 + function.irq_line as u64) * 4);
        debug_print!("[nvme] IRQ {} (vetor {:#x}): {} interrupcoes entregues", function.irq_line, 0x20 + function.irq_line, count);
    }
    let entries = (register(0x24) & 0xFFF) as u64 + 1;
    let word = |physical: u64| crate::hal::volatile::read32(crate::hal::physical::to_virtual(physical));
    let (submission, completion) = (pair(0x28) & !0xFFF, pair(0x30) & !0xFFF);
    if submission == 0 || completion == 0 || completion + entries * 16 > crate::hal::physical::direct_map_limit() || submission + entries * 64 > crate::hal::physical::direct_map_limit() {
        return;
    }
    let commands: alloc::vec::Vec<String> = (0..entries).filter_map(|index| {
        let dword = word(submission + index * 64);
        (dword != 0).then(|| format!("{index}:{:02x}/{:x}", dword & 0xFF, dword >> 16))
    }).collect();
    let completions: alloc::vec::Vec<String> = (0..entries).filter_map(|index| {
        let (head, status) = (word(completion + index * 16 + 8), word(completion + index * 16 + 12));
        (status != 0 || head != 0).then(|| format!("{index}:sqhd{} cid{:x} p{} st{:x}", head & 0xFFFF, status & 0xFFFF, status >> 16 & 1, status >> 17))
    }).collect();
    debug_print!("[nvme] fila de comandos de administracao ({} entradas): {}", entries, commands.join(" "));
    debug_print!("[nvme] fila de conclusoes de administracao: {}", completions.join(" "));
}

/// IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;
/// O arquivo de texto que o xtask grava no volume do `nvme.img`.
const NVME_FILE: &str = "NVME.TXT";
const NVME_FILE_DATA: &[u8] = b"Volume NTFS no disco NVMe do OpenNT.\r\n";
/// O arquivo que o teste cria, grava e relê pelo ntfs.sys no volume.
const NVME_NEW_FILE: &str = "OPENNT-NVME.TXT";
const NVME_NEW_FILE_DATA: &[u8] = b"Gravado pelo ntfs.sys sobre o volume NVMe do OpenNT.\r\n";

/// IRP_MJ_DEVICE_CONTROL síncrono (IoBuildDeviceIoControlRequest +
/// IofCallDriver, esperando o evento se o pedido fica pendente) ao topo da
/// pilha de `device`. Devolve (status, bytes de saída).
fn device_control(device: u64, code: u32, output_length: u32) -> (u32, alloc::vec::Vec<u8>) {
    use crate::ntos::inc::types::{IoStatusBlock, Kevent, LargeInteger};
    use crate::ntos::io::io_manager;
    use crate::ntos::mm::guest_memory as guest;
    let Ok(top) = device_objects::attached_reference(device, false) else { return (u32::MAX, alloc::vec::Vec::new()) };
    let output = guest::alloc_bytes(output_length as u64);
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
    let irp = io_manager::build_device_io_control_request(code, top, 0, 0, output, output_length, 0, event, io_status, None);
    let mut status = if irp != 0 { io_manager::iof_call_driver(top, irp) as u32 } else { u32::MAX };
    if status == 0x103 {
        let timeout = guest::alloc_bytes(LargeInteger::SIZE);
        // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo de 10 s).
        unsafe { LargeInteger::at(timeout) }.quad_part.set(-100_000_000);
        let waited = crate::ntos::ke::dispatcher::wait_for_single_object(event, timeout, 0, false);
        guest::free_bytes(timeout);
        // SAFETY: IO_STATUS_BLOCK gravado na conclusão.
        status = if waited == 0 { unsafe { IoStatusBlock::at(io_status) }.status.get() as u32 } else { 0x102 };
    }
    let _ = device_objects::dereference(top);
    // SAFETY: IO_STATUS_BLOCK do pedido.
    let information = unsafe { IoStatusBlock::at(io_status) }.information.get() as usize;
    let bytes = guest::read_bytes(output, information.min(output_length as usize));
    // O IRP concluído volta ao pool (um pedido que não concluiu fica com ele).
    if status != 0x102 {
        if irp != 0 {
            guest::free_bytes(irp);
        }
        for block in [output, event, io_status] {
            guest::free_bytes(block);
        }
    }
    (status, bytes)
}

/// O `\Device\HarddiskVolumeN` do volmgr.sys cuja única extensão é a
/// partição do disco `disk_number` (IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
/// DiskNumber e o deslocamento do LBA 2048), com o devnode do volume
/// iniciado.
fn partition_volume(disk_number: u32, log: bool) -> Option<(String, u64)> {
    (1..32).find_map(|index| {
        let path = format!("\\Device\\HarddiskVolume{index}");
        let node = object_manager::lookup(&path)?;
        let device = crate::ntos::io::io_manager::device(node).map(|entry| entry.native_device).filter(|&device| device != 0)?;
        let started = pnp::devnode::get(device).map(|node| (node.instance_path.clone(), node.state));
        let (status, extents) = device_control(device, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0x20);
        // VOLUME_DISK_EXTENTS: NumberOfDiskExtents (4 + 4 de alinhamento) e
        // DISK_EXTENT {DiskNumber, StartingOffset, ExtentLength}.
        let field = |offset: usize, size: usize| extents.get(offset..offset + size).map_or(0, |bytes| bytes.iter().rev().fold(0u64, |value, &byte| value << 8 | byte as u64));
        let (count, number, start) = (field(0, 4), field(8, 4), field(16, 8));
        if log {
            debug_print!("[nvme] {}: devnode {:?}, extensoes {:#x}, {} extensao(oes), disco {}, inicio {:#x}", path, started, status, count, number, start);
        }
        let ready = matches!(started, Some((_, pnp::devnode::State::Started)));
        (ready && status == 0 && extents.len() >= 0x20 && count == 1 && number == disk_number as u64 && start == PARTITION_START_LBA as u64 * 512).then_some((path, device))
    })
}

/// O volume da partição chega depois do disco: o partmgr.sys entrega a
/// partição ao volmgr.sys por um work item, e o devnode do volume nasce do
/// PnpDeviceActionWorker. Espera por ele até 5 s, de 100 em 100 ms, e põe
/// no log o estado da última tentativa.
fn wait_partition_volume(disk_number: u32) -> Option<(String, u64)> {
    use crate::ntos::inc::types::LargeInteger;
    use crate::ntos::mm::guest_memory as guest;
    let interval = guest::alloc_bytes(LargeInteger::SIZE);
    // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo de 100 ms).
    unsafe { LargeInteger::at(interval) }.quad_part.set(-1_000_000);
    let mut found = None;
    for attempt in 0..50 {
        found = partition_volume(disk_number, attempt == 49);
        if found.is_some() {
            break;
        }
        let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    }
    guest::free_bytes(interval);
    found
}

/// A letra que o mountmgr.sys deu ao volume `path`: o `\GLOBAL??\X:` (o
/// `\??` e o `\DosDevices` levam a ele) que resolve no dispositivo do
/// volume, e o valor `\DosDevices\X:` do MountedDevices com o identificador
/// único do volume. As letras C: e D: do kernel levam aos volumes dele.
fn drive_letter(path: &str) -> Option<(char, usize)> {
    let target = object_manager::lookup(path)?;
    let letter = ('C'..='Z').find(|letter| object_manager::lookup(&format!("\\GLOBAL??\\{letter}:")) == Some(target))?;
    let unique_id = crate::ntos::cm::registry::read_value_by_path("\\Registry\\Machine\\System\\MountedDevices", &format!("\\DosDevices\\{letter}:"))?;
    Some((letter, unique_id.data.len()))
}

/// O ntfs.sys real monta o volume da partição: abre e lê o arquivo do xtask
/// pelo file system; o VPB do volume fica montado com o dispositivo de volume
/// do \Driver\Ntfs. Depois grava, fecha, reabre e lê de volta um arquivo novo
/// pela letra que o mountmgr.sys deu ao volume (`\??\X:`).
fn check_volume(disk_number: u32) -> Result<(String, char), String> {
    let (path, device) = wait_partition_volume(disk_number).ok_or_else(|| format!("nenhum \\Device\\HarddiskVolumeN iniciado na particao do disco {disk_number}"))?;
    let (letter, unique_id) = drive_letter(&path).ok_or_else(|| format!("{path} sem letra do mountmgr.sys (\\GLOBAL??\\X: e MountedDevices)"))?;
    debug_print!("[nvme] {}: letra {}: do mountmgr.sys (MountedDevices \\DosDevices\\{}: com {} bytes de identificador)", path, letter, letter, unique_id);
    crate::ntos::cm::service::driver::start("Ntfs").map_err(|error| format!("servico Ntfs: {} ({})", error.message, error.win32))?;
    let file_system = lifecycle::initialized_driver("Ntfs").ok_or("\\Driver\\Ntfs ausente")?;
    crate::ntos::test::file_system_mount::read_known_file(device, &path, NVME_FILE, NVME_FILE_DATA)?;
    // SAFETY: o DEVICE_OBJECT do volume, o seu VPB e o dispositivo montado.
    let (vpb_flags, mounted_owner) = unsafe {
        let vpb = crate::ntos::inc::types::Vpb::at(DeviceObject::at(device).vpb.get());
        let mounted = vpb.device_object.get();
        (vpb.flags.get(), if mounted != 0 { DeviceObject::at(mounted).driver_object.get() } else { 0 })
    };
    if vpb_flags & 1 == 0 || mounted_owner != file_system {
        return Err(format!("VPB flags {vpb_flags:#x}, dispositivo montado do driver {mounted_owner:#x} (Ntfs {file_system:#x})"));
    }
    crate::ntos::test::file_system_mount::write_and_read_back(&format!("\\??\\{letter}:"),NVME_NEW_FILE, NVME_NEW_FILE_DATA)?;
    Ok((path, letter))
}

/// Antes da árvore do PnP (`device_tree::build`): o Registro das pilhas de
/// disco e os drivers de boot sem dispositivo a esperar, na ordem dos grupos
/// (o volmgr.sys relata o próprio dispositivo raiz no DriverEntry). Devolve
/// false se a pilha não sobe.
pub fn before_tree() -> bool {
    debug_print!("[nvme] pilha NVMe real pelo PnP (storport.sys + stornvme.sys)");
    if let Err(error) = storage_stack::seed_registry() {
        debug_print!("[nvme] Registro: {}", error);
        return false;
    }
    for service in ["partmgr", "volmgr"] {
        if !crate::ntos::cm::service::system_drivers::load_service_driver(service) {
            debug_print!("[nvme] servico {} nao carregou", service);
        }
    }
    true
}

/// Depois da árvore: o disco do disk.sys sobre a LUN do stornvme (o
/// controlador que o pci.sys enumerou) e o volume da partição.
pub fn check() {
    for number in 0..4 {
        for path in [format!("\\Device\\Harddisk{number}\\DR{number}"), format!("\\Device\\HarddiskVolume{}", number + 1)] {
            if object_manager::lookup(&path).is_some() {
                debug_print!("[nvme] {} presente", path);
            }
        }
    }
    let Some((number, disk)) = nvme_disk() else {
        debug_print!("[nvme] nenhum \\Device\\HarddiskN\\DRN sobre uma LUN do stornvme");
        log_controller_state();
        return;
    };
    if let Err(error) = check_master_boot_record(disk) {
        debug_print!("[nvme] disco {}: {}", number, error);
        return;
    }
    debug_print!("[nvme] \\Device\\Harddisk{}\\DR{} do disk.sys sobre a LUN do storport; o setor 0 e o MBR do nvme.img", number, number);
    debug_print!("NVME_DISK_OK");
    match check_volume(number) {
        Ok((path, letter)) => {
            debug_print!("[nvme] {}: o ntfs.sys montou o volume da particao, leu {} e gravou e releu {} por {}:", path, NVME_FILE, NVME_NEW_FILE, letter);
            debug_print!("NVME_VOLUME_OK");
        }
        Err(error) => debug_print!("[nvme] volume: {}", error),
    }
}
