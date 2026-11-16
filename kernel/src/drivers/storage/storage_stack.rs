//! A pilha de armazenamento real do Windows (`--storage=real`).
//!
//! Com a opção, o fim da fase 1 sobe pelo PnP manager a pilha da
//! controladora IDE do PIIX3 como o Windows: o barramento PCI interno
//! relata as funções, o PnP instala cada uma pelos INFs da caixa
//! (PCI\VEN_8086&DEV_7010 -> intelide.sys com o pciidex.sys; os canais
//! Internal_IDE_Channel -> atapi.sys com o ataport.sys; os discos GenDisk ->
//! disk.sys com o classpnp.sys e o filtro de classe partmgr.sys; Root\VOLMGR
//! -> volmgr.sys), atribui e traduz os recursos, inicia e enumera. Depois lê
//! setores do segundo disco pela pilha real (IRP_MJ_READ no topo da pilha
//! de \Device\Harddisk1\DR1) e os compara com os mesmos setores lidos pelo
//! driver ATA interno antes de a pilha real assumir a controladora: o setor
//! de boot NTFS que o xtask gravou no ntfs.img (OEM "NTFS    " e o número de
//! série "OPENNT!!"); a assinatura de disco MBR que o partmgr.sys grava
//! num disco sem nenhuma (offset 0x1B8) é a única diferença admitida, e sai
//! no log. O resultado sai na serial (`STORAGE_REAL_OK`).
//!
//! Sem a opção nada disto roda e o boot comum não muda. O driver ATA
//! interno continua servindo o volume D: (montado antes); a pilha real só
//! começa depois de ele ler o que o boot precisa, e as duas não disputam a
//! controladora durante o teste.

use alloc::format;
use alloc::vec::Vec;

use crate::ntos::inc::types::{IoStatusBlock, Irp, Kevent, LargeInteger, NtStruct};
use crate::ntos::io::io_manager::{self, irp_mj};
use crate::ntos::io::pnp::{self, install};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::KernelError;

/// `--storage=real`: a pilha de armazenamento sobe pelo PnP.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::real_storage()
}

/// Setores comparados (os 4 KB do começo do volume NTFS).
const SECTORS: u32 = 8;
const SECTOR_SIZE: usize = 512;
/// Disco do volume NTFS (mestre-escravo primário: o segundo disco).
const DATA_DRIVE: u8 = 1;

/// O que a instalação do Windows deixa no Registro para esta pilha e que o
/// OpenNT ainda não tem: os serviços de boot partmgr e volmgr e as classes
/// de dispositivo. Os serviços dos dispositivos (intelide, atapi, disk)
/// entram com a instalação de cada devnode, e a instância ROOT\VOLMGR\0000
/// nasce do IoReportDetectedDevice do próprio volmgr.sys.
fn seed_registry() -> Result<(), KernelError> {
    use install::ServiceSpec;
    // partmgr: o filtro de classe do DiskDrive (c_diskdrive.inf); a chave do
    // serviço vem da instalação do sistema (Group "Boot Bus Extender",
    // Parameters\SanPolicy 1 e as altitudes dos gerenciadores de volume).
    install::install_service(&ServiceSpec { name: "partmgr", display_name: Some("@%SystemRoot%\\system32\\drivers\\partmgr.sys,-100"), start: 0, error_control: 3, binary: "partmgr.sys", group: Some("Boot Bus Extender"), owner: "", values: &[] })?;
    let parameters = format!("{}\\Services\\partmgr\\Parameters", install::CONTROL_SET);
    install::write_dword(&parameters, "SanPolicy", 1)?;
    for (name, altitude) in [("clusbflt", 4), ("spaceport", 0x10), ("volmgr", 0x20)] {
        install::write_dword(&format!("{parameters}\\VolumeManagerAltitudes"), name, altitude)?;
    }
    for class in [&install::CLASS_HDC, &install::CLASS_DISK_DRIVE, &install::CLASS_VOLUME, &install::CLASS_SYSTEM] {
        install::install_class(class)?;
    }
    install::install_service(&ServiceSpec { name: "volmgr", display_name: Some("@volmgr.inf,%volmgr_svcdesc%;Volume Manager Driver"), start: 0, error_control: 3, binary: "volmgr.sys", group: Some("System Bus Extender"), owner: "volmgr.inf", values: &[] })?;
    Ok(())
}

/// Lê `SECTORS` setores do disco pela pilha real: IRP_MJ_READ (MDL do
/// IoBuildSynchronousFsdRequest) no topo da pilha do disco.
fn read_through_stack(disk: u64, lba: u64) -> Result<Vec<u8>, KernelError> {
    let length = SECTORS * SECTOR_SIZE as u32;
    let buffer = guest::alloc_aligned(length as u64, 0x1000, true);
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    let offset = guest::alloc_bytes(LargeInteger::SIZE);
    // SAFETY: LARGE_INTEGER recém-alocado.
    unsafe { LargeInteger::at(offset) }.quad_part.set((lba * SECTOR_SIZE as u64) as i64);
    dispatcher::initialize_event(event, 0, false);
    let top = device_objects::attached_reference(disk, false)?;
    let packet = io_manager::build_synchronous_fsd_request(irp_mj::READ, top, buffer, length, offset, event, io_status);
    // SAFETY: IRP recém-montado.
    let irp = unsafe { Irp::at(packet) };
    irp.tail.overlay.thread.set(crate::ntos::ps::kernel_threads::get_current_thread_handle() as u64);
    let mut status = io_manager::iof_call_driver(top, packet);
    if status == 0x103 {
        let timeout = guest::alloc_bytes(LargeInteger::SIZE);
        // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo de 10 s).
        unsafe { LargeInteger::at(timeout) }.quad_part.set(-100_000_000);
        let waited = dispatcher::wait_for_single_object(event, timeout, 0, false);
        guest::free_bytes(timeout);
        if waited != 0 {
            device_objects::dereference(top)?;
            return Err(KernelError::new("leitura pela pilha real nao concluiu em 10 s"));
        }
    }
    // SAFETY: IO_STATUS_BLOCK gravado na conclusão.
    let result = unsafe { IoStatusBlock::at(io_status) };
    status = result.status.get();
    let transferred = result.information.get();
    device_objects::dereference(top)?;
    let data = guest::read_bytes(buffer, length as usize);
    let descriptor = irp.mdl_address.get();
    if descriptor != 0 {
        guest::free_bytes(descriptor);
    }
    guest::free_bytes(packet);
    for block in [buffer, event, io_status, offset] {
        guest::free_bytes(block);
    }
    if status < 0 || transferred != length as u64 {
        return Err(KernelError::new(format!("IRP_MJ_READ -> {:#x}, {} bytes", status as u32, transferred)));
    }
    Ok(data)
}

/// Assinatura de disco MBR no setor 0 (offset 0x1B8, 4 bytes).
const DISK_SIGNATURE: usize = 0x1B8;

/// Os setores lidos só diferem da referência na assinatura de disco.
fn signature_only_difference(bytes: &[u8], reference: &[u8]) -> bool {
    bytes.len() == reference.len() && bytes.iter().zip(reference).enumerate().all(|(index, (left, right))| left == right || (DISK_SIGNATURE..DISK_SIGNATURE + 4).contains(&index))
}

/// O DEVICE_OBJECT de `\Device\HarddiskN\DR N` criado pelo disk.sys.
fn disk_device(number: u32) -> Option<u64> {
    let node = object_manager::lookup(&format!("\\Device\\Harddisk{number}\\DR{number}"))?;
    io_manager::device(node).map(|entry| entry.native_device).filter(|&device| device != 0)
}

/// Os objetos de armazenamento publicados pela pilha.
fn log_published_objects() {
    for path in ["\\Device\\Harddisk0\\DR0", "\\Device\\Harddisk0\\Partition0", "\\Device\\Harddisk1\\DR1", "\\Device\\Harddisk1\\Partition0", "\\Device\\Harddisk1\\Partition1", "\\Device\\HarddiskVolume1", "\\Device\\HarddiskVolume2", "\\Device\\VolMgrControl", "\\Device\\MountPointManager"] {
        let present = object_manager::lookup(path).is_some();
        debug_print!("[storage] {} {}", path, if present { "presente" } else { "ausente" });
    }
}

/// Sobe a pilha real e confere a leitura. Só com `--storage=real`.
pub fn initialize() {
    debug_print!("[storage] pilha de armazenamento real pelo PnP");
    // Referência: os setores lidos pelo driver interno antes da troca.
    let reference = match crate::drivers::storage::ata_pio::read_sectors(0, SECTORS, DATA_DRIVE) {
        Ok(bytes) => bytes,
        Err(error) => {
            debug_print!("[storage] leitura de referencia falhou: {}", error);
            return;
        }
    };
    if let Err(error) = seed_registry() {
        debug_print!("[storage] Registro: {}", error);
        return;
    }
    if let Err(error) = crate::drivers::bus::device_tree::prepare() {
        debug_print!("[storage] raiz do PnP: {}", error);
        return;
    }
    // Os drivers de boot sem dispositivo a esperar, na ordem dos grupos
    // (Boot Bus Extender, System Bus Extender): o volmgr.sys relata o
    // próprio dispositivo raiz (IoReportDetectedDevice) no DriverEntry.
    for service in ["partmgr", "volmgr"] {
        if !crate::ntos::cm::service::system_drivers::load_service_driver(service) {
            debug_print!("[storage] servico {} nao carregou", service);
        }
    }
    if let Err(error) = pnp::tree::process() {
        debug_print!("[storage] arvore do PnP: {}", error);
    }
    for (path, state, problem, service) in pnp::tree::summary() {
        debug_print!("[storage] devnode {} estado {:?} problema {:#x} servico {}", path, state, problem, service.as_deref().unwrap_or("-"));
    }
    log_published_objects();
    let Some(disk) = disk_device(1) else {
        debug_print!("[storage] \\Device\\Harddisk1\\DR1 nao existe: o disco 1 nao chegou ao disk.sys");
        return;
    };
    match read_through_stack(disk, 0) {
        Ok(mut bytes) if signature_only_difference(&bytes, &reference) => {
            // O partmgr.sys dá uma assinatura de disco MBR (offset 0x1B8 do
            // setor 0) a um disco que não tem nenhuma, como no Windows: o
            // único byte a mudar no disco desde a leitura de referência.
            if bytes[DISK_SIGNATURE..DISK_SIGNATURE + 4] != reference[DISK_SIGNATURE..DISK_SIGNATURE + 4] {
                let signature = u32::from_le_bytes([bytes[DISK_SIGNATURE], bytes[DISK_SIGNATURE + 1], bytes[DISK_SIGNATURE + 2], bytes[DISK_SIGNATURE + 3]]);
                debug_print!("[storage] o partmgr.sys gravou a assinatura de disco {:#010x} no setor 0 do disco 1", signature);
                bytes[DISK_SIGNATURE..DISK_SIGNATURE + 4].copy_from_slice(&reference[DISK_SIGNATURE..DISK_SIGNATURE + 4]);
            }
            let oem = core::str::from_utf8(&bytes[3..11]).unwrap_or("?");
            let serial = core::str::from_utf8(&bytes[72..80]).unwrap_or("?");
            debug_print!("[storage] {} setores do disco 1 pela pilha real == imagem do xtask (OEM {:?}, serie {:?})", SECTORS, oem, serial);
            if oem == "NTFS    " && serial == "OPENNT!!" {
                debug_print!("STORAGE_REAL_OK");
            }
        }
        Ok(bytes) => {
            let first = bytes.iter().zip(&reference).position(|(left, right)| left != right).unwrap_or(0);
            debug_print!("[storage] leitura pela pilha real difere da imagem no byte {}", first);
        }
        Err(error) => debug_print!("[storage] leitura pela pilha real falhou: {}", error),
    }
}
