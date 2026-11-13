//! Suporte do I/O Manager a file systems — io\iomgr (iosubs.c/internal.c):
//! banco de file systems registrados (filas disco/CD-ROM/fita/rede),
//! notificações de registro (filtros legados e o fltmgr), verificação de
//! volume, stream file objects, cancelamento de abertura e o nome do
//! FILE_OBJECT.
//!
//! Derivado do ntoskrnl 10.0.19045 (RVAs nos comentários de cada função). As
//! filas são LIST_ENTRY reais no convidado, ligadas por
//! DEVICE_OBJECT.Queue.ListEntry, sob um ERESOURCE de convidado (o
//! IopDatabaseResource), recursivo para o dono como no NT.
//!
//! O que NÃO existe no OpenNT (e aqui não é fingido): o IopMountVolume — o
//! caminho que, no IopParseDevice/IopCheckVpbMounted, percorre a fila do tipo
//! do dispositivo e envia IRP_MJ_FILE_SYSTEM_CONTROL/IRP_MN_MOUNT_VOLUME a cada
//! file system registrado. `registered_file_systems` entrega a fila a esse
//! caminho quando ele entrar; até lá `verify_volume` devolve
//! STATUS_UNRECOGNIZED_VOLUME no ramo que precisaria remontar.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::ex::{pool_allocation, resource};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, DriverObject, Eresource, Ethread, FileObject, IoStackLocation, Irp, ListEntry, Vpb};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::file::information;
use crate::ntos::io::io_manager;
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::threads::thread_requests;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
use crate::ntos::ob::objects::file::FileCallbacks;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_PENDING: u32 = 0x103;
pub const STATUS_WRONG_VOLUME: u32 = 0xC000_0012;
pub const STATUS_DEVICE_ALREADY_ATTACHED: u32 = 0xC000_0038;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const STATUS_UNRECOGNIZED_VOLUME: u32 = 0xC000_014F;
pub const STATUS_RETRY: u32 = 0xC000_022D;

const DO_VERIFY_VOLUME: u32 = 0x02;
const DO_DEVICE_INITIALIZING: u32 = 0x80;
const DO_LONG_TERM_REQUESTS: u32 = 0x200;
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const DO_LOW_PRIORITY_FILESYSTEM: u32 = 0x1_0000;
const DRVO_BASE_FILESYSTEM_DRIVER: u32 = 0x80;
const FILE_DEVICE_CD_ROM_FILE_SYSTEM: u32 = 0x03;
const FILE_DEVICE_DISK_FILE_SYSTEM: u32 = 0x08;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u32 = 0x14;
const FILE_DEVICE_TAPE_FILE_SYSTEM: u32 = 0x20;
const VPB_MOUNTED: u16 = 0x01;
const VPB_TAG: u32 = 0x2062_7056; // 'Vpb '
const IO_TYPE_VPB: i16 = 10;
const FO_STREAM_FILE: u32 = 0x100;
const FO_HANDLE_CREATED: u32 = 0x4_0000;
const FO_FILE_OPEN_CANCELLED: u32 = 0x20_0000;
const FO_QUEUE_IRP_TO_THREAD: u32 = 0x400_0000;
const IRP_SYNCHRONOUS_API: u32 = 0x04;
const IRP_CLOSE_OPERATION: u32 = 0x400;
const IRP_SYNCHRONOUS_PAGING_IO: u32 = 0x40;
const IRP_MOUNT_COMPLETION: u32 = 0x02;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
const IRP_MJ_CLEANUP: u8 = 0x12;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MN_VERIFY_VOLUME: u8 = 0x02;
const IO_DISK_INCREMENT: u64 = 1;
const NOTIFY_TAG: u32 = 0x7346_6F49; // 'IoFs'
const PAGED_POOL: u32 = 1;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// DEVICE_OBJECT.Queue.ListEntry: o elo de um CDO na fila de file systems.
const QUEUE_LINK: u64 = offset_of!(DeviceObject, queue.list_entry) as u64;

/// Pacote da fila de notificação (IoFs, 0x20: privado do I/O Manager).
#[repr(C)]
struct NotificationPacket {
    list_entry: ListEntry,
    driver_object: Field<u64>,
    notification_routine: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for NotificationPacket {}

/// Cabeças das quatro filas, a de notificação e o ERESOURCE (bloco do OpenNT).
#[repr(C)]
struct DatabaseBlock {
    disk: ListEntry,
    cd_rom: ListEntry,
    tape: ListEntry,
    network: ListEntry,
    notify: ListEntry,
    _pad_50: Reserved<0x10>,
    resource: Eresource,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DatabaseBlock {}

const _: () = {
    assert!(core::mem::size_of::<NotificationPacket>() == 0x20);
    assert!(core::mem::offset_of!(NotificationPacket, notification_routine) == 0x18);
    assert!(core::mem::offset_of!(DatabaseBlock, notify) == 0x40);
    assert!(core::mem::offset_of!(DatabaseBlock, resource) == 0x60);
};

static DATABASE: SpinLock<u64> = SpinLock::new(0);
/// IopSetFsRegistrationInProgress.
static REGISTRATION_IN_PROGRESS: AtomicBool = AtomicBool::new(false);
/// IopFsRegistrationOps.
static REGISTRATION_OPS: AtomicU32 = AtomicU32::new(0);

fn database() -> Result<&'static DatabaseBlock, KernelError> {
    let mut slot = DATABASE.lock();
    if *slot == 0 {
        let address = guest::alloc_bytes(DatabaseBlock::SIZE);
        if address == 0 {
            return Err(KernelError::with_status("file system database allocation failed", STATUS_INSUFFICIENT_RESOURCES));
        }
        // SAFETY: acabou de ser alocado com o tamanho do bloco.
        let block = unsafe { DatabaseBlock::at(address) };
        for head in [&block.disk, &block.cd_rom, &block.tape, &block.network, &block.notify] {
            head.flink.set(head.address());
            head.blink.set(head.address());
        }
        resource::initialize(block.resource.address())?;
        *slot = address;
    }
    // SAFETY: publicado acima; vive pelo resto do boot.
    Ok(unsafe { DatabaseBlock::at(*slot) })
}

fn list(address: u64) -> &'static ListEntry {
    // SAFETY: elos das filas do banco (cabeças do bloco ou Queue.ListEntry de CDOs registrados).
    unsafe { ListEntry::at(address) }
}

fn device_object(address: u64) -> &'static DeviceObject {
    // SAFETY: DEVICE_OBJECTs vivos passados por drivers ou guardados nas filas.
    unsafe { DeviceObject::at(address) }
}

// ---- LIST_ENTRY com as checagens de integridade do NT (int 0x29 -> erro) ------

fn list_corrupt() -> KernelError {
    KernelError::new("FAST_FAIL_CORRUPT_LIST_ENTRY in the file system queue")
}

fn insert_after(previous: &ListEntry, entry: &ListEntry) -> Result<(), KernelError> {
    let next = list(previous.flink.get());
    if next.blink.get() != previous.address() {
        return Err(list_corrupt());
    }
    entry.flink.set(next.address());
    entry.blink.set(previous.address());
    next.blink.set(entry.address());
    previous.flink.set(entry.address());
    Ok(())
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) -> Result<(), KernelError> {
    let last = list(head.blink.get());
    if last.flink.get() != head.address() {
        return Err(list_corrupt());
    }
    insert_after(last, entry)
}

/// RemoveEntryList sem reinicializar a entrada (como o IoUnregisterFileSystem).
fn remove_entry(entry: &ListEntry) -> Result<(), KernelError> {
    let (next, previous) = (list(entry.flink.get()), list(entry.blink.get()));
    if next.blink.get() != entry.address() || previous.flink.get() != entry.address() {
        return Err(list_corrupt());
    }
    previous.flink.set(next.address());
    next.blink.set(previous.address());
    Ok(())
}

fn entries(head: &ListEntry) -> Vec<u64> {
    let mut found = Vec::new();
    let mut cursor = head.flink.get();
    while cursor != head.address() && cursor != 0 && found.len() < 0x10000 {
        found.push(cursor);
        cursor = list(cursor).flink.get();
    }
    found
}

fn queue_for(database: &'static DatabaseBlock, device_type: u32) -> Option<&'static ListEntry> {
    match device_type {
        FILE_DEVICE_DISK_FILE_SYSTEM => Some(&database.disk),
        FILE_DEVICE_CD_ROM_FILE_SYSTEM => Some(&database.cd_rom),
        FILE_DEVICE_TAPE_FILE_SYSTEM => Some(&database.tape),
        FILE_DEVICE_NETWORK_FILE_SYSTEM => Some(&database.network),
        _ => None,
    }
}

/// Os CDOs registrados para um tipo de file system, na ordem de montagem
/// (para o IopMountVolume quando ele existir no OpenNT).
pub fn registered_file_systems(device_type: u32) -> Vec<u64> {
    let Ok(database) = database() else { return Vec::new() };
    queue_for(database, device_type).map(|head| entries(head).into_iter().map(|link| link - QUEUE_LINK).collect()).unwrap_or_default()
}

/// IopIncrementDeviceObjectRefCount / IopDecrementDeviceObjectRefCount.
fn reference_device(device: &DeviceObject) {
    device.reference_count.atomic().fetch_add(1, Ordering::SeqCst);
}

fn dereference_device(device: &DeviceObject) {
    device.reference_count.atomic().fetch_sub(1, Ordering::SeqCst);
    device_objects::changed(device.address());
}

/// IopIncrementVpbRefCount / IopDecrementVpbRefCount sob o LockQueueIoVpbLock.
fn adjust_vpb_references(vpb: &Vpb, delta: i32) -> Result<u32, KernelError> {
    let irql = guest::alloc_bytes(8);
    crate::ntos::ke::spin_lock::acquire_vpb_spin_lock(irql)?;
    let count = vpb.reference_count.atomic().fetch_add(delta as u32, Ordering::SeqCst).wrapping_add(delta as u32);
    // SAFETY: a célula de IRQL que o acquire acabou de gravar.
    crate::ntos::ke::spin_lock::release_vpb_spin_lock(unsafe { Field::<u8>::at(irql) }.get() as u64)?;
    guest::free_bytes(irql);
    Ok(count)
}

fn call_notification(routine: u64, device: u64, active: bool) {
    native_call::call(routine, &[device, active as u64]);
}

fn notification_packets(database: &'static DatabaseBlock) -> Vec<&'static NotificationPacket> {
    // SAFETY: a fila de notificação só liga pacotes IoFs alocados aqui.
    entries(&database.notify).into_iter().map(|entry| unsafe { NotificationPacket::at(entry) }).collect()
}

fn acquire_database(database: &DatabaseBlock, synchronize: bool) -> Result<Option<u32>, KernelError> {
    let resource = database.resource.address();
    if synchronize && resource::acquire_exclusive(resource, false)? == 0 {
        if REGISTRATION_IN_PROGRESS.load(Ordering::Acquire) {
            return Ok(Some(STATUS_RETRY));
        }
        resource::acquire_exclusive(resource, true)?;
    } else if !synchronize {
        resource::acquire_exclusive(resource, true)?;
    }
    Ok(None)
}

/// IoRegisterFileSystem (RVA 0x7806e0).
pub fn register_file_system(device: &DeviceObject) -> Result<(), KernelError> {
    let driver_address = device.driver_object.get();
    // O status do FsRtlSetDriverBacking é ignorado aqui, como no NT.
    invoke_handler("FsRtlSetDriverBacking", &[driver_address, 1])?;
    critical_region::enter_critical()?;
    REGISTRATION_IN_PROGRESS.store(true, Ordering::Release);
    let database = database()?;
    resource::acquire_exclusive(database.resource.address(), true)?;
    let result = (|| -> Result<(), KernelError> {
        let device_type = device.device_type.get();
        if let Some(head) = queue_for(database, device_type) {
            if device_type != FILE_DEVICE_NETWORK_FILE_SYSTEM {
                // SAFETY: o DRIVER_OBJECT dono do CDO.
                let driver = unsafe { DriverObject::at(driver_address) };
                driver.flags.atomic().fetch_or(DRVO_BASE_FILESYSTEM_DRIVER, Ordering::SeqCst);
            }
            let flags = device.flags.get();
            let entry = &device.queue.list_entry;
            if flags & DO_LOW_PRIORITY_FILESYSTEM != 0 {
                insert_tail(head, entry)?;
            } else if flags & DO_LONG_TERM_REQUESTS != 0 {
                insert_after(head, entry)?;
            } else {
                // Depois dos que pedem DO_LONG_TERM_REQUESTS, antes dos demais.
                let mut previous = head;
                let mut next = head.flink.get();
                while next != head.address() && device_object(next - QUEUE_LINK).flags.get() & DO_LONG_TERM_REQUESTS != 0 {
                    previous = list(next);
                    next = previous.flink.get();
                }
                insert_after(previous, entry)?;
            }
        }
        REGISTRATION_OPS.fetch_add(1, Ordering::AcqRel);
        device.flags.atomic().fetch_and(!DO_DEVICE_INITIALIZING, Ordering::SeqCst);
        for packet in notification_packets(database) {
            call_notification(packet.notification_routine.get(), device.address(), true);
        }
        Ok(())
    })();
    REGISTRATION_IN_PROGRESS.store(false, Ordering::Release);
    resource::release(database.resource.address())?;
    critical_region::leave_critical()?;
    result?;
    reference_device(device);
    Ok(())
}

/// IoUnregisterFileSystem (RVA 0x77cf30).
pub fn unregister_file_system(device: &DeviceObject) -> Result<(), KernelError> {
    critical_region::enter_critical()?;
    let database = database()?;
    resource::acquire_exclusive(database.resource.address(), true)?;
    let result = (|| -> Result<(), KernelError> {
        let entry = &device.queue.list_entry;
        if entry.flink.get() != 0 {
            remove_entry(entry)?;
        }
        for packet in notification_packets(database) {
            call_notification(packet.notification_routine.get(), device.address(), false);
        }
        REGISTRATION_OPS.fetch_add(1, Ordering::AcqRel);
        Ok(())
    })();
    resource::release(database.resource.address())?;
    critical_region::leave_critical()?;
    result?;
    dereference_device(device);
    Ok(())
}

/// IopNotifyAlreadyRegisteredFileSystems: o último da fila (RAW) é pulado nas
/// filas locais.
fn notify_already_registered(head: &ListEntry, routine: u64, skip_last: bool) {
    let found = entries(head);
    for (index, &entry) in found.iter().enumerate() {
        if skip_last && index + 1 == found.len() {
            break;
        }
        call_notification(routine, entry - QUEUE_LINK, true);
    }
}

/// IoRegisterFsRegistrationChangeMountAware (RVA 0x7c9a80). O OpenNT não tem
/// IopBlockLegacyFsFilters nem montagens em andamento.
pub fn register_fs_registration_change(driver: u64, routine: u64, synchronize: bool) -> Result<u32, KernelError> {
    let status = invoke_handler("FsRtlSetDriverBacking", &[driver, 1])? as u32;
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    critical_region::enter_critical()?;
    let database = database()?;
    if let Some(status) = acquire_database(database, synchronize)? {
        critical_region::leave_critical()?;
        return Ok(status);
    }
    let result = (|| -> Result<u32, KernelError> {
        let tail = database.notify.blink.get();
        if tail != database.notify.address() {
            // SAFETY: elo da fila de notificação = pacote IoFs.
            let last = unsafe { NotificationPacket::at(tail) };
            if last.driver_object.get() == driver && last.notification_routine.get() == routine {
                return Ok(STATUS_DEVICE_ALREADY_ATTACHED);
            }
        }
        let address = pool_allocation::allocate_tagged(PAGED_POOL, NotificationPacket::SIZE, NOTIFY_TAG)?;
        if address == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: acabou de ser alocado com o tamanho do pacote.
        let packet = unsafe { NotificationPacket::at(address) };
        packet.driver_object.set(driver);
        packet.notification_routine.set(routine);
        insert_tail(&database.notify, &packet.list_entry)?;
        notify_already_registered(&database.network, routine, false);
        notify_already_registered(&database.cd_rom, routine, true);
        notify_already_registered(&database.disk, routine, true);
        notify_already_registered(&database.tape, routine, true);
        Ok(STATUS_SUCCESS)
    })();
    resource::release(database.resource.address())?;
    critical_region::leave_critical()?;
    let status = result?;
    if status == STATUS_SUCCESS {
        invoke_handler("ObfReferenceObject", &[driver])?;
    }
    Ok(status)
}

/// IoEnumerateRegisteredFiltersList(List, ListSizeBytes, *Actual) (RVA 0x76bfb0).
pub fn enumerate_registered_filters(list_output: u64, list_size: u32, actual: &Field<u32>) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let database = database()?;
    if let Some(status) = acquire_database(database, true)? {
        critical_region::leave_critical()?;
        return Ok(status);
    }
    let packets = notification_packets(database);
    let capacity = (list_size >> 3) as usize;
    actual.set(packets.len() as u32);
    let status = if capacity < packets.len() { STATUS_BUFFER_TOO_SMALL } else { STATUS_SUCCESS };
    let mut result = Ok(());
    if capacity != 0 {
        // SAFETY: o vetor PDRIVER_OBJECT do chamador tem ListSizeBytes bytes.
        let slots = unsafe { Field::<u64>::array_at(list_output, capacity) };
        for (slot, packet) in slots.iter().zip(&packets) {
            let driver = packet.driver_object.get();
            if let Err(error) = invoke_handler("ObfReferenceObject", &[driver]) {
                result = Err(error);
                break;
            }
            slot.set(driver);
        }
    }
    resource::release(database.resource.address())?;
    critical_region::leave_critical()?;
    result.map(|_| status)
}

/// IoGetBaseFileSystemDeviceObject (RVA 0x2d7870): o DeviceObject do VPB do
/// arquivo, senão o do VPB do dispositivo, senão o dispositivo do arquivo.
pub fn base_file_system_device(file: &FileObject) -> u64 {
    let vpb = file.vpb.get();
    if vpb != 0 {
        // SAFETY: FileObject->Vpb é o VPB do volume.
        let mounted = unsafe { Vpb::at(vpb) }.device_object.get();
        if mounted != 0 {
            return mounted;
        }
    }
    let device = file.device_object.get();
    if file.flags.get() & FO_DIRECT_DEVICE_OPEN == 0 {
        let volume = device_object(device).vpb.get();
        if volume != 0 {
            // SAFETY: DeviceObject->Vpb é o VPB do dispositivo real.
            let mounted = unsafe { Vpb::at(volume) }.device_object.get();
            if mounted != 0 {
                return mounted;
            }
        }
    }
    device
}

/// IoGetDeviceToVerify / IoSetDeviceToVerify: ETHREAD.DeviceToVerify.
pub fn device_to_verify(thread: &Ethread) -> u64 {
    thread.device_to_verify.get()
}

pub fn set_device_to_verify(thread: &Ethread, device: u64) {
    thread.device_to_verify.set(device);
}

/// IopCreateVpb (RVA 0x781220): VPB zerado ('Vpb ', NonPagedPoolNx) com
/// Type=10/Size=0x60 e RealDevice, ligado em DeviceObject->Vpb.
pub fn create_vpb(device: &DeviceObject) -> Result<u32, KernelError> {
    let address = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, Vpb::SIZE, VPB_TAG)?;
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(address, &[0u8; Vpb::SIZE as usize]);
    // SAFETY: acabou de ser alocado com o tamanho do VPB.
    let vpb = unsafe { Vpb::at(address) };
    vpb.type_.set(IO_TYPE_VPB);
    vpb.size.set(Vpb::SIZE as i16);
    vpb.real_device.set(device.address());
    device.vpb.set(address);
    Ok(STATUS_SUCCESS)
}

/// O DeviceLock é um evento de sincronização sinalizado criado pelo
/// IoCreateDevice do NT; o IoCreateDevice do OpenNT ainda não o inicializa.
fn device_lock(device: &DeviceObject) -> u64 {
    let lock = &device.device_lock;
    if lock.header.type_.get() != 1 {
        dispatcher::initialize_event(lock.address(), 1, true);
    }
    lock.address()
}

/// IRP síncrono a um dispositivo, com a thread na fila de IRPs; espera
/// STATUS_PENDING e devolve o status final.
fn send_synchronous_irp(target: &DeviceObject, irp_flags: u32, configure: impl FnOnce(&Irp, &IoStackLocation)) -> Result<u32, KernelError> {
    let count = (target.stack_size.get() as u8 as u32).max(1);
    let scratch = guest::alloc_bytes(0x30);
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if scratch == 0 || packet == 0 {
        for block in [scratch, packet] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let (event, io_status) = (scratch, scratch + 0x18);
    dispatcher::initialize_event(event, 1, false);
    let thread = process::get_current_thread();
    irp_builder::build(packet, &BuildOptions { device_object: target.address(), stack_count: count, user_event: event, user_iosb: io_status, thread, requestor_mode: 0, ..Default::default() });
    // SAFETY: o IRP e o slot acabaram de ser montados pelo irp_builder.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    irp.flags.set(irp_flags);
    configure(irp, stack);
    let queued = thread != 0 && thread_requests::insert(packet, thread).is_ok();
    let mut status = io_manager::iof_call_driver(target.address(), packet) as u32;
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        // SAFETY: o IO_STATUS_BLOCK do scratch.
        status = unsafe { crate::ntos::inc::types::IoStatusBlock::at(io_status) }.status.get() as u32;
    }
    if queued && irp.thread_list_entry.flink.get() != 0 {
        thread_requests::remove(packet, thread)?;
    }
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    Ok(status)
}

/// IopReferenceVerifyVpb: VPB montado -> referência e o DeviceObject do FS.
fn reference_mounted_vpb(device: &DeviceObject) -> Result<Option<(&'static Vpb, u64)>, KernelError> {
    let address = device.vpb.get();
    if address == 0 {
        return Ok(None);
    }
    // SAFETY: DeviceObject->Vpb é o VPB do dispositivo real.
    let vpb = unsafe { Vpb::at(address) };
    if vpb.flags.get() & VPB_MOUNTED == 0 {
        return Ok(None);
    }
    adjust_vpb_references(vpb, 1)?;
    Ok(Some((vpb, vpb.device_object.get())))
}

/// IoVerifyVolume(DeviceObject, AllowRawMount) (RVA 0x893e50).
pub fn verify_volume(device: &DeviceObject, allow_raw_mount: bool) -> Result<u32, KernelError> {
    critical_region::enter_critical()?;
    let lock = device_lock(device);
    dispatcher::wait_for_single_object(lock, 0, 0, false);
    let result = (|| -> Result<u32, KernelError> {
        if let Some((vpb, file_system)) = reference_mounted_vpb(device)? {
            let target = device_object(device_objects::top(file_system));
            let status = send_synchronous_irp(target, IRP_SYNCHRONOUS_PAGING_IO | IRP_MOUNT_COMPLETION, |_, stack| {
                stack.major_function.set(IRP_MJ_FILE_SYSTEM_CONTROL);
                stack.minor_function.set(IRP_MN_VERIFY_VOLUME);
                stack.flags.set(allow_raw_mount as u8);
                stack.parameters.verify_volume.vpb.set(vpb.address());
                stack.parameters.verify_volume.device_object.set(device.address());
            })?;
            adjust_vpb_references(vpb, -1)?;
            if status != STATUS_WRONG_VOLUME {
                return Ok(status);
            }
        }
        // Volume ausente ou trocado: IopCreateVpb + IopMountVolume. O mount
        // path não existe no OpenNT; o resultado é o de nenhum FS reconhecer.
        let mut status = create_vpb(device)?;
        if status == STATUS_SUCCESS {
            status = STATUS_UNRECOGNIZED_VOLUME;
        }
        device.flags.atomic().fetch_and(!DO_VERIFY_VOLUME, Ordering::SeqCst);
        Ok(status)
    })();
    dispatcher::set_event(lock);
    critical_region::leave_critical()?;
    result
}

/// IRP_MJ_CLEANUP/IRP_MJ_CLOSE de um FILE_OBJECT (IRP_CLOSE_OPERATION|SYNCHRONOUS_API).
fn send_close_irp(target: u64, file: u64, major: u8) -> Result<u32, KernelError> {
    if target == 0 {
        return Ok(STATUS_SUCCESS);
    }
    send_synchronous_irp(device_object(target), IRP_CLOSE_OPERATION | IRP_SYNCHRONOUS_API, |irp, stack| {
        irp.tail.overlay.original_file_object.set(file);
        stack.major_function.set(major);
        stack.file_object.set(file);
    })
}

/// IoCreateStreamFileObject[Lite] -> IoCreateStreamFileObjectEx2 (RVA 0x719a80).
/// O stream nasce com FO_STREAM_FILE, referencia o dispositivo e o VPB; a
/// versão normal abre e fecha um handle (o FS recebe IRP_MJ_CLEANUP), a Lite
/// não. A última referência envia IRP_MJ_CLOSE e solta as referências.
/// Recebe endereços (FileObject opcional) porque io-file-system-support
/// (IoCreateStreamFileObjectEx) a chama assim.
pub fn create_stream_file_object(file: u64, device: u64, lite: bool) -> Result<u64, KernelError> {
    // SAFETY: FILE_OBJECT vivo do chamador, quando presente.
    let device_address = if file != 0 { unsafe { FileObject::at(file) }.device_object.get() } else { device };
    if device_address == 0 {
        return Err(KernelError::with_status("IoCreateStreamFileObject without device", 0xC000_000D));
    }
    let device = device_object(device_address);
    reference_device(device);
    let stream_address = match file_objects::create(device_address, "") {
        Ok(stream) => stream,
        Err(error) => {
            dereference_device(device);
            return Err(error);
        }
    };
    // SAFETY: o FILE_OBJECT que acabou de ser criado.
    let stream = unsafe { FileObject::at(stream_address) };
    stream.flags.set(FO_STREAM_FILE);
    dispatcher::initialize_event(stream.event.address(), 1, false);
    let vpb_address = device.vpb.get();
    if vpb_address != 0 {
        // SAFETY: DeviceObject->Vpb.
        adjust_vpb_references(unsafe { Vpb::at(vpb_address) }, 1)?;
    }
    file_objects::set_callbacks(stream_address, FileCallbacks {
        cleanup: Some(Arc::new(move || send_close_irp(information::related_device(stream_address).unwrap_or(0), stream_address, IRP_MJ_CLEANUP).unwrap_or(0))),
        close: Some(Arc::new(move || {
            let _ = send_close_irp(information::related_device(stream_address).unwrap_or(0), stream_address, IRP_MJ_CLOSE);
            if vpb_address != 0 {
                // SAFETY: o VPB referenciado na criação continua vivo até aqui.
                let _ = adjust_vpb_references(unsafe { Vpb::at(vpb_address) }, -1);
            }
            dereference_device(device_object(device_address));
        })),
        destroy: None,
    })?;
    if lite {
        stream.flags.atomic().fetch_or(FO_HANDLE_CREATED, Ordering::SeqCst);
    } else {
        file_objects::open_handle(stream_address)?;
        file_objects::close_handle(stream_address)?;
    }
    Ok(stream_address)
}

/// IoCancelFileOpen(DeviceObject, FileObject) (RVA 0x893590): um handle já
/// criado é bugcheck 0xE8; senão IRP_MJ_CLEANUP ao dispositivo e
/// FO_FILE_OPEN_CANCELLED.
pub fn cancel_file_open(device: &DeviceObject, file: &FileObject) -> Result<(), KernelError> {
    if file.flags.get() & FO_HANDLE_CREATED != 0 {
        crate::ntos::ke::bugcheck::bug_check_ex(0xE8, file.address(), device.address(), 0, 0);
    }
    if file.flags.get() & FO_QUEUE_IRP_TO_THREAD == 0 {
        dispatcher::clear_event(file.event.address());
    }
    send_close_irp(device.address(), file.address(), IRP_MJ_CLEANUP)?;
    dispatcher::clear_event(file.event.address());
    file.flags.atomic().fetch_or(FO_FILE_OPEN_CANCELLED, Ordering::SeqCst);
    Ok(())
}

/// IoReplaceFileObjectName(FileObject, NewFileName, Length) (RVA 0x734e90):
/// buffer novo (o NT usa pool paginado 'IoNm') em degraus de 0x38/0x78/>=0xF8
/// quando o atual não cabe; o resto do buffer é zerado.
pub fn replace_file_object_name(file: &FileObject, name: u64, length: u16) -> Result<u32, KernelError> {
    let file_name = &file.file_name;
    let mut maximum = file_name.maximum_length.get();
    if length > maximum {
        maximum = if length < 0x38 { 0x38 } else if length < 0x78 { 0x78 } else { length.max(0xF8) };
        // O corpo e o nome de um FILE_OBJECT do OpenNT vivem na arena do
        // convidado (ob::objects::file libera o nome registrado com free_bytes).
        let buffer = guest::alloc_bytes(maximum as u64);
        if buffer == 0 {
            return Ok(STATUS_INSUFFICIENT_RESOURCES);
        }
        let old = file_name.buffer.get();
        if old != 0 {
            invoke_handler("ExFreePool", &[old])?;
        }
        file_name.buffer.set(buffer);
        file_name.maximum_length.set(maximum);
        file_objects::set_name_buffer(file.address(), buffer)?;
    }
    let buffer = file_name.buffer.get();
    file_name.length.set(length);
    guest::write_bytes(buffer, &alloc::vec![0u8; maximum as usize]);
    guest::write_bytes(buffer, &guest::read_bytes(name, length as usize));
    Ok(STATUS_SUCCESS)
}

/// IoRaiseHardError(Irp, Vpb, RealDeviceObject) (RVA 0x5058f0). O OpenNT não
/// tem a entrega de hard errors ao csrss (ExRaiseHardError/popup), então todo
/// pedido segue o ramo do NT para threads com hard errors desabilitados:
/// IRP_SYNCHRONOUS_PAGING_IO zera Information e o IRP é concluído com o
/// status que o FS já gravou.
pub fn raise_hard_error(irp: &Irp) -> Result<(), KernelError> {
    if irp.flags.get() & IRP_SYNCHRONOUS_PAGING_IO != 0 {
        irp.io_status.information.set(0);
    }
    invoke_handler("IofCompleteRequest", &[irp.address(), IO_DISK_INCREMENT])?;
    Ok(())
}

// ---- IoCreateStreamFileObjectEx (io-file-system-support) --------------------
//
// Autocontido (caminhos qualificados, nomes com prefixo `STREAM_`); usa o
// `create_stream_file_object` deste módulo (IoCreateStreamFileObjectEx2).

/// OBJ_KERNEL_HANDLE dos OBJECT_ATTRIBUTES montados pelo Ex2.
const STREAM_HANDLE_ATTRIBUTES: u32 = 0x200;
/// DesiredAccess do ObInsertObjectEx no IoCreateStreamFileObjectEx2 (FILE_READ_DATA).
const STREAM_HANDLE_ACCESS: u32 = 1;

/// IoCreateStreamFileObjectEx(FileObject, DeviceObject, *FileHandle) ->
/// IoCreateStreamFileObjectEx2 com CREATE_OPTIONS {Size 0x10, Flags 1}
/// (RVA 0x772e80): sem FileHandle é o IoCreateStreamFileObject (handle aberto
/// e fechado, o FS recebe IRP_MJ_CLEANUP); com FileHandle o handle de kernel
/// do ObInsertObjectEx fica com o chamador (`handle_output`, o PHANDLE dele),
/// que o fecha com ZwClose/ObCloseHandle — o IRP_MJ_CLEANUP vem nesse
/// fechamento.
pub fn create_stream_file_object_ex(file: u64, device: u64, handle_output: Option<&crate::ntos::inc::field::Field<u64>>) -> Result<u64, crate::rtl::KernelError> {
    let Some(handle_output) = handle_output else { return create_stream_file_object(file, device, false) };
    // Lite: referências de dispositivo/VPB e FO_HANDLE_CREATED, sem handle.
    let stream = create_stream_file_object(file, device, true)?;
    crate::ntos::ob::objects::file::mark_opened(stream)?;
    let status = crate::ntos::ob::open_pointer::open(stream, STREAM_HANDLE_ATTRIBUTES, 0, STREAM_HANDLE_ACCESS, 0, 0, handle_output.address())?;
    if status != 0 {
        crate::ntos::ob::objects::file::dereference(stream)?;
        return Err(crate::rtl::KernelError::with_status("IoCreateStreamFileObjectEx: ObInsertObjectEx", status));
    }
    Ok(stream)
}
