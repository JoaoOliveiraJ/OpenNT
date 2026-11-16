//! O desligamento do I/O Manager: as filas de notificação de desligamento
//! (IoRegisterShutdownNotification, IoRegisterLastChanceShutdownNotification,
//! IoUnregisterShutdownNotification) e o IoShutdownSystem.
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   IoRegisterShutdownNotification rva 0x7be8c0 e
//!   IoRegisterLastChanceShutdownNotification rva 0x7be840: bloco de 0x18
//!     (LIST_ENTRY + DeviceObject) em NonPagedPoolNx ('IoSh');
//!     ObReferenceObject(Device); inserção na CABEÇA da fila
//!     (IopNotifyShutdownQueueHead / IopNotifyLastChanceShutdownQueueHead):
//!     o último a registrar é o primeiro avisado;
//!     Device->Flags |= DO_SHUTDOWN_REGISTERED (bit 11); STATUS_SUCCESS, ou
//!     STATUS_INSUFFICIENT_RESOURCES sem pool.
//!   IoUnregisterShutdownNotification rva 0x9ab150: tira das duas filas toda
//!     entrada do dispositivo (ObDereferenceObject de cada uma) e limpa o
//!     DO_SHUTDOWN_REGISTERED.
//!   IoShutdownSystem(0) rva 0x9aaf18: PnpShutdownDevices (o PnpShutdownEvent;
//!     a desmontagem das pilhas só com PnpTearDownPnpStacksOnShutdown, que o
//!     19041 deixa desligado) e, da cabeça para a cauda, cada entrada da fila
//!     comum sai da fila e recebe IRP_MJ_SHUTDOWN síncrono
//!     (IoBuildSynchronousFsdRequest) no topo da pilha
//!     (IoGetAttachedDeviceReference), esperando o evento se o driver devolve
//!     STATUS_PENDING; as duas referências voltam e o bloco é liberado.
//!   IoShutdownSystem(1): o IopDatabaseResource exclusivo (não é mais
//!     solto: nenhum file system registra nem monta depois disso), os file
//!     systems de disco, de CD-ROM e de fita (IopShutdownBaseFileSystems:
//!     cada CDO sai da fila, referenciado, e recebe IRP_MJ_SHUTDOWN no
//!     IoGetAttachedDevice, onde fica o filtro anexado, como o FltMgr), e
//!     depois a fila de última chance, como a fila comum.
//!
//! O NTFS e os outros file systems recebem o desligamento pela fila de file
//! systems (o ntfs.sys não chama o IoRegisterShutdownNotification); o
//! mountmgr.sys registra na fila comum e o volmgr.sys na de última chance.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::inc::types::{DeviceObject, IoStatusBlock, Kevent, NtStruct};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::file_system;
use crate::ntos::io::io_manager::{self, irp_mj};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::{KernelError, SpinLock};

const DO_SHUTDOWN_REGISTERED: u32 = 0x0000_0800;
const STATUS_PENDING: u32 = 0x103;

/// As duas filas, na ordem de entrega (a cabeça é o último registrado).
static NOTIFY_QUEUE: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
static LAST_CHANCE_QUEUE: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());
/// PnpShutdownEvent: o PnP não aceita mais trabalho de dispositivo.
static PNP_SHUT_DOWN: AtomicBool = AtomicBool::new(false);
/// IRP_MJ_SHUTDOWN entregues por fase: fila comum, file systems e última
/// chance (a serial do desligamento mostra os três).
static DELIVERED: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];

fn device(address: u64) -> &'static DeviceObject {
    // SAFETY: DEVICE_OBJECT vivo, referenciado por quem o pôs na fila.
    unsafe { DeviceObject::at(address) }
}

fn register(queue: &SpinLock<Vec<u64>>, device_address: u64) -> Result<u32, KernelError> {
    invoke_handler("ObfReferenceObject", &[device_address])?;
    queue.lock().insert(0, device_address);
    device(device_address).flags.atomic().fetch_or(DO_SHUTDOWN_REGISTERED, Ordering::SeqCst);
    Ok(0)
}

/// O DriverName do dono do dispositivo, para a serial.
fn driver_name(device_address: u64) -> alloc::string::String {
    let driver = device(device_address).driver_object.get();
    if driver == 0 {
        return alloc::string::String::from("?");
    }
    // SAFETY: o DRIVER_OBJECT dono de um dispositivo vivo.
    crate::ntos::rtl::guest_strings::read_unicode_string(unsafe { crate::ntos::inc::types::DriverObject::at(driver) }.driver_name.address())
}

/// IoRegisterShutdownNotification(DeviceObject).
pub fn register_shutdown(device_address: u64) -> Result<u32, KernelError> {
    register(&NOTIFY_QUEUE, device_address)
}

/// IoRegisterLastChanceShutdownNotification(DeviceObject).
pub fn register_last_chance(device_address: u64) -> Result<u32, KernelError> {
    register(&LAST_CHANCE_QUEUE, device_address)
}

/// IoUnregisterShutdownNotification(DeviceObject): as entradas do
/// dispositivo saem das duas filas.
pub fn unregister(device_address: u64) -> Result<(), KernelError> {
    let mut removed = 0;
    for queue in [&NOTIFY_QUEUE, &LAST_CHANCE_QUEUE] {
        let mut entries = queue.lock();
        let before = entries.len();
        entries.retain(|&candidate| candidate != device_address);
        removed += before - entries.len();
    }
    for _ in 0..removed {
        invoke_handler("ObfDereferenceObject", &[device_address])?;
    }
    device(device_address).flags.atomic().fetch_and(!DO_SHUTDOWN_REGISTERED, Ordering::SeqCst);
    Ok(())
}

/// Os dispositivos da fila comum, na ordem de entrega.
pub fn shutdown_devices() -> Vec<u64> {
    NOTIFY_QUEUE.lock().clone()
}

/// Os dispositivos da fila de última chance, na ordem de entrega.
pub fn last_chance_devices() -> Vec<u64> {
    LAST_CHANCE_QUEUE.lock().clone()
}

/// PnpShutdownEvent sinalizado (IoShutdownSystem(0) já correu).
pub fn pnp_shut_down() -> bool {
    PNP_SHUT_DOWN.load(Ordering::Acquire)
}

/// IRP_MJ_SHUTDOWN entregues: (fila comum, file systems, última chance).
pub fn delivered() -> (u32, u32, u32) {
    (DELIVERED[0].load(Ordering::Acquire), DELIVERED[1].load(Ordering::Acquire), DELIVERED[2].load(Ordering::Acquire))
}

/// IRP_MJ_SHUTDOWN síncrono a `target`, esperando o evento se o driver
/// devolve STATUS_PENDING. Devolve o status final.
pub fn send_shutdown(target: u64) -> u32 {
    let event = guest::alloc_bytes(Kevent::SIZE);
    let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
    if event == 0 || io_status == 0 {
        guest::free_bytes(event);
        guest::free_bytes(io_status);
        return 0xC000_009A;
    }
    dispatcher::initialize_event(event, 0, false);
    let packet = io_manager::build_synchronous_fsd_request(irp_mj::SHUTDOWN, target, 0, 0, 0, event, io_status);
    let mut status = 0xC000_009A;
    if packet != 0 {
        status = io_manager::iof_call_driver(target, packet) as u32;
        if status == STATUS_PENDING {
            dispatcher::wait_for_single_object(event, 0, 0, false);
            // SAFETY: o IO_STATUS_BLOCK alocado acima, gravado na conclusão.
            status = unsafe { IoStatusBlock::at(io_status) }.status.get() as u32;
        }
        guest::free_bytes(packet);
    }
    guest::free_bytes(event);
    guest::free_bytes(io_status);
    status
}

/// Esvazia uma fila de notificação: cada entrada sai da cabeça e recebe o
/// IRP no topo da pilha.
fn drain(queue: &SpinLock<Vec<u64>>, counter: &AtomicU32) -> Result<(), KernelError> {
    loop {
        let next = {
            let mut entries = queue.lock();
            (!entries.is_empty()).then(|| entries.remove(0))
        };
        let Some(registered) = next else { return Ok(()) };
        let status = notify_device(registered)?;
        debug_print!("[io] IRP_MJ_SHUTDOWN -> pilha de {:#x} ({}): {:#x}", registered, driver_name(registered), status);
        counter.fetch_add(1, Ordering::AcqRel);
        invoke_handler("ObfDereferenceObject", &[registered])?;
    }
}

/// O passo de uma entrada das filas: IRP_MJ_SHUTDOWN no topo da pilha do
/// dispositivo registrado (IoGetAttachedDeviceReference), referência
/// devolvida no fim. Devolve o status final do IRP.
pub fn notify_device(registered: u64) -> Result<u32, KernelError> {
    let top = device_objects::attached_reference(registered, false)?;
    let status = send_shutdown(top);
    device_objects::dereference(top)?;
    Ok(status)
}

/// IoShutdownSystem(Phase).
pub fn shutdown_system(phase: u32) -> Result<(), KernelError> {
    match phase {
        0 => {
            // PnpShutdownDevices: o PnpShutdownEvent; sem
            // PnpTearDownPnpStacksOnShutdown as pilhas ficam como estão.
            PNP_SHUT_DOWN.store(true, Ordering::Release);
            drain(&NOTIFY_QUEUE, &DELIVERED[0])
        }
        1 => {
            file_system::shutdown_base_file_systems(|target| {
                let status = send_shutdown(target);
                debug_print!("[io] IRP_MJ_SHUTDOWN -> file system {:#x} ({}): {:#x}", target, driver_name(target), status);
                DELIVERED[1].fetch_add(1, Ordering::AcqRel);
            })?;
            drain(&LAST_CHANCE_QUEUE, &DELIVERED[2])
        }
        _ => Ok(()),
    }
}
