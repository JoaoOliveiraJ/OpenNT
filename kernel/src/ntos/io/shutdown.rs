//! Notificações de desligamento de "última chance" (NT: I/O Manager,
//! IoShutdownSystem fase 1).
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   IoRegisterLastChanceShutdownNotification rva 0x7be840: bloco de 0x18
//!     (LIST_ENTRY + DeviceObject) em NonPagedPool; ObReferenceObject(Device);
//!     inserção na CABEÇA da IopNotifyLastChanceShutdownQueueHead;
//!     Device->Flags |= DO_SHUTDOWN_REGISTERED (bit 11); STATUS_SUCCESS, ou
//!     STATUS_INSUFFICIENT_RESOURCES sem pool.
//!   IoShutdownSystem(1): depois dos sistemas de arquivos, percorre a fila da
//!     cabeça para a cauda e entrega IRP_MJ_SHUTDOWN síncrono ao topo da pilha
//!     de cada dispositivo (IoGetAttachedDeviceReference).
//!
//! A fila é do I/O Manager; o OpenNT ainda não tem o caminho de desligamento
//! que chamaria `run_last_chance_shutdown_notifications` (o mesmo vale para o
//! `run_shutdown_notifications` das notificações comuns).

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::inc::types::{DeviceObject, IoStatusBlock, Kevent, NtStruct};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::io_manager::{self, irp_mj};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::rtl::{KernelError, SpinLock};

const DO_SHUTDOWN_REGISTERED: u32 = 0x0000_0800;
const STATUS_PENDING: u32 = 0x103;

/// Fila na ordem de entrega (a cabeça é o último registrado).
static LAST_CHANCE_QUEUE: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

/// IoRegisterLastChanceShutdownNotification(DeviceObject).
pub fn register_last_chance(device: u64) -> Result<u32, KernelError> {
    invoke_handler("ObfReferenceObject", &[device])?;
    LAST_CHANCE_QUEUE.lock().insert(0, device);
    // SAFETY: DEVICE_OBJECT vivo do driver chamador (referenciado acima).
    unsafe { DeviceObject::at(device) }.flags.atomic().fetch_or(DO_SHUTDOWN_REGISTERED, Ordering::SeqCst);
    Ok(0)
}

/// Dispositivos registrados, na ordem de entrega.
pub fn last_chance_devices() -> Vec<u64> {
    LAST_CHANCE_QUEUE.lock().clone()
}

/// IoShutdownSystem fase 1: IRP_MJ_SHUTDOWN síncrono ao topo de cada pilha
/// registrada, esvaziando a fila.
pub fn run_last_chance_shutdown_notifications() -> Result<(), KernelError> {
    let devices = core::mem::take(&mut *LAST_CHANCE_QUEUE.lock());
    for device in devices {
        let top = device_objects::attached_reference(device, false)?;
        let event = guest::alloc_bytes(Kevent::SIZE);
        let io_status = guest::alloc_bytes(IoStatusBlock::SIZE);
        dispatcher::initialize_event(event, 0, false);
        let packet = io_manager::build_synchronous_fsd_request(irp_mj::SHUTDOWN, top, 0, 0, 0, event, io_status);
        if packet != 0 && io_manager::iof_call_driver(top, packet) as u32 == STATUS_PENDING {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
        if packet != 0 {
            guest::free_bytes(packet);
        }
        guest::free_bytes(event);
        guest::free_bytes(io_status);
        device_objects::dereference(top)?;
        invoke_handler("ObfDereferenceObject", &[device])?;
    }
    Ok(())
}
