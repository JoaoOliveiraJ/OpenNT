//! Pedidos de ejeção de dispositivo: IoRequestDeviceEject e
//! IoRequestDeviceEjectEx.
//!
//! Como no ntoskrnl 19041 (rva 0x50c8f0): um PDO nulo ou sem devnode do PnP
//! (o caso legado também) é PNP_DETECTED_FATAL_ERROR (0xCA, 2, Pdo); senão
//! um bloco de 0x5D8 bytes de NonPagedPoolNx 'PnpF' guarda o callback, o
//! contexto, o DRIVER_OBJECT (referenciado com 'PnpE' até depois do
//! callback), o resultado e o WORK_QUEUE_ITEM, que vai para a
//! DelayedWorkQueue; a chamada devolve STATUS_SUCCESS (ou
//! STATUS_INSUFFICIENT_RESOURCES sem pool). O worker pede ao PnP a ejeção
//! do dispositivo (o PnpQueueQueryAndRemoveEvent: um evento
//! GUID_DEVICE_EJECT na fila de eventos de dispositivo-alvo), entrega o
//! status a Callback(Status, Context), solta o DRIVER_OBJECT e devolve o
//! bloco. O NT guarda no bloco o caminho de instância e reencontra o
//! dispositivo por ele; o OpenNT guarda o próprio PDO, referenciado.
//!
//! O gerenciador de PnP do OpenNT ainda não processa eventos de remoção ou
//! ejeção de dispositivo-alvo (QUERY_REMOVE/REMOVE/EJECT pela árvore): o
//! pedido não é aceito, e o worker conclui com STATUS_TOO_LATE, o status
//! com que o PnpSetTargetDeviceRemove do NT recusa um evento que a máquina
//! de eventos do PnP não pode receber; um dispositivo que perdeu o devnode
//! conclui com STATUS_NO_SUCH_DEVICE, como no original.

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::WorkQueueItem;
use crate::ntos::io::{io_manager, work_items};
use crate::ntos::ke::bugcheck;
use crate::ntos::ob::{object_reference, reference_trace};

const STATUS_SUCCESS: u32 = 0;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_TOO_LATE: u32 = 0xC000_0189;
const PNP_DETECTED_FATAL_ERROR: u32 = 0xCA;
const NON_PAGED_POOL_NX: u32 = 0x200;
const EJECT_TAG: u32 = u32::from_le_bytes(*b"PnpF");
const DRIVER_REFERENCE_TAG: u32 = u32::from_le_bytes(*b"PnpE");

/// O bloco do pedido de ejeção (0x5D8 bytes, layout do ntoskrnl até o
/// WORK_QUEUE_ITEM; em +0x40 o NT guarda o caminho de instância).
#[repr(C)]
struct EjectRequest {
    callback: Field<u64>,
    context: Field<u64>,
    driver_object: Field<u64>,
    result: Field<u32>,
    _pad_1c: Reserved<0x4>,
    work_item: WorkQueueItem,
    /// O PDO referenciado (o OpenNT, no lugar do caminho de instância).
    device: Field<u64>,
    _instance_path: Reserved<0x188>,
    veto_type: Field<u32>,
    veto_name: Reserved<0x404>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for EjectRequest {}

const _: () = {
    assert!(core::mem::size_of::<EjectRequest>() == 0x5D8);
    assert!(core::mem::offset_of!(EjectRequest, work_item) == 0x20);
    assert!(core::mem::offset_of!(EjectRequest, device) == 0x40);
    assert!(core::mem::offset_of!(EjectRequest, veto_type) == 0x1D0);
};

/// O DEVICE_OBJECT tem devnode no PnP do OpenNT (PDO enumerado ou
/// relatado)?
pub fn has_device_node(device: u64) -> bool {
    device != 0 && io_manager::devices().into_iter().any(|(_, entry)| entry.native_device == device && (entry.pdo || entry.extra.is_some()))
}

/// IoRequestDeviceEjectEx(Pdo, Callback, Context, DriverObject).
pub fn request_device_eject(pdo: u64, callback: u64, context: u64, driver_object: u64) -> u32 {
    if pdo == 0 || !has_device_node(pdo) {
        bugcheck::bug_check_ex(PNP_DETECTED_FATAL_ERROR, 2, pdo, 0, 0);
    }
    let block = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, EjectRequest::SIZE, EJECT_TAG).unwrap_or(0);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: o bloco recém-alocado do pedido.
    let request = unsafe { EjectRequest::at(block) };
    request.callback.set(callback);
    request.context.set(context);
    request.driver_object.set(driver_object);
    if driver_object != 0 {
        let _ = object_reference::reference_with_tag(driver_object, DRIVER_REFERENCE_TAG, true);
    }
    request.result.set(0);
    let _ = object_reference::reference_with_tag(pdo, reference_trace::DEFAULT_TAG, true);
    request.device.set(pdo);
    request.veto_type.set(0);
    work_items::queue_kernel_ex_work_item(request.work_item.address(), eject_worker, block);
    STATUS_SUCCESS
}

/// PnpRequestDeviceEjectExWorker.
fn eject_worker(_device: u64, block: u64) {
    // SAFETY: o bloco do pedido, dono deste work item.
    let request = unsafe { EjectRequest::at(block) };
    let device = request.device.get();
    let status = if has_device_node(device) { STATUS_TOO_LATE } else { STATUS_NO_SUCH_DEVICE };
    request.result.set(status);
    let callback = request.callback.get();
    if callback != 0 {
        native_call::call(callback, &[status as u64, request.context.get()]);
    }
    let driver_object = request.driver_object.get();
    if driver_object != 0 {
        let _ = object_reference::dereference_with_tag(driver_object, DRIVER_REFERENCE_TAG, true);
    }
    let _ = object_reference::dereference_with_tag(device, reference_trace::DEFAULT_TAG, true);
    let _ = pool_allocation::free(block, 0);
}
