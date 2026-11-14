//! Pedidos térmicos: PoCreateThermalRequest, PoDeleteThermalRequest,
//! PoGetThermalRequestSupport, PoSetThermalActiveCooling e
//! PoSetThermalPassiveCooling.
//!
//! Como no ntoskrnl 19041, cada dispositivo alvo ganha uma extensão de
//! resfriamento (0x90 bytes, pool paginado 'PCol') na criação do primeiro
//! pedido: a interface GUID_THERMAL_COOLING_INTERFACE (versão 1, 0x38
//! bytes) vem de um IRP_MN_QUERY_INTERFACE síncrono ao próprio dispositivo
//! alvo, e uma falha recusa o pedido com o status do driver. O pedido
//! (0x240 bytes, 'PCol') guarda o contexto de motivo capturado, o
//! percentual passivo (100 de início), o resfriamento ativo e o estado
//! associado. Mudar um pedido recalcula o agregado da extensão (o menor
//! percentual e o OU dos ativos dos pedidos associados, como o
//! PopPropogateCoolingChange) e chama PassiveCooling(Context, Percentual)
//! e ActiveCooling(Context, Engaged) do driver só quando o agregado muda,
//! sem a trava; uma mudança durante a chamada refaz o cálculo. O último
//! pedido apagado devolve a interface (InterfaceDereference) e a extensão.
//! O NT guarda a extensão na DEVICE_OBJECT_POWER_EXTENSION do alvo; o
//! OpenNT, num registro por dispositivo. A proteção contra remoção do
//! alvo (notificação de TargetDeviceChange pedida sem o bit 31 das
//! flags) não é registrada.

use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, IoStackLocation, Irp, ListEntry};
use crate::ntos::io::{irp_builder, irp_request};
use crate::ntos::ke::clock;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::reason_context;
use crate::rtl::sync::SpinLockGuard;
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// O pedido já não está associado à extensão.
const STATUS_TOO_LATE: u32 = 0xC000_0189;
const PAGED_POOL: u32 = 1;
const COOLING_TAG: u32 = u32::from_le_bytes(*b"PCol");
const FULL_THROTTLE: u8 = 100;
/// PoThermalRequestPassive / PoThermalRequestActive.
const REQUEST_PASSIVE: u32 = 0;
const REQUEST_ACTIVE: u32 = 1;
const IRP_MJ_PNP: u8 = 0x1B;
const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
/// GUID_THERMAL_COOLING_INTERFACE {ecbe47a8-c498-4bb9-bd70-e867e0940d22}.
const GUID_THERMAL_COOLING_INTERFACE: [u8; 16] = [0xa8, 0x47, 0xbe, 0xec, 0x98, 0xc4, 0xb9, 0x4b, 0xbd, 0x70, 0xe8, 0x67, 0xe0, 0x94, 0x0d, 0x22];
const COOLING_INTERFACE_VERSION: u16 = 1;

/// `THERMAL_COOLING_INTERFACE` (wdm.h; 0x38 bytes).
#[repr(C)]
pub struct ThermalCoolingInterface {
    pub size: Field<u16>,
    pub version: Field<u16>,
    _pad_4: Reserved<0x4>,
    pub context: Field<u64>,
    pub interface_reference: Field<u64>,
    pub interface_dereference: Field<u64>,
    pub flags: Field<u32>,
    _pad_24: Reserved<0x4>,
    pub active_cooling: Field<u64>,
    pub passive_cooling: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ThermalCoolingInterface {}

/// A extensão de resfriamento de um dispositivo alvo (0x90 bytes).
#[repr(C)]
pub struct CoolingExtension {
    link: ListEntry,
    pub requests: ListEntry,
    lock: Field<u64>,
    _reserved_28: Field<u64>,
    pub device: Field<u64>,
    notification: Field<u64>,
    pub interface_acquired: Field<u8>,
    pub active_engaged: Field<u8>,
    pub passive_throttle: Field<u8>,
    updating: Field<u8>,
    _pad_44: Reserved<0x4>,
    update_event: Field<u64>,
    other_event: Field<u64>,
    pub interface: ThermalCoolingInterface,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CoolingExtension {}

/// O pedido térmico (0x240 bytes).
#[repr(C)]
pub struct ThermalRequest {
    link: ListEntry,
    pub passive_throttle: Field<u8>,
    pub active_engaged: Field<u8>,
    pub active: Field<u8>,
    _pad_13: Reserved<0x5>,
    pub reason: Field<u64>,
    pub extension: Field<u64>,
    _reserved_28: Field<u8>,
    pub active_supported: Field<u8>,
    _pad_2a: Reserved<0x6>,
    pub created: Field<u64>,
    pub updated: Field<u64>,
    _tracking: Reserved<0x200>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ThermalRequest {}

const _: () = {
    assert!(core::mem::size_of::<ThermalCoolingInterface>() == 0x38);
    assert!(core::mem::size_of::<CoolingExtension>() == 0x90);
    assert!(core::mem::offset_of!(CoolingExtension, interface_acquired) == 0x40);
    assert!(core::mem::offset_of!(CoolingExtension, interface) == 0x58);
    assert!(core::mem::size_of::<ThermalRequest>() == 0x240);
    assert!(core::mem::offset_of!(ThermalRequest, reason) == 0x18);
    assert!(core::mem::offset_of!(ThermalRequest, extension) == 0x20);
    assert!(core::mem::offset_of!(ThermalRequest, created) == 0x30);
};

/// (dispositivo, extensão): o papel do ponteiro na DOPE do alvo; a trava
/// também protege as listas de pedidos (o PopCoolingExtensionLock e a
/// trava de cada extensão).
static EXTENSIONS: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());

fn extension_at(address: u64) -> &'static CoolingExtension {
    // SAFETY: uma extensão viva do registro.
    unsafe { CoolingExtension::at(address) }
}

fn request_at(address: u64) -> &'static ThermalRequest {
    // SAFETY: o pedido do chamador, criado por `create`.
    unsafe { ThermalRequest::at(address) }
}

fn link(address: u64) -> &'static ListEntry {
    // SAFETY: elos de uma lista viva de pedidos.
    unsafe { ListEntry::at(address) }
}

fn allocate_zeroed(size: u64) -> u64 {
    let block = pool_allocation::allocate_tagged(PAGED_POOL, size, COOLING_TAG).unwrap_or(0);
    if block != 0 {
        guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    }
    block
}

fn free(block: u64) {
    let _ = pool_allocation::free(block, 0);
}

/// PopAcquireCoolingInterface: IRP_MN_QUERY_INTERFACE ao dispositivo alvo.
fn acquire_cooling_interface(extension: &CoolingExtension) -> u32 {
    // SAFETY: o DEVICE_OBJECT alvo do chamador.
    let device = unsafe { DeviceObject::at(extension.device.get()) };
    let packet = irp_builder::allocate_irp(device.stack_size.get());
    if packet == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &GUID_THERMAL_COOLING_INTERFACE);
    // SAFETY: o IRP recém-alocado e a posição de pilha do primeiro driver.
    let irp = unsafe { Irp::at(packet) };
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    location.major_function.set(IRP_MJ_PNP);
    location.minor_function.set(IRP_MN_QUERY_INTERFACE);
    let parameters = &location.parameters.query_interface;
    parameters.interface_type.set(guid);
    parameters.size.set(ThermalCoolingInterface::SIZE as u16);
    parameters.version.set(COOLING_INTERFACE_VERSION);
    parameters.interface.set(extension.interface.address());
    parameters.interface_specific_data.set(0);
    irp.io_status.status.set(STATUS_NOT_SUPPORTED as i32);
    let status = irp_request::synchronous_call(device.address(), packet).unwrap_or(STATUS_NOT_SUPPORTED);
    irp_builder::free_irp(packet);
    guest::free_bytes(guid);
    status
}

/// O agregado dos pedidos associados: (algum ativo, menor percentual).
fn aggregate(extension: &CoolingExtension) -> (u8, u8) {
    let (mut engaged, mut throttle) = (0u8, FULL_THROTTLE);
    if extension.interface_acquired.get() == 0 {
        return (engaged, throttle);
    }
    let head = extension.requests.address();
    let mut current = extension.requests.flink.get();
    while current != head {
        let request = request_at(current);
        if request.active.get() != 0 {
            throttle = throttle.min(request.passive_throttle.get());
            if request.active_engaged.get() != 0 {
                engaged = 1;
            }
        }
        current = request.link.flink.get();
    }
    (engaged, throttle)
}

type Guard = SpinLockGuard<'static, Vec<(u64, u64)>>;

/// PopPropogateCoolingChange: entra e sai com a trava.
fn propagate(extension: &CoolingExtension, mut guard: Guard) -> Guard {
    if extension.updating.get() != 0 {
        extension.updating.set(0);
        return guard;
    }
    'recompute: loop {
        let (engaged, throttle) = aggregate(extension);
        let calls: [(bool, &Field<u8>, u8, u64); 2] = [(throttle != extension.passive_throttle.get(), &extension.passive_throttle, throttle, extension.interface.passive_cooling.get()), (engaged != extension.active_engaged.get(), &extension.active_engaged, engaged, extension.interface.active_cooling.get())];
        for (changed, cell, value, routine) in calls {
            if !changed {
                continue;
            }
            cell.set(value);
            extension.updating.set(1);
            drop(guard);
            native_call::call(routine, &[extension.interface.context.get(), value as u64]);
            guard = EXTENSIONS.lock();
            if extension.updating.get() == 0 {
                continue 'recompute;
            }
            extension.updating.set(0);
        }
        return guard;
    }
}

fn insert_tail(head: &ListEntry, entry: &ListEntry) {
    let last = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(last);
    link(last).flink.set(entry.address());
    head.blink.set(entry.address());
}

fn remove(entry: &ListEntry) {
    let (flink, blink) = (entry.flink.get(), entry.blink.get());
    link(blink).flink.set(flink);
    link(flink).blink.set(blink);
}

/// PopCleanCoolingExtension: devolve a interface e a extensão.
fn clean(extension: &CoolingExtension) {
    let dereference = extension.interface.interface_dereference.get();
    if extension.interface_acquired.get() != 0 && dereference != 0 {
        native_call::call(dereference, &[extension.interface.context.get()]);
    }
    free(extension.address());
}

/// PopAssociateThermalRequest: a extensão do alvo (criada no primeiro
/// pedido) recebe o pedido.
fn associate(request: &ThermalRequest, device: u64) -> u32 {
    let existing = EXTENSIONS.lock().iter().find(|&&(owner, _)| owner == device).map(|&(_, extension)| extension);
    let address = match existing {
        Some(extension) => extension,
        None => {
            let block = allocate_zeroed(CoolingExtension::SIZE);
            if block == 0 {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            let extension = extension_at(block);
            extension.requests.flink.set(extension.requests.address());
            extension.requests.blink.set(extension.requests.address());
            extension.passive_throttle.set(FULL_THROTTLE);
            extension.device.set(device);
            let status = acquire_cooling_interface(extension);
            if (status as i32) < 0 {
                clean(extension);
                return status;
            }
            extension.interface_acquired.set(1);
            EXTENSIONS.lock().push((device, block));
            block
        }
    };
    let extension = extension_at(address);
    let _guard = EXTENSIONS.lock();
    request.extension.set(address);
    insert_tail(&extension.requests, &request.link);
    request.active.set(1);
    if extension.interface.active_cooling.get() != 0 {
        request.active_supported.set(1);
    }
    STATUS_SUCCESS
}

/// Os argumentos do PoCreateThermalRequest.
pub struct CreateRequest {
    pub target: u64,
    pub policy: u64,
    pub context: u64,
    pub flags: u32,
}

/// PoCreateThermalRequest(ThermalRequest*, Target, Policy, Context, Flags).
pub fn create(output: &Field<u64>, request: &CreateRequest) -> u32 {
    output.set(0);
    if request.target == 0 || request.policy == 0 || request.context == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let reason = match reason_context::capture(request.context) {
        Ok(reason) => reason,
        Err(status) => return status,
    };
    let block = allocate_zeroed(ThermalRequest::SIZE);
    if block == 0 {
        reason_context::destroy(reason);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let thermal = request_at(block);
    thermal.reason.set(reason);
    thermal.passive_throttle.set(FULL_THROTTLE);
    let now = clock::uptime_100ns();
    thermal.created.set(now);
    thermal.updated.set(now);
    let status = associate(thermal, request.target);
    if (status as i32) < 0 {
        reason_context::destroy(reason);
        free(block);
        return status;
    }
    output.set(block);
    status
}

/// PoGetThermalRequestSupport(ThermalRequest, Type).
pub fn support(request: &ThermalRequest, kind: u32) -> bool {
    let extension = extension_at(request.extension.get());
    match kind {
        REQUEST_PASSIVE => extension.interface.passive_cooling.get() != 0,
        REQUEST_ACTIVE => extension.interface.active_cooling.get() != 0,
        _ => false,
    }
}

/// Muda um campo do pedido e propaga, se o pedido ainda está associado.
fn update(request: &ThermalRequest, cell: &Field<u8>, value: u8) -> u32 {
    let extension = extension_at(request.extension.get());
    let guard = EXTENSIONS.lock();
    if request.active.get() == 0 {
        return STATUS_TOO_LATE;
    }
    if cell.get() != value {
        cell.set(value);
        request.updated.set(clock::uptime_100ns());
        drop(propagate(extension, guard));
    }
    STATUS_SUCCESS
}

/// PoSetThermalActiveCooling(ThermalRequest, Engaged).
pub fn set_active_cooling(request: &ThermalRequest, engaged: bool) -> u32 {
    if !support(request, REQUEST_ACTIVE) {
        return STATUS_NOT_SUPPORTED;
    }
    update(request, &request.active_engaged, engaged as u8)
}

/// PoSetThermalPassiveCooling(ThermalRequest, Throttle).
pub fn set_passive_cooling(request: &ThermalRequest, throttle: u8) -> u32 {
    if !support(request, REQUEST_PASSIVE) {
        return STATUS_NOT_SUPPORTED;
    }
    if throttle > FULL_THROTTLE {
        return STATUS_INVALID_PARAMETER;
    }
    update(request, &request.passive_throttle, throttle)
}

/// PoDeleteThermalRequest: desassocia (com o recálculo), tira da lista e,
/// no último pedido do alvo, devolve a extensão.
pub fn delete(request: &ThermalRequest) {
    let extension = extension_at(request.extension.get());
    let mut guard = EXTENSIONS.lock();
    if request.active.get() != 0 {
        request.active.set(0);
        guard = propagate(extension, guard);
    }
    remove(&request.link);
    let last = extension.requests.flink.get() == extension.requests.address();
    if last {
        let device = extension.device.get();
        guard.retain(|&(owner, _)| owner != device);
    }
    drop(guard);
    if last {
        // Uma chamada ao driver em curso em outra CPU termina antes.
        while extension.updating.get() != 0 {
            crate::hal::cpu::pause();
        }
        clean(extension);
    }
    reason_context::destroy(request.reason.get());
    free(request.address());
}
