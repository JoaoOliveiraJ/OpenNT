//! Rastreamento de I/O do I/O Manager — IoRegisterIoTracking e
//! IoUnregisterIoTracking, e a medição de cada IRP que um registro liga.
//!
//! Comportamento conferido contra o ntoskrnl 19041:
//!   IoRegisterIoTracking   rva 0x8955c0
//!   IoUnregisterIoTracking rva 0x8956d0
//!   IoPerfInit             rva 0x507a60 / IoPerfReset 0x507b5c (contador do
//!                          bit 2 de IopPerfStatus)
//!   IopIrpExtensionControl rva 0x500b18 (tipo 2)
//!   IopPerfCallDriver      rva 0x507c40 / IopPerfCompleteRequest 0x507d14
//!   IopProcessIoTracking   rva 0x5081dc
//!
//! O registro é um bloco de 0x18 bytes do NonPagedPoolNx ('IoTr'): a
//! LIST_ENTRY da lista de rastreadores e, em +0x10, a rotina lida de +8 dos
//! parâmetros do chamador; o bloco é o handle devolvido. Enquanto houver
//! registro, o IofCallDriver grava a hora do sistema
//! (KUSER_SHARED_DATA.SystemTime) na extensão de tipo 1 (Timestamp) do IRP,
//! quando a combinação de extensões permite, e o IofCompleteRequest, com o
//! slot corrente dentro da pilha e um dispositivo nele, chama cada rotina
//! registrada com um bloco { Size = 0x18; +8 o tempo decorrido em 100 ns;
//! +0x10 o DeviceType do dispositivo do slot } e libera a extensão de tipo
//! 1. As rotinas rodam sob o lock compartilhado da lista; o
//! IoUnregisterIoTracking tira o bloco com o lock exclusivo, então nenhuma
//! chamada à rotina continua depois do retorno dele.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::hal::amd64::native_call;
use crate::hal::cpu;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{DeviceObject, IoStackLocation, Irp, ListEntry};
use crate::ntos::io::extensions;
use crate::ntos::ke::{bugcheck, clock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::shared_user_data;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// 'IoTr'.
const TAG_IO_TRACKING: u32 = 0x7254_6F49;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// IO_TYPE_IRP.
const IO_TYPE_IRP: i16 = 6;
/// Tipo de extensão que exclui a medição (ZeroingOffset, da mesma união).
const IRP_EXTENSION_ZEROING_OFFSET: u32 = 4;
/// KERNEL_SECURITY_CHECK_FAILURE com FAST_FAIL_CORRUPT_LIST_ENTRY.
const KERNEL_SECURITY_CHECK_FAILURE: u32 = 0x139;
const FAST_FAIL_CORRUPT_LIST_ENTRY: u64 = 3;

/// O bloco de registro (o handle).
#[repr(C)]
struct TrackingBlock {
    links: ListEntry,
    routine: Field<u64>,
}

// SAFETY: #[repr(C)] de células e de uma estrutura do NT.
unsafe impl NtStruct for TrackingBlock {}

/// O bloco que cada rotina recebe.
#[repr(C)]
struct TrackingInformation {
    size: Field<u16>,
    _pad_2: Reserved<0x6>,
    elapsed: Field<u64>,
    device_type: Field<u32>,
    _pad_14: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for TrackingInformation {}

const _: () = {
    assert!(core::mem::size_of::<TrackingBlock>() == 0x18);
    assert!(core::mem::size_of::<TrackingInformation>() == 0x18);
    assert!(core::mem::offset_of!(TrackingInformation, elapsed) == 0x8);
    assert!(core::mem::offset_of!(TrackingInformation, device_type) == 0x10);
};

/// Um registro vivo: o bloco, a rotina e as chamadas em curso dela (o lado
/// compartilhado do lock da lista).
struct Tracker {
    block: u64,
    routine: u64,
    in_flight: Arc<AtomicU32>,
}

static TRACKERS: SpinLock<Vec<Tracker>> = SpinLock::new(Vec::new());
/// Registros vivos (o contador do bit 2 de IopPerfStatus).
static TRACKING_USERS: AtomicU32 = AtomicU32::new(0);

fn block_at(block: u64) -> &'static TrackingBlock {
    // SAFETY: bloco de registro alocado por `register` e vivo até `unregister`.
    unsafe { TrackingBlock::at(block) }
}

/// A hora do sistema que o rastreamento compara (KUSER_SHARED_DATA.SystemTime).
fn system_time() -> u64 {
    shared_user_data::data().map_or_else(clock::system_time_100ns, |shared| shared_user_data::read_shared_time(&shared.system_time))
}

/// IoRegisterIoTracking(Parameters, Handle*): devolve o NTSTATUS.
pub fn register(parameters: u64, handle: &Field<u64>) -> Result<u32, KernelError> {
    handle.set(0);
    let block = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, TrackingBlock::SIZE, TAG_IO_TRACKING)?;
    if block == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &[0u8; TrackingBlock::SIZE as usize]);
    // SAFETY: a estrutura de parâmetros do chamador de modo kernel (rotina em +8).
    let routine = unsafe { Field::<u64>::array_at(parameters, 2) }[1].get();
    block_at(block).routine.set(routine);
    TRACKERS.lock().push(Tracker { block, routine, in_flight: Arc::new(AtomicU32::new(0)) });
    TRACKING_USERS.fetch_add(1, Ordering::SeqCst);
    handle.set(block);
    Ok(0)
}

/// IoUnregisterIoTracking(Handle): desliga a medição do registro, espera as
/// chamadas em curso da rotina e devolve o bloco ao pool. Um handle que não
/// está na lista é a lista corrompida do NT (fast fail).
pub fn unregister(block: u64) -> Result<(), KernelError> {
    TRACKING_USERS.fetch_sub(1, Ordering::SeqCst);
    let removed = {
        let mut trackers = TRACKERS.lock();
        trackers.iter().position(|tracker| tracker.block == block).map(|index| trackers.remove(index))
    };
    let Some(tracker) = removed else {
        bugcheck::bug_check_ex(KERNEL_SECURITY_CHECK_FAILURE, FAST_FAIL_CORRUPT_LIST_ENTRY, block, 0, 0);
    };
    while tracker.in_flight.load(Ordering::SeqCst) != 0 {
        cpu::pause();
    }
    pool_allocation::free(block, TAG_IO_TRACKING as u64)
}

/// Lado do IofCallDriver (IopPerfCallDriver): com rastreamento ligado, a
/// hora do sistema na extensão de tipo 1 do IRP.
pub fn on_call_driver(packet: u64) {
    if TRACKING_USERS.load(Ordering::Relaxed) == 0 || !extensions::irp_extension_combination_valid(packet, extensions::IRP_EXTENSION_TIMESTAMP) {
        return;
    }
    if !matches!(extensions::allocate_irp_extension(packet, extensions::IRP_EXTENSION_TIMESTAMP), Ok(address) if address != 0) {
        return;
    }
    if let Some(timestamp) = extensions::irp_timestamp(packet) {
        timestamp.set(system_time() as i64);
    }
}

/// Lado do IofCompleteRequest (IopPerfCompleteRequest): o IRP medido, com o
/// slot corrente dentro da pilha e um dispositivo nele, passa o tempo
/// decorrido e o DeviceType às rotinas registradas.
pub fn on_complete_request(packet: u64) {
    if TRACKING_USERS.load(Ordering::Relaxed) == 0 {
        return;
    }
    // SAFETY: IRP vivo em conclusão.
    let irp = unsafe { Irp::at(packet) };
    let (location, count) = (irp.current_location.get(), irp.stack_count.get());
    if irp.type_.get() != IO_TYPE_IRP || location > count.wrapping_add(1) || location > count {
        return;
    }
    // SAFETY: o slot corrente de um IRP com CurrentLocation dentro da pilha.
    let device = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }.device_object.get();
    if device == 0 || extensions::irp_has_extension_type(packet, IRP_EXTENSION_ZEROING_OFFSET) {
        return;
    }
    let Some(timestamp) = extensions::irp_timestamp(packet) else { return };
    let elapsed = system_time().wrapping_sub(timestamp.get() as u64);
    // SAFETY: o dispositivo do slot corrente.
    let device_type = unsafe { DeviceObject::at(device) }.device_type.get();
    process_tracking(elapsed, device_type);
    let _ = extensions::free_irp_extension_type(packet, extensions::IRP_EXTENSION_TIMESTAMP);
}

/// IopProcessIoTracking: cada rotina registrada recebe o bloco de medição.
fn process_tracking(elapsed: u64, device_type: u32) {
    let callers: Vec<(u64, Arc<AtomicU32>)> = {
        let trackers = TRACKERS.lock();
        trackers
            .iter()
            .map(|tracker| {
                tracker.in_flight.fetch_add(1, Ordering::SeqCst);
                (tracker.routine, tracker.in_flight.clone())
            })
            .collect()
    };
    if callers.is_empty() {
        return;
    }
    let address = guest::alloc_bytes(TrackingInformation::SIZE);
    if address != 0 {
        guest::write_bytes(address, &[0u8; TrackingInformation::SIZE as usize]);
        // SAFETY: bloco zerado recém-alocado com o tamanho da estrutura.
        let information = unsafe { TrackingInformation::at(address) };
        information.size.set(TrackingInformation::SIZE as u16);
        information.elapsed.set(elapsed);
        information.device_type.set(device_type);
    }
    for (routine, in_flight) in callers {
        if address != 0 && routine != 0 {
            native_call::call(routine, &[address]);
        }
        in_flight.fetch_sub(1, Ordering::SeqCst);
    }
    if address != 0 {
        guest::free_bytes(address);
    }
}
