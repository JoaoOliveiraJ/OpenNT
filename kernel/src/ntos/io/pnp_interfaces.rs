//! Consultas de interfaces do PnP — lista de interfaces de dispositivo de uma
//! classe e interface de IOMMU da HAL.
//!
//! Transcrição do ntoskrnl 19041:
//!   IoGetDeviceInterfaces  rva 0x69c660 -> IopGetDeviceInterfaces 0x6b32e8
//!     MULTI_SZ em PagedPool com tag 'Pp  ' (0x20207050); classe sem interfaces
//!     devolve um único L'\0' (2 bytes) com STATUS_SUCCESS (0x6b36b3); só
//!     interfaces habilitadas, salvo DEVICE_INTERFACE_INCLUDE_NONACTIVE (1)
//!     (`not r9d; and r9d, 1` antes do filtro); o PDO opcional filtra o dono.
//!   IoGetIommuInterface    rva 0x7d4bd0
//!     IRQL != PASSIVE -> KeBugCheckEx(DRIVER_VIOLATION 0x121, 1, Irql, 0, 0);
//!     senão chamada de HalPrivateDispatchTable->HalGetIommuInterface (+0x440).
//!
//! Reuso: o registro de interfaces de `io::device_interface` (o mesmo do
//! IoRegisterDeviceInterface/IoSetDeviceInterfaceState, com o filtro
//! `class_links`), o Object Manager para resolver o dono do link e o pool de
//! `ex::pool_allocation`. Diferença honesta: o OpenNT não tem devnodes; um PDO
//! sem devnode, que o NT levaria a PNP_DETECTED_FATAL_ERROR, é aceito e só
//! filtra pelo destino do link.

use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::io::{device_interface, io_manager};
use crate::ntos::ke::{bugcheck, irql};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::object_manager;
use crate::rtl::KernelError;

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const DEVICE_INTERFACE_INCLUDE_NONACTIVE: u32 = 1;
const PAGED_POOL: u32 = 1;
/// 'Pp  '
const TAG_PNP: u32 = 0x2020_7050;
/// HAL_PRIVATE_DISPATCH.HalGetIommuInterface.
const HAL_GET_IOMMU_INTERFACE: u64 = 0x440;
const DRIVER_VIOLATION: u32 = 0x121;

/// O link resolve para o `\Device` cujo DEVICE_OBJECT é `pdo`.
fn owned_by(link: &str, pdo: u64) -> bool {
    object_manager::lookup(link).and_then(io_manager::device).is_some_and(|entry| entry.native_device == pdo)
}

/// IoGetDeviceInterfaces(InterfaceClassGuid, PhysicalDeviceObject, Flags,
/// SymbolicLinkList): grava a lista MULTI_SZ e devolve o NTSTATUS.
pub fn device_interface_list(class_guid: u64, pdo: u64, flags: u32, output: u64) -> Result<u32, KernelError> {
    let mut class = [0u8; 16];
    class.copy_from_slice(&guest::read_bytes(class_guid, 16));
    let links = device_interface::class_links(&class, flags & DEVICE_INTERFACE_INCLUDE_NONACTIVE != 0);
    // Cada link termina em L'\0' e a lista em mais um; vazia = um L'\0'.
    let mut units: Vec<u16> = Vec::new();
    for link in links.iter().filter(|link| pdo == 0 || owned_by(link, pdo)) {
        units.extend(link.encode_utf16());
        units.push(0);
    }
    units.push(0);
    let list = pool_allocation::allocate_tagged(PAGED_POOL, units.len() as u64 * 2, TAG_PNP)?;
    if list == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    for (index, unit) in units.iter().enumerate() {
        guest::write16(list + index as u64 * 2, *unit);
    }
    guest::write64(output, list);
    Ok(0)
}

/// IoGetIommuInterface(Version, InterfaceOut): o status da HAL.
pub fn iommu_interface(version: u64, interface: u64) -> u32 {
    let current = irql::get_irql();
    if current != 0 {
        bugcheck::bug_check_ex(DRIVER_VIOLATION, 1, current as u64, 0, 0);
    }
    let table = crate::hal::private_dispatch::table_address();
    let routine = if table != 0 { guest::read64(table + HAL_GET_IOMMU_INTERFACE) } else { 0 };
    if routine == 0 {
        return STATUS_NOT_SUPPORTED;
    }
    native_call::call(routine, &[version, interface]) as u32
}
