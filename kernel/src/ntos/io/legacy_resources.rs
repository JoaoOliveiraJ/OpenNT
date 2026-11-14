//! IoAssignResources: a alocação legada de recursos (IopLegacyResourceAllocation
//! com ArbiterRequestLegacyAssigned).
//!
//! Como no ntoskrnl 19041 (rva 0x89cf90): um DEVICE_OBJECT com devnode do
//! PnP é PNP_DETECTED_FATAL_ERROR (0xCA, 2, Device, Driver); uma lista de
//! requisitos sem alternativas ou com a primeira vazia vale como nenhuma;
//! *AllocatedResources começa NULL; um dispositivo sem devnode enumerado
//! por barramento (DO_BUS_ENUMERATED_DEVICE) é recusado com
//! STATUS_UNSUCCESSFUL; sem requisitos, o pedido é a liberação dos recursos
//! legados do dispositivo e devolve STATUS_SUCCESS.
//!
//! Com requisitos, o NT procura uma configuração pelos árbitros da árvore
//! de devnodes (os da raiz para um dispositivo legado), sem rebalancear; a
//! configuração que não se acha devolve STATUS_RETRY. O OpenNT não tem
//! árbitros de recursos (os da raiz nem os dos barramentos): nenhuma
//! configuração existe e o resultado é esse, com *AllocatedResources NULL.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::DeviceObject;
use crate::ntos::io::device_removal;
use crate::ntos::ke::bugcheck;
use crate::ntos::mm::guest_memory as guest;

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_RETRY: u32 = 0xC000_022D;
const PNP_DETECTED_FATAL_ERROR: u32 = 0xCA;
const DO_BUS_ENUMERATED_DEVICE: u32 = 0x1000;
/// IO_RESOURCE_REQUIREMENTS_LIST.AlternativeLists e List[0].Count.
const ALTERNATIVE_LISTS_OFFSET: u64 = 0x1C;
const FIRST_LIST_COUNT_OFFSET: u64 = 0x24;

/// Os argumentos usados do IoAssignResources (RegistryPath e
/// DriverClassName não são lidos pelo original).
pub struct AssignRequest {
    pub driver_object: u64,
    pub device_object: u64,
    pub requirements: u64,
}

/// IoAssignResources.
pub fn assign(request: &AssignRequest, allocated: Option<&Field<u64>>) -> u32 {
    let device = request.device_object;
    if device != 0 && device_removal::has_device_node(device) {
        bugcheck::bug_check_ex(PNP_DETECTED_FATAL_ERROR, 2, device, request.driver_object, 0);
    }
    let mut requirements = request.requirements;
    if requirements != 0 && (guest::read32(requirements + ALTERNATIVE_LISTS_OFFSET) == 0 || guest::read32(requirements + FIRST_LIST_COUNT_OFFSET) == 0) {
        requirements = 0;
    }
    if let Some(allocated) = allocated {
        allocated.set(0);
    }
    if device != 0 {
        // SAFETY: o DEVICE_OBJECT do chamador.
        let flags = unsafe { DeviceObject::at(device) }.flags.get();
        if flags & DO_BUS_ENUMERATED_DEVICE != 0 {
            return STATUS_UNSUCCESSFUL;
        }
    }
    if requirements == 0 {
        return STATUS_SUCCESS;
    }
    STATUS_RETRY
}
