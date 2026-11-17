//! IoAssignResources e IoReportResourceUsage: a alocação legada de recursos
//! (IopLegacyResourceAllocation com ArbiterRequestLegacyAssigned e
//! ArbiterRequestLegacyReported).
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
//! configuração que não se acha devolve STATUS_RETRY. O IoAssignResources
//! do OpenNT ainda não procura a configuração pelos árbitros: o resultado é
//! esse, com *AllocatedResources NULL.

use alloc::vec::Vec;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::DeviceObject;
use crate::ntos::io::device_removal;
use crate::ntos::io::pnp::resources;
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

// ---- IoReportResourceUsage ---------------------------------------------------
//
// Como no ntoskrnl 19041 (IoReportResourceUsage rva 0x8a0040 e o
// IoReportResourceUsageInternal): um DEVICE_OBJECT com devnode do PnP é
// PNP_DETECTED_FATAL_ERROR (0xCA, 2, Device, Driver). A lista vale a do
// dispositivo (DeviceList) ou, sem ela, a do driver (DriverList); vazia
// (sem FULL descriptor ou sem descritores no primeiro), o pedido é a
// liberação dos recursos legados de quem relata. *ConflictDetected começa
// TRUE e o IopLegacyResourceAllocation com ArbiterRequestLegacyReported
// procura os recursos como estão (cada descritor vira um requisito fixo, o
// PnpCmResourcesToIoResources); achou, FALSE e STATUS_SUCCESS; não achou,
// STATUS_CONFLICTING_ADDRESSES. O OverrideConflict não é lido.
//
// O devnode inventado de um dispositivo legado fica sob a raiz, e os
// árbitros que o atendem são os da raiz (`pnp::resources`). Falta o desvio
// do NT para o barramento legado do tipo de interface da lista
// (IopFindLegacyBusDeviceNode, pelo IRP_MN_QUERY_LEGACY_BUS_INFORMATION):
// com a raiz ACPI, portas ISA dentro das janelas do barramento PCI colidem
// com elas na raiz.

const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;

/// Os argumentos usados do IoReportResourceUsage (DriverClassName, os
/// tamanhos das listas e o OverrideConflict não são lidos pelo original
/// além da validação do NT).
pub struct ReportRequest {
    pub driver_object: u64,
    pub driver_list: u64,
    pub device_object: u64,
    pub device_list: u64,
}

/// Os requisitos fixos de uma CM_RESOURCE_LIST (PnpCmResourcesToIoResources
/// do primeiro FULL descriptor): cada descritor só cabe onde está. None para
/// uma lista vazia.
fn fixed_requirements(list: u64) -> Option<resources::Requirements> {
    if list == 0 || guest::read32(list) == 0 {
        return None;
    }
    let cm = resources::CmList::read(list)?;
    if cm.resources.is_empty() {
        return None;
    }
    let needs: Vec<Vec<resources::Choice>> = cm
        .resources
        .iter()
        .filter(|resource| resource.resource_type != resources::resource_type::DEVICE_PRIVATE)
        .map(|resource| {
            let (minimum, length) = match resource.resource_type {
                resources::resource_type::INTERRUPT => (resource.length as u64, 1),
                resources::resource_type::DMA => (resource.start, 1),
                _ => (resource.start, resource.length.max(1) as u64),
            };
            let affinity = resource.extra[0] as u64 | (resource.extra[1] as u64) << 32;
            alloc::vec![resources::Choice { resource_type: resource.resource_type, share: resource.share, flags: resource.flags, length: length as u32, alignment: 1, minimum, maximum: minimum + length - 1, private: [0; 3], affinity, address: 0 }]
        })
        .collect();
    Some(resources::Requirements { interface_type: cm.interface_type, bus_number: cm.bus_number, slot_number: 0, alternatives: alloc::vec![needs] })
}

/// IoReportResourceForDetection(DriverObject, DriverList, DriverListSize,
/// DeviceObject, DeviceList, DeviceListSize, ConflictDetected) (rva
/// 0x89fe50): a mesma checagem de devnode do PnP (0xCA, 2, Device, Driver)
/// e o mesmo IoReportResourceUsageInternal, com ArbiterRequestPnpDetected
/// no lugar do ArbiterRequestLegacyReported. A diferença do 19041 entre os
/// dois é o IopLegacyResourceAllocation não gravar o mapa de recursos no
/// Registro para um pedido PnpDetected; o OpenNT não grava esse mapa para
/// nenhum dos dois.
pub fn report_for_detection(request: &ReportRequest, conflict_detected: Option<&Field<u8>>) -> u32 {
    report_usage(request, conflict_detected)
}

/// IoReportResourceUsage.
pub fn report_usage(request: &ReportRequest, conflict_detected: Option<&Field<u8>>) -> u32 {
    let device = request.device_object;
    if device != 0 && device_removal::has_device_node(device) {
        bugcheck::bug_check_ex(PNP_DETECTED_FATAL_ERROR, 2, device, request.driver_object, 0);
    }
    let list = if request.device_list != 0 { request.device_list } else { request.driver_list };
    // O devnode legado é o do dispositivo ou, sem ele, o do driver.
    let owner = if device != 0 { device } else { request.driver_object };
    if let Some(flag) = conflict_detected {
        flag.set(1);
    }
    let status = match fixed_requirements(list) {
        None => {
            resources::release(owner);
            STATUS_SUCCESS
        }
        Some(requirements) => match resources::assign(owner, &requirements) {
            Some(_) => STATUS_SUCCESS,
            None => STATUS_CONFLICTING_ADDRESSES,
        },
    };
    if status == STATUS_SUCCESS {
        if let Some(flag) = conflict_detected {
            flag.set(0);
        }
    }
    status
}
