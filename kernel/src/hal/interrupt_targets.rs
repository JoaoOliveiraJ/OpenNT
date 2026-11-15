//! Os destinos de interrupção por processador que a HAL publica.
//!
//! No NT a HAL guarda, por processador iniciado, o APIC ID e o
//! PROCESSOR_NUMBER (`HalpInterruptProcessorState`) e o destino que ela
//! programa nos controladores (`HalpInterruptTargets`). O OpenNT programa os
//! APICs em modo de destino físico (o destino é o APIC ID), sem modo lógico
//! nem cluster, e não oferece interrupções por mensagem (MSI) às pilhas
//! PnP. As rotinas seguem as do ntoskrnl 19041 com esse estado:
//! HalGetProcessorIdByNtNumber, HalGetInterruptTargetInformation,
//! HalGetMessageRoutingInfo e HalConvertDeviceIdtToIrql.

use crate::ntos::ke::{processor_group, processor_topology};
use crate::ntos::mm::guest_memory as guest;

const STATUS_INVALID_PARAMETER: i32 = 0xC000_000D_u32 as i32;
const STATUS_NOT_FOUND: i32 = 0xC000_0225_u32 as i32;

/// Modo de destino da HAL (INTERRUPT_TARGET_INFORMATION.Mode): 1 = físico.
const TARGET_MODE_PHYSICAL: u32 = 1;

/// HalpInterruptProcessorCount.
fn processor_count() -> u32 {
    processor_group::active_processor_count() as u32
}

/// APIC ID do processador de índice `index` (os iniciados, na ordem do NT).
fn apic_id(index: u32) -> Option<u32> {
    processor_topology::processor_apic_ids().get(index as usize).copied().filter(|&id| id != u32::MAX)
}

/// HalGetProcessorIdByNtNumber(NtNumber, *ProcessorId): índice além dos
/// processadores da HAL = STATUS_INVALID_PARAMETER; o APIC ID do processador
/// iniciado com aquele PROCESSOR_NUMBER, ou STATUS_NOT_FOUND.
pub fn processor_id_by_nt_number(index: u32) -> Result<u32, i32> {
    if index >= processor_count() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    apic_id(index).ok_or(STATUS_NOT_FOUND)
}

/// O export HalGetProcessorIdByNtNumber: o APIC ID em *ProcessorId.
pub fn get_processor_id_by_nt_number(index: u32, processor_id: u64) -> i32 {
    match processor_id_by_nt_number(index) {
        Ok(id) => {
            guest::write32(processor_id, id);
            0
        }
        Err(status) => status,
    }
}

/// HalGetInterruptTargetInformation(Type, ApicId, Information): Type 0
/// (processador) ou 2 (só o modo); zera a estrutura, grava o tipo e o modo
/// (físico) e, para o tipo 0, o PROCESSOR_NUMBER (+4) do processador
/// iniciado com aquele APIC ID; o destino lógico (+0xC) fica 0 no modo
/// físico. Sem MSI, as flags (+8) ficam 0.
pub fn target_information(target_type: u32, apic: u32, information: u64) -> i32 {
    if target_type != 0 && target_type != 2 {
        return STATUS_INVALID_PARAMETER;
    }
    guest::write32(information, target_type);
    guest::write64(information + 4, 0);
    guest::write64(information + 0xC, 0);
    guest::write32(information + 0x14, TARGET_MODE_PHYSICAL);
    if target_type == 2 {
        return 0;
    }
    let Some(index) = (0..processor_count()).find(|&index| apic_id(index) == Some(apic)) else { return STATUS_NOT_FOUND };
    // PROCESSOR_NUMBER { Group = 0, Number = índice, Reserved = 0 }.
    guest::write32(information + 4, (index & 0xFF) << 16);
    guest::write32(information + 0xC, 0);
    guest::write32(information + 0x14, TARGET_MODE_PHYSICAL);
    0
}

/// HalGetMessageRoutingInfo(Request, Output): Type (+0) 0 ou 1; afinidade
/// (+0x10) e grupo (+0x18); só o modo físico (+0x20 = 1) tem destino nesta
/// HAL (sem modo lógico nem cluster: STATUS_INVALID_PARAMETER, como o NT com
/// o problema 0x14). O destino é o primeiro processador da afinidade (ou um
/// processador iniciado, com a afinidade de todos), validado pelo
/// HalGetProcessorIdByNtNumber; a saída leva 1 em +0 e, para o tipo 0, 1 em
/// +8 e os campos +0x28/+0x2C/+0x30 do pedido em +0x54/+0x50/+0x58; para o
/// tipo 1, 3 em +8 e o modo em +0x50.
pub fn message_routing_info(request: u64, output: u64) -> i32 {
    let request_type = guest::read32(request);
    if request_type > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let mode = guest::read32(request + 0x20);
    if mode != TARGET_MODE_PHYSICAL {
        return STATUS_INVALID_PARAMETER;
    }
    let affinity = guest::read64(request + 0x10);
    let group = guest::read16(request + 0x18);
    let all = processor_group::active_processors();
    let mask = if affinity == 0 { all } else { affinity };
    if group != 0 || mask & all == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let index = (mask & all).trailing_zeros();
    if let Err(status) = processor_id_by_nt_number(index) {
        return status;
    }
    guest::write32(output, 1);
    if request_type == 0 {
        guest::write32(output + 8, 1);
        guest::write32(output + 0x54, guest::read32(request + 0x28));
        guest::write32(output + 0x50, guest::read32(request + 0x2C));
        guest::write32(output + 0x58, guest::read16(request + 0x30) as u32);
    } else {
        guest::write32(output + 8, 3);
        guest::write32(output + 0x50, mode);
    }
    0
}

/// HalConvertDeviceIdtToIrql: o IRQL de um vetor da IDT (vetor >> 4),
/// limitado a [3, 12]; vetores de 0x100 em diante dão 3.
pub fn device_idt_to_irql(vector: u32) -> u8 {
    if vector >= 0x100 {
        return 3;
    }
    ((vector >> 4) as u8).clamp(3, 12)
}

/// HalGetMemoryCachingRequirements(PhysicalAddress, Length, *CacheType):
/// as exigências de cache vêm dos atributos do mapa de memória EFI
/// (HalpCachingRequirements); no boot por BIOS não há nenhuma: *CacheType = 0
/// e STATUS_UNSUCCESSFUL. Sem saída, STATUS_INVALID_PARAMETER.
pub fn memory_caching_requirements(_physical_address: u64, _length: u64, cache_type: u64) -> i32 {
    if cache_type == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    guest::write32(cache_type, 0);
    0xC000_0001_u32 as i32
}
