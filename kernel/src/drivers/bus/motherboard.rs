//! Bus driver dos dispositivos fixos da placa-mãe — `system32/drivers/bus/motherboard.js`.
//!
//! O que o ACPI enumeraria no PC: PNP0303 (controlador de teclado PS/2 8042)
//! e PNP0F13 (mouse PS/2). Cria os PDOs com os recursos reais (portas
//! 0x60/0x64, IRQ1/IRQ12) e responde as queries PnP que o driver funcional
//! (i8042prt.sys) desce para o PDO — o papel do acpi.sys aqui.

use alloc::vec::Vec;

use crate::ntos::io::io_manager::{self as iom, irp_mn, DeviceEntry};
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::object_manager;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{cm_full_resource_descriptor as full, cm_partial_resource_descriptor as part, cm_partial_resource_list as list, cm_resource_list, device_object, io_stack_location as stack, irp};

#[derive(Clone, Copy, Debug)]
pub struct MotherboardResource {
    pub resource_type: u8,
    pub start: u64,
    pub length: u32,
    pub level: u32,
    pub vector: u32,
    pub affinity: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct MotherboardDevice {
    pub name: &'static str,
    pub instance_id: &'static str,
    pub device_id: &'static str,
    pub hardware_ids: &'static [&'static str],
    pub resources: [MotherboardResource; 3],
}

const fn port(start: u64) -> MotherboardResource {
    MotherboardResource { resource_type: part::TYPE_PORT, start, length: 1, level: 0, vector: 0, affinity: 0 }
}

const fn interrupt(level: u32, vector: u32) -> MotherboardResource {
    MotherboardResource { resource_type: part::TYPE_INTERRUPT, start: 0, length: 0, level, vector, affinity: 0xFF }
}

/// Dispositivos fixos desta máquina (QEMU pc i440fx: 8042 sempre presente).
pub const MOTHERBOARD_DEVICES: [MotherboardDevice; 2] = [
    // Dados/comando do 8042 e IRQ1 (DIRQL 8, PIC).
    MotherboardDevice { name: "I8042Kbd", instance_id: "00", device_id: "PNP0303", hardware_ids: &["PNP0303"], resources: [port(0x60), port(0x64), interrupt(8, 0x21)] },
    // IRQ12 (DIRQL 12, PIC escravo).
    MotherboardDevice { name: "I8042Mou", instance_id: "01", device_id: "PNP0F13", hardware_ids: &["PNP0F13"], resources: [port(0x60), port(0x64), interrupt(12, 0x2C)] },
];

/// PDO criado: descritor, nó, DEVICE_OBJECT e CM_RESOURCE_LIST.
#[derive(Clone, Copy, Debug)]
pub struct CreatedPdo {
    pub descriptor: MotherboardDevice,
    pub node: u64,
    pub device_pointer: u64,
    pub resource_list_pointer: u64,
}

static CREATED: SpinLock<Vec<CreatedPdo>> = SpinLock::new(Vec::new());

/// CM_RESOURCE_LIST com um FULL descriptor Isa e alinhamento de 4 (stride
/// 0x14 e união em +4, medidos no i8042prt).
pub fn build_resource_list(resources: &[MotherboardResource]) -> u64 {
    let size = cm_resource_list::FULL_DESCRIPTOR + full::PARTIAL_LIST + list::DESCRIPTORS + part::SIZE * resources.len() as u64;
    let address = guest::alloc_bytes(size);
    guest::write32(address + cm_resource_list::COUNT, 1);
    let descriptor = address + cm_resource_list::FULL_DESCRIPTOR;
    guest::write32(descriptor + full::INTERFACE_TYPE, 1); // Isa
    guest::write32(descriptor + full::BUS_NUMBER, 0);
    let partial = descriptor + full::PARTIAL_LIST;
    guest::write16(partial + list::VERSION, 1);
    guest::write16(partial + list::REVISION, 1);
    guest::write32(partial + list::COUNT, resources.len() as u32);
    let mut cursor = partial + list::DESCRIPTORS;
    for resource in resources {
        guest::write8(cursor + part::TYPE, resource.resource_type);
        guest::write8(cursor + part::SHARE_DISPOSITION, 0); // exclusiva
        guest::write16(cursor + part::FLAGS, 0); // latched
        if resource.resource_type == part::TYPE_INTERRUPT {
            guest::write32(cursor + part::INTERRUPT_LEVEL, resource.level);
            guest::write32(cursor + part::INTERRUPT_VECTOR, resource.vector);
            guest::write64(cursor + part::INTERRUPT_AFFINITY, resource.affinity as u64);
        } else {
            guest::write64(cursor + part::PORT_START, resource.start);
            guest::write32(cursor + part::PORT_LENGTH, resource.length);
        }
        cursor += part::SIZE;
    }
    address
}

/// String wide em pool zerado (já termina em NUL).
fn write_wide_string(text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let buffer = guest::alloc_bytes((units.len() as u64 + 1) * 2);
    for (index, &unit) in units.iter().enumerate() {
        guest::write16(buffer + index as u64 * 2, unit);
    }
    buffer
}

/// MULTI_SZ wide com duplo NUL garantido pelo pool zerado.
fn write_multi_sz(strings: &[&str]) -> u64 {
    let total: usize = 1 + strings.iter().map(|text| text.encode_utf16().count() + 1).sum::<usize>();
    let buffer = guest::alloc_bytes(total as u64 * 2);
    let mut cursor = buffer;
    for text in strings {
        let units: Vec<u16> = text.encode_utf16().collect();
        for &unit in &units {
            guest::write16(cursor, unit);
            cursor += 2;
        }
        cursor += 2;
    }
    buffer
}

/// DEVICE_CAPABILITIES (0x40 bytes) no buffer do chamador: D0 em tudo, sem wake.
fn fill_device_capabilities(address: u64) {
    guest::write_bytes(address, &[0; 0x40]);
    guest::write16(address, 0x40); // Size
    guest::write16(address + 2, 1); // Version
    guest::write32(address + 4, 0);
    guest::write32(address + 8, 0xFFFF_FFFF); // Address
    guest::write32(address + 0xC, 0xFFFF_FFFF); // UINumber
    for index in 0..7 {
        guest::write32(address + 0x10 + index * 4, 1); // DeviceState = D0
    }
    guest::write32(address + 0x2C, 0); // SystemWake
    guest::write32(address + 0x30, 0); // DeviceWake
}

/// IO_RESOURCE_REQUIREMENTS_LIST: descritores IO com união de 24 bytes
/// (stride 0x20), uma lista alternativa com uma opção por recurso.
pub fn build_resource_requirements(resources: &[MotherboardResource]) -> u64 {
    let descriptor_size = 0x20u64;
    let size = 0x20 + 0x08 + descriptor_size * resources.len() as u64;
    let address = guest::alloc_bytes(size);
    guest::write32(address, size as u32); // ListSize
    guest::write32(address + 4, 1); // Isa
    guest::write32(address + 8, 0); // BusNumber
    guest::write32(address + 0x1C, 1); // AlternativeLists
    let alternatives = address + 0x20;
    guest::write16(alternatives, 1);
    guest::write16(alternatives + 2, 1);
    guest::write32(alternatives + 4, resources.len() as u32);
    let mut cursor = alternatives + 8;
    for resource in resources {
        guest::write8(cursor, 0); // Option: obrigatório
        guest::write8(cursor + 1, resource.resource_type);
        guest::write8(cursor + 2, 0);
        guest::write16(cursor + 4, 0);
        if resource.resource_type == part::TYPE_INTERRUPT {
            // IRQ ISA crua, antes da tradução da HAL.
            let irq = resource.vector - 0x20;
            guest::write32(cursor + 8, irq);
            guest::write32(cursor + 0xC, irq);
            guest::write64(cursor + 0x18, 0); // TargetedProcessors padrão
        } else {
            guest::write32(cursor + 8, resource.length);
            guest::write32(cursor + 0xC, 1); // Alignment
            guest::write64(cursor + 0x10, resource.start);
            guest::write64(cursor + 0x18, resource.start + resource.length as u64 - 1);
        }
        cursor += descriptor_size;
    }
    address
}

/// Queries PnP descidas ao PDO (estilo acpi.sys). O bus sempre completa:
/// deixar pendente travaria o forward+wait do driver funcional.
pub fn answer_pnp_irp(device: u64, packet: u64) -> Option<i32> {
    let entry = CREATED.lock().iter().find(|pdo| pdo.device_pointer == device).copied()?;
    let location = guest::read32(packet + irp::CURRENT_STACK_LOCATION) as u64;
    let minor = guest::read8(location + stack::MINOR);
    let mut information = 0;
    let mut status = 0u32;
    match minor {
        irp_mn::START_DEVICE | irp_mn::REMOVE_DEVICE => {}
        irp_mn::QUERY_ID => match guest::read32(location + 0x08) {
            0 => information = write_wide_string(entry.descriptor.device_id),
            1 => information = write_multi_sz(entry.descriptor.hardware_ids),
            2 => information = write_multi_sz(&["PNP0303"]),
            3 => information = write_wide_string(entry.descriptor.instance_id),
            _ => status = 0xC000_00BB,
        },
        // O buffer DEVICE_CAPABILITIES vem pronto em Parameters: o bus o preenche.
        irp_mn::QUERY_CAPABILITIES => fill_device_capabilities(guest::read32(location + 0x08) as u64),
        irp_mn::QUERY_RESOURCES => information = entry.resource_list_pointer,
        irp_mn::QUERY_RESOURCE_REQUIREMENTS => information = build_resource_requirements(&entry.descriptor.resources),
        irp_mn::FILTER_RESOURCE_REQUIREMENTS => {}
        _ => status = 0xC000_00BB,
    }
    guest::write32(packet + irp::IO_STATUS, status);
    guest::write64(packet + irp::IO_STATUS_INFORMATION, information);
    iom::iof_complete_request(packet);
    Some(status as i32)
}

fn free_pdo(pointer: u64) {
    guest::free_bytes(pointer);
}

/// PDOs com DEVICE_OBJECT nativo sem driver (quem responde é o bus).
pub fn enumerate() -> Result<Vec<CreatedPdo>, KernelError> {
    for descriptor in MOTHERBOARD_DEVICES {
        let device = guest::alloc_bytes(device_object::STRUCT_SIZE);
        guest::write16(device + device_object::TYPE, device_object::IO_TYPE);
        guest::write16(device + device_object::SIZE, device_object::STRUCT_SIZE as u16);
        guest::write32(device + device_object::DRIVER_OBJECT, 0);
        guest::write32(device + device_object::REFERENCE_COUNT, 1);
        guest::write8(device + device_object::STACK_SIZE, 1);
        device_objects::register(device, Some(free_pdo), None)?;
        let resources = build_resource_list(&descriptor.resources);
        let node = object_manager::create_object("\\Device", descriptor.name, "Device", None)?;
        iom::register_device(node, DeviceEntry { native_device: device, resources, hardware_ids: Some(descriptor.hardware_ids.iter().map(|id| alloc::string::String::from(*id)).collect()), ..Default::default() });
        CREATED.lock().push(CreatedPdo { descriptor, node, device_pointer: device, resource_list_pointer: resources });
        let summary: Vec<alloc::string::String> = descriptor.resources.iter().map(|resource| if resource.vector != 0 { alloc::format!("{}", resource.vector) } else { alloc::format!("{:x}", resource.start) }).collect();
        debug_print!("[mb] PDO \\Device\\{} criado ({}, IRQ 0x{})", descriptor.name, descriptor.device_id, summary.join("/"));
    }
    iom::register_pdo_native_answerer(answer_pnp_irp);
    Ok(CREATED.lock().clone())
}

pub fn created() -> Vec<CreatedPdo> {
    CREATED.lock().clone()
}
