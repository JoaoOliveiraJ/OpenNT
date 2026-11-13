//! Bus driver dos dispositivos fixos da placa-mãe.
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
use crate::ntos::inc::types::{
    CmFullResourceDescriptor, CmPartialResourceDescriptor, CmPartialResourceList, CmResourceList, DeviceCapabilities, DeviceObject, DevicePowerState, InterfaceType,
    IoResourceDescriptor, IoResourceList, IoResourceRequirementsList, IoStackLocation, Irp, NtStruct, SystemPowerState,
};
use crate::ntos::mm::guest_memory as guest;

/// CM_RESOURCE_TYPE (CmResourceTypePort, CmResourceTypeInterrupt).
mod part {
    pub const TYPE_PORT: u8 = 1;
    pub const TYPE_INTERRUPT: u8 = 2;
}

/// IO_TYPE_DEVICE.
const IO_TYPE_DEVICE: i16 = 3;

/// O IO_STACK_LOCATION corrente de um IRP vivo.
pub(crate) fn current_stack_location(packet: u64) -> (&'static Irp, &'static IoStackLocation) {
    // SAFETY: IRP vivo entregue ao bus; CurrentStackLocation é um ponteiro inteiro.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: a pilha corrente do IRP.
    (irp, unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) })
}

/// Um DEVICE_OBJECT nativo de PDO sem driver (o bus responde por ele).
pub(crate) fn initialize_pdo(device: u64) {
    // SAFETY: bloco recém-alocado do tamanho de um DEVICE_OBJECT.
    let object = unsafe { DeviceObject::at(device) };
    object.type_.set(IO_TYPE_DEVICE);
    object.size.set(DeviceObject::SIZE as u16);
    object.driver_object.set(0);
    object.reference_count.set(1);
    object.stack_size.set(1);
}

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
    use core::mem::{offset_of, size_of};
    let header = offset_of!(CmResourceList, list) + offset_of!(CmFullResourceDescriptor, partial_resource_list) + offset_of!(CmPartialResourceList, partial_descriptors);
    let address = guest::alloc_bytes((header + size_of::<CmPartialResourceDescriptor>() * resources.len()) as u64);
    // SAFETY: bloco recém-alocado com espaço para todos os descritores.
    let list = unsafe { CmResourceList::at(address) };
    list.count.set(1);
    let full = &list.list[0];
    full.interface_type.set(InterfaceType::ISA);
    full.bus_number.set(0);
    let partial = &full.partial_resource_list;
    partial.version.set(1);
    partial.revision.set(1);
    partial.count.set(resources.len() as u32);
    // SAFETY: os descritores seguem a lista parcial no mesmo bloco.
    let descriptors = unsafe { CmPartialResourceDescriptor::array_at(partial.partial_descriptors[0].address(), resources.len()) };
    for (descriptor, resource) in descriptors.iter().zip(resources) {
        descriptor.type_.set(resource.resource_type);
        descriptor.share_disposition.set(0); // exclusiva
        descriptor.flags.set(0); // latched
        if resource.resource_type == part::TYPE_INTERRUPT {
            descriptor.u.interrupt.level.set(resource.level as u16);
            descriptor.u.interrupt.group.set(0);
            descriptor.u.interrupt.vector.set(resource.vector);
            descriptor.u.interrupt.affinity.set(resource.affinity as u64);
        } else {
            descriptor.u.port.start.quad_part.set(resource.start as i64);
            descriptor.u.port.length.set(resource.length);
        }
    }
    address
}

/// String wide em pool zerado (já termina em NUL).
fn write_wide_string(text: &str) -> u64 {
    let bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let buffer = guest::alloc_bytes(bytes.len() as u64 + 2);
    guest::write_bytes(buffer, &bytes);
    buffer
}

/// MULTI_SZ wide com duplo NUL garantido pelo pool zerado.
fn write_multi_sz(strings: &[&str]) -> u64 {
    let mut bytes = Vec::new();
    for text in strings {
        bytes.extend(text.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&[0, 0]);
    let buffer = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(buffer, &bytes);
    buffer
}

/// DEVICE_CAPABILITIES (0x40 bytes) no buffer do chamador: D0 em tudo, sem wake.
fn fill_device_capabilities(address: u64) {
    guest::write_bytes(address, &[0; DeviceCapabilities::SIZE as usize]);
    // SAFETY: o DEVICE_CAPABILITIES do IRP (recém-zerado).
    let capabilities = unsafe { DeviceCapabilities::at(address) };
    capabilities.size.set(DeviceCapabilities::SIZE as u16);
    capabilities.version.set(1);
    capabilities.bitfield_4.set(0);
    capabilities.address.set(0xFFFF_FFFF);
    capabilities.ui_number.set(0xFFFF_FFFF);
    for state in &capabilities.device_state {
        state.set(DevicePowerState::POWER_DEVICE_D0);
    }
    capabilities.system_wake.set(SystemPowerState::POWER_SYSTEM_UNSPECIFIED);
    capabilities.device_wake.set(DevicePowerState::POWER_DEVICE_UNSPECIFIED);
}

/// IO_RESOURCE_REQUIREMENTS_LIST: descritores IO com união de 24 bytes
/// (stride 0x20), uma lista alternativa com uma opção por recurso.
pub fn build_resource_requirements(resources: &[MotherboardResource]) -> u64 {
    use core::mem::{offset_of, size_of};
    let size = (offset_of!(IoResourceRequirementsList, list) + offset_of!(IoResourceList, descriptors) + size_of::<IoResourceDescriptor>() * resources.len()) as u64;
    let address = guest::alloc_bytes(size);
    // SAFETY: bloco recém-alocado com espaço para todos os descritores.
    let requirements = unsafe { IoResourceRequirementsList::at(address) };
    requirements.list_size.set(size as u32);
    requirements.interface_type.set(InterfaceType::ISA);
    requirements.bus_number.set(0);
    requirements.alternative_lists.set(1);
    let alternatives = &requirements.list[0];
    alternatives.version.set(1);
    alternatives.revision.set(1);
    alternatives.count.set(resources.len() as u32);
    // SAFETY: os descritores seguem a lista alternativa no mesmo bloco.
    let descriptors = unsafe { IoResourceDescriptor::array_at(alternatives.descriptors[0].address(), resources.len()) };
    for (descriptor, resource) in descriptors.iter().zip(resources) {
        descriptor.option.set(0); // obrigatório
        descriptor.type_.set(resource.resource_type);
        descriptor.share_disposition.set(0);
        descriptor.flags.set(0);
        if resource.resource_type == part::TYPE_INTERRUPT {
            // IRQ ISA crua, antes da tradução da HAL.
            let irq = resource.vector - 0x20;
            descriptor.u.interrupt.minimum_vector.set(irq);
            descriptor.u.interrupt.maximum_vector.set(irq);
            descriptor.u.interrupt.targeted_processors.set(0); // padrão
        } else {
            descriptor.u.port.length.set(resource.length);
            descriptor.u.port.alignment.set(1);
            descriptor.u.port.minimum_address.quad_part.set(resource.start as i64);
            descriptor.u.port.maximum_address.quad_part.set((resource.start + resource.length as u64 - 1) as i64);
        }
    }
    address
}

/// Queries PnP descidas ao PDO (estilo acpi.sys). O bus sempre completa:
/// deixar pendente travaria o forward+wait do driver funcional.
pub fn answer_pnp_irp(device: u64, packet: u64) -> Option<i32> {
    let entry = CREATED.lock().iter().find(|pdo| pdo.device_pointer == device).copied()?;
    let (request, location) = current_stack_location(packet);
    let minor = location.minor_function.get();
    let mut information = 0;
    let mut status = 0u32;
    match minor {
        irp_mn::START_DEVICE | irp_mn::REMOVE_DEVICE => {}
        irp_mn::QUERY_ID => match location.parameters.query_id.id_type.get().0 {
            0 => information = write_wide_string(entry.descriptor.device_id),
            1 => information = write_multi_sz(entry.descriptor.hardware_ids),
            2 => information = write_multi_sz(&["PNP0303"]),
            3 => information = write_wide_string(entry.descriptor.instance_id),
            _ => status = 0xC000_00BB,
        },
        // O buffer DEVICE_CAPABILITIES vem pronto em Parameters: o bus o preenche.
        irp_mn::QUERY_CAPABILITIES => fill_device_capabilities(location.parameters.device_capabilities.capabilities.get()),
        irp_mn::QUERY_RESOURCES => information = entry.resource_list_pointer,
        irp_mn::QUERY_RESOURCE_REQUIREMENTS => information = build_resource_requirements(&entry.descriptor.resources),
        irp_mn::FILTER_RESOURCE_REQUIREMENTS => {}
        _ => status = 0xC000_00BB,
    }
    request.io_status.status.set(status as i32);
    request.io_status.information.set(information);
    iom::iof_complete_request(packet);
    Some(status as i32)
}

fn free_pdo(pointer: u64) {
    guest::free_bytes(pointer);
}

/// PDOs com DEVICE_OBJECT nativo sem driver (quem responde é o bus).
pub fn enumerate() -> Result<Vec<CreatedPdo>, KernelError> {
    for descriptor in MOTHERBOARD_DEVICES {
        let device = guest::alloc_bytes(DeviceObject::SIZE);
        initialize_pdo(device);
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
