//! Respostas PnP dos PDOs do barramento PCI (o que o pci.sys responde).
//!
//! PDO de função:
//! - QUERY_ID: DeviceID `PCI\VEN_v&DEV_d&SUBSYS_s&REV_r`; HardwareIDs (com
//!   SUBSYS e REV, com SUBSYS, `&CC_ccsspp` e `&CC_ccss`); CompatibleIDs
//!   (`&REV_r`, VEN&DEV, VEN&CC com e sem prog-if, VEN, CC com e sem
//!   prog-if); InstanceID `%02X` de (dispositivo << 3 | função) — os
//!   formatos do pci.sys.
//! - QUERY_CAPABILITIES: Address = (dispositivo << 16) | função, D0 em S0 e
//!   D3 nos demais estados, sem wake, sem UniqueID.
//! - QUERY_RESOURCE_REQUIREMENTS e QUERY_RESOURCES: os BARs (o valor que o
//!   firmware programou como opção preferida e, como alternativa, qualquer
//!   posição alinhada de 16/32 bits; um BAR de memória pré-buscável leva
//!   CM_RESOURCE_MEMORY_PREFETCHABLE) e a IRQ de linha, compartilhável e por
//!   nível, se a função tem pino de interrupção. Numa controladora IDE em
//!   modo de compatibilidade (prog-if com os bits 0/2 limpos) os BARs 0..3
//!   do canal legado não são decodificados e ficam de fora: as portas e IRQs
//!   legadas são dos canais (o pciidex.sys as pede pelos PDOs deles). Uma
//!   função com MSI ou MSI-X cujo INF pediu mensagens (MSISupported) pede
//!   as mensagens antes da linha (`pci_msi`).
//! - START_DEVICE: programa os BARs com os recursos atribuídos e liga I/O,
//!   memória e bus master no registrador de comando; programa as mensagens
//!   atribuídas e liga o MSI/MSI-X (`pci_msi`).
//! - QUERY_BUS_INFORMATION (GUID_BUS_TYPE_PCI, PCIBus, barramento),
//!   QUERY_DEVICE_TEXT (a descrição da classe da tabela de mensagens do
//!   pci.sys e "PCI bus %1, device %2, function %3"), QUERY_INTERFACE
//!   (`pci_interface`), READ_CONFIG/WRITE_CONFIG, TargetDeviceRelation e
//!   DEVICE_USAGE_NOTIFICATION.
//! Um pedido que o barramento não atende é completado com o status que
//! chegou (o STATUS_NOT_SUPPORTED do PnP manager). IRP_MJ_POWER é aceito;
//! outros majors num PDO cru recebem STATUS_INVALID_DEVICE_REQUEST.
//!
//! PDO do barramento raiz (PCI_HAL\PNP0A03\0): BusRelations com os PDOs das
//! funções, QUERY_ID, UniqueID e START.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::pci::PciFunction;
use crate::hal::pci_config;
use crate::ntos::inc::types::{BusQueryIdType, DeviceCapabilities, DevicePowerState, DeviceRelationType, DeviceRelations, DeviceTextType, IoStackLocation, Irp, NtStruct, SystemPowerState};
use crate::ntos::io::io_manager::{self as iom, irp_mj, irp_mn};
use crate::ntos::io::pnp::irp::{IRP_MN_DEVICE_USAGE_NOTIFICATION, IRP_MN_READ_CONFIG, IRP_MN_WRITE_CONFIG};
use crate::ntos::io::pnp::resources::{resource_type, CmList, Resource, SHARE_DEVICE_EXCLUSIVE, SHARE_SHARED};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_DEVICE_REQUEST: i32 = 0xC000_0010u32 as i32;
const STATUS_BUFFER_TOO_SMALL: i32 = 0xC000_0023u32 as i32;

/// GUID_BUS_TYPE_PCI {c8ebdfb0-b510-11d0-80e5-00a0c92542e3} e
/// GUID_BUS_TYPE_INTERNAL {1530ea73-086b-11d1-a09f-00c04fc340b1}.
const GUID_BUS_TYPE_PCI: [u8; 16] = [0xB0, 0xDF, 0xEB, 0xC8, 0x10, 0xB5, 0xD0, 0x11, 0x80, 0xE5, 0x00, 0xA0, 0xC9, 0x25, 0x42, 0xE3];
const GUID_BUS_TYPE_INTERNAL: [u8; 16] = [0x73, 0xEA, 0x30, 0x15, 0x6B, 0x08, 0xD1, 0x11, 0xA0, 0x9F, 0x00, 0xC0, 0x4F, 0xC3, 0x40, 0xB1];
/// INTERFACE_TYPE Internal e PCIBus.
const INTERNAL: i32 = 0;
const PCI_BUS: i32 = 5;
/// IO_RESOURCE_DESCRIPTOR.Option.
const IO_RESOURCE_PREFERRED: u8 = 1;
const IO_RESOURCE_ALTERNATIVE: u8 = 8;
/// CM_RESOURCE_PORT_IO, CM_RESOURCE_MEMORY_READ_WRITE,
/// CM_RESOURCE_MEMORY_PREFETCHABLE e CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE.
const PORT_IO: u16 = 1;
const MEMORY_READ_WRITE: u16 = 0;
const MEMORY_PREFETCHABLE: u16 = 4;
const INTERRUPT_LEVEL_SENSITIVE: u16 = 0;
/// CM_RESOURCE_INTERRUPT_LATCHED e CM_RESOURCE_INTERRUPT_MESSAGE.
const INTERRUPT_LATCHED: u16 = 1;
const INTERRUPT_MESSAGE: u16 = 2;
/// PCI_WHICHSPACE_CONFIG.
const PCI_WHICHSPACE_CONFIG: u32 = 0;

/// Mensagens de classe do pci.sys (id = classe << 8 | subclasse).
const CLASS_TEXT: &[(u16, &str)] = &[
    (0x0001, "VGA Device"),
    (0x0100, "SCSI Controller"),
    (0x0101, "IDE Controller"),
    (0x0102, "Floppy Controller"),
    (0x0104, "RAID Controller"),
    (0x0105, "ATA Controller"),
    (0x0106, "Serial ATA Controller"),
    (0x0180, "Mass Storage Controller"),
    (0x0200, "Ethernet Controller"),
    (0x0280, "Network Controller"),
    (0x0300, "Video Controller (VGA Compatible)"),
    (0x0380, "Video Controller"),
    (0x0401, "Multimedia Audio Controller"),
    (0x0480, "Multimedia Controller"),
    (0x0600, "PCI HOST Bridge"),
    (0x0601, "PCI to ISA Bridge"),
    (0x0604, "PCI to PCI Bridge"),
    (0x0680, "Other PCI Bridge Device"),
    (0x0700, "PCI Serial Port"),
    (0x0880, "Base System Device"),
    (0x0C03, "Universal Serial Bus (USB) Controller"),
    (0x0C05, "SM Bus Controller"),
];

/// Ids do tipo pedido (BUS_QUERY_ID_TYPE), nos formatos do pci.sys.
pub fn ids_of(function: &PciFunction, id_type: u32) -> Vec<String> {
    let (vendor, device, revision) = (function.vendor_id, function.device_id, function.revision);
    let subsystem = function.subsystem_id << 16 | function.subsystem_vendor;
    let (class, sub, prog) = (function.class_code, function.sub_class, function.prog_if);
    match BusQueryIdType(id_type as i32) {
        BusQueryIdType::BUS_QUERY_DEVICE_ID => alloc::vec![format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&SUBSYS_{subsystem:08X}&REV_{revision:02X}")],
        BusQueryIdType::BUS_QUERY_HARDWARE_I_DS => alloc::vec![
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&SUBSYS_{subsystem:08X}&REV_{revision:02X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&SUBSYS_{subsystem:08X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&CC_{class:02X}{sub:02X}{prog:02X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&CC_{class:02X}{sub:02X}"),
        ],
        BusQueryIdType::BUS_QUERY_COMPATIBLE_I_DS => alloc::vec![
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&REV_{revision:02X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}"),
            format!("PCI\\VEN_{vendor:04X}&CC_{class:02X}{sub:02X}{prog:02X}"),
            format!("PCI\\VEN_{vendor:04X}&CC_{class:02X}{sub:02X}"),
            format!("PCI\\VEN_{vendor:04X}"),
            format!("PCI\\CC_{class:02X}{sub:02X}{prog:02X}"),
            format!("PCI\\CC_{class:02X}{sub:02X}"),
        ],
        BusQueryIdType::BUS_QUERY_INSTANCE_ID => alloc::vec![format!("{:02X}", function.device << 3 | function.function)],
        _ => Vec::new(),
    }
}

/// Strings UTF-16 em pool, com o NUL duplo das listas.
fn pool_strings(items: &[String]) -> u64 {
    let mut bytes = Vec::new();
    for item in items {
        bytes.extend(item.encode_utf16().flat_map(|unit| unit.to_le_bytes()));
        bytes.extend_from_slice(&[0, 0]);
    }
    bytes.extend_from_slice(&[0, 0]);
    let buffer = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(buffer, &bytes);
    buffer
}

/// Controladora IDE com o canal `channel` em modo de compatibilidade.
fn legacy_ide_channel(function: &PciFunction, channel: u32) -> bool {
    function.class_code == 0x01 && function.sub_class == 0x01 && function.prog_if & (1 << (channel * 2)) == 0
}

/// BARs que a função decodifica (sem os do canal IDE legado).
fn decoded_bars(function: &PciFunction) -> Vec<super::pci::Bar> {
    function.bars.iter().copied().filter(|bar| !((bar.index < 2 && legacy_ide_channel(function, 0)) || ((2..4).contains(&bar.index) && legacy_ide_channel(function, 1)))).collect()
}

/// Flags do descritor de um BAR: porta de I/O, ou memória com o bit
/// pré-buscável (bit 3 do BAR) como CM_RESOURCE_MEMORY_PREFETCHABLE.
fn bar_flags(bar: &super::pci::Bar) -> u16 {
    if bar.value & 1 != 0 {
        PORT_IO
    } else if bar.value & 0x8 != 0 {
        MEMORY_READ_WRITE | MEMORY_PREFETCHABLE
    } else {
        MEMORY_READ_WRITE
    }
}

fn bar_start(bar: &super::pci::Bar) -> u64 {
    if bar.value & 1 != 0 {
        (bar.value & 0xFFFF_FFFC) as u64
    } else if bar.memory64 {
        (bar.value & 0xFFFF_FFF0) as u64 | (bar.high_value as u64) << 32
    } else {
        (bar.value & 0xFFFF_FFF0) as u64
    }
}

/// A configuração corrente (QUERY_RESOURCES): BARs e a IRQ de linha.
pub fn current_resources(function: &PciFunction) -> CmList {
    let mut resources = Vec::new();
    for bar in decoded_bars(function).iter().filter(|bar| bar.size != 0) {
        let io = bar.value & 1 != 0;
        resources.push(Resource { resource_type: if io { resource_type::PORT } else { resource_type::MEMORY }, share: SHARE_DEVICE_EXCLUSIVE, flags: bar_flags(bar), start: bar_start(bar), length: bar.size, extra: [0; 3] });
    }
    if function.interrupt_pin != 0 && function.irq_line != 0 {
        resources.push(Resource { resource_type: resource_type::INTERRUPT, share: SHARE_SHARED, flags: INTERRUPT_LEVEL_SENSITIVE, start: function.irq_line as u64, length: function.irq_line, extra: [u32::MAX, u32::MAX, 0] });
    }
    CmList { interface_type: PCI_BUS, bus_number: function.bus, resources }
}

/// IO_RESOURCE_REQUIREMENTS_LIST em pool: para cada BAR, a posição corrente
/// (preferida) e qualquer posição alinhada (alternativa); a IRQ de linha.
fn requirements_list(function: &PciFunction) -> u64 {
    use crate::ntos::inc::types::{IoResourceDescriptor, IoResourceList, IoResourceRequirementsList};
    use core::mem::offset_of;
    struct Entry {
        option: u8,
        resource_type: u8,
        share: u8,
        flags: u16,
        length: u32,
        alignment: u32,
        minimum: u64,
        maximum: u64,
    }
    let mut entries: Vec<Entry> = Vec::new();
    for bar in decoded_bars(function).iter().filter(|bar| bar.size != 0) {
        let io = bar.value & 1 != 0;
        let (resource, flags) = (if io { resource_type::PORT } else { resource_type::MEMORY }, bar_flags(bar));
        let start = bar_start(bar);
        let limit = if io { 0xFFFF } else if bar.memory64 { u64::MAX } else { 0xFFFF_FFFF };
        entries.push(Entry { option: IO_RESOURCE_PREFERRED, resource_type: resource, share: SHARE_DEVICE_EXCLUSIVE, flags, length: bar.size, alignment: bar.size, minimum: start, maximum: start + bar.size as u64 - 1 });
        entries.push(Entry { option: IO_RESOURCE_ALTERNATIVE, resource_type: resource, share: SHARE_DEVICE_EXCLUSIVE, flags, length: bar.size, alignment: bar.size, minimum: 0, maximum: limit });
    }
    // As mensagens (MSI/MSI-X) que a função pede vêm antes da linha, que
    // fica como alternativa ou de fora (`pci_msi`).
    let has_line = function.interrupt_pin != 0 && function.irq_line != 0;
    let messages = super::pci_msi::requirement_descriptors(function, function.pdo_pointer, has_line);
    let line_option = messages.as_ref().map_or(Some(0), |(_, option)| *option);
    for &(option, minimum, maximum) in messages.iter().flat_map(|(descriptors, _)| descriptors) {
        entries.push(Entry { option, resource_type: resource_type::INTERRUPT, share: SHARE_DEVICE_EXCLUSIVE, flags: INTERRUPT_LATCHED | INTERRUPT_MESSAGE, length: 0, alignment: 0, minimum: minimum as u64, maximum: maximum as u64 });
    }
    if let Some(option) = line_option.filter(|_| has_line) {
        entries.push(Entry { option, resource_type: resource_type::INTERRUPT, share: SHARE_SHARED, flags: INTERRUPT_LEVEL_SENSITIVE, length: 0, alignment: 0, minimum: function.irq_line as u64, maximum: function.irq_line as u64 });
    }
    if entries.is_empty() {
        return 0;
    }
    let size = (offset_of!(IoResourceRequirementsList, list) + offset_of!(IoResourceList, descriptors)) as u64 + entries.len() as u64 * IoResourceDescriptor::SIZE;
    let address = guest::alloc_bytes(size);
    // SAFETY: bloco recém-alocado com espaço para todos os descritores.
    let header = unsafe { IoResourceRequirementsList::at(address) };
    header.list_size.set(size as u32);
    header.interface_type.set(crate::ntos::inc::types::InterfaceType(PCI_BUS));
    header.bus_number.set(function.bus);
    header.slot_number.set(function.device | function.function << 5);
    header.alternative_lists.set(1);
    let list = &header.list[0];
    list.version.set(1);
    list.revision.set(1);
    list.count.set(entries.len() as u32);
    // SAFETY: os descritores seguem o cabeçalho da lista no mesmo bloco.
    let descriptors = unsafe { IoResourceDescriptor::array_at(list.descriptors[0].address(), entries.len()) };
    for (descriptor, entry) in descriptors.iter().zip(&entries) {
        descriptor.option.set(entry.option);
        descriptor.type_.set(entry.resource_type);
        descriptor.share_disposition.set(entry.share);
        descriptor.flags.set(entry.flags);
        if entry.resource_type == resource_type::INTERRUPT {
            descriptor.u.interrupt.minimum_vector.set(entry.minimum as u32);
            descriptor.u.interrupt.maximum_vector.set(entry.maximum as u32);
        } else {
            descriptor.u.port.length.set(entry.length);
            descriptor.u.port.alignment.set(entry.alignment);
            descriptor.u.port.minimum_address.quad_part.set(entry.minimum as i64);
            descriptor.u.port.maximum_address.quad_part.set(entry.maximum as i64);
        }
    }
    address
}

/// START_DEVICE: cada BAR decodificado recebe o recurso atribuído do mesmo
/// tipo, na ordem; decodificação e bus master ligados.
fn start_function(function: &PciFunction, raw: u64) {
    if let Some(list) = CmList::read(raw) {
        let mut assigned = list.resources.iter().filter(|resource| resource.resource_type == resource_type::PORT || resource.resource_type == resource_type::MEMORY);
        for bar in decoded_bars(function).iter().filter(|bar| bar.size != 0) {
            let Some(resource) = assigned.next() else { break };
            if resource.start != bar_start(bar) {
                let offset = 0x10 + bar.index * 4;
                let low = resource.start as u32 | (bar.value & if bar.value & 1 != 0 { 0x3 } else { 0xF });
                let _ = pci_config::write(function.bus, function.device, function.function, offset, 4, low);
                if bar.memory64 {
                    let _ = pci_config::write(function.bus, function.device, function.function, offset + 4, 4, (resource.start >> 32) as u32);
                }
            }
        }
    }
    let _ = pci_config::enable_command(function.bus, function.device, function.function, 0x07);
    // As mensagens atribuídas (dados de conexão do PDO) e a capacidade ligada.
    let programmed = super::pci_msi::program(function, function.pdo_pointer);
    if programmed != 0 {
        debug_print!("[pci] {}:{}.{}: {} mensagem(ns) programada(s)", function.bus, function.device, function.function, programmed);
    }
}

/// DEVICE_RELATIONS em pool com um PDO referenciado.
fn target_relation(device: u64) -> u64 {
    relations(&[device])
}

fn relations(devices: &[u64]) -> u64 {
    let size = DeviceRelations::SIZE + devices.len().saturating_sub(1) as u64 * 8;
    let address = guest::alloc_bytes(size);
    // SAFETY: DEVICE_RELATIONS recém-alocada com `devices.len()` entradas.
    let list = unsafe { DeviceRelations::at(address) };
    list.count.set(devices.len() as u32);
    // SAFETY: Objects[] segue o cabeçalho na mesma alocação.
    let objects = unsafe { crate::ntos::inc::field::Field::<u64>::array_at(list.objects[0].address(), devices.len()) };
    for (slot, &device) in objects.iter().zip(devices) {
        let _ = device_objects::reference(device);
        slot.set(device);
    }
    address
}

/// PNP_BUS_INFORMATION em pool.
fn bus_information(guid: &[u8; 16], legacy: i32, number: u32) -> u64 {
    use crate::ntos::inc::types::extra_storage::PnpBusInformation;
    let address = guest::alloc_bytes(PnpBusInformation::SIZE);
    // SAFETY: bloco recém-alocado do tamanho da estrutura.
    let information = unsafe { PnpBusInformation::at(address) };
    guest::write_bytes(information.bus_type_guid.address(), guid);
    information.legacy_bus_type.set(crate::ntos::inc::types::InterfaceType(legacy));
    information.bus_number.set(number);
    address
}

/// DEVICE_CAPABILITIES de uma função PCI.
fn fill_capabilities(function: &PciFunction, address: u64) {
    // SAFETY: DEVICE_CAPABILITIES do IRP (Size/Version já gravados pelo PnP).
    let capabilities = unsafe { DeviceCapabilities::at(address) };
    capabilities.address.set(function.device << 16 | function.function);
    capabilities.device_state[0].set(DevicePowerState::POWER_DEVICE_UNSPECIFIED);
    capabilities.device_state[1].set(DevicePowerState::POWER_DEVICE_D0);
    for state in &capabilities.device_state[2..] {
        state.set(DevicePowerState::POWER_DEVICE_D3);
    }
    capabilities.system_wake.set(SystemPowerState::POWER_SYSTEM_UNSPECIFIED);
    capabilities.device_wake.set(DevicePowerState::POWER_DEVICE_UNSPECIFIED);
    // Como o PciDevice_QueryCapabilities: só a ponte de host (classe 06.00)
    // é RawDeviceOK (e SurpriseRemovalOK); ela não tem driver funcional
    // (NO_DRV do machine.inf) e inicia só com o PDO.
    let host_bridge = function.class_code == 0x06 && function.sub_class == 0x00;
    capabilities.set_raw_device_ok(host_bridge as u32);
    capabilities.set_surprise_removal_ok(host_bridge as u32);
}

/// Copia o espaço de configuração (READ_CONFIG/WRITE_CONFIG).
fn config_transfer(function: &PciFunction, location: &IoStackLocation, write: bool) -> (i32, u64) {
    let parameters = &location.parameters.read_write_config;
    if parameters.which_space.get() != PCI_WHICHSPACE_CONFIG {
        return (STATUS_INVALID_DEVICE_REQUEST, 0);
    }
    let slot = function.device | function.function << 5;
    let (buffer, offset, length) = (parameters.buffer.get(), parameters.offset.get(), parameters.length.get());
    let done = if write {
        crate::hal::pci_native::set_bus_data_by_offset(4, function.bus, slot, buffer, offset, length)
    } else {
        crate::hal::pci_native::get_bus_data_by_offset(4, function.bus, slot, buffer, offset, length)
    }
    .unwrap_or(0);
    if done < length {
        return (STATUS_BUFFER_TOO_SMALL, done as u64);
    }
    (STATUS_SUCCESS, done as u64)
}

/// Respostas de IRP_MJ_PNP de um PDO de função; None = não atende.
fn function_pnp(function: &PciFunction, device: u64, location: &IoStackLocation) -> Option<(i32, u64)> {
    match location.minor_function.get() {
        irp_mn::START_DEVICE => {
            start_function(function, location.parameters.start_device.allocated_resources.get());
            Some((STATUS_SUCCESS, 0))
        }
        // QUERY_REMOVE, REMOVE, CANCEL_REMOVE, STOP, QUERY_STOP, CANCEL_STOP
        // e SURPRISE_REMOVAL.
        1..=6 | irp_mn::SURPRISE_REMOVAL => Some((STATUS_SUCCESS, 0)),
        irp_mn::QUERY_ID => {
            let ids = ids_of(function, location.parameters.query_id.id_type.get().0 as u32);
            (!ids.is_empty()).then(|| (STATUS_SUCCESS, pool_strings(&ids)))
        }
        irp_mn::QUERY_CAPABILITIES => {
            let capabilities = location.parameters.device_capabilities.capabilities.get();
            if capabilities == 0 {
                return Some((STATUS_INVALID_DEVICE_REQUEST, 0));
            }
            fill_capabilities(function, capabilities);
            Some((STATUS_SUCCESS, 0))
        }
        irp_mn::QUERY_RESOURCES => Some((STATUS_SUCCESS, current_resources(function).write())),
        irp_mn::QUERY_RESOURCE_REQUIREMENTS => Some((STATUS_SUCCESS, requirements_list(function))),
        irp_mn::QUERY_BUS_INFORMATION => Some((STATUS_SUCCESS, bus_information(&GUID_BUS_TYPE_PCI, PCI_BUS, function.bus))),
        irp_mn::QUERY_DEVICE_TEXT => {
            let text = match location.parameters.query_device_text.device_text_type.get() {
                DeviceTextType::DEVICE_TEXT_DESCRIPTION => {
                    let id = (function.class_code << 8 | function.sub_class) as u16;
                    String::from(CLASS_TEXT.iter().find(|(class, _)| *class == id).map_or("PCI Device", |(_, text)| *text))
                }
                DeviceTextType::DEVICE_TEXT_LOCATION_INFORMATION => format!("PCI bus {}, device {}, function {}", function.bus, function.device, function.function),
                _ => return None,
            };
            Some((STATUS_SUCCESS, pool_strings(&[text])))
        }
        irp_mn::QUERY_INTERFACE => {
            let parameters = &location.parameters.query_interface;
            let mut guid = [0u8; 16];
            guid.copy_from_slice(&guest::read_bytes(parameters.interface_type.get(), 16));
            match super::pci_interface::fill(device, &guid, parameters.size.get(), parameters.version.get(), parameters.interface.get()) {
                Ok(true) => Some((STATUS_SUCCESS, 0)),
                _ => None,
            }
        }
        IRP_MN_READ_CONFIG => Some(config_transfer(function, location, false)),
        IRP_MN_WRITE_CONFIG => Some(config_transfer(function, location, true)),
        IRP_MN_DEVICE_USAGE_NOTIFICATION => Some((STATUS_SUCCESS, 0)),
        irp_mn::QUERY_DEVICE_RELATIONS if location.parameters.query_device_relations.type_.get() == DeviceRelationType::TARGET_DEVICE_RELATION => Some((STATUS_SUCCESS, target_relation(device))),
        _ => None,
    }
}

/// Completa o IRP com a resposta (ou com o status que chegou).
fn complete(irp: &Irp, packet: u64, answer: Option<(i32, u64)>) -> i32 {
    if let Some((status, information)) = answer {
        irp.io_status.status.set(status);
        irp.io_status.information.set(information);
    }
    let status = irp.io_status.status.get();
    iom::iof_complete_request(packet);
    status
}

/// IRP no PDO de uma função.
pub fn answer_function(function: &PciFunction, packet: u64) -> i32 {
    let (irp, location) = super::motherboard::current_stack_location(packet);
    let device = location.device_object.get();
    let answer = match location.major_function.get() {
        irp_mj::PNP => function_pnp(function, device, location),
        irp_mj::POWER => Some((STATUS_SUCCESS, irp.io_status.information.get())),
        // IRP_MJ_SYSTEM_CONTROL: o PDO não é provedor WMI.
        0x17 => None,
        _ => Some((STATUS_INVALID_DEVICE_REQUEST, 0)),
    };
    complete(irp, packet, answer)
}

/// IRP no PDO do barramento raiz.
pub fn answer_root_bus(device: u64, packet: u64, functions: &[u64]) -> i32 {
    let (irp, location) = super::motherboard::current_stack_location(packet);
    let answer = match location.major_function.get() {
        irp_mj::PNP => match location.minor_function.get() {
            0..=6 | irp_mn::SURPRISE_REMOVAL => Some((STATUS_SUCCESS, 0)),
            irp_mn::QUERY_DEVICE_RELATIONS => match location.parameters.query_device_relations.type_.get() {
                DeviceRelationType::BUS_RELATIONS => Some((STATUS_SUCCESS, relations(functions))),
                DeviceRelationType::TARGET_DEVICE_RELATION => Some((STATUS_SUCCESS, target_relation(device))),
                _ => None,
            },
            irp_mn::QUERY_ID => {
                let text = match location.parameters.query_id.id_type.get() {
                    BusQueryIdType::BUS_QUERY_DEVICE_ID => alloc::vec![String::from("PCI_HAL\\PNP0A03")],
                    BusQueryIdType::BUS_QUERY_HARDWARE_I_DS => alloc::vec![String::from("PCI_HAL\\PNP0A03"), String::from("*PNP0A03")],
                    BusQueryIdType::BUS_QUERY_INSTANCE_ID => alloc::vec![String::from("0")],
                    _ => Vec::new(),
                };
                (!text.is_empty()).then(|| (STATUS_SUCCESS, pool_strings(&text)))
            }
            irp_mn::QUERY_CAPABILITIES => {
                // SAFETY: DEVICE_CAPABILITIES do IRP.
                let capabilities = unsafe { DeviceCapabilities::at(location.parameters.device_capabilities.capabilities.get()) };
                capabilities.set_unique_id(1);
                Some((STATUS_SUCCESS, 0))
            }
            irp_mn::QUERY_BUS_INFORMATION => Some((STATUS_SUCCESS, bus_information(&GUID_BUS_TYPE_INTERNAL, INTERNAL, 0))),
            _ => None,
        },
        irp_mj::POWER => Some((STATUS_SUCCESS, irp.io_status.information.get())),
        0x17 => None,
        _ => Some((STATUS_INVALID_DEVICE_REQUEST, 0)),
    };
    complete(irp, packet, answer)
}
