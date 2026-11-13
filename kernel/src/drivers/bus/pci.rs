//! Driver de barramento PCI (estilo pci.sys).
//!
//! Enumera o hardware pelo espaço de configuração (CF8/CFC), lê
//! vendor/device/classe/BARs/IRQ de cada função e cria PDOs
//! (`\Device\PDO<N>`) com os recursos de hardware reais, prontos para
//! drivers funcionais nativos anexarem e receberem os recursos no
//! IRP_MN_START_DEVICE (Parameters.StartDevice.AllocatedResources).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::hal::pci_config;
use crate::ntos::io::device_resources;
use crate::ntos::io::io_manager::{self as iom, irp_mj, irp_mn, status, DeviceEntry, IoRequest, IoResult};
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::object_manager;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::{device_object, io_stack_location as stack, irp};

/// Tipos de CM_PARTIAL_RESOURCE_DESCRIPTOR (wdm.h).
pub mod cm_resource_type {
    pub const PORT: u8 = 1;
    pub const INTERRUPT: u8 = 2;
    pub const MEMORY: u8 = 3;
    pub const DMA: u8 = 4;
}

/// InterfaceType + BusNumber + cabeçalho da lista parcial.
const FULL_DESCRIPTOR_SIZE: u64 = 16;
/// Type + Share + Flags + união de 16 bytes.
const PARTIAL_DESCRIPTOR_SIZE: u64 = 20;

#[derive(Clone, Copy, Debug, Default)]
pub struct Bar {
    pub index: u32,
    pub value: u32,
    pub size: u32,
    pub high_value: u32,
    pub memory64: bool,
}

/// Uma função PCI enumerada.
#[derive(Clone, Debug, Default)]
pub struct PciFunction {
    pub bus: u32,
    pub device: u32,
    pub function: u32,
    pub vendor_id: u32,
    pub device_id: u32,
    pub class_code: u32,
    pub sub_class: u32,
    pub prog_if: u32,
    pub irq_line: u32,
    pub bars: Vec<Bar>,
    pub node: u64,
    pub pdo_pointer: u64,
    pub resource_list_pointer: u64,
    pub pdo_name: String,
}

/// Recurso de hardware de um CM_PARTIAL_RESOURCE_DESCRIPTOR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resource {
    pub resource_type: u8,
    pub flags: u16,
    pub start: u64,
    pub length: u32,
    pub level: u32,
    pub vector: u32,
    pub affinity: u32,
}

static DEVICES: SpinLock<Vec<PciFunction>> = SpinLock::new(Vec::new());

/// CM_RESOURCE_LIST real (layout wdm.h) na memória do convidado.
pub fn build_resource_list(resources: &[Resource]) -> u64 {
    let size = 4 + FULL_DESCRIPTOR_SIZE + PARTIAL_DESCRIPTOR_SIZE * resources.len() as u64;
    let address = guest::alloc_bytes(size);
    guest::write32(address, 1); // Count de FULL
    guest::write32(address + 4, 5); // InterfaceType = PCIBus
    guest::write32(address + 8, 0); // BusNumber
    guest::write16(address + 12, 1); // Version
    guest::write16(address + 14, 1); // Revision
    guest::write32(address + 16, resources.len() as u32);
    let mut cursor = address + 20;
    for resource in resources {
        guest::write8(cursor, resource.resource_type);
        guest::write8(cursor + 1, 0); // ShareDisposition exclusiva
        guest::write16(cursor + 2, resource.flags);
        if resource.resource_type == cm_resource_type::INTERRUPT {
            guest::write32(cursor + 4, if resource.level != 0 { resource.level } else { resource.vector });
            guest::write32(cursor + 8, resource.vector);
            guest::write32(cursor + 12, if resource.affinity != 0 { resource.affinity } else { 0xFFFF_FFFF });
        } else {
            guest::write64(cursor + 4, resource.start);
            guest::write32(cursor + 12, resource.length);
        }
        cursor += PARTIAL_DESCRIPTOR_SIZE;
    }
    address
}

pub fn hardware_id_of(entry: &PciFunction) -> String {
    format!("PCI\\VEN_{:04X}&DEV_{:04X}", entry.vendor_id, entry.device_id)
}

/// Despacho PnP do bus driver antes de um driver funcional anexar no PDO.
fn pdo_pnp_dispatch(device: u64, request: &mut IoRequest) {
    match request.minor {
        irp_mn::START_DEVICE | irp_mn::REMOVE_DEVICE => request.status = status::SUCCESS,
        irp_mn::QUERY_ID => {
            let entry = iom::device(device).and_then(|entry| entry.extra).and_then(|extra| extra.downcast::<PciFunction>().ok());
            request.result = IoResult::Text(entry.map(|entry| hardware_id_of(&entry)).unwrap_or_default());
            request.status = status::SUCCESS;
        }
        _ => request.status = status::NOT_SUPPORTED,
    }
}

/// O FDO desceu (IoCallDriver) até o PDO: o bus driver responde no IRP do
/// convidado e o completa, como o pci.sys. `None` = não é PDO nosso.
pub fn answer_native_pnp_irp(device: u64, packet: u64) -> Option<i32> {
    let entry = DEVICES.lock().iter().find(|entry| entry.node != 0 && entry.pdo_pointer == device).cloned()?;
    let location = guest::read32(packet + irp::CURRENT_STACK_LOCATION) as u64;
    let minor = guest::read8(location + stack::MINOR);
    let information = match minor {
        irp_mn::START_DEVICE | irp_mn::REMOVE_DEVICE => 0,
        irp_mn::QUERY_ID => {
            // Id em pool UTF-16 com duplo NUL (o pool já vem zerado).
            let units: Vec<u16> = hardware_id_of(&entry).encode_utf16().collect();
            let buffer = guest::alloc_bytes((units.len() as u64 + 2) * 2);
            for (index, &unit) in units.iter().enumerate() {
                guest::write16(buffer + index as u64 * 2, unit);
            }
            buffer
        }
        // STATUS_NOT_SUPPORTED sem completar.
        _ => return Some(0xC000_00BBu32 as i32),
    };
    guest::write32(packet + irp::IO_STATUS, 0);
    guest::write64(packet + irp::IO_STATUS_INFORMATION, information);
    iom::iof_complete_request(packet);
    Some(0)
}

/// Mede um BAR: escreve 1s, lê a máscara e restaura, numa transação.
fn size_bar(bus: u32, device: u32, function: u32, offset: u32, original: u32) -> Result<u32, KernelError> {
    let mask = pci_config::transaction(bus, device, function, |io| {
        io.write(offset, 4, 0xFFFF_FFFF)?;
        let mask = io.read(offset, 4);
        io.write(offset, 4, original)?;
        mask
    })?;
    if mask == 0 || mask == 0xFFFF_FFFF {
        return Ok(0);
    }
    if original & 1 != 0 {
        // Porta de I/O: bits [31:2] de endereço.
        return Ok((!(mask & 0xFFFF_FFFC)).wrapping_add(1) & 0xFFFF);
    }
    Ok((!(mask & 0xFFFF_FFF0)).wrapping_add(1))
}

/// Varre os 256 barramentos e habilita IO/Memory/BusMaster nas funções com
/// BARs, como o pci.sys no START_DEVICE.
pub fn enumerate() -> Result<usize, KernelError> {
    let mut found = Vec::new();
    let mut pdo_index = 0;
    for bus in 0..256 {
        for device in 0..32 {
            for function in 0..8 {
                let vendor_id = pci_config::read(bus, device, function, 0x00, 2)?;
                if vendor_id == 0xFFFF {
                    continue;
                }
                let device_id = pci_config::read(bus, device, function, 0x02, 2)?;
                let class = pci_config::read(bus, device, function, 0x08, 4)?;
                let irq_line = pci_config::read(bus, device, function, 0x3C, 4)? & 0xFF;
                let mut bars = Vec::new();
                let mut bar = 0;
                while bar < 6 {
                    let offset = 0x10 + bar * 4;
                    let value = pci_config::read(bus, device, function, offset, 4)?;
                    if value == 0 || value == 0xFFFF_FFFF {
                        bar += 1;
                        continue;
                    }
                    let memory64 = value & 1 == 0 && (value >> 1) & 3 == 2;
                    let size = size_bar(bus, device, function, offset, value)?;
                    if memory64 {
                        let high_value = pci_config::read(bus, device, function, 0x10 + (bar + 1) * 4, 4)?;
                        bars.push(Bar { index: bar, value, size, high_value, memory64: true });
                        bar += 2; // um BAR de 64 bits ocupa dois slots
                        continue;
                    }
                    bars.push(Bar { index: bar, value, size, ..Default::default() });
                    bar += 1;
                }
                let enable = !bars.is_empty();
                found.push(PciFunction {
                    bus,
                    device,
                    function,
                    vendor_id,
                    device_id,
                    class_code: class >> 24,
                    sub_class: (class >> 16) & 0xFF,
                    prog_if: (class >> 8) & 0xFF,
                    irq_line: if irq_line == 0xFF { 0 } else { irq_line },
                    bars,
                    pdo_name: format!("PDO{pdo_index}"),
                    ..Default::default()
                });
                pdo_index += 1;
                if enable {
                    pci_config::enable_command(bus, device, function, 0x07)?;
                }
            }
        }
    }
    let count = found.len();
    *DEVICES.lock() = found;
    Ok(count)
}

/// Recursos de hardware de uma função (BARs + IRQ). IDE em modo de
/// compatibilidade ganha as portas/IRQs fixas que o pci.sys sintetiza, na
/// ordem que o ataport espera: portas do primário antes do secundário e a
/// IRQ do primário (14) por último.
pub fn resources_of(entry: &PciFunction) -> Vec<Resource> {
    let port = |start: u64, length: u32| Resource { resource_type: cm_resource_type::PORT, flags: 0, start, length, level: 0, vector: 0, affinity: 0 };
    let interrupt = |level: u32, flags: u16| Resource { resource_type: cm_resource_type::INTERRUPT, flags, start: 0, length: 0, level, vector: 0x20 + level, affinity: 0xFFFF_FFFF };
    let mut resources = Vec::new();
    let ide = entry.class_code == 0x01 && entry.sub_class == 0x01;
    let compat_primary = ide && entry.prog_if & 0x01 == 0;
    let compat_secondary = ide && entry.prog_if & 0x04 == 0;
    if compat_primary {
        resources.push(port(0x1F0, 8));
        resources.push(port(0x3F6, 1));
    }
    if compat_secondary {
        resources.push(port(0x170, 8));
        resources.push(port(0x376, 1));
    }
    if compat_secondary {
        resources.push(interrupt(15, 0));
    }
    if compat_primary {
        resources.push(interrupt(14, 0)); // borda (ISA legado)
    }
    for bar in &entry.bars {
        if bar.value & 1 != 0 {
            resources.push(port((bar.value & 0xFFFF_FFFC) as u64, bar.size));
        } else {
            let start = if bar.memory64 { (bar.value & 0xFFFF_FFF0) as u64 + bar.high_value as u64 * 0x1_0000_0000 } else { (bar.value & 0xFFFF_FFF0) as u64 };
            resources.push(Resource { resource_type: cm_resource_type::MEMORY, flags: 0, start, length: bar.size, level: 0, vector: 0, affinity: 0 });
        }
    }
    if entry.irq_line != 0 {
        resources.push(interrupt(entry.irq_line, 0x02)); // nível
    }
    resources
}

fn free_pdo(pointer: u64) {
    guest::free_bytes(pointer);
}

/// PDOs com CM_RESOURCE_LIST pronto; cada um tem um DEVICE_OBJECT nativo
/// (DriverObject = 0 até um driver funcional anexar) e aponta para o bus
/// driver, que responde o PnP enquanto não houver pilha nativa.
fn create_pdos() -> Result<(), KernelError> {
    let bus_driver = iom::create_driver("PciBus", &[(irp_mj::PNP, pdo_pnp_dispatch)])?;
    let count = DEVICES.lock().len();
    for index in 0..count {
        let entry = DEVICES.lock()[index].clone();
        let list = build_resource_list(&resources_of(&entry));
        let pdo = guest::alloc_bytes(device_object::STRUCT_SIZE);
        guest::write16(pdo + device_object::TYPE, device_object::IO_TYPE);
        guest::write16(pdo + device_object::SIZE, device_object::STRUCT_SIZE as u16);
        guest::write32(pdo + device_object::REFERENCE_COUNT, 1);
        guest::write8(pdo + device_object::STACK_SIZE, 1);
        device_objects::register(pdo, Some(free_pdo), None)?;
        // A lista fica localizável pelo PDO (IoConnectInterruptEx LINE_BASED).
        device_resources::register_device_resources(pdo, list);
        let node = object_manager::create_object("\\Device", &entry.pdo_name, "Device", None)?;
        let mut published = entry.clone();
        published.node = node;
        published.pdo_pointer = pdo;
        published.resource_list_pointer = list;
        iom::register_device(node, DeviceEntry { driver: Some(bus_driver), native_device: pdo, resources: list, extra: Some(Arc::new(published.clone())), ..Default::default() });
        DEVICES.lock()[index] = published;
    }
    Ok(())
}

pub fn init() -> Result<usize, KernelError> {
    let count = enumerate()?;
    create_pdos()?;
    iom::register_pdo_native_answerer(answer_native_pnp_irp);
    debug_print!("[pci] {} funcoes PCI enumeradas:", count);
    for entry in DEVICES.lock().iter() {
        let bars: Vec<String> = entry.bars.iter().map(|bar| format!("{:#x}", bar.value)).collect();
        let irq = if entry.irq_line != 0 { format!(" irq {}", entry.irq_line) } else { String::new() };
        debug_print!("[pci]   {}:{}.{} {:04x}:{:04x} classe {:02x}.{:02x}{} bars=[{}] -> \\Device\\{}", entry.bus, entry.device, entry.function, entry.vendor_id, entry.device_id, entry.class_code, entry.sub_class, irq, bars.join(","), entry.pdo_name);
    }
    Ok(count)
}

/// Função por vendor/device (para drivers funcionais).
pub fn find_by_id(vendor_id: u32, device_id: u32) -> Option<PciFunction> {
    DEVICES.lock().iter().find(|entry| entry.vendor_id == vendor_id && entry.device_id == device_id).cloned()
}

pub fn devices() -> Vec<PciFunction> {
    DEVICES.lock().clone()
}
