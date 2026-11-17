//! Driver de barramento PCI (estilo pci.sys).
//!
//! Enumera o hardware pelo espaço de configuração (CF8/CFC), lê
//! vendor/device/classe/subsistema/revisão/BARs/IRQ de cada função e cria
//! PDOs (`\Device\PDO<N>`) com os recursos de hardware reais, filhos de um
//! PDO de barramento raiz (o barramento que a HAL enumera, PCI_HAL\PNP0A03).
//! As respostas PnP desses PDOs, as do pci.sys, ficam em `pci_pnp`.

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
use crate::ntos::inc::types::{CmFullResourceDescriptor, CmPartialResourceDescriptor, CmPartialResourceList, CmResourceList, DeviceObject, InterfaceType, NtStruct};
use crate::ntos::mm::guest_memory as guest;

/// Tipos de CM_PARTIAL_RESOURCE_DESCRIPTOR (wdm.h).
pub mod cm_resource_type {
    pub const PORT: u8 = 1;
    pub const INTERRUPT: u8 = 2;
    pub const MEMORY: u8 = 3;
    pub const DMA: u8 = 4;
}



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
    /// Revisão (0x08), subsistema (0x2C/0x2E), cabeçalho (0x0E) e pino de
    /// interrupção (0x3D) do espaço de configuração.
    pub revision: u32,
    pub subsystem_vendor: u32,
    pub subsystem_id: u32,
    pub header_type: u32,
    pub interrupt_pin: u32,
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
    use core::mem::{offset_of, size_of};
    let header = offset_of!(CmResourceList, list) + offset_of!(CmFullResourceDescriptor, partial_resource_list) + offset_of!(CmPartialResourceList, partial_descriptors);
    let address = guest::alloc_bytes((header + size_of::<CmPartialResourceDescriptor>() * resources.len()) as u64);
    // SAFETY: bloco recém-alocado com espaço para todos os descritores.
    let list = unsafe { CmResourceList::at(address) };
    list.count.set(1); // um FULL descriptor
    let full = &list.list[0];
    full.interface_type.set(InterfaceType::PCI_BUS);
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
        descriptor.flags.set(resource.flags);
        if resource.resource_type == cm_resource_type::INTERRUPT {
            let level = if resource.level != 0 { resource.level } else { resource.vector };
            descriptor.u.interrupt.level.set(level as u16);
            descriptor.u.interrupt.group.set(0);
            descriptor.u.interrupt.vector.set(resource.vector);
            // KAFFINITY inteiro (64 bits).
            descriptor.u.interrupt.affinity.set(if resource.affinity != 0 { resource.affinity } else { 0xFFFF_FFFF } as u64);
        } else {
            descriptor.u.port.start.quad_part.set(resource.start as i64);
            descriptor.u.port.length.set(resource.length);
        }
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
            let ids = entry.map(|entry| super::pci_pnp::ids_of(&entry, request.params.relations_type.unwrap_or(0))).unwrap_or_default();
            request.result = IoResult::Text(ids.into_iter().next().unwrap_or_default());
            request.status = status::SUCCESS;
        }
        _ => request.status = status::NOT_SUPPORTED,
    }
}

/// O IRP desceu (IoCallDriver) até um PDO do barramento: o bus driver
/// responde no IRP e o completa, como o pci.sys. `None` = não é PDO nosso.
pub fn answer_native_pnp_irp(device: u64, packet: u64) -> Option<i32> {
    if device == root_bus_pdo() && device != 0 {
        return Some(super::pci_pnp::answer_root_bus(device, packet, &DEVICES.lock().iter().map(|entry| entry.pdo_pointer).collect::<Vec<_>>()));
    }
    let entry = DEVICES.lock().iter().find(|entry| entry.node != 0 && entry.pdo_pointer == device).cloned()?;
    Some(super::pci_pnp::answer_function(&entry, packet))
}

/// A função de um PDO do barramento.
pub fn function_of_pdo(pdo: u64) -> Option<PciFunction> {
    DEVICES.lock().iter().find(|entry| entry.pdo_pointer == pdo && pdo != 0).cloned()
}

/// PDO do barramento raiz (PCI_HAL\PNP0A03\0).
static ROOT_BUS_PDO: SpinLock<u64> = SpinLock::new(0);

pub fn root_bus_pdo() -> u64 {
    *ROOT_BUS_PDO.lock()
}

/// Cria (uma vez) o PDO do barramento raiz, que a árvore do PnP enumera:
/// os PDOs das funções são as BusRelations dele.
pub fn create_root_bus() -> Result<u64, KernelError> {
    let mut root = ROOT_BUS_PDO.lock();
    if *root != 0 {
        return Ok(*root);
    }
    let pdo = guest::alloc_bytes(DeviceObject::SIZE);
    super::motherboard::initialize_pdo(pdo);
    device_objects::register(pdo, Some(free_pdo), None)?;
    crate::ntos::io::pnp::publish_autogenerated_pdo(pdo)?;
    *root = pdo;
    Ok(pdo)
}

/// Bits do registrador de comando (offset 0x04) da configuração PCI.
const COMMAND_IO_SPACE: u32 = 0x0001;
const COMMAND_MEMORY_SPACE: u32 = 0x0002;
const COMMAND_BUS_MASTER: u32 = 0x0004;
const COMMAND_INTERRUPT_DISABLE: u32 = 0x0400;

/// Mede um BAR numa transação: desliga a decodificação de I/O e de memória e
/// o bus master e mascara o INTx no comando, como o PciPreScanDisconnectDevice
/// do pci.sys antes de medir os BARs; escreve 1s, lê a máscara e restaura o
/// BAR e o comando. Com a decodificação ligada, o BAR com 1s responderia no
/// topo dos 4 GB, por cima da ROM do BIOS e de outros dispositivos, enquanto
/// dura a medida (no QEMU com WHPX, o remapeamento da ROM falha e o boot para).
fn size_bar(bus: u32, device: u32, function: u32, offset: u32, original: u32) -> Result<u32, KernelError> {
    let mask = pci_config::transaction(bus, device, function, |io| {
        let command = io.read(0x04, 2)?;
        io.write(0x04, 2, (command & !(COMMAND_IO_SPACE | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER)) | COMMAND_INTERRUPT_DISABLE)?;
        io.write(offset, 4, 0xFFFF_FFFF)?;
        let mask = io.read(offset, 4);
        io.write(offset, 4, original)?;
        io.write(0x04, 2, command)?;
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
                let interrupt = pci_config::read(bus, device, function, 0x3C, 4)?;
                let irq_line = interrupt & 0xFF;
                let subsystem = pci_config::read(bus, device, function, 0x2C, 4)?;
                let header_type = pci_config::read(bus, device, function, 0x0E, 1)?;
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
                    revision: class & 0xFF,
                    subsystem_vendor: subsystem & 0xFFFF,
                    subsystem_id: subsystem >> 16,
                    header_type,
                    interrupt_pin: (interrupt >> 8) & 0xFF,
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
        let pdo = guest::alloc_bytes(DeviceObject::SIZE);
        super::motherboard::initialize_pdo(pdo);
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
