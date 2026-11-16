//! A árvore de dispositivos do PnP sobre o barramento PCI interno.
//!
//! Prepara o que o PnP manager percorre (`ntos/io/pnp/tree.rs`): o PDO do
//! barramento raiz (PCI_HAL\PNP0A03\0, cujo driver é o próprio kernel) como
//! barramento da plataforma sob HTREE\ROOT\0, e os nós das funções que um
//! driver interno do kernel já serve neste boot, que ficam do kernel (sem
//! instalação nem AddDevice), como um dispositivo com driver de boot:
//! - a controladora IDE, sem `--storage=real`: o driver ATA interno serve o
//!   volume do boot e a pilha IDE do Windows não sobe;
//! - o adaptador VGA, sem `--display=basic`: o console em modo texto do
//!   kernel (`drivers/video/vga.rs`) escreve nele e o BasicDisplay.sys não
//!   sobe.
//! Com a opção correspondente, a função segue o caminho comum: instalação
//! pelos INFs da caixa, AddDevice, recursos e START. As demais funções
//! também: a ponte PCI-ISA recebe o msisadrv.sys (machine.inf), um driver
//! KMDF, e `check_kmdf_bus` confere o caminho PnP do framework.
//!
//! Com `--pnp-root=acpi` (`acpi_stack`) a raiz é a da HAL: o computador
//! (`ROOT\ACPI_HAL\0000`, `hal::pnp`) como barramento da plataforma, com o
//! acpi.sys e o pci.sys reais por baixo; as funções dos drivers internos
//! são reconhecidas pelos ids que o pci.sys relata (PCI\CC_0101 e
//! PCI\CC_0300) e ficam igualmente do kernel.

use alloc::format;
use alloc::string::String;

use crate::drivers::bus::{acpi_stack, pci};
use crate::drivers::storage::storage_stack;
use crate::drivers::video::display_stack;
use crate::ntos::inc::types::{DeviceObject, DriverExtension, DriverObject, NtStruct};
use crate::ntos::io::lifecycle;
use crate::ntos::io::pnp::{self, devnode};
use crate::rtl::KernelError;

/// A função é servida por um driver interno do kernel neste boot.
fn internally_driven(function: &pci::PciFunction) -> bool {
    let ide = function.class_code == 0x01 && function.sub_class == 0x01;
    let vga = function.class_code == 0x03 && function.sub_class == 0x00;
    (ide && !storage_stack::enabled()) || (vga && !display_stack::enabled())
}

/// Uma função relatada pelo pci.sys que um driver interno do kernel serve
/// neste boot, pelos ids de classe do pci.sys (PCI\CC_ccss).
fn internally_driven_ids(hardware_ids: &[String], compatible_ids: &[String]) -> bool {
    let has = |id: &str| hardware_ids.iter().chain(compatible_ids.iter()).any(|candidate| candidate.eq_ignore_ascii_case(id));
    (has("PCI\\CC_0101") && !storage_stack::enabled()) || (has("PCI\\CC_0300") && !display_stack::enabled())
}

/// Cria a raiz da árvore com o barramento PCI interno e marca as funções
/// dos drivers internos; com a raiz ACPI, o computador da HAL. Idempotente.
pub fn prepare() -> Result<(), KernelError> {
    if acpi_stack::enabled() {
        let computer = crate::hal::pnp::create()?;
        pnp::tree::initialize()?;
        pnp::root::add_platform_bus(computer);
        pnp::tree::mark_internal(computer);
        pnp::tree::set_internal_ids(internally_driven_ids);
        // A HAL ACPI não traduz linhas na raiz: o tradutor de interrupções
        // do acpi.sys entrega os vetores (o tradutor da raiz é a identidade).
        pnp::resources::set_root_line_translation(false);
        return Ok(());
    }
    let root_bus = pci::create_root_bus()?;
    pnp::tree::initialize()?;
    pnp::root::add_platform_bus(root_bus);
    pnp::tree::mark_internal(root_bus);
    for function in pci::devices().iter().filter(|function| function.pdo_pointer != 0 && internally_driven(function)) {
        pnp::tree::mark_internal(function.pdo_pointer);
    }
    Ok(())
}

/// A árvore de dispositivos do fim da fase 1 (o PipProcessDevNodeTree do
/// boot): o que cada pilha pedida precisa antes dela (os setores de
/// referência, o Registro e os drivers de boot da pilha de armazenamento;
/// o vídeo de boot), a raiz (`prepare`), o processamento da árvore inteira
/// uma vez e as conferências de cada pilha sobre os nós que o barramento
/// relatou.
pub fn build() {
    let storage = if storage_stack::enabled() { storage_stack::before_tree() } else { None };
    if display_stack::enabled() {
        display_stack::before_tree();
    }
    if acpi_stack::enabled() {
        debug_print!("[acpi] arvore de dispositivos com a raiz ACPI (acpi.sys e pci.sys)");
    }
    if let Err(error) = prepare() {
        debug_print!("[pnp] raiz do PnP: {}", error);
        return;
    }
    // `--trace-driver-api` rastreia as APIs que os drivers da árvore chamam.
    crate::ntos::init::exports::set_api_trace(crate::ntos::init::boot_config::trace_driver_api());
    let processed = pnp::tree::process();
    crate::ntos::init::exports::set_api_trace(false);
    if let Err(error) = processed {
        debug_print!("[pnp] arvore do PnP: {}", error);
    }
    for (path, state, problem, service) in pnp::tree::summary() {
        debug_print!("[pnp] devnode {} estado {:?} problema {:#x} servico {}", path, state, problem, service.as_deref().unwrap_or("-"));
    }
    if acpi_stack::enabled() {
        acpi_stack::check();
    }
    if let Some(reference) = storage {
        storage_stack::check(&reference);
    }
    if display_stack::enabled() {
        display_stack::check();
    }
}

/// `device` está na pilha acima de `pdo` (pela cadeia AttachedDevice). Com
/// a raiz ACPI, o filtro do acpi.sys fica entre o PDO do pci.sys e o FDO de
/// um dispositivo que o namespace descreve (_ADR).
pub fn attached_above(pdo: u64, device: u64) -> bool {
    let mut current = pdo;
    for _ in 0..32 {
        // SAFETY: DEVICE_OBJECT da pilha do PDO.
        let next = unsafe { DeviceObject::at(current) }.attached_device.get();
        if next == 0 {
            return false;
        }
        if next == device {
            return true;
        }
        current = next;
    }
    false
}

/// Faixa [início, fim) da imagem de um driver (DriverStart/DriverSize).
pub fn image_range(driver: u64) -> (u64, u64) {
    // SAFETY: DRIVER_OBJECT de um driver carregado.
    let object = unsafe { DriverObject::at(driver) };
    let start = object.driver_start.get();
    (start, start + object.driver_size.get() as u64)
}

/// A ponte PCI-ISA instalada pelo machine.inf com o msisadrv.sys, um driver
/// KMDF, pelo caminho PnP do framework: nó iniciado, FDO do \Driver\msisadrv
/// na pilha do PDO e o AddDevice do driver dentro do runtime Wdf01000.sys (o
/// do framework, que o WdfDriverCreate instala).
pub fn check_kmdf_bus() -> Result<String, String> {
    let bridge = devnode::all().into_iter().find(|node| node.service.as_deref() == Some("msisadrv")).ok_or("nenhuma ponte instalada com o msisadrv")?;
    if bridge.state != devnode::State::Started {
        return Err(format!("{}: estado {:?}, problema {:#x}", bridge.instance_path, bridge.state, bridge.problem));
    }
    let driver = lifecycle::initialized_driver("msisadrv").ok_or("\\Driver\\msisadrv ausente")?;
    let runtime = lifecycle::initialized_driver("Wdf01000").ok_or("\\Driver\\Wdf01000 ausente")?;
    let (start, end) = image_range(runtime);
    // SAFETY: DRIVER_OBJECT do msisadrv e a sua extensão.
    let add_device = unsafe { DriverExtension::at(DriverObject::at(driver).driver_extension.get()) }.add_device.get();
    if !(start..end).contains(&add_device) {
        return Err(format!("AddDevice do msisadrv fora do Wdf01000 ({add_device:#x})"));
    }
    let fdo = bridge.function_device;
    // SAFETY: o FDO do nó.
    let owner = if fdo != 0 { unsafe { DeviceObject::at(fdo) }.driver_object.get() } else { 0 };
    if fdo == 0 || owner != driver || !attached_above(bridge.pdo, fdo) {
        return Err(format!("FDO {fdo:#x}: driver {owner:#x}, fora da pilha do PDO {:#x}", bridge.pdo));
    }
    Ok(bridge.instance_path)
}
