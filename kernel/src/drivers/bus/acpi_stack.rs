//! A raiz ACPI da árvore de dispositivos (o padrão; `--pnp-root=internal`
//! volta ao barramento PCI interno).
//!
//! A árvore do PnP é a do Windows num PC ACPI: sob
//! HTREE\ROOT\0 o computador que a HAL relata (`ROOT\ACPI_HAL\0000`) e, sob
//! ele, o dispositivo ACPI raiz da HAL (`ACPI_HAL\PNP0C08\0`, `hal::pnp`),
//! instalado pelo acpi.inf com o acpi.sys real. O DriverEntry do acpi.sys
//! troca a tabela de energia com a HAL (HalInitPowerManagement) e lê as
//! tabelas do firmware pela HalAcpiDispatchTable (`hal::acpi_pm`); o START
//! carrega a DSDT no interpretador AML dele e as BusRelations da raiz são
//! os dispositivos do namespace (PNP0A03, os processadores, os botões...).
//! O nó PNP0A03 recebe o pci.sys real pelo pci.inf, que enumera as funções
//! PCI ele mesmo. O barramento PCI interno do kernel (`drivers/bus/pci.rs`)
//! não entra na árvore.
//!
//! As funções que um driver interno do kernel serve neste boot (a
//! controladora IDE sem `--storage=real`, o adaptador VGA sem
//! `--display=basic`) ficam com nó do kernel também quando é o pci.sys que
//! as enumera (`device_tree`).
//!
//! Marcadores: `ACPI_ROOT_OK` quando o acpi.sys iniciou a raiz e relatou os
//! dispositivos do namespace; `PCI_ROOT_OK` quando o pci.sys iniciou o
//! barramento e relatou as funções.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::inc::types::{DeviceObject, NtStruct};
use crate::ntos::io::lifecycle;
use crate::ntos::io::pnp::devnode;

/// A raiz da árvore é o acpi.sys sobre a HAL, salvo com
/// `--pnp-root=internal` (o barramento PCI interno do kernel).
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::acpi_root()
}

/// O nó com este serviço iniciado, com o FDO do driver sobre o PDO, e os
/// DeviceIDs dos filhos.
fn started_bus(service: &str, driver_name: &str) -> Result<(devnode::DeviceNode, Vec<String>), String> {
    let node = devnode::all().into_iter().find(|node| node.service.as_deref() == Some(service)).ok_or_else(|| format!("nenhum no instalado com o {service}"))?;
    if node.state != devnode::State::Started {
        return Err(format!("{}: estado {:?}, problema {:#x}", node.instance_path, node.state, node.problem));
    }
    let driver = lifecycle::initialized_driver(driver_name).ok_or_else(|| format!("\\Driver\\{driver_name} ausente"))?;
    let fdo = node.function_device;
    // SAFETY: o FDO do nó.
    let owner = if fdo != 0 { unsafe { DeviceObject::at(fdo) }.driver_object.get() } else { 0 };
    if fdo == 0 || owner != driver {
        return Err(format!("{}: FDO {fdo:#x} do driver {owner:#x}", node.instance_path));
    }
    let children: Vec<String> = node.children.iter().filter_map(|&child| devnode::get(child)).map(|child| child.device_id).collect();
    Ok((node, children))
}

/// A raiz ACPI: o acpi.sys iniciado no ACPI_HAL\PNP0C08 e os dispositivos
/// do namespace relatados, entre eles o barramento PCI (ACPI\PNP0A03).
fn check_acpi_root() -> Result<String, String> {
    let (node, children) = started_bus("ACPI", "ACPI")?;
    if !node.instance_path.eq_ignore_ascii_case("ACPI_HAL\\PNP0C08\\0") {
        return Err(format!("acpi.sys em {}", node.instance_path));
    }
    if !children.iter().any(|id| id.eq_ignore_ascii_case("ACPI\\PNP0A03")) {
        return Err(format!("sem ACPI\\PNP0A03 entre os filhos {children:?}"));
    }
    Ok(format!("{}: {} dispositivo(s) do namespace {:?}", node.instance_path, children.len(), children))
}

/// O barramento PCI: o pci.sys iniciado no ACPI\PNP0A03 e as funções
/// relatadas por ele (PCI\VEN_...). Os objetos do namespace sob o PCI0 que
/// não são funções PCI (os PNP0A06 de recursos de hotplug, o fw_cfg) o
/// acpi.sys acrescenta às BusRelations do barramento, como no Windows.
fn check_pci_root() -> Result<String, String> {
    let (node, children) = started_bus("pci", "pci")?;
    if !node.device_id.eq_ignore_ascii_case("ACPI\\PNP0A03") {
        return Err(format!("pci.sys em {}", node.instance_path));
    }
    let functions: Vec<&String> = children.iter().filter(|id| id.starts_with("PCI\\VEN_")).collect();
    if functions.is_empty() {
        return Err(format!("{}: sem funcoes PCI entre {children:?}", node.instance_path));
    }
    Ok(format!("{}: {} funcao(oes) PCI {:?}, {} filho(s) no total", node.instance_path, functions.len(), functions, children.len()))
}

/// Confere os marcadores da raiz ACPI na árvore montada
/// (`device_tree::build`).
pub fn check() {
    match check_acpi_root() {
        Ok(summary) => {
            debug_print!("[acpi] {}", summary);
            debug_print!("ACPI_ROOT_OK");
        }
        Err(error) => debug_print!("[acpi] raiz ACPI incompleta: {}", error),
    }
    match check_pci_root() {
        Ok(summary) => {
            debug_print!("[acpi] {}", summary);
            debug_print!("PCI_ROOT_OK");
        }
        Err(error) => debug_print!("[acpi] barramento PCI incompleto: {}", error),
    }
}
