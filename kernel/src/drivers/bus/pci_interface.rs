//! Interfaces do barramento PCI entregues no IRP_MN_QUERY_INTERFACE (o que
//! o pci.sys devolve aos drivers dos seus PDOs).
//!
//! - GUID_BUS_INTERFACE_STANDARD (versão 1, 0x40 bytes): TranslateBusAddress
//!   (identidade no PC: o barramento PCI e o processador veem os mesmos
//!   endereços de porta e memória), GetDmaAdapter (o adaptador da HAL para a
//!   DEVICE_DESCRIPTION do driver, `hal::dma`), SetBusData/GetBusData (o
//!   espaço de configuração da função para todo DataType menos o da ROM,
//!   como o pci.sys).
//! - GUID_PCI_BUS_INTERFACE_STANDARD (versão 1, 0x40 bytes): ReadConfig e
//!   WriteConfig por barramento e PCI_SLOT_NUMBER, PinToLine e LineToPin
//!   (sem efeito: o roteamento de IRQ vem do firmware).
//!
//! O Context de cada interface é o PDO da função; InterfaceReference e
//! InterfaceDereference contam as referências dele.

use alloc::collections::BTreeMap;

use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::hal::pci_native;
use crate::ntos::inc::types::extra_storage::{BusInterfaceStandard, PciBusInterfaceStandard};
use crate::ntos::inc::types::NtStruct;
use crate::ntos::init::exports::Call;
use crate::rtl::{KernelError, SpinLock};

/// GUID_BUS_INTERFACE_STANDARD {496B8280-6F25-11D0-BEAF-08002BE2092F}.
pub const GUID_BUS_INTERFACE_STANDARD: [u8; 16] = [0x80, 0x82, 0x6B, 0x49, 0x25, 0x6F, 0xD0, 0x11, 0xBE, 0xAF, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F];
/// GUID_PCI_BUS_INTERFACE_STANDARD {496B8281-6F25-11D0-BEAF-08002BE2092F}.
pub const GUID_PCI_BUS_INTERFACE_STANDARD: [u8; 16] = [0x81, 0x82, 0x6B, 0x49, 0x25, 0x6F, 0xD0, 0x11, 0xBE, 0xAF, 0x08, 0x00, 0x2B, 0xE2, 0x09, 0x2F];

/// PCIConfiguration (BUS_DATA_TYPE) da HAL e PCI_WHICHSPACE_ROM ('PciR').
const PCI_CONFIGURATION: u32 = 4;
const PCI_WHICHSPACE_ROM: u32 = 0x5269_6350;

/// Referências de interface por PDO (InterfaceReference/Dereference).
static REFERENCES: SpinLock<BTreeMap<u64, i64>> = SpinLock::new(BTreeMap::new());

/// Rotinas por ponteiro, na ordem dos slots desta faixa.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "PciReferenceInterface", handler: reference_interface },
    Routine { name: "PciDereferenceInterface", handler: dereference_interface },
    Routine { name: "PciPnpTranslateBusAddress", handler: translate_bus_address },
    Routine { name: "PciPnpGetDmaAdapter", handler: get_dma_adapter },
    Routine { name: "PciPnpWriteConfig", handler: set_bus_data },
    Routine { name: "PciPnpReadConfig", handler: get_bus_data },
    Routine { name: "PciReadConfig", handler: read_config },
    Routine { name: "PciWriteConfig", handler: write_config },
    Routine { name: "PciPinToLine", handler: pin_to_line },
    Routine { name: "PciLineToPin", handler: line_to_pin },
];

fn reference_interface(call: &Call) -> Result<u64, KernelError> {
    *REFERENCES.lock().entry(call.arg(1)).or_insert(0) += 1;
    Ok(0)
}

fn dereference_interface(call: &Call) -> Result<u64, KernelError> {
    *REFERENCES.lock().entry(call.arg(1)).or_insert(0) -= 1;
    Ok(0)
}

/// Referências vivas de interface de um PDO (autoteste).
pub fn references(pdo: u64) -> i64 {
    REFERENCES.lock().get(&pdo).copied().unwrap_or(0)
}

/// TranslateBusAddress(Context, BusAddress, Length, AddressSpace*,
/// TranslatedAddress*) -> BOOLEAN: identidade, AddressSpace inalterado.
fn translate_bus_address(call: &Call) -> Result<u64, KernelError> {
    let translated = call.arg(5);
    if translated == 0 {
        return Ok(0);
    }
    // SAFETY: PPHYSICAL_ADDRESS de saída do driver.
    unsafe { crate::ntos::inc::field::Field::<u64>::at(translated) }.set(call.arg(2));
    Ok(1)
}

/// GetDmaAdapter(Context, DeviceDescription, NumberOfMapRegisters*).
fn get_dma_adapter(call: &Call) -> Result<u64, KernelError> {
    Ok(crate::hal::dma::get_adapter(call.arg(1), call.arg(2), call.arg(3)))
}

/// Barramento e PCI_SLOT_NUMBER da função de um PDO.
fn location(pdo: u64) -> Option<(u32, u32)> {
    super::pci::function_of_pdo(pdo).map(|function| (function.bus, function.device | function.function << 5))
}

/// O espaço do DataType (o WhichSpace do pci.sys): PCI_WHICHSPACE_ROM
/// ('PciR') é a imagem da ROM de expansão, que este barramento não lê nem
/// grava (0 bytes); qualquer outro valor é o espaço de configuração. Como o
/// PciBusInterface_GetBusData/SetBusData do pci.sys 19041, um valor que não
/// é PCI_WHICHSPACE_CONFIG só vai para o Driver Verifier (VfFailDeviceNode
/// 0xF6, sem efeito com o verifier desligado) e o acesso segue na
/// configuração: o storport.sys passa o BusDataType do miniport
/// (PCIConfiguration, 4) direto à interface.
fn config_space(data_type: u32) -> bool {
    data_type != PCI_WHICHSPACE_ROM
}

/// SetBusData(Context, DataType, Buffer, Offset, Length) -> bytes.
fn set_bus_data(call: &Call) -> Result<u64, KernelError> {
    if !config_space(call.arg(2) as u32) {
        return Ok(0);
    }
    let Some((bus, slot)) = location(call.arg(1)) else { return Ok(0) };
    Ok(pci_native::set_bus_data_by_offset(PCI_CONFIGURATION, bus, slot, call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
}

/// GetBusData(Context, DataType, Buffer, Offset, Length) -> bytes.
fn get_bus_data(call: &Call) -> Result<u64, KernelError> {
    if !config_space(call.arg(2) as u32) {
        return Ok(0);
    }
    let Some((bus, slot)) = location(call.arg(1)) else { return Ok(0) };
    Ok(pci_native::get_bus_data_by_offset(PCI_CONFIGURATION, bus, slot, call.arg(3), call.arg(4) as u32, call.arg(5) as u32)? as u64)
}

/// ReadConfig(Context, BusOffset, Slot, Buffer, Offset, Length) -> bytes.
fn read_config(call: &Call) -> Result<u64, KernelError> {
    Ok(pci_native::get_bus_data_by_offset(PCI_CONFIGURATION, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32)? as u64)
}

/// WriteConfig(Context, BusOffset, Slot, Buffer, Offset, Length) -> bytes.
fn write_config(call: &Call) -> Result<u64, KernelError> {
    Ok(pci_native::set_bus_data_by_offset(PCI_CONFIGURATION, call.arg(2) as u32, call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6) as u32)? as u64)
}

fn pin_to_line(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

fn line_to_pin(_: &Call) -> Result<u64, KernelError> {
    Ok(0)
}

/// Preenche a interface pedida no buffer do driver (já zerado e com Size e
/// Version pelo PnP). Devolve false para GUID ou tamanho que o barramento
/// não atende.
pub fn fill(pdo: u64, guid: &[u8; 16], size: u16, version: u16, interface: u64) -> Result<bool, KernelError> {
    if *guid == GUID_BUS_INTERFACE_STANDARD && size as u64 >= BusInterfaceStandard::SIZE && version >= 1 {
        // SAFETY: buffer INTERFACE do driver com pelo menos 0x40 bytes.
        let bus = unsafe { BusInterfaceStandard::at(interface) };
        bus.interface.size.set(BusInterfaceStandard::SIZE as u16);
        bus.interface.version.set(1);
        bus.interface.context.set(pdo);
        bus.interface.interface_reference.set(routine_stubs::address("PciReferenceInterface")?);
        bus.interface.interface_dereference.set(routine_stubs::address("PciDereferenceInterface")?);
        bus.translate_bus_address.set(routine_stubs::address("PciPnpTranslateBusAddress")?);
        bus.get_dma_adapter.set(routine_stubs::address("PciPnpGetDmaAdapter")?);
        bus.set_bus_data.set(routine_stubs::address("PciPnpWriteConfig")?);
        bus.get_bus_data.set(routine_stubs::address("PciPnpReadConfig")?);
        *REFERENCES.lock().entry(pdo).or_insert(0) += 1;
        return Ok(true);
    }
    if *guid == GUID_PCI_BUS_INTERFACE_STANDARD && size as u64 >= PciBusInterfaceStandard::SIZE && version >= 1 {
        // SAFETY: buffer INTERFACE do driver com pelo menos 0x40 bytes.
        let pci = unsafe { PciBusInterfaceStandard::at(interface) };
        pci.interface.size.set(PciBusInterfaceStandard::SIZE as u16);
        pci.interface.version.set(1);
        pci.interface.context.set(pdo);
        pci.interface.interface_reference.set(routine_stubs::address("PciReferenceInterface")?);
        pci.interface.interface_dereference.set(routine_stubs::address("PciDereferenceInterface")?);
        pci.read_config.set(routine_stubs::address("PciReadConfig")?);
        pci.write_config.set(routine_stubs::address("PciWriteConfig")?);
        pci.pin_to_line.set(routine_stubs::address("PciPinToLine")?);
        pci.line_to_pin.set(routine_stubs::address("PciLineToPin")?);
        *REFERENCES.lock().entry(pdo).or_insert(0) += 1;
        return Ok(true);
    }
    Ok(false)
}
