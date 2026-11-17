//! As linhas de modelo dos INFs da caixa para a placa de rede da máquina com
//! `--net` (a Intel PRO/1000 MT, e1000, PCI\VEN_8086&DEV_100E) e o que a
//! instalação de um adaptador da classe Net grava:
//! - nete1g3e.inf `[E100E]` (PCI\VEN_8086&DEV_100E, a linha genérica que
//!   casa com o subsistema 1AF4:1100 do QEMU): o serviço E1G60 (o
//!   E1G6032E.sys, grupo NDIS) e o AddReg da seção na chave do driver
//!   (`Kodiak.reg`, `Copper.reg`, `Advanced.reg`, `TcpSeg.reg` e
//!   `82540EM.reg`: os parâmetros fixos do miniport e a árvore `Ndi`). O
//!   `[common.EventLog]` do AddService vai para o log de eventos, que o
//!   OpenNT não tem;
//! - as diretivas de rede da seção (`*IfType`, `*MediaType`,
//!   `*PhysicalMediaType`, `Characteristics` e `BusType`), que o instalador
//!   da classe Net grava na chave do driver junto com o NetCfgInstanceId, o
//!   ComponentId, o DeviceInstanceID e a `Linkage` do adaptador
//!   (`configure_adapter`);
//! - o objeto da interface e as ligações dela no banco da configuração de
//!   rede (`Control\NetworkSetup2`) vêm da instalação (`cm/network_setup.rs`),
//!   como num Windows em que o adaptador já foi instalado: o NDIS cria o
//!   bloco da interface a partir dele quando inicia, antes do AddDevice.
//!
//! As linhas só entram na seleção com `--net`: sem a opção a placa padrão do
//! QEMU fica sem driver, como antes.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::install::{self, ClassSpec, InfDriver, RegData, RegValue, ServiceSpec, CONTROL_SET};
use crate::ntos::cm::network_setup::{self, NET_LUID_INDEX};
use crate::rtl::KernelError;

/// nete1g3e.inf `[Version]` (a classe Net do c_net.inf).
pub const CLASS_NET: ClassSpec = ClassSpec { guid: "{4d36e972-e325-11ce-bfc1-08002be10318}", name: "Net", upper_filters: &[], lower_filters: &[] };

/// nete1g3e.inf `[e1000_NTX64.Service]` (ServiceBinary `%12%\E1G6032E.sys`,
/// StartType 3, ErrorControl 1, LoadOrderGroup NDIS).
const SERVICE_E1G60: ServiceSpec = ServiceSpec {
    name: "E1G60",
    display_name: Some("@nete1g3e.inf,%e1000.Service.DispName%;Intel(R) PRO/1000 NDIS 6 Adapter Driver"),
    start: 3,
    error_control: 1,
    binary: "E1G6032E.sys",
    group: Some("NDIS"),
    owner: "nete1g3e.inf",
    values: &[],
};

/// nete1g3e.inf `[E100E]`: o AddReg da seção (HKR = a chave do driver).
const E100E_DRIVER: &[RegValue] = &[
    // [Kodiak.reg]
    RegValue { subkey: "Ndi\\Interfaces", name: "UpperRange", data: RegData::Text("ndis5") },
    RegValue { subkey: "Ndi\\Interfaces", name: "LowerRange", data: RegData::Text("ethernet") },
    RegValue { subkey: "Ndi", name: "Service", data: RegData::Text("E1G60") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl", name: "ParamDesc", data: RegData::Text("Flow Control") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl", name: "default", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl\\Enum", name: "1", data: RegData::Text("Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl\\Enum", name: "2", data: RegData::Text("Rx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl\\Enum", name: "3", data: RegData::Text("Rx & Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*FlowControl", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "ParamDesc", data: RegData::Text("Transmit Buffers") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "default", data: RegData::Text("512") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "min", data: RegData::Text("80") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "max", data: RegData::Text("2048") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "step", data: RegData::Text("8") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "Base", data: RegData::Text("10") },
    RegValue { subkey: "Ndi\\params\\*TransmitBuffers", name: "type", data: RegData::Text("int") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "ParamDesc", data: RegData::Text("Receive Buffers") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "default", data: RegData::Text("256") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "min", data: RegData::Text("80") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "max", data: RegData::Text("2048") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "step", data: RegData::Text("8") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "Base", data: RegData::Text("10") },
    RegValue { subkey: "Ndi\\params\\*ReceiveBuffers", name: "type", data: RegData::Text("int") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4", name: "ParamDesc", data: RegData::Text("TCP Checksum Offload (IPv4)") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4", name: "default", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4\\Enum", name: "1", data: RegData::Text("Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4\\Enum", name: "2", data: RegData::Text("Rx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4\\Enum", name: "3", data: RegData::Text("Rx & Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*TCPChecksumOffloadIPv4", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4", name: "ParamDesc", data: RegData::Text("UDP Checksum Offload (IPv4)") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4", name: "default", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4\\Enum", name: "1", data: RegData::Text("Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4\\Enum", name: "2", data: RegData::Text("Rx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4\\Enum", name: "3", data: RegData::Text("Rx & Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*UDPChecksumOffloadIPv4", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4", name: "ParamDesc", data: RegData::Text("IPv4 Checksum Offload") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4", name: "default", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4\\Enum", name: "1", data: RegData::Text("Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4\\Enum", name: "2", data: RegData::Text("Rx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4\\Enum", name: "3", data: RegData::Text("Rx & Tx Enabled") },
    RegValue { subkey: "Ndi\\Params\\*IPChecksumOffloadIPv4", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "ParamDesc", data: RegData::Text("Number of Coalesce Buffers") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "default", data: RegData::Text("128") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "min", data: RegData::Text("16") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "max", data: RegData::Text("768") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "step", data: RegData::Text("1") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "Base", data: RegData::Text("10") },
    RegValue { subkey: "Ndi\\params\\NumCoalesceBuffers", name: "type", data: RegData::Text("int") },
    RegValue { subkey: "Ndi\\params\\NetworkAddress", name: "ParamDesc", data: RegData::Text("Locally Administered Address") },
    RegValue { subkey: "Ndi\\params\\NetworkAddress", name: "Default", data: RegData::Text("") },
    RegValue { subkey: "Ndi\\params\\NetworkAddress", name: "type", data: RegData::Text("edit") },
    RegValue { subkey: "NDI\\params\\NetworkAddress", name: "LimitText", data: RegData::Text("12") },
    RegValue { subkey: "NDI\\params\\NetworkAddress", name: "UpperCase", data: RegData::Text("1") },
    RegValue { subkey: "NDI\\params\\NetworkAddress", name: "optional", data: RegData::Text("1") },
    RegValue { subkey: "", name: "PciScanMethod", data: RegData::Text("3") },
    RegValue { subkey: "", name: "TxIntDelay", data: RegData::Text("28") },
    RegValue { subkey: "", name: "MWIEnable", data: RegData::Text("1") },
    RegValue { subkey: "", name: "CustomMessages", data: RegData::Text("0") },
    RegValue { subkey: "", name: "DmaFairness", data: RegData::Text("0") },
    RegValue { subkey: "", name: "MulticastFilterType", data: RegData::Text("0") },
    RegValue { subkey: "", name: "VlanFiltering", data: RegData::Text("1") },
    RegValue { subkey: "", name: "QtagSwControlled", data: RegData::Text("0") },
    RegValue { subkey: "", name: "TransmitMode", data: RegData::Text("0") },
    RegValue { subkey: "", name: "MaxTxDpcLoopCount", data: RegData::Text("2") },
    RegValue { subkey: "", name: "MaxDpcLoopCount", data: RegData::Text("2") },
    RegValue { subkey: "", name: "MaxNumReceivePackets", data: RegData::Text("64") },
    // [Copper.reg]
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex", name: "ParamDesc", data: RegData::Text("Link Speed & Duplex") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex", name: "default", data: RegData::Text("0") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "0", data: RegData::Text("Auto Negotiation") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "1", data: RegData::Text("10 Mbps Half Duplex") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "2", data: RegData::Text("10 Mbps Full Duplex") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "3", data: RegData::Text("100 Mbps Half Duplex") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "4", data: RegData::Text("100 Mbps Full Duplex") },
    RegValue { subkey: "Ndi\\params\\*SpeedDuplex\\enum", name: "6", data: RegData::Text("1000 Mbps Full Duplex") },
    RegValue { subkey: "PROSetNdi\\NdiExt\\Params\\*SpeedDuplex", name: "ExposeLevel", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\AdaptiveIFS", name: "ParamDesc", data: RegData::Text("Adaptive Inter-Frame Spacing") },
    RegValue { subkey: "Ndi\\Params\\AdaptiveIFS", name: "default", data: RegData::Text("1") },
    RegValue { subkey: "Ndi\\Params\\AdaptiveIFS", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\Params\\AdaptiveIFS\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\AdaptiveIFS\\Enum", name: "1", data: RegData::Text("Enabled") },
    // [Advanced.reg]
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag", name: "ParamDesc", data: RegData::Text("Priority & VLAN") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag", name: "default", data: RegData::Text("3") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag\\Enum", name: "0", data: RegData::Text("Priority & VLAN Disabled") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag\\Enum", name: "1", data: RegData::Text("Priority Enabled") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag\\Enum", name: "2", data: RegData::Text("VLAN Enabled") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag\\Enum", name: "3", data: RegData::Text("Priority & VLAN Enabled") },
    RegValue { subkey: "Ndi\\Params\\*PriorityVLANTag", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket", name: "ParamDesc", data: RegData::Text("Jumbo Packet") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket", name: "default", data: RegData::Text("1514") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket\\Enum", name: "1514", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket\\Enum", name: "4088", data: RegData::Text("4088 Bytes") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket\\Enum", name: "9014", data: RegData::Text("9014 Bytes (Alteon)") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket\\Enum", name: "16128", data: RegData::Text("16128 Bytes") },
    RegValue { subkey: "Ndi\\Params\\*JumboPacket", name: "type", data: RegData::Text("enum") },
    // [TcpSeg.reg]
    RegValue { subkey: "Ndi\\Params\\*LsoV1IPv4", name: "ParamDesc", data: RegData::Text("Large Send Offload (IPv4)") },
    RegValue { subkey: "Ndi\\Params\\*LsoV1IPv4", name: "default", data: RegData::Text("1") },
    RegValue { subkey: "Ndi\\Params\\*LsoV1IPv4\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*LsoV1IPv4\\Enum", name: "1", data: RegData::Text("Enabled") },
    RegValue { subkey: "Ndi\\Params\\*LsoV1IPv4", name: "type", data: RegData::Text("enum") },
    // [82540EM.reg]
    RegValue { subkey: "Ndi\\Params\\ITR", name: "ParamDesc", data: RegData::Text("Interrupt Moderation Rate") },
    RegValue { subkey: "Ndi\\Params\\ITR", name: "default", data: RegData::Text("65535") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "65535", data: RegData::Text("Adaptive") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "3600", data: RegData::Text("Extreme") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "2000", data: RegData::Text("High") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "950", data: RegData::Text("Medium") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "400", data: RegData::Text("Low") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "200", data: RegData::Text("Minimal") },
    RegValue { subkey: "Ndi\\Params\\ITR\\Enum", name: "0", data: RegData::Text("Off") },
    RegValue { subkey: "Ndi\\Params\\ITR", name: "type", data: RegData::Text("enum") },
    RegValue { subkey: "", name: "ITR", data: RegData::Text("65535") },
    RegValue { subkey: "Ndi\\Params\\*InterruptModeration", name: "ParamDesc", data: RegData::Text("Interrupt Moderation") },
    RegValue { subkey: "Ndi\\Params\\*InterruptModeration", name: "default", data: RegData::Text("1") },
    RegValue { subkey: "Ndi\\Params\\*InterruptModeration\\Enum", name: "0", data: RegData::Text("Disabled") },
    RegValue { subkey: "Ndi\\Params\\*InterruptModeration\\Enum", name: "1", data: RegData::Text("Enabled") },
    RegValue { subkey: "Ndi\\Params\\*InterruptModeration", name: "type", data: RegData::Text("enum") },
];

/// As diretivas de rede de uma seção de instalação da classe Net, que o
/// instalador da classe grava na chave do driver.
pub struct NetDirectives {
    pub if_type: u32,
    pub media_type: u32,
    pub physical_media_type: u32,
    pub characteristics: u32,
    pub bus_type: &'static str,
}

/// nete1g3e.inf `[E100E]`: IF_TYPE_ETHERNET_CSMACD, NdisMedium802_3,
/// NdisPhysicalMedium802_3, NCF_HAS_UI | NCF_PHYSICAL e o barramento PCI.
const E100E_DIRECTIVES: NetDirectives = NetDirectives { if_type: 6, media_type: 0, physical_media_type: 14, characteristics: 0x84, bus_type: "5" };

/// As linhas de modelo.
pub const NET_DRIVERS: &[InfDriver] = &[InfDriver {
    inf: "nete1g3e.inf",
    section: "E100E",
    id: "PCI\\VEN_8086&DEV_100E",
    description_key: "E100EGEN.DeviceDesc",
    description: "Intel(R) PRO/1000 MT Network Connection",
    manufacturer_key: "Intel",
    manufacturer: "Intel",
    provider: "Microsoft",
    driver_version: "8.4.13.0",
    service: Some(&SERVICE_E1G60),
    class: &CLASS_NET,
    driver_values: E100E_DRIVER,
    device_values: &[],
    exclude_ids: &[],
}];

/// As diretivas de rede da seção de uma linha.
fn directives(driver: &InfDriver) -> Option<&'static NetDirectives> {
    (driver.inf == "nete1g3e.inf" && driver.section == "E100E").then_some(&E100E_DIRECTIVES)
}

/// As linhas que a seleção considera neste boot.
pub fn candidates() -> &'static [InfDriver] {
    if crate::ntos::init::boot_config::network() {
        NET_DRIVERS
    } else {
        &[]
    }
}

/// O NetCfgInstanceId de um adaptador novo: o da instalação para o
/// primeiro adaptador da classe (os seguintes não estão na máquina).
fn instance_id() -> Result<&'static str, KernelError> {
    let class = format!("{CONTROL_SET}\\Control\\Class\\{}", CLASS_NET.guid);
    let used = crate::ntos::cm::registry::list_keys(&class).iter().any(|key| install::read_text(&format!("{class}\\{key}"), "NetCfgInstanceId").is_some_and(|id| id.eq_ignore_ascii_case(network_setup::ADAPTER_INSTANCE_ID)));
    if used {
        return Err(KernelError::new("um segundo adaptador da classe Net nao tem NetCfgInstanceId na instalacao"));
    }
    Ok(network_setup::ADAPTER_INSTANCE_ID)
}

/// O instalador da classe Net, depois da instalação comum do dispositivo:
/// as diretivas da seção, o NetCfgInstanceId e o NetLuidIndex da interface
/// da instalação (`cm/network_setup.rs`), o ComponentId (o id da linha que
/// casou), o DeviceInstanceID e a `Linkage` na chave do driver (`software`,
/// Control\Class\{guid}\NNNN).
pub fn configure_adapter(instance_path: &str, software: &str, driver: &InfDriver) -> Result<(), KernelError> {
    let Some(directives) = directives(driver) else { return Ok(()) };
    let guid = instance_id()?;
    install::write_dword(software, "NetLuidIndex", NET_LUID_INDEX)?;
    install::write_dword(software, "*IfType", directives.if_type)?;
    install::write_dword(software, "*MediaType", directives.media_type)?;
    install::write_dword(software, "*PhysicalMediaType", directives.physical_media_type)?;
    install::write_dword(software, "Characteristics", directives.characteristics)?;
    install::write_text(software, "BusType", directives.bus_type)?;
    install::write_text(software, "ComponentId", driver.id)?;
    install::write_text(software, "DeviceInstanceID", instance_path)?;
    install::write_text(software, "NetCfgInstanceId", guid)?;
    let linkage = format!("{software}\\Linkage");
    let upper: Vec<String> = network_setup::PROTOCOLS.iter().map(|(name, _)| String::from(*name)).collect();
    install::write_multi(&linkage, "RootDevice", &[String::from(guid)])?;
    install::write_multi(&linkage, "Export", &[format!("\\Device\\{guid}")])?;
    install::write_multi(&linkage, "UpperBind", &upper)
}
