//! O banco da configuração de rede da instalação (`Control\NetworkSetup2`)
//! e a configuração IPv4 persistente do adaptador, na hive SYSTEM.
//!
//! No Windows 10 o ndis.sys lê as ligações entre adaptadores e protocolos
//! desse banco, que o serviço de configuração de rede mantém: as ligações
//! de cada adaptador em `Interfaces\{NetCfgInstanceId}\Kernel` (o
//! `ProtocolList`, lido pelo Ndis::BindStack::ReadV2InterfaceBindings) e,
//! para cada protocolo citado, o objeto do protocolo: o valor do nome em
//! `Protocols\Lookup` (REG_BINARY de 16 bytes, o GUID do objeto) e a chave
//! `Protocols\{GUID}\Properties` com as propriedades dele
//! (ndisBindReadProtocolDriverFromV3Registry). Um protocolo sem objeto não
//! recebe ligação. A propriedade que o ndis.sys lê do objeto do TCP/IP (o
//! NoStartAtBoot do protocolo) é implícita (a ausência vale falso), então a
//! chave fica vazia. Cada propriedade é a subchave `{GUID}\PPPP` da chave
//! `Properties` com o valor padrão do tipo 0xFFFF0000 | DEVPROP_TYPE. O
//! objeto do adaptador (`Interfaces\{NetCfgInstanceId}\Properties`) também
//! está aqui, como num Windows em que a placa já foi instalada: o ndis.sys
//! cria os blocos das interfaces a partir desses objetos quando inicia
//! (ndisIfInitializePhase2) e o AddDevice do miniport falha
//! (0xC00002F0) se a interface do NetCfgInstanceId não existe.
//!
//! Os GUIDs dos objetos, o NetCfgInstanceId e o NetLuidIndex do adaptador
//! são os desta instalação: o adaptador é o primeiro da classe Net, a placa
//! e1000 da máquina com `--net`.
//!
//! A configuração IPv4 estática do adaptador (10.0.2.15/24 com o gateway
//! 10.0.2.2, a rede de modo usuário do QEMU) fica onde o netio.sys guarda o
//! estado persistente do NSI e onde o tcpip.sys a lê quando a interface
//! sobe (Ipv4pAddressInterface, pelo NsiAllocateAndGetTable do repositório
//! persistente): `Control\Nsi\{ModuleId do IPv4}\{objeto}`, um valor por
//! entrada, com o nome igual aos bytes da chave em hexadecimal minúsculo
//! (NsipConvertKeyToKeyValueName) e o dado REG_BINARY com os parâmetros
//! graváveis seguidos da máscara de campos presentes, 0xFF por byte, como o
//! NsipWritePersistentData grava uma entrada criada. Os parâmetros seguem o
//! que o iphlpapi.dll monta para o NSI a partir das estruturas públicas
//! MIB_UNICASTIPADDRESS_ROW e MIB_IPFORWARD_ROW2: o endereço (objeto 10,
//! chave NET_LUID + IN_ADDR, 16 bytes) e a rota padrão (objeto 16, chave de
//! 48 bytes com o compartimento 0 do repositório persistente). O tcpip.sys
//! espelha o endereço em `Services\Tcpip\Parameters\Interfaces\{guid}`, que
//! também entra aqui como a instalação o deixa.
//!
//! Dados puros: o `xtask` inclui este arquivo por `#[path]` (`cm/seed.rs`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::seed::{SeedKey, REG_BINARY, REG_SZ};

/// O NetCfgInstanceId do adaptador e1000 (o primeiro da classe Net).
pub const ADAPTER_INSTANCE_ID: &str = "{0BB5C712-33A7-4FD3-8E99-CA243E03142C}";

/// O NetLuidIndex do adaptador: o primeiro índice que o NDIS dá a uma
/// interface de hardware (os índices começam em 0x8000).
pub const NET_LUID_INDEX: u32 = 0x8000;

/// IF_TYPE_ETHERNET_CSMACD, o `*IfType` da seção do nete1g3e.inf.
pub const ADAPTER_IF_TYPE: u32 = 6;

/// O NET_LUID de uma interface: IfType nos bits 48..63 e o NetLuidIndex nos
/// bits 24..47.
pub const fn net_luid(if_type: u32, index: u32) -> u64 {
    (if_type as u64) << 48 | (index as u64) << 24
}

/// Os protocolos que a instalação liga a um adaptador Ethernet (o
/// `ProtocolList` do adaptador): os dois protocolos que o tcpip.sys
/// registra no NDIS, cada um com o GUID do seu objeto.
pub const PROTOCOLS: &[(&str, &str)] = &[("TCPIP", "{4A7A8ED2-7AC8-4374-9624-E62C2276FBBB}"), ("TCPIP6", "{FC2BD16C-9026-4E98-A062-EDC2507B63F6}")];

/// O endereço IPv4 estático do adaptador, o prefixo e o gateway.
pub const IPV4_ADDRESS: [u8; 4] = [10, 0, 2, 15];
pub const IPV4_PREFIX_LENGTH: u8 = 24;
pub const IPV4_GATEWAY: [u8; 4] = [10, 0, 2, 2];

const NETWORK_SETUP: &str = "CurrentControlSet\\Control\\NetworkSetup2";
/// NPI_MS_IPV4_MODULEID, o módulo do IPv4 no NSI.
const NSI_IPV4: &str = "CurrentControlSet\\Control\\Nsi\\{eb004a00-9b1a-11d4-9123-0050047759bc}";
/// Os objetos do módulo IPv4: os endereços unicast e as rotas.
const NSI_UNICAST_ADDRESS_OBJECT: u32 = 10;
const NSI_ROUTE_OBJECT: u32 = 16;

/// Os 16 bytes de um GUID `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` na ordem
/// da memória (os três primeiros campos little-endian).
pub fn guid_bytes(text: &str) -> [u8; 16] {
    let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).map(|digit| (digit as char).to_digit(16).unwrap_or(0) as u8).collect();
    let mut raw = [0u8; 16];
    for (index, pair) in digits.chunks(2).take(16).enumerate() {
        raw[index] = pair[0] << 4 | pair.get(1).copied().unwrap_or(0);
    }
    let mut bytes = raw;
    bytes[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);
    bytes[4..6].copy_from_slice(&[raw[5], raw[4]]);
    bytes[6..8].copy_from_slice(&[raw[7], raw[6]]);
    bytes
}

/// O nome do valor de uma entrada do repositório persistente do NSI.
fn nsi_value_name(key: &[u8]) -> String {
    key.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// O dado de uma entrada criada: os parâmetros e a máscara toda presente.
fn nsi_value_data(parameters: &[u8]) -> Vec<u8> {
    let mut data = parameters.to_vec();
    data.extend(core::iter::repeat_n(0xFF, parameters.len()));
    data
}

/// O endereço unicast do adaptador (objeto 10): a chave {InterfaceLuid,
/// Address} e os parâmetros graváveis de 0x1C bytes (PreferredLifetime,
/// ValidLifetime infinitos, PrefixOrigin e SuffixOrigin manuais,
/// OnLinkPrefixLength, SkipAsSource e os campos que o iphlpapi deixa
/// inalterados).
fn unicast_address_entry() -> (String, Vec<u8>) {
    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&net_luid(ADAPTER_IF_TYPE, NET_LUID_INDEX).to_le_bytes());
    key.extend_from_slice(&IPV4_ADDRESS);
    key.extend_from_slice(&[0; 4]);
    let mut parameters = [0u8; 0x1C];
    parameters[0x00..0x04].copy_from_slice(&u32::MAX.to_le_bytes());
    parameters[0x04..0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    parameters[0x08..0x0C].copy_from_slice(&1u32.to_le_bytes());
    parameters[0x0C..0x10].copy_from_slice(&1u32.to_le_bytes());
    parameters[0x10] = IPV4_PREFIX_LENGTH;
    parameters[0x14..0x18].copy_from_slice(&u32::MAX.to_le_bytes());
    parameters[0x18] = 0xFF;
    parameters[0x19] = 0xFF;
    (nsi_value_name(&key), nsi_value_data(&parameters))
}

/// A rota padrão (objeto 16): a chave {CompartmentId 0, destino 0.0.0.0/0,
/// origem 0.0.0.0/0, InterfaceLuid duas vezes, NextHop} e os parâmetros
/// graváveis de 0x20 bytes (SitePrefixLength, ValidLifetime e
/// PreferredLifetime infinitos, Metric 0, Protocol MIB_IPPROTO_NETMGMT e os
/// campos inalterados).
fn default_route_entry() -> (String, Vec<u8>) {
    let luid = net_luid(ADAPTER_IF_TYPE, NET_LUID_INDEX).to_le_bytes();
    let mut key = [0u8; 0x30];
    key[0x18..0x20].copy_from_slice(&luid);
    key[0x20..0x28].copy_from_slice(&luid);
    key[0x28..0x2C].copy_from_slice(&IPV4_GATEWAY);
    let mut parameters = [0u8; 0x20];
    parameters[0x01..0x04].copy_from_slice(&[0xFF; 3]);
    parameters[0x04..0x08].copy_from_slice(&u32::MAX.to_le_bytes());
    parameters[0x08..0x0C].copy_from_slice(&u32::MAX.to_le_bytes());
    parameters[0x10..0x14].copy_from_slice(&3u32.to_le_bytes());
    parameters[0x18..0x20].copy_from_slice(&[0xFF; 8]);
    (nsi_value_name(&key), nsi_value_data(&parameters))
}

/// Os tipos das propriedades do banco: o valor padrão da subchave da
/// propriedade tem o tipo 0xFFFF0000 | DEVPROP_TYPE (o que o
/// NetSetupPropertyBag do ndis.sys confere).
const PROPERTY_UINT32: u32 = 0xFFFF_0007;
const PROPERTY_UINT64: u32 = 0xFFFF_0009;
const PROPERTY_BOOLEAN: u32 = 0xFFFF_0011;
const PROPERTY_STRING: u32 = 0xFFFF_0012;

/// As famílias de chaves de propriedade ({a111f1xx-5923-47c0-9a68-
/// d0bafb577901}, as NETSETUPPKEY_* do serviço de configuração): a da
/// interface e a dos dados do INF.
const PROPERTIES_INTERFACE: u32 = 0xA111_F1F4;
const PROPERTIES_INF: u32 = 0xA111_F200;

/// O que o objeto da interface guarda do adaptador: a descrição e o alias,
/// o tipo de mídia (NdisMedium802_3 e NdisPhysicalMedium802_3), as
/// Characteristics (NCF_HAS_UI | NCF_PHYSICAL), o id que casou e a seção do
/// INF.
const ADAPTER_DESCRIPTION: &str = "Intel(R) PRO/1000 MT Network Connection";
const ADAPTER_ALIAS: &str = "Ethernet";
const ADAPTER_MEDIA_TYPE: u32 = 0;
const ADAPTER_PHYSICAL_MEDIA_TYPE: u32 = 14;
const ADAPTER_CHARACTERISTICS: u32 = 0x84;
const ADAPTER_MATCHING_ID: &str = "pci\\ven_8086&dev_100e";
const ADAPTER_INF: (&str, &str) = ("nete1g3e.inf", "E100E");

/// Uma propriedade: a subchave `{família}\PPPP` (GUID em minúsculas, PID com
/// 4 dígitos, como o GetPkeyName do ndis.sys monta) com o valor padrão.
fn property(object: &str, family: u32, pid: u32, property_type: u32, data: Vec<u8>) -> SeedKey {
    let mut key = SeedKey::new(&format!("{object}\\Properties\\{{{family:08x}-5923-47c0-9a68-d0bafb577901}}\\{pid:04x}"));
    key.value("", property_type, data);
    key
}

fn wide(text: &str) -> Vec<u8> {
    super::seed::wide(text)
}

/// O objeto da interface do adaptador (`Interfaces\{NetCfgInstanceId}`):
/// as propriedades que o ndis.sys lê ao criar o bloco da interface na
/// partida (Ndis::BindRegistry::ReadNetworkInterfaceV2: IfAlias, IfDescr,
/// IfType, NetLuid, MediaType, PhysicalMediaType, IsPhysical) e no AddDevice
/// (ndisIfReadInterfaceAddDeviceParameters: NetLuid, PhysicalMediaType e as
/// Characteristics do INF), mais o NetLuidIndex, o id que casou e o INF, e
/// as ligações em `Kernel` (o ProtocolList).
fn interface_keys() -> Vec<SeedKey> {
    let object = format!("{NETWORK_SETUP}\\Interfaces\\{ADAPTER_INSTANCE_ID}");
    let dword = |value: u32| value.to_le_bytes().to_vec();
    let protocols: Vec<&str> = PROTOCOLS.iter().map(|(name, _)| *name).collect();
    let mut kernel = SeedKey::new(&format!("{object}\\Kernel"));
    kernel.strings("ProtocolList", &protocols);
    alloc::vec![
        property(&object, PROPERTIES_INTERFACE, 0x04, PROPERTY_UINT64, net_luid(ADAPTER_IF_TYPE, NET_LUID_INDEX).to_le_bytes().to_vec()),
        property(&object, PROPERTIES_INTERFACE, 0x08, PROPERTY_UINT32, dword(NET_LUID_INDEX)),
        property(&object, PROPERTIES_INTERFACE, 0x0A, PROPERTY_UINT32, dword(ADAPTER_IF_TYPE)),
        property(&object, PROPERTIES_INTERFACE, 0x0C, PROPERTY_UINT32, dword(ADAPTER_MEDIA_TYPE)),
        property(&object, PROPERTIES_INTERFACE, 0x0E, PROPERTY_UINT32, dword(ADAPTER_PHYSICAL_MEDIA_TYPE)),
        property(&object, PROPERTIES_INTERFACE, 0x10, PROPERTY_STRING, wide(ADAPTER_ALIAS)),
        property(&object, PROPERTIES_INTERFACE, 0x12, PROPERTY_STRING, wide(ADAPTER_DESCRIPTION)),
        property(&object, PROPERTIES_INTERFACE, 0x1E, PROPERTY_BOOLEAN, alloc::vec![1]),
        property(&object, PROPERTIES_INTERFACE, 0x34, PROPERTY_STRING, wide(ADAPTER_MATCHING_ID)),
        property(&object, PROPERTIES_INF, 0x02, PROPERTY_STRING, wide(ADAPTER_INF.0)),
        property(&object, PROPERTIES_INF, 0x04, PROPERTY_STRING, wide(ADAPTER_INF.1)),
        property(&object, PROPERTIES_INF, 0x06, PROPERTY_UINT32, dword(ADAPTER_CHARACTERISTICS)),
        kernel,
    ]
}

fn dotted(address: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", address[0], address[1], address[2], address[3])
}

/// As chaves da hive SYSTEM: os objetos dos protocolos e a configuração
/// IPv4 do adaptador.
pub fn seed_keys() -> Vec<SeedKey> {
    let mut keys = Vec::new();
    let mut lookup = SeedKey::new(&format!("{NETWORK_SETUP}\\Protocols\\Lookup"));
    for (name, guid) in PROTOCOLS {
        lookup.value(name, REG_BINARY, guid_bytes(guid).to_vec());
    }
    keys.push(lookup);
    for (_, guid) in PROTOCOLS {
        keys.push(SeedKey::new(&format!("{NETWORK_SETUP}\\Protocols\\{guid}\\Properties")));
    }
    keys.extend(interface_keys());
    let (address_name, address_data) = unicast_address_entry();
    let mut addresses = SeedKey::new(&format!("{NSI_IPV4}\\{NSI_UNICAST_ADDRESS_OBJECT}"));
    addresses.value(&address_name, REG_BINARY, address_data);
    keys.push(addresses);
    let (route_name, route_data) = default_route_entry();
    let mut routes = SeedKey::new(&format!("{NSI_IPV4}\\{NSI_ROUTE_OBJECT}"));
    routes.value(&route_name, REG_BINARY, route_data);
    keys.push(routes);
    let mut interface = SeedKey::new(&format!("CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{ADAPTER_INSTANCE_ID}"));
    let mask = (u32::MAX << (32 - IPV4_PREFIX_LENGTH as u32)).to_be_bytes();
    interface
        .dword("EnableDHCP", 0)
        .strings("IPAddress", &[&dotted(IPV4_ADDRESS)])
        .strings("SubnetMask", &[&dotted(mask)])
        .strings("DefaultGateway", &[&dotted(IPV4_GATEWAY)])
        .text("Domain", REG_SZ, "")
        .text("NameServer", REG_SZ, "");
    keys.push(interface);
    keys
}
