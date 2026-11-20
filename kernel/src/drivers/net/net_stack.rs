//! A pilha de rede do Windows sobre a placa e1000 do QEMU (`--net`).
//!
//! Com a opção, a máquina tem a Intel PRO/1000 MT (e1000, PCI 8086:100E)
//! com a rede de modo usuário do QEMU (a rede 10.0.2.0/24, o gateway
//! 10.0.2.2). Antes da árvore do PnP sobem o ndis.sys, o tcpip.sys e o
//! afd.sys, que no Windows são drivers de boot e de sistema (grupos NDIS e
//! PNP_TDI) iniciados antes de o PnP enumerar a placa; o tcpip.sys registra
//! os seus protocolos no NDIS. Na árvore, o pci.sys relata a placa, o PnP a
//! instala pelo nete1g3e.inf com o E1G6032E.sys (serviço E1G60,
//! `io/pnp/install_net.rs`) e o DriverEntry do miniport se registra no NDIS
//! (NdisMRegisterMiniportDriver), que fica com o AddDevice e o despacho do
//! driver: o START vai ao NDIS, que chama o MiniportInitializeEx. Depois o
//! NDIS liga o adaptador aos protocolos do tcpip.sys pelas ligações do
//! NetworkSetup2 e o tcpip.sys aplica a configuração IPv4 persistente da
//! instalação (`cm/network_setup.rs`).
//!
//! Os marcos saem na serial:
//! - `NIC_STARTED`: o nó da placa iniciado com o miniport;
//! - `NIC_LINK_UP`: o NDIS relata o enlace conectado (o
//!   OID_GEN_MEDIA_CONNECT_STATUS pelo IOCTL_NDIS_QUERY_GLOBAL_STATS no
//!   dispositivo do adaptador, `\Device\{NetCfgInstanceId}`, como um
//!   programa consulta um OID);
//! - `TCPIP_BOUND`: o tcpip.sys tem a interface IPv4 do adaptador com o
//!   endereço da instalação (a entrada ativa do NSI pelo
//!   NsiGetAllParameters do NETIO.SYS);
//! - `PING_OK`: um eco ICMP ao gateway volta pelo WSK (`echo`).
//!
//! Sem a opção nada disto roda e o boot comum não muda.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::cm::network_setup;
use crate::ntos::inc::types::{LargeInteger, NtStruct};
use crate::ntos::io::pnp::devnode;
use crate::ntos::mm::guest_memory as guest;

/// `--net`: a placa de rede recebe o miniport real e a pilha sobe.
pub fn enabled() -> bool {
    crate::ntos::init::boot_config::network()
}

/// O serviço do miniport da placa (nete1g3e.inf).
const MINIPORT_SERVICE: &str = "E1G60";
/// IOCTL_NDIS_QUERY_GLOBAL_STATS: CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD,
/// 0, METHOD_OUT_DIRECT, FILE_ANY_ACCESS).
const IOCTL_NDIS_QUERY_GLOBAL_STATS: u64 = 0x0017_0002;
const OID_GEN_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
const OID_802_3_CURRENT_ADDRESS: u32 = 0x0101_0102;
/// NdisMediaStateConnected.
const MEDIA_STATE_CONNECTED: u32 = 0;
/// O prazo de cada marco depois do anterior.
const SETTLE_MS: i64 = 60_000;
const STEP_MS: i64 = 250;
/// Os pedidos de eco (como o ping.exe, até 4) e o prazo de cada resposta.
const ECHO_ATTEMPTS: u16 = 4;
const ECHO_TIMEOUT_MS: i64 = 4_000;

/// Antes da árvore do PnP: o ndis.sys, o tcpip.sys e o afd.sys, na ordem
/// dos grupos de boot do Windows. Devolve false se um deles não sobe.
pub fn before_tree() -> bool {
    debug_print!("[net] pilha de rede real pelo PnP (ndis.sys, tcpip.sys, afd.sys e E1G6032E.sys na e1000)");
    for service in ["NDIS", "Tcpip", "AFD"] {
        if !crate::ntos::cm::service::system_drivers::load_service_driver(service) {
            debug_print!("[net] servico {} nao iniciou", service);
            return false;
        }
    }
    true
}

/// O nó da placa: o devnode com o serviço do miniport.
fn adapter_node() -> Option<devnode::DeviceNode> {
    devnode::all().into_iter().find(|node| node.service.as_deref().is_some_and(|service| service.eq_ignore_ascii_case(MINIPORT_SERVICE)))
}

/// Espera `milliseconds` como uma thread do sistema (as interrupções, os
/// DPCs, os timers e os work items dos drivers rodam durante a espera).
fn delay(milliseconds: i64) {
    let interval = guest::alloc_bytes(LargeInteger::SIZE);
    // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo).
    unsafe { LargeInteger::at(interval) }.quad_part.set(-milliseconds * 10_000);
    let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    guest::free_bytes(interval);
}

/// Repete `probe` de 100 em 100 ms até dar Some ou passar o prazo.
fn poll<T>(mut probe: impl FnMut() -> Option<T>) -> Option<T> {
    let mut waited = 0;
    loop {
        if let Some(value) = probe() {
            return Some(value);
        }
        if waited >= SETTLE_MS {
            return None;
        }
        delay(STEP_MS);
        waited += STEP_MS;
    }
}

/// Os registradores da e1000 (o BAR0 pelo mapa direto): CTRL, STATUS, o
/// controle de recepção e de transmissão, a máscara de interrupções, os
/// anéis e os contadores de pacotes bons recebidos e transmitidos.
fn log_controller_state() {
    let Some(function) = crate::drivers::bus::pci::find_by_id(0x8086, 0x100E) else { return };
    let Some(bar) = function.bars.iter().find(|bar| bar.index == 0) else { return };
    let base = (bar.value & 0xFFFF_FFF0) as u64;
    let command = crate::hal::pci_config::read(function.bus, function.device, function.function, 0x04, 4).unwrap_or(0);
    if base == 0 || base >= crate::hal::physical::direct_map_limit() {
        debug_print!("[net] BAR0 {:#x} fora do mapa direto; comando/estado PCI {:#010x}", base, command);
        return;
    }
    let register = |offset: u64| crate::hal::volatile::read32(crate::hal::physical::to_virtual(base + offset));
    debug_print!(
        "[net] e1000 em {:#x}: CTRL {:#x} STATUS {:#x} RCTL {:#x} TCTL {:#x} IMS {:#x} RDBAL {:#x} RDLEN {:#x} RDH {} RDT {} TDBAL {:#x} TDH {} TDT {}; comando/estado PCI {:#010x}",
        base,
        register(0x0000),
        register(0x0008),
        register(0x0100),
        register(0x0400),
        register(0x00D0),
        register(0x2800),
        register(0x2808),
        register(0x2810),
        register(0x2818),
        register(0x3800),
        register(0x3810),
        register(0x3818),
        command
    );
}

fn kernel_call(name: &str, arguments: &[u64]) -> u64 {
    match crate::ntos::init::exports::lookup("ntoskrnl.exe", name) {
        Some(crate::ntos::mm::pe_loader::ResolvedImport::Thunk(id)) => crate::ntos::init::exports::thunk_address(id as u64).map_or(u64::MAX, |address| crate::hal::amd64::native_call::call(address, arguments)),
        _ => u64::MAX,
    }
}

/// Um OID do adaptador pelo IOCTL_NDIS_QUERY_GLOBAL_STATS no dispositivo
/// do adaptador: (status, bytes devolvidos).
fn query_oid(oid: u32, length: u32) -> Result<Vec<u8>, String> {
    let block = guest::alloc_bytes(0x400);
    guest::write_bytes(block, &[0u8; 0x400]);
    let name: Vec<u16> = format!("\\Device\\{}", network_setup::ADAPTER_INSTANCE_ID).encode_utf16().collect();
    let text = block + 0x100;
    guest::write_bytes(text, &name.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
    // UNICODE_STRING em +0x40 e OBJECT_ATTRIBUTES em +0 (OBJ_CASE_INSENSITIVE
    // | OBJ_KERNEL_HANDLE).
    guest::write16(block + 0x40, name.len() as u16 * 2);
    guest::write16(block + 0x42, name.len() as u16 * 2);
    guest::write64(block + 0x48, text);
    guest::write32(block, 48);
    guest::write64(block + 0x10, block + 0x40);
    guest::write32(block + 0x18, 0x240);
    let (handle, iosb, input, output) = (block + 0x200, block + 0x210, block + 0x220, block + 0x300);
    // GENERIC_READ | SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
    // FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT.
    let status = kernel_call("ZwCreateFile", &[handle, 0x8010_0000, block, iosb, 0, 0, 3, 1, 0x20, 0, 0]) as u32;
    let result = if status != 0 {
        Err(format!("ZwCreateFile {}: {status:#x}", network_setup::ADAPTER_INSTANCE_ID))
    } else {
        let file = guest::read64(handle);
        guest::write32(input, oid);
        let status = kernel_call("ZwDeviceIoControlFile", &[file, 0, 0, 0, iosb, IOCTL_NDIS_QUERY_GLOBAL_STATS, input, 4, output, length as u64]) as u32;
        let information = guest::read64(iosb + 8).min(length as u64) as usize;
        kernel_call("ZwClose", &[file]);
        if status != 0 {
            Err(format!("IOCTL_NDIS_QUERY_GLOBAL_STATS {oid:#x}: {status:#x}"))
        } else {
            Ok(guest::read_bytes(output, information))
        }
    };
    guest::free_bytes(block);
    result
}

/// A entrada ativa do endereço IPv4 da instalação na interface do
/// adaptador (NETIO!NsiGetAllParameters no NsiActive, objeto 10 do módulo
/// IPv4, chave {InterfaceLuid, Address}).
fn active_ipv4_address() -> Result<Vec<u8>, String> {
    let netio = crate::ntos::mm::sysload::acquire("netio.sys").map_err(|error| format!("netio.sys: {error}"))?;
    let get_all = netio.export("NsiGetAllParameters").ok_or("NETIO!NsiGetAllParameters ausente")?;
    let mut netio = netio;
    let _ = netio.release();
    let block = guest::alloc_bytes(0x100);
    guest::write_bytes(block, &[0u8; 0x100]);
    // NPI_MODULEID {Length 0x18, Type MIT_GUID, Guid} do IPv4.
    let module = block;
    guest::write16(module, 0x18);
    guest::write32(module + 4, 1);
    guest::write_bytes(module + 8, &network_setup::guid_bytes("{eb004a00-9b1a-11d4-9123-0050047759bc}"));
    let key = block + 0x20;
    guest::write64(key, network_setup::net_luid(network_setup::ADAPTER_IF_TYPE, network_setup::NET_LUID_INDEX));
    guest::write_bytes(key + 8, &network_setup::IPV4_ADDRESS);
    let parameters = block + 0x40;
    let status = crate::hal::amd64::native_call::call(get_all, &[1, module, 10, key, 0x10, parameters, 0x1C, 0, 0, 0, 0]) as u32;
    let result = if status == 0 { Ok(guest::read_bytes(parameters, 0x1C)) } else { Err(format!("NsiGetAllParameters {status:#x}")) };
    guest::free_bytes(block);
    result
}

/// Depois da árvore: o nó da placa e os marcos.
pub fn check() {
    let Some(node) = adapter_node() else {
        debug_print!("[net] nenhum devnode com o servico {}", MINIPORT_SERVICE);
        log_controller_state();
        return;
    };
    debug_print!("[net] {}: estado {:?} problema {:#x}", node.instance_path, node.state, node.problem);
    if node.state != devnode::State::Started {
        log_controller_state();
        return;
    }
    let miniport = crate::ntos::io::lifecycle::initialized_driver(MINIPORT_SERVICE);
    debug_print!("[net] {}: miniport {} iniciado pelo NDIS (\\Driver\\{} em {:#x})", node.instance_path, MINIPORT_SERVICE, MINIPORT_SERVICE, miniport.unwrap_or(0));
    debug_print!("NIC_STARTED");
    // O enlace: o NDIS guarda o estado que o miniport indica
    // (NDIS_STATUS_LINK_STATE) e responde o OID por ele.
    let mut last = String::new();
    let link = poll(|| match query_oid(OID_GEN_MEDIA_CONNECT_STATUS, 4) {
        Ok(bytes) if bytes.len() == 4 && u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) == MEDIA_STATE_CONNECTED => Some(()),
        Ok(bytes) => {
            last = format!("estado {bytes:02x?}");
            None
        }
        Err(error) => {
            last = error;
            None
        }
    });
    if link.is_none() {
        debug_print!("[net] enlace nao conectado em {} ms: {}", SETTLE_MS, last);
        log_controller_state();
        return;
    }
    let address = query_oid(OID_802_3_CURRENT_ADDRESS, 6).map(|bytes| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<String>>().join(":")).unwrap_or_else(|error| error);
    debug_print!("[net] \\Device\\{}: enlace conectado (OID_GEN_MEDIA_CONNECT_STATUS), endereco {}", network_setup::ADAPTER_INSTANCE_ID, address);
    debug_print!("NIC_LINK_UP");
    let bound = poll(|| match active_ipv4_address() {
        Ok(parameters) => Some(parameters),
        Err(error) => {
            last = error;
            None
        }
    });
    let Some(parameters) = bound else {
        debug_print!("[net] o tcpip.sys nao tem o endereco 10.0.2.15 na interface do adaptador em {} ms: {}", SETTLE_MS, last);
        log_controller_state();
        return;
    };
    debug_print!("[net] tcpip.sys ligado ao adaptador: 10.0.2.15/{} na interface NET_LUID {:#x} (parametros {:02x?})", parameters[0x10], network_setup::net_luid(network_setup::ADAPTER_IF_TYPE, network_setup::NET_LUID_INDEX), &parameters[..0x14]);
    debug_print!("TCPIP_BOUND");
    for sequence in 1..=ECHO_ATTEMPTS {
        match super::echo::ping(network_setup::IPV4_GATEWAY, sequence, ECHO_TIMEOUT_MS) {
            Ok(reply) => {
                debug_print!("[net] resposta de 10.0.2.2: bytes={} tempo={}ms TTL={} (pedido {})", reply.bytes, reply.milliseconds, reply.ttl, sequence);
                debug_print!("PING_OK");
                return;
            }
            Err(error) => debug_print!("[net] eco {} para 10.0.2.2: {}", sequence, error),
        }
    }
    log_controller_state();
}
