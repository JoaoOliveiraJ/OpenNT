//! Serviço de sessão CSR hospedado no processo System.
//!
//! ABI da ntdll/KERNELBASE x64 do Windows 10 (build 19041): informação de
//! conexão de 48 bytes e ponteiros de dados do servidor expressos no
//! mapeamento supervisor da SharedSection.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::index::{self, late};
use super::sections::{self, CreateOptions, MapRequest, Section};
use super::{lpc, state};
use crate::ntos::alpc::transport::{JobResult, Reply, Service, ServiceReply};
use crate::ntos::ob::object_manager;
use crate::ntos::ob::objects::port::Port;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Cliente CSR de um processo.
struct Client {
    threads: BTreeSet<u64>,
    servers: BTreeSet<u32>,
    process_create_callback: u64,
    connections: Vec<u64>,
}

struct Session {
    base: u64,
    table: u64,
    _data: u64,
    _section: Arc<Section>,
    clients: BTreeMap<u64, Client>,
    /// Porta de conexão → processo cliente.
    ports: BTreeMap<u64, u64>,
}

static SESSION: SpinLock<Option<Session>> = SpinLock::new(None);
/// Conexão USER do subsistema de janelas; fica vazia até o win32k.sys real
/// se registrar.
static USER_CONNECTOR: SpinLock<Option<fn(u64, u64) -> u32>> = SpinLock::new(None);

pub fn set_user_connector(connector: fn(u64, u64) -> u32) {
    *USER_CONNECTOR.lock() = Some(connector);
}

struct CsrService;

impl Service for CsrService {
    fn max_message_length(&self) -> u32 {
        0x3B8
    }
    fn max_connection_info(&self) -> u32 {
        48
    }
    fn connect(&self, port: &Arc<Port>, input: &[u8], _request: Option<&[u8]>) -> Reply {
        Reply::Now(connect(port, input))
    }
    fn request(&self, port: &Arc<Port>, message: &Arc<SpinLock<Vec<u8>>>) -> ServiceReply {
        ServiceReply::Now(request(port, &mut message.lock()))
    }
    fn disconnect(&self, port: &Arc<Port>) {
        disconnect(port);
    }
}

pub fn initialize() -> Result<(), KernelError> {
    if SESSION.lock().is_some() {
        return Ok(());
    }
    object_manager::create_directory("\\Windows")?;
    object_manager::create_directory("\\BaseNamedObjects")?;
    // A sessão zero compartilha o namespace global: os prefixos Global\ e
    // Local\ são links reais do Object Manager, com a mesma identidade.
    object_manager::create_symlink("\\BaseNamedObjects\\Global", "\\BaseNamedObjects")?;
    object_manager::create_symlink("\\BaseNamedObjects\\Local", "\\BaseNamedObjects")?;
    let section = match sections::create(CreateOptions { size: 0x1_0000, page_protect: 4, attributes: 0x0800_0000, name: Some(alloc::string::String::from("\\Windows\\SharedSection")), permanent: true, ..CreateOptions::default() })? {
        Ok(section) => section,
        Err(status) => return Err(KernelError::new(alloc::format!("CSR: create section 0x{status:x}"))),
    };
    let view = match sections::map(&section, &MapRequest { supervisor: true, protect: 4, ..MapRequest::default() })? {
        Ok(view) => view,
        Err(status) => return Err(KernelError::new(alloc::format!("CSR: map section 0x{status:x}"))),
    };
    // Nenhum cliente obtém vista gravável dos dados da sessão.
    section.set_page_protect(2);
    let base = view.base;
    let table = base + 0x100;
    let data = base + 0x1000;
    let mut strings = base + 0x3000;
    let mut unicode = |offset: u64, value: &str| {
        state::write_user_wide(strings, value);
        state::write_unicode_string(data + offset, strings, value);
        strings += ((value.encode_utf16().count() as u64 + 1) * 2).div_ceil(8) * 8;
    };
    guest::write64(table + 8, data); // BASESRV, índice 1 de DLL de servidor
    unicode(0, "C:\\Windows");
    unicode(0x10, "C:\\Windows\\System32");
    unicode(0x20, "\\BaseNamedObjects");
    unicode(0x9D8, "C:\\Windows\\SysWOW64");
    unicode(0x9F0, "\\BaseNamedObjects");
    guest::write64(data + 0x9E8, data); // endereço usado para relocar ponteiros embutidos
    guest::write64(data + 0x170, base + 0x2800); // lista INI-para-registro vazia
    // A sessão zero usa o relógio UTC do convidado, sem fuso de terminal
    // services: hora atual do KUSER_SHARED_DATA.
    let now = guest::read64(0x7FFE_0014);
    guest::write64(data + 0x140, now);
    guest::write64(data + 0x148, now);
    *SESSION.lock() = Some(Session { base, table, _data: data, _section: section, clients: BTreeMap::new(), ports: BTreeMap::new() });
    lpc::register("\\Windows\\ApiPort", Arc::new(CsrService))?;
    crate::debug_print!("[csr] sessao 0: SharedSection e ApiPort prontos");
    Ok(())
}

fn connect(port: &Arc<Port>, input: &[u8]) -> JobResult {
    if input.len() != 48 || port.with(|state| state.views.len()) != 2 {
        return JobResult { status: 0xC000_000D, ..JobResult::default() };
    }
    let mut data = input.to_vec();
    let server = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
    let process_id = port.process_id();
    let mut guard = SESSION.lock();
    let Some(session) = guard.as_mut() else { return JobResult { status: 0xC000_0037, ..JobResult::default() } };
    let client = session.clients.entry(process_id).or_insert_with(|| Client { threads: [port.thread_id()].into_iter().collect(), servers: BTreeSet::new(), process_create_callback: 0, connections: Vec::new() });
    client.connections.push(port.pointer);
    let mut status = 0u32;
    if server == 1 {
        client.servers.insert(1);
        client.process_create_callback = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0; 8]));
    } else if server != 0 {
        status = 0xC000_0002;
    }
    session.ports.insert(port.pointer, process_id);
    data[0..8].copy_from_slice(&session.base.to_le_bytes());
    data[8..16].copy_from_slice(&session.table.to_le_bytes());
    data[16..24].copy_from_slice(&process::SYSTEM_PROCESS_ID.to_le_bytes());
    data[24..32].copy_from_slice(&0u64.to_le_bytes());
    data[36..40].copy_from_slice(&status.to_le_bytes());
    JobResult { status: 0, data, sender: None }
}

fn disconnect(port: &Arc<Port>) {
    let mut guard = SESSION.lock();
    let Some(session) = guard.as_mut() else { return };
    let Some(process_id) = session.ports.remove(&port.pointer) else { return };
    let empty = session.clients.get_mut(&process_id).is_some_and(|client| {
        client.connections.retain(|&connection| connection != port.pointer);
        client.connections.is_empty()
    });
    if empty {
        session.clients.remove(&process_id);
    }
}

/// Estado do cliente de um processo: threads, servidores registrados e o
/// callback de criação de processo.
pub fn client(process_id: u64) -> Option<(Vec<u64>, Vec<u32>, u64)> {
    SESSION.lock().as_ref().and_then(|session| session.clients.get(&process_id)).map(|client| (client.threads.iter().copied().collect(), client.servers.iter().copied().collect(), client.process_create_callback))
}

/// O intervalo está todo dentro do alias supervisor da seção da porta.
pub fn capture_range(port: &Port, address: u64, size: u64) -> bool {
    port.with(|state| state.views.iter().any(|view| view.supervisor && address >= view.base && address.checked_add(size).is_some_and(|end| end <= view.base + view.size)))
}

fn request(port: &Arc<Port>, data: &mut [u8]) -> u32 {
    if data.len() < 64 {
        return 0xC000_0021;
    }
    let u32_at = |data: &[u8], offset: usize| u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]);
    let api = u32_at(data, 48);
    let (server, operation) = (api >> 16, api & 0xFFFF);
    let mut status = 0xC000_0002u32;
    // CsrClientConnectToServer, registro posterior de DLL de servidor: a
    // carga capturada está no alias de servidor negociado pelo NtConnectPort.
    if server == 0 && operation == 0 && data.len() >= 88 {
        let id = u32_at(data, 64);
        let pointer = u64::from_le_bytes(data[72..80].try_into().unwrap_or([0; 8]));
        let size = u32_at(data, 80) as u64;
        crate::debug_print!("[csr] registro de servidor: id={} payload={}", id, size);
        let process_id = port.process_id();
        let add_server = |id: u32, callback: Option<u64>| {
            if let Some(client) = SESSION.lock().as_mut().and_then(|session| session.clients.get_mut(&process_id)) {
                client.servers.insert(id);
                if let Some(callback) = callback {
                    client.process_create_callback = callback;
                }
            }
        };
        if id == 1 && size == 8 && capture_range(port, pointer, size) {
            add_server(1, Some(guest::read64(pointer)));
            status = 0;
        } else if id == 3 {
            status = if size == 0x240 && capture_range(port, pointer, size) {
                match *USER_CONNECTOR.lock() {
                    Some(connect_user) => connect_user(process_id, pointer),
                    None => 0xC000_00BB,
                }
            } else {
                0xC000_000D
            };
            if status == 0 {
                add_server(3, None);
            }
        } else {
            status = if id == 1 { 0xC000_000D } else { 0xC000_0002 };
        }
    }
    data[52..56].copy_from_slice(&status.to_le_bytes());
    crate::debug_print!("[csr] api=0x{:x} status=0x{:x}", api, status);
    // O transporte entregou a resposta; o status CSR vai na mensagem.
    0
}

/// A sessão é criada depois do anel 3 armado (inicialização tardia).
pub fn init() {
    index::set_late_initializer(late::CSR, initialize);
}
