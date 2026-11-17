//! O eco ICMP pela pilha de rede real, como um cliente do Winsock Kernel.
//!
//! O teste faz o que um driver cliente do WSK faz (a interface pública do
//! wsk.h): registra-se no WSK pelo NETIO.SYS (WskRegister), pega o NPI do
//! provedor, que é o afd.sys (WskCaptureProviderNPI), cria um socket de
//! datagramas IPv4 bruto do protocolo ICMP (WskSocket com AF_INET,
//! SOCK_RAW, IPPROTO_ICMP e WSK_FLAG_DATAGRAM_SOCKET), associa-o a
//! 0.0.0.0 (WskBind), deixa uma recepção pendente (WskReceiveFrom) e manda
//! um pedido de eco (WskSendTo). O tcpip.sys resolve o gateway pelo ARP,
//! o NDIS entrega o quadro ao miniport, a resposta volta pela interrupção da
//! placa e chega ao socket com o cabeçalho IPv4 (o socket bruto IPv4 entrega
//! o datagrama inteiro). Cada pedido do WSK leva um IRP do cliente com a
//! rotina de conclusão no próximo slot, que sinaliza um evento.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{IoStackLocation, Irp, Kevent, LargeInteger, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::ResolvedImport;

const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_MORE_PROCESSING_REQUIRED: u64 = 0xC000_0016;
const STATUS_UNSUCCESSFUL: u64 = 0xC000_0001;
/// SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL.
const SL_INVOKE_ALWAYS: u8 = 0xE0;
const AF_INET: u64 = 2;
const SOCK_RAW: u64 = 3;
const IPPROTO_ICMP: u64 = 1;
const WSK_FLAG_DATAGRAM_SOCKET: u64 = 4;
/// MAKE_WSK_VERSION(1, 0).
const WSK_VERSION: u16 = 0x0100;
/// NonPagedPoolNx.
const NON_PAGED_POOL_NX: u64 = 0x200;
const POOL_TAG: u64 = u32::from_le_bytes(*b"Echo") as u64;

/// Os 32 bytes de dados que o ping.exe do Windows manda.
const ECHO_DATA: &[u8; 32] = b"abcdefghijklmnopqrstuvwabcdefghi";
const ECHO_IDENTIFIER: u16 = 1;

/// O endereço de um export do ntoskrnl (o trampolim, como um driver o vê
/// pela IAT).
fn kernel_export(name: &str) -> Result<u64, String> {
    match crate::ntos::init::exports::lookup("ntoskrnl.exe", name) {
        Some(ResolvedImport::Thunk(id)) => crate::ntos::init::exports::thunk_address(id as u64).map_err(|error| format!("{name}: {error}")),
        Some(ResolvedImport::Address { address, .. }) => Ok(address),
        _ => Err(format!("{name}: sem export")),
    }
}

fn call(name: &str, arguments: &[u64]) -> Result<u64, String> {
    Ok(native_call::call(kernel_export(name)?, arguments))
}

/// A rotina de conclusão dos IRPs do cliente: sinaliza o evento e fica com
/// o IRP (STATUS_MORE_PROCESSING_REQUIRED), que o cliente reaproveita.
extern "win64" fn request_completed(_device: u64, _irp: u64, event: u64) -> u64 {
    crate::ntos::ke::dispatcher::set_event(event);
    STATUS_MORE_PROCESSING_REQUIRED
}

/// Um IRP do cliente com o seu evento.
struct Request {
    irp: u64,
    event: u64,
}

impl Request {
    fn new() -> Result<Request, String> {
        let irp = call("IoAllocateIrp", &[1, 0])?;
        if irp == 0 {
            return Err(String::from("IoAllocateIrp"));
        }
        let event = guest::alloc_bytes(Kevent::SIZE);
        crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
        Ok(Request { irp, event })
    }

    /// IoReuseIrp e IoSetCompletionRoutine no próximo slot (o que o
    /// provedor conclui).
    fn prepare(&self) -> Result<u64, String> {
        call("IoReuseIrp", &[self.irp, STATUS_UNSUCCESSFUL])?;
        crate::ntos::ke::dispatcher::clear_event(self.event);
        // SAFETY: IRP alocado por IoAllocateIrp com um slot.
        let irp = unsafe { Irp::at(self.irp) };
        let next = irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE;
        // SAFETY: o slot 0 do IRP.
        let location = unsafe { IoStackLocation::at(next) };
        let routine: extern "win64" fn(u64, u64, u64) -> u64 = request_completed;
        location.completion_routine.set(routine as usize as u64);
        location.context.set(self.event);
        location.control.set(SL_INVOKE_ALWAYS);
        Ok(self.irp)
    }

    /// Espera a conclusão até `milliseconds`; devolve (status, Information)
    /// ou None no prazo.
    fn wait(&self, milliseconds: i64) -> Option<(u32, u64)> {
        let timeout = guest::alloc_bytes(LargeInteger::SIZE);
        // SAFETY: LARGE_INTEGER recém-alocado (tempo relativo).
        unsafe { LargeInteger::at(timeout) }.quad_part.set(-milliseconds * 10_000);
        let waited = crate::ntos::ke::dispatcher::wait_for_single_object(self.event, timeout, 0, false);
        guest::free_bytes(timeout);
        if waited == STATUS_TIMEOUT {
            return None;
        }
        // SAFETY: IRP concluído pelo provedor.
        let irp = unsafe { Irp::at(self.irp) };
        Some((irp.io_status.status.get() as u32, irp.io_status.information.get()))
    }

    /// Cancela um pedido pendente e espera a conclusão.
    fn cancel(&self) {
        let _ = call("IoCancelIrp", &[self.irp]);
        let _ = self.wait(5_000);
    }

    fn free(self) {
        let _ = call("IoFreeIrp", &[self.irp]);
        guest::free_bytes(self.event);
    }
}

/// Um buffer do pool não paginado com o MDL que o descreve (WSK_BUF).
struct Buffer {
    address: u64,
    length: u64,
    mdl: u64,
    wsk_buf: u64,
}

impl Buffer {
    fn new(length: u64) -> Result<Buffer, String> {
        let address = call("ExAllocatePoolWithTag", &[NON_PAGED_POOL_NX, length, POOL_TAG])?;
        if address == 0 {
            return Err(String::from("ExAllocatePoolWithTag"));
        }
        guest::write_bytes(address, &alloc::vec![0u8; length as usize]);
        let mdl = call("IoAllocateMdl", &[address, length, 0, 0, 0])?;
        if mdl == 0 {
            return Err(String::from("IoAllocateMdl"));
        }
        call("MmBuildMdlForNonPagedPool", &[mdl])?;
        // WSK_BUF: Mdl, Offset (ULONG) e Length (SIZE_T).
        let wsk_buf = guest::alloc_bytes(24);
        guest::write64(wsk_buf, mdl);
        guest::write64(wsk_buf + 8, 0);
        guest::write64(wsk_buf + 16, length);
        Ok(Buffer { address, length, mdl, wsk_buf })
    }

    fn free(self) {
        let _ = call("IoFreeMdl", &[self.mdl]);
        let _ = call("ExFreePoolWithTag", &[self.address, POOL_TAG]);
        guest::free_bytes(self.wsk_buf);
    }
}

/// SOCKADDR_IN: família, porta (0) e o endereço.
fn sockaddr_in(address: [u8; 4]) -> u64 {
    let block = guest::alloc_bytes(16);
    let mut bytes = [0u8; 16];
    bytes[0..2].copy_from_slice(&(AF_INET as u16).to_le_bytes());
    bytes[4..8].copy_from_slice(&address);
    guest::write_bytes(block, &bytes);
    block
}

/// A soma de verificação da internet (complemento de um de 16 bits).
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes.chunks(2).map(|pair| u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]) as u32).sum();
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// O pedido de eco ICMP (tipo 8, código 0) com o identificador, a sequência
/// e os dados.
pub fn echo_request(sequence: u16) -> Vec<u8> {
    let mut packet = alloc::vec![8u8, 0, 0, 0];
    packet.extend_from_slice(&ECHO_IDENTIFIER.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    packet.extend_from_slice(ECHO_DATA);
    let checksum = internet_checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    packet
}

/// Uma resposta de eco recebida pelo socket bruto: o datagrama IPv4 inteiro.
/// Devolve o TTL se é a resposta (tipo 0) do pedido `sequence` vinda de
/// `source`, com a soma ICMP certa e os dados de volta.
pub fn echo_reply_ttl(datagram: &[u8], source: [u8; 4], sequence: u16) -> Option<u8> {
    let header = (*datagram.first()? as usize & 0x0F) * 4;
    if datagram.len() < header + 8 || datagram[0] >> 4 != 4 || datagram[9] as u64 != IPPROTO_ICMP || datagram[12..16] != source {
        return None;
    }
    let icmp = &datagram[header..];
    let ok = icmp[0] == 0 && icmp[1] == 0 && icmp[4..6] == ECHO_IDENTIFIER.to_be_bytes() && icmp[6..8] == sequence.to_be_bytes() && internet_checksum(icmp) == 0 && icmp[8..] == ECHO_DATA[..];
    ok.then_some(datagram[8])
}

/// O resultado de um eco.
pub struct EchoReply {
    pub bytes: usize,
    pub ttl: u8,
    pub milliseconds: u64,
}

/// Os pontos de entrada do WSK no NETIO.SYS carregado.
struct WskLibrary {
    register: u64,
    capture: u64,
    release: u64,
    deregister: u64,
}

fn wsk_library() -> Result<WskLibrary, String> {
    let netio = crate::ntos::mm::sysload::acquire("netio.sys").map_err(|error| format!("netio.sys: {error}"))?;
    let export = |name: &str| netio.export(name).ok_or_else(|| format!("NETIO!{name} ausente"));
    let library = WskLibrary { register: export("WskRegister")?, capture: export("WskCaptureProviderNPI")?, release: export("WskReleaseProviderNPI")?, deregister: export("WskDeregister")? };
    // O NETIO.SYS é dependência de import do NDIS e do tcpip.sys, carregados
    // e fixados: a referência deste lease pode voltar já.
    let mut netio = netio;
    let _ = netio.release();
    Ok(library)
}

/// Um eco ICMP para `destination` pelo WSK, esperando a resposta até
/// `timeout_ms`.
pub fn ping(destination: [u8; 4], sequence: u16, timeout_ms: i64) -> Result<EchoReply, String> {
    let library = wsk_library()?;
    // WSK_CLIENT_DISPATCH {Version, Reserved, WskClientEvent} e
    // WSK_CLIENT_NPI {ClientContext, Dispatch}; WSK_REGISTRATION (24 bytes).
    let dispatch = guest::alloc_bytes(16);
    guest::write_bytes(dispatch, &[0u8; 16]);
    guest::write16(dispatch, WSK_VERSION);
    let client = guest::alloc_bytes(16);
    guest::write64(client, 0);
    guest::write64(client + 8, dispatch);
    let registration = guest::alloc_bytes(24);
    guest::write_bytes(registration, &[0u8; 24]);
    let provider = guest::alloc_bytes(16);
    guest::write_bytes(provider, &[0u8; 16]);
    let status = native_call::call(library.register, &[client, registration]) as u32;
    if status != 0 {
        return Err(format!("WskRegister {status:#x}"));
    }
    let result = (|| {
        let status = native_call::call(library.capture, &[registration, 10_000, provider]) as u32;
        if status != 0 {
            return Err(format!("WskCaptureProviderNPI {status:#x}"));
        }
        let result = with_provider(guest::read64(provider), guest::read64(provider + 8), destination, sequence, timeout_ms);
        native_call::call(library.release, &[registration]);
        result
    })();
    native_call::call(library.deregister, &[registration]);
    for block in [dispatch, client, registration, provider] {
        guest::free_bytes(block);
    }
    result
}

/// Com o NPI do provedor: o socket bruto, o eco e o fechamento.
fn with_provider(wsk_client: u64, provider_dispatch: u64, destination: [u8; 4], sequence: u16, timeout_ms: i64) -> Result<EchoReply, String> {
    let request = Request::new()?;
    // WSK_PROVIDER_DISPATCH: Version, Reserved e o WskSocket em +8.
    let wsk_socket = guest::read64(provider_dispatch + 8);
    native_call::call(wsk_socket, &[wsk_client, AF_INET, SOCK_RAW, IPPROTO_ICMP, WSK_FLAG_DATAGRAM_SOCKET, 0, 0, 0, 0, 0, request.prepare()?]);
    let socket = match request.wait(10_000) {
        Some((0, socket)) if socket != 0 => socket,
        Some((status, _)) => {
            request.free();
            return Err(format!("WskSocket {status:#x}"));
        }
        None => {
            request.cancel();
            request.free();
            return Err(String::from("WskSocket sem conclusao em 10 s"));
        }
    };
    let result = echo_on_socket(socket, &request, destination, sequence, timeout_ms);
    // WSK_PROVIDER_DATAGRAM_DISPATCH: WskControlSocket, WskCloseSocket,
    // WskBind, WskSendTo, WskReceiveFrom...
    let close = guest::read64(guest::read64(socket) + 8);
    if let Ok(irp) = request.prepare() {
        native_call::call(close, &[socket, irp]);
        let _ = request.wait(10_000);
    }
    request.free();
    result
}

fn echo_on_socket(socket: u64, request: &Request, destination: [u8; 4], sequence: u16, timeout_ms: i64) -> Result<EchoReply, String> {
    let dispatch = guest::read64(socket);
    let (bind, send_to, receive_from) = (guest::read64(dispatch + 0x10), guest::read64(dispatch + 0x18), guest::read64(dispatch + 0x20));
    let local = sockaddr_in([0; 4]);
    native_call::call(bind, &[socket, local, 0, request.prepare()?]);
    let bound = request.wait(10_000);
    guest::free_bytes(local);
    match bound {
        Some((0, _)) => {}
        Some((status, _)) => return Err(format!("WskBind {status:#x}")),
        None => {
            request.cancel();
            return Err(String::from("WskBind sem conclusao em 10 s"));
        }
    }
    // A recepção fica pendente antes do envio.
    let receiver = Request::new()?;
    let reply = Buffer::new(1500)?;
    let remote = sockaddr_in([0; 4]);
    let pending = native_call::call(receive_from, &[socket, reply.wsk_buf, 0, remote, 0, 0, 0, receiver.prepare()?]);
    let packet = echo_request(sequence);
    let outgoing = Buffer::new(packet.len() as u64)?;
    guest::write_bytes(outgoing.address, &packet);
    let target = sockaddr_in(destination);
    let started = crate::ntos::ke::clock::uptime_ms();
    native_call::call(send_to, &[socket, outgoing.wsk_buf, 0, target, 0, 0, request.prepare()?]);
    let sent = request.wait(10_000);
    let result = match sent {
        Some((0, bytes)) => {
            debug_print!("[net] eco: WskSendTo de {} bytes para {}.{}.{}.{} concluido (recepcao {:#x})", bytes, destination[0], destination[1], destination[2], destination[3], pending);
            wait_reply(&receiver, &reply, destination, sequence, timeout_ms, started)
        }
        Some((status, _)) => Err(format!("WskSendTo {status:#x}")),
        None => {
            request.cancel();
            Err(String::from("WskSendTo sem conclusao em 10 s"))
        }
    };
    if result.is_err() {
        receiver.cancel();
    }
    guest::free_bytes(target);
    guest::free_bytes(remote);
    outgoing.free();
    reply.free();
    receiver.free();
    result
}

fn wait_reply(receiver: &Request, reply: &Buffer, destination: [u8; 4], sequence: u16, timeout_ms: i64, started: u64) -> Result<EchoReply, String> {
    match receiver.wait(timeout_ms) {
        Some((0, bytes)) => {
            let datagram = guest::read_bytes(reply.address, (bytes as usize).min(reply.length as usize));
            let milliseconds = crate::ntos::ke::clock::uptime_ms().saturating_sub(started);
            match echo_reply_ttl(&datagram, destination, sequence) {
                Some(ttl) => Ok(EchoReply { bytes: datagram.len(), ttl, milliseconds }),
                None => Err(format!("datagrama de {} bytes que nao e a resposta: {:02x?}", datagram.len(), &datagram[..datagram.len().min(48)])),
            }
        }
        Some((status, _)) => Err(format!("WskReceiveFrom {status:#x}")),
        None => Err(format!("sem resposta em {timeout_ms} ms")),
    }
}

