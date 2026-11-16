//! Portas LPC entre dois processos (`alpc/lpc_ports.rs` sobre o servidor e o
//! transporte ALPC):
//!
//! - O servidor, em anel 3, recusa o MaxMessageLength acima do
//!   LpcLegacyMaxMessageLength (STATUS_INVALID_PARAMETER), cria a porta de
//!   conexão `\OpenNtLpcTeste` pelo NtCreatePort (a segunda criação dá
//!   STATUS_OBJECT_NAME_COLLISION) e bloqueia no NtListenPort. O teste confere
//!   que ele está parado no kernel antes de pôr o cliente no despachante.
//! - O cliente cria uma seção de 64 KB e conecta pelo NtConnectPort com o
//!   PORT_VIEW dela, o REMOTE_PORT_VIEW e 8 bytes de informação de conexão
//!   (antes, o nome inexistente dá STATUS_OBJECT_NAME_NOT_FOUND e o PORT_VIEW
//!   com Length errado STATUS_INVALID_PARAMETER). O servidor recebe a
//!   LPC_CONNECTION_REQUEST (o tamanho, o PID do cliente, o ClientViewSize e
//!   os dados), aceita pelo NtAcceptConnectPort com o PortContext 0x1234, os
//!   dados da resposta e o REMOTE_PORT_VIEW (a vista do cliente no servidor)
//!   e chama o NtCompleteConnectPort. O cliente acorda com o handle, a
//!   informação da resposta, o MaxMessageLength e as duas bases da vista.
//! - O cliente escreve um marcador na vista e faz um NtRequestWaitReplyPort;
//!   o servidor recebe pelo NtReplyWaitReceivePort o LPC_REQUEST (sem o bit
//!   interno de continuação), o PortContext e o CLIENT_ID, lê o marcador pela
//!   vista no próprio espaço, impersona o cliente (NtImpersonateClientOfPort;
//!   um MessageId sem pedido dá STATUS_REPLY_MESSAGE_MISMATCH), consulta a
//!   porta (NtQueryInformationPort só zera o ReturnLength) e responde pelo
//!   NtReplyPort (a segunda resposta ao mesmo pedido dá
//!   STATUS_REPLY_MESSAGE_MISMATCH). O cliente recebe o LPC_REPLY.
//! - O cliente repete o pedido reaproveitando o buffer da resposta com Type
//!   0 (o MessageId e o CLIENT_ID antigos ficam, como no CsrClientCallServer);
//!   o servidor responde e recebe na mesma chamada o datagrama que o cliente
//!   manda depois (NtRequestPort, LPC_DATAGRAM) e, quando o cliente fecha a
//!   porta, o LPC_PORT_CLOSED com o PortContext.
//!
//! Cada programa sai com o próprio código, ou com o NTSTATUS de um serviço ou
//! o código da etapa que falhou. No fim nenhum dos dois fica no estado e o
//! nome da porta sai do namespace.

use alloc::format;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use super::pipes::Arg::{Addr, Imm, Load};
use super::pipes::{absolute, image, terminate_number, Asm, Data};
use crate::hal::amd64::usermode;
use crate::ntos::ex::{service_abi, service_table};
use crate::ntos::inc::types::{Eprocess, Ethread, NtStruct, PortMessage, PortView, RemotePortView};
use crate::ntos::ke::{clock, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_stack;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::create::{self, CreatedProcess, ImageOrigin};
use crate::ntos::ps::user::process::{self as user_process, RunOptions, StartedProcess};
use crate::ntos::ps::user::{csr, index, process_state, state, threads};
use crate::ntos::ps::{process, process_context, scheduler};

type Assert = fn(bool, &str);

const SERVER_CODE: u32 = 0x71;
const CLIENT_CODE: u32 = 0x72;
const WAIT_DEADLINE_MS: u64 = 10_000;

const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
const STATUS_REPLY_MESSAGE_MISMATCH: u32 = 0xC000_021F;

/// Tipos de PORT_MESSAGE.
const LPC_REQUEST: u32 = 1;
const LPC_REPLY: u32 = 2;
const LPC_DATAGRAM: u32 = 3;
const LPC_PORT_CLOSED: u32 = 5;
const LPC_CONNECTION_REQUEST: u32 = 10;

const PORT_NAME: &str = "\\OpenNtLpcTeste";
const MAXIMUM_MESSAGE: u64 = 0x148;
const VIEW_SIZE: u64 = 0x1_0000;
const PORT_CONTEXT: u32 = 0x1234;
/// Um PORT_MESSAGE com espaço para os dados.
const MESSAGE: usize = PortMessage::SIZE as usize + 0x100;
/// SECTION_ALL_ACCESS, PAGE_READWRITE e SEC_COMMIT.
const SECTION_ALL_ACCESS: u64 = 0xF_001F;
const PAGE_READWRITE: u64 = 4;
const SEC_COMMIT: u64 = 0x800_0000;

/// Os serviços encaminhados, na ordem da tabela de teste (índices 0x1000..).
const FORWARDED: [&str; 13] = [
    "NtCreatePort",
    "NtListenPort",
    "NtAcceptConnectPort",
    "NtCompleteConnectPort",
    "NtReplyWaitReceivePort",
    "NtReplyPort",
    "NtImpersonateClientOfPort",
    "NtQueryInformationPort",
    "NtConnectPort",
    "NtRequestWaitReplyPort",
    "NtRequestPort",
    "NtClose",
    "NtCreateSection",
];
const CREATE_PORT: u32 = 0x1000;
const LISTEN: u32 = 0x1001;
const ACCEPT: u32 = 0x1002;
const COMPLETE: u32 = 0x1003;
const REPLY_WAIT_RECEIVE: u32 = 0x1004;
const REPLY: u32 = 0x1005;
const IMPERSONATE: u32 = 0x1006;
const QUERY_INFORMATION: u32 = 0x1007;
const CONNECT: u32 = 0x1008;
const REQUEST_WAIT_REPLY: u32 = 0x1009;
const REQUEST: u32 = 0x100A;
const CLOSE: u32 = 0x100B;
const CREATE_SECTION: u32 = 0x100C;

static SERVICE_TABLE: [AtomicU32; 13] = [const { AtomicU32::new(0) }; 13];
static SERVICE_ARGUMENTS: [AtomicU8; 13] = [const { AtomicU8::new(0) }; 13];

/// Encaminha ao handler real, como o portão nativo: a pilha do usuário
/// (KPCR.UserRsp, de onde saem os argumentos 5 em diante) e o registro de
/// serviço da thread.
fn forward(name: &'static str, arguments: [u64; 4]) -> u64 {
    let rsp = pcr::current().user_rsp.get();
    let record = state::SyscallRecord { raw_arguments: 0, stack: Some(state::ServiceStack { rsp, bytes: service_abi::stack_arguments(name).unwrap_or(0) as u64 * 8 }) };
    let result = state::with_syscall_record(record, || index::invoke_service(name, arguments, 0, rsp));
    result.unwrap_or_else(|error| if error.status != 0 { error.status } else { 0xC000_0001 }) as u64
}

macro_rules! forwarders {
    ($($routine:ident = $index:expr;)*) => {
        $(
            extern "win64" fn $routine(a: u64, b: u64, c: u64, d: u64) -> u64 {
                forward(FORWARDED[$index], [a, b, c, d])
            }
        )*
        const ROUTINES: [extern "win64" fn(u64, u64, u64, u64) -> u64; 13] = [$($routine),*];
    };
}

forwarders! {
    create_port_service = 0;
    listen_service = 1;
    accept_service = 2;
    complete_service = 3;
    reply_wait_receive_service = 4;
    reply_service = 5;
    impersonate_service = 6;
    query_information_service = 7;
    connect_service = 8;
    request_wait_reply_service = 9;
    request_service = 10;
    close_service = 11;
    create_section_service = 12;
}

/// Publica a tabela 1 de teste; devolve a anterior, para restaurar.
fn publish_services() -> Option<[u64; 4]> {
    let saved = service_table::shadow_second_table().ok()?;
    let table = SERVICE_TABLE.as_ptr() as u64;
    for (slot, routine) in SERVICE_TABLE.iter().zip(ROUTINES) {
        match service_table::encode_entry(table, routine as usize as u64, 0) {
            Ok(entry) => slot.store(entry, Ordering::Release),
            Err(_) => return None,
        }
    }
    if service_table::publish_shadow_second_table(table, SERVICE_TABLE.len() as u32, SERVICE_ARGUMENTS.as_ptr() as u64).is_err() {
        let _ = service_table::restore_shadow_second_table(saved);
        return None;
    }
    Some(saved)
}

fn restore_services(saved: [u64; 4]) {
    let _ = service_table::restore_shadow_second_table(saved);
    for slot in &SERVICE_TABLE {
        slot.store(0, Ordering::Release);
    }
}

// ---- instruções além do montador comum -----------------------------------------

/// Copia `length` bytes de `source` para `target` (rep movsb).
fn copy(asm: &mut Asm, source: usize, target: usize, length: u32) {
    asm.rip(&[0x48, 0x8D, 0x35], source);
    asm.rip(&[0x48, 0x8D, 0x3D], target);
    asm.put(&[0xB9]);
    asm.imm32(length);
    asm.put(&[0xF3, 0xA4]);
}

/// A célula de 32 bits recebe `value`.
fn store_u32(asm: &mut Asm, cell: usize, value: u32) {
    asm.put(&[0xB8]);
    asm.imm32(value);
    asm.rip(&[0x89, 0x05], cell);
}

/// A célula de 64 bits `target` recebe o valor de `source`.
fn store_cell(asm: &mut Asm, source: usize, target: usize) {
    asm.rip(&[0x48, 0x8B, 0x05], source);
    asm.rip(&[0x48, 0x89, 0x05], target);
}

/// A célula de 64 bits não é zero.
fn check_nonzero(asm: &mut Asm, cell: usize, step: u32) {
    asm.rip(&[0x48, 0x8B, 0x05], cell);
    asm.put(&[0x48, 0x85, 0xC0]);
    asm.step_on(0x84, step);
}

/// Os `length` bytes no endereço guardado na célula `pointer` são os de
/// `expected` (repe cmpsb).
fn check_through(asm: &mut Asm, pointer: usize, expected: usize, length: u32, step: u32) {
    asm.rip(&[0x48, 0x8B, 0x35], pointer);
    asm.rip(&[0x48, 0x8D, 0x3D], expected);
    asm.put(&[0xB9]);
    asm.imm32(length);
    asm.put(&[0xF3, 0xA6]);
    asm.step_on(0x85, step);
}

/// Copia `length` bytes de `source` para o endereço guardado na célula
/// `pointer`.
fn copy_through(asm: &mut Asm, source: usize, pointer: usize, length: u32) {
    asm.rip(&[0x48, 0x8D, 0x35], source);
    asm.rip(&[0x48, 0x8B, 0x3D], pointer);
    asm.put(&[0xB9]);
    asm.imm32(length);
    asm.put(&[0xF3, 0xA4]);
}

/// Um PORT_MESSAGE de pedido com `data` (Type 0).
fn message(data: &mut Data, payload: &[u8]) -> usize {
    let at = data.alloc(MESSAGE, 8);
    let mut header = alloc::vec![0u8; PortMessage::SIZE as usize];
    header[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    header[2..4].copy_from_slice(&((PortMessage::SIZE as usize + payload.len()) as u16).to_le_bytes());
    data.put(at, &header);
    data.put(at + PortMessage::SIZE as usize, payload);
    at
}

/// O dword de Type (com DataInfoOffset zero) e o de comprimentos.
fn lengths(data_length: u32) -> u32 {
    data_length | (data_length + PortMessage::SIZE as u32) << 16
}

const TYPE: usize = core::mem::offset_of!(PortMessage, u2);
const CLIENT_PROCESS: usize = core::mem::offset_of!(PortMessage, client_id.unique_process);
const CLIENT_VIEW_SIZE: usize = core::mem::offset_of!(PortMessage, client_view_size);
const DATA: usize = PortMessage::SIZE as usize;

// ---- o servidor ----------------------------------------------------------------

/// As células do servidor que o teste preenche antes de ele rodar.
struct ServerCells {
    client_id: usize,
}

fn server_program(terminate: u32) -> (Vec<u8>, ServerCells) {
    let mut data = Data::new();
    let name = data.attributes(PORT_NAME);
    let port = data.u64(0);
    let again = data.u64(0);
    let communication = data.u64(0);
    let context = data.u64(0);
    let received = data.alloc(MESSAGE, 8);
    let second = data.alloc(MESSAGE, 8);
    let remote = data.alloc(RemotePortView::SIZE as usize, 8);
    data.put(remote, &(RemotePortView::SIZE as u32).to_le_bytes());
    let unknown = message(&mut data, b"x");
    data.put(unknown + core::mem::offset_of!(PortMessage, message_id), &0x7777u32.to_le_bytes());
    let information = data.alloc(0x10, 8);
    let returned = data.u64(0xFFFF_FFFF);
    let client_id = data.u64(0);
    let connect = data.bytes(b"conectar");
    let accepted = data.bytes(b"aceito!!");
    let marker = data.bytes(b"vista do cliente");
    let ping = data.bytes(b"ping");
    let pong = data.bytes(b"pong");
    let datagram = data.bytes(b"dgrm");
    let remote_base = remote + core::mem::offset_of!(RemotePortView, view_base);

    let mut asm = Asm::new(terminate);
    asm.checked(CREATE_PORT, &[Addr(port), Addr(name), Imm(0x100), Imm(0x289), Imm(0)], STATUS_INVALID_PARAMETER);
    asm.checked(CREATE_PORT, &[Addr(port), Addr(name), Imm(0x100), Imm(MAXIMUM_MESSAGE), Imm(0)], STATUS_SUCCESS);
    asm.checked(CREATE_PORT, &[Addr(again), Addr(name), Imm(0x100), Imm(MAXIMUM_MESSAGE), Imm(0)], STATUS_OBJECT_NAME_COLLISION);
    // Escuta: bloqueia até o cliente conectar.
    asm.checked(LISTEN, &[Load(port), Addr(received)], STATUS_SUCCESS);
    asm.check_u32(received + TYPE, LPC_CONNECTION_REQUEST, 1);
    asm.check_u32(received, lengths(8), 2);
    asm.check_cells(received + CLIENT_PROCESS, client_id, 3);
    asm.check_u32(received + CLIENT_VIEW_SIZE, VIEW_SIZE as u32, 4);
    asm.check_bytes(received + DATA, connect, 8, 5);
    // A aceitação com os dados da resposta e a vista do cliente no servidor.
    copy(&mut asm, accepted, received + DATA, 8);
    asm.checked(ACCEPT, &[Addr(communication), Imm(PORT_CONTEXT as u64), Addr(received), Imm(1), Imm(0), Addr(remote)], STATUS_SUCCESS);
    asm.check_u32(remote + core::mem::offset_of!(RemotePortView, view_size), VIEW_SIZE as u32, 6);
    check_nonzero(&mut asm, remote_base, 7);
    asm.checked(COMPLETE, &[Load(communication)], STATUS_SUCCESS);
    // O pedido do cliente: LPC_REQUEST com o PortContext e o CLIENT_ID.
    asm.checked(REPLY_WAIT_RECEIVE, &[Load(port), Addr(context), Imm(0), Addr(received)], STATUS_SUCCESS);
    asm.check_u32(received + TYPE, LPC_REQUEST, 8);
    asm.check_u32(context, PORT_CONTEXT, 9);
    asm.check_cells(received + CLIENT_PROCESS, client_id, 10);
    asm.check_bytes(received + DATA, ping, 4, 11);
    // O marcador que o cliente escreveu na vista, lido pela vista do servidor.
    check_through(&mut asm, remote_base, marker, 16, 12);
    asm.checked(IMPERSONATE, &[Load(communication), Addr(received)], STATUS_SUCCESS);
    asm.checked(IMPERSONATE, &[Load(communication), Addr(unknown)], STATUS_REPLY_MESSAGE_MISMATCH);
    asm.checked(QUERY_INFORMATION, &[Load(communication), Imm(0), Addr(information), Imm(0x10), Addr(returned)], STATUS_SUCCESS);
    asm.check_u32(returned, 0, 13);
    // A resposta, e a segunda resposta ao mesmo pedido.
    copy(&mut asm, pong, received + DATA, 4);
    asm.checked(REPLY, &[Load(communication), Addr(received)], STATUS_SUCCESS);
    asm.checked(REPLY, &[Load(communication), Addr(received)], STATUS_REPLY_MESSAGE_MISMATCH);
    // O pedido com o buffer reaproveitado.
    asm.checked(REPLY_WAIT_RECEIVE, &[Load(port), Addr(context), Imm(0), Addr(received)], STATUS_SUCCESS);
    asm.check_u32(received + TYPE, LPC_REQUEST, 14);
    asm.check_bytes(received + DATA, ping, 4, 15);
    // Responde e recebe na mesma chamada: o datagrama.
    copy(&mut asm, pong, received + DATA, 4);
    asm.checked(REPLY_WAIT_RECEIVE, &[Load(communication), Addr(context), Addr(received), Addr(second)], STATUS_SUCCESS);
    asm.check_u32(second + TYPE, LPC_DATAGRAM, 16);
    asm.check_bytes(second + DATA, datagram, 4, 17);
    asm.check_u32(context, PORT_CONTEXT, 18);
    // O fechamento da porta do cliente.
    asm.checked(REPLY_WAIT_RECEIVE, &[Load(port), Addr(context), Imm(0), Addr(second)], STATUS_SUCCESS);
    asm.check_u32(second + TYPE, LPC_PORT_CLOSED, 19);
    asm.check_u32(context, PORT_CONTEXT, 20);
    asm.checked(CLOSE, &[Load(communication)], STATUS_SUCCESS);
    asm.checked(CLOSE, &[Load(port)], STATUS_SUCCESS);
    asm.exit(SERVER_CODE);
    (image(&asm.finish(&data)), ServerCells { client_id })
}

// ---- o cliente -----------------------------------------------------------------

fn client_program(terminate: u32) -> Vec<u8> {
    let mut data = Data::new();
    let name = data.unicode(PORT_NAME);
    let missing = data.unicode("\\OpenNtLpcInexistente");
    let section = data.u64(0);
    let size = data.u64(VIEW_SIZE);
    let port = data.u64(0);
    // SECURITY_QUALITY_OF_SERVICE: SecurityImpersonation, dinâmico.
    let qos = data.bytes(&[12, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0]);
    let view = data.alloc(PortView::SIZE as usize, 8);
    let mut block = alloc::vec![0u8; PortView::SIZE as usize];
    block[0..4].copy_from_slice(&(PortView::SIZE as u32).to_le_bytes());
    block[0x18..0x20].copy_from_slice(&VIEW_SIZE.to_le_bytes());
    data.put(view, &block);
    let wrong = data.alloc(PortView::SIZE as usize, 8);
    block[0..4].copy_from_slice(&(PortView::SIZE as u32 - 1).to_le_bytes());
    data.put(wrong, &block);
    let server_view = data.alloc(RemotePortView::SIZE as usize, 8);
    data.put(server_view, &(RemotePortView::SIZE as u32).to_le_bytes());
    let maximum = data.u64(0);
    let information = data.alloc(16, 8);
    data.put(information, b"conectar");
    let information_length = data.u64(8);
    let request = message(&mut data, b"ping");
    let reply = data.alloc(MESSAGE, 8);
    let datagram = message(&mut data, b"dgrm");
    let marker = data.bytes(b"vista do cliente");
    let accepted = data.bytes(b"aceito!!");
    let ping = data.bytes(b"ping");
    let pong = data.bytes(b"pong");
    let view_base = view + core::mem::offset_of!(PortView, view_base);

    let mut asm = Asm::new(terminate);
    asm.checked(CREATE_SECTION, &[Addr(section), Imm(SECTION_ALL_ACCESS), Imm(0), Addr(size), Imm(PAGE_READWRITE), Imm(SEC_COMMIT), Imm(0)], STATUS_SUCCESS);
    store_cell(&mut asm, section, view + core::mem::offset_of!(PortView, section_handle));
    store_cell(&mut asm, section, wrong + core::mem::offset_of!(PortView, section_handle));
    asm.checked(CONNECT, &[Addr(port), Addr(missing), Addr(qos), Imm(0), Imm(0), Imm(0), Imm(0), Imm(0)], STATUS_OBJECT_NAME_NOT_FOUND);
    asm.checked(CONNECT, &[Addr(port), Addr(name), Addr(qos), Addr(wrong), Imm(0), Imm(0), Imm(0), Imm(0)], STATUS_INVALID_PARAMETER);
    // A conexão: bloqueia até o servidor aceitar.
    asm.checked(CONNECT, &[Addr(port), Addr(name), Addr(qos), Addr(view), Addr(server_view), Addr(maximum), Addr(information), Addr(information_length)], STATUS_SUCCESS);
    asm.check_u32(information_length, 8, 1);
    asm.check_bytes(information, accepted, 8, 2);
    asm.check_u32(maximum, MAXIMUM_MESSAGE as u32, 3);
    check_nonzero(&mut asm, view_base, 4);
    check_nonzero(&mut asm, view + core::mem::offset_of!(PortView, view_remote_base), 5);
    asm.check_u32(view + core::mem::offset_of!(PortView, view_size), VIEW_SIZE as u32, 6);
    asm.check_u32(server_view + core::mem::offset_of!(RemotePortView, view_size), 0, 7);
    // O marcador na vista do cliente, que o servidor lê pela vista dele.
    copy_through(&mut asm, marker, view_base, 16);
    asm.checked(REQUEST_WAIT_REPLY, &[Load(port), Addr(request), Addr(reply)], STATUS_SUCCESS);
    asm.check_u32(reply + TYPE, LPC_REPLY, 8);
    asm.check_bytes(reply + DATA, pong, 4, 9);
    // O mesmo buffer como pedido: Type 0, MessageId e CLIENT_ID antigos.
    store_u32(&mut asm, reply + TYPE, 0);
    copy(&mut asm, ping, reply + DATA, 4);
    asm.checked(REQUEST_WAIT_REPLY, &[Load(port), Addr(reply), Addr(reply)], STATUS_SUCCESS);
    asm.check_u32(reply + TYPE, LPC_REPLY, 10);
    asm.check_bytes(reply + DATA, pong, 4, 11);
    asm.checked(REQUEST, &[Load(port), Addr(datagram)], STATUS_SUCCESS);
    asm.checked(CLOSE, &[Load(port)], STATUS_SUCCESS);
    asm.checked(CLOSE, &[Load(section)], STATUS_SUCCESS);
    asm.exit(CLIENT_CODE);
    image(&asm.finish(&data))
}

// ---- o teste -------------------------------------------------------------------

fn process_id(process: u64) -> u64 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.unique_process_id.get()
}

fn exit_status(process: u64) -> u32 {
    // SAFETY: EPROCESS retido pelo teste.
    unsafe { Eprocess::at(process) }.exit_status.get() as u32
}

/// Põe um processo criado no despachante, com a thread principal GUI (os
/// serviços de teste entram pela tabela 1 do Shadow).
fn launch(created: CreatedProcess) -> Option<StartedProcess> {
    // SAFETY: a ETHREAD da thread principal, viva enquanto o processo vive.
    unsafe { Ethread::at(created.thread_pointer) }.tcb.set_gui_thread(1);
    match user_process::start_created(created) {
        Ok(started) => Some(started),
        Err(error) => {
            crate::debug_print!("[lpc] nao partiu: {}", error);
            None
        }
    }
}

/// Alguma conferência deste teste falhou.
static FAILED: AtomicBool = AtomicBool::new(false);

fn check(assert: Assert, condition: bool, message: &str) {
    if !condition {
        FAILED.store(true, Ordering::SeqCst);
    }
    assert(condition, message);
}

/// O teste inteiro; `LPC_PORTS_OK` sai só se todas as conferências passarem.
pub fn run(assert: Assert) {
    FAILED.store(false, Ordering::SeqCst);
    body(assert);
    if !FAILED.load(Ordering::SeqCst) {
        crate::debug_print!("LPC_PORTS_OK");
    }
}

fn body(assert: Assert) {
    if !usermode::ready() || process::get_current_thread() == 0 {
        check(assert, false, "lpc: anel 3 armado e thread corrente");
        return;
    }
    if state::with(|state| state.ntdll_exports.as_ref().is_none_or(|exports| !exports.contains_key("LdrInitializeThunk"))) {
        check(assert, false, "lpc: ntdll com LdrInitializeThunk mapeada");
        return;
    }
    let Some(terminate) = terminate_number() else {
        check(assert, false, "lpc: numero do NtTerminateProcess");
        return;
    };
    let _ = csr::initialize();
    let Some(saved) = publish_services() else {
        check(assert, false, "lpc: tabela 1 de teste com os servicos encaminhados");
        return;
    };
    scenario(assert, terminate);
    restore_services(saved);
    kernel_stack::reap();
}

fn scenario(assert: Assert, terminate: u32) {
    let (server_image, cells) = server_program(terminate);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(server_image), "servidor-lpc.exe", "C:\\servidor-lpc.exe", &RunOptions::default());
    let server = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            check(assert, false, &format!("lpc: servidor criado ({failure})"));
            return;
        }
    };
    let server_pointer = server.process_pointer;
    process::reference(server_pointer);
    let request = user_process::windows_process_request(ImageOrigin::Bytes(client_program(terminate)), "cliente-lpc.exe", "C:\\cliente-lpc.exe", &RunOptions::default());
    let client = match create::create_user_process(&request) {
        Ok(created) => created,
        Err(failure) => {
            check(assert, false, &format!("lpc: cliente criado ({failure})"));
            drop(server);
            let _ = process::dereference(server_pointer);
            return;
        }
    };
    let client_pointer = client.process_pointer;
    process::reference(client_pointer);
    let client_id = process_id(client_pointer);
    let _ = process_context::with_process(server_pointer, || guest::write64(absolute(cells.client_id), client_id));

    let Some(server_started) = launch(server) else {
        check(assert, false, "lpc: servidor posto no despachante");
        drop(client);
        let _ = process::dereference(client_pointer);
        let _ = process::dereference(server_pointer);
        return;
    };
    // O servidor anda só pelo tick até bloquear no NtListenPort.
    let main = threads::of_process(server_pointer).first().cloned();
    let listening = || main.as_ref().is_some_and(|thread| thread.waiting() && thread.blocked_in_kernel()) && object_manager::lookup(PORT_NAME).is_some();
    let deadline = clock::uptime_ms() + WAIT_DEADLINE_MS;
    while clock::uptime_ms() < deadline && process_state::get(server_pointer).is_some() && !listening() {
        scheduler::tick(-1);
    }
    let blocked = listening();
    crate::debug_print!("[lpc] servidor bloqueado no NtListenPort={} (saida {:#x})", blocked, exit_status(server_pointer));
    check(assert, blocked, "lpc: o servidor cria a porta LPC em anel 3 (NtCreatePort, com as recusas do MaxMessageLength e do nome repetido) e bloqueia no kernel em NtListenPort");

    let client_started = if blocked {
        launch(client)
    } else {
        drop(client);
        None
    };
    if client_started.is_none() {
        let _ = create::exit_process(server_pointer, 0xC000_0001);
    }
    let server_exit = user_process::wait_started(server_started);
    let client_exit = client_started.map(user_process::wait_started);
    crate::debug_print!("[lpc] saidas: servidor {:?} cliente {:?}", server_exit.as_ref().map_err(|error| format!("{error}")), client_exit.as_ref().map(|exit| exit.as_ref().map_err(|error| format!("{error}"))));
    check(assert, matches!(client_exit, Some(Ok(CLIENT_CODE))) && exit_status(client_pointer) == CLIENT_CODE, "lpc: o cliente conecta com PORT_VIEW e informacao de conexao (NtConnectPort), recebe a resposta e as bases da vista, faz dois NtRequestWaitReplyPort (o segundo com o buffer da resposta reaproveitado) e um NtRequestPort");
    check(assert, matches!(server_exit, Ok(SERVER_CODE)) && exit_status(server_pointer) == SERVER_CODE, "lpc: o servidor recebe a conexao (NtListenPort), aceita com o REMOTE_PORT_VIEW (NtAcceptConnectPort, NtCompleteConnectPort), le a vista do cliente, impersona, consulta e responde (NtReplyPort, NtReplyWaitReceivePort) e recebe o datagrama e o LPC_PORT_CLOSED");
    let released = process_state::get(server_pointer).is_none() && process_state::get(client_pointer).is_none() && object_manager::lookup(PORT_NAME).is_none();
    check(assert, released, "lpc: nada dos dois fica no estado e o nome da porta sai do namespace");
    let _ = process::dereference(client_pointer);
    let _ = process::dereference(server_pointer);
}
