//! O servidor de comandos do Reference Monitor: a porta `\SeRmCommandPort`
//! e a thread de sistema que a atende, como no ntoskrnl 19041.
//!
//! - SeRmInitPhase1 (rva 0xa4ba3c, [`initialize_phase1`]): o ZwCreatePort da
//!   `\SeRmCommandPort` (MaxConnectionInfoLength 4, MaxMessageLength 0x200,
//!   MaxPoolUsage 0x4000) e o PsCreateSystemThread do servidor; o handle da
//!   thread é fechado em seguida.
//! - SepRmCommandServerThread (rva 0x7ad590, [`command_server_thread`]): o
//!   laço do ZwReplyWaitReceivePort, que leva a resposta do comando anterior
//!   e recebe o próximo PORT_MESSAGE (Type sem o bit 15). Um LPC_REQUEST com
//!   CommandNumber de 1 a 12 vai para o trabalhador da SepRmCommandDispatch,
//!   que grava o ReturnedStatus na resposta; a resposta leva o CLIENT_ID e o
//!   MessageId do pedido, com DataLength 0x1D8 e TotalLength 0x200. Um
//!   CommandNumber fora da tabela fica sem resposta. O LPC_CONNECTION_REQUEST
//!   é a conexão do LSA e o LPC_PORT_CLOSED o fim dela; os outros tipos são
//!   ignorados. As falhas 0xC0000001, 0xC000000B e 0xC000021F da recepção
//!   repetem a espera sem resposta.
//! - SepRmLsaConnectRequest (rva 0x7ad710, [`lsa_connect_request`]): o
//!   ZwOpenProcess do cliente (PROCESS_VM_OPERATION | PROCESS_VM_WRITE) pelo
//!   CLIENT_ID da mensagem; um segundo LSA, ou a falha da abertura, recebe a
//!   recusa (ZwAcceptConnectPort com AcceptConnection FALSE). O LSA é aceito
//!   com o PortContext -8 (o silo hospedeiro) e o REMOTE_PORT_VIEW, o
//!   ZwCompleteConnectPort acorda o lsass, e o Reference Monitor conecta de
//!   volta à `\SeLsaCommandPort` dele (ZwConnectPort com o QOS de
//!   impersonação, rastreamento dinâmico e só o efetivo), que precisa
//!   devolver o MaxMessageLength 0x200. Uma falha depois da aceitação limpa o
//!   estado (SepRmCleanupRmLsaState). O estado é a
//!   SEP_RM_LSA_CONNECTION_STATE do silo hospedeiro (o OpenNT não cria
//!   silos de servidor).
//!
//! Os trabalhadores: RmAuditSetCommand (1, a política de auditoria em
//! `se/audit.rs`), RmCreateLogonSession (2) e RmDeleteLogonSession (3, as
//! sessões de logon em `se/logon_session.rs`). Os comandos 4 a 12
//! (informação da sessão, SACL global, políticas de acesso central,
//! auditoria da linha de comando, logoff interativo, sessões irmãs, LUID
//! único do processo e sessão de usuário compartilhada) respondem
//! STATUS_NOT_SUPPORTED, com registro.
//!
//! Lacunas: a conexão de volta não leva o PORT_VIEW de 4 KB (a seção que o
//! SepRmCallLsa usa para dados grandes; o ZwSecureConnectPort de kernel do
//! OpenNT não monta vistas), e o SepRmCallLsa (os comandos do Reference
//! Monitor ao LSA) ainda não existe. O SepRmVerifyLsaProtectionLevel lê a
//! variável de firmware de proteção do LSA, que um boot por BIOS não tem, e
//! não muda nada.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::alpc::lpc;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_obpsse::{RmCommandMessage, RmReplyMessage};
use crate::ntos::inc::types::{Luid, ObjectAttributes, PortMessage, SecurityImpersonationLevel, SecurityQualityOfService, SepRmLsaConnectionState};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_manager, open_pointer};
use crate::ntos::ps::{kernel_threads, open as ps_open};
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::{audit, logon_session};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const COMMAND_PORT_NAME: &str = "\\SeRmCommandPort";
const LSA_COMMAND_PORT_NAME: &str = "\\SeLsaCommandPort";
/// O MaxMessageLength das duas portas (o PORT_MAXIMUM_MESSAGE_LENGTH x64).
const MAXIMUM_MESSAGE_LENGTH: u32 = 0x200;
/// DataLength e TotalLength de uma resposta.
const REPLY_DATA_LENGTH: i16 = 0x1D8;
const REPLY_TOTAL_LENGTH: i16 = 0x200;
/// Tipos de PORT_MESSAGE.
const LPC_REQUEST: u16 = 1;
const LPC_PORT_CLOSED: u16 = 5;
const LPC_CONNECTION_REQUEST: u16 = 10;
/// RM_COMMAND_NUMBER.
const RM_AUDIT_SET_COMMAND: u32 = 1;
const RM_CREATE_LOGON_SESSION: u32 = 2;
const RM_DELETE_LOGON_SESSION: u32 = 3;
const RM_LAST_COMMAND: u32 = 12;
/// O PortContext da conexão do LSA no silo hospedeiro.
const HOST_SILO_CONTEXT: u64 = (-8i64) as u64;
/// PROCESS_VM_OPERATION | PROCESS_VM_WRITE.
const LSA_PROCESS_ACCESS: u32 = 0x28;
/// OBJ_KERNEL_HANDLE.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const THREAD_ALL_ACCESS: u32 = 0x1F_FFFF;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_CID: u32 = 0xC000_000B;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_REPLY_MESSAGE_MISMATCH: u32 = 0xC000_021F;

/// O handle de kernel da `\SeRmCommandPort`.
static COMMAND_PORT: AtomicU64 = AtomicU64::new(0);
/// A SEP_RM_LSA_CONNECTION_STATE do silo hospedeiro.
static CONNECTION_STATE: AtomicU64 = AtomicU64::new(0);

/// UNICODE_STRING de kernel com o texto (o buffer logo depois dela).
fn kernel_unicode_string(text: &str) -> u64 {
    let units = text.encode_utf16().count() as u64;
    let block = guest::alloc_bytes(16 + units * 2 + 2);
    if block != 0 {
        guest_strings::write_wide_string(block + 16, text);
        guest_strings::write_string_fields(block, (units * 2) as u16, (units * 2 + 2) as u16, block + 16);
    }
    block
}

/// Um bloco de kernel zerado.
fn zeroed(size: u64) -> Result<u64, KernelError> {
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return Err(KernelError::new("Reference Monitor: sem memoria"));
    }
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    Ok(block)
}

fn connection_state() -> Option<&'static SepRmLsaConnectionState> {
    let address = CONNECTION_STATE.load(Ordering::Acquire);
    // SAFETY: o bloco zerado de initialize_phase1, que vive enquanto o sistema roda.
    (address != 0).then(|| unsafe { SepRmLsaConnectionState::at(address) })
}

/// O handle de kernel da `\SeRmCommandPort` (0 antes do SeRmInitPhase1).
pub fn command_port() -> u64 {
    COMMAND_PORT.load(Ordering::Acquire)
}

/// O processo do LSA conectado (o handle de kernel; 0 sem conexão).
pub fn lsa_process_handle() -> u64 {
    connection_state().map_or(0, |state| state.lsa_process_handle.get())
}

/// SeRmInitPhase1: a porta de comandos e a thread do servidor.
pub fn initialize_phase1() -> Result<(), KernelError> {
    if COMMAND_PORT.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let state = zeroed(SepRmLsaConnectionState::SIZE)?;
    let name = kernel_unicode_string(COMMAND_PORT_NAME);
    let block = zeroed(ObjectAttributes::SIZE + 8)?;
    if name == 0 {
        return Err(KernelError::new("Reference Monitor: sem memoria"));
    }
    let (attributes_address, handle_cell) = (block, block + ObjectAttributes::SIZE);
    // SAFETY: bloco zerado com o tamanho do OBJECT_ATTRIBUTES.
    let attributes = unsafe { ObjectAttributes::at(attributes_address) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.object_name.set(name);
    attributes.attributes.set(OBJ_KERNEL_HANDLE);
    let status = lpc::create_port(handle_cell, attributes_address, MAXIMUM_MESSAGE_LENGTH)?;
    let handle = guest::read64(handle_cell);
    guest::free_bytes(block);
    guest::free_bytes(name);
    if status != 0 {
        guest::free_bytes(state);
        return Err(KernelError::with_status(alloc::format!("ZwCreatePort {COMMAND_PORT_NAME}: {status:#x}"), status));
    }
    CONNECTION_STATE.store(state, Ordering::Release);
    COMMAND_PORT.store(handle, Ordering::Release);
    let entry: extern "win64" fn(u64) = command_server_thread;
    let start = crate::ntos::mm::kernel_address::image_address(entry as usize as u64)?;
    let thread = kernel_threads::create_system_thread(0, start, 0, THREAD_ALL_ACCESS, 0, None)?;
    let _ = object_manager::close(thread as u32);
    crate::debug_print!("[se] Reference Monitor: {} criada (handle {:#x}) e thread do servidor de comandos", COMMAND_PORT_NAME, handle);
    Ok(())
}

/// SepRmCommandServerThread.
extern "win64" fn command_server_thread(_context: u64) {
    if let Err(error) = serve() {
        crate::debug_print!("[se] servidor de comandos do Reference Monitor parou: {}", error);
    }
}

fn serve() -> Result<(), KernelError> {
    let port = COMMAND_PORT.load(Ordering::Acquire);
    let block = zeroed(RmCommandMessage::SIZE + RmReplyMessage::SIZE + 8)?;
    let (request_address, reply_address, context_cell) = (block, block + RmCommandMessage::SIZE, block + RmCommandMessage::SIZE + RmReplyMessage::SIZE);
    // SAFETY: os três pedaços do bloco zerado, com os tamanhos dos tipos.
    let (request, reply) = unsafe { (RmCommandMessage::at(request_address), RmReplyMessage::at(reply_address)) };
    reply.message_header.u1.s1.data_length.set(REPLY_DATA_LENGTH);
    reply.message_header.u1.s1.total_length.set(REPLY_TOTAL_LENGTH);
    let mut pending_reply = 0;
    loop {
        request.message_header.u1.s1.data_length.set(REPLY_DATA_LENGTH);
        request.message_header.u1.s1.total_length.set(REPLY_TOTAL_LENGTH);
        let status = lpc::reply_wait_receive_port(port, context_cell, pending_reply, request_address)?;
        pending_reply = 0;
        if matches!(status, STATUS_UNSUCCESSFUL | STATUS_INVALID_CID | STATUS_REPLY_MESSAGE_MISMATCH) {
            continue;
        }
        if status & 0x8000_0000 != 0 {
            crate::debug_print!("[se] Reference Monitor: ZwReplyWaitReceivePort -> {:#x}", status);
        }
        match request.message_header.u2.s2.type_.get() as u16 & 0x7FFF {
            LPC_REQUEST => {
                let command = request.command_number.get();
                if !(1..=RM_LAST_COMMAND).contains(&command) {
                    continue;
                }
                dispatch(command, request, reply);
                let header: &PortMessage = &request.message_header;
                reply.message_header.client_id.unique_process.set(header.client_id.unique_process.get());
                reply.message_header.client_id.unique_thread.set(header.client_id.unique_thread.get());
                reply.message_header.message_id.set(header.message_id.get());
                pending_reply = reply_address;
            }
            LPC_PORT_CLOSED => lsa_closed(),
            LPC_CONNECTION_REQUEST => {
                if let Err(error) = lsa_connect_request(request_address) {
                    crate::debug_print!("[se] Reference Monitor: conexao do LSA: {}", error);
                }
            }
            _ => {}
        }
    }
}

/// O LUID dos parâmetros do comando (RmCreateLogonSession e
/// RmDeleteLogonSession).
fn logon_id(request: &RmCommandMessage) -> u64 {
    // SAFETY: o LUID no começo dos CommandParams, alinhado a 4.
    tokens::luid_value(unsafe { Luid::at(request.command_params[0].address()) })
}

/// A tabela SepRmCommandDispatch.
fn dispatch(command: u32, request: &RmCommandMessage, reply: &RmReplyMessage) {
    let status = match command {
        RM_AUDIT_SET_COMMAND => {
            let mut policy = [0u16; audit::LSA_POLICY_SUBCATEGORIES];
            for (index, slot) in policy.iter_mut().enumerate() {
                *slot = u16::from_le_bytes([request.command_params[index * 2].get(), request.command_params[index * 2 + 1].get()]);
            }
            audit::set_policy_from_lsa(&policy);
            0
        }
        RM_CREATE_LOGON_SESSION => logon_session::create_track(logon_id(request)),
        RM_DELETE_LOGON_SESSION => logon_session::delete_track(logon_id(request)),
        _ => {
            crate::debug_print!("[se] Reference Monitor: comando {} sem suporte", command);
            STATUS_NOT_SUPPORTED
        }
    };
    crate::debug_print!("[se] Reference Monitor: comando {} -> {:#x}", command, status);
    reply.returned_status.set(status);
}

/// SepRmLsaConnectRequest.
fn lsa_connect_request(request: u64) -> Result<(), KernelError> {
    let Some(state) = connection_state() else { return Err(KernelError::new("sem estado de conexao")) };
    let block = zeroed(ObjectAttributes::SIZE + 8 + 0x18 + 0x10 + 8)?;
    let (attributes_address, process_cell, remote_view, qos_address, length_cell) = (block, block + ObjectAttributes::SIZE, block + ObjectAttributes::SIZE + 8, block + ObjectAttributes::SIZE + 0x20, block + ObjectAttributes::SIZE + 0x30);
    let result = (|| -> Result<(), KernelError> {
        // SAFETY: bloco zerado com o tamanho do OBJECT_ATTRIBUTES.
        unsafe { ObjectAttributes::at(attributes_address) }.length.set(ObjectAttributes::SIZE as u32);
        let client_id = request + core::mem::offset_of!(PortMessage, client_id) as u64;
        let opened = ps_open::open_process(process_cell, LSA_PROCESS_ACCESS, attributes_address, client_id)? as u32;
        let process_handle = guest::read64(process_cell);
        if opened != 0 || state.lsa_process_handle.get() != 0 {
            if opened == 0 {
                let _ = open_pointer::close(process_handle);
            }
            crate::debug_print!("[se] Reference Monitor: conexao recusada (ZwOpenProcess {:#x}, LSA ja conectado: {})", opened, state.lsa_process_handle.get() != 0);
            let refused = lpc::accept_connect_port(process_cell, 0, request, false, 0, 0)?;
            return Err(KernelError::with_status(alloc::format!("recusa -> {refused:#x}"), opened));
        }
        state.lsa_process_handle.set(process_handle);
        // REMOTE_PORT_VIEW de 0x18 bytes.
        guest::write32(remote_view, 0x18);
        let accepted = lpc::accept_connect_port(state.rm_command_port_handle.address(), HOST_SILO_CONTEXT, request, true, 0, remote_view)?;
        if accepted != 0 {
            return Err(KernelError::with_status(alloc::format!("ZwAcceptConnectPort -> {accepted:#x}"), accepted));
        }
        let completed = lpc::complete_connect_port(state.rm_command_port_handle.get());
        if completed != 0 {
            return Err(KernelError::with_status(alloc::format!("ZwCompleteConnectPort -> {completed:#x}"), completed));
        }
        // A conexão de volta: o QOS do 19041 (Length 0, SecurityImpersonation,
        // rastreamento dinâmico, só o efetivo).
        // SAFETY: o pedaço zerado do bloco com o tamanho do QOS.
        let qos = unsafe { SecurityQualityOfService::at(qos_address) };
        qos.impersonation_level.set(SecurityImpersonationLevel(2));
        qos.context_tracking_mode.set(1);
        qos.effective_only.set(1);
        let name = kernel_unicode_string(LSA_COMMAND_PORT_NAME);
        if name == 0 {
            return Err(KernelError::new("sem memoria"));
        }
        let connected = lpc::secure_connect_port(state.lsa_command_port_handle.address(), name, qos_address, 0, 0, 0, length_cell, 0, 0);
        guest::free_bytes(name);
        let connected = connected?;
        if connected != 0 {
            return Err(KernelError::with_status(alloc::format!("ZwConnectPort {LSA_COMMAND_PORT_NAME} -> {connected:#x}"), connected));
        }
        let maximum = guest::read32(length_cell);
        if maximum != MAXIMUM_MESSAGE_LENGTH {
            return Err(KernelError::with_status(alloc::format!("MaxMessageLength {maximum:#x}"), STATUS_UNSUCCESSFUL));
        }
        crate::debug_print!("[se] Reference Monitor: LSA conectado (pid {}), conexao de volta a {} feita", guest::read64(client_id), LSA_COMMAND_PORT_NAME);
        crate::ntos::init::initial_process::lsa_connected(guest::read64(client_id));
        Ok(())
    })();
    if let Err(error) = &result {
        if state.lsa_process_handle.get() != 0 && error.status != 0 && state.rm_command_port_handle.get() != 0 {
            cleanup_lsa_state(state);
        }
    }
    guest::free_bytes(block);
    result
}

/// SepRmCleanupRmLsaState: os handles da conexão fechados e o estado
/// zerado.
fn cleanup_lsa_state(state: &SepRmLsaConnectionState) {
    for handle in [&state.lsa_command_port_handle, &state.rm_command_port_handle, &state.lsa_command_port_section_handle, &state.lsa_process_handle] {
        let value = handle.get();
        if value != 0 {
            let _ = open_pointer::close(value);
            handle.set(0);
        }
    }
    state.lsa_view_port_memory.set(0);
    state.rm_view_port_memory.set(0);
    state.lsa_command_port_memory_delta.set(0);
}

/// O LPC_PORT_CLOSED da conexão do LSA: o estado limpo. (O NT também zera o
/// SepRmAuditingEnabled, que nenhum portão de auditoria do OpenNT consulta.)
fn lsa_closed() {
    crate::debug_print!("[se] Reference Monitor: a conexao do LSA fechou");
    if let Some(state) = connection_state() {
        cleanup_lsa_state(state);
    }
}
