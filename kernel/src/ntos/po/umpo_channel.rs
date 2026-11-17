//! O canal ALPC do Power Manager com o serviço Power de modo usuário
//! (umpo.dll): o `\PowerPort` do PopUmpoInitializeChannel (ntoskrnl 19041,
//! rva 0xa6fe7c, chamado pelo PoInitSystem).
//!
//! - O PopUmpoInitializeChannel cria a porta de conexão `\PowerPort` pelo
//!   ZwAlpcCreatePort, com OBJ_KERNEL_HANDLE, um descritor cuja DACL dá
//!   GENERIC_ALL ao SYSTEM (o SeLocalSystemSid) e os atributos Flags 0x100000
//!   e MaxMessageLength 0x1000. Cria um objeto Callback sem nome
//!   (ExCreateCallback), registra nele o PopUmpoMessageCallback
//!   (ExRegisterCallback) e o liga à porta pelo NtAlpcSetInformation 9
//!   (AlpcRegisterCallbackInformation, de modo kernel). Depois drena a porta
//!   uma vez.
//! - A cada mensagem posta na fila da porta, o ALPC chama o callback no
//!   contexto de quem enviou; o PopUmpoMessageCallback chama o
//!   PopUmpoProcessMessages, que recebe da porta pelo
//!   ZwAlpcSendWaitReceivePort com prazo zero até a fila esvaziar
//!   (STATUS_TIMEOUT) e trata cada mensagem pelo tipo do PORT_MESSAGE: o
//!   pedido de conexão (LPC_CONNECTION_REQUEST) é aceito pelo
//!   ZwAlpcAcceptConnectPort só para o primeiro cliente (o
//!   PopUmpoAlpcClientConnected); o fim do cliente (LPC_PORT_CLOSED e
//!   LPC_CLIENT_DIED) libera o próximo.
//!
//! O conteúdo dos datagramas que o umpo manda (o PopUmpoProcessPowerMessage
//! de cada mensagem de energia) ainda não é interpretado: a mensagem é
//! recebida e descartada. O kernel também não manda mensagens ao umpo (o
//! PopUmpoSendPowerMessage).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::vec;

use crate::ntos::alpc::{kernel_entry, server};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{AlpcPortAttributes, ObjectAttributes, PortMessage};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::rtl::KernelError;

pub const PORT_NAME: &str = "\\PowerPort";
const OBJ_KERNEL_HANDLE: u32 = 0x200;
const GENERIC_ALL: u32 = 0x1000_0000;
/// Os atributos da porta de conexão do PopUmpoInitializeChannel.
const SERVER_PORT_FLAGS: u32 = 0x10_0000;
const MAXIMUM_MESSAGE_LENGTH: u64 = 0x1000;
/// AlpcRegisterCallbackInformation.
const ALPC_REGISTER_CALLBACK_INFORMATION: u32 = 9;
/// Os tipos de PORT_MESSAGE que o PopUmpoProcessMessage trata.
const LPC_CONNECTION_REQUEST: u16 = 10;
const LPC_PORT_CLOSED: u16 = 5;
const LPC_CLIENT_DIED: u16 = 6;
const STATUS_SUCCESS: u32 = 0;

/// PopAlpcServerPort e PopAlpcClientPort (handles de kernel).
static SERVER_PORT: AtomicU64 = AtomicU64::new(0);
static CLIENT_PORT: AtomicU64 = AtomicU64::new(0);
/// PopUmpoAlpcClientConnected.
static CLIENT_CONNECTED: AtomicBool = AtomicBool::new(false);

/// O cliente (o umpo do serviço Power) está conectado.
pub fn client_connected() -> bool {
    CLIENT_CONNECTED.load(Ordering::Acquire)
}

/// Um bloco de kernel zerado.
fn zeroed(size: u64) -> Result<u64, KernelError> {
    let block = guest::alloc_bytes(size);
    if block == 0 {
        return Err(KernelError::new("canal do umpo: sem memoria"));
    }
    guest::write_bytes(block, &vec![0u8; size as usize]);
    Ok(block)
}

/// OBJECT_ATTRIBUTES de kernel em `block`, com o nome (UNICODE_STRING e o
/// texto logo depois) e o descritor opcionais.
fn object_attributes(block: u64, name: Option<&str>, descriptor: u64) {
    // SAFETY: bloco zerado com o tamanho do OBJECT_ATTRIBUTES e espaço para o nome.
    let attributes = unsafe { ObjectAttributes::at(block) };
    attributes.length.set(ObjectAttributes::SIZE as u32);
    attributes.attributes.set(OBJ_KERNEL_HANDLE);
    attributes.security_descriptor.set(descriptor);
    if let Some(name) = name {
        let string = block + ObjectAttributes::SIZE;
        let units = name.encode_utf16().count() as u64;
        guest_strings::write_wide_string(string + 16, name);
        guest_strings::write_string_fields(string, (units * 2) as u16, (units * 2 + 2) as u16, string + 16);
        attributes.object_name.set(string);
    }
}

/// PopUmpoInitializeChannel.
pub fn initialize() -> Result<(), KernelError> {
    if SERVER_PORT.load(Ordering::Acquire) != 0 {
        return Ok(());
    }
    let policy = SecurityPolicy { dacl: Some(vec![Ace::allow(sid(5, &[18]), GENERIC_ALL)]), ..SecurityPolicy::default() };
    let descriptor_bytes = crate::ntos::se::object_security::encode(&policy, 4);
    let block = zeroed(0x200 + descriptor_bytes.len() as u64)?;
    let (attributes, port_attributes, handle_cell, information, descriptor) = (block, block + 0x80, block + 0xD0, block + 0xE0, block + 0x100);
    guest::write_bytes(descriptor, &descriptor_bytes);
    object_attributes(attributes, Some(PORT_NAME), descriptor);
    // SAFETY: o bloco zerado reserva os 0x48 bytes do ALPC_PORT_ATTRIBUTES.
    let port = unsafe { AlpcPortAttributes::at(port_attributes) };
    port.flags.set(SERVER_PORT_FLAGS);
    port.max_message_length.set(MAXIMUM_MESSAGE_LENGTH);
    let result = (|| -> Result<(), KernelError> {
        let status = crate::ntos::ps::previous_mode::with_kernel(|| server::create_port(handle_cell, attributes, port_attributes, 0))??;
        if status != STATUS_SUCCESS {
            return Err(KernelError::with_status(alloc::format!("ZwAlpcCreatePort {PORT_NAME}: {status:#x}"), status));
        }
        let server_port = guest::read64(handle_cell);
        SERVER_PORT.store(server_port, Ordering::Release);
        let callback = crate::ntos::ex::callbacks::create_internal(false)?;
        let entry: extern "win64" fn(u64, u64, u64) = message_callback;
        let function = crate::ntos::mm::kernel_address::image_address(entry as usize as u64)?;
        if crate::ntos::ex::callbacks::register(callback, function, 0)? == 0 {
            let _ = crate::ntos::ex::callbacks::dereference(callback);
            return Err(KernelError::with_status("ExRegisterCallback do PopUmpoMessageCallback", 0xC000_009A));
        }
        guest::write64(information, callback);
        guest::write64(information + 8, 0);
        let status = crate::ntos::alpc::resource::services::set_information(server_port, ALPC_REGISTER_CALLBACK_INFORMATION, information, 16, 0)?;
        let _ = crate::ntos::ex::callbacks::dereference(callback);
        if status != STATUS_SUCCESS {
            return Err(KernelError::with_status(alloc::format!("AlpcRegisterCallbackInformation: {status:#x}"), status));
        }
        Ok(())
    })();
    guest::free_bytes(block);
    result?;
    process_messages();
    crate::debug_print!("[po] {} criada (canal do servico Power de modo usuario)", PORT_NAME);
    Ok(())
}

/// PopUmpoMessageCallback(CallbackContext, Argument1, Argument2).
extern "win64" fn message_callback(_context: u64, _argument1: u64, _argument2: u64) {
    crate::debug_print!("[po] \\PowerPort: PopUmpoMessageCallback");
    process_messages();
}

/// PopUmpoProcessMessages: recebe da porta com prazo zero até a fila
/// esvaziar.
fn process_messages() {
    let server_port = SERVER_PORT.load(Ordering::Acquire);
    if server_port == 0 {
        return;
    }
    let Ok(block) = zeroed(MAXIMUM_MESSAGE_LENGTH + 0x20) else { return };
    let (message, length, timeout) = (block, block + MAXIMUM_MESSAGE_LENGTH, block + MAXIMUM_MESSAGE_LENGTH + 8);
    loop {
        guest::write64(length, MAXIMUM_MESSAGE_LENGTH);
        guest::write64(timeout, 0);
        let arguments = [server_port, 0, 0, 0, message, length, 0, timeout];
        let status = crate::ntos::ps::previous_mode::with_kernel(|| kernel_entry::send_wait_receive(&arguments)).ok().and_then(Result::ok).unwrap_or(0xC000_0001);
        if status != STATUS_SUCCESS {
            break;
        }
        process_message(message);
    }
    guest::free_bytes(block);
}

/// PopUmpoProcessMessage: o pedido de conexão, o fim do cliente; os
/// datagramas de energia são recebidos e descartados.
fn process_message(message: u64) {
    // SAFETY: a mensagem recebida no bloco de MaxMessageLength bytes.
    let header = unsafe { PortMessage::at(message) };
    let message_type = header.u2.s2.type_.get() as u16 & 0xFF;
    match message_type {
        LPC_CONNECTION_REQUEST => accept_connection(message),
        LPC_PORT_CLOSED | LPC_CLIENT_DIED => {
            CLIENT_CONNECTED.store(false, Ordering::Release);
            let client = CLIENT_PORT.swap(0, Ordering::AcqRel);
            crate::debug_print!("[po] \\PowerPort: o cliente saiu (tipo {}), fechando a porta de comunicacao {:#x}", message_type, client);
            if client != 0 {
                let _ = crate::ntos::ob::close::close(client, Some(0));
            }
            crate::debug_print!("[po] \\PowerPort: porta de comunicacao fechada");
        }
        _ => {}
    }
}

/// ZwAlpcAcceptConnectPort do primeiro cliente, com a porta de comunicação
/// num handle de kernel (OBJ_KERNEL_HANDLE, na tabela do System: o callback
/// roda no contexto do cliente); os outros são recusados.
fn accept_connection(message: u64) {
    let server_port = SERVER_PORT.load(Ordering::Acquire);
    let Ok(block) = zeroed(0x80) else { return };
    let (attributes, handle_cell) = (block, block + 0x40);
    object_attributes(attributes, None, 0);
    let accept = !CLIENT_CONNECTED.load(Ordering::Acquire);
    let status = crate::ntos::ps::previous_mode::with_kernel(|| server::accept_connect_port(handle_cell, server_port, attributes, 0, message, accept, 0)).ok().and_then(Result::ok).unwrap_or(0xC000_0001);
    crate::debug_print!("[po] \\PowerPort: pedido de conexao {} ({:#x})", if accept { "aceito" } else { "recusado" }, status);
    if accept && status == STATUS_SUCCESS {
        CLIENT_PORT.store(guest::read64(handle_cell), Ordering::Release);
        CLIENT_CONNECTED.store(true, Ordering::Release);
    }
    guest::free_bytes(block);
}
