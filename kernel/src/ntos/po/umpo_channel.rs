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
//!   PopUmpoProcessMessages (no OpenNT, por um work item no processo
//!   System, ver `message_callback`), que recebe da porta pelo
//!   ZwAlpcSendWaitReceivePort com prazo zero até a fila esvaziar
//!   (STATUS_TIMEOUT) e trata cada mensagem pelo tipo do PORT_MESSAGE: o
//!   pedido de conexão (LPC_CONNECTION_REQUEST) é aceito pelo
//!   ZwAlpcAcceptConnectPort só para o primeiro cliente (o
//!   PopUmpoAlpcClientConnected); o fim do cliente (LPC_PORT_CLOSED e
//!   LPC_CLIENT_DIED) libera o próximo.
//!
//! As mensagens de energia (LPC_DATAGRAM ou LPC_REPLY sem
//! LPC_CONTINUATION_REQUIRED) vão ao PopUmpoProcessPowerMessage: o ULONG no
//! começo dos dados é o tipo. O umpo manda o tipo 4 (PopSetNewPolicyValue)
//! com cada valor de política: ao subir e a cada troca de esquema,
//! GUID_ACTIVE_POWERSCHEME e cada setting do esquema ativo, AC e DC; o valor
//! vai à configuração do setting (`po/power_setting.rs`), que avisa os
//! callbacks e os nomes WNF pelo worker de política. Os tipos 7, 8, 10 e 14
//! (resposta de evento legado, resposta de consulta de override de power
//! request, início dos power requests do umpo e o timeout de doze AoAc)
//! respondem a mensagens que o kernel do OpenNT não manda ao umpo (o
//! PopUmpoSendPowerMessage) ou só valem numa plataforma AoAc, e são
//! ignorados. Um pedido síncrono (LPC_REQUEST) ou uma mensagem com
//! LPC_CONTINUATION_REQUIRED é cancelado pelo ZwAlpcCancelMessage com o
//! atributo de contexto recebido.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::vec;

use crate::ntos::alpc::{cancel_message, kernel_entry, server};
use crate::ntos::alpc::message::attributes as message_attributes;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{AlpcMessageAttributes, AlpcPortAttributes, Guid, ObjectAttributes, PortMessage, Reserved};
use crate::ntos::po::power_setting;
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
const LPC_REQUEST: u16 = 1;
const LPC_REPLY: u16 = 2;
const LPC_DATAGRAM: u16 = 3;
/// LPC_CONTINUATION_REQUIRED no Type do PORT_MESSAGE.
const LPC_CONTINUATION_REQUIRED: u16 = 0x2000;
const STATUS_SUCCESS: u32 = 0;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// O atributo que o PopUmpoProcessMessages pede em cada recepção, num buffer
/// de atributos de 0xA0 bytes.
const ALPC_MESSAGE_CONTEXT_ATTRIBUTE: u32 = 0x2000_0000;
const RECEIVE_ATTRIBUTES_SIZE: u64 = 0xA0;
/// O tipo da mensagem de energia com um valor de política.
const POWER_MESSAGE_NEW_POLICY_VALUE: u32 = 4;
/// GUID_ACTIVE_POWERSCHEME {31f9f286-5084-42fe-b720-2b0264993763}: o valor é o
/// GUID do esquema ativo, o primeiro que o umpo manda.
const GUID_ACTIVE_POWERSCHEME: [u8; 16] = power_setting::guid(0x31f9_f286, 0x5084, 0x42fe, [0xb7, 0x20, 0x2b, 0x02, 0x64, 0x99, 0x37, 0x63]);

/// Os dados de uma mensagem de energia do serviço Power, depois do
/// PORT_MESSAGE (o que o PopUmpoProcessPowerMessage recebe): o tipo e, de
/// +8, o corpo dele. O umpo.dll monta a mensagem no UmpoAlpcSendPowerMessage
/// (0x6a00) e no UmpoSendKernelPowerPolicyNotification (0x3e90).
#[repr(C)]
struct PowerMessage {
    message_type: Field<u32>,
    _reserved: Reserved<4>,
    policy: PolicyValue,
}

/// O corpo da mensagem 4 (o argumento do PopSetNewPolicyValue); os
/// DataLength bytes de dados vêm logo depois.
#[repr(C)]
struct PolicyValue {
    /// 1 no umpo; o kernel não lê.
    _version: Field<u32>,
    /// O perfil do PPM (nulo = o perfil padrão).
    profile: Guid,
    setting: Guid,
    subgroup: Guid,
    /// 0 AC, 1 DC.
    slot: Field<u32>,
    data_length: Field<u32>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PowerMessage {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for PolicyValue {}

const _: () = {
    assert!(core::mem::size_of::<PolicyValue>() == 0x3C);
    assert!(core::mem::offset_of!(PolicyValue, profile) == 0x4);
    assert!(core::mem::offset_of!(PolicyValue, setting) == 0x14);
    assert!(core::mem::offset_of!(PolicyValue, subgroup) == 0x24);
    assert!(core::mem::offset_of!(PolicyValue, slot) == 0x34);
    assert!(core::mem::offset_of!(PolicyValue, data_length) == 0x38);
    assert!(core::mem::offset_of!(PowerMessage, policy) == 0x8);
};

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
    let item = guest::alloc_bytes(crate::ntos::io::work_items::work_item_size());
    if item == 0 {
        return Err(KernelError::new("canal do umpo: sem memoria para o work item"));
    }
    crate::ntos::io::work_items::create_work_item(0, item);
    WORK_ITEM.store(item, Ordering::Release);
    let policy =SecurityPolicy { dacl: Some(vec![Ace::allow(sid(5, &[18]), GENERIC_ALL)]), ..SecurityPolicy::default() };
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

/// PopUmpoMessageCallback(CallbackContext, Argument1, Argument2). O 19041
/// chama o PopUmpoProcessMessages ali mesmo, no contexto de quem enviou. No
/// OpenNT o callback agenda o work item do canal: o LPC_PORT_CLOSED chega
/// de dentro do fechamento da porta do cliente, e fechar ali a porta de
/// comunicação reentraria nas travas do ALPC. As mensagens são tratadas na
/// mesma ordem, no processo System.
extern "win64" fn message_callback(_context: u64, _argument1: u64, _argument2: u64) {
    schedule();
}

/// O work item do canal e os pedidos acumulados enquanto ele está agendado.
static WORK_ITEM: AtomicU64 = AtomicU64::new(0);
static SCHEDULED: AtomicBool = AtomicBool::new(false);
static REQUESTED: AtomicBool = AtomicBool::new(false);

fn schedule() {
    let item = WORK_ITEM.load(Ordering::Acquire);
    if item == 0 {
        return;
    }
    REQUESTED.store(true, Ordering::Release);
    if SCHEDULED.swap(true, Ordering::AcqRel) {
        return;
    }
    crate::ntos::io::work_items::queue_kernel_work_item(item, worker, 0, None);
}

fn worker(_item: u64, _context: u64) {
    loop {
        while REQUESTED.swap(false, Ordering::AcqRel) {
            let system = crate::ntos::ps::process::get_system_process();
            if let Err(error) = crate::ntos::ps::process_context::with_process(system, process_messages) {
                crate::debug_print!("[po] \\PowerPort: {}", error);
            }
        }
        SCHEDULED.store(false, Ordering::Release);
        // Um pedido chegado entre o fim do laço e a liberação do agendamento.
        if !REQUESTED.load(Ordering::Acquire) || SCHEDULED.swap(true, Ordering::AcqRel) {
            return;
        }
    }
}

/// PopUmpoProcessMessages (0x6f30f4): recebe da porta com prazo zero até a
/// fila esvaziar, pedindo o atributo de contexto de cada mensagem.
fn process_messages() {
    let server_port = SERVER_PORT.load(Ordering::Acquire);
    if server_port == 0 {
        return;
    }
    let Ok(block) = zeroed(MAXIMUM_MESSAGE_LENGTH + 0x20 + RECEIVE_ATTRIBUTES_SIZE + 8) else { return };
    let (message, length, timeout) = (block, block + MAXIMUM_MESSAGE_LENGTH, block + MAXIMUM_MESSAGE_LENGTH + 8);
    let attributes = block + MAXIMUM_MESSAGE_LENGTH + 0x20;
    // SAFETY: o bloco zerado reserva os RECEIVE_ATTRIBUTES_SIZE bytes do
    // ALPC_MESSAGE_ATTRIBUTES e, depois deles, a célula SIZE_T do tamanho.
    let (receive_attributes, required) = unsafe { (AlpcMessageAttributes::at(attributes), Field::<u64>::at(attributes + RECEIVE_ATTRIBUTES_SIZE)) };
    loop {
        let _ = message_attributes::initialize(ALPC_MESSAGE_CONTEXT_ATTRIBUTE, Some(receive_attributes), RECEIVE_ATTRIBUTES_SIZE, required);
        guest::write64(length, MAXIMUM_MESSAGE_LENGTH);
        guest::write64(timeout, 0);
        let arguments = [server_port, 0, 0, 0, message, length, attributes, timeout];
        let status = crate::ntos::ps::previous_mode::with_kernel(|| kernel_entry::send_wait_receive(&arguments)).ok().and_then(Result::ok).unwrap_or(0xC000_0001);
        if status != STATUS_SUCCESS {
            // STATUS_TIMEOUT: a fila esvaziou. Um erro é o que o 19041 rastreia
            // no PopDiagTraceUmpoAlpcProcessingError.
            if status & 0x8000_0000 != 0 {
                crate::debug_print!("[po] \\PowerPort: recepcao falhou ({:#x})", status);
            }
            break;
        }
        process_message(message, message_attributes::get(receive_attributes, ALPC_MESSAGE_CONTEXT_ATTRIBUTE));
    }
    guest::free_bytes(block);
}

/// PopUmpoProcessMessage (0x6f3224): pelo byte baixo do Type do
/// PORT_MESSAGE; o LPC_CONTINUATION_REQUIRED é conferido no Type inteiro.
fn process_message(message: u64, context: u64) {
    // SAFETY: a mensagem recebida no bloco de MaxMessageLength bytes.
    let header = unsafe { PortMessage::at(message) };
    let raw_type = header.u2.s2.type_.get() as u16;
    match raw_type & 0xFF {
        LPC_REQUEST => cancel(context),
        LPC_REPLY | LPC_DATAGRAM if raw_type & LPC_CONTINUATION_REQUIRED != 0 => cancel(context),
        LPC_REPLY | LPC_DATAGRAM => {
            let length = header.u1.s1.data_length.get() as u16 as u32;
            let status = process_power_message(message + PortMessage::SIZE, length);
            if status & 0x8000_0000 != 0 {
                crate::debug_print!("[po] \\PowerPort: mensagem de energia recusada ({:#x})", status);
            }
        }
        LPC_CONNECTION_REQUEST => accept_connection(message),
        message_type @ (LPC_PORT_CLOSED | LPC_CLIENT_DIED) => {
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

/// ZwAlpcCancelMessage(PopAlpcServerPort, 0, ContextAttribute): este canal
/// não responde pedidos síncronos.
fn cancel(context: u64) {
    let server_port = SERVER_PORT.load(Ordering::Acquire);
    if context == 0 || server_port == 0 {
        return;
    }
    let _ = crate::ntos::ps::previous_mode::with_kernel(|| cancel_message::cancel(server_port, 0, context, 0, crate::ntos::ps::user::alpc::cancel_message));
}

/// PopUmpoProcessPowerMessage (0x6f3354) sobre os `length` bytes de dados de
/// uma mensagem em `payload`; os tipos além do 4 não têm efeito no OpenNT
/// (ver o começo do arquivo). Devolve o NTSTATUS (o 19041 devolve zero para
/// todo sucesso).
pub fn process_power_message(payload: u64, length: u32) -> u32 {
    if length < 4 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: os dados da mensagem recebida (bloco de MaxMessageLength bytes)
    // ou o bloco do autoteste, com `length` bytes.
    let message = unsafe { PowerMessage::at(payload) };
    match message.message_type.get() {
        POWER_MESSAGE_NEW_POLICY_VALUE => new_policy_value(&message.policy, length),
        _ => STATUS_SUCCESS,
    }
}

/// O corpo da mensagem 4 ao PopSetNewPolicyValue. O 19041 lê o DataLength
/// sem conferir com a mensagem; o OpenNT recusa dados além dela.
fn new_policy_value(policy: &PolicyValue, length: u32) -> u32 {
    let header = core::mem::offset_of!(PowerMessage, policy) as u32 + PolicyValue::SIZE as u32;
    let data_length = policy.data_length.get();
    if length < header || data_length > length - header {
        return STATUS_INVALID_PARAMETER;
    }
    let data = guest::read_bytes(policy.address() + PolicyValue::SIZE, data_length as usize);
    let setting = power_setting::guid_bytes(&policy.setting);
    let slot = policy.slot.get();
    if setting == GUID_ACTIVE_POWERSCHEME {
        if let Ok(scheme) = <[u8; 16]>::try_from(&data[..]) {
            crate::debug_print!("[po] \\PowerPort: esquema de energia ativo {} ({})", crate::ntos::etw::user_registration::guid_text(&scheme), if slot == 0 { "AC" } else { "DC" });
        }
    }
    power_setting::set_new_policy_value(&power_setting::guid_bytes(&policy.profile), &setting, &power_setting::guid_bytes(&policy.subgroup), slot, &data)
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
