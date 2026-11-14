//! As entradas LPC de modo kernel sobre o ALPC: LpcRequestPort,
//! LpcSendWaitReceivePort e ZwSecureConnectPort (NtSecureConnectPort com
//! PreviousMode KernelMode).
//!
//! Como no ntoskrnl 19041, o LPC é a mesma porta ALPC com o contrato antigo:
//!
//! - LpcRequestPort(PortAddress, RequestMessage): o AlpcpSendMessage na
//!   porta (o ponteiro, não um handle) com ALPC_MSGFLG_RELEASE_MESSAGE e o
//!   modo LPC (0x10002), sem atributos, em KernelMode e numa região crítica:
//!   um datagrama, sem resposta;
//! - LpcSendWaitReceivePort(PortAddress, Flags, SendMessage, ReceiveMessage,
//!   BufferLength, Timeout): o AlpcpProcessSynchronousRequest com Flags | 2
//!   (o envio síncrono e a espera da resposta na mesma chamada), sem
//!   atributos de envio nem de recepção, em KernelMode; os dois status
//!   internos do ALPC voltam como os do LPC (0xC0000703 =
//!   STATUS_PORT_DISCONNECTED, 0xC0000701 = STATUS_LPC_REPLY_LOST);
//! - NtSecureConnectPort(PortHandle, PortName, SecurityQos, ClientView,
//!   RequiredServerSid, ServerView, MaxMessageLength, ConnectionInformation,
//!   ConnectionInformationLength): a conexão ALPC síncrona ao nome, com a
//!   qualidade de segurança pedida, a exigência do SID do servidor e a
//!   informação de conexão como dados da mensagem de conexão; a resposta do
//!   servidor volta na mesma informação de conexão (com o comprimento) e
//!   MaxMessageLength recebe o da porta. As vistas de seção do LPC
//!   (ClientView/ServerView) ainda não são montadas nesta entrada:
//!   STATUS_NOT_SUPPORTED, com registro.

use alloc::sync::Arc;

use crate::ntos::alpc::kernel_entry::{self, Completed, Pending};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{AlpcPortAttributes, PortMessage, SecurityQualityOfService};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::port::{self as port_objects, Port};
use crate::ntos::ps::user::alpc::{self as transport, Exchange, ReceiveArguments};
use crate::rtl::KernelError;

const STATUS_INVALID_PORT_HANDLE: u32 = 0xC000_0042;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PORT_DISCONNECTED: u32 = 0xC000_0037;
const STATUS_LPC_REPLY_LOST: u32 = 0xC000_0253;
/// ALPC_MSGFLG_RELEASE_MESSAGE e o bit de modo LPC do LpcRequestPort.
const LPC_REQUEST_FLAGS: u32 = 0x1_0002;
/// ALPC_MSGFLG_SYNC_REQUEST.
const SYNC_REQUEST: u64 = 0x2_0000;
/// O maior PORT_MESSAGE de uma porta LPC x64 (PORT_MAXIMUM_MESSAGE_LENGTH).
const LPC_MAXIMUM_MESSAGE_LENGTH: u64 = 512;
/// O buffer da mensagem de conexão: o cabeçalho e o maior dado de conexão.
const CONNECTION_BUFFER: u64 = 0x28 + 0xFFD8;

fn port_at(port_object: u64) -> Option<Arc<Port>> {
    port_objects::port_of(port_object).filter(|port| port.kind == "alpc" || port.kind == "port")
}

/// Uma troca de kernel até a conclusão (a mesma continuação do
/// ZwAlpcSendWaitReceivePort).
fn exchange(port: &Arc<Port>, flags: u32, input: u64, receive: ReceiveArguments) -> Result<u32, KernelError> {
    let pending: alloc::boxed::Box<dyn Pending> = port.run(|| -> Result<alloc::boxed::Box<dyn Pending>, KernelError> {
        if port.kind == "alpc" && crate::ntos::alpc::server::owns(port) {
            return crate::ntos::alpc::server::begin_kernel_exchange(port, flags, input, receive);
        }
        Ok(match transport::exchange_messages(port, flags, input, 0, receive, 0)? {
            Exchange::Status(status) => alloc::boxed::Box::new(Completed(status)),
            Exchange::Wait(request) => alloc::boxed::Box::new(request),
        })
    })?;
    Ok(kernel_entry::drive(pending))
}

/// LpcRequestPort(PortAddress, RequestMessage). Devolve o NTSTATUS.
pub fn request_port(port_object: u64, message: u64) -> Result<u32, KernelError> {
    let Some(port) = port_at(port_object) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
    critical_region::enter_critical()?;
    let status = exchange(&port, LPC_REQUEST_FLAGS, message, ReceiveArguments { output: 0, length: 0, receive_attributes: 0, timeout: 0 });
    critical_region::leave_critical()?;
    status
}

/// LpcSendWaitReceivePort(PortAddress, Flags, SendMessage, ReceiveMessage,
/// BufferLength, Timeout). Devolve o NTSTATUS.
pub fn send_wait_receive_port(port_object: u64, flags: u32, send: u64, receive: u64, buffer_length: u64, timeout: u64) -> Result<u32, KernelError> {
    let Some(port) = port_at(port_object) else { return Ok(STATUS_INVALID_PORT_HANDLE) };
    critical_region::enter_critical()?;
    let status = exchange(&port, flags | 2, send, ReceiveArguments { output: receive, length: buffer_length, receive_attributes: 0, timeout });
    critical_region::leave_critical()?;
    Ok(match status? {
        0xC000_0703 => STATUS_PORT_DISCONNECTED,
        0xC000_0701 => STATUS_LPC_REPLY_LOST,
        other => other,
    })
}

/// ZwSecureConnectPort: o NtSecureConnectPort em KernelMode. Devolve o
/// NTSTATUS.
#[allow(clippy::too_many_arguments)]
pub fn secure_connect_port(out: u64, name: u64, quality: u64, client_view: u64, required_sid: u64, server_view: u64, max_length: u64, information: u64, information_length: u64) -> Result<u32, KernelError> {
    if client_view != 0 || server_view != 0 {
        crate::debug_print!("[lpc] ZwSecureConnectPort com vistas de secao (sem suporte)");
        return Ok(STATUS_NOT_SUPPORTED);
    }
    // SAFETY: PULONG ConnectionInformationLength opcional do chamador de kernel.
    let supplied = if information != 0 && information_length != 0 { unsafe { Field::<u32>::at(information_length) }.get() as u64 } else { 0 };
    let block = guest::alloc_bytes(AlpcPortAttributes::SIZE + 8 + CONNECTION_BUFFER);
    if block == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let (attributes, length, message) = (block, block + AlpcPortAttributes::SIZE, block + AlpcPortAttributes::SIZE + 8);
    guest::write_bytes(block, &alloc::vec![0u8; (AlpcPortAttributes::SIZE + 8 + PortMessage::SIZE) as usize]);
    let result = (|| -> Result<u32, KernelError> {
        // SAFETY: blocos recém-alocados com os tamanhos dos tipos.
        let (port_attributes, header) = unsafe { (AlpcPortAttributes::at(attributes), PortMessage::at(message)) };
        if quality != 0 {
            // SAFETY: PSECURITY_QUALITY_OF_SERVICE do chamador de kernel.
            let source = unsafe { SecurityQualityOfService::at(quality) };
            let qos = &port_attributes.security_qos;
            qos.length.set(source.length.get());
            qos.impersonation_level.set(source.impersonation_level.get());
            qos.context_tracking_mode.set(source.context_tracking_mode.get());
            qos.effective_only.set(source.effective_only.get());
        }
        port_attributes.max_message_length.set(LPC_MAXIMUM_MESSAGE_LENGTH);
        let data = supplied.min(CONNECTION_BUFFER - PortMessage::SIZE);
        if data != 0 {
            guest::write_bytes(message + PortMessage::SIZE, &guest::read_bytes(information, data as usize));
        }
        header.u1.s1.data_length.set(data as i16);
        header.u1.s1.total_length.set((PortMessage::SIZE + data) as i16);
        // SAFETY: SIZE_T recém-alocado.
        unsafe { Field::<u64>::at(length) }.set(CONNECTION_BUFFER);
        let status = kernel_entry::connect(&[out, name, 0, attributes, SYNC_REQUEST, required_sid, message, length, 0, 0, 0])?;
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        if information != 0 && information_length != 0 {
            let returned = (header.u1.s1.data_length.get() as u16 as u64).min(supplied);
            guest::write_bytes(information, &guest::read_bytes(message + PortMessage::SIZE, returned as usize));
            // SAFETY: o PULONG do chamador de kernel.
            unsafe { Field::<u32>::at(information_length) }.set(returned as u32);
        }
        if max_length != 0 {
            let maximum = port_maximum(guest::read::<u64>(out)).unwrap_or(LPC_MAXIMUM_MESSAGE_LENGTH as u32);
            // SAFETY: PULONG MaxMessageLength do chamador de kernel.
            unsafe { Field::<u32>::at(max_length) }.set(maximum);
        }
        Ok(status)
    })();
    guest::free_bytes(block);
    result
}

/// O comprimento máximo de mensagem da porta do handle de kernel.
fn port_maximum(handle: u64) -> Option<u32> {
    let mut reference = crate::ntos::alpc::port_reference::reference(handle, 0, 0).ok()?.ok()?;
    let maximum = reference.port.maximum();
    let _ = reference.release();
    Some(maximum)
}
