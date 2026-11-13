//! Exportações Zw do ALPC — `win32/ntoskrnl/alpc.js`.
//!
//! Captura de ponteiros exatos e sem sondagem de UserMode. As chamadas em
//! threads nativas usam a mesma continuação pelo escalonador de kernel; uma
//! falha interna do transporte para a máquina, como no original.

use alloc::boxed::Box;

use crate::ntos::init::exports::{signed_status, Call, Group};
use crate::ntos::alpc::kernel_entry::{self, Pending};
use crate::ntos::alpc::{cancel_message, query_information, query_message};
use crate::ntos::alpc::resource::services;
use crate::ntos::ke::dispatcher;
use crate::ntos::ps::user::alpc as transport;
use crate::ntos::rtl::native_context;
use crate::rtl::KernelError;

/// Resultado de um provedor: transferências de contexto seguem adiante; as
/// demais falhas internas são fatais.
fn finish(what: &str, result: Result<u32, KernelError>) -> Result<u64, KernelError> {
    match result {
        Ok(status) => Ok(signed_status(status)),
        Err(error) if native_context::is_transfer(&error) => Err(error),
        Err(error) => panic!("[alpc] fatal {what}: {error}"),
    }
}

/// Bombeia a operação retomável até concluir; o cancelamento final é
/// inócuo depois da conclusão.
fn drive(mut operation: Box<dyn Pending>) -> u32 {
    let status = loop {
        if let Some(status) = operation.poll() {
            break status;
        }
        dispatcher::pump_kernel();
    };
    operation.cancel();
    status
}

/// Onze argumentos x64, incluindo timeout e atributos depois do quarto slot.
fn connect(call: &Call, extended: bool) -> Result<u64, KernelError> {
    let arguments: [u64; 11] = core::array::from_fn(|index| call.arg(index + 1));
    let begun = if extended { kernel_entry::begin_connection_ex(&arguments) } else { kernel_entry::begin_connection(&arguments) };
    finish("kernel connection", begun.map(drive))
}

fn connect_port(call: &Call) -> Result<u64, KernelError> {
    connect(call, false)
}

fn connect_port_ex(call: &Call) -> Result<u64, KernelError> {
    connect(call, true)
}

fn send_wait_receive_port(call: &Call) -> Result<u64, KernelError> {
    let arguments: [u64; 8] = core::array::from_fn(|index| call.arg(index + 1));
    finish("kernel failure", kernel_entry::begin(&arguments).map(drive))
}

/// Zw consulta handles no modo kernel sem alterar o PreviousMode do chamador.
fn delete_port_section(call: &Call) -> Result<u64, KernelError> {
    finish("section deletion", services::delete_port_section(call.arg(1), call.arg(2) as u32, call.arg(3), 0))
}

/// ViewBase é um valor exato de 64 bits, não um buffer a sondar.
fn delete_section_view(call: &Call) -> Result<u64, KernelError> {
    finish("view deletion", services::delete_section_view(call.arg(1), call.arg(2) as u32, call.arg(3), 0))
}

/// O gateway preserva os quatro ponteiros e os dois ULONGs da assinatura.
fn query_information_message(call: &Call) -> Result<u64, KernelError> {
    finish("message query", query_message::query(call.arg(1), call.arg(2), call.arg(3) as u32, call.arg(4), call.arg(5) as u32, call.arg(6), 0, Some(&transport::pump)))
}

/// O MSRPC associa uma IOCP de kernel pela classe 2; o buffer permanece canônico.
fn set_information(call: &Call) -> Result<u64, KernelError> {
    finish("port information", services::set_information(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, 0))
}

/// READ_CONTROL pertence à consulta Nt; Zw conserva o acesso de KernelMode,
/// mesmo com PreviousMode=UserMode na thread nativa.
fn query_information(call: &Call) -> Result<u64, KernelError> {
    finish("port query", query_information::query(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4) as u32, call.arg(5), 0))
}

/// O handle e o SIZE_T conservam os bits altos.
fn create_port_section(call: &Call) -> Result<u64, KernelError> {
    finish("section creation", services::create_port_section(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), call.arg(5), call.arg(6), 0))
}

fn create_section_view(call: &Call) -> Result<u64, KernelError> {
    finish("view creation", services::create_section_view(call.arg(1), call.arg(2) as u32, call.arg(3), 0))
}

fn disconnect_port(call: &Call) -> Result<u64, KernelError> {
    finish("port disconnection", services::disconnect_port(call.arg(1), call.arg(2) as u32, 0))
}

fn create_security_context(call: &Call) -> Result<u64, KernelError> {
    finish("security creation", services::create_security_context(call.arg(1), call.arg(2) as u32, call.arg(3), 0))
}

/// ContextHandle é um identificador, não um ponteiro a sondar.
fn delete_security_context(call: &Call) -> Result<u64, KernelError> {
    finish("security deletion", services::delete_security_context(call.arg(1), call.arg(2) as u32, call.arg(3), 0))
}

/// A seleção x64 é capturada antes da consulta ao handle, sempre em KernelMode.
fn cancel(call: &Call) -> Result<u64, KernelError> {
    finish("message cancellation", cancel_message::cancel(call.arg(1), call.arg(2) as u32, call.arg(3), 0, transport::cancel_message))
}

fn create_resource_reserve(call: &Call) -> Result<u64, KernelError> {
    finish("reserve creation", services::create_resource_reserve(call.arg(1), call.arg(2) as u32, call.arg(3), call.arg(4), 0))
}

pub static GROUP: Group = Group {
    name: "alpc",
    names: &[
        "ZwAlpcSendWaitReceivePort",
        "ZwAlpcDeletePortSection",
        "ZwAlpcDeleteSectionView",
        "ZwAlpcQueryInformationMessage",
        "ZwAlpcSetInformation",
        "ZwAlpcQueryInformation",
        "ZwAlpcCreatePortSection",
        "ZwAlpcCreateSectionView",
        "ZwAlpcDisconnectPort",
        "ZwAlpcConnectPort",
        "ZwAlpcConnectPortEx",
        "ZwAlpcCreateSecurityContext",
        "ZwAlpcDeleteSecurityContext",
        "ZwAlpcCancelMessage",
        "ZwAlpcCreateResourceReserve",
    ],
    handlers: &[send_wait_receive_port, delete_port_section, delete_section_view, query_information_message, set_information, query_information, create_port_section, create_section_view, disconnect_port, connect_port, connect_port_ex, create_security_context, delete_security_context, cancel, create_resource_reserve],
    data_exports: &[],
};
