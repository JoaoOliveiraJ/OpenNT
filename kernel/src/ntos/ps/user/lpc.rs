//! Endpoints LPC hospedados por serviços do kernel.
//!
//! Os handles de porta possuem os dois aliases da seção de transferência do
//! cliente. Os pedidos são copiados antes do despacho, com CLIENT_ID e IDs
//! de mensagem gerados pelo kernel e respostas limitadas.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use super::sections::{self, MapRequest};
use super::state;
use crate::ntos::alpc::transport::{Reply, Service, ServiceReply};
use crate::ntos::mm::section::handles::{self as section_handles, Kind};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::ntos::ob::objects::port::{self as port_objects, PortState};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{NtStruct, PortMessage, PortView, RemotePortView, SecurityQualityOfService, UnicodeString};

static NEXT_MESSAGE_ID: AtomicU32 = AtomicU32::new(1);
static SERVICES: SpinLock<BTreeMap<NodeId, Arc<dyn Service>>> = SpinLock::new(BTreeMap::new());

/// Cria o nó `Port` com o serviço por trás do nome.
pub fn register(path: &str, service: Arc<dyn Service>) -> Result<NodeId, KernelError> {
    let split = path.rfind('\\').unwrap_or(0);
    let parent = if split == 0 { "\\" } else { &path[..split] };
    let node = object_manager::create_object(parent, &path[split + 1..], "Port", None)?;
    SERVICES.lock().insert(node, service);
    Ok(node)
}

/// Cópia sondada de um buffer de usuário (já validado por `probe_user_*`).
fn copy_in(address: u64, size: u64) -> Result<Vec<u8>, KernelError> {
    guest::try_read_bytes(address, size as usize)
}

/// NtConnectPort: uma falha de sonda em qualquer captura devolve
/// ACCESS_VIOLATION.
#[allow(clippy::too_many_arguments)]
pub fn connect(out: u64, name: u64, qos: u64, client_view: u64, server_view: u64, max_length: u64, info: u64, info_length: u64) -> Result<u32, KernelError> {
    state::guarded(|| connect_captured(out, name, qos, client_view, server_view, max_length, info, info_length))
}

#[allow(clippy::too_many_arguments)]
fn connect_captured(out: u64, name: u64, qos: u64, client_view: u64, server_view: u64, max_length: u64, info: u64, info_length: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || !state::probe_user_read(name, UnicodeString::SIZE) || !state::probe_user_read(qos, SecurityQualityOfService::SIZE) {
        return Ok(0xC000_0005);
    }
    let port_name = state::user_struct::<UnicodeString>(name)?;
    let name_bytes = port_name.length.probe_get()? as u64;
    let name_buffer = port_name.buffer.probe_get()?;
    if name_bytes % 2 != 0 || name_bytes > 1024 || !state::probe_user_read(name_buffer, name_bytes) {
        return Ok(0xC000_000D);
    }
    let path = state::try_read_user_wide_string(name_buffer, name_bytes / 2)?;
    let Some(node) = object_manager::lookup(&path) else { return Ok(0xC000_0034) };
    if object_manager::node(node).is_none_or(|record| record.type_name != "Port") {
        return Ok(0xC000_0024);
    }
    // NtConnectPort captura o layout fixo; o cliente CSR da ntdll não
    // inicializa o membro Length.
    let quality = state::user_struct::<SecurityQualityOfService>(qos)?;
    if quality.impersonation_level.probe_get()?.0 as u32 > 3 || quality.context_tracking_mode.probe_get()? > 1 || quality.effective_only.probe_get()? > 1 {
        return Ok(0xC000_000D);
    }
    let Some(service) = SERVICES.lock().get(&node).cloned() else { return Ok(0xC000_0024) };
    if info_length == 0 || !state::probe_user_write(info_length, 4) {
        return Ok(0xC000_0005);
    }
    // ULONG *ConnectionInformationLength (entrada e saída).
    let size = guest::try_read::<u32>(info_length)? as u64;
    if size > service.max_connection_info() as u64 {
        return Ok(0xC000_000D);
    }
    if !state::probe_user_write(info, size) || (max_length != 0 && !state::probe_user_write(max_length, 4)) || (server_view != 0 && (!state::probe_user_write(server_view, RemotePortView::SIZE) || state::user_struct::<RemotePortView>(server_view)?.length.probe_get()? != RemotePortView::SIZE as u32)) {
        return Ok(0xC000_0005);
    }
    let initial = PortState { service: Some(service.clone()), service_process: process::get_system_process(), port_flags: 0x3_0000, message_sequence: 1, port_context: 0, ..PortState::default() };
    let disconnecting = service.clone();
    let connection = match port_objects::create(
        "port",
        initial,
        service.max_message_length(),
        1,
        0,
        Box::new(move |port| {
            if port.with(|state| state.transport_cleanup) {
                super::alpc::cleanup_transport(port);
            }
            if port.started() {
                disconnecting.disconnect(port);
            }
            for view in port.with(|state| core::mem::take(&mut state.views)) {
                let _ = sections::unmap(&view, None);
            }
        }),
        port_objects::CreateOptions::default(),
    ) {
        Ok(connection) => connection,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    let result = connection.run(|| -> Result<u32, KernelError> {
        if client_view != 0 {
            if !state::probe_user_write(client_view, PortView::SIZE) || state::user_struct::<PortView>(client_view)?.length.probe_get()? != PortView::SIZE as u32 {
                return Ok(0xC000_000D);
            }
            let view = state::user_struct::<PortView>(client_view)?;
            // Handle de SECTION de dados do processo (não imagem), com
            // SECTION_MAP_READ|SECTION_MAP_WRITE.
            let reference = match section_handles::reference(view.section_handle.probe_get()?, Kind::Section, 6, 1) {
                Ok(reference) => reference,
                Err(0xC000_0022) => return Ok(0xC000_0022),
                Err(_) => return Ok(0xC000_0008),
            };
            let section = reference.section.clone().filter(|section| !section.is_image);
            let mapped = (|| -> Result<u32, KernelError> {
                let Some(section) = section else { return Ok(0xC000_0008) };
                let request = MapRequest { offset: view.section_offset.probe_get()? as u64, size: view.view_size.probe_get()?, protect: 4, ..MapRequest::default() };
                for supervisor in [false, true] {
                    match sections::map(&section, &MapRequest { supervisor, ..request })? {
                        Ok(view) => connection.with(|state| state.views.push(view)),
                        Err(status) => return Ok(status),
                    }
                }
                Ok(0)
            })();
            let _ = reference.release();
            match mapped? {
                0 => {}
                status => return Ok(status),
            }
        }
        connection.set_started(true);
        let result = match service.connect(&connection, &copy_in(info, size)?, None) {
            Reply::Now(result) => result,
            Reply::Later(_) => return Err(KernelError::new("LPC service deferred a connection")),
        };
        if connection.closed() {
            return Ok(0xC000_0037);
        }
        if result.status != 0 {
            return Ok(result.status);
        }
        if result.data.len() as u64 > size {
            return Ok(0xC000_0004);
        }
        if client_view != 0 {
            let (local, remote) = connection.with(|state| (state.views[0].clone(), state.views[1].clone()));
            let view = state::user_struct::<PortView>(client_view)?;
            view.view_size.probe_set(local.size)?;
            view.view_base.probe_set(local.base)?;
            view.view_remote_base.probe_set(remote.base)?;
        }
        if server_view != 0 {
            let view = state::user_struct::<RemotePortView>(server_view)?;
            view.view_size.probe_set(0)?;
            view.view_base.probe_set(0)?;
        }
        if max_length != 0 {
            guest::try_write::<u32>(max_length, service.max_message_length())?;
        }
        state::write_user_bytes(info, &result.data)?;
        guest::try_write::<u32>(info_length, result.data.len() as u32)?;
        let status = port_objects::publish(&connection, out, 0)?;
        if status != 0 {
            return Ok(status);
        }
        // O PortHandle publicado acima (lido de volta da saída sondada).
        let handle = guest::try_read::<u64>(out)?;
        connection.with(|state| state.port_context = handle);
        crate::debug_print!("[lpc] conectado {} pid={}", path, connection.process_id());
        Ok(0)
    });
    dispatcher_objects::collect(connection.pointer);
    match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    }
}

fn nt_connect_port(out: u64, name: u64, qos: u64, view: u64, rsp: u64) -> Result<u32, KernelError> {
    connect(out, name, qos, view, state::stack_arg(rsp, 5), state::stack_arg(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg(rsp, 8))
}

fn nt_secure_connect_port(out: u64, name: u64, qos: u64, view: u64, rsp: u64) -> Result<u32, KernelError> {
    // A validação do SID exige o serviço de token/segurança.
    if state::stack_arg(rsp, 5) != 0 {
        return Ok(0xC000_00BB);
    }
    connect(out, name, qos, view, state::stack_arg(rsp, 6), state::stack_arg(rsp, 7), state::stack_arg(rsp, 8), state::stack_arg(rsp, 9))
}

/// Pedido síncrono: status e o comprimento a informar.
pub fn request(handle: u64, input: u64, output: u64, capacity: u64) -> Result<(u32, Option<u64>), KernelError> {
    let Some((_, port)) = port_objects::resolve(handle, "port") else { return Ok((0xC000_0008, None)) };
    port.run(|| {
        if port.closed() {
            return Ok((0xC000_0037, None));
        }
        if !state::probe_user_read(input, PortMessage::SIZE) {
            return Ok((0xC000_0005, None));
        }
        let header = (|| -> Result<(u64, u64, i16), KernelError> {
            let message = state::user_struct::<PortMessage>(input)?;
            Ok((message.u1.s1.total_length.probe_get()? as u16 as u64, message.u1.s1.data_length.probe_get()? as u16 as u64, message.u2.s2.data_info_offset.probe_get()?))
        })();
        let Ok((length, data_length, data_info_offset)) = header else { return Ok((0xC000_0005, None)) };
        let Some(service) = port.with(|state| state.service.clone()) else { return Ok((0xC000_0037, None)) };
        if length < PortMessage::SIZE || length > service.max_message_length() as u64 || data_length != length - PortMessage::SIZE || data_info_offset != 0 {
            return Ok((0xC000_0021, None));
        }
        if capacity < length {
            return Ok((0xC000_0023, Some(length)));
        }
        if !state::probe_user_read(input, length) || !state::probe_user_write(output, length) {
            return Ok((0xC000_0005, None));
        }
        let Ok(mut message) = copy_in(input, length) else { return Ok((0xC000_0005, None)) };
        message[4..6].copy_from_slice(&1u16.to_le_bytes());
        message[8..16].copy_from_slice(&port.process_id().to_le_bytes());
        message[16..24].copy_from_slice(&process::get_current_thread_id().to_le_bytes());
        message[24..28].copy_from_slice(&NEXT_MESSAGE_ID.fetch_add(1, Ordering::SeqCst).to_le_bytes());
        message[32..40].copy_from_slice(&0u64.to_le_bytes());
        let message = Arc::new(SpinLock::new(message));
        let status = match service.request(&port, &message) {
            ServiceReply::Now(status) => status,
            ServiceReply::Later(_) => return Err(KernelError::new("LPC service must complete with NTSTATUS")),
        };
        if port.closed() {
            return Ok((0xC000_0037, None));
        }
        if status != 0 {
            return Ok((status, None));
        }
        let mut reply = message.lock().clone();
        reply[4..6].copy_from_slice(&2u16.to_le_bytes());
        state::write_user_bytes(output, &reply)?;
        Ok((0, Some(length)))
    })
}

fn nt_request_wait_reply_port(handle: u64, input: u64, output: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    request(handle, input, output, 0x1_0000).map(|(status, _)| status)
}

/// Fallback das portas LPC no NtAlpcSendWaitReceivePort.
fn nt_alpc_send_wait_receive_port(handle: u64, flags: u64, input: u64, send_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    let output = state::stack_arg(rsp, 5);
    let length = state::stack_arg(rsp, 6);
    if flags as u32 & !0x2_0000 != 0 || send_attributes != 0 || state::stack_arg(rsp, 7) != 0 || state::stack_arg(rsp, 8) != 0 {
        return Ok(0xC000_00BB);
    }
    if input == 0 || output == 0 || length == 0 || !state::probe_user_write(length, 8) {
        return Ok(0xC000_000D);
    }
    // SIZE_T *BufferLength (entrada e saída, sondado acima).
    let Ok(capacity) = guest::try_read::<u64>(length) else { return Ok(0xC000_0005) };
    let (status, written) = request(handle, input, output, capacity)?;
    if let Some(written) = written {
        if guest::try_write::<u64>(length, written).is_err() {
            return Ok(0xC000_0005);
        }
    }
    Ok(status)
}

/// Registra os handlers antes da camada ALPC, que conserva este emissor
/// para os handles do tipo LPC.
pub fn init() {
    state::register_handler("NtConnectPort", nt_connect_port);
    state::register_handler("NtSecureConnectPort", nt_secure_connect_port);
    state::register_handler("NtRequestWaitReplyPort", nt_request_wait_reply_port);
    state::register_handler("NtAlpcSendWaitReceivePort", nt_alpc_send_wait_receive_port);
}
