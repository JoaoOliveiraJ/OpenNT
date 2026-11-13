//! Conexão ALPC retomável.
//!
//! O handle possui uma porta real ainda pendente; só a decisão do servidor
//! conecta a porta ou produz a recusa. Atributos, filas, limpeza e
//! cancelamento são os do transporte de `ps/user/alpc`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::alpc::connect::capture as connect_capture;
use crate::ntos::alpc::connect::parameters as connect_parameters;
use crate::ntos::alpc::connect::target as connect_target;
use crate::ntos::alpc::kernel_entry::{Completed, Pending};
use crate::ntos::alpc::message::identity as message_identity;
use crate::ntos::alpc::resource::handles::Communication;
use crate::ntos::alpc::small::{context_attribute, direct_event};
use crate::ntos::alpc::transport::{JobResult, Message, Reply, Request, RequestState, Sender};
use crate::ntos::alpc::kernel_wait;
use crate::ntos::alpc::message::{buffer as message_buffer, handles as message_handles, security as message_security};
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::ob::objects::port::{self as port_objects, Port, PortState, Role};
use crate::ntos::ob::objects::dispatcher as dispatcher_objects;
use crate::ntos::ob::{object_manager, object_types, open_pointer};
use crate::ntos::ps::process;
use crate::ntos::ps::user::alpc as transport;
use crate::ntos::ps::user::events;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// Conexões aguardando a decisão do servidor (porta → pedido).
static PENDING: SpinLock<Vec<(Arc<Port>, Arc<Request>)>> = SpinLock::new(Vec::new());

fn completed(status: u32) -> Result<Box<dyn Pending>, KernelError> {
    Ok(Box::new(Completed(status)))
}

/// A fila assume a identidade nas respostas assíncronas; os demais caminhos
/// devolvem o slot, os atributos e a referência retida pelo pedido.
fn release_request(request: &Arc<Request>, status: u32, queued: bool) -> Result<(), KernelError> {
    let (job, direct, release_direct) = {
        let mut state = request.state.lock();
        if state.released {
            return Ok(());
        }
        state.released = true;
        (state.job.take(), state.direct.take(), state.release_direct.take())
    };
    let port = request.identity.port.clone();
    PENDING.lock().retain(|(candidate, _)| !Arc::ptr_eq(candidate, &port));
    if let Some(mut job) = job {
        job.cleanup(status);
    }
    if direct.is_some() {
        if let Some(release) = release_direct {
            release();
        }
    }
    let result = if queued { Ok(()) } else { message_identity::release(&request.identity) };
    let _ = dispatcher_objects::dereference(port.pointer);
    result
}

pub fn cancel_port(port: &Arc<Port>) {
    let request = PENDING.lock().iter().find(|(candidate, _)| Arc::ptr_eq(candidate, port)).map(|(_, request)| request.clone());
    if let Some(request) = request {
        let _ = release_request(&request, 0xC000_0037, false);
    }
}

/// A resposta tem o CID do servidor e o tipo LPC_CONNECTION_REPLY; o
/// serviço fornece a carga e o transporte não inventa dados.
fn finish_server(request: &Arc<Request>, result: JobResult) -> Result<(), KernelError> {
    let port = request.identity.port.clone();
    let identity = &request.identity;
    let (canceled, cancellation_queued, server, synchronous, context, direct) = {
        let state = request.state.lock();
        (state.canceled, state.cancellation_queued, state.server, state.synchronous, state.context, state.direct)
    };
    // Cancelar uma conexão entregue impede a aceitação tardia; a notificação
    // já enfileirada conserva a identidade até ser recebida.
    if canceled {
        port.with(|state| state.connection_state = port_objects::CONNECTION_CANCELED);
        return release_request(request, 0xC000_0703, cancellation_queued);
    }
    let sender = result.sender.unwrap_or(server);
    let thread_pointer = if sender.thread_pointer != 0 { sender.thread_pointer } else { server.thread_pointer };
    let service_process = port.with(|state| state.service_process);
    if process::thread_record(thread_pointer).is_none_or(|thread| thread.process != service_process) {
        return Err(KernelError::new("ALPC connection reply has no owning server thread"));
    }
    let status = result.status;
    if status == 0 && result.data.len() as u64 + 40 > port.maximum() as u64 {
        return Err(KernelError::new("ALPC server supplied an oversized connection reply"));
    }
    let bytes = if status != 0 { None } else { Some(transport::reply(&result.data, 11, identity, Some(sender))) };
    request.state.lock().connect_result = Some((status, bytes.clone()));
    port.with(|state| state.connection_state = if status != 0 { port_objects::CONNECTION_REFUSED } else { port_objects::CONNECTION_CONNECTED });
    message_identity::clear_attributes(identity);
    identity.with(|state| state.replied = true);
    if synchronous {
        return Ok(());
    }
    let message = Message { bytes, context, reserve: None, id: identity.identifier, identity: identity.clone(), sequence: 1, status, sender: Some(sender), synchronous: false, direct: direct.is_some() };
    identity.with(|state| {
        state.queued = true;
        state.direct = message.direct;
    });
    port.with(|state| state.pending.push(message));
    if let Some(event) = direct {
        dispatcher::set_event(event);
    } else if let Some(completion) = port.with(|state| state.completion.clone()) {
        completion.notify();
    }
    release_request(request, status, true)
}

fn poll_request(request: &Arc<Request>) -> Result<(), KernelError> {
    let port = request.identity.port.clone();
    let job = {
        let mut state = request.state.lock();
        if state.released || state.connect_result.is_some() || state.polling {
            return Ok(());
        }
        if port.closed() {
            state.connect_result = Some((0xC000_0037, None));
            return Ok(());
        }
        state.polling = true;
        state.job.take()
    };
    let result = job.map(|mut job| {
        let result = job.poll();
        (job, result)
    });
    let ready = {
        let mut state = request.state.lock();
        state.polling = false;
        match result {
            Some((job, result)) => {
                if !state.released {
                    state.job = Some(job);
                }
                result
            }
            None => None,
        }
    };
    if port.closed() || request.state.lock().released {
        return Ok(());
    }
    match ready {
        Some(result) => finish_server(request, result),
        None => Ok(()),
    }
}

pub fn pump() {
    let requests: Vec<Arc<Request>> = PENDING.lock().iter().map(|(_, request)| request.clone()).collect();
    for request in requests {
        if request.state.lock().released {
            continue;
        }
        let port = request.identity.port.clone();
        if let Err(error) = port.run(|| poll_request(&request)) {
            crate::debug_print!("[alpc] connection pump: {}", error);
        }
    }
}

/// Segurança e handles usam os donos do transporte; o contexto opaco
/// recebe só identidade e sequência NT.
fn capture_attributes(request: &Arc<Request>, pointer: u64, flags: u32, mode: u8) -> Result<u32, KernelError> {
    if pointer == 0 {
        return Ok(0);
    }
    let port = request.identity.port.clone();
    let identity = &request.identity;
    let valid = guest::read32(pointer + 4);
    if valid & 0x8000_0000 != 0 {
        match message_security::capture(&port, transport::attribute_address(pointer, 0x8000_0000), mode)? {
            Err(status) => return Ok(status),
            Ok(message_security::Captured::Empty) => {}
            Ok(message_security::Captured::Borrowed(borrowed)) => identity.with(|state| state.security = Some(borrowed)),
        }
    }
    if valid & 0x1000_0000 != 0 {
        match message_handles::capture(transport::attribute_address(pointer, 0x1000_0000), mode)? {
            Err(status) => return Ok(status),
            Ok(handles) => identity.with(|state| state.handles = Some(handles)),
        }
    }
    if valid & 0x2000_0000 != 0 {
        let context = transport::attribute_address(pointer, 0x2000_0000);
        if !message_buffer::writable(context, 32, mode) {
            return Ok(0xC000_0005);
        }
        let captured = context_attribute::capture(context, 0, identity);
        request.state.lock().context = captured;
    }
    if valid & 0x0400_0000 != 0 {
        let status = direct_event::validate(flags, valid);
        if status != 0 {
            return Ok(status);
        }
        let handle = guest::read64(transport::attribute_address(pointer, 0x0400_0000));
        if mode != 0 {
            match events::reference(handle, 2) {
                Err(status) => return Ok(status),
                Ok(object) => {
                    let mut state = request.state.lock();
                    state.direct = Some(object.pointer);
                    state.release_direct = Some(Box::new(move || events::release(&object)));
                }
            }
        } else {
            request.state.lock().direct = Some(direct_event::borrow(handle));
        }
    }
    Ok(0)
}

/// Estado da conexão partilhado pela limpeza e pela publicação.
struct Connection {
    port: Option<Arc<Port>>,
    handle: Option<u64>,
    request: Option<Arc<Request>>,
    committed: bool,
    body_held: bool,
    region_held: bool,
    caller_thread: u64,
    output: u64,
    mode: u8,
}

type Shared = Arc<SpinLock<Connection>>;

fn leave_region(shared: &Shared) -> Result<(), KernelError> {
    let caller = {
        let mut connection = shared.lock();
        if !connection.region_held {
            return Ok(());
        }
        connection.region_held = false;
        connection.caller_thread
    };
    if process::get_current_thread() == caller {
        return critical_region::leave_critical();
    }
    // O cancelamento pode vir de outra thread: devolve o contador ao dono;
    // as APCs são entregues no próximo despacho dessa thread.
    let address = caller + kthread::KERNEL_APC_DISABLE;
    let previous = guest::read16(address) as i16;
    if previous >= 0 {
        return Err(KernelError::new("unbalanced ALPC connection critical region"));
    }
    guest::write16(address, (previous + 1) as u16);
    Ok(())
}

fn cleanup(shared: &Shared, status: u32) -> Result<(), KernelError> {
    let (request, committed) = {
        let connection = shared.lock();
        (connection.request.clone(), connection.committed)
    };
    let mut result = Ok(());
    if let Some(request) = request {
        let (released, synchronous) = {
            let state = request.state.lock();
            (state.released, state.synchronous)
        };
        if !released && (synchronous || !committed) {
            result = release_request(&request, status, false);
        }
    }
    let unpublished = {
        let mut connection = shared.lock();
        if connection.committed { None } else { connection.handle.take() }
    };
    if let Some(handle) = unpublished {
        let closed = open_pointer::close(handle).unwrap_or(0xC000_0008);
        if closed != 0 && closed != 0xC000_0008 && result.is_ok() {
            result = Err(KernelError::new("ALPC failed to close its unpublished connection handle"));
        }
    }
    let (port, body_held) = {
        let mut connection = shared.lock();
        (connection.port.clone(), core::mem::replace(&mut connection.body_held, false))
    };
    if let Some(port) = port {
        if body_held {
            let _ = dispatcher_objects::dereference(port.pointer);
        } else {
            dispatcher_objects::collect(port.pointer);
        }
    }
    let left = leave_region(shared);
    result.and(left)
}

fn publish(shared: &Shared) -> u32 {
    let mut connection = shared.lock();
    if !message_buffer::writable(connection.output, 8, connection.mode) {
        return 0xC000_0005;
    }
    guest::write64(connection.output, connection.handle.unwrap_or(0));
    connection.committed = true;
    if let Some(port) = connection.port.clone() {
        if port.with(|state| state.creation_flags) & 0x10 != 0 {
            port.with(|state| state.permanent = true);
            let _ = dispatcher_objects::reference(port.pointer);
        }
    }
    0
}

/// Argumentos: saída, nome (ou OBJECT_ATTRIBUTES da porta de conexão, na
/// variante Ex), OBJECT_ATTRIBUTES do cliente, atributos da porta, flags,
/// segurança exigida do servidor, mensagem, comprimento, atributos de
/// envio, atributos de recepção e timeout.
pub fn begin(arguments: &[u64; 11], access_mode: u8, extended: bool) -> Result<Box<dyn Pending>, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ALPC connect requires PASSIVE_LEVEL"));
    }
    let [output, port_name, object_attributes, port_attributes, flags, required_server_security, connection_message, buffer_length, send_attributes, receive_attributes, timeout] = *arguments;
    let mode = access_mode;
    let flags = (flags as u32) & 0xFFFF_0000;
    let caller_thread = process::get_current_thread();
    critical_region::enter_critical()?;
    let shared: Shared = Arc::new(SpinLock::new(Connection { port: None, handle: None, request: None, committed: false, body_held: false, region_held: true, caller_thread, output, mode }));
    let mut transferred = false;
    let outcome = connect(&shared, &mut transferred, [output, port_name, object_attributes, port_attributes, required_server_security, connection_message, buffer_length, send_attributes, receive_attributes, timeout], flags, mode, extended);
    let outcome = match outcome {
        Err(error) if error.status != 0 => completed(error.status),
        other => other,
    };
    if !transferred {
        let committed = shared.lock().committed;
        cleanup(&shared, if committed { 0 } else { 0xC000_0120 })?;
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn connect(shared: &Shared, transferred: &mut bool, pointers: [u64; 10], flags: u32, mode: u8, extended: bool) -> Result<Box<dyn Pending>, KernelError> {
    let [output, port_name, object_attributes, port_attributes, required_server_security, connection_message, buffer_length, send_attributes, receive_attributes, timeout] = pointers;
    if mode != 0 && !message_buffer::writable(output, 8, mode) {
        return completed(0xC000_0005);
    }
    let captured = match connect_parameters::capture(port_attributes, mode) {
        Ok(captured) => captured,
        Err(status) => return completed(status),
    };
    let listener = if extended {
        let required = match connect_target::required_security(required_server_security, mode) {
            Ok(required) => required,
            Err(status) => return completed(status),
        };
        connect_target::listener(port_name, required.as_ref(), mode)
    } else {
        let required = match connect_capture::identifier(required_server_security, mode) {
            Ok(required) => required,
            Err(status) => return completed(status),
        };
        connect_capture::listener(port_name, required.as_deref(), mode)
    };
    let listener = match listener {
        Ok(listener) => listener,
        Err(status) => return completed(status),
    };
    let creation = match connect_capture::object_attributes(object_attributes, mode) {
        Ok(creation) => creation,
        Err(status) => return completed(status),
    };
    let service = listener.server.service.clone();
    let parameters = match connect_parameters::for_client(&captured, service.max_message_length())? {
        Ok(parameters) => parameters,
        Err(status) => return completed(status),
    };
    let server = listener.server.clone();
    let initial = PortState {
        port_flags: parameters.port_flags,
        security_quality: Some(parameters.security_quality),
        maximum_view_size: parameters.maximum_view_size,
        duplicate_object_types: parameters.duplicate_object_types,
        service: Some(service.clone()),
        service_process: server.process,
        role: Role::Client,
        communication: Some(Arc::new(Communication::default())),
        connection_state: port_objects::CONNECTION_PENDING,
        message_sequence: 1,
        port_context: 0,
        creation_flags: creation.flags,
        exclusive_process: if creation.flags & 0x20 != 0 { process::get_current_process() } else { 0 },
        on_disconnect: Some(transport::disconnect_transport),
        ..PortState::default()
    };
    let (server_thread, server_process, disconnecting) = (server.thread, server.process, service.clone());
    let cleanup_port = Box::new(move |connection: &Arc<Port>| {
        cancel_port(connection);
        transport::cleanup_transport(connection);
        if let Some(client) = connection.with(|state| state.client_security.take()) {
            let _ = client.release();
        }
        let (named, permanent, held) = connection.with(|state| (state.named_node, state.permanent, core::mem::replace(&mut state.server_references_held, false)));
        if let Some(named) = named.filter(|_| !permanent) {
            object_manager::remove_named(named);
        }
        if held {
            let _ = process::dereference_thread(server_thread);
            let _ = process::dereference(server_process);
        }
        if connection.started() {
            disconnecting.disconnect(connection);
        }
    });
    let owner = if parameters.port_flags & 0x10_0000 != 0 { process::get_system_process() } else { process::get_current_process() };
    let port = port_objects::create("alpc", initial, parameters.maximum, 1, creation.pointer, cleanup_port, port_objects::CreateOptions { owner_process: Some(owner), kernel_mode: mode == 0, grant_on_create: true })?;
    let _ = dispatcher_objects::reference(port.pointer);
    {
        let mut connection = shared.lock();
        connection.port = Some(port.clone());
        connection.body_held = true;
    }
    if process::thread_record(server.thread).is_none() {
        return completed(0xC000_0037);
    }
    process::reference(server.process);
    process::reference_thread(server.thread);
    port.with(|state| state.server_references_held = true);
    let caller_thread = shared.lock().caller_thread;
    if parameters.security_quality.tracking == 0 {
        match message_security::capture_client(caller_thread, &parameters.security_quality)? {
            Ok(client) => port.with(|state| state.client_security = Some(client)),
            Err(status) => return completed(status),
        }
    }
    if creation.name.is_some() {
        let Some(parent) = creation.parent else { return completed(0xC000_003A) };
        let Some(named) = object_manager::insert_named(parent, &creation.leaf, "AlpcPort", None, creation.insensitive) else { return completed(0xC000_0035) };
        port.with(|state| state.named_node = Some(named));
    }
    let scratch = guest::alloc_bytes(8);
    if scratch == 0 {
        return completed(0xC000_009A);
    }
    // A inserção concede o acesso da criação; a DACL regula aberturas posteriores.
    let type_pointer = object_types::user_type("alpc").map_or(0, |object_type| object_type.pointer);
    let opened = open_pointer::open(port.pointer, creation.flags & 0x222, 0, 0x1F_0001, type_pointer, 0, scratch);
    let handle = guest::read64(scratch);
    guest::free_bytes(scratch);
    let status = opened?;
    if status != 0 {
        return completed(status);
    }
    shared.lock().handle = Some(handle);
    if flags & 0x1_0000 != 0 {
        return completed(0xC000_000D);
    }
    let message = match connect_capture::message(connection_message, service.max_message_length(), mode) {
        Ok(message) => message,
        Err(status) => return completed(status),
    };
    let receive_buffer = match message_buffer::capture_length(connection_message, buffer_length, mode) {
        Ok(buffer) => buffer,
        Err(status) => return completed(status),
    };
    let status = transport::attributes(receive_attributes, false, mode);
    if status != 0 {
        return completed(status);
    }
    let captured_timeout = match kernel_wait::capture_timeout(timeout, mode) {
        Ok(timeout) => timeout,
        Err(status) => return completed(status),
    };
    let status = transport::attributes(send_attributes, true, mode);
    if status != 0 {
        return completed(status);
    }
    let Some(identity) = message_identity::activate(&port, None)? else { return completed(0xC000_009A) };
    let _ = dispatcher_objects::reference(port.pointer);
    let synchronous = flags & 0x2_0000 != 0;
    let request = Arc::new(Request {
        id: identity.identifier,
        identity: identity.clone(),
        state: SpinLock::new(RequestState { synchronous, server: Sender { process: server.process_id, thread: server.thread_id, thread_pointer: server.thread }, sender: transport::current_sender(), ..RequestState::default() }),
    });
    {
        let (port, owner) = (port.clone(), request.clone());
        identity.with(|state| state.cancel_requested_by = Some(Arc::new(move |requesting: &Arc<Port>, cancellation: u32| transport::cancel_exchange(&port, &owner, requesting, cancellation))));
    }
    shared.lock().request = Some(request.clone());
    PENDING.lock().push((port.clone(), request.clone()));
    identity.with(|state| state.sender_thread = caller_thread);
    process::reference_thread(caller_thread);
    identity.with(|state| {
        state.release_sender = Some(Box::new(move || {
            let _ = process::dereference_thread(caller_thread);
        }))
    });
    let status = capture_attributes(&request, send_attributes, flags, mode)?;
    if status != 0 {
        return completed(status);
    }
    request.state.lock().connect_bytes = transport::reply(&message.data, message.message_type, &identity, None);
    transport::add_port(&port);
    port.set_started(true);
    // O callback pode fechar a própria porta: o job é publicado antes que
    // `run` reavalie a limpeza, para que o cancelamento também o libere.
    let bytes = request.state.lock().connect_bytes.clone();
    let decision = port.run(|| service.connect(&port, &message.data, Some(&bytes)));
    let immediate = match decision {
        Reply::Now(result) => Some(result),
        Reply::Later(job) => {
            request.state.lock().job = Some(job);
            None
        }
    };
    if port.closed() || request.state.lock().released {
        return completed(0xC000_0037);
    }
    if let Some(result) = immediate {
        finish_server(&request, result)?;
    }
    if !synchronous {
        return completed(publish(shared));
    }
    let polled = (shared.clone(), port.clone(), request.clone());
    let operation = kernel_wait::Operation {
        poll: Box::new(move || {
            let (shared, port, request) = &polled;
            let outcome = port.run(|| -> Result<Option<u32>, KernelError> {
                if let Some(status) = request.state.lock().cancel_status {
                    return Ok(Some(status));
                }
                if port.closed() || request.state.lock().released {
                    return Ok(Some(0xC000_0037));
                }
                poll_request(request)?;
                let Some((status, bytes)) = request.state.lock().connect_result.clone() else { return Ok(None) };
                if status != 0 {
                    return Ok(Some(status));
                }
                if connection_message != 0 {
                    let delivered = message_buffer::deliver(&receive_buffer, bytes.as_deref().unwrap_or(&[]), true);
                    if delivered != 0 {
                        return Ok(Some(delivered));
                    }
                }
                let checked = transport::attributes(receive_attributes, false, mode);
                if checked != 0 {
                    return Ok(Some(checked));
                }
                let context = request.state.lock().context;
                transport::publish_attributes(receive_attributes, port, context, 1, &request.identity);
                Ok(Some(publish(shared)))
            });
            outcome.unwrap_or_else(|error| {
                crate::debug_print!("[alpc] connection wait: {}", error);
                Some(0xC000_0001)
            })
        }),
        cleanup: {
            let shared = shared.clone();
            Box::new(move |status| {
                if let Err(error) = cleanup(&shared, status) {
                    crate::debug_print!("[alpc] connection cleanup: {}", error);
                }
            })
        },
    };
    let waiting = kernel_wait::begin(operation, captured_timeout, if flags & 0x10_0000 != 0 { 1 } else { mode }, flags & 0x20_0000 != 0)?;
    *transferred = true;
    Ok(Box::new(waiting))
}
