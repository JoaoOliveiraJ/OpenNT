//! I/O Manager.
//!
//! Toda leitura/escrita em dispositivo vira um IRP entregue à rotina de
//! despacho do driver dono do DEVICE_OBJECT. Este arquivo tem a camada
//! nativa: IofCallDriver/IofCompleteRequest com a semântica do NT, os
//! IoBuild*, o despacho de power IRPs e a espera/cancelamento de IRPs
//! pendentes. A camada de dispositivos do Object Manager (drivers em
//! `\Driver`, abertura com FILE_OBJECT, PnP e energia por caminho) usa estes
//! blocos.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::ke::dispatcher;
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ob::object_manager;
use crate::ntos::po::power_manager;
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::{process, process_context};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, DriverObject, IoStackLocation, IoStatusBlock, Irp, LargeInteger, NtStruct, PowerStateType};
use crate::ntos::io::irp_builder::{self as builder, BuildOptions, DeviceControl, Power};

/// Major functions (subconjunto do NT).
pub mod irp_mj {
    pub const CREATE: u8 = 0x00;
    pub const CLOSE: u8 = 0x02;
    pub const READ: u8 = 0x03;
    pub const WRITE: u8 = 0x04;
    pub const FILE_SYSTEM_CONTROL: u8 = 0x0D;
    pub const DEVICE_CONTROL: u8 = 0x0E;
    pub const INTERNAL_DEVICE_CONTROL: u8 = 0x0F;
    pub const SHUTDOWN: u8 = 0x10;
    pub const CLEANUP: u8 = 0x12;
    pub const POWER: u8 = 0x16;
    pub const PNP: u8 = 0x1B;
}

/// Minor functions de IRP_MJ_PNP / IRP_MJ_POWER (wdm.h).
pub mod irp_mn {
    pub const START_DEVICE: u8 = 0;
    pub const QUERY_REMOVE_DEVICE: u8 = 1;
    pub const REMOVE_DEVICE: u8 = 2;
    pub const CANCEL_REMOVE_DEVICE: u8 = 3;
    pub const STOP_DEVICE: u8 = 4;
    pub const CANCEL_STOP_DEVICE: u8 = 6;
    pub const QUERY_DEVICE_RELATIONS: u8 = 0x07;
    pub const QUERY_INTERFACE: u8 = 0x08;
    pub const QUERY_CAPABILITIES: u8 = 0x09;
    pub const QUERY_RESOURCES: u8 = 0x0A;
    pub const QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0B;
    pub const QUERY_DEVICE_TEXT: u8 = 0x0C;
    pub const FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0D;
    pub const QUERY_ID: u8 = 0x13;
    pub const QUERY_BUS_INFORMATION: u8 = 0x15;
    pub const SURPRISE_REMOVAL: u8 = 0x17;
    pub const WAIT_WAKE: u8 = 0;
    pub const POWER_SEQUENCE: u8 = 1;
    pub const SET_POWER: u8 = 2;
    pub const QUERY_POWER: u8 = 3;
}

/// Status internos do I/O Manager (com sinal).
pub mod status {
    pub const SUCCESS: i32 = 0;
    pub const NOT_FOUND: i32 = -2;
    pub const NOT_SUPPORTED: i32 = -3;
    pub const PENDING: i32 = 0x103;
}

/// IRP.Flags: buffered e buffer alocado pelo I/O Manager.
const IRP_BUFFERED_IO: u32 = 0x10;
const IRP_DEALLOCATE_BUFFER: u32 = 0x20;
/// IO_STACK_LOCATION.Control.
const SL_INVOKE_ON_SUCCESS: u8 = 0x40;
const SL_INVOKE_ON_ERROR: u8 = 0x80;
const STATUS_MORE_PROCESSING_REQUIRED: i32 = 0xC000_0016u32 as i32;

/// IRP vivo do chamador (o PIRP dos exports e dos construtores daqui).
fn irp_at(packet: u64) -> &'static Irp {
    // SAFETY: os chamadores passam IRPs vivos (construídos aqui ou por drivers).
    unsafe { Irp::at(packet) }
}

/// DEVICE_OBJECT vivo do chamador.
fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: os chamadores passam DEVICE_OBJECTs vivos.
    unsafe { DeviceObject::at(device) }
}

/// Stack location de um IRP vivo.
fn location_at(address: u64) -> &'static IoStackLocation {
    // SAFETY: endereço dentro da pilha de stack locations de um IRP vivo.
    unsafe { IoStackLocation::at(address) }
}

/// DEVICE_OBJECT.StackSize lido como byte sem sinal, no mínimo 1.
fn stack_size_of(device: u64) -> u32 {
    (device_at(device).stack_size.get() as u8).max(1) as u32
}

/// Respondedores PnP de PDOs dos bus drivers; `None` = não é meu.
pub type PdoAnswerer = fn(u64, u64) -> Option<i32>;
/// Conclusão observada: (status, information).
pub type Completion = Box<dyn FnOnce(i32, u64) + Send>;

static PDO_ANSWERERS: SpinLock<Vec<PdoAnswerer>> = SpinLock::new(Vec::new());
static COMPLETION_OBSERVERS: SpinLock<BTreeMap<u64, Completion>> = SpinLock::new(BTreeMap::new());
static MANAGED_COMPLETIONS: SpinLock<BTreeMap<u64, Completion>> = SpinLock::new(BTreeMap::new());

pub fn register_pdo_native_answerer(answerer: PdoAnswerer) {
    PDO_ANSWERERS.lock().push(answerer);
}

pub fn observe_completion(irp: u64, callback: Completion) {
    COMPLETION_OBSERVERS.lock().insert(irp, callback);
}

pub fn manage_completion(irp: u64, callback: Completion) {
    MANAGED_COMPLETIONS.lock().insert(irp, callback);
}

pub fn forget_managed_completion(irp: u64) {
    MANAGED_COMPLETIONS.lock().remove(&irp);
}

pub fn forget_completion(irp: u64) {
    COMPLETION_OBSERVERS.lock().remove(&irp);
}

/// Cria `\Driver` e registra o despacho de power IRPs no Power Manager.
pub fn init() -> Result<(), KernelError> {
    object_manager::create_directory("\\Driver")?;
    power_manager::register_power_irp_dispatcher(dispatch_native_power_irp);
    // IoTimers vencidos no laço ocioso.
    dispatcher::register_completion_pump(super::threads::io_timer::check_io_timers);
    Ok(())
}

/// IofCallDriver: CL--, CSL--, grava o DeviceObject no slot e chama
/// MajorFunction[major] do driver dono do dispositivo alvo.
pub fn iof_call_driver(device: u64, packet: u64) -> i32 {
    let irp = irp_at(packet);
    let current_location = irp.current_location.get() as u8;
    let stack_count = irp.stack_count.get() as u8;
    if current_location <= 1 {
        debug_print!("[iom] pilha estourada: irp={:#x} CL={} SC={} dev={:#x}", packet, current_location, stack_count, device);
        return status::NOT_SUPPORTED;
    }
    let address = irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE;
    irp.current_location.set((current_location - 1) as i8);
    irp.tail.overlay.current_stack_location.set(address);
    let location = location_at(address);
    location.device_object.set(device);
    let major = location.major_function.get();
    let driver = device_at(device).driver_object.get();
    if driver == 0 {
        // PDO sem driver nativo: o bus driver responde (estilo pci.sys).
        let answerers = PDO_ANSWERERS.lock().clone();
        for answerer in answerers {
            if let Some(status) = answerer(device, packet) {
                return status;
            }
        }
        return status::NOT_SUPPORTED;
    }
    // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
    let handler = unsafe { DriverObject::at(driver) }.major_function.get(major as usize).map_or(0, Field::get);
    if handler == 0 {
        return status::NOT_SUPPORTED;
    }
    native_call::call(handler, &[device, packet]) as i32
}

/// O IOSB e o buffer de um pedido de modo usuário são memória do processo
/// da thread que pediu (Irp->Tail.Overlay.Thread): a cópia final roda nele,
/// como a APC de conclusão do NT, anexada quando a conclusão chega em outro
/// contexto (um pump, uma DPC). Um processo que já saiu não recebe a cópia
/// (a VA pode ser de outro); endereços da metade de sistema não dependem do
/// processo.
fn complete_in_requester(irp: &Irp, addresses: [u64; 2], copy_back: impl FnOnce()) {
    let user = addresses.iter().any(|&address| address != 0 && address < guest::USER_HALF_END);
    let thread = irp.tail.overlay.thread.get();
    let requester = if user && thread != 0 { process::thread_record(thread).map(|record| record.process) } else { None };
    match requester {
        Some(owner) if owner != process::get_current_process() => {
            if process_state::get(owner).is_none() {
                return;
            }
            if let Err(error) = process_context::with_process(owner, copy_back) {
                debug_print!("[iom] conclusao sem anexar ao processo {:#x}: {}", owner, error);
            }
        }
        _ => copy_back(),
    }
}

/// IofCompleteRequest (NT/ReactOS): do slot atual ao topo, chama as rotinas
/// de conclusão marcadas para o resultado com o DeviceObject do slot acima;
/// o IRP sobe um nível antes de cada chamada e MORE_PROCESSING_REQUIRED
/// interrompe. Depois finaliza o IRP síncrono (UserIosb, UserBuffer,
/// UserEvent, buffer do I/O Manager).
pub fn iof_complete_request(packet: u64) -> i32 {
    let irp = irp_at(packet);
    let stack_count = irp.stack_count.get() as u8 as u32;
    let mut current_location = irp.current_location.get() as u8 as u32;
    let mut current_stack = irp.tail.overlay.current_stack_location.get();
    let mut reviewed = current_stack;
    current_location += 1;
    current_stack += IoStackLocation::SIZE;
    while current_location <= stack_count + 1 {
        let location = location_at(reviewed);
        let control = location.control.get();
        let routine = location.completion_routine.get();
        let status = irp.io_status.status.get();
        let invoke = routine != 0 && ((status >= 0 && control & SL_INVOKE_ON_SUCCESS != 0) || (status < 0 && control & SL_INVOKE_ON_ERROR != 0));
        irp.current_location.set(current_location as u8 as i8);
        irp.tail.overlay.current_stack_location.set(current_stack);
        if invoke {
            // O slot acima do topo não existe: a rotina do criador recebe NULL.
            let device = if current_location == stack_count + 1 { 0 } else { location_at(current_stack).device_object.get() };
            let context = location.context.get();
            let result = native_call::call(routine, &[device, packet, context]) as i32;
            if result == STATUS_MORE_PROCESSING_REQUIRED {
                return result;
            }
        }
        reviewed += IoStackLocation::SIZE;
        current_location += 1;
        current_stack += IoStackLocation::SIZE;
    }
    // IRP associado: libera o associado e devolve a contagem ao mestre.
    if crate::ntos::io::irp_support::complete_associated_irp(packet).unwrap_or(false) {
        return 0;
    }
    // IRP de paginação síncrono (IoPageRead/IoSynchronousPageWrite): UserIosb inteiro,
    // UserEvent e IoFreeIrp, como o ramo IRP_PAGING_IO do IopfCompleteRequest.
    if crate::ntos::io::paging_io::complete_paging_request(packet) {
        return 0;
    }
    let (final_status, information) = builder::read_io_status(packet);
    // O lock sai antes da callback: o dono da conclusão pode esquecer ou
    // registrar outras conclusões dentro dela.
    let managed = MANAGED_COMPLETIONS.lock().remove(&packet);
    if let Some(managed) = managed {
        managed(final_status, irp.io_status.information.get());
        return 0;
    }
    let user_iosb = irp.user_iosb.get();
    let user_buffer = irp.user_buffer.get();
    let system_buffer = irp.associated_irp.system_buffer.get();
    let copy_back = || {
        if user_iosb != 0 {
            // SAFETY: UserIosb do IRP, no processo de quem pediu (o corrente).
            let iosb = unsafe { IoStatusBlock::at(user_iosb) };
            iosb.status.set(final_status);
            iosb.information.set(irp.io_status.information.get());
        }
        if user_buffer != 0 && system_buffer != 0 && (final_status as u32) >> 30 != 3 && information > 0 {
            guest::write_bytes(user_buffer, &guest::read_bytes(system_buffer, information as usize));
        }
    };
    complete_in_requester(irp, [user_iosb, user_buffer], copy_back);
    let user_event = irp.user_event.get();
    if user_event != 0 {
        dispatcher::set_event(user_event);
    }
    // IRP_BUFFERED_IO + DEALLOCATE_BUFFER: o SystemBuffer é do I/O Manager.
    if irp.flags.get() & IRP_DEALLOCATE_BUFFER != 0 {
        if system_buffer != 0 {
            guest::free_bytes(system_buffer);
        }
        irp.associated_irp.system_buffer.set(0);
    }
    let observer = COMPLETION_OBSERVERS.lock().remove(&packet);
    if let Some(observer) = observer {
        observer(final_status, information);
    }
    0
}

/// IoBuildSynchronousFsdRequest: o buffer já é memória de kernel.
pub fn build_synchronous_fsd_request(major: u8, device: u64, buffer: u64, length: u32, byte_offset_pointer: u64, event: u64, io_status: u64) -> u64 {
    let stack_count = stack_size_of(device);
    // SAFETY: StartingOffset (PLARGE_INTEGER) do chamador de modo kernel.
    let byte_offset = if byte_offset_pointer != 0 { unsafe { LargeInteger::at(byte_offset_pointer) }.quad_part.get() as u64 } else { 0 };
    let address = guest::alloc_bytes(builder::size_for(stack_count));
    builder::build(address, &BuildOptions { major, buffer, buffer_length: length, device_object: device, stack_count, byte_offset, user_event: event, user_iosb: io_status, ..Default::default() });
    address
}

/// Contexto opcional do pedido (FILE_OBJECT, modo e thread).
#[derive(Clone, Copy, Default)]
pub struct RequestContext {
    pub file_object: u64,
    pub requestor_mode: u8,
    pub thread: u64,
}

/// IoBuildDeviceIoControlRequest com METHOD_BUFFERED real: a entrada vai
/// para o SystemBuffer na construção e o SystemBuffer para a saída na
/// conclusão; METHOD_NEITHER passa a entrada crua em Type3InputBuffer.
#[allow(clippy::too_many_arguments)]
pub fn build_device_io_control_request(code: u32, device: u64, input: u64, input_length: u32, output: u64, output_length: u32, internal: u64, event: u64, io_status: u64, context: Option<RequestContext>) -> u64 {
    // `internal` é BOOLEAN: só o byte baixo do slot de 8 vale.
    let is_internal = internal & 0xFF != 0;
    let stack_count = stack_size_of(device);
    let method_neither = code & 3 == 3;
    let mut system_buffer = 0;
    if !method_neither {
        system_buffer = guest::alloc_bytes(input_length.max(output_length).max(1) as u64);
        if system_buffer == 0 {
            return 0;
        }
        if input != 0 {
            guest::write_bytes(system_buffer, &guest::read_bytes(input, input_length as usize));
        }
    }
    let address = guest::alloc_bytes(builder::size_for(stack_count));
    if address == 0 {
        if system_buffer != 0 {
            guest::free_bytes(system_buffer);
        }
        return 0;
    }
    let context = context.unwrap_or_default();
    builder::build(address, &BuildOptions {
        major: if is_internal { irp_mj::INTERNAL_DEVICE_CONTROL } else { irp_mj::DEVICE_CONTROL },
        buffer: system_buffer,
        buffer_length: output_length,
        device_object: device,
        stack_count,
        ioctl: Some(DeviceControl { code, input_length, type3_buffer: if method_neither { input } else { 0 } }),
        user_event: event,
        user_iosb: io_status,
        user_buffer: output,
        file_object: context.file_object,
        requestor_mode: context.requestor_mode,
        thread: context.thread,
        ..Default::default()
    });
    if !method_neither {
        irp_at(address).flags.set(IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER);
    }
    address
}

/// Entrega um power IRP já construído (PoCallDriver/PoStartNextPowerIrp).
pub fn dispatch_native_power_irp(device: u64, packet: u64) -> u32 {
    let driver = device_at(device).driver_object.get();
    // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
    let handler = unsafe { DriverObject::at(driver) }.major_function[irp_mj::POWER as usize].get();
    if handler == 0 {
        return status::NOT_SUPPORTED as u32;
    }
    let guest_status = native_call::call(handler, &[device, packet]) as u32;
    let io_status = builder::read_io_status(packet).0;
    if io_status != 0 { io_status as u32 } else { guest_status }
}

/// Resultado de um pedido: texto (dados latin-1), bytes ou nada.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum IoResult {
    #[default]
    None,
    Text(String),
    Bytes(Vec<u8>),
}

/// Os parâmetros do IRP_MJ_CREATE de uma abertura por nome (o
/// IopParseDevice): o acesso pedido vai num IO_SECURITY_CONTEXT com um
/// ACCESS_STATE do sujeito corrente, as opções levam a disposição nos bits
/// altos, e os atributos e o compartilhamento vão como vieram.
#[derive(Clone, Copy, Debug, Default)]
pub struct CreateParameters {
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub file_attributes: u32,
    pub case_sensitive: bool,
}

/// Parâmetros de um pedido do I/O Manager.
#[derive(Clone, Default)]
pub struct IoParams {
    pub minor: u8,
    /// IRP_MJ_CREATE por nome: o contexto de segurança e as opções.
    pub create: Option<CreateParameters>,
    /// Dados de escrita/entrada; `binary` escolhe bytes ou texto no resultado.
    pub data: Option<Vec<u8>>,
    pub binary: bool,
    pub output_length: Option<u32>,
    pub buffer_length: Option<u32>,
    pub control_code: u32,
    pub power: Option<Power>,
    pub requestor_mode: u8,
    pub thread: u64,
    pub resources: u64,
    pub relations_type: Option<u32>,
    pub pnp_slot_pointer: u64,
    pub user_event: u64,
}

/// Pedido de I/O.
#[derive(Clone, Default)]
pub struct IoRequest {
    pub id: u64,
    pub major: u8,
    pub minor: u8,
    pub params: IoParams,
    pub status: i32,
    pub result: IoResult,
    pub info: u64,
    pub file_object: u64,
    pub pending_irp: u64,
    pub pending_buffer: u64,
    pub pending_file_object: u64,
}

static NEXT_REQUEST: SpinLock<u64> = SpinLock::new(1);

pub fn make_io_request(major: u8, params: IoParams) -> IoRequest {
    let id = {
        let mut next = NEXT_REQUEST.lock();
        let id = *next;
        *next += 1;
        id
    };
    IoRequest { id, major, minor: params.minor, params, ..Default::default() }
}

fn release_pending(request: &mut IoRequest) {
    guest::free_bytes(request.pending_irp);
    if request.pending_buffer != 0 {
        guest::free_bytes(request.pending_buffer);
    }
    if request.pending_file_object != 0 {
        let _ = file_objects::dereference(request.pending_file_object);
    }
    request.pending_irp = 0;
    request.pending_buffer = 0;
    request.pending_file_object = 0;
}

/// Finaliza um IRP pendente: espera o evento, lê o status final e libera a
/// memória (o papel do chamador síncrono no NT). Timeout vira STATUS_TIMEOUT.
pub fn wait_pending_io_request(request: &mut IoRequest, timeout_ms: u64) -> i32 {
    if request.pending_irp == 0 {
        return request.status;
    }
    let mut timeout = 0;
    if timeout_ms != 0 {
        timeout = guest::alloc_bytes(LargeInteger::SIZE);
        // SAFETY: alocação de um LARGE_INTEGER (tempo relativo).
        unsafe { LargeInteger::at(timeout) }.quad_part.set(-((timeout_ms * 10_000) as i64));
    }
    let wait = dispatcher::wait_for_single_object(request.params.user_event, timeout, 0, false);
    if timeout != 0 {
        guest::free_bytes(timeout);
    }
    if wait != 0 {
        debug_print!("[iom] IRP pendente NAO completou (timeout {}ms) irp={:#x}", timeout_ms, request.pending_irp);
        request.status = 0x102;
    } else {
        let (final_status, information) = builder::read_io_status(request.pending_irp);
        request.status = final_status;
        request.info = information;
    }
    release_pending(request);
    request.status
}

/// IoCancelIrp de um IRP pendente: marca Cancel, chama a cancel routine
/// (que completa o IRP cancelado) e libera a memória.
pub fn cancel_pending_io_request(request: &mut IoRequest) -> i32 {
    let packet = request.pending_irp;
    if packet == 0 {
        return request.status;
    }
    let irp = irp_at(packet);
    irp.cancel.set(1);
    // IoSetCancelRoutine(Irp, NULL): InterlockedExchangePointer.
    let routine = irp.cancel_routine.atomic().swap(0, core::sync::atomic::Ordering::SeqCst);
    if routine != 0 {
        let device = location_at(irp.tail.overlay.current_stack_location.get()).device_object.get();
        native_call::call(routine, &[device, packet]);
    }
    release_pending(request);
    request.status = 0xC000_0120u32 as i32;
    request.status
}

// ---- Camada de dispositivos do Object Manager --------------------------------

use alloc::sync::Arc;
use core::any::Any;

use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ob::objects::file::FileCallbacks;
use crate::ntos::ob::object_manager::NodeId;
use crate::ntos::rtl::guest_strings;

/// Rotina de despacho de um driver do kernel, por IRP_MJ_x.
pub type DispatchRoutine = fn(NodeId, &mut IoRequest);

struct DriverEntry {
    dispatch: BTreeMap<u8, DispatchRoutine>,
    native: bool,
    devices: Vec<NodeId>,
}

/// Dados de um `\Device\<nome>`.
#[derive(Clone, Default)]
pub struct DeviceEntry {
    pub driver: Option<NodeId>,
    pub native_device: u64,
    pub stack_top: u64,
    pub resources: u64,
    pub pnp_started: bool,
    pub open_count: u32,
    /// Dados do bus driver dono do PDO.
    pub extra: Option<Arc<dyn Any + Send + Sync>>,
    /// PnP: PDO enumerado por um barramento (e o FDO pai), ids de hardware,
    /// pilha já montada, FDO funcional do PDO e o PDO de origem de um FDO.
    pub pdo: bool,
    pub child_of: Option<NodeId>,
    pub hardware_ids: Option<Vec<String>>,
    pub stack_enumerated: bool,
    pub function_stack: Option<NodeId>,
    pub pdo_node: Option<NodeId>,
}

struct OpenHandle {
    device: NodeId,
    file_object: u64,
    external: bool,
}

static DRIVERS: SpinLock<BTreeMap<NodeId, DriverEntry>> = SpinLock::new(BTreeMap::new());
static DEVICES: SpinLock<BTreeMap<NodeId, DeviceEntry>> = SpinLock::new(BTreeMap::new());
static OPEN_HANDLES: SpinLock<BTreeMap<u64, OpenHandle>> = SpinLock::new(BTreeMap::new());
static NEXT_HANDLE: SpinLock<u64> = SpinLock::new(1);

/// Cria `\Driver\<nome>` com rotinas de despacho do kernel.
pub fn create_driver(name: &str, dispatch: &[(u8, DispatchRoutine)]) -> Result<NodeId, KernelError> {
    let node = object_manager::create_object("\\Driver", name, "Driver", None)?;
    DRIVERS.lock().insert(node, DriverEntry { dispatch: dispatch.iter().copied().collect(), native: false, devices: Vec::new() });
    Ok(node)
}

/// Cria `\Driver\<nome>` de um driver nativo: o corpo do objeto é o
/// DRIVER_OBJECT e o despacho vem dele (MajorFunction), não do kernel.
pub fn create_native_driver(name: &str, driver_object: u64) -> Result<NodeId, KernelError> {
    let node = object_manager::create_object("\\Driver", name, "Driver", Some(object_manager::ObjectData::pointer(driver_object)))?;
    DRIVERS.lock().insert(node, DriverEntry { dispatch: BTreeMap::new(), native: true, devices: Vec::new() });
    Ok(node)
}

/// Esquece o registro do driver (nome retirado do namespace).
pub fn forget_driver(driver: NodeId) {
    DRIVERS.lock().remove(&driver);
}

/// Liga um `\Device` já criado ao driver dono (IoCreateDevice).
pub fn attach_device_to_driver(driver: NodeId, device: NodeId) {
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        if !entry.devices.contains(&device) {
            entry.devices.push(device);
        }
    }
}

/// Retira um `\Device` da lista do driver.
pub fn detach_device_from_driver(driver: NodeId, device: NodeId) {
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.devices.retain(|&candidate| candidate != device);
    }
}

/// Marca o driver como nativo (.sys carregado pelo loader PE).
pub fn set_driver_native(driver: NodeId, native: bool) {
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.native = native;
    }
}

/// Cria `\Device\<nome>` ligado ao driver.
pub fn create_device(driver: NodeId, name: &str) -> Result<NodeId, KernelError> {
    let node = object_manager::create_object("\\Device", name, "Device", None)?;
    DEVICES.lock().insert(node, DeviceEntry { driver: Some(driver), ..Default::default() });
    if let Some(entry) = DRIVERS.lock().get_mut(&driver) {
        entry.devices.push(node);
    }
    Ok(node)
}

/// Registra um `\Device` sem driver do kernel (PDO ou pilha nativa).
pub fn register_device(node: NodeId, entry: DeviceEntry) {
    DEVICES.lock().insert(node, entry);
}

pub fn device(node: NodeId) -> Option<DeviceEntry> {
    DEVICES.lock().get(&node).cloned()
}

pub fn update_device(node: NodeId, change: impl FnOnce(&mut DeviceEntry)) -> bool {
    DEVICES.lock().get_mut(&node).map(change).is_some()
}

/// Todos os `\Device` registrados (o percurso da árvore `\Device`).
pub fn devices() -> Vec<(NodeId, DeviceEntry)> {
    DEVICES.lock().iter().map(|(&node, entry)| (node, entry.clone())).collect()
}

/// Esquece o registro de um `\Device` destruído.
pub fn unregister_device(node: NodeId) {
    DEVICES.lock().remove(&node);
}

pub fn driver_devices(driver: NodeId) -> Vec<NodeId> {
    DRIVERS.lock().get(&driver).map(|entry| entry.devices.clone()).unwrap_or_default()
}

/// Rota de um dispositivo por caminho: `Some((gerenciado, topo))`, com o
/// topo da pilha (ou o DEVICE_OBJECT nativo) para os nativos.
pub fn device_route(path: &str) -> Option<(bool, u64)> {
    let node = lookup_device(path)?;
    let entry = devices().into_iter().find(|(id, _)| *id == node).map(|(_, entry)| entry)?;
    let driver_native = entry.driver.and_then(|driver| DRIVERS.lock().get(&driver).map(|driver| driver.native)).unwrap_or(false);
    let managed = entry.driver.is_some() && !driver_native && entry.stack_top == 0;
    Some((managed, if entry.stack_top != 0 { entry.stack_top } else { entry.native_device }))
}

fn lookup_device(path: &str) -> Option<NodeId> {
    object_manager::lookup(path).filter(|&node| object_manager::node(node).is_some_and(|node| node.type_name == "Device"))
}

fn device_path(node: NodeId) -> String {
    alloc::format!("\\Device\\{}", object_manager::node(node).map(|node| node.name).unwrap_or_default())
}

/// Constrói um IRP real e o entrega ao topo da pilha de dispositivos
/// (filtros acima do dono); STATUS_PENDING deixa o IRP vivo para o driver
/// completar depois.
fn call_native_driver(device: &DeviceEntry, request: &mut IoRequest) -> Result<(), KernelError> {
    let device_pointer = if device.stack_top != 0 { device.stack_top } else { device.native_device };
    let stack_count = stack_size_of(device_pointer);
    // FILE_OBJECT da operação: o do handle, ou um transitório.
    let transient = request.file_object == 0;
    let file_object = if transient { file_objects::create(device_pointer, "")? } else { request.file_object };
    let data = request.params.data.clone().unwrap_or_default();
    let data_length = data.len() as u32;
    let major = request.major;
    let needs_buffer = matches!(major, irp_mj::READ | irp_mj::WRITE | irp_mj::DEVICE_CONTROL | irp_mj::FILE_SYSTEM_CONTROL);
    let buffer_length = request.params.output_length.unwrap_or(if major == irp_mj::WRITE { data_length } else { request.params.buffer_length.filter(|&length| length != 0).unwrap_or(2048) });
    let mut buffer = 0;
    if needs_buffer {
        buffer = guest::alloc_bytes(buffer_length.max(data_length).max(1) as u64);
        guest::write_bytes(buffer, &data);
    }
    let packet = guest::alloc_bytes(builder::size_for(stack_count));
    let control = matches!(major, irp_mj::DEVICE_CONTROL | irp_mj::FILE_SYSTEM_CONTROL).then_some(DeviceControl { code: request.params.control_code, input_length: data_length, type3_buffer: 0 });
    builder::build(packet, &BuildOptions {
        major,
        minor: request.minor,
        buffer,
        buffer_length: if needs_buffer { buffer_length } else { 0 },
        device_object: device_pointer,
        power: request.params.power,
        stack_count,
        file_object,
        requestor_mode: request.params.requestor_mode,
        thread: request.params.thread,
        resources: request.params.resources,
        relations_type: request.params.relations_type,
        pnp_slot_pointer: request.params.pnp_slot_pointer,
        user_event: request.params.user_event,
        ioctl: control,
        ..Default::default()
    });
    let security = match (major, request.params.create) {
        (irp_mj::CREATE, Some(create)) => Some(prepare_create(packet, stack_count, &create)?),
        _ => None,
    };
    let guest_status = iof_call_driver(device_pointer, packet);
    if let Some(security) = security {
        release_create(security);
    }
    let (io_status, information) = builder::read_io_status(packet);
    request.status = io_status;
    if request.status == 0 && guest_status != 0 {
        request.status = guest_status;
    }
    request.info = information;
    if guest_status == status::PENDING {
        request.pending_irp = packet;
        request.pending_buffer = buffer;
        if transient {
            request.pending_file_object = file_object;
        }
        return Ok(());
    }
    let mut failure = None;
    if (request.status as u32) >> 30 != 3 && matches!(major, irp_mj::READ | irp_mj::DEVICE_CONTROL | irp_mj::FILE_SYSTEM_CONTROL) && request.info > 0 {
        if request.info > buffer_length as u64 {
            failure = Some(KernelError::new("native driver returned data beyond the I/O buffer"));
        } else {
            let bytes = guest::read_bytes(buffer, request.info as usize);
            request.result = if request.params.binary { IoResult::Bytes(bytes) } else { IoResult::Text(bytes.iter().map(|&byte| byte as char).collect()) };
        }
    }
    guest::free_bytes(packet);
    if buffer != 0 {
        guest::free_bytes(buffer);
    }
    if transient {
        let _ = file_objects::dereference(file_object);
    }
    failure.map_or(Ok(()), Err)
}

/// O IO_SECURITY_CONTEXT e o ACCESS_STATE de um IRP_MJ_CREATE.
struct CreateSecurity {
    context: u64,
    access_state: u64,
    aux: u64,
}

/// SL_CASE_SENSITIVE (IO_STACK_LOCATION.Flags do IRP_MJ_CREATE).
const SL_CASE_SENSITIVE: u8 = 0x80;
/// IRP_CREATE_OPERATION | IRP_SYNCHRONOUS_API.
const IRP_CREATE_FLAGS: u32 = 0x80 | 0x4;

/// Preenche a stack location do IRP_MJ_CREATE em `packet`: o contexto de
/// segurança (ACCESS_STATE do SeCreateAccessState sobre a thread e o
/// processo correntes, com o mapeamento genérico do tipo File), as opções
/// (disposição << 24 | opções de criação), os atributos e o
/// compartilhamento.
fn prepare_create(packet: u64, stack_count: u32, create: &CreateParameters) -> Result<CreateSecurity, KernelError> {
    use crate::ntos::inc::types::{AccessState, AuxAccessData, GenericMapping, IoSecurityContext};
    let context = guest::alloc_bytes(IoSecurityContext::SIZE);
    let access_state = guest::alloc_bytes(AccessState::SIZE);
    let aux = guest::alloc_bytes(AuxAccessData::SIZE);
    let mapping = guest::alloc_bytes(GenericMapping::SIZE);
    if context == 0 || access_state == 0 || aux == 0 || mapping == 0 {
        for block in [context, access_state, aux, mapping] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return Err(KernelError::with_status("IRP_MJ_CREATE sem memoria", 0xC000_009A));
    }
    let file_type = crate::ntos::ob::object_types::file_type();
    // SAFETY: blocos recém-alocados com os tamanhos dos tipos.
    let (generic, state, aux_data, security) = unsafe { (GenericMapping::at(mapping), AccessState::at(access_state), AuxAccessData::at(aux), IoSecurityContext::at(context)) };
    generic.generic_read.set(file_type.mapping[0]);
    generic.generic_write.set(file_type.mapping[1]);
    generic.generic_execute.set(file_type.mapping[2]);
    generic.generic_all.set(file_type.mapping[3]);
    let created = crate::ntos::se::access_state::create(process::get_current_thread(), process::get_current_process(), state, aux_data, create.access, Some(generic));
    guest::free_bytes(mapping);
    if let Err(error) = created {
        for block in [context, access_state, aux] {
            guest::free_bytes(block);
        }
        return Err(error);
    }
    security.security_qos.set(0);
    security.access_state.set(access_state);
    security.desired_access.set(state.remaining_desired_access.get() | state.previously_granted_access.get());
    security.full_create_options.set(create.options);
    let location = location_at(builder::first_stack_location(packet, stack_count));
    let parameters = &location.parameters.create;
    parameters.security_context.set(context);
    parameters.options.set((create.disposition << 24) | (create.options & 0x00FF_FFFF));
    parameters.file_attributes.set(create.file_attributes as u16);
    parameters.share_access.set(create.share as u16);
    parameters.ea_length.set(0);
    location.flags.set(if create.case_sensitive { SL_CASE_SENSITIVE } else { 0 });
    // SAFETY: o IRP recém-montado por `builder::build`.
    let irp = unsafe { Irp::at(packet) };
    irp.flags.set(irp.flags.get() | IRP_CREATE_FLAGS);
    Ok(CreateSecurity { context, access_state, aux })
}

/// Desfaz o ACCESS_STATE e libera os blocos do contexto de segurança.
fn release_create(security: CreateSecurity) {
    // SAFETY: o ACCESS_STATE criado por `prepare_create`.
    let _ = crate::ntos::se::access_state::delete(unsafe { crate::ntos::inc::types::AccessState::at(security.access_state) });
    for block in [security.context, security.access_state, security.aux] {
        guest::free_bytes(block);
    }
}

/// O dispositivo e o resto do nome de um caminho de abertura: o prefixo mais
/// longo que resolve (com os links do namespace) para um objeto Device, e o
/// que sobra, com a barra inicial (um caminho que termina na barra abre a
/// raiz do sistema de arquivos do dispositivo: o resto é `\`).
pub fn split_device_path(path: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
    for count in (1..=parts.len()).rev() {
        let prefix = alloc::format!("\\{}", parts[..count].join("\\"));
        let Some(node) = lookup_device(&prefix) else { continue };
        let device = device_path(node);
        let mut rest: String = parts[count..].iter().map(|part| alloc::format!("\\{part}")).collect();
        if rest.is_empty() && path.ends_with('\\') {
            rest.push('\\');
        }
        return Some((device, rest));
    }
    None
}

/// IoCallDriver por caminho: driver do kernel, ou a pilha nativa anexada ao
/// dispositivo (PDOs sem driver do kernel podem ter FDO).
pub fn call_driver(path: &str, request: &mut IoRequest) -> Result<(), KernelError> {
    let Some(node) = lookup_device(path) else {
        request.status = status::NOT_FOUND;
        return Ok(());
    };
    let entry = device(node).unwrap_or_default();
    let driver_native = entry.driver.and_then(|driver| DRIVERS.lock().get(&driver).map(|driver| driver.native)).unwrap_or(false);
    if driver_native || entry.stack_top != 0 || (entry.native_device != 0 && entry.driver.is_none()) {
        return call_native_driver(&entry, request);
    }
    let Some(driver) = entry.driver else {
        request.status = status::NOT_SUPPORTED;
        return Ok(());
    };
    let handler = DRIVERS.lock().get(&driver).and_then(|driver| driver.dispatch.get(&request.major).copied());
    match handler {
        Some(handler) => handler(node, request),
        None => request.status = status::NOT_SUPPORTED,
    }
    Ok(())
}

pub fn write(path: &str, data: &[u8]) -> Result<IoRequest, KernelError> {
    let mut request = make_io_request(irp_mj::WRITE, IoParams { data: Some(data.to_vec()), ..Default::default() });
    call_driver(path, &mut request)?;
    Ok(request)
}

pub fn read(path: &str) -> Result<IoRequest, KernelError> {
    let mut request = make_io_request(irp_mj::READ, IoParams::default());
    call_driver(path, &mut request)?;
    Ok(request)
}

pub fn device_control(path: &str, control_code: u32, params: IoParams) -> Result<IoRequest, KernelError> {
    let mut request = make_io_request(irp_mj::DEVICE_CONTROL, IoParams { control_code, ..params });
    call_driver(path, &mut request)?;
    Ok(request)
}

/// Resultado de `open_device`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub status: i32,
    pub handle: u64,
    pub file_object: u64,
    /// O IoStatus.Information do IRP_MJ_CREATE.
    pub information: u64,
}

/// IRP_MJ_CREATE no topo da pilha: um handle é um FILE_OBJECT vivo. O handle
/// referencia o dispositivo (ObReferenceObject), protegendo o driver de
/// unload; CLEANUP e CLOSE vão ao driver pelas rotinas do FILE_OBJECT.
pub fn open_device(path: &str, external_handles: bool) -> Result<Opened, KernelError> {
    open_device_file(path, "", None, external_handles)
}

/// FILE_OBJECT.Flags de uma abertura por nome, como o IopParseDevice os
/// deriva das opções de criação: FO_SYNCHRONOUS_IO (com FO_ALERTABLE_IO na
/// variante alertável), FO_NO_INTERMEDIATE_BUFFERING, FO_WRITE_THROUGH,
/// FO_SEQUENTIAL_ONLY, FO_RANDOM_ACCESS e FO_OPENED_CASE_SENSITIVE.
fn file_object_flags(create: &CreateParameters) -> u32 {
    let options = create.options;
    let mut flags = 0;
    if options & 0x30 != 0 {
        flags |= 0x2;
    }
    if options & 0x10 != 0 {
        flags |= 0x4;
    }
    if options & 0x8 != 0 {
        flags |= 0x8;
    }
    if options & 0x2 != 0 {
        flags |= 0x10;
    }
    if options & 0x4 != 0 {
        flags |= 0x20;
    }
    if options & 0x800 != 0 {
        flags |= 0x0010_0000;
    }
    if create.case_sensitive {
        flags |= 0x0002_0000;
    }
    flags
}

/// A abertura de `name` (o resto do caminho depois do dispositivo, vazio
/// para o próprio dispositivo) no dispositivo `path`: o FILE_OBJECT com o
/// nome e, com `create`, o IRP_MJ_CREATE com o contexto de segurança e as
/// opções (o IopParseDevice). O Information do IRP (FILE_OPENED,
/// FILE_CREATED...) volta em `Opened::information`.
pub fn open_device_file(path: &str, name: &str, create: Option<CreateParameters>, external_handles: bool) -> Result<Opened, KernelError> {
    let Some(node) = lookup_device(path) else {
        return Ok(Opened { status: status::NOT_FOUND, handle: 0, file_object: 0, information: 0 });
    };
    let entry = device(node).unwrap_or_default();
    let top = if entry.stack_top != 0 { entry.stack_top } else { entry.native_device };
    let file_object = file_objects::create(top, name)?;
    if let Some(create) = &create {
        // SAFETY: o FILE_OBJECT recém-criado.
        let object = unsafe { crate::ntos::inc::types::FileObject::at(file_object) };
        object.flags.set(object.flags.get() | file_object_flags(create));
    }
    let mut request = make_io_request(irp_mj::CREATE, IoParams { create, ..IoParams::default() });
    request.file_object = file_object;
    call_driver(path, &mut request)?;
    if request.status != status::SUCCESS {
        let _ = file_objects::dereference(file_object);
        return Ok(Opened { status: request.status, handle: 0, file_object: 0, information: request.info });
    }
    let information = request.info;
    if top != 0 {
        // InterlockedIncrement do DEVICE_OBJECT.ReferenceCount, como o parse.
        device_at(top).reference_count.atomic().fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    }
    update_device(node, |entry| entry.open_count += 1);
    let handle = {
        let mut next = NEXT_HANDLE.lock();
        let handle = *next;
        *next += 1;
        handle
    };
    let cleanup_path = String::from(path);
    let close_path = String::from(path);
    file_objects::set_callbacks(file_object, FileCallbacks {
        cleanup: Some(Arc::new(move || {
            let mut request = make_io_request(irp_mj::CLEANUP, IoParams::default());
            request.file_object = file_object;
            let _ = call_driver(&cleanup_path, &mut request);
            request.status as u32
        })),
        close: Some(Arc::new(move || {
            let mut request = make_io_request(irp_mj::CLOSE, IoParams::default());
            request.file_object = file_object;
            let _ = call_driver(&close_path, &mut request);
            if top != 0 {
                device_at(top).reference_count.atomic().fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                device_objects::changed(top);
            }
            update_device(node, |entry| entry.open_count -= 1);
        })),
        destroy: None,
    })?;
    if external_handles {
        // O provedor de usuário é dono de cada handle publicado; esta
        // descrição retém só a referência do CREATE.
        file_objects::mark_opened(file_object)?;
    } else {
        file_objects::open_handle(file_object)?;
        file_objects::dereference(file_object)?;
    }
    OPEN_HANDLES.lock().insert(handle, OpenHandle { device: node, file_object, external: external_handles });
    Ok(Opened { status: status::SUCCESS, handle, file_object, information })
}

pub fn cleanup_device(handle: u64) -> Result<i32, KernelError> {
    let Some(file_object) = OPEN_HANDLES.lock().get(&handle).map(|entry| entry.file_object) else { return Ok(status::NOT_FOUND) };
    file_objects::cleanup(file_object).map(|status| status as i32)
}

pub fn close_device(handle: u64) -> Result<i32, KernelError> {
    let Some(entry) = OPEN_HANDLES.lock().remove(&handle) else { return Ok(status::NOT_FOUND) };
    if entry.external {
        file_objects::dereference(entry.file_object)?;
        return Ok(0);
    }
    file_objects::close_handle(entry.file_object).map(|status| status as i32)
}

fn handle_request(handle: u64, major: u8, params: IoParams) -> Result<IoRequest, KernelError> {
    let mut request = make_io_request(major, params);
    let Some((device, file_object)) = OPEN_HANDLES.lock().get(&handle).map(|entry| (entry.device, entry.file_object)) else {
        request.status = status::NOT_FOUND;
        return Ok(request);
    };
    request.file_object = file_object;
    call_driver(&device_path(device), &mut request)?;
    Ok(request)
}

/// I/O num handle aberto (o FILE_OBJECT é o do handle).
pub fn read_handle(handle: u64, params: IoParams) -> Result<IoRequest, KernelError> {
    handle_request(handle, irp_mj::READ, params)
}

pub fn write_handle(handle: u64, data: &[u8]) -> Result<IoRequest, KernelError> {
    handle_request(handle, irp_mj::WRITE, IoParams { data: Some(data.to_vec()), ..Default::default() })
}

/// IRP_MN_START_DEVICE com os recursos alocados; STATUS_PENDING faz o PnP
/// esperar o KEVENT do IRP (o driver completa assíncrono).
pub fn pnp_start_device(device_node: NodeId) -> Result<i32, KernelError> {
    let event = guest::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 1, false);
    let resources = device(device_node).map_or(0, |entry| entry.resources);
    let mut request = make_io_request(irp_mj::PNP, IoParams { minor: irp_mn::START_DEVICE, resources, user_event: event, ..Default::default() });
    // A árvore de devnodes fica travada durante o START (região crítica).
    super::pnp::with_device_tree_lock(|| -> Result<(), KernelError> {
        call_driver(&device_path(device_node), &mut request)?;
        if request.status == status::PENDING {
            wait_pending_io_request(&mut request, 10_000);
        }
        Ok(())
    })?;
    guest::free_bytes(event);
    update_device(device_node, |entry| entry.pnp_started = request.status == status::SUCCESS);
    Ok(request.status)
}

/// IRP_MN_REMOVE_DEVICE.
pub fn pnp_remove_device(device_node: NodeId) -> Result<i32, KernelError> {
    let mut request = make_io_request(irp_mj::PNP, IoParams { minor: irp_mn::REMOVE_DEVICE, ..Default::default() });
    call_driver(&device_path(device_node), &mut request)?;
    Ok(request.status)
}

/// IRP_MN_QUERY_ID (BUS_QUERY_ID_TYPE): o despacho do kernel devolve texto;
/// a pilha nativa devolve em Information um ponteiro para a string wide.
pub fn query_device_id(path: &str, id_type: u32) -> Result<Option<String>, KernelError> {
    let mut request = make_io_request(irp_mj::PNP, IoParams { minor: irp_mn::QUERY_ID, relations_type: Some(id_type), ..Default::default() });
    call_driver(path, &mut request)?;
    if request.status != status::SUCCESS {
        return Ok(None);
    }
    if let IoResult::Text(text) = &request.result {
        return Ok(Some(text.clone()));
    }
    if request.info != 0 {
        let id = guest_strings::read_wide_string(request.info);
        guest::free_bytes(request.info);
        return Ok(Some(id));
    }
    Ok(None)
}

/// IRP_MJ_POWER SET/QUERY_POWER contabilizado no Power Manager.
fn send_power_request(path: &str, minor: u8, device_state: u32) -> Result<IoRequest, KernelError> {
    let Some(node) = lookup_device(path) else {
        let mut request = make_io_request(irp_mj::POWER, IoParams { minor, ..Default::default() });
        request.status = status::NOT_FOUND;
        return Ok(request);
    };
    let pointer = device(node).map_or(0, |entry| entry.native_device);
    let mut request = make_io_request(irp_mj::POWER, IoParams { minor, power: Some(Power { power_state_type: PowerStateType::DEVICE_POWER_STATE.0 as u32, device_state }), ..Default::default() });
    if pointer != 0 {
        power_manager::mark_power_request_started(pointer);
    }
    let result = call_driver(path, &mut request);
    if pointer != 0 {
        power_manager::mark_power_request_done(pointer);
    }
    result.map(|_| request)
}

pub fn set_device_power_state(path: &str, device_state: u32) -> Result<IoRequest, KernelError> {
    send_power_request(path, irp_mn::SET_POWER, device_state)
}

pub fn query_device_power_state(path: &str, device_state: u32) -> Result<IoRequest, KernelError> {
    send_power_request(path, irp_mn::QUERY_POWER, device_state)
}

pub fn get_device_power_state(path: &str) -> Option<u32> {
    let node = lookup_device(path)?;
    Some(power_manager::get_device_power_state(device(node).map_or(0, |entry| entry.native_device)))
}
