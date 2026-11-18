//! NtNotifyChangeDirectoryFile(Ex): o pedido de notificação de mudança num
//! diretório, pelo ZwNotifyChangeDirectoryFile (modo anterior KernelMode,
//! abaixo) e de modo usuário ([`notify_change_directory_user`], o
//! FindFirstChangeNotificationW e o ReadDirectoryChangesW do kernelbase).
//!
//! ntoskrnl 19041: NtNotifyChangeDirectoryFile 0x691630 é o
//! NtNotifyChangeDirectoryFileEx 0x691690 com a classe
//! FileNotifyInformation (1). No ramo KernelMode (o filtro de mudanças só é
//! conferido quando o pedido vem do modo usuário):
//! - IopReferenceFileObject(handle, FILE_LIST_DIRECTORY);
//! - um arquivo com porta de conclusão (CompletionContext) não aceita
//!   ApcRoutine (fora o bit 0): STATUS_INVALID_PARAMETER;
//! - o Event é referenciado e limpo (KeResetEvent); num arquivo síncrono
//!   (FO_SYNCHRONOUS_IO) o lock do arquivo é tomado, e o evento do arquivo é
//!   limpo (IopResetEvent);
//! - IRP_MJ_DIRECTORY_CONTROL / IRP_MN_NOTIFY_CHANGE_DIRECTORY ao
//!   IoGetRelatedDeviceObject, com OriginalFileObject, Thread, RequestorMode
//!   KernelMode, UserEvent, UserIosb e a APC do pedido
//!   (Overlay.AsynchronousParameters); Parameters.NotifyDirectory com Length e
//!   CompletionFilter, e SL_WATCH_TREE nos Flags da stack location;
//! - com Length: DO_BUFFERED_IO usa um SystemBuffer zerado
//!   (IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION, copiado
//!   para o buffer na conclusão) com UserBuffer = Buffer, DO_DIRECT_IO um MDL
//!   das páginas do buffer travadas para escrita, e os demais o próprio
//!   UserBuffer; sem Length, nenhum buffer;
//! - o IopSynchronousServiceTail: o pedido fica pendente até o file system
//!   relatar uma mudança; um arquivo assíncrono devolve STATUS_PENDING e a
//!   conclusão grava o IO_STATUS_BLOCK, sinaliza o evento e entrega a APC
//!   (`file_request`); num arquivo síncrono a thread espera a conclusão.
//!
//! Os arquivos dos volumes do próprio kernel não têm pilha de dispositivos
//! nem file system que acompanhe as mudanças: STATUS_INVALID_DEVICE_REQUEST.

use alloc::boxed::Box;

use crate::ntos::inc::types::{DeviceObject, FileObject, IoStackLocation, Irp, Kthread, NtStruct};
use crate::ntos::io::file::request::{self as file_request, Shared};
use crate::ntos::io::file::{information as file_information, query as query_file};
use crate::ntos::io::io_manager;
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::ke::{apc, dispatcher, irql};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

const STATUS_PENDING: u32 = 0x103;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// IRP_MJ_DIRECTORY_CONTROL / IRP_MN_NOTIFY_CHANGE_DIRECTORY.
const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0C;
const IRP_MN_NOTIFY_CHANGE_DIRECTORY: u8 = 0x02;
/// IO_STACK_LOCATION.Flags: SL_WATCH_TREE.
const SL_WATCH_TREE: u8 = 0x01;
/// IRP.Flags: IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION.
const BUFFERED_INPUT_FLAGS: u32 = 0x70;
/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x04;
const DO_DIRECT_IO: u32 = 0x10;
/// FILE_OBJECT.Flags: FO_SYNCHRONOUS_IO.
const FO_SYNCHRONOUS_IO: u32 = 0x02;
const TAG: u32 = 0x7443_6F49;

/// FILE_OBJECT vivo (referenciado pelo pedido).
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o pedido mantém a referência do FILE_OBJECT.
    unsafe { FileObject::at(file) }
}

/// DEVICE_OBJECT vivo (o relacionado ao arquivo).
fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivo relacionado a um FILE_OBJECT vivo.
    unsafe { DeviceObject::at(device) }
}

/// Os argumentos do NtNotifyChangeDirectoryFileEx (o
/// NtNotifyChangeDirectoryFile é a classe FileNotifyInformation).
pub struct NotifyChange {
    pub handle: u64,
    pub event: u64,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub io_status: u64,
    pub buffer: u64,
    pub length: u32,
    pub completion_filter: u32,
    pub watch_tree: bool,
    /// DIRECTORY_NOTIFY_INFORMATION_CLASS: a FileNotifyExtendedInformation
    /// (2) vira IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX com a classe; as outras, o
    /// IRP_MN_NOTIFY_CHANGE_DIRECTORY.
    pub class: u32,
}

/// DIRECTORY_NOTIFY_INFORMATION_CLASS FileNotifyInformation e
/// FileNotifyExtendedInformation.
pub const FILE_NOTIFY_INFORMATION: u32 = 1;
const FILE_NOTIFY_EXTENDED_INFORMATION: u32 = 2;
/// IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX.
const IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX: u8 = 0x03;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
/// FILE_LIST_DIRECTORY.
const FILE_LIST_DIRECTORY: u32 = 0x1;

/// O minor e a classe do IRP da notificação.
pub fn notify_minor(class: u32) -> (u8, Option<u32>) {
    if class == FILE_NOTIFY_EXTENDED_INFORMATION { (IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX, Some(class)) } else { (IRP_MN_NOTIFY_CHANGE_DIRECTORY, None) }
}

/// NtNotifyChangeDirectoryFileEx com PreviousMode UserMode (0x691690). Antes
/// do caminho comum, o ramo de modo usuário sonda o primeiro ULONG do
/// IO_STATUS_BLOCK para escrita, o Buffer por ProbeForWrite com alinhamento
/// de ULONG (quando há Length) e exige o CompletionFilter entre 1 e 0xFFF
/// (STATUS_INVALID_PARAMETER). Depois o IopReferenceFileObject pede o
/// FILE_LIST_DIRECTORY do handle. Um arquivo dos volumes do próprio kernel
/// não tem file system que acompanhe as mudanças
/// (STATUS_INVALID_DEVICE_REQUEST); um arquivo de driver segue o IRP do I/O
/// Manager (`io/file/irp_service.rs`). Devolve o NTSTATUS.
pub fn notify_change_directory_user(arguments: &NotifyChange) -> u32 {
    use crate::ntos::io::file::read::probe;
    if !probe(arguments.io_status, 4, true) {
        return STATUS_ACCESS_VIOLATION;
    }
    if arguments.length != 0 {
        if arguments.buffer & 3 != 0 {
            return STATUS_DATATYPE_MISALIGNMENT;
        }
        if !probe(arguments.buffer, arguments.length as u64, true) {
            return STATUS_ACCESS_VIOLATION;
        }
    }
    if arguments.completion_filter == 0 || arguments.completion_filter & 0xFFFF_F000 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if let Some(entry) = crate::ntos::ps::user::state::get_user_handle(arguments.handle).filter(|entry| entry.kind() == "file") {
        return if entry.access() & FILE_LIST_DIRECTORY == 0 { STATUS_ACCESS_DENIED } else { STATUS_INVALID_DEVICE_REQUEST };
    }
    crate::ntos::io::file::irp_service::notify_change_directory(arguments)
}

/// ZwNotifyChangeDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
/// IoStatusBlock, Buffer, Length, CompletionFilter, WatchTree) -> NTSTATUS.
pub fn notify_change_directory(arguments: &NotifyChange) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ZwNotifyChangeDirectoryFile requires PASSIVE_LEVEL"));
    }
    let thread = process::get_current_thread();
    // SAFETY: a thread corrente.
    if unsafe { Kthread::at(thread) }.special_apc_disable.get() != 0 {
        return Err(KernelError::new("ZwNotifyChangeDirectoryFile requires special APCs enabled"));
    }
    let selected = match query_file::resolve(arguments.handle & !3, false) {
        Ok(selected) => selected,
        Err(status) => return Ok(status),
    };
    if selected.pointer == 0 {
        return Ok(STATUS_INVALID_DEVICE_REQUEST);
    }
    let file = selected.pointer;
    if file_at(file).completion_context.get() != 0 && arguments.apc_routine & !1 != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let device = file_information::related_device(file)?;
    if device == 0 {
        return Ok(STATUS_INVALID_DEVICE_REQUEST);
    }
    let request = file_request::new(file, thread, None, 0, arguments.io_status, arguments.buffer, arguments.length, arguments.apc_routine, arguments.apc_context, false);
    let synchronous = file_at(file).flags.get() & FO_SYNCHRONOUS_IO != 0;
    let mut locked = false;
    let result = (|| -> Result<u32, KernelError> {
        if file_objects::reference(file)?.is_none() {
            return Ok(STATUS_INVALID_HANDLE);
        }
        process::reference_thread(thread);
        request.lock().retained = true;
        if arguments.event != 0 {
            let reference = match file_request::event_reference(arguments.event, 0) {
                Ok(reference) => reference,
                Err(status) => return Ok(status),
            };
            dispatcher::clear_event(reference.pointer);
            request.lock().event = Some(reference);
        }
        if synchronous {
            file_information::acquire_file(file)?;
            locked = true;
        }
        dispatcher::clear_event(file_at(file).event.address());
        if arguments.apc_routine != 0 {
            let routine = file_request::free_routine()?;
            let Ok(packet) = kernel_pool::allocate(0x58, AllocateOptions { paged: false, tag: TAG, ..Default::default() }) else { return Ok(STATUS_INSUFFICIENT_RESOURCES) };
            if routine == 0 || packet == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            apc::initialize(packet, thread, 0, routine, routine, arguments.apc_routine, 0, arguments.apc_context);
            request.lock().apc = packet;
        }
        let status = dispatch(&request, device, arguments)?;
        let (finished, done) = {
            let r = request.lock();
            (r.finished, r.done)
        };
        if !finished && status != STATUS_PENDING && !done {
            return Ok(status);
        }
        if status == STATUS_PENDING && synchronous {
            file_request::wait_finished(&request, thread, file_at(file).flags.get() & file_request::FO_ALERTABLE_IO != 0, 0);
            return Ok(request.lock().status);
        }
        let r = request.lock();
        Ok(if status == STATUS_PENDING && !synchronous { status } else if r.finished { r.status } else { status })
    })();
    if locked {
        file_information::release_file(file)?;
    }
    if !file_request::is_tracked(&request) && !request.lock().finished {
        file_request::cleanup(&request)?;
    }
    match result {
        Err(error) if error.status != 0xC000_0001 => Ok(error.status),
        other => other,
    }
}

/// Parameters.NotifyDirectory(Ex) do slot: Length, CompletionFilter e, no
/// IRP_MN_NOTIFY_CHANGE_DIRECTORY_EX, a classe; SL_WATCH_TREE nos Flags.
pub fn set_parameters(stack: &IoStackLocation, arguments: &NotifyChange, class: Option<u32>) {
    let parameters = &stack.parameters.notify_directory_ex;
    parameters.length.set(arguments.length);
    parameters.completion_filter.set(arguments.completion_filter);
    if let Some(class) = class {
        parameters.directory_notify_information_class.set(crate::ntos::inc::types::DirectoryNotifyInformationClass(class as i32));
    }
    stack.flags.set(if arguments.watch_tree { SL_WATCH_TREE } else { 0 });
}

/// Monta e envia o IRP da notificação; a conclusão fica com o
/// `file_request`.
fn dispatch(request: &Shared, device: u64, arguments: &NotifyChange) -> Result<u32, KernelError> {
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    request.lock().irp = packet;
    let device_flags = device_at(device).flags.get();
    let (mut irp_flags, mut user_buffer) = (0u32, 0u64);
    if arguments.length != 0 {
        if device_flags & DO_BUFFERED_IO != 0 {
            let Ok(system) = kernel_pool::allocate(arguments.length as u64, AllocateOptions { paged: false, tag: TAG, ..Default::default() }) else { return Ok(STATUS_INSUFFICIENT_RESOURCES) };
            if system == 0 {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
            guest::write_bytes(system, &alloc::vec![0u8; arguments.length as usize]);
            {
                let mut r = request.lock();
                r.system = system;
                r.copy_output = true;
            }
            irp_flags = BUFFERED_INPUT_FLAGS;
            user_buffer = arguments.buffer;
        } else if device_flags & DO_DIRECT_IO != 0 {
            if !file_request::fill_mdl(request, true)? {
                return Ok(STATUS_INSUFFICIENT_RESOURCES);
            }
        } else {
            user_buffer = arguments.buffer;
        }
    }
    let (system, file, thread, io_status, event, mdl_address) = {
        let r = request.lock();
        (r.system, r.file, r.thread, r.io_status, r.event.as_ref().map_or(0, |event| event.pointer), r.mdl)
    };
    let (minor, class) = notify_minor(arguments.class);
    irp_builder::build(packet, &BuildOptions {
        major: IRP_MJ_DIRECTORY_CONTROL,
        minor,
        buffer: system,
        device_object: device,
        stack_count: count,
        file_object: file,
        thread,
        requestor_mode: 0,
        user_iosb: io_status,
        user_buffer,
        user_event: event,
        ..Default::default()
    });
    // SAFETY: IRP recém-construído e o slot do topo dele.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    set_parameters(stack, arguments, class);
    irp.mdl_address.set(mdl_address);
    irp.flags.set(irp_flags);
    irp.overlay.asynchronous_parameters.user_apc_routine.set(arguments.apc_routine);
    irp.overlay.asynchronous_parameters.user_apc_context.set(arguments.apc_context);
    let completed = request.clone();
    io_manager::manage_completion(packet, Box::new(move |status, information| {
        {
            let mut r = completed.lock();
            r.done = true;
            r.status = status as u32;
            r.information = information;
        }
        let _ = file_request::finish(&completed);
    }));
    file_request::track(request);
    let status = io_manager::iof_call_driver(device, packet) as u32;
    if !request.lock().done && status != STATUS_PENDING {
        if status >> 30 != 3 {
            return Err(KernelError::new("driver returned without completing its directory notify IRP"));
        }
        // Sem conclusão do driver: a falha real, sem IOSB inventado.
        {
            let mut r = request.lock();
            r.done = true;
            r.status = if status == 0xFFFF_FFFD { STATUS_INVALID_DEVICE_REQUEST } else { status };
            r.information = 0;
        }
        file_request::finish(request)?;
    }
    Ok(status)
}
