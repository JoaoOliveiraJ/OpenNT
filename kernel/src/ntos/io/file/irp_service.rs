//! Os serviços de arquivo de modo usuário sobre um FILE_OBJECT aberto num
//! driver: NtReadFile, NtWriteFile, NtFsControlFile e NtDeviceIoControlFile
//! (o IopXxxControlFile), NtQueryInformationFile, NtSetInformationFile e
//! NtQueryVolumeInformationFile, montados como o I/O Manager do ntoskrnl
//! 19041 os monta.
//!
//! - O handle de usuário dá o FILE_OBJECT e o acesso concedido (conferido
//!   contra o que a operação exige). O IRP sai do StackSize do dispositivo
//!   relacionado (IoGetRelatedDeviceObject), com Tail.Overlay.Thread = a
//!   thread que pede, OriginalFileObject, RequestorMode = UserMode,
//!   UserIosb, UserEvent (o evento do handle, referenciado e limpo),
//!   UserBuffer e os buffers do método: neither I/O (o buffer de usuário no
//!   UserBuffer, o de entrada no Type3InputBuffer) ou buffered (SystemBuffer
//!   do pool com IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER e, havendo saída,
//!   IRP_INPUT_OPERATION). Ele entra na IrpList da thread
//!   (IopQueueThreadIrp).
//! - IopSynchronousServiceTail: chama o driver; num FILE_OBJECT síncrono
//!   (FO_SYNCHRONOUS_IO, sob o lock do arquivo), STATUS_PENDING vira a espera
//!   de FileObject->Event pelo KeWaitForSingleObject — a thread deixa a CPU
//!   até a conclusão — e o resultado é FileObject->FinalStatus.
//!   NtQueryInformationFile e NtSetInformationFile num arquivo assíncrono
//!   esperam do mesmo jeito um evento e um IO_STATUS_BLOCK locais
//!   (IRP_SYNCHRONOUS_API) e copiam o IO_STATUS_BLOCK para o do usuário.
//! - A conclusão (IopCompleteRequest) roda na thread que pediu: na hora,
//!   quando o driver conclui na própria thread em PASSIVE_LEVEL; senão como
//!   APC especial de kernel para ela, entregue onde ela estiver (bloqueada
//!   numa espera inclusive). Ela copia o SystemBuffer para o UserBuffer
//!   (IRP_INPUT_OPERATION, sem erro), libera o SystemBuffer
//!   (IRP_DEALLOCATE_BUFFER) e as MDLs, grava o IoStatus no UserIosb e
//!   sinaliza o UserEvent (e, num arquivo síncrono, FileObject->Event com
//!   FinalStatus) ou FileObject->Event com FinalStatus — quando não há erro,
//!   ou quando há erro depois de STATUS_PENDING (Irp->PendingReturned) —,
//!   tira o IRP da IrpList, libera-o (IoFreeIrp) e solta o evento e a
//!   referência do FILE_OBJECT (a última, que fecha o arquivo, só em
//!   PASSIVE_LEVEL).
//! - A saída de uma thread cancela as IRPs dela (IoCancelThreadIo); as que
//!   concluem depois disso não tocam mais na memória de usuário.
//! - Classes de informação que o próprio I/O Manager responde, sem IRP:
//!   FileAccessInformation, FileModeInformation, FileAlignmentInformation e,
//!   num arquivo síncrono, FilePositionInformation (consulta e mudança) e
//!   FileModeInformation (mudança); a FileCompletionInformation e a
//!   FileIoCompletionNotificationInformation (a porta de conclusão do
//!   arquivo e os modos FO_SKIP_*, `io/completion/file_port.rs`); de volume,
//!   a FileFsDeviceInformation e a FileFsDriverPathInformation.
//! - A conclusão de um arquivo com porta e com ApcContext (o
//!   UserApcContext do IRP) põe o pacote na IOCP; sem UserEvent, o
//!   FO_SKIP_SET_EVENT deixa o evento do arquivo como está.
//!
//! - NtFsControlFile e NtDeviceIoControlFile (o IRP_MJ_DEVICE_CONTROL do
//!   handle de dispositivo, `ps/user/files.rs`) nos quatro métodos: em
//!   METHOD_IN_DIRECT e METHOD_OUT_DIRECT a entrada vai num SystemBuffer e a
//!   saída num MDL das páginas de usuário travadas (Irp->MdlAddress), que a
//!   conclusão destrava e libera.
//!
//! Fora do NT: o KAPC da conclusão é alocado à parte, não o Tail.Apc do IRP
//! (os últimos bytes do Tail guardam o IrpExtension, que o IoFreeIrp
//! libera); o Fast I/O não é tentado nas leituras, nas escritas e no
//! NtFsControlFile (o IRP chega ao mesmo resultado); leituras e escritas de
//! dispositivos DO_DIRECT_IO e a rotina de APC de usuário (ApcRoutine) ainda
//! não são atendidas (STATUS_NOT_SUPPORTED). O MmMapLockedPagesSpecifyCache
//! de um MDL de usuário devolve a VA de usuário (`mm/mdl.rs`): um driver que
//! escreve nela fora do processo de quem pediu não alcança as páginas.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{DeviceObject, FileObject, IoStackLocation, IoStatusBlock, Irp, Kapc, Kevent, Mdl, NtStruct};
use crate::ntos::io::file::{information, query};
use crate::ntos::io::irp_builder::{self, BuildOptions};
use crate::ntos::io::threads::thread_requests;
use crate::ntos::io::completion::file_port;
use crate::ntos::io::{cancel, io_manager};
use crate::ntos::ke::{apc, dispatcher, irql};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::ntos::ps::user::events::{self, EventObject};
use crate::rtl::SpinLock;

const STATUS_SUCCESS: u32 = 0;
const STATUS_PENDING: u32 = 0x103;
const STATUS_ALERTED: u32 = 0x101;
const STATUS_USER_APC: u32 = 0xC0;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_VERIFY_REQUIRED: u32 = 0x8000_0016;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_THREAD_IS_TERMINATING: u32 = 0xC000_004B;

/// IRP.Flags (wdm.h).
const IRP_SYNCHRONOUS_API: u32 = 0x4;
const IRP_BUFFERED_IO: u32 = 0x10;
const IRP_DEALLOCATE_BUFFER: u32 = 0x20;
const IRP_INPUT_OPERATION: u32 = 0x40;
const IRP_READ_OPERATION: u32 = 0x100;
const IRP_WRITE_OPERATION: u32 = 0x200;
const IRP_DEFER_IO_COMPLETION: u32 = 0x800;
/// FILE_OBJECT.Flags (wdm.h).
const FO_SYNCHRONOUS_IO: u32 = 0x2;
const FO_ALERTABLE_IO: u32 = 0x4;
const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
const FO_WRITE_THROUGH: u32 = 0x10;
const FO_SEQUENTIAL_ONLY: u32 = 0x20;
const FO_NAMED_PIPE: u32 = 0x80;
const FO_MAILSLOT: u32 = 0x200;
const FO_DELETE_ON_CLOSE: u32 = 0x1_0000;
/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x4;
const DO_DIRECT_IO: u32 = 0x10;
/// MDL.MdlFlags: MDL_PAGES_LOCKED.
const MDL_PAGES_LOCKED: i16 = 0x2;
/// Direitos de arquivo e de evento.
const FILE_READ_DATA: u32 = 0x1;
const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const EVENT_MODIFY_STATE: u32 = 0x2;
/// Major/minor functions.
const IRP_MJ_READ: u8 = 0x03;
const IRP_MJ_WRITE: u8 = 0x04;
const IRP_MJ_QUERY_INFORMATION: u8 = 0x05;
const IRP_MJ_SET_INFORMATION: u8 = 0x06;
const IRP_MJ_FILE_SYSTEM_CONTROL: u8 = 0x0D;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MN_USER_FS_REQUEST: u8 = 0x00;
/// Modos do KeWaitForSingleObject.
const KERNEL_MODE: u8 = 0;
const USER_MODE: u8 = 1;
/// Métodos de transferência (CTL_CODE).
const METHOD_BUFFERED: u32 = 0;
const METHOD_IN_DIRECT: u32 = 1;
const METHOD_OUT_DIRECT: u32 = 2;
const METHOD_NEITHER: u32 = 3;
/// FILE_INFORMATION_CLASS respondidas pelo I/O Manager.
const FILE_ACCESS_INFORMATION: u32 = 8;
const FILE_POSITION_INFORMATION: u32 = 14;
const FILE_MODE_INFORMATION: u32 = 16;
const FILE_ALIGNMENT_INFORMATION: u32 = 17;
const FILE_COMPLETION_INFORMATION: u32 = 30;
const FILE_IO_COMPLETION_NOTIFICATION_INFORMATION: u32 = 41;
/// FILE_USE_FILE_POINTER_POSITION (ByteOffset.HighPart = -1, LowPart = -2).
const FILE_USE_FILE_POINTER_POSITION: i64 = -2;
/// IoStatus.Status ainda não gravado pela conclusão (IO_STATUS_BLOCK local).
const UNWRITTEN: i32 = -1;

/// IopSetOperationLength do ntoskrnl 19041 (tamanho mínimo de cada classe
/// do NtSetInformationFile; 0 = classe inválida para mudança).
const SET_MINIMUM: [u8; 76] = [
    0, 0, 0, 0, 40, 0, 0, 0, 0, 0, 24, 24, 0, 1, 8, 0, 4, 0, 0, 8, 8, 0, 0, 8, 0, 16, 0, 8, 0, 72, 16, 24, 56, 0, 0, 0, 16, 0, 0, 8, 8, 4, 16, 4, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 4, 24, 0, 8, 0, 16, 0, 4, 24, 0, 4, 4,
];
/// IopSetOperationAccess do ntoskrnl 19041 (acesso exigido do handle).
const SET_ACCESS: [u32; 76] = [
    0, 0, 0, 0, 0x100, 0, 0, 0, 0, 0, 0x1_0000, 0, 0, 0x1_0000, 0, 0, 0, 0, 0, 0x2, 0x2, 0, 0, 0x100, 0, 0x100, 0, 0, 0, 0, 0, 0x2, 0, 0, 0, 0, 0x2, 0, 0, 0x2, 0x1_0000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFFFF_FFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1_0000,
    0x1_0000, 0, 0x100, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// Uma requisição viva, do IoCallDriver até o IopCompleteRequest.
struct Request {
    /// A thread que pediu (Irp->Tail.Overlay.Thread) e o processo dela.
    thread: u64,
    process: u64,
    /// FILE_OBJECT referenciado pela requisição.
    file: u64,
    /// O evento do handle (o UserEvent), referenciado até a conclusão.
    event: Option<Arc<EventObject>>,
    /// Evento e IO_STATUS_BLOCK locais de NtQuery/SetInformationFile num
    /// arquivo assíncrono (o UserEvent e o UserIosb do IRP).
    local: u64,
    synchronous: bool,
    /// Na IrpList da thread.
    queued: bool,
    /// KAPC da conclusão, quando ela vai para a thread por APC.
    apc: u64,
    /// A thread saiu (IoCancelThreadIo): a conclusão não toca na memória de
    /// usuário.
    abandoned: bool,
    /// O UserApcContext do IRP: o contexto do pacote da porta do arquivo.
    apc_context: u64,
}

static REQUESTS: SpinLock<BTreeMap<u64, Request>> = SpinLock::new(BTreeMap::new());
/// FILE_OBJECTs cuja última referência cai acima de PASSIVE_LEVEL.
static DEFERRED: SpinLock<Vec<u64>> = SpinLock::new(Vec::new());

fn irp_at(packet: u64) -> &'static Irp {
    // SAFETY: IRP vivo alocado por este módulo (até o IoFreeIrp da conclusão).
    unsafe { Irp::at(packet) }
}

fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT referenciado pela requisição ou pelo handle.
    unsafe { FileObject::at(file) }
}

fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivo relacionado a um FILE_OBJECT vivo.
    unsafe { DeviceObject::at(device) }
}

fn nt_error(status: u32) -> bool {
    status >> 30 == 3
}

/// O arquivo de um handle de usuário, referenciado.
struct Target {
    file: u64,
    device: u64,
    access: u32,
    flags: u32,
}

impl Target {
    fn synchronous(&self) -> bool {
        self.flags & FO_SYNCHRONOUS_IO != 0
    }

    fn release(&self) {
        dereference_file(self.file);
    }
}

/// ObReferenceObjectByHandle de um handle de arquivo de modo usuário e o
/// dispositivo relacionado (IoGetRelatedDeviceObject).
fn reference(handle: u64) -> Result<Target, u32> {
    let selected = query::resolve(handle, true)?;
    let file = selected.pointer;
    if file_objects::reference(file).ok().flatten().is_none() {
        return Err(STATUS_INVALID_HANDLE);
    }
    let device = information::related_device(file).unwrap_or(0);
    let target = Target { file, device, access: selected.access, flags: file_at(file).flags.get() };
    if device == 0 {
        target.release();
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(target)
}

/// O arquivo do handle é atendido por este caminho: um FILE_OBJECT de
/// driver cujo dispositivo não pede buffered nem direct I/O nas leituras e
/// escritas (as de um dispositivo DO_BUFFERED_IO seguem `ps/user/device_io`).
pub fn handles_transfer(handle: u64) -> bool {
    let Ok(target) = reference(handle) else { return false };
    let neither = device_at(target.device).flags.get() & (DO_BUFFERED_IO | DO_DIRECT_IO) == 0;
    target.release();
    neither
}

/// Solta uma referência de FILE_OBJECT. A última, que manda o CLOSE ao
/// driver, fica para a bomba em PASSIVE_LEVEL, como a remoção adiada de
/// objetos do NT: a conclusão pode rodar dentro do driver, com os locks
/// dele retidos, ou em APC_LEVEL.
fn dereference_file(file: u64) {
    if file_objects::reference_count(file) == Some(1) {
        DEFERRED.lock().push(file);
        return;
    }
    let _ = file_objects::dereference(file);
}

/// As referências adiadas, soltas em PASSIVE_LEVEL.
fn drain_deferred() {
    if irql::get_irql() != irql::PASSIVE_LEVEL {
        return;
    }
    let files = core::mem::take(&mut *DEFERRED.lock());
    for file in files {
        let _ = file_objects::dereference(file);
    }
}

/// O buffer de usuário aceita a leitura ou a escrita (ProbeForRead/Write).
fn probe(pointer: u64, length: u64, write: bool) -> bool {
    super::read::probe(pointer, length, write)
}

/// O evento opcional do handle, referenciado com EVENT_MODIFY_STATE e limpo
/// (KeClearEvent).
fn reference_event(handle: u64) -> Result<Option<Arc<EventObject>>, u32> {
    if handle == 0 {
        return Ok(None);
    }
    let event = events::reference(handle, EVENT_MODIFY_STATE)?;
    dispatcher::clear_event(event.pointer);
    Ok(Some(event))
}

/// Um IRP para o dispositivo de `target`, montado como o do I/O Manager:
/// a thread corrente, UserMode, o FILE_OBJECT e os campos do pedido.
fn allocate(target: &Target, options: BuildOptions, flags: u32) -> u64 {
    let count = (device_at(target.device).stack_size.get() as u8).max(1) as u32;
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        return 0;
    }
    irp_builder::build(packet, &BuildOptions { device_object: target.device, stack_count: count, file_object: target.file, requestor_mode: USER_MODE, thread: process::get_current_thread(), ..options });
    irp_at(packet).flags.set(flags);
    packet
}

/// A stack location do topo, a do primeiro driver.
fn top_location(packet: u64) -> &'static IoStackLocation {
    let count = irp_at(packet).stack_count.get() as u8 as u32;
    // SAFETY: o slot do topo do IRP recém-montado.
    unsafe { IoStackLocation::at(irp_builder::first_stack_location(packet, count)) }
}

/// Registra a requisição, enfileira o IRP na thread e liga a conclusão. A
/// requisição retém o FILE_OBJECT até o IopCompleteRequest; o serviço
/// guarda a própria referência até sair da cauda, que ainda lê o arquivo.
fn track(packet: u64, target: &Target, event: Option<Arc<EventObject>>, local: u64, apc_context: u64) {
    let _ = file_objects::reference(target.file);
    irp_at(packet).overlay.asynchronous_parameters.user_apc_context.set(apc_context);
    let thread = process::get_current_thread();
    let queued = thread != 0 && thread_requests::insert(packet, thread).is_ok();
    REQUESTS.lock().insert(packet, Request { thread, process: process::get_current_process(), file: target.file, event, local, synchronous: target.synchronous(), queued, apc: 0, abandoned: false, apc_context });
    io_manager::manage_completion(packet, Box::new(move |_, _| completed(packet)));
}

/// IoCallDriver; um slot de MajorFunction vazio conclui o IRP com
/// STATUS_INVALID_DEVICE_REQUEST, como o IopInvalidDeviceRequest.
fn call_driver(device: u64, packet: u64) -> u32 {
    let status = io_manager::iof_call_driver(device, packet);
    if status == io_manager::status::NOT_SUPPORTED {
        let irp = irp_at(packet);
        irp.io_status.status.set(STATUS_INVALID_DEVICE_REQUEST as i32);
        irp.io_status.information.set(0);
        io_manager::iof_complete_request(packet);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    status as u32
}

/// IopCancelAlertedRequest: uma espera alertável interrompida cancela o
/// IRP ainda pendente e espera, sem alerta, a conclusão.
fn cancel_alerted(event: u64, packet: u64) {
    if REQUESTS.lock().contains_key(&packet) {
        let _ = cancel::irp(packet);
    }
    dispatcher::wait_for_single_object(event, 0, KERNEL_MODE, false);
}

/// IopSynchronousServiceTail. Devolve o NTSTATUS do serviço.
fn synchronous_service_tail(target: &Target, packet: u64) -> u32 {
    let status = call_driver(target.device, packet);
    if !target.synchronous() {
        target.release();
        return status;
    }
    let file = file_at(target.file);
    let mut result = status;
    if status == STATUS_PENDING {
        let waited = dispatcher::wait_for_single_object(file.event.address(), 0, USER_MODE, target.flags & FO_ALERTABLE_IO != 0);
        if waited == STATUS_ALERTED || waited == STATUS_USER_APC {
            cancel_alerted(file.event.address(), packet);
        }
        result = if waited == STATUS_THREAD_IS_TERMINATING { waited } else { file.final_status.get() as u32 };
    }
    let _ = information::release_file(target.file);
    target.release();
    result
}

/// Evento e IO_STATUS_BLOCK locais (NtQuery/SetInformationFile num arquivo
/// assíncrono).
fn allocate_local() -> u64 {
    let local = guest::alloc_bytes(Kevent::SIZE + IoStatusBlock::SIZE);
    if local != 0 {
        dispatcher::initialize_event(local, 0, false);
        local_iosb(local).status.set(UNWRITTEN);
    }
    local
}

fn local_iosb(local: u64) -> &'static IoStatusBlock {
    // SAFETY: o IO_STATUS_BLOCK depois do KEVENT do bloco local.
    unsafe { IoStatusBlock::at(local + Kevent::SIZE) }
}

/// A cauda das consultas e mudanças de informação: a síncrona do arquivo,
/// ou a espera do evento local com a cópia do IO_STATUS_BLOCK.
fn information_tail(target: &Target, packet: u64, local: u64, iosb: u64) -> u32 {
    if local == 0 {
        return synchronous_service_tail(target, packet);
    }
    let mut status = call_driver(target.device, packet);
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(local, 0, KERNEL_MODE, false);
        status = local_iosb(local).status.get() as u32;
    }
    let written = local_iosb(local);
    if written.status.get() != UNWRITTEN && write_user_iosb(iosb, written.status.get() as u32, written.information.get()).is_err() {
        status = STATUS_ACCESS_VIOLATION;
    }
    guest::free_bytes(local);
    target.release();
    status
}

fn write_user_iosb(iosb: u64, status: u32, information: u64) -> Result<(), ()> {
    guest::try_write::<i32>(iosb + core::mem::offset_of!(IoStatusBlock, status) as u64, status as i32).map_err(|_| ())?;
    guest::try_write::<u64>(iosb + core::mem::offset_of!(IoStatusBlock, information) as u64, information).map_err(|_| ())
}

/// Encerra um serviço que não chegou ao driver (recusado ou respondido pelo
/// I/O Manager): solta o evento, o lock e o arquivo e devolve `status`.
fn conclude(target: &Target, locked: bool, event: Option<Arc<EventObject>>, status: u32) -> u32 {
    if let Some(event) = event {
        events::release(&event);
    }
    if locked {
        let _ = information::release_file(target.file);
    }
    target.release();
    status
}

// ---- conclusão ---------------------------------------------------------------

/// A conclusão do driver (dentro do IofCompleteRequest, em qualquer
/// contexto): na própria thread em PASSIVE_LEVEL ela termina aqui; senão vai
/// para a thread como APC especial de kernel.
fn completed(packet: u64) {
    let Some((thread, owner, abandoned)) = REQUESTS.lock().get(&packet).map(|request| (request.thread, request.process, request.abandoned)) else { return };
    if abandoned {
        complete(packet, false);
        return;
    }
    if process::get_current_thread() == thread && process::get_current_process() == owner && irql::get_irql() == irql::PASSIVE_LEVEL {
        complete(packet, true);
        return;
    }
    let packet_apc = guest::alloc_bytes(Kapc::SIZE);
    if packet_apc == 0 {
        complete(packet, false);
        return;
    }
    if let Some(request) = REQUESTS.lock().get_mut(&packet) {
        request.apc = packet_apc;
    }
    apc::initialize(packet_apc, thread, 0, complete_request_apc as *const () as u64, abort_request_apc as *const () as u64, 0, KERNEL_MODE, 0);
    if !apc::insert(packet_apc, packet, 0) {
        complete(packet, false);
    }
}

/// KernelRoutine da APC de conclusão, na thread que pediu.
extern "win64" fn complete_request_apc(packet_apc: u64, _normal_routine: u64, _normal_context: u64, _argument1: u64, _argument2: u64) {
    // SAFETY: o KAPC alocado por `completed`, liberado só na conclusão.
    let packet = unsafe { Kapc::at(packet_apc) }.system_argument1.get();
    complete(packet, true);
}

/// RundownRoutine: a thread saiu com a APC na fila.
extern "win64" fn abort_request_apc(packet_apc: u64) {
    // SAFETY: o KAPC alocado por `completed`.
    let packet = unsafe { Kapc::at(packet_apc) }.system_argument1.get();
    complete(packet, false);
}

/// IoFreeMdl de cada MDL do IRP, depois do MmUnlockPages das fixadas.
fn free_mdls(irp: &Irp) {
    let mut mdl = irp.mdl_address.get();
    irp.mdl_address.set(0);
    while mdl != 0 {
        // SAFETY: MDL da cadeia do IRP concluído.
        let descriptor = unsafe { Mdl::at(mdl) };
        let next = descriptor.next.get();
        if descriptor.mdl_flags.get() & MDL_PAGES_LOCKED != 0 {
            let _ = crate::ntos::init::exports::invoke_handler("MmUnlockPages", &[mdl]);
        }
        let _ = crate::ntos::init::exports::invoke_handler("IoFreeMdl", &[mdl]);
        mdl = next;
    }
}

/// IopCompleteRequest. `in_thread`: roda na thread e no processo de quem
/// pediu, com a memória de usuário dele acessível.
fn complete(packet: u64, in_thread: bool) {
    let Some(request) = REQUESTS.lock().remove(&packet) else { return };
    let in_thread = in_thread && !request.abandoned;
    let irp = irp_at(packet);
    let status = irp.io_status.status.get() as u32;
    let information = irp.io_status.information.get();
    let flags = irp.flags.get();
    if flags & IRP_BUFFERED_IO != 0 {
        let system = irp.associated_irp.system_buffer.get();
        if in_thread && flags & IRP_INPUT_OPERATION != 0 && status != STATUS_VERIFY_REQUIRED && !nt_error(status) && information != 0 && system != 0 {
            // A cópia para o buffer de usuário sondada, como o __try do NT.
            let _ = guest::try_write_bytes(irp.user_buffer.get(), &guest::read_bytes(system, information as usize));
        }
        if flags & IRP_DEALLOCATE_BUFFER != 0 && system != 0 {
            let _ = pool_allocation::free(system, 0);
        }
        irp.associated_irp.system_buffer.set(0);
        irp.flags.set(flags & !(IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER));
    }
    free_mdls(irp);
    if !nt_error(status) || irp.pending_returned.get() != 0 {
        let iosb = irp.user_iosb.get();
        if request.local != 0 {
            let local = local_iosb(request.local);
            local.information.set(information);
            local.status.set(status as i32);
            dispatcher::set_event(request.local);
        } else {
            if iosb != 0 && in_thread {
                let _ = write_user_iosb(iosb, status, information);
            }
            let file = file_at(request.file);
            match &request.event {
                Some(event) => {
                    dispatcher::set_event(event.pointer);
                    if request.synchronous {
                        file.final_status.set(status as i32);
                        dispatcher::set_event(file.event.address());
                    }
                }
                None => {
                    file.final_status.set(status as i32);
                    if !file_port::skips_file_event(request.file) {
                        dispatcher::set_event(file.event.address());
                    }
                }
            }
            file_port::complete(request.file, request.apc_context, status, information, irp.pending_returned.get() != 0);
        }
    }
    if request.queued {
        let _ = thread_requests::remove(packet, request.thread);
    }
    if request.apc != 0 {
        guest::free_bytes(request.apc);
    }
    irp_builder::free_irp(packet);
    if let Some(event) = &request.event {
        events::release(event);
    }
    dereference_file(request.file);
}

/// IoCancelThreadIo: a thread que sai cancela as IRPs dela; as conclusões
/// que vierem depois não tocam na memória de usuário.
fn rundown(thread: u64) {
    let pending: Vec<u64> = REQUESTS
        .lock()
        .iter_mut()
        .filter(|(_, request)| request.thread == thread)
        .map(|(&packet, request)| {
            request.abandoned = true;
            packet
        })
        .collect();
    for packet in pending {
        let pending_apc = REQUESTS.lock().get(&packet).is_some_and(|request| request.apc != 0);
        if !pending_apc && REQUESTS.lock().contains_key(&packet) {
            let _ = cancel::irp(packet);
        }
    }
}

/// Liga a saída de threads e a bomba das referências adiadas.
pub fn init() {
    process::register_thread_exit_routine(rundown);
    dispatcher::register_completion_pump(drain_deferred);
}

/// Quantas requisições deste caminho estão vivas para a thread (ETHREAD).
pub fn pending_for_thread(thread: u64) -> usize {
    REQUESTS.lock().values().filter(|request| request.thread == thread).count()
}

// ---- leitura e escrita ---------------------------------------------------------

/// Os argumentos de NtReadFile/NtWriteFile.
#[derive(Clone, Copy)]
pub struct Transfer {
    pub handle: u64,
    pub event: u64,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub io_status: u64,
    pub buffer: u64,
    pub length: u32,
    pub byte_offset: u64,
    pub key: u64,
}

/// NtReadFile (`write` = false) e NtWriteFile de modo usuário.
pub fn transfer(arguments: &Transfer, write: bool) -> u32 {
    let target = match reference(arguments.handle) {
        Ok(target) => target,
        Err(status) => return status,
    };
    let required = if write { FILE_WRITE_DATA | FILE_APPEND_DATA } else { FILE_READ_DATA };
    if target.access & required == 0 {
        return conclude(&target, false, None, STATUS_ACCESS_DENIED);
    }
    if !probe(arguments.io_status, IoStatusBlock::SIZE, true) || !probe(arguments.buffer, arguments.length as u64, !write) {
        return conclude(&target, false, None, STATUS_ACCESS_VIOLATION);
    }
    if arguments.apc_routine != 0 {
        return conclude(&target, false, None, STATUS_NOT_SUPPORTED);
    }
    if device_at(target.device).flags.get() & DO_DIRECT_IO != 0 {
        return conclude(&target, false, None, STATUS_NOT_SUPPORTED);
    }
    if arguments.byte_offset != 0 && arguments.byte_offset & 3 != 0 {
        return conclude(&target, false, None, STATUS_DATATYPE_MISALIGNMENT);
    }
    let offset = if arguments.byte_offset != 0 {
        match guest::try_read::<i64>(arguments.byte_offset) {
            Ok(offset) => Some(offset),
            Err(_) => return conclude(&target, false, None, STATUS_ACCESS_VIOLATION),
        }
    } else {
        None
    };
    let key = if arguments.key != 0 {
        match guest::try_read::<u32>(arguments.key) {
            Ok(key) => key,
            Err(_) => return conclude(&target, false, None, STATUS_ACCESS_VIOLATION),
        }
    } else {
        0
    };
    let event = match reference_event(arguments.event) {
        Ok(event) => event,
        Err(status) => return conclude(&target, false, None, status),
    };
    let synchronous = target.synchronous();
    if synchronous && information::acquire_file(target.file).is_err() {
        return conclude(&target, false, event, STATUS_INSUFFICIENT_RESOURCES);
    }
    let file = file_at(target.file);
    let mut byte_offset = offset.unwrap_or(0);
    if synchronous && (offset.is_none() || offset == Some(FILE_USE_FILE_POINTER_POSITION)) {
        byte_offset = file.current_byte_offset.quad_part.get();
    } else if offset.is_none() && target.flags & (FO_NAMED_PIPE | FO_MAILSLOT) == 0 {
        return conclude(&target, synchronous, event, STATUS_INVALID_PARAMETER);
    }
    if byte_offset < 0 && !(write && byte_offset == -1) {
        return conclude(&target, synchronous, event, STATUS_INVALID_PARAMETER);
    }
    dispatcher::clear_event(file.event.address());
    // DO_BUFFERED_IO: SystemBuffer do pool (a escrita copia a entrada já
    // aqui); neither I/O: o buffer de usuário no UserBuffer.
    let buffered = device_at(target.device).flags.get() & DO_BUFFERED_IO != 0;
    let mut system = 0;
    let mut flags = IRP_DEFER_IO_COMPLETION | if write { IRP_WRITE_OPERATION } else { IRP_READ_OPERATION };
    if buffered && arguments.length != 0 {
        system = guest::alloc_bytes(arguments.length as u64);
        if system == 0 {
            return conclude(&target, synchronous, event, STATUS_INSUFFICIENT_RESOURCES);
        }
        if write {
            match guest::try_read_bytes(arguments.buffer, arguments.length as usize) {
                Ok(bytes) => guest::write_bytes(system, &bytes),
                Err(_) => {
                    let _ = pool_allocation::free(system, 0);
                    return conclude(&target, synchronous, event, STATUS_ACCESS_VIOLATION);
                }
            }
            flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
        } else {
            flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;
        }
    }
    let user_event = event.as_ref().map_or(0, |event| event.pointer);
    let packet = allocate(&target, BuildOptions { major: if write { IRP_MJ_WRITE } else { IRP_MJ_READ }, buffer: system, buffer_length: arguments.length, byte_offset: byte_offset as u64, user_event, user_iosb: arguments.io_status, user_buffer: arguments.buffer, ..BuildOptions::default() }, flags);
    if packet == 0 {
        if system != 0 {
            let _ = pool_allocation::free(system, 0);
        }
        return conclude(&target, synchronous, event, STATUS_INSUFFICIENT_RESOURCES);
    }
    let location = top_location(packet);
    if write {
        location.parameters.write.key.set(key);
    } else {
        location.parameters.read.key.set(key);
    }
    track(packet, &target, event, 0, arguments.apc_context);
    synchronous_service_tail(&target, packet)
}

// ---- controle de file system ---------------------------------------------------

/// Os argumentos de NtFsControlFile.
#[derive(Clone, Copy)]
pub struct Control {
    pub handle: u64,
    pub event: u64,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub io_status: u64,
    pub code: u32,
    pub input: u64,
    pub input_length: u32,
    pub output: u64,
    pub output_length: u32,
}

/// NtFsControlFile de modo usuário: o IopXxxControlFile com
/// IRP_MJ_FILE_SYSTEM_CONTROL / IRP_MN_USER_FS_REQUEST.
pub fn fs_control(arguments: &Control) -> u32 {
    control(arguments, IRP_MJ_FILE_SYSTEM_CONTROL, IRP_MN_USER_FS_REQUEST)
}

/// NtDeviceIoControlFile de modo usuário pelo IRP: o IopXxxControlFile com
/// IRP_MJ_DEVICE_CONTROL, depois do FastIoDeviceControl que quem chama já
/// tentou.
pub fn device_control(arguments: &Control) -> u32 {
    control(arguments, IRP_MJ_DEVICE_CONTROL, 0)
}

/// O IopXxxControlFile: o acesso que o código pede, os buffers do método
/// e o IRP do `major`. METHOD_IN_DIRECT e METHOD_OUT_DIRECT levam a entrada
/// num SystemBuffer e a saída num MDL das páginas de usuário sondadas e
/// travadas (IoAllocateMdl + MmProbeAndLockPages), que a conclusão
/// destrava e libera.
fn control(arguments: &Control, major: u8, minor: u8) -> u32 {
    let target = match reference(arguments.handle) {
        Ok(target) => target,
        Err(status) => return status,
    };
    let method = arguments.code & 3;
    // O acesso que o código pede (FILE_READ_ACCESS/FILE_WRITE_ACCESS).
    let required = (arguments.code >> 14) & 3;
    if (required & 1 != 0 && target.access & FILE_READ_DATA == 0) || (required & 2 != 0 && target.access & FILE_WRITE_DATA == 0) {
        return conclude(&target, false, None, STATUS_ACCESS_DENIED);
    }
    if !probe(arguments.io_status, IoStatusBlock::SIZE, true) {
        return conclude(&target, false, None, STATUS_ACCESS_VIOLATION);
    }
    if arguments.apc_routine != 0 {
        return conclude(&target, false, None, STATUS_NOT_SUPPORTED);
    }
    let direct = method == METHOD_IN_DIRECT || method == METHOD_OUT_DIRECT;
    // A saída de METHOD_IN_DIRECT é lida pelo driver (IoReadAccess); a de
    // METHOD_OUT_DIRECT, escrita (IoWriteAccess).
    if method != METHOD_NEITHER && (!probe(arguments.input, arguments.input_length as u64, false) || !probe(arguments.output, arguments.output_length as u64, method != METHOD_IN_DIRECT)) {
        return conclude(&target, false, None, STATUS_ACCESS_VIOLATION);
    }
    let event = match reference_event(arguments.event) {
        Ok(event) => event,
        Err(status) => return conclude(&target, false, None, status),
    };
    let synchronous = target.synchronous();
    if synchronous && information::acquire_file(target.file).is_err() {
        return conclude(&target, false, event, STATUS_INSUFFICIENT_RESOURCES);
    }
    dispatcher::clear_event(file_at(target.file).event.address());
    let mut system = 0;
    let mut flags = 0;
    let buffered_length = match method {
        METHOD_BUFFERED => arguments.input_length.max(arguments.output_length),
        _ if direct => arguments.input_length,
        _ => 0,
    };
    if buffered_length != 0 {
        system = guest::alloc_bytes(buffered_length as u64);
        if system == 0 {
            return conclude(&target, synchronous, event, STATUS_INSUFFICIENT_RESOURCES);
        }
        if arguments.input_length != 0 {
            match guest::try_read_bytes(arguments.input, arguments.input_length as usize) {
                Ok(bytes) => guest::write_bytes(system, &bytes),
                Err(_) => {
                    let _ = pool_allocation::free(system, 0);
                    return conclude(&target, synchronous, event, STATUS_ACCESS_VIOLATION);
                }
            }
        }
        flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | if method == METHOD_BUFFERED && arguments.output_length != 0 { IRP_INPUT_OPERATION } else { 0 };
    }
    let user_event = event.as_ref().map_or(0, |event| event.pointer);
    let packet = allocate(&target, BuildOptions { major, minor, buffer: system, user_event, user_iosb: arguments.io_status, user_buffer: arguments.output, ..BuildOptions::default() }, flags);
    if packet == 0 {
        if system != 0 {
            let _ = pool_allocation::free(system, 0);
        }
        return conclude(&target, synchronous, event, STATUS_INSUFFICIENT_RESOURCES);
    }
    if direct && arguments.output_length != 0 {
        if crate::ntos::io::mdl::allocate_mdl_for_irp(arguments.output, arguments.output_length, false, packet) == 0 {
            irp_builder::free_irp(packet);
            if system != 0 {
                let _ = pool_allocation::free(system, 0);
            }
            return conclude(&target, synchronous, event, STATUS_INSUFFICIENT_RESOURCES);
        }
        crate::ntos::mm::mdl::probe_and_lock_pages(irp_at(packet).mdl_address.get(), if method == METHOD_IN_DIRECT { 0 } else { 1 });
    }
    // O FileSystemControl e o DeviceIoControl têm o mesmo leiaute.
    let control = &top_location(packet).parameters.device_io_control;
    control.output_buffer_length.set(arguments.output_length);
    control.input_buffer_length.set(arguments.input_length);
    control.io_control_code.set(arguments.code);
    control.type3_input_buffer.set(if method == METHOD_NEITHER { arguments.input } else { 0 });
    track(packet, &target, event, 0, arguments.apc_context);
    synchronous_service_tail(&target, packet)
}

// ---- informação de arquivo -----------------------------------------------------

/// FILE_MODE_INFORMATION.Mode pelas flags do FILE_OBJECT.
fn file_mode(flags: u32) -> u32 {
    let mut mode = 0;
    if flags & FO_WRITE_THROUGH != 0 {
        mode |= 0x2;
    }
    if flags & FO_SEQUENTIAL_ONLY != 0 {
        mode |= 0x4;
    }
    if flags & FO_NO_INTERMEDIATE_BUFFERING != 0 {
        mode |= 0x8;
    }
    if flags & FO_SYNCHRONOUS_IO != 0 {
        mode |= if flags & FO_ALERTABLE_IO != 0 { 0x10 } else { 0x20 };
    }
    if flags & FO_DELETE_ON_CLOSE != 0 {
        mode |= 0x1000;
    }
    mode
}

/// As classes de consulta que o I/O Manager responde sem IRP: o valor e o
/// tamanho escrito.
fn manager_query(target: &Target, class: u32) -> Option<(u64, u64)> {
    match class {
        FILE_ACCESS_INFORMATION => Some((target.access as u64, 4)),
        FILE_MODE_INFORMATION => Some((file_mode(target.flags) as u64, 4)),
        FILE_ALIGNMENT_INFORMATION => Some((device_at(target.device).alignment_requirement.get() as u64, 4)),
        FILE_POSITION_INFORMATION if target.synchronous() => Some((file_at(target.file).current_byte_offset.quad_part.get() as u64, 8)),
        _ => None,
    }
}

/// NtQueryInformationFile de modo usuário num arquivo de driver.
pub fn query_information(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> u32 {
    let validated = query::validate(USER_MODE, class, length, io_status, buffer);
    if validated != 0 {
        return validated;
    }
    let target = match reference(handle) {
        Ok(target) => target,
        Err(status) => return status,
    };
    let required = query::ACCESS[class as usize];
    if required == 0xFFFF_FFFF {
        return conclude(&target, false, None, STATUS_INVALID_INFO_CLASS);
    }
    if required != 0 && target.access & required != required {
        return conclude(&target, false, None, STATUS_ACCESS_DENIED);
    }
    if let Some((value, size)) = manager_query(&target, class) {
        let bytes = value.to_le_bytes();
        let status = if guest::try_write_bytes(buffer, &bytes[..size as usize]).is_err() || write_user_iosb(io_status, STATUS_SUCCESS, size).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS };
        return conclude(&target, false, None, status);
    }
    let synchronous = target.synchronous();
    if synchronous && information::acquire_file(target.file).is_err() {
        return conclude(&target, false, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    let local = if synchronous { 0 } else { allocate_local() };
    let system = guest::alloc_bytes(length as u64);
    if system == 0 || (!synchronous && local == 0) {
        for block in [system, local] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    dispatcher::clear_event(file_at(target.file).event.address());
    let flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION | IRP_DEFER_IO_COMPLETION | if local != 0 { IRP_SYNCHRONOUS_API } else { 0 };
    let (user_event, user_iosb) = if local != 0 { (local, local_iosb(local).address()) } else { (0, io_status) };
    let packet = allocate(&target, BuildOptions { major: IRP_MJ_QUERY_INFORMATION, buffer: system, user_event, user_iosb, user_buffer: buffer, ..BuildOptions::default() }, flags);
    if packet == 0 {
        let _ = pool_allocation::free(system, 0);
        if local != 0 {
            guest::free_bytes(local);
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    let parameters = &top_location(packet).parameters.query_file;
    parameters.length.set(length);
    parameters.file_information_class.set(crate::ntos::inc::types::FileInformationClass(class as i32));
    track(packet, &target, None, local, 0);
    information_tail(&target, packet, local, io_status)
}

/// IopQueryFsOperationLength, o alinhamento do ProbeForWrite e
/// IopQueryFsOperationAccess do ntoskrnl 19041, por FS_INFORMATION_CLASS
/// (0 = classe que não se consulta).
const FS_QUERY_MINIMUM: [u8; 15] = [0, 24, 0, 24, 8, 16, 48, 32, 64, 12, 4, 28, 4, 16, 96];
const FS_QUERY_ALIGNMENT: [u8; 15] = [0, 8, 4, 8, 4, 4, 8, 8, 8, 8, 4, 4, 4, 8, 8];
const FS_QUERY_ACCESS: [u32; 15] = [0, 0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0x80, 0, 0, 0, 0];
/// FileFsDeviceInformation e FileFsDriverPathInformation.
const FILE_FS_DEVICE_INFORMATION: u32 = 4;
const FILE_FS_DRIVER_PATH_INFORMATION: u32 = 9;
/// FO_DIRECT_DEVICE_OPEN, FILE_DEVICE_NETWORK_FILE_SYSTEM,
/// FILE_DEVICE_IS_MOUNTED e VPB_MOUNTED.
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const FILE_DEVICE_NETWORK_FILE_SYSTEM: u32 = 0x14;
const FILE_DEVICE_IS_MOUNTED: u32 = 0x20;
const VPB_MOUNTED: u16 = 0x1;
const IRP_MJ_QUERY_VOLUME_INFORMATION: u8 = 0x0A;

/// IopGetMountFlag: o VPB do dispositivo está montado (lido sob a trava
/// dos VPBs).
fn mount_flag(device: &DeviceObject) -> bool {
    crate::ntos::io::volume_parameters::with_lock(|| {
        let vpb = device.vpb.get();
        // SAFETY: o VPB do dispositivo, estável sob a trava dos VPBs.
        Ok(vpb != 0 && unsafe { crate::ntos::inc::types::Vpb::at(vpb) }.flags.get() & VPB_MOUNTED != 0)
    })
    .unwrap_or(false)
}

/// IopVerifyDriverObjectOnStack: o driver está na pilha do dispositivo,
/// da base (IopGetDeviceAttachmentBase, pelo AttachedTo das extensões) ao
/// topo (AttachedDevice).
fn driver_on_stack(device: u64, driver: u64) -> bool {
    let mut base = device;
    loop {
        let extension = device_at(base).device_object_extension.get();
        // SAFETY: a DEVOBJ_EXTENSION de um dispositivo vivo da pilha.
        let below = if extension != 0 { unsafe { crate::ntos::inc::types::DevobjExtension::at(extension) }.attached_to.get() } else { 0 };
        if below == 0 {
            break;
        }
        base = below;
    }
    let mut current = base;
    while current != 0 {
        if device_at(current).driver_object.get() == driver {
            return true;
        }
        current = device_at(current).attached_device.get();
    }
    false
}

/// FileFsDriverPathInformation (o IopGetDriverPathInformation): o buffer
/// capturado traz o DriverNameLength (+4) e o nome (+8), que precisa caber
/// nele (senão STATUS_INVALID_PARAMETER); o DRIVER_OBJECT vem pelo nome
/// (ObReferenceObjectByName com OBJ_CASE_INSENSITIVE e IoDriverObjectType,
/// em KernelMode) e o DriverInPath diz se ele está na pilha do volume
/// montado (Vpb->DeviceObject) ou, senão, na do dispositivo do arquivo.
fn driver_path_information(file: u64, captured: &[u8]) -> Result<bool, u32> {
    let name_length = u32::from_le_bytes(captured[4..8].try_into().unwrap_or([0; 4]));
    if (captured.len() as u32).wrapping_sub(8) < name_length {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Moldura própria: a UNICODE_STRING, a célula do objeto e o nome.
    let frame = guest::alloc_bytes(crate::ntos::inc::types::UnicodeString::SIZE + 8 + name_length as u64);
    if frame == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let output = frame + crate::ntos::inc::types::UnicodeString::SIZE;
    let text = output + 8;
    guest::write_bytes(text, &captured[8..8 + name_length as usize]);
    crate::ntos::rtl::guest_strings::write_string_fields(frame, name_length as u16, name_length as u16, text);
    guest::write64(output, 0);
    let status = crate::ntos::ob::object_reference::reference_by_name(frame, 0x40, 0, crate::ntos::ob::object_types::driver_type().pointer, KERNEL_MODE, output).map(|status| status as u32).unwrap_or(STATUS_INSUFFICIENT_RESOURCES);
    let driver = guest::read64(output);
    guest::free_bytes(frame);
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    let object = file_at(file);
    let vpb = object.vpb.get();
    // SAFETY: o VPB de um arquivo aberto, retido pelo arquivo.
    let volume = if vpb != 0 { unsafe { crate::ntos::inc::types::Vpb::at(vpb) }.device_object.get() } else { 0 };
    let found = (volume != 0 && driver_on_stack(volume, driver)) || driver_on_stack(object.device_object.get(), driver);
    let _ = crate::ntos::ob::object_reference::dereference_with_tag(driver, crate::ntos::ob::reference_trace::DEFAULT_TAG, false);
    Ok(found)
}

/// NtQueryVolumeInformationFile de modo usuário num arquivo de driver
/// (ntoskrnl 19041, rva 0x6c9680): a classe e o tamanho mínimo pelas
/// tabelas do I/O Manager, o IO_STATUS_BLOCK e o buffer sondados para
/// escrita (alinhamento da classe), o arquivo referenciado com o acesso que
/// a classe pede. Num FILE_OBJECT aberto direto no dispositivo
/// (FO_DIRECT_DEVICE_OPEN) só a FileFsDeviceInformation vale, as outras
/// dão STATUS_INVALID_DEVICE_REQUEST. O próprio I/O Manager responde a
/// FileFsDeviceInformation (menos num arquivo de redirecionador de rede
/// aberto pelo file system): o DeviceType e o Characteristics do
/// FileObject->DeviceObject, com FILE_DEVICE_IS_MOUNTED quando o VPB dele
/// está montado, e IoStatus {0, 8}; e a FileFsDriverPathInformation. As
/// demais vão ao driver em IRP_MJ_QUERY_VOLUME_INFORMATION (buffered, com o
/// SystemBuffer zerado), pela mesma cauda do NtQueryInformationFile.
pub fn query_volume_information(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> u32 {
    let index = class as usize;
    let minimum = FS_QUERY_MINIMUM.get(index).copied().unwrap_or(0) as u32;
    if minimum == 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if length < minimum {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if !probe(io_status, 4, true) {
        return STATUS_ACCESS_VIOLATION;
    }
    if buffer & (FS_QUERY_ALIGNMENT[index] as u64 - 1) != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if !probe(buffer, length as u64, true) {
        return STATUS_ACCESS_VIOLATION;
    }
    let target = match reference(handle) {
        Ok(target) => target,
        Err(status) => return status,
    };
    let required = FS_QUERY_ACCESS[index];
    if required != 0 && target.access & required != required {
        return conclude(&target, false, None, STATUS_ACCESS_DENIED);
    }
    let file = file_at(target.file);
    let direct = target.flags & FO_DIRECT_DEVICE_OPEN != 0;
    if direct && class != FILE_FS_DEVICE_INFORMATION {
        return conclude(&target, false, None, STATUS_INVALID_DEVICE_REQUEST);
    }
    let device = device_at(file.device_object.get());
    if class == FILE_FS_DEVICE_INFORMATION && (direct || device.device_type.get() != FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        let characteristics = device.characteristics.get() | if mount_flag(device) { FILE_DEVICE_IS_MOUNTED } else { 0 };
        let written = guest::try_write::<u32>(buffer, device.device_type.get()).and_then(|()| guest::try_write::<u32>(buffer + 4, characteristics));
        let status = if written.is_err() || write_user_iosb(io_status, STATUS_SUCCESS, 8).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS };
        return conclude(&target, false, None, status);
    }
    let synchronous = target.synchronous();
    if synchronous && information::acquire_file(target.file).is_err() {
        return conclude(&target, false, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    if class == FILE_FS_DRIVER_PATH_INFORMATION {
        let status = match guest::try_read_bytes(buffer, length as usize) {
            Err(_) => STATUS_ACCESS_VIOLATION,
            Ok(captured) => match driver_path_information(target.file, &captured) {
                Err(status) => status,
                Ok(found) => {
                    if guest::try_write::<u8>(buffer, found as u8).is_err() || write_user_iosb(io_status, STATUS_SUCCESS, 0xC).is_err() {
                        STATUS_ACCESS_VIOLATION
                    } else {
                        STATUS_SUCCESS
                    }
                }
            },
        };
        return conclude(&target, synchronous, None, status);
    }
    let local = if synchronous { 0 } else { allocate_local() };
    let system = guest::alloc_bytes(length as u64);
    if system == 0 || (!synchronous && local == 0) {
        for block in [system, local] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(system, &alloc::vec![0u8; length as usize]);
    dispatcher::clear_event(file.event.address());
    let flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION | IRP_DEFER_IO_COMPLETION | if local != 0 { IRP_SYNCHRONOUS_API } else { 0 };
    let (user_event, user_iosb) = if local != 0 { (local, local_iosb(local).address()) } else { (0, io_status) };
    let packet = allocate(&target, BuildOptions { major: IRP_MJ_QUERY_VOLUME_INFORMATION, buffer: system, user_event, user_iosb, user_buffer: buffer, ..BuildOptions::default() }, flags);
    if packet == 0 {
        let _ = pool_allocation::free(system, 0);
        if local != 0 {
            guest::free_bytes(local);
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    let parameters = &top_location(packet).parameters.query_volume;
    parameters.length.set(length);
    parameters.fs_information_class.set(crate::ntos::inc::types::Fsinfoclass(class as i32));
    track(packet, &target, None, local, 0);
    information_tail(&target, packet, local, io_status)
}

/// NtSetInformationFile de modo usuário num arquivo de driver.
pub fn set_information(handle: u64, io_status: u64, buffer: u64, length: u32, class: u32) -> u32 {
    let index = class as usize;
    let minimum = SET_MINIMUM.get(index).copied().unwrap_or(0) as u32;
    if minimum == 0 {
        return STATUS_INVALID_INFO_CLASS;
    }
    if length < minimum {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if !probe(io_status, IoStatusBlock::SIZE, true) {
        return STATUS_ACCESS_VIOLATION;
    }
    if buffer & (query::ALIGNMENT[index] as u64 - 1) != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    if !probe(buffer, length as u64, false) {
        return STATUS_ACCESS_VIOLATION;
    }
    let target = match reference(handle) {
        Ok(target) => target,
        Err(status) => return status,
    };
    let required = SET_ACCESS[index];
    if required == 0xFFFF_FFFF {
        return conclude(&target, false, None, STATUS_INVALID_INFO_CLASS);
    }
    if required != 0 && target.access & required != required {
        return conclude(&target, false, None, STATUS_ACCESS_DENIED);
    }
    let input = match guest::try_read_bytes(buffer, length as usize) {
        Ok(input) => input,
        Err(_) => return conclude(&target, false, None, STATUS_ACCESS_VIOLATION),
    };
    let file = file_at(target.file);
    // A posição de um arquivo síncrono e o modo são do I/O Manager.
    if class == FILE_POSITION_INFORMATION && target.synchronous() {
        let position = i64::from_le_bytes(input[..8].try_into().unwrap_or([0; 8]));
        if position < 0 {
            return conclude(&target, false, None, STATUS_INVALID_PARAMETER);
        }
        file.current_byte_offset.quad_part.set(position);
        let status = if write_user_iosb(io_status, STATUS_SUCCESS, 0).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS };
        return conclude(&target, false, None, status);
    }
    // A porta de conclusão do arquivo e os modos de notificação também são
    // do I/O Manager (`io/completion/file_port.rs`).
    if class == FILE_COMPLETION_INFORMATION || class == FILE_IO_COMPLETION_NOTIFICATION_INFORMATION {
        let word = |at: usize| u64::from_le_bytes(input[at..at + 8].try_into().unwrap_or([0; 8]));
        let status = if class == FILE_COMPLETION_INFORMATION { file_port::associate(target.file, word(0), word(8)) } else { file_port::set_notification_modes(target.file, u32::from_le_bytes(input[..4].try_into().unwrap_or([0; 4]))) };
        let status = if status == STATUS_SUCCESS && write_user_iosb(io_status, STATUS_SUCCESS, 0).is_err() { STATUS_ACCESS_VIOLATION } else { status };
        return conclude(&target, false, None, status);
    }
    if class == FILE_MODE_INFORMATION {
        let mode = u32::from_le_bytes(input[..4].try_into().unwrap_or([0; 4]));
        // Só os bits de modo mutáveis; a sincronia não muda num arquivo
        // assíncrono e vice-versa.
        if mode & !0x3E != 0 || ((mode & 0x30 != 0) != target.synchronous()) || mode & 0x30 == 0x30 {
            return conclude(&target, false, None, STATUS_INVALID_PARAMETER);
        }
        let mut flags = file.flags.get() & !(FO_WRITE_THROUGH | FO_SEQUENTIAL_ONLY | FO_ALERTABLE_IO);
        if mode & 0x2 != 0 {
            flags |= FO_WRITE_THROUGH;
        }
        if mode & 0x4 != 0 {
            flags |= FO_SEQUENTIAL_ONLY;
        }
        if mode & 0x10 != 0 {
            flags |= FO_ALERTABLE_IO;
        }
        file.flags.set(flags);
        let status = if write_user_iosb(io_status, STATUS_SUCCESS, 0).is_err() { STATUS_ACCESS_VIOLATION } else { STATUS_SUCCESS };
        return conclude(&target, false, None, status);
    }
    let synchronous = target.synchronous();
    if synchronous && information::acquire_file(target.file).is_err() {
        return conclude(&target, false, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    let local = if synchronous { 0 } else { allocate_local() };
    let system = guest::alloc_bytes(length as u64);
    if system == 0 || (!synchronous && local == 0) {
        for block in [system, local] {
            if block != 0 {
                guest::free_bytes(block);
            }
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(system, &input);
    dispatcher::clear_event(file.event.address());
    let flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_DEFER_IO_COMPLETION | if local != 0 { IRP_SYNCHRONOUS_API } else { 0 };
    let (user_event, user_iosb) = if local != 0 { (local, local_iosb(local).address()) } else { (0, io_status) };
    let packet = allocate(&target, BuildOptions { major: IRP_MJ_SET_INFORMATION, buffer: system, user_event, user_iosb, ..BuildOptions::default() }, flags);
    if packet == 0 {
        let _ = pool_allocation::free(system, 0);
        if local != 0 {
            guest::free_bytes(local);
        }
        return conclude(&target, synchronous, None, STATUS_INSUFFICIENT_RESOURCES);
    }
    let parameters = &top_location(packet).parameters.set_file;
    parameters.length.set(length);
    parameters.file_information_class.set(crate::ntos::inc::types::FileInformationClass(class as i32));
    parameters.file_object.set(0);
    track(packet, &target, None, local, 0);
    information_tail(&target, packet, local, io_status)
}
