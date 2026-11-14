//! Posse da conclusão nos serviços de arquivo.
//!
//! Drivers concluem IRPs reais; a saída paginável do chamador só é finalizada
//! na thread/contexto que pediu. A requisição guarda arquivo, thread, evento,
//! APC de conclusão, MDL/pinagem e o buffer de sistema até o fim. Os eventos
//! de handles de usuário entram com o estado de modo usuário (fase 7).

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::io::{cancel, io_manager};
use crate::ntos::ke::{apc, context_switch, dispatcher, irql, thread_alert};
use crate::ntos::mm::io_pins::{self, Pin};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{Ethread, FileObject, IoStatusBlock, Kthread, Mdl, NtStruct};

/// MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA.
const MDL_PAGES_LOCKED_AND_MAPPED: i16 = 0x0002 | 0x0001;

/// FILE_OBJECT vivo do pedido (referenciado até o fim).
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o pedido retém o FILE_OBJECT.
    unsafe { FileObject::at(file) }
}

const TAG: u32 = 0x7443_6F49;
/// Requisição sem método de transferência (leitura/escrita).
pub const NO_METHOD: u32 = u32::MAX;

/// Evento referenciado durante a requisição.
pub struct EventReference {
    pub pointer: u64,
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl EventReference {
    fn release(&mut self) {
        if let Some(release) = self.release.take() {
            release();
        }
    }
}

/// Uma requisição de leitura/escrita/controle.
pub struct Request {
    pub file: u64,
    pub thread: u64,
    pub process: Option<u64>,
    pub mode: u8,
    pub io_status: u64,
    pub output: u64,
    pub output_length: u32,
    pub apc_routine: u64,
    pub apc_context: u64,
    pub synchronous: bool,
    pub system: u64,
    pub mdl: u64,
    pub pin: Option<Pin>,
    pub apc: u64,
    pub irp: u64,
    pub event: Option<EventReference>,
    pub done: bool,
    pub finished: bool,
    pub retained: bool,
    pub status: u32,
    pub information: u64,
    /// Método de transferência (0 = buffered; `NO_METHOD` nas leituras e
    /// escritas, que não têm IOCTL) e cópia de saída explícita.
    pub method: u32,
    pub copy_output: bool,
    pub on_complete: Option<Box<dyn FnMut(u32, u64) + Send>>,
    pub skip_event: bool,
    pub skip_file_event: bool,
    pub skip_apc: bool,
    pub rundown: bool,
}

pub type Shared = Arc<SpinLock<Request>>;

static REQUESTS: SpinLock<Vec<Shared>> = SpinLock::new(Vec::new());
static FREE_ROUTINE: AtomicU64 = AtomicU64::new(0);

#[allow(clippy::too_many_arguments)]
pub fn new(file: u64, thread: u64, process: Option<u64>, mode: u8, io_status: u64, output: u64, output_length: u32, apc_routine: u64, apc_context: u64, synchronous: bool) -> Shared {
    Arc::new(SpinLock::new(Request {
        file,
        thread,
        process,
        mode,
        io_status,
        output,
        output_length,
        apc_routine,
        apc_context,
        synchronous,
        system: 0,
        mdl: 0,
        pin: None,
        apc: 0,
        irp: 0,
        event: None,
        done: false,
        finished: false,
        retained: false,
        status: 0x103,
        information: 0,
        method: NO_METHOD,
        copy_output: false,
        on_complete: None,
        skip_event: false,
        skip_file_event: false,
        skip_apc: false,
        rundown: false,
    }))
}

/// A requisição passa a pertencer à lista de pendentes.
pub fn track(request: &Shared) {
    REQUESTS.lock().push(request.clone());
}

pub fn is_tracked(request: &Shared) -> bool {
    REQUESTS.lock().iter().any(|tracked| Arc::ptr_eq(tracked, request))
}

/// Rotina nativa de kernel/rundown da APC de conclusão: devolve o KAPC ao
/// pool (ExFreePoolWithTag(apc, 0)).
pub fn free_routine() -> Result<u64, KernelError> {
    let current = FREE_ROUTINE.load(Ordering::Acquire);
    if current != 0 {
        return Ok(current);
    }
    let code = guest::alloc_bytes(32);
    if code == 0 {
        return Ok(0);
    }
    let free = crate::ntos::init::exports::export_module()?.exports.exports.get("ExFreePoolWithTag").copied().ok_or_else(|| KernelError::new("ExFreePoolWithTag unavailable"))?;
    let mut bytes = alloc::vec![0x48, 0x83, 0xEC, 0x28, 0x31, 0xD2, 0x48, 0xB8];
    bytes.extend_from_slice(&free.to_le_bytes());
    bytes.extend_from_slice(&[0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3]);
    guest::write_bytes(code, &bytes);
    match FREE_ROUTINE.compare_exchange(0, code, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(code),
        Err(existing) => {
            guest::free_bytes(code);
            Ok(existing)
        }
    }
}

/// Evento de um handle de kernel; em modo usuário exige EVENT_MODIFY_STATE.
pub fn event_reference(handle: u64, mode: u8) -> Result<EventReference, u32> {
    let value = handle & !3;
    let kernel = value & 0xFFFF_FFFF_8000_0000 == 0xFFFF_FFFF_8000_0000;
    if !kernel && value > 0x7FFF_FFFF {
        return Err(0xC000_0008);
    }
    let Some(record) = object_manager::handle_record((value & 0x7FFF_FFFC) as u32) else { return Err(0xC000_0008) };
    let kernel_handle = record.options.kernel_handle;
    if kernel != kernel_handle || (mode != 0 && kernel_handle) || (!kernel_handle && record.options.owner_process != Some(process::get_current_process())) {
        return Err(0xC000_0008);
    }
    let node = object_manager::node(record.node).ok_or(0xC000_0008u32)?;
    if node.type_name != "Event" {
        return Err(0xC000_0024);
    }
    if mode != 0 && record.access & 2 == 0 {
        return Err(0xC000_0022);
    }
    let pointer = node.data.as_ref().map_or(0, |data| data.native_pointer);
    if pointer == 0 {
        return Err(0xC000_0024);
    }
    let id = record.node;
    object_manager::update_node(id, |node| node.refs += 1);
    Ok(EventReference { pointer, release: Some(Box::new(move || {
        object_manager::update_node(id, |node| node.refs = node.refs.saturating_sub(1));
    })) })
}

/// Libera IRP, pinagem, MDL, buffer de sistema, APC, evento e retenções.
pub fn cleanup(request: &Shared) -> Result<(), KernelError> {
    let (file, thread, retained) = {
        let mut r = request.lock();
        if r.irp != 0 {
            io_manager::forget_managed_completion(r.irp);
            guest::free_bytes(r.irp);
            r.irp = 0;
        }
        if let Some(mut pin) = r.pin.take() {
            pin.release()?;
        }
        if r.mdl != 0 {
            guest::free_bytes(r.mdl);
            r.mdl = 0;
        }
        if r.system != 0 {
            let _ = kernel_pool::free(r.system, None);
            r.system = 0;
        }
        if r.apc != 0 {
            let _ = kernel_pool::free(r.apc, None);
            r.apc = 0;
        }
        if let Some(mut event) = r.event.take() {
            event.release();
        }
        let retained = r.retained;
        r.retained = false;
        (r.file, r.thread, retained)
    };
    if retained {
        if file != 0 {
            file_objects::dereference(file)?;
        }
        process::dereference_thread(thread)?;
    }
    REQUESTS.lock().retain(|tracked| !Arc::ptr_eq(tracked, request));
    Ok(())
}

/// Finaliza na thread e no processo do pedido, abaixo de DISPATCH_LEVEL:
/// copia a saída buffered, grava IOSB/FinalStatus, sinaliza o evento (ou o
/// do arquivo) e entrega a APC de conclusão.
pub fn finish(request: &Shared) -> Result<(), KernelError> {
    let mut r = request.lock();
    if r.finished || !r.done {
        return Ok(());
    }
    if process::get_current_thread() != r.thread || irql::get_irql() > 1 {
        return Ok(());
    }
    if r.process.is_some_and(|owner| owner != process::get_current_process()) {
        return Ok(());
    }
    let status = r.status;
    let count = r.information;
    if count > r.output_length as u64 {
        return Err(KernelError::new("driver completed I/O with an invalid output length"));
    }
    if (r.copy_output || r.method == 0) && r.system != 0 && count != 0 && status >> 30 != 3 {
        // O buffer de saída é do solicitante (de modo usuário num pedido de
        // modo usuário): cópia sondada, uma falha não derruba a conclusão.
        let _ = guest::try_write_bytes(r.output, &guest::read_bytes(r.system, count as usize));
    }
    if let Some(on_complete) = r.on_complete.as_mut() {
        on_complete(status, count);
    }
    // IoStatusBlock do solicitante (sondado na entrada; escrita sondada como
    // a do IopCompleteRequest, que ignora a exceção).
    let _ = guest::try_write::<i32>(r.io_status + core::mem::offset_of!(IoStatusBlock, status) as u64, status as i32);
    let _ = guest::try_write::<u64>(r.io_status + core::mem::offset_of!(IoStatusBlock, information) as u64, count);
    if r.file != 0 {
        file_at(r.file).final_status.set(status as i32);
    }
    if let Some(event) = &r.event {
        if !r.skip_event {
            dispatcher::set_event(event.pointer);
        }
    } else if r.file != 0 && !r.skip_file_event {
        dispatcher::set_event(file_at(r.file).event.address());
    }
    if r.apc != 0 && !r.rundown && !r.skip_apc && apc::insert(r.apc, r.io_status, 0) {
        r.apc = 0;
    }
    r.finished = true;
    drop(r);
    cleanup(request)
}

/// Bomba de conclusões em PASSIVE_LEVEL com APCs especiais habilitadas.
pub fn pump() {
    // SAFETY: a thread corrente.
    if irql::get_irql() != 0 || unsafe { Kthread::at(process::get_current_thread()) }.special_apc_disable.get() != 0 {
        return;
    }
    let pending: Vec<Shared> = REQUESTS.lock().clone();
    for request in pending {
        if let Err(error) = finish(&request) {
            debug_print!("[file-request] {}", error);
        }
    }
}

/// FO_ALERTABLE_IO: o arquivo foi aberto para E/S síncrona alertável.
pub const FO_ALERTABLE_IO: u32 = 0x04;

/// A ETHREAD `thread` foi terminada (CrossThreadFlags.Terminated).
fn terminated(thread: u64) -> bool {
    // SAFETY: a thread dona da requisição, retida por ela.
    thread != 0 && unsafe { Ethread::at(thread) }.terminated() != 0
}

/// A espera de uma requisição síncrona pendente, como a do evento do
/// FILE_OBJECT no IopSynchronousServiceTail: a thread `thread` (a corrente)
/// espera a conclusão — dentro de uma syscall ela bloqueia e sai da fila de
/// prontas até o despachante ver a requisição concluída
/// (`context_switch::wait_until`); fora dela gira o `pump_kernel`, com as
/// interrupções de dispositivo. Com `alertable` (FO_ALERTABLE_IO) a espera
/// é alertável no modo `mode`: um alerta ou uma APC de usuário a interrompe.
/// Interrompida (alerta, APC de usuário ou término da thread), a requisição é
/// cancelada e a espera continua, não alertável, até a conclusão (o
/// IopCancelAlertedRequest e o IoCancelThreadIo do NT).
pub fn wait_finished(request: &Shared, thread: u64, alertable: bool, mode: u8) {
    let finished = || request.lock().finished;
    let mut poll = || {
        pump();
        if finished() {
            Some(0)
        } else {
            terminated(thread).then_some(context_switch::STATUS_THREAD_IS_TERMINATING)
        }
    };
    if alertable {
        thread_alert::cooperate(thread, mode, true, &mut poll, dispatcher::pump_kernel);
    } else {
        context_switch::wait_until(&mut poll, dispatcher::pump_kernel);
    }
    if finished() {
        return;
    }
    let irp = request.lock().irp;
    if irp != 0 {
        let _ = cancel::irp(irp);
    }
    while !finished() {
        context_switch::wait_until(
            &mut || {
                pump();
                finished().then_some(0)
            },
            dispatcher::pump_kernel,
        );
    }
}

/// MDL das páginas fixadas do buffer de saída (METHOD_*_DIRECT).
pub fn fill_mdl(request: &Shared, write: bool) -> Result<bool, KernelError> {
    let mut r = request.lock();
    let pin = io_pins::pin(r.output, r.output_length as u64, write)?;
    // O vetor de PFNs (PFN_NUMBER) segue o cabeçalho do MDL.
    let size = Mdl::SIZE + pin.pages.len() as u64 * 8;
    let descriptor = guest::alloc_bytes(size);
    if descriptor == 0 {
        r.pin = Some(pin);
        return Ok(false);
    }
    // SAFETY: alocação zerada do MDL com o vetor de PFNs.
    let (header, pfns) = unsafe { (Mdl::at(descriptor), Field::<u64>::array_at(descriptor + Mdl::SIZE, pin.pages.len())) };
    header.size.set(size as i16);
    header.mdl_flags.set(MDL_PAGES_LOCKED_AND_MAPPED);
    header.start_va.set(r.output & !4095);
    header.byte_offset.set((r.output & 4095) as u32);
    header.byte_count.set(r.output_length);
    header.mapped_system_va.set(r.output);
    for (pfn, page) in pfns.iter().zip(pin.pages.iter()) {
        pfn.set(page.frame / 4096);
    }
    r.mdl = descriptor;
    r.pin = Some(pin);
    Ok(true)
}

/// Retém arquivo e thread, referencia o evento (limpo) e prepara a APC.
pub fn prepare(request: &Shared, event: u64) -> Result<u32, KernelError> {
    let (file, thread, mode, apc_routine, apc_context) = {
        let r = request.lock();
        (r.file, r.thread, r.mode, r.apc_routine, r.apc_context)
    };
    if file != 0 && file_objects::reference(file)?.is_none() {
        return Ok(0xC000_0008);
    }
    process::reference_thread(thread);
    request.lock().retained = true;
    if event != 0 {
        let reference = match event_reference(event, mode) {
            Ok(reference) => reference,
            Err(status) => return Ok(status),
        };
        dispatcher::clear_event(reference.pointer);
        request.lock().event = Some(reference);
    }
    if apc_routine != 0 {
        let routine = free_routine()?;
        if routine == 0 {
            return Ok(0xC000_009A);
        }
        let Ok(packet) = kernel_pool::allocate(0x58, AllocateOptions { paged: false, tag: TAG, ..Default::default() }) else { return Ok(0xC000_009A) };
        if packet == 0 {
            return Ok(0xC000_009A);
        }
        apc::initialize(packet, thread, 0, routine, routine, apc_routine, mode, apc_context);
        request.lock().apc = packet;
    }
    Ok(0)
}

/// Saída de thread com I/O pendente: cancela e espera a conclusão.
pub fn rundown(thread: u64) {
    let owned: Vec<Shared> = REQUESTS.lock().iter().filter(|request| request.lock().thread == thread).cloned().collect();
    if owned.is_empty() {
        return;
    }
    if irql::get_irql() != 0 {
        panic!("thread exited with pending I/O above PASSIVE_LEVEL");
    }
    for request in &owned {
        request.lock().rundown = true;
    }
    for request in &owned {
        let (done, irp) = {
            let r = request.lock();
            (r.done, r.irp)
        };
        if !done && irp != 0 {
            let _ = cancel::irp(irp);
        }
    }
    // Espera as conclusões (o IoCancelThreadIo): bloqueia numa syscall,
    // gira o pump fora dela.
    context_switch::wait_until(
        &mut || {
            for request in &owned {
                let _ = finish(request);
            }
            owned.iter().all(|request| request.lock().finished).then_some(0)
        },
        dispatcher::pump_kernel,
    );
}

pub fn init() {
    dispatcher::register_completion_pump(pump);
    process::register_thread_exit_routine(rundown);
}
