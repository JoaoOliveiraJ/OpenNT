//! Posse da conclusão nos serviços de arquivo.
//!
//! Drivers concluem IRPs reais; a saída paginável do chamador só é finalizada
//! na thread/contexto que pediu. A requisição guarda arquivo, thread, evento,
//! APC de conclusão, MDL/pinagem e o buffer de sistema até o fim. Os eventos
//! de handles de usuário entram com o estado de modo usuário (fase 7).

use alloc::boxed::Box;
use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::io::{cancel, io_manager};
use crate::ntos::ke::{apc, context_switch, dispatcher, irql, thread_alert, wait};
use crate::ntos::mm::io_pins::{self, Pin};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ob::object_manager;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, Ethread, FileObject, IoStatusBlock, Kthread, Mdl, NtStruct};
use core::sync::atomic::{AtomicBool, Ordering};

/// MDL_PAGES_LOCKED.
const MDL_PAGES_LOCKED: i16 = 0x0002;

/// FILE_OBJECT vivo do pedido (referenciado até o fim).
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: o pedido retém o FILE_OBJECT.
    unsafe { FileObject::at(file) }
}

const TAG: u32 = 0x7443_6F49;
/// FILE_DEVICE_KEYBOARD: o dispositivo de classe do kbdclass
/// (`\Device\KeyboardClassN`).
const FILE_DEVICE_KEYBOARD: u32 = 0x0B;
/// O `KEYBOARD_INPUT_OK` já saiu.
static KEYBOARD_INPUT_REPORTED: AtomicBool = AtomicBool::new(false);

/// Diagnóstico da entrada: a primeira leitura do teclado concluída com dados
/// para um leitor de modo kernel com rotina de APC, o ZwReadFile do
/// RIMStartDeviceRead do RIT do win32k (a ApcRoutine é o rimInputApc), sai
/// na serial com o `KEYBOARD_INPUT_OK`. É a conclusão do IRP_MJ_READ real do
/// kbdclass, no contexto de quem leu (o csrss da sessão). O serviço de
/// teclado do boot do shell lê sem APC e não conta.
fn report_first_keyboard_input(r: &Request, status: u32, count: u64) {
    if r.mode != 0 || r.apc_routine == 0 || status != 0 || count == 0 || r.file == 0 || KEYBOARD_INPUT_REPORTED.load(Ordering::Relaxed) {
        return;
    }
    // O RIT abre a interface de dispositivo, que aponta para o PDO; o
    // IRP_MJ_READ vai ao topo da pilha (IoGetAttachedDevice), o kbdclass.
    let device = file_at(r.file).device_object.get();
    let top = if device != 0 { crate::ntos::ob::objects::device::top(device) } else { 0 };
    // SAFETY: o FILE_OBJECT do pedido retém o dispositivo e a pilha dele.
    if top == 0 || unsafe { DeviceObject::at(top) }.device_type.get() != FILE_DEVICE_KEYBOARD || KEYBOARD_INPUT_REPORTED.swap(true, Ordering::AcqRel) {
        return;
    }
    debug_print!("[kbd] primeira leitura do teclado concluida para o leitor de kernel: pid {} tid {}, {} bytes\nKEYBOARD_INPUT_OK", process::get_current_process_id(), process::get_current_thread_id(), count);
}

/// Requisição sem método de transferência (leitura/escrita).
pub const NO_METHOD: u32 = u32::MAX;

/// Evento referenciado durante a requisição.
pub struct EventReference {
    pub pointer: u64,
    release: Option<Box<dyn FnOnce() + Send>>,
}

impl EventReference {
    pub fn release(&mut self) {
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

/// A rotina de kernel e de rundown das APCs de conclusão (o IopDeallocateApc
/// do NT): devolve o KAPC ao pool, ExFreePoolWithTag(Apc, 0). É uma função da
/// imagem do kernel, chamada pela ABI MS x64 como as rotinas dos drivers; os
/// outros argumentos da rotina de kernel não são usados.
extern "win64" fn deallocate_apc(apc: u64) {
    if let Err(error) = crate::ntos::ex::pool_allocation::free(apc, 0) {
        panic!("[file-request] KAPC de conclusao {apc:#x} nao voltou ao pool: {error}");
    }
}

/// O endereço de [`deallocate_apc`], a rotina de kernel/rundown das APCs de
/// conclusão.
pub fn free_routine() -> Result<u64, KernelError> {
    Ok(deallocate_apc as extern "win64" fn(u64) as usize as u64)
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
        // O mapeamento de sistema do MDL sai antes de as páginas soltarem
        // (o MmUnlockPages do IopCompleteRequest).
        if r.mdl != 0 {
            crate::ntos::mm::mdl::unmap_locked_pages(r.mdl);
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
    if process::get_current_thread() != r.thread || irql::get_irql() > 1 || r.process.is_some_and(|owner| owner != process::get_current_process()) {
        // A conclusão é da thread que pediu (o IopCompleteRequest é uma APC
        // especial de kernel dela): uma thread de kernel parada numa espera
        // sai dela para concluir no próprio contexto.
        let thread = r.thread;
        drop(r);
        AWAITING.lock().insert(thread);
        wait::apc_queued(thread, false, true, 0);
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
    report_first_keyboard_input(&r, status, count);
    if r.apc != 0 && !r.rundown && !r.skip_apc && apc::insert(r.apc, r.io_status, 0) {
        r.apc = 0;
    }
    r.finished = true;
    drop(r);
    cleanup(request)
}

/// As threads com conclusão pendente que só elas podem terminar.
static AWAITING: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

/// `thread` tem uma conclusão de E/S esperando o contexto dela.
pub fn has_completions_for(thread: u64) -> bool {
    AWAITING.lock().contains(&thread)
}

/// Bomba de conclusões em PASSIVE_LEVEL com APCs especiais habilitadas.
pub fn pump() {
    // SAFETY: a thread corrente.
    if irql::get_irql() != 0 || unsafe { Kthread::at(process::get_current_thread()) }.special_apc_disable.get() != 0 {
        return;
    }
    AWAITING.lock().remove(&process::get_current_thread());
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

/// MDL das páginas fixadas do buffer de saída (METHOD_*_DIRECT), como o
/// IoAllocateMdl com o MmProbeAndLockPages do NT: MDL_PAGES_LOCKED, o
/// Process dono e os PFNs, sem VA de sistema. O driver pede a VA pelo
/// MmGetSystemAddressForMdlSafe, que mapeia as páginas no espaço de sistema
/// (a VA de usuário só vale no processo que fez o pedido).
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
    header.mdl_flags.set(MDL_PAGES_LOCKED);
    header.process.set(if r.output < crate::ntos::mm::memory_map::USER_ADDRESS_LIMIT { process::get_current_process() } else { 0 });
    header.start_va.set(r.output & !4095);
    header.byte_offset.set((r.output & 4095) as u32);
    header.byte_count.set(r.output_length);
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
