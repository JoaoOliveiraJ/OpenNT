//! Process Manager com o modelo do NT.
//!
//! Conferido por disassembly do ntoskrnl.exe real (Win10 22H2):
//!
//! ```text
//! IoGetCurrentProcess:  mov rax, gs:[0x188]  ; Prcb.CurrentThread (KTHREAD)
//!                       mov rax, [rax+0xB8]  ; KTHREAD.ApcState.Process
//! PsGetProcessId:       mov rax, [rcx+0x440] ; EPROCESS.UniqueProcessId
//! ```
//!
//! Cada processo tem um EPROCESS real e cada thread um KTHREAD real com
//! ApcState.Process e Cid. O "registrador de thread corrente" (gs:[0x188])
//! é mantido pelo escalonador e espelhado na PCR. PsActiveProcessHead é uma
//! LIST_ENTRY circular real.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::{push_lock, rundown};
use crate::ntos::ke::{clock, critical_region, pcr};
use crate::ntos::mm::{kernel_data, memory_map};
use crate::ntos::ob::object_manager::{self, ObjectData, ObjectHooks};
use crate::ntos::ob::{object_access, object_types};
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::token::{thread as thread_tokens, tokens};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, Ethread, Kthread, LargeInteger, ListEntry};
use crate::ntos::ps::silo::query::INHERIT as INHERIT_PROCESS_SILO;

use crate::ntos::ps::notify::{process as process_notify, thread as thread_notify};
use crate::ntos::ps::user::process_state;

pub const SYSTEM_PROCESS_ID: u64 = 4;
/// Política inicial de memória, distinta da prioridade de CPU.
const NORMAL_THREAD_PAGE_PRIORITY: u32 = 5;
const STATUS_INVALID_CID: u32 = 0xC000_000B;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
/// KOBJECTS: ProcessObject e ThreadObject (DISPATCHER_HEADER.Type).
const PROCESS_OBJECT: u8 = 3;
const THREAD_OBJECT: u8 = 6;
/// KTHREAD.State: Initialized e Terminated.
const THREAD_INITIALIZED: u8 = 0;
const THREAD_TERMINATED: u8 = 4;

/// Imagem executável de um processo (`ps/process_image`, fase 6).
#[derive(Clone, Debug)]
pub struct ProcessImage {
    pub id: u64,
    pub section_native_pointer: u64,
    pub file: u64,
    pub cache: u64,
}

/// Descrição do executável entregue pelo loader de modo usuário.
pub struct Executable {
    /// Os mesmos bytes que o loader PE consumiu.
    pub source: alloc::sync::Arc<dyn crate::ntos::ob::objects::file::FileSource>,
    pub image_size: u64,
    pub image_information: Option<alloc::vec::Vec<u8>>,
    pub command_line: Option<String>,
}

/// Provedor de imagens de processo (instalado pelo loader PE).
pub struct ImageProvider {
    pub create: fn(&Executable) -> Result<ProcessImage, KernelError>,
    pub release_section: fn(&ProcessImage),
    pub destroy: fn(&ProcessImage),
}

/// Desmontagens de subsistemas ainda instalados depois do Process Manager,
/// na ordem de `terminate_process`.
#[derive(Clone, Copy, Default)]
pub struct TeardownHooks {
    /// `mm::section::views::release_process`.
    pub release_section_views: Option<fn(u64)>,
}

pub struct ProcessRecord {
    pub name: String,
    pub parent_id: u64,
    pub create_time: u64,
    pub peak_threads: u32,
    pub user_time: u64,
    pub kernel_time: u64,
    pub references: u32,
    pub terminated: bool,
    pub exiting: bool,
    pub image: Option<ProcessImage>,
    pub notify_started: bool,
    pub notified: bool,
    pub command_line: Option<String>,
    pub security: SecurityPolicy,
    /// Limites de quota de pool (não paginável, paginável); `None` = SIZE_T_MAX.
    pub pool_quota_limits: Option<[u64; 2]>,
}

#[derive(Clone)]
pub struct ThreadRecord {
    pub pointer: u64,
    pub process: u64,
    pub id: u64,
    pub create_time: u64,
    pub start: u64,
    pub user_time: u64,
    pub kernel_time: u64,
    pub context_switches: u32,
    pub references: u32,
    pub owner_released: bool,
    pub creation_notified: bool,
    pub exit_notified: bool,
    pub exiting: bool,
    pub deleting: bool,
    pub list_linked: bool,
    pub security: SecurityPolicy,
    /// Pid do contexto do escalonador que executa a thread.
    pub runtime: Option<u32>,
    /// O contexto terminou (done/killed).
    pub runtime_dead: bool,
}

struct State {
    active_head: u64,
    primary_tokens: BTreeMap<u64, u64>,
    processes: BTreeMap<u64, ProcessRecord>,
    threads: BTreeMap<u64, ThreadRecord>,
    thread_exit_routines: Vec<fn(u64)>,
    process_exit_routines: Vec<fn(u64)>,
    image_provider: Option<&'static ImageProvider>,
    hooks: TeardownHooks,
}

static STATE: SpinLock<State> = SpinLock::new(State {
    active_head: 0,
    primary_tokens: BTreeMap::new(),
    processes: BTreeMap::new(),
    threads: BTreeMap::new(),
    thread_exit_routines: Vec::new(),
    process_exit_routines: Vec::new(),
    image_provider: None,
    hooks: TeardownHooks { release_section_views: None },
});

static SYSTEM_PROCESS: AtomicU64 = AtomicU64::new(0);
/// A célula PsJobType, publicada no primeiro acesso.
static JOB_TYPE: AtomicU64 = AtomicU64::new(0);
/// O "gs:[0x188]" do kernel.
static CURRENT_THREAD: AtomicU64 = AtomicU64::new(0);

fn timestamp() -> u64 {
    clock::now_ms() * 10_000 + 116_444_736_000_000_000
}

/// A ordem de criação dos processos (o PspProcessSequenceNumber do NT).
static NEXT_SEQUENCE_NUMBER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
/// PROCESS_PRIORITY_CLASS_NORMAL.
const PROCESS_PRIORITY_CLASS_NORMAL: u8 = 2;

/// LARGE_INTEGER de tempo numa única escrita de 64 bits.
fn write_time(time: &LargeInteger, value: u64) {
    time.quad_part.set(value as i64);
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS criado por este módulo (ou retido pelo chamador).
    unsafe { Eprocess::at(process) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREAD criado por este módulo (ou retido pelo chamador).
    unsafe { Ethread::at(thread) }
}

/// Elo de uma das listas circulares mantidas aqui (PsActiveProcessHead,
/// ThreadListHead e seus elementos).
fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: os elos dessas listas apontam sempre para LIST_ENTRYs vivas.
    unsafe { ListEntry::at(address) }
}

pub fn set_image_provider(provider: &'static ImageProvider) {
    STATE.lock().image_provider = Some(provider);
}

pub fn set_teardown_hooks(hooks: TeardownHooks) {
    STATE.lock().hooks = hooks;
}

fn insert_into_active_list(process: &Eprocess) {
    let head = list_entry(STATE.lock().active_head);
    let links = &process.active_process_links;
    let last = head.blink.get();
    links.flink.set(head.address());
    links.blink.set(last);
    list_entry(last).flink.set(links.address());
    head.blink.set(links.address());
}

fn remove_from_active_list(process: &Eprocess) {
    let links = &process.active_process_links;
    let next = links.flink.get();
    let previous = links.blink.get();
    list_entry(previous).flink.set(next);
    list_entry(next).blink.set(previous);
}

/// A lista nativa de ETHREADs da enumeração privada de processos. Threads
/// encerradas mas referenciadas continuam ligadas até a destruição final.
fn with_thread_list_lock<T>(process: u64, action: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if get_current_thread() == 0 {
        return action(); // bootstrap de thread única
    }
    let lock = eprocess(process).process_lock.value.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let result = action();
        push_lock::release_exclusive(lock, 0)?;
        result
    })
}

fn link_thread(thread: u64, process: u64) -> Result<(), KernelError> {
    with_thread_list_lock(process, || {
        let head = &eprocess(process).thread_list_head;
        let entry = &ethread(thread).thread_list_entry;
        let last = head.blink.get();
        entry.flink.set(head.address());
        entry.blink.set(last);
        list_entry(last).flink.set(entry.address());
        head.blink.set(entry.address());
        if let Some(record) = STATE.lock().threads.get_mut(&thread) {
            record.list_linked = true;
        }
        Ok(())
    })
}

fn unlink_thread(thread: u64) -> Result<(), KernelError> {
    let Some((process, linked)) = STATE.lock().threads.get(&thread).map(|record| (record.process, record.list_linked)) else {
        return Ok(());
    };
    if !linked {
        return Ok(());
    }
    with_thread_list_lock(process, || {
        let entry = &ethread(thread).thread_list_entry;
        let entry_address = entry.address();
        let next = entry.flink.get();
        let previous = entry.blink.get();
        if list_entry(next).blink.get() != entry_address || list_entry(previous).flink.get() != entry_address {
            return Err(KernelError::new("corrupt process thread list"));
        }
        list_entry(previous).flink.set(next);
        list_entry(next).blink.set(previous);
        entry.flink.set(entry_address);
        entry.blink.set(entry_address);
        if let Some(record) = STATE.lock().threads.get_mut(&thread) {
            record.list_linked = false;
        }
        Ok(())
    })
}

/// EPROCESS completo para o kernel 19041 correspondente.
pub fn create_process(process_id: u64, image_name: &str, image_base: u64, executable: Option<&Executable>) -> Result<u64, KernelError> {
    let process_type = object_types::process_type();
    let process = guest::alloc_bytes(Eprocess::SIZE);
    if process == 0 {
        return Err(KernelError::new("EPROCESS allocation failed"));
    }
    let provider = STATE.lock().image_provider;
    let parent_token = get_primary_token(get_current_process());
    let primary_token = match tokens::create(parent_token, None) {
        Ok(token) => token,
        Err(error) => {
            guest::free_bytes(process);
            return Err(error);
        }
    };
    let image = match executable {
        Some(executable) => {
            let created = match provider {
                Some(provider) => (provider.create)(executable),
                None => Err(KernelError::new("no process image provider")),
            };
            match created {
                Ok(image) => Some(image),
                Err(error) => {
                    let _ = tokens::release(primary_token);
                    guest::free_bytes(process);
                    return Err(error);
                }
            }
        }
        None => None,
    };
    let security = object_access::capture(Some(primary_token));
    // O estado por processo nasce com a ObjectTable, antes da lista ativa.
    let tables = process_state::create(process, process_id).and_then(|_| {
        process_handles::create(process, process_id).inspect_err(|_| {
            process_state::destroy(process);
        })
    });
    if let Err(error) = tables {
        if let (Some(image), Some(provider)) = (&image, provider) {
            (provider.destroy)(image);
        }
        let _ = tokens::release(primary_token);
        guest::free_bytes(process);
        return Err(error);
    }
    let parent_id = if process_id == SYSTEM_PROCESS_ID { 0 } else { get_current_process_id() };
    let create_time = timestamp();
    let (section, file, cache) = image.as_ref().map_or((0, 0, 0), |image| (image.section_native_pointer, image.file, image.cache));
    {
        let mut state = STATE.lock();
        state.processes.insert(
            process,
            ProcessRecord {
                name: String::from(image_name),
                parent_id,
                create_time,
                peak_threads: 0,
                user_time: 0,
                kernel_time: 0,
                references: 0,
                terminated: false,
                exiting: false,
                image,
                notify_started: false,
                notified: false,
                command_line: executable.and_then(|executable| executable.command_line.clone()),
                security,
                pool_quota_limits: None,
            },
        );
        state.primary_tokens.insert(process, primary_token);
    }
    object_types::account(&process_type.name, 1, 0)?;
    let object = eprocess(process);
    // EX_FAST_REF válido sem referências em cache.
    object.token.object.set(primary_token);
    object.section_base_address.set(image_base);
    object.section_object.set(section);
    object.image_file_pointer.set(file);
    object.se_audit_process_creation_info.image_file_name.set(cache);
    object.rundown_protect.count.set(0);
    object.process_lock.value.set(0);
    let thread_head = &object.thread_list_head;
    thread_head.flink.set(thread_head.address());
    thread_head.blink.set(thread_head.address());
    // Nenhuma decisão de assinatura ou proteção rodou na criação.
    object.signature_level.set(0);
    object.section_signature_level.set(0);
    object.protection.level.set(0);
    object.job.set(0);
    object.server_silo.set(0);
    object.debug_port.set(0);
    object.peb.set(0);
    // A conversão Win32 nativa ainda não ocorreu; sem ambiente WOW64.
    object.win32_process.set(0);
    object.wo_w64_process.set(0);
    // O criador (0 para o System), a ordem de criação e a classe normal.
    let creator = get_current_process();
    let inherited = if process_id == SYSTEM_PROCESS_ID || creator == 0 { 0 } else { eprocess(creator).unique_process_id.get() };
    object.inherited_from_unique_process_id.set(inherited);
    object.sequence_number.set(NEXT_SEQUENCE_NUMBER.fetch_add(1, core::sync::atomic::Ordering::Relaxed));
    object.priority_class.set(PROCESS_PRIORITY_CLASS_NORMAL);
    object.win32_window_station.set(0);
    object.security_port.set(0);
    object.dxg_process.set(0);
    object.exit_status.set(0x103); // STATUS_PENDING
    // Sem sessões MM separadas: NULL, que PsGetProcessSessionId mapeia para 0.
    object.session.set(0);
    object.flags3.set(if process_id == SYSTEM_PROCESS_ID { Eprocess::SYSTEM_PROCESS_MASK } else { 0 });
    object.flags.set(0);
    // KPROCESS embutido: tipo (o DWORD do cabeçalho inteiro) + DirectoryTableBase
    // (CR3 real do sistema).
    object.pcb.header.lock.set(PROCESS_OBJECT as i32);
    object.pcb.base_priority.set(8);
    object.pcb.directory_table_base.set(memory_map::PML4_PHYS);
    object.unique_process_id.set(process_id);
    write_time(&object.create_time, create_time);
    object.active_threads.set(1);
    let short_name = image_name.as_bytes();
    for (index, character) in object.image_file_name.iter().enumerate() {
        character.set(short_name.get(index).copied().unwrap_or(0));
    }
    insert_into_active_list(object);
    Ok(process)
}

/// Cria um KTHREAD real ligado ao processo (ApcState.Process + Cid).
pub fn create_kernel_thread(process: u64, thread_id: u64, defer_notify: bool, previous_mode: u8, initial_stack: Option<u64>) -> Result<u64, KernelError> {
    if previous_mode > 1 {
        return Err(KernelError::new("invalid initial thread mode"));
    }
    let thread_type = object_types::thread_type();
    let thread = guest::alloc_bytes(Ethread::SIZE);
    if thread == 0 {
        return Err(KernelError::new("ETHREAD allocation failed"));
    }
    let owner = eprocess(process);
    let process_id = owner.unique_process_id.get();
    let object = ethread(thread);
    let tcb = &object.tcb;
    tcb.header.type_.set(THREAD_OBJECT);
    tcb.initial_stack.set(initial_stack.unwrap_or(memory_map::BOOT_STACK_TOP));
    tcb.thread_lock.set(0);
    // Initialized não entra em fila antes de receber contexto executável.
    tcb.state.set(THREAD_INITIALIZED);
    let base_priority = owner.pcb.base_priority.get();
    tcb.priority.set(base_priority);
    tcb.base_priority.set(base_priority);
    tcb.saturation.set(0);
    tcb.quantum_reset.set(6);
    tcb.cycle_time.set(0);
    tcb.quantum_target.set(0);
    for alerted in &tcb.alerted {
        alerted.set(0);
    }
    tcb.misc_flags.set(if previous_mode == 0 { Kthread::SYSTEM_THREAD_MASK as i32 } else { 0 });
    for head in [&tcb.apc_state.apc_list_head[0], &tcb.apc_state.apc_list_head[1], &object.irp_list] {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    tcb.apc_state.process.set(process);
    tcb.process.set(process);
    tcb.previous_mode.set(previous_mode as i8);
    object.silo.set(INHERIT_PROCESS_SILO);
    object.same_thread_apc_flags.set(0);
    // A atividade não é herdada implicitamente de outra thread.
    object.activity_id.set(0);
    object.cid.unique_process.set(process_id);
    object.cid.unique_thread.set(thread_id);
    object.rundown_protect.count.set(0);
    object.exit_status.set(0x103);
    // Sem TEB nem thread Win32 até o modo usuário ou o win32k os criarem.
    tcb.teb.set(0);
    tcb.win32_thread.set(0);
    write_time(&object.create_time, timestamp());
    let security = object_access::capture(get_primary_token(process));
    STATE.lock().threads.insert(
        thread,
        ThreadRecord {
            pointer: thread,
            process,
            id: thread_id,
            create_time: timestamp(),
            start: 0,
            user_time: 0,
            kernel_time: 0,
            context_switches: 0,
            references: 0,
            owner_released: false,
            creation_notified: false,
            exit_notified: false,
            exiting: false,
            deleting: false,
            list_linked: false,
            security,
            runtime: None,
            runtime_dead: false,
        },
    );
    // ThreadInserted e prioridade de página normal na criação.
    object.cross_thread_flags.set(Ethread::THREAD_INSERTED_MASK | (NORMAL_THREAD_PAGE_PRIORITY << Ethread::THREAD_PAGE_PRIORITY_SHIFT));
    object_types::account(&thread_type.name, 1, 0)?;
    if let Err(error) = link_thread(thread, process) {
        let linked = STATE.lock().threads.get(&thread).is_some_and(|record| record.list_linked);
        if linked {
            release_thread(thread)?;
        } else {
            STATE.lock().threads.remove(&thread);
            object_types::account(&thread_type.name, -1, 0)?;
            guest::free_bytes(thread);
        }
        return Err(error);
    }
    let start_notify = {
        let mut state = STATE.lock();
        let live = state.threads.values().filter(|record| record.process == process && !record.runtime_dead).count() as u32;
        match state.processes.get_mut(&process) {
            Some(record) => {
                record.peak_threads = record.peak_threads.max(live);
                let start = !record.notify_started;
                record.notify_started = true;
                start
            }
            None => false,
        }
    };
    if start_notify {
        let result = notify_process(process, process_id, true);
        match result {
            Ok(status) if status & 0x8000_0000 == 0 => {
                if let Some(record) = STATE.lock().processes.get_mut(&process) {
                    record.notified = true;
                }
            }
            outcome => {
                let (status, error) = match outcome {
                    Ok(status) => (status, KernelError::with_status("process creation rejected", status)),
                    Err(error) => (if error.status != 0 { error.status } else { 0xC000_0001 }, error),
                };
                terminate_process(process, status)?;
                release_thread(thread)?;
                return Err(error);
            }
        }
    }
    if !defer_notify {
        notify_thread_created(thread)?;
    }
    Ok(thread)
}

fn notify_process(process: u64, process_id: u64, created: bool) -> Result<u32, KernelError> {
    let (parent_id, image, command_line) = {
        let state = STATE.lock();
        let Some(record) = state.processes.get(&process) else { return Ok(0) };
        (record.parent_id, record.image.clone(), record.command_line.clone())
    };
    let notify_record = process_notify::NotifyRecord { parent_id, image: image.as_ref(), command_line: command_line.as_deref() };
    process_notify::notify(process, process_id, &notify_record, created)
}

pub fn notify_thread_created(thread: u64) -> Result<(), KernelError> {
    let process = {
        let mut state = STATE.lock();
        let Some(record) = state.threads.get_mut(&thread) else { return Ok(()) };
        if record.creation_notified {
            return Ok(());
        }
        record.creation_notified = true;
        record.process
    };
    thread_notify::notify(eprocess(process).unique_process_id.get(), ethread(thread).cid.unique_thread.get(), true)
}

/// Executa `body` com `thread` como thread corrente, restaurando a anterior.
fn as_current<T>(thread: u64, body: impl FnOnce() -> T) -> T {
    let previous = get_current_thread();
    set_current_thread(thread);
    let result = body();
    set_current_thread(previous);
    result
}

pub fn exit_thread(thread: u64, exit_status: u32) -> Result<(), KernelError> {
    let process = {
        let mut state = STATE.lock();
        let Some(record) = state.threads.get_mut(&thread) else { return Ok(()) };
        if record.exiting {
            return Ok(());
        }
        record.exiting = true;
        record.process
    };
    let object = ethread(thread);
    // PspSetCrossThreadFlag: OR atômico de Terminated.
    object.cross_thread_flags.atomic().fetch_or(Ethread::TERMINATED_MASK, Ordering::SeqCst);
    object.exit_status.set(exit_status as i32);
    // Donos de I/O cancelam/drenam requisições antes da notificação, do
    // rundown de APCs e da liberação dos recursos de execução.
    let routines = STATE.lock().thread_exit_routines.clone();
    if !routines.is_empty() {
        as_current(thread, || {
            for routine in routines {
                routine(thread);
            }
        });
    }
    // O rundown fechado impede consultas novas de relatar uma thread viva.
    rundown::wait(object.rundown_protect.count.address())?;
    // Uma thread Initialized pode terminar antes de entrar num escalonador; a
    // troca é atômica para não pisar numa transição do escalonador.
    let _ = object.tcb.state.atomic().compare_exchange(THREAD_INITIALIZED, THREAD_TERMINATED, Ordering::SeqCst, Ordering::SeqCst);
    {
        let mut state = STATE.lock();
        let Some(record) = state.threads.get_mut(&thread) else { return Ok(()) };
        if !record.creation_notified || record.exit_notified {
            return Ok(());
        }
        record.exit_notified = true;
    }
    as_current(thread, || thread_notify::notify(eprocess(process).unique_process_id.get(), object.cid.unique_thread.get(), false))
}

pub fn terminate_process(process: u64, exit_status: u32) -> Result<(), KernelError> {
    {
        let mut state = STATE.lock();
        let Some(record) = state.processes.get_mut(&process) else { return Ok(()) };
        if record.terminated || record.exiting {
            return Ok(());
        }
        record.exiting = true;
    }
    // Publicado antes dos callbacks de saída; uma saída repetida não troca
    // o primeiro resultado.
    let object = eprocess(process);
    object.exit_status.set(exit_status as i32);
    object.flags.atomic().fetch_or(Eprocess::PROCESS_EXITING_MASK, Ordering::SeqCst);
    let threads: Vec<u64> = STATE.lock().threads.values().filter(|record| record.process == process).map(|record| record.pointer).collect();
    for thread in threads {
        exit_thread(thread, exit_status)?;
    }
    let process_id = object.unique_process_id.get();
    if STATE.lock().processes.get(&process).is_some_and(|record| record.notified) {
        notify_process(process, process_id, false)?;
    }
    let (routines, hooks, provider) = {
        let state = STATE.lock();
        (state.process_exit_routines.clone(), state.hooks, state.image_provider)
    };
    for routine in routines {
        routine(process);
    }
    // Leitores de ObjectTable e da imagem usam este mesmo rundown nativo.
    rundown::wait(object.rundown_protect.count.address())?;
    process_handles::destroy(process)?;
    object_manager::close_process_native_handles(process);
    if let Some(release) = hooks.release_section_views {
        release(process);
    }
    let image = STATE.lock().processes.get(&process).and_then(|record| record.image.clone());
    if let Some(image) = image {
        object.section_object.set(0);
        object.image_file_pointer.set(0);
        if let Some(provider) = provider {
            (provider.release_section)(&image);
        }
    }
    object.active_threads.set(0);
    write_time(&object.exit_time, timestamp());
    remove_from_active_list(object);
    // Fora da lista ativa, o estado por processo some e o VAD volta inteiro
    // (o MmCleanProcessAddressSpace); o EPROCESS pode continuar retido por
    // referências.
    process_state::destroy(process);
    if let Some(record) = STATE.lock().processes.get_mut(&process) {
        record.terminated = true;
    }
    collect_process(process)
}

/// A vida do EPROCESS independe da execução: referência de driver, handle
/// aberto ou ETHREAD existente retêm o corpo e o token.
fn collect_process(process: u64) -> Result<(), KernelError> {
    let (token, record, provider) = {
        let mut state = STATE.lock();
        let Some(record) = state.processes.get(&process) else { return Ok(()) };
        if !record.terminated || record.references != 0 || state.threads.values().any(|thread| thread.process == process) {
            return Ok(());
        }
        let token = state.primary_tokens.remove(&process);
        let record = state.processes.remove(&process).unwrap();
        (token, record, state.image_provider)
    };
    if let Some(token) = token {
        eprocess(process).token.object.set(0);
        tokens::release(token)?;
    }
    if let (Some(image), Some(provider)) = (&record.image, provider) {
        (provider.destroy)(image);
    }
    object_types::account("Process", -1, 0)?;
    guest::free_bytes(process);
    Ok(())
}

pub fn is_process(pointer: u64) -> bool {
    STATE.lock().processes.contains_key(&pointer)
}

/// Consulta um registro de processo.
pub fn with_record<T>(pointer: u64, body: impl FnOnce(&ProcessRecord) -> T) -> Option<T> {
    STATE.lock().processes.get(&pointer).map(body)
}

pub fn reference(pointer: u64) -> Option<u32> {
    let mut state = STATE.lock();
    let record = state.processes.get_mut(&pointer)?;
    record.references += 1;
    Some(record.references)
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut state = STATE.lock();
        let Some(record) = state.processes.get_mut(&pointer) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("process reference underflow"));
        }
        record.references -= 1;
        record.references
    };
    collect_process(pointer)?;
    Ok(Some(count))
}

/// Atualiza um registro de processo vivo.
pub fn update_record<T>(pointer: u64, body: impl FnOnce(&mut ProcessRecord) -> T) -> Option<T> {
    STATE.lock().processes.get_mut(&pointer).map(body)
}

pub fn reference_count(pointer: u64) -> Option<u32> {
    STATE.lock().processes.get(&pointer).map(|record| record.references)
}

/// Ganchos do handle de processo: o handle retém o EPROCESS.
struct ProcessHandle {
    pointer: u64,
}

impl ObjectHooks for ProcessHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        reference(self.pointer);
        object_types::account("Process", 0, 1)
    }

    fn on_handle_close(&self) {
        let _ = object_types::account("Process", 0, -1);
        let _ = dereference(self.pointer);
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Abre um handle de processo; 0 para processo desconhecido ou direitos
/// fora do tipo.
pub fn open_handle(pointer: u64, access: u32) -> Result<u32, KernelError> {
    if !is_process(pointer) || access & !object_types::process_type().valid_access != 0 {
        return Ok(0);
    }
    let data = ObjectData { native_pointer: pointer, access: Some(access), hooks: Some(alloc::sync::Arc::new(ProcessHandle { pointer })), ..ObjectData::default() };
    let node = object_manager::new_node("", "Process", Some(data));
    object_manager::open_object(node, None)
}

pub fn forget_thread(thread: u64) -> Result<(), KernelError> {
    {
        let mut state = STATE.lock();
        let Some(record) = state.threads.get_mut(&thread) else { return Ok(()) };
        if record.references != 0 {
            return Err(KernelError::new("cannot forget a referenced thread"));
        }
        record.deleting = true;
    }
    if let Err(error) = unlink_thread(thread) {
        if let Some(record) = STATE.lock().threads.get_mut(&thread) {
            record.deleting = false;
        }
        return Err(error);
    }
    thread_tokens::release(thread)?;
    let process = STATE.lock().threads.remove(&thread).map(|record| record.process);
    object_types::account("Thread", -1, 0)?;
    if let Some(process) = process {
        collect_process(process)?;
    }
    Ok(())
}

fn collect_thread(thread: u64) -> Result<(), KernelError> {
    let collectable = STATE.lock().threads.get(&thread).is_some_and(|record| record.owner_released && record.references == 0);
    if !collectable {
        return Ok(());
    }
    crate::ntos::ps::property_set::clear(thread);
    forget_thread(thread)?;
    guest::free_bytes(thread);
    Ok(())
}

pub fn release_thread(thread: u64) -> Result<(), KernelError> {
    if !STATE.lock().threads.contains_key(&thread) {
        return Err(KernelError::new("unknown released thread"));
    }
    exit_thread(thread, 0)?;
    if let Some(record) = STATE.lock().threads.get_mut(&thread) {
        record.owner_released = true;
    }
    collect_thread(thread)
}

pub fn reference_thread(thread: u64) -> Option<u32> {
    let mut state = STATE.lock();
    let record = state.threads.get_mut(&thread)?;
    record.references += 1;
    Some(record.references)
}

pub fn reference_thread_safe(thread: u64) -> bool {
    let mut state = STATE.lock();
    let Some(record) = state.threads.get_mut(&thread) else { return false };
    if record.deleting || (record.owner_released && record.references == 0) {
        return false;
    }
    record.references += 1;
    true
}

/// PsLookupThreadByThreadId: ids de 32 bits alinhados, fora do slot zero.
pub fn reference_thread_by_id(id: u64) -> u64 {
    let id = id & !3;
    if id >= 0x1_0000_0000 || id & 0x3FC == 0 {
        return 0;
    }
    let mut state = STATE.lock();
    for record in state.threads.values_mut() {
        if record.id == id {
            if ethread(record.pointer).tcb.header.type_.get() & 0x7F != THREAD_OBJECT {
                return 0;
            }
            record.references += 1;
            return record.pointer;
        }
    }
    0
}

pub fn dereference_thread(thread: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut state = STATE.lock();
        let Some(record) = state.threads.get_mut(&thread) else { return Ok(None) };
        if record.references == 0 {
            return Err(KernelError::new("thread reference underflow"));
        }
        record.references -= 1;
        record.references
    };
    collect_thread(thread)?;
    Ok(Some(count))
}

pub fn thread_reference_count(thread: u64) -> Option<u32> {
    STATE.lock().threads.get(&thread).map(|record| record.references)
}

pub fn is_thread(pointer: u64) -> bool {
    STATE.lock().threads.contains_key(&pointer)
}

pub fn thread_record(pointer: u64) -> Option<ThreadRecord> {
    STATE.lock().threads.get(&pointer).cloned()
}

pub fn account_thread_handle(delta: i64) -> Result<(), KernelError> {
    object_types::account("Thread", 0, delta)
}

/// Tempo de CPU em unidades de 100 ns (`mode`: kernel ou usuário).
pub fn account_thread(thread: u64, kernel: bool, elapsed_100ns: u64) {
    let mut state = STATE.lock();
    let Some(record) = state.threads.get_mut(&thread) else { return };
    let process = record.process;
    if kernel {
        record.kernel_time += elapsed_100ns;
    } else {
        record.user_time += elapsed_100ns;
    }
    if let Some(process) = state.processes.get_mut(&process) {
        if kernel {
            process.kernel_time += elapsed_100ns;
        } else {
            process.user_time += elapsed_100ns;
        }
    }
}

pub fn dispatch_thread(thread: u64) {
    if let Some(record) = STATE.lock().threads.get_mut(&thread) {
        record.context_switches += 1;
    }
}

pub fn thread_kernel_time(thread: u64) -> u64 {
    STATE.lock().threads.get(&thread).map_or(0, |record| record.kernel_time)
}

/// Rotina inicial publicada da thread.
pub fn set_thread_start(thread: u64, start: u64) {
    if let Some(record) = STATE.lock().threads.get_mut(&thread) {
        record.start = start;
    }
}

/// Liga a thread ao contexto do escalonador.
pub fn describe_thread(thread: u64, runtime: Option<u32>, dead: bool) {
    if let Some(record) = STATE.lock().threads.get_mut(&thread) {
        record.runtime = runtime;
        record.runtime_dead = dead;
    }
}

pub fn register_thread_exit_routine(routine: fn(u64)) {
    let mut state = STATE.lock();
    if !state.thread_exit_routines.iter().any(|&existing| existing as usize == routine as usize) {
        state.thread_exit_routines.push(routine);
    }
}

pub fn register_process_exit_routine(routine: fn(u64)) {
    let mut state = STATE.lock();
    if !state.process_exit_routines.iter().any(|&existing| existing as usize == routine as usize) {
        state.process_exit_routines.push(routine);
    }
}

pub fn unregister_process_exit_routine(routine: fn(u64)) {
    STATE.lock().process_exit_routines.retain(|&existing| existing as usize != routine as usize);
}

pub fn get_primary_token(process: u64) -> Option<u64> {
    STATE.lock().primary_tokens.get(&process).copied()
}

pub fn image_section(process: u64) -> Option<u64> {
    STATE.lock().processes.get(&process).and_then(|record| record.image.as_ref().map(|image| image.section_native_pointer))
}

/// EPROCESS.ActiveThreads real.
pub fn add_thread(process: u64) {
    eprocess(process).active_threads.atomic().fetch_add(1, Ordering::SeqCst);
}

/// Decremento atômico que nunca passa de zero.
pub fn remove_thread(process: u64) {
    let _ = eprocess(process).active_threads.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |active| active.checked_sub(1));
}

/// A troca de thread corrente atualiza a PCR (gs:0x188 =
/// Prcb.CurrentThread), lida direto por drivers nativos.
pub fn set_current_thread(thread: u64) {
    CURRENT_THREAD.store(thread, Ordering::Relaxed);
    pcr::set_current_thread(thread);
}

pub fn get_current_thread() -> u64 {
    CURRENT_THREAD.load(Ordering::Relaxed)
}

/// IoGetCurrentProcess/PsGetCurrentProcess: o mesmo algoritmo do NT.
pub fn get_current_process() -> u64 {
    let thread = get_current_thread();
    if thread == 0 {
        return SYSTEM_PROCESS.load(Ordering::Relaxed);
    }
    ethread(thread).tcb.apc_state.process.get()
}

pub fn get_current_process_id() -> u64 {
    let thread = get_current_thread();
    if thread == 0 {
        return SYSTEM_PROCESS_ID;
    }
    ethread(thread).cid.unique_process.get()
}

/// "Handle de processo" dos serviços Zw: -1/0 = corrente (CID da thread);
/// senão o pid.
pub fn process_id_from_handle(handle: u64) -> u64 {
    let value = handle as u32 as i32;
    if value == -1 || value == 0 {
        let thread = get_current_thread();
        if thread == 0 {
            return 4;
        }
        return ethread(thread).cid.unique_process.get();
    }
    value as u32 as u64
}

pub fn get_current_thread_id() -> u64 {
    let thread = get_current_thread();
    if thread == 0 {
        return 0;
    }
    ethread(thread).cid.unique_thread.get()
}

/// Entrada de `list_active_processes`.
#[derive(Clone, Debug)]
pub struct ActiveProcess {
    pub pid: u64,
    pub name: String,
    pub address: u64,
    pub threads: Vec<u64>,
}

/// Caminha PsActiveProcessHead (como o `!process` do WinDbg).
pub fn list_active_processes() -> Vec<ActiveProcess> {
    let head = STATE.lock().active_head;
    let mut result = Vec::new();
    if head == 0 {
        return result;
    }
    let mut cursor = list_entry(head).flink.get();
    while cursor != 0 && cursor != head {
        // CONTAINING_RECORD(cursor, EPROCESS, ActiveProcessLinks).
        let process = cursor - core::mem::offset_of!(Eprocess, active_process_links) as u64;
        let object = eprocess(process);
        let mut name = String::new();
        for character in &object.image_file_name {
            let character = character.get();
            if character == 0 {
                break;
            }
            name.push(character as char);
        }
        let threads = STATE.lock().threads.values().filter(|record| record.process == process && !record.runtime_dead).map(|record| record.pointer).collect();
        result.push(ActiveProcess { pid: object.unique_process_id.get(), name, address: process, threads });
        cursor = list_entry(cursor).flink.get();
    }
    result
}

/// PsLookupProcessByProcessId: anda a lista de processos ativos procurando
/// o PID; achado, referencia o EPROCESS e o entrega ao chamador.
pub fn lookup_process_by_id(pid: u64, output: u64) -> u32 {
    let Some(found) = list_active_processes().into_iter().find(|entry| entry.pid == pid) else {
        return STATUS_INVALID_CID;
    };
    reference(found.address);
    // SAFETY: PEPROCESS* de saída do chamador de kernel.
    unsafe { Field::<u64>::at(output) }.set(found.address);
    0
}

pub fn get_system_process() -> u64 {
    SYSTEM_PROCESS.load(Ordering::Relaxed)
}

/// O dump referencia a mesma lista circular da enumeração de processos.
pub fn get_active_process_head() -> u64 {
    STATE.lock().active_head
}

/// PsAcquireProcessExitSynchronization: a RundownProtect do EPROCESS, que
/// o término do processo espera esvaziar; com o processo já saindo,
/// STATUS_PROCESS_IS_TERMINATING.
pub fn acquire_exit_synchronization(process: u64) -> Result<u32, KernelError> {
    if rundown::acquire(eprocess(process).rundown_protect.count.address())? {
        Ok(0)
    } else {
        Ok(STATUS_PROCESS_IS_TERMINATING)
    }
}

/// PsReleaseProcessExitSynchronization: ExReleaseRundownProtection em
/// EPROCESS+0x458; devolve a referência retida por
/// PsAcquireProcessExitSynchronization (ela pertence ao chamador).
pub fn release_exit_synchronization(process: u64) -> Result<(), KernelError> {
    rundown::release(eprocess(process).rundown_protect.count.address())
}

/// Célula exportada PsInitialSystemProcess.
pub fn initial_system_process_cell() -> u64 {
    kernel_data::address("PsInitialSystemProcess").unwrap_or(0)
}

/// Célula exportada PsProcessType.
pub fn process_type_cell() -> u64 {
    kernel_data::address("PsProcessType").unwrap_or(0)
}

/// Célula exportada PsThreadType.
pub fn thread_type_cell() -> u64 {
    kernel_data::address("PsThreadType").unwrap_or(0)
}

/// Célula exportada PsJobType, publicada no primeiro acesso: o corpo do
/// tipo Job e a célula que aponta para ele têm alocações distintas.
pub fn job_type_cell() -> u64 {
    let current = JOB_TYPE.load(Ordering::Acquire);
    if current != 0 {
        return current;
    }
    let body = guest::alloc_bytes(0x40);
    let cell = guest::alloc_bytes(8);
    // SAFETY: a célula de 8 bytes acabou de ser alocada.
    unsafe { Field::<u64>::at(cell) }.set(body);
    match JOB_TYPE.compare_exchange(0, cell, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => cell,
        Err(existing) => {
            guest::free_bytes(cell);
            guest::free_bytes(body);
            existing
        }
    }
}

pub fn init() -> Result<(), KernelError> {
    let head = guest::alloc_bytes(16);
    if head == 0 {
        return Err(KernelError::new("PsActiveProcessHead allocation failed"));
    }
    let entry = list_entry(head);
    entry.flink.set(head);
    entry.blink.set(head);
    STATE.lock().active_head = head;
    let system = create_process(SYSTEM_PROCESS_ID, "System", 0, None)?;
    SYSTEM_PROCESS.store(system, Ordering::Relaxed);
    Ok(())
}
