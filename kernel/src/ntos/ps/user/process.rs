//! Execução de processos de usuário.
//!
//! O processo NT real nasce em `ps::create::create_user_process` (o caminho
//! único de criação: EPROCESS com raiz própria, a seção de imagem da fonte
//! exata, PEB, parâmetros, TEB e o CONTEXT inicial); aqui ele roda: o
//! LdrInitializeThunk da ntdll em anel 3 inicializa heap, imports e TLS
//! antes do entry. [`start_created`] põe a thread principal no despachante
//! de todos os processos (o processo anda com os outros, sem ninguém
//! esperá-lo) e [`wait_started`] espera o fim dele, despachando todos
//! enquanto isso. Inclui o post-mortem (candidatos de retorno na pilha da
//! saída, Ldr e pilha da falha), que o fim do processo chama.
//!
//! O NtCreateUserProcess também mora aqui, como adaptador fino: os onze
//! argumentos vão para `ps::create_context::create`, que captura o pedido da
//! memória do chamador, cria pelo mesmo caminho único, põe o processo no
//! despachante e devolve os handles na tabela de quem chamou.
//!
//! Todo processo que roda aqui acaba em `ps::process::terminate_process`
//! (pelo `ps::create::exit_process`, pedido de onde for), inclusive nas
//! falhas, e o término libera tudo o que ele possui
//! (`files::release_user_resources` e `process_state::destroy`): não há
//! reinício global entre um processo e o próximo. Criar
//! (`create_user_process`) e executar ([`run_created`]) são passos
//! separados, então vários processos podem existir criados ao mesmo tempo.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::memory::Space;
use super::state;
use super::threads;
use crate::hal::{bundle, kmalloc};
use crate::hal::amd64::usermode;
use crate::ntos::cm::service::database::{self as service_database, CommandLine, ServiceError, ServiceResult};
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::mm::{paging, pfn};
use crate::ntos::ps::create::{self, CreateFailure, CreateProcessRequest, CreatedProcess, ImageOrigin};
use crate::ntos::ps::create_context::{self, UserCreateRequest};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Eprocess, LdrDataTableEntry, ListEntry, NtStruct, Peb, PebLdrData};

/// Opções de `run_windows_process`.
#[derive(Default)]
pub struct RunOptions<'a> {
    /// Sem console pai: DETACHED_PROCESS (padrão dos serviços e ferramentas).
    pub attached: bool,
    pub standard_output: u64,
    pub on_process_created: Option<&'a dyn Fn(u64) -> Result<(), KernelError>>,
}

/// O pedido de criação de `run_windows_process`: os parâmetros padrão da
/// imagem `dos_path`, com o console e a saída padrão das opções.
pub fn windows_process_request<'a>(image: ImageOrigin, image_name: &'a str, dos_path: &str, options: &RunOptions<'a>) -> CreateProcessRequest<'a> {
    let mut parameters = ProcessParameters::for_image(dos_path);
    if options.attached {
        parameters.console_handle = 0;
    }
    parameters.standard_output = options.standard_output;
    parameters.standard_error = options.standard_output;
    CreateProcessRequest { image, image_name, parameters, parent: None, thread_flags: 0, inherit_handles_from: None, on_created: options.on_process_created, protection: 0, create_session: false }
}

/// Um processo posto no despachante por [`start_created`]: anda com os
/// outros até acabar, esperado ou não. O EPROCESS fica retido até
/// [`wait_started`] (ou o descarte, que não interrompe o processo).
pub struct StartedProcess {
    pub process_pointer: u64,
    pub process_id: u64,
    image_name: String,
    capturing: bool,
    /// Ainda retém o EPROCESS.
    retained: bool,
}

impl Drop for StartedProcess {
    fn drop(&mut self) {
        if core::mem::take(&mut self.retained) {
            let _ = process::dereference(self.process_pointer);
        }
    }
}

/// Põe um processo criado para rodar, sem esperar: a thread principal entra
/// no despachante de todos os processos pelo LdrInitializeThunk da ntdll em
/// anel 3 (heap, imports e TLS antes do entry). Daí em diante o fim do
/// processo, pedido de onde for, passa por `ps::create::exit_process`.
pub fn start_created(mut created: CreatedProcess) -> Result<StartedProcess, KernelError> {
    created.begin_run();
    let process_pointer = created.process_pointer;
    // A captura de chamada arma o breakpoint no export pedido da ntdll.
    let capturing = state::with(|state| !state.capture_export.is_empty());
    if capturing {
        super::call_capture::reset();
        if let Some(exports) = state::with(|state| state.ntdll_exports.clone()) {
            super::call_capture::arm("ntdll.dll", &exports);
        }
    }
    crate::debug_print!("[usermode] {}: LdrInitializeThunk em {:#x} (exe entry {:#x}, teb {:#x})", created.image_name, created.initialize, created.entry_point, created.teb);
    // A partida roda como a thread do processo: o CONTEXT inicial e o PID
    // são dele.
    let previous = process::get_current_thread();
    process::set_current_thread(created.thread_pointer);
    let started = threads::start(&created.thread, created.initialize, created.stack_top, created.context, created.ntdll_base);
    process::set_current_thread(previous);
    if let Err(error) = started {
        create::exit_process(process_pointer, create::failure_status(&error));
        if capturing {
            super::call_capture::finish();
        }
        return Err(error);
    }
    process::reference(process_pointer);
    Ok(StartedProcess { process_pointer, process_id: created.process_id, image_name: created.image_name.clone(), capturing, retained: true })
}

/// Espera o fim de um processo posto para rodar, despachando enquanto isso
/// as threads de todos os processos. O fim (`ps::create::exit_process`) já
/// fez o post-mortem e o término; aqui sai o que restou (o KTHREAD que era o
/// corrente quando a última thread saiu dentro do intervalo). Devolve o
/// código de saída.
pub fn wait_started(started: StartedProcess) -> Result<u32, KernelError> {
    let process_pointer = started.process_pointer;
    let result = threads::wait_for_process(process_pointer);
    if started.capturing {
        super::call_capture::finish();
    }
    let exit_code = match result {
        Ok(exit_code) => exit_code,
        Err(error) => {
            create::exit_process(process_pointer, create::failure_status(&error));
            return Err(error);
        }
    };
    threads::release_process(process_pointer);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", started.image_name, exit_code);
    let (heap_total, heap_used) = kmalloc::info();
    crate::debug_print!("[mm] process exit: PFN used={}/{}, kernel heap={}/{}", pfn::total_count() - pfn::free_count(), pfn::total_count(), heap_used, heap_total);
    Ok(exit_code)
}

/// Executa um processo criado até o fim ([`start_created`] e
/// [`wait_started`]). Devolve o código de saída.
pub fn run_created(created: CreatedProcess) -> Result<u32, KernelError> {
    wait_started(start_created(created)?)
}

/// Cria (`ps::create::create_user_process`) e executa ([`run_created`]) um
/// processo de usuário; devolve o código de saída. Um processo que chegou a
/// existir e falhou na criação devolve o status da falha como código.
pub fn run_windows_process(bytes: Option<Vec<u8>>, image_name: &str, dos_path: &str, reader: Option<Arc<VolumeFile>>, options: RunOptions<'_>) -> Result<u32, KernelError> {
    let image = match (reader, bytes) {
        (Some(file), _) => ImageOrigin::Volume(file),
        (None, Some(bytes)) => ImageOrigin::Bytes(bytes),
        (None, None) => return Err(KernelError::new("processo sem imagem")),
    };
    match create::create_user_process(&windows_process_request(image, image_name, dos_path, &options)) {
        Ok(created) => run_created(created),
        Err(CreateFailure::Terminated(status)) => Ok(status),
        Err(CreateFailure::ExeFormat(error) | CreateFailure::Other(error)) => Err(error),
        Err(failure @ CreateFailure::FileOpen(_)) => Err(KernelError::with_status(format!("{failure}"), failure.status())),
    }
}

/// NtCreateUserProcess(ProcessHandle*, ThreadHandle*, ProcessDesiredAccess,
/// ThreadDesiredAccess, ProcessObjectAttributes, ThreadObjectAttributes,
/// ProcessFlags, ThreadFlags, ProcessParameters, CreateInfo, AttributeList):
/// os sete argumentos da pilha e o corpo de `ps::create_context`.
fn nt_create_user_process(process_handle: u64, thread_handle: u64, process_access: u64, thread_access: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_syscall_stack(rsp, 7 * 8) {
        return Ok(0xC000_0005);
    }
    let request = UserCreateRequest {
        process_handle,
        thread_handle,
        process_access: process_access as u32,
        thread_access: thread_access as u32,
        process_attributes: state::stack_arg(rsp, 5),
        thread_attributes: state::stack_arg(rsp, 6),
        process_flags: state::stack_arg32(rsp, 7),
        thread_flags: state::stack_arg32(rsp, 8),
        parameters: state::stack_arg(rsp, 9),
        create_info: state::stack_arg(rsp, 10),
        attribute_list: state::stack_arg(rsp, 11),
    };
    create_context::create(&request)
}

pub fn init() {
    state::register_handler("NtCreateUserProcess", nt_create_user_process);
}

/// Candidatos de retorno na pilha da saída (não é um unwind), a falha
/// publicada pela HAL e o Ldr real do processo, que é o corrente (anexado).
pub(crate) fn post_mortem(process_pointer: u64) {
    // A pilha da thread que encerrou o processo.
    let termination = threads::of_process(process_pointer).iter().map(|thread| thread.with(|thread| thread.termination_rsp)).find(|&rsp| rsp != 0).unwrap_or(0);
    let images: Vec<(u64, u64, String)> = Space::of(process_pointer).images().iter().map(|image| (image.base(), image.size(), image.name().unwrap_or_default())).collect();
    if termination != 0 {
        let mut matches = 0;
        let mut offset = 0u64;
        while offset < 0x1000 && matches < 32 {
            let at = termination + offset;
            if !state::probe_user_read(at, 8) {
                break;
            }
            let Ok(address) = guest::try_read::<u64>(at) else { break };
            if let Some((base, _, name)) = images.iter().find(|(base, size, _)| address >= *base && address < base + size) {
                crate::debug_print!("[exit-stack] +{:#x}: {}+{:#x}", offset, name.rsplit('\\').next().unwrap_or(name), address - base);
                matches += 1;
            }
            offset += 8;
        }
    }
    let block = usermode::block();
    let fault_rsp = block.fault_rsp.get();
    let fault_cr2 = block.fault_cr2.get();
    if block.fault_vector.get() == 0x29 {
        crate::debug_print!("[usermode] FAST_FAIL codigo={} rip={:#x}", block.fault_rcx.get() as u32, block.fault_rip.get().wrapping_sub(2));
    }
    if fault_cr2 != 0 {
        crate::debug_print!("[usermode] CR2={:#x} -> pagina traduz p/ {:#x}", fault_cr2, paging::translate(fault_cr2 & !0xFFF));
    }
    // O Ldr real do processo (pela PEB do EPROCESS), em memória de usuário:
    // cada passo é sondado.
    // SAFETY: o EPROCESS do processo, ainda antes do término.
    let peb = unsafe { Eprocess::at(process_pointer) }.peb.get();
    let ldr = if state::probe_user_read(peb, Peb::SIZE) { state::user_struct::<Peb>(peb).and_then(|peb| peb.ldr.probe_get()).unwrap_or(0) } else { 0 };
    if ldr != 0 && state::probe_user_read(ldr, PebLdrData::SIZE) {
        let lists = [("InLoad", offset_of!(PebLdrData, in_load_order_module_list), offset_of!(LdrDataTableEntry, in_load_order_links)), ("InMem", offset_of!(PebLdrData, in_memory_order_module_list), offset_of!(LdrDataTableEntry, in_memory_order_links)), ("InInit", offset_of!(PebLdrData, in_initialization_order_module_list), offset_of!(LdrDataTableEntry, in_initialization_order_links))];
        for (tag, list, links) in lists {
            let head = ldr + list as u64;
            let mut link = state::user_struct::<ListEntry>(head).and_then(|head| head.flink.probe_get()).unwrap_or(0);
            let mut modules = String::new();
            let mut count = 0;
            while count < 14 && link != 0 && link != head && state::probe_user_read(link - links as u64, LdrDataTableEntry::SIZE) {
                let Ok(entry) = state::user_struct::<LdrDataTableEntry>(link - links as u64) else { break };
                let Ok((base, length, buffer)) = (|| Ok::<_, KernelError>((entry.dll_base.probe_get()?, entry.base_dll_name.length.probe_get()? as u64, entry.base_dll_name.buffer.probe_get()?)))() else { break };
                let name = if state::probe_user_read(buffer, length) { state::read_user_wide_string(buffer, (length / 2).min(40)) } else { String::new() };
                modules.push_str(&format!(" [{name}@{base:#x}]"));
                let Ok(next) = state::user_struct::<ListEntry>(link).and_then(|link| link.flink.probe_get()) else { break };
                link = next;
                count += 1;
            }
            crate::debug_print!("[usermode] Ldr {}:{}", tag, modules);
        }
    }
    if fault_rsp != 0 && state::probe_user_read(fault_rsp, 8) {
        let mut dump = String::new();
        for index in 0..34u64 {
            let at = fault_rsp + index * 8;
            let value = if state::probe_user_read(at, 8) { guest::try_read::<u64>(at).unwrap_or(0) } else { 0 };
            dump.push_str(&format!(" +{:x}={value:#x}", index * 8));
        }
        crate::debug_print!("[usermode] pilha da falha @{:#x}:{}", fault_rsp, dump);
    }
}

/// hello.exe em anel 3 pela kernel32 real.
pub fn run_hello() {
    let Some(bytes) = bundle::read("apps/hello.exe") else {
        crate::debug_print!("[usermode] hello.exe ausente no bundle");
        return;
    };
    match run_windows_process(Some(bytes.to_vec()), "hello.exe", "C:\\hello.exe", None, RunOptions::default()) {
        Ok(0) => crate::debug_print!("USERMODE_HELLO_OK"),
        Ok(code) => crate::debug_print!("USERMODE_HELLO_FALHOU codigo={:#x}", code),
        Err(error) => crate::debug_print!("USERMODE_HELLO_FALHOU erro={}", error),
    }
}

/// Inicia um serviço instalado pelo mesmo loader nativo. O SCM só recebe
/// RUNNING quando o processo o relata; o retorno é a saída do processo.
pub fn run_service(service_name: &str, diagnostic_image_name: Option<&str>) -> ServiceResult<u32> {
    service_database::launch(
        service_name,
        |path| volume_files::lookup_volume_file(path).map(|file| {
            let directory = file.directory();
            (file, directory)
        }),
        |image: Arc<VolumeFile>, command: &CommandLine, attach: &dyn Fn(u64) -> ServiceResult<()>| {
            if !command.arguments.is_empty() {
                return Err(ServiceError::Win32(50, String::from("Argumentos de processo de servico ainda nao suportados")));
            }
            let image_name = diagnostic_image_name.map_or_else(|| String::from(command.path.replace('\\', "/").rsplit('/').next().unwrap_or("")), String::from);
            let attach_error = core::cell::RefCell::new(None::<ServiceError>);
            let on_created = |process_id: u64| -> Result<(), KernelError> {
                attach(process_id).map_err(|error| {
                    *attach_error.borrow_mut() = Some(error);
                    KernelError::new("SCM attach failed")
                })
            };
            let result = run_windows_process(None, &image_name, &command.path, Some(image), RunOptions { on_process_created: Some(&on_created), ..RunOptions::default() });
            if let Some(error) = attach_error.borrow_mut().take() {
                return Err(error);
            }
            result.map_err(|error| ServiceError::Win32(if error.status != 0 { error.status } else { 1067 }, alloc::format!("{error}")))
        },
    )
}
