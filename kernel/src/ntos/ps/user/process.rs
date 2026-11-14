//! Execução de processos de usuário.
//!
//! O processo NT real nasce em `ps::create::create_user_process` (o caminho
//! único de criação: EPROCESS com raiz própria, a seção de imagem da fonte
//! exata, PEB, parâmetros, TEB e o CONTEXT inicial); aqui ele roda: o
//! LdrInitializeThunk da ntdll em anel 3 inicializa heap, imports e TLS
//! antes do entry, e o despachante executa as threads dele até o fim. Inclui
//! o post-mortem (candidatos de retorno na pilha da saída, Ldr e pilha da
//! falha).
//!
//! Todo processo que roda aqui acaba em `ps::process::terminate_process`,
//! inclusive nas falhas, e o término libera tudo o que ele possui
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
use crate::ntos::ps::process;
use crate::ntos::ps::process_context;
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
    CreateProcessRequest { image, image_name, parameters, on_created: options.on_process_created }
}

/// Executa um processo criado até o fim: o LdrInitializeThunk da ntdll em
/// anel 3 (heap, imports e TLS antes do entry), o despachante das threads
/// dele e o término. Devolve o código de saída.
pub fn run_created(mut created: CreatedProcess) -> Result<u32, KernelError> {
    created.begin_run();
    let process_pointer = created.process_pointer;
    let previous = process::get_current_thread();
    let fail = |error: KernelError| -> KernelError {
        create::end_process(process_pointer, create::failure_status(&error), previous);
        error
    };
    // Daqui em diante a thread do processo é a corrente: as notificações de
    // saída rodam no contexto dele.
    process::set_current_thread(created.thread_pointer);
    // A captura de chamada arma o breakpoint no export pedido da ntdll.
    let capturing = state::with(|state| !state.capture_export.is_empty());
    if capturing {
        super::call_capture::reset();
        if let Some(exports) = state::with(|state| state.ntdll_exports.clone()) {
            super::call_capture::arm("ntdll.dll", &exports);
        }
    }
    crate::debug_print!("[usermode] {}: LdrInitializeThunk em {:#x} (exe entry {:#x}, teb {:#x})", created.image_name, created.initialize, created.entry_point, created.teb);
    let result = threads::run(&created.thread, created.initialize, created.stack_top, created.context, created.ntdll_base);
    if capturing {
        super::call_capture::finish();
    }
    let exit_code = result.map_err(fail)?;
    // O post-mortem lê a pilha, as imagens e o Ldr antes de o término
    // devolver o VAD, anexado ao processo: o laço devolveu a thread de quem
    // o chamou.
    if exit_code != 0x42 && exit_code != 0 {
        let _ = process_context::with_process(process_pointer, || post_mortem(process_pointer));
    }
    create::end_process(process_pointer, exit_code, previous);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", created.image_name, exit_code);
    let (heap_total, heap_used) = kmalloc::info();
    crate::debug_print!("[mm] process exit: PFN used={}/{}, kernel heap={}/{}", pfn::total_count() - pfn::free_count(), pfn::total_count(), heap_used, heap_total);
    Ok(exit_code)
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

/// Candidatos de retorno na pilha da saída (não é um unwind), a falha
/// publicada pela HAL e o Ldr real do processo, que é o corrente (anexado).
fn post_mortem(process_pointer: u64) {
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
