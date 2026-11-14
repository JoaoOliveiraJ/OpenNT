//! Montagem e execução de processos de usuário.
//!
//! O processo NT real (EPROCESS/KTHREAD de `ps/process`, com a seção de
//! imagem da fonte exata) e o LdrInitializeThunk da ntdll em anel 3: a ntdll
//! inicializa heap, imports e TLS antes do entry. Inclui o post-mortem
//! (candidatos de retorno na pilha da saída, Ldr e pilha da falha).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::loader::{self, BytesSource, ImageRegion, Module};
use super::state::{self, RegionKind};
use super::structures::{self, ProcessDescription};
use super::{files, memory, threads};
use crate::hal::{bundle, kmalloc};
use crate::hal::amd64::usermode;
use crate::ntos::cm::service::database::{self as service_database, CommandLine, ServiceError, ServiceResult};
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::mm::{paging, pfn};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::process::{self, Executable};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Context, LdrDataTableEntry, ListEntry, NtStruct, Peb, PebLdrData};
use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::ntos::mm::pe_loader::{self, LoadOptions, PeImage};

/// Arquivo do volume como fonte da imagem principal.
struct VolumeSource {
    name: String,
    file: Arc<VolumeFile>,
}

impl FileSource for VolumeSource {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.file.size()
    }
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, KernelError> {
        self.file.read_at(offset, length as u64)
    }
}

/// O mesmo arquivo como fonte de streaming do carregador de PE.
struct VolumeImage {
    name: String,
    file: Arc<VolumeFile>,
}

impl ImageSource for VolumeImage {
    fn name(&self) -> &str {
        &self.name
    }
    fn size(&self) -> u64 {
        self.file.size()
    }
    fn read_bytes(&self, offset: u64, length: u64) -> Result<Vec<u8>, KernelError> {
        self.file.read_at(offset, length)
    }
    fn supports_copy_to_physical(&self) -> bool {
        true
    }
    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
        Some(self.file.copy_to_physical(offset, address, length))
    }
}

/// Processo carregado pelo caminho de entrada direta.
pub struct Loaded {
    pub entry_point: u64,
    pub image_base: u64,
    pub size_of_image: u64,
    pub stack_top: u64,
    pub process_pointer: u64,
    pub thread_pointer: u64,
    pub source: Arc<dyn FileSource>,
    /// A imagem, desfeita junto com o `Loaded`.
    _image: MainImage,
}

fn push_image(base: u64, size: u64, name: &str) {
    state::with(|state| state.regions(RegionKind::ProcessImages).push(Arc::new(ImageRegion { base, size, name: String::from(name), file: None })));
}

/// A imagem principal, desfeita quando o processo acaba (como a vista da
/// seção de imagem no rundown do NT): as páginas e a faixa voltam ao livre,
/// e o próximo executável com a mesma ImageBase carrega nela de novo.
struct MainImage(PeImage);

impl Drop for MainImage {
    fn drop(&mut self) {
        if let Err(error) = self.0.release() {
            crate::debug_print!("[usermode] imagem principal retida: {}", error);
            return;
        }
        if let Err(error) = crate::ntos::ke::smp::flush_remote_tlb(false) {
            crate::debug_print!("[usermode] TLB da imagem principal: {}", error);
        }
    }
}

/// A pilha da primeira thread: a entrada vê o rsp "depois de um call"
/// (8 mod 16) com endereço de retorno 0, para falhar alto se o programa
/// retornar. Devolve (base, topo, rsp inicial).
fn initial_stack() -> Result<(u64, u64, u64), KernelError> {
    let (base, top) = memory::map_user_stack()?;
    Ok((base, top, top - 8))
}

fn next_process_id() -> u64 {
    state::with(|state| {
        let id = state.next_process_id;
        state.next_process_id += 4;
        id
    })
}

fn syscall_stack() -> Option<u64> {
    Some(state::with(|state| state.syscall_stack_top)).filter(|&top| top != 0)
}

/// EPROCESS/KTHREAD reais: o processo entra em PsActiveProcessHead e vira o
/// corrente durante a execução.
pub fn load_process(bytes: Vec<u8>, image_name: &str) -> Result<Loaded, KernelError> {
    loader::ensure_ntdll()?;
    let image = MainImage(pe_loader::load_user(bytes.clone(), &LoadOptions { notify_image: false, ..LoadOptions::default() })?);
    let (entry_point, image_base, size_of_image) = (image.0.entry_point, image.0.image_base, image.0.size_of_image);
    let (_, _, stack_top) = initial_stack()?;
    let process_id = next_process_id();
    let source: Arc<dyn FileSource> = Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: Arc::new(bytes) });
    let executable = Executable { source: source.clone(), image_size: size_of_image, image_information: Some(image.0.image_information.to_vec()), command_line: None };
    let process_pointer = process::create_process(process_id, image_name, image_base, Some(&executable))?;
    push_image(image_base, size_of_image, source.name());
    let thread_pointer = match process::create_kernel_thread(process_pointer, process_id, true, 1, syscall_stack()).and_then(|thread| process::notify_thread_created(thread).map(|_| thread)) {
        Ok(thread) => thread,
        Err(error) => {
            let _ = process::terminate_process(process_pointer, if error.status != 0 { error.status } else { 0xC000_0001 });
            files::release_user_resources();
            return Err(error);
        }
    };
    Ok(Loaded { entry_point, image_base, size_of_image, stack_top, process_pointer, thread_pointer, source, _image: image })
}

/// Notificações das imagens iniciais: o executável (com o FILE_OBJECT da
/// seção de imagem) e a ntdll.
pub fn notify_initial_images(process_pointer: u64, image: Image, source: &Arc<dyn FileSource>) -> Result<(), KernelError> {
    let file_object = process::image_section(process_pointer).and_then(section_objects::state).map_or(0, |state| state.image_file_object);
    image_notify::notify(image, &NotifyOptions { name: Some(String::from(source.name())), file_object, source: Some(source.clone()), ..NotifyOptions::default() })?;
    if let Some(module) = loader::ntdll_module() {
        let name = module.notification_source.as_ref().map_or_else(|| module.full_name.clone(), |source| String::from(source.name()));
        image_notify::notify(Image { image_base: module.image_base, size_of_image: module.size_of_image }, &NotifyOptions { name: Some(name), source: module.notification_source.clone(), ..NotifyOptions::default() })?;
    }
    Ok(())
}

/// Entrada direta em anel 3 (sem TEB): volta no NtTerminateProcess.
pub fn run_process(bytes: Vec<u8>, image_name: &str) -> Result<u32, KernelError> {
    files::release_user_resources();
    let loaded = load_process(bytes, image_name)?;
    let previous = process::get_current_thread();
    process::set_current_thread(loaded.thread_pointer);
    notify_initial_images(loaded.process_pointer, Image { image_base: loaded.image_base, size_of_image: loaded.size_of_image }, &loaded.source)?;
    crate::debug_print!("[usermode] entrando em ring 3: {} entry {:#x} pilha {:#x}", image_name, loaded.entry_point, loaded.stack_top);
    let exit_code = usermode::exec_user_mode(loaded.entry_point, loaded.stack_top, 0, 0, 0, 0) as u32;
    let _ = process::terminate_process(loaded.process_pointer, exit_code);
    process::set_current_thread(previous);
    let _ = process::release_thread(loaded.thread_pointer);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", image_name, exit_code);
    files::release_user_resources();
    Ok(exit_code)
}

/// Opções de `run_windows_process`.
#[derive(Default)]
pub struct RunOptions<'a> {
    /// Sem console pai: DETACHED_PROCESS (padrão dos serviços e ferramentas).
    pub attached: bool,
    pub standard_output: u64,
    pub on_process_created: Option<&'a dyn Fn(u64) -> Result<(), KernelError>>,
}

/// Estado por processo (um processo de usuário por vez nesta camada).
fn reset_process_state() {
    files::release_user_resources();
    threads::clear();
    state::with(|state| {
        state.user_regions.clear();
        state.process_images.clear();
        state.next_ldr_string_va = 0;
        state.ldr_string_region_end = 0;
        state.mapped_image_exports.clear();
    });
    loader::reset_loaded_modules();
}

/// O kernel entrega exe, ntdll, PEB/TEB e o CONTEXT inicial; o loader
/// nativo carrega as dependências pelas syscalls de arquivo e seção.
pub fn run_windows_process(bytes: Option<Vec<u8>>, image_name: &str, dos_path: &str, reader: Option<Arc<VolumeFile>>, options: RunOptions<'_>) -> Result<u32, KernelError> {
    let capturing = state::with(|state| !state.capture_export.is_empty());
    if capturing {
        super::call_capture::reset();
    }
    reset_process_state();
    loader::ensure_ntdll()?;
    let ntdll: Arc<Module> = loader::ntdll_module().ok_or_else(|| KernelError::new("ntdll ausente"))?;
    if capturing {
        if let Some(exports) = state::with(|state| state.ntdll_exports.clone()) {
            super::call_capture::arm("ntdll.dll", &exports);
        }
    }
    push_image(ntdll.image_base, ntdll.size_of_image, &ntdll.full_name);
    loader::ensure_api_set_schema()?;
    loader::ensure_nls_data()?;
    loader::parse_api_set_schema()?;
    // A ntdll real faz o binding e a relocação da imagem principal.
    let load_options = LoadOptions { skip_imports: true, skip_relocations: true, notify_image: false, ..LoadOptions::default() };
    let (main_image, source): (PeImage, Arc<dyn FileSource>) = match (&reader, bytes) {
        (Some(file), _) => {
            let name = format!("\\NTFS{}", file.volume_path().replace('/', "\\"));
            let image = pe_loader::load_from_source(Arc::new(VolumeImage { name: name.clone(), file: file.clone() }), &LoadOptions { user_space: true, ..load_options })?;
            (image, Arc::new(VolumeSource { name, file: file.clone() }))
        }
        (None, Some(bytes)) => {
            let image = pe_loader::load_user(bytes.clone(), &load_options)?;
            (image, Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: Arc::new(bytes) }))
        }
        (None, None) => return Err(KernelError::new("processo sem imagem")),
    };
    // Desfeita na saída desta função, depois do processo e dos recursos.
    let main_image = MainImage(main_image);
    let image = &main_image.0;
    push_image(image.image_base, image.size_of_image, dos_path);
    let (stack_base, stack_end, stack_top) = initial_stack()?;
    let process_id = next_process_id();
    state::with(|state| {
        state.current_process_id = process_id;
        state.current_process_cookie = 0;
        state.current_image_path = String::from(dos_path);
    });
    let executable = Executable { source: source.clone(), image_size: image.size_of_image, image_information: Some(image.image_information.to_vec()), command_line: Some(format!("\"{dos_path}\"")) };
    let process_pointer = process::create_process(process_id, image_name, image.image_base, Some(&executable))?;
    // A PEB real sai antes das notificações da primeira thread.
    let created = structures::build_process_structures(&ProcessDescription { process_id, process_pointer, image_base: image.image_base, dos_path, detached: !options.attached, console_handle: options.standard_output, stack_base, stack_top: stack_end })
        .and_then(|teb| process::create_kernel_thread(process_pointer, process_id, true, 1, syscall_stack()).map(|thread| (teb, thread)));
    let (teb, thread_pointer) = match created {
        Ok(created) => created,
        Err(error) => {
            let _ = process::terminate_process(process_pointer, if error.status != 0 { error.status } else { 0xC000_0001 });
            files::release_user_resources();
            if error.status != 0 {
                return Ok(error.status);
            }
            return Err(error);
        }
    };
    let main = threads::UserThread::new(process_id, thread_pointer, teb, image.entry_point);
    threads::push(main.clone());
    process::set_thread_start(thread_pointer, image.entry_point);
    process::notify_thread_created(thread_pointer)?;
    if let Some(created) = options.on_process_created {
        created(process_id)?;
    }
    // A ntdll inicializa PEB.Ldr e carrega as dependências; o heap e o
    // runtime vêm antes dos DllMain.
    let peb = state::with(|state| state.current_peb_va);
    // SAFETY: a PEB do processo em montagem, criada pelo kernel.
    unsafe { Peb::at(peb) }.ldr.set(0);
    let context = memory::map_user_region(0x1000)?;
    let (start, initialize) = state::with(|state| {
        let exports = state.ntdll_exports.as_ref();
        (exports.and_then(|exports| exports.get("RtlUserThreadStart").copied()).unwrap_or(0), exports.and_then(|exports| exports.get("LdrInitializeThunk").copied()).unwrap_or(0))
    });
    if initialize == 0 || start == 0 {
        return Err(KernelError::new("ntdll sem inicializacao de processo"));
    }
    // CONTEXT inicial do LdrInitializeThunk, numa região recém-comprometida.
    // SAFETY: a região acabou de ser mapeada pelo kernel.
    let initial = unsafe { Context::at(context) };
    initial.context_flags.set(0x10_000B); // CONTEXT_FULL
    initial.mx_csr.set(0x1F80);
    initial.flt_save.control_word.set(0x37F);
    initial.flt_save.mx_csr.set(0x1F80);
    initial.seg_cs.set(0x33);
    initial.seg_ss.set(0x2B);
    initial.e_flags.set(0x202);
    initial.rcx.set(image.entry_point);
    initial.rdx.set(peb);
    initial.rsp.set(stack_top);
    initial.rip.set(start);
    let previous = process::get_current_thread();
    process::set_current_thread(thread_pointer);
    notify_initial_images(process_pointer, Image { image_base: image.image_base, size_of_image: image.size_of_image }, &source)?;
    crate::debug_print!("[usermode] {}: LdrInitializeThunk em {:#x} (exe entry {:#x}, teb {:#x})", image_name, initialize, image.entry_point, teb);
    state::with(|state| state.termination_rsp = 0);
    let result = threads::run(&main, initialize, stack_top, context, ntdll.image_base);
    if capturing {
        super::call_capture::finish();
    }
    let exit_code = match result {
        Ok(code) => code,
        Err(error) => {
            process::set_current_thread(previous);
            files::release_user_resources();
            return Err(error);
        }
    };
    let _ = process::terminate_process(process_pointer, exit_code);
    process::set_current_thread(previous);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", image_name, exit_code);
    let (heap_total, heap_used) = kmalloc::info();
    crate::debug_print!("[mm] process exit: PFN used={}/{}, kernel heap={}/{}", pfn::total_count() - pfn::free_count(), pfn::total_count(), heap_used, heap_total);
    if exit_code != 0x42 && exit_code != 0 {
        post_mortem();
    }
    files::release_user_resources();
    Ok(exit_code)
}

/// Candidatos de retorno na pilha da saída (não é um unwind), a falha
/// publicada pela HAL e o Ldr real do processo.
fn post_mortem() {
    let (termination, images): (u64, Vec<(u64, u64, String)>) = state::with(|state| (state.termination_rsp, state.process_images.iter().map(|image| (image.base(), image.size(), image.name().unwrap_or_default())).collect()));
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
    let fault_rsp = guest::read64(usermode::FAULT_RSP_CELL);
    let fault_cr2 = guest::read64(usermode::FAULT_CR2_CELL);
    if guest::read32(usermode::FAULT_VECTOR_CELL) == 0x29 {
        crate::debug_print!("[usermode] FAST_FAIL codigo={} rip={:#x}", guest::read32(usermode::FAULT_RCX_CELL), guest::read64(usermode::FAULT_RIP_CELL).wrapping_sub(2));
    }
    if fault_cr2 != 0 {
        crate::debug_print!("[usermode] CR2={:#x} -> pagina traduz p/ {:#x}", fault_cr2, paging::translate(fault_cr2 & !0xFFF));
    }
    // O Ldr real do processo, em memória de usuário: cada passo é sondado.
    let peb = state::with(|state| state.current_peb_va);
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
