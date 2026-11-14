//! Montagem e execução de processos de usuário.
//!
//! O processo NT real (EPROCESS/KTHREAD de `ps/process`, com a seção de
//! imagem da fonte exata) e o LdrInitializeThunk da ntdll em anel 3: a ntdll
//! inicializa heap, imports e TLS antes do entry. Inclui o post-mortem
//! (candidatos de retorno na pilha da saída, Ldr e pilha da falha).
//!
//! Todo processo criado aqui acaba em `ps::process::terminate_process`,
//! inclusive nas falhas depois da criação, e o término libera tudo o que ele
//! possui (`files::release_user_resources` e `process_state::destroy`): não
//! há reinício global entre um processo e o próximo.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::offset_of;

use super::loader::{self, BytesSource, ImageRegion, Module};
use super::memory::{self, Space};
use super::process_state;
use super::state::{self, RegionKind};
use super::structures::{self, ProcessDescription};
use super::threads;
use crate::hal::{bundle, kmalloc};
use crate::hal::amd64::usermode;
use crate::ntos::cm::service::database::{self as service_database, CommandLine, ServiceError, ServiceResult};
use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::mm::{kernel_stack, paging, pfn};
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::cid;
use crate::ntos::ps::process::{self, Executable};
use crate::ntos::ps::process_context;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Context, Eprocess, LdrDataTableEntry, ListEntry, NtStruct, Peb, PebLdrData};
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

/// A imagem no VAD do processo corrente (o processo em montagem, anexado).
fn push_image(base: u64, size: u64, name: &str) {
    memory::insert_region(Space::current(), RegionKind::ProcessImages, Arc::new(ImageRegion { base, size, name: String::from(name), file: None }));
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

/// A KTHREAD da primeira thread, com pilha de kernel própria.
fn create_main_thread(process_pointer: u64, thread_id: u64) -> Result<u64, KernelError> {
    process::create_kernel_thread(process_pointer, thread_id, true, 1, Some(kernel_stack::create(false)?))
}

/// EPROCESS/KTHREAD reais: o processo entra em PsActiveProcessHead e vira o
/// corrente durante a execução.
pub fn load_process(bytes: Vec<u8>, image_name: &str) -> Result<Loaded, KernelError> {
    loader::ensure_ntdll()?;
    let image = MainImage(pe_loader::load_user(bytes.clone(), &LoadOptions { notify_image: false, ..LoadOptions::default() })?);
    let (entry_point, image_base, size_of_image) = (image.0.entry_point, image.0.image_base, image.0.size_of_image);
    let source: Arc<dyn FileSource> = Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: Arc::new(bytes) });
    let executable = Executable { source: source.clone(), image_size: size_of_image, image_information: Some(image.0.image_information.to_vec()), command_line: None };
    let process_pointer = process::create_process(cid::ALLOCATE, image_name, image_base, Some(&executable))?;
    // A imagem e a pilha entram no VAD do processo novo, anexado.
    let stack = process_context::with_process(process_pointer, || {
        push_image(image_base, size_of_image, source.name());
        initial_stack()
    })
    .and_then(|stack| stack);
    let thread = stack.and_then(|(_, _, stack_top)| create_main_thread(process_pointer, cid::ALLOCATE).and_then(|thread| process::notify_thread_created(thread).map(|_| (thread, stack_top))));
    let (thread_pointer, stack_top) = match thread {
        Ok(thread) => thread,
        Err(error) => {
            // O término libera o que o processo já possui.
            let _ = process::terminate_process(process_pointer, failure_status(&error));
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

/// EPROCESS.UniqueProcessId.
fn process_id_of(process: u64) -> u64 {
    // SAFETY: EPROCESS recém-criado, retido pelo chamador.
    unsafe { Eprocess::at(process) }.unique_process_id.get()
}

/// O status de saída de um processo que falhou depois de criado.
fn failure_status(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { 0xC000_0001 }
}

/// Entrada direta em anel 3 (sem TEB): volta no NtTerminateProcess. O
/// término libera o que o processo possui.
pub fn run_process(bytes: Vec<u8>, image_name: &str) -> Result<u32, KernelError> {
    let loaded = load_process(bytes, image_name)?;
    let previous = process::get_current_thread();
    process::set_current_thread(loaded.thread_pointer);
    if let Err(error) = notify_initial_images(loaded.process_pointer, Image { image_base: loaded.image_base, size_of_image: loaded.size_of_image }, &loaded.source) {
        let _ = process::terminate_process(loaded.process_pointer, failure_status(&error));
        process::set_current_thread(previous);
        let _ = process::release_thread(loaded.thread_pointer);
        return Err(error);
    }
    crate::debug_print!("[usermode] entrando em ring 3: {} entry {:#x} pilha {:#x}", image_name, loaded.entry_point, loaded.stack_top);
    let exit_code = usermode::exec_user_mode(loaded.entry_point, loaded.stack_top, 0, 0, 0, 0) as u32;
    let _ = process::terminate_process(loaded.process_pointer, exit_code);
    process::set_current_thread(previous);
    let _ = process::release_thread(loaded.thread_pointer);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", image_name, exit_code);
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

/// O kernel entrega exe, ntdll, PEB/TEB e o CONTEXT inicial; o loader
/// nativo carrega as dependências pelas syscalls de arquivo e seção.
pub fn run_windows_process(bytes: Option<Vec<u8>>, image_name: &str, dos_path: &str, reader: Option<Arc<VolumeFile>>, options: RunOptions<'_>) -> Result<u32, KernelError> {
    let capturing = state::with(|state| !state.capture_export.is_empty());
    if capturing {
        super::call_capture::reset();
    }
    loader::ensure_ntdll()?;
    let ntdll: Arc<Module> = loader::ntdll_module().ok_or_else(|| KernelError::new("ntdll ausente"))?;
    if capturing {
        if let Some(exports) = state::with(|state| state.ntdll_exports.clone()) {
            super::call_capture::arm("ntdll.dll", &exports);
        }
    }
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
    let executable = Executable { source: source.clone(), image_size: image.size_of_image, image_information: Some(image.image_information.to_vec()), command_line: Some(format!("\"{dos_path}\"")) };
    // O PID sai da tabela de ids de cliente; o caminho da imagem fica no
    // estado do processo.
    let process_pointer = process::create_process(cid::ALLOCATE, image_name, image.image_base, Some(&executable))?;
    let process_id = process_id_of(process_pointer);
    if let Some(identity) = process_state::get(process_pointer) {
        identity.set_image_path(dos_path);
    }
    // Daqui em diante toda saída passa pelo término, que libera o que o
    // processo possui; ele roda com a thread do processo ainda corrente (as
    // notificações de saída no contexto do processo, como no NT) e o KTHREAD
    // que era o corrente só é recolhido depois da troca de volta.
    let previous = process::get_current_thread();
    let end = |status: u32| {
        let _ = process::terminate_process(process_pointer, status);
        process::set_current_thread(previous);
        threads::release_process(process_pointer);
    };
    let fail = |error: KernelError| -> KernelError {
        end(failure_status(&error));
        error
    };
    // O espaço do processo novo, anexado (como o MmCreatePeb): a ntdll e o
    // exe no VAD dele, a pilha da primeira thread, a PEB real (antes das
    // notificações da primeira thread) e a região do CONTEXT inicial. O TID
    // da primeira thread sai da mesma tabela dos PIDs, reservado antes porque
    // a TEB o recebe antes de a thread existir.
    let built = cid::allocate(cid::Kind::Thread).and_then(|thread_id| {
        process_context::with_process(process_pointer, || -> Result<(u64, u64, u64, u64), KernelError> {
            push_image(ntdll.image_base, ntdll.size_of_image, &ntdll.full_name);
            push_image(image.image_base, image.size_of_image, dos_path);
            let (stack_base, stack_end, stack_top) = initial_stack()?;
            let teb = structures::build_process_structures(&ProcessDescription { process_id, thread_id, process_pointer, image_base: image.image_base, dos_path, detached: !options.attached, console_handle: options.standard_output, stack_base, stack_top: stack_end })?;
            Ok((thread_id, teb, stack_top, memory::map_user_region(0x1000)?))
        })
        .and_then(|built| built)
        .inspect_err(|_| cid::release(thread_id, 0))
    });
    let created = built.and_then(|(thread_id, teb, stack_top, context)| create_main_thread(process_pointer, thread_id).map(|thread| (thread_id, teb, thread, stack_top, context)).inspect_err(|_| cid::release(thread_id, 0)));
    let (thread_id, teb, thread_pointer, stack_top, context) = match created {
        Ok(created) => created,
        Err(error) => {
            let error = fail(error);
            if error.status != 0 {
                return Ok(error.status);
            }
            return Err(error);
        }
    };
    // A thread principal entra na lista do processo (e no índice global).
    let main = threads::UserThread::new(thread_id, thread_pointer, teb, image.entry_point);
    threads::push(main.clone());
    process::set_thread_start(thread_pointer, image.entry_point);
    process::notify_thread_created(thread_pointer).map_err(fail)?;
    if let Some(created) = options.on_process_created {
        created(process_id).map_err(fail)?;
    }
    // Daqui em diante a thread do processo é a corrente: a PEB e o CONTEXT
    // inicial são memória de usuário dele.
    process::set_current_thread(thread_pointer);
    // A ntdll inicializa PEB.Ldr e carrega as dependências; o heap e o
    // runtime vêm antes dos DllMain.
    // SAFETY: o EPROCESS do processo em montagem.
    let peb = unsafe { Eprocess::at(process_pointer) }.peb.get();
    // SAFETY: a PEB do processo em montagem, criada pelo kernel.
    unsafe { Peb::at(peb) }.ldr.set(0);
    let (start, initialize) = state::with(|state| {
        let exports = state.ntdll_exports.as_ref();
        (exports.and_then(|exports| exports.get("RtlUserThreadStart").copied()).unwrap_or(0), exports.and_then(|exports| exports.get("LdrInitializeThunk").copied()).unwrap_or(0))
    });
    if initialize == 0 || start == 0 {
        return Err(fail(KernelError::new("ntdll sem inicializacao de processo")));
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
    notify_initial_images(process_pointer, Image { image_base: image.image_base, size_of_image: image.size_of_image }, &source).map_err(fail)?;
    crate::debug_print!("[usermode] {}: LdrInitializeThunk em {:#x} (exe entry {:#x}, teb {:#x})", image_name, initialize, image.entry_point, teb);
    let result = threads::run(&main, initialize, stack_top, context, ntdll.image_base);
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
    end(exit_code);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", image_name, exit_code);
    let (heap_total, heap_used) = kmalloc::info();
    crate::debug_print!("[mm] process exit: PFN used={}/{}, kernel heap={}/{}", pfn::total_count() - pfn::free_count(), pfn::total_count(), heap_used, heap_total);
    Ok(exit_code)
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
