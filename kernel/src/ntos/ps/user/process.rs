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
//!
//! Espaço próprio: o processo nasce com a raiz dele (o `create_process` com
//! imagem), e a montagem roda anexada a ele, como o
//! MmInitializeProcessAddressSpace e o MmCreatePeb: as cópias privadas da
//! ntdll, do apiset e do NLS, o executável (dele até o término), a pilha, a
//! PEB/TEB e o CONTEXT inicial vão só para a raiz dele. Montar
//! ([`create_windows_process`]) e executar ([`run_created`]) são passos
//! separados, então vários processos podem existir montados ao mesmo tempo.

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
use crate::ntos::mm::sysload::kernel_image_source::{ImageSource, MemorySource};
use crate::ntos::mm::pe_loader::{self, LoadOptions};

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
}

/// A imagem no VAD do processo corrente (o processo em montagem, anexado).
fn push_image(base: u64, size: u64, name: &str) {
    memory::insert_region(Space::current(), RegionKind::ProcessImages, Arc::new(ImageRegion { base, size, name: String::from(name), file: None }));
}

/// A imagem principal no espaço do processo em montagem (o corrente,
/// anexado): mapeada na raiz dele e possuída por ele até o término (como a
/// vista da seção de imagem no VAD do NT), com EPROCESS.SectionBaseAddress
/// na base real. Devolve (entry, base, tamanho).
fn map_main_image(process_pointer: u64, source: &Arc<dyn ImageSource>, options: &LoadOptions, name: &str) -> Result<(u64, u64, u64), KernelError> {
    let Some(owner) = process_state::get(process_pointer) else { return Err(KernelError::new("imagem principal sem estado do processo")) };
    let image = pe_loader::load_from_source(source.clone(), options)?;
    let placed = (image.entry_point, image.image_base, image.size_of_image);
    owner.adopt_image(image);
    // SAFETY: o EPROCESS em montagem, retido pelo chamador.
    unsafe { Eprocess::at(process_pointer) }.section_base_address.set(placed.1);
    push_image(placed.1, placed.2, name);
    Ok(placed)
}

/// A fonte de bytes da imagem principal, para o loader de PE.
fn memory_image(bytes: Vec<u8>) -> Arc<dyn ImageSource> {
    Arc::new(MemorySource { name: String::new(), bytes })
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
/// corrente durante a execução. Como no NT, o processo (e o espaço dele, a
/// raiz própria) nasce antes da imagem, que é mapeada nele, anexado: o
/// cabeçalho dá a base preferida e o tamanho.
pub fn load_process(bytes: Vec<u8>, image_name: &str) -> Result<Loaded, KernelError> {
    loader::ensure_ntdll()?;
    let source: Arc<dyn FileSource> = Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: Arc::new(bytes.clone()) });
    let image_source = memory_image(bytes);
    let (preferred_base, size_of_image) = pe_loader::image_layout(image_source.as_ref())?;
    let executable = Executable { source: source.clone(), image_size: size_of_image, image_information: None, command_line: None };
    let process_pointer = process::create_process(cid::ALLOCATE, image_name, preferred_base, Some(&executable))?;
    // A imagem e a pilha entram no espaço do processo novo, anexado.
    let placed = process_context::with_process(process_pointer, || -> Result<(u64, u64, u64, u64), KernelError> {
        let (entry_point, image_base, size_of_image) = map_main_image(process_pointer, &image_source, &LoadOptions { user_space: true, notify_image: false, ..LoadOptions::default() }, source.name())?;
        let (_, _, stack_top) = initial_stack()?;
        Ok((entry_point, image_base, size_of_image, stack_top))
    })
    .and_then(|placed| placed);
    let thread = placed.and_then(|placed| create_main_thread(process_pointer, cid::ALLOCATE).and_then(|thread| process::notify_thread_created(thread).map(|_| (thread, placed))));
    let (thread_pointer, (entry_point, image_base, size_of_image, stack_top)) = match thread {
        Ok(thread) => thread,
        Err(error) => {
            // O término libera o que o processo já possui.
            let _ = process::terminate_process(process_pointer, failure_status(&error));
            return Err(error);
        }
    };
    Ok(Loaded { entry_point, image_base, size_of_image, stack_top, process_pointer, thread_pointer, source })
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

/// STATUS_CANCELLED: um processo montado que é descartado sem rodar.
const STATUS_CANCELLED: u32 = 0xC000_0120;

/// O término de um processo montado aqui. Roda com a thread corrente de
/// quem o chama (a do processo, numa falha depois de ela virar a corrente:
/// as notificações de saída no contexto do processo, como no NT); o KTHREAD
/// que era o corrente só é recolhido depois da troca de volta para
/// `previous`.
fn end_process(process_pointer: u64, status: u32, previous: u64) {
    let _ = process::terminate_process(process_pointer, status);
    process::set_current_thread(previous);
    threads::release_process(process_pointer);
}

/// Um processo de usuário montado e ainda parado
/// ([`create_windows_process`]): o EPROCESS com raiz própria e, no espaço
/// dele, as cópias da ntdll, do apiset e do NLS, o executável, a pilha, a
/// PEB/TEB e o CONTEXT inicial; a thread principal ainda não entrou no
/// despachante. [`run_created`] o executa até o fim; descartado sem rodar,
/// ele termina com STATUS_CANCELLED.
pub struct CreatedProcess {
    pub process_pointer: u64,
    pub process_id: u64,
    pub thread_pointer: u64,
    pub thread_id: u64,
    pub teb: u64,
    /// O rsp inicial da primeira thread (topo da pilha - 8).
    pub stack_top: u64,
    pub image_base: u64,
    entry_point: u64,
    size_of_image: u64,
    context: u64,
    main: Arc<threads::UserThread>,
    image_name: String,
    source: Arc<dyn FileSource>,
    ntdll_base: u64,
    capturing: bool,
    /// Ainda não rodou nem terminou.
    pending: bool,
}

impl Drop for CreatedProcess {
    fn drop(&mut self) {
        if self.pending {
            self.pending = false;
            end_process(self.process_pointer, STATUS_CANCELLED, process::get_current_thread());
        }
    }
}

/// O que a montagem anexada ao processo novo produz.
struct Built {
    thread_id: u64,
    teb: u64,
    stack_top: u64,
    context: u64,
    entry_point: u64,
    image_base: u64,
    size_of_image: u64,
}

/// Monta um processo de usuário sem executá-lo: o kernel entrega exe,
/// ntdll, PEB/TEB e o CONTEXT inicial; o loader nativo carrega as
/// dependências pelas syscalls de arquivo e seção quando ele rodar.
/// `Ok(Err(status))`: o processo chegou a existir e já terminou com o
/// status da falha.
pub fn create_windows_process(bytes: Option<Vec<u8>>, image_name: &str, dos_path: &str, reader: Option<Arc<VolumeFile>>, options: &RunOptions<'_>) -> Result<Result<CreatedProcess, u32>, KernelError> {
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
    // A imagem principal: a fonte do loader de PE e a da seção de imagem do
    // processo. O processo (e o espaço dele) nasce antes de a imagem ser
    // mapeada nele, então o cabeçalho dá a base preferida e o tamanho.
    let (image_source, source): (Arc<dyn ImageSource>, Arc<dyn FileSource>) = match (&reader, bytes) {
        (Some(file), _) => {
            let name = format!("\\NTFS{}", file.volume_path().replace('/', "\\"));
            (Arc::new(VolumeImage { name: name.clone(), file: file.clone() }), Arc::new(VolumeSource { name, file: file.clone() }))
        }
        (None, Some(bytes)) => {
            let shared = Arc::new(bytes.clone());
            (memory_image(bytes), Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: shared }))
        }
        (None, None) => return Err(KernelError::new("processo sem imagem")),
    };
    let (preferred_base, size_of_image) = pe_loader::image_layout(image_source.as_ref())?;
    let executable = Executable { source: source.clone(), image_size: size_of_image, image_information: None, command_line: Some(format!("\"{dos_path}\"")) };
    // O PID sai da tabela de ids de cliente e o processo ganha a raiz
    // própria (o PspAllocateProcess); o caminho da imagem fica no estado do
    // processo.
    let process_pointer = process::create_process(cid::ALLOCATE, image_name, preferred_base, Some(&executable))?;
    let process_id = process_id_of(process_pointer);
    if let Some(identity) = process_state::get(process_pointer) {
        identity.set_image_path(dos_path);
    }
    // Daqui em diante toda saída passa pelo término, que libera o que o
    // processo possui.
    let previous = process::get_current_thread();
    let fail = |error: KernelError| -> KernelError {
        end_process(process_pointer, failure_status(&error), previous);
        error
    };
    // O espaço do processo novo, anexado (o MmInitializeProcessAddressSpace
    // e o MmCreatePeb): as cópias de sistema, o exe na raiz dele (a ntdll
    // real faz o binding e a relocação), a ntdll e o exe no VAD, a pilha da
    // primeira thread, a PEB real (antes das notificações da primeira
    // thread) e a região do CONTEXT inicial. O TID da primeira thread sai da
    // mesma tabela dos PIDs, reservado antes porque a TEB o recebe antes de a
    // thread existir.
    let load_options = LoadOptions { user_space: true, skip_imports: true, skip_relocations: true, notify_image: false, ..LoadOptions::default() };
    let built = cid::allocate(cid::Kind::Thread).and_then(|thread_id| {
        process_context::with_process(process_pointer, || -> Result<Built, KernelError> {
            loader::map_system_images()?;
            let (entry_point, image_base, size_of_image) = map_main_image(process_pointer, &image_source, &load_options, dos_path)?;
            push_image(ntdll.image_base, ntdll.size_of_image, &ntdll.full_name);
            let (stack_base, stack_end, stack_top) = initial_stack()?;
            let teb = structures::build_process_structures(&ProcessDescription { process_id, thread_id, process_pointer, image_base, dos_path, detached: !options.attached, console_handle: options.standard_output, stack_base, stack_top: stack_end })?;
            Ok(Built { thread_id, teb, stack_top, context: memory::map_user_region(0x1000)?, entry_point, image_base, size_of_image })
        })
        .and_then(|built| built)
        .inspect_err(|_| cid::release(thread_id, 0))
    });
    let created = built.and_then(|built| {
        let thread_id = built.thread_id;
        create_main_thread(process_pointer, thread_id).map(|thread| (built, thread)).inspect_err(|_| cid::release(thread_id, 0))
    });
    let (built, thread_pointer) = match created {
        Ok(created) => created,
        Err(error) => {
            let error = fail(error);
            if error.status != 0 {
                return Ok(Err(error.status));
            }
            return Err(error);
        }
    };
    // A thread principal entra na lista do processo (e no índice global).
    let main = threads::UserThread::new(built.thread_id, thread_pointer, built.teb, built.entry_point);
    threads::push(main.clone());
    process::set_thread_start(thread_pointer, built.entry_point);
    process::notify_thread_created(thread_pointer).map_err(fail)?;
    if let Some(created) = options.on_process_created {
        created(process_id).map_err(fail)?;
    }
    Ok(Ok(CreatedProcess {
        process_pointer,
        process_id,
        thread_pointer,
        thread_id: built.thread_id,
        teb: built.teb,
        stack_top: built.stack_top,
        image_base: built.image_base,
        entry_point: built.entry_point,
        size_of_image: built.size_of_image,
        context: built.context,
        main,
        image_name: String::from(image_name),
        source,
        ntdll_base: ntdll.image_base,
        capturing,
        pending: true,
    }))
}

/// Executa um processo montado até o fim: o LdrInitializeThunk da ntdll em
/// anel 3 (heap, imports e TLS antes do entry), o despachante das threads
/// dele e o término. Devolve o código de saída.
pub fn run_created(mut created: CreatedProcess) -> Result<u32, KernelError> {
    created.pending = false;
    let process_pointer = created.process_pointer;
    let previous = process::get_current_thread();
    let fail = |error: KernelError| -> KernelError {
        end_process(process_pointer, failure_status(&error), previous);
        error
    };
    // Daqui em diante a thread do processo é a corrente: a PEB e o CONTEXT
    // inicial são memória de usuário dele.
    process::set_current_thread(created.thread_pointer);
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
    let initial = unsafe { Context::at(created.context) };
    initial.context_flags.set(0x10_000B); // CONTEXT_FULL
    initial.mx_csr.set(0x1F80);
    initial.flt_save.control_word.set(0x37F);
    initial.flt_save.mx_csr.set(0x1F80);
    initial.seg_cs.set(0x33);
    initial.seg_ss.set(0x2B);
    initial.e_flags.set(0x202);
    initial.rcx.set(created.entry_point);
    initial.rdx.set(peb);
    initial.rsp.set(created.stack_top);
    initial.rip.set(start);
    notify_initial_images(process_pointer, Image { image_base: created.image_base, size_of_image: created.size_of_image }, &created.source).map_err(fail)?;
    crate::debug_print!("[usermode] {}: LdrInitializeThunk em {:#x} (exe entry {:#x}, teb {:#x})", created.image_name, initialize, created.entry_point, created.teb);
    let result = threads::run(&created.main, initialize, created.stack_top, created.context, created.ntdll_base);
    if created.capturing {
        super::call_capture::finish();
    }
    let exit_code = result.map_err(fail)?;
    // O post-mortem lê a pilha, as imagens e o Ldr antes de o término
    // devolver o VAD, anexado ao processo: o laço devolveu a thread de quem
    // o chamou.
    if exit_code != 0x42 && exit_code != 0 {
        let _ = process_context::with_process(process_pointer, || post_mortem(process_pointer));
    }
    end_process(process_pointer, exit_code, previous);
    crate::debug_print!("[usermode] {} saiu: codigo {:#x}", created.image_name, exit_code);
    let (heap_total, heap_used) = kmalloc::info();
    crate::debug_print!("[mm] process exit: PFN used={}/{}, kernel heap={}/{}", pfn::total_count() - pfn::free_count(), pfn::total_count(), heap_used, heap_total);
    Ok(exit_code)
}

/// Monta e executa um processo de usuário ([`create_windows_process`] e
/// [`run_created`]); devolve o código de saída.
pub fn run_windows_process(bytes: Option<Vec<u8>>, image_name: &str, dos_path: &str, reader: Option<Arc<VolumeFile>>, options: RunOptions<'_>) -> Result<u32, KernelError> {
    match create_windows_process(bytes, image_name, dos_path, reader, &options)? {
        Ok(created) => run_created(created),
        Err(status) => Ok(status),
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
