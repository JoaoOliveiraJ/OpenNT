//! Criação de processos de usuário: um caminho só.
//!
//! O papel do PspCreateProcess/PspAllocateProcess do NT, com o
//! MmInitializeProcessAddressSpace, o MmCreatePeb, o PspAllocateThread e o
//! PspInsertProcess/PspInsertThread. Todo processo de usuário nasce em
//! [`create_user_process`]: os do `run_windows_process` e do `run_service`
//! (`ps/user/process.rs`) e os dos autotestes. A ordem:
//!
//! 1. imagem: o arquivo (caminho NT de um arquivo do volume, um arquivo do
//!    volume já aberto ou bytes do bundle), a abertura de um arquivo do
//!    volume (SYNCHRONIZE | FILE_EXECUTE mais o AdditionalFileAccess do
//!    pedido, com FILE_SHARE_READ | FILE_SHARE_DELETE, contra as aberturas
//!    existentes), o layout do cabeçalho e as características que o pedido
//!    proíbe (PsCreateFailExeFormat); uma falha aqui não cria nada;
//! 2. PspAllocateProcess: `process::create_process` dá o EPROCESS, o PID da
//!    tabela de ids de cliente, a raiz própria, o `ProcessState` e a seção de
//!    imagem; o estado guarda o caminho da imagem; com
//!    `inherit_handles_from` (PROCESS_CREATE_FLAGS_INHERIT_HANDLES), o
//!    ObInitProcess copia os handles inherit do pai com os mesmos valores;
//! 3. anexado ao processo novo (MmInitializeProcessAddressSpace e
//!    MmCreatePeb): as cópias de sistema (ntdll, apiset e NLS), o executável
//!    na raiz dele, a pilha da primeira thread, a PEB (`mm/peb_teb.rs`), a
//!    PEB_LDR_DATA do loader do kernel, o manifesto embutido do executável
//!    quando o pedido manda procurá-lo (o PspLocateInPEManifest: RT_MANIFEST
//!    1 pela pesquisa de recursos da Rtl; achado, o bloco de parâmetros leva
//!    RTL_USER_PROC_APP_MANIFEST_PRESENT), os parâmetros
//!    (`ps/process_parameters.rs`), a TEB e o CONTEXT inicial do
//!    LdrInitializeThunk (RtlUserThreadStart(entry, PEB) na pilha nova);
//! 4. PspAllocateThread: a KTHREAD com pilha de kernel própria e o TID
//!    reservado antes (a TEB o recebe antes de a thread existir), na lista
//!    do processo e no índice global de threads de usuário;
//! 5. PspInsertProcess/PspInsertThread: as notificações de processo e de
//!    thread no contexto de quem cria, e as de carga de imagem do executável
//!    e da ntdll anexadas ao processo novo, com o PID dele (os drivers leem
//!    os cabeçalhos em ImageBase).
//!
//! O pedido pode declarar outro pai (o PS_ATTRIBUTE_PARENT_PROCESS do
//! NtCreateUserProcess, que `ps/create_context.rs` traduz) e criar a thread
//! principal suspensa (THREAD_CREATE_FLAGS_CREATE_SUSPENDED): ela entra no
//! despachante com a suspensão e só anda depois do NtResumeThread.
//!
//! O processo sai parado ([`CreatedProcess`]): a thread principal ainda não
//! entrou no despachante. Toda falha depois do passo 2 passa pelo término,
//! que libera o que o processo já possui, e um processo criado que é
//! descartado sem rodar termina com STATUS_CANCELLED.
//!
//! Aqui também mora o fim de um processo de usuário ([`exit_process`], o
//! PspExitProcess), o único caminho até o término: a falha na criação, o
//! descarte, o NtTerminateProcess dele mesmo (no fim do intervalo), o de
//! outro processo por handle, uma exceção fatal. As threads dele morrem na
//! hora; o término roda quando nenhuma delas tem mais serviço suspenso no
//! kernel (o despachante de `ps/user/threads.rs` desfaz os serviços e o
//! conclui depois do intervalo, [`finish_exit`]).

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::drivers::fs::volume_files::{self, VolumeFile};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Peb};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::pe_loader::{self, LoadOptions};
use crate::ntos::mm::peb_teb::{self, TebDescription};
use crate::ntos::mm::sysload::kernel_image_source::{ImageSource, MemorySource};
use crate::ntos::mm::kernel_stack;
use crate::ntos::ob::objects::file::FileSource;
use crate::ntos::ob::objects::section as section_objects;
use crate::ntos::ps::notify::image::{self as image_notify, Image, NotifyOptions};
use crate::ntos::ps::process::{self, Executable};
use crate::ntos::ps::process_parameters::ProcessParameters;
use crate::ntos::ps::user::file_io;
use crate::ntos::ps::user::loader::{self, BytesSource, ImageRegion, Module};
use crate::ntos::ps::user::memory::{self, Space};
use crate::ntos::ps::user::process_state;
use crate::ntos::ps::user::state::{self, RegionKind};
use crate::ntos::ps::user::threads::{self, UserThread};
use crate::ntos::ps::{cid, process_context};
use crate::ntos::rtl::image::pe_image_information::INFORMATION_SIZE;
use crate::ntos::rtl::resource::find as resource_find;
use crate::rtl::KernelError;

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INVALID_IMAGE_FORMAT: u32 = 0xC000_007B;
const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_RESOURCE_DATA_NOT_FOUND: u32 = 0xC000_0089;
const STATUS_RESOURCE_TYPE_NOT_FOUND: u32 = 0xC000_008A;
const STATUS_RESOURCE_NAME_NOT_FOUND: u32 = 0xC000_008B;
const STATUS_RESOURCE_LANG_NOT_FOUND: u32 = 0xC000_0204;
/// SYNCHRONIZE | FILE_EXECUTE: o acesso mínimo da abertura do executável.
const IMAGE_FILE_ACCESS: u32 = 0x10_0020;
/// FILE_SHARE_READ | FILE_SHARE_DELETE.
pub const IMAGE_FILE_SHARE: u32 = 5;
/// FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE.
pub const IMAGE_FILE_OPTIONS: u32 = 0x60;
/// RT_MANIFEST e CREATEPROCESS_MANIFEST_RESOURCE_ID.
const RT_MANIFEST: u64 = 24;
const CREATEPROCESS_MANIFEST_RESOURCE_ID: u64 = 1;
/// As flags do LdrResSearchResource do PspLocateInPEManifest: só o módulo
/// principal (0x10) e o primeiro idioma achado (0x20).
const MANIFEST_SEARCH_FLAGS: u64 = 0x30;
/// RTL_USER_PROC_APP_MANIFEST_PRESENT, no Flags do bloco de parâmetros.
pub const APP_MANIFEST_PRESENT: u32 = 0x2000;
/// Um processo criado que é descartado sem rodar.
const STATUS_CANCELLED: u32 = 0xC000_0120;
/// THREAD_CREATE_FLAGS_CREATE_SUSPENDED e THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER.
pub const THREAD_CREATE_SUSPENDED: u32 = 0x1;
pub const THREAD_HIDE_FROM_DEBUGGER: u32 = 0x4;

/// De onde vem a imagem principal.
pub enum ImageOrigin {
    /// Caminho NT de um arquivo do volume (`\??\C:\...`).
    NtPath(String),
    /// Um arquivo do volume já resolvido (o do SCM).
    Volume(Arc<VolumeFile>),
    /// Bytes de um executável (bundle e autotestes).
    Bytes(Vec<u8>),
}

/// O pedido de criação.
pub struct CreateProcessRequest<'a> {
    pub image: ImageOrigin,
    /// Nome curto da imagem (EPROCESS.ImageFileName e o nome da fonte de
    /// bytes, `\BootBundle\apps\<nome>`).
    pub image_name: &'a str,
    pub parameters: ProcessParameters,
    /// O pai declarado (EPROCESS), quando não é quem cria: o PID dele vai para
    /// as notificações de processo e para EPROCESS.InheritedFromUniqueProcessId.
    pub parent: Option<u64>,
    /// THREAD_CREATE_FLAGS_* da thread principal: [`THREAD_CREATE_SUSPENDED`]
    /// e [`THREAD_HIDE_FROM_DEBUGGER`] valem; os outros bits não mudam nada
    /// na thread inicial.
    pub thread_flags: u32,
    /// Chamado com o PID quando o processo já está inteiro e ainda parado;
    /// uma falha termina o processo.
    pub on_created: Option<&'a dyn Fn(u64) -> Result<(), KernelError>>,
    /// PROCESS_CREATE_FLAGS_INHERIT_HANDLES: o EPROCESS do pai cujos handles
    /// marcados OBJ_INHERIT o processo novo recebe, com os mesmos valores.
    /// `None`: a tabela do processo novo nasce vazia.
    pub inherit_handles_from: Option<u64>,
    /// PS_PROTECTION do processo novo (0: sem proteção), gravado no EPROCESS
    /// antes da PEB, que recebe IsProtectedProcess/IsProtectedProcessLight.
    pub protection: u8,
    /// PROCESS_CREATE_FLAGS_CREATE_SESSION: o processo abre uma sessão nova
    /// (`mm::session::create`); sem ele, entra na sessão do pai.
    pub create_session: bool,
    /// O token do PS_ATTRIBUTE_TOKEN: o processo recebe uma cópia dele, com
    /// o SessionId da sessão do processo (o SeSubProcessToken do
    /// PspInitializeProcessSecurity), em vez da cópia do token de quem cria.
    pub primary_token: Option<u64>,
    /// O que o InitState do PS_CREATE_INFO pede sobre o arquivo e a imagem.
    pub image_request: ImageRequest,
}

/// O InitState do PS_CREATE_INFO (o PspCaptureCreateInfo): o que quem cria
/// pede sobre o arquivo e a imagem principal. O padrão é o de quem não pede
/// nada.
#[derive(Clone, Copy, Debug, Default)]
pub struct ImageRequest {
    /// AdditionalFileAccess: direitos somados ao SYNCHRONIZE | FILE_EXECUTE
    /// da abertura do arquivo (o kernel32 passa FILE_READ_DATA |
    /// FILE_READ_ATTRIBUTES).
    pub additional_file_access: u32,
    /// ProhibitedImageCharacteristics: bits de FileHeader.Characteristics que
    /// recusam a imagem com PsCreateFailExeFormat (o kernel32 passa
    /// IMAGE_FILE_DLL).
    pub prohibited_characteristics: u16,
    /// DetectManifest: procurar o manifesto embutido do executável (o
    /// PspLocateInPEManifest).
    pub detect_manifest: bool,
}

/// O manifesto embutido do executável (RT_MANIFEST 1): a VA no processo
/// novo e o tamanho.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub address: u64,
    pub size: u32,
}

/// Por que a criação falhou (os estados de falha do PS_CREATE_INFO).
#[derive(Debug)]
pub enum CreateFailure {
    /// O arquivo da imagem não abriu (PsCreateFailOnFileOpen).
    FileOpen(u32),
    /// O arquivo não é um executável aceito (PsCreateFailExeFormat), com o
    /// DllCharacteristics da imagem (0 quando o cabeçalho não foi lido).
    ExeFormat(KernelError, u16),
    /// O processo chegou a existir e já terminou com este status.
    Terminated(u32),
    /// O processo não chegou a existir.
    Other(KernelError),
}

impl CreateFailure {
    /// O NTSTATUS da falha.
    pub fn status(&self) -> u32 {
        match self {
            Self::FileOpen(status) | Self::Terminated(status) => *status,
            Self::ExeFormat(..) => STATUS_INVALID_IMAGE_FORMAT,
            Self::Other(error) => failure_status(error),
        }
    }
}

impl core::fmt::Display for CreateFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FileOpen(status) => write!(formatter, "imagem nao abriu ({status:#x})"),
            Self::ExeFormat(error, _) => write!(formatter, "imagem invalida: {error}"),
            Self::Terminated(status) => write!(formatter, "processo terminou na criacao ({status:#x})"),
            Self::Other(error) => write!(formatter, "{error}"),
        }
    }
}

/// Um processo de usuário criado e ainda parado: o EPROCESS com raiz própria
/// e, no espaço dele, as cópias da ntdll, do apiset e do NLS, o executável,
/// a pilha, a PEB, os parâmetros, a TEB e o CONTEXT inicial; a thread
/// principal ainda não entrou no despachante. Descartado sem rodar, ele
/// termina com STATUS_CANCELLED.
pub struct CreatedProcess {
    pub process_pointer: u64,
    pub process_id: u64,
    pub thread_pointer: u64,
    pub thread_id: u64,
    /// A thread principal (na lista do processo e no índice global).
    pub thread: Arc<UserThread>,
    pub peb: u64,
    pub teb: u64,
    /// O bloco de RTL_USER_PROCESS_PARAMETERS (PEB.ProcessParameters).
    pub parameters: u64,
    /// O rsp inicial da primeira thread (topo da pilha - 8).
    pub stack_top: u64,
    pub image_base: u64,
    pub entry_point: u64,
    pub size_of_image: u64,
    /// O SECTION_IMAGE_INFORMATION da imagem principal, na base real (o
    /// PS_ATTRIBUTE_IMAGE_INFO do NtCreateUserProcess).
    pub image_information: [u8; INFORMATION_SIZE],
    /// O manifesto embutido achado com DetectManifest.
    pub manifest: Option<Manifest>,
    /// O Flags do bloco de parâmetros entregue (o CurrentParameterFlags do
    /// PsCreateSuccess).
    pub parameter_flags: u32,
    /// O arquivo do executável, quando veio do volume, com o acesso da
    /// abertura da criação (o FileHandle do PsCreateSuccess).
    pub image_file: Option<ImageFile>,
    /// O CONTEXT inicial que o LdrInitializeThunk recebe: o
    /// RtlUserThreadStart(entry, PEB) da primeira thread, numa região do
    /// processo.
    pub context: u64,
    /// Onde a primeira thread entra (o LdrInitializeThunk da ntdll) e a base
    /// da ntdll, o segundo argumento dele.
    pub initialize: u64,
    pub ntdll_base: u64,
    pub image_name: String,
    /// Ainda não rodou nem terminou.
    pending: bool,
}

impl CreatedProcess {
    /// O processo vai rodar: daqui em diante quem o executa responde pelo
    /// término, e o descarte não o termina mais.
    pub fn begin_run(&mut self) {
        self.pending = false;
    }
}

impl Drop for CreatedProcess {
    fn drop(&mut self) {
        if self.pending {
            self.pending = false;
            exit_process(self.process_pointer, STATUS_CANCELLED);
        }
    }
}

/// O fim de um processo de usuário (o PspExitProcess), pedido de qualquer
/// contexto: uma falha na criação, o descarte, o NtTerminateProcess dele
/// mesmo (no fim do intervalo), o de outro processo por handle, uma exceção
/// fatal ou uma falha de despacho. As threads dele morrem na hora
/// (`threads::begin_exit`); o término roda já se nenhuma delas tem serviço
/// suspenso no kernel e o intervalo em curso nesta CPU não é de uma delas,
/// ou fica para o despachante, que o conclui ([`finish_exit`]) depois de
/// desfazer os serviços. Só o processo `process_pointer` perde alguma coisa.
/// Devolve `false` se o fim já tinha sido pedido ou o processo já terminou.
pub fn exit_process(process_pointer: u64, status: u32) -> bool {
    if !threads::begin_exit(process_pointer, status) {
        return false;
    }
    crate::debug_print!("[ps] fim do processo {:#x} pedido: codigo {:#x}", process_pointer, status);
    if threads::exit_ready(process_pointer) {
        finish_exit(process_pointer);
    }
    true
}

/// O término de um processo com o fim pedido ([`exit_process`]): o
/// post-mortem de um processo que rodou (anexado, antes de o VAD voltar), o
/// `ps::process::terminate_process` — notificações, as rotinas de saída
/// (`files::release_user_resources`: threads, E/S pendente, fábricas,
/// mutantes, instrumentação e canais RPC do processo), handles, VAD e
/// imagens — e a liberação das threads. As notificações rodam no contexto do
/// processo, como as da última thread no NT: quando quem chama é a última
/// thread dele (a que saiu no próprio contexto), ela mesma; senão uma thread
/// do processo como corrente. O KTHREAD que era o corrente só é recolhido
/// depois da troca de volta para a thread de quem chama.
pub fn finish_exit(process_pointer: u64) {
    let Some(status) = threads::claim_exit(process_pointer) else { return };
    let ran = process_state::get(process_pointer).is_some_and(|state| state.started.load(core::sync::atomic::Ordering::Acquire));
    if ran && status != 0x42 && status != 0 {
        // Um status de exceção sai no bloco do diagnóstico de falhas; os
        // outros, no post-mortem comum.
        let _ = process_context::with_process(process_pointer, || {
            if !crate::ntos::ps::user::crash_report::process_exit(process_pointer, status) {
                crate::ntos::ps::user::process::post_mortem(process_pointer);
            }
        });
    }
    let previous = process::get_current_thread();
    let own_threads: alloc::vec::Vec<u64> = threads::of_process(process_pointer).iter().map(|thread| thread.pointer()).filter(|&pointer| pointer != 0).collect();
    if !own_threads.contains(&previous) {
        if let Some(&own) = own_threads.first() {
            process::set_current_thread(own);
        }
    }
    let _ = process::terminate_process(process_pointer, status);
    process::set_current_thread(previous);
    threads::release_process(process_pointer);
    threads::end_exit(process_pointer);
}

/// O status de saída de um processo que falhou depois de criado.
pub fn failure_status(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_UNSUCCESSFUL }
}

/// Arquivo do volume como fonte da seção de imagem e das notificações.
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
    fn volume(&self) -> Option<&'static dyn crate::drivers::fs::volume::FileSystem> {
        crate::drivers::fs::volume_files::fixed_volume().map(|fixed| fixed as &'static dyn crate::drivers::fs::volume::FileSystem)
    }
    fn volume_path(&self) -> Option<String> {
        Some(self.file.volume_path())
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

/// O arquivo do executável aberto pela criação: o volume e o acesso
/// concedido.
#[derive(Clone)]
pub struct ImageFile {
    pub file: Arc<VolumeFile>,
    pub access: u32,
}

/// O acesso da abertura do executável (o IoCreateFileEx do
/// NtCreateUserProcess, com FILE_SHARE_READ | FILE_SHARE_DELETE):
/// SYNCHRONIZE | FILE_EXECUTE | AdditionalFileAccess; recusada com o acesso
/// adicional, de novo só com SYNCHRONIZE | FILE_EXECUTE. A recusa final é
/// PsCreateFailOnFileOpen com o status dela.
fn image_file_access(file: &VolumeFile, additional: u32) -> Result<u32, CreateFailure> {
    let sharing = |access: u32| file_io::sharing_status(file, access, IMAGE_FILE_SHARE).map_err(CreateFailure::Other);
    let requested = IMAGE_FILE_ACCESS | additional;
    let status = sharing(requested)?;
    if status == 0 {
        return Ok(requested);
    }
    if additional == 0 {
        return Err(CreateFailure::FileOpen(status));
    }
    match sharing(IMAGE_FILE_ACCESS)? {
        0 => Ok(IMAGE_FILE_ACCESS),
        status => Err(CreateFailure::FileOpen(status)),
    }
}

/// A imagem principal: a fonte do carregador de PE, a da seção de imagem do
/// processo (e das notificações) e, para um arquivo do volume, a abertura
/// dele com `additional_access` somado ao mínimo.
fn open_image(image: &ImageOrigin, image_name: &str, additional_access: u32) -> Result<(Arc<dyn ImageSource>, Arc<dyn FileSource>, Option<ImageFile>), CreateFailure> {
    let file = match image {
        ImageOrigin::Bytes(bytes) => {
            let source: Arc<dyn FileSource> = Arc::new(BytesSource { name: format!("\\BootBundle\\apps\\{image_name}"), bytes: Arc::new(bytes.clone()) });
            return Ok((Arc::new(MemorySource { name: String::new(), bytes: bytes.clone() }), source, None));
        }
        ImageOrigin::Volume(file) => file.clone(),
        ImageOrigin::NtPath(path) => {
            let file = volume_files::lookup_volume_file(path).ok_or(CreateFailure::FileOpen(STATUS_OBJECT_NAME_NOT_FOUND))?;
            if file.directory() {
                return Err(CreateFailure::FileOpen(STATUS_FILE_IS_A_DIRECTORY));
            }
            file
        }
    };
    let access = image_file_access(&file, additional_access)?;
    let name = crate::drivers::fs::ntfs::nt_path(&file.volume_path());
    Ok((Arc::new(VolumeImage { name: name.clone(), file: file.clone() }), Arc::new(VolumeSource { name, file: file.clone() }), Some(ImageFile { file, access })))
}

/// O PspLocateInPEManifest: o LdrResSearchResource(SectionBaseAddress,
/// {RT_MANIFEST, CREATEPROCESS_MANIFEST_RESOURCE_ID, 0}, 3, Flags 0x30: só o
/// módulo principal, o primeiro idioma) na imagem principal, mapeada no
/// processo corrente (o novo, anexado). Diretório, tipo, nome ou idioma
/// ausentes são "sem manifesto"; um tamanho acima de 32 bits é
/// STATUS_INVALID_IMAGE_FORMAT; outra falha da pesquisa é o status da
/// criação.
fn locate_manifest(image_base: u64) -> Result<Option<Manifest>, KernelError> {
    // O IdPath de três chaves, a VA e o SIZE_T de saída.
    let scratch = guest::alloc_bytes(0x28);
    if scratch == 0 {
        return Err(KernelError::with_status("PspLocateInPEManifest sem memoria", STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write64(scratch, RT_MANIFEST);
    guest::write64(scratch + 8, CREATEPROCESS_MANIFEST_RESOURCE_ID);
    guest::write64(scratch + 0x10, 0);
    let status = resource_find::search(image_base, scratch, 3, MANIFEST_SEARCH_FLAGS, scratch + 0x18, scratch + 0x20, 0, 0);
    let (address, size) = (guest::read64(scratch + 0x18), guest::read64(scratch + 0x20));
    guest::free_bytes(scratch);
    match status? {
        0 if size > u32::MAX as u64 => Err(KernelError::with_status("manifesto embutido maior que 4 GB", STATUS_INVALID_IMAGE_FORMAT)),
        0 => Ok(Some(Manifest { address, size: size as u32 })),
        STATUS_RESOURCE_DATA_NOT_FOUND | STATUS_RESOURCE_TYPE_NOT_FOUND | STATUS_RESOURCE_NAME_NOT_FOUND | STATUS_RESOURCE_LANG_NOT_FOUND => Ok(None),
        status => Err(KernelError::with_status(format!("manifesto embutido: pesquisa falhou com {status:#x}"), status)),
    }
}

/// A imagem no VAD do processo corrente (o processo em montagem, anexado).
fn push_image(base: u64, size: u64, name: &str) {
    memory::insert_region(Space::current(), RegionKind::ProcessImages, Arc::new(ImageRegion { base, size, name: String::from(name), file: None }));
}

/// A imagem principal no espaço do processo em montagem (o corrente,
/// anexado): mapeada na raiz dele e possuída por ele até o término (como a
/// vista da seção de imagem no VAD do NT), com EPROCESS.SectionBaseAddress
/// na base real. Devolve (entry, base, tamanho) e o
/// SECTION_IMAGE_INFORMATION.
fn map_main_image(process_pointer: u64, source: &Arc<dyn ImageSource>, options: &LoadOptions, name: &str) -> Result<((u64, u64, u64), [u8; INFORMATION_SIZE]), KernelError> {
    let Some(owner) = process_state::get(process_pointer) else { return Err(KernelError::new("imagem principal sem estado do processo")) };
    let image = pe_loader::load_from_source(source.clone(), options)?;
    let placed = (image.entry_point, image.image_base, image.size_of_image);
    let information = image.image_information;
    owner.adopt_image(image);
    // SAFETY: o EPROCESS em montagem, retido pelo chamador.
    unsafe { Eprocess::at(process_pointer) }.section_base_address.set(placed.1);
    push_image(placed.1, placed.2, name);
    Ok((placed, information))
}

/// A KTHREAD da primeira thread, com pilha de kernel própria.
fn create_main_thread(process_pointer: u64, thread_id: u64) -> Result<u64, KernelError> {
    process::create_kernel_thread(process_pointer, thread_id, true, 1, Some(kernel_stack::create(false)?))
}

/// As notificações de carga das imagens iniciais, no processo novo (o
/// corrente, anexado) e com o PID dele: o executável, com o FILE_OBJECT da
/// seção de imagem, e a ntdll.
fn notify_initial_images(process_pointer: u64, process_id: u64, image: Image, source: &Arc<dyn FileSource>, ntdll: &Module) -> Result<(), KernelError> {
    let file_object = process::image_section(process_pointer).and_then(section_objects::state).map_or(0, |state| state.image_file_object);
    image_notify::notify(image, &NotifyOptions { name: Some(String::from(source.name())), file_object, source: Some(source.clone()), process_id: Some(process_id), ..NotifyOptions::default() })?;
    let name = ntdll.notification_source.as_ref().map_or_else(|| ntdll.full_name.clone(), |source| String::from(source.name()));
    image_notify::notify(Image { image_base: ntdll.image_base, size_of_image: ntdll.size_of_image }, &NotifyOptions { name: Some(name), source: ntdll.notification_source.clone(), process_id: Some(process_id), ..NotifyOptions::default() })
}

/// O que a montagem anexada ao processo novo produz.
struct Built {
    thread_id: u64,
    peb: u64,
    parameters: u64,
    teb: u64,
    stack_top: u64,
    context: u64,
    entry_point: u64,
    image_base: u64,
    size_of_image: u64,
    image_information: [u8; INFORMATION_SIZE],
    manifest: Option<Manifest>,
    parameter_flags: u32,
}

/// A ntdll de sistema (o PspSystemDll), o apiset e o NLS prontos, e as
/// entradas da primeira thread: (ntdll, RtlUserThreadStart,
/// LdrInitializeThunk).
fn system_dll() -> Result<(Arc<Module>, u64, u64), KernelError> {
    loader::ensure_ntdll()?;
    loader::ensure_api_set_schema()?;
    loader::ensure_nls_data()?;
    loader::parse_api_set_schema()?;
    let ntdll = loader::ntdll_module().ok_or_else(|| KernelError::new("ntdll ausente"))?;
    let (start, initialize) = state::with(|state| {
        let export = |name: &str| state.ntdll_exports.as_ref().and_then(|exports| exports.get(name).copied()).unwrap_or(0);
        (export("RtlUserThreadStart"), export("LdrInitializeThunk"))
    });
    if start == 0 || initialize == 0 {
        return Err(KernelError::new("ntdll sem inicializacao de processo"));
    }
    Ok((ntdll, start, initialize))
}

/// Cria um processo de usuário sem executá-lo (os passos do cabeçalho do
/// módulo): o kernel entrega exe, ntdll, PEB, parâmetros, TEB e o CONTEXT
/// inicial; o loader nativo carrega as dependências pelas syscalls de
/// arquivo e seção quando ele rodar.
pub fn create_user_process(request: &CreateProcessRequest<'_>) -> Result<CreatedProcess, CreateFailure> {
    let image_request = request.image_request;
    let (image_source, source, image_file) = open_image(&request.image, request.image_name, image_request.additional_file_access)?;
    // O processo (e o espaço dele) nasce antes de a imagem ser mapeada nele:
    // o cabeçalho dá a base preferida e o tamanho.
    let layout = pe_loader::image_layout(image_source.as_ref()).map_err(|error| CreateFailure::ExeFormat(error, 0))?;
    // O PspAllocateProcess recusa, antes de o processo existir, a imagem com
    // uma característica que o pedido proíbe (o kernel32 proíbe
    // IMAGE_FILE_DLL).
    let prohibited = layout.characteristics & image_request.prohibited_characteristics;
    if prohibited != 0 {
        return Err(CreateFailure::ExeFormat(KernelError::with_status(format!("caracteristicas {prohibited:#x} proibidas pelo pedido"), STATUS_INVALID_IMAGE_FORMAT), layout.dll_characteristics));
    }
    let (preferred_base, size_of_image) = (layout.preferred_base, layout.size_of_image);
    let (ntdll, start, initialize) = system_dll().map_err(CreateFailure::Other)?;
    let parameters = &request.parameters;
    let executable = Executable { source: source.clone(), image_size: size_of_image, image_information: None, command_line: Some(parameters.command_line.clone()) };
    // PspAllocateProcess: o PID sai da tabela de ids de cliente e o processo
    // ganha a raiz própria; o caminho da imagem fica no estado do processo.
    let process_pointer = process::create_process(cid::ALLOCATE, request.image_name, preferred_base, Some(&executable)).map_err(CreateFailure::Other)?;
    // SAFETY: EPROCESS recém-criado, retido até o término.
    let process_id = unsafe { Eprocess::at(process_pointer) }.unique_process_id.get();
    if let Some(identity) = process_state::get(process_pointer) {
        identity.set_image_path(&parameters.image_path_name);
    }
    if let Some(parent) = request.parent {
        process::set_parent(process_pointer, parent);
    }
    // EPROCESS.Protection, como no PspAllocateProcess: antes da PEB, que
    // herda dele as marcas de processo protegido.
    // SAFETY: EPROCESS recém-criado, retido até o término.
    unsafe { Eprocess::at(process_pointer) }.protection.level.set(request.protection);
    // Daqui em diante toda saída passa pelo término, que libera o que o
    // processo possui.
    let fail = |error: KernelError| -> CreateFailure {
        let status = failure_status(&error);
        crate::debug_print!("[ps] criacao de {} falhou: {}", request.image_name, error);
        exit_process(process_pointer, status);
        CreateFailure::Terminated(status)
    };
    // ObInitProcess: a herança de handles do pai, antes de o processo novo
    // ter qualquer thread.
    if let Some(parent) = request.inherit_handles_from {
        process_state::inherit_handles(parent, process_pointer).map_err(fail)?;
    }
    // A sessão, antes da PEB (que recebe o SessionId): uma nova com
    // PROCESS_CREATE_FLAGS_CREATE_SESSION (o MiSessionCreate do
    // MiMapProcessExecutable); a do token do PS_ATTRIBUTE_TOKEN quando ela
    // não é a de quem cria (o PspAttachSession do PspAllocateProcess; o
    // NtCreateUserProcess já exigiu o SeAssignPrimaryTokenPrivilege);
    // senão a do pai declarado ou de quem cria.
    let token_session = request.primary_token.map(|token| crate::ntos::se::token::tokens::with(token, |record| record.session_id).unwrap_or(0)).filter(|&session| session != crate::ntos::mm::session::session_id_ex(process::get_current_process()));
    if request.create_session {
        crate::ntos::mm::session::create(process_pointer).map_err(fail)?;
    } else if let Some(session) = token_session {
        crate::ntos::mm::session::join_id(process_pointer, session).map_err(fail)?;
    } else {
        crate::ntos::mm::session::join(process_pointer, request.parent.unwrap_or_else(process::get_current_process));
    }
    // PspInitializeProcessSecurity: o token primário é o SeSubProcessToken
    // do token pedido ou, sem ele, do primário do pai declarado (ou de quem
    // cria), com o SessionId da sessão do processo.
    let token_source = request.primary_token.or_else(|| process::get_primary_token(request.parent.unwrap_or_else(process::get_current_process)));
    if let Some(token) = token_source {
        let session_id = crate::ntos::mm::session::session_id(process_pointer);
        process::replace_primary_token(process_pointer, token, session_id).map_err(fail)?;
    }
    // O espaço do processo novo, anexado: as cópias de sistema, o exe na
    // raiz dele (a ntdll real faz o binding, a relocação e o cookie de
    // segurança: o LdrInitSecurityCookie recusa um cookie que não seja o do
    // link), a ntdll e o exe no VAD, a pilha da primeira thread, a PEB, os
    // parâmetros, a TEB e o CONTEXT inicial. O TID da primeira thread sai da
    // mesma tabela dos PIDs, reservado antes porque a TEB o recebe antes de a
    // thread existir.
    let load_options = LoadOptions { user_space: true, skip_imports: true, skip_relocations: true, skip_security_cookie: true, notify_image: false, ..LoadOptions::default() };
    let built = cid::allocate(cid::Kind::Thread).and_then(|thread_id| {
        process_context::with_process(process_pointer, || -> Result<Built, KernelError> {
            loader::map_system_images()?;
            let ((entry_point, image_base, size_of_image), image_information) = map_main_image(process_pointer, &image_source, &load_options, &parameters.image_path_name)?;
            push_image(ntdll.image_base, ntdll.size_of_image, &ntdll.full_name);
            // A entrada vê o rsp "depois de um call" (8 mod 16) com endereço
            // de retorno 0, para falhar alto se o programa retornar.
            let (stack_limit, stack_base) = memory::map_user_stack()?;
            let stack_top = stack_base - 8;
            let peb = peb_teb::create_peb(process_pointer, image_base)?;
            loader::create_kernel_ldr()?;
            // O PspLocateInPEManifest do PspSetupUserProcessAddressSpace,
            // antes da cópia dos parâmetros: o manifesto achado liga
            // RTL_USER_PROC_APP_MANIFEST_PRESENT no bloco.
            let manifest = if image_request.detect_manifest { locate_manifest(image_base)? } else { None };
            let parameter_flags = if manifest.is_some() { APP_MANIFEST_PRESENT } else { 0 };
            let block = parameters.write(parameter_flags)?;
            // SAFETY: a PEB recém-criada no processo corrente.
            unsafe { Peb::at(peb) }.process_parameters.set(block);
            let teb = peb_teb::create_teb(&TebDescription { process_id, thread_id, peb, stack_base, stack_limit })?;
            let context = memory::map_user_region(threads::CONTEXT_SIZE)?;
            threads::initialize_context(context, start, stack_top, entry_point, peb);
            Ok(Built { thread_id, peb, parameters: block, teb, stack_top, context, entry_point, image_base, size_of_image, image_information, manifest, parameter_flags })
        })
        .and_then(|built| built)
        .inspect_err(|_| cid::release(thread_id, 0))
    });
    // PspAllocateThread: a KTHREAD com o TID reservado.
    let created = built.and_then(|built| {
        let thread_id = built.thread_id;
        create_main_thread(process_pointer, thread_id).map(|thread| (built, thread)).inspect_err(|_| cid::release(thread_id, 0))
    });
    let (built, thread_pointer) = created.map_err(fail)?;
    // A seção de imagem do processo guarda o SECTION_IMAGE_INFORMATION da
    // imagem principal (a ProcessImageInformation).
    if let Some(section) = process::image_section(process_pointer) {
        section_objects::set_image_information(section, built.image_information.to_vec());
    }
    // A thread principal entra na lista do processo (e no índice global),
    // suspensa se o pedido manda: o registro no despacho respeita a contagem.
    let main = UserThread::new(built.thread_id, thread_pointer, built.teb, built.entry_point);
    main.with(|thread| {
        thread.suspend_count = u32::from(request.thread_flags & THREAD_CREATE_SUSPENDED != 0);
        thread.hidden = request.thread_flags & THREAD_HIDE_FROM_DEBUGGER != 0;
    });
    threads::push(main.clone());
    process::set_thread_start(thread_pointer, built.entry_point);
    // PspInsertThread: a notificação de thread no contexto de quem cria (a
    // de processo veio com a primeira KTHREAD) e as de imagem anexadas ao
    // processo novo.
    process::notify_thread_created(thread_pointer).map_err(fail)?;
    let image = Image { image_base: built.image_base, size_of_image: built.size_of_image };
    process_context::with_process(process_pointer, || notify_initial_images(process_pointer, process_id, image, &source, &ntdll)).and_then(|notified| notified).map_err(fail)?;
    // PspInsertProcess: o processo está inserido (EPROCESS.Flags.ProcessInserted).
    // SAFETY: EPROCESS recém-criado, retido até o término.
    unsafe { Eprocess::at(process_pointer) }.flags.atomic().fetch_or(Eprocess::PROCESS_INSERTED_MASK, core::sync::atomic::Ordering::SeqCst);
    if let Some(on_created) = request.on_created {
        on_created(process_id).map_err(fail)?;
    }
    Ok(CreatedProcess {
        process_pointer,
        process_id,
        thread_pointer,
        thread_id: built.thread_id,
        thread: main,
        peb: built.peb,
        teb: built.teb,
        parameters: built.parameters,
        stack_top: built.stack_top,
        image_base: built.image_base,
        entry_point: built.entry_point,
        size_of_image: built.size_of_image,
        image_information: built.image_information,
        manifest: built.manifest,
        parameter_flags: built.parameter_flags,
        image_file,
        context: built.context,
        initialize,
        ntdll_base: ntdll.image_base,
        image_name: String::from(request.image_name),
        pending: true,
    })
}
