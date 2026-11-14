//! Integridade de código.
//!
//! Inicializa a ci.dll original e entrega ao carregador uma decisão real de
//! assinatura. O bootstrap já carregado é a raiz deste ambiente; novas
//! imagens de kernel passam pelo validador antes de imports, relocação e
//! execução.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::mm::section::{map_system_view, handles as section_handles};
use crate::ntos::ps::process;
use crate::ntos::ps::user::sections::{self, Section, SectionFile, View};
use crate::ntos::se::code_integrity_information;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{Field, FileObject, IoStatusBlock, NtStruct, ObjectAttributes, Reserved, UnicodeString};
use core::mem::offset_of;

/// Tabela SeCiCallbacks que o CiInitialize preenche (0xE8 bytes no 19041).
/// Contrato entre o kernel e a ci.dll, sem tipo nos símbolos públicos: só os
/// campos que o OpenNT usa têm nome.
#[repr(C)]
struct CiCallbacks {
    /// Tamanho da tabela, informado pelo kernel.
    size: Field<u32>,
    _reserved_04: Reserved<0x14>,
    /// CiQueryInformation (SystemCodeIntegrityInformation).
    query_information: Field<u64>,
    /// CiValidateImageHeader.
    validate_image_header: Field<u64>,
    _reserved_28: Reserved<0x38>,
    /// CiInitializePolicy.
    initialize_policy: Field<u64>,
    _reserved_68: Reserved<0x8>,
    /// Nível de assinatura exigido: precisa ficar NULL neste contrato.
    required_signing_level: Field<u64>,
    _reserved_78: Reserved<0x68>,
    /// Versão/flags do contrato, informados pelo kernel.
    kernel_version: Field<u64>,
}

/// Provedores privados do kernel entregues ao CiInitialize (só os slots
/// reais publicados; os ausentes ficam NULL).
#[repr(C)]
struct CiPrivateCallbacks {
    _reserved_00: Reserved<0x20>,
    /// SepSetRuntimeUpdatableSigningLevel.
    set_runtime_signing_level: Field<u64>,
    _reserved_28: Reserved<0x8>,
    /// MmGetImageFileSignatureInformation.
    image_file_signature: Field<u64>,
    _reserved_38: Reserved<0x8>,
}

/// Saídas do CiValidateImageHeader.
#[repr(C)]
struct CiValidation {
    validation_mode: Field<u32>,
    _reserved_04: Reserved<0x4>,
    signature_context: Field<u64>,
    signing_level: Field<u8>,
    _reserved_11: Reserved<0x7>,
    image_flags: Field<u32>,
    _reserved_1c: Reserved<0xC>,
    verification_flags: Field<u32>,
    _reserved_2c: Reserved<0x4>,
}

/// Locais da abertura da imagem (substituem a pilha nativa): atributos,
/// nome, handles, IO_STATUS_BLOCK e as saídas da CI; o texto do caminho
/// segue a estrutura.
#[repr(C)]
struct ImageRequest {
    attributes: ObjectAttributes,
    name: UnicodeString,
    file_handle: Field<u64>,
    section_handle: Field<u64>,
    io_status: IoStatusBlock,
    _reserved_60: Reserved<0x10>,
    validation: CiValidation,
    _reserved_a0: Reserved<0x60>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CiCallbacks {}
unsafe impl NtStruct for CiPrivateCallbacks {}
unsafe impl NtStruct for CiValidation {}
unsafe impl NtStruct for ImageRequest {}

const _: () = {
    assert!(core::mem::size_of::<CiCallbacks>() == 0xE8);
    assert!(offset_of!(CiCallbacks, query_information) == 0x18);
    assert!(offset_of!(CiCallbacks, validate_image_header) == 0x20);
    assert!(offset_of!(CiCallbacks, initialize_policy) == 0x60);
    assert!(offset_of!(CiCallbacks, required_signing_level) == 0x70);
    assert!(offset_of!(CiCallbacks, kernel_version) == 0xE0);
    assert!(core::mem::size_of::<CiPrivateCallbacks>() == 0x40);
    assert!(offset_of!(CiPrivateCallbacks, set_runtime_signing_level) == 0x20);
    assert!(offset_of!(CiPrivateCallbacks, image_file_signature) == 0x30);
    assert!(core::mem::size_of::<CiValidation>() == 0x30);
    assert!(offset_of!(CiValidation, signature_context) == 0x8);
    assert!(offset_of!(CiValidation, signing_level) == 0x10);
    assert!(offset_of!(CiValidation, image_flags) == 0x18);
    assert!(offset_of!(CiValidation, verification_flags) == 0x28);
    assert!(offset_of!(ImageRequest, name) == 0x30);
    assert!(offset_of!(ImageRequest, file_handle) == 0x40);
    assert!(offset_of!(ImageRequest, io_status) == 0x50);
    assert!(offset_of!(ImageRequest, validation) == 0x70);
    assert!(core::mem::size_of::<ImageRequest>() == 0x100);
};

fn request_at(storage: u64) -> &'static ImageRequest {
    // SAFETY: bloco próprio alocado por `open_image`, vivo até `release`.
    unsafe { ImageRequest::at(storage) }
}
use crate::ntos::mm::sysload::kernel_image_source::ImageSource;
use crate::ntos::mm::sysload::{self, Acquired};
use crate::ntos::init::exports;
use crate::ntos::mm::pe_loader::{self, CodeIntegrity, LoadOptions, Validation};
use crate::ntos::init::exports::private_routines;

/// A imagem e a tabela permanecem vivas enquanto os callbacks forem
/// publicados.
struct State {
    initialization: Option<Acquired>,
    callbacks: u64,
    failure: Option<KernelError>,
    /// A CI devolveu contexto por página: a posse fica retida e novas cargas
    /// são bloqueadas até esse contrato existir.
    quarantined: bool,
}

static STATE: SpinLock<State> = SpinLock::new(State { initialization: None, callbacks: 0, failure: None, quarantined: false });
/// Consulta de informação da CI (callback 0x18).
static INFORMATION: AtomicU64 = AtomicU64::new(0);

fn failure(message: &str, status: u32) -> KernelError {
    KernelError::with_status(format!("{message}: 0x{status:x}"), status)
}

fn allocate(length: u64) -> Result<u64, KernelError> {
    let pointer = guest::alloc_bytes(length);
    if pointer == 0 {
        return Err(failure("CI allocation failed", 0xC000_009A));
    }
    guest::write_bytes(pointer, &alloc::vec![0u8; length as usize]);
    Ok(pointer)
}

/// Cada chamada tem frame próprio, inclusive quando a CI chama o kernel de
/// volta.
fn invoke(address: u64, arguments: &[u64]) -> u32 {
    native_call::call(address, arguments) as u32
}

/// Callback publicado pela CI, que precisa morar dentro da imagem dela.
fn callback(slot: fn(&CiCallbacks) -> &Field<u64>) -> Result<u64, KernelError> {
    let (callbacks, base, size) = {
        let state = STATE.lock();
        let (base, size) = state.initialization.as_ref().map_or((0, 0), |library| (library.image_base, library.size_of_image));
        (state.callbacks, base, size)
    };
    let (address, offset) = if callbacks == 0 {
        (0, 0)
    } else {
        // SAFETY: tabela própria de 0xE8 bytes, viva enquanto a CI estiver carregada.
        let table = unsafe { CiCallbacks::at(callbacks) };
        let field = slot(table);
        (field.get(), field.address() - callbacks)
    };
    if address < base || address >= base + size {
        return Err(failure(&format!("CI callback absent at {offset:x}"), 0xC000_007A));
    }
    Ok(address)
}

fn require_success(status: u32, operation: &str) -> Result<(), KernelError> {
    if status & 0x8000_0000 != 0 {
        return Err(failure(operation, status));
    }
    Ok(())
}

fn close_handle(handle: u64) -> Result<(), KernelError> {
    if handle == 0 {
        return Ok(());
    }
    require_success(exports::invoke_handler("ZwClose", &[handle])? as u32, "CI close handle")
}

/// Arquivo da imagem aberto sem escrita nem exclusão durante a validação e
/// a cópia; a SECTION mantém o FILE_OBJECT real sem executar a imagem.
struct Request {
    storage: u64,
    file_handle: u64,
    section_handle: u64,
    reference: Option<section_handles::Reference>,
    view: Option<Arc<View>>,
    section: Option<Arc<Section>>,
}

impl Request {
    fn release(&mut self) -> Result<(), KernelError> {
        if let Some(view) = self.view.take() {
            sections::unmap(&view, None)?;
        }
        if let Some(reference) = self.reference.take() {
            reference.release()?;
        }
        self.section = None;
        close_handle(core::mem::take(&mut self.section_handle))?;
        close_handle(core::mem::take(&mut self.file_handle))?;
        if self.storage != 0 {
            guest::free_bytes(core::mem::take(&mut self.storage));
        }
        Ok(())
    }
}

fn open_image(name: &str) -> Result<Request, KernelError> {
    let units: Vec<u16> = name.encode_utf16().collect();
    if !name.starts_with('\\') || units.len() > 1024 {
        return Err(failure("CI requires an owned kernel image path", 0xC000_0033));
    }
    let storage = allocate(ImageRequest::SIZE + ((units.len() as u64 + 1) * 2).div_ceil(8) * 8)?;
    let mut request = Request { storage, file_handle: 0, section_handle: 0, reference: None, view: None, section: None };
    let opened = (|| -> Result<(), KernelError> {
        let locals = request_at(storage);
        let text = storage + ImageRequest::SIZE;
        locals.attributes.length.set(ObjectAttributes::SIZE as u32);
        locals.attributes.object_name.set(locals.name.address());
        locals.attributes.attributes.set(0x240);
        locals.name.length.set(units.len() as u16 * 2);
        locals.name.maximum_length.set((units.len() as u16 + 1) * 2);
        locals.name.buffer.set(text);
        guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        let status = exports::invoke_handler("ZwOpenFile", &[locals.file_handle.address(), 0x8000_0020, locals.attributes.address(), locals.io_status.address(), 1, 0])? as u32;
        require_success(status, "CI open image")?;
        request.file_handle = locals.file_handle.get();
        let status = exports::invoke_handler("ZwCreateSection", &[locals.section_handle.address(), 0xF001F, 0, 0, 0x10, 0x100_0000, request.file_handle])? as u32;
        require_success(status, "CI create image section")?;
        request.section_handle = locals.section_handle.get();
        let reference = section_handles::reference(request.section_handle, section_handles::Kind::Section, 4, 0).map_err(|status| failure("CI reference image section", status))?;
        let section = reference.section.clone();
        request.reference = Some(reference);
        let section = section.ok_or_else(|| failure("CI section missing", 0xC000_0008))?;
        let view = map_system_view::insert(&section, section.size, 0, 1)?.map_err(|status| failure("CI map image section", status))?;
        request.view = Some(view);
        request.section = Some(section);
        Ok(())
    })();
    if let Err(error) = opened {
        let _ = request.release();
        return Err(error);
    }
    Ok(request)
}

/// O leitor do mesmo arquivo retido, e não uma segunda abertura por nome.
struct SectionSource {
    name: String,
    file: Arc<dyn SectionFile>,
}

impl ImageSource for SectionSource {
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
        self.file.has_copy_to_physical()
    }
    fn copy_to_physical(&self, offset: u64, address: u64, length: u64) -> Option<Result<(), KernelError>> {
        self.file.has_copy_to_physical().then(|| self.file.copy_to_physical(offset, address, length))
    }
}

/// Validador do carregador de imagens de kernel: a CI decide sobre o
/// arquivo aberto; o lease segue vivo até o fim da cópia e dos imports.
fn validate_kernel_image(source: &Arc<dyn ImageSource>, options: &LoadOptions) -> Result<Validation, KernelError> {
    {
        let state = STATE.lock();
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if state.quarantined {
            return Err(failure("CI page-validation contract pending", 0xC000_00BB));
        }
    }
    let name = options.image_name.clone().unwrap_or_else(|| String::from(source.name()));
    let mut request = open_image(&name)?;
    let outcome = (|| -> Result<(CodeIntegrity, Arc<dyn SectionFile>), KernelError> {
        let section = request.section.clone().ok_or_else(|| failure("CI section missing", 0xC000_0008))?;
        let view = request.view.clone().ok_or_else(|| failure("CI view missing", 0xC000_0008))?;
        let file = section.file.clone().ok_or_else(|| failure("CI section without file", 0xC000_0008))?;
        let outputs = &request_at(request.storage).validation;
        outputs.validation_mode.set(2);
        outputs.signing_level.set(1);
        let image_file_object = section.state.lock().image_file_object;
        // A ci.dll lê FileObject->SectionObjectPointer->ImageSectionObject
        // (ao registrar uma recusa) sem conferir: como o MmCreateSection, um
        // arquivo sem SECTION_OBJECT_POINTERS não serve de imagem.
        // SAFETY: o FILE_OBJECT da SECTION, retido por ela até o release.
        if image_file_object == 0 || unsafe { FileObject::at(image_file_object) }.section_object_pointer.get() == 0 {
            return Err(failure("CI image file without SectionObjectPointer", 0xC000_0020));
        }
        let arguments = [
            image_file_object,
            view.base,
            section.size,
            view.base,
            section.size,
            outputs.validation_mode.address(),
            process::get_current_process(),
            0,
            1,
            outputs.signature_context.address(),
            1,
            0,
            outputs.signing_level.address(),
            outputs.image_flags.address(),
            0,
            outputs.verification_flags.address(),
        ];
        debug_print!("[ci-loader] validating {} bytes={}", name, file.size());
        let status = invoke(callback(|table| &table.validate_image_header)?, &arguments);
        let result = CodeIntegrity { status, validation_mode: outputs.validation_mode.get(), signature_context: outputs.signature_context.get(), signing_level: outputs.signing_level.get() as u32 };
        let image_flags = outputs.image_flags.get();
        let verification_flags = outputs.verification_flags.get();
        debug_print!(
            "CI_KERNEL_IMAGE_RESULT name={} status=0x{:x} validationMode={} signatureContext=0x{:x} signingLevel={} imageFlags=0x{:x} verificationFlags=0x{:x} importsResolved=false relocationsApplied=false entryPointExecuted=false",
            name, status, result.validation_mode, result.signature_context, result.signing_level, image_flags, verification_flags
        );
        if result.signature_context != 0 {
            return Err(failure("CI returned a page-validation context", if status & 0x8000_0000 != 0 { status } else { 0xC000_00BB }));
        }
        require_success(status, &format!("CI rejected {name}"))?;
        if result.validation_mode != 2 {
            return Err(failure("CI requires another validation mode", 0xC000_00BB));
        }
        Ok((result, file))
    })();
    match outcome {
        Ok((result, file)) => {
            let source: Arc<dyn ImageSource> = Arc::new(SectionSource { name, file });
            let release = SendRequest(request);
            Ok(Validation { result, source, release: Box::new(move || release.release()) })
        }
        Err(error) => {
            if error.message.starts_with("CI returned a page-validation context") {
                // Um contexto por página exige outro contrato: a posse fica
                // retida, sem liberar memória que a CI ainda referencia.
                STATE.lock().quarantined = true;
                core::mem::forget(request);
            } else {
                let _ = request.release();
            }
            Err(error)
        }
    }
}

/// O pedido retido atravessa a liberação diferida do carregador; todo o
/// estado nele pertence ao kernel e é liberado uma vez.
struct SendRequest(Request);
unsafe impl Send for SendRequest {}

impl SendRequest {
    fn release(mut self) {
        if let Err(error) = self.0.release() {
            debug_print!("[ci-loader] liberacao falhou: {}", error);
        }
    }
}

/// SystemCodeIntegrityInformation pela consulta da própria CI. Como o
/// ExpQuerySystemInformation, o SeCodeIntegrityQueryInformation recebe o
/// ReturnLength numa variável local do kernel (a CI grava nele sem conferir
/// o ponteiro), copiada depois para o do chamador, que pode ser NULL.
fn query_information(buffer: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    let local = allocate(8)?;
    let status = invoke(INFORMATION.load(Ordering::SeqCst), &[buffer, length as u64, 0, local]);
    // SAFETY: a célula ULONG própria, recém-alocada.
    let written = unsafe { Field::<u32>::at(local) }.get();
    guest::free_bytes(local);
    if returned != 0 {
        guest::try_write::<u32>(returned, written)?;
    }
    Ok(status)
}

/// Carrega a ci.dll, chama o CiInitialize com os provedores privados reais,
/// inicializa a política e instala o validador de imagens de kernel. Uma
/// falha fica registrada e é devolvida nas chamadas seguintes.
pub fn initialize() -> Result<(), KernelError> {
    {
        let state = STATE.lock();
        if let Some(error) = &state.failure {
            return Err(error.clone());
        }
        if state.initialization.is_some() {
            return Ok(());
        }
    }
    let result = initialize_library();
    if let Err(error) = &result {
        STATE.lock().failure = Some(error.clone());
    }
    result
}

fn initialize_library() -> Result<(), KernelError> {
    let library = sysload::acquire("ci.dll")?;
    let entry = library.export("CiInitialize");
    let callbacks = allocate(CiCallbacks::SIZE)?;
    {
        let mut state = STATE.lock();
        state.initialization = Some(library);
        state.callbacks = callbacks;
    }
    let entry = entry.ok_or_else(|| failure("CiInitialize export absent", 0xC000_0139))?;
    let private_callbacks = allocate(CiPrivateCallbacks::SIZE)?;
    let policy_output = allocate(16)?;
    let result = (|| -> Result<(), KernelError> {
        // SAFETY: blocos próprios recém-alocados e zerados.
        let (table, private) = unsafe { (CiCallbacks::at(callbacks), CiPrivateCallbacks::at(private_callbacks)) };
        table.size.set(CiCallbacks::SIZE as u32);
        table.kernel_version.set(0xA00_0008);
        // Só provedores privados reais; os slots ausentes ficam NULL.
        let signing_policy = private_routines::address("SepSetRuntimeUpdatableSigningLevel");
        if signing_policy == 0 {
            return Err(failure("CI runtime signing provider absent", 0xC000_007A));
        }
        private.set_runtime_signing_level.set(signing_policy);
        let image_file_signature = private_routines::address("MmGetImageFileSignatureInformation");
        if image_file_signature == 0 {
            return Err(failure("CI image signature provider absent", 0xC000_007A));
        }
        private.image_file_signature.set(image_file_signature);
        let status = invoke(entry, &[6, 0, callbacks, private_callbacks]);
        debug_print!("CI_KERNEL_INITIALIZE status=0x{:x}", status);
        require_success(status, "CiInitialize")?;
        let policy_status = invoke(callback(|table| &table.initialize_policy)?, &[0, policy_output, policy_output + 8]);
        debug_print!("CI_KERNEL_POLICY status=0x{:x} elements={}", policy_status, guest::read32(policy_output + 8));
        require_success(policy_status, "CiInitializePolicy")?;
        if table.required_signing_level.get() != 0 {
            return Err(failure("CI required-signing-level contract changed", 0xC000_00BB));
        }
        callback(|table| &table.validate_image_header)?;
        INFORMATION.store(callback(|table| &table.query_information)?, Ordering::SeqCst);
        pe_loader::register_kernel_image_validator(validate_kernel_image)?;
        code_integrity_information::install_query(query_information)?;
        debug_print!("CI_KERNEL_ENFORCEMENT_READY scope=kernel-image-loads bootstrap=preloaded");
        Ok(())
    })();
    guest::free_bytes(policy_output);
    guest::free_bytes(private_callbacks);
    result
}
