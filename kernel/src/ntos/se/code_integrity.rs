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
fn callback(offset: u64) -> Result<u64, KernelError> {
    let (callbacks, base, size) = {
        let state = STATE.lock();
        let (base, size) = state.initialization.as_ref().map_or((0, 0), |library| (library.image_base, library.size_of_image));
        (state.callbacks, base, size)
    };
    let address = if callbacks == 0 { 0 } else { guest::read64(callbacks + offset) };
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
    let storage = allocate(256 + ((units.len() as u64 + 1) * 2).div_ceil(8) * 8)?;
    let mut request = Request { storage, file_handle: 0, section_handle: 0, reference: None, view: None, section: None };
    let opened = (|| -> Result<(), KernelError> {
        guest::write32(storage, 48);
        guest::write64(storage + 16, storage + 48);
        guest::write32(storage + 24, 0x240);
        guest::write16(storage + 48, units.len() as u16 * 2);
        guest::write16(storage + 50, (units.len() as u16 + 1) * 2);
        guest::write64(storage + 56, storage + 256);
        for (index, unit) in units.iter().enumerate() {
            guest::write16(storage + 256 + index as u64 * 2, *unit);
        }
        let status = exports::invoke_handler("ZwOpenFile", &[storage + 64, 0x8000_0020, storage, storage + 80, 1, 0])? as u32;
        require_success(status, "CI open image")?;
        request.file_handle = guest::read64(storage + 64);
        let status = exports::invoke_handler("ZwCreateSection", &[storage + 72, 0xF001F, 0, 0, 0x10, 0x100_0000, request.file_handle])? as u32;
        require_success(status, "CI create image section")?;
        request.section_handle = guest::read64(storage + 72);
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
        let outputs = request.storage + 112;
        guest::write32(outputs, 2);
        guest::write8(outputs + 16, 1);
        let image_file_object = section.state.lock().image_file_object;
        let arguments = [image_file_object, view.base, section.size, view.base, section.size, outputs, process::get_current_process(), 0, 1, outputs + 8, 1, 0, outputs + 16, outputs + 24, 0, outputs + 40];
        debug_print!("[ci-loader] validating {} bytes={}", name, file.size());
        let status = invoke(callback(0x20)?, &arguments);
        let result = CodeIntegrity { status, validation_mode: guest::read32(outputs), signature_context: guest::read64(outputs + 8), signing_level: guest::read8(outputs + 16) as u32 };
        let image_flags = guest::read32(outputs + 24);
        let verification_flags = guest::read32(outputs + 40);
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

/// SystemCodeIntegrityInformation pela consulta da própria CI.
fn query_information(buffer: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    Ok(invoke(INFORMATION.load(Ordering::SeqCst), &[buffer, length as u64, 0, returned]))
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
    let callbacks = allocate(0xE8)?;
    {
        let mut state = STATE.lock();
        state.initialization = Some(library);
        state.callbacks = callbacks;
    }
    let entry = entry.ok_or_else(|| failure("CiInitialize export absent", 0xC000_0139))?;
    let private_callbacks = allocate(64)?;
    let policy_output = allocate(16)?;
    let result = (|| -> Result<(), KernelError> {
        guest::write32(callbacks, 0xE8);
        guest::write64(callbacks + 0xE0, 0xA00_0008);
        // Só provedores privados reais; os slots ausentes ficam NULL.
        let signing_policy = private_routines::address("SepSetRuntimeUpdatableSigningLevel");
        if signing_policy == 0 {
            return Err(failure("CI runtime signing provider absent", 0xC000_007A));
        }
        guest::write64(private_callbacks + 32, signing_policy);
        let image_file_signature = private_routines::address("MmGetImageFileSignatureInformation");
        if image_file_signature == 0 {
            return Err(failure("CI image signature provider absent", 0xC000_007A));
        }
        guest::write64(private_callbacks + 48, image_file_signature);
        let status = invoke(entry, &[6, 0, callbacks, private_callbacks]);
        debug_print!("CI_KERNEL_INITIALIZE status=0x{:x}", status);
        require_success(status, "CiInitialize")?;
        let policy_status = invoke(callback(0x60)?, &[0, policy_output, policy_output + 8]);
        debug_print!("CI_KERNEL_POLICY status=0x{:x} elements={}", policy_status, guest::read32(policy_output + 8));
        require_success(policy_status, "CiInitializePolicy")?;
        if guest::read64(callbacks + 0x70) != 0 {
            return Err(failure("CI required-signing-level contract changed", 0xC000_00BB));
        }
        callback(0x20)?;
        INFORMATION.store(callback(0x18)?, Ordering::SeqCst);
        pe_loader::register_kernel_image_validator(validate_kernel_image)?;
        code_integrity_information::install_query(query_information)?;
        debug_print!("CI_KERNEL_ENFORCEMENT_READY scope=kernel-image-loads bootstrap=preloaded");
        Ok(())
    })();
    guest::free_bytes(policy_output);
    guest::free_bytes(private_callbacks);
    result
}
