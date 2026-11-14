//! O pedido de criação vindo do modo usuário: o corpo do NtCreateUserProcess.
//!
//! O papel do PspBuildCreateProcessContext e do NtCreateUserProcess do NT
//! sobre o caminho único de `ps/create.rs`. Tudo o que o chamador passa é
//! sondado e capturado da memória de usuário dele antes de agir (a criação
//! anexa ao processo novo e deixa de enxergar o chamador):
//!
//! - o PS_CREATE_INFO (`PsCreateInfo`, entrada e saída): Size 0x58 na
//!   entrada (InitFlags e AdditionalFileAccess não mudam nada aqui); na
//!   saída, PsCreateSuccess com a PEB e o bloco de parâmetros no processo
//!   novo, ou o estado da falha: PsCreateFailOnFileOpen (o status do open),
//!   PsCreateFailExeFormat (imagem que não é um PE aceito); outras falhas
//!   deixam o estado como veio;
//! - a PS_ATTRIBUTE_LIST (`PsAttributeList`): honra ImageName (o caminho NT
//!   da imagem, obrigatório), ParentProcess (handle com
//!   PROCESS_CREATE_PROCESS; o pai declarado vai para as notificações e para
//!   InheritedFromUniqueProcessId), PriorityClass e as saídas ClientId,
//!   TebAddress e ImageInfo (o SECTION_IMAGE_INFORMATION da imagem na base
//!   real) e ProtectionLevel (o PS_PROTECTION, com
//!   PROCESS_CREATE_FLAGS_PROTECTED_PROCESS); recusa com
//!   STATUS_NOT_SUPPORTED o que mudaria o processo sem suporte aqui
//!   (DebugObject, Token, SecureProcess, JobList, UmsThread); aceita sem
//!   efeito, com registro no log, os demais
//!   que o kernel32 passa (StdHandleInfo, HandleList, ErrorMode, afinidade,
//!   mitigações e políticas); um número desconhecido, um atributo repetido,
//!   um tamanho errado ou os bits de thread/entrada trocados num atributo
//!   honrado dão STATUS_INVALID_PARAMETER;
//! - o RTL_USER_PROCESS_PARAMETERS, normalizado ou não
//!   (`process_parameters::capture`);
//! - os OBJECT_ATTRIBUTES de processo e thread (sem nome; OBJ_INHERIT vai
//!   para o handle) e as flags: PROCESS_CREATE_FLAGS_* conhecidas são
//!   aceitas, as que pedem um processo diferente (suspenso inteiro, mínimo,
//!   sessão nova, espaço de outro) dão STATUS_NOT_SUPPORTED;
//!   PROTECTED_PROCESS cria o processo com o PS_PROTECTION do atributo
//!   ProtectionLevel (sem ele, STATUS_NOT_SUPPORTED: o processo protegido
//!   legado não existe aqui): quem cria (o pai declarado ou quem chama)
//!   precisa ser protegido (senão STATUS_ACCESS_DENIED, como no
//!   NtCreateUserProcess 19041) e dominar o pedido, com tipo e signatário
//!   pelo menos iguais (a regra do RtlTestProtectedAccess; senão
//!   STATUS_INVALID_PARAMETER); com INHERIT_HANDLES o processo novo recebe, com
//!   os mesmos valores, os handles OBJ_INHERIT do pai declarado
//!   (ParentProcess) ou, sem ele, de quem chama;
//!   THREAD_CREATE_FLAGS_CREATE_SUSPENDED cria a thread principal suspensa.
//!
//! Depois: `create::create_user_process` cria o processo e a thread
//! principal, o processo entra no despachante
//! (`ps/user/process.rs::start_created`; a thread suspensa só anda depois do
//! NtResumeThread), os handles do processo e da thread entram na tabela de
//! QUEM CHAMOU com o acesso pedido (os direitos genéricos mapeados e
//! MAXIMUM_ALLOWED como o acesso total do tipo, o que o criador recebe), e as
//! saídas (handles, CLIENT_ID, TEB, SECTION_IMAGE_INFORMATION e o
//! PS_CREATE_INFO) vão para as VAs já sondadas. Uma falha antes da criação
//! não cria nada; uma falha ao abrir os handles termina o processo novo.
//! FileHandle e SectionHandle do PsCreateSuccess ficam NULL (o chamador só
//! os fecha quando vêm preenchidos).

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ClientId, Eprocess, ObjectAttributes, PsAttribute, PsAttributeList, PsCreateInfo, SectionImageInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_access, object_types};
use crate::ntos::ps::create::{self, CreateFailure, CreateProcessRequest, ImageOrigin};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::{self, ProcessParameters};
use crate::ntos::ps::user::handles::{self, UserProcess};
use crate::ntos::ps::user::process as user_process;
use crate::ntos::ps::user::{state, threads};
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// PROCESS_CREATE_PROCESS: o direito que o handle do pai declarado precisa.
const PROCESS_CREATE_PROCESS: u32 = 0x80;
/// OBJ_INHERIT: o único atributo de OBJECT_ATTRIBUTES que vai para o handle.
const OBJ_INHERIT: u32 = 2;
/// PROCESS_CREATE_FLAGS_* conhecidas: BREAKAWAY, NO_DEBUG_INHERIT,
/// INHERIT_HANDLES, OVERRIDE_ADDRESS_SPACE, LARGE_PAGES,
/// LARGE_PAGE_SYSTEM_DLL, PROTECTED_PROCESS, CREATE_SESSION,
/// INHERIT_FROM_PARENT, SUSPENDED, FORCE_BREAKAWAY, MINIMAL_PROCESS,
/// RELEASE_SECTION, CLONE_MINIMAL, CLONE_MINIMAL_REDUCED_COMMIT,
/// AUXILIARY_PROCESS, CREATE_STORE e USE_PROTECTED_ENVIRONMENT.
const PROCESS_FLAGS_KNOWN: u32 = 0x0006_FFFF;
/// As que pedem um processo diferente, sem suporte aqui:
/// OVERRIDE_ADDRESS_SPACE, SUSPENDED, MINIMAL_PROCESS, CLONE_MINIMAL,
/// CLONE_MINIMAL_REDUCED_COMMIT, AUXILIARY_PROCESS e CREATE_STORE.
const PROCESS_FLAGS_UNSUPPORTED: u32 = 0x0002_EA08;
/// PROCESS_CREATE_FLAGS_CREATE_SESSION: o processo novo abre uma sessão
/// (o bit que o MiMapProcessExecutable do NT testa para o MiSessionCreate).
const PROCESS_CREATE_SESSION: u32 = 0x80;
/// PROCESS_CREATE_FLAGS_PROTECTED_PROCESS.
const PROCESS_PROTECTED: u32 = 0x40;
/// PS_PROTECTION: o maior tipo (PsProtectedTypeProtected) e o maior
/// signatário (PsProtectedSignerApp).
const PROTECTION_TYPE_MAX: u8 = 2;
const PROTECTION_SIGNER_MAX: u8 = 8;
/// PROCESS_CREATE_FLAGS_INHERIT_HANDLES.
const PROCESS_INHERIT_HANDLES: u32 = 0x4;
/// THREAD_CREATE_FLAGS_* aceitas (as mesmas do NtCreateThreadEx).
const THREAD_FLAGS_KNOWN: u32 = 0x77;
/// Entradas de uma PS_ATTRIBUTE_LIST.
const MAXIMUM_ATTRIBUTES: u64 = 64;
/// O maior PROCESS_PRIORITY_CLASS_* (ABOVE_NORMAL).
const MAXIMUM_PRIORITY_CLASS: u64 = 6;

/// `PsAttributeValue(número, thread, entrada, aditivo)`: o número nos 16
/// bits baixos e as três marcas acima.
mod attribute {
    pub const NUMBER: u64 = 0xFFFF;
    pub const THREAD: u64 = 0x1_0000;
    pub const INPUT: u64 = 0x2_0000;
    pub const ADDITIVE: u64 = 0x4_0000;

    /// `PS_ATTRIBUTE_NUM`.
    pub const PARENT_PROCESS: u64 = 0;
    pub const DEBUG_OBJECT: u64 = 1;
    pub const TOKEN: u64 = 2;
    pub const CLIENT_ID: u64 = 3;
    pub const TEB_ADDRESS: u64 = 4;
    pub const IMAGE_NAME: u64 = 5;
    pub const IMAGE_INFO: u64 = 6;
    pub const PRIORITY_CLASS: u64 = 8;
    pub const UMS_THREAD: u64 = 15;
    pub const PROTECTION_LEVEL: u64 = 17;
    pub const SECURE_PROCESS: u64 = 18;
    pub const JOB_LIST: u64 = 19;
    /// O último número conhecido (EnableOptionalXStateFeatures).
    pub const LAST: u64 = 30;
}

/// Os argumentos do NtCreateUserProcess, como vieram do chamador.
pub struct UserCreateRequest {
    pub process_handle: u64,
    pub thread_handle: u64,
    pub process_access: u32,
    pub thread_access: u32,
    pub process_attributes: u64,
    pub thread_attributes: u64,
    pub process_flags: u32,
    pub thread_flags: u32,
    pub parameters: u64,
    pub create_info: u64,
    pub attribute_list: u64,
}

/// Uma saída da lista de atributos: onde escrever e o PSIZE_T opcional.
#[derive(Clone, Copy)]
struct Output {
    value: u64,
    return_length: u64,
}

/// A lista de atributos capturada.
#[derive(Default)]
struct Attributes {
    image_name: Option<String>,
    parent: Option<u64>,
    priority_class: Option<u8>,
    client_id: Option<Output>,
    teb_address: Option<Output>,
    image_info: Option<Output>,
    /// PS_PROTECTION pedido (PsAttributeProtectionLevel).
    protection: Option<u8>,
}

/// O NTSTATUS de um erro de sonda ou de criação.
fn status_of(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_ACCESS_VIOLATION }
}

/// O PS_CREATE_INFO de entrada: gravável inteiro e com o Size do tipo.
fn capture_create_info(address: u64) -> Result<(), u32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !state::probe_user_write(address, PsCreateInfo::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let info = state::user_struct::<PsCreateInfo>(address).map_err(|error| status_of(&error))?;
    if info.size.probe_get().map_err(|error| status_of(&error))? != PsCreateInfo::SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(())
}

/// Os OBJECT_ATTRIBUTES de processo ou de thread (opcionais): sem nome; o
/// OBJ_INHERIT vira o atributo do handle.
fn capture_object_attributes(address: u64) -> Result<u32, u32> {
    if address == 0 {
        return Ok(0);
    }
    if !state::probe_user_read(address, ObjectAttributes::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let read = || -> Result<(u32, u64, u32), KernelError> {
        let attributes = state::user_struct::<ObjectAttributes>(address)?;
        Ok((attributes.length.probe_get()?, attributes.object_name.probe_get()?, attributes.attributes.probe_get()?))
    };
    let (length, name, attributes) = read().map_err(|error| status_of(&error))?;
    if length as u64 != ObjectAttributes::SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Processos e threads não têm nome.
    if name != 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    Ok(attributes & OBJ_INHERIT)
}

/// Uma saída de tamanho `size` em `value` (e o PSIZE_T, se veio), sondadas
/// para escrita.
fn output(value: u64, return_length: u64, size: u64) -> Result<Output, u32> {
    if !state::probe_user_write(value, size) || (return_length != 0 && !state::probe_user_write(return_length, 8)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(Output { value, return_length })
}

/// A PS_ATTRIBUTE_LIST do chamador, copiada uma vez para o kernel e lida da
/// cópia.
fn capture_attributes(list: u64) -> Result<Attributes, u32> {
    if list == 0 {
        return Ok(Attributes::default());
    }
    if list % 8 != 0 || !state::probe_user_read(list, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let total = guest::try_read::<u64>(list).map_err(|error| status_of(&error))?;
    let header = core::mem::offset_of!(PsAttributeList, attributes) as u64;
    if !(header..=header + MAXIMUM_ATTRIBUTES * PsAttribute::SIZE).contains(&total) || (total - header) % PsAttribute::SIZE != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !state::probe_user_read(list, total) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let bytes = guest::try_read_bytes(list, total as usize).map_err(|error| status_of(&error))?;
    let copy = guest::alloc_bytes(total);
    if copy == 0 {
        return Err(STATUS_NO_MEMORY);
    }
    guest::write_bytes(copy, &bytes);
    let count = ((total - header) / PsAttribute::SIZE) as usize;
    // SAFETY: a cópia de kernel recém-alocada, com `count` entradas.
    let entries = unsafe { PsAttribute::array_at(copy + header, count) };
    let captured = read_attributes(entries);
    guest::free_bytes(copy);
    captured
}

/// As entradas da cópia de kernel da lista.
fn read_attributes(entries: &[PsAttribute]) -> Result<Attributes, u32> {
    let mut captured = Attributes::default();
    let mut seen: Vec<u64> = Vec::new();
    for entry in entries {
        let (value, size, inline, return_length) = (entry.attribute.get(), entry.size.get(), entry.value.get(), entry.return_length.get());
        let number = value & attribute::NUMBER;
        if value & !(attribute::NUMBER | attribute::THREAD | attribute::INPUT | attribute::ADDITIVE) != 0 || number > attribute::LAST || seen.contains(&number) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        seen.push(number);
        // Os honrados conferem as marcas de thread e de entrada.
        let marks = value & (attribute::THREAD | attribute::INPUT);
        let expect = |wanted: u64| if marks == wanted { Ok(()) } else { Err(STATUS_INVALID_PARAMETER) };
        match number {
            attribute::IMAGE_NAME => {
                expect(attribute::INPUT)?;
                // PWSTR de Size bytes: um UNICODE_STRING não vazio.
                if size == 0 || size % 2 != 0 || size > 0xFFFE {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if !state::probe_user_read(inline, size) {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                captured.image_name = Some(state::try_read_user_wide_string(inline, size / 2).map_err(|error| status_of(&error))?);
            }
            attribute::PARENT_PROCESS => {
                expect(attribute::INPUT)?;
                if size != 8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let parent = handles::process_pointer(inline, PROCESS_CREATE_PROCESS)?;
                if process::with_record(parent, |record| record.terminated || record.exiting) != Some(false) {
                    return Err(STATUS_PROCESS_IS_TERMINATING);
                }
                captured.parent = (parent != process::get_current_process()).then_some(parent);
            }
            attribute::PRIORITY_CLASS => {
                expect(attribute::INPUT)?;
                if size != 1 || inline & 0xFF > MAXIMUM_PRIORITY_CLASS {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.priority_class = Some(inline as u8);
            }
            attribute::CLIENT_ID => {
                expect(attribute::THREAD)?;
                if size != ClientId::SIZE {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.client_id = Some(output(inline, return_length, size)?);
            }
            attribute::TEB_ADDRESS => {
                expect(attribute::THREAD)?;
                if size != 8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.teb_address = Some(output(inline, return_length, size)?);
            }
            attribute::IMAGE_INFO => {
                expect(0)?;
                if size < SectionImageInformation::SIZE {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.image_info = Some(output(inline, return_length, SectionImageInformation::SIZE)?);
            }
            attribute::PROTECTION_LEVEL => {
                expect(attribute::INPUT)?;
                // PS_PROTECTION por valor: Type nos bits 0..=2, Signer em 4..=7.
                let level = inline as u8;
                if size != 1 || inline > 0xFF || level & 7 > PROTECTION_TYPE_MAX || level >> 4 > PROTECTION_SIGNER_MAX {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.protection = Some(level);
            }
            attribute::DEBUG_OBJECT | attribute::TOKEN | attribute::UMS_THREAD | attribute::SECURE_PROCESS | attribute::JOB_LIST => {
                crate::debug_print!("[ps] NtCreateUserProcess: atributo {:#x} sem suporte", value);
                return Err(STATUS_NOT_SUPPORTED);
            }
            _ => crate::debug_print!("[ps] NtCreateUserProcess: atributo {:#x} aceito sem efeito", value),
        }
    }
    Ok(captured)
}

/// O PS_PROTECTION do processo novo: com PROCESS_CREATE_FLAGS_PROTECTED_PROCESS,
/// o do atributo ProtectionLevel, validado contra quem cria (`creator`);
/// sem a flag, nenhum (o atributo sozinho não protege).
fn requested_protection(process_flags: u32, requested: Option<u8>, creator: u64) -> Result<u8, u32> {
    if process_flags & PROCESS_PROTECTED == 0 {
        if requested.is_some() {
            crate::debug_print!("[ps] NtCreateUserProcess: ProtectionLevel sem PROCESS_CREATE_FLAGS_PROTECTED_PROCESS ignorado");
        }
        return Ok(0);
    }
    let Some(level) = requested else {
        crate::debug_print!("[ps] NtCreateUserProcess: processo protegido legado (sem ProtectionLevel) sem suporte");
        return Err(STATUS_NOT_SUPPORTED);
    };
    // SAFETY: quem cria está retido pela própria chamada (o corrente ou o
    // pai declarado, referenciado pelo handle).
    let own = unsafe { Eprocess::at(creator) }.protection.level.get();
    if own & 7 == 0 {
        return Err(STATUS_ACCESS_DENIED);
    }
    if own & 7 < level & 7 || own >> 4 < level >> 4 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(level)
}

/// O acesso de um handle que o criador recebe: os direitos genéricos
/// mapeados pelo tipo, MAXIMUM_ALLOWED como o acesso total dele; um direito
/// fora do tipo é recusado.
fn creator_access(requested: u32, object_type: &object_types::ObjectType) -> Result<u32, u32> {
    object_access::check(&SecurityPolicy::default(), None, requested, object_type, true)
}

/// O estado de falha no PS_CREATE_INFO (já sondado): PsCreateFailOnFileOpen
/// e PsCreateFailExeFormat; as outras falhas deixam o estado como veio.
fn write_failure(address: u64, failure: &CreateFailure) -> Result<(), KernelError> {
    let info = state::user_struct::<PsCreateInfo>(address)?;
    match failure {
        CreateFailure::FileOpen(_) => info.state.probe_set(PsCreateInfo::FAIL_ON_FILE_OPEN),
        CreateFailure::ExeFormat(_) => {
            info.state.probe_set(PsCreateInfo::FAIL_EXE_FORMAT)?;
            info.exe_format().dll_characteristics.probe_set(0)
        }
        CreateFailure::Terminated(_) | CreateFailure::Other(_) => Ok(()),
    }
}

/// O que as saídas precisam do processo criado.
struct Created {
    process_pointer: u64,
    process_id: u64,
    thread_id: u64,
    teb: u64,
    peb: u64,
    parameters: u64,
    image_information: Vec<u8>,
}

/// As saídas, nas VAs sondadas na captura: os handles, os atributos de saída
/// e o PsCreateSuccess.
fn write_outputs(request: &UserCreateRequest, attributes: &Attributes, created: &Created, handles: (u64, u64)) -> Result<(), KernelError> {
    guest::try_write::<u64>(request.process_handle, handles.0)?;
    guest::try_write::<u64>(request.thread_handle, handles.1)?;
    let returned = |output: &Output, size: u64| if output.return_length != 0 { guest::try_write::<u64>(output.return_length, size) } else { Ok(()) };
    if let Some(output) = &attributes.client_id {
        let client = state::user_struct::<ClientId>(output.value)?;
        client.unique_process.probe_set(created.process_id)?;
        client.unique_thread.probe_set(created.thread_id)?;
        returned(output, ClientId::SIZE)?;
    }
    if let Some(output) = &attributes.teb_address {
        guest::try_write::<u64>(output.value, created.teb)?;
        returned(output, 8)?;
    }
    if let Some(output) = &attributes.image_info {
        guest::try_write_bytes(output.value, &created.image_information)?;
        returned(output, SectionImageInformation::SIZE)?;
    }
    // A união inteira volta zerada antes do estado de sucesso.
    let info = state::user_struct::<PsCreateInfo>(request.create_info)?;
    guest::try_write_bytes(info.address() + 0x10, &[0u8; (PsCreateInfo::SIZE - 0x10) as usize])?;
    let success = info.success_state();
    success.user_process_parameters_native.probe_set(created.parameters)?;
    // O bloco entregue é auto-relativo (Flags 0): a ntdll o normaliza.
    success.current_parameter_flags.probe_set(0)?;
    success.peb_address_native.probe_set(created.peb)?;
    info.state.probe_set(PsCreateInfo::SUCCESS)
}

/// O corpo do NtCreateUserProcess (o cabeçalho do módulo). Devolve o
/// NTSTATUS; as falhas de sonda viram ACCESS_VIOLATION.
pub fn create(request: &UserCreateRequest) -> Result<u32, KernelError> {
    match capture_and_create(request) {
        Ok(status) | Err(status) => Ok(status),
    }
}

fn capture_and_create(request: &UserCreateRequest) -> Result<u32, u32> {
    if !state::probe_user_write(request.process_handle, 8) || !state::probe_user_write(request.thread_handle, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    capture_create_info(request.create_info)?;
    if request.process_flags & !PROCESS_FLAGS_KNOWN != 0 || request.thread_flags & !THREAD_FLAGS_KNOWN != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if request.process_flags & PROCESS_FLAGS_UNSUPPORTED != 0 {
        crate::debug_print!("[ps] NtCreateUserProcess: flags de processo {:#x} sem suporte", request.process_flags & PROCESS_FLAGS_UNSUPPORTED);
        return Err(STATUS_NOT_SUPPORTED);
    }
    let process_handle_attributes = capture_object_attributes(request.process_attributes)?;
    let thread_handle_attributes = capture_object_attributes(request.thread_attributes)?;
    let attributes = capture_attributes(request.attribute_list)?;
    let Some(image_name) = attributes.image_name.clone() else { return Err(STATUS_INVALID_PARAMETER) };
    let dos_path = String::from(image_name.strip_prefix("\\??\\").unwrap_or(&image_name));
    let mut parameters = if request.parameters != 0 { process_parameters::capture(request.parameters)? } else { ProcessParameters::for_image(&dos_path) };
    if parameters.image_path_name.is_empty() {
        parameters.image_path_name = dos_path.clone();
    }
    let protection = requested_protection(request.process_flags, attributes.protection, attributes.parent.unwrap_or_else(process::get_current_process))?;
    let process_access = creator_access(request.process_access, &object_types::process_type())?;
    let thread_access = creator_access(request.thread_access, &object_types::thread_type())?;
    // INHERIT_HANDLES: os handles herdáveis do pai declarado ou, sem ele, de
    // quem chama.
    let inherit_handles_from = (request.process_flags & PROCESS_INHERIT_HANDLES != 0).then(|| attributes.parent.unwrap_or_else(process::get_current_process));

    // A criação: daqui em diante só a memória do kernel e o processo novo.
    let short_name = String::from(dos_path.rsplit('\\').next().unwrap_or(&dos_path));
    let create_request = CreateProcessRequest { image: ImageOrigin::NtPath(image_name), image_name: &short_name, parameters, parent: attributes.parent, thread_flags: request.thread_flags, on_created: None, inherit_handles_from, protection, create_session: request.process_flags & PROCESS_CREATE_SESSION != 0 };
    let created = match create::create_user_process(&create_request) {
        Ok(created) => created,
        Err(failure) => {
            crate::debug_print!("[ps] NtCreateUserProcess de {}: {}", short_name, failure);
            write_failure(request.create_info, &failure).map_err(|error| status_of(&error))?;
            return Err(failure.status());
        }
    };
    if let Some(class) = attributes.priority_class {
        // SAFETY: o EPROCESS recém-criado, retido pelo processo criado.
        unsafe { Eprocess::at(created.process_pointer) }.priority_class.set(class);
    }
    let summary = Created {
        process_pointer: created.process_pointer,
        process_id: created.process_id,
        thread_id: created.thread_id,
        teb: created.teb,
        peb: created.peb,
        parameters: created.parameters,
        image_information: created.image_information.to_vec(),
    };
    let main = created.thread.clone();
    // O processo entra no despachante; a thread suspensa espera o
    // NtResumeThread. Uma falha aqui já terminou o processo.
    drop(user_process::start_created(created).map_err(|error| create::failure_status(&error))?);
    let process = summary.process_pointer;
    let process_handle = state::alloc_user_handle(Arc::new(UserProcess { pointer: process, process_id: summary.process_id }), process_access, process_handle_attributes);
    let process_handle = match process_handle {
        Ok(handle) => handle as u64,
        Err(error) => {
            let status = create::failure_status(&error);
            create::exit_process(process, status);
            return Err(status);
        }
    };
    let thread_handle = match threads::thread_handle(&main, thread_access, thread_handle_attributes) {
        Ok(handle) => handle,
        Err(error) => {
            let status = create::failure_status(&error);
            let _ = state::close_user_handle(process_handle, true, true);
            create::exit_process(process, status);
            return Err(status);
        }
    };
    crate::debug_print!("[ps] NtCreateUserProcess: {} pid={:#x} tid={:#x} handles {:#x}/{:#x}{}", short_name, summary.process_id, summary.thread_id, process_handle, thread_handle, if request.thread_flags & create::THREAD_CREATE_SUSPENDED != 0 { " (suspensa)" } else { "" });
    crate::ntos::init::initial_process::record_creation(process::get_current_process(), process);
    // As VAs foram sondadas; uma falha tardia devolve o status com o
    // processo e os handles já criados, como no NT.
    write_outputs(request, &attributes, &summary, (process_handle, thread_handle)).map_err(|error| status_of(&error))?;
    Ok(STATUS_SUCCESS)
}
