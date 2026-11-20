//! O pedido de criação vindo do modo usuário: o corpo do NtCreateUserProcess.
//!
//! O papel do PspBuildCreateProcessContext e do NtCreateUserProcess do NT
//! sobre o caminho único de `ps/create.rs`. Tudo o que o chamador passa é
//! sondado e capturado da memória de usuário dele antes de agir (a criação
//! anexa ao processo novo e deixa de enxergar o chamador):
//!
//! - o PS_CREATE_INFO (`PsCreateInfo`, entrada e saída), como o
//!   PspCaptureCreateInfo: Size 0x58 e PsCreateInitialState na entrada
//!   (senão STATUS_INVALID_PARAMETER); o InitState vira o `ImageRequest` do
//!   pedido (AdditionalFileAccess na abertura do executável,
//!   ProhibitedImageCharacteristics, DetectManifest) e WriteOutputOnExit
//!   decide a saída. Na saída, o PspUpdateCreateInfo: o estado
//!   (PsCreateSuccess; PsCreateFailOnFileOpen, o status do open;
//!   PsCreateFailExeFormat, imagem que não é um PE aceito ou com uma
//!   característica proibida; outras falhas deixam o estado como veio) e,
//!   só com WriteOutputOnExit, os campos dele: no PsCreateSuccess o
//!   OutputFlags (ProtectedProcess e ProtectedProcessLight do
//!   EPROCESS.Protection, AddressSpaceOverride do EPROCESS.Flags,
//!   ManifestDetected), o manifesto embutido (VA no processo novo e
//!   tamanho), FileHandle e SectionHandle, o bloco de parâmetros, o Flags
//!   dele e a PEB; no PsCreateFailExeFormat, o DllCharacteristics;
//! - a PS_ATTRIBUTE_LIST (`PsAttributeList`): honra ImageName (o caminho NT
//!   da imagem, obrigatório), ParentProcess (handle com
//!   PROCESS_CREATE_PROCESS; o pai declarado vai para as notificações e para
//!   InheritedFromUniqueProcessId), PriorityClass e as saídas ClientId,
//!   TebAddress e ImageInfo (o SECTION_IMAGE_INFORMATION da imagem na base
//!   real) e ProtectionLevel (o PS_PROTECTION, com
//!   PROCESS_CREATE_FLAGS_PROTECTED_PROCESS) e JobList (os handles de job,
//!   referenciados com JOB_OBJECT_ASSIGN_PROCESS: Size múltiplo de 8, não
//!   nulo); recusa com STATUS_NOT_SUPPORTED o que mudaria o processo sem
//!   suporte aqui (DebugObject, SecureProcess, UmsThread); Token (o
//!   CreateProcessAsUser) dá ao processo uma cópia do token primário pedido,
//!   referenciado com TOKEN_ASSIGN_PRIMARY, e exige de quem chama o
//!   SeAssignPrimaryTokenPrivilege no token primário (o RtlAcquirePrivilege
//!   do PspAllocateProcess o habilita numa cópia impersonada) ou habilitado
//!   no efetivo, ou um token filho ou irmão do primário dele (o
//!   SeIsTokenAssignableToProcess, `se/token/assignable.rs`); aceita sem
//!   efeito, com registro no log, os demais
//!   que o kernel32 passa (StdHandleInfo, HandleList, ErrorMode, afinidade,
//!   mitigações e políticas); um número desconhecido, um atributo repetido,
//!   um tamanho errado ou os bits de thread/entrada trocados num atributo
//!   honrado dão STATUS_INVALID_PARAMETER;
//! - o RTL_USER_PROCESS_PARAMETERS, normalizado ou não
//!   (`process_parameters::capture`);
//! - os OBJECT_ATTRIBUTES de processo e thread (sem nome; OBJ_INHERIT vai
//!   para o handle) e as flags: PROCESS_CREATE_FLAGS_* conhecidas são
//!   aceitas, as que pedem um processo diferente (mínimo, clone, store,
//!   espaço de outro) dão STATUS_NOT_SUPPORTED; AUXILIARY_PROCESS (0x8000,
//!   o conhost.exe que o condrv.sys cria) liga o
//!   EPROCESS.Flags3.AuxiliaryProcess e, junto com FORCE_BREAKAWAY, dá
//!   STATUS_INVALID_PARAMETER_MIX; o bit 0x200, que o
//!   kernelbase liga em toda criação sem CREATE_SUSPENDED, só escolhe o
//!   OwnerProcessId (o PspAllocateProcess);
//!   PROTECTED_PROCESS cria o processo com o PS_PROTECTION do atributo
//!   ProtectionLevel (sem ele, STATUS_NOT_SUPPORTED: o processo protegido
//!   legado não existe aqui): quem cria (o pai declarado ou quem chama)
//!   precisa ser protegido (senão STATUS_ACCESS_DENIED, como no
//!   NtCreateUserProcess 19041) e dominar o pedido, com tipo e signatário
//!   pelo menos iguais (a regra do RtlTestProtectedAccess; senão
//!   STATUS_INVALID_PARAMETER); com INHERIT_HANDLES o processo novo recebe, com
//!   os mesmos valores, os handles OBJ_INHERIT do pai declarado
//!   (ParentProcess) ou, sem ele, de quem chama;
//!   THREAD_CREATE_FLAGS_CREATE_SUSPENDED cria a thread principal suspensa;
//!   PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY pede o SeTcbPrivilege no primário
//!   (pelo mesmo RtlAcquirePrivilege) ou habilitado no efetivo (senão
//!   STATUS_PRIVILEGE_NOT_HELD, o PspAllocateProcess).
//! - Os jobs (PspInsertProcess e PspInsertThread), com o processo inteiro e
//!   ainda parado: o processo herda o job do pai declarado ou de quem chama
//!   (`ps/job/membership.rs`, com PROCESS_CREATE_FLAGS_BREAKAWAY e
//!   FORCE_BREAKAWAY) e é atribuído a cada job da JobList; uma recusa
//!   termina o processo novo e é o status da criação.
//!
//! Depois: `create::create_user_process` cria o processo e a thread
//! principal, o processo entra no despachante
//! (`ps/user/process.rs::start_created`; a thread suspensa só anda depois do
//! NtResumeThread), os handles do processo e da thread entram na tabela de
//! QUEM CHAMOU com o acesso pedido (os direitos genéricos mapeados e
//! MAXIMUM_ALLOWED como o acesso total do tipo, o que o criador recebe), e as
//! saídas (handles, CLIENT_ID, TEB, SECTION_IMAGE_INFORMATION e o
//! PS_CREATE_INFO) vão para as VAs já sondadas. Com WriteOutputOnExit, o
//! arquivo do executável (com o acesso da abertura da criação,
//! SYNCHRONIZE | FILE_EXECUTE | AdditionalFileAccess) e a seção de imagem
//! do processo (SECTION_ALL_ACCESS) também entram na tabela de quem chamou,
//! o PspPropagateHandle; o kernel32 os usa na mensagem de SxS ao csrss e os
//! fecha. Sem WriteOutputOnExit (o RtlCreateUserProcess da ntdll), nenhum
//! dos dois é aberto. Uma falha antes da criação não cria nada; uma falha ao
//! abrir os handles termina o processo novo.
//!
//! O ZwCreateUserProcess (PreviousMode KernelMode, o CdpCreateProcess do
//! condrv.sys) passa pelo mesmo corpo, como no NtCreateUserProcess 19041
//! (0x60a630): nada é sondado (só com PreviousMode diferente de KernelMode,
//! 0x60a801), o bloco de parâmetros é usado como veio (o
//! PspCaptureProcessParameters de KernelMode), o ParentProcess e o Token
//! aceitam handles de kernel sem conferir acesso, o SeSinglePrivilegeCheck
//! do PspAllocateProcess passa (0x705051) e, com OBJ_KERNEL_HANDLE nos
//! OBJECT_ATTRIBUTES, os handles do processo e da thread nascem na tabela
//! de kernel.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{ClientId, Eprocess, ObjectAttributes, PsAttribute, PsAttributeList, PsCreateInfo, SectionImageInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_access, object_types};
use crate::ntos::ps::create::{self, CreateFailure, CreateProcessRequest, ImageFile, ImageOrigin, ImageRequest, Manifest};
use crate::ntos::ps::process;
use crate::ntos::ps::process_parameters::{self, ProcessParameters};
use crate::ntos::ps::user::file_io;
use crate::ntos::ps::user::handles::{self, InheritedObject, UserProcess};
use crate::ntos::ps::user::process as user_process;
use crate::ntos::ps::user::{state, threads};
use crate::ntos::se::model::SecurityPolicy;
use crate::ntos::se::policy_descriptor::OwnedDescriptor;
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_BAD_TOKEN_TYPE: u32 = 0xC000_00A8;
/// TOKEN_ASSIGN_PRIMARY.
const TOKEN_ASSIGN_PRIMARY: u32 = 0x1;
/// SeAssignPrimaryTokenPrivilege.
const SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE: u64 = 3;

/// PROCESS_CREATE_PROCESS: o direito que o handle do pai declarado precisa.
const PROCESS_CREATE_PROCESS: u32 = 0x80;
/// OBJ_INHERIT: o único atributo de OBJECT_ATTRIBUTES que vai para o handle
/// de um chamador de modo usuário.
const OBJ_INHERIT: u32 = 2;
/// OBJ_KERNEL_HANDLE: de um chamador de modo kernel, o handle nasce na
/// tabela de kernel.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// PROCESS_CREATE_FLAGS_* conhecidas: BREAKAWAY, NO_DEBUG_INHERIT,
/// INHERIT_HANDLES, OVERRIDE_ADDRESS_SPACE, LARGE_PAGES,
/// LARGE_PAGE_SYSTEM_DLL, PROTECTED_PROCESS, CREATE_SESSION,
/// INHERIT_FROM_PARENT, SUSPENDED, FORCE_BREAKAWAY, MINIMAL_PROCESS,
/// RELEASE_SECTION, CLONE_MINIMAL, CLONE_MINIMAL_REDUCED_COMMIT,
/// AUXILIARY_PROCESS, CREATE_STORE e USE_PROTECTED_ENVIRONMENT.
const PROCESS_FLAGS_KNOWN: u32 = 0x0006_FFFF;
/// As que pedem um processo diferente, sem suporte aqui:
/// OVERRIDE_ADDRESS_SPACE, MINIMAL_PROCESS, CLONE_MINIMAL,
/// CLONE_MINIMAL_REDUCED_COMMIT e CREATE_STORE.
const PROCESS_FLAGS_UNSUPPORTED: u32 = 0x0002_6808;
/// PROCESS_CREATE_FLAGS_AUXILIARY_PROCESS: o PspAllocateProcess liga o
/// EPROCESS.Flags3.AuxiliaryProcess (0x704311).
const PROCESS_AUXILIARY: u32 = 0x8000;
/// STATUS_INVALID_PARAMETER_MIX: AUXILIARY_PROCESS com FORCE_BREAKAWAY
/// (0x60a7d8).
const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
/// O bit 0x200 (o PROCESS_CREATE_FLAGS_SUSPENDED dos cabeçalhos): o
/// CreateProcessInternalW do kernelbase o liga em toda criação sem
/// CREATE_SUSPENDED, e o PspAllocateProcess do 19041 só o lê para o
/// OwnerProcessId do processo novo (o UniqueProcessId de quem cria, com o
/// bit 2 quando ele falta); a thread principal não muda.
const PROCESS_OWNER_PLAIN: u32 = 0x200;
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
/// PROCESS_CREATE_FLAGS_BREAKAWAY e PROCESS_CREATE_FLAGS_FORCE_BREAKAWAY.
const PROCESS_BREAKAWAY: u32 = 0x1;
const PROCESS_FORCE_BREAKAWAY: u32 = 0x400;
/// SeTcbPrivilege (o FORCE_BREAKAWAY) e STATUS_PRIVILEGE_NOT_HELD.
const SE_TCB_PRIVILEGE: u64 = 7;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// THREAD_CREATE_FLAGS_* aceitas (as mesmas do NtCreateThreadEx).
const THREAD_FLAGS_KNOWN: u32 = 0x77;
/// Entradas de uma PS_ATTRIBUTE_LIST.
const MAXIMUM_ATTRIBUTES: u64 = 64;
/// O maior PROCESS_PRIORITY_CLASS_* (ABOVE_NORMAL).
const MAXIMUM_PRIORITY_CLASS: u64 = 6;
/// InitState.InitFlags: WriteOutputOnExit e DetectManifest; o
/// ProhibitedImageCharacteristics nos 16 bits altos.
const INIT_WRITE_OUTPUT_ON_EXIT: u32 = 0x1;
const INIT_DETECT_MANIFEST: u32 = 0x2;
/// SuccessState.OutputFlags: ProtectedProcess, AddressSpaceOverride,
/// ManifestDetected e ProtectedProcessLight.
const OUTPUT_PROTECTED_PROCESS: u32 = 0x1;
const OUTPUT_ADDRESS_SPACE_OVERRIDE: u32 = 0x2;
const OUTPUT_MANIFEST_DETECTED: u32 = 0x8;
const OUTPUT_PROTECTED_PROCESS_LIGHT: u32 = 0x10;
/// PsProtectedTypeProtectedLight, no Type (bits 0..=2) do PS_PROTECTION.
const PROTECTION_TYPE_LIGHT: u8 = 1;
/// SECTION_ALL_ACCESS: o acesso do handle da seção de imagem da criação.
const SECTION_ALL_ACCESS: u32 = 0xF_001F;

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

/// O token do PS_ATTRIBUTE_TOKEN (CreateProcessAsUser), referenciado com
/// TOKEN_ASSIGN_PRIMARY até o fim da criação.
#[derive(Default)]
struct TokenAttribute(Option<crate::ntos::se::token::reference::TokenReference>);

impl Drop for TokenAttribute {
    fn drop(&mut self) {
        if let Some(mut reference) = self.0.take() {
            let _ = reference.release();
        }
    }
}

/// O pai declarado por um handle de kernel (ZwCreateUserProcess),
/// referenciado pelo ObReferenceObjectByHandle de KernelMode até o fim da
/// criação.
#[derive(Default)]
struct ParentReference(Option<u64>);

impl Drop for ParentReference {
    fn drop(&mut self) {
        if let Some(process) = self.0.take() {
            let _ = crate::ntos::ps::query_process::release_process(process);
        }
    }
}

/// Os jobs do PS_ATTRIBUTE_JOB_LIST, referenciados até o fim da criação.
#[derive(Default)]
struct JobList(Vec<u64>);

impl Drop for JobList {
    fn drop(&mut self) {
        for &job in &self.0 {
            crate::ntos::ps::job::dereference_job(job);
        }
    }
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
    /// PsAttributeJobList.
    jobs: JobList,
    /// PsAttributeToken.
    token: TokenAttribute,
    /// A referência do pai declarado em KernelMode.
    parent_reference: ParentReference,
}

/// A sonda de leitura de um ponteiro do chamador: só em UserMode (`mode`
/// 1); em KernelMode o ponteiro vale como veio.
fn probe_read(mode: u8, va: u64, size: u64) -> bool {
    mode == 0 || state::probe_user_read(va, size)
}

/// A sonda de escrita, como [`probe_read`].
fn probe_write(mode: u8, va: u64, size: u64) -> bool {
    mode == 0 || state::probe_user_write(va, size)
}

/// O NTSTATUS de um erro de sonda ou de criação.
fn status_of(error: &KernelError) -> u32 {
    if error.status != 0 { error.status } else { STATUS_ACCESS_VIOLATION }
}

/// O PS_CREATE_INFO de entrada, capturado.
#[derive(Clone, Copy, Debug, Default)]
struct CreateInfoInput {
    /// WriteOutputOnExit: sem ele, a saída é só o estado.
    write_output_on_exit: bool,
    /// O resto do InitState: o pedido sobre o arquivo e a imagem.
    image: ImageRequest,
}

/// O PS_CREATE_INFO de entrada (o PspCaptureCreateInfo): gravável inteiro,
/// com PsCreateInitialState e o Size do tipo; o InitState decodificado.
fn capture_create_info(address: u64, mode: u8) -> Result<CreateInfoInput, u32> {
    if address == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !probe_write(mode, address, PsCreateInfo::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let read = || -> Result<(u32, u64, u32, u32), KernelError> {
        let info = state::user_struct::<PsCreateInfo>(address)?;
        let initial = info.init_state();
        Ok((info.state.probe_get()?, info.size.probe_get()?, initial.init_flags.probe_get()?, initial.additional_file_access.probe_get()?))
    };
    let (create_state, size, init_flags, additional_file_access) = read().map_err(|error| status_of(&error))?;
    if create_state != PsCreateInfo::INITIAL_STATE || size != PsCreateInfo::SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(CreateInfoInput {
        write_output_on_exit: init_flags & INIT_WRITE_OUTPUT_ON_EXIT != 0,
        image: ImageRequest { additional_file_access, prohibited_characteristics: (init_flags >> 16) as u16, detect_manifest: init_flags & INIT_DETECT_MANIFEST != 0 },
    })
}

/// Os OBJECT_ATTRIBUTES de processo ou de thread (opcionais): sem nome; o
/// OBJ_INHERIT vira o atributo do handle, e de um chamador de modo kernel
/// também o OBJ_KERNEL_HANDLE. O SecurityDescriptor é capturado como o do
/// ObCreateObject do PspAllocateProcess (0x704231) e do PspAllocateThread
/// (0x6c418c): um descritor inválido recusa a criação antes do processo.
fn capture_object_attributes(address: u64, mode: u8) -> Result<(u32, Option<OwnedDescriptor>), u32> {
    if address == 0 {
        return Ok((0, None));
    }
    if !probe_read(mode, address, ObjectAttributes::SIZE) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let read = || -> Result<(u32, u64, u32, u64), KernelError> {
        let attributes = state::user_struct::<ObjectAttributes>(address)?;
        Ok((attributes.length.probe_get()?, attributes.object_name.probe_get()?, attributes.attributes.probe_get()?, attributes.security_descriptor.probe_get()?))
    };
    let (length, name, attributes, descriptor) = read().map_err(|error| status_of(&error))?;
    if length as u64 != ObjectAttributes::SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // Processos e threads não têm nome.
    if name != 0 {
        return Err(STATUS_OBJECT_NAME_INVALID);
    }
    let descriptor = crate::ntos::ob::object_security::capture_descriptor(descriptor, mode != 0)?;
    Ok((attributes & if mode == 0 { OBJ_INHERIT | OBJ_KERNEL_HANDLE } else { OBJ_INHERIT }, descriptor))
}

/// Uma saída de tamanho `size` em `value` (e o PSIZE_T, se veio), sondadas
/// para escrita.
fn output(value: u64, return_length: u64, size: u64, mode: u8) -> Result<Output, u32> {
    if !probe_write(mode, value, size) || (return_length != 0 && !probe_write(mode, return_length, 8)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(Output { value, return_length })
}

/// A PS_ATTRIBUTE_LIST do chamador, copiada uma vez para o kernel e lida da
/// cópia.
fn capture_attributes(list: u64, mode: u8) -> Result<Attributes, u32> {
    if list == 0 {
        return Ok(Attributes::default());
    }
    if list % 8 != 0 || !probe_read(mode, list, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let total = guest::try_read::<u64>(list).map_err(|error| status_of(&error))?;
    let header = core::mem::offset_of!(PsAttributeList, attributes) as u64;
    if !(header..=header + MAXIMUM_ATTRIBUTES * PsAttribute::SIZE).contains(&total) || (total - header) % PsAttribute::SIZE != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if !probe_read(mode, list, total) {
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
    let captured = read_attributes(entries, mode);
    guest::free_bytes(copy);
    captured
}

/// As entradas da cópia de kernel da lista.
fn read_attributes(entries: &[PsAttribute], mode: u8) -> Result<Attributes, u32> {
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
                if !probe_read(mode, inline, size) {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                captured.image_name = Some(state::try_read_user_wide_string(inline, size / 2).map_err(|error| status_of(&error))?);
            }
            attribute::PARENT_PROCESS => {
                expect(attribute::INPUT)?;
                if size != 8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                // De KernelMode, o ObReferenceObjectByHandle de KernelMode:
                // um handle de kernel, sem conferir o acesso (o do condrv.sys
                // tem só PROCESS_QUERY_LIMITED_INFORMATION).
                let parent = if mode == 0 {
                    let referenced = crate::ntos::ps::query_process::reference_process(inline, PROCESS_CREATE_PROCESS).map_err(|error| status_of(&error))??;
                    captured.parent_reference = ParentReference(Some(referenced));
                    referenced
                } else {
                    handles::process_pointer(inline, PROCESS_CREATE_PROCESS)?
                };
                if process::with_record(parent, |record| record.terminated || record.exiting) != Some(false) {
                    return Err(STATUS_PROCESS_IS_TERMINATING);
                }
                captured.parent = (parent != process::get_current_process()).then_some(parent);
            }
            attribute::PRIORITY_CLASS => {
                expect(attribute::INPUT)?;
                // Um UCHAR por ponteiro: o CreateProcessInternalW passa o
                // endereço do PROCESS_PRIORITY_CLASS pedido (o
                // NORMAL_PRIORITY_CLASS do dwm.exe que o dwminit cria).
                if size != 1 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if !probe_read(mode, inline, 1) {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                let class = guest::try_read::<u8>(inline).map_err(|error| status_of(&error))?;
                if class as u64 > MAXIMUM_PRIORITY_CLASS {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.priority_class = Some(class);
            }
            attribute::CLIENT_ID => {
                expect(attribute::THREAD)?;
                if size != ClientId::SIZE {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.client_id = Some(output(inline, return_length, size, mode)?);
            }
            attribute::TEB_ADDRESS => {
                expect(attribute::THREAD)?;
                if size != 8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.teb_address = Some(output(inline, return_length, size, mode)?);
            }
            attribute::IMAGE_INFO => {
                expect(0)?;
                if size < SectionImageInformation::SIZE {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                captured.image_info = Some(output(inline, return_length, SectionImageInformation::SIZE, mode)?);
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
            attribute::JOB_LIST => {
                expect(attribute::INPUT)?;
                // HANDLE[Size / 8]: Size não nulo, múltiplo de 8 e de no
                // máximo 0x7FFFFFFF8 bytes (o PspBuildCreateProcessContext).
                if size == 0 || size % 8 != 0 || size > 0x7_FFFF_FFF8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                if !probe_read(mode, inline, size) {
                    return Err(STATUS_ACCESS_VIOLATION);
                }
                let handles = guest::try_read_bytes(inline, size as usize).map_err(|error| status_of(&error))?;
                for handle in handles.chunks_exact(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))) {
                    let job = crate::ntos::ps::job::object::reference_by_handle(handle, crate::ntos::ps::job::JOB_OBJECT_ASSIGN_PROCESS, mode)?;
                    captured.jobs.0.push(job);
                }
            }
            attribute::TOKEN => {
                expect(attribute::INPUT)?;
                // HANDLE por valor: o token primário que o processo copia
                // (TOKEN_ASSIGN_PRIMARY; um de impersonação é
                // STATUS_BAD_TOKEN_TYPE, como o SeIsTokenAssignableToProcess).
                if size != 8 {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                let reference = match crate::ntos::se::token::reference::reference(inline, TOKEN_ASSIGN_PRIMARY, mode, false).map_err(|error| status_of(&error))? {
                    Ok(reference) => reference,
                    Err(status) => return Err(status),
                };
                let kind = crate::ntos::se::token::tokens::with(reference.token, |token| token.kind).unwrap_or(0);
                captured.token = TokenAttribute(Some(reference));
                if kind != 1 {
                    return Err(STATUS_BAD_TOKEN_TYPE);
                }
            }
            attribute::DEBUG_OBJECT | attribute::UMS_THREAD | attribute::SECURE_PROCESS => {
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

/// O estado de falha no PS_CREATE_INFO (já sondado), o PspUpdateCreateInfo:
/// PsCreateFailOnFileOpen e PsCreateFailExeFormat (com o DllCharacteristics
/// da imagem só com WriteOutputOnExit); as outras falhas deixam o estado como
/// veio.
fn write_failure(address: u64, failure: &CreateFailure, input: &CreateInfoInput) -> Result<(), KernelError> {
    let info = state::user_struct::<PsCreateInfo>(address)?;
    match failure {
        CreateFailure::FileOpen(_) => info.state.probe_set(PsCreateInfo::FAIL_ON_FILE_OPEN),
        CreateFailure::ExeFormat(_, dll_characteristics) => {
            if input.write_output_on_exit {
                info.exe_format().dll_characteristics.probe_set(*dll_characteristics)?;
            }
            info.state.probe_set(PsCreateInfo::FAIL_EXE_FORMAT)
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
    manifest: Option<Manifest>,
    parameter_flags: u32,
    image_file: Option<ImageFile>,
}

/// O OutputFlags do PsCreateSuccess (o PspUpdateCreateInfo):
/// ProtectedProcess com qualquer tipo de PS_PROTECTION,
/// ProtectedProcessLight com PsProtectedTypeProtectedLight,
/// AddressSpaceOverride do EPROCESS.Flags e ManifestDetected.
/// DevOverrideEnabled (o PspGlobalFlags) fica desligado.
fn output_flags(created: &Created) -> u32 {
    // SAFETY: o EPROCESS recém-criado, retido pelo processo criado.
    let process = unsafe { Eprocess::at(created.process_pointer) };
    let protection_type = process.protection.level.get() & 7;
    let mut flags = 0;
    if protection_type != 0 {
        flags |= OUTPUT_PROTECTED_PROCESS;
    }
    if protection_type == PROTECTION_TYPE_LIGHT {
        flags |= OUTPUT_PROTECTED_PROCESS_LIGHT;
    }
    if process.flags.get() & Eprocess::OVERRIDE_ADDRESS_SPACE_MASK != 0 {
        flags |= OUTPUT_ADDRESS_SPACE_OVERRIDE;
    }
    if created.manifest.is_some() {
        flags |= OUTPUT_MANIFEST_DETECTED;
    }
    flags
}

/// O PspPropagateHandle do PsCreateSuccess: o arquivo do executável, com o
/// acesso da abertura da criação, e a seção de imagem do processo, com
/// SECTION_ALL_ACCESS, na tabela de quem chamou (o processo corrente).
/// Devolve (FileHandle, SectionHandle); uma falha fecha o que já abriu.
fn propagate_image_handles(image_name: &str, created: &Created) -> Result<(u64, u64), KernelError> {
    let Some(image) = &created.image_file else { return Ok((0, 0)) };
    let file = file_io::open_resolved(&image.file, image_name, image.access, create::IMAGE_FILE_SHARE, create::IMAGE_FILE_OPTIONS, 0)? as u64;
    let section = process::image_section(created.process_pointer).and_then(InheritedObject::new).ok_or_else(|| KernelError::with_status("processo novo sem secao de imagem", STATUS_INVALID_PARAMETER));
    match section.and_then(|section| state::alloc_user_handle(Arc::new(section), SECTION_ALL_ACCESS, 0)) {
        Ok(section) => Ok((file, section as u64)),
        Err(error) => {
            let _ = state::close_user_handle(file, true, true);
            Err(error)
        }
    }
}

/// As saídas, nas VAs sondadas na captura: os handles, os atributos de saída
/// e o PsCreateSuccess (os campos dele só com WriteOutputOnExit, na ordem
/// do PspUpdateCreateInfo; o estado sempre).
fn write_outputs(request: &UserCreateRequest, attributes: &Attributes, input: &CreateInfoInput, created: &Created, handles: (u64, u64), image_handles: (u64, u64)) -> Result<(), KernelError> {
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
    let info = state::user_struct::<PsCreateInfo>(request.create_info)?;
    if input.write_output_on_exit {
        let success = info.success_state();
        // O OutputFlags inteiro, por cima do InitFlags que veio.
        let flags = output_flags(created);
        success.output_flags.probe_set(flags)?;
        if let Some(manifest) = created.manifest {
            success.manifest_address.probe_set(manifest.address)?;
            success.manifest_size.probe_set(manifest.size)?;
        }
        success.file_handle.probe_set(image_handles.0)?;
        success.section_handle.probe_set(image_handles.1)?;
        success.user_process_parameters_native.probe_set(created.parameters)?;
        success.user_process_parameters_wow64.probe_set(0)?;
        // O Flags do bloco entregue (NORMALIZED, com os Buffers absolutos).
        success.current_parameter_flags.probe_set(created.parameter_flags)?;
        success.peb_address_native.probe_set(created.peb)?;
        success.peb_address_wow64.probe_set(0)?;
    }
    info.state.probe_set(PsCreateInfo::SUCCESS)
}

/// Um handle de kernel (OBJ_KERNEL_HANDLE) para o objeto `pointer` com o
/// acesso já mapeado: o ObOpenObjectByPointer de KernelMode. Devolve o
/// handle ou o NTSTATUS.
fn kernel_handle(pointer: u64, attributes: u32, access: u32, object_type: u64) -> Result<u64, u32> {
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        return Err(STATUS_NO_MEMORY);
    }
    let opened = crate::ntos::ob::open_pointer::open_by_pointer(pointer, attributes | OBJ_KERNEL_HANDLE, 0, access, object_type, 0, cell);
    let handle = guest::read64(cell);
    guest::free_bytes(cell);
    match opened {
        Ok(0) => Ok(handle),
        Ok(status) => Err(status),
        Err(error) => Err(status_of(&error)),
    }
}

/// O job do pai do processo novo, retido durante a criação.
struct CreatorJob(u64);

impl Drop for CreatorJob {
    fn drop(&mut self) {
        if self.0 != 0 {
            crate::ntos::ps::job::dereference_job(self.0);
        }
    }
}

/// O EPROCESS.Job de quem cria (o pai declarado ou quem chama), referenciado.
fn creator_job(creator: u64) -> CreatorJob {
    // SAFETY: quem cria está retido pela própria chamada (o corrente ou o pai
    // declarado, referenciado pelo handle).
    let job = unsafe { Eprocess::at(creator) }.job.get();
    if job != 0 {
        crate::ntos::ps::job::reference_job(job);
    }
    CreatorJob(job)
}

/// O corpo do NtCreateUserProcess (o cabeçalho do módulo). Devolve o
/// NTSTATUS; as falhas de sonda viram ACCESS_VIOLATION.
pub fn create(request: &UserCreateRequest) -> Result<u32, KernelError> {
    match capture_and_create(request) {
        Ok(status) | Err(status) => Ok(status),
    }
}

fn capture_and_create(request: &UserCreateRequest) -> Result<u32, u32> {
    // 0 no ZwCreateUserProcess, 1 no NtCreateUserProcess.
    let mode = crate::ntos::ps::previous_mode::get().unwrap_or(1);
    if !probe_write(mode, request.process_handle, 8) || !probe_write(mode, request.thread_handle, 8) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    let create_info = capture_create_info(request.create_info, mode)?;
    if request.process_flags & !PROCESS_FLAGS_KNOWN != 0 || request.thread_flags & !THREAD_FLAGS_KNOWN != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if request.process_flags & (PROCESS_AUXILIARY | PROCESS_FORCE_BREAKAWAY) == PROCESS_AUXILIARY | PROCESS_FORCE_BREAKAWAY {
        return Err(STATUS_INVALID_PARAMETER_MIX);
    }
    if request.process_flags & PROCESS_FLAGS_UNSUPPORTED != 0 {
        crate::debug_print!("[ps] NtCreateUserProcess: flags de processo {:#x} sem suporte", request.process_flags & PROCESS_FLAGS_UNSUPPORTED);
        return Err(STATUS_NOT_SUPPORTED);
    }
    if request.process_flags & PROCESS_FORCE_BREAKAWAY != 0 && mode != 0 && !crate::ntos::se::privilege::acquired_privilege_check(SE_TCB_PRIVILEGE, 1) {
        return Err(STATUS_PRIVILEGE_NOT_HELD);
    }
    let (process_handle_attributes, process_descriptor) = capture_object_attributes(request.process_attributes, mode)?;
    let (thread_handle_attributes, thread_descriptor) = capture_object_attributes(request.thread_attributes, mode)?;
    let attributes = capture_attributes(request.attribute_list, mode)?;
    let Some(image_name) = attributes.image_name.clone() else { return Err(STATUS_INVALID_PARAMETER) };
    let dos_path = String::from(image_name.strip_prefix("\\??\\").unwrap_or(&image_name));
    // De KernelMode o bloco vale como veio (o PspCaptureProcessParameters):
    // o mesmo parser, sem sondas; o DesktopInfo passa nos dois modos.
    let mut parameters = if request.parameters != 0 { process_parameters::capture_from(request.parameters, mode)? } else { ProcessParameters::for_image(&dos_path) };
    if parameters.image_path_name.is_empty() {
        parameters.image_path_name = dos_path.clone();
    }
    let protection = requested_protection(request.process_flags, attributes.protection, attributes.parent.unwrap_or_else(process::get_current_process))?;
    // PsAttributeToken: o SeAssignPrimaryTokenPrivilege (o RtlAcquirePrivilege
    // do PspAllocateProcess o habilita numa cópia do primário de quem chama
    // antes do SeSinglePrivilegeCheck) ou um token filho ou irmão do primário
    // (o SeIsTokenAssignableToProcess, sempre avaliado: a recusa dele vale
    // mesmo com o privilégio). Um token de outra sessão que a de quem cria
    // (o SeQuerySessionIdToken contra o MmGetSessionIdEx, 0x7050a3) exige o
    // privilégio e leva o processo à sessão do token, o que
    // PROCESS_CREATE_FLAGS_CREATE_SESSION não admite
    // (STATUS_INVALID_PARAMETER).
    let primary_token = attributes.token.0.as_ref().map(|reference| reference.token);
    if let Some(token) = primary_token {
        // O SeSinglePrivilegeCheck com PreviousMode KernelMode passa.
        let privileged = mode == 0 || crate::ntos::se::privilege::acquired_privilege_check(SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE, 1);
        let assignable = crate::ntos::se::token::assignable::is_assignable_to_process(token)?;
        if !privileged && !assignable {
            let effective = crate::ntos::ob::object_access::subject().unwrap_or(0);
            let describe = |pointer: u64| {
                crate::ntos::se::token::tokens::with(pointer, |record| {
                    let assign = record.privileges.iter().find(|privilege| privilege.id == SE_ASSIGN_PRIMARY_TOKEN_PRIVILEGE).map(|privilege| privilege.attributes);
                    alloc::format!("logon {:#x}, pai {:#x}, tipo {}, SeAssignPrimaryTokenPrivilege {:?}", record.authentication_id, record.parent_token_id, record.kind, assign)
                })
                .unwrap_or_default()
            };
            crate::debug_print!("[ps] NtCreateUserProcess: token do PS_ATTRIBUTE_TOKEN nao atribuivel ({}); token efetivo de quem cria: {}", describe(token), describe(effective));
            return Err(STATUS_PRIVILEGE_NOT_HELD);
        }
        let token_session = crate::ntos::se::token::tokens::with(token, |record| record.session_id).unwrap_or(0);
        if token_session != crate::ntos::mm::session::session_id_ex(process::get_current_process()) {
            if !privileged {
                return Err(STATUS_PRIVILEGE_NOT_HELD);
            }
            if request.process_flags & PROCESS_CREATE_SESSION != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
        }
    }
    // O sujeito do SeAssignSecurityEx do PspInsertProcess (0x607cab..0x607cbf)
    // para os descritores explícitos: o System quando o pai é o processo do
    // System, o token do processo novo com PS_ATTRIBUTE_TOKEN e, senão, quem
    // cria. Em UserMode o dono explícito precisa ser atribuível por ele
    // (STATUS_INVALID_OWNER) antes de o processo existir.
    let system_parent = attributes.parent.unwrap_or_else(process::get_current_process) == process::get_system_process();
    let explicit_subject = if system_parent { process::get_primary_token(process::get_system_process()) } else { primary_token.or_else(crate::ntos::ob::object_access::subject) }.unwrap_or(0);
    if mode != 0 {
        for descriptor in [process_descriptor.as_ref(), thread_descriptor.as_ref()].into_iter().flatten() {
            crate::ntos::ob::object_security::check_explicit_for_user(descriptor, explicit_subject)?;
        }
    }
    let process_access = creator_access(request.process_access, &object_types::process_type())?;
    let thread_access = creator_access(request.thread_access, &object_types::thread_type())?;
    // INHERIT_HANDLES: os handles herdáveis do pai declarado ou, sem ele, de
    // quem chama.
    let inherit_handles_from = (request.process_flags & PROCESS_INHERIT_HANDLES != 0).then(|| attributes.parent.unwrap_or_else(process::get_current_process));

    // Os jobs do processo novo, com ele inteiro e ainda parado: o do pai
    // declarado (ou de quem chama), pelo PspImplicitAssignProcessToJob, e os
    // da JobList, pelo PspAssignProcessToJobList.
    let creator_job = creator_job(attributes.parent.unwrap_or_else(process::get_current_process));
    let job_flags = request.process_flags & (PROCESS_BREAKAWAY | PROCESS_FORCE_BREAKAWAY);
    let jobs = &attributes.jobs;
    let assign_jobs = |process_id: u64| -> Result<(), KernelError> {
        let Some(process) = crate::ntos::ps::cid::lookup(process_id).map(|entry| entry.object).filter(|&object| object != 0) else { return Ok(()) };
        let status = crate::ntos::ps::job::membership::implicit_assign(creator_job.0, process, job_flags);
        if status & 0x8000_0000 != 0 {
            return Err(KernelError::with_status("o job do pai recusou o processo novo", status));
        }
        let status = crate::ntos::ps::job::membership::assign_job_list(process, &jobs.0);
        if status & 0x8000_0000 != 0 {
            return Err(KernelError::with_status("um job da JobList recusou o processo novo", status));
        }
        Ok(())
    };

    // A criação: daqui em diante só a memória do kernel e o processo novo.
    let short_name = String::from(dos_path.rsplit('\\').next().unwrap_or(&dos_path));
    let create_request = CreateProcessRequest {
        image: ImageOrigin::NtPath(image_name.clone()),
        image_name: &short_name,
        parameters,
        parent: attributes.parent,
        thread_flags: request.thread_flags,
        on_created: Some(&assign_jobs),
        inherit_handles_from,
        protection,
        create_session: request.process_flags & PROCESS_CREATE_SESSION != 0,
        primary_token,
        image_request: create_info.image,
    };
    let created = match create::create_user_process(&create_request) {
        Ok(created) => created,
        Err(failure) => {
            crate::debug_print!("[ps] NtCreateUserProcess de {}: {}", short_name, failure);
            write_failure(request.create_info, &failure, &create_info).map_err(|error| status_of(&error))?;
            return Err(failure.status());
        }
    };
    if let Some(class) = attributes.priority_class {
        // SAFETY: o EPROCESS recém-criado, retido pelo processo criado.
        unsafe { Eprocess::at(created.process_pointer) }.priority_class.set(class);
    }
    // Os descritores explícitos (o ObAssignSecurity do PspInsertProcess
    // 0x607d35 e do PspInsertThread 0x6c22db): o do processo e o da thread
    // principal, com o sujeito acima; o processo novo com PS_ATTRIBUTE_TOKEN
    // responde pelo próprio token. Sem descritor, o padrão do token.
    let subject = if !system_parent && primary_token.is_some() { process::get_primary_token(created.process_pointer).unwrap_or(explicit_subject) } else { explicit_subject };
    if let Some(descriptor) = process_descriptor.as_ref() {
        if let Ok(policy) = crate::ntos::ob::object_security::assign_explicit_for_token(&object_types::process_type(), descriptor, subject) {
            process::update_record(created.process_pointer, |record| record.security = policy);
        }
    }
    if let Some(descriptor) = thread_descriptor.as_ref() {
        if let Ok(policy) = crate::ntos::ob::object_security::assign_explicit_for_token(&object_types::thread_type(), descriptor, subject) {
            process::set_thread_security(created.thread.pointer(), policy);
        }
    }
    // O OwnerProcessId do PspAllocateProcess: o processo que cria.
    let creator = crate::ntos::ps::process::get_current_process();
    if creator != 0 {
        // SAFETY: o EPROCESS de quem chama e o recém-criado, vivos.
        let owner = unsafe { Eprocess::at(creator) }.unique_process_id.get() | if request.process_flags & PROCESS_OWNER_PLAIN != 0 { 0 } else { 2 };
        unsafe { Eprocess::at(created.process_pointer) }.owner_process_id.set(owner);
    }
    if request.process_flags & PROCESS_AUXILIARY != 0 {
        // SAFETY: o EPROCESS recém-criado, retido pelo processo criado.
        unsafe { Eprocess::at(created.process_pointer) }.flags3.atomic().fetch_or(Eprocess::AUXILIARY_PROCESS_MASK, core::sync::atomic::Ordering::SeqCst);
    }
    let summary = Created {
        process_pointer: created.process_pointer,
        process_id: created.process_id,
        thread_id: created.thread_id,
        teb: created.teb,
        peb: created.peb,
        parameters: created.parameters,
        image_information: created.image_information.to_vec(),
        manifest: created.manifest,
        parameter_flags: created.parameter_flags,
        image_file: created.image_file.clone(),
    };
    let main = created.thread.clone();
    // O processo entra no despachante; a thread suspensa espera o
    // NtResumeThread. Uma falha aqui já terminou o processo.
    drop(user_process::start_created(created).map_err(|error| create::failure_status(&error))?);
    let process = summary.process_pointer;
    // De KernelMode com OBJ_KERNEL_HANDLE, os dois handles nascem na tabela
    // de kernel (o ObOpenObjectByPointer do PspInsertThread).
    let kernel_handles = mode == 0 && process_handle_attributes & OBJ_KERNEL_HANDLE != 0;
    let close_handle = |handle: u64| {
        if kernel_handles {
            let _ = crate::ntos::ob::close::close(handle, Some(0));
        } else {
            let _ = state::close_user_handle(handle, true, true);
        }
    };
    let process_handle = if kernel_handles {
        kernel_handle(process, process_handle_attributes, process_access, object_types::process_type().pointer)
    } else {
        state::alloc_user_handle(Arc::new(UserProcess { pointer: process, process_id: summary.process_id }), process_access, process_handle_attributes).map(u64::from).map_err(|error| create::failure_status(&error))
    };
    let process_handle = match process_handle {
        Ok(handle) => handle,
        Err(status) => {
            create::exit_process(process, status);
            return Err(status);
        }
    };
    let thread_handle = if kernel_handles {
        kernel_handle(main.pointer(), thread_handle_attributes | OBJ_KERNEL_HANDLE, thread_access, object_types::thread_type().pointer)
    } else {
        threads::thread_handle(&main, thread_access, thread_handle_attributes).map_err(|error| create::failure_status(&error))
    };
    let thread_handle = match thread_handle {
        Ok(handle) => handle,
        Err(status) => {
            close_handle(process_handle);
            create::exit_process(process, status);
            return Err(status);
        }
    };
    // O PspUpdateCreateInfo com WriteOutputOnExit: o arquivo e a seção da
    // imagem na tabela de quem chamou; uma falha fecha os handles e termina
    // o processo novo, como a dos handles do processo e da thread.
    let image_handles = if create_info.write_output_on_exit {
        match propagate_image_handles(&image_name, &summary) {
            Ok(handles) => handles,
            Err(error) => {
                let status = create::failure_status(&error);
                close_handle(thread_handle);
                close_handle(process_handle);
                create::exit_process(process, status);
                return Err(status);
            }
        }
    } else {
        (0, 0)
    };
    crate::debug_print!(
        "[ps] NtCreateUserProcess: {} pid={:#x} tid={:#x} handles {:#x}/{:#x} arquivo/secao {:#x}/{:#x}{}{}",
        short_name,
        summary.process_id,
        summary.thread_id,
        process_handle,
        thread_handle,
        image_handles.0,
        image_handles.1,
        summary.manifest.map(|manifest| alloc::format!(" manifesto {:#x}+{:#x}", manifest.address, manifest.size)).unwrap_or_default(),
        if request.thread_flags & create::THREAD_CREATE_SUSPENDED != 0 { " (suspensa)" } else { "" }
    );
    crate::ntos::mm::memory_information::print_status("criado", summary.process_id);
    crate::ntos::init::initial_process::record_creation(process::get_current_process(), process);
    // As VAs foram sondadas; uma falha tardia devolve o status com o
    // processo e os handles já criados, como no NT.
    write_outputs(request, &attributes, &create_info, &summary, (process_handle, thread_handle), image_handles).map_err(|error| status_of(&error))?;
    Ok(STATUS_SUCCESS)
}
