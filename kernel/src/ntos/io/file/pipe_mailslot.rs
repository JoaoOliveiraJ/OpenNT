//! NtCreateNamedPipeFile e NtCreateMailslotFile, como no ntoskrnl 19041: o
//! serviço captura os parâmetros do file system num
//! NAMED_PIPE_CREATE_PARAMETERS ou MAILSLOT_CREATE_PARAMETERS e chama o
//! IoCreateFile com CreateFileTypeNamedPipe (1) ou CreateFileTypeMailslot
//! (2); a abertura (`ps/user/files.rs`) leva o ponteiro na stack location do
//! IRP_MJ_CREATE_NAMED_PIPE ou IRP_MJ_CREATE_MAILSLOT ao npfs.sys ou ao
//! msfs.sys.
//!
//! - NtCreateNamedPipeFile: DefaultTimeout opcional (com ele,
//!   TimeoutSpecified = TRUE; de modo usuário, alinhado a 4 e lido sondado);
//!   NamedPipeType, ReadMode, CompletionMode, MaximumInstances e as cotas
//!   vão como vieram. O IoCreateFile recebe AllocationSize, atributos e EAs
//!   nulos.
//! - NtCreateMailslotFile: ReadTimeout opcional, do mesmo jeito; o
//!   IoCreateFile recebe ShareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE e
//!   Disposition = FILE_CREATE.
//! - A validação do IopCreateFile para um chamador de modo usuário: a geral
//!   (atributos, compartilhamento, disposição e opções, SYNCHRONIZE para as
//!   opções síncronas e DELETE para FILE_DELETE_ON_CLOSE) e a de cada tipo —
//!   pipe: NamedPipeType até 3, ReadMode e CompletionMode até 1, sem
//!   FILE_SHARE_DELETE, disposição FILE_OPEN, FILE_CREATE ou FILE_OPEN_IF;
//!   mailslot: FILE_SHARE_READ sem FILE_SHARE_DELETE e FILE_CREATE; nos dois,
//!   só FILE_WRITE_THROUGH e as opções síncronas. Qualquer falha é
//!   STATUS_INVALID_PARAMETER.

use crate::ntos::inc::types::extra_pipes::{MailslotCreateParameters, NamedPipeCreateParameters};
use crate::ntos::inc::types::NtStruct;
use crate::ntos::mm::guest_memory as guest;

/// CREATE_FILE_TYPE do IoCreateFile.
pub const CREATE_FILE_TYPE_NAMED_PIPE: u8 = 1;
pub const CREATE_FILE_TYPE_MAILSLOT: u8 = 2;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const SYNCHRONIZE: u32 = 0x10_0000;
const DELETE: u32 = 0x1_0000;
const FILE_APPEND_DATA: u32 = 0x4;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_SHARE_DELETE: u32 = 0x4;
const FILE_CREATE: u32 = 2;
const FILE_SHARE_READ: u32 = 0x1;
/// Opções de criação (wdm.h).
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
const FILE_DELETE_ON_CLOSE: u32 = 0x1000;

/// Os parâmetros do file system capturados em memória do kernel; vivem até
/// o fim da abertura.
pub struct Captured {
    pointer: u64,
    file_type: u8,
}

impl Captured {
    pub fn pointer(&self) -> u64 {
        self.pointer
    }

    pub fn file_type(&self) -> u8 {
        self.file_type
    }
}

impl Drop for Captured {
    fn drop(&mut self) {
        guest::free_bytes(self.pointer);
    }
}

/// Os argumentos comuns do IoCreateFile.
#[derive(Clone, Copy, Default)]
pub struct CreateArguments {
    pub desired_access: u32,
    pub share_access: u32,
    pub disposition: u32,
    pub create_options: u32,
}

/// Os argumentos próprios do NtCreateNamedPipeFile.
#[derive(Clone, Copy, Default)]
pub struct NamedPipeArguments {
    pub named_pipe_type: u32,
    pub read_mode: u32,
    pub completion_mode: u32,
    pub maximum_instances: u32,
    pub inbound_quota: u32,
    pub outbound_quota: u32,
    /// PLARGE_INTEGER DefaultTimeout (opcional).
    pub default_timeout: u64,
}

/// Os argumentos próprios do NtCreateMailslotFile.
#[derive(Clone, Copy, Default)]
pub struct MailslotArguments {
    pub create_options: u32,
    pub mailslot_quota: u32,
    pub maximum_message_size: u32,
    /// PLARGE_INTEGER ReadTimeout (opcional).
    pub read_timeout: u64,
}

/// O LARGE_INTEGER opcional de modo usuário: ProbeForRead alinhado a 4 e
/// a leitura sondada.
fn capture_timeout(pointer: u64) -> Result<Option<i64>, u32> {
    if pointer == 0 {
        return Ok(None);
    }
    if pointer & 3 != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    guest::try_read::<i64>(pointer).map(Some).map_err(|_| STATUS_ACCESS_VIOLATION)
}

/// A validação geral do IopCreateFile para um chamador de modo usuário
/// (FileAttributes é zero nos dois serviços).
fn check_create(arguments: &CreateArguments) -> Result<(), u32> {
    let (access, share, disposition, options) = (arguments.desired_access, arguments.share_access, arguments.disposition, arguments.create_options);
    let invalid = share & !7 != 0
        || disposition > 5
        || options & 0xEF00_0000 != 0
        || (options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) != 0 && access & SYNCHRONIZE == 0)
        || (options & FILE_DELETE_ON_CLOSE != 0 && access & DELETE == 0)
        || options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT) == (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)
        || (options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE) == FILE_DIRECTORY_FILE && (options & 0xEF5E_0ACC != 0 || !(1..=3).contains(&disposition)))
        || options & 0x10_0100 == 0x10_0100
        || options & 0x1_0100 == 0x1_0100
        || options & 0x11_0000 == 0x11_0000
        || (options & FILE_NO_INTERMEDIATE_BUFFERING != 0 && access & FILE_APPEND_DATA != 0);
    if invalid {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(())
    }
}

/// As opções aceitas num pipe ou mailslot: FILE_WRITE_THROUGH e as
/// síncronas.
fn check_special_options(options: u32) -> Result<(), u32> {
    if options & 0xFFFF_FFCD != 0 {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(())
    }
}

fn allocate(size: u64, file_type: u8) -> Result<Captured, u32> {
    let pointer = guest::alloc_bytes(size);
    if pointer == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    Ok(Captured { pointer, file_type })
}

/// NtCreateNamedPipeFile: o DefaultTimeout capturado, a validação do
/// IopCreateFile e o NAMED_PIPE_CREATE_PARAMETERS.
pub fn capture_named_pipe(create: &CreateArguments, pipe: &NamedPipeArguments) -> Result<Captured, u32> {
    let timeout = capture_timeout(pipe.default_timeout)?;
    check_create(create)?;
    if pipe.named_pipe_type & !3 != 0 || pipe.read_mode > 1 || pipe.completion_mode > 1 || create.share_access & FILE_SHARE_DELETE != 0 || !(1..=3).contains(&create.disposition) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    check_special_options(create.create_options)?;
    let captured = allocate(NamedPipeCreateParameters::SIZE, CREATE_FILE_TYPE_NAMED_PIPE)?;
    // SAFETY: bloco recém-alocado do tamanho da estrutura.
    let parameters = unsafe { NamedPipeCreateParameters::at(captured.pointer) };
    parameters.named_pipe_type.set(pipe.named_pipe_type);
    parameters.read_mode.set(pipe.read_mode);
    parameters.completion_mode.set(pipe.completion_mode);
    parameters.maximum_instances.set(pipe.maximum_instances);
    parameters.inbound_quota.set(pipe.inbound_quota);
    parameters.outbound_quota.set(pipe.outbound_quota);
    parameters.default_timeout.quad_part.set(timeout.unwrap_or(0));
    parameters.timeout_specified.set(timeout.is_some() as u8);
    Ok(captured)
}

/// Os argumentos do IoCreateFile de um NtCreateMailslotFile.
pub fn mailslot_create_arguments(desired_access: u32, mailslot: &MailslotArguments) -> CreateArguments {
    CreateArguments { desired_access, share_access: FILE_SHARE_READ | FILE_SHARE_WRITE, disposition: FILE_CREATE, create_options: mailslot.create_options }
}

/// NtCreateMailslotFile: o ReadTimeout capturado, a validação do
/// IopCreateFile e o MAILSLOT_CREATE_PARAMETERS.
pub fn capture_mailslot(create: &CreateArguments, mailslot: &MailslotArguments) -> Result<Captured, u32> {
    let timeout = capture_timeout(mailslot.read_timeout)?;
    check_create(create)?;
    if create.share_access & FILE_SHARE_DELETE != 0 || create.share_access & !FILE_SHARE_WRITE == 0 || create.disposition != FILE_CREATE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    check_special_options(create.create_options)?;
    let captured = allocate(MailslotCreateParameters::SIZE, CREATE_FILE_TYPE_MAILSLOT)?;
    // SAFETY: bloco recém-alocado do tamanho da estrutura.
    let parameters = unsafe { MailslotCreateParameters::at(captured.pointer) };
    parameters.mailslot_quota.set(mailslot.mailslot_quota);
    parameters.maximum_message_size.set(mailslot.maximum_message_size);
    parameters.read_timeout.quad_part.set(timeout.unwrap_or(0));
    parameters.timeout_specified.set(timeout.is_some() as u8);
    Ok(captured)
}
