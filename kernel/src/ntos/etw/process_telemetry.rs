//! A identidade de telemetria de um processo: EtwQueryProcessTelemetryInfo
//! (ntoskrnl 19041 0x611674), o ramo da classe ProcessTelemetryIdInformation
//! (64) do NtQueryInformationProcess.
//!
//! O PROCESS_TELEMETRY_ID_INFORMATION tem um cabeçalho de 0x60 bytes (PID,
//! chave de início, tempos de criação, número de sequência, sessão, BootId,
//! checksum e data da imagem) e, depois dele, cinco textos: o SID do
//! usuário do token primário, o caminho NT da imagem (o nome de auditoria
//! do EPROCESS), o nome do pacote, o nome relativo do aplicativo e a linha
//! de comando do PEB (no máximo 0x400 bytes, com os NULs trocados por
//! espaços). Os textos levam o terminador zerado pelo memset inicial. O
//! tamanho necessário vai para o ReturnLength antes de tudo; com menos de
//! 0x60 bytes a resposta é STATUS_INFO_LENGTH_MISMATCH, e com o cabeçalho
//! cabendo mas não os textos, STATUS_BUFFER_OVERFLOW com o cabeçalho
//! preenchido (o dcomp.dll pergunta o tamanho assim e pergunta de novo com o
//! buffer certo).

use alloc::vec;
use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::ex::rundown;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_ps_user::ProcessTelemetryIdInformation;
use crate::ntos::inc::types::{Eprocess, ImageNtHeaders64, UnicodeString};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
use crate::ntos::ps::{process_context, security, session};
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

/// PROCESSINFOCLASS ProcessTelemetryIdInformation.
pub const PROCESS_TELEMETRY_ID_INFORMATION: u32 = 64;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
/// O tamanho do cabeçalho, gravado em HeaderSize.
const HEADER_SIZE: u32 = ProcessTelemetryIdInformation::SIZE as u32;
/// SECURITY_MAX_SID_SIZE: o buffer do SID do usuário.
const MAXIMUM_SID_SIZE: u32 = 0x44;
/// Os buffers do nome do pacote e do nome relativo do aplicativo do
/// EtwpQueryTokenPackageInfo (0x100 e 0x82 bytes).
const PACKAGE_NAME_BYTES: u64 = 0x100;
const RELATIVE_APP_NAME_BYTES: u64 = 0x82;
/// O EtwpQueryProcessCommandLine copia no máximo 0x400 bytes.
const COMMAND_LINE_LIMIT: u16 = 0x400;
/// PEB->ProcessParameters e RTL_USER_PROCESS_PARAMETERS.CommandLine.
const PEB_PROCESS_PARAMETERS: u64 = offset_of!(crate::ntos::inc::types::Peb, process_parameters) as u64;
const PARAMETERS_COMMAND_LINE: u64 = offset_of!(crate::ntos::inc::types::RtlUserProcessParameters, command_line) as u64;

/// O nome do pacote e o nome relativo do aplicativo, cada um com o
/// terminador (o EtwpQueryTokenPackageInfo, 19041 0x6023fc).
struct PackageNames {
    package: Vec<u8>,
    relative_application: Vec<u8>,
}

/// EtwpQueryTokenPackageInfo: sem o PspSysAppIdClaim no token, os dois
/// nomes são o texto vazio (2 bytes, o terminador); com ele, o
/// RtlQueryPackageIdentity nos buffers de 0x100 e 0x82 bytes, e uma falha
/// também deixa os dois vazios.
fn package_names(token: u64) -> Result<PackageNames, KernelError> {
    let empty = || PackageNames { package: vec![0; 2], relative_application: vec![0; 2] };
    let (system_application, _packaged) = security::token_attributes(token)?;
    if !system_application {
        return Ok(empty());
    }
    // O bloco do 19041: os dois SIZE_T e os dois buffers, em memória do
    // kernel, como as variáveis locais da rotina.
    let block = guest::alloc_bytes(16 + PACKAGE_NAME_BYTES + RELATIVE_APP_NAME_BYTES);
    if block == 0 {
        return Ok(empty());
    }
    let (package_size, application_size) = (block, block + 8);
    let (package, application) = (block + 16, block + 16 + PACKAGE_NAME_BYTES);
    guest::write64(package_size, PACKAGE_NAME_BYTES);
    guest::write64(application_size, RELATIVE_APP_NAME_BYTES);
    let status = crate::ntos::se::package_identity::query(token, package, package_size, application, application_size, 0);
    let name = |buffer: u64, size: u64, limit: u64| match guest::read64(size) {
        0 => vec![0; 2],
        bytes => guest::read_bytes(buffer, bytes.min(limit) as usize),
    };
    let names = match status {
        Ok(status) if status & 0x8000_0000 == 0 => PackageNames { package: name(package, package_size, PACKAGE_NAME_BYTES), relative_application: name(application, application_size, RELATIVE_APP_NAME_BYTES) },
        _ => empty(),
    };
    guest::free_bytes(block);
    Ok(names)
}

/// SeQueryUserSidToken (19041 0x6544b4): o SID do usuário do token, se cabe
/// em `limit` bytes; o tamanho sai nos dois casos.
fn user_sid(token: u64, limit: u32) -> (u32, Option<Vec<u8>>) {
    let sid = tokens::with(token, |token| token.user.clone()).unwrap_or_default();
    // RtlLengthSid: 8 + 4 * SubAuthorityCount.
    let length = 8 + 4 * sid.get(1).copied().unwrap_or(0) as u32;
    if length > limit {
        return (length, None);
    }
    let mut copy = sid;
    copy.resize(length as usize, 0);
    (length, Some(copy))
}

/// EtwpQueryProcessOtherInfo (19041 0x602928): o CheckSum do cabeçalho
/// opcional e o TimeDateStamp da imagem principal, pelo RtlImageNtHeader da
/// SectionBaseAddress no processo anexado; zeros sem imagem.
fn image_identity(process: &Eprocess) -> (u32, u32) {
    let base = process.section_base_address.get();
    if base == 0 {
        return (0, 0);
    }
    let Ok(header) = crate::ntos::rtl::image::nt_header(base) else { return (0, 0) };
    if header == 0 {
        return (0, 0);
    }
    let checksum = guest::try_read::<u32>(header + offset_of!(ImageNtHeaders64, optional_header.check_sum) as u64).unwrap_or(0);
    let stamp = guest::try_read::<u32>(header + offset_of!(ImageNtHeaders64, file_header.time_date_stamp) as u64).unwrap_or(0);
    (checksum, stamp)
}

/// EtwpQueryProcessCommandLine (19041 0x602968), no processo anexado: o
/// CommandLine do RTL_USER_PROCESS_PARAMETERS do PEB, com o Length par e
/// limitado a 0x400 bytes; um NUL no meio vira espaço. Uma exceção na
/// leitura (buffer ímpar, fora da faixa de usuário ou sem página) deixa o
/// texto vazio, como o Length zero que a rotina devolve.
fn command_line(process: &Eprocess) -> Vec<u8> {
    let peb = process.peb.get();
    if peb == 0 {
        return Vec::new();
    }
    let read = || -> Result<Vec<u8>, KernelError> {
        let parameters = guest::try_read::<u64>(peb + PEB_PROCESS_PARAMETERS)?;
        let string = (parameters + PARAMETERS_COMMAND_LINE).min(USER_PROBE_ADDRESS);
        let length = guest::try_read::<u32>(string)? as u16 & 0xFFFE;
        let buffer = guest::try_read::<u64>(string + 8)?;
        if length == 0 || buffer == 0 {
            return Ok(Vec::new());
        }
        let end = buffer.wrapping_add(length as u64);
        if buffer & 1 != 0 || end > USER_PROBE_ADDRESS || end < buffer {
            return Err(KernelError::with_status("linha de comando fora da faixa de usuario", STATUS_ACCESS_VIOLATION));
        }
        let mut bytes = guest::try_read_bytes(buffer, length.min(COMMAND_LINE_LIMIT) as usize)?;
        for unit in bytes.chunks_exact_mut(2) {
            if unit == [0, 0] {
                unit.copy_from_slice(&0x20u16.to_le_bytes());
            }
        }
        Ok(bytes)
    };
    read().unwrap_or_default()
}

/// EtwQueryProcessTelemetryInfo(Process, Buffer, Length, PreviousMode,
/// ReturnLength*): o processo já referenciado pelo chamador; em UserMode, o
/// alinhamento e a faixa do buffer e o ReturnLength já foram sondados pelo
/// NtQueryInformationProcess, e aqui vem o ProbeForWrite do buffer. Uma
/// falha de acesso à memória de usuário é STATUS_ACCESS_VIOLATION, o
/// `__except` da rotina.
pub fn query(process_pointer: u64, output: u64, length: u32, previous_mode: u8, returned: u64) -> Result<u32, KernelError> {
    // SAFETY: EPROCESS retido pela referência do chamador.
    let process = unsafe { Eprocess::at(process_pointer) };
    let image_name = process.se_audit_process_creation_info.image_file_name.get();
    let image_path = if image_name == 0 {
        Vec::new()
    } else {
        // SAFETY: o OBJECT_NAME_INFORMATION de auditoria criado com o processo.
        let name = unsafe { UnicodeString::at(image_name) };
        guest::read_bytes(name.buffer.get(), name.length.get() as usize)
    };
    let token = security::reference_primary_token(process_pointer)?;
    let result = (|| -> Result<u32, KernelError> {
        let names = package_names(token)?;
        let (sid_length, sid) = user_sid(token, MAXIMUM_SID_SIZE);
        let Some(sid) = sid else { return Ok(STATUS_BUFFER_TOO_SMALL) };
        // PsAcquireProcessExitSynchronization: sem o rundown (o processo
        // está saindo), a imagem e a linha de comando ficam vazias.
        let rundown_pointer = process.rundown_protect.address();
        let ((checksum, stamp), command) = if rundown::acquire(rundown_pointer)? {
            let read = process_context::with_process(process_pointer, || (image_identity(process), command_line(process)));
            rundown::release(rundown_pointer)?;
            read?
        } else {
            ((0, 0), Vec::new())
        };
        // Os dois terminadores (o do caminho e o da linha de comando) somam
        // 4 bytes ao cabeçalho; os nomes do pacote já os contam.
        let required = sid_length
            .wrapping_add(HEADER_SIZE + 4)
            .wrapping_add(image_path.len() as u32)
            .wrapping_add(names.package.len() as u32)
            .wrapping_add(names.relative_application.len() as u32)
            .wrapping_add(command.len() as u32);
        if returned != 0 && guest::try_write::<u32>(returned, required).is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let written = (|| -> Result<u32, KernelError> {
            macro_rules! field {
                ($name:ident, $value:expr) => {
                    guest::try_write(output + offset_of!(ProcessTelemetryIdInformation, $name) as u64, $value)?
                };
            }
            if previous_mode != 0 && length != 0 && !crate::ntos::ps::user::state::probe_user_write(output, length as u64) {
                return Ok(STATUS_ACCESS_VIOLATION);
            }
            guest::try_write_bytes(output, &vec![0u8; required.min(length) as usize])?;
            if length < HEADER_SIZE {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            // O buffer só tem o alinhamento 4 do ProbeForWrite: cada campo é
            // uma escrita sondada no próprio offset.
            let boot_id = crate::ntos::mm::shared_user_data::data().map_or(0, |data| data.boot_id.get());
            field!(header_size, HEADER_SIZE);
            field!(process_id, process.unique_process_id.get() as u32);
            // EtwpGetProcessStartKey: o BootId nos 16 bits altos do número de
            // sequência.
            field!(process_start_key, ((boot_id as u64) << 48) | process.sequence_number.get());
            field!(create_time, process.create_time.quad_part.get() as u64);
            field!(create_interrupt_time, process.create_interrupt_time.get());
            field!(create_unbiased_interrupt_time, process.create_unbiased_interrupt_time.get());
            field!(process_sequence_number, process.sequence_number.get());
            field!(session_create_time, crate::ntos::mm::session::session_create_time(process_pointer));
            field!(session_id, session::query(process_pointer));
            field!(boot_id, boot_id);
            field!(image_checksum, checksum);
            field!(image_time_date_stamp, stamp);
            if length < required {
                return Ok(STATUS_BUFFER_OVERFLOW);
            }
            // Os textos, cada um no offset gravado antes dele; o terminador
            // do caminho e o da linha de comando já são zeros.
            let mut at = HEADER_SIZE;
            field!(user_sid_offset, at);
            guest::try_write_bytes(output + at as u64, &sid)?;
            at += sid_length;
            field!(image_path_offset, at);
            guest::try_write_bytes(output + at as u64, &image_path)?;
            at += image_path.len() as u32 + 2;
            field!(package_name_offset, at);
            guest::try_write_bytes(output + at as u64, &names.package)?;
            at += names.package.len() as u32;
            field!(relative_app_name_offset, at);
            guest::try_write_bytes(output + at as u64, &names.relative_application)?;
            at += names.relative_application.len() as u32;
            field!(command_line_offset, at);
            guest::try_write_bytes(output + at as u64, &command)?;
            Ok(0)
        })();
        match written {
            Err(error) if error.status != 0 => Ok(error.status),
            other => other,
        }
    })();
    security::dereference_primary_token(token)?;
    result
}
