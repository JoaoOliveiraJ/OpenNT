//! Consulta de informações de processo em modo kernel
//! (ZwQueryInformationProcess).
//!
//! ProcessImageInformation (37) vem de `image_information`;
//! ProcessBasicInformation (0) é montado do EPROCESS achado pelo pid do
//! handle. As demais classes devolvem STATUS_INVALID_PARAMETER.

use super::{image_information, process};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, ProcessBasicInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

/// ZwQueryInformationProcess: ProcessImageInformation (37) e
/// ProcessBasicInformation (0). Devolve o NTSTATUS.
pub fn query_information(handle: u64, class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if class == 37 {
        return image_information::query(handle, output, length, returned, 0, None);
    }
    if class != 0 {
        return Ok(0xC000_000D);
    }
    if (length as u64) < ProcessBasicInformation::SIZE {
        if returned != 0 {
            // SAFETY: PULONG ReturnLength do chamador de kernel.
            unsafe { Field::<u32>::at(returned) }.set(ProcessBasicInformation::SIZE as u32);
        }
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let pid = process::process_id_from_handle(handle);
    let Some(target) = process::list_active_processes().into_iter().find(|entry| entry.pid == pid) else { return Ok(STATUS_INVALID_HANDLE) };
    // Zera o buffer inteiro (o preenchimento também) antes dos campos.
    guest::write_bytes(output, &[0; ProcessBasicInformation::SIZE as usize]);
    // SAFETY: PROCESS_BASIC_INFORMATION do chamador de kernel (tamanho conferido).
    let information = unsafe { ProcessBasicInformation::at(output) };
    information.exit_status.set(0x103);
    // SAFETY: EPROCESS achado na lista de processos ativos.
    information.peb_base_address.set(unsafe { Eprocess::at(target.address) }.peb.get());
    information.affinity_mask.set(1);
    information.base_priority.set(8);
    information.unique_process_id.set(pid);
    information.inherited_from_unique_process_id.set(4);
    if returned != 0 {
        // SAFETY: PULONG ReturnLength do chamador de kernel.
        unsafe { Field::<u32>::at(returned) }.set(ProcessBasicInformation::SIZE as u32);
    }
    Ok(0)
}

// ---- PsQueryProcessCommandLine -------------------------------------------------
//
// Como o PsQueryProcessCommandLine do ntoskrnl 19041 (rva 0x3184e0): sob o
// rundown do processo (STATUS_PROCESS_IS_TERMINATING se ele já sai), anexado
// a ele, lê o CommandLine dos parâmetros (PEB->ProcessParameters +0x70; num
// processo WoW64, PEB32->ProcessParameters +0x10 e o UNICODE_STRING32 em
// +0x40) dentro do __try, com o ProbeForRead do buffer (alinhamento de
// WCHAR, faixa de usuário); sem PEB é STATUS_NOT_FOUND. Depois do detach,
// um CommandLine vazio, ímpar, com Length > MaximumLength ou sem buffer é
// STATUS_NOT_FOUND. O tamanho necessário (MaximumLength + 0x10) vai para
// *ReturnLength; com espaço, o UNICODE_STRING de saída aponta para logo
// depois dele e os MaximumLength bytes vêm do processo pelo
// MmCopyVirtualMemory no modo pedido.

const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
/// PEB->ProcessParameters e RTL_USER_PROCESS_PARAMETERS.CommandLine.
const PEB_PROCESS_PARAMETERS: u64 = core::mem::offset_of!(crate::ntos::inc::types::Peb, process_parameters) as u64;
const PARAMETERS_COMMAND_LINE: u64 = core::mem::offset_of!(crate::ntos::inc::types::RtlUserProcessParameters, command_line) as u64;
/// PEB32->ProcessParameters e RTL_USER_PROCESS_PARAMETERS32.CommandLine.
const PEB32_PROCESS_PARAMETERS: u64 = 0x10;
const PARAMETERS32_COMMAND_LINE: u64 = 0x40;

/// O CommandLine (Length, MaximumLength, Buffer) lido da memória do
/// processo anexado; o erro é o código da exceção do __try.
fn captured_command_line(process: &Eprocess) -> Result<(u16, u16, u64), u32> {
    use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
    let read32 = |address: u64| guest::try_read::<u32>(address).map_err(|error| error.status);
    let read64 = |address: u64| guest::try_read::<u64>(address).map_err(|error| error.status);
    let wow64 = process.wo_w64_process.get();
    // SAFETY: EWOW64PROCESS (Peb32 em +0) de um processo vivo.
    let peb32 = if wow64 != 0 { unsafe { Field::<u64>::at(wow64) }.get() } else { 0 };
    let (length, maximum, buffer) = if peb32 != 0 {
        let parameters = read32(peb32 + PEB32_PROCESS_PARAMETERS)? as u64;
        let string = read64(parameters + PARAMETERS32_COMMAND_LINE)?;
        (string as u16, (string >> 16) as u16, string >> 32)
    } else {
        let peb = process.peb.get();
        if peb == 0 {
            return Err(STATUS_NOT_FOUND);
        }
        let parameters = read64(peb + PEB_PROCESS_PARAMETERS)?;
        let string = (parameters + PARAMETERS_COMMAND_LINE).min(USER_PROBE_ADDRESS);
        let lengths = read32(string)?;
        (lengths as u16, (lengths >> 16) as u16, read64(string + 8)?)
    };
    // ProbeForRead(Buffer, MaximumLength, sizeof(WCHAR)).
    if maximum != 0 {
        if buffer & 1 != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let end = buffer.wrapping_add(maximum as u64);
        if end > USER_PROBE_ADDRESS || end < buffer {
            return Err(STATUS_ACCESS_VIOLATION);
        }
    }
    Ok((length, maximum, buffer))
}

/// PsQueryProcessCommandLine(Process, CommandLine, BufferLength, AccessMode,
/// ReturnLength*): devolve o NTSTATUS. `output` e `return_length` são do
/// chamador de modo kernel.
pub fn query_command_line(process: &Eprocess, output: u64, buffer_length: u32, access_mode: u8, return_length: u64) -> Result<u32, KernelError> {
    use crate::ntos::ex::rundown;
    use crate::ntos::inc::types::UnicodeString;
    use crate::ntos::mm::copy_virtual;
    use crate::ntos::ps::process_context;
    let rundown_pointer = process.rundown_protect.address();
    if !rundown::acquire(rundown_pointer)? {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    let result = (|| -> Result<u32, KernelError> {
        let (length, maximum, buffer) = match process_context::with_process(process.address(), || captured_command_line(process))? {
            Ok(captured) => captured,
            Err(status) => return Ok(status),
        };
        if length == 0 || length > maximum || length & 1 != 0 || maximum & 1 != 0 || buffer == 0 {
            return Ok(STATUS_NOT_FOUND);
        }
        let required = maximum as u32 + UnicodeString::SIZE as u32;
        if return_length != 0 {
            // SAFETY: PULONG ReturnLength do chamador de modo kernel.
            unsafe { Field::<u32>::at(return_length) }.set(required);
        }
        if buffer_length < required {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        // SAFETY: o UNICODE_STRING de saída do chamador (tamanho conferido).
        let string = unsafe { UnicodeString::at(output) };
        string.length.set(length);
        string.maximum_length.set(maximum);
        string.buffer.set(output + UnicodeString::SIZE);
        let (status, _) = copy_virtual::copy_virtual_memory(process.address(), buffer, process::get_current_process(), output + UnicodeString::SIZE, maximum as u64, access_mode)?;
        Ok(if (status as i32) < 0 { status } else { 0 })
    })();
    rundown::release(rundown_pointer)?;
    result
}
