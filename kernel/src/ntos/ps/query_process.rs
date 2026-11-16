//! Consulta de informações de processo em modo kernel
//! (ZwQueryInformationProcess).
//!
//! ProcessImageInformation (37) vem de `image_information`;
//! ProcessBasicInformation (0) é montado do EPROCESS achado pelo pid do
//! handle; ProcessDebugFlags (31) é o PROCESS_DEBUG_INHERIT do
//! NoDebugInherit, com o handle referenciado com PROCESS_QUERY_INFORMATION.
//! As demais classes devolvem STATUS_INVALID_PARAMETER.

use super::{image_information, process};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, ProcessBasicInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, object_types, reference_trace};
use crate::rtl::KernelError;

const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// PROCESS_QUERY_INFORMATION.
const PROCESS_QUERY_INFORMATION: u32 = 0x400;

/// ObReferenceObjectByHandle(handle, access, PsProcessType, KernelMode):
/// `Ok(Ok(EPROCESS))` com uma referência que [`release_process`] solta, ou o
/// NTSTATUS da recusa.
pub fn reference_process(handle: u64, access: u32) -> Result<Result<u64, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let result = object_reference::reference_by_handle(handle, access, object_types::process_type().pointer, 0, slot, 0);
    // SAFETY: célula PVOID recém-alocada.
    let pointer = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    Ok(match result? {
        0 => Ok(pointer),
        status => Err(status as u32),
    })
}

/// Solta a referência de [`reference_process`].
pub fn release_process(process: u64) -> Result<(), KernelError> {
    object_reference::dereference_with_tag(process, reference_trace::DEFAULT_TAG, false).map(|_| ())
}

/// ProcessDebugFlags: um ULONG (outro tamanho dá
/// STATUS_INFO_LENGTH_MISMATCH), 1 quando o processo passa o depurador
/// adiante (NoDebugInherit desligado); ReturnLength recebe 4.
fn query_debug_flags(handle: u64, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if length != 4 {
        return Ok(0xC000_0004);
    }
    let process = match reference_process(handle, PROCESS_QUERY_INFORMATION)? {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pela referência acima.
    let inherit = unsafe { Eprocess::at(process) }.no_debug_inherit() ^ 1;
    // SAFETY: PULONG de saída e ReturnLength opcional do chamador de kernel.
    unsafe { Field::<u32>::at(output) }.set(inherit);
    if returned != 0 {
        // SAFETY: idem.
        unsafe { Field::<u32>::at(returned) }.set(4);
    }
    release_process(process)?;
    Ok(0)
}

/// ZwQueryInformationProcess: ProcessImageInformation (37),
/// ProcessDebugFlags (31) e ProcessBasicInformation (0). Devolve o NTSTATUS.
pub fn query_information(handle: u64, class: u32, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    if class == 37 {
        return image_information::query(handle, output, length, returned, 0, None);
    }
    if class == 31 {
        return query_debug_flags(handle, output, length, returned);
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

// ---- NtQueryInformationProcess (ntoskrnl 19041 rva 0x6216c0) --------------------
//
// O export Nt* usa o PreviousMode da thread. Em KernelMode é o mesmo serviço
// do ZwQueryInformationProcess. Em UserMode o prólogo sonda os parâmetros
// antes de qualquer classe: com ProcessInformationLength != 0, o buffer tem
// de estar alinhado ao da classe (byte para 61, 70, 74 e 87; quadword para
// 65, 92 e 94; ULONG para as demais), senão STATUS_DATATYPE_MISALIGNMENT, e
// a faixa inteira abaixo de MmUserProbeAddress, senão
// STATUS_ACCESS_VIOLATION; um ReturnLength é tocado para escrita (o ULONG em
// min(ReturnLength, MmUserProbeAddress)). O handle de UserMode não pode ser
// um handle de kernel (STATUS_INVALID_HANDLE do ObReferenceObjectByHandle).

const STATUS_DATATYPE_MISALIGNMENT_PROBE: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION_PROBE: u32 = 0xC000_0005;
/// KernelMode/UserMode do KPROCESSOR_MODE.
const USER_MODE: u8 = 1;

/// O alinhamento que o prólogo exige do buffer da classe (máscara).
fn information_alignment(class: u32) -> u64 {
    match class {
        61 | 70 | 74 | 87 => 0,
        65 | 92 | 94 => 7,
        _ => 3,
    }
}

/// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass,
/// ProcessInformation, ProcessInformationLength, ReturnLength) no modo
/// anterior `mode`: devolve o NTSTATUS.
pub fn nt_query_information(handle: u64, class: u32, output: u64, length: u32, returned: u64, mode: u8) -> Result<u32, KernelError> {
    if mode == USER_MODE {
        use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
        if length != 0 {
            if output & information_alignment(class) != 0 {
                return Ok(STATUS_DATATYPE_MISALIGNMENT_PROBE);
            }
            let end = output.wrapping_add(length as u64);
            if end > USER_PROBE_ADDRESS || end < output {
                return Ok(STATUS_ACCESS_VIOLATION_PROBE);
            }
        }
        if returned != 0 {
            let probe = returned.min(USER_PROBE_ADDRESS);
            if probe >= USER_PROBE_ADDRESS {
                return Ok(STATUS_ACCESS_VIOLATION_PROBE);
            }
            match guest::try_read::<u32>(probe) {
                Ok(value) => {
                    if let Err(error) = guest::try_write::<u32>(probe, value) {
                        return Ok(error.status);
                    }
                }
                Err(error) => return Ok(error.status),
            }
        }
        // As classes atendidas referenciam o handle: um handle de kernel
        // (bit 63, fora os pseudo-handles) não vale em UserMode.
        if matches!(class, 0 | 31 | 37) && (handle as i64) < -8 {
            return Ok(STATUS_INVALID_HANDLE);
        }
    }
    query_information(handle, class, output, length, returned)
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
