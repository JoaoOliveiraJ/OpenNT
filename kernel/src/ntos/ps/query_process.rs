//! Consulta de informações de processo em modo kernel
//! (ZwQueryInformationProcess).
//!
//! ProcessImageInformation (37) vem de `image_information`;
//! ProcessBasicInformation (0), na forma de 0x30 bytes ou na estendida de
//! 0x40 (com Size e Flags), é lido do EPROCESS do handle; ProcessDebugFlags
//! (31) é o PROCESS_DEBUG_INHERIT do NoDebugInherit, com o handle
//! referenciado com PROCESS_QUERY_INFORMATION. As demais classes devolvem
//! STATUS_INVALID_PARAMETER.

use super::{image_information, process};
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, Ewow64process, ProcessBasicInformation, ProcessExtendedBasicInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, object_types, reference_trace};
use crate::rtl::KernelError;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// PROCESS_QUERY_INFORMATION.
const PROCESS_QUERY_INFORMATION: u32 = 0x400;

/// PROCESSINFOCLASS ProcessDefaultHardErrorMode e ProcessHandleCheckingMode.
pub const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
pub const PROCESS_HANDLE_CHECKING_MODE: u32 = 54;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// NtQueryInformationProcess das classes de modo do processo (ntoskrnl
/// 19041, rvas 0x621eda e 0x6240d6), com o buffer e o ReturnLength já
/// sondados em UserMode; `process_of` resolve o handle com o acesso pedido.
///
/// - ProcessDefaultHardErrorMode (12): um ULONG (outro tamanho dá
///   STATUS_INFO_LENGTH_MISMATCH), PROCESS_QUERY_LIMITED_INFORMATION, o
///   EPROCESS.DefaultHardErrorProcessing e ReturnLength 4.
/// - ProcessHandleCheckingMode (54): um ULONG, PROCESS_QUERY_INFORMATION, 1
///   com HANDLE_TABLE.EnableHandleExceptions ligado (ExQueryHandleExceptions)
///   e 0 sem; sem tabela, STATUS_PROCESS_IS_TERMINATING. O ReturnLength não
///   é gravado.
pub fn query_mode(class: u32, output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 4 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let access = if class == PROCESS_DEFAULT_HARD_ERROR_MODE { PROCESS_QUERY_LIMITED_INFORMATION } else { PROCESS_QUERY_INFORMATION };
    let process = match process_of(access) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    if class == PROCESS_DEFAULT_HARD_ERROR_MODE {
        guest::try_write::<u32>(output, eprocess.default_hard_error_processing.get())?;
        if returned != 0 {
            guest::try_write::<u32>(returned, 4)?;
        }
        return Ok(0);
    }
    let table = crate::ntos::ob::handles::process::reference(process)?;
    if table == 0 {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    // SAFETY: HANDLE_TABLE do EPROCESS.ObjectTable, retida pelo rundown.
    let enabled = unsafe { crate::ntos::inc::types::HandleTable::at(table) }.enable_handle_exceptions() != 0;
    crate::ntos::ob::handles::process::release(process)?;
    guest::try_write::<u32>(output, enabled as u32)?;
    Ok(0)
}

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
    query_basic(handle, output, length, returned)
}

/// O tamanho do PROCESS_BASIC_INFORMATION e o do
/// PROCESS_EXTENDED_BASIC_INFORMATION (Size, a básica e Flags).
pub const BASIC_INFORMATION_SIZE: u32 = ProcessBasicInformation::SIZE as u32;
pub const EXTENDED_BASIC_INFORMATION_SIZE: u32 = ProcessExtendedBasicInformation::SIZE as u32;

/// Os campos do ProcessBasicInformation de um EPROCESS, como o
/// NtQueryInformationProcess 19041 os lê (rva 0x621cc1..0x621ebb).
pub struct BasicInformation {
    /// EPROCESS.ExitStatus (STATUS_PENDING enquanto vivo).
    pub exit_status: i32,
    /// EPROCESS.Peb.
    pub peb_base_address: u64,
    /// A afinidade do processo (o escalonador de usuário roda no BSP).
    pub affinity_mask: u64,
    /// KPROCESS.BasePriority.
    pub base_priority: i32,
    pub unique_process_id: u64,
    pub inherited_from_unique_process_id: u64,
    /// Os Flags da forma estendida.
    pub flags: u32,
}

/// Lê o ProcessBasicInformation de `process`. Os Flags da forma estendida:
/// IsProtectedProcess (PsIsProtectedProcess), IsWow64Process (WoW64Process
/// com Machine x86 0x14C ou ARM 0x1C4), IsProcessDeleting (ProcessDelete ou
/// ProcessSelfDelete), IsCrossSessionCreate (Flags2.CrossSessionCreate),
/// IsFrozen (DeepFreeze + FreezeCount do KPROCESS), IsBackground,
/// IsStronglyNamed (WIN://SYSAPPID no token primário, o
/// PsQueryProcessAttributes), IsSecureProcess (SecureState.SecureProcess) e
/// IsSubsystemProcess (PicoContext).
pub fn basic_information(process: u64) -> BasicInformation {
    // SAFETY: EPROCESS retido por quem consulta.
    let eprocess = unsafe { Eprocess::at(process) };
    let pcb = &eprocess.pcb;
    let wow64 = eprocess.wo_w64_process.get();
    // SAFETY: o EWOW64PROCESS de um processo WoW64, retido com ele.
    let wow64_machine = if wow64 != 0 { unsafe { Ewow64process::at(wow64) }.machine.get() } else { 0 };
    let flag = |bit: u32, set: bool| if set { 1u32 << bit } else { 0 };
    let flags = flag(0, super::process_accessors::is_protected(process))
        | flag(1, matches!(wow64_machine, 0x14C | 0x1C4))
        | flag(2, eprocess.process_delete() != 0 || eprocess.process_self_delete() != 0)
        | flag(3, eprocess.cross_session_create() != 0)
        | flag(4, pcb.deep_freeze() + pcb.freeze_count.get() != 0)
        | flag(5, eprocess.background() != 0)
        | flag(6, super::security::is_system_application(process))
        | flag(7, pcb.secure_state.flags.secure_process() != 0)
        | flag(8, eprocess.pico_context.get() != 0);
    BasicInformation {
        exit_status: eprocess.exit_status.get(),
        peb_base_address: eprocess.peb.get(),
        affinity_mask: 1,
        base_priority: pcb.base_priority.get() as i32,
        unique_process_id: eprocess.unique_process_id.get(),
        inherited_from_unique_process_id: eprocess.inherited_from_unique_process_id.get(),
        flags,
    }
}

/// ProcessBasicInformation de um chamador de kernel: ProcessInformationLength
/// 0x30 (PROCESS_BASIC_INFORMATION) ou 0x40 (PROCESS_EXTENDED_BASIC_INFORMATION,
/// com Size gravado antes de o handle ser referenciado); outro comprimento dá
/// STATUS_INFO_LENGTH_MISMATCH sem ReturnLength. O handle é referenciado com
/// PROCESS_QUERY_LIMITED_INFORMATION; os campos são gravados um a um (o
/// preenchimento fica como estava) e o ReturnLength recebe o comprimento.
fn query_basic(handle: u64, output: u64, length: u32, returned: u64) -> Result<u32, KernelError> {
    let extended = length == EXTENDED_BASIC_INFORMATION_SIZE;
    if !extended && length != BASIC_INFORMATION_SIZE {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    // SAFETY: o buffer do chamador de kernel, do comprimento conferido.
    let extended_information = unsafe { ProcessExtendedBasicInformation::at(output) };
    if extended {
        extended_information.size.set(EXTENDED_BASIC_INFORMATION_SIZE as u64);
    }
    let process = match reference_process(handle, PROCESS_QUERY_LIMITED_INFORMATION)? {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let values = basic_information(process);
    release_process(process)?;
    // SAFETY: idem; a básica fica depois do Size na forma estendida.
    let information = if extended { &extended_information.basic_info } else { unsafe { ProcessBasicInformation::at(output) } };
    information.exit_status.set(values.exit_status);
    information.peb_base_address.set(values.peb_base_address);
    information.affinity_mask.set(values.affinity_mask);
    information.base_priority.set(values.base_priority);
    information.unique_process_id.set(values.unique_process_id);
    information.inherited_from_unique_process_id.set(values.inherited_from_unique_process_id);
    if extended {
        extended_information.flags.set(values.flags);
    }
    if returned != 0 {
        // SAFETY: PULONG ReturnLength do chamador de kernel.
        unsafe { Field::<u32>::at(returned) }.set(length);
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

// ---- Classes de modo usuário do NtQueryInformationProcess -----------------
//
// As classes abaixo recebem o buffer e o ReturnLength já sondados pelo
// adaptador de modo usuário (o ProbeForWrite de alinhamento 4 e a faixa) e
// gravam com escrita sondada; `process_of` resolve o handle com o acesso
// pedido para o EPROCESS, retido enquanto dura a chamada.

/// ProcessQuotaLimits (1), ProcessVmCounters (3), ProcessTimes (4),
/// ProcessPriorityClass (18), ProcessImageFileNameWin32 (43) e
/// ProcessMitigationPolicy (52).
pub const PROCESS_QUOTA_LIMITS: u32 = 1;
pub const PROCESS_VM_COUNTERS: u32 = 3;
pub const PROCESS_TIMES: u32 = 4;
pub const PROCESS_PRIORITY_CLASS: u32 = 18;
pub const PROCESS_IMAGE_FILE_NAME_WIN32: u32 = 43;
pub const PROCESS_MITIGATION_POLICY: u32 = 52;

/// ProcessPriorityClass (o ramo da classe 18 do NtQueryInformationProcess
/// 19041, rva 0x6227d4): exatamente os 2 bytes do PROCESS_PRIORITY_CLASS
/// (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH antes do handle), o handle
/// com PROCESS_QUERY_LIMITED_INFORMATION; Foreground sai sempre FALSE (a
/// consulta não lê o estado de primeiro plano) e PriorityClass é o
/// EPROCESS.PriorityClass. ReturnLength 2. O GetPriorityClass do kernelbase
/// lê a classe por aqui.
pub fn query_priority_class(output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 2 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let class = unsafe { Eprocess::at(process) }.priority_class.get();
    guest::try_write::<u16>(output, u16::from(class) << 8)?;
    if returned != 0 {
        guest::try_write::<u32>(returned, 2)?;
    }
    Ok(0)
}

/// ProcessTimes (o ramo da classe 4, rva 0x62221e): exatamente os 0x20
/// bytes do KERNEL_USER_TIMES, o handle com
/// PROCESS_QUERY_LIMITED_INFORMATION; CreateTime e ExitTime do EPROCESS e os
/// tempos de kernel e de usuário do PsQueryRuntimeProcess (as threads vivas
/// e as que já saíram, em ticks) vezes o KeMaximumIncrement. ReturnLength
/// 0x20.
pub fn query_times(output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 0x20 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let increment = u64::from(crate::ntos::ke::clock::MAXIMUM_INCREMENT);
    let (kernel, user, _) = process::statistics(process);
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    let quad = |time: &crate::ntos::inc::types::LargeInteger| (time.high_part.get() as u32 as u64) << 32 | time.low_part.get() as u64;
    let times = [quad(&eprocess.create_time), quad(&eprocess.exit_time), (kernel / increment & 0xFFFF_FFFF) * increment, (user / increment & 0xFFFF_FFFF) * increment];
    for (index, value) in times.iter().enumerate() {
        guest::try_write::<u64>(output + index as u64 * 8, *value)?;
    }
    if returned != 0 {
        guest::try_write::<u32>(returned, 0x20)?;
    }
    Ok(0)
}

/// Monta `T` numa moldura própria zerada (a estrutura local do serviço) e
/// copia os primeiros `length` bytes para a saída do chamador (o memmove do
/// NT, dentro do __try).
fn copy_out<T: NtStruct + 'static>(output: u64, length: u32, fill: impl FnOnce(&T)) -> Result<Result<(), u32>, KernelError> {
    let scratch = guest::alloc_bytes(T::SIZE);
    if scratch == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(scratch, &alloc::vec![0u8; T::SIZE as usize]);
    // SAFETY: a moldura própria recém-alocada, com o tamanho de `T`.
    fill(unsafe { T::at(scratch) });
    let bytes = guest::read_bytes(scratch, (length as u64).min(T::SIZE) as usize);
    guest::free_bytes(scratch);
    guest::try_write_bytes(output, &bytes)?;
    Ok(Ok(()))
}

/// QUOTA_LIMITS_HARDWS_MIN_ENABLE/MIN_DISABLE/MAX_ENABLE/MAX_DISABLE.
const QUOTA_LIMITS_HARDWS_MIN_ENABLE: u32 = 1;
const QUOTA_LIMITS_HARDWS_MIN_DISABLE: u32 = 2;
const QUOTA_LIMITS_HARDWS_MAX_ENABLE: u32 = 4;
const QUOTA_LIMITS_HARDWS_MAX_DISABLE: u32 = 8;

/// ProcessQuotaLimits (o PspQueryQuotaLimits do ntoskrnl 19041, rva
/// 0x62069c): exatamente os 0x30 bytes do QUOTA_LIMITS ou os 0x58 do
/// QUOTA_LIMITS_EX (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH antes do
/// handle), o handle com PROCESS_QUERY_LIMITED_INFORMATION. Os limites de
/// pool são os do processo (`ps/pool_quota`, SIZE_T máximo sem limite
/// configurado); o OpenNT não impõe cota de arquivo de paginação nem de
/// working set (o bloco de cotas padrão do NT, ilimitado: SIZE_T máximo);
/// TimeLimit é -1; o mínimo e o máximo do working set vêm do
/// MmQueryWorkingSetInformation (`mm/process_usage`), e no EX as flags
/// HARDWS deles (MIN_ENABLE com o mínimo rígido, senão MIN_DISABLE;
/// MAX_ENABLE com o máximo rígido, senão MAX_DISABLE) e CpuRateLimit 0.
/// Copia `length` bytes e o ReturnLength recebe `length`.
pub fn query_quota_limits(output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::extra_ps_user::QuotaLimitsEx;
    use crate::ntos::mm::process_usage;
    if length != 0x30 && length as u64 != QuotaLimitsEx::SIZE {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let pools = super::pool_quota::snapshot(process).map(|[non_paged, paged]| (non_paged.limit, paged.limit)).unwrap_or((u64::MAX, u64::MAX));
    let working_set = process_usage::query_working_set(process);
    let minimum = if working_set.flags & process_usage::WORKING_SET_MINIMUM_HARD != 0 { QUOTA_LIMITS_HARDWS_MIN_ENABLE } else { QUOTA_LIMITS_HARDWS_MIN_DISABLE };
    let maximum = if working_set.flags & process_usage::WORKING_SET_MAXIMUM_HARD != 0 { QUOTA_LIMITS_HARDWS_MAX_ENABLE } else { QUOTA_LIMITS_HARDWS_MAX_DISABLE };
    let copied = copy_out::<QuotaLimitsEx>(output, length, |limits| {
        limits.paged_pool_limit.set(pools.1);
        limits.non_paged_pool_limit.set(pools.0);
        limits.minimum_working_set_size.set(working_set.minimum);
        limits.maximum_working_set_size.set(working_set.maximum);
        limits.pagefile_limit.set(u64::MAX);
        limits.time_limit.set(-1);
        limits.working_set_limit.set(u64::MAX);
        limits.flags.set(minimum | maximum);
        limits.cpu_rate_limit.set(0);
    })?;
    if let Err(status) = copied {
        return Ok(status);
    }
    if returned != 0 {
        guest::try_write::<u32>(returned, length)?;
    }
    Ok(0)
}

/// ProcessVmCounters (o ramo da classe 3 do NtQueryInformationProcess
/// 19041, rva 0x622077): os 0x58 bytes do VM_COUNTERS, os 0x60 do
/// VM_COUNTERS_EX ou os 0x70 do VM_COUNTERS_EX2 (outro tamanho dá
/// STATUS_INFO_LENGTH_MISMATCH antes do handle), o handle com
/// PROCESS_QUERY_LIMITED_INFORMATION. PeakVirtualSize e VirtualSize do VAD
/// e PageFaultCount do Vm (`mm/process_usage`); o working set (pico, atual e
/// privado) do MmQueryWorkingSetInformation; as cotas de pool paginável e
/// não paginável do PsQueryProcessQuotaCounters (`ps/pool_quota`);
/// PagefileUsage e PrivateUsage o CommitCharge, PeakPagefileUsage o
/// CommitChargePeak e SharedCommitUsage o SharedCommitCharge, em bytes.
/// Copia `length` bytes e o ReturnLength recebe `length`.
pub fn query_vm_counters(output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::extra_ps_user::VmCountersEx2;
    use crate::ntos::mm::process_usage;
    if length.wrapping_sub(0x58) & !0x18 != 0 || length == 0x68 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    let (peak_virtual, virtual_size) = process_usage::virtual_size(process);
    let working_set = process_usage::query_working_set(process);
    let pools = super::pool_quota::snapshot(process).ok();
    let copied = copy_out::<VmCountersEx2>(output, length, |counters| {
        counters.peak_virtual_size.set(peak_virtual);
        counters.virtual_size.set(virtual_size);
        counters.page_fault_count.set(eprocess.vm.instance.page_fault_count.get());
        counters.peak_working_set_size.set(working_set.peak);
        counters.working_set_size.set(working_set.current);
        if let Some([non_paged, paged]) = pools {
            counters.quota_peak_paged_pool_usage.set(paged.peak);
            counters.quota_paged_pool_usage.set(paged.usage);
            counters.quota_peak_non_paged_pool_usage.set(non_paged.peak);
            counters.quota_non_paged_pool_usage.set(non_paged.usage);
        }
        counters.pagefile_usage.set(eprocess.commit_charge.get() << 12);
        counters.peak_pagefile_usage.set(eprocess.commit_charge_peak.get() << 12);
        counters.private_usage.set(eprocess.commit_charge.get() << 12);
        counters.private_working_set_size.set(working_set.private);
        counters.shared_commit_usage.set(eprocess.shared_commit_charge.get() << 12);
    })?;
    if let Err(status) = copied {
        return Ok(status);
    }
    if returned != 0 {
        guest::try_write::<u32>(returned, length)?;
    }
    Ok(0)
}

/// ProcessImageFileNameWin32 (o ramo da classe 43, rva 0x621a90): o handle
/// com PROCESS_QUERY_LIMITED_INFORMATION e o nome DOS da imagem (o
/// IoQueryFileDosDeviceName do arquivo da imagem; aqui o caminho DOS que o
/// processo recebeu na criação, o ImagePathName). O tamanho pedido é
/// MaximumLength + 0x10 (o UNICODE_STRING e o texto com o terminador), que
/// vai ao ReturnLength também na recusa; menor que isso dá
/// STATUS_INFO_LENGTH_MISMATCH.
pub fn query_image_file_name_win32(output: u64, length: u32, returned: u64, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    let path = crate::ntos::ps::user::process_state::get(process).map(|identity| identity.image_path()).unwrap_or_default();
    let path = path.strip_prefix("\\??\\").unwrap_or(&path);
    if path.is_empty() {
        return Ok(STATUS_NOT_FOUND);
    }
    let units: alloc::vec::Vec<u16> = path.encode_utf16().collect();
    let text_length = (units.len() * 2) as u32;
    let maximum = text_length + 2;
    let required = maximum + 0x10;
    let status = if required > length {
        STATUS_INFO_LENGTH_MISMATCH
    } else {
        let mut bytes: alloc::vec::Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        guest::try_write::<u16>(output, text_length as u16)?;
        guest::try_write::<u16>(output + 2, maximum as u16)?;
        guest::try_write_bytes(output + 0x10, &bytes)?;
        guest::try_write::<u64>(output + 8, output + 0x10)?;
        0
    };
    if returned != 0 {
        guest::try_write::<u32>(returned, required)?;
    }
    Ok(status)
}

/// PROCESS_MITIGATION_POLICY sem consulta (as políticas 0, 5 e acima de 16).
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

/// Os bits de saída ligados pelos bits de origem: em cada grupo, o primeiro
/// (bit de origem, bit de saída) que casar (os pares de imposto ou
/// auditoria do 19041 são exclusivos).
fn mitigation_bits(source: u32, groups: &[&[(u32, u32)]]) -> u32 {
    groups.iter().fold(0, |flags, group| flags | group.iter().find(|(bit, _)| source & (1 << bit) != 0).map_or(0, |(_, out)| *out))
}

/// ProcessMitigationPolicy (o ramo da classe 52 do NtQueryInformationProcess
/// 19041, rva 0x6239a5): exatamente os 8 bytes do
/// PROCESS_MITIGATION_POLICY_INFORMATION, a política lida do buffer; um
/// handle que não é o pseudo-handle -1 pede
/// PROCESS_QUERY_LIMITED_INFORMATION. As flags (o segundo ULONG) saem, por
/// política, dos bits do EPROCESS (MitigationFlags, MitigationFlags2 e
/// MitigationFlags3), da tabela de handles, do nível de assinatura e do
/// TokenFlags do token primário, como a tabela de saltos do 19041; o
/// ReturnLength não é gravado.
pub fn query_mitigation_policy(output: u64, length: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 8 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let policy = guest::try_read::<u32>(output)?;
    let process = match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    let (first, second, third) = (eprocess.mitigation_flags.get(), eprocess.mitigation_flags2.get(), eprocess.mitigation_flags3.get());
    let token_flags = || process::get_primary_token(process).map_or(0, crate::ntos::se::token::tokens::token_flags);
    let flags = match policy {
        // ProcessASLRPolicy: BottomUp com StackRandomizationDisabled (bit 6)
        // desligado, ForceRelocateImages (4), HighEntropy (5) e
        // DisallowStrippedImages (3).
        1 => (first & 0x40 == 0) as u32 | mitigation_bits(first, &[&[(4, 2)], &[(5, 4)], &[(3, 8)]]),
        // ProcessDynamicCodePolicy.
        2 => mitigation_bits(first, &[&[(8, 1), (11, 8)], &[(9, 2)], &[(10, 4)]]),
        // ProcessStrictHandleCheckPolicy: o ExQueryHandleExceptionsPermanency
        // (sem DebugInfo no OpenNT, o EnableHandleExceptions vale pelos dois
        // bits).
        3 => {
            let table = crate::ntos::ob::handles::process::reference(process)?;
            if table == 0 {
                return Ok(STATUS_PROCESS_IS_TERMINATING);
            }
            // SAFETY: HANDLE_TABLE do EPROCESS.ObjectTable, retida pelo rundown.
            let enabled = unsafe { crate::ntos::inc::types::HandleTable::at(table) }.enable_handle_exceptions() != 0;
            crate::ntos::ob::handles::process::release(process)?;
            if enabled {
                3
            } else {
                0
            }
        }
        // ProcessSystemCallDisablePolicy: as chamadas do win32k (bits 12 e
        // 13) e os bits 1 e 2 do MitigationFlags3.
        4 => mitigation_bits(first, &[&[(12, 1), (13, 2)]]) | mitigation_bits(third, &[&[(1, 4), (2, 8)]]),
        // ProcessExtensionPointDisablePolicy.
        6 => mitigation_bits(first, &[&[(7, 1)]]),
        // ProcessControlFlowGuardPolicy.
        7 => mitigation_bits(first, &[&[(0, 1)], &[(1, 2)], &[(2, 4)]]),
        // ProcessSignaturePolicy (o PsQueryProcessSignatureMitigationPolicy):
        // MicrosoftSignedOnly com os dois níveis de assinatura a partir de 8;
        // sem a rotina de comparação do CI (SeCiCallbacks), os modos
        // auditoria; e o MitigationOptIn (bit 23).
        8 => {
            let microsoft = eprocess.signature_level.get() >= 8 && eprocess.section_signature_level.get() >= 8;
            let primary = if microsoft { 1 } else { mitigation_bits(first, &[&[(24, 8), (25, 0x10)]]) };
            primary | mitigation_bits(first, &[&[(23, 4)]])
        }
        // ProcessFontDisablePolicy.
        9 => mitigation_bits(first, &[&[(16, 1), (17, 2)]]),
        // ProcessImageLoadPolicy.
        10 => mitigation_bits(first, &[&[(19, 1), (20, 8)], &[(21, 2), (22, 0x10)], &[(18, 4)]]),
        // ProcessSystemCallFilterPolicy: o PsGetWin32KFilterSet, que lê o
        // processo corrente.
        // SAFETY: o EPROCESS do processo corrente.
        11 => unsafe { Eprocess::at(process::get_current_process()) }.win32_k_filter_set.get() & 0xF,
        // ProcessPayloadRestrictionPolicy.
        12 => mitigation_bits(second, &[&[(0, 1)], &[(2, 4)], &[(10, 0x10)], &[(4, 0x40)], &[(6, 0x100)], &[(8, 0x400)], &[(1, 2)], &[(3, 8)], &[(11, 0x20)], &[(5, 0x80)], &[(7, 0x200)], &[(9, 0x800)]]),
        // ProcessChildProcessPolicy (o PspGetNoChildProcessRestrictedPolicy
        // do TokenFlags: restrito no bit 19, exceto seguros no 20, auditoria
        // no 21).
        13 => {
            let flags = token_flags();
            match (flags & 1 << 19 != 0, flags & 1 << 20 != 0, flags & 1 << 21 != 0) {
                (true, false, _) => 1,
                (true, true, _) => 5,
                (false, _, true) => 2,
                _ => 0,
            }
        }
        // ProcessSideChannelIsolationPolicy.
        14 => mitigation_bits(first, &[&[(30, 1)], &[(31, 2)]]) | mitigation_bits(second, &[&[(12, 4)], &[(13, 8)]]),
        // ProcessUserShadowStackPolicy.
        15 => mitigation_bits(second, &[&[(14, 1)], &[(15, 2)], &[(17, 4)], &[(18, 8)], &[(20, 0x10)], &[(21, 0x20)], &[(22, 0x40)], &[(23, 0x80)], &[(30, 0x100)], &[(31, 0x200)]]),
        // ProcessRedirectionTrustPolicy (o PspGetRedirectionTrustPolicy do
        // TokenFlags: imposto no bit 23, auditoria no 24).
        16 => {
            let flags = token_flags();
            if flags & 1 << 23 != 0 {
                1
            } else if flags & 1 << 24 != 0 {
                2
            } else {
                0
            }
        }
        _ => return Ok(STATUS_NOT_SUPPORTED),
    };
    guest::try_write::<u32>(output + 4, flags)?;
    Ok(0)
}
