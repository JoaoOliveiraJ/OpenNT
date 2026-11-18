//! Classes do NtSetInformationProcess que mudam o EPROCESS, para o modo
//! usuário e para os drivers (ZwSetInformationProcess, PreviousMode
//! KernelMode).
//!
//! - ProcessBreakOnTermination (29): o processo crítico, cujo fim derruba o
//!   sistema (o RtlSetProcessIsCritical da ntdll; o smss marca assim o csrss
//!   que cria; o win32kfull marca o processo corrente). Como no NT: o buffer
//!   é um ULONG (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH), quem pede
//!   precisa de SeDebugPrivilege no modo anterior (STATUS_PRIVILEGE_NOT_HELD;
//!   KernelMode sempre passa), o handle precisa de PROCESS_SET_INFORMATION, e
//!   o valor liga ou desliga EPROCESS.Flags.BreakOnTermination.
//! - ProcessDebugFlags (31): um ULONG com só o bit PROCESS_DEBUG_INHERIT
//!   (outro bit dá STATUS_INVALID_PARAMETER, conferido depois de referenciar
//!   o handle com PROCESS_SET_INFORMATION); o bit ligado desliga
//!   EPROCESS.Flags.NoDebugInherit e vice-versa (o condrv.sys desliga a
//!   herança do depurador do processo corrente em volta de uma operação e
//!   restaura depois).
//! - ProcessDefaultHardErrorMode (12): o SetErrorMode do processo. Um ULONG
//!   (outro tamanho dá STATUS_INFO_LENGTH_MISMATCH), o handle com
//!   PROCESS_SET_INFORMATION, e o PspSetProcessDefaultHardErrorMode: sob o
//!   ProcessLock, um valor diferente do EPROCESS.DefaultHardErrorProcessing
//!   é gravado e liga ou desliga KPROCESS.AutoAlignment conforme
//!   SEM_NOALIGNMENTFAULTEXCEPT (sempre ligado num processo WoW64).
//! - ProcessHandleCheckingMode (54): um ULONG com só o bit 0 (outro bit dá
//!   STATUS_INVALID_PARAMETER), o handle com PROCESS_SET_INFORMATION; sem
//!   tabela de handles (processo saindo) é STATUS_PROCESS_IS_TERMINATING. O
//!   ExEnableHandleExceptions liga HANDLE_TABLE.EnableHandleExceptions, que
//!   não desliga mais depois de ligado.
//! - ProcessRaiseUMExceptionOnInvalidHandleClose (71): um ULONG (outro
//!   tamanho dá STATUS_INFO_LENGTH_MISMATCH), o handle com
//!   PROCESS_SET_INFORMATION e, sem tabela de handles,
//!   STATUS_PROCESS_IS_TERMINATING. O
//!   ExEnableRaiseUMExceptionOnInvalidHandleClose desliga o bit da
//!   HANDLE_TABLE com 0, liga com 1 e ignora outro valor.
//! - ProcessExceptionPort (8): a porta LPC que recebe as exceções não
//!   tratadas do processo (o csrss põe a dele, a \Windows\ApiPort, em cada
//!   processo da sessão no CsrSbCreateSession). Como no 19041: um HANDLE (8
//!   bytes) ou o PROCESS_EXCEPTION_PORT (16 bytes, com o StateFlags de 3
//!   bits, que volta no buffer com o estado anterior; outro bit dá
//!   STATUS_INVALID_PARAMETER); outro tamanho dá STATUS_INFO_LENGTH_MISMATCH.
//!   Exige SeTcbPrivilege (STATUS_PRIVILEGE_NOT_HELD), referencia a porta
//!   (acesso zero) e o processo com PROCESS_SUSPEND_RESUME, e troca
//!   EPROCESS.ExceptionPortData (o ponteiro da porta com o estado nos 3 bits
//!   baixos); pelo HANDLE só, um estado anterior não zero dá
//!   STATUS_INVALID_PARAMETER. A porta anterior recebe o aviso da troca (o
//!   datagrama de tipo 13 com o PID) e é solta; o fim do processo solta a
//!   porta corrente.
//! - ProcessPriorityClass (18): o PROCESS_PRIORITY_CLASS de 2 bytes
//!   (Foreground e PriorityClass; outro tamanho dá
//!   STATUS_INFO_LENGTH_MISMATCH), o processo com PROCESS_SET_INFORMATION e
//!   o PspSetProcessPriorityClass: classe acima de ABOVE_NORMAL (6) dá
//!   STATUS_INVALID_PARAMETER, a de tempo real nova exige
//!   SeIncreaseBasePriorityPrivilege (STATUS_PRIVILEGE_NOT_HELD) e um job com
//!   JOB_OBJECT_LIMIT_PRIORITY_CLASS impõe a classe dele; depois o
//!   PsSetProcessPriorityByClass leva a base da classe ao processo e às
//!   threads dele (o SetPriorityClass do kernelbase; o wininit pede
//!   HIGH_PRIORITY_CLASS e sai se não consegue).
//! - ProcessForegroundInformation (25): um BOOLEAN, o processo com
//!   PROCESS_SET_LIMITED_INFORMATION e o PsSetProcessPriorityByClass com o
//!   modo de primeiro plano ou de fundo (o csrss põe os processos novos em
//!   fundo).
//! - ProcessBasePriority (5): um ULONG com a base de 1 a 31 e, no bit 31, a
//!   prioridade de memória 2; subir acima da base do processo exige
//!   SeIncreaseBasePriorityPrivilege; depois a base vai ao processo e às
//!   threads (o lsass.exe pede a base 9 ao iniciar e sai sem ela).
//! - ProcessSubsystemProcess (68): sem buffer; só o processo mestre da
//!   sessão marca outro processo como de subsistema
//!   (EPROCESS.Flags3.SubsystemProcess; o smss marca o csrss).
//! - ProcessEnergyTrackingState (82): pelo menos 8 bytes, o estado vai ao
//!   PoSetProcessEnergyTrackingState (`po/power_information`), que sem o
//!   estimador de energia responde STATUS_NOT_SUPPORTED.
//! - ProcessDynamicFunctionTableInformation (53): o {Table, Remove} de 16
//!   bytes do RtlAddGrowableFunctionTable e do RtlDeleteGrowableFunctionTable
//!   da ntdll, só com o pseudo-handle do processo corrente; a tabela entra
//!   ou sai do registro do processo (`rtl/dynamic_function_table`). Não há
//!   consulta: o NtQueryInformationProcess responde STATUS_INVALID_INFO_CLASS.
//!
//! Em UserMode, antes da classe, o buffer passa pelo ProbeForRead com o
//! alinhamento da classe (STATUS_DATATYPE_MISALIGNMENT,
//! STATUS_ACCESS_VIOLATION), como no início do NtSetInformationProcess.
//!
//! O resto das classes ainda não é tratado aqui: STATUS_INVALID_INFO_CLASS.

use crate::ntos::ex::push_lock;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{Eprocess, HandleTable};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::handles::process as process_handles;
use crate::ntos::ps::{query_process, user_probe};
use crate::ntos::rtl::dynamic_function_table;
use crate::rtl::KernelError;

const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SeDebugPrivilege.
const DEBUG_PRIVILEGE: u64 = 20;
/// PROCESS_SET_INFORMATION e PROCESS_SUSPEND_RESUME.
const PROCESS_SET_INFORMATION: u32 = 0x200;
const PROCESS_SUSPEND_RESUME: u32 = 0x800;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
/// SeTcbPrivilege.
const TCB_PRIVILEGE: u64 = 7;
/// PROCESS_SET_LIMITED_INFORMATION.
const PROCESS_SET_LIMITED_INFORMATION: u32 = 0x2000;
/// SeIncreaseBasePriorityPrivilege.
const INCREASE_BASE_PRIORITY_PRIVILEGE: u64 = 14;
/// PROCESS_PRIORITY_CLASS_REALTIME e ABOVE_NORMAL (a maior).
const PRIORITY_CLASS_REALTIME: u8 = 4;
const PRIORITY_CLASS_ABOVE_NORMAL: u8 = 6;
/// JOB_OBJECT_LIMIT_PRIORITY_CLASS.
const JOB_OBJECT_LIMIT_PRIORITY_CLASS: u32 = 0x20;
/// PROCESSINFOCLASS.
pub const PROCESS_BASE_PRIORITY: u32 = 5;
pub const PROCESS_EXCEPTION_PORT: u32 = 8;
pub const PROCESS_DEFAULT_HARD_ERROR_MODE: u32 = 12;
pub const PROCESS_PRIORITY_CLASS: u32 = 18;
pub const PROCESS_FOREGROUND_INFORMATION: u32 = 25;
pub const PROCESS_BREAK_ON_TERMINATION: u32 = 29;
pub const PROCESS_DEBUG_FLAGS: u32 = 31;
pub const PROCESS_HANDLE_CHECKING_MODE: u32 = 54;
/// ProcessRaiseUMExceptionOnInvalidHandleClose (ULONG).
pub const PROCESS_RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE: u32 = 71;
/// ProcessSubsystemProcess (sem buffer) e ProcessEnergyTrackingState.
pub const PROCESS_SUBSYSTEM_PROCESS: u32 = 68;
pub const PROCESS_ENERGY_TRACKING_STATE: u32 = 82;
/// ProcessDynamicFunctionTableInformation (o {Table, Remove} de 16 bytes),
/// tratada à parte por depender do valor do handle
/// ([`set_dynamic_function_table`]).
pub const PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION: u32 = 53;
/// As classes desta área.
pub const CLASSES: [u32; 11] = [PROCESS_BASE_PRIORITY, PROCESS_EXCEPTION_PORT, PROCESS_DEFAULT_HARD_ERROR_MODE, PROCESS_PRIORITY_CLASS, PROCESS_FOREGROUND_INFORMATION, PROCESS_BREAK_ON_TERMINATION, PROCESS_DEBUG_FLAGS, PROCESS_HANDLE_CHECKING_MODE, PROCESS_RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE, PROCESS_SUBSYSTEM_PROCESS, PROCESS_ENERGY_TRACKING_STATE];
/// EPROCESS.Flags3.SubsystemProcess.
const SUBSYSTEM_PROCESS_FLAG: u32 = 1 << 6;
/// O PROCESS_ENERGY_TRACKING_STATE capturado (o resto da cópia local fica
/// zerado).
const ENERGY_TRACKING_STATE_SIZE: u32 = 0x90;
/// PROCESS_DEBUG_INHERIT, o único bit de ProcessDebugFlags.
const PROCESS_DEBUG_INHERIT: u32 = 1;
/// SEM_NOALIGNMENTFAULTEXCEPT do modo de erro.
const SEM_NOALIGNMENTFAULTEXCEPT: u32 = 4;

/// O alinhamento do ProbeForRead de UserMode no início do
/// NtSetInformationProcess (ntoskrnl 19041, rva 0x657be9): 1 byte para as
/// classes de BOOLEAN/UCHAR, 8 para as de ponteiros e handles, 4 para o resto.
fn probe_alignment(class: u32) -> u64 {
    match class {
        0x11 | 0x12 | 0x19 | 0x46 | 0x4A | 0x57 | 0x5A | 0x64 => 1,
        5 | 0x21 | 0x27 | 0x2D | 0x2E | 0x5B | 0x5D => 4,
        0x08 | 0x15 | 0x23 | 0x28 | 0x29 | 0x31 | 0x35 | 0x38 | 0x3E | 0x41 | 0x53 | 0x5F | 0x62 | 0x63 | 0x65 | 0x66 => 8,
        _ => 4,
    }
}

/// O ProbeForRead do buffer de entrada de UserMode, com o alinhamento da
/// classe; um comprimento zero não é sondado.
pub fn probe_input(class: u32, buffer: u64, length: u32) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    if buffer & (probe_alignment(class) - 1) != 0 {
        return Err(STATUS_DATATYPE_MISALIGNMENT);
    }
    if !user_probe::probe_user_read(buffer, u64::from(length)) {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(())
}

/// ProcessBasePriority (o ramo da classe 5 do NtSetInformationProcess do
/// 19041): o bit 31 pede a prioridade de memória 2 (sem ele, 0) e o resto é
/// a prioridade base, de 1 a 31 (senão STATUS_INVALID_PARAMETER); subir
/// acima da base do processo exige SeIncreaseBasePriorityPrivilege
/// (STATUS_PRIVILEGE_NOT_HELD). Depois o KeSetPriorityAndQuantumProcess (a
/// base do processo e das threads) e o MmSetMemoryPriorityProcess. O lsass.exe
/// pede assim a base 9 ao iniciar.
fn set_base_priority(mode: u8, value: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    let memory_priority = if value & 0x8000_0000 != 0 { 2 } else { 0 };
    let base = value & 0x7FFF_FFFF;
    if !(1..=31).contains(&base) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let process = match process_of(PROCESS_SET_INFORMATION) {
        Ok(process) => process,
        Err(status) => return Ok(status),
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    if base as i32 > eprocess.pcb.base_priority.get() as i32 && !crate::ntos::se::privilege::single_privilege_check(INCREASE_BASE_PRIORITY_PRIVILEGE, mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let threads = crate::ntos::ps::process::threads_of_process(process);
    crate::ntos::ke::thread_priority::set_process_base_priority(process, base as i32, &threads)?;
    eprocess.vm.instance.flags.memory_priority.set(memory_priority);
    Ok(0)
}

/// PspSetProcessDefaultHardErrorMode(Process, Thread, Mode).
fn set_default_hard_error_mode(process: u64, mode: u32) -> Result<(), KernelError> {
    // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
    let eprocess = unsafe { Eprocess::at(process) };
    let lock = eprocess.process_lock.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        if eprocess.default_hard_error_processing.get() != mode {
            eprocess.default_hard_error_processing.set(mode);
            // KeSetAutoAlignmentProcess: o bit 0 de KPROCESS.ProcessFlags.
            let automatic = eprocess.wo_w64_process.get() != 0 || mode & SEM_NOALIGNMENTFAULTEXCEPT != 0;
            eprocess.pcb.set_auto_alignment(automatic as u32);
        }
        push_lock::release_exclusive(lock, 0)
    })
}

/// ExEnableHandleExceptions(HandleTable, Enable) (ntoskrnl 19041, rva
/// 0x69cb2c) pelo ObReferenceProcessHandleTable: `None` quando o processo
/// não tem mais a tabela; senão o resultado da rotina, que é `false` só para
/// desligar um bit já ligado (ligado uma vez, fica ligado).
pub(crate) fn enable_handle_exceptions(process: u64, enable: bool) -> Result<Option<bool>, KernelError> {
    let table = process_handles::reference(process)?;
    if table == 0 {
        return Ok(None);
    }
    // SAFETY: HANDLE_TABLE do EPROCESS.ObjectTable, retida pelo rundown.
    let handle_table = unsafe { HandleTable::at(table) };
    let lock = handle_table.handle_table_lock.address();
    // Sob o HandleTableLock; o OpenNT não tem o DebugInfo do rastreio de
    // handles, onde o NT guarda o mesmo bit quando ele existe.
    let result = critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let accepted = if handle_table.enable_handle_exceptions() != 0 {
            enable
        } else {
            handle_table.set_enable_handle_exceptions(enable as u8);
            true
        };
        push_lock::release_exclusive(lock, 0).map(|()| accepted)
    });
    process_handles::release(process)?;
    result.map(Some)
}

/// ExEnableRaiseUMExceptionOnInvalidHandleClose (ntoskrnl 19041, rva
/// 0x68f954): sob o HandleTableLock, 0 desliga o bit
/// RaiseUMExceptionOnInvalidHandleClose da HANDLE_TABLE, 1 liga e outro valor
/// não muda nada. `false` quando o processo já não tem tabela de handles.
fn raise_on_invalid_handle_close(process: u64, value: u32) -> Result<bool, KernelError> {
    let table = process_handles::reference(process)?;
    if table == 0 {
        return Ok(false);
    }
    // SAFETY: HANDLE_TABLE do EPROCESS.ObjectTable, retida pelo rundown.
    let handle_table = unsafe { HandleTable::at(table) };
    let lock = handle_table.handle_table_lock.address();
    let result = critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        match value {
            0 => handle_table.set_raise_um_exception_on_invalid_handle_close(0),
            1 => handle_table.set_raise_um_exception_on_invalid_handle_close(1),
            _ => {}
        }
        push_lock::release_exclusive(lock, 0)
    });
    process_handles::release(process)?;
    result.map(|()| true)
}

/// O ULONG da classe: sondado em UserMode, direto em KernelMode.
fn read_ulong(mode: u8, buffer: u64) -> Result<Result<u32, u32>, KernelError> {
    if mode != 0 {
        if !user_probe::probe_user_read(buffer, 4) {
            return Ok(Err(STATUS_ACCESS_VIOLATION));
        }
        return Ok(Ok(guest::try_read::<u32>(buffer)?));
    }
    // SAFETY: buffer de entrada de um chamador de modo kernel.
    Ok(Ok(unsafe { Field::<u32>::at(buffer) }.get()))
}

/// NtSetInformationProcess das classes que mudam o EPROCESS. `mode` é o
/// PreviousMode; `process_of` resolve o handle com o acesso pedido para o
/// EPROCESS (retido enquanto dura a chamada).
pub fn set_information(mode: u8, class: u32, buffer: u64, length: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if mode != 0 {
        if let Err(status) = probe_input(class, buffer, length) {
            return Ok(status);
        }
    }
    match class {
        PROCESS_BASE_PRIORITY => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            set_base_priority(mode, value, process_of)
        }
        PROCESS_DEFAULT_HARD_ERROR_MODE => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            set_default_hard_error_mode(process, value)?;
            Ok(0)
        }
        // O ramo da classe 71 do NtSetInformationProcess 19041 (rva
        // 0x65b2be): exatamente 4 bytes, o handle com
        // PROCESS_SET_INFORMATION, a tabela de handles referenciada
        // (STATUS_PROCESS_IS_TERMINATING sem ela) e o bit ligado ou
        // desligado sem validar o valor.
        PROCESS_RAISE_UM_EXCEPTION_ON_INVALID_HANDLE_CLOSE => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            Ok(if raise_on_invalid_handle_close(process, value)? { 0 } else { STATUS_PROCESS_IS_TERMINATING })
        }
        PROCESS_HANDLE_CHECKING_MODE => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            if value & !1 != 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            // O resultado do ExEnableHandleExceptions não é conferido.
            Ok(if enable_handle_exceptions(process, value & 1 != 0)?.is_some() { 0 } else { STATUS_PROCESS_IS_TERMINATING })
        }
        PROCESS_BREAK_ON_TERMINATION => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            if !crate::ntos::se::privilege::single_privilege_check(DEBUG_PRIVILEGE, mode as u32) {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
            unsafe { Eprocess::at(process) }.set_break_on_termination((value != 0) as u32);
            Ok(0)
        }
        PROCESS_DEBUG_FLAGS => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            let value = match read_ulong(mode, buffer)? {
                Ok(value) => value,
                Err(status) => return Ok(status),
            };
            if value & !PROCESS_DEBUG_INHERIT != 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            // SAFETY: EPROCESS retido pelo handle que o nomeou.
            unsafe { Eprocess::at(process) }.set_no_debug_inherit((value & PROCESS_DEBUG_INHERIT == 0) as u32);
            Ok(0)
        }
        PROCESS_EXCEPTION_PORT => set_exception_port(mode, buffer, length, process_of),
        PROCESS_PRIORITY_CLASS => {
            if length != 2 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            // PROCESS_PRIORITY_CLASS: Foreground e PriorityClass.
            let captured = if mode != 0 {
                if !user_probe::probe_user_read(buffer, 2) {
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
                guest::try_read::<u16>(buffer)?
            } else {
                // SAFETY: buffer de entrada de um chamador de modo kernel.
                unsafe { Field::<u16>::at(buffer) }.get()
            };
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            let status = set_priority_class(process, (captured >> 8) as u8, mode);
            if status == 0 {
                crate::ntos::ps::process_accessors::set_priority_by_class(process, (captured & 0xFF != 0) as u32);
            }
            Ok(status)
        }
        PROCESS_FOREGROUND_INFORMATION => {
            if length != 1 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let foreground = if mode != 0 {
                if !user_probe::probe_user_read(buffer, 1) {
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
                guest::try_read::<u8>(buffer)?
            } else {
                // SAFETY: buffer de entrada de um chamador de modo kernel.
                unsafe { Field::<u8>::at(buffer) }.get()
            };
            let process = match process_of(PROCESS_SET_LIMITED_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            crate::ntos::ps::process_accessors::set_priority_by_class(process, (foreground != 0) as u32);
            Ok(0)
        }
        // O ramo da classe 68 do NtSetInformationProcess 19041 (rva
        // 0x65b1fe): sem buffer nem tamanho; quem chama precisa ser o
        // processo mestre da sessão (MMSUPPORT_FLAGS.SessionMaster do
        // processo corrente, senão STATUS_PRIVILEGE_NOT_HELD), o handle com
        // PROCESS_SET_INFORMATION e EPROCESS.Flags3.SubsystemProcess ligado
        // por OR atômico. O smss marca assim o csrss que inicia.
        PROCESS_SUBSYSTEM_PROCESS => {
            // SAFETY: o EPROCESS corrente (PsGetCurrentProcess).
            let current = unsafe { Eprocess::at(crate::ntos::ps::process::get_current_process()) };
            if current.vm.instance.flags.session_master() == 0 {
                return Ok(STATUS_PRIVILEGE_NOT_HELD);
            }
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            // SAFETY: EPROCESS retido pelo handle que o nomeou.
            unsafe { Eprocess::at(process) }.flags3.atomic().fetch_or(SUBSYSTEM_PROCESS_FLAG, core::sync::atomic::Ordering::AcqRel);
            Ok(0)
        }
        // O ramo da classe 82 (rva 0x65b4da): pelo menos 8 bytes, os
        // primeiros 0x90 copiados numa estrutura local zerada, o handle com
        // PROCESS_SET_INFORMATION e o PoSetProcessEnergyTrackingState (o
        // svchost põe o "[grupo] [instância]" do processo).
        PROCESS_ENERGY_TRACKING_STATE => {
            if length < 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let copied = length.min(ENERGY_TRACKING_STATE_SIZE) as usize;
            let captured = if mode != 0 {
                match guest::try_read_bytes(buffer, copied) {
                    Ok(bytes) => bytes,
                    Err(error) => return Ok(error.status),
                }
            } else {
                guest::read_bytes(buffer, copied)
            };
            let mut state = alloc::vec![0u8; ENERGY_TRACKING_STATE_SIZE as usize];
            state[..copied].copy_from_slice(&captured);
            let process = match process_of(PROCESS_SET_INFORMATION) {
                Ok(process) => process,
                Err(status) => return Ok(status),
            };
            Ok(crate::ntos::po::power_information::set_process_energy_tracking_state(process, &state))
        }
        _ => {
            crate::debug_print!("[ps] NtSetInformationProcess classe {} (sem suporte)", class);
            Ok(STATUS_INVALID_INFO_CLASS)
        }
    }
}

/// ZwSetInformationProcess(ProcessHandle, Class, Information, Length): o
/// NtSetInformationProcess com PreviousMode KernelMode. O handle é
/// referenciado como o ObReferenceObjectByHandleWithTag do NT (PsProcessType,
/// KernelMode: o pseudo-handle do processo corrente e os handles de kernel) e
/// solto no fim.
pub fn set_information_kernel(handle: u64, class: u32, buffer: u64, length: u32) -> Result<u32, KernelError> {
    if class == PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION {
        return set_dynamic_function_table(0, handle, buffer, length);
    }
    let mut referenced = 0u64;
    let mut failure: Result<(), KernelError> = Ok(());
    let status = set_information(0, class, buffer, length, |access| match query_process::reference_process(handle, access) {
        Ok(Ok(process)) => {
            referenced = process;
            Ok(process)
        }
        Ok(Err(status)) => Err(status),
        Err(error) => {
            failure = Err(error);
            Err(STATUS_INSUFFICIENT_RESOURCES)
        }
    });
    if referenced != 0 {
        query_process::release_process(referenced)?;
    }
    failure?;
    status
}

/// O ramo da classe 53 do NtSetInformationProcess 19041 (rva 0x65abf2): em
/// UserMode o ProbeForRead de alinhamento 8 do começo do serviço; depois só
/// o pseudo-handle do processo corrente (o valor -1, sem referenciar nada;
/// outro handle é STATUS_INVALID_PARAMETER), exatamente 16 bytes
/// (STATUS_INFO_LENGTH_MISMATCH), a captura do {Table, Remove} (uma falha
/// devolve o código da exceção) e o RtlRemoveDynamicFunctionTable ou o
/// RtlInsertDynamicFunctionTable, cujo status volta.
pub fn set_dynamic_function_table(mode: u8, handle: u64, buffer: u64, length: u32) -> Result<u32, KernelError> {
    if mode != 0 {
        if let Err(status) = probe_input(PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION, buffer, length) {
            return Ok(status);
        }
    }
    if handle != u64::MAX {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if length != 16 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let (table, remove) = if mode != 0 {
        match (guest::try_read::<u64>(buffer), guest::try_read::<u8>(buffer + 8)) {
            (Ok(table), Ok(remove)) => (table, remove),
            (Err(error), _) | (_, Err(error)) => return Ok(error.status),
        }
    } else {
        // SAFETY: buffer de entrada de um chamador de modo kernel.
        unsafe { (Field::<u64>::at(buffer).get(), Field::<u8>::at(buffer + 8).get()) }
    };
    if remove != 0 {
        dynamic_function_table::remove(table)
    } else {
        dynamic_function_table::insert(table)
    }
}

/// O tipo da mensagem que avisa a porta de exceções trocada.
const LPC_EXCEPTION_PORT_REPLACED: u16 = 13;

/// ProcessExceptionPort: o HANDLE ou o PROCESS_EXCEPTION_PORT.
fn set_exception_port(mode: u8, buffer: u64, length: u32, process_of: impl FnOnce(u32) -> Result<u64, u32>) -> Result<u32, KernelError> {
    if length != 8 && length != 16 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let read = |offset: u64, size: u64| -> Result<Result<u64, u32>, KernelError> {
        if mode != 0 {
            if !user_probe::probe_user_read(buffer + offset, size) {
                return Ok(Err(STATUS_ACCESS_VIOLATION));
            }
            return Ok(Ok(if size == 8 { guest::try_read::<u64>(buffer + offset)? } else { guest::try_read::<u32>(buffer + offset)? as u64 }));
        }
        // SAFETY: buffer de entrada de um chamador de modo kernel.
        Ok(Ok(if size == 8 { unsafe { Field::<u64>::at(buffer + offset) }.get() } else { unsafe { Field::<u32>::at(buffer + offset) }.get() as u64 }))
    };
    let handle = match read(0, 8)? {
        Ok(handle) => handle,
        Err(status) => return Ok(status),
    };
    let flags = if length == 16 {
        match read(8, 4)? {
            Ok(flags) if flags & !7 != 0 => return Ok(STATUS_INVALID_PARAMETER),
            Ok(flags) => flags,
            Err(status) => return Ok(status),
        }
    } else {
        0
    };
    if !crate::ntos::se::privilege::single_privilege_check(TCB_PRIVILEGE, mode as u32) {
        return Ok(STATUS_PRIVILEGE_NOT_HELD);
    }
    let port = match crate::ntos::alpc::port_reference::reference(handle, 0, mode)? {
        Ok(reference) => reference.port,
        Err(status) => return Ok(status),
    };
    let release_port = |pointer: u64| {
        let _ = crate::ntos::ob::objects::dispatcher::dereference(pointer);
    };
    let process = match process_of(PROCESS_SUSPEND_RESUME) {
        Ok(process) => process,
        Err(status) => {
            release_port(port.pointer);
            return Ok(status);
        }
    };
    // SAFETY: EPROCESS retido pelo handle que o nomeou.
    let data = &unsafe { Eprocess::at(process) }.exception_port_data;
    let new = port.pointer | flags;
    let mut old = data.get();
    loop {
        if length == 16 {
            let state = (old & 7) as u32;
            if mode != 0 {
                if !user_probe::probe_user_write(buffer + 8, 4) || guest::try_write::<u32>(buffer + 8, state).is_err() {
                    release_port(port.pointer);
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
            } else {
                // SAFETY: buffer de um chamador de modo kernel.
                unsafe { Field::<u32>::at(buffer + 8) }.set(state);
            }
        } else if old & 7 != 0 {
            release_port(port.pointer);
            return Ok(STATUS_INVALID_PARAMETER);
        }
        match data.atomic().compare_exchange(old, new, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst) {
            Ok(_) => break,
            Err(current) => old = current,
        }
    }
    let previous = old & !7;
    if previous != 0 {
        if let Some(replaced) = crate::ntos::ob::objects::port::port_of(previous) {
            // SAFETY: EPROCESS retido pelo handle.
            let id = unsafe { Eprocess::at(process) }.unique_process_id.get();
            let sender = crate::ntos::alpc::transport::Sender { process: crate::ntos::ps::process::get_current_process_id(), thread: crate::ntos::ps::process::get_current_thread_id(), thread_pointer: crate::ntos::ps::process::get_current_thread() };
            crate::ntos::alpc::server::post_datagram(&replaced, LPC_EXCEPTION_PORT_REPLACED, &id.to_le_bytes(), sender);
        }
        release_port(previous);
    }
    Ok(0)
}

/// O fim do processo solta a porta de exceções (PspProcessDelete).
fn release_exception_port(process: u64) {
    // SAFETY: o EPROCESS que termina, vivo durante as rotinas de término.
    let data = &unsafe { Eprocess::at(process) }.exception_port_data;
    let previous = data.atomic().swap(0, core::sync::atomic::Ordering::SeqCst) & !7;
    if previous != 0 {
        let _ = crate::ntos::ob::objects::dispatcher::dereference(previous);
    }
}

pub fn init() {
    crate::ntos::ps::process::register_process_exit_routine(release_exception_port);
    crate::ntos::ps::process::register_process_exit_routine(dynamic_function_table::release);
}

/// PspSetProcessPriorityClass(Process, PriorityClass, PreviousMode): grava
/// EPROCESS.PriorityClass. Devolve o NTSTATUS.
fn set_priority_class(process: u64, class: u8, mode: u8) -> u32 {
    if class > PRIORITY_CLASS_ABOVE_NORMAL {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: EPROCESS retido pelo handle que o nomeou.
    let object = unsafe { Eprocess::at(process) };
    if class == PRIORITY_CLASS_REALTIME && object.priority_class.get() != class && !crate::ntos::se::privilege::single_privilege_check(INCREASE_BASE_PRIORITY_PRIVILEGE, mode as u32) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let mut class = class;
    let job = object.job.get();
    if job != 0 {
        // SAFETY: o EJOB do processo, retido pela participação dele.
        let job = unsafe { crate::ntos::inc::types::Ejob::at(job) };
        if job.effective_limit_flags.get() & JOB_OBJECT_LIMIT_PRIORITY_CLASS != 0 {
            class = job.effective_priority_class.get();
        }
    }
    object.priority_class.set(class);
    0
}
