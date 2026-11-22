//! Serviços centrais de modo usuário.
//!
//! Processador corrente, display de boot, término, contador de desempenho,
//! NtContinue sobre o frame do syscall, esperas reais, informações de
//! sistema e de processo, erro fatal, objetos de namespace e segurança. As
//! classes de outros módulos (depuração, instrumentação, TLS, exceções,
//! partições) entram pelos ganchos que esses módulos instalam.

use alloc::string::String;
use alloc::vec::Vec;

use super::state::{self, probe_user_read, probe_user_write, stack_arg, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, TERMINATE_MAGIC};
use super::threads;
use crate::hal::{amd64::usermode, serial};
use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::{clock, pcr, processor_information, smp};
use crate::ntos::mm::{memory_information, memory_map, pfn};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ob::wait as ob_wait;
use crate::ntos::ps::{image_information, system_process_information};
use crate::ntos::ps::context::registers as thread_context_registers;
use crate::ntos::se::{code_integrity_information, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::extra_ps_user::SystemMemoryListInformation;
use crate::ntos::inc::types::{Context, Eprocess, NtStruct, ProcessBasicInformation, ProcessExtendedBasicInformation, ProcessorNumber, SystemBasicInformation, UnicodeString, XsaveFormat};

/// PreviousMode dos serviços deste módulo.
const USER_MODE: u8 = 1;

/// Gancho: (userRsp, retLen*) → status.
pub type StackQuery = fn(u64, u64) -> Result<u32, KernelError>;
/// Gancho: (processHandle, buffer, length) → status.
pub type ProcessSetter = fn(u64, u64, u64) -> Result<u32, KernelError>;

static PROCESS_DEBUG_QUERY: SpinLock<Option<StackQuery>> = SpinLock::new(None);
static INSTRUMENTATION_SET: SpinLock<Option<ProcessSetter>> = SpinLock::new(None);
static TLS_SET: SpinLock<Option<ProcessSetter>> = SpinLock::new(None);
/// `exceptions::raise(record, context, first_chance)`.
static RAISE_EXCEPTION: SpinLock<Option<fn(u64, u64, u64) -> Result<u32, KernelError>>> = SpinLock::new(None);
/// `partition::open(out, access, oa, true)`.
static OPEN_PARTITION: SpinLock<Option<fn(u64, u32, u64) -> Result<u32, KernelError>>> = SpinLock::new(None);
/// `set_user_debug_registers(bank)` da HAL de modo usuário.
static SET_USER_DEBUG_REGISTERS: SpinLock<Option<fn(u64)>> = SpinLock::new(None);

pub fn set_process_debug_query(query: StackQuery) {
    *PROCESS_DEBUG_QUERY.lock() = Some(query);
}

pub fn set_instrumentation_setter(setter: ProcessSetter) {
    *INSTRUMENTATION_SET.lock() = Some(setter);
}

pub fn set_tls_setter(setter: ProcessSetter) {
    *TLS_SET.lock() = Some(setter);
}

pub fn set_exception_raiser(raiser: fn(u64, u64, u64) -> Result<u32, KernelError>) {
    *RAISE_EXCEPTION.lock() = Some(raiser);
}

pub fn set_partition_opener(opener: fn(u64, u32, u64) -> Result<u32, KernelError>) {
    *OPEN_PARTITION.lock() = Some(opener);
}

pub fn set_user_debug_registers(setter: fn(u64)) {
    *SET_USER_DEBUG_REGISTERS.lock() = Some(setter);
}

fn online_mask() -> u64 {
    (1u64 << smp::online_cpu_count()) - 1
}

// O escalonador de usuário roda só no BSP: os APs aceitam trabalhos
// nativos, mas não hospedam threads de usuário.
fn nt_get_current_processor_number(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(0)
}

/// PROCESSOR_NUMBER de quatro bytes.
fn nt_get_current_processor_number_ex(number: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| {
        if number != 0 {
            if !probe_user_write(number, 4) {
                return Ok(0xC000_0005);
            }
            let processor = state::user_struct::<ProcessorNumber>(number)?;
            processor.group.probe_set(0)?;
            processor.number.probe_set(0)?;
            processor.reserved.probe_set(0)?;
        }
        Ok(0)
    })
}

/// NtDisplayString(PUNICODE_STRING): console de boot e serial. A string e o
/// buffer são sondados como no NT.
fn nt_display_string(string: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    state::guarded(|| {
        if !probe_user_read(string, 16) {
            return Ok(0xC000_0005);
        }
        let string = state::user_struct::<UnicodeString>(string)?;
        let length = string.length.probe_get()? as u64;
        let buffer = string.buffer.probe_get()?;
        if !probe_user_read(buffer, length) {
            return Ok(0xC000_0005);
        }
        let text = state::try_read_user_wide_string(buffer, length / 2)?;
        serial::write(text.as_bytes());
        crate::debug_print!("[usermode] NtDisplayString: {}", text.trim_end_matches(['\r', '\n']));
        Ok(STATUS_SUCCESS)
    })
}

/// PROCESS_TERMINATE.
const PROCESS_TERMINATE: u32 = 0x0001;
/// STATUS_PROCESS_IS_TERMINATING.
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// NtTerminateProcess(handle, exitCode). Com NULL, as outras threads do
/// processo corrente terminam e quem chamou segue (o primeiro passo do
/// RtlExitUserProcess, antes do LdrShutdownProcess). Com um handle de outro
/// processo (PROCESS_TERMINATE), o fim dele (`ps::create::exit_process`), sem
/// tocar em quem chamou. Com o do próprio processo (o pseudo-handle ou um
/// handle real para ele), o começo do PspTerminateProcess roda aqui, na
/// thread que chamou (`ps::create::begin_termination`: um processo crítico
/// para a máquina antes de o intervalo acabar), o código vai para a HAL, que
/// encerra o intervalo de vez (longjmp), e o despachante pede o fim do
/// processo.
fn nt_terminate_process(handle: u64, exit_code: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let status = exit_code as u32;
    if handle == 0 {
        crate::debug_print!("[usermode] NtTerminateProcess(NULL, exit={:#x}): as outras threads terminam", status);
        return threads::terminate_other_threads(status);
    }
    let target = match super::handles::process_pointer(handle, PROCESS_TERMINATE) {
        Ok(target) => target,
        Err(status) => return Ok(status),
    };
    if target != crate::ntos::ps::process::get_current_process() {
        crate::debug_print!("[usermode] NtTerminateProcess(processo {:#x}, exit={:#x})", target, status);
        return Ok(if crate::ntos::ps::create::exit_process(target, status) { STATUS_SUCCESS } else { STATUS_PROCESS_IS_TERMINATING });
    }
    if let Some(thread) = threads::current() {
        let rsp = pcr::current().user_rsp.get();
        thread.with(|thread| thread.termination_rsp = rsp);
        // O depurador do kernel vê o fim com um código da tabela dele (o
        // RaiseFailFastException sem o WER termina assim), com a thread na
        // chamada: o CONTEXT da syscall.
        let (context, teb) = thread.with(|thread| (thread.context, thread.teb_va));
        crate::ntos::kd::user_debug::terminating(context, teb, status);
    }
    crate::debug_print!("[usermode] NtTerminateProcess(exit={:#x})", exit_code as u32);
    crate::ntos::ps::create::begin_termination(target, status);
    usermode::block().exit_code.set(exit_code as u32);
    Ok(TERMINATE_MAGIC)
}

fn nt_query_performance_counter(counter: u64, frequency: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if counter == 0 || !probe_user_write(counter, 8) || (frequency != 0 && !probe_user_write(frequency, 8)) {
        return Ok(0xC000_0005);
    }
    super::time_services::count_performance_counter_call();
    state::guarded(|| {
        // LARGE_INTEGER.QuadPart de cada saída: um store de qword sondado
        // (o KeQueryPerformanceCounter e a frequência de 10 MHz).
        guest::try_write::<u64>(counter, clock::query_performance_counter_value())?;
        if frequency != 0 {
            guest::try_write::<u64>(frequency, clock::QPC_FREQUENCY)?;
        }
        Ok(STATUS_SUCCESS)
    })
}

/// NtContinue(context, alertable): reescreve o frame do syscall com o
/// CONTEXT; o retorno da HAL retoma o contexto. GPRs são copiados como
/// padrões de bits opacos. Com CONTEXT_FLOATING_POINT, como o
/// KxContextToKframes de UserMode: o MXCSR que vale é Context.MxCsr &
/// KiMxCsrMask (bits inválidos são mascarados, não recusados) e a palavra de
/// controle x87 do FltSave perde os bits reservados (& 0x1F3F). Com
/// CONTEXT_XSTATE, o pedaço XSTATE do CONTEXT_EX vai ao estado estendido da
/// thread, que volta à CPU.
fn nt_continue(context: u64, _alertable: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if context == 0 || !probe_user_read(context, 0x300) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let user = state::user_struct::<Context>(context)?;
        let flags = user.context_flags.probe_get()?;
        if flags & 3 != 3 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        if flags & 0x40 != 0 {
            if let Err(status) = crate::ntos::rtl::extended_context::validate_context_flags(flags) {
                return Ok(status);
            }
        }
        let canonical = |value: u64| value > 0 && value < 0x8000_0000_0000;
        let (rip, rsp) = (user.rip.probe_get()?, user.rsp.probe_get()?);
        if !canonical(rip) || !canonical(rsp) || user.seg_cs.probe_get()? != 0x33 || user.seg_ss.probe_get()? != 0x2B {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // Tudo é capturado antes de mudar o frame: uma falha de sonda nunca
        // deixa o retorno pela metade.
        let debug = if flags & 0x10 != 0 { Some([user.dr0.probe_get()?, user.dr1.probe_get()?, user.dr2.probe_get()?, user.dr3.probe_get()?, 0, user.dr7.probe_get()?]) } else { None };
        let [rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15] = [&user.rax, &user.rcx, &user.rdx, &user.rbx, &user.rbp, &user.rsi, &user.rdi, &user.r8, &user.r9, &user.r10, &user.r11, &user.r12, &user.r13, &user.r14, &user.r15].map(|register| register.probe_get());
        let (rax, rcx, rdx, rbx, rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15) = (rax?, rcx?, rdx?, rbx?, rbp?, rsi?, rdi?, r8?, r9?, r10?, r11?, r12?, r13?, r14?, r15?);
        let eflags = user.e_flags.probe_get()?;
        let float_state = if flags & 8 != 0 { Some((guest::try_read_bytes(user.flt_save.address(), XsaveFormat::SIZE as usize)?, user.mx_csr.probe_get()?)) } else { None };
        let xstate = if crate::ntos::ps::context::xstate::requested(flags) {
            match crate::ntos::ps::context::xstate::capture_user(context, flags)? {
                Ok(extended) => Some(extended),
                Err(status) => return Ok(status),
            }
        } else {
            None
        };
        // Os registradores de depuração são preparados antes de mudar o frame.
        let mut debug_bank = 0u64;
        if let Some(values) = debug {
            debug_bank = guest::alloc_bytes(48);
            if debug_bank == 0 {
                return Ok(0xC000_009A);
            }
            let bank: Vec<u8> = thread_context_registers::debug_registers(values, 1).into_iter().flat_map(u64::to_le_bytes).collect();
            guest::write_bytes(debug_bank, &bank);
        }
        let frame = state::syscall_frame();
        frame.rax.set(rax);
        frame.rip.set(rip);
        frame.rdx.set(rdx);
        frame.rsi.set(rsi);
        frame.rdi.set(rdi);
        frame.r8.set(r8);
        frame.r9.set(r9);
        frame.r10.set(r10);
        // RF é preservado (um breakpoint de execução retoma a instrução uma
        // vez); IOPL/NT/VM/VIF/VIP continuam filtrados.
        frame.rflags.set(((eflags & 0x21_0DD5) | 0x200) as u64);
        frame.rbx.set(rbx);
        frame.rbp.set(rbp);
        frame.r12.set(r12);
        frame.r13.set(r13);
        frame.r14.set(r14);
        frame.r15.set(r15);
        // A pilha do usuário é a KPCR.UserRsp que o retorno da HAL empilha.
        pcr::current().user_rsp.set(rsp);
        let block = usermode::block();
        block.continue_rcx.set(rcx); // RCX independente do RIP
        block.continue_r11.set(r11); // R11 independente do RFLAGS
        if let Some((image, mxcsr)) = float_state {
            // Imagem FXSAVE que o retorno da HAL restaura, logo abaixo do
            // frame, no lugar da que a entrada do serviço gravou: o
            // MXCSR_MASK dela é a máscara do processador (zero vale 0xFFBF).
            // SAFETY: a área FXSAVE alinhada abaixo do frame do syscall, na
            // pilha de kernel da thread.
            let saved = unsafe { XsaveFormat::at(frame.address() - 0x208) };
            let mask = match saved.mx_csr_mask.get() {
                0 => 0xFFBF,
                mask => mask,
            };
            guest::write_bytes(saved.address(), &image);
            saved.mx_csr.set(mxcsr & mask);
            saved.control_word.set(saved.control_word.get() & 0x1F3F);
        }
        if debug_bank != 0 {
            if let Some(setter) = *SET_USER_DEBUG_REGISTERS.lock() {
                setter(debug_bank);
            }
            guest::free_bytes(debug_bank);
        }
        if let Some(extended) = xstate.as_ref() {
            crate::ntos::ps::context::xstate::apply_to_thread(extended, crate::ntos::ps::process::get_current_thread());
        }
        block.continue_flag.set(1);
        crate::debug_print!("[usermode] NtContinue -> rip {:#x} rsp {:#x}", rip, rsp);
        Ok(rax as u32)
    })
}

/// A espera de um serviço de modo usuário nos objetos capturados: pelo
/// despachante (PENDING + espera registrada) ou, fora dele, a espera do Ke
/// no lugar (o prazo vai numa célula do kernel).
fn wait_captured(set: ob_wait::WaitObjects, wait_type: u32, timeout: Option<i64>, alertable: bool) -> u32 {
    if threads::active() {
        return threads::wait_referenced(set, wait_type, timeout, alertable);
    }
    let cell = match timeout {
        Some(value) => {
            let cell = guest::alloc_bytes(8);
            if cell == 0 {
                set.release();
                return 0xC000_0017;
            }
            guest::write64(cell, value as u64);
            cell
        }
        None => 0,
    };
    let status = ob_wait::wait_referenced(set, wait_type, 0, false, cell);
    if cell != 0 {
        guest::free_bytes(cell);
    }
    status
}

/// NtWaitForSingleObject(handle, alertable, timeout*): o prazo capturado e
/// o ObWaitForSingleObject em UserMode (o handle precisa de SYNCHRONIZE; um
/// objeto sem objeto de espera próprio conclui de imediato).
fn nt_wait_for_single_object(handle: u64, alertable: u64, timeout: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let timeout = match state::capture_timeout(timeout) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(status),
    };
    Ok(match ob_wait::reference_objects(&[handle], USER_MODE, ob_wait::WAIT_ANY) {
        Ok(set) => wait_captured(set, ob_wait::WAIT_ANY, timeout, state::boolean(alertable)),
        Err(status) => status,
    })
}

/// NtWaitForMultipleObjects(count, handles*, waitType, alertable,
/// timeout*), como no 19041: Count e WaitType antes de tudo
/// (STATUS_INVALID_PARAMETER_1/_3), a captura do prazo e do vetor de
/// HANDLEs e o ObWaitForMultipleObjects em UserMode (`ob/wait`).
fn nt_wait_for_multiple_objects(count: u64, handles: u64, wait_type: u64, alertable: u64, rsp: u64) -> Result<u32, KernelError> {
    let (count, wait_type) = (count as u32, wait_type as u32);
    if let Err(status) = ob_wait::check_multiple_wait(count, wait_type) {
        return Ok(status);
    }
    let timeout = match state::capture_timeout(stack_arg(rsp, 5)) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(status),
    };
    if !probe_user_read(handles, count as u64 * 8) {
        return Ok(0xC000_0005);
    }
    // O vetor de HANDLEs é capturado de uma vez (cópia sondada).
    let captured = match guest::try_read_bytes(handles, count as usize * 8) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(0xC000_0005),
    };
    let handles: Vec<u64> = captured.chunks_exact(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))).collect();
    Ok(match ob_wait::reference_objects(&handles, USER_MODE, wait_type) {
        Ok(set) => wait_captured(set, wait_type, timeout, state::boolean(alertable)),
        Err(status) => status,
    })
}

/// NtSignalAndWaitForSingleObject(SignalHandle, WaitHandle, Alertable,
/// Timeout*), como no 19041: o prazo capturado; o SignalHandle referenciado
/// sem direito e o WaitHandle com SYNCHRONIZE (o objeto de espera do tipo);
/// o sinal pelo tipo do primeiro (`ob/wait::SignalObject::signal`) e, só
/// com ele bem-sucedido, a espera no segundo. Toda a CPU de usuário é do
/// serviço até a espera ser instalada, então o sinal e a espera são
/// atômicos para as outras threads.
fn nt_signal_and_wait_for_single_object(signal: u64, wait: u64, alertable: u64, timeout: u64, _rsp: u64) -> Result<u32, KernelError> {
    let timeout = match state::capture_timeout(timeout) {
        Ok(timeout) => timeout,
        Err(status) => return Ok(status),
    };
    let signal_object = match ob_wait::reference_signal_object(signal, USER_MODE) {
        Ok(object) => object,
        Err(status) => return Ok(status),
    };
    let set = match ob_wait::reference_objects(&[wait], USER_MODE, ob_wait::WAIT_ANY) {
        Ok(set) => set,
        Err(status) => {
            signal_object.release();
            return Ok(status);
        }
    };
    let status = signal_object.signal(USER_MODE);
    if status != 0 {
        set.release();
        return Ok(status);
    }
    Ok(wait_captured(set, ob_wait::WAIT_ANY, timeout, state::boolean(alertable)))
}

/// NtSerializeBoot(): `io/pnp::serialize_boot`, de modo usuário.
fn nt_serialize_boot(_: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::io::pnp::serialize_boot(1))
}

/// NtSetSystemInformation(class, buffer, length): `ex/system_information`.
fn nt_set_system_information(class: u64, buffer: u64, length: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    super::crash_report::set_system_information(class as u32);
    crate::ntos::ex::system_information::set_from_user_mode(class as u32, buffer, length as u32)
}

/// NtQuerySystemInformation(class, buffer, length, returnLength*).
fn nt_query_system_information(class: u64, buffer: u64, length: u64, returned: u64, _rsp: u64) -> Result<u32, KernelError> {
    query_system_information(class as u32, buffer, length as u32 as u64, returned)
}

fn query_system_information(class: u32, buffer: u64, length: u64, returned: u64) -> Result<u32, KernelError> {
    match class {
        90 => return boot_environment_information::query(buffer, length, returned, true),
        103 => return code_integrity_information::query(buffer, length, returned, true),
        143 => return secure_boot_information::query(buffer, length, returned, true),
        145 => return secure_boot_information::query_state(buffer, length, returned, true),
        157 => return crate::ntos::ex::manufacturing_information::query(buffer, length, returned, true),
        3 => return crate::ntos::ex::time_of_day_information::query(buffer, length, returned, true),
        44 | 102 => return Ok(crate::ntos::ex::time_zone::query(class, buffer, length, returned, true)),
        124 => return Ok(crate::ntos::ex::time_of_day_information::query_counter_class(buffer, length, returned, true)),
        1 | 63 => return Ok(processor_information::query(buffer, length as u32, returned, true, class == 63)),
        154 => return Ok(processor_information::query_features(buffer, length as u32, returned, true)),
        5 | 57 | 148 => {
            let result = system_process_information::query_class(class, buffer, length, returned, true);
            if matches!(result, Ok(0)) {
                crate::ntos::init::initial_process::process_list_returned(class, buffer);
            }
            return result;
        }
        53 => return system_process_information::query_session(buffer, length, returned, true),
        _ => {}
    }
    // ProbeForWrite real: o buffer de saída e o ReturnLength opcional
    // precisam ser graváveis.
    if (buffer != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let set_returned = |value: u32| if returned != 0 { guest::try_write::<u32>(returned, value) } else { Ok(()) };
        // As classes de tamanho fixo e as da célula de tamanho
        // (`ex/system_information`): o ProbeForWrite delas exige alinhamento 4.
        use crate::ntos::ex::system_information as information;
        let reported_class = matches!(class, information::SYSTEM_CPU_QUOTA_INFORMATION | information::SYSTEM_PLATFORM_BINARY_INFORMATION | information::SYSTEM_MEMORY_TOPOLOGY_INFORMATION | information::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION | information::SYSTEM_FIRMWARE_TABLE_INFORMATION | information::SYSTEM_POLICY_INFORMATION) || information::SYSTEM_CODE_INTEGRITY_POLICY_CLASSES.contains(&class);
        if (information::is_fixed_class(class) || reported_class) && length != 0 && buffer & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if let Some(result) = information::query_reported(class, buffer, length as u32, 1) {
            let (status, reported) = result?;
            if let Some(reported) = reported {
                set_returned(reported)?;
            }
            return Ok(status);
        }
        if let Some(result) = crate::ntos::ex::system_information::query_fixed(class, buffer, length as u32) {
            let (status, required) = result?;
            set_returned(required)?;
            return Ok(status);
        }
        match class {
            // SystemProcessorPerformanceInformation do grupo do processador
            // corrente (o NtQuerySystemInformation passa o grupo da KPRCB):
            // `ke/processor_information`.
            information::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION => {
                let (status, reported) = processor_information::query_performance(0, buffer, length as u32, &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
                set_returned(reported)?;
                Ok(status)
            }
            // SystemFirmwareTableInformation: `ex/firmware_table`, com a cópia
            // de kernel do modo usuário.
            information::SYSTEM_FIRMWARE_TABLE_INFORMATION => {
                let (status, reported) = crate::ntos::ex::firmware_table::query_system_information(buffer, length as u32, true)?;
                set_returned(reported)?;
                Ok(status)
            }
            // Basic/EmulationBasic/NativeBasic x64.
            0 | 62 | 114 => {
                if length < SystemBasicInformation::SIZE {
                    set_returned(SystemBasicInformation::SIZE as u32)?;
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                use crate::ntos::mm::physical_layout;
                // Preenchimento zerado como o resto da estrutura.
                guest::try_write_bytes(buffer, &[0; SystemBasicInformation::SIZE as usize])?;
                let basic = state::user_struct::<SystemBasicInformation>(buffer)?;
                basic.timer_resolution.probe_set(156_250)?; // 100 ns
                basic.page_size.probe_set(0x1000)?;
                basic.number_of_physical_pages.probe_set(physical_layout::number_of_physical_pages() as u32)?;
                basic.lowest_physical_page_number.probe_set(physical_layout::lowest_physical_page() as u32)?;
                basic.highest_physical_page_number.probe_set(physical_layout::highest_physical_page() as u32)?;
                basic.allocation_granularity.probe_set(memory_map::ALLOCATION_GRANULARITY as u32)?;
                basic.minimum_user_mode_address.probe_set(memory_map::LOWEST_USER_ADDRESS)?;
                basic.maximum_user_mode_address.probe_set(memory_map::HIGHEST_USER_ADDRESS)?;
                basic.active_processors_affinity_mask.probe_set(online_mask())?;
                basic.number_of_processors.probe_set(smp::online_cpu_count() as i8)?;
                set_returned(SystemBasicInformation::SIZE as u32)?;
                Ok(STATUS_SUCCESS)
            }
            // SystemLogicalProcessorInformation: o KeBuildLogicalProcessorSystemInformation
            // do grupo da thread (o 0), escrito sondado no buffer do chamador.
            73 => {
                let (status, required) = crate::ntos::ke::processor_topology::build_logical_processor_information(0, buffer, length as u32, &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
                set_returned(required)?;
                Ok(status)
            }
            // SystemPerformanceInformation e SystemPageFileInformation(Ex):
            // `mm/memory_information`.
            2 => {
                let (status, size) = memory_information::performance_information(buffer, length as u32)?;
                set_returned(size)?;
                Ok(status)
            }
            18 | 144 => {
                let entry = memory_information::page_file_entry_size(class == 144);
                if (length as u32) < entry {
                    set_returned(entry)?;
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                let (status, size) = memory_information::page_file_information(buffer, length as u32, class == 144)?;
                set_returned(size)?;
                Ok(status)
            }
            // SystemRangeStartInformation: um ULONG_PTR.
            50 => {
                set_returned(8)?;
                if length < 8 {
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                guest::try_write::<u64>(buffer, 0xFFFF_8000_0000_0000)?;
                Ok(STATUS_SUCCESS)
            }
            // SystemNumaProcessorMap: o ExpQueryNumaProcessorMap
            // (`ke/processor_group`), com as regras de tamanho do 19041.
            55 => {
                let (status, required) = crate::ntos::ke::processor_group::query_numa_processor_map(buffer, length as u32, &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
                set_returned(required)?;
                Ok(status)
            }
            _ => {
                crate::debug_print!("[usermode] NtQuerySystemInformation classe {} (nao coberta ainda)", class);
                // SystemMemoryListInformation.
                if class == 80 {
                    let size = SystemMemoryListInformation::SIZE;
                    set_returned(size as u32)?;
                    if length < size {
                        return Ok(STATUS_INFO_LENGTH_MISMATCH);
                    }
                    guest::try_write_bytes(buffer, &[0; SystemMemoryListInformation::SIZE as usize])?;
                    // Sem lista de páginas zeradas nem standby/pagefile.
                    state::user_struct::<SystemMemoryListInformation>(buffer)?.free_page_count.probe_set(pfn::free_count())?;
                    return Ok(STATUS_SUCCESS);
                }
                Ok(STATUS_INVALID_INFO_CLASS)
            }
        }
    })
}

/// Teto do buffer do kernel da topologia de processadores.
const TOPOLOGY_SCRATCH_LIMIT: u32 = 0x1_0000;

/// NtQuerySystemInformationEx(class, input, inputLength, buffer, length,
/// returnLength*) (19041, 0x6c7760): a entrada é obrigatória (NULL ou
/// comprimento zero, STATUS_INVALID_PARAMETER), só as classes com entrada
/// (`EX_CLASSES`, senão STATUS_INVALID_INFO_CLASS), e a entrada é sondada
/// para leitura com o alinhamento da classe. Depois: a topologia de
/// processadores, o desempenho e os conjuntos de CPU com a entrada deles e,
/// no resto, a variante sem entrada.
/// NtQuerySystemEnvironmentValueEx(VariableName, VendorGuid, Value,
/// ValueLength, Attributes): o acesso e o firmware em
/// `hal/firmware_environment.rs`; no BIOS nenhum argumento é tocado.
fn nt_query_system_environment_value_ex(_name: u64, _guid: u64, _value: u64, _length: u64, _rsp: u64) -> Result<u32, KernelError> {
    crate::hal::firmware_environment::query_user()
}

/// As classes já vistas por serviço: a linha `classe` de cada uma sai nas
/// quatro primeiras vezes e depois uma a cada 256, com a contagem, como as
/// linhas `FALHOU` (`index::failure_printed`); com TRACEFAILURES, todas.
static CLASS_LINES: SpinLock<alloc::collections::BTreeMap<(&'static str, u32), u32>> = SpinLock::new(alloc::collections::BTreeMap::new());

fn note_class(service: &'static str, class: u32) {
    let count = {
        let mut lines = CLASS_LINES.lock();
        let count = lines.entry((service, class)).or_insert(0);
        *count = count.saturating_add(1);
        *count
    };
    if crate::ntos::init::boot_config::trace_failures() || count <= 4 {
        crate::debug_print!("[usermode] {} classe {}", service, class);
    } else if super::win32k_status::printed(count) {
        crate::debug_print!("[usermode] {} classe {} ({} vezes)", service, class, count);
    }
}

fn nt_query_system_information_ex(class: u64, input: u64, input_length: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    let length = state::stack_arg32(rsp, 5) as u64;
    let returned = stack_arg(rsp, 6);
    let class = class as u32;
    note_class("NtQuerySystemInformationEx", class);
    use crate::ntos::ex::system_information as information;
    let input_length = input_length as u32;
    if input == 0 || input_length == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !information::EX_CLASSES.contains(&class) {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if input & (information::ex_input_alignment(class) - 1) != 0 {
        return Ok(0x8000_0002);
    }
    if !probe_user_read(input, input_length as u64) {
        return Ok(0xC000_0005);
    }
    let input_length = input_length as u64;
    match class {
        // SystemProcessorPerformanceInformation do grupo da entrada.
        information::SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION => {
            if (buffer != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
                return Ok(0xC000_0005);
            }
            if length != 0 && buffer & 3 != 0 {
                return Ok(0x8000_0002);
            }
            return state::guarded(|| {
                let group = if input_length >= 2 { guest::try_read::<u16>(input)? } else { 0 };
                let group = match information::ex_group(input_length as u32, group) {
                    Ok(group) => group,
                    Err(status) => return Ok(status),
                };
                let (status, reported) = processor_information::query_performance(group, buffer, length as u32, &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
                if returned != 0 {
                    guest::try_write::<u32>(returned, reported)?;
                }
                Ok(status)
            });
        }
        // SystemCpuSetInformation (0x6ccbac): exatamente o HANDLE do processo
        // alvo (NULL, o corrente), com PROCESS_QUERY_LIMITED_INFORMATION.
        information::SYSTEM_CPU_SET_INFORMATION => {
            if input_length != 8 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            if (buffer != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
                return Ok(0xC000_0005);
            }
            return state::guarded(|| {
                let handle = guest::try_read::<u64>(input)?;
                let mut target = None;
                if handle != 0 {
                    match crate::ntos::ob::process_reference::reference(handle, 0x1000, USER_MODE)? {
                        Ok(process) => target = Some(process),
                        Err(status) => return Ok(status),
                    }
                }
                let (status, reported) = crate::ntos::ke::cpu_set::query(buffer, length as u32, &mut |address, bytes| guest::try_write_bytes(address, bytes).is_ok());
                if let Some(mut process) = target {
                    process.release()?;
                }
                if returned != 0 {
                    guest::try_write::<u32>(returned, reported)?;
                }
                Ok(status)
            });
        }
        _ => {}
    }
    // SystemSupportedProcessorArchitectures: a entrada é o HANDLE do processo.
    if class == 181 {
        return crate::ntos::ex::supported_architectures::query(input, input_length, buffer, length, returned, queried_process);
    }
    // A configuração de features (`cm/feature_configuration`).
    use crate::ntos::cm::feature_configuration;
    if matches!(class, feature_configuration::SYSTEM_FEATURE_CONFIGURATION_INFORMATION | feature_configuration::SYSTEM_FEATURE_CONFIGURATION_SECTION_INFORMATION) {
        return feature_configuration::query_user(class, input, input_length as u32, buffer, length as u32, returned);
    }
    if class != 107 {
        return query_system_information(class, buffer, length, returned);
    }
    // A classe 107 lê a LOGICAL_PROCESSOR_RELATIONSHIP sondada.
    if (input_length as u32) < 4 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if !probe_user_read(input, 4) || (buffer != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let relationship = guest::try_read::<u32>(input)?;
        crate::debug_print!("[usermode] topologia: relationship={}", relationship);
        // O KeQueryLogicalProcessorRelationship num buffer do kernel (no
        // máximo 64 KB, que cobrem 64 processadores), copiado para o do
        // chamador; o ReturnLength recebe o tamanho exigido.
        let capacity = (length as u32).min(TOPOLOGY_SCRATCH_LIMIT);
        let scratch = guest::alloc_bytes(capacity as u64 + 8);
        if scratch == 0 {
            return Ok(0xC000_009A);
        }
        let cell = scratch + capacity as u64;
        guest::write32(cell, capacity);
        let status = crate::ntos::ke::processor_topology::query_logical_processor_relationship(None, relationship, scratch, cell);
        let required = guest::read32(cell);
        let bytes = guest::read_bytes(scratch, required.min(capacity) as usize);
        guest::free_bytes(scratch);
        let status = match status {
            Ok(status) => status,
            Err(_) => return Ok(0xC000_0001),
        };
        if required > capacity && status == STATUS_SUCCESS {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        if status == STATUS_SUCCESS && !bytes.is_empty() {
            guest::try_write_bytes(buffer, &bytes)?;
        }
        if returned != 0 {
            guest::try_write::<u32>(returned, required)?;
        }
        Ok(status)
    })
}

/// NtRaiseHardError(status, count, unicodeMask, params*, responseType,
/// response*): registra a mensagem e responde ResponseAbort.
fn nt_raise_hard_error(status: u64, count: u64, unicode_mask: u64, parameters: u64, rsp: u64) -> Result<u32, KernelError> {
    let count = count as u32 as u64;
    let response = stack_arg(rsp, 6);
    if count > 4 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if (count != 0 && !probe_user_read(parameters, count * 8)) || (response != 0 && !probe_user_write(response, 4)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let mut texts: Vec<String> = Vec::new();
        let mut values: Vec<u64> = Vec::new();
        for index in 0..count {
            // ULONG_PTR Parameters[index].
            let value = guest::try_read::<u64>(parameters + index * 8)?;
            values.push(value);
            if unicode_mask & (1 << index) != 0 {
                if !probe_user_read(value, 16) {
                    return Ok(0xC000_0005);
                }
                let string = state::user_struct::<UnicodeString>(value)?;
                let length = string.length.probe_get()? as u64;
                let buffer = string.buffer.probe_get()?;
                if length & 1 != 0 || !probe_user_read(buffer, length) {
                    return Ok(0xC000_0005);
                }
                texts.push(state::try_read_user_wide_string(buffer, (length / 2).min(512))?);
            } else {
                texts.push(alloc::format!("{value:#x}"));
            }
        }
        crate::debug_print!("[usermode] HARDERROR: status={:#x} params={} (pid {}, retorno {:#x})", status as u32, texts.join(" | "), crate::ntos::ps::process::get_current_process_id(), guest::try_read::<u64>(rsp).unwrap_or(0));
        super::crash_report::hard_error(status as u32, &values);
        if response != 0 {
            guest::try_write::<u32>(response, 2)?; // ResponseAbort
        }
        Ok(STATUS_SUCCESS)
    })
}

/// x64 unificado: a coerência de instruções é garantida pelo hardware. O
/// NtFlushInstructionCache do 19041 é só `xor eax, eax; ret` (nem o handle
/// nem a faixa são conferidos), e o JIT do d3d10warp exige o sucesso.
fn nt_flush_instruction_cache(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(STATUS_SUCCESS)
}

/// NtFlushProcessWriteBuffers do ntoskrnl 19041 (rva 0x3439a0):
/// KeFlushProcessWriteBuffers(FALSE), que interrompe os outros processadores
/// em que o processo está e espera por eles, e STATUS_SUCCESS sempre.
fn nt_flush_process_write_buffers(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if let Err(error) = crate::ntos::ke::smp::flush_process_write_buffers(false) {
        crate::debug_print!("[ke] NtFlushProcessWriteBuffers: {}", error);
    }
    Ok(STATUS_SUCCESS)
}

/// PROCESS_QUERY_LIMITED_INFORMATION, o que ProcessBasicInformation e
/// ProcessImageFileName pedem do handle.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;

/// O EPROCESS consultado: o do handle (de qualquer processo, procurado na
/// tabela de quem chama) ou o corrente pelo pseudo-handle.
fn queried_process(handle: u64) -> Result<u64, u32> {
    if handle as u32 == u32::MAX {
        return Ok(crate::ntos::ps::process::get_current_process());
    }
    super::handles::process_pointer(handle, PROCESS_QUERY_LIMITED_INFORMATION)
}

/// NtQueryInformationProcess(handle, class, buffer, length, retLen*).
fn nt_query_information_process(handle: u64, class: u64, buffer: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let class = class as u32;
    let length = length as u32 as u64;
    let returned = stack_arg(rsp, 5);
    let set_returned = |value: u32| if returned != 0 { guest::try_write::<u32>(returned, value) } else { Ok(()) };
    // As classes locais sondam o ReturnLength antes de qualquer escrita.
    let local = matches!(class, 0 | 24 | 27 | 28 | 31 | 36);
    if local && returned != 0 && !probe_user_write(returned, 4) {
        if class == 0 {
            if let Err(status) = queried_process(handle) {
                return Ok(status);
            }
        }
        return Ok(0xC000_0005);
    }
    // ProcessDefaultHardErrorMode, ProcessHandleCheckingMode e
    // ProcessBreakOnTermination (`ps/query_process`): o ProbeForWrite com
    // alinhamento 4 e a sonda do ReturnLength antes da classe.
    if matches!(class, 12 | 29 | 54) {
        if length != 0 && buffer & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if (length != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
            return Ok(0xC000_0005);
        }
        let process_of = |access: u32| {
            if handle as u32 == u32::MAX {
                Ok(crate::ntos::ps::process::get_current_process())
            } else {
                super::handles::process_pointer(handle, access)
            }
        };
        return state::guarded(|| {
            if class == crate::ntos::ps::query_process::PROCESS_BREAK_ON_TERMINATION {
                return crate::ntos::ps::query_process::query_break_on_termination(buffer, length as u32, returned, process_of);
            }
            crate::ntos::ps::query_process::query_mode(class, buffer, length as u32, returned, process_of)
        });
    }
    // ProcessQuotaLimits, ProcessVmCounters, ProcessTimes,
    // ProcessPriorityClass, ProcessImageFileNameWin32,
    // ProcessMitigationPolicy (`ps/query_process`) e
    // ProcessTelemetryIdInformation (`etw/process_telemetry`): o
    // ProbeForWrite de alinhamento 4 só pela faixa e o ReturnLength sondado
    // antes da classe.
    use crate::ntos::etw::process_telemetry;
    use crate::ntos::ps::query_process;
    if matches!(class, query_process::PROCESS_QUOTA_LIMITS | query_process::PROCESS_VM_COUNTERS | query_process::PROCESS_TIMES | query_process::PROCESS_PRIORITY_CLASS | query_process::PROCESS_IMAGE_FILE_NAME_WIN32 | query_process::PROCESS_MITIGATION_POLICY | process_telemetry::PROCESS_TELEMETRY_ID_INFORMATION) {
        if length != 0 {
            if buffer & 3 != 0 {
                return Ok(0x8000_0002);
            }
            let end = buffer.wrapping_add(length);
            if end > memory_map::USER_ADDRESS_LIMIT || end < buffer {
                return Ok(0xC000_0005);
            }
        }
        if returned != 0 && !probe_user_write(returned, 4) {
            return Ok(0xC000_0005);
        }
        let process_of = |access: u32| {
            if handle as u32 == u32::MAX {
                Ok(crate::ntos::ps::process::get_current_process())
            } else {
                super::handles::process_pointer(handle, access)
            }
        };
        return state::guarded(|| match class {
            query_process::PROCESS_QUOTA_LIMITS => query_process::query_quota_limits(buffer, length as u32, returned, process_of),
            query_process::PROCESS_VM_COUNTERS => query_process::query_vm_counters(buffer, length as u32, returned, process_of),
            query_process::PROCESS_TIMES => query_process::query_times(buffer, length as u32, returned, process_of),
            query_process::PROCESS_PRIORITY_CLASS => query_process::query_priority_class(buffer, length as u32, returned, process_of),
            query_process::PROCESS_IMAGE_FILE_NAME_WIN32 => query_process::query_image_file_name_win32(buffer, length as u32, returned, process_of),
            // O handle com PROCESS_QUERY_LIMITED_INFORMATION e o
            // EtwQueryProcessTelemetryInfo em UserMode.
            process_telemetry::PROCESS_TELEMETRY_ID_INFORMATION => match process_of(PROCESS_QUERY_LIMITED_INFORMATION) {
                Ok(process) => process_telemetry::query(process, buffer, length as u32, 1, returned),
                Err(status) => Ok(status),
            },
            _ => query_process::query_mitigation_policy(buffer, length as u32, process_of),
        });
    }
    state::guarded(|| match class {
        // ProcessBasicInformation (`ps/query_process::basic_information`), do
        // EPROCESS do handle: o processo consultado pode ser outro. Só 0x30
        // ou 0x40 (a estendida, com Size gravado antes da referência do
        // handle e os Flags); outro comprimento dá
        // STATUS_INFO_LENGTH_MISMATCH sem ReturnLength. Os campos são
        // gravados um a um, sem zerar o preenchimento.
        0 => {
            let extended = length == ProcessExtendedBasicInformation::SIZE;
            if length != ProcessBasicInformation::SIZE && !extended {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, length) {
                return Ok(0xC000_0005);
            }
            let extended_information = state::user_struct::<ProcessExtendedBasicInformation>(buffer)?;
            if extended {
                extended_information.size.probe_set(length)?;
            }
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            let values = query_process::basic_information(target);
            let basic = if extended { &extended_information.basic_info } else { state::user_struct::<ProcessBasicInformation>(buffer)? };
            basic.exit_status.probe_set(values.exit_status)?;
            basic.peb_base_address.probe_set(values.peb_base_address)?;
            basic.affinity_mask.probe_set(values.affinity_mask)?;
            basic.base_priority.probe_set(values.base_priority)?;
            basic.unique_process_id.probe_set(values.unique_process_id)?;
            basic.inherited_from_unique_process_id.probe_set(values.inherited_from_unique_process_id)?;
            if extended {
                extended_information.flags.probe_set(values.flags)?;
            }
            set_returned(length as u32)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessDebugPort, do estado da EPROCESS referenciada.
        7 => match *PROCESS_DEBUG_QUERY.lock() {
            Some(query) => query(rsp, returned),
            None => Ok(STATUS_INVALID_INFO_CLASS),
        },
        // ProcessImageInformation: dados da seção da imagem do alvo.
        37 => query_image_information(rsp),
        // ProcessImageFileName: UNICODE_STRING seguido do texto, do processo
        // do handle.
        27 => {
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            let path = super::process_state::get(target).map(|identity| identity.image_path()).unwrap_or_default();
            let path = if path.is_empty() { String::from("C:\\usertest.exe") } else { path };
            let need = UnicodeString::SIZE + (path.encode_utf16().count() as u64 + 1) * 2;
            if length < need {
                set_returned(need as u32)?;
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, need) {
                return Ok(0xC000_0005);
            }
            state::try_write_user_wide(buffer + UnicodeString::SIZE, &path)?;
            state::try_write_unicode_string(buffer, buffer + UnicodeString::SIZE, &path)?;
            set_returned(need as u32)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessSessionInformation (PROCESS_SESSION_INFORMATION, um ULONG):
        // a sessão do processo do handle (PsGetProcessSessionId).
        24 => {
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, 4) {
                return Ok(0xC000_0005);
            }
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            guest::try_write::<u32>(buffer, crate::ntos::ps::session::query(target))?;
            set_returned(4)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessDeviceMap (`ob/device_map.rs`): o ProbeForWrite com
        // alinhamento 4; o PROCESS_DEVICEMAP_INFORMATION de 0x24 bytes ou o
        // _EX de 0x30 com Flags (só PROCESS_LUID_DOSDEVICES_ONLY), outro
        // comprimento dá STATUS_INFO_LENGTH_MISMATCH; o handle com
        // PROCESS_QUERY_INFORMATION e o ObQueryDeviceMapInformation do
        // processo dele (outro que não o corrente é STATUS_INVALID_PARAMETER);
        // o DriveMap e o DriveType[32] no buffer e o comprimento no
        // ReturnLength.
        23 => {
            if length != 0 && buffer & 3 != 0 {
                return Ok(0x8000_0002);
            }
            if (length != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
                return Ok(0xC000_0005);
            }
            let flags = match length {
                0x24 => 0,
                0x30 => {
                    let flags = guest::try_read::<u32>(buffer + 0x28)?;
                    if flags & !1 != 0 {
                        return Ok(0xC000_000D);
                    }
                    flags
                }
                _ => return Ok(STATUS_INFO_LENGTH_MISMATCH),
            };
            let target = if handle as u32 != u32::MAX {
                match super::handles::process_pointer(handle, 0x400) {
                    Ok(target) => target,
                    Err(status) => return Ok(status),
                }
            } else {
                crate::ntos::ps::process::get_current_process()
            };
            let information = match crate::ntos::ob::device_map::query(target, flags) {
                Ok(information) => information,
                Err(status) => return Ok(status),
            };
            guest::try_write::<u32>(buffer, information.drive_map)?;
            guest::try_write_bytes(buffer + 4, &information.drive_type)?;
            set_returned(length as u32)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessWindowInformation (PROCESS_WINDOW_INFORMATION: o ULONG
        // WindowFlags, o USHORT WindowTitleLength e o título), como o
        // NtQueryInformationProcess do 19041 (0x623654): o handle com
        // PROCESS_QUERY_LIMITED_INFORMATION, anexado ao processo, o
        // WindowFlags (+0xA4) e o WindowTitle (+0xB0) do
        // RTL_USER_PROCESS_PARAMETERS do PEB (num processo WOW64, os do
        // PEB32: +0x68 e +0x70); o tamanho é o comprimento do título mais 6,
        // gravado no ReturnLength mesmo quando o buffer é menor
        // (STATUS_INFO_LENGTH_MISMATCH); o título chega ao buffer, logo
        // depois do comprimento, pelo MmCopyVirtualMemory do processo dele.
        // O CallerIdentity::GetWeakProcessAppId do twinui lê por ela o AppId
        // do título (o STARTF_TITLEISAPPID, 0x1000, nas flags).
        50 => {
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            let wow64_peb = crate::ntos::ps::process_accessors::wow64_process(target);
            let native_peb = crate::ntos::ps::process_accessors::peb(target);
            let read = crate::ntos::ps::process_context::with_process(target, || -> Result<(u32, u16, u64), KernelError> {
                if wow64_peb != 0 {
                    let parameters = guest::try_read::<u32>(wow64_peb + 0x10)? as u64;
                    let flags = guest::try_read::<u32>(parameters + 0x68)?;
                    let title_length = guest::try_read::<u16>(parameters + 0x70)?;
                    let title_buffer = guest::try_read::<u32>(parameters + 0x74)? as u64;
                    return Ok((flags, title_length, title_buffer));
                }
                let parameters = state::user_struct::<crate::ntos::inc::types::Peb>(native_peb)?.process_parameters.probe_get()?;
                let parameters = state::user_struct::<crate::ntos::inc::types::RtlUserProcessParameters>(parameters)?;
                Ok((parameters.window_flags.probe_get()?, parameters.window_title.length.probe_get()?, parameters.window_title.buffer.probe_get()?))
            });
            let (flags, title_length, title_buffer) = match read {
                Ok(Ok(values)) => values,
                Ok(Err(error)) => return Ok(error.status),
                Err(_) => return Ok(0xC000_010A),
            };
            let required = title_length as u32 + 6;
            set_returned(required)?;
            if (length as u32) < required {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::try_write::<u32>(buffer, flags)?;
            guest::try_write::<u16>(buffer + 4, title_length)?;
            if title_length == 0 {
                return Ok(STATUS_SUCCESS);
            }
            let current = crate::ntos::ps::process::get_current_process();
            let (status, _) = crate::ntos::mm::copy_virtual::copy_virtual_memory(target, title_buffer, current, buffer + 6, title_length as u64, 1)?;
            Ok(status)
        }
        // ProcessLUIDDeviceMapsEnabled (ULONG): o NtQueryInformationProcess
        // 19041 sonda o buffer (alinhamento 4) e responde a constante 1 sem
        // consultar o handle; comprimento diferente de 4 é
        // STATUS_INFO_LENGTH_MISMATCH.
        28 => {
            if length != 0 && buffer & 3 != 0 {
                return Ok(0x8000_0002);
            }
            if length != 0 && !probe_user_write(buffer, length) {
                return Ok(0xC000_0005);
            }
            if length != 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::try_write::<u32>(buffer, 1)?;
            set_returned(4)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessDebugFlags (ULONG): 1 = sem depurador.
        31 => {
            if length < 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, 4) {
                return Ok(0xC000_0005);
            }
            guest::try_write::<u32>(buffer, 1)?;
            set_returned(4)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessCookie (ULONG): o EPROCESS.Cookie do RtlEncodePointer, por
        // processo e nunca zero (`ps/query_process::query_cookie`); um handle
        // que não é o pseudo-handle precisa de PROCESS_VM_WRITE.
        36 => {
            if length != 0 && buffer & 3 != 0 {
                return Ok(0x8000_0002);
            }
            if length != 0 && !probe_user_write(buffer, length) {
                return Ok(0xC000_0005);
            }
            let handle = if handle as u32 == u32::MAX { u64::MAX } else { handle };
            crate::ntos::ps::query_process::query_cookie(handle, buffer, length as u32, returned, |access| super::handles::process_pointer(handle, access))
        }
        // ProcessConsoleHostProcess (ULONG_PTR): o EPROCESS.OwnerProcessId
        // que o PspAllocateProcess grava (o processo que criou, com o bit 2
        // sem o 0x200 das flags de criação) e que a classe 49 do
        // NtSetInformationProcess troca (o PID do conhost com o bit 0, o
        // ConsoleCommitState do kernelbase); ProcessSequenceNumber
        // (ULONGLONG): o EPROCESS.SequenceNumber. As duas pelo handle com
        // PROCESS_QUERY_LIMITED_INFORMATION, como o NtQueryInformationProcess
        // 19041; outro comprimento é STATUS_INFO_LENGTH_MISMATCH. O csrss as
        // lê no BaseSrvCreateProcess de cada processo novo.
        49 | 92 => {
            if length != 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if buffer & 7 != 0 && class == 92 {
                return Ok(0x8000_0002);
            }
            if !probe_user_write(buffer, 8) {
                return Ok(0xC000_0005);
            }
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            // SAFETY: o EPROCESS do handle, retido pela tabela de handles.
            let process = unsafe { Eprocess::at(target) };
            let value = if class == 49 { process.owner_process_id.get() } else { process.sequence_number.get() };
            guest::try_write::<u64>(buffer, value)?;
            set_returned(8)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessWow64Information (ULONG_PTR): o PEB de 32 bits do processo
        // WoW64, pelo handle com PROCESS_QUERY_LIMITED_INFORMATION; outro
        // comprimento é STATUS_INFO_LENGTH_MISMATCH. O OpenNT só roda
        // processos nativos de 64 bits: 0.
        26 => {
            if length != 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, 8) {
                return Ok(0xC000_0005);
            }
            if let Err(status) = queried_process(handle) {
                return Ok(status);
            }
            guest::try_write::<u64>(buffer, 0)?;
            set_returned(8)?;
            Ok(STATUS_SUCCESS)
        }
        // ProcessProtectionInformation (PS_PROTECTION, 1 byte): o
        // EPROCESS.Protection pelo handle com
        // PROCESS_QUERY_LIMITED_INFORMATION; outro comprimento é
        // STATUS_INFO_LENGTH_MISMATCH. O SspiSrv do lsass lê o nível de
        // proteção do próprio processo.
        61 => {
            if length != 1 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, 1) {
                return Ok(0xC000_0005);
            }
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            // SAFETY: o EPROCESS do handle, retido pela tabela de handles.
            let level = unsafe { Eprocess::at(target) }.protection.level.get();
            guest::try_write::<u8>(buffer, level)?;
            set_returned(1)?;
            Ok(STATUS_SUCCESS)
        }
        _ => {
            note_class("NtQueryInformationProcess", class);
            Ok(STATUS_INVALID_INFO_CLASS)
        }
    })
}

/// `image_information::query`: os 64 bits dos argumentos e as
/// sondagens de UserMode antes de consultar o processo e a seção.
pub fn query_image_information(rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = state::syscall_arg_words(rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let handle = argument(1);
    let output = argument(3);
    let length = state::syscall_arg_words(rsp, 4)[0];
    let returned = argument(5);
    fn probe(pointer: u64, size: u64) -> bool {
        pointer.checked_add(size).is_some_and(|end| end <= memory_map::USER_ADDRESS_LIMIT) && probe_user_write(pointer, size)
    }
    // A sondagem inicial verifica alinhamento e faixa; ReturnLength é
    // sondado antes do tamanho, do handle e da cópia final.
    if length != 0 {
        if output & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if output.checked_add(length as u64).is_none_or(|end| end > memory_map::USER_ADDRESS_LIMIT) {
            return Ok(0xC000_0005);
        }
    }
    if returned != 0 && !probe(returned, 4) {
        return Ok(0xC000_0005);
    }
    image_information::query(handle, output, length, returned, 1, Some(probe))
}

/// NtSetInformationProcess: instrumentação (40), TLS (35) e as classes de
/// `ps/set_process_information`.
/// ProcessMitigationPolicy.
const PROCESS_MITIGATION_POLICY: u32 = 52;

fn nt_set_information_process(handle: u64, class: u64, buffer: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    let setter = match class as u32 {
        40 => *INSTRUMENTATION_SET.lock(),
        35 => *TLS_SET.lock(),
        _ => None,
    };
    if let Some(setter) = setter {
        return setter(handle, buffer, length);
    }
    // ProcessMitigationPolicy: a política e as flags (`ps/mitigation_policy`).
    if class as u32 == PROCESS_MITIGATION_POLICY {
        if length != 8 {
            return Ok(0xC000_0004);
        }
        if !probe_user_read(buffer, 8) {
            return Ok(0xC000_0005);
        }
        let (Ok(policy), Ok(flags)) = (guest::try_read::<u32>(buffer), guest::try_read::<u32>(buffer + 4)) else { return Ok(0xC000_0005) };
        return crate::ntos::ps::mitigation_policy::set(handle as u32 == u32::MAX, policy, flags);
    }
    // As classes que mudam o EPROCESS (`ps/set_process_information`).
    use crate::ntos::ps::set_process_information as set_process;
    if class as u32 == set_process::PROCESS_DYNAMIC_FUNCTION_TABLE_INFORMATION {
        return set_process::set_dynamic_function_table(1, handle, buffer, length as u32);
    }
    if class as u32 == set_process::PROCESS_CONSOLE_HOST_PROCESS {
        return set_process::set_console_host_process(1, handle, buffer, length as u32);
    }
    if set_process::CLASSES.contains(&(class as u32)) {
        return set_process::set_information(1, class as u32, buffer, length as u32, |access| {
            if handle as u32 == u32::MAX {
                Ok(crate::ntos::ps::process::get_current_process())
            } else {
                super::handles::process_pointer(handle, access)
            }
        });
    }
    crate::debug_print!("[usermode] NtSetInformationProcess classe {}", class as u32);
    Ok(STATUS_INVALID_INFO_CLASS)
}

fn nt_raise_exception(record: u64, context: u64, first_chance: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    match *RAISE_EXCEPTION.lock() {
        Some(raise) => raise(record, context, first_chance),
        None => Ok(state::STATUS_NOT_IMPLEMENTED),
    }
}

fn nt_open_symbolic_link_object(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(namespace_handles::open(out, access as u32, attributes, "SymbolicLink", true, false))
}

fn nt_query_symbolic_link_object(handle: u64, out: u64, returned: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(namespace_handles::query_link(handle, out, returned, true))
}

fn nt_open_directory_object(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(namespace_handles::open(out, access as u32, attributes, "Directory", true, false))
}

/// NtCreateDirectoryObject(DirectoryHandle*, DesiredAccess, ObjectAttributes).
fn nt_create_directory_object(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(namespace_handles::open(out, access as u32, attributes, "Directory", true, true))
}

/// NtCreateDirectoryObjectEx(DirectoryHandle*, DesiredAccess,
/// ObjectAttributes, ShadowDirectoryHandle, Flags) (`ob/handles/namespace`).
fn nt_create_directory_object_ex(out: u64, access: u64, attributes: u64, shadow: u64, rsp: u64) -> Result<u32, KernelError> {
    Ok(namespace_handles::create_directory_ex(out, access as u32, attributes, shadow, state::stack_arg32(rsp, 5), true))
}

/// NtCreatePrivateNamespace(NamespaceHandle*, DesiredAccess,
/// ObjectAttributes, BoundaryDescriptor) (`ob/private_namespace`).
fn nt_create_private_namespace(out: u64, access: u64, attributes: u64, boundary: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ob::private_namespace::create(out, access as u32, attributes, boundary, 1))
}

/// NtOpenPrivateNamespace(NamespaceHandle*, DesiredAccess,
/// ObjectAttributes, BoundaryDescriptor) (`ob/private_namespace`).
fn nt_open_private_namespace(out: u64, access: u64, attributes: u64, boundary: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ob::private_namespace::open(out, access as u32, attributes, boundary, 1))
}

/// NtDeletePrivateNamespace(NamespaceHandle) (`ob/private_namespace`).
fn nt_delete_private_namespace(handle: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::ob::private_namespace::delete(handle, 1))
}

/// NtCreateSymbolicLinkObject(LinkHandle*, DesiredAccess, ObjectAttributes,
/// LinkTarget): o destino capturado da UNICODE_STRING do chamador.
fn nt_create_symbolic_link_object(out: u64, access: u64, attributes: u64, target: u64, _rsp: u64) -> Result<u32, KernelError> {
    if !probe_user_read(target, UnicodeString::SIZE) {
        return Ok(0xC000_0005);
    }
    let text = state::user_struct::<UnicodeString>(target).and_then(|target| Ok((target.length.probe_get()? as u64, target.maximum_length.probe_get()? as u64, target.buffer.probe_get()?)));
    let Ok((length, maximum, buffer)) = text else { return Ok(0xC000_0005) };
    if length % 2 != 0 || length > maximum || (length != 0 && !probe_user_read(buffer, length)) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let Ok(target_text) = state::try_read_user_wide_string(buffer, length / 2) else { return Ok(0xC000_0005) };
    Ok(namespace_handles::create_link(out, access as u32, attributes, &target_text, true))
}

/// NtSetSecurityObject(Handle, SecurityInformation, SecurityDescriptor).
fn nt_set_security_object(handle: u64, information: u64, descriptor: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::ob::object_security::set_security_object_from_user(handle, information as u32, descriptor)
}

/// NtQuerySecurityObject(handle, flags, out, length, returned*).
/// O descritor do objeto pelo SecurityProcedure do tipo (`ob/query_security.rs`).
fn nt_query_security_object(handle: u64, flags: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::ob::query_security::query_from_user(handle, flags as u32, out, length as u32, stack_arg(rsp, 5))
}

fn nt_open_partition(out: u64, access: u64, attributes: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    match *OPEN_PARTITION.lock() {
        Some(open) => open(out, access as u32, attributes),
        None => Ok(state::STATUS_NOT_IMPLEMENTED),
    }
}

/// Sem partições de usuário: objeto inexistente é a resposta real.
fn nt_create_partition(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(STATUS_INVALID_HANDLE)
}

/// NtQueryLicenseValue(ValueName, Type, Data, DataSize, ResultDataSize).
fn nt_query_license_value(name: u64, type_pointer: u64, data: u64, data_size: u64, rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::ex::license::values::query_user(name, type_pointer, data, data_size as u32, state::stack_arg(rsp, 5))
}

/// NtQueryDirectoryObject(DirectoryHandle, Buffer, Length,
/// ReturnSingleEntry, RestartScan, Context*, ReturnLength*)
/// (`ob/handles/namespace`).
fn nt_query_directory_object(handle: u64, buffer: u64, length: u64, single: u64, rsp: u64) -> Result<u32, KernelError> {
    let restart = state::stack_boolean(rsp, 5);
    Ok(namespace_handles::query_directory_mode(handle, buffer, length as u32, state::boolean(single), restart, stack_arg(rsp, 6), stack_arg(rsp, 7), true))
}

/// NtApphelpCacheControl(Service, ServiceData) (`ps/apphelp_cache`).
fn nt_apphelp_cache_control(service: u64, data: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    crate::ntos::ps::apphelp_cache::control(service as u32 as i32, data, 1)
}

pub fn init() {
    let handlers: [(&'static str, state::SyscallHandler); 37] = [
        ("NtQueryDirectoryObject", nt_query_directory_object),
        ("NtApphelpCacheControl", nt_apphelp_cache_control),
        ("NtQueryLicenseValue", nt_query_license_value),
        ("NtGetCurrentProcessorNumber", nt_get_current_processor_number),
        ("NtGetCurrentProcessorNumberEx", nt_get_current_processor_number_ex),
        ("NtDisplayString", nt_display_string),
        ("NtTerminateProcess", nt_terminate_process),
        ("NtQueryPerformanceCounter", nt_query_performance_counter),
        ("NtContinue", nt_continue_legacy),
        ("NtContinueEx", nt_continue_ex),
        ("NtWaitForSingleObject", nt_wait_for_single_object),
        ("NtWaitForMultipleObjects", nt_wait_for_multiple_objects),
        ("NtSignalAndWaitForSingleObject", nt_signal_and_wait_for_single_object),
        ("NtQuerySystemInformation", nt_query_system_information),
        ("NtQuerySystemInformationEx", nt_query_system_information_ex),
        ("NtQuerySystemEnvironmentValueEx", nt_query_system_environment_value_ex),
        ("NtSetSystemInformation", nt_set_system_information),
        ("NtSerializeBoot", nt_serialize_boot),
        ("NtRaiseHardError", nt_raise_hard_error),
        ("NtFlushInstructionCache", nt_flush_instruction_cache),
        ("NtFlushProcessWriteBuffers", nt_flush_process_write_buffers),
        ("NtQueryInformationProcess", nt_query_information_process),
        ("NtSetInformationProcess", nt_set_information_process),
        ("NtRaiseException", nt_raise_exception),
        ("NtOpenSymbolicLinkObject", nt_open_symbolic_link_object),
        ("NtQuerySymbolicLinkObject", nt_query_symbolic_link_object),
        ("NtOpenDirectoryObject", nt_open_directory_object),
        ("NtCreateDirectoryObject", nt_create_directory_object),
        ("NtCreateDirectoryObjectEx", nt_create_directory_object_ex),
        ("NtCreatePrivateNamespace", nt_create_private_namespace),
        ("NtOpenPrivateNamespace", nt_open_private_namespace),
        ("NtDeletePrivateNamespace", nt_delete_private_namespace),
        ("NtCreateSymbolicLinkObject", nt_create_symbolic_link_object),
        ("NtQuerySecurityObject", nt_query_security_object),
        ("NtSetSecurityObject", nt_set_security_object),
        ("NtOpenPartition", nt_open_partition),
        ("NtCreatePartition", nt_create_partition),
    ];
    for (name, handler) in handlers {
        state::register_handler(name, handler);
    }
}

// ---- NtContinueEx (KiContinueEx) ----
//
// Medido no ntoskrnl 19045: NtContinue é `movzx edx, dl; jmp NtContinueEx`.
// KiContinueEx: até 0xFF o segundo argumento é o BOOLEAN TestAlert; acima,
// um KCONTINUE_ARGUMENT alinhado a 8 e legível (ContinueFlags: TEST_ALERT 1,
// DELIVER_APC 2; o ContinueType não é conferido). O CONTEXT precisa de
// alinhamento 16; com TestAlert o primeiro e o último byte são sondados para
// escrita, senão o primeiro para leitura. TestAlert chama
// KeTestAlertThread(UserMode); com DELIVER_APC e UserApcPending a próxima APC
// entra no próprio CONTEXT e o serviço devolve 0 sem restaurá-lo; o resto é
// o KiContinuePreviousModeUser (`nt_continue`). Uma pendência publicada sem
// DELIVER_APC sai no retorno ao modo usuário (`user_apc::deliver`).

use super::user_apc;
use crate::ntos::inc::types::extra_usermode::{KcontinueArgument, KCONTINUE_FLAG_DELIVER_APC, KCONTINUE_FLAG_TEST_ALERT};
use crate::ntos::ke::test_alert;
use crate::ntos::ps::process;

/// O ProbeForRead/ProbeForWrite de um endereço desalinhado.
const CONTINUE_MISALIGNED: u32 = 0x8000_0002;
const CONTINUE_ACCESS_VIOLATION: u32 = 0xC000_0005;

fn nt_continue_ex(context: u64, argument: u64, _a3: u64, _a4: u64, rsp: u64) -> Result<u32, KernelError> {
    let (alert, deliver_apc) = if argument > 0xFF {
        if argument & 7 != 0 {
            return Ok(CONTINUE_MISALIGNED);
        }
        if !probe_user_read(argument, KcontinueArgument::SIZE) {
            return Ok(CONTINUE_ACCESS_VIOLATION);
        }
        let flags = match state::user_struct::<KcontinueArgument>(argument).and_then(|continuation| continuation.continue_flags.probe_get()) {
            Ok(flags) => flags,
            Err(error) => return Ok(error.status),
        };
        (flags & KCONTINUE_FLAG_TEST_ALERT != 0, flags & KCONTINUE_FLAG_DELIVER_APC != 0)
    } else {
        (argument as u8 != 0, false)
    };
    if context & 15 != 0 {
        return Ok(CONTINUE_MISALIGNED);
    }
    if alert {
        if !probe_user_write(context, 1) || !probe_user_write(context + Context::SIZE - 1, 1) {
            return Ok(CONTINUE_ACCESS_VIOLATION);
        }
        test_alert::test(1)?;
        let thread = process::get_current_thread();
        if deliver_apc && user_apc::user_apc_pending(thread) {
            if let Some(status) = user_apc::deliver_in_place(thread, context) {
                return Ok(status);
            }
        }
    } else if !probe_user_read(context, 1) {
        return Ok(CONTINUE_ACCESS_VIOLATION);
    }
    nt_continue(context, 0, 0, 0, rsp)
}

/// NtContinue(context, testAlert) = NtContinueEx(context, (BYTE)testAlert).
/// O NtContinue(ctx, TRUE) do LdrInitializeThunk entrega assim as APCs
/// enfileiradas antes da thread começar.
fn nt_continue_legacy(context: u64, alertable: u64, a3: u64, a4: u64, rsp: u64) -> Result<u32, KernelError> {
    nt_continue_ex(context, alertable & 0xFF, a3, a4, rsp)
}
