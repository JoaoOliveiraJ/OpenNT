//! Serviços centrais de modo usuário.
//!
//! Processador corrente, display de boot, término, contador de desempenho,
//! NtContinue sobre o frame do syscall, esperas reais, informações de
//! sistema e de processo, erro fatal, objetos de namespace e segurança. As
//! classes de outros módulos (depuração, instrumentação, TLS, exceções,
//! partições) entram pelos ganchos que esses módulos instalam.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::state::{self, probe_user_read, probe_user_write, stack_arg, UserHandle, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, TERMINATE_MAGIC};
use super::threads;
use crate::hal::{amd64::usermode, cpu, kmalloc, serial};
use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::{clock, dispatcher, pcr, processor_information, smp};
use crate::ntos::mm::{memory_map, pfn};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ps::{image_information, system_process_information};
use crate::ntos::ps::context::registers as thread_context_registers;
use crate::ntos::se::{code_integrity_information, object_security, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::extra_ps_user::SystemMemoryListInformation;
use crate::ntos::inc::types::{Context, Eprocess, NtStruct, ProcessBasicInformation, ProcessExtendedBasicInformation, ProcessorNumber, SystemBasicInformation, SystemLogicalProcessorInformationEx, SystemNumaInformation, UnicodeString, XsaveFormat};

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
/// handle real para ele), o código vai para a HAL, que encerra o intervalo
/// de vez (longjmp), e o despachante pede o fim do processo.
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
    }
    crate::debug_print!("[usermode] NtTerminateProcess(exit={:#x})", exit_code as u32);
    usermode::block().exit_code.set(exit_code as u32);
    Ok(TERMINATE_MAGIC)
}

fn nt_query_performance_counter(counter: u64, frequency: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if counter == 0 || !probe_user_write(counter, 8) || (frequency != 0 && !probe_user_write(frequency, 8)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        // LARGE_INTEGER.QuadPart de cada saída: um store de qword sondado.
        guest::try_write::<u64>(counter, cpu::rdtsc())?;
        if frequency != 0 {
            guest::try_write::<u64>(frequency, clock::tsc_frequency_hz())?;
        }
        Ok(STATUS_SUCCESS)
    })
}

/// NtContinue(context, alertable): reescreve o frame do syscall com o
/// CONTEXT; o retorno da HAL retoma o contexto. GPRs são copiados como
/// padrões de bits opacos.
fn nt_continue(context: u64, _alertable: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if context == 0 || !probe_user_read(context, 0x300) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let user = state::user_struct::<Context>(context)?;
        let flags = user.context_flags.probe_get()?;
        if flags & 3 != 3 || flags & 0x40 != 0 {
            return Ok(STATUS_INVALID_PARAMETER);
        }
        // Bits reservados fariam o FXRSTOR falhar no kernel.
        if flags & 8 != 0 && user.flt_save.mx_csr.probe_get()? & !0xFFFF != 0 {
            return Ok(STATUS_INVALID_PARAMETER);
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
        let float_image = if flags & 8 != 0 { Some(guest::try_read_bytes(user.flt_save.address(), XsaveFormat::SIZE as usize)?) } else { None };
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
        if let Some(image) = float_image {
            // Imagem FXSAVE que o retorno da HAL restaura, logo abaixo do frame.
            guest::write_bytes(frame.address() - 0x208, &image);
        }
        if debug_bank != 0 {
            if let Some(setter) = *SET_USER_DEBUG_REGISTERS.lock() {
                setter(debug_bank);
            }
            guest::free_bytes(debug_bank);
        }
        block.continue_flag.set(1);
        crate::debug_print!("[usermode] NtContinue -> rip {:#x} rsp {:#x}", rip, rsp);
        Ok(rax as u32)
    })
}

/// Objeto esperável do handle com SYNCHRONIZE.
fn waitable(handle: u64) -> Result<(Arc<UserHandle>, u64), u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(STATUS_INVALID_HANDLE) };
    let Some(pointer) = entry.object.wait_pointer() else { return Err(STATUS_INVALID_HANDLE) };
    if entry.access() & 0x10_0000 == 0 {
        return Err(0xC000_0022);
    }
    Ok((entry, pointer))
}

/// NtWaitForSingleObject(handle, alertable, timeout*): espera real.
fn nt_wait_for_single_object(handle: u64, alertable: u64, timeout: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if timeout != 0 && !probe_user_read(timeout, 8) {
        return Ok(0xC000_0005);
    }
    let (entry, pointer) = match waitable(handle) {
        Ok(found) => found,
        Err(status) => return Ok(status),
    };
    if threads::active() {
        return Ok(threads::wait_objects(alloc::vec![entry], alloc::vec![pointer], 1, timeout, alertable & 0xFF != 0));
    }
    Ok(dispatcher::wait_for_single_object(pointer, timeout, 0, false))
}

/// NtWaitForMultipleObjects(count, handles*, waitType, alertable, timeout*).
fn nt_wait_for_multiple_objects(count: u64, handles: u64, wait_type: u64, alertable: u64, rsp: u64) -> Result<u32, KernelError> {
    let count = count as u32 as u64;
    if count == 0 || count > 64 || wait_type > 1 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let timeout = stack_arg(rsp, 5);
    if !probe_user_read(handles, count * 8) || (timeout != 0 && !probe_user_read(timeout, 8)) {
        return Ok(0xC000_0005);
    }
    // O vetor de HANDLEs é capturado de uma vez (cópia sondada).
    let captured = match guest::try_read_bytes(handles, (count * 8) as usize) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(0xC000_0005),
    };
    let mut pointers = Vec::new();
    let mut entries = Vec::new();
    for handle in captured.chunks_exact(8).map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8]))) {
        match waitable(handle) {
            Ok((entry, pointer)) => {
                entries.push(entry);
                pointers.push(pointer);
            }
            Err(status) => return Ok(status),
        }
    }
    let mut unique = pointers.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() as u64 != count {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if threads::active() {
        return Ok(threads::wait_objects(entries, pointers, wait_type as u32, timeout, alertable & 0xFF != 0));
    }
    let array = guest::alloc_bytes(count * 8);
    if array == 0 {
        return Ok(0xC000_0017);
    }
    let objects: Vec<u8> = pointers.iter().flat_map(|pointer| pointer.to_le_bytes()).collect();
    guest::write_bytes(array, &objects);
    let status = dispatcher::wait_for_multiple_objects(count as u32, array, wait_type as u32, timeout, 0, false);
    guest::free_bytes(array);
    Ok(status)
}

/// NtSerializeBoot(): `io/pnp::serialize_boot`, de modo usuário.
fn nt_serialize_boot(_: u64, _: u64, _: u64, _: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(crate::ntos::io::pnp::serialize_boot(1))
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
        157 => return crate::ntos::ex::manufacturing_information::query(buffer, length, returned, true),
        3 => return crate::ntos::ex::time_of_day_information::query(buffer, length, returned, true),
        1 | 63 => return Ok(processor_information::query(buffer, length as u32, returned, true, class == 63)),
        5 => return system_process_information::query(buffer, length, returned, true),
        _ => {}
    }
    // ProbeForWrite real: o buffer de saída e o ReturnLength opcional
    // precisam ser graváveis.
    if (buffer != 0 && !probe_user_write(buffer, length)) || (returned != 0 && !probe_user_write(returned, 4)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        let set_returned = |value: u32| if returned != 0 { guest::try_write::<u32>(returned, value) } else { Ok(()) };
        match class {
            // Basic/EmulationBasic/NativeBasic x64.
            0 | 62 | 114 => {
                if length < SystemBasicInformation::SIZE {
                    set_returned(SystemBasicInformation::SIZE as u32)?;
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                let pages = kmalloc::ram_top() / 0x1000;
                // Preenchimento zerado como o resto da estrutura.
                guest::try_write_bytes(buffer, &[0; SystemBasicInformation::SIZE as usize])?;
                let basic = state::user_struct::<SystemBasicInformation>(buffer)?;
                basic.timer_resolution.probe_set(156_250)?; // 100 ns
                basic.page_size.probe_set(0x1000)?;
                basic.number_of_physical_pages.probe_set(pages as u32)?;
                basic.highest_physical_page_number.probe_set((pages - 1) as u32)?;
                basic.allocation_granularity.probe_set(memory_map::ALLOCATION_GRANULARITY as u32)?;
                basic.minimum_user_mode_address.probe_set(memory_map::LOWEST_USER_ADDRESS)?;
                basic.maximum_user_mode_address.probe_set(memory_map::HIGHEST_USER_ADDRESS)?;
                basic.active_processors_affinity_mask.probe_set(online_mask())?;
                basic.number_of_processors.probe_set(smp::online_cpu_count() as i8)?;
                set_returned(SystemBasicInformation::SIZE as u32)?;
                Ok(STATUS_SUCCESS)
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
            // SYSTEM_NUMA_INFORMATION com um único nó (o prefixo de 24 bytes).
            55 => {
                set_returned(24)?;
                if length < 24 {
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                let numa = state::user_struct::<SystemNumaInformation>(buffer)?;
                numa.highest_node_number.probe_set(0)?;
                numa.reserved.probe_set(0)?;
                let node = &numa.active_processors_group_affinity[0];
                node.mask.probe_set(online_mask())?;
                node.group.probe_set(0)?;
                for reserved in &node.reserved {
                    reserved.probe_set(0)?;
                }
                Ok(STATUS_SUCCESS)
            }
            _ => {
                crate::debug_print!("[usermode] NtQuerySystemInformation classe {} (nao coberta ainda)", class);
                // Classes de política/recurso ausente: buffer zerado, nunca
                // INVALID_INFO_CLASS (a 24H2 trata como fatal no loader).
                if class == 192 || class == 197 {
                    guest::try_write_bytes(buffer, &alloc::vec![0; length as usize])?;
                    set_returned(length as u32)?;
                    return Ok(STATUS_SUCCESS);
                }
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

/// NtQuerySystemInformationEx(class, input, inputLength, buffer, length,
/// returnLength*): a topologia de processadores e, no resto, a variante
/// sem entrada.
fn nt_query_system_information_ex(class: u64, input: u64, input_length: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    let length = state::stack_arg32(rsp, 5) as u64;
    let returned = stack_arg(rsp, 6);
    let class = class as u32;
    crate::debug_print!("[usermode] NtQuerySystemInformationEx classe {}", class);
    // SystemSupportedProcessorArchitectures: a entrada é o HANDLE do processo.
    if class == 181 {
        return crate::ntos::ex::supported_architectures::query(input, input_length, buffer, length, returned, queried_process);
    }
    if class != 107 {
        return query_system_information(class, buffer, length, returned);
    }
    if input_length as u32 != 4 || input == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // InputBuffer e ReturnLength são sondados antes do uso.
    if !probe_user_read(input, 4) || (returned != 0 && !probe_user_write(returned, 4)) {
        return Ok(0xC000_0005);
    }
    state::guarded(|| {
        // LOGICAL_PROCESSOR_RELATIONSHIP.
        let relationship = guest::try_read::<u32>(input)?;
        crate::debug_print!("[usermode] topologia: relationship={}", relationship);
        let need = match relationship {
            4 => 80u64,
            1 | 6 => 48,
            _ => return Ok(STATUS_INVALID_INFO_CLASS),
        };
        if returned != 0 {
            guest::try_write::<u32>(returned, need as u32)?;
        }
        if length < need {
            return Ok(STATUS_INFO_LENGTH_MISMATCH);
        }
        if buffer == 0 || !probe_user_write(buffer, need) {
            return Ok(0xC000_0005);
        }
        guest::try_write_bytes(buffer, &alloc::vec![0; need as usize])?;
        let information = state::user_struct::<SystemLogicalProcessorInformationEx>(buffer)?;
        information.relationship.probe_set(relationship as i32)?;
        information.size.probe_set(need as u32)?;
        if relationship == 4 {
            // RelationGroup: o grupo 0 com as CPUs que deram boot.
            let group = &information.group;
            group.maximum_group_count.probe_set(1)?;
            group.active_group_count.probe_set(1)?;
            let info = &group.group_info[0];
            info.maximum_processor_count.probe_set(64)?;
            info.active_processor_count.probe_set(smp::online_cpu_count() as u8)?;
            info.active_processor_mask.probe_set(online_mask())?;
        } else {
            // NUMA_NODE_RELATIONSHIP: um único nó.
            let node = &information.numa_node;
            node.group_count.probe_set(1)?;
            node.group_mask.mask.probe_set(online_mask())?;
        }
        Ok(STATUS_SUCCESS)
    })
}

/// NtTraceEvent: aceito e descartado (sessão ETW sem consumidor).
fn nt_trace_event(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(STATUS_SUCCESS)
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
        for index in 0..count {
            // ULONG_PTR Parameters[index].
            let value = guest::try_read::<u64>(parameters + index * 8)?;
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
        crate::debug_print!("[usermode] HARDERROR: status={:#x} params={}", status as u32, texts.join(" | "));
        if response != 0 {
            guest::try_write::<u32>(response, 2)?; // ResponseAbort
        }
        Ok(STATUS_SUCCESS)
    })
}

/// x64 unificado: a coerência de instruções é garantida pelo hardware.
fn nt_flush_instruction_cache(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
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
    state::guarded(|| match class {
        // ProcessBasicInformation (ou a estendida com Size e Flags), do
        // EPROCESS do handle: o processo consultado pode ser outro.
        0 => {
            let target = match queried_process(handle) {
                Ok(target) => target,
                Err(status) => return Ok(status),
            };
            let extended = length >= ProcessExtendedBasicInformation::SIZE;
            let size = if extended { ProcessExtendedBasicInformation::SIZE } else { ProcessBasicInformation::SIZE };
            if length != ProcessBasicInformation::SIZE && !extended {
                set_returned(size as u32)?;
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, size) {
                return Ok(0xC000_0005);
            }
            guest::try_write_bytes(buffer, &alloc::vec![0; size as usize])?;
            let basic = if extended {
                let information = state::user_struct::<ProcessExtendedBasicInformation>(buffer)?;
                information.size.probe_set(size)?;
                &information.basic_info
            } else {
                state::user_struct::<ProcessBasicInformation>(buffer)?
            };
            // SAFETY: EPROCESS retido pelo handle que o nomeou (ou o corrente).
            let process = unsafe { Eprocess::at(target) };
            // STATUS_PENDING enquanto vivo; o código de saída depois do
            // término.
            basic.exit_status.probe_set(process.exit_status.get())?;
            basic.peb_base_address.probe_set(process.peb.get())?;
            basic.affinity_mask.probe_set(1)?; // o escalonador de usuário roda no BSP
            basic.base_priority.probe_set(process.pcb.base_priority.get() as i32)?;
            basic.unique_process_id.probe_set(process.unique_process_id.get())?;
            basic.inherited_from_unique_process_id.probe_set(process.inherited_from_unique_process_id.get())?;
            set_returned(size as u32)?;
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
        // ProcessCookie (ULONG): o cookie de RtlEncodePointer, por processo e
        // nunca zero.
        36 => {
            if length < 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, 4) {
                return Ok(0xC000_0005);
            }
            // EPROCESS.Cookie, gerado na primeira consulta e trocado uma vez
            // só (InterlockedCompareExchange).
            // SAFETY: o EPROCESS do processo corrente.
            let cell = unsafe { Eprocess::at(process::get_current_process()) }.cookie.atomic();
            let mut cookie = cell.load(Ordering::Acquire);
            if cookie == 0 {
                let tsc = cpu::rdtsc();
                let mixed = (tsc as u32) ^ (((tsc >> 32) as u32) << 16) ^ (state::current_process_id() as u32).wrapping_mul(0x9E37);
                let fresh = if mixed == 0 { 0x5A17_C0DE } else { mixed };
                cookie = match cell.compare_exchange(0, fresh, Ordering::AcqRel, Ordering::Acquire) {
                    Ok(_) => fresh,
                    Err(existing) => existing,
                };
            }
            guest::try_write::<u32>(buffer, cookie)?;
            set_returned(4)?;
            Ok(STATUS_SUCCESS)
        }
        _ => {
            crate::debug_print!("[usermode] NtQueryInformationProcess classe {}", class);
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

/// NtSetInformationProcess: instrumentação (40) e TLS (35).
fn nt_set_information_process(handle: u64, class: u64, buffer: u64, length: u64, _rsp: u64) -> Result<u32, KernelError> {
    let setter = match class as u32 {
        40 => *INSTRUMENTATION_SET.lock(),
        35 => *TLS_SET.lock(),
        _ => None,
    };
    if let Some(setter) = setter {
        return setter(handle, buffer, length);
    }
    // ProcessBreakOnTermination.
    if class as u32 == 29 {
        return crate::ntos::ps::set_process_information::break_on_termination(buffer, length as u32, |access| {
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
/// ObjectAttributes, ShadowDirectoryHandle, Flags): sem diretório sombra
/// nem flags, é o NtCreateDirectoryObject.
fn nt_create_directory_object_ex(out: u64, access: u64, attributes: u64, shadow: u64, rsp: u64) -> Result<u32, KernelError> {
    let flags = state::stack_arg32(rsp, 5);
    if shadow != 0 || flags != 0 {
        crate::debug_print!("[usermode] NtCreateDirectoryObjectEx com sombra {:#x} e flags {:#x} sem suporte", shadow, flags);
        return Ok(0xC000_00BB);
    }
    Ok(namespace_handles::open(out, access as u32, attributes, "Directory", true, true))
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
fn nt_query_security_object(handle: u64, flags: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let Some(entry) = state::get_user_handle(handle) else { return Ok(0xC000_0008) };
    let Some(security) = entry.object.security() else { return Ok(0xC000_00BB) };
    let flags = flags as u32;
    if flags & !0x1F != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let needed = (if flags & 0x17 != 0 { 0x2_0000 } else { 0 }) | (if flags & 8 != 0 { 0x100_0000 } else { 0 });
    if entry.access() & needed != needed {
        return Ok(0xC000_0022);
    }
    let returned = stack_arg(rsp, 5);
    if !probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    let bytes = object_security::encode(&security, flags);
    if guest::try_write::<u32>(returned, bytes.len() as u32).is_err() {
        return Ok(0xC000_0005);
    }
    if (length as u32 as usize) < bytes.len() {
        return Ok(0xC000_0023);
    }
    if !probe_user_write(out, bytes.len() as u64) {
        return Ok(0xC000_0005);
    }
    state::write_user_bytes(out, &bytes)?;
    Ok(0)
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

pub fn init() {
    let handlers: [(&'static str, state::SyscallHandler); 28] = [
        ("NtGetCurrentProcessorNumber", nt_get_current_processor_number),
        ("NtGetCurrentProcessorNumberEx", nt_get_current_processor_number_ex),
        ("NtDisplayString", nt_display_string),
        ("NtTerminateProcess", nt_terminate_process),
        ("NtQueryPerformanceCounter", nt_query_performance_counter),
        ("NtContinue", nt_continue_legacy),
        ("NtContinueEx", nt_continue_ex),
        ("NtWaitForSingleObject", nt_wait_for_single_object),
        ("NtWaitForMultipleObjects", nt_wait_for_multiple_objects),
        ("NtQuerySystemInformation", nt_query_system_information),
        ("NtQuerySystemInformationEx", nt_query_system_information_ex),
        ("NtSerializeBoot", nt_serialize_boot),
        ("NtTraceEvent", nt_trace_event),
        ("NtRaiseHardError", nt_raise_hard_error),
        ("NtFlushInstructionCache", nt_flush_instruction_cache),
        ("NtQueryInformationProcess", nt_query_information_process),
        ("NtSetInformationProcess", nt_set_information_process),
        ("NtRaiseException", nt_raise_exception),
        ("NtOpenSymbolicLinkObject", nt_open_symbolic_link_object),
        ("NtQuerySymbolicLinkObject", nt_query_symbolic_link_object),
        ("NtOpenDirectoryObject", nt_open_directory_object),
        ("NtCreateDirectoryObject", nt_create_directory_object),
        ("NtCreateDirectoryObjectEx", nt_create_directory_object_ex),
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
