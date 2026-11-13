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

use super::state::{self, probe_user_read, probe_user_write, stack_arg, UserHandle, EXIT_CODE_CELL, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_HANDLE, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, TERMINATE_MAGIC, USER_RSP_CELL_ADDR};
use super::threads;
use crate::hal::{cpu, kmalloc, physical, serial};
use crate::ntos::ex::boot_environment_information;
use crate::ntos::ke::{clock, dispatcher, processor_information, smp};
use crate::ntos::mm::{memory_map, pfn};
use crate::ntos::ob::handles::namespace as namespace_handles;
use crate::ntos::ps::{image_information, system_process_information};
use crate::ntos::ps::context::registers as thread_context_registers;
use crate::ntos::se::{code_integrity_information, object_security, secure_boot_information};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Gancho: (userRsp, retLen*) → status.
pub type StackQuery = fn(u64, u64) -> Result<u32, KernelError>;
/// Gancho: (processHandle, buffer, length) → status.
pub type ProcessSetter = fn(u64, u64, u64) -> Result<u32, KernelError>;

static PROCESS_DEBUG_QUERY: SpinLock<Option<StackQuery>> = SpinLock::new(None);
static INSTRUMENTATION_SET: SpinLock<Option<ProcessSetter>> = SpinLock::new(None);
static TLS_SET: SpinLock<Option<ProcessSetter>> = SpinLock::new(None);
/// `exceptions.raise(record, context, firstChance)`.
static RAISE_EXCEPTION: SpinLock<Option<fn(u64, u64, u64) -> Result<u32, KernelError>>> = SpinLock::new(None);
/// `partition.open(out, access, oa, true)`.
static OPEN_PARTITION: SpinLock<Option<fn(u64, u32, u64) -> Result<u32, KernelError>>> = SpinLock::new(None);
/// `os.setUserDebugRegisters(bank)` da HAL de modo usuário.
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
    if number != 0 {
        if !probe_user_write(number, 4) {
            return Ok(0xC000_0005);
        }
        guest::write32(number, 0);
    }
    Ok(0)
}

/// NtDisplayString(PUNICODE_STRING): console de boot e serial.
fn nt_display_string(string: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let length = guest::read16(string) as u64;
    let buffer = guest::read64(string + 8);
    let text = state::read_user_wide_string(buffer, length / 2);
    serial::write(text.as_bytes());
    crate::debug_print!("[usermode] NtDisplayString: {}", text.trim_end_matches(['\r', '\n']));
    Ok(STATUS_SUCCESS)
}

/// NtTerminateProcess(handle, exitCode): a HAL faz o longjmp de volta.
fn nt_terminate_process(_handle: u64, exit_code: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    state::with(|state| state.termination_rsp = guest::read64(USER_RSP_CELL_ADDR));
    crate::debug_print!("[usermode] NtTerminateProcess(exit={:#x})", exit_code as u32);
    physical::write32(EXIT_CODE_CELL, exit_code as u32);
    Ok(TERMINATE_MAGIC)
}

fn nt_query_performance_counter(counter: u64, frequency: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if counter == 0 || !probe_user_write(counter, 8) || (frequency != 0 && !probe_user_write(frequency, 8)) {
        return Ok(0xC000_0005);
    }
    guest::write64(counter, cpu::rdtsc());
    if frequency != 0 {
        guest::write64(frequency, clock::tsc_frequency_hz());
    }
    Ok(STATUS_SUCCESS)
}

/// NtContinue(context, alertable): reescreve o frame do syscall com o
/// CONTEXT; o retorno da HAL retoma o contexto. GPRs são copiados como
/// padrões de bits opacos.
fn nt_continue(context: u64, _alertable: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    if context == 0 || !probe_user_read(context, 0x300) {
        return Ok(0xC000_0005);
    }
    let flags = guest::read32(context + 0x30);
    if flags & 3 != 3 || flags & 0x40 != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // Bits reservados fariam o FXRSTOR falhar no kernel.
    if flags & 8 != 0 && guest::read32(context + 0x118) & !0xFFFF != 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let frame = state::with(|state| state.syscall_stack_top) - 0x78;
    let read64 = |offset: u64| guest::read64(context + offset);
    let canonical = |value: u64| value > 0 && value < 0x8000_0000_0000;
    if !canonical(read64(0xF8)) || !canonical(read64(0x98)) || guest::read16(context + 0x38) != 0x33 || guest::read16(context + 0x42) != 0x2B {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    // Os registradores de depuração são preparados antes de mudar o frame.
    let mut debug_bank = 0u64;
    if flags & 0x10 != 0 {
        debug_bank = guest::alloc_bytes(48);
        if debug_bank == 0 {
            return Ok(0xC000_009A);
        }
        let values = [read64(0x48), read64(0x50), read64(0x58), read64(0x60), 0, read64(0x70)];
        for (index, value) in thread_context_registers::debug_registers(values, 1).into_iter().enumerate() {
            guest::write64(debug_bank + index as u64 * 8, value);
        }
    }
    let copy = |destination: u64, offset: u64| guest::write64(destination, read64(offset));
    copy(frame, 0x78); // rax
    guest::write64(frame + 0x08, read64(0xF8)); // rip
    copy(frame + 0x10, 0x88); // rdx
    copy(frame + 0x18, 0xA8); // rsi
    copy(frame + 0x20, 0xB0); // rdi
    copy(frame + 0x28, 0xB8); // r8
    copy(frame + 0x30, 0xC0); // r9
    copy(frame + 0x38, 0xC8); // r10
    // RF é preservado (um breakpoint de execução retoma a instrução uma
    // vez); IOPL/NT/VM/VIF/VIP continuam filtrados.
    guest::write64(frame + 0x40, ((guest::read32(context + 0x44) & 0x21_0DD5) | 0x200) as u64);
    copy(frame + 0x48, 0x90); // rbx
    copy(frame + 0x50, 0xA0); // rbp
    copy(frame + 0x58, 0xD8); // r12
    copy(frame + 0x60, 0xE0); // r13
    copy(frame + 0x68, 0xE8); // r14
    copy(frame + 0x70, 0xF0); // r15
    // A pilha do usuário mora na célula compartilhada lida pela HAL.
    guest::write64(USER_RSP_CELL_ADDR, read64(0x98));
    copy(0x8_F0A8, 0x80); // RCX independente do RIP
    copy(0x8_F0B0, 0xD0); // R11 independente do RFLAGS
    if flags & 8 != 0 {
        let fx_save = frame - 0x208;
        for index in 0..512 {
            guest::write8(fx_save + index, guest::read8(context + 0x100 + index));
        }
    }
    if debug_bank != 0 {
        if let Some(setter) = *SET_USER_DEBUG_REGISTERS.lock() {
            setter(debug_bank);
        }
        guest::free_bytes(debug_bank);
    }
    guest::write32(0x8_F0A0, 1);
    crate::debug_print!("[usermode] NtContinue -> rip {:#x} rsp {:#x}", read64(0xF8), read64(0x98));
    Ok(guest::read32(context + 0x78))
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
    let mut pointers = Vec::new();
    let mut entries = Vec::new();
    for index in 0..count {
        match waitable(guest::read64(handles + index * 8)) {
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
    for (index, &pointer) in pointers.iter().enumerate() {
        guest::write64(array + index as u64 * 8, pointer);
    }
    let status = dispatcher::wait_for_multiple_objects(count as u32, array, wait_type as u32, timeout, 0, false);
    guest::free_bytes(array);
    Ok(status)
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
        1 | 63 => return Ok(processor_information::query(buffer, length as u32, returned, true, class == 63)),
        5 => return system_process_information::query(buffer, length, returned, true),
        _ => {}
    }
    // ProbeForWrite real: o buffer de saída precisa ser gravável.
    if buffer != 0 && !probe_user_write(buffer, length) {
        return Ok(0xC000_0005);
    }
    let set_returned = |value: u32| {
        if returned != 0 {
            guest::write32(returned, value);
        }
    };
    match class {
        // Basic/EmulationBasic/NativeBasic x64.
        0 | 62 | 114 => {
            if length < 0x40 {
                set_returned(0x40);
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let pages = kmalloc::ram_top() / 0x1000;
            guest::write32(buffer, 0);
            guest::write32(buffer + 0x04, 156_250); // TimerResolution (100 ns)
            guest::write32(buffer + 0x08, 0x1000);
            guest::write32(buffer + 0x0C, pages as u32);
            guest::write32(buffer + 0x10, 0);
            guest::write32(buffer + 0x14, (pages - 1) as u32);
            guest::write32(buffer + 0x18, 0x10000);
            guest::write32(buffer + 0x1C, 0);
            guest::write64(buffer + 0x20, 0x10000);
            guest::write64(buffer + 0x28, memory_map::USER_ADDRESS_LIMIT - 1);
            guest::write64(buffer + 0x30, online_mask());
            guest::write64(buffer + 0x38, smp::online_cpu_count() as u64);
            set_returned(0x40);
            Ok(STATUS_SUCCESS)
        }
        // SystemRangeStartInformation.
        50 => {
            set_returned(8);
            if length < 8 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::write32(buffer, 0);
            guest::write32(buffer + 4, 0xFFFF_8000);
            Ok(STATUS_SUCCESS)
        }
        // SYSTEM_NUMA_INFORMATION com um único nó.
        55 => {
            set_returned(24);
            if length < 24 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::write64(buffer, 0);
            guest::write64(buffer + 8, online_mask());
            guest::write64(buffer + 16, 0);
            Ok(STATUS_SUCCESS)
        }
        _ => {
            crate::debug_print!("[usermode] NtQuerySystemInformation classe {} (nao coberta ainda)", class);
            // Classes de política/recurso ausente: buffer zerado, nunca
            // INVALID_INFO_CLASS (a 24H2 trata como fatal no loader).
            if class == 192 || class == 197 {
                for index in 0..length {
                    guest::write8(buffer + index, 0);
                }
                set_returned(length as u32);
                return Ok(STATUS_SUCCESS);
            }
            // SystemMemoryListInformation.
            if class == 80 {
                let size = 22 * 8u64;
                set_returned(size as u32);
                if length < size {
                    return Ok(STATUS_INFO_LENGTH_MISMATCH);
                }
                for index in 0..size {
                    guest::write8(buffer + index, 0);
                }
                // Sem lista de páginas zeradas nem standby/pagefile.
                guest::write64(buffer + 0x08, pfn::free_count());
                return Ok(STATUS_SUCCESS);
            }
            Ok(STATUS_INVALID_INFO_CLASS)
        }
    }
}

/// NtQuerySystemInformationEx(class, input, inputLength, buffer, length,
/// returnLength*): a topologia de processadores e, no resto, a variante
/// sem entrada.
fn nt_query_system_information_ex(class: u64, input: u64, input_length: u64, buffer: u64, rsp: u64) -> Result<u32, KernelError> {
    let length = state::stack_arg32(rsp, 5) as u64;
    let returned = stack_arg(rsp, 6);
    let class = class as u32;
    crate::debug_print!("[usermode] NtQuerySystemInformationEx classe {}", class);
    if class != 107 {
        return query_system_information(class, buffer, length, returned);
    }
    if input_length as u32 != 4 || input == 0 {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let relationship = guest::read32(input);
    crate::debug_print!("[usermode] topologia: relationship={}", relationship);
    let need = match relationship {
        4 => 80u64,
        1 | 6 => 48,
        _ => return Ok(STATUS_INVALID_INFO_CLASS),
    };
    if returned != 0 {
        guest::write32(returned, need as u32);
    }
    if length < need {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    if buffer == 0 || !probe_user_write(buffer, need) {
        return Ok(0xC000_0005);
    }
    for index in 0..need {
        guest::write8(buffer + index, 0);
    }
    if relationship == 4 {
        // RelationGroup: o grupo 0 com as CPUs que deram boot.
        guest::write32(buffer, 4);
        guest::write32(buffer + 4, need as u32);
        guest::write16(buffer + 8, 1);
        guest::write16(buffer + 10, 1);
        guest::write8(buffer + 32, 64);
        guest::write8(buffer + 33, smp::online_cpu_count() as u8);
        guest::write64(buffer + 72, online_mask());
    } else {
        // NUMA_RELATIONSHIP: um único nó.
        guest::write32(buffer, relationship);
        guest::write32(buffer + 4, need as u32);
        guest::write16(buffer + 30, 1);
        guest::write64(buffer + 32, online_mask());
    }
    Ok(STATUS_SUCCESS)
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
    let mut texts: Vec<String> = Vec::new();
    for index in 0..count {
        let value = guest::read64(parameters + index * 8);
        if unicode_mask & (1 << index) != 0 {
            if !probe_user_read(value, 16) {
                return Ok(0xC000_0005);
            }
            let length = guest::read16(value) as u64;
            let buffer = guest::read64(value + 8);
            if length & 1 != 0 || !probe_user_read(buffer, length) {
                return Ok(0xC000_0005);
            }
            texts.push(state::read_user_wide_string(buffer, (length / 2).min(512)));
        } else {
            texts.push(alloc::format!("{value:#x}"));
        }
    }
    crate::debug_print!("[usermode] HARDERROR: status={:#x} params={}", status as u32, texts.join(" | "));
    if response != 0 {
        guest::write32(response, 2); // ResponseAbort
    }
    Ok(STATUS_SUCCESS)
}

/// x64 unificado: a coerência de instruções é garantida pelo hardware.
fn nt_flush_instruction_cache(_a1: u64, _a2: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    Ok(STATUS_SUCCESS)
}

/// NtQueryInformationProcess(handle, class, buffer, length, retLen*).
fn nt_query_information_process(handle: u64, class: u64, buffer: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let class = class as u32;
    let length = length as u32 as u64;
    let returned = stack_arg(rsp, 5);
    let set_returned = |value: u32| {
        if returned != 0 {
            guest::write32(returned, value);
        }
    };
    match class {
        // ProcessBasicInformation (ou a estendida com Size e Flags).
        0 => {
            if handle as i64 != -1 && handle as u32 != u32::MAX {
                let status = super::handles::current_process(handle, 0x1000);
                if status != 0 {
                    return Ok(status);
                }
            }
            if returned != 0 && !probe_user_write(returned, 4) {
                return Ok(0xC000_0005);
            }
            let extended = length >= 0x40;
            let size = if extended { 0x40 } else { 0x30 };
            if length != 0x30 && !extended {
                set_returned(size as u32);
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            if !probe_user_write(buffer, size) {
                return Ok(0xC000_0005);
            }
            for index in 0..size {
                guest::write8(buffer + index, 0);
            }
            let at = if extended { 8 } else { 0 };
            if extended {
                guest::write64(buffer, 0x40);
            }
            let (peb, process_id) = state::with(|state| (state.current_peb_va, state.current_process_id));
            guest::write32(buffer + at, 0x103); // processo vivo: STATUS_PENDING
            guest::write64(buffer + at + 0x08, peb);
            guest::write64(buffer + at + 0x10, 1); // o escalonador de usuário roda no BSP
            guest::write32(buffer + at + 0x18, 8);
            guest::write64(buffer + at + 0x20, process_id);
            guest::write64(buffer + at + 0x28, 4); // criado pelo processo System
            set_returned(size as u32);
            Ok(STATUS_SUCCESS)
        }
        // ProcessDebugPort, do estado da EPROCESS referenciada.
        7 => match *PROCESS_DEBUG_QUERY.lock() {
            Some(query) => query(rsp, returned),
            None => Ok(STATUS_INVALID_INFO_CLASS),
        },
        // ProcessImageInformation: dados da seção da imagem do alvo.
        37 => query_image_information(rsp),
        // ProcessImageFileName.
        27 => {
            let path = state::with(|state| state.current_image_path.clone());
            let path = if path.is_empty() { String::from("C:\\usertest.exe") } else { path };
            let need = 16 + (path.encode_utf16().count() as u64 + 1) * 2;
            if length < need {
                set_returned(need as u32);
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            state::write_user_wide(buffer + 16, &path);
            state::write_unicode_string(buffer, buffer + 16, &path);
            set_returned(need as u32);
            Ok(STATUS_SUCCESS)
        }
        // ProcessDebugFlags: 1 = sem depurador.
        31 => {
            if length < 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            guest::write32(buffer, 1);
            set_returned(4);
            Ok(STATUS_SUCCESS)
        }
        // ProcessCookie: o cookie de RtlEncodePointer, por processo e
        // nunca zero.
        36 => {
            if length < 4 {
                return Ok(STATUS_INFO_LENGTH_MISMATCH);
            }
            let cookie = state::with(|state| {
                if state.current_process_cookie == 0 {
                    let tsc = cpu::rdtsc();
                    let mixed = (tsc as u32) ^ (((tsc >> 32) as u32) << 16) ^ (state.current_process_id as u32).wrapping_mul(0x9E37);
                    state.current_process_cookie = if mixed == 0 { 0x5A17_C0DE } else { mixed };
                }
                state.current_process_cookie
            });
            guest::write32(buffer, cookie);
            set_returned(4);
            Ok(STATUS_SUCCESS)
        }
        _ => {
            crate::debug_print!("[usermode] NtQueryInformationProcess classe {}", class);
            Ok(STATUS_INVALID_INFO_CLASS)
        }
    }
}

/// `ps/user/image-information.query`: os 64 bits dos argumentos e as
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
    guest::write32(returned, bytes.len() as u32);
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
    let handlers: [(&'static str, state::SyscallHandler); 22] = [
        ("NtGetCurrentProcessorNumber", nt_get_current_processor_number),
        ("NtGetCurrentProcessorNumberEx", nt_get_current_processor_number_ex),
        ("NtDisplayString", nt_display_string),
        ("NtTerminateProcess", nt_terminate_process),
        ("NtQueryPerformanceCounter", nt_query_performance_counter),
        ("NtContinue", nt_continue),
        ("NtWaitForSingleObject", nt_wait_for_single_object),
        ("NtWaitForMultipleObjects", nt_wait_for_multiple_objects),
        ("NtQuerySystemInformation", nt_query_system_information),
        ("NtQuerySystemInformationEx", nt_query_system_information_ex),
        ("NtTraceEvent", nt_trace_event),
        ("NtRaiseHardError", nt_raise_hard_error),
        ("NtFlushInstructionCache", nt_flush_instruction_cache),
        ("NtQueryInformationProcess", nt_query_information_process),
        ("NtSetInformationProcess", nt_set_information_process),
        ("NtRaiseException", nt_raise_exception),
        ("NtOpenSymbolicLinkObject", nt_open_symbolic_link_object),
        ("NtQuerySymbolicLinkObject", nt_query_symbolic_link_object),
        ("NtOpenDirectoryObject", nt_open_directory_object),
        ("NtQuerySecurityObject", nt_query_security_object),
        ("NtOpenPartition", nt_open_partition),
        ("NtCreatePartition", nt_create_partition),
    ];
    for (name, handler) in handlers {
        state::register_handler(name, handler);
    }
}
