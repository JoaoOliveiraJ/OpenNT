//! Diagnóstico de falhas de processos de usuário na serial.
//!
//! Só diagnóstico: nada aqui muda o despacho de exceções, os serviços nem o
//! término. Uma falha de processo imprime um bloco curto `[crash]`, a partir
//! de um destes pontos:
//! - a exceção de segunda chance do NtRaiseException ([`second_chance`]);
//! - a exceção que não pôde ser entregue ao KiUserExceptionDispatcher
//!   ([`undeliverable`]), que termina o processo;
//! - o NtRaiseHardError de uma exceção ([`hard_error`]): o
//!   STATUS_UNHANDLED_EXCEPTION do UnhandledExceptionFilter da kernelbase,
//!   com código, endereço e ExceptionInformation[0..2] nos parâmetros, ou o
//!   próprio código da exceção;
//! - o NtSetSystemInformation(SystemWin32WerStartCallout = 177) do relatório
//!   de falha da kernel32 ([`set_system_information`]);
//! - o fim de um processo com status de exceção ([`process_exit`], do
//!   `create::finish_exit`).
//!
//! O bloco traz o processo, pid:tid, o código e o endereço da exceção, o
//! módulo + deslocamento (pela lista InLoadOrder do PEB_LDR_DATA ou, fora
//! dela, pelo VAD do processo e as imagens do System), o export mais próximo
//! do módulo e os primeiros quadros da pilha de usuário, desenrolados pela
//! .pdata (RUNTIME_FUNCTION/UNWIND_INFO) de cada módulo; sem RUNTIME_FUNCTION
//! o quadro é de função folha (o retorno no topo da pilha). Cada exceção
//! entregue fica anotada na thread ([`noted`]: código, endereço, parâmetros,
//! registradores inteiros e o frame do despachante), então o bloco de um
//! ponto posterior (o filtro de exceções, o fim do processo) desenrola a
//! pilha da própria falha. Sem a anotação, a pilha sai da chamada de sistema
//! e os quadros do despacho em modo usuário (até o RtlRaiseException ou o
//! KiUserExceptionDispatcher da ntdll) são omitidos. Um processo imprime um
//! bloco por código: os pontos seguintes da mesma falha não repetem.
//!
//! Toda leitura de memória de usuário passa por [`readable`]: páginas
//! presentes de usuário (a sonda do ProbeForRead) do processo corrente ou de
//! uma faixa de sistema (o verificador de posse), antes da leitura sondada.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::{offset_of, size_of};
use core::sync::atomic::Ordering;

use super::memory::{self, Space};
use super::threads::{self, UserThread};
use super::{process_state, state};
use crate::hal::amd64::usermode;
use crate::ntos::inc::types::{
    Context, ExceptionRecord, Field, ImageDataDirectory, ImageDosHeader, ImageExportDirectory, ImageNtHeaders64, ImageRuntimeFunctionEntry, LdrDataTableEntry, NtStruct, Peb, PebLdrData, UnicodeString, UnwindInfo,
};
use crate::ntos::mm::guest_memory::{self as guest, GuestScalar};
use crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
use crate::ntos::ps::{process, process_accessors};

/// SystemWin32WerStartCallout, a classe do NtSetSystemInformation que o
/// relatório de falha da kernel32 chama.
const SYSTEM_WIN32_WER_START_CALLOUT: u32 = 177;
/// STATUS_UNHANDLED_EXCEPTION e o HARDERROR_OVERRIDE_ERRORMODE do status.
const STATUS_UNHANDLED_EXCEPTION: u32 = 0xC000_0144;
const HARDERROR_OVERRIDE_ERRORMODE: u32 = 0x1000_0000;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_IN_PAGE_ERROR: u32 = 0xC000_0006;
const STATUS_STACK_BUFFER_OVERRUN: u32 = 0xC000_0409;
/// O vetor do `__fastfail` (int 0x29).
const FAST_FAIL_VECTOR: u32 = 0x29;
/// Códigos de exceção (com os de cliente, 0xE...): um processo que termina
/// com um deles terminou por uma exceção sem tratamento.
const EXCEPTION_CODES: [u32; 32] = [
    0x4000_0015, // STATUS_FATAL_APP_EXIT
    0x8000_0001, // STATUS_GUARD_PAGE_VIOLATION
    0x8000_0002, // STATUS_DATATYPE_MISALIGNMENT
    0x8000_0003, // STATUS_BREAKPOINT
    0x8000_0004, // STATUS_SINGLE_STEP
    STATUS_ACCESS_VIOLATION,
    STATUS_IN_PAGE_ERROR,
    0xC000_001D, // STATUS_ILLEGAL_INSTRUCTION
    0xC000_0025, // STATUS_NONCONTINUABLE_EXCEPTION
    0xC000_0026, // STATUS_INVALID_DISPOSITION
    0xC000_008C, // STATUS_ARRAY_BOUNDS_EXCEEDED
    0xC000_008D, // STATUS_FLOAT_DENORMAL_OPERAND
    0xC000_008E, // STATUS_FLOAT_DIVIDE_BY_ZERO
    0xC000_008F, // STATUS_FLOAT_INEXACT_RESULT
    0xC000_0090, // STATUS_FLOAT_INVALID_OPERATION
    0xC000_0091, // STATUS_FLOAT_OVERFLOW
    0xC000_0092, // STATUS_FLOAT_STACK_CHECK
    0xC000_0093, // STATUS_FLOAT_UNDERFLOW
    0xC000_0094, // STATUS_INTEGER_DIVIDE_BY_ZERO
    0xC000_0095, // STATUS_INTEGER_OVERFLOW
    0xC000_0096, // STATUS_PRIVILEGED_INSTRUCTION
    0xC000_00FD, // STATUS_STACK_OVERFLOW
    STATUS_UNHANDLED_EXCEPTION,
    0xC000_0194, // STATUS_POSSIBLE_DEADLOCK
    0xC000_0374, // STATUS_HEAP_CORRUPTION
    STATUS_STACK_BUFFER_OVERRUN,
    0xC000_041D, // STATUS_FATAL_USER_CALLBACK_EXCEPTION
    0xC000_0417, // STATUS_INVALID_CRUNTIME_PARAMETER
    0xC000_0420, // STATUS_ASSERTION_FAILURE
    0xC000_0602, // STATUS_FAIL_FAST_EXCEPTION
    0xC06D_007E, // VcppException(ERROR_SEVERITY_ERROR, ERROR_MOD_NOT_FOUND)
    0xC06D_007F, // VcppException(ERROR_SEVERITY_ERROR, ERROR_PROC_NOT_FOUND)
];

/// Rsp no vetor de inteiros (a ordem dos números de registrador do x64).
const RSP: usize = 4;
/// Quadros desenrolados e mostrados.
const WALK_FRAMES: usize = 24;
const SHOWN_FRAMES: usize = 10;
const FRAMES_PER_LINE: usize = 5;
/// Distância máxima ao export mais próximo: no endereço da falha e nos quadros.
const FAULT_SYMBOL_RANGE: u64 = 0x1_0000;
const FRAME_SYMBOL_RANGE: u64 = 0x1000;
/// Limites das leituras do loader e dos exports.
const MAX_MODULES: usize = 512;
const MAX_EXPORTS: u32 = 0x4000;
const MAX_NAME: usize = 64;
/// IMAGE_DIRECTORY_ENTRY_EXPORT e IMAGE_DIRECTORY_ENTRY_EXCEPTION.
const EXPORT_DIRECTORY: usize = 0;
const EXCEPTION_DIRECTORY: usize = 3;
/// UNW_FLAG_CHAININFO e os códigos UWOP_* do UNWIND_CODE.
const UNW_FLAG_CHAININFO: u8 = 4;
const UWOP_PUSH_NONVOL: u16 = 0;
const UWOP_ALLOC_LARGE: u16 = 1;
const UWOP_ALLOC_SMALL: u16 = 2;
const UWOP_SET_FPREG: u16 = 3;
const UWOP_SAVE_NONVOL: u16 = 4;
const UWOP_SAVE_NONVOL_FAR: u16 = 5;
const UWOP_EPILOG: u16 = 6;
const UWOP_SPARE_CODE: u16 = 7;
const UWOP_PUSH_MACHFRAME: u16 = 10;
/// Entradas encadeadas e indiretas seguidas por quadro.
const MAX_CHAIN: usize = 8;

/// O status é um código de exceção.
fn is_exception_code(status: u32) -> bool {
    status & 0xF000_0000 == 0xE000_0000 || EXCEPTION_CODES.contains(&status)
}

// ---- leituras de memória de usuário -------------------------------------------

/// A faixa pode ser lida sem falta nem violação de posse.
fn readable(address: u64, length: u64) -> bool {
    if length == 0 || !state::probe_user_read(address, length) {
        return false;
    }
    let mut page = address & !0xFFF;
    let last = (address + length - 1) & !0xFFF;
    while page <= last {
        if memory::check_user_access(page).is_err() {
            return false;
        }
        page += 0x1000;
    }
    true
}

fn read<T: GuestScalar>(address: u64) -> Option<T> {
    if !readable(address, T::SIZE) {
        return None;
    }
    guest::try_read::<T>(address).ok()
}

fn read_bytes(address: u64, length: usize) -> Option<Vec<u8>> {
    if !readable(address, length as u64) {
        return None;
    }
    guest::try_read_bytes(address, length).ok()
}

/// A estrutura de usuário em `address`, depois de [`readable`] na faixa inteira.
fn read_struct<T: NtStruct>(address: u64) -> Option<&'static T> {
    if !readable(address, T::SIZE) {
        return None;
    }
    T::try_at(address).ok()
}

fn read_u32s(address: u64, count: u32) -> Option<Vec<u32>> {
    if count == 0 {
        return Some(Vec::new());
    }
    Some(read_bytes(address, count as usize * 4)?.chunks_exact(4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).collect())
}

fn read_u16s(address: u64, count: usize) -> Option<Vec<u16>> {
    if count == 0 {
        return Some(Vec::new());
    }
    Some(read_bytes(address, count * 2)?.chunks_exact(2).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]])).collect())
}

/// Um nome ASCII terminado em NUL (no máximo [`MAX_NAME`] caracteres).
fn read_ascii(address: u64) -> Option<String> {
    let mut text = String::new();
    let mut cursor = address;
    while text.len() < MAX_NAME {
        let chunk = ((0x1000 - (cursor & 0xFFF)) as usize).min(MAX_NAME - text.len());
        for byte in read_bytes(cursor, chunk)? {
            if byte == 0 {
                return Some(text);
            }
            if !byte.is_ascii_graphic() {
                return None;
            }
            text.push(byte as char);
        }
        cursor += chunk as u64;
    }
    Some(text)
}

/// Uma UNICODE_STRING de usuário (no máximo [`MAX_NAME`] caracteres).
fn read_unicode(string: &UnicodeString) -> Option<String> {
    let length = string.length.probe_get().ok()? as u64;
    let buffer = string.buffer.probe_get().ok()?;
    let count = (length / 2).min(MAX_NAME as u64);
    if count == 0 || !readable(buffer, count * 2) {
        return None;
    }
    state::try_read_user_wide_string(buffer, count).ok()
}

/// O último componente de um caminho nativo ou DOS.
fn short_name(path: &str) -> String {
    String::from(path.rsplit(['\\', '/']).next().unwrap_or(path))
}

// ---- falha anotada --------------------------------------------------------------

/// Rax..R15 na ordem dos números de registrador do x64, e o Rip.
#[derive(Clone, Copy)]
pub struct Registers {
    integer: [u64; 16],
    rip: u64,
}

impl Registers {
    fn from_fields(context: &Context, get: impl Fn(&Field<u64>) -> Option<u64>) -> Option<Self> {
        let fields = [
            &context.rax, &context.rcx, &context.rdx, &context.rbx, &context.rsp, &context.rbp, &context.rsi, &context.rdi, &context.r8, &context.r9, &context.r10, &context.r11, &context.r12, &context.r13, &context.r14, &context.r15,
        ];
        let mut integer = [0u64; 16];
        for (slot, field) in integer.iter_mut().zip(fields) {
            *slot = get(field)?;
        }
        Some(Self { integer, rip: get(&context.rip)? })
    }

    /// Do CONTEXT salvo de uma thread (memória do kernel).
    fn of_context(context: &Context) -> Self {
        Self::from_fields(context, |field| Some(field.get())).unwrap_or(Self { integer: [0; 16], rip: 0 })
    }

    /// De um CONTEXT de usuário (sondado).
    fn of_user_context(pointer: u64) -> Option<Self> {
        Self::from_fields(read_struct::<Context>(pointer)?, |field| field.probe_get().ok())
    }
}

/// Código, endereço e parâmetros de uma exceção; `None` = não conhecido.
#[derive(Clone, Copy, Default)]
struct Exception {
    code: Option<u32>,
    address: Option<u64>,
    parameters: u32,
    information: [u64; 2],
    /// O código do `__fastfail` (int 0x29), que o registro não leva.
    fast_fail: Option<u32>,
}

impl Exception {
    /// De um EXCEPTION_RECORD capturado.
    fn of_record(record: &[u8]) -> Self {
        let u32_at = |offset: usize| record.get(offset..offset + 4).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
        let u64_at = |offset: usize| record.get(offset..offset + 8).map_or(0, |bytes| u64::from_le_bytes(bytes.try_into().unwrap_or([0; 8])));
        let information = offset_of!(ExceptionRecord, exception_information);
        Self {
            code: Some(u32_at(offset_of!(ExceptionRecord, exception_code))),
            address: Some(u64_at(offset_of!(ExceptionRecord, exception_address))),
            parameters: u32_at(offset_of!(ExceptionRecord, number_parameters)),
            information: [u64_at(information), u64_at(information + 8)],
            fast_fail: None,
        }
    }
}

/// Uma exceção entregue (ou que ia ser) ao KiUserExceptionDispatcher, com
/// os registradores do CONTEXT dela e o frame do despachante na pilha.
#[derive(Clone, Copy)]
pub struct Fault {
    exception: Exception,
    registers: Registers,
    /// O CONTEXT escrito na pilha de usuário (0 antes da entrega).
    frame: u64,
}

impl Fault {
    /// A exceção de `record` no CONTEXT salvo da thread (`context`, memória
    /// do kernel; 0 sem CONTEXT), antes da entrega.
    pub fn capture(record: &[u8], context: u64) -> Self {
        let mut exception = Exception::of_record(record);
        // O `__fastfail` chega pelo int 0x29 com o código em RCX, que a HAL
        // guarda no bloco da CPU desta saída.
        let block = usermode::block();
        if exception.code == Some(STATUS_STACK_BUFFER_OVERRUN) && block.fault_vector.get() == FAST_FAIL_VECTOR {
            exception.fast_fail = Some(block.fault_rcx.get() as u32);
        }
        // SAFETY: o CONTEXT salvo da thread, alocado pelo runtime.
        let registers = if context != 0 { Registers::of_context(unsafe { Context::at(context) }) } else { Registers { integer: [0; 16], rip: 0 } };
        Self { exception, registers, frame: 0 }
    }

    /// O frame do despachante ainda está na pilha abaixo do quadro corrente
    /// (`rsp`) com o mesmo CONTEXT: a exceção é a que está sendo tratada.
    fn live(&self, rsp: u64) -> bool {
        self.frame > rsp
            && read::<u64>(self.frame + offset_of!(Context, rip) as u64) == Some(self.registers.rip)
            && read::<u64>(self.frame + offset_of!(Context, rsp) as u64) == Some(self.registers.integer[RSP])
    }
}

/// A exceção entregue ao KiUserExceptionDispatcher fica anotada na thread,
/// com o frame do CONTEXT na pilha de usuário.
pub fn noted(thread: &UserThread, mut fault: Fault, frame: u64) {
    fault.frame = frame;
    thread.with(|thread| thread.last_exception = Some(fault));
}

// ---- pontos de diagnóstico ------------------------------------------------------

#[derive(Clone, Copy)]
enum Trigger {
    SecondChance,
    Undeliverable(u32),
    HardError(u32),
    WerStart,
    Exit(u32),
}

impl Trigger {
    fn describe(self) -> String {
        match self {
            Trigger::SecondChance => String::from("excecao sem tratamento (NtRaiseException de segunda chance)"),
            Trigger::Undeliverable(status) => format!("excecao nao entregue ao KiUserExceptionDispatcher ({status:#x}), o processo termina"),
            Trigger::HardError(status) => format!("NtRaiseHardError {status:#x}"),
            Trigger::WerStart => String::from("relatorio de falha (NtSetSystemInformation 177, WerStartCallout)"),
            Trigger::Exit(status) => format!("processo termina com {status:#x}"),
        }
    }
}

struct Crash {
    trigger: Trigger,
    process: u64,
    thread_id: u64,
    /// O código que identifica a falha no processo (o já relatado não repete).
    key: Option<u32>,
    exception: Exception,
    /// Onde a pilha começa e se é o contexto da própria falha.
    start: Option<(Registers, bool)>,
}

/// A exceção que não pôde ser entregue: o processo termina com `status`.
pub fn undeliverable(thread: &UserThread, fault: &Fault, status: u32) {
    let process = thread.with(|thread| thread.process_pointer);
    report(Crash {
        trigger: Trigger::Undeliverable(status),
        process: if process != 0 { process } else { process::get_current_process() },
        thread_id: thread.thread_id,
        key: Some(status),
        exception: fault.exception,
        start: Some((fault.registers, true)),
    });
}

/// NtRaiseException de segunda chance: o registro capturado e o CONTEXT de
/// usuário (já validado) do chamador.
pub fn second_chance(record: &[u8], context: u64) {
    let exception = Exception::of_record(record);
    report(Crash {
        trigger: Trigger::SecondChance,
        process: process::get_current_process(),
        thread_id: process::get_current_thread_id(),
        key: exception.code,
        exception,
        start: Registers::of_user_context(context).map(|registers| (registers, true)),
    });
}

/// NtRaiseHardError com os parâmetros capturados (no máximo quatro): o
/// STATUS_UNHANDLED_EXCEPTION traz código, endereço e
/// ExceptionInformation[0..2]; um código de exceção vem sozinho. Os outros
/// erros graves não são falhas de processo.
pub fn hard_error(status: u32, parameters: &[u64]) {
    let code = status & !HARDERROR_OVERRIDE_ERRORMODE;
    let exception = if code == STATUS_UNHANDLED_EXCEPTION && parameters.len() >= 2 {
        let information = |index: usize| parameters.get(index).copied().unwrap_or(0);
        Exception { code: Some(parameters[0] as u32), address: Some(parameters[1]), parameters: parameters.len() as u32 - 2, information: [information(2), information(3)], fast_fail: None }
    } else if is_exception_code(code) {
        Exception { code: Some(code), ..Exception::default() }
    } else {
        return;
    };
    from_service(Trigger::HardError(status), exception);
}

/// NtSetSystemInformation de modo usuário: a classe
/// SystemWin32WerStartCallout é o começo do relatório de falha.
pub fn set_system_information(class: u32) {
    if class == SYSTEM_WIN32_WER_START_CALLOUT {
        from_service(Trigger::WerStart, Exception::default());
    }
}

/// Um ponto dentro de um serviço da thread que falhou: a falha anotada na
/// thread, se é a mesma exceção (mesmo código e endereço, ou, sem eles, o
/// frame do despachante ainda vivo na pilha); senão a pilha da chamada.
fn from_service(trigger: Trigger, exception: Exception) {
    let thread = threads::current();
    let syscall = thread.as_ref().and_then(|thread| thread.with(|thread| (thread.context != 0).then(|| {
        // SAFETY: o CONTEXT salvo da thread corrente, com os registradores da syscall.
        Registers::of_context(unsafe { Context::at(thread.context) })
    })));
    let noted = thread.as_ref().and_then(|thread| thread.with(|thread| thread.last_exception));
    let rsp = syscall.map_or(0, |registers| registers.integer[RSP]);
    let matched = noted.filter(|fault| match (exception.code, exception.address) {
        (Some(code), Some(address)) => fault.exception.code == Some(code) && fault.exception.address == Some(address),
        (Some(code), None) => fault.exception.code == Some(code) && fault.live(rsp),
        _ => fault.live(rsp),
    });
    let (exception, start) = match matched {
        Some(fault) => {
            let mut merged = fault.exception;
            if exception.parameters != 0 && merged.parameters == 0 {
                (merged.parameters, merged.information) = (exception.parameters, exception.information);
            }
            (merged, Some((fault.registers, true)))
        }
        None => (exception, syscall.map(|registers| (registers, false))),
    };
    report(Crash { trigger, process: process::get_current_process(), thread_id: process::get_current_thread_id(), key: exception.code, exception, start });
}

/// O fim de um processo que rodou, anexado a ele (`create::finish_exit`).
/// Devolve se o status é de exceção (o bloco foi impresso agora ou antes);
/// senão quem chama segue com o post-mortem comum.
pub fn process_exit(process: u64, status: u32) -> bool {
    let threads = threads::of_process(process);
    let noted = threads.iter().find_map(|thread| thread.with(|inner| inner.last_exception.filter(|fault| fault.exception.code == Some(status))).map(|fault| (thread.thread_id, fault)));
    if noted.is_none() && !is_exception_code(status) && reported(process) != Some(status) {
        return false;
    }
    let (thread_id, exception, start) = match noted {
        Some((thread_id, fault)) => (thread_id, fault.exception, Some((fault.registers, true))),
        None => {
            // A thread que encerrou o processo, com o CONTEXT da última syscall.
            let terminating = threads.iter().find(|thread| thread.with(|thread| thread.termination_rsp != 0)).or(threads.first());
            let registers = terminating.and_then(|thread| thread.with(|thread| (thread.context != 0).then(|| {
                // SAFETY: o CONTEXT da thread, ainda não liberado (o término vem depois).
                Registers::of_context(unsafe { Context::at(thread.context) })
            })));
            (terminating.map_or(0, |thread| thread.thread_id), Exception { code: Some(status), ..Exception::default() }, registers.map(|registers| (registers, false)))
        }
    };
    report(Crash { trigger: Trigger::Exit(status), process, thread_id, key: Some(status), exception, start });
    true
}

// ---- um bloco por falha ---------------------------------------------------------

/// `ProcessState.crash_reported`: 0 sem bloco; senão este bit e o código.
const REPORTED: u64 = 1 << 32;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Claim {
    Block,
    /// O código que faltava no bloco anterior.
    Line,
    Skip,
}

/// O código do bloco já impresso para o processo (0 = sem código).
fn reported(process: u64) -> Option<u32> {
    let value = process_state::get(process)?.crash_reported.load(Ordering::Acquire);
    (value & REPORTED != 0).then_some(value as u32)
}

fn claim(process: u64, key: Option<u32>) -> Claim {
    let Some(state) = process_state::get(process) else { return Claim::Block };
    let current = key.map_or(REPORTED, |code| REPORTED | code as u64);
    let previous = state.crash_reported.load(Ordering::Acquire);
    let claim = match (previous & REPORTED != 0, previous as u32, key) {
        (false, _, _) => Claim::Block,
        (true, _, None) => Claim::Skip,
        (true, before, Some(code)) if before == code => Claim::Skip,
        (true, 0, Some(_)) => Claim::Line,
        (true, _, Some(_)) => Claim::Block,
    };
    if claim != Claim::Skip {
        state.crash_reported.store(current, Ordering::Release);
    }
    claim
}

/// Um processo de usuário que entrou no despachante (as simulações dos
/// autotestes rodam no System e não imprimem).
fn user_process(process: u64) -> bool {
    process != 0 && process != process::get_system_process() && process_state::get(process).is_some_and(|state| state.started.load(Ordering::Acquire))
}

fn report(crash: Crash) {
    if !user_process(crash.process) {
        return;
    }
    let claim = claim(crash.process, crash.key);
    if claim == Claim::Skip {
        return;
    }
    let name = process::with_record(crash.process, |record| record.name.clone()).filter(|name| !name.is_empty()).map_or_else(|| String::from("?"), |name| short_name(&name));
    let process_id = process_accessors::id(crash.process);
    let mut modules = Modules::of(crash.process);
    let header = format!("[crash] {name} {process_id}:{}: {}", crash.thread_id, crash.trigger.describe());
    let fault = describe_exception(&mut modules, &crash.exception);
    if claim == Claim::Line {
        crate::debug_print!("{header}: {fault}");
        return;
    }
    crate::debug_print!("{header}");
    crate::debug_print!("[crash]   {fault}");
    let Some((registers, from_fault)) = crash.start else { return };
    let frames = walk(&mut modules, registers);
    let skipped = if from_fault { 0 } else { dispatch_frames(&mut modules, &frames) };
    let shown: Vec<String> = frames.iter().skip(skipped).take(SHOWN_FRAMES).map(|&address| modules.describe(address, FRAME_SYMBOL_RANGE)).collect();
    let origin = if from_fault { "pilha da falha" } else { "pilha da chamada" };
    let omitted = if skipped != 0 { format!(", {skipped} quadros do despacho omitidos") } else { String::new() };
    if shown.is_empty() {
        crate::debug_print!("[crash]   {origin} (rsp {:#x}): ilegivel", registers.integer[RSP]);
    }
    for (index, line) in shown.chunks(FRAMES_PER_LINE).enumerate() {
        if index == 0 {
            crate::debug_print!("[crash]   {origin} (rsp {:#x}{omitted}): {}", registers.integer[RSP], line.join(" | "));
        } else {
            crate::debug_print!("[crash]     {}", line.join(" | "));
        }
    }
}

fn describe_exception(modules: &mut Modules, exception: &Exception) -> String {
    let Some(code) = exception.code else { return String::from("excecao nao vista pelo kernel (despacho em modo usuario)") };
    let mut text = format!("excecao {code:#x}");
    if let Some(address) = exception.address {
        text.push_str(&format!(" em {address:#x}"));
        if modules.index(address).is_some() {
            text.push_str(&format!(" = {}", modules.describe(address, FAULT_SYMBOL_RANGE)));
        }
    }
    if let Some(fast_fail) = exception.fast_fail {
        text.push_str(&format!(", __fastfail {fast_fail}"));
    } else if matches!(code, STATUS_ACCESS_VIOLATION | STATUS_IN_PAGE_ERROR) && exception.parameters >= 2 {
        let access = match exception.information[0] {
            0 => "leitura de",
            1 => "escrita em",
            8 => "execucao em",
            _ => "acesso a",
        };
        text.push_str(&format!(", {access} {:#x}", exception.information[1]));
    } else if code == STATUS_STACK_BUFFER_OVERRUN && exception.parameters >= 1 {
        text.push_str(&format!(", codigo {}", exception.information[0]));
    }
    text
}

// ---- módulos e exports ----------------------------------------------------------

struct Exports {
    /// O diretório de exports (RVAs): um endereço dentro dele é um forwarder.
    start: u32,
    end: u32,
    ordinal_base: u32,
    functions: Vec<u32>,
    names: Vec<u32>,
    ordinals: Vec<u16>,
}

impl Exports {
    fn load(base: u64, size: u64) -> Option<Self> {
        let header = nt_headers(base)?;
        let (rva, length) = data_directory(header, EXPORT_DIRECTORY)?;
        if rva == 0 || rva as u64 + ImageExportDirectory::SIZE > size {
            return None;
        }
        let directory = read_struct::<ImageExportDirectory>(base + rva as u64)?;
        let functions = directory.number_of_functions.probe_get().ok()?.min(MAX_EXPORTS);
        let names = directory.number_of_names.probe_get().ok()?.min(MAX_EXPORTS);
        Some(Self {
            start: rva,
            end: rva.saturating_add(length),
            ordinal_base: directory.base.probe_get().ok()?,
            functions: read_u32s(base + directory.address_of_functions.probe_get().ok()? as u64, functions)?,
            names: read_u32s(base + directory.address_of_names.probe_get().ok()? as u64, names)?,
            ordinals: read_u16s(base + directory.address_of_name_ordinals.probe_get().ok()? as u64, names as usize)?,
        })
    }

    /// O export de maior RVA até `rva` (nome, ou #ordinal) e a distância.
    fn nearest(&self, base: u64, rva: u64) -> Option<(String, u64)> {
        let (index, start) = self.functions.iter().enumerate().filter(|&(_, &function)| function != 0 && function as u64 <= rva && !(self.start..self.end).contains(&function)).max_by_key(|&(_, &function)| function)?;
        let name = match self.ordinals.iter().position(|&ordinal| ordinal as usize == index) {
            Some(slot) => read_ascii(base + *self.names.get(slot)? as u64)?,
            None => format!("#{}", self.ordinal_base as u64 + index as u64),
        };
        Some((name, rva - *start as u64))
    }
}

struct Module {
    base: u64,
    size: u64,
    name: String,
    /// Carregados na primeira consulta (`Some(None)`: sem exports legíveis).
    exports: Option<Option<Exports>>,
}

struct Modules {
    process: u64,
    list: Vec<Module>,
}

impl Modules {
    /// A lista InLoadOrder do PEB_LDR_DATA do processo (o corrente, anexado).
    fn of(process: u64) -> Self {
        let mut list = Vec::new();
        let ldr = read_struct::<Peb>(process_accessors::peb(process)).and_then(|peb| peb.ldr.probe_get().ok());
        if let Some(data) = ldr.and_then(read_struct::<PebLdrData>) {
            let head = data.in_load_order_module_list.address();
            let mut link = data.in_load_order_module_list.flink.probe_get().unwrap_or(0);
            while link != 0 && link != head && list.len() < MAX_MODULES {
                let Some(entry) = read_struct::<LdrDataTableEntry>(link - offset_of!(LdrDataTableEntry, in_load_order_links) as u64) else { break };
                let (Ok(base), Ok(size), Ok(next)) = (entry.dll_base.probe_get(), entry.size_of_image.probe_get(), entry.in_load_order_links.flink.probe_get()) else { break };
                if base != 0 && size != 0 {
                    list.push(Module { base, size: size as u64, name: read_unicode(&entry.base_dll_name).unwrap_or_else(|| String::from("?")), exports: None });
                }
                link = next;
            }
        }
        Self { process, list }
    }

    /// O módulo que contém `address`: o do loader ou, fora da lista, uma
    /// região nomeada do VAD do processo ou das imagens do System.
    fn index(&mut self, address: u64) -> Option<usize> {
        if let Some(index) = self.list.iter().position(|module| address >= module.base && address - module.base < module.size) {
            return Some(index);
        }
        let region = Space::of(self.process).find(address).filter(|region| region.name().is_some()).or_else(|| Space::system().find(address).filter(|region| region.name().is_some()))?;
        self.list.push(Module { base: region.base(), size: region.size(), name: short_name(&region.name().unwrap_or_default()), exports: None });
        Some(self.list.len() - 1)
    }

    /// O export mais próximo de `address` no módulo de índice `index`.
    fn symbol(&mut self, index: usize, address: u64) -> Option<(String, u64)> {
        let module = &mut self.list[index];
        let exports = module.exports.get_or_insert_with(|| Exports::load(module.base, module.size));
        exports.as_ref()?.nearest(module.base, address - module.base)
    }

    /// `módulo+deslocamento (Export+distância)`, ou o endereço cru.
    fn describe(&mut self, address: u64, range: u64) -> String {
        let Some(index) = self.index(address) else { return format!("{address:#x}") };
        let mut text = format!("{}+{:#x}", self.list[index].name, address - self.list[index].base);
        if let Some((name, distance)) = self.symbol(index, address).filter(|&(_, distance)| distance <= range) {
            text.push_str(&format!(" ({name}+{distance:#x})"));
        }
        text
    }
}

/// Os cabeçalhos NT de uma imagem mapeada (MZ e PE conferidos).
fn nt_headers(base: u64) -> Option<u64> {
    if read::<u16>(base + offset_of!(ImageDosHeader, e_magic) as u64)? != 0x5A4D {
        return None;
    }
    let header = base + read::<u32>(base + offset_of!(ImageDosHeader, e_lfanew) as u64)? as u64;
    (read::<u32>(header + offset_of!(ImageNtHeaders64, signature) as u64)? == 0x4550).then_some(header)
}

/// Um IMAGE_DATA_DIRECTORY (RVA, tamanho) dos cabeçalhos NT.
fn data_directory(header: u64, index: usize) -> Option<(u32, u32)> {
    if read::<u32>(header + offset_of!(ImageNtHeaders64, optional_header.number_of_rva_and_sizes) as u64)? as usize <= index {
        return None;
    }
    let entry = header + (offset_of!(ImageNtHeaders64, optional_header.data_directory) + index * size_of::<ImageDataDirectory>()) as u64;
    Some((read::<u32>(entry + offset_of!(ImageDataDirectory, virtual_address) as u64)?, read::<u32>(entry + offset_of!(ImageDataDirectory, size) as u64)?))
}

// ---- desenrolamento da pilha de usuário -----------------------------------------

/// Uma RUNTIME_FUNCTION da imagem em `base` (RVAs).
#[derive(Clone, Copy)]
struct FunctionEntry {
    begin: u32,
    end: u32,
    unwind: u32,
}

fn read_function(address: u64) -> Option<FunctionEntry> {
    let entry = read_struct::<ImageRuntimeFunctionEntry>(address)?;
    Some(FunctionEntry { begin: entry.begin_address.probe_get().ok()?, end: entry.end_address.probe_get().ok()?, unwind: entry.unwind_info_address.probe_get().ok()? })
}

/// Busca binária na .pdata da imagem, seguindo as entradas indiretas.
fn function_entry(base: u64, size: u64, pc: u64) -> Option<FunctionEntry> {
    let (table, length) = data_directory(nt_headers(base)?, EXCEPTION_DIRECTORY)?;
    let entry_size = ImageRuntimeFunctionEntry::SIZE;
    if table == 0 || length as u64 % entry_size != 0 || table as u64 + length as u64 > size {
        return None;
    }
    let relative = pc - base;
    let (mut lower, mut upper) = (0i64, (length as u64 / entry_size) as i64 - 1);
    while lower <= upper {
        let index = (lower + upper) / 2;
        let mut function = read_function(base + table as u64 + index as u64 * entry_size)?;
        if relative < function.begin as u64 {
            upper = index - 1;
        } else if relative >= function.end as u64 {
            lower = index + 1;
        } else {
            for _ in 0..MAX_CHAIN {
                if function.unwind & 1 == 0 {
                    return Some(function);
                }
                function = read_function(base + (function.unwind - 1) as u64)?;
            }
            return None;
        }
    }
    None
}

/// Um UNWIND_INFO lido da imagem.
struct UnwindData {
    flags: u8,
    prolog: u8,
    frame: usize,
    frame_offset: u64,
    codes: Vec<u16>,
    /// Depois dos códigos (em número par): a RUNTIME_FUNCTION encadeada.
    tail: u64,
}

/// Slots de 16 bits de cada código (o RtlpUnwindOpSlotTable).
fn slot_count(operation: u16, information: u16) -> Option<usize> {
    Some(match operation {
        UWOP_PUSH_NONVOL | UWOP_ALLOC_SMALL | UWOP_SET_FPREG | UWOP_PUSH_MACHFRAME => 1,
        UWOP_ALLOC_LARGE => {
            if information == 0 {
                2
            } else {
                3
            }
        }
        UWOP_SAVE_NONVOL | UWOP_EPILOG | 8 => 2,
        UWOP_SAVE_NONVOL_FAR | UWOP_SPARE_CODE | 9 => 3,
        _ => return None,
    })
}

impl UnwindData {
    fn read(address: u64) -> Option<Self> {
        let info = read_struct::<UnwindInfo>(address)?;
        let header = info.bitfield_0.probe_get().ok()?;
        let version = (header & UnwindInfo::VERSION_MASK) >> UnwindInfo::VERSION_SHIFT;
        if version != 1 && version != 2 {
            return None;
        }
        let frame = info.bitfield_3.probe_get().ok()?;
        let count = info.count_of_codes.probe_get().ok()? as usize;
        let first = info.unwind_code[0].address();
        Some(Self {
            flags: (header & UnwindInfo::FLAGS_MASK) >> UnwindInfo::FLAGS_SHIFT,
            prolog: info.size_of_prolog.probe_get().ok()?,
            frame: ((frame & UnwindInfo::FRAME_REGISTER_MASK) >> UnwindInfo::FRAME_REGISTER_SHIFT) as usize,
            frame_offset: ((frame & UnwindInfo::FRAME_OFFSET_MASK) >> UnwindInfo::FRAME_OFFSET_SHIFT) as u64 * 16,
            codes: read_u16s(first, count)?,
            tail: first + (((count + 1) & !1) * 2) as u64,
        })
    }

    /// O establisher frame: RSP antes do SET_FPREG, depois o registrador de
    /// frame menos o deslocamento.
    fn establisher(&self, registers: &Registers, relative: u64) -> u64 {
        if self.frame == 0 {
            return registers.integer[RSP];
        }
        let mut established = relative >= self.prolog as u64 || self.flags & UNW_FLAG_CHAININFO != 0;
        let mut slot = 0;
        while !established && slot < self.codes.len() {
            let code = self.codes[slot];
            let operation = (code >> 8) & 0xF;
            established = operation == UWOP_SET_FPREG && (code & 0xFF) as u64 <= relative;
            let Some(slots) = slot_count(operation, code >> 12) else { break };
            slot += slots;
        }
        if established { registers.integer[self.frame].wrapping_sub(self.frame_offset) } else { registers.integer[RSP] }
    }
}

/// O retorno no topo da pilha (função folha ou fim do desenrolamento).
fn pop_return(registers: &mut Registers) -> Option<()> {
    let rsp = registers.integer[RSP];
    registers.rip = read::<u64>(rsp)?;
    registers.integer[RSP] = rsp.wrapping_add(8);
    Some(())
}

/// Desfaz um quadro pelos códigos de unwind (sem epílogos nem handlers): os
/// inteiros e o RIP do chamador. `first`: o RIP é o da falha, não um retorno.
fn unwind_frame(modules: &mut Modules, registers: &mut Registers, first: bool) -> Option<()> {
    let pc = if first { registers.rip } else { registers.rip.wrapping_sub(1) };
    let image = modules.index(pc).map(|index| (modules.list[index].base, modules.list[index].size));
    let Some((base, mut entry)) = image.and_then(|(base, size)| function_entry(base, size, pc).map(|entry| (base, entry))) else {
        return pop_return(registers);
    };
    let mut machine_frame = false;
    let mut establisher_frame = None;
    for _ in 0..MAX_CHAIN {
        let info = UnwindData::read(base + entry.unwind as u64)?;
        let relative = pc.wrapping_sub(base + entry.begin as u64);
        let establisher = *establisher_frame.get_or_insert_with(|| info.establisher(registers, relative));
        let inside_prolog = relative < info.prolog as u64;
        let mut slot = 0;
        while slot < info.codes.len() {
            let code = info.codes[slot];
            let operation = (code >> 8) & 0xF;
            let register = (code >> 12) as usize;
            let slots = slot_count(operation, code >> 12)?;
            if slot + slots > info.codes.len() {
                return None;
            }
            let word = |offset: usize| info.codes.get(slot + offset).copied().unwrap_or(0) as u64;
            let (first_word, second_word) = (word(1), word(2));
            slot += slots;
            // No meio do prólogo só as operações já executadas são desfeitas.
            if operation == UWOP_EPILOG || operation == UWOP_SPARE_CODE || (inside_prolog && (code & 0xFF) as u64 > relative) {
                continue;
            }
            let rsp = registers.integer[RSP];
            match operation {
                UWOP_PUSH_NONVOL => {
                    registers.integer[register] = read::<u64>(rsp)?;
                    registers.integer[RSP] = rsp.wrapping_add(8);
                }
                UWOP_ALLOC_LARGE => registers.integer[RSP] = rsp.wrapping_add(if register != 0 { first_word | second_word << 16 } else { first_word * 8 }),
                UWOP_ALLOC_SMALL => registers.integer[RSP] = rsp.wrapping_add(register as u64 * 8 + 8),
                UWOP_SET_FPREG => registers.integer[RSP] = registers.integer[info.frame].wrapping_sub(info.frame_offset),
                UWOP_SAVE_NONVOL => registers.integer[register] = read::<u64>(establisher.wrapping_add(first_word * 8))?,
                UWOP_SAVE_NONVOL_FAR => registers.integer[register] = read::<u64>(establisher.wrapping_add(first_word | second_word << 16))?,
                UWOP_PUSH_MACHFRAME => {
                    let frame = rsp.wrapping_add(register as u64 * 8);
                    registers.rip = read::<u64>(frame)?;
                    registers.integer[RSP] = read::<u64>(frame + 24)?;
                    machine_frame = true;
                }
                // Os XMM salvos não mudam a pilha.
                _ => {}
            }
        }
        if info.flags & UNW_FLAG_CHAININFO == 0 {
            break;
        }
        entry = read_function(info.tail)?;
    }
    if machine_frame { Some(()) } else { pop_return(registers) }
}

/// Os RIPs dos quadros, a partir de `start`, enquanto a pilha sobe.
fn walk(modules: &mut Modules, start: Registers) -> Vec<u64> {
    let mut frames = Vec::new();
    let mut registers = start;
    for index in 0..WALK_FRAMES {
        let rip = registers.rip;
        if rip == 0 || rip >= USER_PROBE_ADDRESS {
            break;
        }
        frames.push(rip);
        let rsp = registers.integer[RSP];
        if unwind_frame(modules, &mut registers, index == 0).is_none() || registers.integer[RSP] <= rsp {
            break;
        }
    }
    frames
}

/// Quadros do despacho de exceções em modo usuário no começo de uma pilha
/// tirada de uma chamada de sistema: até o último quadro do RtlRaiseException
/// ou do KiUserExceptionDispatcher da ntdll (0 sem eles).
fn dispatch_frames(modules: &mut Modules, frames: &[u64]) -> usize {
    let mut skipped = 0;
    for (position, &address) in frames.iter().enumerate() {
        let Some(index) = modules.index(address) else { continue };
        if !modules.list[index].name.eq_ignore_ascii_case("ntdll.dll") {
            continue;
        }
        if modules.symbol(index, address).is_some_and(|(name, distance)| distance < 0x400 && (name == "RtlRaiseException" || name == "KiUserExceptionDispatcher")) {
            skipped = position;
        }
    }
    skipped
}
