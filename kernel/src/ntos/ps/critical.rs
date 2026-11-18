//! Processos e threads críticos, com a lógica do ntoskrnl 19041.
//!
//! A marca é EPROCESS.Flags.BreakOnTermination num processo e
//! ETHREAD.CrossThreadFlags.BreakOnTermination numa thread, posta pelo
//! NtSetInformationProcess(ProcessBreakOnTermination) e pelo
//! NtSetInformationThread(ThreadBreakOnTermination)
//! (`ps/set_process_information.rs`, `ps/set_thread_information.rs`); o
//! RtlSetProcessIsCritical e o RtlSetThreadIsCritical da ntdll passam por
//! essas classes (com o valor antigo, pela consulta das mesmas classes; com
//! CheckFlag, só se o NtGlobalFlag da PEB tem FLG_ENABLE_SYSTEM_CRIT_BREAKS,
//! senão STATUS_UNSUCCESSFUL sem chamar o kernel). No 19041 ficam críticos:
//! o smss.exe inicial (o StartFirstUserProcess, `init/initial_process.rs`) e
//! a thread principal dele (RtlSetThreadIsCritical no wmain sem argumentos),
//! o csrss.exe de cada sessão (o SmpExecuteImage do smss da sessão marca o
//! subsistema que cria, e o xxxDesktopThread do win32kfull liga a marca do
//! processo corrente ao começar e desliga ao sair), o wininit.exe e a thread
//! principal dele, e o services.exe (o wmain, quando o evento de outra
//! instância não existe). O winlogon.exe não é marcado. O lsass.exe, o
//! svchost.exe e o SmpApiCallback do smss pedem com CheckFlag e, com o
//! NtGlobalFlag zero da hive, não marcam.
//!
//! As verificações, nos pontos do 19041:
//! - o PspTerminateAllThreads (rva 0x707640), que todo fim de processo pedido
//!   atravessa (NtTerminateProcess com handle ou NULL, o fim por job, a
//!   exceção fatal): processo crítico, "Terminating critical process";
//! - o PspTerminateThreadByPointer (rva 0x7079e0): thread crítica cujo
//!   processo não tem ProcessDelete nem ProcessSelfDelete (o fim do processo
//!   inteiro não conta como fim da thread), "Terminating critical thread";
//! - o PspExitThread (rva 0x6c35f8): com o KdDebuggerEnabled, a mesma
//!   condição da thread, "Critical thread ... exited"; e a última thread de
//!   um processo crítico, "Critical process ... exited".
//!
//! O PspCatchCriticalBreak (rva 0x90ae54) recebe a mensagem, o objeto, o
//! ImageFileName do processo, o silo de servidor dele e o código de saída.
//! Um silo de servidor em desligamento (PsGetServerSiloState >= 2) não faz
//! nada. Com o KdDebuggerEnabled, a mensagem vai ao depurador (DbgPrintEx)
//! e, com o host presente, o DbgPrompt "Break, or Ignore (bi)? " repete até
//! B (int 3 e pergunta de novo) ou I (volta sem parar). Depois, no silo
//! hospedeiro, anexa-se ao processo do objeto (KeStackAttachProcess, se não
//! é o corrente) e para a máquina com KeBugCheckEx(CRITICAL_PROCESS_DIED,
//! Objeto, 1 se o objeto é uma thread e 0 se é um processo, 0, 0); num silo
//! de servidor, o PsTerminateServerSilo no lugar da parada. O
//! CRITICAL_OBJECT_TERMINATION (0xF4) não sai daqui no 19041: só o
//! ObpRemoveObjectRoutine o levanta (`ob/object_header.rs`).
//!
//! Diferenças do OpenNT: o transporte do depurador não atende o DbgPrompt
//! (`kd/debug_service.rs`), então com o host presente a mensagem vai a ele e
//! a parada é a do KeBugCheckEx, que entra no depurador antes da tela; e o
//! OpenNT não cria silos de servidor (EPROCESS.ServerSilo fica NULL), então
//! o ramo do silo de servidor só registra o pedido. A mensagem também sai
//! sempre na serial, com o código de saída, e, sem trava do kernel retida, o
//! post-mortem do processo (`ps/user/process.rs`) antes da parada; acima de
//! PASSIVE_LEVEL ou com uma trava retida, a anexação também fica de fora.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::nt_abi::dispatcher_header;
use crate::ntos::inc::types::{Eprocess, Ethread};
use crate::ntos::ke::{bugcheck, irql};
use crate::ntos::kd;
use crate::ntos::ps::process_context;
use crate::ntos::ps::silo::query as silo_query;
use crate::ntos::ps::user::{process as user_process, process_state};
use crate::rtl::sync;

/// CRITICAL_PROCESS_DIED.
pub const CRITICAL_PROCESS_DIED: u32 = 0xEF;
/// KOBJECTS ThreadObject (DISPATCHER_HEADER.Type).
const THREAD_OBJECT: u8 = 6;

/// As mensagens do PspCatchCriticalBreak no 19041.
pub const TERMINATING_PROCESS: &str = "Terminating critical process 0x%p (%s)\n";
pub const TERMINATING_THREAD: &str = "Terminating critical thread 0x%p (in %s)\n";
pub const THREAD_EXITED: &str = "Critical thread 0x%p (in %s) exited\n";
pub const PROCESS_EXITED: &str = "Critical process 0x%p (%s) exited\n";

/// Um PspCatchCriticalBreak pedido: a mensagem, o objeto (EPROCESS ou
/// ETHREAD) e o processo dele (o próprio objeto, ou KTHREAD.Process).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalBreak {
    pub message: &'static str,
    pub object: u64,
    pub process: u64,
}

impl CriticalBreak {
    /// Os parâmetros do KeBugCheckEx(CRITICAL_PROCESS_DIED): o objeto, 1 se
    /// o DISPATCHER_HEADER.Type dele é ThreadObject e 0 senão, 0 e 0.
    pub fn bug_check_parameters(&self) -> [u64; 4] {
        // SAFETY: o EPROCESS ou a ETHREAD que termina, vivo durante o fim; o
        // DISPATCHER_HEADER do KPROCESS e o do KTHREAD abrem o objeto.
        let kind = unsafe { Field::<u8>::at(self.object + dispatcher_header::TYPE) }.get() & 0x7F;
        [self.object, (kind == THREAD_OBJECT) as u64, 0, 0]
    }

    /// A mensagem com o objeto (%p) e o ImageFileName do processo (%s).
    pub fn text(&self) -> String {
        let name = image_file_name(self.process);
        self.message.replacen("%p", &format!("{:016X}", self.object), 1).replacen("%s", &name, 1).trim_end_matches('\n').into()
    }
}

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: o EPROCESS que termina, retido por quem pede o fim.
    unsafe { Eprocess::at(process) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: a ETHREAD que termina, retida por quem pede o fim.
    unsafe { Ethread::at(thread) }
}

/// EPROCESS.ImageFileName até o primeiro zero.
fn image_file_name(process: u64) -> String {
    let bytes: Vec<u8> = eprocess(process).image_file_name.iter().map(|byte| byte.get()).take_while(|&byte| byte != 0).collect();
    String::from_utf8_lossy(&bytes).into()
}

/// ProcessDelete ou ProcessSelfDelete: o fim do processo inteiro já foi
/// pedido (PspTerminateProcess ou NtTerminateProcess(NULL)).
fn process_deleting(process: u64) -> bool {
    eprocess(process).flags.get() & (Eprocess::PROCESS_DELETE_MASK | Eprocess::PROCESS_SELF_DELETE_MASK) != 0
}

/// A entrada do PspTerminateAllThreads: o processo crítico.
pub fn process_termination(process: u64) -> Option<CriticalBreak> {
    (process != 0 && eprocess(process).break_on_termination() != 0).then_some(CriticalBreak { message: TERMINATING_PROCESS, object: process, process })
}

/// A thread crítica de um processo sem fim pedido (a condição do
/// PspTerminateThreadByPointer e a do PspExitThread).
fn critical_thread(thread: u64, message: &'static str) -> Option<CriticalBreak> {
    if thread == 0 || ethread(thread).break_on_termination() == 0 {
        return None;
    }
    let process = ethread(thread).tcb.process.get();
    (process != 0 && !process_deleting(process)).then_some(CriticalBreak { message, object: thread, process })
}

/// A entrada do PspTerminateThreadByPointer.
pub fn thread_termination(thread: u64) -> Option<CriticalBreak> {
    critical_thread(thread, TERMINATING_THREAD)
}

/// A verificação de thread do PspExitThread: só com o KdDebuggerEnabled.
pub fn thread_exit(thread: u64, debugger_enabled: bool) -> Option<CriticalBreak> {
    if !debugger_enabled {
        return None;
    }
    critical_thread(thread, THREAD_EXITED)
}

/// A verificação de processo do PspExitThread: a última thread de um
/// processo crítico.
pub fn last_thread_exit(process: u64) -> Option<CriticalBreak> {
    (process != 0 && eprocess(process).break_on_termination() != 0).then_some(CriticalBreak { message: PROCESS_EXITED, object: process, process })
}

/// O fim pedido de `process` (PspTerminateAllThreads), com `exit_status`.
pub fn terminating_process(process: u64, exit_status: u32) {
    if let Some(critical) = process_termination(process) {
        catch_critical_break(critical, exit_status);
    }
}

/// O fim pedido de `thread` (PspTerminateThreadByPointer).
pub fn terminating_thread(thread: u64, exit_status: u32) {
    if let Some(critical) = thread_termination(thread) {
        catch_critical_break(critical, exit_status);
    }
}

/// A saída de `thread` (PspExitThread); `last_thread` quando ela era a
/// última do processo.
pub fn exiting_thread(thread: u64, last_thread: bool, exit_status: u32) {
    if let Some(critical) = thread_exit(thread, kd::debugger::enabled()) {
        catch_critical_break(critical, exit_status);
    }
    if !last_thread || thread == 0 {
        return;
    }
    if let Some(critical) = last_thread_exit(ethread(thread).tcb.process.get()) {
        catch_critical_break(critical, exit_status);
    }
}

/// PspCatchCriticalBreak(Message, Object, ImageFileName, ServerSilo,
/// ExitStatus). Só volta num silo de servidor.
fn catch_critical_break(critical: CriticalBreak, exit_status: u32) {
    let text = critical.text();
    let silo = silo_query::process_server_silo(critical.process);
    if !silo_query::is_host_silo(silo) {
        debug_print!("[ps] {} (codigo {:#x}; silo de servidor {:#x} sem suporte: sem parada)", text, exit_status, silo);
        return;
    }
    debug_print!("[ps] {} (codigo {:#x})", text, exit_status);
    if kd::debugger::enabled() {
        // DbgPrintEx(DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, Message, ...).
        kd::print_log::output(&text);
    }
    let [first, second, third, fourth] = critical.bug_check_parameters();
    // KeStackAttachProcess ao processo do objeto quando ele não é o corrente;
    // anexado, o post-mortem do OpenNT (a pilha de quem pediu o fim, a falha
    // publicada e o Ldr) vai à serial antes da parada. Acima de
    // PASSIVE_LEVEL ou com uma trava do kernel retida, nada disso: só a
    // parada.
    if irql::get_irql() == irql::PASSIVE_LEVEL && sync::spin_locks_held() == 0 && sync::shared_locks_held() == 0 {
        let ran = process_state::get(critical.process).is_some_and(|state| state.started.load(Ordering::Acquire));
        let _ = process_context::with_process(critical.process, || {
            if ran {
                user_process::post_mortem(critical.process);
            }
            bugcheck::bug_check_ex(CRITICAL_PROCESS_DIED, first, second, third, fourth);
        });
    }
    bugcheck::bug_check_ex(CRITICAL_PROCESS_DIED, first, second, third, fourth)
}
