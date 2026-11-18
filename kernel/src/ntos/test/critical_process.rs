//! Autoteste dos processos e threads críticos (`ps/critical.rs`).
//!
//! Num processo de teste, em KernelMode (sem SeDebugPrivilege): o
//! ZwSetInformationProcess(ProcessBreakOnTermination) e o
//! ZwSetInformationThread(ThreadBreakOnTermination) ligam as marcas que o
//! ZwQueryInformationProcess(29) e o ZwQueryInformationThread(18) devolvem
//! (um ULONG, ReturnLength 4, outro tamanho STATUS_INFO_LENGTH_MISMATCH). As
//! verificações do 19041 respondem como o PspCatchCriticalBreak seria
//! chamado, sem parar a máquina: o PspTerminateAllThreads e o PspExitThread
//! da última thread com o processo crítico; o PspTerminateThreadByPointer
//! com a thread crítica, e o PspExitThread com ela só com o
//! KdDebuggerEnabled; nada para a thread com ProcessSelfDelete ou
//! ProcessDelete (o fim do processo inteiro), que o começo do término
//! (`ps::create::begin_termination`) liga. Os parâmetros do
//! CRITICAL_PROCESS_DIED vêm do DISPATCHER_HEADER.Type do objeto: (EPROCESS,
//! 0, 0, 0) e (ETHREAD, 1, 0, 0).

use alloc::format;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Ethread};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::critical::{self, PROCESS_EXITED, TERMINATING_PROCESS, TERMINATING_THREAD, THREAD_EXITED};
use crate::ntos::test::multiprocess::identity::with_test_process;
use crate::ntos::test::phase6::call_export;

type Assert = fn(bool, &str);

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// O pseudo-handle da thread corrente.
const CURRENT_THREAD: u64 = (-2i64) as u64;

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: o EPROCESS e a ETHREAD do processo de teste, vivos no corpo.
    unsafe { T::at(address) }
}

pub fn run(assert: Assert) {
    let measured = with_test_process("critico.exe", None, |test| {
        let (eprocess, ethread) = (at::<Eprocess>(test.process), at::<Ethread>(test.thread));
        let (value, returned) = (guest::alloc_bytes(8), guest::alloc_bytes(8));
        let status = |result: Option<u64>| result.map_or(u32::MAX, |status| status as u32);
        let set = |name: &str, handle: u64, class: u64, data: u32| {
            guest::write32(value, data);
            status(call_export(name, &[handle, class, value, 4]))
        };
        let query = |name: &str, handle: u64, class: u64, length: u64| {
            guest::write32(value, 0xAAAA_AAAA);
            guest::write32(returned, 0);
            (status(call_export(name, &[handle, class, value, length, returned])), guest::read32(value), guest::read32(returned))
        };
        // O processo crítico.
        let marked = (set("ZwSetInformationProcess", u64::MAX, 29, 1), eprocess.break_on_termination(), query("ZwQueryInformationProcess", u64::MAX, 29, 4), query("ZwQueryInformationProcess", u64::MAX, 29, 8).0);
        let terminating = critical::process_termination(test.process).map(|found| (found.message, found.object, found.bug_check_parameters(), found.text()));
        let last = critical::last_thread_exit(test.process).map(|found| (found.message, found.bug_check_parameters()));
        let unmarked = (set("ZwSetInformationProcess", u64::MAX, 29, 0), query("ZwQueryInformationProcess", u64::MAX, 29, 4), critical::process_termination(test.process), critical::last_thread_exit(test.process));
        // A thread crítica (a corrente durante o corpo).
        let thread_marked = (set("ZwSetInformationThread", CURRENT_THREAD, 18, 1), ethread.break_on_termination(), query("ZwQueryInformationThread", CURRENT_THREAD, 18, 4), query("ZwQueryInformationThread", CURRENT_THREAD, 18, 8).0);
        let thread_terminating = critical::thread_termination(test.thread).map(|found| (found.message, found.process, found.bug_check_parameters()));
        let thread_exit = (critical::thread_exit(test.thread, false), critical::thread_exit(test.thread, true).map(|found| found.message));
        let self_delete = Eprocess::PROCESS_SELF_DELETE_MASK;
        eprocess.flags.atomic().fetch_or(self_delete, core::sync::atomic::Ordering::SeqCst);
        let self_deleting = (critical::thread_termination(test.thread), critical::thread_exit(test.thread, true));
        eprocess.flags.atomic().fetch_and(!self_delete, core::sync::atomic::Ordering::SeqCst);
        // O começo do término de um processo não crítico liga ProcessDelete
        // (com a marca ainda ligada ele pararia a máquina).
        let delete_before = eprocess.process_delete();
        if eprocess.break_on_termination() == 0 {
            crate::ntos::ps::create::begin_termination(test.process, 0x1234);
        }
        let deleting = (delete_before, eprocess.process_delete(), critical::thread_termination(test.thread));
        eprocess.flags.atomic().fetch_and(!Eprocess::PROCESS_DELETE_MASK, core::sync::atomic::Ordering::SeqCst);
        let thread_unmarked = (set("ZwSetInformationThread", CURRENT_THREAD, 18, 0), query("ZwQueryInformationThread", CURRENT_THREAD, 18, 4), critical::thread_termination(test.thread));
        guest::free_bytes(value);
        guest::free_bytes(returned);
        (marked, terminating, last, unmarked, thread_marked, thread_terminating, thread_exit, self_deleting, deleting, thread_unmarked)
    });
    let Some((marked, terminating, last, unmarked, thread_marked, thread_terminating, thread_exit, self_deleting, deleting, thread_unmarked)) = measured else {
        assert(false, "critico: processo de teste");
        return;
    };
    let process = terminating.as_ref().map_or(0, |found| found.1);
    assert(marked == (0, 1, (0, 1, 4), STATUS_INFO_LENGTH_MISMATCH), "critico: ProcessBreakOnTermination liga a marca e o ZwQueryInformationProcess(29) a devolve");
    assert(
        process != 0 && terminating == Some((TERMINATING_PROCESS, process, [process, 0, 0, 0], format!("Terminating critical process 0x{process:016X} (critico.exe)"))) && last == Some((PROCESS_EXITED, [process, 0, 0, 0])),
        "critico: o fim e a ultima thread do processo critico pedem CRITICAL_PROCESS_DIED (EPROCESS, 0, 0, 0)",
    );
    assert(unmarked == (0, (0, 0, 4), None, None), "critico: sem a marca o processo termina sem parada");
    assert(thread_marked == (0, 1, (0, 1, 4), STATUS_INFO_LENGTH_MISMATCH), "critico: ThreadBreakOnTermination liga a marca e o ZwQueryInformationThread(18) a devolve");
    let thread = thread_terminating.as_ref().map_or(0, |found| found.2[0]);
    assert(thread != 0 && thread_terminating == Some((TERMINATING_THREAD, process, [thread, 1, 0, 0])) && thread_exit == (None, Some(THREAD_EXITED)), "critico: a thread critica pede CRITICAL_PROCESS_DIED (ETHREAD, 1, 0, 0); a saida dela so com o KdDebuggerEnabled");
    assert(self_deleting == (None, None) && deleting == (0, 1, None), "critico: com ProcessSelfDelete ou ProcessDelete (o begin_termination) a thread critica nao para a maquina");
    assert(thread_unmarked == (0, (0, 0, 4), None), "critico: sem a marca a thread termina sem parada");
}
