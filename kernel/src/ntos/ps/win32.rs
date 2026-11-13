//! Suporte do Process Manager ao subsistema Win32k, como no Ps do
//! NT: registro e invocação do despachante de callouts
//! (PsEstablishWin32Callouts / PsInvokeWin32Callout), os callouts de saída de
//! thread e de processo, a publicação dos ponteiros Win32Process/Win32Thread/
//! WindowStation/DxgProcess e os filtros de syscalls Win32k do EPROCESS.
//! Conferido contra o ntoskrnl 19041: PsEstablishWin32Callouts 0x7996b0,
//! PsInvokeWin32Callout 0x61b5a0 (ExCallCallBack 0x61b29c), PspExitThread
//! 0x6c35f0 (callouts nos offsets +0x4b0 e +0x593), PsSetProcessWin32Process
//! 0x68c460, PsSetThreadWin32Thread 0x695e20, PsIsWin32KFilterEnabled
//! 0x310e00, PsGetWin32KFilterSet 0x2ff710,
//! PsGetCurrentThreadWin32ThreadAndEnterCriticalRegion 0x2e6c00. As funções
//! que devolvem `u32` devolvem o NTSTATUS.
//!
//! Threads GUI (PsConvertToGuiThread): o win32k real publica a tabela de
//! serviços gráfica (KeAddSystemServiceTable) e o despachante de callouts
//! (PsEstablishWin32Callouts). Uma thread vira GUI na primeira syscall da
//! tabela 1: o KiSystemCall64 chama o PsConvertToGuiThread, que invoca o
//! callout de processo e depois o de thread e só então liga
//! KTHREAD.GuiThread. Sem o win32k não existe bloco de callouts: o
//! PsInvokeWin32Callout devolve STATUS_INVALID_PARAMETER e a thread continua
//! não-GUI.
//!
//! O despachante é o único bloco EX_CALLBACK de PsWin32CallBack, criado por
//! ExAllocateCallBack(Dispatch, NULL): cada callout chama
//! `Dispatch(NULL, CalloutType, Parameter)`. A saída de thread e de processo
//! chega aqui pelas rotinas de saída de `ps::process` (registradas em
//! [`init`]), na ordem do PspExitThread: o callout de thread, com a thread que
//! sai como corrente, e depois o de processo.
//!
//! Lacunas honestas: (1) o OpenNT não tem MM_SESSION_SPACE, então o portão de
//! sessão do MmSessionGetWin32Callouts (sessão pronta -> PsWin32CallBack, senão
//! PsWin32NullCallBack) se reduz a "callouts registrados"; (2) o ramo
//! ProcessTimerDelay de PsSetProcessWin32Process (fila de
//! PspTimerDelayWorkerRoutine quando EPROCESS.ProcessTimerDelay não é zero)
//! não existe no OpenNT, que nunca escreve esse campo.

use core::sync::atomic::Ordering;

use super::process;
use crate::hal::amd64::native_call;
use crate::ntos::ex::push_lock;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_obpsse::{Win32ProcessCalloutParameters, Win32ThreadCalloutParameters};
use crate::ntos::inc::types::{Eprocess, Ethread, Kthread};
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_ALREADY_WIN32: u32 = 0x4000_001B;

/// PSW32CALLOUTTYPE: callout de processo e de thread.
pub const PS_W32_PROCESS_CALLOUT: i32 = 0;
pub const PS_W32_THREAD_CALLOUT: i32 = 1;
/// PSW32THREADCALLOUTTYPE: inicialização (PsConvertToGuiThread) e saída.
const PS_W32_THREAD_CALLOUT_INITIALIZE: u32 = 0;
const PS_W32_THREAD_CALLOUT_EXIT: u32 = 1;

/// PsWin32CallBack: a rotina do bloco (o Context do bloco é NULL); Some =
/// PsWin32CalloutsEstablished.
static WIN32_CALLOUT: SpinLock<Option<u64>> = SpinLock::new(None);

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (do chamador do export ou o que está saindo).
    unsafe { Eprocess::at(process) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREAD vivo (do chamador do export, a corrente ou a que sai).
    unsafe { Ethread::at(thread) }
}

/// Despachante registrado (None antes de PsEstablishWin32Callouts).
pub fn win32_callout() -> Option<u64> {
    *WIN32_CALLOUT.lock()
}

/// PsEstablishWin32Callouts(CalloutDispatch): ExAllocateCallBack(fn, NULL) e
/// ExCompareExchangeCallBack contra o bloco vazio; só o primeiro registro
/// vale. Devolve o BOOLEAN da troca que o 19041 deixa em AL; num segundo
/// registro o bloco novo é liberado sem publicar nada.
pub fn establish_callouts(dispatch: u64) -> bool {
    let mut callout = WIN32_CALLOUT.lock();
    if callout.is_some() {
        return false;
    }
    *callout = Some(dispatch);
    true
}

/// PsInvokeWin32Callout(CalloutType, Parameter) da sessão corrente:
/// ExCallCallBack sobre PsWin32CallBack — `Dispatch(NULL, CalloutType,
/// Parameter)`; sem bloco registrado, STATUS_INVALID_PARAMETER. A rotina é
/// chamada fora do lock (o NT a protege só pela referência do bloco).
pub fn invoke_callout(callout_type: i32, parameter: u64) -> u32 {
    match win32_callout() {
        Some(dispatch) => native_call::call(dispatch, &[0, callout_type as i64 as u64, parameter]) as u32,
        None => STATUS_INVALID_PARAMETER,
    }
}

/// Callout de thread {Thread, CalloutType} (o bloco que o NT monta na pilha).
fn thread_callout(thread: u64, callout_type: u32) -> u32 {
    let block = guest::alloc_bytes(Win32ThreadCalloutParameters::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco recém-alocado com o tamanho do tipo, zerado e alinhado.
    let parameters = unsafe { Win32ThreadCalloutParameters::at(block) };
    parameters.thread.set(thread);
    parameters.callout_type.set(callout_type);
    let status = invoke_callout(PS_W32_THREAD_CALLOUT, block);
    guest::free_bytes(block);
    status
}

/// Callout de processo {Process, Initialize}.
fn process_callout(process: u64, initialize: bool) -> u32 {
    let block = guest::alloc_bytes(Win32ProcessCalloutParameters::SIZE);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: bloco recém-alocado com o tamanho do tipo, zerado e alinhado.
    let parameters = unsafe { Win32ProcessCalloutParameters::at(block) };
    parameters.process.set(process);
    parameters.initialize.set(initialize as u32);
    let status = invoke_callout(PS_W32_PROCESS_CALLOUT, block);
    guest::free_bytes(block);
    status
}

/// PspExitThread (+0x4b0): uma thread com Win32Thread recebe o callout de
/// thread {Thread, PsW32ThreadCalloutExit}. O NT ignora o status.
pub fn thread_exit_callout(thread: u64) {
    if ethread(thread).tcb.win32_thread.get() != 0 {
        let _ = thread_callout(thread, PS_W32_THREAD_CALLOUT_EXIT);
    }
}

/// PspExitThread (+0x593): na saída do último thread de um processo com
/// Win32Process, o callout de processo {Process, Initialize = FALSE}.
pub fn process_exit_callout(process: u64) {
    if eprocess(process).win32_process.get() != 0 {
        let _ = process_callout(process, false);
    }
}

fn current_thread() -> Option<&'static Ethread> {
    let thread = process::get_current_thread();
    (thread != 0).then(|| ethread(thread))
}

/// KTHREAD.GuiThread da thread corrente: o KiSystemCall64 usa o
/// KeServiceDescriptorTableShadow só para threads GUI.
pub fn is_gui_thread() -> bool {
    current_thread().is_some_and(|thread| thread.tcb.gui_thread() != 0)
}

/// PsConvertToGuiThread da thread corrente, na ordem do ntoskrnl 19041:
/// chamada de KernelMode, thread já GUI, processo com
/// DisallowWin32kSystemCalls, o callout de processo (Initialize = TRUE)
/// quando o processo ainda não tem Win32Process, o callout de thread
/// (PsW32ThreadCalloutInitialize) e só então KTHREAD.GuiThread, ligado por
/// LOCK OR (ThreadFlags é compartilhado com outras CPUs).
pub fn convert_to_gui_thread() -> u32 {
    let Some(thread) = current_thread() else { return STATUS_INVALID_PARAMETER };
    if thread.tcb.previous_mode.get() == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if thread.tcb.gui_thread() != 0 {
        return STATUS_ALREADY_WIN32;
    }
    let process = process::get_current_process();
    let owner = eprocess(process);
    if owner.mitigation_flags_values.disallow_win32k_system_calls() != 0 {
        return STATUS_ACCESS_DENIED;
    }
    // Sem o PsEstablishWin32Callouts do win32k, o ExReferenceCallBackBlock
    // não acha a rotina: STATUS_INVALID_PARAMETER.
    if owner.win32_process.get() == 0 {
        let status = process_callout(process, true);
        if (status as i32) < 0 {
            return status;
        }
    }
    let status = thread_callout(thread.address(), PS_W32_THREAD_CALLOUT_INITIALIZE);
    if (status as i32) < 0 {
        return status;
    }
    thread.tcb.thread_flags.atomic().fetch_or(Kthread::GUI_THREAD_MASK as i32, Ordering::SeqCst);
    status
}

/// Liga os callouts de saída às rotinas de saída de `ps::process` (thread,
/// com a thread que sai como corrente; depois processo).
pub fn init() {
    process::register_thread_exit_routine(thread_exit_callout);
    process::register_process_exit_routine(process_exit_callout);
}

/// PsSetProcessWin32Process(Process, Win32Process, PrevWin32Process): sob o
/// ProcessLock exclusivo numa região crítica. Publicar exige o campo vazio e
/// o processo fora de exclusão (senão PROCESS_IS_TERMINATING); limpar
/// (Win32Process NULL) exige que o campo ainda seja o anterior (senão
/// UNSUCCESSFUL).
pub fn set_process_win32_process(process: &Eprocess, win32_process: u64, previous: u64) -> Result<u32, KernelError> {
    let lock = process.process_lock.address();
    critical_region::with_critical(|| {
        push_lock::acquire_exclusive(lock, 0)?;
        let status = if win32_process != 0 {
            if process.process_delete() != 0 || process.win32_process.get() != 0 {
                STATUS_PROCESS_IS_TERMINATING
            } else {
                process.win32_process.set(win32_process);
                0
            }
        } else if process.win32_process.get() == previous {
            process.win32_process.set(0);
            0
        } else {
            STATUS_UNSUCCESSFUL
        };
        push_lock::release_exclusive(lock, 0)?;
        Ok(status)
    })
}

/// PsSetThreadWin32Thread(Thread, Win32Thread, PrevWin32Thread): xchg
/// incondicional ao publicar; ao limpar, lock cmpxchg só se o campo ainda
/// for o anterior. Devolve o valor observado antes da troca.
pub fn set_thread_win32_thread(thread: &Ethread, win32_thread: u64, previous: u64) -> u64 {
    let field = thread.tcb.win32_thread.atomic();
    if win32_thread != 0 {
        return field.swap(win32_thread, Ordering::SeqCst);
    }
    match field.compare_exchange(previous, 0, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(observed) | Err(observed) => observed,
    }
}

/// PsSetProcessWindowStation.
pub fn set_process_window_station(process: &Eprocess, window_station: u64) {
    process.win32_window_station.set(window_station);
}

/// PsSetProcessDxgProcess.
pub fn set_process_dxg_process(process: &Eprocess, dxg_process: u64) {
    process.dxg_process.set(dxg_process);
}

/// PsGetCurrentThreadWin32ThreadAndEnterCriticalRegion(ProcessId*): grava
/// Cid.UniqueProcess, entra na região crítica (KernelApcDisable--) e devolve
/// o Win32Thread da thread corrente.
pub fn current_win32_thread_and_enter_critical_region(process_id_out: &Field<u64>) -> Result<u64, KernelError> {
    let thread = ethread(process::get_current_thread());
    process_id_out.set(thread.cid.unique_process.get());
    critical_region::enter_critical()?;
    Ok(thread.tcb.win32_thread.get())
}

/// PsIsWin32KFilterEnabledForProcess: MitigationFlags.EnableFilteredWin32kAPIs.
pub fn filter_enabled(process: &Eprocess) -> bool {
    process.mitigation_flags_values.enable_filtered_win32k_ap_is() != 0
}

/// PsIsWin32KFilterAuditEnabledForProcess: MitigationFlags.AuditFilteredWin32kAPIs.
pub fn filter_audit_enabled(process: &Eprocess) -> bool {
    process.mitigation_flags_values.audit_filtered_win32k_ap_is() != 0
}

/// PsIsWin32KFilterEnabled: o processo é KTHREAD.ApcState.Process
/// (gs:[0x188]+0xB8), como no PsGetCurrentProcess.
pub fn current_filter_enabled() -> bool {
    filter_enabled(eprocess(process::get_current_process()))
}

/// PsIsWin32KFilterAuditEnabled.
pub fn current_filter_audit_enabled() -> bool {
    filter_audit_enabled(eprocess(process::get_current_process()))
}

/// PsGetWin32KFilterSet: EPROCESS.Win32KFilterSet do processo corrente.
pub fn current_filter_set() -> u32 {
    eprocess(process::get_current_process()).win32_k_filter_set.get()
}
