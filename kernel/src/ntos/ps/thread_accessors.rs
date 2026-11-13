//! Acessores do ETHREAD: os PsGetThread*, PsIsThread*/PsIsSystemThread, os
//! PsGetCurrentThread* e o estado de erros graves da thread.
//!
//! Leem os campos do layout 19041 que o OpenNT mantém, pelo endereço do
//! objeto dado (inclusive um objeto retido depois da saída da thread); não
//! referenciam nem substituem o chamador. As variantes `current_*` partem da
//! thread corrente do Process Manager.

use core::sync::atomic::{AtomicU32, Ordering};

use super::process;
use crate::ntos::ex::rundown;
use crate::ntos::inc::nt_abi::kthread;
use crate::ntos::ke::pcr;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::token::thread as thread_tokens;
use crate::rtl::KernelError;

/// STATUS_PENDING: a thread ainda não terminou.
const STATUS_PENDING: u32 = 0x103;

/// Estado compartilhado dos erros graves (a representação usa um único campo).
static HARD_ERRORS_DISABLED: AtomicU32 = AtomicU32::new(0);

/// PsGetThreadHardErrorsAreDisabled. Padrão do NT: erros graves habilitados (0).
pub fn hard_errors_are_disabled() -> u32 {
    HARD_ERRORS_DISABLED.load(Ordering::Acquire)
}

/// PsSetThreadHardErrorsAreDisabled: devolve o valor anterior.
pub fn set_hard_errors_are_disabled(disabled: bool) -> u32 {
    HARD_ERRORS_DISABLED.swap(disabled as u32, Ordering::AcqRel)
}

/// PsGetThreadExitStatus: enquanto a proteção de rundown ainda pode ser
/// adquirida, a thread não terminou (STATUS_PENDING).
pub fn exit_status(thread: u64) -> Result<u32, KernelError> {
    let protection = thread + kthread::RUNDOWN_PROTECT;
    if rundown::acquire(protection)? {
        rundown::release(protection)?;
        return Ok(STATUS_PENDING);
    }
    Ok(guest::read32(thread + kthread::EXIT_STATUS))
}

/// PsGetThreadId: Cid.UniqueThread.
pub fn id(thread: u64) -> u64 {
    guest::read64(thread + kthread::CID_UNIQUE_THREAD)
}

/// PsGetThreadProcess.
pub fn process(thread: u64) -> u64 {
    guest::read64(thread + kthread::PROCESS)
}

/// PsGetThreadProcessId: Cid.UniqueProcess.
pub fn process_id(thread: u64) -> u64 {
    guest::read64(thread + kthread::CID_UNIQUE_PROCESS)
}

/// PsGetCurrentThreadProcess.
pub fn current_process() -> u64 {
    process(process::get_current_thread())
}

/// PsGetCurrentThreadProcessId.
pub fn current_process_id() -> u64 {
    process_id(process::get_current_thread())
}

/// PsGetThreadTeb.
pub fn teb(thread: u64) -> u64 {
    guest::read64(thread + kthread::TEB)
}

/// PsGetCurrentThreadTeb.
pub fn current_teb() -> u64 {
    teb(process::get_current_thread())
}

/// PsGetThreadWin32Thread.
pub fn win32_thread(thread: u64) -> u64 {
    guest::read64(thread + kthread::WIN32_THREAD)
}

/// PsGetCurrentThreadWin32Thread.
pub fn current_win32_thread() -> u64 {
    win32_thread(process::get_current_thread())
}

/// PsGetThreadCreateTime.
pub fn create_time(thread: u64) -> u64 {
    guest::read64(thread + kthread::CREATE_TIME)
}

/// PsIsSystemThread: MiscFlags.SystemThread (bit 10).
pub fn is_system_thread(thread: u64) -> bool {
    (guest::read32(thread + kthread::MISC_FLAGS) >> 10) & 1 != 0
}

/// PsIsThreadTerminating: CrossThreadFlags.Terminated (bit 0).
pub fn is_terminating(thread: u64) -> bool {
    guest::read32(thread + kthread::CROSS_THREAD_FLAGS) & 1 != 0
}

/// PsIsThreadImpersonating: há um token de personificação ativo na thread.
pub fn is_impersonating(thread: u64) -> bool {
    thread_tokens::get(thread).is_some()
}

/// KeIsExecutingDpc (servido pelo grupo de consultas de silo): a máscara
/// seleciona os indicadores de execução de DPC do DpcRequestSummary.
pub fn is_executing_dpc() -> u32 {
    pcr::get_dpc_request_summary() & 0x10001
}
