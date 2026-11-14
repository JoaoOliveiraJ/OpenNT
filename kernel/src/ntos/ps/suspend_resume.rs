//! Retomada de um processo inteiro (PsResumeProcess).
//!
//! Como o PsResumeProcess do ntoskrnl 19041 (rva 0x6a2050): numa região
//! crítica, adquire o rundown do processo (EPROCESS.RundownProtect; um
//! processo que já sai devolve STATUS_PROCESS_IS_TERMINATING), percorre as
//! threads dele pelo PsGetNextProcessThread e retoma cada uma
//! (KeResumeThread), menos as marcadas com KTHREAD.MiscFlags
//! .BypassProcessFreeze. O registro ETW de suspensão e retomada
//! (EtwTiLogSuspendResumeProcess, com EPROCESS.Flags3
//! .EnableProcessSuspendResumeLogging) não existe no OpenNT.

use crate::ntos::ex::rundown;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Kthread};
use crate::ntos::ke::critical_region;
use crate::ntos::ps::enum_process_threads;
use crate::ntos::ps::user::threads;
use crate::rtl::KernelError;

const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;

/// PsResumeProcess(Process): devolve o NTSTATUS.
pub fn resume_process(process: &Eprocess) -> Result<u32, KernelError> {
    critical_region::with_critical(|| {
        let rundown_pointer = process.rundown_protect.address();
        if !rundown::acquire(rundown_pointer)? {
            return Ok(STATUS_PROCESS_IS_TERMINATING);
        }
        let mut thread = enum_process_threads::get_next(process.address(), 0)?;
        while thread != 0 {
            // SAFETY: a thread referenciada pelo PsGetNextProcessThread.
            if unsafe { Kthread::at(thread) }.bypass_process_freeze() == 0 {
                threads::resume_thread(thread);
            }
            thread = enum_process_threads::get_next(process.address(), thread)?;
        }
        rundown::release(rundown_pointer)?;
        Ok(0)
    })
}
