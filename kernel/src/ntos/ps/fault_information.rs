//! Informação de falha do processo: PsSetProcessFaultInformation (ntoskrnl
//! 19041), o que o win32k e o WER registram de um processo que travou ou
//! caiu.
//!
//! Os bits de `*FaultFlags`:
//! - 0x1: EPROCESS.Flags3.Crashed, ligado atomicamente (no NT, na primeira
//!   vez, também o relatório de telemetria, o registro na caixa preta e o
//!   estado de telemetria do app);
//! - 0x2: HangCount (três bits de EPROCESS+0x87B) mais um, saturando em 7;
//! - 0x4: GhostCount (os três bits seguintes) mais um, saturando em 7;
//! - 0x8: PrefilterException.
//!
//! Os campos de +0x87B mudam com o push lock do processo
//! (EPROCESS.ProcessLock) retido, como no NT. Devolve STATUS_SUCCESS.

use core::sync::atomic::Ordering;

use crate::ntos::ex::push_lock;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::rtl::KernelError;

const CRASHED: u32 = 0x1;
const HANG: u32 = 0x2;
const GHOST: u32 = 0x4;
const PREFILTER_EXCEPTION: u32 = 0x8;
const COUNT_LIMIT: u8 = 7;

/// PsSetProcessFaultInformation(Process, FaultFlags*).
pub fn set_fault_information(process: &Eprocess, flags: u32) -> Result<u32, KernelError> {
    if flags & CRASHED != 0 {
        process.flags3.atomic().fetch_or(Eprocess::CRASHED_MASK, Ordering::SeqCst);
    }
    if flags & (HANG | GHOST | PREFILTER_EXCEPTION) != 0 {
        let lock = process.process_lock.address();
        push_lock::acquire_exclusive(lock, 0)?;
        if flags & HANG != 0 && process.hang_count() < COUNT_LIMIT {
            process.set_hang_count(process.hang_count() + 1);
        }
        if flags & GHOST != 0 && process.ghost_count() < COUNT_LIMIT {
            process.set_ghost_count(process.ghost_count() + 1);
        }
        if flags & PREFILTER_EXCEPTION != 0 {
            process.set_prefilter_exception(1);
        }
        push_lock::release_exclusive(lock, 0)?;
    }
    Ok(0)
}
