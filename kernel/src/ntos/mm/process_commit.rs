//! O commit privado de um processo (EPROCESS.CommitCharge, em páginas),
//! como o ntoskrnl 19041 o cobra:
//!
//! - MiChargeFullProcessCommitment (rva 0x5f90d0): MiChargeProcessCommitment
//!   primeiro — sem teto (CommitChargeLimit 0) o commit só sobe, com o pico
//!   (CommitChargePeak); com teto, passar dele falha e, num processo de job,
//!   o PsReportProcessMemoryLimitViolation avisa o job que impõe o limite —;
//!   depois, com Flags2.ReportCommitChanges, o PspChangeJobMemoryUsageByProcess
//!   cobra a cadeia de jobs, e uma recusa devolve o commit do processo. As
//!   duas recusas são STATUS_COMMITMENT_LIMIT.
//! - MiReturnFullProcessCharges (rva 0x2989f0): devolve aos jobs (com
//!   ReportCommitChanges) e ao processo.
//!
//! Cobram aqui as páginas privadas que o NtAllocateVirtualMemory comita e as
//! regiões privadas que o kernel monta para o processo (pilha, PEB, TEB);
//! as vistas de seções e as imagens não entram no commit do processo.

use core::sync::atomic::Ordering;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::ps::job::limits;

/// STATUS_COMMITMENT_LIMIT.
pub const STATUS_COMMITMENT_LIMIT: u32 = 0xC000_012D;

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: o EPROCESS dono do espaço, vivo enquanto o espaço existe.
    unsafe { Eprocess::at(process) }
}

/// O pico de commit sobe até `value`.
fn raise_peak(process: &Eprocess, value: u64) {
    let peak = process.commit_charge_peak.atomic();
    let mut current = peak.load(Ordering::SeqCst);
    while value > current {
        match peak.compare_exchange(current, value, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(seen) => current = seen,
        }
    }
}

/// MiChargeProcessCommitment(Process, Pages).
fn charge_process(process: &Eprocess, pages: u64) -> bool {
    let cell = process.commit_charge.atomic();
    if process.commit_charge_limit.get() == 0 {
        let charged = cell.fetch_add(pages, Ordering::SeqCst).wrapping_add(pages);
        raise_peak(process, charged);
        return true;
    }
    let mut current = cell.load(Ordering::SeqCst);
    loop {
        let charged = current.wrapping_add(pages);
        if charged > process.commit_charge_limit.get() {
            if process.job.get() != 0 {
                limits::report_process_memory_limit_violation();
            }
            return false;
        }
        match cell.compare_exchange(current, charged, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                raise_peak(process, charged);
                return true;
            }
            Err(seen) => current = seen,
        }
    }
}

/// MiChargeFullProcessCommitment(Process, Pages): 0 ou
/// STATUS_COMMITMENT_LIMIT.
pub fn charge(process: u64, pages: u64) -> u32 {
    if pages == 0 || process == 0 {
        return 0;
    }
    let target = eprocess(process);
    if !charge_process(target, pages) {
        return STATUS_COMMITMENT_LIMIT;
    }
    if !limits::charge_jobs(process, pages as i64) {
        target.commit_charge.atomic().fetch_sub(pages, Ordering::SeqCst);
        return STATUS_COMMITMENT_LIMIT;
    }
    0
}

/// MiReturnFullProcessCharges(Process, Pages).
pub fn release(process: u64, pages: u64) {
    if pages == 0 || process == 0 {
        return;
    }
    limits::charge_jobs(process, -(pages as i64));
    eprocess(process).commit_charge.atomic().fetch_sub(pages, Ordering::SeqCst);
}
