//! A tabela de quantum do primeiro plano (ntoskrnl 19041): o
//! PsChangeQuantumTable (rva 0x78c5d8), que o NtSetSystemInformation
//! (SystemPrioritySeperation, classe 39) chama com o
//! Win32PrioritySeparation que o winsrvext do csrss lê de
//! `Control\PriorityControl`, e o PspComputeQuantum (rva 0x7072ec).
//!
//! - PsPrioritySeparation = min(Sep & 3, 2).
//! - A tabela vem de Sep & 0xC: 4 = variável, 8 = fixa, 0 ou 0xC = o padrão
//!   (fixa num servidor, variável numa estação de trabalho). A metade vem de
//!   Sep & 0x30: 0x10 = longa, 0x20 = curta, senão o padrão (longa num
//!   servidor, curta numa estação). PspForegroundQuantum recebe os três
//!   bytes escolhidos; PspUseJobSchedulingClasses liga só com a fixa longa.
//! - Com ModifyActiveProcesses, cada processo de PsActiveProcessHead recebe
//!   o quantum do PspComputeQuantum pelo KeSetQuantumProcess: 6 na classe
//!   IDLE; num job, com as classes de escalonamento ligadas, o da classe
//!   do job; senão PspForegroundQuantum[primeiro plano ? PsPrioritySeparation
//!   : 0], com o primeiro plano = MemoryPriority do working set diferente de
//!   zero.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::ntos::inc::types::{Eprocess, Ejob, NtStruct};
use crate::rtl::SpinLock;

/// PspVariableQuantums e PspFixedQuantums: metade curta e metade longa.
const VARIABLE_QUANTUMS: [u8; 6] = [6, 12, 18, 12, 24, 36];
const FIXED_QUANTUMS: [u8; 6] = [18, 18, 18, 36, 36, 36];
/// PspJobSchedulingClasses (as classes 0 a 9).
const JOB_SCHEDULING_CLASSES: [u8; 10] = [6, 12, 18, 24, 30, 36, 42, 48, 54, 60];
/// PROCESS_PRIORITY_CLASS_IDLE e o quantum dela.
const PRIORITY_CLASS_IDLE: u8 = 1;
const IDLE_QUANTUM: u8 = 6;

/// PsPrioritySeparation e PspForegroundQuantum com o que o
/// PsChangeQuantumTable(FALSE, PsRawPrioritySeparation) do PspInitPhase0
/// grava com o valor padrão 2 (separação 2, a metade curta da tabela
/// variável); o csrss reaplica o valor do registro pela classe 39.
static PRIORITY_SEPARATION: AtomicU32 = AtomicU32::new(2);
static FOREGROUND_QUANTUM: SpinLock<[u8; 3]> = SpinLock::new([6, 12, 18]);
/// PspUseJobSchedulingClasses.
static USE_JOB_SCHEDULING_CLASSES: AtomicBool = AtomicBool::new(false);

/// MmIsThisAnNtAsSystem: o OpenNT é uma estação de trabalho
/// (RtlGetNtProductType = NtProductWinNt).
fn is_server() -> bool {
    false
}

/// PsPrioritySeparation corrente.
pub fn priority_separation() -> u32 {
    PRIORITY_SEPARATION.load(Ordering::Acquire)
}

/// PspForegroundQuantum corrente.
pub fn foreground_quantum() -> [u8; 3] {
    *FOREGROUND_QUANTUM.lock()
}

/// PspComputeQuantum(Process, Foreground).
fn compute_quantum(process: u64, foreground: bool) -> u8 {
    // SAFETY: EPROCESS vivo da lista de processos ativos.
    let object = unsafe { Eprocess::at(process) };
    if object.priority_class.get() == PRIORITY_CLASS_IDLE {
        return IDLE_QUANTUM;
    }
    let job = object.job.get();
    if job != 0 && USE_JOB_SCHEDULING_CLASSES.load(Ordering::Acquire) {
        // SAFETY: o EJOB referenciado pelo processo.
        let job = unsafe { Ejob::at(job) };
        let effective = job.effective_scheduling_class.get();
        let class = if effective < 10 { effective } else { job.scheduling_class.get() };
        return JOB_SCHEDULING_CLASSES.get(class as usize).copied().unwrap_or(0);
    }
    let index = if foreground { priority_separation() as usize } else { 0 };
    foreground_quantum()[index]
}

/// PsChangeQuantumTable(ModifyActiveProcesses, PrioritySeparation).
pub fn change_quantum_table(modify_active_processes: bool, separation: u32) {
    PRIORITY_SEPARATION.store((separation & 3).min(2), Ordering::Release);
    let fixed = match separation & 0xC {
        4 => false,
        8 => true,
        _ => is_server(),
    };
    let long = match separation & 0x30 {
        0x10 => true,
        0x20 => false,
        _ => is_server(),
    };
    let table = if fixed { &FIXED_QUANTUMS } else { &VARIABLE_QUANTUMS };
    let start = if long { 3 } else { 0 };
    *FOREGROUND_QUANTUM.lock() = [table[start], table[start + 1], table[start + 2]];
    USE_JOB_SCHEDULING_CLASSES.store(fixed && long, Ordering::Release);
    if !modify_active_processes {
        return;
    }
    for entry in crate::ntos::ps::process::list_active_processes() {
        // SAFETY: EPROCESS da lista de processos ativos.
        let foreground = unsafe { Eprocess::at(entry.address) }.vm.instance.flags.memory_priority.get() != 0;
        crate::ntos::ke::thread_priority::set_quantum_process(entry.address, compute_quantum(entry.address, foreground), &entry.threads);
    }
}
