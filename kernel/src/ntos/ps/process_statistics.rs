//! PsQueryStatisticsProcess (ntoskrnl 19041, rva 0x619120): os contadores
//! de um processo que o ExpCopyProcessInfo copia para a lista de processos
//! do NtQuerySystemInformation.
//!
//! O NT soma, sob o ThreadListLock do processo, os campos do KPROCESS
//! (KernelTime, UserTime, ReadyTime, CycleTime, ContextSwitches,
//! KernelWaitTime e UserWaitTime, que guardam o que as threads que já saíram
//! deixaram), os contadores de E/S do EPROCESS (ReadOperationCount ...
//! OtherTransferCount) e os mesmos campos de cada KTHREAD viva da
//! ThreadListHead; os tempos saem em ticks vezes o KeMaximumIncrement.
//!
//! No OpenNT o tempo de kernel e o de usuário de cada thread são cobrados em
//! 100 ns no registro do processo (`process::account_thread`, as threads que
//! já saíram incluídas); aqui eles viram a contagem de ticks de 32 bits do NT
//! vezes o KeMaximumIncrement, como no ProcessTimes. As trocas de contexto
//! vêm do mesmo registro (`process::statistics`). O CycleTime e os contadores
//! de E/S são os campos do KPROCESS, do EPROCESS e das KTHREADs vivas, como
//! no NT.

use super::process;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, Kthread};

/// A saída do PsQueryStatisticsProcess usada pela lista de processos.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProcessStatistics {
    pub kernel_time: u64,
    pub user_time: u64,
    pub cycle_time: u64,
    pub context_switches: u64,
    pub read_operation_count: u64,
    pub write_operation_count: u64,
    pub other_operation_count: u64,
    pub read_transfer_count: u64,
    pub write_transfer_count: u64,
    pub other_transfer_count: u64,
}

/// Um tempo em 100 ns como a contagem de ticks de 32 bits vezes o
/// KeMaximumIncrement.
pub fn tick_time(time_100ns: u64) -> u64 {
    let increment = u64::from(crate::ntos::ke::clock::MAXIMUM_INCREMENT);
    (time_100ns / increment & 0xFFFF_FFFF) * increment
}

/// PsQueryStatisticsProcess(Process, Statistics).
pub fn query(process: u64) -> ProcessStatistics {
    // SAFETY: EPROCESS retido pelo chamador.
    let object = unsafe { Eprocess::at(process) };
    let (kernel, user, switches) = process::statistics(process);
    let mut statistics = ProcessStatistics {
        kernel_time: tick_time(kernel),
        user_time: tick_time(user),
        cycle_time: object.pcb.cycle_time.get(),
        context_switches: switches,
        read_operation_count: object.read_operation_count.quad_part.get() as u64,
        write_operation_count: object.write_operation_count.quad_part.get() as u64,
        other_operation_count: object.other_operation_count.quad_part.get() as u64,
        read_transfer_count: object.read_transfer_count.quad_part.get() as u64,
        write_transfer_count: object.write_transfer_count.quad_part.get() as u64,
        other_transfer_count: object.other_transfer_count.quad_part.get() as u64,
    };
    for thread in process::threads_of_process(process) {
        if !process::reference_thread_safe(thread) {
            continue;
        }
        // SAFETY: KTHREAD retida pela referência acima.
        let kthread = unsafe { Kthread::at(thread) };
        statistics.cycle_time = statistics.cycle_time.wrapping_add(kthread.cycle_time.get());
        statistics.read_operation_count = statistics.read_operation_count.wrapping_add(kthread.read_operation_count.get() as u64);
        statistics.write_operation_count = statistics.write_operation_count.wrapping_add(kthread.write_operation_count.get() as u64);
        statistics.other_operation_count = statistics.other_operation_count.wrapping_add(kthread.other_operation_count.get() as u64);
        statistics.read_transfer_count = statistics.read_transfer_count.wrapping_add(kthread.read_transfer_count.get() as u64);
        statistics.write_transfer_count = statistics.write_transfer_count.wrapping_add(kthread.write_transfer_count.get() as u64);
        statistics.other_transfer_count = statistics.other_transfer_count.wrapping_add(kthread.other_transfer_count.get() as u64);
        let _ = process::dereference_thread(thread);
    }
    statistics
}
