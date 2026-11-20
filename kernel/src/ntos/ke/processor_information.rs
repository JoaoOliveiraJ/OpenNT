//! SystemProcessorInformation e SystemProcessorFeaturesInformation.
//!
//! O ExpGetSystemProcessorInformation do 19041 devolve
//! KeProcessorArchitecture (0 na classe emulada), KeProcessorLevel,
//! KeProcessorRevision, KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS)
//! e o ULONG baixo de KeFeatureBits; o
//! ExpGetSystemProcessorFeaturesInformation, o KeFeatureBits inteiro e três
//! ULONGLONG reservados zerados. Os valores são os que
//! `processor_identity` montou na KPRCB do BSP.

use super::{processor_group, processor_identity};
use crate::ntos::inc::types::{NtStruct, SystemProcessorInformation};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::user_probe;

/// PROCESSOR_ARCHITECTURE_AMD64.
const PROCESSOR_ARCHITECTURE_AMD64: u16 = 9;
/// ALL_PROCESSOR_GROUPS.
const ALL_PROCESSOR_GROUPS: u32 = 0xFFFF;
/// sizeof(SYSTEM_PROCESSOR_FEATURES_INFORMATION).
pub const FEATURES_INFORMATION_SIZE: u32 = 0x20;

/// SYSTEM_PROCESSOR_INFORMATION (12 bytes). A arquitetura emulada altera só
/// o identificador de arquitetura.
pub fn query(
    output: u64,
    buffer_length: u32,
    output_length_pointer: u64,
    from_user_mode: bool,
    report_emulated_architecture: bool,
) -> u32 {
    if from_user_mode {
        if buffer_length != 0 && output % 4 != 0 {
            return 0x8000_0002;
        }
        if !user_probe::probe_user_write(output, buffer_length as u64)
            || (output_length_pointer != 0 && !user_probe::probe_user_write(output_length_pointer, 4))
        {
            return 0xC000_0005;
        }
    }
    let size = SystemProcessorInformation::SIZE as u32;
    // ReturnLength: ponteiro do chamador (do modo usuário quando a chamada vem
    // de lá), escrita sondada.
    let report_length = || output_length_pointer == 0 || guest::try_write::<u32>(output_length_pointer, size).is_ok();
    if buffer_length < size {
        if !report_length() {
            return 0xC000_0005;
        }
        return 0xC000_0004;
    }
    if output == 0 {
        return 0xC000_0005;
    }
    let Ok(information) = SystemProcessorInformation::try_at(output) else { return 0xC000_0005 };
    let architecture = if report_emulated_architecture { 0 } else { PROCESSOR_ARCHITECTURE_AMD64 };
    let written = information.processor_architecture.probe_set(architecture).is_ok()
        && information.processor_level.probe_set(processor_identity::processor_level()).is_ok()
        && information.processor_revision.probe_set(processor_identity::processor_revision()).is_ok()
        && information.maximum_processors.probe_set(processor_group::maximum_processor_count_ex(ALL_PROCESSOR_GROUPS) as u16).is_ok()
        && information.processor_feature_bits.probe_set(processor_identity::feature_bits() as u32).is_ok();
    if !written || !report_length() {
        return 0xC000_0005;
    }
    0
}

/// SYSTEM_PROCESSOR_FEATURES_INFORMATION: KeFeatureBits e três ULONGLONG
/// zerados; com menos de 0x20 bytes, STATUS_INFO_LENGTH_MISMATCH com 0x20 no
/// ReturnLength.
pub fn query_features(output: u64, buffer_length: u32, output_length_pointer: u64, from_user_mode: bool) -> u32 {
    if from_user_mode {
        if buffer_length != 0 && output % 4 != 0 {
            return 0x8000_0002;
        }
        if !user_probe::probe_user_write(output, buffer_length as u64)
            || (output_length_pointer != 0 && !user_probe::probe_user_write(output_length_pointer, 4))
        {
            return 0xC000_0005;
        }
    }
    let report_length = || output_length_pointer == 0 || guest::try_write::<u32>(output_length_pointer, FEATURES_INFORMATION_SIZE).is_ok();
    if buffer_length < FEATURES_INFORMATION_SIZE {
        return if report_length() { 0xC000_0004 } else { 0xC000_0005 };
    }
    let mut bytes = [0u8; FEATURES_INFORMATION_SIZE as usize];
    bytes[..8].copy_from_slice(&processor_identity::feature_bits().to_le_bytes());
    if guest::try_write_bytes(output, &bytes).is_err() || !report_length() {
        return 0xC000_0005;
    }
    0
}

// ---- SystemProcessorPerformanceInformation (8) -----------------------------
//
// ExpQuerySystemInformation 19041, 0x6ca568: um
// SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION de 0x30 bytes por processador do
// grupo pedido (o NtQuerySystemInformation passa o grupo do processador
// corrente; o NtQuerySystemInformationEx, o USHORT da entrada). Um
// comprimento zero ou que não é múltiplo de 0x30 dá
// STATUS_INFO_LENGTH_MISMATCH com 0x30 vezes os processadores do grupo no
// ReturnLength; um comprimento menor que todos devolve só os que cabem, com
// sucesso. Cada campo é uma contagem de ticks vezes o KeMaximumIncrement:
// IdleTime e KernelTime do PoGetIdleTimes (o KernelTime inclui o ocioso),
// UserTime, DpcTime, InterruptTime e InterruptCount da KPRCB.
//
// O OpenNT soma por processador o tempo de kernel e de usuário que o
// `ps::process::account_thread` cobra das threads (em 100 ns); o ocioso é o
// resto do tempo desde o boot. O DPC e as interrupções entram no tempo de
// kernel de quem roda, sem contagem própria (DpcTime, InterruptTime e
// InterruptCount ficam zero).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::extra_ps_user::SystemProcessorPerformanceInformation;
use crate::ntos::mm::memory_map::MAX_CPUS;

/// O tempo de kernel (fora do ocioso) e o de usuário de cada processador,
/// em 100 ns.
static KERNEL_BUSY_TIME: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static USER_TIME: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];

/// O tamanho de um SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION.
pub const PERFORMANCE_INFORMATION_SIZE: u32 = SystemProcessorPerformanceInformation::SIZE as u32;

/// Cobra `elapsed_100ns` de kernel ou de usuário do processador corrente.
pub fn charge_processor_time(kernel: bool, elapsed_100ns: u64) {
    let cpu = (processor_group::current_processor_number() as usize).min(MAX_CPUS - 1);
    let counter = if kernel { &KERNEL_BUSY_TIME[cpu] } else { &USER_TIME[cpu] };
    counter.fetch_add(elapsed_100ns, Ordering::Relaxed);
}

/// Os tempos de um processador em 100 ns, arredondados para baixo ao tick
/// (a contagem de ticks do NT vezes o KeMaximumIncrement): (IdleTime,
/// KernelTime, UserTime).
fn processor_times(cpu: usize) -> (i64, i64, i64) {
    let increment = super::clock::MAXIMUM_INCREMENT as u64;
    let ticks = |value: u64| (value / increment * increment) as i64;
    let elapsed = super::clock::uptime_100ns();
    let user = USER_TIME[cpu].load(Ordering::Relaxed).min(elapsed);
    let busy = KERNEL_BUSY_TIME[cpu].load(Ordering::Relaxed).min(elapsed - user);
    (ticks(elapsed - user - busy), ticks(elapsed - user), ticks(user))
}

/// SystemProcessorPerformanceInformation do grupo `group` (o chamador já
/// conferiu que o grupo existe) em `output`: (NTSTATUS, ReturnLength). Cada
/// estrutura vai para o chamador por `write` (sondado no modo usuário); uma
/// escrita recusada é STATUS_ACCESS_VIOLATION.
pub fn query_performance(group: u16, output: u64, length: u32, write: &mut dyn FnMut(u64, &[u8]) -> bool) -> (u32, u32) {
    let count = processor_group::active_processor_count_ex(group as u32) as u32;
    if length == 0 || length % PERFORMANCE_INFORMATION_SIZE != 0 {
        return (0xC000_0004, PERFORMANCE_INFORMATION_SIZE * count);
    }
    let scratch = guest::alloc_bytes(SystemProcessorPerformanceInformation::SIZE);
    if scratch == 0 {
        return (0xC000_009A, 0);
    }
    let mut written = 0u32;
    for index in 0..count {
        if length < written + PERFORMANCE_INFORMATION_SIZE {
            break;
        }
        let (idle, kernel, user) = processor_times((index as usize).min(MAX_CPUS - 1));
        // SAFETY: o bloco de kernel de 0x30 bytes recém-alocado.
        let information = unsafe { SystemProcessorPerformanceInformation::at(scratch) };
        information.idle_time.set(idle);
        information.kernel_time.set(kernel);
        information.user_time.set(user);
        information.dpc_time.set(0);
        information.interrupt_time.set(0);
        information.interrupt_count.set(0);
        information._padding.set(0);
        if !write(output + written as u64, &guest::read_bytes(scratch, PERFORMANCE_INFORMATION_SIZE as usize)) {
            guest::free_bytes(scratch);
            return (0xC000_0005, written);
        }
        written += PERFORMANCE_INFORMATION_SIZE;
    }
    guest::free_bytes(scratch);
    (0, written)
}
