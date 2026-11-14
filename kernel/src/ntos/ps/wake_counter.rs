//! Contadores de wake do processo: PsChargeProcessWakeCounter e
//! PsReleaseProcessWakeCounter (o PspChargeProcessWakeCounter do ntoskrnl
//! 19041).
//!
//! Os contadores moram no EPROCESS.WakeInfo (PS_PROCESS_WAKE_INFORMATION):
//! WakeCounters[7] e NoWakeCounter. Cada cobrança soma o incremento ao
//! contador escolhido (o índice, ou o NoWakeCounter com o flag 2) com uma
//! instrução atômica; o valor novo sai sem o bit de sinal. Quando o processo
//! tem canal de notificação (WakeInfo.NotificationChannel) e o filtro de
//! borda do contador pede (HighEdgeFilter na subida para 1, LowEdgeFilter na
//! descida para 0), o canal WNF recebe um ZwUpdateWnfStateData vazio. O
//! PsChargeProcessWakeCounter só cobra processos com pai
//! (InheritedFromUniqueProcessId); o PsReleaseProcessWakeCounter recebe o
//! índice nos três bits baixos do ponteiro do processo (7 = o
//! NoWakeCounter). A cobrança do job do processo não existe aqui: o OpenNT
//! não cria jobs (EPROCESS.Job fica NULL).

use core::sync::atomic::Ordering;

use crate::ntos::ex::wnf::update as wnf_update;
use crate::ntos::inc::types::{Eprocess, NtStruct};
use crate::rtl::KernelError;

/// O flag que escolhe o NoWakeCounter.
const NO_WAKE_COUNTER: u32 = 2;
/// O índice etiquetado que pede o NoWakeCounter no release.
const TAGGED_NO_WAKE: u64 = 7;
const COUNTERS: u32 = 7;

/// PspChargeProcessWakeCounter: soma `increment` ao contador e devolve o
/// valor novo (sem o bit de sinal).
fn charge(process: &Eprocess, flags: u32, index: u32, increment: i32) -> Result<u32, KernelError> {
    let info = &process.wake_info;
    let no_wake = flags & NO_WAKE_COUNTER != 0;
    if !no_wake && index >= COUNTERS {
        return Err(KernelError::new("indice de contador de wake invalido"));
    }
    let counter = if no_wake { &info.no_wake_counter } else { &info.wake_counters[index as usize] };
    let previous = counter.atomic().fetch_add(increment as u32, Ordering::SeqCst);
    let value = previous.wrapping_add(increment as u32) & 0x7FFF_FFFF;
    let channel = info.notification_channel.get();
    if !no_wake && channel != 0 {
        let bit = 1u32 << index;
        let edge = if increment > 0 { info.wake_filter.high_edge_filter.get() & bit != 0 && value == 1 } else { info.wake_filter.low_edge_filter.get() & bit != 0 && value == 0 };
        if edge {
            wnf_update::update(info.notification_channel.address(), 0, 0, 0, 0, 0, false)?;
        }
    }
    Ok(value)
}

/// PsChargeProcessWakeCounter(Process, Flags, Index, Tag).
pub fn charge_process(process: &Eprocess, flags: u32, index: u32) -> Result<(), KernelError> {
    if process.inherited_from_unique_process_id.get() != 0 {
        charge(process, flags, index, 1)?;
    }
    Ok(())
}

/// PsReleaseProcessWakeCounter(TaggedProcess, Tag): o índice nos três bits
/// baixos do ponteiro.
pub fn release_process(tagged: u64) -> Result<(), KernelError> {
    let index = tagged & 7;
    // SAFETY: o EPROCESS do chamador de kernel, sem a etiqueta.
    let process = unsafe { Eprocess::at(tagged & !7) };
    let (flags, index) = if index == TAGGED_NO_WAKE { (NO_WAKE_COUNTER, 0) } else { (0, index as u32) };
    charge(process, flags, index, -1)?;
    Ok(())
}
