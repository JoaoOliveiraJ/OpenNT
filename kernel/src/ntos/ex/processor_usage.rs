//! Contadores de uso do processador corrente — ntoskrnl 19041
//! ExGetCurrentProcessorCounts 0x303500, ExGetCurrentProcessorCpuUsage 0x5b1b80.
//!
//! As duas leem só a KPRCB do processador corrente (gs:[0x20], a
//! KPCR.CurrentPrcb): IdleThread->KernelTime (ticks ociosos),
//! KernelTime + UserTime (ticks totais) e Number. O OpenNT mantém a KPRCB
//! real dentro da KPCR; os campos são lidos onde o NT os lê. Enquanto o
//! relógio do OpenNT não acumular os ticks da KPRCB e não houver thread
//! ociosa publicada em IdleThread, os valores ficam zero (IdleThread NULL
//! conta como zero ticks ociosos).

use crate::ntos::inc::types::{Field, Kpcr, Kprcb, Kthread, NtStruct};
use crate::ntos::ke::pcr;

/// KPCR.CurrentPrcb do processador corrente.
fn current_prcb() -> &'static Kprcb {
    // SAFETY: a KPCR está mapeada desde `pcr::init` e CurrentPrcb aponta para
    // a KPRCB embutida nela.
    unsafe { Kprcb::at(Kpcr::at(pcr::get_pcr_address()).current_prcb.get()) }
}

/// Ticks de kernel da thread ociosa (zero sem IdleThread publicada).
fn idle_ticks(prcb: &Kprcb) -> u32 {
    let idle = prcb.idle_thread.get();
    if idle == 0 {
        return 0;
    }
    // SAFETY: KPRCB.IdleThread aponta para a KTHREAD ociosa viva.
    unsafe { Kthread::at(idle) }.kernel_time.get()
}

/// ExGetCurrentProcessorCounts(IdleCount, KernelAndUser, Index): grava os
/// três ULONG sem validar ponteiros; Kernel+User é soma de 32 bits.
pub fn counts(idle: &Field<u32>, kernel_and_user: &Field<u32>, index: &Field<u32>) {
    let prcb = current_prcb();
    idle.set(idle_ticks(prcb));
    kernel_and_user.set(prcb.kernel_time.get().wrapping_add(prcb.user_time.get()));
    index.set(prcb.number.get());
}

/// ExGetCurrentProcessorCpuUsage(CpuUsage): 100 - Idle*100/(Kernel+User),
/// com a soma do divisor em 64 bits (add r8, rax) e o resultado em ULONG.
/// Divergência: o original divide por zero (#DE) se a KPRCB nunca contou um
/// tick; aqui um divisor zero é tratado como processador sem uso (0).
pub fn cpu_usage(usage: &Field<u32>) {
    let prcb = current_prcb();
    let total = prcb.kernel_time.get() as u64 + prcb.user_time.get() as u64;
    usage.set(if total == 0 { 0 } else { 100u32.wrapping_sub((idle_ticks(prcb) as u64 * 100 / total) as u32) });
}
