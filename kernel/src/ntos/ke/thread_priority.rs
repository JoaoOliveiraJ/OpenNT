//! Prioridade dinâmica do KTHREAD.
//!
//! Contrato medido no kernel 19041. As filas e a entrega ao próximo contexto
//! pertencem a `thread_dispatch`.

use alloc::vec::Vec;

use super::{thread_dispatch, thread_lock};
use crate::ntos::inc::types::{Kprocess, Kthread, NtStruct};
use crate::rtl::KernelError;

fn kthread(thread: u64) -> &'static Kthread {
    // SAFETY: KTHREAD viva do chamador.
    unsafe { Kthread::at(thread) }
}

/// KPRIORITY é LONG; o campo interno é um byte com sinal.
pub fn query_priority(thread: u64) -> i32 {
    kthread(thread).priority.get() as i32
}

pub fn query_base_priority(thread: u64) -> i32 {
    kthread(thread).base_priority.get() as i32
}

/// Usa o maior piso ativo (inclusive o bit 31); não troca o resumo por uma
/// política fixa.
pub fn effective_priority(thread: u64, requested: i32) -> i32 {
    let floor_summary = kthread(thread).priority_floor_summary.get();
    requested.max(if floor_summary != 0 { 31 - floor_summary.leading_zeros() as i32 } else { 0 })
}

/// Renova o quantum a partir dos ciclos próprios; a multiplicação é ULONG
/// antes da soma QWORD.
pub fn reset_quantum(thread: u64) {
    let cycles = thread_dispatch::sample_cycles(thread);
    let target = kthread(thread);
    let quantum_reset = target.quantum_reset.get() as u32;
    let quantum_cycles = quantum_reset.wrapping_mul(thread_dispatch::cycles_per_quantum());
    target.quantum_target.set(cycles.wrapping_add(quantum_cycles as u64));
    // ThreadFlags.QuantumDonation: CAS atômico no DWORD compartilhado.
    target.set_quantum_donation(0);
}

/// Remove o boost anterior antes de comparar prioridades, inclusive quando
/// o pedido é igual.
fn clear_decrement(thread: u64) {
    let target = kthread(thread);
    let decrement = target.priority_decrement.get() as u8;
    if decrement & 15 != 0 {
        target.foreground_loss_time.set(thread_dispatch::tick_count());
    }
    if decrement != 0 {
        target.priority_decrement.set(0);
    }
}

/// Uma alteração em Ready muda a fila; em Running/Standby a redução pode
/// escolher uma concorrente mais prioritária antes que o contexto retome.
fn change_priority(thread: u64, requested: i32, deferred: &mut Vec<u64>) -> Result<(), KernelError> {
    let previous = query_priority(thread);
    let priority = effective_priority(thread, requested);
    if priority == previous {
        return Ok(());
    }
    let target = kthread(thread);
    let state = target.state.get();
    if state == thread_dispatch::state::READY {
        thread_dispatch::remove_ready(thread)?;
    }
    target.priority.set(priority as i8);
    if state == thread_dispatch::state::READY {
        // A comparação unsigned reproduz KiPrepareReadyThreadForRescheduling,
        // inclusive o wrap do tick.
        let wait_time = target.wait_time.get();
        if (1..=14).contains(&priority) && thread_dispatch::tick_count().wrapping_sub(300) >= wait_time {
            target.priority_decrement.set((((15 - priority) << 4) & 255) as u8 as i8);
            target.priority.set(15);
            thread_dispatch::ensure_minimum_quantum(thread);
        }
        thread_dispatch::defer_ready(thread, deferred);
    } else if priority < previous && (state == thread_dispatch::state::RUNNING || state == thread_dispatch::state::STANDBY) && (state == thread_dispatch::state::STANDBY || thread_dispatch::next_thread() == 0) {
        let replacement = thread_dispatch::take_ready_above(priority)?;
        if replacement != 0 {
            thread_dispatch::reserve_next(replacement);
            if state == thread_dispatch::state::STANDBY {
                thread_dispatch::defer_ready(thread, deferred);
            }
        }
    }
    // Uma fila local por CPU; não há afinidade com fila partilhada
    // (ThreadFlags.SharedReadyQueueAffinity, CAS atômico).
    target.set_shared_ready_queue_affinity(0);
    Ok(())
}

/// KeSetPriorityThread: devolve a prioridade anterior.
pub fn set_priority(thread: u64, requested_priority: u64) -> Result<i32, KernelError> {
    let requested = requested_priority as i32;
    let mut deferred = Vec::new();
    if thread_dispatch::is_idle_thread(thread) {
        return Ok(1);
    }
    if !(0..=31).contains(&requested) {
        return Err(KernelError::new("KPRIORITY outside 0..31"));
    }
    let previous = thread_lock::with_lock(thread, || -> Result<i32, KernelError> {
        let previous = query_priority(thread);
        let base = query_base_priority(thread);
        clear_decrement(thread);
        if requested != previous {
            reset_quantum(thread);
            let priority = if requested == 0 && base != 0 { 1 } else { requested };
            if base < 16 || priority >= 16 {
                change_priority(thread, priority, &mut deferred)?;
            }
        }
        Ok(previous)
    })?;
    // Nenhum lock de thread nem IRQL elevado atravessa a entrega ao escalonador.
    thread_dispatch::complete_priority_change(&deferred);
    Ok(previous)
}

/// KeSetBasePriorityThread: ajusta a base relativa ao processo dono (sem
/// confundir incremento com prioridade absoluta) e devolve o incremento
/// anterior. Campos e escolhas comparados às instruções do kernel 19041.
pub fn set_base_priority(thread: u64, requested_increment: u64) -> Result<i32, KernelError> {
    let increment = requested_increment as i32;
    let mut deferred = Vec::new();
    if thread_dispatch::is_idle_thread(thread) {
        return Ok(0);
    }
    let target = kthread(thread);
    let previous = thread_lock::with_lock(thread, || -> Result<i32, KernelError> {
        // SAFETY: o processo dono de uma thread viva.
        let process = unsafe { Kprocess::at(target.process.get()) };
        let process_base = process.base_priority.get() as i32;
        let previous_base = query_base_priority(thread);
        let previous_priority = query_priority(thread);
        let previous_saturation = target.saturation.get() as i32;
        let previous = if previous_saturation != 0 { previous_saturation * 16 } else { previous_base - process_base };
        // ABS e adição em LONG de 32 bits, inclusive o overflow de LONG_MIN.
        let absolute = increment.wrapping_abs();
        let saturation: i32 = if absolute >= 16 {
            if increment > 0 {
                1
            } else {
                -1
            }
        } else {
            0
        };
        let requested_base = process_base.wrapping_add(increment);
        let realtime = process_base >= 16;
        let base = requested_base.min(if realtime { 31 } else { 15 }).max(if realtime { 16 } else { 1 });
        let mut dynamic = base;
        if !realtime && saturation == 0 {
            // Tira o boost anterior, preserva o piso e leva a diferença da
            // base para a prioridade.
            let mut unboosted = previous_priority;
            if previous_priority < 16 {
                let decrement = target.priority_decrement.get() as u8 as i32;
                let candidate = (previous_priority - (decrement >> 4) - (decrement & 15)) as i8 as i32;
                unboosted = effective_priority(thread, previous_base.max(candidate));
            }
            dynamic = (unboosted + base - previous_base).min(15).max(1);
        }
        target.saturation.set(saturation as i8);
        target.base_priority.set(base as i8);
        clear_decrement(thread);
        if dynamic != previous_priority {
            reset_quantum(thread);
            change_priority(thread, dynamic, &mut deferred)?;
        }
        Ok(previous)
    })?;
    // A fila pronta é atualizada e a preempção ocorre com o lock liberado.
    thread_dispatch::complete_priority_change(&deferred);
    Ok(previous)
}
