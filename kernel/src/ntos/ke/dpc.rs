//! Fila de chamadas diferidas drenada em DISPATCH_LEVEL.
//!
//! Descritores e argumentos conservam seus endereços de 64 bits até a
//! chamada nativa.

use alloc::collections::{BTreeMap, VecDeque};
use core::sync::atomic::Ordering;

use super::{irql, pcr, smp};
use crate::hal::amd64::native_call;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};
use crate::ntos::inc::types::{Kdpc, KdpcWatchdogInformation, NtStruct, ProcessorNumber};
use crate::rtl::{KernelError, SpinLock};

/// KOBJECTS DpcObject.
const DPC_OBJECT: u8 = 0x13;
/// KDPC_IMPORTANCE MediumImportance.
const MEDIUM_IMPORTANCE: u8 = 1;

/// Rotina interna do kernel (ex.: adaptador de EX_TIMER) para um KDPC.
pub type KernelDpcRoutine = fn(u64, u64, u64, u64);

struct DpcState {
    queue: VecDeque<u64>,
    kernel_routines: BTreeMap<u64, KernelDpcRoutine>,
}

static STATE: SpinLock<DpcState> = SpinLock::new(DpcState { queue: VecDeque::new(), kernel_routines: BTreeMap::new() });

fn kdpc(dpc: u64) -> &'static Kdpc {
    // SAFETY: KDPC viva do chamador (pool do driver ou objeto do kernel).
    unsafe { Kdpc::at(dpc) }
}

/// KeInitializeDpc: preenche o KDPC sem truncar rotina nem contexto.
pub fn initialize_dpc(dpc: u64, routine: u64, context: u64) {
    STATE.lock().kernel_routines.remove(&dpc);
    let object = kdpc(dpc);
    object.type_.set(DPC_OBJECT);
    object.importance.set(MEDIUM_IMPORTANCE);
    object.number.set(0);
    object.dpc_list_entry.next.set(0);
    object.processor_history.set(0);
    object.deferred_routine.set(routine);
    object.deferred_context.set(context);
    object.system_argument1.set(0);
    object.system_argument2.set(0);
    // Não enfileirado; a marca é retirada antes de chamar a rotina.
    object.dpc_data.set(0);
}

/// Rotina interna associada ao mesmo descritor, sem expor um endereço nativo.
pub fn initialize_kernel_dpc(dpc: u64, routine: KernelDpcRoutine, context: u64) {
    initialize_dpc(dpc, 0, context);
    STATE.lock().kernel_routines.insert(dpc, routine);
}

/// KeInsertQueueDpc: recusa dupla inserção. A marca DpcData é tomada num
/// LOCK CMPXCHG (o InterlockedCompareExchangePointer do NT), então só um
/// chamador enfileira o descritor.
pub fn insert_queue_dpc(dpc: u64, first: u64, second: u64) -> bool {
    let object = kdpc(dpc);
    if object.dpc_data.atomic().compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return false;
    }
    object.system_argument1.set(first);
    object.system_argument2.set(second);
    STATE.lock().queue.push_back(dpc);
    true
}

/// KeRemoveQueueDpc.
pub fn remove_queue_dpc(dpc: u64) -> bool {
    let mut state = STATE.lock();
    let Some(index) = state.queue.iter().position(|&queued| queued == dpc) else { return false };
    state.queue.remove(index);
    drop(state);
    kdpc(dpc).dpc_data.set(0);
    true
}

/// Drena a fila. Evita reentrada pelos flags da PCR; retira cada entrada
/// antes do callback e restaura flags e IRQL depois.
pub fn run_queue() -> Result<(), KernelError> {
    if pcr::get_dpc_request_summary() & 0x10001 != 0 || irql::get_irql() > irql::DISPATCH_LEVEL {
        return Ok(());
    }
    loop {
        let Some(dpc) = STATE.lock().queue.pop_front() else { return Ok(()) };
        let object = kdpc(dpc);
        object.dpc_data.set(0);
        let routine = object.deferred_routine.get();
        let context = object.deferred_context.get();
        let first = object.system_argument1.get();
        let second = object.system_argument2.get();
        let previous = irql::raise_irql(irql::DISPATCH_LEVEL);
        let state = pcr::enter_dpc();
        if let Ok(state) = state {
            let kernel_routine = STATE.lock().kernel_routines.get(&dpc).copied();
            match kernel_routine {
                Some(routine) => routine(dpc, context, first, second),
                None => {
                    native_call::call(routine, &[dpc, context, first, second]);
                }
            }
            pcr::leave_dpc(state);
        }
        irql::lower_irql(previous as u64);
        state?;
    }
}

pub fn pending() -> usize {
    STATE.lock().queue.len()
}

/// KeSetImportanceDpc.
pub fn set_importance(dpc: u64, importance: u8) {
    kdpc(dpc).importance.set(importance);
}

/// KeSetTargetProcessorDpc: o byte baixo do número vai para KDPC.Number.
pub fn set_target_processor(dpc: u64, number: u64) {
    kdpc(dpc).number.set((number & 255) as u16);
}

/// KeSetTargetProcessorDpcEx: PROCESSOR_NUMBER { USHORT Group; UCHAR Number;
/// UCHAR Reserved; }; só o grupo 0 e processadores da MADT. Devolve o NTSTATUS.
pub fn set_target_processor_ex(dpc: u64, processor_number: u64) -> u32 {
    // SAFETY: PPROCESSOR_NUMBER do chamador.
    let target = unsafe { ProcessorNumber::at(processor_number) };
    let (group, processor) = (target.group.get(), target.number.get());
    if group != 0 || processor as usize >= smp::discovered_cpu_count() {
        return STATUS_INVALID_PARAMETER;
    }
    kdpc(dpc).number.set(processor as u16);
    STATUS_SUCCESS
}

/// KeQueryDpcWatchdogInformation: sem watchdog de DPC, a estrutura
/// (KDPC_WATCHDOG_INFORMATION, 5 ULONGs) sai zerada.
pub fn query_watchdog_information(information: u64) {
    // SAFETY: PKDPC_WATCHDOG_INFORMATION do chamador.
    let information = unsafe { KdpcWatchdogInformation::at(information) };
    information.dpc_time_limit.set(0);
    information.dpc_time_count.set(0);
    information.dpc_watchdog_limit.set(0);
    information.dpc_watchdog_count.set(0);
    information.reserved.set(0);
}
