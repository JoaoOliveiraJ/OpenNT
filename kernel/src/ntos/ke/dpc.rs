//! Fila de chamadas diferidas drenada em DISPATCH_LEVEL — `system32/ntos/ke/dpc.js`.
//!
//! Descritores e argumentos conservam seus endereços de 64 bits até a
//! chamada nativa.

use alloc::collections::{BTreeMap, VecDeque};

use super::{irql, pcr, smp};
use crate::hal::amd64::native_call;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kdpc;
use crate::ntos::inc::status::{STATUS_INVALID_PARAMETER, STATUS_SUCCESS};

/// Rotina interna do kernel (ex.: adaptador de EX_TIMER) para um KDPC.
pub type KernelDpcRoutine = fn(u64, u64, u64, u64);

struct DpcState {
    queue: VecDeque<u64>,
    kernel_routines: BTreeMap<u64, KernelDpcRoutine>,
}

static STATE: SpinLock<DpcState> = SpinLock::new(DpcState { queue: VecDeque::new(), kernel_routines: BTreeMap::new() });

fn read_field(dpc: u64, offset: u64) -> u64 {
    guest::read64(dpc + offset)
}

fn write_field(dpc: u64, offset: u64, value: u64) {
    guest::write64(dpc + offset, value);
}

/// KeInitializeDpc: preenche o KDPC sem truncar rotina nem contexto.
pub fn initialize_dpc(dpc: u64, routine: u64, context: u64) {
    STATE.lock().kernel_routines.remove(&dpc);
    guest::write8(dpc + kdpc::TYPE, kdpc::TYPE_DPC);
    guest::write8(dpc + kdpc::IMPORTANCE, kdpc::IMPORTANCE_MEDIUM);
    guest::write16(dpc + kdpc::NUMBER, 0);
    write_field(dpc, kdpc::DPC_LIST_ENTRY, 0);
    write_field(dpc, kdpc::PROCESSOR_HISTORY, 0);
    write_field(dpc, kdpc::ROUTINE, routine);
    write_field(dpc, kdpc::CONTEXT, context);
    write_field(dpc, kdpc::SYSARG1, 0);
    write_field(dpc, kdpc::SYSARG2, 0);
    // Não enfileirado; a marca é retirada antes de chamar a rotina.
    write_field(dpc, kdpc::DPC_DATA, 0);
}

/// Rotina interna associada ao mesmo descritor, sem expor um endereço nativo.
pub fn initialize_kernel_dpc(dpc: u64, routine: KernelDpcRoutine, context: u64) {
    initialize_dpc(dpc, 0, context);
    STATE.lock().kernel_routines.insert(dpc, routine);
}

/// KeInsertQueueDpc: recusa dupla inserção.
pub fn insert_queue_dpc(dpc: u64, first: u64, second: u64) -> bool {
    if read_field(dpc, kdpc::DPC_DATA) != 0 {
        return false;
    }
    write_field(dpc, kdpc::SYSARG1, first);
    write_field(dpc, kdpc::SYSARG2, second);
    write_field(dpc, kdpc::DPC_DATA, 1);
    STATE.lock().queue.push_back(dpc);
    true
}

/// KeRemoveQueueDpc.
pub fn remove_queue_dpc(dpc: u64) -> bool {
    let mut state = STATE.lock();
    let Some(index) = state.queue.iter().position(|&queued| queued == dpc) else { return false };
    state.queue.remove(index);
    drop(state);
    write_field(dpc, kdpc::DPC_DATA, 0);
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
        write_field(dpc, kdpc::DPC_DATA, 0);
        let routine = read_field(dpc, kdpc::ROUTINE);
        let context = read_field(dpc, kdpc::CONTEXT);
        let first = read_field(dpc, kdpc::SYSARG1);
        let second = read_field(dpc, kdpc::SYSARG2);
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
    guest::write8(dpc + kdpc::IMPORTANCE, importance);
}

/// KeSetTargetProcessorDpc: o byte baixo do número vai para KDPC.Number.
pub fn set_target_processor(dpc: u64, number: u64) {
    guest::write16(dpc + kdpc::NUMBER, (number & 255) as u16);
}

/// KeSetTargetProcessorDpcEx: PROCESSOR_NUMBER { USHORT Group; UCHAR Number;
/// UCHAR Reserved; }; só o grupo 0 e processadores da MADT. Devolve o NTSTATUS.
pub fn set_target_processor_ex(dpc: u64, processor_number: u64) -> u32 {
    let (group, processor) = (guest::read16(processor_number), guest::read8(processor_number + 2));
    if group != 0 || processor as usize >= smp::discovered_cpu_count() {
        return STATUS_INVALID_PARAMETER;
    }
    guest::write16(dpc + kdpc::NUMBER, processor as u16);
    STATUS_SUCCESS
}

/// KeQueryDpcWatchdogInformation: sem watchdog de DPC, a estrutura sai zerada.
pub fn query_watchdog_information(information: u64) {
    for offset in (0..0x50).step_by(4) {
        guest::write32(information + offset, 0);
    }
}
