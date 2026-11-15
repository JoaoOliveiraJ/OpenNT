//! NtQueryInformationJobObject (rva 0x616ce0) e NtSetInformationJobObject
//! (rva 0x614660), como no ntoskrnl 19041.
//!
//! Consulta: classe fora de 1..47 é STATUS_INVALID_INFO_CLASS; o tamanho é o
//! da PspJobInfoLengths (ExtendedLimit aceita 0x90 e 0x98,
//! ExtendedAccounting 0x1B0, MemoryUsage 0x10 e 0x28, ContainerId 0x10 e
//! 0x24; BasicProcessIdList, SecurityLimit, GroupInformation e as de grupo
//! aceitam a mais), senão STATUS_INFO_LENGTH_MISMATCH; em UserMode o buffer
//! é sondado com o alinhamento da PspJobInfoAlign e o ReturnLength para
//! escrita. O handle é referenciado com JOB_OBJECT_QUERY; sem handle vale o
//! job do processo corrente, e fora de um job só as classes 31 e 39 seguem
//! (as do silo hospedeiro, que respondem STATUS_NOT_SUPPORTED aqui) — as
//! demais são STATUS_ACCESS_DENIED. As classes:
//!
//! - 1, 8 e 19: a contabilidade (PspQueryJobHierarchyAccountingInformation):
//!   o que os processos que saíram somaram ao job mais o dos processos vivos
//!   da hierarquia; contadores de processos do próprio job.
//! - 2 e 9: os limites; LimitFlags filtradas pelas válidas da classe
//!   (PspGetJobLimitInformationValidFlags | 0x7FFF), a afinidade de um grupo
//!   só, os limites de memória e os picos em bytes.
//! - 3: os PIDs dos processos ativos da hierarquia; sem espaço,
//!   STATUS_BUFFER_OVERFLOW com a contagem parcial; ReturnLength é o tamanho
//!   para todos.
//! - 4, 6, 16, 17: a classe de UI, a ação de fim de tempo, o filtro e a
//!   contagem de mensagens da porta; 5 devolve a estrutura zerada; 7 é
//!   STATUS_INVALID_INFO_CLASS; 10 devolve 0; 11 os grupos da afinidade;
//!   15 o controle de CPU (zero sem um); 18 o estado de congelamento; 21 o
//!   de segundo plano; 28 o uso de memória; 29 o commit compartilhado; 30 o
//!   ContainerId (e o de telemetria e o JobId na forma longa).
//!
//! Alteração: tamanho exato (ExtendedLimit 0x90 ou 0x98; GroupInformation e
//! GroupInformationEx a mais), buffer sondado para leitura, handle nulo
//! STATUS_INVALID_HANDLE, acesso JOB_OBJECT_SET_ATTRIBUTES
//! (JOB_OBJECT_SET_SECURITY_ATTRIBUTES para SecurityLimit). As classes:
//!
//! - 2 e 9: flags além das válidas, classe de prioridade acima de 6, classe
//!   de escalonamento acima de 9, limites de tempo nulos, working set
//!   inválido, afinidade vazia ou fora dos processadores ativos e limites de
//!   memória abaixo de uma página são STATUS_INVALID_PARAMETER; prioridade
//!   HIGH/REALTIME e escalonamento acima de 5 pedem
//!   SeIncreaseBasePriorityPrivilege. LimitFlags = (antigas & ~válidas) |
//!   novas (PRESERVE_JOB_TIME preserva o tempo do job); os limites efetivos
//!   da hierarquia e os de cada processo são refeitos. Os limites de tempo,
//!   de working set, de afinidade e de prioridade de base ficam registrados
//!   no job; quem os aplicaria aos processos é o escalonador.
//! - 4: valor acima de 0xFF é STATUS_INVALID_PARAMETER; a hierarquia
//!   precisa permitir restrições de UI (senão STATUS_NOT_SUPPORTED), um job
//!   misto é STATUS_ACCESS_DENIED, o job fica na sessão de quem chama e o
//!   win32k recebe o callout da mudança; UILimits liga.
//! - 5: flags além de 0xF são STATUS_INVALID_PARAMETER, senão
//!   STATUS_NOT_SUPPORTED.
//! - 6: ação acima de 1 é STATUS_INVALID_PARAMETER.
//! - 7: com porta, a IOCP referenciada com IO_COMPLETION_MODIFY_STATE vira a
//!   do job (uma segunda é STATUS_INVALID_PARAMETER, e também um job com
//!   KILL_ON_JOB_CLOSE já fechado); CompletionCount zera e, com o filtro de
//!   NEW_PROCESS, cada processo ativo da hierarquia gera
//!   JOB_OBJECT_MSG_NEW_PROCESS. Sem porta, a associação é desfeita.
//! - 16: bits fora de 0x3FFE são STATUS_INVALID_PARAMETER.
//! - 25: o KEVENT do job volta a não sinalizado.
//! - As demais classes de alteração que o 19041 aceita (controle de CPU, de
//!   rede e de E/S, congelamento, notificações de limite, silos) devolvem
//!   STATUS_NOT_SUPPORTED aqui; as que ele não aceita,
//!   STATUS_INVALID_INFO_CLASS.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::limits::{self, hierarchy, processes_of};
use super::membership::{process_values, ProcessValues};
use super::object::reference_by_handle;
use super::{dereference_job, ejob, eprocess, flags, limit, Outbox, JOBS};
use super::{JOB_OBJECT_QUERY, JOB_OBJECT_SET_ATTRIBUTES, JOB_OBJECT_SET_SECURITY_ATTRIBUTES};
use super::{STATUS_ACCESS_DENIED, STATUS_ACCESS_VIOLATION, STATUS_INFO_LENGTH_MISMATCH, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_SUCCESS};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_jobs::{JobobjectAssociateCompletionPort, JobobjectBasicAccountingInformation, JobobjectExtendedLimitInformation, JobobjectFreezeInformation, JobobjectMemoryUsageInformation, JobobjectSecurityLimitInformation};
use crate::ntos::inc::types::{Ejob, Eprocess};
use crate::ntos::ke::{dispatcher, processor_group};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::{process, user_probe};
use crate::rtl::KernelError;

const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;
/// A maior classe (JobObjectThreadImpersonationInformation).
const MAXIMUM_CLASS: u32 = 47;
/// SeIncreaseBasePriorityPrivilege.
const SE_INC_BASE_PRIORITY_PRIVILEGE: u64 = 14;
/// IO_COMPLETION_MODIFY_STATE.
const IO_COMPLETION_MODIFY_STATE: u32 = 2;
/// O tamanho do registro de contabilidade montado na consulta.
const ACCOUNTING_SIZE: usize = 0x1C0;

/// PspJobInfoLengths: o tamanho de cada classe (1..47).
const LENGTHS: [u32; 47] = [
    0x30, 0x40, 0x10, 0x4, 0x28, 0x4, 0x10, 0x60, 0x90, 0x4, 0x2, 0x0, 0x0, 0x0, 0x8, 0x4, 0x8, 0x10, 0x1B0, 0x0, 0x1, 0x1, 0x1, 0x8, 0x0, 0x8, 0x0, 0x10, 0x8, 0x0, 0x90, 0x10, 0x48, 0x68, 0x0, 0x10, 0x10, 0x20, 0x270, 0x10, 0x4, 0x48, 0x8, 0x10, 0x10, 0x8, 0x1,
];
/// PspJobInfoAlign: o alinhamento do buffer de cada classe (1..47).
const ALIGNMENTS: [u32; 47] = [4, 4, 4, 4, 4, 4, 8, 4, 4, 4, 2, 4, 4, 4, 4, 4, 4, 4, 4, 4, 1, 1, 1, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 0, 4, 4, 4, 4, 4, 4, 4, 8, 4, 0x10, 4, 1];

mod class {
    pub const BASIC_ACCOUNTING: u32 = 1;
    pub const BASIC_LIMIT: u32 = 2;
    pub const BASIC_PROCESS_ID_LIST: u32 = 3;
    pub const BASIC_UI_RESTRICTIONS: u32 = 4;
    pub const SECURITY_LIMIT: u32 = 5;
    pub const END_OF_JOB_TIME: u32 = 6;
    pub const ASSOCIATE_COMPLETION_PORT: u32 = 7;
    pub const BASIC_AND_IO_ACCOUNTING: u32 = 8;
    pub const EXTENDED_LIMIT: u32 = 9;
    pub const JOB_SET: u32 = 10;
    pub const GROUP_INFORMATION: u32 = 11;
    pub const NOTIFICATION_LIMIT: u32 = 12;
    pub const LIMIT_VIOLATION: u32 = 13;
    pub const GROUP_INFORMATION_EX: u32 = 14;
    pub const CPU_RATE_CONTROL: u32 = 15;
    pub const COMPLETION_FILTER: u32 = 16;
    pub const COMPLETION_COUNTER: u32 = 17;
    pub const FREEZE: u32 = 18;
    pub const EXTENDED_ACCOUNTING: u32 = 19;
    pub const WAKE: u32 = 20;
    pub const BACKGROUND: u32 = 21;
    pub const CLEAR_EVENT: u32 = 25;
    pub const MEMORY_USAGE: u32 = 28;
    pub const SHARED_COMMIT: u32 = 29;
    pub const CONTAINER_ID: u32 = 30;
    pub const IO_RATE_CONTROL: u32 = 31;
    pub const SERVER_SILO_USER_SHARED_DATA: u32 = 39;
    pub const MEMORY_PARTITION: u32 = 43;
}

/// Um buffer de saída do chamador: os bytes vão de uma vez, sondados em
/// UserMode.
fn write_out(mode: u8, address: u64, bytes: &[u8]) -> u32 {
    if bytes.is_empty() {
        return STATUS_SUCCESS;
    }
    if mode != 0 {
        return if guest::try_write_bytes(address, bytes).is_ok() { STATUS_SUCCESS } else { STATUS_ACCESS_VIOLATION };
    }
    guest::write_bytes(address, bytes);
    STATUS_SUCCESS
}

/// O ReturnLength (ULONG) do chamador.
fn write_length(mode: u8, address: u64, length: u32) {
    if address == 0 {
        return;
    }
    if mode != 0 {
        let _ = guest::try_write::<u32>(address, length);
    } else {
        guest::write32(address, length);
    }
}

/// Um bloco zerado do kernel para montar uma estrutura.
struct Scratch {
    address: u64,
    size: usize,
}

impl Scratch {
    fn new(size: usize) -> Option<Self> {
        let address = guest::alloc_bytes(size as u64);
        if address == 0 {
            return None;
        }
        guest::write_bytes(address, &alloc::vec![0u8; size]);
        Some(Self { address, size })
    }

    fn view<T: NtStruct>(&self) -> &'static T {
        // SAFETY: bloco do kernel alocado com pelo menos o tamanho do tipo.
        unsafe { T::at(self.address) }
    }

    fn bytes(&self, length: usize) -> Vec<u8> {
        guest::read_bytes(self.address, length.min(self.size))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        guest::free_bytes(self.address);
    }
}

/// O tamanho aceito para a classe na consulta.
fn query_length_valid(class: u32, length: u32) -> bool {
    match class {
        class::EXTENDED_LIMIT => length == 0x90 || length == 0x98,
        class::NOTIFICATION_LIMIT => length == 0x30 || length == 0x38,
        class::LIMIT_VIOLATION => length == 0x50 || length == 0x58,
        class::EXTENDED_ACCOUNTING => length == 0x1B0,
        class::WAKE => length == 0x28 || length == 0x40,
        class::MEMORY_USAGE => length == 0x10 || length == 0x28,
        class::CONTAINER_ID => length == 0x10 || length == 0x24,
        class::MEMORY_PARTITION => length == 1,
        _ => {
            let required = LENGTHS[class as usize - 1];
            length == required || (matches!(class, 3 | 5 | 11 | 14 | 31 | 37) && length >= required)
        }
    }
}

/// A sonda do buffer de modo usuário: alinhamento e faixa.
fn probe_buffer(class: u32, buffer: u64, length: u32, write: bool) -> u32 {
    if length == 0 {
        return STATUS_SUCCESS;
    }
    let alignment = ALIGNMENTS[class as usize - 1].max(1) as u64;
    if buffer & (alignment - 1) != 0 {
        return STATUS_DATATYPE_MISALIGNMENT;
    }
    let valid = if write { user_probe::probe_user_write(buffer, length as u64) } else { user_probe::probe_user_read(buffer, length as u64) };
    if valid { STATUS_SUCCESS } else { STATUS_ACCESS_VIOLATION }
}

/// PspGetJobLimitInformationValidFlags(Class, Length).
fn valid_limit_flags(class: u32, length: u32) -> u32 {
    if class == class::BASIC_LIMIT {
        0xFF
    } else if length == 0x90 {
        0x7FFF
    } else {
        0x0060_7FFF
    }
}

/// A soma dos valores dos processos vivos (sem a contabilidade dobrada) da
/// hierarquia, com a [`JOBS`].
fn live_values(job: u64) -> ProcessValues {
    let mut total = ProcessValues::default();
    for member in hierarchy(job) {
        for process in processes_of(member) {
            if eprocess(process).flags2.get() & Eprocess::ACCOUNTING_FOLDED_MASK != 0 {
                continue;
            }
            let values = process_values(process);
            total.kernel_time = total.kernel_time.wrapping_add(values.kernel_time);
            total.user_time = total.user_time.wrapping_add(values.user_time);
            total.context_switches = total.context_switches.wrapping_add(values.context_switches);
            for (sum, value) in total.io.iter_mut().zip(values.io) {
                *sum = sum.wrapping_add(value);
            }
            total.page_faults = total.page_faults.wrapping_add(values.page_faults);
        }
    }
    total
}

/// PspQueryJobHierarchyAccountingInformation: o registro de 0x1C0 bytes.
fn accounting(job: &Ejob, scratch: &Scratch) {
    let _guard = JOBS.lock();
    let live = live_values(job.address());
    let basic = scratch.view::<JobobjectBasicAccountingInformation>();
    let sum = |base: i64, value: u64| base.wrapping_add(value as i64);
    basic.total_user_time.quad_part.set(sum(job.total_user_time.quad_part.get(), live.user_time));
    basic.this_period_total_user_time.quad_part.set(sum(job.this_period_total_user_time.quad_part.get(), live.user_time));
    basic.total_kernel_time.quad_part.set(sum(job.total_kernel_time.quad_part.get(), live.kernel_time));
    basic.this_period_total_kernel_time.quad_part.set(sum(job.this_period_total_kernel_time.quad_part.get(), live.kernel_time));
    basic.total_page_fault_count.set(job.total_page_fault_count.get().wrapping_add(live.page_faults));
    basic.total_processes.set(job.total_processes.get());
    basic.active_processes.set(job.active_processes.get());
    basic.total_terminated_processes.set(job.total_terminated_processes.get());
    let counters = [&job.read_operation_count, &job.write_operation_count, &job.other_operation_count, &job.read_transfer_count, &job.write_transfer_count, &job.other_transfer_count];
    for (index, (cell, value)) in counters.iter().zip(live.io).enumerate() {
        guest::write64(scratch.address + 0x30 + index as u64 * 8, cell.get().wrapping_add(value));
    }
    let disk = guest::read_bytes(job.disk_io_info.address(), 0x28);
    guest::write_bytes(scratch.address + 0x60, &disk);
    guest::write64(scratch.address + 0x88, job.total_context_switches.get().wrapping_add(live.context_switches));
    guest::write64(scratch.address + 0x90, job.total_cycle_time.quad_part.get() as u64);
    guest::write64(scratch.address + 0x98, job.ready_time.get());
    guest::write64(scratch.address + 0x1B0, job.kernel_wait_time.get());
    guest::write64(scratch.address + 0x1B8, job.user_wait_time.get());
}

/// A máscara de um grupo só da afinidade (KeIsSingleGroupAffinityEx), ou 0.
fn single_group_affinity(job: &Ejob) -> u64 {
    let count = (job.affinity.count.get() as usize).min(job.affinity.bitmap.len());
    let groups: Vec<u64> = job.affinity.bitmap[..count].iter().map(|group| group.get()).filter(|&mask| mask != 0).collect();
    if groups.len() == 1 { groups[0] } else { 0 }
}

/// Os limites (classes 2 e 9).
fn limit_information(job: &Ejob, class: u32, length: u32, scratch: &Scratch) {
    let _guard = JOBS.lock();
    let information = scratch.view::<JobobjectExtendedLimitInformation>();
    let basic = &information.basic_limit_information;
    basic.per_process_user_time_limit.quad_part.set(job.per_process_user_time_limit.quad_part.get());
    basic.per_job_user_time_limit.quad_part.set(job.per_job_user_time_limit.quad_part.get());
    basic.limit_flags.set(job.limit_flags.get() & (valid_limit_flags(class, length) | 0x7FFF));
    basic.minimum_working_set_size.set(job.minimum_working_set_size.get());
    basic.maximum_working_set_size.set(job.maximum_working_set_size.get());
    basic.active_process_limit.set(job.active_process_limit.get());
    basic.affinity.set(single_group_affinity(job));
    basic.priority_class.set(job.priority_class.get() as u32);
    basic.scheduling_class.set(job.scheduling_class.get());
    if class == class::EXTENDED_LIMIT {
        information.process_memory_limit.set(job.process_memory_limit.get() << 12);
        information.job_memory_limit.set(job.job_memory_limit.get() << 12);
        information.peak_process_memory_used.set(job.peak_process_memory_used.get() << 12);
        information.peak_job_memory_used.set(job.peak_job_memory_used.get() << 12);
        information.job_total_memory_limit.set(job.job_total_memory_limit.get() << 12);
    }
}

/// PspQueryJobHierarchyProcessIdList: (status, bytes, ReturnLength).
fn process_id_list(job: &Ejob, length: u32) -> (u32, Vec<u8>, u32) {
    let _guard = JOBS.lock();
    let mut identifiers = Vec::new();
    let mut remaining = length.saturating_sub(8);
    let mut status = STATUS_SUCCESS;
    'walk: for member in hierarchy(job.address()) {
        for process in processes_of(member) {
            let target = eprocess(process);
            if target.flags2.get() & Eprocess::JOB_NOT_REALLY_ACTIVE_MASK != 0 {
                continue;
            }
            if remaining < 8 {
                status = STATUS_BUFFER_OVERFLOW;
                break 'walk;
            }
            identifiers.push(target.unique_process_id.get());
            remaining -= 8;
        }
    }
    let active = job.active_processes.get();
    let mut bytes = Vec::with_capacity(8 + identifiers.len() * 8);
    bytes.extend_from_slice(&active.to_le_bytes());
    bytes.extend_from_slice(&(identifiers.len() as u32).to_le_bytes());
    for identifier in identifiers {
        bytes.extend_from_slice(&identifier.to_le_bytes());
    }
    (status, bytes, active.wrapping_mul(8).wrapping_add(8))
}

/// O corpo da consulta com o job referenciado: (status, bytes a copiar,
/// ReturnLength).
fn query_job(job: &Ejob, class: u32, length: u32) -> (u32, Vec<u8>, u32) {
    let full = |bytes: Vec<u8>| (STATUS_SUCCESS, bytes, length);
    let Some(scratch) = Scratch::new(ACCOUNTING_SIZE) else { return (STATUS_INSUFFICIENT_RESOURCES, Vec::new(), length) };
    match class {
        class::BASIC_ACCOUNTING | class::BASIC_AND_IO_ACCOUNTING | class::EXTENDED_ACCOUNTING => {
            accounting(job, &scratch);
            full(scratch.bytes(length as usize))
        }
        class::BASIC_LIMIT | class::EXTENDED_LIMIT => {
            limit_information(job, class, length, &scratch);
            full(scratch.bytes(length as usize))
        }
        class::BASIC_PROCESS_ID_LIST => process_id_list(job, length),
        class::BASIC_UI_RESTRICTIONS => full(job.ui_restrictions_class.get().to_le_bytes().to_vec()),
        class::SECURITY_LIMIT => (STATUS_SUCCESS, alloc::vec![0u8; JobobjectSecurityLimitInformation::SIZE as usize], length),
        class::END_OF_JOB_TIME => full(job.end_of_job_time_action.get().to_le_bytes().to_vec()),
        class::JOB_SET => full(0u32.to_le_bytes().to_vec()),
        class::GROUP_INFORMATION => {
            let _guard = JOBS.lock();
            let count = (job.affinity.count.get() as usize).min(job.affinity.bitmap.len());
            let groups: Vec<u8> = (0..count).filter(|&group| job.affinity.bitmap[group].get() != 0).flat_map(|group| (group as u16).to_le_bytes()).collect();
            let needed = groups.len() as u32;
            let status = if length < needed { STATUS_BUFFER_TOO_SMALL } else { STATUS_SUCCESS };
            let copied = groups[..(needed.min(length) as usize)].to_vec();
            (status, copied, needed)
        }
        class::CPU_RATE_CONTROL => full(alloc::vec![0u8; 8]),
        class::COMPLETION_FILTER => full(job.completion_filter.get().to_le_bytes().to_vec()),
        class::COMPLETION_COUNTER => full(job.completion_count.get().to_le_bytes().to_vec()),
        class::FREEZE => {
            let freeze = scratch.view::<JobobjectFreezeInformation>();
            let _guard = JOBS.lock();
            let job_flags = job.job_flags.get();
            freeze.flags.set(7);
            freeze.freeze.set(((job_flags >> 9) & 1) as u8);
            freeze.swap.set(((job_flags >> 19) & 1) as u8);
            freeze.wake_filter.set(guest::read64(job.wake_filter.address()));
            full(scratch.bytes(JobobjectFreezeInformation::SIZE as usize))
        }
        class::BACKGROUND => full(alloc::vec![((job.job_flags.get() >> 10) & 1) as u8]),
        class::MEMORY_USAGE => {
            let usage = scratch.view::<JobobjectMemoryUsageInformation>();
            let _guard = JOBS.lock();
            usage.job_memory.set(job.current_job_memory_used.get() << 12);
            usage.peak_job_memory_used.set(job.peak_job_memory_used.get() << 12);
            usage.job_shared_memory.set(job.shared_commit_charge.get() << 12);
            full(scratch.bytes(length as usize))
        }
        class::SHARED_COMMIT => full(job.shared_commit_charge.get().to_le_bytes().to_vec()),
        class::CONTAINER_ID => {
            let mut bytes = guest::read_bytes(job.container_id.address(), 16);
            if length == 0x24 {
                bytes.extend_from_slice(&guest::read_bytes(job.container_telemetry_id.address(), 16));
                bytes.extend_from_slice(&job.job_id.get().to_le_bytes());
            }
            full(bytes)
        }
        class::ASSOCIATE_COMPLETION_PORT => (STATUS_INVALID_INFO_CLASS, Vec::new(), length),
        _ => (STATUS_NOT_SUPPORTED, Vec::new(), length),
    }
}

/// NtQueryInformationJobObject(JobHandle, Class, Information, Length,
/// ReturnLength) no modo `mode`. Devolve o NTSTATUS.
pub fn query(handle: u64, class: u32, buffer: u64, length: u32, return_length: u64, mode: u8) -> Result<u32, KernelError> {
    if class.wrapping_sub(1) >= MAXIMUM_CLASS {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if !query_length_valid(class, length) {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    if mode != 0 {
        let status = probe_buffer(class, buffer, length, true);
        if status != STATUS_SUCCESS {
            return Ok(status);
        }
        if return_length != 0 && !user_probe::probe_user_write(return_length, 4) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let job = if handle != 0 {
        match reference_by_handle(handle, JOB_OBJECT_QUERY, mode) {
            Ok(job) => job,
            Err(status) => return Ok(status),
        }
    } else {
        let job = eprocess(process::get_current_process()).job.get();
        if job == 0 {
            // As classes do silo hospedeiro, que o NT responde sem job.
            return Ok(if matches!(class, class::IO_RATE_CONTROL | class::SERVER_SILO_USER_SHARED_DATA) { STATUS_NOT_SUPPORTED } else { STATUS_ACCESS_DENIED });
        }
        super::reference_job(job);
        job
    };
    let (status, bytes, returned) = query_job(ejob(job), class, length);
    dereference_job(job);
    let mut status = status;
    let copy_now = status & 0x8000_0000 == 0 || (class == class::BASIC_PROCESS_ID_LIST && status == STATUS_BUFFER_OVERFLOW) || (class == class::GROUP_INFORMATION && status == STATUS_BUFFER_TOO_SMALL);
    if copy_now {
        let copied = write_out(mode, buffer, &bytes);
        if copied != STATUS_SUCCESS {
            status = copied;
        }
    }
    write_length(mode, return_length, returned);
    Ok(status)
}

/// O tamanho aceito para a classe na alteração.
fn set_length_valid(class: u32, length: u32) -> bool {
    match class {
        class::EXTENDED_LIMIT => length == 0x90 || length == 0x98,
        class::NOTIFICATION_LIMIT => length == 0x30 || length == 0x38,
        class::IO_RATE_CONTROL => length >= LENGTHS[class as usize - 1],
        _ => {
            let required = LENGTHS[class as usize - 1];
            length == required || (matches!(class, class::GROUP_INFORMATION | class::GROUP_INFORMATION_EX) && length >= required)
        }
    }
}

/// O working set pedido (as recusas do NtSetInformationJobObject).
fn working_set_valid(minimum: u64, maximum: u64) -> bool {
    !((minimum == 0 && maximum == 0) || (minimum == u64::MAX && maximum == u64::MAX) || minimum > maximum || minimum < 0x14000)
}

/// Os limites (classes 2 e 9), com o bloco do chamador já copiado.
fn set_limits(job: u64, class: u32, length: u32, input: &Scratch, mode: u8) -> u32 {
    let information = input.view::<JobobjectExtendedLimitInformation>();
    let basic = &information.basic_limit_information;
    let valid = valid_limit_flags(class, length);
    let mut requested = basic.limit_flags.get();
    if requested & !valid != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let active_limit = if requested & limit::ACTIVE_PROCESS != 0 { basic.active_process_limit.get() } else { 0 };
    let mut priority = 0u8;
    if requested & limit::PRIORITY_CLASS != 0 {
        let value = basic.priority_class.get();
        if value > 6 {
            return STATUS_INVALID_PARAMETER;
        }
        if (3..=4).contains(&value) && !crate::ntos::se::privilege::single_privilege_check(SE_INC_BASE_PRIORITY_PRIVILEGE, mode as u32) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        priority = value as u8;
    }
    let mut scheduling = 5;
    if requested & limit::SCHEDULING_CLASS != 0 {
        let value = basic.scheduling_class.get();
        if value >= 10 {
            return STATUS_INVALID_PARAMETER;
        }
        if value > 5 && !crate::ntos::se::privilege::single_privilege_check(SE_INC_BASE_PRIORITY_PRIVILEGE, mode as u32) {
            return STATUS_PRIVILEGE_NOT_HELD;
        }
        scheduling = value;
    }
    let process_time = if requested & limit::PROCESS_TIME != 0 {
        match basic.per_process_user_time_limit.quad_part.get() {
            0 => return STATUS_INVALID_PARAMETER,
            value => value,
        }
    } else {
        0
    };
    let mut job_time = if requested & limit::JOB_TIME != 0 {
        match basic.per_job_user_time_limit.quad_part.get() {
            0 => return STATUS_INVALID_PARAMETER,
            value => value,
        }
    } else {
        0
    };
    let (minimum, maximum) = if requested & limit::WORKINGSET != 0 {
        let (minimum, maximum) = (basic.minimum_working_set_size.get(), basic.maximum_working_set_size.get());
        if !working_set_valid(minimum, maximum) {
            return STATUS_INVALID_PARAMETER;
        }
        (minimum, maximum)
    } else {
        (0, 0)
    };
    let pages = |bytes: u64| if bytes < 0x1000 { None } else { Some(bytes >> 12) };
    let process_memory = if requested & limit::PROCESS_MEMORY != 0 {
        match pages(information.process_memory_limit.get()) {
            Some(value) => value,
            None => return STATUS_INVALID_PARAMETER,
        }
    } else {
        0
    };
    let job_memory = if requested & limit::JOB_MEMORY != 0 {
        match pages(information.job_memory_limit.get()) {
            Some(value) => value,
            None => return STATUS_INVALID_PARAMETER,
        }
    } else {
        0
    };
    let total_memory = if requested & limit::JOB_TOTAL_MEMORY != 0 {
        match pages(information.job_total_memory_limit.get()) {
            Some(value) => value,
            None => return STATUS_INVALID_PARAMETER,
        }
    } else {
        0
    };
    let body = ejob(job);
    let affinity = if requested & limit::AFFINITY != 0 {
        let mask = basic.affinity.get();
        if body.job_flags.get() & (1 << 1) != 0 || mask == 0 || mask & !processor_group::active_mask() != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        Some(mask)
    } else {
        None
    };
    {
        let _guard = JOBS.lock();
        let old = body.limit_flags.get();
        if requested & limit::JOB_TIME == 0 {
            if requested & limit::PRESERVE_JOB_TIME != 0 {
                requested |= old & limit::JOB_TIME;
                job_time = body.per_job_user_time_limit.quad_part.get();
            } else {
                job_time = 0;
            }
        }
        requested &= !limit::PRESERVE_JOB_TIME;
        if requested & limit::SUBSET_AFFINITY != 0 && body.job_flags.get() & (1 << 1) == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        body.minimum_working_set_size.set(minimum);
        body.maximum_working_set_size.set(maximum);
        body.active_process_limit.set(active_limit);
        if let Some(mask) = affinity {
            guest::write_bytes(body.affinity.address() + 8, &[0u8; 0xA0]);
            body.affinity.count.set(1);
            body.affinity.size.set(0x14);
            body.affinity.bitmap[0].set(mask);
        }
        body.priority_class.set(priority);
        body.scheduling_class.set(scheduling);
        body.per_process_user_time_limit.quad_part.set(process_time);
        body.per_job_user_time_limit.quad_part.set(job_time);
        body.limit_flags.set((old & !valid) | requested);
        if class == class::EXTENDED_LIMIT {
            body.process_memory_limit.set(process_memory);
            body.job_memory_limit.set(job_memory);
            body.job_total_memory_limit.set(total_memory);
        }
        if basic.limit_flags.get() & limit::JOB_TIME != 0 {
            body.this_period_total_user_time.quad_part.set(0);
            body.this_period_total_kernel_time.quad_part.set(0);
        }
        limits::refresh_hierarchy(job);
    }
    if basic.limit_flags.get() & limit::JOB_TIME != 0 {
        dispatcher::reset_event(body.event.address());
    }
    STATUS_SUCCESS
}

/// A classe de restrições de UI (4).
fn set_ui_restrictions(job: u64, value: u32) -> u32 {
    if value & !0xFF != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let body = ejob(job);
    let callout = {
        let _guard = JOBS.lock();
        let mut walk = body.parent_job.get();
        while walk != 0 {
            if ejob(walk).job_flags.get() & flags::UI_LIMITS != 0 {
                return STATUS_NOT_SUPPORTED;
            }
            walk = ejob(walk).parent_job.get();
        }
        if body.session_id.get() == 0xFFFF_FFFE {
            return STATUS_ACCESS_DENIED;
        }
        let session = crate::ntos::mm::session::session_id(process::get_current_process());
        if body.session_id.get() == u32::MAX {
            body.session_id.set(session);
        }
        body.session_id.get() <= 0xFFFF_FFFD && body.ui_restrictions_class.get() != value
    };
    if callout {
        let status = super::membership::job_set_information_callout(body, value);
        if status & 0x8000_0000 != 0 {
            return status;
        }
    }
    let _guard = JOBS.lock();
    body.ui_restrictions_class.set(value);
    body.job_flags.atomic().fetch_or(flags::UI_LIMITS, Ordering::SeqCst);
    STATUS_SUCCESS
}

/// A associação com a porta de conclusão (7).
fn set_completion_port(job: u64, key: u64, port_handle: u64) -> u32 {
    let body = ejob(job);
    if port_handle == 0 {
        let port = {
            let _guard = JOBS.lock();
            let port = body.completion_port.get();
            body.completion_port.set(0);
            port
        };
        if port != 0 {
            let _ = crate::ntos::ob::objects::dispatcher::dereference(port);
        }
        return STATUS_SUCCESS;
    }
    let port = match crate::ntos::io::completion::set::reference_port(port_handle, IO_COMPLETION_MODIFY_STATE) {
        Ok(port) => port,
        Err(status) => return status,
    };
    let mut outbox = Outbox::default();
    let status = {
        let _guard = JOBS.lock();
        let closed = body.limit_flags.get() & limit::KILL_ON_JOB_CLOSE != 0 && body.job_flags.get() & flags::CLOSE_DONE != 0;
        if body.completion_port.get() != 0 || closed {
            STATUS_INVALID_PARAMETER
        } else {
            body.completion_key.set(key);
            body.completion_port.set(port);
            body.completion_count.set(0);
            if body.completion_filter.get() & (1 << super::message::NEW_PROCESS) != 0 {
                // PspAssociateCompletionPortCallback: um NEW_PROCESS por
                // processo ativo já no job.
                for member in hierarchy(job) {
                    for process in processes_of(member) {
                        let target = eprocess(process);
                        if target.flags2.get() & Eprocess::JOB_NOT_REALLY_ACTIVE_MASK != 0 {
                            continue;
                        }
                        limits::set_clear_flags2(target, Eprocess::NEW_PROCESS_REPORTED_MASK, Eprocess::LAST_REPORT_MEMORY_MASK);
                        outbox.notify(body, super::message::NEW_PROCESS, target.unique_process_id.get(), false);
                    }
                }
            }
            STATUS_SUCCESS
        }
    };
    if status != STATUS_SUCCESS {
        let _ = crate::ntos::ob::objects::dispatcher::dereference(port);
    }
    outbox.deliver();
    status
}

/// NtSetInformationJobObject(JobHandle, Class, Information, Length) no modo
/// `mode`. Devolve o NTSTATUS.
pub fn set(handle: u64, class: u32, buffer: u64, length: u32, mode: u8) -> Result<u32, KernelError> {
    if class.wrapping_sub(1) >= MAXIMUM_CLASS {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if !set_length_valid(class, length) {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    if mode != 0 {
        let status = probe_buffer(class, buffer, length, false);
        if status != STATUS_SUCCESS {
            return Ok(status);
        }
    }
    if handle == 0 {
        return Ok(STATUS_INVALID_HANDLE);
    }
    let access = if class == class::SECURITY_LIMIT { JOB_OBJECT_SET_SECURITY_ATTRIBUTES } else { JOB_OBJECT_SET_ATTRIBUTES };
    let job = match reference_by_handle(handle, access, mode) {
        Ok(job) => job,
        Err(status) => return Ok(status),
    };
    // A cópia do bloco do chamador (o __try do NT).
    let copy = |size: usize| -> Result<Scratch, u32> {
        let scratch = Scratch::new(size.max(length as usize)).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let bytes = if mode != 0 { guest::try_read_bytes(buffer, length as usize).map_err(|_| STATUS_ACCESS_VIOLATION)? } else { guest::read_bytes(buffer, length as usize) };
        guest::write_bytes(scratch.address, &bytes);
        Ok(scratch)
    };
    let status = match class {
        class::BASIC_LIMIT | class::EXTENDED_LIMIT => match copy(JobobjectExtendedLimitInformation::SIZE as usize) {
            Ok(input) => set_limits(job, class, length, &input, mode),
            Err(status) => status,
        },
        class::BASIC_UI_RESTRICTIONS | class::END_OF_JOB_TIME | class::COMPLETION_FILTER => match copy(4) {
            Ok(input) => {
                let value = guest::read32(input.address);
                match class {
                    class::BASIC_UI_RESTRICTIONS => set_ui_restrictions(job, value),
                    class::END_OF_JOB_TIME if value > 1 => STATUS_INVALID_PARAMETER,
                    class::END_OF_JOB_TIME => {
                        let _guard = JOBS.lock();
                        ejob(job).end_of_job_time_action.set(value);
                        STATUS_SUCCESS
                    }
                    _ if value & 0xFFFF_C001 != 0 => STATUS_INVALID_PARAMETER,
                    _ => {
                        let _guard = JOBS.lock();
                        ejob(job).completion_filter.set(value);
                        STATUS_SUCCESS
                    }
                }
            }
            Err(status) => status,
        },
        class::SECURITY_LIMIT => match copy(JobobjectSecurityLimitInformation::SIZE as usize) {
            Ok(input) => {
                if input.view::<JobobjectSecurityLimitInformation>().security_limit_flags.get() & !0xF != 0 {
                    STATUS_INVALID_PARAMETER
                } else {
                    STATUS_NOT_SUPPORTED
                }
            }
            Err(status) => status,
        },
        class::ASSOCIATE_COMPLETION_PORT => match copy(JobobjectAssociateCompletionPort::SIZE as usize) {
            Ok(input) => {
                let association = input.view::<JobobjectAssociateCompletionPort>();
                set_completion_port(job, association.completion_key.get(), association.completion_port.get())
            }
            Err(status) => status,
        },
        class::CLEAR_EVENT => {
            dispatcher::reset_event(ejob(job).event.address());
            STATUS_SUCCESS
        }
        // As classes só de consulta.
        class::BASIC_ACCOUNTING | class::BASIC_PROCESS_ID_LIST | class::BASIC_AND_IO_ACCOUNTING | class::JOB_SET | class::COMPLETION_COUNTER | class::EXTENDED_ACCOUNTING | class::MEMORY_USAGE | class::CONTAINER_ID => STATUS_INVALID_INFO_CLASS,
        _ => STATUS_NOT_SUPPORTED,
    };
    dereference_job(job);
    Ok(status)
}
