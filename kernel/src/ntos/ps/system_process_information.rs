//! SYSTEM_PROCESS_INFORMATION + SYSTEM_THREAD_INFORMATION x64 nativos.
//!
//! Os registros vêm do PsActiveProcessHead e do registro de threads do
//! kernel; os nomes vão em UTF-16 e os ponteiros são relocados para o buffer
//! do chamador; o dimensionamento nunca publica uma lista parcial. A amostra
//! de memória e de handles do processo de usuário corrente vem do estado de
//! modo usuário (provedor instalado pela fase 7); sem ele os contadores de
//! memória ficam zerados, como o original faz para os demais processos.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use super::pool_quota::{self, QuotaSnapshot};
use super::{process, scheduler, session, user_probe};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::kthread;

/// Amostra do processo de usuário corrente.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserSample {
    pub current_process_id: u64,
    pub user_handles: u32,
    pub virtual_bytes: u64,
    pub resident: u64,
    pub private_bytes: u64,
}

static USER_STATE: SpinLock<Option<fn() -> UserSample>> = SpinLock::new(None);
/// Picos de memória por processo de usuário.
static MEMORY_PEAKS: SpinLock<BTreeMap<u64, (u64, u64)>> = SpinLock::new(BTreeMap::new());

pub fn set_user_state(provider: fn() -> UserSample) {
    *USER_STATE.lock() = Some(provider);
}

/// Some do mapa de picos quando o processo termina.
pub fn release_process(pid: u64) {
    MEMORY_PEAKS.lock().remove(&pid);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Memory {
    pub virtual_bytes: u64,
    pub resident: u64,
    pub private_bytes: u64,
    pub peak_virtual: u64,
    pub peak_resident: u64,
}

/// Registra o pico antes que as regiões de uma thread sejam liberadas.
pub fn sample() {
    let _ = sample_memory();
}

fn sample_memory() -> Option<(UserSample, Memory)> {
    let provider = (*USER_STATE.lock())?;
    let sample = provider();
    let mut peaks = MEMORY_PEAKS.lock();
    let old = peaks.get(&sample.current_process_id).copied().unwrap_or((0, 0));
    let peak = (old.0.max(sample.virtual_bytes), old.1.max(sample.resident));
    peaks.insert(sample.current_process_id, peak);
    Some((sample, Memory { virtual_bytes: sample.virtual_bytes, resident: sample.resident, private_bytes: sample.private_bytes, peak_virtual: peak.0, peak_resident: peak.1 }))
}

#[derive(Clone, Debug)]
pub struct ThreadRecord {
    pub kernel_time: u64,
    pub user_time: u64,
    pub create_time: u64,
    pub start: u64,
    pub id: u64,
    pub priority: u32,
    pub base_priority: u32,
    pub context_switches: u32,
    pub state: u32,
    pub wait_reason: u32,
}

#[derive(Clone, Debug)]
pub struct ProcessRecord {
    pub pid: u64,
    pub parent_id: u64,
    pub name: String,
    pub create_time: u64,
    pub user_time: u64,
    pub kernel_time: u64,
    pub peak_threads: u32,
    pub session_id: u32,
    pub handles: u32,
    pub pool_quota: [QuotaSnapshot; 2],
    pub memory: Memory,
    pub threads: Vec<ThreadRecord>,
    pub size: u64,
}

fn align(value: u64) -> u64 {
    value.div_ceil(8) * 8
}

pub fn snapshot() -> Result<Vec<ProcessRecord>, KernelError> {
    let user = sample_memory();
    let current = process::get_current_thread();
    let scheduled = scheduler::list();
    let mut records = Vec::new();
    for active in process::list_active_processes() {
        let name: String = active.name.rsplit(['\\', '/']).next().unwrap_or("").chars().take(32766).collect();
        let mut threads = Vec::new();
        for &pointer in &active.threads {
            let Some(record) = process::thread_record(pointer) else { continue };
            let waiting = record.runtime.is_some_and(|pid| scheduled.iter().any(|entry| entry.pid == pid && entry.state == scheduler::ProcessState::Waiting));
            threads.push(ThreadRecord {
                kernel_time: record.kernel_time,
                user_time: record.user_time,
                create_time: record.create_time,
                start: record.start,
                id: record.id,
                priority: guest::read8(pointer + kthread::PRIORITY) as u32,
                base_priority: guest::read8(pointer + kthread::BASE_PRIORITY) as u32,
                context_switches: record.context_switches,
                state: if pointer == current { 2 } else if waiting { 5 } else { 1 },
                wait_reason: 0,
            });
        }
        let (parent_id, create_time, user_time, kernel_time, peak_threads) = process::with_record(active.address, |record| (record.parent_id, record.create_time, record.user_time, record.kernel_time, record.peak_threads)).unwrap_or_default();
        let is_current_user = user.as_ref().is_some_and(|(sample, _)| sample.current_process_id == active.pid);
        let size = align(256 + threads.len() as u64 * 80 + (name.encode_utf16().count() as u64 + 1) * 2);
        records.push(ProcessRecord {
            pid: active.pid,
            parent_id,
            name,
            create_time,
            user_time,
            kernel_time,
            peak_threads,
            session_id: session::query(active.address),
            handles: if is_current_user { user.map_or(0, |(sample, _)| sample.user_handles) } else { 0 },
            pool_quota: pool_quota::snapshot(active.address)?,
            memory: if is_current_user { user.map(|(_, memory)| memory).unwrap_or_default() } else { Memory::default() },
            threads,
            size,
        });
    }
    Ok(records)
}

pub fn encode(records: &[ProcessRecord], base: u64) -> Vec<u8> {
    let total: u64 = records.iter().map(|record| record.size).sum();
    let mut bytes = alloc::vec![0u8; total as usize];
    let mut put = |at: u64, value: &[u8]| bytes[at as usize..at as usize + value.len()].copy_from_slice(value);
    let mut at = 0u64;
    for (index, record) in records.iter().enumerate() {
        let name_at = at + 256 + record.threads.len() as u64 * 80;
        let units: Vec<u16> = record.name.encode_utf16().collect();
        let next = if index + 1 == records.len() { 0 } else { record.size as u32 };
        put(at, &next.to_le_bytes());
        put(at + 4, &(record.threads.len() as u32).to_le_bytes());
        put(at + 20, &record.peak_threads.to_le_bytes());
        put(at + 32, &record.create_time.to_le_bytes());
        put(at + 40, &record.user_time.to_le_bytes());
        put(at + 48, &record.kernel_time.to_le_bytes());
        put(at + 56, &(units.len() as u16 * 2).to_le_bytes());
        put(at + 58, &((units.len() as u16 + 1) * 2).to_le_bytes());
        // O nome fica no buffer do chamador; a base conserva os 64 bits.
        put(at + 64, &base.wrapping_add(name_at).to_le_bytes());
        put(at + 72, &8u32.to_le_bytes());
        put(at + 80, &record.pid.to_le_bytes());
        put(at + 88, &record.parent_id.to_le_bytes());
        put(at + 96, &record.handles.to_le_bytes());
        put(at + 100, &record.session_id.to_le_bytes());
        put(at + 112, &record.memory.peak_virtual.to_le_bytes());
        put(at + 120, &record.memory.virtual_bytes.to_le_bytes());
        put(at + 136, &record.memory.peak_resident.to_le_bytes());
        put(at + 144, &record.memory.resident.to_le_bytes());
        // Cobrança e pico do mesmo EPROCESS usado pelo alocador.
        put(at + 152, &record.pool_quota[1].peak.to_le_bytes());
        put(at + 160, &record.pool_quota[1].usage.to_le_bytes());
        put(at + 168, &record.pool_quota[0].peak.to_le_bytes());
        put(at + 176, &record.pool_quota[0].usage.to_le_bytes());
        // Pagefile e faltas de página ficam sem provedor nesta consulta.
        put(at + 200, &record.memory.private_bytes.to_le_bytes());
        for (thread_index, thread) in record.threads.iter().enumerate() {
            let offset = at + 256 + thread_index as u64 * 80;
            put(offset, &thread.kernel_time.to_le_bytes());
            put(offset + 8, &thread.user_time.to_le_bytes());
            put(offset + 16, &thread.create_time.to_le_bytes());
            put(offset + 32, &thread.start.to_le_bytes());
            put(offset + 40, &record.pid.to_le_bytes());
            put(offset + 48, &thread.id.to_le_bytes());
            put(offset + 56, &thread.priority.to_le_bytes());
            put(offset + 60, &thread.base_priority.to_le_bytes());
            put(offset + 64, &thread.context_switches.to_le_bytes());
            put(offset + 68, &thread.state.to_le_bytes());
            put(offset + 72, &thread.wait_reason.to_le_bytes());
        }
        for (unit_index, unit) in units.iter().enumerate() {
            put(name_at + unit_index as u64 * 2, &unit.to_le_bytes());
        }
        at += record.size;
    }
    bytes
}

/// SystemProcessInformation (5).
pub fn query(output: u64, length: u64, returned: u64, user_mode: bool) -> Result<u32, KernelError> {
    if length > 0xFFFF_FFFF {
        return Ok(0xC000_000D);
    }
    if user_mode && returned != 0 && !user_probe::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    let records = snapshot()?;
    let needed: u64 = records.iter().map(|record| record.size).sum();
    if returned != 0 {
        guest::write32(returned, needed as u32);
    }
    if length < needed {
        return Ok(0xC000_0004);
    }
    if output == 0 || (user_mode && !user_probe::probe_user_write(output, needed)) {
        return Ok(0xC000_0005);
    }
    if output % 8 != 0 {
        return Ok(0x8000_0002);
    }
    guest::write_bytes(output, &encode(&records, output));
    Ok(0)
}
