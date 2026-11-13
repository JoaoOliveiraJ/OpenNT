//! Cobrança real de pool por processo — `system32/ntos/ps/pool-quota.js`.
//!
//! Os contadores publicados no EPROCESS são a fonte de verdade; o registro
//! do processo guarda só os limites.

use super::process;
use crate::ntos::mm::kernel_pool::PoolQuota;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::nt_abi::eprocess;

pub const MAXIMUM_QUOTA: u64 = u64::MAX;
const QUOTA_EXCEEDED: u32 = 0xC000_0044;

/// SIZE_T nativo: índice zero não paginável, índice um paginável.
fn counter(process: u64, paged: bool, offset: u64) -> u64 {
    process + offset + if paged { 8 } else { 0 }
}

/// (uso, pico, limite) de cada pool, sem criar estado para processo ausente.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuotaSnapshot {
    pub usage: u64,
    pub peak: u64,
    pub limit: u64,
}

pub fn snapshot(process: u64) -> Result<[QuotaSnapshot; 2], KernelError> {
    let limits = process::with_record(process, |record| record.pool_quota_limits).ok_or_else(|| KernelError::new("pool quota requires a live process object"))?;
    let limits = limits.unwrap_or([MAXIMUM_QUOTA, MAXIMUM_QUOTA]);
    let read = |paged: bool, index: usize| QuotaSnapshot {
        usage: guest::read64(counter(process, paged, eprocess::POOL_QUOTA_USAGE)),
        peak: guest::read64(counter(process, paged, eprocess::POOL_QUOTA_PEAK)),
        limit: limits[index],
    };
    Ok([read(false, 0), read(true, 1)])
}

/// Limites explícitos são rígidos; sem configuração o limite é SIZE_T_MAX e
/// o alocador continua limitado pelos PFNs/VA reais.
pub fn set_limits(process: u64, non_paged: u64, paged: u64) -> Result<(), KernelError> {
    let current = snapshot(process)?;
    if non_paged < current[0].usage || paged < current[1].usage {
        return Err(KernelError::new("pool quota limit below usage or outside SIZE_T"));
    }
    process::update_record(process, |record| record.pool_quota_limits = Some([non_paged, paged]));
    Ok(())
}

fn cas(address: u64, expected: u64, replacement: u64) -> u64 {
    guest::compare_exchange64(address, expected, replacement).unwrap_or_else(|error| panic!("{error}"))
}

/// O pico sobe por CAS: uma cobrança concorrente maior nunca se perde.
fn raise_peak(address: u64, usage: u64) {
    let mut peak = guest::read64(address);
    while usage > peak {
        let observed = cas(address, peak, usage);
        if observed == peak {
            return;
        }
        peak = observed;
    }
}

/// Devolve uma vez, preserva o pico e só então solta a referência do dono.
fn release(process_pointer: u64, paged: bool, bytes: u64) {
    let usage = counter(process_pointer, paged, eprocess::POOL_QUOTA_USAGE);
    let mut current = guest::read64(usage);
    loop {
        if current < bytes {
            panic!("pool quota underflow");
        }
        let observed = cas(usage, current, current - bytes);
        if observed == current {
            break;
        }
        current = observed;
    }
    if !matches!(process::dereference(process_pointer), Ok(Some(_))) {
        panic!("pool quota owner disappeared");
    }
}

/// Reserva bytes com uma referência real ao EPROCESS; a devolução vai com o
/// bloco de pool e sobrevive ao término do processo. O System não é cobrado.
pub fn charge(process: u64, paged: bool, bytes: u64) -> Result<Result<Option<PoolQuota>, u32>, KernelError> {
    if bytes == 0 {
        return Err(KernelError::new("invalid pool quota charge"));
    }
    let Some(limits) = process::with_record(process, |record| record.pool_quota_limits) else {
        return Err(KernelError::new("pool quota owner is absent"));
    };
    if process == process::get_system_process() {
        return Ok(Ok(None));
    }
    let limit = limits.map_or(MAXIMUM_QUOTA, |limits| limits[paged as usize]);
    let usage_address = counter(process, paged, eprocess::POOL_QUOTA_USAGE);
    let peak_address = counter(process, paged, eprocess::POOL_QUOTA_PEAK);
    let mut usage = guest::read64(usage_address);
    loop {
        let Some(next) = usage.checked_add(bytes).filter(|&next| next <= limit) else {
            return Ok(Err(QUOTA_EXCEEDED));
        };
        let observed = cas(usage_address, usage, next);
        if observed == usage {
            raise_peak(peak_address, next);
            break;
        }
        usage = observed;
    }
    if process::reference(process).is_none() {
        return Err(KernelError::new("pool quota lost owner"));
    }
    Ok(Ok(Some(PoolQuota { process_pointer: process, paged, bytes, release })))
}
