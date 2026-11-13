//! Cobrança real de pool por processo.
//!
//! Os contadores publicados no EPROCESS são a fonte de verdade; o registro
//! do processo guarda só os limites.

use super::process;
use crate::ntos::mm::kernel_pool::PoolQuota;
use crate::rtl::KernelError;
use core::sync::atomic::Ordering;

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::Eprocess;

pub const MAXIMUM_QUOTA: u64 = u64::MAX;
const QUOTA_EXCEEDED: u32 = 0xC000_0044;

fn eprocess(process: u64) -> &'static Eprocess {
    // SAFETY: EPROCESS vivo (o registro do processo existe) ou retido pela cobrança.
    unsafe { Eprocess::at(process) }
}

/// SIZE_T nativo: índice zero não paginável, índice um paginável.
fn usage(process: u64, paged: bool) -> &'static Field<u64> {
    &eprocess(process).process_quota_usage[paged as usize]
}

fn peak(process: u64, paged: bool) -> &'static Field<u64> {
    &eprocess(process).process_quota_peak[paged as usize]
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
        usage: usage(process, paged).get(),
        peak: peak(process, paged).get(),
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

/// O pico sobe por CAS: uma cobrança concorrente maior nunca se perde.
fn raise_peak(peak: &Field<u64>, usage: u64) {
    peak.atomic().fetch_max(usage, Ordering::SeqCst);
}

/// Devolve uma vez, preserva o pico e só então solta a referência do dono.
fn release(process_pointer: u64, paged: bool, bytes: u64) {
    let returned = usage(process_pointer, paged).atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |current| current.checked_sub(bytes));
    if returned.is_err() {
        panic!("pool quota underflow");
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
    let charged = usage(process, paged).atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |current| current.checked_add(bytes).filter(|&next| next <= limit));
    match charged {
        Ok(previous) => raise_peak(peak(process, paged), previous + bytes),
        Err(_) => return Ok(Err(QUOTA_EXCEEDED)),
    }
    if process::reference(process).is_none() {
        return Err(KernelError::new("pool quota lost owner"));
    }
    Ok(Ok(Some(PoolQuota { process_pointer: process, paged, bytes, release })))
}
