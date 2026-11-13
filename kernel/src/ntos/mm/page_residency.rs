//! Dono único dos hooks de falta nativa, acesso de convidado, pressão de
//! PFN e preparo de AP — `system32/ntos/mm/page-residency.js`.
//!
//! Os provedores mantêm seu próprio armazenamento e posse de páginas.
//! Preparar um AP suprime a recuperação em TODOS os provedores.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::{pfn, small};
use crate::ntos::ke::{irql, smp};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory;

/// Resultado de uma falta tratada por um provedor.
pub enum FaultResult {
    NotMine,
    Resolved,
    /// Não retoma a instrução: a trap entrega STATUS_IN_PAGE_ERROR.
    InPageError(u32),
}

#[derive(Clone, Copy)]
pub struct Provider {
    pub fault: fn(u64, u32) -> FaultResult,
    pub resolve: fn(u64) -> Result<Option<u64>, KernelError>,
    pub reclaim: fn(u64) -> Result<u64, KernelError>,
    pub prepare: fn() -> Result<(), KernelError>,
    /// Limites vivos opcionais: só excluem donos impossíveis.
    pub resolve_range: Option<(u64, u64)>,
}

struct Residency {
    providers: Vec<(String, Provider)>,
    errors: BTreeMap<String, String>,
    initialized: bool,
}

static STATE: SpinLock<Residency> = SpinLock::new(Residency { providers: Vec::new(), errors: BTreeMap::new(), initialized: false });
static PREPARING: AtomicBool = AtomicBool::new(false);
static RECLAIMING: AtomicBool = AtomicBool::new(false);

fn providers() -> Vec<(String, Provider)> {
    STATE.lock().providers.clone()
}

/// `__jsosKernelPageFault`: falta de kernel recuperável.
pub fn fault(address: u64, error: u32) -> bool {
    small::clear_page_fault_failure();
    if error & 8 != 0 || irql::get_irql() > 1 {
        return false;
    }
    for (_, provider) in providers() {
        match (provider.fault)(address, error) {
            FaultResult::Resolved => return true,
            FaultResult::InPageError(status) => {
                let _ = small::record_page_fault_failure(address, error, status);
                return false;
            }
            FaultResult::NotMine => {}
        }
    }
    false
}

fn resolve(address: u64) -> Result<Option<u64>, KernelError> {
    for (_, provider) in providers() {
        if let Some((base, top)) = provider.resolve_range {
            if address < base || address >= top {
                continue;
            }
        }
        if let Some(physical) = (provider.resolve)(address)? {
            return Ok(Some(physical));
        }
    }
    Ok(None)
}

/// Recuperador do PFN.
pub fn reclaim(count: u64) -> u64 {
    if PREPARING.load(Ordering::Acquire) || irql::get_irql() > 1 || smp::has_active_jobs() {
        return 0;
    }
    if RECLAIMING.swap(true, Ordering::AcqRel) {
        return 0;
    }
    let mut freed = 0;
    for (name, provider) in providers() {
        if freed >= count {
            break;
        }
        let before = pfn::free_count();
        match (provider.reclaim)(count - freed) {
            Ok(count) => {
                freed += count;
                STATE.lock().errors.remove(&name);
            }
            Err(error) => {
                // Páginas já gravadas e liberadas continuam contando.
                freed += pfn::free_count().saturating_sub(before);
                let message = alloc::format!("{error}");
                let mut state = STATE.lock();
                if state.errors.get(&name) != Some(&message) {
                    debug_print!("[mm] {} reclaim failed: {}", name, message);
                }
                state.errors.insert(name, message);
            }
        }
    }
    RECLAIMING.store(false, Ordering::Release);
    freed
}

fn pfn_reclaimer(count: u64) -> bool {
    reclaim(count) > 0
}

fn prepare() {
    assert!(!PREPARING.swap(true, Ordering::AcqRel), "recursive native residency preparation");
    for (name, provider) in providers() {
        if let Err(error) = (provider.prepare)() {
            debug_print!("[mm] {} prepare failed: {}", name, error);
        }
    }
    PREPARING.store(false, Ordering::Release);
}

pub fn register(name: &str, provider: Provider) -> Result<(), KernelError> {
    let first = {
        let mut state = STATE.lock();
        if state.providers.iter().any(|(existing, _)| existing == name) {
            return Err(KernelError::new(alloc::format!("duplicate residency provider: {name}")));
        }
        state.providers.push((String::from(name), provider));
        let first = !state.initialized;
        state.initialized = true;
        first
    };
    if first {
        guest_memory::set_pageable_resolver(Some(resolve));
        pfn::set_reclaimer(Some(pfn_reclaimer));
        smp::set_prepare_job(Some(prepare));
    }
    Ok(())
}

pub fn errors() -> Vec<(String, String)> {
    STATE.lock().errors.iter().map(|(name, message)| (name.clone(), message.clone())).collect()
}
