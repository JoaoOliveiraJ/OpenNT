//! Referências fortes de silo (PsAcquireSiloHardReference e
//! PsReleaseSiloHardReference).
//!
//! O host (NULL) está sempre presente; um silo de verdade (job com o bit de
//! silo) conta as referências fortes por endereço do objeto.

use alloc::collections::BTreeMap;

use super::query as silo_query;
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

static SILO_HARD_REFERENCES: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// PsAcquireSiloHardReference: só um silo de verdade aceita a referência.
pub fn acquire(silo: u64) -> u32 {
    if silo == 0 {
        return 0;
    }
    if silo_query::job_silo(silo) != silo {
        return STATUS_INVALID_PARAMETER;
    }
    *SILO_HARD_REFERENCES.lock().entry(silo).or_insert(0) += 1;
    0
}

/// PsReleaseSiloHardReference: devolve uma referência adquirida antes.
pub fn release(silo: u64) -> Result<(), KernelError> {
    if silo == 0 {
        return Ok(());
    }
    let mut references = SILO_HARD_REFERENCES.lock();
    match references.get_mut(&silo) {
        Some(count) if *count > 1 => *count -= 1,
        Some(_) => {
            references.remove(&silo);
        }
        None => return Err(KernelError::new("PsReleaseSiloHardReference sem referencia")),
    }
    Ok(())
}
