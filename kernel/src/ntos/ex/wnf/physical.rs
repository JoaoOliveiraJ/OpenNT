//! Transporte do escopo PhysicalMachine — `system32/ntos/ex/wnf-physical.js`.
//!
//! Sem extensão registrada, ExpCrossVmWnfPush devolve NOT_IMPLEMENTED e o
//! WNF segue o caminho local. Registrar uma extensão exige operações reais;
//! a referência ativa protege o provedor em uso.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::rtl::{KernelError, SpinLock};

/// Operações da extensão: push(pedido, nome, carimbo, buffer, tamanho) e
/// populate(estado).
#[derive(Clone, Copy)]
pub struct Transport {
    pub push: fn(u32, u64, u32, u64, u32) -> u32,
    pub populate: fn(u64) -> u32,
}

/// Provedor registrado e o token que identifica o registro.
static EXTENSION: SpinLock<Option<(u64, Transport)>> = SpinLock::new(None);
static BORROWERS: AtomicU32 = AtomicU32::new(0);
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Devolve o token exigido por [`unregister`].
pub fn register(provider: Transport) -> Result<u64, KernelError> {
    let mut extension = EXTENSION.lock();
    if extension.is_some() {
        return Err(KernelError::new("invalid or duplicate WNF physical transport"));
    }
    let token = NEXT_TOKEN.fetch_add(1, Ordering::AcqRel);
    *extension = Some((token, provider));
    Ok(token)
}

pub fn unregister(token: u64) -> Result<(), KernelError> {
    let mut extension = EXTENSION.lock();
    if extension.map(|(current, _)| current) != Some(token) || BORROWERS.load(Ordering::Acquire) != 0 {
        return Err(KernelError::new("WNF physical transport still in use"));
    }
    *extension = None;
    Ok(())
}

fn borrow(action: impl FnOnce(Transport) -> u32) -> u32 {
    let Some((_, provider)) = *EXTENSION.lock() else { return 0xC000_0002 };
    BORROWERS.fetch_add(1, Ordering::AcqRel);
    let status = action(provider);
    BORROWERS.fetch_sub(1, Ordering::AcqRel);
    status
}

pub fn push(request: u32, encoded_name: u64, stamp: u32, buffer: u64, length: u32) -> u32 {
    borrow(|provider| (provider.push)(request, encoded_name, stamp, buffer, length))
}

pub fn populate(state: u64) -> u32 {
    borrow(|provider| (provider.populate)(state))
}
