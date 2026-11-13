//! Retenções de leitura de VAD — `system32/ntos/mm/secured-views.js`.
//!
//! Impedem a desmontagem e a perda de acesso enquanto um dono de kernel usa
//! a vista. A autorização é um objeto privado (o token).

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use alloc::sync::Arc;

use crate::ntos::ps::user::sections::View;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Autorização de leitura protegida de uma vista.
pub struct SecuredToken {
    id: u64,
    view: Arc<View>,
    storage: u64,
    released: AtomicBool,
}

impl SecuredToken {
    pub fn view(&self) -> &Arc<View> {
        &self.view
    }
}

/// Vista desmontada ou em retirada = CONFLICTING_ADDRESSES.
pub fn acquire(view: &Arc<View>) -> Result<Arc<SecuredToken>, u32> {
    {
        let state = view.state.lock();
        if state.unmapped || state.retirement.is_some() {
            return Err(0xC000_0019);
        }
    }
    let storage = guest::alloc_bytes(0x48);
    if storage == 0 {
        return Err(0xC000_009A);
    }
    let token = Arc::new(SecuredToken { id: NEXT_TOKEN.fetch_add(1, Ordering::Relaxed), view: view.clone(), storage, released: AtomicBool::new(false) });
    view.state.lock().secured_reads.push(token.id);
    Ok(token)
}

pub fn release(token: &SecuredToken) -> Result<(), KernelError> {
    let removed = {
        let mut state = token.view.state.lock();
        match state.secured_reads.iter().position(|&id| id == token.id) {
            Some(index) if !token.released.load(Ordering::Acquire) => {
                state.secured_reads.remove(index);
                true
            }
            _ => false,
        }
    };
    if !removed {
        return Err(KernelError::new("invalid secured view release"));
    }
    token.released.store(true, Ordering::Release);
    guest::free_bytes(token.storage);
    Ok(())
}

/// PAGE_READONLY e WRITECOPY continuam legíveis; NOACCESS e GUARD
/// quebrariam a garantia capturada por MmMapSecureViewOfSection.
pub fn protection_status(view: &View, protection: u32) -> u32 {
    if view.state.lock().secured_reads.is_empty() {
        return 0;
    }
    if protection & 0x100 != 0 || protection & 255 == 1 {
        0xC000_0045
    } else {
        0
    }
}

/// Só o próprio token autoriza desmontar uma vista protegida.
pub fn unmap_status(view: &View, authority: Option<&SecuredToken>) -> u32 {
    let state = view.state.lock();
    for &id in &state.secured_reads {
        if authority.is_none_or(|token| token.id != id || token.released.load(Ordering::Acquire)) {
            return 0xC000_0045;
        }
    }
    0
}
