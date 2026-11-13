//! Estado de segurança da thread (impersonação).
//!
//! Este módulo faz a atribuição interna; o serviço chamador autoriza a
//! impersonação antes de pedi-la.

use alloc::collections::BTreeMap;

use crate::ntos::se::token::tokens;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::types::{Ethread, NtStruct};
use core::sync::atomic::Ordering;

#[derive(Clone, Copy, Debug)]
pub struct Impersonation {
    pub token: u64,
    pub level: u32,
    pub copy_on_open: bool,
    pub effective_only: bool,
}

static BY_THREAD: SpinLock<BTreeMap<u64, Impersonation>> = SpinLock::new(BTreeMap::new());

pub fn get(thread: u64) -> Option<Impersonation> {
    BY_THREAD.lock().get(&thread).copied()
}

/// Troca o token da thread e publica a representação nativa. Retém o novo
/// antes de liberar o anterior (mesmo quando são o mesmo objeto).
pub fn assign(thread: u64, token: Option<u64>, level: u32, copy_on_open: bool, effective_only: bool) -> Result<(), KernelError> {
    if !process::is_thread(thread) {
        return Err(KernelError::new("invalid impersonating thread"));
    }
    if token.is_some() && level > 3 {
        return Err(KernelError::new("invalid impersonation level"));
    }
    if let Some(token) = token {
        tokens::retain(token)?;
    }
    let previous = {
        let mut map = BY_THREAD.lock();
        match token {
            Some(token) => map.insert(thread, Impersonation { token, level, copy_on_open, effective_only }),
            None => map.remove(&thread),
        }
    };
    // SAFETY: `is_thread` conferiu o ETHREAD vivo.
    let ethread = unsafe { Ethread::at(thread) };
    // Os bits baixos do ponteiro codificam nível e effectiveOnly
    // (PS_CLIENT_SECURITY_CONTEXT).
    let native = token.map_or(0, |token| token | level as u64 | if effective_only { 4 } else { 0 });
    ethread.client_security.impersonation_data.set(native);
    // Só ActiveImpersonationInfo e CopyTokenOnOpen mudam: outras CPUs mexem
    // nos demais bits de CrossThreadFlags, então a troca é um CAS (o NT usa
    // operações interlocked de bits).
    let mask = Ethread::ACTIVE_IMPERSONATION_INFO_MASK | Ethread::COPY_TOKEN_ON_OPEN_MASK;
    let active = if token.is_some() { Ethread::ACTIVE_IMPERSONATION_INFO_MASK } else { 0 }
        | if token.is_some() && copy_on_open { Ethread::COPY_TOKEN_ON_OPEN_MASK } else { 0 };
    let _ = ethread.cross_thread_flags.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |flags| Some(flags & !mask | active));
    if let Some(previous) = previous {
        tokens::release(previous.token)?;
    }
    Ok(())
}

pub fn release(thread: u64) -> Result<(), KernelError> {
    if get(thread).is_some() {
        assign(thread, None, 0, false, false)?;
    }
    Ok(())
}

/// Token de impersonação, ou o primário do processo corrente (`as_self` ou
/// sem token de cliente). O retorno é emprestado.
pub fn effective(thread: u64, as_self: bool) -> Option<u64> {
    let impersonation = if as_self { None } else { get(thread) };
    impersonation.map(|state| state.token).or_else(|| process::get_primary_token(process::get_current_process()))
}
