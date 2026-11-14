//! EX_PUSH_LOCK_AUTO_EXPAND — push lock que o NT pode "abrir em leque" (uma
//! cópia por processador) quando a contenção compartilhada é alta. O
//! contrato com o driver é o do push lock comum sobre
//! `LocalLock`, mais o token que a aquisição compartilhada devolve.
//!
//! Layout: `_EX_PUSH_LOCK_AUTO_EXPAND` (ntkrnlmp.pdb, 0x10 bytes) é
//! `inc::types::extra_fs_ntfs::ExPushLockAutoExpand`: LocalLock, State
//! (Expanded/Transitioning/Pageable, bits 3.. = tabela em leque) e Stats
//! (amostras de contenção).
//!
//! Comportamento conferido contra o ntoskrnl 10.0.19045:
//!   ExInitializeAutoExpandPushLock(L, Flags) 0x2ffb80: zera 16 bytes;
//!     Flags & 1 (não paginável) -> State = 0, senão State = Pageable (4).
//!   ExCleanupAutoExpandPushLock(L) 0x2e9ed0: se Expanded, ExSaFree(State & ~7).
//!   ExAcquireAutoExpandPushLockExclusive(L, F) 0x2faf60 /
//!   ExReleaseAutoExpandPushLockExclusive(L, F) 0x2fab20: F & ~3 -> bugcheck
//!     0x152(F, L); sem Expanded, ExfAcquire/ReleasePushLockExclusiveEx em L.
//!   ExAcquireAutoExpandPushLockShared(L, F) 0x2e51d0 -> token: sem Expanded,
//!     LocalLock compartilhado e token = L | 1 | (F & 2 ? 0 : 2).
//!   ExReleaseAutoExpandPushLockShared(T, F) 0x2e70e0: F & ~3, ou bit 1 do
//!     token com F & 2, -> bugcheck 0x152(F, T); bit 0 do token = LocalLock
//!     (T & ~3), senão o slot em leque T & ~3.
//!   O bit 1 do token / F & 2 controla o rastreamento AutoBoost
//!   (KeAbPreAcquire/KeAbPostRelease), que o OpenNT não tem.
//!
//! O leque é uma otimização: ExpTryExpandAutoExpandPushLock só expande
//! quando as amostras de contenção em `Stats` passam de
//! ExpAeCycleCountThreshold. O OpenNT não amostra contenção (Stats fica 0),
//! então o lock nunca expande — um estado que o Windows também tem enquanto o
//! limiar não é atingido; a exclusão mútua, o formato do token e as
//! verificações de flags são os mesmos.

use crate::ntos::ex::push_lock;
use crate::ntos::inc::types::extra_fs_ntfs::ExPushLockAutoExpand;
use crate::ntos::inc::NtStruct;
use crate::ntos::ke::bugcheck;
use crate::rtl::KernelError;

/// EX_PUSH_LOCK_AUTO_EXPAND_NONPAGED (Flags do Initialize).
pub const NONPAGED: u32 = 1;
/// Flags válidos de Acquire/Release (bit 1 = sem rastreamento AutoBoost).
const VALID_FLAGS: u32 = 3;
const NO_AUTOBOOST: u32 = 2;
const TOKEN_LOCAL: u64 = 1;
const TOKEN_TRACKED: u64 = 2;
const INVALID_PUSH_LOCK_FLAGS: u32 = 0x152;

fn check_flags(lock: &ExPushLockAutoExpand, flags: u32) {
    if flags & !VALID_FLAGS != 0 {
        bugcheck::bug_check_ex(INVALID_PUSH_LOCK_FLAGS, flags as u64, lock.address(), 0, 0);
    }
}

/// O caminho em leque (ExpAcquire/ReleaseFannedOutPushLock*) só existe com
/// State.Expanded, que o OpenNT nunca liga.
fn ensure_local(lock: &ExPushLockAutoExpand) -> Result<(), KernelError> {
    if lock.state.expanded() != 0 {
        return Err(KernelError::new("EX_PUSH_LOCK_AUTO_EXPAND expandido sem tabela em leque"));
    }
    Ok(())
}

/// ExInitializeAutoExpandPushLock(PushLock, Flags).
pub fn initialize(lock: &ExPushLockAutoExpand, flags: u32) {
    push_lock::initialize(lock.local_lock.address());
    lock.stats.set(0);
    lock.state.value.set(0);
    if flags & NONPAGED == 0 {
        lock.state.set_pageable(1);
    }
}

/// ExCleanupAutoExpandPushLock: só uma tabela em leque teria o que liberar,
/// e o OpenNT nunca expande.
pub fn cleanup(lock: &ExPushLockAutoExpand) -> Result<(), KernelError> {
    ensure_local(lock)
}

/// ExAcquireAutoExpandPushLockExclusive(PushLock, Flags).
pub fn acquire_exclusive(lock: &ExPushLockAutoExpand, flags: u32) -> Result<(), KernelError> {
    check_flags(lock, flags);
    ensure_local(lock)?;
    push_lock::acquire_exclusive(lock.local_lock.address(), 0)
}

/// ExReleaseAutoExpandPushLockExclusive(PushLock, Flags).
pub fn release_exclusive(lock: &ExPushLockAutoExpand, flags: u32) -> Result<(), KernelError> {
    check_flags(lock, flags);
    ensure_local(lock)?;
    push_lock::release_exclusive(lock.local_lock.address(), 0)
}

/// ExAcquireAutoExpandPushLockShared(PushLock, Flags) -> token para o Release.
pub fn acquire_shared(lock: &ExPushLockAutoExpand, flags: u32) -> Result<u64, KernelError> {
    check_flags(lock, flags);
    ensure_local(lock)?;
    push_lock::acquire_shared(lock.local_lock.address(), 0)?;
    let tracked = if flags & NO_AUTOBOOST == 0 { TOKEN_TRACKED } else { 0 };
    Ok(lock.address() | TOKEN_LOCAL | tracked)
}

/// ExReleaseAutoExpandPushLockShared(Token, Flags): o token é o PVOID que a
/// aquisição devolveu (endereço do lock com os bits 0/1), não um objeto.
pub fn release_shared(token: u64, flags: u32) -> Result<(), KernelError> {
    if flags & !VALID_FLAGS != 0 || (token & TOKEN_TRACKED != 0 && flags & NO_AUTOBOOST != 0) {
        bugcheck::bug_check_ex(INVALID_PUSH_LOCK_FLAGS, flags as u64, token, 0, 0);
    }
    if token & TOKEN_LOCAL == 0 {
        return Err(KernelError::new("token de push lock em leque sem tabela em leque"));
    }
    // SAFETY: com o bit 0, `token & ~3` é o EX_PUSH_LOCK_AUTO_EXPAND que a
    // aquisição compartilhada recebeu do mesmo chamador.
    let lock = unsafe { ExPushLockAutoExpand::at(token & !3) };
    push_lock::release_shared(lock.local_lock.address(), 0)
}
