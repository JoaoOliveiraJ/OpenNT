//! PoNotifySystemTimeSet: o aviso de troca da hora do sistema.
//!
//! O PoNotifySystemTimeSet(NewTime, OldTime, Reason) do ntoskrnl 19041 (rva
//! 0x3a7104) só age depois de PsWin32CalloutsEstablished (com o win32k.sys
//! carregado): guarda as duas horas em PopTimeChangeInfo e, em
//! DISPATCH_LEVEL, chama o ExNotifyCallback de \Callback\SetSystemTime
//! (ExCbSetSystemTime, argumentos nulos) e pede o trabalho de política 0x10,
//! o PopPolicyTimeChange: WNF_PO_SYSTEM_TIME_CHANGED com os 16 bytes de
//! PopTimeChangeInfo e o callout de evento do win32k (PsW32SystemTime,
//! `po/win32_callout.rs`). O trabalho de política corre aqui mesmo, depois do
//! callback.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::mm::guest_memory as guest;

/// WNF_PO_SYSTEM_TIME_CHANGED do ntoskrnl 19041.
pub const WNF_PO_SYSTEM_TIME_CHANGED: u64 = 0x41C6_013D_A3BD_0075;

/// PopTimeChangeInfo: a hora nova e a anterior.
static NEW_TIME: AtomicU64 = AtomicU64::new(0);
static OLD_TIME: AtomicU64 = AtomicU64::new(0);

/// PopTimeChangeInfo (hora nova, hora anterior).
pub fn last_change() -> (i64, i64) {
    (NEW_TIME.load(Ordering::Relaxed) as i64, OLD_TIME.load(Ordering::Relaxed) as i64)
}

/// PoNotifySystemTimeSet(NewTime, OldTime).
pub fn notify_system_time_set(new_time: i64, old_time: i64) {
    if crate::ntos::ps::win32::win32_callout().is_none() {
        return;
    }
    NEW_TIME.store(new_time as u64, Ordering::Relaxed);
    OLD_TIME.store(old_time as u64, Ordering::Relaxed);
    if let Some(callback) = crate::ntos::ex::callbacks::system_callback("SetSystemTime") {
        let previous = crate::ntos::ke::irql::raise_irql(2);
        let _ = crate::ntos::ex::callbacks::notify(callback, 0, 0);
        crate::ntos::ke::irql::lower_irql(previous as u64);
    }
    // PopPolicyTimeChange.
    let block = guest::alloc_bytes(24);
    if block == 0 {
        return;
    }
    guest::write64(block, WNF_PO_SYSTEM_TIME_CHANGED);
    guest::write64(block + 8, new_time as u64);
    guest::write64(block + 16, old_time as u64);
    let _ = crate::ntos::ex::wnf::service::update(block, block + 8, 16, 0, 0, 0, false);
    guest::free_bytes(block);
    super::win32_callout::system_time_changed();
}
