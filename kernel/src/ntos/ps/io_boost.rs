//! Reforço de prioridade de I/O da thread — PsBoostThreadIoEx (RVA 0x2cdf90,
//! ntoskrnl 10.0.19045), alcançado por PsEnterPriorityRegion (0x2f2a60) e
//! PsLeavePriorityRegion (0x2f12f0) com a thread corrente.
//!
//! ETHREAD.IoBoostCount conta as regiões abertas (LOCK XADD); enquanto não é
//! zero, PsGetIoPriorityThread eleva a prioridade baixa da thread corrente a
//! Normal (`io::irp_request::io_priority`). Ao entrar na primeira região, o
//! NT ainda põe a thread na lista de autoboost do processador quando
//! KTHREAD.AbWaitEntryCount não é zero (há quem espere por locks dela); o
//! OpenNT não tem autoboost e esse contador fica zero nas suas threads, então
//! só o contador muda. Sair sem região aberta não faz nada. O rastreamento de
//! pilha (PspAlwaysTrackIoBoosting) fica desligado, como no padrão do Windows.

use core::sync::atomic::Ordering;

use crate::ntos::inc::types::Ethread;

/// PsBoostThreadIoEx(Thread, Unboost = FALSE, FALSE, NULL).
pub fn enter_priority_region(thread: &Ethread) {
    thread.io_boost_count.atomic().fetch_add(1, Ordering::SeqCst);
}

/// PsBoostThreadIoEx(Thread, Unboost = TRUE, FALSE, NULL): decrementa só
/// uma contagem não nula.
pub fn leave_priority_region(thread: &Ethread) {
    let _ = thread.io_boost_count.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |count| count.checked_sub(1));
}
