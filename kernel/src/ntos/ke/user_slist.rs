//! A retomada do pop de SList de modo usuário (o ExpInterlockedPopEntrySList
//! da ntdll, que o pool de threads, o heap e o d3d10warp usam). Entre a
//! leitura da cabeça e o LOCK CMPXCHG16B outra thread pode tirar e liberar a
//! entrada lida: a leitura do Next falta ou fica velha, e o pop recomeça do
//! começo. Como no ntoskrnl 19041:
//!
//! - o kernel guarda os exports ExpInterlockedPopEntrySListResume, ...Fault
//!   e ...End da ntdll quando a mapeia (KeUserPopEntrySListResume, ...Fault
//!   e ...End);
//! - KiPreprocessFault (rva 0x33c940, ramo de modo usuário em 0x33cab2 e
//!   0x47f335): uma falta de página de modo usuário
//!   (KI_EXCEPTION_ACCESS_VIOLATION, CS 0x33) com o RIP no ...Fault não vira
//!   exceção: o RIP volta ao ...Resume. A KTHREAD guarda o endereço que
//!   faltou (SListFaultAddress) e conta as faltas seguidas nele
//!   (SListFaultCount); passadas 0x400, a contagem zera e a falta é
//!   entregue como STATUS_ACCESS_VIOLATION;
//! - KiCheckForSListAddress (rva 0x24cf20), que o KiDeliverApc e o
//!   KiDispatchInterrupt chamam com o quadro de modo usuário da thread: um
//!   RIP em (...Resume, ...End] volta ao ...Resume. No OpenNT a troca pela
//!   interrupção é o fim do intervalo de usuário pelo relógio; o CONTEXT
//!   salvo nele é o que as APCs de usuário e a retomada usam.
//!
//! Sem a ntdll real (os três exports ausentes), nada muda.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::types::{Context, Kthread, NtStruct};

/// KeUserPopEntrySListResume, KeUserPopEntrySListFault e
/// KeUserPopEntrySListEnd.
static RESUME: AtomicU64 = AtomicU64::new(0);
static FAULT: AtomicU64 = AtomicU64::new(0);
static END: AtomicU64 = AtomicU64::new(0);

/// O seletor de código de 64 bits de modo usuário.
const USER_CODE_SELECTOR: u16 = 0x33;
/// Faltas seguidas no mesmo endereço antes da entrega.
const MAXIMUM_FAULT_COUNT: u16 = 0x400;

/// Os três endereços da ntdll mapeada (zero quando falta um export).
pub fn set_user_entry_points(resume: u64, fault: u64, end: u64) {
    let (resume, fault, end) = if resume != 0 && fault != 0 && end != 0 { (resume, fault, end) } else { (0, 0, 0) };
    RESUME.store(resume, Ordering::Release);
    FAULT.store(fault, Ordering::Release);
    END.store(end, Ordering::Release);
}

/// (Resume, Fault, End) correntes.
pub fn user_entry_points() -> (u64, u64, u64) {
    (RESUME.load(Ordering::Acquire), FAULT.load(Ordering::Acquire), END.load(Ordering::Acquire))
}

/// O ramo de SList do KiPreprocessFault para a falta de página de modo
/// usuário da thread `thread` no endereço `fault_address`, com o `context`
/// do momento da falta: `true` quando a falta foi absorvida (o RIP do
/// CONTEXT voltou ao ...Resume e nada é despachado).
pub fn preprocess_access_violation(thread: u64, context: &Context, fault_address: u64) -> bool {
    let (resume, fault, _) = user_entry_points();
    if fault == 0 || context.seg_cs.get() != USER_CODE_SELECTOR || context.rip.get() != fault {
        return false;
    }
    // SAFETY: a KTHREAD viva da thread que faltou.
    let kthread = unsafe { Kthread::at(thread) };
    if kthread.s_list_fault_address.get() != fault_address {
        kthread.s_list_fault_address.set(fault_address);
        kthread.s_list_fault_count.set(0);
    } else {
        let count = kthread.s_list_fault_count.get();
        if count > MAXIMUM_FAULT_COUNT {
            kthread.s_list_fault_count.set(0);
            return false;
        }
        kthread.s_list_fault_count.set(count + 1);
    }
    context.rip.set(resume);
    true
}

/// KiCheckForSListAddress sobre o CONTEXT de modo usuário salvo de uma
/// thread: o RIP em (...Resume, ...End] volta ao ...Resume.
pub fn check_for_slist_address(context: &Context) {
    let (resume, _, end) = user_entry_points();
    if resume == 0 || context.seg_cs.get() != USER_CODE_SELECTOR {
        return;
    }
    let rip = context.rip.get();
    if rip > resume && rip <= end {
        context.rip.set(resume);
    }
}
