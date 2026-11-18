//! Autotestes da retomada do pop de SList de modo usuário (`ke/user_slist.rs`)
//! contra o KiPreprocessFault e o KiCheckForSListAddress do ntoskrnl 19041:
//!
//! - os três endereços são os exports ExpInterlockedPopEntrySListResume,
//!   ...Fault e ...End da ntdll mapeada (zero sem eles);
//! - num CONTEXT de modo usuário (CS 0x33) um RIP em (...Resume, ...End]
//!   volta ao ...Resume; o próprio ...Resume, um RIP fora da faixa e o modo
//!   kernel ficam como estão;
//! - a falta de acesso no ...Fault volta ao ...Resume e grava o endereço na
//!   KTHREAD.SListFaultAddress com a contagem zerada; faltas seguidas no
//!   mesmo endereço contam até passar de 0x400, quando a contagem zera e a
//!   falta é entregue; outro endereço recomeça a conta; um RIP fora do
//!   ...Fault ou de modo kernel não é absorvido.

use crate::ntos::inc::types::{Context, Kthread, NtStruct};
use crate::ntos::ke::user_slist;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::ps::user::state;

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    let saved = user_slist::user_entry_points();
    let exported = state::with(|state| {
        state.ntdll_exports.as_ref().map(|exports| {
            let export = |name: &str| exports.get(name).copied().unwrap_or(0);
            (export("ExpInterlockedPopEntrySListResume"), export("ExpInterlockedPopEntrySListFault"), export("ExpInterlockedPopEntrySListEnd"))
        })
    });
    let consistent = match exported {
        Some((resume, fault, end)) if resume != 0 && fault != 0 && end != 0 => saved == (resume, fault, end),
        _ => saved == (0, 0, 0),
    };
    assert(consistent, "uslist: os enderecos de retomada sao os exports da ntdll mapeada");

    let block = guest::alloc_aligned(Context::SIZE, 16, true);
    if block == 0 {
        assert(false, "uslist: CONTEXT do teste");
        return;
    }
    // Os deslocamentos dos exports na ntdll 19041.
    let (resume, fault, end) = (0x7FFA_0000_1167u64, 0x7FFA_0000_1177u64, 0x7FFA_0000_1180u64);
    user_slist::set_user_entry_points(resume, fault, end);
    // SAFETY: CONTEXT alocado pelo teste na memória do kernel.
    let context = unsafe { Context::at(block) };
    context.seg_cs.set(0x33);
    let restart = |rip: u64| {
        context.rip.set(rip);
        user_slist::check_for_slist_address(context);
        context.rip.get()
    };
    let inside = restart(resume + 1) == resume && restart(fault) == resume && restart(end) == resume;
    let outside = restart(resume) == resume && restart(resume - 1) == resume - 1 && restart(end + 1) == end + 1;
    context.seg_cs.set(0x10);
    let kernel = restart(fault) == fault;
    assert(inside && outside && kernel, "uslist: RIP de usuario em (Resume, End] volta ao Resume");

    // SAFETY: a KTHREAD corrente do teste.
    let kthread = unsafe { Kthread::at(process::get_current_thread()) };
    let (saved_address, saved_count) = (kthread.s_list_fault_address.get(), kthread.s_list_fault_count.get());
    let thread = kthread.address();
    let fault_at = |address: u64| {
        context.rip.set(fault);
        let absorbed = user_slist::preprocess_access_violation(thread, context, address);
        (absorbed, context.rip.get())
    };
    context.seg_cs.set(0x33);
    let first = fault_at(0x5000) == (true, resume) && kthread.s_list_fault_address.get() == 0x5000 && kthread.s_list_fault_count.get() == 0;
    let mut repeated = true;
    for _ in 0..0x401 {
        repeated &= fault_at(0x5000) == (true, resume);
    }
    let counted = kthread.s_list_fault_count.get() == 0x401;
    let delivered = fault_at(0x5000) == (false, fault) && kthread.s_list_fault_count.get() == 0;
    let other = fault_at(0x5000) == (true, resume) && fault_at(0x6000) == (true, resume) && kthread.s_list_fault_address.get() == 0x6000 && kthread.s_list_fault_count.get() == 0;
    context.rip.set(resume);
    let elsewhere = !user_slist::preprocess_access_violation(thread, context, 0x6000) && context.rip.get() == resume;
    context.seg_cs.set(0x10);
    let kernel_fault = fault_at(0x6000) == (false, fault);
    assert(first && repeated && counted && delivered && other && elsewhere && kernel_fault, "uslist: falta no Fault volta ao Resume e passa de 0x400 faltas seguidas para a entrega");

    // Sem os exports, nada muda.
    user_slist::set_user_entry_points(0, fault, end);
    context.seg_cs.set(0x33);
    let inert = fault_at(0x7000) == (false, fault) && restart(fault) == fault;
    assert(inert, "uslist: sem os exports da ntdll a retomada nao age");

    kthread.s_list_fault_address.set(saved_address);
    kthread.s_list_fault_count.set(saved_count);
    user_slist::set_user_entry_points(saved.0, saved.1, saved.2);
    guest::free_bytes(block);
}
