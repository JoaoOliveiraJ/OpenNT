//! Prioridade de I/O — io\iomgr (IoRetrievePriorityInfo, IoApplyPriorityInfoThread,
//! IoSetIoPriorityHintIntoThread) e o par Ps que elas usam
//! (PsSetIoPriorityThread 0x277970, PsSetPagePriorityThread 0x277c64,
//! PsGetIoPriorityThread 0x242180).
//!
//! ETHREAD.CrossThreadFlags: ThreadIoPriority (bits 9..11) e
//! ThreadPagePriority (12..14), trocados por CAS que devolve o anterior.
//! ETHREAD.IoBoostCount eleva a Normal a prioridade baixa da thread corrente.
//! EPROCESS.Flags.Background rebaixa I/O a VeryLow e página a no máximo 2.

use core::sync::atomic::Ordering;

use crate::ntos::init::exports::invoke_handler;
use crate::ntos::inc::types::extra_fs_fat::IoPriorityInfo;
use crate::ntos::inc::types::{Eprocess, Ethread, FileObject, Irp, NtStruct};
use crate::ntos::io::extensions;
use crate::ntos::ps::process;
use crate::rtl::KernelError;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_PARAMETER_1: u32 = 0xC000_00EF;

const IO_PRIORITY_NORMAL: u32 = 2;
const MAX_IO_PRIORITY_TYPES: u32 = 5;
const IRP_PRIORITY_MASK: u32 = 0xE_0000;

fn background(thread: &Ethread) -> bool {
    let process = thread.tcb.process.get();
    // SAFETY: KTHREAD.Process de uma thread viva é o seu EPROCESS.
    process != 0 && unsafe { Eprocess::at(process) }.background() != 0
}

/// Troca um campo de 3 bits do CrossThreadFlags; devolve o anterior.
fn exchange_cross_thread_field(thread: &Ethread, shift: u32, value: u32) -> u32 {
    let previous = thread
        .cross_thread_flags
        .atomic()
        .try_update(Ordering::SeqCst, Ordering::SeqCst, |flags| Some((flags & !(7 << shift)) | ((value & 7) << shift)))
        .unwrap_or_else(|flags| flags);
    (previous >> shift) & 7
}

/// PsSetIoPriorityThread.
pub fn set_thread_io_priority(thread: &Ethread, priority: u32) -> u32 {
    exchange_cross_thread_field(thread, Ethread::THREAD_IO_PRIORITY_SHIFT, priority)
}

/// PsSetPagePriorityThread.
pub fn set_thread_page_priority(thread: &Ethread, priority: u32) -> u32 {
    exchange_cross_thread_field(thread, Ethread::THREAD_PAGE_PRIORITY_SHIFT, priority)
}

fn is_current(thread: &Ethread) -> bool {
    thread.address() == process::get_current_thread()
}

/// O piso Normal da thread corrente com IoBoostCount.
fn boosted(thread: &Ethread, priority: u32) -> u32 {
    if priority < IO_PRIORITY_NORMAL && is_current(thread) && thread.io_boost_count.get() != 0 {
        IO_PRIORITY_NORMAL
    } else {
        priority
    }
}

/// PsGetIoPriorityThread.
pub fn thread_io_priority(thread: &Ethread) -> u32 {
    let priority = if background(thread) { 0 } else { thread.thread_io_priority() };
    boosted(thread, priority)
}

/// IoGetIoPriorityHint(Irp) (RVA 0x2547c0): Flags bits 17..19 menos 1; 0 = Normal.
pub fn irp_priority_hint(irp: &Irp) -> u32 {
    let hint = (irp.flags.get() >> 17) & 7;
    if hint == 0 {
        return IO_PRIORITY_NORMAL;
    }
    let priority = hint - 1;
    let thread = irp.tail.overlay.thread.get();
    // SAFETY: Tail.Overlay.Thread de um IRP vivo é um ETHREAD (ou 0).
    if priority < 2 && thread != 0 && unsafe { Ethread::at(thread) }.io_boost_count.get() != 0 {
        return IO_PRIORITY_NORMAL;
    }
    priority
}

/// IoRetrievePriorityInfo(Irp, FileObject, Thread, PriorityInfo) (RVA 0x256230).
pub fn retrieve_priority_info(irp: Option<&Irp>, file: Option<&FileObject>, thread: Option<&Ethread>, info: &IoPriorityInfo) -> u32 {
    info.io_priority.set(IO_PRIORITY_NORMAL);
    let file_hint = file.map_or(0, extensions::file_object_priority_hint);
    let io_priority = match irp {
        Some(irp) if irp.flags.get() & IRP_PRIORITY_MASK != 0 => Some(irp_priority_hint(irp)),
        _ if file_hint != 0 => Some(file_hint - 1),
        _ => thread.map(thread_io_priority),
    };
    if let Some(priority) = io_priority {
        info.io_priority.set(priority);
    }
    let Some(thread) = thread else {
        info.thread_priority.set(u32::MAX);
        info.page_priority.set(u32::MAX);
        return STATUS_SUCCESS;
    };
    // O NT consulta a cadeia de KSCHEDULING_GROUP por processador para threads
    // abaixo de 16; o OpenNT não tem grupos de escalonamento.
    info.thread_priority.set(thread.tcb.base_priority.get() as i32 as u32);
    let mut page = thread.thread_page_priority();
    if background(thread) {
        page = page.min(2);
    }
    info.page_priority.set(page);
    STATUS_SUCCESS
}

/// IoApplyPriorityInfoThread(Input, Output, Thread) (RVA 0x277bc0).
pub fn apply_priority_info(input: &IoPriorityInfo, output: Option<&IoPriorityInfo>, thread: &Ethread) -> Result<u32, KernelError> {
    let thread_priority = input.thread_priority.get();
    if thread_priority == 0xFFFF {
        return Ok(STATUS_INVALID_PARAMETER_1);
    }
    let previous_io = set_thread_io_priority(thread, input.io_priority.get());
    let page = input.page_priority.get();
    let previous_page = if page != u32::MAX { set_thread_page_priority(thread, page) } else { u32::MAX };
    let previous_thread = if thread_priority != u32::MAX {
        let previous = thread.tcb.base_priority.get() as i32 as u32;
        invoke_handler("KeSetActualBasePriorityThread", &[thread.address(), thread_priority as i32 as i64 as u64])?;
        previous
    } else {
        u32::MAX
    };
    if let Some(output) = output {
        output.size.set(IoPriorityInfo::SIZE as u32);
        output.thread_priority.set(previous_thread);
        output.page_priority.set(previous_page);
        output.io_priority.set(previous_io);
    }
    Ok(STATUS_SUCCESS)
}

/// IoSetIoPriorityHintIntoThread(Thread, PriorityHint) (RVA 0x278a90).
pub fn set_thread_priority_hint(thread: &Ethread, hint: u32) -> u32 {
    if hint >= MAX_IO_PRIORITY_TYPES {
        return STATUS_INVALID_PARAMETER;
    }
    set_thread_io_priority(thread, hint);
    STATUS_SUCCESS
}
