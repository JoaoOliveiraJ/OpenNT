//! Kernel executive (Ke) — `system32/ntos/ke/`.

pub mod bugcheck;
pub mod bugcheck_reason;
pub mod clock;
pub mod dpc;
pub mod dump_memory;
pub mod interrupt_object;
pub mod irql;
pub mod pcr;
pub mod processor_information;
pub mod smp;
pub mod thread_dispatch;
pub mod thread_lock;
pub mod apc;
pub mod critical_region;
pub mod dispatcher;
pub mod thread_alert;
pub mod timer;
pub mod test_alert;
pub mod thread_priority;
pub mod fast_mutex;
pub mod process_attachment;
pub mod debugger_data;
pub mod persistent_thread_state;
pub mod kernel_exception;
pub mod spin_lock;
pub mod processor_group;
pub mod affinity;
pub mod callout;
pub mod debug_print;
pub mod xstate;
pub mod version;
pub mod exports;
pub mod services;

/// O kernel drena timers, DPCs, work items e IoTimers no laço ocioso, como o
/// NT ao cair de DISPATCH_LEVEL.
pub fn run_kernel_tasks() {
    crate::ntos::mm::kernel_pool::reap();
    crate::ntos::ex::lookaside::maintain();
    // APCs pendentes entregues ao cair para PASSIVE_LEVEL.
    let _ = crate::ntos::ke::apc::deliver_all_queued();
    crate::ntos::ke::timer::check_timers();
    let _ = crate::ntos::ke::dpc::run_queue();
    crate::ntos::io::work_items::run_queue();
    crate::ntos::io::threads::io_timer::check_io_timers();
    crate::ntos::io::file::request::pump();
}
