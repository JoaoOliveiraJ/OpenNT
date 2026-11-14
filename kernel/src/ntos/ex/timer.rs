//! Timers do Executive (EX_TIMER): ExAllocateTimer, ExSetTimer,
//! ExCancelTimer e ExDeleteTimer sobre o KTIMER e o KDPC do Ke.
//!
//! O EX_TIMER (0x100 bytes) guarda o KTIMER, um KDPC interno, o callback e o
//! contexto; o DPC repassa (exTimer, context) ao PEXT_CALLBACK do driver.

use crate::hal::amd64::native_call;
use crate::ntos::mm::kernel_data;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Kdpc, Ktimer};
use crate::ntos::ke::{dpc, timer};
use crate::ntos::mm::guest_memory as guest;

/// EX_TIMER (0x100 bytes, opaco para os drivers): KTIMER, KDPC interno,
/// callback e contexto. O DPC repassa (exTimer, context) ao PEXT_CALLBACK.
#[repr(C)]
struct ExTimer {
    timer: Ktimer,
    dpc: Kdpc,
    callback: Field<u64>,
    context: Field<u64>,
    _pad_90: Reserved<0x70>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for ExTimer {}

const _: () = {
    assert!(core::mem::size_of::<ExTimer>() == 0x100);
    assert!(core::mem::offset_of!(ExTimer, dpc) == 0x40);
    assert!(core::mem::offset_of!(ExTimer, callback) == 0x80);
};

fn ex_timer(timer_pointer: u64) -> &'static ExTimer {
    // SAFETY: os exports recebem o PEX_TIMER devolvido por `allocate`.
    unsafe { ExTimer::at(timer_pointer) }
}

/// DPC interno do EX_TIMER: o ponteiro recebido é o KDPC embutido.
fn ex_timer_dpc(dpc_pointer: u64, _context: u64, _first: u64, _second: u64) {
    let timer_pointer = dpc_pointer - core::mem::offset_of!(ExTimer, dpc) as u64;
    let body = ex_timer(timer_pointer);
    native_call::call(body.callback.get(), &[timer_pointer, body.context.get()]);
}

/// ExAllocateTimer(callback, context): 0 quando falta memória.
pub fn allocate(callback: u64, context: u64) -> u64 {
    let timer_pointer = guest::alloc_bytes(ExTimer::SIZE);
    if timer_pointer == 0 {
        return 0;
    }
    let body = ex_timer(timer_pointer);
    timer::initialize_timer(body.timer.address(), 0);
    body.callback.set(callback);
    body.context.set(context);
    // O KDPC embutido identifica o EX_TIMER que guarda rotina e contexto.
    dpc::initialize_kernel_dpc(body.dpc.address(), ex_timer_dpc, 0);
    timer_pointer
}

/// ExSetTimer(timer, dueTime, periodMs, parameters). Parameters é um
/// PEXT_SET_PARAMETERS (`EXT_SET_PARAMETERS_V0`: Version, Reserved,
/// NoWakeTolerance): não carrega período, e a tolerância sem despertar não
/// tem efeito aqui.
pub fn set(timer_pointer: u64, due_time: i64, period: u32, _parameters: u64) -> bool {
    let body = ex_timer(timer_pointer);
    timer::set_timer(body.timer.address(), due_time, body.dpc.address(), period)
}

/// ExCancelTimer: TRUE se o timer estava na fila.
pub fn cancel(timer_pointer: u64) -> bool {
    timer::cancel_timer(ex_timer(timer_pointer).timer.address())
}

/// ExDeleteTimer(timer, cancel): cancela quando pedido e libera o EX_TIMER.
pub fn delete(timer_pointer: u64, cancel: bool) -> bool {
    let was_queued = cancel && timer::cancel_timer(ex_timer(timer_pointer).timer.address());
    guest::free_bytes(timer_pointer);
    was_queued
}

/// O OBJECT_TYPE_INITIALIZER do tipo Timer (o ExpTimerInitialization do
/// ntoskrnl 19041): ExpTimerMapping {0x20001, 0x20002, 0x120000, 0x1F0003},
/// ValidAccessMask 0x1F0003, InvalidAttributes OBJ_OPENLINK, NonPagedPoolNx
/// com 0x148 de cobrança não paginável.
const TIMER_TYPE: TypeTemplate = TypeTemplate {
    name: "Timer",
    mapping: [0x2_0001, 0x2_0002, 0x12_0000, 0x1F_0003],
    valid_access: 0x1F_0003,
    flags: 0,
    object_type_code: 0,
    invalid_attributes: 0x100,
    pool_type: 0x200,
    paged_charge: 0,
    non_paged_charge: 0x148,
};

/// Cria o tipo Timer (uma vez) e publica ExTimerObjectType.
pub fn initialize_type() {
    kernel_data::write("ExTimerObjectType", object_types::ensure(&TIMER_TYPE).pointer);
}
