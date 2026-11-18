//! Timers do Executive (EX_TIMER): ExAllocateTimer, ExSetTimer,
//! ExCancelTimer e ExDeleteTimer, como no ntoskrnl 19041.
//!
//! O EX_TIMER (0xA0 bytes do NonPagedPoolNx, tag 'ExTm', opaco para os
//! drivers) começa no KTIMER2 (`ke/timer2`): é ele que vence, sinaliza quem
//! espera no próprio EX_TIMER (KeWaitForMultipleObjects sobre o ponteiro,
//! como a fila de blits do dxgkrnl faz) e chama o PEXT_CALLBACK com
//! (Timer, Context). Depois do KTIMER2 vêm o DeleteCallback e o
//! DeleteContext do EXT_DELETE_PARAMETERS, codificados como os ponteiros do
//! KTIMER2, e o byte do ExpTimerFreedCookie.
//!
//! - ExAllocateTimer(Callback, CallbackContext, Attributes) (o
//!   ExAllocateTimerInternal2 sem identificador IR): EX_TIMER_IDLE_RESILIENT
//!   (2), um atributo fora de EX_TIMER_HIGH_RESOLUTION (4), EX_TIMER_NO_WAKE
//!   (8) e EX_TIMER_NOTIFICATION (bit 31), ou NO_WAKE junto de outro tipo,
//!   são o bugcheck 0xC7 (9, 0, Attributes). Sem memória, NULL. O KTIMER2 é
//!   de notificação com o bit 31 e de sincronização sem ele.
//! - ExSetTimer(Timer, DueTime, Period, Parameters): Period é LONGLONG em
//!   unidades de 100 ns (o vsync emulado do dxgkrnl pede 166666 para 60 Hz);
//!   DueTime absoluto (positivo) num timer de alta resolução é o bugcheck
//!   0xC7 (9, 2), Period negativo o 0xC7 (9, 4) e um EXT_SET_PARAMETERS com
//!   Version diferente de zero ou NoWakeTolerance abaixo de -1 o 0xC7 (9,
//!   1). Um EX_TIMER já liberado (cookie trocado) é o bugcheck 0xC6
//!   (ExpCheckForFreedEnhancedTimer). Depois, o KeSetTimer2.
//! - ExCancelTimer(Timer, Parameters): a mesma checagem do cookie e o
//!   KeCancelTimer2.
//! - ExDeleteTimer(Timer, Cancel, Wait, Parameters): o cookie; um
//!   EXT_DELETE_PARAMETERS com Version diferente de zero é o bugcheck 0xC7
//!   (9, 1), senão DeleteCallback e DeleteContext são gravados; o KTIMER2 é
//!   desabilitado (o KeDisableTimer2) com o ExpFinalizeTimerDeletion como
//!   finalização: quando o timer sai da fila e de um vencimento em curso, o
//!   DeleteCallback roda com o DeleteContext, o cookie é invertido e o
//!   EX_TIMER volta ao pool. Devolve se o Cancel tirou o timer da fila.

use crate::hal::cpu;
use crate::ntos::ex::{ir_timer, pool_allocation};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::Ktimer2;
use crate::ntos::ke::{bugcheck, timer2};
use crate::ntos::mm::kernel_data;
use crate::ntos::ob::object_types::{self, TypeTemplate};
use crate::rtl::SpinLock;

/// O EX_TIMER do ExAllocateTimerInternal2: o KTIMER2, o DeleteCallback e o
/// DeleteContext codificados e o cookie de liberação.
#[repr(C)]
struct ExTimer {
    ke_timer: Ktimer2,
    delete_callback: Field<u64>,
    delete_context: Field<u64>,
    freed_cookie: Field<u8>,
    _pad_99: Reserved<0x7>,
}

// SAFETY: #[repr(C)] só de células e de structs do NT.
unsafe impl NtStruct for ExTimer {}

const _: () = {
    assert!(core::mem::size_of::<ExTimer>() == 0xA0);
    assert!(core::mem::offset_of!(ExTimer, delete_callback) == 0x88);
    assert!(core::mem::offset_of!(ExTimer, delete_context) == 0x90);
    assert!(core::mem::offset_of!(ExTimer, freed_cookie) == 0x98);
};

/// A tag do pool do EX_TIMER ('ExTm').
const POOL_TAG: u32 = 0x6D54_7845;
const NON_PAGED_POOL_NX: u32 = 0x200;
/// TIMER_OR_DPC_INVALID e DRIVER_CAUGHT_MODIFYING_FREED_POOL.
const TIMER_OR_DPC_INVALID: u32 = 0xC7;
const DRIVER_CAUGHT_MODIFYING_FREED_POOL: u32 = 0xC6;
/// O primeiro parâmetro do 0xC7 nas checagens do EX_TIMER.
const EX_TIMER_CHECK: u64 = 9;
/// EX_TIMER_IDLE_RESILIENT e EX_TIMER_HIGH_RESOLUTION.
const ATTRIBUTE_IDLE_RESILIENT: u32 = 2;
const TYPE_HIGH_RESOLUTION: u8 = 4;

/// ExpTimerFreedCookie: um byte sorteado no primeiro uso.
static FREED_COOKIE: SpinLock<Option<u8>> = SpinLock::new(None);

fn freed_cookie() -> u8 {
    *FREED_COOKIE.lock().get_or_insert_with(|| cpu::hardware_random_u64().unwrap_or_else(|| cpu::rdtsc().rotate_left(29)) as u8)
}

fn ex_timer(timer_pointer: u64) -> &'static ExTimer {
    // SAFETY: os exports recebem o PEX_TIMER devolvido por `allocate`.
    unsafe { ExTimer::at(timer_pointer) }
}

/// ExpCheckForFreedEnhancedTimer: um EX_TIMER cujo cookie não é o vigente
/// já voltou ao pool.
fn check_not_freed(timer_pointer: u64) {
    if ex_timer(timer_pointer).freed_cookie.get() != freed_cookie() {
        let mode = crate::ntos::ps::previous_mode::get().unwrap_or(0) as i8 as i64 as u64;
        bugcheck::bug_check_ex(DRIVER_CAUGHT_MODIFYING_FREED_POOL, timer_pointer, 1, mode, 0);
    }
}

/// ExAllocateTimer(Callback, CallbackContext, Attributes): 0 quando falta
/// memória.
pub fn allocate(callback: u64, context: u64, attributes: u32) -> u64 {
    if attributes & ATTRIBUTE_IDLE_RESILIENT != 0 || !ir_timer::attributes_are_valid(attributes) {
        bugcheck::bug_check_ex(TIMER_OR_DPC_INVALID, EX_TIMER_CHECK, 0, attributes as u64, 0);
    }
    let Ok(timer_pointer) = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, ExTimer::SIZE, POOL_TAG) else { return 0 };
    if timer_pointer == 0 {
        return 0;
    }
    let body = ex_timer(timer_pointer);
    timer2::initialize(&body.ke_timer, callback, context, attributes);
    body.delete_callback.set(timer2::encode(0, timer_pointer));
    body.delete_context.set(timer2::encode(0, timer_pointer));
    body.freed_cookie.set(freed_cookie());
    timer_pointer
}

/// ExSetTimer(Timer, DueTime, Period, Parameters): TRUE se o timer já
/// estava na fila.
pub fn set(timer_pointer: u64, due_time: i64, period: i64, parameters: u64) -> bool {
    let body = ex_timer(timer_pointer);
    // O NT passa no terceiro parâmetro o endereço da cópia na pilha; aqui
    // vai o valor.
    if due_time > 0 && body.ke_timer.type_flags.get() & TYPE_HIGH_RESOLUTION != 0 {
        bugcheck::bug_check_ex(TIMER_OR_DPC_INVALID, EX_TIMER_CHECK, 2, due_time as u64, 0);
    }
    if period < 0 {
        bugcheck::bug_check_ex(TIMER_OR_DPC_INVALID, EX_TIMER_CHECK, 4, period as u64, 0);
    }
    if parameters != 0 {
        // SAFETY: EXT_SET_PARAMETERS do chamador (Version em +0,
        // NoWakeTolerance em +8).
        let (version, tolerance) = unsafe { (Field::<u32>::at(parameters).get(), Field::<i64>::at(parameters + 8).get()) };
        if version != 0 || tolerance < -1 {
            bugcheck::bug_check_ex(TIMER_OR_DPC_INVALID, EX_TIMER_CHECK, 1, parameters, 0);
        }
    }
    check_not_freed(timer_pointer);
    timer2::set(&body.ke_timer, due_time, period, parameters)
}

/// ExCancelTimer(Timer, Parameters): TRUE se o timer estava na fila.
pub fn cancel(timer_pointer: u64) -> bool {
    check_not_freed(timer_pointer);
    timer2::cancel(&ex_timer(timer_pointer).ke_timer)
}

/// ExDeleteTimer(Timer, Cancel, Wait, Parameters): TRUE se o Cancel tirou o
/// timer da fila.
pub fn delete(timer_pointer: u64, cancel: bool, wait: bool, parameters: u64) -> bool {
    check_not_freed(timer_pointer);
    let body = ex_timer(timer_pointer);
    if parameters != 0 {
        // SAFETY: EXT_DELETE_PARAMETERS do chamador (Version em +0,
        // DeleteCallback em +8, DeleteContext em +0x10).
        let (version, callback, context) = unsafe { (Field::<u32>::at(parameters).get(), Field::<u64>::at(parameters + 8).get(), Field::<u64>::at(parameters + 0x10).get()) };
        if version != 0 {
            bugcheck::bug_check_ex(TIMER_OR_DPC_INVALID, EX_TIMER_CHECK, 1, version as u64, 0);
        }
        body.delete_callback.set(timer2::encode(callback, timer_pointer));
        body.delete_context.set(timer2::encode(context, timer_pointer));
    }
    timer2::disable(&body.ke_timer, cancel, wait, Some((finalize_deletion, timer_pointer)))
}

/// ExpFinalizeTimerDeletion(Timer): o DeleteCallback do ExDeleteTimer roda
/// com o DeleteContext, o cookie é invertido e o EX_TIMER volta ao pool.
fn finalize_deletion(timer_pointer: u64) {
    let body = ex_timer(timer_pointer);
    let callback = timer2::decode(body.delete_callback.get(), timer_pointer);
    if callback != 0 {
        let context = timer2::decode(body.delete_context.get(), timer_pointer);
        crate::hal::amd64::native_call::call(callback, &[context]);
    }
    body.freed_cookie.set(!freed_cookie());
    let _ = pool_allocation::free(timer_pointer, POOL_TAG as u64);
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
    kernel_data::write("ExTimerObjectType", timer_type_pointer());
}

/// O OBJECT_TYPE "Timer" (o mesmo de ExTimerObjectType).
pub fn timer_type_pointer() -> u64 {
    object_types::ensure(&TIMER_TYPE).pointer
}
