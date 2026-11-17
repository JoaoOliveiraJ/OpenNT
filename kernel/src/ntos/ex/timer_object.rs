//! O objeto Timer do Executive (ETIMER): NtCreateTimer, NtSetTimer e
//! NtCancelTimer, para os drivers (ZwCreateTimer, ZwSetTimer, ZwCancelTimer,
//! PreviousMode KernelMode) e com o modo anterior como parâmetro, para um
//! chamador de modo usuário.
//!
//! Como no ntoskrnl 19041:
//!
//! - NtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType):
//!   TimerType acima de SynchronizationTimer dá STATUS_INVALID_PARAMETER_4;
//!   o corpo de 0x148 bytes vem do ObCreateObjectEx com ExTimerObjectType,
//!   com o KDPC interno (ExpTimerDpcRoutine, contexto = o timer), o KTIMER
//!   do tipo pedido e o resto zerado; o handle sai do ObInsertObjectEx.
//! - NtSetTimer(TimerHandle, DueTime, TimerApcRoutine, TimerContext,
//!   ResumeTimer, Period, PreviousState): Period negativo dá
//!   STATUS_INVALID_PARAMETER_6; o handle é referenciado com
//!   TIMER_MODIFY_STATE (outro tipo: STATUS_OBJECT_TYPE_MISMATCH). Sob o lock
//!   do ETIMER (o ExpSetTimerObject): uma APC associada antes sai da lista
//!   ActiveTimerListHead da thread dona, o KTIMER é cancelado, o DPC e a APC
//!   pendentes saem das filas (cada um devolvendo a referência que levava);
//!   sem APC, o KTIMER na fila é cancelado. O estado anterior é o
//!   SignalState depois do cancelamento. Com TimerApcRoutine, a KAPC é
//!   inicializada para a thread corrente (CurrentApcEnvironment,
//!   KernelRoutine = ExpTimerApcRoutine, NormalRoutine = TimerApcRoutine,
//!   modo = o anterior, NormalContext = TimerContext), o ETIMER entra na
//!   lista da thread, ApcAssociated liga, o KTIMER usa o DPC interno e é de
//!   um disparo (o período é refeito pelo DPC), e a referência do handle
//!   fica com a associação; sem APC, o KTIMER é periódico por conta própria,
//!   sem DPC, e a referência é solta. ResumeTimer marca o timer (o OpenNT não
//!   acorda a máquina de um estado de energia).
//! - ExpTimerDpcRoutine: com a APC associada, enfileira a KAPC com a hora do
//!   sistema (LowPart/HighPart, os TimerLowValue/TimerHighValue da rotina);
//!   a APC leva a referência; num timer periódico a referência é tomada de
//!   novo e o KTIMER é rearmado com -Period ms. A falha do enfileiramento
//!   solta a referência.
//! - ExpTimerApcRoutine (a KernelRoutine): na thread dona, um timer de um
//!   disparo sai da lista e desliga ApcAssociated; a referência da entrega é
//!   solta. A NormalRoutine roda depois com (TimerContext, Low, High).
//! - NtCancelTimer(TimerHandle, CurrentState): o mesmo cancelamento
//!   (ExpCancelTimer), CurrentState = SignalState depois dele.
//! - ExpDeleteTimer (a DeleteProcedure do tipo Timer): cancela o KTIMER.
//! - ExTimerRundown, na saída de uma thread: os timers com APC para ela são
//!   cancelados, soltando as referências das associações.

use alloc::vec::Vec;

use crate::ntos::ex::ir_timer;
use crate::ntos::ex::timer as executive_timers;
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{Ethread, Kapc, Kdpc, Ktimer, ListEntry, TimerBasicInformation, TimerSetCoalescableTimerInfo};
use crate::ntos::init::exports::private_routines;
use crate::ntos::ke::{apc, clock, dpc, spin_lock, timer};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_create, object_reference, object_types, open_pointer, reference_trace};
use crate::ntos::ps::{previous_mode, process, user_probe};
use crate::rtl::KernelError;

const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_PARAMETER_3: u32 = 0xC000_00F1;
const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
const STATUS_INVALID_PARAMETER_6: u32 = 0xC000_00F4;
/// TIMER_QUERY_STATE e TIMER_MODIFY_STATE.
const TIMER_QUERY_STATE: u32 = 1;
const TIMER_MODIFY_STATE: u32 = 2;
/// TIMER_SET_INFORMATION_CLASS: TimerSetCoalescableTimer, a única.
const TIMER_SET_COALESCABLE_TIMER: u32 = 0;
/// SynchronizationTimer, o maior TIMER_TYPE.
const SYNCHRONIZATION_TIMER: u32 = 1;
/// CurrentApcEnvironment.
const CURRENT_APC_ENVIRONMENT: u8 = 2;
/// TimerFlags: ApcAssociated e o pedido de ResumeTimer.
const APC_ASSOCIATED: u8 = 1;
const RESUME_REQUESTED: u8 = 4;

/// O corpo do ETIMER no layout do ntoskrnl 19041 (0x148 bytes; opaco para
/// os drivers, que só esperam no KTIMER do início).
#[repr(C)]
struct Etimer {
    ke_timer: Ktimer,
    lock: Field<u64>,
    timer_apc: Kapc,
    timer_dpc: Kdpc,
    active_timer_list_entry: ListEntry,
    period: Field<u32>,
    _wake_and_virtualization: Reserved<0x3C>,
    timer_flags: Field<u8>,
    _due_time: Reserved<0xF>,
    tolerable_delay: Field<u32>,
    _pad_144: Reserved<4>,
}

// SAFETY: #[repr(C)] só de células e de structs do NT.
unsafe impl NtStruct for Etimer {}

const _: () = {
    assert!(core::mem::size_of::<Etimer>() == 0x148);
    assert!(core::mem::offset_of!(Etimer, lock) == 0x40);
    assert!(core::mem::offset_of!(Etimer, timer_apc) == 0x48);
    assert!(core::mem::offset_of!(Etimer, timer_dpc) == 0xA0);
    assert!(core::mem::offset_of!(Etimer, active_timer_list_entry) == 0xE0);
    assert!(core::mem::offset_of!(Etimer, period) == 0xF0);
    assert!(core::mem::offset_of!(Etimer, timer_flags) == 0x130);
    assert!(core::mem::offset_of!(Etimer, tolerable_delay) == 0x140);
};

fn etimer(pointer: u64) -> &'static Etimer {
    // SAFETY: corpo ETIMER vivo, retido por quem chama.
    unsafe { Etimer::at(pointer) }
}

fn ethread(thread: u64) -> &'static Ethread {
    // SAFETY: ETHREAD viva (a dona da APC ou a corrente).
    unsafe { Ethread::at(thread) }
}

fn list_entry(address: u64) -> &'static ListEntry {
    // SAFETY: vínculo de uma lista ActiveTimerListHead viva.
    unsafe { ListEntry::at(address) }
}

/// O OBJECT_TYPE "Timer" (ExTimerObjectType).
fn timer_type() -> u64 {
    executive_timers::timer_type_pointer()
}

/// Liga a DeleteProcedure (ExpDeleteTimer) ao tipo Timer e o rundown dos
/// timers à saída das threads.
pub fn initialize() {
    executive_timers::initialize_type();
    let delete = private_routines::address("ExpDeleteTimer");
    if let Some(info) = object_types::type_object(timer_type()) {
        info.type_info.delete_procedure.set(delete);
    }
    process::register_thread_exit_routine(timer_rundown);
}

fn dereference(pointer: u64, count: u32) -> Result<(), KernelError> {
    for _ in 0..count {
        object_reference::dereference_with_tag(pointer, reference_trace::DEFAULT_TAG, false)?;
    }
    Ok(())
}

/// Insere/remove o ETIMER na ActiveTimerListHead da thread, sob o
/// ActiveTimerListLock dela.
fn link_to_thread(thread: u64, timer: &Etimer) {
    let owner = ethread(thread);
    let lock = owner.active_timer_list_lock.address();
    spin_lock::acquire_at_dpc_level(lock);
    let head = &owner.active_timer_list_head;
    if head.flink.get() == 0 {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    let entry = &timer.active_timer_list_entry;
    let last = head.blink.get();
    entry.flink.set(head.address());
    entry.blink.set(last);
    list_entry(last).flink.set(entry.address());
    head.blink.set(entry.address());
    spin_lock::release_from_dpc_level(lock);
}

fn unlink_from_thread(thread: u64, timer: &Etimer) {
    let lock = ethread(thread).active_timer_list_lock.address();
    spin_lock::acquire_at_dpc_level(lock);
    let entry = &timer.active_timer_list_entry;
    let (next, previous) = (entry.flink.get(), entry.blink.get());
    list_entry(previous).flink.set(next);
    list_entry(next).blink.set(previous);
    spin_lock::release_from_dpc_level(lock);
}

/// ExpCancelTimer, sob o lock do ETIMER: devolve quantas referências o
/// cancelamento liberou (a do KTIMER/DPC pendente e a da APC na fila).
fn cancel_locked(timer: &Etimer) -> Result<u32, KernelError> {
    let flags = timer.timer_flags.get();
    if flags & APC_ASSOCIATED == 0 {
        timer::cancel_timer(timer.ke_timer.address());
        return Ok(0);
    }
    unlink_from_thread(timer.timer_apc.thread.get(), timer);
    timer.timer_flags.set(flags & !APC_ASSOCIATED);
    let mut released = 0;
    if timer::cancel_timer(timer.ke_timer.address()) || dpc::remove_queue_dpc(timer.timer_dpc.address()) {
        released = 1;
    }
    if apc::remove(timer.timer_apc.address())? {
        released += 1;
    }
    Ok(released)
}

/// Referencia o handle como um ETIMER com `access` no modo dado.
fn reference_timer(handle: u64, access: u32, mode: u8) -> Result<Result<u64, u32>, KernelError> {
    reference_object(handle, access, mode, timer_type())
}

/// O ObReferenceObjectByHandle com `access` no modo dado e o tipo
/// `object_type` (0 = qualquer tipo).
fn reference_object(handle: u64, access: u32, mode: u8, object_type: u64) -> Result<Result<u64, u32>, KernelError> {
    let slot = guest::alloc_bytes(8);
    if slot == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let status = object_reference::reference_by_handle(handle, access, object_type, mode, slot, 0)?;
    // SAFETY: célula PVOID recém-alocada.
    let pointer = unsafe { Field::<u64>::at(slot) }.get();
    guest::free_bytes(slot);
    Ok(if status == 0 { Ok(pointer) } else { Err(status as u32) })
}

/// Grava um valor de saída do chamador: sondado em UserMode.
fn write_output<T: crate::ntos::mm::guest_memory::GuestScalar + Copy>(mode: u8, address: u64, value: T) -> Result<bool, KernelError> {
    if mode != 0 {
        if !user_probe::probe_user_write(address, core::mem::size_of::<T>() as u64) {
            return Ok(false);
        }
        return Ok(guest::try_write::<T>(address, value).is_ok());
    }
    guest::write::<T>(address, value);
    Ok(true)
}

/// NtCreateTimer no modo `mode`. Devolve o NTSTATUS.
pub fn create(handle_out: u64, access: u32, attributes: u64, timer_type_value: u32, mode: u8) -> Result<u32, KernelError> {
    if timer_type_value > SYNCHRONIZATION_TIMER {
        return Ok(STATUS_INVALID_PARAMETER_4);
    }
    if mode != 0 && !user_probe::probe_user_write(handle_out, 8) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let cells = guest::alloc_bytes(16);
    if cells == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = object_create::create(mode, timer_type(), attributes, mode, Etimer::SIZE as u32, 0, 0, cells);
    // SAFETY: as duas células PVOID/HANDLE alocadas acima.
    let (object_cell, handle_cell) = unsafe { (Field::<u64>::at(cells), Field::<u64>::at(cells + 8)) };
    let result = (|| -> Result<u32, KernelError> {
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        let pointer = object_cell.get();
        guest::write_bytes(pointer, &[0u8; Etimer::SIZE as usize]);
        let body = etimer(pointer);
        dpc::initialize_kernel_dpc(body.timer_dpc.address(), timer_dpc_routine, pointer);
        timer::initialize_timer_of_type(body.ke_timer.address(), timer_type_value as u64);
        let status = object_create::insert(pointer, access, 0, 0, handle_cell.address())?;
        if status & 0x8000_0000 == 0 && !write_output::<u64>(mode, handle_out, handle_cell.get())? {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        Ok(status)
    })();
    guest::free_bytes(cells);
    result
}

/// NtSetTimer no modo `mode` (TolerableDelay 0). Devolve o NTSTATUS.
#[allow(clippy::too_many_arguments)]
pub fn set(handle: u64, due_time: u64, apc_routine: u64, apc_context: u64, resume: bool, period: i32, previous_state: u64, mode: u8) -> Result<u32, KernelError> {
    let due = if mode != 0 {
        if !user_probe::probe_user_read(due_time, 8) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        guest::try_read::<i64>(due_time)?
    } else {
        guest::read::<i64>(due_time)
    };
    if period < 0 {
        return Ok(STATUS_INVALID_PARAMETER_6);
    }
    let pointer = match reference_timer(handle, TIMER_MODIFY_STATE, mode)? {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    set_object(pointer, mode, due, apc_routine, apc_context, resume, period as u32, 0, previous_state)
}

/// NtSetTimerEx(TimerHandle, TimerSetInformationClass, TimerSetInformation,
/// TimerSetInformationLength) no modo `mode`, como no 19041: em UserMode o
/// buffer é sondado (alinhamento 4) antes de tudo; só existe a classe
/// TimerSetCoalescableTimer (0, senão STATUS_INVALID_INFO_CLASS), de 0x30
/// bytes (senão STATUS_INFO_LENGTH_MISMATCH), capturados de uma vez.
pub fn set_ex(handle: u64, class: u32, information: u64, length: u32, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && length != 0 {
        if information & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_read(information, length as u64) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if class != TIMER_SET_COALESCABLE_TIMER {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if length != TimerSetCoalescableTimerInfo::SIZE as u32 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let size = TimerSetCoalescableTimerInfo::SIZE as usize;
    let copied = if mode != 0 { guest::try_read_bytes(information, size).ok() } else { Some(guest::read_bytes(information, size)) };
    let Some(bytes) = copied else { return Ok(STATUS_ACCESS_VIOLATION) };
    let captured = guest::alloc_bytes(TimerSetCoalescableTimerInfo::SIZE);
    if captured == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(captured, &bytes);
    // SAFETY: a cópia de kernel recém-preenchida acima.
    let result = set_coalescable(handle, unsafe { TimerSetCoalescableTimerInfo::at(captured) }, mode);
    guest::free_bytes(captured);
    result
}

/// O NtSetTimerEx depois da captura: Period acima de MAXLONG dá
/// STATUS_INVALID_PARAMETER_3; o handle é referenciado com
/// TIMER_MODIFY_STATE sem tipo e despachado pelo tipo do objeto: o ETIMER
/// vai ao ExpSetTimerObject com o TolerableDelay (um WakeContext pede o
/// ResumeTimer; o OpenNT não captura o contexto de razão do Po nem acorda a
/// máquina); o IRTimer exige APC, contexto, WakeContext, TolerableDelay e
/// PreviousState nulos (senão STATUS_INVALID_PARAMETER) e vai ao
/// ExpSetTimerObject2 com o período em 100 ns; outro tipo dá
/// STATUS_OBJECT_TYPE_MISMATCH.
fn set_coalescable(handle: u64, info: &TimerSetCoalescableTimerInfo, mode: u8) -> Result<u32, KernelError> {
    let period = info.period.get();
    if period > i32::MAX as u32 {
        return Ok(STATUS_INVALID_PARAMETER_3);
    }
    let (due, apc_routine, apc_context, wake_context) = (info.due_time.quad_part.get(), info.timer_apc_routine.get(), info.timer_context.get(), info.wake_context.get());
    let (tolerable_delay, previous_state) = (info.tolerable_delay.get(), info.previous_state.get());
    let pointer = match reference_object(handle, TIMER_MODIFY_STATE, mode, 0)? {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    let object_type = open_pointer::describe(pointer).map_or(0, |item| item.object_type.pointer);
    if object_type != 0 && object_type == ir_timer::timer_type() {
        if apc_routine != 0 || apc_context != 0 || wake_context != 0 || tolerable_delay != 0 || previous_state != 0 {
            dereference(pointer, 1)?;
            return Ok(STATUS_INVALID_PARAMETER);
        }
        return Ok(ir_timer::set_object(pointer, Some(due), period as i64 * 10_000, None));
    }
    if object_type != timer_type() {
        dereference(pointer, 1)?;
        return Ok(STATUS_OBJECT_TYPE_MISMATCH);
    }
    set_object(pointer, mode, due, apc_routine, apc_context, wake_context != 0, period, tolerable_delay, previous_state)
}

/// ExpSetTimerObject(Timer, PreviousMode, DueTime, TimerApcRoutine,
/// TimerContext, ResumeTimer, Period, TolerableDelay, PreviousState) sobre
/// o ETIMER já referenciado: a referência do handle fica com a associação
/// da APC ou é solta aqui.
#[allow(clippy::too_many_arguments)]
fn set_object(pointer: u64, mode: u8, due: i64, apc_routine: u64, apc_context: u64, resume: bool, period: u32, tolerable_delay: u32, previous_state: u64) -> Result<u32, KernelError> {
    let body = etimer(pointer);
    let irql = spin_lock::acquire(body.lock.address());
    let outcome = (|| -> Result<(u32, u32), KernelError> {
        let released = cancel_locked(body)?;
        let previous = body.ke_timer.header.signal_state.get() as u32;
        body.period.set(period);
        body.tolerable_delay.set(tolerable_delay);
        let flags = body.timer_flags.get() & !RESUME_REQUESTED;
        body.timer_flags.set(if resume { flags | RESUME_REQUESTED } else { flags });
        let mut drop_handle_reference = 1;
        let (dpc_pointer, timer_period) = if apc_routine != 0 {
            let thread = process::get_current_thread();
            apc::initialize(body.timer_apc.address(), thread, CURRENT_APC_ENVIRONMENT, private_routines::address("ExpTimerApcRoutine"), 0, apc_routine, mode, apc_context);
            link_to_thread(thread, body);
            body.timer_flags.set(body.timer_flags.get() | APC_ASSOCIATED);
            drop_handle_reference = 0;
            (body.timer_dpc.address(), 0)
        } else {
            (0, period)
        };
        timer::set_timer(body.ke_timer.address(), due, dpc_pointer, timer_period);
        Ok((released + drop_handle_reference, previous))
    })();
    spin_lock::release(body.lock.address(), irql as u64);
    let (released, previous) = outcome?;
    dereference(pointer, released)?;
    if previous_state != 0 && !write_output::<u8>(mode, previous_state, (previous != 0) as u8)? {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}

/// NtCancelTimer no modo `mode`. Devolve o NTSTATUS.
pub fn cancel(handle: u64, current_state: u64, mode: u8) -> Result<u32, KernelError> {
    if mode != 0 && current_state != 0 && !user_probe::probe_user_write(current_state, 1) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    let pointer = match reference_timer(handle, TIMER_MODIFY_STATE, mode)? {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    let body = etimer(pointer);
    let irql = spin_lock::acquire(body.lock.address());
    let released = cancel_locked(body);
    spin_lock::release(body.lock.address(), irql as u64);
    let state = body.ke_timer.header.signal_state.get();
    dereference(pointer, released? + 1)?;
    if current_state != 0 && !write_output::<u8>(mode, current_state, (state != 0) as u8)? {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}

/// NtQueryTimer(TimerHandle, TimerInformationClass, TimerInformation,
/// TimerInformationLength, ReturnLength) no modo `mode`, como no 19041: só
/// TimerBasicInformation (0, senão STATUS_INVALID_INFO_CLASS) de 0x10 bytes
/// (senão STATUS_INFO_LENGTH_MISMATCH); em UserMode a saída é sondada com
/// alinhamento 4 e o ReturnLength opcional também; o handle é um ETIMER com
/// TIMER_QUERY_STATE (o IRTimer do NtCreateTimer2 dá
/// STATUS_OBJECT_TYPE_MISMATCH). RemainingTime = KeQueryTimerDueTime menos o
/// tempo de interrupção (negativo num timer fora da fila), TimerState = o
/// SignalState do KTIMER.
pub fn query(handle: u64, class: u32, information: u64, length: u32, return_length: u64, mode: u8) -> Result<u32, KernelError> {
    if class != 0 {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if length != TimerBasicInformation::SIZE as u32 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    if mode != 0 {
        if information & 3 != 0 {
            return Ok(STATUS_DATATYPE_MISALIGNMENT);
        }
        if !user_probe::probe_user_write(information, TimerBasicInformation::SIZE) || (return_length != 0 && !user_probe::probe_user_write(return_length, 4)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    let pointer = match reference_timer(handle, TIMER_QUERY_STATE, mode)? {
        Ok(pointer) => pointer,
        Err(status) => return Ok(status),
    };
    let body = etimer(pointer);
    let state = body.ke_timer.header.signal_state.get() as u8;
    let remaining = timer::query_due_time(body.ke_timer.address()).wrapping_sub(clock::uptime_100ns()) as i64;
    dereference(pointer, 1)?;
    let output = information + core::mem::offset_of!(TimerBasicInformation, timer_state) as u64;
    if !write_output::<i64>(mode, information, remaining)? || !write_output::<u8>(mode, output, state)? || (return_length != 0 && !write_output::<u32>(mode, return_length, TimerBasicInformation::SIZE as u32)?) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}

/// ZwCreateTimer/ZwSetTimer/ZwCancelTimer: PreviousMode KernelMode.
pub fn create_kernel(handle_out: u64, access: u32, attributes: u64, timer_type_value: u32) -> Result<u32, KernelError> {
    previous_mode::with_kernel(|| create(handle_out, access, attributes, timer_type_value, 0))?
}

#[allow(clippy::too_many_arguments)]
pub fn set_kernel(handle: u64, due_time: u64, apc_routine: u64, apc_context: u64, resume: bool, period: i32, previous_state: u64) -> Result<u32, KernelError> {
    previous_mode::with_kernel(|| set(handle, due_time, apc_routine, apc_context, resume, period, previous_state, 0))?
}

pub fn cancel_kernel(handle: u64, current_state: u64) -> Result<u32, KernelError> {
    previous_mode::with_kernel(|| cancel(handle, current_state, 0))?
}

/// ExpTimerDpcRoutine(Dpc, Timer, SystemArgument1, SystemArgument2).
fn timer_dpc_routine(_dpc: u64, pointer: u64, _first: u64, _second: u64) {
    let body = etimer(pointer);
    spin_lock::acquire_at_dpc_level(body.lock.address());
    let mut release = 0u32;
    if body.timer_flags.get() & APC_ASSOCIATED != 0 {
        let now = clock::system_time_100ns();
        let inserted = apc::insert(body.timer_apc.address(), now & 0xFFFF_FFFF, now >> 32);
        if !inserted {
            release = 1;
        }
        let period = body.period.get();
        if period != 0 {
            // A APC enfileirada leva a sua referência; a associação continua.
            if inserted {
                let _ = object_reference::reference_with_tag(pointer, reference_trace::DEFAULT_TAG, false);
            }
            release = 0;
            if timer::set_timer(body.ke_timer.address(), -(period as i64 * 10_000), body.timer_dpc.address(), 0) {
                release += 1;
            }
        }
    }
    spin_lock::release_from_dpc_level(body.lock.address());
    let _ = dereference(pointer, release);
}

/// ExpTimerApcRoutine(Apc, NormalRoutine*, NormalContext*, Argument1*,
/// Argument2*): a KernelRoutine da entrega.
pub fn timer_apc_routine(apc_pointer: u64, _normal_routine: u64, _normal_context: u64, _first: u64, _second: u64) -> Result<(), KernelError> {
    let pointer = apc_pointer - core::mem::offset_of!(Etimer, timer_apc) as u64;
    let body = etimer(pointer);
    let irql = spin_lock::acquire(body.lock.address());
    let current = process::get_current_thread();
    if body.timer_flags.get() & APC_ASSOCIATED != 0 && body.timer_apc.thread.get() == current && body.period.get() == 0 {
        unlink_from_thread(current, body);
        body.timer_flags.set(body.timer_flags.get() & !APC_ASSOCIATED);
    }
    spin_lock::release(body.lock.address(), irql as u64);
    dereference(pointer, 1)
}

/// ExpDeleteTimer(Timer): o último ponteiro foi solto.
pub fn delete_timer(pointer: u64) -> Result<(), KernelError> {
    let body = etimer(pointer);
    timer::cancel_timer(body.ke_timer.address());
    // O descritor do DPC interno deixa de ter rotina associada.
    dpc::initialize_dpc(body.timer_dpc.address(), 0, 0);
    Ok(())
}

/// ExTimerRundown(Thread): cancela os timers com APC associada à thread
/// que sai.
fn timer_rundown(thread: u64) {
    let owner = ethread(thread);
    let head = &owner.active_timer_list_head;
    if head.flink.get() == 0 {
        return;
    }
    let mut timers = Vec::new();
    let irql = spin_lock::acquire(owner.active_timer_list_lock.address());
    let mut entry = head.flink.get();
    while entry != head.address() {
        let pointer = entry - core::mem::offset_of!(Etimer, active_timer_list_entry) as u64;
        if object_reference::reference_safe(pointer, reference_trace::DEFAULT_TAG) {
            timers.push(pointer);
        }
        entry = list_entry(entry).flink.get();
    }
    spin_lock::release(owner.active_timer_list_lock.address(), irql as u64);
    for pointer in timers {
        let body = etimer(pointer);
        let irql = spin_lock::acquire(body.lock.address());
        let released = if body.timer_flags.get() & APC_ASSOCIATED != 0 && body.timer_apc.thread.get() == thread { cancel_locked(body).unwrap_or(0) } else { 0 };
        spin_lock::release(body.lock.address(), irql as u64);
        let _ = dereference(pointer, released + 1);
    }
}
