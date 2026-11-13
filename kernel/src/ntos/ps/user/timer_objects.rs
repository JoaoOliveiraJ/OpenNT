//! Timers de usuário (NtCreateTimer2) — `system32/ntos/ps/user/timer-objects.js`.
//!
//! O prazo e o período ficam em unidades de 100 ns inteiras (o original
//! guardava ms em ponto flutuante: as mesmas contas sem perder a fração).
//! `pump` sinaliza os vencidos e reprograma os periódicos.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::registry::parse_user_object_attributes;
use super::state;
use crate::ntos::ke::{clock, dispatcher};
use crate::ntos::ob::objects::dispatcher::{self as dispatcher_objects, DispatcherHooks, UserDispatcher};
use crate::ntos::ob::object_manager::{self, NodeId};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

/// Prazo (absoluto, em 100 ns do relógio do sistema) e período.
#[derive(Clone, Copy, Default)]
struct Schedule {
    due: Option<i64>,
    period: i64,
}

pub struct TimerObject {
    pub pointer: u64,
    pub name: String,
    pub attributes: u32,
    schedule: SpinLock<Schedule>,
    node: SpinLock<Option<NodeId>>,
}

static TIMERS: SpinLock<BTreeMap<u64, Arc<TimerObject>>> = SpinLock::new(BTreeMap::new());

fn now() -> i64 {
    clock::now_ms() as i64 * 10_000
}

fn signed64(at: u64) -> i64 {
    guest::read64(at) as i64
}

fn dispose(pointer: u64) {
    let timer = TIMERS.lock().remove(&pointer);
    if let Some(node) = timer.and_then(|timer| timer.node.lock().take()) {
        object_manager::remove_named(node);
    }
    guest::free_bytes(pointer);
}

fn publish(timer: &Arc<TimerObject>, out: u64, access: u32, attributes: u64, success: u32) -> Result<u32, KernelError> {
    let flags = if attributes != 0 { guest::read32(attributes + 24) } else { 0 };
    dispatcher_objects::publish(timer.pointer, out, access, flags, success, false, Some(timer.clone()))
}

fn timer_of_node(node: NodeId) -> Option<Arc<TimerObject>> {
    let pointer = object_manager::node(node)?.data?.native_pointer;
    TIMERS.lock().get(&pointer).cloned()
}

fn resolve(handle: u64, access: u32) -> Result<Arc<TimerObject>, u32> {
    let Some(entry) = state::get_user_handle(handle) else { return Err(0xC000_0008) };
    if entry.kind() != "timer" {
        return Err(0xC000_0024);
    }
    if entry.access() & access != access {
        return Err(0xC000_0022);
    }
    entry.downcast::<UserDispatcher>().and_then(|dispatcher| dispatcher.payload.clone()).and_then(|payload| payload.downcast::<TimerObject>().ok()).ok_or(0xC000_0024)
}

/// NtCreateTimer2(out, id, oa, attributes, access): provedores IR e prazos
/// de alta resolução ainda não são expostos pela HAL (0xC00000BB).
fn nt_create_timer2(out: u64, id: u64, attributes: u64, timer_attributes: u64, rsp: u64) -> Result<u32, KernelError> {
    if !state::probe_user_write(out, 8) || (attributes != 0 && !state::probe_user_read(attributes, 48)) {
        return Ok(0xC000_0005);
    }
    let timer_attributes = timer_attributes as u32;
    if timer_attributes & !0x8000_000E != 0 {
        return Ok(0xC000_000D);
    }
    if id != 0 || timer_attributes & 6 != 0 {
        return Ok(0xC000_00BB);
    }
    let access = state::stack_arg32(rsp, 5);
    let name = if attributes != 0 {
        match parse_user_object_attributes(attributes) {
            Some(parsed) => parsed.path,
            None => return Ok(0xC000_000D),
        }
    } else {
        String::new()
    };
    let cut = name.rfind('\\').unwrap_or(0);
    let parent = if cut == 0 { String::from("\\") } else { String::from(&name[..cut]) };
    if !name.is_empty() {
        if let Some(node) = object_manager::lookup(&name) {
            if object_manager::node(node).is_none_or(|node| node.type_name != "Timer") {
                return Ok(0xC000_0024);
            }
            if guest::read32(attributes + 24) & 0x80 == 0 {
                return Ok(0xC000_0035);
            }
            let Some(timer) = timer_of_node(node) else { return Ok(0xC000_0024) };
            return publish(&timer, out, access, attributes, 0x4000_0000);
        }
        if object_manager::lookup(&parent).and_then(object_manager::node).is_none_or(|node| node.type_name != "Directory") {
            return Ok(0xC000_003A);
        }
    }
    let pointer = guest::alloc_bytes(0x40);
    if pointer == 0 {
        return Ok(0xC000_0017);
    }
    dispatcher::initialize_event(pointer, if timer_attributes & 0x8000_0000 != 0 { 8 } else { 9 }, false);
    guest::write8(pointer + 2, 0x40 / 4);
    let timer = Arc::new(TimerObject { pointer, name: name.clone(), attributes: timer_attributes, schedule: SpinLock::new(Schedule::default()), node: SpinLock::new(None) });
    if let Err(error) = dispatcher_objects::create(pointer, "timer", dispose, None, attributes, true, DispatcherHooks::default()) {
        guest::free_bytes(pointer);
        return if error.status != 0 { Ok(error.status) } else { Err(error) };
    }
    TIMERS.lock().insert(pointer, timer.clone());
    if !name.is_empty() {
        match object_manager::create_object(&parent, &name[cut + 1..], "Timer", Some(dispatcher_objects::data(pointer))) {
            Ok(node) => *timer.node.lock() = Some(node),
            Err(error) => {
                dispatcher_objects::collect(pointer);
                return if error.status != 0 { Ok(error.status) } else { Err(error) };
            }
        }
    }
    publish(&timer, out, access, attributes, 0)
}

/// NtSetTimer2(handle, due*, period*, parameters*): prazo relativo
/// (negativo) ou absoluto em FILETIME; T2_SET_PARAMETERS com Version 0 e
/// NoWakeTolerance >= -1 (o DWORD em +4 é preenchimento).
fn nt_set_timer2(handle: u64, due: u64, period: u64, parameters: u64, _rsp: u64) -> Result<u32, KernelError> {
    let timer = match resolve(handle, 2) {
        Ok(timer) => timer,
        Err(status) => return Ok(status),
    };
    if !state::probe_user_read(due, 8) || (period != 0 && !state::probe_user_read(period, 8)) || (parameters != 0 && !state::probe_user_read(parameters, 16)) {
        return Ok(0xC000_0005);
    }
    if parameters != 0 && (guest::read32(parameters) != 0 || signed64(parameters + 8) < -1) {
        debug_print!("[timer] T2_SET_PARAMETERS version={} reserved={} tolerance={}", guest::read32(parameters), guest::read32(parameters + 4), signed64(parameters + 8));
        return Ok(0xC000_000D);
    }
    let interval = if period != 0 { signed64(period) } else { 0 };
    if interval < 0 {
        debug_print!("[timer] invalid period={}", interval);
        return Ok(0xC000_000D);
    }
    let value = signed64(due);
    let absolute = if value < 0 { now() - value } else { value - 116_444_736_000_000_000 };
    *timer.schedule.lock() = Schedule { due: Some(absolute), period: interval };
    dispatcher::reset_event(timer.pointer);
    Ok(0)
}

fn nt_cancel_timer2(handle: u64, parameters: u64, _a3: u64, _a4: u64, _rsp: u64) -> Result<u32, KernelError> {
    let timer = match resolve(handle, 2) {
        Ok(timer) => timer,
        Err(status) => return Ok(status),
    };
    if parameters != 0 {
        return Ok(0xC000_000D);
    }
    timer.schedule.lock().due = None;
    Ok(0)
}

/// NtQueryTimer(TimerBasicInformation): tempo restante e estado.
fn nt_query_timer(handle: u64, class: u64, out: u64, length: u64, rsp: u64) -> Result<u32, KernelError> {
    let timer = match resolve(handle, 1) {
        Ok(timer) => timer,
        Err(status) => return Ok(status),
    };
    if class != 0 {
        return Ok(0xC000_0003);
    }
    let returned = state::stack_arg(rsp, 5);
    if returned != 0 && !state::probe_user_write(returned, 4) {
        return Ok(0xC000_0005);
    }
    if returned != 0 {
        guest::write32(returned, 16);
    }
    if length != 16 {
        return Ok(0xC000_0004);
    }
    if !state::probe_user_write(out, 16) {
        return Ok(0xC000_0005);
    }
    let remaining = timer.schedule.lock().due.map_or(0, |due| (due - now()).max(0));
    guest::write64(out, remaining as u64);
    guest::write64(out + 8, (dispatcher::read_state(timer.pointer) != 0) as u64);
    Ok(0)
}

/// Sinaliza os timers vencidos e reprograma os periódicos.
pub fn pump() {
    let current = now();
    let timers: Vec<Arc<TimerObject>> = TIMERS.lock().values().cloned().collect();
    for timer in timers {
        let fire = {
            let mut schedule = timer.schedule.lock();
            match schedule.due {
                Some(due) if due <= current => {
                    schedule.due = if schedule.period != 0 { Some(due + ((current - due) / schedule.period + 1) * schedule.period) } else { None };
                    true
                }
                _ => false,
            }
        };
        if fire {
            dispatcher::set_event(timer.pointer);
        }
    }
}

pub fn init() {
    state::register_handler("NtCreateTimer2", nt_create_timer2);
    state::register_handler("NtSetTimer2", nt_set_timer2);
    state::register_handler("NtCancelTimer2", nt_cancel_timer2);
    state::register_handler("NtQueryTimer", nt_query_timer);
}
