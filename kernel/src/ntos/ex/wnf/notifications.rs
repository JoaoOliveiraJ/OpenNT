//! Entrega WNF.
//!
//! A fila de cada processo conserva máscaras pendentes e o estado de
//! entrega; callbacks de kernel usam o work item real e eventos de usuário
//! usam o dispatcher real. Instância única, ligada ao namespace do serviço.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::ntos::ex::{push_lock, rundown};
use crate::ntos::ex::wnf::name as wnf_name;
use crate::hal::amd64::native_call;
use crate::ntos::io::work_items;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::mm::kernel_pool;
use crate::ntos::ob::open_pointer;
use crate::ntos::ps::{previous_mode, process, process_context};
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const STATE_TAG: u32 = 0x2066_6E57;
const PROCESS_CONTEXT_OFFSET: u64 = 0x868;

static WORK_ITEM: AtomicU64 = AtomicU64::new(0);
static SCHEDULED: AtomicBool = AtomicBool::new(false);
static REQUESTED: AtomicBool = AtomicBool::new(false);
static ACTIVE_DISPATCHERS: AtomicU32 = AtomicU32::new(0);

fn locked<T>(pointer: u64, exclusive: bool, action: impl FnOnce() -> Result<T, KernelError>) -> Result<T, KernelError> {
    if exclusive {
        push_lock::acquire_exclusive(pointer, 0)?;
    } else {
        push_lock::acquire_shared(pointer, 0)?;
    }
    let result = action();
    if exclusive {
        push_lock::release_exclusive(pointer, 0)?;
    } else {
        push_lock::release_shared(pointer, 0)?;
    }
    result
}

/// Contador de 32 bits por compare-exchange; devolve o novo valor.
pub fn change_counter(pointer: u64, delta: i32) -> Result<u32, KernelError> {
    let mut previous = guest::read32(pointer);
    loop {
        let next = previous.wrapping_add(delta as u32);
        let observed = guest::compare_exchange32(pointer, previous, next)?;
        if observed == previous {
            return Ok(next);
        }
        previous = observed;
    }
}

fn unlink(entry: u64) -> Result<(), KernelError> {
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("corrupt WNF subscription list"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    Ok(())
}

fn insert_last(head: u64, entry: u64) -> Result<(), KernelError> {
    let previous = guest::read64(head + 8);
    if guest::read64(previous) != head {
        return Err(KernelError::new("corrupt WNF pending queue"));
    }
    guest::write64(entry, head);
    guest::write64(entry + 8, previous);
    guest::write64(previous, entry);
    guest::write64(head + 8, entry);
    Ok(())
}

/// Verdadeiro só quando o assinante precisa acordar o consumidor; repetidas
/// atualizações acumulam a máscara sem duplicar o nó na fila.
pub fn enqueue(subscription: u64, event_mask: u32) -> Result<bool, KernelError> {
    let owner = guest::read64(subscription + 0x28);
    if owner == 0 {
        return Ok(false);
    }
    let context = guest::read64(owner + PROCESS_CONTEXT_OFFSET);
    if context == 0 {
        return Err(KernelError::new("WNF subscription owner has no context"));
    }
    locked(context + 0x68, true, || {
        let interest = guest::read32(subscription + 0x64);
        let accepted = event_mask & interest;
        if accepted == 0 {
            return Ok(false);
        }
        let state = guest::read32(subscription + 0x78);
        let mut wake = false;
        if state == 0 {
            insert_last(context + 0x70, subscription + 0x68)?;
            wake = true;
        } else if state == 3 {
            wake = true;
        }
        if wake {
            guest::write32(subscription + 0x78, 1);
        }
        let pending = guest::read32(subscription + 0x7C);
        let delivering = guest::read32(subscription + 0x80);
        if accepted & 1 != 0 && (pending | delivering) & 1 == 0 {
            change_counter(guest::read64(subscription + 0x30) + 0xA4, 1)?;
        }
        guest::write32(subscription + 0x7C, (pending | accepted) & interest);
        Ok(wake)
    })
}

/// Reserva o work item do dispatcher de kernel; `false` sem memória.
pub fn create() -> Result<bool, KernelError> {
    if WORK_ITEM.load(Ordering::Acquire) != 0 {
        return Err(KernelError::new("WNF notifications already exist"));
    }
    let item = guest::alloc_bytes(0x80);
    if item == 0 {
        return Ok(false);
    }
    work_items::create_work_item(0, item);
    WORK_ITEM.store(item, Ordering::Release);
    SCHEDULED.store(false, Ordering::Release);
    REQUESTED.store(false, Ordering::Release);
    Ok(true)
}

fn signal_process(process: u64) {
    let context = guest::read64(process + PROCESS_CONTEXT_OFFSET);
    let event = guest::read64(context + 0x80);
    if event != 0 {
        dispatcher::set_event(event);
    }
}

/// Notificação inicial de uma inscrição recém-criada ou atualizada; o
/// consumidor é acordado depois de liberar o lock do nome.
pub fn notify_subscription(name: u64, subscription: u64, event_mask: u32, inline: bool) -> Result<(), KernelError> {
    let process = locked(name + 0x70, false, || {
        if guest::read64(subscription + 0x30) == 0 {
            return Ok(0);
        }
        Ok(if enqueue(subscription, event_mask)? { guest::read64(subscription + 0x28) } else { 0 })
    })?;
    if process == 0 {
        return Ok(());
    }
    if process == process::get_system_process() {
        start_kernel_dispatcher(inline)
    } else {
        signal_process(process);
        Ok(())
    }
}

/// Enfileira para todos os assinantes do nome. Sem leitores de dados, a
/// conclusão (máscara 8) é anunciada logo.
pub fn notify_name(name: u64, event_mask: u32, start_dispatcher: bool, inline: bool) -> Result<(), KernelError> {
    let system = process::get_system_process();
    let (has_data_subscribers, kernel_pending) = locked(name + 0x70, false, || {
        let mut data = false;
        let mut kernel = false;
        let head = name + 0x78;
        let mut entry = guest::read64(head);
        while entry != head {
            let subscription = entry - 0x40;
            if guest::read32(subscription + 0x64) & 1 != 0 {
                data = true;
            }
            if enqueue(subscription, event_mask)? {
                let process = guest::read64(subscription + 0x28);
                if process == system {
                    kernel = true;
                } else {
                    signal_process(process);
                }
            }
            entry = guest::read64(entry);
        }
        Ok((data, kernel))
    })?;
    if !has_data_subscribers && event_mask & 1 != 0 {
        notify_name(name, 8, !kernel_pending && start_dispatcher, inline)?;
    }
    if kernel_pending && start_dispatcher {
        start_kernel_dispatcher(inline)?;
    }
    Ok(())
}

/// Callback de kernel: (inscrição, &nome, máscara, carimbo, TypeId, contexto).
fn invoke_callback(subscription: u64, name: u64, event_mask: u32) -> Result<(), KernelError> {
    let frame = guest::alloc_bytes(64);
    if frame == 0 {
        return Err(KernelError::new("WNF callback argument frame allocation failed"));
    }
    guest::write64(frame + 48, guest::read64(subscription + 0x38) ^ wnf_name::NAME_MASK);
    let stamp = if name != 0 && event_mask & 1 != 0 { guest::read32(name + 0x60) as u64 } else { 0 };
    let type_identifier = if name != 0 { guest::read64(name + 0x40) } else { 0 };
    native_call::call(guest::read64(subscription + 0x50), &[subscription, frame + 48, event_mask as u64, stamp, type_identifier, guest::read64(subscription + 0x58)]);
    guest::free_bytes(frame);
    Ok(())
}

/// Consome a fila do processo do sistema, chamando cada callback com a
/// máscara entregue (dados só com carimbo novo).
pub fn dispatch_kernel_subscriptions() -> Result<(), KernelError> {
    let context = guest::read64(process::get_system_process() + PROCESS_CONTEXT_OFFSET);
    if context == 0 {
        return Ok(());
    }
    let pending_lock = context + 0x68;
    let pending_head = context + 0x70;
    loop {
        let subscription = locked(pending_lock, true, || {
            let entry = guest::read64(pending_head);
            if entry == pending_head {
                return Ok(0);
            }
            let pointer = entry - 0x68;
            if !rundown::acquire(pointer + 8)? {
                return Err(KernelError::new("queued WNF subscription is being freed"));
            }
            guest::write32(pointer + 0x78, 2);
            unlink(entry)?;
            Ok(pointer)
        })?;
        if subscription == 0 {
            return Ok(());
        }
        let result = (|| -> Result<(), KernelError> {
            loop {
                let pending = locked(pending_lock, true, || {
                    let mask = guest::read32(subscription + 0x7C);
                    guest::write32(subscription + 0x7C, 0);
                    Ok(mask)
                })?;
                let mut delivered = pending;
                let name = locked(context + 0x50, false, || {
                    let mut name = guest::read64(subscription + 0x30);
                    if name != 0 && !rundown::acquire(name + 8)? {
                        name = 0;
                    }
                    if name == 0 {
                        delivered &= !1;
                    } else if delivered & 1 != 0 {
                        let stamp = guest::read32(name + 0x60);
                        if stamp <= guest::read32(subscription + 0x60) {
                            delivered &= !1;
                        } else {
                            guest::write32(subscription + 0x60, stamp);
                        }
                    }
                    Ok(name)
                })?;
                let delivery = (|| -> Result<(), KernelError> {
                    if delivered != 0 {
                        invoke_callback(subscription, name, delivered)?;
                    }
                    if delivered & 1 != 0 && change_counter(name + 0xA4, -1)? == 0 {
                        notify_name(name, 8, false, false)?;
                    }
                    Ok(())
                })();
                if name != 0 {
                    rundown::release(name + 8)?;
                }
                delivery?;
                let repeat = locked(pending_lock, true, || {
                    if guest::read32(subscription + 0x7C) != 0 {
                        return Ok(true);
                    }
                    guest::write32(subscription + 0x78, 0);
                    Ok(false)
                })?;
                if !repeat {
                    return Ok(());
                }
            }
        })();
        rundown::release(subscription + 8)?;
        result?;
    }
}

fn dispatch_with_kernel_context() -> Result<(), KernelError> {
    ACTIVE_DISPATCHERS.fetch_add(1, Ordering::AcqRel);
    let result = process_context::with_process(process::get_system_process(), || {
        previous_mode::with_kernel(|| -> Result<(), KernelError> {
            let previous = silo_query::attach(0);
            let entered = critical_region::enter_critical();
            let dispatched = if entered.is_ok() { dispatch_kernel_subscriptions() } else { Ok(()) };
            let left = if entered.is_ok() { critical_region::leave_critical() } else { Ok(()) };
            silo_query::detach(previous);
            entered?;
            dispatched?;
            left
        })
    });
    ACTIVE_DISPATCHERS.fetch_sub(1, Ordering::AcqRel);
    result???;
    Ok(())
}

fn worker(_item: u64, _context: u64) {
    while REQUESTED.swap(false, Ordering::AcqRel) {
        if let Err(error) = dispatch_with_kernel_context() {
            debug_print!("[wnf] {}", error);
        }
    }
    SCHEDULED.store(false, Ordering::Release);
}

/// Entrega inline ou pelo work item (pedidos agrupados enquanto agendado).
pub fn start_kernel_dispatcher(inline: bool) -> Result<(), KernelError> {
    let item = WORK_ITEM.load(Ordering::Acquire);
    if item == 0 {
        return Err(KernelError::new("WNF dispatcher already disposed"));
    }
    if inline {
        return dispatch_with_kernel_context();
    }
    REQUESTED.store(true, Ordering::Release);
    if SCHEDULED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    work_items::queue_kernel_work_item(item, worker, 0, None);
    Ok(())
}

/// Desliga os assinantes de um nome antes do rundown dele; a inscrição
/// continua do processo.
pub fn detach_name(name: u64) -> Result<(), KernelError> {
    let head = name + 0x78;
    loop {
        let subscription = locked(name + 0x70, true, || {
            let entry = guest::read64(head);
            if entry == head {
                return Ok(0);
            }
            let pointer = entry - 0x40;
            if !rundown::acquire(pointer + 8)? {
                return Err(KernelError::new("linked WNF subscription is in rundown"));
            }
            Ok(pointer)
        })?;
        if subscription == 0 {
            return Ok(());
        }
        let process = guest::read64(subscription + 0x28);
        let context = guest::read64(process + PROCESS_CONTEXT_OFFSET);
        let result = locked(context + 0x50, true, || {
            locked(name + 0x70, true, || {
                if guest::read64(subscription + 0x30) == name {
                    unlink(subscription + 0x40)?;
                    guest::write64(subscription + 0x30, 0);
                }
                Ok(())
            })
        });
        rundown::release(subscription + 8)?;
        result?;
    }
}

/// Remove o assinante de todas as listas na desmontagem do processo; o
/// corpo só sai do pool quando callbacks e consultas devolvem o rundown.
pub fn delete_process_subscriptions(process: u64, context: u64) -> Result<(), KernelError> {
    let head = context + 0x58;
    let system = process::get_system_process();
    loop {
        let mut name = 0u64;
        let mut last_data_subscriber = false;
        let mut delivery_completed = false;
        let subscription = locked(context + 0x50, true, || {
            let entry = guest::read64(head);
            if entry == head {
                return Ok(0);
            }
            let pointer = entry - 0x18;
            name = guest::read64(pointer + 0x30);
            let mut remove = || -> Result<u64, KernelError> {
                if name != 0 {
                    if !rundown::acquire(name + 8)? {
                        return Err(KernelError::new("WNF subscriber references a closing name"));
                    }
                    unlink(pointer + 0x40)?;
                    guest::write64(pointer + 0x30, 0);
                    if guest::read32(pointer + 0x64) & 1 != 0 {
                        last_data_subscriber = change_counter(name + 0xA0, -1)? == 0;
                    }
                }
                unlink(pointer + 0x18)?;
                locked(context + 0x68, true, || {
                    let state = guest::read32(pointer + 0x78);
                    if state == 1 || (process != system && state != 0) {
                        unlink(pointer + 0x68)?;
                        if name != 0 && guest::read32(pointer + 0x64) & 1 != 0 && (guest::read32(pointer + 0x7C) | guest::read32(pointer + 0x80)) & 1 != 0 {
                            delivery_completed = change_counter(name + 0xA4, -1)? == 0;
                        }
                    }
                    guest::write64(pointer + 0x28, 0);
                    Ok(())
                })?;
                Ok(pointer)
            };
            if name != 0 { locked(name + 0x70, true, remove) } else { remove() }
        })?;
        if subscription == 0 {
            break;
        }
        let inline = process != system;
        let notified = (|| -> Result<(), KernelError> {
            if delivery_completed {
                notify_name(name, 8, true, inline)?;
            }
            if last_data_subscriber {
                notify_name(name, 4, true, inline)?;
            }
            Ok(())
        })();
        if name != 0 {
            rundown::release(name + 8)?;
        }
        notified?;
        rundown::wait(subscription + 8)?;
        let _ = kernel_pool::free(subscription, Some(STATE_TAG));
    }
    let event = guest::read64(context + 0x80);
    if event != 0 {
        if let Some(described) = open_pointer::describe(event) {
            described.dereference();
        }
        guest::write64(context + 0x80, 0);
    }
    Ok(())
}

/// Versões para o ciclo de vida do namespace (`fn` sem resultado).
pub fn detach_name_hook(name: u64) {
    if let Err(error) = detach_name(name) {
        debug_print!("[wnf] {}", error);
    }
}

pub fn delete_process_subscriptions_hook(process: u64, context: u64) {
    if let Err(error) = delete_process_subscriptions(process, context) {
        debug_print!("[wnf] {}", error);
    }
}

pub fn dispose() -> Result<(), KernelError> {
    let item = WORK_ITEM.load(Ordering::Acquire);
    if item == 0 || ACTIVE_DISPATCHERS.load(Ordering::Acquire) != 0 {
        return Err(KernelError::new("WNF dispatcher is active or already disposed"));
    }
    work_items::unqueue(item);
    guest::free_bytes(item);
    REQUESTED.store(false, Ordering::Release);
    SCHEDULED.store(false, Ordering::Release);
    WORK_ITEM.store(0, Ordering::Release);
    Ok(())
}
