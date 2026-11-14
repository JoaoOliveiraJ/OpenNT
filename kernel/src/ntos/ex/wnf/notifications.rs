//! Entrega WNF.
//!
//! A fila de cada processo conserva máscaras pendentes e o estado de
//! entrega; callbacks de kernel usam o work item real e eventos de usuário
//! usam o dispatcher real. Instância única, ligada ao namespace do serviço.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use core::mem::offset_of;

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
use super::objects::{name_at, process_at, process_context_at, subscription_at};
use crate::ntos::ex::list_entry;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{WnfStateName, WnfSubscription, WnfSubscriptionState};

const STATE_TAG: u32 = 0x2066_6E57;

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

/// Contador de 32 bits (DataSubscribersCount/CurrentDeliveryCount) por
/// LOCK XADD; devolve o novo valor.
pub fn change_counter(counter: &Field<i32>, delta: i32) -> Result<u32, KernelError> {
    Ok(counter.atomic().fetch_add(delta, Ordering::SeqCst).wrapping_add(delta) as u32)
}

fn unlink(entry: u64) -> Result<(), KernelError> {
    list_entry::remove(list_entry::at(entry)).map(|_| ()).ok_or_else(|| KernelError::new("corrupt WNF subscription list"))
}

fn insert_last(head: u64, entry: u64) -> Result<(), KernelError> {
    let head = list_entry::at(head);
    if !list_entry::tail_consistent(head) {
        return Err(KernelError::new("corrupt WNF pending queue"));
    }
    list_entry::insert_tail(head, list_entry::at(entry));
    Ok(())
}

/// Verdadeiro só quando o assinante precisa acordar o consumidor; repetidas
/// atualizações acumulam a máscara sem duplicar o nó na fila.
pub fn enqueue(subscription: u64, event_mask: u32) -> Result<bool, KernelError> {
    let owner = subscription_at(subscription).process.get();
    if owner == 0 {
        return Ok(false);
    }
    let context = process_at(owner).wnf_context.get();
    if context == 0 {
        return Err(KernelError::new("WNF subscription owner has no context"));
    }
    locked(process_context_at(context).delivery_pending_list_lock.address(), true, || {
        let interest = subscription_at(subscription).subscribed_event_set.get();
        let accepted = event_mask & interest;
        if accepted == 0 {
            return Ok(false);
        }
        let state = subscription_at(subscription).subscription_state.get().0;
        let mut wake = false;
        if state == 0 {
            insert_last(process_context_at(context).delivery_pending_list_head.address(), subscription_at(subscription).pending_subscription_list_entry.address())?;
            wake = true;
        } else if state == 3 {
            wake = true;
        }
        if wake {
            subscription_at(subscription).subscription_state.set(WnfSubscriptionState(1));
        }
        let pending = subscription_at(subscription).signaled_event_set.get();
        let delivering = subscription_at(subscription).in_delivery_event_set.get();
        if accepted & 1 != 0 && (pending | delivering) & 1 == 0 {
            change_counter(&name_at(subscription_at(subscription).name_instance.get()).current_delivery_count, 1)?;
        }
        subscription_at(subscription).signaled_event_set.set((pending | accepted) & interest);
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
    let context = process_at(process).wnf_context.get();
    let event = process_context_at(context).notification_event.get();
    if event != 0 {
        dispatcher::set_event(event);
    }
}

/// Notificação inicial de uma inscrição recém-criada ou atualizada; o
/// consumidor é acordado depois de liberar o lock do nome.
pub fn notify_subscription(name: u64, subscription: u64, event_mask: u32, inline: bool) -> Result<(), KernelError> {
    let process = locked(name_at(name).state_subscription_list_lock.address(), false, || {
        if subscription_at(subscription).name_instance.get() == 0 {
            return Ok(0);
        }
        Ok(if enqueue(subscription, event_mask)? { subscription_at(subscription).process.get() } else { 0 })
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
    let (has_data_subscribers, kernel_pending) = locked(name_at(name).state_subscription_list_lock.address(), false, || {
        let mut data = false;
        let mut kernel = false;
        let head = name_at(name).state_subscription_list_head.address();
        let mut entry = list_entry::at(head).flink.get();
        while entry != head {
            let subscription = entry - offset_of!(WnfSubscription, state_subscription_list_entry) as u64;
            if subscription_at(subscription).subscribed_event_set.get() & 1 != 0 {
                data = true;
            }
            if enqueue(subscription, event_mask)? {
                let process = subscription_at(subscription).process.get();
                if process == system {
                    kernel = true;
                } else {
                    signal_process(process);
                }
            }
            entry = list_entry::at(entry).flink.get();
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
    // O nome externo (WNF_STATE_NAME) vai por ponteiro, numa célula própria.
    let frame = guest::alloc_bytes(WnfStateName::SIZE);
    if frame == 0 {
        return Err(KernelError::new("WNF callback argument frame allocation failed"));
    }
    // SAFETY: alocação nova de 8 bytes.
    unsafe { Field::<u64>::at(frame) }.set(subscription_at(subscription).state_name.bitfield_0.get() ^ wnf_name::NAME_MASK);
    let stamp = if name != 0 && event_mask & 1 != 0 { name_at(name).current_change_stamp.get() as u64 } else { 0 };
    let type_identifier = if name != 0 { name_at(name).state_name_info.type_id.get() } else { 0 };
    native_call::call(subscription_at(subscription).callback_routine.get(), &[subscription, frame, event_mask as u64, stamp, type_identifier, subscription_at(subscription).callback_context.get()]);
    guest::free_bytes(frame);
    Ok(())
}

/// Consome a fila do processo do sistema, chamando cada callback com a
/// máscara entregue (dados só com carimbo novo).
pub fn dispatch_kernel_subscriptions() -> Result<(), KernelError> {
    let context = process_at(process::get_system_process()).wnf_context.get();
    if context == 0 {
        return Ok(());
    }
    let pending_lock = process_context_at(context).delivery_pending_list_lock.address();
    let pending_head = process_context_at(context).delivery_pending_list_head.address();
    loop {
        let subscription = locked(pending_lock, true, || {
            let entry = list_entry::at(pending_head).flink.get();
            if entry == pending_head {
                return Ok(0);
            }
            let pointer = entry - offset_of!(WnfSubscription, pending_subscription_list_entry) as u64;
            if !rundown::acquire(subscription_at(pointer).run_ref.address())? {
                return Err(KernelError::new("queued WNF subscription is being freed"));
            }
            subscription_at(pointer).subscription_state.set(WnfSubscriptionState(2));
            unlink(entry)?;
            Ok(pointer)
        })?;
        if subscription == 0 {
            return Ok(());
        }
        let result = (|| -> Result<(), KernelError> {
            loop {
                let pending = locked(pending_lock, true, || {
                    let mask = subscription_at(subscription).signaled_event_set.get();
                    subscription_at(subscription).signaled_event_set.set(0);
                    Ok(mask)
                })?;
                let mut delivered = pending;
                let name = locked(process_context_at(context).process_subscription_list_lock.address(), false, || {
                    let mut name = subscription_at(subscription).name_instance.get();
                    if name != 0 && !rundown::acquire(name_at(name).run_ref.address())? {
                        name = 0;
                    }
                    if name == 0 {
                        delivered &= !1;
                    } else if delivered & 1 != 0 {
                        let stamp = name_at(name).current_change_stamp.get();
                        if stamp <= subscription_at(subscription).current_change_stamp.get() {
                            delivered &= !1;
                        } else {
                            subscription_at(subscription).current_change_stamp.set(stamp);
                        }
                    }
                    Ok(name)
                })?;
                let delivery = (|| -> Result<(), KernelError> {
                    if delivered != 0 {
                        invoke_callback(subscription, name, delivered)?;
                    }
                    if delivered & 1 != 0 && change_counter(&name_at(name).current_delivery_count, -1)? == 0 {
                        notify_name(name, 8, false, false)?;
                    }
                    Ok(())
                })();
                if name != 0 {
                    rundown::release(name_at(name).run_ref.address())?;
                }
                delivery?;
                let repeat = locked(pending_lock, true, || {
                    if subscription_at(subscription).signaled_event_set.get() != 0 {
                        return Ok(true);
                    }
                    subscription_at(subscription).subscription_state.set(WnfSubscriptionState(0));
                    Ok(false)
                })?;
                if !repeat {
                    return Ok(());
                }
            }
        })();
        rundown::release(subscription_at(subscription).run_ref.address())?;
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
    let head = name_at(name).state_subscription_list_head.address();
    loop {
        let subscription = locked(name_at(name).state_subscription_list_lock.address(), true, || {
            let entry = list_entry::at(head).flink.get();
            if entry == head {
                return Ok(0);
            }
            let pointer = entry - offset_of!(WnfSubscription, state_subscription_list_entry) as u64;
            if !rundown::acquire(subscription_at(pointer).run_ref.address())? {
                return Err(KernelError::new("linked WNF subscription is in rundown"));
            }
            Ok(pointer)
        })?;
        if subscription == 0 {
            return Ok(());
        }
        let process = subscription_at(subscription).process.get();
        let context = process_at(process).wnf_context.get();
        let result = locked(process_context_at(context).process_subscription_list_lock.address(), true, || {
            locked(name_at(name).state_subscription_list_lock.address(), true, || {
                if subscription_at(subscription).name_instance.get() == name {
                    unlink(subscription_at(subscription).state_subscription_list_entry.address())?;
                    subscription_at(subscription).name_instance.set(0);
                }
                Ok(())
            })
        });
        rundown::release(subscription_at(subscription).run_ref.address())?;
        result?;
    }
}

/// O que a remoção de um assinante deixa para anunciar depois dos locks.
struct Removed {
    name: u64,
    last_data_subscriber: bool,
    delivery_completed: bool,
}

/// Tira a inscrição das listas do nome, do processo e da fila de entrega
/// (o miolo do ExpWnfDeleteSubscription); exige o lock das inscrições do
/// processo. O nome volta com uma referência de rundown.
fn unlink_subscription(pointer: u64, process: u64, context: u64) -> Result<Removed, KernelError> {
    let system = process::get_system_process();
    let name = subscription_at(pointer).name_instance.get();
    let mut removed = Removed { name, last_data_subscriber: false, delivery_completed: false };
    let mut remove = || -> Result<(), KernelError> {
        if name != 0 {
            if !rundown::acquire(name_at(name).run_ref.address())? {
                return Err(KernelError::new("WNF subscriber references a closing name"));
            }
            unlink(subscription_at(pointer).state_subscription_list_entry.address())?;
            subscription_at(pointer).name_instance.set(0);
            if subscription_at(pointer).subscribed_event_set.get() & 1 != 0 {
                removed.last_data_subscriber = change_counter(&name_at(name).data_subscribers_count, -1)? == 0;
            }
        }
        unlink(subscription_at(pointer).process_subscription_list_entry.address())?;
        locked(process_context_at(context).delivery_pending_list_lock.address(), true, || {
            let state = subscription_at(pointer).subscription_state.get().0;
            if state == 1 || (process != system && state != 0) {
                unlink(subscription_at(pointer).pending_subscription_list_entry.address())?;
                if name != 0 && subscription_at(pointer).subscribed_event_set.get() & 1 != 0 && (subscription_at(pointer).signaled_event_set.get() | subscription_at(pointer).in_delivery_event_set.get()) & 1 != 0 {
                    removed.delivery_completed = change_counter(&name_at(name).current_delivery_count, -1)? == 0;
                }
            }
            subscription_at(pointer).process.set(0);
            Ok(())
        })
    };
    if name != 0 { locked(name_at(name).state_subscription_list_lock.address(), true, remove)? } else { remove()? };
    Ok(removed)
}

/// Anuncia as transições da remoção, solta a referência do nome e devolve o
/// corpo ao pool quando callbacks e consultas devolvem o rundown.
fn finish_removal(subscription: u64, process: u64, removed: Removed) -> Result<(), KernelError> {
    let inline = process != process::get_system_process();
    let name = removed.name;
    let notified = (|| -> Result<(), KernelError> {
        if removed.delivery_completed {
            notify_name(name, 8, true, inline)?;
        }
        if removed.last_data_subscriber {
            notify_name(name, 4, true, inline)?;
        }
        Ok(())
    })();
    if name != 0 {
        rundown::release(name_at(name).run_ref.address())?;
    }
    notified?;
    rundown::wait(subscription_at(subscription).run_ref.address())?;
    let _ = kernel_pool::free(subscription, Some(STATE_TAG));
    Ok(())
}

/// Remove o assinante de todas as listas na desmontagem do processo; o
/// corpo só sai do pool quando callbacks e consultas devolvem o rundown.
pub fn delete_process_subscriptions(process: u64, context: u64) -> Result<(), KernelError> {
    let head = process_context_at(context).process_subscription_list_head.address();
    loop {
        let mut removed = None;
        let subscription = locked(process_context_at(context).process_subscription_list_lock.address(), true, || {
            let entry = list_entry::at(head).flink.get();
            if entry == head {
                return Ok(0);
            }
            let pointer = entry - offset_of!(WnfSubscription, process_subscription_list_entry) as u64;
            removed = Some(unlink_subscription(pointer, process, context)?);
            Ok(pointer)
        })?;
        let Some(removed) = removed.filter(|_| subscription != 0) else { break };
        finish_removal(subscription, process, removed)?;
    }
    let event = process_context_at(context).notification_event.get();
    if event != 0 {
        if let Some(described) = open_pointer::describe(event) {
            described.dereference();
        }
        process_context_at(context).notification_event.set(0);
    }
    Ok(())
}

/// ExUnsubscribeWnfStateChange: ExpWnfDeleteSubscription de uma inscrição de
/// kernel (dona: o System). Solta a referência de rundown do ponteiro
/// devolvido pelo ExSubscribeWnfStateChange e espera os callbacks em curso
/// antes de liberar o bloco. Uma inscrição já desligada do processo só
/// devolve a referência.
pub fn delete_kernel_subscription(subscription: u64) -> Result<(), KernelError> {
    let process = process::get_system_process();
    let context = process_at(process).wnf_context.get();
    let mut removed = None;
    if context != 0 {
        locked(process_context_at(context).process_subscription_list_lock.address(), true, || {
            if subscription_at(subscription).process.get() != 0 {
                removed = Some(unlink_subscription(subscription, process, context)?);
            }
            Ok(())
        })?;
    }
    rundown::release(subscription_at(subscription).run_ref.address())?;
    match removed {
        Some(removed) => finish_removal(subscription, process, removed),
        None => Ok(()),
    }
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
