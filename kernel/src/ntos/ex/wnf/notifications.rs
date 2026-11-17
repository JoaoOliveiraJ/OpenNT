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

/// NtUnsubscribeWnfStateChange (19041, rva 0x611a40): o
/// ExpWnfAcquireSubscriptionByName procura, na lista de inscrições do
/// contexto WNF do processo, a inscrição do nome decodificado
/// (WNF_SUBSCRIPTION.StateName), e o ExpWnfDeleteSubscription a remove. Sem
/// contexto ou sem inscrição: STATUS_OBJECT_NAME_NOT_FOUND.
pub fn delete_subscription_by_name(process: u64, decoded_name: u64) -> Result<u32, KernelError> {
    let context = process_at(process).wnf_context.get();
    if context == 0 {
        return Ok(0xC000_0034);
    }
    let mut removed = None;
    let subscription = locked(process_context_at(context).process_subscription_list_lock.address(), true, || {
        let head = process_context_at(context).process_subscription_list_head.address();
        let mut entry = list_entry::at(head).flink.get();
        while entry != head {
            let pointer = entry - offset_of!(WnfSubscription, process_subscription_list_entry) as u64;
            if subscription_at(pointer).state_name.bitfield_0.get() == decoded_name {
                removed = Some(unlink_subscription(pointer, process, context)?);
                return Ok(pointer);
            }
            entry = list_entry::at(entry).flink.get();
        }
        Ok(0)
    })?;
    match removed {
        Some(removed) if subscription != 0 => {
            finish_removal(subscription, process, removed)?;
            Ok(0)
        }
        _ => Ok(0xC000_0034),
    }
}

/// Versões para o ciclo de vida do namespace (`fn` sem resultado).
const STATUS_RETRY: u32 = 0xC000_022D;
const STATUS_NO_MORE_ENTRIES: u32 = 0x8000_001A;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// O cabeçalho WNF_DELIVERY_DESCRIPTOR antes dos dados.
const DELIVERY_HEADER: u64 = 0x30;

/// ExpWnfCompleteThreadSubscriptions (19041, rva 0x60e73c): o fim da
/// entrega anterior do processo. Sob o ProcessSubscriptionListLock
/// (compartilhado) e o DeliveryPendingListLock (exclusivo), procura na fila
/// a inscrição com o SubscriptionId e o nome dados.
///
/// - Achada, só age com a máscara igual ao InDeliveryEventSet e o estado em
///   entrega (> 1). Com sinais novos chegados na entrega, volta a READY (e
///   STATUS_RETRY religa o bit 0); sem eles, STATUS_RETRY a deixa em RETRY
///   na fila e o sucesso a tira da fila (estado 0). Nos dois primeiros casos
///   a entrega dos dados que acabou (bit 0 entregue e não sinalizado de
///   novo) desconta o CurrentDeliveryCount do nome, e o InDeliveryEventSet
///   zera.
/// - Não achada, com o bit 0 na máscara: o nome do escopo do processo
///   desconta o CurrentDeliveryCount.
///
/// O nome cujo contador chega a zero recebe, fora das travas, o aviso de
/// entrega concluída (máscara 8).
pub fn complete_thread_subscriptions(context: u64, decoded_name: u64, subscription_id: u64, event_mask: u32, status: u32) -> Result<u32, KernelError> {
    let pending_lock = process_context_at(context).delivery_pending_list_lock.address();
    let pending_head = process_context_at(context).delivery_pending_list_head.address();
    let (found, kept) = locked(process_context_at(context).process_subscription_list_lock.address(), false, || {
        locked(pending_lock, true, || {
            let mut entry = list_entry::at(pending_head).flink.get();
            while entry != pending_head {
                let subscription = entry - offset_of!(WnfSubscription, pending_subscription_list_entry) as u64;
                let record = subscription_at(subscription);
                if record.subscription_id.get() != subscription_id || record.state_name.bitfield_0.get() != decoded_name {
                    entry = list_entry::at(entry).flink.get();
                    continue;
                }
                if event_mask != record.in_delivery_event_set.get() || record.subscription_state.get().0 <= 1 {
                    return Ok((true, 0));
                }
                let signaled = record.signaled_event_set.get();
                if signaled != 0 {
                    record.subscription_state.set(WnfSubscriptionState(1));
                    if status == STATUS_RETRY && signaled & 1 == 0 {
                        record.signaled_event_set.set(signaled | 1);
                    }
                } else if status != 0 {
                    record.subscription_state.set(WnfSubscriptionState(3));
                    return Ok((true, 0));
                } else {
                    record.subscription_state.set(WnfSubscriptionState(0));
                    unlink(entry)?;
                }
                let mut kept = 0;
                let name = record.name_instance.get();
                if record.signaled_event_set.get() & 1 == 0 && record.in_delivery_event_set.get() & 1 != 0 && name != 0 && change_counter(&name_at(name).current_delivery_count, -1)? == 0 && rundown::acquire(name_at(name).run_ref.address())? {
                    kept = name;
                }
                record.in_delivery_event_set.set(0);
                return Ok((true, kept));
            }
            Ok((false, 0))
        })
    })?;
    let mut kept = kept;
    let mut lookup = None;
    if !found && event_mask & 1 != 0 {
        let process = process_context_at(context).process.get();
        if let Ok(scope) = super::namespace::resolve_creator_scope(process, ((decoded_name >> 6) & 0xF) as u32)? {
            if let Ok(state) = super::namespace::lookup_name(scope, decoded_name)? {
                if change_counter(&name_at(state.pointer).current_delivery_count, -1)? == 0 {
                    kept = state.pointer;
                    lookup = Some(state);
                } else {
                    super::namespace::release_name(&state)?;
                }
            }
            super::namespace::release_scope(scope)?;
        }
    }
    if kept != 0 {
        notify_name(kept, 8, true, true)?;
        match lookup {
            Some(state) => super::namespace::release_name(&state)?,
            None => rundown::release(name_at(kept).run_ref.address())?,
        }
    }
    Ok(0)
}

/// O fim de uma inscrição sem nada a entregar (o caminho frio do
/// ExpWnfDeliverThreadNotifications): sai da fila, estado 0, sinais e
/// entrega zerados. Devolve o nome a avisar quando a entrega de dados
/// pendente zera o CurrentDeliveryCount dele.
fn retire_pending(entry: u64, name: u64) -> Result<u64, KernelError> {
    let record = subscription_at(entry - offset_of!(WnfSubscription, pending_subscription_list_entry) as u64);
    unlink(entry)?;
    record.subscription_state.set(WnfSubscriptionState(0));
    let old = record.signaled_event_set.get();
    record.signaled_event_set.set(0);
    record.in_delivery_event_set.set(0);
    if name != 0 && old & 1 != 0 && change_counter(&name_at(name).current_delivery_count, -1)? == 0 {
        return Ok(name);
    }
    Ok(0)
}

/// O resultado de um passo da busca do ExpWnfDeliverThreadNotifications.
enum Delivery {
    /// O status final (um descritor escrito, nada pendente ou a falha).
    Done(u32),
    /// Um nome a avisar fora das travas; a busca recomeça do início.
    Restart(u64),
}

/// ExpWnfDeliverThreadNotifications (19041, rva 0x60e474): a próxima
/// inscrição READY da fila do processo vira um WNF_DELIVERY_DESCRIPTOR no
/// buffer do chamador (o SubscriptionId, o nome externo, a máscara e, com o
/// bit 0, o TypeId, o ChangeStamp e os dados depois dos 0x30 bytes do
/// cabeçalho). A inscrição fica na fila em entrega (estado 2) com a máscara
/// entregue no InDeliveryEventSet; uma por chamada. A que não tem o que
/// entregar sai da fila. Sem nenhuma, STATUS_NO_MORE_ENTRIES; uma leitura de
/// dados que falha vale como resultado se nenhuma outra entrega ocorrer.
pub fn deliver_thread_notifications(context: u64, descriptor: u64, size: u32) -> Result<u32, KernelError> {
    let available = size.saturating_sub(DELIVERY_HEADER as u32);
    let pending_lock = process_context_at(context).delivery_pending_list_lock.address();
    let pending_head = process_context_at(context).delivery_pending_list_head.address();
    loop {
        let step = locked(process_context_at(context).process_subscription_list_lock.address(), false, || {
            locked(pending_lock, true, || -> Result<Delivery, KernelError> {
                let mut result = STATUS_NO_MORE_ENTRIES;
                let mut entry = list_entry::at(pending_head).flink.get();
                while entry != pending_head {
                    let next = list_entry::at(entry).flink.get();
                    let record = subscription_at(entry - offset_of!(WnfSubscription, pending_subscription_list_entry) as u64);
                    if record.subscription_state.get().0 != 1 {
                        entry = next;
                        continue;
                    }
                    let mut name = record.name_instance.get();
                    if name != 0 && !rundown::acquire(name_at(name).run_ref.address())? {
                        name = 0;
                    }
                    let mut mask = record.subscribed_event_set.get() & record.signaled_event_set.get();
                    if name == 0 {
                        mask &= !1;
                    }
                    if mask == 0 {
                        let notify = retire_pending(entry, name)?;
                        if notify != 0 {
                            return Ok(Delivery::Restart(notify));
                        }
                        if name != 0 {
                            rundown::release(name_at(name).run_ref.address())?;
                        }
                        entry = next;
                        continue;
                    }
                    let mut header = [0u8; DELIVERY_HEADER as usize];
                    header[0..8].copy_from_slice(&record.subscription_id.get().to_le_bytes());
                    header[8..16].copy_from_slice(&(record.state_name.bitfield_0.get() ^ wnf_name::NAME_MASK).to_le_bytes());
                    let (mut stamp, mut read_status) = (0u32, 0u32);
                    let written = (|| -> Result<(), KernelError> {
                        if mask & 1 != 0 {
                            let type_identifier = name_at(name).state_name_info.type_id.get();
                            if type_identifier != 0 {
                                header[0x1C..0x2C].copy_from_slice(&guest::read_bytes(type_identifier, 16));
                            }
                            let cells = guest::alloc_bytes(8);
                            if cells == 0 {
                                return Err(KernelError::new("WNF delivery cells allocation failed"));
                            }
                            guest::write64(cells, 0);
                            read_status = super::data_block::read(&super::namespace::describe_name(name), cells, descriptor + DELIVERY_HEADER, available, cells + 4)?;
                            if read_status & 0x8000_0000 == 0 {
                                stamp = guest::read32(cells);
                                header[0x10..0x14].copy_from_slice(&stamp.to_le_bytes());
                                header[0x14..0x18].copy_from_slice(&guest::read32(cells + 4).to_le_bytes());
                            }
                            guest::free_bytes(cells);
                        }
                        header[0x18..0x1C].copy_from_slice(&mask.to_le_bytes());
                        header[0x2C..0x30].copy_from_slice(&(DELIVERY_HEADER as u32).to_le_bytes());
                        guest::try_write_bytes(descriptor, &header)
                    })();
                    if name != 0 {
                        rundown::release(name_at(name).run_ref.address())?;
                    }
                    if let Err(error) = written {
                        if error.status == STATUS_ACCESS_VIOLATION {
                            return Ok(Delivery::Done(STATUS_ACCESS_VIOLATION));
                        }
                        return Err(error);
                    }
                    if read_status == STATUS_ACCESS_VIOLATION {
                        return Ok(Delivery::Done(STATUS_ACCESS_VIOLATION));
                    }
                    if read_status & 0x8000_0000 != 0 {
                        if result == STATUS_NO_MORE_ENTRIES {
                            result = read_status;
                        }
                        entry = next;
                        continue;
                    }
                    if stamp == 0 {
                        mask &= !1;
                    }
                    if mask == 0 {
                        retire_pending(entry, 0)?;
                        entry = next;
                        continue;
                    }
                    record.in_delivery_event_set.set(mask);
                    record.signaled_event_set.set(0);
                    record.subscription_state.set(WnfSubscriptionState(2));
                    return Ok(Delivery::Done(0));
                }
                Ok(Delivery::Done(result))
            })
        })?;
        match step {
            Delivery::Done(status) => return Ok(status),
            Delivery::Restart(name) => {
                notify_name(name, 8, true, true)?;
                rundown::release(name_at(name).run_ref.address())?;
            }
        }
    }
}

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
