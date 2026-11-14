//! Inscrições WNF.
//!
//! Inscrições nas listas nativas do namespace. O processo é dono do bloco e
//! da quota; a operação só conserva um empréstimo de rundown até publicar
//! as notificações iniciais.

use core::sync::atomic::{AtomicU64, Ordering};
use core::mem::offset_of;

use crate::ntos::ex::wnf::name::DecodedName;
use crate::ntos::ex::wnf::namespace::{self, NameDefinition};
use crate::ntos::ex::wnf::notifications::{self, change_counter};
use crate::ntos::ex::{pool_allocation, pool_quota, push_lock, rundown};
use crate::ntos::ex::wnf::security as wnf_security;
use crate::ntos::mm::kernel_pool;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use super::objects::{name_at, process_at, process_context_at, subscription_at};
use crate::ntos::ex::list_entry;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{WnfSubscription, WnfSubscriptionState};

const SUBSCRIPTION_TAG: u32 = 0x2066_6E57;
const SUBSCRIPTION_SIZE: u64 = WnfSubscription::SIZE;
const STATUS_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Sequência de identificadores do kernel (zero é pulado no wrap).
static NEXT_IDENTIFIER: AtomicU64 = AtomicU64::new(0);

fn allocate_identifier() -> u64 {
    loop {
        let next = NEXT_IDENTIFIER.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        if next != 0 {
            return next;
        }
    }
}

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

fn append(head: u64, entry: u64) -> Result<(), KernelError> {
    let head = list_entry::at(head);
    if !list_entry::tail_consistent(head) {
        return Err(KernelError::new("lista de inscricoes WNF corrompida"));
    }
    list_entry::insert_tail(head, list_entry::at(entry));
    Ok(())
}

fn unlink(entry: u64) -> Result<(), KernelError> {
    list_entry::remove(list_entry::at(entry)).map(|_| ()).ok_or_else(|| KernelError::new("fila de inscricoes WNF corrompida"))
}

/// Inscrição publicada (com uma referência de rundown para o chamador).
#[derive(Clone, Copy, Debug, Default)]
pub struct Subscribed {
    pub pointer: u64,
    pub identifier: u64,
    pub reader_transition: i32,
    pub pending_data_removed: bool,
    pub notification_performed: bool,
}

/// Exige o lock das inscrições do processo. Uma inscrição existente mantém
/// identificador e carimbo, mesmo quando a máscara muda.
fn update_existing(name: u64, context: u64, event_mask: u32) -> Result<Option<Subscribed>, KernelError> {
    let head = process_context_at(context).process_subscription_list_head.address();
    let mut entry = list_entry::at(head).flink.get();
    while entry != head {
        let subscription = entry - offset_of!(WnfSubscription, process_subscription_list_entry) as u64;
        if subscription_at(subscription).name_instance.get() != name {
            entry = list_entry::at(entry).flink.get();
            continue;
        }
        let (reader_transition, pending_data_removed) = locked(process_context_at(context).delivery_pending_list_lock.address(), true, || {
            let mut transition = 0;
            let previous_mask = subscription_at(subscription).subscribed_event_set.get();
            if (previous_mask ^ event_mask) & 1 != 0 {
                if event_mask & 1 != 0 {
                    if change_counter(&name_at(name).data_subscribers_count, 1)? == 1 {
                        transition = 1;
                    }
                } else if change_counter(&name_at(name).data_subscribers_count, -1)? == 0 {
                    transition = -1;
                }
            }
            let delivery_state = subscription_at(subscription).subscription_state.get().0;
            let previous_pending = subscription_at(subscription).signaled_event_set.get();
            let removed = delivery_state != 2 && previous_pending & 1 != 0 && event_mask & 1 == 0;
            let pending = previous_pending & event_mask;
            subscription_at(subscription).callback_routine.set(0);
            subscription_at(subscription).callback_context.set(0);
            subscription_at(subscription).subscribed_event_set.set(event_mask);
            subscription_at(subscription).signaled_event_set.set(pending);
            if delivery_state != 0 && pending == 0 && subscription_at(subscription).in_delivery_event_set.get() == 0 {
                unlink(subscription_at(subscription).pending_subscription_list_entry.address())?;
                subscription_at(subscription).subscription_state.set(WnfSubscriptionState(0));
            }
            Ok((transition, removed))
        })?;
        if !rundown::acquire(subscription_at(subscription).run_ref.address())? {
            return Err(KernelError::new("inscricao WNF ligada ja esta em rundown"));
        }
        return Ok(Some(Subscribed { pointer: subscription, identifier: subscription_at(subscription).subscription_id.get(), reader_transition, pending_data_removed, notification_performed: false }));
    }
    Ok(None)
}

/// Publica só as transições dos contadores; a fila e a sinalização são do
/// notificador compartilhado.
fn announce_transitions(name: u64, mut result: Subscribed) -> Result<Subscribed, KernelError> {
    let mut event_mask = 0;
    if result.pending_data_removed && change_counter(&name_at(name).current_delivery_count, -1)? == 0 {
        event_mask |= 8;
    }
    if result.reader_transition > 0 {
        event_mask |= 2;
    } else if result.reader_transition < 0 {
        event_mask |= 4;
    }
    result.notification_performed = event_mask != 0;
    if event_mask != 0 {
        if let Err(error) = notifications::notify_name(name, event_mask, true, true) {
            rundown::release(subscription_at(result.pointer).run_ref.address())?;
            return Err(error);
        }
    }
    Ok(result)
}

/// Inscreve (ou atualiza) o processo no nome.
pub fn subscribe_name(name: u64, process: u64, change_stamp: u32, event_mask: u32) -> Result<Result<Subscribed, u32>, KernelError> {
    let context = process_at(process).wnf_context.get();
    if context == 0 {
        return Err(KernelError::new("processo sem contexto WNF apos resolucao do escopo"));
    }
    if let Some(existing) = locked(process_context_at(context).process_subscription_list_lock.address(), false, || update_existing(name, context, event_mask))? {
        return announce_transitions(name, existing).map(Ok);
    }
    // A variante com quota devolve NULL sem recursos; o free devolve a quota.
    let mut candidate = if process == process::get_system_process() {
        pool_allocation::allocate_tagged(1, SUBSCRIPTION_SIZE, SUBSCRIPTION_TAG).unwrap_or(0)
    } else {
        pool_quota::allocate(9, SUBSCRIPTION_SIZE, SUBSCRIPTION_TAG).unwrap_or(0)
    };
    if candidate == 0 {
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(candidate, &[0u8; SUBSCRIPTION_SIZE as usize]);
    let header = &subscription_at(candidate).header;
    header.node_type_code.set(0x905);
    header.node_byte_size.set(SUBSCRIPTION_SIZE as u16);
    subscription_at(candidate).current_change_stamp.set(change_stamp);
    subscription_at(candidate).subscribed_event_set.set(event_mask);
    subscription_at(candidate).state_name.bitfield_0.set(name_at(name).state_name.bitfield_0.get());
    let identifier = allocate_identifier();
    let result = locked(process_context_at(context).process_subscription_list_lock.address(), true, || {
        locked(name_at(name).state_subscription_list_lock.address(), true, || {
            if name_at(name).scope_instance.get() == 0 {
                return Ok(Err(STATUS_NOT_FOUND));
            }
            // Outra chamada pode ter inscrito o mesmo nome durante a alocação.
            if let Some(existing) = update_existing(name, context, event_mask)? {
                return Ok(Ok(existing));
            }
            subscription_at(candidate).process.set(process);
            subscription_at(candidate).name_instance.set(name);
            subscription_at(candidate).subscription_id.set(identifier);
            if !rundown::acquire(subscription_at(candidate).run_ref.address())? {
                return Err(KernelError::new("rundown inicial WNF invalido"));
            }
            append(process_context_at(context).process_subscription_list_head.address(), subscription_at(candidate).process_subscription_list_entry.address())?;
            append(name_at(name).state_subscription_list_head.address(), subscription_at(candidate).state_subscription_list_entry.address())?;
            let reader_transition = if event_mask & 1 != 0 && change_counter(&name_at(name).data_subscribers_count, 1)? == 1 { 1 } else { 0 };
            let published = candidate;
            candidate = 0;
            Ok(Ok(Subscribed { pointer: published, identifier, reader_transition, pending_data_removed: false, notification_performed: false }))
        })
    });
    if candidate != 0 {
        let _ = kernel_pool::free(candidate, Some(SUBSCRIPTION_TAG));
    }
    match result? {
        Ok(subscribed) => announce_transitions(name, subscribed).map(Ok),
        Err(status) => Ok(Err(status)),
    }
}

/// Inscrição de kernel no nome (o ramo KernelMode do
/// ExpWnfSubscribeNameInstance): sempre um bloco novo do System, com o
/// callback e o contexto, identificador igual ao próprio ponteiro e uma
/// segunda referência de rundown que pertence ao PWNF_SUBSCRIPTION devolvido
/// (solta pelo ExUnsubscribeWnfStateChange).
fn subscribe_kernel_name(name: u64, change_stamp: u32, event_mask: u32, callback: u64, context: u64) -> Result<Result<Subscribed, u32>, KernelError> {
    let process = process::get_system_process();
    let process_context = process_at(process).wnf_context.get();
    if process_context == 0 {
        return Err(KernelError::new("System sem contexto WNF apos resolucao do escopo"));
    }
    let Ok(candidate) = pool_allocation::allocate_tagged(1, SUBSCRIPTION_SIZE, SUBSCRIPTION_TAG) else { return Ok(Err(STATUS_INSUFFICIENT_RESOURCES)) };
    guest::write_bytes(candidate, &[0u8; SUBSCRIPTION_SIZE as usize]);
    let subscription = subscription_at(candidate);
    subscription.header.node_type_code.set(0x905);
    subscription.header.node_byte_size.set(SUBSCRIPTION_SIZE as u16);
    subscription.callback_routine.set(callback);
    subscription.callback_context.set(context);
    subscription.current_change_stamp.set(change_stamp);
    subscription.subscribed_event_set.set(event_mask);
    subscription.state_name.bitfield_0.set(name_at(name).state_name.bitfield_0.get());
    let result = locked(process_context_at(process_context).process_subscription_list_lock.address(), true, || {
        locked(name_at(name).state_subscription_list_lock.address(), true, || {
            if name_at(name).scope_instance.get() == 0 {
                return Ok(Err(STATUS_NOT_FOUND));
            }
            subscription.process.set(process);
            subscription.name_instance.set(name);
            subscription.subscription_id.set(candidate);
            // A referência da operação e a do ponteiro devolvido.
            if !rundown::acquire(subscription.run_ref.address())? || !rundown::acquire(subscription.run_ref.address())? {
                return Err(KernelError::new("rundown inicial WNF invalido"));
            }
            append(process_context_at(process_context).process_subscription_list_head.address(), subscription.process_subscription_list_entry.address())?;
            append(name_at(name).state_subscription_list_head.address(), subscription.state_subscription_list_entry.address())?;
            let reader_transition = if event_mask & 1 != 0 && change_counter(&name_at(name).data_subscribers_count, 1)? == 1 { 1 } else { 0 };
            Ok(Ok(Subscribed { pointer: candidate, identifier: candidate, reader_transition, pending_data_removed: false, notification_performed: false }))
        })
    });
    match result {
        Ok(Ok(subscribed)) => {
            // As transições dos contadores vão pelo work item (não inline).
            if subscribed.reader_transition > 0 {
                notifications::notify_name(name, 2, true, false)?;
                return Ok(Ok(Subscribed { notification_performed: true, ..subscribed }));
            }
            Ok(Ok(subscribed))
        }
        other => {
            let _ = kernel_pool::free(candidate, Some(SUBSCRIPTION_TAG));
            other
        }
    }
}

/// ExSubscribeWnfStateChange com o nome já decodificado
/// (ExpWnfSubscribeWnfStateChange em KernelMode): escopo do System, nome
/// criado pela definição permanente se preciso, sem verificação de acesso;
/// a notificação inicial descreve o estado real e vai pelo work item. Devolve
/// o PWNF_SUBSCRIPTION.
pub fn subscribe_kernel(name: &DecodedName, change_stamp: u32, event_mask: u32, callback: u64, context: u64) -> Result<Result<u64, u32>, KernelError> {
    let process = process::get_system_process();
    let scope = match namespace::resolve_kernel_scope(process, name.scope, 0)? {
        Ok(scope) => scope,
        Err(status) => return Ok(Err(status)),
    };
    if namespace::ensure_process_context(process)? == 0 {
        namespace::release_scope(scope)?;
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    let mut state = None;
    let mut subscription = 0u64;
    let result = (|| -> Result<Result<u64, u32>, KernelError> {
        let current = match namespace::lookup_name(scope, name.decoded_name)? {
            Err(STATUS_NOT_FOUND) => {
                if name.lifetime == 3 {
                    return Ok(Err(STATUS_NOT_FOUND));
                }
                let definition = match namespace::lookup_definition(name.decoded_name)? {
                    Ok(definition) => definition,
                    Err(status) => return Ok(Err(status)),
                };
                let created = namespace::create_name(scope, name.decoded_name, NameDefinition::from(&definition), process)?;
                definition.release();
                match created {
                    Ok(created) => created,
                    Err(status) => return Ok(Err(status)),
                }
            }
            Err(status) => return Ok(Err(status)),
            Ok(found) => found,
        };
        state = Some(current);
        let subscribed = match subscribe_kernel_name(current.pointer, change_stamp, event_mask, callback, context)? {
            Ok(subscribed) => subscribed,
            Err(status) => return Ok(Err(status)),
        };
        subscription = subscribed.pointer;
        let mut initial = if change_stamp != current.change_stamp() && current.data_pointer() != 0 { 1 } else { 0 };
        if name_at(current.pointer).current_delivery_count.get() == 0 {
            initial |= 8;
        }
        if !subscribed.notification_performed {
            initial |= if name_at(current.pointer).data_subscribers_count.get() != 0 { 2 } else { 4 };
        }
        initial &= event_mask;
        if initial != 0 {
            notifications::notify_subscription(current.pointer, subscription, initial, false)?;
        }
        Ok(Ok(subscribed.pointer))
    })();
    if subscription != 0 {
        rundown::release(subscription_at(subscription).run_ref.address())?;
    }
    if let Some(state) = state {
        namespace::release_name(&state)?;
    }
    namespace::release_scope(scope)?;
    result
}

/// NtSubscribeWnfStateChange com o nome já capturado: resolve o escopo do
/// usuário, cria o nome pela definição se preciso, confere o acesso e
/// publica a notificação inicial que descreve o estado real.
pub fn subscribe_captured(name: &DecodedName, change_stamp: u32, event_mask: u32) -> Result<Result<u64, u32>, KernelError> {
    let process = process::get_current_process();
    let desired = (if event_mask & 0x11 != 0 { 1 } else { 0 }) | (if event_mask & !0x11 != 0 { 2 } else { 0 });
    let scope = match namespace::resolve_user_scope(process, name.scope, 0)? {
        Ok(scope) => scope,
        Err(status) => return Ok(Err(status)),
    };
    let mut state = None;
    let mut subscription = 0u64;
    let result = (|| -> Result<Result<u64, u32>, KernelError> {
        let found = namespace::lookup_name(scope, name.decoded_name)?;
        let current = match found {
            Err(STATUS_NOT_FOUND) => {
                if name.lifetime == 3 {
                    return Ok(Err(STATUS_NOT_FOUND));
                }
                let definition = match namespace::lookup_definition(name.decoded_name)? {
                    Ok(definition) => definition,
                    Err(status) => return Ok(Err(status)),
                };
                let access = wnf_security::check(definition.security_descriptor, desired)?;
                if access & 0x8000_0000 != 0 {
                    return Ok(Err(access));
                }
                let created = namespace::create_name(scope, name.decoded_name, NameDefinition::from(&definition), process)?;
                definition.release();
                match created {
                    Ok(created) => created,
                    Err(status) => return Ok(Err(status)),
                }
            }
            Err(status) => return Ok(Err(status)),
            Ok(found) => {
                let access = wnf_security::check(found.security_descriptor(), desired)?;
                if access & 0x8000_0000 != 0 {
                    state = Some(found);
                    return Ok(Err(access));
                }
                found
            }
        };
        state = Some(current);
        let subscribed = match subscribe_name(current.pointer, process, change_stamp, event_mask)? {
            Ok(subscribed) => subscribed,
            Err(status) => return Ok(Err(status)),
        };
        subscription = subscribed.pointer;
        // O marcador de dados 1 também conta como ponteiro não nulo.
        let mut initial = if change_stamp != current.change_stamp() && current.data_pointer() != 0 { 1 } else { 0 };
        if name_at(current.pointer).current_delivery_count.get() == 0 {
            initial |= 8;
        }
        if !subscribed.notification_performed {
            initial |= if name_at(current.pointer).data_subscribers_count.get() != 0 { 2 } else { 4 };
        }
        initial &= event_mask;
        if initial != 0 {
            notifications::notify_subscription(current.pointer, subscription, initial, true)?;
        }
        Ok(Ok(subscribed.identifier))
    })();
    if subscription != 0 {
        rundown::release(subscription_at(subscription).run_ref.address())?;
    }
    if let Some(state) = state {
        namespace::release_name(&state)?;
    }
    namespace::release_scope(scope)?;
    result
}
