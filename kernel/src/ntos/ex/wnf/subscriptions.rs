//! Inscrições WNF.
//!
//! Inscrições nas listas nativas do namespace. O processo é dono do bloco e
//! da quota; a operação só conserva um empréstimo de rundown até publicar
//! as notificações iniciais.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::ex::wnf::name::DecodedName;
use crate::ntos::ex::wnf::namespace::{self, NameDefinition};
use crate::ntos::ex::wnf::notifications::{self, change_counter};
use crate::ntos::ex::{pool_allocation, pool_quota, push_lock, rundown};
use crate::ntos::ex::wnf::security as wnf_security;
use crate::ntos::mm::kernel_pool;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

const SUBSCRIPTION_TAG: u32 = 0x2066_6E57;
const SUBSCRIPTION_SIZE: u64 = 0x88;
const STATUS_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const PROCESS_CONTEXT_OFFSET: u64 = 0x868;

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
    let previous = guest::read64(head + 8);
    if guest::read64(previous) != head {
        return Err(KernelError::new("lista de inscricoes WNF corrompida"));
    }
    guest::write64(entry, head);
    guest::write64(entry + 8, previous);
    guest::write64(previous, entry);
    guest::write64(head + 8, entry);
    Ok(())
}

fn unlink(entry: u64) -> Result<(), KernelError> {
    let next = guest::read64(entry);
    let previous = guest::read64(entry + 8);
    if guest::read64(next + 8) != entry || guest::read64(previous) != entry {
        return Err(KernelError::new("fila de inscricoes WNF corrompida"));
    }
    guest::write64(previous, next);
    guest::write64(next + 8, previous);
    Ok(())
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
    let head = context + 0x58;
    let mut entry = guest::read64(head);
    while entry != head {
        let subscription = entry - 0x18;
        if guest::read64(subscription + 0x30) != name {
            entry = guest::read64(entry);
            continue;
        }
        let (reader_transition, pending_data_removed) = locked(context + 0x68, true, || {
            let mut transition = 0;
            let previous_mask = guest::read32(subscription + 0x64);
            if (previous_mask ^ event_mask) & 1 != 0 {
                if event_mask & 1 != 0 {
                    if change_counter(name + 0xA0, 1)? == 1 {
                        transition = 1;
                    }
                } else if change_counter(name + 0xA0, -1)? == 0 {
                    transition = -1;
                }
            }
            let delivery_state = guest::read32(subscription + 0x78);
            let previous_pending = guest::read32(subscription + 0x7C);
            let removed = delivery_state != 2 && previous_pending & 1 != 0 && event_mask & 1 == 0;
            let pending = previous_pending & event_mask;
            guest::write64(subscription + 0x50, 0);
            guest::write64(subscription + 0x58, 0);
            guest::write32(subscription + 0x64, event_mask);
            guest::write32(subscription + 0x7C, pending);
            if delivery_state != 0 && pending == 0 && guest::read32(subscription + 0x80) == 0 {
                unlink(subscription + 0x68)?;
                guest::write32(subscription + 0x78, 0);
            }
            Ok((transition, removed))
        })?;
        if !rundown::acquire(subscription + 8)? {
            return Err(KernelError::new("inscricao WNF ligada ja esta em rundown"));
        }
        return Ok(Some(Subscribed { pointer: subscription, identifier: guest::read64(subscription + 0x10), reader_transition, pending_data_removed, notification_performed: false }));
    }
    Ok(None)
}

/// Publica só as transições dos contadores; a fila e a sinalização são do
/// notificador compartilhado.
fn announce_transitions(name: u64, mut result: Subscribed) -> Result<Subscribed, KernelError> {
    let mut event_mask = 0;
    if result.pending_data_removed && change_counter(name + 0xA4, -1)? == 0 {
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
            rundown::release(result.pointer + 8)?;
            return Err(error);
        }
    }
    Ok(result)
}

/// Inscreve (ou atualiza) o processo no nome.
pub fn subscribe_name(name: u64, process: u64, change_stamp: u32, event_mask: u32) -> Result<Result<Subscribed, u32>, KernelError> {
    let context = guest::read64(process + PROCESS_CONTEXT_OFFSET);
    if context == 0 {
        return Err(KernelError::new("processo sem contexto WNF apos resolucao do escopo"));
    }
    if let Some(existing) = locked(context + 0x50, false, || update_existing(name, context, event_mask))? {
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
    guest::write32(candidate, 0x0088_0905);
    guest::write32(candidate + 0x60, change_stamp);
    guest::write32(candidate + 0x64, event_mask);
    guest::write64(candidate + 0x38, guest::read64(name + 0x28));
    let identifier = allocate_identifier();
    let result = locked(context + 0x50, true, || {
        locked(name + 0x70, true, || {
            if guest::read64(name + 0x30) == 0 {
                return Ok(Err(STATUS_NOT_FOUND));
            }
            // Outra chamada pode ter inscrito o mesmo nome durante a alocação.
            if let Some(existing) = update_existing(name, context, event_mask)? {
                return Ok(Ok(existing));
            }
            guest::write64(candidate + 0x28, process);
            guest::write64(candidate + 0x30, name);
            guest::write64(candidate + 0x10, identifier);
            if !rundown::acquire(candidate + 8)? {
                return Err(KernelError::new("rundown inicial WNF invalido"));
            }
            append(context + 0x58, candidate + 0x18)?;
            append(name + 0x78, candidate + 0x40)?;
            let reader_transition = if event_mask & 1 != 0 && change_counter(name + 0xA0, 1)? == 1 { 1 } else { 0 };
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
        if guest::read32(current.pointer + 0xA4) == 0 {
            initial |= 8;
        }
        if !subscribed.notification_performed {
            initial |= if guest::read32(current.pointer + 0xA0) != 0 { 2 } else { 4 };
        }
        initial &= event_mask;
        if initial != 0 {
            notifications::notify_subscription(current.pointer, subscription, initial, true)?;
        }
        Ok(Ok(subscribed.identifier))
    })();
    if subscription != 0 {
        rundown::release(subscription + 8)?;
    }
    if let Some(state) = state {
        namespace::release_name(&state)?;
    }
    namespace::release_scope(scope)?;
    result
}
