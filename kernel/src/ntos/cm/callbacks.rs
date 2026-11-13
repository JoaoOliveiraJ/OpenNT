//! Filtros nativos do registro.
//!
//! Cada inscrição tem altitude copiada, cookie e referências das notificações
//! em andamento. As estruturas ficam na memória do convidado e as rotinas
//! rodam pela ABI x64, sempre sem lock retido.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::callbacks::compare_altitude;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

pub const CALLBACK_BYPASS: u32 = 0xC000_0503;

#[derive(Clone)]
struct Record {
    pointer: u64,
    buffer: u64,
    altitude: String,
    callback: u64,
    context: u64,
    active: u32,
    removing: bool,
}

#[derive(Default)]
struct Callbacks {
    by_cookie: BTreeMap<u64, Record>,
    /// Pilha de reentrada por thread: (cookie, altitude).
    active_by_thread: BTreeMap<u64, Vec<(u64, String)>>,
    sequence: u64,
}

static CALLBACKS: SpinLock<Option<Callbacks>> = SpinLock::new(None);

fn with<T>(body: impl FnOnce(&mut Callbacks) -> T) -> T {
    let mut callbacks = CALLBACKS.lock();
    body(callbacks.get_or_insert_with(Callbacks::default))
}

/// Inscrição, remoção e notificação acima de APC_LEVEL são uso indevido.
fn validate_interrupt_level() -> Result<(), KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("CM callback operation above APC_LEVEL"));
    }
    Ok(())
}

/// CmRegisterCallbackEx: Driver não nulo e Reserved nulo; copia a altitude e
/// publica o cookie (mesmo quando recusa altitude equivalente).
pub fn register(callback: u64, altitude: u64, driver: u64, context: u64, output_cookie: u64, reserved: u64) -> Result<u32, KernelError> {
    validate_interrupt_level()?;
    if driver == 0 {
        return Ok(0xC000_00F1);
    }
    if reserved != 0 {
        return Ok(0xC000_00F4);
    }
    // Registro de 80 bytes em pool paginado: cookie +24, contexto +32,
    // rotina +40 e UNICODE_STRING da altitude +48.
    let Ok(record) = kernel_pool::allocate(80, AllocateOptions { paged: true, tag: 0x6263_4D43, zero: true, ..Default::default() }) else {
        return Ok(0xC000_009A);
    };
    let length = guest::read16(altitude);
    let source = guest::read64(altitude + 8);
    let Ok(buffer) = kernel_pool::allocate((length as u64).max(1), AllocateOptions { paged: true, tag: 0x6163_4D43, zero: true, ..Default::default() }) else {
        let _ = kernel_pool::free(record, None);
        return Ok(0xC000_009A);
    };
    for offset in 0..length as u64 {
        guest::write8(buffer + offset, guest::read8(source + offset));
    }
    let units: Vec<u16> = (0..length as u64 / 2).map(|index| guest::read16(buffer + index * 2)).collect();
    let text = String::from_utf16_lossy(&units);
    let (cookie, collision) = with(|callbacks| {
        callbacks.sequence += 1;
        (callbacks.sequence, callbacks.by_cookie.values().any(|existing| compare_altitude(&existing.altitude, &text) == Ordering::Equal))
    });
    guest::write64(record + 24, cookie);
    guest::write64(record + 32, context);
    guest::write64(record + 40, callback);
    guest::write16(record + 48, length);
    guest::write16(record + 50, length);
    guest::write64(record + 56, buffer);
    guest::write64(output_cookie, cookie);
    if collision {
        let _ = kernel_pool::free(buffer, None);
        let _ = kernel_pool::free(record, None);
        return Ok(0xC01C_0011);
    }
    with(|callbacks| callbacks.by_cookie.insert(cookie, Record { pointer: record, buffer, altitude: text, callback, context, active: 0, removing: false }));
    Ok(0)
}

/// Remoção em andamento: [`Removal::poll`] só libera a memória quando as
/// notificações já iniciadas terminarem.
pub struct Removal {
    cookie: Option<u64>,
    completed: bool,
}

impl Removal {
    /// `None` enquanto houver notificações em andamento.
    pub fn poll(&mut self) -> Option<u32> {
        let Some(cookie) = self.cookie else { return Some(0xC000_000D) };
        if self.completed {
            return Some(0);
        }
        let removed = with(|callbacks| {
            if callbacks.by_cookie.get(&cookie).is_some_and(|record| record.active != 0) {
                return None;
            }
            Some(callbacks.by_cookie.remove(&cookie))
        })?;
        if let Some(record) = removed {
            let _ = kernel_pool::free(record.buffer, None);
            let _ = kernel_pool::free(record.pointer, None);
        }
        self.completed = true;
        Some(0)
    }
}

/// Marca a inscrição para impedir novas entregas; remover de dentro de uma
/// notificação é recusado.
pub fn begin_remove(cookie: u64) -> Result<Removal, KernelError> {
    validate_interrupt_level()?;
    let thread = process::get_current_thread();
    with(|callbacks| {
        let Some(record) = callbacks.by_cookie.get(&cookie).filter(|record| !record.removing) else {
            return Ok(Removal { cookie: None, completed: false });
        };
        let _ = record;
        if callbacks.active_by_thread.get(&thread).is_some_and(|stack| !stack.is_empty()) {
            return Err(KernelError::new("CM callback cannot unregister from a registry notification"));
        }
        if let Some(record) = callbacks.by_cookie.get_mut(&cookie) {
            record.removing = true;
        }
        Ok(Removal { cookie: Some(cookie), completed: false })
    })
}

/// CmUnRegisterCallback: espera cooperativamente pelo dispatcher.
pub fn remove(cookie: u64) -> Result<u32, KernelError> {
    let mut removal = begin_remove(cookie)?;
    loop {
        if let Some(status) = removal.poll() {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

/// Empilha a inscrição na thread e chama a rotina com contexto, classe
/// REG_NOTIFY_CLASS e estrutura; a pilha é restaurada em qualquer saída.
fn invoke(cookie: u64, record: &Record, class: u32, information: u64) -> u32 {
    let thread = process::get_current_thread();
    with(|callbacks| callbacks.active_by_thread.entry(thread).or_default().push((cookie, record.altitude.clone())));
    let status = native_call::call(record.callback, &[record.context, class as u64, information]) as u32;
    with(|callbacks| {
        if let Some(stack) = callbacks.active_by_thread.get_mut(&thread) {
            stack.pop();
            if stack.is_empty() {
                callbacks.active_by_thread.remove(&thread);
            }
        }
    });
    status
}

/// Resultado de uma operação filtrada: NTSTATUS e objeto (corpo de chave).
pub trait Outcome {
    fn status(&self) -> u32;
    fn object(&self) -> u64;
    fn set_status(&mut self, status: u32);
    fn set_object(&mut self, object: u64);
    fn from_status(status: u32) -> Self;
}

/// Descrição REG_* da operação: classes pré/pós, estrutura, offset do
/// CallContext, objeto inicial e o tratamento de STATUS_CALLBACK_BYPASS.
pub struct Operation<'a, R> {
    pub pre: u32,
    pub post: u32,
    pub info: u64,
    pub call_offset: u64,
    pub object: u64,
    pub unblockable: bool,
    pub bypass: Option<&'a dyn Fn() -> R>,
}

/// Filtros pré em altitude decrescente, a operação e as notificações pós em
/// ordem inversa. A reentrada só admite altitudes abaixo do filtro que
/// originou a operação.
pub fn perform<R: Outcome>(operation: &Operation<R>, action: impl FnOnce() -> R) -> Result<R, KernelError> {
    match perform_fallible::<R, core::convert::Infallible>(operation, || Ok(action()))? {
        Ok(result) => Ok(result),
        Err(never) => match never {},
    }
}

/// Como [`perform`], mas a ação pode falhar: a falha interrompe as
/// notificações posteriores (as retenções e o workspace são liberados).
pub fn perform_fallible<R: Outcome, E>(operation: &Operation<R>, action: impl FnOnce() -> Result<R, E>) -> Result<Result<R, E>, KernelError> {
    if !has() {
        return Ok(action());
    }
    validate_interrupt_level()?;
    let thread = process::get_current_thread();
    let mut eligible: Vec<(u64, String)> = with(|callbacks| {
        let parent = callbacks.active_by_thread.get(&thread).and_then(|stack| stack.last().map(|(_, altitude)| altitude.clone()));
        callbacks
            .by_cookie
            .iter()
            .filter(|(_, record)| !record.removing && parent.as_ref().is_none_or(|parent| compare_altitude(&record.altitude, parent) == Ordering::Less))
            .map(|(&cookie, record)| (cookie, record.altitude.clone()))
            .collect()
    });
    if eligible.is_empty() {
        return Ok(action());
    }
    eligible.sort_by(|left, right| compare_altitude(&right.1, &left.1));
    // REG_POST_OPERATION_INFORMATION (56 bytes) e o frame de três argumentos.
    let workspace = guest::alloc_bytes(80);
    if workspace == 0 {
        return Ok(Ok(R::from_status(0xC000_009A)));
    }
    let post_information = workspace;
    let call_context = operation.info + operation.call_offset;
    let mut posts: Vec<(u64, Record, u64)> = Vec::new();
    let mut result: Option<R> = None;
    critical_region::enter_critical()?;
    for (cookie, _) in eligible {
        // Retém a inscrição antes da chamada; o campo removing é relido para
        // respeitar remoções feitas por callbacks anteriores.
        let Some(record) = with(|callbacks| {
            let record = callbacks.by_cookie.get_mut(&cookie).filter(|record| !record.removing)?;
            record.active += 1;
            Some(record.clone())
        }) else {
            continue;
        };
        guest::write64(call_context, 0);
        let status = invoke(cookie, &record, operation.pre, operation.info);
        if !operation.unblockable && (status == CALLBACK_BYPASS || status & 0x8000_0000 != 0) {
            with(|callbacks| {
                if let Some(record) = callbacks.by_cookie.get_mut(&cookie) {
                    record.active -= 1;
                }
            });
            result = Some(if status == CALLBACK_BYPASS {
                match operation.bypass {
                    Some(bypass) => bypass(),
                    None => R::from_status(0),
                }
            } else {
                R::from_status(status)
            });
            break;
        }
        posts.push((cookie, record, guest::read64(call_context)));
    }
    let mut result = match result {
        Some(result) => result,
        None => match action() {
            Ok(result) => result,
            Err(error) => {
                release_posts(&posts);
                let left = critical_region::leave_critical();
                guest::free_bytes(workspace);
                left?;
                return Ok(Err(error));
            }
        },
    };
    for (cookie, record, context) in posts.iter().rev() {
        // CallContext desta inscrição; Status e ReturnStatus começam com o
        // resultado efetivo da operação.
        guest::write64(call_context, *context);
        let object = if result.status() == 0 { if result.object() != 0 { result.object() } else { operation.object } } else { 0 };
        guest::write64(post_information, object);
        guest::write32(post_information + 8, result.status());
        guest::write64(post_information + 16, operation.info);
        guest::write32(post_information + 24, result.status());
        guest::write64(post_information + 32, *context);
        guest::write64(post_information + 40, 0);
        guest::write64(post_information + 48, 0);
        let status = invoke(*cookie, record, operation.post, post_information);
        if !operation.unblockable && status == CALLBACK_BYPASS {
            result.set_status(guest::read32(post_information + 24));
            result.set_object(guest::read64(post_information));
        }
    }
    release_posts(&posts);
    let left = critical_region::leave_critical();
    guest::free_bytes(workspace);
    left?;
    Ok(Ok(result))
}

fn release_posts(posts: &[(u64, Record, u64)]) {
    with(|callbacks| {
        for (cookie, _, _) in posts {
            if let Some(record) = callbacks.by_cookie.get_mut(cookie) {
                record.active -= 1;
            }
        }
    });
}

pub fn has() -> bool {
    with(|callbacks| !callbacks.by_cookie.is_empty())
}

/// (ponteiro do registro, altitude, ativo, removendo) da inscrição.
pub fn get(cookie: u64) -> Option<(u64, String, u32, bool)> {
    with(|callbacks| callbacks.by_cookie.get(&cookie).map(|record| (record.pointer, record.altitude.clone(), record.active, record.removing)))
}
