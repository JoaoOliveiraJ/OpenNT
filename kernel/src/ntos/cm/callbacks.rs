//! Filtros nativos do registro.
//!
//! Cada inscrição tem altitude copiada, cookie e referências das notificações
//! em andamento. As estruturas ficam na memória do convidado e as rotinas
//! rodam pela ABI x64, sempre sem lock retido.
//!
//! Como no ntoskrnl 19041:
//! - o CmRegisterCallback (rva 0x7d5410) é o CmpRegisterCallbackInternal com
//!   a altitude legada `425000` (CmLegacyAltitude) e altitude repetida
//!   permitida: a inscrição nova entra depois das de mesma altitude;
//! - o CmSetCallbackObjectContext (rva 0x5d5830) guarda um contexto por
//!   objeto de chave e inscrição (a lista ContextListHead do CM_KEY_BODY):
//!   Object que não é um corpo 'ky02' é STATUS_INVALID_PARAMETER_1, cookie
//!   sem inscrição STATUS_INVALID_PARAMETER_2; um contexto existente é
//!   trocado e o antigo devolvido. O contexto vai no ObjectContext das
//!   notificações seguintes sobre o objeto (CmpCallbackFillObjectContext), e
//!   a destruição do objeto ou a remoção da inscrição o entrega ao filtro
//!   com RegNtCallbackObjectContextCleanup;
//! - o CmCallbackGetKeyObjectID (rva 0x8699e0) devolve o KeyControlBlock do
//!   corpo como identidade e o nome da chave em cache nela; o ...Ex (rva
//!   0x6de900, Flags tem de ser 0) devolve um nome novo, que o
//!   CmCallbackReleaseKeyObjectIDEx libera (pool 'CMNb');
//! - o CmGetBoundTransaction (rva 0x69fe90) devolve o Trans do corpo (nulo
//!   com o bit 0 ligado ou sem cookie); o CmGetCallbackVersion (rva
//!   0x869b10) devolve 1 e 1.

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
use crate::ntos::cm::out;
use crate::ntos::inc::types::{CmKeyBody, Field, LargeInteger, NtStruct, RegPostOperationInformation, Reserved, UnicodeString};
use crate::ntos::inc::types::extra_se_cm::RegCallbackContextCleanupInformation;
use crate::ntos::cm::key::objects as key_objects;
use crate::ntos::cm::registry;
use crate::ntos::ex::pool_allocation;

/// PagedPool e a tag 'CMNb' dos nomes do CmCallbackGetKeyObjectIDEx.
const PAGED_POOL: u32 = 1;
const NAME_TAG: u32 = 0x624e_4d43;

/// Registro de inscrição em pool paginado (layout do OpenNT, modelado no
/// bloco de callback do NT): cookie, contexto, rotina e a altitude copiada.
#[repr(C)]
struct CallbackRecord {
    _reserved_00: Reserved<0x18>,
    cookie: Field<u64>,
    context: Field<u64>,
    function: Field<u64>,
    altitude: UnicodeString,
    _reserved_40: Reserved<0x10>,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for CallbackRecord {}

const _: () = {
    assert!(core::mem::size_of::<CallbackRecord>() == 80);
    assert!(core::mem::offset_of!(CallbackRecord, cookie) == 0x18);
    assert!(core::mem::offset_of!(CallbackRecord, altitude) == 0x30);
};

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
    /// Contextos de objeto: (corpo da chave, cookie, contexto).
    contexts: Vec<(u64, u64, u64)>,
}

/// RegNtCallbackObjectContextCleanup.
pub const CONTEXT_CLEANUP: u32 = 40;
/// A altitude das inscrições do CmRegisterCallback (CmLegacyAltitude).
pub const LEGACY_ALTITUDE: &str = "425000";

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
    // SAFETY: PCUNICODE_STRING Altitude do chamador.
    let altitude = unsafe { UnicodeString::at(altitude) };
    let copied = guest::read_bytes(altitude.buffer.get(), altitude.length.get() as usize);
    register_internal(callback, &copied, false, context, output_cookie)
}

/// CmRegisterCallback(Function, Context, Cookie*): a altitude legada, com
/// altitude repetida permitida.
pub fn register_legacy(callback: u64, context: u64, output_cookie: u64) -> Result<u32, KernelError> {
    validate_interrupt_level()?;
    let altitude: Vec<u8> = LEGACY_ALTITUDE.encode_utf16().flat_map(u16::to_le_bytes).collect();
    register_internal(callback, &altitude, true, context, output_cookie)
}

/// CmpRegisterCallbackInternal: o bloco de 0x50 bytes ('CMcb') com a
/// altitude copiada ('CMca') e a inserção por altitude
/// (CmpInsertCallbackInListByAltitude); o cookie é publicado mesmo quando a
/// altitude repetida é recusada (STATUS_FLT_INSTANCE_ALTITUDE_COLLISION).
fn register_internal(callback: u64, copied: &[u8], allow_same_altitude: bool, context: u64, output_cookie: u64) -> Result<u32, KernelError> {
    let length = copied.len() as u16;
    let Ok(record) = kernel_pool::allocate(CallbackRecord::SIZE, AllocateOptions { paged: true, tag: 0x6263_4D43, zero: true, ..Default::default() }) else {
        return Ok(0xC000_009A);
    };
    let Ok(buffer) = kernel_pool::allocate((length as u64).max(1), AllocateOptions { paged: true, tag: 0x6163_4D43, zero: true, ..Default::default() }) else {
        let _ = kernel_pool::free(record, None);
        return Ok(0xC000_009A);
    };
    guest::write_bytes(buffer, copied);
    let units: Vec<u16> = copied.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    let text = String::from_utf16_lossy(&units);
    let (cookie, collision) = with(|callbacks| {
        callbacks.sequence += 1;
        (callbacks.sequence, !allow_same_altitude && callbacks.by_cookie.values().any(|existing| compare_altitude(&existing.altitude, &text) == Ordering::Equal))
    });
    // SAFETY: registro próprio recém-alocado e zerado.
    let block = unsafe { CallbackRecord::at(record) };
    block.cookie.set(cookie);
    block.context.set(context);
    block.function.set(callback);
    block.altitude.length.set(length);
    block.altitude.maximum_length.set(length);
    block.altitude.buffer.set(buffer);
    // SAFETY: PLARGE_INTEGER Cookie do chamador.
    unsafe { LargeInteger::at(output_cookie) }.quad_part.set(cookie as i64);
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
    let registered = with(|callbacks| {
        if !callbacks.by_cookie.get(&cookie).is_some_and(|record| !record.removing) {
            return Ok(false);
        }
        if callbacks.active_by_thread.get(&thread).is_some_and(|stack| !stack.is_empty()) {
            return Err(KernelError::new("CM callback cannot unregister from a registry notification"));
        }
        Ok(true)
    })?;
    if !registered {
        return Ok(Removal { cookie: None, completed: false });
    }
    // CmpFreeCallbackObjectContexts: os contextos desta inscrição voltam ao
    // filtro antes da remoção.
    let contexts = with(|callbacks| take_contexts(callbacks, |&(_, owner, _)| owner == cookie));
    deliver_cleanup(contexts);
    with(|callbacks| {
        if let Some(record) = callbacks.by_cookie.get_mut(&cookie) {
            record.removing = true;
        }
    });
    Ok(Removal { cookie: Some(cookie), completed: false })
}

/// Tira da lista os contextos escolhidos.
fn take_contexts(callbacks: &mut Callbacks, select: impl Fn(&(u64, u64, u64)) -> bool) -> Vec<(u64, u64, u64)> {
    let mut taken = Vec::new();
    callbacks.contexts.retain(|entry| {
        if select(entry) {
            taken.push(*entry);
            false
        } else {
            true
        }
    });
    taken
}

/// RegNtCallbackObjectContextCleanup de cada (corpo, cookie, contexto),
/// com o REG_CALLBACK_CONTEXT_CLEANUP_INFORMATION.
fn deliver_cleanup(entries: Vec<(u64, u64, u64)>) {
    if entries.is_empty() {
        return;
    }
    let information = guest::alloc_bytes(RegCallbackContextCleanupInformation::SIZE);
    if information == 0 {
        return;
    }
    // SAFETY: bloco próprio recém-alocado.
    let block = unsafe { RegCallbackContextCleanupInformation::at(information) };
    for (body, cookie, context) in entries {
        let Some(record) = with(|callbacks| callbacks.by_cookie.get(&cookie).cloned()) else { continue };
        block.object.set(body);
        block.object_context.set(context);
        block.reserved.set(0);
        let _ = invoke(cookie, &record, CONTEXT_CLEANUP, information);
    }
    guest::free_bytes(information);
}

/// O objeto de chave foi destruído: os contextos dele voltam aos filtros.
pub fn object_destroyed(body: u64) {
    let contexts = with(|callbacks| take_contexts(callbacks, |&(object, _, _)| object == body));
    deliver_cleanup(contexts);
}

/// O contexto de uma inscrição num objeto (CmpGetCallbackObjectContext).
fn context_for(object: u64, cookie: u64) -> u64 {
    if object == 0 {
        return 0;
    }
    with(|callbacks| callbacks.contexts.iter().find(|&&(body, owner, _)| body == object && owner == cookie).map_or(0, |&(_, _, context)| context))
}

/// O Object é um corpo de chave vivo ('ky02').
fn is_key_body(object: u64) -> bool {
    object != 0 && guest::try_read::<u32>(object).is_ok_and(|kind| kind == key_objects::KEY_BODY_TYPE)
}

/// CmSetCallbackObjectContext(Object, Cookie*, NewContext, OldContext*).
pub fn set_object_context(object: u64, cookie: u64, new_context: u64, old_context: u64) -> u32 {
    if !is_key_body(object) {
        return 0xC000_00EF;
    }
    if old_context != 0 {
        out::<u64>(old_context).set(0);
    }
    // SAFETY: PLARGE_INTEGER Cookie do chamador de modo kernel.
    let cookie = unsafe { LargeInteger::at(cookie) }.quad_part.get() as u64;
    let previous = with(|callbacks| {
        if let Some(entry) = callbacks.contexts.iter_mut().find(|entry| entry.0 == object && entry.1 == cookie) {
            return Ok(Some(core::mem::replace(&mut entry.2, new_context)));
        }
        if !callbacks.by_cookie.contains_key(&cookie) {
            return Err(0xC000_00F0);
        }
        callbacks.contexts.push((object, cookie, new_context));
        Ok(None)
    });
    match previous {
        Ok(Some(previous)) => {
            if old_context != 0 {
                out::<u64>(old_context).set(previous);
            }
            0
        }
        Ok(None) => 0,
        Err(status) => status,
    }
}

/// O nome da chave de um corpo: o caminho real do nó vivo, senão o do
/// handle.
fn key_name(object: u64) -> Option<String> {
    let body = key_objects::get(object)?;
    Some(registry::path_of(body.node).unwrap_or(body.path))
}

/// CmCallbackGetKeyObjectID(Cookie, Object, ObjectID*, ObjectName**): a
/// identidade é o KeyControlBlock do corpo e o nome fica em cache nela.
pub fn get_key_object_id(cookie: u64, object: u64, object_id: u64, object_name: u64) -> u32 {
    if !is_key_body(object) || cookie == 0 {
        return 0xC000_000D;
    }
    // SAFETY: corpo de chave vivo conferido acima.
    let identity = unsafe { CmKeyBody::at(object) }.key_control_block.get();
    if object_id != 0 {
        out::<u64>(object_id).set(identity);
    }
    if object_name == 0 {
        return 0;
    }
    if identity & 1 != 0 || identity == 0 {
        return 0xC000_000D;
    }
    // CmpConstructAndCacheName: o UNICODE_STRING no início da identidade.
    // SAFETY: bloco de identidade de `key_objects`, vivo com o nó.
    let cached = unsafe { UnicodeString::at(identity) };
    if cached.buffer.get() == 0 {
        let Some(name) = key_name(object) else { return 0xC000_009A };
        let units: Vec<u16> = name.encode_utf16().collect();
        let Ok(buffer) = kernel_pool::allocate(units.len() as u64 * 2 + 2, AllocateOptions { paged: true, tag: 0x6e4b_4d43, zero: true, ..Default::default() }) else { return 0xC000_009A };
        guest::write_bytes(buffer, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        cached.length.set(units.len() as u16 * 2);
        cached.maximum_length.set(units.len() as u16 * 2 + 2);
        cached.buffer.set(buffer);
    }
    out::<u64>(object_name).set(identity);
    0
}

/// CmCallbackGetKeyObjectIDEx(Cookie, Object, ObjectID*, ObjectName**,
/// Flags): o nome é uma cópia nova ('CMNb', o UNICODE_STRING seguido do
/// texto), liberada pelo CmCallbackReleaseKeyObjectIDEx.
pub fn get_key_object_id_ex(cookie: u64, object: u64, object_id: u64, object_name: u64, flags: u32) -> u32 {
    if !is_key_body(object) || cookie == 0 || flags != 0 {
        return 0xC000_000D;
    }
    // SAFETY: corpo de chave vivo conferido acima.
    let identity = unsafe { CmKeyBody::at(object) }.key_control_block.get();
    if object_id != 0 {
        out::<u64>(object_id).set(identity);
    }
    if object_name == 0 {
        return 0;
    }
    if identity & 1 != 0 {
        return 0xC000_000D;
    }
    let Some(name) = key_name(object) else { return 0xC000_009A };
    let units: Vec<u16> = name.encode_utf16().collect();
    let Ok(block) = pool_allocation::allocate_tagged(PAGED_POOL, UnicodeString::SIZE + units.len() as u64 * 2 + 2, NAME_TAG) else { return 0xC000_009A };
    guest::write_bytes(block, &[0u8; UnicodeString::SIZE as usize]);
    let text = block + UnicodeString::SIZE;
    guest::write_bytes(text, &units.iter().flat_map(|unit| unit.to_le_bytes()).chain([0, 0]).collect::<Vec<u8>>());
    // SAFETY: bloco próprio recém-alocado.
    let string = unsafe { UnicodeString::at(block) };
    string.length.set(units.len() as u16 * 2);
    string.maximum_length.set(units.len() as u16 * 2 + 2);
    string.buffer.set(text);
    out::<u64>(object_name).set(block);
    0
}

/// CmCallbackReleaseKeyObjectIDEx(ObjectName).
pub fn release_key_object_id_ex(object_name: u64) -> Result<(), KernelError> {
    if object_name == 0 {
        return Ok(());
    }
    pool_allocation::free(object_name, NAME_TAG as u64)
}

/// CmGetBoundTransaction(Cookie, Object): o Trans do corpo; nulo sem cookie
/// ou com o bit 0 (transação leve).
pub fn bound_transaction(cookie: u64, object: u64) -> u64 {
    if cookie == 0 || !is_key_body(object) {
        return 0;
    }
    // SAFETY: corpo de chave vivo conferido acima.
    let trans = unsafe { CmKeyBody::at(object) }.trans.trans_ptr.get();
    if trans & 1 != 0 { 0 } else { trans & !1 }
}

/// CmGetCallbackVersion(Major*, Minor*): 1 e 1.
pub fn callback_version(major: u64, minor: u64) {
    for pointer in [major, minor] {
        if pointer != 0 {
            out::<u32>(pointer).set(1);
        }
    }
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
    // REG_POST_OPERATION_INFORMATION e o frame de três argumentos.
    let workspace = guest::alloc_bytes(80);
    if workspace == 0 {
        return Ok(Ok(R::from_status(0xC000_009A)));
    }
    let post_information = workspace;
    // SAFETY: o início do workspace próprio guarda a REG_POST_OPERATION_INFORMATION.
    let post = unsafe { RegPostOperationInformation::at(post_information) };
    // CallContext da notificação REG_*_INFORMATION (offset do layout da classe).
    let call_context: &Field<u64> = out::<u64>(operation.info + operation.call_offset);
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
        call_context.set(0);
        // CmpCallbackFillObjectContext: o ObjectContext da inscrição no
        // objeto da operação, logo depois do CallContext.
        out::<u64>(operation.info + operation.call_offset + 8).set(context_for(operation.object, cookie));
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
        posts.push((cookie, record, call_context.get()));
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
        call_context.set(*context);
        let object = if result.status() == 0 { if result.object() != 0 { result.object() } else { operation.object } } else { 0 };
        post.object.set(object);
        post.status.set(result.status() as i32);
        post.pre_information.set(operation.info);
        post.return_status.set(result.status() as i32);
        post.call_context.set(*context);
        post.object_context.set(context_for(operation.object, *cookie));
        post.reserved.set(0);
        let status = invoke(*cookie, record, operation.post, post_information);
        if !operation.unblockable && status == CALLBACK_BYPASS {
            result.set_status(post.return_status.get() as u32);
            result.set_object(post.object.get());
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
