//! Objetos de callback do Executive.
//!
//! ExCreateCallback, ExRegisterCallback, ExUnregisterCallback e
//! ExNotifyCallback. Corpo nativo de 0x38 bytes (tag 'Call', LIST_ENTRY dos
//! registros em +0x10, AllowMultipleCallbacks em +0x20) e registros de 0x30
//! bytes (objeto +0x10, rotina +0x18, contexto +0x20, chamadas ativas +0x28,
//! retirada +0x2C).
//!
//! Handles de usuário (`ps/user/state`) entram na fase 7.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::callback_security;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{dispatcher, irql};
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ob::close::{self, KernelHandleOwner};
use crate::ntos::ob::object_manager::{self, NodeId, ObjectData, ObjectHooks, OpenOptions};
use crate::ntos::ob::object_types::{self, ObjectType};
use crate::ntos::ob::open_pointer::{self, ObjectOwner, Slot};
use crate::ntos::ps::process;
use crate::ntos::se::model::SecurityPolicy;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{ListEntry, ObjectAttributes, UnicodeString};
use crate::ntos::rtl::guest_strings;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const OBJECT_PERMANENT: u32 = 0x10;
const OBJECT_CASE_INSENSITIVE: u32 = 0x40;
const OBJECT_KERNEL_HANDLE: u32 = 0x200;
const OBJECT_POOL_TAG: u32 = 0x6C6C_6143;
const REGISTRATION_POOL_TAG: u32 = 0x6552_4243;

/// Corpo do objeto Callback (0x38 bytes): assinatura 'Call', a lista dos
/// registros e AllowMultipleCallbacks. O estado real vive em `STATE`; o corpo
/// espelha a ordem dos registros para quem percorre a lista.
#[repr(C)]
struct CallbackObject {
    signature: Field<u32>,
    _pad_4: Reserved<0xC>,
    registered_callbacks: ListEntry,
    allow_multiple_callbacks: Field<u8>,
    _pad_21: Reserved<0x17>,
}

/// Registro de 0x30 bytes: vínculo, objeto, rotina, contexto, chamadas
/// ativas e retirada pendente.
#[repr(C)]
struct CallbackRegistration {
    link: ListEntry,
    /// -> corpo do objeto Callback.
    callback_object: Field<u64>,
    callback_function: Field<u64>,
    callback_context: Field<u64>,
    busy: Field<u32>,
    unregister_waiting: Field<u8>,
    _pad_2d: Reserved<0x3>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CallbackObject {}
// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for CallbackRegistration {}

const _: () = {
    assert!(core::mem::size_of::<CallbackObject>() == 0x38);
    assert!(core::mem::offset_of!(CallbackObject, registered_callbacks) == 0x10);
    assert!(core::mem::offset_of!(CallbackObject, allow_multiple_callbacks) == 0x20);
    assert!(core::mem::size_of::<CallbackRegistration>() == 0x30);
    assert!(core::mem::offset_of!(CallbackRegistration, callback_object) == 0x10);
    assert!(core::mem::offset_of!(CallbackRegistration, busy) == 0x28);
    assert!(core::mem::offset_of!(CallbackRegistration, unregister_waiting) == 0x2C);
};

fn object_at(pointer: u64) -> &'static CallbackObject {
    // SAFETY: só corpos alocados por `allocate_named` chegam aqui.
    unsafe { CallbackObject::at(pointer) }
}

/// O PCALLBACK_OBJECT de saída do chamador (modo kernel).
fn write_output(output: u64, pointer: u64) {
    // SAFETY: parâmetro de saída do ExCreateCallback.
    unsafe { Field::<u64>::at(output) }.set(pointer);
}

fn registration_at(pointer: u64) -> &'static CallbackRegistration {
    // SAFETY: só registros alocados por `register` chegam aqui.
    unsafe { CallbackRegistration::at(pointer) }
}

struct Item {
    references: u32,
    handles: u32,
    permanent: bool,
    named: bool,
    node: Option<NodeId>,
    name: Option<String>,
    registrations: Vec<u64>,
    multiple: bool,
    security: SecurityPolicy,
    dpc_notification: bool,
}

struct Registration {
    item: u64,
    callback: u64,
    context: u64,
    sequence: u64,
    active: u32,
    removing: bool,
}

struct State {
    objects: BTreeMap<u64, Item>,
    registrations: BTreeMap<u64, Registration>,
    kernel_handles: BTreeMap<u64, u32>,
    sequence: u64,
}

static STATE: SpinLock<State> = SpinLock::new(State { objects: BTreeMap::new(), registrations: BTreeMap::new(), kernel_handles: BTreeMap::new(), sequence: 0 });

fn require_irql(maximum: u8) -> Result<(), KernelError> {
    if irql::get_irql() > maximum {
        return Err(KernelError::new("callback API at invalid IRQL"));
    }
    Ok(())
}

fn callback_type() -> ObjectType {
    object_types::callback_type()
}

pub fn exists(pointer: u64) -> bool {
    STATE.lock().objects.contains_key(&pointer)
}

fn require_live(pointer: u64) -> Result<(), KernelError> {
    if exists(pointer) { Ok(()) } else { Err(KernelError::new("invalid callback object")) }
}

/// Publica a lista circular de registros no corpo, na ordem do dono.
fn synchronize_registration_list(state: &State, pointer: u64) {
    let head = &object_at(pointer).registered_callbacks;
    let head_address = head.address();
    let list: &[u64] = state.objects.get(&pointer).map_or(&[], |item| item.registrations.as_slice());
    head.flink.set(list.first().copied().unwrap_or(head_address));
    head.blink.set(list.last().copied().unwrap_or(head_address));
    for (index, &registration) in list.iter().enumerate() {
        let link = &registration_at(registration).link;
        link.flink.set(list.get(index + 1).copied().unwrap_or(head_address));
        link.blink.set(if index > 0 { list[index - 1] } else { head_address });
    }
}

/// Remove uma única vez o nome; referências existentes continuam válidas.
fn remove_object_name(pointer: u64) {
    let node = {
        let mut state = STATE.lock();
        let Some(item) = state.objects.get_mut(&pointer) else { return };
        if !item.named {
            return;
        }
        item.named = false;
        item.node
    };
    if let Some(node) = node {
        object_manager::remove_named(node);
    }
}

/// Libera o corpo não permanente sem referências nem handles.
fn collect(pointer: u64) -> Result<(), KernelError> {
    {
        let state = STATE.lock();
        let Some(item) = state.objects.get(&pointer) else { return Ok(()) };
        if item.permanent || item.references != 0 || item.handles != 0 {
            return Ok(());
        }
        if !item.registrations.is_empty() {
            return Err(KernelError::new("callback registrations lost their object references"));
        }
    }
    remove_object_name(pointer);
    STATE.lock().objects.remove(&pointer);
    object_types::account(&callback_type().name, -1, 0)?;
    kernel_pool::free(pointer, None)
}

pub fn reference(pointer: u64) -> Option<u32> {
    let mut state = STATE.lock();
    let item = state.objects.get_mut(&pointer)?;
    item.references += 1;
    Some(item.references)
}

pub fn dereference(pointer: u64) -> Result<Option<u32>, KernelError> {
    let count = {
        let mut state = STATE.lock();
        let Some(item) = state.objects.get_mut(&pointer) else { return Ok(None) };
        if item.references == 0 {
            return Err(KernelError::new("callback reference underflow"));
        }
        item.references -= 1;
        item.references
    };
    collect(pointer)?;
    Ok(Some(count))
}

/// OBJECT_ATTRIBUTES capturados para a criação.
pub struct Captured {
    pub flags: u32,
    pub parent: NodeId,
    pub name: String,
    pub full: String,
    pub insensitive: bool,
    pub node: Option<NodeId>,
    pub security_descriptor: u64,
}

/// Captura OBJECT_ATTRIBUTES e o nome, resolve a raiz e confere o caminho.
pub fn attributes(pointer: u64) -> Result<Captured, u32> {
    if pointer == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: ExCreateCallback recebe POBJECT_ATTRIBUTES de modo kernel.
    let object_attributes = unsafe { ObjectAttributes::at(pointer) };
    if object_attributes.length.get() as u64 != ObjectAttributes::SIZE {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let root = object_attributes.root_directory.get();
    let name_pointer = object_attributes.object_name.get();
    let flags = object_attributes.attributes.get();
    if name_pointer == 0 {
        return Err(0xC000_0001);
    }
    // SAFETY: ObjectName é o PUNICODE_STRING do mesmo chamador.
    let object_name = unsafe { UnicodeString::at(name_pointer) };
    let length = object_name.length.get();
    let maximum = object_name.maximum_length.get();
    let buffer = object_name.buffer.get();
    if length & 1 != 0 || length > maximum || (buffer == 0 && length != 0) {
        return Err(0xC000_0033);
    }
    let name = guest_strings::read_unicode_string(name_pointer);
    if name.is_empty() || name.contains('\0') || name.ends_with('\\') {
        return Err(0xC000_0033);
    }
    let full = if root != 0 {
        if name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        let directory = if root <= 0x7FFF_FFFF { object_manager::get_object(root as u32) } else { None };
        let Some(directory) = directory else { return Err(0xC000_0008) };
        if object_manager::node(directory).is_none_or(|node| node.type_name != "Directory") {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        let Some(path) = object_manager::path_of(directory) else { return Err(0xC000_003A) };
        alloc::format!("{}\\{}", if path == "\\" { "" } else { path.as_str() }, name)
    } else {
        if !name.starts_with('\\') {
            return Err(0xC000_003B);
        }
        name
    };
    let separator = full.rfind('\\').unwrap_or(0);
    let parent_path = if separator == 0 { String::from("\\") } else { String::from(&full[..separator]) };
    let insensitive = flags & OBJECT_CASE_INSENSITIVE != 0;
    let Some(parent) = object_manager::resolve_from(&parent_path, 0, insensitive, false, object_manager::ROOT).0 else {
        return Err(0xC000_003A);
    };
    if object_manager::node(parent).is_none_or(|node| node.type_name != "Directory" || node.mount.is_some()) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    let node = object_manager::resolve_from(&full, 0, insensitive, false, object_manager::ROOT).0;
    Ok(Captured { flags, parent, name: String::from(&full[separator + 1..]), full, insensitive, node, security_descriptor: object_attributes.security_descriptor.get() })
}

/// Aloca o corpo de 0x38 bytes, registra o tipo e publica o nome opcional.
fn allocate_named(captured: Option<&Captured>, multiple: bool, permanent: bool, security: SecurityPolicy) -> Result<u64, KernelError> {
    let type_name = callback_type().name;
    let pointer = kernel_pool::allocate(CallbackObject::SIZE, AllocateOptions { tag: OBJECT_POOL_TAG, zero: true, ..AllocateOptions::default() })?;
    if pointer == 0 {
        return Ok(0);
    }
    let mut node = None;
    let mut name = None;
    if let Some(captured) = captured {
        match object_manager::insert_named(captured.parent, &captured.name, "Callback", Some(ObjectData::pointer(pointer)), captured.insensitive) {
            Some(inserted) => {
                node = Some(inserted);
                name = object_manager::path_of(inserted);
            }
            None => {
                kernel_pool::free(pointer, None)?;
                return Ok(0);
            }
        }
    }
    let body = object_at(pointer);
    body.signature.set(OBJECT_POOL_TAG);
    body.allow_multiple_callbacks.set(multiple as u8);
    {
        let mut state = STATE.lock();
        state.objects.insert(pointer, Item { references: 1, handles: 0, permanent, named: captured.is_some(), node, name, registrations: Vec::new(), multiple, security, dpc_notification: false });
        synchronize_registration_list(&state, pointer);
    }
    object_types::account(&type_name, 1, 0)?;
    register_owners();
    Ok(pointer)
}

/// Objeto sem nome de uso interno, com a política padrão do sujeito.
pub fn create_internal(multiple: bool) -> Result<u64, KernelError> {
    require_irql(1)?;
    let security = callback_security::capture(0).unwrap_or_default();
    allocate_named(None, multiple, false, security)
}

/// ExCreateCallback: reutiliza um callback existente ou cria quando
/// `create_new` permite; a saída recebe uma referência por ponteiro.
pub fn create(output: u64, object_attributes: u64, create_new: bool, multiple: bool) -> Result<u32, KernelError> {
    require_irql(1)?;
    let captured = match attributes(object_attributes) {
        Ok(captured) => captured,
        Err(status) => return Ok(status),
    };
    if let Some(node) = captured.node {
        let Some(snapshot) = object_manager::node(node).filter(|node| node.type_name == "Callback") else {
            return Ok(STATUS_OBJECT_TYPE_MISMATCH);
        };
        let pointer = snapshot.data.map_or(0, |data| data.native_pointer);
        require_live(pointer)?;
        reference(pointer);
        write_output(output, pointer);
        return Ok(0);
    }
    if !create_new {
        return Ok(STATUS_OBJECT_NAME_NOT_FOUND);
    }
    // A segurança é capturada antes da publicação (sobrevive ao buffer).
    let security = match callback_security::capture(captured.security_descriptor) {
        Ok(policy) => policy,
        Err(status) => return Ok(status),
    };
    let permanent = captured.flags & OBJECT_PERMANENT != 0;
    let pointer = allocate_named(Some(&captured), multiple, permanent, security)?;
    if pointer == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // ExCreateCallback fecha o handle interno; o nome temporário some aí.
    if !permanent {
        remove_object_name(pointer);
    }
    write_output(output, pointer);
    Ok(0)
}

/// ExRegisterCallback: registro de 0x30 bytes que retém o objeto. 0 quando
/// a política ou a alocação impede.
pub fn register(pointer: u64, callback: u64, context: u64) -> Result<u64, KernelError> {
    require_irql(1)?;
    require_live(pointer)?;
    {
        let state = STATE.lock();
        let item = &state.objects[&pointer];
        if !item.multiple && !item.registrations.is_empty() {
            return Ok(0);
        }
    }
    let registration = kernel_pool::allocate(CallbackRegistration::SIZE, AllocateOptions { tag: REGISTRATION_POOL_TAG, zero: true, ..AllocateOptions::default() })?;
    if registration == 0 {
        return Ok(0);
    }
    reference(pointer);
    let mut state = STATE.lock();
    state.sequence += 1;
    let sequence = state.sequence;
    state.registrations.insert(registration, Registration { item: pointer, callback, context, sequence, active: 0, removing: false });
    state.objects.get_mut(&pointer).unwrap().registrations.push(registration);
    let record = registration_at(registration);
    record.callback_object.set(pointer);
    record.callback_function.set(callback);
    record.callback_context.set(context);
    synchronize_registration_list(&state, pointer);
    Ok(registration)
}

/// Retirada suspensível: só libera quando as chamadas ativas acabam.
pub struct UnregisterRequest {
    registration: u64,
    done: bool,
}

pub fn begin_unregister(registration: u64) -> Result<UnregisterRequest, KernelError> {
    require_irql(1)?;
    let mut state = STATE.lock();
    let Some(record) = state.registrations.get_mut(&registration).filter(|record| !record.removing) else {
        return Err(KernelError::new("invalid callback registration removal"));
    };
    record.removing = true;
    registration_at(registration).unregister_waiting.set(1);
    Ok(UnregisterRequest { registration, done: false })
}

impl UnregisterRequest {
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if self.done {
            return Ok(Some(0));
        }
        let item = {
            let mut state = STATE.lock();
            let Some(record) = state.registrations.get(&self.registration) else { return Ok(Some(0)) };
            if record.active != 0 {
                return Ok(None);
            }
            let item = record.item;
            state.registrations.remove(&self.registration);
            if let Some(owner) = state.objects.get_mut(&item) {
                owner.registrations.retain(|&entry| entry != self.registration);
            }
            synchronize_registration_list(&state, item);
            item
        };
        kernel_pool::free(self.registration, None)?;
        self.done = true;
        dereference(item)?;
        Ok(Some(0))
    }

    pub fn cancel(&mut self) {
        if !self.done {
            if let Some(record) = STATE.lock().registrations.get_mut(&self.registration) {
                record.removing = false;
            }
            registration_at(self.registration).unregister_waiting.set(0);
            self.done = true;
        }
    }
}

/// ExUnregisterCallback: avança o dispatcher até as chamadas terminarem.
pub fn unregister(registration: u64) -> Result<u32, KernelError> {
    let mut request = begin_unregister(registration)?;
    loop {
        if let Some(status) = request.poll()? {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

/// Uma chamada pendente da notificação: rotina e argumentos.
pub struct PendingCall {
    pub callback: u64,
    pub arguments: [u64; 3],
}

/// Notificação suspensível: cada poll entrega no máximo uma chamada.
pub struct NotifyRequest {
    pointer: u64,
    first: u64,
    second: u64,
    at_dispatch: bool,
    previous_sequence: u64,
    pending: Option<u64>,
    done: bool,
}

pub fn begin_notify(pointer: u64, first: u64, second: u64) -> Result<NotifyRequest, KernelError> {
    require_irql(2)?;
    if pointer == 0 {
        return Ok(NotifyRequest { pointer, first, second, at_dispatch: false, previous_sequence: 0, pending: None, done: true });
    }
    require_live(pointer)?;
    // Em DISPATCH_LEVEL a notificação exclui reentrada no mesmo corpo.
    let at_dispatch = irql::get_irql() == 2;
    {
        let mut state = STATE.lock();
        let item = state.objects.get_mut(&pointer).unwrap();
        if item.dpc_notification {
            return Err(KernelError::new("callback object reentered while its DPC spin lock is held"));
        }
        if at_dispatch {
            item.dpc_notification = true;
        }
    }
    reference(pointer);
    Ok(NotifyRequest { pointer, first, second, at_dispatch, previous_sequence: 0, pending: None, done: false })
}

impl NotifyRequest {
    fn finish(&mut self) -> Result<(), KernelError> {
        if !self.done {
            self.done = true;
            if self.at_dispatch {
                if let Some(item) = STATE.lock().objects.get_mut(&self.pointer) {
                    item.dpc_notification = false;
                }
            }
            dereference(self.pointer)?;
        }
        Ok(())
    }

    /// `Some(chamada)` a executar, ou `None` quando terminou.
    pub fn poll(&mut self) -> Result<Option<PendingCall>, KernelError> {
        if self.done {
            return Ok(None);
        }
        if self.pending.is_some() {
            return Err(KernelError::new("callback notification resumed before its callback returned"));
        }
        let next = {
            let mut state = STATE.lock();
            let registrations = state.objects.get(&self.pointer).map(|item| item.registrations.clone()).unwrap_or_default();
            // Em DISPATCH_LEVEL a visita inclui registros com retirada pendente.
            let found = registrations.into_iter().find(|entry| state.registrations.get(entry).is_some_and(|record| record.sequence > self.previous_sequence && (self.at_dispatch || !record.removing)));
            found.map(|entry| {
                let record = state.registrations.get_mut(&entry).unwrap();
                record.active += 1;
                registration_at(entry).busy.set(record.active);
                (entry, record.callback, record.context)
            })
        };
        let Some((entry, callback, context)) = next else {
            self.finish()?;
            return Ok(None);
        };
        self.pending = Some(entry);
        Ok(Some(PendingCall { callback, arguments: [context, self.first, self.second] }))
    }

    pub fn resume(&mut self) -> Result<(), KernelError> {
        let Some(entry) = self.pending.take() else {
            return Err(KernelError::new("callback notification has no active registration"));
        };
        let mut state = STATE.lock();
        if let Some(record) = state.registrations.get_mut(&entry) {
            record.active -= 1;
            registration_at(entry).busy.set(record.active);
            self.previous_sequence = record.sequence;
        }
        Ok(())
    }

    pub fn cancel(&mut self) -> Result<(), KernelError> {
        if let Some(entry) = self.pending.take() {
            if let Some(record) = STATE.lock().registrations.get_mut(&entry) {
                record.active -= 1;
                registration_at(entry).busy.set(record.active);
            }
        }
        self.finish()
    }
}

/// ExNotifyCallback: chama cada registro pela ABI nativa (três argumentos).
pub fn notify(pointer: u64, first: u64, second: u64) -> Result<(), KernelError> {
    let mut request = begin_notify(pointer, first, second)?;
    loop {
        match request.poll() {
            Ok(Some(call)) => {
                native_call::call(call.callback, &call.arguments);
                request.resume()?;
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                request.cancel()?;
                return Err(error);
            }
        }
    }
}

/// Uma abertura retém o corpo e conta handles do objeto e do tipo.
pub fn retain_handle(pointer: u64) -> Result<(), KernelError> {
    if let Some(item) = STATE.lock().objects.get_mut(&pointer) {
        item.handles += 1;
    }
    reference(pointer);
    object_types::account(&callback_type().name, 0, 1)
}

/// O último handle remove o nome de um objeto temporário.
pub fn close_handle(pointer: u64) -> Result<(), KernelError> {
    let (remaining, permanent) = {
        let mut state = STATE.lock();
        let item = state.objects.get_mut(&pointer).ok_or_else(|| KernelError::new("invalid callback object"))?;
        if item.handles == 0 {
            return Err(KernelError::new("callback handle underflow"));
        }
        item.handles -= 1;
        (item.handles, item.permanent)
    };
    object_types::account(&callback_type().name, 0, -1)?;
    if remaining == 0 && !permanent {
        remove_object_name(pointer);
    }
    dereference(pointer).map(|_| ())
}

struct CallbackHandle {
    pointer: u64,
}

impl ObjectHooks for CallbackHandle {
    fn on_handle_open(&self) -> Result<(), KernelError> {
        retain_handle(self.pointer)
    }
    fn on_handle_close(&self) {
        let _ = close_handle(self.pointer);
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
}

/// Verifica o acesso e publica o handle (`Ok(handle)` ou `Err(NTSTATUS)`).
pub fn open_handle(pointer: u64, requested: u32, flags: u32, from_user_mode: bool) -> Result<Result<u64, u32>, KernelError> {
    require_live(pointer)?;
    let security = STATE.lock().objects[&pointer].security.clone();
    let access = match callback_security::access(&security, requested, from_user_mode || flags & 0x400 != 0) {
        Ok(access) => access,
        Err(status) => return Ok(Err(status)),
    };
    if from_user_mode && flags & OBJECT_KERNEL_HANDLE != 0 {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    if from_user_mode || (flags & OBJECT_KERNEL_HANDLE == 0 && process::get_current_process() != process::get_system_process()) {
        // A tabela de handles de usuário entra na fase 7.
        return Ok(Err(0xC000_0002));
    }
    let owner = if flags & OBJECT_KERNEL_HANDLE != 0 { process::get_system_process() } else { process::get_current_process() };
    let name = STATE.lock().objects[&pointer].name.clone().unwrap_or_default();
    let data = ObjectData { native_pointer: pointer, access: Some(access), attributes: flags, owner_process: Some(owner), hooks: Some(Arc::new(CallbackHandle { pointer })), ..ObjectData::default() };
    let node = object_manager::new_node(&name, "Callback", Some(data));
    let kernel = flags & OBJECT_KERNEL_HANDLE != 0;
    let options = OpenOptions {
        access: Some(access),
        attributes: Some(flags),
        owner_process: Some(owner),
        on_open: Some(Arc::new(move |identifier| {
            if kernel {
                STATE.lock().kernel_handles.insert(0xFFFF_FFFF_8000_0000 | identifier as u64, identifier);
            }
        })),
        on_close: Some(Arc::new(|identifier| {
            STATE.lock().kernel_handles.remove(&(0xFFFF_FFFF_8000_0000 | identifier as u64));
        })),
        ..OpenOptions::default()
    };
    let identifier = object_manager::open_object(node, Some(options))?;
    Ok(Ok(if kernel { 0xFFFF_FFFF_8000_0000 | identifier as u64 } else { identifier as u64 }))
}

/// Só handles de callback visíveis no modo e processo atuais.
pub fn resolve_handle(handle: u64, from_user_mode: bool) -> Option<ObjectData> {
    let identifier = STATE.lock().kernel_handles.get(&handle).copied();
    if let Some(identifier) = identifier {
        return if from_user_mode { None } else { object_manager::get_object(identifier).and_then(object_manager::node).and_then(|node| node.data) };
    }
    if handle > 0x7FFF_FFFF || from_user_mode || process::get_current_process() != process::get_system_process() {
        return None;
    }
    object_manager::get_object(handle as u32).and_then(object_manager::node).filter(|node| node.type_name == "Callback").and_then(|node| node.data)
}

/// Fecha pela tabela dona; `None` = outro provedor trata o identificador.
pub fn close_native(handle: u64) -> Option<u32> {
    let identifier = STATE.lock().kernel_handles.get(&handle).copied()?;
    Some(if matches!(object_manager::close(identifier), Ok(true)) { 0 } else { 0xC000_0008 })
}

/// NtMakeTemporaryObject para callbacks.
pub fn make_temporary(handle: u64) -> Result<Option<u32>, KernelError> {
    let Some(data) = resolve_handle(handle, false) else { return Ok(None) };
    let pointer = data.native_pointer;
    require_live(pointer)?;
    let handles = {
        let mut state = STATE.lock();
        let item = state.objects.get_mut(&pointer).unwrap();
        item.permanent = false;
        item.handles
    };
    if handles == 0 {
        remove_object_name(pointer);
    }
    collect(pointer)?;
    Ok(Some(0))
}

pub fn access(pointer: u64, requested: u32, check: bool) -> Result<u32, u32> {
    let security = STATE.lock().objects.get(&pointer).map(|item| item.security.clone()).ok_or(STATUS_INVALID_PARAMETER)?;
    callback_security::access(&security, requested, check)
}

pub fn name(pointer: u64) -> Option<String> {
    STATE.lock().objects.get(&pointer).filter(|item| item.named).and_then(|item| item.name.clone())
}

/// (referências, handles, registros) de um objeto vivo.
pub fn counts(pointer: u64) -> Option<(u32, u32, usize)> {
    STATE.lock().objects.get(&pointer).map(|item| (item.references, item.handles, item.registrations.len()))
}

struct CallbackOwner;

static OWNER: CallbackOwner = CallbackOwner;

impl CallbackOwner {
    fn record(pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        let (references, handles, _) = counts(pointer).unwrap_or((0, 0, 0));
        let path = name(pointer).and_then(|name| crate::ntos::ob::object_manager::lookup(&name).and_then(crate::ntos::ob::object_manager::path_of)).unwrap_or_default();
        crate::ntos::ob::open_pointer::QueryRecord { handles: Some(handles), references, permanent: false, name: path }
    }
}

impl ObjectOwner for CallbackOwner {
    fn query_record(&self, pointer: u64) -> crate::ntos::ob::open_pointer::QueryRecord {
        Self::record(pointer)
    }
    fn object_type(&self, _pointer: u64) -> ObjectType {
        callback_type()
    }
    fn reference(&self, pointer: u64) {
        reference(pointer);
    }
    fn dereference(&self, pointer: u64) {
        let _ = dereference(pointer);
    }
    fn open_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(retain_handle(pointer))
    }
    fn close_handle(&self, pointer: u64) -> Option<Result<(), KernelError>> {
        Some(close_handle(pointer))
    }
    fn security(&self, pointer: u64) -> SecurityPolicy {
        STATE.lock().objects.get(&pointer).map(|item| item.security.clone()).unwrap_or_default()
    }
    fn data(&self, _pointer: u64) -> ObjectData {
        ObjectData::default()
    }
}

static OWNERS_REGISTERED: SpinLock<bool> = SpinLock::new(false);

/// Slot Callback do `open_pointer` e dono de handles de kernel do NtClose.
fn register_owners() {
    let mut registered = OWNERS_REGISTERED.lock();
    if *registered {
        return;
    }
    *registered = true;
    open_pointer::register_owner(Slot::Callback, exists, &OWNER);
    close::register_kernel_handle_owner(KernelHandleOwner {
        attributes: |handle| resolve_handle(handle, false).map(|data| data.attributes),
        close: |handle| close_native(handle).unwrap_or(close::STATUS_INVALID_HANDLE),
    });
}

/// Diretório \Callback e os objetos permanentes de hora, energia e
/// processadores.
pub fn init() -> Result<(), KernelError> {
    let directory = object_manager::create_directory("\\Callback")?;
    for name in ["SetSystemTime", "PowerState", "ProcessorAdd"] {
        if object_manager::lookup(&alloc::format!("\\Callback\\{name}")).is_some() {
            continue;
        }
        let captured = Captured { flags: 0, parent: directory, name: String::from(name), full: String::new(), insensitive: true, node: None, security_descriptor: 0 };
        let security = callback_security::capture(0).unwrap_or_default();
        let pointer = allocate_named(Some(&captured), true, true, security)?;
        if pointer == 0 {
            return Err(KernelError::new("system callback object allocation failed"));
        }
        dereference(pointer)?;
    }
    register_owners();
    Ok(())
}
