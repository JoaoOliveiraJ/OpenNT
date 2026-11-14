//! ObRegisterCallbacks.
//!
//! Registra callbacks de objetos e mantém as listas nativas
//! (OBJECT_TYPE.CallbackList) ordenadas por altitude. A confiança vem do
//! registro da imagem no carregador (LoaderFlags 0x20); os flags do
//! cabeçalho PE não bastam.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::object_manager::ObjectData;
use super::open_pointer::{self, Described};
use super::object_types::{self, ObjectType};
use crate::hal::amd64::native_call;
use crate::ntos::ex::rundown;
use crate::ntos::ke::{critical_region, dispatcher, irql};
use crate::ntos::mm::{kernel_pool, loaded_images};
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::inc::field::{Field, NtStruct, Reserved};
use crate::ntos::inc::types::{self as nt, ExRundownRef, ListEntry, ObCallbackRegistration, ObOperationRegistration, ObPostOperationInformation, ObPostOperationParameters, ObPreOperationInformation, ObPreOperationParameters, UnicodeString};
use crate::ntos::mm::guest_memory as guest;

/// Bloco devolvido por ObRegisterCallbacks como handle do registro. Os
/// itens seguem o cabeçalho e entram na CallbackList do OBJECT_TYPE, que
/// drivers podem percorrer: o layout é o do NT.
#[repr(C)]
struct RegistrationBlock {
    version: Field<u16>,
    operation_registration_count: Field<u16>,
    _pad_4: Reserved<4>,
    registration_context: Field<u64>,
    altitude: UnicodeString,
}

/// Item de callback de um tipo (um por OB_OPERATION_REGISTRATION).
#[repr(C)]
struct CallbackEntryItem {
    entry_item_list: ListEntry,
    operations: Field<u32>,
    active: Field<u32>,
    /// -> `RegistrationBlock`
    registration: Field<u64>,
    /// -> `_OBJECT_TYPE`
    object_type: Field<u64>,
    pre_operation: Field<u64>,
    post_operation: Field<u64>,
    rundown: ExRundownRef,
}

/// Informação entregue aos callbacks: a PRE ocupa os primeiros 0x28 bytes
/// da POST (mesma memória) e os parâmetros vêm logo depois.
#[repr(C)]
struct OperationBlock {
    information: ObPostOperationInformation,
    parameters: ObPreOperationParameters,
}

// SAFETY: #[repr(C)] só de células (Field/Reserved/NtStruct).
unsafe impl NtStruct for RegistrationBlock {}
unsafe impl NtStruct for CallbackEntryItem {}
unsafe impl NtStruct for OperationBlock {}

const _: () = {
    assert!(core::mem::size_of::<RegistrationBlock>() == 0x20);
    assert!(core::mem::offset_of!(RegistrationBlock, altitude) == 0x10);
    assert!(core::mem::size_of::<CallbackEntryItem>() == 0x40);
    assert!(core::mem::offset_of!(CallbackEntryItem, operations) == 0x10);
    assert!(core::mem::offset_of!(CallbackEntryItem, registration) == 0x18);
    assert!(core::mem::offset_of!(CallbackEntryItem, rundown) == 0x38);
    assert!(core::mem::size_of::<OperationBlock>() == 0x48);
    assert!(core::mem::offset_of!(OperationBlock, parameters) == 0x30);
};

fn entry_item(pointer: u64) -> &'static CallbackEntryItem {
    // SAFETY: itens alocados por `register`, vivos enquanto o registro existe.
    unsafe { CallbackEntryItem::at(pointer) }
}

/// Célula de rundown do item (protege a execução dos callbacks).
fn rundown_of(pointer: u64) -> u64 {
    entry_item(pointer).rundown.address()
}

#[derive(Clone)]
struct Entry {
    pointer: u64,
    record: u64,
    mask: u32,
    pre: u64,
    post: u64,
    enabled: bool,
}

struct Registration {
    context: u64,
    entries: Vec<u64>,
    altitude: String,
    removing: bool,
}

struct State {
    registrations: BTreeMap<u64, Registration>,
    by_type: BTreeMap<u64, Vec<Entry>>,
    executing: BTreeMap<u64, BTreeMap<u64, u32>>,
}

static STATE: SpinLock<State> = SpinLock::new(State { registrations: BTreeMap::new(), by_type: BTreeMap::new(), executing: BTreeMap::new() });

fn require_callback_level() -> Result<(), KernelError> {
    if irql::get_irql() > 1 {
        return Err(KernelError::new("OB callback API above APC_LEVEL"));
    }
    Ok(())
}

/// Compara altitudes decimais como texto, sem arredondar; zeros à esquerda
/// e zeros fracionários à direita não alteram a ordem.
pub fn compare_altitude(left: &str, right: &str) -> Ordering {
    fn split(text: &str) -> (&str, &str) {
        let (integer, fraction) = match text.find('.') {
            Some(index) => (&text[..index], &text[index + 1..]),
            None => (text, ""),
        };
        (integer.trim_start_matches('0'), fraction)
    }
    let (left_integer, left_fraction) = split(left);
    let (right_integer, right_fraction) = split(right);
    if left_integer.len() != right_integer.len() {
        return left_integer.len().cmp(&right_integer.len());
    }
    if left_integer != right_integer {
        return left_integer.cmp(right_integer);
    }
    let left_digits = left_fraction.as_bytes();
    let right_digits = right_fraction.as_bytes();
    for index in 0..left_digits.len().max(right_digits.len()) {
        let left_digit = left_digits.get(index).copied().unwrap_or(b'0');
        let right_digit = right_digits.get(index).copied().unwrap_or(b'0');
        if left_digit != right_digit {
            return left_digit.cmp(&right_digit);
        }
    }
    Ordering::Equal
}

/// Reescreve os links da lista nativa do OBJECT_TYPE (sentinela CallbackList).
fn synchronize_type_list(state: &State, type_pointer: u64) {
    let empty = Vec::new();
    let entries = state.by_type.get(&type_pointer).unwrap_or(&empty);
    // SAFETY: tipos registrados em `object_types` vivem até o desligamento.
    let list = &unsafe { nt::ObjectType::at(type_pointer) }.callback_list;
    let head = list.address();
    list.flink.set(entries.first().map_or(head, |entry| entry.pointer));
    list.blink.set(entries.last().map_or(head, |entry| entry.pointer));
    for (index, entry) in entries.iter().enumerate() {
        let links = &entry_item(entry.pointer).entry_item_list;
        links.flink.set(entries.get(index + 1).map_or(head, |next| next.pointer));
        links.blink.set(if index > 0 { entries[index - 1].pointer } else { head });
    }
}

fn belongs_to_verified_image(pointer: u64) -> bool {
    loaded_images::find(pointer).is_some_and(|image| image.loader_flags & 0x20 != 0)
}

/// ObRegisterCallbacks: lê OB_CALLBACK_REGISTRATION, copia a altitude e
/// valida cada operação antes de habilitá-la. O handle só é escrito depois
/// da publicação de todas as entradas.
pub fn register(registration: u64, output_handle: u64) -> Result<u32, KernelError> {
    require_callback_level()?;
    // SAFETY: OB_CALLBACK_REGISTRATION de um chamador de kernel.
    let registration = unsafe { ObCallbackRegistration::at(registration) };
    let version = registration.version.get();
    let count = registration.operation_registration_count.get() as u64;
    if version & 0xFF00 != 0x100 || count == 0 {
        return Ok(0xC000_000D);
    }
    let length = registration.altitude.length.get() as u64;
    let buffer = registration.altitude.buffer.get();
    // Cabeçalho, itens e texto da altitude numa alocação paginável.
    let pointer = kernel_pool::allocate(RegistrationBlock::SIZE + count * CallbackEntryItem::SIZE + length, kernel_pool::AllocateOptions { paged: true, tag: 0x6C46_624F, zero: true, ..Default::default() })?;
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    // SAFETY: alocação nova do tamanho do cabeçalho, dos itens e do texto.
    let block = unsafe { RegistrationBlock::at(pointer) };
    let altitude_pointer = pointer + RegistrationBlock::SIZE + count * CallbackEntryItem::SIZE;
    let context = registration.registration_context.get();
    block.version.set(0x100);
    block.registration_context.set(context);
    block.altitude.length.set(length as u16);
    block.altitude.maximum_length.set(length as u16);
    block.altitude.buffer.set(altitude_pointer);
    let text = guest::read_bytes(buffer, length as usize);
    guest::write_bytes(altitude_pointer, &text);
    let units: Vec<u16> = text.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
    let altitude = String::from_utf16_lossy(&units);
    let operations = registration.operation_registration.get();
    let mut created: Vec<u64> = Vec::new();
    let mut status = 0;
    let mut state = STATE.lock();
    state.registrations.insert(pointer, Registration { context, entries: Vec::new(), altitude: altitude.clone(), removing: false });
    // SAFETY: vetor OperationRegistration com `count` entradas do chamador.
    let operations = unsafe { ObOperationRegistration::array_at(operations, count as usize) };
    for (index, operation) in operations.iter().enumerate() {
        let index = index as u64;
        let mask = operation.operations.get();
        if mask == 0 {
            status = 0xC000_000D;
            break;
        }
        // ObjectType é um POBJECT_TYPE* (a célula exportada, como PsProcessType).
        // SAFETY: ponteiro para a célula do tipo, fornecido pelo driver.
        let type_pointer = unsafe { Field::<u64>::at(operation.object_type.get()) }.get();
        // SAFETY: só tipos registrados em `object_types` passam do `find`.
        if object_types::find(type_pointer).is_none() || unsafe { nt::ObjectType::at(type_pointer) }.type_info.supports_object_callbacks() == 0 {
            status = 0xC000_000D;
            break;
        }
        let pre = operation.pre_operation.get();
        let post = operation.post_operation.get();
        if pre == 0 && post == 0 {
            status = 0xC000_000D;
            break;
        }
        if (pre != 0 && !belongs_to_verified_image(pre)) || (post != 0 && !belongs_to_verified_image(post)) {
            status = 0xC000_0022;
            break;
        }
        let duplicate = state.by_type.get(&type_pointer).is_some_and(|entries| {
            entries.iter().any(|entry| state.registrations.get(&entry.record).is_some_and(|other| compare_altitude(&other.altitude, &altitude) == Ordering::Equal))
        });
        if duplicate {
            status = 0xC01C_0011;
            break;
        }
        let node = pointer + RegistrationBlock::SIZE + index * CallbackEntryItem::SIZE;
        let item = entry_item(node);
        item.operations.set(mask);
        item.registration.set(pointer);
        item.object_type.set(type_pointer);
        item.pre_operation.set(pre);
        item.post_operation.set(post);
        item.rundown.count.set(0);
        created.push(node);
        state.registrations.get_mut(&pointer).unwrap().entries.push(node);
        let entry = Entry { pointer: node, record: pointer, mask, pre, post, enabled: false };
        let altitudes: BTreeMap<u64, String> = state.registrations.iter().map(|(&key, record)| (key, record.altitude.clone())).collect();
        let entries = state.by_type.entry(type_pointer).or_default();
        entries.push(entry);
        entries.sort_by(|left, right| compare_altitude(&altitudes[&right.record], &altitudes[&left.record]));
        synchronize_type_list(&state, type_pointer);
        block.operation_registration_count.set(created.len() as u16);
    }
    if status != 0 {
        // Desfaz as entradas parciais.
        state.registrations.remove(&pointer);
        let touched: Vec<u64> = state.by_type.iter_mut().filter_map(|(&type_pointer, entries)| {
            let before = entries.len();
            entries.retain(|entry| entry.record != pointer);
            (entries.len() != before).then_some(type_pointer)
        }).collect();
        for type_pointer in touched {
            synchronize_type_list(&state, type_pointer);
        }
        drop(state);
        kernel_pool::free(pointer, None)?;
        return Ok(status);
    }
    // A habilitação ocorre só depois de todas as validações.
    for entries in state.by_type.values_mut() {
        for entry in entries.iter_mut().filter(|entry| entry.record == pointer) {
            entry.enabled = true;
            entry_item(entry.pointer).active.set(1);
        }
    }
    drop(state);
    // SAFETY: PVOID* RegistrationHandle de um chamador de kernel.
    unsafe { Field::<u64>::at(output_handle) }.set(pointer);
    Ok(0)
}

/// Remoção por etapas: cada poll aguarda o rundown da entrada atual.
pub struct RemoveRequest {
    record: u64,
    index: usize,
    wait: Option<rundown::RundownRequest>,
    done: bool,
}

pub fn begin_remove(handle: u64) -> Result<RemoveRequest, KernelError> {
    require_callback_level()?;
    let thread = process::get_current_thread();
    let mut state = STATE.lock();
    let executing = state.executing.get(&thread).is_some_and(|running| running.contains_key(&handle));
    let Some(record) = state.registrations.get_mut(&handle).filter(|record| !record.removing) else {
        return Err(KernelError::new("invalid OB callback registration removal"));
    };
    if executing {
        return Err(KernelError::new("OB callback cannot unregister its executing registration"));
    }
    record.removing = true;
    Ok(RemoveRequest { record: handle, index: 0, wait: None, done: false })
}

impl RemoveRequest {
    pub fn poll(&mut self) -> Result<Option<u32>, KernelError> {
        if self.done {
            return Ok(Some(0));
        }
        loop {
            let Some(entry) = STATE.lock().registrations.get(&self.record).and_then(|record| record.entries.get(self.index).copied()) else { break };
            if self.wait.is_none() {
                self.wait = Some(rundown::begin(rundown_of(entry), false)?);
            }
            if !self.wait.as_mut().unwrap().poll() {
                return Ok(None);
            }
            let mut state = STATE.lock();
            let type_pointer = state.by_type.iter().find(|(_, entries)| entries.iter().any(|candidate| candidate.pointer == entry)).map(|(&type_pointer, _)| type_pointer);
            if let Some(type_pointer) = type_pointer {
                state.by_type.get_mut(&type_pointer).unwrap().retain(|candidate| candidate.pointer != entry);
                synchronize_type_list(&state, type_pointer);
            }
            self.wait = None;
            self.index += 1;
        }
        STATE.lock().registrations.remove(&self.record);
        kernel_pool::free(self.record, None)?;
        self.done = true;
        Ok(Some(0))
    }
}

/// ObUnRegisterCallbacks: avança o dispatcher para que callbacks suspensos
/// terminem e soltem suas referências.
pub fn unregister(handle: u64) -> Result<u32, KernelError> {
    let mut request = begin_remove(handle)?;
    loop {
        if let Some(status) = request.poll()? {
            return Ok(status);
        }
        dispatcher::pump_kernel();
    }
}

/// Alguma entrada habilitada acompanha a operação para o tipo.
pub fn has(object_type: &ObjectType, operation: u32) -> bool {
    STATE.lock().by_type.get(&object_type.pointer).is_some_and(|entries| entries.iter().any(|entry| entry.enabled && entry.mask & operation != 0))
}

pub fn registration_count() -> usize {
    STATE.lock().registrations.len()
}

pub struct PerformOptions {
    pub operation: u32,
    pub enforce: bool,
    pub kernel_handle: bool,
    pub source_process: u64,
    pub target_process: u64,
}

/// Resultado da ação protegida: status, direitos concedidos e valor.
pub struct Outcome {
    pub status: u32,
    pub granted: Option<u32>,
    pub value: u32,
    pub error: Option<KernelError>,
}

fn invoke(thread: u64, entry: &Entry, address: u64, context: u64, information: u64) {
    {
        let mut state = STATE.lock();
        *state.executing.entry(thread).or_default().entry(entry.record).or_insert(0) += 1;
    }
    native_call::call(address, &[context, information]);
    let mut state = STATE.lock();
    if let Some(running) = state.executing.get_mut(&thread) {
        if let Some(count) = running.get_mut(&entry.record) {
            *count -= 1;
            if *count == 0 {
                running.remove(&entry.record);
            }
        }
        if running.is_empty() {
            state.executing.remove(&thread);
        }
    }
}

/// Pré-callbacks, a ação e pós-callbacks (em ordem inversa). Só a redução de
/// direitos feita pelos callbacks é aceita.
pub fn perform(item: &Described, desired_access: u32, options: &PerformOptions, action: &mut dyn FnMut(u32) -> Outcome) -> Result<Outcome, KernelError> {
    let operation = if options.operation != 0 { options.operation } else { 1 };
    if !has(&item.object_type, operation) {
        return Ok(action(desired_access));
    }
    require_callback_level()?;
    let thread = process::get_current_thread();
    let memory = guest::alloc_bytes(OperationBlock::SIZE);
    if memory == 0 {
        return Ok(Outcome { status: 0xC000_009A, granted: None, value: 0, error: None });
    }
    // SAFETY: alocação nova do tamanho do bloco, liberada no fim da função.
    let block = unsafe { OperationBlock::at(memory) };
    let post_information = &block.information;
    // SAFETY: a PRE é o prefixo da POST na mesma memória.
    let information = unsafe { ObPreOperationInformation::at(post_information.address()) };
    let parameters = &block.parameters;
    // SAFETY: OB_POST_OPERATION_PARAMETERS sobrepõe os mesmos bytes.
    let post_parameters = unsafe { ObPostOperationParameters::at(parameters.address()) };
    let original = desired_access;
    let entries: Vec<Entry> = STATE.lock().by_type.get(&item.object_type.pointer).cloned().unwrap_or_default();
    item.reference();
    let result = critical_region::with_critical(|| {
        information.operation.set(operation);
        information.flags.set(options.kernel_handle as u32);
        information.object.set(item.pointer);
        information.object_type.set(item.object_type.pointer);
        information.parameters.set(parameters.address());
        parameters.create_handle_information.desired_access.set(original);
        parameters.create_handle_information.original_desired_access.set(original);
        if operation == 2 {
            let duplicate = &parameters.duplicate_handle_information;
            duplicate.source_process.set(if options.source_process != 0 { options.source_process } else { process::get_current_process() });
            duplicate.target_process.set(if options.target_process != 0 { options.target_process } else { process::get_current_process() });
        }
        let mut post_callbacks: Vec<(Entry, u64)> = Vec::new();
        for entry in &entries {
            let context = STATE.lock().registrations.get(&entry.record).map_or(0, |record| record.context);
            if !entry.enabled || entry.mask & operation == 0 || !rundown::acquire(rundown_of(entry.pointer))? {
                continue;
            }
            information.call_context.set(0);
            if entry.pre != 0 {
                invoke(thread, entry, entry.pre, context, information.address());
            }
            if entry.post != 0 {
                post_callbacks.push((entry.clone(), information.call_context.get()));
            } else {
                rundown::release(rundown_of(entry.pointer))?;
            }
        }
        let filtered = original & parameters.create_handle_information.desired_access.get();
        let outcome = action(if options.enforce { filtered } else { original });
        post_information.return_status.set(outcome.status as i32);
        post_information.parameters.set(post_parameters.address());
        post_parameters.create_handle_information.granted_access.set(outcome.granted.unwrap_or(0));
        for (entry, saved_context) in post_callbacks.iter().rev() {
            let context = STATE.lock().registrations.get(&entry.record).map_or(0, |record| record.context);
            post_information.call_context.set(*saved_context);
            invoke(thread, entry, entry.post, context, post_information.address());
        }
        for (entry, _) in &post_callbacks {
            rundown::release(rundown_of(entry.pointer))?;
        }
        Ok(outcome)
    });
    item.dereference();
    guest::free_bytes(memory);
    result
}

/// Encaminha aberturas e duplicações de processos ou threads aos callbacks
/// registrados; os demais tipos executam a ação diretamente.
pub fn route(kind: &str, data: &ObjectData, operation: u32, from_user_mode: bool, action: &mut dyn FnMut(u32) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let current = process::get_current_process();
    route_between(kind, data, operation, from_user_mode, current, current, action)
}

/// [`route`] com os processos de origem e destino de uma duplicação entre
/// processos (os do OB_PRE_DUPLICATE_HANDLE_INFORMATION); numa abertura os
/// dois são o processo que recebe o handle.
pub fn route_between(kind: &str, data: &ObjectData, operation: u32, from_user_mode: bool, source_process: u64, target_process: u64, action: &mut dyn FnMut(u32) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let access = data.access.unwrap_or(0);
    if registration_count() == 0 || (kind != "Process" && kind != "Thread") {
        return action(access);
    }
    let object_type = if kind == "Process" { object_types::process_type() } else { object_types::thread_type() };
    if !has(&object_type, operation) {
        return action(access);
    }
    let mut pointer = data.native_pointer;
    if pointer == 0 && kind == "Process" {
        if let Some(pid) = data.process_id {
            pointer = process::list_active_processes().into_iter().find(|entry| entry.pid == pid).map_or(0, |entry| entry.address);
        }
    }
    let Some(item) = open_pointer::describe(pointer) else {
        return Err(KernelError::new(alloc::format!("ObOpenObjectByPointer: invalid native object {pointer:#x}")));
    };
    let options = PerformOptions {
        operation,
        enforce: from_user_mode,
        kernel_handle: data.open_attributes.unwrap_or(0) & 0x200 != 0,
        source_process,
        target_process,
    };
    let desired = data.access.unwrap_or(object_type.valid_access);
    let outcome = perform(&item, desired, &options, &mut |granted| match action(granted) {
        Ok(value) => Outcome { status: 0, granted: Some(granted), value, error: None },
        Err(error) if error.status != 0 => Outcome { status: error.status, granted: None, value: 0, error: Some(error) },
        Err(error) => Outcome { status: 0xC000_0001, granted: None, value: 0, error: Some(error) },
    })?;
    if outcome.status != 0 {
        return Err(outcome.error.unwrap_or_else(|| KernelError::with_status("OB handle operation failed", outcome.status)));
    }
    Ok(outcome.value)
}
