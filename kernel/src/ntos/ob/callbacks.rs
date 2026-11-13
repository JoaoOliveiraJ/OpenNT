//! ObRegisterCallbacks — `system32/ntos/ob/callbacks.js`.
//!
//! Registra callbacks de objetos e mantém as listas nativas (OBJECT_TYPE +
//! 0xC8) ordenadas por altitude. A confiança vem do registro da imagem no
//! carregador (LoaderFlags 0x20); os flags do cabeçalho PE não bastam.

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
use crate::ntos::mm::guest_memory as guest;

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

/// Reescreve os links da lista nativa do OBJECT_TYPE (sentinela em +0xC8).
fn synchronize_type_list(state: &State, type_pointer: u64) {
    let empty = Vec::new();
    let entries = state.by_type.get(&type_pointer).unwrap_or(&empty);
    let head = type_pointer + 0xC8;
    guest::write64(head, entries.first().map_or(head, |entry| entry.pointer));
    guest::write64(head + 8, entries.last().map_or(head, |entry| entry.pointer));
    for (index, entry) in entries.iter().enumerate() {
        guest::write64(entry.pointer, entries.get(index + 1).map_or(head, |next| next.pointer));
        guest::write64(entry.pointer + 8, if index > 0 { entries[index - 1].pointer } else { head });
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
    let version = guest::read16(registration);
    let count = guest::read16(registration + 2) as u64;
    if version & 0xFF00 != 0x100 || count == 0 {
        return Ok(0xC000_000D);
    }
    let length = guest::read16(registration + 8) as u64;
    let buffer = guest::read64(registration + 16);
    // Cabeçalho, entradas de 64 bytes e texto da altitude numa alocação paginável.
    let pointer = kernel_pool::allocate(32 + count * 64 + length, kernel_pool::AllocateOptions { paged: true, tag: 0x6C46_624F, zero: true, ..Default::default() })?;
    if pointer == 0 {
        return Ok(0xC000_009A);
    }
    let altitude_pointer = pointer + 32 + count * 64;
    let context = guest::read64(registration + 24);
    guest::write16(pointer, 0x100);
    guest::write64(pointer + 8, context);
    guest::write16(pointer + 16, length as u16);
    guest::write16(pointer + 18, length as u16);
    guest::write64(pointer + 24, altitude_pointer);
    for offset in 0..length {
        guest::write8(altitude_pointer + offset, guest::read8(buffer + offset));
    }
    let units: Vec<u16> = (0..length / 2).map(|index| guest::read16(altitude_pointer + index * 2)).collect();
    let altitude = String::from_utf16_lossy(&units);
    let operations = guest::read64(registration + 32);
    let mut created: Vec<u64> = Vec::new();
    let mut status = 0;
    let mut state = STATE.lock();
    state.registrations.insert(pointer, Registration { context, entries: Vec::new(), altitude: altitude.clone(), removing: false });
    for index in 0..count {
        let operation = operations + index * 32;
        let mask = guest::read32(operation + 8);
        if mask == 0 {
            status = 0xC000_000D;
            break;
        }
        let type_pointer = guest::read64(guest::read64(operation));
        if object_types::find(type_pointer).is_none() || guest::read16(type_pointer + 0x42) & 0x40 == 0 {
            status = 0xC000_000D;
            break;
        }
        let pre = guest::read64(operation + 16);
        let post = guest::read64(operation + 24);
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
        let node = pointer + 32 + index * 64;
        guest::write32(node + 16, mask);
        guest::write64(node + 24, pointer);
        guest::write64(node + 32, type_pointer);
        guest::write64(node + 40, pre);
        guest::write64(node + 48, post);
        guest::write64(node + 56, 0);
        created.push(node);
        state.registrations.get_mut(&pointer).unwrap().entries.push(node);
        let entry = Entry { pointer: node, record: pointer, mask, pre, post, enabled: false };
        let altitudes: BTreeMap<u64, String> = state.registrations.iter().map(|(&key, record)| (key, record.altitude.clone())).collect();
        let entries = state.by_type.entry(type_pointer).or_default();
        entries.push(entry);
        entries.sort_by(|left, right| compare_altitude(&altitudes[&right.record], &altitudes[&left.record]));
        synchronize_type_list(&state, type_pointer);
        guest::write16(pointer + 2, created.len() as u16);
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
            guest::write32(entry.pointer + 20, 1);
        }
    }
    drop(state);
    guest::write64(output_handle, pointer);
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
                self.wait = Some(rundown::begin(entry + 56, false)?);
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
    let memory = guest::alloc_bytes(96);
    if memory == 0 {
        return Ok(Outcome { status: 0xC000_009A, granted: None, value: 0, error: None });
    }
    let information = memory;
    let parameters = information + 48;
    let original = desired_access;
    let entries: Vec<Entry> = STATE.lock().by_type.get(&item.object_type.pointer).cloned().unwrap_or_default();
    item.reference();
    let result = critical_region::with_critical(|| {
        guest::write32(information, operation);
        guest::write32(information + 4, options.kernel_handle as u32);
        guest::write64(information + 8, item.pointer);
        guest::write64(information + 16, item.object_type.pointer);
        guest::write64(information + 32, parameters);
        guest::write32(parameters, original);
        guest::write32(parameters + 4, original);
        if operation == 2 {
            guest::write64(parameters + 8, if options.source_process != 0 { options.source_process } else { process::get_current_process() });
            guest::write64(parameters + 16, if options.target_process != 0 { options.target_process } else { process::get_current_process() });
        }
        let mut post_callbacks: Vec<(Entry, u64)> = Vec::new();
        for entry in &entries {
            let context = STATE.lock().registrations.get(&entry.record).map_or(0, |record| record.context);
            if !entry.enabled || entry.mask & operation == 0 || !rundown::acquire(entry.pointer + 56)? {
                continue;
            }
            guest::write64(information + 24, 0);
            if entry.pre != 0 {
                invoke(thread, entry, entry.pre, context, information);
            }
            if entry.post != 0 {
                post_callbacks.push((entry.clone(), guest::read64(information + 24)));
            } else {
                rundown::release(entry.pointer + 56)?;
            }
        }
        let filtered = original & guest::read32(parameters);
        let outcome = action(if options.enforce { filtered } else { original });
        guest::write32(information + 32, outcome.status);
        guest::write64(information + 40, parameters);
        guest::write32(parameters, outcome.granted.unwrap_or(0));
        for (entry, saved_context) in post_callbacks.iter().rev() {
            let context = STATE.lock().registrations.get(&entry.record).map_or(0, |record| record.context);
            guest::write64(information + 24, *saved_context);
            invoke(thread, entry, entry.post, context, information);
        }
        for (entry, _) in &post_callbacks {
            rundown::release(entry.pointer + 56)?;
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
        source_process: process::get_current_process(),
        target_process: process::get_current_process(),
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
