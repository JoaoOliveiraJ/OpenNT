//! Registros e habilitações ETW.
//!
//! Uma sessão só existe com um consumidor real; registrar um provedor não
//! habilita eventos sozinho. Rotinas de habilitação nativas e consumidores
//! rodam sem o lock retido (um callback pode remover o próprio registro).
//! Os traits de EtwSetInformation ficam guardados por registro.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::event_enabled;
use crate::hal::amd64::native_call;
use crate::ntos::ke::irql;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

const ALL_KEYWORDS: u64 = u64::MAX;
const REGISTRATION_SIZE: u64 = 0x70;
const GUID_ENTRY_SIZE: u64 = 0x1A8;
const GUID_TAG: u32 = 0x4777_7445;
const REGISTRATION_TAG: u32 = 0x5277_7445;
/// GUID reservado comparado literalmente pelo EtwpRegisterProvider medido.
const RESERVED_GUID: [u8; 16] = [37, 150, 132, 84, 120, 84, 148, 73, 165, 186, 62, 59, 3, 40, 195, 13];

/// TRACE_ENABLE_INFO agregado ou de uma sessão.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Information {
    pub enabled: u32,
    pub level: u8,
    pub properties: u32,
    pub any_keyword: u64,
    pub all_keyword: u64,
}

fn empty_information() -> Information {
    Information { enabled: 0, level: 0, properties: 0, any_keyword: 0, all_keyword: ALL_KEYWORDS }
}

/// EtwpComputeRegEntryEnableInfo: máximo, OR, AND e OR.
pub fn aggregate(list: &[Information]) -> Information {
    let mut result = empty_information();
    for information in list {
        result.enabled = 1;
        result.level = result.level.max(information.level);
        result.properties |= information.properties;
        result.any_keyword |= information.any_keyword;
        result.all_keyword &= information.all_keyword;
    }
    result
}

#[derive(Clone, Copy)]
struct Subscription {
    session: u16,
    information: Information,
}

struct GuidEntry {
    pointer: u64,
    identifier: [u8; 16],
    references: u64,
    registrations: Vec<u64>,
    slots: [Option<Subscription>; 8],
    information: Information,
}

struct Registration {
    pointer: u64,
    entry: String,
    callback: u64,
    context: u64,
    active: u32,
    closing: bool,
}

/// Evento entregue ao consumidor (cópias dos buffers do chamador).
#[derive(Clone, Debug)]
pub struct Event {
    pub provider: [u8; 16],
    pub descriptor: [u8; 16],
    pub activity: [u8; 16],
    pub related_activity: [u8; 16],
    pub data: Vec<Vec<u8>>,
}

pub type Consumer = Arc<dyn Fn(&Event) + Send + Sync>;

struct Session {
    consumer: Consumer,
    silo: u64,
    source_identifier: [u8; 16],
    subscriptions: BTreeMap<String, usize>,
    delivered: u64,
}

#[derive(Default)]
struct Etw {
    entries: BTreeMap<String, GuidEntry>,
    registrations: BTreeMap<u64, Registration>,
    sessions: BTreeMap<u16, Session>,
    next_session: u32,
}

static ETW: SpinLock<Option<Etw>> = SpinLock::new(None);

fn with<T>(body: impl FnOnce(&mut Etw) -> T) -> T {
    let mut etw = ETW.lock();
    body(etw.get_or_insert_with(|| Etw { next_session: 1, ..Default::default() }))
}

fn require_passive_level() -> Result<(), KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("ETW registration and session control require PASSIVE_LEVEL"));
    }
    Ok(())
}

fn read_guid(pointer: u64) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&guest::read_bytes(pointer, 16));
    bytes
}

fn identifier_key(identifier: &[u8; 16], silo: u64) -> String {
    let mut key = alloc::format!("{silo:x}:");
    for byte in identifier {
        key.push_str(&alloc::format!("{byte:02x}"));
    }
    key
}

/// Retira IsEnabled enquanto os outros campos são publicados.
fn publish_information(address: u64, information: &Information, session: u16) {
    guest::write32(address, 0);
    guest::write8(address + 4, information.level);
    guest::write16(address + 6, session);
    guest::write32(address + 8, information.properties);
    guest::write64(address + 16, information.any_keyword);
    guest::write64(address + 24, information.all_keyword);
    guest::write32(address, information.enabled);
}

fn synchronize(etw: &mut Etw, key: &str) {
    let Some(entry) = etw.entries.get_mut(key) else { return };
    let mut enabled = Vec::new();
    let mut mask = 0u8;
    for index in 0..8 {
        let subscription = entry.slots[index];
        let information = subscription.map_or_else(empty_information, |subscription| subscription.information);
        publish_information(entry.pointer + 0x80 + index as u64 * 32, &information, subscription.map_or(0, |subscription| subscription.session));
        if subscription.is_some() {
            mask |= 1 << index;
            enabled.push(information);
        }
    }
    entry.information = aggregate(&enabled);
    publish_information(entry.pointer + 0x60, &entry.information, 0);
    for &registration in &entry.registrations {
        guest::write8(registration + 0x64, mask);
    }
    let head = entry.pointer + 0x38;
    let mut links = alloc::vec![head];
    links.extend(entry.registrations.iter().copied());
    let count = links.len();
    for (index, &pointer) in links.iter().enumerate() {
        guest::write64(pointer, links[(index + 1) % count]);
        guest::write64(pointer + 8, links[(index + count - 1) % count]);
    }
    guest::write64(entry.pointer + 0x20, entry.references);
}

fn discard_unused_entry(etw: &mut Etw, key: &str) {
    if etw.entries.get(key).is_some_and(|entry| entry.references == 0) {
        if let Some(entry) = etw.entries.remove(key) {
            let _ = kernel_pool::free(entry.pointer, None);
        }
    }
}

fn acquire_entry(etw: &mut Etw, identifier: [u8; 16], silo: u64) -> Option<String> {
    let key = identifier_key(&identifier, silo);
    if etw.entries.contains_key(&key) {
        return Some(key);
    }
    let pointer = kernel_pool::allocate(GUID_ENTRY_SIZE, AllocateOptions { tag: GUID_TAG, zero: true, ..Default::default() }).ok()?;
    for offset in [0u64, 0x10, 0x38] {
        guest::write64(pointer + offset, pointer + offset);
        guest::write64(pointer + offset + 8, pointer + offset);
    }
    guest::write_bytes(pointer + 0x28, &identifier);
    etw.entries.insert(key.clone(), GuidEntry { pointer, identifier, references: 0, registrations: Vec::new(), slots: [None; 8], information: empty_information() });
    Some(key)
}

fn finalize_registration(etw: &mut Etw, pointer: u64) {
    let finished = etw.registrations.get(&pointer).is_some_and(|record| record.closing && record.active == 0);
    if !finished {
        return;
    }
    let Some(record) = etw.registrations.remove(&pointer) else { return };
    let _ = kernel_pool::free(record.pointer, None);
    if let Some(entry) = etw.entries.get_mut(&record.entry) {
        entry.references -= 1;
        guest::write64(entry.pointer + 0x20, entry.references);
    }
    discard_unused_entry(etw, &record.entry);
}

/// Copia os argumentos antes da chamada nativa; a referência retém o
/// registro e o GUID mesmo se o callback remover o próprio registro.
fn notify_registration(pointer: u64, source: Option<[u8; 16]>, control: Option<u64>) -> Result<(), KernelError> {
    let call = with(|etw| {
        let record = etw.registrations.get_mut(&pointer)?;
        if record.callback == 0 || record.closing {
            return None;
        }
        record.active += 1;
        let information = etw.entries.get(&record.entry).map_or_else(empty_information, |entry| entry.information);
        Some((record.callback, record.context, information))
    });
    let Some((callback, context, information)) = call else { return Ok(()) };
    let frame = kernel_pool::allocate(80, AllocateOptions { tag: REGISTRATION_TAG, zero: true, ..Default::default() });
    let result = match frame {
        Ok(frame) => {
            guest::write_bytes(frame, &source.unwrap_or([0; 16]));
            // ControlCode: 0/1 pelo estado agregado, ou 2 (CAPTURE_STATE).
            let control = control.unwrap_or(information.enabled as u64);
            native_call::call(callback, &[frame, control, information.level as u64, information.any_keyword, information.all_keyword, 0, context]);
            let _ = kernel_pool::free(frame, None);
            Ok(())
        }
        Err(_) => Err(KernelError::new("ETW enable callback allocation failed")),
    };
    with(|etw| {
        if let Some(record) = etw.registrations.get_mut(&pointer) {
            record.active -= 1;
        }
        finalize_registration(etw, pointer);
    });
    result
}

fn notify_entry(key: &str, source: [u8; 16]) -> Result<(), KernelError> {
    notify_entry_with(key, source, None)
}

fn notify_entry_with(key: &str, source: [u8; 16], control: Option<u64>) -> Result<(), KernelError> {
    let registrations = with(|etw| etw.entries.get(key).map(|entry| entry.registrations.clone()).unwrap_or_default());
    for registration in registrations {
        notify_registration(registration, Some(source), control)?;
    }
    Ok(())
}

/// EVENT_CONTROL_CODE_CAPTURE_STATE: os registros de um provedor habilitado
/// para a sessão recebem o ControlCode 2 e registram o próprio estado.
pub fn capture_state(session: u16, identifier_pointer: u64) -> Result<(), KernelError> {
    require_passive_level()?;
    let found = with(|etw| {
        let session = etw.sessions.get(&session)?;
        let key = identifier_key(&read_guid(identifier_pointer), session.silo);
        session.subscriptions.contains_key(&key).then_some((key, session.source_identifier))
    });
    match found {
        Some((key, source)) => notify_entry_with(&key, source, Some(2)),
        None => Ok(()),
    }
}

/// EtwRegister: contexto sem callback e o GUID reservado são recusados.
pub fn register(identifier_pointer: u64, callback: u64, context: u64, output: u64, classic: bool) -> Result<u32, KernelError> {
    require_passive_level()?;
    guest::write64(output, 0);
    let identifier = read_guid(identifier_pointer);
    if (callback == 0 && context != 0) || (classic && callback == 0) || identifier == RESERVED_GUID {
        return Ok(0xC000_000D);
    }
    let silo = if classic { 0 } else { silo_query::current_server_silo() };
    let created = with(|etw| {
        let key = acquire_entry(etw, identifier, silo)?;
        let Ok(pointer) = kernel_pool::allocate(REGISTRATION_SIZE, AllocateOptions { tag: REGISTRATION_TAG, zero: true, ..Default::default() }) else {
            discard_unused_entry(etw, &key);
            return None;
        };
        guest::write64(pointer + 0x10, pointer + 0x10);
        guest::write64(pointer + 0x18, pointer + 0x10);
        let entry = etw.entries.get_mut(&key).expect("entrada adquirida");
        guest::write64(pointer + 0x20, entry.pointer);
        guest::write64(pointer + 0x50, context);
        guest::write64(pointer + 0x58, callback);
        guest::write16(pointer + 0x62, if classic { 0x89 } else { 0x81 });
        entry.registrations.push(pointer);
        entry.references += 1;
        let enabled = entry.information.enabled != 0;
        etw.registrations.insert(pointer, Registration { pointer, entry: key.clone(), callback, context, active: 0, closing: false });
        synchronize(etw, &key);
        let enabled = enabled || etw.entries.get(&key).is_some_and(|entry| entry.information.enabled != 0);
        Some((pointer, enabled))
    });
    let Some((pointer, enabled)) = created else { return Ok(0xC000_009A) };
    guest::write64(output, pointer);
    if enabled {
        if let Err(error) = notify_registration(pointer, None, None) {
            let _ = unregister(pointer);
            guest::write64(output, 0);
            return Err(error);
        }
    }
    Ok(0)
}

/// EtwUnregister.
pub fn unregister(handle: u64) -> Result<u32, KernelError> {
    require_passive_level()?;
    Ok(with(|etw| {
        let Some(record) = etw.registrations.get_mut(&handle) else { return 0xC000_0008 };
        if record.closing {
            return 0xC000_0008;
        }
        record.closing = true;
        let key = record.entry.clone();
        if let Some(entry) = etw.entries.get_mut(&key) {
            entry.registrations.retain(|&pointer| pointer != handle);
        }
        guest::write16(handle + 0x62, guest::read16(handle + 0x62) | 0x40);
        synchronize(etw, &key);
        finalize_registration(etw, handle);
        0
    }))
}

/// Sessão interna de controle com consumidor; devolve o identificador.
pub fn open_session(consumer: Consumer, silo: Option<u64>, source_identifier: Option<[u8; 16]>) -> Result<u16, KernelError> {
    require_passive_level()?;
    with(|etw| {
        if etw.next_session > 0xFFFF {
            return Err(KernelError::new("ETW session identifiers exhausted"));
        }
        let identifier = etw.next_session as u16;
        etw.next_session += 1;
        etw.sessions.insert(identifier, Session { consumer, silo: silo.unwrap_or_else(silo_query::current_server_silo), source_identifier: source_identifier.unwrap_or([0; 16]), subscriptions: BTreeMap::new(), delivered: 0 });
        Ok(identifier)
    })
}

/// Opções de habilitação (nível 0 vira 255; keyword zero incluída por padrão).
#[derive(Clone, Copy)]
pub struct EnableOptions {
    pub level: u8,
    pub any_keyword: u64,
    pub all_keyword: u64,
    pub include_keyword_zero: bool,
}

impl Default for EnableOptions {
    fn default() -> Self {
        Self { level: 255, any_keyword: ALL_KEYWORDS, all_keyword: 0, include_keyword_zero: true }
    }
}

pub fn enable(session: u16, identifier_pointer: u64, options: EnableOptions) -> Result<(), KernelError> {
    require_passive_level()?;
    let identifier = read_guid(identifier_pointer);
    let (key, source) = with(|etw| {
        let silo = etw.sessions.get(&session).map(|found| found.silo).ok_or_else(|| KernelError::new("closed ETW session"))?;
        let key = acquire_entry(etw, identifier, silo).ok_or_else(|| KernelError::new("ETW GUID entry allocation failed"))?;
        let existing = etw.sessions.get(&session).and_then(|found| found.subscriptions.get(&key).copied());
        let slot = match existing {
            Some(slot) => slot,
            None => {
                let entry = etw.entries.get_mut(&key).expect("entrada adquirida");
                let Some(slot) = entry.slots.iter().position(Option::is_none) else {
                    return Err(KernelError::new("ETW provider already has eight sessions"));
                };
                entry.slots[slot] = Some(Subscription { session, information: empty_information() });
                entry.references += 1;
                etw.sessions.get_mut(&session).expect("sessao viva").subscriptions.insert(key.clone(), slot);
                slot
            }
        };
        let information = Information {
            enabled: 1,
            level: if options.level == 0 { 255 } else { options.level },
            properties: if options.include_keyword_zero { 0x40 } else { 0 },
            any_keyword: if options.any_keyword == 0 { ALL_KEYWORDS } else { options.any_keyword },
            all_keyword: options.all_keyword,
        };
        etw.entries.get_mut(&key).expect("entrada adquirida").slots[slot] = Some(Subscription { session, information });
        synchronize(etw, &key);
        Ok((key, etw.sessions[&session].source_identifier))
    })?;
    notify_entry(&key, source)
}

fn disable_subscription(session: u16, key: &str) -> Result<(), KernelError> {
    let source = with(|etw| {
        let source = etw.sessions.get_mut(&session).and_then(|found| {
            let slot = found.subscriptions.remove(key)?;
            Some((slot, found.source_identifier))
        });
        if let Some((slot, _)) = source {
            if let Some(entry) = etw.entries.get_mut(key) {
                entry.slots[slot] = None;
            }
            synchronize(etw, key);
        }
        source.map(|(_, source)| source)
    });
    let Some(source) = source else { return Ok(()) };
    let notified = notify_entry(key, source);
    with(|etw| {
        if let Some(entry) = etw.entries.get_mut(key) {
            entry.references -= 1;
            guest::write64(entry.pointer + 0x20, entry.references);
        }
        discard_unused_entry(etw, key);
    });
    notified
}

pub fn disable(session: u16, identifier_pointer: u64) -> Result<(), KernelError> {
    require_passive_level()?;
    let silo = with(|etw| etw.sessions.get(&session).map(|found| found.silo)).ok_or_else(|| KernelError::new("closed ETW session"))?;
    let key = identifier_key(&read_guid(identifier_pointer), silo);
    disable_subscription(session, &key)
}

pub fn close_session(session: u16) -> Result<(), KernelError> {
    require_passive_level()?;
    let keys: Vec<String> = with(|etw| etw.sessions.get(&session).map(|found| found.subscriptions.keys().cloned().collect())).ok_or_else(|| KernelError::new("closed ETW session"))?;
    for key in keys {
        disable_subscription(session, &key)?;
    }
    with(|etw| etw.sessions.remove(&session));
    Ok(())
}

/// EtwWrite: um provedor sem sessões nem lê os buffers do chamador; cada
/// sessão casada recebe uma cópia do evento.
pub fn write(handle: u64, descriptor: u64, activity: u64, related: u64, count: u32, data: u64) -> Result<u32, KernelError> {
    let prepared = with(|etw| {
        let record = etw.registrations.get(&handle).filter(|record| !record.closing)?;
        let entry = etw.entries.get(&record.entry)?;
        Some((entry.information.enabled != 0, entry.pointer, entry.identifier, entry.slots))
    });
    let Some((enabled, entry_pointer, provider, slots)) = prepared else { return Ok(0xC000_0008) };
    if !enabled {
        return Ok(0);
    }
    let keyword = guest::read64(descriptor + 8);
    let level = guest::read8(descriptor + 4);
    let recipients: Vec<u16> = slots
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| slot.filter(|_| event_enabled::matches(entry_pointer + 0x80 + index as u64 * 32, level, keyword)).map(|subscription| subscription.session))
        .collect();
    if recipients.is_empty() {
        return Ok(0);
    }
    if count > 128 {
        return Ok(0xC000_000D);
    }
    let mut segments = Vec::new();
    let mut total = 80u64; // EVENT_HEADER antes dos dados de usuário
    for index in 0..count as u64 {
        let descriptor_address = data + index * 16;
        let pointer = guest::read64(descriptor_address);
        let size = guest::read32(descriptor_address + 8) as u64;
        total += size;
        if total > 0xFFFF {
            return Ok(0x8000_0005);
        }
        segments.push(guest::read_bytes(pointer, size as usize));
    }
    let event = Event {
        provider,
        descriptor: read_guid(descriptor),
        activity: if activity != 0 { read_guid(activity) } else { [0; 16] },
        related_activity: if related != 0 { read_guid(related) } else { [0; 16] },
        data: segments,
    };
    for session in recipients {
        let Some(consumer) = with(|etw| etw.sessions.get_mut(&session).map(|found| {
            found.delivered += 1;
            found.consumer.clone()
        })) else {
            continue;
        };
        consumer(&event);
    }
    Ok(0)
}

/// (registros, GUIDs, sessões).
pub fn statistics() -> (usize, usize, usize) {
    with(|etw| (etw.registrations.values().filter(|record| !record.closing).count(), etw.entries.len(), etw.sessions.len()))
}

/// O registro existe, mesmo em fechamento.
pub fn exists(handle: u64) -> bool {
    with(|etw| etw.registrations.contains_key(&handle))
}

pub fn is_registered(handle: u64) -> bool {
    with(|etw| etw.registrations.get(&handle).is_some_and(|record| !record.closing))
}

pub fn delivered(session: u16) -> Option<u64> {
    with(|etw| etw.sessions.get(&session).map(|found| found.delivered))
}

/// EventProviderSetTraits: tamanho dos traits por registro.
static TRAITS: SpinLock<BTreeMap<u64, u32>> = SpinLock::new(BTreeMap::new());

/// EtwSetInformation(RegHandle, InformationClass, Information): atualiza os
/// metadados de um registro conforme a classe (1 = traits). Devolve o
/// NTSTATUS (STATUS_INVALID_HANDLE sem o registro).
pub fn set_information(handle: u64, class: u32, information: u64) -> u32 {
    if !exists(handle) {
        return 0xC000_0008;
    }
    if class == 1 && information != 0 {
        TRAITS.lock().insert(handle, guest::read32(information));
    }
    0
}

/// EtwUnregister: os traits guardados saem antes do próprio registro.
pub fn unregister_with_traits(handle: u64) -> Result<u32, KernelError> {
    TRAITS.lock().remove(&handle);
    unregister(handle)
}
