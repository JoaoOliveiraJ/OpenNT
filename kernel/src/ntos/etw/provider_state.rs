//! Registros e habilitações ETW: o registro único de provedores.
//!
//! Cada GUID tem uma ETW_GUID_ENTRY nativa (por silo e por tipo: provedor de
//! trace ou GUID de notificação) com os oito TRACE_ENABLE_INFO das sessões
//! e o ProviderEnableInfo agregado; cada registro é um ETW_REG_ENTRY ligado
//! no RegListHead da entrada. Os registros de kernel (EtwRegister) vêm do
//! pool e têm rotina de habilitação nativa; os de modo usuário
//! (NtTraceControl EtwRegisterGuids) são o corpo de um objeto
//! EtwRegistration (`user_registration`) e recebem as mudanças de
//! habilitação como notificação na fila do processo.
//!
//! Uma sessão só existe com um consumidor real; registrar um provedor não
//! habilita eventos sozinho. Rotinas de habilitação nativas, notificações e
//! consumidores rodam sem o lock retido (um callback pode remover o próprio
//! registro).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::{activity, event_enabled};
use crate::hal::amd64::native_call;
use crate::ntos::ke::irql;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::silo::query as silo_query;
use crate::ntos::inc::types::{EtwGuidEntry, EtwRegEntry, EventDataDescriptor, Field, Guid, ListEntry, NtStruct, TraceEnableInfo};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SpinLock};

const ALL_KEYWORDS: u64 = u64::MAX;
const REGISTRATION_SIZE: u64 = core::mem::size_of::<EtwRegEntry>() as u64;
const GUID_ENTRY_SIZE: u64 = core::mem::size_of::<EtwGuidEntry>() as u64;

/// ETW_REG_ENTRY.Flags.
pub mod flags {
    /// DbgKernelRegistration.
    pub const KERNEL: u16 = 0x01;
    /// DbgUserRegistration.
    pub const USER: u16 = 0x02;
    /// DbgClassicRegistration.
    pub const CLASSIC: u16 = 0x08;
    /// DbgTrackedBinary: o EtwpTrackProviderBinary já rodou.
    pub const TRACKED_BINARY: u16 = 0x20;
    /// DbgClosed.
    pub const CLOSED: u16 = 0x40;
    /// DbgInserted.
    pub const INSERTED: u16 = 0x80;
    /// DbgWow64: registrado por um processo WoW64.
    pub const WOW64: u16 = 0x100;
    /// DbgUseDescriptorType (também ligado por traits aceitos).
    pub const USE_DESCRIPTOR_TYPE: u16 = 0x200;
}

/// EVENT_INFO_CLASS.
const EVENT_PROVIDER_SET_TRAITS: u32 = 2;
const EVENT_PROVIDER_USE_DESCRIPTOR_TYPE: u32 = 3;

pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// STATUS_FILE_CORRUPT_ERROR: traits mal formados.
pub const STATUS_FILE_CORRUPT_ERROR: u32 = 0xC000_0102;

/// EVENT_HEADER.Flags.
pub mod header_flags {
    pub const EXTENDED_INFO: u16 = 0x0001;
    pub const STRING_ONLY: u16 = 0x0004;
    pub const SIXTY_FOUR_BIT_HEADER: u16 = 0x0040;
}

fn guid_entry(pointer: u64) -> &'static EtwGuidEntry {
    // SAFETY: entrada alocada por `acquire_entry` (pool do kernel).
    unsafe { EtwGuidEntry::at(pointer) }
}

fn registration(pointer: u64) -> &'static EtwRegEntry {
    // SAFETY: registro alocado por `register` (o REGHANDLE) ou corpo de um
    // objeto EtwRegistration vivo.
    unsafe { EtwRegEntry::at(pointer) }
}
const GUID_TAG: u32 = 0x4777_7445;
const REGISTRATION_TAG: u32 = 0x5277_7445;
/// Tag dos traits ('EtwT').
const TRAITS_TAG: u32 = 0x5477_7445;
/// Cabeçalho dos traits guardados (nó da árvore e contagem) antes da cópia.
const TRAITS_HEADER: u64 = 0x1C;
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

impl Information {
    /// Os 0x20 bytes do TRACE_ENABLE_INFO (LoggerId 0, como o agregado do
    /// EtwpComputeRegEntryEnableInfo).
    pub fn bytes(&self) -> [u8; 0x20] {
        let mut bytes = [0u8; 0x20];
        bytes[0..4].copy_from_slice(&self.enabled.to_le_bytes());
        bytes[4] = self.level;
        bytes[8..12].copy_from_slice(&self.properties.to_le_bytes());
        bytes[0x10..0x18].copy_from_slice(&self.any_keyword.to_le_bytes());
        bytes[0x18..0x20].copy_from_slice(&self.all_keyword.to_le_bytes());
        bytes
    }
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

/// Dono de modo usuário de um registro.
#[derive(Clone, Copy, Debug)]
pub struct UserOwner {
    /// EPROCESS registrador (referenciado pelo registro).
    pub process: u64,
    /// Índice do registro na tabela da ntdll (ETWP_NOTIFICATION_HEADER.RegIndex).
    pub index: u16,
    /// ETW_NOTIFICATION_TYPE do registro.
    pub kind: u32,
}

struct Registration {
    pointer: u64,
    entry: String,
    callback: u64,
    context: u64,
    active: u32,
    closing: bool,
    user: Option<UserOwner>,
}

/// Evento entregue ao consumidor (cópias dos buffers do chamador).
#[derive(Clone, Debug)]
pub struct Event {
    pub provider: [u8; 16],
    pub descriptor: [u8; 16],
    pub activity: [u8; 16],
    pub related_activity: [u8; 16],
    /// O chamador passou RelatedActivityId (item estendido no registro).
    pub has_related: bool,
    /// EVENT_HEADER.Flags pedidos pelo chamador (STRING_ONLY...).
    pub flags: u16,
    pub event_property: u16,
    pub process_id: u32,
    pub thread_id: u32,
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
    bytes.copy_from_slice(&guest::read_bytes(pointer, Guid::SIZE as usize));
    bytes
}

/// Chave da entrada: o tipo de GUID (EtwTraceGuidType 0, EtwNotificationGuidType
/// 1), o silo e o GUID.
fn entry_key(identifier: &[u8; 16], silo: u64, notification: bool) -> String {
    let mut key = alloc::format!("{}:{silo:x}:", notification as u8);
    for byte in identifier {
        key.push_str(&alloc::format!("{byte:02x}"));
    }
    key
}

fn identifier_key(identifier: &[u8; 16], silo: u64) -> String {
    entry_key(identifier, silo, false)
}

/// Retira IsEnabled enquanto os outros campos são publicados.
fn publish_information(target: &TraceEnableInfo, information: &Information, session: u16) {
    target.is_enabled.set(0);
    target.level.set(information.level);
    target.logger_id.set(session);
    target.enable_property.set(information.properties);
    target.match_any_keyword.set(information.any_keyword);
    target.match_all_keyword.set(information.all_keyword);
    target.is_enabled.set(information.enabled);
}

fn synchronize(etw: &mut Etw, key: &str) {
    let Some(entry) = etw.entries.get_mut(key) else { return };
    let native = guid_entry(entry.pointer);
    let mut enabled = Vec::new();
    let mut mask = 0u8;
    for index in 0..8 {
        let subscription = entry.slots[index];
        let information = subscription.map_or_else(empty_information, |subscription| subscription.information);
        publish_information(&native.enable_info[index], &information, subscription.map_or(0, |subscription| subscription.session));
        if subscription.is_some() {
            mask |= 1 << index;
            enabled.push(information);
        }
    }
    entry.information = aggregate(&enabled);
    publish_information(&native.provider_enable_info, &entry.information, 0);
    for &pointer in &entry.registrations {
        registration(pointer).enable_mask.set(mask);
    }
    // Anel RegListHead + RegList de cada registro (ETW_REG_ENTRY.RegList em +0).
    let mut links = alloc::vec![native.reg_list_head.address()];
    links.extend(entry.registrations.iter().copied());
    let count = links.len();
    for (index, &pointer) in links.iter().enumerate() {
        // SAFETY: a cabeça da entrada ou o RegList de um registro vivo.
        let link = unsafe { ListEntry::at(pointer) };
        link.flink.set(links[(index + 1) % count]);
        link.blink.set(links[(index + count - 1) % count]);
    }
    native.ref_count.set(entry.references as i64);
}

fn discard_unused_entry(etw: &mut Etw, key: &str) {
    if etw.entries.get(key).is_some_and(|entry| entry.references == 0) {
        if let Some(entry) = etw.entries.remove(key) {
            let _ = kernel_pool::free(entry.pointer, None);
        }
    }
}

fn acquire_entry_of(etw: &mut Etw, identifier: [u8; 16], silo: u64, notification: bool) -> Option<String> {
    let key = entry_key(&identifier, silo, notification);
    if etw.entries.contains_key(&key) {
        return Some(key);
    }
    // O pool esgotado devolve NULL (Ok(0)), como o ExAllocatePool.
    let pointer = kernel_pool::allocate(GUID_ENTRY_SIZE, AllocateOptions { tag: GUID_TAG, zero: true, ..Default::default() }).ok().filter(|&pointer| pointer != 0)?;
    let native = guid_entry(pointer);
    for head in [&native.guid_list, &native.silo_guid_list, &native.reg_list_head] {
        head.flink.set(head.address());
        head.blink.set(head.address());
    }
    guest::write_bytes(native.guid.address(), &identifier);
    etw.entries.insert(key.clone(), GuidEntry { pointer, identifier, references: 0, registrations: Vec::new(), slots: [None; 8], information: empty_information() });
    Some(key)
}

fn acquire_entry(etw: &mut Etw, identifier: [u8; 16], silo: u64) -> Option<String> {
    acquire_entry_of(etw, identifier, silo, false)
}

fn release_traits(pointer: u64) {
    let traits = registration(pointer).traits.get();
    if traits != 0 {
        registration(pointer).traits.set(0);
        let _ = kernel_pool::free(traits, None);
    }
}

fn finalize_registration(etw: &mut Etw, pointer: u64) {
    let finished = etw.registrations.get(&pointer).is_some_and(|record| record.closing && record.active == 0);
    if !finished {
        return;
    }
    let Some(record) = etw.registrations.remove(&pointer) else { return };
    release_traits(record.pointer);
    // O corpo de um registro de modo usuário é do gerenciador de objetos.
    if record.user.is_none() {
        let _ = kernel_pool::free(record.pointer, None);
    }
    if let Some(entry) = etw.entries.get_mut(&record.entry) {
        entry.references -= 1;
        guid_entry(entry.pointer).ref_count.set(entry.references as i64);
    }
    discard_unused_entry(etw, &record.entry);
}

/// O que uma mudança de habilitação entrega a um registro de modo usuário.
#[derive(Clone, Copy, Debug)]
pub struct UserNotification {
    pub owner: UserOwner,
    pub registration: u64,
    pub provider: [u8; 16],
    pub source: [u8; 16],
    pub information: Information,
}

/// Copia os argumentos antes da chamada nativa; a referência retém o
/// registro e o GUID mesmo se o callback remover o próprio registro. Um
/// registro de modo usuário recebe a notificação na fila do processo.
fn notify_registration(pointer: u64, source: Option<[u8; 16]>, control: Option<u64>) -> Result<(), KernelError> {
    enum Delivery {
        Native(u64, u64, Information),
        User(UserNotification),
    }
    let call = with(|etw| {
        let record = etw.registrations.get_mut(&pointer)?;
        if record.closing {
            return None;
        }
        let (information, provider) = etw.entries.get(&record.entry).map_or_else(|| (empty_information(), [0; 16]), |entry| (entry.information, entry.identifier));
        if let Some(owner) = record.user {
            return Some(Delivery::User(UserNotification { owner, registration: pointer, provider, source: source.unwrap_or([0; 16]), information }));
        }
        if record.callback == 0 {
            return None;
        }
        record.active += 1;
        Some(Delivery::Native(record.callback, record.context, information))
    });
    let (callback, context, information) = match call {
        None => return Ok(()),
        Some(Delivery::User(notification)) => {
            // EVENT_CONTROL_CODE_CAPTURE_STATE não chega ao modo usuário por aqui.
            if control.is_none() {
                super::user_registration::queue_enable(&notification);
            }
            return Ok(());
        }
        Some(Delivery::Native(callback, context, information)) => (callback, context, information),
    };
    let frame = kernel_pool::allocate(80, AllocateOptions { tag: REGISTRATION_TAG, zero: true, ..Default::default() }).ok().filter(|&frame| frame != 0);
    let result = match frame {
        Some(frame) => {
            guest::write_bytes(frame, &source.unwrap_or([0; 16]));
            // ControlCode: 0/1 pelo estado agregado, ou 2 (CAPTURE_STATE).
            let control = control.unwrap_or(information.enabled as u64);
            native_call::call(callback, &[frame, control, information.level as u64, information.any_keyword, information.all_keyword, 0, context]);
            let _ = kernel_pool::free(frame, None);
            Ok(())
        }
        None => Err(KernelError::new("ETW enable callback allocation failed")),
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
    // SAFETY: PREGHANDLE de saída do driver.
    let handle_out = unsafe { Field::<u64>::at(output) };
    handle_out.set(0);
    let identifier = read_guid(identifier_pointer);
    if (callback == 0 && context != 0) || (classic && callback == 0) || identifier == RESERVED_GUID {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let silo = if classic { 0 } else { silo_query::current_server_silo() };
    let created = with(|etw| {
        let key = acquire_entry(etw, identifier, silo)?;
        let Some(pointer) = kernel_pool::allocate(REGISTRATION_SIZE, AllocateOptions { tag: REGISTRATION_TAG, zero: true, ..Default::default() }).ok().filter(|&pointer| pointer != 0) else {
            discard_unused_entry(etw, &key);
            return None;
        };
        let native = registration(pointer);
        native.group_reg_list.flink.set(native.group_reg_list.address());
        native.group_reg_list.blink.set(native.group_reg_list.address());
        let entry = etw.entries.get_mut(&key).expect("entrada adquirida");
        native.guid_entry.set(entry.pointer);
        native.callback_context.set(context);
        native.callback.set(callback);
        native.flags.set(flags::KERNEL | flags::INSERTED | if classic { flags::CLASSIC } else { 0 });
        entry.registrations.push(pointer);
        entry.references += 1;
        let enabled = entry.information.enabled != 0;
        etw.registrations.insert(pointer, Registration { pointer, entry: key.clone(), callback, context, active: 0, closing: false, user: None });
        synchronize(etw, &key);
        let enabled = enabled || etw.entries.get(&key).is_some_and(|entry| entry.information.enabled != 0);
        Some((pointer, enabled))
    });
    let Some((pointer, enabled)) = created else { return Ok(STATUS_INSUFFICIENT_RESOURCES) };
    handle_out.set(pointer);
    if enabled {
        if let Err(error) = notify_registration(pointer, None, None) {
            let _ = unregister(pointer);
            handle_out.set(0);
            return Err(error);
        }
    }
    Ok(0)
}

/// O estado de habilitação de um registro de modo usuário recém-criado
/// (EtwpRegisterUMGuid): a máscara de sessões e o agregado delas.
#[derive(Clone, Copy, Debug)]
pub struct UserRegistrationState {
    pub enable_mask: u8,
    pub information: Information,
}

/// EtwpAddUmRegEntry sobre um corpo EtwRegistration recém-criado: liga o
/// registro na entrada do GUID (provedor de trace para os tipos 2 e 3,
/// GUID de notificação para os demais) com o processo, o índice e o
/// contexto da ntdll.
pub fn register_user(identifier: [u8; 16], body: u64, owner: UserOwner, context: u64, wow64: bool) -> Result<UserRegistrationState, u32> {
    let notification = !matches!(owner.kind, 2 | 3);
    let silo = silo_query::current_server_silo();
    with(|etw| {
        let key = acquire_entry_of(etw, identifier, silo, notification).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let native = registration(body);
        native.group_reg_list.flink.set(native.group_reg_list.address());
        native.group_reg_list.blink.set(native.group_reg_list.address());
        let entry = etw.entries.get_mut(&key).expect("entrada adquirida");
        native.guid_entry.set(entry.pointer);
        native.process.set(owner.process);
        native.callback.set(context);
        native.index.set(owner.index);
        let mut value = flags::USER | flags::INSERTED;
        if owner.kind == 2 {
            value |= flags::CLASSIC;
        }
        if wow64 {
            value |= flags::WOW64;
        }
        native.flags.set(value);
        entry.registrations.push(body);
        entry.references += 1;
        etw.registrations.insert(body, Registration { pointer: body, entry: key.clone(), callback: 0, context, active: 0, closing: false, user: Some(owner) });
        synchronize(etw, &key);
        let information = etw.entries.get(&key).map_or_else(empty_information, |entry| entry.information);
        Ok(UserRegistrationState { enable_mask: native.enable_mask.get(), information })
    })
}

/// EtwpDeleteRegistrationObject: o registro sai da entrada do GUID.
/// Devolve o dono (o processo a desreferenciar) se o corpo era um registro.
pub fn delete_user(body: u64) -> Option<UserOwner> {
    with(|etw| {
        let record = etw.registrations.get_mut(&body)?;
        let owner = record.user;
        record.closing = true;
        let key = record.entry.clone();
        if let Some(entry) = etw.entries.get_mut(&key) {
            entry.registrations.retain(|&pointer| pointer != body);
        }
        let native_flags = &registration(body).flags;
        native_flags.set(native_flags.get() | flags::CLOSED);
        synchronize(etw, &key);
        finalize_registration(etw, body);
        owner
    })
}

/// O dono de modo usuário de um registro vivo.
pub fn user_owner(body: u64) -> Option<UserOwner> {
    with(|etw| etw.registrations.get(&body).filter(|record| !record.closing).and_then(|record| record.user))
}

/// EtwUnregister.
pub fn unregister(handle: u64) -> Result<u32, KernelError> {
    require_passive_level()?;
    Ok(with(|etw| {
        let Some(record) = etw.registrations.get_mut(&handle) else { return STATUS_INVALID_HANDLE };
        if record.closing || record.user.is_some() {
            return STATUS_INVALID_HANDLE;
        }
        record.closing = true;
        let key = record.entry.clone();
        if let Some(entry) = etw.entries.get_mut(&key) {
            entry.registrations.retain(|&pointer| pointer != handle);
        }
        let native_flags = &registration(handle).flags;
        native_flags.set(native_flags.get() | flags::CLOSED);
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
    enable_identifier(session, read_guid(identifier_pointer), options)
}

/// Habilita o provedor `identifier` (16 bytes) na sessão.
pub fn enable_identifier(session: u16, identifier: [u8; 16], options: EnableOptions) -> Result<(), KernelError> {
    require_passive_level()?;
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
            guid_entry(entry.pointer).ref_count.set(entry.references as i64);
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

/// Os dados de um evento: o descritor e os segmentos de usuário, lidos da
/// origem só depois de alguma sessão aceitar o evento.
pub struct Payload {
    pub activity: [u8; 16],
    pub related_activity: Option<[u8; 16]>,
    pub flags: u16,
    pub event_property: u16,
    pub segments: Vec<Vec<u8>>,
}

/// Até 128 EVENT_DATA_DESCRIPTOR e 0xFFFF bytes com o EVENT_HEADER.
const MAXIMUM_DESCRIPTORS: u32 = 128;
const MAXIMUM_EVENT_SIZE: u64 = 0xFFFF;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// Lê os segmentos de usuário (`read` decide se a origem é sondada).
pub fn read_segments(count: u32, data: u64, read: impl Fn(u64, usize) -> Result<Vec<u8>, KernelError>) -> Result<Result<Vec<Vec<u8>>, u32>, KernelError> {
    if count > MAXIMUM_DESCRIPTORS {
        return Ok(Err(STATUS_INVALID_PARAMETER));
    }
    let mut segments = Vec::new();
    let mut total = core::mem::size_of::<crate::ntos::inc::types::EventHeader>() as u64;
    for index in 0..count as u64 {
        let item = read(data + index * EventDataDescriptor::SIZE, EventDataDescriptor::SIZE as usize)?;
        let pointer = u64::from_le_bytes(item[0..8].try_into().unwrap());
        let size = u32::from_le_bytes(item[8..12].try_into().unwrap()) as u64;
        total += size;
        if total > MAXIMUM_EVENT_SIZE {
            return Ok(Err(STATUS_BUFFER_OVERFLOW));
        }
        segments.push(if size == 0 { Vec::new() } else { read(pointer, size as usize)? });
    }
    Ok(Ok(segments))
}

/// Entrega um evento de um registro: um provedor sem sessões nem lê os
/// buffers do chamador; cada sessão cujo TRACE_ENABLE_INFO aceita o nível e
/// a keyword recebe uma cópia.
pub fn deliver(handle: u64, descriptor: [u8; 16], payload: impl FnOnce() -> Result<Result<Payload, u32>, KernelError>) -> Result<u32, KernelError> {
    let prepared = with(|etw| {
        let record = etw.registrations.get(&handle).filter(|record| !record.closing)?;
        let entry = etw.entries.get(&record.entry)?;
        Some((entry.information.enabled != 0, entry.pointer, entry.identifier, entry.slots))
    });
    let Some((enabled, entry_pointer, provider, slots)) = prepared else { return Ok(STATUS_INVALID_HANDLE) };
    if !enabled {
        return Ok(0);
    }
    let level = descriptor[4];
    let keyword = u64::from_le_bytes(descriptor[8..16].try_into().unwrap());
    let native = guid_entry(entry_pointer);
    let recipients: Vec<u16> = slots
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| slot.filter(|_| event_enabled::matches(native.enable_info[index].address(), level, keyword)).map(|subscription| subscription.session))
        .collect();
    if recipients.is_empty() {
        return Ok(0);
    }
    let payload = match payload()? {
        Ok(payload) => payload,
        Err(status) => return Ok(status),
    };
    let thread = crate::ntos::ke::pcr::current_thread();
    let event = Event {
        provider,
        descriptor,
        activity: payload.activity,
        related_activity: payload.related_activity.unwrap_or([0; 16]),
        has_related: payload.related_activity.is_some(),
        flags: payload.flags,
        event_property: payload.event_property,
        process_id: if thread != 0 { crate::ntos::ps::thread_accessors::process_id(thread) as u32 } else { 0 },
        thread_id: if thread != 0 { crate::ntos::ps::thread_accessors::id(thread) as u32 } else { 0 },
        data: payload.segments,
    };
    // O diagnóstico na serial (os eventos do SCM), uma vez por evento.
    super::diagnostic::observe(&event);
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

/// EtwWrite/EtwWriteTransfer/EtwWriteEx de um chamador de kernel: ActivityId
/// nulo usa a atividade da thread.
pub fn write_ex(handle: u64, descriptor: u64, activity_pointer: u64, related: u64, count: u32, data: u64) -> Result<u32, KernelError> {
    let descriptor_bytes = read_guid(descriptor);
    deliver(handle, descriptor_bytes, || {
        let segments = match read_segments(count, data, |address, length| Ok(guest::read_bytes(address, length)))? {
            Ok(segments) => segments,
            Err(status) => return Ok(Err(status)),
        };
        Ok(Ok(Payload { activity: activity::resolve(activity_pointer), related_activity: (related != 0).then(|| read_guid(related)), flags: header_flags::SIXTY_FOUR_BIT_HEADER, event_property: 0, segments }))
    })
}

/// EtwWrite(RegHandle, EventDescriptor, ActivityId, UserDataCount, UserData)
/// (EtwWriteTransfer passa também o RelatedActivityId).
pub fn write(handle: u64, descriptor: u64, activity_pointer: u64, related: u64, count: u32, data: u64) -> Result<u32, KernelError> {
    write_ex(handle, descriptor, activity_pointer, related, count, data)
}

/// EtwWriteString(RegHandle, Level, Keyword, ActivityId, String): um evento
/// só de texto (EVENT_HEADER_FLAG_STRING_ONLY), a cadeia com o NUL.
pub fn write_string(handle: u64, level: u8, keyword: u64, activity_pointer: u64, string: u64) -> Result<u32, KernelError> {
    let mut descriptor = [0u8; 16];
    descriptor[4] = level;
    descriptor[8..16].copy_from_slice(&keyword.to_le_bytes());
    deliver(handle, descriptor, || {
        let text = crate::ntos::rtl::guest_strings::read_wide_string(string);
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0, 0]);
        if bytes.len() as u64 + core::mem::size_of::<crate::ntos::inc::types::EventHeader>() as u64 > MAXIMUM_EVENT_SIZE {
            return Ok(Err(STATUS_BUFFER_OVERFLOW));
        }
        Ok(Ok(Payload { activity: activity::resolve(activity_pointer), related_activity: None, flags: header_flags::SIXTY_FOUR_BIT_HEADER | header_flags::STRING_ONLY, event_property: 0, segments: alloc::vec![bytes] }))
    })
}

/// (registros, GUIDs, sessões).
pub fn statistics() -> (usize, usize, usize) {
    with(|etw| (etw.registrations.values().filter(|record| !record.closing).count(), etw.entries.len(), etw.sessions.len()))
}

/// Registros de modo usuário vivos.
pub fn user_registrations() -> usize {
    with(|etw| etw.registrations.values().filter(|record| !record.closing && record.user.is_some()).count())
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

// ---- Traits (EventProviderSetTraits) ---------------------------------------

/// A validação do EtwpSetProviderTraitsCommon: TotalSize (USHORT inicial) =
/// tamanho, o nome do provedor terminado em NUL e, depois dele, itens que
/// começam pelo próprio USHORT de tamanho e fecham exatamente o total.
pub fn validate_traits(traits: &[u8]) -> Result<(), u32> {
    let size = traits.len();
    if size < 3 || u16::from_le_bytes([traits[0], traits[1]]) as usize != size {
        return Err(STATUS_FILE_CORRUPT_ERROR);
    }
    let name = traits[2..].iter().position(|&byte| byte == 0).unwrap_or(size - 2);
    let mut offset = name + 3;
    if offset > size {
        return Err(STATUS_FILE_CORRUPT_ERROR);
    }
    while offset < size {
        if offset + 2 > size {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        let item = u16::from_le_bytes([traits[offset], traits[offset + 1]]) as usize;
        // Um item de tamanho zero nunca fecharia o total.
        if item == 0 {
            return Err(STATUS_FILE_CORRUPT_ERROR);
        }
        offset += item;
    }
    if offset == size { Ok(()) } else { Err(STATUS_FILE_CORRUPT_ERROR) }
}

/// Guarda os traits no registro (ETW_REG_ENTRY.Traits, o bloco 'EtwT' com a
/// cópia depois do cabeçalho): traits já guardados são STATUS_UNSUCCESSFUL;
/// aceitos, o registro passa a usar o tipo dos descritores.
pub fn set_traits(handle: u64, traits: &[u8]) -> u32 {
    if let Err(status) = validate_traits(traits) {
        return status;
    }
    let native = registration(handle);
    if native.traits.get() != 0 {
        return STATUS_UNSUCCESSFUL;
    }
    let Some(block) = kernel_pool::allocate(TRAITS_HEADER + traits.len() as u64, AllocateOptions { tag: TRAITS_TAG, zero: true, ..Default::default() }).ok().filter(|&block| block != 0) else { return STATUS_INSUFFICIENT_RESOURCES };
    guest::write32(block + 0x18, 1);
    guest::write_bytes(block + TRAITS_HEADER, traits);
    if native.traits.atomic().compare_exchange(0, block, core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst).is_err() {
        let _ = kernel_pool::free(block, None);
        return STATUS_UNSUCCESSFUL;
    }
    native.flags.atomic().fetch_or(flags::USE_DESCRIPTOR_TYPE, core::sync::atomic::Ordering::SeqCst);
    0
}

/// Os traits guardados de um registro (vazio sem eles).
pub fn traits(handle: u64) -> Vec<u8> {
    let block = registration(handle).traits.get();
    if block == 0 {
        return Vec::new();
    }
    let size = guest::read::<u16>(block + TRAITS_HEADER) as usize;
    guest::read_bytes(block + TRAITS_HEADER, size)
}

/// EventProviderUseDescriptorType: 1 liga e 0 desliga o uso do Type dos
/// EVENT_DATA_DESCRIPTOR; outro valor é STATUS_INVALID_PARAMETER.
pub fn use_descriptor_type(handle: u64, value: u8) -> u32 {
    let native_flags = &registration(handle).flags;
    match value {
        1 => native_flags.atomic().fetch_or(flags::USE_DESCRIPTOR_TYPE, core::sync::atomic::Ordering::SeqCst),
        0 => native_flags.atomic().fetch_and(!flags::USE_DESCRIPTOR_TYPE, core::sync::atomic::Ordering::SeqCst),
        _ => return STATUS_INVALID_PARAMETER,
    };
    0
}

/// EtwSetInformation(RegHandle, InformationClass, EventInformation,
/// InformationLength), como no ntoskrnl 19041: REGHANDLE nulo é
/// STATUS_INVALID_HANDLE (um REGHANDLE que não é registro vivo também, em
/// vez de ser seguido); EventProviderSetTraits (2) pede informação não
/// nula de 3 a 0x7FFF bytes num registro de kernel não clássico e
/// EventProviderUseDescriptorType (3) um BOOLEAN; as outras classes são
/// STATUS_INVALID_DEVICE_REQUEST.
pub fn set_information(handle: u64, class: u32, information: u64, length: u32) -> u32 {
    if handle == 0 || !is_registered(handle) {
        return STATUS_INVALID_HANDLE;
    }
    match class {
        EVENT_PROVIDER_SET_TRAITS => {
            if information == 0 || !(3..=0x7FFF).contains(&length) {
                return STATUS_INVALID_PARAMETER;
            }
            let value = registration(handle).flags.get();
            if value & flags::CLASSIC != 0 || value & flags::KERNEL == 0 {
                return STATUS_INVALID_PARAMETER;
            }
            set_traits(handle, &guest::read_bytes(information, length as usize))
        }
        EVENT_PROVIDER_USE_DESCRIPTOR_TYPE => {
            if information == 0 || length != 1 {
                return STATUS_INVALID_PARAMETER;
            }
            use_descriptor_type(handle, guest::read::<u8>(information))
        }
        _ => STATUS_INVALID_DEVICE_REQUEST,
    }
}
