//! Power settings (ntoskrnl 19041): os callbacks de drivers
//! (PoRegister/PoUnregisterPowerSettingCallback) e as configurações de
//! setting que o NtPowerInformation 58 (PowerSettingNotificationName) e 59
//! (GetPowerSettingValue) consultam.
//!
//! Os callbacks registrados ficam guardados para quando um setting mudar;
//! hoje nenhum muda, então nenhum é disparado. O handle devolvido ao driver
//! é o endereço do próprio callback.
//!
//! Configurações (PopPowerSettings e PopSessionSpecificLists, sob o
//! PopSettingLock):
//!
//! - Cada configuração tem o GUID, a sessão (-1 fora dos dois settings de
//!   sessão, GUID_SESSION_DISPLAY_STATUS e GUID_SESSION_USER_PRESENCE), as
//!   flags (1 = nome de notificação criado; 4 = em remoção; 8 = os três
//!   valores seguem a fonte de energia corrente), três valores (AC, DC e
//!   Hot) e o nome WNF de notificação.
//! - Só o PopSetPowerSettingValue cria configurações. No boot, o
//!   PopInitilizeAcDcSettings do PoInitSystem grava GUID_ACDC_POWER_SOURCE
//!   com AC = PoAc (0) e DC = PoDc (1). Os valores vêm em blocos
//!   {ChangeStamp, dados}: um valor igual ao de outro slot da mesma
//!   configuração reaproveita o bloco; senão o bloco novo recebe o próximo
//!   PopPowerSettingChangeStamp (que pula o zero).
//! - O PopGetSettingNotificationName devolve o nome WNF da configuração e o
//!   cria no primeiro pedido (PopCreateNotificationName: ZwCreateWnfStateName
//!   temporário, escopo de máquina, MaximumStateSize 0x24, DACL SYSTEM
//!   0x1F0003 e Everyone, ALL APPLICATION PACKAGES e a capability
//!   `lpacPnpNotifications` com 0x120001, sem dono). GUID desconhecido =
//!   STATUS_NOT_FOUND. Sem GUID, o nome é o PopPopPowerSettingSetChangeNotification
//!   global, criado do mesmo modo. A publicação dos valores no nome
//!   (PopSetNotificationWork) ainda não existe: as assinaturas valem, sem
//!   dados.
//! - O PopGetSettingValue serializa os três valores da configuração da
//!   sessão do chamador (PopMarshalSettingValues): o total de bytes e três
//!   registros {ChangeStamp, DataLength, Data}; um slot vazio vai como {0, 0}
//!   e o Hot vazio repete o DC. Com a flag 8, os três são o valor da fonte
//!   corrente.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::types::{Field, NtStruct};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::{KernelError, SharedLock, SpinLock};

const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Callback de power setting (disparado quando um setting muda; hoje
/// nenhum muda).
struct PowerSettingCallback {
    callback: u64,
    _context: u64,
    _device: u64,
    _setting_guid: u64,
}

static POWER_SETTING_CALLBACKS: SpinLock<Vec<PowerSettingCallback>> = SpinLock::new(Vec::new());

/// PoRegisterPowerSettingCallback(device, &setting_guid, callback, context,
/// &handle): guarda o callback e grava o handle quando pedido.
pub fn register_callback(device: u64, setting_guid: u64, callback: u64, context: u64, handle_out: u64) {
    POWER_SETTING_CALLBACKS.lock().push(PowerSettingCallback { callback, _context: context, _device: device, _setting_guid: setting_guid });
    if handle_out != 0 {
        // SAFETY: PVOID* Handle de saída do chamador.
        unsafe { Field::<u64>::at(handle_out) }.set(callback);
    }
}

/// PoUnregisterPowerSettingCallback(handle): STATUS_NOT_FOUND para um handle
/// desconhecido. Devolve o NTSTATUS.
pub fn unregister_callback(handle: u64) -> u32 {
    let mut callbacks = POWER_SETTING_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|entry| entry.callback == handle) else { return STATUS_NOT_FOUND };
    callbacks.remove(index);
    0
}

/// Um GUID nos 16 bytes do layout de memória.
const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let a = data1.to_le_bytes();
    let b = data2.to_le_bytes();
    let c = data3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], data4[0], data4[1], data4[2], data4[3], data4[4], data4[5], data4[6], data4[7]]
}

/// GUID_ACDC_POWER_SOURCE {5d3e9a59-e9d5-4b00-a6bd-ff34ff516548}.
pub const GUID_ACDC_POWER_SOURCE: [u8; 16] = guid(0x5d3e_9a59, 0xe9d5, 0x4b00, [0xa6, 0xbd, 0xff, 0x34, 0xff, 0x51, 0x65, 0x48]);
/// PopSessionSpecificGuids: GUID_SESSION_DISPLAY_STATUS
/// {2b84c20e-ad23-4ddf-93db-05ffbd7efca5} e GUID_SESSION_USER_PRESENCE
/// {3c0f4548-c03f-4c4d-b9f2-237ede686376}.
const SESSION_SPECIFIC_GUIDS: [[u8; 16]; 2] = [guid(0x2b84_c20e, 0xad23, 0x4ddf, [0x93, 0xdb, 0x05, 0xff, 0xbd, 0x7e, 0xfc, 0xa5]), guid(0x3c0f_4548, 0xc03f, 0x4c4d, [0xb9, 0xf2, 0x23, 0x7e, 0xde, 0x68, 0x63, 0x76])];

/// Flags da configuração.
const FLAG_NOTIFICATION_NAME: u32 = 1;
const FLAG_DELETED: u32 = 4;
const FLAG_FOLLOWS_POWER_SOURCE: u32 = 8;
/// A sessão das configurações que não são de sessão.
const ANY_SESSION: u32 = u32::MAX;
/// Os slots de valor: AC, DC e Hot.
const SLOT_AC: usize = 0;
const SLOT_DC: usize = 1;
const SLOT_HOT: usize = 2;

/// Um bloco de valor ('PSet' do PopSetPowerSettingValue).
struct Value {
    change_stamp: u32,
    data: Vec<u8>,
}

/// Uma configuração de power setting.
struct Configuration {
    guid: [u8; 16],
    session: u32,
    flags: u32,
    notification_name: u64,
    values: [Option<Arc<Value>>; 3],
}

/// PopSettingLock (o fast mutex do 19041): serializa as consultas e as
/// mudanças; a lista em si fica num SpinLock tomado só por instantes.
static SETTING_LOCK: SharedLock = SharedLock::new();
static CONFIGURATIONS: SpinLock<Vec<Configuration>> = SpinLock::new(Vec::new());
/// PopPowerSettingChangeStamp.
static CHANGE_STAMP: AtomicU32 = AtomicU32::new(0);
/// PopPopPowerSettingSetChangeNotification.
static SETTING_SET_CHANGE_NAME: AtomicU64 = AtomicU64::new(0);

/// PopPowerSettingValues+0xEC: o índice da fonte de energia corrente. O
/// OpenNT não tem bateria nem troca de fonte: PoAc (0).
fn current_power_source() -> usize {
    SLOT_AC
}

/// PopStateIsSessionSpecific.
fn is_session_specific(setting: &[u8; 16]) -> bool {
    SESSION_SPECIFIC_GUIDS.contains(setting)
}

/// PopFindPowerSettingConfiguration: o primeiro com o GUID; nos settings de
/// sessão, o da sessão pedida que não esteja em remoção.
fn find(configurations: &[Configuration], setting: &[u8; 16], session: u32) -> Option<usize> {
    if is_session_specific(setting) {
        configurations.iter().position(|entry| entry.guid == *setting && entry.session == session && entry.flags & FLAG_DELETED == 0)
    } else {
        configurations.iter().position(|entry| entry.guid == *setting)
    }
}

/// O próximo PopPowerSettingChangeStamp (o zero é pulado).
fn next_change_stamp() -> u32 {
    loop {
        let stamp = CHANGE_STAMP.fetch_add(1, Ordering::AcqRel).wrapping_add(1);
        if stamp != 0 {
            return stamp;
        }
    }
}

/// PopSetPowerSettingValue(Guid, Session, Slot, Data): cria a configuração
/// que faltar e troca o valor do slot. Um valor igual ao do slot não muda
/// nada; igual ao de outro slot, reaproveita aquele bloco.
fn set_value(setting: &[u8; 16], session: u32, slot: usize, data: &[u8]) {
    let _guard = SETTING_LOCK.acquire_exclusive();
    let mut configurations = CONFIGURATIONS.lock();
    let index = match find(&configurations, setting, session) {
        Some(index) => index,
        None => {
            configurations.push(Configuration { guid: *setting, session, flags: 0, notification_name: 0, values: [None, None, None] });
            configurations.len() - 1
        }
    };
    let configuration = &mut configurations[index];
    let equal = |value: &Option<Arc<Value>>| value.as_ref().is_some_and(|value| value.data == data);
    if equal(&configuration.values[slot]) {
        return;
    }
    let shared = (0..3).filter(|&other| other != slot).find(|&other| equal(&configuration.values[other])).and_then(|other| configuration.values[other].clone());
    let value = shared.unwrap_or_else(|| Arc::new(Value { change_stamp: next_change_stamp(), data: data.to_vec() }));
    configuration.values[slot] = Some(value);
    if configuration.notification_name != 0 {
        configuration.flags |= FLAG_NOTIFICATION_NAME;
    }
}

/// PopInitilizeAcDcSettings (PoInitSystem): GUID_ACDC_POWER_SOURCE com AC =
/// PoAc e DC = PoDc.
pub fn initialize_ac_dc_settings() {
    set_value(&GUID_ACDC_POWER_SOURCE, ANY_SESSION, SLOT_AC, &0u32.to_le_bytes());
    set_value(&GUID_ACDC_POWER_SOURCE, ANY_SESSION, SLOT_DC, &1u32.to_le_bytes());
}

/// O descritor absoluto do PopCreateNotificationName, num bloco de kernel:
/// DACL de 0x148 bytes, sem dono.
fn notification_descriptor() -> Result<u64, u32> {
    use crate::ntos::se::model::sid;
    use crate::ntos::se::{acl as acls, descriptor as descriptors};
    const ACL_SIZE: u32 = 0x148;
    let entries: [(Vec<u8>, u32); 4] = [(sid(5, &[18]), 0x1F_0003), (sid(1, &[0]), 0x12_0001), (sid(15, &[2, 1]), 0x12_0001), (crate::ntos::se::capability::identifiers::capability_sid("lpacPnpNotifications"), 0x12_0001)];
    let sid_bytes: usize = entries.iter().map(|(bytes, _)| bytes.len()).sum();
    let block = guest::alloc_bytes(0x28 + ACL_SIZE as u64 + sid_bytes as u64);
    if block == 0 {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let (descriptor, acl) = (block, block + 0x28);
    let mut cursor = acl + ACL_SIZE as u64;
    let mut status = acls::create(acl, ACL_SIZE, 2);
    for (bytes, mask) in &entries {
        guest::write_bytes(cursor, bytes);
        if status == 0 {
            status = acls::add_known_ace(acl, 2, 0, *mask, cursor, 0);
        }
        cursor += bytes.len() as u64;
    }
    if status == 0 {
        status = descriptors::create(descriptor, 1);
    }
    if status == 0 {
        status = descriptors::set_dacl(descriptor, true, acl, false);
    }
    if status != 0 {
        guest::free_bytes(block);
        return Err(status);
    }
    Ok(block)
}

/// PopCreateNotificationName: um nome WNF temporário de escopo de máquina.
fn create_notification_name() -> Result<Result<u64, u32>, KernelError> {
    const WNF_TEMPORARY_STATE_NAME: u32 = 3;
    const WNF_DATA_SCOPE_MACHINE: u32 = 4;
    const MAXIMUM_STATE_SIZE: u32 = 0x24;
    let descriptor = match notification_descriptor() {
        Ok(descriptor) => descriptor,
        Err(status) => return Ok(Err(status)),
    };
    let cell = guest::alloc_bytes(8);
    if cell == 0 {
        guest::free_bytes(descriptor);
        return Ok(Err(STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write64(cell, 0);
    let request = crate::ntos::ex::wnf::service::CreateName { output: cell, lifetime: WNF_TEMPORARY_STATE_NAME, scope: WNF_DATA_SCOPE_MACHINE, persist: false, type_identifier: 0, maximum_size: MAXIMUM_STATE_SIZE, security_descriptor: descriptor };
    let status = crate::ntos::ps::previous_mode::with_kernel(|| crate::ntos::ex::wnf::service::create_state_name(&request));
    let name = guest::read64(cell);
    guest::free_bytes(cell);
    guest::free_bytes(descriptor);
    let status = status??;
    Ok(if status & 0x8000_0000 != 0 { Err(status) } else { Ok(name) })
}

/// RtlCheckTokenMembership(NULL, Sid) da identidade do chamador
/// (PopValidateContextMembership): STATUS_ACCESS_DENIED fora dela.
fn validate_membership(identifier: &[u8]) -> u32 {
    let block = guest::alloc_bytes(8 + identifier.len() as u64);
    if block == 0 {
        return STATUS_ACCESS_DENIED;
    }
    guest::write_bytes(block + 8, identifier);
    let status = crate::ntos::se::token::membership::check(0, block + 8, block).unwrap_or(STATUS_ACCESS_DENIED);
    let member = status & 0x8000_0000 == 0 && guest::read8(block) != 0;
    guest::free_bytes(block);
    if member { 0 } else { STATUS_ACCESS_DENIED }
}

/// PsIsServiceSession: a sessão 0 (o OpenNT não tem server silos).
fn is_service_session(session: u32) -> bool {
    session == 0
}

/// PopGetSettingNotificationName(Input, &Name): `input` é o GUID e a sessão
/// pedida (None = o nome global de mudança do conjunto de settings).
/// Devolve o nome WNF ou o NTSTATUS.
pub fn notification_name(input: Option<([u8; 16], u32)>) -> Result<Result<u64, u32>, KernelError> {
    let guard = SETTING_LOCK.acquire_exclusive();
    let Some((setting, requested)) = input else {
        let existing = SETTING_SET_CHANGE_NAME.load(Ordering::Acquire);
        if existing != 0 {
            return Ok(Ok(existing));
        }
        let created = create_notification_name()?;
        if let Ok(name) = created {
            SETTING_SET_CHANGE_NAME.store(name, Ordering::Release);
        }
        return Ok(created);
    };
    let session = if is_session_specific(&setting) {
        // A sessão de um setting de sessão: a do chamador (pedida como -1 ou
        // como a própria, nunca a de serviços); outra sessão pede o SYSTEM
        // ou, para quem está na sessão de serviços, o LocalService.
        let caller = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
        if requested == ANY_SESSION || requested == caller {
            if caller == ANY_SESSION || is_service_session(caller) {
                return Ok(Err(STATUS_INVALID_PARAMETER));
            }
            caller
        } else {
            use crate::ntos::se::model::sid;
            let status = validate_membership(&sid(5, &[18]));
            if status != 0 {
                if !is_service_session(caller) {
                    return Ok(Err(status));
                }
                let status = validate_membership(&sid(5, &[19]));
                if status != 0 {
                    return Ok(Err(status));
                }
            }
            requested
        }
    } else {
        ANY_SESSION
    };
    let existing = {
        let configurations = CONFIGURATIONS.lock();
        let Some(index) = find(&configurations, &setting, session) else { return Ok(Err(STATUS_NOT_FOUND)) };
        configurations[index].notification_name
    };
    if existing != 0 {
        return Ok(Ok(existing));
    }
    let name = match create_notification_name()? {
        Ok(name) => name,
        Err(status) => return Ok(Err(status)),
    };
    {
        let mut configurations = CONFIGURATIONS.lock();
        if let Some(index) = find(&configurations, &setting, session) {
            let configuration = &mut configurations[index];
            configuration.notification_name = name;
            configuration.flags |= FLAG_NOTIFICATION_NAME;
            if setting == GUID_ACDC_POWER_SOURCE {
                configuration.flags |= FLAG_FOLLOWS_POWER_SOURCE;
            }
        }
    }
    drop(guard);
    Ok(Ok(name))
}

/// PopGetSettingValue(Guid, Output, OutputLength): a configuração da sessão
/// do chamador serializada (PopMarshalSettingValues), com o total na
/// frente. STATUS_INVALID_PARAMETER sem configuração; STATUS_BUFFER_TOO_SMALL
/// se os registros não cabem em OutputLength - 4.
pub fn setting_value(setting: &[u8; 16], output_length: u32) -> Result<Vec<u8>, u32> {
    let _guard = SETTING_LOCK.acquire_exclusive();
    let session = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
    let configurations = CONFIGURATIONS.lock();
    let Some(index) = find(&configurations, setting, session) else { return Err(STATUS_INVALID_PARAMETER) };
    let configuration = &configurations[index];
    let mut chosen: [Option<Arc<Value>>; 3] = [None, None, None];
    for slot in 0..3 {
        chosen[slot] = if configuration.flags & FLAG_FOLLOWS_POWER_SOURCE != 0 {
            configuration.values[current_power_source()].clone()
        } else if slot == SLOT_HOT && configuration.values[SLOT_HOT].is_none() {
            chosen[SLOT_DC].clone()
        } else {
            configuration.values[slot].clone()
        };
    }
    let total: usize = chosen.iter().map(|value| 8 + value.as_ref().map_or(0, |value| value.data.len())).sum();
    if (output_length.wrapping_sub(4) as usize) < total {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let mut output = Vec::with_capacity(4 + total);
    output.extend_from_slice(&(total as u32).to_le_bytes());
    for value in &chosen {
        match value {
            Some(value) => {
                output.extend_from_slice(&value.change_stamp.to_le_bytes());
                output.extend_from_slice(&(value.data.len() as u32).to_le_bytes());
                output.extend_from_slice(&value.data);
            }
            None => output.extend_from_slice(&[0u8; 8]),
        }
    }
    Ok(output)
}
