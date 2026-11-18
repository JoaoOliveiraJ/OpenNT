//! Power settings (ntoskrnl 19041): as configurações que o
//! NtPowerInformation 58 (PowerSettingNotificationName) e 59
//! (GetPowerSettingValue) consultam, os callbacks dos drivers
//! (PoRegister/PoUnregisterPowerSettingCallback) e a entrega das mudanças
//! pelo worker de política (`po/policy_worker.rs`).
//!
//! Configurações (PopPowerSettings e PopSessionSpecificLists, sob o
//! PopSettingLock):
//!
//! - Cada configuração tem o GUID, a sessão (-1 fora dos dois settings de
//!   sessão, GUID_SESSION_DISPLAY_STATUS e GUID_SESSION_USER_PRESENCE), as
//!   flags (1 = publicação WNF pendente; 2 = publicação em curso; 4 = em
//!   remoção; 8 = os três valores seguem a fonte de energia corrente), três
//!   valores (AC, DC e Hot), os callbacks registrados e o nome WNF de
//!   notificação.
//! - Só o PopSetPowerSettingValue (0x6f35e8) cria configurações. No boot, o
//!   PopInitilizeAcDcSettings do PoInitSystem grava GUID_ACDC_POWER_SOURCE
//!   com AC = PoAc (0) e DC = PoDc (1); o PopUpdateConsoleDisplayState grava
//!   GUID_CONSOLE_DISPLAY_STATE e GUID_MONITOR_POWER_ON, e o SessionDisplayState
//!   do win32k, GUID_SESSION_DISPLAY_STATUS da sessão (`po/display_state.rs`).
//!   A conexão e a entrada da sessão (os níveis 61 e 62 do win32k,
//!   `po/user_presence.rs`) gravam GUID_SESSION_DISPLAY_STATUS e
//!   GUID_SESSION_USER_PRESENCE da sessão e GUID_GLOBAL_USER_PRESENCE.
//!   Os valores vêm em blocos {ChangeStamp, dados}: um valor igual ao do slot
//!   não muda nada; igual ao de outro slot da mesma configuração, reaproveita
//!   aquele bloco; senão o bloco novo recebe o próximo
//!   PopPowerSettingChangeStamp (que pula o zero). A configuração nova de um
//!   setting de máquina leva os callbacks que esperavam por ela em
//!   PopRegisteredPowerSettingCallbacks.
//! - Com o PoInitSystem na fase 3 (PopOsInitPhase), o PopSetPowerSettingValue
//!   avisa as mudanças: a configuração nova publica o nome global
//!   (PopPopPowerSettingSetChangeNotification, sem dados) se ele existe; a
//!   troca do slot da fonte corrente num setting de máquina pede o
//!   PopDispatchPowerSettingCallbacks (PopSetNotificationWork 0x20); e a
//!   configuração com nome WNF marca a publicação pendente e pede o
//!   PopDispatchNotifications (0x80). Os settings de sessão não chamam
//!   callbacks de driver.
//! - O PopGetSettingNotificationName devolve o nome WNF da configuração e o
//!   cria no primeiro pedido (PopCreateNotificationName: ZwCreateWnfStateName
//!   temporário, escopo de máquina, MaximumStateSize 0x24, DACL SYSTEM
//!   0x1F0003 e Everyone, ALL APPLICATION PACKAGES e a capability
//!   `lpacPnpNotifications` com 0x120001, sem dono), marcando a publicação
//!   do valor corrente (PopSetNotificationWork 0x80). GUID desconhecido =
//!   STATUS_NOT_FOUND. Sem GUID, o nome é o global, criado do mesmo modo.
//!   É o caminho do RegisterPowerSettingNotification do user32 e do
//!   PowerSettingRegisterNotification do powrprof: o processo assina o nome
//!   e recebe cada publicação.
//! - O PopDispatchNotifications (0x6f5030) percorre as listas (a de máquina e
//!   as duas de sessão) e publica cada configuração pendente no nome dela
//!   (ZwUpdateWnfStateData com os registros do PopMarshalSettingValues, no
//!   máximo 0x24 bytes; registros que não cabem vão vazios). Uma publicação
//!   que falha fica pendente para o próximo pedido; um valor trocado durante
//!   a publicação é publicado de novo.
//! - O PopGetSettingValue serializa os três valores da configuração da
//!   sessão do chamador (PopMarshalSettingValues): o total de bytes e três
//!   registros {ChangeStamp, DataLength, Data}; um slot vazio vai como {0, 0}
//!   e o Hot vazio repete o DC. Com a flag 8, os três são o valor da fonte
//!   corrente.
//!
//! Callbacks (PoRegisterPowerSettingCallback 0x6f4a10,
//! PoUnregisterPowerSettingCallback 0x772260):
//!
//! - O registro é um bloco de 0x70 bytes com a tag 'PSet' em +0x10, e o
//!   endereço dele é o handle. Um setting de sessão é STATUS_INVALID_PARAMETER.
//!   O bloco entra na lista da configuração do GUID ou, sem ela, em
//!   PopRegisteredPowerSettingCallbacks. O último valor entregue começa
//!   vazio (para GUID_IDLE_BACKGROUND_TASK e GUID_BACKGROUND_TASK_NOTIFICATION,
//!   o valor corrente), então, a partir da fase 3, o PopSetNotificationWork
//!   0x20 do registro entrega o valor corrente ao callback: o callback
//!   inicial. O 19041 também troca o GUID de um callback de
//!   GUID_CONSOLE_DISPLAY_STATE pela errata do arquivo do driver
//!   (EmClientRuleEvaluate de GUID_EM_PO_CONSOLE_STATE_CHANGE_REMAP_RULE); o
//!   OpenNT não tem banco de erratas, então nada é trocado.
//! - O PopDispatchPowerSettingCallbacks (0x6f2bf0) percorre as
//!   configurações de máquina e, em cada uma, os callbacks cujo último valor
//!   entregue não é o valor da fonte corrente; o PopCallPowerSettingCallback
//!   (0x6f4728) marca a thread que chama, solta o PopSettingLock, chama
//!   Callback(&Guid, Data, DataLength, Context), confere o IRQL (outro IRQL na
//!   volta = INTERNAL_POWER_ERROR 0x900) e repete se um valor mais novo
//!   chegou durante a chamada. Uma configuração sem callbacks, sem nome WNF
//!   e sem valores sai da lista.
//! - O PoUnregisterPowerSettingCallback recusa (STATUS_INVALID_PARAMETER)
//!   um handle sem a tag, já removido ou com remoção pendente. Com o callback
//!   rodando na própria thread, a remoção fica para a volta dele; noutra
//!   thread, espera o PopPowerSettingCallbackReturned até o callback voltar.
//!
//! Os valores chegam aos callbacks numa cópia em memória do kernel. O
//! callback de rastro ETW que o 19041 registra em cada configuração nova
//! (PopTracePowerSettingChange) e a contagem de atualizações pendentes do
//! deep sleep (PopIncrement/DecrementPowerSettingPendingUpdates) ficam de
//! fora. O PopValidatePowerSettingData sobe ao mínimo os timeouts de disco,
//! standby e hibernação. Os valores do esquema de energia chegam do serviço
//! Power pela mensagem 4 do `\PowerPort` (PopSetNewPolicyValue,
//! `po/umpo_channel.rs`) e vão aos callbacks e aos nomes WNF como qualquer
//! outro. Os callbacks internos do Po (PopInitialSettingCallbacks do
//! PopInitializePowerSettingCallbacks: os timeouts de vídeo e de console, o
//! sono, os botões, o repasse ao win32k pelo PopWin32kPowerSettingCallback)
//! não são registrados, então o PopPowerSettingValues continua zerado.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::hal::amd64::native_call;
use crate::ntos::inc::types::{Field, Guid, Kevent, ListEntry, NtStruct, Reserved};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::policy_worker::{self, NOTIFY_POWER_SETTING_CALLBACKS, NOTIFY_SETTING_NOTIFICATIONS};
use crate::rtl::sync::SharedLockGuard;
use crate::rtl::{KernelError, SharedLock, SpinLock};

const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

/// Um GUID nos 16 bytes do layout de memória.
pub(crate) const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> [u8; 16] {
    let a = data1.to_le_bytes();
    let b = data2.to_le_bytes();
    let c = data3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], data4[0], data4[1], data4[2], data4[3], data4[4], data4[5], data4[6], data4[7]]
}

/// GUID_ACDC_POWER_SOURCE {5d3e9a59-e9d5-4b00-a6bd-ff34ff516548}.
pub const GUID_ACDC_POWER_SOURCE: [u8; 16] = guid(0x5d3e_9a59, 0xe9d5, 0x4b00, [0xa6, 0xbd, 0xff, 0x34, 0xff, 0x51, 0x65, 0x48]);
/// GUID_SESSION_DISPLAY_STATUS {2b84c20e-ad23-4ddf-93db-05ffbd7efca5}.
pub const GUID_SESSION_DISPLAY_STATUS: [u8; 16] = guid(0x2b84_c20e, 0xad23, 0x4ddf, [0x93, 0xdb, 0x05, 0xff, 0xbd, 0x7e, 0xfc, 0xa5]);
/// GUID_SESSION_USER_PRESENCE {3c0f4548-c03f-4c4d-b9f2-237ede686376}.
pub const GUID_SESSION_USER_PRESENCE: [u8; 16] = guid(0x3c0f_4548, 0xc03f, 0x4c4d, [0xb9, 0xf2, 0x23, 0x7e, 0xde, 0x68, 0x63, 0x76]);
/// PopSessionSpecificGuids.
const SESSION_SPECIFIC_GUIDS: [[u8; 16]; 2] = [GUID_SESSION_DISPLAY_STATUS, GUID_SESSION_USER_PRESENCE];
/// GUID_CONSOLE_DISPLAY_STATE {6fe69556-704a-47a0-8f24-c28d936fda47}.
pub const GUID_CONSOLE_DISPLAY_STATE: [u8; 16] = guid(0x6fe6_9556, 0x704a, 0x47a0, [0x8f, 0x24, 0xc2, 0x8d, 0x93, 0x6f, 0xda, 0x47]);
/// GUID_MONITOR_POWER_ON {02731015-4510-4526-99e6-e5a17ebd1aea}.
pub const GUID_MONITOR_POWER_ON: [u8; 16] = guid(0x0273_1015, 0x4510, 0x4526, [0x99, 0xe6, 0xe5, 0xa1, 0x7e, 0xbd, 0x1a, 0xea]);
/// GUID_GLOBAL_USER_PRESENCE {786e8a1d-b427-4344-9207-09e70bdcbea9}: a
/// presença do usuário da máquina (o PopEvaluateGlobalUserStatus).
pub const GUID_GLOBAL_USER_PRESENCE: [u8; 16] = guid(0x786e_8a1d, 0xb427, 0x4344, [0x92, 0x07, 0x09, 0xe7, 0x0b, 0xdc, 0xbe, 0xa9]);
/// GUID_IDLE_BACKGROUND_TASK {515c31d8-f734-163d-a0fd-11a08c91e8f1} e
/// GUID_BACKGROUND_TASK_NOTIFICATION {cf23f240-2a54-48d8-b114-de1518ff052e}:
/// o registro já começa com o valor corrente (sem callback inicial).
const GUID_IDLE_BACKGROUND_TASK: [u8; 16] = guid(0x515c_31d8, 0xf734, 0x163d, [0xa0, 0xfd, 0x11, 0xa0, 0x8c, 0x91, 0xe8, 0xf1]);
const GUID_BACKGROUND_TASK_NOTIFICATION: [u8; 16] = guid(0xcf23_f240, 0x2a54, 0x48d8, [0xb1, 0x14, 0xde, 0x15, 0x18, 0xff, 0x05, 0x2e]);
/// GUID_PROCESSOR_SETTINGS_SUBGROUP {54533251-82be-4824-96c1-47b60b740d00}:
/// os valores deste subgrupo vão antes aos perfis do PPM.
pub const GUID_PROCESSOR_SETTINGS_SUBGROUP: [u8; 16] = guid(0x5453_3251, 0x82be, 0x4824, [0x96, 0xc1, 0x47, 0xb6, 0x0b, 0x74, 0x0d, 0x00]);
/// GUID_DISK_POWERDOWN_TIMEOUT {6738e2c4-e8a5-4a42-b16a-e040e769756e},
/// GUID_STANDBY_TIMEOUT {29f6c1db-86da-48c5-9fdb-f2b67b1f44da} e
/// GUID_HIBERNATE_TIMEOUT {9d7815a6-7ee4-497e-8888-515a05f02364}: os
/// timeouts com mínimo no PopValidatePowerSettingData.
pub const GUID_DISK_POWERDOWN_TIMEOUT: [u8; 16] = guid(0x6738_e2c4, 0xe8a5, 0x4a42, [0xb1, 0x6a, 0xe0, 0x40, 0xe7, 0x69, 0x75, 0x6e]);
pub const GUID_STANDBY_TIMEOUT: [u8; 16] = guid(0x29f6_c1db, 0x86da, 0x48c5, [0x9f, 0xdb, 0xf2, 0xb6, 0x7b, 0x1f, 0x44, 0xda]);
pub const GUID_HIBERNATE_TIMEOUT: [u8; 16] = guid(0x9d78_15a6, 0x7ee4, 0x497e, [0x88, 0x88, 0x51, 0x5a, 0x05, 0xf0, 0x23, 0x64]);

/// Flags da configuração.
const FLAG_PUBLISH_PENDING: u32 = 1;
const FLAG_PUBLISHING: u32 = 2;
const FLAG_DELETED: u32 = 4;
const FLAG_FOLLOWS_POWER_SOURCE: u32 = 8;
/// A sessão das configurações que não são de sessão.
const ANY_SESSION: u32 = u32::MAX;
/// Os slots de valor: AC, DC e Hot.
const SLOT_AC: usize = 0;
const SLOT_DC: usize = 1;
const SLOT_HOT: usize = 2;
/// O MaximumStateSize dos nomes de notificação (três registros de 4 bytes).
const MAXIMUM_STATE_SIZE: u32 = 0x24;
/// A tag dos blocos de power setting ('PSet').
const POWER_SETTING_TAG: u32 = 0x7465_5350;
/// INTERNAL_POWER_ERROR e o parâmetro do IRQL trocado por um callback.
const INTERNAL_POWER_ERROR: u32 = 0xA0;
const CALLBACK_CHANGED_IRQL: u64 = 0x900;

/// O bloco de um registro de callback (o handle do driver): a tag e os
/// campos que saem do Po. O estado dinâmico (thread, último valor, remoção)
/// fica em [`Registration`].
#[repr(C)]
struct RegistrationBlock {
    link: ListEntry,
    /// 'PSet' enquanto registrado.
    tag: Field<u32>,
    _reserved0: Reserved<0x10>,
    /// O GUID da configuração.
    setting: Guid,
    /// O GUID que o callback recebe.
    callback_setting: Guid,
    _reserved1: Reserved<0xC>,
    callback: Field<u64>,
    context: Field<u64>,
    device: Field<u64>,
    _reserved2: Reserved<8>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for RegistrationBlock {}

const _: () = {
    assert!(core::mem::size_of::<RegistrationBlock>() == 0x70);
    assert!(core::mem::offset_of!(RegistrationBlock, tag) == 0x10);
    assert!(core::mem::offset_of!(RegistrationBlock, setting) == 0x24);
    assert!(core::mem::offset_of!(RegistrationBlock, callback_setting) == 0x34);
    assert!(core::mem::offset_of!(RegistrationBlock, callback) == 0x50);
    assert!(core::mem::offset_of!(RegistrationBlock, device) == 0x60);
};

/// Os 16 bytes de um GUID do NT.
pub(crate) fn guid_bytes(value: &Guid) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&value.data1.get().to_le_bytes());
    bytes[4..6].copy_from_slice(&value.data2.get().to_le_bytes());
    bytes[6..8].copy_from_slice(&value.data3.get().to_le_bytes());
    for (byte, cell) in bytes[8..].iter_mut().zip(&value.data4) {
        *byte = cell.get();
    }
    bytes
}

/// Grava os 16 bytes num GUID do NT.
fn store_guid(target: &Guid, bytes: &[u8; 16]) {
    target.data1.set(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
    target.data2.set(u16::from_le_bytes([bytes[4], bytes[5]]));
    target.data3.set(u16::from_le_bytes([bytes[6], bytes[7]]));
    for (cell, byte) in target.data4.iter().zip(&bytes[8..]) {
        cell.set(*byte);
    }
}

/// Um bloco de valor ('PSet' do PopSetPowerSettingValue).
struct Value {
    change_stamp: u32,
    data: Vec<u8>,
}

/// O mesmo bloco de valor (dois vazios também são o mesmo).
fn same_value(left: &Option<Arc<Value>>, right: &Option<Arc<Value>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}

/// Um callback registrado.
struct Registration {
    /// O bloco 'PSet' (o handle).
    handle: u64,
    setting: [u8; 16],
    callback: u64,
    context: u64,
    /// O último valor entregue (+0x48 no 19041).
    delivered: Option<Arc<Value>>,
    /// A thread que está chamando o callback (+0x18).
    thread: u64,
    /// O PopDispatchPowerSettingCallbacks está neste registro (+0x68).
    dispatching: bool,
    /// Removido de dentro do próprio callback (+0x20).
    remove_on_return: bool,
    /// Um PoUnregisterPowerSettingCallback de outra thread espera a volta
    /// do callback (+0x21).
    removal_waiting: bool,
    /// Já fora da lista, à espera de quem o remove (a entrada apontando
    /// para si mesma no 19041).
    unlinked: bool,
}

/// Uma configuração de power setting.
struct Configuration {
    /// Identidade estável (as listas do OpenNT são vetores).
    id: u64,
    guid: [u8; 16],
    session: u32,
    flags: u32,
    notification_name: u64,
    values: [Option<Arc<Value>>; 3],
    registrations: Vec<Registration>,
}

/// As listas do Po: as configurações, na ordem de criação, e
/// PopRegisteredPowerSettingCallbacks (os callbacks à espera da
/// configuração do GUID).
struct Settings {
    configurations: Vec<Configuration>,
    unattached: Vec<Registration>,
    next_id: u64,
}

impl Settings {
    fn index_of(&self, id: u64) -> Option<usize> {
        self.configurations.iter().position(|configuration| configuration.id == id)
    }

    /// O registro do handle, numa configuração ou à espera de uma.
    fn registration(&mut self, handle: u64) -> Option<&mut Registration> {
        let in_configuration = self.configurations.iter().position(|configuration| configuration.registrations.iter().any(|entry| entry.handle == handle));
        match in_configuration {
            Some(index) => self.configurations[index].registrations.iter_mut().find(|entry| entry.handle == handle),
            None => self.unattached.iter_mut().find(|entry| entry.handle == handle),
        }
    }

    /// Tira o registro das listas (true se estava nelas).
    fn remove(&mut self, handle: u64) -> bool {
        for configuration in &mut self.configurations {
            if let Some(index) = configuration.registrations.iter().position(|entry| entry.handle == handle) {
                configuration.registrations.remove(index);
                return true;
            }
        }
        if let Some(index) = self.unattached.iter().position(|entry| entry.handle == handle) {
            self.unattached.remove(index);
            return true;
        }
        false
    }

    /// A configuração nova do PopSetPowerSettingValue, no fim da lista; a de
    /// um setting de máquina leva os callbacks que esperavam por ela.
    fn create(&mut self, setting: &[u8; 16], session: u32) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        let mut registrations = Vec::new();
        let session = if is_session_specific(setting) {
            session
        } else {
            let mut index = 0;
            while index < self.unattached.len() {
                if self.unattached[index].setting == *setting {
                    registrations.push(self.unattached.remove(index));
                } else {
                    index += 1;
                }
            }
            ANY_SESSION
        };
        self.configurations.push(Configuration { id, guid: *setting, session, flags: 0, notification_name: 0, values: [None, None, None], registrations });
        self.configurations.len() - 1
    }
}

/// PopSettingLock (o fast mutex do 19041): serializa as consultas e as
/// mudanças; as listas em si ficam num SpinLock tomado só por instantes.
static SETTING_LOCK: SharedLock = SharedLock::new();
static SETTINGS: SpinLock<Settings> = SpinLock::new(Settings { configurations: Vec::new(), unattached: Vec::new(), next_id: 1 });
/// PopPowerSettingChangeStamp.
static CHANGE_STAMP: AtomicU32 = AtomicU32::new(0);
/// PopPopPowerSettingSetChangeNotification.
static SETTING_SET_CHANGE_NAME: AtomicU64 = AtomicU64::new(0);
/// PopOsInitPhase: a fase do PoInitSystem em curso.
static OS_INIT_PHASE: AtomicU32 = AtomicU32::new(0);
/// PopPowerSettingCallbackReturned (KEVENT de notificação).
static CALLBACK_RETURNED: AtomicU64 = AtomicU64::new(0);

/// PoInitSystem(Phase) grava PopOsInitPhase na entrada; da fase 3 em
/// diante as mudanças e os registros pedem a entrega.
pub fn begin_init_phase(phase: u32) {
    OS_INIT_PHASE.store(phase, Ordering::Release);
}

fn notifications_enabled() -> bool {
    OS_INIT_PHASE.load(Ordering::Acquire) >= 3
}

/// PopPowerSettingValues+0xEC: o índice da fonte de energia corrente. O
/// OpenNT não tem bateria nem troca de fonte: PoAc (0).
fn current_power_source() -> usize {
    SLOT_AC
}

/// PopStateIsSessionSpecific.
fn is_session_specific(setting: &[u8; 16]) -> bool {
    SESSION_SPECIFIC_GUIDS.contains(setting)
}

/// PopGetListHead: 0 = PopPowerSettings; 1 e 2 = as listas dos dois
/// settings de sessão.
fn list_of(setting: &[u8; 16]) -> usize {
    SESSION_SPECIFIC_GUIDS.iter().position(|entry| entry == setting).map_or(0, |index| index + 1)
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

/// PopValidatePowerSettingData (0x6f3bc4) sobre a cópia do valor, antes da
/// comparação com o slot: um ULONG de GUID_DISK_POWERDOWN_TIMEOUT entre 1 e
/// 14 vira 15 (fora de uma plataforma AoAc, que o OpenNT não é), de
/// GUID_STANDBY_TIMEOUT entre 1 e 29 vira 30 e de GUID_HIBERNATE_TIMEOUT
/// entre 1 e 59 vira 60. O zero (nunca), outros tamanhos e os outros
/// settings passam iguais.
pub fn validate_data(setting: &[u8; 16], data: &mut [u8]) {
    let Ok(bytes) = <[u8; 4]>::try_from(&data[..]) else { return };
    let minimum = if *setting == GUID_DISK_POWERDOWN_TIMEOUT {
        15
    } else if *setting == GUID_STANDBY_TIMEOUT {
        30
    } else if *setting == GUID_HIBERNATE_TIMEOUT {
        60
    } else {
        return;
    };
    let value = u32::from_le_bytes(bytes);
    if value != 0 && value < minimum {
        data.copy_from_slice(&u32::to_le_bytes(minimum));
    }
}

/// PopSetPowerSettingValue(Guid, Session, Slot, Data).
fn set_value(setting: &[u8; 16], session: u32, slot: usize, data: &[u8]) {
    let mut data = data.to_vec();
    validate_data(setting, &mut data);
    let data = &data[..];
    let session_specific = is_session_specific(setting);
    let guard = SETTING_LOCK.acquire_exclusive();
    let (announce, dispatch, publish) = {
        let mut settings = SETTINGS.lock();
        let (index, created) = match find(&settings.configurations, setting, session) {
            Some(index) => (index, false),
            None => (settings.create(setting, session), true),
        };
        let announce = created && SETTING_SET_CHANGE_NAME.load(Ordering::Acquire) != 0;
        let configuration = &mut settings.configurations[index];
        let equal = |value: &Option<Arc<Value>>| value.as_ref().is_some_and(|value| value.data == data);
        if equal(&configuration.values[slot]) {
            (announce, false, false)
        } else {
            let old = configuration.values[slot].take();
            let mut shared = None;
            let mut old_shared = false;
            for other in (0..3).filter(|&other| other != slot) {
                let value = &configuration.values[other];
                if shared.is_none() && equal(value) {
                    shared = value.clone();
                }
                old_shared |= same_value(value, &old);
            }
            // O bloco antigo que nenhum outro slot usa deixa de ser o último
            // valor entregue dos callbacks.
            if let Some(old) = &old {
                if !old_shared {
                    for registration in &mut configuration.registrations {
                        if registration.delivered.as_ref().is_some_and(|delivered| Arc::ptr_eq(delivered, old)) {
                            registration.delivered = None;
                        }
                    }
                }
            }
            configuration.values[slot] = Some(shared.unwrap_or_else(|| Arc::new(Value { change_stamp: next_change_stamp(), data: data.to_vec() })));
            let publish = configuration.notification_name != 0;
            if publish {
                configuration.flags |= FLAG_PUBLISH_PENDING;
            }
            (announce, slot == current_power_source() && !session_specific, publish)
        }
    };
    drop(guard);
    if notifications_enabled() {
        if announce {
            let _ = publish_set_change();
        }
        if dispatch {
            policy_worker::set_notification_work(NOTIFY_POWER_SETTING_CALLBACKS);
        }
        if publish {
            policy_worker::set_notification_work(NOTIFY_SETTING_NOTIFICATIONS);
        }
    }
}

/// PopInitilizeAcDcSettings (PoInitSystem): GUID_ACDC_POWER_SOURCE com AC =
/// PoAc e DC = PoDc.
pub fn initialize_ac_dc_settings() {
    set_value(&GUID_ACDC_POWER_SOURCE, ANY_SESSION, SLOT_AC, &0u32.to_le_bytes());
    set_value(&GUID_ACDC_POWER_SOURCE, ANY_SESSION, SLOT_DC, &1u32.to_le_bytes());
}

/// PopSetPowerSettingValueAcDc(Guid, DataLength, Data): o mesmo valor nos
/// slots AC e DC da configuração de máquina (sessão -1).
pub fn set_value_ac_dc(setting: &[u8; 16], data: &[u8]) {
    set_value(setting, ANY_SESSION, SLOT_AC, data);
    set_value(setting, ANY_SESSION, SLOT_DC, data);
}

/// PopSetSessionDisplayStatus(Session, State): o estado da tela da sessão
/// em GUID_SESSION_DISPLAY_STATUS, AC e DC.
pub fn set_session_display_status(session: u32, state: u32) {
    let data = state.to_le_bytes();
    set_value(&GUID_SESSION_DISPLAY_STATUS, session, SLOT_AC, &data);
    set_value(&GUID_SESSION_DISPLAY_STATUS, session, SLOT_DC, &data);
}

/// O par de PopSetPowerSettingValue do PopSetSessionUserStatus (0x725574 e
/// 0x725596): o USER_ACTIVITY_PRESENCE da sessão em
/// GUID_SESSION_USER_PRESENCE, AC e DC (`po/user_presence.rs`).
pub fn set_session_user_presence(session: u32, status: u32) {
    let data = status.to_le_bytes();
    set_value(&GUID_SESSION_USER_PRESENCE, session, SLOT_AC, &data);
    set_value(&GUID_SESSION_USER_PRESENCE, session, SLOT_DC, &data);
}

/// PopSetNewPolicyValue (0x6f33c0): um valor de política que o serviço Power
/// manda pelo `\PowerPort` (a mensagem 4 do `po/umpo_channel.rs`). Um setting
/// de sessão é ignorado. Fora do subgrupo do processador o valor vai à
/// configuração de máquina no slot pedido (0 AC, 1 DC). No subgrupo do
/// processador o 19041 entrega antes o valor ao perfil do PPM
/// (PpmSetProfilePolicySetting, com STATUS_NOT_FOUND contando como sucesso)
/// e só o perfil nulo, o padrão do umpo, chega também à configuração; o
/// OpenNT não tem os perfis do PPM, que respondem como STATUS_NOT_FOUND. O
/// 19041 indexa a configuração com o slot sem conferir; o OpenNT recusa os
/// slots além do Hot. Devolve o NTSTATUS.
pub fn set_new_policy_value(profile: &[u8; 16], setting: &[u8; 16], subgroup: &[u8; 16], slot: u32, data: &[u8]) -> u32 {
    if is_session_specific(setting) {
        return 0;
    }
    if *subgroup == GUID_PROCESSOR_SETTINGS_SUBGROUP && *profile != [0u8; 16] {
        return 0;
    }
    if slot as usize > SLOT_HOT {
        return STATUS_INVALID_PARAMETER;
    }
    set_value(setting, ANY_SESSION, slot as usize, data);
    0
}

/// PoRegisterPowerSettingCallback(DeviceObject, &SettingGuid, Callback,
/// Context, &Handle). Devolve o NTSTATUS.
pub fn register_callback(device: u64, setting_guid: u64, callback: u64, context: u64, handle_out: u64) -> u32 {
    // SAFETY: LPCGUID do driver (memória do kernel).
    let setting = guid_bytes(unsafe { Guid::at(setting_guid) });
    if is_session_specific(&setting) {
        return STATUS_INVALID_PARAMETER;
    }
    let guard = SETTING_LOCK.acquire_exclusive();
    let handle = guest::alloc_bytes(RegistrationBlock::SIZE);
    if handle == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(handle, &alloc::vec![0u8; RegistrationBlock::SIZE as usize]);
    // SAFETY: o bloco zerado de 0x70 bytes acima.
    let block = unsafe { RegistrationBlock::at(handle) };
    block.tag.set(POWER_SETTING_TAG);
    store_guid(&block.setting, &setting);
    store_guid(&block.callback_setting, &setting);
    block.callback.set(callback);
    block.context.set(context);
    block.device.set(device);
    let mut registration = Registration { handle, setting, callback, context, delivered: None, thread: 0, dispatching: false, remove_on_return: false, removal_waiting: false, unlinked: false };
    {
        let mut settings = SETTINGS.lock();
        match find(&settings.configurations, &setting, ANY_SESSION) {
            Some(index) => {
                let configuration = &mut settings.configurations[index];
                if setting == GUID_IDLE_BACKGROUND_TASK || setting == GUID_BACKGROUND_TASK_NOTIFICATION {
                    registration.delivered = configuration.values[current_power_source()].clone();
                }
                configuration.registrations.push(registration);
            }
            None => settings.unattached.push(registration),
        }
    }
    let notify = notifications_enabled();
    if handle_out != 0 {
        // SAFETY: PVOID* Handle de saída do driver.
        unsafe { Field::<u64>::at(handle_out) }.set(handle);
    }
    drop(guard);
    if notify {
        policy_worker::set_notification_work(NOTIFY_POWER_SETTING_CALLBACKS);
    }
    0
}

/// O PopPowerSettingCallbackReturned, criado no primeiro uso (0 sem memória).
fn callback_returned_event() -> u64 {
    let existing = CALLBACK_RETURNED.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }
    let event = guest::alloc_bytes(Kevent::SIZE);
    if event == 0 {
        return 0;
    }
    // NotificationEvent, não sinalizado.
    crate::ntos::ke::dispatcher::initialize_event(event, 0, false);
    match CALLBACK_RETURNED.compare_exchange(0, event, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => event,
        Err(winner) => {
            guest::free_bytes(event);
            winner
        }
    }
}

/// O fim do bloco de um registro removido: a tag apagada, a entrada
/// apontando para si mesma e a memória devolvida.
fn release_block(handle: u64) {
    // SAFETY: o bloco do registro, alocado no PoRegisterPowerSettingCallback.
    let block = unsafe { RegistrationBlock::at(handle) };
    block.tag.set(0);
    block.link.flink.set(handle);
    block.link.blink.set(handle);
    guest::free_bytes(handle);
}

/// PopUnregisterPowerSettingCallback com o PopSettingLock: com alguém à
/// espera, o registro sai da lista e o PopPowerSettingCallbackReturned é
/// sinalizado (quem espera devolve o bloco); senão o bloco é devolvido.
fn unregister_locked(handle: u64) {
    let waiting = {
        let mut settings = SETTINGS.lock();
        match settings.registration(handle) {
            Some(registration) if registration.removal_waiting => {
                registration.unlinked = true;
                true
            }
            Some(_) => {
                settings.remove(handle);
                false
            }
            None => return,
        }
    };
    if waiting {
        let event = callback_returned_event();
        if event != 0 {
            crate::ntos::ke::dispatcher::set_event(event);
        }
    } else {
        release_block(handle);
    }
}

/// PoUnregisterPowerSettingCallback(Handle). Devolve o NTSTATUS.
pub fn unregister_callback(handle: u64) -> u32 {
    if handle == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut guard = SETTING_LOCK.acquire_exclusive();
    let current = crate::ntos::ps::process::get_current_thread();
    let running = {
        let mut settings = SETTINGS.lock();
        let Some(registration) = settings.registration(handle) else { return STATUS_INVALID_PARAMETER };
        if registration.remove_on_return || registration.removal_waiting || registration.unlinked {
            return STATUS_INVALID_PARAMETER;
        }
        if registration.thread == current {
            // Dentro do próprio callback: a remoção fica para a volta.
            registration.remove_on_return = true;
            return 0;
        }
        if registration.thread != 0 {
            registration.removal_waiting = true;
        }
        registration.thread != 0
    };
    if running {
        let event = callback_returned_event();
        loop {
            let still_running = SETTINGS.lock().registration(handle).is_some_and(|registration| registration.thread != 0);
            if !still_running {
                break;
            }
            drop(guard);
            if event != 0 {
                crate::ntos::ke::dispatcher::wait_for_single_object(event, 0, 0, false);
                crate::ntos::ke::dispatcher::reset_event(event);
            }
            guard = SETTING_LOCK.acquire_exclusive();
        }
        if let Some(registration) = SETTINGS.lock().registration(handle) {
            registration.removal_waiting = false;
        }
    }
    if SETTINGS.lock().remove(handle) {
        release_block(handle);
    }
    drop(guard);
    0
}

/// Chama o callback com uma cópia do valor e confere o IRQL na volta.
fn invoke(handle: u64, callback: u64, context: u64, value: &Value) {
    if callback == 0 {
        return;
    }
    let length = value.data.len() as u64;
    let data = guest::alloc_bytes(length.max(1));
    if data == 0 {
        return;
    }
    guest::write_bytes(data, &value.data);
    // SAFETY: o bloco do registro, vivo enquanto a thread dele chama.
    let block = unsafe { RegistrationBlock::at(handle) };
    let before = crate::ntos::ke::irql::get_irql();
    let _ = native_call::call(callback, &[block.callback_setting.address(), data, length, context]);
    let after = crate::ntos::ke::irql::get_irql();
    guest::free_bytes(data);
    if after != before {
        crate::ntos::ke::bugcheck::bug_check_ex(INTERNAL_POWER_ERROR, CALLBACK_CHANGED_IRQL, callback, before as u64, after as u64);
    }
}

/// PopCallPowerSettingCallback(Registration, Value), com o PopSettingLock:
/// sem valor não faz nada; com o callback já rodando noutra volta, só troca
/// o valor a entregar (quem chama repete). A trava fica solta durante a
/// chamada.
fn call_callback(mut guard: SharedLockGuard<'static>, handle: u64, value: Option<Arc<Value>>) -> SharedLockGuard<'static> {
    let Some(value) = value else { return guard };
    {
        let mut settings = SETTINGS.lock();
        let Some(registration) = settings.registration(handle) else { return guard };
        registration.delivered = Some(value);
        if registration.thread != 0 {
            return guard;
        }
        registration.thread = crate::ntos::ps::process::get_current_thread();
    }
    loop {
        let call = SETTINGS.lock().registration(handle).and_then(|registration| registration.delivered.clone().map(|value| (registration.callback, registration.context, value)));
        let Some((callback, context, value)) = call else { break };
        drop(guard);
        invoke(handle, callback, context, &value);
        guard = SETTING_LOCK.acquire_exclusive();
        let newer = SETTINGS.lock().registration(handle).is_some_and(|registration| registration.delivered.as_ref().is_some_and(|delivered| !Arc::ptr_eq(delivered, &value)));
        if !newer {
            break;
        }
    }
    if let Some(registration) = SETTINGS.lock().registration(handle) {
        registration.thread = 0;
    }
    guard
}

/// O que o PopDispatchPowerSettingCallbacks faz com um registro.
enum Step {
    /// Já em despacho ou fora da lista: o seguinte.
    Skip(Option<u64>),
    /// Entrega o valor (None = o slot da fonte está vazio).
    Deliver(Option<Arc<Value>>),
    /// O último valor entregue já é o corrente.
    Current,
}

/// PopDispatchPowerSettingCallbacks (PopNotifyWork 0x20).
pub fn dispatch_callbacks() {
    let mut guard = SETTING_LOCK.acquire_exclusive();
    let source = current_power_source();
    let ids: Vec<u64> = SETTINGS.lock().configurations.iter().filter(|configuration| list_of(&configuration.guid) == 0).map(|configuration| configuration.id).collect();
    for id in ids {
        let mut cursor = {
            let settings = SETTINGS.lock();
            settings.index_of(id).and_then(|index| settings.configurations[index].registrations.first().map(|registration| registration.handle))
        };
        while let Some(handle) = cursor {
            let step = {
                let mut settings = SETTINGS.lock();
                let Some(index) = settings.index_of(id) else { break };
                let configuration = &mut settings.configurations[index];
                let current = configuration.values[source].clone();
                let Some(position) = configuration.registrations.iter().position(|registration| registration.handle == handle) else { break };
                let following = configuration.registrations.get(position + 1).map(|registration| registration.handle);
                let registration = &mut configuration.registrations[position];
                if registration.dispatching || registration.unlinked {
                    Step::Skip(following)
                } else {
                    registration.dispatching = true;
                    if same_value(&registration.delivered, &current) { Step::Current } else { Step::Deliver(current) }
                }
            };
            match step {
                Step::Skip(following) => {
                    cursor = following;
                    continue;
                }
                Step::Deliver(value) => guard = call_callback(guard, handle, value),
                Step::Current => {}
            }
            let (following, remove) = {
                let mut settings = SETTINGS.lock();
                let Some(index) = settings.index_of(id) else { break };
                let registrations = &mut settings.configurations[index].registrations;
                let Some(position) = registrations.iter().position(|registration| registration.handle == handle) else { break };
                let following = registrations.get(position + 1).map(|registration| registration.handle);
                let registration = &mut registrations[position];
                registration.dispatching = false;
                (following, registration.remove_on_return || registration.removal_waiting)
            };
            if remove {
                unregister_locked(handle);
            }
            cursor = following;
        }
        // Sem callbacks, sem nome WNF e sem valores: a configuração sai.
        let mut settings = SETTINGS.lock();
        if let Some(index) = settings.index_of(id) {
            let configuration = &settings.configurations[index];
            if configuration.registrations.is_empty() && configuration.notification_name == 0 && configuration.values.iter().all(Option::is_none) {
                settings.configurations.remove(index);
            }
        }
    }
    drop(guard);
}

/// ZwUpdateWnfStateData(&Name, Data, Length, NULL, NULL, 0, FALSE) de modo
/// kernel; `data` None = buffer NULL. Devolve o NTSTATUS.
fn publish(name: u64, data: Option<&[u8]>) -> u32 {
    let bytes = data.unwrap_or(&[]);
    let block = guest::alloc_bytes(8 + bytes.len().max(1) as u64);
    if block == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: o bloco de kernel acima, com o WNF_STATE_NAME no começo.
    unsafe { Field::<u64>::at(block) }.set(name);
    guest::write_bytes(block + 8, bytes);
    let buffer = if data.is_some() { block + 8 } else { 0 };
    let status = crate::ntos::ex::wnf::service::update(block, buffer, bytes.len() as u32, 0, 0, 0, false).unwrap_or(STATUS_INSUFFICIENT_RESOURCES);
    guest::free_bytes(block);
    status
}

/// O aviso de configuração nova no nome global, sem dados.
fn publish_set_change() -> u32 {
    let name = SETTING_SET_CHANGE_NAME.load(Ordering::Acquire);
    if name == 0 {
        return 0;
    }
    publish(name, None)
}

/// PopDispatchNotifications (PopNotifyWork 0x80): a lista de máquina e as
/// duas de sessão.
pub fn dispatch_notifications() {
    for list in 0..=SESSION_SPECIFIC_GUIDS.len() {
        dispatch_notifications_to_list(list);
    }
}

/// PopDispatchNotificationsToList.
fn dispatch_notifications_to_list(list: usize) {
    let mut guard = SETTING_LOCK.acquire_exclusive();
    let ids: Vec<u64> = SETTINGS.lock().configurations.iter().filter(|configuration| list_of(&configuration.guid) == list).map(|configuration| configuration.id).collect();
    for id in ids {
        loop {
            let job = {
                let mut settings = SETTINGS.lock();
                let Some(index) = settings.index_of(id) else { break };
                let configuration = &mut settings.configurations[index];
                if configuration.flags & FLAG_PUBLISH_PENDING == 0 || configuration.flags & FLAG_PUBLISHING != 0 {
                    break;
                }
                configuration.flags = (configuration.flags & !FLAG_PUBLISH_PENDING) | FLAG_PUBLISHING;
                // Registros que não cabem no nome vão vazios.
                (configuration.notification_name, marshal(configuration, MAXIMUM_STATE_SIZE).unwrap_or_default())
            };
            drop(guard);
            let status = publish(job.0, Some(&job.1));
            guard = SETTING_LOCK.acquire_exclusive();
            let mut settings = SETTINGS.lock();
            let Some(index) = settings.index_of(id) else { break };
            let configuration = &mut settings.configurations[index];
            configuration.flags &= !FLAG_PUBLISHING;
            if status & 0x8000_0000 != 0 {
                // Fica pendente para o próximo pedido.
                configuration.flags |= FLAG_PUBLISH_PENDING;
                break;
            }
        }
    }
    drop(guard);
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
        let settings = SETTINGS.lock();
        let Some(index) = find(&settings.configurations, &setting, session) else { return Ok(Err(STATUS_NOT_FOUND)) };
        settings.configurations[index].notification_name
    };
    if existing != 0 {
        return Ok(Ok(existing));
    }
    let name = match create_notification_name()? {
        Ok(name) => name,
        Err(status) => return Ok(Err(status)),
    };
    {
        let mut settings = SETTINGS.lock();
        if let Some(index) = find(&settings.configurations, &setting, session) {
            let configuration = &mut settings.configurations[index];
            if setting == GUID_ACDC_POWER_SOURCE {
                configuration.flags |= FLAG_FOLLOWS_POWER_SOURCE;
            }
            configuration.notification_name = name;
            configuration.flags |= FLAG_PUBLISH_PENDING;
        }
    }
    drop(guard);
    // A publicação do valor corrente no nome novo.
    policy_worker::set_notification_work(NOTIFY_SETTING_NOTIFICATIONS);
    Ok(Ok(name))
}

/// PopMarshalSettingValues(Configuration, Buffer, Capacity, &Size): os três
/// registros {ChangeStamp, DataLength, Data} (AC, DC, Hot; um slot vazio é
/// {0, 0} e o Hot vazio repete o DC; com a flag 8, os três são o valor da
/// fonte corrente). STATUS_BUFFER_TOO_SMALL se não cabem em `capacity`.
fn marshal(configuration: &Configuration, capacity: u32) -> Result<Vec<u8>, u32> {
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
    if (capacity as usize) < total {
        return Err(STATUS_BUFFER_TOO_SMALL);
    }
    let mut records = Vec::with_capacity(total);
    for value in &chosen {
        match value {
            Some(value) => {
                records.extend_from_slice(&value.change_stamp.to_le_bytes());
                records.extend_from_slice(&(value.data.len() as u32).to_le_bytes());
                records.extend_from_slice(&value.data);
            }
            None => records.extend_from_slice(&[0u8; 8]),
        }
    }
    Ok(records)
}

/// PopGetSettingValue(Guid, Output, OutputLength): a configuração da sessão
/// do chamador serializada (PopMarshalSettingValues), com o total na
/// frente. STATUS_INVALID_PARAMETER sem configuração; STATUS_BUFFER_TOO_SMALL
/// se os registros não cabem em OutputLength - 4.
pub fn setting_value(setting: &[u8; 16], output_length: u32) -> Result<Vec<u8>, u32> {
    let _guard = SETTING_LOCK.acquire_exclusive();
    let session = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
    let settings = SETTINGS.lock();
    let Some(index) = find(&settings.configurations, setting, session) else { return Err(STATUS_INVALID_PARAMETER) };
    let records = marshal(&settings.configurations[index], output_length.wrapping_sub(4))?;
    let mut output = Vec::with_capacity(4 + records.len());
    output.extend_from_slice(&(records.len() as u32).to_le_bytes());
    output.extend_from_slice(&records);
    Ok(output)
}
