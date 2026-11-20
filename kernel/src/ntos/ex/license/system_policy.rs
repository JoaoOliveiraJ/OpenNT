//! SystemPolicyInformation (NtQuerySystemInformation classe 134): o canal
//! cifrado do slc com o kernel (o SPCall do ntoskrnl 19041).
//!
//! O ExpQuerySystemInformation (rva 0x6cc402) exige exatamente os 0x20
//! bytes do SYSTEM_POLICY_INFORMATION; a captura (rva 0x6c8260) copia o
//! pedido do usuário e chama o despachante (rva 0x5fe2ac, pela pilha
//! expandida de 0x686b10), que:
//!
//! 1. separa o pedido em três blobs `u32 tamanho, bytes` (dados cifrados,
//!    0xA0 bytes de parâmetros de rodada, chave de 8 bytes) e decifra os
//!    dados (`policy_cipher`), conferindo o XOR do claro;
//! 2. lê do claro `u32 contagem, u32 tamanho` e os itens `u32 tamanho,
//!    bytes`: o item 0 é o código da função; os itens 1 e 2, os parâmetros e
//!    a chave com que a resposta é cifrada;
//! 3. chama o tratador do código, que monta os itens da resposta;
//! 4. junta `u32 contagem, u32 tamanho`, os itens e um sal do rdtsc nos
//!    últimos 8 bytes do claro (arredondado a 8), cifra e devolve os três
//!    blobs no mesmo formato do pedido.
//!
//! Os tratadores daqui são os dos chamadores do sistema: o código 0 (o
//! SLGetWindowsInformation do slc, do lsm e do msv1_0: um valor de licença
//! pelo nome, com a verificação de estado genuíno do kernel) e o código 5
//! (o trabalhador da marca d'água do explorer: espera a notificação de cópia
//! não genuína). Os demais códigos respondem como o tratador padrão do 19041
//! (rva 0x962f2c): um item E_NOTIMPL.
//!
//! As respostas vêm só do armazém de licença do convidado (o
//! SLQueryLicenseValueInternal de `service.rs` sobre o ProductPolicy do
//! próprio convidado); nada aqui escolhe ou fixa um estado de licença.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::policy_cipher::{self, Key, Parameters, KEY_SIZE, PARAMETERS_SIZE};
use crate::ntos::inc::field::{Field, NtStruct, Reserved, UnalignedField};
use crate::ntos::inc::types::{Kevent, Kmutant, UnicodeString};
use crate::ntos::ke::{dispatcher, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
use crate::ntos::ps::user_probe::{probe_user_read, probe_user_write};
use crate::rtl::{KernelError, SpinLock};

const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_MEMORY: u32 = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
const STATUS_DATA_ERROR: u32 = 0xC000_003E;
const STATUS_INTEGER_OVERFLOW: u32 = 0xC000_0095;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ALERTED: u32 = 0x101;
const STATUS_TIMEOUT: u32 = 0x102;
const STATUS_USER_APC: u32 = 0xC0;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_UNEXPECTED: u32 = 0x8000_FFFF;
/// O bit que os tratadores ligam no status que vai no primeiro item.
const REPLY_STATUS_BIT: u32 = 0x1000_0000;
/// UserMode: as esperas dos tratadores são do modo do chamador.
const USER_MODE: u8 = 1;
/// O maior tamanho de valor que o código 0 lê de uma vez (0x5fd89b).
const DIRECT_VALUE_LIMIT: u32 = 0x10_0000;
/// REG_DWORD e REG_BINARY nos tipos de valor de licença.
const REG_DWORD: u32 = 4;
const REG_BINARY: u32 = 3;

/// Os nomes de valor de licença lidos pelos tratadores (as UNICODE_STRING
/// do ntoskrnl em 0x98e990, 0xd2d6d0 e 0xd2d6e0).
const GENUINE_LOCAL_STATUS: &str = "Security-SPP-GenuineLocalStatus";
const NOTIFICATION_TYPE: &str = "Kernel-NonGenuineNotificationType";
const NOTIFICATION_STRING_IDS: &str = "Kernel-NonGenuineNotificationStringIds";
/// A chave cuja presença escolhe o tipo de notificação 3 (o
/// OBJECT_ATTRIBUTES em 0xd2d860).
const NOTIFICATION_KEY: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\7503491f-4a39-4f84-b231-8aca3e203b94";
/// WNF_OLIC_OS_LICENSE_NON_GENUINE (o WNF_STATE_NAME em 0xf818).
const WNF_OLIC_OS_LICENSE_NON_GENUINE: u64 = 0x028F_0222_A3BC_6875;
/// Prazos do estado não genuíno, em milissegundos de tempo de boot.
const WNF_DELAY_MS: u64 = 9_000_000;
const MUTEX_DELAY_MS: u64 = 0xA4_CBFB;
const NOTIFY_DELAY_MS: u64 = 0xAD_F4FC;
/// O valor inicial de g_ulOldGenuineStateForWnf (nenhum estado visto).
const UNKNOWN_STATE: u32 = 0xF_423F;
const POOL_TAG: u32 = 0x2053_4C53;

/// SYSTEM_POLICY_INFORMATION: InputData, OutputData, InputDataSize,
/// OutputDataSize e Version (não lido). A captura do 19041 copia os 0x20
/// bytes com dois movups, sem exigir alinhamento de 8 dos ponteiros (o
/// serviço só sonda o buffer com alinhamento 4).
#[repr(C)]
struct SystemPolicyInformation {
    input_data: UnalignedField<u64>,
    output_data: UnalignedField<u64>,
    input_data_size: Field<u32>,
    output_data_size: Field<u32>,
    version: Field<u32>,
    _pad_1c: Reserved<0x4>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for SystemPolicyInformation {}

const _: () = {
    assert!(core::mem::size_of::<SystemPolicyInformation>() == 0x20);
    assert!(core::mem::offset_of!(SystemPolicyInformation, output_data_size) == 0x14);
};

/// O tamanho da classe no ExpQuerySystemInformation.
pub const INFORMATION_SIZE: u32 = 0x20;

/// Um valor do armazém de licença: o status, o tipo e o tamanho que a
/// consulta gravou e os bytes do buffer (do tamanho pedido).
pub struct LicenseValue {
    pub status: u32,
    pub value_type: u32,
    pub result_length: u32,
    pub data: Vec<u8>,
}

impl LicenseValue {
    fn dword(&self) -> u32 {
        self.data.get(..4).map_or(0, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// O que os tratadores leem fora do despachante; os self-tests trocam por
/// valores sintéticos.
pub struct Environment {
    /// O g_kernelCallbacks+0x128 (rva 0x71f3c0): o valor pelo nome no
    /// contexto de licença do silo; `None` é a consulta sem buffer. O tipo e
    /// o tamanho entram com os valores das células do chamador.
    pub query_value: fn(name: &[u16], capacity: Option<u32>, value_type: u32, result_length: u32) -> Result<LicenseValue, KernelError>,
    /// O rdtsc do sal da resposta.
    pub timestamp: fn() -> u64,
    /// O TickCount × KeQueryTimeIncrement / 10000 (milissegundos de boot).
    pub uptime_ms: fn() -> u64,
    /// O ZwUpdateWnfStateData(WNF_OLIC_OS_LICENSE_NON_GENUINE) sem dados.
    pub publish_non_genuine: fn(),
    /// O ZwOpenKey de [`NOTIFICATION_KEY`] com KEY_QUERY_VALUE.
    pub notification_key_present: fn() -> bool,
}

/// O ambiente do sistema: o armazém de licença do convidado.
pub const SYSTEM: Environment = Environment {
    query_value: query_silo_value,
    timestamp: crate::hal::cpu::rdtsc,
    uptime_ms: crate::ntos::ke::clock::uptime_ms,
    publish_non_genuine,
    notification_key_present,
};

/// O estado de cópia genuína que os códigos 0 e 5 dividem (os globais do
/// ntoskrnl em 0xd2d064..0xd2d1f0, o KEVENT de notificação em 0xc13e60 e o
/// KMUTEX em 0xc13e80, iniciados em 0xa5b300).
pub struct GenuineState {
    /// KEVENT de notificação, não sinalizado no início: sinalizado quando o
    /// estado não genuíno passa do prazo, zerado quando volta a genuíno.
    event: u64,
    /// O mutant (sem dono no início) da decisão de sinalizar.
    mutex: u64,
    /// g_ulOldGenuineStateForWnf e g_qwSystemInitTime: o último estado
    /// visto e desde quando.
    wnf_state: AtomicU32,
    wnf_since: AtomicU64,
    /// O código 5 já esperou (g_ulOldGenuineStateForWnf+4).
    waiter: AtomicU32,
    /// g_bWNFEventFired.
    wnf_fired: AtomicU32,
    /// g_ulOldGenuineState e o momento em que o estado mudou (0xd2d158).
    state: AtomicU32,
    state_since: AtomicU64,
    /// O modo de notificação devolvido pelo código 5 (0xd2d064).
    notification: AtomicU32,
}

impl GenuineState {
    pub fn new() -> Result<GenuineState, KernelError> {
        let options = AllocateOptions { zero: true, paged: false, tag: POOL_TAG, ..Default::default() };
        let event = kernel_pool::allocate(Kevent::SIZE, options)?;
        let mutex = kernel_pool::allocate(Kmutant::SIZE, AllocateOptions { zero: true, paged: false, tag: POOL_TAG, ..Default::default() })?;
        dispatcher::initialize_event(event, 0, false);
        dispatcher::initialize_mutant(mutex, false);
        Ok(GenuineState {
            event,
            mutex,
            wnf_state: AtomicU32::new(UNKNOWN_STATE),
            wnf_since: AtomicU64::new(0),
            waiter: AtomicU32::new(0),
            wnf_fired: AtomicU32::new(0),
            state: AtomicU32::new(0),
            state_since: AtomicU64::new(0),
            notification: AtomicU32::new(0),
        })
    }

    /// O KEVENT de notificação (os self-tests o sinalizam).
    pub fn event(&self) -> u64 {
        self.event
    }

    pub fn notification(&self) -> u32 {
        self.notification.load(Ordering::SeqCst)
    }
}

static SYSTEM_STATE: SpinLock<Option<&'static GenuineState>> = SpinLock::new(None);

/// O estado do sistema, criado no primeiro uso.
fn system_state() -> Result<&'static GenuineState, KernelError> {
    let mut slot = SYSTEM_STATE.lock();
    if let Some(state) = *slot {
        return Ok(state);
    }
    let state: &'static GenuineState = alloc::boxed::Box::leak(alloc::boxed::Box::new(GenuineState::new()?));
    *slot = Some(state);
    Ok(state)
}

/// Uma falha do despachante: o NTSTATUS devolvido ou um erro do kernel.
enum Failure {
    Status(u32),
    Kernel(KernelError),
}

impl From<KernelError> for Failure {
    fn from(error: KernelError) -> Failure {
        Failure::Kernel(error)
    }
}

type Outcome<T> = Result<T, Failure>;

fn fail<T>(status: u32) -> Outcome<T> {
    Err(Failure::Status(status))
}

fn checked(value: Option<u32>) -> Outcome<u32> {
    value.ok_or(Failure::Status(STATUS_INTEGER_OVERFLOW))
}

fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Os itens de uma resposta: `contagem`, `tamanho` e os itens `u32
/// tamanho, bytes`, num buffer do tamanho já calculado; um item que não cabe
/// é STATUS_BUFFER_TOO_SMALL.
pub struct ReplyItems {
    count: u32,
    size: u32,
    bytes: Vec<u8>,
}

impl ReplyItems {
    pub fn count(&self) -> u32 {
        self.count
    }

    /// O item `index` já gravado.
    pub fn item(&self, index: usize) -> Option<&[u8]> {
        let mut at = 0usize;
        for current in 0..self.count as usize {
            let length = read_u32(&self.bytes, at) as usize;
            if current == index {
                return self.bytes.get(at + 4..at + 4 + length);
            }
            at += 4 + length;
        }
        None
    }

    fn sized(size: u32) -> Outcome<ReplyItems> {
        if size == 0 {
            return fail(STATUS_DATA_ERROR);
        }
        Ok(ReplyItems { count: 0, size, bytes: Vec::with_capacity(size as usize) })
    }

    fn add(&mut self, data: &[u8]) -> Outcome<()> {
        if self.bytes.len() + 4 + data.len() > self.size as usize {
            return fail(STATUS_BUFFER_TOO_SMALL);
        }
        self.bytes.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(data);
        self.count += 1;
        Ok(())
    }
}

/// Os parâmetros e a chave da resposta (os itens 1 e 2 do pedido).
struct ReplyCipher<'a> {
    parameters: &'a [u8],
    key: &'a [u8],
}

/// O item `index`; contagem curta é STATUS_INVALID_PARAMETER.
fn item<'a>(items: &[&'a [u8]], index: usize) -> Outcome<&'a [u8]> {
    match items.get(index) {
        Some(item) => Ok(item),
        None => fail(STATUS_INVALID_PARAMETER),
    }
}

/// Um item de tamanho fixo; outro tamanho é STATUS_BUFFER_TOO_SMALL.
fn fixed_item<'a>(items: &[&'a [u8]], index: usize, size: usize) -> Outcome<&'a [u8]> {
    let item = item(items, index)?;
    if item.len() != size {
        return fail(STATUS_BUFFER_TOO_SMALL);
    }
    Ok(item)
}

fn dword_item(items: &[&[u8]], index: usize) -> Outcome<u32> {
    Ok(read_u32(fixed_item(items, index, 4)?, 0))
}

/// O item 3 dos códigos 0 e 5: o u64 que volta na resposta.
fn nonce_item(items: &[&[u8]]) -> Outcome<u64> {
    let item = fixed_item(items, 3, 8)?;
    Ok(u64::from_le_bytes([item[0], item[1], item[2], item[3], item[4], item[5], item[6], item[7]]))
}

fn units_of(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// KeWaitForSingleObject(objeto, UserRequest, UserMode, ...).
fn wait_user_request(object: u64, alertable: bool, timeout: Option<u64>) -> u32 {
    dispatcher::wait_for_single_object_reason(object, wait::reason::USER_REQUEST, USER_MODE, alertable, timeout)
}

/// Repete a espera alertável enquanto ela volta STATUS_ALERTED.
fn wait_until_not_alerted(object: u64) -> u32 {
    loop {
        let status = wait_user_request(object, true, None);
        if status != STATUS_ALERTED {
            return status;
        }
    }
}

/// O estado da consulta do Security-SPP-GenuineLocalStatus no código 0:
/// genuíno com um DWORD diferente de zero ou um erro da consulta; não
/// genuíno com o valor zero, outro tipo ou o nome ausente (0x5fdabb).
fn genuine_from(value: &LicenseValue) -> u32 {
    if value.status == STATUS_OBJECT_NAME_NOT_FOUND {
        return 0;
    }
    if value.status & 0x8000_0000 != 0 {
        return 1;
    }
    (value.value_type == REG_DWORD && value.dword() != 0) as u32
}

/// A verificação de estado genuíno do código 0 (0x5fda5c..0x5fdda4). Devolve
/// o último item da resposta: o modo de notificação quando o pedido tem o
/// item 5 diferente de zero e esta chamada sinalizou o evento, senão zero.
fn genuine_check(environment: &Environment, state: &GenuineState, flags: u32) -> Outcome<u32> {
    let now = (environment.uptime_ms)();
    let value = (environment.query_value)(&units_of(GENUINE_LOCAL_STATUS), Some(4), 0, 0)?;
    let genuine = genuine_from(&value);
    if state.wnf_state.load(Ordering::SeqCst) != genuine {
        state.wnf_since.store(now, Ordering::SeqCst);
        state.wnf_state.store(genuine, Ordering::SeqCst);
    }
    let elapsed = now.wrapping_sub(state.wnf_since.load(Ordering::SeqCst));
    if genuine == 0 && state.wnf_fired.load(Ordering::SeqCst) == 0 && elapsed >= WNF_DELAY_MS {
        state.wnf_fired.store(1, Ordering::SeqCst);
        (environment.publish_non_genuine)();
    }
    if elapsed < MUTEX_DELAY_MS {
        return Ok(0);
    }
    // Só uma chamada decide de cada vez: o mutant com prazo zero.
    let acquired = wait_user_request(state.mutex, false, Some(0));
    if acquired & 0x8000_0000 != 0 || acquired == STATUS_USER_APC || acquired == STATUS_TIMEOUT {
        return Ok(0);
    }
    if state.state.load(Ordering::SeqCst) != genuine {
        if genuine != 0 {
            dispatcher::reset_event(state.event);
        } else {
            state.state_since.store((environment.uptime_ms)(), Ordering::SeqCst);
        }
    }
    let since = now.wrapping_sub(state.state_since.load(Ordering::SeqCst));
    state.state.store(genuine, Ordering::SeqCst);
    if genuine != 0 || since < NOTIFY_DELAY_MS || state.waiter.load(Ordering::SeqCst) == 0 {
        dispatcher::release_mutex(state.mutex);
        return Ok(0);
    }
    dispatcher::set_event(state.event);
    let kind = if (environment.notification_key_present)() {
        3
    } else {
        let kind = (environment.query_value)(&units_of(NOTIFICATION_TYPE), Some(4), REG_DWORD, 0)?;
        if kind.status & 0x8000_0000 == 0 && kind.value_type == REG_DWORD && (1..=3).contains(&kind.dword()) { kind.dword() } else { 1 }
    };
    let strings = (environment.query_value)(&units_of(NOTIFICATION_STRING_IDS), Some(0xC), 0, 0)?;
    let listed = (strings.status & 0x8000_0000 == 0 && strings.value_type == REG_BINARY && strings.result_length == 0xC)
        .then(|| (0..3).map(|index| read_u32(&strings.data, index * 4)).find(|entry| entry & 0xF == kind))
        .flatten();
    let mode = listed.unwrap_or((state.notification.load(Ordering::SeqCst) & 0xFFFF_3211) | 0x3211);
    state.notification.store(mode, Ordering::SeqCst);
    if flags == 0 {
        dispatcher::release_mutex(state.mutex);
        return Ok(0);
    }
    // Com o item 5 ligado o 19041 devolve o modo e sai com o mutant ainda
    // possuído pela thread (0x5fdd92).
    Ok(mode)
}

/// Código 0 (rva 0x5fd540): o valor de licença pelo nome. Itens do pedido:
/// 3 (u64 devolvido), 4 (o nome UTF-16 terminado em NUL), 5 (u32 de
/// opções) e 6 (u32 com o tamanho pedido). Resposta: o status da consulta
/// com o bit 28, o u64, o tipo, os dados, o tamanho e o modo de
/// notificação (ou zero).
fn query_license_value(items: &[&[u8]], cipher: &ReplyCipher, output_capacity: u32, environment: &Environment, state: &GenuineState) -> Outcome<ReplyItems> {
    let nonce = nonce_item(items)?;
    let name = item(items, 4)?;
    if name.is_empty() || name.len() % 2 != 0 || name[name.len() - 2..] != [0, 0] {
        return fail(STATUS_DATA_ERROR);
    }
    let units: Vec<u16> = name.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
    // StringCbLengthW: o primeiro NUL tem de ser o final.
    let characters = units.iter().position(|&unit| unit == 0).unwrap_or(units.len());
    if characters * 2 + 2 != name.len() {
        return fail(STATUS_DATA_ERROR);
    }
    let name = &units[..characters];
    let flags = dword_item(items, 5)?;
    let mut length = dword_item(items, 6)?;
    // A consulta (0x5fd891..0x5fd988): direta até 1 MB; sem tamanho ou acima
    // disso, primeiro sem buffer para saber o tamanho.
    let mut status = 0u32;
    let mut value_type = 0u32;
    let mut result_length = 0u32;
    let mut data: Option<Vec<u8>> = None;
    let direct = if length != 0 && length <= DIRECT_VALUE_LIMIT {
        true
    } else {
        let buffered = length != 0;
        let probe = (environment.query_value)(name, None, value_type, result_length)?;
        value_type = probe.value_type;
        result_length = probe.result_length;
        if probe.status == STATUS_BUFFER_TOO_SMALL {
            if length < result_length {
                // Pedido menor que o valor: segue sem dados, com o
                // STATUS_BUFFER_TOO_SMALL quando havia um tamanho pedido.
                status = if length == 0 { 0 } else { probe.status };
                false
            } else {
                length = result_length;
                buffered
            }
        } else if probe.status & 0x8000_0000 != 0 {
            return fail(probe.status);
        } else if result_length != 0 {
            return fail(E_UNEXPECTED);
        } else {
            length = 0;
            false
        }
    };
    if direct {
        let value = (environment.query_value)(name, Some(length), value_type, result_length)?;
        status = value.status;
        value_type = value.value_type;
        result_length = value.result_length;
        if status != STATUS_BUFFER_TOO_SMALL && status & 0x8000_0000 != 0 {
            return fail(status);
        }
        length = length.min(result_length);
        data = Some(value.data);
    }
    // Tamanhos: os itens (0x30 bytes fixos e os dados), o claro arredondado
    // e a resposta inteira, para ver se cabe no buffer de saída.
    let items_size = checked(checked(checked(checked(length.checked_add(4))?.checked_add(0x1C))?.checked_add(8))?.checked_add(8))?;
    let unrounded = checked(items_size.checked_add(8))?;
    let plain_size = checked(unrounded.checked_add(7))? & !7;
    let data_size = checked(plain_size.checked_add(8))?;
    let needed = checked(checked(checked(checked(data_size.checked_add(8))?.checked_add(cipher.parameters.len() as u32))?.checked_add(4))?.checked_add(cipher.key.len() as u32))?;
    let mut last = 0u32;
    if output_capacity >= needed && status & 0x8000_0000 == 0 {
        last = genuine_check(environment, state, flags)?;
    }
    let mut reply = ReplyItems::sized(items_size)?;
    reply.add(&(status | REPLY_STATUS_BIT).to_le_bytes())?;
    reply.add(&nonce.to_le_bytes())?;
    reply.add(&value_type.to_le_bytes())?;
    match &data {
        Some(data) if length != 0 => reply.add(&data[..length as usize])?,
        None if length == 0 => reply.add(&[])?,
        _ => return fail(STATUS_INVALID_PARAMETER),
    }
    reply.add(&result_length.to_le_bytes())?;
    reply.add(&last.to_le_bytes())?;
    Ok(reply)
}

/// Código 5 (rva 0x78cb9c): espera a notificação de cópia não genuína.
/// Com o Security-SPP-GenuineLocalStatus num DWORD diferente de zero (a
/// cópia genuína) o evento volta a não sinalizado; a espera, alertável e de
/// modo usuário, só termina quando o código 0 sinaliza o evento (o estado
/// não genuíno passou do prazo), numa APC de usuário ou num erro. Resposta:
/// o status da espera com o bit 28, o u64 do pedido e o modo de notificação.
fn wait_genuine_state(items: &[&[u8]], cipher: &ReplyCipher, environment: &Environment, state: &GenuineState) -> Outcome<ReplyItems> {
    let nonce = nonce_item(items)?;
    let value = (environment.query_value)(&units_of(GENUINE_LOCAL_STATUS), Some(4), 0, 0)?;
    if value.status != STATUS_OBJECT_NAME_NOT_FOUND {
        if value.status & 0x8000_0000 != 0 {
            return fail(value.status);
        }
        if value.value_type == REG_DWORD && value.dword() != 0 {
            dispatcher::reset_event(state.event);
        }
    }
    state.waiter.store(1, Ordering::SeqCst);
    debug_print!("[sl] SystemPolicyInformation codigo 0x5: esperando a notificacao de copia nao genuina");
    let mut status = wait_until_not_alerted(state.event);
    if status & 0x8000_0000 == 0 && status != STATUS_USER_APC {
        status = wait_until_not_alerted(state.mutex);
        if status & 0x8000_0000 == 0 && status != STATUS_USER_APC && status != STATUS_TIMEOUT {
            dispatcher::release_mutex(state.mutex);
        }
    }
    checked(checked(checked((cipher.parameters.len() as u32).checked_add(0x38))?.checked_add(4))?.checked_add(cipher.key.len() as u32))?;
    let mut reply = ReplyItems::sized(0x1C)?;
    reply.add(&(status | REPLY_STATUS_BIT).to_le_bytes())?;
    reply.add(&nonce.to_le_bytes())?;
    reply.add(&state.notification.load(Ordering::SeqCst).to_le_bytes())?;
    Ok(reply)
}

/// O tratador padrão do 19041 (rva 0x962f2c): um item com E_NOTIMPL.
fn not_implemented() -> Outcome<ReplyItems> {
    let mut reply = ReplyItems::sized(8)?;
    reply.add(&E_NOTIMPL.to_le_bytes())?;
    Ok(reply)
}

/// Os três blobs do pedido (0x5fe350..0x5fe455): tamanhos que não fecham
/// com o pedido são STATUS_DATA_ERROR.
fn split_request(input: &[u8]) -> Outcome<(&[u8], &[u8], &[u8])> {
    let size = input.len();
    let mut at = 0usize;
    let mut blobs = [&input[..0]; 3];
    for blob in blobs.iter_mut() {
        if size - at < 4 {
            return fail(STATUS_DATA_ERROR);
        }
        let length = read_u32(input, at) as usize;
        at += 4;
        if size - at < length {
            return fail(STATUS_DATA_ERROR);
        }
        *blob = &input[at..at + length];
        at += length;
    }
    if at != size {
        return fail(STATUS_DATA_ERROR);
    }
    Ok((blobs[0], blobs[1], blobs[2]))
}

/// Os itens do claro (0x5fed10..0x5ff0fa).
fn parse_plain(plain: &[u8]) -> Outcome<Vec<&[u8]>> {
    let size = plain.len();
    if size < 4 {
        return fail(STATUS_DATA_ERROR);
    }
    let declared = read_u32(plain, 0);
    if size - 4 < 4 {
        return fail(STATUS_DATA_ERROR);
    }
    let length = read_u32(plain, 4) as usize;
    if size - 8 < length || size - 8 - length >= 8 {
        return fail(STATUS_DATA_ERROR);
    }
    let end = 8 + length;
    let mut items = Vec::new();
    let mut at = 8usize;
    while at < end {
        if end - at < 4 {
            return fail(STATUS_INVALID_PARAMETER);
        }
        let item_length = read_u32(plain, at);
        checked(item_length.checked_add(4))?;
        if end - at - 4 < item_length as usize {
            return fail(STATUS_INVALID_PARAMETER);
        }
        items.push(&plain[at + 4..at + 4 + item_length as usize]);
        at += 4 + item_length as usize;
    }
    if declared as usize != items.len() {
        return fail(STATUS_DATA_ERROR);
    }
    if length == 0 || items.is_empty() {
        return fail(STATUS_INVALID_PARAMETER);
    }
    if items[0].len() != 4 {
        return fail(STATUS_BUFFER_TOO_SMALL);
    }
    if items.len() < 3 {
        return fail(STATUS_INVALID_PARAMETER);
    }
    Ok(items)
}

fn dispatch_request(input: &[u8], output_capacity: u32, environment: &Environment, state: &GenuineState) -> Outcome<Vec<u8>> {
    let (data, parameters, key) = split_request(input)?;
    if data.is_empty() || parameters.is_empty() || key.is_empty() {
        return fail(STATUS_DATA_ERROR);
    }
    if key.len() != KEY_SIZE || parameters.len() != PARAMETERS_SIZE || data.len() <= 8 {
        return fail(STATUS_UNSUCCESSFUL);
    }
    let parameters: &Parameters = parameters.try_into().map_err(|_| Failure::Status(STATUS_UNSUCCESSFUL))?;
    let key: &Key = key.try_into().map_err(|_| Failure::Status(STATUS_UNSUCCESSFUL))?;
    let (encrypted, stored) = data.split_at(data.len() - 8);
    let plain = policy_cipher::decrypt_request(encrypted, parameters, key);
    let stored = u64::from_le_bytes([stored[0], stored[1], stored[2], stored[3], stored[4], stored[5], stored[6], stored[7]]);
    if policy_cipher::checksum(&plain) as u64 != stored {
        // O conferidor errado é 0xC004D501 por dentro (0x5fec8f), mas o
        // despachante sai com STATUS_UNSUCCESSFUL (0x5fecdf).
        return fail(STATUS_UNSUCCESSFUL);
    }
    let items = parse_plain(&plain)?;
    let code = read_u32(items[0], 0);
    let reply = handle(&items, output_capacity, environment, state);
    match &reply {
        Ok(reply) => debug_print!("[sl] SystemPolicyInformation codigo {:#x}: {} itens", code, reply.count),
        Err(Failure::Status(status)) => debug_print!("[sl] SystemPolicyInformation codigo {:#x}: {:#x}", code, status),
        Err(Failure::Kernel(_)) => {}
    }
    seal_reply(&reply?, &ReplyCipher { parameters: items[1], key: items[2] }, (environment.timestamp)())
}

/// O switch do código (0x5ff263) sobre os itens já conferidos.
fn handle(items: &[&[u8]], output_capacity: u32, environment: &Environment, state: &GenuineState) -> Outcome<ReplyItems> {
    let cipher = ReplyCipher { parameters: items[1], key: items[2] };
    match read_u32(items[0], 0) {
        0 => query_license_value(items, &cipher, output_capacity, environment, state),
        5 => wait_genuine_state(items, &cipher, environment, state),
        _ => not_implemented(),
    }
}

/// O despachante a partir do claro já decifrado (os itens e o tratador):
/// os itens da resposta, antes do sal e da cifra, ou o NTSTATUS de falha.
pub fn dispatch_plain(plain: &[u8], output_capacity: u32, environment: &Environment, state: &GenuineState) -> Result<Result<ReplyItems, u32>, KernelError> {
    match parse_plain(plain).and_then(|items| handle(&items, output_capacity, environment, state)) {
        Ok(reply) => Ok(Ok(reply)),
        Err(Failure::Status(status)) => Ok(Err(status)),
        Err(Failure::Kernel(error)) => Err(error),
    }
}

/// O claro da resposta (0x5ffd16..0x600617), a cifra com os itens 1 e 2 do
/// pedido e os três blobs de saída (0x600cb3..0x600e7e).
fn seal_reply(reply: &ReplyItems, cipher: &ReplyCipher, salt: u64) -> Outcome<Vec<u8>> {
    let unrounded = checked(8u32.checked_add(reply.size))?;
    let plain_size = checked(unrounded.checked_add(7))? & !7;
    if plain_size == 0 {
        return fail(STATUS_DATA_ERROR);
    }
    let mut plain = alloc::vec![0u8; plain_size as usize];
    plain[0..4].copy_from_slice(&reply.count.to_le_bytes());
    plain[4..8].copy_from_slice(&reply.size.to_le_bytes());
    // O sal primeiro; os itens por cima (só o que sobra dele fica).
    let salt_at = plain_size as usize - 8;
    plain[salt_at..].copy_from_slice(&salt.to_le_bytes());
    plain[8..8 + reply.bytes.len()].copy_from_slice(&reply.bytes);
    if cipher.key.is_empty() || cipher.parameters.is_empty() {
        return fail(STATUS_INVALID_PARAMETER);
    }
    let (Ok(parameters), Ok(key)) = (<&Parameters>::try_from(cipher.parameters), <&Key>::try_from(cipher.key)) else { return fail(STATUS_UNSUCCESSFUL) };
    let mut data = policy_cipher::encrypt_reply(&plain, parameters, key);
    data.extend_from_slice(&(policy_cipher::checksum(&plain) as u64).to_le_bytes());
    let total = checked(checked(checked(checked(checked(4u32.checked_add(data.len() as u32))?.checked_add(4))?.checked_add(PARAMETERS_SIZE as u32))?.checked_add(4))?.checked_add(KEY_SIZE as u32))?;
    let mut output = Vec::with_capacity(total as usize);
    for blob in [&data[..], &parameters[..], &key[..]] {
        output.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        output.extend_from_slice(blob);
    }
    Ok(output)
}

/// O despachante sobre um pedido já capturado: a resposta ou o NTSTATUS de
/// falha. `output_capacity` é o OutputDataSize (zero sem OutputData).
pub fn dispatch(input: &[u8], output_capacity: u32, environment: &Environment, state: &GenuineState) -> Result<Result<Vec<u8>, u32>, KernelError> {
    match dispatch_request(input, output_capacity, environment, state) {
        Ok(reply) => Ok(Ok(reply)),
        Err(Failure::Status(status)) => Ok(Err(status)),
        Err(Failure::Kernel(error)) => Err(error),
    }
}

fn is_fault(error: &KernelError) -> bool {
    matches!(error.status, STATUS_ACCESS_VIOLATION | STATUS_DATATYPE_MISALIGNMENT)
}

/// A captura da classe 134 (rva 0x6c8260), depois da regra de tamanho: o
/// SYSTEM_POLICY_INFORMATION e o InputData sondados na faixa de usuário (as
/// faltas viram o status da exceção), o pedido copiado, o despachante e a
/// resposta no OutputData, com o tamanho em OutputDataSize (também sem
/// OutputData).
pub fn query(information: u64) -> Result<u32, KernelError> {
    match capture_and_dispatch(information, &SYSTEM) {
        Err(error) if is_fault(&error) => Ok(error.status),
        other => other,
    }
}

fn capture_and_dispatch(information: u64, environment: &Environment) -> Result<u32, KernelError> {
    if information == 0 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    if !probe_user_read(information, INFORMATION_SIZE as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    // SAFETY: a faixa de 0x20 bytes foi sondada; os acessos são sondados de novo.
    let spi = unsafe { SystemPolicyInformation::at(information) };
    let input_data = spi.input_data.probe_get()?;
    let output_data = spi.output_data.probe_get()?;
    let input_size = spi.input_data_size.probe_get()?;
    let output_size = spi.output_data_size.probe_get()?;
    let _ = spi.version.probe_get()?;
    if input_size != 0 && !probe_user_read(input_data, input_size as u64) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if input_data == 0 || input_size == 0 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    let input = guest::try_read_bytes(input_data, input_size as usize)?;
    let capacity = if output_data != 0 { output_size } else { 0 };
    let reply = match dispatch(&input, capacity, environment, system_state()?)? {
        Ok(reply) => reply,
        Err(status) => return Ok(status),
    };
    if output_data != 0 {
        if output_size < reply.len() as u32 {
            return Ok(STATUS_BUFFER_TOO_SMALL);
        }
        if !probe_user_write(output_data, reply.len() as u64) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        guest::try_write_bytes(output_data, &reply)?;
    }
    spi.output_data_size.probe_set(reply.len() as u32)?;
    Ok(0)
}

/// [`Environment::query_value`] do sistema: a UNICODE_STRING, as células e
/// o buffer em memória do kernel, pelo contexto de licença do silo.
fn query_silo_value(name: &[u16], capacity: Option<u32>, value_type: u32, result_length: u32) -> Result<LicenseValue, KernelError> {
    let text_bytes = name.len() as u64 * 2;
    let frame = guest::alloc_bytes(UnicodeString::SIZE + text_bytes + 2 + 4 + 8);
    let size = capacity.unwrap_or(0);
    let buffer = if size != 0 { guest::alloc_bytes(size as u64) } else { 0 };
    if frame == 0 || (size != 0 && buffer == 0) {
        guest::free_bytes(frame);
        guest::free_bytes(buffer);
        return Ok(LicenseValue { status: STATUS_NO_MEMORY, value_type, result_length, data: alloc::vec![0; size as usize] });
    }
    let text = frame + UnicodeString::SIZE;
    let bytes: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).chain([0, 0]).collect();
    guest::write_bytes(text, &bytes);
    // SAFETY: moldura nova, alinhada a 16.
    let string = unsafe { UnicodeString::at(frame) };
    string.length.set(text_bytes as u16);
    string.maximum_length.set(text_bytes as u16 + 2);
    string.buffer.set(text);
    let cells = (text + text_bytes + 2 + 3) & !3;
    // SAFETY: as duas células de u32 da moldura.
    let (type_cell, result_cell) = unsafe { (Field::<u32>::at(cells), Field::<u32>::at(cells + 4)) };
    type_cell.set(value_type);
    result_cell.set(result_length);
    let status = super::values::query_silo(frame, cells, buffer, size, cells + 4);
    let value = LicenseValue { status: *status.as_ref().unwrap_or(&0), value_type: type_cell.get(), result_length: result_cell.get(), data: if size != 0 { guest::read_bytes(buffer, size as usize) } else { Vec::new() } };
    guest::free_bytes(frame);
    guest::free_bytes(buffer);
    status.map(|_| value)
}

/// O ZwUpdateWnfStateData(&WNF_OLIC_OS_LICENSE_NON_GENUINE, NULL, 0, NULL,
/// NULL, 0, 0) do código 0; o status não é conferido.
fn publish_non_genuine() {
    let name = guest::alloc_bytes(8);
    if name == 0 {
        return;
    }
    // SAFETY: célula nova de 8 bytes.
    unsafe { Field::<u64>::at(name) }.set(WNF_OLIC_OS_LICENSE_NON_GENUINE);
    let _ = crate::ntos::ex::wnf::service::update(name, 0, 0, 0, 0, 0, false);
    guest::free_bytes(name);
}

/// O ZwOpenKey(KEY_QUERY_VALUE, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE) de
/// [`NOTIFICATION_KEY`], fechado em seguida.
fn notification_key_present() -> bool {
    use crate::ntos::cm::registry;
    match registry::open(NOTIFICATION_KEY) {
        Ok(handle) if handle != 0 => {
            registry::close_handle(handle);
            true
        }
        _ => false,
    }
}
