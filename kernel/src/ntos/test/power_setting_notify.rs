//! Autotestes (fase 6) da entrega das mudanças de power setting
//! (`po/power_setting.rs`, `po/policy_worker.rs`), com callbacks de teste
//! que o worker de política chama:
//!
//! - PoRegisterPowerSettingCallback de um GUID ainda sem valor não chama
//!   nada; o primeiro valor (PopSetPowerSettingValueAcDc) chega ao callback
//!   com o GUID, os dados e o contexto;
//! - um registro feito com o valor já gravado recebe o valor corrente (o
//!   callback inicial); um valor igual não chama ninguém; um diferente chama
//!   cada registro uma vez;
//! - PoUnregisterPowerSettingCallback para a entrega e recusa o handle já
//!   removido; o callback que se remove de dentro dele mesmo recebe sucesso
//!   e sai na volta; um setting de sessão é recusado sem handle;
//! - o SessionDisplayState (ZwPowerInformation 42) entrega
//!   GUID_CONSOLE_DISPLAY_STATE aos callbacks (GUID_MONITOR_POWER_ON, que não
//!   muda com a tela esmaecida, não é chamado) e publica os registros do
//!   valor no nome WNF que o NtPowerInformation 58 devolve;
//! - uma configuração nova é avisada no nome global de mudança do conjunto
//!   de settings.
//!
//! Os valores esperados vêm do PopSetPowerSettingValue,
//! PopDispatchPowerSettingCallbacks, PopCallPowerSettingCallback e
//! PopDispatchNotificationsToList do ntoskrnl 19041.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::phase6::call_export;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::{display_state, power_setting};
use crate::rtl::SpinLock;

type Assert = fn(bool, &str);

const STATUS_INVALID_PARAMETER: u64 = 0xFFFF_FFFF_C000_000D;
/// GUIDs só deste teste.
const TEST_SETTING: [u8; 16] = *b"OPNTPWRSETTEST01";
const NEW_SETTING: [u8; 16] = *b"OPNTPWRSETTEST02";

/// As chamadas recebidas: (contexto, GUID, dados).
static CALLS: SpinLock<Vec<(u64, [u8; 16], Vec<u8>)>> = SpinLock::new(Vec::new());
/// A célula com o handle do callback que se remove, e o status que o
/// PoUnregisterPowerSettingCallback lhe devolveu.
static SELF_REMOVING_HANDLE_CELL: AtomicU64 = AtomicU64::new(0);
static SELF_REMOVAL_STATUS: AtomicU64 = AtomicU64::new(u64::MAX);

fn record(setting: u64, value: u64, length: u32, context: u64) {
    let mut guid = [0u8; 16];
    guid.copy_from_slice(&guest::read_bytes(setting, 16));
    let data = guest::read_bytes(value, length as usize);
    CALLS.lock().push((context, guid, data));
}

extern "win64" fn recording_callback(setting: u64, value: u64, length: u32, context: u64) -> u32 {
    record(setting, value, length, context);
    0
}

extern "win64" fn self_removing_callback(setting: u64, value: u64, length: u32, context: u64) -> u32 {
    record(setting, value, length, context);
    let handle = guest::read64(SELF_REMOVING_HANDLE_CELL.load(Ordering::Acquire));
    SELF_REMOVAL_STATUS.store(power_setting::unregister_callback(handle) as u64, Ordering::Release);
    0
}

/// As chamadas de um contexto, na ordem: (GUID, dados).
fn calls_of(context: u64) -> Vec<([u8; 16], Vec<u8>)> {
    CALLS.lock().iter().filter(|call| call.0 == context).map(|call| (call.1, call.2.clone())).collect()
}

/// Os dados da chamada `index` de um contexto, como ULONG.
fn value_of(context: u64, index: usize) -> Option<u32> {
    calls_of(context).get(index).filter(|call| call.1.len() == 4).map(|call| u32::from_le_bytes([call.1[0], call.1[1], call.1[2], call.1[3]]))
}

fn delay(milliseconds: u64) {
    let cell = guest::alloc_bytes(8);
    guest::write64(cell, (-(milliseconds as i64 * 10_000)) as u64);
    let _ = call_export("KeDelayExecutionThread", &[0, 0, cell]);
    guest::free_bytes(cell);
}

/// Espera (até uns 3 s) que `condition` valha.
fn wait_until(mut condition: impl FnMut() -> bool) -> bool {
    for _ in 0..300 {
        if condition() {
            return true;
        }
        crate::ntos::io::work_items::run_queue();
        delay(10);
    }
    condition()
}

/// Tempo para algumas voltas do worker de política (10 ms cada): o que não
/// chegou até aqui não vai chegar.
fn settle() {
    crate::ntos::io::work_items::run_queue();
    delay(80);
}

/// PoRegisterPowerSettingCallback(NULL, &guid, callback, context, &handle)
/// com o GUID e o handle em `block`: (status, handle).
fn register(setting: &[u8; 16], callback: u64, context: u64, block: u64) -> (Option<u64>, u64) {
    guest::write_bytes(block, setting);
    guest::write64(block + 0x10, 0);
    let status = call_export("PoRegisterPowerSettingCallback", &[0, block, callback, context, block + 0x10]);
    (status, guest::read64(block + 0x10))
}

fn unregister(handle: u64) -> Option<u64> {
    call_export("PoUnregisterPowerSettingCallback", &[handle])
}

/// ZwQueryWnfStateData do nome: (ChangeStamp, dados).
fn wnf_state(name: u64, block: u64) -> Option<(u32, Vec<u8>)> {
    let (cell, stamp, length, output) = (block, block + 8, block + 0x10, block + 0x20);
    guest::write64(cell, name);
    guest::write32(stamp, 0);
    guest::write32(length, 0x40);
    match crate::ntos::ex::wnf::service::query(cell, 0, 0, stamp, output, length) {
        Ok(0) => Some((guest::read32(stamp), guest::read_bytes(output, guest::read32(length).min(0x40) as usize))),
        _ => None,
    }
}

/// O valor AC dos registros publicados (o terceiro ULONG do primeiro
/// registro {ChangeStamp, DataLength, Data}).
fn published_ac(data: &[u8]) -> Option<u32> {
    (data.len() == 0x24 && u32::from_le_bytes([data[4], data[5], data[6], data[7]]) == 4).then(|| u32::from_le_bytes([data[8], data[9], data[10], data[11]]))
}

pub fn run(assert: Assert) {
    CALLS.lock().clear();
    let block = guest::alloc_bytes(0x400);
    guest::write_bytes(block, &[0u8; 0x400]);
    let recording = recording_callback as extern "win64" fn(u64, u64, u32, u64) -> u32 as usize as u64;
    let self_removing = self_removing_callback as extern "win64" fn(u64, u64, u32, u64) -> u32 as usize as u64;

    // O registro sem valor espera; o primeiro valor chega a ele.
    let (first_status, first) = register(&TEST_SETTING, recording, 1, block);
    settle();
    let silent = calls_of(1).is_empty();
    power_setting::set_value_ac_dc(&TEST_SETTING, &5u32.to_le_bytes());
    let delivered = wait_until(|| calls_of(1).len() == 1);
    let first_call = calls_of(1).first().cloned();
    assert(
        first_status == Some(0) && first != 0 && guest::read32(first + 0x10) == 0x7465_5350 && silent && delivered && first_call == Some((TEST_SETTING, 5u32.to_le_bytes().to_vec())),
        "power-setting: o primeiro valor chega ao callback registrado antes dele, com o GUID, os dados e o contexto",
    );

    // Callback inicial; valor igual sem chamada; valor novo uma vez a cada um.
    let (second_status, second) = register(&TEST_SETTING, recording, 2, block + 0x40);
    let initial = wait_until(|| calls_of(2).len() == 1) && value_of(2, 0) == Some(5);
    power_setting::set_value_ac_dc(&TEST_SETTING, &5u32.to_le_bytes());
    settle();
    let unchanged = calls_of(1).len() == 1 && calls_of(2).len() == 1;
    power_setting::set_value_ac_dc(&TEST_SETTING, &7u32.to_le_bytes());
    let changed = wait_until(|| calls_of(1).len() == 2 && calls_of(2).len() == 2);
    settle();
    let once = calls_of(1).len() == 2 && calls_of(2).len() == 2 && value_of(1, 1) == Some(7) && value_of(2, 1) == Some(7);
    assert(
        second_status == Some(0) && second != 0 && second != first && initial && unchanged && changed && once,
        "power-setting: o registro recebe o valor corrente, o valor igual nao chama e o novo chama cada callback uma vez",
    );

    // A remoção para a entrega; o setting de sessão é recusado.
    let removed = unregister(second);
    let removed_again = unregister(second);
    power_setting::set_value_ac_dc(&TEST_SETTING, &9u32.to_le_bytes());
    let after_removal = wait_until(|| calls_of(1).len() == 3) && value_of(1, 2) == Some(9);
    settle();
    let stopped = calls_of(2).len() == 2;
    let (session_status, session_handle) = register(&power_setting::GUID_SESSION_DISPLAY_STATUS, recording, 4, block + 0x80);
    assert(
        removed == Some(0) && removed_again == Some(STATUS_INVALID_PARAMETER) && unregister(0) == Some(STATUS_INVALID_PARAMETER) && after_removal && stopped && session_status == Some(STATUS_INVALID_PARAMETER) && session_handle == 0,
        "power-setting: PoUnregisterPowerSettingCallback para a entrega e o setting de sessao e recusado",
    );

    // O callback que se remove de dentro dele mesmo.
    SELF_REMOVING_HANDLE_CELL.store(block + 0xD0, Ordering::Release);
    SELF_REMOVAL_STATUS.store(u64::MAX, Ordering::Release);
    let (third_status, third) = register(&TEST_SETTING, self_removing, 3, block + 0xC0);
    let removed_itself = wait_until(|| calls_of(3).len() == 1 && SELF_REMOVAL_STATUS.load(Ordering::Acquire) == 0) && value_of(3, 0) == Some(9);
    power_setting::set_value_ac_dc(&TEST_SETTING, &11u32.to_le_bytes());
    let others = wait_until(|| calls_of(1).len() == 4);
    settle();
    assert(
        third_status == Some(0) && removed_itself && others && calls_of(3).len() == 1 && unregister(third) == Some(STATUS_INVALID_PARAMETER),
        "power-setting: o callback que se remove de dentro dele sai na volta",
    );

    console_display(assert, recording, block + 0x100);

    // Uma configuração nova avisa o nome global (sem dados).
    let global_status = call_export("ZwPowerInformation", &[58, 0, 0, block + 0x300, 8]).map(|status| status & 0xFFFF_FFFF);
    let global = guest::read64(block + 0x300);
    let before = wnf_state(global, block + 0x340).map_or(0, |state| state.0);
    power_setting::set_value_ac_dc(&NEW_SETTING, &1u32.to_le_bytes());
    let announced = wnf_state(global, block + 0x340).is_some_and(|(stamp, data)| stamp > before && data.is_empty());
    assert(global_status == Some(0) && global != 0 && announced, "power-setting: a configuracao nova e avisada no nome global");

    let _ = unregister(first);
    guest::free_bytes(block);
}

/// O estado da tela do console: GUID_CONSOLE_DISPLAY_STATE e
/// GUID_MONITOR_POWER_ON aos callbacks e ao nome WNF de notificação.
fn console_display(assert: Assert, recording: u64, block: u64) {
    let (console_status, console) = register(&power_setting::GUID_CONSOLE_DISPLAY_STATE, recording, 10, block);
    let (monitor_status, monitor) = register(&power_setting::GUID_MONITOR_POWER_ON, recording, 11, block + 0x20);
    let previous = display_state::console_display_state();
    let initial = wait_until(|| calls_of(10).len() == 1 && calls_of(11).len() == 1) && value_of(10, 0) == Some(previous) && value_of(11, 0) == Some((previous != 0) as u32);
    assert(console_status == Some(0) && monitor_status == Some(0) && previous == 1 && initial, "power-setting: GUID_CONSOLE_DISPLAY_STATE e GUID_MONITOR_POWER_ON entregam o valor corrente no registro");

    // O nome WNF de GUID_CONSOLE_DISPLAY_STATE recebe os registros do valor.
    let (request, name_cell, wnf) = (block + 0x40, block + 0x60, block + 0x80);
    guest::write_bytes(request, &power_setting::GUID_CONSOLE_DISPLAY_STATE);
    guest::write32(request + 0x10, 0xFFFF_FFFF);
    let name_status = call_export("ZwPowerInformation", &[58, request, 0x14, name_cell, 8]).map(|status| status & 0xFFFF_FFFF);
    let name = guest::read64(name_cell);
    let published = wait_until(|| wnf_state(name, wnf).is_some_and(|(_, data)| published_ac(&data) == Some(previous)));
    let stamp = wnf_state(name, wnf).map_or(0, |state| state.0);

    // A tela esmaecida pelo SessionDisplayState do win32k.
    let input = block + 0x100;
    let display = |state: u32| {
        guest::write32(input, 1);
        guest::write32(input + 4, state);
        guest::write32(input + 8, 0);
        guest::write_bytes(input + 0xC, &[1, 1, 0, 0]);
        call_export("ZwPowerInformation", &[42, input, 0x10, 0, 0]).map(|status| status & 0xFFFF_FFFF)
    };
    let dimmed = display(2) == Some(0) && wait_until(|| calls_of(10).len() == 2) && value_of(10, 1) == Some(2);
    let republished = wait_until(|| wnf_state(name, wnf).is_some_and(|(changed, data)| changed > stamp && published_ac(&data) == Some(2)));
    settle();
    let monitor_quiet = calls_of(11).len() == 1;
    let restored = display(previous) == Some(0) && wait_until(|| calls_of(10).len() == 3) && value_of(10, 2) == Some(previous);
    assert(
        name_status == Some(0) && name != 0 && published && dimmed && republished && monitor_quiet && restored,
        "power-setting: o SessionDisplayState entrega GUID_CONSOLE_DISPLAY_STATE e publica o valor no nome WNF",
    );
    let _ = unregister(console);
    let _ = unregister(monitor);
}
