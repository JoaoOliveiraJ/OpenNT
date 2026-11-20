//! O estado da tela do console e das sessões (ntoskrnl 19041).
//!
//! - PopConsoleDisplayState (MONITOR_DISPLAY_STATE: 0 PowerMonitorOff, 1
//!   PowerMonitorOn, 2 PowerMonitorDim) começa no zero do .data sem
//!   inicializador do ntoskrnl e só o PopUpdateConsoleDisplayState o grava.
//!   A fase 3 do PoInitSystem (0xa3f82f), logo depois do
//!   PopInitilizeAcDcSettings, liga a tela (PowerMonitorOn) e publica o
//!   mesmo estado em WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE ([`initialize`]).
//!   O SystemVideoState (NtPowerInformation 29) o devolve.
//! - SessionDisplayState (NtPowerInformation 42, 0x6f0fb9, só de modo
//!   kernel) é o aviso que o UpdateDisplayState do win32kbase manda a cada
//!   mudança da tela de uma sessão: a entrada de exatamente 0x10 bytes
//!   {SessionId, DisplayState, Reason, BOOLEAN[4]} e nenhuma saída
//!   (`po/power_information.rs` confere). Com os BOOLEANs de +0xD e +0xC, o
//!   PopSetDisplayStatus (GUID_SESSION_DISPLAY_STATUS da sessão de quem
//!   chama, AC e DC) e o PopUpdateConsoleDisplayState com o DisplayState;
//!   com os de +0xE e +0xC, o DisplayState em
//!   WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE. O SessionId e o Reason só entram
//!   nos rastros ETW do 19041.
//! - PopUpdateConsoleDisplayState (0x781304): um estado igual ao corrente não
//!   muda nada. Um estado novo é guardado, vai a GUID_CONSOLE_DISPLAY_STATE e,
//!   como BOOL "monitor ligado" (estado diferente de PowerMonitorOff), a
//!   GUID_MONITOR_POWER_ON (PopSetPowerSettingValueAcDc: AC e DC da
//!   configuração de máquina) e a WNF_UBPM_CONSOLE_MONITOR. Cada mudança sai
//!   na serial (`[po] tela do console: …`).
//!
//! O OpenNT não é uma plataforma AoAc (o PopPlatformAoAc é FALSE) e não tem o
//! agregador de energia (o PopPowerAggregatorNotifyDisplayPoweredOn de um
//! estado PowerMonitorOn), os rastros ETW, os cenários de resiliência, a
//! estimativa de bateria nem a política de ociosidade que o 19041 também
//! avisa.

use core::sync::atomic::{AtomicU32, Ordering};

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::power_setting;
use crate::rtl::KernelError;

/// WNF_UBPM_CONSOLE_MONITOR e WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE do
/// ntoskrnl 19041 (nomes bem conhecidos, definidos em
/// `Control\Notifications`).
pub const WNF_UBPM_CONSOLE_MONITOR: u64 = 0x0C96_0C38_A3BC_1075;
pub const WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE: u64 = 0x41C6_013D_A3BC_A075;

/// O comprimento da entrada do SessionDisplayState.
pub const SESSION_DISPLAY_STATE_INPUT: usize = 0x10;
/// O comprimento da entrada do PowerInternalSessionPowerState
/// (NtPowerInformation 87, tipo interno 0x13).
pub const SESSION_POWER_STATE_INPUT: usize = 0x14;

/// PopConsoleDisplayState.
static CONSOLE_DISPLAY_STATE: AtomicU32 = AtomicU32::new(0);

/// O PopConsoleDisplayState corrente (o que o SystemVideoState devolve).
pub fn console_display_state() -> u32 {
    CONSOLE_DISPLAY_STATE.load(Ordering::Acquire)
}

/// ZwUpdateWnfStateData(Name, &Value, 4, NULL, NULL, 0, FALSE); o status é
/// ignorado, como no 19041.
fn publish(name: u64, value: u32) -> Result<(), KernelError> {
    let block = guest::alloc_bytes(16);
    if block == 0 {
        return Ok(());
    }
    guest::write64(block, name);
    guest::write32(block + 8, value);
    let result = crate::ntos::ex::wnf::service::update(block, block + 8, 4, 0, 0, 0, false);
    guest::free_bytes(block);
    result.map(|_| ())
}

/// PopUpdateConsoleDisplayState(State).
fn update_console_display_state(state: u32) -> Result<(), KernelError> {
    if CONSOLE_DISPLAY_STATE.swap(state, Ordering::AcqRel) == state {
        return Ok(());
    }
    // Só diagnóstico: no QEMU a tela desligada pelo BasicDisplay (VBE 4F10h)
    // continua mostrando o último quadro, então a mudança sai na serial.
    crate::debug_print!(
        "[po] tela do console: {}",
        match state {
            0 => "desligada",
            2 => "esmaecida",
            _ => "ligada",
        }
    );
    power_setting::set_value_ac_dc(&power_setting::GUID_CONSOLE_DISPLAY_STATE, &state.to_le_bytes());
    let monitor_on = (state != 0) as u32;
    power_setting::set_value_ac_dc(&power_setting::GUID_MONITOR_POWER_ON, &monitor_on.to_le_bytes());
    publish(WNF_UBPM_CONSOLE_MONITOR, monitor_on)
}

/// MONITOR_DISPLAY_STATE PowerMonitorOn.
const POWER_MONITOR_ON: u32 = 1;

/// A tela do console no PoInitSystem: PopUpdateConsoleDisplayState
/// (PowerMonitorOn) e o mesmo estado em WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE.
/// No OpenNT o serviço WNF nasce no primeiro uso, e os autotestes da fase 5
/// criam e descartam o namespace deles antes disso; sem o serviço ainda de
/// pé, o boot grava o estado e os valores de energia sem publicar: a
/// WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE sai no primeiro SessionDisplayState
/// do win32kbase e a WNF_UBPM_CONSOLE_MONITOR na próxima mudança da tela.
pub fn initialize() -> Result<(), KernelError> {
    if !crate::ntos::ex::wnf::service::exists() {
        CONSOLE_DISPLAY_STATE.store(POWER_MONITOR_ON, Ordering::Release);
        power_setting::set_value_ac_dc(&power_setting::GUID_CONSOLE_DISPLAY_STATE, &POWER_MONITOR_ON.to_le_bytes());
        power_setting::set_value_ac_dc(&power_setting::GUID_MONITOR_POWER_ON, &1u32.to_le_bytes());
        return Ok(());
    }
    update_console_display_state(POWER_MONITOR_ON)?;
    publish(WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE, POWER_MONITOR_ON)
}

/// SessionDisplayState sobre a entrada capturada de
/// [`SESSION_DISPLAY_STATE_INPUT`] bytes.
pub fn session_display_state(input: &[u8]) -> Result<(), KernelError> {
    let state = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    let flag = |offset: usize| input[offset] != 0;
    if flag(0xD) && flag(0xC) {
        // PopSetDisplayStatus: a sessão do processo corrente.
        let session = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
        power_setting::set_session_display_status(session, state);
        update_console_display_state(state)?;
    }
    if flag(0xE) && flag(0xC) {
        publish(WNF_PO_PRIMARY_DISPLAY_VISIBLE_STATE, state)?;
    }
    Ok(())
}

/// PowerInternalSessionPowerState (PopPowerInformationInternal 0x81ce97, só
/// de modo kernel: o UpdateSessionPowerState do win32kbase) sobre a entrada
/// capturada de [`SESSION_POWER_STATE_INPUT`] bytes {POWER_INFORMATION_INTERNAL_HEADER,
/// SessionId, BOOLEAN On, BOOLEAN Console, Reason}. O
/// TtmNotifySessionPowerStateChange não acha sessão com o TTM desligado (só
/// registra o erro). Com Console, sob o PopPolicyLock, o PopSetDisplayStatus
/// (GUID_SESSION_DISPLAY_STATUS da sessão de quem chama) e o
/// PopUpdateConsoleDisplayState com On (1 PowerMonitorOn, 0 PowerMonitorOff);
/// o SessionId e o Reason só entram no rastro ETW
/// (PopDiagTraceSessionDisplayStateChange).
pub fn session_power_state(input: &[u8]) -> Result<(), KernelError> {
    let on = (input[0xC] != 0) as u32;
    if input[0xD] != 0 {
        let session = crate::ntos::mm::session::session_id_ex(crate::ntos::ps::process::get_current_process());
        power_setting::set_session_display_status(session, on);
        update_console_display_state(on)?;
    }
    Ok(())
}
