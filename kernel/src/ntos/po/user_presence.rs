//! Presença do usuário (ntoskrnl 19041): o estado adaptativo do Po por
//! sessão (PopConsoleContext e PopConnectionBitmap, sob o PopAdpmLock) que o
//! win32kbase alimenta pelos níveis 61 e 62 do NtPowerInformation e que o Po
//! publica em GUID_SESSION_USER_PRESENCE (da sessão) e
//! GUID_GLOBAL_USER_PRESENCE (da máquina).
//!
//! - SessionConnectNotification (nível 62, só de modo kernel, 0x6f1108):
//!   o PowerConnectionEvent do win32kbase (o SetConnectCompletedState do
//!   xxxRemoteConnect) manda {BOOLEAN Connected, BOOLEAN Console} e recebe
//!   {InputTimeout, DisplayTimeout} em segundos, que viram o
//!   giPowerSessionActivityTimeOutMs e o giPowerOffTimeOutMs. O
//!   PopSessionConnectionChange (0x78d74c) chama o PopSessionConnected
//!   (0x78d7f0: GUID_SESSION_DISPLAY_STATUS da sessão ligado; a sessão do
//!   console vira a do PopConsoleContext e recebe a entrada ativa com o
//!   tick em ms; uma sessão remota recebe a entrada ativa remota) ou o
//!   PopSessionDisconnected (0x7798f8: o PopConsoleContext da sessão do
//!   console volta ao inicial, a tela da sessão desligada, a sessão
//!   PowerUserInactive, a saída zero). O PoPdcCallbacks+0x28 que o 19041
//!   chama depois é do pdc.sys, que o OpenNT não tem: fica NULL.
//! - SessionRITState (nível 61, só de modo kernel, 0x6f0ee4): o
//!   PowerInputEvent do win32kbase manda {BOOLEAN Active, ULONG
//!   LastInputTime} quando a sessão fica passiva (a tela desligada pelo
//!   UpdateDisplayState ou pelo UpdateSessionPowerState) e quando a primeira
//!   entrada depois disso a reativa (o evento 8 que o EditionKeepMachineUp
//!   do win32kfull pede). O PopSessionInputChange (0x724fb4): ativa =
//!   PowerUserPresent, passiva = PowerUserInactive, e a saída como no 62.
//! - PopSetSessionUserStatus (0x725504): o estado da sessão do console no
//!   PopConsoleContext+0x20, GUID_SESSION_USER_PRESENCE da sessão (AC e DC),
//!   o bit da sessão no PopConnectionBitmap (ligado = PowerUserPresent) e o
//!   PopEvaluateGlobalUserStatus (0x7255e8): PowerUserPresent com algum bit
//!   ligado (ou com override), senão PowerUserInactive; um estado novo (o
//!   PopGlobalUserPresenceState começa em 3, inválido) conta uma transição e
//!   vai a GUID_GLOBAL_USER_PRESENCE (AC e DC) e a
//!   WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED ({NotPresent, transições}). A
//!   mensagem 0xC do 19041 ao umpo fica de fora: o OpenNT não manda
//!   mensagens ao umpo, e o umpo só a usa com o UmpoSmartPresenceEnabled de
//!   uma plataforma AoAc.
//!
//! Os timeouts (PopInputTimeout, PopDisplayTimeout e o timeout da tela de
//! bloqueio do PopGetLockConsoleTimeout) só são gravados pelo
//! PopAdaptivePowerSettingCallback, um callback interno do Po que o OpenNT
//! não registra: ficam zero, a saída dos níveis 61 e 62 é {0, 0} e o win32k
//! não conta inatividade. O PoSetUserPresent do win32kfull é outro caminho
//! (o motivo de ligar a tela, `po/system_state.rs`). O nível 57
//! (PopUserPresentOverride) só vale numa edição Embedded e o 64
//! (SessionLockState) não é atendido.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::power_setting;
use crate::rtl::{SharedLock, SpinLock};

/// USER_ACTIVITY_PRESENCE.
pub const POWER_USER_PRESENT: u32 = 0;
pub const POWER_USER_NOT_PRESENT: u32 = 1;
pub const POWER_USER_INACTIVE: u32 = 2;
/// PowerUserMaximum: o valor inicial do PopGlobalUserPresenceState (.data,
/// 0xc0f1f4) e do PopConsoleContext+0x20.
pub const POWER_USER_INVALID: u32 = 3;

/// WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED (nome bem conhecido em
/// `Control\Notifications`).
pub const WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED: u64 = 0x41C6_013D_A3BC_8875;

/// Os comprimentos de entrada do SessionRITState e do
/// SessionConnectNotification (a saída dos dois tem 8 bytes).
pub const SESSION_RIT_STATE_INPUT: usize = 8;
pub const SESSION_CONNECT_INPUT: usize = 2;

/// A sessão de quem não tem sessão.
const NO_SESSION: u32 = u32::MAX;
/// GUID_SESSION_DISPLAY_STATUS da conexão e da desconexão.
const DISPLAY_OFF: u32 = 0;
const DISPLAY_ON: u32 = 1;

/// PopPrintUserActivityPresence (0x725718).
pub fn presence_name(status: u32) -> &'static str {
    match status {
        POWER_USER_PRESENT => "PowerUserPresent",
        POWER_USER_NOT_PRESENT => "PowerUserNotPresent",
        POWER_USER_INACTIVE => "PowerUserInactive",
        _ => "Invalid",
    }
}

/// PopConsoleContext (0xc20580): o contexto adaptativo da sessão do console.
/// Os registros {timeout, computed, zeroed} do 19041 ficam só com o
/// timeout de tela, o único que volta numa saída (a entrada passiva).
#[derive(Clone, Copy)]
struct ConsoleContext {
    /// +0x0: a sessão do console (-1 sem console).
    session: u32,
    /// +0xc: o timeout de tela do último PopUpdateTimeouts.
    display_timeout: u32,
    /// +0x18: o instante da última entrada que o win32k informou (ms).
    last_input: u32,
    /// +0x20: o USER_ACTIVITY_PRESENCE da sessão do console.
    user_status: u32,
    /// +0x24: o timeout de entrada vale (entrada ativa com PopInputTimeout).
    input_timeout_active: bool,
}

/// O PopConsoleContext do PopInitializeAdpm e do PopSessionDisconnected.
const CONSOLE_IDLE: ConsoleContext = ConsoleContext { session: NO_SESSION, display_timeout: 0, last_input: 0, user_status: POWER_USER_INVALID, input_timeout_active: false };

/// O que uma mudança grava, em ordem, depois do cálculo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// PopSetSessionDisplayStatus: GUID_SESSION_DISPLAY_STATUS da sessão.
    SessionDisplayStatus { session: u32, status: u32 },
    /// GUID_SESSION_USER_PRESENCE da sessão (o PopSetSessionUserStatus).
    SessionUserPresence { session: u32, status: u32 },
    /// Um PopGlobalUserPresenceState novo: GUID_GLOBAL_USER_PRESENCE e
    /// WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED.
    GlobalUserPresence { state: u32, transitions: u32 },
}

/// O estado adaptativo do Po (o do PopInitializeAdpm em [`AdaptiveState::new`]).
pub struct AdaptiveState {
    console: ConsoleContext,
    /// PopConnectionBitmap: as sessões com PowerUserPresent.
    present: BTreeSet<u32>,
    /// PopGlobalUserPresenceState.
    global: u32,
    /// PopGlobalUserPresenceStateTransitions.
    transitions: u32,
    /// PopUserPresentOverrideCount (só o nível 57 de uma edição Embedded).
    override_count: u32,
    /// PopInputTimeout e PopDisplayTimeout, em segundos (só o
    /// PopAdaptivePowerSettingCallback os grava).
    input_timeout: u32,
    display_timeout: u32,
}

impl AdaptiveState {
    pub const fn new() -> Self {
        Self::with_timeouts(0, 0)
    }

    /// O estado inicial com os timeouts que o PopAdaptivePowerSettingCallback
    /// teria gravado.
    pub const fn with_timeouts(input_timeout: u32, display_timeout: u32) -> Self {
        Self { console: CONSOLE_IDLE, present: BTreeSet::new(), global: POWER_USER_INVALID, transitions: 0, override_count: 0, input_timeout, display_timeout }
    }

    pub fn console_session(&self) -> u32 {
        self.console.session
    }

    pub fn console_user_status(&self) -> u32 {
        self.console.user_status
    }

    /// (PopConsoleContext+0x18, +0x24).
    pub fn console_input(&self) -> (u32, bool) {
        (self.console.last_input, self.console.input_timeout_active)
    }

    pub fn global_state(&self) -> u32 {
        self.global
    }

    pub fn is_present(&self, session: u32) -> bool {
        self.present.contains(&session)
    }

    fn is_console(&self, session: u32) -> bool {
        self.console.session == session && session != NO_SESSION
    }

    /// PopSetSessionUserStatus (0x725504).
    fn set_session_user_status(&mut self, session: u32, status: u32, effects: &mut Vec<Effect>) {
        if self.is_console(session) {
            self.console.user_status = status;
        }
        effects.push(Effect::SessionUserPresence { session, status });
        if status == POWER_USER_PRESENT {
            self.present.insert(session);
        } else {
            self.present.remove(&session);
        }
        self.evaluate_global_user_status(effects);
    }

    /// PopEvaluateGlobalUserStatus (0x7255e8).
    fn evaluate_global_user_status(&mut self, effects: &mut Vec<Effect>) {
        let state = if self.override_count != 0 || !self.present.is_empty() { POWER_USER_PRESENT } else { POWER_USER_INACTIVE };
        if state == self.global {
            return;
        }
        self.transitions = self.transitions.wrapping_add(1);
        self.global = state;
        effects.push(Effect::GlobalUserPresence { state, transitions: self.transitions });
    }

    /// PopGetDisplayTimeout (0x772aa4): zero fora do console; no console, o
    /// timeout da tela de bloqueio (zero sem o SessionLockState) ou o
    /// PopDisplayTimeout.
    fn display_timeout_of(&self, session: u32) -> u32 {
        if self.is_console(session) { self.display_timeout } else { 0 }
    }

    /// PopRemoteSessionActiveInput (0x772a68).
    fn remote_active_input(&mut self, session: u32, effects: &mut Vec<Effect>) -> [u32; 2] {
        self.set_session_user_status(session, POWER_USER_PRESENT, effects);
        [self.input_timeout, self.display_timeout_of(session)]
    }

    /// PopConsoleSessionActiveInput (0x7729f4); o PopUpdateTimeouts guarda o
    /// timeout de tela no contexto.
    fn console_active_input(&mut self, session: u32, time: u32, effects: &mut Vec<Effect>) -> [u32; 2] {
        let timeouts = self.remote_active_input(session, effects);
        self.console.input_timeout_active = timeouts[0] != 0;
        self.console.last_input = time;
        self.console.display_timeout = timeouts[1];
        timeouts
    }

    /// PopConsoleSessionPassiveInput (0x724f38).
    fn console_passive_input(&mut self, session: u32, time: u32, effects: &mut Vec<Effect>) -> [u32; 2] {
        self.console.input_timeout_active = false;
        self.console.last_input = time;
        self.set_session_user_status(session, POWER_USER_INACTIVE, effects);
        [0, self.console.display_timeout]
    }

    /// PopSessionInputChange (0x724fb4): o SessionRITState da sessão.
    pub fn session_input_change(&mut self, session: u32, active: bool, time: u32, effects: &mut Vec<Effect>) -> [u32; 2] {
        match (active, self.is_console(session)) {
            (true, true) => self.console_active_input(session, time, effects),
            (true, false) => self.remote_active_input(session, effects),
            (false, true) => self.console_passive_input(session, time, effects),
            (false, false) => {
                self.set_session_user_status(session, POWER_USER_INACTIVE, effects);
                [self.input_timeout, self.display_timeout_of(session)]
            }
        }
    }

    /// PopSessionConnectionChange (0x78d74c): o SessionConnectNotification
    /// da sessão; `time` é o tick em ms da conexão do console.
    pub fn session_connection_change(&mut self, session: u32, connected: bool, console: bool, time: u32, effects: &mut Vec<Effect>) -> [u32; 2] {
        if !connected {
            if self.is_console(session) {
                self.console = CONSOLE_IDLE;
            }
            effects.push(Effect::SessionDisplayStatus { session, status: DISPLAY_OFF });
            self.set_session_user_status(session, POWER_USER_INACTIVE, effects);
            return [0, 0];
        }
        effects.push(Effect::SessionDisplayStatus { session, status: DISPLAY_ON });
        if console {
            self.console.session = session;
            self.console_active_input(session, time, effects)
        } else {
            self.remote_active_input(session, effects)
        }
    }
}

/// PopAdpmLock: serializa as mudanças e a gravação delas (o 19041 grava os
/// settings com ele tomado, antes do PopSettingLock).
static ADPM_LOCK: SharedLock = SharedLock::new();
static STATE: SpinLock<AdaptiveState> = SpinLock::new(AdaptiveState::new());

/// ZwUpdateWnfStateData(WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED,
/// {NotPresent, transições}, 8); o status é ignorado, como no 19041.
fn publish_sleep_study(state: u32, transitions: u32) {
    let block = guest::alloc_bytes(16);
    if block == 0 {
        return;
    }
    guest::write64(block, WNF_PO_SLEEP_STUDY_USER_PRESENCE_CHANGED);
    guest::write32(block + 8, (state != POWER_USER_PRESENT) as u32);
    guest::write32(block + 12, transitions);
    let _ = crate::ntos::ex::wnf::service::update(block, block + 8, 8, 0, 0, 0, false);
    guest::free_bytes(block);
}

fn apply(effects: &[Effect]) {
    for effect in effects {
        match *effect {
            Effect::SessionDisplayStatus { session, status } => power_setting::set_session_display_status(session, status),
            Effect::SessionUserPresence { session, status } => {
                crate::debug_print!("[po] presenca do usuario da sessao {}: {}", session, presence_name(status));
                power_setting::set_session_user_presence(session, status);
            }
            Effect::GlobalUserPresence { state, transitions } => {
                crate::debug_print!("[po] presenca global do usuario: {} (transicao {})", presence_name(state), transitions);
                power_setting::set_value_ac_dc(&power_setting::GUID_GLOBAL_USER_PRESENCE, &state.to_le_bytes());
                publish_sleep_study(state, transitions);
            }
        }
    }
}

/// Uma mudança sob o PopAdpmLock; devolve os 8 bytes {InputTimeout,
/// DisplayTimeout} da saída.
fn change(operation: impl FnOnce(&mut AdaptiveState, &mut Vec<Effect>) -> [u32; 2]) -> Vec<u8> {
    let _guard = ADPM_LOCK.acquire_exclusive();
    let mut effects = Vec::new();
    let timeouts = {
        let mut state = STATE.lock();
        operation(&mut *state, &mut effects)
    };
    apply(&effects);
    let mut output = Vec::with_capacity(8);
    output.extend_from_slice(&timeouts[0].to_le_bytes());
    output.extend_from_slice(&timeouts[1].to_le_bytes());
    output
}

/// SessionRITState sobre a entrada capturada de [`SESSION_RIT_STATE_INPUT`]
/// bytes, da sessão de quem chama.
pub fn session_input_change(session: u32, input: &[u8]) -> Vec<u8> {
    let active = input[0] != 0;
    let time = u32::from_le_bytes([input[4], input[5], input[6], input[7]]);
    change(|state, effects| state.session_input_change(session, active, time, effects))
}

/// SessionConnectNotification sobre a entrada capturada de
/// [`SESSION_CONNECT_INPUT`] bytes, da sessão de quem chama.
pub fn session_connection_change(session: u32, input: &[u8]) -> Vec<u8> {
    let (connected, console) = (input[0] != 0, input[1] != 0);
    crate::debug_print!("[po] sessao {} {} ({})", session, if connected { "conectada" } else { "desconectada" }, if console { "console" } else { "remota" });
    let time = crate::ntos::ke::thread_dispatch::tick_count();
    change(|state, effects| state.session_connection_change(session, connected, console, time, effects))
}
