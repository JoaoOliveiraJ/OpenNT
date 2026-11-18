//! Autotestes (fase 6) da presença do usuário (`po/user_presence.rs`):
//!
//! - a máquina de estados do PopConsoleContext e do PopConnectionBitmap
//!   num estado só do teste (o do Po fica intocado): a conexão do console
//!   liga a tela da sessão e deixa sessão e máquina PowerUserPresent; a
//!   entrada passiva e a ativa trocam a sessão e a máquina só muda com a
//!   última sessão presente; a desconexão zera o contexto do console;
//! - a saída: o timeout de entrada e, só no console, o de tela; a entrada
//!   passiva do console zera o de entrada;
//! - os níveis 61 e 62 recusam entrada e saída de tamanho errado;
//! - GUID_SESSION_USER_PRESENCE (AC e DC) no nível 59; o nível 58 de um
//!   setting de sessão recusado para quem não tem sessão;
//!   GUID_GLOBAL_USER_PRESENCE ainda sem configuração (ela nasce com a
//!   primeira sessão conectada, depois deste teste).
//!
//! Os valores esperados vêm do PopSessionConnected, PopSessionDisconnected,
//! PopSessionInputChange, PopSetSessionUserStatus e
//! PopEvaluateGlobalUserStatus do ntoskrnl 19041.

use alloc::vec::Vec;

use super::phase6::call_export;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::po::power_setting;
use crate::ntos::po::user_presence::{self, AdaptiveState, Effect, POWER_USER_INACTIVE, POWER_USER_INVALID, POWER_USER_PRESENT};

type Assert = fn(bool, &str);

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

fn u32_at(records: &[u8], offset: usize) -> u32 {
    records.get(offset..offset + 4).map_or(u32::MAX, |bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn run(assert: Assert) {
    states(assert);
    timeouts(assert);
    levels(assert);
    session_setting(assert);
}

fn states(assert: Assert) {
    use Effect::{GlobalUserPresence, SessionDisplayStatus, SessionUserPresence};
    let names = user_presence::presence_name(0) == "PowerUserPresent" && user_presence::presence_name(1) == "PowerUserNotPresent" && user_presence::presence_name(2) == "PowerUserInactive" && user_presence::presence_name(3) == "Invalid";
    let mut state = AdaptiveState::new();
    let fresh = state.global_state() == POWER_USER_INVALID && state.console_session() == u32::MAX && state.console_user_status() == POWER_USER_INVALID;
    let mut effects = Vec::new();

    // A conexão do console (sessão 7).
    let output = state.session_connection_change(7, true, true, 1000, &mut effects);
    let connected = output == [0, 0]
        && effects == [SessionDisplayStatus { session: 7, status: 1 }, SessionUserPresence { session: 7, status: POWER_USER_PRESENT }, GlobalUserPresence { state: POWER_USER_PRESENT, transitions: 1 }]
        && state.console_session() == 7 && state.console_user_status() == POWER_USER_PRESENT && state.console_input() == (1000, false) && state.is_present(7);
    assert(names && fresh && connected, "user-presence: a conexao do console liga a tela da sessao e deixa sessao e maquina PowerUserPresent");

    // Sessão remota 9; a passiva do console não muda a máquina; a passiva
    // da última sessão presente muda; a ativa volta.
    effects.clear();
    let remote = state.session_connection_change(9, true, false, 1100, &mut effects) == [0, 0]
        && effects == [SessionDisplayStatus { session: 9, status: 1 }, SessionUserPresence { session: 9, status: POWER_USER_PRESENT }];
    effects.clear();
    let passive = state.session_input_change(7, false, 2000, &mut effects) == [0, 0]
        && effects == [SessionUserPresence { session: 7, status: POWER_USER_INACTIVE }]
        && state.console_user_status() == POWER_USER_INACTIVE && state.console_input() == (2000, false) && state.global_state() == POWER_USER_PRESENT;
    effects.clear();
    let _ = state.session_input_change(9, false, 2100, &mut effects);
    let away = effects == [SessionUserPresence { session: 9, status: POWER_USER_INACTIVE }, GlobalUserPresence { state: POWER_USER_INACTIVE, transitions: 2 }];
    effects.clear();
    let _ = state.session_input_change(7, true, 3000, &mut effects);
    let back = effects == [SessionUserPresence { session: 7, status: POWER_USER_PRESENT }, GlobalUserPresence { state: POWER_USER_PRESENT, transitions: 3 }] && state.console_input() == (3000, false);
    assert(remote && passive && away && back, "user-presence: entrada passiva e ativa trocam a sessao e a maquina so muda com a ultima sessao presente");

    // A desconexão do console zera o contexto; a da sessão 9, já inativa,
    // não muda a máquina.
    effects.clear();
    let reset = state.session_connection_change(7, false, true, 4000, &mut effects) == [0, 0]
        && state.console_session() == u32::MAX && state.console_user_status() == POWER_USER_INVALID && !state.is_present(7)
        && effects == [SessionDisplayStatus { session: 7, status: 0 }, SessionUserPresence { session: 7, status: POWER_USER_INACTIVE }, GlobalUserPresence { state: POWER_USER_INACTIVE, transitions: 4 }];
    effects.clear();
    let _ = state.session_connection_change(9, false, false, 4100, &mut effects);
    let quiet = effects == [SessionDisplayStatus { session: 9, status: 0 }, SessionUserPresence { session: 9, status: POWER_USER_INACTIVE }];
    assert(reset && quiet, "user-presence: a desconexao zera o contexto do console, desliga a tela e deixa a sessao inativa");
}

fn timeouts(assert: Assert) {
    let mut state = AdaptiveState::with_timeouts(300, 600);
    let mut effects = Vec::new();
    let console = state.session_connection_change(1, true, true, 10, &mut effects);
    let active_flag = state.console_input() == (10, true);
    let remote = state.session_connection_change(2, true, false, 20, &mut effects);
    let remote_passive = state.session_input_change(2, false, 30, &mut effects);
    let console_passive = state.session_input_change(1, false, 40, &mut effects);
    let passive_flag = state.console_input() == (40, false);
    let console_active = state.session_input_change(1, true, 50, &mut effects);
    assert(
        console == [300, 600] && active_flag && remote == [300, 0] && remote_passive == [300, 0] && console_passive == [0, 600] && passive_flag && console_active == [300, 600],
        "user-presence: a saida leva o timeout de entrada e, so no console, o de tela; a passiva do console zera o de entrada",
    );
}

fn levels(assert: Assert) {
    let block = guest::alloc_bytes(0x40);
    guest::write_bytes(block, &[0u8; 0x40]);
    let (input, output) = (block, block + 0x20);
    let call = |level: u64, input_length: u64, output_length: u64| call_export("ZwPowerInformation", &[level, input, input_length, output, output_length]).map(|status| status as u32);
    let refused = [call(61, 7, 8), call(61, 8, 4), call(61, 8, 0), call(62, 3, 8), call(62, 2, 16), call(62, 0, 8)].iter().all(|status| *status == Some(STATUS_INVALID_PARAMETER));
    let untouched = guest::read_bytes(output, 8) == [0u8; 8];
    assert(refused && untouched, "user-presence: SessionRITState e SessionConnectNotification recusam entrada e saida de tamanho errado");
    guest::free_bytes(block);
}

fn session_setting(assert: Assert) {
    // Ninguém conectou uma sessão ainda: sem configuração de máquina.
    let global_absent = power_setting::setting_value(&power_setting::GUID_GLOBAL_USER_PRESENCE, 0x40) == Err(STATUS_INVALID_PARAMETER);
    // GUID_SESSION_USER_PRESENCE da sessão -1 (a do processo System, que o
    // nível 59 daqui lê e que nenhuma sessão de usuário enxerga).
    power_setting::set_session_user_presence(u32::MAX, POWER_USER_INACTIVE);
    let read = || power_setting::setting_value(&power_setting::GUID_SESSION_USER_PRESENCE, 0x40).ok();
    let inactive = read().is_some_and(|r| r.len() == 0x28 && u32_at(&r, 0) == 0x24 && u32_at(&r, 4) != 0 && u32_at(&r, 4) == u32_at(&r, 16) && u32_at(&r, 8) == 4 && u32_at(&r, 12) == 2 && u32_at(&r, 24) == 2 && u32_at(&r, 36) == 2);
    power_setting::set_session_user_presence(u32::MAX, POWER_USER_PRESENT);
    let present = read().is_some_and(|r| u32_at(&r, 12) == 0 && u32_at(&r, 24) == 0 && u32_at(&r, 36) == 0);
    // O nível 58 de um setting de sessão pedido por quem não tem sessão.
    let request = guest::alloc_bytes(0x20);
    guest::write_bytes(request, &power_setting::GUID_SESSION_USER_PRESENCE);
    guest::write32(request + 0x10, 0xFFFF_FFFF);
    let name_status = call_export("ZwPowerInformation", &[58, request, 0x14, request + 0x18, 8]).map(|status| status as u32);
    guest::free_bytes(request);
    assert(
        global_absent && inactive && present && name_status == Some(STATUS_INVALID_PARAMETER),
        "user-presence: GUID_SESSION_USER_PRESENCE da sessao no nivel 59, o 58 recusado sem sessao e GUID_GLOBAL_USER_PRESENCE sem configuracao",
    );
}
