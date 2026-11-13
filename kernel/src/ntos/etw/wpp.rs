//! Sessões de rastreamento WPP (WppAutoLogStart/Trace/Stop e o replay).
//!
//! As sessões de trace existem de verdade (estado e buffer circular de 256
//! eventos por sessão) e os eventos saem na serial. O conteúdo WPP é
//! binário e formatado offline: cada evento é registrado pelo número da
//! mensagem.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;

use crate::ntos::inc::types::{Field, NtStruct};
use crate::rtl::SpinLock;

const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;

struct Sessions {
    next: u64,
    sessions: BTreeMap<u64, VecDeque<String>>,
}

static SESSIONS: SpinLock<Sessions> = SpinLock::new(Sessions { next: 1, sessions: BTreeMap::new() });

/// WppAutoLogStart(guid, &handle, callback): inicia uma sessão real.
pub fn auto_log_start(handle_out: u64) {
    let mut sessions = SESSIONS.lock();
    let handle = sessions.next;
    sessions.next += 1;
    sessions.sessions.insert(handle, VecDeque::new());
    drop(sessions);
    if handle_out != 0 {
        // SAFETY: handle de saída do driver.
        unsafe { Field::<u64>::at(handle_out) }.set(handle);
    }
}

/// WppAutoLogTrace(handle, level, flags, guid, msgNumber, ...): registra
/// pelo número da mensagem (o conteúdo WPP é binário, formatado offline).
pub fn auto_log_trace(handle: u32, message: u32) {
    let line = format!("[wpp] evento msg#{}", message);
    if let Some(events) = SESSIONS.lock().sessions.get_mut(&u64::from(handle)) {
        events.push_back(line.clone());
        if events.len() > 256 {
            events.pop_front();
        }
    }
    debug_print!("{}", line);
}

/// WppAutoLogStop(handle, guid): encerra a sessão.
pub fn auto_log_stop(handle: u32) {
    SESSIONS.lock().sessions.remove(&u64::from(handle));
}

/// imp_WppRecorderReplay(handle, ...): repete o buffer circular. Devolve o
/// NTSTATUS (STATUS_INVALID_HANDLE sem a sessão).
pub fn recorder_replay(handle: u32) -> u32 {
    let sessions = SESSIONS.lock();
    let Some(events) = sessions.sessions.get(&u64::from(handle)) else { return STATUS_INVALID_HANDLE };
    for line in events {
        debug_print!("[replay] {}", line);
    }
    0
}
