//! Sessões de logon do Security Reference Monitor (SEP_LOGON_SESSION_
//! REFERENCES) e o SeSetSessionIdTokenWithLinked.
//!
//! Como no NT, o banco de sessões nasce no SepRmDbInitialization (ntoskrnl
//! 19041 rva 0xa6e540) com as duas sessões de boot, SYSTEM
//! (SeSystemAuthenticationId, 0x3E7) e ANONYMOUS (SeAnonymousAuthenticationId,
//! 0x3E6), ambas no silo hospedeiro, sem token de sessão (o Token que o LSA
//! liga pelo SepSetLogonSessionToken) e sem sessão irmã (BuddyLogonId, que o
//! LSA liga pelo SepLinkLogonSessions). O LSA cria e apaga sessões pelos
//! comandos RmCreateLogonSession e RmDeleteLogonSession da `SeRmCommandPort`
//! (`se/reference_monitor.rs`, [`create_track`] e [`delete_track`]); o token
//! de sessão e a sessão irmã ainda não são ligados.
//!
//! SeSetSessionIdTokenWithLinked (rva 0x91c8b0): referencia o token pelo
//! handle (TOKEN_QUERY, no modo anterior), recusa um token já em uso como
//! primário de um processo (STATUS_TOKEN_ALREADY_IN_USE), procura a sessão
//! de logon do token (STATUS_NO_SUCH_LOGON_SESSION se não existe) e grava o
//! SessionId no token da sessão e no da sessão irmã, quando existem — não no
//! token do handle.

use alloc::vec::Vec;

use crate::ntos::ps::{previous_mode, process};
use crate::ntos::se::token::{reference, tokens};
use crate::rtl::{KernelError, SpinLock};

const STATUS_TOKEN_ALREADY_IN_USE: u32 = 0xC000_012B;
const STATUS_NO_SUCH_LOGON_SESSION: u32 = 0xC000_005F;
const STATUS_LOGON_SESSION_COLLISION: u32 = 0xC000_00EE;
const STATUS_BAD_LOGON_SESSION_STATE: u32 = 0xC000_0104;
const TOKEN_QUERY: u32 = 0x8;

/// SeSystemAuthenticationId e SeAnonymousAuthenticationId.
pub const SYSTEM_LUID: u64 = 0x3E7;
pub const ANONYMOUS_LUID: u64 = 0x3E6;

/// Uma SEP_LOGON_SESSION_REFERENCES: LogonId, o silo, o token da sessão, a
/// sessão irmã e o AccountName e o AuthorityName que o LSA informa.
#[derive(Clone)]
struct LogonSession {
    logon_id: u64,
    server_silo: u64,
    token: u64,
    buddy_logon_id: u64,
    account_name: Vec<u16>,
    authority_name: Vec<u16>,
}

impl LogonSession {
    fn new(logon_id: u64) -> Self {
        Self { logon_id, server_silo: 0, token: 0, buddy_logon_id: 0, account_name: Vec::new(), authority_name: Vec::new() }
    }
}

/// SepLogonSessions.
static SESSIONS: SpinLock<Vec<LogonSession>> = SpinLock::new(Vec::new());

/// SepRmDbInitialization: as sessões de boot, criadas na primeira consulta.
fn with_sessions<T>(body: impl FnOnce(&mut Vec<LogonSession>) -> T) -> T {
    let mut sessions = SESSIONS.lock();
    if sessions.is_empty() {
        for logon_id in [SYSTEM_LUID, ANONYMOUS_LUID] {
            sessions.push(LogonSession::new(logon_id));
        }
    }
    body(&mut sessions)
}

/// SepReferenceLogonSessionSilo: a sessão do LogonId no silo.
fn find(logon_id: u64, server_silo: u64) -> Option<LogonSession> {
    with_sessions(|sessions| sessions.iter().find(|session| session.logon_id == logon_id && session.server_silo == server_silo).cloned())
}

/// SepCreateLogonSessionTrack (rva 0x6850ac), o RmCreateLogonSession do LSA
/// (`se/reference_monitor.rs`): a sessão nova no silo hospedeiro (o OpenNT não
/// cria silos de servidor), sem token de sessão nem irmã;
/// STATUS_LOGON_SESSION_COLLISION se o LogonId já existe. Devolve o NTSTATUS.
pub fn create_track(logon_id: u64) -> u32 {
    with_sessions(|sessions| {
        if sessions.iter().any(|session| session.logon_id == logon_id && session.server_silo == 0) {
            return STATUS_LOGON_SESSION_COLLISION;
        }
        sessions.push(LogonSession::new(logon_id));
        0
    })
}

/// SepUpdateLogonSessionTrack (rva 0x692474), o comando 4 do LSA
/// (SepRmAddLogonSessionInfoWrkr): o AccountName e o AuthorityName da
/// sessão do LogonId no silo hospedeiro, que trocam os anteriores;
/// STATUS_NO_SUCH_LOGON_SESSION se a sessão não existe. Devolve o NTSTATUS.
pub fn add_info(logon_id: u64, account_name: &[u16], authority_name: &[u16]) -> u32 {
    with_sessions(|sessions| {
        let Some(session) = sessions.iter_mut().find(|session| session.logon_id == logon_id && session.server_silo == 0) else { return STATUS_NO_SUCH_LOGON_SESSION };
        session.account_name = account_name.to_vec();
        session.authority_name = authority_name.to_vec();
        0
    })
}

/// O AccountName e o AuthorityName que o LSA informou para a sessão.
pub fn names(logon_id: u64) -> Option<(Vec<u16>, Vec<u16>)> {
    find(logon_id, 0).map(|session| (session.account_name, session.authority_name))
}

/// SepDeleteLogonSessionTrack (rva 0x77a490) sem a revogação de handles, o
/// RmDeleteLogonSession do LSA: STATUS_NO_SUCH_LOGON_SESSION se a sessão não
/// existe no silo e STATUS_BAD_LOGON_SESSION_STATE enquanto algum token dela
/// a referencia (no NT, o ReferenceCount acima da referência da própria
/// sessão; um token com TOKEN_SESSION_NOT_REFERENCED não conta).
/// Devolve o NTSTATUS.
pub fn delete_track(logon_id: u64) -> u32 {
    with_sessions(|sessions| {
        let Some(position) = sessions.iter().position(|session| session.logon_id == logon_id && session.server_silo == 0) else { return STATUS_NO_SUCH_LOGON_SESSION };
        if tokens::any(|token| token.authentication_id == logon_id && token.server_silo == 0 && tokens::references_logon_session(token)) {
            return STATUS_BAD_LOGON_SESSION_STATE;
        }
        sessions.remove(position);
        0
    })
}

/// A sessão de logon existe no silo (a consulta do SepReferenceLogonSession).
pub fn exists(logon_id: u64, server_silo: u64) -> bool {
    find(logon_id, server_silo).is_some()
}

/// TokenInUse: o token é o primário de algum processo vivo.
fn token_in_use(token: u64) -> bool {
    process::list_active_processes().iter().any(|entry| process::get_primary_token(entry.address) == Some(token))
}

/// SeSetSessionIdToken sobre o token da sessão.
fn set_session_id(token: u64, session_id: u32) {
    let _ = tokens::update(token, |token| token.session_id = session_id);
}

/// SeSetSessionIdTokenWithLinked(TokenHandle, SessionId): devolve o
/// NTSTATUS.
pub fn set_session_id_token_with_linked(handle: u64, session_id: u32) -> Result<u32, KernelError> {
    let mut reference = match reference::reference(handle, TOKEN_QUERY, previous_mode::get()?, true)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let token = reference.token;
    let result = (|| {
        if token_in_use(token) {
            return STATUS_TOKEN_ALREADY_IN_USE;
        }
        let Some((logon_id, server_silo)) = tokens::with(token, |token| (token.authentication_id, token.server_silo)) else { return STATUS_NO_SUCH_LOGON_SESSION };
        let Some(session) = find(logon_id, server_silo) else { return STATUS_NO_SUCH_LOGON_SESSION };
        let buddy = if session.buddy_logon_id != 0 {
            match find(session.buddy_logon_id, server_silo) {
                Some(buddy) => buddy.token,
                None => return STATUS_NO_SUCH_LOGON_SESSION,
            }
        } else {
            0
        };
        for linked in [session.token, buddy] {
            if linked != 0 {
                set_session_id(linked, session_id);
            }
        }
        0
    })();
    reference.release()?;
    Ok(result)
}
