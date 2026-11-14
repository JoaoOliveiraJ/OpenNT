//! Sessões de logon do Security Reference Monitor (SEP_LOGON_SESSION_
//! REFERENCES) e o SeSetSessionIdTokenWithLinked.
//!
//! Como no NT, o banco de sessões nasce no SepRmDbInitialization (ntoskrnl
//! 19041 rva 0xa6e540) com as duas sessões de boot, SYSTEM
//! (SeSystemAuthenticationId, 0x3E7) e ANONYMOUS (SeAnonymousAuthenticationId,
//! 0x3E6), ambas no silo hospedeiro, sem token de sessão (o Token que o LSA
//! liga pelo SepSetLogonSessionToken) e sem sessão irmã (BuddyLogonId, que o
//! LSA liga pelo SepLinkLogonSessions). O OpenNT não tem LSA, então o banco
//! fica nesse estado de boot.
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
const TOKEN_QUERY: u32 = 0x8;

/// SeSystemAuthenticationId e SeAnonymousAuthenticationId.
pub const SYSTEM_LUID: u64 = 0x3E7;
pub const ANONYMOUS_LUID: u64 = 0x3E6;

/// Uma SEP_LOGON_SESSION_REFERENCES: LogonId, o silo, o token da sessão e
/// a sessão irmã.
#[derive(Clone, Copy)]
struct LogonSession {
    logon_id: u64,
    server_silo: u64,
    token: u64,
    buddy_logon_id: u64,
}

/// SepLogonSessions.
static SESSIONS: SpinLock<Vec<LogonSession>> = SpinLock::new(Vec::new());

/// SepRmDbInitialization: as sessões de boot, criadas na primeira consulta.
fn with_sessions<T>(body: impl FnOnce(&[LogonSession]) -> T) -> T {
    let mut sessions = SESSIONS.lock();
    if sessions.is_empty() {
        for logon_id in [SYSTEM_LUID, ANONYMOUS_LUID] {
            sessions.push(LogonSession { logon_id, server_silo: 0, token: 0, buddy_logon_id: 0 });
        }
    }
    body(&sessions)
}

/// SepReferenceLogonSessionSilo: a sessão do LogonId no silo.
fn find(logon_id: u64, server_silo: u64) -> Option<LogonSession> {
    with_sessions(|sessions| sessions.iter().copied().find(|session| session.logon_id == logon_id && session.server_silo == server_silo))
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
