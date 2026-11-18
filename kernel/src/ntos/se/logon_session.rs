//! Sessões de logon do Security Reference Monitor (SEP_LOGON_SESSION_
//! REFERENCES): as referências dos tokens, o token de sessão, a notificação
//! de término aos file systems e o SeSetSessionIdTokenWithLinked.
//!
//! Como no NT, o banco de sessões nasce no SepRmDbInitialization (ntoskrnl
//! 19041 rva 0xa6e540) com as duas sessões de boot, SYSTEM
//! (SeSystemAuthenticationId, 0x3E7) e ANONYMOUS (SeAnonymousAuthenticationId,
//! 0x3E6), ambas no silo hospedeiro, sem token de sessão e sem sessão irmã
//! (BuddyLogonId, que o LSA liga pelo SepLinkLogonSessions e o OpenNT ainda
//! não liga). No NT elas ficam presas pelos tokens permanentes do boot
//! (SeSystemToken e SeAnonymousLogonToken); aqui a referência desses tokens
//! entra já contada (ReferenceCount 1 com o bit de referência de token), e
//! nenhuma das duas chega a zero. O LSA cria e apaga sessões pelos comandos
//! RmCreateLogonSession e RmDeleteLogonSession da `SeRmCommandPort`
//! (`se/reference_monitor.rs`, [`create_track`] e [`delete_track`]).
//!
//! Contagem de referências, como no 19041:
//! - SepCreateLogonSessionTrack (rva 0x6850ac) cria a sessão com
//!   ReferenceCount 1, a referência do LSA;
//! - SepReferenceLogonSessionSilo (rva 0x5dc7fc), na criação de cada token
//!   ([`reference_for_token`], chamado por `se/token/tokens.rs`): o primeiro
//!   token liga o bit 8 de Flags e herda a referência do LSA; os seguintes
//!   somam 1;
//! - SepDeReferenceLogonSession (rva 0x6f7be4), na destruição do token
//!   ([`dereference_for_token`]): no zero a sessão sai do banco, solta o
//!   token de sessão e, se marcada (Flags & 1), avisa os file systems pelo
//!   SepInformFileSystemsOfDeletedLogon (rva 0x923864): um bloco de 0x30
//!   bytes de NonPagedPoolNx ('SeFS') com o WORK_QUEUE_ITEM, o LogonId e o
//!   silo (referenciado), na DelayedWorkQueue; o SepNotifyFileSystems (rva
//!   0x923a80) chama cada rotina registrada com (&LogonId, Silo, Context);
//! - SepDeleteLogonSessionTrack (rva 0x77a490): só apaga a sessão sem
//!   referência, ou com a referência única do LSA (bit 8 desligado); senão
//!   STATUS_BAD_LOGON_SESSION_STATE. Apagar pelo LSA não avisa os file
//!   systems.
//!
//! As rotinas de término: SeRegisterLogonSessionTerminatedRoutineEx (rva
//! 0x7d0dd0) põe (Routine, Context) na cabeça da lista
//! SeFileSystemNotifyRoutinesExHead (STATUS_INVALID_PARAMETER sem rotina);
//! SeUnregisterLogonSessionTerminatedRoutineEx (rva 0x923560) tira o par
//! exato (STATUS_NOT_FOUND se não existe); o
//! SeMarkLogonSessionForTerminationNotificationEx (rva 0x6a5970) liga o bit
//! 1 da sessão do LogonId no silo pedido (silo NULL casa qualquer silo),
//! STATUS_NOT_FOUND sem a sessão. O NT chama as rotinas segurando o
//! SepRmNotifyMutex; aqui a lista é copiada sob o lock e as rotinas rodam
//! fora dele.
//!
//! O token de sessão: o SepSetLogonSessionToken (rva 0x5d9ee0), chamado pelo
//! SepFilterToken quando o token filtrado fica restrito, guarda na sessão
//! (uma vez) uma cópia primária do token original não restrito; a cópia
//! deixa de referenciar a sessão (SepStopReferencingLogonSession, TokenFlags
//! |= TOKEN_SESSION_NOT_REFERENCED). O SeGetLogonSessionToken (rva 0x922920)
//! referencia o token pelo handle (TOKEN_QUERY), recusa a sessão sem token
//! de sessão (STATUS_NO_TOKEN) e devolve um handle (TOKEN_ALL_ACCESS) para
//! uma cópia primária dele, de kernel quando o modo é KernelMode.
//!
//! SeSetSessionIdTokenWithLinked (rva 0x91c8b0): referencia o token pelo
//! handle (TOKEN_QUERY, no modo anterior), recusa um token já em uso como
//! primário de um processo (STATUS_TOKEN_ALREADY_IN_USE), procura a sessão
//! de logon do token (STATUS_NO_SUCH_LOGON_SESSION se não existe) e grava o
//! SessionId no token da sessão e no da sessão irmã, quando existem — não no
//! token do handle.

use alloc::vec::Vec;

use crate::hal::amd64::native_call;
use crate::ntos::ex::pool_allocation;
use crate::ntos::inc::types::{Field, Luid, NtStruct, WorkQueueItem};
use crate::ntos::ob::object_reference;
use crate::ntos::ps::previous_mode;
use crate::ntos::se::token::{handles, reference, tokens};
use crate::rtl::{KernelError, SpinLock};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_SUCH_LOGON_SESSION: u32 = 0xC000_005F;
const STATUS_NO_TOKEN: u32 = 0xC000_007C;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_LOGON_SESSION_COLLISION: u32 = 0xC000_00EE;
const STATUS_BAD_LOGON_SESSION_STATE: u32 = 0xC000_0104;
const STATUS_TOKEN_ALREADY_IN_USE: u32 = 0xC000_012B;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
const TOKEN_QUERY: u32 = 0x8;
/// TOKEN_ALL_ACCESS, o acesso do handle do SeGetLogonSessionToken.
const TOKEN_ALL_ACCESS: u32 = 0xF_01FF;
/// OBJ_KERNEL_HANDLE.
const OBJ_KERNEL_HANDLE: u32 = 0x200;
/// TokenFlags: TOKEN_WRITE_RESTRICTED e TOKEN_IS_RESTRICTED.
const TOKEN_WRITE_RESTRICTED: u32 = 0x8;
const TOKEN_IS_RESTRICTED: u32 = 0x10;
/// Flags da sessão: avisar os file systems no fim, e já referenciada por
/// um token.
const SESSION_TERMINATION_NOTIFY: u32 = 0x1;
const SESSION_TOKEN_REFERENCED: u32 = 0x8;
/// NonPagedPoolNx e 'SeFS'.
const NON_PAGED_POOL_NX: u32 = 0x200;
const NOTIFY_TAG: u32 = u32::from_le_bytes(*b"SeFS");

/// SeSystemAuthenticationId e SeAnonymousAuthenticationId.
pub const SYSTEM_LUID: u64 = 0x3E7;
pub const ANONYMOUS_LUID: u64 = 0x3E6;

/// Uma SEP_LOGON_SESSION_REFERENCES: LogonId, ReferenceCount, Flags, o
/// silo, o token da sessão, a sessão irmã e o AccountName e o
/// AuthorityName que o LSA informa.
#[derive(Clone)]
struct LogonSession {
    logon_id: u64,
    reference_count: u64,
    flags: u32,
    server_silo: u64,
    token: u64,
    buddy_logon_id: u64,
    account_name: Vec<u16>,
    authority_name: Vec<u16>,
}

impl LogonSession {
    fn new(logon_id: u64, server_silo: u64) -> Self {
        Self { logon_id, reference_count: 1, flags: 0, server_silo, token: 0, buddy_logon_id: 0, account_name: Vec::new(), authority_name: Vec::new() }
    }
}

/// SepLogonSessions.
static SESSIONS: SpinLock<Vec<LogonSession>> = SpinLock::new(Vec::new());

/// SeFileSystemNotifyRoutinesExHead: (Routine, Context), a mais nova
/// primeiro.
static TERMINATED_ROUTINES: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());

/// SepRmDbInitialization: as sessões de boot, criadas na primeira consulta,
/// já presas pelos tokens permanentes do boot.
fn with_sessions<T>(body: impl FnOnce(&mut Vec<LogonSession>) -> T) -> T {
    let mut sessions = SESSIONS.lock();
    if sessions.is_empty() {
        for logon_id in [SYSTEM_LUID, ANONYMOUS_LUID] {
            sessions.push(LogonSession { flags: SESSION_TOKEN_REFERENCED, ..LogonSession::new(logon_id, 0) });
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
/// cria silos de servidor), com a referência do LSA, sem token de sessão nem
/// irmã; STATUS_LOGON_SESSION_COLLISION se o LogonId já existe. Devolve o
/// NTSTATUS.
pub fn create_track(logon_id: u64) -> u32 {
    with_sessions(|sessions| {
        if sessions.iter().any(|session| session.logon_id == logon_id && session.server_silo == 0) {
            return STATUS_LOGON_SESSION_COLLISION;
        }
        sessions.push(LogonSession::new(logon_id, 0));
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

/// O BuddyLogonId da sessão (a sessão ligada de um par de tokens de UAC; 0
/// sem sessão ligada ou sem a sessão).
pub fn buddy_logon_id(logon_id: u64, server_silo: u64) -> u64 {
    find(logon_id, server_silo).map_or(0, |session| session.buddy_logon_id)
}

/// SepDeleteLogonSessionTrack (rva 0x77a490) sem a revogação de handles, o
/// RmDeleteLogonSession do LSA: STATUS_NO_SUCH_LOGON_SESSION se a sessão não
/// existe no silo; STATUS_BAD_LOGON_SESSION_STATE enquanto um token a
/// referencia (bit 8 ligado, ou mais de uma referência) ou enquanto um token
/// vivo do LogonId dela ainda a segura (um token com
/// TOKEN_SESSION_NOT_REFERENCED não conta). Devolve o NTSTATUS.
pub fn delete_track(logon_id: u64) -> u32 {
    let removed = with_sessions(|sessions| {
        let Some(position) = sessions.iter().position(|session| session.logon_id == logon_id && session.server_silo == 0) else { return Err(STATUS_NO_SUCH_LOGON_SESSION) };
        let session = &sessions[position];
        if session.reference_count != 0 && (session.flags & SESSION_TOKEN_REFERENCED != 0 || session.reference_count != 1) {
            return Err(STATUS_BAD_LOGON_SESSION_STATE);
        }
        if tokens::any(|token| token.authentication_id == logon_id && token.server_silo == 0 && tokens::references_logon_session(token)) {
            return Err(STATUS_BAD_LOGON_SESSION_STATE);
        }
        Ok(sessions.remove(position))
    });
    match removed {
        Ok(session) => {
            if session.token != 0 {
                let _ = tokens::release(session.token);
            }
            0
        }
        Err(status) => status,
    }
}

/// A sessão de logon existe no silo (a consulta do SepReferenceLogonSession).
pub fn exists(logon_id: u64, server_silo: u64) -> bool {
    find(logon_id, server_silo).is_some()
}

/// SepReferenceLogonSessionSilo na criação de um token: o primeiro token
/// herda a referência do LSA (bit 8), os outros somam 1. `false` se a
/// sessão não existe.
pub fn reference_for_token(logon_id: u64, server_silo: u64) -> bool {
    with_sessions(|sessions| {
        let Some(session) = sessions.iter_mut().find(|session| session.logon_id == logon_id && session.server_silo == server_silo) else { return false };
        let referenced = session.flags & SESSION_TOKEN_REFERENCED != 0;
        session.flags |= SESSION_TOKEN_REFERENCED;
        if referenced {
            session.reference_count += 1;
        }
        true
    })
}

/// SepDeReferenceLogonSessionDirect: solta uma referência que nunca é a
/// última (a do token que deixa de referenciar a sessão).
pub fn dereference_direct(logon_id: u64, server_silo: u64) {
    with_sessions(|sessions| {
        if let Some(session) = sessions.iter_mut().find(|session| session.logon_id == logon_id && session.server_silo == server_silo) {
            if session.reference_count > 1 {
                session.reference_count -= 1;
            }
        }
    });
}

/// SepDeReferenceLogonSession na destruição de um token: no zero a sessão
/// sai do banco, o token de sessão é solto e, com a marca de término, os
/// file systems são avisados. O aviso ao LSA que o 19041 dá em seguida (o
/// SepInformLsaOfDeletedLogon) ainda não existe; o que ele precisa está em
/// `se/reference_monitor.rs`.
pub fn dereference_for_token(logon_id: u64, server_silo: u64) {
    let removed = with_sessions(|sessions| {
        let position = sessions.iter().position(|session| session.logon_id == logon_id && session.server_silo == server_silo)?;
        let session = &mut sessions[position];
        session.reference_count = session.reference_count.saturating_sub(1);
        if session.reference_count > 0 {
            return None;
        }
        Some(sessions.remove(position))
    });
    let Some(session) = removed else { return };
    if session.token != 0 {
        let _ = tokens::release(session.token);
    }
    if session.flags & SESSION_TERMINATION_NOTIFY != 0 {
        inform_file_systems(session.logon_id, session.server_silo);
    }
}

/// SeRegisterLogonSessionTerminatedRoutineEx(Routine, Context) -> NTSTATUS.
pub fn register_terminated_routine(routine: u64, context: u64) -> u32 {
    if routine == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    TERMINATED_ROUTINES.lock().insert(0, (routine, context));
    0
}

/// SeUnregisterLogonSessionTerminatedRoutineEx(Routine, Context) -> NTSTATUS.
pub fn unregister_terminated_routine(routine: u64, context: u64) -> u32 {
    if routine == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut routines = TERMINATED_ROUTINES.lock();
    match routines.iter().position(|&entry| entry == (routine, context)) {
        Some(position) => {
            routines.remove(position);
            0
        }
        None => STATUS_NOT_FOUND,
    }
}

/// SeMarkLogonSessionForTerminationNotificationEx(LogonId*, ServerSilo) ->
/// NTSTATUS: silo NULL casa a sessão do LogonId em qualquer silo.
pub fn mark_for_termination_notification(logon_id: u64, server_silo: u64) -> u32 {
    with_sessions(|sessions| {
        match sessions.iter_mut().find(|session| session.logon_id == logon_id && (server_silo == 0 || session.server_silo == server_silo)) {
            Some(session) => {
                session.flags |= SESSION_TERMINATION_NOTIFY;
                0
            }
            None => STATUS_NOT_FOUND,
        }
    })
}

/// O bloco do SepInformFileSystemsOfDeletedLogon: o WORK_QUEUE_ITEM, o
/// LogonId e o silo.
#[repr(C)]
struct DeletedLogonNotice {
    work_item: WorkQueueItem,
    logon_id: Luid,
    server_silo: Field<u64>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for DeletedLogonNotice {}

const _: () = {
    assert!(core::mem::size_of::<DeletedLogonNotice>() == 0x30);
    assert!(core::mem::offset_of!(DeletedLogonNotice, logon_id) == 0x20);
};

/// SepInformFileSystemsOfDeletedLogon: o aviso vai à DelayedWorkQueue; sem
/// pool, nenhum aviso (como no NT).
fn inform_file_systems(logon_id: u64, server_silo: u64) {
    let Ok(block) = pool_allocation::allocate_tagged(NON_PAGED_POOL_NX, DeletedLogonNotice::SIZE, NOTIFY_TAG) else { return };
    if block == 0 {
        return;
    }
    // SAFETY: bloco recém-alocado do tamanho do aviso.
    let notice = unsafe { DeletedLogonNotice::at(block) };
    tokens::set_luid(&notice.logon_id, logon_id);
    notice.server_silo.set(server_silo);
    if server_silo != 0 {
        let _ = object_reference::reference_with_tag(server_silo, NOTIFY_TAG, false);
    }
    crate::ntos::io::work_items::queue_kernel_ex_work_item(block, notify_file_systems, block);
}

/// SepNotifyFileSystems: chama cada rotina registrada com (&LogonId, Silo,
/// Context), solta o silo e libera o bloco.
fn notify_file_systems(_device: u64, block: u64) {
    // SAFETY: o bloco do aviso, vivo até o fim desta rotina.
    let notice = unsafe { DeletedLogonNotice::at(block) };
    let server_silo = notice.server_silo.get();
    let routines = TERMINATED_ROUTINES.lock().clone();
    for (routine, context) in routines {
        native_call::call(routine, &[notice.logon_id.address(), server_silo, context]);
    }
    if server_silo != 0 {
        let _ = object_reference::dereference_with_tag(server_silo, NOTIFY_TAG, false);
    }
    let _ = pool_allocation::free(block, 0);
}

/// SepSetLogonSessionToken (rva 0x5d9ee0): com a sessão do token ainda sem
/// token de sessão e o token não restrito, guarda nela uma cópia primária
/// dele que não referencia a sessão.
pub fn set_session_token(token: u64) {
    let Some(Some((logon_id, server_silo))) = tokens::with(token, |record| record.logon_reference) else { return };
    if find(logon_id, server_silo).is_none_or(|session| session.token != 0) {
        return;
    }
    if tokens::body(token).token_flags.get() & (TOKEN_IS_RESTRICTED | TOKEN_WRITE_RESTRICTED) != 0 {
        return;
    }
    let Ok(copy) = tokens::duplicate(token, 0, false, 1) else { return };
    // SepStopReferencingLogonSession: a cópia solta a referência à sessão.
    tokens::stop_referencing_logon_session(copy);
    let stored = with_sessions(|sessions| match sessions.iter_mut().find(|session| session.logon_id == logon_id && session.server_silo == server_silo) {
        Some(session) if session.token == 0 => {
            session.token = copy;
            true
        }
        _ => false,
    });
    if !stored {
        let _ = tokens::release(copy);
    }
}

/// SeGetLogonSessionToken(TokenHandle, AccessMode, NewTokenHandle*) ->
/// NTSTATUS.
pub fn get_logon_session_token(handle: u64, access_mode: u8, output: &Field<u64>) -> Result<u32, KernelError> {
    let mut reference = match reference::reference(handle, TOKEN_QUERY, access_mode, false)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = (|| -> Result<u32, KernelError> {
        let session_token = tokens::with(reference.token, |record| record.logon_reference).flatten().and_then(|(logon_id, server_silo)| find(logon_id, server_silo)).map_or(0, |session| session.token);
        if session_token == 0 {
            return Ok(STATUS_NO_TOKEN);
        }
        let copy = match tokens::duplicate(session_token, 0, false, 1) {
            Ok(copy) => copy,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(_) => return Ok(STATUS_INSUFFICIENT_RESOURCES),
        };
        let attributes = if access_mode == 0 { OBJ_KERNEL_HANDLE } else { 0 };
        let status = match handles::create(copy, TOKEN_ALL_ACCESS, attributes, access_mode != 0) {
            Ok(new_handle) => {
                output.set(new_handle);
                0
            }
            Err(error) if error.status != 0 => error.status,
            Err(error) => {
                let _ = tokens::release(copy);
                return Err(error);
            }
        };
        tokens::release(copy)?;
        Ok(status)
    })();
    reference.release()?;
    result
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
        if tokens::in_use(token) {
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

/// Os pares (Routine, Context) registrados, a mais nova primeiro (para o
/// autoteste).
pub fn terminated_routines() -> Vec<(u64, u64)> {
    TERMINATED_ROUTINES.lock().clone()
}

/// ReferenceCount e Flags da sessão (para o autoteste).
pub fn reference_state(logon_id: u64, server_silo: u64) -> Option<(u64, u32)> {
    find(logon_id, server_silo).map(|session| (session.reference_count, session.flags))
}
