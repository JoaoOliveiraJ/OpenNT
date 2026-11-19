//! Sessões de logon do Security Reference Monitor (SEP_LOGON_SESSION_
//! REFERENCES): as referências dos tokens, o token de sessão, o par de
//! sessões do UAC, a notificação de término aos file systems e o
//! SeSetSessionIdTokenWithLinked.
//!
//! Como no NT, o banco de sessões nasce no SepRmDbInitialization (ntoskrnl
//! 19041 rva 0xa6e540) com as duas sessões de boot, SYSTEM
//! (SeSystemAuthenticationId, 0x3E7) e ANONYMOUS (SeAnonymousAuthenticationId,
//! 0x3E6), ambas no silo hospedeiro, sem token de sessão e sem sessão irmã
//! (BuddyLogonId, que o LSA liga pelo SepLinkLogonSessions, [`link_sessions`],
//! quando divide um logon do UAC). No NT elas ficam presas pelos tokens permanentes do boot
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
//!   0x923a80) chama cada rotina registrada com (&LogonId, Silo, Context).
//!   Por último vem o aviso ao LSA, o SepInformLsaOfDeletedLogon (rva
//!   0x6f7da0, `se/lsa_call.rs`), para toda sessão que sai assim;
//! - SepDeleteLogonSessionTrack (rva 0x77a490): só apaga a sessão sem
//!   referência, ou com a referência única do LSA (bit 8 desligado); senão
//!   STATUS_BAD_LOGON_SESSION_STATE. Apagar pelo LSA não avisa os file
//!   systems nem o próprio LSA.
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
//! O par do UAC: o SepLinkLogonSessions (rva 0x32c264; o TokenLinkedToken
//! do NtSetInformationToken, `se/token/elevation.rs`) guarda em cada sessão
//! uma cópia primária do seu token (o token de sessão, que deixa de
//! referenciar a sessão) e o LogonId da outra; a do token completo ganha o
//! Flags 2, a do filtrado o Flags 4, e a completa ganha uma referência a
//! mais (SepReferenceLogonSession), que a filtrada solta quando sai
//! (SepDeReferenceLogonSession do BuddyLogonId). Ligar um token à própria
//! sessão só marca o Flags 4. O TokenElevationType sai desses Flags.
//!
//! SeSetSessionIdTokenWithLinked (rva 0x91c8b0): referencia o token pelo
//! handle (TOKEN_QUERY, no modo anterior), recusa um token já em uso como
//! primário de um processo (STATUS_TOKEN_ALREADY_IN_USE), procura a sessão
//! de logon do token (STATUS_NO_SUCH_LOGON_SESSION se não existe) e grava o
//! SessionId no token da sessão e no da sessão irmã, quando existem — não no
//! token do handle.
//!
//! O mapa de devices DOS da sessão (SEP_LOGON_SESSION_REFERENCES.pDeviceMap,
//! `ob/device_map.rs`): o SeGetTokenDeviceMap (rva 0x6770fc) recusa um token
//! sem a sessão (TOKEN_SESSION_NOT_REFERENCED ou sem LogonSession:
//! STATUS_NO_SUCH_LOGON_SESSION) e devolve o mapa da sessão, sem referência;
//! na primeira vez cria o `\Sessions\0\DosDevices\%08x-%08x` (HighPart e
//! LowPart do AuthenticationId; OBJ_CASE_INSENSITIVE | OBJ_OPENIF |
//! OBJ_KERNEL_HANDLE, sem OBJ_PERMANENT), o ObpSetDeviceMap dele sem processo
//! com a Flag 2 (o global é o `\GLOBAL??`) e, dentro, o link permanente
//! `Global` para `\Global??`; o mapa entra na sessão por compare-exchange (o
//! perdedor solta o seu). O `\Sessions\0\DosDevices` é do csrss da sessão 0
//! (CsrCreateSessionObjectDirectory); sem ele a criação falha e o `\??` de
//! quem não é SYSTEM fica sem mapa, como no NT. Quando a sessão sai
//! (SepDeReferenceLogonSession e SepDeleteLogonSessionTrack), o
//! SepCleanupLUIDDeviceMapDirectory (rva 0x6f78cc) torna temporários os
//! links do diretório e o mapa é solto.

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
/// Flags da sessão ligada pelo SepLinkLogonSessions: a do token completo e
/// a do token filtrado.
pub const SESSION_FULL_LINK: u32 = 0x2;
pub const SESSION_LIMITED_LINK: u32 = 0x4;
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
    /// pDeviceMap: o DEVICE_MAP do `\??` da sessão, com a referência dela
    /// (0 até o primeiro SeGetTokenDeviceMap).
    device_map: u64,
}

impl LogonSession {
    fn new(logon_id: u64, server_silo: u64) -> Self {
        Self { logon_id, reference_count: 1, flags: 0, server_silo, token: 0, buddy_logon_id: 0, account_name: Vec::new(), authority_name: Vec::new(), device_map: 0 }
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

/// Os Flags de vínculo do UAC da sessão (SESSION_FULL_LINK e
/// SESSION_LIMITED_LINK; 0 sem a sessão).
pub fn link_flags(logon_id: u64, server_silo: u64) -> u32 {
    find(logon_id, server_silo).map_or(0, |session| session.flags & (SESSION_FULL_LINK | SESSION_LIMITED_LINK))
}

/// A sessão já guarda um token de sessão.
pub fn holds_session_token(logon_id: u64, server_silo: u64) -> bool {
    find(logon_id, server_silo).is_some_and(|session| session.token != 0)
}

/// SepReferenceLogonSessionSilo sobre a entrada: o primeiro token herda a
/// referência do LSA (liga o bit 8), os seguintes somam 1.
fn reference_entry(session: &mut LogonSession) {
    let referenced = session.flags & SESSION_TOKEN_REFERENCED != 0;
    session.flags |= SESSION_TOKEN_REFERENCED;
    if referenced {
        session.reference_count += 1;
    }
}

/// O SepReferenceLogonSessionSilo do BuddyLogonId da sessão (LogonId,
/// silo), como o TokenLinkedToken faz: a sessão irmã referenciada e o token
/// de sessão dela, com uma referência de objeto; devolve (LogonId da irmã,
/// token). Sem a irmã, STATUS_NO_SUCH_LOGON_SESSION. A referência à sessão
/// sai pelo [`dereference_direct`]. Uma irmã sem token de sessão não existe
/// no NT (o SepLinkLogonSessions liga as duas com os tokens); aqui ela dá
/// STATUS_NO_TOKEN.
pub fn reference_linked_token(logon_id: u64, server_silo: u64) -> Result<(u64, u64), u32> {
    let buddy = buddy_logon_id(logon_id, server_silo);
    let token = with_sessions(|sessions| {
        let Some(session) = sessions.iter_mut().find(|session| session.logon_id == buddy && session.server_silo == server_silo) else { return Err(STATUS_NO_SUCH_LOGON_SESSION) };
        reference_entry(session);
        // A referência de objeto é tomada sob a trava das sessões, que
        // seguram o token de sessão (a trava dos tokens vem depois dela).
        if session.token == 0 || tokens::retain(session.token).is_err() {
            return Ok(None);
        }
        Ok(Some(session.token))
    })?;
    match token {
        Some(token) => Ok((buddy, token)),
        None => {
            dereference_direct(buddy, server_silo);
            Err(STATUS_NO_TOKEN)
        }
    }
}

/// O corpo do SepLinkLogonSessions (ntoskrnl 19041, rva 0x32c264) depois do
/// privilégio, da sessão do token sem token de sessão e da referência ao
/// token ligado (`se/token/elevation.rs`): `full` é o token completo (o do
/// NtSetInformationToken) e `limited` o filtrado (o do handle).
/// - a sessão do token ligado já com token de sessão é
///   STATUS_INVALID_PARAMETER;
/// - os dois tokens na mesma sessão: a sessão ganha o Flags 4 e o vínculo
///   termina com sucesso;
/// - algum dos dois que não é primário é STATUS_INVALID_PARAMETER;
/// - uma cópia primária de cada um (SepDuplicateToken em KernelMode, sem
///   descritor); a sessão do completo ganha uma referência no silo de
///   servidor de quem chama (SepReferenceLogonSession), que a do filtrado
///   segura;
/// - cada sessão guarda a cópia do seu token e o LogonId da outra; a do
///   completo ganha o Flags 2 e a do filtrado o Flags 4;
/// - as duas cópias deixam de referenciar a sessão
///   (SepStopReferencingLogonSession), que as segura.
/// Uma falha solta as cópias já feitas. Devolve o NTSTATUS.
pub fn link_sessions(full: u64, limited: u64) -> u32 {
    let identity = |token: u64| tokens::with(token, |record| (record.authentication_id, record.server_silo, record.kind));
    let (Some((full_id, full_silo, full_kind)), Some((limited_id, limited_silo, limited_kind))) = (identity(full), identity(limited)) else { return STATUS_INVALID_PARAMETER };
    match find(limited_id, limited_silo) {
        None => return STATUS_NO_SUCH_LOGON_SESSION,
        Some(session) if session.token != 0 => return STATUS_INVALID_PARAMETER,
        Some(_) => {}
    }
    if (full_id, full_silo) == (limited_id, limited_silo) {
        with_sessions(|sessions| {
            if let Some(session) = sessions.iter_mut().find(|session| session.logon_id == limited_id && session.server_silo == limited_silo) {
                session.flags |= SESSION_LIMITED_LINK;
            }
        });
        return 0;
    }
    if full_kind != 1 || limited_kind != 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let status_of = |error: KernelError| if error.status != 0 { error.status } else { STATUS_INSUFFICIENT_RESOURCES };
    let full_copy = match tokens::duplicate(full, 0, false, 1) {
        Ok(copy) => copy,
        Err(error) => return status_of(error),
    };
    let limited_copy = match tokens::duplicate(limited, 0, false, 1) {
        Ok(copy) => copy,
        Err(error) => {
            let _ = tokens::release(full_copy);
            return status_of(error);
        }
    };
    if !reference_for_token(full_id, crate::ntos::ps::silo::query::current_server_silo()) {
        let _ = tokens::release(limited_copy);
        let _ = tokens::release(full_copy);
        return STATUS_NO_SUCH_LOGON_SESSION;
    }
    let (full_stored, limited_stored) = with_sessions(|sessions| {
        let (mut full_stored, mut limited_stored) = (false, false);
        for session in sessions.iter_mut() {
            if session.logon_id == full_id && session.server_silo == full_silo {
                session.token = full_copy;
                session.buddy_logon_id = limited_id;
                session.flags |= SESSION_FULL_LINK;
                full_stored = true;
            } else if session.logon_id == limited_id && session.server_silo == limited_silo {
                session.token = limited_copy;
                session.buddy_logon_id = full_id;
                session.flags |= SESSION_LIMITED_LINK;
                limited_stored = true;
            }
        }
        (full_stored, limited_stored)
    });
    tokens::stop_referencing_logon_session(limited_copy);
    tokens::stop_referencing_logon_session(full_copy);
    // As cópias referenciam as sessões até aqui, então as duas existiam;
    // uma cópia sem sessão que a guarde não fica viva.
    for (stored, copy) in [(full_stored, full_copy), (limited_stored, limited_copy)] {
        if !stored {
            let _ = tokens::release(copy);
        }
    }
    0
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
            release_device_map(&session);
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
        reference_entry(session);
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
/// sai do banco; a do token filtrado de um par do UAC (Flags 4) solta a
/// referência que segura na sessão irmã (o SepDeReferenceLogonSession do
/// BuddyLogonId, quando não é zero); o token de sessão é solto, com a
/// marca de término os file systems são avisados e, por fim, o LSA (o
/// SepInformLsaOfDeletedLogon, `se/lsa_call.rs`).
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
    if session.flags & SESSION_LIMITED_LINK != 0 && session.buddy_logon_id != 0 {
        dereference_for_token(session.buddy_logon_id, session.server_silo);
    }
    if session.token != 0 {
        let _ = tokens::release(session.token);
    }
    release_device_map(&session);
    if session.flags & SESSION_TERMINATION_NOTIFY != 0 {
        inform_file_systems(session.logon_id, session.server_silo);
    }
    crate::ntos::se::lsa_call::inform_lsa_of_deleted_logon(session.logon_id, session.server_silo);
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

/// O pDeviceMap da sessão (0 sem mapa; `None` sem a sessão).
pub fn device_map(logon_id: u64, server_silo: u64) -> Option<u64> {
    find(logon_id, server_silo).map(|session| session.device_map)
}

/// O diretório de devices DOS de um LogonId: `\Sessions\<sessão de
/// serviço>\DosDevices\<HighPart>-<LowPart>`, com a sessão de serviço 0 do
/// silo hospedeiro (PsGetServerSiloServiceSessionId).
pub fn dos_devices_directory_name(logon_id: u64) -> alloc::string::String {
    alloc::format!("\\Sessions\\0\\DosDevices\\{:08x}-{:08x}", logon_id >> 32, logon_id & 0xFFFF_FFFF)
}

/// O status de uma falha interna como NTSTATUS (STATUS_UNSUCCESSFUL sem um).
fn status_of(error: KernelError) -> u32 {
    if error.status != 0 { error.status } else { 0xC000_0001 }
}

/// SeGetTokenDeviceMap(Token, DeviceMap*): o mapa de devices DOS da sessão
/// de logon do token, sem referência própria (a sessão o retém).
pub fn token_device_map(token: u64) -> Result<u64, u32> {
    use crate::ntos::ob::device_map;
    use crate::ntos::ob::handles::namespace as namespace_handles;
    /// DIRECTORY_ALL_ACCESS, SYMBOLIC_LINK_ALL_ACCESS e os atributos do NT:
    /// OBJ_CASE_INSENSITIVE | OBJ_OPENIF | OBJ_KERNEL_HANDLE (0x2C0), e o
    /// link com OBJ_PERMANENT (0x2D0).
    const DIRECTORY_ALL_ACCESS: u32 = 0xF000F;
    const SYMBOLIC_LINK_ALL_ACCESS: u32 = 0xF0001;
    const DIRECTORY_ATTRIBUTES: u32 = 0x2C0;
    const LINK_ATTRIBUTES: u32 = 0x2D0;
    if token == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if tokens::body(token).token_flags.get() & tokens::TOKEN_SESSION_NOT_REFERENCED != 0 {
        return Err(STATUS_NO_SUCH_LOGON_SESSION);
    }
    let Some(Some((logon_id, server_silo))) = tokens::with(token, |record| record.logon_reference) else { return Err(STATUS_NO_SUCH_LOGON_SESSION) };
    match device_map(logon_id, server_silo) {
        None => return Err(STATUS_NO_SUCH_LOGON_SESSION),
        Some(existing) if existing != 0 => return Ok(existing),
        Some(_) => {}
    }
    let authentication_id = tokens::with(token, |record| record.authentication_id).unwrap_or(logon_id);
    let directory = namespace_handles::create_directory_from_kernel(0, &dos_devices_directory_name(authentication_id), DIRECTORY_ALL_ACCESS, DIRECTORY_ATTRIBUTES)?;
    let result = (|| -> Result<u64, u32> {
        let created = match device_map::set_device_map(0, directory, 0, device_map::SET_GLOBAL_DIRECTORY) {
            Ok(Ok(created)) => created,
            Ok(Err(status)) => return Err(status),
            Err(error) => return Err(status_of(error)),
        };
        match namespace_handles::create_link_named_from_kernel(directory, "Global", SYMBOLIC_LINK_ALL_ACCESS, LINK_ATTRIBUTES, "\\Global??") {
            Ok(link) => {
                let _ = crate::ntos::ob::close::close(link, Some(0));
            }
            Err(status) => {
                device_map::dereference(created);
                return Err(status);
            }
        }
        let installed = with_sessions(|sessions| {
            let session = sessions.iter_mut().find(|session| session.logon_id == logon_id && session.server_silo == server_silo)?;
            if session.device_map == 0 {
                session.device_map = created;
            }
            Some(session.device_map)
        });
        if installed != Some(created) {
            device_map::dereference(created);
        }
        installed.ok_or(STATUS_NO_SUCH_LOGON_SESSION)
    })();
    let _ = crate::ntos::ob::close::close(directory, Some(0));
    result
}

/// SepCleanupLUIDDeviceMapDirectory(LogonId*, Silo): os links do diretório
/// de devices DOS da sessão viram temporários (o ZwMakeTemporaryObject de
/// cada um, aberto e fechado em seguida) e saem do namespace.
fn cleanup_device_map_directory(logon_id: u64) {
    use crate::ntos::ob::object_manager;
    let Some(directory) = object_manager::resolve_from(&dos_devices_directory_name(logon_id), 0, true, false, object_manager::ROOT).0 else { return };
    let children = object_manager::node(directory).and_then(|node| node.children).unwrap_or_default();
    for (_, child) in children {
        if object_manager::node(child).is_none_or(|node| node.type_name != "SymbolicLink") {
            continue;
        }
        if let Ok(Some(body)) = crate::ntos::ob::objects::namespace::ensure(child) {
            crate::ntos::ob::handles::namespace::make_temporary_by_pointer(body);
        }
    }
}

/// A saída do mapa de uma sessão apagada: a limpeza do diretório e o
/// ObfDereferenceDeviceMap.
fn release_device_map(session: &LogonSession) {
    if session.device_map != 0 {
        cleanup_device_map_directory(session.logon_id);
        crate::ntos::ob::device_map::dereference(session.device_map);
    }
}
