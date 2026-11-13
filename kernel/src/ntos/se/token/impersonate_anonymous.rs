//! Nt/ZwImpersonateAnonymousToken.

use crate::ntos::se::token::{anonymous as anonymous_tokens, thread as thread_tokens, tokens};
use crate::ntos::cm::registry;
use crate::ntos::ke::irql;
use crate::ntos::ob::handles::thread as thread_handles;
use crate::ntos::ps::process;
use crate::ntos::ps::silo::query as silo_query;
use crate::rtl::KernelError;
use crate::ntos::inc::types::{Ejob, EserversiloGlobals, Ethread, NtStruct, SiloUserSharedData};

const POLICY_PATH: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Lsa";

/// Política ausente, de outro tipo ou com tamanho inválido segue o padrão.
fn policy(name: &str) -> u32 {
    match registry::read_value_by_path(POLICY_PATH, name) {
        Some(value) if value.value_type == 4 && value.data.len() == 4 => u32::from_le_bytes([value.data[0], value.data[1], value.data[2], value.data[3]]),
        _ => 0,
    }
}

/// A identidade anônima dispensa SeImpersonatePrivilege; o AppContainer
/// ainda limita a thread ao próprio pacote ou a um pacote filho.
fn permits_package(primary: Option<&[u8]>, anonymous: Option<&[u8]>) -> bool {
    let Some(primary) = primary else { return true };
    let Some(anonymous) = anonymous else { return false };
    if primary == anonymous {
        return true;
    }
    if primary.len() != 40
        || anonymous.len() != 56
        || primary[0] != 1
        || primary[1] != 8
        || anonymous[0] != 1
        || anonymous[1] != 12
        || primary[2..7].iter().any(|&byte| byte != 0)
        || primary[7] != 15
        || primary[8] != 2
        || primary[9..12].iter().any(|&byte| byte != 0)
    {
        return false;
    }
    primary.iter().enumerate().all(|(index, &byte)| index == 1 || byte == anonymous[index])
}

/// Atribui à thread alvo o token anônimo do escopo do chamador.
pub fn impersonate(thread_handle: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("anonymous impersonation requires PASSIVE_LEVEL"));
    }
    let mut target = match thread_handles::reference(thread_handle, 0x100, access_mode)? {
        Ok(target) => target,
        Err(status) => return Ok(status),
    };
    let primary = process::get_primary_token(process::get_current_process());
    let client = thread_tokens::get(process::get_current_thread());
    let subject = client.map(|client| client.token).or(primary);
    let mut identity: Option<u64> = None;
    let mut primary_retained = false;
    let mut client_retained = false;
    let result = (|| -> Result<u32, KernelError> {
        let (Some(primary), Some(subject)) = (primary, subject) else { return Ok(0xC000_0001) };
        tokens::retain(primary)?;
        primary_retained = true;
        if client.is_some() {
            tokens::retain(subject)?;
            client_retained = true;
        }
        let subject_info = tokens::with(subject, |token| (token.kind, token.impersonation_level, token.app_container.clone())).ok_or_else(|| KernelError::new("anonymous impersonation subject vanished"))?;
        let primary_info = tokens::with(primary, |token| (token.app_container.clone(), !token.restricted_sids.is_empty(), token.write_restricted)).ok_or_else(|| KernelError::new("anonymous impersonation primary vanished"))?;
        if policy("AnonymousAppContainerImpersonationLevelCheck") == 0 && subject_info.0 != 1 && primary_info.0.is_some() && subject_info.1 < 2 {
            return Ok(0xC000_00A5);
        }
        // O ramo AppContainer precede Everyone e a restrição do primário.
        let include_everyone = subject_info.2.is_none() && policy("EveryoneIncludesAnonymous") == 1;
        let server_silo = if subject_info.2.is_some() { 0 } else { silo_query::current_server_silo() };
        // PsGetSiloSessionId consulta SILO_USER_SHARED_DATA.
        let mut session_id = -1i64;
        if server_silo != 0 {
            // SAFETY: server silo vivo com globais e SILO_USER_SHARED_DATA publicados.
            session_id = unsafe {
                let globals = Ejob::at(server_silo).server_silo_globals.get();
                let shared = EserversiloGlobals::at(globals).user_shared_data.get();
                SiloUserSharedData::at(shared).service_session_id.get() as i64
            };
        }
        let (mut token, copy_on_open) = anonymous_tokens::acquire(subject, include_everyone, server_silo, session_id)?;
        identity = Some(token);
        if subject_info.2.is_none() && primary_info.1 && !primary_info.2 {
            return Ok(0xC000_0022);
        }
        // SAFETY: thread alvo referenciada pelo handle (ETHREAD).
        let owner_process = unsafe { Ethread::at(target.pointer) }.tcb.process.get();
        let owner_container = process::get_primary_token(owner_process).map(|owner| tokens::with(owner, |token| token.app_container.clone()).flatten());
        let anonymous_container = tokens::with(token, |token| token.app_container.clone()).flatten();
        let mut level = 2;
        if let Some(owner_container) = owner_container {
            if !permits_package(owner_container.as_deref(), anonymous_container.as_deref()) {
                // PsImpersonateClient reduz à identificação quando o pacote
                // destino não pode agir com a identidade do cliente.
                let identification = tokens::duplicate(token, 1, false, 2)?;
                tokens::release(token)?;
                token = identification;
                identity = Some(token);
                level = 1;
            }
        }
        thread_tokens::assign(target.pointer, Some(token), level, copy_on_open, false)?;
        Ok(0)
    })();
    if let Some(token) = identity {
        let _ = tokens::release(token);
    }
    if client_retained {
        if let Some(subject) = subject {
            let _ = tokens::release(subject);
        }
    }
    if primary_retained {
        if let Some(primary) = primary {
            let _ = tokens::release(primary);
        }
    }
    target.release()?;
    match result {
        // Só falhas com NTSTATUS explícito viram retorno; as demais sobem.
        Err(error) if error.status != crate::ntos::inc::status::STATUS_UNSUCCESSFUL => Ok(error.status),
        other => other,
    }
}
