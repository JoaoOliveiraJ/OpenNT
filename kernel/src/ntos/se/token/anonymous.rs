//! Tokens anônimos do sistema.
//!
//! Cada variante (com e sem Everyone) tem uma referência permanente do
//! sistema, como os dois SeAnonymousLogonToken do kernel original.

use alloc::vec;

use crate::ntos::se::model::{sid, Ace, Group, SecurityPolicy};
use crate::ntos::se::token::tokens;
use crate::rtl::{KernelError, SpinLock};

static SYSTEM_TOKENS: SpinLock<[u64; 2]> = SpinLock::new([0; 2]);

/// A primeira aquisição cria o corpo da variante.
fn system_token(include_everyone: bool) -> Result<u64, KernelError> {
    let index = include_everyone as usize;
    let existing = SYSTEM_TOKENS.lock()[index];
    if existing != 0 {
        return Ok(existing);
    }
    let initialize = move |identity: &mut tokens::Token| {
        let anonymous = sid(5, &[7]);
        let everyone = sid(1, &[0]);
        let untrusted = sid(16, &[0]);
        identity.authentication_id = 0x3E6;
        // TIME_FIELDS {3000, 1, 1, 1, 1, 1, 1}: prazo do token anônimo original.
        identity.expiration_time = 441_481_572_610_010_000;
        identity.user = anonymous.clone();
        identity.owner = anonymous.clone();
        identity.primary_group = anonymous.clone();
        identity.integrity = untrusted.clone();
        identity.groups = if include_everyone { vec![Group { sid: everyone.clone(), attributes: 7 }] } else { vec![] };
        identity.groups.push(Group { sid: untrusted, attributes: 0x60 });
        identity.privileges = vec![];
        let dacl = vec![Ace::allow(everyone.clone(), 0xF01FF), Ace::allow(anonymous, 0xF01FF)];
        identity.default_dacl = Some(dacl.clone());
        identity.security = SecurityPolicy { owner: everyone.clone(), group: Some(everyone), dacl: Some(dacl), ..SecurityPolicy::default() };
    };
    let token = tokens::create(None, Some(&initialize))?;
    SYSTEM_TOKENS.lock()[index] = token;
    Ok(token)
}

/// Token anônimo para a chamada (a referência devolvida pertence ao
/// chamador) e o CopyOnOpen. AppContainer e server silo exigem tokens
/// privados de seu escopo.
pub fn acquire(subject: u64, include_everyone: bool, server_silo: u64, session_id: i64) -> Result<(u64, bool), KernelError> {
    let Some((app_container, capabilities, subject_session, network_flags)) =
        tokens::with(subject, |token| (token.app_container.clone(), token.capabilities.clone(), token.session_id, token.network_access_flags))
    else {
        return Err(KernelError::new("anonymous token subject is not a live token"));
    };
    let shared = system_token(app_container.is_none() && server_silo == 0 && include_everyone)?;
    let network_access_flags = network_flags & 0x38_0000;
    if app_container.is_none() && server_silo == 0 && network_access_flags == 0 {
        tokens::retain(shared)?;
        return Ok((shared, true));
    }
    let token = tokens::duplicate(shared, 2, false, 2)?;
    tokens::update(token, |record| {
        if let Some(container) = &app_container {
            record.app_container = Some(container.clone());
            record.capabilities = capabilities.clone();
            record.session_id = subject_session;
            record.network_access_flags = network_access_flags;
        } else if server_silo != 0 {
            // O ramo de silo usa a variante sem Everyone e não herda direitos.
            record.server_silo = server_silo;
            if session_id != 0xFFFF_FFFF && session_id != -1 {
                record.session_id = session_id as u32;
            }
        } else {
            record.network_access_flags = network_access_flags;
        }
    });
    Ok((token, server_silo == 0 || app_container.is_some()))
}
