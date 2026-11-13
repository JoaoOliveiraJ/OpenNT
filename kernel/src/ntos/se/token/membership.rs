//! RtlCheckTokenMembership(Ex) / SeTokenIsMember.

use alloc::vec::Vec;

use crate::ntos::se::token::{thread as thread_tokens, capability_access as token_capability_access, handles as token_handles, tokens};
use crate::ntos::ob::{object_types, open_pointer};
use crate::ntos::ps::{previous_mode, process};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// A consulta sem flags usa a mesma ACL de membership Ex com flags zero.
pub fn contains(token: u64, identifier: Option<&[u8]>) -> bool {
    token_capability_access::permits_membership(token, identifier, 0)
}

/// Bytes do SID de kernel; o construtor nativo da ACL rejeita endereços de
/// usuário antes de ler.
pub fn read_security_identifier(pointer: u64) -> Option<Vec<u8>> {
    if pointer <= 0x7FFF_FFFF_0000 {
        return None;
    }
    let count = guest::read8(pointer + 1);
    if guest::read8(pointer) & 15 != 1 || count > 15 {
        return None;
    }
    Some(guest::read_bytes(pointer, 8 + count as usize * 4))
}

/// Contexto da avaliação: modo anterior e nível da impersonação capturada.
pub struct Context {
    pub previous_mode: u8,
    pub client_level: Option<u32>,
}

/// Captura a identidade atual (handle 0) ou duplica um handle explícito;
/// todo recurso é liberado também quando a avaliação falha.
pub fn with_token(handle: u64, evaluate: impl FnOnce(u64, &Context) -> Result<u32, KernelError>) -> Result<u32, KernelError> {
    let previous = previous_mode::get()?;
    let mut referenced = 0u64;
    let mut token = 0u64;
    let mut private_handle = None;
    let mut primary = 0u64;
    let mut client: Option<thread_tokens::Impersonation> = None;
    let result = (|| -> Result<u32, KernelError> {
        if handle != 0 {
            let status = previous_mode::with_kernel(|| -> Result<u32, KernelError> {
                let output = guest::alloc_bytes(8);
                if output == 0 {
                    return Ok(0xC000_009A);
                }
                let outcome = (|| -> Result<u32, KernelError> {
                    let status = open_pointer::reference_handle(handle, 2, object_types::token_type().pointer, 0, output, 0)?.unwrap_or(0xC000_0008);
                    if status != 0 {
                        return Ok(status);
                    }
                    referenced = guest::read64(output);
                    let Some((kind, level)) = tokens::with(referenced, |record| (record.kind, record.impersonation_level)) else {
                        return Err(KernelError::new("referenced token has no security record"));
                    };
                    if kind == 2 && level < 2 {
                        return Ok(0xC000_00A5);
                    }
                    token = tokens::duplicate(referenced, 2, false, 2)?;
                    private_handle = Some(token_handles::create(token, 8, 0x200, false)?);
                    Ok(0)
                })();
                guest::free_bytes(output);
                outcome
            })??;
            if status != 0 {
                return Ok(status);
            }
        } else {
            let Some(primary_token) = process::get_primary_token(process::get_current_process()) else { return Ok(0xC000_007C) };
            primary = primary_token;
            tokens::retain(primary)?;
            client = thread_tokens::get(process::get_current_thread());
            if let Some(impersonation) = client {
                tokens::retain(impersonation.token)?;
            }
            token = client.map_or(primary, |impersonation| impersonation.token);
        }
        evaluate(token, &Context { previous_mode: previous, client_level: client.map(|impersonation| impersonation.level) })
    })();
    // Handle privado, origem, cópia e identidade capturada têm donos distintos.
    if let Some(private) = private_handle {
        let _ = previous_mode::with_kernel(|| token_handles::close_native(private));
    }
    if referenced != 0 {
        if token != 0 {
            tokens::release(token)?;
        }
        tokens::release(referenced)?;
    }
    if let Some(impersonation) = client {
        tokens::release(impersonation.token)?;
    }
    if primary != 0 {
        tokens::release(primary)?;
    }
    match result {
        Err(error) if error.status != 0 => Ok(error.status),
        other => other,
    }
}

/// Membership num BOOLEAN. KernelMode conserva a regra medida no
/// SeAccessCheck original; UserMode verifica a ACL e a impersonação.
pub fn check(handle: u64, sid_pointer: u64, output: u64) -> Result<u32, KernelError> {
    guest::write8(output, 0);
    with_token(handle, |token, context| {
        let identifier = read_security_identifier(sid_pointer);
        if context.previous_mode != 0 && context.client_level.is_some_and(|level| level < 2) {
            return Ok(0xC000_00A5);
        }
        if context.previous_mode == 0 || contains(token, identifier.as_deref()) {
            guest::write8(output, 1);
        }
        Ok(0)
    })
}
