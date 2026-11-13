//! ZwDuplicateToken.
//!
//! O serviço Nt de UserMode ainda exige a política de redução de direitos de
//! RtlIsSandboxedToken antes de ser exposto.

use crate::ntos::se::model::{sid, Ace, SecurityPolicy};
use crate::ntos::se::descriptor;
use crate::ntos::se::token::{thread as thread_tokens, access as token_access, handles as token_handles, reference as token_reference, tokens};
use crate::ntos::alpc::message::buffer as message_buffer;
use crate::ntos::ex::callback_security;
use crate::ntos::ke::irql;
use crate::ntos::mm::section::create as create_section;
use crate::ntos::ps::process;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// SECURITY_QUALITY_OF_SERVICE (alinhamento ULONG), capturado antes da
/// resolução do handle. `Ok(None)` = sem QoS.
fn capture_quality(attributes: u64, mode: u8) -> Result<Option<u32>, u32> {
    if attributes == 0 {
        return Ok(None);
    }
    if mode != 0 && attributes & 3 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(attributes, 48, mode, false) {
        return Err(0xC000_0005);
    }
    let quality = guest::read64(attributes + 40);
    if quality == 0 {
        return Ok(None);
    }
    if mode != 0 && quality & 3 != 0 {
        return Err(0x8000_0002);
    }
    if !message_buffer::accessible(quality, 12, mode, false) {
        return Err(0xC000_0005);
    }
    if guest::read32(quality) != 12 || guest::read8(quality + 8) > 1 {
        return Err(0xC000_000D);
    }
    let level = guest::read32(quality + 4);
    if level > 3 { Err(0xC000_00A5) } else { Ok(Some(level)) }
}

fn privilege(subject: u64, identifier: u64, mode: u8) -> bool {
    mode == 0 || tokens::with(subject, |token| token.privileges.iter().any(|entry| entry.id == identifier && entry.attributes & 2 != 0)).unwrap_or(false)
}

/// A DACL do objeto guarda direitos de Token, já sem os bits GENERIC, e a
/// representação capturada acompanha.
fn map_creation_acl(policy: &mut SecurityPolicy) {
    let mut offset = 8usize;
    let Some(entries) = policy.dacl.as_mut() else { return };
    for entry in entries.iter_mut() {
        let ace_type = entry.raw.as_ref().map_or(entry.deny as u8, |raw| raw[0]);
        if ace_type <= 16 {
            entry.mask = token_access::map_generic_access(entry.mask);
            if let Some(raw) = entry.raw.as_mut() {
                raw[4..8].copy_from_slice(&entry.mask.to_le_bytes());
            }
            if let Some(bytes) = policy.dacl_bytes.as_mut() {
                if offset + 8 <= bytes.len() {
                    bytes[offset + 4..offset + 8].copy_from_slice(&entry.mask.to_le_bytes());
                }
            }
        }
        offset += entry.raw.as_ref().map_or_else(|| 8 + entry.sid.as_ref().map_or(0, |sid| sid.len()), |raw| raw.len());
    }
}

struct Creation {
    flags: u32,
    policy: SecurityPolicy,
}

fn capture_creation(attributes: u64, mode: u8, subject: u64) -> Result<Creation, u32> {
    let mut flags = 0;
    let mut security = 0;
    if attributes != 0 {
        if mode != 0 && attributes & 7 != 0 {
            return Err(0x8000_0002);
        }
        if guest::read32(attributes) != 48 {
            return Err(0xC000_000D);
        }
        flags = guest::read32(attributes + 24);
        // Token aceita EXCLUSIVE na criação, mas não OPENLINK nem bits indefinidos.
        if flags & !0x11EF2 != 0 {
            return Err(0xC000_000D);
        }
        if mode != 0 {
            flags &= !0x200;
        }
        let root = guest::read64(attributes + 8);
        let name = guest::read64(attributes + 16);
        if name != 0 {
            if mode != 0 && name & 7 != 0 {
                return Err(0x8000_0002);
            }
            if !message_buffer::accessible(name, 16, mode, false) {
                return Err(0xC000_0005);
            }
            // Tokens não são nomeados; um descritor vazio é aceito.
            if guest::read16(name) != 0 {
                return Err(0xC000_0033);
            }
        } else if root != 0 {
            return Err(0xC000_0033);
        }
        security = guest::read64(attributes + 32);
    }
    if flags & 0x10 != 0 && !privilege(subject, 16, mode) {
        return Err(0xC000_0061);
    }
    if security != 0 {
        if mode != 0 && security & 3 != 0 {
            return Err(0x8000_0002);
        }
        if mode != 0 && !create_section::descriptor_probe(security) {
            return Err(0xC000_0005);
        }
        if guest::read8(security) != 1 {
            return Err(0xC000_0058);
        }
        if !descriptor::valid(security) {
            return Err(0xC000_0079);
        }
    }
    let mut policy = callback_security::capture(security)?;
    if policy.sacl.is_some() && !privilege(subject, 8, mode) {
        return Err(0xC000_0061);
    }
    map_creation_acl(&mut policy);
    // Sem descritor explícito, SepFinalizeTokenAcls acrescenta TOKEN_QUERY
    // para BUILTIN\Administrators; uma DACL NULL continua NULL.
    if security == 0 {
        if let Some(dacl) = policy.dacl.as_mut() {
            let administrators = sid(5, &[32, 544]);
            if !dacl.iter().any(|entry| entry.sid.as_ref() == Some(&administrators)) {
                dacl.push(Ace { sid: Some(administrators), mask: 8, deny: false, flags: 0, raw: None });
            }
        }
    }
    Ok(Creation { flags, policy })
}

/// ZwDuplicateToken(ExistingToken, DesiredAccess, ObjectAttributes,
/// EffectiveOnly, TokenType, NewToken).
pub fn duplicate(existing: u64, access: u32, attributes: u64, effective_only: bool, token_type: u32, output: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("token duplication requires PASSIVE_LEVEL"));
    }
    let mode = access_mode;
    if token_type != 1 && token_type != 2 {
        return Ok(0xC000_000D);
    }
    if mode != 0 && !message_buffer::accessible(output, 8, mode, true) {
        return Ok(0xC000_0005);
    }
    let quality = match capture_quality(attributes, mode) {
        Ok(quality) => quality,
        Err(status) => return Ok(status),
    };
    let mut reference = match token_reference::reference(existing, 2, mode, false)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let mut created = 0;
    let result = (|| -> Result<u32, KernelError> {
        let source = reference.token;
        let Some((source_type, source_level)) = tokens::with(source, |token| (token.kind, token.impersonation_level)) else {
            return Ok(0xC000_0008);
        };
        let level = quality.unwrap_or(source_level);
        if source_type == 2 && ((token_type == 2 && level > source_level) || (token_type == 1 && source_level < 2)) {
            return Ok(0xC000_00A5);
        }
        let Some(subject) = thread_tokens::effective(process::get_current_thread(), false) else { return Ok(0xC000_007C) };
        let input = match capture_creation(attributes, mode, subject) {
            Ok(input) => input,
            Err(status) => return Ok(status),
        };
        // DesiredAccess zero herda a máscara do handle de origem; bits fora da
        // máscara válida são retirados na criação.
        let requested = if access != 0 { access } else { reference.granted_access };
        let mapped = token_access::map_generic_access(requested);
        let mut granted = (mapped & 0x1F_01FF) | if mapped & 0x0200_0000 != 0 { 0xF_01FF } else { 0 };
        if mapped & 0x0100_0000 != 0 {
            if !privilege(subject, 8, mode) {
                return Ok(0xC000_0061);
            }
            granted |= 0x0100_0000;
        }
        created = tokens::duplicate(source, level, effective_only, token_type)?;
        let current = process::get_current_process();
        tokens::update(created, |token| {
            token.security = input.policy.clone();
            if input.flags & 0x20 != 0 {
                token.exclusive_process = current;
            }
        });
        let handle = match token_handles::create(created, granted, input.flags, mode != 0) {
            Ok(handle) => handle,
            Err(error) if error.status != 0 => return Ok(error.status),
            Err(error) => return Err(error),
        };
        if input.flags & 0x10 != 0 {
            // OBJ_PERMANENT é uma referência de posse independente do handle.
            tokens::retain(created)?;
            tokens::update(created, |token| token.permanent = true);
        }
        // A cópia final vem depois da publicação; uma falha conserva a entrada
        // já pertencente ao processo.
        if !message_buffer::accessible(output, 8, mode, true) {
            return Ok(0xC000_0005);
        }
        guest::write64(output, handle);
        Ok(0)
    })();
    if created != 0 {
        tokens::release(created)?;
    }
    reference.release()?;
    result
}
