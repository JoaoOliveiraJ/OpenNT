//! Segurança dos objetos de callback — `system32/ntos/ex/callback-security.js`.
//!
//! Captura cópias próprias dos componentes do descritor e avalia direitos
//! sobre essa cópia; os buffers do chamador não ficam retidos pelo objeto.

use alloc::vec::Vec;

use crate::ntos::ob::object_access;
use crate::ntos::se::model::{equal_sids, Ace, SecurityPolicy};
use crate::ntos::se::{descriptor, sid};
use crate::ntos::se::token::tokens;
use crate::ntos::mm::guest_memory as guest;

/// Direitos aceitos pelo tipo Callback, incluindo os padrão do objeto.
const VALID_CALLBACK_ACCESS: u32 = 0x1F_0001;

/// Valida e captura o descritor. Ponteiro zero seleciona dono, grupo e DACL
/// padrão do token. `Err(NTSTATUS)` nas falhas.
pub fn capture(pointer: u64) -> Result<SecurityPolicy, u32> {
    let Some(token) = object_access::subject() else { return Err(0xC000_007C) };
    let Some(mut policy) = tokens::with(token, |token| SecurityPolicy {
        owner: token.owner.clone(),
        group: Some(token.primary_group.clone()),
        dacl: token.default_dacl.clone(),
        ..SecurityPolicy::default()
    }) else {
        return Err(0xC000_007C);
    };
    if pointer == 0 {
        return Ok(policy);
    }
    if !descriptor::valid(pointer) {
        return Err(0xC000_0079);
    }
    let control = descriptor::control(pointer);
    policy.control = Some(control);
    // Offsets no descritor autocontido; ponteiros de 64 bits no absoluto.
    let component = |index: u64| -> u64 {
        if control & 0x8000 != 0 {
            let offset = guest::read32(pointer + 4 + index * 4);
            if offset != 0 { pointer + offset as u64 } else { 0 }
        } else {
            guest::read64(pointer + 8 + index * 8)
        }
    };
    let owner = component(0);
    if owner != 0 {
        policy.owner = sid::read(owner);
    }
    let group = component(1);
    if group != 0 {
        policy.group = Some(sid::read(group));
    }
    // Os bytes da SACL são preservados; esta rotina não executa auditoria.
    if control & 16 != 0 {
        let value = component(2);
        if value != 0 {
            policy.sacl = Some(guest::read_bytes(value, guest::read16(value + 2) as usize));
        }
    }
    if control & 4 != 0 {
        let value = component(3);
        policy.dacl = None;
        if value != 0 {
            policy.dacl_bytes = Some(guest::read_bytes(value, guest::read16(value + 2) as usize));
            let mut entries = Vec::new();
            let mut offset = 8u64;
            for _ in 0..guest::read16(value + 4) {
                let entry = value + offset;
                let ace_type = guest::read8(entry);
                let length = guest::read16(entry + 2) as u64;
                let flags = guest::read8(entry + 1);
                let mask = guest::read32(entry + 4);
                // Permitir/negar simples expõem SID e máscara; o resto conserva os bytes.
                if ace_type == 0 || ace_type == 1 {
                    entries.push(Ace { sid: Some(sid::read(entry + 8)), mask, deny: ace_type == 1, flags, raw: None });
                } else {
                    entries.push(Ace { sid: None, mask, deny: false, flags, raw: Some(guest::read_bytes(entry, length as usize)) });
                }
                offset += length;
            }
            policy.dacl = Some(entries);
        }
    }
    Ok(policy)
}

/// READ, WRITE, EXECUTE e ALL para os direitos do tipo Callback.
fn map_generic_access(mask: u32) -> u32 {
    let mut mask = mask;
    for (flag, value) in [(0x8000_0000u32, 0x20000u32), (0x4000_0000, 0x20001), (0x2000_0000, 0x12_0000), (0x1000_0000, VALID_CALLBACK_ACCESS)] {
        if mask & flag != 0 {
            mask |= value;
        }
    }
    mask & 0x0FFF_FFFF
}

/// Separa direitos explícitos de MAXIMUM_ALLOWED, verifica privilégios e
/// percorre a DACL em ordem. `Ok(máscara)` ou `Err(NTSTATUS)`.
pub fn access(policy: &SecurityPolicy, requested: u32, enforce: bool) -> Result<u32, u32> {
    let mask = map_generic_access(requested);
    let explicit = mask & !0x0200_0000;
    let maximum_allowed = mask & 0x0200_0000 != 0;
    if explicit & !(VALID_CALLBACK_ACCESS | 0x0100_0000) != 0 {
        return Err(0xC000_0022);
    }
    if !enforce {
        return Ok(explicit | if maximum_allowed { VALID_CALLBACK_ACCESS } else { 0 });
    }
    let Some(token) = object_access::subject() else { return Err(0xC000_007C) };
    let Some((user, groups, privileges)) = tokens::with(token, |token| (token.user.clone(), token.groups.clone(), token.privileges.clone())) else {
        return Err(0xC000_007C);
    };
    let enabled = |id: u64| privileges.iter().any(|privilege| privilege.id == id && privilege.attributes & 2 != 0);
    if explicit & 0x0100_0000 != 0 && !enabled(8) {
        return Err(0xC000_0061);
    }
    // O dono começa com READ_CONTROL e WRITE_DAC.
    let mut granted = if equal_sids(&policy.owner, &user) { 0x60000 } else { 0 };
    let mut denied = 0;
    if enabled(9) {
        granted |= 0x80000;
    }
    match &policy.dacl {
        None => granted |= VALID_CALLBACK_ACCESS,
        Some(entries) => {
            for ace in entries {
                // INHERIT_ONLY não vale para o próprio objeto.
                if ace.flags & 8 != 0 {
                    continue;
                }
                // Uma entrada estendida sem avaliador não concede em silêncio.
                let Some(ace_sid) = &ace.sid else {
                    if explicit & !granted != 0 || maximum_allowed {
                        return Err(0xC000_00BB);
                    }
                    continue;
                };
                // Grupos habilitados concedem; grupos só de negação só negam.
                let matches = equal_sids(ace_sid, &user)
                    || groups.iter().any(|group| equal_sids(&group.sid, ace_sid) && ((group.attributes & 4 != 0 && group.attributes & 16 == 0) || (ace.deny && group.attributes & 16 != 0)));
                if !matches {
                    continue;
                }
                let rights = map_generic_access(ace.mask) & VALID_CALLBACK_ACCESS;
                if ace.deny {
                    denied |= rights & !granted;
                } else {
                    granted |= rights & !denied;
                }
            }
        }
    }
    if explicit & 0x0100_0000 != 0 {
        granted |= 0x0100_0000;
    }
    if explicit & !granted != 0 {
        return Err(0xC000_0022);
    }
    Ok(explicit | if maximum_allowed { granted } else { 0 })
}
