//! Atribuição e ajuste do SECURITY_DESCRIPTOR de objetos novos
//! (SeAssignSecurity(Ex), SeDeassignSecurity e SeSetSecurityDescriptorInfo).
//!
//! Reusa `inherit_descriptor::assign` (herança) e `query_descriptor`
//! (leitura dos componentes); a serialização self-relative é a única
//! montagem nova, sobre as peças existentes. Os descritores publicados são
//! cópias self-relative alocadas na arena do convidado. As funções devolvem
//! o NTSTATUS.

use alloc::vec::Vec;

use crate::ntos::inc::types::{GenericMapping, NtStruct, SecuritySubjectContext};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::process;
use crate::ntos::se::inherit_descriptor::{self, Captured};
use crate::ntos::se::model::sid;
use crate::ntos::se::query_descriptor;
use crate::ntos::se::token::tokens;

// SECURITY_INFORMATION bits.
const OWNER_INFORMATION: u32 = 0x0000_0001;
const GROUP_INFORMATION: u32 = 0x0000_0002;
const DACL_INFORMATION: u32 = 0x0000_0004;
/// SACL(8) | LABEL(0x10) | ATTRIBUTE(0x20) | SCOPE(0x40) | TRUST(0x80) | FILTER(0x100).
const SACL_SELECTORS: u32 = 0x0000_01F8;

// SECURITY_DESCRIPTOR control bits.
const SELF_RELATIVE: u16 = 0x8000;
const DACL_PRESENT: u16 = 0x0004;
const DACL_DEFAULTED: u16 = 0x0008;
const SACL_PRESENT: u16 = 0x0010;
const SACL_DEFAULTED: u16 = 0x0020;
const DACL_AUTO_INHERITED: u16 = 0x0400;
const SACL_AUTO_INHERITED: u16 = 0x0800;
const DACL_PROTECTED: u16 = 0x1000;
const SACL_PROTECTED: u16 = 0x2000;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INVALID_SECURITY_DESCR: u32 = 0xC000_0079;

/// GENERIC_MAPPING (Read/Write/Execute/All). Map NULL só ocorre por engano
/// do chamador; nesse caso deixa os direitos específicos passarem.
fn read_mapping(map: u64) -> [u32; 4] {
    if map == 0 {
        return [0, 0, 0, 0xFFFF_FFFF];
    }
    // SAFETY: PGENERIC_MAPPING do chamador de SeAssignSecurity.
    let mapping = unsafe { GenericMapping::at(map) };
    [mapping.generic_read.get(), mapping.generic_write.get(), mapping.generic_execute.get(), mapping.generic_all.get()]
}

/// Lê um SECURITY_DESCRIPTOR (absoluto ou self-relative) do convidado para um
/// `Captured`; owner/group ausentes ficam vazios.
fn captured_from(pointer: u64) -> Option<Captured> {
    query_descriptor::read_descriptor(pointer).map(|descriptor| Captured {
        control: descriptor.control,
        owner: descriptor.owner.unwrap_or_default(),
        group: descriptor.group.unwrap_or_default(),
        dacl: descriptor.dacl,
        sacl: descriptor.sacl,
    })
}

/// Owner/group padrão para CREATOR OWNER/GROUP: do token primário do subject
/// context, com recuo ao token corrente e, em último caso, ao SYSTEM.
fn subject_owner_group(subject: u64) -> (Vec<u8>, Vec<u8>) {
    let mut token = 0;
    if subject != 0 {
        // SAFETY: PSECURITY_SUBJECT_CONTEXT do chamador.
        let context = unsafe { SecuritySubjectContext::at(subject) };
        let primary = context.primary_token.get();
        token = if primary != 0 { primary } else { context.client_token.get() };
    }
    if token == 0 {
        token = process::get_primary_token(process::get_current_process()).unwrap_or(0);
    }
    let default = || sid(5, &[18]);
    tokens::with(token, |token| (token.owner.clone(), token.primary_group.clone()))
        .map(|(owner, group)| (if owner.is_empty() { default() } else { owner }, if group.is_empty() { default() } else { group }))
        .unwrap_or_else(|| (default(), default()))
}

/// Captured -> SECURITY_DESCRIPTOR_RELATIVE. Ordem de campos indiferente; os
/// componentes do assign já são múltiplos de 4, mantendo o alinhamento que o
/// `descriptor::valid_relative` exige. (Montagem nova, sobre peças existentes.)
fn serialize_relative(descriptor: &Captured) -> Vec<u8> {
    let mut header = [0u8; 20];
    header[0] = 1;
    header[2..4].copy_from_slice(&(descriptor.control | SELF_RELATIVE).to_le_bytes());
    let mut body = Vec::new();
    let mut offset = 20u32;
    if !descriptor.owner.is_empty() {
        header[4..8].copy_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&descriptor.owner);
        offset += descriptor.owner.len() as u32;
    }
    if !descriptor.group.is_empty() {
        header[8..12].copy_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&descriptor.group);
        offset += descriptor.group.len() as u32;
    }
    if let Some(sacl) = &descriptor.sacl {
        header[12..16].copy_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(sacl);
        offset += sacl.len() as u32;
    }
    if let Some(dacl) = &descriptor.dacl {
        header[16..20].copy_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(dacl);
        offset += dacl.len() as u32;
    }
    let _ = offset;
    let mut bytes = Vec::with_capacity(20 + body.len());
    bytes.extend_from_slice(&header);
    bytes.extend_from_slice(&body);
    bytes
}

/// Serializa e publica `*out` com uma cópia pooled self-relative do descritor.
fn publish(descriptor: &Captured, out: u64) {
    let bytes = serialize_relative(descriptor);
    let pointer = guest::alloc_bytes(bytes.len() as u64);
    guest::write_bytes(pointer, &bytes);
    super::out::<u64>(out).set(pointer);
}

/// Núcleo comum de SeAssignSecurity/SeAssignSecurityEx: monta o `creator`
/// (owner/group explícitos ou do token) e delega a herança ao
/// `inherit_descriptor::assign`, que faz mapeamento genérico, CREATOR
/// OWNER/GROUP, AutoInherit e proteção. ObjectType (GUID) é ignorado.
pub fn assign(parent_ptr: u64, explicit_ptr: u64, out: u64, container: bool, auto_flags: u32, subject: u64, map: u64) -> u32 {
    if out == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mapping = read_mapping(map);
    let parent = captured_from(parent_ptr);
    let explicit = captured_from(explicit_ptr);
    let (owner_default, group_default) = subject_owner_group(subject);
    let creator = Captured {
        control: explicit.as_ref().map_or(0, |captured| captured.control),
        owner: explicit.as_ref().filter(|captured| !captured.owner.is_empty()).map_or(owner_default, |captured| captured.owner.clone()),
        group: explicit.as_ref().filter(|captured| !captured.group.is_empty()).map_or(group_default, |captured| captured.group.clone()),
        dacl: explicit.as_ref().and_then(|captured| captured.dacl.clone()),
        sacl: explicit.as_ref().and_then(|captured| captured.sacl.clone()),
    };
    match inherit_descriptor::assign(parent.as_ref(), &creator, &mapping, auto_flags & 3, container) {
        Ok(Ok(result)) => {
            publish(&result, out);
            0
        }
        Ok(Err(status)) => status,
        Err(_) => STATUS_INVALID_SECURITY_DESCR,
    }
}

/// SeDeassignSecurity: libera `*descriptor_pointer` e zera o ponteiro.
pub fn deassign(descriptor_pointer: u64) {
    let descriptor = super::out::<u64>(descriptor_pointer);
    let pointer = descriptor.get();
    if pointer != 0 {
        guest::free_bytes(pointer);
    }
    descriptor.set(0);
}

/// SeSetSecurityDescriptorInfo(Object, *Information, Modification, *ObjectSd,
/// Pool, Map). Mescla os componentes selecionados da Modification sobre o SD
/// atual, pooleia um novo SD self-relative e troca `*ObjectSd` (liberando o
/// antigo). Parcial: owner/group/DACL e troca inteira de SACL/label.
pub fn set_info(information_pointer: u64, modification: u64, object_sd_pointer: u64, map: u64) -> u32 {
    let information = super::out::<u32>(information_pointer).get();
    let object_sd = super::out::<u64>(object_sd_pointer);
    let current = captured_from(object_sd.get());
    let modification = captured_from(modification);
    let mapping = read_mapping(map);
    // Cada componente vem da Modification se o seu bit estiver em Information,
    // senão permanece o do objeto.
    let pick = |from_modification: bool| if from_modification { modification.as_ref() } else { current.as_ref() };
    let owner_source = pick(information & OWNER_INFORMATION != 0);
    let group_source = pick(information & GROUP_INFORMATION != 0);
    let dacl_source = pick(information & DACL_INFORMATION != 0);
    let sacl_source = pick(information & SACL_SELECTORS != 0);
    let mut control = 0u16;
    control |= dacl_source.map_or(0, |captured| captured.control) & (DACL_PRESENT | DACL_DEFAULTED | DACL_PROTECTED);
    control |= sacl_source.map_or(0, |captured| captured.control) & (SACL_PRESENT | SACL_DEFAULTED | SACL_PROTECTED);
    let merged = Captured {
        control,
        owner: owner_source.filter(|captured| !captured.owner.is_empty()).map_or_else(|| sid(5, &[18]), |captured| captured.owner.clone()),
        group: group_source.filter(|captured| !captured.group.is_empty()).map_or_else(|| sid(5, &[18]), |captured| captured.group.clone()),
        dacl: dacl_source.and_then(|captured| captured.dacl.clone()),
        sacl: sacl_source.and_then(|captured| captured.sacl.clone()),
    };
    // Reaproveita AutoInherit do assign para mapear genéricos e remontar ACLs.
    let flags = (dacl_source.map_or(0, |captured| captured.control) & DACL_AUTO_INHERITED != 0) as u32
        | (((sacl_source.map_or(0, |captured| captured.control) & SACL_AUTO_INHERITED != 0) as u32) << 1);
    match inherit_descriptor::assign(None, &merged, &mapping, flags, false) {
        Ok(Ok(result)) => {
            // O descritor anterior continua de quem chama (que o libera ou o
            // devolve ao cache do Ob, como o npfs faz com
            // ObDereferenceSecurityDescriptor): só o ponteiro é trocado.
            publish(&result, object_sd_pointer);
            0
        }
        Ok(Err(status)) => status,
        Err(_) => STATUS_INVALID_SECURITY_DESCR,
    }
}
