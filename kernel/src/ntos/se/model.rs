//! Tipos compartilhados do modelo de segurança: os objetos `{ sid, mask,
//! deny, flags }`, `{ sid, attributes }` e as políticas `{ owner, group,
//! dacl }` que os módulos de `ntos/se` e `ntos/ob` trocam entre si.

use alloc::vec::Vec;

/// SID serializado (revision, count, autoridade big-endian, subautoridades).
pub type Sid = Vec<u8>;

/// Entrada de ACL. `sid` ausente marca uma ACE não suportada (só `raw`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub sid: Option<Sid>,
    pub mask: u32,
    pub deny: bool,
    pub flags: u8,
    pub raw: Option<Vec<u8>>,
}

impl Ace {
    pub fn allow(sid: Sid, mask: u32) -> Self {
        Self { sid: Some(sid), mask, deny: false, flags: 0, raw: None }
    }
}

/// Grupo de token (ou SID restrito / capacidade).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Group {
    pub sid: Sid,
    pub attributes: u32,
}

/// Privilégio: LUID e atributos (2 = SE_PRIVILEGE_ENABLED).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Privilege {
    pub id: u64,
    pub attributes: u32,
}

/// Segurança capturada por um objeto (dono, grupo, DACL e opcionais).
/// `dacl: None` é uma DACL nula (acesso total).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SecurityPolicy {
    pub owner: Sid,
    pub group: Option<Sid>,
    pub dacl: Option<Vec<Ace>>,
    pub sacl: Option<Vec<u8>>,
    pub dacl_bytes: Option<Vec<u8>>,
    /// Nível de integridade obrigatório do objeto, quando definido.
    pub integrity: Option<u32>,
    /// Campo Control do descritor capturado, quando veio de um descritor.
    pub control: Option<u16>,
}

pub fn equal_sids(left: &[u8], right: &[u8]) -> bool {
    left == right
}

/// A SACL (os bytes da ACL) pede SeSecurityPrivilege a quem a define: só as
/// ACEs de auditoria e alarme pedem. As de rótulo e de política
/// (SYSTEM_MANDATORY_LABEL 0x11, SYSTEM_RESOURCE_ATTRIBUTE 0x12,
/// SYSTEM_SCOPED_POLICY_ID 0x13, SYSTEM_PROCESS_TRUST_LABEL 0x14,
/// SYSTEM_ACCESS_FILTER 0x15) não: o rótulo de integridade e o de confiança
/// de um processo protegido seguem regras próprias. Uma ACL malformada pede.
pub fn sacl_requires_security_privilege(sacl: &[u8]) -> bool {
    // ACL: AclRevision, Sbz1, AclSize (u16), AceCount (u16), Sbz2; depois as
    // ACEs, cada uma com AceType, AceFlags e AceSize (u16).
    if sacl.len() < 8 {
        return !sacl.is_empty();
    }
    let count = u16::from_le_bytes([sacl[4], sacl[5]]) as usize;
    let mut offset = 8;
    for _ in 0..count {
        if offset + 4 > sacl.len() {
            return true;
        }
        let (kind, size) = (sacl[offset], u16::from_le_bytes([sacl[offset + 2], sacl[offset + 3]]) as usize);
        if !(0x11..=0x15).contains(&kind) || size < 4 {
            return true;
        }
        offset += size;
    }
    false
}

/// Serializa a autoridade em seis bytes big-endian e as subautoridades ULONG
/// em little-endian.
pub fn sid(authority: u64, sub_authorities: &[u32]) -> Sid {
    let mut bytes = alloc::vec![0u8; 8 + sub_authorities.len() * 4];
    bytes[0] = 1;
    bytes[1] = sub_authorities.len() as u8;
    let mut value = authority;
    for index in (2..=7).rev() {
        bytes[index] = (value % 256) as u8;
        value /= 256;
    }
    for (index, part) in sub_authorities.iter().enumerate() {
        bytes[8 + index * 4..12 + index * 4].copy_from_slice(&part.to_le_bytes());
    }
    bytes
}
