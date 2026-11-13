//! Tipos compartilhados do modelo de segurança: os objetos `{ sid, mask,
//! deny, flags }`, `{ sid, attributes }` e as políticas `{ owner, group,
//! dacl }` que os módulos de `ntos/se` e `ntos/ob` do original trocam entre si.

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

/// Serializa a autoridade em seis bytes big-endian e as subautoridades ULONG
/// em little-endian (`Tokens.sid`).
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
