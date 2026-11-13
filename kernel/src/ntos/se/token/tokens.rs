//! Tokens de segurança e o seu armazenamento dinâmico.
//!
//! Processos de boot herdam o contexto de segurança do sistema. O endereço
//! nativo (corpo de 0x100 bytes) identifica o registro de identidade, grupos
//! e privilégios; consultas serializam esse estado nos layouts NT.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use crate::ntos::se::model::{sid, Ace, Group, Privilege, SecurityPolicy, Sid};
use crate::ntos::se::security_attributes::{self, SecurityAttribute};
use crate::ntos::ob::object_types;
use crate::ntos::inc::status::{STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES};
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;

#[derive(Clone, Debug)]
pub struct Token {
    pub pointer: u64,
    pub refs: u64,
    pub id: u64,
    pub modified_id: u64,
    pub authentication_id: u64,
    pub expiration_time: u64,
    pub user: Sid,
    pub user_attributes: u32,
    pub owner: Sid,
    pub primary_group: Sid,
    /// 1 = primário, 2 = impersonação.
    pub kind: u32,
    pub session_id: u32,
    pub integrity: Sid,
    pub groups: Vec<Group>,
    pub privileges: Vec<Privilege>,
    pub restricted_sids: Vec<Group>,
    pub write_restricted: bool,
    pub security_attributes: Vec<SecurityAttribute>,
    pub bno_prefix: String,
    pub app_container: Option<Sid>,
    pub capabilities: Vec<Group>,
    pub less_privileged_app_container: bool,
    pub server_silo: u64,
    pub network_access_flags: u32,
    /// DACL do objeto token (controla a abertura deste token).
    pub security: SecurityPolicy,
    /// TokenDefaultDacl: rege os objetos criados por esta identidade.
    pub default_dacl: Option<Vec<Ace>>,
    pub impersonation_level: u32,
    /// Processo dono de um token criado com OBJ_EXCLUSIVE (0 = compartilhado).
    pub exclusive_process: u64,
    /// OBJ_PERMANENT: referência de posse independente dos handles.
    pub permanent: bool,
}

struct Storage {
    pointer: u64,
    charged: u64,
    used: u64,
}

struct Tokens {
    records: BTreeMap<u64, Token>,
    storage: BTreeMap<u64, Storage>,
    next_identifier: u64,
}

static TOKENS: SpinLock<Tokens> = SpinLock::new(Tokens { records: BTreeMap::new(), storage: BTreeMap::new(), next_identifier: 0x1000 });

/// Um LUID novo, do mesmo contador dos identificadores de token (o
/// SeLuidCounter do NT): nenhum LUID se repete no sistema.
pub fn allocate_luid() -> u64 {
    let mut tokens = TOKENS.lock();
    let id = tokens.next_identifier;
    tokens.next_identifier += 1;
    id
}

/// ZwAllocateLocallyUniqueId: grava em `output` um LUID novo do contador
/// único. Ponteiro nulo (sem consumir LUID) ou não gravável dá
/// STATUS_ACCESS_VIOLATION; devolve o NTSTATUS.
pub fn allocate_luid_into(output: u64) -> u32 {
    if output == 0 {
        return STATUS_ACCESS_VIOLATION;
    }
    let luid = allocate_luid();
    if guest::try_write32(output, luid as u32).and_then(|_| guest::try_write32(output + 4, (luid >> 32) as u32)).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    0
}

// ---- armazenamento dinâmico ----------------------------------------------

/// ACL padrão com ACEs allow/deny e SID próprio.
fn encode_default_acl(entries: Option<&[Ace]>) -> Result<Vec<u8>, KernelError> {
    let Some(entries) = entries else { return Ok(Vec::new()) };
    let length: usize = 8 + entries.iter().map(|entry| 8 + entry.sid.as_ref().map_or(0, |sid| sid.len())).sum::<usize>();
    if length > 0xFFFF || entries.len() > 0xFFFF {
        return Err(KernelError::with_status("Token default ACL exceeds its native length", 0xC000_0077));
    }
    let mut bytes = alloc::vec![0u8; length];
    bytes[0] = 2;
    bytes[2..4].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&(entries.len() as u16).to_le_bytes());
    let mut at = 8;
    for entry in entries {
        let sid = entry.sid.clone().unwrap_or_default();
        bytes[at] = entry.deny as u8;
        bytes[at + 1] = entry.flags;
        bytes[at + 2..at + 4].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&entry.mask.to_le_bytes());
        bytes[at + 8..at + 8 + sid.len()].copy_from_slice(&sid);
        at += 8 + sid.len();
    }
    Ok(bytes)
}

fn create_storage(tokens: &mut Tokens, token: &Token) -> Result<(), KernelError> {
    if tokens.storage.contains_key(&token.pointer) {
        return Err(KernelError::new("Token dynamic storage already exists"));
    }
    let acl = encode_default_acl(token.default_dacl.as_deref())?;
    let used = (token.primary_group.len() + acl.len()) as u64;
    let charged = used.div_ceil(16) * 16;
    let pointer = guest::alloc_bytes(charged);
    if pointer == 0 {
        return Err(KernelError::with_status("Token dynamic storage allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    guest::write_bytes(pointer, &token.primary_group);
    guest::write_bytes(pointer + token.primary_group.len() as u64, &acl);
    tokens.storage.insert(token.pointer, Storage { pointer, charged, used });
    Ok(())
}

fn release_storage(tokens: &mut Tokens, token_pointer: u64) {
    if let Some(storage) = tokens.storage.remove(&token_pointer) {
        guest::free_bytes(storage.pointer);
    }
}

/// (DynamicCharged, DynamicAvailable) do proprietário da memória.
pub fn accounting(token_pointer: u64) -> Result<(u64, u64), KernelError> {
    let tokens = TOKENS.lock();
    let storage = tokens.storage.get(&token_pointer).ok_or_else(|| KernelError::new("Live token has no dynamic storage"))?;
    Ok((storage.charged, storage.charged - storage.used))
}

// ---- tokens ---------------------------------------------------------------

/// Cria um token primário, copiando o estado herdável do pai. O registro só
/// fica acessível depois de publicar os campos nativos e a referência inicial.
pub fn create(parent: Option<u64>, initialize: Option<&dyn Fn(&mut Token)>) -> Result<u64, KernelError> {
    let object_type = object_types::token_type();
    let pointer = guest::alloc_bytes(0x100);
    if pointer == 0 {
        return Err(KernelError::with_status("Token allocation failed", STATUS_INSUFFICIENT_RESOURCES));
    }
    let mut tokens = TOKENS.lock();
    let parent = parent.and_then(|parent| tokens.records.get(&parent).cloned());
    let id = tokens.next_identifier;
    tokens.next_identifier += 1;
    let user = parent.as_ref().map_or_else(|| sid(5, &[18]), |parent| parent.user.clone());
    let mut token = Token {
        pointer,
        refs: 1,
        exclusive_process: 0,
        permanent: false,
        id,
        modified_id: id,
        authentication_id: parent.as_ref().map_or(0x3E7, |parent| parent.authentication_id),
        // O contexto de boot não expira; duplicações conservam a política do pai.
        expiration_time: parent.as_ref().map_or(0x7FFF_FFFF_FFFF_FFFF, |parent| parent.expiration_time),
        user: user.clone(),
        user_attributes: parent.as_ref().map_or(0, |parent| parent.user_attributes),
        owner: user.clone(),
        primary_group: parent.as_ref().map_or_else(|| user.clone(), |parent| parent.primary_group.clone()),
        kind: 1,
        session_id: parent.as_ref().map_or(0, |parent| parent.session_id),
        integrity: parent.as_ref().map_or_else(|| sid(16, &[0x4000]), |parent| parent.integrity.clone()),
        groups: parent.as_ref().map_or_else(
            || {
                alloc::vec![
                    Group { sid: sid(1, &[0]), attributes: 7 },
                    Group { sid: sid(5, &[11]), attributes: 7 },
                    Group { sid: sid(5, &[32, 544]), attributes: 15 },
                ]
            },
            |parent| parent.groups.clone(),
        ),
        // Sem privilégios de usuário inventados para serviços não implementados.
        privileges: parent.as_ref().map_or_else(Vec::new, |parent| parent.privileges.clone()),
        restricted_sids: parent.as_ref().map_or_else(Vec::new, |parent| parent.restricted_sids.clone()),
        write_restricted: parent.as_ref().is_some_and(|parent| parent.write_restricted),
        security_attributes: parent
            .as_ref()
            .map_or_else(Vec::new, |parent| security_attributes::clone(&parent.security_attributes, true)),
        bno_prefix: String::new(),
        app_container: parent.as_ref().and_then(|parent| parent.app_container.clone()),
        capabilities: parent.as_ref().map_or_else(Vec::new, |parent| parent.capabilities.clone()),
        less_privileged_app_container: parent.as_ref().is_some_and(|parent| parent.less_privileged_app_container),
        server_silo: parent.as_ref().map_or(0, |parent| parent.server_silo),
        network_access_flags: parent.as_ref().map_or(0, |parent| parent.network_access_flags),
        security: SecurityPolicy { owner: user.clone(), dacl: Some(alloc::vec![Ace::allow(user.clone(), 0x1F01FF)]), ..Default::default() },
        default_dacl: match &parent {
            Some(parent) => parent.default_dacl.clone(),
            None => Some(alloc::vec![Ace::allow(user.clone(), 0x1000_0000)]),
        },
        impersonation_level: 2,
    };
    // Identidades especiais definem seus campos antes do armazenamento dinâmico.
    if let Some(initialize) = initialize {
        initialize(&mut token);
    }
    if let Err(error) = create_storage(&mut tokens, &token) {
        drop(tokens);
        guest::free_bytes(pointer);
        return Err(error);
    }
    guest::write64(pointer, token.authentication_id);
    guest::write64(pointer + 8, token.id);
    tokens.records.insert(pointer, token);
    drop(tokens);
    object_types::account(&object_type.name, 1, 0)?;
    Ok(pointer)
}

fn validate(tokens: &Tokens, pointer: u64) -> Result<(), KernelError> {
    match tokens.records.get(&pointer) {
        Some(token) if token.refs > 0 => Ok(()),
        _ => Err(KernelError::new("Invalid or released token reference")),
    }
}

pub fn retain(pointer: u64) -> Result<u64, KernelError> {
    let mut tokens = TOKENS.lock();
    validate(&tokens, pointer)?;
    let token = tokens.records.get_mut(&pointer).unwrap();
    token.refs = token.refs.checked_add(1).ok_or_else(|| KernelError::new("Token reference count overflow"))?;
    Ok(token.refs)
}

/// A última referência retira o objeto da tabela e libera o corpo.
pub fn release(pointer: u64) -> Result<u64, KernelError> {
    let remaining = {
        let mut tokens = TOKENS.lock();
        validate(&tokens, pointer)?;
        let token = tokens.records.get_mut(&pointer).unwrap();
        token.refs -= 1;
        let remaining = token.refs;
        if remaining == 0 {
            tokens.records.remove(&pointer);
            release_storage(&mut tokens, pointer);
        }
        remaining
    };
    if remaining == 0 {
        object_types::account("Token", -1, 0)?;
        guest::free_bytes(pointer);
    }
    Ok(remaining)
}

pub fn exists(pointer: u64) -> bool {
    TOKENS.lock().records.contains_key(&pointer)
}

/// Cópia do registro, não o objeto vivo.
pub fn get(pointer: u64) -> Option<Token> {
    TOKENS.lock().records.get(&pointer).cloned()
}

/// Lê o registro vivo.
pub fn with<T>(pointer: u64, body: impl FnOnce(&Token) -> T) -> Option<T> {
    TOKENS.lock().records.get(&pointer).map(body)
}

/// Altera o registro vivo.
pub fn update<T>(pointer: u64, body: impl FnOnce(&mut Token) -> T) -> Option<T> {
    TOKENS.lock().records.get_mut(&pointer).map(body)
}

/// Interface por endereço: nova contagem, ou `None` sem objeto.
pub fn reference(pointer: u64) -> Option<u64> {
    retain(pointer).ok()
}

pub fn dereference(pointer: u64) -> Option<u64> {
    if !exists(pointer) {
        return None;
    }
    release(pointer).ok()
}

pub fn account_handle(pointer: u64, change: i64) -> Result<(), KernelError> {
    validate(&TOKENS.lock(), pointer)?;
    object_types::account("Token", 0, change)
}

/// Token de impersonação com cópias próprias de identidade, DACL e
/// atributos. `effective_only` remove grupos e privilégios inativos.
pub fn duplicate(source: u64, level: u32, effective_only: bool, token_type: u32) -> Result<u64, KernelError> {
    let source_token = {
        let tokens = TOKENS.lock();
        validate(&tokens, source)?;
        tokens.records[&source].clone()
    };
    if level > 3 {
        return Err(KernelError::new("invalid token impersonation level"));
    }
    if token_type != 1 && token_type != 2 {
        return Err(KernelError::new("invalid duplicate token type"));
    }
    let pointer = create(Some(source), None)?;
    update(pointer, |token| {
        token.kind = token_type;
        token.impersonation_level = level;
        token.owner = source_token.owner.clone();
        token.primary_group = source_token.primary_group.clone();
        token.security_attributes = security_attributes::clone(&source_token.security_attributes, false);
        token.security = source_token.security.clone();
        token.bno_prefix = source_token.bno_prefix.clone();
        token.app_container = source_token.app_container.clone();
        if effective_only {
            // SepMakeTokenEffectiveOnly conserva enabled, deny-only e integrity;
            // compacta trocando a entrada removida pela última, sem ordenar.
            let mut index = 0;
            while index < token.groups.len() {
                if token.groups[index].attributes & 0x34 != 0 {
                    index += 1;
                    continue;
                }
                if token.groups[index].sid == token.owner {
                    token.owner = token.user.clone();
                }
                let last = token.groups.pop().unwrap();
                if index < token.groups.len() {
                    token.groups[index] = last;
                }
            }
            token.privileges.retain(|privilege| privilege.attributes & 2 != 0);
        }
    });
    Ok(pointer)
}
