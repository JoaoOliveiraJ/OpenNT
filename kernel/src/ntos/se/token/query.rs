//! NtQueryInformationToken.
//!
//! Cada classe é serializada do registro do token com os ponteiros internos
//! relativos ao buffer do chamador (`encode`). Como no ntoskrnl 19041, o
//! ReturnLength recebe o tamanho exigido antes da comparação com o Length, e
//! um buffer curto devolve STATUS_BUFFER_TOO_SMALL sem nenhum byte gravado
//! nele (`write_encoded`). TokenStatistics (classe 10), pedido pelo MSRPC
//! original, grava campo a campo, também pela variante de syscall de usuário
//! (`query_user`).

use alloc::vec::Vec;
use core::mem::offset_of;

use crate::ntos::inc::types::{LuidAndAttributes, NtStruct, SidAndAttributes, SidAndAttributesHash, TokenAccessInformation, TokenMandatoryPolicy, TokenPrivileges};
use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::mm::{page_residency, paging};
use crate::ntos::ps::user_probe;
use crate::ntos::se::model::{Group, Sid};
use crate::ntos::se::security_attributes;
use crate::ntos::se::token::tokens::{self, Token};
use crate::ntos::se::token::{reference as token_reference, statistics as token_statistics};
use crate::rtl::KernelError;

/// MmUserProbeAddress.
const USER_PROBE_LIMIT: u64 = crate::ntos::mm::memory_map::USER_PROBE_ADDRESS;
const REJECTED_CLASSES: [u32; 7] = [0, 14, 35, 36, 38, 45, 46];
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// SE_GROUP_LOGON_ID.
const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
/// TokenAccessInformation.
const TOKEN_ACCESS_INFORMATION_CLASS: u32 = 22;
/// TokenFlags: TOKEN_WRITE_RESTRICTED, TOKEN_IS_RESTRICTED e TOKEN_IS_FILTERED.
const TOKEN_WRITE_RESTRICTED: u32 = 0x8;
const TOKEN_IS_RESTRICTED: u32 = 0x10;
const TOKEN_IS_FILTERED: u32 = 0x800;

/// O TokenFlags do corpo do token.
fn token_flags(token: &Token) -> u32 {
    tokens::body(token.pointer).token_flags.get()
}
/// SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED.
const SE_GROUP_INTEGRITY: u32 = 0x60;

/// Só memória com dono; a falha de um campo preserva os anteriores.
fn writable(address: u64, length: u64, from_user_mode: bool) -> bool {
    if from_user_mode {
        return address < USER_PROBE_LIMIT && user_probe::probe_user_write(address, length);
    }
    let Some(end) = address.checked_add(length) else { return false };
    if address == 0 || (address < 0xFFFF_8000_0000_0000 && end > 0x8000_0000_0000) {
        return false;
    }
    let mut page = address & !0xFFF;
    while page < end {
        let flags = paging::access_flags(page);
        if flags & 3 != 3 && (!page_residency::fault(page, 2 | (flags & 1) as u32) || paging::access_flags(page) & 3 != 3) {
            return false;
        }
        page += 4096;
    }
    true
}

/// NtQueryInformationToken(handle, classe, saída, tamanho, ReturnLength).
pub fn query(handle: u64, information_class: u32, output: u64, length: u32, returned: u64, access_mode: u8) -> Result<u32, KernelError> {
    if irql::get_irql() != 0 {
        return Err(KernelError::new("Token query requires PASSIVE_LEVEL"));
    }
    let from_user_mode = access_mode != 0;
    if from_user_mode {
        // ProbeForWrite alinha a quatro mesmo com Length 1.
        if length != 0 && output & 3 != 0 {
            return Ok(0x8000_0002);
        }
        if length != 0 && (output + length as u64 > USER_PROBE_LIMIT || !writable(output, length as u64, true)) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        // ReturnLength é obrigatório e sondado antes da classe e do handle.
        if !writable(returned, 4, true) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    if information_class > 48 || REJECTED_CLASSES.contains(&information_class) {
        return Ok(STATUS_INVALID_INFO_CLASS);
    }
    if information_class == TOKEN_ELEVATION_CLASS {
        if let Some(status) = elevation_length(length, returned, from_user_mode) {
            return Ok(status);
        }
    }
    // TokenSource pede TOKEN_QUERY_SOURCE; as demais classes, TOKEN_QUERY.
    let desired = if information_class == 7 { 0x10 } else { 8 };
    let mut reference = match token_reference::reference(handle, desired, access_mode, true)? {
        Ok(reference) => reference,
        Err(status) => return Ok(status),
    };
    let result = if information_class == 10 {
        statistics(reference.token, output, length, returned, from_user_mode)
    } else if information_class == TOKEN_LINKED_TOKEN_CLASS {
        linked_token(reference.token, output, length, returned, from_user_mode)
    } else {
        Ok(write_encoded(encode(reference.token, information_class, output), output, length, returned, from_user_mode))
    };
    reference.release()?;
    result
}

/// TokenLinkedToken e TokenElevation.
const TOKEN_LINKED_TOKEN_CLASS: u32 = 19;
pub const TOKEN_ELEVATION_CLASS: u32 = 20;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
/// SeTcbPrivilege.
const SE_TCB_PRIVILEGE: u64 = 7;
/// TOKEN_ALL_ACCESS e OBJ_KERNEL_HANDLE: o handle do token ligado.
const TOKEN_ALL_ACCESS: u32 = 0xF_01FF;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// TokenElevation (o ramo da classe 20 do NtQueryInformationToken 19041,
/// rva 0x6d21ee): o ReturnLength recebe 4 e outro Length dá
/// STATUS_INFO_LENGTH_MISMATCH antes da referência ao token. `None` segue
/// para a consulta.
pub fn elevation_length(length: u32, returned: u64, from_user_mode: bool) -> Option<u32> {
    if !writable(returned, 4, from_user_mode) || guest::try_write::<u32>(returned, 4).is_err() {
        return Some(STATUS_ACCESS_VIOLATION);
    }
    (length != 4).then_some(STATUS_INFO_LENGTH_MISMATCH)
}

/// TokenLinkedToken (o ramo da classe 19 do NtQueryInformationToken 19041,
/// rva 0x6d1f0b), depois da referência com TOKEN_QUERY: o ReturnLength
/// recebe 8 antes de tudo; outro Length dá STATUS_INFO_LENGTH_MISMATCH. O
/// SeTcbPrivilege de quem consulta, no modo anterior, escolhe o tipo da
/// cópia do token ligado (`elevation::linked_token_copy`: sem sessão irmã,
/// STATUS_NO_SUCH_LOGON_SESSION). A cópia ganha um handle
/// (ObInsertObject com TOKEN_ALL_ACCESS, de kernel em KernelMode), gravado
/// no TOKEN_LINKED_TOKEN; se a gravação falha, o handle é fechado. O OpenNT
/// não tem o modo S sem administrador (o outro ramo de
/// STATUS_NO_SUCH_LOGON_SESSION).
pub fn linked_token(token: u64, output: u64, length: u32, returned: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    use crate::ntos::se::privilege;
    use crate::ntos::se::token::{elevation, handles};
    if !writable(returned, 4, from_user_mode) || guest::try_write::<u32>(returned, 8).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if length != 8 {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let tcb = privilege::single_privilege_check(SE_TCB_PRIVILEGE, from_user_mode as u32);
    let copy = match elevation::linked_token_copy(token, tcb) {
        Ok(copy) => copy,
        Err(status) => return Ok(status),
    };
    let attributes = if from_user_mode { 0 } else { OBJ_KERNEL_HANDLE };
    let created = handles::create(copy, TOKEN_ALL_ACCESS, attributes, from_user_mode);
    tokens::release(copy)?;
    let handle = match created {
        Ok(handle) => handle,
        Err(error) if error.status != 0 => return Ok(error.status),
        Err(error) => return Err(error),
    };
    if !writable(output, 8, from_user_mode) || guest::try_write::<u64>(output, handle).is_err() {
        if from_user_mode {
            let _ = crate::ntos::ps::user::state::close_user_handle(handle, true, true);
        } else {
            let _ = handles::close_native(handle);
        }
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    Ok(0)
}

/// TOKEN_STATISTICS na saída do chamador, sondada campo a campo.
fn statistics(token: u64, output: u64, length: u32, returned: u64, from_user_mode: bool) -> Result<u32, KernelError> {
    if !writable(returned, 4, from_user_mode) {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if guest::try_write::<u32>(returned, 56).is_err() {
        return Ok(STATUS_ACCESS_VIOLATION);
    }
    if length < 56 {
        return Ok(STATUS_BUFFER_TOO_SMALL);
    }
    // ReturnLength precede os dados, inclusive com endereços sobrepostos.
    for (offset, width, value) in token_statistics::fields(token)? {
        let destination = output + offset;
        if !writable(destination, width as u64, from_user_mode) {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
        let written = if width == 8 { guest::try_write::<u64>(destination, value) } else { guest::try_write::<u32>(destination, value as u32) };
        if written.is_err() {
            return Ok(STATUS_ACCESS_VIOLATION);
        }
    }
    Ok(0)
}

/// O tamanho exigido vai para o ReturnLength; com o Length menor, só ele é
/// gravado e a consulta devolve STATUS_BUFFER_TOO_SMALL.
pub fn write_encoded(result: Result<Vec<u8>, u32>, output: u64, length: u32, returned: u64, from_user_mode: bool) -> u32 {
    let bytes = match result {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    if !writable(returned, 4, from_user_mode) || guest::try_write::<u32>(returned, bytes.len() as u32).is_err() {
        return STATUS_ACCESS_VIOLATION;
    }
    if (length as usize) < bytes.len() {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if !bytes.is_empty() && (!writable(output, bytes.len() as u64, from_user_mode) || guest::try_write_bytes(output, &bytes).is_err()) {
        return STATUS_ACCESS_VIOLATION;
    }
    0
}

/// Variante de syscall: os 64 bits dos argumentos vêm do frame bruto ou da
/// pilha de usuário.
pub fn query_user(user_rsp: u64) -> Result<u32, KernelError> {
    let argument = |index: u64| {
        let words = crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index);
        words[0] as u64 | ((words[1] as u64) << 32)
    };
    let low = |index: u64| crate::ntos::ps::user::state::syscall_arg_words(user_rsp, index)[0];
    query(argument(1), low(2), argument(3), low(4), argument(5), 1)
}

/// Montador de layouts com SIDs anexados depois da parte fixa.
struct Layout {
    bytes: Vec<u8>,
    base: u64,
}

impl Layout {
    fn reserve(&mut self, size: usize) -> usize {
        let offset = self.bytes.len();
        self.bytes.resize(offset + size, 0);
        offset
    }
    fn u32(&mut self, offset: usize, value: u32) {
        self.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn u64(&mut self, offset: usize, value: u64) {
        self.bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn append_sid(&mut self, pointer_offset: usize, sid: &Sid) {
        let offset = self.reserve(sid.len());
        self.bytes[offset..offset + sid.len()].copy_from_slice(sid);
        self.u64(pointer_offset, self.base + offset as u64);
    }
    fn groups(&mut self, entries: &[Group]) {
        self.reserve(8 + entries.len() * 16);
        self.u32(0, entries.len() as u32);
        for (index, group) in entries.iter().enumerate() {
            self.append_sid(8 + index * 16, &group.sid);
            self.u32(16 + index * 16, group.attributes);
        }
    }
    fn scalar(&mut self, value: u32) {
        self.reserve(4);
        self.u32(0, value);
    }
}

/// Layout da classe com ponteiros relativos a `base`, ou o NTSTATUS.
pub fn encode(token_pointer: u64, class: u32, base: u64) -> Result<Vec<u8>, u32> {
    let Some(token) = tokens::get(token_pointer) else { return Err(STATUS_INVALID_HANDLE) };
    let mut layout = Layout { bytes: Vec::with_capacity(512), base };
    match class {
        1 => {
            layout.reserve(16);
            layout.append_sid(0, &token.user);
            layout.u32(8, token.user_attributes);
        }
        // TokenGroups: os grupos com o rótulo de integridade no seu lugar
        // (o UserAndGroups do NT sem o usuário).
        2 => layout.groups(&token.groups_with_label()),
        3 => {
            layout.reserve(4 + token.privileges.len() * 12);
            layout.u32(0, token.privileges.len() as u32);
            for (index, privilege) in token.privileges.iter().enumerate() {
                layout.u64(4 + index * 12, privilege.id);
                layout.u32(12 + index * 12, privilege.attributes);
            }
        }
        4 | 5 => {
            layout.reserve(8);
            layout.append_sid(0, if class == 4 { &token.owner } else { &token.primary_group });
        }
        6 => match &token.default_dacl {
            None => {
                layout.reserve(8);
            }
            Some(entries) => {
                let sids: Vec<Sid> = entries.iter().map(|ace| ace.sid.clone().unwrap_or_default()).collect();
                let size = 8 + sids.iter().map(|sid| 8 + sid.len()).sum::<usize>();
                layout.reserve(8 + size);
                layout.u64(0, base + 8);
                layout.bytes[8] = 2;
                layout.bytes[10..12].copy_from_slice(&(size as u16).to_le_bytes());
                layout.bytes[12..14].copy_from_slice(&(entries.len() as u16).to_le_bytes());
                let mut cursor = 16;
                for (ace, sid) in entries.iter().zip(&sids) {
                    layout.bytes[cursor] = if ace.deny { 1 } else { 0 };
                    layout.bytes[cursor + 1] = ace.flags;
                    layout.bytes[cursor + 2..cursor + 4].copy_from_slice(&((8 + sid.len()) as u16).to_le_bytes());
                    layout.u32(cursor + 4, ace.mask);
                    layout.bytes[cursor + 8..cursor + 8 + sid.len()].copy_from_slice(sid);
                    cursor += 8 + sid.len();
                }
            }
        },
        // TOKEN_SOURCE: a do NtCreateToken; nos tokens do contexto de boot,
        // a do OpenNT.
        7 => {
            layout.reserve(16);
            match token.source {
                Some((name, identifier)) => {
                    layout.bytes[..8].copy_from_slice(&name);
                    layout.u64(8, identifier);
                }
                None => {
                    layout.bytes[..8].copy_from_slice(b"OpenNTbt");
                    layout.u64(8, token.authentication_id);
                }
            }
        }
        8 => layout.scalar(token.kind),
        9 => {
            if token.kind != 2 {
                return Err(STATUS_INVALID_INFO_CLASS);
            }
            layout.scalar(token.impersonation_level);
        }
        10 => return token_statistics::encode(token_pointer).map(|bytes| bytes.to_vec()).map_err(|error| if error.status != 0 { error.status } else { 0xC000_0001 }),
        11 => layout.groups(&token.restricted_sids),
        TOKEN_ACCESS_INFORMATION_CLASS => return access_information(&token, base),
        // TokenLogonSid (0x6d28d1): a primeira entrada do UserAndGroups (o
        // usuário primeiro) com SE_GROUP_LOGON_ID, num TOKEN_GROUPS de uma
        // entrada; sem ela, STATUS_NOT_FOUND sem ReturnLength.
        28 => {
            let user = Group { sid: token.user.clone(), attributes: token.user_attributes };
            let all = token.groups_with_label();
            let Some(logon) = core::iter::once(&user).chain(all.iter()).find(|group| group.attributes & SE_GROUP_LOGON_ID == SE_GROUP_LOGON_ID) else { return Err(STATUS_NOT_FOUND) };
            layout.groups(core::slice::from_ref(logon));
        }
        37 | 38 => layout.groups(&[]),
        30 => layout.groups(&token.capabilities),
        29 => layout.scalar(token.app_container.is_some() as u32),
        12 => layout.scalar(token.session_id),
        // TokenOrigin: o OriginatingLogonSession (zero até o LSA gravá-lo).
        17 => {
            layout.reserve(8);
            layout.u64(0, token.originating_logon_session);
        }
        // TokenElevationType e TokenElevation (`se/token/elevation.rs`).
        18 => layout.scalar(crate::ntos::se::token::elevation::elevation_type(&token)),
        19 => return Err(STATUS_INVALID_PARAMETER),
        TOKEN_ELEVATION_CLASS => layout.scalar(crate::ntos::se::token::elevation::is_elevated(&token) as u32),
        // TOKEN_MANDATORY_LABEL: o SepCopyTokenIntegrity copia o SID e os
        // atributos do grupo de integridade; sem ele (IntegrityLevelIndex
        // -1), o SeUntrustedMandatorySid.
        25 => {
            layout.reserve(16);
            layout.u32(8, if token.integrity.is_empty() { SE_GROUP_INTEGRITY } else { token.label_attributes });
            let untrusted = crate::ntos::se::model::sid(16, &[0]);
            layout.append_sid(0, if token.integrity.is_empty() { &untrusted } else { &token.integrity });
        }
        27 => layout.scalar(token.mandatory_policy),
        31 => {
            layout.reserve(8);
            if let Some(container) = &token.app_container {
                layout.append_sid(0, container);
            }
        }
        // Sem pacote nem SID de confiança do processo.
        41 => {
            layout.reserve(8);
        }
        39 => return security_attributes::encode(&token.security_attributes, base),
        // Versão 1, atributos de segurança vazios.
        33..=36 | 43 => {
            layout.reserve(16);
            layout.bytes[0] = 1;
        }
        // Sem isolamento BNO: o namespace nomeado do kernel é compartilhado.
        44 => {
            layout.reserve(16);
        }
        // As classes de TokenFlags do NtQueryInformationToken do 19041
        // (0x6d21ae e 0x6d2310..0x6d2372): TokenHasRestrictions é um
        // BOOLEAN de um byte, IS_FILTERED ou IS_RESTRICTED; as demais, um
        // ULONG com um bit (VirtualizationAllowed, VirtualizationEnabled,
        // UIAccess e PrivateNameSpace) ou, na TokenIsRestricted,
        // IS_RESTRICTED ou WRITE_RESTRICTED.
        21 => layout.bytes.push((token_flags(&token) & (TOKEN_IS_FILTERED | TOKEN_IS_RESTRICTED) != 0) as u8),
        23 => layout.scalar(token_flags(&token) >> 9 & 1),
        24 => layout.scalar(token_flags(&token) >> 10 & 1),
        26 => layout.scalar(token_flags(&token) >> 12 & 1),
        40 => layout.scalar((token_flags(&token) & (TOKEN_IS_RESTRICTED | TOKEN_WRITE_RESTRICTED) != 0) as u32),
        42 => layout.scalar(token_flags(&token) >> 16 & 1),
        // TokenAppContainerNumber (0x6d243e): o LowboxNumber da entrada do
        // token, 0 sem ela.
        32 => layout.scalar(token.lowbox_number.map_or(0, |(_, number)| number)),
        15 | 47 | 48 => layout.scalar(0),
        _ => return Err(STATUS_INVALID_INFO_CLASS),
    }
    Ok(layout.bytes)
}

// ---- TokenAccessInformation (classe 22) -----------------------------------
//
// Como o SepGetTokenAccessInformationBufferSize e o
// SepCopyTokenAccessInformation do ntoskrnl 19041. O bloco começa pelo
// TOKEN_ACCESS_INFORMATION e segue, nesta ordem: o SID_AND_ATTRIBUTES_HASH
// dos UserAndGroups com o vetor e os SIDs, o dos SIDs restritos, o das
// capacidades, o PackageSid, o TrustLevelSid, os atributos de segurança no
// formato interno do token e o TOKEN_PRIVILEGES. Cada região de SIDs mede
// Count * 16 mais os SIDs alinhados a 8, mas o RtlCopySidAndAttributesArray
// os cola sem alinhamento logo depois do vetor. O hash marca, para os 64
// primeiros SIDs, o bit i em Hash[b & 0xF] e Hash[16 + (b >> 4)], com b o
// byte baixo da última subautoridade (RtlSidHashInitialize). Os privilégios
// saem na ordem do LUID (o bitmap Present do token, LUIDs 0 a 36), com
// SE_PRIVILEGE_ENABLED e SE_PRIVILEGE_ENABLED_BY_DEFAULT. O OpenNT não tem
// processos protegidos: TrustLevelSid nulo. O AppContainerNumber é o número
// LowBox do token (0 sem ele).

const TAI_SIZE: usize = TokenAccessInformation::SIZE as usize;
const HASH_SIZE: usize = SidAndAttributesHash::SIZE as usize;
const ENTRY_SIZE: usize = SidAndAttributes::SIZE as usize;
const PRIVILEGE_SIZE: usize = LuidAndAttributes::SIZE as usize;
/// Bits do bitmap Present que o SepTokenPrivilegeCount percorre.
const PRIVILEGE_BITS: u64 = 37;
/// Quantos SIDs o hash cobre.
const HASHED_SIDS: usize = 64;

fn align8(length: usize) -> usize {
    (length + 7) & !7
}

/// Região de um vetor de SID_AND_ATTRIBUTES e dos seus SIDs.
fn sid_region(entries: &[(&Sid, u32)]) -> usize {
    entries.len() * ENTRY_SIZE + entries.iter().map(|(sid, _)| align8(sid.len())).sum::<usize>()
}

struct Image {
    bytes: Vec<u8>,
    base: u64,
}

impl Image {
    fn put(&mut self, offset: usize, value: &[u8]) {
        self.bytes[offset..offset + value.len()].copy_from_slice(value);
    }
    fn put32(&mut self, offset: usize, value: u32) {
        self.put(offset, &value.to_le_bytes());
    }
    fn put64(&mut self, offset: usize, value: u64) {
        self.put(offset, &value.to_le_bytes());
    }
    fn address(&self, offset: usize) -> u64 {
        self.base + offset as u64
    }
    /// SID_AND_ATTRIBUTES_HASH em `hash`, o vetor logo depois e os SIDs
    /// colados depois do vetor; devolve o fim da região.
    fn sid_hash(&mut self, hash: usize, entries: &[(&Sid, u32)]) -> usize {
        let array = hash + HASH_SIZE;
        self.put32(hash + offset_of!(SidAndAttributesHash, sid_count), entries.len() as u32);
        self.put64(hash + offset_of!(SidAndAttributesHash, sid_attr), self.address(array));
        let mut sid_at = array + entries.len() * ENTRY_SIZE;
        for (index, (sid, attributes)) in entries.iter().enumerate() {
            let entry = array + index * ENTRY_SIZE;
            self.put64(entry + offset_of!(SidAndAttributes, sid), self.address(sid_at));
            self.put32(entry + offset_of!(SidAndAttributes, attributes), *attributes);
            self.put(sid_at, sid);
            sid_at += sid.len();
            if index < HASHED_SIDS {
                let count = sid.get(1).copied().unwrap_or(0) as usize;
                let byte = sid.get(4 * count + 4).copied().unwrap_or(0) as usize;
                let bit = 1u64 << index;
                for slot in [byte & 0xF, 16 + (byte >> 4)] {
                    let at = hash + offset_of!(SidAndAttributesHash, hash) + slot * 8;
                    let mut word = [0u8; 8];
                    word.copy_from_slice(&self.bytes[at..at + 8]);
                    self.put64(at, u64::from_le_bytes(word) | bit);
                }
            }
        }
        array + sid_region(entries)
    }
}

/// TOKEN_ACCESS_INFORMATION com o bloco que o segue, montado para `base`.
fn access_information(token: &Token, base: u64) -> Result<Vec<u8>, u32> {
    // UserAndGroups: o usuário e os grupos com o rótulo de integridade no
    // seu lugar (ausente num token criado sem ele).
    let labeled = token.groups_with_label();
    let mut groups: Vec<(&Sid, u32)> = alloc::vec![(&token.user, token.user_attributes)];
    groups.extend(labeled.iter().map(|group| (&group.sid, group.attributes)));
    let restricted: Vec<(&Sid, u32)> = token.restricted_sids.iter().map(|group| (&group.sid, group.attributes)).collect();
    let capabilities: Vec<(&Sid, u32)> = token.capabilities.iter().map(|group| (&group.sid, group.attributes)).collect();
    let mut privileges: Vec<(u64, u32)> = token.privileges.iter().filter(|privilege| privilege.id < PRIVILEGE_BITS).map(|privilege| (privilege.id, privilege.attributes & 3)).collect();
    privileges.sort_unstable_by_key(|&(id, _)| id);
    privileges.dedup_by_key(|&mut (id, _)| id);
    let package_size = token.app_container.as_ref().map_or(0, |sid| align8(sid.len()));
    let attributes_size = security_attributes::internal_size(&token.security_attributes)? as usize;
    let privileges_size = if privileges.is_empty() { TokenPrivileges::SIZE as usize } else { offset_of!(TokenPrivileges, privileges) + privileges.len() * PRIVILEGE_SIZE };

    let sid_hash = TAI_SIZE;
    let restricted_hash = sid_hash + HASH_SIZE + sid_region(&groups);
    let capabilities_hash = restricted_hash + HASH_SIZE + sid_region(&restricted);
    let package = capabilities_hash + HASH_SIZE + sid_region(&capabilities);
    // Sem TrustLevelSid, os atributos seguem o PackageSid.
    let attributes = package + package_size;
    let privileges_at = attributes + attributes_size;
    let total = privileges_at + privileges_size;
    if total > u32::MAX as usize {
        return Err(0xC000_0095);
    }

    let mut image = Image { bytes: alloc::vec![0u8; total], base };
    image.sid_hash(sid_hash, &groups);
    image.sid_hash(restricted_hash, &restricted);
    image.sid_hash(capabilities_hash, &capabilities);
    let package_sid = match &token.app_container {
        Some(sid) => {
            image.put(package, sid);
            image.address(package)
        }
        None => 0,
    };
    let internal = security_attributes::encode_internal(&token.security_attributes, image.address(attributes))?;
    image.put(attributes, &internal);
    image.put32(privileges_at + offset_of!(TokenPrivileges, privilege_count), privileges.len() as u32);
    for (index, &(id, bits)) in privileges.iter().enumerate() {
        let entry = privileges_at + offset_of!(TokenPrivileges, privileges) + index * PRIVILEGE_SIZE;
        image.put64(entry + offset_of!(LuidAndAttributes, luid), id);
        image.put32(entry + offset_of!(LuidAndAttributes, attributes), bits);
    }

    // TokenFlags do corpo, onde o bit TOKEN_LOWBOX acompanha o AppContainer.
    let flags = tokens::body(token.pointer).token_flags.get();
    image.put64(offset_of!(TokenAccessInformation, sid_hash), image.address(sid_hash));
    image.put64(offset_of!(TokenAccessInformation, restricted_sid_hash), image.address(restricted_hash));
    image.put64(offset_of!(TokenAccessInformation, privileges), image.address(privileges_at));
    image.put64(offset_of!(TokenAccessInformation, authentication_id), token.authentication_id);
    image.put32(offset_of!(TokenAccessInformation, token_type), token.kind);
    image.put32(offset_of!(TokenAccessInformation, impersonation_level), token.impersonation_level);
    image.put32(offset_of!(TokenAccessInformation, mandatory_policy) + offset_of!(TokenMandatoryPolicy, policy), token.mandatory_policy);
    image.put32(offset_of!(TokenAccessInformation, flags), flags);
    image.put32(offset_of!(TokenAccessInformation, app_container_number), token.lowbox_number.map_or(0, |(_, number)| number));
    image.put64(offset_of!(TokenAccessInformation, package_sid), package_sid);
    image.put64(offset_of!(TokenAccessInformation, capabilities_hash), image.address(capabilities_hash));
    image.put64(offset_of!(TokenAccessInformation, trust_level_sid), 0);
    image.put64(offset_of!(TokenAccessInformation, security_attributes), image.address(attributes));
    Ok(image.bytes)
}
