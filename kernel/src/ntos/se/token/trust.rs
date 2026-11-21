//! O nível de confiança de processo do token (TOKEN.TrustLevelSid), como no
//! ntoskrnl 19041.
//!
//! - SepSidFromProcessProtection: o PS_PROTECTION do processo (tipo nos 3
//!   bits baixos, signatário nos 4 altos) escolhe um dos SIDs
//!   `S-1-19-<tipo>-<signatário>` do SepVariableInitialization (os
//!   SeProcTrust*Sid): o tipo é 0x200 no protegido leve e 0x400 no
//!   protegido; o signatário, 0x400 Authenticode, 0x600 Antimalware, 0x800
//!   App, 0x1000 Windows e 0x2000 WinTcb (o WinSystem também). Outro nível,
//!   nenhum SID.
//! - SepSetTrustLevelForProcessToken: o SeSubProcessToken põe no token
//!   primário de um processo novo o SID do PS_PROTECTION dele (um processo
//!   sem proteção tira o que viesse do token de origem); um SID igual não
//!   muda nada.
//! - RtlSidDominatesForTrust e RtlpValidTrustSubjectContext: um SID de
//!   confiança domina outro quando as duas subautoridades são maiores ou
//!   iguais; sem SID, o token só domina o tipo 0. Atribuir ou trocar um
//!   rótulo de confiança (SYSTEM_PROCESS_TRUST_LABEL_ACE) exige um token com
//!   SID de confiança que domine o rótulo (senão STATUS_ACCESS_DENIED). A
//!   ntdll faz a mesma conta no RtlpNewSecurityObject de modo usuário pelo
//!   NtQueryInformationToken(TokenProcessTrustLevel), e o ntmarta só grava
//!   o rótulo de uma pasta (o AppXApplyTrustLabelToFolder do AppXSvc, um
//!   processo protegido leve do signatário Windows) com ela.

use super::tokens;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::Eprocess;
use crate::ntos::se::model::{sid, Sid};

/// SECURITY_PROCESS_TRUST_AUTHORITY.
const TRUST_AUTHORITY: u64 = 19;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;

/// SepSidFromProcessProtection(Protection): o SID de confiança do
/// PS_PROTECTION `level`, ou nenhum.
pub fn sid_from_protection(level: u8) -> Option<Sid> {
    let (kind, signer) = match level {
        // PsProtectedTypeProtected com o signatário Authenticode.
        0x12 => (0x400, 0x400),
        // PsProtectedTypeProtectedLight: Antimalware, Windows, WinTcb e App.
        0x31 => (0x200, 0x600),
        0x51 => (0x200, 0x1000),
        0x61 => (0x200, 0x2000),
        0x81 => (0x200, 0x800),
        // PsProtectedTypeProtected: Windows, WinTcb e WinSystem.
        0x52 => (0x400, 0x1000),
        0x62 | 0x72 => (0x400, 0x2000),
        _ => return None,
    };
    Some(sid(TRUST_AUTHORITY, &[kind, signer]))
}

/// A subautoridade `index` de um SID em bytes.
fn sub_authority(sid: &[u8], index: usize) -> Option<u32> {
    let at = 8 + index * 4;
    sid.get(at..at + 4).map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// RtlIsValidProcessTrustLabelSid: revisão 1, autoridade 19, duas
/// subautoridades, e o tipo 0 só com o signatário 0.
pub fn is_valid_trust_sid(sid: &[u8]) -> bool {
    if sid.len() < 16 || sid[0] != 1 || sid[1] != 2 || sid[2..8] != [0, 0, 0, 0, 0, TRUST_AUTHORITY as u8] {
        return false;
    }
    sub_authority(sid, 0) != Some(0) || sub_authority(sid, 1) == Some(0)
}

/// RtlSidDominatesForTrust(Sid1, Sid2, *Dominates): `token` (o SID do
/// token; nenhum é o de um processo sem proteção) domina `label`. Um SID
/// inválido é STATUS_INVALID_PARAMETER; sem `label`, domina.
pub fn dominates(token: Option<&[u8]>, label: Option<&[u8]>) -> Result<bool, u32> {
    if token.is_some_and(|sid| !is_valid_trust_sid(sid)) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let Some(label) = label else { return Ok(true) };
    if !is_valid_trust_sid(label) {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(match token {
        Some(token) => sub_authority(token, 0) >= sub_authority(label, 0) && sub_authority(token, 1) >= sub_authority(label, 1),
        None => sub_authority(label, 0) == Some(0),
    })
}

/// RtlpValidTrustSubjectContext(TokenTrustSid, LabelSid, ..., *Status):
/// atribuir o rótulo `label` pede um token com SID de confiança (sem ele,
/// STATUS_ACCESS_DENIED) que o domine.
pub fn valid_trust_subject(token: Option<&[u8]>, label: &[u8]) -> Result<(), u32> {
    let Some(token) = token else { return Err(STATUS_ACCESS_DENIED) };
    match dominates(Some(token), Some(label)) {
        Ok(true) => Ok(()),
        Ok(false) => Err(STATUS_ACCESS_DENIED),
        Err(status) => Err(status),
    }
}

/// SepLocateTokenTrustLevel(SubjectContext): sem token de cliente, o SID do
/// primário; com ele, o do cliente quando o primário o domina, senão o do
/// primário.
pub fn subject_trust_sid(primary: u64, client: Option<u64>) -> Option<Sid> {
    let primary_sid = token_trust_sid(primary);
    let Some(client) = client else { return primary_sid };
    let client_sid = token_trust_sid(client);
    if dominates(primary_sid.as_deref(), client_sid.as_deref()) == Ok(true) {
        client_sid
    } else {
        primary_sid
    }
}

/// O SID de confiança do sujeito corrente (o SeCaptureSubjectContext da
/// thread: o token de impersonação dela, se houver, e o primário do
/// processo), pelo [`subject_trust_sid`].
pub fn current_subject_trust_sid() -> Option<Sid> {
    let primary = crate::ntos::ps::process::get_primary_token(crate::ntos::ps::process::get_current_process())?;
    let client = super::thread::get(crate::ntos::ps::process::get_current_thread()).map(|state| state.token);
    subject_trust_sid(primary, client)
}

/// SYSTEM_PROCESS_TRUST_LABEL_ACE_TYPE.
pub const TRUST_LABEL_ACE_TYPE: u8 = 0x14;
/// STATUS_INVALID_LABEL.
const STATUS_INVALID_LABEL: u32 = 0xC000_0446;

/// As ACEs de uma ACL em bytes (cabeçalho de 8 bytes e AceSize de cada).
fn aces(acl: &[u8]) -> impl Iterator<Item = &[u8]> {
    let count = acl.get(4..6).map_or(0, |bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize);
    let mut offset = 8usize;
    (0..count).map_while(move |_| {
        let size = acl.get(offset + 2..offset + 4).map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]) as usize)?;
        let ace = acl.get(offset..offset + size).filter(|_| size >= 8)?;
        offset += size;
        Some(ace)
    })
}

/// O RtlpSetSecurityObject com PROCESS_TRUST_LABEL_SECURITY_INFORMATION:
/// sem SID de confiança no sujeito, STATUS_ACCESS_DENIED; cada
/// SYSTEM_PROCESS_TRUST_LABEL_ACE da SACL nova precisa de uma máscara sem
/// direitos genéricos (STATUS_INVALID_LABEL) e de um SID que o sujeito
/// domine (RtlpValidTrustSubjectContext).
pub fn check_new_trust_labels(sacl: Option<&[u8]>, subject: Option<&[u8]>) -> Result<(), u32> {
    let Some(subject) = subject else { return Err(STATUS_ACCESS_DENIED) };
    for ace in sacl.into_iter().flat_map(aces).filter(|ace| ace[0] == TRUST_LABEL_ACE_TYPE) {
        let mask = u32::from_le_bytes([ace[4], ace[5], ace[6], ace[7]]);
        if mask & 0xFF00_0000 != 0 {
            return Err(STATUS_INVALID_LABEL);
        }
        valid_trust_subject(Some(subject), &ace[8..])?;
    }
    Ok(())
}

/// O RtlpNewSecurityObject com um rótulo de confiança explícito na SACL do
/// criador: o sujeito precisa de um SID de confiança que o domine
/// (RtlpValidTrustSubjectContext), senão STATUS_ACCESS_DENIED.
pub fn check_creator_trust_label(sacl: Option<&[u8]>, subject: Option<&[u8]>) -> Result<(), u32> {
    match sacl.into_iter().flat_map(aces).find(|ace| ace[0] == TRUST_LABEL_ACE_TYPE) {
        Some(ace) => valid_trust_subject(subject, &ace[8..]),
        None => Ok(()),
    }
}

/// O SID de confiança do token `token` (nenhum num token sem nível).
pub fn token_trust_sid(token: u64) -> Option<Sid> {
    tokens::with(token, |record| record.trust_level_sid.clone()).flatten()
}

/// SepSetTrustLevelForProcessToken(Token, Process, *Changed): o SID do
/// PS_PROTECTION de `process` vai para o token primário `token`; devolve se
/// mudou.
pub fn set_for_process_token(token: u64, process: u64) -> bool {
    // SAFETY: o EPROCESS do processo que recebe o token, retido pela criação.
    let level = unsafe { Eprocess::at(process) }.protection.level.get();
    set_level(token, level)
}

/// O token do System (SeMakeSystemToken): o SepCreateTokenEx lhe dá o
/// SeProcTrustWinTcbSid, `S-1-19-1024-8192`.
pub fn set_system_token(token: u64) {
    tokens::update(token, |record| record.trust_level_sid = Some(sid(TRUST_AUTHORITY, &[0x400, 0x2000])));
}

/// O SID do PS_PROTECTION `level` no token: igual ao que ele tem, nada
/// muda; senão troca (ou tira, sem SID). Devolve se mudou.
pub fn set_level(token: u64, level: u8) -> bool {
    let wanted = sid_from_protection(level);
    tokens::update(token, |record| {
        if record.trust_level_sid == wanted {
            return false;
        }
        record.trust_level_sid = wanted;
        true
    })
    .unwrap_or(false)
}
