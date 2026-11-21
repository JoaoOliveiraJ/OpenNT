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
