//! Autoteste do nível de confiança de processo do token
//! (`se/token/trust.rs`), contra o ntoskrnl 19041:
//!
//! - o SepSidFromProcessProtection: os PS_PROTECTION dos processos
//!   protegidos dão os SeProcTrust*Sid (`S-1-19-512-4096` no leve do
//!   signatário Windows, o do AppXSvc; `S-1-19-512-8192` no leve WinTcb, o
//!   do smss; o WinSystem cai no WinTcb) e os demais, nenhum;
//! - o RtlSidDominatesForTrust e o RtlpValidTrustSubjectContext: as duas
//!   subautoridades maiores ou iguais; sem SID, o token só domina o tipo 0
//!   e não atribui rótulo nenhum; SID inválido é STATUS_INVALID_PARAMETER;
//! - o SepSetTrustLevelForProcessToken num token: o SID entra, um SID igual
//!   não muda nada e um processo sem proteção o tira; o
//!   NtQueryInformationToken(TokenProcessTrustLevel) devolve o ponteiro e o
//!   SID colado (24 bytes) ou só o ponteiro nulo (8), e o
//!   TokenAccessInformation aponta o TrustLevelSid; o NtCompareTokens
//!   distingue a presença do SID;
//! - o token do System tem o SeProcTrustWinTcbSid.

use crate::ntos::inc::types::TokenAccessInformation;
use crate::ntos::ps::process;
use crate::ntos::se::model::sid;
use crate::ntos::se::token::{compare, query, tokens, trust};

type Assert = fn(bool, &str);

pub fn run(assert: Assert) {
    let lite_windows = sid(19, &[0x200, 0x1000]);
    let lite_wintcb = sid(19, &[0x200, 0x2000]);
    let wintcb = sid(19, &[0x400, 0x2000]);
    let none = sid(19, &[0, 0]);
    let mapping = trust::sid_from_protection(0x51).as_ref() == Some(&lite_windows)
        && trust::sid_from_protection(0x61).as_ref() == Some(&lite_wintcb)
        && trust::sid_from_protection(0x62).as_ref() == Some(&wintcb)
        && trust::sid_from_protection(0x72).as_ref() == Some(&wintcb)
        && trust::sid_from_protection(0x31) == Some(sid(19, &[0x200, 0x600]))
        && trust::sid_from_protection(0x81) == Some(sid(19, &[0x200, 0x800]))
        && trust::sid_from_protection(0x12) == Some(sid(19, &[0x400, 0x400]))
        && trust::sid_from_protection(0).is_none()
        && trust::sid_from_protection(0x41).is_none();
    assert(mapping, "trust: SepSidFromProcessProtection da os SeProcTrust*Sid dos niveis protegidos e nenhum aos outros");

    let dominance = trust::dominates(Some(&lite_wintcb), Some(&lite_windows)) == Ok(true)
        && trust::dominates(Some(&lite_windows), Some(&lite_windows)) == Ok(true)
        && trust::dominates(Some(&lite_windows), Some(&lite_wintcb)) == Ok(false)
        && trust::dominates(Some(&lite_wintcb), Some(&wintcb)) == Ok(false)
        && trust::dominates(None, Some(&none)) == Ok(true)
        && trust::dominates(None, Some(&lite_windows)) == Ok(false)
        && trust::dominates(Some(&lite_windows), None) == Ok(true)
        && trust::dominates(None, Some(&sid(5, &[18]))) == Err(0xC000_000D)
        && trust::dominates(Some(&sid(19, &[0, 0x1000])), None) == Err(0xC000_000D);
    let subject = trust::valid_trust_subject(None, &none) == Err(0xC000_0022) && trust::valid_trust_subject(Some(&lite_windows), &none).is_ok() && trust::valid_trust_subject(Some(&lite_windows), &lite_wintcb) == Err(0xC000_0022);
    assert(dominance && subject, "trust: RtlSidDominatesForTrust e RtlpValidTrustSubjectContext (sem SID de confianca nenhum rotulo e atribuido)");

    let Some(primary) = process::get_primary_token(process::get_current_process()) else {
        assert(false, "trust: token primario do processo corrente");
        return;
    };
    let Ok(copy) = tokens::create(Some(primary), None) else {
        assert(false, "trust: copia do token");
        return;
    };
    trust::set_level(copy, 0);
    let base = 0x1000u64;
    let empty = query::encode(copy, 41, base).map(|bytes| bytes.len() == 8 && bytes.iter().all(|&byte| byte == 0)).unwrap_or(false);
    let set = trust::set_level(copy, 0x51);
    let unchanged = !trust::set_level(copy, 0x51);
    let reported = query::encode(copy, 41, base).map(|bytes| bytes.len() == 24 && bytes[..8] == (base + 8).to_le_bytes() && bytes[8..] == lite_windows[..]).unwrap_or(false);
    let access = query::encode(copy, 22, base)
        .map(|bytes| {
            let at = core::mem::offset_of!(TokenAccessInformation, trust_level_sid);
            let pointer = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
            let offset = pointer.wrapping_sub(base) as usize;
            pointer != 0 && bytes.get(offset..offset + 16) == Some(&lite_windows[..])
        })
        .unwrap_or(false);
    let other = tokens::create(Some(copy), None).ok();
    let compared = other.is_some_and(|other| {
        let same = tokens::get(copy).zip(tokens::get(other)).is_some_and(|(left, right)| compare::equivalent(&left, &right));
        trust::set_level(other, 0);
        let differ = tokens::get(copy).zip(tokens::get(other)).is_some_and(|(left, right)| !compare::equivalent(&left, &right));
        same && differ
    });
    if let Some(other) = other {
        let _ = tokens::release(other);
    }
    let removed = trust::set_level(copy, 0) && trust::token_trust_sid(copy).is_none();
    let _ = tokens::release(copy);
    assert(empty && set && unchanged && reported && access && compared && removed, "trust: SepSetTrustLevelForProcessToken, TokenProcessTrustLevel, TokenAccessInformation e NtCompareTokens com o SID de confianca");

    let system_trust = process::get_primary_token(process::get_system_process()).and_then(trust::token_trust_sid);
    assert(system_trust.as_ref() == Some(&wintcb), "trust: o token do System tem o SeProcTrustWinTcbSid");
}
