//! ProcessMitigationPolicy (classe 52) do NtSetInformationProcess, como no
//! ntoskrnl 19041 (o ramo da classe no NtSetInformationProcess, rva
//! 0x659d0b).
//!
//! A entrada é o PROCESS_MITIGATION_POLICY_INFORMATION de 8 bytes (a
//! política e as flags dela; outro tamanho dá STATUS_INFO_LENGTH_MISMATCH).
//! Só o processo corrente (o pseudo-handle -1) recebe políticas; outro
//! handle só vale para a de código dinâmico, e as outras dão
//! STATUS_INVALID_PARAMETER. Cada política confere as flags (bits fora da
//! estrutura dão STATUS_INVALID_PARAMETER), recusa desligar uma proteção já
//! ligada (STATUS_ACCESS_DENIED) e liga os bits do EPROCESS.MitigationFlags:
//!
//! - ProcessDynamicCodePolicy (2): ProhibitDynamicCode, AllowThreadOptOut e
//!   AllowRemoteDowngrade (estes dois só com o primeiro) e o modo auditoria
//!   (descartado quando a proibição vem junto); DisableDynamicCode,
//!   DisableDynamicCodeAllowOptOut, DisableDynamicCodeAllowRemoteDowngrade e
//!   AuditDisableDynamicCode. Nenhuma opção de sistema (MitigationOptions do
//!   kernel) é ligada no OpenNT, então o PsIsSystemWideMitigationOptionSet
//!   nunca recusa;
//! - ProcessExtensionPointDisablePolicy (6): ExtensionPointDisable;
//! - ProcessSignaturePolicy (8): MicrosoftSignedOnly ou StoreSignedOnly (no
//!   máximo um), os dois modos auditoria e o MitigationOptIn; os níveis de
//!   assinatura do processo sobem (SignatureLevel e SectionSignatureLevel
//!   8 com MicrosoftSignedOnly; SectionSignatureLevel 6 com StoreSignedOnly)
//!   e os bits SignatureMitigationOptIn, AuditBlockNonMicrosoftBinaries e
//!   AuditBlockNonMicrosoftBinariesAllowStore;
//! - ProcessFontDisablePolicy (9): DisableNonSystemFonts ou o modo auditoria
//!   AuditNonSystemFontLoading.
//!
//! As políticas sem tratamento no 19041 (0, 5, 11, 12 e acima de 16) dão
//! STATUS_NOT_SUPPORTED. Lacuna: as outras políticas (ASLR, verificação
//! estrita de handles, chamadas do win32k, CFG, carga de imagens, processos
//! filhos, isolamento de canal lateral, pilha sombra e a 16) e a de código
//! dinâmico noutro processo ainda respondem STATUS_NOT_SUPPORTED, com
//! registro.

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, EprocessMitigationFlagsValues as Flags};
use crate::ntos::ps::process;
use crate::ntos::se::signing_level;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

const DYNAMIC_CODE_POLICY: u32 = 2;
const EXTENSION_POINT_DISABLE_POLICY: u32 = 6;
const SIGNATURE_POLICY: u32 = 8;
const FONT_DISABLE_POLICY: u32 = 9;

/// SE_SIGNING_LEVEL_MICROSOFT (8) e SE_SIGNING_LEVEL_STORE (6).
const SIGNING_LEVEL_MICROSOFT: u8 = 8;
const SIGNING_LEVEL_STORE: u8 = 6;

/// RtlInterlockedSetClearBits no EPROCESS.MitigationFlags.
fn set_clear(process: &Eprocess, set: u32, clear: u32) {
    let _ = process.mitigation_flags.atomic().try_update(core::sync::atomic::Ordering::SeqCst, core::sync::atomic::Ordering::SeqCst, |flags| Some((flags | set) & !clear));
}

/// O ramo da classe 52 do NtSetInformationProcess: `current` diz se o
/// handle é o pseudo-handle do processo corrente. Devolve o NTSTATUS.
pub fn set(current: bool, policy: u32, flags: u32) -> u32 {
    if !current && policy != DYNAMIC_CODE_POLICY {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: o EPROCESS do processo corrente, vivo durante o serviço.
    let process = unsafe { Eprocess::at(process::get_current_process()) };
    match policy {
        DYNAMIC_CODE_POLICY if current => dynamic_code(process, flags),
        EXTENSION_POINT_DISABLE_POLICY => extension_point_disable(process, flags),
        SIGNATURE_POLICY => signature(process, flags),
        FONT_DISABLE_POLICY => font_disable(process, flags),
        1 | 2 | 3 | 4 | 7 | 10 | 13 | 14 | 15 | 16 => {
            crate::debug_print!("[ps] ProcessMitigationPolicy: politica {} sem suporte (corrente: {})", policy, current);
            STATUS_NOT_SUPPORTED
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

fn dynamic_code(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0xF != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut flags = flags;
    // A auditoria sai quando a proibição vem junto.
    if flags & 1 != 0 && flags & 8 != 0 {
        flags &= !8;
    }
    let prohibit = flags & 1 != 0;
    if !prohibit && flags & 6 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let current = process.mitigation_flags.get();
    if !prohibit && current & Flags::DISABLE_DYNAMIC_CODE_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    let audit = flags & 8 != 0;
    if !audit && !prohibit && current & Flags::AUDIT_DISABLE_DYNAMIC_CODE_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    let opt_out = flags & 2 != 0;
    if opt_out && current & Flags::DISABLE_DYNAMIC_CODE_MASK != 0 && current & Flags::DISABLE_DYNAMIC_CODE_ALLOW_OPT_OUT_MASK == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let remote_downgrade = flags & 4 != 0;
    if remote_downgrade && current & Flags::DISABLE_DYNAMIC_CODE_MASK != 0 && current & Flags::DISABLE_DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE_MASK == 0 {
        return STATUS_ACCESS_DENIED;
    }
    let base = if prohibit { Flags::DISABLE_DYNAMIC_CODE_MASK | Flags::AUDIT_DISABLE_DYNAMIC_CODE_MASK } else if audit { Flags::AUDIT_DISABLE_DYNAMIC_CODE_MASK } else { 0 };
    let set = base | if opt_out { Flags::DISABLE_DYNAMIC_CODE_ALLOW_OPT_OUT_MASK } else { 0 } | if remote_downgrade { Flags::DISABLE_DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE_MASK } else { 0 };
    let clear = if opt_out { 0 } else { Flags::DISABLE_DYNAMIC_CODE_ALLOW_OPT_OUT_MASK } | if remote_downgrade { 0 } else { Flags::DISABLE_DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE_MASK };
    set_clear(process, set, clear);
    0
}

fn extension_point_disable(process: &Eprocess, flags: u32) -> u32 {
    if flags & !1 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & 1 == 0 {
        return if process.mitigation_flags.get() & Flags::EXTENSION_POINT_DISABLE_MASK != 0 { STATUS_ACCESS_DENIED } else { 0 };
    }
    set_clear(process, Flags::EXTENSION_POINT_DISABLE_MASK, 0);
    0
}

/// SeCompareSigningLevels(a, b): `a` alcança `b`.
fn reaches(actual: u8, expected: u8) -> bool {
    signing_level::compare(actual, expected) & 0xFF != 0
}

fn signature(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0x1F != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut flags = flags;
    // MicrosoftSignedOnly descarta as duas auditorias; StoreSignedOnly, a
    // auditoria da loja.
    if flags & 1 != 0 && flags & 0x18 != 0 {
        flags &= !0x18;
    }
    if flags & 2 != 0 && flags & 0x10 != 0 {
        flags &= !0x10;
    }
    let audit_microsoft = flags & 8 != 0;
    let audit_store = flags & 0x10 != 0;
    if audit_microsoft && audit_store {
        return STATUS_INVALID_PARAMETER;
    }
    let (microsoft, store) = (flags & 1 != 0, flags & 2 != 0);
    if microsoft && store {
        return STATUS_INVALID_PARAMETER;
    }
    let (level, section_level) = (process.signature_level.get(), process.section_signature_level.get());
    if !microsoft {
        if level >= SIGNING_LEVEL_MICROSOFT && section_level >= SIGNING_LEVEL_MICROSOFT {
            return STATUS_ACCESS_DENIED;
        }
        if !store && reaches(level, SIGNING_LEVEL_STORE) && reaches(section_level, SIGNING_LEVEL_STORE) {
            return STATUS_ACCESS_DENIED;
        }
    }
    let current = process.mitigation_flags.get();
    if current & (Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_MASK | Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE_MASK) != 0 && !audit_store && !store && !audit_microsoft && !microsoft {
        return STATUS_ACCESS_DENIED;
    }
    if microsoft {
        process.signature_level.set(level.max(SIGNING_LEVEL_MICROSOFT));
        process.section_signature_level.set(section_level.max(SIGNING_LEVEL_MICROSOFT));
    } else if store {
        if !reaches(level, SIGNING_LEVEL_STORE) {
            return STATUS_ACCESS_DENIED;
        }
        if reaches(SIGNING_LEVEL_STORE, section_level) {
            process.section_signature_level.set(SIGNING_LEVEL_STORE);
        }
    }
    let opt_in = if flags != 0 { Flags::SIGNATURE_MITIGATION_OPT_IN_MASK } else { 0 };
    let set = opt_in | if audit_microsoft { Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_MASK } else { 0 } | if audit_store { Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE_MASK } else { 0 };
    let clear = if audit_microsoft { 0 } else { Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_MASK } | if audit_store { 0 } else { Flags::AUDIT_BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE_MASK };
    set_clear(process, set, clear);
    0
}

fn font_disable(process: &Eprocess, flags: u32) -> u32 {
    if flags & !3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let current = process.mitigation_flags.get();
    let (disable, audit) = (flags & 1 != 0, flags & 2 != 0);
    if !disable && current & Flags::DISABLE_NON_SYSTEM_FONTS_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !disable && !audit && current & Flags::AUDIT_NON_SYSTEM_FONT_LOADING_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if disable {
        set_clear(process, Flags::DISABLE_NON_SYSTEM_FONTS_MASK, Flags::AUDIT_NON_SYSTEM_FONT_LOADING_MASK);
    } else if audit {
        set_clear(process, Flags::AUDIT_NON_SYSTEM_FONT_LOADING_MASK, Flags::DISABLE_NON_SYSTEM_FONTS_MASK);
    }
    0
}
