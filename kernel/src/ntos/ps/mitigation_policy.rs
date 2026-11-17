//! ProcessMitigationPolicy (classe 52) do NtSetInformationProcess, como no
//! ntoskrnl 19041 (o ramo da classe no NtSetInformationProcess, rva
//! 0x659d0b, com a tabela das políticas em 0x65c080).
//!
//! A entrada é o PROCESS_MITIGATION_POLICY_INFORMATION de 8 bytes (a
//! política e as flags dela; outro tamanho dá STATUS_INFO_LENGTH_MISMATCH).
//! Só o processo corrente (o pseudo-handle -1) recebe políticas; outro
//! handle só vale para a de código dinâmico, e as outras dão
//! STATUS_INVALID_PARAMETER. Cada política confere as flags (bits fora da
//! estrutura dão STATUS_INVALID_PARAMETER), recusa desligar uma proteção já
//! ligada (STATUS_ACCESS_DENIED) e liga os bits do EPROCESS.MitigationFlags
//! (MitigationFlags2 e MitigationFlags3 em algumas) ou do TokenFlags do token
//! primário:
//!
//! - ProcessASLRPolicy (1): ForceRelocateImages, BottomUp (desliga
//!   StackRandomizationDisabled) e DisallowStrippedImages, este só com o
//!   primeiro (STATUS_INVALID_PARAMETER_MIX); HighEntropy é ignorado;
//! - ProcessDynamicCodePolicy (2): ProhibitDynamicCode, AllowThreadOptOut e
//!   AllowRemoteDowngrade (estes dois só com o primeiro) e o modo auditoria
//!   (descartado quando a proibição vem junto); DisableDynamicCode,
//!   DisableDynamicCodeAllowOptOut, DisableDynamicCodeAllowRemoteDowngrade e
//!   AuditDisableDynamicCode. Nenhuma opção de sistema (MitigationOptions do
//!   kernel) é ligada no OpenNT, então o PsIsSystemWideMitigationOptionSet
//!   nunca recusa;
//! - ProcessStrictHandleCheckPolicy (3): os dois bits juntos ou nenhum; o
//!   ExEnableHandleExceptions na tabela de handles (desligar o que já está
//!   ligado é STATUS_ACCESS_DENIED; sem tabela, STATUS_PROCESS_IS_TERMINATING);
//! - ProcessSystemCallDisablePolicy (4): as chamadas do win32k
//!   (DisallowWin32kSystemCalls e a auditoria) e as de FSCTL
//!   (MitigationFlags3); desligar as do win32k numa thread GUI é
//!   STATUS_TOO_LATE;
//! - ProcessExtensionPointDisablePolicy (6): ExtensionPointDisable;
//! - ProcessControlFlowGuardPolicy (7): só acrescenta o modo estrito a um
//!   processo com CFG. O OpenNT não liga CFG em processo nenhum (o mapa de
//!   bits do CFG não existe), então toda combinação válida é
//!   STATUS_ACCESS_DENIED, como o 19041 responde a um processo sem CFG;
//! - ProcessSignaturePolicy (8): MicrosoftSignedOnly ou StoreSignedOnly (no
//!   máximo um), os dois modos auditoria e o MitigationOptIn; os níveis de
//!   assinatura do processo sobem (SignatureLevel e SectionSignatureLevel
//!   8 com MicrosoftSignedOnly; SectionSignatureLevel 6 com StoreSignedOnly)
//!   e os bits SignatureMitigationOptIn, AuditBlockNonMicrosoftBinaries e
//!   AuditBlockNonMicrosoftBinariesAllowStore;
//! - ProcessFontDisablePolicy (9): DisableNonSystemFonts ou o modo auditoria
//!   AuditNonSystemFontLoading;
//! - ProcessImageLoadPolicy (10): NoRemoteImages, NoLowMandatoryLabelImages
//!   e PreferSystem32Images, com os dois modos auditoria (cada um descartado
//!   quando a proibição dele vem junto); o fontdrvhost pede 3;
//! - ProcessChildProcessPolicy (13): NoChildProcessCreation (com
//!   AllowSecureProcessCreation) ou o modo auditoria, no TokenFlags pelo
//!   SeTokenSetNoChildProcessRestricted; o fontdrvhost pede a restrição;
//! - ProcessSideChannelIsolationPolicy (14): SmtBranchTargetIsolation,
//!   IsolateSecurityDomain (com um domínio de segurança novo do
//!   PsNextSecurityDomain), DisablePageCombine e SpeculativeStoreBypassDisable;
//! - ProcessRedirectionTrustPolicy (16): impor ou auditar, no TokenFlags pelo
//!   SeTokenSetRedirectionTrustPolicy; o svchost pede a auditoria quando o
//!   grupo não diz nada.
//!
//! As políticas sem tratamento no 19041 (0, 5, 11, 12 e acima de 16) dão
//! STATUS_NOT_SUPPORTED. Lacuna: a ProcessUserShadowStackPolicy (15) e a de
//! código dinâmico noutro processo ainda respondem STATUS_NOT_SUPPORTED, com
//! registro.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{Eprocess, EprocessMitigationFlags2Values as Flags2, EprocessMitigationFlags3Values as Flags3, EprocessMitigationFlagsValues as Flags};
use crate::ntos::ps::{process, set_process_information, win32};
use crate::ntos::se::signing_level;
use crate::ntos::se::token::tokens;
use crate::rtl::KernelError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_INVALID_PARAMETER_MIX: u32 = 0xC000_0030;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_PROCESS_IS_TERMINATING: u32 = 0xC000_010A;
const STATUS_TOO_LATE: u32 = 0xC000_0189;

const ASLR_POLICY: u32 = 1;
const DYNAMIC_CODE_POLICY: u32 = 2;
const STRICT_HANDLE_CHECK_POLICY: u32 = 3;
const SYSTEM_CALL_DISABLE_POLICY: u32 = 4;
const EXTENSION_POINT_DISABLE_POLICY: u32 = 6;
const CONTROL_FLOW_GUARD_POLICY: u32 = 7;
const SIGNATURE_POLICY: u32 = 8;
const FONT_DISABLE_POLICY: u32 = 9;
const IMAGE_LOAD_POLICY: u32 = 10;
const CHILD_PROCESS_POLICY: u32 = 13;
const SIDE_CHANNEL_ISOLATION_POLICY: u32 = 14;
const REDIRECTION_TRUST_POLICY: u32 = 16;

/// SE_SIGNING_LEVEL_MICROSOFT (8) e SE_SIGNING_LEVEL_STORE (6).
const SIGNING_LEVEL_MICROSOFT: u8 = 8;
const SIGNING_LEVEL_STORE: u8 = 6;

/// RtlInterlockedSetClearBits no EPROCESS.MitigationFlags.
fn set_clear(process: &Eprocess, set: u32, clear: u32) {
    let _ = process.mitigation_flags.atomic().try_update(Ordering::SeqCst, Ordering::SeqCst, |flags| Some((flags | set) & !clear));
}

/// O ramo da classe 52 do NtSetInformationProcess: `current` diz se o
/// handle é o pseudo-handle do processo corrente. Devolve o NTSTATUS.
pub fn set(current: bool, policy: u32, flags: u32) -> Result<u32, KernelError> {
    if !current && policy != DYNAMIC_CODE_POLICY {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let pointer = process::get_current_process();
    // SAFETY: o EPROCESS do processo corrente, vivo durante o serviço.
    let process = unsafe { Eprocess::at(pointer) };
    Ok(match policy {
        ASLR_POLICY => aslr(process, flags),
        DYNAMIC_CODE_POLICY if current => dynamic_code(process, flags),
        STRICT_HANDLE_CHECK_POLICY => return strict_handle_check(pointer, flags),
        SYSTEM_CALL_DISABLE_POLICY => system_call_disable(process, flags),
        EXTENSION_POINT_DISABLE_POLICY => extension_point_disable(process, flags),
        CONTROL_FLOW_GUARD_POLICY => control_flow_guard(process, flags),
        SIGNATURE_POLICY => signature(process, flags),
        FONT_DISABLE_POLICY => font_disable(process, flags),
        IMAGE_LOAD_POLICY => image_load(process, flags),
        CHILD_PROCESS_POLICY => child_process(pointer, flags),
        SIDE_CHANNEL_ISOLATION_POLICY => side_channel_isolation(process, flags),
        REDIRECTION_TRUST_POLICY => redirection_trust(pointer, flags),
        2 | 15 => {
            crate::debug_print!("[ps] ProcessMitigationPolicy: politica {} sem suporte (corrente: {})", policy, current);
            STATUS_NOT_SUPPORTED
        }
        _ => STATUS_NOT_SUPPORTED,
    })
}

/// ProcessASLRPolicy: EnableBottomUpRandomization (bit 0),
/// EnableForceRelocateImages (1), EnableHighEntropy (2, ignorado) e
/// DisallowStrippedImages (3).
fn aslr(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0xF != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let (bottom_up, force_relocate, disallow_stripped) = (flags & 1 != 0, flags & 2 != 0, flags & 8 != 0);
    let current = process.mitigation_flags.get();
    if !force_relocate && current & Flags::FORCE_RELOCATE_IMAGES_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    // A aleatorização de baixo para cima já ligada não desliga.
    if !bottom_up && current & Flags::STACK_RANDOMIZATION_DISABLED_MASK == 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !disallow_stripped && current & Flags::DISALLOW_STRIPPED_IMAGES_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if disallow_stripped && !force_relocate {
        return STATUS_INVALID_PARAMETER_MIX;
    }
    if force_relocate {
        set_clear(process, Flags::FORCE_RELOCATE_IMAGES_MASK, 0);
    }
    if bottom_up {
        set_clear(process, 0, Flags::STACK_RANDOMIZATION_DISABLED_MASK);
    }
    if disallow_stripped {
        set_clear(process, Flags::DISALLOW_STRIPPED_IMAGES_MASK, 0);
    }
    0
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

/// ProcessStrictHandleCheckPolicy: RaiseExceptionOnInvalidHandleReference
/// (bit 0) e HandleExceptionsPermanentlyEnabled (1) andam juntos.
fn strict_handle_check(process: u64, flags: u32) -> Result<u32, KernelError> {
    if flags & !3 != 0 || (flags & 1 != 0) != (flags & 2 != 0) {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    Ok(match set_process_information::enable_handle_exceptions(process, flags & 1 != 0)? {
        None => STATUS_PROCESS_IS_TERMINATING,
        Some(true) => 0,
        Some(false) => STATUS_ACCESS_DENIED,
    })
}

/// ProcessSystemCallDisablePolicy: DisallowWin32kSystemCalls (bit 0),
/// AuditDisallowWin32kSystemCalls (1), DisallowFsctlSystemCalls (2) e
/// AuditDisallowFsctlSystemCalls (3); cada auditoria sai quando a proibição
/// dela vem junto.
fn system_call_disable(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0xF != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut flags = flags;
    if flags & 3 == 3 {
        flags &= !2;
    }
    if flags & 0xC == 0xC {
        flags &= !8;
    }
    let (disallow, audit, disallow_fsctl, audit_fsctl) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 8 != 0);
    let (first, third) = (process.mitigation_flags.get(), process.mitigation_flags3.get());
    if !disallow && first & Flags::DISALLOW_WIN32K_SYSTEM_CALLS_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !disallow_fsctl && third & Flags3::DISALLOW_FSCTL_SYSTEM_CALLS_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !audit && !disallow && first & Flags::AUDIT_DISALLOW_WIN32K_SYSTEM_CALLS_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    if !audit_fsctl && !disallow_fsctl && third & Flags3::AUDIT_DISALLOW_FSCTL_SYSTEM_CALLS_MASK != 0 {
        return STATUS_ACCESS_DENIED;
    }
    // PsIsGuiThread da thread corrente: tarde demais para as do win32k.
    if (disallow || audit) && win32::is_gui_thread() {
        return STATUS_TOO_LATE;
    }
    if disallow {
        set_clear(process, Flags::DISALLOW_WIN32K_SYSTEM_CALLS_MASK | Flags::AUDIT_DISALLOW_WIN32K_SYSTEM_CALLS_MASK, 0);
    } else if audit {
        set_clear(process, Flags::AUDIT_DISALLOW_WIN32K_SYSTEM_CALLS_MASK, 0);
    }
    let fsctl = if disallow_fsctl { Flags3::DISALLOW_FSCTL_SYSTEM_CALLS_MASK | Flags3::AUDIT_DISALLOW_FSCTL_SYSTEM_CALLS_MASK } else if audit_fsctl { Flags3::AUDIT_DISALLOW_FSCTL_SYSTEM_CALLS_MASK } else { 0 };
    if fsctl != 0 {
        process.mitigation_flags3.atomic().fetch_or(fsctl, Ordering::SeqCst);
    }
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

/// ProcessControlFlowGuardPolicy: EnableControlFlowGuard (bit 0),
/// EnableExportSuppression (1) e StrictMode (2); só o modo estrito entra, e
/// só num processo com CFG.
fn control_flow_guard(process: &Eprocess, flags: u32) -> u32 {
    if flags & !7 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if process.mitigation_flags.get() & Flags::CONTROL_FLOW_GUARD_ENABLED_MASK == 0 || flags & 4 == 0 {
        return STATUS_ACCESS_DENIED;
    }
    set_clear(process, Flags::CONTROL_FLOW_GUARD_STRICT_MASK, 0);
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

/// ProcessImageLoadPolicy: NoRemoteImages (bit 0), NoLowMandatoryLabelImages
/// (1), PreferSystem32Images (2), AuditNoRemoteImages (3) e
/// AuditNoLowMandatoryLabelImages (4).
fn image_load(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0x1F != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut flags = flags;
    if flags & 1 != 0 && flags & 8 != 0 {
        flags &= !8;
    }
    if flags & 2 != 0 && flags & 0x10 != 0 {
        flags &= !0x10;
    }
    let (no_remote, no_low_label, prefer_system32, audit_remote, audit_low_label) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 8 != 0, flags & 0x10 != 0);
    let current = process.mitigation_flags.get();
    let refused = (!no_remote && current & Flags::PROHIBIT_REMOTE_IMAGE_MAP_MASK != 0)
        || (!no_low_label && current & Flags::PROHIBIT_LOW_IL_IMAGE_MAP_MASK != 0)
        || (!prefer_system32 && current & Flags::PREFER_SYSTEM32_IMAGES_MASK != 0)
        || (!audit_remote && !no_remote && current & Flags::AUDIT_PROHIBIT_REMOTE_IMAGE_MAP_MASK != 0)
        || (!audit_low_label && !no_low_label && current & Flags::AUDIT_PROHIBIT_LOW_IL_IMAGE_MAP_MASK != 0);
    if refused {
        return STATUS_ACCESS_DENIED;
    }
    let (mut set, mut clear) = (0, 0);
    if no_remote {
        set |= Flags::PROHIBIT_REMOTE_IMAGE_MAP_MASK;
        clear |= Flags::AUDIT_PROHIBIT_REMOTE_IMAGE_MAP_MASK;
    } else if audit_remote {
        set |= Flags::AUDIT_PROHIBIT_REMOTE_IMAGE_MAP_MASK;
    }
    if no_low_label {
        set |= Flags::PROHIBIT_LOW_IL_IMAGE_MAP_MASK;
        clear |= Flags::AUDIT_PROHIBIT_LOW_IL_IMAGE_MAP_MASK;
    } else if audit_low_label {
        set |= Flags::AUDIT_PROHIBIT_LOW_IL_IMAGE_MAP_MASK;
    }
    if prefer_system32 {
        set |= Flags::PREFER_SYSTEM32_IMAGES_MASK;
    }
    set_clear(process, set, clear);
    0
}

/// PspGetNoChildProcessRestrictedPolicy: 1 restrito, 2 restrito exceto
/// processos seguros, 3 só auditoria, 0 sem a mitigação (o
/// SeTokenGetNoChildProcessRestricted do token primário).
fn no_child_process_policy(token: Option<u64>) -> u32 {
    let flags = token.map_or(0, tokens::token_flags);
    if flags & tokens::TOKEN_NO_CHILD_PROCESS != 0 {
        if flags & tokens::TOKEN_NO_CHILD_PROCESS_UNLESS_SECURE != 0 { 2 } else { 1 }
    } else if flags & tokens::TOKEN_AUDIT_NO_CHILD_PROCESS != 0 {
        3
    } else {
        0
    }
}

/// ProcessChildProcessPolicy: NoChildProcessCreation (bit 0),
/// AuditNoChildProcessCreation (1, descartado com o 0) e
/// AllowSecureProcessCreation (2, só com o 0). O PspSetNoChildProcessRestrictedPolicy
/// grava o modo no token primário.
fn child_process(process: u64, flags: u32) -> u32 {
    if flags & !7 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let restrict = flags & 1 != 0;
    if !restrict && flags & 4 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let (audit, allow_secure) = (!restrict && flags & 2 != 0, flags & 4 != 0);
    let token = process::get_primary_token(process);
    let current = no_child_process_policy(token);
    if !restrict && matches!(current, 1 | 2) {
        return STATUS_ACCESS_DENIED;
    }
    if allow_secure && current == 1 {
        return STATUS_ACCESS_DENIED;
    }
    if !audit && !restrict && current == 3 {
        return STATUS_ACCESS_DENIED;
    }
    if let Some(token) = token {
        if restrict {
            tokens::set_no_child_process_restricted(token, allow_secure, false);
        } else if audit {
            tokens::set_no_child_process_restricted(token, false, true);
        }
    }
    0
}

/// PsNextSecurityDomain: o próximo domínio de segurança (o primeiro valor do
/// 19041 é 0x1_0000_0000).
static NEXT_SECURITY_DOMAIN: AtomicU64 = AtomicU64::new(0x1_0000_0000);

/// ProcessSideChannelIsolationPolicy: SmtBranchTargetIsolation (bit 0),
/// IsolateSecurityDomain (1), DisablePageCombine (2) e
/// SpeculativeStoreBypassDisable (3).
fn side_channel_isolation(process: &Eprocess, flags: u32) -> u32 {
    if flags & !0xF != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let (branch_target, isolate_domain, page_combine, store_bypass) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 8 != 0);
    let (first, second) = (process.mitigation_flags.get(), process.mitigation_flags2.get());
    let refused = (!branch_target && first & Flags::RESTRICT_INDIRECT_BRANCH_PREDICTION_MASK != 0)
        || (!isolate_domain && first & Flags::ISOLATE_SECURITY_DOMAIN_MASK != 0)
        || (!store_bypass && second & Flags2::SPECULATIVE_STORE_BYPASS_DISABLE_MASK != 0)
        || (!page_combine && second & Flags2::DISABLE_PAGE_COMBINE_MASK != 0);
    if refused {
        return STATUS_ACCESS_DENIED;
    }
    if branch_target {
        set_clear(process, Flags::RESTRICT_INDIRECT_BRANCH_PREDICTION_MASK, 0);
    }
    if isolate_domain {
        set_clear(process, Flags::ISOLATE_SECURITY_DOMAIN_MASK, 0);
        process.flags3.atomic().fetch_or(Eprocess::SECURITY_DOMAIN_CHANGED_MASK, Ordering::SeqCst);
        // PspWriteProcessSecurityDomain com o domínio novo também como o do
        // pai. O KeSynchronizeSecurityDomain avisa os processadores que rodam
        // o processo para trocar o preditor de desvios na próxima entrada; o
        // OpenNT não separa o preditor por domínio, então não há o que avisar.
        let domain = NEXT_SECURITY_DOMAIN.fetch_add(1, Ordering::SeqCst) + 1;
        process.security_domain.set(domain);
        process.parent_security_domain.set(domain);
    }
    let second_set = if page_combine { Flags2::DISABLE_PAGE_COMBINE_MASK } else { 0 } | if store_bypass { Flags2::SPECULATIVE_STORE_BYPASS_DISABLE_MASK } else { 0 };
    if second_set != 0 {
        process.mitigation_flags2.atomic().fetch_or(second_set, Ordering::SeqCst);
    }
    0
}

/// PspGetRedirectionTrustPolicy: 1 impor, 2 auditar, 0 sem a mitigação (o
/// SeTokenGetRedirectionTrustPolicy do token primário).
fn redirection_trust_policy(token: Option<u64>) -> u32 {
    let flags = token.map_or(0, tokens::token_flags);
    if flags & tokens::TOKEN_ENFORCE_REDIRECTION_TRUST != 0 {
        1
    } else if flags & tokens::TOKEN_AUDIT_REDIRECTION_TRUST != 0 {
        2
    } else {
        0
    }
}

/// ProcessRedirectionTrustPolicy: EnforceRedirectionTrust (bit 0) e
/// AuditRedirectionTrust (1, descartado com o 0). O
/// PspSetRedirectionTrustPolicy grava o modo no token primário.
fn redirection_trust(process: u64, flags: u32) -> u32 {
    if flags & !3 != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let enforce = flags & 1 != 0;
    let audit = !enforce && flags & 2 != 0;
    let token = process::get_primary_token(process);
    let current = redirection_trust_policy(token);
    if !enforce && current == 1 {
        return STATUS_ACCESS_DENIED;
    }
    if !audit && !enforce && current == 2 {
        return STATUS_ACCESS_DENIED;
    }
    if let Some(token) = token {
        if enforce {
            tokens::set_redirection_trust_policy(token, false);
        } else if audit {
            tokens::set_redirection_trust_policy(token, true);
        }
    }
    0
}
