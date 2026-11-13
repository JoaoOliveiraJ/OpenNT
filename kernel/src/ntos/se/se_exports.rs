//! Tabela SE_EXPORTS.
//!
//! Corresponde ao kernel 10.0.19041.6456, na ordem da inicialização nativa.
//! LUIDs de privilégios e SIDs identificam recursos; publicar a tabela não
//! concede direitos a tokens.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::model;
use crate::ntos::mm::kernel_data;
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;

/// LUID numérico, ou autoridade e subautoridades de um SID.
enum Field {
    Privilege(u64),
    Sid(u64, &'static [u32]),
}

use Field::{Privilege as P, Sid as S};

const FIELDS: &[(&str, Field)] = &[
    ("SeCreateTokenPrivilege", P(2)),
    ("SeAssignPrimaryTokenPrivilege", P(3)),
    ("SeLockMemoryPrivilege", P(4)),
    ("SeIncreaseQuotaPrivilege", P(5)),
    ("SeUnsolicitedInputPrivilege", P(6)),
    ("SeTcbPrivilege", P(7)),
    ("SeSecurityPrivilege", P(8)),
    ("SeTakeOwnershipPrivilege", P(9)),
    ("SeLoadDriverPrivilege", P(10)),
    ("SeCreatePagefilePrivilege", P(15)),
    ("SeIncreaseBasePriorityPrivilege", P(14)),
    ("SeSystemProfilePrivilege", P(11)),
    ("SeSystemtimePrivilege", P(12)),
    ("SeProfileSingleProcessPrivilege", P(13)),
    ("SeCreatePermanentPrivilege", P(16)),
    ("SeBackupPrivilege", P(17)),
    ("SeRestorePrivilege", P(18)),
    ("SeShutdownPrivilege", P(19)),
    ("SeDebugPrivilege", P(20)),
    ("SeAuditPrivilege", P(21)),
    ("SeSystemEnvironmentPrivilege", P(22)),
    ("SeChangeNotifyPrivilege", P(23)),
    ("SeRemoteShutdownPrivilege", P(24)),
    ("SeNullSid", S(0, &[0])),
    ("SeWorldSid", S(1, &[0])),
    ("SeLocalSid", S(2, &[0])),
    ("SeCreatorOwnerSid", S(3, &[0])),
    ("SeCreatorGroupSid", S(3, &[1])),
    ("SeNtAuthoritySid", S(5, &[])),
    ("SeDialupSid", S(5, &[1])),
    ("SeNetworkSid", S(5, &[2])),
    ("SeBatchSid", S(5, &[3])),
    ("SeInteractiveSid", S(5, &[4])),
    ("SeLocalSystemSid", S(5, &[18])),
    ("SeAliasAdminsSid", S(5, &[32, 544])),
    ("SeAliasUsersSid", S(5, &[32, 545])),
    ("SeAliasGuestsSid", S(5, &[32, 546])),
    ("SeAliasPowerUsersSid", S(5, &[32, 547])),
    ("SeAliasAccountOpsSid", S(5, &[32, 548])),
    ("SeAliasSystemOpsSid", S(5, &[32, 549])),
    ("SeAliasPrintOpsSid", S(5, &[32, 550])),
    ("SeAliasBackupOpsSid", S(5, &[32, 551])),
    ("SeAuthenticatedUsersSid", S(5, &[11])),
    ("SeRestrictedSid", S(5, &[12])),
    ("SeAnonymousLogonSid", S(5, &[7])),
    ("SeUndockPrivilege", P(25)),
    ("SeSyncAgentPrivilege", P(26)),
    ("SeEnableDelegationPrivilege", P(27)),
    ("SeLocalServiceSid", S(5, &[19])),
    ("SeNetworkServiceSid", S(5, &[20])),
    ("SeManageVolumePrivilege", P(28)),
    ("SeImpersonatePrivilege", P(29)),
    ("SeCreateGlobalPrivilege", P(30)),
    ("SeTrustedCredManAccessPrivilege", P(31)),
    ("SeRelabelPrivilege", P(32)),
    ("SeIncreaseWorkingSetPrivilege", P(33)),
    ("SeTimeZonePrivilege", P(34)),
    ("SeCreateSymbolicLinkPrivilege", P(35)),
    ("SeIUserSid", S(5, &[17])),
    ("SeUntrustedMandatorySid", S(16, &[0])),
    ("SeLowMandatorySid", S(16, &[0x1000])),
    ("SeMediumMandatorySid", S(16, &[0x2000])),
    ("SeHighMandatorySid", S(16, &[0x3000])),
    ("SeSystemMandatorySid", S(16, &[0x4000])),
    ("SeOwnerRightsSid", S(3, &[4])),
    ("SeAllAppPackagesSid", S(15, &[2, 1])),
    ("SeUserModeDriversSid", S(5, &[84, 0, 0, 0, 0, 0])),
    ("SeProcTrustWinTcbSid", S(19, &[1024, 8192])),
    ("SeTrustedInstallerSid", S(5, &[80, 956_008_885, 3_418_522_649, 1_831_038_044, 1_853_292_631, 2_271_478_464])),
    ("SeDelegateSessionUserImpersonatePrivilege", P(36)),
];

/// Ponteiro publicado depois da escrita completa; zero = ainda não existe.
static TABLE: AtomicU64 = AtomicU64::new(0);

/// Quantidade de campos de oito bytes depois da célula pública.
pub fn field_count() -> usize {
    FIELDS.len()
}

/// Índice do campo pelo nome do export (diagnóstico e testes).
pub fn field_index(name: &str) -> Option<usize> {
    FIELDS.iter().position(|(field, _)| *field == name)
}

/// Preenche a reserva permanente de SeExports uma única vez, publicando o
/// ponteiro por último.
pub fn init() -> Result<u64, KernelError> {
    let published = TABLE.load(Ordering::Acquire);
    if published != 0 {
        return Ok(published);
    }
    let (address, size) = kernel_data::region("SeExports")?;
    // Privilégios ficam na tabela; SIDs ganham corpos binários depois dos campos.
    let bodies: Vec<Option<model::Sid>> = FIELDS.iter().map(|(_, field)| match field {
        Field::Sid(authority, parts) => Some(model::sid(*authority, parts)),
        Field::Privilege(_) => None,
    }).collect();
    let required = 8 + FIELDS.len() * 8 + bodies.iter().flatten().map(Vec::len).sum::<usize>();
    if required as u64 != size {
        return Err(KernelError::new("SeExports: kernel data storage disagrees with the complete table"));
    }
    if kernel_data::read("SeExports") != 0 {
        return Err(KernelError::new("SeExports: unexpected previous publication"));
    }
    let mut bytes = alloc::vec![0u8; required];
    let mut body_offset = 8 + FIELDS.len() * 8;
    for (index, ((_, field), body)) in FIELDS.iter().zip(&bodies).enumerate() {
        let value = match (field, body) {
            (_, Some(body)) => {
                let pointer = address + body_offset as u64;
                bytes[body_offset..body_offset + body.len()].copy_from_slice(body);
                body_offset += body.len();
                pointer
            }
            (Field::Privilege(luid), None) => *luid,
            (Field::Sid(..), None) => unreachable!(),
        };
        bytes[8 + index * 8..16 + index * 8].copy_from_slice(&value.to_le_bytes());
    }
    // O ponteiro público fica NULL até campos e SIDs estarem prontos.
    guest::write_bytes(address + 8, &bytes[8..]);
    kernel_data::write("SeExports", address + 8);
    TABLE.store(address + 8, Ordering::Release);
    Ok(address + 8)
}
