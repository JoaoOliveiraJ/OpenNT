//! Tradução de NTSTATUS para códigos de erro Win32 —
//! RtlNtStatusToDosError e RtlNtStatusToDosErrorNoTeb — e de SECURITY_STATUS
//! (SEC_E_*) para NTSTATUS — RtlMapSecurityErrorToNtStatus.
//!
//! Subconjunto da tabela real usado pelos drivers; sem mapeamento =
//! ERROR_MR_MID_NOT_FOUND (317).

/// RtlMapSecurityErrorToNtStatus (ntoskrnl 19041 rva 0x31cd40): os SEC_E_*
/// que têm NTSTATUS próprio, lidos da tabela de saltos do original; todo
/// outro valor volta igual.
pub fn map_security_error_to_status(error: u32) -> u32 {
    match error {
        0x8009_0300 => 0xC000_009A, // SEC_E_INSUFFICIENT_MEMORY
        0x8009_0301 => 0xC000_0008, // SEC_E_INVALID_HANDLE
        0x8009_0302 => 0xC000_00BB, // SEC_E_UNSUPPORTED_FUNCTION
        0x8009_0303 => 0xC000_00BE, // SEC_E_TARGET_UNKNOWN
        0x8009_0304 => 0xC000_00E5, // SEC_E_INTERNAL_ERROR
        0x8009_0305 | 0x8009_0307 | 0x8009_0316 => 0xC000_00FE, // SEC_E_SECPKG_NOT_FOUND, SEC_E_CANNOT_INSTALL, SEC_E_BAD_PKGID
        0x8009_0306 => 0xC000_0061, // SEC_E_NOT_OWNER
        0x8009_0308 | 0x8009_0309 | 0x8009_035D => 0xC000_000D, // SEC_E_INVALID_TOKEN, SEC_E_CANNOT_PACK, SEC_E_INVALID_PARAMETER
        0x8009_030A | 0x8009_0331 => 0xC000_00BB, // SEC_E_QOP_NOT_SUPPORTED, SEC_E_ALGORITHM_MISMATCH
        0x8009_030B => 0xC000_010D, // SEC_E_NO_IMPERSONATION
        0x8009_030C => 0xC000_006D, // SEC_E_LOGON_DENIED
        0x8009_030D | 0x8009_030E => 0xC000_005F, // SEC_E_UNKNOWN_CREDENTIALS, SEC_E_NO_CREDENTIALS
        0x8009_030F | 0x8009_0310 => 0xC000_0022, // SEC_E_MESSAGE_ALTERED, SEC_E_OUT_OF_SEQUENCE
        0x8009_0311 => 0xC000_005E, // SEC_E_NO_AUTHENTICATING_AUTHORITY
        0x8009_0324 => 0xC000_0133, // SEC_E_TIME_SKEW
        other => other,
    }
}

/// RtlNtStatusToDosError: a tabela real (subconjunto usado por drivers);
/// sem mapeamento = ERROR_MR_MID_NOT_FOUND (317).
pub fn status_to_dos_error(status: u32) -> u32 {
    match status {
        0x0000_0000 => 0,
        0x8000_0005 => 234,
        0xC000_0001 => 31,
        0xC000_0002 => 1,
        0xC000_0004 => 24,
        0xC000_0005 => 998,
        0xC000_0008 => 6,
        0xC000_000D => 87,
        0xC000_0017 => 8,
        0xC000_0022 => 5,
        0xC000_0023 => 122,
        0xC000_0034 => 2,
        0xC000_0035 => 183,
        0xC000_003A => 3,
        0xC000_0043 => 32,
        0xC000_009A => 8,
        0xC000_009D => 1167,
        0xC000_00A5 => 31,
        0xC000_00BB => 50,
        0xC000_0185 => 1117,
        0xC000_0225 => 1168,
        _ => 317,
    }
}
