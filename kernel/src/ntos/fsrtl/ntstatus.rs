//! Classificação de NTSTATUS de exceção do FsRtl — FsRtlIsNtstatusExpected e
//! FsRtlNormalizeNtstatus, reproduzidos da desmontagem do `ntoskrnl` real.

/// Conjunto exato de status "inesperados" da cadeia de `cmp` em
/// FsRtlIsNtstatusExpected (RVA 0x31b530), reproduzido byte-a-byte da
/// desmontagem (comparações com sinal; o resultado é este conjunto).
pub fn is_ntstatus_expected(status: u32) -> bool {
    !matches!(
        status,
        0x8000_0001
            | 0x8000_0002
            | 0x8000_0003
            | 0xC000_0005
            | 0xC000_001D
            | 0xC000_0046
            | 0xC000_0047
            | 0xC000_008C
            | 0xC000_0094
            | 0xC000_0096
            | 0xC000_00AA
            | 0xC000_0409
            | 0xC000_0420
    )
}

/// FsRtlNormalizeNtstatus(Exception, GenericException) -> NTSTATUS.
/// `IsNtstatusExpected(exc) ? exc : generic` (RVA 0x36cae0, `cmove`).
pub fn normalize_ntstatus(exception: u32, generic: u32) -> u32 {
    if is_ntstatus_expected(exception) { exception } else { generic }
}
