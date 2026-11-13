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

// ---- FsRtlIsTotalDeviceFailure ------------------------------------------------
//
// ntoskrnl 19041 rva 0x255200: TRUE para todo status com o bit de sinal
// (`test ecx, ecx; jns` — avisos 0x8xxxxxxx incluídos) exceto os três que o
// original compara — STATUS_CRC_ERROR (0xC000003F), STATUS_DEVICE_DATA_ERROR
// (0xC000009C) e 0xC0000470 —, que indicam falha de um setor e não do
// dispositivo; sucessos e informativos = FALSE.

const TOTAL_FAILURE_EXCEPT_CRC_ERROR: u32 = 0xC000_003F;
const TOTAL_FAILURE_EXCEPT_DEVICE_DATA_ERROR: u32 = 0xC000_009C;
const TOTAL_FAILURE_EXCEPT_0470: u32 = 0xC000_0470;

/// FsRtlIsTotalDeviceFailure(Status).
pub fn is_total_device_failure(status: u32) -> bool {
    (status as i32) < 0 && status != TOTAL_FAILURE_EXCEPT_CRC_ERROR && status != TOTAL_FAILURE_EXCEPT_DEVICE_DATA_ERROR && status != TOTAL_FAILURE_EXCEPT_0470
}
