//! Kernel Shim Engine (KSE) — o motor de shims de driver/dispositivo do
//! ntoskrnl. KseQueryDeviceFlags 0x75f0f0 (ntoskrnl 19041).
//!
//! KseQueryDeviceFlags(DeviceId, Category, Flags):
//! - se o motor não está inicializado (estado global != 2) ou está
//!   desligado (KseEngine & 2), devolve STATUS_NOT_FOUND sem validar nem
//!   tocar nada;
//! - senão DeviceId/Category/Flags NULL = STATUS_INVALID_PARAMETER; zera
//!   *Flags e consulta KseQueryDeviceData(DeviceId, Category, tipo 0xB, 8
//!   bytes); erro volta; dado de outro tipo = STATUS_NOT_FOUND; senão
//!   registra o evento e grava os flags.
//! O OpenNT não tem o KSE (nenhum banco de shims, nenhum KseRegisterShim
//! efetivo): o motor fica no estado "não inicializado", que é exatamente o
//! primeiro ramo do original.

const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// O motor nunca chega ao estado inicializado (2) no OpenNT.
pub fn engine_initialized() -> bool {
    false
}

/// KseQueryDeviceFlags: com o motor não inicializado o original devolve
/// STATUS_NOT_FOUND antes de olhar os argumentos; *Flags fica intocado.
pub fn query_device_flags(_device_id: u64, _category: u64, _flags_out: u64) -> u32 {
    STATUS_NOT_FOUND
}

// ---- KseRegisterShim -------------------------------------------------------
//
// KseRegisterShim (ntoskrnl 19041 rva 0x7bdb00) -> KseRegisterShimEx(Shim,
// Reserved, Flags, NULL) rva 0x7bdb20: Shim NULL = STATUS_INVALID_PARAMETER;
// motor fora do estado inicializado (2) = STATUS_UNSUCCESSFUL, antes de
// validar o provedor ou tocar no KSE_SHIM. No OpenNT o motor nunca inicializa
// (`engine_initialized`), então todo registro válido termina aí.

const KSE_STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const KSE_STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;

/// KseRegisterShim(Shim, Reserved, Flags).
pub fn register_shim(shim: u64, _reserved: u64, _flags: u32) -> u32 {
    if shim == 0 {
        return KSE_STATUS_INVALID_PARAMETER;
    }
    // engine_initialized() é sempre falso: o ramo "motor não inicializado".
    debug_assert!(!engine_initialized());
    KSE_STATUS_UNSUCCESSFUL
}
