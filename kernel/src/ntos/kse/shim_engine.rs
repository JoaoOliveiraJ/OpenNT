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
