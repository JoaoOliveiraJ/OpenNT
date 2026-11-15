//! Windows Hardware Error Architecture (WHEA).
//!
//! O OpenNT não tem HEST nem PSHED: só as fontes de erro registradas por
//! drivers (tipos não-HEST) existem. Ver `error_source`.

pub mod error_source;
pub mod exports;

use crate::ntos::mm::guest_memory as guest;

/// 'WhLg', a assinatura do WHEA_EVENT_LOG_ENTRY_HEADER.
const EVENT_LOG_SIGNATURE: u32 = 0x674C_6857;

/// Eventos internos aceitos (o contador dos testes).
static LOGGED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// WheaLogInternalEvent(Entry): o PSHED e a HAL registram eventos internos
/// do WHEA (WHEA_EVENT_LOG_ENTRY: cabeçalho 'WhLg' com Flags em +0x18 e o
/// tamanho do conteúdo em +0x1C). No NT o evento vai ao provedor ETW do
/// WHEA (Flags bit 1) e ao log de erros (bits 2 e 3); o OpenNT não tem
/// consumidor ETW nem log de eventos do WHEA, então o evento é aceito e
/// descartado, como um provedor sem sessão.
pub fn log_internal_event(entry: u64) {
    if entry == 0 || guest::read32(entry) != EVENT_LOG_SIGNATURE {
        return;
    }
    LOGGED.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

/// Eventos internos aceitos desde o boot.
pub fn logged_internal_events() -> u32 {
    LOGGED.load(core::sync::atomic::Ordering::SeqCst)
}
