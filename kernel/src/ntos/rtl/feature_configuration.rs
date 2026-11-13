//! Configuração de features do Rtl — RtlQueryFeatureConfiguration, as
//! notificações de mudança e o relato de uso (RtlNotifyFeatureUsage).
//!
//! Nenhuma configuração de feature é publicada; as notificações só ficam
//! registradas. O relato de uso vai ao Cm com o IRQL efetivo do chamador:
//! com IF (0x200) ligado no EFLAGS do CONTEXT vale o IRQL corrente; com
//! interrupções desligadas o relato é tratado em HIGH_LEVEL. Falha interna do
//! relato interrompe o sistema; o sinal de transferência do CONTEXT continua
//! propagando.

use alloc::vec::Vec;

use crate::ntos::cm::feature_usage;
use crate::ntos::ke::irql;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::native_context;
use crate::rtl::{KernelError, SpinLock};

const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// Notificações de mudança de feature (callback, contexto).
static FEATURE_NOTIFICATIONS: SpinLock<Vec<(u64, u64)>> = SpinLock::new(Vec::new());

/// RtlQueryFeatureConfiguration: nenhuma configuração de feature publicada.
pub fn query() -> u32 {
    STATUS_NOT_FOUND
}

/// RtlRegisterFeatureConfigurationChangeNotification: o handle devolvido é o
/// próprio callback.
pub fn register_change_notification(callback: u64, context: u64, handle_out: u64) {
    FEATURE_NOTIFICATIONS.lock().push((callback, context));
    if handle_out != 0 {
        guest::write64(handle_out, callback);
    }
}

/// RtlUnregisterFeatureConfigurationChangeNotification: STATUS_NOT_FOUND
/// para um handle desconhecido.
pub fn unregister_change_notification(handle: u64) -> u32 {
    let mut notifications = FEATURE_NOTIFICATIONS.lock();
    let Some(index) = notifications.iter().position(|(callback, _)| *callback == handle) else { return STATUS_NOT_FOUND };
    notifications.remove(index);
    0
}

/// RtlNotifyFeatureUsage: entrega o relato ao Cm no IRQL efetivo.
pub fn notify_usage(report: u64) -> Result<u32, KernelError> {
    let flags = guest::read32(native_context::current()? + 0x44);
    let level = if flags & 0x200 != 0 { irql::get_irql() } else { 15 };
    match feature_usage::notify(report, Some(level)) {
        Err(error) if !native_context::is_transfer(&error) => {
            debug_print!("[feature-usage] fatal kernel report failure: {}", error);
            panic!("[feature-usage] fatal kernel report failure: {error}");
        }
        result => result,
    }
}
