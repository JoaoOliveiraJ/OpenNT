//! Limite de latência do sistema do PoFx e o VSync do vídeo
//! (PoNotifyVSyncChange).
//!
//! Como no ntoskrnl 19041: PoNotifyVSyncChange(Enabled) grava
//! PopFxVSyncEnabled sob o PopFxSystemLatencyLock e chama o
//! PoFxSendSystemLatencyUpdate, que recalcula o limite sem resiliência
//! (PopFxGetLatencyLimitWithoutResiliency): com o VSync ligado (e a
//! atualização por VSync permitida, PpmDisableVsyncLatencyUpdate = 0) o
//! limite é o do quadro (13001 µs, o valor do ALMOSTRO do 19041); desligado,
//! o PpmLatencyToleranceLimit (100000 µs). Se o valor mudou, ele vira o
//! PopFxSystemLatencyHint, os plugins de PEP são notificados (o OpenNT não tem
//! nenhum) e o PopFxSystemLatencyLimit recebe o novo valor. O VSync começa
//! ligado (PopFxVSyncEnabled = 1) e o limite em 0xFFFFFFFF, até o primeiro
//! recálculo.

use crate::rtl::SpinLock;

/// PpmLatencyToleranceLimit (µs).
pub const LATENCY_TOLERANCE_LIMIT: u32 = 100_000;
/// O limite com VSync ligado (µs).
pub const VSYNC_LATENCY_LIMIT: u32 = 13_001;
/// PpmDisableVsyncLatencyUpdate.
const DISABLE_VSYNC_LATENCY_UPDATE: bool = false;

struct SystemLatency {
    /// PopFxVSyncEnabled.
    vsync_enabled: bool,
    /// PopFxSystemLatencyLimit.
    limit: u32,
    /// PopFxSystemLatencyHint.
    hint: u32,
}

/// PopFxSystemLatencyLock e o estado que ele protege.
static LATENCY: SpinLock<SystemLatency> = SpinLock::new(SystemLatency { vsync_enabled: true, limit: u32::MAX, hint: u32::MAX });

/// PopFxGetLatencyLimitWithoutResiliency.
fn limit_without_resiliency(latency: &SystemLatency) -> u32 {
    if !DISABLE_VSYNC_LATENCY_UPDATE && latency.vsync_enabled { VSYNC_LATENCY_LIMIT } else { LATENCY_TOLERANCE_LIMIT }
}

/// PoFxSendSystemLatencyUpdate (com o lock retido).
fn send_system_latency_update(latency: &mut SystemLatency) {
    let limit = limit_without_resiliency(latency);
    if limit == latency.limit {
        return;
    }
    latency.hint = limit;
    // PoFxSystemLatencyNotify: a lista de plugins de PEP está vazia.
    latency.limit = limit;
}

/// PoNotifyVSyncChange(BOOLEAN Enabled).
pub fn notify_vsync_change(enabled: bool) {
    let mut latency = LATENCY.lock();
    latency.vsync_enabled = enabled;
    send_system_latency_update(&mut latency);
}

/// (VSync ligado, limite, dica) correntes.
pub fn system_latency() -> (bool, u32, u32) {
    let latency = LATENCY.lock();
    (latency.vsync_enabled, latency.limit, latency.hint)
}
