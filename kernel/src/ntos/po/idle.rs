//! Detecção de ociosidade por dispositivo (PoRegisterDeviceForIdleDetection,
//! PoSetDeviceBusyEx).
//!
//! Cada dispositivo registrado ganha um contador de ociosidade real de 32
//! bits no pool do convidado; o driver o zera a cada atividade.

use alloc::collections::BTreeMap;

use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

/// Contadores de ociosidade por dispositivo.
static IDLE_COUNTERS: SpinLock<BTreeMap<u64, u64>> = SpinLock::new(BTreeMap::new());

/// PoRegisterDeviceForIdleDetection(device, ...): o contador de ociosidade
/// real do dispositivo (zerado por PoSetDeviceBusyEx).
pub fn register_device(device: u64) -> u64 {
    let counter = guest::alloc_bytes(4);
    IDLE_COUNTERS.lock().insert(device, counter);
    counter
}

/// PoSetDeviceBusyEx(counter): zera o contador de ociosidade.
pub fn set_device_busy(counter: u64) {
    guest::write32(counter, 0);
}
