//! Detecção de ociosidade por dispositivo (PoRegisterDeviceForIdleDetection,
//! PoSetDeviceBusyEx).
//!
//! Cada dispositivo registrado ganha um contador de ociosidade real de 32
//! bits no pool do convidado; o driver o zera a cada atividade.

use alloc::collections::BTreeMap;

use crate::ntos::inc::types::{DeviceObject, Field, NtStruct};
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
    // SAFETY: o contador PULONG devolvido por PoRegisterDeviceForIdleDetection.
    unsafe { Field::<u32>::at(counter) }.set(0);
}

/// PopDisksRegisteredForIdle: algum registro é de disco (o IdleType
/// DeviceIdleDisk que o PoRegisterDeviceForIdleDetection dá a um
/// FILE_DEVICE_DISK ou FILE_DEVICE_MASS_STORAGE sem FILE_REMOVABLE_MEDIA,
/// fora de uma plataforma AoAc).
pub fn disks_registered() -> bool {
    const FILE_DEVICE_DISK: u32 = 7;
    const FILE_DEVICE_MASS_STORAGE: u32 = 0x2D;
    const FILE_REMOVABLE_MEDIA: u32 = 1;
    IDLE_COUNTERS.lock().keys().any(|&device| {
        // O DEVICE_OBJECT vem do driver: lido com sonda.
        let Ok(object) = DeviceObject::try_at(device) else { return false };
        matches!(object.device_type.probe_get(), Ok(FILE_DEVICE_DISK | FILE_DEVICE_MASS_STORAGE)) && object.characteristics.probe_get().is_ok_and(|characteristics| characteristics & FILE_REMOVABLE_MEDIA == 0)
    })
}
