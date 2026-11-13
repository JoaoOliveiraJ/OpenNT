//! Callbacks de power setting (PoRegister/PoUnregisterPowerSettingCallback).
//!
//! Os callbacks registrados ficam guardados para quando um setting mudar;
//! hoje nenhum muda, então nenhum é disparado. O handle devolvido ao driver
//! é o endereço do próprio callback.

use alloc::vec::Vec;

use crate::ntos::mm::guest_memory as guest;
use crate::rtl::SpinLock;

const STATUS_NOT_FOUND: u32 = 0xC000_0225;

/// Callback de power setting (disparado quando um setting muda; hoje
/// nenhum muda).
struct PowerSettingCallback {
    callback: u64,
    _context: u64,
    _device: u64,
    _setting_guid: u64,
}

static POWER_SETTING_CALLBACKS: SpinLock<Vec<PowerSettingCallback>> = SpinLock::new(Vec::new());

/// PoRegisterPowerSettingCallback(device, &setting_guid, callback, context,
/// &handle): guarda o callback e grava o handle quando pedido.
pub fn register_callback(device: u64, setting_guid: u64, callback: u64, context: u64, handle_out: u64) {
    POWER_SETTING_CALLBACKS.lock().push(PowerSettingCallback { callback, _context: context, _device: device, _setting_guid: setting_guid });
    if handle_out != 0 {
        guest::write64(handle_out, callback);
    }
}

/// PoUnregisterPowerSettingCallback(handle): STATUS_NOT_FOUND para um handle
/// desconhecido. Devolve o NTSTATUS.
pub fn unregister_callback(handle: u64) -> u32 {
    let mut callbacks = POWER_SETTING_CALLBACKS.lock();
    let Some(index) = callbacks.iter().position(|entry| entry.callback == handle) else { return STATUS_NOT_FOUND };
    callbacks.remove(index);
    0
}
