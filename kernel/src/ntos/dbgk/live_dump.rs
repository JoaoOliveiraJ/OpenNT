//! Callbacks de dump de memória do kernel ao vivo (LKMD):
//! DbgkLkmdRegisterCallback, como no ntoskrnl 19041.
//!
//! Oito slots, cada um com a rotina, o contexto e as flags (o
//! EX_CALLBACK_ROUTINE_BLOCK do ExAllocateCallBack e o DWORD das flags ao
//! lado do slot). Flags com os dois bits baixos ligados são inválidas
//! (STATUS_INVALID_PARAMETER); uma rotina já registrada dá 0xC0000718 e,
//! sem slot livre, 0xC000042B, os códigos do NT. O dump ao vivo que
//! chamaria os registrados ainda não existe
//! no OpenNT: os callbacks ficam guardados para ele.

use crate::rtl::SpinLock;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
/// A rotina já está num slot.
const STATUS_CALLBACK_ALREADY_REGISTERED: u32 = 0xC000_0718;
/// Os oito slots estão ocupados.
const STATUS_NO_FREE_SLOT: u32 = 0xC000_042B;
const SLOTS: usize = 8;

/// Uma rotina registrada: (rotina, contexto, flags).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Registration {
    pub callback: u64,
    pub context: u64,
    pub flags: u32,
}

static CALLBACKS: SpinLock<[Option<Registration>; SLOTS]> = SpinLock::new([None; SLOTS]);

/// DbgkLkmdRegisterCallback(Callback, Context, Flags).
pub fn register(callback: u64, context: u64, flags: u32) -> u32 {
    if flags & 3 == 3 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut slots = CALLBACKS.lock();
    if slots.iter().flatten().any(|registration| registration.callback == callback) {
        return STATUS_CALLBACK_ALREADY_REGISTERED;
    }
    match slots.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => {
            *slot = Some(Registration { callback, context, flags });
            0
        }
        None => STATUS_NO_FREE_SLOT,
    }
}

/// O registro de `callback`, se houver.
pub fn registration(callback: u64) -> Option<Registration> {
    CALLBACKS.lock().iter().flatten().find(|registration| registration.callback == callback).copied()
}

/// Tira `callback` do seu slot (o lado do DbgkLkmdUnregisterCallback).
pub fn unregister(callback: u64) -> bool {
    let mut slots = CALLBACKS.lock();
    match slots.iter_mut().find(|slot| slot.is_some_and(|registration| registration.callback == callback)) {
        Some(slot) => {
            *slot = None;
            true
        }
        None => false,
    }
}
