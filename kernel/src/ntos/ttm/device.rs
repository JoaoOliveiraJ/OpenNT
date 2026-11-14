//! Notificações de dispositivo do Terminal Topology Manager
//! (TtmNotifyDeviceArrival, TtmNotifyDeviceDeparture, TtmNotifyDeviceInput).
//!
//! No ntoskrnl 19041 o TTM agrupa dispositivos de entrada e de vídeo em
//! terminais de uma sessão; só funciona com TtmpEnabled = 1, o valor
//! `TtmEnabled` de `Control\Session Manager\Power` lido no boot pelo
//! CmControlVector (sem o valor, o padrão é 0: desktops não o definem). As
//! três notificações começam pela sessão corrente (TtmiAcquireCurrentSession):
//! um processo fora de sessão (o System, PsGetProcessSessionIdEx = -1) dá
//! 0xC0000455; com o TTM desligado, TtmpAcquireSessionById dá
//! STATUS_NOT_SUPPORTED; ligado, só a sessão criada pelo
//! TtmInitCurrentSession é aceita — o OpenNT não cria sessões de TTM, então
//! sobra 0xC0000455. Depois de uma falha a chegada devolve o status e a saída
//! e a entrada não devolvem nada (VOID), como no NT.
//!
//! A chegada valida os parâmetros antes da sessão: Properties
//! (TTM_DEVICE_PROPERTIES) obrigatório com o primeiro ponteiro não nulo e sem
//! os ponteiros em +0x10 e +0x18 ao mesmo tempo; o nome opcional precisa de
//! um texto terminado em NUL dentro de 260 caracteres (RtlStringCchLengthW).

use core::sync::atomic::{AtomicU8, Ordering};

use crate::ntos::cm::registry;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::ps::{process, session};

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
/// O status do TTM sem a sessão pedida.
const STATUS_TTM_SESSION_NOT_FOUND: u32 = 0xC000_0455;
/// Limite do nome do dispositivo (MAX_PATH caracteres).
const NAME_LIMIT: u64 = 0x104;

/// TtmpEnabled: 0 = não lido, 1 = desligado, 2 = ligado.
static ENABLED: AtomicU8 = AtomicU8::new(0);

/// TtmpEnabled, do `TtmEnabled` (REG_DWORD) da chave Power, lido uma vez.
pub fn enabled() -> bool {
    let cached = ENABLED.load(Ordering::Acquire);
    if cached != 0 {
        return cached == 2;
    }
    let value = registry::read_value_by_path("\\Registry\\Machine\\System\\CurrentControlSet\\Control\\Session Manager\\Power", "TtmEnabled").filter(|entry| entry.data.len() >= 4).map(|entry| u32::from_le_bytes([entry.data[0], entry.data[1], entry.data[2], entry.data[3]]));
    let on = value == Some(1);
    ENABLED.store(if on { 2 } else { 1 }, Ordering::Release);
    on
}

/// TtmiAcquireCurrentSession: a sessão de TTM da sessão do processo corrente.
fn acquire_current_session() -> Result<(), u32> {
    if session::query_ex(process::get_current_process()) == 0xFFFF_FFFF {
        return Err(STATUS_TTM_SESSION_NOT_FOUND);
    }
    if !enabled() {
        return Err(STATUS_NOT_SUPPORTED);
    }
    // Nenhum TtmInitCurrentSession criou a sessão de TTM.
    Err(STATUS_TTM_SESSION_NOT_FOUND)
}

fn pointer_at(address: u64) -> u64 {
    // SAFETY: estruturas de entrada de um chamador de modo kernel.
    unsafe { Field::<u64>::at(address) }.get()
}

/// RtlStringCchLengthW(Buffer, 260) do nome: NUL dentro do limite.
fn name_length_valid(buffer: u64) -> bool {
    if buffer == 0 {
        return false;
    }
    // SAFETY: o texto do nome, memória do chamador de modo kernel.
    (0..NAME_LIMIT).any(|index| unsafe { Field::<u16>::at(buffer + index * 2) }.get() == 0)
}

/// TtmNotifyDeviceArrival(DeviceType, DeviceToken, Properties, Flags, Name).
pub fn notify_device_arrival(_device_type: u32, _token: u64, properties: u64, _flags: u32, name: u64) -> u32 {
    if properties == 0 || pointer_at(properties) == 0 || (pointer_at(properties + 0x18) != 0 && pointer_at(properties + 0x10) != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if name != 0 && !name_length_valid(pointer_at(name + 8)) {
        return STATUS_INVALID_PARAMETER;
    }
    match acquire_current_session() {
        Ok(()) => 0,
        Err(status) => status,
    }
}

/// TtmNotifyDeviceDeparture(DeviceType, DeviceToken): sem sessão, nada muda.
pub fn notify_device_departure(_device_type: u32, _token: u64) {
    let _ = acquire_current_session();
}

/// TtmNotifyDeviceInput(DeviceType, DeviceToken, Flags): sem sessão, nada muda.
pub fn notify_device_input(_device_type: u32, _token: u64, _flags: u32) {
    let _ = acquire_current_session();
}

/// O status da sessão de TTM do processo corrente (autotestes).
pub fn session_status() -> u32 {
    acquire_current_session().err().unwrap_or(0)
}
