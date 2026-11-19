//! SystemConsoleInformation (132): o NtSetSystemInformation que carrega e
//! descarrega o condrv.sys, como no ntoskrnl 19041 (0x708e34):
//! - Length diferente de 4 é STATUS_INFO_LENGTH_MISMATCH;
//! - com o bit DriverLoaded (bit 0 do primeiro byte), o ZwLoadDriver da chave
//!   `\Registry\Machine\System\CurrentControlSet\Services\condrv` sob o
//!   ExpConDrvLoadLock (push lock exclusivo numa região crítica), sem checar
//!   privilégio (o ZwLoadDriver roda em KernelMode); devolve o status dele
//!   (um condrv já carregado dá STATUS_IMAGE_ALREADY_LOADED);
//! - sem o bit, o SeLoadDriverPrivilege do PreviousMode
//!   (STATUS_PRIVILEGE_NOT_HELD) e o ZwUnloadDriver da mesma chave.
//!
//! O kernelbase (ConsoleAllocate 0x487cc) chama a classe quando o
//! `\Device\ConDrv\Server` ainda não existe, ignora o status e abre o
//! servidor de novo.

use alloc::vec::Vec;
use core::sync::atomic::AtomicU64;

use crate::ntos::ex::push_lock;
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::status::{STATUS_INSUFFICIENT_RESOURCES, STATUS_UNSUCCESSFUL};
use crate::ntos::inc::types::UnicodeString;
use crate::ntos::io::driver_load;
use crate::ntos::ke::critical_region;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::se::privilege;

/// SYSTEM_INFORMATION_CLASS SystemConsoleInformation.
pub const SYSTEM_CONSOLE_INFORMATION: u32 = 132;
/// A chave de serviço do condrv.sys (o literal do ntoskrnl, Length 0x74).
const CONDRV_SERVICE: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\condrv";
/// SYSTEM_CONSOLE_INFORMATION.DriverLoaded.
const DRIVER_LOADED: u8 = 1;
/// SE_LOAD_DRIVER_PRIVILEGE.
const SE_LOAD_DRIVER_PRIVILEGE: u64 = 10;
const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
const STATUS_PRIVILEGE_NOT_HELD: u32 = 0xC000_0061;

/// ExpConDrvLoadLock (EX_PUSH_LOCK).
static CON_DRV_LOAD_LOCK: AtomicU64 = AtomicU64::new(0);

/// NtSetSystemInformation(SystemConsoleInformation): `buffer` já sondado
/// pelo chamador de modo usuário (alinhamento 4 e faixa, em
/// `system_information::set_from_user_mode`); `previous_mode` 0 KernelMode,
/// 1 UserMode. Devolve o NTSTATUS.
pub fn set(buffer: u64, length: u32, previous_mode: u8) -> u32 {
    if length != 4 {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // A leitura do buffer dentro do __try do serviço.
    let Ok(information) = guest::try_read::<u8>(buffer) else { return STATUS_ACCESS_VIOLATION };
    let load = information & DRIVER_LOADED != 0;
    if !load && !privilege::single_privilege_check(SE_LOAD_DRIVER_PRIVILEGE, previous_mode as u32) {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    // A UNICODE_STRING de kernel {0x74, 0x76, texto} sobre o literal.
    let units: Vec<u8> = CONDRV_SERVICE.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    let name = guest::alloc_bytes(UnicodeString::SIZE + units.len() as u64);
    if name == 0 {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    guest::write_bytes(name + UnicodeString::SIZE, &units);
    // SAFETY: UNICODE_STRING recém-alocada.
    let string = unsafe { UnicodeString::at(name) };
    string.length.set(units.len() as u16 - 2);
    string.maximum_length.set(units.len() as u16);
    string.buffer.set(name + UnicodeString::SIZE);
    // O ZwLoadDriver/ZwUnloadDriver: o resto em KernelMode.
    let status = if load {
        let lock = CON_DRV_LOAD_LOCK.as_ptr() as u64;
        crate::ntos::ps::previous_mode::with_kernel(|| {
            critical_region::with_critical(|| {
                push_lock::acquire_exclusive(lock, 0)?;
                let status = driver_load::load_driver_image(name, 0);
                push_lock::release_exclusive(lock, 0)?;
                Ok(status)
            })
        })
        .and_then(|status| status)
        .unwrap_or(STATUS_UNSUCCESSFUL)
    } else {
        crate::ntos::ps::previous_mode::with_kernel(|| driver_load::unload_driver_image(name, 0)).unwrap_or(STATUS_UNSUCCESSFUL)
    };
    guest::free_bytes(name);
    debug_print!("[ex] SystemConsoleInformation: {} condrv -> {:#x}", if load { "carga" } else { "descarga" }, status);
    status
}
