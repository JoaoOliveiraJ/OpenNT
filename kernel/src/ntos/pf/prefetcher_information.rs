//! SystemPrefetcherInformation (NtSetSystemInformation 56):
//! PfSnSetPrefetcherInformation (ntoskrnl 19041, 0x709b5c).
//!
//! - A entrada é o PREFETCHER_INFORMATION de exatamente 0x20 bytes (senão
//!   STATUS_INFO_LENGTH_MISMATCH): Version 1 e Magic 'kuhC', senão
//!   STATUS_INVALID_PARAMETER.
//! - As classes fora de {3, 5, 8} pedem o SeProfileSingleProcessPrivilege
//!   (senão STATUS_ACCESS_DENIED).
//! - 3 (fase do boot): um ULONG (senão STATUS_INVALID_PARAMETER); o modo
//!   usuário só pode anunciar a fase 2 (senão STATUS_ACCESS_DENIED); o
//!   PfSnBeginBootPhase (0x99b274) recusa a fase 5 em diante com
//!   STATUS_INVALID_PARAMETER e nas outras só troca as flags do prefetcher.
//! - 5 (operação: o OperationStart/OperationEnd do advapi32): o PF_OPERATION
//!   de 0xC bytes (senão STATUS_INVALID_PARAMETER). O PfSnOperationProcess
//!   (0x6a51b8) confere Version 1, o byte de flags menor que 2, o reservado
//!   zero e o código (com a flag de fim, menor que 2; sem ela, menor que 8 e
//!   sem os bits 0-1 junto com o 2); depois o PfSnCheckScenario (0x62eb58)
//!   recusa o cenário desligado e a operação volta com sucesso.
//! - 6 (atualização de entrada do cache): 0x48 bytes (senão
//!   STATUS_INVALID_BUFFER_SIZE) com o primeiro ULONG 2 (senão
//!   STATUS_INVALID_PARAMETER).
//! - 8 (cenário de lançamento de aplicativo: o ActivateProcessIfNeeded do
//!   rpcss): 0x10 bytes (senão STATUS_INVALID_BUFFER_SIZE); o
//!   PfSnAppLaunchScenarioControl (0x8e0830) quer Version 1 (senão
//!   STATUS_REVISION_MISMATCH), o tipo diferente de zero (senão
//!   STATUS_INVALID_PARAMETER) e o handle do processo com
//!   PROCESS_VM_OPERATION, e volta com sucesso.
//! - Outras classes: STATUS_INVALID_INFO_CLASS.
//!
//! O OpenNT não tem o prefetcher: os cenários dele estão desligados (como um
//! EnablePrefetcher 0), então as operações, o cache e os lançamentos não
//! guardam nada, e o que sobra é a validação do 19041.

use crate::ntos::inc::types::extra_ps_user::PrefetcherInformation;
use crate::ntos::inc::types::NtStruct;
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
const STATUS_REVISION_MISMATCH: u32 = 0xC000_0059;
const STATUS_INVALID_BUFFER_SIZE: u32 = 0xC000_0206;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;
/// PREFETCHER_INFORMATION.Magic: 'kuhC'.
const PREFETCHER_MAGIC: u32 = 0x6B75_6843;
const PREFETCHER_VERSION: u32 = 1;
/// As classes que não pedem privilégio (a máscara 0x128).
const UNPRIVILEGED_CLASSES: u32 = 0x128;
/// SE_PROF_SINGLE_PROCESS_PRIVILEGE.
const SE_PROF_SINGLE_PROCESS_PRIVILEGE: u64 = 13;
/// PROCESS_VM_OPERATION.
const PROCESS_VM_OPERATION: u32 = 8;
/// PrefetcherBootPhase, PrefetcherScenarioOperation,
/// PrefetcherCacheEntryUpdate e PrefetcherAppLaunchScenarioControl.
const BOOT_PHASE: u32 = 3;
const SCENARIO_OPERATION: u32 = 5;
const CACHE_ENTRY_UPDATE: u32 = 6;
const APP_LAUNCH_SCENARIO_CONTROL: u32 = 8;
/// A única fase do boot que o modo usuário anuncia.
const USER_BOOT_PHASE: u32 = 2;

/// A cópia de `length` bytes do buffer interno: no modo usuário, sondado
/// com o alinhamento pedido (o ProbeForRead e o __try do 19041).
fn capture(address: u64, length: usize, alignment: u64, user: bool) -> Result<alloc::vec::Vec<u8>, u32> {
    if user {
        if address & (alignment - 1) != 0 {
            return Err(STATUS_DATATYPE_MISALIGNMENT);
        }
        let source = address.min(crate::ntos::mm::memory_map::USER_PROBE_ADDRESS);
        return guest::try_read_bytes(source, length).map_err(|error| if error.status != 0 { error.status } else { STATUS_ACCESS_VIOLATION });
    }
    Ok(guest::read_bytes(address, length))
}

fn ulong(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3]])
}

/// PfSnOperationProcess sobre o PF_OPERATION capturado: a validação e o
/// cenário desligado (sucesso).
fn operation(operation: &[u8]) -> u32 {
    let (version, flags, reserved) = (operation[0], operation[1], u16::from_le_bytes([operation[2], operation[3]]));
    if version != 1 || flags >= 2 || reserved != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let code = ulong(operation, 4);
    let valid = if flags & 1 != 0 { code < 2 } else { !(code & 4 != 0 && code & 3 != 0) && code < 8 };
    if !valid {
        return STATUS_INVALID_PARAMETER;
    }
    0
}

/// PfSnSetPrefetcherInformation(Buffer, Length, PreviousMode): o NTSTATUS.
pub fn set(buffer: u64, length: u32, user: bool) -> Result<u32, KernelError> {
    if length as u64 != PrefetcherInformation::SIZE {
        return Ok(STATUS_INFO_LENGTH_MISMATCH);
    }
    let header = match capture(buffer, PrefetcherInformation::SIZE as usize, 1, user) {
        Ok(bytes) => bytes,
        Err(status) => return Ok(status),
    };
    let block = guest::alloc_bytes(PrefetcherInformation::SIZE);
    if block == 0 {
        return Ok(crate::ntos::inc::status::STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write_bytes(block, &header);
    // SAFETY: a cópia de kernel de 0x20 bytes recém-alocada.
    let information = unsafe { PrefetcherInformation::at(block) };
    let (version, magic, class, inner, inner_length) = (information.version.get(), information.magic.get(), information.prefetcher_information_class.get(), information.prefetcher_information.get(), information.prefetcher_information_length.get());
    guest::free_bytes(block);
    if version != PREFETCHER_VERSION || magic != PREFETCHER_MAGIC {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if (class > 8 || UNPRIVILEGED_CLASSES & (1 << class) == 0) && !crate::ntos::se::privilege::single_privilege_check(SE_PROF_SINGLE_PROCESS_PRIVILEGE, user as u32) {
        return Ok(STATUS_ACCESS_DENIED);
    }
    Ok(match class {
        BOOT_PHASE => {
            if inner_length != 4 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let phase = match capture(inner, 4, 4, user) {
                Ok(bytes) => ulong(&bytes, 0),
                Err(status) => return Ok(status),
            };
            if phase != USER_BOOT_PHASE && user {
                return Ok(STATUS_ACCESS_DENIED);
            }
            if phase >= 5 { STATUS_INVALID_PARAMETER } else { 0 }
        }
        SCENARIO_OPERATION => {
            if inner_length != 0xC {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            match capture(inner, 0xC, 4, user) {
                Ok(bytes) => operation(&bytes),
                Err(status) => status,
            }
        }
        CACHE_ENTRY_UPDATE => {
            if inner_length != 0x48 {
                return Ok(STATUS_INVALID_BUFFER_SIZE);
            }
            match capture(inner, 0x48, 4, user) {
                Ok(bytes) if ulong(&bytes, 0) == 2 => 0,
                Ok(_) => STATUS_INVALID_PARAMETER,
                Err(status) => status,
            }
        }
        APP_LAUNCH_SCENARIO_CONTROL => {
            if inner_length != 0x10 {
                return Ok(STATUS_INVALID_BUFFER_SIZE);
            }
            let control = match capture(inner, 0x10, 8, user) {
                Ok(bytes) => bytes,
                Err(status) => return Ok(status),
            };
            if ulong(&control, 0) != 1 {
                return Ok(STATUS_REVISION_MISMATCH);
            }
            if ulong(&control, 4) == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            let handle = u64::from_le_bytes(control[8..16].try_into().unwrap_or([0; 8]));
            match crate::ntos::ob::process_reference::reference(handle, PROCESS_VM_OPERATION, user as u8)? {
                Ok(mut process) => {
                    process.release()?;
                    0
                }
                Err(status) => status,
            }
        }
        _ => STATUS_INVALID_INFO_CLASS,
    })
}
