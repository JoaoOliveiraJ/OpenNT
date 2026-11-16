//! O cliente do cache de compatibilidade de aplicativos no kernel:
//! NtApphelpCacheControl (ntoskrnl 19041, rva 0x6660f0), que a ntdll e o
//! sxssrv pedem para consultar e atualizar o cache que o ahcache.sys mantém.
//!
//! Como no NT:
//! - um serviço (APPHELPCACHESERVICECLASS) a partir de 12 é
//!   STATUS_INVALID_PARAMETER, assim como um valor negativo;
//! - o 9 (a consulta do identificador de hardware) é o AhcCacheQueryHwId,
//!   só de UserMode (em KernelMode, STATUS_NOT_IMPLEMENTED);
//! - os demais vão ao \Device\ahcache como o IOCTL 0x220003 | serviço << 2
//!   (FILE_DEVICE_UNKNOWN, METHOD_NEITHER), com o ServiceData de 0x178 bytes
//!   como entrada, o RequestorMode do chamador e o status do IofCallDriver
//!   como resposta. O g_AhcDeviceObject é aberto na primeira chamada pelo
//!   IoGetDeviceObjectPointer (GENERIC_READ | GENERIC_WRITE); sem o
//!   dispositivo (o ahcache.sys não carregado), o serviço
//!   responde o status pré-definido dele: STATUS_NOT_FOUND para a consulta
//!   (0) e a notificação (6), STATUS_SUCCESS para 1, 2, 3, 7 e 10, e
//!   STATUS_UNSUCCESSFUL para 4, 5, 8 e 11.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{IoStatusBlock, Irp, Kevent, UnicodeString};
use crate::ntos::io::{device, io_manager};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::{object_reference, reference_trace};
use crate::rtl::KernelError;

const STATUS_SUCCESS: u32 = 0;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_FOUND: u32 = 0xC000_0225;
/// ApphelpCacheServiceQueryHwId.
const SERVICE_QUERY_HW_ID: i32 = 9;
const SERVICE_LIMIT: i32 = 12;
/// O tamanho do APPHELP_CACHE_SERVICE_REQUEST que vai ao driver.
const SERVICE_DATA_LENGTH: u32 = 0x178;
const DEVICE_NAME: &str = "\\Device\\ahcache";

/// g_AhcDeviceObject: o dispositivo do ahcache.sys, aberto uma vez.
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// O status de um serviço quando o \Device\ahcache não existe; `None` para
/// um serviço inválido.
fn preset_status(service: i32) -> Option<u32> {
    match service {
        0 | 6 => Some(STATUS_NOT_FOUND),
        1 | 2 | 3 | 7 | 10 => Some(STATUS_SUCCESS),
        4 | 5 | 8 | 11 => Some(STATUS_UNSUCCESSFUL),
        _ => None,
    }
}

/// IoGetDeviceObjectPointer(\Device\ahcache) e a troca atômica do
/// g_AhcDeviceObject; o perdedor da corrida solta o FILE_OBJECT dele.
fn open_device() -> Result<u64, KernelError> {
    let scratch = guest::alloc_bytes(0x80);
    if scratch == 0 {
        return Ok(0);
    }
    let units: alloc::vec::Vec<u16> = DEVICE_NAME.encode_utf16().collect();
    guest::write_bytes(scratch + 0x40, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<alloc::vec::Vec<u8>>());
    // SAFETY: células de rascunho dentro de `scratch`.
    let (name, file_output, device_output) = unsafe { (UnicodeString::at(scratch), Field::<u64>::at(scratch + 0x20), Field::<u64>::at(scratch + 0x28)) };
    name.length.set(units.len() as u16 * 2);
    name.maximum_length.set(units.len() as u16 * 2 + 2);
    name.buffer.set(scratch + 0x40);
    file_output.set(0);
    device_output.set(0);
    let status = device::get_device_object_pointer(name.address(), 0xC000_0000, file_output.address(), device_output.address());
    let (file, opened) = (file_output.get(), device_output.get());
    guest::free_bytes(scratch);
    if status? & 0x8000_0000 != 0 || opened == 0 {
        return Ok(0);
    }
    match DEVICE.compare_exchange(0, opened, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => Ok(opened),
        Err(existing) => {
            object_reference::dereference_with_tag(file, reference_trace::DEFAULT_TAG, false)?;
            Ok(existing)
        }
    }
}

/// O IOCTL do serviço ao ahcache.sys, sem esperar uma conclusão pendente.
fn call_device(device_object: u64, service: i32, data: u64, previous_mode: u8) -> u32 {
    let block = guest::alloc_bytes(Kevent::SIZE + IoStatusBlock::SIZE);
    if block == 0 {
        return STATUS_UNSUCCESSFUL;
    }
    // SAFETY: bloco recém-alocado: o KEVENT seguido do IO_STATUS_BLOCK.
    let (event, iosb) = unsafe { (Kevent::at(block), IoStatusBlock::at(block + Kevent::SIZE)) };
    dispatcher::initialize_event(event.address(), 1, false);
    let code = ((service as u32) << 2) | 0x22_0003;
    let irp = io_manager::build_device_io_control_request(code, device_object, data, SERVICE_DATA_LENGTH, 0, 0, 0, event.address(), iosb.address(), None);
    let status = if irp == 0 {
        STATUS_UNSUCCESSFUL
    } else {
        // SAFETY: IRP recém-montado.
        unsafe { Irp::at(irp) }.requestor_mode.set(previous_mode as i8);
        io_manager::iof_call_driver(device_object, irp) as u32
    };
    // O NT deixa o evento e o IOSB na pilha: um driver que conclui depois do
    // retorno não é suportado por esse caminho; o bloco só sai sem pendência.
    if status != 0x103 {
        guest::free_bytes(block);
    }
    status
}

/// NtApphelpCacheControl(Service, ServiceData).
pub fn control(service: i32, data: u64, previous_mode: u8) -> Result<u32, KernelError> {
    if service >= SERVICE_LIMIT {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    if service == SERVICE_QUERY_HW_ID {
        if previous_mode != 1 {
            return Ok(STATUS_NOT_IMPLEMENTED);
        }
        // O AhcCacheQueryHwId de UserMode (o hash do hardware para o
        // sxssrv) ainda não existe no OpenNT.
        crate::debug_print!("[ahc] NtApphelpCacheControl(QueryHwId) ainda sem suporte");
        return Ok(STATUS_NOT_IMPLEMENTED);
    }
    let Some(preset) = preset_status(service) else { return Ok(STATUS_INVALID_PARAMETER) };
    let mut device_object = DEVICE.load(Ordering::Acquire);
    if device_object == 0 {
        device_object = open_device()?;
        if device_object == 0 {
            return Ok(preset);
        }
    }
    Ok(call_device(device_object, service, data, previous_mode))
}
