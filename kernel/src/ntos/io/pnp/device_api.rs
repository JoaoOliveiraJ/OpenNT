//! O driver da API de dispositivos do PnP manager (`\Driver\DeviceApi`).
//!
//! Como o ntoskrnl 19041: o IopInitializePlugPlayServices chama o PiDaInit
//! (rva 0xa53550), que cria o driver embutido `\Driver\DeviceApi` pelo
//! IoCreateDriver com o PiDaDriverEntry (rva 0xa72be0). Esse põe o
//! PiDaDispatch em IRP_MJ_CREATE, CLOSE, DEVICE_CONTROL e CLEANUP, aponta o
//! DriverObject->FastIoDispatch para uma FAST_IO_DISPATCH zerada de 0xE0
//! bytes com o PiDaFastIoDispatch no FastIoDeviceControl e cria o
//! `\Device\DeviceApi` (FILE_DEVICE_UNKNOWN, sem extensão,
//! FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL, não exclusivo), já sem
//! DO_DEVICE_INITIALIZING.
//!
//! O nome aberto abaixo do dispositivo escolhe o tratador (a
//! IrpHandlingTable, rva 0x6360): `\Dev\Query` e `\Dev\NoState` (consultas
//! de dispositivos, PiDqDispatch), `\CMApi` (o configuration manager do
//! cfgmgr32, `cm_api`), `\SwDevice` (dispositivos de software, PiSwDispatch)
//! e `\CMNotify` (notificações de eventos de dispositivo, `cm_notify`). No
//! IRP_MJ_CREATE o PiDaDispatch compara o FileName com os nomes da tabela e
//! guarda o índice no FsContext do FILE_OBJECT (nome desconhecido:
//! STATUS_INVALID_PARAMETER); os outros IRPs e o Fast I/O vão ao tratador
//! do índice (índice inválido: STATUS_INVALID_DEVICE_REQUEST; Fast I/O sem
//! tratador: FALSE, e o I/O Manager monta o IRP).

use core::sync::atomic::{AtomicU64, Ordering};

use crate::hal::amd64::routine_stubs::{self, Routine};
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, IoStackLocation, Irp, NtStruct};
use crate::ntos::init::exports::{signed_status, Call};
use crate::ntos::io::{builtin_driver, device, io_manager};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;
use crate::rtl::KernelError;

use super::{cm_api, cm_notify};

const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;

const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL: u32 = 0x2_0000;
const DO_DEVICE_INITIALIZING: u32 = 0x80;
/// O PiDaDriverEntry zera e declara 0xE0 bytes de FAST_IO_DISPATCH.
const FAST_IO_DISPATCH_SIZE: u64 = 0xE0;

const DRIVER_NAME: &str = "\\Driver\\DeviceApi";
const DEVICE_NAME: &str = "\\Device\\DeviceApi";

/// Rotinas que o driver entrega ao I/O Manager por ponteiro.
pub const ROUTINES: &[Routine] = &[
    Routine { name: "PiDaDriverEntry", handler: driver_entry_routine },
    Routine { name: "PiDaDispatch", handler: dispatch_routine },
    Routine { name: "PiDaFastIoDispatch", handler: fast_io_routine },
];

/// O DEVICE_OBJECT do `\Device\DeviceApi` (0 antes do PiDaInit).
static DEVICE: AtomicU64 = AtomicU64::new(0);

/// Os tratadores da IrpHandlingTable, na ordem dela.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handler {
    DeviceQuery,
    DeviceQueryNoState,
    CmApi,
    SoftwareDevice,
    CmNotify,
}

/// IrpHandlingTable: o nome relativo ao `\Device\DeviceApi` e o tratador.
const TABLE: [(&str, Handler); 5] = [("\\Dev\\Query", Handler::DeviceQuery), ("\\Dev\\NoState", Handler::DeviceQueryNoState), ("\\CMApi", Handler::CmApi), ("\\SwDevice", Handler::SoftwareDevice), ("\\CMNotify", Handler::CmNotify)];

/// O índice da tabela para o FileName aberto: a comparação do PiDaDispatch
/// é exata e sensível à caixa (WCHAR a WCHAR até o NUL do nome da tabela).
pub fn handler_index(name: &str) -> Option<usize> {
    TABLE.iter().position(|(entry, _)| *entry == name)
}

/// O tratador de um índice guardado no FsContext.
pub fn handler_at(index: u64) -> Option<Handler> {
    TABLE.get(usize::try_from(index).ok()?).map(|(_, handler)| *handler)
}

/// O `\Device\DeviceApi` (0 antes do PiDaInit).
pub fn device_object() -> u64 {
    DEVICE.load(Ordering::Acquire)
}

/// UNICODE_STRING de kernel com o texto (o buffer logo depois dela).
fn kernel_unicode_string(text: &str) -> u64 {
    let units = text.encode_utf16().count() as u64;
    let block = guest::alloc_bytes(16 + units * 2 + 2);
    if block != 0 {
        guest_strings::write_wide_string(block + 16, text);
        guest_strings::write_string_fields(block, (units * 2) as u16, (units * 2 + 2) as u16, block + 16);
    }
    block
}

/// PiDaInit: o `\Driver\DeviceApi` embutido, pelo IoCreateDriver.
pub fn initialize() -> Result<u32, KernelError> {
    let name = kernel_unicode_string(DRIVER_NAME);
    if name == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = builtin_driver::create(name, routine_stubs::address("PiDaDriverEntry")?);
    guest::free_bytes(name);
    status
}

/// PiDaDriverEntry(DriverObject, RegistryPath).
fn driver_entry(driver: u64) -> Result<u32, KernelError> {
    let dispatch = routine_stubs::address("PiDaDispatch")?;
    let fast = routine_stubs::address("PiDaFastIoDispatch")?;
    // SAFETY: DRIVER_OBJECT que o IoCreateDriver acabou de criar.
    let object = unsafe { DriverObject::at(driver) };
    for major in [IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_DEVICE_CONTROL, IRP_MJ_CLEANUP] {
        object.major_function[major as usize].set(dispatch);
    }
    let table = guest::alloc_bytes(FAST_IO_DISPATCH_SIZE);
    if table == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: bloco zerado de 0xE0 bytes, o tamanho da FAST_IO_DISPATCH.
    let fast_io = unsafe { FastIoDispatch::at(table) };
    fast_io.size_of_fast_io_dispatch.set(FAST_IO_DISPATCH_SIZE as u32);
    fast_io.fast_io_device_control.set(fast);
    object.fast_io_dispatch.set(table);
    let name = kernel_unicode_string(DEVICE_NAME);
    let output = guest::alloc_bytes(8);
    if name == 0 || output == 0 {
        guest::free_bytes(name);
        guest::free_bytes(output);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    let status = device::create_device(driver, 0, name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL, output)?;
    let created = guest::read64(output);
    guest::free_bytes(name);
    guest::free_bytes(output);
    if status & 0x8000_0000 != 0 {
        return Ok(status);
    }
    // SAFETY: o DEVICE_OBJECT que o IoCreateDevice acabou de devolver.
    let device = unsafe { DeviceObject::at(created) };
    device.flags.set(device.flags.get() & !DO_DEVICE_INITIALIZING);
    DEVICE.store(created, Ordering::Release);
    Ok(status)
}

fn driver_entry_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(driver_entry(call.arg(1))?))
}

/// Conclui o IRP com o status (IofCompleteRequest com IO_NO_INCREMENT).
pub fn complete(irp: &Irp, status: u32) -> u32 {
    irp.io_status.status.set(status as i32);
    io_manager::iof_complete_request(irp.address());
    status
}

/// PiDaDispatch(DeviceObject, Irp).
fn dispatch(device: u64, packet: u64) -> Result<u32, KernelError> {
    // SAFETY: o IRP que o I/O Manager entregou ao despacho, com o slot
    // corrente dele e o FILE_OBJECT do pedido.
    let irp = unsafe { Irp::at(packet) };
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    let file = unsafe { FileObject::at(location.file_object.get()) };
    let handler = if location.major_function.get() == IRP_MJ_CREATE {
        let name = guest_strings::read_unicode_string(file.file_name.address());
        let Some(index) = handler_index(&name) else { return Ok(complete(irp, STATUS_INVALID_PARAMETER)) };
        file.fs_context.set(index as u64);
        TABLE[index].1
    } else {
        match handler_at(file.fs_context.get()) {
            Some(handler) => handler,
            None => return Ok(complete(irp, STATUS_INVALID_DEVICE_REQUEST)),
        }
    };
    match handler {
        Handler::CmApi => Ok(cm_api::dispatch(irp, location)),
        Handler::CmNotify => cm_notify::dispatch(device, irp, location, file),
        Handler::DeviceQuery | Handler::DeviceQueryNoState | Handler::SoftwareDevice => {
            // As consultas de dispositivos (PiDqDispatch) e os dispositivos
            // de software (PiSwDispatch) ainda não têm suporte no kernel.
            debug_print!("[pnp] \\Device\\DeviceApi: tratador {:?} sem suporte (IRP_MJ {:#x})", handler, location.major_function.get());
            if location.major_function.get() == IRP_MJ_CLOSE || location.major_function.get() == IRP_MJ_CLEANUP {
                return Ok(complete(irp, 0));
            }
            Ok(complete(irp, STATUS_NOT_SUPPORTED))
        }
    }
}

fn dispatch_routine(call: &Call) -> Result<u64, KernelError> {
    Ok(signed_status(dispatch(call.arg(1), call.arg(2))?))
}

/// Os argumentos do FastIoDeviceControl.
pub struct FastIoRequest {
    pub file: u64,
    pub input: u64,
    pub input_length: u32,
    pub output: u64,
    pub output_length: u32,
    pub code: u32,
    pub io_status: u64,
}

/// PiDaFastIoDispatch(FileObject, Wait, InputBuffer, InputBufferLength,
/// OutputBuffer, OutputBufferLength, IoControlCode, IoStatus, DeviceObject).
fn fast_io(request: &FastIoRequest) -> Result<bool, KernelError> {
    // SAFETY: o FILE_OBJECT referenciado pelo I/O Manager durante a chamada.
    let file = unsafe { FileObject::at(request.file) };
    match handler_at(file.fs_context.get()) {
        Some(Handler::CmApi) => cm_api::fast_io_device_control(request),
        _ => Ok(false),
    }
}

fn fast_io_routine(call: &Call) -> Result<u64, KernelError> {
    let request = FastIoRequest { file: call.arg(1), input: call.arg(3), input_length: call.arg(4) as u32, output: call.arg(5), output_length: call.arg(6) as u32, code: call.arg(7) as u32, io_status: call.arg(8) };
    Ok(fast_io(&request)? as u64)
}
