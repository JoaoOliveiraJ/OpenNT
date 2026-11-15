//! As notificações de eventos de dispositivo para o modo usuário
//! (`\Device\DeviceApi\CMNotify`), por onde o CM_Register_Notification do
//! cfgmgr32 recebe chegada e remoção de interfaces e de dispositivos.
//!
//! PiUEventDispatch (ntoskrnl 19041, rva 0x715380): IRP_MJ_CREATE zera o
//! FsContext2 do FILE_OBJECT (o contexto de registro do cliente); CLOSE
//! libera o contexto que estiver nele; CLEANUP conclui com sucesso;
//! DEVICE_CONTROL vai ao PiUEventHandleIoctl; os demais concluem com
//! STATUS_NOT_SUPPORTED. Um IRP que chega com falha no IoStatus volta com
//! ela, sem conclusão.

use crate::ntos::inc::types::{FileObject, IoStackLocation, Irp};
use crate::rtl::KernelError;

use super::device_api;

const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

const IRP_MJ_CREATE: u8 = 0x00;
const IRP_MJ_CLOSE: u8 = 0x02;
const IRP_MJ_DEVICE_CONTROL: u8 = 0x0E;
const IRP_MJ_CLEANUP: u8 = 0x12;

/// PiUEventDispatch(DeviceObject, Irp).
pub fn dispatch(_device: u64, irp: &Irp, location: &IoStackLocation, file: &FileObject) -> Result<u32, KernelError> {
    let current = irp.io_status.status.get() as u32;
    if current & 0x8000_0000 != 0 {
        return Ok(current);
    }
    Ok(match location.major_function.get() {
        IRP_MJ_CREATE => {
            file.fs_context2.set(0);
            device_api::complete(irp, 0)
        }
        IRP_MJ_CLOSE => {
            file.fs_context2.set(0);
            device_api::complete(irp, 0)
        }
        IRP_MJ_CLEANUP => device_api::complete(irp, 0),
        IRP_MJ_DEVICE_CONTROL => {
            let code = location.parameters.device_io_control.io_control_code.get();
            debug_print!("[pnp] CMNotify: IOCTL {:#x} sem suporte no kernel", code);
            device_api::complete(irp, STATUS_NOT_IMPLEMENTED)
        }
        _ => device_api::complete(irp, STATUS_NOT_SUPPORTED),
    })
}
