//! IOCTL síncrono do FsRtl — FsRtlIssueDeviceIoControl (RVA 0x6954f0) e o
//! seu cliente FsRtlVolumeDeviceToCorrelationId (RVA 0x695060) do ntoskrnl
//! 10.0.19045.
//!
//! FsRtlIssueDeviceIoControl(DeviceObject, IoCtl, Flags, InputBuffer,
//! InputBufferLength, OutputBuffer, OutputBufferLength, IosbInformation):
//! KeInitializeEvent(Notification, FALSE) + IoBuildDeviceIoControlRequest
//! (não interno) — sem IRP, STATUS_INSUFFICIENT_RESOURCES —, Flags somado ao
//! IO_STACK_LOCATION.Flags do próximo slot, IofCallDriver e, se pendente,
//! KeWaitForSingleObject + Iosb.Status; com sucesso devolve
//! Iosb.Information em *IosbInformation (se dado).
//!
//! FsRtlVolumeDeviceToCorrelationId(VolumeDeviceObject, Guid):
//! IOCTL_MOUNTDEV_QUERY_STABLE_GUID (0x4D0018) com saída de 16 bytes;
//! sucesso copia o GUID. STUB (sinalizado): na falha o NT recorre ao
//! IoVolumeDeviceToGuid (banco do mount manager); o OpenNT não tem mount
//! manager, então devolve o status do IOCTL.

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DeviceObject, Guid, IoStackLocation, IoStatusBlock, Irp, Kevent};
use crate::ntos::io::io_manager;
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;

pub const STATUS_PENDING: u32 = 0x0000_0103;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const IOCTL_MOUNTDEV_QUERY_STABLE_GUID: u32 = 0x004D_0018;

const NOTIFICATION_EVENT: u8 = 0;

/// FsRtlIssueDeviceIoControl. `information_out` recebe Iosb.Information no
/// sucesso (o `PULONG_PTR IosbInformation` opcional).
#[allow(clippy::too_many_arguments)]
pub fn issue_device_io_control(device: &DeviceObject, io_control_code: u32, flags: u8, input: u64, input_length: u32, output: u64, output_length: u32, information_out: Option<&Field<u64>>) -> u32 {
    // KEVENT + IO_STATUS_BLOCK (variáveis locais no NT).
    let block = guest::alloc_bytes(Kevent::SIZE + IoStatusBlock::SIZE);
    // SAFETY: bloco recém-alocado: o KEVENT seguido do IO_STATUS_BLOCK.
    let (event, iosb) = unsafe { (Kevent::at(block), IoStatusBlock::at(block + Kevent::SIZE)) };
    dispatcher::initialize_event(event.address(), NOTIFICATION_EVENT, false);
    let irp = io_manager::build_device_io_control_request(io_control_code, device.address(), input, input_length, output, output_length, 0, event.address(), iosb.address(), None);
    let status = if irp == 0 {
        STATUS_INSUFFICIENT_RESOURCES
    } else {
        // SAFETY: IRP recém-montado; o próximo slot fica logo abaixo do corrente.
        let next_stack = unsafe { IoStackLocation::at(Irp::at(irp).tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
        next_stack.flags.set(next_stack.flags.get() | flags);
        let mut status = io_manager::iof_call_driver(device.address(), irp) as u32;
        if status == STATUS_PENDING {
            dispatcher::wait_for_single_object(event.address(), 0, 0, false);
            status = iosb.status.get() as u32;
        }
        if let (true, Some(out)) = ((status as i32) >= 0, information_out) {
            out.set(iosb.information.get());
        }
        status
    };
    guest::free_bytes(block);
    status
}

/// FsRtlVolumeDeviceToCorrelationId(VolumeDeviceObject, Guid) -> NTSTATUS.
pub fn volume_device_to_correlation_id(device: &DeviceObject, guid: &Guid) -> u32 {
    let output = guest::alloc_bytes(Guid::SIZE);
    let status = issue_device_io_control(device, IOCTL_MOUNTDEV_QUERY_STABLE_GUID, 0, 0, 0, output, Guid::SIZE as u32, None);
    if (status as i32) >= 0 {
        guest::write_bytes(guid.address(), &guest::read_bytes(output, Guid::SIZE as usize));
    }
    guest::free_bytes(output);
    status
}
