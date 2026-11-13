//! Consultas por FILE_OBJECT.
//!
//! Drivers nativos recebem o buffer de kernel original num IRP real; a
//! conclusão é dona do resultado, inclusive no I/O pendente. Para arquivos
//! sem dispositivo o tamanho vem dos serviços de arquivo do kernel (`zw`),
//! que instalam a consulta por objeto (`set_object_query`).

use alloc::collections::BTreeSet;

use crate::ntos::io::io_manager;
use crate::ntos::io::small::thread_io;
use crate::hal::amd64::native_call;
use crate::ntos::ke::{critical_region, dispatcher};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::field::Field;
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, FileStandardInformation, IoStackLocation, IoStatusBlock, IopFileObjectExtension, Irp, LargeInteger, NtStruct, Vpb};
use crate::ntos::io::irp_builder::{self, BuildOptions};

const RESOURCE: u32 = 0xC000_009A;
/// FILE_OBJECT.Flags.
const FO_SYNCHRONOUS_IO: u32 = 0x02;
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
/// Slot do IopGetFileObjectExtension com a dica de dispositivo do topo
/// (TopDeviceObjectHint em +0 do bloco; layout privado do kernel).
const DEVICE_HINT_EXTENSION_SLOT: usize = 1;
/// FileStandardInformation e o IO_STATUS_BLOCK de rascunho logo depois.
const SCRATCH_IO_STATUS: u64 = 24;

/// FILE_OBJECT vivo do chamador.
fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: os chamadores passam FILE_OBJECTs vivos (referenciados).
    unsafe { FileObject::at(file) }
}

/// DEVICE_OBJECT vivo.
fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivos alcançados por um FILE_OBJECT ou VPB vivos.
    unsafe { DeviceObject::at(device) }
}

/// ZwQueryInformationFile por objeto: (file, classe, tamanho, buffer, retornado).
pub type ObjectQuery = fn(u64, u32, u32, u64, u64) -> Result<u32, KernelError>;

static OBJECT_QUERY: SpinLock<Option<ObjectQuery>> = SpinLock::new(None);

pub fn set_object_query(query: ObjectQuery) {
    *OBJECT_QUERY.lock() = Some(query);
}

/// IoGetRelatedDeviceObject: o dispositivo do VPB (ou o do arquivo, ou o do
/// volume montado) e o topo da pilha, que uma extensão real de arquivo pode
/// mandar parar num filtro abaixo do topo.
pub fn related_device(file: u64) -> Result<u64, KernelError> {
    let object = file_at(file);
    let vpb = object.vpb.get();
    // SAFETY: FileObject->Vpb de um arquivo vivo.
    let mut device = if vpb != 0 { unsafe { Vpb::at(vpb) }.device_object.get() } else { 0 };
    if device == 0 {
        device = object.device_object.get();
        if device != 0 && object.flags.get() & FO_DIRECT_DEVICE_OPEN == 0 {
            let volume = device_at(device).vpb.get();
            if volume != 0 {
                // SAFETY: DeviceObject->Vpb de um dispositivo vivo.
                let mounted = unsafe { Vpb::at(volume) }.device_object.get();
                if mounted != 0 {
                    device = mounted;
                }
            }
        }
    }
    if device == 0 {
        return Ok(0);
    }
    let extension = object.file_object_extension.get();
    // SAFETY: FileObjectExtension aponta para a _IOP_FILE_OBJECT_EXTENSION.
    let filter = if extension != 0 { unsafe { IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[DEVICE_HINT_EXTENSION_SLOT].get() } else { 0 };
    let hint = if filter != 0 { guest::read64(filter) } else { 0 };
    let mut seen = BTreeSet::new();
    let mut top = device;
    while top != 0 {
        if !seen.insert(top) {
            return Err(KernelError::new("cyclic device attachment"));
        }
        if hint != 0 && top == hint {
            return Ok(top);
        }
        let next = device_at(top).attached_device.get();
        if next == 0 {
            return Ok(top);
        }
        top = next;
    }
    Ok(device)
}

/// Trava síncrona do FILE_OBJECT (Busy, Waiters e o KEVENT Lock) dentro de
/// uma região crítica.
pub fn acquire_file(file: u64) -> Result<(), KernelError> {
    use core::sync::atomic::Ordering::SeqCst;
    critical_region::enter_critical()?;
    let object = file_at(file);
    if object.busy.atomic().compare_exchange(0, 1, SeqCst, SeqCst).is_ok() {
        return Ok(());
    }
    // Waiters muda por InterlockedIncrement/InterlockedDecrement.
    object.waiters.atomic().fetch_add(1, SeqCst);
    while object.busy.atomic().compare_exchange(0, 1, SeqCst, SeqCst).is_err() {
        dispatcher::wait_for_single_object(object.lock.address(), 0, 0, false);
    }
    object.waiters.atomic().fetch_sub(1, SeqCst);
    Ok(())
}

pub fn release_file(file: u64) -> Result<(), KernelError> {
    let object = file_at(file);
    object.busy.atomic().store(0, core::sync::atomic::Ordering::SeqCst);
    if object.waiters.get() != 0 {
        dispatcher::set_event(object.lock.address());
    }
    critical_region::leave_critical()
}

/// IRP_MJ_QUERY_INFORMATION (ou QUERY_VOLUME_INFORMATION) ao dispositivo
/// relacionado. FsRtlGetFileSize dá precedência a um retorno de despacho com
/// falha; IoQueryFileInformation usa o status imediato ou, depois de
/// STATUS_PENDING, o da conclusão.
#[allow(clippy::too_many_arguments)]
pub fn query_native(file: u64, class: u32, length: u32, buffer: u64, return_length: u64, size_query: bool, volume_query: bool, requestor_mode: u8) -> Result<u32, KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    let scratch = guest::alloc_bytes(48);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let mut packet = 0;
    let mut locked = false;
    let mut referenced = false;
    let mut old_hard_error = None;
    let result = (|| -> Result<u32, KernelError> {
        let object = file_at(file);
        if !size_query {
            referenced = file_objects::reference(file)?.is_some();
            if object.flags.get() & FO_SYNCHRONOUS_IO != 0 {
                acquire_file(file)?;
                locked = true;
                dispatcher::clear_event(object.event.address());
            }
        }
        let event = if locked { object.event.address() } else { scratch };
        let io_status = scratch + SCRATCH_IO_STATUS;
        if !locked {
            dispatcher::initialize_event(event, if size_query { 0 } else { 1 }, false);
        }
        let count = match device_at(device).stack_size.get() as u8 {
            0 => 1,
            count => count as u32,
        };
        packet = guest::alloc_bytes(irp_builder::size_for(count));
        if packet == 0 {
            return Ok(RESOURCE);
        }
        irp_builder::build(packet, &BuildOptions { major: if volume_query { 10 } else { 5 }, minor: 0, buffer, buffer_length: length, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode, ..Default::default() });
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
        let extended = !size_query && requestor_mode == 0 && class == 75;
        // Parameters.QueryFile.FileInformationClass / QueryVolume.FsInformationClass.
        stack.parameters.query_file.file_information_class.set(crate::ntos::inc::types::FileInformationClass(if extended { 71 } else { class } as i32));
        if extended {
            stack.flags.set(1);
        }
        irp.flags.set(if size_query { 0x42 } else if locked { 0x10 } else { 0x14 });
        if locked {
            irp.allocation_flags.set(irp.allocation_flags.get() | 2);
        }
        if size_query {
            old_hard_error = Some(thread_io::set_hard_error_mode(0)?);
        }
        let status = io_manager::iof_call_driver(device, packet);
        if status == 0x103 {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
        // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
        let iosb = unsafe { IoStatusBlock::at(io_status) };
        let completed = iosb.status.get();
        let result = if size_query {
            if status < 0 {
                status
            } else {
                completed
            }
        } else if status == 0x103 {
            completed
        } else {
            status
        };
        if locked {
            object.final_status.set(completed);
        }
        if return_length != 0 {
            // SAFETY: PULONG ReturnLength do chamador de modo kernel.
            unsafe { Field::<u32>::at(return_length) }.set(iosb.information.get() as u32);
        }
        Ok(result as u32)
    })();
    if let Some(mode) = old_hard_error {
        let _ = thread_io::set_hard_error_mode(mode as u8);
    }
    if packet != 0 {
        guest::free_bytes(packet);
    }
    if locked {
        release_file(file)?;
    }
    if referenced {
        file_objects::dereference(file)?;
    }
    guest::free_bytes(scratch);
    result
}

/// FsRtlGetFileSize: Fast I/O (FastIoQueryStandardInfo) quando o driver tem,
/// senão IRP; diretório devolve STATUS_FILE_IS_A_DIRECTORY.
pub fn get_size(file: u64, output: u64) -> Result<u32, KernelError> {
    let scratch = guest::alloc_bytes(80);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let result = (|| -> Result<u32, KernelError> {
        let device = related_device(file)?;
        let size = FileStandardInformation::SIZE as u32;
        let status = if device != 0 {
            let driver = device_at(device).driver_object.get();
            // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
            let fast = if driver != 0 { unsafe { DriverObject::at(driver) }.fast_io_dispatch.get() } else { 0 };
            // SAFETY: DriverObject->FastIoDispatch do driver vivo.
            let routine = if fast != 0 { unsafe { FastIoDispatch::at(fast) }.fast_io_query_standard_info.get() } else { 0 };
            let handled = routine != 0 && native_call::call(routine, &[file, 1, scratch, scratch + SCRATCH_IO_STATUS, device]) & 0xFF != 0;
            if handled {
                // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
                unsafe { IoStatusBlock::at(scratch + SCRATCH_IO_STATUS) }.status.get() as u32
            } else {
                query_native(file, 5, size, scratch, 0, true, false, 0)?
            }
        } else {
            let query = (*OBJECT_QUERY.lock()).ok_or_else(|| KernelError::new("kernel file services unavailable"))?;
            query(file, 5, size, scratch, scratch + SCRATCH_IO_STATUS)?
        };
        if status & 0x8000_0000 != 0 {
            return Ok(status);
        }
        // SAFETY: FILE_STANDARD_INFORMATION de rascunho no início de `scratch`.
        let standard = unsafe { FileStandardInformation::at(scratch) };
        if standard.directory.get() != 0 {
            return Ok(0xC000_00BA);
        }
        // SAFETY: PLARGE_INTEGER FileSize do chamador de modo kernel.
        unsafe { LargeInteger::at(output) }.quad_part.set(standard.end_of_file.quad_part.get());
        Ok(status)
    })();
    guest::free_bytes(scratch);
    result
}
