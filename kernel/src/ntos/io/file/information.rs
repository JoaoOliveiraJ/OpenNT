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
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, FileStandardInformation, IoStackLocation, IoStatusBlock, IopFileObjectExtension, Irp, Kevent, LargeInteger, NtStruct, Vpb};
use crate::ntos::io::irp_builder::{self, BuildOptions};

const RESOURCE: u32 = 0xC000_009A;
/// FILE_OBJECT.Flags.
const FO_SYNCHRONOUS_IO: u32 = 0x02;
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
const FO_VOLUME_OPEN: u32 = 0x40_0000;
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

/// O dispositivo a que o I/O Manager manda os IRPs do arquivo: o do
/// IoGetRelatedDeviceObject, salvo nos arquivos dos volumes do próprio
/// kernel, cujo file system embutido não tem pilha de IRP para eles
/// (`drivers/fs/volume_device.rs`): o I/O Manager responde no lugar as
/// operações desses arquivos, e aqui o resultado é 0. A abertura do volume
/// inteiro (FO_VOLUME_OPEN) é atendida por IRP no dispositivo de volume.
pub fn related_device(file: u64) -> Result<u64, KernelError> {
    let device = related_device_object(file)?;
    let volume_open = file_at(file).flags.get() & FO_VOLUME_OPEN != 0;
    Ok(if !volume_open && crate::drivers::fs::volume_device::is_volume_device(device) { 0 } else { device })
}

/// O dispositivo de um IRP `major` do arquivo: o de [`related_device`],
/// salvo os IRPs que o file system embutido atende por despacho
/// (`volume_device::serves`: o IRP_MJ_LOCK_CONTROL e o
/// IRP_MJ_DIRECTORY_CONTROL de notificação), que vão ao dispositivo de
/// volume dele.
pub fn request_device(file: u64, major: u8) -> Result<u64, KernelError> {
    let device = related_device_object(file)?;
    let volume_open = file_at(file).flags.get() & FO_VOLUME_OPEN != 0;
    Ok(if !volume_open && crate::drivers::fs::volume_device::is_volume_device(device) && !crate::drivers::fs::volume_device::serves(major) { 0 } else { device })
}

/// IoGetRelatedDeviceObject: o dispositivo do VPB (ou o do arquivo, ou o do
/// volume montado) e o topo da pilha, que uma extensão real de arquivo pode
/// mandar parar num filtro abaixo do topo.
pub fn related_device_object(file: u64) -> Result<u64, KernelError> {
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

/// FsRtlSetFileSize (RVA 0x669a10, do MiCreateDataFileMap e do
/// MmExtendSection): IRP_MJ_SET_INFORMATION FileEndOfFileInformation com
/// Flags IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO (0x42), o tamanho no
/// SystemBuffer e o modo de erro grave da thread desligado durante o
/// pedido. Devolve o NTSTATUS (o do envio, se for falha).
pub fn set_size(file: u64, size: u64) -> Result<u32, KernelError> {
    set_end_of_file(file, size, true)
}

/// IRP_MJ_SET_INFORMATION FileEndOfFileInformation ao file system do
/// arquivo: o de paginação do FsRtlSetFileSize (`paging`) ou o comum do
/// ZwSetInformationFile de modo kernel (sem as flags de paginação).
pub fn set_end_of_file(file: u64, size: u64, paging: bool) -> Result<u32, KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    // O LARGE_INTEGER do tamanho, o IO_STATUS_BLOCK e o KEVENT.
    let scratch = guest::alloc_bytes(8 + IoStatusBlock::SIZE + Kevent::SIZE);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        guest::free_bytes(scratch);
        return Ok(RESOURCE);
    }
    let (buffer, io_status, event) = (scratch, scratch + 8, scratch + 8 + IoStatusBlock::SIZE);
    guest::write64(buffer, size);
    dispatcher::initialize_event(event, 0, false);
    irp_builder::build(packet, &BuildOptions { major: SET_IRP_MJ_SET_INFORMATION, buffer, buffer_length: 8, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
    // SAFETY: IRP recém-construído e o slot do topo dele.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    stack.parameters.set_file.file_information_class.set(crate::ntos::inc::types::FileInformationClass(20));
    irp.flags.set(if paging { 0x42 } else { 0 });
    let old_hard_error = thread_io::set_hard_error_mode(0);
    let status = io_manager::iof_call_driver(device, packet);
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
    }
    // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
    let completed = unsafe { IoStatusBlock::at(io_status) }.status.get();
    if let Ok(mode) = old_hard_error {
        let _ = thread_io::set_hard_error_mode(mode as u8);
    }
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    Ok((if status < 0 { status } else { completed }) as u32)
}

/// IRP_MJ_FLUSH_BUFFERS ao file system do arquivo, o do NtFlushBuffersFile
/// de modo kernel (ZwFlushBuffersFile): síncrono, com o evento local e sem
/// o minor de dados. Devolve o NTSTATUS da conclusão.
pub fn flush_buffers(file: u64) -> Result<u32, KernelError> {
    let device = request_device(file, IRP_MJ_FLUSH_BUFFERS)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    let scratch = guest::alloc_bytes(IoStatusBlock::SIZE + Kevent::SIZE);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        guest::free_bytes(scratch);
        return Ok(RESOURCE);
    }
    let (io_status, event) = (scratch, scratch + IoStatusBlock::SIZE);
    dispatcher::initialize_event(event, 0, false);
    irp_builder::build(packet, &BuildOptions { major: IRP_MJ_FLUSH_BUFFERS, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
    let status = io_manager::iof_call_driver(device, packet);
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
    }
    // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
    let completed = unsafe { IoStatusBlock::at(io_status) }.status.get();
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    Ok((if status < 0 { status } else { completed }) as u32)
}

const IRP_MJ_FLUSH_BUFFERS: u8 = 9;
const IRP_MJ_DIRECTORY_CONTROL: u8 = 0x0C;
const IRP_MN_QUERY_DIRECTORY: u8 = 0x01;

/// O IRP_MN_QUERY_DIRECTORY do ZwQueryDirectoryFile de modo kernel num
/// arquivo de file system (o CatRoot que a ci.dll varre depois da troca do
/// `\SystemRoot`): RequestorMode KernelMode, o buffer de quem chama como
/// UserBuffer, o FileName (PUNICODE_STRING) e a classe no
/// Parameters.QueryDirectory e o SL_RESTART_SCAN/SL_RETURN_SINGLE_ENTRY em
/// `flags`. Síncrono: a trava e o FileObject->Event num arquivo síncrono,
/// senão um evento local. Devolve o status e grava o IO_STATUS_BLOCK de
/// quem chama.
pub fn query_directory(file: u64, io_status: u64, buffer: u64, length: u32, class: u32, flags: u8, file_name: u64) -> Result<u32, KernelError> {
    let device = request_device(file, IRP_MJ_DIRECTORY_CONTROL)?;
    if device == 0 {
        return Ok(0xC000_0010);
    }
    let scratch = guest::alloc_bytes(IoStatusBlock::SIZE + Kevent::SIZE);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        guest::free_bytes(scratch);
        return Ok(RESOURCE);
    }
    let object = file_at(file);
    let referenced = file_objects::reference(file)?.is_some();
    let locked = object.flags.get() & FO_SYNCHRONOUS_IO != 0;
    if locked {
        acquire_file(file)?;
        dispatcher::clear_event(object.event.address());
    }
    let (local_status, local_event) = (scratch, scratch + IoStatusBlock::SIZE);
    let event = if locked { object.event.address() } else { local_event };
    if !locked {
        dispatcher::initialize_event(local_event, 0, false);
    }
    irp_builder::build(packet, &BuildOptions { major: IRP_MJ_DIRECTORY_CONTROL, minor: IRP_MN_QUERY_DIRECTORY, device_object: device, stack_count: count, file_object: file, user_event: if locked { 0 } else { event }, user_iosb: local_status, user_buffer: buffer, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
    // SAFETY: IRP recém-construído e o slot do topo dele.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    irp.flags.set(if locked { 0 } else { SET_IRP_SYNCHRONOUS_API });
    let parameters = &stack.parameters.query_directory;
    parameters.length.set(length);
    parameters.file_name.set(file_name);
    parameters.file_information_class.set(crate::ntos::inc::types::FileInformationClass(class as i32));
    parameters.file_index.set(0);
    stack.flags.set(flags);
    let mut status = io_manager::iof_call_driver(device, packet);
    // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
    let completed = unsafe { IoStatusBlock::at(local_status) };
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = completed.status.get();
    }
    if locked {
        object.final_status.set(completed.status.get());
        release_file(file)?;
    }
    if io_status != 0 {
        // SAFETY: IO_STATUS_BLOCK de quem chama (modo kernel).
        let caller = unsafe { IoStatusBlock::at(io_status) };
        caller.status.set(completed.status.get());
        caller.information.set(completed.information.get());
    }
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    if referenced {
        file_objects::dereference(file)?;
    }
    Ok(status as u32)
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

// ---- IoSetInformation e IoQueryFileDosDeviceName (io-file-system-support) ---
//
// IoSetInformation (RVA 0x77bef0): IRP_MJ_SET_INFORMATION do modo kernel ao
// dispositivo relacionado, com o mesmo par trava/evento do `query_native`
// (FO_SYNCHRONOUS_IO serializa no FILE_OBJECT e espera em FileObject->Event;
// senão evento local e IRP_SYNCHRONOUS_API). A conclusão do OpenNT não grava
// FinalStatus nem libera o IRP: como no `query_native`, o status vem do
// IO_STATUS_BLOCK depois de STATUS_PENDING e o IRP é liberado aqui. Usa os
// itens deste arquivo (`file_at`, `device_at`, `related_device`,
// `acquire_file`, `release_file`, `query_native`, `RESOURCE`,
// `FO_SYNCHRONOUS_IO`, `SCRATCH_IO_STATUS`); os tipos que o arquivo não
// importa vão por caminho qualificado e os nomes novos têm prefixo `SET_`/
// `DOS_`.

const SET_FO_ALERTABLE_IO: u32 = 0x04;
const SET_FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x08;
const SET_FO_WRITE_THROUGH: u32 = 0x10;
const SET_FO_SEQUENTIAL_ONLY: u32 = 0x20;
const SET_FILE_WRITE_THROUGH: u32 = 0x02;
const SET_FILE_SEQUENTIAL_ONLY: u32 = 0x04;
const SET_FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
const SET_IRP_MJ_SET_INFORMATION: u8 = 6;
const SET_IRP_BUFFERED_IO: u32 = 0x10;
const SET_IRP_SYNCHRONOUS_API: u32 = 0x04;
const SET_IRP_ALLOCATION_SYNCHRONOUS: u8 = 0x02;
/// IO_STACK_LOCATION.Flags bit 0 das variantes BypassAccessCheck/ForceAccessCheck.
const SET_STACK_ACCESS_CHECK_FLAG: u8 = 0x01;
const SET_STATUS_PENDING: i32 = 0x103;
const SET_STATUS_NOT_IMPLEMENTED: i32 = 0xC000_0002_u32 as i32;
const SET_STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
// FILE_INFORMATION_CLASS tratadas antes do IRP.
const SET_FILE_RENAME_INFORMATION: u32 = 10;
const SET_FILE_LINK_INFORMATION: u32 = 11;
const SET_FILE_MODE_INFORMATION: u32 = 16;
const SET_FILE_MOVE_CLUSTER_INFORMATION: u32 = 31;
const SET_FILE_RENAME_INFORMATION_EX: u32 = 65;
const SET_FILE_MEMORY_PARTITION_INFORMATION: u32 = 69;
const SET_FILE_CASE_SENSITIVE_INFORMATION: u32 = 71;
const SET_FILE_LINK_INFORMATION_EX: u32 = 72;

/// Variantes BypassAccessCheck/ForceAccessCheck viram a classe base com
/// o bit 0 do IO_STACK_LOCATION.Flags ligado.
fn set_base_class(class: u32) -> (u32, bool) {
    match class {
        56 => (SET_FILE_RENAME_INFORMATION, true),
        57 => (SET_FILE_LINK_INFORMATION, true),
        66 => (SET_FILE_RENAME_INFORMATION_EX, true),
        73 => (SET_FILE_LINK_INFORMATION_EX, true),
        75 => (SET_FILE_CASE_SENSITIVE_INFORMATION, true),
        other => (other, false),
    }
}

/// FileModeInformation é aplicada pelo I/O Manager no próprio FILE_OBJECT
/// (cópia literal da sequência em 0x8465bf, inclusive o teste do bit 1 do
/// modo antes de mexer em FO_ALERTABLE_IO).
fn set_mode_information(file: &FileObject, mode: u32) {
    let mut flags = file.flags.get();
    if flags & SET_FO_NO_INTERMEDIATE_BUFFERING == 0 {
        flags = if mode & SET_FILE_WRITE_THROUGH != 0 { flags | SET_FO_WRITE_THROUGH } else { flags & !SET_FO_WRITE_THROUGH };
    }
    flags = if mode & SET_FILE_SEQUENTIAL_ONLY != 0 { flags | SET_FO_SEQUENTIAL_ONLY } else { flags & !SET_FO_SEQUENTIAL_ONLY };
    if mode & SET_FILE_WRITE_THROUGH != 0 {
        flags = if mode & SET_FILE_SYNCHRONOUS_IO_ALERT != 0 { flags | SET_FO_ALERTABLE_IO } else { flags & !SET_FO_ALERTABLE_IO };
    }
    file.flags.set(flags);
}

/// As classes com o layout do FILE_RENAME_INFORMATION (ReplaceIfExists,
/// Flags ou ClusterCount; RootDirectory; FileNameLength; FileName), cujo
/// nome absoluto ou relativo a um RootDirectory abre o diretório de destino
/// (o bitmap 0x4080000000200003 a partir da classe 10 do
/// NtSetInformationFile e do IoSetInformation).
pub fn names_link_target(class: u32) -> bool {
    matches!(class, SET_FILE_RENAME_INFORMATION | SET_FILE_LINK_INFORMATION | SET_FILE_MOVE_CLUSTER_INFORMATION | SET_FILE_RENAME_INFORMATION_EX | SET_FILE_LINK_INFORMATION_EX)
}

/// O Parameters.SetFile de uma classe de [`names_link_target`]: o
/// ClusterCount da FileMoveClusterInformation, o bit 0 do Flags das classes
/// Ex, senão o ReplaceIfExists. Devolve se o destino precisa ser aberto (o
/// nome começa com `\` ou há RootDirectory).
pub fn prepare_link_target(class: u32, information: &crate::ntos::inc::types::FileRenameInformation, stack: &IoStackLocation) -> bool {
    let set_file = &stack.parameters.set_file;
    match class {
        SET_FILE_MOVE_CLUSTER_INFORMATION => set_file.cluster_count.set(information.flags.get()),
        SET_FILE_RENAME_INFORMATION_EX | SET_FILE_LINK_INFORMATION_EX => set_file.replace_if_exists.set((information.flags.get() & 1) as u8),
        _ => set_file.replace_if_exists.set(information.replace_if_exists.get()),
    }
    information.file_name[0].get() == b'\\' as u16 || information.root_directory.get() != 0
}

/// O que o I/O Manager faz com a classe antes de chamar o driver:
/// `Ok(None)` = enviar o IRP; `Ok(Some(handle))` = enviar com o diretório de
/// destino aberto no handle de kernel, fechado depois da conclusão;
/// `Err(status)` = completar aqui com esse status.
fn set_prepare(file: &FileObject, class: u32, buffer: u64, stack: &IoStackLocation) -> Result<Option<u64>, i32> {
    use crate::ntos::inc::types::{FileModeInformation, FileRenameInformation};
    match class {
        SET_FILE_MODE_INFORMATION => {
            // SAFETY: FILE_MODE_INFORMATION do chamador de modo kernel.
            set_mode_information(file, unsafe { FileModeInformation::at(buffer) }.mode.get());
            Err(0)
        }
        _ if names_link_target(class) => {
            // SAFETY: estrutura do chamador de modo kernel.
            let information = unsafe { FileRenameInformation::at(buffer) };
            if !prepare_link_target(class, information, stack) {
                return Ok(None);
            }
            let previous_mode = crate::ntos::ps::previous_mode::get().unwrap_or(0);
            let force = stack.flags.get() & SET_STACK_ACCESS_CHECK_FLAG == 0;
            let (handle, target) = open_link_or_rename_target(file.address(), buffer, force, previous_mode).map_err(|status| status as i32)?;
            stack.parameters.set_file.file_object.set(target);
            Ok(Some(handle))
        }
        // IopSetFileMemoryPartitionInformation: sem partições de memória por arquivo no OpenNT.
        SET_FILE_MEMORY_PARTITION_INFORMATION => Err(SET_STATUS_NOT_IMPLEMENTED),
        _ => Ok(None),
    }
}

// ---- IopOpenLinkOrRenameTarget (RVA 0x608e08) --------------------------------

const LINK_FILE_ADD_FILE: u32 = 0x2;
const LINK_FILE_ADD_SUBDIRECTORY: u32 = 0x4;
const LINK_SYNCHRONIZE: u32 = 0x10_0000;
const LINK_FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const LINK_FO_OPENED_CASE_SENSITIVE: u32 = 0x2_0000;
const LINK_OBJ_CASE_INSENSITIVE: u32 = 0x40;
const LINK_OBJ_KERNEL_HANDLE: u32 = 0x200;
const LINK_OBJ_FORCE_ACCESS_CHECK: u32 = 0x400;
/// IO_FORCE_ACCESS_CHECK, IO_OPEN_TARGET_DIRECTORY e IO_NO_PARAMETER_CHECKING.
const LINK_IO_FORCE_ACCESS_CHECK: u32 = 0x1;
const LINK_IO_OPEN_TARGET_DIRECTORY: u32 = 0x4;
const LINK_IO_NO_PARAMETER_CHECKING: u32 = 0x100;
const LINK_FILE_SHARE_READ_WRITE: u32 = 3;
const LINK_FILE_OPEN: u32 = 1;
const LINK_FILE_OPEN_FOR_BACKUP_INTENT: u32 = 0x4000;
const LINK_FILE_BASIC_INFORMATION: u32 = 4;
const LINK_STATUS_NOT_SAME_DEVICE: u32 = 0xC000_00D4;
const LINK_STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xC000_0024;
/// IRP_OB_QUERY_NAME | IRP_BUFFERED_IO | IRP_SYNCHRONOUS_API, o Flags do
/// IRP do IopGetFileInformation (0x620ee3).
const FILE_INFORMATION_IRP_FLAGS: u32 = 0x1014;

/// O rascunho do IopOpenLinkOrRenameTarget: os OBJECT_ATTRIBUTES e o nome
/// do destino, o handle aberto, o handle de kernel do RootDirectory de um
/// chamador de modo usuário, o IO_STATUS_BLOCK e o FILE_BASIC_INFORMATION
/// do arquivo renomeado.
#[repr(C)]
struct LinkTargetRequest {
    attributes: crate::ntos::inc::types::ObjectAttributes,
    name: crate::ntos::inc::types::UnicodeString,
    handle: Field<u64>,
    root: Field<u64>,
    io_status: IoStatusBlock,
    basic: crate::ntos::inc::types::FileBasicInformation,
}

// SAFETY: #[repr(C)] só de células e estruturas do NT.
unsafe impl NtStruct for LinkTargetRequest {}

/// IopGetFileInformation (RVA 0x620e34): IRP_MJ_QUERY_INFORMATION ao
/// dispositivo relacionado com evento local e sem a trava do FILE_OBJECT
/// (quem chama pode estar com ela, num arquivo síncrono), RequestorMode
/// KernelMode e o IRP_OB_QUERY_NAME. Devolve o status e o Information.
fn get_file_information(file: u64, class: u32, length: u32, buffer: u64) -> Result<(u32, u64), KernelError> {
    let device = related_device_object(file)?;
    let scratch = guest::alloc_bytes(IoStatusBlock::SIZE + Kevent::SIZE);
    if scratch == 0 {
        return Ok((RESOURCE, 0));
    }
    let count = match device_at(device).stack_size.get() as u8 {
        0 => 1,
        count => count as u32,
    };
    let packet = guest::alloc_bytes(irp_builder::size_for(count));
    if packet == 0 {
        guest::free_bytes(scratch);
        return Ok((RESOURCE, 0));
    }
    let referenced = file_objects::reference(file)?.is_some();
    let (io_status, event) = (scratch, scratch + IoStatusBlock::SIZE);
    dispatcher::initialize_event(event, 1, false);
    irp_builder::build(packet, &BuildOptions { major: 5, buffer, buffer_length: length, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
    // SAFETY: IRP recém-construído e o slot do topo dele.
    let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
    stack.parameters.query_file.file_information_class.set(crate::ntos::inc::types::FileInformationClass(class as i32));
    irp.flags.set(FILE_INFORMATION_IRP_FLAGS);
    let mut status = io_manager::iof_call_driver(device, packet);
    // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
    let iosb = unsafe { IoStatusBlock::at(io_status) };
    if status == 0x103 {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = iosb.status.get();
    }
    let information = iosb.information.get();
    guest::free_bytes(packet);
    guest::free_bytes(scratch);
    if referenced {
        file_objects::dereference(file)?;
    }
    Ok((status as u32, information))
}

/// IopGetBasicInformationFile (RVA 0x608d48): o FastIoQueryBasicInfo do
/// driver do dispositivo relacionado (Wait = FO_SYNCHRONOUS_IO) e, se ele
/// não atende, o IopGetFileInformation(FileBasicInformation).
fn get_basic_information(file: u64, output: &crate::ntos::inc::types::FileBasicInformation, io_status: &IoStatusBlock) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::FileBasicInformation;
    let device = related_device_object(file)?;
    let driver = device_at(device).driver_object.get();
    // SAFETY: DeviceObject->DriverObject de um dispositivo vivo.
    let fast = if driver != 0 { unsafe { DriverObject::at(driver) }.fast_io_dispatch.get() } else { 0 };
    // SAFETY: DriverObject->FastIoDispatch do driver vivo.
    let routine = if fast != 0 { unsafe { FastIoDispatch::at(fast) }.fast_io_query_basic_info.get() } else { 0 };
    let wait = (file_at(file).flags.get() & FO_SYNCHRONOUS_IO != 0) as u64;
    if routine != 0 && native_call::call(routine, &[file, wait, output.address(), io_status.address(), device]) & 0xFF != 0 {
        return Ok(io_status.status.get() as u32);
    }
    get_file_information(file, LINK_FILE_BASIC_INFORMATION, FileBasicInformation::SIZE as u32, output.address()).map(|(status, _)| status)
}

/// IopOpenLinkOrRenameTarget(TargetHandle, Irp, RenameBuffer, FileObject):
/// abre o diretório de destino de um rename/link (o nome do
/// FILE_RENAME_INFORMATION de `rename`, um buffer de sistema) num handle de
/// kernel, cujo FILE_OBJECT quem chama põe no Parameters.SetFile.FileObject
/// da posição do IRP que o file system recebe. O acesso é
/// FILE_ADD_FILE, ou FILE_ADD_SUBDIRECTORY quando o arquivo é diretório
/// (pelo IopGetBasicInformationFile, salvo numa abertura direta do
/// dispositivo); o RootDirectory de um chamador de modo usuário vira handle
/// de kernel (IoConvertFileHandleToKernelHandle), fechado no fim. A abertura
/// é o IoCreateFileEx com SYNCHRONIZE, FILE_SHARE_READ | FILE_SHARE_WRITE,
/// FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, IO_NO_PARAMETER_CHECKING |
/// IO_OPEN_TARGET_DIRECTORY e a dica de dispositivo do arquivo; com `force`
/// (sem o bit 0 no Flags da posição, o das classes que dispensam a
/// checagem), também OBJ_FORCE_ACCESS_CHECK e IO_FORCE_ACCESS_CHECK. Um
/// destino em outro dispositivo é STATUS_NOT_SAME_DEVICE. Devolve o handle,
/// que quem chama fecha depois de o IRP terminar, e o FILE_OBJECT dele.
pub fn open_link_or_rename_target(file: u64, rename: u64, force: bool, previous_mode: u8) -> Result<(u64, u64), u32> {
    let block = guest::alloc_bytes(LinkTargetRequest::SIZE);
    if block == 0 {
        return Err(RESOURCE);
    }
    guest::write_bytes(block, &alloc::vec![0u8; LinkTargetRequest::SIZE as usize]);
    // SAFETY: bloco zerado recém-alocado do tamanho da estrutura.
    let request = unsafe { LinkTargetRequest::at(block) };
    let result = open_link_target(file, rename, force, previous_mode, request);
    let root = request.root.get();
    if root != 0 {
        let _ = crate::ntos::ob::close::close(root, Some(0));
    }
    guest::free_bytes(block);
    result
}

fn open_link_target(file: u64, rename: u64, force: bool, previous_mode: u8, request: &LinkTargetRequest) -> Result<(u64, u64), u32> {
    use crate::ntos::inc::types::FileRenameInformation;
    let failed = |error: KernelError| if error.status != 0 { error.status } else { 0xC000_0001 };
    let object = file_at(file);
    let mut access = LINK_FILE_ADD_FILE;
    if object.flags.get() & FO_DIRECT_DEVICE_OPEN == 0 {
        let status = get_basic_information(file, &request.basic, &request.io_status).map_err(failed)?;
        if status & 0x8000_0000 != 0 {
            return Err(status);
        }
        if request.basic.file_attributes.get() & LINK_FILE_ATTRIBUTE_DIRECTORY != 0 {
            access = LINK_FILE_ADD_SUBDIRECTORY;
        }
    }
    // SAFETY: o FILE_RENAME_INFORMATION no buffer de sistema do IRP.
    let information = unsafe { FileRenameInformation::at(rename) };
    let mut root = information.root_directory.get();
    if root != 0 && previous_mode == 1 {
        let status = super::convert_handle::convert(root, 1, 0, false, request.root.address()).map_err(failed)?;
        if status & 0x8000_0000 != 0 {
            return Err(status);
        }
        root = request.root.get();
    }
    let length = information.file_name_length.get() as u16;
    request.name.length.set(length);
    request.name.maximum_length.set(length);
    request.name.buffer.set(information.file_name[0].address());
    let case = if object.flags.get() & LINK_FO_OPENED_CASE_SENSITIVE == 0 { LINK_OBJ_CASE_INSENSITIVE } else { 0 };
    let attributes = &request.attributes;
    attributes.length.set(crate::ntos::inc::types::ObjectAttributes::SIZE as u32);
    attributes.root_directory.set(root);
    attributes.object_name.set(request.name.address());
    attributes.attributes.set(LINK_OBJ_KERNEL_HANDLE | case | if force { LINK_OBJ_FORCE_ACCESS_CHECK } else { 0 });
    // O TopDeviceObjectHint da extensão do arquivo (IopGetFileObjectExtension(File, 1)).
    let extension = object.file_object_extension.get();
    // SAFETY: a extensão de um FILE_OBJECT vivo.
    let hint_block = if extension != 0 { unsafe { IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[DEVICE_HINT_EXTENSION_SLOT].get() } else { 0 };
    let context = crate::ntos::io::parse::DriverCreateContext {
        device_object_hint: if hint_block != 0 { guest::read64(hint_block) } else { 0 },
        options: LINK_IO_NO_PARAMETER_CHECKING | LINK_IO_OPEN_TARGET_DIRECTORY | if force { LINK_IO_FORCE_ACCESS_CHECK } else { 0 },
        ..Default::default()
    };
    let status = super::zw::create_kernel_file_with_context(request.handle.address(), access | LINK_SYNCHRONIZE, attributes.address(), request.io_status.address(), LINK_FILE_SHARE_READ_WRITE, LINK_FILE_OPEN, LINK_FILE_OPEN_FOR_BACKUP_INTENT, context).map_err(failed)?;
    if status & 0x8000_0000 != 0 {
        return Err(status);
    }
    let handle = request.handle.get();
    // ObReferenceObjectByHandle(handle, acesso, IoFileObjectType, KernelMode):
    // o handle segura o objeto até quem chama fechá-lo.
    let target = super::zw::file_object_of_handle(handle);
    if target == 0 {
        let _ = crate::ntos::ob::close::close(handle, Some(0));
        return Err(LINK_STATUS_OBJECT_TYPE_MISMATCH);
    }
    let same = matches!((related_device_object(file), related_device_object(target)), (Ok(source), Ok(destination)) if source == destination);
    if !same {
        let _ = crate::ntos::ob::close::close(handle, Some(0));
        return Err(LINK_STATUS_NOT_SAME_DEVICE);
    }
    Ok((handle, target))
}

/// IoSetInformation(FileObject, FileInformationClass, Length, FileInformation).
/// Os arquivos do file system embutido (sem dispositivo de despacho) mudam
/// de tamanho pelo volume (`zw::set_volume_file_information`).
pub fn set_native(file: u64, class: u32, length: u32, buffer: u64) -> Result<u32, KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return super::zw::set_volume_file_information(file, class, length, buffer).unwrap_or(Ok(SET_STATUS_INVALID_DEVICE_REQUEST));
    }
    let scratch = guest::alloc_bytes(48);
    if scratch == 0 {
        return Ok(RESOURCE);
    }
    let (base_class, flagged) = set_base_class(class);
    let mut packet = 0;
    let mut locked = false;
    let mut referenced = false;
    let result = (|| -> Result<u32, KernelError> {
        let object = file_at(file);
        referenced = file_objects::reference(file)?.is_some();
        if object.flags.get() & FO_SYNCHRONOUS_IO != 0 {
            acquire_file(file)?;
            locked = true;
            dispatcher::clear_event(object.event.address());
        }
        let event = if locked { object.event.address() } else { scratch };
        let io_status = scratch + SCRATCH_IO_STATUS;
        if !locked {
            dispatcher::initialize_event(event, 1, false);
        }
        let count = match device_at(device).stack_size.get() as u8 {
            0 => 1,
            count => count as u32,
        };
        packet = guest::alloc_bytes(irp_builder::size_for(count));
        if packet == 0 {
            return Ok(RESOURCE);
        }
        irp_builder::build(packet, &BuildOptions { major: SET_IRP_MJ_SET_INFORMATION, buffer, buffer_length: length, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (irp, stack) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count))) };
        // Parameters.SetFile.Length já veio do build (mesmo lugar de Parameters.Read.Length).
        stack.parameters.set_file.file_information_class.set(crate::ntos::inc::types::FileInformationClass(base_class as i32));
        if flagged {
            stack.flags.set(stack.flags.get() | SET_STACK_ACCESS_CHECK_FLAG);
        }
        irp.flags.set(if locked { SET_IRP_BUFFERED_IO } else { SET_IRP_SYNCHRONOUS_API | SET_IRP_BUFFERED_IO });
        if locked {
            irp.allocation_flags.set(irp.allocation_flags.get() | SET_IRP_ALLOCATION_SYNCHRONOUS);
        }
        let mut target_handle = 0;
        let status = match set_prepare(object, base_class, buffer, stack) {
            Err(local) => {
                // Completa como se o IofCallDriver tivesse descido ao primeiro slot.
                irp.current_location.set(irp.current_location.get() - 1);
                irp.tail.overlay.current_stack_location.set(stack.address());
                irp.io_status.status.set(local);
                irp.io_status.information.set(0);
                io_manager::iof_complete_request(packet);
                local
            }
            Ok(target) => {
                target_handle = target.unwrap_or(0);
                io_manager::iof_call_driver(device, packet)
            }
        };
        if status == SET_STATUS_PENDING {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
        // O handle do diretório de destino sai depois da conclusão.
        if target_handle != 0 {
            let _ = crate::ntos::ob::close::close(target_handle, Some(0));
        }
        // SAFETY: IO_STATUS_BLOCK de rascunho dentro de `scratch`.
        let completed = unsafe { IoStatusBlock::at(io_status) }.status.get();
        if locked {
            object.final_status.set(completed);
        }
        let final_status = if status == SET_STATUS_PENDING { completed } else { status };
        Ok(final_status as u32)
    })();
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

// IoQueryFileDosDeviceName (RVA 0x620880 -> IopQueryNameInternal 0x620924 com
// UseDosDeviceName): o nome DOS do volume (IoVolumeDeviceToDosName; um
// dispositivo remoto vira "\", uma falha cai no nome NT do dispositivo) mais
// o FileNameInformation do FS, num OBJECT_NAME_INFORMATION de PagedPool
// ('IoDn') que o chamador libera com ExFreePool.

const DOS_FILE_REMOTE_DEVICE: u32 = 0x10;
const DOS_FILE_NAME_INFORMATION: u32 = 9;
const DOS_STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
const DOS_STATUS_OBJECT_PATH_INVALID: u32 = 0xC000_0039;
const DOS_NAME_TAG: u32 = 0x6E44_6F49; // 'IoDn'
const DOS_PAGED_POOL: u32 = 1;
/// Falhas do FS que o NT trata como "sem nome de arquivo": NOT_IMPLEMENTED,
/// INVALID_INFO_CLASS, INVALID_PARAMETER, INVALID_DEVICE_REQUEST.
const DOS_EMPTY_NAME_FAILURES: [u32; 4] = [0xC000_0002, 0xC000_0003, 0xC000_000D, 0xC000_0010];

/// Prefixo do volume em UTF-16.
fn dos_device_prefix(device: &DeviceObject) -> Result<alloc::vec::Vec<u16>, KernelError> {
    use crate::ntos::inc::types::UnicodeString;
    if device.characteristics.get() & DOS_FILE_REMOTE_DEVICE != 0 {
        return Ok(alloc::vec![b'\\' as u16]);
    }
    let scratch = guest::alloc_bytes(UnicodeString::SIZE);
    let status = crate::ntos::io::volume_dos_name::volume_device_to_dos_name(device.address(), scratch)?;
    if status & 0x8000_0000 == 0 {
        // SAFETY: UNICODE_STRING preenchido pelo IoVolumeDeviceToDosName.
        let dos_name = unsafe { UnicodeString::at(scratch) };
        let buffer = dos_name.buffer.get();
        let bytes = guest::read_bytes(buffer, dos_name.length.get() as usize);
        crate::ntos::mm::kernel_pool::free(buffer, None)?;
        guest::free_bytes(scratch);
        return Ok(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect());
    }
    guest::free_bytes(scratch);
    // ObQueryNameString do dispositivo: um dispositivo sem nome dá nome vazio.
    Ok(device_nt_name(device.address()))
}

/// FileName do FILE_NAME_INFORMATION (classe 9), crescendo o buffer em
/// STATUS_BUFFER_OVERFLOW; as falhas de "classe não suportada" dão nome vazio.
fn dos_file_name(file: u64) -> Result<Result<alloc::vec::Vec<u16>, u32>, KernelError> {
    use crate::ntos::inc::types::FileNameInformation;
    let header = core::mem::offset_of!(FileNameInformation, file_name) as u32;
    let mut capacity = 0x200u32;
    loop {
        let buffer = guest::alloc_bytes(capacity as u64);
        if buffer == 0 {
            return Ok(Err(RESOURCE));
        }
        let status = query_native(file, DOS_FILE_NAME_INFORMATION, capacity, buffer, 0, false, false, 0)?;
        // SAFETY: FILE_NAME_INFORMATION de `capacity` bytes alocado aqui.
        let information = unsafe { FileNameInformation::at(buffer) };
        let name_length = information.file_name_length.get();
        let first = information.file_name[0].get();
        let bytes = guest::read_bytes(information.file_name[0].address(), (name_length.min(capacity - header) & !1) as usize);
        guest::free_bytes(buffer);
        if status == DOS_STATUS_BUFFER_OVERFLOW && name_length > capacity - header {
            capacity = name_length + header;
            continue;
        }
        if status & 0xC000_0000 == 0xC000_0000 {
            return Ok(if DOS_EMPTY_NAME_FAILURES.contains(&status) { Ok(alloc::vec::Vec::new()) } else { Err(status) });
        }
        if first != b'\\' as u16 {
            return Ok(Err(DOS_STATUS_OBJECT_PATH_INVALID));
        }
        return Ok(Ok(bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect()));
    }
}

/// O nome NT de um dispositivo (o ObQueryNameString dele): o caminho do nó
/// no namespace; um dispositivo sem nome dá nome vazio.
fn device_nt_name(device: u64) -> alloc::vec::Vec<u16> {
    crate::ntos::io::io_manager::devices()
        .into_iter()
        .find(|(_, entry)| entry.native_device == device || entry.stack_top == device)
        .and_then(|(node, _)| crate::ntos::ob::object_manager::path_of(node))
        // Um dispositivo publicado só no namespace (o volume embutido).
        .or_else(|| crate::ntos::ob::query_object::native_object_path(device))
        .unwrap_or_default()
        .encode_utf16()
        .collect()
}

/// IopQueryName (a QueryNameProcedure do tipo File, que o ObQueryNameString
/// de um FILE_OBJECT chama; o IopQueryNameInternal sem UseDosDeviceName): o
/// nome NT do dispositivo do arquivo e, fora de uma abertura direta do
/// dispositivo, o FileNameInformation do FS (as falhas de "classe não
/// suportada" dão só o dispositivo). O volume embutido do kernel não recebe
/// IRPs: ali o nome do arquivo é o FileName do FILE_OBJECT, o caminho que
/// o próprio file system deu na abertura.
pub fn query_object_name(file: u64) -> Result<Result<alloc::vec::Vec<u16>, u32>, KernelError> {
    let object = file_at(file);
    let device = object.device_object.get();
    if device == 0 {
        return Ok(Err(SET_STATUS_INVALID_DEVICE_REQUEST));
    }
    let mut name = device_nt_name(device);
    if object.flags.get() & FO_DIRECT_DEVICE_OPEN != 0 {
        return Ok(Ok(name));
    }
    if related_device(file)? == 0 {
        let length = object.file_name.length.get() as usize;
        let buffer = object.file_name.buffer.get();
        if length != 0 && buffer != 0 {
            let bytes = guest::read_bytes(buffer, length & !1);
            let units: alloc::vec::Vec<u16> = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
            if units.first() != Some(&(b'\\' as u16)) {
                name.push(b'\\' as u16);
            }
            name.extend_from_slice(&units);
        }
        return Ok(Ok(name));
    }
    match dos_file_name(file)? {
        Ok(path) => name.extend_from_slice(&path),
        Err(status) => return Ok(Err(status)),
    }
    Ok(Ok(name))
}

/// IoQueryFileDosDeviceName(FileObject, *ObjectNameInformation).
pub fn query_dos_device_name(file: u64, output: &Field<u64>) -> Result<u32, KernelError> {
    use crate::ntos::inc::types::ObjectNameInformation;
    let device = file_at(file).device_object.get();
    if device == 0 {
        return Ok(SET_STATUS_INVALID_DEVICE_REQUEST);
    }
    let mut name = dos_device_prefix(device_at(device))?;
    match dos_file_name(file)? {
        Ok(path) => name.extend_from_slice(&path),
        Err(status) => return Ok(status),
    }
    let bytes = name.len() as u64 * 2;
    let allocation = crate::ntos::ex::pool_allocation::allocate_tagged(DOS_PAGED_POOL, ObjectNameInformation::SIZE + bytes + 2, DOS_NAME_TAG)?;
    if allocation == 0 {
        return Ok(RESOURCE);
    }
    // SAFETY: OBJECT_NAME_INFORMATION recém-alocado, seguido do texto.
    let information = unsafe { ObjectNameInformation::at(allocation) };
    let text = allocation + ObjectNameInformation::SIZE;
    information.name.length.set(bytes as u16);
    information.name.maximum_length.set(bytes as u16 + 2);
    information.name.buffer.set(text);
    let mut encoded: alloc::vec::Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    encoded.extend_from_slice(&[0, 0]);
    guest::write_bytes(text, &encoded);
    output.set(allocation);
    Ok(0)
}

/// IRP_MJ_SET_VOLUME_INFORMATION (0x0B) ao dispositivo relacionado
/// (NtSetVolumeInformationFile de kernel): o buffer do chamador é o
/// SystemBuffer; Parameters.SetVolume = { Length, FsInformationClass }.
/// Arquivo síncrono: trava do FILE_OBJECT e o seu Event, como em
/// `query_native`. Devolve (status, Information).
pub fn set_volume_native(file: u64, class: u32, length: u32, buffer: u64) -> Result<(u32, u64), KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return Ok((0xC000_0010, 0));
    }
    let scratch = guest::alloc_bytes(48);
    if scratch == 0 {
        return Ok((RESOURCE, 0));
    }
    let mut packet = 0;
    let mut locked = false;
    let referenced = file_objects::reference(file)?.is_some();
    let result = (|| -> Result<(u32, u64), KernelError> {
        let object = file_at(file);
        if object.flags.get() & FO_SYNCHRONOUS_IO != 0 {
            acquire_file(file)?;
            locked = true;
            dispatcher::clear_event(object.event.address());
        }
        let event = if locked { object.event.address() } else { scratch };
        let io_status = scratch + SCRATCH_IO_STATUS;
        if !locked {
            dispatcher::initialize_event(event, 1, false);
        }
        let count = (device_at(device).stack_size.get() as u8 as u32).max(1);
        packet = guest::alloc_bytes(irp_builder::size_for(count));
        if packet == 0 {
            return Ok((RESOURCE, 0));
        }
        irp_builder::build(packet, &BuildOptions { major: 0x0B, buffer, buffer_length: length, device_object: device, stack_count: count, file_object: file, user_event: event, user_iosb: io_status, thread: process::get_current_thread(), requestor_mode: 0, ..Default::default() });
        // SAFETY: IRP recém-construído, o slot do topo e o IOSB de rascunho.
        let (irp, stack, status_block) = unsafe { (Irp::at(packet), IoStackLocation::at(irp_builder::first_stack_location(packet, count)), IoStatusBlock::at(io_status)) };
        stack.parameters.set_volume.fs_information_class.set(crate::ntos::inc::types::Fsinfoclass(class as i32));
        irp.flags.set(if locked { 0x10 } else { 0x14 });
        let status = io_manager::iof_call_driver(device, packet);
        if status == 0x103 {
            dispatcher::wait_for_single_object(event, 0, 0, false);
        }
        let completed = status_block.status.get();
        if locked {
            object.final_status.set(completed);
        }
        Ok((if status == 0x103 { completed as u32 } else { status as u32 }, status_block.information.get()))
    })();
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
