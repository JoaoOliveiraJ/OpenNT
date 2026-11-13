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

/// O que o I/O Manager faz com a classe antes de chamar o driver: `None` =
/// enviar o IRP; `Some(status)` = completar aqui com esse status.
fn set_prepare(file: &FileObject, class: u32, buffer: u64, stack: &IoStackLocation) -> Option<i32> {
    use crate::ntos::inc::types::{FileModeInformation, FileRenameInformation};
    match class {
        SET_FILE_MODE_INFORMATION => {
            // SAFETY: FILE_MODE_INFORMATION do chamador de modo kernel.
            set_mode_information(file, unsafe { FileModeInformation::at(buffer) }.mode.get());
            Some(0)
        }
        SET_FILE_RENAME_INFORMATION | SET_FILE_LINK_INFORMATION | SET_FILE_RENAME_INFORMATION_EX | SET_FILE_LINK_INFORMATION_EX | SET_FILE_MOVE_CLUSTER_INFORMATION => {
            // FILE_RENAME/LINK_INFORMATION[_EX] e FILE_MOVE_CLUSTER_INFORMATION
            // dividem o layout (ReplaceIfExists/Flags/ClusterCount, RootDirectory,
            // FileNameLength, FileName).
            // SAFETY: estrutura do chamador de modo kernel.
            let information = unsafe { FileRenameInformation::at(buffer) };
            let set_file = &stack.parameters.set_file;
            match class {
                SET_FILE_MOVE_CLUSTER_INFORMATION => set_file.cluster_count.set(information.flags.get()),
                SET_FILE_RENAME_INFORMATION_EX | SET_FILE_LINK_INFORMATION_EX => set_file.replace_if_exists.set((information.flags.get() & 1) as u8),
                _ => set_file.replace_if_exists.set(information.replace_if_exists.get()),
            }
            let needs_target = information.file_name[0].get() == b'\\' as u16 || information.root_directory.get() != 0;
            // IopOpenLinkOrRenameTarget (abrir o diretório de destino) não existe no OpenNT.
            needs_target.then_some(SET_STATUS_NOT_IMPLEMENTED)
        }
        // IopSetFileMemoryPartitionInformation: sem partições de memória por arquivo no OpenNT.
        SET_FILE_MEMORY_PARTITION_INFORMATION => Some(SET_STATUS_NOT_IMPLEMENTED),
        _ => None,
    }
}

/// IoSetInformation(FileObject, FileInformationClass, Length, FileInformation).
pub fn set_native(file: u64, class: u32, length: u32, buffer: u64) -> Result<u32, KernelError> {
    let device = related_device(file)?;
    if device == 0 {
        return Ok(SET_STATUS_INVALID_DEVICE_REQUEST);
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
        let status = match set_prepare(object, base_class, buffer, stack) {
            Some(local) => {
                // Completa como se o IofCallDriver tivesse descido ao primeiro slot.
                irp.current_location.set(irp.current_location.get() - 1);
                irp.tail.overlay.current_stack_location.set(stack.address());
                irp.io_status.status.set(local);
                irp.io_status.information.set(0);
                io_manager::iof_complete_request(packet);
                local
            }
            None => io_manager::iof_call_driver(device, packet),
        };
        if status == SET_STATUS_PENDING {
            dispatcher::wait_for_single_object(event, 0, 0, false);
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
    let path = crate::ntos::io::io_manager::devices()
        .into_iter()
        .find(|(_, entry)| entry.native_device == device.address() || entry.stack_top == device.address())
        .and_then(|(node, _)| crate::ntos::ob::object_manager::path_of(node))
        .unwrap_or_default();
    Ok(path.encode_utf16().collect())
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
