//! QuerySecurity dos objetos de I/O.
//!
//! Conserva o descritor real do dispositivo ou encaminha a consulta ao
//! driver por IRP_MJ_QUERY_SECURITY (neither I/O).

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::ntos::io::threads::thread_requests;
use crate::ntos::io::file::information as file_information;
use crate::ntos::io::io_manager;
use crate::ntos::ke::{dispatcher, pcr};
use crate::ntos::mm::{data_pool, kernel_pool};
use crate::ntos::ob::objects::file as file_objects;
use crate::ntos::ps::process;
use crate::ntos::se::query_descriptor::{self, QueryResult};
use crate::rtl::KernelError;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{DeviceObject, FileObject, IoStackLocation, IoStatusBlock, Irp, Kpcr, Kthread, Mdl, NtStruct, SecurityDescriptorRelative};
use crate::ntos::io::irp_builder::{self, BuildOptions};

const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const STATUS_INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
const STATUS_BUFFER_TOO_SMALL: u32 = 0xC000_0023;
const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;
/// SE_SELF_RELATIVE.
const SE_SELF_RELATIVE: u32 = 0x8000;
/// FILE_OBJECT.Flags.
const FO_SYNCHRONOUS_IO: u32 = 0x02;
const FO_DIRECT_DEVICE_OPEN: u32 = 0x800;
/// DEVICE_OBJECT.Characteristics: FILE_DEVICE_SECURE_OPEN.
const FILE_DEVICE_SECURE_OPEN: u32 = 0x100;
/// IO_STATUS_BLOCK de rascunho depois do KEVENT.
const SCRATCH_IO_STATUS: u64 = 24;

fn file_at(file: u64) -> &'static FileObject {
    // SAFETY: FILE_OBJECT vivo (referenciado pelo chamador).
    unsafe { FileObject::at(file) }
}

fn device_at(device: u64) -> &'static DeviceObject {
    // SAFETY: dispositivo vivo alcançado por um FILE_OBJECT.
    unsafe { DeviceObject::at(device) }
}

/// SeAssignWorldSecurityDescriptor: o fallback para driver sem segurança e
/// dispositivo sem FILE_DEVICE_SECURE_OPEN; o tamanho necessário é sempre 44.
pub fn query_unsupported_file(information: u32, buffer: u64, capacity: u32) -> QueryResult {
    let needed = 44;
    if capacity < needed as u32 {
        return QueryResult { status: STATUS_BUFFER_TOO_SMALL, needed, information };
    }
    guest::write_bytes(buffer, &[0; SecurityDescriptorRelative::SIZE as usize]);
    // SAFETY: buffer do chamador de modo kernel com capacidade conferida.
    let descriptor = unsafe { SecurityDescriptorRelative::at(buffer) };
    descriptor.revision.set(1);
    let mut cursor = SecurityDescriptorRelative::SIZE as u32;
    // S-1-1-0 (World).
    let world = [1u8, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
    for (bit, offset) in [(1u32, &descriptor.owner), (2, &descriptor.group)] {
        if information & bit == 0 {
            continue;
        }
        offset.set(cursor);
        guest::write_bytes(buffer + cursor as u64, &world);
        cursor += world.len() as u32;
    }
    descriptor.control.set((SE_SELF_RELATIVE | (information & 4) | ((information & 8) << 1)) as u16);
    QueryResult { status: 0, needed, information }
}

/// O descritor do DEVICE_OBJECT (+0x110); ausência continua ausência.
pub fn query_device(device: u64, information: u32, buffer: u64, capacity: u32) -> QueryResult {
    let descriptor = device_at(device).security_descriptor.get();
    query_descriptor::query_descriptor(query_descriptor::read_descriptor(descriptor).as_ref(), information, buffer, capacity)
}

/// MDLs anexados pelo driver pertencem ao IRP concluído.
fn release_request_descriptors(request: u64) -> Result<(), KernelError> {
    // SAFETY: IRP concluído ainda de posse do chamador.
    let mut descriptor = unsafe { Irp::at(request) }.mdl_address.get();
    while descriptor != 0 {
        // SAFETY: cadeia de MDLs (MDL.Next) anexada ao IRP.
        let next = unsafe { Mdl::at(descriptor) }.next.get();
        if kernel_pool::owns(descriptor) {
            let _ = kernel_pool::free(descriptor, None);
        } else if data_pool::owns(descriptor) {
            data_pool::free(descriptor)?;
        } else if guest::owns_allocation(descriptor) {
            guest::free_bytes(descriptor);
        } else {
            return Err(KernelError::new("query-security MDL has no allocation owner"));
        }
        descriptor = next;
    }
    Ok(())
}

/// O buffer original vai em UserBuffer; a conclusão é dona do IOSB e o
/// retorno imediato tem precedência, salvo STATUS_PENDING.
fn dispatch_query(file: u64, device: u64, information: u32, buffer: u64, capacity: u32, requestor_mode: u8) -> Result<QueryResult, KernelError> {
    let scratch = guest::alloc_bytes(40);
    if scratch == 0 {
        return Ok(QueryResult { status: STATUS_INSUFFICIENT_RESOURCES, needed: capacity as usize, information });
    }
    let thread = process::get_current_thread();
    let file_flags = file_at(file).flags.get();
    let mut request = 0u64;
    let mut file_references = 0;
    let mut locked = false;
    let mut thread_retained = false;
    let linked = Arc::new(AtomicBool::new(false));
    let completed = Arc::new(AtomicBool::new(false));
    let completion = Arc::new(AtomicU64::new(0));
    let completion_length = Arc::new(AtomicU64::new(0));
    let mut dispatched = false;
    let mut immediate: Option<u32> = None;
    let result = (|| -> Result<QueryResult, KernelError> {
        if file_objects::reference(file)?.is_none() {
            return Err(KernelError::new("query-security file has no owner"));
        }
        file_references += 1;
        if file_flags & FO_SYNCHRONOUS_IO != 0 {
            file_information::acquire_file(file)?;
            locked = true;
            if file_objects::reference(file)?.is_none() {
                return Err(KernelError::new("locked file lost its owner"));
            }
            file_references += 1;
        }
        if file_flags & 0x400_0000 == 0 {
            dispatcher::clear_event(file_at(file).event.address());
        }
        let event = if locked { file_at(file).event.address() } else { scratch };
        let status_block = scratch + SCRATCH_IO_STATUS;
        if !locked {
            dispatcher::initialize_event(event, 1, false);
        }
        let stack_count = device_at(device).stack_size.get() as u8 as u32;
        if stack_count == 0 {
            return Err(KernelError::new("query-security device has no IRP stack"));
        }
        request = guest::alloc_bytes(irp_builder::size_for(stack_count));
        if request == 0 {
            return Ok(QueryResult { status: STATUS_INSUFFICIENT_RESOURCES, needed: capacity as usize, information });
        }
        irp_builder::build(request, &BuildOptions { major: 0x14, minor: 0, stack_count, device_object: device, file_object: file, user_buffer: buffer, user_iosb: status_block, user_event: if locked { 0 } else { event }, requestor_mode, thread, ..Default::default() });
        // SAFETY: IRP recém-construído e o slot do topo dele.
        let (irp, stack) = unsafe { (Irp::at(request), IoStackLocation::at(irp_builder::first_stack_location(request, stack_count))) };
        stack.parameters.query_security.security_information.set(information);
        stack.parameters.query_security.length.set(capacity);
        irp.flags.set(if locked { 0 } else { 4 });
        if locked {
            irp.allocation_flags.set(2);
        }
        if process::reference_thread(thread).is_none() {
            return Err(KernelError::new("query-security thread has no owner"));
        }
        thread_retained = true;
        thread_requests::insert(request, thread)?;
        linked.store(true, Ordering::Release);
        // IopUpdateOtherOperationCount: contadores da própria thread e da CPU.
        // SAFETY: a thread corrente.
        let counter = &unsafe { Kthread::at(thread) }.other_operation_count;
        counter.set(counter.get().wrapping_add(1));
        let processor = pcr::get_pcr_address();
        if processor != 0 {
            // SAFETY: KPCR da CPU corrente.
            let count = &unsafe { Kpcr::at(processor) }.prcb.io_other_operation_count;
            count.atomic().fetch_add(1, Ordering::Relaxed);
        }
        {
            let (completed, completion, completion_length, linked) = (completed.clone(), completion.clone(), completion_length.clone(), linked.clone());
            io_manager::manage_completion(request, Box::new(move |status, information| {
                if completed.swap(true, Ordering::AcqRel) {
                    panic!("query-security IRP completed twice");
                }
                completion.store(status as u32 as u64, Ordering::Release);
                completion_length.store(information, Ordering::Release);
                let _ = thread_requests::remove(request, thread);
                linked.store(false, Ordering::Release);
                // SAFETY: IO_STATUS_BLOCK de rascunho, vivo até o pedido terminar.
                let iosb = unsafe { IoStatusBlock::at(status_block) };
                iosb.status.set(status);
                iosb.information.set(information);
                file_at(file).final_status.set(status);
                dispatcher::set_event(event);
            }));
        }
        dispatched = true;
        let returned = io_manager::iof_call_driver(device, request) as u32;
        immediate = Some(returned);
        if returned == 0x103 {
            while !completed.load(Ordering::Acquire) {
                dispatcher::wait_for_single_object(event, 0, 0, false);
                if !completed.load(Ordering::Acquire) {
                    dispatcher::pump_kernel();
                }
            }
        } else if !completed.load(Ordering::Acquire) && returned & 0x8000_0000 == 0 {
            return Err(KernelError::new("driver returned success without completing query-security IRP"));
        }
        let mut status = if returned == 0x103 { completion.load(Ordering::Acquire) as u32 } else { returned };
        // -3 interno = MajorFunction ausente.
        if status == 0xFFFF_FFFD {
            status = STATUS_INVALID_DEVICE_REQUEST;
        }
        if status == STATUS_BUFFER_OVERFLOW {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        Ok(QueryResult { status, needed: (completion_length.load(Ordering::Acquire) & 0xFFFF_FFFF) as usize, information })
    })();
    // Um pedido que ainda pode pertencer ao driver não é liberado.
    let still_owned = dispatched && !completed.load(Ordering::Acquire) && immediate.is_none_or(|status| status == 0x103 || status & 0x8000_0000 == 0);
    if !still_owned {
        if request != 0 {
            io_manager::forget_managed_completion(request);
            if linked.load(Ordering::Acquire) {
                thread_requests::remove(request, thread)?;
            }
            release_request_descriptors(request)?;
            guest::free_bytes(request);
        }
        if thread_retained {
            process::dereference_thread(thread)?;
        }
        if locked {
            file_information::release_file(file)?;
        }
        for _ in 0..file_references {
            file_objects::dereference(file)?;
        }
        guest::free_bytes(scratch);
    }
    result
}

/// Volume sem nome e abertura direta usam o dispositivo base; arquivos
/// normais seguem o dispositivo relacionado e o fallback do Windows.
pub fn query_file(file: u64, information: u32, buffer: u64, capacity: u32, requestor_mode: u8) -> Result<QueryResult, KernelError> {
    let object = file_at(file);
    let base_device = object.device_object.get();
    if base_device == 0 {
        return Err(KernelError::new("native file security requires a device"));
    }
    let direct = object.flags.get() & FO_DIRECT_DEVICE_OPEN != 0;
    let volume_open = object.file_name.length.get() == 0 && object.related_file_object.get() == 0;
    if direct || volume_open {
        return Ok(query_device(base_device, information, buffer, capacity));
    }
    let device = file_information::related_device(file)?;
    let result = dispatch_query(file, device, information, buffer, capacity, requestor_mode)?;
    if result.status != STATUS_INVALID_DEVICE_REQUEST {
        return Ok(result);
    }
    Ok(if device_at(device).characteristics.get() & FILE_DEVICE_SECURE_OPEN != 0 { query_device(device, information, buffer, capacity) } else { query_unsupported_file(information, buffer, capacity) })
}
