//! Envio e conclusão de pedidos de IRP — o assunto do `io\iosubs.c` do NT
//! para envio síncrono, construção assíncrona, alocação com extensão,
//! conclusão unload-safe e consultas do solicitante.
//!
//! Transcrição do ntoskrnl 19041:
//!   IoSynchronousCallDriver        rva 0x318390  (KEVENT de pilha + CmpCompleteFlushAndPurgeIrp)
//!   IoForwardIrpSynchronously      rva 0x689b00
//!   IoBuildAsynchronousFsdRequest  rva 0x358db0 -> IopBuildAsynchronousFsdRequest 0x358df0
//!   IoAllocateIrpEx                rva 0x2f9a50 -> IopAllocateIrpPrivate 0x2d2220
//!   IoSetCompletionRoutineEx       rva 0x31dab0  (+ IopUnloadSafeCompletion 0x31f420)
//!   IoIsOperationSynchronous       rva 0x2f4390
//!   IoPropagateIrpExtension        rva 0x2e67b0 -> IoPropagateIrpExtensionEx 0x2e67d0
//!   IoGetRequestorProcessId        rva 0x3cf2d0
//!   IoGetRequestorSessionId        rva 0x32be20
//!   IoGetInitiatorProcess          rva 0x32c4d0 (-> IopGetFileObjectExtension 0x2d6f90, slot 1)
//!   PsGetIoPriorityThread          rva 0x242180 (prioridade de I/O do IRP assíncrono)
//!
//! Reuso: `io_manager::iof_call_driver`, `retained_irp::completion_routine`
//! (o mesmo KeSetEvent + STATUS_MORE_PROCESSING_REQUIRED do
//! CmpCompleteFlushAndPurgeIrp), `irp_builder::{allocate_irp, free_irp}`,
//! `mdl::allocate_mdl`, as extensões de IRP de `irp_extension` (o corpo do
//! IoPropagateIrpExtensionEx e do IoGet/SetActivityIdIrp) e o provider do
//! IoGetRequestorProcess (sem função de assunto: a política do OpenNT vive no
//! adaptador, então é chamado pelo nome). O
//! IopUnloadSafeCompletion é uma rotina privada (id próprio, fora da EAT).

use crate::hal::amd64::native_call;
use crate::ntos::inc::nt_abi::{device_object, eprocess, io_stack_location as stack, irp, kthread};
use crate::ntos::init::exports::{invoke_handler, private_routines};
use crate::ntos::io::{io_manager, irp_builder, irp_extension, mdl, retained_irp};
use crate::ntos::ke::dispatcher;
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::objects::device as device_objects;
use crate::ntos::ps::{process, session};
use crate::rtl::KernelError;

const STATUS_PENDING: u32 = 0x103;
const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
/// SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL.
const INVOKE_ALWAYS: u8 = 0xE0;
const SL_PENDING_RETURNED: u8 = 0x01;
/// IRP.PendingReturned / IRP.Tail.Overlay.IrpExtension (PDB _IRP).
const IRP_PENDING_RETURNED: u64 = 0x41;
const IRP_EXTENSION: u64 = 0xC8;
/// FILE_OBJECT.Flags / FILE_OBJECT.FileObjectExtension (PDB _FILE_OBJECT).
const FILE_OBJECT_FLAGS: u64 = 0x50;
const FILE_OBJECT_EXTENSION: u64 = 0xD0;
const FO_SYNCHRONOUS_IO: u32 = 0x02;
/// DEVICE_OBJECT.Flags.
const DO_BUFFERED_IO: u32 = 0x04;
const DO_DIRECT_IO: u32 = 0x10;
const DO_DEVICE_IRP_REQUIRES_EXTENSION: u32 = 0x0800_0000;
/// IRP.Flags.
const IRP_BUFFERED_WRITE: u32 = 0x30; // IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER
const IRP_BUFFERED_READ: u32 = 0x70; // ... | IRP_INPUT_OPERATION
const IRP_PAGING_IO: u32 = 0x02;
const IRP_SYNCHRONOUS_API: u32 = 0x04;
const IRP_SYNCHRONOUS_PAGING_IO: u32 = 0x40;
const IO_PRIORITY_MASK: u32 = 0xFFF1_FFFF;
const IRP_MJ_WRITE: u32 = 0x04;
/// Majors sem tratamento de buffer: FLUSH_BUFFERS, SHUTDOWN, POWER, PNP (`bt 0x8410200`).
const NO_BUFFER_MAJORS: u32 = 0x0841_0200;
/// ETHREAD.IoBoostCount, EPROCESS.Flags (PDB 19041).
const THREAD_IO_BOOST_COUNT: u64 = 0x550;
const PROCESS_FLAGS: u64 = 0x464;
/// Bloco do IoSetCompletionRoutineEx (0x20 bytes, tag 'IoUs').
const BLOCK_DEVICE: u64 = 0x00;
const BLOCK_CONTEXT: u64 = 0x08;
const BLOCK_ROUTINE: u64 = 0x10;
const BLOCK_ON_ERROR: u64 = 0x18;
const BLOCK_ON_SUCCESS: u64 = 0x19;
const BLOCK_ON_CANCEL: u64 = 0x1A;
const BLOCK_SIZE: u64 = 0x20;
/// IoPropagateIrpExtension: tipos pedidos.
const PROPAGATE_GENERIC: u32 = 0x01;
const PROPAGATE_ACTIVITY_ID: u32 = 0x02;

/// IoSynchronousCallDriver(Device, Irp): KEVENT de notificação, rotina de
/// conclusão na próxima stack location com Control = 0xE0; espera só quando o
/// despacho devolve STATUS_PENDING e então devolve Irp->IoStatus.Status.
pub fn synchronous_call(device: u64, packet: u64) -> Result<u32, KernelError> {
    let routine = retained_irp::completion_routine()?;
    let event = guest::alloc_bytes(0x18);
    if routine == 0 || event == 0 {
        if event != 0 {
            guest::free_bytes(event);
        }
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    dispatcher::initialize_event(event, 0, false);
    let next = guest::read64(packet + irp::CURRENT_STACK_LOCATION) - stack::SIZE;
    guest::write64(next + stack::COMPLETION_ROUTINE, routine);
    guest::write64(next + stack::CONTEXT, event);
    guest::write8(next + stack::CONTROL, INVOKE_ALWAYS);
    let mut status = io_manager::iof_call_driver(device, packet) as u32;
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = guest::read32(packet + irp::IO_STATUS);
    }
    guest::free_bytes(event);
    Ok(status)
}

/// IoForwardIrpSynchronously: FALSE sem stack location livre; senão
/// IoCopyCurrentIrpStackLocationToNext (0x38 bytes, Control zerado) e a
/// chamada síncrona.
pub fn forward_irp_synchronously(device: u64, packet: u64) -> Result<bool, KernelError> {
    if guest::read8(packet + irp::CURRENT_LOCATION) == 1 {
        return Ok(false);
    }
    let current = guest::read64(packet + irp::CURRENT_STACK_LOCATION);
    let next = current - stack::SIZE;
    guest::write_bytes(next, &guest::read_bytes(current, stack::COMPLETION_ROUTINE as usize));
    guest::write8(next + stack::CONTROL, 0);
    synchronous_call(device, packet)?;
    Ok(true)
}

/// PsGetIoPriorityThread.
fn io_priority(thread: u64) -> u32 {
    if thread == 0 {
        return 0;
    }
    let mut priority = (guest::read32(thread + kthread::CROSS_THREAD_FLAGS) >> 9) & 7;
    let owner = guest::read64(thread + kthread::PROCESS);
    if owner != 0 && guest::read32(owner + PROCESS_FLAGS) & 0x10_0000 != 0 {
        priority = 0;
    }
    if priority < 2 && thread == process::get_current_thread() && guest::read32(thread + THREAD_IO_BOOST_COUNT) != 0 {
        priority = 2;
    }
    priority
}

/// IoBuildAsynchronousFsdRequest(Major, Device, Buffer, Length,
/// StartingOffset, IoStatusBlock): sem UserEvent e fora da fila da thread.
pub fn build_asynchronous_fsd_request(major: u32, device: u64, buffer: u64, length: u32, offset: u64, io_status: u64) -> Result<u64, KernelError> {
    let packet = irp_builder::allocate_irp(guest::read8(device + device_object::STACK_SIZE) as i8);
    if packet == 0 {
        return Ok(0);
    }
    let thread = process::get_current_thread();
    guest::write64(packet + irp::THREAD, thread);
    let top = guest::read64(packet + irp::CURRENT_STACK_LOCATION) - stack::SIZE;
    guest::write8(top + stack::MAJOR, major as u8);
    if !(major <= 0x1B && NO_BUFFER_MAJORS & (1 << major) != 0) {
        let flags = guest::read32(device + device_object::FLAGS);
        if flags & DO_BUFFERED_IO != 0 {
            // O SystemBuffer é do I/O Manager (IRP_DEALLOCATE_BUFFER): sai do
            // mesmo pool que o IofCompleteRequest do OpenNT libera.
            let system = guest::alloc_bytes((length as u64).max(1));
            if system == 0 {
                irp_builder::free_irp(packet);
                return Ok(0);
            }
            guest::write64(packet + irp::SYSTEM_BUFFER, system);
            if major == IRP_MJ_WRITE {
                guest::write_bytes(system, &guest::read_bytes(buffer, length as usize));
                guest::write32(packet + irp::FLAGS, IRP_BUFFERED_WRITE);
            } else {
                guest::write64(packet + irp::USER_BUFFER, buffer);
                guest::write32(packet + irp::FLAGS, IRP_BUFFERED_READ);
            }
        } else if flags & DO_DIRECT_IO != 0 {
            // IoAllocateMdl + IopProbeAndLockPages: a memória do OpenNT já é residente.
            let descriptor = mdl::allocate_mdl(buffer, length);
            if descriptor == 0 {
                irp_builder::free_irp(packet);
                return Ok(0);
            }
            guest::write64(packet + irp::MDL_ADDRESS, descriptor);
        } else {
            guest::write64(packet + irp::USER_BUFFER, buffer);
        }
        guest::write32(top + stack::READ_LENGTH, length);
        if offset != 0 {
            guest::write64(top + stack::READ_OFFSET, guest::read64(offset));
        }
    }
    let flags = guest::read32(packet + irp::FLAGS) & IO_PRIORITY_MASK;
    guest::write32(packet + irp::FLAGS, flags | ((io_priority(thread) + 1) << 17));
    guest::write64(packet + irp::USER_IOSB, io_status);
    Ok(packet)
}

/// IoAllocateIrpEx(DeviceObject, StackSize, ChargeQuota): DeviceObject == -1
/// ou DO_DEVICE_IRP_REQUIRES_EXTENSION reserva duas stack locations no topo
/// para a _IOP_IRP_EXTENSION (StackCount/CurrentLocation -2, CSL -0x90 e
/// IrpExtension = CSL). ChargeQuota não muda nada: os IRPs do OpenNT saem da
/// arena sem cota, como no IoAllocateIrp do OpenNT.
pub fn allocate_irp_ex(device: u64, stack_size: u8, _charge_quota: bool) -> u64 {
    let extension = device == u64::MAX || (device != 0 && guest::read32(device + device_object::FLAGS) & DO_DEVICE_IRP_REQUIRES_EXTENSION != 0);
    if !extension {
        return irp_builder::allocate_irp(stack_size as i8);
    }
    let packet = irp_builder::allocate_irp(stack_size.wrapping_add(2) as i8);
    if packet == 0 {
        return 0;
    }
    guest::write8(packet + irp::STACK_COUNT, guest::read8(packet + irp::STACK_COUNT).wrapping_sub(2));
    guest::write8(packet + irp::CURRENT_LOCATION, guest::read8(packet + irp::CURRENT_LOCATION).wrapping_sub(2));
    let current = guest::read64(packet + irp::CURRENT_STACK_LOCATION) - 2 * stack::SIZE;
    guest::write64(packet + irp::CURRENT_STACK_LOCATION, current);
    guest::write64(packet + IRP_EXTENSION, current);
    packet
}

/// Gatilhos do IoSetCompletionRoutineEx.
pub struct InvokeOn {
    pub success: bool,
    pub error: bool,
    pub cancel: bool,
}

/// IoSetCompletionRoutineEx(Device, Irp, Routine, Context, OnSuccess, OnError,
/// OnCancel): sem gatilho -> STATUS_INVALID_PARAMETER; senão o bloco de 0x20
/// bytes e IopUnloadSafeCompletion na próxima stack location (Control 0xE0).
pub fn set_completion_routine_ex(device: u64, packet: u64, routine: u64, context: u64, invoke: InvokeOn) -> Result<u32, KernelError> {
    if !invoke.error && !invoke.cancel && !invoke.success {
        return Ok(STATUS_INVALID_PARAMETER);
    }
    let wrapper = private_routines::address("IopUnloadSafeCompletion");
    if wrapper == 0 {
        return Err(KernelError::new("IopUnloadSafeCompletion sem entrada nativa"));
    }
    let block = guest::alloc_bytes(BLOCK_SIZE);
    if block == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    guest::write64(block + BLOCK_DEVICE, device);
    guest::write64(block + BLOCK_CONTEXT, context);
    guest::write64(block + BLOCK_ROUTINE, routine);
    guest::write8(block + BLOCK_ON_ERROR, invoke.error as u8);
    guest::write8(block + BLOCK_ON_SUCCESS, invoke.success as u8);
    guest::write8(block + BLOCK_ON_CANCEL, invoke.cancel as u8);
    let next = guest::read64(packet + irp::CURRENT_STACK_LOCATION) - stack::SIZE;
    guest::write64(next + stack::COMPLETION_ROUTINE, wrapper);
    guest::write64(next + stack::CONTEXT, block);
    guest::write8(next + stack::CONTROL, INVOKE_ALWAYS);
    Ok(0)
}

/// IopUnloadSafeCompletion(DeviceObject, Irp, Block) — corpo da rotina
/// privada: retém o dispositivo do bloco durante a rotina do driver; sem
/// gatilho propaga o pending e devolve STATUS_PENDING/STATUS_SUCCESS.
pub fn unload_safe_completion(device: u64, packet: u64, block: u64) -> Result<u32, KernelError> {
    let status = guest::read32(packet + irp::IO_STATUS) as i32;
    let selected = if status >= 0 { guest::read8(block + BLOCK_ON_SUCCESS) } else { guest::read8(block + BLOCK_ON_ERROR) };
    let invoke = selected != 0 || (guest::read8(packet + irp::CANCEL) != 0 && guest::read8(block + BLOCK_ON_CANCEL) != 0);
    if !invoke {
        let mut result = 0;
        if guest::read8(packet + IRP_PENDING_RETURNED) != 0 {
            let current = guest::read64(packet + irp::CURRENT_STACK_LOCATION);
            guest::write8(current + stack::CONTROL, guest::read8(current + stack::CONTROL) | SL_PENDING_RETURNED);
            result = STATUS_PENDING;
        }
        guest::free_bytes(block);
        return Ok(result);
    }
    let held = guest::read64(block + BLOCK_DEVICE);
    let referenced = held != 0 && device_objects::reference(held)?.is_some();
    let result = native_call::call(guest::read64(block + BLOCK_ROUTINE), &[device, packet, guest::read64(block + BLOCK_CONTEXT)]) as u32;
    guest::free_bytes(block);
    if referenced {
        device_objects::dereference(held)?;
    }
    Ok(result)
}

/// IoIsOperationSynchronous(Irp).
pub fn is_operation_synchronous(packet: u64) -> bool {
    let flags = guest::read32(packet + irp::FLAGS);
    let file = guest::read64(guest::read64(packet + irp::CURRENT_STACK_LOCATION) + stack::FILE_OBJECT);
    let synchronous_file = file != 0 && guest::read32(file + FILE_OBJECT_FLAGS) & FO_SYNCHRONOUS_IO != 0;
    let paging = flags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO);
    if flags & IRP_SYNCHRONOUS_API == 0 && !synchronous_file && paging != IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO {
        return false;
    }
    paging != IRP_PAGING_IO
}

/// IoPropagateIrpExtension(Source, Target, Flags) = Ex(Source, Target, NULL,
/// Flags). Flag 1: GenericExtension; flag 2: ActivityId. Os demais tipos
/// (zeroing offset, atribuição de disco, FsTrack, DriverFlags) não têm estado
/// no OpenNT.
pub fn propagate_irp_extension(source: u64, target: u64, flags: u32) {
    if flags & PROPAGATE_GENERIC != 0 {
        // Copia a extensão genérica (valor e marca de propagação); a ausência
        // na origem (STATUS_NOT_FOUND) não altera o alvo.
        irp_extension::propagate(source, target);
    }
    if flags & PROPAGATE_ACTIVITY_ID != 0 {
        let activity = guest::alloc_bytes(16);
        if activity == 0 {
            return;
        }
        if irp_extension::activity_id(source, activity) == 0 {
            irp_extension::set_activity_id(target, activity);
        }
        guest::free_bytes(activity);
    }
}

/// IoGetRequestorProcessId: UniqueProcessId (ULONG) do IoGetRequestorProcess.
pub fn requestor_process_id(packet: u64) -> Result<u32, KernelError> {
    let owner = invoke_handler("IoGetRequestorProcess", &[packet])?;
    Ok(if owner == 0 { 0 } else { guest::read32(owner + eprocess::UNIQUE_PROCESS_ID) })
}

/// IoGetRequestorSessionId(Irp, SessionId): sem Tail.Overlay.Thread grava -1
/// e devolve STATUS_UNSUCCESSFUL; senão MmGetSessionIdEx do processo da
/// thread com -1 -> 0 (`ps::session::query` faz o mesmo mapeamento).
pub fn requestor_session_id(packet: u64, output: u64) -> u32 {
    let thread = guest::read64(packet + irp::THREAD);
    if thread == 0 {
        guest::write32(output, 0xFFFF_FFFF);
        return STATUS_UNSUCCESSFUL;
    }
    let owner = guest::read64(thread + kthread::PROCESS);
    guest::write32(output, if owner == 0 { 0 } else { session::query(owner) });
    0
}

/// IoGetInitiatorProcess(FileObject): IopGetFileObjectExtension(Fo, 1) e o
/// processo iniciador em +8 do bloco; FILE_OBJECT sem extensão -> NULL.
pub fn initiator_process(file_object: u64) -> u64 {
    let extension = guest::read64(file_object + FILE_OBJECT_EXTENSION);
    if extension == 0 {
        return 0;
    }
    let block = guest::read64(extension + 0x10);
    if block == 0 { 0 } else { guest::read64(block + 8) }
}
