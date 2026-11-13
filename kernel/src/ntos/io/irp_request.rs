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

use core::mem::offset_of;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, Reserved};
use crate::ntos::inc::types::extra_io::IrpExtensionField;
use crate::ntos::inc::types::{DeviceObject, Eprocess, Ethread, FileObject, IoStackLocation, IopFileObjectExtension, Irp, Kthread, LargeInteger, NtStruct};
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
/// EPROCESS.Flags: prioridade de I/O desligada no processo.
const PROCESS_NO_IO_PRIORITY: u32 = 0x10_0000;
/// IoPropagateIrpExtension: tipos pedidos.
const PROPAGATE_GENERIC: u32 = 0x01;
const PROPAGATE_ACTIVITY_ID: u32 = 0x02;
/// Slot do IopGetFileObjectExtension com o bloco do iniciador; o processo
/// iniciador fica em +8 do bloco (layout privado do kernel, sem tipo nos
/// símbolos).
const INITIATOR_EXTENSION_SLOT: usize = 1;
const INITIATOR_PROCESS: u64 = 8;

/// Bloco do IoSetCompletionRoutineEx (0x20 bytes, tag 'IoUs'): privado do
/// kernel, entregue como Context ao IopUnloadSafeCompletion.
#[repr(C)]
struct UnloadSafeBlock {
    device: Field<u64>,
    context: Field<u64>,
    routine: Field<u64>,
    on_error: Field<u8>,
    on_success: Field<u8>,
    on_cancel: Field<u8>,
    _pad_1b: Reserved<0x5>,
}

// SAFETY: #[repr(C)] só de células.
unsafe impl NtStruct for UnloadSafeBlock {}

const _: () = {
    assert!(core::mem::size_of::<UnloadSafeBlock>() == 0x20);
    assert!(offset_of!(UnloadSafeBlock, routine) == 0x10);
    assert!(offset_of!(UnloadSafeBlock, on_error) == 0x18);
    assert!(offset_of!(UnloadSafeBlock, on_cancel) == 0x1A);
};

/// IoGetNextIrpStackLocation.
fn next_location(irp: &Irp) -> &'static IoStackLocation {
    // SAFETY: a stack location abaixo da corrente pertence ao mesmo IRP.
    unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) }
}

/// IoGetCurrentIrpStackLocation.
fn current_location(irp: &Irp) -> &'static IoStackLocation {
    // SAFETY: CurrentStackLocation de um IRP vivo.
    unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) }
}

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
    // SAFETY: IRP vivo do chamador.
    let irp = unsafe { Irp::at(packet) };
    let next = next_location(irp);
    next.completion_routine.set(routine);
    next.context.set(event);
    next.control.set(INVOKE_ALWAYS);
    let mut status = io_manager::iof_call_driver(device, packet) as u32;
    if status == STATUS_PENDING {
        dispatcher::wait_for_single_object(event, 0, 0, false);
        status = irp.io_status.status.get() as u32;
    }
    guest::free_bytes(event);
    Ok(status)
}

/// IoForwardIrpSynchronously: FALSE sem stack location livre; senão
/// IoCopyCurrentIrpStackLocationToNext (0x38 bytes, Control zerado) e a
/// chamada síncrona.
pub fn forward_irp_synchronously(device: u64, packet: u64) -> Result<bool, KernelError> {
    // SAFETY: IRP vivo do chamador.
    let irp = unsafe { Irp::at(packet) };
    if irp.current_location.get() == 1 {
        return Ok(false);
    }
    let current = current_location(irp);
    let next = next_location(irp);
    guest::write_bytes(next.address(), &guest::read_bytes(current.address(), offset_of!(IoStackLocation, completion_routine)));
    next.control.set(0);
    synchronous_call(device, packet)?;
    Ok(true)
}

/// PsGetIoPriorityThread.
pub fn io_priority(thread: u64) -> u32 {
    if thread == 0 {
        return 0;
    }
    // SAFETY: ETHREAD vivo (a thread corrente ou a do IRP).
    let ethread = unsafe { Ethread::at(thread) };
    let mut priority = ethread.thread_io_priority();
    let owner = ethread.tcb.process.get();
    // SAFETY: KTHREAD.Process de uma thread viva é um EPROCESS vivo.
    if owner != 0 && unsafe { Eprocess::at(owner) }.flags.get() & PROCESS_NO_IO_PRIORITY != 0 {
        priority = 0;
    }
    if priority < 2 && thread == process::get_current_thread() && ethread.io_boost_count.get() != 0 {
        priority = 2;
    }
    priority
}

/// IoBuildAsynchronousFsdRequest(Major, Device, Buffer, Length,
/// StartingOffset, IoStatusBlock): sem UserEvent e fora da fila da thread.
pub fn build_asynchronous_fsd_request(major: u32, device: u64, buffer: u64, length: u32, offset: u64, io_status: u64) -> Result<u64, KernelError> {
    // SAFETY: DEVICE_OBJECT vivo do chamador.
    let target = unsafe { DeviceObject::at(device) };
    let packet = irp_builder::allocate_irp(target.stack_size.get());
    if packet == 0 {
        return Ok(0);
    }
    // SAFETY: IRP recém-alocado.
    let irp = unsafe { Irp::at(packet) };
    let thread = process::get_current_thread();
    irp.tail.overlay.thread.set(thread);
    let top = next_location(irp);
    top.major_function.set(major as u8);
    if !(major <= 0x1B && NO_BUFFER_MAJORS & (1 << major) != 0) {
        let flags = target.flags.get();
        if flags & DO_BUFFERED_IO != 0 {
            // O SystemBuffer é do I/O Manager (IRP_DEALLOCATE_BUFFER): sai do
            // mesmo pool que o IofCompleteRequest do OpenNT libera.
            let system = guest::alloc_bytes((length as u64).max(1));
            if system == 0 {
                irp_builder::free_irp(packet);
                return Ok(0);
            }
            irp.associated_irp.system_buffer.set(system);
            if major == IRP_MJ_WRITE {
                guest::write_bytes(system, &guest::read_bytes(buffer, length as usize));
                irp.flags.set(IRP_BUFFERED_WRITE);
            } else {
                irp.user_buffer.set(buffer);
                irp.flags.set(IRP_BUFFERED_READ);
            }
        } else if flags & DO_DIRECT_IO != 0 {
            // IoAllocateMdl + IopProbeAndLockPages: a memória do OpenNT já é residente.
            let descriptor = mdl::allocate_mdl(buffer, length);
            if descriptor == 0 {
                irp_builder::free_irp(packet);
                return Ok(0);
            }
            irp.mdl_address.set(descriptor);
        } else {
            irp.user_buffer.set(buffer);
        }
        // Parameters.Read e Parameters.Write têm o mesmo layout.
        top.parameters.read.length.set(length);
        if offset != 0 {
            // SAFETY: StartingOffset (PLARGE_INTEGER) do chamador de modo kernel.
            let starting = unsafe { LargeInteger::at(offset) };
            top.parameters.read.byte_offset.quad_part.set(starting.quad_part.get());
        }
    }
    let flags = irp.flags.get() & IO_PRIORITY_MASK;
    irp.flags.set(flags | ((io_priority(thread) + 1) << 17));
    irp.user_iosb.set(io_status);
    Ok(packet)
}

/// IoAllocateIrpEx(DeviceObject, StackSize, ChargeQuota): DeviceObject == -1
/// ou DO_DEVICE_IRP_REQUIRES_EXTENSION reserva duas stack locations no topo
/// para a _IOP_IRP_EXTENSION (StackCount/CurrentLocation -2, CSL -0x90 e
/// IrpExtension = CSL). ChargeQuota não muda nada: os IRPs do OpenNT saem da
/// arena sem cota, como no IoAllocateIrp do OpenNT.
pub fn allocate_irp_ex(device: u64, stack_size: u8, _charge_quota: bool) -> u64 {
    // SAFETY: DEVICE_OBJECT vivo quando não é nulo nem -1.
    let extension = device == u64::MAX || (device != 0 && unsafe { DeviceObject::at(device) }.flags.get() & DO_DEVICE_IRP_REQUIRES_EXTENSION != 0);
    if !extension {
        return irp_builder::allocate_irp(stack_size as i8);
    }
    let packet = irp_builder::allocate_irp(stack_size.wrapping_add(2) as i8);
    if packet == 0 {
        return 0;
    }
    // SAFETY: IRP recém-alocado.
    let irp = unsafe { Irp::at(packet) };
    irp.stack_count.set(irp.stack_count.get().wrapping_sub(2));
    irp.current_location.set(irp.current_location.get().wrapping_sub(2));
    let current = irp.tail.overlay.current_stack_location.get() - 2 * IoStackLocation::SIZE;
    irp.tail.overlay.current_stack_location.set(current);
    irp.irp_extension().set(current);
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
    let address = guest::alloc_bytes(UnloadSafeBlock::SIZE);
    if address == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: alocação zerada do tamanho do bloco.
    let block = unsafe { UnloadSafeBlock::at(address) };
    block.device.set(device);
    block.context.set(context);
    block.routine.set(routine);
    block.on_error.set(invoke.error as u8);
    block.on_success.set(invoke.success as u8);
    block.on_cancel.set(invoke.cancel as u8);
    // SAFETY: IRP vivo do chamador.
    let next = next_location(unsafe { Irp::at(packet) });
    next.completion_routine.set(wrapper);
    next.context.set(address);
    next.control.set(INVOKE_ALWAYS);
    Ok(0)
}

/// IopUnloadSafeCompletion(DeviceObject, Irp, Block) — corpo da rotina
/// privada: retém o dispositivo do bloco durante a rotina do driver; sem
/// gatilho propaga o pending e devolve STATUS_PENDING/STATUS_SUCCESS.
pub fn unload_safe_completion(device: u64, packet: u64, address: u64) -> Result<u32, KernelError> {
    // SAFETY: IRP em conclusão e o bloco que set_completion_routine_ex alocou.
    let (irp, block) = unsafe { (Irp::at(packet), UnloadSafeBlock::at(address)) };
    let status = irp.io_status.status.get();
    let selected = if status >= 0 { block.on_success.get() } else { block.on_error.get() };
    let invoke = selected != 0 || (irp.cancel.get() != 0 && block.on_cancel.get() != 0);
    if !invoke {
        let mut result = 0;
        if irp.pending_returned.get() != 0 {
            // IoMarkIrpPending.
            let current = current_location(irp);
            current.control.set(current.control.get() | SL_PENDING_RETURNED);
            result = STATUS_PENDING;
        }
        guest::free_bytes(address);
        return Ok(result);
    }
    let held = block.device.get();
    let referenced = held != 0 && device_objects::reference(held)?.is_some();
    let result = native_call::call(block.routine.get(), &[device, packet, block.context.get()]) as u32;
    guest::free_bytes(address);
    if referenced {
        device_objects::dereference(held)?;
    }
    Ok(result)
}

/// IoIsOperationSynchronous(Irp).
pub fn is_operation_synchronous(packet: u64) -> bool {
    // SAFETY: IRP vivo do chamador.
    let irp = unsafe { Irp::at(packet) };
    let flags = irp.flags.get();
    let file = current_location(irp).file_object.get();
    // SAFETY: FileObject da stack location corrente, vivo durante o IRP.
    let synchronous_file = file != 0 && unsafe { FileObject::at(file) }.flags.get() & FO_SYNCHRONOUS_IO != 0;
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
    // SAFETY: o IoGetRequestorProcess devolve um EPROCESS vivo ou NULL.
    Ok(if owner == 0 { 0 } else { unsafe { Eprocess::at(owner) }.unique_process_id.get() as u32 })
}

/// IoGetRequestorSessionId(Irp, SessionId): sem Tail.Overlay.Thread grava -1
/// e devolve STATUS_UNSUCCESSFUL; senão MmGetSessionIdEx do processo da
/// thread com -1 -> 0 (`ps::session::query` faz o mesmo mapeamento).
pub fn requestor_session_id(packet: u64, output: u64) -> u32 {
    // SAFETY: IRP vivo e PULONG SessionId do chamador de modo kernel.
    let (irp, session_id) = unsafe { (Irp::at(packet), Field::<u32>::at(output)) };
    let thread = irp.tail.overlay.thread.get();
    if thread == 0 {
        session_id.set(0xFFFF_FFFF);
        return STATUS_UNSUCCESSFUL;
    }
    // SAFETY: Tail.Overlay.Thread de um IRP vivo.
    let owner = unsafe { Kthread::at(thread) }.process.get();
    session_id.set(if owner == 0 { 0 } else { session::query(owner) });
    0
}

/// IoGetInitiatorProcess(FileObject): IopGetFileObjectExtension(Fo, 1) e o
/// processo iniciador em +8 do bloco; FILE_OBJECT sem extensão -> NULL.
pub fn initiator_process(file_object: u64) -> u64 {
    // SAFETY: FILE_OBJECT vivo do chamador.
    let extension = unsafe { FileObject::at(file_object) }.file_object_extension.get();
    if extension == 0 {
        return 0;
    }
    // SAFETY: FileObjectExtension aponta para a _IOP_FILE_OBJECT_EXTENSION.
    let block = unsafe { IopFileObjectExtension::at(extension) }.fo_ext_per_type_extension[INITIATOR_EXTENSION_SLOT].get();
    if block == 0 { 0 } else { guest::read64(block + INITIATOR_PROCESS) }
}
