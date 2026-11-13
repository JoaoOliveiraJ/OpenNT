//! I/O de paginação do I/O Manager — IoPageRead
//! (RVA 0x37f0a0 -> IoPageReadEx 0x29c7c0), IoSynchronousPageWrite (RVA
//! 0x31b920 -> IoSynchronousPageWriteEx 0x29c49c) e o ramo IRP_PAGING_IO do
//! IopfCompleteRequest (0x24322e..0x24329c).
//!
//! O IRP leva o MDL do chamador (o Mm, o LFS do NTFS), Flags
//! IRP_NOCACHE|IRP_PAGING_IO|IRP_SYNCHRONOUS_PAGING_IO (0x43; a leitura com o
//! bit 0 do ponteiro do MDL usa 0x403) mais a prioridade de I/O da thread em
//! Flags bits 17..19, UserBuffer = StartVa + ByteOffset do MDL e
//! IoStatusBlock->Information = o próprio IRP antes do IofCallDriver. Na
//! conclusão o NT copia o IO_STATUS_BLOCK inteiro para UserIosb, sinaliza
//! UserEvent e libera o IRP (o MDL é do Mm).
//!
//! Diferenças declaradas: os IRPs de reserva/"backpocket" do NT para falta de
//! memória não existem (sem IRP -> STATUS_INSUFFICIENT_RESOURCES, o mesmo
//! status do NT quando eles também faltam); o IRP não entra na lista de IRPs
//! da thread (IopQueueThreadIrp) nem ganha a extensão de atribuição de disco,
//! que o OpenNT não consome. Outros construtores do OpenNT (por exemplo o
//! FsRtlGetFileSize do `file::information`) usam Flags de paginação e liberam
//! o próprio IRP, então a liberação na conclusão vale só para os IRPs criados
//! aqui (conjunto `PAGING_IRPS`).

use alloc::collections::BTreeSet;

use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension;
use crate::ntos::inc::types::extra_io::IrpExtensionField;
use crate::ntos::inc::types::{DeviceObject, Ethread, FileObject, IoStackLocation, IoStatusBlock, Irp, LargeInteger, Mdl};
use crate::ntos::io::{file::information, io_manager, irp_builder, irp_request};
use crate::ntos::ke::dispatcher;
use crate::ntos::ps::process;
use crate::rtl::{KernelError, SpinLock};

pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

const IRP_PAGING_IO: u32 = 0x02;
const IRP_SYNCHRONOUS_PAGING_IO: u32 = 0x40;
const IRP_CLOSE_OPERATION: u32 = 0x400;
/// NOCACHE | PAGING_IO | SYNCHRONOUS_PAGING_IO.
const PAGING_FLAGS: u32 = 0x43;
/// NOCACHE | PAGING_IO | 0x400 (leitura pedida com o bit 0 do MDL).
const PAGING_READ_ALTERNATE_FLAGS: u32 = 0x403;
const IRP_MJ_READ: u8 = 3;
const IRP_MJ_WRITE: u8 = 4;
const IRP_ALLOCATION_MUST_COMPLETE: u8 = 0x20;
/// IopDriverFlagsType: o bit no TypesAllocated e o valor gravado em DriverFlags.
const DRIVER_FLAGS_TYPE: u16 = 1 << 8;
const DRIVER_FLAGS_TAGGED_READ: u64 = 1 << 32;
const MDL_IO_PAGE_READ: i16 = 0x40;
const IO_PRIORITY_NORMAL: u32 = 2;
const IO_PRIORITY_HIGH: u32 = 3;
const IRP_PRIORITY_SHIFT: u32 = 17;
const FSRTL_FSP_TOP_LEVEL_IRP: u64 = 2;
const USER_MODE: i8 = 1;
// Bits do pedido de leitura (o IoPageReadEx recebe do IoPageRead).
const READ_FILE_TAG_ONE: u32 = 0x1;
const READ_FILE_TAG_TWO: u32 = 0x2;
const READ_MDL_TAG_ONE: u32 = 0x4;
const READ_MDL_TAG_TWO: u32 = 0x8;

/// IRPs desta unidade ainda não concluídos.
static PAGING_IRPS: SpinLock<BTreeSet<u64>> = SpinLock::new(BTreeSet::new());

fn current_thread() -> &'static Ethread {
    // SAFETY: a ETHREAD corrente está viva enquanto ela executa.
    unsafe { Ethread::at(process::get_current_thread()) }
}

/// Prioridade da leitura: uma thread de prioridade baixa sobe a Normal
/// (IoPagingReadLowPriorityBumpedCount), salvo pedido "file tag 2", leitura
/// marcada com o bit 0 do FileObject ou thread em prefetch; o bit 1 do MDL
/// eleva Normal a High.
fn read_priority(thread: &Ethread, request: u32) -> u32 {
    let mut priority = irp_request::io_priority(thread.address());
    if priority < IO_PRIORITY_NORMAL && request & (READ_FILE_TAG_ONE | READ_FILE_TAG_TWO) == 0 && thread.prefetching() == 0 {
        priority = IO_PRIORITY_NORMAL;
    }
    if request & READ_MDL_TAG_TWO != 0 && priority == IO_PRIORITY_NORMAL {
        priority = IO_PRIORITY_HIGH;
    }
    priority
}

/// Prioridade da escrita: sobe a Normal salvo thread de sistema, modo
/// anterior usuário, prefetch ou TopLevelIrp == FSRTL_FSP_TOP_LEVEL_IRP.
fn write_priority(thread: &Ethread) -> u32 {
    let priority = irp_request::io_priority(thread.address());
    let keep = thread.tcb.system_thread() != 0 || thread.tcb.previous_mode.get() == USER_MODE || thread.prefetching() != 0 || thread.top_level_irp.get() == FSRTL_FSP_TOP_LEVEL_IRP;
    if priority < IO_PRIORITY_NORMAL && !keep { IO_PRIORITY_NORMAL } else { priority }
}

/// O pedido de paginação: arquivo, MDL, deslocamento e o par evento/IOSB do chamador.
pub struct PagingRequest<'a> {
    pub file: &'a FileObject,
    pub descriptor: &'a Mdl,
    pub offset: &'a LargeInteger,
    pub event: u64,
    pub io_status: &'a IoStatusBlock,
}

/// Campos comuns do IRP de paginação e da próxima stack location.
fn fill(irp: &Irp, request: &PagingRequest<'_>, flags: u32, major: u8) {
    irp.mdl_address.set(request.descriptor.address());
    irp.flags.set(flags);
    irp.requestor_mode.set(0);
    irp.user_event.set(request.event);
    irp.user_iosb.set(request.io_status.address());
    irp.user_buffer.set(request.descriptor.start_va.get().wrapping_add(request.descriptor.byte_offset.get() as u64));
    irp.tail.overlay.original_file_object.set(request.file.address());
    irp.tail.overlay.thread.set(process::get_current_thread());
    // SAFETY: a stack location abaixo da corrente pertence ao IRP recém-alocado.
    let next = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    next.major_function.set(major);
    next.file_object.set(request.file.address());
    // Parameters.Read e Parameters.Write têm o mesmo layout.
    next.parameters.read.length.set(request.descriptor.byte_count.get());
    next.parameters.read.byte_offset.quad_part.set(request.offset.quad_part.get());
}

fn dispatch(device: u64, packet: u64) -> u32 {
    PAGING_IRPS.lock().insert(packet);
    io_manager::iof_call_driver(device, packet) as u32
}

fn device_stack_size(device: u64) -> u8 {
    // SAFETY: o dispositivo relacionado de um FILE_OBJECT vivo.
    unsafe { DeviceObject::at(device) }.stack_size.get() as u8
}

/// IoPageRead(FileObject, MemoryDescriptorList, StartingOffset, Event,
/// IoStatusBlock): os dois bits baixos do FileObject e do MDL são marcas do
/// Mm, convertidas nas flags do IoPageReadEx (o adaptador já limpou os
/// ponteiros e passa as marcas em `tags`).
pub fn page_read(request: &PagingRequest<'_>, file_tags: u64, descriptor_tags: u64) -> Result<u32, KernelError> {
    let mut tags = 0;
    if file_tags != 0 {
        tags = if file_tags & 1 != 0 { READ_FILE_TAG_ONE } else { READ_FILE_TAG_TWO };
    }
    if descriptor_tags & 1 != 0 {
        tags |= READ_MDL_TAG_ONE;
    }
    if descriptor_tags & 2 != 0 {
        tags |= READ_MDL_TAG_TWO;
    }
    let device = information::related_device(request.file.address())?;
    let flags = if tags & READ_MDL_TAG_ONE != 0 { PAGING_READ_ALTERNATE_FLAGS } else { PAGING_FLAGS };
    // Leitura marcada (bit 0 do FileObject) reserva a extensão embutida (DeviceObject -1).
    let target = if tags & READ_FILE_TAG_ONE != 0 { u64::MAX } else { device };
    let packet = irp_request::allocate_irp_ex(target, device_stack_size(device), false);
    if packet == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: IRP recém-alocado.
    let irp = unsafe { Irp::at(packet) };
    if request.descriptor.mdl_flags.get() & MDL_IO_PAGE_READ != 0 && flags & IRP_SYNCHRONOUS_PAGING_IO != 0 {
        irp.allocation_flags.set(irp.allocation_flags.get() | IRP_ALLOCATION_MUST_COMPLETE);
    }
    let priority = read_priority(current_thread(), tags);
    fill(irp, request, flags | ((priority << IRP_PRIORITY_SHIFT) + (1 << IRP_PRIORITY_SHIFT)), IRP_MJ_READ);
    if tags & READ_FILE_TAG_ONE != 0 {
        // IopSetDriverFlagsExtension(Irp, 1 << 32) na extensão reservada pelo allocate_irp_ex(-1).
        // SAFETY: IrpExtension aponta para as duas stack locations reservadas.
        let extension = unsafe { IopIrpExtension::at(irp.irp_extension().get()) };
        extension.types_allocated.set(extension.types_allocated.get() | DRIVER_FLAGS_TYPE);
        extension.driver_flags.set(extension.driver_flags.get() | DRIVER_FLAGS_TAGGED_READ);
    }
    request.io_status.information.set(packet);
    Ok(dispatch(device, packet))
}

/// IoSynchronousPageWrite(FileObject, MemoryDescriptorList, StartingOffset,
/// Event, IoStatusBlock) = IoSynchronousPageWriteEx(..., 0, NULL).
pub fn synchronous_page_write(request: &PagingRequest<'_>) -> Result<u32, KernelError> {
    let device = information::related_device(request.file.address())?;
    let packet = irp_request::allocate_irp_ex(device, device_stack_size(device), false);
    if packet == 0 {
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: IRP recém-alocado.
    let irp = unsafe { Irp::at(packet) };
    irp.allocation_flags.set(irp.allocation_flags.get() | IRP_ALLOCATION_MUST_COMPLETE);
    let priority = write_priority(current_thread());
    fill(irp, request, PAGING_FLAGS | ((priority << IRP_PRIORITY_SHIFT) + (1 << IRP_PRIORITY_SHIFT)), IRP_MJ_WRITE);
    request.io_status.information.set(packet);
    Ok(dispatch(device, packet))
}

/// Ramo IRP_PAGING_IO/IRP_CLOSE_OPERATION síncrono do IopfCompleteRequest,
/// depois das rotinas de conclusão: `true` = o IRP era desta unidade e foi
/// concluído (UserIosb inteiro, UserEvent e IoFreeIrp); `false` = segue a
/// conclusão normal do OpenNT.
pub fn complete_paging_request(packet: u64) -> bool {
    // SAFETY: o IofCompleteRequest recebe um IRP vivo.
    let irp = unsafe { Irp::at(packet) };
    let flags = irp.flags.get();
    if flags & (IRP_PAGING_IO | IRP_CLOSE_OPERATION) == 0 || flags & (IRP_SYNCHRONOUS_PAGING_IO | IRP_CLOSE_OPERATION) == 0 {
        return false;
    }
    if !PAGING_IRPS.lock().remove(&packet) {
        return false;
    }
    // SAFETY: UserIosb do Mm/LFS (memória de kernel), gravado no IoPageRead/IoSynchronousPageWrite.
    let io_status = unsafe { IoStatusBlock::at(irp.user_iosb.get()) };
    io_status.status.set(irp.io_status.status.get());
    io_status.information.set(irp.io_status.information.get());
    let event = irp.user_event.get();
    if event != 0 {
        dispatcher::set_event(event);
    }
    if flags & (IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO) != 0 {
        irp_builder::free_irp(packet);
    }
    true
}
