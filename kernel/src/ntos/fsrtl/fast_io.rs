//! Suporte de Fast I/O do FsRtl, como no NT.
//!
//! * Contadores de leitura rápida do Cache Manager: campos da KPRCB
//!   (`CcFastReadNoWait`, `CcFastReadWait`, `CcFastReadNotPossible`,
//!   `CcFastMdlReadWait`, `CcFastReadResourceMiss`) incrementados por
//!   FsRtlIncrementCc* (`inc dword ptr gs:[x]` no NT; aqui atômico).
//! * MDL read / prepare MDL write "Ex" (FsRtlMdlReadEx 0x6a2f60,
//!   FsRtlPrepareMdlWriteEx 0x6a2e40): primeiro o caminho rápido do próprio
//!   file system (FAST_IO_DISPATCH.MdlRead / PrepareMdlWrite do driver do
//!   device relacionado, exigindo SizeOfFastIoDispatch maior que o offset do
//!   slot — FsRtlMdlRead 0x6a2fe0 / FsRtlPrepareMdlWrite 0x6a2ec0); se ele
//!   recusar, um IRP_MJ_READ/IRP_MJ_WRITE com IRP_MN_MDL construído por
//!   IoBuildAsynchronousFsdRequest e enviado com IoSynchronousCallDriver. O
//!   Cache Manager só é alcançado pelo file system (ex.: NtfsMdlReadA ->
//!   CcMdlRead), nunca daqui.

use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, IoStackLocation, IoStatusBlock, Irp, Kpcr, Kprcb};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::irp_request;
use crate::ntos::ke::pcr;
use crate::rtl::KernelError;

/// Contadores de leitura rápida da KPRCB.
#[derive(Clone, Copy)]
pub enum CacheCounter {
    FastReadNoWait,
    FastReadWait,
    FastReadNotPossible,
    FastMdlReadWait,
    FastReadResourceMiss,
}

const IRP_MJ_READ: u32 = 3;
const IRP_MJ_WRITE: u32 = 4;
const IRP_MN_MDL: u8 = 2;
const IRP_SYNCHRONOUS_API: u32 = 0x4;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

fn counter_field(prcb: &Kprcb, counter: CacheCounter) -> &Field<u32> {
    match counter {
        CacheCounter::FastReadNoWait => &prcb.cc_fast_read_no_wait,
        CacheCounter::FastReadWait => &prcb.cc_fast_read_wait,
        CacheCounter::FastReadNotPossible => &prcb.cc_fast_read_not_possible,
        CacheCounter::FastMdlReadWait => &prcb.cc_fast_mdl_read_wait,
        CacheCounter::FastReadResourceMiss => &prcb.cc_fast_read_resource_miss,
    }
}

/// FsRtlIncrementCc*: soma 1 ao contador da KPRCB do processador.
pub fn increment(counter: CacheCounter) {
    // SAFETY: a KPCR publicada em IA32_GS_BASE (KPRCB embutida).
    let prcb = &unsafe { Kpcr::at(pcr::get_pcr_address()) }.prcb;
    counter_field(prcb, counter).atomic().fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
enum MdlSlot {
    Read,
    PrepareWrite,
}

/// Device relacionado do FILE_OBJECT (IoGetRelatedDeviceObject).
fn related_device(file_object: &FileObject) -> Result<&'static DeviceObject, KernelError> {
    let device = invoke_handler("IoGetRelatedDeviceObject", &[file_object.address()])?;
    // SAFETY: device object vivo devolvido pelo I/O Manager.
    Ok(unsafe { DeviceObject::at(device) })
}

/// Rotina do FAST_IO_DISPATCH do driver dono do device, se a tabela for
/// grande o bastante para conter o slot.
fn fast_io_routine(device: &DeviceObject, slot: MdlSlot) -> u64 {
    // SAFETY: DriverObject de um device vivo.
    let driver = unsafe { DriverObject::at(device.driver_object.get()) };
    let dispatch = driver.fast_io_dispatch.get();
    if dispatch == 0 {
        return 0;
    }
    // SAFETY: tabela FAST_IO_DISPATCH registrada pelo driver.
    let table = unsafe { FastIoDispatch::at(dispatch) };
    let (offset, routine) = match slot {
        MdlSlot::Read => (offset_of!(FastIoDispatch, mdl_read), &table.mdl_read),
        MdlSlot::PrepareWrite => (offset_of!(FastIoDispatch, prepare_mdl_write), &table.prepare_mdl_write),
    };
    if table.size_of_fast_io_dispatch.get() as usize <= offset {
        return 0;
    }
    routine.get()
}

/// FsRtlMdlRead / FsRtlPrepareMdlWrite: FastIo(FileObject, FileOffset,
/// Length, LockKey, MdlChain, IoStatus, DeviceObject) -> BOOLEAN; FALSE sem
/// rotina.
fn fast_path(slot: MdlSlot, file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: &Field<u64>, io_status: &IoStatusBlock) -> Result<bool, KernelError> {
    let device = related_device(file_object)?;
    let routine = fast_io_routine(device, slot);
    if routine == 0 {
        return Ok(false);
    }
    let arguments = [file_object.address(), file_offset, length as u64, lock_key as u64, mdl_chain.address(), io_status.address(), device.address()];
    Ok(native_call::call(routine, &arguments) as u8 != 0)
}

/// IRP com IRP_MN_MDL enviado de forma síncrona ao device relacionado.
/// Devolve (status, IRP) — o IRP ainda precisa ser liberado — ou None sem
/// recursos.
fn send_mdl_irp(major: u32, file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32) -> Result<Option<(u32, &'static Irp)>, KernelError> {
    let device = related_device(file_object)?;
    let packet = irp_request::build_asynchronous_fsd_request(major, device.address(), 0, length, file_offset, 0)?;
    if packet == 0 {
        return Ok(None);
    }
    // SAFETY: IRP recém-alocado por IoBuildAsynchronousFsdRequest.
    let irp = unsafe { Irp::at(packet) };
    // IoGetNextIrpStackLocation: o elemento anterior ao corrente no vetor.
    // SAFETY: o vetor de stack locations do mesmo IRP.
    let next = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get() - IoStackLocation::SIZE) };
    next.file_object.set(file_object.address());
    next.minor_function.set(IRP_MN_MDL);
    next.parameters.read.key.set(lock_key);
    irp.flags.atomic().fetch_or(IRP_SYNCHRONOUS_API, Ordering::SeqCst);
    let status = irp_request::synchronous_call(device.address(), packet)?;
    Ok(Some((status, irp)))
}

fn copy_io_status(irp: &Irp, io_status: &IoStatusBlock) {
    io_status.status.set(irp.io_status.status.get());
    io_status.information.set(irp.io_status.information.get());
}

fn take_mdl_chain(irp: &Irp, mdl_chain: &Field<u64>) {
    mdl_chain.set(irp.mdl_address.get());
    irp.mdl_address.set(0);
}

/// FsRtlMdlReadEx(FileObject, FileOffset, Length, LockKey, MdlChain,
/// IoStatus) -> NTSTATUS. No caminho de IRP o IoStatus recebe sempre o do
/// IRP; a cadeia de MDL só é entregue em sucesso.
pub fn mdl_read_ex(file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: &Field<u64>, io_status: &IoStatusBlock) -> Result<u32, KernelError> {
    if fast_path(MdlSlot::Read, file_object, file_offset, length, lock_key, mdl_chain, io_status)? {
        return Ok(0);
    }
    let Some((status, irp)) = send_mdl_irp(IRP_MJ_READ, file_object, file_offset, length, lock_key)? else {
        io_status.status.set(STATUS_INSUFFICIENT_RESOURCES as i32);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    };
    copy_io_status(irp, io_status);
    if (status as i32) >= 0 {
        take_mdl_chain(irp, mdl_chain);
    }
    invoke_handler("IoFreeIrp", &[irp.address()])?;
    Ok(status)
}

/// FsRtlPrepareMdlWriteEx(FileObject, FileOffset, Length, LockKey,
/// MdlChain, IoStatus) -> NTSTATUS. Ao contrário da leitura, o IoStatus e a
/// cadeia só são escritos em sucesso (0x80df7d no NT).
pub fn prepare_mdl_write_ex(file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: &Field<u64>, io_status: &IoStatusBlock) -> Result<u32, KernelError> {
    if fast_path(MdlSlot::PrepareWrite, file_object, file_offset, length, lock_key, mdl_chain, io_status)? {
        return Ok(0);
    }
    let Some((status, irp)) = send_mdl_irp(IRP_MJ_WRITE, file_object, file_offset, length, lock_key)? else {
        io_status.status.set(STATUS_INSUFFICIENT_RESOURCES as i32);
        return Ok(STATUS_INSUFFICIENT_RESOURCES);
    };
    if (status as i32) >= 0 {
        take_mdl_chain(irp, mdl_chain);
        copy_io_status(irp, io_status);
    }
    invoke_handler("IoFreeIrp", &[irp.address()])?;
    Ok(status)
}

// ---- FsRtlMdlReadCompleteDev / FsRtlMdlWriteCompleteDev (fsrtl-volume-support) -----
//
// ntoskrnl 10.0.19045: FsRtlMdlReadCompleteDev 0x35ab40 = CcMdlReadComplete2 e
// TRUE; FsRtlMdlWriteCompleteDev 0x6a1510: FileObject->Flags & FO_WRITE_THROUGH
// (0x10) -> FALSE (o FS faz o caminho de IRP), senão CcMdlWriteComplete2 e
// TRUE. As versões "2" (sem voltar ao fast I/O do FS) são as rotinas do
// assunto do Cache Manager (`cc::mdl`), as mesmas dos exports Cc.

const FO_WRITE_THROUGH: u32 = 0x10;

/// FsRtlMdlReadCompleteDev(FileObject, MdlChain, DeviceObject) -> TRUE.
pub fn mdl_read_complete_dev(file_object: &FileObject, mdl_chain: u64) -> bool {
    crate::ntos::cc::mdl::mdl_read_complete(file_object.address(), mdl_chain);
    true
}

/// FsRtlMdlWriteCompleteDev(FileObject, FileOffset, MdlChain, DeviceObject) -> BOOLEAN.
/// `file_offset` é o PLARGE_INTEGER, repassado como o Cc o recebe.
pub fn mdl_write_complete_dev(file_object: &FileObject, file_offset: u64, mdl_chain: u64) -> Result<bool, KernelError> {
    if file_object.flags.get() & FO_WRITE_THROUGH != 0 {
        return Ok(false);
    }
    crate::ntos::cc::status::into_export(crate::ntos::cc::mdl::mdl_write_complete(file_object.address(), file_offset, mdl_chain).map(|()| 0))?;
    Ok(true)
}
