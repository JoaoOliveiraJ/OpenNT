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
//!   CcMdlRead), nunca daqui. FsRtlMdlRead e FsRtlMdlReadComplete são os
//!   caminhos rápidos sozinhos.
//! * Fast I/O genérico em cache (FsRtlCopyRead, FsRtlCopyWrite,
//!   FsRtlMdlReadDev, FsRtlPrepareMdlWriteDev): as rotinas que o file system
//!   põe no próprio FAST_IO_DISPATCH e que chamam o Cache Manager (seção no
//!   fim do arquivo).

use core::mem::offset_of;
use core::sync::atomic::Ordering;

use crate::hal::amd64::native_call;
use crate::ntos::cc::status::{CcResult, Failure};
use crate::ntos::cc::{cache_map, copy, flush, mdl};
use crate::ntos::ex::resource;
use crate::ntos::fsrtl::ntstatus;
use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, IoStackLocation, IoStatusBlock, Irp, Kpcr, Kprcb, LargeInteger};
use crate::ntos::init::exports::invoke_handler;
use crate::ntos::io::irp_request;
use crate::ntos::io::threads::top_level_irp;
use crate::ntos::ke::{critical_region, pcr};
use crate::ntos::mm::guest_memory as guest;
use crate::rtl::KernelError;

/// Contadores de leitura rápida da KPRCB.
#[derive(Clone, Copy)]
pub enum CacheCounter {
    FastReadNoWait,
    FastReadWait,
    FastReadNotPossible,
    FastMdlReadWait,
    FastReadResourceMiss,
    /// KPRCB.CcFastMdlReadNotPossible (sem export FsRtlIncrement*; o
    /// FsRtlMdlReadDev o soma direto).
    FastMdlReadNotPossible,
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
        CacheCounter::FastMdlReadNotPossible => &prcb.cc_fast_mdl_read_not_possible,
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
    ReadComplete,
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
        MdlSlot::ReadComplete => (offset_of!(FastIoDispatch, mdl_read_complete), &table.mdl_read_complete),
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

// ---- Fast I/O genérico em cache --------------------------------------------------
//
// ntoskrnl 10.0.19041: FsRtlCopyRead 0x88a580, FsRtlCopyWrite 0x88a800,
// FsRtlMdlReadDev 0x88afc0, FsRtlPrepareMdlWriteDev 0x88b220; FsRtlMdlRead
// 0x6a2fe0 e FsRtlMdlReadComplete 0x4eede0 só repassam ao FAST_IO_DISPATCH do
// device relacionado (MdlRead em +0x80, MdlReadComplete em +0x88). As quatro
// primeiras são as rotinas de Fast I/O que um file system põe direto no seu
// FAST_IO_DISPATCH: o FsContext do FILE_OBJECT começa com o
// FSRTL_COMMON_FCB_HEADER, o Header->Resource é tomado (compartilhado; na
// escrita, exclusivo quando o arquivo cresce ou o destino é o fim do
// arquivo), IsFastIoPossible decide (Questionable pergunta ao
// FastIoCheckIfPossible do driver do DeviceObject recebido), o
// ETHREAD.TopLevelIrp fica em FSRTL_FAST_IO_TOP_LEVEL_IRP durante a chamada
// ao Cache Manager e uma exceção dele com status esperado
// (FsRtlIsNtstatusExpected) vira FALSE; a inesperada continua subindo, como
// no filtro do NT.

const FAST_IO_TOP_LEVEL_IRP: u64 = 4;
const FAST_IO_IS_NOT_POSSIBLE: u8 = 0;
const FAST_IO_IS_QUESTIONABLE: u8 = 2;
const FO_FILE_MODIFIED: u32 = 0x1000;
const FO_FILE_SIZE_CHANGED: u32 = 0x2000;
const FO_FILE_FAST_IO_READ: u32 = 0x8_0000;
const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
/// FILE_WRITE_TO_END_OF_FILE: LowPart e HighPart 0xFFFFFFFF.
const WRITE_TO_END_OF_FILE: i64 = -1;

fn header_of(file_object: &FileObject) -> &'static FsrtlCommonFcbHeader {
    // SAFETY: o FsContext de um arquivo em cache começa com o
    // FSRTL_COMMON_FCB_HEADER (contrato do Fast I/O genérico do NT).
    unsafe { FsrtlCommonFcbHeader::at(file_object.fs_context.get()) }
}

fn large_integer(pointer: u64) -> &'static LargeInteger {
    // SAFETY: PLARGE_INTEGER do file system (memória de kernel).
    unsafe { LargeInteger::at(pointer) }
}

fn set_io_status(io_status: &IoStatusBlock, status: u32, information: u64) {
    io_status.status.set(status as i32);
    io_status.information.set(information);
}

/// FsRtlEnterFileSystem / FsRtlExitFileSystem.
fn enter_file_system() -> Result<(), KernelError> {
    critical_region::enter_critical()
}

fn exit_file_system() -> Result<(), KernelError> {
    critical_region::leave_critical()
}

fn release_and_exit(header: &FsrtlCommonFcbHeader) -> Result<(), KernelError> {
    resource::release(header.resource.get())?;
    exit_file_system()
}

/// DeviceObject->DriverObject->FastIoDispatch->FastIoCheckIfPossible(FileObject,
/// FileOffset, Length, Wait, LockKey, CheckForReadOperation, IoStatus,
/// DeviceObject). O NT segue os ponteiros sem conferir: um FS que marca
/// FastIoIsQuestionable tem a rotina.
#[allow(clippy::too_many_arguments)]
fn check_if_possible(device: &DeviceObject, file_object: &FileObject, file_offset: u64, length: u32, wait: bool, lock_key: u32, check_for_read: bool, io_status: u64) -> Result<bool, KernelError> {
    // SAFETY: DriverObject do DeviceObject que o I/O Manager passou ao FS.
    let driver = unsafe { DriverObject::at(device.driver_object.get()) };
    let dispatch = driver.fast_io_dispatch.get();
    if dispatch == 0 {
        return Err(KernelError::new("FastIoIsQuestionable without a FAST_IO_DISPATCH"));
    }
    // SAFETY: FAST_IO_DISPATCH registrado pelo driver.
    let routine = unsafe { FastIoDispatch::at(dispatch) }.fast_io_check_if_possible.get();
    if routine == 0 {
        return Err(KernelError::new("FastIoIsQuestionable without FastIoCheckIfPossible"));
    }
    let arguments = [file_object.address(), file_offset, length as u64, wait as u64, lock_key as u64, check_for_read as u64, io_status, device.address()];
    Ok(native_call::call(routine, &arguments) as u8 != 0)
}

/// O `__except` do NT em volta da chamada ao Cc: `None` quando ele captura
/// (status esperado: o resto do bloco `try` não roda e o resultado é FALSE);
/// o status inesperado continua subindo ao chamador.
fn cache_outcome<T>(result: CcResult<T>) -> Result<Option<T>, KernelError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Failure::Raise(code)) if ntstatus::is_ntstatus_expected(code) => Ok(None),
        Err(Failure::Raise(code)) => crate::ntos::rtl::exceptions::raise_status(code, 0, 0, 1).map(|_| None),
        Err(Failure::Kernel(error)) => Err(error),
    }
}

/// CcCanIWrite fora de qualquer `try`: uma exceção sobe ao chamador.
fn can_i_write(file_object: &FileObject, length: u32, wait: bool) -> Result<bool, KernelError> {
    Ok(crate::ntos::cc::status::into_export(copy::can_i_write(file_object.address(), length, wait, 0).map(|answer| answer as u64))? != 0)
}

/// Resultado da checagem de leitura rápida, com o recurso tomado.
enum ReadPlan {
    /// Fast I/O impossível.
    NotPossible,
    /// O início já passa do fim: IoStatus = STATUS_END_OF_FILE e TRUE.
    EndOfFile,
    /// Ler `length` bytes (aparado ao FileSize).
    Read(u32),
}

/// O que FsRtlCopyRead e FsRtlMdlReadDev decidem depois de tomar o recurso.
#[allow(clippy::too_many_arguments)]
fn read_plan(header: &FsrtlCommonFcbHeader, file_object: &FileObject, file_offset: u64, length: u32, wait: bool, lock_key: u32, io_status: &IoStatusBlock, device: &DeviceObject) -> Result<ReadPlan, KernelError> {
    let possible = header.is_fast_io_possible.get();
    if file_object.private_cache_map.get() == 0 || possible == FAST_IO_IS_NOT_POSSIBLE {
        return Ok(ReadPlan::NotPossible);
    }
    if possible == FAST_IO_IS_QUESTIONABLE && !check_if_possible(device, file_object, file_offset, length, wait, lock_key, true, io_status.address())? {
        return Ok(ReadPlan::NotPossible);
    }
    let offset = large_integer(file_offset).quad_part.get();
    let beyond = offset.wrapping_add(length as i64);
    let file_size = header.file_size.quad_part.get();
    if beyond > file_size {
        if offset >= file_size {
            set_io_status(io_status, STATUS_END_OF_FILE, 0);
            return Ok(ReadPlan::EndOfFile);
        }
        return Ok(ReadPlan::Read((file_size - offset) as u32));
    }
    Ok(ReadPlan::Read(length))
}

/// FsRtlCopyRead(FileObject, FileOffset, Length, Wait, LockKey, Buffer,
/// IoStatus, DeviceObject) -> BOOLEAN.
#[allow(clippy::too_many_arguments)]
pub fn copy_read(file_object: &FileObject, file_offset: u64, length: u32, wait: bool, lock_key: u32, buffer: u64, io_status: &IoStatusBlock, device: &DeviceObject) -> Result<bool, KernelError> {
    if top_level_irp::get() != 0 {
        return Ok(false);
    }
    if length == 0 {
        set_io_status(io_status, 0, 0);
        return Ok(true);
    }
    if i64::MAX - large_integer(file_offset).quad_part.get() < length as i64 {
        set_io_status(io_status, STATUS_INVALID_PARAMETER, 0);
        return Ok(false);
    }
    let header = header_of(file_object);
    enter_file_system()?;
    increment(if wait { CacheCounter::FastReadWait } else { CacheCounter::FastReadNoWait });
    if resource::acquire_shared(header.resource.get(), wait)? == 0 {
        exit_file_system()?;
        increment(CacheCounter::FastReadResourceMiss);
        return Ok(false);
    }
    let length = match read_plan(header, file_object, file_offset, length, wait, lock_key, io_status, device)? {
        ReadPlan::NotPossible => {
            release_and_exit(header)?;
            increment(CacheCounter::FastReadNotPossible);
            return Ok(false);
        }
        ReadPlan::EndOfFile => {
            release_and_exit(header)?;
            return Ok(true);
        }
        ReadPlan::Read(length) => length,
    };
    top_level_irp::set(FAST_IO_TOP_LEVEL_IRP);
    let outcome = cache_outcome(copy::copy_read(file_object.address(), file_offset, length, wait, buffer, io_status.address()));
    let copied = match outcome {
        Ok(Some(copied)) => {
            file_object.flags.atomic().fetch_or(FO_FILE_FAST_IO_READ, Ordering::SeqCst);
            if copied {
                file_object.current_byte_offset.quad_part.set(large_integer(file_offset).quad_part.get().wrapping_add(io_status.information.get() as i64));
            }
            copied
        }
        Ok(None) => false,
        Err(error) => {
            top_level_irp::set(0);
            return Err(error);
        }
    };
    top_level_irp::set(0);
    release_and_exit(header)?;
    Ok(copied)
}

/// FsRtlMdlReadDev(FileObject, FileOffset, Length, LockKey, MdlChain,
/// IoStatus, DeviceObject) -> BOOLEAN. Sempre espera pelo recurso.
#[allow(clippy::too_many_arguments)]
pub fn mdl_read_dev(file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: u64, io_status: &IoStatusBlock, device: &DeviceObject) -> Result<bool, KernelError> {
    if top_level_irp::get() != 0 {
        return Ok(false);
    }
    if length == 0 {
        set_io_status(io_status, 0, 0);
        return Ok(true);
    }
    let header = header_of(file_object);
    enter_file_system()?;
    increment(CacheCounter::FastMdlReadWait);
    resource::acquire_shared(header.resource.get(), true)?;
    let length = match read_plan(header, file_object, file_offset, length, true, lock_key, io_status, device)? {
        ReadPlan::NotPossible => {
            release_and_exit(header)?;
            increment(CacheCounter::FastMdlReadNotPossible);
            return Ok(false);
        }
        ReadPlan::EndOfFile => {
            release_and_exit(header)?;
            return Ok(true);
        }
        ReadPlan::Read(length) => length,
    };
    top_level_irp::set(FAST_IO_TOP_LEVEL_IRP);
    let read = match cache_outcome(mdl::mdl_read(file_object.address(), file_offset, length, mdl_chain, io_status.address())) {
        Ok(Some(())) => {
            file_object.flags.atomic().fetch_or(FO_FILE_FAST_IO_READ, Ordering::SeqCst);
            true
        }
        Ok(None) => false,
        Err(error) => {
            top_level_irp::set(0);
            return Err(error);
        }
    };
    top_level_irp::set(0);
    release_and_exit(header)?;
    Ok(read)
}

/// Como a escrita rápida chega ao Cache Manager.
#[derive(Clone, Copy)]
enum WriteKind {
    /// FsRtlCopyWrite: CcCopyWrite com o buffer do chamador.
    Copy { wait: bool, buffer: u64 },
    /// FsRtlPrepareMdlWriteDev: CcPrepareMdlWrite, sempre esperando.
    Mdl { chain: u64 },
}

impl WriteKind {
    fn wait(self) -> bool {
        match self {
            WriteKind::Copy { wait, .. } => wait,
            WriteKind::Mdl { .. } => true,
        }
    }
}

/// Grava um tamanho do cabeçalho (FileSize ou ValidDataLength). Se a parte
/// alta muda e há PagingIoResource, a gravação é feita com ele exclusivo,
/// como no NT (quem pagina nunca vê metade de um LARGE_INTEGER).
fn set_header_size(header: &FsrtlCommonFcbHeader, field: &LargeInteger, value: i64) -> Result<(), KernelError> {
    let paging = header.paging_io_resource.get();
    if field.high_part.get() != (value >> 32) as i32 && paging != 0 {
        resource::acquire_exclusive(paging, true)?;
        field.quad_part.set(value);
        resource::release(paging)?;
    } else {
        field.quad_part.set(value);
    }
    Ok(())
}

/// Desfaz o crescimento de FileSize/ValidDataLength de uma escrita que falhou.
fn restore_sizes(header: &FsrtlCommonFcbHeader, file_size: i64, valid_data_length: i64) -> Result<(), KernelError> {
    let paging = header.paging_io_resource.get();
    if paging != 0 {
        resource::acquire_exclusive(paging, true)?;
    }
    header.file_size.quad_part.set(file_size);
    header.valid_data_length.quad_part.set(valid_data_length);
    if paging != 0 {
        resource::release(paging)?;
    }
    Ok(())
}

/// Corpo comum de FsRtlCopyWrite e FsRtlPrepareMdlWriteDev, a partir do
/// FsRtlEnterFileSystem.
#[allow(clippy::too_many_arguments)]
fn cached_write(header: &FsrtlCommonFcbHeader, file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, io_status: &IoStatusBlock, device: &DeviceObject, kind: WriteKind) -> Result<bool, KernelError> {
    let wait = kind.wait();
    let requested = large_integer(file_offset).quad_part.get();
    let to_end = requested == WRITE_TO_END_OF_FILE;
    let resource_address = header.resource.get();
    let shared = !to_end && requested.wrapping_add(length as i64) <= header.valid_data_length.quad_part.get();
    let acquired = if shared { resource::acquire_shared(resource_address, wait)? } else { resource::acquire_exclusive(resource_address, wait)? };
    if acquired == 0 {
        exit_file_system()?;
        return Ok(false);
    }
    let start = |header: &FsrtlCommonFcbHeader| if to_end { header.file_size.quad_part.get() } else { requested };
    let possible = |header: &FsrtlCommonFcbHeader| file_object.private_cache_map.get() != 0 && header.is_fast_io_possible.get() != FAST_IO_IS_NOT_POSSIBLE;
    let mut offset = start(header);
    let mut new_file_size = offset.wrapping_add(length as i64);
    let near_valid_data = match kind {
        WriteKind::Copy { .. } => offset < header.valid_data_length.quad_part.get().wrapping_add(0x2000),
        WriteKind::Mdl { .. } => true,
    };
    if !(possible(header) && near_valid_data && i64::MAX - offset >= length as i64 && new_file_size <= header.allocation_size.quad_part.get()) {
        release_and_exit(header)?;
        return Ok(false);
    }
    if shared && new_file_size > header.valid_data_length.quad_part.get() {
        resource::release(resource_address)?;
        if resource::acquire_exclusive(resource_address, wait)? == 0 {
            exit_file_system()?;
            return Ok(false);
        }
        if to_end {
            offset = start(header);
            new_file_size = offset.wrapping_add(length as i64);
        }
        if !(possible(header) && new_file_size <= header.allocation_size.quad_part.get()) {
            release_and_exit(header)?;
            return Ok(false);
        }
    }
    if header.is_fast_io_possible.get() == FAST_IO_IS_QUESTIONABLE {
        let questionable = match kind {
            WriteKind::Copy { .. } => {
                // O NT pergunta com um IO_STATUS_BLOCK local e, para o fim do
                // arquivo, com &Header->FileSize no lugar do -1.
                let local = guest::alloc_bytes(IoStatusBlock::SIZE);
                let pointer = if requested == WRITE_TO_END_OF_FILE { header.file_size.address() } else { file_offset };
                let answer = check_if_possible(device, file_object, pointer, length, wait, lock_key, false, local);
                guest::free_bytes(local);
                answer?
            }
            WriteKind::Mdl { .. } => check_if_possible(device, file_object, file_offset, length, true, lock_key, false, io_status.address())?,
        };
        if !questionable {
            release_and_exit(header)?;
            return Ok(false);
        }
    }
    let old_file_size = header.file_size.quad_part.get();
    let old_valid_data_length = header.valid_data_length.quad_part.get();
    let size_changed = new_file_size > old_file_size;
    if size_changed {
        set_header_size(header, &header.file_size, new_file_size)?;
    }
    // O LARGE_INTEGER local com o início da escrita que o NT passa ao Cc.
    let local_offset = guest::alloc_bytes(LargeInteger::SIZE);
    large_integer(local_offset).quad_part.set(offset);
    top_level_irp::set(FAST_IO_TOP_LEVEL_IRP);
    let outcome = (|| -> Result<bool, KernelError> {
        if offset > header.valid_data_length.quad_part.get() && cache_outcome(flush::zero_data(file_object.address(), header.valid_data_length.address(), local_offset, wait))? != Some(true) {
            return Ok(false);
        }
        let written = match kind {
            WriteKind::Copy { wait, buffer } => cache_outcome(copy::copy_write(file_object.address(), local_offset, length, wait, buffer))?,
            WriteKind::Mdl { chain } => cache_outcome(mdl::prepare_mdl_write(file_object.address(), local_offset, length, chain, io_status.address()).map(|()| true))?,
        };
        Ok(written == Some(true))
    })();
    guest::free_bytes(local_offset);
    top_level_irp::set(0);
    let done = outcome?;
    if done {
        if new_file_size > header.valid_data_length.quad_part.get() {
            set_header_size(header, &header.valid_data_length, new_file_size)?;
        }
        file_object.flags.atomic().fetch_or(FO_FILE_MODIFIED, Ordering::SeqCst);
        if size_changed {
            cache_map::set_file_size_field(file_object.address(), new_file_size as u64);
            file_object.flags.atomic().fetch_or(FO_FILE_SIZE_CHANGED, Ordering::SeqCst);
        }
        if let WriteKind::Copy { .. } = kind {
            file_object.current_byte_offset.quad_part.set(offset.wrapping_add(length as i64));
        }
    } else if size_changed {
        restore_sizes(header, old_file_size, old_valid_data_length)?;
    }
    release_and_exit(header)?;
    Ok(done)
}

/// FsRtlCopyWrite(FileObject, FileOffset, Length, Wait, LockKey, Buffer,
/// IoStatus, DeviceObject) -> BOOLEAN.
#[allow(clippy::too_many_arguments)]
pub fn copy_write(file_object: &FileObject, file_offset: u64, length: u32, wait: bool, lock_key: u32, buffer: u64, io_status: &IoStatusBlock, device: &DeviceObject) -> Result<bool, KernelError> {
    if top_level_irp::get() != 0 {
        return Ok(false);
    }
    if !can_i_write(file_object, length, wait)? {
        return Ok(false);
    }
    if file_object.flags.get() & FO_WRITE_THROUGH != 0 || !copy::copy_write_wont_flush(file_object.address(), file_offset, length) {
        return Ok(false);
    }
    set_io_status(io_status, 0, length as u64);
    if length == 0 {
        return Ok(true);
    }
    let header = header_of(file_object);
    enter_file_system()?;
    cached_write(header, file_object, file_offset, length, lock_key, io_status, device, WriteKind::Copy { wait, buffer })
}

/// FsRtlPrepareMdlWriteDev(FileObject, FileOffset, Length, LockKey,
/// MdlChain, IoStatus, DeviceObject) -> BOOLEAN.
#[allow(clippy::too_many_arguments)]
pub fn prepare_mdl_write_dev(file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: u64, io_status: &IoStatusBlock, device: &DeviceObject) -> Result<bool, KernelError> {
    if top_level_irp::get() != 0 {
        return Ok(false);
    }
    if !can_i_write(file_object, length, true)? || file_object.flags.get() & FO_WRITE_THROUGH != 0 {
        return Ok(false);
    }
    io_status.status.set(0);
    if length == 0 {
        return Ok(true);
    }
    let header = header_of(file_object);
    enter_file_system()?;
    cached_write(header, file_object, file_offset, length, lock_key, io_status, device, WriteKind::Mdl { chain: mdl_chain })
}

/// FsRtlMdlRead(FileObject, FileOffset, Length, LockKey, MdlChain, IoStatus)
/// -> BOOLEAN: o MdlRead do FAST_IO_DISPATCH do device relacionado (exigindo
/// SizeOfFastIoDispatch > 0x80), FALSE sem ele.
pub fn mdl_read(file_object: &FileObject, file_offset: u64, length: u32, lock_key: u32, mdl_chain: &Field<u64>, io_status: &IoStatusBlock) -> Result<bool, KernelError> {
    fast_path(MdlSlot::Read, file_object, file_offset, length, lock_key, mdl_chain, io_status)
}

/// FsRtlMdlReadComplete(FileObject, MdlChain) -> BOOLEAN: o MdlReadComplete
/// do FAST_IO_DISPATCH do device relacionado (exigindo
/// SizeOfFastIoDispatch > 0x88), FALSE sem ele.
pub fn mdl_read_complete(file_object: &FileObject, mdl_chain: u64) -> Result<bool, KernelError> {
    let device = related_device(file_object)?;
    let routine = fast_io_routine(device, MdlSlot::ReadComplete);
    if routine == 0 {
        return Ok(false);
    }
    Ok(native_call::call(routine, &[file_object.address(), mdl_chain, device.address()]) as u8 != 0)
}
