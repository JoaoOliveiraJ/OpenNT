//! Autotestes (fase 6) do suporte FsRtl que os file systems reais importam:
//! o Fast I/O genérico em cache (FsRtlCopyRead/CopyWrite, MdlReadDev,
//! PrepareMdlWriteDev, MdlRead, MdlReadComplete) sobre o arquivo sintético do
//! Cache Manager (`cc_fixture`) com um FSRTL_COMMON_FCB_HEADER; os eventos de
//! volume (FsRtlNotifyVolumeEvent(Ex)) por um PDO relatado; FsRtlBalanceReads
//! e FsRtlGetSectorSizeInformation contra um disco sintético que responde os
//! IOCTLs; FsRtlCheckOplockForFsFilterCallback; FsRtlNotifyFilterReportChange
//! e a variante Lite da notificação de diretório. Cada export é chamado pelo
//! nome, e os valores esperados seguem as rotinas do ntoskrnl 19041.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);
type CallExport = fn(&str, &[u64]) -> Option<u64>;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
const STATUS_NOTIFY_ENUM_DIR: u32 = 0x10C;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo próprio teste com o tamanho do tipo ou
    // objetos vivos do kernel.
    unsafe { T::at(address) }
}

fn status(value: Option<u64>) -> u32 {
    value.unwrap_or(u64::MAX) as u32
}

/// Endereço chamável de uma rotina nativa do teste.
fn routine(address: usize) -> u64 {
    let address = address as u64;
    crate::ntos::mm::kernel_address::image_address(address).unwrap_or(address)
}

fn large(value: i64) -> u64 {
    let address = guest::alloc_bytes(8);
    at::<nt::Field<i64>>(address).set(value);
    address
}

fn unicode(text: &str) -> u64 {
    let units: Vec<u8> = text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    let address = guest::alloc_bytes(nt::UnicodeString::SIZE + units.len() as u64 + 2);
    guest::write_bytes(address + nt::UnicodeString::SIZE, &units);
    let string = at::<nt::UnicodeString>(address);
    string.length.set(units.len() as u16);
    string.maximum_length.set(units.len() as u16);
    string.buffer.set(address + nt::UnicodeString::SIZE);
    address
}

pub fn run(assert: Assert, call_export: CallExport) {
    cached_fast_io(assert, call_export);
    fast_io_passthrough(assert, call_export);
    volume_events(assert, call_export);
    device_queries(assert, call_export);
    oplock_filter(assert, call_export);
    notify_filter(assert, call_export);
    notify_lite(assert, call_export);
}

// ---- Fast I/O genérico em cache --------------------------------------------------

static CHECK_ANSWER: AtomicU32 = AtomicU32::new(1);
static CHECK_CALLS: AtomicU32 = AtomicU32::new(0);
static CHECK_FOR_READ: AtomicU64 = AtomicU64::new(0);

/// FastIoCheckIfPossible(FileObject, FileOffset, Length, Wait, LockKey,
/// CheckForReadOperation, IoStatus, DeviceObject).
extern "win64" fn check_if_possible(_file: u64, _offset: u64, _length: u32, _wait: u8, _key: u32, check_for_read: u8, _io_status: u64, _device: u64) -> u8 {
    CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
    CHECK_FOR_READ.store(check_for_read as u64, Ordering::SeqCst);
    CHECK_ANSWER.load(Ordering::SeqCst) as u8
}

fn cached_fast_io(assert: Assert, call_export: CallExport) {
    use crate::ntos::ex::resource;
    use crate::ntos::inc::types::extra_cc::SharedCacheMap;
    use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
    use crate::ntos::ke::pcr;
    use crate::ntos::test::cc_fixture as fixture;
    const SIZE: u64 = 0x5_0000;
    let Some(f) = fixture::create(SIZE) else {
        assert(false, "fsrtl-cached-fast-io: fixture de arquivo sintetico");
        return;
    };
    let block = guest::alloc_bytes(FsrtlCommonFcbHeader::SIZE + nt::Eresource::SIZE);
    let header = at::<FsrtlCommonFcbHeader>(block);
    let resource_address = block + FsrtlCommonFcbHeader::SIZE;
    let _ = resource::initialize(resource_address);
    header.resource.set(resource_address);
    header.allocation_size.quad_part.set(0x6_0000);
    header.file_size.quad_part.set(SIZE as i64);
    header.valid_data_length.quad_part.set(SIZE as i64);
    header.is_fast_io_possible.set(1);
    let file = at::<nt::FileObject>(f.file);
    file.fs_context.set(block);
    let dispatch = guest::alloc_bytes(nt::FastIoDispatch::SIZE);
    let table = at::<nt::FastIoDispatch>(dispatch);
    table.size_of_fast_io_dispatch.set(nt::FastIoDispatch::SIZE as u32);
    table.fast_io_check_if_possible.set(routine(check_if_possible as extern "win64" fn(u64, u64, u32, u8, u32, u8, u64, u64) -> u8 as usize));
    at::<nt::DriverObject>(f.driver).fast_io_dispatch.set(dispatch);
    let _ = call_export("CcInitializeCacheMap", &[f.file, f.sizes, 0, 0, 0]);

    let buffer = guest::alloc_bytes(0x400);
    let iosb_address = guest::alloc_bytes(nt::IoStatusBlock::SIZE);
    let iosb = at::<nt::IoStatusBlock>(iosb_address);
    let prcb = &at::<nt::Kpcr>(pcr::get_pcr_address()).prcb;
    let read = |offset: i64, length: u64, wait: u64| {
        let pointer = large(offset);
        let result = call_export("FsRtlCopyRead", &[f.file, pointer, length, wait, 0, buffer, iosb_address, f.device]);
        guest::free_bytes(pointer);
        result
    };
    let pattern = |offset: u64, length: usize| -> Vec<u8> { (offset..offset + length as u64).map(fixture::pattern).collect() };

    // Leitura em cache: bytes do arquivo, IoStatus, CurrentByteOffset,
    // FO_FILE_FAST_IO_READ e o contador CcFastReadWait.
    let waits = prcb.cc_fast_read_wait.get();
    let ok = read(0x1234, 0x100, 1) == Some(1);
    assert(
        ok && guest::read_bytes(buffer, 0x100) == pattern(0x1234, 0x100) && iosb.status.get() == 0 && iosb.information.get() == 0x100 && file.current_byte_offset.quad_part.get() == 0x1334 && file.flags.get() & 0x8_0000 != 0 && prcb.cc_fast_read_wait.get() == waits.wrapping_add(1),
        "fsrtl-cached-fast-io: FsRtlCopyRead le pelo cache e atualiza o FILE_OBJECT",
    );
    // Aparado ao FileSize; no fim, STATUS_END_OF_FILE e TRUE; tamanho zero.
    assert(read(SIZE as i64 - 0x100, 0x200, 1) == Some(1) && iosb.information.get() == 0x100 && guest::read_bytes(buffer, 0x100) == pattern(SIZE - 0x100, 0x100), "fsrtl-cached-fast-io: FsRtlCopyRead apara ao FileSize");
    assert(read(SIZE as i64, 0x10, 1) == Some(1) && iosb.status.get() as u32 == STATUS_END_OF_FILE && iosb.information.get() == 0, "fsrtl-cached-fast-io: FsRtlCopyRead alem do fim = STATUS_END_OF_FILE");
    iosb.status.set(-1);
    assert(read(0, 0, 1) == Some(1) && iosb.status.get() == 0 && iosb.information.get() == 0, "fsrtl-cached-fast-io: FsRtlCopyRead de tamanho zero");
    assert(read(0x7FFF_FFFF_FFFF_FF00, 0x200, 1) == Some(0) && iosb.status.get() as u32 == STATUS_INVALID_PARAMETER, "fsrtl-cached-fast-io: deslocamento + tamanho alem de MAXLONGLONG");
    // Com IRP de nível superior a rotina recusa sem tocar em nada.
    let _ = call_export("IoSetTopLevelIrp", &[1]);
    let refused = read(0, 0x10, 1) == Some(0);
    let _ = call_export("IoSetTopLevelIrp", &[0]);
    assert(refused, "fsrtl-cached-fast-io: FsRtlCopyRead recusa com IoGetTopLevelIrp nao nulo");
    // FastIoIsNotPossible e FastIoIsQuestionable.
    let not_possible = prcb.cc_fast_read_not_possible.get();
    header.is_fast_io_possible.set(0);
    let refused = read(0, 0x10, 1) == Some(0) && prcb.cc_fast_read_not_possible.get() == not_possible.wrapping_add(1);
    header.is_fast_io_possible.set(2);
    CHECK_ANSWER.store(0, Ordering::SeqCst);
    let calls = CHECK_CALLS.load(Ordering::SeqCst);
    let questioned_no = read(0, 0x10, 1) == Some(0) && CHECK_CALLS.load(Ordering::SeqCst) == calls + 1 && CHECK_FOR_READ.load(Ordering::SeqCst) == 1;
    CHECK_ANSWER.store(1, Ordering::SeqCst);
    let questioned_yes = read(0x10, 0x10, 1) == Some(1) && guest::read_bytes(buffer, 0x10) == pattern(0x10, 0x10);
    header.is_fast_io_possible.set(1);
    assert(refused && questioned_no && questioned_yes, "fsrtl-cached-fast-io: IsFastIoPossible (nao possivel e FastIoCheckIfPossible)");

    // Escrita em cache dentro do ValidDataLength.
    let write = |offset: i64, data: &[u8]| {
        guest::write_bytes(buffer, data);
        let pointer = large(offset);
        let result = call_export("FsRtlCopyWrite", &[f.file, pointer, data.len() as u64, 1, 0, buffer, iosb_address, f.device]);
        guest::free_bytes(pointer);
        result
    };
    file.flags.set(file.flags.get() & !0x3000);
    let data: Vec<u8> = (0..0x80u32).map(|index| (index * 3 + 1) as u8).collect();
    let written = write(0x100, &data) == Some(1) && iosb.status.get() == 0 && iosb.information.get() == 0x80 && file.current_byte_offset.quad_part.get() == 0x180 && file.flags.get() & 0x1000 != 0;
    assert(written && read(0x100, 0x80, 1) == Some(1) && guest::read_bytes(buffer, 0x80) == data, "fsrtl-cached-fast-io: FsRtlCopyWrite grava pelo cache");
    // Estende o arquivo: FileSize, ValidDataLength, SharedCacheMap->FileSize e FO_FILE_SIZE_CHANGED.
    let map = at::<SharedCacheMap>(at::<nt::SectionObjectPointers>(f.pointers).shared_cache_map.get());
    let tail: Vec<u8> = (0..0x100u32).map(|index| (index ^ 0x5A) as u8).collect();
    let extended = write(SIZE as i64, &tail) == Some(1) && header.file_size.quad_part.get() == 0x5_0100 && header.valid_data_length.quad_part.get() == 0x5_0100 && map.file_size.quad_part.get() == 0x5_0100 && file.flags.get() & 0x2000 != 0;
    assert(extended && read(SIZE as i64, 0x100, 1) == Some(1) && guest::read_bytes(buffer, 0x100) == tail, "fsrtl-cached-fast-io: FsRtlCopyWrite estende o arquivo e o SharedCacheMap");
    // FILE_WRITE_TO_END_OF_FILE escreve no FileSize corrente.
    let appended = write(-1, &[0xEE; 0x10]) == Some(1) && header.file_size.quad_part.get() == 0x5_0110 && file.current_byte_offset.quad_part.get() == 0x5_0110;
    assert(appended && read(0x5_0100, 0x10, 1) == Some(1) && guest::read_bytes(buffer, 0x10) == [0xEE; 0x10], "fsrtl-cached-fast-io: FsRtlCopyWrite no fim do arquivo (-1)");
    // Além do ValidDataLength (até 8 KB): o intervalo é zerado pelo CcZeroData.
    let gap = write(0x5_1000, &[0x77; 0x10]) == Some(1) && header.file_size.quad_part.get() == 0x5_1010 && header.valid_data_length.quad_part.get() == 0x5_1010;
    assert(gap && read(0x5_0200, 0x100, 1) == Some(1) && guest::read_bytes(buffer, 0x100) == [0u8; 0x100], "fsrtl-cached-fast-io: FsRtlCopyWrite apos o VDL zera o intervalo");
    // Além do AllocationSize ou com FO_WRITE_THROUGH: FALSE sem mexer nos tamanhos.
    header.allocation_size.quad_part.set(0x5_1020);
    let beyond = write(0x5_1010, &[1; 0x20]) == Some(0) && header.file_size.quad_part.get() == 0x5_1010 && header.valid_data_length.quad_part.get() == 0x5_1010;
    header.allocation_size.quad_part.set(0x6_0000);
    file.flags.set(file.flags.get() | 0x10);
    let through = write(0x200, &[2; 0x10]) == Some(0);
    file.flags.set(file.flags.get() & !0x10);
    assert(beyond && through, "fsrtl-cached-fast-io: FsRtlCopyWrite recusa alem do AllocationSize e com write-through");

    // MDL de leitura pelo cache: cadeia com os bytes, contadores e recusa.
    let chain = guest::alloc_bytes(8);
    let chain_cell = at::<nt::Field<u64>>(chain);
    let mdl_waits = prcb.cc_fast_mdl_read_wait.get();
    let offset = large(0x2000);
    let mdl_ok = call_export("FsRtlMdlReadDev", &[f.file, offset, 0x100, 0, chain, iosb_address, f.device]) == Some(1);
    let mdl = chain_cell.get();
    let mdl_bytes = mdl != 0 && guest::read_bytes(at::<nt::Mdl>(mdl).mapped_system_va.get(), 0x100) == pattern(0x2000, 0x100);
    assert(mdl_ok && mdl_bytes && iosb.information.get() == 0x100 && prcb.cc_fast_mdl_read_wait.get() == mdl_waits.wrapping_add(1), "fsrtl-cached-fast-io: FsRtlMdlReadDev devolve a cadeia de MDL do cache");
    let _ = call_export("CcMdlReadComplete", &[f.file, mdl]);
    let mdl_not_possible = prcb.cc_fast_mdl_read_not_possible.get();
    header.is_fast_io_possible.set(0);
    chain_cell.set(0);
    let refused = call_export("FsRtlMdlReadDev", &[f.file, offset, 0x100, 0, chain, iosb_address, f.device]) == Some(0) && chain_cell.get() == 0 && prcb.cc_fast_mdl_read_not_possible.get() == mdl_not_possible.wrapping_add(1);
    header.is_fast_io_possible.set(1);
    assert(refused, "fsrtl-cached-fast-io: FsRtlMdlReadDev sem Fast I/O soma CcFastMdlReadNotPossible");
    guest::free_bytes(offset);

    // MDL de escrita: os bytes postos na cadeia chegam ao cache no complete.
    let offset = large(0x3000);
    file.flags.set(file.flags.get() & !0x1000);
    chain_cell.set(0);
    let prepared = call_export("FsRtlPrepareMdlWriteDev", &[f.file, offset, 0x80, 0, chain, iosb_address, f.device]) == Some(1) && chain_cell.get() != 0 && iosb.status.get() == 0 && file.flags.get() & 0x1000 != 0;
    let mdl = chain_cell.get();
    if prepared {
        guest::write_bytes(at::<nt::Mdl>(mdl).mapped_system_va.get(), &[0xC3; 0x80]);
        let _ = call_export("CcMdlWriteComplete", &[f.file, offset, mdl]);
    }
    assert(prepared && read(0x3000, 0x80, 1) == Some(1) && guest::read_bytes(buffer, 0x80) == [0xC3; 0x80], "fsrtl-cached-fast-io: FsRtlPrepareMdlWriteDev prepara a cadeia de escrita do cache");
    guest::free_bytes(offset);

    let _ = call_export("CcUninitializeCacheMap", &[f.file, 0, 0]);
    at::<nt::DriverObject>(f.driver).fast_io_dispatch.set(0);
    file.fs_context.set(0);
    let _ = resource::delete(resource_address);
    for address in [chain, iosb_address, buffer, dispatch, block] {
        guest::free_bytes(address);
    }
    fixture::destroy(f);
}

// ---- FsRtlMdlRead / FsRtlMdlReadComplete -------------------------------------------

static MDL_READ_ARGUMENTS: AtomicU64 = AtomicU64::new(0);
static MDL_COMPLETE_ARGUMENTS: AtomicU64 = AtomicU64::new(0);

extern "win64" fn fast_mdl_read(_file: u64, _offset: u64, length: u32, key: u32, _chain: u64, _io_status: u64, _device: u64) -> u8 {
    MDL_READ_ARGUMENTS.store((length as u64) << 32 | key as u64, Ordering::SeqCst);
    1
}

extern "win64" fn fast_mdl_read_complete(_file: u64, chain: u64, _device: u64) -> u8 {
    MDL_COMPLETE_ARGUMENTS.store(chain, Ordering::SeqCst);
    1
}

fn fast_io_passthrough(assert: Assert, call_export: CallExport) {
    use crate::ntos::ob::objects::file as file_objects;
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let device = guest::alloc_bytes(nt::DeviceObject::SIZE);
    let dispatch = guest::alloc_bytes(nt::FastIoDispatch::SIZE);
    at::<nt::DeviceObject>(device).driver_object.set(driver);
    at::<nt::DeviceObject>(device).stack_size.set(1);
    at::<nt::DriverObject>(driver).fast_io_dispatch.set(dispatch);
    let table = at::<nt::FastIoDispatch>(dispatch);
    table.mdl_read.set(routine(fast_mdl_read as extern "win64" fn(u64, u64, u32, u32, u64, u64, u64) -> u8 as usize));
    table.mdl_read_complete.set(routine(fast_mdl_read_complete as extern "win64" fn(u64, u64, u64) -> u8 as usize));
    let Ok(file) = file_objects::create(device, "\\opennt-fast-io") else {
        assert(false, "fsrtl-cached-fast-io: FILE_OBJECT do dispositivo sintetico");
        return;
    };
    let scratch = guest::alloc_bytes(0x40);
    // A tabela precisa cobrir o slot (MdlRead em +0x80, MdlReadComplete em +0x88).
    table.size_of_fast_io_dispatch.set(0x80);
    let short_read = call_export("FsRtlMdlRead", &[file, scratch, 0x200, 7, scratch + 8, scratch + 0x10]) == Some(0);
    table.size_of_fast_io_dispatch.set(0x88);
    let read = call_export("FsRtlMdlRead", &[file, scratch, 0x200, 7, scratch + 8, scratch + 0x10]) == Some(1) && MDL_READ_ARGUMENTS.load(Ordering::SeqCst) == 0x200 << 32 | 7;
    let short_complete = call_export("FsRtlMdlReadComplete", &[file, 0x1234_5678]) == Some(0);
    table.size_of_fast_io_dispatch.set(nt::FastIoDispatch::SIZE as u32);
    let complete = call_export("FsRtlMdlReadComplete", &[file, 0x1234_5678]) == Some(1) && MDL_COMPLETE_ARGUMENTS.load(Ordering::SeqCst) == 0x1234_5678;
    assert(short_read && read, "fsrtl-cached-fast-io: FsRtlMdlRead repassa ao MdlRead do FAST_IO_DISPATCH");
    assert(short_complete && complete, "fsrtl-cached-fast-io: FsRtlMdlReadComplete repassa ao MdlReadComplete");
    let _ = file_objects::dereference(file);
    for address in [scratch, dispatch, device, driver] {
        guest::free_bytes(address);
    }
}

// ---- FsRtlNotifyVolumeEvent(Ex) ----------------------------------------------------

static VOLUME_EVENTS: crate::rtl::SpinLock<Vec<([u8; 16], u16, i32)>> = crate::rtl::SpinLock::new(Vec::new());

/// Registro de EventCategoryTargetDeviceChange: guarda (Event, Size, NameBufferOffset).
extern "win64" fn volume_notification(notification: u64, _context: u64) -> u32 {
    let mut event = [0u8; 16];
    event.copy_from_slice(&guest::read_bytes(notification + 4, 16));
    let size = at::<nt::Field<u16>>(notification + 2).get();
    let offset = at::<nt::Field<i32>>(notification + 0x20).get();
    VOLUME_EVENTS.lock().push((event, size, offset));
    0
}

fn volume_events(assert: Assert, call_export: CallExport) {
    use crate::ntos::io::work_items;
    use crate::ntos::ob::objects::{device as device_objects, file as file_objects};
    // GUID_IO_VOLUME_LOCK, _MOUNT e _CHANGE_SIZE (bytes da memória, ioevent.h).
    const LOCK: [u8; 16] = [0x74, 0x88, 0x70, 0x50, 0xAF, 0xC9, 0xD1, 0x11, 0x8F, 0xEF, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
    const MOUNT: [u8; 16] = [0x78, 0x48, 0x80, 0xB5, 0x96, 0x1A, 0xD2, 0x11, 0x8F, 0xFD, 0x00, 0xA0, 0xC9, 0xA0, 0x6D, 0x32];
    const CHANGE_SIZE: [u8; 16] = [0xBE, 0x25, 0x16, 0x3A, 0x03, 0xAD, 0xF1, 0x49, 0x8E, 0xF8, 0x6B, 0xBA, 0xC1, 0x82, 0xD1, 0xFD];
    // PDO relatado (devnode do PnP) para um driver sintético "OpenNtVolume".
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE + nt::DriverExtension::SIZE + 0x40);
    let extension = driver + nt::DriverObject::SIZE;
    let service = extension + nt::DriverExtension::SIZE;
    let text: Vec<u8> = "OpenNtVolume".encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    guest::write_bytes(service, &text);
    at::<nt::DriverObject>(driver).driver_extension.set(extension);
    let key = &at::<nt::DriverExtension>(extension).service_key_name;
    key.length.set(text.len() as u16);
    key.maximum_length.set(text.len() as u16);
    key.buffer.set(service);
    let output = guest::alloc_bytes(8);
    let reported = call_export("IoReportDetectedDevice", &[driver, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0, 0, 1, output]) == Some(0);
    let pdo = at::<nt::Field<u64>>(output).get();
    let Ok(file) = file_objects::create(pdo, "") else {
        assert(false, "fsrtl-volume-event: FILE_OBJECT do volume");
        return;
    };
    let entry = guest::alloc_bytes(8);
    let registered = call_export("IoRegisterPlugPlayNotification", &[3, 0, file, driver, routine(volume_notification as extern "win64" fn(u64, u64) -> u32 as usize), 0, entry]) == Some(0);
    VOLUME_EVENTS.lock().clear();
    let references = device_objects::reference_count(pdo);
    // LOCK (3): entrega síncrona, estrutura montada pelo FsRtlNotifyVolumeEvent.
    let lock = status(call_export("FsRtlNotifyVolumeEvent", &[file, 3])) == 0 && VOLUME_EVENTS.lock().as_slice() == [(LOCK, 0x24, -1)];
    assert(reported && registered && lock, "fsrtl-volume-event: FSRTL_VOLUME_LOCK entregue na hora com GUID_IO_VOLUME_LOCK");
    // MOUNT (6): assíncrono; a cópia sobrevive à estrutura da pilha.
    VOLUME_EVENTS.lock().clear();
    let mounted = status(call_export("FsRtlNotifyVolumeEvent", &[file, 6])) == 0 && VOLUME_EVENTS.lock().is_empty();
    work_items::run_queue();
    let delivered = VOLUME_EVENTS.lock().as_slice() == [(MOUNT, 0x24, -1)];
    assert(mounted && delivered, "fsrtl-volume-event: FSRTL_VOLUME_MOUNT entregue por work item");
    // Ex: o GUID vai para a estrutura do chamador; fora da tabela, STATUS_INVALID_PARAMETER.
    VOLUME_EVENTS.lock().clear();
    let custom = guest::alloc_bytes(0x30);
    at::<nt::Field<u16>>(custom).set(1);
    at::<nt::Field<u16>>(custom + 2).set(0x28);
    at::<nt::Field<i32>>(custom + 0x20).set(-1);
    let ex = status(call_export("FsRtlNotifyVolumeEventEx", &[file, 13, custom])) == 0 && guest::read_bytes(custom + 4, 16) == CHANGE_SIZE;
    work_items::run_queue();
    let ex_delivered = VOLUME_EVENTS.lock().as_slice() == [(CHANGE_SIZE, 0x28, -1)];
    assert(ex && ex_delivered, "fsrtl-volume-event: FsRtlNotifyVolumeEventEx grava o GUID e entrega a estrutura do chamador");
    let invalid = status(call_export("FsRtlNotifyVolumeEvent", &[file, 0])) == STATUS_INVALID_PARAMETER && status(call_export("FsRtlNotifyVolumeEvent", &[file, 15])) == STATUS_INVALID_PARAMETER;
    assert(invalid && device_objects::reference_count(pdo) == references, "fsrtl-volume-event: codigo fora da tabela e a referencia do PDO solta");
    // Dispositivo sem devnode (o driver não atende IRP_MJ_PNP): a falha volta.
    let plain_driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let plain = guest::alloc_bytes(nt::DeviceObject::SIZE);
    at::<nt::DeviceObject>(plain).driver_object.set(plain_driver);
    at::<nt::DeviceObject>(plain).stack_size.set(1);
    if let Ok(other) = file_objects::create(plain, "\\opennt-plain-volume") {
        let failed = status(call_export("FsRtlNotifyVolumeEvent", &[other, 3]));
        assert(failed & 0x8000_0000 != 0 && VOLUME_EVENTS.lock().len() == 1, "fsrtl-volume-event: sem PDO alvo devolve a falha do IoGetRelatedTargetDevice");
        let _ = file_objects::dereference(other);
    }
    let _ = call_export("IoUnregisterPlugPlayNotification", &[at::<nt::Field<u64>>(entry).get()]);
    let _ = file_objects::dereference(file);
    for address in [plain, plain_driver, custom, entry, output] {
        guest::free_bytes(address);
    }
}

// ---- FsRtlBalanceReads / FsRtlGetSectorSizeInformation -------------------------------

/// Respostas do disco sintético.
struct DiskAnswers {
    geometry_status: u32,
    bytes_per_sector: u32,
    alignment_status: u32,
    physical: u32,
    sector_offset: u32,
    partition_offset: u64,
    seek_penalty: u8,
    trim: u8,
    attributes: u64,
    balance_status: u32,
}

static DISK: crate::rtl::SpinLock<DiskAnswers> = crate::rtl::SpinLock::new(DiskAnswers { geometry_status: 0, bytes_per_sector: 512, alignment_status: 0, physical: 4096, sector_offset: 0, partition_offset: 0x10_0000, seek_penalty: 0, trim: 1, attributes: 1, balance_status: 0 });
/// (IOCTL, Flags da stack location) de cada pedido.
static DISK_REQUESTS: crate::rtl::SpinLock<Vec<(u32, u8)>> = crate::rtl::SpinLock::new(Vec::new());

extern "win64" fn disk_control(_device: u64, packet: u64) -> u32 {
    let irp = at::<nt::Irp>(packet);
    let location = at::<nt::IoStackLocation>(irp.tail.overlay.current_stack_location.get());
    let code = location.parameters.device_io_control.io_control_code.get();
    DISK_REQUESTS.lock().push((code, location.flags.get()));
    let system = irp.associated_irp.system_buffer.get();
    let words = |values: &[u32]| {
        let bytes: Vec<u8> = values.iter().flat_map(|value| value.to_le_bytes()).collect();
        guest::write_bytes(system, &bytes);
        bytes.len() as u64
    };
    let answers = DISK.lock();
    let (result, information) = match code {
        0x0066_001B => (answers.balance_status, 0),
        0x0007_0000 if answers.geometry_status == 0 => (0, words(&[100, 0, 12, 255, 63, answers.bytes_per_sector])),
        0x0007_0000 => (answers.geometry_status, 0),
        0x0007_0048 => {
            guest::write_bytes(system, &[0u8; 0x90]);
            at::<nt::Field<u64>>(system + 8).set(answers.partition_offset);
            (0, 0x90)
        }
        0x002D_1400 => match at::<nt::Field<u32>>(system).get() {
            6 if answers.alignment_status == 0 => (0, words(&[0x1C, 0x1C, 64, 0, answers.bytes_per_sector, answers.physical, answers.sector_offset])),
            6 => (answers.alignment_status, 0),
            7 => (0, words(&[0x0C, 0x0C, answers.seek_penalty as u32])),
            8 => (0, words(&[0x0C, 0x0C, answers.trim as u32])),
            0x37 => (0, words(&[0x10, 0x10, answers.attributes as u32, (answers.attributes >> 32) as u32])),
            _ => (STATUS_NOT_SUPPORTED, 0),
        },
        _ => (STATUS_NOT_SUPPORTED, 0),
    };
    drop(answers);
    irp.io_status.status.set(result as i32);
    irp.io_status.information.set(information);
    crate::ntos::io::io_manager::iof_complete_request(packet);
    result
}

fn device_queries(assert: Assert, call_export: CallExport) {
    use crate::ntos::fsrtl::device_control::FileFsSectorSizeInformation;
    let driver = guest::alloc_bytes(nt::DriverObject::SIZE);
    let device = guest::alloc_bytes(nt::DeviceObject::SIZE);
    at::<nt::DriverObject>(driver).major_function[0x0E].set(routine(disk_control as extern "win64" fn(u64, u64) -> u32 as usize));
    at::<nt::DeviceObject>(device).driver_object.set(driver);
    at::<nt::DeviceObject>(device).stack_size.set(1);
    let configure = |change: &dyn Fn(&mut DiskAnswers)| {
        let mut answers = DISK.lock();
        *answers = DiskAnswers { geometry_status: 0, bytes_per_sector: 512, alignment_status: 0, physical: 4096, sector_offset: 0, partition_offset: 0x10_0000, seek_penalty: 0, trim: 1, attributes: 1, balance_status: 0 };
        change(&mut answers);
        DISK_REQUESTS.lock().clear();
    };

    // FsRtlBalanceReads: FT_BALANCED_READ_MODE sem flags; o status do driver volta.
    configure(&|_| {});
    let balanced = status(call_export("FsRtlBalanceReads", &[device])) == 0 && DISK_REQUESTS.lock().as_slice() == [(0x0066_001B, 0)];
    configure(&|answers| answers.balance_status = STATUS_NOT_SUPPORTED);
    let unsupported = status(call_export("FsRtlBalanceReads", &[device])) == STATUS_NOT_SUPPORTED;
    assert(balanced && unsupported, "fsrtl-device-queries: FsRtlBalanceReads envia FT_BALANCED_READ_MODE e devolve o status");

    let info_address = guest::alloc_bytes(FileFsSectorSizeInformation::SIZE);
    let info = at::<FileFsSectorSizeInformation>(info_address);
    let query = || status(call_export("FsRtlGetSectorSizeInformation", &[device, info_address]));
    let fields = || [info.logical_bytes_per_sector.get(), info.physical_bytes_per_sector_for_atomicity.get(), info.physical_bytes_per_sector_for_performance.get(), info.file_system_effective_physical_bytes_per_sector_for_atomicity.get(), info.flags.get(), info.byte_offset_for_sector_alignment.get(), info.byte_offset_for_partition_alignment.get()];
    // Disco 512e alinhado: 4 KB físicos, partição em 1 MB, sem penalidade, TRIM e bytes endereçáveis.
    configure(&|_| {});
    let aligned = query() == 0 && fields() == [512, 4096, 4096, 512, 0x1F, 0, 0];
    let codes: Vec<(u32, u8)> = DISK_REQUESTS.lock().clone();
    let expected_codes = [(0x0007_0000, 2), (0x002D_1400, 2), (0x0007_0048, 2), (0x002D_1400, 2), (0x002D_1400, 2), (0x002D_1400, 2)];
    assert(aligned && codes == expected_codes, "fsrtl-device-queries: FsRtlGetSectorSizeInformation de um disco 512e alinhado");
    // Setor deslocado 512 e partição em 0x7E00: alinhamento só da partição.
    configure(&|answers| {
        answers.sector_offset = 512;
        answers.partition_offset = 0x7E00;
        answers.seek_penalty = 1;
        answers.trim = 0;
        answers.attributes = 0;
    });
    assert(query() == 0 && fields() == [512, 4096, 4096, 512, 0x2, 512, 3584], "fsrtl-device-queries: setor desalinhado do fisico, particao coerente");
    // Partição em 0x8000 com setor deslocado 512: os dois flags de alinhamento caem.
    configure(&|answers| {
        answers.sector_offset = 512;
        answers.partition_offset = 0x8000;
    });
    assert(query() == 0 && fields() == [512, 4096, 4096, 512, 0x1C, 512, 0], "fsrtl-device-queries: particao incoerente com o deslocamento do setor");
    // Sem o descritor de alinhamento: o físico é o lógico e os deslocamentos são desconhecidos.
    configure(&|answers| answers.alignment_status = STATUS_NOT_SUPPORTED);
    let fallback = query() == 0 && fields() == [512, 512, 512, 512, 0x1F, 0xFFFF_FFFF, 0xFFFF_FFFF] && !DISK_REQUESTS.lock().iter().any(|&(code, _)| code == 0x0007_0048);
    configure(&|answers| answers.physical = 1536);
    let not_power = query() == 0 && fields()[1] == 512 && fields()[5] == 0xFFFF_FFFF;
    assert(fallback && not_power, "fsrtl-device-queries: descritor ausente ou invalido usa a geometria");
    // Geometria com falha ou BytesPerSector inválido.
    configure(&|answers| answers.geometry_status = 0xC000_0010);
    let failed = query() == 0xC000_0010;
    configure(&|answers| answers.bytes_per_sector = 768);
    let odd = query() == 0xC000_00CB;
    configure(&|answers| answers.bytes_per_sector = 0);
    let zero = query() == 0xC000_00CB;
    assert(failed && odd && zero, "fsrtl-device-queries: falha da geometria e BytesPerSector invalido (STATUS_BAD_DEVICE_TYPE)");
    for address in [info_address, device, driver] {
        guest::free_bytes(address);
    }
}

// ---- FsRtlCheckOplockForFsFilterCallback ----------------------------------------------

fn oplock_filter(assert: Assert, call_export: CallExport) {
    use crate::ntos::fsrtl::oplock::FsFilterCallbackData;
    use crate::ntos::ke::fast_mutex;
    let handle = guest::alloc_bytes(8);
    let data_address = guest::alloc_bytes(FsFilterCallbackData::SIZE);
    let data = at::<FsFilterCallbackData>(data_address);
    data.size_of_fs_filter_callback_data.set(FsFilterCallbackData::SIZE as u32);
    data.operation.set(0xFF);
    data.sync_type.set(1);
    data.page_protection.set(0x04);
    let check = |flags: u64| status(call_export("FsRtlCheckOplockForFsFilterCallback", &[handle, data_address, flags]));
    assert(check(0x10) == STATUS_INVALID_PARAMETER && check(0x9) == STATUS_INVALID_PARAMETER, "fsrtl-oplock-filter: flags alem de OPLOCK_FLAG_IGNORE_OPLOCK_KEYS");
    assert(check(0) == 0 && check(8) == 0, "fsrtl-oplock-filter: oplock NULL = STATUS_SUCCESS");
    // Bloco interno com o FAST_MUTEX em +0x98: sem níveis 0x7000, ou pedido
    // que não cria seção gravável, não há o que quebrar.
    let block = guest::alloc_bytes(0xA0 + nt::FastMutex::SIZE);
    let mutex = block + 0xA0;
    fast_mutex::initialize(mutex);
    at::<nt::Field<u64>>(block + 0x98).set(mutex);
    at::<nt::Field<u64>>(handle).set(block);
    at::<nt::Field<u32>>(block + 0x90).set(0x40);
    let no_levels = check(0) == 0 && at::<nt::FastMutex>(mutex).count.get() == 1;
    at::<nt::Field<u32>>(block + 0x90).set(0x1000);
    data.page_protection.set(0x02);
    let read_only = check(0) == 0;
    data.page_protection.set(0x04);
    data.sync_type.set(0);
    let other_sync = check(0) == 0;
    data.sync_type.set(1);
    data.operation.set(0xFE);
    let other_operation = check(8) == 0 && at::<nt::FastMutex>(mutex).count.get() == 1;
    assert(no_levels && read_only && other_sync && other_operation, "fsrtl-oplock-filter: so a secao gravavel com niveis de cache pede quebra; o mutex volta livre");
    at::<nt::Field<u64>>(handle).set(0);
    for address in [block, data_address, handle] {
        guest::free_bytes(address);
    }
}

// ---- Notificação de diretório: FilterReportChange e Lite ---------------------------

/// Um IRP_MJ_DIRECTORY_CONTROL/IRP_MN_NOTIFY_CHANGE_DIRECTORY de uma posição.
struct NotifyIrp {
    irp: u64,
    file: u64,
    out: u64,
}

impl NotifyIrp {
    fn new() -> Self {
        let irp = guest::alloc_bytes(nt::Irp::SIZE + nt::IoStackLocation::SIZE);
        let file = guest::alloc_bytes(nt::FileObject::SIZE);
        let out = guest::alloc_bytes(0x200);
        NotifyIrp { irp, file, out }
    }

    fn arm(&self, length: u32) {
        guest::write_bytes(self.irp, &alloc::vec![0u8; (nt::Irp::SIZE + nt::IoStackLocation::SIZE) as usize]);
        guest::write_bytes(self.out, &[0u8; 0x200]);
        let (packet, stack) = (at::<nt::Irp>(self.irp), at::<nt::IoStackLocation>(self.irp + nt::Irp::SIZE));
        packet.type_.set(6);
        packet.stack_count.set(1);
        packet.current_location.set(1);
        packet.tail.overlay.current_stack_location.set(stack.address());
        packet.user_buffer.set(self.out);
        packet.tail.overlay.thread.set(crate::ntos::ps::process::get_current_thread());
        stack.major_function.set(0x0C);
        stack.minor_function.set(2);
        stack.parameters.notify_directory.length.set(length);
        stack.file_object.set(self.file);
    }

    fn packet(&self) -> &'static nt::Irp {
        at::<nt::Irp>(self.irp)
    }

    /// Pendente: Information aponta o NOTIFY_CHANGE e o elo está na lista dele.
    fn pending(&self) -> bool {
        let link = &self.packet().tail.overlay.list_entry;
        self.packet().io_status.information.get() != 0 && link.flink.get() != 0 && at::<nt::ListEntry>(link.blink.get()).flink.get() == link.address()
    }

    fn completed(&self, code: u32, information: u64) -> bool {
        self.packet().io_status.status.get() as u32 == code && self.packet().io_status.information.get() == information
    }

    /// (NextEntryOffset, Action, nome) do registro FILE_NOTIFY_INFORMATION em `offset`.
    fn record(&self, offset: u64) -> (u32, u32, Vec<u16>) {
        let record = at::<nt::extra_fs_fat::FileNotifyInformation>(self.out + offset);
        let length = record.file_name_length.get() as u64 / 2;
        let name = (0..length).map(|index| at::<nt::Field<u16>>(record.file_name[0].address() + index * 2).get()).collect();
        (record.next_entry_offset.get(), record.action.get(), name)
    }

    fn free(self) {
        for address in [self.out, self.file, self.irp] {
            guest::free_bytes(address);
        }
    }
}

fn units(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

static FILTER_CALLS: AtomicU32 = AtomicU32::new(0);
static FILTER_CONTEXT: AtomicU64 = AtomicU64::new(0);

/// FilterCallback(NotifyContext, FilterContext): aceita só o contexto 0x55.
extern "win64" fn filter_callback(_notify_context: u64, filter_context: u64) -> u8 {
    FILTER_CALLS.fetch_add(1, Ordering::SeqCst);
    FILTER_CONTEXT.store(filter_context, Ordering::SeqCst);
    (filter_context == 0x55) as u8
}

fn new_list() -> u64 {
    let list = guest::alloc_bytes(nt::ListEntry::SIZE);
    at::<nt::ListEntry>(list).flink.set(list);
    at::<nt::ListEntry>(list).blink.set(list);
    list
}

fn notify_filter(assert: Assert, call_export: CallExport) {
    let sync_cell = guest::alloc_bytes(8);
    let list = new_list();
    let directory = unicode("\\dir");
    let target = unicode("\\dir\\a.txt");
    let stream = unicode("s1");
    let filter = routine(filter_callback as extern "win64" fn(u64, u64) -> u8 as usize);
    let _ = call_export("FsRtlNotifyInitializeSync", &[sync_cell]);
    let sync = at::<nt::Field<u64>>(sync_cell).get();
    let request = NotifyIrp::new();
    request.arm(0x100);
    let _ = call_export("FsRtlNotifyFilterChangeDirectory", &[sync, list, 0x1234, directory, 0, 0, 1, request.irp, 0, 0, filter]);
    let report = |filter_context: u64| call_export("FsRtlNotifyFilterReportChange", &[sync, list, target, 10, 0, 0, 1, 1, 0, filter_context]);
    // FilterContext que o FilterCallback recusa: nada sai.
    let calls = FILTER_CALLS.load(Ordering::SeqCst);
    report(0x66);
    let refused = request.pending() && FILTER_CALLS.load(Ordering::SeqCst) == calls + 1 && FILTER_CONTEXT.load(Ordering::SeqCst) == 0x66;
    // TargetNameOffset 0 com nome é ignorado sem chamar nada.
    let _ = call_export("FsRtlNotifyFilterReportChange", &[sync, list, target, 0, 0, 0, 1, 1, 0, 0x55]);
    let ignored = request.pending() && FILTER_CALLS.load(Ordering::SeqCst) == calls + 1;
    // O contexto aceito conclui com o registro relativo (22 bytes, sem preenchimento final).
    report(0x55);
    let accepted = request.completed(0, 22) && request.record(0) == (0, 1, units("a.txt"));
    assert(refused && ignored && accepted, "fsrtl-notify-filter: FsRtlNotifyFilterReportChange consulta o FilterCallback com o FilterContext");
    // Sem FilterContext o FilterCallback não é chamado (o caminho do FullReportChange).
    request.arm(0x100);
    let _ = call_export("FsRtlNotifyFilterChangeDirectory", &[sync, list, 0x1234, directory, 0, 0, 1, request.irp, 0, 0, filter]);
    let calls = FILTER_CALLS.load(Ordering::SeqCst);
    report(0);
    assert(request.completed(0, 22) && FILTER_CALLS.load(Ordering::SeqCst) == calls, "fsrtl-notify-filter: FilterContext NULL nao chama o FilterCallback");
    // Sem FullTargetName: o NOTIFY_CHANGE de SubjectContext == TargetContext
    // recebe só o StreamName, sem CompletionFilter.
    request.arm(0x100);
    let _ = call_export("FsRtlNotifyFilterChangeDirectory", &[sync, list, 0x1234, directory, 0, 0, 1, request.irp, 0, 0, filter]);
    let _ = call_export("FsRtlNotifyFilterReportChange", &[sync, list, 0, 0, stream, 0, 0, 3, 0, 0]);
    assert(request.completed(0, 16) && request.record(0) == (0, 3, units("s1")), "fsrtl-notify-filter: sem FullTargetName o registro leva o StreamName");
    let _ = call_export("FsRtlNotifyCleanup", &[sync, list, 0x1234]);
    let _ = call_export("FsRtlNotifyUninitializeSync", &[sync_cell]);
    request.free();
    for address in [stream, target, directory, list, sync_cell] {
        guest::free_bytes(address);
    }
}

fn notify_lite(assert: Assert, call_export: CallExport) {
    let sync_cell = guest::alloc_bytes(8);
    let sync = at::<nt::Field<u64>>(sync_cell);
    let (list, extended_list, small_list) = (new_list(), new_list(), new_list());
    let (name_b, name_old, name_new, name_e) = (unicode("b.txt"), unicode("old"), unicode("new"), unicode("e.txt"));
    let request = NotifyIrp::new();
    let change = |list: u64, context: u64, flags: u64, irp: u64| call_export("FsRtlNotifyFilterChangeDirectoryLite", &[sync_cell, list, context, flags, 1, irp, 0, 0, 0]);
    let report = |list: u64, name: u64, action: u64, flags: u64, extended: u64| call_export("FsRtlNotifyFilterReportChangeLiteEx", &[sync_cell, list, name, 0, 1, action, 0, 0, flags, extended]);

    // O NOTIFY_SYNC nasce na primeira chamada; o IRP fica pendente.
    request.arm(0x100);
    change(list, 0x4321, 1, request.irp);
    let created = sync.get() != 0 && request.pending();
    report(list, name_b, 1, 1, 0);
    assert(created && request.completed(0, 22) && request.record(0) == (0, 1, units("b.txt")), "fsrtl-notify-filter: Lite cria o NOTIFY_SYNC e conclui com FILE_NOTIFY_INFORMATION");
    // Fora do diretório (flags 0) exige WatchTree; RENAMED_OLD_NAME segura a
    // conclusão até o próximo registro, e os dois saem encadeados.
    request.arm(0x100);
    change(list, 0x4321, 1, request.irp);
    report(list, name_old, 4, 0, 0);
    let held = request.pending();
    report(list, name_new, 5, 0, 0);
    let pair = request.completed(0, 38) && request.record(0) == (20, 4, units("old")) && request.record(20) == (0, 5, units("new"));
    assert(held && pair, "fsrtl-notify-filter: Lite segura o RENAMED_OLD_NAME e encadeia o par alinhado a 4");
    // Registros estendidos (flag 4): cabeçalho de 0x54 com os campos do chamador.
    let extended = guest::alloc_bytes(0x60);
    at::<nt::Field<u32>>(extended).set(0x50);
    let fields: Vec<u8> = (8u8..0x50).collect();
    guest::write_bytes(extended + 8, &fields);
    let wide = NotifyIrp::new();
    wide.arm(0x100);
    change(extended_list, 0x99, 5, wide.irp);
    at::<nt::Field<u32>>(extended).set(0x4F);
    report(extended_list, name_e, 1, 1, extended);
    let short_ignored = wide.pending();
    at::<nt::Field<u32>>(extended).set(0x50);
    report(extended_list, name_e, 1, 1, extended);
    let name: Vec<u16> = (0..5).map(|index| at::<nt::Field<u16>>(wide.out + 0x54 + index * 2).get()).collect();
    let header_ok = at::<nt::Field<u32>>(wide.out).get() == 0 && at::<nt::Field<u32>>(wide.out + 4).get() == 1 && guest::read_bytes(wide.out + 8, 0x48) == fields && at::<nt::Field<u32>>(wide.out + 0x50).get() == 10;
    assert(short_ignored && wide.completed(0, 0x54 + 10) && header_ok && name == units("e.txt"), "fsrtl-notify-filter: Lite estendido grava FILE_NOTIFY_EXTENDED_INFORMATION");
    // Buffer pequeno: o registro não cabe e o IRP sai com STATUS_NOTIFY_ENUM_DIR.
    let small = NotifyIrp::new();
    small.arm(16);
    change(small_list, 0x77, 1, small.irp);
    report(small_list, name_b, 1, 1, 0);
    assert(small.completed(STATUS_NOTIFY_ENUM_DIR, 0), "fsrtl-notify-filter: Lite sem espaco conclui com STATUS_NOTIFY_ENUM_DIR");
    // Sem IRP: todo NOTIFY_CHANGE da lista fica DELETE_PENDING.
    request.arm(0x100);
    change(list, 0x4321, 1, request.irp);
    change(list, 0x4321, 1, 0);
    let deleted = request.completed(STATUS_DELETE_PENDING, 0);
    request.arm(0x100);
    change(list, 0x4321, 1, request.irp);
    assert(deleted && request.completed(STATUS_DELETE_PENDING, 0), "fsrtl-notify-filter: Lite sem IRP marca DELETE_PENDING");
    for (list, context) in [(list, 0x4321), (extended_list, 0x99), (small_list, 0x77)] {
        let _ = call_export("FsRtlNotifyCleanup", &[sync.get(), list, context]);
    }
    let lists_empty = [list, extended_list, small_list].iter().all(|&list| at::<nt::ListEntry>(list).flink.get() == list);
    let _ = call_export("FsRtlNotifyUninitializeSync", &[sync_cell]);
    assert(lists_empty && sync.get() == 0, "fsrtl-notify-filter: Cleanup e UninitializeSync desfazem o Lite");
    request.free();
    wide.free();
    small.free();
    for address in [extended, name_e, name_new, name_old, name_b, small_list, extended_list, list, sync_cell] {
        guest::free_bytes(address);
    }
}
