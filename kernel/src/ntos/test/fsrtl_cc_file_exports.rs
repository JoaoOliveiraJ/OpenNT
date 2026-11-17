//! Autoteste dos exports de FsRtl, Cc, Io (lado de arquivo) e Ob que eram
//! os últimos imports de drivers reais (mup.sys, udfs.sys, dfsc.sys,
//! csc.sys, vhdmp.sys, spaceport.sys, crashdmp.sys, srv2.sys, appid.sys):
//! o MCB de 32 bits e o FsRtlLookupLastLargeMcbEntry, a tabela do MUP, o
//! FsRtlNotifyCleanupAll, o FsRtlRemoveDotsFromPath, os recursos do volume
//! pelo Filter Manager, o FsRtlQueryCachedVdl, as páginas sujas do volume e o
//! limite de páginas sujas do Cc, os parâmetros de create e o FsTrackOffset
//! do IRP, ZwSetEaFile, ZwNotifyChangeDirectoryFile, NtSetInformationFile,
//! NtFsControlFile e ZwCreateSymbolicLinkObject.
//!
//! Cada export é chamado pelo trampolim nativo (ABI MS x64). Os valores
//! esperados seguem o ntoskrnl 19041: os do FsRtlRemoveDotsFromPath foram
//! medidos na própria rotina executada num emulador (status, NewLength e o
//! buffer inteiro depois da chamada); os demais seguem os caminhos lidos na
//! desmontagem. Os pedidos de arquivo vão a um file system sintético (um
//! DRIVER_OBJECT com IRP_MJ_SET_EA, IRP_MJ_DIRECTORY_CONTROL e
//! IRP_MJ_FILE_SYSTEM_CONTROL) por um stream file object com handle de
//! kernel.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::{types as nt, NtStruct};
use crate::ntos::mm::guest_memory as guest;

type Assert = fn(bool, &str);

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(0xDEAD_DEAD_DEAD_DEAD)
}

fn status(name: &str, arguments: &[u64]) -> u32 {
    call(name, arguments) as u32
}

fn at<T: NtStruct>(address: u64) -> &'static T {
    // SAFETY: blocos alocados pelo teste com o tamanho do tipo ou objetos vivos.
    unsafe { T::at(address) }
}

fn zeroed(size: u64) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    block
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn unicode_string(text: &str) -> u64 {
    let units = wide(text);
    let buffer = zeroed(units.len() as u64 * 2 + 2);
    crate::ntos::rtl::guest_strings::write_wide_string(buffer, text);
    let string = zeroed(nt::UnicodeString::SIZE);
    at::<nt::UnicodeString>(string).length.set(units.len() as u16 * 2);
    at::<nt::UnicodeString>(string).maximum_length.set(units.len() as u16 * 2 + 2);
    at::<nt::UnicodeString>(string).buffer.set(buffer);
    string
}

fn object_attributes(name: &str, attributes: u32) -> u64 {
    let block = zeroed(nt::ObjectAttributes::SIZE);
    let object = at::<nt::ObjectAttributes>(block);
    object.length.set(nt::ObjectAttributes::SIZE as u32);
    object.object_name.set(unicode_string(name));
    object.attributes.set(attributes);
    block
}

/// Endereço de uma rotina `extern "win64"` do teste (chamada pelo kernel).
fn routine(address: usize) -> u64 {
    address as u64
}

pub fn run(assert: Assert) {
    mcb_32(assert);
    mup_register(assert);
    notify_cleanup_all(assert);
    remove_dots(assert);
    supported_features(assert);
    volume_dirty_data(assert);
    irp_file_parameters(assert);
    file_system_requests(assert);
    set_information_file(assert);
    symbolic_link_create(assert);
}

// ---- FsRtlInitializeMcb / FsRtlAddMcbEntry / FsRtlLookupLastLargeMcbEntry ---------

fn mcb_32(assert: Assert) {
    let mcb = zeroed(nt::extra_fs_fat::LargeMcb::SIZE);
    let outputs = zeroed(0x10);
    let (vbn, lbn) = (outputs, outputs + 8);
    let initialized = call("FsRtlInitializeMcb", &[mcb, 1]);
    let mutex = at::<nt::Field<u64>>(mcb).get();
    let empty = call("FsRtlLookupLastLargeMcbEntry", &[mcb, vbn, lbn]);
    // [0x10, 0x18) -> 0x1000 e [0x20, 0x24) -> 0x2000, com buracos antes de cada um.
    let added = [call("FsRtlAddMcbEntry", &[mcb, 0x10, 0x1000, 8]), call("FsRtlAddMcbEntry", &[mcb, 0x20, 0x2000, 4])];
    guest::write64(vbn, 0xAAAA_AAAA_AAAA_AAAA);
    guest::write64(lbn, 0xAAAA_AAAA_AAAA_AAAA);
    let found = call("FsRtlLookupLastLargeMcbEntry", &[mcb, vbn, lbn]);
    let runs = call("FsRtlNumberOfRunsInLargeMcb", &[mcb]);
    assert(
        initialized == 0 && mutex != 0 && empty == 0 && added == [1, 1] && found == 1 && guest::read64(vbn) == 0x23 && guest::read64(lbn) == 0x2003 && runs == 4,
        "fsrtl-mcb: FsRtlInitializeMcb e FsRtlAddMcbEntry no LARGE_MCB; FsRtlLookupLastLargeMcbEntry da o ultimo VBN e o seu LBN",
    );
    call("FsRtlUninitializeMcb", &[mcb]);
    assert(at::<nt::Field<u64>>(mcb).get() == 0, "fsrtl-mcb: FsRtlUninitializeMcb solta a mutex do MCB");
    guest::free_bytes(outputs);
    guest::free_bytes(mcb);
}

// ---- FsRtlRegisterMupCalls ------------------------------------------------------

static MUP_SEEN: AtomicU64 = AtomicU64::new(0);

extern "win64" fn mup_provider_id(name: u64, provider_id: u64) -> u32 {
    MUP_SEEN.store(name, Ordering::SeqCst);
    guest::write32(provider_id, 0x0051_0003);
    0
}

extern "win64" fn mup_provider_info(_file: u64, _level: u64, _buffer: u64, _size: u64) -> u32 {
    0xC000_0022
}

fn mup_register(assert: Assert) {
    use crate::ntos::fsrtl::small::mup_calls;
    let previous = mup_calls::register(0);
    mup_calls::register(previous);
    let table = zeroed(0x10);
    guest::write64(table, routine(mup_provider_info as extern "win64" fn(u64, u64, u64, u64) -> u32 as usize));
    guest::write64(table + 8, routine(mup_provider_id as extern "win64" fn(u64, u64) -> u32 as usize));
    let id = zeroed(8);
    call("FsRtlRegisterMupCalls", &[table]);
    let by_name = status("FsRtlMupGetProviderIdFromName", &[0x5151, id]);
    let by_file = status("FsRtlMupGetProviderInfoFromFileObject", &[0, 1, 0, 0]);
    call("FsRtlRegisterMupCalls", &[0]);
    let unregistered = status("FsRtlMupGetProviderIdFromName", &[0x5151, id]);
    mup_calls::register(previous);
    assert(
        by_name == 0 && MUP_SEEN.load(Ordering::SeqCst) == 0x5151 && guest::read32(id) == 0x0051_0003 && by_file == 0xC000_0022 && unregistered == 0xC000_00BB,
        "fsrtl-mup-register: FsRtlRegisterMupCalls publica a tabela do MUP (entradas 0 e 1) e NULL a retira",
    );
    guest::free_bytes(id);
    guest::free_bytes(table);
}

// ---- FsRtlNotifyCleanupAll --------------------------------------------------------

fn notify_cleanup_all(assert: Assert) {
    let block = zeroed(0x200);
    let (sync_cell, list_address) = (block, block + 0x10);
    let list = at::<nt::ListEntry>(list_address);
    list.flink.set(list_address);
    list.blink.set(list_address);
    let directories = [unicode_string("\\tsta"), unicode_string("\\tstb")];
    let file = zeroed(nt::FileObject::SIZE);
    let output = zeroed(0x100);
    let irp_size = nt::Irp::SIZE + nt::IoStackLocation::SIZE;
    let irps = [zeroed(irp_size), zeroed(irp_size)];
    for &irp in &irps {
        let (packet, stack) = (at::<nt::Irp>(irp), at::<nt::IoStackLocation>(irp + nt::Irp::SIZE));
        packet.type_.set(6);
        packet.stack_count.set(1);
        packet.current_location.set(1);
        packet.tail.overlay.current_stack_location.set(stack.address());
        packet.user_buffer.set(output);
        packet.tail.overlay.thread.set(crate::ntos::ps::process::get_current_thread());
        stack.major_function.set(0x0C);
        stack.minor_function.set(2);
        stack.parameters.notify_directory.length.set(0x100);
        stack.file_object.set(file);
    }
    call("FsRtlNotifyInitializeSync", &[sync_cell]);
    let sync = guest::read64(sync_cell);
    // Dois diretórios com FsContexts diferentes, cada um com um pedido pendente.
    call("FsRtlNotifyFullChangeDirectory", &[sync, list_address, 0x1234, directories[0], 0, 0, 1, irps[0], 0, 0]);
    call("FsRtlNotifyFullChangeDirectory", &[sync, list_address, 0x5678, directories[1], 0, 0, 1, irps[1], 0, 0]);
    let queued = list.flink.get() != list_address && list.flink.get() != list.blink.get();
    call("FsRtlNotifyCleanupAll", &[sync, list_address]);
    let completed = irps.iter().all(|&irp| at::<nt::Irp>(irp).io_status.status.get() as u32 == 0x10B);
    assert(
        queued && completed && list.flink.get() == list_address && list.blink.get() == list_address,
        "fsrtl-notify-cleanup-all: FsRtlNotifyCleanupAll conclui os pedidos de todos os FsContexts com STATUS_NOTIFY_CLEANUP e esvazia a lista",
    );
    call("FsRtlNotifyUninitializeSync", &[sync_cell]);
    for &irp in &irps {
        guest::free_bytes(irp);
    }
    guest::free_bytes(output);
    guest::free_bytes(file);
    guest::free_bytes(block);
}

// ---- FsRtlRemoveDotsFromPath ------------------------------------------------------

/// (caminho, status, NewLength, buffer depois da chamada) medidos no
/// FsRtlRemoveDotsFromPath do 19041; NewLength 0x5555 = não gravado.
const DOT_CASES: &[(&str, u32, u16, &str)] = &[
    ("\\a\\b\\..", 0, 4, "\\a\0\0\0\0\0"),
    ("\\a\\.\\b", 0, 8, "\\a\\b\0\0"),
    ("\\a\\\\b", 0, 8, "\\a\\b\0"),
    ("\\a\\b\\.", 0, 8, "\\a\\b\0\0"),
    ("\\a\\..", 0, 2, "\\\0\0\0\0"),
    ("\\a\\b\\..\\c\\.\\d\\..\\e", 0, 0xC, "\\a\\c\\e\0\0\0\0\0\0\0\0\0\0\0\0"),
    ("\\a\\..x\\.y", 0, 0x12, "\\a\\..x\\.y"),
    ("\\..", 0xC000_0278, 0x5555, "\\.."),
    ("..\\x", 0xC000_0278, 0x5555, "..\\x"),
    ("\\a\\..\\..\\b", 0xC000_0278, 0x5555, "\\a\\..\\..\\b"),
    ("a\\..\\b", 0xC000_0278, 0x5555, "a\\..\\b"),
];

fn remove_dots(assert: Assert) {
    let buffer = zeroed(0x100);
    let new_length = zeroed(8);
    let mut failures = 0;
    for &(path, expected_status, expected_length, expected) in DOT_CASES {
        let units = wide(path);
        let mut bytes: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        bytes.extend_from_slice(&[0xAA; 8]);
        guest::write_bytes(buffer, &bytes);
        guest::write16(new_length, 0x5555);
        let result = status("FsRtlRemoveDotsFromPath", &[buffer, units.len() as u64 * 2, new_length]);
        let after: Vec<u16> = (0..units.len() as u64).map(|index| guest::read16(buffer + index * 2)).collect();
        let tail_intact = guest::read_bytes(buffer + units.len() as u64 * 2, 8) == [0xAA; 8];
        if result != expected_status || guest::read16(new_length) != expected_length || after != wide(expected) || !tail_intact {
            crate::debug_print!("[teste-fsrtl] RemoveDots '{}': status={:#x} NewLength={:#x} buffer={:x?}", path, result, guest::read16(new_length), after);
            failures += 1;
        }
    }
    assert(failures == 0, "fsrtl-remove-dots: FsRtlRemoveDotsFromPath reescreve o caminho no lugar como o 19041 (status, NewLength e buffer)");
    guest::free_bytes(new_length);
    guest::free_bytes(buffer);
}

// ---- FsRtlGetSupportedFeatures ----------------------------------------------------

static FEATURES_DEVICE: AtomicU64 = AtomicU64::new(0);
static FEATURES_BEFORE: AtomicU64 = AtomicU64::new(u64::MAX);

extern "win64" fn supported_features_routine(device: u64, features: u64) -> u32 {
    FEATURES_DEVICE.store(device, Ordering::SeqCst);
    FEATURES_BEFORE.store(guest::read32(features) as u64, Ordering::SeqCst);
    guest::write32(features, 0x11);
    0x4000_0001
}

fn supported_features(assert: Assert) {
    use crate::drivers::fs::filter_callbacks;
    let features = zeroed(8);
    let previous = filter_callbacks::exchange_callbacks(0);
    guest::write32(features, 0xFFFF_FFFF);
    let without = status("FsRtlGetSupportedFeatures", &[0x7000, features]);
    let zeroed_without = guest::read32(features) == 0;
    let table = zeroed(0x28);
    guest::write64(table + 0x10, routine(supported_features_routine as extern "win64" fn(u64, u64) -> u32 as usize));
    filter_callbacks::exchange_callbacks(table);
    guest::write32(features, 0xFFFF_FFFF);
    let with = status("FsRtlGetSupportedFeatures", &[0x7000, features]);
    filter_callbacks::exchange_callbacks(previous);
    assert(
        without == 0 && zeroed_without && with == 0x4000_0001 && FEATURES_DEVICE.load(Ordering::SeqCst) == 0x7000 && FEATURES_BEFORE.load(Ordering::SeqCst) == 0 && guest::read32(features) == 0x11,
        "fsrtl-filter-features: FsRtlGetSupportedFeatures zera a saida e pergunta ao slot 0x10 do Filter Manager; sem ele, sucesso com zero",
    );
    guest::free_bytes(table);
    guest::free_bytes(features);
}

// ---- CcIsThereDirtyDataEx / CcSetDirtyPageThreshold -------------------------------

fn volume_dirty_data(assert: Assert) {
    use crate::ntos::cc::pin;
    use crate::ntos::test::cc_fixture as fixture;
    let Some(f) = fixture::create(0x4_0000) else {
        assert(false, "cc-volume-dirty-data: fixture");
        return;
    };
    let vpb = zeroed(nt::Vpb::SIZE);
    let other_vpb = zeroed(nt::Vpb::SIZE);
    at::<nt::Vpb>(vpb).device_object.set(f.device);
    at::<nt::Vpb>(other_vpb).device_object.set(0x7FF0_0000);
    let header = zeroed(nt::extra_fsrtl::FsrtlCommonFcbHeader::SIZE);
    let file = at::<nt::FileObject>(f.file);
    file.vpb.set(vpb);
    file.fs_context.set(header);
    let block = zeroed(0x60);
    let (count, offset, bcb, buffer, iosb) = (block, block + 8, block + 0x10, block + 0x18, block + 0x20);
    guest::write32(count, 0x77);
    let before = call("CcIsThereDirtyDataEx", &[vpb, count]);
    let _ = call("CcInitializeCacheMap", &[f.file, f.sizes, 1, 0, 0]);
    let map = at::<nt::SectionObjectPointers>(f.pointers).shared_cache_map.get();
    if map == 0 {
        assert(false, "cc-volume-dirty-data: cache map inicializado");
        file.vpb.set(0);
        file.fs_context.set(0);
        fixture::destroy(f);
        return;
    }
    call("CcSetDirtyPageThreshold", &[f.file, 0x20]);
    let threshold = at::<nt::extra_cc::SharedCacheMap>(map).dirty_page_threshold.get() == 0x20 && at::<nt::extra_fsrtl::FsrtlCommonFcbHeader>(header).flags.get() & 0x04 != 0;
    assert(threshold, "cc-volume-dirty-data: CcSetDirtyPageThreshold grava o limite no SHARED_CACHE_MAP e liga FSRTL_FLAG_LIMIT_MODIFIED_PAGES");
    let clean = call("CcIsThereDirtyDataEx", &[vpb, count]);
    // Duas páginas sujas do arquivo (BCBs em páginas diferentes).
    let mut pinned = true;
    for page_offset in [0x1100i64, 0x5000] {
        at::<nt::LargeInteger>(offset).quad_part.set(page_offset);
        pinned &= pin::pin_read(f.file, offset, 0x80, 1, bcb, buffer).is_ok_and(|done| done);
        let pinned_bcb = guest::read64(bcb);
        let _ = call("CcSetDirtyPinnedData", &[pinned_bcb, 0]);
        let _ = call("CcUnpinData", &[pinned_bcb]);
    }
    let dirty = call("CcIsThereDirtyDataEx", &[vpb, count]);
    let pages = guest::read32(count);
    let without_count = call("CcIsThereDirtyDataEx", &[vpb, 0]);
    let elsewhere = call("CcIsThereDirtyDataEx", &[other_vpb, count]);
    // Um arquivo temporário conta no Ex (o mapa do volume soma todos), não no CcIsThereDirtyData.
    file.flags.atomic().fetch_or(0x8000, Ordering::SeqCst);
    let temporary = (call("CcIsThereDirtyDataEx", &[vpb, 0]), call("CcIsThereDirtyData", &[vpb]));
    file.flags.atomic().fetch_and(!0x8000, Ordering::SeqCst);
    let _ = call("CcFlushCache", &[f.pointers, 0, 0, iosb]);
    guest::write32(count, 0x77);
    let flushed = call("CcIsThereDirtyDataEx", &[vpb, count]);
    assert(
        before == 0 && clean == 0 && pinned && dirty == 1 && pages == 2 && without_count == 1 && elsewhere == 0 && temporary == (1, 0) && flushed == 0 && guest::read32(count) == 0x77,
        "cc-volume-dirty-data: CcIsThereDirtyDataEx soma as paginas sujas do volume do VPB (temporarios inclusive) e nao toca a saida sem elas",
    );
    let _ = call("CcUninitializeCacheMap", &[f.file, 0, 0]);
    file.vpb.set(0);
    file.fs_context.set(0);
    guest::free_bytes(block);
    guest::free_bytes(header);
    guest::free_bytes(other_vpb);
    guest::free_bytes(vpb);
    fixture::destroy(f);
}

// ---- IoSetIrpExtraCreateParameter / IoGetFsTrackOffsetState -----------------------

fn irp_file_parameters(assert: Assert) {
    let block = zeroed(0x30);
    let (list_cell, found, blob, offset) = (block, block + 8, block + 0x10, block + 0x18);
    let irp = call("IoAllocateIrp", &[1, 0]);
    let packet = at::<nt::Irp>(irp);
    let _ = call("FsRtlAllocateExtraCreateParameterList", &[0, list_cell]);
    let list = guest::read64(list_cell);
    let not_create = status("IoSetIrpExtraCreateParameter", &[irp, list]);
    packet.flags.set(packet.flags.get() | 0x80);
    let set = status("IoSetIrpExtraCreateParameter", &[irp, list]);
    let marked = at::<nt::extra_fsrtl::EcpList>(list).flags.get() & 0x08 != 0;
    let again = status("IoSetIrpExtraCreateParameter", &[irp, list]);
    let read_back = status("IoGetIrpExtraCreateParameter", &[irp, found]);
    assert(
        list != 0 && not_create == 0xC000_00EF && set == 0 && packet.user_buffer.get() == list && marked && again == 0xC000_00F0 && read_back == 0 && guest::read64(found) == list,
        "io-irp-file-parameters: IoSetIrpExtraCreateParameter so num IRP de create sem lista anterior, e marca a ECP_LIST como do IRP",
    );
    packet.user_buffer.set(0);
    let _ = call("FsRtlFreeExtraCreateParameterList", &[list]);
    call("IoFreeIrp", &[irp]);

    let irp = call("IoAllocateIrp", &[1, 0]);
    guest::write64(blob, 0x5A5A);
    guest::write64(offset, 0x5A5A);
    let missing = status("IoGetFsTrackOffsetState", &[irp, blob, offset]);
    let untouched = guest::read64(blob) == 0x5A5A && guest::read64(offset) == 0x5A5A;
    let stored = status("IoSetFsTrackOffsetState", &[irp, 0xFFFF_8000_0000_1234, 0x5678]);
    let got = status("IoGetFsTrackOffsetState", &[irp, blob, offset]);
    let values = guest::read64(blob) == 0xFFFF_8000_0000_1234 && guest::read64(offset) == 0x5678;
    let _ = call("IoClearFsTrackOffsetState", &[irp]);
    let cleared = status("IoGetFsTrackOffsetState", &[irp, blob, offset]);
    assert(
        missing == 0xC000_0225 && untouched && stored == 0 && got == 0 && values && cleared == 0xC000_0225,
        "io-irp-file-parameters: IoGetFsTrackOffsetState devolve o blob e o deslocamento da extensao FsTrackOffset; sem ela STATUS_NOT_FOUND",
    );
    call("IoFreeIrp", &[irp]);
    guest::free_bytes(block);
}

// ---- O file system sintético ------------------------------------------------------

/// O que o despacho de teste viu no último IRP.
static SEEN_MAJOR: AtomicU64 = AtomicU64::new(0);
static SEEN_MINOR: AtomicU64 = AtomicU64::new(0);
static SEEN_STACK_FLAGS: AtomicU64 = AtomicU64::new(0);
static SEEN_IRP_FLAGS: AtomicU64 = AtomicU64::new(0);
static SEEN_LENGTH: AtomicU64 = AtomicU64::new(0);
static SEEN_SECOND: AtomicU64 = AtomicU64::new(0);
static SEEN_CODE: AtomicU64 = AtomicU64::new(0);
static SEEN_SYSTEM: AtomicU64 = AtomicU64::new(0);
static SEEN_USER: AtomicU64 = AtomicU64::new(0);
static SEEN_FILE: AtomicU64 = AtomicU64::new(0);
static SEEN_DATA: AtomicU64 = AtomicU64::new(0);
static CALLS: AtomicU64 = AtomicU64::new(0);
/// O que o despacho faz: 1/2/3 regiões do FSCTL_QUERY_FILE_REGIONS (duas
/// válidas, uma válida, falha), 4 o FSCTL de teste, 5 a notificação já
/// concluída, 6 a notificação pendente.
static MODE: AtomicU64 = AtomicU64::new(0);
static PENDING_IRP: AtomicU64 = AtomicU64::new(0);

const TEST_FSCTL: u32 = 0x0009_1FC0;
const QUERY_FILE_REGIONS: u32 = 0x0009_0284;

/// Um FILE_NOTIFY_INFORMATION "a.b" (FILE_ACTION_ADDED), 0x12 bytes.
fn notify_record() -> Vec<u8> {
    let mut record = Vec::new();
    record.extend_from_slice(&0u32.to_le_bytes());
    record.extend_from_slice(&1u32.to_le_bytes());
    record.extend_from_slice(&6u32.to_le_bytes());
    for unit in wide("a.b") {
        record.extend_from_slice(&unit.to_le_bytes());
    }
    record
}

fn complete(packet: u64, status: u32, information: u64) -> u32 {
    at::<nt::Irp>(packet).io_status.status.set(status as i32);
    at::<nt::Irp>(packet).io_status.information.set(information);
    crate::ntos::io::io_manager::iof_complete_request(packet);
    status
}

extern "win64" fn file_system_dispatch(_device: u64, packet: u64) -> u32 {
    let irp = at::<nt::Irp>(packet);
    let stack = at::<nt::IoStackLocation>(irp.tail.overlay.current_stack_location.get());
    let major = stack.major_function.get();
    CALLS.fetch_add(1, Ordering::SeqCst);
    SEEN_MAJOR.store(major as u64, Ordering::SeqCst);
    SEEN_MINOR.store(stack.minor_function.get() as u64, Ordering::SeqCst);
    SEEN_STACK_FLAGS.store(stack.flags.get() as u64, Ordering::SeqCst);
    SEEN_IRP_FLAGS.store(irp.flags.get() as u64, Ordering::SeqCst);
    SEEN_SYSTEM.store(irp.associated_irp.system_buffer.get(), Ordering::SeqCst);
    SEEN_USER.store(irp.user_buffer.get(), Ordering::SeqCst);
    SEEN_FILE.store(stack.file_object.get(), Ordering::SeqCst);
    let system = irp.associated_irp.system_buffer.get();
    match major {
        0x08 => {
            // IRP_MJ_SET_EA: o comprimento e os primeiros bytes da lista vista.
            let length = stack.parameters.set_ea.length.get();
            SEEN_LENGTH.store(length as u64, Ordering::SeqCst);
            let source = if system != 0 { system } else { irp.user_buffer.get() };
            SEEN_DATA.store(if source != 0 { guest::read64(source) } else { 0 }, Ordering::SeqCst);
            complete(packet, 0, 0)
        }
        0x0C => {
            let notify = &stack.parameters.notify_directory;
            SEEN_LENGTH.store(notify.length.get() as u64, Ordering::SeqCst);
            SEEN_SECOND.store(notify.completion_filter.get() as u64, Ordering::SeqCst);
            if MODE.load(Ordering::SeqCst) == 6 {
                // IoMarkIrpPending: o pedido fica até o teste relatar a mudança.
                stack.control.set(stack.control.get() | 0x01);
                PENDING_IRP.store(packet, Ordering::SeqCst);
                return 0x103;
            }
            let record = notify_record();
            guest::write_bytes(system, &record);
            complete(packet, 0, record.len() as u64)
        }
        0x0D => {
            let control = &stack.parameters.file_system_control;
            SEEN_CODE.store(control.fs_control_code.get() as u64, Ordering::SeqCst);
            SEEN_LENGTH.store(control.input_buffer_length.get() as u64, Ordering::SeqCst);
            SEEN_SECOND.store(control.output_buffer_length.get() as u64, Ordering::SeqCst);
            match MODE.load(Ordering::SeqCst) {
                1 | 2 => {
                    let input = at::<nt::extra_fsrtl::FileRegionInput>(system);
                    SEEN_DATA.store((input.file_offset.get() == 0 && input.length.get() == i64::MAX && input.desired_usage.get() == 1) as u64, Ordering::SeqCst);
                    let output = at::<nt::extra_fsrtl::FileRegionOutput>(system);
                    output.flags.set(0);
                    output.total_region_entry_count.set(2);
                    output.region_entry_count.set(2);
                    let regions = [(0i64, 0x1000i64, 1u32), (0x3000, 0x2000, if MODE.load(Ordering::SeqCst) == 1 { 1 } else { 0 })];
                    for (index, &(file_offset, length, usage)) in regions.iter().enumerate() {
                        let region = at::<nt::extra_fsrtl::FileRegionInfo>(output.region[0].address() + index as u64 * nt::extra_fsrtl::FileRegionInfo::SIZE);
                        region.file_offset.set(file_offset);
                        region.length.set(length);
                        region.usage.set(usage);
                    }
                    complete(packet, 0, 0x40)
                }
                4 => {
                    SEEN_DATA.store(guest::read32(system) as u64, Ordering::SeqCst);
                    guest::write_bytes(system, b"FSCTL-OK");
                    complete(packet, 0, 8)
                }
                _ => complete(packet, 0xC000_0010, 0),
            }
        }
        _ => complete(packet, 0xC000_0010, 0),
    }
}

/// O dispositivo sintético e um stream file object nele, com handle de kernel.
struct FileSystem {
    driver: u64,
    device: u64,
    file: u64,
    handle: u64,
}

fn file_system() -> Option<FileSystem> {
    let driver = zeroed(nt::DriverObject::SIZE);
    let device = zeroed(nt::DeviceObject::SIZE);
    let dispatch = routine(file_system_dispatch as extern "win64" fn(u64, u64) -> u32 as usize);
    for major in [0x08usize, 0x0C, 0x0D] {
        at::<nt::DriverObject>(driver).major_function[major].set(dispatch);
    }
    let device_object = at::<nt::DeviceObject>(device);
    device_object.type_.set(3);
    device_object.driver_object.set(driver);
    device_object.device_type.set(8);
    device_object.stack_size.set(1);
    let handle_cell = zeroed(8);
    let file = call("IoCreateStreamFileObjectEx", &[0, device, handle_cell]);
    let handle = guest::read64(handle_cell);
    guest::free_bytes(handle_cell);
    (file != 0 && file != 0xDEAD_DEAD_DEAD_DEAD && handle != 0).then_some(FileSystem { driver, device, file, handle })
}

fn release(system: FileSystem) {
    call("ZwClose", &[system.handle]);
    call("ObfDereferenceObject", &[system.file]);
    // O CLOSE do stream solta o dispositivo; só então a memória volta.
    if at::<nt::DeviceObject>(system.device).reference_count.get() == 0 {
        guest::free_bytes(system.device);
        guest::free_bytes(system.driver);
    }
}

fn file_system_requests(assert: Assert) {
    let Some(system) = file_system() else {
        assert(false, "io-file-services: stream file object no file system sintetico");
        return;
    };
    cached_vdl(assert, &system);
    fs_control(assert, &system);
    set_ea(assert, &system);
    notify_change(assert, &system);
    release(system);
}

// ---- FsRtlQueryCachedVdl ------------------------------------------------------------

fn cached_vdl(assert: Assert, system: &FileSystem) {
    let vdl = zeroed(8);
    let mut results = [(0u32, 0i64); 3];
    for (index, mode) in [1u64, 2, 3].into_iter().enumerate() {
        MODE.store(mode, Ordering::SeqCst);
        guest::write64(vdl, 0x7777);
        results[index] = (status("FsRtlQueryCachedVdl", &[system.file, vdl]), guest::read64(vdl) as i64);
    }
    let request_shape = SEEN_MAJOR.load(Ordering::SeqCst) == 0x0D && SEEN_MINOR.load(Ordering::SeqCst) == 0 && SEEN_CODE.load(Ordering::SeqCst) == QUERY_FILE_REGIONS as u64 && SEEN_LENGTH.load(Ordering::SeqCst) == 0x18 && SEEN_SECOND.load(Ordering::SeqCst) == 0x40 && SEEN_FILE.load(Ordering::SeqCst) == system.file;
    MODE.store(1, Ordering::SeqCst);
    let _ = call("FsRtlQueryCachedVdl", &[system.file, vdl]);
    let input_ok = SEEN_DATA.load(Ordering::SeqCst) == 1;
    assert(
        results == [(0, 0x5000), (0, 0x1000), (0xC000_0010, 0x7777)] && request_shape && input_ok,
        "fsrtl-cached-vdl: FsRtlQueryCachedVdl manda o FSCTL_QUERY_FILE_REGIONS {0, MAXLONGLONG, dados validos em cache} e devolve o fim da ultima regiao valida",
    );
    guest::free_bytes(vdl);
}

// ---- NtFsControlFile ------------------------------------------------------------------

fn fs_control(assert: Assert, system: &FileSystem) {
    let block = zeroed(0x40);
    let (iosb, input, output) = (block, block + 0x10, block + 0x20);
    guest::write_bytes(input, b"TST!");
    MODE.store(4, Ordering::SeqCst);
    let result = crate::ntos::ps::previous_mode::with_kernel(|| status("NtFsControlFile", &[system.handle, 0, 0, 0, iosb, TEST_FSCTL as u64, input, 4, output, 8])).unwrap_or(1);
    let flags = SEEN_IRP_FLAGS.load(Ordering::SeqCst);
    assert(
        result == 0
            && SEEN_MAJOR.load(Ordering::SeqCst) == 0x0D
            && SEEN_MINOR.load(Ordering::SeqCst) == 0
            && SEEN_CODE.load(Ordering::SeqCst) == TEST_FSCTL as u64
            && SEEN_LENGTH.load(Ordering::SeqCst) == 4
            && SEEN_SECOND.load(Ordering::SeqCst) == 8
            && SEEN_DATA.load(Ordering::SeqCst) == u32::from_le_bytes(*b"TST!") as u64
            && flags & 0x870 == 0x870
            && at::<nt::IoStatusBlock>(iosb).status.get() == 0
            && at::<nt::IoStatusBlock>(iosb).information.get() == 8
            && guest::read_bytes(output, 8) == b"FSCTL-OK",
        "io-file-services: NtFsControlFile de modo kernel manda IRP_MJ_FILE_SYSTEM_CONTROL buffered com IRP_DEFER_IO_COMPLETION e copia a saida",
    );
    guest::free_bytes(block);
}

// ---- ZwSetEaFile -----------------------------------------------------------------------

/// Um FILE_FULL_EA_INFORMATION "ABC" = "xy" (14 bytes); com `broken` o
/// EaNameLength passa do fim do buffer.
fn ea_list(broken: bool) -> Vec<u8> {
    let mut entry = Vec::new();
    entry.extend_from_slice(&0u32.to_le_bytes());
    entry.push(0);
    entry.push(if broken { 0x40 } else { 3 });
    entry.extend_from_slice(&2u16.to_le_bytes());
    entry.extend_from_slice(b"ABC\0xy");
    entry
}

fn set_ea(assert: Assert, system: &FileSystem) {
    let block = zeroed(0x40);
    let (iosb, buffer) = (block, block + 0x10);
    at::<nt::DeviceObject>(system.device).flags.set(0x04);
    guest::write_bytes(buffer, &ea_list(false));
    let calls = CALLS.load(Ordering::SeqCst);
    let valid = status("ZwSetEaFile", &[system.handle, iosb, buffer, 14]);
    let buffered = SEEN_MAJOR.load(Ordering::SeqCst) == 0x08 && SEEN_LENGTH.load(Ordering::SeqCst) == 14 && SEEN_SYSTEM.load(Ordering::SeqCst) != 0 && SEEN_SYSTEM.load(Ordering::SeqCst) != buffer && SEEN_DATA.load(Ordering::SeqCst) == guest::read64(buffer) && SEEN_IRP_FLAGS.load(Ordering::SeqCst) & 0x34 == 0x34;
    let sent = CALLS.load(Ordering::SeqCst) == calls + 1;
    // Lista inconsistente num dispositivo buffered: o I/O Manager recusa sem IRP.
    guest::write_bytes(buffer, &ea_list(true));
    guest::write64(iosb + 8, 0x99);
    let refused = status("ZwSetEaFile", &[system.handle, iosb, buffer, 14]);
    let refused_iosb = at::<nt::IoStatusBlock>(iosb).status.get() as u32 == 0x8000_0014 && at::<nt::IoStatusBlock>(iosb).information.get() == 0;
    let not_sent = CALLS.load(Ordering::SeqCst) == calls + 1;
    // Sem DO_BUFFERED_IO/DO_DIRECT_IO a lista vai crua no UserBuffer, sem conferência.
    at::<nt::DeviceObject>(system.device).flags.set(0);
    let neither = status("ZwSetEaFile", &[system.handle, iosb, buffer, 14]);
    let raw = SEEN_USER.load(Ordering::SeqCst) == buffer && SEEN_SYSTEM.load(Ordering::SeqCst) == 0;
    assert(
        valid == 0 && buffered && sent && refused == 0x8000_0014 && refused_iosb && not_sent && neither == 0 && raw,
        "io-file-services: ZwSetEaFile manda IRP_MJ_SET_EA com a copia conferida pelo IoCheckEaBufferValidity no dispositivo buffered, ou o buffer cru",
    );
    guest::free_bytes(block);
}

// ---- ZwNotifyChangeDirectoryFile -------------------------------------------------------

fn notify_change(assert: Assert, system: &FileSystem) {
    let block = zeroed(0x100);
    let (iosb, buffer, event_cell, timeout) = (block, block + 0x20, block + 0x80, block + 0x88);
    at::<nt::DeviceObject>(system.device).flags.set(0x04);
    let record = notify_record();
    // Concluído pelo file system na hora.
    MODE.store(5, Ordering::SeqCst);
    let immediate = status("ZwNotifyChangeDirectoryFile", &[system.handle, 0, 0, 0, iosb, buffer, 0x40, 3, 1]);
    let shape = SEEN_MAJOR.load(Ordering::SeqCst) == 0x0C && SEEN_MINOR.load(Ordering::SeqCst) == 2 && SEEN_STACK_FLAGS.load(Ordering::SeqCst) == 1 && SEEN_LENGTH.load(Ordering::SeqCst) == 0x40 && SEEN_SECOND.load(Ordering::SeqCst) == 3 && SEEN_IRP_FLAGS.load(Ordering::SeqCst) & 0x70 == 0x70 && SEEN_USER.load(Ordering::SeqCst) == buffer;
    let delivered = at::<nt::IoStatusBlock>(iosb).status.get() == 0 && at::<nt::IoStatusBlock>(iosb).information.get() == record.len() as u64 && guest::read_bytes(buffer, record.len()) == record;
    assert(immediate == 0 && shape && delivered, "io-file-services: ZwNotifyChangeDirectoryFile manda IRP_MN_NOTIFY_CHANGE_DIRECTORY (SL_WATCH_TREE, filtro, SystemBuffer) e copia os registros");
    // Pendente num arquivo assíncrono: STATUS_PENDING; a conclusão grava o IOSB e sinaliza o evento.
    let _ = call("ZwCreateEvent", &[event_cell, 0x1F_0003, 0, 0, 0]);
    let event = guest::read64(event_cell);
    guest::write_bytes(buffer, &[0u8; 0x40]);
    guest::write64(iosb, 0xAAAA_AAAA);
    guest::write64(iosb + 8, 0xAAAA_AAAA);
    MODE.store(6, Ordering::SeqCst);
    PENDING_IRP.store(0, Ordering::SeqCst);
    let pending = status("ZwNotifyChangeDirectoryFile", &[system.handle, event, 0, 0, iosb, buffer, 0x40, 1, 0]);
    let waiting = guest::read64(iosb) == 0xAAAA_AAAA && status("ZwWaitForSingleObject", &[event, 0, timeout]) == 0x102 && SEEN_STACK_FLAGS.load(Ordering::SeqCst) == 0;
    let irp = PENDING_IRP.load(Ordering::SeqCst);
    if irp != 0 {
        guest::write_bytes(at::<nt::Irp>(irp).associated_irp.system_buffer.get(), &record);
        at::<nt::Irp>(irp).io_status.status.set(0);
        at::<nt::Irp>(irp).io_status.information.set(record.len() as u64);
        call("IofCompleteRequest", &[irp, 0]);
    }
    let signaled = status("ZwWaitForSingleObject", &[event, 0, timeout]) == 0;
    let completed = at::<nt::IoStatusBlock>(iosb).status.get() == 0 && at::<nt::IoStatusBlock>(iosb).information.get() == record.len() as u64 && guest::read_bytes(buffer, record.len()) == record;
    assert(
        pending == 0x103 && waiting && irp != 0 && signaled && completed,
        "io-file-services: ZwNotifyChangeDirectoryFile assincrono fica pendente e a conclusao do file system grava o IOSB, copia os registros e sinaliza o evento",
    );
    call("ZwClose", &[event]);
    MODE.store(0, Ordering::SeqCst);
    guest::free_bytes(block);
}

// ---- NtSetInformationFile --------------------------------------------------------------

fn set_information_file(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    let block = zeroed(0x100);
    let (handle_cell, iosb, information, buffer) = (block, block + 0x10, block + 0x20, block + 0x40);
    let attributes = object_attributes("\\FS\\opennt-tst-set.txt", 0x240);
    let created = status("ZwCreateFile", &[handle_cell, 0x12019F, attributes, iosb, 0, 0x80, 3, 3, 0x20, 0, 0]);
    let file = guest::read64(handle_cell);
    guest::write_bytes(buffer, b"OpenNT tst");
    let _ = call("ZwWriteFile", &[file, 0, 0, 0, iosb, buffer, 10, 0, 0]);
    let result = crate::ntos::ps::previous_mode::with_kernel(|| {
        // Uma classe que o caminho Zw deste arquivo recusa: o mesmo status
        // pelos dois exports.
        guest::write64(information, 4);
        let refused = status("NtSetInformationFile", &[file, iosb, information, 8, 14]);
        let zw_refused = status("ZwSetInformationFile", &[file, iosb, information, 8, 14]);
        // FileDispositionInformation (13): DeleteFile = TRUE.
        guest::write64(information, 1);
        let deleted = status("NtSetInformationFile", &[file, iosb, information, 1, 13]);
        (refused, zw_refused, deleted)
    })
    .unwrap_or((1, 0, 1));
    call("ZwClose", &[file]);
    let gone = !memory_file_system::exists("/opennt-tst-set.txt");
    assert(
        created == 0 && result == (0xC000_000D, 0xC000_000D, 0) && gone,
        "io-file-services: NtSetInformationFile de modo kernel recusa a mesma classe e apaga como o ZwSetInformationFile",
    );
    guest::free_bytes(block);
}

// ---- ZwCreateSymbolicLinkObject ------------------------------------------------------

fn symbolic_link_create(assert: Assert) {
    let block = zeroed(0x100);
    let (handle_cell, second_cell, returned, query) = (block, block + 8, block + 0x10, block + 0x20);
    let target_text = "\\Device\\TstTarget";
    let target = unicode_string(target_text);
    let attributes = object_attributes("\\TstLink", 0x240);
    let created = status("ZwCreateSymbolicLinkObject", &[handle_cell, 0xF_0001, attributes, target]);
    let handle = guest::read64(handle_cell);
    let collision = status("ZwCreateSymbolicLinkObject", &[second_cell, 0xF_0001, attributes, target]);
    // O destino lido de volta pelo ZwQuerySymbolicLinkObject.
    let opened = status("ZwOpenSymbolicLinkObject", &[second_cell, 1, attributes]);
    let reader = guest::read64(second_cell);
    let text_buffer = zeroed(0x80);
    at::<nt::UnicodeString>(query).maximum_length.set(0x80);
    at::<nt::UnicodeString>(query).buffer.set(text_buffer);
    let queried = status("ZwQuerySymbolicLinkObject", &[reader, query, returned]);
    let length = at::<nt::UnicodeString>(query).length.get() as u64;
    let text: Vec<u16> = (0..length / 2).map(|index| guest::read16(text_buffer + index * 2)).collect();
    call("ZwClose", &[reader]);
    // Validação do UNICODE_STRING do destino.
    let string = at::<nt::UnicodeString>(target);
    let invalid = |length: u16, maximum: u16| {
        string.length.set(length);
        string.maximum_length.set(maximum);
        status("ZwCreateSymbolicLinkObject", &[second_cell, 0xF_0001, object_attributes("\\TstLinkB", 0x240), target])
    };
    let rejected = [invalid(3, 8), invalid(0, 0), invalid(8, 6), invalid(8, 1)];
    // MaximumLength ímpar perde o bit 0: 8 de 9 cabe.
    let odd_maximum = invalid(8, 9);
    let odd_handle = guest::read64(second_cell);
    call("ZwClose", &[odd_handle]);
    call("ZwClose", &[handle]);
    // O link temporário sai do namespace no último fechamento.
    let after = status("ZwOpenSymbolicLinkObject", &[second_cell, 1, attributes]);
    assert(
        created == 0 && handle != 0 && collision == 0xC000_0035 && opened == 0 && queried == 0 && text == wide(target_text),
        "ob-symbolic-link-create: ZwCreateSymbolicLinkObject cria o link com o destino e recusa o nome repetido",
    );
    assert(
        rejected == [0xC000_000D; 4] && odd_maximum == 0 && after == 0xC000_0034,
        "ob-symbolic-link-create: Length impar, MaximumLength zero ou menor que Length recusados; MaximumLength impar perde o bit 0; o link temporario some no ultimo fechamento",
    );
    guest::free_bytes(text_buffer);
    guest::free_bytes(block);
}
