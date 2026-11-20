//! Autoteste dos exports de Ke, Ex, Po, Mm e Io (lado do IRP) que eram os
//! últimos imports de drivers reais (mmcss.sys, msquic.sys, mssecflt.sys,
//! rdyboost.sys, spaceport.sys, usbaudio.sys, vhdmp.sys, iastorv.sys,
//! msircomm.sys, mup.sys...).
//!
//! Cada export é chamado pelo trampolim nativo (ABI MS x64). Os valores
//! esperados seguem os caminhos do ntoskrnl 19041 lidos na desmontagem
//! (os RVAs estão nos arquivos de cada assunto):
//!
//! - IoSizeOfIrpEx/IoInitializeIrpEx: duas stack locations a mais para o
//!   dispositivo -1 ou com DO_DEVICE_IRP_REQUIRES_EXTENSION, IrpExtension na
//!   CurrentStackLocation; IoCleanupIrp zera o Type e solta a extensão do
//!   pool; IoSetIoAttributionIrp valida as Flags, procura a atribuição do
//!   processo (direto, pela thread ou pela WorkOnBehalfThread) e a grava na
//!   extensão de tipo 6 que o IoGetIoAttributionHandle lê; IoEnqueueIrp põe
//!   a IRP na IrpList da thread dona; IoReportResourceForDetection relata,
//!   acusa o conflito e libera como o IoReportResourceUsage.
//! - ExfReleasePushLockShared/Exclusive contra a palavra do push lock; o
//!   ExEnterCriticalRegionAndAcquireSharedWaitForExclusive (região crítica,
//!   posse compartilhada e o Win32Thread); o ExBlockOnAddressPushLock com
//!   valores diferentes, tamanho inválido, prazo vencido (STATUS_TIMEOUT) e
//!   uma thread de sistema acordada pelo ExUnblockOnAddressPushLockEx, que
//!   também sinaliza um bloco encadeado à mão; o ExGetSystemFirmwareTable
//!   com os provedores 'FIRM' (as tabelas 0xC0000/0xE0000 da memória física)
//!   e 'RSMB' (o SMBIOS do QEMU), assinatura desconhecida e buffer curto.
//! - MmAreMdlPagesCached (pool cacheado, frame de firmware sem PfnExists,
//!   frame impossível) e MmCopyMemory (Flags, cópia virtual entre páginas,
//!   faixa vazia, VA não canônica e sem tradução, cópia física do BIOS).
//! - KeUpdateThreadTag (Tag e Header.Tagged) e KeRaiseUserException (o
//!   quadro de usuário trocado para o despachante da NTDLL, sem quadro nada
//!   muda).
//! - Os pedidos de energia de kernel (criação, tipos aceitos, contadores por
//!   pedido e globais, a exclusão que desconta), o PoNotifyMediaBuffering
//!   pelo work item e o PoCpuIdledSinceLastCallImprecise contra o
//!   PowerState da KPRCB.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::ntos::inc::field::{Field, NtStruct};
use crate::ntos::inc::types::extra_io::IrpExtensionField;
use crate::ntos::inc::types::{DeviceObject, DevobjExtension, DriverObject, Eprocess, Ethread, Irp, Kthread, KtrapFrame, Teb};
use crate::ntos::ke::{clock, wait};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ps::{kernel_threads, process, scheduler};

type Assert = fn(bool, &str);

const STATUS_TIMEOUT: u64 = 0x102;
const STATUS_INVALID_PARAMETER: u64 = 0xC000_000D;
const STATUS_NOT_IMPLEMENTED: u64 = 0xC000_0002;
const STATUS_CONFLICTING_ADDRESSES: u64 = 0xC000_0018;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xC000_0023;
const STATUS_NOT_SUPPORTED: u64 = 0xC000_00BB;
const STATUS_INVALID_PARAMETER_1: u64 = 0xC000_00EF;
const STATUS_INVALID_PARAMETER_4: u64 = 0xC000_00F2;
const STATUS_INVALID_ADDRESS: u64 = 0xC000_0141;
const STATUS_NOT_FOUND: u64 = 0xC000_0225;
/// O valor devolvido quando o export não está registrado.
const MISSING: u64 = 0xDEAD_DEAD_DEAD_DEAD;

fn call(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).unwrap_or(MISSING)
}

/// O NTSTATUS (32 bits baixos) ou MISSING.
fn status(name: &str, arguments: &[u64]) -> u64 {
    super::phase6::call_export(name, arguments).map_or(MISSING, |value| value as u32 as u64)
}

fn zeroed(size: u64) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![0u8; size as usize]);
    block
}

fn filled(size: u64, byte: u8) -> u64 {
    let block = guest::alloc_bytes(size);
    guest::write_bytes(block, &alloc::vec![byte; size as usize]);
    block
}

fn irp(address: u64) -> &'static Irp {
    // SAFETY: IRP de teste vivo.
    unsafe { Irp::at(address) }
}

pub fn run(assert: Assert) {
    irp_ex(assert);
    io_attribution(assert);
    enqueue_irp(assert);
    report_for_detection(assert);
    push_lock_release(assert);
    resource_wait_exclusive(assert);
    push_lock_address_wait(assert);
    firmware_tables(assert);
    system_information_classes(assert);
    set_system_information_classes(assert);
    mdl_pages_cached(assert);
    copy_memory(assert);
    thread_tag(assert);
    raise_user_exception(assert);
    power_requests(assert);
    processor_power(assert);
}

// ---- IoSizeOfIrpEx / IoInitializeIrpEx / IoCleanupIrp -----------------------

/// Um DEVICE_OBJECT sintético com Flags e um DRIVER_OBJECT (sem devnode).
fn synthetic_device(flags: u32) -> (u64, u64, u64) {
    let (driver, device, extension) = (zeroed(DriverObject::SIZE), zeroed(DeviceObject::SIZE), zeroed(DevobjExtension::SIZE));
    // SAFETY: blocos zerados recém-alocados com o tamanho de cada tipo.
    let device_object = unsafe { DeviceObject::at(device) };
    device_object.driver_object.set(driver);
    device_object.stack_size.set(1);
    device_object.flags.set(flags);
    device_object.device_object_extension.set(extension);
    (driver, device, extension)
}

fn free_device((driver, device, extension): (u64, u64, u64)) {
    for block in [driver, device, extension] {
        guest::free_bytes(block);
    }
}

fn irp_ex(assert: Assert) {
    let plain = synthetic_device(0);
    let extended = synthetic_device(0x0800_0000);
    let sizes = [call("IoSizeOfIrpEx", &[0, 3]) & 0xFFFF, call("IoSizeOfIrpEx", &[u64::MAX, 3]) & 0xFFFF, call("IoSizeOfIrpEx", &[extended.1, 3]) & 0xFFFF, call("IoSizeOfIrpEx", &[plain.1, 3]) & 0xFFFF, call("IoSizeOfIrpEx", &[0, 0]) & 0xFFFF];
    assert(sizes == [0x1A8, 0x238, 0x238, 0x1A8, 0xD0], "io-irp-ex: IoSizeOfIrpEx soma duas stack locations para o dispositivo -1 ou com DO_DEVICE_IRP_REQUIRES_EXTENSION");
    let packet = filled(0x238, 0xCC);
    call("IoInitializeIrpEx", &[packet, u64::MAX, 0x238, 3]);
    let request = irp(packet);
    let located = (request.type_.get(), request.size.get(), request.stack_count.get(), request.current_location.get(), request.tail.overlay.current_stack_location.get() - packet, request.irp_extension().get() - packet, request.allocation_flags.get());
    let plain_packet = filled(0x1A8, 0xCC);
    call("IoInitializeIrpEx", &[plain_packet, plain.1, 0x1A8, 3]);
    let plain_request = irp(plain_packet);
    assert(
        located == (6, 0x238, 3, 4, 0x1A8, 0x1A8, 0) && plain_request.irp_extension().get() == 0 && plain_request.type_.get() == 6 && guest::read8(plain_packet + 0x30) == 0,
        "io-irp-ex: IoInitializeIrpEx zera o pacote e aponta IrpExtension para a CurrentStackLocation so com a extensao pedida",
    );
    guest::free_bytes(packet);
    guest::free_bytes(plain_packet);
    free_device(plain);
    free_device(extended);
}

// ---- IoSetIoAttributionIrp ---------------------------------------------------

fn io_attribution(assert: Assert) {
    let packet = zeroed(0x1A8);
    call("IoInitializeIrp", &[packet, 0x1A8, 3]);
    let invalid = [status("IoSetIoAttributionIrp", &[packet, 0, 0]), status("IoSetIoAttributionIrp", &[packet, 0, 3]), status("IoSetIoAttributionIrp", &[packet, 0, 4])];
    let current = status("IoSetIoAttributionIrp", &[packet, process::get_current_thread(), 1]);
    assert(invalid == [STATUS_INVALID_PARAMETER; 3] && current == STATUS_NOT_FOUND && irp(packet).irp_extension().get() == 0, "io-attribution-irp: Flags invalidas e o System sem atribuicao de disco (STATUS_NOT_FOUND)");
    // Um processo com atribuição (o handle em +0x18 da atribuição).
    let attribution = zeroed(0x30);
    guest::write64(attribution + 0x18, 0x5150_0000_1234);
    let process_block = zeroed(Eprocess::SIZE);
    // SAFETY: EPROCESS sintético zerado.
    unsafe { Eprocess::at(process_block) }.disk_io_attribution.set(attribution);
    let by_process = status("IoSetIoAttributionIrp", &[packet, process_block, 2]);
    let handle = zeroed(8);
    let queried = status("IoGetIoAttributionHandle", &[packet, handle]);
    let allocated = irp(packet).allocation_flags.get() & 0x40 != 0;
    assert(by_process == 0 && queried == 0 && guest::read64(handle) == 0x5150_0000_1234 && allocated, "io-attribution-irp: a atribuicao do processo vai para a extensao de tipo 6 (IoGetIoAttributionHandle)");
    // Pela thread: a WorkOnBehalfThread aponta para uma thread do processo.
    let (worker, owner) = (zeroed(Ethread::SIZE), zeroed(Ethread::SIZE));
    // SAFETY: ETHREADs sintéticas zeradas.
    unsafe {
        Ethread::at(worker).work_on_behalf_thread.set(owner);
        Ethread::at(owner).tcb.process.set(process_block);
    }
    let second = zeroed(0x1A8);
    call("IoInitializeIrp", &[second, 0x1A8, 3]);
    let by_thread = status("IoSetIoAttributionIrp", &[second, worker, 1]);
    guest::write64(handle, 0);
    let second_queried = status("IoGetIoAttributionHandle", &[second, handle]);
    assert(by_thread == 0 && second_queried == 0 && guest::read64(handle) == 0x5150_0000_1234, "io-attribution-irp: pela thread, a WorkOnBehalfThread atribui ao processo dela");
    // IoCleanupIrp solta a extensão do pool e zera o Type.
    call("IoCleanupIrp", &[packet]);
    call("IoCleanupIrp", &[second]);
    let cleaned = [packet, second].map(|address| (irp(address).type_.get(), irp(address).allocation_flags.get() & 0x40, irp(address).irp_extension().get()));
    assert(cleaned == [(0, 0, 0); 2], "io-irp-ex: IoCleanupIrp zera o Type e libera a extensao alocada");
    for block in [packet, second, attribution, process_block, handle, worker, owner] {
        guest::free_bytes(block);
    }
}

// ---- IoEnqueueIrp ------------------------------------------------------------

fn enqueue_irp(assert: Assert) {
    use crate::ntos::io::threads::thread_requests;
    let thread = zeroed(Ethread::SIZE);
    // SAFETY: ETHREAD sintética zerada: IrpList vazia apontando para si.
    let head = &unsafe { Ethread::at(thread) }.irp_list;
    head.flink.set(head.address());
    head.blink.set(head.address());
    let packet = call("IoAllocateIrp", &[1, 0]);
    irp(packet).tail.overlay.thread.set(thread);
    call("IoEnqueueIrp", &[packet]);
    let listed = thread_requests::of_thread(thread).unwrap_or_default();
    assert(listed == [packet] && irp(packet).thread_list_entry.blink.get() == head.address(), "io-enqueue-irp: IoEnqueueIrp poe a IRP na IrpList da thread dona");
    let _ = thread_requests::remove(packet, thread);
    call("IoFreeIrp", &[packet]);
    guest::free_bytes(thread);
}

// ---- IoReportResourceForDetection --------------------------------------------

fn report_for_detection(assert: Assert) {
    use crate::ntos::io::pnp::resources;
    let first = synthetic_device(0);
    let second = synthetic_device(0);
    let conflict = zeroed(8);
    let list = resources::CmList { interface_type: 0, bus_number: 0, resources: alloc::vec![resources::Resource { resource_type: resources::resource_type::MEMORY, share: 1, flags: 0, start: 0x34_0000_0000, length: 0x1000, extra: [0; 3] }] }.write();
    let report = |device: (u64, u64, u64), cm: u64| -> (u64, u8) {
        guest::write8(conflict, 0x55);
        (status("IoReportResourceForDetection", &[device.0, 0, 0, device.1, cm, if cm != 0 { 0x28 } else { 0 }, conflict]), guest::read8(conflict))
    };
    let reported = report(first, list);
    let colliding = report(second, list);
    let released = report(first, 0);
    let moved = report(second, list);
    let cleared = report(second, 0);
    assert(reported == (0, 0) && colliding == (0xC000_0018, 1) && released == (0, 0) && moved == (0, 0) && cleared == (0, 0), "io-report-resource-detection: relata, acusa o conflito (ConflictDetected) e a lista vazia libera");
    guest::free_bytes(list);
    guest::free_bytes(conflict);
    free_device(first);
    free_device(second);
}

// ---- ExfReleasePushLockShared / ExfReleasePushLockExclusive ------------------

fn push_lock_release(assert: Assert) {
    let lock = zeroed(8);
    call("ExAcquirePushLockSharedEx", &[lock, 0]);
    call("ExAcquirePushLockSharedEx", &[lock, 0]);
    let two = guest::read64(lock);
    call("ExfReleasePushLockShared", &[lock]);
    let one = guest::read64(lock);
    call("ExfReleasePushLockShared", &[lock]);
    let none = guest::read64(lock);
    call("ExAcquirePushLockExclusiveEx", &[lock, 0]);
    let exclusive = guest::read64(lock);
    call("ExfReleasePushLockExclusive", &[lock]);
    assert(two == 0x21 && one == 0x11 && none == 0 && exclusive == 1 && guest::read64(lock) == 0, "ex-push-lock-release: soltura de leitor e de escritor pela palavra do push lock");
    guest::free_bytes(lock);
}

// ---- ExEnterCriticalRegionAndAcquireSharedWaitForExclusive -------------------

fn resource_wait_exclusive(assert: Assert) {
    let resource = zeroed(0x68);
    call("ExInitializeResourceLite", &[resource]);
    let thread = process::get_current_thread();
    // SAFETY: a KTHREAD corrente.
    let kthread = unsafe { Kthread::at(thread) };
    let before = kthread.kernel_apc_disable.get();
    let win32 = call("ExEnterCriticalRegionAndAcquireSharedWaitForExclusive", &[resource]);
    let inside = (kthread.kernel_apc_disable.get(), call("ExIsResourceAcquiredSharedLite", &[resource]) & 0xFFFF_FFFF);
    call("ExReleaseResourceAndLeaveCriticalRegion", &[resource]);
    assert(win32 == kthread.win32_thread.get() && inside == (before - 1, 1) && kthread.kernel_apc_disable.get() == before, "ex-resource-critical-wait-exclusive: regiao critica, posse compartilhada e o Win32Thread da thread");
    call("ExDeleteResourceLite", &[resource]);
    guest::free_bytes(resource);
}

// ---- ExBlockOnAddressPushLock / ExUnblockOnAddressPushLockEx -----------------

static BLOCKED_STATUS: AtomicU64 = AtomicU64::new(u64::MAX);

/// Thread de sistema: espera no push lock enquanto [lock+8] == [lock+0x10].
extern "win64" fn address_waiter(lock: u64) {
    let status = call("ExBlockOnAddressPushLock", &[lock, lock + 8, lock + 0x10, 4, 0]);
    BLOCKED_STATUS.store(status as u32 as u64, Ordering::SeqCst);
}

fn pump(milliseconds: u64, done: &dyn Fn() -> bool) -> bool {
    let deadline = clock::uptime_ms() + milliseconds;
    while clock::uptime_ms() < deadline {
        if done() {
            return true;
        }
        scheduler::tick(-1);
    }
    done()
}

fn push_lock_address_wait(assert: Assert) {
    let lock = zeroed(0x20);
    let (target, compare) = (lock + 8, lock + 0x10);
    guest::write32(target, 1);
    guest::write32(compare, 2);
    let different = status("ExBlockOnAddressPushLock", &[lock, target, compare, 4, 0]);
    guest::write32(compare, 1);
    let odd_size = status("ExBlockOnAddressPushLock", &[lock, target, compare, 3, 0]);
    let timeout = zeroed(8);
    guest::write64(timeout, (-100_000i64) as u64);
    let expired = status("ExBlockOnAddressPushLock", &[lock, target, compare, 4, timeout]);
    assert(different == 0 && odd_size == 0 && expired == STATUS_TIMEOUT && guest::read64(lock) == 0, "ex-push-lock-address-wait: valores diferentes e tamanho invalido nao esperam; iguais vencem o prazo com STATUS_TIMEOUT e a cadeia volta vazia");
    // Bloco encadeado à mão, fora da espera ativa: o desbloqueio o sinaliza.
    let block = zeroed(0x40);
    call("KeInitializeEvent", &[block, 0, 0]);
    guest::write64(lock, block);
    call("ExUnblockOnAddressPushLockEx", &[lock, 0]);
    let signaled = call("KeReadStateEvent", &[block]) & 0xFFFF_FFFF;
    call("ExUnblockOnAddressPushLockEx", &[lock, 0]);
    assert(guest::read64(lock) == 0 && signaled == 1, "ex-push-lock-address-wait: ExUnblockOnAddressPushLockEx retira a cadeia e sinaliza o bloco; cadeia vazia nao faz nada");
    // Uma thread de sistema bloqueia e é acordada.
    BLOCKED_STATUS.store(u64::MAX, Ordering::SeqCst);
    let handle = kernel_threads::create_system_thread(0, address_waiter as extern "win64" fn(u64) as usize as u64, lock, 0x1F_FFFF, 0, None).unwrap_or(0);
    let thread = kernel_threads::of_handle(handle).unwrap_or(0);
    let parked = pump(2000, &|| guest::read64(lock) != 0 && thread != 0 && wait::is_waiting(thread));
    call("ExUnblockOnAddressPushLockEx", &[lock, 0]);
    let woke = pump(2000, &|| BLOCKED_STATUS.load(Ordering::SeqCst) != u64::MAX);
    assert(parked && woke && BLOCKED_STATUS.load(Ordering::SeqCst) == 0 && guest::read64(lock) == 0, "ex-push-lock-address-wait: a thread parada no push lock volta com STATUS_SUCCESS pelo ExUnblockOnAddressPushLockEx");
    if handle != 0 {
        call("ZwClose", &[handle]);
    }
    for allocation in [lock, timeout, block] {
        guest::free_bytes(allocation);
    }
}

// ---- ExGetSystemFirmwareTable -------------------------------------------------

fn firmware_tables(assert: Assert) {
    use crate::ntos::ex::firmware_table::{self, PROVIDER_FIRM, PROVIDER_RSMB};
    let returned = zeroed(8);
    let reset = || guest::write32(returned, 0x5555);
    reset();
    let null_buffer = status("ExGetSystemFirmwareTable", &[PROVIDER_FIRM as u64, 0xC_0000, 0, 4, returned]);
    let unknown = status("ExGetSystemFirmwareTable", &[u32::from_be_bytes(*b"XXXX") as u64, 0, 0, 0, returned]);
    assert(null_buffer == STATUS_INVALID_PARAMETER && unknown == STATUS_NOT_IMPLEMENTED && guest::read32(returned) == 0x5555, "ex-firmware-table: buffer nulo com tamanho e provedor desconhecido (STATUS_NOT_IMPLEMENTED, sem ReturnLength)");
    // 'FIRM': a tabela 0xC0000 de 128 KB da memória física.
    let short = status("ExGetSystemFirmwareTable", &[PROVIDER_FIRM as u64, 0xC_0000, 0, 0, returned]);
    let short_length = guest::read32(returned);
    let buffer = zeroed(0x2_0000);
    let full = status("ExGetSystemFirmwareTable", &[PROVIDER_FIRM as u64, 0xC_0000, buffer, 0x2_0000, returned]);
    let same = guest::read_bytes(buffer, 0x100) == crate::hal::physical::read_bytes(0xC_0000, 0x100) && guest::read_bytes(buffer + 0x1_FF00, 0x100) == crate::hal::physical::read_bytes(0xD_FF00, 0x100);
    reset();
    let bad_table = status("ExGetSystemFirmwareTable", &[PROVIDER_FIRM as u64, 0x1234, buffer, 0x2_0000, returned]);
    assert(short == STATUS_BUFFER_TOO_SMALL && short_length == 0x2_0000 && full == 0 && same && bad_table == STATUS_INVALID_PARAMETER_1 && guest::read32(returned) == 0x5555, "ex-firmware-table: 'FIRM' devolve o tamanho, copia 0xC0000 da memoria fisica e recusa TableID desconhecido");
    // 'RSMB': o SMBIOS com o cabeçalho RawSMBIOSData.
    let table = firmware_table::smbios_table();
    reset();
    let probe = status("ExGetSystemFirmwareTable", &[PROVIDER_RSMB as u64, 0, 0, 0, returned]);
    let needed = guest::read32(returned);
    let raw = zeroed(needed.max(8) as u64);
    let read = status("ExGetSystemFirmwareTable", &[PROVIDER_RSMB as u64, 0, raw, needed as u64, returned]);
    let matches = table.is_some_and(|table| {
        needed == table.length + 8
            && guest::read8(raw) == 0
            && guest::read8(raw + 1) == table.major_version
            && guest::read8(raw + 2) == table.minor_version
            && guest::read32(raw + 4) == table.length
            && guest::read_bytes(raw + 8, 0x40.min(table.length as usize)) == crate::hal::physical::read_bytes(table.physical_address, 0x40.min(table.length as usize))
            && guest::read8(raw + 8) == 0
    });
    assert(table.is_some() && probe == STATUS_BUFFER_TOO_SMALL && read == 0 && matches, "ex-firmware-table: 'RSMB' devolve RawSMBIOSData com a versao e a tabela do SMBIOS (primeira estrutura do tipo 0)");
    for block in [returned, buffer, raw] {
        guest::free_bytes(block);
    }
}

// ---- ZwQuerySystemInformation(Ex): 8, 76 e 175 ----------------------------------

/// As classes do ExpQuerySystemInformation que o modo kernel agora atende:
/// SystemProcessorPerformanceInformation (8, 0x30 por processador, também
/// pelo Ex com o grupo), SystemFirmwareTableInformation (76, o 'RSMB' do
/// próprio kernel) e SystemCpuSetInformation (175, só pelo Ex, com o HANDLE
/// do processo).
fn system_information_classes(assert: Assert) {
    use crate::ntos::ex::firmware_table::PROVIDER_RSMB;
    let count = crate::ntos::ke::smp::online_cpu_count() as u64;
    let returned = zeroed(8);
    let buffer = zeroed(0x40 * count + 0x40);
    let query = |class: u64, length: u64| {
        guest::write32(returned, 0x5555);
        status("ZwQuerySystemInformation", &[class, buffer, length, returned])
    };
    // 8: cada processador com KernelTime >= IdleTime; comprimento que não é
    // múltiplo de 0x30, STATUS_INFO_LENGTH_MISMATCH com o tamanho de todos.
    let all = query(8, 0x30 * count);
    let all_length = guest::read32(returned) as u64;
    let times_ok = (0..count).all(|index| {
        let base = buffer + index * 0x30;
        let (idle, kernel) = (guest::read64(base), guest::read64(base + 8));
        kernel >= idle && kernel % crate::ntos::ke::clock::MAXIMUM_INCREMENT as u64 == 0
    });
    let odd = query(8, 0x20);
    let odd_length = guest::read32(returned) as u64;
    let single = query(8, 0x30);
    let single_length = guest::read32(returned) as u64;
    assert(
        all == 0 && all_length == 0x30 * count && times_ok && odd == 0xC000_0004 && odd_length == 0x30 * count && single == 0 && single_length == 0x30,
        "zw-system-information: SystemProcessorPerformanceInformation (0x30 por processador, o que cabe, e o tamanho de todos no comprimento invalido)",
    );
    // 76: o enumerar do 'RSMB' (um TableID 0 de 4 bytes).
    guest::write32(buffer, PROVIDER_RSMB);
    guest::write32(buffer + 4, 0);
    guest::write32(buffer + 8, 0);
    guest::write32(buffer + 0xC, 0x7777);
    guest::write32(buffer + 0x10, 0xEEEE_EEEE);
    let enumerate = query(76, 0x14);
    let enumerate_answer = (guest::read32(returned), guest::read32(buffer + 0xC), guest::read32(buffer + 0x10));
    let short = query(76, 0xF);
    let short_length = guest::read32(returned);
    guest::write32(buffer, u32::from_be_bytes(*b"XXXX"));
    let unknown = query(76, 0x14);
    let unknown_length = guest::read32(returned);
    assert(
        enumerate == 0 && enumerate_answer == (0x14, 4, 0) && short == 0xC000_0004 && short_length == 0x10 && unknown == STATUS_NOT_IMPLEMENTED && unknown_length == 0,
        "zw-system-information: SystemFirmwareTableInformation em KernelMode (o enumerar do 'RSMB', cabecalho curto e provedor desconhecido)",
    );
    // O Ex: 8 com o grupo da entrada; 175 com o HANDLE (NULL, o corrente).
    let input = zeroed(8);
    let query_ex = |class: u64, input_length: u64, length: u64| {
        guest::write32(returned, 0x5555);
        status("ZwQuerySystemInformationEx", &[class, input, input_length, buffer, length, returned])
    };
    let group_zero = query_ex(8, 2, 0x30 * count);
    let group_zero_length = guest::read32(returned) as u64;
    guest::write16(input, 1);
    let group_one = query_ex(8, 2, 0x30 * count);
    guest::write64(input, 0);
    let cpu_short = query_ex(175, 8, 0x20 * count - 1);
    let cpu_short_length = guest::read32(returned) as u64;
    guest::write_bytes(buffer, &alloc::vec![0xEE; (0x20 * count) as usize]);
    let cpu_sets = query_ex(175, 8, 0x20 * count);
    let cpu_sets_length = guest::read32(returned) as u64;
    let entries_ok = (0..count).all(|index| {
        let base = buffer + index * 0x20;
        guest::read32(base) == 0x20 && guest::read32(base + 4) == 0 && guest::read32(base + 8) == 0x100 + index as u32 && guest::read16(base + 0xC) == 0 && guest::read8(base + 0xE) == index as u8 && guest::read8(base + 0x13) == 0 && guest::read64(base + 0x18) == 0
    });
    let cpu_bad_input = query_ex(175, 4, 0x20 * count);
    assert(
        group_zero == 0 && group_zero_length == 0x30 * count && group_one == STATUS_INVALID_PARAMETER && cpu_short == STATUS_BUFFER_TOO_SMALL && cpu_short_length == 0x20 * count && cpu_sets == 0 && cpu_sets_length == 0x20 * count && entries_ok && cpu_bad_input == STATUS_INVALID_PARAMETER,
        "zw-system-information: o Ex com o grupo (8) e os conjuntos de CPU (175: Id 0x100 + indice, sem flags)",
    );
    // 75: o registro de um provedor de driver (sem chamá-lo): uma assinatura
    // nova com Register, a repetida (STATUS_OBJECT_NAME_EXISTS), a remoção
    // por outro DriverObject (STATUS_INVALID_PARAMETER), a remoção certa e a
    // de uma assinatura ausente.
    let handler = zeroed(0x18);
    let register = |register: u8, driver_object: u64, length: u64| {
        guest::write32(handler, u32::from_be_bytes(*b"TST1"));
        guest::write8(handler + 4, register);
        guest::write64(handler + 8, 0xFFFF_F800_DEAD_0000);
        guest::write64(handler + 0x10, driver_object);
        status("ZwSetSystemInformation", &[75, handler, length])
    };
    let registrations = [register(1, 0, 0x18), register(1, 0, 0x18), register(0, 0x1234, 0x18), register(0, 0, 0x18), register(0, 0, 0x18), register(1, 0, 0x10)];
    assert(registrations == [0, 0x4000_0000, STATUS_INVALID_PARAMETER, 0, STATUS_INVALID_PARAMETER, 0xC000_0004], "zw-system-information: SystemRegisterFirmwareTableInformationHandler registra, recusa a repeticao e remove so pelo mesmo DriverObject");
    for block in [returned, buffer, input, handler] {
        guest::free_bytes(block);
    }
}

/// ZwSetSystemInformation 56 (SystemPrefetcherInformation, a validação do
/// PfSnSetPrefetcherInformation com os cenários do prefetcher desligados) e
/// 177 (SystemWin32WerStartCallout: o System fora de sessão não chama o
/// win32k).
fn set_system_information_classes(assert: Assert) {
    let header = zeroed(0x20);
    let inner = zeroed(0x48);
    let prefetch = |class: u32, inner_length: u32, length: u64| {
        guest::write32(header, 1);
        guest::write32(header + 4, 0x6B75_6843);
        guest::write32(header + 8, class);
        guest::write64(header + 0x10, inner);
        guest::write32(header + 0x18, inner_length);
        status("ZwSetSystemInformation", &[56, header, length])
    };
    let short = prefetch(3, 4, 0x1F);
    guest::write32(inner, 2);
    let boot_phase = prefetch(3, 4, 0x20);
    guest::write32(inner, 5);
    let late_phase = prefetch(3, 4, 0x20);
    let phase_length = prefetch(3, 8, 0x20);
    guest::write_bytes(inner, &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]);
    let operation = prefetch(5, 0xC, 0x20);
    guest::write8(inner, 2);
    let operation_version = prefetch(5, 0xC, 0x20);
    guest::write32(inner, 1);
    guest::write32(inner + 4, 1);
    guest::write64(inner + 8, u64::MAX);
    let launch = prefetch(8, 0x10, 0x20);
    guest::write32(inner, 2);
    let launch_version = prefetch(8, 0x10, 0x20);
    let launch_length = prefetch(8, 0xC, 0x20);
    let unknown = prefetch(9, 0, 0x20);
    guest::write32(header + 4, 0);
    let bad_magic = status("ZwSetSystemInformation", &[56, header, 0x20]);
    assert(
        [short, boot_phase, late_phase, phase_length, operation, operation_version, launch, launch_version, launch_length, unknown, bad_magic] == [0xC000_0004, 0, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER, 0, STATUS_INVALID_PARAMETER, 0, 0xC000_0059, 0xC000_0206, 0xC000_0003, STATUS_INVALID_PARAMETER],
        "zw-set-system-information: SystemPrefetcherInformation (tamanho, Magic, fase do boot, operacao, lancamento de aplicativo, classe desconhecida)",
    );
    guest::write64(inner, u64::MAX);
    let wer_current = status("ZwSetSystemInformation", &[177, 0, 0]);
    let wer_handle = status("ZwSetSystemInformation", &[177, inner, 8]);
    let wer_length = status("ZwSetSystemInformation", &[177, inner, 4]);
    assert(wer_current == 0 && wer_handle == 0 && wer_length == 0xC000_0004, "zw-set-system-information: SystemWin32WerStartCallout (o System fora de sessao, sem callout; tamanho invalido)");
    for block in [header, inner] {
        guest::free_bytes(block);
    }
}

// ---- MmAreMdlPagesCached --------------------------------------------------------

fn mdl_pages_cached(assert: Assert) {
    let buffer = guest::alloc_bytes(0x2000);
    let mdl = call("IoAllocateMdl", &[buffer, 0x2000, 0, 0, 0]);
    call("MmBuildMdlForNonPagedPool", &[mdl]);
    let cached = call("MmAreMdlPagesCached", &[mdl]) & 0xFF;
    // SAFETY: o MDL alocado acima; o vetor de PFNs vem logo depois.
    let frames = unsafe { Field::<u64>::array_at(mdl + crate::ntos::inc::types::Mdl::SIZE, 2) };
    let original = frames[1].get();
    frames[1].set(0xA0);
    let firmware_hole = call("MmAreMdlPagesCached", &[mdl]) & 0xFF;
    frames[1].set(0x10_0000_0000);
    let impossible = call("MmAreMdlPagesCached", &[mdl]) & 0xFF;
    frames[1].set(original);
    assert(cached == 1 && firmware_hole == 0 && impossible == 0 && call("MmAreMdlPagesCached", &[mdl]) & 0xFF == 1, "mm-mdl-pages-cached: pool cacheado, frame do buraco VGA sem PfnExists e frame impossivel");
    call("IoFreeMdl", &[mdl]);
    guest::free_bytes(buffer);
}

// ---- MmCopyMemory -----------------------------------------------------------------

fn copy_memory(assert: Assert) {
    let transferred = zeroed(8);
    let copy = |target: u64, source: u64, length: u64, flags: u64| -> (u64, u64) {
        guest::write64(transferred, 0x77);
        (status("MmCopyMemory", &[target, source, length, flags, transferred]), guest::read64(transferred))
    };
    let source = guest::alloc_bytes(0x2100);
    let pattern: Vec<u8> = (0..0x2100u32).map(|index| (index * 7 + 3) as u8).collect();
    guest::write_bytes(source, &pattern);
    let target = zeroed(0x2000);
    let flags = [copy(target, source, 8, 0), copy(target, source, 8, 3)];
    let virtual_copy = copy(target, source + 0x80, 0x2000, 2);
    let same = guest::read_bytes(target, 0x2000) == pattern[0x80..0x2080];
    let empty = copy(target, source, 0, 2);
    let noncanonical = copy(target, 0x0000_8000_0000_0000, 8, 2);
    let unmapped = copy(target, 0xFFFF_A001_0000_0000, 8, 2);
    let physical = copy(target, 0xF_FFF5, 8, 1);
    let physical_same = guest::read_bytes(target, 8) == crate::hal::physical::read_bytes(0xF_FFF5, 8);
    let wrapping = copy(target, u64::MAX - 4, 16, 1);
    assert(flags == [(STATUS_INVALID_PARAMETER_4, 0); 2] && virtual_copy == (0, 0x2000) && same && empty == (STATUS_CONFLICTING_ADDRESSES, 0) && noncanonical == (STATUS_CONFLICTING_ADDRESSES, 0), "mm-copy-memory: Flags invalidas, copia virtual entre paginas, faixa vazia e VA nao canonica");
    assert(unmapped == (STATUS_INVALID_ADDRESS, 0) && physical == (0, 8) && physical_same && wrapping == (STATUS_CONFLICTING_ADDRESSES, 0), "mm-copy-memory: pagina de sistema sem traducao, copia fisica do BIOS e faixa fisica que da a volta");
    for block in [transferred, source, target] {
        guest::free_bytes(block);
    }
}

// ---- KeUpdateThreadTag ---------------------------------------------------------------

fn thread_tag(assert: Assert) {
    const TAGGED: i32 = 1 << 20;
    let synthetic = zeroed(Kthread::SIZE);
    // SAFETY: KTHREAD sintética zerada.
    let kthread = unsafe { Kthread::at(synthetic) };
    call("KeUpdateThreadTag", &[synthetic, 7]);
    let tagged = (kthread.tag.get(), kthread.header.lock.get() & TAGGED != 0);
    call("KeUpdateThreadTag", &[synthetic, 0]);
    let untagged = (kthread.tag.get(), kthread.header.lock.get() & TAGGED != 0);
    let current = process::get_current_thread();
    // SAFETY: a KTHREAD corrente.
    let own = unsafe { Kthread::at(current) };
    let original = own.tag.get();
    call("KeUpdateThreadTag", &[current, 3]);
    let current_tagged = (own.tag.get(), own.header.lock.get() & TAGGED != 0);
    call("KeUpdateThreadTag", &[current, original as u64]);
    assert(tagged == (7, true) && untagged == (0, false) && current_tagged == (3, true) && own.tag.get() == original, "ke-thread-tag: KeUpdateThreadTag grava Tag e liga/desliga o Header.Tagged");
    guest::free_bytes(synthetic);
}

// ---- KeRaiseUserException --------------------------------------------------------------

fn raise_user_exception(assert: Assert) {
    let current = process::get_current_thread();
    // SAFETY: a KTHREAD corrente; os campos trocados voltam no fim.
    let own = unsafe { Kthread::at(current) };
    let (saved_trap, saved_teb) = (own.trap_frame.get(), own.teb.get());
    let plain = status("KeRaiseUserException", &[0xC000_0005]);
    let (frame, teb) = (zeroed(KtrapFrame::SIZE), zeroed(Teb::SIZE));
    // SAFETY: quadro e TEB sintéticos zerados.
    let (trap, environment) = unsafe { (KtrapFrame::at(frame), Teb::at(teb)) };
    trap.seg_cs.set(0x10);
    trap.rip.set(0x1234);
    own.teb.set(teb);
    own.trap_frame.set(frame);
    let kernel_frame = status("KeRaiseUserException", &[0xC000_0026]);
    let kernel_untouched = (trap.seg_cs.get(), trap.rip.get(), environment.exception_code.get());
    trap.seg_cs.set(0x33);
    let user_frame = status("KeRaiseUserException", &[0xC000_0026]);
    let redirected = (trap.seg_cs.get(), trap.rip.get(), environment.exception_code.get() as u32);
    own.trap_frame.set(saved_trap);
    own.teb.set(saved_teb);
    let dispatcher = crate::ntos::ps::user::exceptions::raise_dispatcher();
    assert(plain == 0xC000_0005 && kernel_frame == 0xC000_0026 && kernel_untouched == (0x10, 0x1234, 0), "ke-raise-user-exception: sem quadro de usuario devolve o codigo e nada muda");
    assert(user_frame == 0xC000_0026 && redirected == (0x33, dispatcher, 0xC000_0026), "ke-raise-user-exception: o quadro de usuario volta pelo KiRaiseUserExceptionDispatcher com o codigo na TEB");
    guest::free_bytes(frame);
    guest::free_bytes(teb);
}

// ---- PoCreatePowerRequest / PoSetPowerRequest / PoClearPowerRequest / PoDeletePowerRequest

fn power_requests(assert: Assert) {
    use crate::ntos::po::power_request;
    let device = synthetic_device(0);
    let output = zeroed(8);
    guest::write64(output, 0x55);
    let no_device = status("PoCreatePowerRequest", &[output, 0, 0]);
    let no_device_output = guest::read64(output);
    // COUNTED_REASON_CONTEXT com Version 1: recusado pela captura.
    let context = zeroed(0x28);
    guest::write32(context, 1);
    guest::write64(output, 0x55);
    let bad_context = status("PoCreatePowerRequest", &[output, device.1, context]);
    assert(no_device == STATUS_INVALID_PARAMETER && no_device_output == 0 && bad_context == STATUS_INVALID_PARAMETER && guest::read64(output) == 0, "po-power-requests: sem DeviceObject e com contexto invalido nao criam o pedido");
    let live = power_request::live_requests();
    let created = status("PoCreatePowerRequest", &[output, device.1, 0]);
    let request = guest::read64(output);
    let unsupported = [status("PoSetPowerRequest", &[request, 0]), status("PoSetPowerRequest", &[request, 3]), status("PoSetPowerRequest", &[request, 4]), status("PoClearPowerRequest", &[request, 1])];
    assert(created == 0 && request != 0 && power_request::live_requests() == live + 1 && unsupported == [STATUS_NOT_SUPPORTED; 4], "po-power-requests: o pedido de kernel so aceita PowerRequestSystemRequired e o clear de tipo desligado e recusado");
    let before = power_request::active_requests(1);
    let first = status("PoSetPowerRequest", &[request, 1]);
    let after_first = power_request::active_requests(1);
    let second = status("PoSetPowerRequest", &[request, 1]);
    let after_second = power_request::active_requests(1);
    let cleared = status("PoClearPowerRequest", &[request, 1]);
    let after_clear = power_request::active_requests(1);
    let last = status("PoClearPowerRequest", &[request, 1]);
    let after_last = power_request::active_requests(1);
    let extra = status("PoClearPowerRequest", &[request, 1]);
    assert(
        [first, second, cleared, last] == [0; 4] && (after_first, after_second, after_clear, after_last) == (before + 1, before + 1, before + 1, before) && extra == STATUS_NOT_SUPPORTED,
        "po-power-requests: o contador global muda so na passagem de 0 para 1 e de 1 para 0",
    );
    status("PoSetPowerRequest", &[request, 1]);
    let set_again = power_request::active_requests(1);
    call("PoDeletePowerRequest", &[request]);
    assert(set_again == before + 1 && power_request::active_requests(1) == before && power_request::live_requests() == live, "po-power-requests: PoDeletePowerRequest tira o pedido e desconta o tipo ligado");
    guest::free_bytes(output);
    guest::free_bytes(context);
    free_device(device);
}

// ---- PoNotifyMediaBuffering / PoCpuIdledSinceLastCallImprecise ----------------------

fn processor_power(assert: Assert) {
    use crate::ntos::po::processor_power;
    let drain = || {
        for _ in 0..64 {
            crate::ntos::io::work_items::run_queue();
            if !processor_power::media_buffering_state().2 {
                return;
            }
        }
    };
    drain();
    let (_, _, _, updates) = processor_power::media_buffering_state();
    call("PoNotifyMediaBuffering", &[1]);
    let queued = processor_power::media_buffering_state();
    call("PoNotifyMediaBuffering", &[1]);
    drain();
    let engaged = processor_power::media_buffering_state();
    call("PoNotifyMediaBuffering", &[0]);
    drain();
    let disengaged = processor_power::media_buffering_state();
    // O trabalho pode rodar logo (os pumps do kernel drenam a fila); a
    // contagem mostra que dois avisos iguais aplicam uma vez só.
    assert(queued.0 && engaged == (true, true, false, updates + 1) && disengaged == (false, false, false, updates + 2), "po-processor-power: PoNotifyMediaBuffering enfileira uma vez e o trabalho aplica o estado pedido");
    // KiProcessorBlock vazio: TRUE sem tocar na saída.
    let last = zeroed(8);
    guest::write64(last, 0x99);
    let absent = call("PoCpuIdledSinceLastCallImprecise", &[0x7FF, last]) & 0xFF;
    let untouched = guest::read64(last);
    let prcb = crate::ntos::ke::pcr::processor_block(0);
    let measured = prcb.map(|prcb| {
        let power = &prcb.power_state;
        let (saved_total, saved_entry) = (power.idle_time_total.get(), power.idle_time_entry.get());
        power.idle_time_total.set(1000);
        power.idle_time_entry.set(0);
        guest::write64(last, 0);
        let grew = call("PoCpuIdledSinceLastCallImprecise", &[0, last]) & 0xFF;
        let recorded = guest::read64(last);
        let same = call("PoCpuIdledSinceLastCallImprecise", &[0, last]) & 0xFF;
        power.idle_time_entry.set(5);
        let idle_now = call("PoCpuIdledSinceLastCallImprecise", &[0, last]) & 0xFF;
        power.idle_time_total.set(saved_total);
        power.idle_time_entry.set(saved_entry);
        (grew, recorded, same, idle_now)
    });
    assert(absent == 1 && untouched == 0x99 && measured == Some((1, 1000, 0, 1)), "po-processor-power: PoCpuIdledSinceLastCallImprecise pelo IdleTimeTotal e IdleTimeEntry da KPRCB");
    guest::free_bytes(last);
}
