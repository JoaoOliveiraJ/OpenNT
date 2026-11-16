//! Autoteste dos exports de Io e FsRtl que eram os últimos imports de drivers
//! reais: origem e 32 bits do pedido, work item por nó, IoDeleteDriver,
//! rastreamento de I/O, alias de interface, RtlVolumeDeviceToDosName, a
//! sincronização de seção do FsRtl (callbacks de filtro, Fast I/O e o
//! ERESOURCE do FCB) e o despacho pela tabela do MUP. Cada export é chamado
//! pelo trampolim nativo (ABI MS x64); os resultados esperados seguem os
//! caminhos do ntoskrnl 19041.

use alloc::string::String;
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

/// Bloco zerado do tamanho do tipo.
fn zeroed<T: NtStruct>() -> u64 {
    let block = guest::alloc_bytes(T::SIZE);
    guest::write_bytes(block, &alloc::vec![0u8; T::SIZE as usize]);
    block
}

fn unicode_string(text: &str) -> u64 {
    let units: Vec<u16> = text.encode_utf16().collect();
    let buffer = guest::alloc_bytes(units.len() as u64 * 2 + 2);
    crate::ntos::rtl::guest_strings::write_wide_string(buffer, text);
    let string = zeroed::<nt::UnicodeString>();
    at::<nt::UnicodeString>(string).length.set(units.len() as u16 * 2);
    at::<nt::UnicodeString>(string).maximum_length.set(units.len() as u16 * 2 + 2);
    at::<nt::UnicodeString>(string).buffer.set(buffer);
    string
}

/// Endereço de uma rotina `extern "win64"` do teste (chamada pelos exports).
fn routine(address: usize) -> u64 {
    address as u64
}

// ---- Origem do pedido: IoIsFileObjectIgnoringSharing, IoSetFileOrigin, IoIsInitiator32bitProcess

/// EPROCESS sintético com um EWOW64PROCESS da máquina pedida (0 = sem WoW64).
fn process_with_machine(machine: u16) -> u64 {
    let process = zeroed::<nt::Eprocess>();
    if machine != 0 {
        let wow64 = zeroed::<nt::Ewow64process>();
        at::<nt::Ewow64process>(wow64).machine.set(machine);
        at::<nt::Eprocess>(process).wo_w64_process.set(wow64);
    }
    process
}

fn file_object_origin(assert: Assert) {
    let file = zeroed::<nt::FileObject>();
    let object = at::<nt::FileObject>(file);
    let ignoring = |expected: u64| call("IoIsFileObjectIgnoringSharing", &[file]) & 0xFF == expected;
    let without_extension = ignoring(0);
    let extension = zeroed::<nt::IopFileObjectExtension>();
    object.file_object_extension.set(extension);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_flags.set(1);
    let flagged = ignoring(1);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_flags.set(2);
    let other_flag = ignoring(0);
    assert(without_extension && flagged && other_flag, "io-origin: IoIsFileObjectIgnoringSharing le FoExtFlags & 1 da extensao do FILE_OBJECT");

    object.flags.set(0x42);
    let set = status("IoSetFileOrigin", &[file, 1]);
    let marked = object.flags.get() == 0x0100_0042;
    let again = status("IoSetFileOrigin", &[file, 1]);
    let cleared = status("IoSetFileOrigin", &[file, 0]);
    let unmarked = object.flags.get() == 0x42;
    let twice = status("IoSetFileOrigin", &[file, 0]);
    assert(set == 0 && marked && again == 0xC000_0030 && cleared == 0 && unmarked && twice == 0xC000_0030, "io-origin: IoSetFileOrigin liga e desliga FO_REMOTE_ORIGIN; o estado repetido e STATUS_INVALID_PARAMETER_MIX");

    // IRP de modo usuário com um slot cujo FILE_OBJECT não tem iniciador.
    let irp = guest::alloc_bytes(nt::Irp::SIZE + nt::IoStackLocation::SIZE);
    guest::write_bytes(irp, &alloc::vec![0u8; (nt::Irp::SIZE + nt::IoStackLocation::SIZE) as usize]);
    let packet = at::<nt::Irp>(irp);
    let location = irp + nt::Irp::SIZE;
    packet.tail.overlay.current_stack_location.set(location);
    at::<nt::IoStackLocation>(location).file_object.set(file);
    let wow64 = process_with_machine(0x14C);
    let arm32 = process_with_machine(0x1C4);
    let native = process_with_machine(0x8664);
    let plain = process_with_machine(0);
    let initiator32 = |packet_address: u64| call("IoIsInitiator32bitProcess", &[packet_address]) & 0xFF == 1;
    packet.requestor_mode.set(1);
    packet.flags.set(0x2000);
    packet.overlay.asynchronous_parameters.issuing_process.set(wow64 | 2);
    let issuing = initiator32(irp);
    packet.overlay.asynchronous_parameters.issuing_process.set(native);
    let issuing_native = !initiator32(irp);
    packet.requestor_mode.set(0);
    packet.overlay.asynchronous_parameters.issuing_process.set(wow64);
    let kernel_mode = !initiator32(irp);
    assert(issuing && issuing_native && kernel_mode, "io-origin: IoIsInitiator32bitProcess sem iniciador usa o IssuingProcess (marcas 1..2 ignoradas) e so o modo usuario");

    packet.requestor_mode.set(1);
    packet.flags.set(0);
    let thread = zeroed::<nt::Ethread>();
    at::<nt::Ethread>(thread).tcb.process.set(arm32);
    at::<nt::Ethread>(thread).tcb.apc_state.process.set(plain);
    let no_thread = !initiator32(irp);
    packet.tail.overlay.thread.set(thread);
    packet.apc_environment.set(0);
    let own = initiator32(irp);
    packet.apc_environment.set(1);
    let attached = !initiator32(irp);
    packet.apc_environment.set(2);
    let other_environment = !initiator32(irp);
    assert(no_thread && own && attached && other_environment, "io-origin: IoIsInitiator32bitProcess sem iniciador usa o processo da thread pelo ApcEnvironment (0 o proprio, 1 o anexado)");

    // O processo iniciador do FILE_OBJECT (FoExtPerTypeExtension[1], +8) decide.
    let block = guest::alloc_bytes(0x10);
    guest::write_bytes(block, &[0u8; 0x10]);
    at::<nt::IopFileObjectExtension>(extension).fo_ext_per_type_extension[1].set(block);
    guest::write64(block + 8, wow64);
    packet.apc_environment.set(1);
    let initiator_wins = initiator32(irp);
    guest::write64(block + 8, native);
    packet.apc_environment.set(0);
    let initiator_native = !initiator32(irp);
    assert(initiator_wins && initiator_native, "io-origin: IoIsInitiator32bitProcess decide pelo processo iniciador do FILE_OBJECT quando ele existe");
}

// ---- IoQueueWorkItemToNode -----------------------------------------------------

extern "win64" fn node_work_routine(io_object: u64, context: u64, item: u64) {
    guest::write64(context, io_object);
    guest::write64(context + 8, item);
}

fn work_item_node(assert: Assert) {
    let device = zeroed::<nt::DeviceObject>();
    let item = call("IoAllocateWorkItem", &[device]);
    let context = guest::alloc_bytes(0x10);
    guest::write_bytes(context, &[0u8; 0x10]);
    // Nó fora de KeNumberNodes: o da CPU corrente.
    let queued = call("IoQueueWorkItemToNode", &[item, routine(node_work_routine as extern "win64" fn(u64, u64, u64) as usize), 1, context, 7]) & 0xFF;
    let mut ran = false;
    for _ in 0..1000 {
        crate::ntos::io::work_items::run_queue();
        if guest::read64(context + 8) == item {
            ran = true;
            break;
        }
        crate::hal::cpu::pause();
    }
    let arguments = guest::read64(context) == device;
    call("IoFreeWorkItem", &[item]);
    assert(item != 0 && queued == 1 && ran && arguments, "io-work-item-node: IoQueueWorkItemToNode enfileira como o IoQueueWorkItemEx (IoObject, Context, IoWorkItem) e devolve TRUE");
}

// ---- IoDeleteDriver -------------------------------------------------------------

fn delete_driver(assert: Assert) {
    use crate::ntos::ob::object_manager;
    let driver = object_manager::namespace_entries()
        .into_iter()
        .filter_map(|(id, _)| object_manager::node(id))
        .filter(|node| node.type_name == "Driver")
        .filter_map(|node| node.data.as_ref().map(|data| data.native_pointer))
        .find(|&pointer| pointer != 0)
        .unwrap_or(0);
    // ObfReferenceObject devolve a contagem nova: depois do IoDeleteDriver a
    // mesma referência volta ao valor anterior.
    let first = call("ObfReferenceObject", &[driver]);
    call("IoDeleteDriver", &[driver]);
    let second = call("ObfReferenceObject", &[driver]);
    call("ObfDereferenceObject", &[driver]);
    assert(driver != 0 && first != 0 && second == first, "io-delete-driver: IoDeleteDriver solta uma referencia do DRIVER_OBJECT (ObDereferenceObject)");
}

// ---- IoRegisterIoTracking / IoUnregisterIoTracking --------------------------------

/// DeviceType do dispositivo sintético medido.
const TRACKED_DEVICE_TYPE: u64 = 0x8A5A;
static TRACKED_CALLS: AtomicU64 = AtomicU64::new(0);
static TRACKED_SIZE: AtomicU64 = AtomicU64::new(0);
static TRACKED_ELAPSED: AtomicU64 = AtomicU64::new(u64::MAX);

extern "win64" fn tracking_routine(information: u64) {
    if guest::read32(information + 0x10) as u64 == TRACKED_DEVICE_TYPE {
        TRACKED_SIZE.store(guest::read16(information) as u64, Ordering::SeqCst);
        TRACKED_ELAPSED.store(guest::read64(information + 8), Ordering::SeqCst);
        TRACKED_CALLS.fetch_add(1, Ordering::SeqCst);
    }
}

extern "win64" fn tracked_dispatch(_device: u64, packet: u64) -> u32 {
    at::<nt::Irp>(packet).io_status.status.set(0);
    at::<nt::Irp>(packet).io_status.information.set(0);
    crate::ntos::io::io_manager::iof_complete_request(packet);
    0
}

/// Um IRP_MJ_DEVICE_CONTROL pelo IofCallDriver ao dispositivo medido;
/// devolve se o IRP ainda tinha a extensão Timestamp depois da conclusão.
fn send_tracked_irp(device: u64) -> bool {
    let irp = call("IoAllocateIrp", &[1, 0]);
    let next = at::<nt::Irp>(irp).tail.overlay.current_stack_location.get() - nt::IoStackLocation::SIZE;
    at::<nt::IoStackLocation>(next).major_function.set(0x0E);
    call("IofCallDriver", &[device, irp]);
    let stamped = crate::ntos::io::extensions::irp_timestamp(irp).is_some();
    call("IoFreeIrp", &[irp]);
    stamped
}

fn io_tracking(assert: Assert) {
    let driver = zeroed::<nt::DriverObject>();
    let device = zeroed::<nt::DeviceObject>();
    at::<nt::DriverObject>(driver).major_function[0x0E].set(routine(tracked_dispatch as extern "win64" fn(u64, u64) -> u32 as usize));
    at::<nt::DeviceObject>(device).driver_object.set(driver);
    at::<nt::DeviceObject>(device).stack_size.set(1);
    at::<nt::DeviceObject>(device).device_type.set(TRACKED_DEVICE_TYPE as u32);
    // Sem registro, nada é medido.
    TRACKED_CALLS.store(0, Ordering::SeqCst);
    send_tracked_irp(device);
    let quiet_before = TRACKED_CALLS.load(Ordering::SeqCst) == 0;
    let parameters = guest::alloc_bytes(0x10);
    guest::write64(parameters, 0x10);
    guest::write64(parameters + 8, routine(tracking_routine as extern "win64" fn(u64) as usize));
    let handle = guest::alloc_bytes(8);
    guest::write64(handle, 0xFFFF_FFFF_FFFF_FFFF);
    let registered = status("IoRegisterIoTracking", &[parameters, handle]);
    let block = guest::read64(handle);
    let block_routine = if block != 0 { guest::read64(block + 0x10) } else { 0 };
    let stamped = send_tracked_irp(device);
    let calls = TRACKED_CALLS.load(Ordering::SeqCst);
    let size = TRACKED_SIZE.load(Ordering::SeqCst);
    let elapsed = TRACKED_ELAPSED.load(Ordering::SeqCst);
    call("IoUnregisterIoTracking", &[block]);
    send_tracked_irp(device);
    let quiet_after = TRACKED_CALLS.load(Ordering::SeqCst) == calls;
    if !(registered == 0 && block != 0 && calls == 1 && size == 0x18 && !stamped && quiet_after) {
        crate::debug_print!("[teste-io] tracking: status={:#x} bloco={:#x} chamadas={} size={:#x} decorrido={} extensao={} depois={}", registered, block, calls, size, elapsed, stamped, quiet_after);
    }
    assert(quiet_before && registered == 0 && block != 0 && block_routine == guest::read64(parameters + 8) && calls == 1 && size == 0x18 && elapsed < 10_000_000 && !stamped && quiet_after, "io-tracking: IoRegisterIoTracking mede cada IRP (Timestamp no IofCallDriver, {0x18, decorrido, DeviceType} na conclusao) ate o IoUnregisterIoTracking");
}

// ---- IoGetDeviceInterfaceAlias ------------------------------------------------------

fn interface_alias(assert: Assert) {
    use crate::ntos::io::pnp::devnode;
    let output = zeroed::<nt::UnicodeString>();
    let empty = zeroed::<nt::UnicodeString>();
    let class_a = guest::alloc_bytes(16);
    let class_b = guest::alloc_bytes(16);
    let class_c = guest::alloc_bytes(16);
    guest::write_bytes(class_a, &[0x51, 0xA2, 0xC3, 0xD4, 0x02, 0, 0x02, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 0x0A]);
    guest::write_bytes(class_b, &[0x51, 0xA2, 0xC3, 0xD4, 0x02, 0, 0x02, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 0x0B]);
    guest::write_bytes(class_c, &[0x51, 0xA2, 0xC3, 0xD4, 0x02, 0, 0x02, 0x40, 0x80, 0, 0, 0, 0, 0, 0, 0x0C]);
    let rejected = [
        status("IoGetDeviceInterfaceAlias", &[0, class_b, output]),
        status("IoGetDeviceInterfaceAlias", &[empty, class_b, output]),
        status("IoGetDeviceInterfaceAlias", &[unicode_string("\\Device\\QW2#ALIAS#0000#{d4c3a251-0002-4002-8000-00000000000a}"), class_b, output]),
    ];
    let pdo = crate::ntos::io::io_manager::devices().into_iter().map(|(_, entry)| entry.native_device).find(|&device| device != 0 && !devnode::exists(device)).unwrap_or(0);
    let mut node = devnode::DeviceNode::new(pdo, 0, 1);
    node.instance_path = String::from("ROOT\\QW2ALIAS\\0000");
    devnode::insert(node);
    let reference = unicode_string("ref");
    let (link_a, link_b, link_a_plain) = (zeroed::<nt::UnicodeString>(), zeroed::<nt::UnicodeString>(), zeroed::<nt::UnicodeString>());
    let registered = [
        status("IoRegisterDeviceInterface", &[pdo, class_a, reference, link_a]),
        status("IoRegisterDeviceInterface", &[pdo, class_b, reference, link_b]),
        status("IoRegisterDeviceInterface", &[pdo, class_a, 0, link_a_plain]),
    ];
    let read = |string: u64| crate::ntos::rtl::guest_strings::read_unicode_string(string);
    let found = status("IoGetDeviceInterfaceAlias", &[link_a, class_b, output]);
    let alias = read(output);
    let alias_text_ok = alias == "\\??\\ROOT#QW2ALIAS#0000#{d4c3a251-0002-4002-8000-00000000000b}\\ref" && alias == read(link_b) && at::<nt::UnicodeString>(output).maximum_length.get() == at::<nt::UnicodeString>(output).length.get() + 2;
    let buffer = at::<nt::UnicodeString>(output).buffer.get();
    if buffer != 0 {
        let _ = crate::ntos::ex::pool_allocation::free(buffer, 0);
    }
    // Sem a referência a irmã da classe B não existe; a classe C nunca foi registrada.
    let missing = status("IoGetDeviceInterfaceAlias", &[link_a_plain, class_b, output]);
    let cleared = at::<nt::UnicodeString>(output).buffer.get() == 0 && at::<nt::UnicodeString>(output).length.get() == 0;
    let unregistered_class = status("IoGetDeviceInterfaceAlias", &[link_b, class_c, output]);
    // Os links do Object Manager são os nomes sem a referência.
    for link in [link_a_plain, unicode_string("\\??\\ROOT#QW2ALIAS#0000#{d4c3a251-0002-4002-8000-00000000000b}")] {
        call("IoDeleteSymbolicLink", &[link]);
    }
    devnode::remove(pdo);
    if !(found == 0 && alias_text_ok) {
        crate::debug_print!("[teste-io] alias {:#x} '{}' (irma '{}') recusas {:x?} registro {:x?}", found, alias, read(link_b), rejected, registered);
    }
    assert(rejected == [0xC000_000D, 0xC000_000D, 0xC000_000D] && pdo != 0 && registered == [0, 0, 0] && found == 0 && alias_text_ok, "io-interface-alias: IoGetDeviceInterfaceAlias monta a irma da outra classe (instancia, GUID minusculo, referencia) e devolve o nome do pool");
    assert(missing == 0xC000_0034 && cleared && unregistered_class == 0xC000_0034, "io-interface-alias: irma nao registrada devolve o status da abertura e zera o UNICODE_STRING");
}

// ---- IoGetDeviceDirectory ----------------------------------------------------------------

fn device_directory(assert: Assert) {
    use crate::drivers::fs::memory_file_system;
    use crate::ntos::cm::{persisted_state, registry};
    use crate::ntos::io::device_property;
    use crate::ntos::io::pnp::devnode;
    use crate::ntos::io::state_directory::{STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID};
    let wide = |text: &str| -> Vec<u8> { text.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect() };
    let output = guest::alloc_bytes(8);
    let pdo = crate::ntos::io::io_manager::devices().into_iter().map(|(_, entry)| entry.native_device).find(|&device| device != 0 && !devnode::exists(device)).unwrap_or(0);
    let directory = |pdo: u64, kind: u64, flags: u64, reserved: u64, output: u64| status("IoGetDeviceDirectory", &[pdo, kind, flags, reserved, output]);
    let rejected = [directory(0, 0, 0, 0, output), directory(pdo, 0, 1, 0, output), directory(pdo, 0, 0, 0x1000, output), directory(pdo, 0, 0, 0, 0), directory(pdo, 0, 0, 0, output)];
    let mut node = devnode::DeviceNode::new(pdo, 0, 1);
    node.instance_path = String::from("ROOT\\QW2DIR\\0000");
    devnode::insert(node);
    let other_type = directory(pdo, 1, 0, 0, output);
    // A raiz redirecionada pelo RedirectionMap (Files\DriverState) para o volume em memória.
    let key = registry::open_or_create(&(String::from(persisted_state::ROOT) + "Files\\DriverState"), None).unwrap_or(0);
    registry::set_value(key, "", 1, wide("\\FS\\QwState"));
    let property = || device_property::device_property_value(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID);
    // Diretório ausente: o status da abertura (o volume do OpenNT responde
    // OBJECT_NAME_NOT_FOUND) volta sem handle nem propriedade.
    guest::write64(output, 0x55);
    let missing = directory(pdo, 0, 0, 0, output);
    let untouched = guest::read64(output) == 0x55 && property().is_none();
    // `<raiz>\Devices\<InstancePath com '\' -> '#'>\Data` existente: aberto, e a propriedade guarda o nome.
    let _ = memory_file_system::write_bytes("/QwState/Devices/ROOT#QW2DIR#0000/Data", Vec::new());
    let opened = directory(pdo, 0, 0, 0, output);
    let handle = guest::read64(output);
    let named = property() == Some((0x12, wide("ROOT#QW2DIR#0000")));
    let closed = status("ZwClose", &[handle]);
    // Propriedade com caractere ilegal (':'): volta ao InstancePath e a regrava.
    device_property::store_device_property(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID, 0x12, &wide("Qw:Ilegal"));
    let fallback = directory(pdo, 0, 0, 0, output);
    let rewritten = property() == Some((0x12, wide("ROOT#QW2DIR#0000")));
    let _ = status("ZwClose", &[guest::read64(output)]);
    // Propriedade legal: o diretório dela, sem regravar.
    device_property::store_device_property(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID, 0x12, &wide("QwNomeado"));
    let _ = memory_file_system::write_bytes("/QwState/Devices/QwNomeado/Data", Vec::new());
    let by_property = directory(pdo, 0, 0, 0, output);
    let kept = property() == Some((0x12, wide("QwNomeado")));
    let _ = status("ZwClose", &[guest::read64(output)]);
    let _ = memory_file_system::remove("/QwState/Devices/ROOT#QW2DIR#0000/Data");
    let _ = memory_file_system::remove("/QwState/Devices/QwNomeado/Data");
    registry::delete_key(key);
    registry::close_handle(key);
    device_property::store_device_property(pdo, STATE_DIRECTORY_ID, STATE_DIRECTORY_ID_PID, 0, &[]);
    devnode::remove(pdo);
    if !(missing == 0xC000_0034 && untouched && opened == 0 && named && fallback == 0 && rewritten && by_property == 0 && kept) {
        crate::debug_print!("[teste-io] devicedir: recusas {:x?} tipo {:#x} ausente {:#x} aberto {:#x} handle {:#x} nome {} reserva {:#x} {} propriedade {:#x} {}", rejected, other_type, missing, opened, handle, named, fallback, rewritten, by_property, kept);
    }
    assert(pdo != 0 && rejected == [0xC000_000D; 5] && other_type == 0xC000_000D, "io-device-directory: IoGetDeviceDirectory recusa PDO, Flags, Reserved, saida, devnode e DirectoryType invalidos");
    assert(missing == 0xC000_0034 && untouched && opened == 0 && handle != 0 && closed == 0 && named && fallback == 0 && rewritten && by_property == 0 && kept, "io-device-directory: <raiz do RedirectionMap>\\Devices\\<nome>\\Data pelo DEVPKEY_Device_StateDirectoryId legal ou pelo InstancePath, com a propriedade gravada");
}

// ---- RtlVolumeDeviceToDosName ----------------------------------------------------------

fn volume_dos_name(assert: Assert) {
    let device = zeroed::<nt::DeviceObject>();
    at::<nt::DeviceObject>(device).device_type.set(0x22);
    let name = zeroed::<nt::UnicodeString>();
    let rejected = status("RtlVolumeDeviceToDosName", &[device, name]);
    let same = status("IoVolumeDeviceToDosName", &[device, name]);
    assert(rejected == 0xC000_000D && same == rejected && at::<nt::UnicodeString>(name).buffer.get() == 0, "rtl-volume-dos-name: RtlVolumeDeviceToDosName e o IoVolumeDeviceToDosName (dispositivo que nao e volume recusado)");
}

// ---- FsRtlAcquireFileExclusive / FsRtlReleaseFile ----------------------------------------

static FILTER_PRE: AtomicU64 = AtomicU64::new(0);
static FILTER_POST: AtomicU64 = AtomicU64::new(0);
static FILTER_POST_CONTEXT: AtomicU64 = AtomicU64::new(0);
static FILTER_DEVICE: AtomicU64 = AtomicU64::new(0);
static FAST_ACQUIRED: AtomicU64 = AtomicU64::new(0);
static FAST_RELEASED: AtomicU64 = AtomicU64::new(0);

/// Operação (byte), SyncType e o arquivo vistos pela rotina Pre; o contexto
/// de conclusão recebe a operação marcada.
extern "win64" fn filter_pre(data: u64, context: u64) -> u32 {
    let operation = guest::read8(data + 4) as u64;
    FILTER_PRE.store(operation | (guest::read32(data + 0x18) as u64) << 8 | ((guest::read32(data) as u64) << 16), Ordering::SeqCst);
    FILTER_DEVICE.store(guest::read64(data + 8), Ordering::SeqCst);
    if context != 0 {
        guest::write64(context, 0x51C0_0000 | operation);
    }
    0
}

extern "win64" fn filter_post(data: u64, status: u32, context: u64) {
    FILTER_POST.store(guest::read8(data + 4) as u64 | (status as u64) << 8, Ordering::SeqCst);
    FILTER_POST_CONTEXT.store(context, Ordering::SeqCst);
}

extern "win64" fn fast_acquire(file: u64) {
    FAST_ACQUIRED.store(file, Ordering::SeqCst);
}

extern "win64" fn fast_release(file: u64) {
    FAST_RELEASED.store(file, Ordering::SeqCst);
}

/// Driver, dispositivo (com DEVOBJ_EXTENSION) e as tabelas opcionais.
fn file_system_device(fast_io: u64, filters: u64) -> u64 {
    let driver = zeroed::<nt::DriverObject>();
    let extension = zeroed::<nt::DriverExtension>();
    at::<nt::DriverObject>(driver).driver_extension.set(extension);
    at::<nt::DriverObject>(driver).fast_io_dispatch.set(fast_io);
    at::<nt::DriverExtension>(extension).fs_filter_callbacks.set(filters);
    let device = zeroed::<nt::DeviceObject>();
    at::<nt::DeviceObject>(device).driver_object.set(driver);
    at::<nt::DeviceObject>(device).stack_size.set(1);
    at::<nt::DeviceObject>(device).device_object_extension.set(zeroed::<nt::DevobjExtension>());
    device
}

fn kernel_apc_disable() -> i16 {
    at::<nt::Kthread>(crate::ntos::ps::process::get_current_thread()).kernel_apc_disable.get()
}

fn file_acquire(assert: Assert) {
    use crate::ntos::ex::resource;
    use crate::ntos::inc::types::extra_fsrtl::FsrtlCommonFcbHeader;
    // Sem filtros nem Fast I/O: o ERESOURCE principal do FCB, exclusivo, numa região crítica.
    let base = file_system_device(0, 0);
    let file = zeroed::<nt::FileObject>();
    at::<nt::FileObject>(file).device_object.set(base);
    let fcb = guest::alloc_bytes(0x40);
    guest::write_bytes(fcb, &[0u8; 0x40]);
    let lock = zeroed::<nt::Eresource>();
    let initialized = resource::initialize(lock).is_ok_and(|status| status == 0);
    at::<FsrtlCommonFcbHeader>(fcb).resource.set(lock);
    at::<nt::FileObject>(file).fs_context.set(fcb);
    let apcs = kernel_apc_disable();
    let acquired = status("FsRtlAcquireFileExclusive", &[file]);
    let held = resource::is_acquired_exclusive(lock).unwrap_or(false);
    let inside = kernel_apc_disable() == apcs - 1;
    call("FsRtlReleaseFile", &[file]);
    let released = !resource::is_acquired_exclusive(lock).unwrap_or(true);
    let outside = kernel_apc_disable() == apcs;
    let _ = resource::delete(lock);
    assert(initialized && acquired == 0 && held && inside && released && outside, "fsrtl-file-acquire: sem filtros nem Fast I/O o FsRtlAcquireFileExclusive pega o ERESOURCE do FCB exclusivo numa regiao critica e o FsRtlReleaseFile solta");

    // Filtro com FS_FILTER_CALLBACKS sobre um file system com Fast I/O.
    let fast_io = zeroed::<nt::FastIoDispatch>();
    at::<nt::FastIoDispatch>(fast_io).size_of_fast_io_dispatch.set(nt::FastIoDispatch::SIZE as u32);
    at::<nt::FastIoDispatch>(fast_io).acquire_file_for_nt_create_section.set(routine(fast_acquire as extern "win64" fn(u64) as usize));
    at::<nt::FastIoDispatch>(fast_io).release_file_for_nt_create_section.set(routine(fast_release as extern "win64" fn(u64) as usize));
    let callbacks = zeroed::<nt::FsFilterCallbacks>();
    let table = at::<nt::FsFilterCallbacks>(callbacks);
    table.size_of_fs_filter_callbacks.set(0x28);
    let pre = routine(filter_pre as extern "win64" fn(u64, u64) -> u32 as usize);
    let post = routine(filter_post as extern "win64" fn(u64, u32, u64) as usize);
    table.pre_acquire_for_section_synchronization.set(pre);
    table.post_acquire_for_section_synchronization.set(post);
    table.pre_release_for_section_synchronization.set(pre);
    table.post_release_for_section_synchronization.set(post);
    let base = file_system_device(fast_io, 0);
    let filter = file_system_device(0, callbacks);
    at::<nt::DeviceObject>(base).attached_device.set(filter);
    at::<nt::DevobjExtension>(at::<nt::DeviceObject>(filter).device_object_extension.get()).attached_to.set(base);
    let file = zeroed::<nt::FileObject>();
    at::<nt::FileObject>(file).device_object.set(base);
    for cell in [&FILTER_PRE, &FILTER_POST, &FILTER_POST_CONTEXT, &FILTER_DEVICE, &FAST_ACQUIRED, &FAST_RELEASED] {
        cell.store(0, Ordering::SeqCst);
    }
    let apcs = kernel_apc_disable();
    let acquired = status("FsRtlAcquireFileExclusive", &[file]);
    let acquire_seen = (FILTER_PRE.load(Ordering::SeqCst), FILTER_DEVICE.load(Ordering::SeqCst), FILTER_POST.load(Ordering::SeqCst), FILTER_POST_CONTEXT.load(Ordering::SeqCst), FAST_ACQUIRED.load(Ordering::SeqCst));
    let inside = kernel_apc_disable() == apcs - 1;
    call("FsRtlReleaseFile", &[file]);
    let release_seen = (FILTER_PRE.load(Ordering::SeqCst) & 0xFF, FILTER_POST.load(Ordering::SeqCst), FILTER_POST_CONTEXT.load(Ordering::SeqCst), FAST_RELEASED.load(Ordering::SeqCst));
    let outside = kernel_apc_disable() == apcs;
    let acquire_ok = acquire_seen == (0x40_00FF, filter, 0xFF, 0x51C0_00FF, file);
    let release_ok = release_seen == (0xFE, 0xFE, 0x51C0_00FE, file);
    if !(acquired == 0 && acquire_ok && release_ok) {
        crate::debug_print!("[teste-io] fsfilter: status={:#x} aquisicao {:x?} liberacao {:x?}", acquired, acquire_seen, release_seen);
    }
    assert(acquired == 0 && acquire_ok && inside && release_ok && outside, "fsrtl-file-acquire: Pre e Post do filtro (operacoes 0xFF/0xFE, SyncTypeOther, contexto de conclusao) e o Fast I/O AcquireFileForNtCreateSection/ReleaseFileForNtCreateSection do file system de base");
}

// ---- FsRtlMupGetProviderIdFromName / FsRtlMupGetProviderInfoFromFileObject ----------------

extern "win64" fn mup_info(file_object: u64, level: u64, buffer: u64, size: u64) -> u32 {
    guest::write64(buffer, file_object ^ size);
    0x4000_0000 | level as u32
}

extern "win64" fn mup_id(name: u64, provider_id: u64) -> u32 {
    guest::write32(provider_id, guest::read16(name) as u32 + 0x100);
    0
}

fn mup_provider(assert: Assert) {
    use crate::ntos::fsrtl::small::mup_calls;
    let previous = mup_calls::register(0);
    let buffer = guest::alloc_bytes(0x10);
    let name = unicode_string("\\Device\\Mup");
    let unregistered = [status("FsRtlMupGetProviderIdFromName", &[name, buffer]), status("FsRtlMupGetProviderInfoFromFileObject", &[0x1234, 1, buffer, 0x40])];
    let table = guest::alloc_bytes(0x10);
    guest::write64(table, routine(mup_info as extern "win64" fn(u64, u64, u64, u64) -> u32 as usize));
    guest::write64(table + 8, routine(mup_id as extern "win64" fn(u64, u64) -> u32 as usize));
    mup_calls::register(table);
    let info = status("FsRtlMupGetProviderInfoFromFileObject", &[0x1234, 2, buffer, 0x40]);
    let info_written = guest::read64(buffer) == 0x1234 ^ 0x40;
    let id = status("FsRtlMupGetProviderIdFromName", &[name, buffer + 8]);
    let id_written = guest::read32(buffer + 8) == 0x100 + at::<nt::UnicodeString>(name).length.get() as u32;
    mup_calls::register(previous);
    assert(unregistered == [0xC000_00BB, 0xC000_00BB] && info == 0x4000_0002 && info_written && id == 0 && id_written, "fsrtl-mup-provider: sem tabela do MUP STATUS_NOT_SUPPORTED; com ela as duas consultas vao as entradas 0 e 1 com os argumentos intactos");
}

pub fn run(assert: Assert) {
    file_object_origin(assert);
    work_item_node(assert);
    delete_driver(assert);
    io_tracking(assert);
    interface_alias(assert);
    device_directory(assert);
    volume_dos_name(assert);
    file_acquire(assert);
    mup_provider(assert);
}
