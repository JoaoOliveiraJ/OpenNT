//! Self-test da fase 4 — I/O e armazenamento.
//!
//! Exercita, no hardware emulado do QEMU (PC/i440fx), os módulos de HAL,
//! barramento, armazenamento e I/O implementados na fase 4.

use crate::ntos::mm::guest_memory as guest;
use crate::ntos::inc::types::{
    CmPartialResourceDescriptor, CmResourceList, ControllerObject, DeviceCapabilities, DeviceObject, DevobjExtension, DriverObject,
    Ethread, EtwRegEntry, EventDataDescriptor, EventDescriptor, InterfaceType, IoMiniCompletionPacketUser, IoResourceRequirementsList,
    IoStackLocation, IoStatusBlock, Irp, Kthread, LargeInteger, ListEntry, NtStruct, Vpb,
};

type Assert = fn(bool, &str);

/// `IRP_MJ_*` como índice de `DRIVER_OBJECT.MajorFunction`.
fn major_function(driver: &DriverObject, major: u8, routine: u64) {
    driver.major_function[major as usize].set(routine);
}

fn pci_configuration(assert: Assert) {
    use crate::hal::{pci_config, pci_native};
    // Host bridge i440FX em 00:00.0.
    assert(matches!(pci_config::read(0, 0, 0, 0, 2), Ok(0x8086)) && matches!(pci_config::read(0, 0, 0, 2, 2), Ok(0x1237)) && matches!(pci_config::read(0, 0, 0, 0, 4), Ok(0x1237_8086)), "pci: host bridge 8086:1237 pelo mecanismo 1");
    assert(pci_config::read(0, 0, 0, 1, 2).is_err() && pci_config::read(0, 0, 0, 254, 4).is_err() && pci_config::read(0, 32, 0, 0, 2).is_err() && pci_config::read(0, 0, 8, 0, 2).is_err(), "pci: largura, faixa e endereco invalidos recusados");
    assert(matches!(pci_config::read(0, 31, 0, 0, 2), Ok(0xFFFF)), "pci: dispositivo ausente responde FFFF");
    let command = pci_config::read(0, 1, 1, 4, 2).unwrap_or(0);
    assert(matches!(pci_config::enable_command(0, 1, 1, 0), Ok(value) if value == command), "pci: comando lido e regravado numa transacao");
    // HalGetBusDataByOffset.
    let buffer = guest::alloc_bytes(0x20);
    guest::write_bytes(buffer, &[0; 0x20]);
    assert(matches!(pci_native::get_bus_data_by_offset(4, 0, 0, buffer, 0, 4), Ok(4)) && guest::read32(buffer) == 0x1237_8086, "pcinative: vendor e device do host bridge");
    assert(matches!(pci_native::get_bus_data_by_offset(5, 0, 0, buffer, 0, 4), Ok(0)) && matches!(pci_native::get_bus_data(4, 256, 0, buffer, 4), Ok(0)) && matches!(pci_native::get_bus_data_by_offset(4, 0, 0, buffer, 256, 4), Ok(0)), "pcinative: tipo de barramento e faixa invalidos");
    // Slot = device | function << 5; o IDE do PIIX3 fica em 00:01.1.
    assert(matches!(pci_native::get_bus_data_by_offset(4, 0, 1 | 1 << 5, buffer, 0, 4), Ok(4)) && guest::read32(buffer) == 0x7010_8086, "pcinative: funcao 1 de dispositivo multifuncao");
    guest::write32(buffer, 0);
    assert(matches!(pci_native::get_bus_data_by_offset(4, 0, 1 << 5, buffer, 0, 4), Ok(2)) && guest::read16(buffer) == 0xFFFF && guest::read16(buffer + 2) == 0, "pcinative: funcao de dispositivo nao multifuncao responde como vendor ausente");
    guest::write32(buffer, 0);
    assert(matches!(pci_native::get_bus_data_by_offset(4, 0, 31, buffer, 0, 4), Ok(2)) && guest::read16(buffer) == 0xFFFF && matches!(pci_native::get_bus_data_by_offset(4, 0, 31, buffer, 2, 2), Ok(0)), "pcinative: dispositivo ausente so devolve o vendor FFFF");
    assert(matches!(pci_native::get_bus_data_by_offset(4, 0, 0, buffer, 0xFC, 16), Ok(4)), "pcinative: comprimento cortado no fim do espaco de 256 bytes");
    guest::write32(buffer, 0);
    assert(matches!(pci_native::kd_get_pci_data_by_offset(0, 31, buffer, 0, 4), Ok(4)) && guest::read32(buffer) == 0xFFFF_FFFF, "pcinative: KD devolve os bytes FFFF do hardware");
    guest::write16(buffer, command as u16);
    assert(matches!(pci_native::set_bus_data_by_offset(4, 0, 1 | 1 << 5, buffer, 4, 2), Ok(2)) && matches!(pci_config::read(0, 1, 1, 4, 2), Ok(value) if value == command), "pcinative: HalSetBusDataByOffset em cabecalho tipo 0");
    guest::free_bytes(buffer);
}

fn irp_builder(assert: Assert) {
    use crate::ntos::io::irp_builder::{self as builder, BuildOptions, DeviceControl, Power};
    assert(builder::size_for(0) == 0xD0 + 0x48 && builder::size_for(3) == 0xD0 + 3 * 0x48, "irp: tamanho com pelo menos um slot");
    let packet = guest::alloc_bytes(builder::size_for(3));
    guest::write_bytes(packet, &[0xCC; 0x1A8]);
    // IRP_MJ_READ com três níveis de pilha.
    builder::build(packet, &BuildOptions { major: 3, buffer: 0x1000, buffer_length: 0x200, device_object: 0xD000, stack_count: 3, file_object: 0xF000, byte_offset: 0x400, user_event: 0xE000, user_iosb: 0xE100, requestor_mode: 1, thread: 0xA000, ..Default::default() });
    let top = builder::first_stack_location(packet, 3);
    let irp = unsafe { Irp::at(packet) };
    // As IO_STACK_LOCATIONs seguem o IRP.
    let slots = unsafe { IoStackLocation::array_at(packet + Irp::SIZE, 3) };
    assert(irp.type_.get() == 6 && irp.size.get() == 0x1A8 && irp.stack_count.get() == 3 && irp.current_location.get() == 4, "irp: cabecalho IO_TYPE_IRP");
    assert(top == slots[2].address() && irp.tail.overlay.current_stack_location.get() == top + IoStackLocation::SIZE, "irp: CurrentStackLocation uma acima do topo");
    let top_slot = &slots[2];
    assert(top_slot.major_function.get() == 3 && top_slot.parameters.read.length.get() == 0x200 && top_slot.parameters.read.byte_offset.quad_part.get() == 0x400 && top_slot.device_object.get() == 0xD000 && top_slot.file_object.get() == 0xF000, "irp: slot do topo com Parameters.Read");
    assert(irp.associated_irp.system_buffer.get() == 0x1000 && irp.user_event.get() == 0xE000 && irp.user_iosb.get() == 0xE100 && irp.requestor_mode.get() == 1 && irp.tail.overlay.thread.get() == 0xA000 && irp.tail.overlay.original_file_object.get() == 0xF000, "irp: buffers, evento, modo e thread");
    let bottom_slot = &slots[0];
    assert(bottom_slot.major_function.get() == 0 && bottom_slot.minor_function.get() == 0 && bottom_slot.flags.get() == 0 && bottom_slot.control.get() == 0 && irp.io_status.status.get() == 0 && irp.user_buffer.get() == 0, "irp: campos opcionais zerados");
    // IRP_MJ_DEVICE_CONTROL (METHOD_NEITHER) e IRP_MJ_POWER num slot.
    builder::build(packet, &BuildOptions { major: 0x0E, buffer_length: 0x40, ioctl: Some(DeviceControl { code: 0x2D_1400, input_length: 8, type3_buffer: 0xB000 }), ..Default::default() });
    let single = builder::first_stack_location(packet, 1);
    let slot = &slots[0];
    let parameters = &slot.parameters;
    assert(single == slot.address() && irp.stack_count.get() == 1 && parameters.device_io_control.io_control_code.get() == 0x2D_1400 && parameters.device_io_control.input_buffer_length.get() == 8 && parameters.device_io_control.output_buffer_length.get() == 0x40 && parameters.device_io_control.type3_input_buffer.get() == 0xB000, "irp: Parameters.DeviceIoControl");
    builder::build(packet, &BuildOptions { major: 0x16, minor: 2, power: Some(Power { power_state_type: 1, device_state: 4 }), ..Default::default() });
    assert(slot.minor_function.get() == 2 && parameters.power.type_.get().0 == 1 && parameters.power.state.device_state.get().0 == 4, "irp: Parameters.Power");
    builder::build(packet, &BuildOptions { major: 0x1B, minor: 7, buffer_length: 0x99, relations_type: Some(0), ..Default::default() });
    assert(parameters.query_device_relations.type_.get().0 == 0, "irp: QueryDeviceRelations.Type sobre a uniao");
    builder::build(packet, &BuildOptions { major: 0x1B, resources: 0xC000, ..Default::default() });
    assert(parameters.start_device.allocated_resources.get() == 0xC000 && parameters.start_device.allocated_resources_translated.get() == 0xC000, "irp: StartDevice.AllocatedResources");
    irp.io_status.status.set(0xC000_0001u32 as i32);
    irp.io_status.information.set(0x1234);
    assert(builder::read_io_status(packet) == (0xC000_0001u32 as i32, 0x1234), "irp: IoStatus com sinal");
    guest::free_bytes(packet);
}

/// (dispositivo, IRP) da última chamada do despachante de teste.
static POWER_CALLS: crate::rtl::SpinLock<alloc::vec::Vec<(u64, u64)>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());

fn test_power_dispatcher(device: u64, irp: u64) -> u32 {
    POWER_CALLS.lock().push((device, irp));
    0x42
}

fn power_manager(assert: Assert) {
    use crate::ntos::po::power_manager as po;
    use crate::ntos::inc::nt_abi::{device_power_state as d, power_state_type};
    let device = guest::alloc_bytes(DeviceObject::SIZE);
    guest::write_bytes(device, &[0; DeviceObject::SIZE as usize]);
    assert(po::get_device_power_state(device) == d::D0 && po::set_power_state(device, power_state_type::DEVICE_POWER_STATE, d::D3) == d::D0 && po::get_device_power_state(device) == d::D3, "power: PoSetPowerState devolve o estado anterior");
    assert(po::set_power_state(device, power_state_type::SYSTEM_POWER_STATE, 5) == 5 && po::get_device_power_state(device) == d::D3, "power: SystemPowerState nao e rastreado por dispositivo");
    let previous = po::set_power_irp_dispatcher(Some(test_power_dispatcher));
    POWER_CALLS.lock().clear();
    assert(!po::queue_power_request(device, 0x1000), "power: primeiro IRP nao espera");
    po::mark_power_request_started(device);
    assert(po::queue_power_request(device, 0x2000), "power: IRP enfileirado atras do que esta em processamento");
    po::start_next_power_request(device);
    po::start_next_power_request(device);
    po::start_next_power_request(device);
    assert(*POWER_CALLS.lock() == alloc::vec![(device, 0x1000), (device, 0x2000)], "power: PoStartNextPowerIrp em ordem FIFO");
    po::mark_power_request_done(device);
    assert(po::call_driver_down_the_stack(device, 0x3000) == 0, "power: fundo da pilha conclui sem despachar");
    unsafe { DeviceObject::at(device) }.attached_device.set(0x5000);
    assert(po::call_driver_down_the_stack(device, 0x3000) == 0x42 && POWER_CALLS.lock().last() == Some(&(0x5000, 0x3000)), "power: PoCallDriver desce para o dispositivo anexado");
    po::forget_device(device);
    assert(po::get_device_power_state(device) == d::D0, "power: dispositivo esquecido volta a D0");
    po::set_power_irp_dispatcher(previous);
    guest::free_bytes(device);
}

fn black_box_recorder(assert: Assert) {
    use crate::ntos::po::black_box;
    const CATEGORY: u32 = 20;
    let request = guest::alloc_bytes(32);
    let payload = guest::alloc_bytes(0x1400);
    let output = guest::alloc_bytes(8);
    let submit = |source: u64, length: u64, offset: u64, category: u32, flags: u32| {
        guest::write64(request, source);
        guest::write64(request + 8, length);
        guest::write64(request + 16, offset);
        guest::write32(request + 24, category);
        guest::write32(request + 28, flags);
        black_box::update_from_kernel(request, 32, 0, 0).unwrap_or(1)
    };
    assert(matches!(black_box::update_from_kernel(0, 32, 0, 0), Ok(0xC000_000D)) && matches!(black_box::update_from_kernel(request, 32, output, 4), Ok(0xC000_000D)) && matches!(black_box::update_from_kernel(request, 31, 0, 0), Ok(0xC000_0023)), "blackbox: entrada de 32 bytes sem saida");
    guest::write_bytes(payload, b"hello");
    assert(submit(payload, 5, 0, 99, 0) == 0xC000_000D, "blackbox: categoria invalida");
    assert(submit(payload, 5, 0, CATEGORY, 0) == 0 && black_box::snapshot(CATEGORY as usize).is_ok_and(|record| record.stored_length == 5 && record.requested_length == 5 && record.bytes == b"hello" && record.buffer != 0 && record.name == "User mode LKD API caller data"), "blackbox: registro gravado no pool proprio");
    guest::write_bytes(payload, b"ABC");
    assert(submit(payload, 3, 1, CATEGORY, 1) == 0 && black_box::snapshot(CATEGORY as usize).is_ok_and(|record| record.bytes == b"hABCo" && record.requested_length == 5), "blackbox: atualizacao parcial com flag 1");
    assert(submit(payload, 3, 3, CATEGORY, 1) == 0xC000_000D && submit(payload, 0, 0, CATEGORY, 1) == 0xC000_000D && submit(payload, 2, u64::MAX, CATEGORY, 1) == 0xC000_0095, "blackbox: faixa alem do pedido, comprimento zero e overflow");
    assert(submit(payload, 5000, 0, CATEGORY, 0) == 0 && black_box::snapshot(CATEGORY as usize).is_ok_and(|record| record.stored_length == 4096 && record.requested_length == 5000), "blackbox: so 4096 bytes conservados");
    assert(submit(0, 4, 0, CATEGORY, 0) == 0xC000_0005 && black_box::snapshot(CATEGORY as usize).is_ok_and(|record| record.stored_length == 0 && record.requested_length == 0 && record.buffer != 0), "blackbox: origem NULL invalida os comprimentos");
    guest::write_bytes(payload, b"ok");
    assert(submit(payload, 2, 0, CATEGORY, 0) == 0 && submit(0xFFFF_FFFF_8000_0000, 2, 0, CATEGORY, 0) == 0xC000_0005, "blackbox: origem nao mapeada vira access violation");
    assert(black_box::snapshot(99).is_err(), "blackbox: snapshot de categoria invalida");
    for pointer in [request, payload, output] {
        guest::free_bytes(pointer);
    }
}

/// (dispositivo do READ, contexto da conclusão, dispositivo da conclusão,
/// dispositivo do cancelamento, chamadas de conclusão, resultado da conclusão).
static IO_SEEN: [core::sync::atomic::AtomicU64; 6] = [const { core::sync::atomic::AtomicU64::new(0) }; 6];

fn seen(index: usize) -> u64 {
    IO_SEEN[index].load(core::sync::atomic::Ordering::SeqCst)
}

fn record(index: usize, value: u64) {
    IO_SEEN[index].store(value, core::sync::atomic::Ordering::SeqCst);
}

extern "win64" fn test_read_dispatch(device: u64, packet: u64) -> u64 {
    record(0, device);
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(0);
    irp.io_status.information.set(5);
    0
}

extern "win64" fn test_power_dispatch(_device: u64, _packet: u64) -> u64 {
    0x103
}

extern "win64" fn test_completion(device: u64, _packet: u64, context: u64) -> u64 {
    record(1, context);
    record(2, device);
    IO_SEEN[4].fetch_add(1, core::sync::atomic::Ordering::SeqCst);
    seen(5)
}

extern "win64" fn test_cancel(device: u64, _packet: u64) -> u64 {
    record(3, device);
    0
}

fn io_manager_native(assert: Assert) {
    use crate::ntos::io::io_manager::{self as iom, irp_mj, status, IoParams};
    use crate::ntos::ke::dispatcher;
    use crate::ntos::inc::nt_abi::{SL_INVOKE_ON_ERROR, SL_INVOKE_ON_SUCCESS};
    use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
    for slot in &IO_SEEN {
        slot.store(0, core::sync::atomic::Ordering::SeqCst);
    }
    let driver = guest::alloc_bytes(0x160);
    let upper = guest::alloc_bytes(DeviceObject::SIZE);
    let lower = guest::alloc_bytes(DeviceObject::SIZE);
    for &(pointer, size) in &[(driver, 0x160usize), (upper, DeviceObject::SIZE as usize), (lower, DeviceObject::SIZE as usize)] {
        guest::write_bytes(pointer, &alloc::vec![0; size]);
    }
    let driver_object = unsafe { DriverObject::at(driver) };
    major_function(driver_object, irp_mj::READ, test_read_dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    major_function(driver_object, irp_mj::POWER, test_power_dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    for &device in &[upper, lower] {
        let device = unsafe { DeviceObject::at(device) };
        device.driver_object.set(driver);
        device.stack_size.set(2);
    }
    // IofCallDriver desce dois níveis e recusa o terceiro.
    let packet = guest::alloc_bytes(builder::size_for(2));
    let iosb = guest::alloc_bytes(16);
    let event = guest::alloc_bytes(0x18);
    dispatcher::initialize_event(event, 0, false);
    builder::build(packet, &BuildOptions { major: irp_mj::READ, stack_count: 2, user_iosb: iosb, user_event: event, ..Default::default() });
    let top = builder::first_stack_location(packet, 2);
    let irp = unsafe { Irp::at(packet) };
    let top_slot = unsafe { IoStackLocation::at(top) };
    assert(crate::ntos::mm::memory_map::is_kernel_heap(packet) && iom::iof_call_driver(upper, packet) == 0 && seen(0) == upper && irp.current_location.get() == 2 && irp.tail.overlay.current_stack_location.get() == top && top_slot.device_object.get() == upper, "iom: IofCallDriver desce um nivel");
    // O driver superior pede conclusão no slot inferior (IoSetCompletionRoutine).
    let bottom = top - IoStackLocation::SIZE;
    let bottom_slot = unsafe { IoStackLocation::at(bottom) };
    bottom_slot.major_function.set(irp_mj::READ);
    bottom_slot.control.set(SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR);
    bottom_slot.completion_routine.set(test_completion as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64);
    bottom_slot.context.set(0xC0FFEE);
    assert(iom::iof_call_driver(lower, packet) == 0 && irp.current_location.get() == 1 && bottom_slot.device_object.get() == lower, "iom: segundo nivel da pilha");
    assert(iom::iof_call_driver(lower, packet) == status::NOT_SUPPORTED, "iom: pilha estourada recusada");
    // MORE_PROCESSING_REQUIRED interrompe antes da finalização.
    record(5, 0xC000_0016);
    let user_iosb = unsafe { IoStatusBlock::at(iosb) };
    irp.tail.overlay.current_stack_location.set(bottom);
    irp.current_location.set(1);
    assert(iom::iof_complete_request(packet) == 0xC000_0016u32 as i32 && seen(1) == 0xC0FFEE && seen(2) == upper && user_iosb.status.get() == 0 && dispatcher::read_state(event) == 0, "iom: rotina de conclusao com o dispositivo de cima e MORE_PROCESSING_REQUIRED");
    // Conclusão completa: UserIosb e UserEvent.
    record(5, 0);
    irp.tail.overlay.current_stack_location.set(bottom);
    irp.current_location.set(1);
    irp.io_status.status.set(0);
    assert(iom::iof_complete_request(packet) == 0 && seen(4) == 2 && user_iosb.status.get() == 0 && user_iosb.information.get() == 5 && dispatcher::read_state(event) == 1 && irp.current_location.get() == 3, "iom: IofCompleteRequest finaliza UserIosb e UserEvent");
    // IoBuildDeviceIoControlRequest METHOD_BUFFERED e METHOD_NEITHER.
    let input = guest::alloc_bytes(16);
    let output = guest::alloc_bytes(16);
    guest::write_bytes(input, b"ABCDEFGH");
    guest::write_bytes(output, &[0; 16]);
    let buffered = iom::build_device_io_control_request(0x22_0000, upper, input, 8, output, 4, 0x100, 0, iosb, None);
    let buffered_top = builder::first_stack_location(buffered, 2);
    let buffered_irp = unsafe { Irp::at(buffered) };
    let buffered_slot = unsafe { IoStackLocation::at(buffered_top) };
    let system = buffered_irp.associated_irp.system_buffer.get();
    assert(buffered != 0 && system != 0 && guest::read_bytes(system, 8) == b"ABCDEFGH" && buffered_slot.major_function.get() == irp_mj::DEVICE_CONTROL && buffered_irp.flags.get() == 0x30 && buffered_slot.parameters.device_io_control.output_buffer_length.get() == 4, "iom: METHOD_BUFFERED copia a entrada para o SystemBuffer");
    buffered_irp.tail.overlay.current_stack_location.set(buffered_top);
    buffered_irp.current_location.set(2);
    buffered_irp.io_status.information.set(4);
    assert(iom::iof_complete_request(buffered) == 0 && guest::read_bytes(output, 5) == b"ABCD\0" && buffered_irp.associated_irp.system_buffer.get() == 0, "iom: conclusao copia o SystemBuffer e o libera");
    let neither = iom::build_device_io_control_request(0x22_0003, upper, input, 8, 0, 0, 1, 0, 0, None);
    let neither_top = builder::first_stack_location(neither, 2);
    let neither_irp = unsafe { Irp::at(neither) };
    let neither_slot = unsafe { IoStackLocation::at(neither_top) };
    assert(neither_irp.associated_irp.system_buffer.get() == 0 && neither_slot.parameters.device_io_control.type3_input_buffer.get() == input && neither_slot.major_function.get() == irp_mj::INTERNAL_DEVICE_CONTROL && neither_irp.flags.get() == 0, "iom: METHOD_NEITHER e IRP interno");
    // IoBuildSynchronousFsdRequest.
    unsafe { LargeInteger::at(input) }.quad_part.set(0x2000);
    let fsd = iom::build_synchronous_fsd_request(irp_mj::READ, upper, output, 0x200, input, event, iosb);
    let fsd_top = builder::first_stack_location(fsd, 2);
    let fsd_irp = unsafe { Irp::at(fsd) };
    let fsd_slot = unsafe { IoStackLocation::at(fsd_top) };
    assert(fsd_irp.stack_count.get() == 2 && fsd_slot.parameters.read.byte_offset.quad_part.get() == 0x2000 && fsd_slot.parameters.read.length.get() == 0x200 && fsd_irp.associated_irp.system_buffer.get() == output, "iom: IoBuildSynchronousFsdRequest");
    // Conclusões gerenciadas e observadas.
    let managed = alloc::sync::Arc::new(core::sync::atomic::AtomicU64::new(0));
    let sink = managed.clone();
    iom::manage_completion(fsd, alloc::boxed::Box::new(move |status, information| sink.store(((status as u32 as u64) << 32) | information, core::sync::atomic::Ordering::SeqCst)));
    user_iosb.status.set(-1);
    fsd_irp.io_status.status.set(0xC000_0001u32 as i32);
    fsd_irp.io_status.information.set(7);
    fsd_irp.tail.overlay.current_stack_location.set(fsd_top);
    assert(iom::iof_complete_request(fsd) == 0 && managed.load(core::sync::atomic::Ordering::SeqCst) == (0xC000_0001u64 << 32) | 7 && user_iosb.status.get() == -1, "iom: conclusao gerenciada substitui a finalizacao");
    // Power IRP: status de retorno quando o IoStatus fica zero.
    let power = guest::alloc_bytes(builder::size_for(1));
    builder::build(power, &BuildOptions { major: irp_mj::POWER, ..Default::default() });
    assert(iom::dispatch_native_power_irp(upper, power) == 0x103, "iom: despacho de power IRP");
    unsafe { Irp::at(power) }.io_status.status.set(0xC000_00BBu32 as i32);
    assert(iom::dispatch_native_power_irp(upper, power) == 0xC000_00BB, "iom: power IRP devolve o IoStatus nao nulo");
    // IRP pendente: espera com o evento já sinalizado e cancelamento.
    let mut request = iom::make_io_request(irp_mj::READ, IoParams { user_event: event, ..Default::default() });
    request.pending_irp = iom::build_synchronous_fsd_request(irp_mj::READ, upper, output, 4, 0, event, 0);
    unsafe { Irp::at(request.pending_irp) }.io_status.information.set(9);
    dispatcher::set_event(event);
    assert(iom::wait_pending_io_request(&mut request, 100) == 0 && request.info == 9 && request.pending_irp == 0, "iom: espera de IRP pendente");
    request.pending_irp = iom::build_synchronous_fsd_request(irp_mj::READ, upper, output, 4, 0, 0, 0);
    let pending_top = builder::first_stack_location(request.pending_irp, 2);
    let pending_irp = unsafe { Irp::at(request.pending_irp) };
    pending_irp.tail.overlay.current_stack_location.set(pending_top);
    unsafe { IoStackLocation::at(pending_top) }.device_object.set(upper);
    pending_irp.cancel_routine.set(test_cancel as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    assert(iom::cancel_pending_io_request(&mut request) == 0xC000_0120u32 as i32 && seen(3) == upper && request.pending_irp == 0, "iom: IoCancelIrp chama a cancel routine");
    for pointer in [driver, upper, lower, packet, iosb, event, input, output, buffered, neither, fsd, power] {
        guest::free_bytes(pointer);
    }
}

static ECHO_EVENTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn echo_read(_device: u64, request: &mut crate::ntos::io::io_manager::IoRequest) {
    request.result = crate::ntos::io::io_manager::IoResult::Text("eco".into());
}

fn echo_write(_device: u64, request: &mut crate::ntos::io::io_manager::IoRequest) {
    request.info = request.params.data.as_ref().map_or(0, |data| data.len() as u64);
}

fn echo_create(_device: u64, _request: &mut crate::ntos::io::io_manager::IoRequest) {
    ECHO_EVENTS.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
}

fn echo_cleanup(_device: u64, _request: &mut crate::ntos::io::io_manager::IoRequest) {
    ECHO_EVENTS.fetch_add(0x10, core::sync::atomic::Ordering::SeqCst);
}

fn echo_close(_device: u64, _request: &mut crate::ntos::io::io_manager::IoRequest) {
    ECHO_EVENTS.fetch_add(0x100, core::sync::atomic::Ordering::SeqCst);
}

fn echo_pnp(_device: u64, request: &mut crate::ntos::io::io_manager::IoRequest) {
    use crate::ntos::io::io_manager::{irp_mn, IoResult};
    if request.minor == irp_mn::QUERY_ID {
        request.result = IoResult::Text(alloc::format!("ECHO\\ID{}", request.params.relations_type.unwrap_or(99)));
    }
}

fn io_manager_devices(assert: Assert) {
    use crate::ntos::io::io_manager::{self as iom, irp_mj, status, DeviceEntry, IoParams, IoResult};
    use crate::ntos::ob::objects::file as file_objects;
    use crate::ntos::ob::object_manager as om;
    use crate::ntos::inc::nt_abi::device_power_state;
    // Driver do kernel com despacho por major function.
    ECHO_EVENTS.store(0, core::sync::atomic::Ordering::SeqCst);
    let driver = iom::create_driver("Phase4Echo", &[(irp_mj::READ, echo_read), (irp_mj::WRITE, echo_write), (irp_mj::CREATE, echo_create), (irp_mj::CLEANUP, echo_cleanup), (irp_mj::CLOSE, echo_close), (irp_mj::PNP, echo_pnp)]);
    let device = driver.as_ref().ok().and_then(|&driver| iom::create_device(driver, "Phase4Echo").ok()).unwrap_or(0);
    let path = "\\Device\\Phase4Echo";
    assert(device != 0 && driver.as_ref().is_ok_and(|&driver| iom::driver_devices(driver) == alloc::vec![device]), "iomdev: \\Driver e \\Device ligados");
    assert(iom::read(path).is_ok_and(|request| request.status == 0 && request.result == IoResult::Text("eco".into())) && iom::write(path, b"abc").is_ok_and(|request| request.info == 3), "iomdev: READ e WRITE pelo despacho do driver");
    assert(iom::device_control(path, 0x22_0000, IoParams::default()).is_ok_and(|request| request.status == status::NOT_SUPPORTED) && iom::read("\\Device\\Phase4Missing").is_ok_and(|request| request.status == status::NOT_FOUND), "iomdev: major sem rotina e dispositivo ausente");
    assert(matches!(iom::query_device_id(path, 1), Ok(Some(id)) if id == "ECHO\\ID1") && matches!(iom::pnp_start_device(device), Ok(0)) && iom::device(device).is_some_and(|entry| entry.pnp_started), "iomdev: QUERY_ID e START_DEVICE");
    // Abertura com FILE_OBJECT: CREATE, I/O no handle, CLEANUP e CLOSE.
    let opened = iom::open_device(path, false).unwrap_or(iom::Opened { status: -1, handle: 0, file_object: 0, information: 0 });
    assert(opened.status == 0 && opened.handle != 0 && ECHO_EVENTS.load(core::sync::atomic::Ordering::SeqCst) == 1 && iom::device(device).is_some_and(|entry| entry.open_count == 1) && file_objects::state(opened.file_object).is_some_and(|state| state.0 == 1), "iomdev: IRP_MJ_CREATE publica o handle");
    assert(iom::read_handle(opened.handle, IoParams::default()).is_ok_and(|request| request.result == IoResult::Text("eco".into())) && iom::write_handle(opened.handle, b"xy").is_ok_and(|request| request.info == 2), "iomdev: I/O no handle aberto");
    assert(matches!(iom::cleanup_device(opened.handle), Ok(0)) && ECHO_EVENTS.load(core::sync::atomic::Ordering::SeqCst) == 0x11, "iomdev: IRP_MJ_CLEANUP");
    assert(matches!(iom::close_device(opened.handle), Ok(0)) && ECHO_EVENTS.load(core::sync::atomic::Ordering::SeqCst) == 0x111 && iom::device(device).is_some_and(|entry| entry.open_count == 0) && !file_objects::is_file(opened.file_object) && matches!(iom::close_device(opened.handle), Ok(status::NOT_FOUND)), "iomdev: IRP_MJ_CLOSE libera o FILE_OBJECT");
    let external = iom::open_device(path, true).unwrap_or(iom::Opened { status: -1, handle: 0, file_object: 0, information: 0 });
    assert(external.status == 0 && file_objects::state(external.file_object).is_some_and(|state| state.0 == 0 && state.1) && matches!(iom::close_device(external.handle), Ok(0)) && !file_objects::is_file(external.file_object), "iomdev: handles externos retem so a referencia do CREATE");
    // Pilha nativa: IRP real entregue ao DEVICE_OBJECT.
    let native_driver = guest::alloc_bytes(0x160);
    let native_device = guest::alloc_bytes(DeviceObject::SIZE);
    guest::write_bytes(native_driver, &[0; 0x160]);
    guest::write_bytes(native_device, &[0; DeviceObject::SIZE as usize]);
    let driver_object = unsafe { DriverObject::at(native_driver) };
    major_function(driver_object, irp_mj::READ, test_read_dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    major_function(driver_object, irp_mj::POWER, test_power_dispatch as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    let device_object = unsafe { DeviceObject::at(native_device) };
    device_object.driver_object.set(native_driver);
    device_object.stack_size.set(1);
    let native_node = om::create_object("\\Device", "Phase4Native", "Device", None).unwrap_or(0);
    iom::register_device(native_node, DeviceEntry { native_device, ..Default::default() });
    let native_path = "\\Device\\Phase4Native";
    assert(iom::read(native_path).is_ok_and(|request| request.status == 0 && request.info == 5 && matches!(&request.result, IoResult::Text(text) if text.len() == 5)), "iomdev: READ nativo devolve o buffer como texto");
    let mut binary = iom::make_io_request(irp_mj::READ, IoParams { binary: true, data: Some(alloc::vec![1, 2]), ..Default::default() });
    assert(iom::call_driver(native_path, &mut binary).is_ok() && binary.result == IoResult::Bytes(alloc::vec![1, 2, 0, 0, 0]), "iomdev: entrada binaria e resultado em bytes");
    let mut power = iom::set_device_power_state(native_path, device_power_state::D3).unwrap_or_default();
    assert(power.status == status::PENDING && power.pending_irp != 0 && iom::get_device_power_state(native_path) == Some(device_power_state::D0), "iomdev: SET_POWER pendente sem mudar o estado registrado");
    assert(iom::cancel_pending_io_request(&mut power) == 0xC000_0120u32 as i32 && power.pending_irp == 0, "iomdev: IRP de energia pendente cancelado");
    assert(matches!(iom::pnp_start_device(native_node), Ok(status::NOT_SUPPORTED)) && iom::device(native_node).is_some_and(|entry| !entry.pnp_started), "iomdev: START_DEVICE sem rotina PnP nativa");
    let _ = om::unlink(native_path);
    let _ = om::unlink(path);
    let _ = om::unlink("\\Driver\\Phase4Echo");
    guest::free_bytes(native_driver);
    guest::free_bytes(native_device);
}

fn pci_bus_driver(assert: Assert) {
    use crate::drivers::bus::pci::{self, cm_resource_type, Resource};
    use crate::ntos::io::{device_resources, io_manager as iom};
    use crate::ntos::ob::object_manager as om;
    use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
    let devices = pci::devices();
    assert(devices.first().is_some_and(|entry| entry.vendor_id == 0x8086 && entry.device_id == 0x1237 && entry.pdo_name == "PDO0" && entry.node != 0), "pcibus: host bridge enumerado como PDO0");
    let Some(ide) = pci::find_by_id(0x8086, 0x7010) else {
        assert(false, "pcibus: IDE do PIIX3 enumerado");
        return;
    };
    assert(ide.class_code == 0x01 && ide.sub_class == 0x01 && ide.bars.iter().any(|bar| bar.index == 4 && bar.value & 1 != 0 && bar.size == 16), "pcibus: classe IDE e BAR4 de bus master medido");
    let resources = pci::resources_of(&ide);
    assert(resources.len() >= 7 && resources[0].start == 0x1F0 && resources[1].start == 0x3F6 && resources[2].start == 0x170 && resources[3].start == 0x376 && resources[4].level == 15 && resources[5].level == 14 && resources[5].vector == 0x2E && resources[6].resource_type == cm_resource_type::PORT, "pcibus: recursos IDE de compatibilidade na ordem do ataport");
    let path = alloc::format!("\\Device\\{}", ide.pdo_name);
    let node = om::lookup(&path).unwrap_or(0);
    assert(node == ide.node && iom::device(node).is_some_and(|entry| entry.native_device == ide.pdo_pointer && entry.resources == ide.resource_list_pointer) && device_resources::lookup_resource_list(ide.pdo_pointer) == ide.resource_list_pointer, "pcibus: PDO no namespace com CM_RESOURCE_LIST registrado");
    let list = unsafe { CmResourceList::at(ide.resource_list_pointer) };
    let full = &list.list[0];
    let first = &full.partial_resource_list.partial_descriptors[0];
    assert(list.count.get() == 1 && full.interface_type.get() == InterfaceType::PCI_BUS && full.partial_resource_list.count.get() == resources.len() as u32 && first.type_.get() == cm_resource_type::PORT && first.u.port.start.quad_part.get() == 0x1F0, "pcibus: CM_RESOURCE_LIST no layout do wdm.h");
    let pdo = unsafe { DeviceObject::at(ide.pdo_pointer) };
    assert(pdo.type_.get() == 3 && pdo.reference_count.get() == 1 && pdo.stack_size.get() == 1, "pcibus: DEVICE_OBJECT do PDO");
    // QUERY_ID pelo despacho do bus driver e pela pilha nativa.
    assert(matches!(iom::query_device_id(&path, 1), Ok(Some(id)) if id == "PCI\\VEN_8086&DEV_7010"), "pcibus: QUERY_ID pelo bus driver");
    let packet = guest::alloc_bytes(builder::size_for(1));
    builder::build(packet, &BuildOptions { major: 0x1B, minor: 0x13, device_object: ide.pdo_pointer, ..Default::default() });
    let irp = unsafe { Irp::at(packet) };
    assert(iom::iof_call_driver(ide.pdo_pointer, packet) == 0 && irp.io_status.status.get() == 0, "pcibus: PDO sem driver nativo respondido pelo bus");
    let information = irp.io_status.information.get();
    assert(information != 0 && crate::ntos::rtl::guest_strings::read_wide_string(information) == "PCI\\VEN_8086&DEV_7010", "pcibus: id UTF-16 em pool no Information");
    guest::free_bytes(information);
    builder::build(packet, &BuildOptions { major: 0x1B, minor: 0x09, device_object: ide.pdo_pointer, ..Default::default() });
    assert(iom::iof_call_driver(ide.pdo_pointer, packet) == 0xC000_00BBu32 as i32, "pcibus: minor sem resposta nao completa o IRP");
    assert(pci::answer_native_pnp_irp(0x1234_0000, packet).is_none(), "pcibus: dispositivo de outro bus");
    guest::free_bytes(packet);
    // IoConnectInterruptEx LINE_BASED: interrupções consumidas em ordem.
    let interrupt = |level: u32| Resource { resource_type: cm_resource_type::INTERRUPT, flags: 0, start: 0, length: 0, level, vector: 0x20 + level, affinity: 0 };
    let synthetic = pci::build_resource_list(&[Resource { resource_type: cm_resource_type::PORT, flags: 0, start: 0x170, length: 8, level: 0, vector: 0, affinity: 0 }, interrupt(15), interrupt(14)]);
    let fake_pdo = 0x7_0000_1000;
    device_resources::register_device_resources(fake_pdo, synthetic);
    let synthetic_list = unsafe { CmResourceList::at(synthetic) };
    let synthetic_descriptors = unsafe { CmPartialResourceDescriptor::array_at(synthetic_list.list[0].partial_resource_list.partial_descriptors[0].address(), 3) };
    assert(synthetic_descriptors[1].u.interrupt.affinity.get() as u32 == 0xFFFF_FFFF, "pcibus: afinidade padrao");
    assert(device_resources::consume_next_interrupt(fake_pdo) == Some(device_resources::Interrupt { level: 15, vector: 0x2F, flags: 0 }) && device_resources::consume_next_interrupt(fake_pdo).is_some_and(|found| found.level == 14) && device_resources::consume_next_interrupt(fake_pdo).is_none() && device_resources::consume_next_interrupt(0x9999).is_none(), "devres: interrupcoes LINE_BASED na ordem declarada");
    assert(device_resources::lookup_resource_list(fake_pdo) == synthetic && device_resources::lookup_resource_list(fake_pdo & 0xFFFF_FFFF) == 0, "devres: chave e lista com os 64 bits do PDO");
}

fn motherboard_bus_driver(assert: Assert) {
    use crate::drivers::bus::motherboard;
    use crate::ntos::io::io_manager as iom;
    use crate::ntos::ob::object_manager as om;
    use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
    // A pilha de teclado enumera no boot quando existir; senão o teste enumera.
    let pdos = if motherboard::created().is_empty() { motherboard::enumerate().unwrap_or_default() } else { motherboard::created() };
    assert(pdos.len() == 2 && om::lookup("\\Device\\I8042Kbd") == Some(pdos[0].node) && om::lookup("\\Device\\I8042Mou") == Some(pdos[1].node), "motherboard: PDOs PNP0303 e PNP0F13");
    let keyboard = pdos[0];
    assert(iom::device(keyboard.node).is_some_and(|entry| entry.driver.is_none() && entry.native_device == keyboard.device_pointer && entry.resources == keyboard.resource_list_pointer) && unsafe { DeviceObject::at(keyboard.device_pointer) }.driver_object.get() == 0, "motherboard: PDO nativo sem driver");
    // QUERY_ID pela pilha nativa: o IofCallDriver cai no respondedor do bus.
    assert(matches!(iom::query_device_id("\\Device\\I8042Kbd", 0), Ok(Some(id)) if id == "PNP0303") && matches!(iom::query_device_id("\\Device\\I8042Kbd", 3), Ok(Some(id)) if id == "00") && matches!(iom::query_device_id("\\Device\\I8042Mou", 1), Ok(Some(id)) if id == "PNP0F13"), "motherboard: QUERY_ID DeviceID, InstanceID e HardwareIDs");
    assert(matches!(iom::query_device_id("\\Device\\I8042Kbd", 5), Ok(None)), "motherboard: tipo de id sem suporte");
    let packet = guest::alloc_bytes(builder::size_for(1));
    let irp = unsafe { Irp::at(packet) };
    let query = |minor: u8, slot: u64| {
        builder::build(packet, &BuildOptions { major: 0x1B, minor, device_object: keyboard.device_pointer, pnp_slot_pointer: slot, ..Default::default() });
        let status = iom::iof_call_driver(keyboard.device_pointer, packet);
        (status, irp.io_status.status.get() as u32, irp.io_status.information.get())
    };
    // QUERY_RESOURCES: o CM_RESOURCE_LIST Isa com alinhamento de 4.
    let (status, io_status, list) = query(0x0A, 0);
    let resource_list = unsafe { CmResourceList::at(list) };
    let full = &resource_list.list[0];
    let descriptors = unsafe { CmPartialResourceDescriptor::array_at(full.partial_resource_list.partial_descriptors[0].address(), 3) };
    assert(status == 0 && io_status == 0 && list == keyboard.resource_list_pointer && resource_list.count.get() == 1 && full.interface_type.get() == InterfaceType::ISA && full.partial_resource_list.count.get() == 3 && descriptors[0].type_.get() == 1 && descriptors[0].u.port.start.quad_part.get() == 0x60, "motherboard: QUERY_RESOURCES com portas 0x60/0x64");
    let interrupt = &descriptors[2];
    assert(interrupt.type_.get() == 2 && interrupt.u.interrupt.level.get() == 8 && interrupt.u.interrupt.vector.get() == 0x21 && interrupt.u.interrupt.affinity.get() == 0xFF, "motherboard: IRQ1 no DIRQL 8");
    // QUERY_RESOURCE_REQUIREMENTS: descritores IO com stride 0x20.
    let (_, _, requirements) = query(0x0B, 0);
    let requirements_list = unsafe { IoResourceRequirementsList::at(requirements) };
    let alternative = &requirements_list.list[0];
    let io_descriptors = unsafe { crate::ntos::inc::types::IoResourceDescriptor::array_at(alternative.descriptors[0].address(), 3) };
    assert(requirements != 0 && requirements_list.list_size.get() == 0x88 && requirements_list.alternative_lists.get() == 1 && alternative.count.get() == 3 && io_descriptors[0].u.port.minimum_address.quad_part.get() == 0x60 && io_descriptors[2].u.interrupt.minimum_vector.get() == 1, "motherboard: IO_RESOURCE_REQUIREMENTS_LIST com a IRQ ISA crua");
    guest::free_bytes(requirements);
    // QUERY_CAPABILITIES preenche o buffer do chamador.
    let capabilities = guest::alloc_bytes(DeviceCapabilities::SIZE);
    guest::write_bytes(capabilities, &[0xCC; DeviceCapabilities::SIZE as usize]);
    let (status, _, _) = query(0x09, capabilities);
    let device_capabilities = unsafe { DeviceCapabilities::at(capabilities) };
    assert(status == 0 && device_capabilities.size.get() == 0x40 && device_capabilities.version.get() == 1 && device_capabilities.address.get() == 0xFFFF_FFFF && device_capabilities.device_state[0].get().0 == 1 && device_capabilities.device_state[6].get().0 == 1 && device_capabilities.system_wake.get().0 == 0, "motherboard: DEVICE_CAPABILITIES em D0 sem wake");
    let (status, io_status, _) = query(0x15, 0);
    assert(status == 0xC000_00BBu32 as i32 && io_status == 0xC000_00BB && irp.current_location.get() == 2, "motherboard: minor sem suporte e completado mesmo assim");
    assert(motherboard::answer_pnp_irp(0x5555_0000, packet).is_none(), "motherboard: dispositivo de outro bus");
    guest::free_bytes(packet);
    guest::free_bytes(capabilities);
}

fn ata_disk(assert: Assert) {
    use crate::drivers::storage::ata_pio as ata;
    assert(matches!(ata::present(0), Ok(true)) && matches!(ata::present(1), Ok(true)), "ata: discos mestre e escravo primarios presentes");
    let volume = ata::read_sectors(0, 1, 1).unwrap_or_default();
    assert(volume.len() == 512 && &volume[3..11] == b"NTFS    " && volume[510] == 0x55 && volume[511] == 0xAA, "ata: setor de boot NTFS no segundo disco");
    // Setor de boot do os.img por DMA de bus master e por PIO.
    let boot = ata::read_sectors(0, 1, 0).unwrap_or_default();
    assert(boot.len() == 512 && boot[510] == 0x55 && boot[511] == 0xAA, "ata: setor de boot com assinatura 55AA por DMA");
    assert(ata::read_sectors_pio(0, 1, 0).is_ok_and(|pio| pio == boot), "ata: PIO le os mesmos bytes que o DMA");
    assert(ata::read_sectors(0, 3, 0).is_ok_and(|three| three.len() == 1536 && three[..512] == boot[..]), "ata: leitura multi-setor");
    // Escrita na área do stage2 (já carregado), leitura de volta e restauração.
    const SECTOR: u64 = 40;
    let original = ata::read_sectors(SECTOR, 1, 0).unwrap_or_default();
    let pattern: alloc::vec::Vec<u8> = (0..512u32).map(|index| (index as u8) ^ 0xA5).collect();
    assert(original.len() == 512 && ata::write_sectors(SECTOR, &pattern, 0).is_ok() && ata::read_sectors(SECTOR, 1, 0).is_ok_and(|back| back == pattern), "ata: WRITE DMA e leitura de volta");
    assert(ata::write_sectors_pio(SECTOR, &original, 0).is_ok() && ata::flush(0).is_ok() && ata::read_sectors(SECTOR, 1, 0).is_ok_and(|back| back == original), "ata: WRITE SECTORS por PIO restaura o setor e FLUSH CACHE");
    // Faixas e argumentos inválidos.
    assert(ata::read_sectors(0x0FFF_FFFF, 2, 0).is_err() && ata::read_sectors(0, 1, 2).is_err() && ata::write_sectors(0, &[0; 100], 0).is_err() && ata::read_sectors_dma_to_physical(0, 1, 0, 0x1001).is_err(), "ata: LBA28, drive, setores incompletos e destino impar recusados");
}

fn ntfs_reader(assert: Assert) {
    use crate::drivers::fs::ntfs::{self, PendingWrite};
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "ntfs: montagem do segundo disco");
        return;
    };
    let geometry = volume.geometry;
    assert(geometry.sector_size == 512 && geometry.sectors_per_cluster == 1 && geometry.mft_lcn == 4 && geometry.record_size == 16384 && geometry.total_sectors * 512 >= 42_030_080, "ntfs: geometria do boot sector (o volume vazio ocupa 42030080 bytes; os arquivos extras do build aumentam)");
    assert(volume.volume_information().is_ok_and(|info| info.label == "OPENNT" && info.serial == u32::from_le_bytes(*b"OPEN") && info.file_system == "NTFS" && info.maximum_component_length == 255), "ntfs: $Volume com rotulo e numero de serie");
    assert(matches!(volume.list("/"), Ok(Some(names)) if boot_root(&names)), "ntfs: indice da raiz (HELLO.TXT e os binarios extras do build)");
    assert(matches!(volume.exists("/hello.txt"), Ok(true)) && matches!(volume.exists("/NADA.TXT"), Ok(false)) && volume.find("/../HELLO.TXT").is_err(), "ntfs: busca sem diferenca de caixa e caminho nao canonico recusado");
    assert(matches!(volume.read("/HELLO.TXT"), Ok(Some(text)) if text == "Ola do NTFS no OpenNT!\r\n") && matches!(volume.size("/HELLO.TXT"), Ok(24)) && matches!(volume.size("/NADA"), Ok(-1)), "ntfs: $DATA residente do HELLO.TXT");
    assert(volume.stat("/HELLO.TXT").is_ok_and(|stat| stat.is_some_and(|stat| stat.reference == 16 && !stat.directory && stat.size == 24 && stat.attributes == 0x20 && stat.sequence == 1)), "ntfs: stat do registro 16");
    assert(matches!(volume.read_range("/HELLO.TXT", 4, 4), Ok(Some(bytes)) if bytes == b"do N") && matches!(volume.read_range("/HELLO.TXT", 100, 4), Ok(Some(bytes)) if bytes.is_empty()) && volume.file_layout("/HELLO.TXT").is_ok_and(|layout| layout.is_some_and(|layout| layout.runs.is_none())), "ntfs: faixa de arquivo residente");
    // Registros de sistema não residentes ($MFT e $Bitmap).
    let mft = volume.read_record(0).unwrap_or_default();
    let runs = ntfs::find_attribute(&mft, 0x80).ok().flatten().and_then(|data| ntfs::parse_runs(&mft, data.run_offset).ok());
    assert(runs == Some(alloc::vec![ntfs::Run { lcn: 4, count: 16384 }]), "ntfs: runlist da $MFT");
    let bitmap_record = volume.read_record(6).unwrap_or_default();
    let bitmap = volume.read_data(&bitmap_record, 0x80).unwrap_or_default();
    assert(bitmap.len() as u64 == geometry.total_sectors.div_ceil(8) && bitmap[0] == 0xFF && bitmap[bitmap.len() - 1] & 0x80 != 0, "ntfs: $Bitmap nao residente lido pela runlist");
    assert(volume.root_index(16).is_err_and(|error| error.status == 0xC000_0103), "ntfs: arquivo nao e diretorio");
    // Escritas pendentes sobrepostas às leituras.
    volume.pending.lock().push(PendingWrite { lba: 0, count: 1, bytes: None });
    let overlaid = volume.read_sectors(0, 2).unwrap_or_default();
    volume.pending.lock().clear();
    assert(overlaid.len() == 1024 && overlaid[..512].iter().all(|&byte| byte == 0) && volume.read_sectors(0, 1).is_ok_and(|boot| &boot[3..11] == b"NTFS    "), "ntfs: escrita pendente sobreposta e removida");
    // O destino é o endereço físico do bloco da arena (VA na janela do heap).
    let destination = guest::alloc_bytes(64);
    let physical = crate::ntos::mm::paging::translate(destination);
    assert(physical != 0 && volume.copy_range_to_physical("/HELLO.TXT", 0, physical, 24).is_ok() && guest::read_bytes(destination, 24) == b"Ola do NTFS no OpenNT!\r\n" && volume.copy_range_to_physical("/HELLO.TXT", 20, physical, 8).is_err(), "ntfs: copia para memoria fisica e faixa invalida");
    guest::free_bytes(destination);
    let generation = volume.generation();
    volume.changed();
    assert(volume.generation() == generation + 1 && matches!(volume.exists("/HELLO.TXT"), Ok(true)), "ntfs: geracao invalida os caches");
}

fn extended_attributes(assert: Assert) {
    use crate::drivers::fs::extended_attributes::{self as ea, Entry, QueryOptions, QueryState};
    use alloc::vec::Vec;
    let entry = |name: &[u8], flags: u8, value: &[u8]| Entry { name: name.to_vec(), flags, value: value.to_vec() };
    let entries = alloc::vec![entry(b"A", 0, b"xy"), entry(b"BB", 0x80, b"z")];
    let encoded = ea::encode(&entries, false);
    assert(encoded.len() == 24 && u32::from_le_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) == 12 && encoded[12..16] == [0, 0, 0, 0] && ea::encode(&entries, true).len() == 24, "ea: FILE_FULL_EA_INFORMATION com a ultima entrada sem alinhamento");
    assert(ea::parse(&encoded, false, false).is_ok_and(|parsed| parsed == entries), "ea: ida e volta pela lista encadeada");
    let mut lower = encoded.clone();
    lower[8] = b'a';
    assert(ea::parse(&lower, false, false).is_ok_and(|parsed| parsed[0].name == b"A"), "ea: nome ASCII em maiusculas");
    let mut bad_name = encoded.clone();
    bad_name[12 + 8] = b'*';
    assert(ea::parse(&bad_name, false, false) == Err(ea::EaError { status: 0x8000_0013, information: 12 }), "ea: caractere invalido no nome com o deslocamento da entrada");
    let mut bad_next = encoded.clone();
    bad_next[0] = 13;
    assert(ea::parse(&bad_next, false, false).is_err_and(|error| error.status == 0x8000_0014) && ea::parse(&[], false, false).is_err(), "ea: lista inconsistente e vazia");
    let sizes = ea::info(&entries);
    assert(sizes.packed == 8 + 8 && sizes.unpacked == 24 && sizes.need == 1, "ea: tamanhos do $EA_INFORMATION");
    // Atualização: valor vazio remove, $KERNEL só pelo kernel.
    let changes = ea::encode(&[entry(b"A", 0, b""), entry(b"C", 0, b"new"), entry(b"$KERNEL.X", 0, b"k")], false);
    assert(ea::update(&entries, &changes, false).is_ok_and(|result| result.iter().map(|entry| entry.name.clone()).collect::<Vec<_>>() == alloc::vec![b"BB".to_vec(), b"C".to_vec()]), "ea: atualizacao remove e acrescenta, ignora $KERNEL");
    assert(ea::update(&entries, &changes, true).is_ok_and(|result| result.len() == 3 && result[2].name == b"$KERNEL.X"), "ea: $KERNEL aplicado pela chamada do kernel");
    // Consultas.
    let mut state = QueryState::default();
    let all = ea::query(&entries, 64, &QueryOptions { restart: true, ..Default::default() }, &mut state);
    assert(all.status == 0 && all.information == 24 && state.index == 2 && ea::query(&entries, 64, &QueryOptions::default(), &mut state).status == 0x8000_0012, "ea: enumeracao completa e fim da lista");
    let second = ea::query(&entries, 64, &QueryOptions { index: Some(2), ..Default::default() }, &mut state);
    assert(second.status == 0 && second.bytes[8..10] == *b"BB" && ea::query(&entries, 64, &QueryOptions { index: Some(5), ..Default::default() }, &mut state).status == 0xC000_0051, "ea: consulta por indice");
    let partial = ea::query(&entries, 14, &QueryOptions { restart: true, ..Default::default() }, &mut state);
    assert(partial.status == 0x8000_0005 && partial.information == 12 && ea::query(&entries, 8, &QueryOptions { restart: true, ..Default::default() }, &mut state).status == 0xC000_0023, "ea: buffer parcial e buffer pequeno demais");
    assert(ea::query(&[], 64, &QueryOptions::default(), &mut QueryState::default()).status == 0xC000_0052, "ea: arquivo sem EAs");
    let mut names = alloc::vec![8, 0, 0, 0, 2, b'b', b'b', 0];
    names.extend_from_slice(&[0, 0, 0, 0, 7]);
    names.extend_from_slice(b"MISSING");
    names.push(0);
    let named = ea::query(&entries, 64, &QueryOptions { names: Some(names), ..Default::default() }, &mut QueryState::default());
    assert(named.status == 0 && ea::parse(&named.bytes[..named.information as usize], false, false).is_ok_and(|parsed| parsed.len() == 2 && parsed[0] == entries[1] && parsed[1].name == b"MISSING" && parsed[1].value.is_empty()), "ea: consulta por nomes com entrada ausente vazia");
}

fn ntfs_writer(assert: Assert) {
    use crate::drivers::fs::extended_attributes::{self as ea, Entry, QueryOptions, QueryState};
    use crate::drivers::fs::ntfs;
    use alloc::string::String;
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "ntfswrite: montagem");
        return;
    };
    let names = |volume: &ntfs::Ntfs, path: &str| volume.list(path).ok().flatten().unwrap_or_default();
    let initial = volume.space().map(|space| space.free_clusters).unwrap_or(0);
    assert(volume.space().is_ok_and(|space| space.clusters == volume.geometry.total_sectors && space.free_clusters > 60_000 && space.cluster_size == 512), "ntfswrite: espaco pelo $Bitmap");
    // Criação e escrita residente: o primeiro registro livre vem depois do
    // HELLO.TXT (16) e de cada arquivo e diretório extra do build.
    let before = names(&volume, "/");
    let first_free = 16 + tree_entries(&volume, "/");
    let created = volume.create("/NOVO.TXT", false, 0, 0);
    assert(matches!(&created, Ok(Some(stat)) if stat.reference == first_free && stat.size == 0 && !stat.directory), "ntfswrite: arquivo criado no primeiro registro livre");
    let mut expected = before.clone();
    expected.push(String::from("/NOVO.TXT"));
    expected.sort_by_key(|name| name.to_uppercase());
    assert(names(&volume, "/") == expected, "ntfswrite: indice da raiz em ordem");
    assert(matches!(volume.write("/NOVO.TXT", 0, b"abc"), Ok(3)) && matches!(volume.read("/NOVO.TXT"), Ok(Some(text)) if text == "abc"), "ntfswrite: escrita residente");
    // Escrita não residente e leitura depois de remontar.
    let pattern: alloc::vec::Vec<u8> = (0..20_000u32).map(|index| (index % 251) as u8).collect();
    assert(matches!(volume.write("/NOVO.TXT", 0, &pattern), Ok(20_000)) && volume.stat("/NOVO.TXT").is_ok_and(|stat| stat.is_some_and(|stat| stat.size == 20_000 && stat.allocated == 20_480)), "ntfswrite: escrita nao residente");
    assert(volume.space().is_ok_and(|space| space.free_clusters == initial - 40), "ntfswrite: clusters alocados no $Bitmap");
    let remounted = ntfs::mount(1);
    assert(remounted.as_ref().is_ok_and(|fresh| matches!(fresh.read_bytes("/NOVO.TXT"), Ok(Some(bytes)) if bytes == pattern)), "ntfswrite: dados persistidos no disco");
    assert(matches!(volume.resize("/NOVO.TXT", 100), Ok(100)) && matches!(volume.read_bytes("/NOVO.TXT"), Ok(Some(bytes)) if bytes[..] == pattern[..100]) && volume.space().is_ok_and(|space| space.free_clusters == initial - 1), "ntfswrite: reducao libera clusters");
    // Renomeação, diretórios e EAs.
    assert(volume.rename("/NOVO.TXT", "/RENOMEADO.TXT", false).is_ok() && matches!(volume.exists("/RENOMEADO.TXT"), Ok(true)) && matches!(volume.exists("/NOVO.TXT"), Ok(false)), "ntfswrite: renomeacao");
    assert(volume.create("/DIR", true, 0, 0).is_ok_and(|stat| stat.is_some_and(|stat| stat.directory)) && volume.create("/DIR/A.TXT", false, 0, 0).is_ok() && names(&volume, "/DIR") == alloc::vec![String::from("/DIR/A.TXT")], "ntfswrite: diretorio com filho");
    assert(volume.remove("/DIR").is_err_and(|error| error.status == 0xC000_0101), "ntfswrite: diretorio nao vazio");
    let extended = ea::encode(&[Entry { name: b"X".to_vec(), flags: 0, value: b"1".to_vec() }], false);
    assert(volume.set_ea("/RENOMEADO.TXT", &extended, false).is_ok() && volume.query_ea("/RENOMEADO.TXT", 64, &QueryOptions { restart: true, ..Default::default() }, &mut QueryState::default()).is_ok_and(|result| result.status == 0 && result.bytes[8] == b'X') && volume.stat("/RENOMEADO.TXT").is_ok_and(|stat| stat.is_some_and(|stat| stat.ea_size != 0)), "ntfswrite: EA gravado e consultado");
    // Erros.
    assert(volume.create("/RENOMEADO.TXT", false, 0, 0).is_err_and(|error| error.status == 0xC000_0035) && volume.write("/NADA.TXT", 0, b"x").is_err_and(|error| error.status == 0xC000_0034) && volume.create("/a:b", false, 0, 0).is_err_and(|error| error.status == 0xC000_0033) && volume.create("/SEMPAI/X", false, 0, 0).is_err_and(|error| error.status == 0xC000_003A), "ntfswrite: nome existente, ausente, invalido e pai ausente");
    // Remoção devolve o volume ao estado inicial.
    assert(volume.remove("/DIR/A.TXT").is_ok() && volume.remove("/DIR").is_ok() && volume.remove("/RENOMEADO.TXT").is_ok(), "ntfswrite: remocoes");
    let fresh = ntfs::mount(1);
    assert(fresh.as_ref().is_ok_and(|fresh| boot_root(&names(fresh, "/")) && matches!(fresh.read("/HELLO.TXT"), Ok(Some(text)) if text == "Ola do NTFS no OpenNT!\r\n")) && volume.space().is_ok_and(|space| space.free_clusters == initial), "ntfswrite: volume de volta ao estado inicial");
}

static FILTER_SEEN: [core::sync::atomic::AtomicU64; 5] = [const { core::sync::atomic::AtomicU64::new(0) }; 5];

extern "win64" fn test_get_file_name(file_object: u64, options: u64, name: u64, information: u64) -> u64 {
    for (slot, value) in FILTER_SEEN.iter().zip([file_object, options, name, information]) {
        slot.store(value, core::sync::atomic::Ordering::SeqCst);
    }
    0xFFFF_FFFF_0000_1234
}

extern "win64" fn test_release_file_name(information: u64, _a: u64, _b: u64, _c: u64) -> u64 {
    FILTER_SEEN[4].store(information, core::sync::atomic::Ordering::SeqCst);
    0
}

fn fs_volume_queries(assert: Assert) {
    use crate::drivers::fs::{filter_callbacks as filters, ntfs, volume_information as info};
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "fsquery: montagem");
        return;
    };
    // FSCTLs do NTFS.
    let control = |code: u32, length: u32| volume.control("/HELLO.TXT", code, &[], length).unwrap_or(crate::drivers::fs::ntfs_control::ControlResult { status: 1, information: 0, bytes: alloc::vec::Vec::new() });
    assert(volume.control("/NADA", 0x9_0028, &[], 0).is_ok_and(|result| result.status == 0xC000_0034) && control(0x9_0028, 0).status == 0 && control(0x9_00F4, 0).status == 0xC000_02B8 && control(0x1234, 0).status == 0xC000_0010, "ntfsctl: volume montado, USN inativo e controle desconhecido");
    assert(control(0x9_003C, 2).bytes == alloc::vec![0, 0] && control(0x9_003C, 1).status == 0xC000_0023, "ntfsctl: FSCTL_GET_COMPRESSION");
    let data = control(0x9_0064, 96);
    let field = |at: usize, count: usize| data.bytes[at..at + count].iter().rev().fold(0u64, |value, &byte| value << 8 | byte as u64);
    let geometry = volume.geometry;
    assert(data.status == 0 && data.information == 96 && field(0, 8) == geometry.serial && field(8, 8) == geometry.total_sectors && field(16, 8) == geometry.total_sectors && field(40, 4) == 512 && field(48, 4) == 16384 && field(52, 4) == 32 && field(64, 8) == 4 && field(72, 8) == geometry.mirror_lcn && field(88, 8) == 4 + 16384, "ntfsctl: NTFS_VOLUME_DATA_BUFFER");
    assert(control(0x9_0064, 100).information == 100 && control(0x9_0064, 104).information == 104 && control(0x9_0064, 95).status == 0xC000_0023, "ntfsctl: extensao NTFS_EXTENDED_VOLUME_DATA e buffer curto");
    // FileFsXxxInformation.
    let query = |class: u32, length: u32| info::query(Some(&*volume as &dyn info::VolumeQuery), class, length).unwrap_or(info::QueryResult { status: 1, information: 0, bytes: alloc::vec::Vec::new() });
    let label = query(1, 64);
    assert(label.status == 0 && label.information == 30 && label.bytes[12] == 12 && label.bytes[18..30] == *"OPENNT".encode_utf16().flat_map(u16::to_le_bytes).collect::<alloc::vec::Vec<u8>>(), "fsinfo: FileFsVolumeInformation com o rotulo");
    let truncated = query(1, 27);
    assert(truncated.status == 0x8000_0005 && truncated.information == 27 && truncated.bytes[12] == 12 && truncated.bytes[18..27] == [b'O', 0, b'P', 0, b'E', 0, b'N', 0, b'N'], "fsinfo: rotulo truncado com STATUS_BUFFER_OVERFLOW e byte impar");
    assert(query(1, 23).status == 0xC000_0004 && query(2, 64).status == 0xC000_0003 && info::query(None, 1, 64).is_ok_and(|result| result.status == 0xC000_0010), "fsinfo: buffer curto, classe invalida e volume ausente");
    let size = query(3, 24);
    let full = query(7, 32);
    let read = |bytes: &[u8], at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
    assert(read(&size.bytes, 0) == geometry.total_sectors && read(&size.bytes, 8) == read(&full.bytes, 16) && size.bytes[16] == 1 && size.bytes[20..22] == [0, 2] && full.bytes[24] == 1, "fsinfo: FileFsSize e FileFsFullSize");
    let attribute = query(5, 64);
    assert(query(4, 8).bytes[0] == 7 && attribute.information == 20 && attribute.bytes[0] == 6 && attribute.bytes[4] == 255 && attribute.bytes[12..20] == [b'N', 0, b'T', 0, b'F', 0, b'S', 0], "fsinfo: FileFsDevice e FileFsAttribute");
    // FsRtlGetFileNameInformation pela tabela do Filter Manager.
    assert(filters::current_callbacks() == 0 && filters::get_file_name_information(1, 2, 3, 4) == 0xC000_00BB, "filter: sem Filter Manager");
    let table = guest::alloc_bytes(0x30);
    guest::write64(table + 0x18, test_get_file_name as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64);
    guest::write64(table + 0x20, test_release_file_name as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64);
    let previous = filters::exchange_callbacks(table);
    let status = filters::get_file_name_information(0xF11E, 0x101, 0xAA, 0xBB);
    let seen: alloc::vec::Vec<u64> = FILTER_SEEN.iter().take(4).map(|slot| slot.load(core::sync::atomic::Ordering::SeqCst)).collect();
    filters::release_file_name_information(0xBB);
    assert(previous == 0 && status == 0x1234 && seen == alloc::vec![0xF11E, 0x101, 0xAA, 0xBB] && FILTER_SEEN[4].load(core::sync::atomic::Ordering::SeqCst) == 0xBB, "filter: callbacks dos slots 0x18 e 0x20");
    assert(filters::exchange_callbacks(previous) == table && filters::current_callbacks() == 0, "filter: dono restaurado");
    guest::free_bytes(table);
}

static IO_SMALL_SEEN: [core::sync::atomic::AtomicU64; 4] = [const { core::sync::atomic::AtomicU64::new(0) }; 4];

/// Rotina de cancelamento: libera o spin lock com o CancelIrql do IRP.
extern "win64" fn test_cancel_spin(device: u64, packet: u64) -> u64 {
    IO_SMALL_SEEN[0].store(device, core::sync::atomic::Ordering::SeqCst);
    IO_SMALL_SEEN[1].store(crate::ntos::io::cancel::is_held() as u64, core::sync::atomic::Ordering::SeqCst);
    let _ = crate::ntos::io::cancel::release(unsafe { Irp::at(packet) }.cancel_irql.get());
    0
}

extern "win64" fn test_io_timer(device: u64, context: u64) -> u64 {
    IO_SMALL_SEEN[2].store(device, core::sync::atomic::Ordering::SeqCst);
    IO_SMALL_SEEN[3].fetch_add(context, core::sync::atomic::Ordering::SeqCst);
    0
}

fn io_small_modules(assert: Assert) {
    use crate::ntos::io::small::{boot_drivers_state, delete_device, initial_stack, thread_io};
    use crate::ntos::io::threads::{io_timer, thread_activity, thread_requests};
    use crate::ntos::io::cancel;
    use crate::ntos::ke::irql;
    use crate::ntos::ps::process;
    use crate::ntos::ob::objects::device as device_objects;
    use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
    let seen = |index: usize| IO_SMALL_SEEN[index].load(core::sync::atomic::Ordering::SeqCst);
    // Spin lock de cancelamento e IoCancelIrp.
    let level = irql::get_irql();
    let previous = cancel::acquire().unwrap_or(0xFF);
    assert(previous == level && irql::get_irql() == 2 && cancel::acquire().is_err() && cancel::release(previous).is_ok() && irql::get_irql() == level && cancel::release(previous).is_err(), "cancel: IoAcquire/ReleaseCancelSpinLock");
    let packet = guest::alloc_bytes(builder::size_for(1));
    builder::build(packet, &BuildOptions { major: 3, device_object: 0xDE00, ..Default::default() });
    let irp = unsafe { Irp::at(packet) };
    let slot = unsafe { IoStackLocation::at(builder::first_stack_location(packet, 1)) };
    irp.tail.overlay.current_stack_location.set(slot.address());
    assert(matches!(cancel::irp(packet), Ok(0)) && irp.cancel.get() == 1 && !cancel::is_held(), "cancel: IRP sem rotina so marca Cancel");
    irp.cancel_routine.set(test_cancel_spin as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    assert(matches!(cancel::irp(packet), Ok(1)) && seen(0) == slot.device_object.get() && seen(1) == 1 && irp.cancel_routine.get() == 0 && irp.cancel_irql.get() == level && !cancel::is_held() && irql::get_irql() == level, "cancel: rotina recebe o lock e o CancelIrql");
    guest::free_bytes(packet);
    // IoDeleteDevice.
    let device = guest::alloc_bytes(DeviceObject::SIZE);
    let _ = device_objects::register(device, None, None);
    assert(matches!(delete_device::delete_device(device), Ok(0)) && !device_objects::is_device(device) && delete_device::delete_device(device).is_err(), "iodelete: IoDeleteDevice retira o dispositivo registrado");
    guest::free_bytes(device);
    // Estado dos drivers de boot, pilha inicial e hard errors.
    boot_drivers_state::complete();
    let thread = process::get_current_thread();
    let ethread = unsafe { Ethread::at(thread) };
    assert(boot_drivers_state::is_initialized() && initial_stack::get() == unsafe { Kthread::at(thread) }.initial_stack.get(), "io: drivers de boot concluidos e IoGetInitialStack");
    let mode = thread_io::set_hard_error_mode(0).unwrap_or(9);
    assert(ethread.hard_errors_are_disabled() != 0 && matches!(thread_io::set_hard_error_mode(1), Ok(0)) && ethread.hard_errors_are_disabled() == 0 && mode <= 1, "io: IoSetThreadHardErrorMode");
    // IoTimer por dispositivo.
    let timed = guest::alloc_bytes(DeviceObject::SIZE);
    let routine = test_io_timer as extern "win64" fn(u64, u64) -> u64 as usize as u64;
    IO_SMALL_SEEN[3].store(0, core::sync::atomic::Ordering::SeqCst);
    assert(io_timer::initialize_timer(timed, routine, 7) == 0 && unsafe { DeviceObject::at(timed) }.timer.get() == 1 && io_timer::initialize_timer(timed, routine, 7) == 0xC000_0035 && io_timer::start_timer(0x1234) == 0xC000_000D, "iotimer: IoInitializeTimer");
    assert(io_timer::start_timer(timed) == 0, "iotimer: IoStartTimer");
    io_timer::expire_now(timed);
    io_timer::check_io_timers();
    assert(seen(2) == timed && seen(3) == 7, "iotimer: rotina vencida chamada com dispositivo e contexto");
    io_timer::check_io_timers();
    assert(seen(3) == 7 && io_timer::stop_timer(timed) == 0, "iotimer: periodo de 1 s e IoStopTimer");
    io_timer::expire_now(timed);
    io_timer::check_io_timers();
    assert(seen(3) == 7, "iotimer: timer parado nao dispara");
    io_timer::forget_device(timed);
    guest::free_bytes(timed);
    // Activity ID da thread.
    let guid = guest::alloc_bytes(32);
    guest::write_bytes(guid, b"0123456789ABCDEF");
    let original = thread_activity::set(guid);
    assert(thread_activity::get() == guid, "activity: IoSetActivityIdThread");
    thread_activity::clear(original);
    let output = guest::alloc_bytes(8);
    assert(thread_activity::get() == original && thread_activity::propagate(0, guid + 16, output) == 0xC000_0225, "activity: clear e propagacao sem origem");
    assert(thread_activity::propagate(guid, guid + 16, output) == 0 && guest::read_bytes(guid + 16, 16) == b"0123456789ABCDEF" && thread_activity::get() == guid + 16 && guest::read64(output) == original, "activity: IoPropagateActivityIdToThread");
    thread_activity::clear(original);
    // Lista de IRPs da ETHREAD.
    let fake = guest::alloc_bytes(Ethread::SIZE);
    let head: &ListEntry = &unsafe { Ethread::at(fake) }.irp_list;
    head.flink.set(head.address());
    head.blink.set(head.address());
    let (first, second) = (guest::alloc_bytes(Irp::SIZE), guest::alloc_bytes(Irp::SIZE));
    let (first_links, second_links) = unsafe { (&Irp::at(first).thread_list_entry, &Irp::at(second).thread_list_entry) };
    assert(thread_requests::insert(first, fake).is_ok() && thread_requests::insert(second, fake).is_ok() && head.flink.get() == second_links.address() && second_links.flink.get() == first_links.address() && first_links.flink.get() == head.address(), "threadirp: IopQueueThreadIrp insere no inicio");
    assert(thread_requests::insert(first, fake).is_err() && thread_requests::remove(first, fake).is_ok() && head.flink.get() == second_links.address() && second_links.flink.get() == head.address() && thread_requests::remove(second, fake).is_ok() && head.flink.get() == head.address() && thread_requests::remove(second, fake).is_err(), "threadirp: remocao fora de ordem e lista vazia");
    for pointer in [guid, output, fake, first, second] {
        guest::free_bytes(pointer);
    }
}

/// (chamadas, último contexto, último IRP, ação a devolver).
static CONTROLLER_SEEN: [core::sync::atomic::AtomicU64; 4] = [const { core::sync::atomic::AtomicU64::new(0) }; 4];
static START_IO_ORDER: crate::rtl::SpinLock<alloc::vec::Vec<u64>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());

extern "win64" fn test_controller_routine(_device: u64, packet: u64, _map: u64, context: u64) -> u64 {
    use core::sync::atomic::Ordering::SeqCst;
    CONTROLLER_SEEN[0].fetch_add(1, SeqCst);
    CONTROLLER_SEEN[1].store(context, SeqCst);
    CONTROLLER_SEEN[2].store(packet, SeqCst);
    CONTROLLER_SEEN[3].load(SeqCst)
}

extern "win64" fn test_start_io(_device: u64, packet: u64, _context: u64) -> u64 {
    START_IO_ORDER.lock().push(packet);
    0
}

fn io_controller_and_start_io(assert: Assert) {
    use crate::ntos::io::controller::{controller, start_io};
    use core::sync::atomic::Ordering::SeqCst;
    /// IO_ALLOCATION_ACTION.
    const KEEP_OBJECT: u64 = 1;
    const DEALLOCATE_OBJECT: u64 = 2;
    let calls = || CONTROLLER_SEEN[0].load(SeqCst);
    for slot in &CONTROLLER_SEEN {
        slot.store(0, SeqCst);
    }
    CONTROLLER_SEEN[3].store(KEEP_OBJECT, SeqCst);
    // CONTROLLER_OBJECT: a fila de espera é a DeviceWaitQueue (KDEVICE_QUEUE).
    let routine = test_controller_routine as extern "win64" fn(u64, u64, u64, u64) -> u64 as usize as u64;
    let device = guest::alloc_bytes(DeviceObject::SIZE);
    guest::write_bytes(device, &[0; DeviceObject::SIZE as usize]);
    let device_object = unsafe { DeviceObject::at(device) };
    device_object.current_irp.set(0xABC0);
    let object = controller::create(16);
    let controller_object = unsafe { ControllerObject::at(object) };
    let wait_queue = &controller_object.device_wait_queue;
    let waiting = || wait_queue.device_list_head.flink.get() != wait_queue.device_list_head.address();
    // IO_TYPE_CONTROLLER = 2 (o IoCreateController do ntoskrnl grava 2).
    assert(controller_object.type_.get() == 2 && controller_object.size.get() as u64 == ControllerObject::SIZE + 16 && controller_object.controller_extension.get() == object + ControllerObject::SIZE && wait_queue.type_.get() == 0x14 && wait_queue.size.get() == 0x28 && wait_queue.busy.get() == 0, "controller: IoCreateController com extensao e DeviceWaitQueue");
    controller::allocate(object, device, routine, 0x11);
    assert(calls() == 1 && CONTROLLER_SEEN[1].load(SeqCst) == 0x11 && CONTROLLER_SEEN[2].load(SeqCst) == 0xABC0 && wait_queue.busy.get() == 1 && !waiting(), "controller: livre executa ja com o CurrentIrp (KeepObject mantem ocupado)");
    controller::allocate(object, device, routine, 0x22);
    assert(calls() == 1 && waiting(), "controller: ocupado entra na DeviceWaitQueue");
    controller::free(object);
    assert(calls() == 2 && CONTROLLER_SEEN[1].load(SeqCst) == 0x22 && !waiting() && wait_queue.busy.get() == 1, "controller: IoFreeController dispara o proximo, que fica com o controlador (KeepObject)");
    controller::free(object);
    assert(calls() == 2 && wait_queue.busy.get() == 0, "controller: IoFreeController com a fila vazia libera");
    CONTROLLER_SEEN[3].store(DEALLOCATE_OBJECT, SeqCst);
    controller::allocate(object, device, routine, 0x33);
    assert(calls() == 3 && wait_queue.busy.get() == 0, "controller: DeallocateObject libera na hora");
    controller::delete(object);
    // StartIo com a KDEVICE_QUEUE do DEVICE_OBJECT.
    let driver = guest::alloc_bytes(0x160);
    guest::write_bytes(driver, &[0; 0x160]);
    unsafe { DriverObject::at(driver) }.driver_start_io.set(test_start_io as extern "win64" fn(u64, u64, u64) -> u64 as usize as u64);
    guest::write_bytes(device, &[0; DeviceObject::SIZE as usize]);
    device_object.driver_object.set(driver);
    // O que o IoCreateDevice prepara: DEVOBJ_EXTENSION e DeviceQueue inicializada.
    let extension = guest::alloc_bytes(DevobjExtension::SIZE);
    guest::write_bytes(extension, &[0; DevobjExtension::SIZE as usize]);
    let object_extension = unsafe { DevobjExtension::at(extension) };
    device_object.device_object_extension.set(extension);
    start_io::queue_initialize(device);
    START_IO_ORDER.lock().clear();
    let packets: alloc::vec::Vec<u64> = (0..4).map(|_| guest::alloc_bytes(Irp::SIZE)).collect();
    let queue_entry = |index: usize| &unsafe { Irp::at(packets[index]) }.tail.overlay.device_queue_entry;
    let keys = guest::alloc_bytes(8);
    guest::write32(keys, 5);
    guest::write32(keys + 4, 2);
    let first = start_io::start_packet(device, packets[0], 0, 0).is_ok();
    let queue = &device_object.device_queue;
    assert(first && device_object.current_irp.get() == packets[0] && queue.busy.get() == 1 && queue.type_.get() == 0x14 && queue.size.get() == 0x28 && *START_IO_ORDER.lock() == alloc::vec![packets[0]], "startio: dispositivo livre roda o StartIo na hora");
    let queued = start_io::start_packet(device, packets[1], keys, 0).is_ok() && start_io::start_packet(device, packets[2], keys + 4, 0).is_ok() && start_io::start_packet(device, packets[3], 0, 0).is_ok();
    // KeInsertByKeyDeviceQueue grava a SortKey; sem chave o IRP entra no fim.
    assert(queued && START_IO_ORDER.lock().len() == 1 && queue_entry(1).sort_key.get() == 5 && queue_entry(2).sort_key.get() == 2 && (1..4).all(|index| queue_entry(index).inserted.get() == 1), "startio: ocupado entra na fila com a chave");
    let drained = (0..4).all(|_| start_io::start_next_packet(device, false).is_ok());
    assert(drained && *START_IO_ORDER.lock() == alloc::vec![packets[0], packets[2], packets[1], packets[3]] && device_object.current_irp.get() == 0 && queue.busy.get() == 0 && (1..4).all(|index| queue_entry(index).inserted.get() == 0), "startio: fila ordenada pela chave e esvaziada");
    // IoSetStartIoAttributes: DOE_SIO_DEFERRED (0x100) e DOE_SIO_NO_CANCEL
    // (0x200) no StartIoFlags da DEVOBJ_EXTENSION; só liga bits e não toca
    // nas Characteristics.
    device_object.characteristics.set(0x100);
    start_io::set_start_io_attributes(device, true, false);
    let deferred = object_extension.start_io_flags.get();
    start_io::set_start_io_attributes(device, false, true);
    let both = object_extension.start_io_flags.get();
    start_io::set_start_io_attributes(device, false, false);
    assert(deferred == 0x100 && both == 0x300 && object_extension.start_io_flags.get() == 0x300 && device_object.characteristics.get() == 0x100, "startio: IoSetStartIoAttributes no StartIoFlags da DEVOBJ_EXTENSION");
    for pointer in packets.into_iter().chain([device, driver, keys, extension]) {
        guest::free_bytes(pointer);
    }
}

fn io_file_lifetime(assert: Assert) {
    use crate::drivers::fs::ntfs;
    use crate::ntos::io::file::lifetime::{self as life, Entry, LifetimeFileSystem};
    use crate::ntos::ob::objects::file as files;
    use alloc::sync::Arc;
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "lifetime: montagem");
        return;
    };
    let file_system: Arc<dyn LifetimeFileSystem> = volume.clone();
    // Abre uma descrição: o handle fica com a única referência ao FILE_OBJECT.
    let open = |path: &str, access: u32, share: u32| -> u64 {
        let file_object = files::create(0, path).unwrap_or(0);
        let _ = files::open_handle(file_object);
        let _ = files::dereference(file_object);
        let _ = life::bind(Entry { access, share, file_object, file: None }, &file_system, path);
        file_object
    };
    let path = "/LIFE.TXT";
    let _ = volume.create(path, false, 0, 0);
    let _ = volume.write(path, 0, b"vida");
    let reader = open(path, 0x1, 1);
    assert(life::bind(Entry { access: 1, share: 1, file_object: reader, file: None }, &file_system, path).is_err(), "lifetime: FILE_OBJECT ligado uma unica vez");
    assert(life::validate_open(&file_system, path, 0x2, 7) == 0xC000_0043 && life::validate_open(&file_system, path, 0x1, 1) == 0 && life::validate_open(&file_system, path, 0x80, 0) == 0, "lifetime: SHARE_ACCESS e abertura so de metadados");
    assert(matches!(life::request_delete(&file_system, path, 0), Ok(0xC000_0043)), "lifetime: exclusao bloqueada por handle sem FILE_SHARE_DELETE");
    let _ = files::close_handle(reader);
    let deleter = open(path, 0x1_0000, 7);
    assert(matches!(life::request_delete(&file_system, path, deleter), Ok(0)) && unsafe { crate::ntos::inc::types::FileObject::at(deleter) }.delete_pending.get() == 1 && matches!(volume.exists(path), Ok(true)) && life::validate_open(&file_system, path, 0x1, 7) == 0xC000_0056, "lifetime: DELETE_PENDING publicado no FILE_OBJECT");
    let _ = files::close_handle(deleter);
    assert(matches!(volume.exists(path), Ok(false)), "lifetime: remocao fisica no CLEANUP da ultima descricao");
    // SECTION de dados conserva os bytes depois da retirada do nome.
    let _ = volume.create("/SEC.TXT", false, 0, 0);
    let _ = volume.write("/SEC.TXT", 0, b"secao");
    let section = life::retain_section(&file_system, "/SEC.TXT", false);
    let holder = open("/SEC.TXT", 0x1_0000, 7);
    assert(matches!(life::request_delete(&file_system, "/SEC.TXT", holder), Ok(0)), "lifetime: exclusao com SECTION de dados");
    let _ = files::close_handle(holder);
    assert(matches!(volume.exists("/SEC.TXT"), Ok(false)) && life::read_detached(section, 0, 5).is_some_and(|bytes| bytes == b"secao"), "lifetime: SECTION le os bytes orfaos");
    assert(matches!(life::write_detached(section, 0, b"S"), Ok(true)) && life::read_detached(section, 0, 5).is_some_and(|bytes| bytes == b"Secao") && life::write_detached(section, 4, b"xy").is_err(), "lifetime: writeback no armazenamento proprio e limite");
    assert(life::release_section(section).is_ok() && life::release_section(section).is_err() && life::read_detached(section, 0, 1).is_none(), "lifetime: liberacao da SECTION");
    // Imagem e somente leitura impedem a exclusão.
    let _ = volume.create("/IMG.TXT", false, 0, 0);
    let image = life::retain_section(&file_system, "/IMG.TXT", true);
    assert(matches!(life::request_delete(&file_system, "/IMG.TXT", 0), Ok(0xC000_0121)) && life::release_section(image).is_ok(), "lifetime: SECTION de imagem impede DELETE_ON_CLOSE");
    assert(matches!(life::request_delete(&file_system, "/IMG.TXT", 0), Ok(0)) && matches!(volume.exists("/IMG.TXT"), Ok(false)), "lifetime: sem descricoes a exclusao e imediata");
    let _ = volume.create("/RO.TXT", false, 1, 0);
    assert(matches!(life::request_delete(&file_system, "/RO.TXT", 0), Ok(0xC000_0121)) && volume.remove("/RO.TXT").is_ok(), "lifetime: arquivo somente leitura");
    assert(matches!(volume.list("/"), Ok(Some(names)) if boot_root(&names)), "lifetime: volume de volta ao estado inicial");
}

fn io_handles_and_volumes(assert: Assert) {
    use crate::ntos::io::file::convert_handle as convert;
    use crate::ntos::io::volume_parameters as volumes;
    use crate::ntos::ob::{close, object_manager, object_types, open_pointer};
    use crate::ntos::ob::objects::{device as device_objects, file as files};
    use crate::ntos::ob::handles::file as file_handles;
    // IoConvertFileHandleToKernelHandle.
    let file = files::create(0, "\\Phase4\\convert.txt").unwrap_or(0);
    let _ = files::open_handle(file);
    let output = guest::alloc_bytes(8);
    let _ = open_pointer::open(file, 0, 0, 0x1, object_types::file_type().pointer, 0, output);
    let handle = guest::read64(output);
    let granted = object_manager::handle_record((handle & 0x7FFF_FFFF) as u32).map_or(0, |record| record.access);
    guest::write64(output, 0xFFFF);
    assert(matches!(convert::convert(0, 1, 1, false, output), Ok(0)) && guest::read64(output) == 0, "convert: origem nula zera a saida");
    let wider = (object_types::file_type().valid_access & !granted) & (object_types::file_type().valid_access & !granted).wrapping_neg();
    assert(wider == 0 || (matches!(convert::convert(handle, 1, wider, false, output), Ok(0xC000_0022)) && guest::read64(output) == 0), "convert: pre-checagem de direitos");
    assert(wider == 0 || matches!(convert::convert(handle, 1, wider, true, output), Ok(0xC000_0022)), "convert: a duplicacao revalida mesmo sem pre-checagem");
    assert(matches!(convert::convert(0x7FFF_0000, 1, 1, false, output), Ok(0xC000_0008)), "convert: handle invalido");
    assert(matches!(convert::convert(handle, 1, granted, false, output), Ok(0)), "convert: conversao concluida");
    let kernel_handle = guest::read64(output);
    let target = file_handles::reference(kernel_handle, 0);
    assert(kernel_handle >> 31 == 0x1_FFFF_FFFF && matches!(&target, Ok(Ok(reference)) if reference.pointer == file) && files::state(file).is_some_and(|state| state.0 == 3), "convert: handle de kernel do mesmo FILE_OBJECT");
    if let Ok(Ok(mut reference)) = target {
        let _ = reference.release();
    }
    let _ = file_handles::close_kernel(kernel_handle);
    let _ = close::close(handle, Some(0));
    let _ = files::close_handle(file);
    let _ = files::dereference(file);
    // IoGetDiskDeviceObject pelo VPB do volume.
    /// `VPB_MOUNTED`.
    const VPB_MOUNTED: u16 = 1;
    let storage = guest::alloc_bytes(DeviceObject::SIZE);
    unsafe { DeviceObject::at(storage) }.vpb.set(0x1000);
    assert(matches!(volumes::get_disk_device(storage, output), Ok(0xC000_000D)), "vpb: dispositivo de armazenamento recusado");
    let file_system = guest::alloc_bytes(DeviceObject::SIZE);
    let extension = guest::alloc_bytes(DevobjExtension::SIZE);
    let volume = guest::alloc_bytes(Vpb::SIZE);
    unsafe { DeviceObject::at(file_system) }.device_object_extension.set(extension);
    assert(matches!(volumes::get_disk_device(file_system, output), Ok(0xC000_000D)), "vpb: volume sem VPB");
    unsafe { DevobjExtension::at(extension) }.vpb.set(volume);
    assert(matches!(volumes::get_disk_device(file_system, output), Ok(0xC000_026E)), "vpb: volume nao montado");
    let disk = guest::alloc_bytes(DeviceObject::SIZE);
    let _ = device_objects::register(disk, None, None);
    let vpb = unsafe { Vpb::at(volume) };
    vpb.reference_count.set(1);
    vpb.flags.set(VPB_MOUNTED);
    vpb.real_device.set(disk);
    let before = device_objects::reference_count(disk).unwrap_or(0);
    assert(matches!(volumes::get_disk_device(file_system, output), Ok(0)) && guest::read64(output) == disk && device_objects::reference_count(disk) == Some(before + 1), "vpb: disco real com referencia do Ob");
    let _ = device_objects::dereference(disk);
    let _ = device_objects::retire(disk);
    for pointer in [output, storage, file_system, extension, volume, disk] {
        guest::free_bytes(pointer);
    }
}

static PACKET_CALLBACK: [core::sync::atomic::AtomicU64; 2] = [const { core::sync::atomic::AtomicU64::new(0) }; 2];

extern "win64" fn test_packet_callback(packet: u64, context: u64) -> u64 {
    PACKET_CALLBACK[0].store(packet, core::sync::atomic::Ordering::SeqCst);
    PACKET_CALLBACK[1].store(context, core::sync::atomic::Ordering::SeqCst);
    0
}

/// Fonte bufferizada que entrega no máximo `limit` bytes.
struct ShortSource {
    limit: u64,
    empty: bool,
}

impl crate::ntos::io::transfer::backed_file_transfer::TransferSource for ShortSource {
    fn read_at(&self, offset: u64, length: u64) -> Result<Option<alloc::vec::Vec<u8>>, crate::rtl::KernelError> {
        if self.empty {
            return Ok(None);
        }
        let available = self.limit.saturating_sub(offset).min(length);
        Ok(Some((0..available).map(|index| (offset + index) as u8).collect()))
    }
}

fn io_packets_and_transfer(assert: Assert) {
    use crate::drivers::fs::ntfs;
    use crate::ntos::io::transfer::backed_file_transfer::{self as transfer, NtfsFile};
    use crate::ntos::io::transfer::completion_packets as packets;
    use crate::ntos::mm::kernel_pool::{self, AllocateOptions};
    // Mini pacotes de conclusão com cache limitado.
    packets::trim();
    let packet_type = |packet: u64| unsafe { IoMiniCompletionPacketUser::at(packet) }.packet_type.get();
    let first = packets::allocate(false);
    assert(first != 0 && packet_type(first) == 1 && packets::release(first).is_ok() && packets::is_cached(first) && packets::release(first).is_err(), "packets: bloco devolvido ao cache uma unica vez");
    let reused = packets::allocate(true);
    assert(reused == first && packet_type(reused) == 1 && packets::cached_count() == 0, "packets: bloco do cache sem nova cobranca");
    let charged = packets::allocate(true);
    assert(charged != 0 && packet_type(charged) == 3 && packets::release(charged).is_ok() && packets::release(reused).is_ok() && packets::cached_count() == 2, "packets: pacote cobrado (tipo 3) tambem volta ao cache");
    let many: alloc::vec::Vec<u64> = (0..20).map(|_| packets::allocate(false)).collect();
    for &packet in &many {
        let _ = packets::release(packet);
    }
    assert(packets::cached_count() == packets::CACHE_CAPACITY, "packets: cache limitado a 16 blocos");
    packets::trim();
    assert(packets::cached_count() == 0, "packets: trim libera os ociosos");
    // Pacotes de usuário (tipo 4).
    let user = kernel_pool::allocate(packets::USER_PACKET_BYTE_LENGTH, AllocateOptions { tag: packets::PACKET_TAG, zero: true, ..Default::default() }).unwrap_or(0);
    let user_packet = unsafe { IoMiniCompletionPacketUser::at(user) };
    user_packet.packet_type.set(4);
    user_packet.mini_packet_callback.set(test_packet_callback as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    user_packet.context.set(0xC0DE);
    assert(packets::release(user).is_ok() && PACKET_CALLBACK[0].load(core::sync::atomic::Ordering::SeqCst) == user && PACKET_CALLBACK[1].load(core::sync::atomic::Ordering::SeqCst) == 0xC0DE && kernel_pool::info(user).is_some(), "packets: callback do usuario recebe a posse");
    user_packet.mini_packet_callback.set(0);
    user_packet.allocated.set(1);
    assert(packets::release(user).is_ok() && kernel_pool::info(user).is_none(), "packets: Allocated devolve o bloco ao pool");
    let invalid = guest::alloc_bytes(IoMiniCompletionPacketUser::SIZE);
    unsafe { IoMiniCompletionPacketUser::at(invalid) }.packet_type.set(7);
    assert(packets::release(invalid).is_err(), "packets: tipo invalido recusado");
    guest::free_bytes(invalid);
    // Transferência de arquivo para o buffer do chamador.
    let Ok(volume) = ntfs::mount(1) else {
        assert(false, "transfer: montagem");
        return;
    };
    let pattern: alloc::vec::Vec<u8> = (0..70_000u32).map(|index| (index % 253) as u8).collect();
    let _ = volume.create("/XFER.BIN", false, 0, 0);
    let _ = volume.write("/XFER.BIN", 0, &pattern);
    let output = guest::alloc_bytes(70_016);
    let source = NtfsFile { volume: volume.clone(), path: alloc::string::String::from("/XFER.BIN") };
    assert(matches!(transfer::read_into_guest(&source, 0, output, 70_000), Ok(70_000)) && guest::read_bytes(output, 70_000) == pattern, "transfer: blocos de 64 KB por DMA com paginas fixadas");
    guest::write_bytes(output, &[0; 64]);
    assert(matches!(transfer::read_into_guest(&source, 100, output + 3, 20), Ok(20)) && guest::read_bytes(output + 3, 20) == pattern[100..120], "transfer: faixa desalinhada");
    assert(matches!(transfer::read_into_guest(&ShortSource { limit: 10, empty: false }, 0, output, 100), Ok(10)) && guest::read_bytes(output, 10) == (0..10u8).collect::<alloc::vec::Vec<u8>>(), "transfer: leitura curta encerra sem zeros");
    assert(transfer::read_into_guest(&ShortSource { limit: 0, empty: true }, 0, output, 8).is_err_and(|error| error.status == 0xC000_0185), "transfer: provedor sem dados");
    let _ = volume.remove("/XFER.BIN");
    guest::free_bytes(output);
}

/// (chamadas, IsEnabled, nível, contexto) da rotina de habilitação ETW.
static ETW_CALLBACK: [core::sync::atomic::AtomicU64; 4] = [const { core::sync::atomic::AtomicU64::new(0) }; 4];
static ETW_EVENTS: crate::rtl::SpinLock<alloc::vec::Vec<crate::ntos::etw::provider_state::Event>> = crate::rtl::SpinLock::new(alloc::vec::Vec::new());

extern "win64" fn test_etw_enable(_source: u64, enabled: u64, level: u64, _any: u64, _all: u64, _filter: u64, context: u64) -> u64 {
    use core::sync::atomic::Ordering::SeqCst;
    ETW_CALLBACK[0].fetch_add(1, SeqCst);
    ETW_CALLBACK[1].store(enabled, SeqCst);
    ETW_CALLBACK[2].store(level, SeqCst);
    ETW_CALLBACK[3].store(context, SeqCst);
    0
}

fn etw_firmware_and_telemetry(assert: Assert) {
    use crate::ntos::etw::{event_enabled, provider_state as etw};
    use crate::hal::firmware_environment as firmware;
    use crate::ntos::se::capability::telemetry;
    use core::sync::atomic::Ordering::SeqCst;
    // Ambiente de firmware pelo handoff BIOS do stage2.
    assert(matches!(firmware::firmware_type(), Ok(1)) && matches!(firmware::query(0, 0, 0, 0, 0), Ok(0xC000_0002)), "firmware: BIOS legado sem variaveis EFI");
    // Registro sem sessões não habilita nada.
    let guid = guest::alloc_bytes(0x80);
    guest::write_bytes(guid, &[0x11; 16]);
    let output = guest::alloc_bytes(16);
    let descriptor = guid + 0x20;
    let event_descriptor = unsafe { EventDescriptor::at(descriptor) };
    event_descriptor.level.set(4);
    event_descriptor.keyword.set(0x10);
    let (registrations, guids, sessions) = etw::statistics();
    assert(matches!(etw::register(guid, 0, 0x1234, output, false), Ok(0xC000_000D)) && guest::read64(output) == 0, "etw: contexto sem callback recusado");
    let reserved = guid + 0x40;
    guest::write_bytes(reserved, &[37, 150, 132, 84, 120, 84, 148, 73, 165, 186, 62, 59, 3, 40, 195, 13]);
    assert(matches!(etw::register(reserved, 0, 0, output, false), Ok(0xC000_000D)), "etw: GUID reservado recusado");
    assert(matches!(etw::register(guid, 0, 0, output, false), Ok(0)), "etw: EtwRegister");
    let plain = guest::read64(output);
    assert(plain != 0 && etw::statistics() == (registrations + 1, guids + 1, sessions) && event_enabled::query(plain, descriptor) == 0 && matches!(etw::write(plain, descriptor, 0, 0, 0, 0), Ok(0)), "etw: provedor sem sessao nao entrega eventos");
    // Sessão com consumidor habilita o provedor e notifica callbacks.
    ETW_EVENTS.lock().clear();
    for slot in &ETW_CALLBACK {
        slot.store(0, SeqCst);
    }
    let session = etw::open_session(alloc::sync::Arc::new(|event: &etw::Event| ETW_EVENTS.lock().push(event.clone())), Some(0), None).unwrap_or(0);
    assert(session != 0 && etw::enable(session, guid, etw::EnableOptions::default()).is_ok() && event_enabled::query(plain, descriptor) == 1 && unsafe { EtwRegEntry::at(plain) }.enable_mask.get() == 1, "etw: sessao habilita o provedor (mascara de slots)");
    let callback = test_etw_enable as extern "win64" fn(u64, u64, u64, u64, u64, u64, u64) -> u64 as usize as u64;
    assert(matches!(etw::register(guid, callback, 0xC0DE, output, false), Ok(0)) && ETW_CALLBACK[0].load(SeqCst) == 1 && ETW_CALLBACK[1].load(SeqCst) == 1 && ETW_CALLBACK[2].load(SeqCst) == 255 && ETW_CALLBACK[3].load(SeqCst) == 0xC0DE, "etw: registro habilitado chama o callback na hora");
    let notified = guest::read64(output);
    // EtwWrite entrega cópias dos dados à sessão.
    let data = guid + 0x60;
    guest::write_bytes(guid + 0x50, b"etw!");
    let data_descriptor = unsafe { EventDataDescriptor::at(data) };
    data_descriptor.ptr.set(guid + 0x50);
    data_descriptor.size.set(4);
    assert(matches!(etw::write(plain, descriptor, 0, 0, 1, data), Ok(0)) && ETW_EVENTS.lock().len() == 1 && ETW_EVENTS.lock()[0].data == alloc::vec![b"etw!".to_vec()] && ETW_EVENTS.lock()[0].provider == [0x11; 16] && etw::delivered(session) == Some(1), "etw: EtwWrite entrega o evento ao consumidor");
    assert(matches!(etw::write(plain, descriptor, 0, 0, 129, data), Ok(0xC000_000D)), "etw: descritores demais");
    assert(etw::enable(session, guid, etw::EnableOptions { level: 2, ..Default::default() }).is_ok() && ETW_CALLBACK[2].load(SeqCst) == 2 && matches!(etw::write(plain, descriptor, 0, 0, 1, data), Ok(0)) && ETW_EVENTS.lock().len() == 1, "etw: nivel acima do habilitado nao entrega");
    assert(etw::disable(session, guid).is_ok() && ETW_CALLBACK[1].load(SeqCst) == 0 && event_enabled::query(plain, descriptor) == 0, "etw: desabilitar notifica e limpa IsEnabled");
    assert(matches!(etw::unregister(notified), Ok(0)) && matches!(etw::unregister(notified), Ok(0xC000_0008)) && matches!(etw::unregister(plain), Ok(0)) && !etw::is_registered(plain), "etw: EtwUnregister");
    // Telemetria de RtlCapabilityCheck pela mesma infraestrutura.
    let telemetry_guid = guid + 0x70;
    let identifier: alloc::vec::Vec<u8> = (0..16).map(|index| u8::from_str_radix(&telemetry::PROVIDER_IDENTIFIER[index * 2..index * 2 + 2], 16).unwrap_or(0)).collect();
    guest::write_bytes(telemetry_guid, &identifier);
    assert(etw::enable(session, telemetry_guid, etw::EnableOptions::default()).is_ok(), "telemetry: sessao habilita o provedor de capabilities");
    let frequency = crate::ntos::ke::clock::tsc_frequency_hz();
    telemetry::record(1000, 1000 + frequency / 1000, 1, 0, 1, 1);
    let events = ETW_EVENTS.lock().clone();
    let latency = events.last().map(|event| event.data.get(2).cloned().unwrap_or_default()).unwrap_or_default();
    let expected = ((frequency / 1000).wrapping_mul(1_000_000) as i64 / frequency as i64) as u64;
    assert(events.len() == 2 && events[1].data.len() == 7, "telemetry: evento entregue com sete segmentos");
    assert(latency.len() == 8 && u64::from_le_bytes(latency.clone().try_into().unwrap_or([0; 8])) == expected && (999..=1000).contains(&expected) && events[1].data[3] == [1] && events[1].data[4] == [0], "telemetry: latencia em microssegundos e os quatro campos");
    telemetry::record(1000, 2000, 0, 0, 0, 0);
    assert(ETW_EVENTS.lock().len() == 2, "telemetry: um evento a cada 100 consultas");
    assert(etw::close_session(session).is_ok() && etw::statistics().2 == sessions, "etw: sessao encerrada");
    guest::free_bytes(guid);
    guest::free_bytes(output);
}

/// A raiz do volume como o build a entrega: HELLO.TXT, os binários reais do
/// Windows copiados como extras (.SYS, .DLL, .EXE, .NLS) e a árvore `Windows`.
fn boot_root(names: &[alloc::string::String]) -> bool {
    names.iter().any(|name| name == "/HELLO.TXT") && names.iter().all(|name| name == "/HELLO.TXT" || name == "/Windows" || [".SYS", ".DLL", ".EXE", ".NLS"].iter().any(|extension| name.ends_with(extension)))
}

/// Arquivos e diretórios abaixo de `path`, recursivamente (um registro cada).
fn tree_entries(volume: &crate::drivers::fs::ntfs::Ntfs, path: &str) -> u64 {
    volume.list(path).ok().flatten().unwrap_or_default().iter().map(|name| 1 + if matches!(volume.stat(name), Ok(Some(stat)) if stat.directory) { tree_entries(volume, name) } else { 0 }).sum()
}

pub fn run(assert: Assert) {
    pci_configuration(assert);
    irp_builder(assert);
    power_manager(assert);
    black_box_recorder(assert);
    io_manager_native(assert);
    io_manager_devices(assert);
    pci_bus_driver(assert);
    motherboard_bus_driver(assert);
    ata_disk(assert);
    ntfs_reader(assert);
    extended_attributes(assert);
    ntfs_writer(assert);
    fs_volume_queries(assert);
    io_small_modules(assert);
    io_controller_and_start_io(assert);
    io_file_lifetime(assert);
    io_handles_and_volumes(assert);
    io_packets_and_transfer(assert);
    etw_firmware_and_telemetry(assert);
    debug_print!("PHASE4_SELFTEST_OK");
}
