//! Autoteste do suporte do PnP manager à pilha de armazenamento real
//! (chamado pela fase 4).
//!
//! - O PDO PCI da controladora IDE do PIIX3 responde como o pci.sys: os ids
//!   nos formatos do pci.sys (o DeviceID e o InstanceID que um Windows nesta
//!   VM mostra, `PCI\VEN_8086&DEV_7010&SUBSYS_11001AF4&REV_00\...&09`), as
//!   capacidades (Address = dispositivo << 16 | função), os requisitos (só o
//!   BAR4 de bus master: os BARs do canal legado não são decodificados), o
//!   barramento, os textos da tabela de mensagens do pci.sys, o
//!   QUERY_INTERFACE de BUS_INTERFACE_STANDARD (GetBusData chamado pelo stub
//!   nativo lê o vendor/device) e o READ_CONFIG.
//! - IoGetDmaAdapter no PDO chega ao adaptador da HAL pela interface do
//!   barramento: tabela V2 (Size 0x138, rotinas V3 nulas), 17 registradores
//!   de mapa para 64 KB, buffer comum com endereço lógico físico,
//!   CalculateScatterGatherList e MapTransfer pelos stubs nativos.
//! - O hash do ParentIdPrefix confere com o prefixo real de um Windows nesta
//!   VM (`ACPI\PNP0A03\0` -> 267a616a, o "3&267a616a&0" das instâncias PCI).
//! - A escolha de driver pelos INFs segue o posto (intelide para 7010,
//!   atapi para o canal, disk para GenDisk), e os árbitros e o tradutor da
//!   raiz atribuem e traduzem recursos (conflito cai na alternativa, sem
//!   janelas de barramento; IRQ 14 vira o vetor 0x2E no IRQL 14).
//! - Um requisito sob um barramento cujo driver arbitra o tipo vai ao
//!   ArbiterHandler dele (TestAllocation com o ARBITER_LIST_ENTRY do PDO,
//!   CommitAllocation), a lista bruta é o Assignment preenchido, e a
//!   liberação é o pedido nulo do PDO.
//! - Um devnode sintético responde IoGetDeviceProperty e
//!   IoOpenDeviceRegistryKey pela árvore do PnP.
//! - As linhas do display.inf (BasicDisplay.sys do repositório de drivers
//!   para PCI\CC_0300, com o ExcludeID da seção) e do machine.inf
//!   (msisadrv.sys para PCI\CC_0601), e o BAR pré-buscável do adaptador VGA
//!   com CM_RESOURCE_MEMORY_PREFETCHABLE.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::drivers::bus::{pci, pci_interface};
use crate::hal::amd64::{native_call, routine_stubs};
use crate::ntos::inc::types::extra_storage::{BusInterfaceStandard, DeviceDescription, DmaAdapter, DmaOperations, PnpBusInformation};
use crate::ntos::inc::types::{DeviceCapabilities, DeviceObject, IoResourceDescriptor, IoResourceRequirementsList, IoStackLocation, Irp, NtStruct};
use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
use crate::ntos::io::pnp::{self, devnode, install, resources, tree};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

type Assert = fn(bool, &str);

/// Um IRP_MJ_PNP montado à mão no PDO: (status, Information).
fn pnp_irp(pdo: u64, minor: u8, fill: impl FnOnce(&IoStackLocation)) -> (i32, u64) {
    let packet = guest::alloc_bytes(builder::size_for(1));
    builder::build(packet, &BuildOptions { major: 0x1B, minor, device_object: pdo, ..Default::default() });
    // SAFETY: IRP recém-montado.
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(0xC000_00BBu32 as i32);
    // SAFETY: a posição do topo do IRP de uma posição.
    let location = unsafe { IoStackLocation::at(builder::first_stack_location(packet, 1)) };
    fill(location);
    let status = crate::ntos::io::io_manager::iof_call_driver(pdo, packet);
    let information = irp.io_status.information.get();
    guest::free_bytes(packet);
    (status, information)
}

fn pci_function_pdo(assert: Assert) {
    use crate::ntos::inc::types::{BusQueryIdType, DeviceTextType};
    let Some(ide) = pci::find_by_id(0x8086, 0x7010) else {
        assert(false, "pnp-storage: IDE do PIIX3 enumerado");
        return;
    };
    let id = |id_type: BusQueryIdType| -> Vec<String> {
        let (status, information) = pnp_irp(ide.pdo_pointer, 0x13, |location| location.parameters.query_id.id_type.set(id_type));
        let mut ids = Vec::new();
        if status == 0 && information != 0 {
            let mut cursor = information;
            loop {
                let text = guest_strings::read_wide_string(cursor);
                if text.is_empty() {
                    break;
                }
                cursor += (text.encode_utf16().count() as u64 + 1) * 2;
                ids.push(text);
            }
            guest::free_bytes(information);
        }
        ids
    };
    assert(id(BusQueryIdType::BUS_QUERY_DEVICE_ID) == ["PCI\\VEN_8086&DEV_7010&SUBSYS_11001AF4&REV_00"], "pnp-storage: DeviceID do PIIX3 no formato do pci.sys");
    assert(id(BusQueryIdType::BUS_QUERY_INSTANCE_ID) == ["09"], "pnp-storage: InstanceID = dispositivo << 3 | funcao");
    assert(id(BusQueryIdType::BUS_QUERY_HARDWARE_I_DS) == ["PCI\\VEN_8086&DEV_7010&SUBSYS_11001AF4&REV_00", "PCI\\VEN_8086&DEV_7010&SUBSYS_11001AF4", "PCI\\VEN_8086&DEV_7010&CC_010180", "PCI\\VEN_8086&DEV_7010&CC_0101"], "pnp-storage: HardwareIDs do pci.sys");
    let compatible = id(BusQueryIdType::BUS_QUERY_COMPATIBLE_I_DS);
    assert(compatible.len() == 7 && compatible[1] == "PCI\\VEN_8086&DEV_7010" && compatible[6] == "PCI\\CC_0101", "pnp-storage: CompatibleIDs do pci.sys");
    // A escolha pelos INFs: intelide (VEN&DEV compatível) antes do pciide (CC_0101).
    let hardware = id(BusQueryIdType::BUS_QUERY_HARDWARE_I_DS);
    assert(install::select_driver(&hardware, &compatible).is_some_and(|driver| driver.service.is_some_and(|service| service.name == "intelide")), "pnp-storage: PCI\\VEN_8086&DEV_7010 instala o intelide.sys");
    assert(install::select_driver(&[String::from("Internal_IDE_Channel")], &[String::from("*PNP0600")]).is_some_and(|driver| driver.service.is_some_and(|service| service.name == "atapi")), "pnp-storage: canal IDE instala o atapi.sys");
    assert(install::select_driver(&[String::from("IDE\\DiskQEMU_HARDDISK___________________________2.5+____")], &[String::from("IDE\\Disk"), String::from("GenDisk")]).is_some_and(|driver| driver.class.name == "DiskDrive"), "pnp-storage: GenDisk instala o disk.sys");
    // O controlador NVMe do QEMU: o stornvme.inf casa pela classe 01.08.02
    // (PCI\CC_010802), entre os CompatibleIDs, na classe SCSIAdapter.
    let nvme = install::select_driver(&[String::from("PCI\\VEN_1B36&DEV_0010&SUBSYS_11001AF4&REV_02"), String::from("PCI\\VEN_1B36&DEV_0010&CC_010802")], &[String::from("PCI\\VEN_1B36&DEV_0010"), String::from("PCI\\CC_010802"), String::from("PCI\\CC_0108")]);
    assert(nvme.is_some_and(|driver| driver.inf == "stornvme.inf" && driver.class.name == "SCSIAdapter" && driver.service.is_some_and(|service| service.name == "stornvme" && service.group == Some("SCSI Miniport"))), "pnp-storage: PCI\\CC_010802 instala o stornvme.sys (stornvme.inf, SCSIAdapter)");
    // QUERY_CAPABILITIES.
    let capabilities = guest::alloc_bytes(DeviceCapabilities::SIZE);
    let (status, _) = pnp_irp(ide.pdo_pointer, 0x09, |location| location.parameters.device_capabilities.capabilities.set(capabilities));
    // SAFETY: bloco recém-alocado.
    let address = unsafe { DeviceCapabilities::at(capabilities) }.address.get();
    assert(status == 0 && address == (ide.device << 16 | ide.function), "pnp-storage: Address = dispositivo << 16 | funcao");
    guest::free_bytes(capabilities);
    // QUERY_RESOURCE_REQUIREMENTS: só o BAR4 (16 portas), preferido + alternativa.
    let (status, list) = pnp_irp(ide.pdo_pointer, 0x0B, |_| {});
    // SAFETY: lista devolvida pelo barramento.
    let header = unsafe { IoResourceRequirementsList::at(list) };
    let alternative = &header.list[0];
    // SAFETY: os descritores da lista.
    let descriptors = unsafe { IoResourceDescriptor::array_at(alternative.descriptors[0].address(), alternative.count.get() as usize) };
    let bar4 = ide.bars.iter().find(|bar| bar.index == 4).map_or(0, |bar| (bar.value & !3) as i64);
    assert(status == 0 && alternative.count.get() == 2 && descriptors[0].type_.get() == 1 && descriptors[0].u.port.length.get() == 16 && descriptors[0].u.port.minimum_address.quad_part.get() == bar4 && descriptors[1].option.get() == 8, "pnp-storage: requisitos sem os BARs do canal legado");
    let requirements = resources::Requirements::read(list).unwrap_or_default();
    assert(requirements.alternatives.len() == 1 && requirements.alternatives[0].len() == 1 && requirements.alternatives[0][0].len() == 2, "pnp-storage: a alternativa do BAR fica no mesmo requisito");
    // FILTER_RESOURCE_REQUIREMENTS com a lista parte com STATUS_SUCCESS (o
    // IopFilterResourceRequirementsCall) e o barramento, que não trata o
    // pedido, o devolve como chegou: sucesso com a mesma lista.
    let filtered = pnp::irp::filter_resource_requirements_call(ide.pdo_pointer, list);
    let without_list = pnp::irp::filter_resource_requirements_call(ide.pdo_pointer, 0);
    assert(filtered.is_ok_and(|outcome| outcome.status == 0 && outcome.information == list) && without_list.is_ok_and(|outcome| outcome.status == 0xC000_00BBu32 as i32), "pnp-storage: FILTER_RESOURCE_REQUIREMENTS parte com STATUS_SUCCESS e a lista; sem lista, STATUS_NOT_SUPPORTED");
    guest::free_bytes(list);
    // QUERY_BUS_INFORMATION e QUERY_DEVICE_TEXT.
    let (status, information) = pnp_irp(ide.pdo_pointer, 0x15, |_| {});
    // SAFETY: PNP_BUS_INFORMATION devolvida.
    let bus = unsafe { PnpBusInformation::at(information) };
    assert(status == 0 && bus.legacy_bus_type.get().0 == 5 && bus.bus_type_guid.data1.get() == 0xC8EB_DFB0, "pnp-storage: barramento PCI (GUID_BUS_TYPE_PCI)");
    guest::free_bytes(information);
    let text = |text_type: DeviceTextType| -> String {
        let (_, information) = pnp_irp(ide.pdo_pointer, 0x0C, |location| location.parameters.query_device_text.device_text_type.set(text_type));
        let text = if information != 0 { guest_strings::read_wide_string(information) } else { String::new() };
        if information != 0 {
            guest::free_bytes(information);
        }
        text
    };
    assert(text(DeviceTextType::DEVICE_TEXT_DESCRIPTION) == "IDE Controller" && text(DeviceTextType::DEVICE_TEXT_LOCATION_INFORMATION) == "PCI bus 0, device 1, function 1", "pnp-storage: textos da tabela de mensagens do pci.sys");
    // Um minor que o barramento não atende volta completado com o status que chegou.
    let (status, _) = pnp_irp(ide.pdo_pointer, 0x18, |_| {});
    assert(status == 0xC000_00BBu32 as i32, "pnp-storage: minor sem resposta completado com STATUS_NOT_SUPPORTED");
    // QUERY_INTERFACE(GUID_BUS_INTERFACE_STANDARD) e GetBusData pelo stub.
    let guid = guest::alloc_bytes(16);
    guest::write_bytes(guid, &pci_interface::GUID_BUS_INTERFACE_STANDARD);
    let interface = guest::alloc_bytes(BusInterfaceStandard::SIZE);
    let status = pnp::query_interface(ide.pdo_pointer, guid, 1, BusInterfaceStandard::SIZE as u16, 0, interface).unwrap_or(0xFFFF_FFFF);
    // SAFETY: interface preenchida pelo barramento.
    let bus_interface = unsafe { BusInterfaceStandard::at(interface) };
    let read = guest::alloc_bytes(4);
    let bytes = native_call::call(bus_interface.get_bus_data.get(), &[bus_interface.interface.context.get(), 0, read, 0, 4]);
    assert(status == 0 && bus_interface.interface.context.get() == ide.pdo_pointer && bytes == 4 && guest::read32(read) == 0x7010_8086, "pnp-storage: GetBusData da BUS_INTERFACE_STANDARD le o vendor/device");
    // O DataType PCIConfiguration (4), que o storport.sys repassa do miniport,
    // também lê a configuração; o da ROM ('PciR') não lê nada.
    guest::write32(read, 0);
    let configuration = native_call::call(bus_interface.get_bus_data.get(), &[ide.pdo_pointer, 4, read, 0, 4]);
    let configuration_value = guest::read32(read);
    guest::write32(read, 0);
    let rom = native_call::call(bus_interface.get_bus_data.get(), &[ide.pdo_pointer, 0x5269_6350, read, 0, 4]);
    assert(configuration == 4 && configuration_value == 0x7010_8086 && rom == 0 && guest::read32(read) == 0, "pnp-storage: GetBusData com PCIConfiguration le a configuracao, com PCI_WHICHSPACE_ROM nao");
    let before = pci_interface::references(ide.pdo_pointer);
    native_call::call(bus_interface.interface.interface_dereference.get(), &[ide.pdo_pointer]);
    assert(pci_interface::references(ide.pdo_pointer) == before - 1, "pnp-storage: InterfaceDereference");
    // IRP_MN_READ_CONFIG.
    guest::write32(read, 0);
    let (status, information) = pnp_irp(ide.pdo_pointer, 0x0F, |location| {
        let config = &location.parameters.read_write_config;
        config.which_space.set(0);
        config.buffer.set(read);
        config.offset.set(0);
        config.length.set(4);
    });
    assert(status == 0 && information == 4 && guest::read32(read) == 0x7010_8086, "pnp-storage: IRP_MN_READ_CONFIG");
    guest::free_bytes(read);
    guest::free_bytes(interface);
    guest::free_bytes(guid);
}

fn dma_adapter(assert: Assert) {
    let Some(ide) = pci::find_by_id(0x8086, 0x7010) else { return };
    let description = guest::alloc_bytes(DeviceDescription::SIZE);
    // SAFETY: bloco recém-alocado.
    let device_description = unsafe { DeviceDescription::at(description) };
    device_description.version.set(2);
    device_description.master.set(1);
    device_description.scatter_gather.set(1);
    device_description.dma32_bit_addresses.set(1);
    device_description.interface_type.set(crate::ntos::inc::types::InterfaceType::PCI_BUS);
    device_description.maximum_length.set(0x10000);
    let registers = guest::alloc_bytes(4);
    let adapter = super::phase6::call_export("IoGetDmaAdapter", &[ide.pdo_pointer, description, registers]).unwrap_or(0);
    assert(adapter != 0 && crate::hal::dma::is_adapter(adapter) && guest::read32(registers) == 17, "pnp-storage: IoGetDmaAdapter pela interface do barramento, 17 registradores para 64 KB");
    if adapter == 0 {
        return;
    }
    // SAFETY: DMA_ADAPTER e DMA_OPERATIONS devolvidos pela HAL.
    let header = unsafe { DmaAdapter::at(adapter) };
    // SAFETY: tabela de operações do adaptador.
    let operations = unsafe { DmaOperations::at(header.dma_operations.get()) };
    assert(header.version.get() == 1 && operations.size.get() == 0x138 && operations.get_scatter_gather_list.get() == routine_stubs::address("HalGetScatterGatherList").unwrap_or(1) && operations.get_dma_adapter_info.get() == 0 && operations.allocate_common_buffer_ex.get() != 0, "pnp-storage: tabela de operacoes V2 (Size 0x138, rotinas V3 nulas)");
    // AllocateCommonBuffer: endereço lógico = físico.
    let logical = guest::alloc_bytes(8);
    let va = native_call::call(operations.allocate_common_buffer.get(), &[adapter, 0x2000, logical, 1]);
    assert(va != 0 && va & 0xFFF == 0 && guest::read64(logical) == crate::ntos::mm::paging::translate(va), "pnp-storage: buffer comum alinhado com endereco logico fisico");
    // MapTransfer e CalculateScatterGatherList num MDL do buffer comum.
    let mdl = crate::ntos::io::mdl::allocate_mdl(va + 0x100, 0x1000);
    crate::ntos::mm::mdl::build_for_non_paged_pool(mdl);
    let length = guest::alloc_bytes(4);
    guest::write32(length, 0x1000);
    let physical = native_call::call(operations.map_transfer.get(), &[adapter, mdl, 0, va + 0x100, length, 0]);
    assert(physical == guest::read64(logical) + 0x100 && guest::read32(length) == 0x1000, "pnp-storage: MapTransfer devolve o trecho fisico contiguo");
    let size = guest::alloc_bytes(4);
    let status = native_call::call(operations.calculate_scatter_gather_list.get(), &[adapter, mdl, va + 0x100, 0x1000, size, 0]);
    assert(status == 0 && guest::read32(size) == 0x10 + 0x18, "pnp-storage: CalculateScatterGatherList com um elemento (pagina fisica contigua)");
    native_call::call(operations.free_common_buffer.get(), &[adapter, 0x2000, guest::read64(logical), va, 1]);
    native_call::call(operations.put_dma_adapter.get(), &[adapter]);
    assert(!crate::hal::dma::is_adapter(adapter), "pnp-storage: PutDmaAdapter");
    // DEVICE_DESCRIPTION da versão 3 (a do KMDF): a tabela HalpDmaOperationsV3.
    device_description.version.set(3);
    device_description.dma_address_width.set(32);
    let adapter = super::phase6::call_export("IoGetDmaAdapter", &[ide.pdo_pointer, description, registers]).unwrap_or(0);
    if adapter != 0 {
        // SAFETY: DMA_ADAPTER e DMA_OPERATIONS devolvidos pela HAL.
        let operations = unsafe { DmaOperations::at(DmaAdapter::at(adapter).dma_operations.get()) };
        assert(operations.size.get() == 0x138 && operations.get_dma_adapter_info.get() == routine_stubs::address("HalGetDmaAdapterInfo").unwrap_or(1) && operations.build_scatter_gather_list_ex.get() == routine_stubs::address("HalBuildScatterGatherListEx").unwrap_or(1) && operations.free_common_buffer_vector.get() != 0, "pnp-storage: IoGetDmaAdapter da versao 3 com a tabela V3 completa");
        // GetDmaAdapterInfo: só a versão 1; o caminho de bus master.
        let information = guest::alloc_bytes(0x18);
        guest::write32(information, 2);
        let refused = native_call::call(operations.get_dma_adapter_info.get(), &[adapter, information]);
        guest::write32(information, 1);
        let answered = native_call::call(operations.get_dma_adapter_info.get(), &[adapter, information]);
        let fields: alloc::vec::Vec<u32> = (0..6).map(|index| guest::read32(information + index * 4)).collect();
        assert(refused as u32 == 0xC000_00BB && answered == 0 && fields == [1, 0, u32::MAX, 32, 3, 1], "pnp-storage: GetDmaAdapterInfo V1 (largura 32, SYNCHRONOUS_CALLBACK | API_BYPASS)");
        // InitializeDmaTransferContext: Version 1 e o bit 1 de +0x24.
        let context = guest::alloc_bytes(0x80);
        guest::write_bytes(context, &[0xAA; 0x80]);
        native_call::call(operations.initialize_dma_transfer_context.get(), &[adapter, context]);
        let cleared = guest::read_bytes(context, 0x80);
        assert(guest::read32(context) == 1 && guest::read32(context + 0x24) == 2 && cleared.iter().enumerate().all(|(index, &byte)| index < 4 || (0x24..0x28).contains(&index) || byte == 0), "pnp-storage: InitializeDmaTransferContext zera o contexto com Version 1");
        // GetDmaTransferInfo e BuildScatterGatherListEx no MDL do buffer comum
        // (Offset a partir do início do MDL).
        let va = native_call::call(operations.allocate_common_buffer.get(), &[adapter, 0x2000, logical, 1]);
        let mdl = crate::ntos::io::mdl::allocate_mdl(va + 0x100, 0x1000);
        crate::ntos::mm::mdl::build_for_non_paged_pool(mdl);
        let transfer = guest::alloc_bytes(0x14);
        guest::write32(transfer, 1);
        let info = native_call::call(operations.get_dma_transfer_info.get(), &[adapter, mdl, 0x10, 0x800, 0, transfer]);
        assert(info == 0 && guest::read32(transfer + 4) == 1 && guest::read32(transfer + 8) == 1 && guest::read32(transfer + 0xC) == 0x28, "pnp-storage: GetDmaTransferInfo V1 (uma pagina, um elemento, lista de 0x28 bytes)");
        let buffer = guest::alloc_bytes(0x40);
        let list_cell = guest::alloc_bytes(8);
        let built = native_call::call(operations.build_scatter_gather_list_ex.get(), &[adapter, 0, context, mdl, 0x10, 0x800, 1, 0, 0, 1, buffer, 0x40, 0, 0, list_cell]);
        let physical = guest::read64(logical);
        assert(built == 0 && guest::read64(list_cell) == buffer && guest::read32(buffer) == 1 && guest::read64(buffer + 0x10) == physical + 0x110 && guest::read32(buffer + 0x18) == 0x800, "pnp-storage: BuildScatterGatherListEx sincrono com o trecho fisico do Offset");
        let small = native_call::call(operations.build_scatter_gather_list_ex.get(), &[adapter, 0, context, mdl, 0, 0x1000, 1, 0, 0, 1, buffer, 0x20, 0, 0, list_cell]);
        assert(small as u32 == 0xC000_0023, "pnp-storage: BuildScatterGatherListEx com buffer pequeno = STATUS_BUFFER_TOO_SMALL");
        let got = native_call::call(operations.get_scatter_gather_list_ex.get(), &[adapter, 0, context, mdl, 0, 0x1000, 1, 0, 0, 1, 0, 0, list_cell]);
        let list = guest::read64(list_cell);
        assert(got == 0 && list != buffer && guest::read32(list) == 1 && guest::read64(list + 0x10) == physical + 0x100, "pnp-storage: GetScatterGatherListEx sincrono aloca a lista");
        native_call::call(operations.put_scatter_gather_list.get(), &[adapter, list, 1]);
        assert(native_call::call(operations.cancel_mapped_transfer.get(), &[adapter, context]) as u32 == 0xC000_000D && native_call::call(operations.get_dma_domain.get(), &[adapter]) == 0, "pnp-storage: bus master sem transferencia mapeada a cancelar nem dominio");
        native_call::call(operations.free_common_buffer.get(), &[adapter, 0x2000, physical, va, 1]);
        native_call::call(operations.put_dma_adapter.get(), &[adapter]);
        for block in [information, context, mdl, transfer, buffer, list_cell] {
            guest::free_bytes(block);
        }
    } else {
        assert(false, "pnp-storage: IoGetDmaAdapter da versao 3");
    }
    for block in [mdl, length, size, logical, registers, description] {
        guest::free_bytes(block);
    }
    dma_adapter_v3(assert, ide.pdo_pointer);
}

/// DEVICE_DESCRIPTION versão 3 (o HalGetAdapterV3 que o storport.sys pede):
/// a tabela HalpDmaOperationsV3, o GetDmaAdapterInfo com a largura do
/// DmaAddressWidth, o FlushDmaBuffer e o FlushAdapterBuffersEx; abaixo de 32
/// bits não há adaptador.
fn dma_adapter_v3(assert: Assert, pdo: u64) {
    let description = guest::alloc_bytes(DeviceDescription::SIZE);
    // SAFETY: bloco recém-alocado.
    let device_description = unsafe { DeviceDescription::at(description) };
    device_description.version.set(3);
    device_description.master.set(1);
    device_description.scatter_gather.set(1);
    device_description.interface_type.set(crate::ntos::inc::types::InterfaceType::PCI_BUS);
    device_description.maximum_length.set(0x20000);
    device_description.dma_address_width.set(24);
    let registers = guest::alloc_bytes(4);
    let narrow = super::phase6::call_export("IoGetDmaAdapter", &[pdo, description, registers]).unwrap_or(1);
    device_description.dma_address_width.set(64);
    let adapter = super::phase6::call_export("IoGetDmaAdapter", &[pdo, description, registers]).unwrap_or(0);
    assert(narrow == 0 && adapter != 0 && crate::hal::dma::is_adapter(adapter) && guest::read32(registers) == 33, "pnp-storage: IoGetDmaAdapter versao 3, 33 registradores para 128 KB; abaixo de 32 bits sem adaptador");
    if adapter == 0 {
        guest::free_bytes(registers);
        guest::free_bytes(description);
        return;
    }
    // SAFETY: DMA_ADAPTER e a tabela V3 devolvidos pela HAL.
    let operations = unsafe { DmaOperations::at(DmaAdapter::at(adapter).dma_operations.get()) };
    let slot = |name: &str| routine_stubs::address(name).unwrap_or(1);
    assert(
        operations.size.get() == 0x138 && operations.free_common_buffer.get() == slot("HalFreeCommonBufferV3") && operations.build_scatter_gather_list.get() == slot("HalBuildScatterGatherListV3") && operations.get_scatter_gather_list.get() == slot("HalGetScatterGatherList") && operations.get_dma_adapter_info.get() == slot("HalGetDmaAdapterInfo") && operations.flush_dma_buffer.get() == slot("HalFlushDmaBuffer") && operations.get_dma_transfer_info.get() == slot("HalGetDmaTransferInfo"),
        "pnp-storage: tabela de operacoes V3 (Size 0x138, as variantes V3 e o FlushDmaBuffer)",
    );
    // GetDmaAdapterInfo: só a versão 1.
    let info = guest::alloc_bytes(crate::ntos::inc::types::DmaAdapterInfo::SIZE);
    guest::write32(info, 2);
    let unsupported = native_call::call(operations.get_dma_adapter_info.get(), &[adapter, info]) as u32;
    guest::write32(info, 1);
    let status = native_call::call(operations.get_dma_adapter_info.get(), &[adapter, info]) as u32;
    // SAFETY: DMA_ADAPTER_INFO preenchida.
    let v1 = unsafe { &crate::ntos::inc::types::DmaAdapterInfo::at(info).v1 };
    assert(unsupported == 0xC000_00BB && status == 0 && v1.dma_address_width.get() == 64 && v1.flags.get() == 3 && v1.scatter_gather_limit.get() == u32::MAX && v1.read_dma_counter_available.get() == 0 && v1.minimum_transfer_unit.get() == 1, "pnp-storage: GetDmaAdapterInfo versao 1 de um bus master de 64 bits");
    // FlushDmaBuffer e FlushAdapterBuffersEx num MDL de uma página.
    let buffer = guest::alloc_aligned(0x1000, 0x1000, true);
    let mdl = crate::ntos::io::mdl::allocate_mdl(buffer, 0x800);
    crate::ntos::mm::mdl::build_for_non_paged_pool(mdl);
    let flushed = native_call::call(operations.flush_dma_buffer.get(), &[adapter, mdl, 1]) as u32;
    let inside = native_call::call(operations.flush_adapter_buffers_ex.get(), &[adapter, mdl, 0, 0x7FF, 1, 1]) as u32;
    let beyond = native_call::call(operations.flush_adapter_buffers_ex.get(), &[adapter, mdl, 0, 0x800, 1, 1]) as u32;
    assert(flushed == 0 && inside == 0 && beyond == 0xC000_000D && native_call::call(operations.get_dma_domain.get(), &[adapter]) == 0, "pnp-storage: FlushDmaBuffer e FlushAdapterBuffersEx (Offset alem do ByteCount invalido), sem dominio de DMA");
    native_call::call(operations.put_dma_adapter.get(), &[adapter]);
    for block in [mdl, info, registers, description, buffer] {
        guest::free_bytes(block);
    }
}

fn tree_support(assert: Assert) {
    // O prefixo real de um Windows nesta VM: "3&267a616a&0&09" (pai ACPI\PNP0A03\0).
    assert(tree::parent_id_hash("ACPI\\PNP0A03\\0") == 0x267A_616A && tree::parent_id_hash("acpi\\pnp0a03\\0") == 0x267A_616A, "pnp-storage: hash do ParentIdPrefix igual ao do Windows");
    assert(tree::parent_id_hash("PCI_HAL\\PNP0A03\\0") == 0x0EBB_567F, "pnp-storage: hash do barramento raiz do OpenNT");
    // Arbitragem: a faixa preferida ocupada cai na alternativa. Memória acima
    // de tudo que a raiz já atribuiu (com a raiz ACPI, as janelas do
    // barramento PCI ocupam as portas e a memória baixa na raiz).
    const BASE: u64 = 0x30_0000_0000;
    let choice = |minimum: u64, maximum: u64, option_length: u32| resources::Choice { resource_type: resources::resource_type::MEMORY, share: resources::SHARE_DEVICE_EXCLUSIVE, flags: 0, length: option_length, alignment: 16, minimum: BASE + minimum, maximum: BASE + maximum, private: [0; 3], affinity: 0, address: 0 };
    let requirements = resources::Requirements { interface_type: 5, bus_number: 0, slot_number: 0, alternatives: alloc::vec![alloc::vec![alloc::vec![choice(0xF000, 0xF00F, 16), choice(0xE000, 0xEFFF, 16)]]] };
    let first = resources::assign(0x7_7000_0001, &requirements);
    let second = resources::assign(0x7_7000_0002, &requirements);
    assert(first.as_ref().is_some_and(|list| list.resources[0].start == BASE + 0xF000) && second.as_ref().is_some_and(|list| list.resources[0].start == BASE + 0xE000), "pnp-storage: conflito na faixa preferida usa a alternativa");
    resources::release(0x7_7000_0001);
    resources::release(0x7_7000_0002);
    // Os árbitros da raiz não conhecem janelas de barramento: o filho de um
    // nó com faixas atribuídas na raiz colide com elas (quem aloca dentro
    // das janelas é o árbitro do driver do barramento).
    let (bus, child) = (0x7_7000_0010u64, 0x7_7000_0011u64);
    let window = resources::CmList { interface_type: 5, bus_number: 0, resources: alloc::vec![resources::Resource { resource_type: resources::resource_type::MEMORY, share: resources::SHARE_DEVICE_EXCLUSIVE, flags: 0, start: BASE + 0xD000, length: 0x1000, extra: [0; 3] }] };
    resources::reserve(bus, &window);
    let anywhere = resources::Requirements { interface_type: 5, bus_number: 0, slot_number: 0, alternatives: alloc::vec![alloc::vec![alloc::vec![choice(0xD000, 0xFFFF, 0x10)]]] };
    let outside = resources::assign(child, &anywhere);
    for owner in [bus, child] {
        resources::release(owner);
    }
    // IoInvalidateDeviceRelations de um nó da árvore: BusRelations e
    // SingleBusRelations enfileiram a reenumeração (RemovalRelations não) e,
    // fora do `process`, o PnpDeviceActionWorker da fila de trabalho drena o
    // pedido (o nó ainda não iniciado não recebe IRP).
    let queued_device = guest::alloc_bytes(DeviceObject::SIZE);
    guest::write_bytes(queued_device, &[0; DeviceObject::SIZE as usize]);
    // SAFETY: DEVICE_OBJECT recém-alocado.
    unsafe { DeviceObject::at(queued_device) }.type_.set(3);
    let _ = crate::ntos::ob::objects::device::register(queued_device, None, None);
    devnode::insert(devnode::DeviceNode::new(queued_device, 0, 1));
    let before = tree::pending_requests();
    let single = tree::invalidate_relations(queued_device, 5) && tree::pending_requests() == before + 1;
    let removal = tree::invalidate_relations(queued_device, 3) && tree::pending_requests() == before + 1;
    // O worker roda numa thread de sistema (antes do processo System, num
    // work item): a espera dá a vez a ele.
    let interval = guest::alloc_bytes(8);
    for _ in 0..200 {
        crate::ntos::io::work_items::run_queue();
        if tree::pending_requests() == 0 {
            break;
        }
        guest::write64(interval, (-50_000i64) as u64);
        let _ = crate::ntos::ke::timer::delay_execution_thread(interval, 0, false);
    }
    guest::free_bytes(interval);
    let drained = tree::pending_requests() == 0;
    let _ = devnode::remove(queued_device);
    assert(single && removal && drained, "pnp-storage: SingleBusRelations enfileira a reenumeracao e o PnpDeviceActionWorker a drena");
    assert(outside.as_ref().is_some_and(|list| list.resources[0].start == BASE + 0xE000), "pnp-storage: a raiz aloca fora das faixas ja atribuidas, sem janelas de barramento");
    // O tradutor da raiz: a HAL sem ACPI leva a IRQ 14 ao vetor 0x2E no IRQL
    // 14; com a raiz ACPI (o tradutor do acpi.sys já traduziu), a identidade.
    let interrupt = resources::CmList { interface_type: 1, bus_number: 0, resources: alloc::vec![resources::Resource { resource_type: resources::resource_type::INTERRUPT, share: 1, flags: 1, start: 14, length: 14, extra: [u32::MAX, u32::MAX, 0] }] };
    let translated = resources::translate(&interrupt);
    let expected = if crate::drivers::bus::acpi_stack::enabled() { (14, 14) } else { (14, 0x2E) };
    assert(resources::translate_interrupt(14) == (0x2E, 14) && (translated.resources[0].start, translated.resources[0].length) == expected, "pnp-storage: IRQ 14 traduzida pela raiz (vetor 0x2E no IRQL 14 sem ACPI, identidade com a raiz ACPI)");
    // A lista escrita e relida é a mesma.
    let written = translated.write();
    assert(resources::CmList::read(written).is_some_and(|list| list.resources == translated.resources && list.interface_type == 1), "pnp-storage: CM_RESOURCE_LIST escrita e relida");
    guest::free_bytes(written);
}

/// Contadores do árbitro de teste: TestAllocation, CommitAllocation, as
/// entradas do último TestAllocation e o PDO da primeira delas.
static TEST_ARBITER_CALLS: [AtomicU64; 4] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// O ArbiterHandler de um árbitro de teste (ABI do driver): no
/// TestAllocation, cada entrada recebe a primeira alternativa no mínimo
/// dela (Assignment, SelectedAlternative e ArbiterResultSuccess); conta os
/// TestAllocation e os CommitAllocation.
extern "win64" fn test_arbiter_handler(_context: u64, action: u32, parameters: u64) -> i32 {
    use crate::ntos::inc::types::{ArbiterListEntry, ArbiterParameters, ArbiterResult, CmPartialResourceDescriptor};
    match action as u64 {
        pnp::arbiter::action::TEST_ALLOCATION => {
            TEST_ARBITER_CALLS[0].fetch_add(1, Ordering::AcqRel);
            // SAFETY: ARBITER_PARAMETERS do PnP manager com a lista de entradas.
            let head = unsafe { ArbiterParameters::at(parameters) }.parameters.test_allocation.arbitration_list.get();
            let mut entries = 0;
            let mut cursor = guest::read64(head);
            while cursor != head {
                // SAFETY: ARBITER_LIST_ENTRY da lista.
                let entry = unsafe { ArbiterListEntry::at(cursor) };
                if entries == 0 {
                    TEST_ARBITER_CALLS[3].store(entry.physical_device_object.get(), Ordering::Release);
                }
                entries += 1;
                if entry.alternative_count.get() != 0 {
                    // SAFETY: as alternativas e o descritor de saída da entrada.
                    let (alternative, assignment) = unsafe { (IoResourceDescriptor::at(entry.alternatives.get()), CmPartialResourceDescriptor::at(entry.assignment.get())) };
                    assignment.type_.set(alternative.type_.get());
                    assignment.share_disposition.set(alternative.share_disposition.get());
                    assignment.flags.set(alternative.flags.get());
                    assignment.u.port.start.quad_part.set(alternative.u.port.minimum_address.quad_part.get());
                    assignment.u.port.length.set(alternative.u.port.length.get());
                    entry.selected_alternative.set(entry.alternatives.get());
                    entry.result.set(ArbiterResult::ARBITER_RESULT_SUCCESS);
                } else {
                    entry.result.set(ArbiterResult::ARBITER_RESULT_NULL_REQUEST);
                }
                cursor = guest::read64(cursor);
            }
            TEST_ARBITER_CALLS[2].store(entries, Ordering::Release);
            0
        }
        pnp::arbiter::action::COMMIT_ALLOCATION => {
            TEST_ARBITER_CALLS[1].fetch_add(1, Ordering::AcqRel);
            0
        }
        _ => 0,
    }
}

/// Um requisito de um nó sob um barramento cujo driver dá o árbitro do tipo
/// vai a esse árbitro (TestAllocation com a entrada do PDO e o
/// CommitAllocation), não à raiz; a lista bruta é o Assignment que o
/// árbitro preencheu; a liberação é o pedido nulo do PDO.
fn driver_arbiters(assert: Assert) {
    use crate::ntos::inc::types::ArbiterInterface;
    let (bus, child) = (0x7_7000_0020u64, 0x7_7000_0021u64);
    devnode::insert(devnode::DeviceNode::new(bus, 0, 1));
    devnode::insert(devnode::DeviceNode::new(child, bus, 2));
    let interface = guest::alloc_bytes(ArbiterInterface::SIZE);
    // SAFETY: bloco recém-alocado.
    let arbiter = unsafe { ArbiterInterface::at(interface) };
    arbiter.size.set(ArbiterInterface::SIZE as u16);
    let handler: extern "win64" fn(u64, u32, u64) -> i32 = test_arbiter_handler;
    arbiter.arbiter_handler.set(handler as usize as u64);
    // As respostas das pilhas sintéticas: o barramento arbitra memória, sem
    // tradutores.
    pnp::arbiter::remember(bus, true, resources::resource_type::MEMORY, interface);
    pnp::arbiter::remember(bus, false, resources::resource_type::MEMORY, 0);
    pnp::arbiter::remember(child, false, resources::resource_type::MEMORY, 0);
    for counter in &TEST_ARBITER_CALLS {
        counter.store(0, Ordering::Release);
    }
    // Memória acima do que a raiz já atribuiu, para comparar com ela.
    const BASE: u64 = 0x31_0000_0000;
    let choice = resources::Choice { resource_type: resources::resource_type::MEMORY, share: resources::SHARE_DEVICE_EXCLUSIVE, flags: 0, length: 0x10, alignment: 0x10, minimum: BASE + 0x5000, maximum: BASE + 0x5FFF, private: [0; 3], affinity: 0, address: 0 };
    let requirements = resources::Requirements { interface_type: 5, bus_number: 0, slot_number: 0, alternatives: alloc::vec![alloc::vec![alloc::vec![choice]]] };
    let lists = pnp::arbiter::allocate(child, &requirements).ok().flatten();
    let tested = TEST_ARBITER_CALLS.iter().map(|counter| counter.load(Ordering::Acquire)).collect::<Vec<_>>();
    let at_root = resources::assign(0x7_7000_0022, &requirements);
    resources::release(0x7_7000_0022);
    assert(
        lists.as_ref().is_some_and(|(raw, translated)| raw.resources.len() == 1 && raw.resources[0].start == BASE + 0x5000 && raw.resources[0].length == 0x10 && translated.resources == raw.resources)
            && tested == [1, 1, 1, child]
            && at_root.as_ref().is_some_and(|list| list.resources[0].start == BASE + 0x5000),
        "pnp-storage: o requisito vai ao arbitro do driver do barramento (TestAllocation com a entrada do PDO, CommitAllocation), nao a raiz",
    );
    pnp::arbiter::release(child);
    assert(TEST_ARBITER_CALLS[0].load(Ordering::Acquire) == 2 && TEST_ARBITER_CALLS[1].load(Ordering::Acquire) == 2 && TEST_ARBITER_CALLS[2].load(Ordering::Acquire) == 1, "pnp-storage: a liberacao e o pedido nulo do PDO ao arbitro (TestAllocation e CommitAllocation)");
    for node in [child, bus] {
        pnp::arbiter::forget(node);
        let _ = devnode::remove(node);
    }
    guest::free_bytes(interface);
}

fn devnode_properties(assert: Assert) {
    // Um PDO sintético com devnode: as propriedades vêm da árvore do PnP.
    let pdo = guest::alloc_bytes(DeviceObject::SIZE);
    crate::drivers::bus::motherboard::initialize_pdo(pdo);
    if crate::ntos::ob::objects::device::register(pdo, None, None).is_err() {
        assert(false, "pnp-storage: PDO sintetico registrado");
        return;
    }
    let mut node = devnode::DeviceNode::new(pdo, 0, 2);
    node.instance_path = String::from("PNPTEST\\VEN_1234\\1&0&0");
    node.hardware_ids = alloc::vec![String::from("PNPTEST\\VEN_1234&DEV_0001"), String::from("PNPTEST\\VEN_1234")];
    let mut capabilities = alloc::vec![0u8; 0x40];
    capabilities[8..12].copy_from_slice(&0x0003_0002u32.to_le_bytes());
    capabilities[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    node.capabilities = capabilities;
    node.bus_information = Some(([0; 16], 5, 7));
    devnode::insert(node);
    let buffer = guest::alloc_bytes(0x100);
    let returned = guest::alloc_bytes(4);
    let status = super::phase6::call_export("IoGetDeviceProperty", &[pdo, 1, 0x100, buffer, returned]).unwrap_or(1) as u32;
    let expected = install::multi_sz_owned(&[String::from("PNPTEST\\VEN_1234&DEV_0001"), String::from("PNPTEST\\VEN_1234")]);
    assert(status == 0 && guest::read32(returned) as usize == expected.len() && guest::read_bytes(buffer, expected.len()) == expected, "pnp-storage: IoGetDeviceProperty(HardwareID) do devnode");
    let small = super::phase6::call_export("IoGetDeviceProperty", &[pdo, 0xF, 4, buffer, returned]).unwrap_or(1) as u32;
    assert(small == 0xC000_0023 && guest::read32(returned) == 16, "pnp-storage: EnumeratorName com buffer pequeno pede 16 bytes");
    let status = super::phase6::call_export("IoGetDeviceProperty", &[pdo, 0x10, 4, buffer, returned]).unwrap_or(1) as u32;
    assert(status == 0 && guest::read32(buffer) == 0x0003_0002, "pnp-storage: Address das capacidades");
    let status = super::phase6::call_export("IoGetDeviceProperty", &[pdo, 0xE, 4, buffer, returned]).unwrap_or(1) as u32;
    assert(status == 0 && guest::read32(buffer) == 7, "pnp-storage: BusNumber do QUERY_BUS_INFORMATION");
    let missing = super::phase6::call_export("IoGetDeviceProperty", &[pdo, 0x11, 4, buffer, returned]).unwrap_or(1) as u32;
    assert(missing == 0xC000_0034, "pnp-storage: UINumber ausente");
    // IoGetDevicePropertyData num PDO com devnode: propriedade ausente é
    // STATUS_OBJECT_NAME_NOT_FOUND (o partmgr.sys segue o START com ela).
    let key = guest::alloc_bytes(0x14);
    let required = guest::alloc_bytes(8);
    let property = super::phase6::call_export("IoGetDevicePropertyData", &[pdo, key, 0, 0, 0x10, buffer, required, required + 4]).unwrap_or(1) as u32;
    assert(property == 0xC000_0034, "pnp-storage: IoGetDevicePropertyData de devnode sem a propriedade");
    // DEVPKEY_Device_ClassGuid ({a45c254e-df1c-4efd-8020-67d146a850e0}, 10)
    // vem do ClassGUID da chave da instância, como DEVPROP_TYPE_GUID.
    let _ = install::write_text(&alloc::format!("{}\\Enum\\PNPTEST\\VEN_1234\\1&0&0", install::CONTROL_SET), "ClassGUID", "{4d36e967-e325-11ce-bfc1-08002be10318}");
    guest::write_bytes(key, &[0x4E, 0x25, 0x5C, 0xA4, 0x1C, 0xDF, 0xFD, 0x4E, 0x80, 0x20, 0x67, 0xD1, 0x46, 0xA8, 0x50, 0xE0, 10, 0, 0, 0]);
    let property = super::phase6::call_export("IoGetDevicePropertyData", &[pdo, key, 0, 0, 0x10, buffer, required, required + 4]).unwrap_or(1) as u32;
    assert(property == 0 && guest::read32(required) == 16 && guest::read32(required + 4) == 0x0D && guest::read_bytes(buffer, 16) == [0x67, 0xE9, 0x36, 0x4D, 0x25, 0xE3, 0xCE, 0x11, 0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18], "pnp-storage: DEVPKEY_Device_ClassGuid do devnode");
    guest::free_bytes(key);
    guest::free_bytes(required);
    // IoOpenDeviceRegistryKey(PLUGPLAY_REGKEY_DEVICE) cria Device Parameters.
    let handle = guest::alloc_bytes(8);
    let status = super::phase6::call_export("IoOpenDeviceRegistryKey", &[pdo, 1, 0xF003F, handle]).unwrap_or(1) as u32;
    let created = crate::ntos::cm::registry::node_by_path(&alloc::format!("{}\\Enum\\PNPTEST\\VEN_1234\\1&0&0\\Device Parameters", install::CONTROL_SET)).is_some();
    assert(status == 0 && guest::read64(handle) != 0 && created, "pnp-storage: IoOpenDeviceRegistryKey(DEVICE) abre Device Parameters");
    let _ = super::phase6::call_export("ZwClose", &[guest::read64(handle)]);
    let driver = super::phase6::call_export("IoOpenDeviceRegistryKey", &[pdo, 2, 0xF003F, handle]).unwrap_or(1) as u32;
    assert(driver == 0xC000_0034, "pnp-storage: sem valor Driver nao ha chave de driver");
    devnode::remove(pdo);
    for block in [buffer, returned, handle] {
        guest::free_bytes(block);
    }
}

fn io_attribution(assert: Assert) {
    // IoGetIoAttributionHandle: IRP sem IOP_IRP_EXTENSION -> STATUS_NOT_FOUND
    // (o classpnp.sys não usa a atribuição de um IRP sem ela).
    let packet = builder::allocate_irp(1);
    let output = guest::alloc_bytes(8);
    guest::write64(output, 0x5A5A);
    let status = super::phase6::call_export("IoGetIoAttributionHandle", &[packet, output]).unwrap_or(0) as u32;
    assert(status == 0xC000_0225 && guest::read64(output) == 0x5A5A, "pnp-storage: IoGetIoAttributionHandle sem extensao");
    // Com a extensão e o tipo 6, o handle da extensão.
    let extension = crate::ntos::io::extensions::allocate_irp_extension(packet, crate::ntos::io::extensions::IRP_EXTENSION_DISK_IO_ATTRIBUTION).unwrap_or(0);
    if extension != 0 {
        // SAFETY: IOP_IRP_EXTENSION recém-alocada.
        unsafe { crate::ntos::inc::types::extra_fs_ntfs::IopIrpExtension::at(extension) }.disk_io_attribution_handle.set(0x1234);
    }
    let status = super::phase6::call_export("IoGetIoAttributionHandle", &[packet, output]).unwrap_or(1) as u32;
    assert(extension != 0 && status == 0 && guest::read64(output) == 0x1234, "pnp-storage: IoGetIoAttributionHandle com extensao do tipo 6");
    let information = guest::alloc_bytes(0x40);
    guest::write32(information, 2);
    let mismatch = super::phase6::call_export("IoRecordIoAttribution", &[0x1234, information]).unwrap_or(0) as u32;
    guest::write32(information, 1);
    let unknown = super::phase6::call_export("IoRecordIoAttribution", &[0x1234, information]).unwrap_or(0) as u32;
    assert(mismatch == 0xC000_0059 && unknown == 0xC000_0008, "pnp-storage: IoRecordIoAttribution versao e handle");
    builder::free_irp(packet);
    guest::free_bytes(information);
    // KeQueryUnbiasedInterruptTimePrecise devolve o tempo (o classpnp.sys
    // mede intervalos por ele) e grava o QPC no ponteiro.
    guest::write64(output, 0);
    let first = super::phase6::call_export("KeQueryUnbiasedInterruptTimePrecise", &[output]).unwrap_or(0);
    let qpc = guest::read64(output);
    let _ = super::phase6::call_export("KeStallExecutionProcessor", &[2000]);
    let second = super::phase6::call_export("KeQueryUnbiasedInterruptTimePrecise", &[output]).unwrap_or(0);
    assert(first != 0 && qpc != 0 && second > first && guest::read64(output) > qpc, "pnp-storage: KeQueryUnbiasedInterruptTimePrecise devolve o tempo e grava o QPC");
    guest::free_bytes(output);
}

/// DeviceObject da posição corrente e MinorFunction do último IRP de
/// energia visto pelo driver de teste.
static POWER_SEEN: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];

/// IRP_MJ_POWER de teste: anota o pedido e o conclui com sucesso.
extern "win64" fn test_power_complete(_device: u64, packet: u64) -> u64 {
    // SAFETY: IRP vivo entregue pelo IofCallDriver.
    let irp = unsafe { Irp::at(packet) };
    // SAFETY: a posição corrente que o IofCallDriver acabou de ajustar.
    let location = unsafe { IoStackLocation::at(irp.tail.overlay.current_stack_location.get()) };
    POWER_SEEN[0].store(location.device_object.get(), Ordering::SeqCst);
    POWER_SEEN[1].store(location.minor_function.get() as u64, Ordering::SeqCst);
    irp.io_status.status.set(0);
    crate::ntos::io::io_manager::iof_complete_request(packet);
    0
}

/// O suporte de I/O que a pilha de disco usa: VPB do IoCreateDevice, nome
/// em colisão, MDL do IoBuildSynchronousFsdRequest e chave com separador no
/// fim.
fn io_support(assert: Assert) {
    use crate::ntos::inc::types::{DriverObject, Vpb};
    let driver = guest::alloc_bytes(DriverObject::SIZE);
    let output = guest::alloc_bytes(8);
    // IoCreateDevice(FILE_DEVICE_DISK) sem nome: VPB, SectorSize e DeviceLock.
    let status = crate::ntos::io::device::create_device(driver, 0, 0, 7, 0, output).unwrap_or(1);
    let device = guest::read64(output);
    // SAFETY: DEVICE_OBJECT recém-criado.
    let object = unsafe { DeviceObject::at(device) };
    let vpb = object.vpb.get();
    // SAFETY: o VPB que o IoCreateDevice criou.
    let volume = unsafe { Vpb::at(vpb) };
    assert(status == 0 && vpb != 0 && volume.type_.get() == 10 && volume.size.get() == 0x60 && volume.real_device.get() == device && object.sector_size.get() == 512 && object.device_lock.header.type_.get() == 1 && object.device_lock.header.signal_state.get() == 1, "pnp-storage: IoCreateDevice de disco com VPB, SectorSize 512 e DeviceLock");
    // IoBuildSynchronousFsdRequest num DO_DIRECT_IO: o buffer vai num MDL.
    object.flags.set(object.flags.get() | 0x10);
    let buffer = guest::alloc_aligned(0x1000, 0x1000, true);
    let packet = crate::ntos::io::io_manager::build_synchronous_fsd_request(3, device, buffer + 0x200, 0x400, 0, 0, 0);
    // SAFETY: IRP recém-montado.
    let irp = unsafe { Irp::at(packet) };
    let descriptor = irp.mdl_address.get();
    // SAFETY: o MDL do IRP.
    let mdl = unsafe { crate::ntos::inc::types::Mdl::at(descriptor) };
    assert(descriptor != 0 && irp.associated_irp.system_buffer.get() == 0 && mdl.byte_count.get() == 0x400 && mdl.byte_offset.get() == 0x200, "pnp-storage: IoBuildSynchronousFsdRequest com MDL num DO_DIRECT_IO");
    guest::free_bytes(descriptor);
    guest::free_bytes(packet);
    guest::free_bytes(buffer);
    // IoCreateSymbolicLink com um nome que já existe: STATUS_OBJECT_NAME_COLLISION.
    let (link, target) = (guest::alloc_bytes(0x80), guest::alloc_bytes(0x80));
    let (link_text, target_text) = (guest::alloc_bytes(0x80), guest::alloc_bytes(0x80));
    guest_strings::write_wide_string(link_text, "\\DosDevices\\OpenNtPnpTestLink");
    guest_strings::write_wide_string(target_text, "\\Device\\Null");
    let _ = super::phase6::call_export("RtlInitUnicodeString", &[link, link_text]);
    let _ = super::phase6::call_export("RtlInitUnicodeString", &[target, target_text]);
    let first = super::phase6::call_export("IoCreateSymbolicLink", &[link, target]).unwrap_or(1) as u32;
    let second = super::phase6::call_export("IoCreateSymbolicLink", &[link, target]).unwrap_or(1) as u32;
    assert(first == 0 && second == 0xC000_0035, "pnp-storage: IoCreateSymbolicLink em colisao devolve STATUS_OBJECT_NAME_COLLISION");
    let _ = super::phase6::call_export("IoDeleteSymbolicLink", &[link]);
    // PoRequestPowerIrp: o IRP desce pelo IofCallDriver ao topo da pilha (o
    // MajorFunction[IRP_MJ_POWER] do driver o conclui) e o Po o libera na
    // conclusão; devolve STATUS_PENDING e o IRP em *Irp.
    // SAFETY: DRIVER_OBJECT de teste, vivo até o fim da função.
    unsafe { DriverObject::at(driver) }.major_function[0x16].set(test_power_complete as extern "win64" fn(u64, u64) -> u64 as usize as u64);
    POWER_SEEN[0].store(0, Ordering::SeqCst);
    let irp_out = guest::alloc_bytes(8);
    let power = super::phase6::call_export("PoRequestPowerIrp", &[device, 2, 1, 0, 0, irp_out]).unwrap_or(0) as u32;
    // MinorFunction IRP_MN_SET_POWER (2) e o DeviceObject no slot do driver.
    let seen = (POWER_SEEN[0].load(Ordering::SeqCst), POWER_SEEN[1].load(Ordering::SeqCst));
    assert(power == 0x103 && guest::read64(irp_out) != 0 && seen == (device, 2), "pnp-storage: PoRequestPowerIrp pelo IofCallDriver");
    guest::free_bytes(irp_out);
    let _ = super::phase6::call_export("IoDeleteDevice", &[device]);
    // Chave criada com separador no fim do nome (o "Target0\" do ataport).
    let base = alloc::format!("{}\\Services\\OpenNtPnpTest", install::CONTROL_SET);
    let open = |path: &str| -> u32 {
        let (status, handle) = crate::ntos::cm::key::services::open_path(path, true).unwrap_or((1, 0));
        if handle != 0 {
            crate::ntos::cm::registry::close_handle(handle as u32);
        }
        status
    };
    let parent = open(&base);
    let child = open(&alloc::format!("{base}\\Target0\\"));
    assert(parent == 0 && child == 0 && crate::ntos::cm::registry::node_by_path(&alloc::format!("{base}\\Target0")).is_some(), "pnp-storage: chave criada com separador no fim do nome");
    for block in [driver, output, link, target, link_text, target_text] {
        guest::free_bytes(block);
    }
}

/// As linhas do display.inf e do machine.inf (com o ExcludeID da seção
/// MSBDA e o ImagePath do repositório de drivers) e o BAR pré-buscável do
/// adaptador VGA nos requisitos do PDO.
fn display_and_bridge_rows(assert: Assert) {
    let ids = |list: &[&str]| list.iter().map(|id| String::from(*id)).collect::<Vec<String>>();
    let vga = install::select_driver(&ids(&["PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02", "PCI\\VEN_1234&DEV_1111&CC_0300"]), &ids(&["PCI\\VEN_1234&DEV_1111", "PCI\\CC_030000", "PCI\\CC_0300"]));
    let basic_display = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicdisplay.inf_amd64_19e58b6267591a82\\BasicDisplay.sys";
    assert(vga.is_some_and(|driver| driver.inf == "display.inf" && driver.section == "MSBDA" && driver.class.name == "Display" && driver.service.is_some_and(|service| service.name == "BasicDisplay" && install::service_image_path(service) == basic_display)), "pnp-storage: PCI\\CC_0300 instala o BasicDisplay.sys do repositorio de drivers (display.inf)");
    assert(install::select_driver(&ids(&["PCI\\VEN_1414&DEV_5353&SUBSYS_00000000&REV_00"]), &ids(&["PCI\\VEN_1414&DEV_5353", "PCI\\CC_0300"])).is_none(), "pnp-storage: o ExcludeID da secao MSBDA recusa o adaptador do Hyper-V");
    let bridge = install::select_driver(&ids(&["PCI\\VEN_8086&DEV_7000&SUBSYS_11001AF4&REV_00"]), &ids(&["PCI\\VEN_8086&DEV_7000", "PCI\\CC_060100", "PCI\\CC_0601"]));
    assert(bridge.is_some_and(|driver| driver.inf == "machine.inf" && driver.class.name == "System" && driver.service.is_some_and(|service| service.name == "msisadrv" && install::service_image_path(service) == "System32\\drivers\\msisadrv.sys")), "pnp-storage: PCI\\CC_0601 instala o msisadrv.sys (machine.inf)");
    // O adaptador de renderização da raiz e os monitores que o dxgkrnl relata.
    let render = install::select_driver(&ids(&["ROOT\\BasicRender"]), &[]);
    let basic_render = "\\SystemRoot\\System32\\DriverStore\\FileRepository\\basicrender.inf_amd64_eebb5a8467eb88ec\\BasicRender.sys";
    assert(render.is_some_and(|driver| driver.inf == "basicrender.inf" && driver.section == "BasicRender" && driver.class.name == "System" && driver.service.is_some_and(|service| service.name == "BasicRender" && service.start == 1 && install::service_image_path(service) == basic_render)), "pnp-storage: ROOT\\BasicRender instala o BasicRender.sys do repositorio de drivers (basicrender.inf)");
    let monitor = |hardware: &[&str], section: &str| install::select_driver(&ids(hardware), &ids(&["*PNP09FF"])).is_some_and(|driver| driver.inf == "monitor.inf" && driver.section == section && driver.class.name == "Monitor" && driver.service.is_some_and(|service| service.name == "monitor" && install::service_image_path(service) == "\\SystemRoot\\System32\\drivers\\monitor.sys"));
    assert(monitor(&["MONITOR\\Default_Monitor"], "NonPnPMonitor.Install") && monitor(&["MONITOR\\MSI3DC9"], "PnPMonitor.Install"), "pnp-storage: MONITOR\\Default_Monitor e *PNP09FF instalam o monitor.sys (monitor.inf)");
    // O TPM 2.0 que o acpi.sys relata (ids do MSFT0101), com a raiz ACPI: o
    // tpm.inf com o serviço TPM sob demanda no grupo Boot Bus Extender, a
    // classe SecurityDevices e o HardwareType 20 do TPM 2.0.
    if crate::drivers::bus::acpi_stack::enabled() {
        let tpm = install::select_driver(&ids(&["ACPI\\VEN_MSFT&DEV_0101", "ACPI\\MSFT0101", "*MSFT0101"]), &[]);
        let hardware_type = tpm.is_some_and(|driver| driver.device_values.iter().any(|value| value.name == "HardwareType" && matches!(value.data, install::RegData::Dword(20))));
        assert(tpm.is_some_and(|driver| driver.inf == "tpm.inf" && driver.section == "Tpm2BaseInstall" && driver.class.name == "SecurityDevices" && driver.service.is_some_and(|service| service.name == "TPM" && service.start == 3 && service.group == Some("Boot Bus Extender") && install::service_image_path(service) == "System32\\drivers\\tpm.sys")) && hardware_type, "pnp-storage: ACPI\\MSFT0101 instala o tpm.sys (tpm.inf, Tpm2BaseInstall, HardwareType 20)");
    }
    let Some(adapter) = pci::devices().into_iter().find(|function| function.class_code == 0x03 && function.sub_class == 0x00) else {
        assert(false, "pnp-storage: adaptador VGA enumerado");
        return;
    };
    let (status, list) = pnp_irp(adapter.pdo_pointer, 0x0B, |_| {});
    if status != 0 || list == 0 {
        assert(false, "pnp-storage: requisitos do adaptador VGA");
        return;
    }
    // SAFETY: lista devolvida pelo barramento.
    let header = unsafe { IoResourceRequirementsList::at(list) };
    let alternative = &header.list[0];
    // SAFETY: os descritores da lista.
    let descriptors = unsafe { IoResourceDescriptor::array_at(alternative.descriptors[0].address(), alternative.count.get() as usize) };
    let memory: Vec<&pci::Bar> = adapter.bars.iter().filter(|bar| bar.value & 1 == 0 && bar.size != 0).collect();
    let flags_match = memory.iter().enumerate().all(|(index, bar)| {
        let expected = if bar.value & 0x8 != 0 { 4 } else { 0 };
        descriptors.get(index * 2).is_some_and(|descriptor| descriptor.type_.get() == 3 && descriptor.flags.get() == expected) && descriptors.get(index * 2 + 1).is_some_and(|descriptor| descriptor.flags.get() == expected)
    });
    assert(memory.iter().any(|bar| bar.value & 0x8 != 0) && flags_match, "pnp-storage: BAR pre-buscavel do adaptador VGA com CM_RESOURCE_MEMORY_PREFETCHABLE (preferido e alternativa)");
    guest::free_bytes(list);
}

pub fn run(assert: Assert) {
    io_attribution(assert);
    io_support(assert);
    pci_function_pdo(assert);
    display_and_bridge_rows(assert);
    dma_adapter(assert);
    tree_support(assert);
    driver_arbiters(assert);
    devnode_properties(assert);
}
