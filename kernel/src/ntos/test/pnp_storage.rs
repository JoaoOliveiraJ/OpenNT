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
//!   atapi para o canal, disk para GenDisk), e os árbitros e o tradutor
//!   atribuem e traduzem recursos (conflito cai na alternativa; IRQ 14 vira
//!   o vetor 0x2E no IRQL 14).
//! - Um devnode sintético responde IoGetDeviceProperty e
//!   IoOpenDeviceRegistryKey pela árvore do PnP.

use alloc::string::String;
use alloc::vec::Vec;

use crate::drivers::bus::{pci, pci_interface};
use crate::hal::amd64::{native_call, routine_stubs};
use crate::ntos::inc::types::extra_storage::{BusInterfaceStandard, DeviceDescription, DmaAdapter, DmaOperations, PnpBusInformation};
use crate::ntos::inc::types::{DeviceCapabilities, DeviceObject, IoResourceDescriptor, IoResourceRequirementsList, Irp, NtStruct};
use crate::ntos::io::irp_builder::{self as builder, BuildOptions};
use crate::ntos::io::pnp::{self, devnode, install, resources, tree};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::rtl::guest_strings;

type Assert = fn(bool, &str);

/// Um IRP_MJ_PNP montado à mão no PDO: (status, Information).
fn pnp_irp(pdo: u64, minor: u8, fill: impl FnOnce(&crate::ntos::inc::types::IoStackLocation)) -> (i32, u64) {
    let packet = guest::alloc_bytes(builder::size_for(1));
    builder::build(packet, &BuildOptions { major: 0x1B, minor, device_object: pdo, ..Default::default() });
    // SAFETY: IRP recém-montado.
    let irp = unsafe { Irp::at(packet) };
    irp.io_status.status.set(0xC000_00BBu32 as i32);
    // SAFETY: a posição do topo do IRP de uma posição.
    let location = unsafe { crate::ntos::inc::types::IoStackLocation::at(builder::first_stack_location(packet, 1)) };
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
    for block in [mdl, length, size, logical, registers, description] {
        guest::free_bytes(block);
    }
}

fn tree_support(assert: Assert) {
    // O prefixo real de um Windows nesta VM: "3&267a616a&0&09" (pai ACPI\PNP0A03\0).
    assert(tree::parent_id_hash("ACPI\\PNP0A03\\0") == 0x267A_616A && tree::parent_id_hash("acpi\\pnp0a03\\0") == 0x267A_616A, "pnp-storage: hash do ParentIdPrefix igual ao do Windows");
    assert(tree::parent_id_hash("PCI_HAL\\PNP0A03\\0") == 0x0EBB_567F, "pnp-storage: hash do barramento raiz do OpenNT");
    // Arbitragem: a faixa preferida ocupada cai na alternativa.
    let choice = |minimum: u64, maximum: u64, option_length: u32| resources::Choice { resource_type: resources::resource_type::PORT, share: resources::SHARE_DEVICE_EXCLUSIVE, flags: 1, length: option_length, alignment: 16, minimum, maximum, private: [0; 3], affinity: 0 };
    let requirements = resources::Requirements { interface_type: 5, bus_number: 0, slot_number: 0, alternatives: alloc::vec![alloc::vec![alloc::vec![choice(0xF000, 0xF00F, 16), choice(0xE000, 0xEFFF, 16)]]] };
    let first = resources::assign(0x7_7000_0001, &requirements);
    let second = resources::assign(0x7_7000_0002, &requirements);
    assert(first.as_ref().is_some_and(|list| list.resources[0].start == 0xF000) && second.as_ref().is_some_and(|list| list.resources[0].start == 0xE000), "pnp-storage: conflito na faixa preferida usa a alternativa");
    resources::release(0x7_7000_0001);
    resources::release(0x7_7000_0002);
    let interrupt = resources::CmList { interface_type: 1, bus_number: 0, resources: alloc::vec![resources::Resource { resource_type: resources::resource_type::INTERRUPT, share: 1, flags: 1, start: 14, length: 14, extra: [u32::MAX, u32::MAX, 0] }] };
    let translated = resources::translate(&interrupt);
    assert(translated.resources[0].length == 0x2E && translated.resources[0].start == 14, "pnp-storage: IRQ 14 traduzida para o vetor 0x2E no IRQL 14");
    // A lista escrita e relida é a mesma.
    let written = translated.write();
    assert(resources::CmList::read(written).is_some_and(|list| list.resources == translated.resources && list.interface_type == 1), "pnp-storage: CM_RESOURCE_LIST escrita e relida");
    guest::free_bytes(written);
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
    // PoRequestPowerIrp: o IRP desce pelo IofCallDriver ao topo da pilha (um
    // driver sem MajorFunction[IRP_MJ_POWER] o conclui com
    // STATUS_INVALID_DEVICE_REQUEST) e o Po o libera na conclusão; devolve
    // STATUS_PENDING e o IRP em *Irp.
    let irp_out = guest::alloc_bytes(8);
    let power = super::phase6::call_export("PoRequestPowerIrp", &[device, 2, 1, 0, 0, irp_out]).unwrap_or(0) as u32;
    assert(power == 0x103 && guest::read64(irp_out) != 0, "pnp-storage: PoRequestPowerIrp pelo IofCallDriver");
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

pub fn run(assert: Assert) {
    io_attribution(assert);
    io_support(assert);
    pci_function_pdo(assert);
    dma_adapter(assert);
    tree_support(assert);
    devnode_properties(assert);
}
