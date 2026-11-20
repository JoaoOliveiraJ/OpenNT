//! Autoteste do `\Device\DeviceApi` do PnP manager: o driver embutido do
//! PiDaInit, a escolha do tratador pelo nome aberto (IrpHandlingTable) e os
//! IOCTLs do `\CMApi` pelo FastIoDeviceControl, com os resultados no buffer
//! de saída como o PiCMHandleIoctl os grava ({tamanho, status, ...}), sobre
//! a árvore de dispositivos (um nó de teste entra e sai dela).

use alloc::string::String;
use alloc::vec::Vec;

use super::phase6::{call_export, object_attributes_for};
use crate::ntos::inc::field::NtStruct;
use crate::ntos::inc::types::{DeviceObject, DriverObject, FastIoDispatch, FileObject, IoStatusBlock};
use crate::ntos::io::pnp::{cm_api, device_api, devnode};
use crate::ntos::mm::guest_memory as guest;
use crate::ntos::ob::close;

type Assert = fn(bool, &str);

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_NO_SUCH_DEVICE: u32 = 0xC000_000E;
const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
const STATUS_OBJECT_NAME_INVALID: u32 = 0xC000_0033;
const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;

fn status(value: Option<u64>) -> u32 {
    value.map_or(u32::MAX, |value| value as u32)
}

/// O pedido de objeto do cfgmgr32 (0x28 bytes) e o nome logo depois.
fn object_input(block: u64, flags: u32, parameter: u32, result_size: u32, name: Option<&str>) {
    guest::write_bytes(block, &[0u8; 0x200]);
    guest::write32(block, 0x28);
    guest::write32(block + 4, flags);
    guest::write32(block + 8, 1);
    guest::write32(block + 0x1C, parameter);
    guest::write32(block + 0x20, result_size);
    if let Some(name) = name {
        let units: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        guest::write_bytes(block + 0x40, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        guest::write64(block + 0x10, block + 0x40);
        guest::write32(block + 0x18, units.len() as u32 * 2);
    }
}

pub fn run(assert: Assert) {
    // O driver embutido e o dispositivo do PiDaDriverEntry.
    let device = device_api::device_object();
    let device_object = (device != 0).then(|| unsafe { DeviceObject::at(device) });
    let driver = device_object.map_or(0, |device| device.driver_object.get());
    let driver_object = (driver != 0).then(|| unsafe { DriverObject::at(driver) });
    let fast = driver_object.map_or(0, |driver| driver.fast_io_dispatch.get());
    let fast_io = (fast != 0).then(|| unsafe { FastIoDispatch::at(fast) });
    let name = driver_object.map(|driver| crate::ntos::rtl::guest_strings::read_unicode_string(driver.driver_name.address())).unwrap_or_default();
    assert(
        device_object.is_some_and(|device| device.device_type.get() == 0x22 && device.characteristics.get() == 0x2_0000 && device.flags.get() & 0x80 == 0 && device.device_extension.get() == 0)
            && driver_object.is_some_and(|driver| driver.flags.get() & 4 != 0 && [0usize, 2, 0xE, 0x12].iter().all(|&major| driver.major_function[major].get() != 0 && driver.major_function[major].get() == driver.major_function[0].get()))
            && fast_io.is_some_and(|table| table.size_of_fast_io_dispatch.get() == 0xE0 && table.fast_io_device_control.get() != 0 && table.fast_io_read.get() == 0)
            && name == "\\Driver\\DeviceApi",
        "deviceapi: \\Driver\\DeviceApi embutido com PiDaDispatch, FastIoDeviceControl e \\Device\\DeviceApi (FILE_DEVICE_UNKNOWN, AppContainer traversal)",
    );
    assert(
        device_api::handler_index("\\CMApi") == Some(2) && device_api::handler_index("\\CMNotify") == Some(4) && device_api::handler_index("\\Dev\\Query") == Some(0) && device_api::handler_index("\\cmapi").is_none() && device_api::handler_index("\\CMApi\\x").is_none(),
        "deviceapi: IrpHandlingTable com o nome exato e sensivel a caixa",
    );
    let block = guest::alloc_bytes(0x2000);
    let output = block + 0x1F00;
    let iosb = block + 0x1F10;
    // Nome desconhecido: o IRP_MJ_CREATE conclui com STATUS_INVALID_PARAMETER.
    let bogus = object_attributes_for(block + 0x1000, "\\Device\\DeviceApi\\Bogus", 0x240);
    let refused = status(call_export("ZwCreateFile", &[output, 0x8000_0000, bogus, iosb, 0, 0, 0, 1, 0, 0, 0]));
    let attributes = object_attributes_for(block + 0x1000, "\\Device\\DeviceApi\\CMApi", 0x240);
    let opened = status(call_export("ZwCreateFile", &[output, 0x8000_0000, attributes, iosb, 0, 0, 0, 1, 0, 0, 0]));
    let handle = guest::read64(output);
    let file = crate::ntos::io::file::query::resolve(handle, false).map_or(0, |selected| selected.pointer);
    let context = (file != 0).then(|| unsafe { FileObject::at(file) }.fs_context.get());
    assert(refused == STATUS_INVALID_PARAMETER && opened == 0 && context == Some(2), "deviceapi: abrir \\CMApi guarda o indice do tratador no FsContext; nome desconhecido falha com STATUS_INVALID_PARAMETER");
    if opened != 0 {
        guest::free_bytes(block);
        return;
    }
    let io_status = unsafe { IoStatusBlock::at(iosb) };
    let (input, result) = (block, block + 0x800);
    let control = |code: u32, input_length: u32, output_length: u32| -> (u32, u64) {
        guest::write_bytes(result, &[0xCCu8; 0x200]);
        let returned = status(call_export("ZwDeviceIoControlFile", &[handle, 0, 0, 0, iosb, code as u64, input, input_length as u64, result, output_length as u64]));
        (returned, io_status.information.get())
    };
    let words = |count: usize| -> Vec<u32> { (0..count).map(|index| guest::read32(result + index as u64 * 4)).collect() };
    // Um nó de teste na árvore de dispositivos, filho da raiz (ou raiz).
    let fake_pdo = guest::alloc_bytes(DeviceObject::SIZE);
    let fake_child = guest::alloc_bytes(DeviceObject::SIZE);
    let root = devnode::root();
    let mut node = devnode::DeviceNode::new(fake_pdo, root, if root != 0 { 1 } else { 0 });
    node.instance_path = String::from("Root\\OPENNT_CMAPI\\0000");
    node.state = devnode::State::Started;
    devnode::insert(node);
    let mut child = devnode::DeviceNode::new(fake_child, fake_pdo, if root != 0 { 2 } else { 1 });
    child.instance_path = String::from("OPENNT\\CMAPI_CHILD\\1");
    child.state = devnode::State::Failed;
    child.problem = 0x1C;
    devnode::insert(child);
    // PiCMGetDeviceStatus.
    object_input(input, 0, 0, 0x14, Some("Root\\OPENNT_CMAPI\\0000"));
    let (returned, information) = control(cm_api::code::GET_DEVICE_STATUS, 0x28, 0x14);
    let started = words(5);
    object_input(input, 0, 0, 0x14, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::GET_DEVICE_STATUS, 0x28, 0x14);
    let failed = words(5);
    object_input(input, 0, 0, 0x14, Some("OPENNT\\SEM_NO\\0"));
    let _ = control(cm_api::code::GET_DEVICE_STATUS, 0x28, 0x14);
    let missing = words(2);
    object_input(input, 0, 0, 0x14, Some("Root\\OPENNT_CMAPI\\0000"));
    let small = control(cm_api::code::GET_DEVICE_STATUS, 0x28, 0x10);
    assert(
        returned == 0 && information == 0x14 && started == [0x14, 0, 0x0180_200B, 0, 0] && failed == [0x14, 0, 0x0180_2400, 0x1C, 0] && missing == [0x14, STATUS_NO_SUCH_DEVICE] && small.0 == STATUS_INVALID_PARAMETER,
        "deviceapi: GetDeviceStatus pelo FastIoDeviceControl devolve DN_* e problema do no ({0x14, status, DN, problema, 0}); saida pequena recusa o IOCTL",
    );
    // PiCMGetDeviceDepth e PiCMGetRelatedDeviceInstance.
    object_input(input, 0, 0, 0xC, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::GET_DEVICE_DEPTH, 0x28, 0xC);
    let depth = words(3);
    object_input(input, 0, 0, 0xC, Some("OPENNT\\CMAPI_CHILD"));
    let _ = control(cm_api::code::GET_DEVICE_DEPTH, 0x28, 0xC);
    let invalid_name = words(2);
    object_input(input, 0, 2, 0x14, Some("Root\\OPENNT_CMAPI\\0000"));
    let (related, related_information) = control(cm_api::code::GET_RELATED_DEVICE_INSTANCE, 0x28, 0x100);
    let header = words(4);
    let path = crate::ntos::rtl::guest_strings::read_wide_string(result + 0x10);
    object_input(input, 0, 1, 0x14, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::GET_RELATED_DEVICE_INSTANCE, 0x28, 0x100);
    let parent = crate::ntos::rtl::guest_strings::read_wide_string(result + 0x10);
    object_input(input, 0, 2, 0x14, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::GET_RELATED_DEVICE_INSTANCE, 0x28, 0x100);
    let childless = words(4);
    object_input(input, 0, 1, 0x14, Some("OPENNT\\CMAPI_CHILD\\1"));
    let tight = control(cm_api::code::GET_RELATED_DEVICE_INSTANCE, 0x28, 0x18);
    assert(
        depth == [0xC, 0, if root != 0 { 2 } else { 1 }]
            && invalid_name == [0xC, STATUS_OBJECT_NAME_INVALID]
            && related == 0
            && related_information == 0x14 + 0x2A
            && header == [0x14, 0, 0x2A, 0]
            && path == "OPENNT\\CMAPI_CHILD\\1"
            && parent == "Root\\OPENNT_CMAPI\\0000"
            && childless == [0x14, STATUS_NO_SUCH_DEVICE, 0, 0]
            && tight.0 == STATUS_INVALID_PARAMETER,
        "deviceapi: GetDeviceDepth e GetRelatedDeviceInstance (pai, filho; nome invalido, sem filho e caminho que nao cabe)",
    );
    // PiCMGetDeviceInterfaceList numa classe sem interfaces (a do uDWM,
    // GUID_DEVINTERFACE_HOLOGRAPHIC_DISPLAY): L"\0", com o tamanho no
    // resultado {0x14, Status, Required, Extra} do PiCMReturnBufferResultData.
    const HOLOGRAPHIC: [u8; 16] = [0xab, 0x60, 0xac, 0xde, 0xe2, 0x66, 0xa4, 0x42, 0xad, 0x9b, 0x55, 0x7e, 0xe3, 0x3a, 0xe2, 0xd5];
    let interface_input = |flags: u32, result_size: u32| {
        guest::write_bytes(input, &[0u8; 0x40]);
        guest::write32(input, 0x28);
        guest::write32(input + 4, flags);
        guest::write_bytes(input + 8, &HOLOGRAPHIC);
        guest::write32(input + 0x24, result_size);
    };
    interface_input(0x1_0000, 0x14);
    let (size_call, size_information) = control(cm_api::code::GET_DEVICE_INTERFACE_LIST, 0x28, 0x14);
    let size_words = words(4);
    let (list_call, list_information) = control(cm_api::code::GET_DEVICE_INTERFACE_LIST, 0x28, 0x16);
    let list_words = words(5);
    interface_input(1, 0x14);
    let _ = control(cm_api::code::GET_DEVICE_INTERFACE_LIST, 0x28, 0x14);
    let bad_flags = words(4);
    interface_input(0x1_0000, 0x10);
    let bad_expected = control(cm_api::code::GET_DEVICE_INTERFACE_LIST, 0x28, 0x14);
    interface_input(0x1_0000, 0x14);
    let short_output = control(cm_api::code::GET_DEVICE_INTERFACE_LIST, 0x28, 0x10);
    assert(
        size_call == 0 && size_information == 0x14 && size_words == [0x14, 0xC000_0023, 2, 0] && list_call == 0 && list_information == 0x16 && list_words[..4] == [0x14, 0, 2, 0] && list_words[4] & 0xFFFF == 0 && bad_flags == [0x14, STATUS_INVALID_PARAMETER, 0, 0] && bad_expected == (STATUS_INVALID_PARAMETER, 0) && short_output.0 == STATUS_INVALID_PARAMETER,
        "deviceapi: GetDeviceInterfaceList de classe sem interfaces devolve L\"\\0\" (tamanho 0xC0000023 com 2; lista 0 com 2 bytes em +0x10); flags e resultado fora do contrato",
    );
    // PiCMValidateDeviceInstance: chave Enum e nó presente.
    let enum_key = alloc::format!("{}\\Enum\\Root\\OPENNT_CMAPI\\0000", crate::ntos::io::pnp::install::CONTROL_SET);
    let created = crate::ntos::cm::registry::open_or_create(&enum_key, None);
    object_input(input, 1, 0, 8, Some("Root\\OPENNT_CMAPI\\0000"));
    let _ = control(cm_api::code::VALIDATE_DEVICE_INSTANCE, 0x28, 8);
    let present = words(2);
    object_input(input, 1, 0, 8, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::VALIDATE_DEVICE_INSTANCE, 0x28, 8);
    let no_key = words(2);
    object_input(input, 3, 0, 8, Some("Root\\OPENNT_CMAPI\\0000"));
    let _ = control(cm_api::code::VALIDATE_DEVICE_INSTANCE, 0x28, 8);
    let bad_flags = words(2);
    if let Ok(handle) = created {
        crate::ntos::cm::registry::delete_key(handle);
        crate::ntos::cm::registry::close_handle(handle);
    }
    // Entrada fora do contrato e IOCTL desconhecido.
    guest::write32(input, 0x20);
    let wrong_size = control(cm_api::code::GET_DEVICE_STATUS, 0x28, 0x14);
    let unknown = control(0x0047_0FFF, 0x28, 0x14);
    assert(
        present == [8, 0] && no_key == [8, STATUS_NO_SUCH_DEVICE] && bad_flags == [8, STATUS_INVALID_PARAMETER] && wrong_size.0 == STATUS_INVALID_PARAMETER && unknown.0 == STATUS_NOT_SUPPORTED,
        "deviceapi: ValidateDeviceInstance (chave Enum e no presente) e recusas de entrada e de codigo",
    );
    // PiCMGetObjectProperty (0x204): o pedido de 0x48 bytes com o
    // DEVPROPKEY; a propriedade guardada no nó volta com Required = tamanho
    // e Extra = DEVPROPTYPE, a saída curta dá STATUS_BUFFER_TOO_SMALL, a
    // ausente STATUS_NOT_FOUND, a instância sem nó STATUS_NO_SUCH_DEVICE e
    // flags não nulos STATUS_INVALID_PARAMETER, todos no resultado.
    let property_input = |object_type: u32, name: &str, fmtid: [u8; 16], pid: u32, flags: u32| {
        guest::write_bytes(input, &[0u8; 0x200]);
        guest::write32(input, 0x48);
        guest::write32(input + 4, flags);
        guest::write32(input + 8, object_type);
        let units: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        guest::write_bytes(input + 0x80, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        guest::write64(input + 0x10, input + 0x80);
        guest::write32(input + 0x18, units.len() as u32 * 2);
        guest::write_bytes(input + 0x1C, &fmtid);
        guest::write32(input + 0x2C, pid);
        guest::write32(input + 0x44, 0x14);
    };
    let property_key = [0x5Au8; 16];
    crate::ntos::io::device_property::store_device_property(fake_pdo, property_key, 7, 7, &0x1234_5678u32.to_le_bytes());
    property_input(1, "Root\\OPENNT_CMAPI\\0000", property_key, 7, 0);
    let found = (control(cm_api::code::GET_OBJECT_PROPERTY, 0x48, 0x100), words(5));
    let short = (control(cm_api::code::GET_OBJECT_PROPERTY, 0x48, 0x14), words(4));
    property_input(1, "Root\\OPENNT_CMAPI\\0000", property_key, 8, 0);
    let _ = control(cm_api::code::GET_OBJECT_PROPERTY, 0x48, 0x100);
    let absent = words(4);
    property_input(1, "Root\\OPENNT_SEM_NO\\0000", property_key, 7, 0);
    let _ = control(cm_api::code::GET_OBJECT_PROPERTY, 0x48, 0x100);
    let no_node = words(4);
    property_input(1, "Root\\OPENNT_CMAPI\\0000", property_key, 7, 1);
    let _ = control(cm_api::code::GET_OBJECT_PROPERTY, 0x48, 0x100);
    let bad_flags = words(4);
    crate::ntos::io::device_property::store_device_property(fake_pdo, property_key, 7, 0, &[]);
    assert(
        found == ((0, 0x18), alloc::vec![0x14, 0, 4, 7, 0x1234_5678])
            && short == ((0, 0x14), alloc::vec![0x14, 0xC000_0023, 4, 7])
            && absent == [0x14, 0xC000_0225, 0, 0]
            && no_node == [0x14, STATUS_NO_SUCH_DEVICE, 0, 0]
            && bad_flags == [0x14, STATUS_INVALID_PARAMETER, 0, 0],
        "deviceapi: GetObjectProperty devolve a propriedade do no (tamanho e tipo), BUFFER_TOO_SMALL, NOT_FOUND, NO_SUCH_DEVICE e flags recusados no resultado",
    );
    // PiCMGetRegistryProperty (0x206): o pedido de 0x38 bytes com a
    // propriedade CM_DRP_*; os valores da chave da instância (o texto
    // indireto do INF resolvido), EnumeratorName pelo nome, Class pela
    // classe de instalação do ClassGUID, RemovalPolicy do devnode, a classe
    // pelo GUID (tipo 2, Properties) e as recusas no resultado.
    use crate::ntos::cm::{registry, seed::REG_DWORD};
    use crate::ntos::io::pnp::install;
    let class_guid = "{0E0E0E0E-0000-4000-8000-0000CA0A0001}";
    let instance_key = alloc::format!("{}\\Enum\\Root\\OPENNT_CMAPI\\0000", install::CONTROL_SET);
    let class_key = alloc::format!("{}\\Control\\Class\\{}", install::CONTROL_SET, class_guid);
    let _ = install::write_text(&instance_key, "DeviceDesc", "@oem9.inf,%cmapi.desc%;Dispositivo CMApi");
    let _ = install::write_dword(&instance_key, "ConfigFlags", 0x20);
    let _ = install::write_value(&instance_key, "Capabilities", REG_DWORD, alloc::vec![1, 0]);
    let _ = install::write_text(&instance_key, "ClassGUID", class_guid);
    let _ = install::write_text(&class_key, "Class", "OpenNTCmApi");
    let _ = install::write_dword(&alloc::format!("{class_key}\\Properties"), "DeviceType", 0x22);
    let registry_input = |object_type: u32, name: &str, property: u32, flags: u32| {
        guest::write_bytes(input, &[0u8; 0x200]);
        guest::write32(input, 0x38);
        guest::write32(input + 4, flags);
        guest::write32(input + 8, object_type);
        let units: Vec<u16> = name.encode_utf16().chain(core::iter::once(0)).collect();
        guest::write_bytes(input + 0x80, &units.iter().flat_map(|unit| unit.to_le_bytes()).collect::<Vec<u8>>());
        guest::write64(input + 0x10, input + 0x80);
        guest::write32(input + 0x18, units.len() as u32 * 2);
        guest::write32(input + 0x1C, property);
        guest::write32(input + 0x34, 0x14);
    };
    let text_at = |offset: u64, bytes: usize| -> String {
        let units: Vec<u16> = (0..bytes / 2).map(|index| guest::read16(result + offset + index as u64 * 2)).take_while(|&unit| unit != 0).collect();
        String::from_utf16_lossy(&units)
    };
    let device = "Root\\OPENNT_CMAPI\\0000";
    let mut answers: Vec<(u32, u64, Vec<u32>)> = Vec::new();
    let mut ask = |object_type: u32, name: &str, property: u32, flags: u32, output_length: u32, count: usize| {
        registry_input(object_type, name, property, flags);
        let (returned, information) = control(cm_api::code::GET_REGISTRY_PROPERTY, 0x38, output_length);
        answers.push((returned, information, words(count)));
    };
    ask(1, device, 0x01, 0, 0x100, 4);
    let description = text_at(0x10, 0x24);
    ask(1, device, 0x01, 0, 0x14, 4);
    ask(1, device, 0x0B, 0, 0x100, 5);
    ask(1, device, 0x10, 0, 0x100, 4);
    ask(1, device, 0x17, 0, 0x100, 4);
    let enumerator = text_at(0x10, 0x0A);
    ask(1, device, 0x08, 0, 0x100, 4);
    let class_name = text_at(0x10, 0x18);
    ask(1, device, 0x20, 0, 0x100, 5);
    ask(1, device, 0x24, 0, 0x100, 4);
    ask(1, device, 0x06, 0, 0x100, 4);
    ask(1, device, 0x26, 0, 0x100, 4);
    ask(3, device, 0x01, 0, 0x100, 4);
    ask(1, device, 0x01, 1, 0x100, 4);
    ask(1, "OPENNT\\CMAPI_CHILD\\1", 0x01, 0, 0x100, 4);
    ask(2, class_guid, 0x1A, 0, 0x100, 5);
    ask(2, class_guid, 0x01, 0, 0x100, 4);
    for key in [alloc::format!("{class_key}\\Properties"), class_key.clone(), instance_key.clone()] {
        if let Ok(opened) = registry::open(&key) {
            registry::delete_key(opened);
            registry::close_handle(opened);
        }
    }
    let expected: [(u32, u64, &[u32]); 15] = [
        (0, 0x38, &[0x14, 0, 0x24, 1]),
        (0, 0x14, &[0x14, 0xC000_0023, 0x24, 1]),
        (0, 0x18, &[0x14, 0, 4, 4, 0x20]),
        (0, 0x14, &[0x14, 0xC000_0225, 0, 0]),
        (0, 0x1E, &[0x14, 0, 0x0A, 1]),
        (0, 0x2C, &[0x14, 0, 0x18, 1]),
        (0, 0x18, &[0x14, 0, 4, 4, 1]),
        (0, 0x14, &[0x14, 0xC000_0225, 0, 0]),
        (0, 0x14, &[0x14, 0xC000_0230, 0, 0]),
        (0, 0x14, &[0x14, STATUS_INVALID_PARAMETER, 0, 0]),
        (0, 0x14, &[0x14, STATUS_INVALID_PARAMETER, 0xEC, 0]),
        (0, 0x14, &[0x14, STATUS_INVALID_PARAMETER, 0, 0]),
        (0, 0x14, &[0x14, STATUS_OBJECT_NAME_NOT_FOUND, 0, 0]),
        (0, 0x18, &[0x14, 0, 4, 4, 0x22]),
        (0, 0x14, &[0x14, 0xC000_0230, 0, 0]),
    ];
    let mismatch = answers.iter().zip(expected.iter()).position(|(answer, wanted)| answer.0 != wanted.0 || answer.1 != wanted.1 || answer.2.as_slice() != wanted.2);
    if let Some(index) = mismatch {
        crate::debug_print!("[deviceapi] GetRegistryProperty caso {}: {:x?}", index, answers[index]);
    }
    assert(
        answers.len() == expected.len() && mismatch.is_none() && description == "Dispositivo CMApi" && enumerator == "Root" && class_name == "OpenNTCmApi",
        "deviceapi: GetRegistryProperty devolve os valores da instancia (texto indireto resolvido, DWORD), EnumeratorName, Class pela classe do ClassGUID, RemovalPolicy do devnode e a classe pelo GUID; DWORD curto e LocationPaths NOT_FOUND, propriedade nao lida PROPSET_NOT_FOUND, fora da faixa, tipo e flags INVALID_PARAMETER, instancia sem chave OBJECT_NAME_NOT_FOUND",
    );
    devnode::remove(fake_child);
    devnode::remove(fake_pdo);
    guest::free_bytes(fake_pdo);
    guest::free_bytes(fake_child);
    let _ = close::close(handle, Some(0));
    // \CMNotify abre (FsContext2 zerado) e fecha.
    let notify = object_attributes_for(block + 0x1000, "\\Device\\DeviceApi\\CMNotify", 0x240);
    let notify_opened = status(call_export("ZwCreateFile", &[output, 0x8000_0000, notify, iosb, 0, 0, 0, 1, 0, 0, 0]));
    let notify_handle = guest::read64(output);
    let notify_file = crate::ntos::io::file::query::resolve(notify_handle, false).map_or(0, |selected| selected.pointer);
    let notify_context = (notify_file != 0).then(|| unsafe { FileObject::at(notify_file) });
    assert(notify_opened == 0 && notify_context.is_some_and(|file| file.fs_context.get() == 4 && file.fs_context2.get() == 0), "deviceapi: \\CMNotify abre com o indice 4 e FsContext2 zerado");
    // O registro (0x470800): o nome do módulo e o CM_NOTIFY_FILTER de uma
    // classe de interface; a saída recebe um nome WNF temporário e o
    // contexto fica no FsContext2. Recusas de tamanho e de filtro.
    let (register_input, register_output) = (block + 0x1400, block + 0x1800);
    let notify_control = |code: u32, input_length: u32, output_length: u32| -> (u32, u64) {
        guest::write64(register_output, 0);
        let returned = status(call_export("ZwDeviceIoControlFile", &[notify_handle, 0, 0, 0, iosb, code as u64, register_input, input_length as u64, register_output, output_length as u64]));
        (returned, unsafe { crate::ntos::inc::types::IoStatusBlock::at(iosb) }.information.get())
    };
    let filter = |flags: u32, filter_type: u32| {
        guest::write_bytes(register_input, &[0u8; 0x3A8]);
        crate::ntos::rtl::guest_strings::write_wide_string(register_input, "C:\\Windows\\System32\\lsm.dll");
        guest::write32(register_input + 0x208, 0x1A0);
        guest::write32(register_input + 0x20C, flags);
        guest::write32(register_input + 0x210, filter_type);
        guest::write_bytes(register_input + 0x218, &[0x80, 0x51, 0xA0, 0x1C, 0x99, 0xA6, 0x0A, 0x45, 0x9A, 0x0C, 0xDE, 0x4F, 0xBE, 0x3D, 0xDD, 0x89]);
    };
    filter(0, 0);
    let short = notify_control(0x47_0800, 0x3A0, 8);
    let bad_flags = { filter(4, 0); notify_control(0x47_0800, 0x3A8, 8) };
    let all_classes_instance = { filter(1, 2); notify_control(0x47_0800, 0x3A8, 8) };
    let refused_context = notify_context.map_or(1, |file| file.fs_context2.get());
    filter(0, 0);
    let (registered, registered_information) = notify_control(0x47_0800, 0x3A8, 8);
    let state_name = guest::read64(register_output);
    let context = notify_context.map_or(0, |file| file.fs_context2.get());
    let registration = crate::ntos::io::pnp::cm_notify::registrations().into_iter().find(|(entry, _)| *entry == context).map(|(_, registration)| registration);
    let unregistered = notify_control(0x47_080C, 0, 0).0;
    let get_event = notify_control(0x47_0804, 0, 0).0;
    assert(
        short.0 == STATUS_INVALID_PARAMETER
            && bad_flags.0 == STATUS_INVALID_PARAMETER
            && all_classes_instance.0 == STATUS_INVALID_PARAMETER
            && refused_context == 0
            && registered == 0
            && registered_information == 8
            && state_name != 0
            && state_name & 0xF != 0
            && registration.is_some_and(|registration| registration.state_name == state_name && registration.target.is_some())
            && unregistered == 0
            && get_event == 0xC000_0002,
        "deviceapi: \\CMNotify registra uma classe de interface com um nome WNF temporario e recusa tamanho e filtro",
    );
    if notify_opened == 0 {
        let _ = close::close(notify_handle, Some(0));
    }
    guest::free_bytes(block);
}
