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
    let header = words(5);
    let path = crate::ntos::rtl::guest_strings::read_wide_string(result + 0x14);
    object_input(input, 0, 1, 0x14, Some("OPENNT\\CMAPI_CHILD\\1"));
    let _ = control(cm_api::code::GET_RELATED_DEVICE_INSTANCE, 0x28, 0x100);
    let parent = crate::ntos::rtl::guest_strings::read_wide_string(result + 0x14);
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
            && header == [0x14, 0, 0, 0x2A, 0]
            && path == "OPENNT\\CMAPI_CHILD\\1"
            && parent == "Root\\OPENNT_CMAPI\\0000"
            && childless == [0x14, STATUS_NO_SUCH_DEVICE, 0, 0]
            && tight.0 == STATUS_INVALID_PARAMETER,
        "deviceapi: GetDeviceDepth e GetRelatedDeviceInstance (pai, filho; nome invalido, sem filho e caminho que nao cabe)",
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
    if notify_opened == 0 {
        let _ = close::close(notify_handle, Some(0));
    }
    guest::free_bytes(block);
}
